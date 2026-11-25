// Copyright (C) 2025, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Session selection and request correlation for Chrome netlogs.
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::BuildHasher;
use std::io::BufRead;

use netlog::http;
use netlog::read_netlog_record;
use tabled::Tabled;

use super::ApplicationProto;
use super::Datastore;
use super::DatastoreError;
use crate::LogFileData;
use crate::RawLogEvents;

#[derive(Tabled)]
pub struct NetlogSession {
    #[tabled(rename = "ID")]
    session_id: i64,
    #[tabled(rename = "Protocol")]
    application_proto: ApplicationProto,
    #[tabled(rename = "SNI")]
    host: String,
    start_time: u64,
}

impl Debug for NetlogSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "app proto={:?}, host={}",
            self.application_proto, self.host
        )
    }
}

/// The discovery time of the request associated with each HTTP stream job.
pub type StreamBindingMap = BTreeMap<i64, u64>;

/// Discovery times indexed by QUIC stream ID within a single session.
pub type QuicRequestDiscovery = BTreeMap<u64, u64>;

type ParsedSessions = (Vec<LogFileData>, BTreeMap<i64, NetlogSession>);

type SessionEvents = Vec<(netlog::EventHeader, netlog::Event)>;

/// Retain identifiers until all records have been parsed.
///
/// A discovery event can be observed after a binding; the association itself
/// still follows the order of session binding and transaction headers so
/// retries don't attach to the wrong session.
#[derive(Default)]
struct RequestLinks {
    discoveries: BTreeMap<i64, u64>,
    jobs: BTreeMap<i64, i64>,
    active_quic_sessions: BTreeMap<i64, i64>,
    quic_streams: BTreeMap<i64, BTreeMap<u64, i64>>,
}

impl RequestLinks {
    fn discover(&mut self, request_id: i64, time: u64) {
        self.discoveries
            .entry(request_id)
            .and_modify(|earliest| {
                *earliest = (*earliest).min(time);
            })
            .or_insert(time);
    }

    fn observe(&mut self, source_id: i64, event: &http::Event) {
        match event {
            http::Event::HttpStreamJobBoundToRequest(event) => {
                self.jobs
                    .insert(source_id, event.params.source_dependency.id);
            },
            http::Event::HttpStreamRequestBoundToJob(event) => {
                self.jobs
                    .entry(event.params.source_dependency.id)
                    .or_insert(source_id);
            },
            http::Event::HttpStreamRequestBoundToQuicSession(event) => {
                self.active_quic_sessions
                    .insert(source_id, event.params.source_dependency.id);
            },
            http::Event::HttpTransactionQuicSendRequestHeaders(event) =>
                if let Some(session) = self.active_quic_sessions.get(&source_id) {
                    self.quic_streams
                        .entry(*session)
                        .or_default()
                        .entry(event.params.quic_stream_id)
                        .or_insert(source_id);
                },
            _ => (),
        }
    }

    fn job_discoveries(&self) -> StreamBindingMap {
        self.jobs
            .iter()
            .filter_map(|(job, request)| {
                self.discoveries.get(request).map(|time| (*job, *time))
            })
            .collect()
    }

    fn quic_discoveries(&mut self, session: i64) -> QuicRequestDiscovery {
        self.quic_streams
            .remove(&session)
            .into_iter()
            .flatten()
            .filter_map(|(stream, request)| {
                self.discoveries.get(&request).map(|time| (stream, *time))
            })
            .collect()
    }
}

#[derive(Default)]
struct SessionCollection {
    sessions: BTreeMap<i64, NetlogSession>,
    events: BTreeMap<i64, SessionEvents>,
    links: RequestLinks,
}

impl SessionCollection {
    fn register<S: BuildHasher>(
        &mut self, header: &netlog::EventHeader, protocol: ApplicationProto,
        host: String, filter: &HashSet<String, S>,
    ) {
        let id = header.source.id;
        if filter.is_empty() || filter.contains(&host) {
            self.events.entry(id).or_default();
        }
        self.sessions.entry(id).or_insert(NetlogSession {
            session_id: id,
            application_proto: protocol,
            host,
            start_time: header.time_num,
        });
    }

    fn observe<S: BuildHasher>(
        &mut self, header: netlog::EventHeader, event: Option<netlog::Event>,
        filter: &HashSet<String, S>,
    ) {
        if header.phase_string == "PHASE_BEGIN" {
            match &event {
                Some(netlog::Event::Quic(netlog::quic::Event::QuicSession(
                    event,
                ))) => {
                    self.register(
                        &header,
                        ApplicationProto::Http3,
                        format!("{}:{}", event.params.host, event.params.port),
                        filter,
                    );
                },
                Some(netlog::Event::H2(netlog::h2::Event::Http2Session(
                    event,
                ))) => {
                    self.register(
                        &header,
                        ApplicationProto::Http2,
                        event.params.host.clone(),
                        filter,
                    );
                },
                _ =>
                    if header.ty_string == "CORS_REQUEST" {
                        self.links.discover(header.source.id, header.time_num);
                    },
            }
        }
        if let Some(event) = event {
            if let netlog::Event::Http(event) = &event {
                self.links.observe(header.source.id, event);
            }
            if let Some(events) = self.events.get_mut(&header.source.id) {
                events.push((header, event));
            }
        }
    }

    fn build(
        mut self, constants: &netlog::constants::Constants,
    ) -> Result<ParsedSessions, DatastoreError> {
        let jobs = self.links.job_discoveries();
        let mut data = Vec::with_capacity(self.events.len());
        for (session_id, events) in self.events {
            let Some(session) = self.sessions.get(&session_id) else {
                continue;
            };
            let discoveries = self.links.quic_discoveries(session_id);
            let mut datastore = Datastore {
                session_id: Some(session_id),
                application_proto: session.application_proto,
                host: Some(session.host.clone()),
                ..Datastore::default()
            };
            for (header, event) in &events {
                datastore.consume_netlog_event(
                    session.start_time,
                    header,
                    event,
                    constants,
                    &jobs,
                    Some(&discoveries),
                )?;
            }
            datastore.hydrate_http_requests();
            datastore.finalize();
            data.push(LogFileData {
                datastore,
                raw: RawLogEvents::Netlog { events },
                trace: None,
            });
        }
        Ok((data, self.sessions))
    }
}

fn parse_header(
    record: &[u8], constants: &netlog::constants::Constants,
) -> Option<netlog::EventHeader> {
    let mut header: netlog::EventHeader = match serde_json::from_slice(record) {
        Ok(header) => header,
        Err(error) => {
            log::error!("Error deserializing netlog record: {error}");
            return None;
        },
    };
    if let Err(error) = header.populate_strings(constants) {
        log::warn!("Skipping netlog record with undefined event ID: {error}");
        return None;
    }
    let Ok(time) = header.time.parse() else {
        log::warn!(
            "Skipping netlog {} record with invalid timestamp {:?}",
            header.ty_string,
            header.time
        );
        return None;
    };
    header.time_num = time;
    Some(header)
}

/// Parse selected Chrome netlog sessions into independent datastores.
///
/// # Errors
/// Returns arithmetic overflow instead of producing wrapped byte histories.
pub fn with_netlog_reader<R: BufRead, S: BuildHasher>(
    reader: &mut R, hostname_filter: &HashSet<String, S>,
    constants: &netlog::constants::Constants,
) -> Result<ParsedSessions, DatastoreError> {
    // Skip the events array opening line after the constants record.
    let _ = read_netlog_record(reader);
    let mut collection = SessionCollection::default();
    while let Some(record) = read_netlog_record(reader) {
        if let Some(header) = parse_header(&record, constants) {
            let event = netlog::parse_event(&header, &record);
            collection.observe(header, event, hostname_filter);
        }
    }
    println!("All sessions in this netlog = {:#?}", collection.sessions);
    collection.build(constants)
}

#[cfg(test)]
mod tests {
    use super::with_netlog_reader;
    use super::RequestLinks;
    use netlog::http;
    use serde_json::json;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::collections::HashSet;
    use std::io::Cursor;

    fn binding(
        ty: &str, dependency: i64,
    ) -> Result<http::Event, Box<dyn std::error::Error>> {
        let header = netlog::EventHeader {
            ty_string: ty.to_owned(),
            ..Default::default()
        };
        let data = json!({"params": {"source_dependency": {"id": dependency, "type": 1}}});
        match netlog::parse_event(&header, &serde_json::to_vec(&data)?) {
            Some(netlog::Event::Http(event)) => Ok(event),
            _ => Err(format!("unrecognized binding {ty}").into()),
        }
    }

    #[test]
    fn links_preserve_each_session_on_retries_and_resolve_late_discovery(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut links = RequestLinks::default();
        links.observe(41, &binding("HTTP_STREAM_JOB_BOUND_TO_REQUEST", 8)?);
        links.observe(9, &binding("HTTP_STREAM_REQUEST_BOUND_TO_JOB", 42)?);
        let headers = |stream_id| {
            http::Event::HttpTransactionQuicSendRequestHeaders(
                http::HttpTransactionQuicSendRequestHeadersEvent {
                    params: http::HttpTransactionQuicSendRequestHeadersParams {
                        quic_stream_id: stream_id,
                        ..Default::default()
                    },
                },
            )
        };
        links.observe(
            8,
            &binding("HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION", 100)?,
        );
        links.observe(8, &headers(4));
        links.observe(
            8,
            &binding("HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION", 200)?,
        );
        links.observe(8, &headers(0));
        links.observe(
            9,
            &binding("HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION", 100)?,
        );
        links.observe(9, &headers(8));
        links.discover(8, 30);
        links.discover(8, 20);
        links.discover(9, 40);
        assert_eq!(
            links.job_discoveries(),
            BTreeMap::from([(41, 20), (42, 40)])
        );
        assert_eq!(
            links.quic_discoveries(100),
            BTreeMap::from([(4, 20), (8, 40)])
        );
        assert_eq!(links.quic_discoveries(200), BTreeMap::from([(0, 20)]));
        assert_eq!(links.quic_discoveries(300), BTreeMap::new());
        Ok(())
    }

    fn record(id: i64, ty: i64, time: u64, params: Value) -> Value {
        json!({"phase": 1, "source": {"id": id, "type": 1, "start_time": "0"},
            "type": ty, "time": time.to_string(), "params": params})
    }

    #[test]
    fn filtered_session_reader_resolves_http2_and_http3_discovery(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = json!({
            "constants": {
                "activeFieldTrialGroups": [], "addressFamily": {},
                "certPathBuilderDigestPolicy": {}, "certStatusFlag": {},
                "certVerifierFlags": {}, "clientInfo": {}, "dnsQueryType": {},
                "loadFlag": {}, "loadState": {},
                "logEventPhase": {"PHASE_BEGIN": 1},
                "logEventTypes": {
                    "QUIC_SESSION": 1, "HTTP2_SESSION": 2, "CORS_REQUEST": 3,
                    "HTTP_STREAM_JOB_BOUND_TO_REQUEST": 4,
                    "HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION": 5,
                    "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS": 6,
                    "HTTP3_HEADERS_SENT": 7, "HTTP2_SESSION_SEND_HEADERS": 8
                },
                "logFormatVersion": 123, "logSourceType": {},
                "netError": {}, "quicError": {}, "quicRstStreamError": {},
                "secureDnsMode": {}, "timeTickOffset": 0
            }
        });
        let quic_session = |host| {
            json!({
                "cert_verify_flags": 0, "connection_id": "", "host": host,
                "port": 443, "network_isolation_key": "", "privacy_mode": ""
            })
        };
        let records = [
            record(100, 1, 100, quic_session("selected.test")),
            record(
                200,
                2,
                200,
                json!({"host": "selected.test:443", "proxy": ""}),
            ),
            record(300, 1, 300, quic_session("excluded.test")),
            record(
                41,
                4,
                201,
                json!({"source_dependency": {"id": 8, "type": 1}}),
            ),
            record(
                9,
                5,
                101,
                json!({"source_dependency": {"id": 100, "type": 1}}),
            ),
            record(
                9,
                6,
                102,
                json!({"headers": [], "quic_priority_incremental": false,
                "quic_priority_type": "", "quic_priority_urgency": 3, "quic_stream_id": 4}),
            ),
            record(
                100,
                7,
                103,
                json!({"stream_id": 4, "headers": [":method: GET"]}),
            ),
            record(
                200,
                8,
                202,
                json!({"stream_id": 1, "headers": [":method: GET"], "fin": true,
                "has_priority": false, "exclusive": false, "weight": 16, "parent_stream_id": 0,
                "source_dependency": {"id": 41, "type": 1}}),
            ),
            // Discovery records may arrive after the binding/header records.
            record(9, 3, 90, json!({})),
            record(8, 3, 180, json!({})),
        ];
        let mut input = constants.to_string();
        input.pop();
        use std::fmt::Write;
        write!(
            input,
            ",\n\"events\": [\n{}\n]\n}}",
            records.map(|record| record.to_string()).join(",\n")
        )?;
        let mut reader = Cursor::new(input);
        let constants = netlog::read_netlog_constants(&mut reader)?;
        let (logs, sessions) = with_netlog_reader(
            &mut reader,
            &HashSet::from(["selected.test:443".to_owned()]),
            &constants,
        )?;
        assert_eq!(sessions.len(), 3);
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].datastore.session_id, Some(100));
        assert_eq!(
            logs[0]
                .datastore
                .http_requests
                .get(&4)
                .and_then(|req| req.time_discovery),
            Some(-10.0)
        );
        assert_eq!(logs[1].datastore.session_id, Some(200));
        assert_eq!(
            logs[1]
                .datastore
                .http_requests
                .get(&1)
                .and_then(|req| req.time_discovery),
            Some(-20.0)
        );
        Ok(())
    }
}
