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

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use config::AppConfig;
use datastore::Datastore;
use datastore::NetlogSession;
use log::debug;
use log::error;

use qlog::reader::QlogSeqReader;
use qlog::Qlog;

use serde::ser::Serialize;

use crate::wirefilter::filter_sqlog_events;

pub type QlogPointu64 = (f64, u64);
pub type QlogPointRtt = (f64, f32);

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Copy, Clone)]
pub enum PacketType {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
    Retry,
    VersionNegotiation,
    Unknown,
}

impl PacketType {
    /// Classify a typed qlog packet, mapping unknown and stateless-reset
    /// packets to the generic bucket used by the plots.
    #[must_use = "the returned value identifies the converted packet type"]
    pub const fn from_qlog_packet_type(
        ty: &qlog::events::quic::PacketType,
    ) -> Self {
        use qlog::events::quic::PacketType as QlogPacketType;

        match ty {
            QlogPacketType::Initial => Self::Initial,
            QlogPacketType::Handshake => Self::Handshake,
            QlogPacketType::ZeroRtt => Self::ZeroRtt,
            QlogPacketType::OneRtt => Self::OneRtt,
            QlogPacketType::Retry => Self::Retry,
            QlogPacketType::VersionNegotiation => Self::VersionNegotiation,
            QlogPacketType::StatelessReset | QlogPacketType::Unknown =>
                Self::Unknown,
        }
    }

    /// Classify a packet from Chrome netlog header metadata.
    #[must_use = "the returned value identifies the decoded packet type"]
    pub fn from_netlog_packet_header(
        header_format: &str, long_header_type: Option<&str>,
    ) -> Self {
        match header_format {
            "IETF_QUIC_LONG_HEADER_PACKET" => match long_header_type {
                Some("INITIAL") => Self::Initial,
                Some("HANDSHAKE") => Self::Handshake,
                _ => Self::Unknown,
            },
            "IETF_QUIC_SHORT_HEADER_PACKET" => Self::OneRtt,
            _ => Self::Unknown,
        }
    }

    /// Classify a packet from Chrome netlog's encryption level.
    #[must_use = "the returned value identifies the packet encryption level"]
    pub fn from_netlog_encryption_level(encryption_level: &str) -> Self {
        match encryption_level {
            "ENCRYPTION_INITIAL" => Self::Initial,
            "ENCRYPTION_HANDSHAKE" => Self::Handshake,
            "ENCRYPTION_ZERO_RTT" => Self::ZeroRtt,
            "ENCRYPTION_FORWARD_SECURE" => Self::OneRtt,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationFormat {
    QlogJson,
    QlogJsonSeq,
    NetlogJson,
    Unknown,
}

impl SerializationFormat {
    #[must_use = "the returned format determines how to parse the input file"]
    pub fn from_file_extension(extension: &str) -> Self {
        match extension {
            ext if ext.eq_ignore_ascii_case("qlog") => Self::QlogJson,
            ext if ["sqlog", "gz", "zst"]
                .iter()
                .any(|suffix| ext.eq_ignore_ascii_case(suffix)) =>
                Self::QlogJsonSeq,
            ext if ext.eq_ignore_ascii_case("json") => Self::NetlogJson,
            _ => Self::Unknown,
        }
    }

    #[must_use = "the returned format determines how to parse the input file"]
    pub fn from_filename(filename: &str) -> Self {
        // Path handles the final suffix of compound extensions like .sqlog.gz.
        std::path::Path::new(filename)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .map_or(Self::Unknown, Self::from_file_extension)
    }
}

/// Identity of one independent qlog trace. Indices are zero-based and
/// correspond to the trace's position in the source document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QlogTraceIdentity {
    pub index: usize,
    pub title: Option<String>,
    pub vantage_point: qlog::VantagePointType,
}

impl QlogTraceIdentity {
    #[must_use = "the returned string contains the trace label"]
    pub fn label(&self) -> String {
        let prefix = format!("trace {}", self.index + 1);
        self.title
            .as_deref()
            .map_or_else(|| prefix.clone(), |title| format!("{prefix}: {title}"))
    }
}

pub struct LogFileDetails {
    pub file_schema: String,
    pub serialization_format: String,
    pub sessions: BTreeMap<i64, NetlogSession>,
}

pub enum RawLogEvents {
    QlogJson {
        events: Vec<qlog::events::Event>,
    },
    QlogJsonSeq {
        events: Vec<qlog::reader::Event>,
    },
    /// Parsed events belonging to each selected Chrome netlog session.
    Netlog {
        events: Vec<(netlog::EventHeader, netlog::Event)>,
    },
}

pub struct LogFileData {
    pub datastore: Datastore,
    pub raw: RawLogEvents,
    /// None for Chrome netlog sessions; Some for each JSON or JSON-SEQ trace.
    pub trace: Option<QlogTraceIdentity>,
}

pub struct LogFileParseResult {
    pub details: LogFileDetails,
    pub data: Vec<LogFileData>,
}

/// Parse the configured qlog JSON, JSON-SEQ or Chrome netlog input.
///
/// # Errors
/// Returns an error for an unknown format, malformed input, unsupported
/// vantage points, invalid filters or datastore processing failures.
pub fn parse_log_file(
    config: &AppConfig,
) -> Result<LogFileParseResult, Box<dyn Error>> {
    match config.log_format {
        SerializationFormat::QlogJson => parse_qlog_json(config),
        SerializationFormat::QlogJsonSeq => parse_qlog_json_seq(config),
        SerializationFormat::NetlogJson => parse_netlog_json(config),
        SerializationFormat::Unknown => {
            error!("Unknown log file format for {}", config.filename);
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unknown log file format for {}", config.filename),
            )
            .into())
        },
    }
}

fn parse_qlog_json(
    config: &AppConfig,
) -> Result<LogFileParseResult, Box<dyn Error>> {
    let started = std::time::Instant::now();
    let qlog = read_qlog_from_file(&config.file)?;
    if qlog.traces.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "qlog file contains no traces",
        )
        .into());
    }
    debug!("parsed qlog JSON in {:?}", started.elapsed());

    let started = std::time::Instant::now();
    let mut data = Vec::with_capacity(qlog.traces.len());
    for (index, trace) in qlog.traces.into_iter().enumerate() {
        let vantage_point = trace
            .vantage_point
            .as_ref()
            .map_or(qlog::VantagePointType::Unknown, |vp| vp.ty.clone());
        let datastore = Datastore::with_qlog_events(
            &trace.events,
            &vantage_point,
            !config.ignore_acks,
        )?;
        data.push(LogFileData {
            datastore,
            raw: RawLogEvents::QlogJson {
                events: trace.events,
            },
            trace: Some(QlogTraceIdentity {
                index,
                title: trace.title,
                vantage_point,
            }),
        });
    }
    debug!(
        "populated {} independent qlog datastores in {:?}",
        data.len(),
        started.elapsed()
    );
    Ok(LogFileParseResult {
        details: LogFileDetails {
            file_schema: qlog.file_schema,
            serialization_format: qlog.serialization_format,
            sessions: BTreeMap::new(),
        },
        data,
    })
}

fn parse_qlog_json_seq(
    config: &AppConfig,
) -> Result<LogFileParseResult, Box<dyn Error>> {
    println!("parsing qlog as JSON-SEQ...");
    let started = std::time::Instant::now();
    let (qlog_reader, details) = qlog_seq_reader(config)?;
    debug!("	complete in {:?}", started.elapsed());

    println!("populating datastore...");
    let started = std::time::Instant::now();
    let trace = QlogTraceIdentity {
        index: 0,
        title: qlog_reader.qlog.trace.title.clone(),
        vantage_point: qlog_reader
            .qlog
            .trace
            .vantage_point
            .as_ref()
            .map_or(qlog::VantagePointType::Unknown, |vp| vp.ty.clone()),
    };
    let events = qlog_reader.collect::<std::io::Result<Vec<_>>>()?;
    let events = if let Some(filter) = &config.qlog_wirefilter {
        filter_sqlog_events(events, filter)?
    } else {
        events
    };
    // Keep plot series, stats, and raw event exports in agreement.
    let datastore = Datastore::with_sqlog_reader_events(
        &events,
        &trace.vantage_point,
        !config.ignore_acks,
    )?;
    debug!("	complete in {:?}", started.elapsed());

    Ok(LogFileParseResult {
        details,
        data: vec![LogFileData {
            datastore,
            raw: RawLogEvents::QlogJsonSeq { events },
            trace: Some(trace),
        }],
    })
}

fn parse_netlog_json(
    config: &AppConfig,
) -> Result<LogFileParseResult, Box<dyn Error>> {
    println!("setting up parsing file as netlog...");
    let started = std::time::Instant::now();
    let file = File::open(&config.file)?;
    let mut reader = BufReader::new(file);
    let constants = netlog::read_netlog_constants(&mut reader)?;
    debug!("	complete in {:?}", started.elapsed());

    println!("parsing file ...");
    println!("Filtering on hostnames: {:#?}", config.netlog_filter);
    let started = std::time::Instant::now();
    let (data, sessions) = datastore::with_netlog_reader(
        &mut reader,
        &config.netlog_filter,
        &constants,
    )?;
    debug!("	complete in {:?}", started.elapsed());

    Ok(LogFileParseResult {
        details: LogFileDetails {
            file_schema: constants.log_format_version.to_string(),
            serialization_format: "Chrome netlog".to_string(),
            sessions,
        },
        data,
    })
}

/// Read a qlog JSON document from disk.
///
/// # Errors
/// Returns an error if the file cannot be opened or decoded as qlog JSON.
pub fn read_qlog_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<Qlog, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let qlog = serde_json::from_reader(reader)?;

    Ok(qlog)
}

/// Open a sequential qlog file, including supported compressed formats.
///
/// # Errors
/// Returns an error for an unsupported file extension, invalid header,
/// unavailable decompressor, or an I/O failure.
pub fn qlog_seq_reader(
    config: &AppConfig,
) -> Result<(QlogSeqReader<'static>, LogFileDetails), Box<dyn Error>> {
    let qlog_reader =
        QlogSeqReader::with_file(config.file.clone()).map_err(|e| {
            std::io::Error::other(format!("problem reading qlog file: {e}"))
        })?;

    let log_file_details = LogFileDetails {
        file_schema: qlog_reader.qlog.file_schema.clone(),
        serialization_format: qlog_reader.qlog.serialization_format.clone(),
        sessions: BTreeMap::new(),
    };

    Ok((qlog_reader, log_file_details))
}

pub fn stringify_last<T>(src: &[T]) -> String
where
    T: std::fmt::Debug,
{
    match src {
        [] | [_] => "n/a".to_string(),
        [.., last] => format!("{last:?}"),
    }
}

// slight hack: duplicate the previous point so
// that no misleading line interpolation occurs
fn push_interp<X: Clone, Y: Clone>(collection: &mut Vec<(X, Y)>, value: (X, Y)) {
    let prev = collection.last().cloned();
    let new_time = value.0.clone();

    if let Some((_, y)) = prev {
        collection.push((new_time, y));
    }

    collection.push(value);
}

fn create_file_recursive(filename: &str) -> std::io::Result<File> {
    let path = std::path::Path::new(filename);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    File::create(filename)
}

/// Split the category at the first separator, preserving arbitrary colons
/// within custom event names.
#[must_use = "the returned pair contains the event category and type"]
pub fn category_and_type_from_name(name: &str) -> (String, String) {
    match name.split_once(':') {
        Some((category, event_name)) =>
            (category.to_owned(), event_name.to_owned()),
        None => (name.to_owned(), String::new()),
    }
}

/// Derive the category and full event name from a serializable log record.
///
/// # Errors
/// Returns the serialization error (or a descriptive missing-name error)
/// rather than panicking when an event cannot be serialized.
pub fn category_and_type_from_event<T: Serialize>(
    ev: &T,
) -> Result<(String, String), serde_json::Error> {
    let encoded = serde_json::to_value(ev)?;
    let name = encoded
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "serialized qlog event has no string name",
            ))
        })?;
    Ok(category_and_type_from_name(name))
}

pub mod config;
pub mod datastore;
pub mod plots;
pub mod reports;
pub mod request_stub;
pub mod seriesstore;
#[cfg(any(target_arch = "wasm32", test))]
mod sqlog_stream;
pub mod trackers;
#[cfg(target_arch = "wasm32")]
pub mod web;
pub mod wirefilter;

#[cfg(test)]
mod input_tests {
    use super::stringify_last;
    use super::SerializationFormat;
    use std::io::Cursor;

    #[test]
    fn packet_types_map_without_conflating_known_quic_packets() {
        use qlog::events::quic::PacketType as QlogPacketType;

        for (input, expected) in [
            (QlogPacketType::Initial, super::PacketType::Initial),
            (QlogPacketType::Handshake, super::PacketType::Handshake),
            (QlogPacketType::ZeroRtt, super::PacketType::ZeroRtt),
            (QlogPacketType::OneRtt, super::PacketType::OneRtt),
            (QlogPacketType::Retry, super::PacketType::Retry),
            (
                QlogPacketType::VersionNegotiation,
                super::PacketType::VersionNegotiation,
            ),
            (QlogPacketType::StatelessReset, super::PacketType::Unknown),
            (QlogPacketType::Unknown, super::PacketType::Unknown),
        ] {
            assert_eq!(
                super::PacketType::from_qlog_packet_type(&input),
                expected,
                "{input:?}"
            );
        }

        for (header, long_type, expected) in [
            (
                "IETF_QUIC_LONG_HEADER_PACKET",
                Some("INITIAL"),
                super::PacketType::Initial,
            ),
            (
                "IETF_QUIC_LONG_HEADER_PACKET",
                Some("HANDSHAKE"),
                super::PacketType::Handshake,
            ),
            (
                "IETF_QUIC_LONG_HEADER_PACKET",
                Some("OTHER"),
                super::PacketType::Unknown,
            ),
            (
                "IETF_QUIC_LONG_HEADER_PACKET",
                None,
                super::PacketType::Unknown,
            ),
            (
                "IETF_QUIC_SHORT_HEADER_PACKET",
                None,
                super::PacketType::OneRtt,
            ),
            (
                "IETF_QUIC_SHORT_HEADER_PACKET",
                Some("INITIAL"),
                super::PacketType::OneRtt,
            ),
            ("NOT_A_PACKET", Some("INITIAL"), super::PacketType::Unknown),
        ] {
            assert_eq!(
                super::PacketType::from_netlog_packet_header(header, long_type),
                expected,
                "{header:?} {long_type:?}"
            );
        }
        for (level, expected) in [
            ("ENCRYPTION_INITIAL", super::PacketType::Initial),
            ("ENCRYPTION_HANDSHAKE", super::PacketType::Handshake),
            ("ENCRYPTION_ZERO_RTT", super::PacketType::ZeroRtt),
            ("ENCRYPTION_FORWARD_SECURE", super::PacketType::OneRtt),
            ("UNRECOGNIZED", super::PacketType::Unknown),
        ] {
            assert_eq!(
                super::PacketType::from_netlog_encryption_level(level),
                expected,
                "{level:?}"
            );
        }
    }

    #[test]
    fn trace_labels_cover_titled_and_untitled_sessions() {
        let trace = super::QlogTraceIdentity {
            index: 2,
            title: Some("handshake".to_string()),
            vantage_point: qlog::VantagePointType::Client,
        };
        assert_eq!(trace.label(), "trace 3: handshake");
        let untitled = super::QlogTraceIdentity {
            title: None,
            ..trace
        };
        assert_eq!(untitled.label(), "trace 3");
    }

    #[test]
    fn serialization_format_recognizes_case_insensitive_extensions() {
        use SerializationFormat::NetlogJson;
        use SerializationFormat::QlogJson;
        use SerializationFormat::QlogJsonSeq;
        use SerializationFormat::Unknown;

        for (filename, expected) in [
            ("capture.qlog", QlogJson),
            ("capture.QLOG", QlogJson),
            ("nested.path/capture.QLog", QlogJson),
            ("capture.sqlog", QlogJsonSeq),
            ("capture.SQLOG", QlogJsonSeq),
            ("capture.sqlog.GZ", QlogJsonSeq),
            ("capture.SQLOG.ZST", QlogJsonSeq),
            ("capture.gz", QlogJsonSeq),
            ("capture.ZsT", QlogJsonSeq),
            ("capture.json", NetlogJson),
            ("capture.JSON", NetlogJson),
            ("capture.json.gz", QlogJsonSeq),
            ("capture.qlog.bak", Unknown),
            ("capture", Unknown),
            ("qlog", Unknown),
            (".qlog", Unknown),
            ("", Unknown),
        ] {
            assert_eq!(
                SerializationFormat::from_filename(filename),
                expected,
                "{filename:?}"
            );
        }

        assert_eq!(SerializationFormat::from_file_extension("Gz"), QlogJsonSeq);
        assert_eq!(SerializationFormat::from_file_extension("JSoN"), NetlogJson);
    }

    fn netlog_constants_document() -> serde_json::Value {
        serde_json::json!({
            "constants": {
                "activeFieldTrialGroups": [],
                "addressFamily": {},
                "certPathBuilderDigestPolicy": {},
                "certStatusFlag": {},
                "certVerifierFlags": {},
                "clientInfo": {},
                "dnsQueryType": {},
                "loadFlag": {},
                "loadState": {},
                "logEventPhase": {"PHASE_BEGIN": 1},
                "logEventTypes": {"HTTP2_SESSION": 101, "QUIC_SESSION": 102},
                "logFormatVersion": 123,
                "logSourceType": {},
                "netError": {},
                "quicError": {},
                "quicRstStreamError": {},
                "secureDnsMode": {},
                "timeTickOffset": 0
            }
        })
    }

    #[test]
    fn malformed_netlog_event_records_do_not_abort_later_sessions(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::collections::HashSet;

        let document = netlog_constants_document().to_string();
        let prefix = document
            .strip_suffix('}')
            .ok_or("missing JSON object suffix")?;
        let event = |id: i64,
                     ty: i64,
                     phase: i64,
                     time: &str,
                     params: serde_json::Value| {
            serde_json::json!({
                "phase": phase,
                "source": {"id": id, "type": 7, "start_time": "0"},
                "time": time,
                "type": ty,
                "params": params,
            })
        };
        let records = [
            event(1, 999, 1, "1", serde_json::json!({})),
            event(2, 101, 999, "2", serde_json::json!({})),
            event(3, 101, 1, "garbage", serde_json::json!({})),
            event(4, 101, 1, "3", serde_json::json!({})),
            event(5, 102, 1, "4", serde_json::json!({})),
            event(
                6,
                101,
                1,
                "5",
                serde_json::json!({"host": "example.test", "proxy": ""}),
            ),
        ];
        let data = format!(
            "{prefix},\r\n\"events\": [\r\n{}\r\n]\r\n}}",
            records.map(|value| value.to_string()).join(",\r\n")
        );
        let mut reader = Cursor::new(data.into_bytes());
        let constants = netlog::read_netlog_constants(&mut reader)?;
        let (logs, sessions) = crate::datastore::with_netlog_reader(
            &mut reader,
            &HashSet::new(),
            &constants,
        )?;
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key(&6));
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].datastore.host.as_deref(), Some("example.test"));
        match &logs[0].raw {
            super::RawLogEvents::Netlog { events } => {
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].0.ty_string, "HTTP2_SESSION");
                assert_eq!(events[0].0.time, "5");
            },
            _ =>
                return Err(
                    "parsed Chrome netlog must retain selected session events"
                        .into(),
                ),
        }

        Ok(())
    }

    #[test]
    fn event_name_preserves_colons_and_serialization_errors_are_returned() {
        use serde::Serialize;
        struct BrokenEvent;
        impl Serialize for BrokenEvent {
            fn serialize<S: serde::Serializer>(
                &self, _serializer: S,
            ) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("event serializer failure"))
            }
        }
        assert!(
            super::category_and_type_from_event(&BrokenEvent).is_err_and(
                |error| error.to_string().contains("event serializer failure")
            )
        );
        assert_eq!(
            super::category_and_type_from_name("quic:some:future:event"),
            ("quic".to_owned(), "some:future:event".to_owned()),
        );
        assert_eq!(
            super::category_and_type_from_event(&serde_json::json!({
                "name": "custom:event:type", "data": {"x": 1}
            }))
            .ok(),
            Some(("custom".to_owned(), "event:type".to_owned())),
        );
        assert!(super::category_and_type_from_event(
            &serde_json::json!({"x": 1})
        )
        .is_err());
    }

    #[test]
    fn stringify_last_handles_empty_and_single_item_slices() {
        assert_eq!(stringify_last::<u8>(&[]), "n/a");
        assert_eq!(stringify_last(&[1_u8]), "n/a");
        assert_eq!(stringify_last(&[1_u8, 2_u8]), "2");
    }
}
