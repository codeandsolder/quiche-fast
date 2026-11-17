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

use std::fmt::Write;

use qlog::events::http3::Http3Frame;
use qlog::events::quic::QuicFrame;
use qlog::events::EventData;
use tabled::Table;
use tabled::Tabled;

use crate::category_and_type_from_event;
use crate::category_and_type_from_name;

macro_rules! printy {
    ($k:expr, $value:expr, $s:expr) => {{
        let _ = write!(&mut $s, "{}={}, ", $k, $value);
    }};
}

macro_rules! printyo {
    ($k:expr, $value:expr, $s:expr) => {{
        if let Some(v) = $value {
            let _ = write!(&mut $s, "{}={}, ", $k, v);
        }
    }};
}

macro_rules! printy_json {
    ($k:expr, $value:expr, $s:expr) => {{
        let _ = write!(
            &mut $s,
            "{}={}, ",
            $k,
            &serde_json::to_string(&$value)?.replace("\"", "")
        );
    }};
}

macro_rules! printyo_json {
    ($k:expr, $value:expr, $s:expr) => {{
        if let Some(v) = $value {
            let _ = write!(
                &mut $s,
                "{}={}, ",
                $k,
                &serde_json::to_string(&v)?.replace("\"", "")
            );
        }
    }};
}

#[derive(Debug, Default, Tabled)]
struct PrintableEvent {
    pub time: f64,
    pub category: String,
    #[tabled(rename = "Type")]
    pub ty: String,
    pub details: String,
}

pub fn frames_to_string(frames: &[QuicFrame]) -> String {
    let mut s = String::new();
    for f in frames {
        match f {
            QuicFrame::Padding { raw, .. } => {
                let _ = write!(&mut s, " PADDING {{raw={raw:?}}}");
            },
            QuicFrame::Ping { .. } => {
                s += " PING";
            },
            QuicFrame::Ack { acked_ranges, .. } => {
                s += " ACK {";
                if let Some(acked_ranges) = acked_ranges {
                    for range in acked_ranges {
                        let _ = write!(&mut s, "{range}, ");
                    }
                }
                s += "}";
            },
            QuicFrame::ResetStream {
                stream_id,
                error,
                error_code,
                final_size,
                ..
            } => {
                let _ = write!(&mut s, " RESET_STREAM {{id={stream_id}, error={error:?}, error_code={error_code:?}, final_size={final_size}}}");
            },
            QuicFrame::StopSending {
                stream_id,
                error,
                error_code,
                ..
            } => {
                let _ = write!(&mut s, " STOP_SENDING {{id={stream_id}, error={error:?}, error_code={error_code:?}}}");
            },
            QuicFrame::Crypto { offset, raw } => {
                let _ = write!(&mut s, " CRYPTO {{off={offset}, raw={raw:?}}}");
            },
            QuicFrame::NewToken { token, .. } => {
                s += " NEW_TOKEN ";
                if let Some(ty) = &token.ty {
                    let _ = write!(&mut s, "{{ty={ty:?}}}");
                }
            },
            QuicFrame::Stream {
                stream_id,
                offset,
                fin,
                raw,
            } => {
                let _ = write!(
                    &mut s,
                    " STREAM {{id={stream_id}, off={offset:?}, raw={raw:?}"
                );
                if let Some(f) = fin {
                    let _ = write!(&mut s, ", fin={f}");
                }
                s += "}";
            },
            QuicFrame::MaxData { maximum, .. } => {
                let _ = write!(&mut s, " MAX_DATA {{max={maximum}}}");
            },
            QuicFrame::MaxStreamData {
                stream_id, maximum, ..
            } => {
                let _ = write!(
                    &mut s,
                    " MAX_STREAM_DATA {{id={stream_id}, max={maximum}}}"
                );
            },
            QuicFrame::MaxStreams {
                stream_type,
                maximum,
                ..
            } => {
                let _ = write!(
                    &mut s,
                    " MAX_STREAMS {{ty={stream_type:?}, max={maximum}}}"
                );
            },
            QuicFrame::DataBlocked { limit, .. } => {
                let _ = write!(&mut s, " DATA_BLOCKED {{limit={limit}}}");
            },
            QuicFrame::StreamDataBlocked {
                stream_id, limit, ..
            } => {
                let _ = write!(
                    &mut s,
                    " STREAM_DATA_BLOCKED {{id={stream_id}, limit={limit}}}"
                );
            },
            QuicFrame::StreamsBlocked {
                stream_type, limit, ..
            } => {
                let _ = write!(
                    &mut s,
                    " STREAMS_BLOCKED {{ty={stream_type:?}, limit={limit}}}"
                );
            },
            QuicFrame::NewConnectionId {
                sequence_number,
                retire_prior_to,
                connection_id_length,
                connection_id,
                stateless_reset_token,
                ..
            } => {
                let _ = write!(&mut s,
                    " NEW_CONNECTION_ID {{sn={sequence_number}, retire_prior_to={retire_prior_to}, cid_length={connection_id_length:?}, cid={connection_id:?}, reset_token={stateless_reset_token:?}}}"
                );
            },
            QuicFrame::RetireConnectionId {
                sequence_number, ..
            } => {
                let _ = write!(
                    &mut s,
                    " RETIRE_CONNECTION_ID {{sn={sequence_number}}}"
                );
            },
            QuicFrame::PathChallenge { data, .. } => {
                let _ = write!(&mut s, " PATH_CHALLENGE {{data={data:?}}}");
            },
            QuicFrame::PathResponse { data, .. } => {
                let _ = write!(&mut s, " PATH_RESPONSE {{data={data:?}}}");
            },
            QuicFrame::ConnectionClose {
                error_space,
                error_code,
                reason,
                ..
            } => {
                s += " CONNECTION_CLOSE {";
                if let Some(es) = error_space {
                    let _ = write!(&mut s, " ty={es:?},");
                }
                printyo!(" code", error_code, s);
                printyo!(" reason", reason, s);
                s += "}";
            },
            QuicFrame::HandshakeDone { .. } => {
                s += " HANDSHAKE_DONE";
            },
            QuicFrame::Datagram { raw, .. } => {
                let _ = write!(&mut s, " DATAGRAM {{raw={raw:?}}}");
            },
            QuicFrame::Unknown {
                frame_type_bytes, ..
            } => {
                let _ = write!(
                    &mut s,
                    " UNKNOWN {{frame_type_bytes={frame_type_bytes:?}}}"
                );
            },
        }
    }

    s
}

fn http_frame_to_string(frame: &Http3Frame) -> String {
    let mut s = String::new();

    match frame {
        Http3Frame::Data { raw } => {
            s += " DATA";
            if let Some(r) = raw {
                printyo!("len", r.length, s);
            }
        },
        Http3Frame::Headers { headers, .. } => {
            s += " HEADERS {";

            for header in headers {
                let name = header.name.as_deref().unwrap_or("<binary>");
                let value = header.value.as_deref().unwrap_or("<binary>");
                let _ = write!(&mut s, "{name}: {value}, ");
            }

            s += "}";
        },
        Http3Frame::CancelPush { push_id, .. } => {
            let _ = write!(&mut s, " CANCEL_PUSH {{id={push_id}}}");
        },
        Http3Frame::Settings { settings, .. } => {
            let _ = write!(&mut s, " SETTINGS {{settings={settings:?}}}");
        },
        Http3Frame::PushPromise {
            push_id, headers, ..
        } => {
            let _ = write!(
                &mut s,
                " PUSH_PROMISE {{push_id={push_id}, headers={headers:?}}}"
            );
        },
        Http3Frame::Goaway { id, .. } => {
            let _ = write!(&mut s, " GOAWAY {{id={id}}}");
        },
        Http3Frame::MaxPushId { push_id, .. } => {
            let _ = write!(&mut s, " MAX_PUSH_ID {{id={push_id}}}");
        },
        Http3Frame::PriorityUpdate {
            stream_id,
            push_id,
            priority_field_value,
            ..
        } => {
            let _ = write!(&mut s, " PRIORITY_UPDATE {{stream_id={stream_id:?}, push_id={push_id:?}, priority={priority_field_value:?}}}");
        },
        Http3Frame::Reserved {
            frame_type_bytes, ..
        } => {
            let _ = write!(&mut s, " GREASE {{ty={frame_type_bytes}}}");
        },
        Http3Frame::Unknown {
            frame_type_bytes, ..
        } => {
            let _ = write!(&mut s, " UNKNOWN {{ty={frame_type_bytes}}}");
        },
    }

    s
}

/// A borrowed view of both the native and extensible qlog record encodings.
/// The same formatter serves JSON and JSON-SEQ logs without cloning events.
enum EventView<'a> {
    Native(&'a qlog::events::Event),
    Json(&'a qlog::events::JsonEvent),
}

fn qlog_event_rows<'a>(
    events: impl IntoIterator<Item = EventView<'a>>,
) -> Result<tabled::builder::Builder, serde_json::Error> {
    let mut pp = vec![];

    for event in events {
        match event {
            EventView::Native(ev) => {
                let (cat, ty) = category_and_type_from_event(ev)?;

                let mut p = PrintableEvent {
                    time: ev.time,
                    ty,
                    category: cat,
                    ..Default::default()
                };

                match &ev.data {
                    EventData::QuicConnectionStarted(v) => {
                        printyo!("local_ip_v4", &v.local.ip_v4, p.details);
                        printyo!("local_port_v4", &v.local.port_v4, p.details);
                        printyo!("local_ip_v6", &v.local.ip_v6, p.details);
                        printyo!("local_port_v6", &v.local.port_v6, p.details);
                        printy!(
                            "local_cids",
                            format!("{:?}", &v.local.connection_ids),
                            p.details
                        );
                        printyo!("remote_ip_v4", &v.remote.ip_v4, p.details);
                        printyo!("remote_port_v4", &v.remote.port_v4, p.details);
                        printyo!("remote_ip_v6", &v.remote.ip_v6, p.details);
                        printyo!("remote_port_v6", &v.remote.port_v6, p.details);
                        printy!(
                            "remote_cids",
                            format!("{:?}", &v.remote.connection_ids),
                            p.details
                        );
                    },
                    EventData::QuicConnectionClosed(v) => {
                        printyo_json!("initiator", &v.initiator, p.details);
                        printyo_json!(
                            "connection_code",
                            &v.connection_error,
                            p.details
                        );
                        printyo_json!(
                            "application_error",
                            &v.application_error,
                            p.details
                        );
                        printyo!("internal_code", &v.internal_code, p.details);
                        printyo!("reason", &v.reason, p.details);
                        printyo_json!("trigger", &v.trigger, p.details);
                    },
                    EventData::QuicParametersSet(v) => {
                        printyo_json!("initiator", &v.initiator, p.details);
                        printyo!(
                            "resumption_allowed",
                            &v.resumption_allowed,
                            p.details
                        );
                        printyo!(
                            "early_data_enabled",
                            &v.early_data_enabled,
                            p.details
                        );
                        printyo!("tls_cipher", &v.tls_cipher, p.details);
                        printyo!(
                            "odcid",
                            &v.original_destination_connection_id,
                            p.details
                        );
                        printyo!(
                            "initial_scid",
                            &v.initial_source_connection_id,
                            p.details
                        );
                        printyo!(
                            "retry_scid",
                            &v.retry_source_connection_id,
                            p.details
                        );
                        printyo!(
                            "stateless_reset_token",
                            &v.stateless_reset_token,
                            p.details
                        );
                        printyo!(
                            "disable_active_migration",
                            &v.disable_active_migration,
                            p.details
                        );
                        printyo!(
                            "max_idle_timeout",
                            &v.max_idle_timeout,
                            p.details
                        );
                        printyo!(
                            "max_udp_payload_size",
                            &v.max_udp_payload_size,
                            p.details
                        );
                        printyo!("max_ack_delay", &v.max_ack_delay, p.details);
                        printyo!(
                            "active_connection_id_limit",
                            &v.active_connection_id_limit,
                            p.details
                        );
                        printyo!(
                            "initial_max_data",
                            &v.initial_max_data,
                            p.details
                        );
                        printyo!(
                            "initial_max_stream_data_bidi_local",
                            &v.initial_max_stream_data_bidi_local,
                            p.details
                        );
                        printyo!(
                            "initial_max_stream_data_bidi_remote",
                            &v.initial_max_stream_data_bidi_remote,
                            p.details
                        );
                        printyo!(
                            "initial_max_stream_data_uni",
                            &v.initial_max_stream_data_uni,
                            p.details
                        );
                        printyo!(
                            "initial_max_streams_bidi",
                            &v.initial_max_streams_bidi,
                            p.details
                        );
                        printyo!(
                            "initial_max_streams_uni",
                            &v.initial_max_streams_uni,
                            p.details
                        );
                        printyo_json!(
                            "preferred_address",
                            &v.preferred_address,
                            p.details
                        );
                        // TODO: v.unknown_parameters
                    },
                    EventData::QuicPacketSent(v) => {
                        p.details.push_str(
                            serde_json::to_string(&v.header.packet_type)?
                                .trim_matches('"'),
                        );
                        printyo!(" pn", v.header.packet_number, p.details);

                        if let Some(frames) = &v.frames {
                            p.details += &frames_to_string(frames);
                        }
                    },
                    EventData::QuicPacketReceived(v) => {
                        p.details.push_str(
                            serde_json::to_string(&v.header.packet_type)?
                                .trim_matches('"'),
                        );
                        printyo!(" pn", v.header.packet_number, p.details);

                        if let Some(frames) = &v.frames {
                            p.details += &frames_to_string(frames);
                        }
                    },
                    EventData::QuicStreamDataMoved(v) => {
                        printyo!("id", v.stream_id, p.details);
                        printyo!("off", v.offset, p.details);
                        if let Some(raw) = &v.raw {
                            printyo!("len", raw.length, p.details);
                        }
                        printyo_json!("from", &v.from, p.details);
                        printyo_json!("to", &v.to, p.details);
                    },
                    EventData::QuicMetricsUpdated(v) => {
                        printyo!("min_rtt", v.min_rtt, p.details);
                        printyo!("smoothed_rtt", v.smoothed_rtt, p.details);
                        printyo!("latest_rtt", v.latest_rtt, p.details);
                        printyo!("rtt_variance", v.rtt_variance, p.details);
                        printyo!("pto_count", v.pto_count, p.details);
                        printyo!("cwnd", v.congestion_window, p.details);
                        printyo!("bytes_in_flight", v.bytes_in_flight, p.details);
                        printyo!("ssthresh", v.ssthresh, p.details);
                        printyo!(
                            "packets_in_flight",
                            v.packets_in_flight,
                            p.details
                        );
                        printyo!("pacing_rate", v.pacing_rate, p.details);
                    },
                    EventData::Http3StreamTypeSet(ev) => {
                        printy!("id", &ev.stream_id, p.details);
                        printyo_json!("initiator", &ev.initiator, p.details);
                        printy_json!("ty", &ev.stream_type, p.details);
                    },
                    EventData::Http3FrameCreated(v) => {
                        printy!("id", v.stream_id, p.details);
                        printyo!("len", v.length, p.details);
                        p.details += &http_frame_to_string(&v.frame);
                    },
                    EventData::Http3FrameParsed(v) => {
                        printy!("id", v.stream_id, p.details);
                        printyo!("len", v.length, p.details);
                        p.details += &http_frame_to_string(&v.frame);
                    },

                    _ => {
                        p.details += &serde_json::to_string(&ev.data)?;
                    },
                }

                pp.push(p);
            },

            EventView::Json(ev) => {
                let (cat, ty) = category_and_type_from_name(&ev.name);

                let p = PrintableEvent {
                    time: ev.time,
                    ty,
                    category: cat,
                    details: serde_json::to_string(&ev.data)?,
                };

                pp.push(p);
            },
        }
    }

    Ok(Table::builder(pp))
}

/// Render native qlog JSON records without copying the event list.
pub fn qlog_event_list(
    events: &[qlog::events::Event],
) -> Result<tabled::builder::Builder, serde_json::Error> {
    qlog_event_rows(events.iter().map(EventView::Native))
}

/// Render both typed and extensible qlog JSON-SEQ records.
pub fn sqlog_event_list(
    events: &[qlog::reader::Event],
) -> Result<tabled::builder::Builder, serde_json::Error> {
    qlog_event_rows(events.iter().map(|event| match event {
        qlog::reader::Event::Qlog(event) => EventView::Native(event),
        qlog::reader::Event::Json(event) => EventView::Json(event),
    }))
}

/// Display exact identifiers and timestamps for the recognized, parsed
/// Chrome netlog events of one session (the netlog deserializer supports a
/// selected subset of Chromium event types).
pub fn netlog_event_list(
    events: &[(netlog::EventHeader, netlog::Event)],
) -> tabled::builder::Builder {
    #[derive(Tabled)]
    struct PrintableNetlogEvent {
        time: String,
        #[tabled(rename = "Type")]
        ty: String,
        phase: String,
        source_id: i64,
        details: String,
    }

    Table::builder(events.iter().map(|(header, event)| PrintableNetlogEvent {
        time: header.time.clone(),
        ty: header.ty_string.clone(),
        phase: header.phase_string.clone(),
        source_id: header.source.id,
        details: format!("{event:?}"),
    }))
}

/// Convert any of the three supported log formats into a report table.
pub fn event_list(
    raw: &crate::RawLogEvents,
) -> Result<tabled::builder::Builder, serde_json::Error> {
    match raw {
        crate::RawLogEvents::QlogJson { events } => qlog_event_list(events),
        crate::RawLogEvents::QlogJsonSeq { events } => sqlog_event_list(events),
        crate::RawLogEvents::Netlog { events } => Ok(netlog_event_list(events)),
    }
}

#[cfg(test)]
mod tests {
    use super::frames_to_string;
    use super::http_frame_to_string;
    use super::qlog_event_list;
    use qlog::events::quic::PacketHeader;
    use qlog::events::quic::PacketSent;
    use qlog::events::quic::PacketType;
    use qlog::events::quic::QuicFrame;
    use qlog::events::Event;
    use qlog::events::EventData;
    use serde_json::json;

    #[test]
    fn quic_frame_report_includes_connection_and_path_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let frames: Vec<QuicFrame> = serde_json::from_value(json!([
            {
                "frame_type": "new_connection_id",
                "sequence_number": 7,
                "retire_prior_to": 3,
                "connection_id_length": 2,
                "connection_id": "beef",
                "stateless_reset_token": "0123"
            },
            {"frame_type": "retire_connection_id", "sequence_number": 9},
            {"frame_type": "path_challenge", "data": "aabb"},
            {"frame_type": "path_response", "data": "ccdd"}
        ]))?;
        let printed = frames_to_string(&frames);
        for expected in [
            "sn=7",
            "retire_prior_to=3",
            "cid=\"beef\"",
            "reset_token=Some(\"0123\")",
            "RETIRE_CONNECTION_ID",
            "PATH_CHALLENGE {data=Some(\"aabb\")}",
            "PATH_RESPONSE {data=Some(\"ccdd\")}",
        ] {
            assert!(
                printed.contains(expected),
                "{expected} missing from {printed}"
            );
        }
        assert!(!printed.contains("todo"));
        Ok(())
    }

    #[test]
    fn http3_frame_report_includes_settings_push_and_priority_details(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let frames: Vec<qlog::events::http3::Http3Frame> =
            serde_json::from_value(json!([
                {"frame_type": "settings", "settings": [
                    {"name": "qpack_max_table_capacity", "value": 42}
                ]},
                {"frame_type": "push_promise", "push_id": 12, "headers": [
                    {"name": "x-test", "value": "abc"}
                ]},
                {"frame_type": "priority_update", "stream_id": 4,
                 "priority_field_value": "u=3"},
                {"frame_type": "reserved", "frame_type_bytes": 31}
            ]))?;
        let printed: String = frames.iter().map(http_frame_to_string).collect();
        for expected in [
            "SETTINGS",
            "qpack_max_table_capacity",
            "value: 42",
            "PUSH_PROMISE {push_id=12",
            "x-test",
            "abc",
            "PRIORITY_UPDATE {stream_id=Some(4)",
            "priority=\"u=3\"",
            "GREASE {ty=31}",
        ] {
            assert!(
                printed.contains(expected),
                "{expected} missing from {printed}"
            );
        }
        assert!(!printed.contains("todo"));
        Ok(())
    }

    #[test]
    fn event_report_uses_remote_connection_ids_and_fallible_packet_types(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let started: qlog::events::quic::ConnectionStarted =
            serde_json::from_value(json!({
                "local": {"connection_ids": ["local-cid"]},
                "remote": {"connection_ids": ["remote-cid"]}
            }))?;
        let sent = PacketSent {
            header: PacketHeader {
                packet_type: PacketType::OneRtt,
                ..Default::default()
            },
            ..Default::default()
        };
        let events = [
            Event::with_time(1.0, EventData::QuicConnectionStarted(started)),
            Event::with_time(2.0, EventData::QuicPacketSent(sent)),
        ];
        let table = qlog_event_list(&events)?.build().to_string();
        assert!(
            table.contains("local_cids=Some([\"local-cid\"])"),
            "{table}"
        );
        assert!(
            table.contains("remote_cids=Some([\"remote-cid\"])"),
            "{table}"
        );
        assert!(table.contains("1RTT"), "{table}");
        Ok(())
    }
}
