// Copyright (C) 2024, Cloudflare, Inc.
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

use crate::quiche;
use qlog::events::http3::FrameCreated;
use qlog::events::http3::Http3Frame;
use qlog::events::http3::HttpHeader;
use qlog::events::http3::Initiator;
use qlog::events::http3::Setting;
use qlog::events::http3::StreamType;
use qlog::events::http3::StreamTypeSet;
use qlog::events::quic::ErrorSpace;
use qlog::events::quic::PacketSent;
use qlog::events::quic::QuicFrame;
use qlog::events::Event;
use qlog::events::EventData;
use qlog::events::EventImportance;
use qlog::events::ExData;
use qlog::events::JsonEvent;
use qlog::events::RawInfo;
use quiche::h3::frame::Frame;
use quiche::h3::Header;
use quiche::h3::NameValue;

use serde_json::json;

use crate::actions::h3::Action;
use crate::actions::h3::ExpectedStreamSendResult;
use crate::actions::h3::WaitType;
use crate::client::ClientError;
use crate::fake_packet_sent;
use crate::HTTP3_CONTROL_STREAM_TYPE_ID;
use crate::HTTP3_PUSH_STREAM_TYPE_ID;
use crate::QPACK_DECODER_STREAM_TYPE_ID;
use crate::QPACK_ENCODER_STREAM_TYPE_ID;

/// A qlog event representation using either the official RFC format or a
/// custom JSON event.
pub enum QlogEvent {
    Event {
        data: Box<EventData>,
        ex_data: ExData,
    },
    JsonEvent(JsonEvent),
}

/// A collection of replay [`Action`]s.
pub struct H3Actions(pub Vec<Action>);

impl QlogEvent {
    fn standard(data: EventData, ex_data: ExData) -> Self {
        Self::Event {
            data: Box::new(data),
            ex_data,
        }
    }

    fn packet(frame: QuicFrame, ex_data: ExData) -> Self {
        Self::standard(fake_packet_sent(Some(vec![frame])), ex_data)
    }

    fn custom(name: &str, data: serde_json::Value) -> Self {
        Self::JsonEvent(JsonEvent {
            time: 0.0,
            importance: EventImportance::Core,
            name: name.to_owned(),
            data,
        })
    }

    /// Write the event using the streamer's timestamp and filtering policy.
    ///
    /// # Errors
    /// Returns an error if the event cannot be recorded.
    pub fn write(
        self, streamer: &mut qlog::streamer::QlogStreamer,
    ) -> qlog::Result<()> {
        match self {
            Self::Event { data, ex_data } =>
                streamer.add_event_data_ex_now(*data, ex_data),
            Self::JsonEvent(event) => streamer.add_event_now(event),
        }
    }
}

fn fin_extension(fin_stream: bool) -> ExData {
    if fin_stream {
        BTreeMap::from([("fin_stream".into(), json!(true))])
    } else {
        BTreeMap::new()
    }
}

fn frame_event(stream_id: u64, frame: Http3Frame, ex_data: ExData) -> QlogEvent {
    QlogEvent::standard(
        EventData::Http3FrameCreated(FrameCreated {
            stream_id,
            frame,
            ..FrameCreated::default()
        }),
        ex_data,
    )
}

fn record_frame(stream_id: u64, fin_stream: bool, frame: &Frame) -> QlogEvent {
    let payload = match frame {
        Frame::Data { payload } | Frame::Unknown { payload, .. } => Some(payload),
        Frame::Headers { header_block } |
        Frame::PushPromise { header_block, .. } => Some(header_block),
        Frame::PriorityUpdateRequest {
            priority_field_value,
            ..
        } |
        Frame::PriorityUpdatePush {
            priority_field_value,
            ..
        } => Some(priority_field_value),
        Frame::Settings { .. } |
        Frame::CancelPush { .. } |
        Frame::GoAway { .. } |
        Frame::MaxPushId { .. } => None,
    };
    let mut ex_data = fin_extension(fin_stream);
    if let Some(payload) = payload {
        ex_data.insert("h3i_payload".into(), json!(payload));
    }
    frame_event(stream_id, frame.to_qlog(), ex_data)
}

fn record_headers(
    stream_id: u64, fin_stream: bool, headers: &[Header], literal_headers: bool,
) -> QlogEvent {
    let mut ex_data = fin_extension(fin_stream);
    if literal_headers {
        ex_data.insert("literal_headers".into(), json!(true));
    }
    if headers.iter().any(|header| {
        std::str::from_utf8(header.name()).is_err() ||
            std::str::from_utf8(header.value()).is_err()
    }) {
        let bytes: Vec<_> = headers
            .iter()
            .map(|header| (header.name(), header.value()))
            .collect();
        ex_data.insert("h3i_headers".into(), json!(bytes));
    }
    let headers = headers
        .iter()
        .map(|header| HttpHeader {
            name: Some(String::from_utf8_lossy(header.name()).into_owned()),
            name_bytes: None,
            value: Some(String::from_utf8_lossy(header.value()).into_owned()),
            value_bytes: None,
        })
        .collect();
    frame_event(
        stream_id,
        Http3Frame::Headers { headers, raw: None },
        ex_data,
    )
}

fn record_uni_stream(
    stream_id: u64, fin_stream: bool, stream_type: u64,
) -> QlogEvent {
    let ty = match stream_type {
        HTTP3_CONTROL_STREAM_TYPE_ID => StreamType::Control,
        HTTP3_PUSH_STREAM_TYPE_ID => StreamType::Push,
        QPACK_ENCODER_STREAM_TYPE_ID => StreamType::QpackEncode,
        QPACK_DECODER_STREAM_TYPE_ID => StreamType::QpackDecode,
        _ => StreamType::Unknown,
    };
    let stream_type_bytes =
        matches!(ty, StreamType::Unknown).then_some(stream_type);
    QlogEvent::standard(
        EventData::Http3StreamTypeSet(StreamTypeSet {
            initiator: Some(Initiator::Local),
            stream_id,
            stream_type: ty,
            stream_type_bytes,
            ..StreamTypeSet::default()
        }),
        fin_extension(fin_stream),
    )
}

fn raw_info(payload: &[u8]) -> RawInfo {
    RawInfo {
        length: None,
        payload_length: Some(payload.len() as u64),
        data: std::str::from_utf8(payload)
            .ok()
            .map(|text| Box::new(text.to_owned())),
    }
}

fn payload_extension(payload: &[u8]) -> ExData {
    BTreeMap::from([("h3i_payload".into(), json!(payload))])
}

fn record_close(error: &quiche::ConnectionError) -> QlogEvent {
    let error_space = if error.is_app {
        ErrorSpace::Application
    } else {
        ErrorSpace::Transport
    };
    let reason = std::str::from_utf8(&error.reason)
        .ok()
        .filter(|reason| !reason.is_empty())
        .map(str::to_owned);
    let mut ex_data = BTreeMap::new();
    if reason.is_none() && !error.reason.is_empty() {
        ex_data.insert("h3i_reason".into(), json!(error.reason));
    }
    QlogEvent::packet(
        QuicFrame::ConnectionClose {
            error_space: Some(error_space),
            error: None,
            error_code: Some(error.error_code),
            reason,
            reason_bytes: None,
            trigger_frame_type: None,
        },
        ex_data,
    )
}

impl TryFrom<&Action> for QlogEvent {
    type Error = ClientError;

    fn try_from(action: &Action) -> Result<Self, Self::Error> {
        let mut event = match action {
            Action::SendFrame {
                stream_id,
                fin_stream,
                frame,
                ..
            } => record_frame(*stream_id, *fin_stream, frame),
            Action::SendHeadersFrame {
                stream_id,
                fin_stream,
                headers,
                literal_headers,
                ..
            } =>
                record_headers(*stream_id, *fin_stream, headers, *literal_headers),
            Action::OpenUniStream {
                stream_id,
                fin_stream,
                stream_type,
                ..
            } => record_uni_stream(*stream_id, *fin_stream, *stream_type),
            Action::StreamBytes {
                stream_id,
                fin_stream,
                bytes,
                ..
            } => Self::packet(
                QuicFrame::Stream {
                    stream_id: *stream_id,
                    fin: Some(*fin_stream),
                    offset: None,
                    raw: Some(Box::new(raw_info(bytes))),
                },
                payload_extension(bytes),
            ),
            Action::SendDatagram { payload } => Self::packet(
                QuicFrame::Datagram {
                    raw: Some(Box::new(raw_info(payload))),
                },
                payload_extension(payload),
            ),
            Action::ResetStream {
                stream_id,
                error_code,
            } => Self::packet(
                QuicFrame::ResetStream {
                    stream_id: *stream_id,
                    error: qlog::events::ApplicationError::Unknown,
                    error_code: Some(*error_code),
                    final_size: 0,
                    raw: None,
                },
                ExData::new(),
            ),
            Action::StopSending {
                stream_id,
                error_code,
            } => Self::packet(
                QuicFrame::StopSending {
                    stream_id: *stream_id,
                    error: qlog::events::ApplicationError::Unknown,
                    error_code: Some(*error_code),
                    raw: None,
                },
                ExData::new(),
            ),
            Action::Wait { wait_type } => Self::custom(
                "h3i:wait",
                serde_json::to_value(wait_type)
                    .map_err(|error| ClientError::Other(error.to_string()))?,
            ),
            Action::ConnectionClose { error } => record_close(error),
            Action::FlushPackets => Self::custom("h3i:flush_packets", json!({})),
        };
        record_expected_result(action, &mut event)?;
        Ok(event)
    }
}

fn record_expected_result(
    action: &Action, event: &mut QlogEvent,
) -> Result<(), ClientError> {
    let expected = match action {
        Action::SendFrame {
            expected_result, ..
        } |
        Action::SendHeadersFrame {
            expected_result, ..
        } |
        Action::OpenUniStream {
            expected_result, ..
        } |
        Action::StreamBytes {
            expected_result, ..
        } => Some(expected_result),
        _ => None,
    };
    if let (Some(expected), QlogEvent::Event { ex_data, .. }) = (expected, event)
    {
        if !matches!(expected, ExpectedStreamSendResult::Ok) {
            ex_data.insert(
                "h3i_expected_result".into(),
                serde_json::to_value(expected)
                    .map_err(|error| ClientError::Other(error.to_string()))?,
            );
        }
    }
    Ok(())
}

/// Convert a recorded event into replay actions, rejecting malformed action
/// data instead of executing a different action or panicking.
///
/// # Errors
/// Returns a client error when an action cannot be reconstructed from the
/// event.
pub fn actions_from_qlog(
    event: Event, host_override: Option<&str>,
) -> Result<H3Actions, ClientError> {
    match event.data {
        EventData::QuicPacketSent(ps) => packet_actions(&ps, &event.ex_data),
        EventData::Http3FrameCreated(fc) => Ok(H3Actions(vec![replay_frame(
            &fc,
            &event.ex_data,
            host_override,
        )?])),
        EventData::Http3StreamTypeSet(st) =>
            Ok(H3Actions(from_qlog_stream_type_set(&st, &event.ex_data)?)),
        _ => Ok(H3Actions(vec![])),
    }
}

impl TryFrom<JsonEvent> for H3Actions {
    type Error = ClientError;

    fn try_from(event: JsonEvent) -> Result<Self, Self::Error> {
        if event.name == "h3i:flush_packets" {
            return Ok(Self(vec![Action::FlushPackets]));
        }
        if event.name != "h3i:wait" {
            return Ok(Self(vec![]));
        }
        let wait_type =
            serde_json::from_value::<WaitType>(event.data).map_err(|error| {
                ClientError::Other(format!("invalid h3i wait: {error}"))
            })?;
        Ok(Self(vec![Action::Wait { wait_type }]))
    }
}

fn extension<T: serde::de::DeserializeOwned>(
    ex_data: &ExData, name: &str,
) -> Result<Option<T>, ClientError> {
    ex_data
        .get(name)
        .map(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                ClientError::Other(format!(
                    "invalid qlog extension {name}: {error}"
                ))
            })
        })
        .transpose()
}

fn packet_actions(
    ps: &PacketSent, ex_data: &ExData,
) -> Result<H3Actions, ClientError> {
    let mut actions = vec![];
    if let Some(frames) = &ps.frames {
        for frame in frames {
            match frame {
                QuicFrame::ResetStream {
                    stream_id,
                    error_code,
                    ..
                } => actions.push(Action::ResetStream {
                    stream_id: *stream_id,
                    error_code: error_code.ok_or_else(|| {
                        ClientError::Other(
                            "qlog stream close has no error code".into(),
                        )
                    })?,
                }),

                QuicFrame::StopSending {
                    stream_id,
                    error_code,
                    ..
                } => actions.push(Action::StopSending {
                    stream_id: *stream_id,
                    error_code: error_code.ok_or_else(|| {
                        ClientError::Other(
                            "qlog stream close has no error code".into(),
                        )
                    })?,
                }),

                QuicFrame::ConnectionClose {
                    error_space,
                    error_code,
                    reason,
                    ..
                } => {
                    let is_app = match error_space {
                        Some(ErrorSpace::Application) => true,
                        Some(ErrorSpace::Transport) => false,
                        None =>
                            return Err(ClientError::Other(
                                "qlog connection close has no error space".into(),
                            )),
                    };
                    let error_code = error_code.ok_or_else(|| {
                        ClientError::Other(
                            "qlog connection close has no error code".into(),
                        )
                    })?;
                    let reason = extension(ex_data, "h3i_reason")?
                        .unwrap_or_else(|| {
                            reason
                                .as_ref()
                                .map_or_else(Vec::new, |s| s.as_bytes().to_vec())
                        });
                    actions.push(Action::ConnectionClose {
                        error: quiche::ConnectionError {
                            is_app,
                            error_code,
                            reason,
                        },
                    });
                },

                QuicFrame::Stream { stream_id, fin, .. } => {
                    let fin_stream = fin.unwrap_or_default();
                    // Ordinary packet traces also contain H3 frame bytes. Only
                    // replay explicit h3i stream payloads, not retransmissions.
                    let payload = extension(ex_data, "h3i_payload")?;
                    if fin_stream || payload.is_some() {
                        actions.push(Action::StreamBytes {
                            stream_id: *stream_id,
                            fin_stream,
                            bytes: payload.unwrap_or_default(),
                            expected_result: extension(
                                ex_data,
                                "h3i_expected_result",
                            )?
                            .unwrap_or_default(),
                        });
                    }
                },
                QuicFrame::Datagram { raw, .. } => {
                    let payload = extension(ex_data, "h3i_payload")?
                        .or_else(|| {
                            raw.as_ref()
                                .and_then(|r| r.data.as_ref())
                                .map(|data| data.as_bytes().to_vec())
                        })
                        .ok_or_else(|| {
                            ClientError::Other(
                                "qlog datagram lacks payload bytes".into(),
                            )
                        })?;
                    actions.push(Action::SendDatagram { payload });
                },
                _ => (),
            }
        }
    }

    Ok(H3Actions(actions))
}

fn map_header(name: &[u8], value: &[u8], host_override: Option<&str>) -> Header {
    let value = if name.eq_ignore_ascii_case(b":authority") ||
        name.eq_ignore_ascii_case(b"host")
    {
        host_override.map_or(value, str::as_bytes)
    } else {
        value
    };
    Header::new(name, value)
}

fn replay_settings(settings: &[Setting]) -> Result<Frame, ClientError> {
    // All pairs are explicit on replay; semantic fields would normalize order,
    // remove duplicates and synthesize the legacy H3_DATAGRAM setting.
    let pairs = settings
        .iter()
        .map(|setting| {
            let name = setting.name.as_deref().unwrap_or("");
            let id = match name {
                "MAX_FIELD_SECTION_SIZE" => Some(0x6),
                "QPACK_MAX_TABLE_CAPACITY" => Some(0x1),
                "QPACK_BLOCKED_STREAMS" => Some(0x7),
                "SETTINGS_ENABLE_CONNECT_PROTOCOL" => Some(0x8),
                "H3_DATAGRAM" => Some(0x33),
                _ => setting.name_bytes.or_else(|| name.parse().ok()),
            }
            .ok_or_else(|| {
                ClientError::Other(format!("unknown qlog setting {name:?}"))
            })?;
            Ok((id, setting.value))
        })
        .collect::<Result<Vec<_>, ClientError>>()?;
    Ok(Frame::Settings {
        max_field_section_size: None,
        qpack_max_table_capacity: None,
        qpack_blocked_streams: None,
        connect_protocol_enabled: None,
        h3_datagram: None,
        grease: None,
        raw: None,
        additional_settings: Some(pairs),
    })
}

fn replay_headers(
    headers: &[HttpHeader], ex_data: &ExData, host_override: Option<&str>,
) -> Result<Vec<Header>, ClientError> {
    let raw_headers: Option<Vec<(Vec<u8>, Vec<u8>)>> =
        extension(ex_data, "h3i_headers")?;
    Ok(raw_headers.map_or_else(
        || {
            headers
                .iter()
                .map(|header| {
                    map_header(
                        header.name.as_deref().unwrap_or("").as_bytes(),
                        header.value.as_deref().unwrap_or("").as_bytes(),
                        host_override,
                    )
                })
                .collect()
        },
        |raw_headers| {
            raw_headers
                .iter()
                .map(|(name, value)| map_header(name, value, host_override))
                .collect()
        },
    ))
}

fn payload_from_raw(
    payload: Option<Vec<u8>>, raw: Option<&RawInfo>,
) -> Result<Vec<u8>, ClientError> {
    payload
        .or_else(|| {
            raw.and_then(|raw| raw.data.as_ref())
                .map(|data| data.as_bytes().to_vec())
        })
        .ok_or_else(|| {
            ClientError::Other("qlog frame lacks payload bytes".into())
        })
}

fn replay_priority(
    request_id: Option<u64>, push_id: Option<u64>, value: Vec<u8>,
) -> Result<Frame, ClientError> {
    match (request_id, push_id) {
        (Some(id), None) => Ok(Frame::PriorityUpdateRequest {
            prioritized_element_id: id,
            priority_field_value: value,
        }),
        (None, Some(id)) => Ok(Frame::PriorityUpdatePush {
            prioritized_element_id: id,
            priority_field_value: value,
        }),
        _ => Err(ClientError::Other(
            "qlog priority update requires exactly one element ID".into(),
        )),
    }
}

fn replay_frame(
    created: &FrameCreated, ex_data: &ExData, host_override: Option<&str>,
) -> Result<Action, ClientError> {
    let stream_id = created.stream_id;
    let fin_stream = extension(ex_data, "fin_stream")?.unwrap_or_default();
    let payload: Option<Vec<u8>> = extension(ex_data, "h3i_payload")?;
    let frame = match &created.frame {
        Http3Frame::Settings { settings, .. } => replay_settings(settings)?,
        Http3Frame::Headers { headers, .. } => {
            if let Some(header_block) = payload {
                Frame::Headers { header_block }
            } else {
                return Ok(Action::SendHeadersFrame {
                    stream_id,
                    fin_stream,
                    literal_headers: extension(ex_data, "literal_headers")?
                        .unwrap_or_default(),
                    headers: replay_headers(headers, ex_data, host_override)?,
                    expected_result: extension(ex_data, "h3i_expected_result")?
                        .unwrap_or_default(),
                });
            }
        },
        Http3Frame::Data { raw } => Frame::Data {
            payload: payload_from_raw(payload, raw.as_ref())?,
        },
        Http3Frame::Goaway { id, .. } => Frame::GoAway { id: *id },
        Http3Frame::CancelPush { push_id, .. } =>
            Frame::CancelPush { push_id: *push_id },
        Http3Frame::MaxPushId { push_id, .. } =>
            Frame::MaxPushId { push_id: *push_id },
        Http3Frame::PriorityUpdate {
            stream_id: request_id,
            push_id,
            priority_field_value,
            ..
        } => replay_priority(
            *request_id,
            *push_id,
            payload.unwrap_or_else(|| priority_field_value.as_bytes().to_vec()),
        )?,
        Http3Frame::Reserved {
            frame_type_bytes,
            raw,
        } |
        Http3Frame::Unknown {
            frame_type_bytes,
            raw,
        } => Frame::Unknown {
            raw_type: *frame_type_bytes,
            payload: payload_from_raw(payload, raw.as_ref())?,
        },
        Http3Frame::PushPromise { push_id, .. } => Frame::PushPromise {
            push_id: *push_id,
            header_block: payload.ok_or_else(|| {
                ClientError::Other(
                    "qlog push promise lacks the encoded QPACK block".into(),
                )
            })?,
        },
    };
    Ok(Action::SendFrame {
        stream_id,
        fin_stream,
        frame,
        expected_result: extension(ex_data, "h3i_expected_result")?
            .unwrap_or_default(),
    })
}

fn from_qlog_stream_type_set(
    st: &StreamTypeSet, ex_data: &ExData,
) -> Result<Vec<Action>, ClientError> {
    let mut actions = vec![];
    if matches!(st.initiator, Some(Initiator::Remote)) {
        return Ok(actions);
    }
    let fin_stream = extension(ex_data, "fin_stream")?.unwrap_or_default();
    let stream_type = match st.stream_type {
        StreamType::Control => Some(0x0),
        StreamType::Push => Some(0x1),
        StreamType::QpackEncode => Some(0x2),
        StreamType::QpackDecode => Some(0x3),
        StreamType::Reserved | StreamType::Unknown => st.stream_type_bytes,
        StreamType::Request => None,
    };

    if let Some(ty) = stream_type {
        actions.push(Action::OpenUniStream {
            stream_id: st.stream_id,
            fin_stream,
            stream_type: ty,
            expected_result: extension(ex_data, "h3i_expected_result")?
                .unwrap_or_default(),
        });
    }

    Ok(actions)
}

#[cfg(test)]
mod tests {
    use crate::actions::h3::StreamEvent;
    use crate::actions::h3::StreamEventType;
    use std::time::Duration;

    use super::actions_from_qlog;
    use super::Action;
    use super::Event;
    use super::ExpectedStreamSendResult;
    use super::Frame;
    use super::H3Actions;
    use super::Header;
    use super::JsonEvent;
    use super::QlogEvent;
    use super::WaitType;
    use crate::quiche;

    const NOW: f64 = 123.0;
    const H3I_WAIT: &str = "h3i:wait";

    #[test]
    fn ser_duration_wait() -> Result<(), Box<dyn std::error::Error>> {
        let ev = JsonEvent {
            time: NOW,
            importance: qlog::events::EventImportance::Core,
            name: H3I_WAIT.to_string(),
            data: serde_json::to_value(WaitType::WaitDuration(
                Duration::from_millis(12345),
            ))?,
        };
        let serialized = serde_json::to_string(&ev);

        let expected =
            r#"{"time":123.0,"name":"h3i:wait","data":{"duration":12345.0}}"#;
        assert_eq!(serialized?, expected);
        Ok(())
    }

    #[test]
    fn deser_duration_wait() -> Result<(), Box<dyn std::error::Error>> {
        let ev = JsonEvent {
            time: NOW,
            importance: qlog::events::EventImportance::Core,
            name: H3I_WAIT.to_string(),
            data: serde_json::to_value(WaitType::WaitDuration(
                Duration::from_millis(12345),
            ))?,
        };

        let expected =
            r#"{"time":123.0,"name":"h3i:wait","data":{"duration":12345.0}}"#;
        let deser = serde_json::from_str::<JsonEvent>(expected)?;
        assert_eq!(deser.data, ev.data);
        Ok(())
    }

    #[test]
    fn ser_stream_wait() -> Result<(), Box<dyn std::error::Error>> {
        let expected = r#"{"time":123.0,"name":"h3i:wait","data":{"StreamEvent":{"stream_id":0,"type":"data"}}}"#;
        let ev = JsonEvent {
            time: NOW,
            importance: qlog::events::EventImportance::Core,
            name: H3I_WAIT.to_string(),
            data: serde_json::to_value(WaitType::StreamEvent(StreamEvent {
                stream_id: 0,
                event_type: StreamEventType::Data,
            }))?,
        };

        let serialized = serde_json::to_string(&ev);
        assert_eq!(serialized?, expected);
        Ok(())
    }

    #[test]
    fn deser_stream_wait() -> Result<(), Box<dyn std::error::Error>> {
        let ev = JsonEvent {
            time: NOW,
            importance: qlog::events::EventImportance::Core,
            name: H3I_WAIT.to_string(),
            data: serde_json::to_value(WaitType::StreamEvent(StreamEvent {
                stream_id: 0,
                event_type: StreamEventType::Data,
            }))?,
        };

        let expected = r#"{"time":123.0,"name":"h3i:wait","data":{"StreamEvent":{"stream_id":0,"type":"data"}}}"#;
        let deser = serde_json::from_str::<JsonEvent>(expected)?;
        assert_eq!(deser.data, ev.data);
        Ok(())
    }

    #[test]
    fn deser_http_headers_to_action() -> Result<(), Box<dyn std::error::Error>> {
        let serialized = r#"{"time":0.074725,"name":"http3:frame_created","data":{"stream_id":0,"frame":{"frame_type":"headers","headers":[{"name":":method","value":"GET"},{"name":":authority","value":"example.net"},{"name":":path","value":"/"},{"name":":scheme","value":"https"}]}},"fin_stream":true}"#;
        let deserialized = serde_json::from_str::<Event>(serialized)?;
        let actions = actions_from_qlog(deserialized, None)?;
        assert_eq!(actions.0.len(), 1);

        let headers = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":authority", b"example.net"),
            Header::new(b":path", b"/"),
            Header::new(b":scheme", b"https"),
        ];
        let expected = Action::SendHeadersFrame {
            stream_id: 0,
            fin_stream: true,
            literal_headers: false,
            headers,
            expected_result: ExpectedStreamSendResult::default(),
        };

        assert_eq!(actions.0, vec![expected]);
        Ok(())
    }

    #[test]
    fn deser_http_headers_host_overrid_to_action(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = r#"{"time":0.074725,"name":"http3:frame_created","data":{"stream_id":0,"frame":{"frame_type":"headers","headers":[{"name":":method","value":"GET"},{"name":":authority","value":"bla.com"},{"name":":path","value":"/"},{"name":":scheme","value":"https"}]}},"fin_stream":true}"#;
        let deserialized = serde_json::from_str::<Event>(serialized)?;
        let actions = actions_from_qlog(deserialized, Some("example.org"))?;
        assert_eq!(actions.0.len(), 1);

        let headers = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":authority", b"example.org"),
            Header::new(b":path", b"/"),
            Header::new(b":scheme", b"https"),
        ];
        let expected = Action::SendHeadersFrame {
            stream_id: 0,
            fin_stream: true,
            literal_headers: false,
            headers,
            expected_result: ExpectedStreamSendResult::default(),
        };

        assert_eq!(actions.0, vec![expected]);
        Ok(())
    }

    #[test]
    fn deser_http_headers_literal_to_action(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = r#"{"time":0.074725,"name":"http3:frame_created","data":{"stream_id":0,"frame":{"frame_type":"headers","headers":[{"name":":method","value":"GET"},{"name":":authority","value":"bla.com"},{"name":":path","value":"/"},{"name":":scheme","value":"https"},{"name":"Foo","value":"bar"}]}},"fin_stream":true,"literal_headers":true}"#;
        let deserialized = serde_json::from_str::<Event>(serialized)?;
        let actions = actions_from_qlog(deserialized, None)?;
        assert_eq!(actions.0.len(), 1);

        let headers = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":authority", b"bla.com"),
            Header::new(b":path", b"/"),
            Header::new(b":scheme", b"https"),
            Header::new(b"Foo", b"bar"),
        ];
        let expected = Action::SendHeadersFrame {
            stream_id: 0,
            fin_stream: true,
            literal_headers: true,
            headers,
            expected_result: ExpectedStreamSendResult::default(),
        };

        assert_eq!(actions.0, vec![expected]);
        Ok(())
    }

    fn replay(
        action: &Action,
    ) -> Result<Vec<Action>, Box<dyn std::error::Error>> {
        let replayed = match QlogEvent::try_from(action)? {
            QlogEvent::Event { data, ex_data } => {
                let event = Event::with_time_ex(NOW, *data, ex_data);
                let event =
                    serde_json::from_str(&serde_json::to_string(&event)?)?;
                actions_from_qlog(event, None)?
            },
            QlogEvent::JsonEvent(event) => {
                let event = serde_json::from_str::<JsonEvent>(
                    &serde_json::to_string(&event)?,
                )?;
                H3Actions::try_from(event)?
            },
        };
        Ok(replayed.0)
    }

    #[test]
    fn replay_preserves_frame_variants() -> Result<(), Box<dyn std::error::Error>>
    {
        let frames = [
            Frame::Data {
                payload: vec![0, 255, 128],
            },
            Frame::Headers {
                header_block: vec![0, 255, 128],
            },
            Frame::PushPromise {
                push_id: 9,
                header_block: vec![0, 255, 128],
            },
            Frame::CancelPush { push_id: 7 },
            Frame::MaxPushId { push_id: 17 },
            Frame::GoAway { id: 12 },
            Frame::Unknown {
                raw_type: 42,
                payload: vec![0, 255, 128],
            },
            Frame::PriorityUpdateRequest {
                prioritized_element_id: 0,
                priority_field_value: vec![255],
            },
            Frame::PriorityUpdatePush {
                prioritized_element_id: 1,
                priority_field_value: vec![255],
            },
        ];
        for frame in frames {
            let action = Action::SendFrame {
                stream_id: 0,
                fin_stream: true,
                frame,
                expected_result: ExpectedStreamSendResult::default(),
            };
            assert_eq!(replay(&action)?, vec![action]);
        }

        Ok(())
    }

    #[test]
    fn replay_preserves_other_actions_and_waits(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::actions::h3::RequiredStreamsQuota;
        for action in [
            Action::SendHeadersFrame {
                stream_id: 0,
                fin_stream: false,
                literal_headers: true,
                headers: vec![Header::new(b"x-binary", &[0, 255, 128])],
                expected_result: ExpectedStreamSendResult::default(),
            },
            Action::StreamBytes {
                stream_id: 0,
                fin_stream: false,
                bytes: vec![0, 255, 128],
                expected_result: ExpectedStreamSendResult::default(),
            },
            Action::StreamBytes {
                stream_id: 0,
                fin_stream: true,
                bytes: vec![],
                expected_result: ExpectedStreamSendResult::default(),
            },
            Action::SendDatagram {
                payload: vec![0, 255, 128],
            },
            Action::ConnectionClose {
                error: quiche::ConnectionError {
                    is_app: false,
                    error_code: 12,
                    reason: vec![0, 255, 128],
                },
            },
            Action::OpenUniStream {
                stream_id: 2,
                stream_type: 123,
                fin_stream: false,
                expected_result: ExpectedStreamSendResult::default(),
            },
            Action::ResetStream {
                stream_id: 4,
                error_code: 99,
            },
            Action::StopSending {
                stream_id: 4,
                error_code: 99,
            },
            Action::Wait {
                wait_type: WaitType::WaitDuration(Duration::from_millis(123)),
            },
            Action::Wait {
                wait_type: WaitType::StreamEvent(StreamEvent {
                    stream_id: 4,
                    event_type: StreamEventType::Data,
                }),
            },
            Action::Wait {
                wait_type: WaitType::CanOpenNumStreams(RequiredStreamsQuota {
                    num: 2,
                    bidi: true,
                }),
            },
            Action::FlushPackets,
        ] {
            assert_eq!(replay(&action)?, vec![action]);
        }
        Ok(())
    }

    #[test]
    fn replay_preserves_nondefault_send_expectations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for expected_result in [
            ExpectedStreamSendResult::OkExact(19),
            ExpectedStreamSendResult::Error(quiche::Error::StreamStopped(0x102)),
            ExpectedStreamSendResult::Error(quiche::Error::InvalidStreamState(
                32,
            )),
            ExpectedStreamSendResult::Error(quiche::Error::Done),
        ] {
            for action in [
                Action::SendFrame {
                    stream_id: 0,
                    fin_stream: false,
                    frame: Frame::Data { payload: vec![1] },
                    expected_result: expected_result.clone(),
                },
                Action::SendHeadersFrame {
                    stream_id: 4,
                    fin_stream: true,
                    literal_headers: false,
                    headers: vec![Header::new(b"x", b"y")],
                    expected_result: expected_result.clone(),
                },
                Action::StreamBytes {
                    stream_id: 8,
                    fin_stream: false,
                    bytes: vec![2],
                    expected_result: expected_result.clone(),
                },
                Action::OpenUniStream {
                    stream_id: 2,
                    fin_stream: false,
                    stream_type: 0,
                    expected_result,
                },
            ] {
                assert_eq!(replay(&action)?, vec![action]);
            }
        }
        Ok(())
    }

    #[test]
    fn replay_preserves_settings_wire_order_and_known_ids(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let frame = Frame::Settings {
            max_field_section_size: Some(123),
            qpack_max_table_capacity: None,
            qpack_blocked_streams: Some(1),
            connect_protocol_enabled: None,
            h3_datagram: Some(1),
            grease: Some((33, 7)),
            raw: None,
            additional_settings: Some(vec![(6, 42), (0x70, 3)]),
        };
        let expected = frame.to_vec()?;
        let actions = replay(&Action::SendFrame {
            stream_id: 2,
            fin_stream: false,
            frame,
            expected_result: ExpectedStreamSendResult::default(),
        })?;
        assert!(
            matches!(actions.as_slice(), [Action::SendFrame { frame, .. }] if frame.to_vec().is_ok_and(|wire| wire == expected))
        );
        Ok(())
    }

    #[test]
    fn invalid_actions_fail_without_panicking(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for json in [
            r#"{"time":0.0,"name":"http3:frame_created","data":{"stream_id":0,"frame":{"frame_type":"data"}}}"#,
            r#"{"time":0.0,"name":"http3:frame_created","data":{"stream_id":0,"frame":{"frame_type":"priority_update","priority_field_value":"u=1"}}}"#,
        ] {
            let event = serde_json::from_str::<Event>(json)?;
            assert!(actions_from_qlog(event, None).is_err());
        }

        let event = serde_json::from_str::<JsonEvent>(
            r#"{"time":0.0,"name":"h3i:wait","data":{}}"#,
        )?;
        assert!(H3Actions::try_from(event).is_err());

        let event = serde_json::from_str::<JsonEvent>(
            r#"{"time":0.0,"name":"other:event","data":{}}"#,
        )?;
        assert_eq!(H3Actions::try_from(event)?.0, Vec::<Action>::new());
        Ok(())
    }
}
