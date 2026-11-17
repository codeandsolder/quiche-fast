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

use qlog::events::quic::QuicFrame;
use qlog::events::EventData;
use qlog::reader::Event;
use std::iter::FromIterator;
use wirefilter::ExecutionContext;
use wirefilter::Scheme;
use wirefilter::TypedArray;

use crate::category_and_type_from_event;

/// Errors that can occur when parsing or executing a SQLOG filter.
#[derive(Debug)]
pub enum FilterError {
    InvalidExpression(String),
    InvalidStreamId(u64),
    Execution(String),
    EventEncoding(String),
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidExpression(error) => {
                write!(f, "invalid qlog wirefilter expression: {error}")
            },
            Self::InvalidStreamId(id) => {
                write!(
                    f,
                    "stream ID {id} cannot be represented by a filter integer"
                )
            },
            Self::Execution(error) =>
                write!(f, "qlog filter execution failed: {error}"),
            Self::EventEncoding(error) =>
                write!(f, "qlog event metadata serialization failed: {error}"),
        }
    }
}

impl std::error::Error for FilterError {}

fn checked_stream_id(id: u64) -> Result<i64, FilterError> {
    i64::try_from(id).map_err(|_| FilterError::InvalidStreamId(id))
}

fn stream_ids(event: &Event) -> Result<TypedArray<'_, i64>, FilterError> {
    let mut ids: TypedArray<i64> = TypedArray::new();

    match event {
        Event::Qlog(event) => match &event.data {
            EventData::QuicStreamDataMoved(v) =>
                if let Some(id) = v.stream_id {
                    ids.push(checked_stream_id(id)?);
                },
            EventData::QuicPacketSent(v) => {
                if let Some(frames) = &v.frames {
                    for frame in frames {
                        match frame {
                            QuicFrame::ResetStream { stream_id, .. } =>
                                ids.push(checked_stream_id(*stream_id)?),
                            QuicFrame::StopSending { stream_id, .. } =>
                                ids.push(checked_stream_id(*stream_id)?),
                            QuicFrame::Stream { stream_id, .. } =>
                                ids.push(checked_stream_id(*stream_id)?),
                            QuicFrame::MaxStreamData { stream_id, .. } =>
                                ids.push(checked_stream_id(*stream_id)?),
                            QuicFrame::StreamDataBlocked {
                                stream_id, ..
                            } => ids.push(checked_stream_id(*stream_id)?),

                            // other frames are not related to streams
                            _ => (),
                        }
                    }
                }
            },
            EventData::Http3StreamTypeSet(v) => {
                ids.push(checked_stream_id(v.stream_id)?);
            },
            EventData::Http3FrameCreated(v) => {
                ids.push(checked_stream_id(v.stream_id)?);
            },
            EventData::Http3FrameParsed(v) => {
                ids.push(checked_stream_id(v.stream_id)?);
            },

            // other events are not related to streams
            _ => (),
        },

        // TODO: try and fuzzy extract stream id
        Event::Json(_event) => {},
    }

    Ok(ids)
}

/// Filters SQLOG events by a Wirefilter expression.
///
/// # Errors
/// Returns a descriptive error when the filter expression is invalid or when
/// the filter's runtime scheme cannot be populated or evaluated.
pub fn filter_sqlog_events(
    events: Vec<Event>, filter: &str,
) -> Result<Vec<Event>, FilterError> {
    let scheme = Scheme! {
        category: Bytes,
        name: Bytes,
        stream_id: Array(Int),
    }
    .build();
    let ast = scheme
        .parse(filter)
        .map_err(|error| FilterError::InvalidExpression(error.to_string()))?;
    let compiled = ast.compile();

    let category_field = scheme
        .get_field("category")
        .map_err(|error| FilterError::Execution(error.to_string()))?;
    let name_field = scheme
        .get_field("name")
        .map_err(|error| FilterError::Execution(error.to_string()))?;
    let stream_id_field = scheme
        .get_field("stream_id")
        .map_err(|error| FilterError::Execution(error.to_string()))?;

    let mut matched = Vec::new();
    for event in events {
        // Each event needs an independent context with event-scoped values.
        let mut ctx = ExecutionContext::new(&scheme);
        let (category, name) = match &event {
            Event::Qlog(event) => category_and_type_from_event(event),
            Event::Json(event) => category_and_type_from_event(event),
        }
        .map_err(|error| FilterError::EventEncoding(error.to_string()))?;
        ctx.set_field_value(category_field, category)
            .map_err(|error| FilterError::Execution(error.to_string()))?;
        ctx.set_field_value(name_field, name)
            .map_err(|error| FilterError::Execution(error.to_string()))?;
        ctx.set_field_value(stream_id_field, stream_ids(&event)?)
            .map_err(|error| FilterError::Execution(error.to_string()))?;

        if compiled
            .execute(&ctx)
            .map_err(|error| FilterError::Execution(error.to_string()))?
        {
            matched.push(event);
        }
    }

    Ok(matched)
}
#[cfg(test)]
mod tests {
    use crate::wirefilter::filter_sqlog_events;
    use qlog::events::quic::PacketHeader;
    use qlog::events::quic::PacketSent;
    use qlog::events::quic::PacketType::Initial;
    use qlog::events::quic::QuicFrame;
    use qlog::events::EventData::QuicPacketSent;
    use qlog::events::RawInfo;
    use qlog::reader::Event;

    fn stream_frame(stream_id: u64) -> QuicFrame {
        QuicFrame::Stream {
            stream_id,
            offset: Some(0),
            fin: Some(true),
            raw: Some(Box::new(RawInfo {
                length: None,
                payload_length: Some(10),
                data: None,
            })),
        }
    }

    // Events are not cloneable in this qlog version, so use a helper.
    fn events() -> Vec<Event> {
        let mut events = vec![];
        let scid = [0x7e, 0x37, 0xe4, 0xdc, 0xc6, 0x68, 0x2d, 0xa8];
        let dcid = [0x36, 0xce, 0x10, 0x4e, 0xee, 0x50, 0x10, 0x1c];
        let pkt_hdr = PacketHeader::new(
            Initial,
            Some(0),
            None,
            None,
            Some(1),
            Some(&scid),
            Some(&dcid),
        );
        let raw = RawInfo {
            length: None,
            payload_length: Some(0),
            data: None,
        };

        let frames = vec![
            QuicFrame::Crypto {
                offset: 0,
                raw: Some(Box::new(raw)),
            },
            stream_frame(1),
            stream_frame(2),
            stream_frame(3),
            stream_frame(4),
            stream_frame(5),
        ];

        let raw = RawInfo {
            length: Some(1251),
            payload_length: Some(1224),
            data: None,
        };

        let event_data = QuicPacketSent(PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(frames),
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(raw.clone()),
            datagram_id: None,
            is_mtu_probe_packet: None,
            send_at_time: None,
            trigger: None,
        });

        events.push(Event::Qlog(qlog::events::Event::with_time(0.0, event_data)));

        let frames = vec![
            stream_frame(0),
            stream_frame(100),
            stream_frame(200),
            stream_frame(300),
            stream_frame(400),
        ];

        let event_data = QuicPacketSent(PacketSent {
            header: pkt_hdr.clone(),
            frames: Some(frames),
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(raw.clone()),
            datagram_id: None,
            is_mtu_probe_packet: None,
            send_at_time: None,
            trigger: None,
        });

        events.push(Event::Qlog(qlog::events::Event::with_time(0.0, event_data)));

        let frames = vec![
            stream_frame(1),
            stream_frame(100),
            stream_frame(2),
            stream_frame(200),
        ];

        let event_data = QuicPacketSent(PacketSent {
            header: pkt_hdr,
            frames: Some(frames),
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(raw),
            datagram_id: None,
            is_mtu_probe_packet: None,
            send_at_time: None,
            trigger: None,
        });

        events.push(Event::Qlog(qlog::events::Event::with_time(0.0, event_data)));

        events
    }

    #[test]
    fn valid_large_stream_id_remains_exact() {
        let mut entries = events();
        let stream_id = (1_u64 << 62) - 1;
        if let Event::Qlog(ref mut event) = entries[0] {
            if let QuicPacketSent(ref mut packet) = event.data {
                packet.frames = Some(vec![stream_frame(stream_id)]);
            }
        }
        let query = format!("any(stream_id[*] == {stream_id})");
        let filtered = filter_sqlog_events(entries, &query).unwrap();
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn out_of_range_stream_id_is_rejected_instead_of_wrapping_negative() {
        let mut entries = events();
        if let Event::Qlog(ref mut event) = entries[0] {
            if let QuicPacketSent(ref mut packet) = event.data {
                packet.frames = Some(vec![stream_frame(u64::MAX)]);
            }
        }
        assert!(filter_sqlog_events(entries, "any(stream_id[*] == -1)").is_err());
    }

    #[test]
    fn malformed_filter_returns_error_without_panicking() {
        let err = filter_sqlog_events(events(), "any(stream_id[*] ==")
            .err()
            .map(|error| error.to_string());
        assert!(
            err.is_some_and(|error| error.contains("invalid qlog wirefilter"))
        );
    }

    #[test]
    fn test_stream_id_filter_no_match() {
        let events = events();
        assert_eq!(events.len(), 3);

        let filter = "any(stream_id[*]==13)";
        let filtered_events = filter_sqlog_events(events, filter).unwrap();
        assert!(filtered_events.is_empty());
    }

    #[test]
    fn test_stream_id_filter_stream0() {
        let events = events();
        assert_eq!(events.len(), 3);

        let filter = "any(stream_id[*]==0)";
        let filtered_events = filter_sqlog_events(events, filter).unwrap();
        assert_eq!(filtered_events.len(), 1);

        let ev = &filtered_events[0];
        match ev {
            Event::Qlog(event) => {
                // assert_eq!
                match &event.data {
                    QuicPacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(vec![
                                stream_frame(0),
                                stream_frame(100),
                                stream_frame(200),
                                stream_frame(300),
                                stream_frame(400),
                            ])
                        );
                    },
                    _ => panic!("unexpected event data"),
                }
            },
            Event::Json(_json_event) => panic!("unexpected type"),
        }
    }

    #[test]
    fn test_stream_id_filter_stream1() {
        let events = events();
        assert_eq!(events.len(), 3);

        let filter = "any(stream_id[*]==1)";
        let filtered_events = filter_sqlog_events(events, filter).unwrap();
        assert_eq!(filtered_events.len(), 2);

        let ev = &filtered_events[0];

        let raw = RawInfo {
            length: None,
            payload_length: Some(0),
            data: None,
        };

        match ev {
            Event::Qlog(event) => match &event.data {
                QuicPacketSent(packet_sent) => {
                    assert_eq!(
                        packet_sent.frames,
                        Some(vec![
                            QuicFrame::Crypto {
                                offset: 0,
                                raw: Some(Box::new(raw)),
                            },
                            stream_frame(1),
                            stream_frame(2),
                            stream_frame(3),
                            stream_frame(4),
                            stream_frame(5),
                        ])
                    );
                },
                _ => panic!("unexpected event data"),
            },
            Event::Json(_json_event) => panic!("unexpected type"),
        }

        let ev = &filtered_events[1];
        match ev {
            Event::Qlog(event) => {
                // assert_eq!
                match &event.data {
                    QuicPacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(vec![
                                stream_frame(1),
                                stream_frame(100),
                                stream_frame(2),
                                stream_frame(200),
                            ])
                        );
                    },
                    _ => panic!("unexpected event data"),
                }
            },
            Event::Json(_json_event) => panic!("unexpected type"),
        }
    }

    #[test]
    fn test_stream_id_filter_stream0_and_stream3() {
        let events = events();
        assert_eq!(events.len(), 3);

        let filter = "any(stream_id[*]==0) || any(stream_id[*]==3)";
        let filtered_events = filter_sqlog_events(events, filter).unwrap();
        assert_eq!(filtered_events.len(), 2);

        let raw = RawInfo {
            length: None,
            payload_length: Some(0),
            data: None,
        };

        let ev = &filtered_events[0];
        match ev {
            Event::Qlog(event) => {
                // assert_eq!
                match &event.data {
                    QuicPacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(vec![
                                QuicFrame::Crypto {
                                    offset: 0,
                                    raw: Some(Box::new(raw)),
                                },
                                stream_frame(1),
                                stream_frame(2),
                                stream_frame(3),
                                stream_frame(4),
                                stream_frame(5),
                            ])
                        );
                    },
                    _ => panic!("unexpected event data"),
                }
            },
            Event::Json(_json_event) => panic!("unexpected type"),
        }

        let ev = &filtered_events[1];
        match ev {
            Event::Qlog(event) => {
                // assert_eq!
                match &event.data {
                    QuicPacketSent(packet_sent) => {
                        assert_eq!(
                            packet_sent.frames,
                            Some(vec![
                                stream_frame(0),
                                stream_frame(100),
                                stream_frame(200),
                                stream_frame(300),
                                stream_frame(400),
                            ])
                        );
                    },
                    _ => panic!("unexpected event data"),
                }
            },
            Event::Json(_json_event) => panic!("unexpected type"),
        }
    }
}
