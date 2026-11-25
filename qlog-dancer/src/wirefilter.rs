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

use qlog::events::http3::Http3Frame;
use qlog::events::quic::QuicFrame;
use qlog::events::EventData;
use qlog::reader::Event;
use std::iter::FromIterator;
use wirefilter::ExecutionContext;
use wirefilter::Scheme;
use wirefilter::TypedArray;

use crate::category_and_type_from_event;
use crate::category_and_type_from_name;

/// Errors that can occur when parsing or executing a SQLOG filter.
#[derive(Debug)]
pub enum FilterError {
    InvalidExpression(String),
    InvalidStreamId(u64),
    InvalidQuarterStreamId(u64),
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
            Self::InvalidQuarterStreamId(id) => write!(f, "quarter stream ID {id} cannot be represented by a filter integer"),
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

const fn frame_stream_id(frame: &QuicFrame) -> Option<u64> {
    match frame {
        QuicFrame::ResetStream { stream_id, .. } |
        QuicFrame::StopSending { stream_id, .. } |
        QuicFrame::Stream { stream_id, .. } |
        QuicFrame::MaxStreamData { stream_id, .. } |
        QuicFrame::StreamDataBlocked { stream_id, .. } => Some(*stream_id),
        _ => None,
    }
}

const fn priority_target(frame: &Http3Frame) -> Option<u64> {
    match frame {
        Http3Frame::PriorityUpdate { stream_id, .. } => *stream_id,
        _ => None,
    }
}

fn quarter_to_stream_id(id: u64) -> Result<u64, FilterError> {
    id.checked_mul(4)
        .filter(|value| i64::try_from(*value).is_ok())
        .ok_or(FilterError::InvalidQuarterStreamId(id))
}

fn native_stream_ids(
    data: &EventData,
) -> Result<TypedArray<'_, i64>, FilterError> {
    let mut ids = TypedArray::new();
    let mut add = |id| {
        ids.push(checked_stream_id(id)?);
        Ok::<(), FilterError>(())
    };
    if let Some(frames) = data.quic_frames() {
        for id in frames.iter().filter_map(frame_stream_id) {
            add(id)?;
        }
    }
    match data {
        EventData::QuicStreamDataMoved(event) => {
            if let Some(id) = event.stream_id {
                add(id)?;
            }
        },
        EventData::QuicStreamStateUpdated(event) => add(event.stream_id)?,
        EventData::QuicStreamDataBlockedUpdated(event) => add(event.stream_id)?,
        EventData::Http3StreamTypeSet(event) => add(event.stream_id)?,
        EventData::Http3PriorityUpdated(event) => {
            if let Some(id) = event.stream_id {
                add(id)?;
            }
        },
        EventData::Http3FrameCreated(event) => {
            add(event.stream_id)?;
            if let Some(id) = priority_target(&event.frame) {
                add(id)?;
            }
        },
        EventData::Http3FrameParsed(event) => {
            add(event.stream_id)?;
            if let Some(id) = priority_target(&event.frame) {
                add(id)?;
            }
        },
        EventData::Http3DatagramCreated(event) =>
            add(quarter_to_stream_id(event.quarter_stream_id)?)?,
        EventData::Http3DatagramParsed(event) =>
            add(quarter_to_stream_id(event.quarter_stream_id)?)?,
        EventData::Http3PushResolved(event) =>
            if let Some(id) = event.stream_id {
                add(id)?;
            },
        _ => (),
    }
    Ok(ids)
}

fn stream_ids(event: &Event) -> Result<TypedArray<'_, i64>, FilterError> {
    match event {
        Event::Qlog(event) => native_stream_ids(&event.data),
        Event::Json(event) => {
            // Custom events can explicitly name a stream, but arbitrary nested
            // identifiers are not interpreted as stream IDs.
            let mut ids = TypedArray::new();
            if let Some(id) = event
                .data
                .get("stream_id")
                .and_then(serde_json::Value::as_u64)
            {
                ids.push(checked_stream_id(id)?);
            }
            if let Some(id) = event
                .data
                .get("quarter_stream_id")
                .and_then(serde_json::Value::as_u64)
            {
                ids.push(checked_stream_id(quarter_to_stream_id(id)?)?);
            }
            Ok(ids)
        },
    }
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
            Event::Json(event) => Ok(category_and_type_from_name(&event.name)),
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
    use super::filter_sqlog_events;
    use super::FilterError;
    use qlog::events::http3;
    use qlog::events::quic;
    use qlog::events::Event as NativeEvent;
    use qlog::events::EventData;
    use qlog::events::EventImportance;
    use qlog::events::JsonEvent;
    use qlog::reader::Event;

    fn native(data: EventData) -> Event {
        Event::Qlog(NativeEvent::with_time(0.0, data))
    }

    fn stream_frame(stream_id: u64) -> quic::QuicFrame {
        quic::QuicFrame::Stream {
            stream_id,
            offset: Some(0),
            fin: Some(true),
            raw: None,
        }
    }

    fn sent(streams: &[u64]) -> Event {
        native(EventData::QuicPacketSent(quic::PacketSent {
            frames: Some(streams.iter().copied().map(stream_frame).collect()),
            ..quic::PacketSent::default()
        }))
    }

    fn compare_events(
        actual: &[Event], expected: &[Event],
    ) -> Result<(), serde_json::Error> {
        fn serialize(
            event: &Event,
        ) -> Result<serde_json::Value, serde_json::Error> {
            match event {
                Event::Qlog(event) => serde_json::to_value(event),
                Event::Json(event) => serde_json::to_value(event),
            }
        }
        assert_eq!(
            actual
                .iter()
                .map(serialize)
                .collect::<Result<Vec<_>, _>>()?,
            expected
                .iter()
                .map(serialize)
                .collect::<Result<Vec<_>, _>>()?,
        );
        Ok(())
    }

    #[test]
    fn stream_filter_preserves_order_and_complete_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let events = vec![
            sent(&[1, 2, 3, 4, 5]),
            sent(&[0, 100, 200, 300, 400]),
            sent(&[1, 100, 2, 200]),
        ];
        for (query, expected) in [
            ("any(stream_id[*] == 13)", vec![]),
            ("any(stream_id[*] == 0)", vec![1]),
            ("any(stream_id[*] == 1)", vec![0, 2]),
            ("any(stream_id[*] in {0 3})", vec![0, 1]),
        ] {
            let expected = expected
                .into_iter()
                .map(|index| events[index].clone())
                .collect::<Vec<_>>();
            compare_events(
                &filter_sqlog_events(events.clone(), query)?,
                &expected,
            )?;
        }
        Ok(())
    }

    fn stream_frames(id: u64) -> Vec<quic::QuicFrame> {
        vec![
            quic::QuicFrame::Ping { raw: None },
            quic::QuicFrame::ResetStream {
                stream_id: id,
                error: qlog::events::ApplicationError::Unknown,
                error_code: Some(1),
                final_size: 2,
                raw: None,
            },
            quic::QuicFrame::StopSending {
                stream_id: id,
                error: qlog::events::ApplicationError::Unknown,
                error_code: Some(1),
                raw: None,
            },
            stream_frame(id),
            quic::QuicFrame::MaxStreamData {
                stream_id: id,
                maximum: 100,
                raw: None,
            },
            quic::QuicFrame::StreamDataBlocked {
                stream_id: id,
                limit: 100,
                raw: None,
            },
        ]
    }

    fn frame_events(frames: Vec<quic::QuicFrame>) -> Vec<Event> {
        vec![
            native(EventData::QuicPacketSent(quic::PacketSent {
                frames: Some(frames.clone()),
                ..quic::PacketSent::default()
            })),
            native(EventData::QuicPacketReceived(quic::PacketReceived {
                frames: Some(frames.clone()),
                ..quic::PacketReceived::default()
            })),
            native(EventData::QuicPacketLost(quic::PacketLost {
                frames: Some(frames.clone()),
                ..quic::PacketLost::default()
            })),
            native(EventData::QuicFramesProcessed(quic::FramesProcessed {
                frames: frames.clone(),
                packet_numbers: None,
            })),
            native(EventData::QuicMarkedForRetransmit(
                quic::MarkedForRetransmit { frames },
            )),
        ]
    }

    #[test]
    fn all_stream_frame_variants_and_event_containers_are_filterable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for frame in stream_frames(40) {
            let is_stream = !matches!(frame, quic::QuicFrame::Ping { .. });
            let events = frame_events(vec![frame]);
            let expected = if is_stream { events.as_slice() } else { &[] };
            compare_events(
                &filter_sqlog_events(events.clone(), "any(stream_id[*] == 40)")?,
                expected,
            )?;
        }
        Ok(())
    }

    #[test]
    fn all_explicit_stream_references_are_filterable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let id = 40;
        let priority = http3::Http3Frame::PriorityUpdate {
            stream_id: Some(id),
            push_id: None,
            priority_field_value: "u=1".into(),
            raw: None,
        };
        let events = vec![
            native(EventData::QuicStreamStateUpdated(
                quic::StreamStateUpdated {
                    stream_id: id,
                    stream_type: None,
                    old: None,
                    new: quic::StreamState::Open,
                    trigger: None,
                },
            )),
            native(EventData::QuicStreamDataMoved(quic::StreamDataMoved {
                stream_id: Some(id),
                ..quic::StreamDataMoved::default()
            })),
            native(EventData::QuicStreamDataBlockedUpdated(
                quic::StreamDataBlockedUpdated {
                    stream_id: id,
                    ..quic::StreamDataBlockedUpdated::default()
                },
            )),
            native(EventData::Http3StreamTypeSet(http3::StreamTypeSet {
                stream_id: id,
                ..http3::StreamTypeSet::default()
            })),
            native(EventData::Http3PriorityUpdated(http3::PriorityUpdated {
                stream_id: Some(id),
                ..http3::PriorityUpdated::default()
            })),
            native(EventData::Http3FrameCreated(http3::FrameCreated {
                stream_id: 2,
                frame: priority.clone(),
                ..http3::FrameCreated::default()
            })),
            native(EventData::Http3FrameParsed(http3::FrameParsed {
                stream_id: 3,
                frame: priority,
                ..http3::FrameParsed::default()
            })),
            native(EventData::Http3DatagramCreated(http3::DatagramCreated {
                quarter_stream_id: id / 4,
                ..http3::DatagramCreated::default()
            })),
            native(EventData::Http3DatagramParsed(http3::DatagramParsed {
                quarter_stream_id: id / 4,
                ..http3::DatagramParsed::default()
            })),
            native(EventData::Http3PushResolved(http3::PushResolved {
                stream_id: Some(id),
                push_id: None,
                decision: http3::PushDecision::Claimed,
            })),
            Event::Json(JsonEvent {
                time: 0.0,
                importance: EventImportance::Core,
                name: "custom:event:with_colon".into(),
                data: serde_json::json!({"stream_id": id}),
            }),
            Event::Json(JsonEvent {
                time: 0.0,
                importance: EventImportance::Core,
                name: "custom:datagram".into(),
                data: serde_json::json!({"quarter_stream_id": id / 4}),
            }),
        ];
        compare_events(
            &filter_sqlog_events(events.clone(), "any(stream_id[*] == 40)")?,
            &events,
        )?;
        assert!(
            filter_sqlog_events(events.clone(), "any(stream_id[*] == 10)")?
                .is_empty()
        );
        assert_eq!(
            filter_sqlog_events(
                events,
                "category == \"custom\" && name == \"event:with_colon\""
            )?
            .len(),
            1
        );
        Ok(())
    }

    #[test]
    fn large_ids_are_exact_and_overflow_is_rejected() -> Result<(), FilterError> {
        let id = (1_u64 << 62) - 1;
        assert_eq!(
            filter_sqlog_events(
                vec![sent(&[id])],
                &format!("any(stream_id[*] == {id})")
            )?
            .len(),
            1
        );
        assert!(matches!(
            filter_sqlog_events(
                vec![sent(&[u64::MAX])],
                "any(stream_id[*] == -1)"
            ),
            Err(FilterError::InvalidStreamId(u64::MAX))
        ));
        let event =
            native(EventData::Http3DatagramCreated(http3::DatagramCreated {
                quarter_stream_id: u64::MAX,
                ..http3::DatagramCreated::default()
            }));
        assert!(matches!(
            filter_sqlog_events(vec![event], "any(stream_id[*] == -1)"),
            Err(FilterError::InvalidQuarterStreamId(u64::MAX))
        ));
        assert!(matches!(
            filter_sqlog_events(vec![], "any(stream_id[*] =="),
            Err(FilterError::InvalidExpression(_))
        ));
        Ok(())
    }
}
