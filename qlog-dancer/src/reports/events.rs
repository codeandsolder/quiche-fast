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

//! Event reports retain every field represented by the parsed qlog schema.
//! The wire-format names are used directly, including extension fields and
//! binary values; no per-event hand-written field selection is necessary.

use serde_json::Value;
use tabled::Table;
use tabled::Tabled;

use crate::category_and_type_from_name;

#[derive(Debug)]
struct PrintableEvent {
    time: f64,
    category: String,
    ty: String,
    details: String,
    metadata: String,
}

impl PrintableEvent {
    fn from_native(
        event: &qlog::events::Event,
    ) -> Result<Self, serde_json::Error> {
        // Serialize once. Besides obtaining the authoritative event name,
        // this preserves native payloads and all top-level extension metadata.
        let Value::Object(mut fields) = serde_json::to_value(event)? else {
            return Err(invalid_event("serialized qlog event is not an object"));
        };
        let Some(Value::String(name)) = fields.remove("name") else {
            return Err(invalid_event(
                "serialized qlog event has no string name",
            ));
        };
        let payload = fields
            .remove("data")
            .ok_or_else(|| invalid_event("serialized qlog event has no data"))?;
        fields.remove("time");
        let (category, ty) = category_and_type_from_name(&name);
        Ok(Self {
            time: event.time,
            category,
            ty,
            details: serde_json::to_string(&payload)?,
            metadata: if fields.is_empty() {
                String::new()
            } else {
                serde_json::to_string(&fields)?
            },
        })
    }

    fn from_json(
        event: &qlog::events::JsonEvent,
    ) -> Result<Self, serde_json::Error> {
        let (category, ty) = category_and_type_from_name(&event.name);
        Ok(Self {
            time: event.time,
            category,
            ty,
            details: serde_json::to_string(&event.data)?,
            metadata: String::new(),
        })
    }
}

fn invalid_event(message: &'static str) -> serde_json::Error {
    serde_json::Error::io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    ))
}

fn event_rows(
    rows: impl IntoIterator<Item = Result<PrintableEvent, serde_json::Error>>,
) -> Result<tabled::builder::Builder, serde_json::Error> {
    let mut table = tabled::builder::Builder::default();
    table.push_record(["time", "category", "Type", "details", "metadata"]);
    for row in rows {
        let PrintableEvent {
            time,
            category,
            ty,
            details,
            metadata,
        } = row?;
        table.push_record([time.to_string(), category, ty, details, metadata]);
    }
    Ok(table)
}

/// Render native qlog JSON records without copying the event list.
///
/// # Errors
/// Returns a serialization error if a parsed event cannot be represented.
pub fn qlog_event_list(
    events: &[qlog::events::Event],
) -> Result<tabled::builder::Builder, serde_json::Error> {
    event_rows(events.iter().map(PrintableEvent::from_native))
}

/// Render both typed and extensible qlog JSON-SEQ records.
///
/// # Errors
/// Returns a serialization error if a parsed event cannot be represented.
pub fn sqlog_event_list(
    events: &[qlog::reader::Event],
) -> Result<tabled::builder::Builder, serde_json::Error> {
    event_rows(events.iter().map(|event| match event {
        qlog::reader::Event::Qlog(event) => PrintableEvent::from_native(event),
        qlog::reader::Event::Json(event) => PrintableEvent::from_json(event),
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
    use super::qlog_event_list;
    use super::sqlog_event_list;
    use super::PrintableEvent;
    use qlog::events::Event;
    use serde_json::json;
    use serde_json::Value;

    fn native(name: &str, data: Value) -> Result<Event, serde_json::Error> {
        let mut event = json!({"time": 1.0, "name": name});
        event["data"] = data;
        serde_json::from_value(event)
    }

    #[test]
    fn packet_report_preserves_complete_quic_frame_payloads(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let frames = json!([
            {"frame_type": "ack", "acked_ranges": [[1, 3]], "ack_delay": 1.5,
                "ect0": 4, "ect1": 5, "ce": 6, "raw": {"length": 7}},
            {"frame_type": "new_connection_id", "sequence_number": 7, "retire_prior_to": 3,
                "connection_id_length": 2, "connection_id": "beef", "stateless_reset_token": "0123"},
            {"frame_type": "retire_connection_id", "sequence_number": 9},
            {"frame_type": "path_challenge", "data": "aabb"},
            {"frame_type": "path_response", "data": "ccdd"},
            {"frame_type": "stream", "stream_id": 18_014_398_509_481_985_u64, "offset": 12,
                "fin": true, "raw": {"length": 9, "data": "aabb"}},
        ]);
        let event = native(
            "quic:packet_sent",
            json!({
                "header": {"packet_type": "1RTT", "packet_number": 42}, "frames": frames
            }),
        )?;
        let row = PrintableEvent::from_native(&event)?;
        assert_eq!(
            (row.category.as_str(), row.ty.as_str()),
            ("quic", "packet_sent")
        );
        let payload: Value = serde_json::from_str(&row.details)?;
        assert_eq!(payload["frames"], frames);
        assert_eq!(payload["header"]["packet_type"], "1RTT");
        assert_eq!(payload["header"]["packet_number"], 42);
        Ok(())
    }

    #[test]
    fn http3_report_preserves_binary_headers_settings_and_raw_data(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for frame in [
            json!({"frame_type": "settings", "settings": [{"name": "qpack_max_table_capacity", "value": 42}]}),
            json!({"frame_type": "push_promise", "push_id": 12, "headers": [{"name": "x-test", "value": "abc"}]}),
            json!({"frame_type": "priority_update", "stream_id": 4, "priority_field_value": "u=3"}),
            json!({"frame_type": "headers", "headers": [{"name_bytes": "ff", "value_bytes": "00ff"}, {"name": "x-test", "value": "hello"}],
                "raw": {"length": 4, "data": "abcd"}}),
            json!({"frame_type": "reserved", "frame_type_bytes": 31}),
            json!({"frame_type": "data", "raw": {"length": 3, "data": "123456"}}),
        ] {
            let event = native(
                "http3:frame_created",
                json!({"stream_id": 0, "frame": frame}),
            )?;
            let row = PrintableEvent::from_native(&event)?;
            let payload: Value = serde_json::from_str(&row.details)?;
            assert_eq!(payload["frame"], frame);
        }
        Ok(())
    }

    #[test]
    fn native_and_sequential_reports_share_payload_and_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let event: Event = serde_json::from_value(json!({
            "time": 2.0, "name": "quic:connection_started",
            "data": {"local": {"connection_ids": ["local-cid"]}, "remote": {"connection_ids": ["remote-cid"]}},
            "group_id": "connection-7", "example:custom": {"nested": [1, 2]}
        }))?;
        let row = PrintableEvent::from_native(&event)?;
        let payload: Value = serde_json::from_str(&row.details)?;
        assert_eq!(payload["local"]["connection_ids"], json!(["local-cid"]));
        assert_eq!(payload["remote"]["connection_ids"], json!(["remote-cid"]));
        let metadata: Value = serde_json::from_str(&row.metadata)?;
        assert_eq!(metadata["group_id"], "connection-7");
        assert_eq!(metadata["example:custom"], json!({"nested": [1, 2]}));
        let native_rows = Vec::<Vec<String>>::from(qlog_event_list(
            std::slice::from_ref(&event),
        )?);
        let sequential_rows = Vec::<Vec<String>>::from(sqlog_event_list(&[
            qlog::reader::Event::Qlog(event),
        ])?);
        assert_eq!(native_rows, sequential_rows);
        Ok(())
    }
}
