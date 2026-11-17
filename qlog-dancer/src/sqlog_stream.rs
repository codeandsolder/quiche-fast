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
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Incremental RFC 7464 JSON text sequence framing for the browser and tests.
//! Each ASCII RS starts a record, and the next RS or EOF completes it.
//! JSON string escapes are not confused with record separators.

use qlog::reader::Event as ReaderEvent;
use qlog::QlogSeq;

/// A streaming JSON-SEQ parser that preserves records across arbitrary chunks.
/// Header validation and event decoding happen only at record boundaries.
#[derive(Default)]
pub(crate) struct SqlogStream {
    header: Option<QlogSeq>,
    events: Vec<ReaderEvent>,
    pending: Vec<u8>,
    in_record: bool,
    finished: bool,
    record_number: usize,
}

impl SqlogStream {
    /// Feed an arbitrary byte fragment, including an empty fragment.
    ///
    /// # Errors
    /// Returns an error for invalid non-whitespace framing, a malformed
    /// header, an invalid event, or input after the stream was finalized.
    pub(crate) fn push_chunk(&mut self, chunk: &[u8]) -> Result<(), String> {
        if self.finished {
            return Err("qlog JSON-SEQ input was already finalized".into());
        }

        let mut remaining = chunk;
        while let Some(rs) = remaining.iter().position(|byte| *byte == 0x1e) {
            self.consume(&remaining[..rs])?;
            if self.in_record {
                self.complete_record()?;
            }
            self.in_record = true;
            remaining = &remaining[rs + 1..];
        }
        self.consume(remaining)
    }

    /// Complete the final record even when there is no trailing RS or newline.
    ///
    /// # Errors
    /// Returns an error if there is no complete qlog JSON-SEQ header or the
    /// final event is malformed/truncated.
    pub(crate) fn finish(&mut self) -> Result<(), String> {
        if self.finished {
            return Ok(());
        }
        if self.in_record && self.pending.iter().any(|b| !b.is_ascii_whitespace())
        {
            self.complete_record()?;
        }
        if self.header.is_none() {
            return Err("qlog JSON-SEQ input has no header".into());
        }
        self.finished = true;
        Ok(())
    }

    pub(crate) fn header(&self) -> Option<&QlogSeq> {
        self.header.as_ref()
    }

    pub(crate) fn events(&self) -> &[ReaderEvent] {
        &self.events
    }

    fn consume(&mut self, bytes: &[u8]) -> Result<(), String> {
        if self.in_record {
            self.pending.extend_from_slice(bytes);
        } else if bytes.iter().any(|b| !b.is_ascii_whitespace()) {
            return Err(
                "qlog JSON-SEQ data must begin with a record separator".into()
            );
        }
        Ok(())
    }

    fn complete_record(&mut self) -> Result<(), String> {
        self.record_number += 1;
        let bytes = std::mem::take(&mut self.pending);
        if self.header.is_none() {
            let header: QlogSeq = serde_json::from_slice(&bytes)
                .map_err(|err| format!("invalid qlog header: {err}"))?;
            if header.serialization_format != "JSON-SEQ" {
                return Err(format!(
                    "expected JSON-SEQ serialization format, got {:?}",
                    header.serialization_format
                ));
            }
            self.header = Some(header);
            return Ok(());
        }

        // Extra empty records between separators are harmless, but malformed
        // nonempty records must be reported rather than silently dropped.
        if bytes.iter().all(|b| b.is_ascii_whitespace()) {
            return Ok(());
        }

        if let Ok(event) = serde_json::from_slice::<qlog::events::Event>(&bytes) {
            self.events.push(ReaderEvent::Qlog(event));
            return Ok(());
        }
        let event: qlog::events::JsonEvent = serde_json::from_slice(&bytes)
            .map_err(|err| {
                format!("invalid qlog event #{}: {err}", self.record_number - 1)
            })?;
        self.events.push(ReaderEvent::Json(event));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlog::reader::Event;

    const HEADER: &str = r#"{"file_schema":"0.3","serialization_format":"JSON-SEQ","trace":{"event_schemas":[],"vantage_point":{"type":"client"}}}"#;
    const EVENT_ONE: &str =
        r#"{"time":1.0,"name":"custom:one","data":{"message":"hello"}}"#;
    const EVENT_TWO: &str =
        r#"{"time":2.0,"name":"custom:two","data":{"message":"world"}}"#;

    fn sample() -> Vec<u8> {
        format!("\u{1e}{HEADER}\n\u{1e}{EVENT_ONE}\n\u{1e}{EVENT_TWO}\n")
            .into_bytes()
    }

    fn check(stream: &SqlogStream) {
        assert!(stream.finished);
        let header = stream.header().expect("header must be decoded");
        assert_eq!(header.serialization_format, "JSON-SEQ");
        assert_eq!(
            header.trace.vantage_point.as_ref().map(|v| &v.ty),
            Some(&qlog::VantagePointType::Client)
        );
        assert_eq!(stream.events().len(), 2);
        let times: Vec<f64> = stream
            .events()
            .iter()
            .map(|event| match event {
                Event::Qlog(event) => event.time,
                Event::Json(event) => event.time,
            })
            .collect();
        assert_eq!(times, [1.0, 2.0]);
    }

    #[test]
    fn arbitrary_chunk_lengths_and_all_split_positions_preserve_records() {
        let bytes = sample();
        for size in [1, 2, 3, 5, 7, 31, bytes.len(), bytes.len() + 1] {
            let mut stream = SqlogStream::default();
            for chunk in bytes.chunks(size) {
                stream.push_chunk(chunk).expect("chunk must parse");
                stream
                    .push_chunk(&[])
                    .expect("empty chunk must be harmless");
            }
            stream.finish().expect("last event must be committed");
            stream.finish().expect("finalization must be idempotent");
            check(&stream);
            assert!(stream.push_chunk(b"\x1e").is_err());
        }

        for split in 0..=bytes.len() {
            let mut stream = SqlogStream::default();
            stream.push_chunk(&bytes[..split]).expect("first half");
            stream.push_chunk(&bytes[split..]).expect("second half");
            stream.finish().expect("EOF");
            check(&stream);
        }
    }

    #[test]
    fn header_and_last_event_are_not_parsed_until_complete() {
        let mut stream = SqlogStream::default();
        let prefix = format!("\u{1e}{}", &HEADER[..HEADER.len() / 2]);
        stream
            .push_chunk(prefix.as_bytes())
            .expect("partial header");
        assert!(stream.header().is_none());
        stream
            .push_chunk(
                format!("{}\n\u{1e}", &HEADER[HEADER.len() / 2..]).as_bytes(),
            )
            .expect("complete header");
        assert!(stream.header().is_some());
        stream
            .push_chunk(EVENT_ONE.as_bytes())
            .expect("partial event");
        assert!(stream.events().is_empty());
        stream.finish().expect("EOF commits the last event");
        assert_eq!(stream.events().len(), 1);
    }

    #[test]
    fn invalid_header_and_events_are_reported_not_dropped() {
        let mut missing_header = SqlogStream::default();
        assert!(missing_header.finish().is_err());
        let mut missing_separator = SqlogStream::default();
        assert!(missing_separator.push_chunk(HEADER.as_bytes()).is_err());

        let mut invalid_header = SqlogStream::default();
        assert!(invalid_header
            .push_chunk(b"\x1e{bad}\x1e")
            .expect_err("invalid header")
            .contains("invalid qlog header"));

        let mut invalid_event = SqlogStream::default();
        invalid_event
            .push_chunk(format!("\u{1e}{HEADER}\n\u{1e}{{bad}}\u{1e}").as_bytes())
            .expect_err("invalid event")
            .contains("invalid qlog event #1");
    }

    #[test]
    fn malformed_eof_and_wrong_serialization_format_are_errors() {
        let mut truncated = SqlogStream::default();
        truncated
            .push_chunk(format!("\u{1e}{HEADER}\n\u{1e}{{\"time\":1").as_bytes())
            .expect("the parser must buffer the incomplete record");
        assert!(truncated
            .finish()
            .expect_err("invalid final event must be reported")
            .contains("invalid qlog event #1"));

        let invalid_format = HEADER.replace("JSON-SEQ", "JSON");
        let mut wrong_format = SqlogStream::default();
        assert!(wrong_format
            .push_chunk(format!("\u{1e}{invalid_format}\n\u{1e}").as_bytes())
            .expect_err("non-sequential qlog must be rejected")
            .contains("expected JSON-SEQ"));
    }

    #[test]
    fn known_qlog_event_and_header_vantage_point_are_preserved() {
        let typed = r#"{"time":3.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":4},"raw":{"length":100}}}"#;
        let mut stream = SqlogStream::default();
        stream
            .push_chunk(format!("\u{1e}{HEADER}\n\u{1e}{typed}\n").as_bytes())
            .expect("typed event");
        stream.finish().expect("EOF");
        assert!(matches!(stream.events(), [Event::Qlog(_)]));
        let viewpoint = stream
            .header()
            .and_then(|header| header.trace.vantage_point.as_ref())
            .map(|point| &point.ty)
            .expect("client viewpoint");
        let ds = crate::datastore::Datastore::with_sqlog_reader_events(
            stream.events(),
            viewpoint,
            true,
        )
        .expect("typed event should populate the datastore");
        assert!(matches!(
            ds.vantage_point,
            crate::datastore::VantagePoint::Client
        ));
    }

    #[test]
    fn header_only_and_trailing_separator_are_valid() {
        let mut stream = SqlogStream::default();
        stream
            .push_chunk(format!("\u{1e}{HEADER}\n\u{1e}").as_bytes())
            .expect("header");
        stream.finish().expect("trailing empty record");
        assert_eq!(stream.events().len(), 0);
        assert!(stream.header().is_some());
    }
}
