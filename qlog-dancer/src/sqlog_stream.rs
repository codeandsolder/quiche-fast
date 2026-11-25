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

//! Browser-side collection of records from the shared qlog decoder.

use qlog::reader::Event;
use qlog::reader::QlogSeqDecoder;
use qlog::QlogSeq;

#[derive(Default)]
pub struct SqlogStream {
    decoder: QlogSeqDecoder,
    events: Vec<Event>,
}

impl SqlogStream {
    pub(super) fn push_chunk(&mut self, mut chunk: &[u8]) -> std::io::Result<()> {
        loop {
            if let Some(event) = self.decoder.decode(&mut chunk)? {
                self.events.push(event);
            }
            if chunk.is_empty() {
                return Ok(());
            }
        }
    }

    pub(super) fn finish(&mut self) -> std::io::Result<()> {
        if let Some(event) = self.decoder.finish()? {
            self.events.push(event);
        }
        Ok(())
    }

    pub(super) const fn header(&self) -> Option<&QlogSeq> {
        self.decoder.header()
    }

    pub(super) fn events(&self) -> &[Event] {
        &self.events
    }
}

#[cfg(test)]
mod tests {
    use super::SqlogStream;
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

    fn check(stream: &SqlogStream) -> std::io::Result<()> {
        let header = stream
            .header()
            .ok_or_else(|| std::io::Error::other("header must be decoded"))?;
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
        Ok(())
    }

    #[test]
    fn arbitrary_chunk_lengths_and_all_split_positions_preserve_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = sample();
        for size in [1, 2, 3, 5, 7, 31, bytes.len(), bytes.len() + 1] {
            let mut stream = SqlogStream::default();
            for chunk in bytes.chunks(size) {
                stream.push_chunk(chunk)?;
                stream.push_chunk(&[])?;
            }
            stream.finish()?;
            stream.finish()?;
            check(&stream)?;
            assert!(stream.push_chunk(b"\x1e").is_err());
        }

        for split in 0..=bytes.len() {
            let mut stream = SqlogStream::default();
            stream.push_chunk(&bytes[..split])?;
            stream.push_chunk(&bytes[split..])?;
            stream.finish()?;
            check(&stream)?;
        }
        Ok(())
    }

    #[test]
    fn header_and_last_event_are_not_parsed_until_complete(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = SqlogStream::default();
        let prefix = format!("\u{1e}{}", &HEADER[..HEADER.len() / 2]);
        stream.push_chunk(prefix.as_bytes())?;
        assert!(stream.header().is_none());
        stream.push_chunk(
            format!("{}\n\u{1e}", &HEADER[HEADER.len() / 2..]).as_bytes(),
        )?;
        assert!(stream.header().is_some());
        stream.push_chunk(EVENT_ONE.as_bytes())?;
        assert!(stream.events().is_empty());
        stream.finish()?;
        assert_eq!(stream.events().len(), 1);
        Ok(())
    }

    #[test]
    fn invalid_header_and_events_are_reported_not_dropped(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut missing_header = SqlogStream::default();
        assert!(missing_header.finish().is_err());
        let mut missing_separator = SqlogStream::default();
        assert!(missing_separator.push_chunk(HEADER.as_bytes()).is_err());

        let mut invalid_header = SqlogStream::default();
        assert!(invalid_header
            .push_chunk(b"\x1e{bad}\x1e")
            .err()
            .ok_or("invalid header")?
            .to_string()
            .contains("invalid qlog header"));

        let mut invalid_event = SqlogStream::default();
        assert!(invalid_event
            .push_chunk(format!("\u{1e}{HEADER}\n\u{1e}{{bad}}\u{1e}").as_bytes())
            .err()
            .ok_or("invalid event")?
            .to_string()
            .contains("invalid qlog event #1"));
        Ok(())
    }

    #[test]
    fn malformed_eof_and_wrong_serialization_format_are_errors(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut truncated = SqlogStream::default();
        truncated.push_chunk(
            format!("\u{1e}{HEADER}\n\u{1e}{{\"time\":1").as_bytes(),
        )?;
        assert!(truncated
            .finish()
            .err()
            .ok_or("invalid final event must be reported")?
            .to_string()
            .contains("invalid qlog event #1"));

        let invalid_format = HEADER.replace("JSON-SEQ", "JSON");
        let mut wrong_format = SqlogStream::default();
        assert!(wrong_format
            .push_chunk(format!("\u{1e}{invalid_format}\n\u{1e}").as_bytes())
            .err()
            .ok_or("non-sequential qlog must be rejected")?
            .to_string()
            .contains("expected JSON-SEQ"));
        Ok(())
    }

    #[test]
    fn known_qlog_event_and_header_vantage_point_are_preserved(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let typed = r#"{"time":3.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":4},"raw":{"length":100}}}"#;
        let mut stream = SqlogStream::default();
        stream
            .push_chunk(format!("\u{1e}{HEADER}\n\u{1e}{typed}\n").as_bytes())?;
        stream.finish()?;
        assert!(matches!(stream.events(), [Event::Qlog(_)]));
        let viewpoint = stream
            .header()
            .and_then(|header| header.trace.vantage_point.as_ref())
            .map(|point| &point.ty)
            .ok_or("client viewpoint missing")?;
        let ds = crate::datastore::Datastore::with_sqlog_reader_events(
            stream.events(),
            viewpoint,
            true,
        )?;
        assert!(matches!(
            ds.vantage_point,
            crate::datastore::VantagePoint::Client
        ));
        Ok(())
    }

    #[test]
    fn header_only_and_trailing_separator_are_valid(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = SqlogStream::default();
        stream.push_chunk(format!("\u{1e}{HEADER}\n\u{1e}").as_bytes())?;
        stream.finish()?;
        assert!(stream.events().is_empty());
        assert!(stream.header().is_some());
        Ok(())
    }
}
