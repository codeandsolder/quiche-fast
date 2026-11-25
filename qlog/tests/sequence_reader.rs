// Copyright (C) 2026, Cloudflare, Inc.
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

//! Verify that both native and chunked readers consume the same JSON-SEQ
//! records regardless of chunk size or a missing terminal newline.

use std::io;
use std::io::BufReader;
use std::io::Cursor;
use std::io::Read;

use qlog::reader::Event;
use qlog::reader::QlogSeqDecoder;
use qlog::reader::QlogSeqReader;

const HEADER: &str = r#"{"file_schema":"0.3","serialization_format":"JSON-SEQ","trace":{"event_schemas":[],"vantage_point":{"type":"client"}}}"#;
const NATIVE: &str = r#"{"time":1.0,"name":"quic:packet_sent","data":{"header":{"packet_type":"handshake","packet_number":4}}}"#;
const CUSTOM: &str = r#"{"time":2.0,"name":"custom:event","data":{"text":"escaped \u001e and unicode —"}}"#;

fn events_as_json(
    events: &[Event],
) -> Result<Vec<serde_json::Value>, serde_json::Error> {
    events
        .iter()
        .map(|event| match event {
            Event::Qlog(event) => serde_json::to_value(event),
            Event::Json(event) => serde_json::to_value(event),
        })
        .collect()
}

fn feed(
    decoder: &mut QlogSeqDecoder, mut input: &[u8], events: &mut Vec<Event>,
) -> io::Result<()> {
    while !input.is_empty() {
        if let Some(event) = decoder.decode(&mut input)? {
            events.push(event);
        }
    }
    Ok(())
}

#[test]
fn arbitrary_boundaries_and_final_record_without_newline(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = format!(
        " \n\u{1e}\u{1e}{HEADER}\n\u{1e}{NATIVE}\n\u{1e} \n\u{1e}{CUSTOM}"
    );
    let bytes = input.as_bytes();
    let expected = vec![
        serde_json::to_value(serde_json::from_str::<qlog::events::Event>(
            NATIVE,
        )?)?,
        serde_json::to_value(serde_json::from_str::<qlog::events::JsonEvent>(
            CUSTOM,
        )?)?,
    ];
    for size in [1, 2, 7, 31, bytes.len()] {
        let reader = QlogSeqReader::new(Box::new(BufReader::with_capacity(
            size,
            Cursor::new(bytes),
        )))?;
        assert_eq!(reader.qlog.serialization_format, "JSON-SEQ");
        let events = reader.collect::<io::Result<Vec<_>>>()?;
        assert!(matches!(events.as_slice(), [
            Event::Qlog(_),
            Event::Json(_)
        ]));
        assert_eq!(events_as_json(&events)?, expected);
    }
    for split in 0..=bytes.len() {
        let mut decoder = QlogSeqDecoder::default();
        let mut events = Vec::new();
        feed(&mut decoder, &bytes[..split], &mut events)?;
        feed(&mut decoder, &bytes[split..], &mut events)?;
        events.extend(decoder.finish()?);
        assert!(decoder.finish()?.is_none());
        assert_eq!(
            decoder
                .header()
                .map(|header| header.serialization_format.as_str()),
            Some("JSON-SEQ")
        );
        assert_eq!(events_as_json(&events)?, expected);
    }
    Ok(())
}

#[test]
fn malformed_record_is_reported_at_its_boundary_and_reader_is_fused(
) -> io::Result<()> {
    let input =
        format!("\u{1e}{HEADER}\n\u{1e}{CUSTOM}\n\u{1e}{{bad}}\u{1e}{CUSTOM}");
    let mut reader = QlogSeqReader::new(Box::new(BufReader::new(Cursor::new(
        input.as_bytes(),
    ))))?;
    assert!(matches!(reader.next(), Some(Ok(Event::Json(_)))));
    let error = reader
        .next()
        .transpose()
        .err()
        .ok_or_else(|| io::Error::other("missing invalid record error"))?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("invalid qlog event #2"));
    assert!(reader.next().is_none());
    let mut decoder = QlogSeqDecoder::default();
    assert!(feed(&mut decoder, input.as_bytes(), &mut Vec::new()).is_err());
    assert!(decoder.finish().is_err());
    assert!(decoder.decode(&mut CUSTOM.as_bytes()).is_err());
    Ok(())
}

#[test]
fn header_only_at_eof_and_invalid_prefix_or_header() -> io::Result<()> {
    let input = format!("\u{1e}{HEADER}");
    let mut reader = QlogSeqReader::new(Box::new(Cursor::new(input.as_bytes())))?;
    assert_eq!(reader.qlog.serialization_format, "JSON-SEQ");
    assert!(reader.next().is_none());
    for input in [
        String::new(),
        HEADER.to_owned(),
        format!("junk\u{1e}{HEADER}"),
        "\u{1e}{bad}".to_owned(),
        format!("\u{1e}{}", HEADER.replace("JSON-SEQ", "JSON")),
    ] {
        assert!(
            QlogSeqReader::new(Box::new(Cursor::new(input.as_bytes()))).is_err()
        );
    }
    Ok(())
}

// A read error after complete records must not look like successful EOF.
struct FailingInput<'a> {
    bytes: &'a [u8],
}

impl Read for FailingInput<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated input",
            ));
        }
        self.bytes.read(output)
    }
}

#[test]
fn read_failure_is_distinct_from_eof() -> io::Result<()> {
    let input = format!("\u{1e}{HEADER}\n\u{1e}{CUSTOM}\n\u{1e}");
    let mut reader =
        QlogSeqReader::new(Box::new(BufReader::new(FailingInput {
            bytes: input.as_bytes(),
        })))?;
    assert!(matches!(reader.next(), Some(Ok(Event::Json(_)))));
    let error = reader
        .next()
        .transpose()
        .err()
        .ok_or_else(|| io::Error::other("missing I/O failure"))?;
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert!(reader.next().is_none());
    Ok(())
}
