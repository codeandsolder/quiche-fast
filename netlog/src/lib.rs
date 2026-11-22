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

//! The netlog crate is a reverse-engineered deserializer for the Chrome
//! [netlog] format. It supports QUIC and HTTP(/2 and /3) events.
//!
//! # Overview
//!
//! Chromium-based browsers allow users to enable detailed logging, netlog,
//! which is useful for debugging interoperability or performance issues. A
//! netlog file uses a kind of line-delimited JSON format. The first line
//! contains "constants", which are specific to the version of the software used
//! to generate the log. These constants are used for a form of compressed
//! encoding for the netlog events that appear on each subsequent newline.
//!
//! This crate supports parsing a netlog file and converting a subset of netlog
//! events into Rust structures, via Serde.
//!
//! # Example usage
//!
//! Assuming a netlog file name of `chrome-net-export-log-error.json`, the first
//! task is to create a `BufReader` for the file and initialize the netlog
//! constants.
//!
//! ```no_run
//! use netlog::read_netlog_constants;
//! use std::fs::File;
//! use std::io::BufReader;
//!
//! let mut reader =
//!     BufReader::new(File::open("chrome-net-export-log-error.json").unwrap());
//!
//! let constants = read_netlog_constants(&mut reader).unwrap();
//! ```
//!
//! Then move on to parsing the netlog file until the end.
//!
//! ```no_run
//! # use std::io::BufReader;
//! # use std::fs::File;
//! # use netlog::read_netlog_constants;
//! use netlog::read_netlog_record;
//! use netlog::EventHeader;
//! use netlog::h2::Http2SessionEvent;
//! use netlog::quic::QuicSessionEvent;
//! # let mut reader =
//! #    BufReader::new(File::open("chrome-net-export-log-error.json").unwrap());
//! # let constants = read_netlog_constants(&mut reader).unwrap();
//! // The second line of a netlog is `"events" [`, which can be skipped over.
//! read_netlog_record(&mut reader);
//!
//! while let Some(record) = read_netlog_record(&mut reader) {
//!     let res: Result<EventHeader, serde_json::Error> =
//!         serde_json::from_slice(&record);
//!
//!     match res {
//!         Ok(mut event_hdr) => {
//!             let Ok(()) = event_hdr.populate_strings(&constants) else {
//!                 continue;
//!             };
//!             event_hdr.time_num = event_hdr.time.parse::<u64>().unwrap();
//!
//!             // Netlogs can hold many different sessions.
//!             // Application might want to track these separately
//!             if event_hdr.phase_string == "PHASE_BEGIN" {
//!                 match event_hdr.ty_string.as_str() {
//!                     "HTTP2_SESSION" => {
//!                         let ev: Http2SessionEvent =
//!                             serde_json::from_slice(&record).unwrap();
//!                         // Handle new session event ...
//!                     },
//!                     "QUIC_SESSION" => {
//!                         let ev: QuicSessionEvent =
//!                             serde_json::from_slice(&record).unwrap();
//!                         // Handle new session event ...
//!                     },
//!
//!                     // Ignore others
//!                     _ => (),
//!                 }
//!             }
//!
//!             // Try to parse other events.
//!             if let Some(ev) = netlog::parse_event(&event_hdr, &record) {
//!                 // Handle parsed event.
//!             }
//!         },
//!
//!         Err(e) => {
//!             println!("Error deserializing: {}", e);
//!             println!("input value {}", String::from_utf8_lossy(&record));
//!         },
//!     }
//! }
//! ```
//!
//! [netlog]:
//! (https://www.chromium.org/developers/design-documents/network-stack/netlog/)
use std::io::BufRead;

use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::constants::Constants;
use crate::constants::ConstantsLine;

#[derive(Deserialize, Debug, Default)]
pub struct EventSource {
    #[serde(skip)]
    pub start_time_int: u64,

    pub id: i64,
    pub start_time: String,
    #[serde(rename = "type")]
    pub ty: i64,
}

#[derive(Deserialize, Debug, Default)]
pub struct EventHeader {
    #[serde(skip)]
    pub ty_string: String,
    #[serde(skip)]
    pub phase_string: String,
    #[serde(skip)]
    pub time_num: u64,

    pub phase: i64,
    pub source: EventSource,
    pub time: String,
    #[serde(rename = "type")]
    pub ty: i64,
}

/// A numeric event code missing from the Chrome netlog constants table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLookupError {
    UnknownEventType(i64),
    UnknownEventPhase(i64),
}

impl std::fmt::Display for EventLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownEventType(id) =>
                write!(f, "unknown netlog event type ID {id}"),
            Self::UnknownEventPhase(id) =>
                write!(f, "unknown netlog phase ID {id}"),
        }
    }
}

impl std::error::Error for EventLookupError {}

impl EventHeader {
    /// Resolve the event and phase IDs against the log's constants table.
    ///
    /// # Errors
    /// Returns an error if either ID is not defined by this log's constants.
    /// Leaves the existing strings unchanged when resolution fails.
    pub fn populate_strings(
        &mut self, constants: &constants::Constants,
    ) -> Result<(), EventLookupError> {
        let event_type = constants
            .log_event_types_id_keyed
            .get(&self.ty)
            .ok_or(EventLookupError::UnknownEventType(self.ty))?;
        let phase = constants
            .log_event_phase_id_keyed
            .get(&self.phase)
            .ok_or(EventLookupError::UnknownEventPhase(self.phase))?;
        self.ty_string.clone_from(event_type);
        self.phase_string.clone_from(phase);
        Ok(())
    }
}

#[derive(Deserialize, Debug, Default)]
pub struct SourceDependency {
    pub id: i64,
    #[serde(rename = "type")]
    pub ty: i64,
}

/// The core netlog event type with several domain-specific variants.
#[derive(Debug)]
pub enum Event {
    Http(http::Event),
    H2(h2::Event),
    H3(h3::Event),
    Quic(quic::Event),
}

/// Read the netlog constants from a netlog file accessed by a `BufRead`.
///
/// # Errors
///
/// Returns an error if the constants line cannot be read or decoded as JSON.
pub fn read_netlog_constants<R: BufRead>(
    reader: &mut R,
) -> Result<Constants, serde_json::Error> {
    let mut buf = Vec::<u8>::new();

    // Read the constants line and replace the trailing comma (,) with a brace
    // (}) to close the object and make it parseable.
    reader
        .read_until(b'\n', &mut buf)
        .map_err(serde_json::Error::io)?;

    let end = buf
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .ok_or_else(|| {
            serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "netlog constants header is empty",
            ))
        })?;
    match buf[end] {
        b',' => buf[end] = b'}',
        b'}' => {}, // Already a complete standalone constants object.
        _ => {
            return Err(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "netlog constants header must end with ',' or '}'",
            )));
        },
    }
    buf.truncate(end + 1);

    let res: Result<ConstantsLine, serde_json::Error> =
        serde_json::from_slice(&buf);

    match res {
        Ok(mut line) => {
            line.constants.populate_id_keyed();

            Ok(line.constants)
        },

        Err(e) => {
            log::error!("Error deserializing constants: {e}");

            Err(e)
        },
    }
}

/// Reads a single record from a netlog file accessed by a `BufRead`.
///
/// Returns `None` at end of input, for non-event lines, or if the underlying
/// reader reports an I/O error.
#[must_use = "the returned record has been consumed from the input reader"]
pub fn read_netlog_record<R: BufRead>(reader: &mut R) -> Option<Vec<u8>> {
    let mut buf = Vec::<u8>::new();

    loop {
        buf.clear();
        let size = match reader.read_until(b'\n', &mut buf) {
            Ok(size) => size,
            Err(error) => {
                log::error!("Error reading netlog record: {error}");
                return None;
            },
        };
        if size == 0 {
            return None;
        }

        // Empty lines are legal JSON whitespace between array records.
        let mut record = buf.trim_ascii();
        if record.is_empty() {
            continue;
        }
        // Non-event lines are structural array endings, or the polledData
        // section that follows the events array.
        if record.first() != Some(&b'{') {
            return None;
        }
        record = record.strip_suffix(b",").unwrap_or(record);
        // A closing ']' sometimes shares the final event's line.
        record = record.strip_suffix(b"]").unwrap_or(record);

        log::trace!("read record={}", String::from_utf8_lossy(record));
        return Some(record.to_vec());
    }
}

fn decode_event<T: DeserializeOwned>(event: &[u8]) -> Option<T> {
    match serde_json::from_slice(event) {
        Ok(value) => Some(value),
        Err(e) => {
            log::debug!("Skipping malformed netlog event: {e}");
            None
        },
    }
}

/// Parses the provided `event` based on the event type provided in `event_hdr`.
#[must_use = "the result contains the decoded event, or indicates that it could not be decoded"]
pub fn parse_event(event_hdr: &EventHeader, event: &[u8]) -> Option<Event> {
    if event_hdr.ty_string.starts_with("HTTP_") {
        return http::parse_event(event_hdr, event);
    } else if event_hdr.ty_string.starts_with("HTTP2_") {
        return h2::parse_event(event_hdr, event);
    } else if event_hdr.ty_string.starts_with("HTTP3_") {
        return h3::parse_event(event_hdr, event);
    } else if event_hdr.ty_string.starts_with("QUIC") {
        return quic::parse_event(event_hdr, event);
    }

    None
}

pub mod constants;
pub mod h2;
pub mod h3;
pub mod http;
pub mod quic;

#[cfg(test)]
mod input_tests {
    use super::read_netlog_constants;
    use super::read_netlog_record;
    use super::EventHeader;
    use super::EventLookupError;
    use std::io::Cursor;
    use std::io::Read;

    fn constants_document() -> serde_json::Value {
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
                "logEventTypes": {"HTTP2_SESSION": 101},
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
    fn unknown_event_id_or_phase_is_recoverable_and_atomic(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let data = constants_document().to_string();
        let mut reader = Cursor::new(data.as_bytes());
        let constants = read_netlog_constants(&mut reader)?;

        let mut event = EventHeader {
            ty: 999,
            phase: 1,
            ty_string: "previous type".into(),
            phase_string: "previous phase".into(),
            ..EventHeader::default()
        };
        assert_eq!(
            event.populate_strings(&constants),
            Err(EventLookupError::UnknownEventType(999)),
        );
        assert_eq!(event.ty_string, "previous type");
        assert_eq!(event.phase_string, "previous phase");

        event.ty = 101;
        event.phase = 999;
        assert_eq!(
            event.populate_strings(&constants),
            Err(EventLookupError::UnknownEventPhase(999)),
        );
        assert_eq!(event.ty_string, "previous type");
        assert_eq!(event.phase_string, "previous phase");

        event.phase = 1;
        event.populate_strings(&constants)?;
        assert_eq!(event.ty_string, "HTTP2_SESSION");
        assert_eq!(event.phase_string, "PHASE_BEGIN");
        Ok(())
    }

    #[test]
    fn constants_header_accepts_lf_crlf_whitespace_and_eof(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let document = constants_document().to_string();
        let prefix = document.strip_suffix('}').ok_or("no closing JSON brace")?;

        for bytes in [
            format!("{prefix},\nnext"),
            format!("{prefix},\r\nnext"),
            format!("{prefix},   \t\r\nnext"),
            format!("{document}\nnext"),
        ] {
            let mut reader = Cursor::new(bytes.as_bytes());
            let constants = read_netlog_constants(&mut reader)?;
            assert_eq!(constants.log_format_version, 123);
            let mut remaining = String::new();
            reader.read_to_string(&mut remaining)?;
            assert_eq!(remaining, "next");
        }

        for bytes in [format!("{prefix},"), document] {
            let mut reader = Cursor::new(bytes.as_bytes());
            assert_eq!(
                read_netlog_constants(&mut reader)?.log_format_version,
                123
            );
            assert_eq!(reader.position(), bytes.len() as u64);
        }

        for bad in ["", "\r\n", "{", "{}]"] {
            assert!(
                read_netlog_constants(&mut Cursor::new(bad.as_bytes())).is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn record_reader_handles_blank_lines_crlf_and_last_array_bracket() {
        let raw = b"  \r\n\n  {\"type\":1},  \r\n\t{\"type\":2}]\r\n\"polledData\":{}\r\n";
        let mut reader = Cursor::new(raw.as_slice());
        assert_eq!(
            read_netlog_record(&mut reader).as_deref(),
            Some(b"{\"type\":1}".as_slice())
        );
        assert_eq!(
            read_netlog_record(&mut reader).as_deref(),
            Some(b"{\"type\":2}".as_slice())
        );
        assert_eq!(read_netlog_record(&mut reader), None);
        assert_eq!(read_netlog_record(&mut reader), None);
    }
}
