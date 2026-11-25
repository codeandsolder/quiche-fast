// Copyright (C) 2023, Cloudflare, Inc.
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

use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

use crate::QlogSeq;
use crate::SQLOG_EXT;
use crate::SQLOG_GZ_EXT;
use crate::SQLOG_ZST_EXT;

/// Represents the format of the read event.
#[expect(
    clippy::large_enum_variant,
    reason = "Boxing the native qlog event would add allocation and change the public Event API"
)]
#[derive(Clone, Debug)]
pub enum Event {
    /// A native qlog event type.
    Qlog(crate::events::Event),

    // An extended JSON event type.
    Json(crate::events::JsonEvent),
}

/// Incremental JSON-SEQ decoding state. Failed input cannot be resumed.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Preamble,
    Header,
    Events,
    Finished,
    Failed,
}

/// A record-at-a-time JSON-SEQ decoder shared by buffered readers and
/// arbitrarily fragmented browser or network input.
///
/// Each ASCII record separator starts a new record. EOF completes the last
/// record even when there is no trailing newline or separator. Empty records
/// are ignored. Decoding errors permanently invalidate the sequence.
#[derive(Default)]
pub struct QlogSeqDecoder {
    phase: Phase,
    header: Option<QlogSeq>,
    pending: Vec<u8>,
    record_number: usize,
}

impl QlogSeqDecoder {
    /// Borrow the header once it has been decoded.
    #[must_use = "the header describes the decoded trace"]
    pub const fn header(&self) -> Option<&QlogSeq> {
        self.header.as_ref()
    }

    /// Consume part or all of the supplied fragment, stopping at a record
    /// boundary. Call repeatedly while input remains. A successful call with
    /// no event may have consumed the header, an empty record, or part of a
    /// record.
    ///
    /// # Errors
    /// Reports invalid framing, invalid JSON, or input after finalization.
    pub fn decode(&mut self, input: &mut &[u8]) -> io::Result<Option<Event>> {
        let result = self.decode_inner(input);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    fn decode_inner(&mut self, input: &mut &[u8]) -> io::Result<Option<Event>> {
        match self.phase {
            Phase::Finished =>
                return Err(invalid("qlog JSON-SEQ input was already finalized")),
            Phase::Failed =>
                return Err(invalid("qlog JSON-SEQ decoder has failed")),
            Phase::Preamble => {
                let separator = input.iter().position(|byte| *byte == 0x1e);
                let prefix = &input[..separator.unwrap_or(input.len())];
                if prefix.iter().any(|byte| !byte.is_ascii_whitespace()) {
                    return Err(invalid(
                        "qlog JSON-SEQ data must begin with a record separator",
                    ));
                }
                let Some(separator) = separator else {
                    *input = &[];
                    return Ok(None);
                };
                *input = &input[separator + 1..];
                self.phase = Phase::Header;
            },
            Phase::Header | Phase::Events => (),
        }

        if let Some(separator) = input.iter().position(|byte| *byte == 0x1e) {
            self.pending.extend_from_slice(&input[..separator]);
            *input = &input[separator + 1..];
            return self.complete_record();
        }
        self.pending.extend_from_slice(input);
        *input = &[];
        Ok(None)
    }

    fn complete_record(&mut self) -> io::Result<Option<Event>> {
        if self.pending.iter().all(u8::is_ascii_whitespace) {
            self.pending.clear();
            return Ok(None);
        }
        if self.phase == Phase::Header {
            let header: QlogSeq =
                serde_json::from_slice(&self.pending).map_err(|error| {
                    invalid(format!("invalid qlog header: {error}"))
                })?;
            if header.serialization_format != "JSON-SEQ" {
                return Err(invalid(format!(
                    "expected JSON-SEQ serialization format, got {:?}",
                    header.serialization_format
                )));
            }
            self.header = Some(header);
            self.phase = Phase::Events;
            self.pending.clear();
            return Ok(None);
        }
        self.record_number =
            self.record_number.checked_add(1).ok_or_else(|| {
                invalid("qlog record count exceeds addressable range")
            })?;
        // Custom and unknown event types use the generic JSON representation.
        let event = if let Ok(event) =
            serde_json::from_slice::<crate::events::Event>(&self.pending)
        {
            Event::Qlog(event)
        } else {
            Event::Json(serde_json::from_slice(&self.pending).map_err(
                |error| {
                    invalid(format!(
                        "invalid qlog event #{}: {error}",
                        self.record_number
                    ))
                },
            )?)
        };
        self.pending.clear();
        Ok(Some(event))
    }

    /// Complete the last record at EOF. Successful repeated calls are harmless.
    ///
    /// # Errors
    /// Reports a missing header, malformed final record, or prior failure.
    pub fn finish(&mut self) -> io::Result<Option<Event>> {
        match self.phase {
            Phase::Finished => return Ok(None),
            Phase::Failed =>
                return Err(invalid("qlog JSON-SEQ decoder has failed")),
            Phase::Preamble | Phase::Header | Phase::Events => (),
        }
        let result = self.complete_record().and_then(|event| {
            if self.phase == Phase::Events {
                Ok(event)
            } else {
                Err(invalid("qlog JSON-SEQ input has no header"))
            }
        });
        self.phase = if result.is_ok() {
            Phase::Finished
        } else {
            Phase::Failed
        };
        result
    }

    const fn is_terminal(&self) -> bool {
        matches!(self.phase, Phase::Finished | Phase::Failed)
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn read_step(
    reader: &mut (dyn BufRead + Send + Sync), decoder: &mut QlogSeqDecoder,
) -> io::Result<Option<Event>> {
    loop {
        let mut input = match reader.fill_buf() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if input.is_empty() {
            return decoder.finish();
        }
        let len = input.len();
        let result = decoder.decode(&mut input);
        let consumed = len - input.len();
        reader.consume(consumed);
        return result;
    }
}

/// The filename convention is independent of available Cargo features.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileEncoding {
    Raw,
    Gzip,
    Zstd,
}

fn file_encoding(name: &std::ffi::OsStr) -> Option<FileEncoding> {
    let bytes = name.as_encoded_bytes();
    if bytes.ends_with(SQLOG_GZ_EXT.as_bytes()) {
        Some(FileEncoding::Gzip)
    } else if bytes.ends_with(SQLOG_ZST_EXT.as_bytes()) {
        Some(FileEncoding::Zstd)
    } else if bytes.ends_with(SQLOG_EXT.as_bytes()) {
        Some(FileEncoding::Raw)
    } else {
        None
    }
}

/// A streaming JSON-SEQ reader. Each iterator item is fallible so invalid
/// records or decompression errors cannot be mistaken for successful EOF.
pub struct QlogSeqReader<'a> {
    pub qlog: QlogSeq,
    reader: Box<dyn BufRead + Send + Sync + 'a>,
    decoder: QlogSeqDecoder,
}

impl<'a> QlogSeqReader<'a> {
    /// Creates a reader from buffered JSON-SEQ input.
    ///
    /// # Errors
    /// Returns an error if input cannot be read or the header is missing or
    /// malformed.
    pub fn new(
        mut reader: Box<dyn BufRead + Send + Sync + 'a>,
    ) -> io::Result<Self> {
        let mut decoder = QlogSeqDecoder::default();
        loop {
            read_step(reader.as_mut(), &mut decoder)?;
            if let Some(qlog) = decoder.header.take() {
                return Ok(Self {
                    qlog,
                    reader,
                    decoder,
                });
            }
        }
    }

    /// Convenience constructor that opens `path` and picks a streaming
    /// decoder based on the file's compound extension:
    ///
    /// * `*.sqlog` -> raw JSON-SEQ (always available).
    /// * `*.sqlog.gz` -> gzip via `flate2` (requires the `gzip` feature).
    /// * `*.sqlog.zst` -> zstd via `zstd` (requires the `zstd` feature).
    ///
    /// The dispatch tests the *compound* suffix (`.sqlog.gz`,
    /// `.sqlog.zst`, `.sqlog`) on the full filename, in that order.
    /// This rejects bare `.gz` or `.zst` names that do not also carry
    /// the `.sqlog` segment, and avoids the trap where
    /// [`Path::extension`] strips only the last component (which
    /// would silently accept `something.tar.gz`).
    ///
    /// Unknown extensions, or compressed extensions whose matching
    /// feature is not enabled, return an [`std::io::ErrorKind::Unsupported`]
    /// error with a message pointing at the feature that is needed.
    ///
    /// This is the intended single entry point for reading a qlog
    /// file regardless of compression. Concatenated compression members are
    /// decoded as one byte stream, and corrupt trailing members are errors.
    ///
    /// # Errors
    /// Returns an error if opening, decompression, or qlog header parsing
    /// fails.
    pub fn with_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let name = path.file_name().unwrap_or_default();
        let encoding = file_encoding(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("qlog file {name:?} does not match a known qlog extension ({SQLOG_EXT}, {SQLOG_GZ_EXT}, {SQLOG_ZST_EXT})"),
            )
        })?;
        match encoding {
            FileEncoding::Raw => Self::new(Box::new(BufReader::new(file))),
            FileEncoding::Gzip => {
                #[cfg(feature = "gzip")]
                {
                    Self::new(Box::new(BufReader::new(
                        flate2::read::MultiGzDecoder::new(file),
                    )))
                }
                #[cfg(not(feature = "gzip"))]
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("qlog file {name:?} requires the `gzip` feature on the qlog crate to decode"),
                ))
            },
            FileEncoding::Zstd => {
                #[cfg(feature = "zstd")]
                {
                    let decoder = zstd::Decoder::new(file)?;
                    Self::new(Box::new(BufReader::new(decoder)))
                }
                #[cfg(not(feature = "zstd"))]
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("qlog file {name:?} requires the `zstd` feature on the qlog crate to decode"),
                ))
            },
        }
    }
}

impl Iterator for QlogSeqReader<'_> {
    type Item = io::Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.decoder.is_terminal() {
            match read_step(self.reader.as_mut(), &mut self.decoder) {
                Ok(Some(event)) => return Some(Ok(event)),
                Ok(None) => (),
                Err(error) => {
                    self.decoder.phase = Phase::Failed;
                    return Some(Err(error));
                },
            }
        }
        None
    }
}

impl std::iter::FusedIterator for QlogSeqReader<'_> {}

#[cfg(test)]
mod filename_tests {
    use super::file_encoding;
    use super::FileEncoding;
    use std::ffi::OsStr;

    #[test]
    fn only_complete_suffixes_are_recognized() {
        for (name, expected) in [
            ("trace.sqlog", Some(FileEncoding::Raw)),
            ("trace.sqlog.gz", Some(FileEncoding::Gzip)),
            ("trace.sqlog.zst", Some(FileEncoding::Zstd)),
            ("trace.gz", None),
            ("trace.tar.zst", None),
            ("trace.sqlog.gz.tmp", None),
        ] {
            assert_eq!(file_encoding(OsStr::new(name)), expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_prefix_does_not_prevent_suffix_recognition() {
        use std::os::unix::ffi::OsStrExt;
        for (name, expected) in [
            (b"trace-\xff.sqlog".as_slice(), FileEncoding::Raw),
            (b"trace-\xff.sqlog.gz".as_slice(), FileEncoding::Gzip),
            (b"trace-\xff.sqlog.zst".as_slice(), FileEncoding::Zstd),
        ] {
            assert_eq!(file_encoding(OsStr::from_bytes(name)), Some(expected));
        }
    }
}
