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

//! Stateful parsing of QUIC streams into HTTP/3 frames.

use crate::frame::EnrichedHeaders;
use crate::frame::H3iFrame;
use crate::quiche;
use quiche::h3::frame::Frame as QFrame;
use quiche::h3::Error as H3Error;
use quiche::h3::Result;

/// Maximum buffered frame payload in bytes.
const MAX_STREAM_STATE_SIZE: u64 = 2_000_000;

#[derive(Debug, Eq, PartialEq)]
/// The reason frame parsing was interrupted.
pub enum InterruptCause {
    FinBit,
    ResetStream(u64),
}

#[derive(Debug, Eq, PartialEq)]
/// The next complete frame or terminal stream event.
pub enum FrameParseResult {
    /// A frame was parsed, with its final byte carrying the indicated FIN.
    FrameParsed { h3i_frame: H3iFrame, fin: bool },
    /// FIN or `RESET_STREAM` occurred before another complete frame.
    Interrupted(InterruptCause),
}

#[derive(Debug)]
struct Varint {
    bytes: [u8; 8],
    filled: usize,
    expected: usize,
}

enum ReadProgress<T> {
    Complete(T, bool),
    Ended,
}

impl Varint {
    const fn new() -> Self {
        Self {
            bytes: [0; 8],
            filled: 0,
            expected: 1,
        }
    }

    fn read(
        &mut self,
        read: &mut impl FnMut(&mut [u8]) -> quiche::Result<(usize, bool)>,
    ) -> Result<ReadProgress<u64>> {
        loop {
            let (count, fin) = read(&mut self.bytes[self.filled..self.expected])?;
            self.filled += count;
            if self.filled == 1 {
                self.expected = octets::varint_parse_len(self.bytes[0]);
            }
            if self.filled == self.expected {
                let value =
                    octets::Octets::with_slice(&self.bytes[..self.expected])
                        .get_varint()?;
                return Ok(ReadProgress::Complete(value, fin));
            }
            if fin {
                return Ok(ReadProgress::Ended);
            }
            if count == 0 {
                return Err(H3Error::Done);
            }
        }
    }
}

#[derive(Debug)]
enum Stage {
    Type(Varint),
    Length {
        kind: u64,
        varint: Varint,
    },
    Payload {
        kind: u64,
        bytes: Vec<u8>,
        filled: usize,
    },
}

/// Parses frames on one QUIC stream without consuming the next frame's bytes.
#[derive(Debug)]
pub(crate) struct FrameParser {
    stream_id: u64,
    stage: Stage,
}

impl FrameParser {
    pub(crate) const fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            stage: Stage::Type(Varint::new()),
        }
    }

    /// Read until a frame, terminal stream event, or transport backpressure.
    /// The parser retains partial headers and payloads across I/O cycles.
    pub(crate) fn try_parse_frame<F: quiche::BufFactory>(
        &mut self, conn: &mut quiche::Connection<F>,
    ) -> Result<FrameParseResult> {
        let stream_id = self.stream_id;
        let outcome =
            self.parse_with(|buffer| conn.stream_recv(stream_id, buffer));
        if let Ok(FrameParseResult::FrameParsed { fin, .. }) = &outcome {
            log::trace!(
                "{} stream={stream_id} frame parsed fin={fin}",
                conn.trace_id()
            );
        }
        outcome
    }

    fn parse_with(
        &mut self,
        mut read: impl FnMut(&mut [u8]) -> quiche::Result<(usize, bool)>,
    ) -> Result<FrameParseResult> {
        match self.parse(&mut read) {
            Err(H3Error::Transport(quiche::Error::StreamReset(code))) => Ok(
                FrameParseResult::Interrupted(InterruptCause::ResetStream(code)),
            ),
            outcome => outcome,
        }
    }

    fn parse(
        &mut self,
        read: &mut impl FnMut(&mut [u8]) -> quiche::Result<(usize, bool)>,
    ) -> Result<FrameParseResult> {
        loop {
            match &mut self.stage {
                Stage::Type(varint) => match varint.read(read)? {
                    ReadProgress::Complete(kind, false) => {
                        self.stage = Stage::Length {
                            kind,
                            varint: Varint::new(),
                        };
                    },
                    ReadProgress::Complete(_, true) | ReadProgress::Ended =>
                        return Ok(FrameParseResult::Interrupted(
                            InterruptCause::FinBit,
                        )),
                },
                Stage::Length { kind, varint } => {
                    let ReadProgress::Complete(length, fin) =
                        varint.read(read)?
                    else {
                        return Ok(FrameParseResult::Interrupted(
                            InterruptCause::FinBit,
                        ));
                    };
                    // Check the wire length before converting to usize or
                    // allocating. This also prevents wrapping on 32-bit hosts.
                    if length > MAX_STREAM_STATE_SIZE {
                        return Err(H3Error::ExcessiveLoad);
                    }
                    let length = usize::try_from(length)
                        .map_err(|_| H3Error::ExcessiveLoad)?;
                    if length == 0 {
                        let frame = decode_frame(*kind, &[])?;
                        self.stage = Stage::Type(Varint::new());
                        return Ok(FrameParseResult::FrameParsed {
                            h3i_frame: frame,
                            fin,
                        });
                    }
                    if fin {
                        return Ok(FrameParseResult::Interrupted(
                            InterruptCause::FinBit,
                        ));
                    }
                    self.stage = Stage::Payload {
                        kind: *kind,
                        bytes: vec![0; length],
                        filled: 0,
                    };
                },
                Stage::Payload {
                    kind,
                    bytes,
                    filled,
                } => {
                    let (count, fin) = read(&mut bytes[*filled..])?;
                    *filled += count;
                    if *filled == bytes.len() {
                        let frame = decode_frame(*kind, bytes)?;
                        self.stage = Stage::Type(Varint::new());
                        return Ok(FrameParseResult::FrameParsed {
                            h3i_frame: frame,
                            fin,
                        });
                    }
                    if fin {
                        return Ok(FrameParseResult::Interrupted(
                            InterruptCause::FinBit,
                        ));
                    }
                    if count == 0 {
                        return Err(H3Error::Done);
                    }
                },
            }
        }
    }
}

fn decode_frame(kind: u64, bytes: &[u8]) -> Result<H3iFrame> {
    match QFrame::from_bytes(kind, bytes.len() as u64, bytes)? {
        QFrame::Headers { header_block } =>
            EnrichedHeaders::from_wire(header_block).map(H3iFrame::Headers),
        frame => Ok(frame.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::FrameParseResult;
    use super::FrameParser;
    use super::H3Error;
    use super::InterruptCause;
    use super::MAX_STREAM_STATE_SIZE;
    use crate::frame::H3iFrame;
    use crate::quiche;
    use quiche::h3::frame::Frame;
    use quiche::h3::testing::Session;
    use quiche::h3::Result;

    const DONE: H3Error = H3Error::Done;

    // One I/O cycle: expose an arbitrary prefix, and either terminate the
    // stream at its end or report transport backpressure.
    fn read_chunk(
        parser: &mut FrameParser, input: &mut &[u8], fin: bool,
    ) -> Result<FrameParseResult> {
        parser.parse_with(|buffer| {
            if input.is_empty() && !fin {
                return Err(quiche::Error::Done);
            }
            let count = input.len().min(buffer.len());
            buffer[..count].copy_from_slice(&input[..count]);
            *input = &input[count..];
            Ok((count, fin && input.is_empty()))
        })
    }

    fn parsed(frame: Frame, fin: bool) -> FrameParseResult {
        FrameParseResult::FrameParsed {
            h3i_frame: H3iFrame::QuicheH3(frame),
            fin,
        }
    }

    fn wire(frame: &Frame, capacity: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; capacity];
        let written =
            frame.to_bytes(&mut octets::OctetsMut::with_slice(&mut bytes))?;
        bytes.truncate(written);
        Ok(bytes)
    }

    #[test]
    fn all_header_widths_and_split_positions() -> Result<()> {
        let frames = [
            Frame::Data {
                payload: vec![1, 2, 3, 4, 5],
            },
            Frame::Data {
                payload: vec![57; 64],
            },
            Frame::Unknown {
                raw_type: 64,
                payload: vec![1, 2, 3, 4, 5],
            },
            Frame::Unknown {
                raw_type: 16_384,
                payload: vec![64; 65],
            },
            Frame::Unknown {
                raw_type: 1 << 30,
                payload: Vec::new(),
            },
        ];
        for frame in frames {
            let bytes = wire(&frame, 256)?;
            for split in 0..bytes.len() {
                let mut parser = FrameParser::new(0);
                let mut first = &bytes[..split];
                assert_eq!(read_chunk(&mut parser, &mut first, false), Err(DONE));
                assert_eq!(first, &[] as &[u8]);
                let mut second = &bytes[split..];
                assert_eq!(
                    read_chunk(&mut parser, &mut second, true)?,
                    parsed(frame.clone(), true)
                );
                assert_eq!(second, &[] as &[u8]);
            }
            // Every byte is delivered in its own I/O cycle.
            let mut parser = FrameParser::new(0);
            for (index, byte) in bytes.iter().enumerate() {
                let mut input = std::slice::from_ref(byte);
                let fin = index + 1 == bytes.len();
                let outcome = read_chunk(&mut parser, &mut input, fin);
                if fin {
                    assert_eq!(outcome?, parsed(frame.clone(), true));
                } else {
                    assert_eq!(outcome, Err(DONE));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn fin_at_every_incomplete_position_is_terminal() -> Result<()> {
        let frame = Frame::Unknown {
            raw_type: 1 << 30,
            payload: vec![57; 64],
        };
        let bytes = wire(&frame, 256)?;
        for end in 0..bytes.len() {
            let mut parser = FrameParser::new(0);
            let mut input = &bytes[..end];
            assert_eq!(
                read_chunk(&mut parser, &mut input, true)?,
                FrameParseResult::Interrupted(InterruptCause::FinBit)
            );
        }
        Ok(())
    }

    #[test]
    fn length_limit_checks_wire_value_before_allocation() -> Result<()> {
        for length in [MAX_STREAM_STATE_SIZE + 1, 1_u64 << 32, (1_u64 << 62) - 1]
        {
            let mut bytes = [0; 9];
            let mut writer = octets::OctetsMut::with_slice(&mut bytes);
            writer.put_varint(0)?;
            writer.put_varint(length)?;
            let size = writer.off();
            let mut input = &bytes[..size];
            assert_eq!(
                read_chunk(&mut FrameParser::new(0), &mut input, false),
                Err(H3Error::ExcessiveLoad)
            );
        }
        Ok(())
    }

    #[test]
    fn multiple_frames_and_empty_payload_do_not_consume_next_header() -> Result<()>
    {
        let frames = [
            Frame::Unknown {
                raw_type: 64,
                payload: Vec::new(),
            },
            Frame::Data {
                payload: vec![1, 2, 3],
            },
            Frame::Data {
                payload: vec![4, 5, 6, 7],
            },
        ];
        let mut bytes = Vec::new();
        for frame in &frames {
            bytes.extend(wire(frame, 256)?);
        }
        let mut parser = FrameParser::new(4);
        let mut input = bytes.as_slice();
        for (index, frame) in frames.into_iter().enumerate() {
            assert_eq!(
                read_chunk(&mut parser, &mut input, true)?,
                parsed(frame, index == 2)
            );
        }
        assert_eq!(input, &[] as &[u8]);
        Ok(())
    }

    #[test]
    fn reset_is_reported_during_every_stage() -> Result<()> {
        let frame = Frame::Unknown {
            raw_type: 64,
            payload: vec![57; 64],
        };
        let bytes = wire(&frame, 256)?;
        for end in 0..bytes.len() {
            let mut parser = FrameParser::new(0);
            assert_eq!(
                read_chunk(&mut parser, &mut &bytes[..end], false),
                Err(DONE)
            );
            assert_eq!(
                parser.parse_with(|_| Err(quiche::Error::StreamReset(57)))?,
                FrameParseResult::Interrupted(InterruptCause::ResetStream(57))
            );
        }
        Ok(())
    }

    #[test]
    fn actual_quic_transport_fragmentation_and_nonzero_stream() -> Result<()> {
        let mut session = Session::new()?;
        session.handshake()?;
        for stream_id in [0, 4] {
            let mut parser = FrameParser::new(stream_id);
            let first = Frame::Data {
                payload: vec![1, 2, 3],
            };
            let second = Frame::Unknown {
                raw_type: 64,
                payload: vec![57; 64],
            };
            let mut bytes = wire(&first, 256)?;
            bytes.extend(wire(&second, 256)?);
            // Keep the first frame and one byte of the next type together.
            session.send_arbitrary_stream_data_client(
                &bytes[..6],
                stream_id,
                false,
            )?;
            assert_eq!(
                parser.try_parse_frame(&mut session.pipe.server)?,
                parsed(first, false)
            );
            assert_eq!(
                parser.try_parse_frame(&mut session.pipe.server),
                Err(DONE)
            );
            session.send_arbitrary_stream_data_client(
                &bytes[6..],
                stream_id,
                true,
            )?;
            assert_eq!(
                parser.try_parse_frame(&mut session.pipe.server)?,
                parsed(second, true)
            );
        }
        Ok(())
    }

    #[test]
    fn actual_quic_transport_fin_and_reset() -> Result<()> {
        let mut session = Session::new()?;
        session.handshake()?;
        for (stream, bytes) in [
            (0, &[64][..]),
            (4, &[0, 64][..]),
            (8, &[0, 3, 1, 2][..]),
            (12, &[0][..]),
        ] {
            let mut parser = FrameParser::new(stream);
            session.send_arbitrary_stream_data_client(bytes, stream, true)?;
            assert_eq!(
                parser.try_parse_frame(&mut session.pipe.server)?,
                FrameParseResult::Interrupted(InterruptCause::FinBit)
            );
        }
        let mut parser = FrameParser::new(16);
        session.send_arbitrary_stream_data_client(&[0, 3, 1], 16, false)?;
        assert_eq!(parser.try_parse_frame(&mut session.pipe.server), Err(DONE));
        session
            .pipe
            .client
            .stream_shutdown(16, quiche::Shutdown::Write, 57)?;
        session.pipe.advance()?;
        assert_eq!(
            parser.try_parse_frame(&mut session.pipe.server)?,
            FrameParseResult::Interrupted(InterruptCause::ResetStream(57))
        );
        Ok(())
    }
}
