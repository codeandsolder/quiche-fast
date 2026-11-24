// Copyright (C) 2018-2019, Cloudflare, Inc.
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

use std::convert::TryInto;

use crate::Error;
use crate::Result;

use crate::packet;
use crate::range_buf::RangeBuf;
use crate::ranges;
use crate::stream::StreamDirection;

#[cfg(feature = "qlog")]
use qlog::events::quic::AckRange;
#[cfg(feature = "qlog")]
use qlog::events::quic::ErrorSpace;
#[cfg(feature = "qlog")]
use qlog::events::quic::QuicFrame;
#[cfg(feature = "qlog")]
use qlog::events::quic::StreamType;

pub const MAX_STREAM_SIZE: u64 = 1 << 62;

/// Output of the shared frame encoding schema. A size-only sink validates
/// the same field widths without allocating or writing a packet.
pub trait FrameSink {
    fn put_varint(&mut self, value: u64) -> Result<()> {
        self.put_varint_with_len(value, octets::varint_len(value))
    }

    fn put_varint_with_len(&mut self, value: u64, len: usize) -> Result<()> {
        self.put_bytes(octets::EncodedVarint::with_len(value, len)?.as_ref())
    }
    fn put_bytes(&mut self, value: &[u8]) -> Result<()>;
    fn put_padding(&mut self, len: usize) -> Result<()>;
}

impl FrameSink for octets::OctetsMut<'_> {
    fn put_bytes(&mut self, value: &[u8]) -> Result<()> {
        octets::OctetsMut::put_bytes(self, value)?;
        Ok(())
    }

    fn put_padding(&mut self, len: usize) -> Result<()> {
        self.get_bytes_mut(len)?.as_mut().fill(0);
        Ok(())
    }
}

#[derive(Default)]
struct FrameSizer {
    len: usize,
}

impl FrameSizer {
    fn add(&mut self, len: usize) -> Result<()> {
        self.len = self.len.checked_add(len).ok_or(Error::BufferTooShort)?;
        Ok(())
    }
}

impl FrameSink for FrameSizer {
    fn put_bytes(&mut self, value: &[u8]) -> Result<()> {
        self.add(value.len())
    }

    fn put_padding(&mut self, len: usize) -> Result<()> {
        self.add(len)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcnCounts {
    ect0: u64,
    ect1: u64,
    ce: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Frame {
    Padding {
        len: usize,
    },

    Ping {
        // Attach metadata to the Ping frame. This doesn't appear on the wire,
        // but does tell us if this frame was part of a PMTUD probe and how
        // large the probe was. This will only show up on sent frames and be
        // None otherwise. This is the total size of the QUIC packet in the
        // probe.
        mtu_probe: Option<usize>,
    },

    Ack {
        ack_delay: u64,
        ranges: ranges::RangeSet,
        ecn_counts: Option<EcnCounts>,
    },

    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },

    StopSending {
        stream_id: u64,
        error_code: u64,
    },

    Crypto {
        data: RangeBuf,
    },

    CryptoHeader {
        offset: u64,
        length: usize,
    },

    NewToken {
        token: Vec<u8>,
    },

    Stream {
        stream_id: u64,
        data: RangeBuf,
    },

    StreamHeader {
        stream_id: u64,
        offset: u64,
        length: usize,
        fin: bool,
    },

    MaxData {
        max: u64,
    },

    MaxStreamData {
        stream_id: u64,
        max: u64,
    },

    MaxStreams {
        direction: StreamDirection,
        max: u64,
    },

    DataBlocked {
        limit: u64,
    },

    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },

    StreamsBlocked {
        direction: StreamDirection,
        limit: u64,
    },

    NewConnectionId {
        seq_num: u64,
        retire_prior_to: u64,
        conn_id: packet::ConnectionId<'static>,
        reset_token: [u8; 16],
    },

    RetireConnectionId {
        seq_num: u64,
    },

    PathChallenge {
        data: [u8; 8],
    },

    PathResponse {
        data: [u8; 8],
    },

    ConnectionClose {
        error_code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    },

    ApplicationClose {
        error_code: u64,
        reason: Vec<u8>,
    },

    HandshakeDone,

    Datagram {
        data: Vec<u8>,
    },

    DatagramHeader {
        length: usize,
    },
}

/// Read and validate a frame type before interpreting any type-dependent
/// payload. RFC 9000 sections 12.4–12.5 and RFC 9221 section 4.
pub fn read_frame_type(b: &mut octets::Octets, pkt: packet::Type) -> Result<u64> {
    let before = b.off();
    let ty = b.get_varint()?;
    if !matches!(ty, 0x00..=0x1e | 0x30 | 0x31) {
        return Err(Error::InvalidFrame);
    }
    // Every currently supported frame type fits in a single byte. Other
    // varints in the frame payload may use any legal encoding width.
    if b.off() - before != octets::varint_len(ty) {
        return Err(Error::InvalidPacket);
    }

    let allowed = match pkt {
        packet::Type::Initial | packet::Type::Handshake =>
            matches!(ty, 0x00..=0x03 | 0x06 | 0x1c),
        packet::Type::ZeroRTT =>
            !matches!(ty, 0x02 | 0x03 | 0x06 | 0x07 | 0x19 | 0x1b | 0x1e),
        packet::Type::Short => true,
        packet::Type::Retry | packet::Type::VersionNegotiation => false,
    };
    if !allowed {
        return Err(Error::InvalidPacket);
    }
    Ok(ty)
}

impl Frame {
    pub fn from_bytes(b: &mut octets::Octets, pkt: packet::Type) -> Result<Self> {
        let frame_type = read_frame_type(b, pkt)?;
        Self::from_bytes_with_type(frame_type, b)
    }

    /// Decode the payload after `read_frame_type` has validated the type.
    pub(crate) fn from_bytes_with_type(
        frame_type: u64, b: &mut octets::Octets,
    ) -> Result<Self> {
        let frame = match frame_type {
            0x00 => {
                let mut len = 1;

                while b.peek_u8() == Ok(0x00) {
                    b.get_u8()?;

                    len += 1;
                }

                Self::Padding { len }
            },

            0x01 => Self::Ping { mtu_probe: None },

            0x02..=0x03 => parse_ack_frame(frame_type, b)?,

            0x04 => Self::ResetStream {
                stream_id: b.get_varint()?,
                error_code: b.get_varint()?,
                final_size: b.get_varint()?,
            },

            0x05 => Self::StopSending {
                stream_id: b.get_varint()?,
                error_code: b.get_varint()?,
            },

            0x06 => {
                let offset = b.get_varint()?;
                let data = b.get_bytes_with_varint_length()?;
                let data = <RangeBuf>::from(data.as_ref(), offset, false);

                Self::Crypto { data }
            },

            0x07 => parse_new_token(b)?,

            0x08..=0x0f => parse_stream_frame(frame_type, b)?,

            0x10 => Self::MaxData {
                max: b.get_varint()?,
            },

            0x11 => Self::MaxStreamData {
                stream_id: b.get_varint()?,
                max: b.get_varint()?,
            },

            0x12..=0x13 => Self::MaxStreams {
                direction: StreamDirection::from_uni(frame_type & 1 != 0),
                max: b.get_varint()?,
            },

            0x14 => Self::DataBlocked {
                limit: b.get_varint()?,
            },

            0x15 => Self::StreamDataBlocked {
                stream_id: b.get_varint()?,
                limit: b.get_varint()?,
            },

            0x16..=0x17 => Self::StreamsBlocked {
                direction: StreamDirection::from_uni(frame_type & 1 != 0),
                limit: b.get_varint()?,
            },

            0x18 => parse_new_connection_id(b)?,

            0x19 => Self::RetireConnectionId {
                seq_num: b.get_varint()?,
            },

            0x1a => Self::PathChallenge {
                data: b
                    .get_bytes(8)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?,
            },

            0x1b => Self::PathResponse {
                data: b
                    .get_bytes(8)?
                    .buf()
                    .try_into()
                    .map_err(|_| Error::BufferTooShort)?,
            },

            0x1c => Self::ConnectionClose {
                error_code: b.get_varint()?,
                frame_type: b.get_varint()?,
                reason: b.get_bytes_with_varint_length()?.to_vec(),
            },

            0x1d => Self::ApplicationClose {
                error_code: b.get_varint()?,
                reason: b.get_bytes_with_varint_length()?.to_vec(),
            },

            0x1e => Self::HandshakeDone,

            0x30 | 0x31 => parse_datagram_frame(frame_type, b)?,

            _ => return Err(Error::InvalidFrame),
        };

        Ok(frame)
    }

    #[cfg(any(test, feature = "internal"))]
    pub fn to_bytes(&self, b: &mut octets::OctetsMut) -> Result<usize> {
        let before = b.cap();
        self.encode(b)?;
        Ok(before - b.cap())
    }

    pub fn wire_len(&self) -> Result<usize> {
        let mut sizer = FrameSizer::default();
        self.encode(&mut sizer)?;
        Ok(sizer.len)
    }

    pub(crate) fn encode(&self, b: &mut impl FrameSink) -> Result<()> {
        match self {
            Self::Padding { len } => b.put_padding(*len),

            Self::Ping { .. } => b.put_varint(0x01),

            Self::Ack {
                ack_delay,
                ranges,
                ecn_counts,
            } => encode_ack_frame(*ack_delay, ranges, ecn_counts.as_ref(), b),

            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => encode_varints(b, [0x04, *stream_id, *error_code, *final_size]),

            Self::StopSending {
                stream_id,
                error_code,
            } => encode_varints(b, [0x05, *stream_id, *error_code]),

            Self::Crypto { data } => {
                encode_crypto_header(
                    data.off(),
                    data.len() as u64,
                    payload_length_width(data.len() as u64),
                    b,
                )?;

                b.put_bytes(data)
            },

            Self::NewToken { token } => {
                encode_varints(b, [0x07, token.len() as u64])?;
                b.put_bytes(token)
            },

            Self::Stream { stream_id, data } => {
                encode_stream_header(
                    *stream_id,
                    data.off(),
                    data.len() as u64,
                    data.fin(),
                    payload_length_width(data.len() as u64),
                    b,
                )?;

                b.put_bytes(data)
            },

            Self::MaxData { max } => encode_varints(b, [0x10, *max]),

            Self::MaxStreamData { stream_id, max } =>
                encode_varints(b, [0x11, *stream_id, *max]),

            Self::MaxStreams { direction, max } =>
                encode_varints(b, [0x12 | direction.wire_bit(), *max]),

            Self::DataBlocked { limit } => encode_varints(b, [0x14, *limit]),

            Self::StreamDataBlocked { stream_id, limit } =>
                encode_varints(b, [0x15, *stream_id, *limit]),

            Self::StreamsBlocked { direction, limit } =>
                encode_varints(b, [0x16 | direction.wire_bit(), *limit]),

            Self::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => encode_new_connection_id(
                *seq_num,
                *retire_prior_to,
                conn_id,
                reset_token,
                b,
            ),

            Self::RetireConnectionId { seq_num } =>
                encode_varints(b, [0x19, *seq_num]),

            Self::PathChallenge { data } => {
                b.put_varint(0x1a)?;

                b.put_bytes(data.as_ref())
            },

            Self::PathResponse { data } => {
                b.put_varint(0x1b)?;

                b.put_bytes(data.as_ref())
            },

            Self::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                encode_varints(b, [
                    0x1c,
                    *error_code,
                    *frame_type,
                    reason.len() as u64,
                ])?;
                b.put_bytes(reason.as_ref())
            },

            Self::ApplicationClose { error_code, reason } => {
                encode_varints(b, [0x1d, *error_code, reason.len() as u64])?;
                b.put_bytes(reason.as_ref())
            },

            Self::HandshakeDone => b.put_varint(0x1e),

            Self::Datagram { data } => {
                encode_dgram_header(data.len() as u64, b)?;

                b.put_bytes(data.as_ref())
            },

            // These variants only describe frames already encoded directly
            // into the packet. They do not own a serializable payload.
            Self::CryptoHeader { .. } |
            Self::StreamHeader { .. } |
            Self::DatagramHeader { .. } => Err(Error::InvalidState),
        }
    }

    pub const fn ack_eliciting(&self) -> bool {
        // Any other frame is ack-eliciting (note the `!`).
        !matches!(
            self,
            Self::Padding { .. } |
                Self::Ack { .. } |
                Self::ApplicationClose { .. } |
                Self::ConnectionClose { .. }
        )
    }

    pub const fn probing(&self) -> bool {
        matches!(
            self,
            Self::Padding { .. } |
                Self::NewConnectionId { .. } |
                Self::PathChallenge { .. } |
                Self::PathResponse { .. }
        )
    }

    #[cfg(feature = "qlog")]
    pub fn to_qlog(&self, ack_delay_exponent: u64) -> QuicFrame {
        use qlog::events::RawInfo;

        match self {
            Self::Padding { len } => QuicFrame::Padding {
                raw: Some(Box::new(qlog_payload(*len as u64))),
            },

            Self::Ping { .. } => QuicFrame::Ping { raw: None },

            Self::Ack {
                ack_delay,
                ranges,
                ecn_counts,
            } => qlog_ack(
                *ack_delay,
                ranges,
                ecn_counts.as_ref(),
                ack_delay_exponent,
            ),

            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => QuicFrame::ResetStream {
                stream_id: *stream_id,
                error: qlog::events::ApplicationError::Unknown,
                error_code: Some(*error_code),
                final_size: *final_size,
                raw: None,
            },

            Self::StopSending {
                stream_id,
                error_code,
            } => QuicFrame::StopSending {
                stream_id: *stream_id,
                error: qlog::events::ApplicationError::Unknown,
                error_code: Some(*error_code),
                raw: None,
            },

            Self::Crypto { data } => qlog_crypto(data.off(), data.len()),
            Self::CryptoHeader { offset, length } =>
                qlog_crypto(*offset, *length),

            Self::NewToken { token } => QuicFrame::NewToken {
                token: qlog::Token {
                    // TODO: pick the token type some how
                    ty: Some(qlog::TokenType::Retry),
                    raw: Some(RawInfo {
                        data: qlog::HexSlice::maybe_string(Some(token))
                            .map(Box::new),
                        length: Some(token.len() as u64),
                        payload_length: None,
                    }),
                    details: None,
                },
                raw: None,
            },

            Self::Stream { stream_id, data } =>
                qlog_stream(*stream_id, data.off(), data.len(), data.fin()),
            Self::StreamHeader {
                stream_id,
                offset,
                length,
                fin,
            } => qlog_stream(*stream_id, *offset, *length, *fin),

            Self::MaxData { max } => QuicFrame::MaxData {
                maximum: *max,
                raw: None,
            },

            Self::MaxStreamData { stream_id, max } => QuicFrame::MaxStreamData {
                stream_id: *stream_id,
                maximum: *max,
                raw: None,
            },

            Self::MaxStreams { direction, max } => QuicFrame::MaxStreams {
                stream_type: qlog_stream_type(*direction),
                maximum: *max,
                raw: None,
            },

            Self::DataBlocked { limit } => QuicFrame::DataBlocked {
                limit: *limit,
                raw: None,
            },

            Self::StreamDataBlocked { stream_id, limit } =>
                QuicFrame::StreamDataBlocked {
                    stream_id: *stream_id,
                    limit: *limit,
                    raw: None,
                },

            Self::StreamsBlocked { direction, limit } =>
                QuicFrame::StreamsBlocked {
                    stream_type: qlog_stream_type(*direction),
                    limit: *limit,
                    raw: None,
                },

            Self::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => QuicFrame::NewConnectionId {
                sequence_number: *seq_num,
                retire_prior_to: *retire_prior_to,
                // Qlog's length field is u8. Do not silently wrap if a
                // diagnostic frame contains an oversized identifier.
                connection_id_length: Some(
                    u8::try_from(conn_id.len()).unwrap_or(u8::MAX),
                ),
                connection_id: format!("{}", qlog::HexSlice::new(conn_id)),
                stateless_reset_token: qlog::HexSlice::maybe_string(Some(
                    reset_token,
                )),
                raw: None,
            },

            Self::RetireConnectionId { seq_num } =>
                QuicFrame::RetireConnectionId {
                    sequence_number: *seq_num,
                    raw: None,
                },

            Self::PathChallenge { .. } => QuicFrame::PathChallenge {
                data: None,
                raw: None,
            },

            Self::PathResponse { .. } => QuicFrame::PathResponse {
                data: None,
                raw: None,
            },

            Self::ConnectionClose {
                error_code, reason, ..
            } => qlog_close(ErrorSpace::Transport, *error_code, reason),
            Self::ApplicationClose { error_code, reason } =>
                qlog_close(ErrorSpace::Application, *error_code, reason),

            Self::HandshakeDone => QuicFrame::HandshakeDone { raw: None },

            Self::Datagram { data } => QuicFrame::Datagram {
                raw: Some(Box::new(qlog_payload(data.len() as u64))),
            },

            Self::DatagramHeader { length } => QuicFrame::Datagram {
                raw: Some(Box::new(qlog_payload(*length as u64))),
            },
        }
    }
}

#[cfg(feature = "qlog")]
const fn qlog_stream_type(direction: StreamDirection) -> StreamType {
    match direction {
        StreamDirection::Bidirectional => StreamType::Bidirectional,
        StreamDirection::Unidirectional => StreamType::Unidirectional,
    }
}

#[cfg(feature = "qlog")]
const fn qlog_payload(length: u64) -> qlog::events::RawInfo {
    qlog::events::RawInfo {
        length: None,
        payload_length: Some(length),
        data: None,
    }
}

#[cfg(feature = "qlog")]
fn qlog_crypto(offset: u64, length: usize) -> QuicFrame {
    QuicFrame::Crypto {
        offset,
        raw: Some(Box::new(qlog_payload(length as u64))),
    }
}

#[cfg(feature = "qlog")]
fn qlog_stream(
    stream_id: u64, offset: u64, length: usize, fin: bool,
) -> QuicFrame {
    QuicFrame::Stream {
        stream_id,
        offset: Some(offset),
        fin: fin.then_some(true),
        raw: Some(Box::new(qlog_payload(length as u64))),
    }
}

#[cfg(feature = "qlog")]
fn qlog_close(space: ErrorSpace, error_code: u64, reason: &[u8]) -> QuicFrame {
    use qlog::events::ConnectionClosedFrameError;
    let error = match space {
        ErrorSpace::Transport => ConnectionClosedFrameError::TransportError(
            qlog::events::quic::TransportError::Unknown,
        ),
        ErrorSpace::Application => ConnectionClosedFrameError::ApplicationError(
            qlog::events::ApplicationError::Unknown,
        ),
    };
    QuicFrame::ConnectionClose {
        error: Some(error),
        error_space: Some(space),
        error_code: Some(error_code),
        reason: Some(String::from_utf8_lossy(reason).into_owned()),
        reason_bytes: None,
        trigger_frame_type: None,
    }
}

#[cfg(feature = "qlog")]
fn qlog_ack(
    ack_delay: u64, ranges: &ranges::RangeSet, ecn_counts: Option<&EcnCounts>,
    ack_delay_exponent: u64,
) -> QuicFrame {
    let ack_ranges = ranges
        .iter()
        .map(|r| AckRange::new(r.start, r.end - 1))
        .collect();

    let (ect0, ect1, ce) = ecn_counts.map_or((None, None, None), |ecn| {
        (Some(ecn.ect0), Some(ecn.ect1), Some(ecn.ce))
    });

    QuicFrame::Ack {
        // The ACK frame stores wire units; qlog uses milliseconds.
        // Omit unrepresentable delays rather than logging a
        // misleading value for a frame recovery will reject.
        ack_delay: crate::decode_ack_delay(ack_delay, ack_delay_exponent)
            .ok()
            .map(|micros| {
                std::time::Duration::from_micros(micros).as_secs_f32() * 1000.0
            }),
        acked_ranges: Some(ack_ranges),
        ect1,
        ect0,
        ce,
        raw: None,
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Padding { len } => write!(f, "PADDING len={len}"),

            Self::Ping { mtu_probe } => write!(f, "PING mtu_probe={mtu_probe:?}"),

            Self::Ack {
                ack_delay,
                ranges,
                ecn_counts,
            } => write!(
                    f,
                    "ACK delay={ack_delay} blocks={ranges:?} ecn_counts={ecn_counts:?}"
                ),

            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => write!(
                    f,
                    "RESET_STREAM stream={stream_id} err={error_code:x} size={final_size}"
                ),

            Self::StopSending {
                stream_id,
                error_code,
            } => write!(f, "STOP_SENDING stream={stream_id} err={error_code:x}"),

            Self::Crypto { data } => write!(f, "CRYPTO off={} len={}", data.off(), data.len()),

            Self::CryptoHeader { offset, length } => write!(f, "CRYPTO off={offset} len={length}"),

            Self::NewToken { token } => write!(f, "NEW_TOKEN len={}", token.len()),

            Self::Stream { stream_id, data } => write!(
                    f,
                    "STREAM id={stream_id} off={} len={} fin={}",
                    data.off(),
                    data.len(),
                    data.fin()
                ),

            Self::StreamHeader {
                stream_id,
                offset,
                length,
                fin,
            } => write!(
                    f,
                    "STREAM id={stream_id} off={offset} len={length} fin={fin}"
                ),

            Self::MaxData { max } => write!(f, "MAX_DATA max={max}"),

            Self::MaxStreamData { stream_id, max } => write!(f, "MAX_STREAM_DATA stream={stream_id} max={max}"),

            Self::MaxStreams { direction, max } => write!(f, "MAX_STREAMS type={} max={max}", direction.label()),

            Self::DataBlocked { limit } => write!(f, "DATA_BLOCKED limit={limit}"),

            Self::StreamDataBlocked { stream_id, limit } => write!(
                    f,
                    "STREAM_DATA_BLOCKED stream={stream_id} limit={limit}"
                ),

            Self::StreamsBlocked { direction, limit } => write!(f, "STREAMS_BLOCKED type={} limit={limit}", direction.label()),

            Self::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => write!(
                    f,
                    "NEW_CONNECTION_ID seq_num={seq_num} retire_prior_to={retire_prior_to} conn_id={conn_id:02x?} reset_token={reset_token:02x?}",
                ),

            Self::RetireConnectionId { seq_num } => write!(f, "RETIRE_CONNECTION_ID seq_num={seq_num}"),

            Self::PathChallenge { data } => write!(f, "PATH_CHALLENGE data={data:02x?}"),

            Self::PathResponse { data } => write!(f, "PATH_RESPONSE data={data:02x?}"),

            Self::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => write!(
                    f,
                    "CONNECTION_CLOSE err={error_code:x} frame={frame_type:x} reason={reason:x?}"
                ),

            Self::ApplicationClose { error_code, reason } => write!(
                    f,
                    "APPLICATION_CLOSE err={error_code:x} reason={reason:x?}"
                ),

            Self::HandshakeDone => write!(f, "HANDSHAKE_DONE"),

            Self::Datagram { data } => write!(f, "DATAGRAM len={}", data.len()),

            Self::DatagramHeader { length } => write!(f, "DATAGRAM len={length}"),
        }
    }
}

fn parse_new_token(b: &mut octets::Octets) -> Result<Frame> {
    let len =
        usize::try_from(b.get_varint()?).map_err(|_| Error::BufferTooShort)?;
    if len == 0 {
        return Err(Error::InvalidFrame);
    }

    Ok(Frame::NewToken {
        token: b.get_bytes(len)?.to_vec(),
    })
}

fn encode_varints<const N: usize>(
    b: &mut impl FrameSink, values: [u64; N],
) -> Result<()> {
    for value in values {
        b.put_varint(value)?;
    }
    Ok(())
}

fn validate_connection_id_length(len: usize) -> Result<u8> {
    let len = u8::try_from(len).map_err(|_| Error::InvalidFrame)?;
    if !(1..=packet::MAX_CID_LEN).contains(&len) {
        return Err(Error::InvalidFrame);
    }
    Ok(len)
}

fn encode_new_connection_id(
    seq_num: u64, retire_prior_to: u64, conn_id: &packet::ConnectionId<'_>,
    reset_token: &[u8; 16], b: &mut impl FrameSink,
) -> Result<()> {
    let len = validate_connection_id_length(conn_id.len())?;
    encode_varints(b, [0x18, seq_num, retire_prior_to])?;
    b.put_bytes(&[len])?;
    b.put_bytes(conn_id.as_ref())?;
    b.put_bytes(reset_token)
}

fn parse_new_connection_id(b: &mut octets::Octets) -> Result<Frame> {
    let seq_num = b.get_varint()?;
    let retire_prior_to = b.get_varint()?;
    let conn_id_len = validate_connection_id_length(usize::from(b.get_u8()?))?;

    Ok(Frame::NewConnectionId {
        seq_num,
        retire_prior_to,
        conn_id: packet::ConnectionId::copy_from_slice(
            b.get_bytes(usize::from(conn_id_len))?.as_ref(),
        ),
        reset_token: b
            .get_bytes(16)?
            .buf()
            .try_into()
            .map_err(|_| Error::BufferTooShort)?,
    })
}

fn encode_ack_frame(
    ack_delay: u64, ranges: &ranges::RangeSet, ecn_counts: Option<&EcnCounts>,
    b: &mut impl FrameSink,
) -> Result<()> {
    let mut it = ranges.iter().rev();
    let first = it.next().ok_or(Error::InvalidFrame)?;

    b.put_varint(if ecn_counts.is_some() { 0x03 } else { 0x02 })?;
    let ack_block = (first.end - 1) - first.start;

    b.put_varint(first.end - 1)?;
    b.put_varint(ack_delay)?;
    b.put_varint(it.len() as u64)?;
    b.put_varint(ack_block)?;

    let mut smallest_ack = first.start;

    for block in it {
        let gap = smallest_ack
            .checked_sub(block.end)
            .and_then(|gap| gap.checked_sub(1))
            .ok_or(Error::InvalidFrame)?;
        let ack_block = (block.end - 1) - block.start;

        b.put_varint(gap)?;
        b.put_varint(ack_block)?;

        smallest_ack = block.start;
    }

    if let Some(ecn) = ecn_counts {
        b.put_varint(ecn.ect0)?;
        b.put_varint(ecn.ect1)?;
        b.put_varint(ecn.ce)?;
    }
    Ok(())
}

fn parse_ack_frame(ty: u64, b: &mut octets::Octets) -> Result<Frame> {
    let largest_ack = b.get_varint()?;
    let ack_delay = b.get_varint()?;
    let block_count = b.get_varint()?;
    let ack_block = b.get_varint()?;

    if largest_ack < ack_block {
        return Err(Error::InvalidFrame);
    }

    let mut smallest_ack = largest_ack - ack_block;

    let mut ranges = ranges::RangeSet::default();

    ranges.insert(smallest_ack..largest_ack + 1);

    for _i in 0..block_count {
        let gap = b.get_varint()?;

        if smallest_ack < 2 + gap {
            return Err(Error::InvalidFrame);
        }

        let largest_ack = (smallest_ack - gap) - 2;
        let ack_block = b.get_varint()?;

        if largest_ack < ack_block {
            return Err(Error::InvalidFrame);
        }

        smallest_ack = largest_ack - ack_block;

        ranges.insert(smallest_ack..largest_ack + 1);
    }

    let ecn_counts = if ty & 0x01 != 0 {
        let ecn = EcnCounts {
            ect0: b.get_varint()?,
            ect1: b.get_varint()?,
            ce: b.get_varint()?,
        };

        Some(ecn)
    } else {
        None
    };

    Ok(Frame::Ack {
        ack_delay,
        ranges,
        ecn_counts,
    })
}

/// Payload lengths are at least two bytes, permitting reservation before
/// emission. Larger lengths use the next representable width.
pub fn payload_length_width(length: u64) -> usize {
    octets::varint_len(length).max(2)
}

/// Largest payload that fits in the available bytes including its length
/// field, and the exact reserved width. At a width transition there may be
/// one or more unused bytes rather than room for another payload byte.
pub fn payload_capacity(available: usize) -> Option<(usize, usize)> {
    for width in [8, 4, 2] {
        let Some(capacity) = available.checked_sub(width) else {
            continue;
        };
        let limit = (1_u64 << (width * 8 - 2)) - 1;
        let capacity = capacity.min(usize::try_from(limit).unwrap_or(usize::MAX));
        if payload_length_width(capacity as u64) == width {
            return Some((capacity, width));
        }
    }
    None
}

pub fn encode_crypto_header(
    offset: u64, length: u64, length_width: usize, b: &mut impl FrameSink,
) -> Result<()> {
    b.put_varint(0x06)?;

    b.put_varint(offset)?;

    b.put_varint_with_len(length, length_width)?;

    Ok(())
}

pub fn encode_stream_header(
    stream_id: u64, offset: u64, length: u64, fin: bool, length_width: usize,
    b: &mut impl FrameSink,
) -> Result<()> {
    let mut ty: u8 = 0x08;

    // Always encode offset.
    ty |= 0x04;

    // Always encode length.
    ty |= 0x02;

    if fin {
        ty |= 0x01;
    }

    b.put_varint(u64::from(ty))?;

    b.put_varint(stream_id)?;
    b.put_varint(offset)?;

    b.put_varint_with_len(length, length_width)?;

    Ok(())
}

pub fn encode_dgram_header(length: u64, b: &mut impl FrameSink) -> Result<()> {
    let mut ty: u8 = 0x30;

    // Always encode length
    ty |= 0x01;

    b.put_varint(u64::from(ty))?;

    b.put_varint_with_len(length, payload_length_width(length))?;

    Ok(())
}

fn parse_stream_frame(ty: u64, b: &mut octets::Octets) -> Result<Frame> {
    let stream_id = b.get_varint()?;

    let offset = if ty & 0x04 != 0 { b.get_varint()? } else { 0 };

    let declared_len = if ty & 0x02 != 0 {
        b.get_varint()?
    } else {
        b.cap() as u64
    };

    if offset
        .checked_add(declared_len)
        .is_none_or(|end| end >= MAX_STREAM_SIZE)
    {
        return Err(Error::InvalidFrame);
    }
    let len = usize::try_from(declared_len).map_err(|_| Error::BufferTooShort)?;

    let fin = ty & 0x01 != 0;

    let data = b.get_bytes(len)?;
    let data = <RangeBuf>::from(data.as_ref(), offset, fin);

    Ok(Frame::Stream { stream_id, data })
}

pub fn parse_datagram_payload<'a>(
    ty: u64, b: &mut octets::Octets<'a>,
) -> Result<octets::Octets<'a>> {
    if ty & 0x01 != 0 {
        // Octets validates the full QUIC varint before converting to usize.
        Ok(b.get_bytes_with_varint_length()?)
    } else {
        Ok(b.get_bytes(b.cap())?)
    }
}

fn parse_datagram_frame(ty: u64, b: &mut octets::Octets) -> Result<Frame> {
    let data = parse_datagram_payload(ty, b)?;

    Ok(Frame::Datagram {
        data: Vec::from(data.buf()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_checked(frame: &Frame, out: &mut [u8]) -> usize {
        let expected = frame.wire_len().unwrap();
        let mut b = octets::OctetsMut::with_slice(out);
        let written = frame.to_bytes(&mut b).unwrap();
        assert_eq!(written, expected);
        assert_eq!(written, b.off());
        written
    }

    fn assert_roundtrip(
        frame: &Frame, out: &mut [u8], expected_len: usize,
        other_allowed: &[packet::Type],
    ) {
        assert_eq!(encode_checked(frame, out), expected_len);
        for ty in [
            packet::Type::Short,
            packet::Type::Initial,
            packet::Type::ZeroRTT,
            packet::Type::Handshake,
        ] {
            let mut reader = octets::Octets::with_slice(out);
            let decoded = Frame::from_bytes(&mut reader, ty);
            if ty == packet::Type::Short || other_allowed.contains(&ty) {
                assert_eq!(decoded, Ok(frame.clone()), "{ty:?}");
            } else {
                assert!(decoded.is_err(), "{ty:?}");
            }
        }
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn payload_and_encoded_header_have_identical_diagnostics() {
        let data = b"abc";
        let cases = [
            (
                Frame::Crypto {
                    data: <RangeBuf>::from(data, 42, false),
                },
                Frame::CryptoHeader {
                    offset: 42,
                    length: 3,
                },
            ),
            (
                Frame::Stream {
                    stream_id: 4,
                    data: <RangeBuf>::from(data, 42, true),
                },
                Frame::StreamHeader {
                    stream_id: 4,
                    offset: 42,
                    length: 3,
                    fin: true,
                },
            ),
            (
                Frame::Datagram {
                    data: data.to_vec(),
                },
                Frame::DatagramHeader { length: 3 },
            ),
        ];
        for (payload, header) in cases {
            assert_eq!(payload.to_qlog(3), header.to_qlog(3));
            assert_eq!(format!("{payload:?}"), format!("{header:?}"));
        }
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn qlog_ack_preserves_all_ecn_counters() {
        let mut ranges = ranges::RangeSet::default();
        ranges.insert(12..15);
        let frame = Frame::Ack {
            ack_delay: 0,
            ranges,
            ecn_counts: Some(EcnCounts {
                ect0: 37,
                ect1: 42,
                ce: 9,
            }),
        };
        assert!(matches!(frame.to_qlog(3), QuicFrame::Ack {
            ect0: Some(37),
            ect1: Some(42),
            ce: Some(9),
            ..
        }));

        let frame = Frame::Ack {
            ack_delay: 0,
            ranges: ranges::RangeSet::default(),
            ecn_counts: None,
        };
        assert!(matches!(frame.to_qlog(3), QuicFrame::Ack {
            ect0: None,
            ect1: None,
            ce: None,
            ..
        }));
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn qlog_ack_delay_uses_wire_exponent_and_milliseconds() {
        let mut ranges = ranges::RangeSet::default();
        ranges.insert(1..2);

        for (encoded, exponent, expected) in [
            (125, 0, 0.125),
            (125, 3, 1.0),
            (125, 8, 32.0),
            (125, 20, 131_072.0),
            (0, 20, 0.0),
        ] {
            let frame = Frame::Ack {
                ack_delay: encoded,
                ranges: ranges.clone(),
                ecn_counts: None,
            };
            let QuicFrame::Ack { ack_delay, .. } = frame.to_qlog(exponent) else {
                panic!("expected ACK");
            };
            let delay = ack_delay.unwrap();
            assert!((delay - expected).abs() <= expected * f32::EPSILON);
        }

        let frame = Frame::Ack {
            ack_delay: octets::MAX_VAR_INT,
            ranges,
            ecn_counts: None,
        };
        assert!(matches!(frame.to_qlog(20), QuicFrame::Ack {
            ack_delay: None,
            ..
        }));
    }

    #[test]
    fn frame_type_validation_matches_packet_spaces() {
        use packet::Type::Handshake;
        use packet::Type::Initial;
        use packet::Type::Retry;
        use packet::Type::Short;
        use packet::Type::VersionNegotiation;
        use packet::Type::ZeroRTT;
        let cases = [
            (Initial, &[0, 1, 2, 3, 6, 0x1c][..]),
            (Handshake, &[0, 1, 2, 3, 6, 0x1c][..]),
            (
                ZeroRTT,
                &[
                    0, 1, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                    21, 22, 23, 24, 26, 28, 29, 48, 49,
                ][..],
            ),
            (Short, &(0..=30).chain([48, 49]).collect::<Vec<_>>()[..]),
            (Retry, &[][..]),
            (VersionNegotiation, &[][..]),
        ];
        for (packet, allowed) in cases {
            for ty in 0_u8..=63 {
                let wire = [ty];
                let mut reader = octets::Octets::with_slice(&wire);
                let expected = if allowed.contains(&ty) {
                    Ok(u64::from(ty))
                } else if matches!(ty, 0..=30 | 48 | 49) {
                    Err(Error::InvalidPacket)
                } else {
                    Err(Error::InvalidFrame)
                };
                assert_eq!(
                    read_frame_type(&mut reader, packet),
                    expected,
                    "{packet:?} type {ty:#x}"
                );
            }
        }
    }

    #[test]
    fn only_frame_type_requires_minimal_varint_encoding() {
        for ty in [0_u64, 1, 0x08, 0x1c, 0x30, 0x31] {
            for width in [2, 4, 8] {
                let mut wire = [0; 16];
                let mut writer = octets::OctetsMut::with_slice(&mut wire);
                writer.put_varint_with_len(ty, width).unwrap();
                let mut reader = octets::Octets::with_slice(&wire[..width]);
                assert_eq!(
                    Frame::from_bytes(&mut reader, packet::Type::Short),
                    Err(Error::InvalidPacket)
                );
            }
        }
        // A non-minimal encoding of a frame field remains legal.
        let mut reader = octets::Octets::with_slice(&[0x10, 0x40, 0x01]);
        assert_eq!(
            Frame::from_bytes(&mut reader, packet::Type::Short),
            Ok(Frame::MaxData { max: 1 })
        );
    }

    #[test]
    fn rejects_invalid_frame_layouts_consistently() {
        let mut ranges = ranges::RangeSet::default();
        ranges.insert(octets::MAX_VAR_INT + 1..octets::MAX_VAR_INT + 2);
        let cases = [
            (
                Frame::Ack {
                    ack_delay: 0,
                    ranges: ranges::RangeSet::default(),
                    ecn_counts: None,
                },
                Error::InvalidFrame,
            ),
            (
                Frame::Ack {
                    ack_delay: 0,
                    ranges,
                    ecn_counts: None,
                },
                Error::BufferTooShort,
            ),
            (
                Frame::NewConnectionId {
                    seq_num: 1,
                    retire_prior_to: 0,
                    conn_id: packet::ConnectionId::default(),
                    reset_token: [0; 16],
                },
                Error::InvalidFrame,
            ),
            (
                Frame::NewConnectionId {
                    seq_num: 1,
                    retire_prior_to: 0,
                    conn_id: packet::ConnectionId::copy_from_slice(&[0; 256]),
                    reset_token: [0; 16],
                },
                Error::InvalidFrame,
            ),
            (
                Frame::CryptoHeader {
                    offset: 0,
                    length: 4,
                },
                Error::InvalidState,
            ),
            (
                Frame::StreamHeader {
                    stream_id: 0,
                    offset: 0,
                    length: 4,
                    fin: false,
                },
                Error::InvalidState,
            ),
            (Frame::DatagramHeader { length: 4 }, Error::InvalidState),
        ];
        let mut out = [0; 17_000];
        for (frame, error) in cases {
            assert_eq!(frame.wire_len(), Err(error));
            let mut b = octets::OctetsMut::with_slice(&mut out);
            assert_eq!(frame.to_bytes(&mut b), Err(error));
        }
    }

    #[test]
    fn payload_capacity_is_maximal_at_width_transitions() {
        for available in (0..=65_535)
            .chain((1_073_741_810..=1_073_741_840).chain([usize::MAX]))
        {
            if let Some((payload, width)) = payload_capacity(available) {
                assert_eq!(width, payload_length_width(payload as u64));
                assert!(payload + width <= available);
                if let Some(next) = payload.checked_add(1) {
                    assert!(
                        next as u64 > octets::MAX_VAR_INT ||
                            next.checked_add(payload_length_width(
                                next as u64
                            ))
                            .is_none_or(|size| size > available)
                    );
                }
            } else {
                assert!(available < 2);
            }
        }
    }

    #[test]
    fn large_data_frames_roundtrip() {
        for length in [16_383, 16_384, 65_000] {
            let data = vec![0x5a; length];
            let width = payload_length_width(length as u64);
            let frames = [
                (
                    Frame::Crypto {
                        data: <RangeBuf>::from(&data, 0, false),
                    },
                    2,
                ),
                (
                    Frame::Stream {
                        stream_id: 0,
                        data: <RangeBuf>::from(&data, 0, true),
                    },
                    3,
                ),
                (Frame::Datagram { data }, 1),
            ];
            for (frame, fixed) in frames {
                let mut output = vec![0; fixed + width + length];
                assert_eq!(encode_checked(&frame, &mut output), output.len());
                let mut reader = octets::Octets::with_slice(&output);
                assert_eq!(
                    Frame::from_bytes(&mut reader, packet::Type::Short),
                    Ok(frame)
                );
                assert_eq!(reader.cap(), 0);
            }
        }
    }

    #[test]
    fn padding() {
        let mut d = [42; 128];

        let frame = Frame::Padding { len: 128 };

        assert_roundtrip(&frame, &mut d, 128, &[
            packet::Type::Initial,
            packet::Type::ZeroRTT,
            packet::Type::Handshake,
        ]);
    }

    #[test]
    fn ping() {
        let mut d = [42; 128];

        let frame = Frame::Ping { mtu_probe: None };

        let wire_len = encode_checked(&frame, &mut d);

        assert_eq!(wire_len, 1);
        assert_eq!(&d[..wire_len], [0x01_u8]);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(Frame::from_bytes(&mut b, packet::Type::Short), Ok(frame));

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_ok());

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_ok());
    }

    #[test]
    fn ack() {
        let mut d = [42; 128];

        let mut ranges = ranges::RangeSet::default();
        ranges.insert(4..7);
        ranges.insert(9..12);
        ranges.insert(15..19);
        ranges.insert(3000..5000);

        let frame = Frame::Ack {
            ack_delay: 874_656_534,
            ranges,
            ecn_counts: None,
        };

        assert_roundtrip(&frame, &mut d, 17, &[
            packet::Type::Initial,
            packet::Type::Handshake,
        ]);
    }

    #[test]
    fn ack_ecn() {
        let mut d = [42; 128];

        let mut ranges = ranges::RangeSet::default();
        ranges.insert(4..7);
        ranges.insert(9..12);
        ranges.insert(15..19);
        ranges.insert(3000..5000);

        let ecn_counts = Some(EcnCounts {
            ect0: 100,
            ect1: 200,
            ce: 300,
        });

        let frame = Frame::Ack {
            ack_delay: 874_656_534,
            ranges,
            ecn_counts,
        };

        assert_roundtrip(&frame, &mut d, 23, &[
            packet::Type::Initial,
            packet::Type::Handshake,
        ]);
    }

    #[test]
    fn reset_stream() {
        let mut d = [42; 128];

        let frame = Frame::ResetStream {
            stream_id: 123_213,
            error_code: 21_123_767,
            final_size: 21_123_767,
        };

        assert_roundtrip(&frame, &mut d, 13, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn stop_sending() {
        let mut d = [42; 128];

        let frame = Frame::StopSending {
            stream_id: 123_213,
            error_code: 15_352,
        };

        assert_roundtrip(&frame, &mut d, 7, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn crypto() {
        let mut d = [42; 128];

        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Crypto {
            data: <RangeBuf>::from(&data, 1230976, false),
        };

        assert_roundtrip(&frame, &mut d, 19, &[
            packet::Type::Initial,
            packet::Type::Handshake,
        ]);
    }

    #[test]
    fn new_token() {
        let mut d = [42; 128];

        let frame = Frame::NewToken {
            token: Vec::from("this is a token"),
        };

        assert_roundtrip(&frame, &mut d, 17, &[]);
    }

    #[test]
    fn stream() {
        let mut d = [42; 128];

        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Stream {
            stream_id: 32,
            data: <RangeBuf>::from(&data, 1230976, true),
        };

        assert_roundtrip(&frame, &mut d, 20, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn oversized_wire_frame_lengths_cannot_wrap_to_empty_payloads() {
        // A 2^32 length is valid QUIC varint syntax, but far larger than
        // this packet. On 32-bit systems the old `as usize` yielded zero.
        const OVERSIZED_LENGTH: u64 = 1_u64 << 32;
        for frame_type in [0x07_u64, 0x0a, 0x31] {
            let mut wire = [0_u8; 32];
            let mut writer = octets::OctetsMut::with_slice(&mut wire);
            writer.put_varint(frame_type).unwrap();
            if frame_type == 0x0a {
                writer.put_varint(0).unwrap(); // STREAM ID
            }
            writer.put_varint(OVERSIZED_LENGTH).unwrap();
            let used = 32 - writer.cap();
            let mut reader = octets::Octets::with_slice(&wire[..used]);
            assert_eq!(
                Frame::from_bytes(&mut reader, packet::Type::Short),
                Err(Error::BufferTooShort),
                "frame {frame_type:#x} accepted a truncated oversized payload",
            );
        }
    }

    #[test]
    fn stream_too_big() {
        let mut d = [42; 128];

        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Stream {
            stream_id: 32,
            data: <RangeBuf>::from(&data, MAX_STREAM_SIZE - 11, true),
        };

        let wire_len = encode_checked(&frame, &mut d);

        assert_eq!(wire_len, 24);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short),
            Err(Error::InvalidFrame)
        );
    }

    #[test]
    fn max_data() {
        let mut d = [42; 128];

        let frame = Frame::MaxData { max: 128_318_273 };

        assert_roundtrip(&frame, &mut d, 5, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn max_stream_data() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreamData {
            stream_id: 12_321,
            max: 128_318_273,
        };

        assert_roundtrip(&frame, &mut d, 7, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn stream_count_direction_keeps_exact_wire_types() {
        for (direction, max_ty, blocked_ty) in [
            (StreamDirection::Bidirectional, 0x12, 0x16),
            (StreamDirection::Unidirectional, 0x13, 0x17),
        ] {
            for (frame, ty) in [
                (Frame::MaxStreams { direction, max: 17 }, max_ty),
                (
                    Frame::StreamsBlocked {
                        direction,
                        limit: 17,
                    },
                    blocked_ty,
                ),
            ] {
                let mut bytes = [0; 2];
                assert_eq!(encode_checked(&frame, &mut bytes), 2);
                assert_eq!(bytes, [ty, 17]);
                let mut reader = octets::Octets::with_slice(&bytes);
                assert_eq!(
                    Frame::from_bytes(&mut reader, packet::Type::Short),
                    Ok(frame)
                );
            }
        }
    }

    #[test]
    fn max_streams_bidi() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreams {
            direction: StreamDirection::Bidirectional,
            max: 128_318_273,
        };

        assert_roundtrip(&frame, &mut d, 5, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn max_streams_uni() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreams {
            direction: StreamDirection::Unidirectional,
            max: 128_318_273,
        };

        assert_roundtrip(&frame, &mut d, 5, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn data_blocked() {
        let mut d = [42; 128];

        let frame = Frame::DataBlocked { limit: 128_318_273 };

        assert_roundtrip(&frame, &mut d, 5, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn stream_data_blocked() {
        let mut d = [42; 128];

        let frame = Frame::StreamDataBlocked {
            stream_id: 12_321,
            limit: 128_318_273,
        };

        assert_roundtrip(&frame, &mut d, 7, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn streams_blocked_bidi() {
        let mut d = [42; 128];

        let frame = Frame::StreamsBlocked {
            direction: StreamDirection::Bidirectional,
            limit: 128_318_273,
        };

        assert_roundtrip(&frame, &mut d, 5, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn streams_blocked_uni() {
        let mut d = [42; 128];

        let frame = Frame::StreamsBlocked {
            direction: StreamDirection::Unidirectional,
            limit: 128_318_273,
        };

        assert_roundtrip(&frame, &mut d, 5, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn new_connection_id() {
        let mut d = [42; 128];

        let frame = Frame::NewConnectionId {
            seq_num: 123_213,
            retire_prior_to: 122_211,
            conn_id: packet::ConnectionId::copy_from_slice(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            ]),
            reset_token: [0x42; 16],
        };

        assert_roundtrip(&frame, &mut d, 41, &[packet::Type::ZeroRTT]);
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn qlog_connection_id_length_saturates_instead_of_truncating() {
        for (length, reported) in [(20, 20), (256, u8::MAX as usize)] {
            let frame = Frame::NewConnectionId {
                seq_num: 1,
                retire_prior_to: 0,
                conn_id: packet::ConnectionId::copy_from_slice(&vec![7; length]),
                reset_token: [0; 16],
            };
            assert!(matches!(
                frame.to_qlog(3),
                QuicFrame::NewConnectionId {
                    connection_id_length: Some(n),
                    ..
                } if usize::from(n) == reported
            ));
        }
    }

    #[test]
    fn retire_connection_id() {
        let mut d = [42; 128];

        let frame = Frame::RetireConnectionId { seq_num: 123_213 };

        assert_roundtrip(&frame, &mut d, 5, &[]);
    }

    #[test]
    fn path_challenge() {
        let mut d = [42; 128];

        let frame = Frame::PathChallenge {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        };

        assert_roundtrip(&frame, &mut d, 9, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn path_response() {
        let mut d = [42; 128];

        let frame = Frame::PathResponse {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        };

        assert_roundtrip(&frame, &mut d, 9, &[]);
    }

    #[test]
    fn connection_close() {
        let mut d = [42; 128];

        let frame = Frame::ConnectionClose {
            error_code: 0xbeef,
            frame_type: 523_423,
            reason: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        assert_roundtrip(&frame, &mut d, 22, &[
            packet::Type::Initial,
            packet::Type::Handshake,
            packet::Type::ZeroRTT,
        ]);
    }

    #[test]
    fn application_close() {
        let mut d = [42; 128];

        let frame = Frame::ApplicationClose {
            error_code: 0xbeef,
            reason: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        assert_roundtrip(&frame, &mut d, 18, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn handshake_done() {
        let mut d = [42; 128];

        let frame = Frame::HandshakeDone;

        assert_roundtrip(&frame, &mut d, 1, &[]);
    }

    #[test]
    fn datagram() {
        let mut d = [42; 128];

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let frame = Frame::Datagram { data: data.clone() };

        let wire_len = encode_checked(&frame, &mut d);

        assert_eq!(wire_len, 15);

        let mut b = octets::Octets::with_slice(&d);
        assert_eq!(
            Frame::from_bytes(&mut b, packet::Type::Short),
            Ok(frame.clone())
        );

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Initial).is_err());

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(&mut b, packet::Type::ZeroRTT).is_ok());

        let mut b = octets::Octets::with_slice(&d);
        assert!(Frame::from_bytes(&mut b, packet::Type::Handshake).is_err());

        let frame_data = match &frame {
            Frame::Datagram { data } => data.clone(),

            _ => unreachable!(),
        };

        assert_eq!(frame_data, data);
    }
}
