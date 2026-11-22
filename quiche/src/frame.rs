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

#[cfg(feature = "qlog")]
use qlog::events::quic::AckRange;
#[cfg(feature = "qlog")]
use qlog::events::quic::ErrorSpace;
#[cfg(feature = "qlog")]
use qlog::events::quic::QuicFrame;
#[cfg(feature = "qlog")]
use qlog::events::quic::StreamType;

pub const MAX_CRYPTO_OVERHEAD: usize = 8;
pub const MAX_DGRAM_OVERHEAD: usize = 2;
pub const MAX_STREAM_SIZE: u64 = 1 << 62;

/// Output of the shared frame encoding schema. A size-only sink validates
/// the same field widths without allocating or writing a packet.
pub trait FrameSink {
    fn put_varint(&mut self, value: u64) -> Result<()> {
        self.put_varint_with_len(value, octets::varint_len(value))
    }

    fn put_varint_with_len(&mut self, value: u64, len: usize) -> Result<()>;
    fn put_bytes(&mut self, value: &[u8]) -> Result<()>;
    fn put_padding(&mut self, len: usize) -> Result<()>;
}

impl FrameSink for octets::OctetsMut<'_> {
    fn put_varint_with_len(&mut self, value: u64, len: usize) -> Result<()> {
        octets::OctetsMut::put_varint_with_len(self, value, len)?;
        Ok(())
    }

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
    fn put_varint_with_len(&mut self, value: u64, len: usize) -> Result<()> {
        if !matches!(len, 1 | 2 | 4 | 8) ||
            value > octets::MAX_VAR_INT ||
            octets::varint_len(value) > len
        {
            return Err(Error::BufferTooShort);
        }
        // All callers supply the natural varint width or the fixed two-byte
        // payload length specified by the stream/crypto/datagram schema.
        self.add(len)
    }

    fn put_bytes(&mut self, value: &[u8]) -> Result<()> {
        self.add(value.len())
    }

    fn put_padding(&mut self, len: usize) -> Result<()> {
        self.add(len)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcnCounts {
    ect0_count: u64,
    ect1_count: u64,
    ecn_ce_count: u64,
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

    #[expect(
        clippy::upper_case_acronyms,
        reason = "ACK is the standardized QUIC frame name"
    )]
    ACK {
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

    MaxStreamsBidi {
        max: u64,
    },

    MaxStreamsUni {
        max: u64,
    },

    DataBlocked {
        limit: u64,
    },

    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },

    StreamsBlockedBidi {
        limit: u64,
    },

    StreamsBlockedUni {
        limit: u64,
    },

    NewConnectionId {
        seq_num: u64,
        retire_prior_to: u64,
        conn_id: Vec<u8>,
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

impl Frame {
    pub fn from_bytes(b: &mut octets::Octets, pkt: packet::Type) -> Result<Self> {
        let frame_type = b.get_varint()?;
        Self::from_bytes_with_type(frame_type, b, pkt)
    }

    pub(crate) fn from_bytes_with_type(
        frame_type: u64, b: &mut octets::Octets, pkt: packet::Type,
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

            0x07 => {
                let len = usize::try_from(b.get_varint()?)
                    .map_err(|_| Error::BufferTooShort)?;
                if len == 0 {
                    return Err(Error::InvalidFrame);
                }

                Self::NewToken {
                    token: b.get_bytes(len)?.to_vec(),
                }
            },

            0x08..=0x0f => parse_stream_frame(frame_type, b)?,

            0x10 => Self::MaxData {
                max: b.get_varint()?,
            },

            0x11 => Self::MaxStreamData {
                stream_id: b.get_varint()?,
                max: b.get_varint()?,
            },

            0x12 => Self::MaxStreamsBidi {
                max: b.get_varint()?,
            },

            0x13 => Self::MaxStreamsUni {
                max: b.get_varint()?,
            },

            0x14 => Self::DataBlocked {
                limit: b.get_varint()?,
            },

            0x15 => Self::StreamDataBlocked {
                stream_id: b.get_varint()?,
                limit: b.get_varint()?,
            },

            0x16 => Self::StreamsBlockedBidi {
                limit: b.get_varint()?,
            },

            0x17 => Self::StreamsBlockedUni {
                limit: b.get_varint()?,
            },

            0x18 => {
                let seq_num = b.get_varint()?;
                let retire_prior_to = b.get_varint()?;
                let conn_id_len = b.get_u8()?;

                if !(1..=packet::MAX_CID_LEN).contains(&conn_id_len) {
                    return Err(Error::InvalidFrame);
                }

                Self::NewConnectionId {
                    seq_num,
                    retire_prior_to,
                    conn_id: b.get_bytes(conn_id_len as usize)?.to_vec(),
                    reset_token: b
                        .get_bytes(16)?
                        .buf()
                        .try_into()
                        .map_err(|_| Error::BufferTooShort)?,
                }
            },

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

        let allowed = match (pkt, &frame) {
            // PADDING and PING are allowed on all packet types.
            (_, Self::Padding { .. } | Self::Ping { .. }) => true,

            // ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE, and
            // RETIRE_CONNECTION_ID can't be sent on 0-RTT packets.
            (packet::Type::ZeroRTT, Self::ACK { .. }) => false,
            (packet::Type::ZeroRTT, Self::Crypto { .. }) => false,
            (packet::Type::ZeroRTT, Self::HandshakeDone) => false,
            (packet::Type::ZeroRTT, Self::NewToken { .. }) => false,
            (packet::Type::ZeroRTT, Self::PathResponse { .. }) => false,
            (packet::Type::ZeroRTT, Self::RetireConnectionId { .. }) => false,
            (packet::Type::ZeroRTT, Self::ConnectionClose { .. }) => false,

            // ACK, CRYPTO and CONNECTION_CLOSE can be sent on all other packet
            // types.
            (_, Self::ACK { .. }) => true,
            (_, Self::Crypto { .. }) => true,
            (_, Self::ConnectionClose { .. }) => true,

            // All frames are allowed on 0-RTT and 1-RTT packets.
            (packet::Type::Short, _) => true,
            (packet::Type::ZeroRTT, _) => true,

            // All other cases are forbidden.
            (..) => false,
        };

        if !allowed {
            return Err(Error::InvalidPacket);
        }

        Ok(frame)
    }

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

    fn encode(&self, b: &mut impl FrameSink) -> Result<()> {
        match self {
            Self::Padding { len } => b.put_padding(*len)?,

            Self::Ping { .. } => {
                b.put_varint(0x01)?;
            },

            Self::ACK {
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                let mut it = ranges.iter().rev();
                let first = it.next().ok_or(Error::InvalidFrame)?;

                b.put_varint(if ecn_counts.is_some() { 0x03 } else { 0x02 })?;
                let ack_block = (first.end - 1) - first.start;

                b.put_varint(first.end - 1)?;
                b.put_varint(*ack_delay)?;
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
                    b.put_varint(ecn.ect0_count)?;
                    b.put_varint(ecn.ect1_count)?;
                    b.put_varint(ecn.ecn_ce_count)?;
                }
            },

            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                b.put_varint(0x04)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*error_code)?;
                b.put_varint(*final_size)?;
            },

            Self::StopSending {
                stream_id,
                error_code,
            } => {
                b.put_varint(0x05)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*error_code)?;
            },

            Self::Crypto { data } => {
                encode_crypto_header(data.off(), data.len() as u64, b)?;

                b.put_bytes(data)?;
            },

            Self::NewToken { token } => {
                b.put_varint(0x07)?;

                b.put_varint(token.len() as u64)?;
                b.put_bytes(token)?;
            },

            Self::Stream { stream_id, data } => {
                encode_stream_header(
                    *stream_id,
                    data.off(),
                    data.len() as u64,
                    data.fin(),
                    b,
                )?;

                b.put_bytes(data)?;
            },

            Self::MaxData { max } => {
                b.put_varint(0x10)?;

                b.put_varint(*max)?;
            },

            Self::MaxStreamData { stream_id, max } => {
                b.put_varint(0x11)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*max)?;
            },

            Self::MaxStreamsBidi { max } => {
                b.put_varint(0x12)?;

                b.put_varint(*max)?;
            },

            Self::MaxStreamsUni { max } => {
                b.put_varint(0x13)?;

                b.put_varint(*max)?;
            },

            Self::DataBlocked { limit } => {
                b.put_varint(0x14)?;

                b.put_varint(*limit)?;
            },

            Self::StreamDataBlocked { stream_id, limit } => {
                b.put_varint(0x15)?;

                b.put_varint(*stream_id)?;
                b.put_varint(*limit)?;
            },

            Self::StreamsBlockedBidi { limit } => {
                b.put_varint(0x16)?;

                b.put_varint(*limit)?;
            },

            Self::StreamsBlockedUni { limit } => {
                b.put_varint(0x17)?;

                b.put_varint(*limit)?;
            },

            Self::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                let len = u8::try_from(conn_id.len())
                    .map_err(|_| Error::InvalidFrame)?;
                if !(1..=packet::MAX_CID_LEN).contains(&len) {
                    return Err(Error::InvalidFrame);
                }
                b.put_varint(0x18)?;

                b.put_varint(*seq_num)?;
                b.put_varint(*retire_prior_to)?;
                b.put_bytes(&[len])?;
                b.put_bytes(conn_id.as_ref())?;
                b.put_bytes(reset_token.as_ref())?;
            },

            Self::RetireConnectionId { seq_num } => {
                b.put_varint(0x19)?;

                b.put_varint(*seq_num)?;
            },

            Self::PathChallenge { data } => {
                b.put_varint(0x1a)?;

                b.put_bytes(data.as_ref())?;
            },

            Self::PathResponse { data } => {
                b.put_varint(0x1b)?;

                b.put_bytes(data.as_ref())?;
            },

            Self::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                b.put_varint(0x1c)?;

                b.put_varint(*error_code)?;
                b.put_varint(*frame_type)?;
                b.put_varint(reason.len() as u64)?;
                b.put_bytes(reason.as_ref())?;
            },

            Self::ApplicationClose { error_code, reason } => {
                b.put_varint(0x1d)?;

                b.put_varint(*error_code)?;
                b.put_varint(reason.len() as u64)?;
                b.put_bytes(reason.as_ref())?;
            },

            Self::HandshakeDone => {
                b.put_varint(0x1e)?;
            },

            Self::Datagram { data } => {
                encode_dgram_header(data.len() as u64, b)?;

                b.put_bytes(data.as_ref())?;
            },

            // These variants only describe frames already encoded directly
            // into the packet. They do not own a serializable payload.
            Self::CryptoHeader { .. } |
            Self::StreamHeader { .. } |
            Self::DatagramHeader { .. } => return Err(Error::InvalidState),
        }
        Ok(())
    }

    pub const fn ack_eliciting(&self) -> bool {
        // Any other frame is ack-eliciting (note the `!`).
        !matches!(
            self,
            Self::Padding { .. } |
                Self::ACK { .. } |
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
    pub fn to_qlog(&self) -> QuicFrame {
        use qlog::events::ConnectionClosedFrameError;
        use qlog::events::RawInfo;

        match self {
            Frame::Padding { len } => QuicFrame::Padding {
                raw: Some(Box::new(RawInfo {
                    length: None,
                    payload_length: Some(*len as u64),
                    data: None,
                })),
            },

            Frame::Ping { .. } => QuicFrame::Ping { raw: None },

            Frame::ACK {
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                let ack_ranges = ranges
                    .iter()
                    .map(|r| AckRange::new(r.start, r.end - 1))
                    .collect();

                let (ect0, ect1, ce) = match ecn_counts {
                    Some(ecn) => (
                        Some(ecn.ect0_count),
                        Some(ecn.ect1_count),
                        Some(ecn.ecn_ce_count),
                    ),

                    None => (None, None, None),
                };

                QuicFrame::Ack {
                    ack_delay: Some(*ack_delay as f32 / 1000.0),
                    acked_ranges: Some(ack_ranges),
                    ect1,
                    ect0,
                    ce,
                    raw: None,
                }
            },

            Frame::ResetStream {
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

            Frame::StopSending {
                stream_id,
                error_code,
            } => QuicFrame::StopSending {
                stream_id: *stream_id,
                error: qlog::events::ApplicationError::Unknown,
                error_code: Some(*error_code),
                raw: None,
            },

            Frame::Crypto { data } => QuicFrame::Crypto {
                offset: data.off(),
                raw: Some(Box::new(RawInfo {
                    length: None,
                    payload_length: Some(data.len() as u64),
                    data: None,
                })),
            },

            Frame::CryptoHeader { offset, length } => QuicFrame::Crypto {
                offset: *offset,
                raw: Some(Box::new(RawInfo {
                    length: None,
                    payload_length: Some(*length as u64),
                    data: None,
                })),
            },

            Frame::NewToken { token } => QuicFrame::NewToken {
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

            Frame::Stream { stream_id, data } => QuicFrame::Stream {
                stream_id: *stream_id,
                offset: Some(data.off()),
                fin: data.fin().then_some(true),
                raw: Some(Box::new(RawInfo {
                    length: None,
                    payload_length: Some(data.len() as u64),
                    data: None,
                })),
            },

            Frame::StreamHeader {
                stream_id,
                offset,
                length,
                fin,
            } => QuicFrame::Stream {
                stream_id: *stream_id,
                offset: Some(*offset),
                fin: fin.then(|| true),
                raw: Some(Box::new(RawInfo {
                    length: None,
                    payload_length: Some(*length as u64),
                    data: None,
                })),
            },

            Frame::MaxData { max } => QuicFrame::MaxData {
                maximum: *max,
                raw: None,
            },

            Frame::MaxStreamData { stream_id, max } => QuicFrame::MaxStreamData {
                stream_id: *stream_id,
                maximum: *max,
                raw: None,
            },

            Frame::MaxStreamsBidi { max } => QuicFrame::MaxStreams {
                stream_type: StreamType::Bidirectional,
                maximum: *max,
                raw: None,
            },

            Frame::MaxStreamsUni { max } => QuicFrame::MaxStreams {
                stream_type: StreamType::Unidirectional,
                maximum: *max,
                raw: None,
            },

            Frame::DataBlocked { limit } => QuicFrame::DataBlocked {
                limit: *limit,
                raw: None,
            },

            Frame::StreamDataBlocked { stream_id, limit } =>
                QuicFrame::StreamDataBlocked {
                    stream_id: *stream_id,
                    limit: *limit,
                    raw: None,
                },

            Frame::StreamsBlockedBidi { limit } => QuicFrame::StreamsBlocked {
                stream_type: StreamType::Bidirectional,
                limit: *limit,
                raw: None,
            },

            Frame::StreamsBlockedUni { limit } => QuicFrame::StreamsBlocked {
                stream_type: StreamType::Unidirectional,
                limit: *limit,
                raw: None,
            },

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => QuicFrame::NewConnectionId {
                sequence_number: *seq_num,
                retire_prior_to: *retire_prior_to,
                connection_id_length: Some(conn_id.len() as u8),
                connection_id: format!("{}", qlog::HexSlice::new(conn_id)),
                stateless_reset_token: qlog::HexSlice::maybe_string(Some(
                    reset_token,
                )),
                raw: None,
            },

            Frame::RetireConnectionId { seq_num } =>
                QuicFrame::RetireConnectionId {
                    sequence_number: *seq_num,
                    raw: None,
                },

            Frame::PathChallenge { .. } => QuicFrame::PathChallenge {
                data: None,
                raw: None,
            },

            Frame::PathResponse { .. } => QuicFrame::PathResponse {
                data: None,
                raw: None,
            },

            Frame::ConnectionClose {
                error_code, reason, ..
            } => QuicFrame::ConnectionClose {
                // TODO: use actual variant not unknown
                error: Some(ConnectionClosedFrameError::TransportError(
                    qlog::events::quic::TransportError::Unknown,
                )),
                error_space: Some(ErrorSpace::Transport),
                error_code: Some(*error_code),
                reason: Some(String::from_utf8_lossy(reason).into_owned()),
                reason_bytes: None,
                trigger_frame_type: None, // don't know trigger type
            },

            Frame::ApplicationClose { error_code, reason } => {
                QuicFrame::ConnectionClose {
                    error: Some(ConnectionClosedFrameError::ApplicationError(
                        qlog::events::ApplicationError::Unknown,
                    )),
                    error_space: Some(ErrorSpace::Application),
                    error_code: Some(*error_code),
                    reason: Some(String::from_utf8_lossy(reason).into_owned()),
                    reason_bytes: None,
                    trigger_frame_type: None, // don't know trigger type
                }
            },

            Frame::HandshakeDone => QuicFrame::HandshakeDone { raw: None },

            Frame::Datagram { data } => QuicFrame::Datagram {
                raw: Some(Box::new(RawInfo {
                    length: None,
                    payload_length: Some(data.len() as u64),
                    data: None,
                })),
            },

            Frame::DatagramHeader { length } => QuicFrame::Datagram {
                raw: Some(Box::new(RawInfo {
                    length: None,
                    payload_length: Some(*length as u64),
                    data: None,
                })),
            },
        }
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Padding { len } => {
                write!(f, "PADDING len={len}")?;
            },

            Self::Ping { mtu_probe } => {
                write!(f, "PING mtu_probe={mtu_probe:?}")?;
            },

            Self::ACK {
                ack_delay,
                ranges,
                ecn_counts,
            } => {
                write!(
                    f,
                    "ACK delay={ack_delay} blocks={ranges:?} ecn_counts={ecn_counts:?}"
                )?;
            },

            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                write!(
                    f,
                    "RESET_STREAM stream={stream_id} err={error_code:x} size={final_size}"
                )?;
            },

            Self::StopSending {
                stream_id,
                error_code,
            } => {
                write!(f, "STOP_SENDING stream={stream_id} err={error_code:x}")?;
            },

            Self::Crypto { data } => {
                write!(f, "CRYPTO off={} len={}", data.off(), data.len())?;
            },

            Self::CryptoHeader { offset, length } => {
                write!(f, "CRYPTO off={offset} len={length}")?;
            },

            Self::NewToken { token } => {
                write!(f, "NEW_TOKEN len={}", token.len())?;
            },

            Self::Stream { stream_id, data } => {
                write!(
                    f,
                    "STREAM id={stream_id} off={} len={} fin={}",
                    data.off(),
                    data.len(),
                    data.fin()
                )?;
            },

            Self::StreamHeader {
                stream_id,
                offset,
                length,
                fin,
            } => {
                write!(
                    f,
                    "STREAM id={stream_id} off={offset} len={length} fin={fin}"
                )?;
            },

            Self::MaxData { max } => {
                write!(f, "MAX_DATA max={max}")?;
            },

            Self::MaxStreamData { stream_id, max } => {
                write!(f, "MAX_STREAM_DATA stream={stream_id} max={max}")?;
            },

            Self::MaxStreamsBidi { max } => {
                write!(f, "MAX_STREAMS type=bidi max={max}")?;
            },

            Self::MaxStreamsUni { max } => {
                write!(f, "MAX_STREAMS type=uni max={max}")?;
            },

            Self::DataBlocked { limit } => {
                write!(f, "DATA_BLOCKED limit={limit}")?;
            },

            Self::StreamDataBlocked { stream_id, limit } => {
                write!(
                    f,
                    "STREAM_DATA_BLOCKED stream={stream_id} limit={limit}"
                )?;
            },

            Self::StreamsBlockedBidi { limit } => {
                write!(f, "STREAMS_BLOCKED type=bidi limit={limit}")?;
            },

            Self::StreamsBlockedUni { limit } => {
                write!(f, "STREAMS_BLOCKED type=uni limit={limit}")?;
            },

            Self::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                write!(
                    f,
                    "NEW_CONNECTION_ID seq_num={seq_num} retire_prior_to={retire_prior_to} conn_id={conn_id:02x?} reset_token={reset_token:02x?}",
                )?;
            },

            Self::RetireConnectionId { seq_num } => {
                write!(f, "RETIRE_CONNECTION_ID seq_num={seq_num}")?;
            },

            Self::PathChallenge { data } => {
                write!(f, "PATH_CHALLENGE data={data:02x?}")?;
            },

            Self::PathResponse { data } => {
                write!(f, "PATH_RESPONSE data={data:02x?}")?;
            },

            Self::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                write!(
                    f,
                    "CONNECTION_CLOSE err={error_code:x} frame={frame_type:x} reason={reason:x?}"
                )?;
            },

            Self::ApplicationClose { error_code, reason } => {
                write!(
                    f,
                    "APPLICATION_CLOSE err={error_code:x} reason={reason:x?}"
                )?;
            },

            Self::HandshakeDone => {
                write!(f, "HANDSHAKE_DONE")?;
            },

            Self::Datagram { data } => {
                write!(f, "DATAGRAM len={}", data.len())?;
            },

            Self::DatagramHeader { length } => {
                write!(f, "DATAGRAM len={length}")?;
            },
        }

        Ok(())
    }
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
            ect0_count: b.get_varint()?,
            ect1_count: b.get_varint()?,
            ecn_ce_count: b.get_varint()?,
        };

        Some(ecn)
    } else {
        None
    };

    Ok(Frame::ACK {
        ack_delay,
        ranges,
        ecn_counts,
    })
}

pub fn encode_crypto_header(
    offset: u64, length: u64, b: &mut impl FrameSink,
) -> Result<()> {
    b.put_varint(0x06)?;

    b.put_varint(offset)?;

    // Always encode length field as 2-byte varint.
    b.put_varint_with_len(length, 2)?;

    Ok(())
}

pub fn encode_stream_header(
    stream_id: u64, offset: u64, length: u64, fin: bool, b: &mut impl FrameSink,
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

    // Always encode length field as 2-byte varint.
    b.put_varint_with_len(length, 2)?;

    Ok(())
}

pub fn encode_dgram_header(length: u64, b: &mut impl FrameSink) -> Result<()> {
    let mut ty: u8 = 0x30;

    // Always encode length
    ty |= 0x01;

    b.put_varint(u64::from(ty))?;

    // Always encode length field as 2-byte varint.
    b.put_varint_with_len(length, 2)?;

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

    #[test]
    fn rejects_invalid_frame_layouts_consistently() {
        let mut ranges = ranges::RangeSet::default();
        ranges.insert(octets::MAX_VAR_INT + 1..octets::MAX_VAR_INT + 2);
        let cases = [
            (
                Frame::ACK {
                    ack_delay: 0,
                    ranges: ranges::RangeSet::default(),
                    ecn_counts: None,
                },
                Error::InvalidFrame,
            ),
            (
                Frame::ACK {
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
                    conn_id: vec![],
                    reset_token: [0; 16],
                },
                Error::InvalidFrame,
            ),
            (
                Frame::NewConnectionId {
                    seq_num: 1,
                    retire_prior_to: 0,
                    conn_id: vec![0; 256],
                    reset_token: [0; 16],
                },
                Error::InvalidFrame,
            ),
            (
                Frame::Datagram {
                    data: vec![0; 16_384],
                },
                Error::BufferTooShort,
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

        let frame = Frame::ACK {
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
            ect0_count: 100,
            ect1_count: 200,
            ecn_ce_count: 300,
        });

        let frame = Frame::ACK {
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
    fn max_streams_bidi() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreamsBidi { max: 128_318_273 };

        assert_roundtrip(&frame, &mut d, 5, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn max_streams_uni() {
        let mut d = [42; 128];

        let frame = Frame::MaxStreamsUni { max: 128_318_273 };

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

        let frame = Frame::StreamsBlockedBidi { limit: 128_318_273 };

        assert_roundtrip(&frame, &mut d, 5, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn streams_blocked_uni() {
        let mut d = [42; 128];

        let frame = Frame::StreamsBlockedUni { limit: 128_318_273 };

        assert_roundtrip(&frame, &mut d, 5, &[packet::Type::ZeroRTT]);
    }

    #[test]
    fn new_connection_id() {
        let mut d = [42; 128];

        let frame = Frame::NewConnectionId {
            seq_num: 123_213,
            retire_prior_to: 122_211,
            conn_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            reset_token: [0x42; 16],
        };

        assert_roundtrip(&frame, &mut d, 41, &[packet::Type::ZeroRTT]);
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
