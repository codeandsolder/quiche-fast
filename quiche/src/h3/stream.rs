// Copyright (C) 2019, Cloudflare, Inc.
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

use bytes::BufMut as _;

use crate::buffers::BufFactory;

use super::Error;
use super::Result;

use super::frame;

pub const HTTP3_CONTROL_STREAM_TYPE_ID: u64 = 0x0;
pub const HTTP3_PUSH_STREAM_TYPE_ID: u64 = 0x1;
pub const QPACK_ENCODER_STREAM_TYPE_ID: u64 = 0x2;
pub const QPACK_DECODER_STREAM_TYPE_ID: u64 = 0x3;

const MAX_STATE_BUF_SIZE: usize = (1 << 24) - 1;
const MAX_STATE_BUF_ALLOC_SIZE: usize = 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Control,
    Request,
    Push,
    QpackEncoder,
    QpackDecoder,
    Unknown,
}

impl Type {
    #[cfg(feature = "qlog")]
    pub const fn to_qlog(self) -> qlog::events::http3::StreamType {
        match self {
            Self::Control => qlog::events::http3::StreamType::Control,
            Self::Request => qlog::events::http3::StreamType::Request,
            Self::Push => qlog::events::http3::StreamType::Push,
            Self::QpackEncoder => qlog::events::http3::StreamType::QpackEncode,
            Self::QpackDecoder => qlog::events::http3::StreamType::QpackDecode,
            Self::Unknown => qlog::events::http3::StreamType::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Reading the stream's type.
    StreamType,

    /// Reading the stream's current frame's type.
    FrameType,

    /// Reading the stream's current frame's payload length.
    FramePayloadLen,

    /// Reading the stream's current frame's payload.
    FramePayload,

    /// Reading DATA payload.
    Data,

    /// Reading the push ID.
    PushId,

    /// Reading a QPACK instruction.
    QpackInstruction,

    /// Reading the stream's current frame's payload without buffering the data.
    SkipFramePayload,

    /// Reading and discarding data.
    Drain,

    /// All data has been read.
    Finished,
}

impl State {
    const fn buffers_input(self) -> bool {
        matches!(
            self,
            Self::StreamType |
                Self::FrameType |
                Self::FramePayloadLen |
                Self::FramePayload |
                Self::PushId
        )
    }
}

impl Type {
    pub const fn deserialize(v: u64) -> Self {
        match v {
            HTTP3_CONTROL_STREAM_TYPE_ID => Self::Control,
            HTTP3_PUSH_STREAM_TYPE_ID => Self::Push,
            QPACK_ENCODER_STREAM_TYPE_ID => Self::QpackEncoder,
            QPACK_DECODER_STREAM_TYPE_ID => Self::QpackDecoder,
            _ => Self::Unknown,
        }
    }
}

/// Message-frame sequencing, independent of the wire parser's current state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceivePhase {
    Initial,
    Open,
    Trailers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendPhase {
    Initial,
    Informational,
    Open,
    Trailers,
    Finished,
}

/// Semantic kind of a header section written to a message stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderSection {
    Informational,
    Final,
    Trailers,
}

impl HeaderSection {
    /// Classify response headers without validating application-level fields.
    pub fn response(headers: &[impl super::NameValue]) -> Self {
        if headers
            .iter()
            .find(|h| h.name() == b":status")
            .is_some_and(|h| {
                matches!(h.value(), [b'1', b'0'..=b'9', b'0'..=b'9'])
            })
        {
            Self::Informational
        } else {
            Self::Final
        }
    }
}

/// An HTTP/3 stream.
///
/// This maintains the HTTP/3 state for streams of any type (control, request,
/// QPACK, ...).
///
/// A number of bytes, depending on the current stream's state, is read from the
/// transport stream into the HTTP/3 stream's "state buffer". This intermediate
/// buffering is required due to the fact that data read from the transport
/// might not be complete (e.g. a varint might be split across multiple QUIC
/// packets).
///
/// When enough data to complete the current state has been buffered, it is
/// consumed from the state buffer and the stream is transitioned to the next
/// state (see `State` for a list of possible states).
#[derive(Debug)]
pub struct Stream {
    /// The corresponding transport stream's ID.
    id: u64,

    /// The stream's type (if known).
    ty: Option<Type>,

    /// The current stream state.
    state: State,

    /// The buffer holding partial data for the current state.
    state_buf: Vec<u8>,

    /// The expected number of wire bytes required to complete the state.
    /// Streaming payloads need not fit in the local address space.
    state_len: u64,

    /// The number of wire bytes consumed in the current state. For buffered
    /// states this equals the initialized length of the state buffer.
    state_off: u64,

    /// The type of the frame currently being parsed.
    frame_type: Option<u64>,

    /// Whether the stream was created locally, or by the peer.
    is_local: bool,

    /// Peer control initialization or HTTP message receive phase.
    receive_phase: ReceivePhase,

    /// Local HTTP message send phase.
    send_phase: SendPhase,

    /// Whether a `Data` event has been triggered for this stream.
    data_event_triggered: bool,

    /// The last `PRIORITY_UPDATE` frame encoded field value, if any.
    last_priority_update: Option<Vec<u8>>,

    /// Max size of QPACK encoded headers carried in HEADERS or `PUSH_PROMISE`
    /// frames. Related to `SETTINGS_MAX_FIELD_LIST_SIZE`; see
    /// <https://datatracker.ietf.org/doc/html/rfc9114#section-7.2.4.1>
    max_encoded_headers_payload_size: u64,

    /// Max `PRIORITY_UPDATE` frame payload size; see
    /// <https://datatracker.ietf.org/doc/html/rfc9218#section-7.2>
    max_priority_update_size: u64,
}

impl Stream {
    /// Creates a new HTTP/3 stream.
    ///
    /// The `is_local` parameter indicates whether the stream was created by the
    /// local endpoint, or by the peer.
    pub fn new(
        id: u64, is_local: bool, max_field_section_size: u64,
        max_priority_update_size: u64,
    ) -> Self {
        let (ty, state) = if crate::stream::is_bidi(id) {
            // All bidirectional streams are "request" streams, so we don't
            // need to read the stream type.
            (Some(Type::Request), State::FrameType)
        } else {
            // The stream's type is yet to be determined.
            (None, State::StreamType)
        };

        // Huffman encoding might inflate the size of encoded headers
        // when transferred in HEADERS or PUSH_PROMISE frames. Scale up
        // the limit by 50% to accommodate this.
        let max_encoded_headers_payload_size =
            max_field_section_size.saturating_add(max_field_section_size / 2);

        Self {
            id,
            ty,

            state,

            // Pre-allocate a buffer to avoid multiple tiny early allocations.
            state_buf: Vec::with_capacity(16),

            // Expect one byte for the initial state, to parse the initial
            // varint length.
            state_len: 1,
            state_off: 0,

            frame_type: None,

            is_local,

            receive_phase: ReceivePhase::Initial,
            send_phase: SendPhase::Initial,

            data_event_triggered: false,

            last_priority_update: None,

            max_encoded_headers_payload_size,
            max_priority_update_size,
        }
    }

    pub const fn ty(&self) -> Option<Type> {
        self.ty
    }

    pub const fn state(&self) -> State {
        self.state
    }

    /// Sets the stream's type and transitions to the next state.
    pub fn set_ty(&mut self, ty: Type) -> Result<()> {
        assert_eq!(self.state, State::StreamType);

        self.ty = Some(ty);

        let state = match ty {
            Type::Control | Type::Request => State::FrameType,

            Type::Push => State::PushId,

            Type::QpackEncoder | Type::QpackDecoder => State::QpackInstruction,

            Type::Unknown => State::Drain,
        };

        self.state_transition(state, 1)?;

        Ok(())
    }

    /// Sets the push ID and transitions to the next state.
    pub fn set_push_id(&mut self, _id: u64) -> Result<()> {
        assert_eq!(self.state, State::PushId);

        // TODO: implement push ID.

        self.state_transition(State::FrameType, 1)?;

        Ok(())
    }

    /// Sets the frame type and transitions to the next state.
    pub fn set_frame_type(&mut self, ty: u64) -> Result<()> {
        assert_eq!(self.state, State::FrameType);

        // Only expect frames on Control, Request and Push streams.
        match self.ty {
            Some(Type::Control) => {
                // Control stream starts uninitialized and only SETTINGS is
                // accepted in that state. Other frames cause an error. Once
                // initialized, no more SETTINGS are permitted.
                match (ty, self.receive_phase) {
                    (frame::SETTINGS_FRAME_TYPE_ID, ReceivePhase::Initial) =>
                        self.receive_phase = ReceivePhase::Open,

                    (_, ReceivePhase::Initial) =>
                        return Err(Error::MissingSettings),

                    (
                        frame::SETTINGS_FRAME_TYPE_ID |
                        frame::DATA_FRAME_TYPE_ID |
                        frame::HEADERS_FRAME_TYPE_ID |
                        frame::PUSH_PROMISE_FRAME_TYPE_ID,
                        _,
                    ) => return Err(Error::FrameUnexpected),

                    _ => (),
                }
            },

            Some(Type::Request) => {
                self.validate_request_frame_type(ty)?;
            },

            Some(Type::Push) => {
                match ty {
                    // Frames that can never be received on push streams.
                    frame::CANCEL_PUSH_FRAME_TYPE_ID |
                    frame::SETTINGS_FRAME_TYPE_ID |
                    frame::PUSH_PROMISE_FRAME_TYPE_ID |
                    frame::GOAWAY_FRAME_TYPE_ID |
                    frame::MAX_PUSH_FRAME_TYPE_ID =>
                        return Err(Error::FrameUnexpected),

                    _ => (),
                }
            },

            _ => return Err(Error::FrameUnexpected),
        }

        self.frame_type = Some(ty);

        self.state_transition(State::FramePayloadLen, 1)?;

        Ok(())
    }

    /// Validate request and response frame ordering (RFC 9114 section 4.1).
    /// Requests have one initial header section, optional DATA, then optional
    /// trailers. Responses can have informational sections before the final
    /// header section, so initial response HEADERS advance the receive phase
    /// only after QPACK decoding identifies their status.
    const fn validate_request_frame_type(&mut self, ty: u64) -> Result<()> {
        if matches!(
            ty,
            frame::CANCEL_PUSH_FRAME_TYPE_ID |
                frame::SETTINGS_FRAME_TYPE_ID |
                frame::GOAWAY_FRAME_TYPE_ID |
                frame::MAX_PUSH_FRAME_TYPE_ID |
                frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID |
                frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID
        ) {
            return Err(Error::FrameUnexpected);
        }

        match (ty, self.receive_phase) {
            (frame::HEADERS_FRAME_TYPE_ID, ReceivePhase::Initial) => {
                if !self.is_local {
                    self.receive_phase = ReceivePhase::Open;
                }
            },

            (frame::HEADERS_FRAME_TYPE_ID, ReceivePhase::Open) =>
                self.receive_phase = ReceivePhase::Trailers,

            (frame::DATA_FRAME_TYPE_ID, ReceivePhase::Initial) |
            (
                frame::HEADERS_FRAME_TYPE_ID | frame::DATA_FRAME_TYPE_ID,
                ReceivePhase::Trailers,
            ) => return Err(Error::FrameUnexpected),

            // Extension and unknown frames are not part of message framing.
            _ => (),
        }

        Ok(())
    }

    /// Advance the received response's header phase after decoding its fields.
    /// Informational responses do not establish the final message body.
    /// Full pseudo-header/field validation remains the application's concern.
    pub fn on_decoded_headers(&mut self, headers: &[super::Header]) {
        if !self.is_local || !matches!(self.receive_phase, ReceivePhase::Initial)
        {
            return;
        }

        if HeaderSection::response(headers) == HeaderSection::Final {
            self.receive_phase = ReceivePhase::Open;
        }
    }

    // Returns the stream's current frame type, if any
    pub const fn frame_type(&self) -> Option<u64> {
        self.frame_type
    }

    /// Sets the frame's payload length and transitions to the next state.
    pub fn set_frame_payload_len(&mut self, len: u64) -> Result<()> {
        assert_eq!(self.state, State::FramePayloadLen);

        // Only expect frames on Control, Request and Push streams.
        if !matches!(self.ty, Some(Type::Control | Type::Request | Type::Push)) {
            return Err(Error::Internal);
        }

        let state = match self.frame_type {
            Some(frame::DATA_FRAME_TYPE_ID) => State::Data,

            Some(frame::HEADERS_FRAME_TYPE_ID) => {
                if len > self.max_encoded_headers_payload_size {
                    return Err(Error::ExcessiveLoad);
                }

                State::FramePayload
            },

            // These frames carry a mandatory single varint, so their payload
            // size has to be at least 1 byte and at most 8 bytes.
            Some(
                frame::CANCEL_PUSH_FRAME_TYPE_ID |
                frame::GOAWAY_FRAME_TYPE_ID |
                frame::MAX_PUSH_FRAME_TYPE_ID,
            ) => {
                if !(1..=8).contains(&len) {
                    return Err(Error::MalformedFrame);
                }

                State::FramePayload
            },

            Some(frame::SETTINGS_FRAME_TYPE_ID) => {
                if len > frame::MAX_SETTINGS_PAYLOAD_SIZE as u64 {
                    return Err(Error::MalformedFrame);
                }

                State::FramePayload
            },

            Some(frame::PUSH_PROMISE_FRAME_TYPE_ID) => {
                // A push promise payload includes a varint and a field section.
                let max_push_promise_size =
                    self.max_encoded_headers_payload_size.saturating_add(8);

                if len == 0 {
                    return Err(Error::MalformedFrame);
                }

                if len > max_push_promise_size {
                    return Err(Error::ExcessiveLoad);
                }

                State::FramePayload
            },

            Some(
                frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID |
                frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID,
            ) => {
                if len == 0 {
                    return Err(Error::MalformedFrame);
                }

                if len > self.max_priority_update_size {
                    return Err(Error::ExcessiveLoad);
                }

                State::FramePayload
            },

            // Ignore unknown frames' payloads.
            _ => {
                if len > MAX_STATE_BUF_SIZE as u64 {
                    return Err(Error::ExcessiveLoad);
                }

                State::SkipFramePayload
            },
        };

        self.state_transition(state, len)?;

        Ok(())
    }

    /// Ensure bounded incremental growth and return the number of bytes that
    /// may be appended without allocating additional capacity. The transport
    /// writes through `BufMut`, which advances the initialized length itself.
    fn state_buf_read_limit(&mut self) -> Result<usize> {
        if !self.state.buffers_input() {
            return Err(Error::Internal);
        }
        debug_assert_eq!(self.state_off, self.state_buf.len() as u64);
        let need = self.addressable_remaining();
        if self.state_buf.len() == self.state_buf.capacity() {
            self.state_buf
                .try_reserve(MAX_STATE_BUF_ALLOC_SIZE.min(need))
                .map_err(|_| Error::ExcessiveLoad)?;
        }
        Ok(need.min(self.state_buf.capacity() - self.state_buf.len()))
    }

    /// Tries to fill the state buffer by reading data from the corresponding
    /// transport stream.
    ///
    /// When not enough data can be read to complete the state, this returns
    /// `Error::Done`.
    pub fn try_fill_buffer<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> Result<()> {
        // If no bytes are required to be read, return early.
        if self.state_buffer_complete() {
            return Ok(());
        }

        loop {
            let stream_id = self.id;

            let spare_len = self.state_buf_read_limit()?;
            match conn.stream_recv_buf(
                stream_id,
                (&mut self.state_buf).limit(spare_len),
            ) {
                Ok((read, fin)) => {
                    self.state_off = self.state_buf.len() as u64;

                    if self.critical_stream_closed(fin) {
                        super::close_conn_critical_stream(conn)?;
                    }

                    trace!(
                        "{} read {read} bytes on stream {}",
                        conn.trace_id(),
                        self.id,
                    );

                    if read < spare_len {
                        break;
                    }

                    if self.state_buffer_complete() {
                        return Ok(());
                    }
                },

                Err(e @ crate::Error::StreamReset(_)) => {
                    if self.critical_stream_closed(true) {
                        super::close_conn_critical_stream(conn)?;
                    }

                    return Err(e.into());
                },

                Err(e) => {
                    // The stream is not readable anymore, so re-arm the Data
                    // event.
                    if e == crate::Error::Done {
                        self.reset_data_event();
                    }

                    return Err(e.into());
                },
            }
        }

        if !self.state_buffer_complete() {
            self.reset_data_event();

            return Err(Error::Done);
        }

        Ok(())
    }

    /// Tries to read data from the corresponding transport stream up to the
    /// state's size, without storing the data in the state buffer.
    ///
    /// When not enough data can be read to complete the state, this returns
    /// `Error::Done`.
    pub fn try_skip_data<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> Result<()> {
        // If no bytes are required to be read, return early.
        if self.state_buffer_complete() {
            return Ok(());
        }

        let len = self.addressable_remaining();

        let read = match conn.stream_discard(self.id, len) {
            Ok((len, fin)) => {
                if self.critical_stream_closed(fin) {
                    super::close_conn_critical_stream(conn)?;
                }

                len
            },

            Err(e @ crate::Error::StreamReset(_)) => {
                if self.critical_stream_closed(true) {
                    super::close_conn_critical_stream(conn)?;
                }

                return Err(e.into());
            },

            Err(e) => {
                // The stream is not readable anymore, so re-arm the Data
                // event.
                if e == crate::Error::Done {
                    self.reset_data_event();
                }

                return Err(e.into());
            },
        };

        trace!(
            "{} discarded {read} bytes on stream {}",
            conn.trace_id(),
            self.id,
        );

        self.state_off += read as u64;

        if !self.state_buffer_complete() {
            self.reset_data_event();

            return Err(Error::Done);
        }

        Ok(())
    }

    /// Whether a first local header section may be sent.
    pub const fn can_send_initial_headers(&self) -> bool {
        matches!(self.send_phase, SendPhase::Initial)
    }

    /// Whether another header section may be sent after the first.
    pub const fn can_send_additional_headers(
        &self, section: HeaderSection,
    ) -> bool {
        matches!(
            (self.send_phase, section),
            (
                SendPhase::Informational,
                HeaderSection::Informational | HeaderSection::Final
            ) | (SendPhase::Open, HeaderSection::Trailers)
        )
    }

    /// Whether DATA may be sent after the final header section.
    pub const fn can_send_body(&self) -> bool {
        matches!(self.send_phase, SendPhase::Open)
    }

    /// Trailers forbid further HTTP/3 frames, but may still need a QUIC FIN.
    pub const fn awaiting_fin_after_trailers(&self) -> bool {
        matches!(self.send_phase, SendPhase::Trailers)
    }

    /// Advance only after the entire header section was buffered.
    pub const fn on_sent_headers(&mut self, section: HeaderSection, fin: bool) {
        self.send_phase = if fin {
            SendPhase::Finished
        } else {
            match section {
                HeaderSection::Informational => SendPhase::Informational,
                HeaderSection::Final => SendPhase::Open,
                HeaderSection::Trailers => SendPhase::Trailers,
            }
        };
    }

    /// Finish the local part of the stream.
    pub const fn finish_local(&mut self) {
        self.send_phase = SendPhase::Finished;
    }

    /// Whether the local send-side of the stream has finished.
    pub const fn local_finished(&self) -> bool {
        matches!(self.send_phase, SendPhase::Finished)
    }

    /// Tries to fill the state buffer by reading data from the given cursor.
    ///
    /// This is intended to replace `try_fill_buffer()` in tests, in order to
    /// avoid having to setup a transport connection.
    #[cfg(test)]
    fn try_fill_buffer_for_tests(
        &mut self, stream: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<()> {
        // If no bytes are required to be read, return early
        if self.state_buffer_complete() {
            return Ok(());
        }

        loop {
            use std::io::BufRead as _;
            let spare_len = self.state_buf_read_limit()?;
            let available = stream.fill_buf().map_err(|_| Error::Internal)?;
            let read = available.len().min(spare_len);
            self.state_buf.extend_from_slice(&available[..read]);
            stream.consume(read);
            self.state_off = self.state_buf.len() as u64;

            if read < spare_len {
                break;
            }

            if self.state_buffer_complete() {
                break;
            }
        }

        if !self.state_buffer_complete() {
            return Err(Error::Done);
        }

        Ok(())
    }

    /// Read a complete varint, respecting incremental transport delivery.
    pub fn read_varint<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> Result<u64> {
        self.try_fill_buffer(conn)?;
        match self.try_consume_varint() {
            Err(Error::Done) => {
                self.try_fill_buffer(conn)?;
                self.try_consume_varint()
            },
            result => result,
        }
    }

    /// Tries to parse a varint (including length) from the state buffer.
    pub fn try_consume_varint(&mut self) -> Result<u64> {
        if self.state_off == 1 {
            self.state_len = octets::varint_parse_len(self.state_buf[0]) as u64;
        }

        // Return early if we don't have enough data in the state buffer to
        // parse the whole varint.
        if !self.state_buffer_complete() {
            return Err(Error::Done);
        }

        let varint = octets::Octets::with_slice(&self.state_buf).get_varint()?;

        Ok(varint)
    }

    /// Tries to parse a frame from the state buffer.
    ///
    /// If successful, returns the `frame::Frame` and the payload length.
    pub fn try_consume_frame(&mut self) -> Result<(frame::Frame, u64)> {
        if self.state != State::FramePayload {
            return Err(Error::Internal);
        }
        if !self.state_buffer_complete() {
            return Err(Error::Done);
        }
        let payload_len = self.state_len;
        let ty = self.frame_type.ok_or(Error::Internal)?;
        let frame = frame::Frame::from_bytes(ty, payload_len, &self.state_buf)?;

        self.state_transition(State::FrameType, 1)?;
        // Processing a frame other than DATA, so re-arm the Data event.
        self.reset_data_event();

        Ok((frame, payload_len))
    }

    /// Tries to skip the current frame's payload.
    pub fn try_skip_frame<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> Result<()> {
        self.try_skip_data(conn)?;

        // Processing a frame other than DATA, so re-arm the Data event.
        self.reset_data_event();

        self.state_transition(State::FrameType, 1)?;

        Ok(())
    }

    /// Tries to read DATA payload from the transport stream.
    pub fn try_consume_data<F: BufFactory, OUT: bytes::BufMut>(
        &mut self, conn: &mut crate::Connection<F>, out: OUT,
    ) -> Result<(usize, bool)> {
        debug_assert_eq!(self.state, State::Data);
        let out = out.limit(self.addressable_remaining());

        let (len, fin) = match conn.stream_recv_buf(self.id, out) {
            Ok(v) => v,

            Err(e) => {
                // The stream is not readable anymore, so re-arm the Data event.
                if e == crate::Error::Done {
                    self.reset_data_event();
                }

                return Err(e.into());
            },
        };

        self.state_off += len as u64;
        debug_assert!(self.state_len >= self.state_off);

        // The stream is not readable anymore, so re-arm the Data event.
        if !conn.stream_readable(self.id) {
            self.reset_data_event();
        }

        if self.state_buffer_complete() {
            self.state_transition(State::FrameType, 1)?;
        }

        Ok((len, fin))
    }

    /// Marks the stream as finished.
    pub fn finished(&mut self) {
        let _ = self.state_transition(State::Finished, 0);
    }

    /// Tries to read DATA payload from the given cursor.
    ///
    /// This is intended to replace `try_consume_data()` in tests, in order to
    /// avoid having to setup a transport connection.
    #[cfg(test)]
    fn try_consume_data_for_tests(
        &mut self, stream: &mut std::io::Cursor<Vec<u8>>, out: &mut [u8],
    ) -> Result<usize> {
        let left = out.len().min(self.addressable_remaining());

        let len = std::io::Read::read(stream, &mut out[..left])
            .map_err(|_| Error::Internal)?;

        self.state_off += len as u64;

        if self.state_buffer_complete() {
            self.state_transition(State::FrameType, 1)?;
        }

        Ok(len)
    }

    /// Tries to update the data triggered state for the stream.
    ///
    /// This returns `true` if a Data event was not already triggered before
    /// the last reset, and updates the state. Returns `false` otherwise.
    pub const fn try_trigger_data_event(&mut self) -> bool {
        if self.data_event_triggered {
            return false;
        }

        self.data_event_triggered = true;

        true
    }

    /// Resets the data triggered state.
    const fn reset_data_event(&mut self) {
        self.data_event_triggered = false;
    }

    /// Set the last priority update for the stream.
    pub fn set_last_priority_update(&mut self, priority_update: Option<Vec<u8>>) {
        self.last_priority_update = priority_update;
    }

    /// Take the last priority update and leave `None` in its place.
    pub const fn take_last_priority_update(&mut self) -> Option<Vec<u8>> {
        self.last_priority_update.take()
    }

    /// Returns `true` if there is a priority update.
    pub const fn has_last_priority_update(&self) -> bool {
        self.last_priority_update.is_some()
    }

    /// Checks whether one of the critical streams was closed.
    const fn critical_stream_closed(&self, fin: bool) -> bool {
        fin && matches!(
            self.ty,
            Some(Type::Control | Type::QpackEncoder | Type::QpackDecoder)
        )
    }

    /// Returns true if the state buffer has enough data to complete the state.
    const fn state_buffer_complete(&self) -> bool {
        self.state_off == self.state_len
    }

    /// Limit a single read to the local address space, not the whole frame.
    fn addressable_remaining(&self) -> usize {
        usize::try_from(self.state_len - self.state_off).unwrap_or(usize::MAX)
    }

    /// Transitions the stream to a new state. Only buffered states allocate,
    /// and their lengths must satisfy the state-buffer limit.
    fn state_transition(
        &mut self, new_state: State, expected_len: u64,
    ) -> Result<()> {
        if new_state.buffers_input() {
            let len = usize::try_from(expected_len)
                .map_err(|_| Error::ExcessiveLoad)?;
            if len > MAX_STATE_BUF_SIZE {
                return Err(Error::ExcessiveLoad);
            }
            let reserve_len = len.min(MAX_STATE_BUF_ALLOC_SIZE);
            self.state_buf
                .try_reserve(reserve_len.saturating_sub(self.state_buf.len()))
                .map_err(|_| Error::ExcessiveLoad)?;
        }

        self.state_buf.clear();
        self.state = new_state;
        self.state_off = 0;
        self.state_len = expected_len;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::h3::frame::*;
    use crate::h3::PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT;
    use crate::h3::SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT;

    use super::*;

    fn open_uni(b: &mut octets::OctetsMut, ty: u64) -> Result<Stream> {
        let stream = <Stream>::new(
            2,
            false,
            SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );
        assert_eq!(stream.state, State::StreamType);

        b.put_varint(ty)?;

        Ok(stream)
    }

    fn open_remote_request_stream() -> Stream {
        Stream::new(
            0,
            false,
            SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        )
    }

    fn parse_uni(
        stream: &mut Stream, ty: u64, cursor: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<()> {
        stream.try_fill_buffer_for_tests(cursor)?;

        let stream_ty = stream.try_consume_varint()?;
        assert_eq!(stream_ty, ty);
        stream.set_ty(Type::deserialize(stream_ty))?;

        Ok(())
    }

    /// Fill the buffer and parse a multi-byte varint that requires two
    /// fills (the first read gets the length prefix, the second gets the
    /// remaining bytes).
    fn parse_multibyte_varint(
        stream: &mut Stream, cursor: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<u64> {
        stream.try_fill_buffer_for_tests(cursor)?;
        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
        stream.try_fill_buffer_for_tests(cursor)?;
        stream.try_consume_varint()
    }

    fn parse_skip_frame(
        stream: &mut Stream, cursor: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<()> {
        // Parse the frame type.
        stream.try_fill_buffer_for_tests(cursor)?;

        let frame_ty = stream.try_consume_varint()?;

        stream.set_frame_type(frame_ty)?;
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the frame payload length.
        stream.try_fill_buffer_for_tests(cursor)?;

        let frame_payload_len = stream.try_consume_varint()?;
        stream.set_frame_payload_len(frame_payload_len)?;
        assert_eq!(stream.state, State::FramePayload);

        // Parse the frame payload.
        stream.try_fill_buffer_for_tests(cursor)?;

        stream.try_consume_frame()?;
        assert_eq!(stream.state, State::FrameType);

        Ok(())
    }

    #[test]
    fn large_data_frame_length_is_not_truncated_to_usize() -> Result<()> {
        let mut stream = open_remote_request_stream();
        // Simulate an already accepted final HEADERS block. A DATA frame is
        // otherwise invalid before the initial HEADERS on request streams.
        stream.receive_phase = ReceivePhase::Open;
        stream.set_frame_type(DATA_FRAME_TYPE_ID)?;

        let length = u64::from(u32::MAX) + 1;
        let capacity = stream.state_buf.capacity();
        stream.set_frame_payload_len(length)?;
        assert_eq!(stream.state, State::Data);
        assert_eq!(stream.state_len, length);
        assert_eq!(stream.state_buf.capacity(), capacity);

        // Seed the streamed offset near the 32-bit boundary rather than
        // allocating several GiB just to test the arithmetic.
        stream.state_off = length - 2;
        let mut cursor = std::io::Cursor::new(vec![1, 2, 3]);
        let mut out = [0; 8];
        assert_eq!(
            stream.try_consume_data_for_tests(&mut cursor, &mut out),
            Ok(2)
        );
        assert_eq!(&out[..2], &[1, 2]);
        assert_eq!(cursor.position(), 2);
        assert_eq!(stream.state, State::FrameType);
        assert_eq!(stream.state_buf.capacity(), capacity);
        Ok(())
    }

    fn read_frame_header(
        stream: &mut Stream, cursor: &mut std::io::Cursor<Vec<u8>>,
        expected_type: u64, expected_len: u64, expected_state: State,
    ) -> Result<()> {
        stream.try_fill_buffer_for_tests(cursor)?;
        let ty = stream.try_consume_varint()?;
        assert_eq!(ty, expected_type);
        stream.set_frame_type(ty)?;
        assert_eq!(stream.state, State::FramePayloadLen);
        stream.try_fill_buffer_for_tests(cursor)?;
        let len = stream.try_consume_varint()?;
        assert_eq!(len, expected_len);
        stream.set_frame_payload_len(len)?;
        assert_eq!(stream.state, expected_state);
        Ok(())
    }

    fn read_buffered_frame(
        stream: &mut Stream, cursor: &mut std::io::Cursor<Vec<u8>>, frame: Frame,
        len: u64,
    ) -> Result<()> {
        read_frame_header(
            stream,
            cursor,
            frame_type_id(&frame),
            len,
            State::FramePayload,
        )?;
        stream.try_fill_buffer_for_tests(cursor)?;
        assert_eq!(stream.try_consume_frame(), Ok((frame, len)));
        assert_eq!(stream.state, State::FrameType);
        Ok(())
    }

    fn read_data_frame(
        stream: &mut Stream, cursor: &mut std::io::Cursor<Vec<u8>>,
        payload: &[u8],
    ) -> Result<()> {
        read_frame_header(
            stream,
            cursor,
            DATA_FRAME_TYPE_ID,
            payload.len() as u64,
            State::Data,
        )?;
        let mut received = vec![0; payload.len()];
        assert_eq!(
            stream.try_consume_data_for_tests(cursor, &mut received),
            Ok(payload.len())
        );
        assert_eq!(payload, received);
        assert_eq!(stream.state, State::FrameType);
        Ok(())
    }

    fn control_settings(empty: bool) -> Frame {
        let value = (!empty).then_some(0);
        let raw = if empty {
            vec![]
        } else {
            vec![
                (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
                (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
                (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
            ]
        };
        Frame::Settings {
            max_field_section_size: value,
            qpack_max_table_capacity: value,
            qpack_blocked_streams: value,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: None,
            raw: Some(raw),
        }
    }

    fn control_stream(
        frames: &[&Frame],
    ) -> Result<(Stream, std::io::Cursor<Vec<u8>>)> {
        let mut data = vec![42; 128];
        let mut writer = octets::OctetsMut::with_slice(&mut data);
        let mut stream = open_uni(&mut writer, HTTP3_CONTROL_STREAM_TYPE_ID)?;
        for frame in frames {
            frame.to_bytes(&mut writer)?;
        }
        let mut cursor = std::io::Cursor::new(data);
        parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)?;
        assert_eq!(stream.state, State::FrameType);
        Ok((stream, cursor))
    }

    #[rstest::rstest]
    fn control_settings_frames(
        #[values(false, true)] empty: bool,
        #[values(false, true)] duplicate: bool,
    ) -> Result<()> {
        let frame = control_settings(empty);
        let frames = if duplicate {
            vec![&frame, &frame]
        } else {
            vec![&frame]
        };
        let (mut stream, mut cursor) = control_stream(&frames)?;
        read_buffered_frame(
            &mut stream,
            &mut cursor,
            frame,
            if empty { 0 } else { 6 },
        )?;
        if duplicate {
            stream.try_fill_buffer_for_tests(&mut cursor)?;
            let ty = stream.try_consume_varint()?;
            assert_eq!(ty, SETTINGS_FRAME_TYPE_ID);
            assert_eq!(stream.set_frame_type(ty), Err(Error::FrameUnexpected));
        }
        Ok(())
    }

    #[test]
    fn control_bad_late_settings() -> Result<()> {
        let (mut stream, mut cursor) = control_stream(&[
            &Frame::GoAway { id: 0 },
            &control_settings(false),
        ])?;
        stream.try_fill_buffer_for_tests(&mut cursor)?;
        let ty = stream.try_consume_varint()?;
        assert_eq!(ty, GOAWAY_FRAME_TYPE_ID);
        assert_eq!(stream.set_frame_type(ty), Err(Error::MissingSettings));
        Ok(())
    }

    #[test]
    fn control_bad_frame() -> Result<()> {
        let settings = control_settings(false);
        let headers = Frame::Headers {
            header_block: (1..=12).collect(),
        };
        let (mut stream, mut cursor) = control_stream(&[&settings, &headers])?;
        read_buffered_frame(&mut stream, &mut cursor, settings, 6)?;
        stream.try_fill_buffer_for_tests(&mut cursor)?;
        let ty = stream.try_consume_varint()?;
        assert_eq!(ty, HEADERS_FRAME_TYPE_ID);
        assert_eq!(stream.set_frame_type(ty), Err(Error::FrameUnexpected));
        Ok(())
    }

    #[test]
    fn request_no_data() {
        let mut stream = open_remote_request_stream();

        assert_eq!(stream.ty, Some(Type::Request));
        assert_eq!(stream.state, State::FrameType);

        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
    }

    #[rstest::rstest]
    fn request_or_push_good(#[values(false, true)] push: bool) -> Result<()> {
        let mut data = vec![42; 128];
        let mut writer = octets::OctetsMut::with_slice(&mut data);
        let mut stream = if push {
            let stream = open_uni(&mut writer, HTTP3_PUSH_STREAM_TYPE_ID)?;
            writer.put_varint(1)?;
            stream
        } else {
            open_remote_request_stream()
        };
        let headers = Frame::Headers {
            header_block: (1..=12).collect(),
        };
        let payload: Vec<u8> = (1..=12).collect();
        headers.to_bytes(&mut writer)?;
        Frame::Data {
            payload: payload.clone(),
        }
        .to_bytes(&mut writer)?;
        let mut cursor = std::io::Cursor::new(data);
        if push {
            parse_uni(&mut stream, HTTP3_PUSH_STREAM_TYPE_ID, &mut cursor)?;
            assert_eq!(stream.state, State::PushId);
            stream.try_fill_buffer_for_tests(&mut cursor)?;
            let id = stream.try_consume_varint()?;
            assert_eq!(id, 1);
            stream.set_push_id(id)?;
        }
        assert_eq!(stream.state, State::FrameType);
        read_buffered_frame(&mut stream, &mut cursor, headers, 12)?;
        read_data_frame(&mut stream, &mut cursor, &payload)
    }

    #[test]
    fn grease() -> Result<()> {
        let mut d = vec![42; 20];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let mut stream = open_uni(&mut b, 33)?;

        let mut cursor = std::io::Cursor::new(d);

        // Parse stream type.
        stream.try_fill_buffer_for_tests(&mut cursor)?;

        let stream_ty = stream.try_consume_varint()?;
        assert_eq!(stream_ty, 33);
        stream.set_ty(Type::deserialize(stream_ty))?;
        assert_eq!(stream.state, State::Drain);
        Ok(())
    }

    #[test]
    fn data_before_headers() -> Result<()> {
        let mut stream = open_remote_request_stream();

        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let data = Frame::Data {
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        data.to_bytes(&mut b)?;

        let mut cursor = std::io::Cursor::new(d);

        // Parse the DATA frame type.
        stream.try_fill_buffer_for_tests(&mut cursor)?;

        let frame_ty = stream.try_consume_varint()?;
        assert_eq!(frame_ty, DATA_FRAME_TYPE_ID);

        assert_eq!(stream.set_frame_type(frame_ty), Err(Error::FrameUnexpected));
        Ok(())
    }

    #[test]
    fn additional_headers() -> Result<()> {
        let mut stream = Stream::new(
            0,
            true,
            SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );

        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let info_hdrs = Frame::Headers {
            header_block: header_block.clone(),
        };
        let non_info_hdrs = Frame::Headers {
            header_block: header_block.clone(),
        };
        let trailers = Frame::Headers { header_block };
        let data = Frame::Data {
            payload: payload.clone(),
        };

        info_hdrs.to_bytes(&mut b)?;
        non_info_hdrs.to_bytes(&mut b)?;
        data.to_bytes(&mut b)?;
        trailers.to_bytes(&mut b)?;

        let mut cursor = std::io::Cursor::new(d);

        read_buffered_frame(&mut stream, &mut cursor, info_hdrs, 12)?;
        stream
            .on_decoded_headers(&[super::super::Header::new(b":status", b"103")]);
        assert_eq!(stream.state, State::FrameType);
        read_buffered_frame(&mut stream, &mut cursor, non_info_hdrs, 12)?;
        stream
            .on_decoded_headers(&[super::super::Header::new(b":status", b"200")]);
        assert_eq!(stream.state, State::FrameType);
        read_data_frame(&mut stream, &mut cursor, &payload)?;
        read_buffered_frame(&mut stream, &mut cursor, trailers, 12)?;
        Ok(())
    }

    #[test]
    fn request_and_response_message_phases() {
        let mut request = open_remote_request_stream();
        assert_eq!(
            request.validate_request_frame_type(DATA_FRAME_TYPE_ID),
            Err(Error::FrameUnexpected)
        );
        assert_eq!(
            request.validate_request_frame_type(HEADERS_FRAME_TYPE_ID),
            Ok(())
        );
        assert_eq!(
            request.validate_request_frame_type(HEADERS_FRAME_TYPE_ID),
            Ok(())
        );
        assert_eq!(
            request.validate_request_frame_type(DATA_FRAME_TYPE_ID),
            Err(Error::FrameUnexpected)
        );
        assert_eq!(
            request.validate_request_frame_type(HEADERS_FRAME_TYPE_ID),
            Err(Error::FrameUnexpected)
        );

        let mut response = Stream::new(
            0,
            true,
            SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );
        assert_eq!(
            response.validate_request_frame_type(DATA_FRAME_TYPE_ID),
            Err(Error::FrameUnexpected)
        );
        for code in [b"100", b"103"] {
            assert_eq!(
                response.validate_request_frame_type(HEADERS_FRAME_TYPE_ID),
                Ok(())
            );
            response.on_decoded_headers(&[super::super::Header::new(
                b":status", code,
            )]);
            assert_eq!(
                response.validate_request_frame_type(DATA_FRAME_TYPE_ID),
                Err(Error::FrameUnexpected)
            );
        }
        assert_eq!(
            response.validate_request_frame_type(HEADERS_FRAME_TYPE_ID),
            Ok(())
        );
        response
            .on_decoded_headers(&[super::super::Header::new(b":status", b"200")]);
        assert_eq!(
            response.validate_request_frame_type(DATA_FRAME_TYPE_ID),
            Ok(())
        );
        assert_eq!(
            response.validate_request_frame_type(HEADERS_FRAME_TYPE_ID),
            Ok(())
        );
        assert_eq!(response.validate_request_frame_type(33), Ok(()));
        assert_eq!(
            response.validate_request_frame_type(DATA_FRAME_TYPE_ID),
            Err(Error::FrameUnexpected)
        );
        assert_eq!(
            response.validate_request_frame_type(HEADERS_FRAME_TYPE_ID),
            Err(Error::FrameUnexpected)
        );

        assert!(response.can_send_initial_headers());
        response.on_sent_headers(HeaderSection::Informational, false);
        assert!(!response.can_send_initial_headers());
        assert!(!response.can_send_body());
        assert!(
            response.can_send_additional_headers(HeaderSection::Informational)
        );
        assert!(response.can_send_additional_headers(HeaderSection::Final));
        assert!(!response.can_send_additional_headers(HeaderSection::Trailers));
        response.on_sent_headers(HeaderSection::Final, false);
        assert!(response.can_send_body());
        assert!(!response.can_send_additional_headers(HeaderSection::Final));
        assert!(response.can_send_additional_headers(HeaderSection::Trailers));
        response.on_sent_headers(HeaderSection::Trailers, true);
        assert!(response.local_finished());
        assert!(!response.can_send_body());
        assert!(!response.can_send_additional_headers(HeaderSection::Trailers));
    }

    /// Returns the frame type ID for a given frame variant.
    const fn frame_type_id(frame: &Frame) -> u64 {
        match frame {
            Frame::Data { .. } => DATA_FRAME_TYPE_ID,
            Frame::Headers { .. } => HEADERS_FRAME_TYPE_ID,
            Frame::CancelPush { .. } => CANCEL_PUSH_FRAME_TYPE_ID,
            Frame::Settings { .. } => SETTINGS_FRAME_TYPE_ID,
            Frame::PushPromise { .. } => PUSH_PROMISE_FRAME_TYPE_ID,
            Frame::GoAway { .. } => GOAWAY_FRAME_TYPE_ID,
            Frame::MaxPushId { .. } => MAX_PUSH_FRAME_TYPE_ID,
            Frame::PriorityUpdateRequest { .. } =>
                PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID,
            Frame::PriorityUpdatePush { .. } =>
                PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID,
            Frame::Unknown { raw_type, .. } => *raw_type,
        }
    }

    /// Parse a large frame and check the size limit behavior.
    ///
    /// Writes the frame to a buffer, parses the frame type and payload
    /// length (handling multi-byte varint retry), then checks whether
    /// `set_frame_payload_len` accepts or rejects the frame. If accepted,
    /// also parses the payload and verifies `try_consume_frame` output.
    ///
    /// - `stream`: the HTTP/3 stream to parse the frame on.
    /// - `frame`: the frame to encode and parse back.
    /// - `expected_payload_len`: the expected encoded payload length.
    /// - `expect_accept`: if true, the frame should be accepted and fully
    ///   parsed; if false, `set_frame_payload_len` should reject it with
    ///   `Error::ExcessiveLoad`.
    fn check_large_frame_size_limit(
        stream: &mut Stream, frame: Frame, expected_payload_len: u64,
        expect_accept: bool,
    ) -> Result<()> {
        let expected_type_id = frame_type_id(&frame);

        let mut d = vec![42; 20_000];
        let mut b = octets::OctetsMut::with_slice(&mut d);
        frame.to_bytes(&mut b)?;
        let mut cursor = std::io::Cursor::new(d);

        // Parse frame type.
        stream.try_fill_buffer_for_tests(&mut cursor)?;
        let frame_ty = stream.try_consume_varint()?;
        assert_eq!(frame_ty, expected_type_id);

        stream.set_frame_type(frame_ty)?;
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse frame payload length.
        let frame_payload_len = parse_multibyte_varint(stream, &mut cursor)?;
        assert_eq!(frame_payload_len, expected_payload_len);

        if expect_accept {
            stream.set_frame_payload_len(frame_payload_len)?;
            assert_eq!(stream.state, State::FramePayload);

            stream.try_fill_buffer_for_tests(&mut cursor)?;

            assert_eq!(
                stream.try_consume_frame(),
                Ok((frame, expected_payload_len))
            );
            assert_eq!(stream.state, State::FrameType);
        } else {
            assert_eq!(
                stream.set_frame_payload_len(frame_payload_len),
                Err(Error::ExcessiveLoad)
            );
        }
        Ok(())
    }

    #[rstest::rstest]
    #[case::default_limit(SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT, 16_384, true)]
    #[case::huffman_margin(4_196, 6_294, true)]
    #[case::excessive(4_196, 16_384, false)]
    fn large_field_section_limits(
        #[case] limit: u64, #[case] block_len: usize, #[case] accepted: bool,
        #[values(false, true)] push_promise: bool,
    ) -> Result<()> {
        let mut stream = Stream::new(
            0,
            false,
            limit,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );
        let header_block = vec![0; block_len];
        let (frame, payload_len) = if push_promise {
            (
                Frame::PushPromise {
                    push_id: 0,
                    header_block,
                },
                block_len + 1,
            )
        } else {
            (Frame::Headers { header_block }, block_len)
        };
        check_large_frame_size_limit(
            &mut stream,
            frame,
            payload_len as u64,
            accepted,
        )
    }

    #[rstest::rstest]
    #[case::accepted(20_000, true)]
    #[case::rejected(123, false)]
    fn large_priority_update_limit(
        #[case] limit: u64, #[case] accepted: bool,
    ) -> Result<()> {
        let settings = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: None,
            raw: Some(vec![]),
        };

        let mut d = vec![42; 20_000];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        // Control stream needs a SETTINGS frame to transition it into
        // being able to parse other frame types.
        let mut stream = <Stream>::new(
            2,
            false,
            SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT,
            limit,
        );
        b.put_varint(HTTP3_CONTROL_STREAM_TYPE_ID)?;
        settings.to_bytes(&mut b)?;

        let priority_field_value = vec![0; 16_384];
        let pu = Frame::PriorityUpdateRequest {
            prioritized_element_id: 0,
            priority_field_value,
        };

        pu.to_bytes(&mut b)?;

        let mut cursor = std::io::Cursor::new(d);

        parse_uni(&mut stream, HTTP3_CONTROL_STREAM_TYPE_ID, &mut cursor)?;

        // Skip SETTINGS frame type.
        parse_skip_frame(&mut stream, &mut cursor)?;

        // Parse the frame type.
        stream.try_fill_buffer_for_tests(&mut cursor)?;

        // Parse fails because we need more bytes for the 4-byte encoded length.
        // This trial then sets the expected buffer size for us to fill.
        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
        stream.try_fill_buffer_for_tests(&mut cursor)?;
        let frame_ty = stream.try_consume_varint()?;
        assert_eq!(frame_ty, PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID);

        stream.set_frame_type(frame_ty)?;
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse the frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor)?;

        // Parse fails because we need more bytes for the 4-byte encoded length.
        // This trial then sets the expected buffer size for us to fill.
        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
        stream.try_fill_buffer_for_tests(&mut cursor)?;

        let frame_payload_len = stream.try_consume_varint()?;
        assert_eq!(frame_payload_len, 1 + 16_384);

        if accepted {
            stream.set_frame_payload_len(frame_payload_len)?;
            assert_eq!(stream.state, State::FramePayload);
            stream.try_fill_buffer_for_tests(&mut cursor)?;
            assert_eq!(stream.try_consume_frame(), Ok((pu, 1 + 16_384)));
            assert_eq!(stream.state, State::FrameType);
        } else {
            assert_eq!(
                stream.set_frame_payload_len(frame_payload_len),
                Err(Error::ExcessiveLoad)
            );
        }
        Ok(())
    }

    #[test]
    fn finite_sized_frame_limits() -> Result<()> {
        let settings = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: None,
            raw: Some(vec![]),
        };

        for ty in [
            CANCEL_PUSH_FRAME_TYPE_ID,
            GOAWAY_FRAME_TYPE_ID,
            MAX_PUSH_FRAME_TYPE_ID,
        ] {
            // These frames must have a size between 1 and 8 bytes inclusive.
            for size in [0, 9] {
                let mut d = vec![42; 128];
                let mut b = octets::OctetsMut::with_slice(&mut d);

                // Control stream needs a SETTINGS frame to transition it into
                // being able to parse other frame types.
                let mut stream = open_uni(&mut b, HTTP3_CONTROL_STREAM_TYPE_ID)?;
                settings.to_bytes(&mut b)?;

                // Write bytes as far as frame length.
                b.put_varint(ty)?;
                b.put_varint(size)?;

                let mut cursor = std::io::Cursor::new(d);

                parse_uni(
                    &mut stream,
                    HTTP3_CONTROL_STREAM_TYPE_ID,
                    &mut cursor,
                )?;

                // Skip SETTINGS frame type.
                parse_skip_frame(&mut stream, &mut cursor)?;

                // Parse frame type.
                stream.try_fill_buffer_for_tests(&mut cursor)?;
                let frame_ty = stream.try_consume_varint()?;
                assert_eq!(frame_ty, ty);

                stream.set_frame_type(frame_ty)?;
                assert_eq!(stream.state, State::FramePayloadLen);

                // Parse frame payload length.
                stream.try_fill_buffer_for_tests(&mut cursor)?;
                let frame_payload_len = stream.try_consume_varint()?;
                assert_eq!(
                    Err(Error::MalformedFrame),
                    stream.set_frame_payload_len(frame_payload_len)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn zero_length_push_promise() -> Result<()> {
        let mut d = vec![42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let mut stream = open_remote_request_stream();

        assert_eq!(stream.ty, Some(Type::Request));
        assert_eq!(stream.state, State::FrameType);

        // Write a 0-length payload frame.
        b.put_varint(PUSH_PROMISE_FRAME_TYPE_ID)?;
        b.put_varint(0)?;

        let mut cursor = std::io::Cursor::new(d);

        // Parse frame type.
        stream.try_fill_buffer_for_tests(&mut cursor)?;
        let frame_ty = stream.try_consume_varint()?;
        assert_eq!(frame_ty, PUSH_PROMISE_FRAME_TYPE_ID);

        stream.set_frame_type(frame_ty)?;
        assert_eq!(stream.state, State::FramePayloadLen);

        // Parse frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor)?;
        let frame_payload_len = stream.try_consume_varint()?;
        assert_eq!(
            Err(Error::MalformedFrame),
            stream.set_frame_payload_len(frame_payload_len)
        );
        Ok(())
    }

    #[test]
    fn incomplete_buffered_frame_remains_readable() -> Result<()> {
        let mut stream = Stream::new(
            0,
            false,
            SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );
        stream.set_frame_type(HEADERS_FRAME_TYPE_ID)?;
        stream.set_frame_payload_len(4)?;
        let mut first = std::io::Cursor::new(vec![1, 2]);
        assert_eq!(
            stream.try_fill_buffer_for_tests(&mut first),
            Err(Error::Done)
        );
        assert_eq!(stream.try_consume_frame(), Err(Error::Done));
        assert_eq!(stream.state_buf, [1, 2]);
        assert_eq!(
            stream.state_transition(
                State::FramePayload,
                MAX_STATE_BUF_SIZE as u64 + 1
            ),
            Err(Error::ExcessiveLoad),
        );
        assert_eq!(stream.state_buf, [1, 2]);
        assert_eq!(stream.state_off, 2);
        let mut last = std::io::Cursor::new(vec![3, 4, 5, 6]);
        assert_eq!(stream.try_fill_buffer_for_tests(&mut last), Ok(()));
        assert_eq!(last.position(), 2);
        assert_eq!(
            stream.try_consume_frame(),
            Ok((
                Frame::Headers {
                    header_block: vec![1, 2, 3, 4],
                },
                4
            ))
        );
        Ok(())
    }

    fn large_header_fixture(
        len: usize, fill: u8,
    ) -> Result<(Stream, Frame, Vec<u8>)> {
        let mut stream = Stream::new(
            0,
            false,
            len as u64,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );
        let mut data = vec![42; len + 10];
        let headers = Frame::Headers {
            header_block: vec![fill; len],
        };
        headers.to_bytes(&mut octets::OctetsMut::with_slice(&mut data))?;
        let mut cursor = std::io::Cursor::new(data);
        stream.try_fill_buffer_for_tests(&mut cursor)?;
        let ty = stream.try_consume_varint()?;
        assert_eq!(ty, HEADERS_FRAME_TYPE_ID);
        stream.set_frame_type(ty)?;
        let payload_len = parse_multibyte_varint(&mut stream, &mut cursor)?;
        assert_eq!(payload_len, len as u64);
        stream.set_frame_payload_len(payload_len)?;
        assert_eq!(stream.state, State::FramePayload);
        assert_eq!(stream.state_buf.capacity(), MAX_STATE_BUF_ALLOC_SIZE);
        assert!(stream.state_buf.is_empty());
        let offset = usize::try_from(cursor.position())
            .map_err(|_| Error::InternalError)?;
        assert_eq!(offset, 5);
        Ok((
            stream,
            headers,
            cursor.into_inner()[offset..offset + len].to_vec(),
        ))
    }

    #[test]
    /// Drip feed data in chunks that exactly match spare capacity, forcing
    /// spare to hit 0 on every re-entry to `try_fill_buffer_for_tests`.
    fn large_state_buf_exact_spare_drip_feed() -> Result<()> {
        const LARGE_HEADER_LEN: usize = 16_384;
        let (mut stream, hdrs, payload_data) =
            large_header_fixture(LARGE_HEADER_LEN, 0xAB)?;

        // Drip feed in chunks that exactly match MAX_STATE_BUF_ALLOC_SIZE.
        // Each chunk fully consumes spare, so on re-entry spare is exactly 0
        // and state_buf_read_limit must reserve.
        let mut fed = 0;
        while fed + MAX_STATE_BUF_ALLOC_SIZE <= LARGE_HEADER_LEN {
            let chunk = &payload_data[fed..fed + MAX_STATE_BUF_ALLOC_SIZE];
            let mut chunk_cursor = std::io::Cursor::new(chunk.to_vec());

            let result = stream.try_fill_buffer_for_tests(&mut chunk_cursor);

            fed += MAX_STATE_BUF_ALLOC_SIZE;

            if fed < LARGE_HEADER_LEN {
                assert_eq!(result, Err(Error::Done));
                assert_eq!(stream.state_off, fed as u64);
                // state_buf_read_limit should have reserved on each re-entry
                // since previous chunk consumed all spare.
                assert!(stream.state_buf.capacity() >= fed);
            } else {
                assert_eq!(result, Ok(()));
                assert_eq!(stream.state_off, LARGE_HEADER_LEN as u64);
            }
        }

        assert_eq!(
            stream.try_consume_frame(),
            Ok((hdrs, LARGE_HEADER_LEN as u64))
        );
        assert_eq!(stream.state, State::FrameType);
        Ok(())
    }

    #[test]
    /// Drip feed data in chunks smaller than spare capacity, so spare is
    /// small but nonzero on re-entry. Verifies that the buffer eventually
    /// grows when spare is fully consumed across multiple small reads.
    fn large_state_buf_small_leftover_spare() -> Result<()> {
        const LARGE_HEADER_LEN: usize = 260_000;
        let (mut stream, hdrs, payload_data) =
            large_header_fixture(LARGE_HEADER_LEN, 0)?;

        // Drip feed 1000-byte chunks. These don't align with the 4096 spare
        // capacity, so spare will be nonzero but shrinking on each re-entry
        // until it hits 0 and forces a reserve.
        let chunk_size = 1000;
        let mut fed = 0;
        while fed < LARGE_HEADER_LEN {
            let end = std::cmp::min(fed + chunk_size, LARGE_HEADER_LEN);
            let chunk = &payload_data[fed..end];
            let mut chunk_cursor = std::io::Cursor::new(chunk.to_vec());

            let result = stream.try_fill_buffer_for_tests(&mut chunk_cursor);

            fed = end;

            if fed < LARGE_HEADER_LEN {
                assert_eq!(result, Err(Error::Done));
                assert_eq!(stream.state_off, fed as u64);
                // Capacity must always be at least as large as what we've
                // buffered.
                assert!(stream.state_buf.capacity() >= stream.state_buf.len());
                // Capacity should grow incrementally. The allocator may
                // over-allocate (typically doubling), so we allow up to
                // 2x (bytes_read + reserve_size) to account for that.
                // The key property: capacity never jumps to the full
                // frame size before we've read a proportional amount.
                assert!(
                    stream.state_buf.capacity() <=
                        (fed + MAX_STATE_BUF_ALLOC_SIZE) * 2,
                    "capacity {} grew too far ahead of bytes read {} \
                     (max alloc size {})",
                    stream.state_buf.capacity(),
                    fed,
                    MAX_STATE_BUF_ALLOC_SIZE,
                );
            } else {
                assert_eq!(result, Ok(()));
            }
        }

        assert_eq!(
            stream.try_consume_frame(),
            Ok((hdrs, LARGE_HEADER_LEN as u64))
        );
        assert_eq!(stream.state, State::FrameType);
        Ok(())
    }

    /// Assert `state_len`, `state_off`, and `state_buf.capacity()` in one
    /// call, with labeled messages on failure.
    fn assert_state_buf_props(
        stream: &Stream, len: usize, off: usize, capacity: usize,
    ) {
        assert_eq!(stream.state_len, len as u64, "state_len");
        assert_eq!(stream.state_off, off as u64, "state_off");
        assert_eq!(stream.state_buf.capacity(), capacity, "capacity");
    }

    #[test]
    fn large_state_buf_allocation() -> Result<()> {
        const LARGE_HEADER_LEN: usize = 260_000;
        let mut stream = Stream::new(
            0,
            false,
            LARGE_HEADER_LEN as u64,
            PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        );
        assert_eq!(stream.state_buf.capacity(), 16);

        let mut d = vec![42; 5];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        // Drip feed a large HEADERS frame into the "stream"
        b.put_varint(HEADERS_FRAME_TYPE_ID)?;
        b.put_varint(LARGE_HEADER_LEN as u64)?;

        let mut cursor = std::io::Cursor::new(d);

        // Parse the HEADERS frame type.
        stream.try_fill_buffer_for_tests(&mut cursor)?;
        assert_eq!(stream.state_buf.capacity(), 16);

        let frame_ty = stream.try_consume_varint()?;
        assert_eq!(frame_ty, HEADERS_FRAME_TYPE_ID);
        assert_eq!(stream.state_buf.capacity(), 16);

        stream.set_frame_type(frame_ty)?;
        assert_eq!(stream.state_buf.capacity(), 16);

        // Parse the HEADERS frame payload length.
        stream.try_fill_buffer_for_tests(&mut cursor)?;
        assert_eq!(stream.state_buf.capacity(), 16);

        // Parse fails because we need more bytes for the 4-byte encoded length.
        // This trial then sets the expected buffer size for us to fill.
        assert_eq!(stream.try_consume_varint(), Err(Error::Done));
        stream.try_fill_buffer_for_tests(&mut cursor)?;
        assert_eq!(stream.state_buf.capacity(), 16);

        let frame_payload_len = stream.try_consume_varint()?;
        assert_eq!(frame_payload_len, LARGE_HEADER_LEN as u64);
        assert_eq!(stream.state_buf.capacity(), 16);

        stream.set_frame_payload_len(frame_payload_len)?;
        assert_eq!(stream.state_buf.capacity(), MAX_STATE_BUF_ALLOC_SIZE);

        // Start consuming HEADERS frame payload. It fails because the cursor
        // doesn't have the target size of data in it.
        assert_eq!(
            stream.try_fill_buffer_for_tests(&mut cursor),
            Err(Error::Done)
        );
        assert_state_buf_props(
            &stream,
            LARGE_HEADER_LEN,
            0,
            MAX_STATE_BUF_ALLOC_SIZE,
        );

        // Initially consume spare capacity without growing; each later
        // chunk crosses a reserve boundary. Keep the exact original
        // offsets and expected capacity at every intermediate read.
        let schedule = [
            (2_048, 1),
            (1_024, 1),
            (512, 1),
            (4_096, 2),
            (8_192, 4),
            (16_384, 8),
            (32_768, 16),
            (65_536, 32),
        ];
        let mut fed = 0;
        for (chunk, multiplier) in schedule {
            fed += chunk;
            cursor.get_mut().resize(5 + fed, 123);
            assert_eq!(
                stream.try_fill_buffer_for_tests(&mut cursor),
                Err(Error::Done)
            );
            assert_state_buf_props(
                &stream,
                LARGE_HEADER_LEN,
                fed,
                MAX_STATE_BUF_ALLOC_SIZE * multiplier,
            );
        }
        assert_eq!(fed, 130_560);
        cursor.get_mut().resize(5 + LARGE_HEADER_LEN, 123);
        assert_eq!(stream.try_fill_buffer_for_tests(&mut cursor), Ok(()));
        assert_state_buf_props(
            &stream,
            LARGE_HEADER_LEN,
            LARGE_HEADER_LEN,
            MAX_STATE_BUF_ALLOC_SIZE * 64,
        );

        let header_block = vec![123; LARGE_HEADER_LEN];
        let hdrs = Frame::Headers { header_block };
        assert_eq!(
            stream.try_consume_frame(),
            Ok((hdrs, LARGE_HEADER_LEN as u64))
        );
        assert_eq!(stream.state, State::FrameType);

        assert_state_buf_props(&stream, 1, 0, MAX_STATE_BUF_ALLOC_SIZE * 64);
        Ok(())
    }
}
