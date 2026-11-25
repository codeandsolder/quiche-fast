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

use super::Result;

#[cfg(feature = "qlog")]
use qlog::events::http3::Http3Frame;

pub const DATA_FRAME_TYPE_ID: u64 = 0x0;
pub const HEADERS_FRAME_TYPE_ID: u64 = 0x1;
pub const CANCEL_PUSH_FRAME_TYPE_ID: u64 = 0x3;
pub const SETTINGS_FRAME_TYPE_ID: u64 = 0x4;
pub const PUSH_PROMISE_FRAME_TYPE_ID: u64 = 0x5;
pub const GOAWAY_FRAME_TYPE_ID: u64 = 0x7;
pub const MAX_PUSH_FRAME_TYPE_ID: u64 = 0xD;
pub const PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID: u64 = 0xF0700;
pub const PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID: u64 = 0xF0701;

pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;
pub const SETTINGS_H3_DATAGRAM_00: u64 = 0x276;
pub const SETTINGS_H3_DATAGRAM: u64 = 0x33;

// Permit between 16 maximally-encoded and 128 minimally-encoded SETTINGS.
pub const MAX_SETTINGS_PAYLOAD_SIZE: usize = 256;

#[derive(Clone, PartialEq, Eq)]
pub enum Frame {
    Data {
        payload: Vec<u8>,
    },

    Headers {
        header_block: Vec<u8>,
    },

    CancelPush {
        push_id: u64,
    },

    Settings {
        max_field_section_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
        connect_protocol_enabled: Option<u64>,
        h3_datagram: Option<u64>,
        grease: Option<(u64, u64)>,
        additional_settings: Option<Vec<(u64, u64)>>,
        raw: Option<Vec<(u64, u64)>>,
    },

    PushPromise {
        push_id: u64,
        header_block: Vec<u8>,
    },

    GoAway {
        id: u64,
    },

    MaxPushId {
        push_id: u64,
    },

    PriorityUpdateRequest {
        prioritized_element_id: u64,
        priority_field_value: Vec<u8>,
    },

    PriorityUpdatePush {
        prioritized_element_id: u64,
        priority_field_value: Vec<u8>,
    },

    Unknown {
        raw_type: u64,
        payload: Vec<u8>,
    },
}

/// The wire payload shapes shared by frame variants. Calculating the exact
/// encoded size before writing avoids leaving a partial frame in the caller's
/// output buffer if there is insufficient space or a varint is out of range.
enum FramePayload<'a> {
    Bytes(&'a [u8]),
    Varint(u64),
    IdAndBytes(u64, &'a [u8]),
    Settings(&'a Frame),
}

impl FramePayload<'_> {
    fn encoded_len(&self) -> Result<usize> {
        match self {
            Self::Bytes(bytes) => Ok(bytes.len()),

            Self::Varint(value) => {
                if *value > octets::MAX_VAR_INT {
                    return Err(super::Error::BufferTooShort);
                }
                Ok(octets::varint_len(*value))
            },

            Self::IdAndBytes(id, bytes) => {
                if *id > octets::MAX_VAR_INT {
                    return Err(super::Error::BufferTooShort);
                }
                octets::varint_len(*id)
                    .checked_add(bytes.len())
                    .ok_or(super::Error::BufferTooShort)
            },

            Self::Settings(frame) =>
                frame
                    .settings_pairs()
                    .try_fold(0_usize, |len, (id, value)| {
                        if id > octets::MAX_VAR_INT || value > octets::MAX_VAR_INT
                        {
                            return Err(super::Error::InvalidSettings);
                        }
                        let len = len
                            .checked_add(octets::varint_len(id))
                            .and_then(|len| {
                                len.checked_add(octets::varint_len(value))
                            })
                            .ok_or(super::Error::ExcessiveLoad)?;
                        if len > MAX_SETTINGS_PAYLOAD_SIZE {
                            return Err(super::Error::ExcessiveLoad);
                        }
                        Ok(len)
                    }),
        }
    }

    fn encode(&self, b: &mut octets::OctetsMut) -> Result<()> {
        match self {
            Self::Bytes(bytes) => {
                b.put_bytes(bytes)?;
            },

            Self::Varint(value) => {
                b.put_varint(*value)?;
            },

            Self::IdAndBytes(id, bytes) => {
                b.put_varint(*id)?;
                b.put_bytes(bytes)?;
            },

            Self::Settings(frame) =>
                for (id, value) in frame.settings_pairs() {
                    b.put_varint(id)?;
                    b.put_varint(value)?;
                },
        }
        Ok(())
    }
}

struct FrameEncoding<'a> {
    frame_type: u64,
    payload: FramePayload<'a>,
    wire_payload_len: u64,
    total: usize,
}

impl FrameEncoding<'_> {
    fn write(&self, b: &mut octets::OctetsMut) -> Result<usize> {
        if b.cap() < self.total {
            return Err(super::Error::BufferTooShort);
        }
        b.put_varint(self.frame_type)?;
        b.put_varint(self.wire_payload_len)?;
        self.payload.encode(b)?;
        Ok(self.total)
    }
}

impl Frame {
    pub fn from_bytes(
        frame_type: u64, payload_length: u64, bytes: &[u8],
    ) -> Result<Self> {
        // Validate the entire wire length before narrowing to usize. On a
        // 32-bit target a large varint must never wrap into a short payload.
        // SETTINGS is rejected for excessive size independently of the data
        // buffer, including when its length cannot fit in usize.
        if frame_type == SETTINGS_FRAME_TYPE_ID &&
            payload_length > MAX_SETTINGS_PAYLOAD_SIZE as u64
        {
            return Err(super::Error::ExcessiveLoad);
        }

        let payload_length = usize::try_from(payload_length)
            .map_err(|_| super::Error::BufferTooShort)?;
        let bytes = bytes
            .get(..payload_length)
            .ok_or(super::Error::BufferTooShort)?;
        let mut b = octets::Octets::with_slice(bytes);

        let frame = match frame_type {
            DATA_FRAME_TYPE_ID => Self::Data {
                payload: b.get_bytes(payload_length)?.to_vec(),
            },

            HEADERS_FRAME_TYPE_ID => Self::Headers {
                header_block: b.get_bytes(payload_length)?.to_vec(),
            },

            CANCEL_PUSH_FRAME_TYPE_ID => Self::CancelPush {
                push_id: parse_single_varint(payload_length, &mut b)?,
            },

            SETTINGS_FRAME_TYPE_ID => parse_settings_frame(&mut b)?,

            PUSH_PROMISE_FRAME_TYPE_ID =>
                parse_push_promise(payload_length, &mut b)?,

            GOAWAY_FRAME_TYPE_ID => Self::GoAway {
                id: parse_single_varint(payload_length, &mut b)?,
            },

            MAX_PUSH_FRAME_TYPE_ID => Self::MaxPushId {
                push_id: parse_single_varint(payload_length, &mut b)?,
            },

            PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID |
            PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID =>
                parse_priority_update(frame_type, payload_length, &mut b)?,

            _ => Self::Unknown {
                raw_type: frame_type,
                payload: b.get_bytes(payload_length)?.to_vec(),
            },
        };

        Ok(frame)
    }

    /// Prepare a frame's wire type and payload without allocating or writing.
    fn encoding(&self) -> (u64, FramePayload<'_>) {
        match self {
            Self::Data { payload } =>
                (DATA_FRAME_TYPE_ID, FramePayload::Bytes(payload)),

            Self::Headers { header_block } =>
                (HEADERS_FRAME_TYPE_ID, FramePayload::Bytes(header_block)),

            Self::CancelPush { push_id } =>
                (CANCEL_PUSH_FRAME_TYPE_ID, FramePayload::Varint(*push_id)),

            Self::Settings { .. } =>
                (SETTINGS_FRAME_TYPE_ID, FramePayload::Settings(self)),

            Self::PushPromise {
                push_id,
                header_block,
            } => (
                PUSH_PROMISE_FRAME_TYPE_ID,
                FramePayload::IdAndBytes(*push_id, header_block),
            ),

            Self::GoAway { id } =>
                (GOAWAY_FRAME_TYPE_ID, FramePayload::Varint(*id)),

            Self::MaxPushId { push_id } =>
                (MAX_PUSH_FRAME_TYPE_ID, FramePayload::Varint(*push_id)),

            Self::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => (
                PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID,
                FramePayload::IdAndBytes(
                    *prioritized_element_id,
                    priority_field_value,
                ),
            ),

            Self::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => (
                PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID,
                FramePayload::IdAndBytes(
                    *prioritized_element_id,
                    priority_field_value,
                ),
            ),

            Self::Unknown { raw_type, payload } =>
                (*raw_type, FramePayload::Bytes(payload)),
        }
    }

    /// Iterates over the encoded SETTINGS pairs, excluding the decoded `raw`
    /// field. The same iterator is used for exact size planning and emission.
    fn settings_pairs(&self) -> impl Iterator<Item = (u64, u64)> + Clone + '_ {
        let Self::Settings {
            max_field_section_size,
            qpack_max_table_capacity,
            qpack_blocked_streams,
            connect_protocol_enabled,
            h3_datagram,
            grease,
            additional_settings,
            ..
        } = self
        else {
            unreachable!("SETTINGS pairs requested for a different frame type");
        };

        [
            max_field_section_size.map(|v| (SETTINGS_MAX_FIELD_SECTION_SIZE, v)),
            qpack_max_table_capacity
                .map(|v| (SETTINGS_QPACK_MAX_TABLE_CAPACITY, v)),
            qpack_blocked_streams.map(|v| (SETTINGS_QPACK_BLOCKED_STREAMS, v)),
            connect_protocol_enabled
                .map(|v| (SETTINGS_ENABLE_CONNECT_PROTOCOL, v)),
            h3_datagram.map(|v| (SETTINGS_H3_DATAGRAM_00, v)),
            h3_datagram.map(|v| (SETTINGS_H3_DATAGRAM, v)),
            *grease,
        ]
        .into_iter()
        .flatten()
        .chain(additional_settings.iter().flatten().copied())
    }

    fn encoding_plan(&self) -> Result<FrameEncoding<'_>> {
        let (frame_type, payload) = self.encoding();
        if frame_type > octets::MAX_VAR_INT {
            return Err(super::Error::BufferTooShort);
        }
        let payload_len = payload.encoded_len()?;
        let wire_payload_len = u64::try_from(payload_len)
            .map_err(|_| super::Error::BufferTooShort)?;
        if wire_payload_len > octets::MAX_VAR_INT {
            return Err(super::Error::BufferTooShort);
        }
        let total = octets::varint_len(frame_type)
            .checked_add(octets::varint_len(wire_payload_len))
            .and_then(|len| len.checked_add(payload_len))
            .ok_or(super::Error::BufferTooShort)?;
        Ok(FrameEncoding {
            frame_type,
            payload,
            wire_payload_len,
            total,
        })
    }

    /// Encodes an entire frame, leaving the caller's buffer and write cursor
    /// untouched if its encoded size cannot fit or a varint is invalid.
    pub fn to_bytes(&self, b: &mut octets::OctetsMut) -> Result<usize> {
        self.encoding_plan()?.write(b)
    }

    /// Encodes an entire frame into a dynamically sized owned buffer.
    ///
    /// # Errors
    /// Returns an error for invalid wire values or failed allocation.
    #[cfg(any(feature = "internal", test))]
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let plan = self.encoding_plan()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(plan.total)
            .map_err(|_| super::Error::ExcessiveLoad)?;
        bytes.resize(plan.total, 0);
        plan.write(&mut octets::OctetsMut::with_slice(&mut bytes))?;
        Ok(bytes)
    }

    #[cfg(feature = "qlog")]
    #[must_use = "the returned frame is the diagnostic representation to record"]
    pub fn to_qlog(&self) -> Http3Frame {
        use qlog::events::RawInfo;

        match self {
            Self::Data { .. } => Http3Frame::Data { raw: None },

            // Qlog expects the `headers` to be represented as an array of
            // name:value pairs. At this stage, we only have the qpack block, so
            // populate the field with an empty vec.
            Self::Headers { .. } => Http3Frame::Headers {
                headers: vec![],
                raw: None,
            },

            Self::CancelPush { push_id } => Http3Frame::CancelPush {
                push_id: *push_id,
                raw: None,
            },

            Self::Settings {
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                connect_protocol_enabled,
                h3_datagram,
                grease,
                additional_settings,
                ..
            } => {
                use qlog::events::http3::Setting;

                let known = [
                    ("MAX_FIELD_SECTION_SIZE", max_field_section_size),
                    ("QPACK_MAX_TABLE_CAPACITY", qpack_max_table_capacity),
                    ("QPACK_BLOCKED_STREAMS", qpack_blocked_streams),
                    (
                        "SETTINGS_ENABLE_CONNECT_PROTOCOL",
                        connect_protocol_enabled,
                    ),
                    ("H3_DATAGRAM", h3_datagram),
                ];
                let mut settings: Vec<_> = known
                    .into_iter()
                    .filter_map(|(name, value)| {
                        value.map(|value| Setting {
                            name: Some(name.to_owned()),
                            name_bytes: None,
                            value,
                        })
                    })
                    .collect();

                settings.extend(
                    grease
                        .iter()
                        .chain(additional_settings.iter().flatten())
                        .map(|(k, v)| Setting {
                            name: Some(k.to_string()),
                            name_bytes: None,
                            value: *v,
                        }),
                );

                Http3Frame::Settings {
                    settings,
                    raw: None,
                }
            },

            // Qlog expects the `headers` to be represented as an array of
            // name:value pairs. At this stage, we only have the qpack block, so
            // populate the field with an empty vec.
            Self::PushPromise { push_id, .. } => Http3Frame::PushPromise {
                push_id: *push_id,
                headers: vec![],
                raw: None,
            },

            Self::GoAway { id } => Http3Frame::Goaway { id: *id, raw: None },

            Self::MaxPushId { push_id } => Http3Frame::MaxPushId {
                push_id: *push_id,
                raw: None,
            },

            Self::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => Http3Frame::PriorityUpdate {
                stream_id: Some(*prioritized_element_id),
                push_id: None,
                priority_field_value: String::from_utf8_lossy(
                    priority_field_value,
                )
                .into_owned(),
                raw: None,
            },

            Self::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => Http3Frame::PriorityUpdate {
                stream_id: None,
                push_id: Some(*prioritized_element_id),
                priority_field_value: String::from_utf8_lossy(
                    priority_field_value,
                )
                .into_owned(),
                raw: None,
            },

            Self::Unknown { raw_type, payload } => Http3Frame::Unknown {
                frame_type_bytes: *raw_type,
                raw: Some(RawInfo {
                    data: None,
                    payload_length: Some(payload.len() as u64),
                    length: None,
                }),
            },
        }
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Data { .. } => {
                write!(f, "DATA")?;
            },

            Self::Headers { .. } => {
                write!(f, "HEADERS")?;
            },

            Self::CancelPush { push_id } => {
                write!(f, "CANCEL_PUSH push_id={push_id}")?;
            },

            Self::Settings {
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                additional_settings,
                raw,
                ..
            } => {
                write!(f, "SETTINGS max_field_section={max_field_section_size:?}, qpack_max_table={qpack_max_table_capacity:?}, qpack_blocked={qpack_blocked_streams:?} raw={raw:?}, additional_settings={additional_settings:?}")?;
            },

            Self::PushPromise {
                push_id,
                header_block,
            } => {
                write!(
                    f,
                    "PUSH_PROMISE push_id={push_id} len={}",
                    header_block.len()
                )?;
            },

            Self::GoAway { id } => {
                write!(f, "GOAWAY id={id}")?;
            },

            Self::MaxPushId { push_id } => {
                write!(f, "MAX_PUSH_ID push_id={push_id}")?;
            },

            Self::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => {
                write!(
                    f,
                    "PRIORITY_UPDATE request_stream_id={prioritized_element_id}, priority_field_len={}",
                    priority_field_value.len()
                )?;
            },

            Self::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => {
                write!(
                    f,
                    "PRIORITY_UPDATE push_id={prioritized_element_id}, priority_field_len={}",
                    priority_field_value.len()
                )?;
            },

            Self::Unknown { raw_type, .. } => {
                write!(f, "UNKNOWN raw_type={raw_type}")?;
            },
        }

        Ok(())
    }
}

fn parse_settings_frame(b: &mut octets::Octets) -> Result<Frame> {
    let mut max_field_section_size = None;
    let mut qpack_max_table_capacity = None;
    let mut qpack_blocked_streams = None;
    let mut connect_protocol_enabled = None;
    let mut h3_datagram = None;
    let mut draft_h3_datagram = None;
    let mut raw = Vec::new();
    let mut additional_settings: Option<Vec<(u64, u64)>> = None;

    // The caller has already checked and bounded the payload.
    while b.cap() > 0 {
        let identifier = b.get_varint()?;
        let value = b.get_varint()?;

        // MAX_SETTINGS_PAYLOAD_SIZE protects us from storing too many raw
        // settings.
        if raw.iter().any(|&(id, _)| id == identifier) {
            return Err(super::Error::InvalidSettings);
        }
        raw.push((identifier, value));

        match identifier {
            SETTINGS_QPACK_MAX_TABLE_CAPACITY => {
                qpack_max_table_capacity = Some(value);
            },

            SETTINGS_MAX_FIELD_SECTION_SIZE => {
                max_field_section_size = Some(value);
            },

            SETTINGS_QPACK_BLOCKED_STREAMS => {
                qpack_blocked_streams = Some(value);
            },

            SETTINGS_ENABLE_CONNECT_PROTOCOL => {
                if value > 1 {
                    return Err(super::Error::InvalidSettings);
                }

                connect_protocol_enabled = Some(value);
            },

            SETTINGS_H3_DATAGRAM_00 | SETTINGS_H3_DATAGRAM => {
                if value > 1 {
                    return Err(super::Error::InvalidSettings);
                }

                if identifier == SETTINGS_H3_DATAGRAM {
                    h3_datagram = Some(value);
                } else {
                    draft_h3_datagram = Some(value);
                }
            },

            // Reserved values overlap with HTTP/2 and MUST be rejected
            0x0 | 0x2 | 0x3 | 0x4 | 0x5 =>
                return Err(super::Error::InvalidSettings),

            // Unknown Settings parameters go into additional_settings.
            _ => {
                let s: &mut Vec<(u64, u64)> =
                    additional_settings.get_or_insert_with(Vec::new);
                s.push((identifier, value));
            },
        }
    }

    Ok(Frame::Settings {
        max_field_section_size,
        qpack_max_table_capacity,
        qpack_blocked_streams,
        connect_protocol_enabled,
        h3_datagram: h3_datagram.or(draft_h3_datagram),
        grease: None,
        raw: Some(raw),
        additional_settings,
    })
}

/// Parses the payload of a frame that carries a single varint, making sure the
/// varint covers the whole payload.
fn parse_single_varint(
    payload_length: usize, b: &mut octets::Octets,
) -> Result<u64> {
    let before = b.off();
    let v = b.get_varint()?;

    if b.off() - before != payload_length {
        return Err(super::Error::MalformedFrame);
    }

    Ok(v)
}

/// Decode a required leading ID and its remaining, frame-bounded payload.
/// Both `PUSH_PROMISE` and `PRIORITY_UPDATE` have the same wire structure.
fn parse_id_and_payload(
    payload_length: usize, b: &mut octets::Octets,
) -> Result<(u64, Vec<u8>)> {
    let before = b.off();
    let id = b.get_varint()?;
    let remaining = payload_length
        .checked_sub(b.off() - before)
        .ok_or(super::Error::MalformedFrame)?;
    Ok((id, b.get_bytes(remaining)?.to_vec()))
}

fn parse_push_promise(
    payload_length: usize, b: &mut octets::Octets,
) -> Result<Frame> {
    let (push_id, header_block) = parse_id_and_payload(payload_length, b)?;

    Ok(Frame::PushPromise {
        push_id,
        header_block,
    })
}

fn parse_priority_update(
    frame_type: u64, payload_length: usize, b: &mut octets::Octets,
) -> Result<Frame> {
    let (prioritized_element_id, priority_field_value) =
        parse_id_and_payload(payload_length, b)?;

    match frame_type {
        PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID =>
            Ok(Frame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            }),

        PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID => Ok(Frame::PriorityUpdatePush {
            prioritized_element_id,
            priority_field_value,
        }),

        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(
        frame: &Frame, frame_type: u64, payload_len: usize, header_len: usize,
    ) -> Result<Result<Frame>> {
        let mut storage = vec![0x2a; header_len + payload_len];
        let written =
            frame.to_bytes(&mut octets::OctetsMut::with_slice(&mut storage))?;
        assert_eq!(written, header_len + payload_len);
        let mut wire = octets::Octets::with_slice(&storage);
        assert_eq!(wire.get_varint()?, frame_type);
        assert_eq!(wire.get_varint()?, payload_len as u64);
        assert_eq!(wire.off(), header_len);
        Ok(Frame::from_bytes(
            frame_type,
            payload_len as u64,
            &storage[header_len..],
        ))
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn qlog_settings_preserve_order_and_omit_absent_values() {
        let frame = Frame::Settings {
            max_field_section_size: Some(1024),
            qpack_max_table_capacity: None,
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: Some(1),
            h3_datagram: None,
            grease: Some((33, 42)),
            additional_settings: Some(vec![(65, 7), (66, 8)]),
            raw: Some(vec![(99, 100)]),
        };
        let expected = [
            ("MAX_FIELD_SECTION_SIZE", 1024),
            ("QPACK_BLOCKED_STREAMS", 0),
            ("SETTINGS_ENABLE_CONNECT_PROTOCOL", 1),
            ("33", 42),
            ("65", 7),
            ("66", 8),
        ]
        .into_iter()
        .map(|(name, value)| qlog::events::http3::Setting {
            name: Some(name.to_owned()),
            name_bytes: None,
            value,
        })
        .collect();
        assert_eq!(frame.to_qlog(), Http3Frame::Settings {
            settings: expected,
            raw: None,
        });
    }

    #[test]
    fn frame_encoding_does_not_write_partial_frames() -> Result<()> {
        // All variants must leave both the cursor and caller's buffer intact
        // if the frame cannot be written in full. Test every truncation
        // boundary, including a pre-existing nonzero writer offset.
        let frames = [
            Frame::Data {
                payload: vec![1, 2, 3, 4, 5],
            },
            Frame::Headers {
                header_block: vec![7, 8, 9],
            },
            Frame::CancelPush { push_id: 456 },
            Frame::Settings {
                max_field_section_size: Some(123),
                qpack_max_table_capacity: Some(456),
                qpack_blocked_streams: None,
                connect_protocol_enabled: Some(1),
                h3_datagram: Some(1),
                grease: Some((0x21, 0x23)),
                additional_settings: Some(vec![(0x45, 0x67)]),
                raw: None,
            },
            Frame::PushPromise {
                push_id: 123,
                header_block: vec![9, 8, 7],
            },
            Frame::GoAway { id: 456 },
            Frame::MaxPushId { push_id: 789 },
            Frame::PriorityUpdateRequest {
                prioritized_element_id: 12,
                priority_field_value: b"u=3,i".to_vec(),
            },
            Frame::PriorityUpdatePush {
                prioritized_element_id: 13,
                priority_field_value: b"u=4".to_vec(),
            },
            Frame::Unknown {
                raw_type: 0x42,
                payload: vec![0x33; 5],
            },
        ];
        for frame in frames {
            let mut full = [0xA5; 512];
            let total =
                frame.to_bytes(&mut octets::OctetsMut::with_slice(&mut full))?;
            assert_eq!(frame.to_vec()?, full[..total]);
            for capacity in 0..total {
                let mut storage = [0xA5; 512];
                let mut writer =
                    octets::OctetsMut::with_slice(&mut storage[..=capacity]);
                writer.put_u8(0x5A)?;
                assert_eq!(
                    frame.to_bytes(&mut writer),
                    Err(super::super::Error::BufferTooShort),
                    "frame={frame:?}, capacity={capacity}"
                );
                assert_eq!(
                    writer.off(),
                    1,
                    "frame={frame:?}, capacity={capacity}"
                );
                assert_eq!(storage[0], 0x5A);
                assert!(storage[1..].iter().all(|&byte| byte == 0xA5));
            }
        }
        Ok(())
    }

    #[test]
    fn payload_varint_width_transitions_are_atomic() -> Result<()> {
        for len in [0, 63, 64, 16_383, 16_384] {
            let payload = vec![0x31; len];
            for frame in [
                Frame::Data {
                    payload: payload.clone(),
                },
                Frame::PushPromise {
                    push_id: 16_384,
                    header_block: payload.clone(),
                },
                Frame::PriorityUpdatePush {
                    prioritized_element_id: 63,
                    priority_field_value: payload,
                },
            ] {
                let mut full = vec![0xA5; len + 32];
                let total = frame
                    .to_bytes(&mut octets::OctetsMut::with_slice(&mut full))?;
                assert_eq!(frame.to_vec()?, full[..total]);
                for available in [0, 1, total - 1] {
                    let mut storage = vec![0xA5; available];
                    let mut writer = octets::OctetsMut::with_slice(&mut storage);
                    assert_eq!(
                        frame.to_bytes(&mut writer),
                        Err(super::super::Error::BufferTooShort),
                        "frame={frame:?}, available={available}"
                    );
                    assert_eq!(writer.off(), 0);
                    assert!(storage.iter().all(|&byte| byte == 0xA5));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn invalid_frame_varints_do_not_write_partial_headers() {
        for frame in [
            Frame::GoAway {
                id: octets::MAX_VAR_INT + 1,
            },
            Frame::Unknown {
                raw_type: octets::MAX_VAR_INT + 1,
                payload: vec![1, 2, 3],
            },
            Frame::PriorityUpdateRequest {
                prioritized_element_id: octets::MAX_VAR_INT + 1,
                priority_field_value: vec![1, 2, 3],
            },
        ] {
            let mut storage = [0xA5; 64];
            let mut writer = octets::OctetsMut::with_slice(&mut storage);
            assert_eq!(
                frame.to_bytes(&mut writer),
                Err(super::super::Error::BufferTooShort)
            );
            assert_eq!(frame.to_vec(), Err(super::super::Error::BufferTooShort));
            assert_eq!(writer.off(), 0, "frame={frame:?}");
            assert!(storage.iter().all(|&byte| byte == 0xA5));
        }
    }

    #[test]
    fn data() -> Result<()> {
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let frame_payload_len = payload.len();
        let frame_header_len = 2;

        let frame = Frame::Data { payload };

        assert_eq!(
            round_trip(
                &frame,
                DATA_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn headers() -> Result<()> {
        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let frame_payload_len = header_block.len();
        let frame_header_len = 2;

        let frame = Frame::Headers { header_block };

        assert_eq!(
            round_trip(
                &frame,
                HEADERS_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn cancel_push() -> Result<()> {
        let frame = Frame::CancelPush { push_id: 0 };

        let frame_payload_len = 1;
        let frame_header_len = 2;

        assert_eq!(
            round_trip(
                &frame,
                CANCEL_PUSH_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn settings_reject_duplicate_wire_identifiers() -> Result<()> {
        for id in [
            SETTINGS_MAX_FIELD_SECTION_SIZE,
            SETTINGS_QPACK_MAX_TABLE_CAPACITY,
            SETTINGS_QPACK_BLOCKED_STREAMS,
            SETTINGS_ENABLE_CONNECT_PROTOCOL,
            SETTINGS_H3_DATAGRAM,
            SETTINGS_H3_DATAGRAM_00,
            9,
            octets::MAX_VAR_INT,
        ] {
            let mut bytes = [0; 32];
            let mut out = octets::OctetsMut::with_slice(&mut bytes);
            out.put_varint(id)?;
            out.put_varint(0)?;
            out.put_varint_with_len(id, 8)?;
            out.put_varint(1)?;
            let len = out.off();
            assert_eq!(
                Frame::from_bytes(
                    SETTINGS_FRAME_TYPE_ID,
                    len as u64,
                    &bytes[..len]
                ),
                Err(crate::h3::Error::InvalidSettings),
                "duplicate {id}"
            );
        }
        Ok(())
    }

    #[test]
    fn standard_datagram_setting_takes_precedence_in_either_order() -> Result<()>
    {
        for bytes in [[0x42, 0x76, 1, 0x33, 0], [0x33, 0, 0x42, 0x76, 1]] {
            let parsed = Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                bytes.len() as u64,
                &bytes,
            )?;
            assert!(matches!(parsed, Frame::Settings {
                h3_datagram: Some(0),
                ..
            }));
        }
        let parsed =
            Frame::from_bytes(SETTINGS_FRAME_TYPE_ID, 3, &[0x42, 0x76, 1])?;
        assert!(matches!(parsed, Frame::Settings {
            h3_datagram: Some(1),
            ..
        }));
        Ok(())
    }

    #[test]
    fn settings_all_no_grease() -> Result<()> {
        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
            (SETTINGS_ENABLE_CONNECT_PROTOCOL, 0),
            (SETTINGS_H3_DATAGRAM_00, 0),
            (SETTINGS_H3_DATAGRAM, 0),
        ];

        let frame = Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: Some(0),
            h3_datagram: Some(0),
            grease: None,
            raw: Some(raw_settings),
            additional_settings: None,
        };

        let frame_payload_len = 13;
        let frame_header_len = 2;

        assert_eq!(
            round_trip(
                &frame,
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn settings_all_grease() -> Result<()> {
        let frame = Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: Some(0),
            h3_datagram: Some(0),
            grease: Some((33, 33)),
            raw: None,
            additional_settings: None,
        };

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
            (SETTINGS_ENABLE_CONNECT_PROTOCOL, 0),
            (SETTINGS_H3_DATAGRAM_00, 0),
            (SETTINGS_H3_DATAGRAM, 0),
            (33, 33),
        ];

        // Frame parsing will not populate GREASE property but will be in the
        // raw info.
        let frame_parsed = Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: Some(0),
            h3_datagram: Some(0),
            grease: None,
            raw: Some(raw_settings),
            additional_settings: Some(vec![(33, 33)]),
        };

        let frame_payload_len = 15;
        let frame_header_len = 2;

        assert_eq!(
            round_trip(
                &frame,
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame_parsed),
        );
        Ok(())
    }

    #[test]
    fn settings_h3_only() -> Result<()> {
        let raw_settings = vec![(SETTINGS_MAX_FIELD_SECTION_SIZE, 1024)];

        let frame = Frame::Settings {
            max_field_section_size: Some(1024),
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(raw_settings),
            additional_settings: None,
        };

        let frame_payload_len = 3;
        let frame_header_len = 2;

        assert_eq!(
            round_trip(
                &frame,
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn settings_h3_connect_protocol_enabled() -> Result<()> {
        let raw_settings = vec![(SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)];

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: Some(1),
            h3_datagram: None,
            grease: None,
            raw: Some(raw_settings),
            additional_settings: None,
        };

        let frame_payload_len = 2;
        let frame_header_len = 2;

        assert_eq!(
            round_trip(
                &frame,
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn settings_h3_connect_protocol_enabled_bad() -> Result<()> {
        let raw_settings = vec![(SETTINGS_ENABLE_CONNECT_PROTOCOL, 9)];

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: Some(9),
            h3_datagram: None,
            grease: None,
            raw: Some(raw_settings),
            additional_settings: None,
        };

        let frame_payload_len = 2;
        let frame_header_len = 2;

        assert_eq!(
            round_trip(
                &frame,
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Err(crate::h3::Error::InvalidSettings),
        );
        Ok(())
    }

    #[test]
    fn settings_h3_dgram_only() -> Result<()> {
        let raw_settings =
            vec![(SETTINGS_H3_DATAGRAM_00, 1), (SETTINGS_H3_DATAGRAM, 1)];

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: Some(1),
            grease: None,
            raw: Some(raw_settings),
            additional_settings: None,
        };

        let frame_payload_len = 5;
        let frame_header_len = 2;

        assert_eq!(
            round_trip(
                &frame,
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn settings_h3_dgram_bad() -> Result<()> {
        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: Some(5),
            grease: None,
            raw: None,
            additional_settings: None,
        };

        let frame_payload_len = 5;
        let frame_header_len = 2;

        assert_eq!(
            round_trip(
                &frame,
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Err(crate::h3::Error::InvalidSettings),
        );
        Ok(())
    }

    #[test]
    fn settings_qpack_only() -> Result<()> {
        let raw_settings = vec![
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let frame = Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(raw_settings),
            additional_settings: None,
        };

        let frame_payload_len = 4;
        let frame_header_len = 2;

        assert_eq!(
            round_trip(
                &frame,
                SETTINGS_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn settings_h2_prohibited() {
        for prohibited in [0, 2, 3, 4, 5] {
            assert_eq!(
                Frame::from_bytes(SETTINGS_FRAME_TYPE_ID, 2, &[prohibited, 1]),
                Err(crate::h3::Error::InvalidSettings),
                "prohibited setting {prohibited}",
            );
        }
    }

    #[test]
    fn settings_too_big() {
        // Payload content is immaterial: reject the oversized declaration
        // before reading a setting.
        assert_eq!(
            Frame::from_bytes(
                SETTINGS_FRAME_TYPE_ID,
                (MAX_SETTINGS_PAYLOAD_SIZE + 1) as u64,
                &[1, 1]
            ),
            Err(crate::h3::Error::ExcessiveLoad),
        );
    }

    #[test]
    fn push_promise() -> Result<()> {
        let header_block = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let frame_payload_len = 1 + header_block.len();
        let frame_header_len = 2;

        let frame = Frame::PushPromise {
            push_id: 0,
            header_block,
        };

        assert_eq!(
            round_trip(
                &frame,
                PUSH_PROMISE_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn push_promise_non_minimal_varint() -> Result<()> {
        // A regression test for a bug handling varints in frame processing.

        // Value 37 minimally encodes as 1 byte [0x25]. Non-minimal
        // 2-byte encoding: [0x40, 0x25] (2-byte varint prefix 0b01).
        let header_block = b"\x00\x01\x02";
        let mut payload = vec![0x40u8, 0x25]; // non-minimal push_id = 37
        payload.extend_from_slice(header_block);
        let payload_length = payload.len() as u64;
        let frame = Frame::from_bytes(
            PUSH_PROMISE_FRAME_TYPE_ID,
            payload_length,
            &payload,
        )?;
        assert_eq!(frame, Frame::PushPromise {
            push_id: 37,
            header_block: header_block.to_vec(),
        });
        Ok(())
    }

    #[test]
    fn goaway() -> Result<()> {
        let frame = Frame::GoAway { id: 32 };

        let frame_payload_len = 1;
        let frame_header_len = 2;

        assert_eq!(
            round_trip(
                &frame,
                GOAWAY_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn max_push_id() -> Result<()> {
        let frame = Frame::MaxPushId { push_id: 128 };

        let frame_payload_len = 2;
        let frame_header_len = 2;

        assert_eq!(
            round_trip(
                &frame,
                MAX_PUSH_FRAME_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn single_varint_frames_reject_trailing_bytes() {
        // The payload is a 1-byte varint followed by two extra bytes.
        let d = [0x05, 0xaa, 0xbb];

        for frame_type in [
            CANCEL_PUSH_FRAME_TYPE_ID,
            GOAWAY_FRAME_TYPE_ID,
            MAX_PUSH_FRAME_TYPE_ID,
        ] {
            assert_eq!(
                Frame::from_bytes(frame_type, d.len() as u64, &d),
                Err(crate::h3::Error::MalformedFrame)
            );
        }
    }

    #[test]
    fn priority_update_request() -> Result<()> {
        let prioritized_element_id = 4;
        let priority_field_value = b"abcdefghijklm".to_vec();
        let frame_payload_len = 1 + priority_field_value.len();
        let frame_header_len = 5;

        let frame = Frame::PriorityUpdateRequest {
            prioritized_element_id,
            priority_field_value,
        };

        assert_eq!(
            round_trip(
                &frame,
                PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn priority_update_push() -> Result<()> {
        let prioritized_element_id = 6;
        let priority_field_value = b"abcdefghijklm".to_vec();
        let frame_payload_len = 1 + priority_field_value.len();
        let frame_header_len = 5;

        let frame = Frame::PriorityUpdatePush {
            prioritized_element_id,
            priority_field_value,
        };

        assert_eq!(
            round_trip(
                &frame,
                PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID,
                frame_payload_len,
                frame_header_len
            )?,
            Ok(frame),
        );
        Ok(())
    }

    #[test]
    fn priority_update_non_minimal_varint() -> Result<()> {
        // A regression test for a bug handling varints in frame processing.

        // Value 37 minimally encodes as 1 byte [0x25]. Non-minimal
        // 2-byte encoding: [0x40, 0x25] (2-byte varint prefix 0b01).
        let priority_field = b"u=3";
        let mut payload = vec![0x40u8, 0x25];
        payload.extend_from_slice(priority_field);
        let payload_length = payload.len() as u64;

        let frame = Frame::from_bytes(
            PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID,
            payload_length,
            &payload,
        )?;

        assert_eq!(frame, Frame::PriorityUpdateRequest {
            prioritized_element_id: 37,
            priority_field_value: priority_field.to_vec(),
        });
        Ok(())
    }

    #[test]
    fn oversized_declared_lengths_are_rejected_on_all_target_widths() {
        // 2^32 previously narrowed to zero on 32-bit targets, allowing an
        // empty DATA/HEADERS/UNKNOWN frame to be accepted as valid.
        for length in [u64::from(u32::MAX) + 1, u64::MAX] {
            for frame_type in [
                DATA_FRAME_TYPE_ID,
                HEADERS_FRAME_TYPE_ID,
                CANCEL_PUSH_FRAME_TYPE_ID,
                PUSH_PROMISE_FRAME_TYPE_ID,
                GOAWAY_FRAME_TYPE_ID,
                MAX_PUSH_FRAME_TYPE_ID,
                PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID,
                PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID,
                0xff,
            ] {
                assert_eq!(
                    Frame::from_bytes(frame_type, length, &[0]),
                    Err(crate::h3::Error::BufferTooShort),
                    "unexpected frame type {frame_type:#x}, length {length}",
                );
            }
            assert_eq!(
                Frame::from_bytes(SETTINGS_FRAME_TYPE_ID, length, &[0]),
                Err(crate::h3::Error::ExcessiveLoad),
            );
        }
    }

    #[test]
    fn frames_cannot_read_past_the_declared_payload_boundary() {
        // A two-byte varint cannot borrow its trailing byte from the next
        // frame, even when those bytes are present in the caller's slice.
        for frame_type in [
            CANCEL_PUSH_FRAME_TYPE_ID,
            SETTINGS_FRAME_TYPE_ID,
            PUSH_PROMISE_FRAME_TYPE_ID,
            GOAWAY_FRAME_TYPE_ID,
            MAX_PUSH_FRAME_TYPE_ID,
            PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID,
            PRIORITY_UPDATE_FRAME_PUSH_TYPE_ID,
        ] {
            assert_eq!(
                Frame::from_bytes(frame_type, 1, &[0x40, 0x01]),
                Err(crate::h3::Error::BufferTooShort),
                "frame type {frame_type:#x} crossed its declared boundary",
            );
        }

        // A frame carrying no payload is legal for DATA and unknown types,
        // but not for types requiring an ID or priority varint.
        assert_eq!(
            Frame::from_bytes(DATA_FRAME_TYPE_ID, 0, &[]),
            Ok(Frame::Data { payload: vec![] }),
        );
        assert_eq!(
            Frame::from_bytes(PUSH_PROMISE_FRAME_TYPE_ID, 0, &[0]),
            Err(crate::h3::Error::BufferTooShort),
        );
        assert_eq!(
            Frame::from_bytes(PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID, 0, &[0]),
            Err(crate::h3::Error::BufferTooShort),
        );
    }

    #[test]
    fn unknown_type() {
        let d = [42; 12];

        assert_eq!(
            Frame::from_bytes(255, 12, &d[..]),
            Ok(Frame::Unknown {
                raw_type: 255,
                payload: vec![42; 12]
            })
        );
    }
}
