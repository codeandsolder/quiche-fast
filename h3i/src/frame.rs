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

//! Helpers for dealing with quiche stream events and HTTP/3 frames.

use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::sync::Arc;

use crate::quiche;

use quiche::h3::frame::Frame as QFrame;
use quiche::h3::Header;
use quiche::h3::NameValue;
use serde::ser::SerializeStruct;
use serde::ser::Serializer;
use serde::Serialize;

use crate::client::connection_summary::MAX_SERIALIZED_BUFFER_LEN;

pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// An internal representation of a QUIC or HTTP/3 frame. This type exists so
/// that we can extend types defined in Quiche.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum H3iFrame {
    /// A wrapper around a quiche HTTP/3 frame.
    QuicheH3(QFrame),
    /// A wrapper around an [`EnrichedHeaders`] struct.
    Headers(EnrichedHeaders),
    /// A wrapper around a [`ResetStream`] struct.
    ResetStream(ResetStream),
}

impl H3iFrame {
    /// Borrow decoded headers without copying the field section.
    #[must_use = "returns headers only for a HEADERS frame"]
    pub const fn as_enriched_headers(&self) -> Option<&EnrichedHeaders> {
        match self {
            Self::Headers(headers) => Some(headers),
            _ => None,
        }
    }
}

impl Serialize for H3iFrame {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::QuicheH3(frame) => {
                let mut state = s.serialize_struct("frame", 1)?;
                let name = frame_name(frame);
                state.serialize_field(name, &SerializableQFrame(frame))?;
                state.end()
            },
            Self::Headers(headers) => {
                let mut state = s.serialize_struct("enriched_headers", 1)?;
                state.serialize_field("enriched_headers", headers)?;
                state.end()
            },
            Self::ResetStream(reset) => {
                let mut state = s.serialize_struct("reset_stream", 1)?;
                state.serialize_field("reset_stream", reset)?;
                state.end()
            },
        }
    }
}

impl From<QFrame> for H3iFrame {
    fn from(value: QFrame) -> Self {
        Self::QuicheH3(value)
    }
}

impl TryFrom<Vec<Header>> for H3iFrame {
    type Error = quiche::h3::qpack::Error;

    fn try_from(headers: Vec<Header>) -> Result<Self, Self::Error> {
        EnrichedHeaders::try_from(headers).map(Self::Headers)
    }
}

/// An HTTP/3 HEADERS frame with decoded headers and its original QPACK block.
///
/// Equality compares ordered decoded headers, independently of compression.
#[derive(Clone)]
pub struct EnrichedHeaders {
    header_block: Vec<u8>,
    headers: Vec<Header>,
}

/// A wrapper to help serialize a quiche HTTP header.
pub struct SerializableHeader<'a>(&'a Header);

impl Serialize for SerializableHeader<'_> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = s.serialize_struct("header", 2)?;
        state.serialize_field("name", &String::from_utf8_lossy(self.0.name()))?;
        state
            .serialize_field("value", &String::from_utf8_lossy(self.0.value()))?;
        state.end()
    }
}

impl EnrichedHeaders {
    pub(crate) fn from_wire(header_block: Vec<u8>) -> quiche::h3::Result<Self> {
        let headers = quiche::h3::qpack::decode(&header_block, u64::MAX)
            .map_err(|_| quiche::h3::Error::QpackDecompressionFailed)?;
        Ok(Self::from_parts(header_block, headers))
    }

    const fn from_parts(header_block: Vec<u8>, headers: Vec<Header>) -> Self {
        Self {
            header_block,
            headers,
        }
    }

    /// Return the decoded headers in wire order.
    #[must_use = "borrows the decoded header fields"]
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// Return the encoded QPACK field section, including its prefix.
    #[must_use = "borrows the original encoded field section"]
    pub fn header_block(&self) -> &[u8] {
        &self.header_block
    }

    /// Iterate over all values for the given name in field-section order.
    pub fn header_values<'a>(
        &'a self, name: &'a [u8],
    ) -> impl Iterator<Item = &'a [u8]> {
        self.headers.iter().filter_map(move |header| {
            (header.name() == name).then(|| header.value())
        })
    }

    /// Fetch the first value of the `:status` pseudo-header, when present.
    #[must_use = "returns the first status header if present"]
    pub fn status_code(&self) -> Option<&[u8]> {
        self.header_values(b":status").next()
    }

    /// Match a multiset of expected name/value pairs, including duplicates.
    fn contains_headers(&self, expected: &Self) -> bool {
        if expected.headers.len() > self.headers.len() {
            return false;
        }

        let mut counts = HashMap::new();
        for header in &expected.headers {
            *counts
                .entry((header.name(), header.value()))
                .or_insert(0_usize) += 1;
        }

        for header in &self.headers {
            let key = (header.name(), header.value());
            if let Some(count) = counts.get_mut(&key) {
                *count -= 1;
                if *count == 0 {
                    counts.remove(&key);
                }
            }
            if counts.is_empty() {
                return true;
            }
        }
        counts.is_empty()
    }
}

impl Serialize for EnrichedHeaders {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = s.serialize_struct("enriched_headers", 2)?;
        state.serialize_field("header_block_len", &self.header_block.len())?;
        let x: Vec<SerializableHeader> =
            self.headers.iter().map(SerializableHeader).collect();
        state.serialize_field("headers", &x)?;
        state.end()
    }
}

impl TryFrom<Vec<Header>> for EnrichedHeaders {
    type Error = quiche::h3::qpack::Error;

    fn try_from(headers: Vec<Header>) -> Result<Self, Self::Error> {
        // Literal encoding preserves even deliberately non-compliant names,
        // which is useful for protocol test expectations.
        let header_block = quiche::h3::qpack::encode_literal(&headers)?;
        Ok(Self::from_parts(header_block, headers))
    }
}

impl PartialEq for EnrichedHeaders {
    fn eq(&self, other: &Self) -> bool {
        self.headers == other.headers
    }
}

impl Eq for EnrichedHeaders {}

impl TryFrom<QFrame> for EnrichedHeaders {
    type Error = BoxError;

    fn try_from(value: QFrame) -> Result<Self, Self::Error> {
        match value {
            QFrame::Headers { header_block } =>
                Ok(Self::from_wire(header_block)?),
            _ => Err("Cannot convert non-Headers frame into HeadersFrame".into()),
        }
    }
}

impl Debug for EnrichedHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrichedHeaders")
            .field("headers", &self.headers)
            .field("header_block_len", &self.header_block.len())
            .finish_non_exhaustive()
    }
}

/// A `RESET_STREAM` frame.
///
/// See [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000#name-reset_stream-frames) for
/// more.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ResetStream {
    /// The stream ID over which the `RESET_STREAM` frame was sent.
    pub stream_id: u64,
    /// The error code sent from the peer.
    pub error_code: u64,
}

const fn frame_name(frame: &QFrame) -> &'static str {
    match frame {
        QFrame::Data { .. } => "DATA",
        QFrame::Headers { .. } => "HEADERS",
        QFrame::CancelPush { .. } => "CANCEL_PUSH",
        QFrame::Settings { .. } => "SETTINGS",
        QFrame::PushPromise { .. } => "PUSH_PROMISE",
        QFrame::GoAway { .. } => "GO_AWAY",
        QFrame::MaxPushId { .. } => "MAX_PUSH_ID",
        QFrame::PriorityUpdateRequest { .. } => "PRIORITY_UPDATE(REQUEST)",
        QFrame::PriorityUpdatePush { .. } => "PRIORITY_UPDATE(PUSH)",
        QFrame::Unknown { .. } => "UNKNOWN",
    }
}

/// A wrapper to help serialize a quiche HTTP/3 frame.
pub struct SerializableQFrame<'a>(&'a QFrame);

fn serialize_payload<S: SerializeStruct>(
    state: &mut S, payload: &[u8],
) -> Result<(), S::Error> {
    let max = payload.len().min(MAX_SERIALIZED_BUFFER_LEN);
    state.serialize_field("payload_len", &payload.len())?;
    state.serialize_field(
        "payload",
        &qlog::HexSlice::maybe_string(Some(&payload[..max])),
    )
}

fn serialize_priority<S: SerializeStruct>(
    state: &mut S, id: u64, value: &[u8],
) -> Result<(), S::Error> {
    let max = value.len().min(MAX_SERIALIZED_BUFFER_LEN);
    state.serialize_field("prioritized_element_id", &id)?;
    state.serialize_field("priority_field_value_len", &value.len())?;
    state.serialize_field(
        "priority_field_value",
        &String::from_utf8_lossy(&value[..max]),
    )
}

impl Serialize for SerializableQFrame<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let name = frame_name(self.0);
        match self.0 {
            QFrame::Data { payload } => {
                let mut state = serializer.serialize_struct(name, 2)?;
                serialize_payload(&mut state, payload)?;
                state.end()
            },
            QFrame::Headers { header_block } => {
                let mut state = serializer.serialize_struct(name, 1)?;
                state.serialize_field("header_block_len", &header_block.len())?;
                state.end()
            },
            QFrame::CancelPush { push_id } | QFrame::MaxPushId { push_id } => {
                let mut state = serializer.serialize_struct(name, 1)?;
                state.serialize_field("push_id", push_id)?;
                state.end()
            },
            QFrame::Settings {
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                connect_protocol_enabled,
                h3_datagram,
                additional_settings,
                ..
            } => {
                let mut state = serializer.serialize_struct(name, 6)?;
                state.serialize_field(
                    "max_field_section_size",
                    max_field_section_size,
                )?;
                state.serialize_field(
                    "qpack_max_table_capacity",
                    qpack_max_table_capacity,
                )?;
                state.serialize_field(
                    "qpack_blocked_streams",
                    qpack_blocked_streams,
                )?;
                state.serialize_field(
                    "connect_protocol_enabled",
                    connect_protocol_enabled,
                )?;
                state.serialize_field("h3_datagram", h3_datagram)?;
                state.serialize_field(
                    "additional_settings",
                    additional_settings,
                )?;
                state.end()
            },
            QFrame::PushPromise {
                push_id,
                header_block,
            } => {
                let mut state = serializer.serialize_struct(name, 2)?;
                state.serialize_field("push_id", push_id)?;
                state.serialize_field("header_block_len", &header_block.len())?;
                state.end()
            },
            QFrame::GoAway { id } => {
                let mut state = serializer.serialize_struct(name, 1)?;
                state.serialize_field("id", id)?;
                state.end()
            },
            QFrame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } |
            QFrame::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => {
                let mut state = serializer.serialize_struct(name, 3)?;
                serialize_priority(
                    &mut state,
                    *prioritized_element_id,
                    priority_field_value,
                )?;
                state.end()
            },
            QFrame::Unknown { raw_type, payload } => {
                let mut state = serializer.serialize_struct(name, 3)?;
                state.serialize_field("raw_type", raw_type)?;
                serialize_payload(&mut state, payload)?;
                state.end()
            },
        }
    }
}

type CustomEquivalenceHandler = dyn Fn(&H3iFrame) -> bool + Send + Sync + 'static;

#[derive(Clone)]
enum Comparator {
    Frame(H3iFrame),
    /// Specifies how to compare an incoming [`H3iFrame`] with this
    /// [`CloseTriggerFrame`]. Typically, the validation attempts to fuzzy-match
    /// the [`CloseTriggerFrame`] against the incoming [`H3iFrame`], but there
    /// are times where other behavior is desired (for example, checking
    /// deserialized JSON payloads in a headers frame, or ensuring a random
    /// value matches a regex).
    ///
    /// See [`CloseTriggerFrame::is_equivalent`] for more on how frames are
    /// compared.
    Fn(Arc<CustomEquivalenceHandler>),
}

impl Serialize for Comparator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Fn(_) => serializer.serialize_str("<comparator_fn>"),
            Self::Frame(f) => {
                let mut frame_ser = serializer.serialize_struct("frame", 1)?;
                frame_ser.serialize_field("frame", f)?;
                frame_ser.end()
            },
        }
    }
}

/// Instructs h3i to watch for certain incoming [`H3iFrame`]s. The incoming
/// frames can either be supplied directly via [`CloseTriggerFrame::new`], or
/// via a verification callback  passed to
/// [`CloseTriggerFrame::new_with_comparator`].
#[derive(Serialize, Clone)]
pub struct CloseTriggerFrame {
    stream_id: u64,
    comparator: Comparator,
}

impl CloseTriggerFrame {
    /// Create a new [`CloseTriggerFrame`] which should watch for the provided
    /// [`H3iFrame`].
    ///
    /// # Note
    ///
    /// For [`QuicheH3`] and [`ResetStream`] variants, equivalence is the same
    /// as equality.
    ///
    /// For Headers variants, this [`CloseTriggerFrame`] is equivalent to the
    /// incoming [`H3iFrame`] if the [`H3iFrame`] contains all [`Header`]s
    /// in _this_ frame. In other words, `this` can be considered equivalent
    /// to `other` if `other` contains a superset of `this`'s [`Header`]s.
    ///
    /// This allows users for fuzzy-matching on header frames without needing to
    /// supply every individual header on the frame.
    ///
    /// [`ResetStream`]: H3iFrame::ResetStream
    /// [`QuicheH3`]: H3iFrame::QuicheH3
    #[must_use = "creates a trigger for the supplied stream"]
    pub const fn new(stream_id: u64, frame: H3iFrame) -> Self {
        Self {
            stream_id,
            comparator: Comparator::Frame(frame),
        }
    }

    /// Create a new [`CloseTriggerFrame`] which will match incoming
    /// [`H3iFrame`]s according to the passed `comparator_fn`.
    ///
    /// The `comparator_fn` will be called with every incoming [`H3iFrame`]. It
    /// should return `true` if the incoming frame is expected, and `false`
    /// if it is not.
    #[must_use = "creates a trigger using the provided predicate"]
    pub fn new_with_comparator<F>(stream_id: u64, comparator_fn: F) -> Self
    where
        F: Fn(&H3iFrame) -> bool + Send + Sync + 'static,
    {
        Self {
            stream_id,
            comparator: Comparator::Fn(Arc::new(comparator_fn)),
        }
    }

    pub(crate) const fn stream_id(&self) -> u64 {
        self.stream_id
    }

    pub(crate) fn is_equivalent(&self, other: &H3iFrame) -> bool {
        let frame = match &self.comparator {
            Comparator::Fn(compare) => return compare(other),
            Comparator::Frame(frame) => frame,
        };

        match (frame, other) {
            (H3iFrame::Headers(expected), H3iFrame::Headers(received)) =>
                received.contains_headers(expected),
            _ => frame == other,
        }
    }
}

impl Debug for CloseTriggerFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match &self.comparator {
            Comparator::Frame(frame) => format!("{frame:?}"),
            Comparator::Fn(_) => "closure".to_string(),
        };

        write!(
            f,
            "CloseTriggerFrame {{ stream_id: {}, comparator: {repr} }}",
            self.stream_id
        )
    }
}

impl PartialEq for CloseTriggerFrame {
    fn eq(&self, other: &Self) -> bool {
        self.stream_id == other.stream_id &&
            match (&self.comparator, &other.comparator) {
                (Comparator::Frame(a), Comparator::Frame(b)) => a == b,
                (Comparator::Fn(a), Comparator::Fn(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }
}

impl Eq for CloseTriggerFrame {}

#[cfg(test)]
mod tests {
    use super::BoxError;
    use super::CloseTriggerFrame;
    use super::EnrichedHeaders;
    use super::H3iFrame;
    use super::ResetStream;
    use crate::quiche;
    use quiche::h3::frame::Frame;
    use quiche::h3::Header;

    fn headers(fields: &[(&[u8], &[u8])]) -> Result<H3iFrame, BoxError> {
        Ok(H3iFrame::try_from(
            fields
                .iter()
                .map(|(name, value)| Header::new(name, value))
                .collect::<Vec<_>>(),
        )?)
    }

    #[test]
    fn decoded_header_block_preserves_original_wire_representation(
    ) -> Result<(), BoxError> {
        let headers = vec![
            Header::new(b":status", b"200"),
            Header::new(b"x-test", b"test"),
        ];
        let literal = crate::encode_header_block_literal(&headers)?;
        let compressed = crate::encode_header_block(&headers)?;
        assert_ne!(literal, compressed);
        let enriched = EnrichedHeaders::from_wire(literal.clone())?;
        let decoded = EnrichedHeaders::try_from(Frame::Headers {
            header_block: compressed.clone(),
        })?;
        assert_eq!(enriched.header_block(), literal);
        assert_eq!(decoded.header_block(), compressed);
        assert_eq!(enriched.headers(), headers);
        assert_eq!(decoded.headers(), headers);
        assert_eq!(enriched, decoded);
        Ok(())
    }

    #[test]
    fn header_trigger_matches_multiset_without_requiring_order(
    ) -> Result<(), BoxError> {
        let trigger = CloseTriggerFrame::new(
            0,
            headers(&[(b"hello", b"world"), (b"go", b"jets"), (b"go", b"jets")])?,
        );
        let match_frame = headers(&[
            (b"go", b"jets"),
            (b"go", b"devils"),
            (b"hello", b"world"),
            (b"go", b"jets"),
        ])?;
        let missing_duplicate = headers(&[
            (b"hello", b"world"),
            (b"go", b"jets"),
            (b"go", b"devils"),
        ])?;
        assert!(trigger.is_equivalent(&match_frame));
        let decoded = match_frame
            .as_enriched_headers()
            .ok_or("expected headers")?;
        assert_eq!(decoded.header_values(b"go").collect::<Vec<_>>(), [
            b"jets".as_slice(),
            b"devils".as_slice(),
            b"jets".as_slice()
        ]);
        assert_eq!(decoded.header_values(b"absent").next(), None);
        assert!(!trigger.is_equivalent(&missing_duplicate));
        assert!(!trigger.is_equivalent(
            &Frame::Data {
                payload: Vec::new()
            }
            .into()
        ));
        let empty = CloseTriggerFrame::new(0, headers(&[])?);
        assert!(empty.is_equivalent(&match_frame));
        assert!(empty.is_equivalent(&headers(&[])?));
        Ok(())
    }

    #[test]
    fn data_and_reset_triggers_require_exact_equality() {
        let frames = [
            (
                H3iFrame::ResetStream(ResetStream {
                    stream_id: 0,
                    error_code: 57,
                }),
                H3iFrame::ResetStream(ResetStream {
                    stream_id: 57,
                    error_code: 57,
                }),
            ),
            (
                Frame::Data {
                    payload: b"57".to_vec(),
                }
                .into(),
                Frame::Data {
                    payload: b"go jets".to_vec(),
                }
                .into(),
            ),
        ];
        for (expected, different) in frames {
            let trigger = CloseTriggerFrame::new(0, expected.clone());
            assert!(trigger.is_equivalent(&expected));
            assert!(!trigger.is_equivalent(&different));
        }
    }

    #[test]
    fn comparator_can_borrow_headers_and_has_identity_equality(
    ) -> Result<(), BoxError> {
        let trigger = CloseTriggerFrame::new_with_comparator(0, |frame| {
            frame
                .as_enriched_headers()
                .and_then(|headers| headers.header_values(b"cookie").next())
                .and_then(|value| std::str::from_utf8(value).ok())
                .is_some_and(|value| value.to_lowercase().contains("cookie"))
        });
        assert_eq!(trigger, trigger.clone());
        assert_ne!(trigger, CloseTriggerFrame::new_with_comparator(0, |_| true));
        assert!(trigger
            .is_equivalent(&headers(&[(b"cookie", b"SomeRandomCookie1234")])?));
        assert!(!trigger.is_equivalent(&headers(&[(b"cookie", &[255])])?));
        Ok(())
    }

    #[test]
    fn serialization_keeps_frame_names_and_bounded_payloads(
    ) -> Result<(), BoxError> {
        let data = H3iFrame::from(Frame::Data {
            payload: vec![0x57; super::MAX_SERIALIZED_BUFFER_LEN + 1],
        });
        let unknown = H3iFrame::from(Frame::Unknown {
            raw_type: 123,
            payload: vec![0x57; super::MAX_SERIALIZED_BUFFER_LEN + 1],
        });
        let data = serde_json::to_value(data)?;
        let unknown = serde_json::to_value(unknown)?;
        assert_eq!(data["DATA"]["payload"], unknown["UNKNOWN"]["payload"]);
        assert_eq!(
            data["DATA"]["payload_len"],
            super::MAX_SERIALIZED_BUFFER_LEN + 1
        );
        assert_eq!(
            data["DATA"]["payload"].as_str().map(str::len),
            Some(2 * super::MAX_SERIALIZED_BUFFER_LEN)
        );
        assert_eq!(unknown["UNKNOWN"]["raw_type"], 123);
        Ok(())
    }
}
