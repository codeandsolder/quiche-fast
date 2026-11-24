// Copyright (C) 2018-2025, Cloudflare, Inc.
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

//! Transport parameters handling as per RFC 9000 Section 7.4
//! Part of the Cryptographic and Transport Handshake

use std::collections::HashSet;
use std::mem::size_of;

use crate::ConnectionId;
use crate::Error;
use crate::Result;
use crate::MAX_CONN_ID_LEN;
use crate::MAX_STREAM_COUNT;

#[cfg(feature = "qlog")]
use crate::crypto;
#[cfg(feature = "qlog")]
use qlog::events::quic::TransportInitiator;
#[cfg(feature = "qlog")]
use qlog::events::EventData;

/// Maximum permitted value of the `ack_delay_exponent` transport parameter,
/// as mandated by RFC 9000 Section 18.2.
pub const MAX_ACK_DELAY_EXPONENT: u64 = 20;

pub const MAX_ACK_DELAY: u64 = (1 << 14) - 1;
pub const MIN_UDP_PAYLOAD_SIZE: u64 = 1200;
const DEFAULT_UDP_PAYLOAD_SIZE: u64 = 65527;
const DEFAULT_ACK_DELAY_EXPONENT: u64 = 3;
const DEFAULT_MAX_ACK_DELAY: u64 = 25;

/// QUIC Unknown Transport Parameter.
///
/// A QUIC transport parameter that is not specifically recognized
/// by this implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownTransportParameter<T> {
    /// The ID of the unknown transport parameter.
    pub id: u64,

    /// Original data representing the value of the unknown transport parameter.
    pub value: T,
}

impl<T> UnknownTransportParameter<T> {
    /// Checks whether an unknown Transport Parameter's ID is in the reserved
    /// space.
    ///
    /// See Section 18.1 in [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000#name-reserved-transport-paramete).
    pub const fn is_reserved(&self) -> bool {
        self.id >= 27 && (self.id - 27).is_multiple_of(31)
    }
}

#[cfg(feature = "qlog")]
impl<T: AsRef<[u8]>> From<&UnknownTransportParameter<T>>
    for qlog::events::quic::UnknownTransportParameter
{
    fn from(value: &UnknownTransportParameter<T>) -> Self {
        Self {
            id: value.id,
            value: qlog::HexSlice::new(&value.value).to_string(),
        }
    }
}

/// Track unknown transport parameters, up to a limit.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct UnknownTransportParameters {
    /// The space remaining for storing unknown transport parameters.
    remaining_capacity: usize,
    /// The unknown transport parameters.
    parameters: Vec<UnknownTransportParameter<Vec<u8>>>,
}

impl UnknownTransportParameters {
    /// Create an empty tracker with the given byte budget.
    #[must_use = "the returned tracker enforces the requested byte budget"]
    pub const fn new(capacity: usize) -> Self {
        Self {
            remaining_capacity: capacity,
            parameters: Vec::new(),
        }
    }

    /// Number of bytes still available for parameter IDs and values.
    #[must_use = "reading the budget does not change it"]
    pub const fn remaining_capacity(&self) -> usize {
        self.remaining_capacity
    }

    /// Iterate over the recorded parameters in wire order.
    pub fn iter(
        &self,
    ) -> std::slice::Iter<'_, UnknownTransportParameter<Vec<u8>>> {
        self.parameters.iter()
    }

    /// Pushes an unknown transport parameter into storage if there is space
    /// remaining.
    ///
    /// # Errors
    ///
    /// Returns `Error::BufferTooShort` if the parameter plus its identifier
    /// exceeds the remaining tracking capacity or storage cannot be reserved.
    pub fn push(&mut self, new: UnknownTransportParameter<&[u8]>) -> Result<()> {
        let cost = new
            .value
            .len()
            .checked_add(size_of::<u64>())
            .ok_or(Error::BufferTooShort)?;
        let remaining = self
            .remaining_capacity
            .checked_sub(cost)
            .ok_or(Error::BufferTooShort)?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(new.value.len())
            .map_err(|_| Error::BufferTooShort)?;
        self.parameters
            .try_reserve(1)
            .map_err(|_| Error::BufferTooShort)?;
        value.extend_from_slice(new.value);
        self.parameters
            .push(UnknownTransportParameter { id: new.id, value });
        self.remaining_capacity = remaining;
        Ok(())
    }
}

impl<'a> IntoIterator for &'a UnknownTransportParameters {
    type IntoIter = std::slice::Iter<'a, UnknownTransportParameter<Vec<u8>>>;
    type Item = &'a UnknownTransportParameter<Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// QUIC Transport Parameters
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportParams {
    /// Value of Destination CID field from first Initial packet sent by client
    pub original_destination_connection_id: Option<ConnectionId<'static>>,
    /// The maximum idle timeout.
    pub max_idle_timeout: u64,
    /// Token used for verifying stateless resets
    pub stateless_reset_token: Option<u128>,
    /// The maximum UDP payload size.
    pub max_udp_payload_size: u64,
    /// The initial flow control maximum data for the connection.
    pub initial_max_data: u64,
    /// The initial flow control maximum data for local bidirectional streams.
    pub initial_max_stream_data_bidi_local: u64,
    /// The initial flow control maximum data for remote bidirectional streams.
    pub initial_max_stream_data_bidi_remote: u64,
    /// The initial flow control maximum data for unidirectional streams.
    pub initial_max_stream_data_uni: u64,
    /// The initial maximum bidirectional streams.
    pub initial_max_streams_bidi: u64,
    /// The initial maximum unidirectional streams.
    pub initial_max_streams_uni: u64,
    /// The ACK delay exponent.
    pub ack_delay_exponent: u64,
    /// The max ACK delay.
    pub max_ack_delay: u64,
    /// Whether active migration is disabled.
    pub disable_active_migration: bool,
    /// The active connection ID limit.
    pub active_conn_id_limit: u64,
    /// The value that the endpoint included in the Source CID field of a Retry
    /// Packet.
    pub initial_source_connection_id: Option<ConnectionId<'static>>,
    /// The value that the server included in the Source CID field of a Retry
    /// Packet.
    pub retry_source_connection_id: Option<ConnectionId<'static>>,
    /// DATAGRAM frame extension parameter, if any.
    pub max_datagram_frame_size: Option<u64>,
    /// Unknown peer transport parameters and values, if any.
    pub unknown_params: Option<UnknownTransportParameters>,
    // pub preferred_address: ...,
}

impl Default for TransportParams {
    fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            max_idle_timeout: 0,
            stateless_reset_token: None,
            max_udp_payload_size: DEFAULT_UDP_PAYLOAD_SIZE,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: DEFAULT_ACK_DELAY_EXPONENT,
            max_ack_delay: DEFAULT_MAX_ACK_DELAY,
            disable_active_migration: false,
            active_conn_id_limit: 2,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            max_datagram_frame_size: None,
            unknown_params: Option::default(),
        }
    }
}

// The length of the parameter is separate from the varint width. A known
// integer parameter must contain exactly one varint, even when represented
// using a non-minimal varint width.
fn decode_integer(bytes: &[u8]) -> Result<u64> {
    let mut value = octets::Octets::with_slice(bytes);
    let v = value
        .get_varint()
        .map_err(|_| Error::InvalidTransportParam)?;
    if value.cap() != 0 {
        return Err(Error::InvalidTransportParam);
    }
    Ok(v)
}

/// Decode a connection ID only after checking its wire length.
fn decode_cid(value: &[u8]) -> Result<ConnectionId<'static>> {
    if value.len() > MAX_CONN_ID_LEN {
        return Err(Error::InvalidTransportParam);
    }
    Ok(ConnectionId::copy_from_slice(value))
}

/// Validate the preferred-address layout even though migration to a
/// preferred address is not implemented.
fn validate_preferred_address(bytes: &[u8]) -> Result<()> {
    const ADDRESS_BYTES: usize = 4 + 2 + 16 + 2;
    const FIXED_BYTES: usize = ADDRESS_BYTES + 1 + 16;
    let cid_len = usize::from(
        *bytes
            .get(ADDRESS_BYTES)
            .ok_or(Error::InvalidTransportParam)?,
    );
    if !(1..=MAX_CONN_ID_LEN).contains(&cid_len) ||
        bytes.len() != FIXED_BYTES + cid_len
    {
        return Err(Error::InvalidTransportParam);
    }
    Ok(())
}

impl TransportParams {
    fn validate(&self) -> Result<()> {
        for (value, min, max) in [
            (self.max_idle_timeout, 0, octets::MAX_VAR_INT),
            (
                self.max_udp_payload_size,
                MIN_UDP_PAYLOAD_SIZE,
                octets::MAX_VAR_INT,
            ),
            (self.initial_max_data, 0, octets::MAX_VAR_INT),
            (
                self.initial_max_stream_data_bidi_local,
                0,
                octets::MAX_VAR_INT,
            ),
            (
                self.initial_max_stream_data_bidi_remote,
                0,
                octets::MAX_VAR_INT,
            ),
            (self.initial_max_stream_data_uni, 0, octets::MAX_VAR_INT),
            (self.initial_max_streams_bidi, 0, MAX_STREAM_COUNT),
            (self.initial_max_streams_uni, 0, MAX_STREAM_COUNT),
            (self.ack_delay_exponent, 0, MAX_ACK_DELAY_EXPONENT),
            (self.max_ack_delay, 0, MAX_ACK_DELAY),
            (self.active_conn_id_limit, 2, octets::MAX_VAR_INT),
        ] {
            if !(min..=max).contains(&value) {
                return Err(Error::InvalidTransportParam);
            }
        }
        if self
            .max_datagram_frame_size
            .is_some_and(|v| v > octets::MAX_VAR_INT)
        {
            return Err(Error::InvalidTransportParam);
        }
        for cid in [
            &self.original_destination_connection_id,
            &self.initial_source_connection_id,
            &self.retry_source_connection_id,
        ]
        .into_iter()
        .flatten()
        {
            if cid.len() > MAX_CONN_ID_LEN {
                return Err(Error::InvalidTransportParam);
            }
        }
        Ok(())
    }

    pub(crate) fn decode(
        buf: &[u8], is_server: bool, unknown_size: Option<usize>,
    ) -> Result<Self> {
        let mut params = octets::Octets::with_slice(buf);
        let mut seen_small = 0_u64;
        let mut seen_large = HashSet::new();
        let mut tp = Self {
            unknown_params: unknown_size.map(UnknownTransportParameters::new),
            ..Self::default()
        };

        while params.cap() > 0 {
            let id = params
                .get_varint()
                .map_err(|_| Error::InvalidTransportParam)?;
            // The usual transport parameter IDs fit into a single word.
            // Larger extension IDs still participate in global duplicate
            // detection, even when unknown parameter tracking is disabled.
            if id < u64::from(u64::BITS) {
                let bit = 1_u64 << id;
                if seen_small & bit != 0 {
                    return Err(Error::InvalidTransportParam);
                }
                seen_small |= bit;
            } else {
                seen_large
                    .try_reserve(1)
                    .map_err(|_| Error::InvalidTransportParam)?;
                if !seen_large.insert(id) {
                    return Err(Error::InvalidTransportParam);
                }
            }

            let value = params
                .get_bytes_with_varint_length()
                .map_err(|_| Error::InvalidTransportParam)?;
            tp.decode_parameter(id, value.buf(), is_server)?;
        }

        tp.validate()?;
        Ok(tp)
    }

    /// Decode one parameter value, applying the sender role and its wire
    /// schema.
    fn decode_parameter(
        &mut self, id: u64, value: &[u8], is_server: bool,
    ) -> Result<()> {
        // Parameters that can only be received from a server.
        if is_server && matches!(id, 0x0000 | 0x0002 | 0x000d | 0x0010) {
            return Err(Error::InvalidTransportParam);
        }
        match id {
            0x0000 =>
                self.original_destination_connection_id = Some(decode_cid(value)?),
            0x0001 => self.max_idle_timeout = decode_integer(value)?,
            0x0002 =>
                self.stateless_reset_token = Some(u128::from_be_bytes(
                    value.try_into().map_err(|_| Error::InvalidTransportParam)?,
                )),
            0x0003 => self.max_udp_payload_size = decode_integer(value)?,
            0x0004 => self.initial_max_data = decode_integer(value)?,
            0x0005 =>
                self.initial_max_stream_data_bidi_local = decode_integer(value)?,
            0x0006 =>
                self.initial_max_stream_data_bidi_remote = decode_integer(value)?,
            0x0007 => self.initial_max_stream_data_uni = decode_integer(value)?,
            0x0008 => self.initial_max_streams_bidi = decode_integer(value)?,
            0x0009 => self.initial_max_streams_uni = decode_integer(value)?,
            0x000a => self.ack_delay_exponent = decode_integer(value)?,
            0x000b => self.max_ack_delay = decode_integer(value)?,
            0x000c => {
                if !value.is_empty() {
                    return Err(Error::InvalidTransportParam);
                }
                self.disable_active_migration = true;
            },
            0x000d => validate_preferred_address(value)?,
            0x000e => self.active_conn_id_limit = decode_integer(value)?,
            0x000f =>
                self.initial_source_connection_id = Some(decode_cid(value)?),
            0x0010 => self.retry_source_connection_id = Some(decode_cid(value)?),
            0x0020 => self.max_datagram_frame_size = Some(decode_integer(value)?),
            _ => {
                if let Some(unknown) = &mut self.unknown_params {
                    // Tracking is optional and can be exhausted without
                    // invalidating an otherwise valid peer parameter.
                    let _ = unknown.push(UnknownTransportParameter { id, value });
                }
            },
        }
        Ok(())
    }

    pub(crate) fn encode_param(
        b: &mut octets::OctetsMut, ty: u64, len: usize,
    ) -> Result<()> {
        b.put_varint(ty)?;
        b.put_varint(len as u64)?;

        Ok(())
    }

    fn encode_integer(b: &mut octets::OctetsMut, id: u64, v: u64) -> Result<()> {
        Self::encode_param(b, id, octets::varint_len(v))?;
        b.put_varint(v)?;
        Ok(())
    }

    pub(crate) fn encode<'a>(
        tp: &Self, is_server: bool, out: &'a mut [u8],
    ) -> Result<&'a mut [u8]> {
        tp.validate()?;
        let mut b = octets::OctetsMut::with_slice(out);

        if is_server {
            if let Some(odcid) = &tp.original_destination_connection_id {
                Self::encode_param(&mut b, 0x0000, odcid.len())?;
                b.put_bytes(odcid)?;
            }
        }

        if tp.max_idle_timeout != 0 {
            Self::encode_integer(&mut b, 0x0001, tp.max_idle_timeout)?;
        }

        if is_server {
            if let Some(token) = tp.stateless_reset_token {
                Self::encode_param(&mut b, 0x0002, 16)?;
                b.put_bytes(&token.to_be_bytes())?;
            }
        }

        Self::encode_integer(&mut b, 0x0003, tp.max_udp_payload_size)?;
        for (id, value) in [
            (0x0004, tp.initial_max_data),
            (0x0005, tp.initial_max_stream_data_bidi_local),
            (0x0006, tp.initial_max_stream_data_bidi_remote),
            (0x0007, tp.initial_max_stream_data_uni),
            (0x0008, tp.initial_max_streams_bidi),
            (0x0009, tp.initial_max_streams_uni),
        ] {
            if value != 0 {
                Self::encode_integer(&mut b, id, value)?;
            }
        }
        // Explicit zero differs from the peer's default of 3 or 25.
        Self::encode_integer(&mut b, 0x000a, tp.ack_delay_exponent)?;
        Self::encode_integer(&mut b, 0x000b, tp.max_ack_delay)?;

        if tp.disable_active_migration {
            Self::encode_param(&mut b, 0x000c, 0)?;
        }

        // TODO: encode preferred_address

        if tp.active_conn_id_limit != 2 {
            Self::encode_integer(&mut b, 0x000e, tp.active_conn_id_limit)?;
        }

        if let Some(scid) = &tp.initial_source_connection_id {
            Self::encode_param(&mut b, 0x000f, scid.len())?;
            b.put_bytes(scid)?;
        }

        if is_server {
            if let Some(scid) = &tp.retry_source_connection_id {
                Self::encode_param(&mut b, 0x0010, scid.len())?;
                b.put_bytes(scid)?;
            }
        }

        if let Some(max_datagram_frame_size) = tp.max_datagram_frame_size {
            Self::encode_integer(&mut b, 0x0020, max_datagram_frame_size)?;
        }

        let out_len = b.off();

        Ok(&mut out[..out_len])
    }

    /// Creates a qlog event for connection transport parameters and TLS fields
    #[cfg(feature = "qlog")]
    pub fn to_qlog(
        &self, initiator: TransportInitiator, cipher: Option<crypto::Algorithm>,
    ) -> EventData {
        let original_destination_connection_id = qlog::HexSlice::maybe_string(
            self.original_destination_connection_id.as_ref(),
        );

        let stateless_reset_token = qlog::HexSlice::maybe_string(
            self.stateless_reset_token.map(u128::to_be_bytes).as_ref(),
        );

        let tls_cipher: Option<String> = cipher.map(|f| format!("{f:?}"));

        EventData::QuicParametersSet(Box::new(
            qlog::events::quic::ParametersSet {
                initiator: Some(initiator),
                tls_cipher,
                original_destination_connection_id,
                stateless_reset_token,
                disable_active_migration: Some(self.disable_active_migration),
                max_idle_timeout: Some(self.max_idle_timeout),
                max_udp_payload_size: Some(self.max_udp_payload_size),
                ack_delay_exponent: Some(self.ack_delay_exponent),
                max_ack_delay: Some(self.max_ack_delay),
                active_connection_id_limit: Some(self.active_conn_id_limit),

                initial_max_data: Some(self.initial_max_data),
                initial_max_stream_data_bidi_local: Some(
                    self.initial_max_stream_data_bidi_local,
                ),
                initial_max_stream_data_bidi_remote: Some(
                    self.initial_max_stream_data_bidi_remote,
                ),
                initial_max_stream_data_uni: Some(
                    self.initial_max_stream_data_uni,
                ),
                initial_max_streams_bidi: Some(self.initial_max_streams_bidi),
                initial_max_streams_uni: Some(self.initial_max_streams_uni),

                unknown_parameters: self
                    .unknown_params
                    .iter()
                    .flat_map(UnknownTransportParameters::iter)
                    .map(Into::into)
                    .collect(),

                ..Default::default()
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_parameter_reservation_and_exact_capacity() {
        for id in 0u64..100 {
            let param = UnknownTransportParameter {
                id,
                value: &b"abc"[..],
            };
            assert_eq!(param.is_reserved(), matches!(id, 27 | 58 | 89));
        }
        let mut tracked = UnknownTransportParameters::new(11);
        let param = UnknownTransportParameter {
            id: 17,
            value: &b"abc"[..],
        };
        assert_eq!(tracked.push(param), Ok(()));
        assert_eq!(tracked.remaining_capacity(), 0);
        assert_eq!(tracked.push(param), Err(Error::BufferTooShort));
        assert_eq!(tracked.iter().len(), 1);
        assert_eq!(tracked.into_iter().len(), 1);
    }

    #[test]
    fn duplicate_parameter_ids_across_width_classes(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        for id in [17, 27, 58, 63, 64, 1 << 14, octets::MAX_VAR_INT] {
            let mut wire = [0; 32];
            let mut writer = octets::OctetsMut::with_slice(&mut wire);
            writer.put_varint(id)?;
            writer.put_varint(0)?;
            let first = writer.off();
            writer.put_varint_with_len(id, 8)?;
            writer.put_varint(0)?;
            let end = writer.off();
            for tracking in [None, Some(0), Some(16)] {
                assert!(TransportParams::decode(&wire[..first], false, tracking)
                    .is_ok());
                assert_eq!(
                    TransportParams::decode(&wire[..end], false, tracking),
                    Err(Error::InvalidTransportParam)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn malformed_parameter_envelopes_have_transport_parameter_error() {
        for wire in [
            &[0x40][..],
            &[0x11][..],
            &[0x11, 0x40][..],
            &[0x11, 2, 0][..],
        ] {
            assert_eq!(
                TransportParams::decode(wire, false, None),
                Err(Error::InvalidTransportParam)
            );
        }
    }

    #[test]
    fn stateless_reset_token_requires_exact_length(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut underlong = vec![0x02, 0x0f];
        underlong.extend_from_slice(&[0xba; 15]);

        assert!(matches!(
            TransportParams::decode(&underlong, false, None),
            Err(Error::InvalidTransportParam)
        ));

        let mut overlong = vec![0x02, 0x11];
        overlong.extend_from_slice(&[0xba; 17]);

        assert!(matches!(
            TransportParams::decode(&overlong, false, None),
            Err(Error::InvalidTransportParam)
        ));

        let mut exact = vec![0x02, 0x10];
        exact.extend_from_slice(&[0xba; 16]);

        let decoded = TransportParams::decode(&exact, false, None)?;
        assert_eq!(
            decoded.stateless_reset_token,
            Some(u128::from_be_bytes([0xba; 16]))
        );
        Ok(())
    }
}
