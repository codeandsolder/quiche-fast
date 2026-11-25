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

use datagram_socket::DgramBuffer;
use quiche::h3::NameValue;
use quiche::h3::{
    self,
};

use crate::quic::QuicheConnection;
use tokio::sync::mpsc;

/// RFC 9297, sections 2 and 2.1.
pub(super) const DATAGRAM_ERROR: u64 = 0x33;
const MAX_QUARTER_STREAM_ID: u64 = octets::MAX_VAR_INT / 4;

/// A local application handle bound to one HTTP request stream.
///
/// Datagram submissions are best effort: queue acceptance does not guarantee
/// transmission or delivery. A closed stream can never be reopened through
/// a retained handle, because QUIC stream IDs are not reused.
#[derive(Clone, Debug)]
pub struct DatagramFlowSender {
    stream_id: u64,
    data: mpsc::Sender<FlowDatagram>,
    shutdown: mpsc::UnboundedSender<u64>,
}

#[derive(Debug)]
pub(super) struct FlowDatagram {
    pub(super) stream_id: u64,
    pub(super) payload: DgramBuffer,
}

impl DatagramFlowSender {
    pub(super) const fn new(
        stream_id: u64, data: mpsc::Sender<FlowDatagram>,
        shutdown: mpsc::UnboundedSender<u64>,
    ) -> Self {
        Self {
            stream_id,
            data,
            shutdown,
        }
    }

    /// The request stream that owns this datagram flow.
    #[must_use = "the stream ID identifies the associated HTTP request"]
    pub const fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Enqueues a datagram without waiting for shared queue capacity.
    ///
    /// # Errors
    /// Returns the original payload if the connection queue is full or closed.
    pub fn try_send(
        &self, payload: DgramBuffer,
    ) -> Result<(), mpsc::error::TrySendError<DgramBuffer>> {
        let permit = match self.data.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) =>
                return Err(mpsc::error::TrySendError::Full(payload)),
            Err(mpsc::error::TrySendError::Closed(())) =>
                return Err(mpsc::error::TrySendError::Closed(payload)),
        };
        permit.send(FlowDatagram {
            stream_id: self.stream_id,
            payload,
        });
        Ok(())
    }

    /// Waits for capacity in the shared outbound datagram queue.
    ///
    /// # Errors
    /// Returns the original payload if the connection worker has stopped.
    pub async fn send(
        &self, payload: DgramBuffer,
    ) -> Result<(), mpsc::error::SendError<DgramBuffer>> {
        let Ok(permit) = self.data.reserve().await else {
            return Err(mpsc::error::SendError(payload));
        };
        permit.send(FlowDatagram {
            stream_id: self.stream_id,
            payload,
        });
        Ok(())
    }

    /// Requests closure of the associated stream. The independent control
    /// queue is not blocked by a saturated datagram queue.
    ///
    /// # Errors
    /// Returns an error if the connection worker has stopped.
    pub fn shutdown(&self) -> Result<(), mpsc::error::SendError<()>> {
        self.shutdown
            .send(self.stream_id)
            .map_err(|_| mpsc::error::SendError(()))
    }
}

/// Extended CONNECT explicitly associates extension semantics with the request.
/// The application decides which extensions it supports; ordinary CONNECT,
/// GET, and POST requests do not establish HTTP datagram flows.
pub(super) fn is_extended_connect(headers: &[h3::Header]) -> bool {
    let mut method = None;
    let mut protocol = None;
    for header in headers {
        match header.name() {
            b":method" => method = Some(header.value()),
            b":protocol" => protocol = Some(header.value()),
            _ => {},
        }
    }
    method == Some(b"CONNECT") && protocol.is_some_and(|value| !value.is_empty())
}

/// Sends an HTTP/3 datagram over the QUIC connection with the given
/// `quarter_stream_id`.
#[inline]
pub(super) fn send_h3_dgram(
    conn: &mut QuicheConnection, quarter_stream_id: u64, dgram: DgramBuffer,
) -> quiche::Result<()> {
    conn.dgram_send_buf(h3_dgram_add_quarter_stream_id(quarter_stream_id, dgram)?)
}

/// Prepend the `quarter_stream_id` to `dgram`
fn h3_dgram_add_quarter_stream_id(
    quarter_stream_id: u64, mut dgram: DgramBuffer,
) -> quiche::Result<DgramBuffer> {
    if quarter_stream_id > MAX_QUARTER_STREAM_ID {
        return Err(quiche::Error::InvalidFrame);
    }
    let mut prefix_buf = [0u8; 8];
    let mut enc = octets::OctetsMut::with_slice(&mut prefix_buf);
    let prefix = enc.put_varint(quarter_stream_id)?;

    dgram.prepend(prefix);
    Ok(dgram)
}

/// Strips the varint-encoded quarter stream ID from the front of `dgram` and
/// returns `(quarter_stream_id, dgram)` with the cursor advanced past the
/// prefix.
fn h3_dgram_remove_quarter_stream_id(
    mut dgram: DgramBuffer,
) -> quiche::Result<(u64, DgramBuffer)> {
    let mut b = octets::Octets::with_slice(dgram.as_slice());
    let quarter_stream_id = b.get_varint()?;
    if quarter_stream_id > MAX_QUARTER_STREAM_ID {
        return Err(quiche::Error::InvalidFrame);
    }
    // Advance the cursor past the varint prefix — zero copy.
    let advance = b.off();
    dgram.advance(advance);
    Ok((quarter_stream_id, dgram))
}

/// Reads the next HTTP/3 datagram from the QUIC connection.
///
/// [`quiche::Error::Done`] is returned if there is no datagram to read.
#[inline]
pub(super) fn receive_h3_dgram(
    conn: &mut QuicheConnection,
) -> quiche::Result<(u64, DgramBuffer)> {
    let dgram = conn.dgram_recv_buf()?;
    let (quarter_stream_id, dgram) = h3_dgram_remove_quarter_stream_id(dgram)?;
    Ok((quarter_stream_id * 4, dgram))
}

/// Discard datagrams queued in transport before the request's send half closed.
pub(super) fn purge_stream_datagrams(
    conn: &mut QuicheConnection, stream_id: u64,
) {
    let quarter_stream_id = stream_id / 4;
    conn.dgram_purge_outgoing(|payload| {
        octets::Octets::with_slice(payload).get_varint() == Ok(quarter_stream_id)
    });
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;
    use datagram_socket::DgramBuffer;

    use super::*;

    #[test]
    fn h3_dgram_add_quarter_stream_id_enough_headroom() -> quiche::Result<()> {
        let mut dgram = DgramBuffer::with_capacity_and_headroom(16, 8);
        dgram.put_slice(&[0xaa, 0xbb, 0xcc]);

        // 67 requires two bytes to encode
        let result = h3_dgram_add_quarter_stream_id(67, dgram)?;
        assert_eq!(result.as_slice(), &[64, 67, 0xaa, 0xbb, 0xcc]);
        Ok(())
    }

    /// When there is no headroom, `splice_headroom` is invoked automatically.
    #[test]
    fn h3_dgram_add_quarter_stream_id_need_more_headroom() -> quiche::Result<()> {
        let dgram = DgramBuffer::from_slice(&[1, 2]);

        // 42 requires a single byte for encoding
        let result = h3_dgram_add_quarter_stream_id(42, dgram)?;
        assert_eq!(result.as_slice(), &[42, 1, 2]);
        Ok(())
    }

    #[test]
    fn h3_dgram_remove_quarter_stream_id_tests() -> quiche::Result<()> {
        let dgram = DgramBuffer::from_slice(&[1, 2, 3, 4]);
        let dgram = h3_dgram_add_quarter_stream_id(67, dgram)?;
        let (quarter_stream_id, rest) = h3_dgram_remove_quarter_stream_id(dgram)?;

        assert_eq!(quarter_stream_id, 67);
        assert_eq!(rest.as_slice(), &[1, 2, 3, 4]);
        Ok(())
    }

    #[test]
    fn h3_dgram_remove_quarter_stream_id_non_minimal_varint() -> quiche::Result<()>
    {
        // Quarter Stream ID = 0 encoded NON-minimally as a 2-byte varint (0x40
        // 0x00), followed by application payload [1, 2, 3, 4].
        // RFC 9000 §16 permits non-minimal encodings; quiche's get_varint()
        // accepts them.
        let dgram = DgramBuffer::from_slice(&[0x40, 0x00, 1, 2, 3, 4]);
        let (qsid, rest) = h3_dgram_remove_quarter_stream_id(dgram)?;
        assert_eq!(qsid, 0);

        assert_eq!(
            rest.as_slice(),
            &[1, 2, 3, 4],
            "leftover non-minimal varint byte leaked into payload prefix"
        );
        Ok(())
    }

    #[test]
    fn every_varint_width_roundtrips_for_each_headroom_size() -> quiche::Result<()>
    {
        let payload = [0xff, 0x01, 0x02];
        for id in [
            0,
            63,
            64,
            16_383,
            16_384,
            (1 << 30) - 1,
            1 << 30,
            MAX_QUARTER_STREAM_ID,
        ] {
            for headroom in 0..=16 {
                let mut dgram =
                    DgramBuffer::with_capacity_and_headroom(32, headroom);
                dgram.put_slice(&payload);
                let encoded = h3_dgram_add_quarter_stream_id(id, dgram)?;
                let (decoded, body) = h3_dgram_remove_quarter_stream_id(encoded)?;
                assert_eq!(decoded, id);
                assert_eq!(body.as_slice(), &payload);
            }
        }
        assert!(h3_dgram_add_quarter_stream_id(
            MAX_QUARTER_STREAM_ID + 1,
            DgramBuffer::new()
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn extended_connect_requires_method_and_nonempty_protocol() {
        let method = h3::Header::new(b":method", b"CONNECT");
        let protocol = h3::Header::new(b":protocol", b"connect-udp");
        assert!(is_extended_connect(&[method.clone(), protocol.clone()]));
        assert!(is_extended_connect(&[protocol.clone(), method.clone()]));
        assert!(!is_extended_connect(&[method.clone()]));
        assert!(!is_extended_connect(&[
            method,
            h3::Header::new(b":protocol", b"")
        ]));
        assert!(!is_extended_connect(&[
            h3::Header::new(b":method", b"GET"),
            protocol
        ]));
    }

    #[test]
    fn oversized_quarter_stream_id_cannot_alias_a_request() -> quiche::Result<()>
    {
        let mut bytes = [0u8; 8];
        let mut enc = octets::OctetsMut::with_slice(&mut bytes);
        enc.put_varint(MAX_QUARTER_STREAM_ID + 1)?;
        assert!(matches!(
            h3_dgram_remove_quarter_stream_id(DgramBuffer::from_slice(&bytes)),
            Err(quiche::Error::InvalidFrame)
        ));
        Ok(())
    }

    /// `remove_quarter_stream_id` on an empty buffer returns an error (buffer
    /// too short).
    #[test]
    fn remove_quarter_stream_id_empty_buffer_errors() {
        let dgram = DgramBuffer::new();
        assert!(h3_dgram_remove_quarter_stream_id(dgram).is_err());
    }
}
