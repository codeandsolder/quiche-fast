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

use std::error::Error;
use std::io;
use std::net::SocketAddr;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_DATAGRAM_SIZE: usize = 1350;
pub const MAX_UDP_PAYLOAD: usize = 65535;

/// Shared transport limits for the loopback examples. Endpoint-specific
/// TLS credentials and early-data policy remain with the caller.
pub fn demo_config(protocols: &[&[u8]]) -> quiche::Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.set_application_protos(protocols)?;
    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    Ok(config)
}

pub fn receive_datagram(
    socket: &mio::net::UdpSocket, input: &mut [u8],
) -> io::Result<Option<(usize, SocketAddr)>> {
    loop {
        match socket.recv_from(input) {
            Ok(received) => return Ok(Some(received)),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock =>
                return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error),
        }
    }
}

/// Retain a generated datagram until the socket has accepted it. While it
/// is pending, the transport does not generate another packet into the buffer.
pub struct DatagramOutput {
    bytes: [u8; MAX_DATAGRAM_SIZE],
    pending: Option<(usize, SocketAddr)>,
}

impl Default for DatagramOutput {
    fn default() -> Self {
        Self {
            bytes: [0; MAX_DATAGRAM_SIZE],
            pending: None,
        }
    }
}

impl DatagramOutput {
    /// The packet generator may access storage only after the previous
    /// datagram was accepted by the socket.
    pub fn buffer(&mut self) -> &mut [u8] {
        debug_assert!(!self.blocked());
        &mut self.bytes
    }

    pub fn flush(&mut self, socket: &mio::net::UdpSocket) -> io::Result<()> {
        self.flush_with(|bytes, peer| socket.send_to(bytes, peer))
    }

    fn flush_with(
        &mut self,
        mut transmit: impl FnMut(&[u8], SocketAddr) -> io::Result<usize>,
    ) -> io::Result<()> {
        let Some((length, peer)) = self.pending else {
            return Ok(());
        };
        loop {
            match transmit(&self.bytes[..length], peer) {
                Ok(written) if written == length => {
                    self.pending = None;
                    return Ok(());
                },
                Ok(_) =>
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial UDP datagram",
                    )),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock =>
                    return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error),
            }
        }
    }

    pub fn send(
        &mut self, socket: &mio::net::UdpSocket, length: usize, peer: SocketAddr,
    ) -> io::Result<()> {
        debug_assert!(self.pending.is_none());
        self.pending = Some((length, peer));
        self.flush(socket)
    }

    pub const fn blocked(&self) -> bool {
        self.pending.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_datagram_survives_interrupted_and_blocked_writes(
    ) -> io::Result<()> {
        let mut output = DatagramOutput::default();
        let peer = SocketAddr::from(([127, 0, 0, 1], 4433));
        let packet = b"retained packet";
        output.buffer()[..packet.len()].copy_from_slice(packet);
        output.pending = Some((packet.len(), peer));

        let mut attempts = 0;
        output.flush_with(|bytes, address| {
            assert_eq!(bytes, packet);
            assert_eq!(address, peer);
            attempts += 1;
            let kind = if attempts == 1 {
                io::ErrorKind::Interrupted
            } else {
                io::ErrorKind::WouldBlock
            };
            Err(kind.into())
        })?;
        assert_eq!(attempts, 2);
        assert!(output.blocked());

        output.flush_with(|bytes, address| {
            assert_eq!(bytes, packet);
            assert_eq!(address, peer);
            Ok(bytes.len())
        })?;
        assert!(!output.blocked());
        output.flush_with(|_, _| Err(io::Error::other("no queued datagram")))?;
        Ok(())
    }
}
