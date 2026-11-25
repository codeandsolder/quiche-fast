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

//! Nonblocking UDP I/O for the synchronous client.

use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use mio::Events;
use mio::Interest;
use mio::Poll;
use mio::Token;

use crate::quiche;

use super::ClientError;
use super::MAX_DATAGRAM_SIZE;

const SOCKET: Token = Token(0);
const IO_BUDGET: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TxStatus {
    Idle,
    Pacing(Instant),
    Blocked,
    More,
}

impl TxStatus {
    pub(super) const fn deadline(self, now: Instant) -> Option<Instant> {
        match self {
            Self::Pacing(deadline) => Some(deadline),
            Self::More => Some(now),
            Self::Idle | Self::Blocked => None,
        }
    }
}

/// A generated packet is owned until the UDP socket accepts the whole packet.
/// A retry cannot regenerate, overwrite, or split its payload.
struct PendingDatagram {
    buffer: [u8; MAX_DATAGRAM_SIZE],
    packet: Option<(usize, quiche::SendInfo)>,
}

impl Default for PendingDatagram {
    fn default() -> Self {
        Self {
            buffer: [0; MAX_DATAGRAM_SIZE],
            packet: None,
        }
    }
}

impl PendingDatagram {
    fn flush_with(
        &mut self, now: Instant,
        mut send: impl FnMut(&[u8], SocketAddr) -> io::Result<usize>,
    ) -> io::Result<Option<TxStatus>> {
        let Some((len, info)) = self.packet else {
            return Ok(None);
        };
        if info.at > now {
            return Ok(Some(TxStatus::Pacing(info.at)));
        }
        let bytes = self
            .buffer
            .get(..len)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        loop {
            match send(bytes, info.to) {
                Ok(written) if written == len => {
                    self.packet = None;
                    return Ok(None);
                },
                Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock =>
                    return Ok(Some(TxStatus::Blocked)),
                Err(error) => return Err(error),
            }
        }
    }
}

pub(super) struct SyncIo {
    poll: Poll,
    events: Events,
    socket: mio::net::UdpSocket,
    local_addr: SocketAddr,
    receive_buffer: Vec<u8>,
    receive_pending: bool,
    tx: PendingDatagram,
    writable_interest: bool,
}

impl SyncIo {
    pub(super) fn bind(bind_addr: SocketAddr) -> Result<Self, ClientError> {
        let poll = Poll::new().map_err(io_error)?;
        let mut socket =
            mio::net::UdpSocket::bind(bind_addr).map_err(io_error)?;
        poll.registry()
            .register(&mut socket, SOCKET, Interest::READABLE)
            .map_err(io_error)?;
        let local_addr = socket.local_addr().map_err(io_error)?;
        Ok(Self {
            poll,
            socket,
            local_addr,
            events: Events::with_capacity(16),
            receive_buffer: vec![0; 65_535],
            receive_pending: false,
            tx: PendingDatagram::default(),
            writable_interest: false,
        })
    }

    pub(super) const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn set_writable_interest(
        &mut self, enabled: bool,
    ) -> Result<(), ClientError> {
        if self.writable_interest != enabled {
            let interest = if enabled {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            self.poll
                .registry()
                .reregister(&mut self.socket, SOCKET, interest)
                .map_err(io_error)?;
            self.writable_interest = enabled;
        }
        Ok(())
    }

    /// Generate the ClientHello without transmitting it. This initializes TLS
    /// early-data state before the application queues its first flight.
    pub(super) fn stage_initial(
        &mut self, conn: &mut quiche::Connection,
    ) -> Result<(), ClientError> {
        self.tx.packet =
            Some(conn.send(&mut self.tx.buffer).map_err(|error| {
                ClientError::Other(format!("generate ClientHello: {error}"))
            })?);
        Ok(())
    }

    /// Drain an existing packet first, then ask quiche for another one.
    /// The send budget bounds each iteration even under continuous traffic.
    pub(super) fn flush(
        &mut self, conn: &mut quiche::Connection,
    ) -> Result<TxStatus, ClientError> {
        let status = self.flush_packets(conn)?;
        self.set_writable_interest(status == TxStatus::Blocked)?;
        Ok(status)
    }

    fn flush_packets(
        &mut self, conn: &mut quiche::Connection,
    ) -> Result<TxStatus, ClientError> {
        for _ in 0..IO_BUDGET {
            if self.tx.packet.is_none() {
                match conn.send(&mut self.tx.buffer) {
                    Ok((len, info)) => {
                        self.tx.packet = Some((len, info));
                    },
                    Err(quiche::Error::Done) => return Ok(TxStatus::Idle),
                    Err(error) =>
                        return Err(ClientError::Other(format!(
                            "generate QUIC packet: {error}"
                        ))),
                }
            }
            let socket = &self.socket;
            if let Some(status) = self
                .tx
                .flush_with(Instant::now(), |bytes, to| socket.send_to(bytes, to))
                .map_err(io_error)?
            {
                return Ok(status);
            }
        }
        Ok(TxStatus::More)
    }

    /// Wait until input, writable readiness, or the earliest absolute
    /// deadline. A bounded receive drain retains its own readiness when the
    /// socket still has packets; edge-triggered polling cannot strand them.
    pub(super) fn wait(
        &mut self, conn: &mut quiche::Connection, deadline: Option<Instant>,
    ) -> Result<(), ClientError> {
        if !self.receive_pending {
            loop {
                let timeout = deadline
                    .map(|time| time.saturating_duration_since(Instant::now()));
                match self.poll.poll(&mut self.events, timeout) {
                    Ok(()) => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted =>
                        (),
                    Err(error) => return Err(io_error(error)),
                }
            }
            self.receive_pending = self
                .events
                .iter()
                .any(|event| event.token() == SOCKET && event.is_readable());
        }
        if self.receive_pending {
            self.receive_pending = self.receive(conn)?;
        }
        Ok(())
    }

    fn receive(
        &mut self, conn: &mut quiche::Connection,
    ) -> Result<bool, ClientError> {
        for _ in 0..IO_BUDGET {
            let (len, from) =
                match self.socket.recv_from(&mut self.receive_buffer) {
                    Ok(packet) => packet,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted =>
                        continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock =>
                        return Ok(false),
                    Err(error) => return Err(io_error(error)),
                };
            let recv_info = quiche::RecvInfo {
                from,
                to: self.local_addr,
            };
            if let Err(error) =
                conn.recv(&mut self.receive_buffer[..len], recv_info)
            {
                log::debug!("{}: recv failed: {error}", self.local_addr);
            }
        }
        Ok(true)
    }
}

fn io_error(error: io::Error) -> ClientError {
    ClientError::Other(format!("UDP I/O: {error}"))
}

#[cfg(test)]
mod tests {
    use super::PendingDatagram;
    use super::TxStatus;
    use crate::quiche;
    use std::io;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn pending_datagram_survives_pacing_and_backpressure(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let at = now + Duration::from_millis(10);
        let to = "127.0.0.1:4433".parse()?;
        let from = "127.0.0.1:4321".parse()?;
        let mut pending = PendingDatagram::default();
        pending.buffer[..4].copy_from_slice(b"quic");
        pending.packet = Some((4, quiche::SendInfo { from, to, at }));
        let mut sent = Vec::new();
        assert_eq!(
            pending.flush_with(now, |bytes, _| {
                sent.push(bytes.to_vec());
                Ok(bytes.len())
            })?,
            Some(TxStatus::Pacing(at))
        );
        assert_eq!(sent, Vec::<Vec<u8>>::new());
        assert_eq!(
            pending.flush_with(at, |bytes, destination| {
                assert_eq!(bytes, b"quic");
                assert_eq!(destination, to);
                Err(io::ErrorKind::WouldBlock.into())
            })?,
            Some(TxStatus::Blocked)
        );
        assert!(pending.packet.is_some());
        let mut calls = 0;
        assert_eq!(
            pending.flush_with(at, |bytes, destination| {
                calls += 1;
                if calls == 1 {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                assert_eq!(destination, to);
                sent.push(bytes.to_vec());
                Ok(bytes.len())
            })?,
            None
        );
        assert_eq!(sent, vec![b"quic".to_vec()]);
        assert_eq!(calls, 2);
        assert!(pending.packet.is_none());
        Ok(())
    }

    #[test]
    fn short_udp_write_does_not_consume_packet(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let addr = "127.0.0.1:4433".parse()?;
        let mut pending = PendingDatagram::default();
        pending.packet = Some((4, quiche::SendInfo {
            from: addr,
            to: addr,
            at: now,
        }));
        let error = pending
            .flush_with(now, |_, _| Ok(3))
            .err()
            .ok_or("expected short write error")?;
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert!(pending.packet.is_some());
        Ok(())
    }
}
