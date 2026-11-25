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

//! Linux UDP receive buffering and checked ancillary metadata decoding.
use std::io;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::num::NonZeroUsize;
use std::os::fd::AsRawFd;
use std::task::ready;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use std::time::SystemTime;

use foundations::telemetry::metrics::Counter;
use foundations::telemetry::metrics::TimeHistogram;
use nix::sys::socket::recvmsg;
use nix::sys::socket::ControlMessageOwned;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::SockaddrStorage;
use tokio::io::Interest;
use tokio::net::UdpSocket;

use super::Incoming;
use crate::buf_factory::BufFactory;
use crate::metrics::labels::QuicHandshakeStage;
use crate::metrics::Metrics;

pub(super) struct LinuxReceiver {
    buffer: Vec<u8>,
    control_space: Vec<u8>,
    dropped: u32,
    drop_metric: Counter,
    queue_wait_metric: TimeHistogram,
}

impl LinuxReceiver {
    pub(super) fn new(metrics: &impl Metrics) -> Self {
        Self {
            buffer: Vec::new(),
            // Reserve for every enabled control message. Never accept a
            // truncated GRO batch.
            control_space: nix::cmsg_space!(
                i32,
                nix::sys::time::TimeSpec,
                u32,
                libc::sockaddr_in,
                libc::sockaddr_in6,
                u32,
                libc::in_pktinfo,
                libc::in6_pktinfo
            ),
            dropped: 0,
            drop_metric: metrics.udp_drop_count(),
            queue_wait_metric: metrics
                .handshake_time_seconds(QuicHandshakeStage::QueueWaiting),
        }
    }

    pub(super) fn poll(
        &mut self, socket: &UdpSocket, local_addr: SocketAddr,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Incoming>> {
        loop {
            match socket
                .try_io(Interest::READABLE, || self.receive(socket, local_addr))
            {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    ready!(socket.poll_recv_ready(cx))?;
                },
                result => return Poll::Ready(result),
            }
        }
    }

    fn receive(
        &mut self, socket: &UdpSocket, local_addr: SocketAddr,
    ) -> io::Result<Incoming> {
        self.buffer.resize(BufFactory::MAX_BUF_SIZE, 0);
        let mut buffers = [io::IoSliceMut::new(&mut self.buffer)];
        let message = recvmsg::<SockaddrStorage>(
            socket.as_raw_fd(),
            &mut buffers,
            Some(&mut self.control_space),
            MsgFlags::empty(),
        )?;
        if message
            .flags
            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
        {
            return Err(invalid("truncated UDP payload or control messages"));
        }
        let peer = message
            .address
            .and_then(|address| {
                address
                    .as_sockaddr_in()
                    .copied()
                    .map(SocketAddr::from)
                    .or_else(|| {
                        address.as_sockaddr_in6().copied().map(SocketAddr::from)
                    })
            })
            .ok_or_else(|| invalid("UDP source address is missing or not IP"))?;
        let metadata = Ancillary::decode(message.cmsgs()?)?;
        let payload = message.iovs().next().map_or_else(Vec::new, Vec::from);
        if payload.len() != message.bytes {
            return Err(invalid(
                "UDP payload length does not match recvmsg result",
            ));
        }

        if let Some(count) = metadata.drop_count {
            self.drop_metric
                .inc_by(drop_delta(&mut self.dropped, count));
        }
        if let Some(elapsed) =
            metadata.rx_time.and_then(|time| time.elapsed().ok())
        {
            self.queue_wait_metric
                .observe(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
        }

        Ok(Incoming {
            buf: payload,
            peer_addr: peer,
            local_addr: metadata.destination_for(local_addr, peer),
            rx_time: metadata.rx_time,
            gro: metadata.segment_size,
            so_mark_data: metadata.mark,
        })
    }
}

fn drop_delta(previous: &mut u32, count: u32) -> u64 {
    u64::from(count.wrapping_sub(std::mem::replace(previous, count)))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// All values used by the routing and worker paths have been validated here.
#[derive(Default, Debug)]
struct Ancillary {
    drop_count: Option<u32>,
    rx_time: Option<SystemTime>,
    segment_size: Option<NonZeroUsize>,
    destination: Option<SocketAddr>,
    ipv4_destination: Option<Ipv4Addr>,
    ipv6_destination: Option<(Ipv6Addr, u32)>,
    mark: Option<[u8; 4]>,
}

impl Ancillary {
    fn decode(
        messages: impl IntoIterator<Item = ControlMessageOwned>,
    ) -> io::Result<Self> {
        let mut metadata = Self::default();
        for message in messages {
            match message {
                ControlMessageOwned::RxqOvfl(count) =>
                    metadata.drop_count = Some(count),
                ControlMessageOwned::ScmTimestampns(time) => {
                    metadata.rx_time = timestamp(
                        i128::from(time.tv_sec()),
                        i128::from(time.tv_nsec()),
                    );
                },
                ControlMessageOwned::UdpGroSegments(size) => {
                    let size = usize::try_from(size)
                        .ok()
                        .and_then(NonZeroUsize::new)
                        .filter(|size| u16::try_from(size.get()).is_ok())
                        .ok_or_else(|| invalid("invalid UDP GRO segment size"))?;
                    metadata.segment_size = Some(size);
                },
                ControlMessageOwned::Ipv4PacketInfo(info) => {
                    metadata.ipv4_destination =
                        Some(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()));
                },
                ControlMessageOwned::Ipv6PacketInfo(info) => {
                    metadata.ipv6_destination = Some((
                        Ipv6Addr::from(info.ipi6_addr.s6_addr),
                        info.ipi6_ifindex,
                    ));
                },
                ControlMessageOwned::Ipv4OrigDstAddr(address) => {
                    metadata.destination =
                        Some(SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)),
                            u16::from_be(address.sin_port),
                        )));
                },
                ControlMessageOwned::Ipv6OrigDstAddr(address) => {
                    // Match the socket API's host-order flow/scope fields;
                    // only the port is in network byte order.
                    metadata.destination =
                        Some(SocketAddr::V6(SocketAddrV6::new(
                            Ipv6Addr::from(address.sin6_addr.s6_addr),
                            u16::from_be(address.sin6_port),
                            address.sin6_flowinfo,
                            address.sin6_scope_id,
                        )));
                },
                ControlMessageOwned::SoMark(mark) =>
                    metadata.mark = Some(mark.to_ne_bytes()),
                // Unknown options do not change the destination.
                _ => (),
            }
        }
        Ok(metadata)
    }

    /// Original destination includes the pre-redirection port. Ordinary
    /// packet info provides the local IP and interface, but not the port.
    /// Keep IPv4-mapped addresses in the same representation as the peer.
    fn destination_for(&self, bound: SocketAddr, peer: SocketAddr) -> SocketAddr {
        let packet_info = match peer {
            SocketAddr::V4(_) => self
                .ipv4_destination
                .map(|ip| SocketAddr::V4(SocketAddrV4::new(ip, bound.port()))),
            SocketAddr::V6(peer) if peer.ip().to_ipv4_mapped().is_some() => self
                .ipv4_destination
                .map(|ip| {
                    SocketAddr::V6(SocketAddrV6::new(
                        ip.to_ipv6_mapped(),
                        bound.port(),
                        0,
                        0,
                    ))
                })
                .or_else(|| {
                    self.ipv6_destination.map(|(ip, _)| {
                        SocketAddr::V6(SocketAddrV6::new(ip, bound.port(), 0, 0))
                    })
                }),
            SocketAddr::V6(_) => self.ipv6_destination.map(|(ip, interface)| {
                SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    bound.port(),
                    0,
                    if ip.is_unicast_link_local() {
                        interface
                    } else {
                        0
                    },
                ))
            }),
        };
        let mut destination = self.destination.or(packet_info).unwrap_or(bound);
        match (destination, peer) {
            (SocketAddr::V4(addr), SocketAddr::V6(peer))
                if peer.ip().to_ipv4_mapped().is_some() =>
            {
                destination = SocketAddr::V6(SocketAddrV6::new(
                    addr.ip().to_ipv6_mapped(),
                    addr.port(),
                    0,
                    0,
                ));
            },
            (SocketAddr::V6(mut addr), SocketAddr::V6(_))
                if addr.ip().is_unicast_link_local() && addr.scope_id() == 0 =>
                if let Some((_, interface)) = self.ipv6_destination {
                    addr.set_scope_id(interface);
                    destination = SocketAddr::V6(addr);
                },
            _ => (),
        }
        destination
    }
}

/// Handle normalized pre-epoch timestamps as well as positive timestamps.
fn timestamp(seconds: i128, nanoseconds: i128) -> Option<SystemTime> {
    if !(0..1_000_000_000).contains(&nanoseconds) {
        return None;
    }
    let magnitude =
        Duration::from_secs(u64::try_from(seconds.unsigned_abs()).ok()?);
    let base = if seconds < 0 {
        SystemTime::UNIX_EPOCH.checked_sub(magnitude)?
    } else {
        SystemTime::UNIX_EPOCH.checked_add(magnitude)?
    };
    base.checked_add(Duration::from_nanos(u64::try_from(nanoseconds).ok()?))
}

#[cfg(test)]
mod tests {
    use super::timestamp;
    use super::Ancillary;
    use nix::sys::socket::ControlMessageOwned;
    use std::net::Ipv6Addr;
    use std::net::SocketAddr;
    use std::net::SocketAddrV6;
    use std::time::Duration;
    use std::time::SystemTime;

    #[test]
    fn rejects_invalid_gro_lengths() -> crate::QuicResult<()> {
        for size in [i32::MIN, -1, 0, 65536, i32::MAX] {
            assert!(Ancillary::decode([ControlMessageOwned::UdpGroSegments(
                size
            )])
            .is_err());
        }
        for size in [1, 1200, 65535] {
            let metadata =
                Ancillary::decode([ControlMessageOwned::UdpGroSegments(size)])?;
            assert_eq!(
                metadata.segment_size.map(std::num::NonZeroUsize::get),
                Some(usize::try_from(size)?)
            );
        }
        Ok(())
    }

    #[test]
    fn preserves_ipv6_scope_and_mark() -> std::io::Result<()> {
        let address = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6
                .try_into()
                .map_err(std::io::Error::other)?,
            sin6_port: 443_u16.to_be(),
            sin6_flowinfo: 0x12345,
            sin6_addr: libc::in6_addr {
                s6_addr: Ipv6Addr::LOCALHOST.octets(),
            },
            sin6_scope_id: 19,
        };
        let metadata = Ancillary::decode([
            ControlMessageOwned::Ipv6OrigDstAddr(address),
            ControlMessageOwned::SoMark(0x1234_5678),
            ControlMessageOwned::RxqOvfl(2),
        ])?;
        assert_eq!(
            metadata.destination,
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                443,
                0x12345,
                19
            )))
        );
        assert_eq!(metadata.mark, Some(0x1234_5678_u32.to_ne_bytes()));
        assert_eq!(metadata.drop_count, Some(2));
        Ok(())
    }

    #[test]
    fn wrapping_drop_counter_tracks_successive_samples() {
        let mut previous = u32::MAX - 1;
        assert_eq!(super::drop_delta(&mut previous, 2), 4);
        assert_eq!(super::drop_delta(&mut previous, 2), 0);
        assert_eq!(super::drop_delta(&mut previous, 5), 3);
        assert_eq!(previous, 5);
    }

    #[tokio::test]
    async fn receives_original_destination_and_timestamp() -> crate::QuicResult<()>
    {
        use nix::sys::socket::setsockopt;
        use nix::sys::socket::sockopt;
        use tokio::net::UdpSocket;
        for (wildcard, loopback) in
            [("0.0.0.0:0", "127.0.0.1:0"), ("[::]:0", "[::1]:0")]
        {
            let socket = UdpSocket::bind(wildcard).await?;
            let peer = UdpSocket::bind(loopback).await?;
            let local = socket.local_addr()?;
            let destination =
                SocketAddr::new(peer.local_addr()?.ip(), local.port());
            if local.is_ipv4() {
                setsockopt(&socket, sockopt::Ipv4OrigDstAddr, &true)?;
                setsockopt(&socket, sockopt::Ipv4PacketInfo, &true)?;
            } else {
                setsockopt(&socket, sockopt::Ipv6OrigDstAddr, &true)?;
                setsockopt(&socket, sockopt::Ipv6RecvPacketInfo, &true)?;
            }
            setsockopt(&socket, sockopt::ReceiveTimestampns, &true)?;
            peer.send_to(b"hello", destination).await?;
            let mut receiver =
                super::LinuxReceiver::new(&crate::metrics::DefaultMetrics);
            let packet = tokio::time::timeout(
                Duration::from_secs(1),
                std::future::poll_fn(|cx| receiver.poll(&socket, local, cx)),
            )
            .await??;
            assert_eq!(packet.buf, b"hello");
            assert_eq!(packet.peer_addr, peer.local_addr()?);
            assert_eq!(packet.local_addr, destination);
            assert!(packet.rx_time.is_some());
            assert!(packet.gro.is_none());
        }
        Ok(())
    }

    #[cfg(not(feature = "fuzzing"))]
    #[tokio::test]
    async fn wildcard_packet_info_preserves_reply_source() -> crate::QuicResult<()>
    {
        use crate::quic::io::gso::send_packets_before;
        use crate::quic::io::gso::PacketSend;
        use crate::quic::io::gso::SendOutcome;
        use crate::socket::SocketCapabilitiesBuilder;
        use std::time::Instant;
        use tokio::net::UdpSocket;
        for (wildcard, source, peer_addr, dualstack) in [
            ("0.0.0.0:0", "127.0.0.2", "127.0.0.1:0", false),
            ("[::]:0", "::1", "[::1]:0", false),
            ("[::]:0", "127.0.0.2", "127.0.0.1:0", true),
        ] {
            let socket = if dualstack {
                use nix::sys::socket::bind;
                use nix::sys::socket::setsockopt;
                use nix::sys::socket::socket;
                use nix::sys::socket::AddressFamily;
                use nix::sys::socket::SockFlag;
                use nix::sys::socket::SockType;
                use nix::sys::socket::SockaddrIn6;
                use std::os::fd::AsRawFd;
                let fd = socket(
                    AddressFamily::Inet6,
                    SockType::Datagram,
                    SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
                    None,
                )?;
                setsockopt(&fd, nix::sys::socket::sockopt::Ipv6V6Only, &false)?;
                bind(
                    fd.as_raw_fd(),
                    &SockaddrIn6::from(SocketAddrV6::new(
                        Ipv6Addr::UNSPECIFIED,
                        0,
                        0,
                        0,
                    )),
                )?;
                UdpSocket::from_std(std::net::UdpSocket::from(fd))?
            } else {
                UdpSocket::bind(wildcard).await?
            };
            let peer = UdpSocket::bind(peer_addr).await?;
            let bound = socket.local_addr()?;
            let destination = SocketAddr::new(source.parse()?, bound.port());
            let mut builder = SocketCapabilitiesBuilder::new(&socket);
            if destination.is_ipv4() {
                builder.ipv4_pktinfo()?;
            }
            if bound.is_ipv6() {
                builder.ipv6_pktinfo()?;
            }
            let caps = builder.finish();
            peer.send_to(b"hello", destination).await?;
            let mut receiver =
                super::LinuxReceiver::new(&crate::metrics::DefaultMetrics);
            let packet = tokio::time::timeout(
                Duration::from_secs(1),
                std::future::poll_fn(|cx| receiver.poll(&socket, bound, cx)),
            )
            .await??;
            let expected_local = match destination {
                SocketAddr::V4(addr) if dualstack =>
                    SocketAddr::V6(SocketAddrV6::new(
                        addr.ip().to_ipv6_mapped(),
                        addr.port(),
                        0,
                        0,
                    )),
                addr => addr,
            };
            assert_eq!(packet.local_addr, expected_local);
            assert!(caps.supports_pktinfo(packet.local_addr));
            let outcome = send_packets_before(
                &socket,
                b"reply",
                PacketSend {
                    to: packet.peer_addr,
                    from: Some(packet.local_addr),
                    segment_size: None,
                    tx_time: None,
                    dscp: None,
                },
                &crate::metrics::DefaultMetrics,
                Instant::now() + Duration::from_secs(1),
            )
            .await?;
            assert_eq!(outcome, SendOutcome::Sent);
            let mut reply = [0u8; 16];
            let (len, from) = tokio::time::timeout(
                Duration::from_secs(1),
                peer.recv_from(&mut reply),
            )
            .await??;
            assert_eq!(&reply[..len], b"reply");
            assert_eq!(from, destination);
        }
        Ok(())
    }

    #[test]
    fn checked_timestamps_cover_both_sides_of_epoch() {
        assert_eq!(
            timestamp(1, 500_000_000),
            SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(1500))
        );
        assert_eq!(
            timestamp(-1, 500_000_000),
            SystemTime::UNIX_EPOCH.checked_sub(Duration::from_millis(500))
        );
        assert_eq!(timestamp(0, -1), None);
        assert_eq!(timestamp(0, 1_000_000_000), None);
        assert_eq!(timestamp(i128::MAX, 0), None);
    }
}
