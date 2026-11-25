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

use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use crate::metrics::labels::QuicWriteError;
use crate::metrics::Metrics;
use crate::quic::Dscp;
use datagram_socket::DatagramSocketSend;
use datagram_socket::DatagramSocketSendExt;

#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
use nix::sys::socket::sendmsg;
#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
use nix::sys::socket::ControlMessage;
#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
use nix::sys::socket::MsgFlags;
#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
use nix::sys::socket::SockaddrStorage;
#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
use smallvec::SmallVec;
#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
use std::io::ErrorKind;
#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
use std::os::fd::AsRawFd;
#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
use tokio::io::Interest;

/// Metadata for one UDP datagram or one equal-sized GSO batch.
#[derive(Clone, Copy, Debug)]
pub(in crate::quic) struct PacketSend {
    pub(crate) to: SocketAddr,
    pub(crate) from: Option<SocketAddr>,
    pub(crate) segment_size: Option<usize>,
    pub(crate) tx_time: Option<Instant>,
    pub(crate) dscp: Option<Dscp>,
}

impl PacketSend {
    const fn has_control(self) -> bool {
        self.from.is_some() ||
            self.segment_size.is_some() ||
            self.tx_time.is_some() ||
            self.dscp.is_some()
    }
}

/// Preserve UDP datagram boundaries even on a non-UDP transport wrapper.
/// Ancillary options are independent of segmentation: a source address,
/// pacing deadline or DSCP alone is sufficient to use sendmsg on Linux.
async fn send_packets<S: DatagramSocketSend + ?Sized, M: Metrics>(
    socket: &S, buffer: &[u8], packet: PacketSend, metrics: &M,
) -> io::Result<()> {
    let segment_size = match checked_segment_size(packet.segment_size) {
        Ok(size) => size,
        Err(error) => {
            metrics.write_errors(QuicWriteError::Err).inc();
            return Err(error);
        },
    };
    if let (true, Some(udp)) = (
        cfg!(all(target_os = "linux", not(feature = "fuzzing"))) &&
            packet.has_control(),
        socket.as_udp_socket(),
    ) {
        return check_datagram_send(
            send_to(udp, buffer, packet, metrics).await,
            buffer.len(),
            metrics,
        );
    }
    if let Some(deadline) = packet.tx_time {
        tokio::time::sleep_until(deadline.into()).await;
    }
    if let Some(size) = segment_size {
        for datagram in buffer.chunks(usize::from(size)) {
            check_datagram_send(
                socket.send_to(datagram, packet.to).await,
                datagram.len(),
                metrics,
            )?;
        }
        Ok(())
    } else {
        check_datagram_send(
            socket.send_to(buffer, packet.to).await,
            buffer.len(),
            metrics,
        )
    }
}

/// Result of a deadline-bounded send. Expired batches are treated as packet
/// loss by the QUIC worker, not retried with the same packet numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::quic) enum SendOutcome {
    Sent,
    DeadlineExpired,
}

/// Cancel a pending datagram send when its owner needs to service a timer.
/// Software segmentation may have already sent a prefix of the batch; the
/// transport recovery machinery, rather than this layer, recovers its suffix.
pub(in crate::quic) async fn send_packets_before<
    S: DatagramSocketSend + ?Sized,
    M: Metrics,
>(
    socket: &S, buffer: &[u8], packet: PacketSend, metrics: &M, deadline: Instant,
) -> io::Result<SendOutcome> {
    let deadline = tokio::time::Instant::from_std(deadline);
    if deadline > tokio::time::Instant::now() {
        // A successful ready send needs no registered timer. Pending sends
        // remain cancellable through the socket's poll-based API.
        if let Ok(result) = tokio::time::timeout_at(
            deadline,
            send_packets(socket, buffer, packet, metrics),
        )
        .await
        {
            return result.map(|()| SendOutcome::Sent);
        }
    }
    metrics.write_errors(QuicWriteError::DeadlineExpired).inc();
    Ok(SendOutcome::DeadlineExpired)
}

fn checked_segment_size(size: Option<usize>) -> io::Result<Option<u16>> {
    size.map(|size| {
        u16::try_from(size)
            .ok()
            .filter(|size| *size != 0)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP GSO segment size must be in 1..=65535",
                )
            })
    })
    .transpose()
}

fn check_datagram_send<M: Metrics>(
    result: io::Result<usize>, expected: usize, metrics: &M,
) -> io::Result<()> {
    match result {
        Ok(written) if written == expected => Ok(()),
        Ok(written) => {
            metrics.write_errors(QuicWriteError::Partial).inc();
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("datagram send reported {written} of {expected} bytes"),
            ))
        },
        Err(error) => {
            metrics.write_errors(QuicWriteError::Err).inc();
            Err(error)
        },
    }
}

/// QUIC has already accounted for generated packets as transmitted. A
/// path-local or temporary network failure is therefore recoverable as
/// ordinary loss. Local transport contract/configuration errors must not be
/// silently converted into endless retransmission.
pub(super) fn recoverable_send_error(error: &io::Error) -> bool {
    #[cfg(target_os = "linux")]
    if matches!(error.raw_os_error(), Some(libc::EMSGSIZE | libc::ENOBUFS)) {
        return true;
    }
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted |
            io::ErrorKind::WouldBlock |
            io::ErrorKind::ConnectionRefused |
            io::ErrorKind::ConnectionReset |
            io::ErrorKind::HostUnreachable |
            io::ErrorKind::NetworkUnreachable |
            io::ErrorKind::NetworkDown |
            io::ErrorKind::TimedOut |
            io::ErrorKind::AddrNotAvailable
    )
}

// Maximum number of packets can be sent in UDP GSO.
pub(super) const UDP_MAX_SEGMENT_COUNT: usize = 64;

#[cfg(not(feature = "gcongestion"))]
/// Returns a new max send buffer size to avoid the fragmentation
/// at the end. Maximum send buffer size is min(`MAX_SEND_BUF_SIZE`,
/// connection's `send_quantum`).
/// For example,
///
/// - `max_send_buf` = 1000 and `mss` = 100, return 1000
/// - `max_send_buf` = 1000 and `mss` = 90, return 990
///
/// not to have last 10 bytes packet.
pub(super) fn tune_max_send_size(
    segment_size: Option<usize>, send_quantum: usize, max_capacity: usize,
) -> usize {
    let max_send_buf_size = send_quantum.min(max_capacity);

    segment_size
        .filter(|size| *size != 0)
        .map_or(max_send_buf_size, |mss| max_send_buf_size / mss * mss)
}

// https://wiki.cfdata.org/pages/viewpage.action?pageId=436188159
pub(super) const UDP_MAX_GSO_PACKET_SIZE: usize = 65507;

#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
#[derive(Copy, Clone, Debug)]
enum PktInfo {
    V4(libc::in_pktinfo),
    V6(libc::in6_pktinfo),
}

#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
impl PktInfo {
    const fn make_cmsg(&'_ self) -> ControlMessage<'_> {
        match self {
            Self::V4(pkt) => ControlMessage::Ipv4PacketInfo(pkt),
            Self::V6(pkt) => ControlMessage::Ipv6PacketInfo(pkt),
        }
    }

    const fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(ipv4) => {
                // This is basically a safe wrapper around `mem::transmute()`.
                // Calling this on the raw octets will ensure they
                // become a native-endian, kernel-readable u32
                let s_addr = u32::from_ne_bytes(ipv4.ip().octets());

                Self::V4(libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr { s_addr },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                })
            },
            SocketAddr::V6(ipv6) => Self::V6(libc::in6_pktinfo {
                ipi6_ifindex: ipv6.scope_id(),
                ipi6_addr: libc::in6_addr {
                    s6_addr: ipv6.ip().octets(),
                },
            }),
        }
    }
}

#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
fn monotonic_timespec_ns(ts: libc::timespec) -> io::Result<u64> {
    const NANOS_PER_SECOND: u64 = 1_000_000_000;

    let seconds =
        u64::try_from(ts.tv_sec).map_err(|_| io::ErrorKind::InvalidData)?;
    let nanos =
        u64::try_from(ts.tv_nsec).map_err(|_| io::ErrorKind::InvalidData)?;
    if nanos >= NANOS_PER_SECOND {
        return Err(io::ErrorKind::InvalidData.into());
    }
    seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|seconds| seconds.checked_add(nanos))
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}

/// Translate an opaque Rust Instant relative to a sampled `CLOCK_MONOTONIC`
/// value, without relying on `Instant`'s private layout.
#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
fn tx_time_from_anchor(
    deadline: Instant, anchor: Instant, anchor_ns: u64,
) -> io::Result<u64> {
    let (forward, difference) = if deadline >= anchor {
        (true, deadline.duration_since(anchor))
    } else {
        (false, anchor.duration_since(deadline))
    };
    let delta = u64::try_from(difference.as_nanos())
        .map_err(|_| io::ErrorKind::InvalidInput)?;

    if forward {
        anchor_ns.checked_add(delta)
    } else {
        anchor_ns.checked_sub(delta)
    }
    .ok_or_else(|| io::ErrorKind::InvalidInput.into())
}

#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
fn monotonic_tx_time(deadline: Instant) -> io::Result<u64> {
    // SO_TXTIME uses CLOCK_MONOTONIC, as does Instant::now() on Linux.
    // Bracket the kernel sample with Rust Instant readings and use their
    // midpoint to bound sampling skew, including under preemption.
    let before = Instant::now();
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid writable timespec; clock_gettime fills it on
    // success.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let after = Instant::now();
    let span = after
        .checked_duration_since(before)
        .ok_or(io::ErrorKind::InvalidData)?;
    let anchor = before
        .checked_add(span / 2)
        .ok_or(io::ErrorKind::InvalidData)?;
    tx_time_from_anchor(deadline, anchor, monotonic_timespec_ns(ts)?)
}

#[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
async fn send_to<M: Metrics>(
    socket: &tokio::net::UdpSocket, send_buf: &[u8], packet: PacketSend,
    metrics: &M,
) -> io::Result<usize> {
    let PacketSend {
        to,
        from,
        segment_size,
        tx_time,
        dscp,
    } = packet;
    let raw_time = tx_time.map(monotonic_tx_time).transpose()?.unwrap_or(0);
    // UDP_SEGMENT is a nonzero u16 on the wire. Truncating a usize here
    // silently changes the segment size and can even turn it into zero.
    let segment_size_u16 = checked_segment_size(segment_size)?;

    let mut sendmsg_retry_timer = None;
    loop {
        let iov = [std::io::IoSlice::new(send_buf)];

        let pkt_info = from.map(PktInfo::from_socket_addr);
        let tos = dscp.map(Dscp::tos);
        let tclass = tos.map(i32::from);

        let mut cmsgs: SmallVec<[ControlMessage; 4]> = SmallVec::new();

        if let Some(segment_size) = segment_size_u16.as_ref() {
            cmsgs.push(ControlMessage::UdpGsoSegments(segment_size));
        }

        if tx_time.is_some() {
            // Create cmsg for TXTIME.
            cmsgs.push(ControlMessage::TxTime(&raw_time));
        }

        if let Some(pkt) = pkt_info.as_ref() {
            // Create cmsg for IP(V6)_PKTINFO.
            cmsgs.push(pkt.make_cmsg());
        }

        match (to, tos.as_ref(), tclass.as_ref()) {
            (SocketAddr::V4(_), Some(tos), _) =>
                cmsgs.push(ControlMessage::Ipv4Tos(tos)),
            // Linux transmits IPv4-mapped destinations as IPv4 and silently
            // ignores IPV6_TCLASS for them.
            (SocketAddr::V6(to), Some(tos), _)
                if to.ip().to_ipv4_mapped().is_some() =>
                cmsgs.push(ControlMessage::Ipv4Tos(tos)),
            (SocketAddr::V6(_), _, Some(tclass)) =>
                cmsgs.push(ControlMessage::Ipv6TClass(tclass)),
            _ => (),
        }

        let addr = SockaddrStorage::from(to);

        // Must use [`try_io`] so tokio can properly clear its readyness flag
        let res = socket.try_io(Interest::WRITABLE, || {
            let fd = socket.as_raw_fd();
            sendmsg(fd, &iov, &cmsgs, MsgFlags::empty(), Some(&addr))
                .map_err(Into::into)
        });

        match res {
            // Wait for the socket to become writable and try again
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if sendmsg_retry_timer.is_none() {
                    sendmsg_retry_timer = Some(
                        metrics.send_to_wouldblock_duration_s().start_timer(),
                    );
                }
                metrics.write_errors(QuicWriteError::WouldBlock).inc();
                socket.writable().await?;
            },
            res => return res,
        }
    }
}

#[cfg(any(not(target_os = "linux"), feature = "fuzzing"))]
async fn send_to<M: Metrics>(
    _socket: &tokio::net::UdpSocket, _send_buf: &[u8], _packet: PacketSend,
    _metrics: &M,
) -> io::Result<usize> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(all(target_os = "linux", test, not(feature = "fuzzing")))]
pub(crate) mod test {
    use super::*;
    use crate::metrics::DefaultMetrics;
    use crate::quic::DscpHandle;
    use nix::sys::socket::recvmsg;
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt;
    use nix::sys::socket::ControlMessageOwned;
    use nix::sys::socket::MsgFlags;
    use std::io::IoSliceMut;
    use std::os::fd::AsRawFd;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;
    use tokio::time::Duration;

    const TEST_DSCP: Dscp = Dscp::new(34).unwrap();

    pub(crate) fn enable_tos(socket: &UdpSocket) {
        if socket.local_addr().unwrap().is_ipv4() {
            setsockopt(socket, sockopt::IpRecvTos, &true).unwrap();
        } else {
            setsockopt(socket, sockopt::Ipv6RecvTClass, &true).unwrap();
        }
    }

    pub(crate) async fn recv_tos(socket: &UdpSocket) -> (Vec<u8>, u8) {
        let receive = async {
            let mut buf = [0u8; 2048];
            let mut cmsg_space = nix::cmsg_space!(libc::c_int);

            loop {
                socket.readable().await.unwrap();
                match socket.try_io(Interest::READABLE, || {
                    let mut iov = [IoSliceMut::new(&mut buf)];
                    let msg = recvmsg::<()>(
                        socket.as_raw_fd(),
                        &mut iov,
                        Some(&mut cmsg_space),
                        MsgFlags::empty(),
                    )
                    .map_err(io::Error::from)?;
                    let tos =
                        msg.cmsgs().map_err(io::Error::from)?.find_map(|cmsg| {
                            match cmsg {
                                ControlMessageOwned::Ipv4Tos(tos) => Some(tos),
                                ControlMessageOwned::Ipv6TClass(tclass) =>
                                    Some(u8::try_from(tclass).unwrap()),
                                _ => None,
                            }
                        });
                    Ok((msg.bytes, tos))
                }) {
                    Ok((len, Some(tos))) => return (buf[..len].to_vec(), tos),
                    Ok((_, None)) => panic!("IP TOS control message missing"),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                    Err(e) => panic!("recvmsg failed: {e}"),
                }
            }
        };

        timeout(Duration::from_secs(2), receive)
            .await
            .expect("timed out waiting for UDP packet")
    }

    async fn send_packet(
        sender: &UdpSocket, receiver: &UdpSocket, buf: &[u8],
        segment_size: Option<usize>, from: Option<SocketAddr>,
        dscp: Option<Dscp>,
    ) {
        let metrics = DefaultMetrics;
        let bytes = send_to(
            sender,
            buf,
            PacketSend {
                to: receiver.local_addr().unwrap(),
                from,
                segment_size,
                tx_time: None,
                dscp,
            },
            &metrics,
        )
        .await
        .unwrap();
        assert_eq!(bytes, buf.len());
    }

    #[tokio::test]
    async fn per_packet_dscp_overrides_socket_without_leaking() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        enable_tos(&receiver);

        // A nonzero socket default makes an explicit zero distinguishable from
        // omitting the cmsg after a marking is cleared.
        setsockopt(&sender, sockopt::Ipv4Tos, &136).unwrap();
        let first = DscpHandle::new();
        let second = DscpHandle::new();
        second.set(Dscp::new(1));

        for (dscp, expected) in
            [(first.get(), 136), (second.get(), 4), (first.get(), 136)]
        {
            send_packet(
                &sender,
                &receiver,
                b"quic",
                None,
                Some(sender.local_addr().unwrap()),
                dscp,
            )
            .await;
            let (payload, tos) = recv_tos(&receiver).await;
            assert_eq!(payload, b"quic");
            assert_eq!(tos & 0xfc, expected);
        }

        first.set(Dscp::new(28));
        send_packet(&sender, &receiver, b"updated", None, None, first.get())
            .await;
        assert_eq!(recv_tos(&receiver).await.1 & 0xfc, 112);

        first.set(Dscp::new(0));
        send_packet(&sender, &receiver, b"zero", None, None, first.get()).await;
        assert_eq!(recv_tos(&receiver).await.1 & 0xfc, 0);

        first.set(None);
        send_packet(&sender, &receiver, b"unmarked", None, None, first.get())
            .await;
        assert_eq!(recv_tos(&receiver).await.1 & 0xfc, 136);
    }

    #[tokio::test]
    async fn gso_segments_keep_dscp_with_pktinfo() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        enable_tos(&receiver);

        let buf = vec![42u8; 2400];
        send_packet(
            &sender,
            &receiver,
            &buf,
            Some(1200),
            Some(sender.local_addr().unwrap()),
            Some(TEST_DSCP),
        )
        .await;

        for _ in 0..2 {
            let (payload, tos) = recv_tos(&receiver).await;
            assert_eq!(payload, &buf[..1200]);
            assert_eq!(tos >> 2, TEST_DSCP.value());
        }
    }

    #[tokio::test]
    async fn ipv6_tclass_marks_packet_without_gso() {
        let sender = UdpSocket::bind("[::1]:0").await.unwrap();
        let receiver = UdpSocket::bind("[::1]:0").await.unwrap();
        enable_tos(&receiver);

        send_packet(
            &sender,
            &receiver,
            b"ipv6",
            None,
            Some(sender.local_addr().unwrap()),
            Some(TEST_DSCP),
        )
        .await;
        let (payload, tos) = recv_tos(&receiver).await;
        assert_eq!(payload, b"ipv6");
        assert_eq!(tos >> 2, TEST_DSCP.value());
    }

    #[tokio::test]
    async fn ipv4_mapped_ipv6_peer_uses_ipv4_tos() {
        use std::net::Ipv4Addr;
        use std::net::SocketAddr;
        use std::net::SocketAddrV6;

        let sender = UdpSocket::bind("[::]:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        enable_tos(&receiver);

        let SocketAddr::V4(peer) = receiver.local_addr().unwrap() else {
            unreachable!()
        };
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            peer.ip().to_ipv6_mapped(),
            peer.port(),
            0,
            0,
        ));
        let mapped_source = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            sender.local_addr().unwrap().port(),
            0,
            0,
        ));
        let metrics = DefaultMetrics;
        for from in [None, Some(mapped_source)] {
            send_to(
                &sender,
                b"mapped",
                PacketSend {
                    to: mapped,
                    from,
                    segment_size: None,
                    tx_time: None,
                    dscp: Some(TEST_DSCP),
                },
                &metrics,
            )
            .await
            .unwrap();

            let (payload, tos) = recv_tos(&receiver).await;
            assert_eq!(payload, b"mapped");
            assert_eq!(tos >> 2, TEST_DSCP.value());
        }
    }

    #[test]
    fn monotonic_tx_time_checked_arithmetic() {
        let anchor = Instant::now();
        let ahead = anchor.checked_add(Duration::from_nanos(5)).unwrap();
        let behind = anchor.checked_sub(Duration::from_nanos(5)).unwrap();

        assert_eq!(tx_time_from_anchor(anchor, anchor, 42).unwrap(), 42);
        assert_eq!(tx_time_from_anchor(ahead, anchor, 42).unwrap(), 47);
        assert_eq!(tx_time_from_anchor(behind, anchor, 42).unwrap(), 37);
        assert_eq!(
            tx_time_from_anchor(ahead, anchor, u64::MAX - 5).unwrap(),
            u64::MAX
        );
        assert_eq!(tx_time_from_anchor(behind, anchor, 5).unwrap(), 0);

        assert_eq!(
            tx_time_from_anchor(ahead, anchor, u64::MAX - 4)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            tx_time_from_anchor(behind, anchor, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        // Exercise the real CLOCK_MONOTONIC sampling path too; no timing
        // assertions that can fail under CI scheduling delays.
        assert!(monotonic_tx_time(anchor).unwrap() > 0);
    }

    #[test]
    fn monotonic_timespec_checks_kernel_values() {
        let ts = |sec, nsec| libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        };
        assert_eq!(
            monotonic_timespec_ns(ts(2, 999_999_999)).unwrap(),
            2_999_999_999
        );
        for invalid in [ts(-1, 0), ts(0, -1), ts(0, 1_000_000_000)] {
            assert_eq!(
                monotonic_timespec_ns(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        if let Ok(seconds) = libc::time_t::try_from(u64::MAX / 1_000_000_000 + 1)
        {
            assert_eq!(
                monotonic_timespec_ns(ts(seconds, 0)).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[tokio::test]
    async fn invalid_udp_segment_sizes_are_errors_not_truncations() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let metrics = DefaultMetrics;
        for size in [0, usize::from(u16::MAX) + 1, usize::MAX] {
            let err = send_to(
                &sender,
                b"segment",
                PacketSend {
                    to: receiver.local_addr().unwrap(),
                    from: None,
                    segment_size: Some(size),
                    tx_time: None,
                    dscp: None,
                },
                &metrics,
            )
            .await
            .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "size={size}");
        }
    }

    #[tokio::test]
    async fn txtime_control_message_is_accepted_by_linux_socket() {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cfg = libc::sock_txtime {
            clockid: libc::CLOCK_MONOTONIC,
            flags: 0,
        };
        setsockopt(&sender, sockopt::TxTime, &cfg).unwrap();

        let metrics = DefaultMetrics;
        let sent = send_to(
            &sender,
            b"deadline",
            PacketSend {
                to: receiver.local_addr().unwrap(),
                from: None,
                segment_size: None,
                tx_time: Some(Instant::now() + Duration::from_millis(100)),
                dscp: None,
            },
            &metrics,
        )
        .await
        .unwrap();
        assert_eq!(sent, b"deadline".len());
    }
}

#[cfg(test)]
mod send_tests {
    use super::recoverable_send_error;
    use super::send_packets;
    use super::PacketSend;
    use crate::metrics::DefaultMetrics;
    use datagram_socket::DatagramSocketSend;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::task::Context;
    use std::task::Poll;

    #[derive(Default)]
    struct RecordingSocket {
        datagrams: Mutex<Vec<Vec<u8>>>,
        partial: bool,
    }
    impl DatagramSocketSend for RecordingSocket {
        fn poll_send(
            &self, _cx: &mut Context<'_>, buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.datagrams.lock() {
                Ok(mut datagrams) => {
                    datagrams.push(buffer.to_vec());
                    Poll::Ready(Ok(if self.partial {
                        buffer.len().saturating_sub(1)
                    } else {
                        buffer.len()
                    }))
                },
                Err(_) => Poll::Ready(Err(io::Error::other(
                    "recording socket poisoned",
                ))),
            }
        }

        fn poll_send_to(
            &self, cx: &mut Context<'_>, buffer: &[u8], _addr: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            self.poll_send(cx, buffer)
        }
    }

    #[tokio::test]
    async fn transport_wrapper_preserves_gso_datagram_boundaries(
    ) -> crate::QuicResult<()> {
        let socket = RecordingSocket::default();
        let packet = PacketSend {
            to: "127.0.0.1:1234".parse()?,
            from: None,
            segment_size: Some(3),
            tx_time: None,
            dscp: None,
        };
        send_packets(&socket, b"abcdefg", packet, &DefaultMetrics).await?;
        let datagrams = socket
            .datagrams
            .lock()
            .map_err(|_| "recording socket poisoned")?;
        assert_eq!(datagrams.as_slice(), &[
            b"abc".to_vec(),
            b"def".to_vec(),
            b"g".to_vec()
        ]);
        Ok(())
    }

    #[tokio::test]
    async fn partial_datagram_is_a_fatal_transport_contract_error(
    ) -> crate::QuicResult<()> {
        let socket = RecordingSocket {
            partial: true,
            ..RecordingSocket::default()
        };
        let packet = PacketSend {
            to: "127.0.0.1:1234".parse()?,
            from: None,
            segment_size: None,
            tx_time: None,
            dscp: None,
        };
        let error = send_packets(&socket, b"abcdefg", packet, &DefaultMetrics)
            .await
            .err()
            .ok_or("partial send was accepted")?;
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert!(!recoverable_send_error(&error));
        Ok(())
    }

    struct BlockedSocket;

    impl DatagramSocketSend for BlockedSocket {
        fn poll_send(
            &self, _cx: &mut Context<'_>, _buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_send_to(
            &self, cx: &mut Context<'_>, buffer: &[u8], _addr: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            self.poll_send(cx, buffer)
        }
    }

    #[tokio::test]
    async fn blocked_send_releases_at_deadline_and_expired_send_is_not_started(
    ) -> crate::QuicResult<()> {
        tokio::time::pause();
        let packet = PacketSend {
            to: "127.0.0.1:1234".parse()?,
            from: None,
            segment_size: None,
            tx_time: None,
            dscp: None,
        };
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_millis(20);
        assert_eq!(
            super::send_packets_before(
                &BlockedSocket,
                b"packet",
                packet,
                &DefaultMetrics,
                deadline.into_std()
            )
            .await?,
            super::SendOutcome::DeadlineExpired,
        );
        assert!(tokio::time::Instant::now() >= deadline);
        let socket = RecordingSocket::default();
        assert_eq!(
            super::send_packets_before(
                &socket,
                b"expired",
                packet,
                &DefaultMetrics,
                deadline.into_std()
            )
            .await?,
            super::SendOutcome::DeadlineExpired,
        );
        assert!(socket
            .datagrams
            .lock()
            .map_err(|_| "recording socket poisoned")?
            .is_empty());
        let next_deadline =
            tokio::time::Instant::now() + std::time::Duration::from_millis(20);
        assert_eq!(
            super::send_packets_before(
                &socket,
                b"ready",
                packet,
                &DefaultMetrics,
                next_deadline.into_std()
            )
            .await?,
            super::SendOutcome::Sent,
        );
        Ok(())
    }

    #[test]
    fn temporary_network_failures_are_not_fatal_to_the_connection() {
        for kind in [
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::TimedOut,
        ] {
            assert!(recoverable_send_error(&kind.into()));
        }
        for kind in [
            io::ErrorKind::InvalidInput,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::BrokenPipe,
        ] {
            assert!(!recoverable_send_error(&kind.into()));
        }
        #[cfg(target_os = "linux")]
        for errno in [libc::EMSGSIZE, libc::ENOBUFS] {
            assert!(recoverable_send_error(&io::Error::from_raw_os_error(errno)));
        }
    }
}
