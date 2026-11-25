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

#[cfg(target_os = "linux")]
mod linux_imports {
    pub use libc::c_int;
    pub use libc::c_void;
    pub use libc::sock_txtime;
    pub use libc::socklen_t;
    pub use libc::IPPROTO_IP;
    pub use libc::IPPROTO_IPV6;
    pub use libc::IPV6_MTU_DISCOVER;
    pub use libc::IPV6_PMTUDISC_PROBE;
    pub use libc::IP_MTU_DISCOVER;
    pub use libc::IP_PMTUDISC_PROBE;
    pub use libc::SOL_SOCKET;
    pub use libc::SO_RCVMARK;
    pub use nix::sys::socket::getsockopt;
    pub use nix::sys::socket::setsockopt;
    pub use nix::sys::socket::sockopt::IpFreebind;
    pub use nix::sys::socket::sockopt::IpTransparent;
    pub use nix::sys::socket::sockopt::Ipv4OrigDstAddr;
    pub use nix::sys::socket::sockopt::Ipv4PacketInfo;
    pub use nix::sys::socket::sockopt::Ipv6OrigDstAddr;
    pub use nix::sys::socket::sockopt::Ipv6RecvPacketInfo;
    #[cfg(feature = "perf-quic-listener-metrics")]
    pub use nix::sys::socket::sockopt::ReceiveTimestampns;
    pub use nix::sys::socket::sockopt::RxqOvfl;
    pub use nix::sys::socket::sockopt::TxTime;
    pub use nix::sys::socket::sockopt::UdpGroSegment;
    pub use nix::sys::socket::sockopt::UdpGsoSegment;
    pub use nix::sys::socket::SetSockOpt;
    pub use std::io;
    pub use std::os::fd::AsFd;
    pub use std::os::fd::AsRawFd;
    pub use std::os::fd::BorrowedFd;
}

#[cfg(target_os = "linux")]
use linux_imports::*;

/// Integer-valued Linux socket options not exposed by nix.
#[cfg(target_os = "linux")]
fn set_integer_option(
    socket: BorrowedFd<'_>, level: c_int, option: c_int, value: c_int,
) -> io::Result<()> {
    let length =
        socklen_t::try_from(size_of::<c_int>()).map_err(io::Error::other)?;
    // SAFETY: the borrowed descriptor stays alive for the call, and value
    // points to an initialized integer of exactly the supplied length.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&raw const value).cast::<c_void>(),
            length,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Builder to enable Linux sockopts which improve QUIC performance.
#[cfg(target_os = "linux")]
pub struct SocketCapabilitiesBuilder<'s> {
    socket: BorrowedFd<'s>,
    cap: SocketCapabilities,
}

#[cfg(target_os = "linux")]
impl<'s> SocketCapabilitiesBuilder<'s> {
    /// Creates a new sockopt builder for `socket`.
    pub fn new<S: AsFd>(socket: &'s S) -> Self {
        Self {
            socket: socket.as_fd(),
            cap: Default::default(),
        }
    }

    fn enable<O: SetSockOpt>(
        &mut self, option: O, value: &O::Val, capability: SocketCapability,
    ) -> io::Result<()> {
        setsockopt(&self.socket, option, value)?;
        self.cap.insert(capability);
        Ok(())
    }

    fn enable_integer(
        &mut self, level: c_int, option: c_int, value: c_int,
        capability: SocketCapability,
    ) -> io::Result<()> {
        set_integer_option(self.socket, level, option, value)?;
        self.cap.insert(capability);
        Ok(())
    }

    /// Enables [`UDP_SEGMENT`](https://man7.org/linux/man-pages/man7/udp.7.html),
    /// a generic segmentation offload (GSO).
    ///
    /// GSO improves transmit performance by treating multiple sequential UDP
    /// packets as a single entity in the kernel. Segmentation into
    /// individual packets happens in the NIC, if it supports GSO. The
    /// parameter specifies the packet size.
    pub fn gso(&mut self) -> io::Result<()> {
        // Initialize GSO with the maximum segment size so later increases to
        // `max_send_udp_payload_size` do not exceed the initial setting.
        //
        // https://elixir.bootlin.com/linux/v6.14.6/source/net/ipv4/udp.c#L2998
        // https://elixir.bootlin.com/linux/v6.14.6/source/include/vdso/limits.h#L5
        self.enable(UdpGsoSegment, &i32::from(u16::MAX), SocketCapability::Gso)
    }

    /// Enables [`SO_RXQ_OVFL`](https://man7.org/linux/man-pages/man7/socket.7.html),
    /// which reports dropped packets due to insufficient buffer space.
    pub fn check_udp_drop(&mut self) -> io::Result<()> {
        self.enable(RxqOvfl, &1, SocketCapability::ReceiveDropCount)
    }

    /// Enables [`SO_TXTIME`](https://man7.org/linux/man-pages/man8/tc-etf.8.html)
    /// to control packet transmit timestamps for QUIC pacing.
    pub fn txtime(&mut self) -> io::Result<()> {
        let cfg = sock_txtime {
            clockid: libc::CLOCK_MONOTONIC,
            flags: 0,
        };
        self.enable(TxTime, &cfg, SocketCapability::TransmitTime)
    }

    /// Enables [`SO_TIMESTAMPNS`](https://man7.org/linux/man-pages/man7/socket.7.html),
    /// which records a wall-clock timestamp for each received packet.
    #[cfg(feature = "perf-quic-listener-metrics")]
    pub fn rxtime(&mut self) -> io::Result<()> {
        self.enable(
            ReceiveTimestampns,
            &true,
            SocketCapability::ReceiveTimestamp,
        )
    }

    /// Enables [`UDP_GRO`](https://man7.org/linux/man-pages/man7/udp.7.html),
    /// a generic receive offload (GRO).
    ///
    /// GRO improves receive performance by allowing the kernel to yield
    /// multiple UDP packets in one [`recvmsg(2)`](https://man7.org/linux/man-pages/man2/recv.2.html)
    /// call. It is the equivalent of GSO for the receive path.
    pub fn gro(&mut self) -> io::Result<()> {
        self.enable(UdpGroSegment, &true, SocketCapability::Gro)
    }

    /// Enables [`IP_PKTINFO`](https://man7.org/linux/man-pages/man7/ip.7.html)
    /// to control the source IP in outbound IPv4 packets.
    pub fn ipv4_pktinfo(&mut self) -> io::Result<()> {
        self.enable(Ipv4PacketInfo, &true, SocketCapability::Ipv4PacketInfo)
    }

    /// Enables [`IP_RECVORIGDSTADDR`](https://man7.org/linux/man-pages/man7/ip.7.html),
    /// which reports each packet's real IPv4 destination address.
    ///
    /// This can be different from the socket's local address due to netfilter
    /// TPROXY rules or eBPF redirects.
    pub fn ipv4_recvorigdstaddr(&mut self) -> io::Result<()> {
        self.enable(
            Ipv4OrigDstAddr,
            &true,
            SocketCapability::Ipv4OriginalDestination,
        )
    }

    /// Enables [`IPV6_RECVPKTINFO`](https://man7.org/linux/man-pages/man7/ipv6.7.html)
    /// to control the source IP in outbound IPv6 packets.
    pub fn ipv6_pktinfo(&mut self) -> io::Result<()> {
        self.enable(Ipv6RecvPacketInfo, &true, SocketCapability::Ipv6PacketInfo)
    }

    /// Enables [`IPV6_RECVORIGDSTADDR`](https://elixir.bootlin.com/linux/v6.12/source/net/ipv6/datagram.c#L722-L743),
    /// which reports each packet's real IPv6 destination address.
    ///
    /// This can be different from the socket's local address due to netfilter
    /// TPROXY rules or eBPF redirects.
    pub fn ipv6_recvorigdstaddr(&mut self) -> io::Result<()> {
        self.enable(
            Ipv6OrigDstAddr,
            &true,
            SocketCapability::Ipv6OriginalDestination,
        )
    }

    /// Sets [`IP_MTU_DISCOVER`](https://man7.org/linux/man-pages/man7/ip.7.html), to
    /// `IP_PMTUDISC_PROBE`, which disables kernel PMTUD and sets the `DF`
    /// (Don't Fragment) flag.
    pub fn ip_mtu_discover_probe(&mut self) -> io::Result<()> {
        self.enable_integer(
            IPPROTO_IP,
            IP_MTU_DISCOVER,
            IP_PMTUDISC_PROBE,
            SocketCapability::Ipv4MtuProbe,
        )
    }

    /// Sets [`IPV6_MTU_DISCOVER`](https://man7.org/linux/man-pages/man7/ipv6.7.html), to
    /// `IPV6_PMTUDISC_PROBE`, which disables kernel PMTUD and sets the `DF`
    /// (Don't Fragment) flag.
    pub fn ipv6_mtu_discover_probe(&mut self) -> io::Result<()> {
        self.enable_integer(
            IPPROTO_IPV6,
            IPV6_MTU_DISCOVER,
            IPV6_PMTUDISC_PROBE,
            SocketCapability::Ipv6MtuProbe,
        )
    }

    /// Tests whether [`IP_FREEBIND`](https://man7.org/linux/man-pages/man7/ip.7.html)
    /// or [`IP_TRANSPARENT`](https://man7.org/linux/man-pages/man7/ip.7.html) are
    /// enabled for this socket.
    ///
    /// # Warning
    /// These sockopts require elevated permissions to enable, so the builder
    /// will only check their status. **If neither of them is enabled, the
    /// `PKTINFO` sockopts will cause errors when sending packets.**
    pub fn allows_nonlocal_source(&self) -> io::Result<bool> {
        Ok(getsockopt(&self.socket.as_fd(), IpFreebind)? ||
            getsockopt(&self.socket.as_fd(), IpTransparent)?)
    }

    pub fn rcvmark(&mut self) -> io::Result<()> {
        self.enable_integer(
            SOL_SOCKET,
            SO_RCVMARK,
            1,
            SocketCapability::ReceiveMark,
        )
    }

    /// Consumes the builder and returns the configured [`SocketCapabilities`].
    pub fn finish(self) -> SocketCapabilities {
        self.cap
    }
}

/// Socket options successfully enabled by the builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SocketCapability {
    /// UDP segmentation offload.
    Gso,
    /// Receive queue overflow counter.
    ReceiveDropCount,
    /// Kernel transmit scheduling.
    TransmitTime,
    /// Nanosecond receive timestamp.
    ReceiveTimestamp,
    /// UDP generic receive offload.
    Gro,
    /// IPv4 source/destination packet information.
    Ipv4PacketInfo,
    /// IPv4 original destination address.
    Ipv4OriginalDestination,
    /// IPv6 source/destination packet information.
    Ipv6PacketInfo,
    /// IPv6 original destination address.
    Ipv6OriginalDestination,
    /// IPv4 probe-mode path MTU discovery.
    Ipv4MtuProbe,
    /// IPv6 probe-mode path MTU discovery.
    Ipv6MtuProbe,
    /// Receive socket mark.
    ReceiveMark,
}

impl SocketCapability {
    const ALL: [Self; 12] = [
        Self::Gso,
        Self::ReceiveDropCount,
        Self::TransmitTime,
        Self::ReceiveTimestamp,
        Self::Gro,
        Self::Ipv4PacketInfo,
        Self::Ipv4OriginalDestination,
        Self::Ipv6PacketInfo,
        Self::Ipv6OriginalDestination,
        Self::Ipv4MtuProbe,
        Self::Ipv6MtuProbe,
        Self::ReceiveMark,
    ];

    const fn mask(self) -> u16 {
        1 << self as u8
    }
}

/// Compact set of enabled socket options. Failed probes never add a capability.
/// All options are disabled by default, including on non-Linux targets.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct SocketCapabilities(u16);

impl std::fmt::Debug for SocketCapabilities {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_set().entries(self.iter()).finish()
    }
}

impl SocketCapabilities {
    /// Reports whether a capability has been successfully enabled.
    pub const fn contains(self, capability: SocketCapability) -> bool {
        self.0 & capability.mask() != 0
    }

    /// Derives a capability set with a particular option disabled by policy.
    #[must_use = "the returned capability set contains the policy change"]
    pub const fn without(self, capability: SocketCapability) -> Self {
        Self(self.0 & !capability.mask())
    }

    /// Lists the enabled capabilities.
    pub fn iter(self) -> impl Iterator<Item = SocketCapability> {
        SocketCapability::ALL
            .into_iter()
            .filter(move |capability| self.contains(*capability))
    }

    #[cfg(any(target_os = "linux", test))]
    const fn insert(&mut self, capability: SocketCapability) {
        self.0 |= capability.mask();
    }

    /// Tries to enable all supported sockopts and returns indicators
    /// of which settings were successfully applied.
    #[cfg(target_os = "linux")]
    pub fn apply_all_and_get_compatibility<S>(socket: &S) -> Self
    where
        S: AsFd,
    {
        let mut b = SocketCapabilitiesBuilder::new(socket);
        let _ = b.gso();
        let _ = b.check_udp_drop();
        let _ = b.txtime();
        #[cfg(feature = "perf-quic-listener-metrics")]
        let _ = b.rxtime();
        let _ = b.gro();
        let _ = b.rcvmark();

        // We can't determine if this is an IPv4 or IPv6 socket, so try setting
        // the relevant options for both
        let _ = b.ip_mtu_discover_probe();
        let _ = b.ipv6_mtu_discover_probe();
        if let Ok(true) = b.allows_nonlocal_source() {
            let _ = b.ipv4_pktinfo();
            let _ = b.ipv4_recvorigdstaddr();
            let _ = b.ipv6_pktinfo();
            let _ = b.ipv6_recvorigdstaddr();
        }
        b.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::SocketCapabilities;
    use super::SocketCapability;

    #[test]
    fn capability_set_preserves_independent_flags() {
        let mut capabilities = SocketCapabilities::default();
        assert_eq!(capabilities.iter().count(), 0);
        for (count, capability) in SocketCapability::ALL.into_iter().enumerate() {
            assert!(!capabilities.contains(capability));
            capabilities.insert(capability);
            assert!(capabilities.contains(capability));
            assert_eq!(capabilities.iter().count(), count + 1);
        }
        assert_eq!(
            capabilities.iter().collect::<Vec<_>>(),
            SocketCapability::ALL
        );
    }

    #[test]
    fn disabling_one_capability_preserves_every_other_flag() {
        let mut enabled = SocketCapabilities::default();
        for capability in SocketCapability::ALL {
            enabled.insert(capability);
        }
        for disabled in SocketCapability::ALL {
            let effective = enabled.without(disabled);
            for capability in SocketCapability::ALL {
                assert_eq!(
                    effective.contains(capability),
                    capability != disabled
                );
                assert!(enabled.contains(capability));
            }
            assert_eq!(effective.without(disabled), effective);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_socket_option_does_not_record_capability() -> std::io::Result<()> {
        let file = std::fs::File::open("/dev/null")?;
        let mut builder = super::SocketCapabilitiesBuilder::new(&file);
        assert!(builder.gro().is_err());
        assert!(builder.ip_mtu_discover_probe().is_err());
        assert_eq!(builder.finish(), SocketCapabilities::default());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successful_integer_and_typed_options_are_recorded() -> std::io::Result<()>
    {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let mut builder = super::SocketCapabilitiesBuilder::new(&socket);
        builder.ip_mtu_discover_probe()?;
        builder.check_udp_drop()?;
        let capabilities = builder.finish();
        assert!(capabilities.contains(SocketCapability::Ipv4MtuProbe));
        assert!(capabilities.contains(SocketCapability::ReceiveDropCount));
        assert!(!capabilities.contains(SocketCapability::Ipv6MtuProbe));
        Ok(())
    }
}
