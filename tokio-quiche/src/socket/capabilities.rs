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
use libc::c_int;
#[cfg(target_os = "linux")]
use libc::c_void;
#[cfg(target_os = "linux")]
use libc::sock_txtime;
#[cfg(target_os = "linux")]
use libc::socklen_t;
#[cfg(target_os = "linux")]
use libc::IPPROTO_IP;
#[cfg(target_os = "linux")]
use libc::IPPROTO_IPV6;
#[cfg(target_os = "linux")]
use libc::IPV6_MTU_DISCOVER;
#[cfg(target_os = "linux")]
use libc::IPV6_PMTUDISC_PROBE;
#[cfg(target_os = "linux")]
use libc::IP_MTU_DISCOVER;
#[cfg(target_os = "linux")]
use libc::IP_PMTUDISC_PROBE;
#[cfg(target_os = "linux")]
use libc::SOL_SOCKET;
#[cfg(target_os = "linux")]
use libc::SO_RCVMARK;
#[cfg(target_os = "linux")]
use nix::sys::socket::getsockopt;
#[cfg(target_os = "linux")]
use nix::sys::socket::setsockopt;
#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::IpFreebind;
#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::IpTransparent;
#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::Ipv4OrigDstAddr;
#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::Ipv4PacketInfo;
#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::Ipv6OrigDstAddr;
#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::Ipv6RecvPacketInfo;
#[cfg(all(target_os = "linux", feature = "perf-quic-listener-metrics"))]
use nix::sys::socket::sockopt::ReceiveTimestampns;
#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::RxqOvfl;
#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::TxTime;
#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::UdpGroSegment;
#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::UdpGsoSegment;
#[cfg(target_os = "linux")]
use nix::sys::socket::SetSockOpt;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::fd::BorrowedFd;

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
            cap: SocketCapabilities::default(),
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
    ///
    /// # Errors
    /// Returns the operating system error if enabling the socket option fails.
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
    ///
    /// # Errors
    /// Returns the operating system error if enabling the socket option fails.
    pub fn check_udp_drop(&mut self) -> io::Result<()> {
        self.enable(RxqOvfl, &1, SocketCapability::ReceiveDropCount)
    }

    /// Enables [`SO_TXTIME`](https://man7.org/linux/man-pages/man8/tc-etf.8.html)
    /// to control packet transmit timestamps for QUIC pacing.
    ///
    /// # Errors
    /// Returns the operating system error if enabling the socket option fails.
    pub fn txtime(&mut self) -> io::Result<()> {
        let cfg = sock_txtime {
            clockid: libc::CLOCK_MONOTONIC,
            flags: 0,
        };
        self.enable(TxTime, &cfg, SocketCapability::TransmitTime)
    }

    /// Enables [`SO_TIMESTAMPNS`](https://man7.org/linux/man-pages/man7/socket.7.html),
    /// which records a wall-clock timestamp for each received packet.
    ///
    /// # Errors
    /// Returns the operating system error if enabling the socket option fails.
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
    ///
    /// # Errors
    /// Returns the operating system error if enabling the socket option fails.
    pub fn gro(&mut self) -> io::Result<()> {
        self.enable(UdpGroSegment, &true, SocketCapability::Gro)
    }

    /// Enables [`IP_PKTINFO`](https://man7.org/linux/man-pages/man7/ip.7.html)
    /// to control the source IP in outbound IPv4 packets.
    ///
    /// # Errors
    /// Returns the operating system error if enabling the socket option fails.
    pub fn ipv4_pktinfo(&mut self) -> io::Result<()> {
        self.enable(Ipv4PacketInfo, &true, SocketCapability::Ipv4PacketInfo)
    }

    /// Enables [`IP_RECVORIGDSTADDR`](https://man7.org/linux/man-pages/man7/ip.7.html),
    /// which reports each packet's real IPv4 destination address.
    ///
    /// This can be different from the socket's local address due to netfilter
    /// TPROXY rules or eBPF redirects.
    ///
    /// # Errors
    /// Returns the operating system error if enabling the socket option fails.
    pub fn ipv4_recvorigdstaddr(&mut self) -> io::Result<()> {
        self.enable(
            Ipv4OrigDstAddr,
            &true,
            SocketCapability::Ipv4OriginalDestination,
        )
    }

    /// Enables [`IPV6_RECVPKTINFO`](https://man7.org/linux/man-pages/man7/ipv6.7.html)
    /// to control the source IP in outbound IPv6 packets.
    ///
    /// # Errors
    /// Returns the operating system error if enabling the socket option fails.
    pub fn ipv6_pktinfo(&mut self) -> io::Result<()> {
        self.enable(Ipv6RecvPacketInfo, &true, SocketCapability::Ipv6PacketInfo)
    }

    /// Enables [`IPV6_RECVORIGDSTADDR`](https://elixir.bootlin.com/linux/v6.12/source/net/ipv6/datagram.c#L722-L743),
    /// which reports each packet's real IPv6 destination address.
    ///
    /// This can be different from the socket's local address due to netfilter
    /// TPROXY rules or eBPF redirects.
    ///
    /// # Errors
    /// Returns the operating system error if enabling the socket option fails.
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
    ///
    /// # Errors
    /// Returns the operating system error if enabling the socket option fails.
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
    ///
    /// # Errors
    /// Returns the operating system error if enabling the socket option fails.
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
    ///
    /// # Errors
    /// Returns the socket query error if reading either option fails.
    pub fn allows_nonlocal_source(&self) -> io::Result<bool> {
        Ok(getsockopt(&self.socket.as_fd(), IpFreebind)? ||
            getsockopt(&self.socket.as_fd(), IpTransparent)?)
    }

    /// Enables `SO_RCVMARK` to receive the packet mark as ancillary data.
    ///
    /// # Errors
    /// Returns the operating system error if enabling the socket option fails.
    pub fn rcvmark(&mut self) -> io::Result<()> {
        self.enable_integer(
            SOL_SOCKET,
            SO_RCVMARK,
            1,
            SocketCapability::ReceiveMark,
        )
    }

    /// Consumes the builder and returns the configured [`SocketCapabilities`].
    #[must_use = "the returned set records the successfully enabled capabilities"]
    pub const fn finish(self) -> SocketCapabilities {
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
    #[must_use = "the result indicates whether the option is available"]
    pub const fn contains(self, capability: SocketCapability) -> bool {
        self.0 & capability.mask() != 0
    }

    /// Whether source address selection is supported for this address family.
    /// IPv4-mapped IPv6 addresses use IPv4 control messages on Linux.
    #[must_use = "the result determines whether the source address can be selected"]
    pub const fn supports_pktinfo(self, addr: std::net::SocketAddr) -> bool {
        self.contains(match addr {
            std::net::SocketAddr::V4(_) => SocketCapability::Ipv4PacketInfo,
            std::net::SocketAddr::V6(addr)
                if addr.ip().to_ipv4_mapped().is_some() =>
                SocketCapability::Ipv4PacketInfo,
            std::net::SocketAddr::V6(_) => SocketCapability::Ipv6PacketInfo,
        })
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
        // Packet information is useful on ordinary wildcard-bound sockets too:
        // it preserves the actual destination and lets replies use that source.
        let _ = b.ipv4_pktinfo();
        let _ = b.ipv6_pktinfo();
        if matches!(b.allows_nonlocal_source(), Ok(true)) {
            let _ = b.ipv4_recvorigdstaddr();
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
