// Copyright (C) 2021, Cloudflare, Inc.
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

use std::cmp;

use std::io;

/// For Linux, try to detect GSO is available.
#[cfg(target_os = "linux")]
pub fn detect_gso(socket: &mio::net::UdpSocket, segment_size: usize) -> bool {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::UdpGsoSegment;
    use std::os::unix::io::AsFd;

    let Ok(size) = valid_gso_segment_size(segment_size) else {
        return false;
    };
    setsockopt(&socket.as_fd(), UdpGsoSegment, &i32::from(size)).is_ok()
}

#[cfg(target_os = "linux")]
fn valid_gso_segment_size(segment_size: usize) -> io::Result<u16> {
    u16::try_from(segment_size)
        .ok()
        .filter(|size| *size != 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP GSO segment size must be in 1..=65535",
            )
        })
}

/// For non-Linux, there is no GSO support.
#[cfg(not(target_os = "linux"))]
pub fn detect_gso(_socket: &mio::net::UdpSocket, _segment_size: usize) -> bool {
    false
}

/// Send packets using sendmsg() with GSO.
#[cfg(target_os = "linux")]
fn send_to_gso_pacing(
    socket: &mio::net::UdpSocket, buf: &[u8], send_info: &quiche::SendInfo,
    segment_size: usize,
) -> io::Result<usize> {
    use nix::sys::socket::sendmsg;
    use nix::sys::socket::ControlMessage;
    use nix::sys::socket::MsgFlags;
    use nix::sys::socket::SockaddrStorage;
    use std::io::IoSlice;
    use std::os::unix::io::AsRawFd;

    let iov = [IoSlice::new(buf)];
    let segment_size = valid_gso_segment_size(segment_size)?;
    let dst = SockaddrStorage::from(send_info.to);
    let sockfd = socket.as_raw_fd();

    // GSO option.
    let cmsg_gso = ControlMessage::UdpGsoSegments(&segment_size);

    // Pacing option.
    let send_time = std_time_to_u64(&send_info.at)?;
    let cmsg_txtime = ControlMessage::TxTime(&send_time);

    match sendmsg(
        sockfd,
        &iov,
        &[cmsg_gso, cmsg_txtime],
        MsgFlags::empty(),
        Some(&dst),
    ) {
        Ok(v) => Ok(v),
        Err(e) => Err(e.into()),
    }
}

/// A wrapper function of send_to().
///
/// When GSO and SO_TXTIME are enabled, send packets using send_to_gso().
/// Otherwise, send packets using socket.send_to().
pub fn send_to(
    socket: &mio::net::UdpSocket, buf: &[u8], send_info: &quiche::SendInfo,
    segment_size: usize, pacing: bool, enable_gso: bool,
) -> io::Result<usize> {
    if segment_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP segment size must be positive",
        ));
    }

    #[cfg(target_os = "linux")]
    if pacing && enable_gso {
        return send_to_gso_pacing(socket, buf, send_info, segment_size);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (pacing, enable_gso);

    let mut off = 0;
    let mut left = buf.len();
    let mut written = 0;

    while left > 0 {
        let pkt_len = cmp::min(left, segment_size);

        {
            let v = socket.send_to(&buf[off..off + pkt_len], send_info.to)?;
            written += v;
        }

        off += pkt_len;
        left -= pkt_len;
    }

    Ok(written)
}

#[cfg(target_os = "linux")]
fn monotonic_timespec_ns(ts: libc::timespec) -> io::Result<u64> {
    const NANOS_PER_SECOND: u64 = 1_000_000_000;

    let seconds =
        u64::try_from(ts.tv_sec).map_err(|_| io::ErrorKind::InvalidData)?;
    let nanoseconds =
        u64::try_from(ts.tv_nsec).map_err(|_| io::ErrorKind::InvalidData)?;
    if nanoseconds >= NANOS_PER_SECOND {
        return Err(io::ErrorKind::InvalidData.into());
    }
    seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|seconds| seconds.checked_add(nanoseconds))
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}

#[cfg(target_os = "linux")]
fn deadline_from_anchor(
    deadline: std::time::Instant, anchor: std::time::Instant, anchor_ns: u64,
) -> io::Result<u64> {
    let (forward, difference) = if deadline >= anchor {
        (true, deadline.duration_since(anchor))
    } else {
        (false, anchor.duration_since(deadline))
    };
    let difference_ns = u64::try_from(difference.as_nanos())
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    if forward {
        anchor_ns.checked_add(difference_ns)
    } else {
        anchor_ns.checked_sub(difference_ns)
    }
    .ok_or_else(|| io::ErrorKind::InvalidInput.into())
}

/// Convert Rust's opaque Instant into the CLOCK_MONOTONIC nanoseconds expected
/// by Linux SCM_TXTIME, without depending on Instant's private layout.
#[cfg(target_os = "linux")]
fn std_time_to_u64(deadline: &std::time::Instant) -> io::Result<u64> {
    // The socket is configured with CLOCK_MONOTONIC. Bracket the kernel clock
    // read to bound the sampling error even if the thread is preempted.
    let before = std::time::Instant::now();
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid writable timespec that clock_gettime fills on
    // success.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let after = std::time::Instant::now();
    let span = after
        .checked_duration_since(before)
        .ok_or(io::ErrorKind::InvalidData)?;
    let anchor = before
        .checked_add(span / 2)
        .ok_or(io::ErrorKind::InvalidData)?;
    deadline_from_anchor(*deadline, anchor, monotonic_timespec_ns(ts)?)
}

#[cfg(test)]
mod pacing_tests {
    use super::*;

    fn addresses() -> io::Result<(mio::net::UdpSocket, quiche::SendInfo)> {
        let sender = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0")?;
        sender.set_nonblocking(true)?;
        let info = quiche::SendInfo {
            from: sender.local_addr()?,
            to: receiver.local_addr()?,
            at: std::time::Instant::now(),
        };
        Ok((mio::net::UdpSocket::from_std(sender), info))
    }

    #[test]
    fn zero_segment_is_rejected_instead_of_looping_forever() -> io::Result<()> {
        let (sender, info) = addresses()?;
        for (pacing, gso) in [(false, false), (true, true)] {
            let error = send_to(&sender, b"payload", &info, 0, pacing, gso)
                .expect_err("zero segment must be an error");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn monotonic_clock_conversion_is_checked_and_deterministic() {
        use std::time::Duration;

        let now = std::time::Instant::now();
        let ahead = now.checked_add(Duration::from_nanos(5)).unwrap();
        let behind = now.checked_sub(Duration::from_nanos(5)).unwrap();

        assert_eq!(deadline_from_anchor(now, now, 42).unwrap(), 42);
        assert_eq!(deadline_from_anchor(ahead, now, 42).unwrap(), 47);
        assert_eq!(deadline_from_anchor(behind, now, 42).unwrap(), 37);
        assert_eq!(
            deadline_from_anchor(ahead, now, u64::MAX - 5).unwrap(),
            u64::MAX
        );
        assert_eq!(deadline_from_anchor(behind, now, 5).unwrap(), 0);
        assert_eq!(
            deadline_from_anchor(ahead, now, u64::MAX - 4)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            deadline_from_anchor(behind, now, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        assert!(std_time_to_u64(&now).unwrap() > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_timespec_and_gso_segment_bounds_are_validated() {
        let ts = |sec, nsec| libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        };
        assert_eq!(
            monotonic_timespec_ns(ts(1, 999_999_999)).unwrap(),
            1_999_999_999
        );
        for invalid in [ts(-1, 0), ts(0, -1), ts(0, 1_000_000_000)] {
            assert_eq!(
                monotonic_timespec_ns(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        if let Ok(secs) = libc::time_t::try_from(u64::MAX / 1_000_000_000 + 1) {
            assert_eq!(
                monotonic_timespec_ns(ts(secs, 0)).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(valid_gso_segment_size(1).unwrap(), 1);
        assert_eq!(valid_gso_segment_size(u16::MAX as usize).unwrap(), u16::MAX);
        for invalid in [0, u16::MAX as usize + 1, usize::MAX] {
            assert_eq!(
                valid_gso_segment_size(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
