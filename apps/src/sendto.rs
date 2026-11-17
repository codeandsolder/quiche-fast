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

    setsockopt(&socket.as_fd(), UdpGsoSegment, &(segment_size as i32)).is_ok()
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
    let segment_size = segment_size as u16;
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

/// For non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn send_to_gso_pacing(
    _socket: &mio::net::UdpSocket, _buf: &[u8], _send_info: &quiche::SendInfo,
    _segment_size: usize,
) -> io::Result<usize> {
    panic!("send_to_gso() should not be called on non-linux platforms");
}

/// A wrapper function of send_to().
///
/// When GSO and SO_TXTIME are enabled, send packets using send_to_gso().
/// Otherwise, send packets using socket.send_to().
pub fn send_to(
    socket: &mio::net::UdpSocket, buf: &[u8], send_info: &quiche::SendInfo,
    segment_size: usize, pacing: bool, enable_gso: bool,
) -> io::Result<usize> {
    if pacing && enable_gso {
        match send_to_gso_pacing(socket, buf, send_info, segment_size) {
            Ok(v) => {
                return Ok(v);
            },
            Err(e) => {
                return Err(e);
            },
        }
    }

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
fn std_time_to_u64(deadline: &std::time::Instant) -> io::Result<u64> {
    let now = std::time::Instant::now();
    let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: clock_gettime initializes the timespec on success.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: clock_gettime returned success.
    let ts = unsafe { ts.assume_init() };
    let secs =
        u64::try_from(ts.tv_sec).map_err(|_| io::ErrorKind::InvalidData)?;
    let nanos =
        u64::try_from(ts.tv_nsec).map_err(|_| io::ErrorKind::InvalidData)?;
    if nanos >= 1_000_000_000 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let base = secs
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(nanos))
        .ok_or(io::ErrorKind::InvalidData)?;
    let result = if *deadline >= now {
        u64::try_from(deadline.duration_since(now).as_nanos())
            .ok()
            .and_then(|delta| base.checked_add(delta))
    } else {
        u64::try_from(now.duration_since(*deadline).as_nanos())
            .ok()
            .and_then(|delta| base.checked_sub(delta))
    };
    result.ok_or_else(|| io::ErrorKind::InvalidInput.into())
}

#[cfg(all(test, target_os = "linux"))]
mod pacing_tests {
    use super::*;
    #[test]
    fn monotonic_deadlines_are_ordered() {
        let now = std::time::Instant::now();
        let earlier = std_time_to_u64(&now).unwrap();
        let later =
            std_time_to_u64(&(now + std::time::Duration::from_millis(50)))
                .unwrap();
        assert!(later > earlier);
        assert!(later.abs_diff(earlier).abs_diff(50_000_000) < 10_000_000);
    }
}
