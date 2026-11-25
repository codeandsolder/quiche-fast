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

use std::io;
use std::ops::Range;

use mio::net::UdpSocket;
use mio::Interest;
use mio::Registry;
use mio::Token;

/// Contiguous datagrams with a compatible route, deadline and GSO stride.
/// Every segment except the last must have exactly that stride.
#[derive(Clone, Debug)]
pub struct DatagramBatch {
    bytes: Range<usize>,
    segment_size: usize,
    info: quiche::SendInfo,
    pacing: bool,
}

impl DatagramBatch {
    /// Append a generated datagram, combining compatible neighbors.
    pub fn push(
        batches: &mut Vec<Self>, bytes: Range<usize>, info: quiche::SendInfo,
        pacing: bool,
    ) {
        if bytes.is_empty() {
            return;
        }
        let len = bytes.len();
        if let Some(batch) = batches.last_mut() {
            if batch.info.from == info.from &&
                batch.info.to == info.to &&
                batch.pacing == pacing &&
                (!pacing ||
                    batch.info.at == info.at ||
                    batch.info.at.max(info.at) <= std::time::Instant::now()) &&
                batch.bytes.end == bytes.start &&
                batch.bytes.len().is_multiple_of(batch.segment_size) &&
                batch.bytes.len() / batch.segment_size < 64 &&
                len <= batch.segment_size
            {
                batch.bytes.end = bytes.end;
                // Distinct deadlines may share a GSO operation only when both
                // are already due. Retain the later deadline for submission.
                batch.info.at = batch.info.at.max(info.at);
                return;
            }
        }
        batches.push(Self {
            bytes,
            segment_size: len,
            info,
            pacing,
        });
    }
}

/// Owns at most one generated burst per UDP socket.
///
/// Swapping the scratch buffer transfers ownership without copying packet
/// payloads. Backpressure
/// preserves the unsent datagrams, without replaying accepted datagrams.
pub struct DatagramQueue {
    buffer: Vec<u8>,
    batches: Vec<DatagramBatch>,
    next: usize,
    writable_interest: bool,
    gso: bool,
}

impl DatagramQueue {
    /// Allocate a reusable buffer with the same size as the producer's scratch
    /// buffer.
    #[must_use = "the queue owns generated datagrams until the socket accepts them"]
    pub fn new(buffer_size: usize, gso: bool) -> Self {
        Self {
            buffer: vec![0; buffer_size],
            batches: Vec::new(),
            next: 0,
            writable_interest: false,
            gso: gso && cfg!(target_os = "linux"),
        }
    }

    /// Whether generated datagrams remain unsent.
    #[must_use = "pending packets must be drained before generating another burst"]
    pub const fn is_pending(&self) -> bool {
        self.next < self.batches.len()
    }

    /// Transfer a complete generated burst into an empty queue.
    ///
    /// # Errors
    /// Returns an error if a burst is already pending, or ranges are invalid.
    pub fn stage(
        &mut self, output: &mut Vec<u8>, batches: &mut Vec<DatagramBatch>,
    ) -> io::Result<()> {
        if self.is_pending() ||
            batches.iter().any(|batch| {
                batch.bytes.end > output.len() || batch.bytes.is_empty()
            })
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.batches.clear();
        self.next = 0;
        std::mem::swap(&mut self.buffer, output);
        std::mem::swap(&mut self.batches, batches);
        Ok(())
    }

    /// Attempt to flush the queued burst, updating writable readiness interest.
    ///
    /// # Errors
    /// Returns socket or registration errors, or an invalid datagram write.
    /// `WouldBlock` is reported by returning false, with the unsent suffix
    /// retained.
    pub fn flush(
        &mut self, socket: &mut UdpSocket, registry: &Registry, token: Token,
    ) -> io::Result<bool> {
        let drained = self.flush_with(|bytes, info, stride, pacing| {
            transmit(socket, bytes, info, stride, pacing)
        })?;
        let need_writable = !drained;
        if self.writable_interest != need_writable {
            let interest = if need_writable {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            registry.reregister(socket, token, interest)?;
            self.writable_interest = need_writable;
        }
        Ok(drained)
    }

    /// Transfer a generated burst and immediately attempt to transmit it.
    ///
    /// # Errors
    /// Returns invalid range, socket or readiness registration errors.
    pub fn submit(
        &mut self, output: &mut Vec<u8>, batches: &mut Vec<DatagramBatch>,
        socket: &mut UdpSocket, registry: &Registry, token: Token,
    ) -> io::Result<bool> {
        self.stage(output, batches)?;
        self.flush(socket, registry, token)
    }

    fn flush_with(
        &mut self,
        mut send: impl FnMut(
            &[u8],
            &quiche::SendInfo,
            Option<usize>,
            bool,
        ) -> io::Result<usize>,
    ) -> io::Result<bool> {
        while let Some(batch) = self.batches.get_mut(self.next) {
            let remaining = batch.bytes.len();
            let stride = (self.gso && remaining > batch.segment_size)
                .then_some(batch.segment_size);
            let len = if stride.is_some() {
                remaining
            } else {
                remaining.min(batch.segment_size)
            };
            let end = batch.bytes.start + len;
            let bytes = &self.buffer[batch.bytes.start..end];
            match send(bytes, &batch.info, stride, batch.pacing) {
                Ok(written) if written == len => batch.bytes.start = end,
                Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted =>
                    continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock =>
                    return Ok(false),
                Err(error) => return Err(error),
            }
            if batch.bytes.is_empty() {
                self.next += 1;
            }
        }
        self.batches.clear();
        self.next = 0;
        Ok(true)
    }
}

/// For Linux, try to detect GSO is available.
#[cfg(target_os = "linux")]
pub fn detect_gso(socket: &mio::net::UdpSocket, segment_size: usize) -> bool {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::UdpGsoSegment;
    use std::os::unix::io::AsFd;

    let Ok(size) = valid_gso_segment_size(segment_size) else {
        return false;
    };
    // Probe support but leave the socket default unsegmented. Individual
    // batches carry their own UDP_SEGMENT control message.
    setsockopt(&socket.as_fd(), UdpGsoSegment, &i32::from(size)).is_ok() &&
        setsockopt(&socket.as_fd(), UdpGsoSegment, &0).is_ok()
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

/// Transmit one UDP datagram or an atomic GSO batch. Pacing is independent
/// of GSO: each operation carries its actual deadline when requested.
#[cfg(target_os = "linux")]
fn transmit(
    socket: &UdpSocket, buf: &[u8], info: &quiche::SendInfo,
    stride: Option<usize>, pacing: bool,
) -> io::Result<usize> {
    use nix::sys::socket::sendmsg;
    use nix::sys::socket::ControlMessage;
    use nix::sys::socket::MsgFlags;
    use nix::sys::socket::SockaddrStorage;
    use std::io::IoSlice;
    use std::os::unix::io::AsRawFd;

    if stride.is_none() && !pacing {
        return socket.send_to(buf, info.to);
    }
    let iov = [IoSlice::new(buf)];
    let dst = SockaddrStorage::from(info.to);
    let segment_size = stride.map(valid_gso_segment_size).transpose()?;
    let send_time = pacing.then(|| std_time_to_u64(&info.at)).transpose()?;
    let gso = ControlMessage::UdpGsoSegments(segment_size.as_ref().unwrap_or(&0));
    let txtime = ControlMessage::TxTime(send_time.as_ref().unwrap_or(&0));
    let messages = [gso, txtime];
    let messages = match (segment_size.is_some(), send_time.is_some()) {
        (true, true) => &messages[..],
        (true, false) => &messages[..1],
        (false, true) => &messages[1..],
        (false, false) => &messages[..0],
    };
    sendmsg(
        socket.as_raw_fd(),
        &iov,
        messages,
        MsgFlags::empty(),
        Some(&dst),
    )
    .map_err(Into::into)
}

#[cfg(not(target_os = "linux"))]
fn transmit(
    socket: &UdpSocket, buf: &[u8], info: &quiche::SendInfo,
    _stride: Option<usize>, _pacing: bool,
) -> io::Result<usize> {
    socket.send_to(buf, info.to)
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

/// Convert Rust's opaque `Instant` into the `CLOCK_MONOTONIC` nanoseconds
/// expected by Linux `SCM_TXTIME`, without depending on `Instant`'s private
/// layout.
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
    fn datagram_batches_preserve_actual_lengths_and_routes() -> io::Result<()> {
        use std::time::Duration;
        use std::time::Instant;
        let sender = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let a = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let b = std::net::UdpSocket::bind("127.0.0.1:0")?;
        for receiver in [&a, &b] {
            receiver.set_read_timeout(Some(Duration::from_secs(1)))?;
        }
        sender.set_nonblocking(true)?;
        let info = quiche::SendInfo {
            from: sender.local_addr()?,
            to: a.local_addr()?,
            at: Instant::now(),
        };
        let other = quiche::SendInfo {
            to: b.local_addr()?,
            ..info
        };
        let mut sender = mio::net::UdpSocket::from_std(sender);

        // A smaller tail, a larger PMTU probe, then a path change.
        let mut batches = Vec::new();
        let datagrams = [(4, info), (4, info), (2, info), (7, info), (7, other)];
        let mut output = Vec::new();
        for (index, (len, route)) in datagrams.into_iter().enumerate() {
            let start = output.len();
            output.resize(
                start + len,
                u8::try_from(index + 1).map_err(io::Error::other)?,
            );
            DatagramBatch::push(&mut batches, start..start + len, route, false);
        }
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].bytes, 0..10);
        assert_eq!(batches[0].segment_size, 4);
        assert_eq!(batches[1].bytes, 10..17);
        assert_eq!(batches[1].segment_size, 7);
        assert_eq!(batches[2].info, other);

        let poll = mio::Poll::new()?;
        poll.registry()
            .register(&mut sender, Token(0), Interest::READABLE)?;
        for gso in [false, true] {
            if gso && !detect_gso(&sender, 7) {
                continue;
            }
            let mut queue = DatagramQueue::new(output.len(), gso);
            queue.stage(&mut output.clone(), &mut batches.clone())?;
            assert!(queue.flush(&mut sender, poll.registry(), Token(0))?);

            let mut received = [0; 32];
            for (receiver, len, marker) in
                [(&a, 4, 1), (&a, 4, 2), (&a, 2, 3), (&a, 7, 4), (&b, 7, 5)]
            {
                assert_eq!(receiver.recv(&mut received)?, len);
                assert_eq!(&received[..len], vec![marker; len]);
            }
        }
        Ok(())
    }

    #[test]
    fn blocked_fallback_keeps_only_unsent_datagrams() -> io::Result<()> {
        let (_, info) = addresses()?;
        let mut output = vec![1, 1, 2, 2, 3];
        let mut batches = Vec::new();
        for range in [0..2, 2..4, 4..5] {
            DatagramBatch::push(&mut batches, range, info, false);
        }
        let mut queue = DatagramQueue::new(output.len(), false);
        queue.stage(&mut output, &mut batches)?;
        let mut sent = Vec::new();
        let mut attempts = 0;
        assert!(!queue.flush_with(|bytes, route, stride, pacing| {
            assert_eq!(*route, info);
            assert_eq!(stride, None);
            assert!(!pacing);
            attempts += 1;
            if attempts == 2 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            sent.extend_from_slice(bytes);
            Ok(bytes.len())
        })?);
        assert_eq!(sent, [1, 1]);
        assert!(queue.is_pending());
        assert!(queue.stage(&mut output, &mut batches).is_err());
        assert!(queue.flush_with(|bytes, route, _, _| {
            assert_eq!(*route, info);
            sent.extend_from_slice(bytes);
            Ok(bytes.len())
        })?);
        assert_eq!(sent, [1, 1, 2, 2, 3]);
        assert!(!queue.is_pending());
        Ok(())
    }

    #[test]
    fn gso_combines_distinct_due_deadlines_but_not_future_deadlines(
    ) -> io::Result<()> {
        let (_, info) = addresses()?;
        let earlier = quiche::SendInfo {
            at: info
                .at
                .checked_sub(std::time::Duration::from_secs(1))
                .ok_or(io::ErrorKind::InvalidInput)?,
            ..info
        };
        let future = quiche::SendInfo {
            at: info
                .at
                .checked_add(std::time::Duration::from_secs(3600))
                .ok_or(io::ErrorKind::InvalidInput)?,
            ..info
        };
        let mut batches = Vec::new();
        for (range, route) in [(0..2, earlier), (2..4, info), (4..6, future)] {
            DatagramBatch::push(&mut batches, range, route, true);
        }
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].bytes, 0..4);
        assert_eq!(batches[0].info.at, info.at);
        assert_eq!(batches[1].bytes, 4..6);
        assert_eq!(batches[1].info.at, future.at);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gso_preserves_routes_and_pacing_deadlines_across_blocking(
    ) -> io::Result<()> {
        let (_, info) = addresses()?;
        let later = quiche::SendInfo {
            at: info
                .at
                .checked_add(std::time::Duration::from_secs(3600))
                .ok_or(io::ErrorKind::InvalidInput)?,
            ..info
        };
        let other = quiche::SendInfo {
            to: "127.0.0.1:12345".parse().map_err(io::Error::other)?,
            ..later
        };
        let mut output = vec![1, 1, 2, 2, 3, 3, 4];
        let mut batches = Vec::new();
        for (range, route) in
            [(0..2, info), (2..4, info), (4..6, later), (6..7, other)]
        {
            DatagramBatch::push(&mut batches, range, route, true);
        }
        assert_eq!(batches.len(), 3);
        let mut queue = DatagramQueue::new(output.len(), true);
        queue.stage(&mut output, &mut batches)?;
        let mut sent = Vec::new();
        let mut routes = Vec::new();
        assert!(!queue.flush_with(|bytes, route, stride, pacing| {
            assert!(pacing);
            if routes.is_empty() {
                assert_eq!(bytes, [1, 1, 2, 2]);
                assert_eq!(*route, info);
                assert_eq!(stride, Some(2));
                routes.push(*route);
                sent.extend_from_slice(bytes);
                Ok(bytes.len())
            } else {
                assert_eq!(bytes, [3, 3]);
                assert_eq!(*route, later);
                assert_eq!(stride, None);
                Err(io::ErrorKind::WouldBlock.into())
            }
        })?);
        assert_eq!(sent, [1, 1, 2, 2]);
        assert!(queue.flush_with(|bytes, route, stride, pacing| {
            assert!(pacing);
            assert_eq!(stride, None);
            routes.push(*route);
            sent.extend_from_slice(bytes);
            Ok(bytes.len())
        })?);
        assert_eq!(routes, [info, later, other]);
        assert_eq!(sent, [1, 1, 2, 2, 3, 3, 4]);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn monotonic_clock_conversion_is_checked_and_deterministic() -> io::Result<()>
    {
        use std::time::Duration;

        let now = std::time::Instant::now();
        let ahead = now
            .checked_add(Duration::from_nanos(5))
            .ok_or(io::ErrorKind::InvalidInput)?;
        let behind = now
            .checked_sub(Duration::from_nanos(5))
            .ok_or(io::ErrorKind::InvalidInput)?;

        assert_eq!(deadline_from_anchor(now, now, 42)?, 42);
        assert_eq!(deadline_from_anchor(ahead, now, 42)?, 47);
        assert_eq!(deadline_from_anchor(behind, now, 42)?, 37);
        assert_eq!(deadline_from_anchor(ahead, now, u64::MAX - 5)?, u64::MAX);
        assert_eq!(deadline_from_anchor(behind, now, 5)?, 0);
        assert_eq!(
            deadline_from_anchor(ahead, now, u64::MAX - 4)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
        assert_eq!(
            deadline_from_anchor(behind, now, 4)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );

        assert!(std_time_to_u64(&now)? > 0);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_timespec_and_gso_segment_bounds_are_validated() -> io::Result<()> {
        let ts = |sec, nsec| libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        };
        assert_eq!(monotonic_timespec_ns(ts(1, 999_999_999))?, 1_999_999_999);
        for invalid in [ts(-1, 0), ts(0, -1), ts(0, 1_000_000_000)] {
            assert_eq!(
                monotonic_timespec_ns(invalid)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidData)
            );
        }
        if let Ok(secs) = libc::time_t::try_from(u64::MAX / 1_000_000_000 + 1) {
            assert_eq!(
                monotonic_timespec_ns(ts(secs, 0))
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidData)
            );
        }
        assert_eq!(valid_gso_segment_size(1)?, 1);
        assert_eq!(valid_gso_segment_size(u16::MAX as usize)?, u16::MAX);
        for invalid in [0, u16::MAX as usize + 1, usize::MAX] {
            assert_eq!(
                valid_gso_segment_size(invalid)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::InvalidInput)
            );
        }
        Ok(())
    }
}
