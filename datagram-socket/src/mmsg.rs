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
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;

use smallvec::SmallVec;
use tokio::io::ReadBuf;

pub const MAX_MMSG: usize = 16;

/// Receives as many datagrams as are immediately available into `bufs`.
///
/// # Errors
///
/// Returns the operating-system socket error if no datagram was received, or
/// an `InvalidData` error if a syscall result cannot be represented safely.
pub fn recvmmsg(fd: BorrowedFd, bufs: &mut [ReadBuf<'_>]) -> io::Result<usize> {
    if bufs.is_empty() {
        return Ok(0);
    }

    let mut msgvec: SmallVec<[libc::mmsghdr; MAX_MMSG]> = SmallVec::new();
    let mut iovecs: SmallVec<[libc::iovec; MAX_MMSG]> = SmallVec::new();

    let mut ret = 0;

    for bufs in bufs.chunks_mut(MAX_MMSG) {
        msgvec.clear();
        iovecs.clear();

        for buf in bufs.iter_mut() {
            // SAFETY: we only write into the unfilled region and never
            // de-initialize bytes that ReadBuf already considers initialized.
            let unfilled = unsafe { buf.unfilled_mut() };
            iovecs.push(libc::iovec {
                iov_base: unfilled.as_mut_ptr().cast(),
                iov_len: unfilled.len(),
            });
        }

        for iovec in &mut iovecs {
            msgvec.push(libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: iovec,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            });
        }

        // SAFETY: each iovec points to a distinct unfilled region owned by a
        // ReadBuf in `bufs`. Those regions and the message headers remain
        // alive and unmoved for the duration of the syscall, and recvmmsg()
        // does not retain any of the pointers.
        let vlen = u32::try_from(msgvec.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "recvmmsg batch exceeds u32",
            )
        })?;
        // SAFETY: vlen was checked against u32 and every iovec/header remains
        // valid and unmoved for the duration of this non-retaining syscall.
        let result = unsafe {
            libc::recvmmsg(
                fd.as_raw_fd(),
                msgvec.as_mut_ptr(),
                vlen,
                0,
                std::ptr::null_mut(),
            )
        };

        if result == -1 {
            break;
        }

        let received = usize::try_from(result).map_err(|_| {
            io::Error::other(
                "recvmmsg returned a negative count without reporting an error",
            )
        })?;

        for (buf, msg) in bufs.iter_mut().zip(msgvec.iter()).take(received) {
            let filled = msg.msg_len as usize;
            debug_assert!(filled <= buf.remaining());

            // SAFETY: recvmmsg() reported `filled` bytes written into this
            // buffer's iovec, whose length was exactly the buffer's unfilled
            // region.
            unsafe { buf.assume_init(filled) };
            buf.advance(filled);
            ret += 1;
        }

        if received < bufs.len() {
            break;
        }
    }

    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(ret)
}

/// Sends multiple datagrams with a single system call where possible.
///
/// The returned value is the number of datagrams sent.
///
/// # Errors
///
/// Returns the socket error if no datagram can be sent, or `InvalidInput` if
/// the batch size cannot be represented by the platform `sendmmsg(2)` ABI.
pub fn sendmmsg(fd: BorrowedFd, bufs: &[ReadBuf<'_>]) -> io::Result<usize> {
    sendmmsg_impl(fd, bufs, None)
}

/// Sends multiple datagrams, appending the same suffix to every datagram.
///
/// This is useful when an empty datagram payload needs to remain
/// distinguishable from an end-of-stream marker in a higher-level protocol.
///
/// The returned value is the number of datagrams sent. The suffix is framing
/// supplied on the caller's behalf and does not affect that count.
///
/// # Errors
///
/// Returns the socket error if no datagram can be sent, or `InvalidInput` if
/// the batch size cannot be represented by the platform `sendmmsg(2)` ABI.
pub fn sendmmsg_with_suffix(
    fd: BorrowedFd, bufs: &[ReadBuf<'_>], suffix: &[u8],
) -> io::Result<usize> {
    sendmmsg_impl(fd, bufs, Some(suffix))
}

fn sendmmsg_impl(
    fd: BorrowedFd, bufs: &[ReadBuf<'_>], suffix: Option<&[u8]>,
) -> io::Result<usize> {
    if bufs.is_empty() {
        return Ok(0);
    }

    let mut msgvec: SmallVec<[libc::mmsghdr; MAX_MMSG]> = SmallVec::new();
    let mut iovecs: SmallVec<[libc::iovec; 2 * MAX_MMSG]> = SmallVec::new();

    let mut ret = 0;

    for bufs in bufs.chunks(MAX_MMSG) {
        msgvec.clear();
        iovecs.clear();

        for buf in bufs {
            iovecs.push(iovec(buf.filled()));

            if let Some(suffix) = suffix {
                iovecs.push(iovec(suffix));
            }
        }

        // Populate all iovecs before taking pointers into the vector. This
        // ensures none of the pointers can be invalidated by a reallocation.
        let iovecs_per_message = if suffix.is_some() { 2 } else { 1 };
        for message_iovecs in iovecs.chunks_exact_mut(iovecs_per_message) {
            msgvec.push(libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: message_iovecs.as_mut_ptr(),
                    msg_iovlen: iovecs_per_message,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                // Output field populated by the kernel.
                msg_len: 0,
            });
        }

        let vlen = u32::try_from(msgvec.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "sendmmsg batch exceeds u32",
            )
        })?;

        // SAFETY: `iovecs` was fully populated before pointers into it were
        // stored in `msgvec`; neither vector is modified before the syscall
        // returns. Each header points to one or two live iovecs containing
        // initialized bytes, and `fd` remains valid for the call.
        let result = unsafe {
            libc::sendmmsg(fd.as_raw_fd(), msgvec.as_mut_ptr(), vlen, 0)
        };

        if result == -1 {
            let err = io::Error::last_os_error();

            if ret == 0 {
                return Err(err);
            }

            break;
        }

        let sent = usize::try_from(result).map_err(|_| {
            io::Error::other(
                "sendmmsg returned a negative count without reporting an error",
            )
        })?;
        ret += sent;

        if sent < bufs.len() {
            break;
        }
    }

    Ok(ret)
}

fn iovec(buf: &[u8]) -> libc::iovec {
    libc::iovec {
        // `sendmmsg(2)` only reads this memory; the C ABI nevertheless uses
        // a mutable pointer type for iov_base.
        iov_base: buf.as_ptr().cast_mut().cast(),
        iov_len: buf.len(),
    }
}

#[macro_export]
macro_rules! poll_recvmmsg {
    ($self: expr, $cx: ident, $bufs: ident) => {
        if $bufs.is_empty() {
            Poll::Ready(Ok(0))
        } else {
            loop {
                match $self.poll_recv_ready($cx)? {
                    Poll::Ready(()) => {
                        match $self.try_io(tokio::io::Interest::READABLE, || {
                            $crate::mmsg::recvmmsg($self.as_fd(), $bufs)
                        }) {
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}  // Have to poll for recv ready
                            res => break Poll::Ready(res),
                        }
                    }
                    Poll::Pending => break Poll::Pending,
                }
            }
        }
    };
}

#[macro_export]
macro_rules! poll_sendmmsg {
    ($self: expr, $cx: ident, $bufs: ident) => {
        if $bufs.is_empty() {
            Poll::Ready(Ok(0))
        } else {
            loop {
                match $self.poll_send_ready($cx)? {
                    Poll::Ready(()) => {
                        match $self.try_io(tokio::io::Interest::WRITABLE, || {
                            $crate::mmsg::sendmmsg($self.as_fd(), $bufs)
                        }) {
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {} // Have to poll for send ready
                            res => break Poll::Ready(res),
                        }
                    }
                    Poll::Pending => break Poll::Pending,
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use std::io;

    use std::os::fd::AsFd;
    use std::os::unix::net::UnixDatagram as StdUnixDatagram;
    use tokio::io::ReadBuf;
    use tokio::net::UnixDatagram;

    use super::sendmmsg;
    use super::sendmmsg_with_suffix;
    use super::MAX_MMSG;
    use crate::DatagramSocketRecvExt;
    use crate::DatagramSocketSendExt;

    #[test]
    fn empty_batches_are_noop() -> io::Result<()> {
        let (socket, _peer) = StdUnixDatagram::pair()?;
        let mut recv_bufs = [];

        assert_eq!(super::recvmmsg(socket.as_fd(), &mut recv_bufs)?, 0);
        assert_eq!(sendmmsg(socket.as_fd(), &[])?, 0);
        assert_eq!(sendmmsg_with_suffix(socket.as_fd(), &[], b"suffix")?, 0);

        Ok(())
    }

    #[tokio::test]
    async fn empty_socket_recv_batch_is_immediately_ready() -> io::Result<()> {
        let (_sender, mut receiver) = UnixDatagram::pair()?;
        let mut bufs = [];
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());

        assert!(matches!(
            crate::DatagramSocketRecv::poll_recv_many(
                &mut receiver,
                &mut cx,
                &mut bufs,
            ),
            std::task::Poll::Ready(Ok(0))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn recvmmsg() -> io::Result<()> {
        let (s, mut r) = UnixDatagram::pair()?;
        let mut bufs = [[0u8; 128]; 128];

        for i in 0..5 {
            s.send(&[i; 128]).await?;
        }

        let mut rbufs: Vec<_> =
            bufs.iter_mut().map(|s| ReadBuf::new(&mut s[..])).collect();
        assert_eq!(r.recv_many(&mut rbufs).await?, 5);

        for (expected, buf) in (0_u8..5).zip(rbufs[0..5].iter()) {
            assert_eq!(buf.filled(), &[expected; 128]);
        }

        for i in 0..92 {
            s.send(&[i; 128]).await?;
        }

        let mut rbufs: Vec<_> =
            bufs.iter_mut().map(|s| ReadBuf::new(&mut s[..])).collect();
        assert_eq!(r.recv_many(&mut rbufs).await?, 92);

        for (expected, buf) in (0_u8..92).zip(rbufs[0..92].iter()) {
            assert_eq!(buf.filled(), &[expected; 128]);
        }

        Ok(())
    }

    #[tokio::test]
    async fn send_many() -> io::Result<()> {
        let (s, r) = UnixDatagram::pair()?;
        let mut bufs = [[0_u8; 128]; 128];
        for (value, buf) in (0_u8..5).zip(bufs.iter_mut()) {
            buf.fill(value);
        }

        let wbufs: Vec<_> = bufs
            .iter_mut()
            .map(|s| {
                let mut b = ReadBuf::new(&mut s[..]);
                b.set_filled(128);
                b
            })
            .collect();

        assert_eq!(s.send_many(&wbufs[..5]).await?, 5);

        let mut rbuf = [0u8; 128];

        for expected in 0_u8..5 {
            assert_eq!(r.recv(&mut rbuf).await?, 128);
            assert_eq!(rbuf, [expected; 128]);
        }

        Ok(())
    }

    #[tokio::test]
    async fn sendmmsg_with_suffix_appends_to_every_datagram() -> io::Result<()> {
        let (s, r) = UnixDatagram::pair()?;
        let suffix = b"-suffix";
        let mut payloads: Vec<Vec<u8>> =
            (0..MAX_MMSG + 4).map(|i| vec![i as u8; i]).collect();
        let bufs: Vec<_> = payloads
            .iter_mut()
            .map(|payload| {
                let len = payload.len();
                let mut buf = ReadBuf::new(payload);
                buf.set_filled(len);
                buf
            })
            .collect();

        assert_eq!(
            sendmmsg_with_suffix(s.as_fd(), &bufs, suffix)?,
            payloads.len()
        );

        let mut received = vec![0; MAX_MMSG + suffix.len() + 4];
        for expected in &payloads {
            let received_len = r.recv(&mut received).await?;
            let mut expected_with_suffix =
                Vec::with_capacity(expected.len() + suffix.len());
            expected_with_suffix.extend_from_slice(expected);
            expected_with_suffix.extend_from_slice(suffix);
            assert_eq!(&received[..received_len], expected_with_suffix);
        }

        Ok(())
    }

    #[test]
    fn sendmmsg_with_suffix_reports_an_error_without_progress() -> io::Result<()>
    {
        let (s, r) = StdUnixDatagram::pair()?;
        drop(r);

        let mut payload = *b"payload";
        let payload_len = payload.len();
        let mut buf = ReadBuf::new(&mut payload);
        buf.set_filled(payload_len);

        assert!(sendmmsg_with_suffix(s.as_fd(), &[buf], b"suffix").is_err());

        Ok(())
    }
}
