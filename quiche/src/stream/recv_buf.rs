// Copyright (C) 2023, Cloudflare, Inc.
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

use std::collections::BTreeMap;
use std::ops::Bound::Excluded;
use std::ops::Bound::Unbounded;

use std::time::Duration;
use std::time::Instant;

use crate::stream::RecvAction;
use crate::stream::RecvBufResetReturn;
use crate::Error;
use crate::Result;

use crate::flowcontrol;

use crate::range_buf::RangeBuf;

/// Final size and the one-shot application notification are independent of
/// the buffered byte ranges.
#[derive(Debug, Default)]
enum ReceiveEnd {
    #[default]
    Open,
    Fin(u64),
    Reset {
        offset: u64,
        code: u64,
    },
    Delivered(u64),
}

impl ReceiveEnd {
    const fn offset(&self) -> Option<u64> {
        match *self {
            Self::Open => None,
            Self::Fin(offset) |
            Self::Reset { offset, .. } |
            Self::Delivered(offset) => Some(offset),
        }
    }

    const fn pending_at(&self, off: u64) -> bool {
        matches!(*self, Self::Fin(offset) | Self::Reset { offset, .. } if offset == off)
    }
}

/// Receive-side stream buffer.
///
/// Stream data received by the peer is buffered in a list of data chunks
/// ordered by offset in ascending order. Contiguous data can then be read
/// into a slice.
#[derive(Debug, Default)]
pub struct RecvBuf {
    /// Chunks of data received from the peer that have not yet been read by
    /// the application, ordered by offset.
    data: BTreeMap<u64, RangeBuf>,

    /// The lowest data offset that has yet to be read by the application.
    off: u64,

    /// The total length of data received on this stream.
    len: u64,

    /// Receiver flow controller.
    flow_control: flowcontrol::FlowControl,

    /// The peer's final size and outstanding terminal event.
    end: ReceiveEnd,

    /// Whether incoming data is validated but not buffered.
    drain: bool,
}

impl RecvBuf {
    /// Creates a new receive buffer.
    pub fn new(max_data: u64, initial_window: u64, max_window: u64) -> Self {
        Self {
            flow_control: flowcontrol::FlowControl::new(
                max_data,
                initial_window,
                max_window,
            ),
            ..Self::default()
        }
    }

    /// Inserts the given chunk of data in the buffer.
    ///
    /// This also takes care of enforcing stream flow control limits, as well
    /// as handling incoming data that overlaps data that is already in the
    /// buffer.
    pub fn write(&mut self, buf: RangeBuf) -> Result<()> {
        if buf.max_off() > self.max_data() {
            return Err(Error::FlowControl);
        }

        if let Some(fin_off) = self.end.offset() {
            // Stream's size is known, forbid data beyond that point.
            if buf.max_off() > fin_off {
                return Err(Error::FinalSize);
            }

            // Stream's size is already known, forbid changing it.
            if buf.fin() && fin_off != buf.max_off() {
                return Err(Error::FinalSize);
            }
        }

        // Stream's known size is lower than data already received.
        if buf.fin() && buf.max_off() < self.len {
            return Err(Error::FinalSize);
        }

        if buf.fin() && matches!(self.end, ReceiveEnd::Open) {
            self.end = if self.drain {
                ReceiveEnd::Delivered(buf.max_off())
            } else {
                ReceiveEnd::Fin(buf.max_off())
            };
        }

        // Empty frames still advance the largest received offset used for
        // flow control, but never occupy a byte-range entry. A FIN is tracked
        // by the terminal state even when its bytes were previously read.
        if self.drain || buf.is_empty() {
            self.len = cmp::max(self.len, buf.max_off());
            if self.drain {
                self.off = self.len;
            }
            return Ok(());
        }

        if self.off >= buf.max_off() {
            return Ok(());
        }

        let previous_end = self.len;
        let mut buf = buf;
        // Trim already-consumed data without cloning the backing allocation.
        buf.discard_prefix(self.off_front());
        self.len = self.len.max(buf.max_off());

        // In-order data cannot overlap anything already buffered.
        if buf.off() >= previous_end {
            self.data.insert(buf.max_off(), buf);
            return Ok(());
        }

        // The map is keyed by end offset. Find the first interval ending
        // strictly after the remaining input starts (adjacency is not an
        // overlap). Keep only uncovered prefixes and advance through each
        // overlapping interval once, without a temporary queue of fragments.
        while !buf.is_empty() {
            let overlap = self
                .data
                .range((Excluded(buf.off()), Unbounded))
                .next()
                .map(|(&end, entry)| (entry.off(), end))
                .filter(|&(start, _)| start < buf.max_off());

            let Some((start, end)) = overlap else {
                self.data.insert(buf.max_off(), buf);
                break;
            };

            if start > buf.off() {
                let remainder =
                    buf.split_off(start).ok_or(Error::InvalidState)?;
                self.data.insert(start, buf);
                buf = remainder;
            }

            // Existing data wins even when retransmissions disagree.
            buf.discard_prefix(end);
        }

        Ok(())
    }

    /// Reads contiguous data from the receive buffer.
    ///
    /// Data is written into the given `out` buffer, up to the length of `out`.
    ///
    /// Only contiguous data is removed, starting from offset 0. The offset is
    /// incremented as data is taken out of the receive buffer. If there is no
    /// data at the expected read offset, the `Done` error is returned.
    ///
    /// On success the amount of data read and a flag indicating
    /// if there is no more data in the buffer, are returned as a tuple.
    #[inline]
    pub fn emit(&mut self, mut out: &mut [u8]) -> Result<(usize, bool)> {
        self.emit_or_discard(RecvAction::Emit { out: &mut out })
    }

    /// Reads or discards contiguous data from the receive buffer.
    ///
    /// Passing an `action` of `StreamRecvAction::Emit` results in data being
    /// written into the provided buffer, up to its length.
    ///
    /// Passing an `action` of `StreamRecvAction::Discard` results in up to
    /// the indicated number of bytes being discarded without copying.
    ///
    /// Only contiguous data is removed, starting from offset 0. The offset is
    /// incremented as data is taken out of the receive buffer. If there is no
    /// data at the expected read offset, the `Done` error is returned.
    ///
    /// On success the amount of data read or discarded, and a flag indicating
    /// if there is no more data in the buffer, are returned as a tuple.
    pub fn emit_or_discard<B: bytes::BufMut>(
        &mut self, mut action: RecvAction<B>,
    ) -> Result<(usize, bool)> {
        let mut len = 0;
        let mut cap = match &action {
            RecvAction::Emit { out } => out.remaining_mut(),
            RecvAction::Discard { len } => *len,
        };

        if !self.ready() {
            return Err(Error::Done);
        }

        if let ReceiveEnd::Reset { offset, code } = self.end {
            self.end = ReceiveEnd::Delivered(offset);
            return Err(Error::StreamReset(code));
        }

        while self.ready() {
            let Some(mut entry) = self.data.first_entry() else {
                break;
            };

            let buf = entry.get_mut();

            if cap == 0 {
                break;
            }

            let buf_len = cmp::min(buf.len(), cap);

            // Only copy data if we're emitting, not discarding.
            if let RecvAction::Emit { ref mut out } = action {
                // Note: `BufMut::remaining_mut()` cannot "shrink", but BufMut
                // impls are allowed to grow the buffer, so we
                // check here that we still have at least
                // `cap` bytes, but we can't require equality
                debug_assert!(
                    cap <= out.remaining_mut(),
                    "We updated `cap` incorrectly"
                );
                out.put_slice(&buf[..buf_len]);
            }

            self.off += buf_len as u64;

            len += buf_len;
            cap -= buf_len;

            if buf_len < buf.len() {
                buf.consume(buf_len);

                // We reached the maximum capacity, so end here.
                break;
            }

            entry.remove();
        }

        // Update consumed bytes for flow control.
        self.flow_control.add_consumed(len as u64);

        let fin = self.is_fin();
        if fin {
            self.end = ReceiveEnd::Delivered(self.off);
        }
        Ok((len, fin))
    }

    /// Reset the stream at the supplied final size. Validate both the
    /// stream and connection flow-control budgets before changing state.
    pub fn reset(
        &mut self, error_code: u64, final_size: u64, connection_credit: u64,
    ) -> Result<RecvBufResetReturn> {
        // Stream's size is already known, forbid changing it.
        if self.end.offset().is_some_and(|offset| offset != final_size) ||
            final_size < self.len
        {
            return Err(Error::FinalSize);
        }

        let max_data_delta = final_size - self.len;
        if final_size > self.max_data() || max_data_delta > connection_credit {
            return Err(Error::FlowControl);
        }

        if matches!(
            self.end,
            ReceiveEnd::Reset { .. } | ReceiveEnd::Delivered(_)
        ) {
            return Ok(RecvBufResetReturn::zero());
        }

        let result = RecvBufResetReturn {
            max_data_delta,
            consumed_flowcontrol: final_size - self.off,
        };

        self.end = if self.drain {
            ReceiveEnd::Delivered(final_size)
        } else {
            ReceiveEnd::Reset {
                offset: final_size,
                code: error_code,
            }
        };
        self.len = final_size;
        self.off = final_size;
        self.data.clear();

        Ok(result)
    }

    /// Commits the new `max_data` limit.
    pub fn update_max_data(&mut self, now: Instant) {
        self.flow_control.update_max_data(now);
    }

    /// Return the new `max_data` limit.
    pub fn max_data_next(&self) -> u64 {
        self.flow_control.max_data_next()
    }

    /// Return the current flow control limit.
    pub const fn max_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    /// Return the current window.
    pub const fn window(&self) -> u64 {
        self.flow_control.window()
    }

    /// Autotune the window size.
    pub fn autotune_window(&mut self, now: Instant, rtt: Duration) {
        self.flow_control.autotune_window(now, rtt);
    }

    /// Shuts down receiving data and returns the number of bytes
    /// that should be returned to the connection level flow
    /// control
    pub fn shutdown(&mut self) -> Result<u64> {
        if self.drain {
            return Err(Error::Done);
        }

        self.drain = true;

        self.data.clear();

        let consumed = self.max_off() - self.off;
        self.off = self.max_off();
        if let Some(offset) = self.end.offset() {
            self.end = ReceiveEnd::Delivered(offset);
        }

        Ok(consumed)
    }

    /// Returns the lowest offset of data buffered.
    pub const fn off_front(&self) -> u64 {
        self.off
    }

    /// Returns true if we need to update the local flow control limit.
    pub fn almost_full(&self) -> bool {
        self.end.offset().is_none() && self.flow_control.should_update_max_data()
    }

    /// Returns the largest offset ever received.
    pub const fn max_off(&self) -> u64 {
        self.len
    }

    /// Returns true if the receive-side of the stream is complete.
    ///
    /// This happens when the stream's receive final size is known, and the
    /// application has read all data from the stream.
    pub fn is_fin(&self) -> bool {
        self.end.offset() == Some(self.off)
    }

    /// Returns true if the stream is not storing incoming data.
    pub const fn is_draining(&self) -> bool {
        self.drain
    }

    /// Returns true if contiguous data or a terminal event is readable.
    pub fn ready(&self) -> bool {
        !self.drain &&
            (self.end.pending_at(self.off) ||
                self.data
                    .first_key_value()
                    .is_some_and(|(_, buf)| buf.off() == self.off))
    }

    /// Returns the number of bytes that can be read contiguously from the
    /// current read offset, up to `max_len`.
    ///
    /// Data buffered behind a gap (received out of order) is not counted, so
    /// this never reports bytes that are not yet readable. The cost is
    /// proportional to the number of contiguous buffered chunks at the front
    /// of the buffer, up to `max_len`; no data is copied.
    pub fn readable_len(&self, max_len: usize) -> usize {
        let mut contiguous = 0usize;
        let mut next_off = self.off;

        // `data` is ordered by offset, so walk from the front and stop at the
        // first gap (a chunk that does not start where the contiguous run so
        // far leaves off).
        for buf in self.data.values() {
            if buf.off() != next_off {
                break;
            }

            contiguous = contiguous.saturating_add(buf.len()).min(max_len);
            next_off = buf.max_off();

            if contiguous == max_len {
                break;
            }
        }

        contiguous
    }

    #[cfg(test)]
    pub(crate) const fn flow_control_for_tests(
        &self,
    ) -> &flowcontrol::FlowControl {
        &self.flow_control
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default size of the receiver stream flow control window.
    const DEFAULT_STREAM_WINDOW: u64 = 32 * 1024;
    use bytes::BufMut as _;
    use rstest::rstest;

    // Helper function for testing either buffer emit or discard.
    //
    // The `emit` parameter controls whether data is emitted or discarded from
    // `recv`.
    //
    // The `target_len` parameter controls the maximum amount of bytes that
    // could be read, up to the capacity of `recv`. The `result_len` is the
    // actual number of bytes that were taken out of `recv`. An assert is
    // performed on `result_len` to ensure the number of bytes read meets the
    // caller expectations.
    //
    // The `is_fin` parameter relates to the buffer's finished status. An assert
    // is performed on it to ensure the status meet the caller expectations.
    //
    // The `test_bytes` parameter carries an optional slice of bytes. Is set, an
    // assert is performed against the bytes that were read out of the buffer,
    // to ensure caller expectations are met.
    fn assert_emit_discard(
        recv: &mut RecvBuf, emit: bool, target_len: usize, result_len: usize,
        is_fin: bool, test_bytes: Option<&[u8]>,
    ) -> Result<()> {
        let mut buf = Vec::<u8>::with_capacity(512).limit(target_len);
        let action = if emit {
            RecvAction::Emit { out: &mut buf }
        } else {
            RecvAction::Discard { len: target_len }
        };

        let (read, fin) = recv.emit_or_discard(action)?;

        let buf = buf.into_inner();
        if emit {
            assert_eq!(buf.len(), read);
            if let Some(v) = test_bytes {
                assert_eq!(&buf, v);
            }
        }

        assert_eq!(read, result_len);
        assert_eq!(is_fin, fin);
        Ok(())
    }

    // Helper function for testing buffer status for either emit or discard.
    fn assert_emit_discard_done(recv: &mut RecvBuf, emit: bool) {
        let mut buf = [0u8; 32];
        let action = if emit {
            RecvAction::Emit {
                out: &mut buf.as_mut_slice(),
            }
        } else {
            RecvAction::Discard { len: 32 }
        };
        assert_eq!(recv.emit_or_discard(action), Err(Error::Done));
    }

    #[rstest]
    fn empty_read(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        assert_emit_discard_done(&mut recv, emit);
    }

    #[rstest]
    fn empty_stream_frame(#[values(true, false)] emit: bool) -> Result<()> {
        let mut recv =
            RecvBuf::new(15, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let buf = RangeBuf::from(b"hello", 0, false);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 5);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert_emit_discard(&mut recv, emit, 32, 5, false, None)?;

        // Don't store non-fin empty buffer, but track its offset.
        let buf = RangeBuf::from(b"", 10, false);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 0);

        // Check flow control for empty buffer.
        let buf = RangeBuf::from(b"", 16, false);
        assert_eq!(recv.write(buf), Err(Error::FlowControl));

        // A final size below the advanced largest offset is an error
        // (RFC 9000 Section 4.5).
        let buf = RangeBuf::from(b"", 5, true);
        assert_eq!(recv.write(buf), Err(Error::FinalSize));

        // Record the final size without storing an empty byte range.
        let buf = RangeBuf::from(b"", 10, true);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 0);

        // Duplicate FINs do not create another event.
        let buf = RangeBuf::from(b"", 10, true);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 0);

        // Accept another fin buffer with the same final size.
        let buf = RangeBuf::from(b"aa", 8, true);
        assert!(recv.write(buf).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 5);
        assert_eq!(recv.data.len(), 1);

        // A fin buffer whose end disagrees with the known final size errors.
        let buf = RangeBuf::from(b"aa", 3, true);
        assert_eq!(recv.write(buf), Err(Error::FinalSize));

        // Validate final size with fin empty buffers.
        let buf = RangeBuf::from(b"", 11, true);
        assert_eq!(recv.write(buf), Err(Error::FinalSize));
        let buf = RangeBuf::from(b"", 9, true);
        assert_eq!(recv.write(buf), Err(Error::FinalSize));

        // The gap prevents delivery; once filled, the tail and FIN survive.
        assert_emit_discard_done(&mut recv, emit);
        assert_eq!(recv.write(RangeBuf::from(b"bbb", 5, false)), Ok(()));
        assert_emit_discard(&mut recv, emit, 32, 5, true, Some(b"bbbaa"))?;
        assert_emit_discard_done(&mut recv, emit);
        Ok(())
    }

    #[rstest]
    fn ordered_read(#[values(true, false)] emit: bool) -> Result<()> {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);

        assert_emit_discard_done(&mut recv, emit);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_emit_discard_done(&mut recv, emit);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_emit_discard(
            &mut recv,
            emit,
            32,
            19,
            true,
            Some(b"helloworldsomething"),
        )?;
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);

        assert_emit_discard_done(&mut recv, emit);
        Ok(())
    }

    #[test]
    /// `readable_len` counts only contiguous in-order data, up to its limit.
    fn readable_len() {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);

        // Empty buffer: nothing readable.
        assert_eq!(recv.readable_len(64 * 1024), 0);

        // Data buffered behind a gap is not readable.
        assert!(recv.write(RangeBuf::from(b"hello", 0, false)).is_ok());
        assert!(recv.write(RangeBuf::from(b"something", 10, false)).is_ok());
        assert_eq!(recv.readable_len(64 * 1024), 5);

        // Filling the gap makes the full range readable, bounded by the limit.
        assert!(recv.write(RangeBuf::from(b"world", 5, false)).is_ok());
        assert_eq!(recv.readable_len(64 * 1024), 19);
        assert_eq!(recv.readable_len(10), 10);
    }

    /// Test shutdown behavior
    #[rstest]
    fn shutdown(#[values(true, false)] emit: bool) {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, false);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);

        assert_emit_discard_done(&mut recv, emit);

        // shutdown the buffer. Buffer is dropped.
        assert_eq!(recv.shutdown(), Ok(10));
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 10);
        assert_eq!(recv.data.len(), 0);

        assert_emit_discard_done(&mut recv, emit);

        // subsequent writes are validated but not added to the buffer
        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 10);
        assert_eq!(recv.data.len(), 0);

        // the max offset of received data can increase and
        // the recv.off must increase with it
        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
        assert_eq!(recv.data.len(), 0);

        // Send a reset
        assert_emit_discard_done(&mut recv, emit);
        assert_eq!(
            recv.reset(42, 123, u64::MAX),
            Ok(RecvBufResetReturn {
                max_data_delta: 104,
                consumed_flowcontrol: 104,
            })
        );
        assert_eq!(recv.len, 123);
        assert_eq!(recv.off, 123);
        assert_eq!(recv.data.len(), 0);

        assert_emit_discard_done(&mut recv, emit);
    }

    /// An empty non-fin buffer advances the largest received offset, which the
    /// connection charges to flow control on arrival, so a draining stream must
    /// consume it too and a later reset must not credit it again.
    #[test]
    fn shutdown_empty_stream_frame() {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);

        assert!(recv.write(RangeBuf::from(b"hello", 0, false)).is_ok());
        assert_eq!(recv.shutdown(), Ok(5));

        assert!(recv.write(RangeBuf::from(b"", 10, false)).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 10);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(
            recv.reset(42, 10, u64::MAX),
            Ok(RecvBufResetReturn {
                max_data_delta: 0,
                consumed_flowcontrol: 0,
            })
        );
    }

    #[rstest]
    fn reset_after_fin_preserves_single_terminal_notification(
        #[values(false, true)] drain: bool,
    ) {
        let mut recv = RecvBuf::new(20, 20, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.write(RangeBuf::from(b"tail", 6, true)), Ok(()));
        assert!(!recv.ready());
        if drain {
            assert_eq!(recv.shutdown(), Ok(10));
        }
        let expected_consumed = if drain { 0 } else { 10 };
        assert_eq!(
            recv.reset(42, 10, 0),
            Ok(RecvBufResetReturn {
                max_data_delta: 0,
                consumed_flowcontrol: expected_consumed,
            })
        );
        assert!(recv.is_fin());
        assert_eq!(recv.reset(43, 10, 0), Ok(RecvBufResetReturn::zero()));
        assert_eq!(recv.ready(), !drain);
        if !drain {
            assert_eq!(recv.emit(&mut [0; 10]), Err(Error::StreamReset(42)));
        }
        assert_eq!(recv.emit(&mut [0; 10]), Err(Error::Done));
        assert!(!recv.ready());
    }

    #[test]
    fn rejected_reset_leaves_receive_state_unchanged() {
        let mut recv = RecvBuf::new(20, 20, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.write(RangeBuf::from(b"hello", 0, false)), Ok(()));
        for (size, credit) in [(21, u64::MAX), (10, 4)] {
            assert_eq!(recv.reset(42, size, credit), Err(Error::FlowControl));
            assert_eq!(recv.max_off(), 5);
            assert_eq!(recv.off_front(), 0);
            assert!(recv.ready());
            assert!(!recv.is_fin());
            assert!(matches!(recv.end, ReceiveEnd::Open));
        }
        let mut data = [0; 5];
        assert_eq!(recv.emit(&mut data), Ok((5, false)));
        assert_eq!(&data, b"hello");
    }

    #[rstest]
    fn split_read(#[values(true, false)] emit: bool) -> Result<()> {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_emit_discard(&mut recv, emit, 10, 10, false, Some(b"somethingh"))?;
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 10);

        assert_emit_discard(&mut recv, emit, 5, 5, false, Some(b"ellow"))?;
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 15);

        assert_emit_discard(&mut recv, emit, 5, 4, true, Some(b"orld"))?;
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
        Ok(())
    }

    #[test]
    fn split_read_incremental_buf() {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let mut buf = Vec::new().limit(10);
        assert_eq!(
            recv.emit_or_discard(RecvAction::Emit { out: &mut buf }),
            Ok((10, false))
        );
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 10);
        assert_eq!(buf.get_ref().len(), 10);
        assert_eq!(buf.get_ref().as_slice(), b"somethingh");

        buf.set_limit(5);
        assert_eq!(
            recv.emit_or_discard(RecvAction::Emit { out: &mut buf }),
            Ok((5, false))
        );
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 15);
        assert_eq!(buf.get_ref().len(), 15);
        assert_eq!(buf.get_ref().as_slice(), b"somethinghellow");

        buf.set_limit(42);
        assert_eq!(
            recv.emit_or_discard(RecvAction::Emit { out: &mut buf }),
            Ok((4, true))
        );
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
        assert_eq!(buf.get_ref().len(), 19);
        assert_eq!(buf.get_ref().as_slice(), b"somethinghelloworld");
    }

    #[rstest]
    fn incomplete_read(#[values(true, false)] emit: bool) -> Result<()> {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let mut buf = [0u8; 32];

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"helloworld", 9, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        let action = if emit {
            RecvAction::Emit {
                out: &mut buf.as_mut_slice(),
            }
        } else {
            RecvAction::Discard { len: 32 }
        };
        assert_eq!(recv.emit_or_discard(action), Err(Error::Done));

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_emit_discard(
            &mut recv,
            emit,
            32,
            19,
            true,
            Some(b"somethinghelloworld"),
        )?;
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);
        Ok(())
    }

    #[rstest]
    fn zero_len_read(#[values(true, false)] emit: bool) -> Result<()> {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"", 9, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert_emit_discard(&mut recv, emit, 32, 9, true, Some(b"something"))?;
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        Ok(())
    }

    #[rstest]
    fn past_read(#[values(true, false)] emit: bool) -> Result<()> {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"something", 0, false);
        let second = RangeBuf::from(b"hello", 3, false);
        let third = RangeBuf::from(b"ello", 4, true);
        let fourth = RangeBuf::from(b"ello", 5, true);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 0);
        assert_eq!(recv.data.len(), 1);

        assert_emit_discard(&mut recv, emit, 32, 9, false, Some(b"something"))?;
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_eq!(recv.write(third), Err(Error::FinalSize));

        assert!(recv.write(fourth).is_ok());
        assert_eq!(recv.len, 9);
        assert_eq!(recv.off, 9);
        assert_eq!(recv.data.len(), 0);

        assert_emit_discard(&mut recv, emit, 32, 0, true, Some(b""))?;
        assert_eq!(recv.write(RangeBuf::from(b"", 9, true)), Ok(()));
        assert_eq!(recv.write(RangeBuf::from(b"ello", 5, true)), Ok(()));
        assert_emit_discard_done(&mut recv, emit);
        Ok(())
    }

    struct ReceiveStep {
        bytes: &'static [u8],
        offset: u64,
        fin: bool,
        end: u64,
        ranges: usize,
    }

    #[rstest]
    #[case::fully_overlapping_read(&[
            ReceiveStep { bytes: b"something", offset: 0, fin: false, end: 9, ranges: 1 },
            ReceiveStep { bytes: b"hello", offset: 4, fin: false, end: 9, ranges: 1 }
        ], b"something", false)]
    #[case::fully_overlapping_read2(&[
            ReceiveStep { bytes: b"hello", offset: 4, fin: false, end: 9, ranges: 1 },
            ReceiveStep { bytes: b"something", offset: 0, fin: false, end: 9, ranges: 2 }
        ], b"somehello", false)]
    #[case::fully_overlapping_read3(&[
            ReceiveStep { bytes: b"hello", offset: 3, fin: false, end: 8, ranges: 1 },
            ReceiveStep { bytes: b"something", offset: 0, fin: false, end: 9, ranges: 3 }
        ], b"somhellog", false)]
    #[case::fully_overlapping_read_multi(&[
            ReceiveStep { bytes: b"hello", offset: 3, fin: false, end: 8, ranges: 1 },
            ReceiveStep { bytes: b"hello", offset: 12, fin: false, end: 17, ranges: 2 },
            ReceiveStep { bytes: b"somethingsomething", offset: 0, fin: false, end: 18, ranges: 5 }
        ], b"somhellogsomhellog", false)]
    #[case::overlapping_start_read(&[
            ReceiveStep { bytes: b"something", offset: 0, fin: false, end: 9, ranges: 1 },
            ReceiveStep { bytes: b"hello", offset: 8, fin: true, end: 13, ranges: 2 }
        ], b"somethingello", true)]
    #[case::overlapping_end_read(&[
            ReceiveStep { bytes: b"something", offset: 3, fin: true, end: 12, ranges: 1 },
            ReceiveStep { bytes: b"hello", offset: 0, fin: false, end: 12, ranges: 2 }
        ], b"helsomething", true)]
    #[case::overlapping_end_twice_read(&[
            ReceiveStep { bytes: b"rl", offset: 7, fin: false, end: 9, ranges: 1 },
            ReceiveStep { bytes: b"ow", offset: 4, fin: false, end: 9, ranges: 2 },
            ReceiveStep { bytes: b"he", offset: 0, fin: false, end: 9, ranges: 3 },
            ReceiveStep { bytes: b"helloworld", offset: 0, fin: true, end: 10, ranges: 6 }
        ], b"helloworld", true)]
    #[case::overlapping_end_twice_and_contained_read(&[
            ReceiveStep { bytes: b"rl", offset: 7, fin: false, end: 9, ranges: 1 },
            ReceiveStep { bytes: b"barfoo", offset: 10, fin: true, end: 16, ranges: 2 },
            ReceiveStep { bytes: b"hellow", offset: 0, fin: false, end: 16, ranges: 3 },
            ReceiveStep { bytes: b"elloworldbarfoo", offset: 1, fin: true, end: 16, ranges: 5 }
        ], b"helloworldbarfoo", true)]
    #[case::partially_multi_overlapping_reordered_read(&[
            ReceiveStep { bytes: b"hello", offset: 8, fin: false, end: 13, ranges: 1 },
            ReceiveStep { bytes: b"something", offset: 0, fin: false, end: 13, ranges: 2 },
            ReceiveStep { bytes: b"moar", offset: 11, fin: true, end: 15, ranges: 3 }
        ], b"somethinhelloar", true)]
    #[case::partially_multi_overlapping_reordered_read2(&[
            ReceiveStep { bytes: b"bbb", offset: 2, fin: false, end: 5, ranges: 1 },
            ReceiveStep { bytes: b"ddd", offset: 6, fin: false, end: 9, ranges: 2 },
            ReceiveStep { bytes: b"ccc", offset: 4, fin: false, end: 9, ranges: 3 },
            ReceiveStep { bytes: b"aaa", offset: 0, fin: false, end: 9, ranges: 4 },
            ReceiveStep { bytes: b"fff", offset: 11, fin: false, end: 14, ranges: 5 },
            ReceiveStep { bytes: b"eee", offset: 9, fin: false, end: 14, ranges: 6 }
        ], b"aabbbcdddeefff", false)]
    fn overlapping_arrival_sequences(
        #[case] steps: &[ReceiveStep], #[case] expected: &[u8],
        #[case] fin: bool, #[values(true, false)] emit: bool,
    ) -> Result<()> {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);
        for step in steps {
            recv.write(RangeBuf::from(step.bytes, step.offset, step.fin))?;
            assert_eq!(recv.len, step.end);
            assert_eq!(recv.off, 0);
            assert_eq!(recv.data.len(), step.ranges);
        }
        assert_emit_discard(
            &mut recv,
            emit,
            32,
            expected.len(),
            fin,
            Some(expected),
        )?;
        assert_eq!(recv.len, expected.len() as u64);
        assert_eq!(recv.off, expected.len() as u64);
        assert_eq!(recv.data.len(), 0);
        assert_emit_discard_done(&mut recv, emit);
        Ok(())
    }

    #[test]
    fn interval_insertion_matches_first_arrival_byte_model() -> Result<()> {
        const SIZE: usize = 8;

        let intervals: Vec<_> = (0..=SIZE)
            .flat_map(|start| (start..=SIZE).map(move |end| (start, end)))
            .collect();
        for &(first_start, first_end) in &intervals {
            for &(second_start, second_end) in &intervals {
                for consumed in 0..=SIZE {
                    let mut recv = RecvBuf::new(
                        SIZE as u64,
                        DEFAULT_STREAM_WINDOW,
                        DEFAULT_STREAM_WINDOW,
                    );
                    let mut expected = [None; SIZE];
                    let first = [1; SIZE];
                    let second = [2; SIZE];
                    recv.write(RangeBuf::from(
                        &first[first_start..first_end],
                        first_start as u64,
                        false,
                    ))?;
                    expected[first_start..first_end].fill(Some(1));

                    let mut output = [0; SIZE];
                    let prefix =
                        expected.iter().take_while(|b| b.is_some()).count();
                    let read = prefix.min(consumed);
                    if prefix > 0 {
                        assert_eq!(
                            recv.emit(&mut output[..consumed]),
                            Ok((read, false))
                        );
                        assert_eq!(&output[..read], &first[..read]);
                    } else {
                        assert_eq!(
                            recv.emit(&mut output[..consumed]),
                            Err(Error::Done)
                        );
                    }

                    recv.write(RangeBuf::from(
                        &second[second_start..second_end],
                        second_start as u64,
                        false,
                    ))?;
                    for byte in &mut expected[second_start..second_end] {
                        byte.get_or_insert(2);
                    }

                    // Fill every remaining gap with a different byte
                    // and check that the first arrival was preserved.
                    recv.write(RangeBuf::from(&[3; SIZE], 0, true))?;
                    let expected: Vec<_> =
                        expected[read..].iter().map(|b| b.unwrap_or(3)).collect();
                    assert_eq!(recv.emit(&mut output), Ok((SIZE - read, true)));
                    assert_eq!(&output[..SIZE - read], expected);
                    assert!(recv.data.is_empty());
                    assert_eq!(recv.emit(&mut output), Err(Error::Done));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn mixed_read_actions() -> Result<()> {
        let mut recv =
            RecvBuf::new(u64::MAX, DEFAULT_STREAM_WINDOW, DEFAULT_STREAM_WINDOW);
        assert_eq!(recv.len, 0);

        let first = RangeBuf::from(b"hello", 0, false);
        let second = RangeBuf::from(b"world", 5, false);
        let third = RangeBuf::from(b"something", 10, true);

        assert!(recv.write(second).is_ok());
        assert_eq!(recv.len, 10);
        assert_eq!(recv.off, 0);

        assert_emit_discard_done(&mut recv, true);
        assert_emit_discard_done(&mut recv, false);

        assert!(recv.write(third).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_emit_discard_done(&mut recv, true);
        assert_emit_discard_done(&mut recv, false);

        assert!(recv.write(first).is_ok());
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 0);

        assert_emit_discard(&mut recv, true, 5, 5, false, Some(b"hello"))?;
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 5);

        assert_emit_discard(&mut recv, false, 5, 5, false, None)?;
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 10);

        assert_emit_discard(&mut recv, true, 9, 9, true, Some(b"something"))?;
        assert_eq!(recv.len, 19);
        assert_eq!(recv.off, 19);

        assert_emit_discard_done(&mut recv, true);
        assert_emit_discard_done(&mut recv, false);
        Ok(())
    }
}
