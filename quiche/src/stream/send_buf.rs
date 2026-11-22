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

use std::collections::VecDeque;

use crate::buffers::BufSplit;
use crate::range_buf::RangeBuf;
use crate::BufFactory;
use crate::Error;
use crate::Result;

use crate::buffers::DefaultBufFactory;
use crate::ranges;

#[cfg(test)]
const SEND_BUFFER_SIZE: usize = 5;

#[cfg(not(test))]
const SEND_BUFFER_SIZE: usize = 4096;

struct SendReserve<'a, F: BufFactory> {
    inner: &'a mut SendBuf<F>,
    reserved: usize,
    fin: bool,
}

impl<F: BufFactory> SendReserve<'_, F> {
    fn append_buf(&mut self, buf: F::Buf) -> Result<()> {
        let len = buf.as_ref().len();
        let inner = &mut self.inner;

        if len > self.reserved {
            return Err(Error::BufferTooShort);
        }

        let fin: bool = self.reserved == len && self.fin;

        let buf = RangeBuf::from_raw(buf, inner.off, fin);

        // The new data can simply be appended at the end of the send buffer.
        inner.data.push_back(buf);

        inner.off += len as u64;
        inner.buffered_bytes += len as u64;
        self.reserved -= len;

        Ok(())
    }
}

impl<F: BufFactory> Drop for SendReserve<'_, F> {
    fn drop(&mut self) {
        assert_eq!(self.reserved, 0);
    }
}

/// Final-size state is independent of acknowledgment of stream data.
#[derive(Debug, Default)]
enum FinalSize {
    #[default]
    Open,
    Pending(u64),
    InFlight(u64),
    Acknowledged(u64),
    Reset {
        offset: u64,
        local_shutdown: bool,
        stop: Option<StopNotice>,
    },
}

#[derive(Debug)]
struct StopNotice {
    code: u64,
    reported: bool,
}

impl FinalSize {
    const fn offset(&self) -> Option<u64> {
        match *self {
            Self::Open => None,
            Self::Pending(offset) |
            Self::InFlight(offset) |
            Self::Acknowledged(offset) |
            Self::Reset { offset, .. } => Some(offset),
        }
    }
}

/// Send-side stream buffer.
///
/// Stream data scheduled to be sent to the peer is buffered in a list of data
/// chunks ordered by offset in ascending order. Contiguous data can then be
/// read into a slice.
///
/// By default, new data is appended at the end of the stream, but data can be
/// inserted at the start of the buffer (this is to allow data that needs to be
/// retransmitted to be re-buffered).
#[derive(Debug, Default)]
pub struct SendBuf<F = DefaultBufFactory>
where
    F: BufFactory,
{
    /// Chunks of data to be sent, ordered by offset.
    data: VecDeque<RangeBuf<F>>,

    /// The index of the buffer that needs to be sent next.
    pos: usize,

    /// The maximum offset of data buffered in the stream.
    off: u64,

    /// The maximum offset of data sent to the peer, regardless of
    /// retransmissions.
    emit_off: u64,

    /// The number of bytes buffered and ready to be emitted to the peer.
    ///
    /// This includes fresh data that has not yet been sent, as well as data
    /// marked for retransmission. It excludes data that has been emitted but
    /// not yet acknowledged (in-flight data).
    buffered_bytes: u64,

    /// The maximum offset we are allowed to send to the peer.
    max_data: u64,

    /// The last offset the stream was blocked at, if any.
    blocked_at: Option<u64>,

    /// Final-size transmission state, including reset and peer stop delivery.
    final_size: FinalSize,

    /// Ranges of data offsets that have been acked.
    acked: ranges::RangeSet,
}

impl<F: BufFactory> SendBuf<F> {
    /// Creates a new send buffer.
    pub fn new(max_data: u64) -> Self {
        Self {
            max_data,
            ..Self::default()
        }
    }

    /// Try to reserve the required number of bytes to be sent
    fn reserve_for_write(
        &mut self, mut len: usize, mut fin: bool,
    ) -> Result<SendReserve<'_, F>> {
        let requested_end = self.off.checked_add(len as u64);

        // Get the stream send capacity. This will return an error if the stream
        // was stopped. Clamp before calculating the accepted end offset.
        let cap = self.cap()?;
        if len > cap {
            len = cap;
            fin = false;
        }

        if let Some(fin_off) = self.final_size.offset() {
            let requested_end = requested_end.ok_or(Error::FinalSize)?;
            // Can't write past final offset.
            if requested_end > fin_off {
                return Err(Error::FinalSize);
            }

            // Can't "undo" final offset.
            if requested_end == fin_off && !fin {
                return Err(Error::FinalSize);
            }
        }

        // The accepted length is bounded by the remaining u64 credit, even
        // when that credit exceeds usize::MAX on this target.
        let max_off = self.off + len as u64;
        if fin && matches!(self.final_size, FinalSize::Open) {
            self.final_size = FinalSize::Pending(max_off);
        }

        // Don't queue data that was already fully acked.
        if self.ack_off() >= max_off {
            return Ok(SendReserve {
                inner: self,
                reserved: 0,
                fin,
            });
        }

        Ok(SendReserve {
            inner: self,
            reserved: len,
            fin,
        })
    }

    /// Inserts the given slice of data at the end of the buffer.
    ///
    /// The number of bytes that were actually stored in the buffer is returned
    /// (this may be lower than the size of the input buffer, in case of partial
    /// writes).
    pub fn write(&mut self, data: &[u8], fin: bool) -> Result<usize> {
        let mut reserve = self.reserve_for_write(data.len(), fin)?;

        if reserve.reserved == 0 {
            return Ok(0);
        }

        let ret = reserve.reserved;

        // Split the remaining input data into consistently-sized buffers to
        // avoid fragmentation.
        for chunk in data[..reserve.reserved].chunks(SEND_BUFFER_SIZE) {
            reserve.append_buf(F::buf_from_slice(chunk))?;
        }

        Ok(ret)
    }

    /// Inserts the given buffer of data at the end of the buffer.
    ///
    /// The number of bytes that were actually stored in the buffer is returned
    /// (this may be lower than the size of the input buffer, in case of partial
    /// writes, in which case the unwritten buffer is also returned).
    pub fn append_buf(
        &mut self, mut data: F::Buf, cap: usize, fin: bool,
    ) -> Result<(usize, Option<F::Buf>)>
    where
        F::Buf: BufSplit,
    {
        let len = data.as_ref().len();
        let mut reserve = self.reserve_for_write(cap.min(len), fin)?;

        if reserve.reserved == 0 {
            return Ok((0, Some(data)));
        }

        let remainder =
            (reserve.reserved < len).then(|| data.split_at(reserve.reserved));

        let ret = reserve.reserved;

        reserve.append_buf(data)?;

        Ok((ret, remainder))
    }

    /// Writes data from the send buffer into the given output buffer.
    pub fn emit(&mut self, mut out: impl bytes::BufMut) -> (usize, bool) {
        let capacity = out.remaining_mut();
        let mut out_len = capacity;
        let mut next_off = self.off_front();

        while out_len > 0 {
            let off_front = self.off_front();

            if self.is_empty() ||
                off_front >= self.off ||
                off_front != next_off ||
                off_front >= self.max_data
            {
                break;
            }

            let Some(buf) = self.data.get_mut(self.pos) else {
                break;
            };

            if buf.is_empty() {
                self.pos += 1;
                continue;
            }

            let buf_len = cmp::min(buf.len(), out_len);
            let partial = buf_len < buf.len();

            // Copy data to the output buffer.
            out.put_slice(&buf[..buf_len]);

            self.buffered_bytes -= buf_len as u64;

            out_len -= buf_len;

            next_off = buf.off() + buf_len as u64;

            buf.consume(buf_len);

            if partial {
                // We reached the maximum capacity, so end here.
                break;
            }

            self.pos += 1;
        }

        // Override the `fin` flag set for the output buffer by matching the
        // buffer's maximum offset against the stream's final offset (if known).
        //
        // This is more efficient than tracking `fin` using the range buffers
        // themselves, and lets us avoid queueing empty buffers just so we can
        // propagate the final size.
        let fin = match self.final_size {
            FinalSize::Pending(offset) => offset == next_off,
            // Piggyback the final size on retransmitted data if it has not
            // been acknowledged. Never emit another empty FIN unless pending.
            FinalSize::InFlight(offset) =>
                offset == next_off && out_len < capacity,
            _ => false,
        };

        if fin {
            self.final_size = FinalSize::InFlight(next_off);
        }

        // Record the largest offset that has been sent so we can accurately
        // report final_size
        self.emit_off = cmp::max(self.emit_off, next_off);

        (capacity - out_len, fin)
    }

    /// Updates the `max_data` limit to the given value.
    pub fn update_max_data(&mut self, max_data: u64) {
        self.max_data = cmp::max(self.max_data, max_data);
    }

    /// Updates the last offset the stream was blocked at, if any.
    pub const fn update_blocked_at(&mut self, blocked_at: Option<u64>) {
        self.blocked_at = blocked_at;
    }

    /// The last offset the stream was blocked at, if any.
    pub const fn blocked_at(&self) -> Option<u64> {
        self.blocked_at
    }

    /// Marks the stream's final size as acknowledged by the peer.
    pub(crate) const fn ack_fin(&mut self) {
        if let FinalSize::Pending(offset) | FinalSize::InFlight(offset) =
            self.final_size
        {
            self.final_size = FinalSize::Acknowledged(offset);
        }
    }

    /// Retire acknowledged byte ranges, including sparse acknowledgments.
    /// Returns the number of pending bytes removed from the send queue.
    pub fn ack_and_drop(&mut self, off: u64, len: usize) -> u64 {
        let end = off.saturating_add(len as u64).min(self.emit_off);
        if off >= end {
            return 0;
        }
        self.acked.insert(off..end);

        // Acknowledgment can only remove pending data, never move it
        // earlier. Remember the cursor before changing chunk indices.
        let next_pending = self.off_front();
        let mut first = self.data.partition_point(|buf| buf.max_off() <= off);
        let Some(buf) = self.data.get_mut(first) else {
            return 0;
        };
        if buf.start_offset() >= end {
            return 0;
        }

        // Retain any unacknowledged prefix of the first overlapping chunk.
        if buf.start_offset() < off {
            if let Some(tail) = buf.split_off(off) {
                first += 1;
                self.data.insert(first, tail);
            }
        }

        // Remove whole chunks, and trim a partially covered last chunk
        // without copying its backing allocation.
        let last = self.data.partition_point(|buf| buf.max_off() <= end);
        let mut dropped = self
            .data
            .drain(first..last)
            .map(|buf| buf.len() as u64)
            .sum::<u64>();
        if let Some(buf) = self.data.get_mut(first) {
            dropped += buf.acknowledge_prefix(end);
        }

        self.pos = self
            .data
            .partition_point(|buf| buf.max_off() <= next_pending);
        self.buffered_bytes -= dropped;
        dropped
    }

    pub fn retransmit(&mut self, off: u64, len: usize) -> u64 {
        let end = off.saturating_add(len as u64).min(self.emit_off);
        let start = off.max(self.ack_off());
        if start >= end {
            return 0;
        }

        let mut total_retransmitted = 0;
        let first = self.data.partition_point(|buf| buf.max_off() <= start);
        for i in first..self.data.len() {
            let buf = &mut self.data[i];
            if buf.start_offset() >= end {
                break;
            }
            if start >= buf.off() {
                continue;
            }

            // Split only when an already emitted suffix lies outside the
            // loss. An existing pending suffix can stay in the same chunk.
            let tail = if end < buf.off() {
                buf.split_off(end)
            } else {
                None
            };
            let retransmitted = buf.rewind_to(start);
            if retransmitted != 0 {
                self.pos = self.pos.min(i);
                self.buffered_bytes += retransmitted;
                total_retransmitted += retransmitted;
            }

            if let Some(tail) = tail {
                self.data.insert(i + 1, tail);
                break;
            }
        }
        total_retransmitted
    }

    /// Marks the final size for retransmission after a STREAM frame carrying
    /// FIN was lost.
    ///
    /// This is needed even when the frame's data was acknowledged in another
    /// packet, as the FIN still has to reach the peer.
    pub(crate) const fn retransmit_fin(&mut self) {
        if let FinalSize::InFlight(offset) = self.final_size {
            self.final_size = FinalSize::Pending(offset);
        }
    }

    /// Resets the stream at the current offset and clears all buffered data.
    fn reset(
        &mut self, local_shutdown: bool, stop: Option<StopNotice>,
    ) -> (u64, u64) {
        let unsent_off = cmp::max(self.off_front(), self.emit_off);
        let unsent_len = self.off_back().saturating_sub(unsent_off);

        // The final size is sent in RESET_STREAM instead.
        self.final_size = FinalSize::Reset {
            offset: unsent_off,
            local_shutdown,
            stop,
        };

        // Drop all buffered data.
        self.data.clear();

        // Mark relevant data as acked.
        self.off = unsent_off;
        // This covers the entire logical stream, not a single in-memory
        // buffer. Keep the ACK range in the u64 stream-offset domain.
        self.acked.insert(0..self.off);

        self.pos = 0;
        self.buffered_bytes = 0;

        (self.emit_off, unsent_len)
    }

    /// Resets the streams and records the received error code.
    ///
    /// Calling this again after the first time has no effect.
    pub fn stop(&mut self, error_code: u64) -> Result<(u64, u64)> {
        if self.is_stopped() {
            return Err(Error::Done);
        }

        Ok(self.reset(
            self.is_shutdown(),
            Some(StopNotice {
                code: error_code,
                reported: false,
            }),
        ))
    }

    /// Shuts down sending data.
    pub fn shutdown(&mut self) -> Result<(u64, u64)> {
        if self.is_shutdown() {
            return Err(Error::Done);
        }

        let stop = match &mut self.final_size {
            FinalSize::Reset { stop, .. } => stop.take(),
            _ => None,
        };
        Ok(self.reset(true, stop))
    }

    /// Seeds send offsets without buffering the preceding data.
    #[cfg(test)]
    pub fn seed_offsets_for_test(&mut self, off: u64) {
        assert!(self.data.is_empty());
        self.off = off;
        self.emit_off = off;
    }

    /// Returns the largest offset of data buffered.
    pub const fn off_back(&self) -> u64 {
        self.off
    }

    /// Returns the lowest offset of data buffered.
    pub fn off_front(&self) -> u64 {
        let mut pos = self.pos;

        // Skip empty buffers from the start of the queue.
        while let Some(b) = self.data.get(pos) {
            if !b.is_empty() {
                return b.off();
            }

            pos += 1;
        }

        self.off
    }

    /// Returns true if the next call to [`Self::emit`] will emit an empty FIN.
    pub fn empty_fin_next(&self) -> bool {
        matches!(self.final_size, FinalSize::Pending(offset) if offset == self.off_front())
    }

    /// The maximum offset we are allowed to send to the peer.
    pub const fn max_off(&self) -> u64 {
        self.max_data
    }

    /// Returns true if all data in the stream has been sent.
    ///
    /// This happens when the stream's send final size is known, and the
    /// application has already written data up to that point.
    pub fn is_fin(&self) -> bool {
        self.final_size.offset() == Some(self.off)
    }

    /// Returns true if the final size still needs to be sent to the peer.
    pub const fn is_fin_pending(&self) -> bool {
        matches!(self.final_size, FinalSize::Pending(_))
    }

    /// Returns true if the send-side of the stream is complete.
    ///
    /// This happens when the peer has acknowledged the stream's final size and
    /// all stream data up to that point, or the stream has been reset.
    pub fn is_complete(&self) -> bool {
        match self.final_size {
            FinalSize::Acknowledged(offset) | FinalSize::Reset { offset, .. } =>
                self.ack_off() == offset,
            _ => false,
        }
    }

    /// Returns true if the stream was stopped before completion.
    pub const fn is_stopped(&self) -> bool {
        matches!(self.final_size, FinalSize::Reset { stop: Some(_), .. })
    }

    /// Returns true if a `STOP_SENDING` error still needs to be delivered.
    pub const fn has_unreported_stop(&self) -> bool {
        matches!(self.final_size, FinalSize::Reset {
            stop: Some(StopNotice {
                reported: false,
                ..
            }),
            local_shutdown: false,
            ..
        })
    }

    /// Marks the `STOP_SENDING` error as reported to the application.
    pub const fn mark_stop_reported(&mut self) {
        if let FinalSize::Reset {
            stop: Some(notice), ..
        } = &mut self.final_size
        {
            notice.reported = true;
        }
    }

    /// Returns true if the stream was shut down.
    pub const fn is_shutdown(&self) -> bool {
        matches!(self.final_size, FinalSize::Reset {
            local_shutdown: true,
            ..
        })
    }

    /// Returns true if there is no data.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the highest contiguously acked offset.
    pub fn ack_off(&self) -> u64 {
        match self.acked.iter().next() {
            // Only consider the initial range if it contiguously covers the
            // start of the stream (i.e. from offset 0).
            Some(std::ops::Range { start: 0, end }) => end,

            Some(_) | None => 0,
        }
    }

    /// Returns the outgoing flow control capacity, capped at `usize::MAX`.
    ///
    /// # Errors
    /// Returns [`Error::StreamStopped`] if the peer stopped the stream.
    pub fn cap(&self) -> Result<usize> {
        // The stream was stopped, so return the error code instead.
        if let FinalSize::Reset {
            stop: Some(ref notice),
            ..
        } = self.final_size
        {
            return Err(Error::StreamStopped(notice.code));
        }

        Ok(usize::try_from(self.max_data.saturating_sub(self.off))
            .unwrap_or(usize::MAX))
    }

    /// Returns the number of separate buffers stored.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "stream tests inspect buffer-count coalescing and retirement; production does not need this accessor"
        )
    )]
    pub fn bufs_count(&self) -> usize {
        self.data.len()
    }

    /// Returns the number of bytes ready to be emitted to the peer.
    ///
    /// This includes fresh data that has not yet been sent, as well as data
    /// marked for retransmission. It excludes data that has been emitted but
    /// not yet acknowledged (in-flight data).
    pub const fn buffered_bytes(&self) -> u64 {
        self.buffered_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_buffered_accounting_keeps_full_logical_width() {
        let mut streams = <crate::stream::StreamMap>::new(5, 5, 15);
        let baseline = u64::from(u32::MAX);
        let params = crate::TransportParams {
            initial_max_data: baseline + 64,
            initial_max_stream_data_bidi_local: baseline + 32,
            initial_max_stream_data_bidi_remote: baseline + 32,
            initial_max_streams_bidi: 5,
            ..Default::default()
        };
        streams.update_peer_max_streams_bidi(5);

        // Seed a logical byte count without allocating gigabytes of data.
        streams
            .get_or_create(0, &params, &params, true, false)
            .unwrap()
            .send
            .buffered_bytes = baseline;
        streams.add_tx_buffered(baseline);

        {
            let stream = streams
                .get_or_create(4, &params, &params, true, false)
                .unwrap();
            assert_eq!(stream.send.write(b"hello", false), Ok(5));
        }
        streams.add_tx_buffered(5);
        assert_eq!(streams.tx_buffered(), baseline + 5);
        assert!(streams.tx_buffered_is_consistent());

        streams.get_mut(0).unwrap().send.buffered_bytes = 0;
        streams.sub_tx_buffered(baseline);
        assert_eq!(streams.tx_buffered(), 5);
        let mut buf = [0; 5];
        let (written, _) = streams.get_mut(4).unwrap().send.emit(&mut buf[..]);
        streams.sub_tx_buffered(written as u64);
        assert_eq!(streams.tx_buffered(), 0);
        assert!(streams.tx_buffered_is_consistent());
    }

    #[test]
    fn empty_write() {
        let mut buf = [0; 5];

        let mut send = <SendBuf>::new(u64::MAX);
        assert_eq!(send.buffered_bytes, 0);

        let (written, fin) = send.emit(&mut buf[..]);
        assert_eq!(written, 0);
        assert!(!fin);
    }

    #[test]
    fn empty_stream_completion_requires_terminal_state_not_data_ranges() {
        let mut send = <SendBuf>::new(0);
        assert!(!send.is_complete());
        assert_eq!(send.write(b"", true), Ok(0));
        assert!(!send.is_complete());
        assert_eq!(send.emit(&mut [0_u8; 0][..]), (0, true));
        assert!(!send.is_complete());
        send.ack_fin();
        assert!(send.is_complete());
        assert_eq!(send.acked.len(), 0);

        let mut send = <SendBuf>::new(0);
        assert_eq!(send.shutdown(), Ok((0, 0)));
        assert!(send.is_complete());
        assert_eq!(send.acked.len(), 0);

        let mut send = <SendBuf>::new(0);
        assert_eq!(send.stop(42), Ok((0, 0)));
        assert!(send.is_complete());
        assert_eq!(send.acked.len(), 0);
    }

    #[test]
    fn send_credit_preserves_large_remaining_windows() {
        const LARGE: u64 = 1_u64 << 32;
        let mut send = <SendBuf>::new(LARGE);
        assert_eq!(send.cap(), Ok(usize::try_from(LARGE).unwrap_or(usize::MAX)));
        assert_eq!(send.write(b"hello", false), Ok(5));
        assert_eq!(send.off_back(), 5);

        let mut send = <SendBuf>::new(LARGE + 8);
        send.seed_offsets_for_test(LARGE + 3);
        assert_eq!(send.cap(), Ok(5));
        assert_eq!(send.write(b"hello!", true), Ok(5));
        assert_eq!(send.off_back(), LARGE + 8);
        assert!(!send.is_fin_pending());
        assert_eq!(send.cap(), Ok(0));
        send.update_max_data(LARGE + 9);
        assert_eq!(send.write(b"!", true), Ok(1));
        assert!(send.is_fin_pending());
    }

    #[test]
    fn stream_reset_keeps_full_logical_ack_range() {
        const OFFSET: u64 = (1_u64 << 32) + 17;
        let mut send = <SendBuf>::new(OFFSET + 10);
        send.seed_offsets_for_test(OFFSET);
        assert_eq!(send.write(b"hello", false), Ok(5));
        let mut output = [0; 2];
        assert_eq!(send.emit(&mut output[..]), (2, false));
        assert_eq!(send.shutdown(), Ok((OFFSET + 2, 3)));
        assert_eq!(send.ack_off(), OFFSET + 2);
        assert_eq!(send.off_back(), OFFSET + 2);
        assert!(send.is_complete());
        assert!(send.is_empty());
        assert_eq!(send.buffered_bytes(), 0);
    }

    #[test]
    fn write_clamps_before_computing_the_accepted_offset() {
        let mut send = <SendBuf>::new(u64::MAX);
        send.seed_offsets_for_test(u64::MAX - 2);
        assert_eq!(send.write(b"hello", true), Ok(2));
        assert_eq!(send.off_back(), u64::MAX);
        assert_eq!(send.cap(), Ok(0));
        assert!(!send.is_fin_pending());
        assert_eq!(send.write(b"more", false), Ok(0));
        assert_eq!(send.write(b"", true), Ok(0));
        assert!(send.is_fin_pending());
        assert_eq!(send.write(b"more", true), Err(Error::FinalSize));
    }

    #[test]
    fn multi_write() {
        let mut buf = [0; 128];

        let mut send = <SendBuf>::new(u64::MAX);
        assert_eq!(send.buffered_bytes, 0);

        let first = b"something";
        let second = b"helloworld";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.buffered_bytes, 9);

        assert!(send.write(second, true).is_ok());
        assert_eq!(send.buffered_bytes, 19);

        let (written, fin) = send.emit(&mut buf[..128]);
        assert_eq!(written, 19);
        assert!(fin);
        assert_eq!(&buf[..written], b"somethinghelloworld");
        assert_eq!(send.buffered_bytes, 0);
    }

    #[track_caller]
    fn assert_emission(
        send: &mut SendBuf, capacity: usize, data: &[u8], fin: bool,
        buffered: u64, next_off: u64,
    ) {
        let mut buf = [0; 15];
        assert_eq!(send.emit(&mut buf[..capacity]), (data.len(), fin));
        assert_eq!(&buf[..data.len()], data);
        assert_eq!(send.buffered_bytes, buffered);
        assert_eq!(send.off_front(), next_off);
    }

    #[test]
    fn split_write() {
        let mut send = <SendBuf>::new(u64::MAX);
        assert_eq!(send.buffered_bytes, 0);

        let first = b"something";
        let second = b"helloworld";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.buffered_bytes, 9);

        assert!(send.write(second, true).is_ok());
        assert_eq!(send.buffered_bytes, 19);

        assert_eq!(send.off_front(), 0);

        assert_emission(&mut send, 10, b"somethingh", false, 9, 10);

        assert_emission(&mut send, 5, b"ellow", false, 4, 15);

        assert_emission(&mut send, 10, b"orld", true, 0, 19);
    }

    #[test]
    fn resend() {
        let mut send = <SendBuf>::new(u64::MAX);
        assert_eq!(send.buffered_bytes, 0);
        assert_eq!(send.off_front(), 0);

        let first = b"something";
        let second = b"helloworld";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.off_front(), 0);

        assert!(send.write(second, true).is_ok());
        assert_eq!(send.off_front(), 0);

        assert_eq!(send.buffered_bytes, 19);

        assert_emission(&mut send, 4, b"some", false, 15, 4);

        assert_emission(&mut send, 5, b"thing", false, 10, 9);

        assert_emission(&mut send, 5, b"hello", false, 5, 14);

        send.retransmit(4, 5);
        assert_eq!(send.buffered_bytes, 10);
        assert_eq!(send.off_front(), 4);

        send.retransmit(0, 4);
        assert_eq!(send.buffered_bytes, 14);
        assert_eq!(send.off_front(), 0);

        assert_emission(&mut send, 11, b"something", false, 5, 14);

        assert_emission(&mut send, 11, b"world", true, 0, 19);
    }

    #[test]
    fn write_blocked_by_off() {
        let mut buf = [0; 10];

        let mut send = <SendBuf>::default();
        assert_eq!(send.buffered_bytes, 0);

        let first = b"something";
        let second = b"helloworld";

        assert_eq!(send.write(first, false), Ok(0));
        assert_eq!(send.buffered_bytes, 0);

        assert_eq!(send.write(second, true), Ok(0));
        assert_eq!(send.buffered_bytes, 0);

        send.update_max_data(5);

        assert_eq!(send.write(first, false), Ok(5));
        assert_eq!(send.buffered_bytes, 5);

        assert_eq!(send.write(second, true), Ok(0));
        assert_eq!(send.buffered_bytes, 5);

        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..10]);
        assert_eq!(written, 5);
        assert!(!fin);
        assert_eq!(&buf[..written], b"somet");
        assert_eq!(send.buffered_bytes, 0);

        assert_eq!(send.off_front(), 5);

        let (written, fin) = send.emit(&mut buf[..10]);
        assert_eq!(written, 0);
        assert!(!fin);
        assert_eq!(&buf[..written], b"");
        assert_eq!(send.buffered_bytes, 0);

        send.update_max_data(15);

        assert_eq!(send.write(&first[5..], false), Ok(4));
        assert_eq!(send.buffered_bytes, 4);

        assert_eq!(send.write(second, true), Ok(6));
        assert_eq!(send.buffered_bytes, 10);

        assert_eq!(send.off_front(), 5);

        let (written, fin) = send.emit(&mut buf[..10]);
        assert_eq!(written, 10);
        assert!(!fin);
        assert_eq!(&buf[..10], b"hinghellow");
        assert_eq!(send.buffered_bytes, 0);

        send.update_max_data(25);

        assert_eq!(send.write(&second[6..], true), Ok(4));
        assert_eq!(send.buffered_bytes, 4);

        assert_eq!(send.off_front(), 15);

        let (written, fin) = send.emit(&mut buf[..10]);
        assert_eq!(written, 4);
        assert!(fin);
        assert_eq!(&buf[..written], b"orld");
        assert_eq!(send.buffered_bytes, 0);
    }

    #[test]
    fn zero_len_write() {
        let mut buf = [0; 10];

        let mut send = <SendBuf>::new(u64::MAX);
        assert_eq!(send.buffered_bytes, 0);

        let first = b"something";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.buffered_bytes, 9);

        assert!(send.write(&[], true).is_ok());
        assert_eq!(send.buffered_bytes, 9);

        assert_eq!(send.off_front(), 0);

        let (written, fin) = send.emit(&mut buf[..10]);
        assert_eq!(written, 9);
        assert!(fin);
        assert_eq!(&buf[..written], b"something");
        assert_eq!(send.buffered_bytes, 0);
    }

    /// Check SendBuf::len calculation on a retransmit case
    #[test]
    fn send_buf_len_on_retransmit() {
        let mut buf = [0; 15];

        let mut send = <SendBuf>::new(u64::MAX);
        assert_eq!(send.buffered_bytes, 0);
        assert_eq!(send.off_front(), 0);

        let first = b"something";

        assert!(send.write(first, false).is_ok());
        assert_eq!(send.off_front(), 0);

        assert_eq!(send.buffered_bytes, 9);

        let (written, fin) = send.emit(&mut buf[..4]);
        assert_eq!(written, 4);
        assert!(!fin);
        assert_eq!(&buf[..written], b"some");
        assert_eq!(send.buffered_bytes, 5);
        assert_eq!(send.off_front(), 4);

        send.retransmit(3, 5);
        assert_eq!(send.buffered_bytes, 6);
        assert_eq!(send.off_front(), 3);
    }

    #[test]
    fn contiguous_partial_ack_releases_pending_prefix() {
        let mut send = <SendBuf>::new(u64::MAX);
        let mut out = [0; 5];
        assert_eq!(send.write(b"hello", true), Ok(5));
        assert_eq!(send.emit(&mut out[..]), (5, true));
        assert_eq!(send.retransmit(0, 5), 5);

        assert_eq!(send.ack_and_drop(0, 2), 2);
        assert_eq!(send.buffered_bytes(), 3);
        assert_eq!(send.off_front(), 2);
        assert_eq!(send.retransmit(0, 5), 0);
        assert_eq!(send.emit(&mut out[..]), (3, true));
        assert_eq!(&out[..3], b"llo");
        assert_eq!(send.retransmit(0, 5), 3);
        assert_eq!(send.off_front(), 2);
    }

    #[test]
    fn sparse_ack_removes_only_matching_pending_bytes() {
        let mut send = <SendBuf>::new(30);
        let mut out = [0; 15];
        assert_eq!(send.write(b"abcdefghijklmno", true), Ok(15));
        assert_eq!(send.emit(&mut out[..]), (15, true));
        assert_eq!(send.retransmit(0, 15), 15);
        assert_eq!(send.ack_and_drop(3, 9), 9);
        assert_eq!(send.ack_and_drop(5, 4), 0);
        assert_eq!(send.retransmit(0, 15), 0);
        assert_emission(&mut send, 15, b"abc", false, 3, 12);
        assert_emission(&mut send, 15, b"mno", true, 0, 15);
        assert_eq!(send.retransmit(2, 11), 2);
        assert_eq!(send.ack_and_drop(0, 3), 1);
        assert_eq!(send.ack_off(), 12);
        assert_emission(&mut send, 15, b"m", false, 0, 15);
        assert_eq!(send.ack_and_drop(12, 3), 0);
        send.ack_fin();
        assert!(send.is_complete());
        assert!(send.is_empty());
    }

    #[test]
    fn sparse_ack_and_loss_match_byte_state_model() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum ByteState {
            Pending,
            InFlight,
            Acked,
        }
        use ByteState::Acked;
        use ByteState::InFlight;
        use ByteState::Pending;
        const DATA: &[u8] = b"abcdefghijklmnopqrstuvwxy";
        for seed in 1_u32..=128 {
            let mut send = <SendBuf>::new(DATA.len() as u64);
            let mut model = [Pending; DATA.len()];
            let mut highest = 0;
            let mut rng = seed;
            assert_eq!(send.write(DATA, false), Ok(DATA.len()));
            for _ in 0..160 {
                // Deterministic, dependency-free operation sequence.
                rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
                let first = (rng >> 8) as usize % (DATA.len() + 1);
                let len = (rng >> 16) as usize % (DATA.len() + 1);
                let end = (first + len).min(highest);
                let start = first.min(end);
                match rng % 3 {
                    0 => {
                        let expected = model[start..end]
                            .iter()
                            .filter(|&&s| s == Pending)
                            .count();
                        model[start..end].fill(Acked);
                        assert_eq!(
                            send.ack_and_drop(first as u64, len),
                            expected as u64
                        );
                    },
                    1 => {
                        let mut expected = 0;
                        for state in &mut model[start..end] {
                            if *state == InFlight {
                                *state = Pending;
                                expected += 1;
                            }
                        }
                        assert_eq!(send.retransmit(first as u64, len), expected);
                    },
                    _ => {
                        let start = model
                            .iter()
                            .position(|&s| s == Pending)
                            .unwrap_or(DATA.len());
                        let count = model[start..]
                            .iter()
                            .take(len)
                            .take_while(|&&s| s == Pending)
                            .count();
                        let mut out = [0; DATA.len()];
                        assert_eq!(send.emit(&mut out[..len]), (count, false));
                        assert_eq!(&out[..count], &DATA[start..start + count]);
                        model[start..start + count].fill(InFlight);
                        highest = highest.max(start + count);
                    },
                }
                assert_eq!(
                    send.buffered_bytes(),
                    model.iter().filter(|&&s| s == Pending).count() as u64,
                    "seed {seed}"
                );
                assert_eq!(
                    send.off_front(),
                    model
                        .iter()
                        .position(|&s| s == Pending)
                        .unwrap_or(DATA.len()) as u64,
                    "seed {seed}"
                );
                assert_eq!(
                    send.ack_off(),
                    model.iter().take_while(|&&s| s == Acked).count() as u64,
                    "seed {seed}"
                );
                for buf in &send.data {
                    let start = buf.start_offset() as usize;
                    let end = buf.max_off() as usize;
                    assert!(model[start..end].iter().all(|&s| s != Acked));
                }
            }
        }
    }

    #[test]
    fn send_buf_final_size_retransmit() {
        let mut buf = [0; 50];
        let mut send = <SendBuf>::new(u64::MAX);

        send.write(&buf, false).unwrap();
        assert_eq!(send.off_front(), 0);

        // Emit the whole buffer
        let (written, _fin) = send.emit(&mut buf[..]);
        assert_eq!(written, buf.len());
        assert_eq!(send.off_front(), buf.len() as u64);

        // Server decides to retransmit the last 10 bytes. It's possible
        // it's not actually lost and that the client did receive it.
        send.retransmit(40, 10);

        // Server receives STOP_SENDING from client. The final_size we
        // send in the RESET_STREAM should be 50. If we send anything less,
        // it's a FINAL_SIZE_ERROR.
        let (fin_off, unsent) = send.stop(0).unwrap();
        assert_eq!(fin_off, 50);
        assert_eq!(unsent, 0);
    }

    #[test]
    fn send_buf_fin_pending() {
        let mut buf = [0; 10];

        let mut send = <SendBuf>::new(u64::MAX);

        assert_eq!(send.write(b"hello", false), Ok(5));
        assert!(!send.is_fin_pending());

        assert_eq!(send.emit(&mut buf[..]), (5, false));

        // The final size became known after all data was sent.
        assert_eq!(send.write(b"", true), Ok(0));
        assert!(send.is_fin_pending());

        assert_eq!(send.emit(&mut buf[..]), (0, true));
        assert!(!send.is_fin_pending());

        // Writing the FIN again doesn't schedule another one.
        assert_eq!(send.write(b"", true), Ok(0));
        assert!(!send.is_fin_pending());

        // A lost FIN needs to be resent even if its data was acked.
        send.ack_and_drop(0, 5);
        send.retransmit(0, 5);
        send.retransmit_fin();
        assert!(send.is_fin_pending());

        send.ack_fin();
        assert!(!send.is_fin_pending());

        send.retransmit_fin();
        assert!(!send.is_fin_pending());
    }

    #[test]
    fn acknowledged_fin_is_not_emitted_again() {
        let mut send = <SendBuf>::new(10);
        let mut out = [0; 5];
        assert_eq!(send.write(b"hello", true), Ok(5));
        assert_eq!(send.emit(&mut out[..]), (5, true));
        assert!(!send.empty_fin_next());
        assert_eq!(send.emit(&mut out[..]), (0, false));
        send.ack_fin();
        assert_eq!(send.retransmit(0, 5), 5);
        send.retransmit_fin();
        assert_eq!(send.emit(&mut out[..]), (5, false));
        assert!(!send.empty_fin_next());
        assert_eq!(send.emit(&mut out[..]), (0, false));
        send.ack_and_drop(0, 5);
        assert!(send.is_complete());
    }

    #[test]
    fn peer_stop_and_local_shutdown_preserve_terminal_state() {
        for local_first in [false, true] {
            let mut send = <SendBuf>::new(10);
            assert_eq!(send.write(b"hello", true), Ok(5));
            if local_first {
                assert_eq!(send.shutdown(), Ok((0, 5)));
                assert_eq!(send.stop(42), Ok((0, 0)));
            } else {
                assert_eq!(send.stop(42), Ok((0, 5)));
                assert!(send.has_unreported_stop());
                send.mark_stop_reported();
                assert!(!send.has_unreported_stop());
                assert_eq!(send.shutdown(), Ok((0, 0)));
            }
            assert!(send.is_shutdown());
            assert!(send.is_stopped());
            assert!(send.is_complete());
            assert!(!send.has_unreported_stop());
            assert_eq!(send.cap(), Err(Error::StreamStopped(42)));
            assert_eq!(send.stop(43), Err(Error::Done));
            assert_eq!(send.shutdown(), Err(Error::Done));
            send.ack_fin();
            send.retransmit_fin();
            assert!(!send.empty_fin_next());
            assert_eq!(send.emit(&mut [0; 5][..]), (0, false));
        }
    }

    #[test]
    fn send_buf_fin_not_pending_after_shutdown() {
        let mut send = <SendBuf>::new(u64::MAX);

        assert_eq!(send.write(b"hello", true), Ok(5));
        assert!(send.is_fin_pending());

        assert!(send.shutdown().is_ok());
        assert!(!send.is_fin_pending());

        send.retransmit_fin();
        assert!(!send.is_fin_pending());
    }
}
