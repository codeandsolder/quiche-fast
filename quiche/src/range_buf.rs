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

use std::cmp;
use std::marker::PhantomData;
use std::ops::Deref;

use crate::buffers::BufFactory;
use crate::buffers::DefaultBufFactory;

/// Buffer holding data at a specific offset.
///
/// The data is stored in a `Vec<u8>` in such a way that it can be shared
/// between multiple `RangeBuf` objects.
///
/// Each `RangeBuf` will have its own view of that buffer, where the `start`
/// value indicates the initial offset within the `Vec`, and `len` indicates the
/// number of bytes, starting from `start` that are included.
///
/// In addition, `pos` indicates the current offset within the `Vec`, starting
/// from the very beginning of the `Vec`.
///
/// Finally, `off` is the starting offset for the specific `RangeBuf` within the
/// stream the buffer belongs to.
#[derive(Clone, Debug, Default)]
pub struct RangeBuf<F = DefaultBufFactory>
where
    F: BufFactory,
{
    /// The internal buffer holding the data.
    ///
    /// To avoid needless allocations when a `RangeBuf` is split, this field
    /// should be reference-counted so it can be shared between multiple
    /// `RangeBuf` objects, and sliced using the `start` and `len` values.
    data: F::Buf,

    /// The initial offset within the internal buffer.
    start: usize,

    /// The current offset within the internal buffer.
    pos: usize,

    /// The number of bytes in the buffer, from the initial offset.
    len: usize,

    /// The offset of the buffer within a stream.
    off: u64,

    /// Whether this contains the final byte in the stream.
    fin: bool,

    _bf: PhantomData<F>,
}

impl<F: BufFactory> RangeBuf<F>
where
    F::Buf: Clone,
{
    /// Creates a new `RangeBuf` from the given slice.
    pub fn from(buf: &[u8], off: u64, fin: bool) -> Self {
        Self::from_raw(F::buf_from_slice(buf), off, fin)
    }

    pub fn from_raw(data: F::Buf, off: u64, fin: bool) -> Self {
        Self {
            len: data.as_ref().len(),
            data,
            start: 0,
            pos: 0,
            off,
            fin,
            _bf: PhantomData,
        }
    }

    /// Returns whether `self` holds the final offset in the stream.
    pub const fn fin(&self) -> bool {
        self.fin
    }

    /// Returns the starting offset of `self`.
    pub const fn off(&self) -> u64 {
        self.off + (self.pos - self.start) as u64
    }

    /// Returns the final offset of `self`.
    pub const fn max_off(&self) -> u64 {
        self.off() + self.len() as u64
    }

    /// Returns the length of `self`.
    pub const fn len(&self) -> usize {
        self.len - (self.pos - self.start)
    }

    /// Returns true if `self` has a length of zero bytes.
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Consumes the starting `count` bytes of `self`.
    pub const fn consume(&mut self, count: usize) {
        self.pos += count;
    }

    /// The stream offset of the retained range, including emitted bytes.
    pub const fn start_offset(&self) -> u64 {
        self.off
    }

    /// Split at an absolute stream offset, not an index into an allocation.
    /// Both pieces retain their emitted/pending cursor positions.
    pub fn split_off(&mut self, offset: u64) -> Option<Self> {
        let at = usize::try_from(offset.checked_sub(self.off)?).ok()?;
        if at > self.len {
            return None;
        }

        let middle = self.start + at;
        let buf = Self {
            data: self.data.clone(),
            start: middle,
            pos: cmp::max(self.pos, middle),
            len: self.len - at,
            off: offset,
            _bf: PhantomData,
            fin: self.fin,
        };

        self.pos = cmp::min(self.pos, middle);
        self.len = at;
        self.fin = false;
        Some(buf)
    }

    /// Rewind the emitted cursor no earlier than the retained range.
    /// Return the newly pending byte count.
    pub fn rewind_to(&mut self, offset: u64) -> u64 {
        if offset >= self.off() {
            return 0;
        }
        let relative =
            usize::try_from(offset.saturating_sub(self.off)).unwrap_or(self.len);
        let next = self.start + relative;
        let restored = self.pos - next;
        self.pos = next;
        restored as u64
    }

    /// Drop a contiguous prefix without cloning the backing
    /// allocation. Return the number of pending bytes removed.
    pub fn discard_prefix(&mut self, offset: u64) -> u64 {
        let bytes = usize::try_from(offset.saturating_sub(self.off))
            .unwrap_or(self.len)
            .min(self.len);
        let start = self.start + bytes;
        let pending = start.saturating_sub(self.pos);
        self.start = start;
        self.pos = self.pos.max(start);
        self.len -= bytes;
        self.off += bytes as u64;
        pending as u64
    }
}

impl<F: BufFactory> Deref for RangeBuf<F> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data.as_ref()[self.pos..self.start + self.len]
    }
}

impl<F: BufFactory> Ord for RangeBuf<F> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // Invert ordering to implement min-heap.
        self.off.cmp(&other.off).reverse()
    }
}

impl<F: BufFactory> PartialOrd for RangeBuf<F> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: BufFactory> Eq for RangeBuf<F> {}

impl<F: BufFactory> PartialEq for RangeBuf<F> {
    fn eq(&self, other: &Self) -> bool {
        self.off == other.off
    }
}

#[cfg(test)]
mod tests {
    use super::RangeBuf;

    #[test]
    fn rangebuf_split_off() {
        let mut buf = <RangeBuf>::from(b"helloworld", 5, true);
        assert_eq!(buf.start, 0);
        assert_eq!(buf.pos, 0);
        assert_eq!(buf.len, 10);
        assert_eq!(buf.off, 5);
        assert!(buf.fin);

        assert_eq!(buf.len(), 10);
        assert_eq!(buf.off(), 5);
        assert!(buf.fin());

        assert_eq!(&buf[..], b"helloworld");

        // Advance buffer.
        buf.consume(5);

        assert_eq!(buf.start, 0);
        assert_eq!(buf.pos, 5);
        assert_eq!(buf.len, 10);
        assert_eq!(buf.off, 5);
        assert!(buf.fin);

        assert_eq!(buf.len(), 5);
        assert_eq!(buf.off(), 10);
        assert!(buf.fin());

        assert_eq!(&buf[..], b"world");

        // Split buffer before position.
        let mut new_buf = buf.split_off(8).unwrap();

        assert_eq!(buf.start, 0);
        assert_eq!(buf.pos, 3);
        assert_eq!(buf.len, 3);
        assert_eq!(buf.off, 5);
        assert!(!buf.fin);

        assert_eq!(buf.len(), 0);
        assert_eq!(buf.off(), 8);
        assert!(!buf.fin());

        assert_eq!(&buf[..], b"");

        assert_eq!(new_buf.start, 3);
        assert_eq!(new_buf.pos, 5);
        assert_eq!(new_buf.len, 7);
        assert_eq!(new_buf.off, 8);
        assert!(new_buf.fin);

        assert_eq!(new_buf.len(), 5);
        assert_eq!(new_buf.off(), 10);
        assert!(new_buf.fin());

        assert_eq!(&new_buf[..], b"world");

        // Advance buffer.
        new_buf.consume(2);

        assert_eq!(new_buf.start, 3);
        assert_eq!(new_buf.pos, 7);
        assert_eq!(new_buf.len, 7);
        assert_eq!(new_buf.off, 8);
        assert!(new_buf.fin);

        assert_eq!(new_buf.len(), 3);
        assert_eq!(new_buf.off(), 12);
        assert!(new_buf.fin());

        assert_eq!(&new_buf[..], b"rld");

        // Split buffer after position.
        let mut new_new_buf = new_buf.split_off(13).unwrap();

        assert_eq!(new_buf.start, 3);
        assert_eq!(new_buf.pos, 7);
        assert_eq!(new_buf.len, 5);
        assert_eq!(new_buf.off, 8);
        assert!(!new_buf.fin);

        assert_eq!(new_buf.len(), 1);
        assert_eq!(new_buf.off(), 12);
        assert!(!new_buf.fin());

        assert_eq!(&new_buf[..], b"r");

        assert_eq!(new_new_buf.start, 8);
        assert_eq!(new_new_buf.pos, 8);
        assert_eq!(new_new_buf.len, 2);
        assert_eq!(new_new_buf.off, 13);
        assert!(new_new_buf.fin);

        assert_eq!(new_new_buf.len(), 2);
        assert_eq!(new_new_buf.off(), 13);
        assert!(new_new_buf.fin());

        assert_eq!(&new_new_buf[..], b"ld");

        // Advance buffer.
        new_new_buf.consume(2);

        assert_eq!(new_new_buf.start, 8);
        assert_eq!(new_new_buf.pos, 10);
        assert_eq!(new_new_buf.len, 2);
        assert_eq!(new_new_buf.off, 13);
        assert!(new_new_buf.fin);

        assert_eq!(new_new_buf.len(), 0);
        assert_eq!(new_new_buf.off(), 15);
        assert!(new_new_buf.fin());

        assert_eq!(&new_new_buf[..], b"");
    }

    #[test]
    fn invalid_absolute_split_preserves_range() {
        let mut buf = <RangeBuf>::from(b"hello", 7, true);
        for offset in [0, 6, 13, u64::MAX] {
            assert!(buf.split_off(offset).is_none());
            assert_eq!(buf.off(), 7);
            assert_eq!(buf.max_off(), 12);
            assert_eq!(&buf[..], b"hello");
            assert!(buf.fin());
        }
    }
}
