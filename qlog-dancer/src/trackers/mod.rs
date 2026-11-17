// Copyright (C) 2026, Cloudflare, Inc.
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

pub mod stream_buffer_tracker;
pub mod stream_max_tracker;

pub use stream_buffer_tracker::StreamBufferTracker;
pub use stream_max_tracker::StreamMaxTracker;

/// A stream tracker rejected an unrepresentable value without mutating its
/// history, per-stream maxima or cumulative totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerError {
    /// The end position of a stream buffer access exceeds `u64::MAX`.
    StreamEndOverflow {
        stream_id: u64,
        offset: u64,
        length: u64,
    },
    /// The total of all stream maxima exceeds `u64::MAX`.
    RunningSumOverflow {
        stream_id: u64,
        total: u64,
        increment: u64,
    },
}

impl std::fmt::Display for TrackerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StreamEndOverflow { stream_id, offset, length } =>
                write!(f, "stream {stream_id} end offset overflows: {offset} + {length}"),
            Self::RunningSumOverflow { stream_id, total, increment } =>
                write!(f, "stream {stream_id} cumulative tracker total overflows: {total} + {increment}"),
        }
    }
}

impl std::error::Error for TrackerError {}

/// Calculate all changes before the caller records any event history.
/// Returns the new maximum and cumulative total.
fn checked_max_advance(
    stream_id: u64, old_max: u64, new_value: u64, running_sum: u64,
) -> Result<(u64, u64), TrackerError> {
    let new_max = old_max.max(new_value);
    let increment = new_max - old_max;
    let total = running_sum.checked_add(increment).ok_or(
        TrackerError::RunningSumOverflow {
            stream_id,
            total: running_sum,
            increment,
        },
    )?;
    Ok((new_max, total))
}
