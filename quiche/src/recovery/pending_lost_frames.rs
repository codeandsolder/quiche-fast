// Copyright (C) 2026, codeandsolder contributors.
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

use std::collections::VecDeque;

use crate::frame::Frame;

/// The storage policy for frames awaiting retransmission. Legacy recovery
/// drains a stack; generic/BBRv2 recovery drains a FIFO, and their queues
/// must retain those distinct semantics.
pub trait LostFrameQueue: Default + Extend<Frame> {
    fn pop_for_retransmission(&mut self) -> Option<Frame>;
    fn is_empty(&self) -> bool;
    fn clear(&mut self);

    #[cfg(test)]
    fn len(&self) -> usize;
}

impl LostFrameQueue for Vec<Frame> {
    fn pop_for_retransmission(&mut self) -> Option<Frame> {
        self.pop()
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    fn clear(&mut self) {
        self.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.len()
    }
}

impl LostFrameQueue for VecDeque<Frame> {
    fn pop_for_retransmission(&mut self) -> Option<Frame> {
        self.pop_front()
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    fn clear(&mut self) {
        self.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.len()
    }
}

/// Packet-number-space retransmission obligations. ACK-detected losses take
/// precedence over PTO probes; storage preserves each engine's frame order.
#[derive(Default)]
pub struct PendingLostFrames<Q: LostFrameQueue> {
    ack: Q,
    pto: Q,
}

impl<Q: LostFrameQueue> PendingLostFrames<Q> {
    pub fn queue_ack(&mut self, frames: impl IntoIterator<Item = Frame>) {
        self.ack.extend(frames);
    }

    pub fn queue_pto(&mut self, frames: impl IntoIterator<Item = Frame>) {
        self.pto.extend(frames);
    }

    pub fn next_lost_frame(&mut self) -> Option<Frame> {
        self.ack
            .pop_for_retransmission()
            .or_else(|| self.pto.pop_for_retransmission())
    }

    #[must_use = "the result indicates whether retransmission work remains"]
    pub fn has_pending(&self) -> bool {
        !self.ack.is_empty() || !self.pto.is_empty()
    }

    #[must_use = "the result controls whether another PTO can queue frames"]
    pub fn pto_is_empty(&self) -> bool {
        self.pto.is_empty()
    }

    pub fn clear(&mut self) {
        self.ack.clear();
        self.pto.clear();
    }

    #[cfg(test)]
    pub fn count(&self) -> usize {
        self.ack.len() + self.pto.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_queue_policy<Q: LostFrameQueue>(expected: [u8; 4]) {
        let mut pending = PendingLostFrames::<Q>::default();
        let frame = |n| Frame::PathResponse { data: [n; 8] };

        assert!(!pending.has_pending());
        assert!(pending.pto_is_empty());
        assert_eq!(pending.count(), 0);
        assert_eq!(pending.next_lost_frame(), None);

        // PTO can be scheduled before ACK-detected losses, but ACK losses
        // still take priority regardless of either queue's draining order.
        pending.queue_pto([frame(3), frame(4)]);
        pending.queue_ack([frame(1), frame(2)]);
        assert!(pending.has_pending());
        assert!(!pending.pto_is_empty());
        assert_eq!(pending.count(), 4);

        for (index, value) in expected.into_iter().enumerate() {
            assert_eq!(pending.next_lost_frame(), Some(frame(value)));
            assert_eq!(pending.count(), 3 - index);
        }
        assert!(pending.pto_is_empty());
        assert!(!pending.has_pending());
        assert_eq!(pending.next_lost_frame(), None);

        // Packet-number-space discard clears both queues without dropping
        // their allocations; a subsequent epoch can enqueue fresh work.
        pending.queue_ack([Frame::Ping { mtu_probe: None }]);
        pending.queue_pto([Frame::Ping { mtu_probe: None }]);
        pending.clear();
        assert!(!pending.has_pending());
        assert!(pending.pto_is_empty());
        assert_eq!(pending.count(), 0);
        assert_eq!(pending.next_lost_frame(), None);
    }

    #[test]
    fn legacy_vec_retransmission_is_lifo() {
        check_queue_policy::<Vec<Frame>>([2, 1, 4, 3]);
    }

    #[test]
    fn bbr2_vecdeque_retransmission_is_fifo() {
        check_queue_policy::<VecDeque<Frame>>([1, 2, 3, 4]);
    }
}
