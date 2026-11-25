// Copyright (C) 2024, Cloudflare, Inc.
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

//! Shared action scheduling for synchronous and asynchronous clients.

use std::time::Instant;

use crate::actions::h3::Action;
use crate::actions::h3::StreamEvent;
use crate::actions::h3::WaitType;
use crate::actions::h3::WaitingFor;
use crate::quiche;

use super::execute_action;
use super::StreamParserMap;

/// An ordered action queue. Consecutive waits form a single barrier: all
/// stream/quota conditions must hold and the sum of duration waits must elapse.
/// Explicit packet flushes yield to the transport before the next action.
#[derive(Default)]
pub(crate) struct ActionQueue {
    actions: Vec<Action>,
    next: usize,
    waiting: WaitingFor,
    deadline: Option<Instant>,
}

impl ActionQueue {
    pub(crate) fn new(actions: Vec<Action>) -> Self {
        Self {
            actions,
            next: 0,
            waiting: WaitingFor::default(),
            deadline: None,
        }
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.next == self.actions.len() &&
            self.deadline.is_none() &&
            self.waiting.is_empty()
    }

    pub(crate) fn wakeup(&self, now: Instant) -> Option<Instant> {
        if !self.waiting.is_empty() {
            return None;
        }
        self.deadline
            .or_else(|| (self.next < self.actions.len()).then_some(now))
    }

    fn refresh(&mut self, now: Instant, bidi: u64, uni: u64) {
        if self.deadline.is_some_and(|deadline| deadline <= now) {
            self.deadline = None;
        }
        self.waiting.check_quotas(bidi, uni);
    }

    fn is_blocked(&self) -> bool {
        self.deadline.is_some() || !self.waiting.is_empty()
    }

    fn prepare_waits(
        &mut self, now: Instant, bidi: u64, uni: u64,
    ) -> Result<(), String> {
        self.refresh(now, bidi, uni);
        if self.is_blocked() {
            return Ok(());
        }
        while let Some(Action::Wait { wait_type }) = self.actions.get(self.next) {
            match wait_type {
                WaitType::WaitDuration(duration) => {
                    self.deadline = Some(
                        self.deadline
                            .unwrap_or(now)
                            .checked_add(*duration)
                            .ok_or_else(|| {
                                "wait duration exceeds clock range".to_owned()
                            })?,
                    );
                },
                WaitType::StreamEvent(event) => self.waiting.add_wait(event),
                WaitType::CanOpenNumStreams(quota) =>
                    self.waiting.set_required_stream_quota(*quota),
            }
            self.next += 1;
        }
        self.refresh(now, bidi, uni);
        Ok(())
    }

    /// Register leading waits before reading so an already-received response in
    /// the current I/O iteration cannot race the barrier registration.
    pub(crate) fn before_reads<F: quiche::BufFactory>(
        &mut self, now: Instant, conn: &quiche::Connection<F>,
    ) -> Result<(), String> {
        self.prepare_waits(
            now,
            conn.peer_streams_left_bidi(),
            conn.peer_streams_left_uni(),
        )
    }

    pub(crate) fn on_stream_event(&mut self, event: StreamEvent) {
        self.waiting.remove_wait(event);
    }

    /// Execute until blocked, exhausted, or an explicit flush is encountered.
    /// Each wait starts at the current clock after preceding actions execute.
    pub(crate) fn advance<F: quiche::BufFactory>(
        &mut self, now: impl Fn() -> Instant, conn: &mut quiche::Connection<F>,
        parsers: &mut StreamParserMap,
    ) -> Result<(), String> {
        loop {
            self.before_reads(now(), conn)?;
            if self.is_blocked() {
                return Ok(());
            }
            let Some(action) = self.actions.get(self.next) else {
                return Ok(());
            };
            if matches!(action, Action::FlushPackets) {
                self.next += 1;
                return Ok(());
            }
            execute_action(action, conn, parsers)?;
            self.next += 1;
            if matches!(action, Action::ConnectionClose { .. }) {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ActionQueue;
    use crate::actions::h3::Action;
    use crate::actions::h3::RequiredStreamsQuota;
    use crate::actions::h3::StreamEvent;
    use crate::actions::h3::StreamEventType;
    use crate::actions::h3::WaitType;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn consecutive_waits_are_one_barrier_with_independent_conditions(
    ) -> Result<(), String> {
        let now = Instant::now();
        let event = StreamEvent {
            stream_id: 4,
            event_type: StreamEventType::Headers,
        };
        let mut queue = ActionQueue::new(vec![
            WaitType::WaitDuration(Duration::from_millis(10)).into(),
            WaitType::StreamEvent(event).into(),
            WaitType::WaitDuration(Duration::from_millis(20)).into(),
            WaitType::CanOpenNumStreams(RequiredStreamsQuota {
                num: 3,
                bidi: true,
            })
            .into(),
            WaitType::CanOpenNumStreams(RequiredStreamsQuota {
                num: 2,
                bidi: false,
            })
            .into(),
            Action::FlushPackets,
        ]);
        queue.prepare_waits(now, 1, 1)?;
        assert_eq!(queue.wakeup(now), None);
        assert_eq!(queue.next, 5);
        queue.on_stream_event(StreamEvent {
            stream_id: 8,
            event_type: StreamEventType::Headers,
        });
        queue.prepare_waits(now, 3, 2)?;
        assert_eq!(queue.wakeup(now), None);
        queue.on_stream_event(event);
        let deadline = now + Duration::from_millis(30);
        assert_eq!(queue.wakeup(now), Some(deadline));
        queue.prepare_waits(now + Duration::from_millis(29), 3, 2)?;
        assert!(queue.is_blocked());
        queue.prepare_waits(deadline, 3, 2)?;
        assert!(!queue.is_blocked());
        assert_eq!(queue.wakeup(deadline), Some(deadline));
        assert_eq!(queue.actions.get(queue.next), Some(&Action::FlushPackets));
        Ok(())
    }

    #[test]
    fn already_satisfied_quota_and_zero_duration_do_not_block(
    ) -> Result<(), String> {
        let now = Instant::now();
        let mut queue = ActionQueue::new(vec![
            WaitType::CanOpenNumStreams(RequiredStreamsQuota {
                num: 1,
                bidi: true,
            })
            .into(),
            WaitType::WaitDuration(Duration::ZERO).into(),
        ]);
        queue.prepare_waits(now, 1, 0)?;
        assert!(queue.is_finished());
        assert_eq!(queue.wakeup(now), None);
        Ok(())
    }

    #[test]
    fn terminal_duration_remains_pending_and_overflow_is_an_error(
    ) -> Result<(), String> {
        let now = Instant::now();
        let mut queue = ActionQueue::new(vec![WaitType::WaitDuration(
            Duration::from_millis(1),
        )
        .into()]);
        queue.prepare_waits(now, 0, 0)?;
        assert!(!queue.is_finished());
        let later = now + Duration::from_millis(1);
        queue.prepare_waits(later, 0, 0)?;
        assert!(queue.is_finished());
        let mut queue =
            ActionQueue::new(vec![WaitType::WaitDuration(Duration::MAX).into()]);
        assert!(queue.prepare_waits(now, 0, 0).is_err());
        Ok(())
    }
}
