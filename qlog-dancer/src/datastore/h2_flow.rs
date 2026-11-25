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

//! Observed HTTP/2 send-window history.
use std::borrow::Cow;
use std::collections::BTreeMap;

use netlog::h2::H2_DEFAULT_WINDOW_SIZE;

/// One observed send-window lifetime. The initial credit belongs to the
/// stream's first observation, rather than the session's final SETTINGS.
#[derive(Debug)]
pub struct H2SendWindowHistory {
    pub(crate) opened_at: f64,
    pub(crate) initial: u32,
    pub(crate) changes: Vec<(f64, i64)>,
}

#[derive(Clone, Copy, Debug)]
enum WindowEvent {
    Open(u32),
    Change { stream: u32, delta: i64 },
    Close(u32),
    CloseSession,
    InitialCredit(u32),
}

/// HTTP/2 send-side lifecycle and window observations. Replay in timestamp
/// order so a late log record cannot retroactively change an earlier window.
/// Peer SETTINGS and WINDOW_UPDATE adjust credit; locally sent DATA consumes
/// it. Only observed open send sides receive subsequent SETTINGS changes.
#[derive(Debug, Default)]
pub struct H2SendWindows {
    events: Vec<(f64, WindowEvent)>,
}

#[derive(Default)]
struct SendSide {
    history: Option<H2SendWindowHistory>,
    closed: bool,
}

impl SendSide {
    fn open(
        &mut self, stream: u32, time: f64, initial_stream_credit: u32,
    ) -> Option<&mut H2SendWindowHistory> {
        if self.closed {
            return None;
        }
        Some(self.history.get_or_insert_with(|| H2SendWindowHistory {
            opened_at: if stream == 0 { time.min(0.0) } else { time },
            initial: if stream == 0 {
                H2_DEFAULT_WINDOW_SIZE
            } else {
                initial_stream_credit
            },
            changes: Vec::new(),
        }))
    }
}

impl H2SendWindows {
    pub(crate) fn open(&mut self, stream: u32, time: f64) {
        self.events.push((time, WindowEvent::Open(stream)));
    }

    pub(crate) fn change(&mut self, stream: u32, time: f64, delta: i64) {
        self.events
            .push((time, WindowEvent::Change { stream, delta }));
    }

    pub(crate) fn close(&mut self, stream: u32, time: f64) {
        if stream != 0 {
            self.events.push((time, WindowEvent::Close(stream)));
        }
    }

    pub(crate) fn close_session(&mut self, time: f64) {
        self.events.push((time, WindowEvent::CloseSession));
    }

    pub(crate) fn set_initial_credit(&mut self, time: f64, credit: u32) {
        self.events.push((time, WindowEvent::InitialCredit(credit)));
    }

    /// Reconstruct lifetimes and window changes. A reset before any observed
    /// opening leaves a closed-side tombstone, not a fabricated history.
    /// Preserve log order at equal timestamps.
    #[must_use = "the histories are the source for reconstructed send-window plots"]
    pub(crate) fn histories(&self) -> BTreeMap<u32, H2SendWindowHistory> {
        let events = if self
            .events
            .windows(2)
            .all(|pair| pair[0].0.total_cmp(&pair[1].0).is_le())
        {
            Cow::Borrowed(self.events.as_slice())
        } else {
            let mut events = self.events.clone();
            events.sort_by(|a, b| a.0.total_cmp(&b.0));
            Cow::Owned(events)
        };
        let mut sides = BTreeMap::<u32, SendSide>::new();
        let mut initial_stream_credit = H2_DEFAULT_WINDOW_SIZE;
        for &(time, event) in events.as_ref() {
            match event {
                WindowEvent::Open(stream) => {
                    let _ = sides.entry(stream).or_default().open(
                        stream,
                        time,
                        initial_stream_credit,
                    );
                },
                WindowEvent::Change { stream, delta } => {
                    if let Some(history) = sides.entry(stream).or_default().open(
                        stream,
                        time,
                        initial_stream_credit,
                    ) {
                        history.changes.push((time, delta));
                    }
                },
                WindowEvent::Close(stream) => {
                    sides.entry(stream).or_default().closed = true;
                },
                WindowEvent::CloseSession => break,
                WindowEvent::InitialCredit(credit) => {
                    let delta =
                        i64::from(credit) - i64::from(initial_stream_credit);
                    initial_stream_credit = credit;
                    if delta != 0 {
                        for (&stream, side) in &mut sides {
                            if stream != 0 && !side.closed {
                                if let Some(history) = &mut side.history {
                                    history.changes.push((time, delta));
                                }
                            }
                        }
                    }
                },
            }
        }
        sides
            .into_iter()
            .filter_map(|(stream, side)| {
                side.history.map(|history| (stream, history))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::H2SendWindows;

    #[test]
    fn replay_orders_settings_activity_and_closure_and_keeps_tombstones() {
        let mut tracker = H2SendWindows::default();
        tracker.change(1, 6.0, 50);
        tracker.close(1, 5.0);
        tracker.close(3, 2.0);
        tracker.change(3, 4.0, 30);
        tracker.set_initial_credit(3.0, 50);
        tracker.open(1, 1.0);
        tracker.change(1, 2.0, -80);
        tracker.open(5, 4.0);
        tracker.close_session(8.0);
        tracker.set_initial_credit(7.0, 120);
        tracker.change(0, 4.0, -80);
        tracker.change(0, 9.0, 100);
        tracker.open(7, 10.0);

        let histories = tracker.histories();
        assert_eq!(histories.keys().copied().collect::<Vec<_>>(), [0, 1, 5]);
        assert_eq!(histories[&1].initial, 65_535);
        assert_eq!(histories[&1].changes, [(2.0, -80), (3.0, -65_485)]);
        assert_eq!(histories[&5].initial, 50);
        assert_eq!(histories[&5].changes, [(7.0, 70)]);
        assert_eq!(histories[&0].initial, 65_535);
        assert_eq!(histories[&0].changes, [(4.0, -80)]);
    }
}
