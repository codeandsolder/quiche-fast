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
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use netlog::h2::H2_DEFAULT_WINDOW_SIZE;

/// One observed send-window lifetime. The initial credit belongs to the
/// stream's first observation, rather than the session's final SETTINGS.
#[derive(Debug)]
pub(crate) struct H2SendWindowHistory {
    pub(crate) opened_at: f64,
    pub(crate) initial: u32,
    pub(crate) changes: Vec<(f64, i64)>,
}

/// Reconstruct local send credit from peer SETTINGS/WINDOW_UPDATE and
/// locally sent DATA. Only streams with an observed opening and no observed
/// local FIN/reset are affected by subsequent SETTINGS adjustments.
#[derive(Debug)]
pub struct H2SendWindows {
    initial_stream_credit: u32,
    histories: BTreeMap<u32, H2SendWindowHistory>,
    active: BTreeSet<u32>,
}

impl Default for H2SendWindows {
    fn default() -> Self {
        Self {
            initial_stream_credit: H2_DEFAULT_WINDOW_SIZE,
            histories: BTreeMap::new(),
            active: BTreeSet::new(),
        }
    }
}

impl H2SendWindows {
    pub(crate) fn open(&mut self, stream: u32, time: f64) {
        use std::collections::btree_map::Entry;
        if let Entry::Vacant(entry) = self.histories.entry(stream) {
            entry.insert(H2SendWindowHistory {
                opened_at: time,
                initial: if stream == 0 {
                    H2_DEFAULT_WINDOW_SIZE
                } else {
                    self.initial_stream_credit
                },
                changes: Vec::new(),
            });
            if stream != 0 {
                self.active.insert(stream);
            }
        }
    }

    pub(crate) fn change(&mut self, stream: u32, time: f64, delta: i64) {
        self.open(stream, if stream == 0 { time.min(0.0) } else { time });
        if stream != 0 && !self.active.contains(&stream) {
            return;
        }
        if let Some(history) = self.histories.get_mut(&stream) {
            history.changes.push((time, delta));
        }
    }

    pub(crate) fn close(&mut self, stream: u32) {
        self.active.remove(&stream);
    }

    pub(crate) fn close_session(&mut self) {
        self.active.clear();
    }

    pub(crate) fn set_initial_credit(&mut self, time: f64, credit: u32) {
        let delta = i64::from(credit) - i64::from(self.initial_stream_credit);
        self.initial_stream_credit = credit;
        if delta == 0 {
            return;
        }
        for stream in &self.active {
            if let Some(history) = self.histories.get_mut(stream) {
                history.changes.push((time, delta));
            }
        }
    }

    #[must_use = "the histories are the source for reconstructed send-window plots"]
    pub(crate) const fn histories(&self) -> &BTreeMap<u32, H2SendWindowHistory> {
        &self.histories
    }
}
