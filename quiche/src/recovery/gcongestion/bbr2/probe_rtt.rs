// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

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

use std::time::Instant;

use crate::recovery::gcongestion::bbr2::Params;

use super::mode::Cycle;
use super::network_model::BBRv2NetworkModel;
use super::BBRv2CongestionEvent;
use super::Limits;

#[derive(Debug)]
pub(super) struct ProbeRTT {
    pub(super) cycle: Cycle,
    exit_time: Option<Instant>,
}

impl ProbeRTT {
    pub(super) const fn new(cycle: Cycle) -> Self {
        Self {
            cycle,
            exit_time: None,
        }
    }

    fn inflight_target(model: &BBRv2NetworkModel, params: &Params) -> usize {
        model.bdp(
            model.max_bandwidth(),
            params.probe_rtt_inflight_target_bdp_fraction,
        )
    }

    /// Returns true when the min-RTT sampling interval has completed.
    pub(super) fn on_congestion_event(
        &mut self, model: &BBRv2NetworkModel, event: &BBRv2CongestionEvent,
        params: &Params,
    ) -> bool {
        if let Some(exit_time) = self.exit_time {
            return event.event_time > exit_time;
        }
        if event.bytes_in_flight <= Self::inflight_target(model, params) {
            self.exit_time = Some(event.event_time + params.probe_rtt_duration);
        }
        false
    }

    pub(super) fn cwnd_limits(
        model: &BBRv2NetworkModel, params: &Params,
    ) -> Limits<usize> {
        Limits::no_greater_than(
            model
                .inflight_lo()
                .min(model.inflight_hi_with_headroom(params))
                .min(Self::inflight_target(model, params)),
        )
    }

    pub(super) fn ready_to_leave_quiescence(&self, now: Instant) -> bool {
        self.exit_time.is_none_or(|exit_time| now > exit_time)
    }
}
