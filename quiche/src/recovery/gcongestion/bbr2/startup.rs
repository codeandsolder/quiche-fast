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

use crate::recovery::gcongestion::bbr2::Params;
use crate::recovery::RecoveryStats;
use crate::recovery::StartupExit;
use crate::recovery::StartupExitReason;

use super::network_model::BBRv2NetworkModel;
use super::BBRv2CongestionEvent;

/// Returns whether startup has reached full bandwidth and should drain.
pub(super) fn on_congestion_event(
    model: &mut BBRv2NetworkModel, congestion_event: &BBRv2CongestionEvent,
    params: &Params, recovery_stats: &mut RecoveryStats,
) -> bool {
    if model.full_bandwidth_reached() {
        return true;
    }

    if !congestion_event.end_of_round_trip {
        return false;
    }

    let has_bandwidth_growth =
        model.has_bandwidth_growth(congestion_event, params);
    if model.full_bandwidth_reached() {
        recovery_stats.set_startup_exit(StartupExit::new(
            congestion_event.prior_cwnd,
            Some(model.max_bandwidth()),
            StartupExitReason::BandwidthPlateau,
        ));
    }

    let check_persistent_queue =
        params.max_startup_queue_rounds > 0 && !has_bandwidth_growth;
    if check_persistent_queue {
        // https://github.com/google/quiche/blob/27eca0257490df89d2bd2c2a8bcea15565e7831c/quiche/quic/core/congestion_control/bbr2_startup.cc#L60-L62
        // 1.75 is less than the 2x CWND gain, but substantially more than
        // 1.25x, the minimum bandwidth increase expected during
        // STARTUP.
        model.check_persistent_queue(
            1.75,
            congestion_event.max_datagram_size,
            params,
        );
        if model.full_bandwidth_reached() {
            recovery_stats.set_startup_exit(StartupExit::new(
                congestion_event.prior_cwnd,
                Some(model.max_bandwidth()),
                StartupExitReason::PersistentQueue,
            ));
        }
    }

    // TCP BBR always exits upon excessive losses. QUIC BBRv1 does not exit
    // upon excessive losses if enough bandwidth growth is observed or the
    // sample was app-limited.
    let check_for_excessive_loss = !congestion_event.last_packet_send_state.is_app_limited &&
                !has_bandwidth_growth &&
                // check for excessive loss only if not exiting for other reasons
                !model.full_bandwidth_reached();

    if check_for_excessive_loss {
        check_excessive_losses(model, congestion_event, params);

        if model.full_bandwidth_reached() {
            recovery_stats.set_startup_exit(StartupExit::new(
                congestion_event.prior_cwnd,
                Some(model.max_bandwidth()),
                StartupExitReason::Loss,
            ));
        }
    }

    model.full_bandwidth_reached()
}

fn check_excessive_losses(
    model: &mut BBRv2NetworkModel, congestion_event: &BBRv2CongestionEvent,
    params: &Params,
) {
    // At the end of a round trip. Check if loss is too high in this round.
    if model.is_inflight_too_high(
        congestion_event,
        params.startup_full_loss_count,
        params,
    ) {
        let mut new_inflight_hi = model.bdp0();

        if params.startup_loss_exit_use_max_delivered_for_inflight_hi {
            new_inflight_hi =
                new_inflight_hi.max(model.max_bytes_delivered_in_round());
        }

        model.set_inflight_hi(new_inflight_hi);
        model.set_full_bandwidth_reached();
    }
}
