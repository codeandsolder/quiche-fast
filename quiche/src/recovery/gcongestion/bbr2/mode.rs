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

use std::time::Duration;
use std::time::Instant;

use crate::recovery::gcongestion::bbr2::Params;
use crate::recovery::RecoveryStats;

use super::network_model::BBRv2NetworkModel;
use super::probe_bw::ProbeBW;
use super::probe_rtt::ProbeRTT;
use super::startup;
use super::BBRv2CongestionEvent;
use super::Limits;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CyclePhase {
    Up,
    Down,
    Cruise,
    Refill,
}

impl CyclePhase {
    pub(super) const fn pacing_gain(self, params: &Params) -> f32 {
        match self {
            Self::Up => params.probe_bw_probe_up_pacing_gain,
            Self::Down => params.probe_bw_probe_down_pacing_gain,
            _ => params.probe_bw_default_pacing_gain,
        }
    }

    pub(super) const fn cwnd_gain(self, params: &Params) -> f32 {
        match self {
            Self::Up => params.probe_bw_up_cwnd_gain,
            _ => params.probe_bw_cwnd_gain,
        }
    }
}

/// Why the last upward probe ended. Loss and a preemptively stopped
/// risky probe are mutually exclusive outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProbeOutcome {
    Normal,
    TooHigh,
    Risky,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Cycle {
    pub(super) start_time: Instant,
    pub(super) phase: CyclePhase,
    pub(super) rounds_in_phase: usize,
    pub(super) phase_start_time: Instant,
    pub(super) rounds_since_probe: usize,
    pub(super) probe_wait_time: Option<Duration>,
    pub(super) probe_up_rounds: usize,
    pub(super) probe_up_bytes: Option<usize>,
    pub(super) probe_up_acked: usize,
    // Whether max bandwidth filter window has advanced in this cycle. It is
    // advanced once per cycle.
    pub(super) has_advanced_max_bw: bool,
    pub(super) is_sample_from_probing: bool,

    pub(super) outcome: ProbeOutcome,
}

impl Cycle {
    pub(super) const fn new(now: Instant) -> Self {
        Self {
            start_time: now,
            phase_start_time: now,

            phase: CyclePhase::Down,
            rounds_in_phase: 0,
            rounds_since_probe: 0,
            probe_wait_time: None,
            probe_up_rounds: 0,
            probe_up_bytes: None,
            probe_up_acked: 0,
            has_advanced_max_bw: false,
            is_sample_from_probing: false,
            outcome: ProbeOutcome::Normal,
        }
    }
}

/// Phase-local state only. The network model belongs to Mode and stays
/// in the same allocation through every phase transition.
#[derive(Debug)]
enum Phase {
    Startup,
    Drain,
    ProbeBw(Cycle),
    ProbeRtt(ProbeRTT),
}

#[derive(Debug)]
pub(super) struct Mode {
    model: BBRv2NetworkModel,
    phase: Phase,
}

impl Mode {
    pub(super) const fn startup(model: BBRv2NetworkModel) -> Self {
        Self {
            model,
            phase: Phase::Startup,
        }
    }

    /// Process one phase. Return whether the event entered a different
    /// mode, so the caller can reprocess it under the new mode's rules.
    pub(super) fn do_on_congestion_event(
        &mut self, event: &mut BBRv2CongestionEvent,
        target_bytes_inflight: usize, params: &Params,
        recovery_stats: &mut RecoveryStats,
    ) -> bool {
        let now = event.event_time;
        let next =
            match &mut self.phase {
                Phase::Startup => {
                    if startup::on_congestion_event(
                        &mut self.model,
                        event,
                        params,
                        recovery_stats,
                    ) {
                        self.model.clear_bandwidth_lo();
                        Some(Phase::Drain)
                    } else {
                        None
                    }
                },
                Phase::Drain => {
                    self.model.set_pacing_gain(params.drain_pacing_gain);
                    self.model.set_cwnd_gain(params.drain_cwnd_gain);
                    if event.bytes_in_flight <= self.model.bdp0() {
                        let mut cycle = Cycle::new(now);
                        ProbeBW {
                            model: &mut self.model,
                            cycle: &mut cycle,
                        }
                        .enter_probe_down(
                            ProbeOutcome::Normal,
                            now,
                            params,
                        );
                        Some(Phase::ProbeBw(cycle))
                    } else {
                        None
                    }
                },
                Phase::ProbeBw(cycle) => {
                    let switch_to_rtt = ProbeBW {
                        model: &mut self.model,
                        cycle,
                    }
                    .on_congestion_event(event, target_bytes_inflight, params);
                    if switch_to_rtt {
                        self.model.set_pacing_gain(params.probe_rtt_pacing_gain);
                        self.model.set_cwnd_gain(params.probe_rtt_cwnd_gain);
                        Some(Phase::ProbeRtt(ProbeRTT::new(*cycle)))
                    } else {
                        None
                    }
                },
                Phase::ProbeRtt(probe) => {
                    if probe.on_congestion_event(&self.model, event, params) {
                        let mut cycle = probe.cycle;
                        ProbeBW {
                            model: &mut self.model,
                            cycle: &mut cycle,
                        }
                        .resume(now);
                        Some(Phase::ProbeBw(cycle))
                    } else {
                        None
                    }
                },
            };
        if let Some(next) = next {
            self.phase = next;
            true
        } else {
            false
        }
    }

    pub(super) fn do_on_exit_quiescence(
        &mut self, now: Instant, quiescence_start_time: Instant,
    ) {
        match &mut self.phase {
            Phase::Startup | Phase::Drain => {},
            Phase::ProbeBw(_) => self.model.postpone_min_rtt_timestamp(
                now.saturating_duration_since(quiescence_start_time),
            ),
            Phase::ProbeRtt(probe) =>
                if probe.ready_to_leave_quiescence(now) {
                    let mut cycle = probe.cycle;
                    ProbeBW {
                        model: &mut self.model,
                        cycle: &mut cycle,
                    }
                    .resume(now);
                    self.phase = Phase::ProbeBw(cycle);
                },
        }
    }

    pub(super) fn get_cwnd_limits(&self, params: &Params) -> Limits<usize> {
        match &self.phase {
            Phase::Startup | Phase::Drain =>
                Limits::no_greater_than(self.model.inflight_lo()),
            Phase::ProbeBw(cycle) =>
                ProbeBW::cwnd_limits(cycle, &self.model, params),
            Phase::ProbeRtt(_) => ProbeRTT::cwnd_limits(&self.model, params),
        }
    }

    pub(super) const fn is_probing_for_bandwidth(&self) -> bool {
        match &self.phase {
            Phase::Startup => true,
            Phase::ProbeBw(cycle) =>
                matches!(cycle.phase, CyclePhase::Refill | CyclePhase::Up),
            Phase::Drain | Phase::ProbeRtt(_) => false,
        }
    }

    #[cfg(feature = "qlog")]
    pub(super) const fn state_str(&self) -> &'static str {
        match &self.phase {
            Phase::Startup => "bbr_startup",
            Phase::Drain => "bbr_drain",
            Phase::ProbeBw(cycle) => match cycle.phase {
                CyclePhase::Up => "bbr_probe_bw_up",
                CyclePhase::Down => "bbr_probe_bw_down",
                CyclePhase::Cruise => "bbr_probe_bw_cruise",
                CyclePhase::Refill => "bbr_probe_bw_refill",
            },
            Phase::ProbeRtt(_) => "bbr_probe_rtt",
        }
    }

    pub const fn network_model(&self) -> &BBRv2NetworkModel {
        &self.model
    }

    pub const fn network_model_mut(&mut self) -> &mut BBRv2NetworkModel {
        &mut self.model
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::gcongestion::bbr2::DEFAULT_PARAMS;
    use crate::BbrParams;

    #[rstest::rstest]
    fn phase_transitions_keep_model_and_probe_history(
        #[values(false, true)] resume_from_quiescence: bool,
    ) {
        let custom_bbr_settings = BbrParams {
            probe_rtt_pacing_gain: Some(0.8),
            probe_rtt_cwnd_gain: Some(0.5),
            ..Default::default()
        };
        let params = &DEFAULT_PARAMS.with_overrides(&custom_bbr_settings);
        let mut mode = Mode::startup(BBRv2NetworkModel::new(
            params,
            Duration::from_millis(100),
        ));
        let model_address = std::ptr::from_ref(mode.network_model());
        mode.model.set_full_bandwidth_reached();
        mode.model.set_inflight_hi(46_000);
        let now = mode.model.min_rtt_timestamp();
        let mut event = BBRv2CongestionEvent::new(now, 13_000, 0, true, 1300);
        let mut stats = RecoveryStats::default();

        assert!(mode.is_probing_for_bandwidth());
        assert!(
            mode.do_on_congestion_event(&mut event, 13_000, params, &mut stats)
        );
        assert!(matches!(mode.phase, Phase::Drain));
        assert!(
            mode.do_on_congestion_event(&mut event, 13_000, params, &mut stats)
        );
        let Phase::ProbeBw(cycle) = &mut mode.phase else {
            panic!("DRAIN must enter PROBE_BW");
        };
        assert_eq!(cycle.phase, CyclePhase::Down);
        cycle.outcome = ProbeOutcome::TooHigh;

        event.event_time += params.probe_rtt_period + Duration::from_millis(1);
        event.sample_min_rtt = Some(Duration::from_millis(80));
        assert!(
            mode.do_on_congestion_event(&mut event, 13_000, params, &mut stats)
        );
        assert!(matches!(mode.phase, Phase::ProbeRtt(_)));
        assert_eq!(mode.model.pacing_gain(), 0.8);
        assert_eq!(mode.model.cwnd_gain(), 0.5);

        if resume_from_quiescence {
            mode.do_on_exit_quiescence(event.event_time, now);
        } else {
            assert!(!mode
                .do_on_congestion_event(&mut event, 13_000, params, &mut stats));
            event.event_time +=
                params.probe_rtt_duration + Duration::from_millis(1);
            assert!(mode
                .do_on_congestion_event(&mut event, 13_000, params, &mut stats));
        }

        let Phase::ProbeBw(cycle) = &mode.phase else {
            panic!("PROBE_RTT must resume PROBE_BW");
        };
        assert_eq!(cycle.phase, CyclePhase::Refill);
        assert_eq!(cycle.outcome, ProbeOutcome::TooHigh);
        assert!(mode.is_probing_for_bandwidth());
        assert_eq!(std::ptr::from_ref(mode.network_model()), model_address);
        assert_eq!(mode.model.inflight_hi(), 46_000);
        assert_eq!(mode.model.min_rtt(), Duration::from_millis(80));
    }

    #[test]
    fn cycle_params() {
        let custom_bbr_settings = BbrParams {
            probe_bw_up_cwnd_gain: Some(2.25),
            probe_bw_cwnd_gain: Some(2.0),
            ..Default::default()
        };
        let params = &DEFAULT_PARAMS.with_overrides(&custom_bbr_settings);

        assert_eq!(CyclePhase::Up.pacing_gain(params), 1.25);
        assert_eq!(CyclePhase::Up.cwnd_gain(params), 2.25);

        assert_eq!(CyclePhase::Down.pacing_gain(params), 0.9);
        assert_eq!(CyclePhase::Down.cwnd_gain(params), 2.0);

        assert_eq!(CyclePhase::Cruise.pacing_gain(params), 1.0);
        assert_eq!(CyclePhase::Cruise.cwnd_gain(params), 2.0);

        assert_eq!(CyclePhase::Refill.pacing_gain(params), 1.0);
        assert_eq!(CyclePhase::Refill.cwnd_gain(params), 2.0);
    }
}
