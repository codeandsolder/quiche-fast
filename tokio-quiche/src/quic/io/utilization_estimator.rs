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

use foundations::telemetry::metrics::Gauge;
use quiche::windowed_filter::WindowedFilter;
use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use crate::quic::QuicheConnection;

const EST_WIN: usize = 10;
const MIN_PAIRED_ROUNDS: usize = 4;
const FILTER_WINDOW: Duration = Duration::from_secs(120);
const INITIAL_UPDATE_PERIOD: Duration = Duration::from_millis(50);
const MIN_UPDATE_PERIOD: Duration = Duration::from_millis(1);

/// Connection byte counters at a sampling boundary. Counter resets invalidate
/// the pending interval rather than inventing a huge wrapped delta.
#[derive(Clone, Copy, Default)]
struct ByteCounts {
    sent: u64,
    acked: u64,
    lost: u64,
}

impl ByteCounts {
    fn delta(self, previous: Self) -> Option<Self> {
        Some(Self {
            sent: self.sent.checked_sub(previous.sent)?,
            acked: self.acked.checked_sub(previous.acked)?,
            lost: self.lost.checked_sub(previous.lost)?,
        })
    }
}

/// Loss as a fraction of observed ACK/loss outcomes, in basis points.
/// Bounded integer representation avoids NaN, infinity and lossy float casts.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct LossRatio(u16);

impl LossRatio {
    fn from_outcomes(acked: u64, lost: u64) -> Self {
        let lost = u128::from(lost);
        let total = u128::from(acked) + lost;
        if total == 0 {
            return Self::default();
        }
        let basis_points = (lost * 10_000 + total / 2) / total;
        Self(u16::try_from(basis_points).unwrap_or(10_000))
    }

    pub(super) fn percent(self) -> f64 {
        f64::from(self.0) / 100.0
    }

    pub(super) fn rounded_percent(self) -> u8 {
        u8::try_from((self.0 + 50) / 100).unwrap_or(100)
    }
}

/// Tracks rolling utilized bandwidth and lifetime peaks across all connection
/// worker stages. Its current contribution is removed when the worker drops.
pub(in crate::quic) struct BandwidthReporter {
    last_update: Instant,
    update_period: Duration,
    last_bandwidth: u64,
    counters: ByteCounts,
    pub(super) max_bandwidth: u64,
    pub(super) max_loss: LossRatio,
    estimator: MaxUtilizedBandwidthEstimator,
    gauge: Gauge,
}

impl BandwidthReporter {
    pub(in crate::quic) fn new(gauge: Gauge) -> Self {
        Self {
            last_update: Instant::now(),
            update_period: INITIAL_UPDATE_PERIOD,
            last_bandwidth: 0,
            counters: ByteCounts::default(),
            max_bandwidth: 0,
            max_loss: LossRatio::default(),
            estimator: MaxUtilizedBandwidthEstimator::new(),
            gauge,
        }
    }

    pub(super) fn update(&mut self, quiche: &QuicheConnection, now: Instant) {
        if now.saturating_duration_since(self.last_update) < self.update_period {
            return;
        }
        let stats = quiche.stats();
        let counters = ByteCounts {
            sent: stats.sent_bytes,
            acked: stats.acked_bytes,
            lost: stats.lost_bytes,
        };
        let rtt = quiche
            .path_stats()
            .find(|path| path.active)
            .map(|path| path.rtt);
        self.update_counters(counters, now, rtt);
    }

    fn update_counters(
        &mut self, counters: ByteCounts, now: Instant, rtt: Option<Duration>,
    ) {
        let Some(elapsed) = now.checked_duration_since(self.last_update) else {
            return;
        };
        if elapsed < self.update_period {
            return;
        }
        let delta = counters.delta(self.counters);
        self.counters = counters;
        self.last_update = now;
        if let Some(rtt) = rtt {
            self.update_period = rtt.max(MIN_UPDATE_PERIOD);
        }
        let Some(delta) = delta else {
            self.estimator = MaxUtilizedBandwidthEstimator::new();
            self.set_bandwidth(0);
            return;
        };
        let bandwidth = self.estimator.new_round(now, elapsed, delta);
        self.set_bandwidth(bandwidth);
        self.max_bandwidth = self.max_bandwidth.max(bandwidth);
        self.max_loss = self
            .max_loss
            .max(LossRatio::from_outcomes(delta.acked, delta.lost));
    }

    fn set_bandwidth(&mut self, bandwidth: u64) {
        if bandwidth > self.last_bandwidth {
            self.gauge.inc_by(bandwidth - self.last_bandwidth);
        } else if bandwidth < self.last_bandwidth {
            self.gauge.dec_by(self.last_bandwidth - bandwidth);
        }
        self.last_bandwidth = bandwidth;
    }
}

impl Drop for BandwidthReporter {
    fn drop(&mut self) {
        self.gauge.dec_by(self.last_bandwidth);
    }
}

#[derive(Clone, Copy)]
struct SendInterval {
    bytes: u64,
    duration: Duration,
}

struct Round {
    sent: SendInterval,
    acked: u64,
    feedback_duration: Duration,
    end: Instant,
}

/// Pairs a send interval with feedback from the following interval (roughly
/// one RTT later). The actual elapsed time of each interval is retained;
/// variable RTTs and delayed polling do not bias either rate denominator.
struct MaxUtilizedBandwidthEstimator {
    rounds: VecDeque<Round>,
    maximum: WindowedFilter<u64, Instant, Duration>,
    previous_send: Option<SendInterval>,
}

impl MaxUtilizedBandwidthEstimator {
    fn new() -> Self {
        Self {
            rounds: VecDeque::with_capacity(EST_WIN),
            maximum: WindowedFilter::new(FILTER_WINDOW),
            previous_send: None,
        }
    }

    fn new_round(
        &mut self, now: Instant, elapsed: Duration, delta: ByteCounts,
    ) -> u64 {
        if elapsed.is_zero() {
            return 0;
        }
        // Do not reuse ancient send or feedback history after a long idle gap.
        if elapsed >= FILTER_WINDOW {
            self.rounds.clear();
            self.previous_send = None;
            self.maximum = WindowedFilter::new(FILTER_WINDOW);
        }
        let sent = SendInterval {
            bytes: delta.sent,
            duration: elapsed,
        };
        let previous = self.previous_send.replace(sent);
        if let Some(previous) = previous {
            while self.rounds.front().is_some_and(|round| {
                now.saturating_duration_since(round.end) > FILTER_WINDOW
            }) {
                self.rounds.pop_front();
            }
            if self.rounds.len() == EST_WIN {
                self.rounds.pop_front();
            }
            self.rounds.push_back(Round {
                sent: previous,
                acked: delta.acked,
                feedback_duration: elapsed,
                end: now,
            });
        }

        let (sent_bytes, acked_bytes, sent_nanos, feedback_nanos) =
            self.rounds.iter().fold(
                (0_u128, 0_u128, 0_u128, 0_u128),
                |(sent, acked, send_time, feedback_time), round| {
                    (
                        sent + u128::from(round.sent.bytes),
                        acked + u128::from(round.acked),
                        send_time + round.sent.duration.as_nanos(),
                        feedback_time + round.feedback_duration.as_nanos(),
                    )
                },
            );
        let sample = if self.rounds.len() >= MIN_PAIRED_ROUNDS && delta.acked > 0
        {
            bandwidth(sent_bytes, sent_nanos)
                .min(bandwidth(acked_bytes, feedback_nanos))
        } else {
            0
        };
        // Always advance the filter, including samples with no ACKs. Otherwise
        // a previously busy but now idle connection contributes forever.
        self.maximum.update(sample, now);
        self.maximum.get_best().unwrap_or_default()
    }
}

/// Rate in bits per second, with saturating conversion for extreme counters.
fn bandwidth(bytes: u128, nanos: u128) -> u64 {
    if nanos == 0 {
        return 0;
    }
    let bits_per_second = bytes.saturating_mul(8_000_000_000) / nanos;
    u64::try_from(bits_per_second).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(
        estimator: &mut MaxUtilizedBandwidthEstimator, now: &mut Instant,
        elapsed: Duration, sent: u64, acked: u64, lost: u64,
    ) -> u64 {
        *now += elapsed;
        estimator.new_round(*now, elapsed, ByteCounts { sent, acked, lost })
    }

    #[test]
    fn unequal_intervals_use_independent_send_and_feedback_durations() {
        let mut estimator = MaxUtilizedBandwidthEstimator::new();
        let mut now = Instant::now();
        // Constant 8 Mbps over alternating 1/2-second intervals. Feedback
        // arrives one sample late, but is capped by its actual delivery rate.
        let periods = [1, 2, 1, 2, 1];
        let mut previous_sent = 0;
        let mut estimate = 0;
        for seconds in periods {
            let sent = seconds * 1_000_000;
            estimate = round(
                &mut estimator,
                &mut now,
                Duration::from_secs(seconds),
                sent,
                previous_sent,
                0,
            );
            previous_sent = sent;
        }
        assert_eq!(estimate, 8_000_000);
    }

    #[test]
    fn idle_period_expires_previous_peak_even_without_acks() {
        let mut estimator = MaxUtilizedBandwidthEstimator::new();
        let mut now = Instant::now();
        let mut estimate = 0;
        for _ in 0..5 {
            estimate = round(
                &mut estimator,
                &mut now,
                Duration::from_secs(1),
                1_000_000,
                1_000_000,
                0,
            );
        }
        assert_eq!(estimate, 8_000_000);
        for _ in 0..3 {
            estimate =
                round(&mut estimator, &mut now, Duration::from_secs(41), 0, 0, 0);
        }
        assert_eq!(estimate, 0);
    }

    #[test]
    fn loss_is_bounded_when_feedback_is_delayed_or_only_losses_arrive() {
        assert_eq!(LossRatio::from_outcomes(0, 0).0, 0);
        assert_eq!(LossRatio::from_outcomes(0, 100).0, 10_000);
        assert_eq!(LossRatio::from_outcomes(75, 25).0, 2_500);
        assert_eq!(LossRatio::from_outcomes(2, 1).0, 3_333);
        assert_eq!(LossRatio::from_outcomes(0, 1).rounded_percent(), 100);
    }

    #[test]
    fn bandwidth_saturates_extreme_values_and_has_no_zero_time_spike() {
        assert_eq!(bandwidth(u128::from(u64::MAX), 1), u64::MAX);
        assert_eq!(bandwidth(10, 0), 0);
        assert_eq!(bandwidth(1, 8_000_000_001), 0);
    }

    #[test]
    fn first_interval_loss_is_reported_without_bandwidth_warmup() {
        let mut reporter = BandwidthReporter::new(Gauge::default());
        let now = reporter.last_update + Duration::from_secs(1);
        reporter.update_counters(
            ByteCounts {
                sent: 100,
                acked: 0,
                lost: 100,
            },
            now,
            None,
        );
        assert_eq!(reporter.max_bandwidth, 0);
        assert_eq!(reporter.max_loss.rounded_percent(), 100);
    }

    #[test]
    fn gauge_tracks_delta_and_is_released_on_drop() {
        let gauge = Gauge::default();
        let mut reporter = BandwidthReporter::new(gauge.clone());
        let mut now = reporter.last_update;
        for count in 1..=5 {
            now += Duration::from_secs(1);
            reporter.update_counters(
                ByteCounts {
                    sent: count * 1_000_000,
                    acked: count * 1_000_000,
                    lost: 0,
                },
                now,
                Some(Duration::from_secs(1)),
            );
        }
        assert_eq!(reporter.max_bandwidth, 8_000_000);
        assert_eq!(gauge.get(), 8_000_000);
        now += Duration::from_secs(1);
        reporter.update_counters(
            ByteCounts {
                sent: 5_000_000,
                acked: 5_000_000,
                lost: 2_000_000,
            },
            now,
            None,
        );
        assert!(reporter.max_loss.0 > 0);
        now += Duration::from_secs(1);
        reporter.update_counters(ByteCounts::default(), now, None);
        assert_eq!(gauge.get(), 0);
        reporter.set_bandwidth(100);
        drop(reporter);
        assert_eq!(gauge.get(), 0);
    }
}
