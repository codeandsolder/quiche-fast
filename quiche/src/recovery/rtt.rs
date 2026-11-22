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

use std::time::Duration;
use std::time::Instant;

use crate::minmax::Minmax;
use crate::recovery::GRANULARITY;

pub const RTT_WINDOW: Duration = Duration::from_secs(300);

pub struct RttStats {
    pub(super) latest_rtt: Duration,

    max_rtt: Duration,

    pub(super) smoothed_rtt: Duration,

    pub(super) rttvar: Duration,

    pub(super) min_rtt: Minmax<Duration>,

    pub(super) max_ack_delay: Duration,

    pub(super) first_rtt_sample_time: Option<Instant>,
}

impl std::fmt::Debug for RttStats {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("RttStats")
            .field("latest_rtt", &self.latest_rtt)
            .field("smoothed_rtt", &self.smoothed_rtt)
            .field("min_rtt", &*self.min_rtt)
            .field("max_rtt", &self.max_rtt)
            .field("rttvar", &self.rttvar)
            .field("max_ack_delay", &self.max_ack_delay)
            .field("first_rtt_sample_time", &self.first_rtt_sample_time)
            .finish()
    }
}

impl RttStats {
    pub(crate) fn new(initial_rtt: Duration, max_ack_delay: Duration) -> Self {
        Self {
            latest_rtt: Duration::ZERO,
            min_rtt: Minmax::new(initial_rtt),
            smoothed_rtt: initial_rtt,
            max_rtt: initial_rtt,
            rttvar: initial_rtt / 2,
            first_rtt_sample_time: None,
            max_ack_delay,
        }
    }

    pub(crate) fn update_rtt(
        &mut self, latest_rtt: Duration, mut ack_delay: Duration, now: Instant,
        handshake_confirmed: bool,
    ) {
        self.latest_rtt = latest_rtt;

        if self.first_rtt_sample_time.is_none() {
            self.min_rtt.reset(now, latest_rtt);
            self.smoothed_rtt = latest_rtt;
            self.max_rtt = latest_rtt;
            self.rttvar = latest_rtt / 2;
            self.first_rtt_sample_time = Some(now);
            return;
        }

        // min_rtt ignores acknowledgment delay.
        self.min_rtt.running_min(RTT_WINDOW, now, latest_rtt);

        self.max_rtt = self.max_rtt.max(latest_rtt);

        // Limit ack_delay by max_ack_delay after handshake confirmation.
        if handshake_confirmed {
            ack_delay = ack_delay.min(self.max_ack_delay);
        }

        // Adjust for acknowledgment delay only when the result is plausible.
        let adjusted_rtt = latest_rtt
            .checked_sub(ack_delay)
            .filter(|adjusted| *adjusted >= *self.min_rtt)
            .unwrap_or(latest_rtt);

        self.rttvar = weighted_part::<3, 4>(self.rttvar) +
            self.smoothed_rtt.abs_diff(adjusted_rtt) / 4;

        self.smoothed_rtt =
            weighted_part::<7, 8>(self.smoothed_rtt) + adjusted_rtt / 8;
    }

    pub(crate) const fn rtt(&self) -> Duration {
        self.smoothed_rtt
    }

    #[cfg(feature = "qlog")]
    pub(crate) fn latest_rtt(&self) -> Duration {
        self.latest_rtt
    }

    pub(crate) const fn rttvar(&self) -> Duration {
        self.rttvar
    }

    pub(crate) fn min_rtt(&self) -> Option<Duration> {
        if self.first_rtt_sample_time.is_some() {
            Some(*self.min_rtt)
        } else {
            None
        }
    }

    pub(crate) const fn max_rtt(&self) -> Option<Duration> {
        if self.first_rtt_sample_time.is_some() {
            Some(self.max_rtt)
        } else {
            None
        }
    }

    pub(super) fn probe_timeout(&self) -> Duration {
        self.smoothed_rtt
            .saturating_add(self.rttvar.saturating_mul(4).max(GRANULARITY))
    }

    pub(crate) fn loss_delay(&self, time_thresh: f64) -> Duration {
        let rtt = self.latest_rtt.max(self.smoothed_rtt);
        Duration::try_from_secs_f64(time_thresh * rtt.as_secs_f64())
            .unwrap_or(Duration::MAX)
            .max(GRANULARITY)
    }
}

/// Computes floor(duration * NUM / DEN) without overflowing an intermediate
/// Duration. In the ordinary RTT range the checked multiplication is enough;
/// the quotient/remainder decomposition also handles `Duration::MAX` exactly.
fn weighted_part<const NUM: u32, const DEN: u32>(duration: Duration) -> Duration {
    const { assert!(DEN > 0 && NUM <= DEN) };
    if let Some(scaled) = duration.checked_mul(NUM) {
        return scaled / DEN;
    }

    let quotient = duration / DEN;
    let remainder = duration - quotient * DEN;
    quotient * NUM + remainder * NUM / DEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighted_duration_preserves_full_width_and_rounding() {
        for duration in [
            Duration::ZERO,
            Duration::from_nanos(7),
            Duration::from_micros(312_345),
            Duration::from_secs(u64::MAX / 2),
            Duration::MAX,
        ] {
            let nanos = duration.as_nanos();
            assert_eq!(weighted_part::<3, 4>(duration).as_nanos(), nanos * 3 / 4);
            assert_eq!(weighted_part::<7, 8>(duration).as_nanos(), nanos * 7 / 8);
        }
    }

    #[test]
    fn rtt_update_handles_extreme_samples_and_ack_delay() {
        let now = Instant::now();
        let first = Duration::from_secs(u64::MAX / 2);
        let second = Duration::MAX;
        let mut stats = RttStats::new(first, Duration::MAX);
        stats.update_rtt(first, Duration::ZERO, now, false);
        stats.update_rtt(second, Duration::MAX, now, true);

        // The ACK delay is implausible: subtracting it would take the sample
        // below min_rtt. Variance must retain all bits of the full-width delta.
        assert_eq!(
            stats.smoothed_rtt.as_nanos(),
            first.as_nanos() * 7 / 8 + second.as_nanos() / 8
        );
        assert_eq!(
            stats.rttvar.as_nanos(),
            (first / 2).as_nanos() * 3 / 4 + (second - first).as_nanos() / 4
        );
        assert_eq!(stats.loss_delay(1.125), Duration::MAX);
        assert_eq!(stats.probe_timeout(), Duration::MAX);
    }
}
