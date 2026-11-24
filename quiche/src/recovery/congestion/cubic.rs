// Copyright (C) 2019, Cloudflare, Inc.
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

//! CUBIC Congestion Control
//!
//! This implementation is based on the following draft:
//! <https://tools.ietf.org/html/draft-ietf-tcpm-rfc8312bis-02>
//!
//! Note that Slow Start can use `HyStart`++ when enabled.

use std::cmp;

use std::time::Duration;
use std::time::Instant;

use super::rtt::RttStats;
use super::Acked;
use super::Sent;

use super::reno;
use super::Congestion;
use super::CongestionControlOps;
use crate::recovery::MINIMUM_WINDOW_PACKETS;

pub static CUBIC: CongestionControlOps = CongestionControlOps {
    on_init,
    on_packet_sent,
    on_packets_acked,
    congestion_event,
    checkpoint,
    rollback,
    #[cfg(feature = "qlog")]
    state_str,
    debug_fmt: Some(debug_fmt),
};

// RFC 9438 specifies beta = 0.7. Byte counts use the rational 7/10
// rather than the nearest binary64 representation of that constant.
fn beta_reduce(bytes: usize) -> usize {
    crate::scale::scale_ratio_usize(bytes, 7, 10, crate::scale::Rounding::Down)
}

const C: f64 = 0.4;

/// Threshold for rolling back state, as percentage of lost packets relative to
/// cwnd.
const ROLLBACK_THRESHOLD_PERCENT: usize = 20;

/// Minimum threshold for rolling back state, as number of packets.
const MIN_ROLLBACK_THRESHOLD: usize = 2;

/// RFC 9438 Reno-friendliness gain before and after reaching `W_max`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum RenoGain {
    #[default]
    Reduced,
    Full,
}

impl RenoGain {
    const fn ratio(self) -> (u128, u128) {
        match self {
            Self::Reduced => (9, 17),
            Self::Full => (1, 1),
        }
    }
}

/// Byte count with 32 fractional bits; a full usize window remains exact.
/// Floating-point curve evaluation supplies only a displacement from the
/// exact byte anchor, not an approximation of the entire congestion window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct Window(u128);

impl Window {
    const MAX: u128 = (usize::MAX as u128) * Self::ONE;
    const ONE: u128 = 1 << 32;

    const fn bytes(bytes: usize) -> Self {
        Self((bytes as u128) * Self::ONE)
    }

    fn whole(self) -> usize {
        usize::try_from(self.0 / Self::ONE).unwrap_or(usize::MAX)
    }

    /// Convert a curve *difference* to floating point for the cube root.
    /// Each limb is representable exactly; the final sum has the precision
    /// of binary64, as required by the continuous CUBIC time model.
    fn continuous(self) -> f64 {
        let raw = self.0.to_le_bytes();
        let (words, _) = raw.as_chunks::<4>();
        let high = f64::from(u32::from_le_bytes(words[2]));
        let low = f64::from(u32::from_le_bytes(words[1]));
        let fraction = f64::from(u32::from_le_bytes(words[0]));
        high.mul_add(4_294_967_296.0, low + fraction / 4_294_967_296.0)
    }

    fn add_curve(self, mss: usize, coefficient: f64) -> Self {
        use crate::scale::scale_wide;
        use crate::scale::Rounding;
        let magnitude = coefficient.abs() * 4_294_967_296.0;
        let mss = u64::try_from(mss).unwrap_or(u64::MAX);
        if coefficient < 0.0 {
            Self(
                self.0
                    .saturating_sub(scale_wide(mss, magnitude, Rounding::Up)),
            )
        } else {
            Self(
                self.0
                    .saturating_add(scale_wide(mss, magnitude, Rounding::Down))
                    .min(Self::MAX),
            )
        }
    }

    fn reno_increment(
        acked: usize, cwnd: usize, mss: usize, gain: RenoGain,
    ) -> Self {
        if cwnd == 0 {
            return Self::default();
        }
        let (numerator, denominator) = gain.ratio();
        let product = (acked as u128) * (mss as u128);
        let divisor = cwnd as u128;
        let factor = Self::ONE * numerator;
        let scaled = product.checked_mul(factor).map_or_else(
            || {
                // Divide before multiplying by the fractional scale when the
                // intermediate would overflow. Retain the exact remainder.
                let whole = product / divisor;
                let remainder = product % divisor;
                whole
                    .saturating_mul(factor)
                    .saturating_add(remainder * factor / divisor)
            },
            |product| product / divisor,
        );
        Self((scaled / denominator).min(Self::MAX))
    }

    fn add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0).min(Self::MAX))
    }
}

/// CUBIC State Variables.
///
/// We need to keep those variables across the connection.
/// k, `w_max`, `w_est` are described in the RFC.
#[derive(Debug, Default)]
pub struct State {
    curve: CurveState,

    // Used in CUBIC fix (see on_packet_sent())
    last_sent_time: Option<Instant>,

    // Tracks when the last ACK was processed, approximating when
    // bytes_in_flight transitioned toward zero. Used to measure the
    // actual idle duration in on_packet_sent() instead of the time
    // since the last send (which inflates the delta by a full RTT).
    last_ack_time: Option<Instant>,

    // CUBIC state checkpoint preceding the last congestion event.
    prior: Option<PriorState>,
}

/// Congestion-avoidance variables that must be restored together after
/// a spurious congestion event. Send and ACK timestamps are not rolled back.
#[derive(Clone, Copy, Debug, Default)]
struct CurveState {
    // Curve time excludes application-idle intervals. This is not the
    // packet-send-time cutoff of the latest congestion event.
    epoch_start: Option<Instant>,
    k: f64,
    w_max: Window,
    w_est: Window,
    reno_gain: RenoGain,
    cwnd_inc: usize,
}

/// Stores the CUBIC state from before the last congestion event.
/// <https://tools.ietf.org/id/draft-ietf-tcpm-rfc8312bis-00.html#section-4.9>
#[derive(Debug)]
struct PriorState {
    cwnd: usize,
    ssthresh: usize,
    curve: CurveState,
    recovery_start: Option<Instant>,
    lost_count: usize,
}

/// CUBIC Functions.
///
/// Note that these calculations are based on a count of cwnd as bytes,
/// not packets.
/// Unit of t (duration) and RTT are based on seconds (f64).
impl CurveState {
    // K = cubic_root ((W_max - cwnd) / MSS / C) (Eq. 2).
    fn cubic_k(&self, cwnd: usize, max_datagram_size: usize) -> f64 {
        let difference =
            Window(self.w_max.0.saturating_sub(Window::bytes(cwnd).0));
        libm::cbrt(
            difference.continuous() /
                (C * Window::bytes(max_datagram_size).continuous()),
        )
    }

    // W_cubic(t) = W_max + MSS * C * (t - K)^3 (Eq. 1).
    fn w_cubic(&self, t: Duration, max_datagram_size: usize) -> Window {
        self.w_max
            .add_curve(max_datagram_size, C * (t.as_secs_f64() - self.k).powi(3))
    }

    fn update_reno_estimate(&mut self, acked: usize, cwnd: usize, mss: usize) {
        self.w_est = self.w_est.add(Window::reno_increment(
            acked,
            cwnd,
            mss,
            self.reno_gain,
        ));
        if self.w_est >= self.w_max {
            self.reno_gain = RenoGain::Full;
        }
    }
}

const fn on_init(_r: &mut Congestion) {}

fn on_packet_sent(
    r: &mut Congestion, sent_bytes: usize, bytes_in_flight: usize, now: Instant,
) {
    reno::on_packet_sent(r, sent_bytes, bytes_in_flight, now);

    // Non-data packets must not affect the idle estimate.
    if sent_bytes == 0 {
        return;
    }

    // RFC 9438: suspend curve growth while application-limited. Only
    // the curve epoch moves; the recovery cutoff is the actual time of
    // the congestion event and must not move with it.
    let cubic = &mut r.cubic_state;
    if bytes_in_flight == 0 {
        if let (Some(epoch), Some(idle_start)) = (
            cubic.curve.epoch_start,
            cmp::max(cubic.last_ack_time, cubic.last_sent_time),
        ) {
            let idle = now.saturating_duration_since(idle_start.max(epoch));
            // idle <= now - epoch, so the adjusted epoch cannot exceed now.
            cubic.curve.epoch_start = Some(epoch + idle);
        }
    }

    cubic.last_sent_time = Some(now);
}

fn on_packets_acked(
    r: &mut Congestion, bytes_in_flight: usize, packets: &mut Vec<Acked>,
    now: Instant, rtt_stats: &RttStats,
) {
    for pkt in packets.drain(..) {
        on_packet_acked(r, bytes_in_flight, &pkt, now, rtt_stats);
    }
}

fn on_packet_acked(
    r: &mut Congestion, bytes_in_flight: usize, packet: &Acked, now: Instant,
    rtt_stats: &RttStats,
) {
    if !packet.in_flight || packet.size == 0 {
        return;
    }
    r.cubic_state.last_ack_time = Some(now);
    let in_congestion_recovery = r.in_congestion_recovery(packet.transmitted_at);

    if in_congestion_recovery {
        r.prr.on_packet_acked(
            packet.size,
            bytes_in_flight,
            r.ssthresh.get(),
            r.max_datagram_size,
        );

        return;
    }

    if r.app_limited {
        return;
    }

    // Detecting spurious congestion events.
    // <https://tools.ietf.org/id/draft-ietf-tcpm-rfc8312bis-00.html#section-4.9>
    //
    // If recovery ends after fewer than
    // `cwnd / mss * ROLLBACK_THRESHOLD_PERCENT` packets, treat the congestion
    // event as spurious and restore the previous state.
    if let Some(prior) = &r.cubic_state.prior {
        let new_lost = r.lost_count.saturating_sub(prior.lost_count);

        let rollback_threshold = crate::scale::scale_ratio_usize(
            r.cwnd / r.max_datagram_size,
            ROLLBACK_THRESHOLD_PERCENT as u64,
            100,
            crate::scale::Rounding::Down,
        );

        let rollback_threshold = rollback_threshold.max(MIN_ROLLBACK_THRESHOLD);

        if r.recovery_started_at.is_some() && new_lost < rollback_threshold {
            let did_rollback = rollback(r);
            if did_rollback {
                return;
            }
        }
    }

    if r.cwnd < r.ssthresh.get() {
        slow_start_ack(r, packet, now, rtt_stats);
    } else {
        congestion_avoidance_ack(r, packet, now, rtt_stats);
    }
}

fn slow_start_ack(
    r: &mut Congestion, packet: &Acked, now: Instant, rtt_stats: &RttStats,
) {
    // In Slow start, bytes_acked_sl is used for counting
    // acknowledged bytes.
    let acked = r.bytes_acked_sl as u128 + packet.size as u128;
    let remainder = if acked >= r.max_datagram_size as u128 {
        let increase = if r.hystart.in_css() {
            super::hystart::Hystart::css_cwnd_inc(r.max_datagram_size)
        } else {
            r.max_datagram_size
        };
        r.cwnd = r.cwnd.saturating_add(increase);

        acked - r.max_datagram_size as u128
    } else {
        acked
    };
    r.bytes_acked_sl = usize::try_from(remainder).unwrap_or(usize::MAX);

    if r.hystart.on_packet_acked(packet, rtt_stats.latest_rtt, now) {
        // Exit to congestion avoidance if CSS ends.
        r.ssthresh.update(r.cwnd, true);
    }
}

fn congestion_avoidance_ack(
    r: &mut Congestion, packet: &Acked, now: Instant, rtt_stats: &RttStats,
) {
    let curve = &mut r.cubic_state.curve;
    let ca_start_time = *curve.epoch_start.get_or_insert_with(|| {
        curve.w_max = Window::bytes(r.cwnd);
        curve.k = 0.0;
        curve.w_est = Window::bytes(r.cwnd);
        curve.reno_gain = RenoGain::Reduced;
        r.hystart.css_start_time().unwrap_or(now)
    });

    let t = now.saturating_duration_since(ca_start_time);

    // target = w_cubic(t + rtt)
    let target = r
        .cubic_state
        .curve
        .w_cubic(t.saturating_add(*rtt_stats.min_rtt), r.max_datagram_size);

    // Clip to [cwnd, 1.5 * cwnd] in the exact integer byte domain.
    let target = target
        .whole()
        .clamp(r.cwnd, r.cwnd.saturating_add(r.cwnd / 2));

    r.cubic_state.curve.update_reno_estimate(
        packet.size,
        r.cwnd,
        r.max_datagram_size,
    );

    let mut cubic_cwnd = r.cwnd;

    if r.cubic_state.curve.w_cubic(t, r.max_datagram_size) <
        r.cubic_state.curve.w_est
    {
        // AIMD friendly region (W_cubic(t) < W_est)
        cubic_cwnd = cmp::max(cubic_cwnd, r.cubic_state.curve.w_est.whole());
    } else {
        // Concave region or convex region use same increment.
        let delta = target.saturating_sub(cubic_cwnd);
        // The product may exceed the address width before division,
        // especially for multi-megabyte congestion windows on 32-bit.
        let cubic_inc = if cubic_cwnd == 0 {
            0
        } else if let Some(product) = r.max_datagram_size.checked_mul(delta) {
            product / cubic_cwnd
        } else {
            usize::try_from(
                r.max_datagram_size as u128 * delta as u128 / cubic_cwnd as u128,
            )
            .unwrap_or(usize::MAX)
        };

        cubic_cwnd = cubic_cwnd.saturating_add(cubic_inc);
    }

    // Update the increment and increase cwnd by MSS.
    let increment =
        r.cubic_state.curve.cwnd_inc as u128 + (cubic_cwnd - r.cwnd) as u128;
    let remainder = if increment >= r.max_datagram_size as u128 {
        r.cwnd = r.cwnd.saturating_add(r.max_datagram_size);
        increment - r.max_datagram_size as u128
    } else {
        increment
    };
    r.cubic_state.curve.cwnd_inc =
        usize::try_from(remainder).unwrap_or(usize::MAX);
}

fn congestion_event(
    r: &mut Congestion, bytes_in_flight: usize, _lost_bytes: usize,
    largest_lost_pkt: &Sent, now: Instant,
) {
    let transmitted_at = largest_lost_pkt.transmitted_at;
    let in_congestion_recovery = r.in_congestion_recovery(transmitted_at);

    // Start a new congestion event if packet was sent after the
    // start of the previous congestion recovery period.
    if !in_congestion_recovery {
        r.recovery_started_at = Some(now);
        r.cubic_state.curve.epoch_start = Some(now);

        // Fast convergence uses the exact rational (1 + beta) / 2 = 17/20.
        let window = Window::bytes(r.cwnd);
        r.cubic_state.curve.w_max = if window < r.cubic_state.curve.w_max {
            Window(window.0 * 17 / 20)
        } else {
            window
        };

        let ssthresh = beta_reduce(r.cwnd);
        let ssthresh = cmp::max(
            ssthresh,
            r.max_datagram_size.saturating_mul(MINIMUM_WINDOW_PACKETS),
        );
        r.ssthresh.update(ssthresh, r.hystart.in_css());
        r.cwnd = ssthresh;

        r.cubic_state.curve.k =
            if r.cubic_state.curve.w_max < Window::bytes(r.cwnd) {
                0.0
            } else {
                r.cubic_state.curve.cubic_k(r.cwnd, r.max_datagram_size)
            };

        r.cubic_state.curve.cwnd_inc = beta_reduce(r.cubic_state.curve.cwnd_inc);

        r.cubic_state.curve.w_est = Window::bytes(r.cwnd);
        r.cubic_state.curve.reno_gain = RenoGain::Reduced;

        if r.hystart.in_css() {
            r.hystart.congestion_event();
        }

        r.prr.congestion_event(bytes_in_flight);
    }
}

const fn checkpoint(r: &mut Congestion) {
    r.cubic_state.prior = Some(PriorState {
        cwnd: r.cwnd,
        ssthresh: r.ssthresh.get(),
        curve: r.cubic_state.curve,
        recovery_start: r.recovery_started_at,
        lost_count: r.lost_count,
    });
}

fn rollback(r: &mut Congestion) -> bool {
    let Some(prior) = &r.cubic_state.prior else {
        return false;
    };

    // Don't go back to slow start or decrease the window.
    if prior.cwnd < prior.ssthresh || r.cwnd >= prior.cwnd {
        return false;
    }

    r.cwnd = prior.cwnd;
    r.ssthresh.update(prior.ssthresh, false);
    r.cubic_state.curve = prior.curve;
    r.recovery_started_at = prior.recovery_start;
    r.prr = super::prr::PRR::default();
    r.cubic_state.prior = None;

    true
}

#[cfg(feature = "qlog")]
fn state_str(r: &Congestion, now: Instant) -> &'static str {
    reno::state_str(r, now)
}

fn debug_fmt(r: &Congestion, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    write!(
        f,
        "cubic={{ k={} w_max={} }} ",
        r.cubic_state.curve.k,
        r.cubic_state.curve.w_max.whole()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::CongestionControlAlgorithm;

    use crate::recovery::congestion::hystart;
    use crate::recovery::congestion::recovery::LegacyRecovery;
    use crate::recovery::congestion::test_sender::FixtureResult;
    use crate::recovery::congestion::test_sender::TestSender;
    use crate::recovery::RecoveryOps;

    fn test_sender() -> TestSender {
        TestSender::new(CongestionControlAlgorithm::Cubic, false)
    }

    fn hystart_test_sender() -> TestSender {
        TestSender::new(CongestionControlAlgorithm::Cubic, true)
    }

    #[test]
    fn fixed_window_retains_fractional_growth_at_full_width() {
        let anchor = usize::MAX - 4096;
        let original = Window::bytes(anchor);
        assert_eq!(original.add_curve(1200, 0.125).whole(), anchor + 150);
        assert_eq!(original.add_curve(1200, -0.125).whole(), anchor - 150);
        assert_eq!(original.add_curve(1200, 0.000_125).whole(), anchor);
        assert_eq!(original.add_curve(1200, -0.000_125).whole(), anchor - 1);
        assert_eq!(original.add_curve(1200, f64::MAX).whole(), usize::MAX);
        assert_eq!(original.add_curve(1200, -f64::MAX).whole(), 0);

        let half = Window::reno_increment(1000, 2000, 1, RenoGain::Full);
        assert_eq!(half.0, Window::ONE / 2);
        assert_eq!(original.add(half).add(half).whole(), anchor + 1);
        let reduced = Window::reno_increment(17, 9, 1, RenoGain::Reduced);
        assert_eq!(reduced, Window::bytes(1));
        assert_eq!(
            Window::reno_increment(usize::MAX, 1, usize::MAX, RenoGain::Reduced)
                .whole(),
            usize::MAX
        );
        assert_eq!(
            Window::reno_increment(
                usize::MAX,
                usize::MAX,
                usize::MAX,
                RenoGain::Full
            )
            .whole(),
            usize::MAX
        );
    }

    #[test]
    fn fixed_window_reno_increment_matches_rational_oracle() {
        for acked in [0, 1, 1300, 9000, 65_527] {
            for cwnd in [1, 12_000, 8_000_000, usize::MAX] {
                for mss in [1200, 9000, 65_527] {
                    for gain in [RenoGain::Reduced, RenoGain::Full] {
                        let (num, den) = gain.ratio();
                        let exact =
                            (acked as u128) * (mss as u128) * Window::ONE * num /
                                ((cwnd as u128) * den);
                        assert_eq!(
                            Window::reno_increment(acked, cwnd, mss, gain).0,
                            exact.min(Window::MAX)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn cubic_integer_loss_reduction_at_full_width() -> FixtureResult {
        for value in [10, 11, usize::MAX, usize::MAX - 1] {
            assert_eq!(beta_reduce(value), value / 10 * 7 + value % 10 * 7 / 10);
        }
        let mut sender = test_sender();
        let size = sender.max_datagram_size;
        sender.cwnd = usize::MAX;
        sender.cubic_state.curve.cwnd_inc = usize::MAX - 1;
        sender.send_packet(size);
        sender.lose_n_packets(1, None)?;
        assert_eq!(sender.cwnd, beta_reduce(usize::MAX));
        assert_eq!(
            sender.cubic_state.curve.cwnd_inc,
            beta_reduce(usize::MAX - 1)
        );
        Ok(())
    }

    #[test]
    fn cubic_congestion_avoidance_large_window() -> FixtureResult {
        let mut sender = test_sender();
        let mss = sender.max_datagram_size;
        let cwnd = 8 * 1024 * 1024;
        sender.cwnd = cwnd;
        sender.ssthresh.update(cwnd, false);
        sender.cubic_state.curve.w_max = Window::bytes(cwnd);
        sender.cubic_state.curve.w_est = Window::bytes(cwnd);
        sender.cubic_state.curve.k = 0.0;
        sender.cubic_state.curve.reno_gain = RenoGain::Full;
        sender.cubic_state.curve.epoch_start =
            Some(sender.time - Duration::from_secs(100));
        sender.send_packet(mss);
        sender.send_packet(mss);
        sender.update_app_limited(false);
        sender.advance_time(Duration::from_millis(100));
        sender.ack_n_packets(1)?;
        // The target is clipped at 1.5*cwnd; the exact increment
        // is half an MSS despite the intermediate product exceeding u32.
        assert_eq!(sender.cubic_state.curve.cwnd_inc, mss / 2);
        assert_eq!(sender.cwnd, cwnd);
        sender.ack_n_packets(1)?;
        assert_eq!(sender.cwnd, cwnd + mss);
        Ok(())
    }

    #[test]
    fn cubic_init() {
        let cfg = crate::recovery::RecoveryConfig {
            cc_algorithm: CongestionControlAlgorithm::Cubic,
            ..crate::recovery::RecoveryConfig::default()
        };

        let r = LegacyRecovery::new_with_config(&cfg);

        assert!(r.cwnd() > 0);
        assert_eq!(r.bytes_in_flight(), 0);
    }

    #[test]
    fn cubic_slow_start() -> FixtureResult {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let cwnd_prev = sender.cwnd;

        sender.ack_n_packets(1)?;

        // Check if cwnd increased by packet size (slow start)
        assert_eq!(sender.cwnd, cwnd_prev + size);
        Ok(())
    }

    #[test]
    fn cubic_slow_start_multi_acks() -> FixtureResult {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let cwnd_prev = sender.cwnd;

        sender.ack_n_packets(3)?;

        // Acked 3 packets.
        assert_eq!(sender.cwnd, cwnd_prev + size * 3);
        Ok(())
    }

    #[test]
    fn cubic_congestion_event() -> FixtureResult {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        sender.send_packet(size);

        let cwnd_prev = sender.cwnd;

        sender.lose_n_packets(1, None)?;

        // In CUBIC, after congestion event, cwnd will be reduced by (1 -
        // CUBIC_BETA)
        assert_eq!(beta_reduce(cwnd_prev), sender.cwnd);
        Ok(())
    }

    #[test]
    fn cubic_congestion_avoidance() -> FixtureResult {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        let prev_cwnd = sender.cwnd;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let rtt = Duration::from_millis(100);

        sender.advance_time(rtt);
        sender.lose_n_packets(1, None)?;

        // After congestion event, cwnd will be reduced.
        let cur_cwnd = beta_reduce(prev_cwnd);
        assert_eq!(sender.cwnd, cur_cwnd);

        // Shift current time by 1 RTT.
        sender.update_rtt(rtt);
        // Exit from the recovery.
        sender.advance_time(rtt);

        sender.ack_n_packets(sender.initial_congestion_window_packets - 2)?;
        // Only packets sent after exit recovery can increase cwnd.
        assert_eq!(sender.cwnd, cur_cwnd);

        for _ in 0..8 {
            sender.send_packet(size);
        }
        sender.advance_time(rtt);

        sender.ack_n_packets(1)?;
        // Only packets sent after exit recovery can increase cwnd.
        assert_eq!(sender.cwnd, cur_cwnd);

        // During Congestion Avoidance, it will take
        // 6 ACKs to increase cwnd by 1 MSS.
        for _ in 0..6 {
            sender.ack_n_packets(1)?;
            sender.advance_time(rtt);
        }

        assert_eq!(sender.cwnd, cur_cwnd + size);
        Ok(())
    }

    #[test]
    fn cubic_hystart_css_to_ss() -> FixtureResult {
        let mut sender = hystart_test_sender();
        let size = sender.max_datagram_size;

        // 1st round.
        let n_rtt_sample = hystart::N_RTT_SAMPLE;

        let rtt_1st = Duration::from_millis(50);

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        // Send 1st round packets.
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        sender.advance_time(rtt_1st);
        sender.update_rtt(rtt_1st);
        sender.ack_n_packets(n_rtt_sample)?;

        // Not in CSS yet.
        assert!(sender.hystart.css_start_time().is_none());

        // 2nd round.
        let mut rtt_2nd = Duration::from_millis(100);

        sender.advance_time(rtt_2nd);

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        // Send 2nd round packets.
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        // Last ack will cause to exit to CSS.
        let mut cwnd_prev = sender.window();

        for _ in 0..n_rtt_sample {
            cwnd_prev = sender.window();
            sender.update_rtt(rtt_2nd);
            sender.ack_n_packets(1)?;
            // Keep increasing RTT so that hystart exits to CSS.
            rtt_2nd += rtt_2nd.saturating_add(Duration::from_millis(4));
        }

        // Now we are in CSS.
        assert!(sender.hystart.css_start_time().is_some());
        assert_eq!(sender.window(), cwnd_prev + size);

        // 3rd round, which RTT is less than previous round to
        // trigger back to Slow Start.
        let rtt_3rd = Duration::from_millis(80);
        sender.advance_time(rtt_3rd);
        cwnd_prev = sender.window();

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        // Send 3nd round packets.
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        // Last ack will cause to exit to SS.
        sender.update_rtt(rtt_3rd);
        sender.ack_n_packets(n_rtt_sample)?;

        // Now we are back in Slow Start.
        assert!(sender.hystart.css_start_time().is_none());
        assert_eq!(
            sender.window(),
            cwnd_prev +
                size / hystart::CSS_GROWTH_DIVISOR * hystart::N_RTT_SAMPLE
        );
        Ok(())
    }

    #[test]
    fn cubic_hystart_css_to_ca() -> FixtureResult {
        let mut sender = hystart_test_sender();
        let size = sender.max_datagram_size;

        // 1st round.
        let n_rtt_sample = hystart::N_RTT_SAMPLE;

        let rtt_1st = Duration::from_millis(50);

        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        // Send 1st round packets.
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        sender.advance_time(rtt_1st);
        sender.update_rtt(rtt_1st);
        sender.ack_n_packets(n_rtt_sample)?;

        // Not in CSS yet.
        assert!(sender.hystart.css_start_time().is_none());

        // 2nd round.
        let mut rtt_2nd = Duration::from_millis(100);
        sender.advance_time(rtt_2nd);
        // Send 2nd round packets.
        let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
        sender.hystart.start_round(next_rnd);
        for _ in 0..n_rtt_sample {
            sender.send_packet(size);
        }
        sender.update_app_limited(false);

        // Receiving Acks.
        // Last ack will cause to exit to CSS.
        let mut cwnd_prev = sender.window();

        for _ in 0..n_rtt_sample {
            cwnd_prev = sender.window();
            sender.update_rtt(rtt_2nd);
            sender.ack_n_packets(1)?;
            // Keep increasing RTT so that hystart exits to CSS.
            rtt_2nd += rtt_2nd.saturating_add(Duration::from_millis(4));
        }

        // Now we are in CSS.
        assert!(sender.hystart.css_start_time().is_some());
        assert_eq!(sender.window(), cwnd_prev + size);

        // Run 5 (CSS_ROUNDS) in CSS, to exit to congestion avoidance.
        let rtt_css = Duration::from_millis(100);
        sender.advance_time(rtt_css);

        for _ in 0..hystart::CSS_ROUNDS {
            // Send a round of packets.
            let next_rnd = sender.next_pkt + n_rtt_sample as u64 - 1;
            sender.hystart.start_round(next_rnd);
            for _ in 0..n_rtt_sample {
                sender.send_packet(size);
            }
            sender.update_app_limited(false);

            // Receiving Acks.
            sender.update_rtt(rtt_css);
            sender.ack_n_packets(n_rtt_sample)?;
        }
        // Now we are in congestion avoidance.
        assert_eq!(sender.window(), sender.ssthresh.get());
        Ok(())
    }

    #[test]
    fn cubic_spurious_congestion_event() -> FixtureResult {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        let prev_cwnd = sender.window();

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }
        sender.lose_n_packets(1, None)?;

        // After congestion event, cwnd will be reduced.
        let cur_cwnd = beta_reduce(prev_cwnd);
        assert_eq!(sender.window(), cur_cwnd);

        // Ack more than cwnd bytes with rtt=100ms
        let rtt = Duration::from_millis(100);
        sender.update_rtt(rtt);

        let acked = Acked {
            pkt_num: 0,
            // To exit from recovery
            transmitted_at: sender.time + rtt,
            size,
            in_flight: true,
            delivered: 0,
            delivered_time: sender.time,
            first_sent_time: sender.time,
            is_app_limited: false,
            rtt: Duration::ZERO,
        };

        // Trigger detecting spurious congestion event
        sender.inject_ack(acked, sender.time + rtt + Duration::from_millis(5));

        // This is from slow start, no rollback.
        assert_eq!(sender.window(), cur_cwnd);

        sender.advance_time(rtt);

        let prev_cwnd = sender.window();

        sender.lose_n_packets(1, Some(sender.time))?;

        // After congestion event, cwnd will be reduced.
        let cur_cwnd = beta_reduce(cur_cwnd);
        assert_eq!(sender.window(), cur_cwnd);

        sender.advance_time(rtt + Duration::from_millis(5));

        let acked = Acked {
            pkt_num: 0,
            // To exit from recovery
            transmitted_at: sender.time + rtt,
            size,
            in_flight: true,
            delivered: 0,
            delivered_time: sender.time,
            first_sent_time: sender.time,
            is_app_limited: false,
            rtt: Duration::ZERO,
        };

        // Trigger detecting spurious congestion event.
        sender.inject_ack(acked, sender.time + rtt + Duration::from_millis(5));

        // cwnd is rolled back to the previous one.
        assert_eq!(sender.window(), prev_cwnd);
        Ok(())
    }

    #[test]
    fn cubic_rollback_restores_full_curve_once() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;
        let cwnd = 20 * size;
        sender.cwnd = cwnd;
        sender.ssthresh.update(cwnd, false);
        sender.cubic_state.curve = CurveState {
            epoch_start: Some(sender.time - Duration::from_secs(2)),
            k: 1.5,
            w_max: Window::bytes(100_000),
            w_est: Window::bytes(50_000),
            reno_gain: RenoGain::Full,
            cwnd_inc: size / 2,
        };
        let prior = sender.cubic_state.curve;
        let epoch = sender.time;
        sender.recovery_started_at = Some(epoch);
        checkpoint(&mut sender);
        sender.cwnd = beta_reduce(cwnd);
        sender.ssthresh.update(beta_reduce(cwnd), false);
        sender.cubic_state.curve = CurveState::default();
        sender.recovery_started_at = Some(epoch + Duration::from_secs(1));
        let last_ack = epoch + Duration::from_secs(2);
        sender.cubic_state.last_ack_time = Some(last_ack);

        assert!(rollback(&mut sender));
        assert_eq!(sender.cwnd, cwnd);
        assert_eq!(sender.ssthresh.get(), cwnd);
        assert_eq!(sender.recovery_started_at, Some(epoch));
        assert_eq!(sender.cubic_state.curve.epoch_start, prior.epoch_start);
        assert_eq!(sender.cubic_state.curve.k.to_bits(), prior.k.to_bits());
        assert_eq!(sender.cubic_state.curve.w_max, prior.w_max);
        assert_eq!(sender.cubic_state.curve.w_est, prior.w_est);
        assert_eq!(sender.cubic_state.curve.reno_gain, prior.reno_gain);
        assert_eq!(sender.cubic_state.curve.cwnd_inc, prior.cwnd_inc);
        assert_eq!(sender.cubic_state.last_ack_time, Some(last_ack));
        sender.cwnd = beta_reduce(cwnd);
        assert!(!rollback(&mut sender));
    }

    #[test]
    fn cubic_fast_convergence() -> FixtureResult {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        let prev_cwnd = sender.cwnd;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        // Trigger congestion event to update ssthresh
        sender.lose_n_packets(1, None)?;

        // After 1st congestion event, cwnd will be reduced.
        let cur_cwnd = beta_reduce(prev_cwnd);
        assert_eq!(sender.cwnd, cur_cwnd);

        // Shift current time by 1 RTT.
        let rtt = Duration::from_millis(100);
        sender.update_rtt(rtt);
        // Exit from the recovery.
        sender.advance_time(rtt);

        // Drain most packets in flight except for 1 to avoid adjustments to
        // cubic.last_sent_time when idle, see on_packet_sent.
        sender.ack_n_packets(sender.initial_congestion_window_packets - 2)?;

        // During Congestion Avoidance, it will take 6 ACKs to
        // increase cwnd by 1 MSS.  But ACKed packets must have been
        // sent after the loss event.
        for _ in 0..7 {
            sender.send_packet(size);
        }
        // ACK the packet that was sent before the loss event.
        sender.ack_n_packets(1)?;
        sender.advance_time(rtt);
        for _ in 0..6 {
            sender.ack_n_packets(1)?;
        }

        assert_eq!(sender.cwnd, cur_cwnd + size);

        let prev_cwnd = sender.cwnd;

        // Fast convergence: now there is 2nd congestion event and
        // cwnd is not fully recovered to w_max, w_max will be
        // further reduced.
        sender.lose_n_packets(1, None)?;

        // After 2nd congestion event, cwnd will be reduced.
        let cur_cwnd = beta_reduce(prev_cwnd);
        assert_eq!(sender.cwnd, cur_cwnd);

        // w_max will be further reduced, not prev_cwnd
        assert_eq!(
            sender.cubic_state.curve.w_max,
            Window(Window::bytes(prev_cwnd).0 * 17 / 20)
        );
        Ok(())
    }

    #[test]
    fn cubic_perpetual_recovery_trap() -> FixtureResult {
        // Reproduces the bug where cwnd stays pinned at minimum after a
        // loss event because the idle-time epoch shift pushes
        // recovery_started_at into the future on every
        // send -> ACK -> send cycle when bif transiently hits 0.
        let mut sender = test_sender();
        let size = sender.max_datagram_size;
        let rtt = Duration::from_millis(100);

        // Fill the pipe.
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        sender.update_rtt(rtt);
        sender.advance_time(rtt);

        // Trigger a loss to enter recovery and reduce cwnd.
        let initial_cwnd = sender.cwnd;
        sender.lose_n_packets(1, None)?;
        let post_loss_cwnd = sender.cwnd;
        assert_eq!(post_loss_cwnd, beta_reduce(initial_cwnd));
        let initial_recovery_start_time = sender.time;
        assert_eq!(
            sender.recovery_started_at,
            Some(initial_recovery_start_time)
        );

        // ACK remaining in-flight packets to exit recovery.
        sender.ack_n_packets(sender.initial_congestion_window_packets - 1)?;
        assert_eq!(sender.bytes_in_flight, 0);

        // Now simulate the problematic pattern: send a small burst at
        // minimum cwnd, ACK it (bif drops to 0), advance one RTT, repeat.
        // With the bug, recovery_start_time would advance on every
        // cycle, trapping cwnd.  With the fix, cwnd must grow.
        let packets_per_burst = cmp::max(1, sender.cwnd / size);

        for _ in 0..20 {
            for _ in 0..packets_per_burst {
                sender.send_packet(size);
            }

            sender.advance_time(rtt);
            sender.ack_n_packets(packets_per_burst)?;
            assert_eq!(sender.bytes_in_flight, 0);
        }

        // cwnd must have grown beyond the post-loss value.
        assert!(
            sender.cwnd > post_loss_cwnd,
            "cwnd stuck at {} (post-loss {}): perpetual recovery trap",
            sender.cwnd,
            post_loss_cwnd,
        );
        // Recovery start hasn't changed.
        assert_eq!(
            sender.recovery_started_at,
            Some(initial_recovery_start_time),
            "epoch should not have shifted without idle gap",
        );
        Ok(())
    }

    #[rstest::rstest]
    fn cubic_idle_shifts_curve_but_not_recovery_cutoff(
        #[values(false, true)] lose_after_idle: bool,
    ) -> FixtureResult {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;
        let rtt = Duration::from_millis(100);
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }
        sender.update_rtt(rtt);
        sender.advance_time(rtt);
        sender.lose_n_packets(1, None)?;
        let loss_time = sender.time;
        let post_loss_cwnd = sender.cwnd;
        sender.ack_n_packets(sender.initial_congestion_window_packets - 1)?;

        let idle = Duration::from_secs(5);
        sender.advance_time(idle);
        sender.send_packet(size);
        assert_eq!(sender.cubic_state.curve.epoch_start, Some(loss_time + idle));
        assert_eq!(sender.recovery_started_at, Some(loss_time));
        assert!(!sender.in_congestion_recovery(sender.time));

        if lose_after_idle {
            sender.advance_time(rtt);
            // A loss on the first post-idle packet is a new congestion event.
            sender.lose_n_packets(1, None)?;
            assert_eq!(sender.cwnd, beta_reduce(post_loss_cwnd));
            assert_eq!(sender.recovery_started_at, Some(sender.time));
        } else {
            sender.update_app_limited(false);
            sender.advance_time(rtt);
            sender.ack_n_packets(1)?;
            assert!(sender.cwnd >= post_loss_cwnd);
            assert!(sender.cwnd <= post_loss_cwnd + size);
            assert_eq!(sender.recovery_started_at, Some(loss_time));
        }
        Ok(())
    }

    #[test]
    fn persistent_congestion_invalidates_curve_and_rollback() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;
        let cwnd = 20 * size;
        sender.cwnd = cwnd;
        sender.ssthresh.update(cwnd, false);
        sender.cubic_state.curve = CurveState {
            epoch_start: Some(sender.time),
            k: 1.5,
            w_max: Window::bytes(cwnd),
            w_est: Window::bytes(cwnd),
            reno_gain: RenoGain::Full,
            cwnd_inc: size / 2,
        };
        checkpoint(&mut sender);
        sender.prr.snd_cnt = size;
        sender.on_persistent_congestion();
        assert_eq!(sender.cwnd, size * MINIMUM_WINDOW_PACKETS);
        assert!(sender.cubic_state.curve.epoch_start.is_none());
        assert!(sender.cubic_state.prior.is_none());
        assert_eq!(sender.cubic_state.curve.cwnd_inc, 0);
        assert_eq!(sender.prr.snd_cnt, 0);
        assert!(!rollback(&mut sender));
        assert_eq!(sender.cwnd, size * MINIMUM_WINDOW_PACKETS);
    }

    #[test]
    fn cubic_zero_bytes_sent_no_epoch_shift() -> FixtureResult {
        // A zero-byte packet (e.g. PADDING-only) must NOT shift
        // recovery_started_at or update last_sent_time.
        let mut sender = test_sender();
        let size = sender.max_datagram_size;
        let rtt = Duration::from_millis(100);

        // Fill pipe, trigger loss to set recovery_started_at.
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }
        sender.update_rtt(rtt);
        sender.advance_time(rtt);
        sender.lose_n_packets(1, None)?;

        // ACK everything → bif = 0.
        sender.ack_n_packets(sender.initial_congestion_window_packets - 1)?;
        assert_eq!(sender.bytes_in_flight, 0);

        // Record state before zero-byte send.
        let recovery_start_before = sender.recovery_started_at;
        let curve_epoch_before = sender.cubic_state.curve.epoch_start;
        let last_sent_before = sender.cubic_state.last_sent_time;

        // Advance time so any shift would be visible.
        sender.advance_time(Duration::from_millis(500));

        // Send a zero-byte packet (simulates PADDING-only).
        sender.send_packet(0);

        // Neither recovery_start_time nor last_sent_time should change.
        assert_eq!(
            sender.recovery_started_at, recovery_start_before,
            "recovery_start_time must not shift on zero-byte send",
        );
        assert_eq!(sender.cubic_state.curve.epoch_start, curve_epoch_before);
        assert_eq!(
            sender.cubic_state.last_sent_time, last_sent_before,
            "last_sent_time must not update on zero-byte send",
        );
        Ok(())
    }
}
