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

//! Reno Congestion Control
//!
//! Note that Slow Start can use `HyStart`++ when enabled.

use std::cmp;
use std::time::Instant;

use super::rtt::RttStats;
use super::Acked;
use super::Sent;

use super::Congestion;
use super::CongestionControlOps;
use crate::recovery::MINIMUM_WINDOW_PACKETS;

pub static RENO: CongestionControlOps = CongestionControlOps {
    on_init,
    on_packet_sent,
    on_packets_acked,
    congestion_event,
    checkpoint,
    rollback,
    #[cfg(feature = "qlog")]
    state_str,
    debug_fmt: None,
};

pub const fn on_init(_r: &mut Congestion) {}

pub const fn on_packet_sent(
    _r: &mut Congestion, _sent_bytes: usize, _bytes_in_flight: usize,
    _now: Instant,
) {
}

fn on_packets_acked(
    r: &mut Congestion, _bytes_in_flight: usize, packets: &mut Vec<Acked>,
    now: Instant, rtt_stats: &RttStats,
) {
    for pkt in packets.drain(..) {
        on_packet_acked(r, &pkt, now, rtt_stats);
    }
}

fn on_packet_acked(
    r: &mut Congestion, packet: &Acked, now: Instant, rtt_stats: &RttStats,
) {
    if !packet.in_flight {
        return;
    }

    if r.in_congestion_recovery(packet.transmitted_at) {
        return;
    }

    if r.app_limited {
        return;
    }

    if r.cwnd < r.ssthresh.get() {
        if r.hystart.in_css() {
            r.cwnd = r.cwnd.saturating_add(
                super::hystart::Hystart::css_cwnd_inc(r.max_datagram_size),
            );
        } else {
            // RFC 9002, Section 7.3.1: while a sender is in slow start, the
            // congestion window increases by the number of bytes acknowledged.
            r.cwnd = r.cwnd.saturating_add(packet.size);
        }

        if r.hystart.on_packet_acked(packet, rtt_stats.latest_rtt, now) {
            // Exit to congestion avoidance if CSS ends.
            r.ssthresh.update(r.cwnd, true);
        }
    } else {
        // Congestion avoidance.
        let acked = r.bytes_acked_ca as u128 + packet.size as u128;
        let remainder = if acked >= r.cwnd as u128 {
            let remainder = acked - r.cwnd as u128;
            r.cwnd = r.cwnd.saturating_add(r.max_datagram_size);
            remainder
        } else {
            acked
        };
        r.bytes_acked_ca = usize::try_from(remainder).unwrap_or(usize::MAX);
    }
}

fn congestion_event(
    r: &mut Congestion, _bytes_in_flight: usize, _lost_bytes: usize,
    largest_lost_pkt: &Sent, now: Instant,
) {
    // Start a new congestion event if packet was sent after the
    // start of the previous congestion recovery period.
    let transmitted_at = largest_lost_pkt.transmitted_at;

    if !r.in_congestion_recovery(transmitted_at) {
        r.recovery_started_at = Some(now);

        r.cwnd /= 2;

        r.cwnd = cmp::max(
            r.cwnd,
            r.max_datagram_size.saturating_mul(MINIMUM_WINDOW_PACKETS),
        );

        r.bytes_acked_ca = r.cwnd / 2;

        r.ssthresh.update(r.cwnd, r.hystart.in_css());

        if r.hystart.in_css() {
            r.hystart.congestion_event();
        }
    }
}

const fn checkpoint(_r: &mut Congestion) {}

const fn rollback(_r: &mut Congestion) -> bool {
    true
}

#[cfg(feature = "qlog")]
pub fn state_str(r: &Congestion, now: Instant) -> &'static str {
    if r.hystart.in_css() {
        "conservative_slow_start"
    } else if r.cwnd < r.ssthresh.get() {
        "slow_start"
    } else if r.in_congestion_recovery(now) {
        "recovery"
    } else {
        "congestion_avoidance"
    }
}

#[cfg(test)]
mod tests {
    use crate::CongestionControlAlgorithm;

    use super::*;

    use crate::recovery::congestion::recovery::LegacyRecovery;
    use crate::recovery::congestion::test_sender::TestSender;
    use crate::recovery::RecoveryOps;

    use std::time::Duration;

    fn test_sender() -> TestSender {
        TestSender::new(CongestionControlAlgorithm::Reno, false)
    }

    #[test]
    fn reno_congestion_avoidance_preserves_credit_at_width_limit() {
        let mut sender = test_sender();
        let mss = sender.max_datagram_size;
        let cwnd = usize::MAX - mss / 2;
        sender.cwnd = cwnd;
        sender.ssthresh.update(cwnd, false);
        sender.bytes_acked_ca = cwnd - 1;
        sender.send_packet(mss);
        sender.update_app_limited(false);
        sender.advance_time(Duration::from_millis(100));
        sender.ack_n_packets(1, mss);
        assert_eq!(sender.cwnd, usize::MAX);
        assert_eq!(sender.bytes_acked_ca, mss - 1);
    }

    #[test]
    fn reno_init() {
        let mut cfg = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        cfg.set_cc_algorithm(CongestionControlAlgorithm::Reno);

        let r = LegacyRecovery::new(&cfg);

        assert!(r.cwnd() > 0);
        assert_eq!(r.bytes_in_flight(), 0);
    }

    #[test]
    fn reno_slow_start() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let cwnd_prev = sender.cwnd;

        sender.ack_n_packets(1, size);

        // Check if cwnd increased by packet size (slow start).
        assert_eq!(sender.cwnd, cwnd_prev + size);
    }

    #[test]
    fn reno_slow_start_smaller_than_mss() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let partial = size / 4;
        sender.send_packet(partial);
        sender.ack_n_packets(sender.initial_congestion_window_packets, size);

        let cwnd_prev = sender.cwnd;
        sender.ack_n_packets(1, partial);

        assert_eq!(sender.cwnd, cwnd_prev + partial);
    }

    #[test]
    fn reno_slow_start_multi_acks() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let cwnd_prev = sender.cwnd;

        sender.ack_n_packets(3, size);

        // Acked 3 packets.
        assert_eq!(sender.cwnd, cwnd_prev + size * 3);
    }

    #[test]
    fn reno_ignores_non_in_flight_ack() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        for _ in 0..sender.initial_congestion_window_packets {
            sender.send_packet(size);
        }

        let cwnd_prev = sender.cwnd;
        let now = sender.time;

        sender.inject_ack(
            Acked {
                pkt_num: 0,
                transmitted_at: now,
                size,
                in_flight: false,
                rtt: Duration::ZERO,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
            },
            now,
        );

        assert_eq!(sender.cwnd, cwnd_prev);
    }

    #[test]
    fn reno_congestion_event() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        let prev_cwnd = sender.cwnd;

        sender.send_packet(size);
        sender.lose_n_packets(1, size, None);

        // In Reno, after congestion event, cwnd will be cut in half.
        assert_eq!(prev_cwnd / 2, sender.cwnd);
    }

    #[test]
    fn reno_loss_reduction_is_exact_at_width_limit() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;
        sender.cwnd = usize::MAX;
        sender.send_packet(size);
        sender.lose_n_packets(1, size, None);
        assert_eq!(sender.cwnd, usize::MAX / 2);
        assert_eq!(sender.bytes_acked_ca, usize::MAX / 4);
    }

    #[test]
    fn reno_congestion_avoidance() {
        let mut sender = test_sender();
        let size = sender.max_datagram_size;

        // Send initcwnd full MSS packets to become no longer app limited
        for _ in 0..14 {
            sender.send_packet(size);
        }

        let rtt = Duration::from_millis(100);
        let prev_cwnd = sender.cwnd;

        sender.advance_time(rtt);
        sender.lose_n_packets(1, size, None);

        // After congestion event, cwnd will be reduced.
        let cur_cwnd = prev_cwnd / 2;
        assert_eq!(sender.cwnd, cur_cwnd);

        sender.update_rtt(rtt);
        sender.advance_time(2 * rtt);

        sender.ack_n_packets(13, size);
        // Acked packets were sent before the loss event, window does not
        // increase.
        assert_eq!(sender.cwnd, cur_cwnd);

        for _ in 0..7 {
            sender.send_packet(size);
        }
        sender.advance_time(rtt);
        sender.ack_n_packets(2, size);
        // Not enough ACKed, window does not increase.
        assert_eq!(sender.cwnd, cur_cwnd);

        sender.ack_n_packets(1, size);
        // Expect cwnd increased by MSS
        assert_eq!(sender.cwnd, cur_cwnd + size);

        for _ in 0..7 {
            sender.send_packet(size);
        }

        // Expect a second window increase after a cwnd's worth of ACKs.
        sender.ack_n_packets(5, size);
        // Not yet, one more ACK needed.
        assert_eq!(sender.cwnd, cur_cwnd + size);
        sender.ack_n_packets(1, size);
        // Expect cwnd increased by MSS
        assert_eq!(sender.cwnd, cur_cwnd + 2 * size);
    }
}
