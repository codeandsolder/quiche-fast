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

use std::collections::VecDeque;
use std::ops::Deref;
use std::ops::DerefMut;
use std::time::Duration;
use std::time::Instant;

use super::rtt::RttStats;
use super::Acked;
use super::Congestion;
use super::Sent;
use crate::recovery::PacketFlight;
use crate::recovery::RecoveryConfig;
use crate::CongestionControlAlgorithm;
use crate::DEFAULT_INITIAL_RTT;

pub(super) type FixtureResult = Result<(), &'static str>;

pub(super) struct TestSender {
    cc: Congestion,
    pub(super) next_pkt: u64,
    pub(super) bytes_in_flight: usize,
    pub(super) time: Instant,
    rtt_stats: RttStats,
    sent_packets: VecDeque<Sent>,
}

impl TestSender {
    pub(super) fn new(algo: CongestionControlAlgorithm, hystart: bool) -> Self {
        let cfg = RecoveryConfig {
            cc_algorithm: algo,
            hystart,
            ..RecoveryConfig::default()
        };

        TestSender {
            next_pkt: 0,
            bytes_in_flight: 0,
            time: Instant::now(),
            rtt_stats: RttStats::new(DEFAULT_INITIAL_RTT, Duration::ZERO),
            cc: Congestion::from_config(&cfg),
            sent_packets: VecDeque::new(),
        }
    }

    pub(super) fn send_packet(&mut self, bytes: usize) {
        let mut sent = Sent {
            pkt_num: self.next_pkt,
            frames: smallvec::SmallVec::new(),
            transmitted_at: self.time,
            acked_at: None,
            lost_at: None,
            size: bytes,
            flight: PacketFlight::AckEliciting,
            delivered: 0,
            delivered_time: self.time,
            first_sent_time: self.time,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
        };

        self.cc.on_packet_sent(
            self.bytes_in_flight,
            bytes,
            self.time,
            &mut sent,
            0,
            true,
        );

        self.sent_packets.push_back(sent);

        self.bytes_in_flight += bytes;
        self.next_pkt += 1;
    }

    /// Inject a synthetic ACK event into the congestion controller without
    /// pretending that it acknowledged an unrelated queued packet.
    pub(super) fn inject_ack(&mut self, acked: Acked, now: Instant) {
        self.cc.on_packets_acked(
            self.bytes_in_flight,
            &mut vec![acked],
            &self.rtt_stats,
            now,
        );
    }

    /// Acknowledge the oldest packets, deriving byte accounting from their
    /// recorded sizes instead of requiring a uniform packet size.
    pub(super) fn ack_n_packets(&mut self, n: usize) -> FixtureResult {
        if n > self.sent_packets.len() {
            return Err("ACK exceeds outstanding packet count");
        }
        if n == 0 {
            return Ok(());
        }

        let mut acknowledged_bytes = 0;
        let mut acked = Vec::with_capacity(n);
        for unacked in self.sent_packets.drain(..n) {
            acknowledged_bytes += unacked.size;
            acked.push(Acked {
                pkt_num: unacked.pkt_num,
                transmitted_at: unacked.transmitted_at,
                size: unacked.size,
                in_flight: unacked.flight.in_flight(),
                rtt: self.time.saturating_duration_since(unacked.transmitted_at),
                delivered: unacked.delivered,
                delivered_time: unacked.delivered_time,
                first_sent_time: unacked.first_sent_time,
                is_app_limited: unacked.is_app_limited,
            });
        }

        self.cc.on_packets_acked(
            self.bytes_in_flight,
            &mut acked,
            &self.rtt_stats,
            self.time,
        );

        self.bytes_in_flight -= acknowledged_bytes;
        Ok(())
    }

    /// Report a batch of lost packets. The last packet defines the recovery
    /// cutoff; tests can explicitly inject a synthetic transmission time.
    pub(super) fn lose_n_packets(
        &mut self, n: usize, transmitted_at: Option<Instant>,
    ) -> FixtureResult {
        if n == 0 || n > self.sent_packets.len() {
            return Err("loss requires a nonempty batch of outstanding packets");
        }

        let lost_bytes = self
            .sent_packets
            .iter()
            .take(n)
            .map(|packet| packet.size)
            .sum::<usize>();
        let mut unacked = self
            .sent_packets
            .drain(..n)
            .last()
            .ok_or("loss batch has no final packet")?;
        if let Some(time) = transmitted_at {
            unacked.transmitted_at = time;
        }

        if !self.cc.in_congestion_recovery(unacked.transmitted_at) {
            (self.cc.cc_ops.checkpoint)(&mut self.cc);
        }

        (self.cc.cc_ops.congestion_event)(
            &mut self.cc,
            self.bytes_in_flight,
            lost_bytes,
            &unacked,
            self.time,
        );

        self.cc.lost_count += n;
        self.bytes_in_flight -= lost_bytes;
        Ok(())
    }

    pub(super) fn update_rtt(&mut self, rtt: Duration) {
        self.rtt_stats
            .update_rtt(rtt, Duration::ZERO, self.time, true)
    }

    pub(super) fn advance_time(&mut self, period: Duration) {
        self.time += period;
    }
}

impl Deref for TestSender {
    type Target = Congestion;

    fn deref(&self) -> &Self::Target {
        &self.cc
    }
}

impl DerefMut for TestSender {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cc
    }
}

#[test]
fn mixed_packet_sizes_and_invalid_batches_preserve_flight_accounting(
) -> FixtureResult {
    let mut sender = TestSender::new(CongestionControlAlgorithm::Reno, false);
    for size in [1200, 300, 500, 700] {
        sender.send_packet(size);
    }
    assert_eq!(sender.bytes_in_flight, 2700);
    assert!(sender.ack_n_packets(5).is_err());
    assert!(sender.lose_n_packets(0, None).is_err());
    assert!(sender.lose_n_packets(5, None).is_err());
    assert_eq!(sender.bytes_in_flight, 2700);
    assert_eq!(sender.sent_packets.len(), 4);
    sender.ack_n_packets(2)?;
    assert_eq!(sender.bytes_in_flight, 1200);
    assert_eq!(sender.sent_packets.len(), 2);
    sender.lose_n_packets(2, None)?;
    assert_eq!(sender.bytes_in_flight, 0);
    assert!(sender.sent_packets.is_empty());
    assert_eq!(sender.lost_count, 2);
    Ok(())
}
