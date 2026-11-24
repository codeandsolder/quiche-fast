// Copyright (C) 2018-2019, Cloudflare, Inc.
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

use std::cmp;

use std::time::Duration;
use std::time::Instant;

use std::collections::BTreeSet;
use std::collections::VecDeque;

use super::RecoveryConfig;
use super::Sent;

use crate::packet::Epoch;
use crate::ranges::RangeSet;
use crate::recovery::validate_ack_ranges;
use crate::recovery::Bandwidth;
use crate::recovery::HandshakeStatus;
use crate::recovery::OnLossDetectionTimeoutOutcome;
use crate::recovery::RecoveryOps;
use crate::recovery::StartupExit;
use crate::Result;

#[cfg(feature = "qlog")]
use crate::recovery::QlogMetrics;

use crate::frame;
use crate::recovery::pending_lost_frames::PendingLostFrames;

#[cfg(feature = "qlog")]
use qlog::events::EventData;

use super::Congestion;
use crate::recovery::bytes_in_flight::BytesInFlight;
use crate::recovery::recovery_deadline;
use crate::recovery::rtt::RttStats;
use crate::recovery::spurious_packet_threshold;
use crate::recovery::EpochTiming;
use crate::recovery::LossDetectionTimer;
use crate::recovery::OnAckReceivedOutcome;
use crate::recovery::RecoveryDeadline;
use crate::recovery::ReleaseDecision;
use crate::recovery::ReleaseTime;
use crate::recovery::GRANULARITY;
use crate::recovery::INITIAL_PACKET_THRESHOLD;
use crate::recovery::INITIAL_TIME_THRESHOLD;
use crate::recovery::MAX_OUTSTANDING_NON_ACK_ELICITING;
use crate::recovery::MAX_PACKET_THRESHOLD;
use crate::recovery::MAX_PTO_PROBES_COUNT;
use crate::recovery::PACKET_REORDER_TIME_THRESHOLD;
use crate::recovery::PERSISTENT_CONGESTION_THRESHOLD;

#[derive(Default)]
struct RecoveryEpoch {
    timing: EpochTiming,

    /// The largest packet number acknowledged in the packet number space so
    /// far.
    largest_acked_packet: Option<u64>,

    /// An association of packet numbers in a packet number space to information
    /// about them.
    sent_packets: VecDeque<Sent>,

    /// Sender-created packet-number gaps that can still affect loss distance.
    skipped_packet_numbers: Vec<u64>,

    loss_probes: usize,

    acked_frames: Vec<frame::Frame>,

    /// Send times newly acknowledged by the current ACK, including spurious
    /// acknowledgments of packets that had already been declared lost.
    newly_acked_send_times: Vec<Instant>,

    // Frames scheduled for retransmission due to PTO are tracked
    // separately so we can check that frames were drained before
    // generating more PTO probes.
    pending_lost_frames: PendingLostFrames<Vec<frame::Frame>>,

    /// The largest packet number sent in the packet number space so far.
    #[cfg(test)]
    test_largest_sent_pkt_num_on_path: Option<u64>,
}

struct AckedDetectionResult {
    acked_bytes: usize,
    spurious_losses: usize,
    spurious_pkt_thresh: Option<u64>,
    has_ack_eliciting: bool,
    has_in_flight_spurious_loss: bool,
}

struct LossDetectionResult {
    largest_lost_pkt: Option<Sent>,
    lost_packets: usize,
    lost_bytes: usize,
    pmtud_lost_bytes: usize,

    // Send times of the first and last ack-eliciting in-flight packets
    // declared lost, and how many there were, to establish persistent
    // congestion.
    first_lost_ack_eliciting: Option<Instant>,
    last_lost_ack_eliciting: Option<Instant>,
    lost_ack_eliciting: usize,
}

impl RecoveryEpoch {
    // ACK ranges and the largest acknowledged packet have been validated.
    fn detect_and_remove_acked_packets(
        &mut self, now: Instant, peer_sent_ack_ranges: &RangeSet,
        newly_acked: &mut Vec<Acked>, rtt_stats: &RttStats,
        largest_ack_received: u64, trace_id: &str,
    ) -> AckedDetectionResult {
        newly_acked.clear();
        self.newly_acked_send_times.clear();

        let mut acked_bytes = 0;
        let mut spurious_losses = 0;
        let mut spurious_pkt_thresh = None;
        let mut has_ack_eliciting = false;
        let mut has_in_flight_spurious_loss = false;

        let largest_acked = self
            .largest_acked_packet
            .unwrap_or(0)
            .max(largest_ack_received);

        for peer_sent_range in peer_sent_ack_ranges.iter() {
            // Because packets always have incrementing numbers, they are always
            // in sorted order.
            let start = if self
                .sent_packets
                .front()
                .as_ref()
                .is_some_and(|e| e.pkt_num >= peer_sent_range.start)
            {
                // Usually it will be the first packet.
                0
            } else {
                self.sent_packets
                    .binary_search_by_key(&peer_sent_range.start, |p| p.pkt_num)
                    .unwrap_or_else(|e| e)
            };

            for unacked in self.sent_packets.range_mut(start..) {
                if unacked.pkt_num >= peer_sent_range.end {
                    break;
                }

                if unacked.acked_at.is_some() {
                    // Already acked.
                } else if unacked.lost_at.is_some() {
                    // An acked packet was already declared lost.
                    spurious_losses += 1;
                    spurious_pkt_thresh.get_or_insert_with(|| {
                        spurious_packet_threshold(
                            largest_acked,
                            unacked.pkt_num,
                            &self.skipped_packet_numbers,
                        )
                    });
                    unacked.acked_at = Some(now);
                    self.newly_acked_send_times.push(unacked.sent_at);

                    if unacked.flight.in_flight() {
                        has_in_flight_spurious_loss = true;
                    }
                } else {
                    if unacked.flight.in_flight() {
                        self.timing.in_flight_count -= 1;
                        acked_bytes += unacked.size;
                    }

                    newly_acked.push(Acked {
                        pkt_num: unacked.pkt_num,
                        sent_at: unacked.sent_at,
                        size: unacked.size,
                        in_flight: unacked.flight.in_flight(),

                        rtt: now.saturating_duration_since(unacked.sent_at),
                        delivered: unacked.delivered,
                        delivered_time: unacked.delivered_time,
                        first_sent_time: unacked.first_sent_time,
                        is_app_limited: unacked.is_app_limited,
                    });

                    trace!("{trace_id} packet newly acked {}", unacked.pkt_num);

                    self.acked_frames
                        .extend(std::mem::take(&mut unacked.frames));

                    has_ack_eliciting |= unacked.flight.ack_eliciting();
                    unacked.acked_at = Some(now);
                    self.newly_acked_send_times.push(unacked.sent_at);
                }
            }
        }

        self.skipped_packet_numbers.retain(|&pn| {
            largest_ack_received < pn.saturating_add(MAX_PACKET_THRESHOLD)
        });

        self.drain_acked_and_lost_packets(now.checked_sub(rtt_stats.rtt()));

        AckedDetectionResult {
            acked_bytes,
            spurious_losses,
            spurious_pkt_thresh,
            has_ack_eliciting,
            has_in_flight_spurious_loss,
        }
    }

    fn detect_lost_packets(
        &mut self, loss_delay: Duration, pkt_thresh: u64, now: Instant,
        trace_id: &str, epoch: Epoch, first_rtt_sample_time: Option<Instant>,
    ) -> LossDetectionResult {
        self.timing.loss = None;

        // Minimum time of kGranularity before packets are deemed lost.
        let loss_delay = cmp::max(loss_delay, GRANULARITY);
        let largest_acked = self.largest_acked_packet.unwrap_or(0);

        // Packets sent before this time are deemed lost.
        let lost_send_time = now.checked_sub(loss_delay);

        let mut lost_packets = 0;
        let mut lost_bytes = 0;
        let mut pmtud_lost_bytes = 0;

        let mut largest_lost_pkt = None;

        let mut first_lost_ack_eliciting: Option<Instant> = None;
        let mut last_lost_ack_eliciting: Option<Instant> = None;
        let mut lost_ack_eliciting = 0;

        let skipped_packet_numbers = &self.skipped_packet_numbers;

        let unacked_iter = self
            .sent_packets
            .iter_mut()
            .take_while(|p| p.pkt_num <= largest_acked)
            .filter(|p| p.acked_at.is_none() && p.lost_at.is_none());

        for unacked in unacked_iter {
            let skipped_between = skipped_packet_numbers
                .iter()
                .filter(|&&pn| pn > unacked.pkt_num && pn <= largest_acked)
                .count() as u64;
            let packet_distance = largest_acked
                .saturating_sub(unacked.pkt_num)
                .saturating_sub(skipped_between);

            if lost_send_time.is_some_and(|time| unacked.sent_at <= time) ||
                packet_distance >= pkt_thresh
            {
                self.pending_lost_frames.queue_ack(unacked.frames.drain(..));

                unacked.lost_at = Some(now);

                if unacked.flight.is_pmtud_probe() {
                    pmtud_lost_bytes += unacked.size;
                    self.timing.in_flight_count -= 1;

                    // Do not track PMTUD probes losses.
                    continue;
                }

                if unacked.flight.in_flight() {
                    lost_bytes += unacked.size;

                    if unacked.flight.ack_eliciting() &&
                        first_rtt_sample_time.is_some_and(|first_rtt| {
                            unacked.sent_at > first_rtt
                        })
                    {
                        // Packets are visited in packet number order, so this
                        // records the span the lost packets were sent over.
                        first_lost_ack_eliciting.get_or_insert(unacked.sent_at);
                        last_lost_ack_eliciting = Some(unacked.sent_at);
                        lost_ack_eliciting += 1;
                    }

                    // Frames have already been removed from the packet, so
                    // cloning the whole packet should be relatively cheap.
                    largest_lost_pkt = Some(unacked.clone());

                    self.timing.in_flight_count -= 1;

                    trace!(
                        "{trace_id} packet {} lost on epoch {epoch}",
                        unacked.pkt_num
                    );
                }

                lost_packets += 1;
            } else {
                self.timing.loss = unacked.sent_at.checked_add(loss_delay);
                break;
            }
        }

        LossDetectionResult {
            largest_lost_pkt,
            lost_packets,
            lost_bytes,
            pmtud_lost_bytes,
            first_lost_ack_eliciting,
            last_lost_ack_eliciting,
            lost_ack_eliciting,
        }
    }

    fn drain_acked_and_lost_packets(&mut self, loss_thresh: Option<Instant>) {
        // In order to avoid removing elements from the middle of the list
        // (which would require copying other elements to compact the list),
        // we only remove a contiguous range of elements from the start of the
        // list.
        //
        // This means that acked or lost elements coming after this will not
        // be removed at this point, but their removal is delayed for a later
        // time, once the gaps have been filled.
        while let Some(pkt) = self.sent_packets.front() {
            if let Some(lost_at) = pkt.lost_at {
                if loss_thresh.is_none_or(|threshold| lost_at > threshold) {
                    break;
                }
            }

            if pkt.acked_at.is_none() && pkt.lost_at.is_none() {
                break;
            }

            self.sent_packets.pop_front();
        }
    }
}

pub struct LegacyRecovery {
    epochs: [RecoveryEpoch; Epoch::count()],

    loss_timer: LossDetectionTimer,

    pto_count: u32,

    rtt_stats: RttStats,

    lost_spurious_count: usize,

    pkt_thresh: u64,

    time_thresh: f64,

    bytes_in_flight: BytesInFlight,

    bytes_lost: u64,

    #[cfg(feature = "qlog")]
    qlog_metrics: QlogMetrics,

    #[cfg(feature = "qlog")]
    qlog_prev_cc_state: &'static str,

    /// How many non-ack-eliciting packets have been sent.
    outstanding_non_ack_eliciting: usize,

    pub congestion: Congestion,

    /// A resusable list of acks.
    newly_acked: Vec<Acked>,

    /// Send times of acknowledged packets that can still separate future
    /// persistent-congestion endpoints across packet-number spaces.
    acked_packet_send_times: BTreeSet<Instant>,
}

impl LegacyRecovery {
    pub fn new_with_config(recovery_config: &RecoveryConfig) -> Self {
        Self {
            epochs: Default::default(),

            loss_timer: LossDetectionTimer::default(),

            pto_count: 0,

            rtt_stats: RttStats::new(
                recovery_config.initial_rtt,
                recovery_config.max_ack_delay,
            ),

            lost_spurious_count: 0,

            pkt_thresh: INITIAL_PACKET_THRESHOLD,

            time_thresh: INITIAL_TIME_THRESHOLD,

            bytes_in_flight: BytesInFlight::default(),

            bytes_lost: 0,

            #[cfg(feature = "qlog")]
            qlog_metrics: QlogMetrics::default(),

            #[cfg(feature = "qlog")]
            qlog_prev_cc_state: "",

            outstanding_non_ack_eliciting: 0,

            congestion: Congestion::from_config(recovery_config),

            newly_acked: Vec::new(),
            acked_packet_send_times: BTreeSet::new(),
        }
    }

    #[cfg(test)]
    pub fn new(config: &crate::Config) -> Self {
        Self::new_with_config(&config.recovery)
    }

    fn deadline(
        &self, handshake_status: HandshakeStatus, now: Instant,
    ) -> Option<RecoveryDeadline> {
        recovery_deadline(
            handshake_status,
            now,
            self.bytes_in_flight.is_zero(),
            &self.rtt_stats,
            self.pto_count,
            |epoch| self.epochs[epoch].timing,
        )
    }

    fn set_loss_detection_timer(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
    ) {
        self.loss_timer.update(self.deadline(handshake_status, now));
    }

    // https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6.2
    fn in_persistent_congestion(&self, first: Instant, last: Instant) -> bool {
        // RFC 9002 only considers packets sent after the first RTT sample was
        // obtained. The loss collector applies the same filter; keep this
        // check here as a defensive invariant at the declaration boundary.
        let Some(first_rtt_sample_time) = self.rtt_stats.first_rtt_sample_time
        else {
            return false;
        };
        if first <= first_rtt_sample_time {
            return false;
        }

        // https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6.1
        let duration = self
            .rtt_stats
            .probe_timeout()
            .saturating_add(self.rtt_stats.max_ack_delay)
            .saturating_mul(PERSISTENT_CONGESTION_THRESHOLD);

        if last.saturating_duration_since(first) <= duration {
            return false;
        }

        // Across all packet number spaces, none of the packets sent between the
        // two may have been acknowledged. Recovery epochs eagerly drain ACKed
        // packets, so the live packet queues alone are insufficient for this
        // cross-space RFC requirement.
        self.acked_packet_send_times
            .range((
                std::ops::Bound::Excluded(first),
                std::ops::Bound::Excluded(last),
            ))
            .next()
            .is_none()
    }

    fn prune_acked_packet_send_times(&mut self) {
        let oldest_outstanding = self
            .epochs
            .iter()
            .flat_map(|epoch| epoch.sent_packets.iter())
            .filter(|pkt| pkt.acked_at.is_none() && pkt.lost_at.is_none())
            .map(|pkt| pkt.sent_at)
            .min();

        if let Some(oldest_outstanding) = oldest_outstanding {
            self.acked_packet_send_times =
                self.acked_packet_send_times.split_off(&oldest_outstanding);
        } else {
            self.acked_packet_send_times.clear();
        }
    }

    fn detect_lost_packets(
        &mut self, epoch: Epoch, now: Instant, trace_id: &str,
    ) -> (usize, usize) {
        let loss_delay = self.rtt_stats.loss_delay(self.time_thresh);

        let loss = self.epochs[epoch].detect_lost_packets(
            loss_delay,
            self.pkt_thresh,
            now,
            trace_id,
            epoch,
            self.rtt_stats.first_rtt_sample_time,
        );

        if let Some(pkt) = loss.largest_lost_pkt {
            if !self.congestion.in_congestion_recovery(pkt.sent_at) {
                (self.congestion.cc_ops.checkpoint)(&mut self.congestion);
            }

            (self.congestion.cc_ops.congestion_event)(
                &mut self.congestion,
                self.bytes_in_flight.get(),
                loss.lost_bytes,
                &pkt,
                now,
            );

            self.bytes_in_flight
                .saturating_subtract(loss.lost_bytes, now);
        }

        // https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6
        // Losing every packet sent over a long enough period means the network
        // is in persistent congestion and the window collapses.
        if loss.lost_ack_eliciting >= 2 {
            if let (Some(first), Some(last)) =
                (loss.first_lost_ack_eliciting, loss.last_lost_ack_eliciting)
            {
                if self.in_persistent_congestion(first, last) {
                    self.congestion.on_persistent_congestion();
                }
            }
        }

        self.bytes_in_flight
            .saturating_subtract(loss.pmtud_lost_bytes, now);

        self.epochs[epoch]
            .drain_acked_and_lost_packets(now.checked_sub(self.rtt_stats.rtt()));

        self.congestion.lost_count += loss.lost_packets;

        (loss.lost_packets, loss.lost_bytes)
    }
}

impl RecoveryOps for LegacyRecovery {
    /// Returns whether or not we should elicit an ACK even if we wouldn't
    /// otherwise have constructed an ACK eliciting packet.
    fn should_elicit_ack(&self, epoch: Epoch) -> bool {
        self.epochs[epoch].loss_probes > 0 ||
            self.outstanding_non_ack_eliciting >=
                MAX_OUTSTANDING_NON_ACK_ELICITING
    }

    fn next_acked_frame(&mut self, epoch: Epoch) -> Option<frame::Frame> {
        self.epochs[epoch].acked_frames.pop()
    }

    fn next_lost_frame(&mut self, epoch: Epoch) -> Option<frame::Frame> {
        self.epochs[epoch].pending_lost_frames.next_lost_frame()
    }

    #[cfg(test)]
    fn get_largest_acked_on_epoch(&self, epoch: Epoch) -> Option<u64> {
        self.epochs[epoch].largest_acked_packet
    }

    fn has_lost_frames(&self, epoch: Epoch) -> bool {
        self.epochs[epoch].pending_lost_frames.has_pending()
    }

    fn loss_probes(&self, epoch: Epoch) -> usize {
        self.epochs[epoch].loss_probes
    }

    #[cfg(test)]
    fn inc_loss_probes(&mut self, epoch: Epoch) {
        self.epochs[epoch].loss_probes += 1;
    }

    #[cfg(test)]
    fn lost_frames_count(&self, epoch: Epoch) -> usize {
        self.epochs[epoch].pending_lost_frames.count()
    }

    fn ping_sent(&mut self, epoch: Epoch) {
        self.epochs[epoch].loss_probes =
            self.epochs[epoch].loss_probes.saturating_sub(1);
    }

    fn on_packet_sent(
        &mut self, mut pkt: Sent, epoch: Epoch,
        handshake_status: HandshakeStatus, now: Instant, trace_id: &str,
    ) {
        let ack_eliciting = pkt.flight.ack_eliciting();
        let in_flight = pkt.flight.in_flight();
        let sent_bytes = pkt.size;

        if ack_eliciting {
            self.outstanding_non_ack_eliciting = 0;
        } else {
            self.outstanding_non_ack_eliciting += 1;
        }

        if in_flight && ack_eliciting {
            self.epochs[epoch].timing.last_ack_eliciting = Some(now);
        }

        self.congestion.on_packet_sent(
            self.bytes_in_flight.get(),
            sent_bytes,
            now,
            &mut pkt,
            self.bytes_lost,
            in_flight,
        );

        if in_flight {
            self.epochs[epoch].timing.in_flight_count += 1;
            self.bytes_in_flight.add(sent_bytes, now);

            self.set_loss_detection_timer(handshake_status, now);
        }

        #[cfg(test)]
        {
            self.epochs[epoch].test_largest_sent_pkt_num_on_path = self.epochs
                [epoch]
                .test_largest_sent_pkt_num_on_path
                .max(Some(pkt.pkt_num));
        }

        self.epochs[epoch].sent_packets.push_back(pkt);

        trace!("{trace_id} {self:?}");
    }

    fn on_packet_number_skipped(&mut self, pkt_num: u64) {
        self.epochs[Epoch::Application]
            .skipped_packet_numbers
            .push(pkt_num);
    }

    fn get_packet_send_time(&self, now: Instant) -> Instant {
        now
    }

    // peer_sent_ack_ranges has been validated before use.
    fn on_ack_received(
        &mut self, peer_sent_ack_ranges: &RangeSet, ack_delay: u64, epoch: Epoch,
        handshake_status: HandshakeStatus, now: Instant, skip_pn: Option<u64>,
        trace_id: &str,
    ) -> Result<OnAckReceivedOutcome> {
        let largest_ack_received =
            validate_ack_ranges(peer_sent_ack_ranges, skip_pn)?;
        let AckedDetectionResult {
            acked_bytes,
            spurious_losses,
            spurious_pkt_thresh,
            has_ack_eliciting,
            has_in_flight_spurious_loss,
        } = self.epochs[epoch].detect_and_remove_acked_packets(
            now,
            peer_sent_ack_ranges,
            &mut self.newly_acked,
            &self.rtt_stats,
            largest_ack_received,
            trace_id,
        );

        self.acked_packet_send_times
            .extend(self.epochs[epoch].newly_acked_send_times.iter().copied());

        self.lost_spurious_count += spurious_losses;
        if let Some(thresh) = spurious_pkt_thresh {
            self.pkt_thresh =
                self.pkt_thresh.max(thresh.min(MAX_PACKET_THRESHOLD));
            self.time_thresh = PACKET_REORDER_TIME_THRESHOLD;
        }

        if has_in_flight_spurious_loss {
            (self.congestion.cc_ops.rollback)(&mut self.congestion);
        }

        let largest_acked_pkt_num = self.epochs[epoch]
            .largest_acked_packet
            .unwrap_or(0)
            .max(largest_ack_received);
        self.epochs[epoch].largest_acked_packet = Some(largest_acked_pkt_num);

        if let Some(largest_newly_acked) = self.newly_acked.last() {
            if largest_newly_acked.pkt_num == largest_acked_pkt_num &&
                has_ack_eliciting
            {
                let latest_rtt = now - largest_newly_acked.sent_at;
                self.rtt_stats.update_rtt(
                    latest_rtt,
                    Duration::from_micros(ack_delay),
                    now,
                    handshake_status.completed,
                );
            }
        }

        let (lost_packets, lost_bytes) =
            self.detect_lost_packets(epoch, now, trace_id);

        if !self.newly_acked.is_empty() {
            self.congestion.on_packets_acked(
                self.bytes_in_flight.get(),
                &mut self.newly_acked,
                &self.rtt_stats,
                now,
            );
            self.bytes_in_flight.saturating_subtract(acked_bytes, now);
            if handshake_status.peer_verified_address {
                self.pto_count = 0;
            }
        }

        self.set_loss_detection_timer(handshake_status, now);
        self.epochs[epoch]
            .drain_acked_and_lost_packets(now.checked_sub(self.rtt_stats.rtt()));
        self.prune_acked_packet_send_times();

        Ok(OnAckReceivedOutcome {
            lost_packets,
            lost_bytes,
            acked_bytes,
            spurious_losses,
        })
    }

    fn on_loss_detection_timeout(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
        trace_id: &str,
    ) -> OnLossDetectionTimeoutOutcome {
        let deadline = self.deadline(handshake_status, now);

        if let Some(RecoveryDeadline::Loss(_, epoch)) = deadline {
            // Time threshold loss detection.
            let (lost_packets, lost_bytes) =
                self.detect_lost_packets(epoch, now, trace_id);

            self.set_loss_detection_timer(handshake_status, now);

            trace!("{trace_id} {self:?}");
            return OnLossDetectionTimeoutOutcome {
                lost_packets,
                lost_bytes,
            };
        }

        let Some(RecoveryDeadline::Probe(_, epoch)) = deadline else {
            self.loss_timer.update(None);
            return OnLossDetectionTimeoutOutcome::default();
        };

        self.pto_count = self.pto_count.saturating_add(1);

        let probe_count = cmp::min(self.pto_count as usize, MAX_PTO_PROBES_COUNT);

        // RFC 9002 Section 6.2.4 recommends probing every other eligible
        // packet-number space that still has data in flight as well.
        for other in [Epoch::Initial, Epoch::Handshake, Epoch::Application] {
            if other == epoch || self.epochs[other].timing.in_flight_count == 0 {
                continue;
            }

            // Match the PTO deadline selector: Application data is not an
            // eligible PTO space until the handshake is complete.
            if other == Epoch::Application && !handshake_status.completed {
                continue;
            }

            self.epochs[other].loss_probes =
                cmp::max(self.epochs[other].loss_probes, probe_count);
        }

        let epoch = &mut self.epochs[epoch];

        epoch.loss_probes = probe_count;

        let sent_packets_iter_limit = if epoch.pending_lost_frames.pto_is_empty()
        {
            usize::MAX
        } else {
            // Skip the search for frames to add to PTO probes if frames
            // added in a prior PTO haven't been processed yet.
            0
        };

        let unacked_iter = epoch
            .sent_packets
            .iter()
            .take(sent_packets_iter_limit)
            // Skip packets that have already been acked or lost, and packets
            // that don't contain either CRYPTO or STREAM frames.
            .filter(|p| {
                p.flight.has_data() && p.acked_at.is_none() && p.lost_at.is_none()
            })
            // Only return as many packets as the number of probe packets that
            // will be sent.
            .take(epoch.loss_probes);

        // Retransmit the frames from the oldest sent packets on PTO. However
        // the packets are not actually declared lost (so there is no effect to
        // congestion control), we just reschedule the data they carried.
        //
        // This will also trigger sending an ACK and retransmitting frames like
        // HANDSHAKE_DONE and MAX_DATA / MAX_STREAM_DATA as well, in addition
        // to CRYPTO and STREAM, if the original packet carried them.
        for unacked in unacked_iter {
            epoch
                .pending_lost_frames
                .queue_pto(unacked.frames.iter().cloned());
        }

        self.set_loss_detection_timer(handshake_status, now);

        trace!("{trace_id} {self:?}");

        OnLossDetectionTimeoutOutcome {
            lost_packets: 0,
            lost_bytes: 0,
        }
    }

    fn on_pkt_num_space_discarded(
        &mut self, epoch: Epoch, handshake_status: HandshakeStatus, now: Instant,
    ) {
        let epoch = &mut self.epochs[epoch];

        let unacked_bytes = epoch
            .sent_packets
            .iter()
            .filter(|p| {
                p.flight.in_flight() &&
                    p.acked_at.is_none() &&
                    p.lost_at.is_none()
            })
            .fold(0, |acc, p| acc + p.size);

        self.bytes_in_flight.saturating_subtract(unacked_bytes, now);

        epoch.sent_packets.clear();
        epoch.pending_lost_frames.clear();
        epoch.acked_frames.clear();

        epoch.timing = EpochTiming::default();
        epoch.loss_probes = 0;

        self.set_loss_detection_timer(handshake_status, now);
    }

    fn on_path_change(
        &mut self, epoch: Epoch, now: Instant, trace_id: &str,
    ) -> (usize, usize) {
        // Time threshold loss detection.
        self.detect_lost_packets(epoch, now, trace_id)
    }

    fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_timer.time
    }

    fn cwnd(&self) -> usize {
        self.congestion.window()
    }

    fn cwnd_available(&self) -> usize {
        // Open more space (snd_cnt) for PRR when allowed.
        self.cwnd()
            .saturating_sub(self.bytes_in_flight.get())
            .saturating_add(self.congestion.prr.snd_cnt)
    }

    fn rtt(&self) -> Duration {
        self.rtt_stats.rtt()
    }

    fn min_rtt(&self) -> Option<Duration> {
        self.rtt_stats.min_rtt()
    }

    fn max_rtt(&self) -> Option<Duration> {
        self.rtt_stats.max_rtt()
    }

    fn rttvar(&self) -> Duration {
        self.rtt_stats.rttvar
    }

    fn pto(&self) -> Duration {
        self.rtt_stats.probe_timeout()
    }

    /// The most recent data delivery rate estimate.
    fn delivery_rate(&self) -> Bandwidth {
        self.congestion.delivery_rate()
    }

    fn max_bandwidth(&self) -> Option<Bandwidth> {
        // TODO implement
        None
    }

    fn rtt_persistent_jump_count(&self) -> u64 {
        // Persistent RTT jump counts are produced by the BBR2 RTT jump
        // detector. Legacy Reno/CUBIC recovery does not own a BBR2 network
        // model or run that detector, but it still implements
        // RecoveryOps so PathStats can be populated through one shared
        // interface. Report zero to indicate that no detector is active on
        // this path.
        0
    }

    /// Statistics from when a CCA first exited the startup phase.
    fn startup_exit(&self) -> Option<StartupExit> {
        self.congestion.ssthresh.startup_exit()
    }

    fn max_datagram_size(&self) -> usize {
        self.congestion.max_datagram_size
    }

    fn pmtud_update_max_datagram_size(&mut self, new_max_datagram_size: usize) {
        // Rescale the initial window only until congestion control has
        // made its own decision. A later return to the same byte count
        // is not the initial window.
        if self.congestion.ssthresh.startup_exit().is_none() &&
            self.cwnd() == self.congestion.send_quantum()
        {
            self.congestion.cwnd = new_max_datagram_size.saturating_mul(
                self.congestion.initial_congestion_window_packets,
            );
        }

        self.congestion.max_datagram_size = new_max_datagram_size;
    }

    fn update_max_datagram_size(&mut self, new_max_datagram_size: usize) {
        self.pmtud_update_max_datagram_size(
            self.congestion.max_datagram_size.min(new_max_datagram_size),
        );
    }

    #[cfg(test)]
    fn sent_packets_len(&self, epoch: Epoch) -> usize {
        self.epochs[epoch].sent_packets.len()
    }

    #[cfg(test)]
    fn in_flight_count(&self, epoch: Epoch) -> usize {
        self.epochs[epoch].timing.in_flight_count
    }

    fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight.get()
    }

    fn has_pending_recovery_work(&self) -> bool {
        self.epochs.iter().any(|epoch| {
            // ACK-only packets need no acknowledgment of their own, so they
            // must not prevent an otherwise idle path from being retired.
            epoch.sent_packets.iter().any(|pkt| {
                pkt.acked_at.is_none() &&
                    pkt.lost_at.is_none() &&
                    pkt.flight.ack_eliciting()
            }) || !epoch.acked_frames.is_empty() ||
                epoch.pending_lost_frames.has_pending() ||
                epoch.loss_probes != 0
        })
    }

    fn bytes_in_flight_duration(&self) -> Duration {
        self.bytes_in_flight.get_duration()
    }

    #[cfg(test)]
    fn pacing_rate(&self) -> u64 {
        0
    }

    #[cfg(test)]
    fn pto_count(&self) -> u32 {
        self.pto_count
    }

    #[cfg(test)]
    fn pkt_thresh(&self) -> Option<u64> {
        Some(self.pkt_thresh)
    }

    #[cfg(test)]
    fn time_thresh(&self) -> f64 {
        self.time_thresh
    }

    #[cfg(test)]
    fn lost_spurious_count(&self) -> usize {
        self.lost_spurious_count
    }

    #[cfg(test)]
    fn detect_lost_packets_for_test(
        &mut self, epoch: Epoch, now: Instant,
    ) -> (usize, usize) {
        self.detect_lost_packets(epoch, now, "")
    }

    // FIXME only used by gcongestion
    fn on_app_limited(&mut self) {
        // Not implemented for legacy recovery, update_app_limited and
        // delivery_rate_update_app_limited used instead.
    }

    #[cfg(test)]
    fn largest_sent_pkt_num_on_path(&self, epoch: Epoch) -> Option<u64> {
        self.epochs[epoch].test_largest_sent_pkt_num_on_path
    }

    #[cfg(any(test, feature = "qlog"))]
    fn app_limited(&self) -> bool {
        self.congestion.app_limited
    }

    fn update_app_limited(&mut self, v: bool) {
        self.congestion.update_app_limited(v);
    }

    // FIXME only used by congestion
    fn delivery_rate_update_app_limited(&mut self, v: bool) {
        self.congestion.delivery_rate.update_app_limited(v);
    }

    // FIXME only used by congestion
    fn update_max_ack_delay(&mut self, max_ack_delay: Duration) {
        self.rtt_stats.max_ack_delay = max_ack_delay;
    }

    #[cfg(feature = "qlog")]
    fn state_str(&self, now: Instant) -> &'static str {
        (self.congestion.cc_ops.state_str)(&self.congestion, now)
    }

    #[cfg(feature = "qlog")]
    fn get_updated_qlog_event_data(&mut self) -> Option<EventData> {
        let qlog_metrics = QlogMetrics {
            min_rtt: *self.rtt_stats.min_rtt,
            smoothed_rtt: self.rtt(),
            latest_rtt: self.rtt_stats.latest_rtt,
            rttvar: self.rtt_stats.rttvar,
            cwnd: self.cwnd() as u64,
            bytes_in_flight: self.bytes_in_flight.get() as u64,
            ssthresh: Some(self.congestion.ssthresh.get() as u64),
            lost_packets: Some(self.congestion.lost_count as u64),
            lost_bytes: Some(self.bytes_lost),
            pto_count: Some(crate::recovery::qlog_pto_count(self.pto_count)),
            app_limited: Some(self.app_limited()),
            ..Default::default()
        };

        self.qlog_metrics.maybe_update(&qlog_metrics)
    }

    #[cfg(feature = "qlog")]
    fn get_updated_qlog_cc_state(
        &mut self, now: Instant,
    ) -> Option<&'static str> {
        let cc_state = self.state_str(now);
        if cc_state == self.qlog_prev_cc_state {
            None
        } else {
            self.qlog_prev_cc_state = cc_state;
            Some(cc_state)
        }
    }

    fn send_quantum(&self) -> usize {
        self.congestion.send_quantum()
    }

    fn get_next_release_time(&self) -> ReleaseDecision {
        ReleaseDecision {
            time: ReleaseTime::Immediate,
            allow_burst: false,
        }
    }

    fn gcongestion_enabled(&self) -> bool {
        false
    }

    fn lost_count(&self) -> usize {
        self.congestion.lost_count
    }

    fn bytes_lost(&self) -> u64 {
        self.bytes_lost
    }
}

impl std::fmt::Debug for LegacyRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "timer={:?} ", self.loss_timer)?;
        write!(f, "latest_rtt={:?} ", self.rtt_stats.latest_rtt)?;
        write!(f, "srtt={:?} ", self.rtt_stats.smoothed_rtt)?;
        write!(f, "min_rtt={:?} ", *self.rtt_stats.min_rtt)?;
        write!(f, "rttvar={:?} ", self.rtt_stats.rttvar)?;
        write!(f, "cwnd={} ", self.cwnd())?;
        write!(f, "ssthresh={} ", self.congestion.ssthresh.get())?;
        write!(f, "bytes_in_flight={} ", self.bytes_in_flight.get())?;
        write!(f, "app_limited={} ", self.congestion.app_limited)?;
        write!(
            f,
            "congestion_recovery_start_time={:?} ",
            self.congestion.recovery_started_at
        )?;
        write!(f, "{:?} ", self.congestion.delivery_rate)?;

        if self.congestion.hystart.enabled() {
            write!(f, "hystart={:?} ", self.congestion.hystart)?;
        }

        // CC-specific debug info
        if let Some(debug_fmt) = self.congestion.cc_ops.debug_fmt {
            debug_fmt(&self.congestion, f)?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct Acked {
    pub pkt_num: u64,

    pub sent_at: Instant,

    pub size: usize,

    /// Whether the acknowledged packet contributed to bytes in flight.
    pub in_flight: bool,

    pub rtt: Duration,

    pub delivered: u64,

    pub delivered_time: Instant,

    pub first_sent_time: Instant,

    pub is_app_limited: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::HandshakeStatus;
    use std::time::Instant;

    #[rstest::rstest]
    fn legacy_pmtu_uses_live_mss(#[values("cubic", "reno")] algorithm: &str) {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config.set_cc_algorithm_name(algorithm).unwrap();
        let mut r = LegacyRecovery::new(&config);
        let initial_packets = r.congestion.initial_congestion_window_packets;

        r.pmtud_update_max_datagram_size(1450);
        assert_eq!(r.max_datagram_size(), 1450);
        assert_eq!(r.cwnd(), 1450 * initial_packets);
        assert_eq!(r.send_quantum(), r.cwnd());

        // A loss can occur even if the window subsequently equals the
        // original initial byte count. Do not rescale that learned window.
        r.congestion.ssthresh.update(r.cwnd(), false);
        let learned = r.cwnd();
        r.pmtud_update_max_datagram_size(1600);
        assert_eq!(r.max_datagram_size(), 1600);
        assert_eq!(r.cwnd(), learned);
        assert_eq!(r.send_quantum(), 1600 * initial_packets);

        r.update_max_datagram_size(1300);
        assert_eq!(r.max_datagram_size(), 1300);
        r.congestion.on_persistent_congestion();
        assert_eq!(r.cwnd(), 1300 * crate::recovery::MINIMUM_WINDOW_PACKETS);
    }

    #[test]
    fn test_high_pto_count_no_panic() {
        let config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        let recovery_config = config.recovery;
        let mut r = LegacyRecovery::new_with_config(&recovery_config);

        r.pto_count = 99999;

        #[cfg(feature = "qlog")]
        {
            let Some(EventData::QuicMetricsUpdated(initial)) =
                r.get_updated_qlog_event_data()
            else {
                panic!("expected initial recovery metrics");
            };
            assert_eq!(initial.pto_count, Some(u16::MAX));
            r.pto_count = u32::MAX;
            assert!(r.get_updated_qlog_event_data().is_none());
            r.pto_count = 0;
            let Some(EventData::QuicMetricsUpdated(reset)) =
                r.get_updated_qlog_event_data()
            else {
                panic!("expected PTO reset");
            };
            assert_eq!(reset.pto_count, Some(0));
            r.pto_count = 99999;
        }

        let handshake_status = HandshakeStatus {
            completed: true,
            has_handshake_keys: true,
            peer_verified_address: false,
        };
        let now = Instant::now();

        let _ = r.deadline(handshake_status, now);
    }
}
