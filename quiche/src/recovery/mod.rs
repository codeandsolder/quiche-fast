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

use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

use crate::frame;
use crate::packet;
use crate::ranges::RangeSet;
pub use crate::recovery::bandwidth::Bandwidth;
#[cfg(test)]
use crate::Config;
use crate::Error;
use crate::Result;

#[cfg(feature = "qlog")]
use qlog::events::EventData;

use smallvec::SmallVec;

use self::congestion::recovery::LegacyRecovery;
use self::gcongestion::GRecovery;
pub use gcongestion::BbrAckCompensation;
pub use gcongestion::BbrBwLoReductionStrategy;
pub use gcongestion::BbrParams;
#[cfg(feature = "internal")]
pub use gcongestion::BbrRttJumpDetector;

// Loss Recovery
const INITIAL_PACKET_THRESHOLD: u64 = 3;

const MAX_PACKET_THRESHOLD: u64 = 20;

/// The packet reordering distance of the first newly acknowledged packet
/// that recovery previously declared lost. Locally skipped packet numbers
/// cannot contribute to the peer's observed reordering distance.
fn spurious_packet_threshold(
    largest_acked: u64, packet_num: u64, skipped_packet_numbers: &[u64],
) -> u64 {
    let skipped_between = skipped_packet_numbers
        .iter()
        .filter(|&&pn| pn > packet_num && pn <= largest_acked)
        .count();
    let skipped_between = u64::try_from(skipped_between).unwrap_or(u64::MAX);
    largest_acked
        .saturating_sub(packet_num)
        .saturating_sub(skipped_between)
        .saturating_add(1)
}

// Time threshold used to calculate the loss time.
//
// https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2
const INITIAL_TIME_THRESHOLD: f64 = 9.0 / 8.0;

// Reduce the sensitivity to packet reordering after the first reordering event.
//
// Packet reorder is not a real loss event so quickly reduce the sensitivity to
// avoid penializing subsequent packet reordering.
//
// https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2
//
// Implementations MAY experiment with absolute thresholds, thresholds from
// previous connections, adaptive thresholds, or the including of RTT variation.
// Smaller thresholds reduce reordering resilience and increase spurious
// retransmissions, and larger thresholds increase loss detection delay.
const PACKET_REORDER_TIME_THRESHOLD: f64 = 5.0 / 4.0;

// # Experiment: enable_relaxed_loss_threshold
//
// Time threshold overhead used to calculate the loss time.
//
// The actual threshold is calcualted as 1 + INITIAL_TIME_THRESHOLD_OVERHEAD and
// equivalent to INITIAL_TIME_THRESHOLD.
const INITIAL_TIME_THRESHOLD_OVERHEAD: f64 = 1.0 / 8.0;
// # Experiment: enable_relaxed_loss_threshold
//
// The factor by which to increase the time threshold on spurious loss.
const TIME_THRESHOLD_OVERHEAD_MULTIPLIER: f64 = 2.0;

const GRANULARITY: Duration = Duration::from_millis(1);

const MAX_PTO_PROBES_COUNT: usize = 2;

const MINIMUM_WINDOW_PACKETS: usize = 2;

// https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6.1
const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

// How many non ACK eliciting packets we send before including a PING to solicit
// an ACK.
pub const MAX_OUTSTANDING_NON_ACK_ELICITING: usize = 24;

/// A deadline always identifies a concrete packet number space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryDeadline {
    Loss(Instant, packet::Epoch),
    Probe(Instant, packet::Epoch),
}

impl RecoveryDeadline {
    const fn time(self) -> Instant {
        match self {
            Self::Loss(time, _) | Self::Probe(time, _) => time,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct EpochTiming {
    /// Earliest time at which a packet can be declared lost.
    loss: Option<Instant>,
    /// Most recent ack-eliciting send time.
    last_ack_eliciting: Option<Instant>,
    in_flight_count: usize,
}

/// RFC 9002: loss-time deadlines take priority over PTO, and a missing
/// deadline must never compete with a real deadline.
fn recovery_deadline(
    handshake: HandshakeStatus, now: Instant, no_in_flight: bool,
    rtt: &rtt::RttStats, pto_count: u32,
    timing: impl Fn(packet::Epoch) -> EpochTiming,
) -> Option<RecoveryDeadline> {
    let epochs = [
        packet::Epoch::Initial,
        packet::Epoch::Handshake,
        packet::Epoch::Application,
    ];
    if let Some((time, epoch)) = epochs
        .into_iter()
        .filter_map(|epoch| timing(epoch).loss.map(|time| (time, epoch)))
        .min_by_key(|&(time, _)| time)
    {
        return Some(RecoveryDeadline::Loss(time, epoch));
    }

    let backoff = 2_u32.saturating_pow(pto_count);
    let duration = rtt.probe_timeout().saturating_mul(backoff);

    if no_in_flight {
        if handshake.peer_verified_address {
            return None;
        }
        let epoch = if handshake.has_handshake_keys {
            packet::Epoch::Handshake
        } else {
            packet::Epoch::Initial
        };
        return now
            .checked_add(duration)
            .map(|time| RecoveryDeadline::Probe(time, epoch));
    }

    epochs
        .into_iter()
        .filter_map(|epoch| {
            let space = timing(epoch);
            if space.in_flight_count == 0 ||
                (epoch == packet::Epoch::Application && !handshake.completed)
            {
                return None;
            }
            let duration = if epoch == packet::Epoch::Application {
                duration.saturating_add(rtt.max_ack_delay.saturating_mul(backoff))
            } else {
                duration
            };
            let time = space.last_ack_eliciting?.checked_add(duration)?;
            Some(RecoveryDeadline::Probe(time, epoch))
        })
        .min_by_key(|deadline| deadline.time())
}

#[derive(Default)]
struct LossDetectionTimer {
    time: Option<Instant>,
}

impl LossDetectionTimer {
    fn update(&mut self, deadline: Option<RecoveryDeadline>) {
        self.time = deadline.map(RecoveryDeadline::time);
    }
}

impl std::fmt::Debug for LossDetectionTimer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.time {
            Some(v) => {
                let now = Instant::now();
                if v > now {
                    let d = v.duration_since(now);
                    write!(f, "{d:?}")
                } else {
                    write!(f, "exp")
                }
            },
            None => write!(f, "none"),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct RecoveryConfig {
    pub initial_rtt: Duration,
    pub max_send_udp_payload_size: usize,
    pub max_ack_delay: Duration,
    pub cc_algorithm: CongestionControlAlgorithm,
    pub custom_bbr_params: Option<BbrParams>,
    pub hystart: bool,
    pub pacing: bool,
    pub max_pacing_rate: Option<u64>,
    pub initial_congestion_window_packets: usize,
    pub enable_relaxed_loss_threshold: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            initial_rtt: crate::DEFAULT_INITIAL_RTT,
            max_send_udp_payload_size: crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE,
            // Peer delay is not known until transport parameters are received.
            max_ack_delay: Duration::ZERO,
            cc_algorithm: CongestionControlAlgorithm::Cubic,
            custom_bbr_params: None,
            hystart: true,
            pacing: true,
            max_pacing_rate: None,
            initial_congestion_window_packets:
                crate::DEFAULT_INITIAL_CONGESTION_WINDOW_PACKETS,
            enable_relaxed_loss_threshold: false,
        }
    }
}

#[enum_dispatch::enum_dispatch(RecoveryOps)]
#[expect(
    clippy::large_enum_variant,
    reason = "Boxing the large variant would add unnecessary indirection"
)]
#[derive(Debug)]
pub enum Recovery {
    Legacy(LegacyRecovery),
    GCongestion(GRecovery),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct OnAckReceivedOutcome {
    pub lost_packets: usize,
    pub lost_bytes: usize,
    pub acked_bytes: usize,
    pub spurious_losses: usize,
}

/// Validates the complete ACK before any recovery state is changed.
pub fn validate_ack_ranges(
    ranges: &RangeSet, skip_pn: Option<u64>,
) -> Result<u64> {
    let largest = ranges.last().ok_or(Error::InvalidAckRange)?;
    if skip_pn.is_some_and(|pn| ranges.contains(pn)) {
        return Err(Error::OptimisticAckDetected);
    }
    Ok(largest)
}

#[derive(Debug, Default)]
pub struct OnLossDetectionTimeoutOutcome {
    pub lost_packets: usize,
    pub lost_bytes: usize,
}

#[enum_dispatch::enum_dispatch]
#[expect(
    clippy::too_many_arguments,
    reason = "RecoveryOps has one protocol-state transition whose established signature carries the QUIC ACK inputs explicitly"
)]
/// Api for the Recovery implementation
pub trait RecoveryOps {
    fn lost_count(&self) -> usize;
    fn bytes_lost(&self) -> u64;

    /// Returns whether or not we should elicit an ACK even if we wouldn't
    /// otherwise have constructed an ACK eliciting packet.
    fn should_elicit_ack(&self, epoch: packet::Epoch) -> bool;

    fn next_acked_frame(&mut self, epoch: packet::Epoch) -> Option<frame::Frame>;

    fn next_lost_frame(&mut self, epoch: packet::Epoch) -> Option<frame::Frame>;

    #[cfg(test)]
    fn get_largest_acked_on_epoch(&self, epoch: packet::Epoch) -> Option<u64>;
    fn has_lost_frames(&self, epoch: packet::Epoch) -> bool;
    fn loss_probes(&self, epoch: packet::Epoch) -> usize;
    #[cfg(test)]
    fn inc_loss_probes(&mut self, epoch: packet::Epoch);
    #[cfg(test)]
    fn lost_frames_count(&self, epoch: packet::Epoch) -> usize;

    fn ping_sent(&mut self, epoch: packet::Epoch);

    fn on_packet_sent(
        &mut self, pkt: Sent, epoch: packet::Epoch,
        handshake_status: HandshakeStatus, now: Instant, trace_id: &str,
    );
    /// Records a connection-global packet number intentionally skipped by the
    /// sender for optimistic-ACK detection.
    fn on_packet_number_skipped(&mut self, pkt_num: u64);
    fn get_packet_send_time(&self, now: Instant) -> Instant;
    fn on_ack_received(
        &mut self, ranges: &RangeSet, ack_delay: u64, epoch: packet::Epoch,
        handshake_status: HandshakeStatus, now: Instant, skip_pn: Option<u64>,
        trace_id: &str,
    ) -> Result<OnAckReceivedOutcome>;

    fn on_loss_detection_timeout(
        &mut self, handshake_status: HandshakeStatus, now: Instant,
        trace_id: &str,
    ) -> OnLossDetectionTimeoutOutcome;
    fn on_pkt_num_space_discarded(
        &mut self, epoch: packet::Epoch, handshake_status: HandshakeStatus,
        now: Instant,
    );
    fn on_path_change(
        &mut self, epoch: packet::Epoch, now: Instant, _trace_id: &str,
    ) -> (usize, usize);
    fn loss_detection_timer(&self) -> Option<Instant>;
    fn cwnd(&self) -> usize;
    fn cwnd_available(&self) -> usize;
    fn rtt(&self) -> Duration;

    fn min_rtt(&self) -> Option<Duration>;

    fn max_rtt(&self) -> Option<Duration>;

    fn rttvar(&self) -> Duration;

    fn pto(&self) -> Duration;

    /// The most recent data delivery rate estimate.
    fn delivery_rate(&self) -> Bandwidth;

    /// Maximum bandwidth estimate, if one is available.
    fn max_bandwidth(&self) -> Option<Bandwidth>;

    /// Total number of confirmed persistent RTT jump episodes.
    fn rtt_persistent_jump_count(&self) -> u64;

    /// Statistics from when a CCA first exited the startup phase.
    fn startup_exit(&self) -> Option<StartupExit>;

    fn max_datagram_size(&self) -> usize;

    fn pmtud_update_max_datagram_size(&mut self, new_max_datagram_size: usize);

    fn update_max_datagram_size(&mut self, new_max_datagram_size: usize);

    fn on_app_limited(&mut self);

    // Since a recovery module is path specific, this tracks the largest packet
    // sent per path.
    #[cfg(test)]
    fn largest_sent_pkt_num_on_path(&self, epoch: packet::Epoch) -> Option<u64>;

    #[cfg(any(test, feature = "qlog"))]
    fn app_limited(&self) -> bool;

    #[cfg(test)]
    fn sent_packets_len(&self, epoch: packet::Epoch) -> usize;

    fn bytes_in_flight(&self) -> usize;

    /// Whether retiring a path would discard retransmittable packets, ACK
    /// processing, lost/PTO frames, or pending loss probes. This is stronger
    /// than a nonzero congestion-control bytes-in-flight count: packets can
    /// already be declared lost while their frames still need retransmission.
    fn has_pending_recovery_work(&self) -> bool;

    fn bytes_in_flight_duration(&self) -> Duration;

    #[cfg(test)]
    fn in_flight_count(&self, epoch: packet::Epoch) -> usize;

    #[cfg(test)]
    fn pacing_rate(&self) -> u64;

    #[cfg(test)]
    fn pto_count(&self) -> u32;

    // This value might be `None` when the `enable_relaxed_loss_threshold`
    // experiment is enabled for gcongestion.
    #[cfg(test)]
    fn pkt_thresh(&self) -> Option<u64>;

    #[cfg(test)]
    fn time_thresh(&self) -> f64;

    #[cfg(test)]
    fn lost_spurious_count(&self) -> usize;

    #[cfg(test)]
    fn detect_lost_packets_for_test(
        &mut self, epoch: packet::Epoch, now: Instant,
    ) -> (usize, usize);

    fn update_app_limited(&mut self, v: bool);

    fn delivery_rate_update_app_limited(&mut self, v: bool);

    fn update_max_ack_delay(&mut self, max_ack_delay: Duration);

    #[cfg(feature = "qlog")]
    fn state_str(&self, now: Instant) -> &'static str;

    #[cfg(feature = "qlog")]
    fn get_updated_qlog_event_data(&mut self) -> Option<EventData>;

    #[cfg(feature = "qlog")]
    fn get_updated_qlog_cc_state(&mut self, now: Instant)
        -> Option<&'static str>;

    fn send_quantum(&self) -> usize;

    fn get_next_release_time(&self) -> ReleaseDecision;

    fn gcongestion_enabled(&self) -> bool;
}

impl Recovery {
    pub fn new_with_config(recovery_config: &RecoveryConfig) -> Self {
        GRecovery::new(recovery_config).map_or_else(
            || Self::from(LegacyRecovery::new_with_config(recovery_config)),
            Self::from,
        )
    }

    #[cfg(feature = "qlog")]
    pub fn maybe_qlog(
        &mut self, qlog: &mut qlog::streamer::QlogStreamer, now: Instant,
    ) {
        if let Some(ev_data) = self.get_updated_qlog_event_data() {
            qlog.add_event_data_with_instant(ev_data, now).ok();
        }

        if let Some(cc_state) = self.get_updated_qlog_cc_state(now) {
            let ev_data = EventData::QuicCongestionStateUpdated(
                qlog::events::quic::CongestionStateUpdated {
                    old: None,
                    new: cc_state.to_string(),
                    trigger: None,
                },
            );

            qlog.add_event_data_with_instant(ev_data, now).ok();
        }
    }

    #[cfg(test)]
    pub fn new(config: &Config) -> Self {
        Self::new_with_config(&config.recovery)
    }
}

/// Available congestion control algorithms.
///
/// This enum provides currently available list of congestion control
/// algorithms.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum CongestionControlAlgorithm {
    /// Reno congestion control algorithm. `reno` in a string form.
    Reno            = 0,
    /// CUBIC congestion control algorithm (default). `cubic` in a string form.
    Cubic           = 1,
    /// `BBRv2` congestion control algorithm implementation from gcongestion
    /// branch. `bbr2_gcongestion` in a string form.
    Bbr2Gcongestion = 4,
}

impl FromStr for CongestionControlAlgorithm {
    type Err = Error;

    /// Converts a string to `CongestionControlAlgorithm`.
    ///
    /// If `name` is not valid, `Error::CongestionControl` is returned.
    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        match name {
            "reno" => Ok(Self::Reno),
            "cubic" => Ok(Self::Cubic),
            "bbr" | "bbr2" | "bbr2_gcongestion" => Ok(Self::Bbr2Gcongestion),
            _ => Err(Error::CongestionControl),
        }
    }
}

/// Packet classification shared by the packet writer and both recovery
/// engines. ACK-only packets are not in flight; padding-only packets are in
/// flight without eliciting ACKs. Data and dedicated PMTU probes are distinct
/// kinds of ack-eliciting packet, with different recovery policies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PacketFlight {
    #[default]
    NotInFlight,
    PaddingInFlight,
    AckEliciting,
    Data,
    PmtuProbe,
}

impl PacketFlight {
    #[must_use = "the result controls congestion-window accounting"]
    pub const fn in_flight(self) -> bool {
        !matches!(self, Self::NotInFlight)
    }

    #[must_use = "the result determines whether acknowledgement and loss recovery are required"]
    pub const fn ack_eliciting(self) -> bool {
        matches!(self, Self::AckEliciting | Self::Data | Self::PmtuProbe)
    }

    #[must_use = "the result distinguishes data-bearing packets for congestion accounting"]
    pub const fn has_data(self) -> bool {
        matches!(self, Self::Data)
    }

    #[must_use = "the result selects path MTU probe accounting"]
    pub const fn is_pmtud_probe(self) -> bool {
        matches!(self, Self::PmtuProbe)
    }

    pub(crate) const fn record_padding(&mut self) {
        if !self.in_flight() {
            *self = Self::PaddingInFlight;
        }
    }

    pub(crate) const fn record_ack_eliciting(&mut self) {
        if !self.ack_eliciting() {
            *self = Self::AckEliciting;
        }
    }
}

#[derive(Clone)]
pub struct Sent {
    pub pkt_num: u64,

    pub frames: SmallVec<[frame::Frame; 1]>,

    pub transmitted_at: Instant,

    pub acked_at: Option<Instant>,

    pub lost_at: Option<Instant>,

    pub size: usize,

    pub flight: PacketFlight,

    pub delivered: u64,

    pub delivered_time: Instant,

    pub first_sent_time: Instant,

    pub is_app_limited: bool,

    pub tx_in_flight: usize,

    pub lost: u64,
}

impl std::fmt::Debug for Sent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "pkt_num={:?} ", self.pkt_num)?;
        write!(f, "pkt_sent_time={:?} ", self.transmitted_at)?;
        write!(f, "pkt_size={:?} ", self.size)?;
        write!(f, "delivered={:?} ", self.delivered)?;
        write!(f, "delivered_time={:?} ", self.delivered_time)?;
        write!(f, "first_sent_time={:?} ", self.first_sent_time)?;
        write!(f, "is_app_limited={} ", self.is_app_limited)?;
        write!(f, "tx_in_flight={} ", self.tx_in_flight)?;
        write!(f, "lost={} ", self.lost)?;
        write!(f, "has_data={} ", self.flight.has_data())?;
        write!(f, "is_pmtud_probe={}", self.flight.is_pmtud_probe())?;

        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HandshakeStatus {
    pub has_handshake_keys: bool,

    pub peer_verified_address: bool,

    pub completed: bool,
}

#[cfg(test)]
impl Default for HandshakeStatus {
    fn default() -> Self {
        Self {
            has_handshake_keys: true,

            peer_verified_address: true,

            completed: true,
        }
    }
}

// We don't need to log all qlog metrics every time there is a recovery event.
// Instead, we can log only the MetricsUpdated event data fields that we care
// about, only when they change. To support this, the QLogMetrics structure
// keeps a running picture of the fields.
#[derive(Default)]
#[cfg(feature = "qlog")]
struct QlogMetrics {
    min_rtt: Duration,
    smoothed_rtt: Duration,
    latest_rtt: Duration,
    rttvar: Duration,
    cwnd: u64,
    bytes_in_flight: u64,
    ssthresh: Option<u64>,
    pacing_rate: Option<u64>,
    delivery_rate: Option<u64>,
    send_rate: Option<u64>,
    ack_rate: Option<u64>,
    lost_packets: Option<u64>,
    lost_bytes: Option<u64>,
    pto_count: Option<u16>,
    app_limited: Option<bool>,
}

// Delta events contain observations, not a nullable complete snapshot.
// Missing optional values must not cause empty events or forget a baseline.
#[cfg(feature = "qlog")]
fn changed<T: Copy + PartialEq>(previous: &mut T, value: T) -> Option<T> {
    if *previous == value {
        return None;
    }
    *previous = value;
    Some(value)
}

#[cfg(feature = "qlog")]
fn observed<T: Copy + PartialEq>(
    previous: &mut Option<T>, value: Option<T>,
) -> Option<T> {
    changed(previous, Some(value?)).flatten()
}

#[cfg(feature = "qlog")]
impl QlogMetrics {
    fn maybe_update(&mut self, latest: &Self) -> Option<EventData> {
        let mut metrics = qlog::events::quic::RecoveryMetricsUpdated {
            min_rtt: changed(&mut self.min_rtt, latest.min_rtt)
                .map(duration_millis_f32),
            smoothed_rtt: changed(&mut self.smoothed_rtt, latest.smoothed_rtt)
                .map(duration_millis_f32),
            latest_rtt: changed(&mut self.latest_rtt, latest.latest_rtt)
                .map(duration_millis_f32),
            rtt_variance: changed(&mut self.rttvar, latest.rttvar)
                .map(duration_millis_f32),
            congestion_window: changed(&mut self.cwnd, latest.cwnd),
            bytes_in_flight: changed(
                &mut self.bytes_in_flight,
                latest.bytes_in_flight,
            ),
            ssthresh: observed(&mut self.ssthresh, latest.ssthresh),
            pacing_rate: observed(&mut self.pacing_rate, latest.pacing_rate),
            pto_count: observed(&mut self.pto_count, latest.pto_count),
            ..Default::default()
        };

        if let Some(app_limited) =
            observed(&mut self.app_limited, latest.app_limited)
        {
            metrics
                .ex_data
                .insert("cf_app_limited".into(), app_limited.into());
        }

        for (name, previous, value) in [
            (
                "cf_delivery_rate",
                &mut self.delivery_rate,
                latest.delivery_rate,
            ),
            ("cf_send_rate", &mut self.send_rate, latest.send_rate),
            ("cf_ack_rate", &mut self.ack_rate, latest.ack_rate),
        ] {
            if let Some(rate) = observed(previous, value) {
                metrics.ex_data.insert(name.into(), rate.into());
            }
        }

        for (name, previous, value) in [
            (
                "cf_lost_packets",
                &mut self.lost_packets,
                latest.lost_packets,
            ),
            ("cf_lost_bytes", &mut self.lost_bytes, latest.lost_bytes),
        ] {
            let baseline = previous.unwrap_or(0);
            if let Some(total) = observed(previous, value) {
                // If a counter resets, its new total is the first delta in
                // the new counter generation, not an unsigned underflow.
                let delta = total.checked_sub(baseline).unwrap_or(total);
                metrics.ex_data.insert(
                    name.into(),
                    serde_json::json!({
                        "total": total,
                        "delta": delta,
                    }),
                );
            }
        }

        if metrics == qlog::events::quic::RecoveryMetricsUpdated::default() {
            None
        } else {
            Some(EventData::QuicMetricsUpdated(metrics))
        }
    }
}

/// The standard qlog PTO counter has type `uint16` even though recovery
/// tracks the count at `u32` width. Saturate rather than wrap.
#[cfg(feature = "qlog")]
fn qlog_pto_count(count: u32) -> u16 {
    u16::try_from(count).unwrap_or(u16::MAX)
}

#[cfg(feature = "qlog")]
fn duration_millis_f32(duration: Duration) -> f32 {
    duration.as_secs_f32() * 1000.0
}

/// When the pacer thinks is a good time to release the next packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseTime {
    Immediate,
    At(Instant),
}

/// When the next packet should be release and if it can be part of a burst
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseDecision {
    time: ReleaseTime,
    allow_burst: bool,
}

impl ReleaseTime {
    /// Add the specific delay to the current time
    fn inc(&mut self, delay: Duration) {
        match self {
            Self::Immediate => {},
            Self::At(time) => *time += delay,
        }
    }

    /// Set the time to the later of two times
    fn set_max(&mut self, other: Instant) {
        match self {
            Self::Immediate => *self = Self::At(other),
            Self::At(time) => *self = Self::At(other.max(*time)),
        }
    }
}

impl ReleaseDecision {
    pub(crate) const EQUAL_THRESHOLD: Duration = Duration::from_micros(50);

    /// Get the [`Instant`] the next packet should be released. It will never be
    /// in the past.
    #[inline]
    pub fn time(&self, now: Instant) -> Option<Instant> {
        match self.time {
            ReleaseTime::Immediate => None,
            ReleaseTime::At(other) => other.gt(&now).then_some(other),
        }
    }

    /// Can this packet be appended to a previous burst
    #[inline]
    pub const fn can_burst(&self) -> bool {
        self.allow_burst
    }

    /// Check if the two packets can be released at the same time
    #[inline]
    pub fn time_eq(&self, other: &Self, now: Instant) -> bool {
        let delta = match (self.time(now), other.time(now)) {
            (None, None) => Duration::ZERO,
            (Some(t), None) | (None, Some(t)) => t.duration_since(now),
            (Some(t1), Some(t2)) if t1 < t2 => t2.duration_since(t1),
            (Some(t1), Some(t2)) => t1.duration_since(t2),
        };

        delta <= Self::EQUAL_THRESHOLD
    }
}

/// Recovery statistics
#[derive(Default, Debug)]
pub struct RecoveryStats {
    startup_exit: Option<StartupExit>,
}

impl RecoveryStats {
    // Record statistics when a CCA first exits startup.
    pub const fn set_startup_exit(&mut self, startup_exit: StartupExit) {
        if self.startup_exit.is_none() {
            self.startup_exit = Some(startup_exit);
        }
    }
}

/// Statistics from when a CCA first exited the startup phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupExit {
    /// The `congestion_window` recorded at Startup exit.
    pub cwnd: usize,

    /// The bandwidth estimate recorded at Startup exit.
    pub bandwidth: Option<u64>,

    /// The reason a CCA exited the startup phase.
    pub reason: StartupExitReason,
}

impl StartupExit {
    fn new(
        cwnd: usize, bandwidth: Option<Bandwidth>, reason: StartupExitReason,
    ) -> Self {
        let bandwidth = bandwidth.map(Bandwidth::to_bytes_per_second);
        Self {
            cwnd,
            bandwidth,
            reason,
        }
    }
}

/// The reason a CCA exited the startup phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupExitReason {
    /// Exit slow start or BBR startup due to excessive loss
    Loss,

    /// Exit BBR startup due to bandwidth plateau.
    BandwidthPlateau,

    /// Exit BBR startup due to persistent queue.
    PersistentQueue,

    /// Exit `HyStart`++ conservative slow start after the max rounds allowed.
    ConservativeSlowStartRounds,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame;
    use crate::packet;
    use crate::range_buf::RangeBuf;
    use crate::test_utils;
    use crate::CongestionControlAlgorithm;
    use crate::DEFAULT_INITIAL_RTT;
    use rstest::rstest;
    use smallvec::smallvec;
    use std::str::FromStr;

    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn recovery_config(cc_algorithm_name: &str) -> Result<Config> {
        let mut cfg = Config::new(crate::PROTOCOL_VERSION)?;
        cfg.set_cc_algorithm_name(cc_algorithm_name)?;
        Ok(cfg)
    }

    #[test]
    fn spurious_packet_threshold_excludes_local_gaps() {
        assert_eq!(spurious_packet_threshold(9, 3, &[2, 4, 7, 10]), 5);
        assert_eq!(spurious_packet_threshold(9, 3, &[]), 7);
        assert_eq!(spurious_packet_threshold(u64::MAX, 0, &[]), u64::MAX);
    }

    /// Sender-induced packet-number gaps are not reordering. The gap must
    /// remain excluded from packet-threshold distance even after a higher ACK
    /// has validated it and the optimistic-ACK marker itself is cleared.
    #[test]
    fn packet_flight_classification_preserves_probe_and_data_purpose() {
        for (mut flight, in_flight, eliciting, data, probe) in [
            (PacketFlight::NotInFlight, false, false, false, false),
            (PacketFlight::PaddingInFlight, true, false, false, false),
            (PacketFlight::AckEliciting, true, true, false, false),
            (PacketFlight::Data, true, true, true, false),
            (PacketFlight::PmtuProbe, true, true, false, true),
        ] {
            assert_eq!(flight.in_flight(), in_flight);
            assert_eq!(flight.ack_eliciting(), eliciting);
            assert_eq!(flight.has_data(), data);
            assert_eq!(flight.is_pmtud_probe(), probe);
            flight.record_padding();
            assert!(flight.in_flight());
            assert_eq!(flight.ack_eliciting(), eliciting);
            flight.record_ack_eliciting();
            assert!(flight.ack_eliciting());
            assert_eq!(flight.has_data(), data);
            assert_eq!(flight.is_pmtud_probe(), probe);
        }
    }

    #[rstest]
    fn sender_gap_does_not_shorten_packet_threshold(
        #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;

        let now = Instant::now();
        let mut r = Recovery::new(&cfg);
        let hs = HandshakeStatus::default();

        // PN 2 is deliberately skipped.
        r.on_packet_number_skipped(2);
        for pkt_num in [0, 1, 3] {
            r.on_packet_sent(
                test_utils::helper_packet_sent(pkt_num, now, 1000),
                packet::Epoch::Application,
                hs,
                now,
                "",
            );
        }

        let mut acked = RangeSet::default();
        acked.insert(3..4);
        let outcome = r.on_ack_received(
            &acked,
            25,
            packet::Epoch::Application,
            hs,
            now,
            Some(2),
            "",
        )?;
        assert_eq!(outcome.lost_packets, 0);

        // In the real connection layer ACK 3 now validates skipped PN 2 and
        // clears the marker. ACK 4 therefore arrives with skip_pn=None.
        r.on_packet_sent(
            test_utils::helper_packet_sent(4, now, 1000),
            packet::Epoch::Application,
            hs,
            now,
            "",
        );
        let mut acked = RangeSet::default();
        acked.insert(3..5);
        let outcome = r.on_ack_received(
            &acked,
            25,
            packet::Epoch::Application,
            hs,
            now,
            None,
            "",
        )?;

        // Three packets (1,3,4) were actually sent after PN 0, but only two
        // (3,4) after PN 1. Only PN 0 has crossed the threshold.
        assert_eq!(outcome.lost_packets, 1);

        r.on_packet_sent(
            test_utils::helper_packet_sent(5, now, 1000),
            packet::Epoch::Application,
            hs,
            now,
            "",
        );
        let mut acked = RangeSet::default();
        acked.insert(3..6);
        let outcome = r.on_ack_received(
            &acked,
            25,
            packet::Epoch::Application,
            hs,
            now,
            None,
            "",
        )?;

        // PN 1 now has three actually-sent packets after it: 3, 4 and 5.
        assert_eq!(outcome.lost_packets, 1);
        Ok(())
    }

    fn recovery_for_alg(
        algo: CongestionControlAlgorithm,
    ) -> TestResult<Recovery> {
        let mut cfg = Config::new(crate::PROTOCOL_VERSION)?;
        cfg.set_cc_algorithm(algo);
        Ok(Recovery::new(&cfg))
    }

    #[cfg(feature = "qlog")]
    fn app_limited_value(
        event: EventData,
    ) -> TestResult<Option<serde_json::Value>> {
        let EventData::QuicMetricsUpdated(metrics) = event else {
            return Err("expected recovery metrics updated event".into());
        };

        Ok(metrics.ex_data.get("cf_app_limited").cloned())
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn qlog_app_limited_emits_initial_false_and_transitions() -> TestResult {
        let mut metrics = QlogMetrics::default();

        let event = metrics
            .maybe_update(&QlogMetrics {
                app_limited: Some(false),
                ..Default::default()
            })
            .ok_or("expected changed recovery metrics")?;
        assert_eq!(app_limited_value(event)?, Some(false.into()));

        let event = metrics
            .maybe_update(&QlogMetrics {
                app_limited: Some(true),
                ..Default::default()
            })
            .ok_or("expected changed recovery metrics")?;
        assert_eq!(app_limited_value(event)?, Some(true.into()));

        let event = metrics
            .maybe_update(&QlogMetrics {
                app_limited: Some(false),
                ..Default::default()
            })
            .ok_or("expected changed recovery metrics")?;
        assert_eq!(app_limited_value(event)?, Some(false.into()));
        Ok(())
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn qlog_app_limited_suppresses_unchanged_values() -> TestResult {
        let mut metrics = QlogMetrics::default();
        metrics
            .maybe_update(&QlogMetrics {
                app_limited: Some(false),
                ..Default::default()
            })
            .ok_or("expected changed recovery metrics")?;

        assert!(metrics
            .maybe_update(&QlogMetrics {
                app_limited: Some(false),
                ..Default::default()
            })
            .is_none());

        let event = metrics
            .maybe_update(&QlogMetrics {
                cwnd: 1,
                app_limited: Some(false),
                ..Default::default()
            })
            .ok_or("expected changed recovery metrics")?;
        assert_eq!(app_limited_value(event)?, None);
        Ok(())
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn qlog_observations_do_not_emit_empty_events_or_forget_baselines() {
        let mut metrics = QlogMetrics::default();
        let latest = QlogMetrics {
            pacing_rate: Some(800),
            ssthresh: Some(12_000),
            pto_count: Some(0),
            ..Default::default()
        };
        assert!(metrics.maybe_update(&latest).is_some());
        assert!(metrics.maybe_update(&QlogMetrics::default()).is_none());
        assert!(metrics.maybe_update(&latest).is_none());
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn qlog_counter_deltas_survive_missing_observations_and_reset() -> TestResult
    {
        let mut metrics = QlogMetrics::default();
        for (total, expected_delta) in [(5, 5), (9, 4), (2, 2), (3, 1)] {
            let event = metrics
                .maybe_update(&QlogMetrics {
                    lost_bytes: Some(total),
                    lost_packets: Some(total),
                    ..Default::default()
                })
                .ok_or("expected changed recovery metrics")?;
            let EventData::QuicMetricsUpdated(event) = event else {
                return Err("expected recovery metrics".into());
            };
            let expected =
                serde_json::json!({"total": total, "delta": expected_delta});
            assert_eq!(event.ex_data.get("cf_lost_bytes"), Some(&expected));
            assert_eq!(event.ex_data.get("cf_lost_packets"), Some(&expected));
            assert!(metrics.maybe_update(&QlogMetrics::default()).is_none());
        }
        Ok(())
    }

    #[cfg(feature = "qlog")]
    #[test]
    fn qlog_pto_count_saturates_at_schema_width() {
        for count in [0, 1, 65_534, 65_535, 65_536, u32::MAX] {
            assert_eq!(
                u32::from(qlog_pto_count(count)),
                count.min(u32::from(u16::MAX))
            );
        }
    }

    #[test]
    fn lookup_cc_algo_ok() -> TestResult {
        for (name, expected, gcongestion) in [
            ("reno", CongestionControlAlgorithm::Reno, false),
            ("cubic", CongestionControlAlgorithm::Cubic, false),
            ("bbr", CongestionControlAlgorithm::Bbr2Gcongestion, true),
            ("bbr2", CongestionControlAlgorithm::Bbr2Gcongestion, true),
            (
                "bbr2_gcongestion",
                CongestionControlAlgorithm::Bbr2Gcongestion,
                true,
            ),
        ] {
            let algo = CongestionControlAlgorithm::from_str(name)?;
            assert_eq!(algo, expected);
            assert_eq!(
                recovery_for_alg(algo)?.gcongestion_enabled(),
                gcongestion
            );
        }
        Ok(())
    }

    #[test]
    fn lookup_cc_algo_bad() {
        assert_eq!(
            CongestionControlAlgorithm::from_str("???"),
            Err(Error::CongestionControl)
        );
    }

    fn sent_fixture(
        pn: u64, now: Instant, size: usize, flight: PacketFlight,
    ) -> Sent {
        Sent {
            flight,
            ..test_utils::helper_packet_sent(pn, now, size)
        }
    }

    /// Identical initial send/flight observations for both timer scenarios.
    fn recovery_with_four_sent_packets(
        cc_algorithm_name: &str, now: Instant,
    ) -> TestResult<Recovery> {
        let cfg = recovery_config(cc_algorithm_name)?;
        let mut r = Recovery::new(&cfg);
        let epoch = packet::Epoch::Application;
        assert_eq!(r.sent_packets_len(epoch), 0);
        for pn in 0..4 {
            r.on_packet_sent(
                sent_fixture(pn, now, 1000, PacketFlight::AckEliciting),
                epoch,
                HandshakeStatus::default(),
                now,
                "",
            );
            assert_eq!(r.sent_packets_len(epoch), usize::try_from(pn)? + 1);
            assert_eq!(r.bytes_in_flight(), (usize::try_from(pn)? + 1) * 1000);
            assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);
        }
        Ok(r)
    }

    #[rstest]
    fn loss_on_pto(
        #[values("reno", "cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let mut now = Instant::now();
        let mut r = recovery_with_four_sent_packets(cc_algorithm_name, now)?;

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // Only the first 2 packets are acked.
        let mut acked = RangeSet::default();
        acked.insert(0..2);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 2 * 1000,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 2000);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(10));
        assert_eq!(r.lost_count(), 0);

        // Wait until loss detection timer expires.
        now = r
            .loss_detection_timer()
            .ok_or("expected armed loss timer")?;

        // PTO.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.loss_probes(packet::Epoch::Application), 1);
        assert_eq!(r.lost_count(), 0);
        assert_eq!(r.pto_count(), 1);

        let p = sent_fixture(4, now, 1000, PacketFlight::AckEliciting);

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 3);
        assert_eq!(r.bytes_in_flight(), 3000);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(30));

        let p = sent_fixture(5, now, 1000, PacketFlight::AckEliciting);

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 4);
        assert_eq!(r.bytes_in_flight(), 4000);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(30));
        assert_eq!(r.lost_count(), 0);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // PTO packets are acked.
        let mut acked = RangeSet::default();
        acked.insert(4..6);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 2,
                lost_bytes: 2000,
                acked_bytes: 2 * 1000,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 4);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(40));

        assert_eq!(r.lost_count(), 2);

        // Wait 1 RTT.
        now += r.rtt();

        assert_eq!(
            r.detect_lost_packets_for_test(packet::Epoch::Application, now),
            (0, 0)
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        if cc_algorithm_name == "reno" || cc_algorithm_name == "cubic" {
            assert!(r.startup_exit().is_some());
            assert_eq!(
                r.startup_exit()
                    .ok_or("expected startup exit observation")?
                    .reason,
                StartupExitReason::Loss
            );
        } else {
            assert_eq!(r.startup_exit(), None);
        }
        Ok(())
    }

    #[rstest]
    fn loss_deadline_survives_empty_packet_number_spaces(
        #[values("reno", "cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
        #[values(
            packet::Epoch::Initial,
            packet::Epoch::Handshake,
            packet::Epoch::Application
        )]
        epoch: packet::Epoch,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;
        let mut r = Recovery::new(&cfg);
        let sent = Instant::now();
        let hs = HandshakeStatus {
            completed: epoch == packet::Epoch::Application,
            ..HandshakeStatus::default()
        };
        for pn in 0..2 {
            r.on_packet_sent(
                test_utils::helper_packet_sent(pn, sent, 1000),
                epoch,
                hs,
                sent,
                "",
            );
        }

        let mut acked = RangeSet::default();
        acked.insert(1..2);
        let ack_time = sent + Duration::from_millis(20);
        let outcome =
            r.on_ack_received(&acked, 0, epoch, hs, ack_time, None, "")?;
        assert_eq!(outcome.lost_packets, 0);
        assert_eq!(
            r.loss_detection_timer(),
            Some(sent + Duration::from_micros(22_500))
        );

        let outcome = r.on_loss_detection_timeout(
            hs,
            sent + Duration::from_micros(22_500),
            "",
        );
        assert_eq!(outcome.lost_packets, 1);
        assert_eq!(r.loss_probes(epoch), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        Ok(())
    }

    #[rstest]
    fn loss_on_timer(
        #[values("reno", "cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let mut now = Instant::now();
        let mut r = recovery_with_four_sent_packets(cc_algorithm_name, now)?;

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // Only the first 2 packets and the last one are acked.
        let mut acked = RangeSet::default();
        acked.insert(0..2);
        acked.insert(3..4);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 3 * 1000,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 1000);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(10));
        assert_eq!(r.lost_count(), 0);

        // Wait until loss detection timer expires.
        now = r
            .loss_detection_timer()
            .ok_or("expected armed loss timer")?;

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.loss_probes(packet::Epoch::Application), 0);

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_micros(11250));

        assert_eq!(r.lost_count(), 1);

        // Wait 1 RTT.
        now += r.rtt();

        assert_eq!(
            r.detect_lost_packets_for_test(packet::Epoch::Application, now),
            (0, 0)
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        if cc_algorithm_name == "reno" || cc_algorithm_name == "cubic" {
            assert!(r.startup_exit().is_some());
            assert_eq!(
                r.startup_exit()
                    .ok_or("expected startup exit observation")?
                    .reason,
                StartupExitReason::Loss
            );
        } else {
            assert_eq!(r.startup_exit(), None);
        }
        Ok(())
    }

    #[rstest]
    fn loss_on_reordering(
        #[values("reno", "cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

        // Start by sending a few packets.
        //
        // pkt number: [0, 1, 2, 3]
        for i in 0..4 {
            let p = test_utils::helper_packet_sent(i, now, 1000);
            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            let pkt_count = usize::try_from(i + 1)?;
            assert_eq!(r.sent_packets_len(packet::Epoch::Application), pkt_count);
            assert_eq!(r.bytes_in_flight(), pkt_count * 1000);
            assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);
        }

        // Wait for 10ms after sending.
        now += Duration::from_millis(10);

        // Recieve reordered ACKs, i.e. pkt_num [2, 3]
        let mut acked = RangeSet::default();
        acked.insert(2..4);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 1,
                lost_bytes: 1000,
                acked_bytes: 1000 * 2,
                spurious_losses: 0,
            }
        );
        // Since we only remove packets from the back to avoid compaction, the
        // send length remains the same after receiving reordered ACKs
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 4);
        assert_eq!(r.pkt_thresh(), Some(INITIAL_PACKET_THRESHOLD));
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Wait for 10ms after receiving first set of ACKs.
        now += Duration::from_millis(10);

        // Recieve remaining ACKs, i.e. pkt_num [0, 1]
        let mut acked = RangeSet::default();
        acked.insert(0..2);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 1000,
                spurious_losses: 1,
            }
        );
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(20));

        // Spurious loss.
        assert_eq!(r.lost_count(), 1);
        assert_eq!(r.lost_spurious_count(), 1);

        // Packet threshold was increased.
        assert_eq!(r.pkt_thresh(), Some(4));
        assert_eq!(r.time_thresh(), PACKET_REORDER_TIME_THRESHOLD);

        // Wait 1 RTT.
        now += r.rtt();

        // All packets have been ACKed so dont expect additional lost packets
        assert_eq!(
            r.detect_lost_packets_for_test(packet::Epoch::Application, now),
            (0, 0)
        );
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

        if cc_algorithm_name == "reno" || cc_algorithm_name == "cubic" {
            assert!(r.startup_exit().is_some());
            assert_eq!(
                r.startup_exit()
                    .ok_or("expected startup exit observation")?
                    .reason,
                StartupExitReason::Loss
            );
        } else {
            assert_eq!(r.startup_exit(), None);
        }
        Ok(())
    }

    // TODO: This should run agains both `congestion` and `gcongestion`.
    // `congestion` and `gcongestion` behave differently. That might be ok
    // given the different algorithms but it would be ideal to merge and share
    // the logic.
    #[rstest]
    fn time_thresholds_on_reordering(
        #[values("bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        const THRESH_GAP: Duration = Duration::from_millis(30);

        let cfg = recovery_config(cc_algorithm_name)?;

        let mut now = Instant::now();
        let mut r = Recovery::new(&cfg);
        assert_eq!(r.rtt(), DEFAULT_INITIAL_RTT);

        // Choose times around the threshold to test its increase.
        //
        // ```
        //              between_thresh_ms
        //                         |
        //    initial_thresh_ms    |     spurious_thresh_ms
        //      v                  v             v
        // --------------------------------------------------
        //      | ................ | ..................... |
        //            THRESH_GAP         THRESH_GAP
        // ```
        //
        // Threshold gap time.
        // Initial time theshold based on inital RTT.
        let initial_thresh_ms =
            DEFAULT_INITIAL_RTT.mul_f64(INITIAL_TIME_THRESHOLD);
        // The time threshold after spurious loss.
        let spurious_thresh_ms: Duration =
            DEFAULT_INITIAL_RTT.mul_f64(PACKET_REORDER_TIME_THRESHOLD);
        // Time between the two thresholds
        let between_thresh_ms = initial_thresh_ms + THRESH_GAP;
        assert!(between_thresh_ms > initial_thresh_ms);
        assert!(between_thresh_ms < spurious_thresh_ms);
        assert!(between_thresh_ms + THRESH_GAP > spurious_thresh_ms);

        for i in 0..6 {
            let send_time = now + i * between_thresh_ms;

            let p = test_utils::helper_packet_sent(i.into(), send_time, 1000);
            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                send_time,
                "",
            );
        }

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 6);
        assert_eq!(r.bytes_in_flight(), 6 * 1000);
        assert_eq!(r.pkt_thresh(), Some(INITIAL_PACKET_THRESHOLD));
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Wait for `between_thresh_ms` after sending to trigger loss based on
        // loss threshold.
        now += between_thresh_ms;

        // Ack packet: 1
        //
        // [0, 1, 2, 3, 4, 5]
        //     ^
        let mut acked = RangeSet::default();
        acked.insert(1..2);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 1,
                lost_bytes: 1000,
                acked_bytes: 1000,
                spurious_losses: 0,
            }
        );
        assert_eq!(r.pkt_thresh(), Some(INITIAL_PACKET_THRESHOLD));
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Ack packet: 0
        //
        // [0, 1, 2, 3, 4, 5]
        //  ^  x
        let mut acked = RangeSet::default();
        acked.insert(0..1);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 0,
                spurious_losses: 1,
            }
        );
        // The time_thresh after spurious loss
        assert_eq!(r.time_thresh(), PACKET_REORDER_TIME_THRESHOLD);

        // Wait for `between_thresh_ms` after sending. However, since the
        // threshold has increased, we do not expect loss.
        now += between_thresh_ms;

        // Ack packet: 3
        //
        // [2, 3, 4, 5]
        //     ^
        let mut acked = RangeSet::default();
        acked.insert(3..4);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 1000,
                spurious_losses: 0,
            }
        );

        // Wait for and additional `plus_overhead` to trigger loss based on the
        // new time threshold.
        now += THRESH_GAP;

        // Ack packet: 4
        //
        // [2, 3, 4, 5]
        //     x  ^
        let mut acked = RangeSet::default();
        acked.insert(4..5);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 1,
                lost_bytes: 1000,
                acked_bytes: 1000,
                spurious_losses: 0,
            }
        );
        Ok(())
    }

    // TODO: Implement `enable_relaxed_loss_threshold` and enable this test for
    // the congestion module.
    #[rstest]
    fn relaxed_thresholds_on_reordering(
        #[values("bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        const THRESH_GAP: Duration = Duration::from_millis(30);

        let mut cfg = recovery_config(cc_algorithm_name)?;
        cfg.set_enable_relaxed_loss_threshold(true);

        let mut now = Instant::now();
        let mut r = Recovery::new(&cfg);
        assert_eq!(r.rtt(), DEFAULT_INITIAL_RTT);

        // Choose times around the threshold to test its increase.
        //
        // ```
        //              between_thresh_ms
        //                         |
        //    initial_thresh_ms    |     spurious_thresh_ms
        //      v                  v             v
        // --------------------------------------------------
        //      | ................ | ..................... |
        //            THRESH_GAP         THRESH_GAP
        // ```
        // Threshold gap time.
        // Initial time theshold based on inital RTT.
        let initial_thresh_ms =
            DEFAULT_INITIAL_RTT.mul_f64(INITIAL_TIME_THRESHOLD);
        // The time threshold after spurious loss.
        let spurious_thresh_ms: Duration =
            DEFAULT_INITIAL_RTT.mul_f64(PACKET_REORDER_TIME_THRESHOLD);
        // Time between the two thresholds
        let between_thresh_ms = initial_thresh_ms + THRESH_GAP;
        assert!(between_thresh_ms > initial_thresh_ms);
        assert!(between_thresh_ms < spurious_thresh_ms);
        assert!(between_thresh_ms + THRESH_GAP > spurious_thresh_ms);

        for i in 0..6 {
            let send_time = now + i * between_thresh_ms;

            let p = test_utils::helper_packet_sent(i.into(), send_time, 1000);
            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                send_time,
                "",
            );
        }

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 6);
        assert_eq!(r.bytes_in_flight(), 6 * 1000);
        // Intitial thresholds
        assert_eq!(r.pkt_thresh(), Some(INITIAL_PACKET_THRESHOLD));
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Wait for `between_thresh_ms` after sending to trigger loss based on
        // loss threshold.
        now += between_thresh_ms;

        // Ack packet: 1
        //
        // [0, 1, 2, 3, 4, 5]
        //     ^
        let mut acked = RangeSet::default();
        acked.insert(1..2);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 1,
                lost_bytes: 1000,
                acked_bytes: 1000,
                spurious_losses: 0,
            }
        );
        // Thresholds after 1st loss
        assert_eq!(r.pkt_thresh(), Some(INITIAL_PACKET_THRESHOLD));
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Ack packet: 0
        //
        // [0, 1, 2, 3, 4, 5]
        //  ^  x
        let mut acked = RangeSet::default();
        acked.insert(0..1);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 0,
                spurious_losses: 1,
            }
        );
        // Thresholds after 1st spurious loss
        //
        // Packet threshold should be disabled. Time threshold overhead should
        // stay the same.
        assert_eq!(r.pkt_thresh(), None);
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Set now to send time of packet 2 so we can trigger spurious loss for
        // packet 2.
        now += between_thresh_ms;
        // Then wait for `between_thresh_ms` after sending packet 2 to trigger
        // loss. Since the time threshold has NOT increased, expect a
        // loss.
        now += between_thresh_ms;

        // Ack packet: 3
        //
        // [2, 3, 4, 5]
        //     ^
        let mut acked = RangeSet::default();
        acked.insert(3..4);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 1,
                lost_bytes: 1000,
                acked_bytes: 1000,
                spurious_losses: 0,
            }
        );
        // Thresholds after 2nd loss.
        assert_eq!(r.pkt_thresh(), None);
        assert_eq!(r.time_thresh(), INITIAL_TIME_THRESHOLD);

        // Wait for and additional `plus_overhead` to trigger loss based on the
        // new time threshold.
        // now += THRESH_GAP;

        // Ack packet: 2
        //
        // [2, 3, 4, 5]
        //  ^  x
        let mut acked = RangeSet::default();
        acked.insert(2..3);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 0,
                spurious_losses: 1,
            }
        );
        // Thresholds after 2nd spurious loss.
        //
        // Time threshold overhead should double.
        assert_eq!(r.pkt_thresh(), None);
        let double_time_thresh_overhead =
            2.0_f64.mul_add(INITIAL_TIME_THRESHOLD_OVERHEAD, 1.0);
        assert_eq!(r.time_thresh(), double_time_thresh_overhead);
        Ok(())
    }

    #[rstest]
    fn pacing(
        #[values("reno", "cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
        #[values(false, true)] time_sent_set_to_now: bool,
    ) -> TestResult {
        let pacing_enabled = cc_algorithm_name == "bbr2" ||
            cc_algorithm_name == "bbr2_gcongestion";

        let mut cfg = Config::new(crate::PROTOCOL_VERSION)?;
        cfg.set_cc_algorithm_name(cc_algorithm_name)?;

        #[cfg(feature = "internal")]
        cfg.set_custom_bbr_params(BbrParams {
            time_sent_set_to_now: Some(time_sent_set_to_now),
            ..Default::default()
        });

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

        // send out first packet burst (a full initcwnd).
        for i in 0..10 {
            let p = Sent {
                pkt_num: i,
                frames: smallvec![],
                transmitted_at: now,
                acked_at: None,
                lost_at: None,
                size: 1200,
                flight: PacketFlight::Data,
                delivered: 0,
                delivered_time: now,
                first_sent_time: now,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
            };

            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 10);
        assert_eq!(r.bytes_in_flight(), 12000);
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

        assert_eq!(r.pacing_rate(), if pacing_enabled { 103_963 } else { 0 });
        assert_eq!(r.get_packet_send_time(now), now);

        assert_eq!(r.cwnd(), 12000);
        assert_eq!(r.cwnd_available(), 0);

        // Wait 50ms for ACK.
        let initial_rtt = Duration::from_millis(50);
        now += initial_rtt;

        let mut acked = RangeSet::default();
        acked.insert(0..10);

        assert_eq!(
            r.on_ack_received(
                &acked,
                10,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 12000,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt);
        assert_eq!(r.min_rtt(), Some(initial_rtt));
        assert_eq!(r.rtt(), initial_rtt);

        // 10 MSS increased due to acks.
        assert_eq!(r.cwnd(), 12000 + 1200 * 10);

        // Send the second packet burst.
        let p = sent_fixture(10, now, 6000, PacketFlight::Data);

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 1);
        assert_eq!(r.bytes_in_flight(), 6000);
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt);

        assert_eq!(r.get_packet_send_time(now) != now, pacing_enabled);

        // Send the third and fourth packet bursts together.
        let p = sent_fixture(11, now, 6000, PacketFlight::Data);

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 12000);
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt);

        // Send the fourth packet burst.
        let p = sent_fixture(12, now, 1000, PacketFlight::Data);

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 3);
        assert_eq!(r.bytes_in_flight(), 13000);
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt);

        // We pace this outgoing packet. as all conditions for pacing
        // are passed.
        let pacing_rate = if pacing_enabled {
            // BW estimate precedes the doubling of cwnd; calculate the
            // reference rate with integer nanoseconds.
            let delivered_bytes = u128::from(u64::try_from(r.cwnd())?) / 2;
            u64::try_from(
                delivered_bytes * 1_000_000_000 / initial_rtt.as_nanos(),
            )?
        } else {
            0
        };
        assert_eq!(r.pacing_rate(), pacing_rate);

        let scale_factor = if pacing_enabled {
            // For bbr2_gcongestion, send time is almost 13000 / pacing_rate.
            // Don't know where 13000 comes from.
            1.083_333_32
        } else {
            1.0
        };
        assert_eq!(
            r.get_packet_send_time(now) - now,
            if pacing_enabled {
                Duration::from_secs_f64(
                    scale_factor * 12000.0 /
                        f64::from(u32::try_from(pacing_rate)?),
                )
            } else {
                Duration::ZERO
            }
        );
        assert_eq!(r.startup_exit(), None);

        let reduced_rtt = Duration::from_millis(40);
        now += reduced_rtt;

        let mut acked = RangeSet::default();
        acked.insert(10..11);

        assert_eq!(
            r.on_ack_received(
                &acked,
                0,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 6000,
                spurious_losses: 0,
            }
        );

        let expected_srtt = (7 * initial_rtt + reduced_rtt) / 8;
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 7000);
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt + reduced_rtt);
        assert_eq!(r.min_rtt(), Some(reduced_rtt));
        assert_eq!(r.rtt(), expected_srtt);

        let mut acked = RangeSet::default();
        acked.insert(11..12);

        assert_eq!(
            r.on_ack_received(
                &acked,
                0,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 6000,
                spurious_losses: 0,
            }
        );

        // When enabled, the pacer adds a 25msec delay to the packet
        // sends which will be applied to the sent times tracked by
        // the recovery module, bringing down RTT to 15msec.
        let expected_min_rtt = if pacing_enabled &&
            !time_sent_set_to_now &&
            cfg!(feature = "internal")
        {
            reduced_rtt
                .checked_sub(Duration::from_millis(25))
                .ok_or("RTT shorter than pacing delay")?
        } else {
            reduced_rtt
        };

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 1);
        assert_eq!(r.bytes_in_flight(), 1000);
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt + reduced_rtt);
        assert_eq!(r.min_rtt(), Some(expected_min_rtt));

        let expected_srtt = (7 * expected_srtt + expected_min_rtt) / 8;
        assert_eq!(r.rtt(), expected_srtt);

        let mut acked = RangeSet::default();
        acked.insert(12..13);

        assert_eq!(
            r.on_ack_received(
                &acked,
                0,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 1000,
                spurious_losses: 0,
            }
        );

        // Pacer adds 50msec delay to the second packet, resulting in
        // an effective RTT of 0.
        let expected_min_rtt = if pacing_enabled &&
            !time_sent_set_to_now &&
            cfg!(feature = "internal")
        {
            Duration::from_millis(0)
        } else {
            reduced_rtt
        };
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), initial_rtt + reduced_rtt);
        assert_eq!(r.min_rtt(), Some(expected_min_rtt));

        let expected_srtt = (7 * expected_srtt + expected_min_rtt) / 8;
        assert_eq!(r.rtt(), expected_srtt);
        Ok(())
    }

    #[rstest]
    // initial_cwnd / first_rtt == initial_pacing_rate.  Pacing is 1.0 * bw before
    // and after.
    #[case::bw_estimate_equal_after_first_rtt(1.0, 1.0)]
    // initial_cwnd / first_rtt < initial_pacing_rate.  Pacing decreases from 2 *
    // bw to 1.0 * bw.
    #[case::bw_estimate_decrease_after_first_rtt(2.0, 1.0)]
    // initial_cwnd / first_rtt > initial_pacing_rate from 0.5 * bw to 1.0 * bw.
    // Initial pacing remains 0.5 * bw because the initial_pacing_rate parameter
    // is used an upper bound for the pacing rate after the first RTT.
    // Pacing rate after the first ACK should be:
    // min(initial_pacing_rate_bytes_per_second, init_cwnd / first_rtt)
    #[case::bw_estimate_increase_after_first_rtt(0.5, 0.5)]
    #[cfg(feature = "internal")]
    fn initial_pacing_rate_override(
        #[case] initial_multipler: f64, #[case] expected_multiplier: f64,
    ) -> TestResult {
        let rtt = Duration::from_millis(50);
        let bw = Bandwidth::from_bytes_and_time_delta(12000, rtt);
        let initial_pacing_rate_hint = bw * initial_multipler;
        let expected_pacing_with_rtt_measurement = bw * expected_multiplier;

        let cc_algorithm_name = "bbr2_gcongestion";
        let mut cfg = recovery_config(cc_algorithm_name)?;
        cfg.set_custom_bbr_params(BbrParams {
            initial_pacing_rate_bytes_per_second: Some(
                initial_pacing_rate_hint.to_bytes_per_second(),
            ),
            ..Default::default()
        });

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

        // send some packets.
        for i in 0..2 {
            let p = test_utils::helper_packet_sent(i, now, 1200);
            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 2400);
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

        // Initial pacing rate matches the override value.
        assert_eq!(
            r.pacing_rate(),
            initial_pacing_rate_hint.to_bytes_per_second()
        );
        assert_eq!(r.get_packet_send_time(now), now);

        assert_eq!(r.cwnd(), 12000);
        assert_eq!(r.cwnd_available(), 9600);

        // Wait 1 rtt for ACK.
        now += rtt;

        let mut acked = RangeSet::default();
        acked.insert(0..2);

        assert_eq!(
            r.on_ack_received(
                &acked,
                10,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 2400,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), rtt);
        assert_eq!(r.rtt(), rtt);

        // Pacing rate is recalculated based on initial cwnd when the
        // first RTT estimate is available.
        assert_eq!(
            r.pacing_rate(),
            expected_pacing_with_rtt_measurement.to_bytes_per_second()
        );
        Ok(())
    }

    #[rstest]
    fn invalid_ack_preserves_recovery_state(
        #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;
        let epoch = packet::Epoch::Application;
        let mut recovery = Recovery::new(&cfg);
        let now = Instant::now();
        let handshake = HandshakeStatus::default();
        for pn in [0, 1, 3] {
            let sent = test_utils::helper_packet_sent(pn, now, 1000);
            recovery.on_packet_sent(sent, epoch, handshake, now, "");
        }
        recovery.on_packet_number_skipped(2);
        let now = now + Duration::from_millis(10);
        let mut acked = RangeSet::default();
        assert_eq!(
            recovery.on_ack_received(
                &acked,
                0,
                epoch,
                handshake,
                now,
                Some(2),
                ""
            ),
            Err(Error::InvalidAckRange),
        );
        acked.insert(0..1);
        acked.insert(2..3);
        assert_eq!(
            recovery.on_ack_received(
                &acked,
                0,
                epoch,
                handshake,
                now,
                Some(2),
                ""
            ),
            Err(Error::OptimisticAckDetected),
        );
        assert_eq!(recovery.bytes_in_flight(), 3000);
        assert_eq!(recovery.sent_packets_len(epoch), 3);
        assert_eq!(recovery.get_largest_acked_on_epoch(epoch), None);
        assert!(recovery.next_acked_frame(epoch).is_none());

        let mut valid = RangeSet::default();
        valid.insert(0..2);
        let outcome = recovery.on_ack_received(
            &valid,
            0,
            epoch,
            handshake,
            now,
            Some(2),
            "",
        )?;
        assert_eq!(outcome.acked_bytes, 2000);
        assert_eq!(recovery.bytes_in_flight(), 1000);
        Ok(())
    }

    #[rstest]
    fn validate_ack_range_on_ack_received(
        #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;

        let epoch = packet::Epoch::Application;
        let mut r = Recovery::new(&cfg);
        let mut now = Instant::now();
        assert_eq!(r.sent_packets_len(epoch), 0);

        // Send 4 packets
        let pkt_size = 1000;
        let pkt_count = 4;
        for pkt_num in 0..pkt_count {
            let sent = test_utils::helper_packet_sent(pkt_num, now, pkt_size);
            r.on_packet_sent(sent, epoch, HandshakeStatus::default(), now, "");
        }
        assert_eq!(r.sent_packets_len(epoch), usize::try_from(pkt_count)?);
        assert_eq!(r.bytes_in_flight(), usize::try_from(pkt_count)? * pkt_size);
        assert!(r.get_largest_acked_on_epoch(epoch).is_none());
        assert_eq!(r.largest_sent_pkt_num_on_path(epoch), Some(3));

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // ACK 2 packets
        let mut acked = RangeSet::default();
        acked.insert(0..2);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                epoch,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 2 * 1000,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(epoch), 2);
        assert_eq!(r.bytes_in_flight(), 2 * 1000);

        assert_eq!(r.get_largest_acked_on_epoch(epoch), Some(1));
        assert_eq!(r.largest_sent_pkt_num_on_path(epoch), Some(3));

        // ACK large range
        let mut acked = RangeSet::default();
        acked.insert(0..10);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                epoch,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 2 * 1000,
                spurious_losses: 0,
            }
        );
        assert_eq!(r.sent_packets_len(epoch), 0);
        assert_eq!(r.bytes_in_flight(), 0);

        // largest_acked is the connection-global ACK high-water mark, even
        // when this path only sent packets through PN 3.
        assert_eq!(r.get_largest_acked_on_epoch(epoch), Some(9));
        assert_eq!(r.largest_sent_pkt_num_on_path(epoch), Some(3));
        Ok(())
    }

    #[rstest]
    fn pmtud_loss_on_timer(
        #[values("reno", "cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;

        let mut r = Recovery::new(&cfg);
        assert_eq!(r.cwnd(), 12000);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

        // Start by sending a few packets.
        let p = sent_fixture(0, now, 1000, PacketFlight::AckEliciting);

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.in_flight_count(packet::Epoch::Application), 1);
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 1);
        assert_eq!(r.bytes_in_flight(), 1000);
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

        let p = sent_fixture(1, now, 1000, PacketFlight::PmtuProbe);

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.in_flight_count(packet::Epoch::Application), 2);

        let p = sent_fixture(2, now, 1000, PacketFlight::AckEliciting);

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        assert_eq!(r.in_flight_count(packet::Epoch::Application), 3);

        // Wait for 10ms.
        now += Duration::from_millis(10);

        // Only the first  packets and the last one are acked.
        let mut acked = RangeSet::default();
        acked.insert(0..1);
        acked.insert(2..3);

        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 2 * 1000,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.bytes_in_flight(), 1000);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_millis(10));
        assert_eq!(r.lost_count(), 0);

        // Wait until loss detection timer expires.
        now = r
            .loss_detection_timer()
            .ok_or("expected armed loss timer")?;

        // Packet is declared lost.
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");
        assert_eq!(r.loss_probes(packet::Epoch::Application), 0);

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 2);
        assert_eq!(r.in_flight_count(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_micros(11250));
        assert_eq!(r.cwnd(), 12000);

        assert_eq!(r.lost_count(), 0);

        // Wait 1 RTT.
        now += r.rtt();

        assert_eq!(
            r.detect_lost_packets_for_test(packet::Epoch::Application, now),
            (0, 0)
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.in_flight_count(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), Duration::from_micros(11250));
        assert_eq!(r.lost_count(), 0);
        assert_eq!(r.startup_exit(), None);
        Ok(())
    }

    /// RFC 9002, Section 7.6: losing every packet sent over a period longer
    /// than the persistent congestion duration collapses the window to the
    /// minimum.
    #[rstest]
    fn persistent_congestion_collapses_cwnd(
        #[values("cubic", "reno")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;

        let mut r = Recovery::new(&cfg);
        let epoch = packet::Epoch::Application;
        let start = Instant::now();

        // An RTT sample is needed before the duration can be computed.
        r.on_packet_sent(
            test_utils::helper_packet_sent(0, start, 1000),
            epoch,
            HandshakeStatus::default(),
            start,
            "",
        );

        let mut acked = RangeSet::default();
        acked.insert(0..1);
        r.on_ack_received(
            &acked,
            0,
            epoch,
            HandshakeStatus::default(),
            start + Duration::from_millis(10),
            None,
            "",
        )?;

        // Three packets spanning ten seconds, none of which is acknowledged.
        for (pkt_num, offset) in [(1, 0), (2, 5), (3, 10)] {
            let transmitted_at = start + Duration::from_secs(offset);
            r.on_packet_sent(
                test_utils::helper_packet_sent(pkt_num, transmitted_at, 1000),
                epoch,
                HandshakeStatus::default(),
                transmitted_at,
                "",
            );
        }

        let cwnd_before = r.cwnd();
        assert!(cwnd_before > r.max_datagram_size() * MINIMUM_WINDOW_PACKETS);

        // A later packet gets through, so the three above are declared lost.
        let now = start + Duration::from_secs(11);
        r.on_packet_sent(
            test_utils::helper_packet_sent(4, now, 1000),
            epoch,
            HandshakeStatus::default(),
            now,
            "",
        );

        let mut acked = RangeSet::default();
        acked.insert(4..5);
        r.on_ack_received(
            &acked,
            0,
            epoch,
            HandshakeStatus::default(),
            now,
            None,
            "",
        )?;

        assert_eq!(r.cwnd(), r.max_datagram_size() * MINIMUM_WINDOW_PACKETS);
        Ok(())
    }

    /// RFC 9002 Section 7.6 only considers persistent-congestion endpoints
    /// sent after the first RTT sample was obtained.
    #[rstest]
    fn persistent_congestion_ignores_packets_sent_before_first_rtt_sample(
        #[values("cubic", "reno")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;

        let mut r = Recovery::new(&cfg);
        let epoch = packet::Epoch::Application;
        let start = Instant::now();

        // These two packets span long enough for persistent congestion, but
        // both predate the first RTT sample.
        for (pkt_num, offset) in [(0, 0), (1, 5)] {
            let transmitted_at = start + Duration::from_secs(offset);
            r.on_packet_sent(
                test_utils::helper_packet_sent(pkt_num, transmitted_at, 1000),
                epoch,
                HandshakeStatus::default(),
                transmitted_at,
                "",
            );
        }

        // ACK a later packet to obtain the first RTT sample and declare the
        // two earlier packets lost in the same ACK processing pass.
        let sample_sent = start + Duration::from_secs(6);
        r.on_packet_sent(
            test_utils::helper_packet_sent(2, sample_sent, 1000),
            epoch,
            HandshakeStatus::default(),
            sample_sent,
            "",
        );

        let mut acked = RangeSet::default();
        acked.insert(2..3);
        r.on_ack_received(
            &acked,
            0,
            epoch,
            HandshakeStatus::default(),
            sample_sent + Duration::from_millis(10),
            None,
            "",
        )?;

        assert!(r.cwnd() > r.max_datagram_size() * MINIMUM_WINDOW_PACKETS);
        Ok(())
    }

    /// The RFC's no-ACK-between-endpoints condition spans all packet number
    /// spaces, including acknowledged packets that their epoch has already
    /// drained.
    #[rstest]
    fn persistent_congestion_respects_drained_cross_space_ack(
        #[values("cubic", "reno")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;

        let mut r = Recovery::new(&cfg);
        let app = packet::Epoch::Application;
        let handshake = packet::Epoch::Handshake;
        let start = Instant::now();

        // Establish the first RTT sample before the candidate loss interval.
        r.on_packet_sent(
            test_utils::helper_packet_sent(0, start, 1000),
            app,
            HandshakeStatus::default(),
            start,
            "",
        );
        let mut acked = RangeSet::default();
        acked.insert(0..1);
        r.on_ack_received(
            &acked,
            0,
            app,
            HandshakeStatus::default(),
            start + Duration::from_millis(10),
            None,
            "",
        )?;

        let first_lost = start + Duration::from_secs(1);
        r.on_packet_sent(
            test_utils::helper_packet_sent(1, first_lost, 1000),
            app,
            HandshakeStatus::default(),
            first_lost,
            "",
        );

        // This ACK sits chronologically between the eventual lost endpoints,
        // but is in another packet-number space and gets drained immediately.
        let middle = start + Duration::from_secs(3);
        r.on_packet_sent(
            test_utils::helper_packet_sent(0, middle, 1000),
            handshake,
            HandshakeStatus::default(),
            middle,
            "",
        );
        let mut acked = RangeSet::default();
        acked.insert(0..1);
        r.on_ack_received(
            &acked,
            0,
            handshake,
            HandshakeStatus::default(),
            middle + Duration::from_millis(10),
            None,
            "",
        )?;
        assert_eq!(r.sent_packets_len(handshake), 0);

        let last_lost = start + Duration::from_secs(6);
        r.on_packet_sent(
            test_utils::helper_packet_sent(2, last_lost, 1000),
            app,
            HandshakeStatus::default(),
            last_lost,
            "",
        );

        let trigger = start + Duration::from_secs(7);
        r.on_packet_sent(
            test_utils::helper_packet_sent(3, trigger, 1000),
            app,
            HandshakeStatus::default(),
            trigger,
            "",
        );
        let mut acked = RangeSet::default();
        acked.insert(3..4);
        r.on_ack_received(
            &acked,
            0,
            app,
            HandshakeStatus::default(),
            trigger + Duration::from_millis(10),
            None,
            "",
        )?;

        assert!(r.cwnd() > r.max_datagram_size() * MINIMUM_WINDOW_PACKETS);
        Ok(())
    }

    // Modeling delivery_rate for gcongestion is non-trivial so we only test the
    // congestion specific algorithms.
    #[rstest]
    fn congestion_delivery_rate(
        #[values("reno", "cubic", "bbr2")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;

        let mut r = Recovery::new(&cfg);
        assert_eq!(r.cwnd(), 12000);

        let now = Instant::now();

        let mut total_bytes_sent = 0;
        for pn in 0..10 {
            // Start by sending a few packets.
            let bytes = 1000;
            let sent = test_utils::helper_packet_sent(pn, now, bytes);
            r.on_packet_sent(
                sent,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            total_bytes_sent += bytes;
        }

        // Ack
        let interval = Duration::from_secs(10);
        let mut acked = RangeSet::default();
        acked.insert(0..10);
        assert_eq!(
            r.on_ack_received(
                &acked,
                25,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now + interval,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: total_bytes_sent,
                spurious_losses: 0,
            }
        );
        assert_eq!(r.delivery_rate().to_bytes_per_second(), 1000);
        assert_eq!(r.min_rtt(), Some(interval));
        // delivery rate should be in units bytes/sec
        assert_eq!(
            total_bytes_sent as u64 / interval.as_secs(),
            r.delivery_rate().to_bytes_per_second()
        );
        assert_eq!(r.startup_exit(), None);
        Ok(())
    }

    #[rstest]
    fn acks_with_no_retransmittable_data(
        #[values("reno", "cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let rtt = Duration::from_millis(100);

        let cfg = recovery_config(cc_algorithm_name)?;

        let mut r = Recovery::new(&cfg);

        let mut now = Instant::now();

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);

        let mut next_packet = 0;
        // send some packets.
        for _ in 0..3 {
            let p = test_utils::helper_packet_sent(next_packet, now, 1200);
            next_packet += 1;
            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );
        }

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 3);
        assert_eq!(r.bytes_in_flight(), 3600);
        assert_eq!(r.bytes_in_flight_duration(), Duration::ZERO);

        assert_eq!(
            r.pacing_rate(),
            if cc_algorithm_name == "bbr2_gcongestion" {
                103_963
            } else {
                0
            },
        );
        assert_eq!(r.get_packet_send_time(now), now);
        assert_eq!(r.cwnd(), 12000);
        assert_eq!(r.cwnd_available(), 8400);

        // Wait 1 rtt for ACK.
        now += rtt;

        let mut acked = RangeSet::default();
        acked.insert(0..3);

        assert_eq!(
            r.on_ack_received(
                &acked,
                10,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                None,
                "",
            )?,
            OnAckReceivedOutcome {
                lost_packets: 0,
                lost_bytes: 0,
                acked_bytes: 3600,
                spurious_losses: 0,
            }
        );

        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 0);
        assert_eq!(r.bytes_in_flight(), 0);
        assert_eq!(r.bytes_in_flight_duration(), rtt);
        assert_eq!(r.rtt(), rtt);

        // Pacing rate is recalculated based on initial cwnd when the
        // first RTT estimate is available.
        assert_eq!(
            r.pacing_rate(),
            if cc_algorithm_name == "bbr2_gcongestion" {
                120_000
            } else {
                0
            },
        );

        // Send some no "in_flight" packets
        for iter in 3..1000 {
            let mut p = test_utils::helper_packet_sent(next_packet, now, 1200);
            // Model an ACK-only packet, which contributes no in-flight bytes.
            p.flight = PacketFlight::NotInFlight;
            p.size = 0;
            next_packet += 1;
            r.on_packet_sent(
                p,
                packet::Epoch::Application,
                HandshakeStatus::default(),
                now,
                "",
            );

            now += rtt;

            let mut acked = RangeSet::default();
            acked.insert(iter..(iter + 1));

            assert_eq!(
                r.on_ack_received(
                    &acked,
                    10,
                    packet::Epoch::Application,
                    HandshakeStatus::default(),
                    now,
                    None,
                    "",
                )?,
                OnAckReceivedOutcome {
                    lost_packets: 0,
                    lost_bytes: 0,
                    acked_bytes: 0,
                    spurious_losses: 0,
                }
            );

            // Verify that connection has not exited startup.
            assert_eq!(r.startup_exit(), None, "{iter}");

            // Unchanged metrics.
            assert_eq!(
                r.sent_packets_len(packet::Epoch::Application),
                0,
                "{iter}"
            );
            assert_eq!(r.bytes_in_flight(), 0, "{iter}");
            assert_eq!(r.bytes_in_flight_duration(), rtt, "{iter}");
            assert_eq!(
                r.pacing_rate(),
                if cc_algorithm_name == "bbr2_gcongestion" ||
                    cc_algorithm_name == "bbr2"
                {
                    120_000
                } else {
                    0
                },
                "{iter}"
            );
        }
        Ok(())
    }
    /// RFC 9002 Section 6.2.4: when PTO fires, also probe the other
    /// eligible packet-number spaces that still have data in flight.
    #[rstest]
    fn pto_probes_every_in_flight_packet_number_space(
        #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;

        let mut r = Recovery::new(&cfg);
        let now = Instant::now();
        let handshake_status = HandshakeStatus {
            has_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };

        for (pkt_num, epoch) in
            [(0, packet::Epoch::Initial), (1, packet::Epoch::Handshake)]
        {
            r.on_packet_sent(
                test_utils::helper_packet_sent(pkt_num, now, 1000),
                epoch,
                handshake_status,
                now,
                "",
            );
        }

        let timeout = r
            .loss_detection_timer()
            .ok_or("expected armed loss timer")?;
        r.on_loss_detection_timeout(handshake_status, timeout, "");

        assert!(r.loss_probes(packet::Epoch::Initial) > 0);
        assert!(r.loss_probes(packet::Epoch::Handshake) > 0);
        Ok(())
    }

    /// ACKs for packets sent on a different path still advance the global
    /// packet threshold. Control-only frames on the old path must therefore
    /// become lost and eligible for retransmission even with no local ACK.
    #[rstest]
    fn cross_path_ack_marks_control_frame_lost(
        #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;

        let now = Instant::now();
        let mut r = Recovery::new(&cfg);
        let epoch = packet::Epoch::Application;
        let hs = HandshakeStatus::default();

        let mut sent = test_utils::helper_packet_sent(0, now, 1000);
        sent.flight = PacketFlight::AckEliciting;
        sent.frames = smallvec![frame::Frame::ResetStream {
            stream_id: 0,
            error_code: 42,
            final_size: 0,
        }];
        r.on_packet_sent(sent, epoch, hs, now, "");

        // PN 3 was sent on another path. Its ACK is connection-valid but does
        // not newly acknowledge anything in this path-local recovery object.
        let mut acked = RangeSet::default();
        acked.insert(3..4);
        let outcome = r.on_ack_received(&acked, 0, epoch, hs, now, None, "")?;

        assert_eq!(outcome.acked_bytes, 0);
        assert_eq!(outcome.lost_packets, 1);
        assert_eq!(r.lost_frames_count(epoch), 1);
        assert!(matches!(
            r.next_lost_frame(epoch),
            Some(frame::Frame::ResetStream {
                stream_id: 0,
                error_code: 42,
                final_size: 0,
            })
        ));
        Ok(())
    }

    #[rstest]
    fn pto_overflow_reproduction(
        #[values("reno", "cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;
        let mut r = Recovery::new(&cfg);
        let now = Instant::now();

        // Scenario: Handshake not completed
        let handshake_status = HandshakeStatus {
            has_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };

        // 1. Send Initial packet to arm the timer
        let p_initial = Sent {
            pkt_num: 0,
            frames: smallvec::smallvec![],
            transmitted_at: now,
            acked_at: None,
            lost_at: None,
            size: 1000,
            flight: PacketFlight::AckEliciting,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
        };
        r.on_packet_sent(
            p_initial,
            packet::Epoch::Initial,
            handshake_status,
            now,
            "",
        );

        // The timer should now be set for the Initial packet.
        assert!(r.loss_detection_timer().is_some());

        // 2. Send Application packet (0-RTT)
        let p_app = Sent {
            pkt_num: 0, // Application space has its own packet numbers
            frames: smallvec::smallvec![],
            transmitted_at: now,
            acked_at: None,
            lost_at: None,
            size: 1000,
            flight: PacketFlight::Data,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,

            lost: 0,
        };
        r.on_packet_sent(
            p_app,
            packet::Epoch::Application,
            handshake_status,
            now,
            "",
        );

        // 3. Acknowledge the Initial packet.
        // This empties the Initial space, but Application space still has data
        // in flight.
        let mut ranges = RangeSet::default();
        ranges.insert(0..1);
        r.on_ack_received(
            &ranges,
            0,
            packet::Epoch::Initial,
            handshake_status,
            now,
            None,
            "",
        )?;

        // The timer should be cleared at this point.
        // Although there is Application data in flight, the handshake is not
        // confirmed, so it cannot be used to arm the PTO timer. Since there are
        // no packets in flight in Initial or Handshake spaces either, no timer
        // should be set.
        assert!(r.loss_detection_timer().is_none());
        Ok(())
    }

    // Test that consecutive PTOs don't add duplicate frames to lost_frames.
    // This validates the fix: `if epoch.lost_frames.is_empty()` guard.
    #[rstest]
    fn pto_does_not_duplicate_frames_on_consecutive_timeouts(
        #[values("reno", "cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;

        let mut r = Recovery::new(&cfg);
        let mut now = Instant::now();

        // Send a packet with a STREAM frame.
        let frames = smallvec![frame::Frame::Stream {
            stream_id: 4,
            data: RangeBuf::from(b"test", 0, false),
        },];

        let p = Sent {
            pkt_num: 0,
            frames,
            transmitted_at: now,
            acked_at: None,
            lost_at: None,
            size: 1000,
            flight: PacketFlight::Data,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
        };

        r.on_packet_sent(
            p,
            packet::Epoch::Application,
            HandshakeStatus::default(),
            now,
            "",
        );

        // Verify initial state
        assert_eq!(r.lost_frames_count(packet::Epoch::Application), 0);
        assert_eq!(r.lost_count(), 0);

        // First PTO - should add frames when lost_frames is empty.
        now = r
            .loss_detection_timer()
            .ok_or("expected armed loss timer")?;
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");

        assert_eq!(r.pto_count(), 1);
        let frames_after_first_pto =
            r.lost_frames_count(packet::Epoch::Application);
        assert_eq!(
            frames_after_first_pto, 1,
            "First PTO should add exactly 1 frame"
        );
        assert_eq!(
            r.lost_count(),
            0,
            "PTO doesn't declare packets lost (no CC impact)"
        );

        // Second PTO while lost_frames is still populated.
        // WITHOUT the fix: would add duplicate frame (count becomes 2).
        // WITH the fix: skips adding (count stays 1).
        now = r
            .loss_detection_timer()
            .ok_or("expected armed loss timer")?;
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");

        assert_eq!(r.pto_count(), 2);
        let frames_after_second_pto =
            r.lost_frames_count(packet::Epoch::Application);
        assert_eq!(
            frames_after_second_pto, frames_after_first_pto,
            "Second PTO must NOT add duplicate frames (fix: `if \
             lost_frames.is_empty()`)"
        );

        // Third PTO for extra validation
        now = r
            .loss_detection_timer()
            .ok_or("expected armed loss timer")?;
        r.on_loss_detection_timeout(HandshakeStatus::default(), now, "");

        assert_eq!(r.pto_count(), 3);
        let frames_after_third_pto =
            r.lost_frames_count(packet::Epoch::Application);
        assert_eq!(
            frames_after_third_pto, frames_after_first_pto,
            "Third PTO must NOT add duplicate frames"
        );

        // Verify packets are still tracked (not removed)
        assert_eq!(r.sent_packets_len(packet::Epoch::Application), 1);
        // Verify lost_count never increased (PTO doesn't trigger CC)
        assert_eq!(r.lost_count(), 0);
        Ok(())
    }

    /// RFC 9002, Section 6.2.1: Initial ACKs do not reset a client's
    /// PTO backoff until the peer has validated the client's address.
    #[rstest]
    fn pto_backoff_kept_until_peer_validated_address(
        #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        let cfg = recovery_config(cc_algorithm_name)?;

        let unvalidated = HandshakeStatus {
            has_handshake_keys: false,
            peer_verified_address: false,
            completed: false,
        };

        let mut now = Instant::now();
        let mut r = Recovery::new(&cfg);

        r.on_packet_sent(
            test_utils::helper_packet_sent(0, now, 1000),
            packet::Epoch::Initial,
            unvalidated,
            now,
            "",
        );

        now = r
            .loss_detection_timer()
            .ok_or("expected armed loss timer")?;
        r.on_loss_detection_timeout(unvalidated, now, "");
        assert_eq!(r.pto_count(), 1);

        let mut acked = RangeSet::default();
        acked.insert(0..1);
        r.on_ack_received(
            &acked,
            25,
            packet::Epoch::Initial,
            unvalidated,
            now,
            None,
            "",
        )?;
        assert_eq!(r.pto_count(), 1);

        r.on_packet_sent(
            test_utils::helper_packet_sent(1, now, 1000),
            packet::Epoch::Initial,
            unvalidated,
            now,
            "",
        );

        let validated = HandshakeStatus {
            peer_verified_address: true,
            ..unvalidated
        };

        let mut acked = RangeSet::default();
        acked.insert(0..2);
        r.on_ack_received(
            &acked,
            25,
            packet::Epoch::Initial,
            validated,
            now,
            None,
            "",
        )?;
        assert_eq!(r.pto_count(), 0);
        Ok(())
    }

    // Test that send_on_path after PTO timeout properly sends retransmissions
    // and doesn't mark packets as lost (lost_count should remain 0).
    #[rstest]
    fn pto_send_on_path_retransmits_without_loss(
        #[values("reno", "cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    ) -> TestResult {
        use crate::test_utils;

        let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

        // Complete handshake
        assert_eq!(pipe.handshake(), Ok(()));

        // Client sends stream data
        assert_eq!(pipe.client.stream_send(4, b"hello", false), Ok(5));

        let mut buf = vec![0; 65_535];

        // Send the packet but drop it (don't deliver to server)
        let (len1, _) = pipe.client.send(&mut buf)?;
        assert!(len1 > 0);

        // Verify lost_count is 0 (no losses yet)
        let initial_lost_count =
            pipe.client.paths.get_active()?.recovery.lost_count();
        assert_eq!(initial_lost_count, 0, "No packets should be lost initially");

        // Verify frames are not yet in lost_frames
        let initial_lost_frames = pipe
            .client
            .paths
            .get_active()?
            .recovery
            .lost_frames_count(packet::Epoch::Application);
        assert_eq!(
            initial_lost_frames, 0,
            "No frames should be in lost_frames initially"
        );

        // Wait for PTO timeout
        let timer = pipe.client.timeout().ok_or("expected connection timeout")?;
        std::thread::sleep(timer + Duration::from_millis(1));

        // Trigger PTO via on_timeout()
        pipe.client.on_timeout();

        // After PTO, frames should be in lost_frames for retransmission
        let lost_frames_after_pto = pipe
            .client
            .paths
            .get_active()?
            .recovery
            .lost_frames_count(packet::Epoch::Application);
        assert!(
            lost_frames_after_pto > 0,
            "PTO should add frames to lost_frames for retransmission"
        );

        // But lost_count should still be 0 (PTO doesn't declare packets lost)
        let lost_count_after_pto =
            pipe.client.paths.get_active()?.recovery.lost_count();
        assert_eq!(
            lost_count_after_pto, 0,
            "PTO should not increment lost_count"
        );

        // Now send the retransmission via send_on_path
        let (len2, _) = pipe.client.send(&mut buf)?;
        assert!(len2 > 0, "Should send PTO probe packet");

        // After sending, lost_count should still be 0
        let lost_count_after_send =
            pipe.client.paths.get_active()?.recovery.lost_count();
        assert_eq!(
            lost_count_after_send, 0,
            "Sending PTO probe should not increment lost_count"
        );

        // Deliver the retransmission to server
        assert_eq!(pipe.server_recv(&mut buf[..len2]), Ok(len2));

        // Server should receive the stream data
        let mut recv_buf = [0; 100];
        assert_eq!(pipe.server.stream_recv(4, &mut recv_buf), Ok((5, false)));
        assert_eq!(&recv_buf[..5], b"hello");

        // Final verification: lost_count on client should still be 0
        let final_lost_count =
            pipe.client.paths.get_active()?.recovery.lost_count();
        assert_eq!(
            final_lost_count, 0,
            "No packets should be marked as lost - PTO only retransmits"
        );
        Ok(())
    }
}

mod bandwidth;
mod bytes_in_flight;
mod congestion;
mod gcongestion;
mod pending_lost_frames;
mod rtt;
