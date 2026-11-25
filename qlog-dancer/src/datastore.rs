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

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::Display;

use log::error;
use log::trace;
use qlog::events::http3::Http3Frame;
use qlog::events::quic::QuicFrame;
use qlog::events::quic::TransportInitiator;
use qlog::events::EventData;
use qlog::events::RawInfo;

use tabled::Tabled;

use crate::request_stub::HttpRequestStub;
use crate::request_stub::NaOption;
use crate::trackers::StreamBufferTracker;
use crate::trackers::StreamMaxTracker;
use crate::trackers::TrackerError;
use crate::LogFileData;
use crate::PacketType;
use crate::QlogPointRtt;
use crate::QlogPointu64;
use crate::RawLogEvents::Netlog;
use netlog;
use netlog::h2;
use netlog::h2::Event::*;
use netlog::h2::*;
use netlog::h3;
use netlog::h3::Event::*;
use netlog::http;
use netlog::quic;
use netlog::quic::Event::*;
use netlog::quic::*;
use netlog::read_netlog_record;

pub type ParseResult<T> = Result<T, serde_json::Error>;
#[derive(Debug, Clone)]
pub struct PacketInfoStub {
    pub acked: Option<bool>,
    pub raw: Option<RawInfo>,
    pub created_time: f64,
    pub send_at_time: Option<f64>,
    pub ty: PacketType,
    pub number: u64,
}

#[derive(Clone, Debug)]
pub struct StreamAccess {
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RequestAtServerDeltas {
    pub rx_hdr_tx_hdr: NaOption<f64>,
    pub rx_hdr_tx_first_data: NaOption<f64>,
    pub rx_hdr_tx_last_data: NaOption<f64>,
    pub tx_first_data_tx_last_data: NaOption<f64>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RequestAtClientDeltas {
    pub discover_tx_hdr: NaOption<f64>,
    pub tx_hdr_rx_hdr: NaOption<f64>,
    pub tx_hdr_rx_first_data: NaOption<f64>,
    pub tx_hdr_rx_last_data: NaOption<f64>,
    pub tx_first_data_tx_last_data: NaOption<f64>,
    pub rx_first_data_rx_last_data: NaOption<f64>,
    pub rx_hdr_rx_last_data: NaOption<f64>,
}

#[derive(Debug, Default)]
pub enum RequestActor {
    #[default]
    Client,
    Server,
}

impl From<VantagePoint> for RequestActor {
    fn from(value: VantagePoint) -> Self {
        match value {
            VantagePoint::Client => RequestActor::Client,
            VantagePoint::Server => RequestActor::Server,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub enum VantagePoint {
    #[default]
    Client,
    Server,
}

/// A qlog vantage point with no valid client/server interpretation.
#[derive(Debug)]
pub struct UnsupportedVantagePoint(pub qlog::VantagePointType);

impl std::fmt::Display for UnsupportedVantagePoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unsupported qlog vantage point {:?}: expected client or server",
            self.0
        )
    }
}

impl std::error::Error for UnsupportedVantagePoint {}

/// Failure to build a qlog or Chrome netlog datastore from recorded events:
/// unsupported vantage point, stream arithmetic overflow, or netlog counters
/// that cannot be represented without wrapping.
#[derive(Debug)]
pub enum DatastoreError {
    UnsupportedVantagePoint(UnsupportedVantagePoint),
    Tracker(TrackerError),
    NetlogCounterOverflow { field: &'static str },
}

impl From<UnsupportedVantagePoint> for DatastoreError {
    fn from(value: UnsupportedVantagePoint) -> Self {
        Self::UnsupportedVantagePoint(value)
    }
}

impl From<TrackerError> for DatastoreError {
    fn from(value: TrackerError) -> Self {
        Self::Tracker(value)
    }
}

impl std::fmt::Display for DatastoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVantagePoint(error) =>
                std::fmt::Display::fmt(error, f),
            Self::Tracker(error) => std::fmt::Display::fmt(error, f),
            Self::NetlogCounterOverflow { field } => {
                write!(f, "netlog counter overflow: {field}")
            },
        }
    }
}

impl std::error::Error for DatastoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsupportedVantagePoint(error) => Some(error),
            Self::Tracker(error) => Some(error),
            Self::NetlogCounterOverflow { .. } => None,
        }
    }
}

impl TryFrom<&qlog::VantagePointType> for VantagePoint {
    type Error = UnsupportedVantagePoint;

    fn try_from(value: &qlog::VantagePointType) -> Result<Self, Self::Error> {
        match value {
            qlog::VantagePointType::Client => Ok(Self::Client),
            qlog::VantagePointType::Server => Ok(Self::Server),
            other => Err(UnsupportedVantagePoint(other.clone())),
        }
    }
}

#[derive(Debug, Default)]
pub struct StreamDatapoint {
    pub offset: u64,
    pub length: u64,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationProto {
    Http2,
    #[default]
    Http3,
}

impl Debug for ApplicationProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for ApplicationProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = match self {
            ApplicationProto::Http2 => "HTTP/2",
            ApplicationProto::Http3 => "HTTP/3",
        };

        write!(f, "{}", v)
    }
}

#[derive(Debug, Default, Tabled)]
pub struct QuicSessionClose {
    #[tabled(rename = "ID")]
    pub session_id: i64,
    #[tabled(rename = "SNI")]
    pub sni: String,
    #[tabled(rename = "Error")]
    pub quic_error: i64,
    #[tabled(rename = "Description")]
    pub quic_error_pretty: NaOption<String>,
    #[tabled(rename = "From peer")]
    pub from_peer: bool,
    #[tabled(rename = "Additional Details")]
    pub details: String,
}

#[derive(Debug, Default, Tabled)]
pub struct H2SessionClose {
    #[tabled(rename = "ID")]
    pub session_id: i64,
    #[tabled(rename = "SNI")]
    pub sni: String,
    #[tabled(rename = "Error")]
    pub net_err: i64,
    #[tabled(rename = "Description")]
    pub net_err_pretty: NaOption<String>,
    #[tabled(rename = "Additional Details")]
    pub details: String,
}

#[derive(Default, Debug)]
pub struct QuicStreamStopSending {
    pub quic_rst_stream_error: u64,
    pub quic_rst_stream_error_friendly: Option<String>,
}

impl Display for QuicStreamStopSending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "code={}, {}",
            self.quic_rst_stream_error,
            self.quic_rst_stream_error_friendly.as_deref().unwrap_or("")
        )
    }
}

#[derive(Default, Debug)]
pub struct QuicStreamReset {
    pub offset: u64,
    pub quic_rst_stream_error: u64,
    pub quic_rst_stream_error_friendly: Option<String>,
}

impl Display for QuicStreamReset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "offset={}, code={}, {}",
            self.offset,
            self.quic_rst_stream_error,
            self.quic_rst_stream_error_friendly.as_deref().unwrap_or("")
        )
    }
}

#[derive(Default, Debug)]
pub struct H2StreamReset {
    pub error: String,
    pub description: String,
}

impl Display for H2StreamReset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "code={}, {}", self.error, self.description,)
    }
}

/// Most recent observed QUIC packet number in each independently numbered
/// packet-number space. 0-RTT and 1-RTT both use Application Data numbering.
#[derive(Debug, Default)]
pub struct NetlogPacketNumberProgress {
    initial: Option<u64>,
    handshake: Option<u64>,
    application: Option<u64>,
}

impl NetlogPacketNumberProgress {
    const fn previous(&self, packet_type: PacketType) -> Option<u64> {
        match packet_type {
            PacketType::Initial => self.initial,
            PacketType::Handshake => self.handshake,
            PacketType::ZeroRtt | PacketType::OneRtt => self.application,
            // Retry/Version Negotiation do not carry ordinary QUIC packet
            // numbers. Unknown is insufficient to identify a space safely.
            PacketType::Retry |
            PacketType::VersionNegotiation |
            PacketType::Unknown => None,
        }
    }

    const fn observe(&mut self, packet_type: PacketType, number: u64) {
        let slot = match packet_type {
            PacketType::Initial => &mut self.initial,
            PacketType::Handshake => &mut self.handshake,
            PacketType::ZeroRtt | PacketType::OneRtt => &mut self.application,
            PacketType::Retry |
            PacketType::VersionNegotiation |
            PacketType::Unknown => return,
        };
        *slot = Some(number);
    }
}

#[derive(Default, Debug)]
pub struct Datastore {
    pub vantage_point: VantagePoint,
    pub application_proto: ApplicationProto,
    pub session_id: Option<i64>,
    pub host: Option<String>,

    pub h2_client_settings: Http2Settings,
    pub h2_server_settings: Http2Settings,

    pub client_quic_tps: TransportParameters,

    pub last_event_time: f64,

    // There are several packet spaces, so store a map of all packets sent
    // according to packet space. Each space then contains a map of packet
    // header info keyed off the packet number.
    pub packet_sent: HashMap<PacketType, BTreeMap<u64, PacketInfoStub>>,
    pub packet_received: HashMap<PacketType, BTreeMap<u64, PacketInfoStub>>,

    // TODO: netlog packet sent happens after frame, so we can't detect the
    // packet type properly. Stick all in one bucket for now and accept we'll
    // alias packet numbers that overlap between spaced
    pub netlog_ack_sent_missing_packet: BTreeMap<PacketType, BTreeSet<u64>>,
    pub netlog_ack_received_missing_packet: BTreeMap<PacketType, BTreeSet<u64>>,

    pub packet_acked: Vec<QlogPointu64>,

    pub local_cwnd: Vec<QlogPointu64>,
    pub local_bytes_in_flight: Vec<QlogPointu64>,
    pub local_ssthresh: Vec<QlogPointu64>,
    pub local_pacing_rate: Vec<QlogPointu64>,
    pub local_delivery_rate: Vec<QlogPointu64>,
    pub local_send_rate: Vec<QlogPointu64>,
    pub local_ack_rate: Vec<QlogPointu64>,

    pub local_min_rtt: Vec<QlogPointRtt>,
    pub local_latest_rtt: Vec<QlogPointRtt>,
    pub local_smoothed_rtt: Vec<QlogPointRtt>,

    pub congestion_state_updates: Vec<(f64, u64, String)>,

    pub received_max_data: Vec<QlogPointu64>,

    /// Tracks per-stream max data: full history, current max, and cumulative
    /// sum.
    pub received_stream_max_data_tracker: StreamMaxTracker,

    pub sent_max_data: Vec<QlogPointu64>,

    /// Tracks per-stream max data: full history, current max, and cumulative
    /// sum.
    pub sent_stream_max_data_tracker: StreamMaxTracker,

    /// Tracks stream buffer reads: per-stream history, current max, and running
    /// sum.
    pub stream_buffer_reads_tracker: StreamBufferTracker,

    /// Tracks stream buffer writes: per-stream history, current max, and
    /// running sum.
    pub stream_buffer_writes_tracker: StreamBufferTracker,

    /// Tracks stream buffer dropped: per-stream history, current max, and
    /// running sum.
    pub stream_buffer_dropped_tracker: StreamBufferTracker,

    /// Records qlog stream bytes delivered to the user (distinct from the
    /// application).
    pub stream_buffer_user_tracker: StreamBufferTracker,

    /// Records qlog stream bytes delivered to the network (distinct from
    /// transport).
    pub stream_buffer_network_tracker: StreamBufferTracker,

    pub received_reset_stream: BTreeMap<u64, Vec<QuicFrame>>,
    pub sent_reset_stream: BTreeMap<u64, Vec<QuicFrame>>,

    pub received_stream_frames: BTreeMap<u64, Vec<(f64, StreamDatapoint)>>,
    pub received_stream_frames_count_based:
        BTreeMap<u64, Vec<(u64, StreamDatapoint)>>,
    pub total_received_stream_frame_count: u64,

    pub sent_stream_frames: BTreeMap<u64, Vec<(f64, QuicFrame)>>,
    pub sent_stream_frames_count_based: BTreeMap<u64, Vec<(u64, QuicFrame)>>,
    pub total_sent_stream_frame_count: u64,

    pub received_data_frames: BTreeMap<u64, Vec<(f64, u64)>>,
    pub received_data_frames_count_based: BTreeMap<u64, Vec<(u64, u64)>>,
    pub total_received_data_frame_count: u64,
    pub received_data_cumulative: BTreeMap<u64, Vec<(f64, u64)>>,
    pub received_data_cumulative_max: BTreeMap<u64, u64>,

    pub sent_data_frames: BTreeMap<u64, Vec<(f64, u64)>>,
    pub sent_data_frames_count_based: BTreeMap<u64, Vec<(u64, u64)>>,
    pub total_sent_data_frame_count: u64,
    pub sent_data_cumulative: BTreeMap<u64, Vec<(f64, u64)>>,
    pub sent_data_cumulative_max: BTreeMap<u64, u64>,

    pub http_requests: BTreeMap<u64, HttpRequestStub>,
    pub largest_data_frame_rx_length_global: u64,
    pub largest_data_frame_tx_length_global: u64,

    pub local_initial_stream_limits: InitialStreamLimits,
    pub peer_initial_stream_limits: InitialStreamLimits,

    pub h2_recv_window_updates: BTreeMap<u32, Vec<(f64, i32)>>,

    // Balance against incoming data to make it easier to plot in some cases
    pub h2_send_window_updates_balanced: BTreeMap<u32, Vec<(f64, i64)>>,

    // Just store raw updates for clear absolute values
    pub h2_send_window_updates_absolute: BTreeMap<u32, Vec<(f64, u64)>>,

    pub netlog_quic_server_window_blocked: BTreeMap<i64, Vec<f64>>,
    pub netlog_quic_client_side_window_updates: BTreeMap<i64, Vec<(f64, u64)>>,

    pub netlog_h2_stream_received_connection_cumulative: Vec<QlogPointu64>,
    pub netlog_quic_stream_received_connection_cumulative: Vec<QlogPointu64>,

    pub received_packets_netlog: Vec<(f64, PacketInfoStub)>,
    pub received_netlog_packet_numbers: NetlogPacketNumberProgress,
    pub discontinuous_packet_number_count: u64,

    pub netlog_ack_sent_missing_packets_raw: Vec<(f64, Vec<u64>)>,

    pub total_tx_ack: usize,
    pub max_ack_sent_missing_packets_size: usize,

    pub total_rx_ack: usize,
    pub max_ack_received_missing_packets_size: usize,

    pub quic_session_close: Option<QuicSessionClose>,
    pub h2_session_close: Option<H2SessionClose>,
}

/// Convert the difference, not the absolute timestamps, to floating point.
/// Chrome timestamps are unsigned; discovery can precede session creation.
///
/// Splitting the unsigned delta into 32-bit halves avoids overflow, sign-wrap,
/// and intermediate floating-point rounding of absolute timestamps.
fn netlog_relative_time(timestamp: u64, reference: u64) -> f64 {
    let bytes = timestamp.abs_diff(reference).to_be_bytes();
    let high = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let low = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let magnitude = f64::from(high).mul_add(4_294_967_296.0, f64::from(low));
    if timestamp < reference {
        -magnitude
    } else {
        magnitude
    }
}

fn checked_netlog_sum(
    previous: u64, increment: u64, field: &'static str,
) -> Result<u64, DatastoreError> {
    previous
        .checked_add(increment)
        .ok_or(DatastoreError::NetlogCounterOverflow { field })
}

fn checked_netlog_count(
    previous: usize, field: &'static str,
) -> Result<usize, DatastoreError> {
    previous
        .checked_add(1)
        .ok_or(DatastoreError::NetlogCounterOverflow { field })
}

fn cumulative_total(
    values: &[(f64, u64)], length: u64, field: &'static str,
) -> Result<u64, DatastoreError> {
    checked_netlog_sum(values.last().map_or(0, |value| value.1), length, field)
}

/// Initial receive limits are relative to the endpoint advertising them,
/// not the vantage point of the log. For bidirectional streams bit zero
/// selects the initiator; bit one identifies unidirectional streams.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InitialStreamLimits {
    bidi_local: u64,
    bidi_remote: u64,
    uni: u64,
}

impl InitialStreamLimits {
    fn update(&mut self, tp: &qlog::events::quic::ParametersSet) {
        self.bidi_local = tp
            .initial_max_stream_data_bidi_local
            .unwrap_or(self.bidi_local);
        self.bidi_remote = tp
            .initial_max_stream_data_bidi_remote
            .unwrap_or(self.bidi_remote);
        self.uni = tp.initial_max_stream_data_uni.unwrap_or(self.uni);
    }

    const fn for_stream(&self, stream_id: u64, advertiser: VantagePoint) -> u64 {
        if stream_id & 2 != 0 {
            return self.uni;
        }
        let client_initiated = stream_id & 1 == 0;
        let client_advertised = matches!(advertiser, VantagePoint::Client);
        if client_initiated == client_advertised {
            self.bidi_local
        } else {
            self.bidi_remote
        }
    }
}

impl VantagePoint {
    const fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// Whether Chrome recorded an ACK frame we transmitted or received.
#[derive(Clone, Copy)]
enum NetlogAckDirection {
    Sent,
    Received,
}

/// Direction and kind of netlog QUIC stream termination. All variants share
/// the same error-code lookup but update distinct request fields.
#[derive(Clone, Copy)]
enum NetlogQuicTermination {
    ResetReceived { offset: u64 },
    ResetSent { offset: u64 },
    StopSendingSent,
}

/// `WINDOW_UPDATE` and `RST_STREAM` have opposite local/peer directions.
#[derive(Clone, Copy)]
enum NetlogH2Direction {
    Sent,
    Received,
}

/// Whether an HTTP/3 frame was written by this endpoint or read from its peer.
#[derive(Clone, Copy)]
enum QlogH3Direction {
    Created,
    Parsed,
}

impl Datastore {
    /// Track missing ACK numbers while retaining their best-known packet
    /// space. If a received ACK has no preceding packet header, preserve its
    /// gaps in Unknown instead of discarding observations.
    fn record_netlog_ack_gaps(
        &mut self, direction: NetlogAckDirection, missing_packets: &[u64],
        event_time: f64,
    ) -> Result<(), DatastoreError> {
        match direction {
            NetlogAckDirection::Sent => {
                let count =
                    checked_netlog_count(self.total_tx_ack, "total_tx_ack")?;
                self.total_tx_ack = count;
                self.max_ack_sent_missing_packets_size = self
                    .max_ack_sent_missing_packets_size
                    .max(missing_packets.len());

                if !missing_packets.is_empty() {
                    self.netlog_ack_sent_missing_packets_raw
                        .push((event_time, missing_packets.to_vec()));
                    // The sent packet header is logged after its ACK frame,
                    // so its packet space is not known at this point.
                    self.netlog_ack_sent_missing_packet
                        .entry(PacketType::Unknown)
                        .or_default()
                        .extend(missing_packets.iter().copied());
                }
            },
            NetlogAckDirection::Received => {
                let count =
                    checked_netlog_count(self.total_rx_ack, "total_rx_ack")?;
                self.total_rx_ack = count;
                self.max_ack_received_missing_packets_size = self
                    .max_ack_received_missing_packets_size
                    .max(missing_packets.len());

                if !missing_packets.is_empty() {
                    // Chrome associates a received ACK with the last observed
                    // packet header. Missing header metadata must not cause
                    // the ACK gaps themselves to disappear.
                    let packet_type = self
                        .received_packets_netlog
                        .last()
                        .map_or(PacketType::Unknown, |(_, packet)| packet.ty);
                    self.netlog_ack_received_missing_packet
                        .entry(packet_type)
                        .or_default()
                        .extend(missing_packets.iter().copied());
                }
            },
        }
        Ok(())
    }

    /// Update the datastore from a parsed Chrome netlog event.
    ///
    /// # Errors
    /// Returns a typed overflow error instead of wrapping byte/counter values.
    /// A caller that encounters an error must discard the current datastore.
    pub fn consume_netlog_event(
        &mut self, session_start_time: u64, ev_hdr: &netlog::EventHeader,
        event: &netlog::Event, constants: &netlog::constants::Constants,
        stream_bind: &StreamBindingMap,
        h3_session_requests: Option<&[ReqOverH3]>,
    ) -> Result<(), DatastoreError> {
        match event {
            // nothing to do for this type just now
            netlog::Event::Http(_e) => (),
            netlog::Event::H2(e) => self.consume_netlog_h2(
                session_start_time,
                ev_hdr,
                e,
                constants,
                stream_bind,
            )?,

            netlog::Event::H3(e) => self.consume_netlog_h3(
                session_start_time,
                ev_hdr,
                e,
                h3_session_requests,
            )?,
            netlog::Event::Quic(e) => self.consume_netlog_quic(
                session_start_time,
                ev_hdr,
                e,
                constants,
            )?,
        }
        Ok(())
    }

    fn record_netlog_received_quic_stream_frame(
        &mut self, params: &quic::QuicSessionStreamFrameReceivedParams,
        event_time: f64,
    ) -> Result<(), DatastoreError> {
        // Validate all counters before mutating any of this event's
        // state.
        let next_count = checked_netlog_sum(
            self.total_received_stream_frame_count,
            1,
            "total_received_stream_frame_count",
        )?;
        let cumulative = cumulative_total(
            &self.netlog_quic_stream_received_connection_cumulative,
            params.length,
            "netlog_quic_stream_received_connection_cumulative",
        )?;

        let s = self
            .received_stream_frames
            .entry(params.stream_id)
            .or_default();
        s.push((event_time, StreamDatapoint {
            offset: params.offset,
            length: params.length,
        }));

        let s = self
            .received_stream_frames_count_based
            .entry(params.stream_id)
            .or_default();
        s.push((self.total_received_stream_frame_count, StreamDatapoint {
            offset: params.offset,
            length: params.length,
        }));

        self.total_received_stream_frame_count = next_count;

        if params.fin {
            if let Some(req) = self.http_requests.get_mut(&params.stream_id) {
                req.time_fin_rx = Some(event_time);
            }
        }

        self.netlog_quic_stream_received_connection_cumulative
            .push((event_time, cumulative));
        Ok(())
    }

    fn record_netlog_received_packet_header(
        &mut self,
        params: &quic::QuicSessionUnauthenticatedPacketHeaderReceivedParams,
        event_time: f64,
    ) -> Result<(), DatastoreError> {
        let packet_type = PacketType::from_netlog_packet_header(
            &params.header_format,
            params.long_header_type.as_deref(),
        );

        // The most recently logged packet might be in a different
        // QUIC packet-number space. Compare only consecutive
        // observations in the *same* space to avoid false gaps.
        if let Some(previous) =
            self.received_netlog_packet_numbers.previous(packet_type)
        {
            if previous.abs_diff(params.packet_number) > 1 {
                self.discontinuous_packet_number_count = checked_netlog_sum(
                    self.discontinuous_packet_number_count,
                    1,
                    "discontinuous_packet_number_count",
                )?;
            }
        }

        // Record the latest number only after validating overflow;
        // rejected events must not alter progress or packet maps.
        self.received_netlog_packet_numbers
            .observe(packet_type, params.packet_number);

        let packet_info = PacketInfoStub {
            acked: None,
            raw: None,
            created_time: event_time,
            send_at_time: None,
            ty: packet_type,
            number: params.packet_number,
        };

        self.received_packets_netlog
            .push((event_time, packet_info.clone()));

        let s = self.packet_received.entry(packet_type).or_default();

        s.insert(params.packet_number, packet_info);
        Ok(())
    }

    fn record_netlog_sent_packet(
        &mut self, params: &quic::QuicSessionPacketSentParams, event_time: f64,
    ) {
        let packet_type =
            PacketType::from_netlog_encryption_level(&params.encryption_level);

        let packet_info = PacketInfoStub {
            acked: None,
            raw: None,
            created_time: event_time,
            send_at_time: None,
            ty: packet_type,
            number: params.packet_number,
        };

        let s = self.packet_sent.entry(packet_type).or_default();

        s.insert(params.packet_number, packet_info);

        // Resolve any ACK gaps logged before their packet metadata.
        if let Some(pending) = self
            .netlog_ack_sent_missing_packet
            .remove(&PacketType::Unknown)
        {
            if !pending.is_empty() {
                self.netlog_ack_sent_missing_packet
                    .entry(packet_type)
                    .or_default()
                    .extend(pending);
            }
        }
    }

    /// QUIC resets and `STOP_SENDING` are meaningful only for request streams
    /// already discovered by the headers parser. Preserve that invariant.
    fn record_netlog_quic_stream_termination(
        &mut self, stream_id: u64, error_code: u64,
        termination: NetlogQuicTermination,
        constants: &netlog::constants::Constants,
    ) {
        let Some(req) = self.http_requests.get_mut(&stream_id) else {
            return;
        };

        // Chromium records the unsigned code, whereas the constants table
        // uses i64. Large codes still survive intact without bogus labels.
        let friendly = i64::try_from(error_code)
            .ok()
            .and_then(|code| constants.quic_rst_stream_error_id_keyed.get(&code))
            .cloned();
        match termination {
            NetlogQuicTermination::ResetReceived { offset } => {
                req.quic_stream_reset_received = Some(QuicStreamReset {
                    offset,
                    quic_rst_stream_error: error_code,
                    quic_rst_stream_error_friendly: friendly,
                });
            },
            NetlogQuicTermination::ResetSent { offset } => {
                req.quic_stream_reset_sent = Some(QuicStreamReset {
                    offset,
                    quic_rst_stream_error: error_code,
                    quic_rst_stream_error_friendly: friendly,
                });
            },
            NetlogQuicTermination::StopSendingSent => {
                req.quic_stream_stop_sending_sent = Some(QuicStreamStopSending {
                    quic_rst_stream_error: error_code,
                    quic_rst_stream_error_friendly: friendly,
                });
            },
        }
    }

    fn consume_netlog_quic(
        &mut self, session_start_time: u64, ev_hdr: &netlog::EventHeader,
        ev: &quic::Event, constants: &netlog::constants::Constants,
    ) -> Result<(), DatastoreError> {
        let rel_event_time =
            netlog_relative_time(ev_hdr.time_num, session_start_time);

        match ev {
            QuicSessionStreamFrameReceived(e) => self
                .record_netlog_received_quic_stream_frame(
                    &e.params,
                    rel_event_time,
                )?,

            QuicSessionUnauthenticatedPacketHeaderReceived(e) => self
                .record_netlog_received_packet_header(
                    &e.params,
                    rel_event_time,
                )?,

            QuicSessionPacketSent(e) =>
                self.record_netlog_sent_packet(&e.params, rel_event_time),

            QuicSessionAckFrameSent(e) => self.record_netlog_ack_gaps(
                NetlogAckDirection::Sent,
                &e.params.missing_packets,
                rel_event_time,
            )?,

            QuicSessionAckFrameReceived(e) => self.record_netlog_ack_gaps(
                NetlogAckDirection::Received,
                &e.params.missing_packets,
                rel_event_time,
            )?,

            QuicSessionClosed(e) => {
                self.quic_session_close = Some(QuicSessionClose {
                    session_id: self.session_id.unwrap_or(-1),
                    sni: self
                        .host
                        .clone()
                        .unwrap_or_else(|| "ERROR UNKNOWN".to_owned()),
                    details: e.params.details.clone(),
                    from_peer: e.params.from_peer,
                    quic_error: e.params.quic_error,
                    quic_error_pretty: NaOption::new(
                        constants
                            .quic_error_id_keyed
                            .get(&e.params.quic_error)
                            .cloned(),
                    ),
                });
            },

            QuicSessionRstStreamFrameReceived(e) => self
                .record_netlog_quic_stream_termination(
                    e.params.stream_id,
                    e.params.quic_rst_stream_error,
                    NetlogQuicTermination::ResetReceived {
                        offset: e.params.offset,
                    },
                    constants,
                ),

            QuicSessionRstStreamFrameSent(e) => self
                .record_netlog_quic_stream_termination(
                    e.params.stream_id,
                    e.params.quic_rst_stream_error,
                    NetlogQuicTermination::ResetSent {
                        offset: e.params.offset,
                    },
                    constants,
                ),

            QuicSessionStopSendingFrameSent(e) => self
                .record_netlog_quic_stream_termination(
                    e.params.stream_id,
                    e.params.quic_rst_stream_error,
                    NetlogQuicTermination::StopSendingSent,
                    constants,
                ),

            QuicSessionBlockedFrameReceived(e) => {
                let s = self
                    .netlog_quic_server_window_blocked
                    .entry(e.params.stream_id)
                    .or_default();
                s.push(rel_event_time);
            },

            QuicSessionWindowUpdateFrameSent(e) => {
                let s = self
                    .netlog_quic_client_side_window_updates
                    .entry(e.params.stream_id)
                    .or_default();

                s.push((rel_event_time, e.params.byte_offset));
            },

            QuicSessionTransportParametersSent(e) => {
                self.client_quic_tps =
                    e.params.quic_transport_parameters.clone().into();

                let s = self
                    .netlog_quic_client_side_window_updates
                    .entry(-1)
                    .or_default();

                s.push((
                    rel_event_time,
                    self.client_quic_tps.initial_max_data.unwrap_or_default(),
                ));
            },

            // ignore the other events for now
            QuicSession(_) | QuicSessionTransportParametersReceived(_) => (),
        }
        Ok(())
    }

    /// Record received HTTP/2 or HTTP/3 DATA with the same per-stream
    /// semantics. Only HTTP/2 additionally maintains a connection-wide total.
    ///
    /// Validate every fallible counter first: a rejected frame must not leave
    /// updated request timing or any partial stream history behind.
    fn record_netlog_received_data(
        &mut self, proto: ApplicationProto, stream_id: u64, length: u64,
        event_time: f64,
    ) -> Result<(), DatastoreError> {
        let next_count = checked_netlog_sum(
            self.total_received_data_frame_count,
            1,
            "total_received_data_frame_count",
        )?;
        let cumulative = cumulative_total(
            self.received_data_cumulative
                .get(&stream_id)
                .map_or(&[], Vec::as_slice),
            length,
            "received_data_cumulative",
        )?;
        let connection_total = match proto {
            ApplicationProto::Http2 => Some(cumulative_total(
                &self.netlog_h2_stream_received_connection_cumulative,
                length,
                "netlog_h2_stream_received_connection_cumulative",
            )?),
            ApplicationProto::Http3 => None,
        };

        let previous_count = self.total_received_data_frame_count;
        let req = self.get_or_insert_http_req(stream_id);
        req.time_first_data_rx.get_or_insert(event_time);
        req.time_last_data_rx = Some(event_time);
        req.time_data_rx_set.push((event_time, length));
        req.server_transferred_bytes = std::cmp::max(
            req.server_transferred_bytes,
            NaOption::new(Some(cumulative)),
        );

        self.largest_data_frame_rx_length_global =
            self.largest_data_frame_rx_length_global.max(length);
        self.received_data_frames
            .entry(stream_id)
            .or_default()
            .push((event_time, length));
        self.received_data_frames_count_based
            .entry(stream_id)
            .or_default()
            .push((previous_count, length));
        self.total_received_data_frame_count = next_count;
        self.received_data_cumulative
            .entry(stream_id)
            .or_default()
            .push((event_time, cumulative));
        let maximum = self
            .received_data_cumulative_max
            .entry(stream_id)
            .or_default();
        *maximum = (*maximum).max(cumulative);

        if let Some(total) = connection_total {
            self.netlog_h2_stream_received_connection_cumulative
                .push((event_time, total));
        }
        Ok(())
    }

    /// HTTP/2 outbound DATA contributes to the local upload stream counters
    /// and consumes send-window credit, unlike a received DATA frame.
    fn record_netlog_sent_h2_data(
        &mut self, stream_id: u32, size: u32, event_time: f64,
    ) -> Result<(), DatastoreError> {
        let stream_id_u64 = u64::from(stream_id);
        let length = u64::from(size);
        let next_count = checked_netlog_sum(
            self.total_sent_data_frame_count,
            1,
            "total_sent_data_frame_count",
        )?;
        let cumulative = cumulative_total(
            self.sent_data_cumulative
                .get(&stream_id_u64)
                .map_or(&[], Vec::as_slice),
            length,
            "sent_data_cumulative",
        )?;

        let previous_count = self.total_sent_data_frame_count;
        let req = self.get_or_insert_http_req(stream_id_u64);
        req.time_first_data_tx.get_or_insert(event_time);
        req.time_last_data_tx = Some(event_time);
        req.time_data_tx_set.push((event_time, length));
        req.client_transferred_bytes = std::cmp::max(
            req.client_transferred_bytes,
            NaOption::new(Some(cumulative)),
        );

        self.largest_data_frame_tx_length_global =
            self.largest_data_frame_tx_length_global.max(length);
        self.sent_data_frames
            .entry(stream_id_u64)
            .or_default()
            .push((event_time, length));
        self.sent_data_frames_count_based
            .entry(stream_id_u64)
            .or_default()
            .push((previous_count, length));
        self.total_sent_data_frame_count = next_count;
        self.h2_send_window_updates_balanced
            .entry(stream_id)
            .or_default()
            .push((event_time, -i64::from(size)));
        self.sent_data_cumulative
            .entry(stream_id_u64)
            .or_default()
            .push((event_time, cumulative));
        let maximum = self
            .sent_data_cumulative_max
            .entry(stream_id_u64)
            .or_default();
        *maximum = (*maximum).max(cumulative);
        Ok(())
    }

    fn consume_netlog_h3(
        &mut self, session_start_time: u64, ev_hdr: &netlog::EventHeader,
        ev: &h3::Event, h3_session_requests: Option<&[ReqOverH3]>,
    ) -> Result<(), DatastoreError> {
        let rel_event_time =
            netlog_relative_time(ev_hdr.time_num, session_start_time);

        match ev {
            Http3PriorityUpdateSent(e) => {
                let req =
                    self.get_or_insert_http_req(e.params.prioritized_element_id);
                req.priority_updates
                    .push(e.params.priority_field_value.clone());
            },

            Http3HeadersSent(e) => {
                let req = self.get_or_insert_http_req(e.params.stream_id);
                req.time_first_headers_tx.get_or_insert(rel_event_time);
                req.set_request_info_from_netlog(&e.params.headers);

                if let Some(reqs) = h3_session_requests {
                    for r in reqs {
                        if let Some(stream_id) = r.quic_stream_id {
                            if stream_id == e.params.stream_id {
                                // Request discovery may precede session start.
                                req.time_discovery = Some(netlog_relative_time(
                                    r.discover_time,
                                    session_start_time,
                                ));
                                break;
                            }
                        }
                    }
                }
            },

            // TODO: this is reception of headers frame, before the field
            // section is decoded. Ignore for now and just use the decoded
            // event.
            Http3HeadersReceived(_) => (),

            Http3HeadersDecoded(e) => {
                let req = self.get_or_insert_http_req(e.params.stream_id);
                req.time_first_headers_rx.get_or_insert(rel_event_time);
                req.set_response_info_from_netlog(&e.params.headers);
            },

            Http3DataFrameReceived(e) => self.record_netlog_received_data(
                ApplicationProto::Http3,
                e.params.stream_id,
                e.params.payload_length,
                rel_event_time,
            )?,

            // TODO: track outbound HTTP/3 DATA once netlog exposes the needed
            // accounting.
            Http3DataSent(_) => (),
        }
        Ok(())
    }

    /// `WINDOW_UPDATE` received from the peer increases our send credit;
    /// `WINDOW_UPDATE` we sent increases the peer's send credit instead.
    /// Neither invalid nor zero deltas are valid protocol increments.
    fn record_netlog_h2_window_update(
        &mut self, direction: NetlogH2Direction, stream_id: u32, delta: i32,
        event_time: f64,
    ) {
        let Some(increment) =
            u64::try_from(delta).ok().filter(|increment| *increment > 0)
        else {
            let direction_label = match direction {
                NetlogH2Direction::Received => "received",
                NetlogH2Direction::Sent => "sent",
            };
            error!(
                "ignoring nonpositive HTTP/2 {direction_label} WINDOW_UPDATE increment: {delta}"
            );
            return;
        };

        match direction {
            NetlogH2Direction::Received => {
                self.h2_send_window_updates_balanced
                    .entry(stream_id)
                    .or_default()
                    .push((event_time, i64::from(delta)));
                self.h2_send_window_updates_absolute
                    .entry(stream_id)
                    .or_default()
                    .push((event_time, increment));
            },
            NetlogH2Direction::Sent => {
                self.h2_recv_window_updates
                    .entry(stream_id)
                    .or_default()
                    .push((event_time, delta));
            },
        }
    }

    /// Netlog request resets are recorded only for known request streams.
    /// The received `RESET_STREAM` event provides no description text.
    fn record_netlog_h2_stream_reset(
        &mut self, direction: NetlogH2Direction, stream_id: u32,
        error_code: &str, description: Option<&str>,
    ) {
        let Some(req) = self.http_requests.get_mut(&u64::from(stream_id)) else {
            return;
        };
        let reset = H2StreamReset {
            error: error_code.to_owned(),
            description: description.unwrap_or_default().to_owned(),
        };
        match direction {
            NetlogH2Direction::Sent => req.h2_stream_reset_sent = Some(reset),
            NetlogH2Direction::Received =>
                req.h2_stream_reset_receive = Some(reset),
        }
    }

    /// The netlog close record carries the native net error and, when
    /// available, a human-readable Chromium error name.
    fn record_netlog_h2_session_close(
        &mut self, params: &h2::Http2SessionCloseParams,
        constants: &netlog::constants::Constants,
    ) {
        self.h2_session_close = Some(H2SessionClose {
            session_id: self.session_id.unwrap_or(-1),
            sni: self
                .host
                .clone()
                .unwrap_or_else(|| "ERROR UNKNOWN".to_owned()),
            details: params.description.clone(),
            net_err: params.net_error,
            net_err_pretty: NaOption::new(
                constants.net_error_id_keyed.get(&params.net_error).cloned(),
            ),
        });
    }

    fn consume_netlog_h2(
        &mut self, session_start_time: u64, ev_hdr: &netlog::EventHeader,
        ev: &h2::Event, constants: &netlog::constants::Constants,
        stream_bind: &StreamBindingMap,
    ) -> Result<(), DatastoreError> {
        let rel_event_time =
            netlog_relative_time(ev_hdr.time_num, session_start_time);

        match ev {
            Http2SessionSendSettings(e) => {
                match Http2Settings::try_from(e.params.settings.as_slice()) {
                    Ok(v) => self.h2_client_settings = v,

                    Err(e) => error!("{}", e),
                }
            },

            Http2SessionRecvSetting(e) => {
                if let Some(id) = h2::parse_recv_setting_id(&e.params.id) {
                    self.h2_server_settings.set_from_wire(id, e.params.value);
                } else {
                    error!("parsing H2 setting {:?}", e.params);
                }
            },
            Http2SessionSendHeaders(e) => {
                let req =
                    self.get_or_insert_http_req(u64::from(e.params.stream_id));
                req.time_first_headers_tx.get_or_insert(rel_event_time);
                req.set_request_info_from_netlog(&e.params.headers);

                if let Some(sb) = stream_bind.get(&e.params.source_dependency.id)
                {
                    // Discovery can precede the session's creation.
                    req.time_discovery = Some(netlog_relative_time(
                        sb.request_discovery_time,
                        session_start_time,
                    ));
                }
            },

            Http2SessionRecvHeaders(e) => {
                let req =
                    self.get_or_insert_http_req(u64::from(e.params.stream_id));
                req.time_first_headers_rx.get_or_insert(rel_event_time);
                req.set_response_info_from_netlog(&e.params.headers);
            },

            Http2SessionRecvData(e) => self.record_netlog_received_data(
                ApplicationProto::Http2,
                u64::from(e.params.stream_id),
                u64::from(e.params.size),
                rel_event_time,
            )?,

            Http2SessionSendData(e) => self.record_netlog_sent_h2_data(
                e.params.stream_id,
                e.params.size,
                rel_event_time,
            )?,

            Http2SessionRecvWindowUpdate(e) => self
                .record_netlog_h2_window_update(
                    NetlogH2Direction::Received,
                    e.params.stream_id,
                    e.params.delta,
                    rel_event_time,
                ),

            Http2SessionSendWindowUpdate(e) => self
                .record_netlog_h2_window_update(
                    NetlogH2Direction::Sent,
                    e.params.stream_id,
                    e.params.delta,
                    rel_event_time,
                ),

            Http2SessionClose(e) =>
                self.record_netlog_h2_session_close(&e.params, constants),

            Http2SessionSendRstStream(e) => self.record_netlog_h2_stream_reset(
                NetlogH2Direction::Sent,
                e.params.stream_id,
                &e.params.error_code,
                Some(&e.params.description),
            ),

            Http2SessionRecvRstStream(e) => self.record_netlog_h2_stream_reset(
                NetlogH2Direction::Received,
                e.params.stream_id,
                &e.params.error_code,
                None,
            ),

            // ignore the other events for now
            Http2Session(_) => (),
            Http2SessionInitialized(_) => (),
            Http2SessionUpdateRecvWindow(_) => (),
            Http2SessionUpdateSendWindow(_) => (),
            Http2SessionUpdateStreamsSendWindowSize(_) => (),
            Http2SessionStalledMaxStreams(_) => (),

            Http2StreamUpdateSendWindow(_) => (),
            Http2StreamUpdateRecvWindow(_) => (),
            Http2StreamStalledByStreamSendWindow(_) => (),
            Http2SessionPing(_) => (),

            Http2SessionRecvGoaway(_) => (),
        }
        Ok(())
    }

    /// Consume one typed qlog event.
    ///
    /// # Errors
    /// Returns the tracker overflow. A multi-frame event may already have
    /// updated unrelated fields; discard the datastore on failure. Both log
    /// constructors and the browser's transactional builder do so.
    pub fn consume_qlog_event(
        &mut self, event: &qlog::events::Event, process_acks: bool,
    ) -> Result<(), TrackerError> {
        let ev_time = event.time;

        match &event.data {
            EventData::QuicParametersSet(v) =>
                self.consume_qlog_transport_parameters_set(v),

            EventData::QuicPacketReceived(v) =>
                self.consume_qlog_packet_received(v, ev_time, process_acks)?,

            EventData::QuicPacketSent(v) =>
                self.consume_qlog_packet_sent(v, ev_time)?,

            EventData::QuicStreamDataMoved(v) =>
                self.consume_qlog_stream_data_moved(v, ev_time)?,

            EventData::QuicMetricsUpdated(v) =>
                self.consume_qlog_metrics_updated(v, ev_time),

            EventData::QuicCongestionStateUpdated(v) =>
                self.consume_qlog_congestion_state_updated(v, ev_time),

            EventData::Http3FrameCreated(v) => self.consume_qlog_h3_frame(
                v.stream_id,
                &v.frame,
                v.length,
                ev_time,
                QlogH3Direction::Created,
            ),

            EventData::Http3FrameParsed(v) => self.consume_qlog_h3_frame(
                v.stream_id,
                &v.frame,
                v.length,
                ev_time,
                QlogH3Direction::Parsed,
            ),

            _ => (), // trace!("skipping {:?}", event.data),
        }
        if ev_time > self.last_event_time {
            self.last_event_time = ev_time;
        }
        Ok(())
    }

    /// Builds a datastore from qlog JSON events.
    ///
    /// # Errors
    /// Returns an error for unsupported vantage points or tracker arithmetic
    /// overflow.
    pub fn with_qlog_events(
        events: &[qlog::events::Event], vantage_point: &qlog::VantagePointType,
        process_acks: bool,
    ) -> Result<Self, DatastoreError> {
        let vp = VantagePoint::try_from(vantage_point)?;

        let mut ds = Datastore {
            vantage_point: vp,
            ..Default::default()
        };

        for event in events {
            ds.consume_qlog_event(event, process_acks)?;
        }

        ds.hydrate_http_requests();
        ds.finalize();

        Ok(ds)
    }

    pub fn finalize(&mut self) {
        if let Some(last) = self.local_cwnd.last().cloned() {
            self.local_cwnd.push((self.last_event_time, last.1));
        }

        if let Some(last) = self.local_pacing_rate.last().cloned() {
            trace!("pushing last {:?}", last);
            self.local_pacing_rate.push((self.last_event_time, last.1));
        }
    }

    pub fn hydrate_http_requests(&mut self) {
        for req in self.http_requests.values_mut() {
            req.calculate_deltas();
            req.calculate_upload_download_rate();
        }
    }

    fn consume_qlog_transport_parameters_set(
        &mut self, tp: &qlog::events::quic::ParametersSet,
    ) {
        let (limits, connection) = match tp.initiator {
            Some(TransportInitiator::Local) => (
                &mut self.local_initial_stream_limits,
                &mut self.sent_max_data,
            ),
            Some(TransportInitiator::Remote) => (
                &mut self.peer_initial_stream_limits,
                &mut self.received_max_data,
            ),
            None => {
                trace!("ignoring transport parameters with no initiator");
                return;
            },
        };
        if let Some(max_data) = tp.initial_max_data {
            connection.push((0.0, max_data));
        }
        limits.update(tp);
    }

    /// ACKs in a 1-RTT packet acknowledge the shared application-data
    /// packet-number space, including packets sent with 0-RTT keys.
    fn mark_qlog_acks(
        &mut self, packet_type: PacketType,
        ranges: &[qlog::events::quic::AckRange],
    ) {
        let spaces: &[PacketType] = match packet_type {
            PacketType::Initial => &[PacketType::Initial],
            PacketType::Handshake => &[PacketType::Handshake],
            PacketType::OneRtt => &[PacketType::ZeroRtt, PacketType::OneRtt],
            _ => return,
        };
        for range in ranges {
            // Deserialized external logs can contain reversed endpoints.
            // Ignore that malformed range without losing valid sibling ranges.
            if range.start > range.end {
                log::warn!("ignoring reversed qlog ACK range {range}");
                continue;
            }
            for space in spaces {
                if let Some(packets) = self.packet_sent.get_mut(space) {
                    for (_, packet) in
                        packets.range_mut(range.as_range_inclusive())
                    {
                        packet.acked = Some(true);
                    }
                }
            }
        }
    }

    fn consume_qlog_packet_received(
        &mut self, pr: &qlog::events::quic::PacketReceived, ev_time: f64,
        process_acks: bool,
    ) -> Result<(), TrackerError> {
        let packet_type =
            PacketType::from_qlog_packet_type(&pr.header.packet_type);
        if let Some(number) = pr.header.packet_number {
            self.packet_received
                .entry(packet_type)
                .or_default()
                .entry(number)
                .or_insert_with(|| PacketInfoStub {
                    acked: None,
                    raw: pr.raw.clone(),
                    created_time: ev_time,
                    send_at_time: None,
                    ty: packet_type,
                    number,
                });
        }
        if let Some(frames) = &pr.frames {
            for frame in frames {
                match frame {
                    QuicFrame::Ack {
                        acked_ranges: Some(ranges),
                        ..
                    } if process_acks => self.mark_qlog_acks(packet_type, ranges),

                    QuicFrame::MaxData { maximum, .. } => {
                        self.received_max_data.push((ev_time, *maximum));
                    },

                    QuicFrame::MaxStreamData {
                        stream_id, maximum, ..
                    } => {
                        let init_val = self
                            .peer_initial_stream_limits
                            .for_stream(*stream_id, self.vantage_point.peer());
                        self.received_stream_max_data_tracker
                            .update(*stream_id, *maximum, ev_time, init_val)?;
                    },

                    QuicFrame::ResetStream { stream_id, .. } => {
                        let s = self
                            .received_reset_stream
                            .entry(*stream_id)
                            .or_default();
                        s.push(frame.clone());
                    },

                    QuicFrame::Stream {
                        stream_id,
                        offset,
                        raw,
                        ..
                    } => {
                        let length = raw
                            .as_ref()
                            .and_then(|raw| raw.payload_length)
                            .unwrap_or_default();
                        let s = self
                            .received_stream_frames
                            .entry(*stream_id)
                            .or_default();
                        s.push((ev_time, StreamDatapoint {
                            length,
                            offset: offset.unwrap_or_default(),
                        }));

                        let s = self
                            .received_stream_frames_count_based
                            .entry(*stream_id)
                            .or_default();
                        s.push((
                            self.total_received_stream_frame_count,
                            StreamDatapoint {
                                length,
                                offset: offset.unwrap_or_default(),
                            },
                        ));

                        self.total_received_stream_frame_count += 1;
                    },

                    _ => (),
                }
            }
        }
        Ok(())
    }

    fn consume_qlog_packet_sent(
        &mut self, ps: &qlog::events::quic::PacketSent, ev_time: f64,
    ) -> Result<(), TrackerError> {
        // A missing packet number prevents indexing the packet, not
        // processing other frame observations in the same record.
        if let Some(number) = ps.header.packet_number {
            let packet_type =
                PacketType::from_qlog_packet_type(&ps.header.packet_type);
            self.packet_sent
                .entry(packet_type)
                .or_default()
                .entry(number)
                .or_insert_with(|| PacketInfoStub {
                    acked: None,
                    raw: ps.raw.clone(),
                    created_time: ev_time,
                    send_at_time: ps.send_at_time,
                    ty: packet_type,
                    number,
                });
        }

        // Prefer to use the packet_sent send_at_time if it exists. Otherwise
        // fallback to the event time.
        let event_time = ps.send_at_time.unwrap_or(ev_time);

        if let Some(frames) = &ps.frames {
            for frame in frames {
                match frame {
                    QuicFrame::Ack { .. } => {
                        // TODO
                    },

                    QuicFrame::MaxData { maximum, .. } => {
                        self.sent_max_data.push((event_time, *maximum));
                    },

                    QuicFrame::MaxStreamData {
                        stream_id, maximum, ..
                    } => {
                        let init_val = self
                            .local_initial_stream_limits
                            .for_stream(*stream_id, self.vantage_point);
                        self.sent_stream_max_data_tracker
                            .update(*stream_id, *maximum, event_time, init_val)?;
                    },

                    QuicFrame::ResetStream { stream_id, .. } => {
                        let s =
                            self.sent_reset_stream.entry(*stream_id).or_default();
                        s.push(frame.clone());
                    },

                    QuicFrame::Stream { stream_id, .. } => {
                        let s = self
                            .sent_stream_frames
                            .entry(*stream_id)
                            .or_default();
                        s.push((event_time, frame.clone()));

                        let s = self
                            .sent_stream_frames_count_based
                            .entry(*stream_id)
                            .or_default();
                        s.push((
                            self.total_sent_stream_frame_count,
                            frame.clone(),
                        ));

                        self.total_sent_stream_frame_count += 1;
                    },

                    QuicFrame::DataBlocked { limit, .. } => {
                        trace!(
                            "todo DATA_BLOCKED t={} limit={}",
                            event_time,
                            limit
                        );
                    },

                    QuicFrame::StreamDataBlocked {
                        stream_id, limit, ..
                    } => {
                        trace!(
                            "todo STREAM_DATA_BLOCKED t={} stream={} limit={}",
                            event_time,
                            stream_id,
                            limit
                        );
                    },

                    _ => (),
                }
            }
        }
        Ok(())
    }

    fn consume_qlog_stream_data_moved(
        &mut self, dm: &qlog::events::quic::StreamDataMoved, ev_time: f64,
    ) -> Result<(), TrackerError> {
        if let Some(recipient) = &dm.to {
            let tracker = match recipient {
                qlog::events::DataRecipient::Application =>
                    &mut self.stream_buffer_reads_tracker,
                qlog::events::DataRecipient::Transport =>
                    &mut self.stream_buffer_writes_tracker,
                qlog::events::DataRecipient::Dropped =>
                    &mut self.stream_buffer_dropped_tracker,
                qlog::events::DataRecipient::User =>
                    &mut self.stream_buffer_user_tracker,
                qlog::events::DataRecipient::Network =>
                    &mut self.stream_buffer_network_tracker,
            };

            if let Some(stream_id) = dm.stream_id {
                if let Some(raw) = &dm.raw {
                    if let (Some(offset), Some(length)) = (dm.offset, raw.length)
                    {
                        tracker.update(
                            stream_id,
                            StreamAccess { offset, length },
                            ev_time,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    fn consume_qlog_metrics_updated(
        &mut self, mu: &qlog::events::quic::RecoveryMetricsUpdated, ev_time: f64,
    ) {
        if let Some(cwnd) = mu.congestion_window {
            self.local_cwnd.push((ev_time, cwnd));
        }

        if let Some(bif) = mu.bytes_in_flight {
            self.local_bytes_in_flight.push((ev_time, bif));
        }

        if let Some(rtt) = mu.min_rtt {
            self.local_min_rtt.push((ev_time, rtt));
        }

        if let Some(rtt) = mu.latest_rtt {
            self.local_latest_rtt.push((ev_time, rtt));
        }

        if let Some(rtt) = mu.smoothed_rtt {
            self.local_smoothed_rtt.push((ev_time, rtt));
        }

        if let Some(thresh) = mu.ssthresh {
            self.local_ssthresh.push((ev_time, thresh));
        }

        if let Some(pacing_rate) = mu.pacing_rate {
            // The standard qlog pacing_rate is bits/sec; the plot and the
            // Cloudflare extension rates use bytes/sec.
            self.local_pacing_rate.push((ev_time, pacing_rate / 8));
        }

        // Extract rate metrics from ex_data
        if let Some(rate) =
            mu.ex_data.get("cf_delivery_rate").and_then(|v| v.as_u64())
        {
            self.local_delivery_rate.push((ev_time, rate));
        }

        if let Some(rate) =
            mu.ex_data.get("cf_send_rate").and_then(|v| v.as_u64())
        {
            self.local_send_rate.push((ev_time, rate));
        }

        if let Some(rate) = mu.ex_data.get("cf_ack_rate").and_then(|v| v.as_u64())
        {
            self.local_ack_rate.push((ev_time, rate));
        }
    }

    fn consume_qlog_congestion_state_updated(
        &mut self, csu: &qlog::events::quic::CongestionStateUpdated, ev_time: f64,
    ) {
        if let Some(point) = self.local_cwnd.last() {
            // give this a virtual y-value of the last cwnd value recorded, we
            // can choose to use it or not later.
            self.congestion_state_updates.push((
                ev_time,
                point.1,
                csu.new.clone(),
            ));
        }
    }

    fn get_or_insert_http_req(&mut self, stream_id: u64) -> &mut HttpRequestStub {
        let actor = self.vantage_point.into();
        self.http_requests
            .entry(stream_id)
            .or_insert_with(|| HttpRequestStub {
                stream_id,
                request_actor: actor,
                ..Default::default()
            })
    }

    /// Record an HTTP/3 frame with the same semantics regardless of source
    /// endpoint. Client/server vantage determines which headers represent
    /// requests and responses; only the client records parsed DATA in the
    /// received-frame series.
    fn consume_qlog_h3_frame(
        &mut self, stream_id: u64, frame: &Http3Frame, length: Option<u64>,
        ev_time: f64, direction: QlogH3Direction,
    ) {
        match frame {
            Http3Frame::Headers { headers, .. } => {
                let vantage = self.vantage_point;
                let req = self.get_or_insert_http_req(stream_id);
                match direction {
                    QlogH3Direction::Created => {
                        req.time_first_headers_tx.get_or_insert(ev_time);
                    },
                    QlogH3Direction::Parsed => {
                        req.time_first_headers_rx.get_or_insert(ev_time);
                    },
                }
                match (direction, vantage) {
                    (QlogH3Direction::Created, VantagePoint::Client) |
                    (QlogH3Direction::Parsed, VantagePoint::Server) =>
                        req.set_request_info_from_qlog(headers),
                    (QlogH3Direction::Created, VantagePoint::Server) |
                    (QlogH3Direction::Parsed, VantagePoint::Client) =>
                        req.set_response_info_from_qlog(headers),
                }
            },

            Http3Frame::Data { .. } => {
                let length = length.unwrap_or_default();
                let req = self.get_or_insert_http_req(stream_id);
                match direction {
                    QlogH3Direction::Created => {
                        req.time_first_data_tx.get_or_insert(ev_time);
                        req.time_last_data_tx = Some(ev_time);
                        req.time_data_tx_set.push((ev_time, length));
                        self.largest_data_frame_tx_length_global =
                            self.largest_data_frame_tx_length_global.max(length);
                    },
                    QlogH3Direction::Parsed => {
                        req.time_first_data_rx.get_or_insert(ev_time);
                        req.time_last_data_rx = Some(ev_time);
                        req.time_data_rx_set.push((ev_time, length));
                        self.largest_data_frame_rx_length_global =
                            self.largest_data_frame_rx_length_global.max(length);
                        if let VantagePoint::Client = self.vantage_point {
                            self.received_data_frames
                                .entry(stream_id)
                                .or_default()
                                .push((ev_time, length));
                        }
                    },
                }
            },

            Http3Frame::PriorityUpdate {
                stream_id: Some(priority_stream_id),
                priority_field_value,
                ..
            } => {
                if matches!(
                    (direction, self.vantage_point),
                    (QlogH3Direction::Created, VantagePoint::Client) |
                        (QlogH3Direction::Parsed, VantagePoint::Server)
                ) {
                    self.get_or_insert_http_req(*priority_stream_id)
                        .priority_updates
                        .push(priority_field_value.clone());
                }
            },

            _ => (),
        }
    }

    /// Builds a datastore from qlog JSON-SEQ events.
    ///
    /// # Errors
    /// Returns an error for unsupported vantage points or tracker arithmetic
    /// overflow.
    pub fn with_sqlog_reader_events(
        events: &[qlog::reader::Event], vantage_point: &qlog::VantagePointType,
        process_acks: bool,
    ) -> Result<Self, DatastoreError> {
        let vp = VantagePoint::try_from(vantage_point)?;

        let mut ds = Datastore {
            total_sent_stream_frame_count: 0,
            vantage_point: vp,
            ..Default::default()
        };

        for event in events {
            match event {
                qlog::reader::Event::Qlog(ev) => {
                    ds.consume_qlog_event(ev, process_acks)?;
                },

                qlog::reader::Event::Json(ev) => {
                    // Just swallow the failure and move on
                    error!("unhandled Json event {:?}", ev);
                },
            }
        }

        ds.hydrate_http_requests();
        ds.finalize();

        Ok(ds)
    }
}

#[derive(Tabled)]
pub struct NetlogSession {
    #[tabled(rename = "ID")]
    session_id: i64,
    #[tabled(rename = "Protocol")]
    application_proto: ApplicationProto,
    #[tabled(rename = "SNI")]
    host: String,
    start_time: u64,
}

impl Debug for NetlogSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "app proto={:?}, host={}",
            self.application_proto, self.host
        )
    }
}

pub struct RequestDiscovery {
    pub time: u64,
    pub stream_job_id: Option<i64>,
}

pub struct StreamBind {
    pub time: u64,
    pub request_discovery_id: i64,
    pub request_discovery_time: u64,
}

pub type RequestDiscoveryMap = BTreeMap<i64, RequestDiscovery>;
pub type StreamBindingMap = BTreeMap<i64, StreamBind>;

#[derive(Debug)]
pub struct ReqOverH3 {
    pub id: i64,
    pub discover_time: u64,
    pub session_id: Option<i64>,
    pub quic_stream_id: Option<u64>,
}

pub type RequestOverH3Map = BTreeMap<i64, Vec<ReqOverH3>>;

/// Parse selected Chrome netlog sessions into independent datastores.
///
/// # Errors
/// Returns arithmetic overflow instead of producing wrapped byte histories;
/// callers discard the partially built session collection on failure.
pub fn with_netlog_reader<R: std::io::BufRead, S: std::hash::BuildHasher>(
    reader: &mut R, hostname_filter: &HashSet<String, S>,
    constants: &netlog::constants::Constants,
) -> Result<(Vec<LogFileData>, BTreeMap<i64, NetlogSession>), DatastoreError> {
    // second line in a netlog is always `"events": [` so skip it
    let _ = read_netlog_record(reader);

    let mut sessions: BTreeMap<i64, NetlogSession> = BTreeMap::new();
    let mut session_events: BTreeMap<
        i64,
        Vec<(netlog::EventHeader, netlog::Event)>,
    > = BTreeMap::new();

    let mut h3_session_requests: RequestOverH3Map = BTreeMap::new();

    let mut req_id_to_session_id: BTreeMap<i64, i64> = BTreeMap::new();

    let mut request_discovery: RequestDiscoveryMap = BTreeMap::new();
    let mut stream_bind: StreamBindingMap = BTreeMap::new();

    while let Some(event) = read_netlog_record(reader) {
        let res: Result<netlog::EventHeader, serde_json::Error> =
            serde_json::from_slice(&event);

        match res {
            Ok(mut event_hdr) => {
                if let Err(error) = event_hdr.populate_strings(constants) {
                    log::warn!(
                        "Skipping netlog record with undefined event ID: {error}"
                    );
                    continue;
                }
                let Ok(time) = event_hdr.time.parse::<u64>() else {
                    log::warn!(
                        "Skipping netlog {} record with invalid timestamp {:?}",
                        event_hdr.ty_string,
                        event_hdr.time
                    );
                    continue;
                };
                event_hdr.time_num = time;

                // If this is a session creation, store the session, so we can
                // link events with it. The source ID of these events is the
                // unique value that we will use to link things together.
                // This assumes events belonging to a session do not occur
                // before the session is created.
                if event_hdr.phase_string == "PHASE_BEGIN" {
                    match event_hdr.ty_string.as_str() {
                        "QUIC_SESSION" => {
                            let ev: QuicSessionEvent =
                                match serde_json::from_slice(&event) {
                                    Ok(value) => value,
                                    Err(error) => {
                                        log::warn!("Skipping malformed QUIC_SESSION: {error}");
                                        continue;
                                    },
                                };

                            // QUIC sessions split host and port, which
                            // interferes with filter expression, so merge them
                            let host =
                                format!("{}:{}", ev.params.host, ev.params.port,);

                            sessions.insert(event_hdr.source.id, NetlogSession {
                                session_id: event_hdr.source.id,
                                application_proto: ApplicationProto::Http3,
                                host: host.clone(),
                                start_time: event_hdr.time_num,
                            });

                            let do_insert = hostname_filter.is_empty() ||
                                hostname_filter.contains(&host);

                            if do_insert {
                                session_events
                                    .insert(event_hdr.source.id, Vec::new());

                                h3_session_requests
                                    .insert(event_hdr.source.id, Vec::new());
                            }
                        },

                        "HTTP2_SESSION" => {
                            let ev: Http2SessionEvent =
                                match serde_json::from_slice(&event) {
                                    Ok(value) => value,
                                    Err(error) => {
                                        log::warn!("Skipping malformed HTTP2_SESSION: {error}");
                                        continue;
                                    },
                                };

                            sessions.insert(event_hdr.source.id, NetlogSession {
                                session_id: event_hdr.source.id,
                                application_proto: ApplicationProto::Http2,
                                host: ev.params.host.clone(),
                                start_time: event_hdr.time_num,
                            });

                            let do_insert = hostname_filter.is_empty() ||
                                hostname_filter.contains(&ev.params.host);

                            if do_insert {
                                session_events
                                    .insert(event_hdr.source.id, Vec::new());
                            }
                        },

                        "CORS_REQUEST" => {
                            // Seems to be the earliest netlog event related to
                            // any request.
                            request_discovery.insert(
                                event_hdr.source.id,
                                RequestDiscovery {
                                    time: event_hdr.time_num,
                                    stream_job_id: None,
                                },
                            );
                        },

                        _ => (),
                    }
                }

                if event_hdr.ty_string.starts_with("HTTP_") {
                    let event = netlog::http::parse_event(&event_hdr, &event);

                    if let Some(netlog::Event::Http(e)) = event {
                        match e {
                                http::Event::HttpStreamJobBoundToRequest(v)  => {
                                    let request_discovery_id = v.params.source_dependency.id;
                                    if let Some(rd) = request_discovery.get_mut(&request_discovery_id) {
                                        stream_bind.insert(event_hdr.source.id, StreamBind{time: event_hdr.time_num, request_discovery_id, request_discovery_time: rd.time});
                                        rd.stream_job_id = Some(event_hdr.source.id);
                                    }
                                },

                                http::Event::HttpStreamRequestBoundToQuicSession(v) => {
                                    let request_discovery_id = event_hdr.source.id;
                                    if let Some(rd) = request_discovery.get(&request_discovery_id) {

                                        if let Some(session_requests) = h3_session_requests.get_mut(&v.params.source_dependency.id) {
                                            let req = ReqOverH3{id: event_hdr.source.id, discover_time: rd.time, session_id: Some(v.params.source_dependency.id), quic_stream_id: None };
                                            session_requests.push(req);

                                            // populate reverse mapping, each unique request ID has a session ID
                                            req_id_to_session_id.insert(event_hdr.source.id, v.params.source_dependency.id);
                                        }
                                    }
                                }

                                http::Event::HttpTransactionQuicSendRequestHeaders(v) => {
                                    let req_id = event_hdr.source.id;
                                    if let Some(session_id) = req_id_to_session_id.get(&req_id) {
                                        if let Some(reqs) = h3_session_requests.get_mut(session_id) {
                                            // todo replace vec with map?
                                            for req in reqs {
                                                if req.id == req_id {
                                                    req.quic_stream_id = Some(v.params.quic_stream_id);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }

                            _ => (),
                        }
                    }
                }

                if let Some(session) =
                    session_events.get_mut(&event_hdr.source.id)
                {
                    if let Some(ev) = netlog::parse_event(&event_hdr, &event) {
                        session.push((event_hdr, ev));
                    }
                }
            },

            Err(e) => {
                error!("Error deserializing: {}", e);
                error!("input value {}", String::from_utf8_lossy(&event));

                // Just swallow the failure and move on
            },
        }
    }

    println!("All sessions in this netlog = {:#?}", sessions);

    let mut log_file_data = Vec::new();

    for (session_id, details) in &sessions {
        if let Some(events) = session_events.remove(session_id) {
            let mut ds = Datastore {
                session_id: Some(*session_id),
                application_proto: details.application_proto,
                host: Some(details.host.clone()),
                total_sent_stream_frame_count: 0,
                ..Default::default()
            };

            for (ev_hdr, event) in &events {
                ds.consume_netlog_event(
                    details.start_time,
                    ev_hdr,
                    event,
                    constants,
                    &stream_bind,
                    h3_session_requests.get(session_id).map(Vec::as_slice),
                )?;
            }

            ds.hydrate_http_requests();
            ds.finalize();
            log_file_data.push(LogFileData {
                datastore: ds,
                raw: Netlog { events },
                trace: None,
            });
        }
    }

    Ok((log_file_data, sessions))
}

#[cfg(test)]
mod input_tests {
    use super::Datastore;
    use super::VantagePoint;
    use qlog::events::quic::ParametersSet;
    use qlog::events::quic::TransportInitiator;
    use qlog::events::Event;
    use qlog::events::EventData;
    use qlog::VantagePointType;

    #[test]
    fn invalid_vantage_points_are_reported_in_both_log_formats() {
        for value in [VantagePointType::Unknown, VantagePointType::Network] {
            let normal = Datastore::with_qlog_events(&[], &value, false);
            let sequential =
                Datastore::with_sqlog_reader_events(&[], &value, false);
            for result in [normal, sequential] {
                assert!(result.is_err_and(|error| {
                    error.to_string().contains("unsupported qlog vantage point")
                }));
            }
        }
    }

    #[test]
    fn client_and_server_vantage_points_are_recognized(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client =
            Datastore::with_qlog_events(&[], &VantagePointType::Client, false)?;
        let server = Datastore::with_sqlog_reader_events(
            &[],
            &VantagePointType::Server,
            false,
        )?;
        assert!(matches!(client.vantage_point, VantagePoint::Client));
        assert!(matches!(server.vantage_point, VantagePoint::Server));
        Ok(())
    }

    #[test]
    fn every_qlog_data_recipient_has_a_distinct_tracking_destination() {
        use qlog::events::quic::StreamDataMoved;
        use qlog::events::DataRecipient;

        for recipient in [
            DataRecipient::User,
            DataRecipient::Application,
            DataRecipient::Transport,
            DataRecipient::Network,
            DataRecipient::Dropped,
        ] {
            let mut datastore = Datastore::default();
            let moved = StreamDataMoved {
                stream_id: Some(13),
                offset: Some(3),
                to: Some(recipient.clone()),
                raw: Some(qlog::events::RawInfo {
                    length: Some(7),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(datastore
                .consume_qlog_event(
                    &Event::with_time(2.0, EventData::QuicStreamDataMoved(moved)),
                    false,
                )
                .is_ok());
            let trackers = [
                (&DataRecipient::User, &datastore.stream_buffer_user_tracker),
                (
                    &DataRecipient::Application,
                    &datastore.stream_buffer_reads_tracker,
                ),
                (
                    &DataRecipient::Transport,
                    &datastore.stream_buffer_writes_tracker,
                ),
                (
                    &DataRecipient::Network,
                    &datastore.stream_buffer_network_tracker,
                ),
                (
                    &DataRecipient::Dropped,
                    &datastore.stream_buffer_dropped_tracker,
                ),
            ];
            for (target, tracker) in trackers {
                if target == &recipient {
                    assert_eq!(tracker.get_stream_max(13), Some(10));
                    assert_eq!(tracker.sum_series, vec![(2.0, 10)]);
                } else {
                    assert_eq!(tracker.get_stream_max(13), None);
                    assert!(tracker.sum_series.is_empty());
                }
            }
        }
    }

    #[test]
    fn stream_end_overflow_propagates_through_both_qlog_decoders() {
        use qlog::events::quic::StreamDataMoved;
        use qlog::events::DataRecipient;

        let event = Event::with_time(
            2.0,
            EventData::QuicStreamDataMoved(StreamDataMoved {
                stream_id: Some(42),
                offset: Some(u64::MAX),
                to: Some(DataRecipient::Application),
                raw: Some(qlog::events::RawInfo {
                    length: Some(1),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        );
        let regular = Datastore::with_qlog_events(
            std::slice::from_ref(&event),
            &VantagePointType::Client,
            false,
        );
        let sequential = Datastore::with_sqlog_reader_events(
            &[qlog::reader::Event::Qlog(event.clone())],
            &VantagePointType::Client,
            false,
        );
        for result in [regular, sequential] {
            assert!(matches!(
                result,
                Err(super::DatastoreError::Tracker(
                    super::TrackerError::StreamEndOverflow {
                        stream_id: 42,
                        offset: u64::MAX,
                        length: 1,
                    }
                ))
            ));
        }

        let mut ds = Datastore::default();
        assert!(ds.consume_qlog_event(&event, false).is_err());
        assert_eq!(ds.last_event_time, 0.0);
        assert!(ds.stream_buffer_reads_tracker.per_stream.is_empty());
    }

    #[test]
    fn stream_max_aggregate_overflow_propagates_from_packet_frames() {
        use qlog::events::quic::PacketReceived;
        use qlog::events::quic::QuicFrame;
        let make_event = |time: f64, stream_id: u64, maximum: u64| {
            Event::with_time(
                time,
                EventData::QuicPacketReceived(PacketReceived {
                    frames: Some(vec![QuicFrame::MaxStreamData {
                        stream_id,
                        maximum,
                        raw: None,
                    }]),
                    ..PacketReceived::default()
                }),
            )
        };
        let events = [make_event(1.0, 1, u64::MAX), make_event(2.0, 2, 1)];
        let result = Datastore::with_qlog_events(
            &events,
            &VantagePointType::Client,
            false,
        );
        assert!(matches!(
            result,
            Err(super::DatastoreError::Tracker(
                super::TrackerError::RunningSumOverflow {
                    stream_id: 2,
                    total: u64::MAX,
                    increment: 1,
                }
            ))
        ));

        let mut ds = Datastore::default();
        assert!(ds.consume_qlog_event(&events[0], false).is_ok());
        assert_eq!(ds.last_event_time, 1.0);
        assert!(ds.consume_qlog_event(&events[1], false).is_err());
        assert_eq!(ds.last_event_time, 1.0);
        assert!(!ds
            .received_stream_max_data_tracker
            .per_stream
            .contains_key(&2));
        assert_eq!(ds.received_stream_max_data_tracker.current_sum(), u64::MAX);
    }

    #[test]
    fn missing_transport_parameter_initiator_is_ignored_without_a_panic() {
        let mut datastore = Datastore::default();
        let limits = ParametersSet {
            initiator: None,
            initial_max_data: Some(123),
            initial_max_stream_data_bidi_local: Some(456),
            ..ParametersSet::default()
        };
        assert!(datastore
            .consume_qlog_event(
                &Event::with_time(
                    1.0,
                    EventData::QuicParametersSet(Box::new(limits)),
                ),
                false,
            )
            .is_ok());
        assert!(datastore.sent_max_data.is_empty());
        assert!(datastore.received_max_data.is_empty());
        assert_eq!(
            datastore.local_initial_stream_limits,
            super::InitialStreamLimits::default()
        );
        assert_eq!(
            datastore.peer_initial_stream_limits,
            super::InitialStreamLimits::default()
        );

        for (initiator, expected_local) in [
            (TransportInitiator::Local, true),
            (TransportInitiator::Remote, false),
        ] {
            let mut datastore = Datastore::default();
            let limits = ParametersSet {
                initiator: Some(initiator),
                initial_max_data: Some(123),
                ..ParametersSet::default()
            };
            assert!(datastore
                .consume_qlog_event(
                    &Event::with_time(
                        1.0,
                        EventData::QuicParametersSet(Box::new(limits)),
                    ),
                    false,
                )
                .is_ok());
            assert_eq!(
                datastore.sent_max_data,
                if expected_local {
                    vec![(0.0, 123)]
                } else {
                    Vec::new()
                }
            );
            assert_eq!(
                datastore.received_max_data,
                if expected_local {
                    Vec::new()
                } else {
                    vec![(0.0, 123)]
                }
            );
        }
    }
}

#[cfg(test)]
mod netlog_tests {
    use super::*;
    use std::io::Cursor;

    fn constants() -> netlog::constants::Constants {
        let mut constants: netlog::constants::Constants =
            serde_json::from_value(serde_json::json!({
                "activeFieldTrialGroups": [],
                "addressFamily": {},
                "certPathBuilderDigestPolicy": {},
                "certStatusFlag": {},
                "certVerifierFlags": {},
                "clientInfo": {},
                "dnsQueryType": {},
                "loadFlag": {},
                "loadState": {},
                "logEventPhase": {"PHASE_BEGIN": 1},
                "logEventTypes": {
                    "QUIC_SESSION": 101,
                    "QUIC_SESSION_STREAM_FRAME_RECEIVED": 102
                },
                "logFormatVersion": 123,
                "logSourceType": {},
                "netError": {"ERR_HTTP2_PROTOCOL_ERROR": -337},
                "quicError": {},
                "quicRstStreamError": {"STREAM_CANCELLED": 42},
                "secureDnsMode": {},
                "timeTickOffset": 0
            }))
            .expect("valid minimal netlog constants fixture");
        constants.populate_id_keyed();
        constants
    }

    fn consume(
        datastore: &mut Datastore, time: u64, event: &netlog::Event,
    ) -> Result<(), DatastoreError> {
        datastore.consume_netlog_event(
            100,
            &netlog::EventHeader {
                time_num: time,
                ..Default::default()
            },
            event,
            &constants(),
            &StreamBindingMap::new(),
            None,
        )
    }

    fn quic_stream(length: u64) -> netlog::Event {
        netlog::Event::Quic(quic::Event::QuicSessionStreamFrameReceived(
            quic::QuicSessionStreamFrameReceivedEvent {
                params: quic::QuicSessionStreamFrameReceivedParams {
                    stream_id: 7,
                    length,
                    offset: 0,
                    fin: false,
                },
            },
        ))
    }

    fn h2_received(stream_id: u32, size: u32) -> netlog::Event {
        netlog::Event::H2(h2::Event::Http2SessionRecvData(
            h2::Http2SessionRecvDataEvent {
                params: h2::Http2SessionSendDataParams {
                    stream_id,
                    size,
                    fin: false,
                },
            },
        ))
    }

    fn h2_sent(stream_id: u32, size: u32) -> netlog::Event {
        netlog::Event::H2(h2::Event::Http2SessionSendData(
            h2::Http2SessionSendDataEvent {
                params: h2::Http2SessionSendDataParams {
                    stream_id,
                    size,
                    fin: false,
                },
            },
        ))
    }

    fn h3_received(stream_id: u64, size: u64) -> netlog::Event {
        netlog::Event::H3(h3::Event::Http3DataFrameReceived(
            h3::Http3DataFrameReceivedEvent {
                params: h3::Http3DataFrameReceivedParams {
                    stream_id,
                    payload_length: size,
                },
            },
        ))
    }

    #[test]
    fn netlog_h2_h3_received_data_record_identical_per_stream_histories() {
        let mut h2 = Datastore::default();
        let mut h3 = Datastore::default();

        for (time, length) in [(102, 5), (104, 7), (106, 0)] {
            consume(&mut h2, time, &h2_received(9, length))
                .expect("valid HTTP/2 DATA");
            consume(&mut h3, time, &h3_received(9, u64::from(length)))
                .expect("valid HTTP/3 DATA");
        }

        for ds in [&h2, &h3] {
            assert_eq!(ds.total_received_data_frame_count, 3);
            assert_eq!(ds.received_data_frames[&9], vec![
                (2.0, 5),
                (4.0, 7),
                (6.0, 0)
            ]);
            assert_eq!(ds.received_data_frames_count_based[&9], vec![
                (0, 5),
                (1, 7),
                (2, 0)
            ]);
            assert_eq!(ds.received_data_cumulative[&9], vec![
                (2.0, 5),
                (4.0, 12),
                (6.0, 12)
            ]);
            assert_eq!(ds.received_data_cumulative_max[&9], 12);
            assert_eq!(ds.largest_data_frame_rx_length_global, 7);

            let request = &ds.http_requests[&9];
            assert_eq!(request.time_first_data_rx, Some(2.0));
            assert_eq!(request.time_last_data_rx, Some(6.0));
            assert_eq!(request.time_data_rx_set, vec![
                (2.0, 5),
                (4.0, 7),
                (6.0, 0)
            ]);
            assert_eq!(request.server_transferred_bytes.inner, Some(12));
        }

        // Only HTTP/2 records connection-wide received DATA. HTTP/3 uses
        // QUIC STREAM frames for its separate connection aggregate.
        assert_eq!(h2.netlog_h2_stream_received_connection_cumulative, vec![
            (2.0, 5),
            (4.0, 12),
            (6.0, 12)
        ]);
        assert!(h3
            .netlog_h2_stream_received_connection_cumulative
            .is_empty());
    }

    #[test]
    fn netlog_h2_sent_data_updates_upload_histories_and_send_credit() {
        let mut datastore = Datastore::default();
        for (time, length) in [(101, 4), (105, 9), (108, 0)] {
            consume(&mut datastore, time, &h2_sent(5, length))
                .expect("valid HTTP/2 outbound DATA");
        }

        assert_eq!(datastore.total_sent_data_frame_count, 3);
        assert_eq!(datastore.sent_data_frames[&5], vec![
            (1.0, 4),
            (5.0, 9),
            (8.0, 0)
        ]);
        assert_eq!(datastore.sent_data_frames_count_based[&5], vec![
            (0, 4),
            (1, 9),
            (2, 0)
        ]);
        assert_eq!(datastore.sent_data_cumulative[&5], vec![
            (1.0, 4),
            (5.0, 13),
            (8.0, 13)
        ]);
        assert_eq!(datastore.sent_data_cumulative_max[&5], 13);
        assert_eq!(datastore.largest_data_frame_tx_length_global, 9);
        assert_eq!(datastore.h2_send_window_updates_balanced[&5], vec![
            (1.0, -4),
            (5.0, -9),
            (8.0, 0)
        ]);
        let request = &datastore.http_requests[&5];
        assert_eq!(request.time_first_data_tx, Some(1.0));
        assert_eq!(request.time_last_data_tx, Some(8.0));
        assert_eq!(request.client_transferred_bytes.inner, Some(13));
        assert_eq!(request.time_data_tx_set, vec![(1.0, 4), (5.0, 9), (8.0, 0)]);
        assert!(datastore.received_data_frames.is_empty());
    }

    #[test]
    fn netlog_data_counter_overflow_does_not_mutate_request_state() {
        for event in [h2_received(5, 1), h3_received(5, 1)] {
            let mut datastore = Datastore {
                total_received_data_frame_count: u64::MAX,
                ..Default::default()
            };
            assert!(matches!(
                consume(&mut datastore, 105, &event),
                Err(DatastoreError::NetlogCounterOverflow {
                    field: "total_received_data_frame_count"
                })
            ));
            assert!(datastore.http_requests.is_empty());
            assert!(datastore.received_data_frames.is_empty());
            assert!(datastore.received_data_cumulative.is_empty());
            assert!(datastore.received_data_frames_count_based.is_empty());
        }

        let mut datastore = Datastore {
            total_sent_data_frame_count: u64::MAX,
            ..Default::default()
        };
        assert!(matches!(
            consume(&mut datastore, 105, &h2_sent(5, 1)),
            Err(DatastoreError::NetlogCounterOverflow {
                field: "total_sent_data_frame_count"
            })
        ));
        assert!(datastore.http_requests.is_empty());
        assert!(datastore.sent_data_frames.is_empty());
        assert!(datastore.sent_data_cumulative.is_empty());
        assert!(datastore.h2_send_window_updates_balanced.is_empty());
    }

    #[test]
    fn netlog_quic_reset_and_stop_sending_preserve_direction_and_error_names() {
        let mut datastore = Datastore::default();

        let reset_received =
            netlog::Event::Quic(quic::Event::QuicSessionRstStreamFrameReceived(
                quic::QuicSessionRstStreamFrameReceivedEvent {
                    params: quic::QuicSessionRstStreamFrameReceivedParams {
                        stream_id: 7,
                        offset: 11,
                        quic_rst_stream_error: 42,
                    },
                },
            ));
        let reset_sent =
            netlog::Event::Quic(quic::Event::QuicSessionRstStreamFrameSent(
                quic::QuicSessionRstStreamFrameSentEvent {
                    params: quic::QuicSessionRstStreamFrameSentParams {
                        stream_id: 7,
                        offset: 29,
                        quic_rst_stream_error: 42,
                    },
                },
            ));
        let stop =
            netlog::Event::Quic(quic::Event::QuicSessionStopSendingFrameSent(
                quic::QuicSessionStopSendingFrameSentEvent {
                    params: quic::QuicSessionStopSendingFrameSentParams {
                        stream_id: 7,
                        quic_rst_stream_error: 42,
                    },
                },
            ));

        // A termination frame on a non-request stream is ignored.
        consume(&mut datastore, 101, &reset_received)
            .expect("non-request reset event");
        consume(&mut datastore, 102, &reset_sent)
            .expect("non-request reset-sent event");
        consume(&mut datastore, 103, &stop)
            .expect("non-request stop-sending event");
        assert!(datastore.http_requests.is_empty());

        datastore.get_or_insert_http_req(7);
        for event in [&reset_received, &reset_sent, &stop] {
            consume(&mut datastore, 104, event)
                .expect("known request stream termination");
        }
        let request = &datastore.http_requests[&7];
        let received = request
            .quic_stream_reset_received
            .as_ref()
            .expect("received reset recorded");
        let sent = request
            .quic_stream_reset_sent
            .as_ref()
            .expect("sent reset recorded");
        let stopped = request
            .quic_stream_stop_sending_sent
            .as_ref()
            .expect("sent stop-sending recorded");
        assert_eq!((received.offset, received.quic_rst_stream_error), (11, 42));
        assert_eq!((sent.offset, sent.quic_rst_stream_error), (29, 42));
        assert_eq!(stopped.quic_rst_stream_error, 42);
        assert_eq!(
            received.quic_rst_stream_error_friendly.as_deref(),
            Some("STREAM_CANCELLED")
        );
        assert_eq!(
            sent.quic_rst_stream_error_friendly.as_deref(),
            Some("STREAM_CANCELLED")
        );
        assert_eq!(
            stopped.quic_rst_stream_error_friendly.as_deref(),
            Some("STREAM_CANCELLED")
        );
        assert!(request.quic_stream_stop_sending_received.is_none());

        // Chrome can record u64 errors larger than i64::MAX. They must
        // survive exactly and must not produce a bogus friendly label.
        let huge =
            netlog::Event::Quic(quic::Event::QuicSessionRstStreamFrameReceived(
                quic::QuicSessionRstStreamFrameReceivedEvent {
                    params: quic::QuicSessionRstStreamFrameReceivedParams {
                        stream_id: 7,
                        offset: u64::MAX,
                        quic_rst_stream_error: u64::MAX,
                    },
                },
            ));
        consume(&mut datastore, 105, &huge).expect("large-code reset event");
        let request = &datastore.http_requests[&7];
        let received = request
            .quic_stream_reset_received
            .as_ref()
            .expect("large-code received reset recorded");
        assert_eq!(received.offset, u64::MAX);
        assert_eq!(received.quic_rst_stream_error, u64::MAX);
        assert!(received.quic_rst_stream_error_friendly.is_none());
        assert_eq!(
            request
                .quic_stream_reset_sent
                .as_ref()
                .expect("sent reset preserved")
                .offset,
            29
        );
    }

    #[test]
    fn netlog_quic_stream_fin_only_updates_existing_request_after_validation() {
        let mut datastore = Datastore::default();
        let fin =
            netlog::Event::Quic(quic::Event::QuicSessionStreamFrameReceived(
                quic::QuicSessionStreamFrameReceivedEvent {
                    params: quic::QuicSessionStreamFrameReceivedParams {
                        stream_id: 7,
                        offset: 10,
                        length: 0,
                        fin: true,
                    },
                },
            ));
        consume(&mut datastore, 111, &fin)
            .expect("first FIN without discovered request");
        assert!(datastore.http_requests.is_empty());
        assert_eq!(datastore.total_received_stream_frame_count, 1);
        datastore.get_or_insert_http_req(7);
        consume(&mut datastore, 115, &fin).expect("FIN with discovered request");
        assert_eq!(datastore.http_requests[&7].time_fin_rx, Some(15.0));
        assert_eq!(datastore.total_received_stream_frame_count, 2);
        assert_eq!(datastore.received_stream_frames[&7].len(), 2);
        assert_eq!(
            datastore.received_stream_frames_count_based[&7]
                .iter()
                .map(|(count, _)| *count)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(
            datastore.netlog_quic_stream_received_connection_cumulative,
            vec![(11.0, 0), (15.0, 0)]
        );

        datastore.total_received_stream_frame_count = u64::MAX;
        assert!(matches!(
            consume(&mut datastore, 120, &fin),
            Err(DatastoreError::NetlogCounterOverflow {
                field: "total_received_stream_frame_count"
            })
        ));
        assert_eq!(datastore.http_requests[&7].time_fin_rx, Some(15.0));
        assert_eq!(datastore.received_stream_frames[&7].len(), 2);
    }

    #[test]
    fn netlog_signed_time_handles_events_before_session_and_wide_absolute_timestamps(
    ) {
        assert_eq!(netlog_relative_time(90, 100), -10.0);
        assert_eq!(netlog_relative_time(110, 100), 10.0);
        assert_eq!(netlog_relative_time(100, 100), 0.0);
        assert_eq!(netlog_relative_time(u64::MAX, u64::MAX - 1), 1.0);
        assert_eq!(netlog_relative_time(u64::MAX - 1, u64::MAX), -1.0);
        assert_eq!(netlog_relative_time(0, u64::MAX), -(u64::MAX as f64));
        let mut datastore = Datastore::default();
        assert!(consume(&mut datastore, 90, &quic_stream(1)).is_ok());
        assert_eq!(datastore.received_stream_frames[&7][0].0, -10.0);
        assert_eq!(
            datastore.netlog_quic_stream_received_connection_cumulative,
            vec![(-10.0, 1)]
        );
    }

    #[test]
    fn netlog_quic_counter_overflow_is_reported_without_updating_any_event_fields(
    ) {
        let mut datastore = Datastore::default();
        datastore
            .netlog_quic_stream_received_connection_cumulative
            .push((0.0, u64::MAX));
        let event = quic_stream(1);
        assert!(matches!(
            consume(&mut datastore, 120, &event),
            Err(DatastoreError::NetlogCounterOverflow {
                field: "netlog_quic_stream_received_connection_cumulative"
            })
        ));
        assert_eq!(datastore.total_received_stream_frame_count, 0);
        assert!(datastore.received_stream_frames.is_empty());
        assert!(datastore.received_stream_frames_count_based.is_empty());
        assert_eq!(
            datastore
                .netlog_quic_stream_received_connection_cumulative
                .len(),
            1
        );
        datastore
            .netlog_quic_stream_received_connection_cumulative
            .clear();
        datastore.total_received_stream_frame_count = u64::MAX;
        assert!(matches!(
            consume(&mut datastore, 120, &event),
            Err(DatastoreError::NetlogCounterOverflow {
                field: "total_received_stream_frame_count"
            })
        ));
        assert!(datastore.received_stream_frames.is_empty());
    }

    #[test]
    fn netlog_h3_and_h2_counter_overflow_is_rejected_before_mutation() {
        let mut h3 = Datastore::default();
        h3.received_data_cumulative.insert(9, vec![(0.0, u64::MAX)]);
        let event = netlog::Event::H3(h3::Event::Http3DataFrameReceived(
            h3::Http3DataFrameReceivedEvent {
                params: h3::Http3DataFrameReceivedParams {
                    stream_id: 9,
                    payload_length: 1,
                },
            },
        ));
        assert!(matches!(
            consume(&mut h3, 120, &event),
            Err(DatastoreError::NetlogCounterOverflow {
                field: "received_data_cumulative"
            })
        ));
        assert!(!h3.http_requests.contains_key(&9));
        assert_eq!(h3.total_received_data_frame_count, 0);

        let mut h2 = Datastore::default();
        h2.received_data_cumulative
            .insert(11, vec![(0.0, u64::MAX)]);
        assert!(matches!(
            consume(&mut h2, 120, &h2_received(11, 1)),
            Err(DatastoreError::NetlogCounterOverflow {
                field: "received_data_cumulative"
            })
        ));
        assert!(!h2.http_requests.contains_key(&11));
        h2.received_data_cumulative.clear();
        h2.netlog_h2_stream_received_connection_cumulative
            .push((0.0, u64::MAX));
        assert!(matches!(
            consume(&mut h2, 120, &h2_received(11, 1)),
            Err(DatastoreError::NetlogCounterOverflow {
                field: "netlog_h2_stream_received_connection_cumulative"
            })
        ));
        assert!(!h2.http_requests.contains_key(&11));
        assert_eq!(h2.total_received_data_frame_count, 0);

        let mut h2 = Datastore::default();
        h2.sent_data_cumulative.insert(11, vec![(0.0, u64::MAX)]);
        assert!(matches!(
            consume(&mut h2, 120, &h2_sent(11, 1)),
            Err(DatastoreError::NetlogCounterOverflow {
                field: "sent_data_cumulative"
            })
        ));
        assert!(!h2.http_requests.contains_key(&11));
        assert_eq!(h2.total_sent_data_frame_count, 0);
    }

    fn quic_ack_received(missing_packets: Vec<u64>) -> netlog::Event {
        netlog::Event::Quic(quic::Event::QuicSessionAckFrameReceived(
            quic::QuicSessionAckFrameReceived {
                params: quic::QuicSessionAckFrameReceivedParams {
                    missing_packets,
                    ..Default::default()
                },
            },
        ))
    }

    fn quic_ack_sent(missing_packets: Vec<u64>) -> netlog::Event {
        netlog::Event::Quic(quic::Event::QuicSessionAckFrameSent(
            quic::QuicSessionAckFrameSent {
                params: quic::QuicSessionAckFrameSentParams {
                    missing_packets,
                    ..Default::default()
                },
            },
        ))
    }

    #[test]
    fn netlog_received_ack_without_packet_header_keeps_unknown_space_gaps() {
        let mut datastore = Datastore::default();
        consume(&mut datastore, 105, &quic_ack_received(vec![3, 4, 4]))
            .expect("ACK event");
        assert_eq!(datastore.total_rx_ack, 1);
        assert_eq!(datastore.max_ack_received_missing_packets_size, 3);
        assert_eq!(
            datastore.netlog_ack_received_missing_packet[&PacketType::Unknown],
            BTreeSet::from([3, 4])
        );
        assert!(datastore.netlog_ack_sent_missing_packet.is_empty());

        // Later packet observations cannot retroactively classify this ACK:
        // Unknown is intentional and must remain visible in the text report.
        let header = netlog::Event::Quic(
            quic::Event::QuicSessionUnauthenticatedPacketHeaderReceived(
                quic::QuicSessionUnauthenticatedPacketHeaderReceived {
                    params: quic::QuicSessionUnauthenticatedPacketHeaderReceivedParams {
                        packet_number: 7,
                        header_format: "IETF_QUIC_SHORT_HEADER_PACKET".to_owned(),
                        ..Default::default()
                    },
                },
            ),
        );
        consume(&mut datastore, 106, &header).expect("packet header");
        consume(&mut datastore, 107, &quic_ack_received(vec![8]))
            .expect("ACK with known parent packet");
        assert_eq!(
            datastore.netlog_ack_received_missing_packet[&PacketType::OneRtt],
            BTreeSet::from([8])
        );
        assert_eq!(
            datastore.netlog_ack_received_missing_packet[&PacketType::Unknown],
            BTreeSet::from([3, 4])
        );
    }

    #[test]
    fn netlog_sent_ack_gaps_reclassify_when_packet_header_follows() {
        let mut datastore = Datastore::default();
        consume(&mut datastore, 101, &quic_ack_sent(vec![9, 11]))
            .expect("sent ACK");
        consume(&mut datastore, 102, &quic_ack_sent(vec![11, 12]))
            .expect("second sent ACK");
        assert_eq!(datastore.total_tx_ack, 2);
        assert_eq!(datastore.max_ack_sent_missing_packets_size, 2);
        assert_eq!(
            datastore.netlog_ack_sent_missing_packet[&PacketType::Unknown],
            BTreeSet::from([9, 11, 12])
        );
        assert_eq!(datastore.netlog_ack_sent_missing_packets_raw, vec![
            (1.0, vec![9, 11]),
            (2.0, vec![11, 12])
        ]);

        // The event has a private transmission_type field: construct the
        // packet with the same serde path used by the netlog parser.
        let packet: quic::QuicSessionPacketSent =
            serde_json::from_value(serde_json::json!({
                "params": {
                    "encryption_level": "ENCRYPTION_HANDSHAKE",
                    "packet_number": 17,
                    "sent_time_us": 0,
                    "transmission_type": "NOT_RETRANSMISSION"
                }
            }))
            .expect("valid Chrome QUIC packet event");
        consume(
            &mut datastore,
            103,
            &netlog::Event::Quic(quic::Event::QuicSessionPacketSent(packet)),
        )
        .expect("sent packet following ACK");
        assert_eq!(
            datastore.netlog_ack_sent_missing_packet[&PacketType::Handshake],
            BTreeSet::from([9, 11, 12])
        );
        assert!(!datastore
            .netlog_ack_sent_missing_packet
            .contains_key(&PacketType::Unknown));
        assert_eq!(
            datastore.packet_sent[&PacketType::Handshake][&17].number,
            17
        );

        // An empty ACK does not create a misleading empty packet-space entry.
        consume(&mut datastore, 104, &quic_ack_sent(vec![]))
            .expect("empty sent ACK");
        assert_eq!(datastore.total_tx_ack, 3);
        assert_eq!(datastore.netlog_ack_sent_missing_packet.len(), 1);
    }

    #[test]
    fn netlog_ack_count_overflow_does_not_change_gap_histories() {
        let mut datastore = Datastore {
            total_rx_ack: usize::MAX,
            total_tx_ack: usize::MAX,
            ..Default::default()
        };
        for (event, field) in [
            (quic_ack_received(vec![5, 6]), "total_rx_ack"),
            (quic_ack_sent(vec![2, 3]), "total_tx_ack"),
        ] {
            assert!(matches!(
                consume(&mut datastore, 120, &event),
                Err(DatastoreError::NetlogCounterOverflow {
                    field: actual
                }) if actual == field
            ));
        }
        assert!(datastore.netlog_ack_received_missing_packet.is_empty());
        assert!(datastore.netlog_ack_sent_missing_packet.is_empty());
        assert!(datastore.netlog_ack_sent_missing_packets_raw.is_empty());
        assert_eq!(datastore.max_ack_sent_missing_packets_size, 0);
        assert_eq!(datastore.max_ack_received_missing_packets_size, 0);
    }

    fn quic_received_packet_header(
        header_format: &str, long_header_type: Option<&str>, number: u64,
    ) -> netlog::Event {
        netlog::Event::Quic(
            quic::Event::QuicSessionUnauthenticatedPacketHeaderReceived(
                quic::QuicSessionUnauthenticatedPacketHeaderReceived {
                    params: quic::QuicSessionUnauthenticatedPacketHeaderReceivedParams {
                        header_format: header_format.to_owned(),
                        long_header_type: long_header_type.map(str::to_owned),
                        packet_number: number,
                        ..Default::default()
                    },
                },
            ),
        )
    }

    #[test]
    fn netlog_packet_gaps_are_counted_only_within_each_packet_number_space() {
        let mut datastore = Datastore::default();
        let initial = |number| {
            quic_received_packet_header(
                "IETF_QUIC_LONG_HEADER_PACKET",
                Some("INITIAL"),
                number,
            )
        };
        let handshake = |number| {
            quic_received_packet_header(
                "IETF_QUIC_LONG_HEADER_PACKET",
                Some("HANDSHAKE"),
                number,
            )
        };
        let application = |number| {
            quic_received_packet_header(
                "IETF_QUIC_SHORT_HEADER_PACKET",
                None,
                number,
            )
        };

        // Switching spaces must not manufacture a packet-number gap.
        for event in [
            initial(10),
            handshake(0),
            initial(11),
            handshake(1),
            application(200),
            application(201),
        ] {
            consume(&mut datastore, 101, &event)
                .expect("valid received packet header");
        }
        assert_eq!(datastore.discontinuous_packet_number_count, 0);

        // Only jumps within an individual space count; reordering retains
        // the existing absolute-difference behavior.
        for (event, expected) in [
            (initial(14), 1),
            (handshake(5), 2),
            (application(198), 3),
            (application(199), 3),
        ] {
            consume(&mut datastore, 102, &event).expect("valid packet header");
            assert_eq!(datastore.discontinuous_packet_number_count, expected);
        }

        // Unclassified headers cannot establish a packet-number space.
        consume(
            &mut datastore,
            103,
            &quic_received_packet_header("UNRECOGNIZED", None, 9000),
        )
        .expect("unknown packet header should be preserved");
        consume(&mut datastore, 104, &initial(15))
            .expect("continuation of Initial space");
        assert_eq!(datastore.discontinuous_packet_number_count, 3);
        assert_eq!(datastore.received_packets_netlog.len(), 12);
        assert_eq!(
            datastore
                .received_netlog_packet_numbers
                .previous(PacketType::Initial),
            Some(15)
        );
    }

    #[test]
    fn netlog_application_space_is_shared_by_zero_and_one_rtt() {
        let mut progress = NetlogPacketNumberProgress::default();
        progress.observe(PacketType::ZeroRtt, 4);
        assert_eq!(progress.previous(PacketType::OneRtt), Some(4));
        progress.observe(PacketType::OneRtt, 5);
        assert_eq!(progress.previous(PacketType::ZeroRtt), Some(5));
        assert_eq!(progress.previous(PacketType::Initial), None);
        assert_eq!(progress.previous(PacketType::Handshake), None);
        assert_eq!(progress.previous(PacketType::Retry), None);
        progress.observe(PacketType::Unknown, 999);
        assert_eq!(progress.previous(PacketType::OneRtt), Some(5));
    }

    #[test]
    fn netlog_discontinuity_overflow_preserves_last_observed_packet_number() {
        let mut datastore = Datastore::default();
        datastore
            .received_netlog_packet_numbers
            .observe(PacketType::Handshake, 100);
        datastore.discontinuous_packet_number_count = u64::MAX;

        let event = quic_received_packet_header(
            "IETF_QUIC_LONG_HEADER_PACKET",
            Some("HANDSHAKE"),
            104,
        );
        assert!(matches!(
            consume(&mut datastore, 120, &event),
            Err(DatastoreError::NetlogCounterOverflow {
                field: "discontinuous_packet_number_count"
            })
        ));
        assert_eq!(
            datastore
                .received_netlog_packet_numbers
                .previous(PacketType::Handshake),
            Some(100)
        );
        assert!(datastore.packet_received.is_empty());
        assert!(datastore.received_packets_netlog.is_empty());
        assert_eq!(datastore.discontinuous_packet_number_count, u64::MAX);
    }

    #[test]
    fn netlog_recv_acks_have_independent_maximum_from_sent_acks() {
        let mut datastore = Datastore::default();
        let sent = netlog::Event::Quic(quic::Event::QuicSessionAckFrameSent(
            quic::QuicSessionAckFrameSent {
                params: quic::QuicSessionAckFrameSentParams {
                    missing_packets: vec![1, 2, 3, 4, 5, 6, 7],
                    ..Default::default()
                },
            },
        ));
        let received =
            netlog::Event::Quic(quic::Event::QuicSessionAckFrameReceived(
                quic::QuicSessionAckFrameReceived {
                    params: quic::QuicSessionAckFrameReceivedParams {
                        missing_packets: vec![3, 4],
                        ..Default::default()
                    },
                },
            ));
        assert!(consume(&mut datastore, 101, &sent).is_ok());
        assert!(consume(&mut datastore, 102, &received).is_ok());
        assert_eq!(datastore.total_tx_ack, 1);
        assert_eq!(datastore.total_rx_ack, 1);
        assert_eq!(datastore.max_ack_sent_missing_packets_size, 7);
        assert_eq!(datastore.max_ack_received_missing_packets_size, 2);
        datastore.total_rx_ack = usize::MAX;
        assert!(matches!(
            consume(&mut datastore, 103, &received),
            Err(DatastoreError::NetlogCounterOverflow {
                field: "total_rx_ack"
            })
        ));
    }

    fn h2_window_received(stream_id: u32, delta: i32) -> netlog::Event {
        netlog::Event::H2(h2::Event::Http2SessionRecvWindowUpdate(
            h2::Http2SessionRecvWindowUpdateEvent {
                params: h2::Http2SessionRecvWindowUpdateParams {
                    stream_id,
                    delta,
                },
            },
        ))
    }

    fn h2_window_sent(stream_id: u32, delta: i32) -> netlog::Event {
        netlog::Event::H2(h2::Event::Http2SessionSendWindowUpdate(
            h2::Http2SessionSendWindowUpdateEvent {
                params: h2::Http2SessionSendWindowUpdateParams {
                    stream_id,
                    delta,
                },
            },
        ))
    }

    #[test]
    fn netlog_h2_close_preserves_error_label_and_session_metadata() {
        let event = netlog::Event::H2(h2::Event::Http2SessionClose(
            h2::Http2SessionCloseEvent {
                params: h2::Http2SessionCloseParams {
                    net_error: -337,
                    description: "protocol error".to_owned(),
                },
            },
        ));
        let mut datastore = Datastore::default();
        consume(&mut datastore, 120, &event).expect("H2 close event");
        let close = datastore.h2_session_close.as_ref().expect("close record");
        assert_eq!(close.session_id, -1);
        assert_eq!(close.sni, "ERROR UNKNOWN");
        assert_eq!(close.details, "protocol error");
        assert_eq!(close.net_err, -337);
        assert_eq!(
            close.net_err_pretty.inner.as_deref(),
            Some("ERR_HTTP2_PROTOCOL_ERROR")
        );

        datastore.session_id = Some(42);
        datastore.host = Some("server.example.test".to_owned());
        consume(&mut datastore, 121, &event).expect("close with known host");
        let close = datastore.h2_session_close.as_ref().expect("close record");
        assert_eq!(close.session_id, 42);
        assert_eq!(close.sni, "server.example.test");
        assert_eq!(close.details, "protocol error");
    }

    #[test]
    fn netlog_h2_stream_reset_preserves_direction_and_missing_description() {
        let mut datastore = Datastore::default();
        let sent = netlog::Event::H2(h2::Event::Http2SessionSendRstStream(
            h2::Http2SessionSendRstStreamEvent {
                params: h2::Http2SessionSendRstStreamParams {
                    stream_id: 23,
                    error_code: "CANCEL".to_owned(),
                    description: "peer cancelled".to_owned(),
                },
            },
        ));
        let received = netlog::Event::H2(h2::Event::Http2SessionRecvRstStream(
            h2::Http2SessionRecvRstStreamEvent {
                params: h2::Http2SessionRecvRstStreamParams {
                    stream_id: 23,
                    error_code: "REFUSED_STREAM".to_owned(),
                },
            },
        ));

        // Reset events do not create a request for non-request streams.
        consume(&mut datastore, 102, &received).expect("unknown recv reset");
        consume(&mut datastore, 103, &sent).expect("unknown sent reset");
        assert!(datastore.http_requests.is_empty());

        datastore.get_or_insert_http_req(23);
        consume(&mut datastore, 104, &sent).expect("sent H2 reset");
        consume(&mut datastore, 105, &received).expect("received H2 reset");
        let request = &datastore.http_requests[&23];
        let sent_reset = request
            .h2_stream_reset_sent
            .as_ref()
            .expect("sent reset retained");
        assert_eq!(sent_reset.error, "CANCEL");
        assert_eq!(sent_reset.description, "peer cancelled");
        let received_reset = request
            .h2_stream_reset_receive
            .as_ref()
            .expect("received reset retained");
        assert_eq!(received_reset.error, "REFUSED_STREAM");
        assert!(received_reset.description.is_empty());

        // Sending a later reset must not erase the received direction.
        consume(&mut datastore, 106, &sent).expect("repeat sent reset");
        assert_eq!(
            datastore.http_requests[&23]
                .h2_stream_reset_receive
                .as_ref()
                .expect("received direction preserved")
                .error,
            "REFUSED_STREAM"
        );
    }

    #[test]
    fn netlog_h2_window_update_keeps_independent_stream_and_direction_series() {
        let mut datastore = Datastore::default();
        for (time, event) in [
            (101, h2_window_received(1, 50)),
            (102, h2_window_sent(1, 7)),
            (103, h2_window_received(3, 8)),
            (104, h2_window_sent(3, 11)),
            (105, h2_window_received(1, -1)),
            (106, h2_window_sent(3, 0)),
            (107, h2_window_received(1, 0)),
            (108, h2_window_sent(3, -9)),
        ] {
            consume(&mut datastore, time, &event)
                .expect("H2 WINDOW_UPDATE event");
        }
        assert_eq!(datastore.h2_send_window_updates_balanced[&1], vec![(
            1.0, 50
        )]);
        assert_eq!(datastore.h2_send_window_updates_absolute[&1], vec![(
            1.0, 50
        )]);
        assert_eq!(datastore.h2_send_window_updates_balanced[&3], vec![(
            3.0, 8
        )]);
        assert_eq!(datastore.h2_send_window_updates_absolute[&3], vec![(
            3.0, 8
        )]);
        assert_eq!(datastore.h2_recv_window_updates[&1], vec![(2.0, 7)]);
        assert_eq!(datastore.h2_recv_window_updates[&3], vec![(4.0, 11)]);
        assert_eq!(datastore.h2_send_window_updates_balanced.len(), 2);
        assert_eq!(datastore.h2_recv_window_updates.len(), 2);
    }

    #[test]
    fn http2_window_updates_separate_peer_send_credit_and_our_receive_credit() {
        let mut datastore = Datastore::default();
        assert!(consume(&mut datastore, 110, &h2_window_received(3, 10)).is_ok());
        assert!(consume(&mut datastore, 120, &h2_window_sent(3, 20)).is_ok());
        assert!(consume(&mut datastore, 130, &h2_window_sent(3, -1)).is_ok());
        assert!(consume(&mut datastore, 140, &h2_window_received(3, 0)).is_ok());
        assert_eq!(datastore.h2_send_window_updates_balanced[&3], vec![(
            10.0, 10
        )]);
        assert_eq!(datastore.h2_send_window_updates_absolute[&3], vec![(
            10.0, 10
        )]);
        assert_eq!(datastore.h2_recv_window_updates[&3], vec![(20.0, 20)]);
        assert_eq!(datastore.h2_send_window_updates_balanced[&3].len(), 1);
    }

    #[test]
    fn netlog_reader_propagates_session_cumulative_overflow(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut source = serde_json::json!({
            "constants": {
                "activeFieldTrialGroups": [], "addressFamily": {},
                "certPathBuilderDigestPolicy": {}, "certStatusFlag": {},
                "certVerifierFlags": {}, "clientInfo": {}, "dnsQueryType": {},
                "loadFlag": {}, "loadState": {},
                "logEventPhase": {"PHASE_BEGIN": 1},
                "logEventTypes": {
                    "QUIC_SESSION": 101,
                    "QUIC_SESSION_STREAM_FRAME_RECEIVED": 102
                },
                "logFormatVersion": 123, "logSourceType": {},
                "netError": {}, "quicError": {}, "quicRstStreamError": {},
                "secureDnsMode": {}, "timeTickOffset": 0
            }
        })
        .to_string();
        source.pop(); // close the outer document after the events array.
        let record = |ty: i64, time: u64, params: serde_json::Value| {
            serde_json::json!({
                "phase": 1, "source": {"id": 7, "type": 7, "start_time": "0"},
                "time": time.to_string(), "type": ty, "params": params
            })
            .to_string()
        };
        let records = [
            record(
                101,
                100,
                serde_json::json!({
                    "cert_verify_flags": 0, "connection_id": "",
                    "host": "example.test", "port": 443,
                    "network_isolation_key": "", "privacy_mode": ""
                }),
            ),
            record(
                102,
                105,
                serde_json::json!({
                    "stream_id": 7, "length": u64::MAX, "offset": 0, "fin": false
                }),
            ),
            record(
                102,
                106,
                serde_json::json!({
                    "stream_id": 7, "length": 1, "offset": 0, "fin": false
                }),
            ),
        ];
        source.push_str(&format!(
            ",\n\"events\": [\n{}\n]\n}}",
            records.join(",\n")
        ));
        let mut reader = Cursor::new(source.as_bytes());
        let parsed_constants = netlog::read_netlog_constants(&mut reader)?;
        let result =
            with_netlog_reader(&mut reader, &HashSet::new(), &parsed_constants);
        assert!(matches!(
            result,
            Err(DatastoreError::NetlogCounterOverflow {
                field: "netlog_quic_stream_received_connection_cumulative"
            })
        ));
        Ok(())
    }
}

#[cfg(test)]
mod qlog_rate_tests {
    use super::Datastore;
    use qlog::events::quic::RecoveryMetricsUpdated;

    #[test]
    fn standard_pacing_rate_is_converted_to_bytes_for_the_plot() {
        let mut ds = Datastore::default();
        let mut metrics = RecoveryMetricsUpdated {
            pacing_rate: Some(8_000),
            ..RecoveryMetricsUpdated::default()
        };
        metrics
            .ex_data
            .insert("cf_delivery_rate".into(), 1000_u64.into());
        ds.consume_qlog_metrics_updated(&metrics, 42.0);
        assert_eq!(ds.local_pacing_rate, ds.local_delivery_rate);
        assert_eq!(ds.local_pacing_rate, vec![(42.0, 1000)]);
    }
}

#[cfg(test)]
mod qlog_h3_direction_tests {
    use super::Datastore;
    use qlog::events::http3::FrameCreated;
    use qlog::events::http3::FrameParsed;
    use qlog::events::http3::Http3Frame;
    use qlog::events::http3::HttpHeader;
    use qlog::events::Event;
    use qlog::events::EventData;
    use qlog::VantagePointType;

    fn headers(values: &[(&str, &str)]) -> Http3Frame {
        Http3Frame::Headers {
            headers: values
                .iter()
                .map(|&(name, value)| HttpHeader {
                    name: Some(name.into()),
                    name_bytes: None,
                    value: Some(value.into()),
                    value_bytes: None,
                })
                .collect(),
            raw: None,
        }
    }

    fn data() -> Http3Frame {
        Http3Frame::Data { raw: None }
    }

    fn priority(value: &str) -> Http3Frame {
        Http3Frame::PriorityUpdate {
            stream_id: Some(12),
            push_id: None,
            priority_field_value: value.into(),
            raw: None,
        }
    }

    fn event(
        time: f64, created: bool, frame: Http3Frame, length: Option<u64>,
    ) -> Event {
        let data = if created {
            EventData::Http3FrameCreated(FrameCreated {
                stream_id: 8,
                length,
                frame,
                raw: None,
            })
        } else {
            EventData::Http3FrameParsed(FrameParsed {
                stream_id: 8,
                length,
                frame,
                raw: None,
            })
        };
        Event::with_time(time, data)
    }

    #[test]
    fn h3_frames_preserve_direction_and_complete_request_response_metadata() {
        for (vantage, request_created) in [
            (VantagePointType::Client, true),
            (VantagePointType::Server, false),
        ] {
            let events = vec![
                event(
                    1.0,
                    request_created,
                    headers(&[
                        (":method", "POST"),
                        (":authority", "example.test"),
                        (":path", "/upload"),
                        ("priority", "u=3"),
                        ("content-length", "11"),
                    ]),
                    None,
                ),
                event(
                    2.0,
                    !request_created,
                    headers(&[(":status", "201"), ("content-length", "17")]),
                    None,
                ),
                event(3.0, true, data(), Some(11)),
                event(4.0, false, data(), Some(17)),
                event(5.0, request_created, priority("u=2"), None),
                event(6.0, !request_created, priority("ignored"), None),
            ];

            let ds =
                Datastore::with_qlog_events(&events, &vantage, false).unwrap();
            let req = ds.http_requests.get(&8).unwrap();
            assert_eq!(req.method.inner.as_deref(), Some("POST"));
            assert_eq!(req.host.inner.as_deref(), Some("example.test"));
            assert_eq!(req.path.inner.as_deref(), Some("/upload"));
            assert_eq!(req.client_pri_hdr.inner.as_deref(), Some("u=3"));
            assert_eq!(req.client_content_length.inner.as_deref(), Some("11"));
            assert_eq!(req.status.inner.as_deref(), Some("201"));
            assert_eq!(req.server_content_length.inner.as_deref(), Some("17"));

            assert_eq!(req.time_first_data_tx, Some(3.0));
            assert_eq!(req.time_last_data_tx, Some(3.0));
            assert_eq!(req.time_data_tx_set, vec![(3.0, 11)]);
            assert_eq!(req.time_first_data_rx, Some(4.0));
            assert_eq!(req.time_last_data_rx, Some(4.0));
            assert_eq!(req.time_data_rx_set, vec![(4.0, 17)]);
            assert_eq!(ds.largest_data_frame_tx_length_global, 11);
            assert_eq!(ds.largest_data_frame_rx_length_global, 17);

            let priority_req = ds.http_requests.get(&12).unwrap();
            assert_eq!(priority_req.priority_updates, vec!["u=2"]);

            let observed = ds.received_data_frames.get(&8);
            match vantage {
                VantagePointType::Client =>
                    assert_eq!(observed, Some(&vec![(4.0, 17)])),
                VantagePointType::Server => assert!(observed.is_none()),
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod qlog_packet_history_tests {
    use super::Datastore;
    use super::VantagePoint;
    use crate::PacketType;
    use qlog::events::quic::AckRange;
    use qlog::events::quic::PacketHeader;
    use qlog::events::quic::PacketReceived;
    use qlog::events::quic::PacketSent;
    use qlog::events::quic::PacketType as WirePacketType;
    use qlog::events::quic::ParametersSet;
    use qlog::events::quic::QuicFrame;
    use qlog::events::quic::TransportInitiator;
    use qlog::events::Event;
    use qlog::events::EventData;
    use qlog::events::RawInfo;

    fn header(packet_type: WirePacketType, number: Option<u64>) -> PacketHeader {
        PacketHeader {
            packet_type,
            packet_number: number,
            ..PacketHeader::default()
        }
    }

    fn sent(time: f64, packet_type: WirePacketType, number: u64) -> Event {
        Event::with_time(
            time,
            EventData::QuicPacketSent(PacketSent {
                header: header(packet_type, Some(number)),
                raw: Some(RawInfo {
                    length: Some(100),
                    ..RawInfo::default()
                }),
                ..PacketSent::default()
            }),
        )
    }

    fn ack(ranges: Vec<AckRange>) -> QuicFrame {
        QuicFrame::Ack {
            ack_delay: None,
            acked_ranges: Some(ranges),
            ect1: None,
            ect0: None,
            ce: None,
            raw: None,
        }
    }

    fn received(
        time: f64, packet_type: WirePacketType, number: Option<u64>,
        frames: Vec<QuicFrame>,
    ) -> Event {
        Event::with_time(
            time,
            EventData::QuicPacketReceived(PacketReceived {
                header: header(packet_type, number),
                raw: Some(RawInfo {
                    length: Some(200),
                    ..RawInfo::default()
                }),
                frames: Some(frames),
                ..PacketReceived::default()
            }),
        )
    }

    #[test]
    fn received_packets_are_indexed_and_available_to_the_plot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let events = [
            received(1.0, WirePacketType::Initial, Some(5), vec![]),
            received(2.0, WirePacketType::OneRtt, Some(5), vec![]),
            received(3.0, WirePacketType::OneRtt, Some(8), vec![]),
            received(4.0, WirePacketType::OneRtt, Some(5), vec![]),
            received(5.0, WirePacketType::Retry, None, vec![]),
        ];
        let data = Datastore::with_qlog_events(
            &events,
            &qlog::VantagePointType::Client,
            false,
        )?;
        assert_eq!(data.packet_received.len(), 2);
        let packets = data
            .packet_received
            .get(&PacketType::OneRtt)
            .ok_or("missing application packets")?;
        assert_eq!(packets.keys().copied().collect::<Vec<_>>(), [5, 8]);
        assert_eq!(packets.get(&5).map(|packet| packet.created_time), Some(2.0));
        assert_eq!(
            packets
                .get(&8)
                .and_then(|packet| packet.raw.as_ref())
                .and_then(|raw| raw.length),
            Some(200)
        );
        let series = crate::seriesstore::SeriesStore::from_datastore(&data)?;
        assert_eq!(series.onertt_packet_received, [(2.0, 5), (3.0, 8)]);
        assert_eq!(series.received_x_max, 3.0);
        Ok(())
    }

    #[test]
    fn ack_ranges_are_inclusive_and_respect_packet_number_spaces(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let events = [
            sent(1.0, WirePacketType::Initial, 5),
            sent(2.0, WirePacketType::Handshake, 5),
            sent(3.0, WirePacketType::ZeroRtt, 4),
            sent(4.0, WirePacketType::ZeroRtt, 5),
            sent(5.0, WirePacketType::OneRtt, 6),
            sent(6.0, WirePacketType::OneRtt, 7),
            received(7.0, WirePacketType::OneRtt, Some(9), vec![ack(vec![
                AckRange::new(7, 1),
                AckRange::new(5, 6),
            ])]),
            // Repeated metadata must not discard the ACK state.
            sent(8.0, WirePacketType::OneRtt, 6),
        ];
        for process_acks in [false, true] {
            let data = Datastore::with_qlog_events(
                &events,
                &qlog::VantagePointType::Client,
                process_acks,
            )?;
            for (packet_type, number, acknowledged) in [
                (PacketType::Initial, 5, false),
                (PacketType::Handshake, 5, false),
                (PacketType::ZeroRtt, 4, false),
                (PacketType::ZeroRtt, 5, true),
                (PacketType::OneRtt, 6, true),
                (PacketType::OneRtt, 7, false),
            ] {
                let packet = data
                    .packet_sent
                    .get(&packet_type)
                    .and_then(|packets| packets.get(&number))
                    .ok_or("missing sent packet")?;
                assert_eq!(
                    packet.acked,
                    (process_acks && acknowledged).then_some(true)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn missing_packet_number_does_not_discard_frame_observations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut data = Datastore::default();
        data.consume_qlog_event(
            &Event::with_time(
                1.0,
                EventData::QuicPacketSent(PacketSent {
                    header: header(WirePacketType::OneRtt, None),
                    send_at_time: Some(2.0),
                    frames: Some(vec![QuicFrame::MaxData {
                        maximum: 100,
                        raw: None,
                    }]),
                    ..PacketSent::default()
                }),
            ),
            false,
        )?;
        assert!(data.packet_sent.is_empty());
        assert_eq!(data.sent_max_data, [(2.0, 100)]);
        Ok(())
    }

    #[test]
    fn transport_limits_follow_advertiser_and_stream_initiator(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (vantage, local_bidi, remote_bidi) in [
            (VantagePoint::Client, [10, 20], [50, 40]),
            (VantagePoint::Server, [20, 10], [40, 50]),
        ] {
            let mut data = Datastore {
                vantage_point: vantage,
                ..Datastore::default()
            };
            for (initiator, bidi_local, bidi_remote, uni) in [
                (TransportInitiator::Local, 10, 20, 30),
                (TransportInitiator::Remote, 40, 50, 60),
            ] {
                data.consume_qlog_event(
                    &Event::with_time(
                        0.0,
                        EventData::QuicParametersSet(Box::new(ParametersSet {
                            initiator: Some(initiator),
                            initial_max_stream_data_bidi_local: Some(bidi_local),
                            initial_max_stream_data_bidi_remote: Some(
                                bidi_remote,
                            ),
                            initial_max_stream_data_uni: Some(uni),
                            ..ParametersSet::default()
                        })),
                    ),
                    false,
                )?;
            }
            let frames: Vec<_> = (0..4)
                .map(|stream_id| QuicFrame::MaxStreamData {
                    stream_id,
                    maximum: 100,
                    raw: None,
                })
                .collect();
            data.consume_qlog_event(
                &Event::with_time(
                    1.0,
                    EventData::QuicPacketSent(PacketSent {
                        header: header(WirePacketType::OneRtt, Some(1)),
                        send_at_time: Some(3.0),
                        frames: Some(frames.clone()),
                        ..PacketSent::default()
                    }),
                ),
                false,
            )?;
            data.consume_qlog_event(
                &received(2.0, WirePacketType::OneRtt, Some(2), frames),
                false,
            )?;
            for (stream_id, local, peer) in [
                (0, local_bidi[0], remote_bidi[0]),
                (1, local_bidi[1], remote_bidi[1]),
                (2, 30, 60),
                (3, 30, 60),
            ] {
                assert_eq!(
                    data.sent_stream_max_data_tracker
                        .per_stream
                        .get(&stream_id)
                        .map(Vec::as_slice),
                    Some([(0.0, local), (3.0, 100)].as_slice())
                );
                assert_eq!(
                    data.received_stream_max_data_tracker
                        .per_stream
                        .get(&stream_id)
                        .map(Vec::as_slice),
                    Some([(0.0, peer), (2.0, 100)].as_slice())
                );
            }
        }
        Ok(())
    }
}
