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
use crate::trackers::QuicStreamObservation;
use crate::trackers::QuicStreamTracker;
use crate::trackers::StreamBufferTracker;
use crate::trackers::StreamMaxTracker;
use crate::trackers::TrackerError;
use crate::PacketType;
use crate::QlogPointRtt;
use crate::QlogPointu64;
use netlog;
use netlog::h2;
use netlog::h2::Http2Settings;
use netlog::h3;
use netlog::quic;

mod h2_flow;
pub use h2_flow::H2SendWindows;
mod netlog_reader;
pub use netlog_reader::with_netlog_reader;
pub use netlog_reader::NetlogSession;
pub use netlog_reader::QuicRequestDiscovery;
pub use netlog_reader::StreamBindingMap;

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
            VantagePoint::Client => Self::Client,
            VantagePoint::Server => Self::Server,
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
/// unsupported vantage point, stream arithmetic overflow, or event counters
/// that cannot be represented without wrapping.
#[derive(Debug)]
pub enum DatastoreError {
    UnsupportedVantagePoint(UnsupportedVantagePoint),
    Tracker(TrackerError),
    CounterOverflow { field: &'static str },
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
            Self::CounterOverflow { field } => {
                write!(f, "log counter overflow: {field}")
            },
        }
    }
}

impl std::error::Error for DatastoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsupportedVantagePoint(error) => Some(error),
            Self::Tracker(error) => Some(error),
            Self::CounterOverflow { .. } => None,
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
            Self::Http2 => "HTTP/2",
            Self::Http3 => "HTTP/3",
        };

        write!(f, "{v}")
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
        write!(f, "code={}, {}", self.error, self.description)
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

    pub last_event_time: f64,
    pub time_session_close: Option<f64>,

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

    /// Authoritative inbound STREAM/RESET evidence and connection credit.
    pub received_quic_streams: QuicStreamTracker,

    /// Authoritative outbound STREAM/RESET evidence and connection credit.
    pub sent_quic_streams: QuicStreamTracker,

    pub http_requests: BTreeMap<u64, HttpRequestStub>,

    pub local_initial_stream_limits: InitialStreamLimits,
    pub peer_initial_stream_limits: InitialStreamLimits,

    /// Credit granted to the peer by locally sent `WINDOW_UPDATE` frames.
    pub h2_recv_window_updates: BTreeMap<u32, Vec<(f64, u64)>>,

    // Local send credit changes: received grants minus transmitted DATA.
    pub h2_send_windows: H2SendWindows,
    // Resets can precede the first observed HTTP header or DATA frame.
    pub h2_reset_times: BTreeMap<u64, f64>,

    pub quic_peer_window_blocked: BTreeMap<i64, Vec<f64>>,

    /// Checked sum of known H2 inbound DATA lengths, used during ingestion.
    pub h2_received_data_total: u64,

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

fn checked_counter_sum(
    previous: u64, increment: u64, field: &'static str,
) -> Result<u64, DatastoreError> {
    previous
        .checked_add(increment)
        .ok_or(DatastoreError::CounterOverflow { field })
}

fn checked_counter_count(
    previous: usize, field: &'static str,
) -> Result<usize, DatastoreError> {
    previous
        .checked_add(1)
        .ok_or(DatastoreError::CounterOverflow { field })
}

/// Initial receive limits are relative to the endpoint advertising them.
///
/// For bidirectional streams bit zero
/// selects the initiator; bit one identifies unidirectional streams.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InitialStreamLimits {
    pub connection: Option<u64>,
    pub bidi_local: Option<u64>,
    pub bidi_remote: Option<u64>,
    pub uni: Option<u64>,
}

impl InitialStreamLimits {
    fn update(&mut self, observed: Self) {
        self.connection = observed.connection.or(self.connection);
        self.bidi_local = observed.bidi_local.or(self.bidi_local);
        self.bidi_remote = observed.bidi_remote.or(self.bidi_remote);
        self.uni = observed.uni.or(self.uni);
    }

    const fn for_stream(
        &self, stream_id: u64, advertiser: VantagePoint,
    ) -> Option<u64> {
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

/// Whether this endpoint sent or received a recorded event.
#[derive(Clone, Copy)]
enum LocalDirection {
    Sent,
    Received,
}

impl LocalDirection {
    const fn is_client_data(self, vantage: VantagePoint) -> bool {
        matches!(
            (self, vantage),
            (Self::Sent, VantagePoint::Client) |
                (Self::Received, VantagePoint::Server)
        )
    }
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
                    checked_counter_count(self.total_tx_ack, "total_tx_ack")?;
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
                    checked_counter_count(self.total_rx_ack, "total_rx_ack")?;
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
        h3_session_requests: Option<&QuicRequestDiscovery>,
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
        self.last_event_time = self
            .last_event_time
            .max(netlog_relative_time(ev_hdr.time_num, session_start_time));
        Ok(())
    }

    fn record_netlog_quic_stream_frame(
        &mut self, params: &quic::QuicSessionStreamFrameParams, time: f64,
        direction: LocalDirection,
    ) -> Result<(), TrackerError> {
        let observation = QuicStreamObservation::Frame {
            offset: Some(params.offset),
            length: Some(params.length),
            fin: Some(params.fin),
        };
        self.record_quic_stream(direction, params.stream_id, observation, time)
    }

    fn record_quic_stream(
        &mut self, direction: LocalDirection, stream_id: u64,
        observation: QuicStreamObservation, time: f64,
    ) -> Result<(), TrackerError> {
        match direction {
            LocalDirection::Sent =>
                self.sent_quic_streams.observe(stream_id, observation, time),
            LocalDirection::Received =>
                self.received_quic_streams
                    .observe(stream_id, observation, time),
        }
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
                self.discontinuous_packet_number_count = checked_counter_sum(
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

    fn record_session_close_time(&mut self, time: f64) {
        self.time_session_close =
            Some(self.time_session_close.map_or(time, |old| old.min(time)));
    }

    fn record_netlog_quic_close(
        &mut self, params: &quic::QuicSessionClosedParams,
        constants: &netlog::constants::Constants, time: f64,
    ) {
        self.record_session_close_time(time);
        self.quic_session_close = Some(QuicSessionClose {
            session_id: self.session_id.unwrap_or(-1),
            sni: self
                .host
                .clone()
                .unwrap_or_else(|| "ERROR UNKNOWN".to_owned()),
            details: params.details.clone(),
            from_peer: params.from_peer,
            quic_error: params.quic_error,
            quic_error_pretty: NaOption::new(
                constants
                    .quic_error_id_keyed
                    .get(&params.quic_error)
                    .cloned(),
            ),
        });
    }

    fn record_netlog_quic_reset(
        &mut self, params: &quic::QuicSessionRstStreamFrameParams, time: f64,
        direction: LocalDirection, constants: &netlog::constants::Constants,
    ) -> Result<(), TrackerError> {
        let (tracker, termination) = match direction {
            LocalDirection::Sent => (
                &mut self.sent_quic_streams,
                NetlogQuicTermination::ResetSent {
                    offset: params.offset,
                },
            ),
            LocalDirection::Received => (
                &mut self.received_quic_streams,
                NetlogQuicTermination::ResetReceived {
                    offset: params.offset,
                },
            ),
        };
        tracker.observe(
            params.stream_id,
            QuicStreamObservation::Reset {
                final_size: params.offset,
            },
            time,
        )?;
        self.record_netlog_quic_stream_termination(
            params.stream_id,
            params.quic_rst_stream_error,
            termination,
            constants,
        );
        Ok(())
    }

    fn record_quic_max_data(
        &mut self, direction: LocalDirection, time: f64, maximum: u64,
    ) {
        match direction {
            LocalDirection::Sent => &mut self.sent_max_data,
            LocalDirection::Received => &mut self.received_max_data,
        }
        .push((time, maximum));
    }

    fn record_quic_max_stream_data(
        &mut self, direction: LocalDirection, stream_id: u64, time: f64,
        maximum: u64,
    ) -> Result<(), TrackerError> {
        let (limits, advertiser, tracker) = match direction {
            LocalDirection::Sent => (
                &self.local_initial_stream_limits,
                self.vantage_point,
                &mut self.sent_stream_max_data_tracker,
            ),
            LocalDirection::Received => (
                &self.peer_initial_stream_limits,
                self.vantage_point.peer(),
                &mut self.received_stream_max_data_tracker,
            ),
        };
        tracker.update(
            stream_id,
            maximum,
            time,
            limits.for_stream(stream_id, advertiser),
        )?;
        Ok(())
    }

    fn record_netlog_quic_window_update(
        &mut self, direction: LocalDirection, time: f64,
        params: &quic::QuicSessionWindowUpdateFrameParams,
    ) -> Result<(), TrackerError> {
        if params.stream_id == -1 {
            self.record_quic_max_data(direction, time, params.byte_offset);
        } else if let Ok(stream_id) = u64::try_from(params.stream_id) {
            self.record_quic_max_stream_data(
                direction,
                stream_id,
                time,
                params.byte_offset,
            )?;
        } else {
            log::warn!(
                "ignoring negative stream id in netlog window update: {}",
                params.stream_id
            );
        }
        Ok(())
    }

    fn record_quic_initial_limits(
        &mut self, direction: LocalDirection, time: f64,
        observed: InitialStreamLimits,
    ) {
        if let Some(maximum) = observed.connection {
            self.record_quic_max_data(direction, time, maximum);
        }
        match direction {
            LocalDirection::Sent => &mut self.local_initial_stream_limits,
            LocalDirection::Received => &mut self.peer_initial_stream_limits,
        }
        .update(observed);
    }

    fn record_netlog_quic_transport_parameters(
        &mut self, direction: LocalDirection, time: f64,
        params: &quic::QuicSessionTransportParametersParams,
    ) {
        let parsed = quic::TransportParameters::from(
            params.quic_transport_parameters.as_str(),
        );
        self.record_quic_initial_limits(direction, time, InitialStreamLimits {
            connection: parsed.initial_max_data,
            bidi_local: parsed.initial_max_stream_data_bidi_local,
            bidi_remote: parsed.initial_max_stream_data_bidi_remote,
            uni: parsed.initial_max_stream_data_uni,
        });
    }

    fn consume_netlog_quic(
        &mut self, session_start_time: u64, ev_hdr: &netlog::EventHeader,
        ev: &quic::Event, constants: &netlog::constants::Constants,
    ) -> Result<(), DatastoreError> {
        let rel_event_time =
            netlog_relative_time(ev_hdr.time_num, session_start_time);

        match ev {
            quic::Event::QuicSessionStreamFrameReceived(e) => self
                .record_netlog_quic_stream_frame(
                    &e.params,
                    rel_event_time,
                    LocalDirection::Received,
                )?,
            quic::Event::QuicSessionStreamFrameSent(e) => self
                .record_netlog_quic_stream_frame(
                    &e.params,
                    rel_event_time,
                    LocalDirection::Sent,
                )?,

            quic::Event::QuicSessionUnauthenticatedPacketHeaderReceived(e) =>
                self.record_netlog_received_packet_header(
                    &e.params,
                    rel_event_time,
                )?,

            quic::Event::QuicSessionPacketSent(e) =>
                self.record_netlog_sent_packet(&e.params, rel_event_time),

            quic::Event::QuicSessionAckFrameSent(e) => self
                .record_netlog_ack_gaps(
                    NetlogAckDirection::Sent,
                    &e.params.missing_packets,
                    rel_event_time,
                )?,

            quic::Event::QuicSessionAckFrameReceived(e) => self
                .record_netlog_ack_gaps(
                    NetlogAckDirection::Received,
                    &e.params.missing_packets,
                    rel_event_time,
                )?,

            quic::Event::QuicSessionClosed(e) => self.record_netlog_quic_close(
                &e.params,
                constants,
                rel_event_time,
            ),

            quic::Event::QuicSessionRstStreamFrameReceived(e) => self
                .record_netlog_quic_reset(
                    &e.params,
                    rel_event_time,
                    LocalDirection::Received,
                    constants,
                )?,

            quic::Event::QuicSessionRstStreamFrameSent(e) => self
                .record_netlog_quic_reset(
                    &e.params,
                    rel_event_time,
                    LocalDirection::Sent,
                    constants,
                )?,

            quic::Event::QuicSessionStopSendingFrameSent(e) => self
                .record_netlog_quic_stream_termination(
                    e.params.stream_id,
                    e.params.quic_rst_stream_error,
                    NetlogQuicTermination::StopSendingSent,
                    constants,
                ),

            quic::Event::QuicSessionBlockedFrameReceived(e) => {
                let s = self
                    .quic_peer_window_blocked
                    .entry(e.params.stream_id)
                    .or_default();
                s.push(rel_event_time);
            },

            quic::Event::QuicSessionWindowUpdateFrameSent(e) => self
                .record_netlog_quic_window_update(
                    LocalDirection::Sent,
                    rel_event_time,
                    &e.params,
                )?,
            quic::Event::QuicSessionWindowUpdateFrameReceived(e) => self
                .record_netlog_quic_window_update(
                    LocalDirection::Received,
                    rel_event_time,
                    &e.params,
                )?,

            quic::Event::QuicSessionTransportParametersSent(e) => self
                .record_netlog_quic_transport_parameters(
                    LocalDirection::Sent,
                    rel_event_time,
                    &e.params,
                ),
            quic::Event::QuicSessionTransportParametersReceived(e) => self
                .record_netlog_quic_transport_parameters(
                    LocalDirection::Received,
                    rel_event_time,
                    &e.params,
                ),

            quic::Event::QuicSession(_) => (),
        }
        Ok(())
    }

    /// Record known DATA lengths consistently across log formats and endpoint
    /// roles. Validate arithmetic before mutating frame history or request
    /// metadata.
    fn record_http_data(
        &mut self, direction: LocalDirection, stream_id: u64,
        length: Option<u64>, time: f64,
    ) -> Result<(), DatastoreError> {
        let req = self.get_or_insert_http_req(stream_id);
        let (history, field) = match direction {
            LocalDirection::Sent => (&mut req.sent_data, "sent_data_bytes"),
            LocalDirection::Received =>
                (&mut req.received_data, "received_data_bytes"),
        };
        history
            .record(time, length)
            .map_err(|_| DatastoreError::CounterOverflow { field })
    }

    /// Chrome HTTP/2 additionally records a connection-wide DATA total.
    fn record_netlog_received_data(
        &mut self, proto: ApplicationProto, stream_id: u64, length: u64,
        event_time: f64,
    ) -> Result<(), DatastoreError> {
        let connection_total = match proto {
            ApplicationProto::Http2 => Some(checked_counter_sum(
                self.h2_received_data_total,
                length,
                "h2_received_data_total",
            )?),
            ApplicationProto::Http3 => None,
        };
        self.record_http_data(
            LocalDirection::Received,
            stream_id,
            Some(length),
            event_time,
        )?;
        if let Some(total) = connection_total {
            self.h2_received_data_total = total;
        }
        Ok(())
    }

    /// HTTP/2 outbound DATA also consumes send-window credit.
    fn record_netlog_sent_h2_data(
        &mut self, params: &h2::Http2SessionSendDataParams, event_time: f64,
    ) -> Result<(), DatastoreError> {
        self.record_http_data(
            LocalDirection::Sent,
            u64::from(params.stream_id),
            Some(u64::from(params.size)),
            event_time,
        )?;
        let delta = -i64::from(params.size);
        self.h2_send_windows
            .change(params.stream_id, event_time, delta);
        if params.stream_id != 0 {
            self.h2_send_windows.change(0, event_time, delta);
        }
        if params.fin {
            self.h2_send_windows.close(params.stream_id, event_time);
            self.record_h2_data_end(
                params.stream_id,
                LocalDirection::Sent,
                event_time,
            );
        }
        Ok(())
    }

    fn record_netlog_received_h2_data(
        &mut self, params: &h2::Http2SessionRecvDataParams, time: f64,
    ) -> Result<(), DatastoreError> {
        self.record_netlog_received_data(
            ApplicationProto::Http2,
            u64::from(params.stream_id),
            u64::from(params.size),
            time,
        )?;
        self.observe_h2_received_stream(params.stream_id, time);
        if params.fin {
            self.record_h2_data_end(
                params.stream_id,
                LocalDirection::Received,
                time,
            );
        }
        Ok(())
    }

    fn record_netlog_http_headers(
        &mut self, stream_id: u64, direction: LocalDirection, time: f64,
        headers: &[String], end_stream: bool,
    ) -> &mut HttpRequestStub {
        let is_request = direction.is_client_data(self.vantage_point);
        let req = self.get_or_insert_http_req(stream_id);
        req.observe_headers(time, matches!(direction, LocalDirection::Sent));
        if is_request {
            req.set_request_info_from_netlog(headers);
        } else {
            req.set_response_info_from_netlog(headers);
            if end_stream {
                req.record_response_terminal(time);
            }
        }
        req
    }

    fn record_h2_data_end(
        &mut self, stream_id: u32, direction: LocalDirection, time: f64,
    ) {
        if !direction.is_client_data(self.vantage_point) {
            self.get_or_insert_http_req(u64::from(stream_id))
                .record_response_terminal(time);
        }
    }

    fn consume_netlog_h3(
        &mut self, session_start_time: u64, ev_hdr: &netlog::EventHeader,
        ev: &h3::Event, h3_session_requests: Option<&QuicRequestDiscovery>,
    ) -> Result<(), DatastoreError> {
        let rel_event_time =
            netlog_relative_time(ev_hdr.time_num, session_start_time);

        match ev {
            h3::Event::Http3PriorityUpdateSent(e) => {
                let req =
                    self.get_or_insert_http_req(e.params.prioritized_element_id);
                req.priority_updates
                    .push(e.params.priority_field_value.clone());
            },

            h3::Event::Http3HeadersSent(e) => {
                let is_request =
                    LocalDirection::Sent.is_client_data(self.vantage_point);
                let req = self.record_netlog_http_headers(
                    e.params.stream_id,
                    LocalDirection::Sent,
                    rel_event_time,
                    &e.params.headers,
                    false,
                );

                if let Some(time) = h3_session_requests
                    .filter(|_| is_request)
                    .and_then(|requests| requests.get(&e.params.stream_id))
                {
                    req.time_discovery =
                        Some(netlog_relative_time(*time, session_start_time));
                }
            },

            h3::Event::Http3HeadersDecoded(e) => {
                self.record_netlog_http_headers(
                    e.params.stream_id,
                    LocalDirection::Received,
                    rel_event_time,
                    &e.params.headers,
                    false,
                );
            },

            h3::Event::Http3DataFrameReceived(e) => self
                .record_netlog_received_data(
                    ApplicationProto::Http3,
                    e.params.stream_id,
                    e.params.payload_length,
                    rel_event_time,
                )?,

            h3::Event::Http3DataSent(e) => self.record_http_data(
                LocalDirection::Sent,
                e.params.stream_id,
                Some(e.params.payload_length),
                rel_event_time,
            )?,

            // Decoded headers are handled above.
            h3::Event::Http3HeadersReceived(_) => (),
        }
        Ok(())
    }

    // Chrome logs a client endpoint. Server-initiated push streams do not
    // have a client send side; the connection itself always has one.
    const fn h2_has_local_send_side(&self, stream_id: u32) -> bool {
        stream_id == 0 ||
            stream_id & 1 != 0 ||
            matches!(self.vantage_point, VantagePoint::Server)
    }

    /// A received frame on a stream with a local send side provides
    /// evidence of that stream's existence in a partial capture.
    fn observe_h2_received_stream(&mut self, stream_id: u32, time: f64) {
        if stream_id != 0 && self.h2_has_local_send_side(stream_id) {
            self.h2_send_windows.open(stream_id, time);
        }
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
            NetlogH2Direction::Received
                if self.h2_has_local_send_side(stream_id) =>
            {
                self.h2_send_windows.change(
                    stream_id,
                    event_time,
                    i64::from(delta),
                );
            },
            NetlogH2Direction::Received => (),
            NetlogH2Direction::Sent => {
                self.h2_recv_window_updates
                    .entry(stream_id)
                    .or_default()
                    .push((event_time, increment));
            },
        }
    }

    /// Netlog request resets are recorded only for known request streams.
    /// The received `RESET_STREAM` event provides no description text.
    fn record_netlog_h2_stream_reset(
        &mut self, direction: NetlogH2Direction, stream_id: u32,
        error_code: &str, description: Option<&str>, time: f64,
    ) {
        self.h2_send_windows.close(stream_id, time);
        self.h2_reset_times
            .entry(u64::from(stream_id))
            .and_modify(|old| *old = old.min(time))
            .or_insert(time);
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
        constants: &netlog::constants::Constants, time: f64,
    ) {
        self.h2_send_windows.close_session(time);
        self.record_session_close_time(time);
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

    fn record_netlog_h2_peer_setting(
        &mut self, params: &h2::Http2SessionRecvSettingParams, time: f64,
    ) {
        let Some(id) = h2::parse_recv_setting_id(&params.id) else {
            error!("parsing H2 setting {params:?}");
            return;
        };
        let value = params.value;
        if id == h2::H2_INITIAL_WINDOW_SIZE {
            if value > h2::H2_MAX_WINDOW_SIZE {
                error!("ignoring invalid HTTP/2 initial send window: {value}");
                return;
            }
            self.h2_send_windows.set_initial_credit(time, value);
        }
        self.h2_server_settings.set_from_wire(id, value);
    }

    fn record_netlog_h2_sent_headers(
        &mut self, params: &h2::Http2SessionSendHeadersParams, time: f64,
        session_start_time: u64, stream_bind: &StreamBindingMap,
    ) {
        self.h2_send_windows.open(params.stream_id, time);
        if params.fin {
            self.h2_send_windows.close(params.stream_id, time);
        }
        let is_request = LocalDirection::Sent.is_client_data(self.vantage_point);
        let req = self.record_netlog_http_headers(
            u64::from(params.stream_id),
            LocalDirection::Sent,
            time,
            &params.headers,
            params.fin,
        );

        if let Some(sb) = stream_bind
            .get(&params.source_dependency.id)
            .filter(|_| is_request)
        {
            // Discovery can precede the session's creation.
            req.time_discovery =
                Some(netlog_relative_time(*sb, session_start_time));
        }
    }

    fn consume_netlog_h2(
        &mut self, session_start_time: u64, ev_hdr: &netlog::EventHeader,
        ev: &h2::Event, constants: &netlog::constants::Constants,
        stream_bind: &StreamBindingMap,
    ) -> Result<(), DatastoreError> {
        let rel_event_time =
            netlog_relative_time(ev_hdr.time_num, session_start_time);

        match ev {
            h2::Event::Http2SessionSendSettings(e) =>
                match Http2Settings::try_from(e.params.settings.as_slice()) {
                    Ok(v) => self.h2_client_settings = v,

                    Err(e) => error!("{e}"),
                },

            h2::Event::Http2SessionRecvSetting(e) => {
                self.record_netlog_h2_peer_setting(&e.params, rel_event_time);
            },
            h2::Event::Http2SessionSendHeaders(e) => self
                .record_netlog_h2_sent_headers(
                    &e.params,
                    rel_event_time,
                    session_start_time,
                    stream_bind,
                ),

            h2::Event::Http2SessionRecvHeaders(e) => {
                self.observe_h2_received_stream(
                    e.params.stream_id,
                    rel_event_time,
                );
                self.record_netlog_http_headers(
                    u64::from(e.params.stream_id),
                    LocalDirection::Received,
                    rel_event_time,
                    &e.params.headers,
                    e.params.fin,
                );
            },

            h2::Event::Http2SessionRecvData(e) =>
                self.record_netlog_received_h2_data(&e.params, rel_event_time)?,

            h2::Event::Http2SessionSendData(e) =>
                self.record_netlog_sent_h2_data(&e.params, rel_event_time)?,

            h2::Event::Http2SessionRecvWindowUpdate(e) => self
                .record_netlog_h2_window_update(
                    NetlogH2Direction::Received,
                    e.params.stream_id,
                    e.params.delta,
                    rel_event_time,
                ),

            h2::Event::Http2SessionSendWindowUpdate(e) => self
                .record_netlog_h2_window_update(
                    NetlogH2Direction::Sent,
                    e.params.stream_id,
                    e.params.delta,
                    rel_event_time,
                ),

            h2::Event::Http2SessionClose(e) => self
                .record_netlog_h2_session_close(
                    &e.params,
                    constants,
                    rel_event_time,
                ),

            h2::Event::Http2SessionSendRstStream(e) => self
                .record_netlog_h2_stream_reset(
                    NetlogH2Direction::Sent,
                    e.params.stream_id,
                    &e.params.error_code,
                    Some(&e.params.description),
                    rel_event_time,
                ),

            h2::Event::Http2SessionRecvRstStream(e) => self
                .record_netlog_h2_stream_reset(
                    NetlogH2Direction::Received,
                    e.params.stream_id,
                    &e.params.error_code,
                    None,
                    rel_event_time,
                ),

            // Recognized netlog events with no datastore series.
            h2::Event::Http2Session(_) |
            h2::Event::Http2SessionInitialized(_) |
            h2::Event::Http2SessionUpdateRecvWindow(_) |
            h2::Event::Http2SessionUpdateSendWindow(_) |
            h2::Event::Http2SessionUpdateStreamsSendWindowSize(_) |
            h2::Event::Http2SessionStalledMaxStreams(_) |
            h2::Event::Http2StreamUpdateSendWindow(_) |
            h2::Event::Http2StreamUpdateRecvWindow(_) |
            h2::Event::Http2StreamStalledByStreamSendWindow(_) |
            h2::Event::Http2SessionPing(_) |
            h2::Event::Http2SessionRecvGoaway(_) => (),
        }
        Ok(())
    }

    /// Consume one typed qlog event.
    ///
    /// # Errors
    /// Returns tracker or DATA counter overflow. A multi-frame event may
    /// already have updated unrelated fields; discard the datastore on failure.
    /// Both log constructors and the browser's transactional builder do so.
    pub fn consume_qlog_event(
        &mut self, event: &qlog::events::Event, process_acks: bool,
    ) -> Result<(), DatastoreError> {
        let ev_time = event.time;

        match &event.data {
            EventData::QuicConnectionClosed(_) =>
                self.record_session_close_time(ev_time),

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
                v.length.or_else(|| {
                    v.raw.as_ref().and_then(|raw| raw.payload_length)
                }),
                ev_time,
                LocalDirection::Sent,
            )?,

            EventData::Http3FrameParsed(v) => self.consume_qlog_h3_frame(
                v.stream_id,
                &v.frame,
                v.length.or_else(|| {
                    v.raw.as_ref().and_then(|raw| raw.payload_length)
                }),
                ev_time,
                LocalDirection::Received,
            )?,

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

        let mut ds = Self {
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
        if let Some(last) = self.local_cwnd.last().copied() {
            self.local_cwnd.push((self.last_event_time, last.1));
        }

        if let Some(last) = self.local_pacing_rate.last().copied() {
            trace!("pushing last {last:?}");
            self.local_pacing_rate.push((self.last_event_time, last.1));
        }
    }

    pub fn hydrate_http_requests(&mut self) {
        for (&stream_id, req) in &mut self.http_requests {
            let response_streams = match req.request_actor {
                RequestActor::Client => &self.received_quic_streams,
                RequestActor::Server => &self.sent_quic_streams,
            };
            if let Some(history) = response_streams.streams().get(&stream_id) {
                if let Some(terminal) = history
                    .points()
                    .iter()
                    .filter_map(|(time, observation)| {
                        matches!(
                            observation,
                            QuicStreamObservation::Frame {
                                fin: Some(true),
                                ..
                            } | QuicStreamObservation::Reset { .. }
                        )
                        .then_some(*time)
                    })
                    .min_by(f64::total_cmp)
                {
                    req.record_response_terminal(terminal);
                }
            }
            if let Some(&time) = self.h2_reset_times.get(&stream_id) {
                req.record_response_terminal(time);
            }
            req.calculate_deltas();
        }
    }

    fn consume_qlog_transport_parameters_set(
        &mut self, tp: &qlog::events::quic::ParametersSet,
    ) {
        let direction = match tp.initiator {
            Some(TransportInitiator::Local) => LocalDirection::Sent,
            Some(TransportInitiator::Remote) => LocalDirection::Received,
            None => {
                trace!("ignoring transport parameters with no initiator");
                return;
            },
        };
        self.record_quic_initial_limits(direction, 0.0, InitialStreamLimits {
            connection: tp.initial_max_data,
            bidi_local: tp.initial_max_stream_data_bidi_local,
            bidi_remote: tp.initial_max_stream_data_bidi_remote,
            uni: tp.initial_max_stream_data_uni,
        });
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

    fn record_qlog_stream_frame(
        &mut self, direction: LocalDirection, frame: &QuicFrame, time: f64,
    ) -> Result<(), TrackerError> {
        match frame {
            QuicFrame::MaxData { maximum, .. } => {
                self.record_quic_max_data(direction, time, *maximum);
            },

            QuicFrame::MaxStreamData {
                stream_id, maximum, ..
            } => self.record_quic_max_stream_data(
                direction, *stream_id, time, *maximum,
            )?,

            QuicFrame::ResetStream {
                stream_id,
                final_size,
                ..
            } => {
                let (tracker, resets) = match direction {
                    LocalDirection::Sent =>
                        (&mut self.sent_quic_streams, &mut self.sent_reset_stream),
                    LocalDirection::Received => (
                        &mut self.received_quic_streams,
                        &mut self.received_reset_stream,
                    ),
                };
                tracker.observe(
                    *stream_id,
                    QuicStreamObservation::Reset {
                        final_size: *final_size,
                    },
                    time,
                )?;
                resets.entry(*stream_id).or_default().push(frame.clone());
            },

            QuicFrame::Stream {
                stream_id,
                offset,
                fin,
                raw,
            } => {
                self.record_quic_stream(
                    direction,
                    *stream_id,
                    QuicStreamObservation::Frame {
                        offset: *offset,
                        length: raw.as_ref().and_then(|raw| raw.payload_length),
                        fin: *fin,
                    },
                    time,
                )?;
            },

            _ => (),
        }
        Ok(())
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

                    QuicFrame::DataBlocked { .. } => {
                        self.quic_peer_window_blocked
                            .entry(-1)
                            .or_default()
                            .push(ev_time);
                    },

                    _ => self.record_qlog_stream_frame(
                        LocalDirection::Received,
                        frame,
                        ev_time,
                    )?,
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

                    QuicFrame::DataBlocked { limit, .. } => {
                        trace!("todo DATA_BLOCKED t={event_time} limit={limit}");
                    },

                    QuicFrame::StreamDataBlocked {
                        stream_id, limit, ..
                    } => {
                        trace!(
                            "todo STREAM_DATA_BLOCKED t={event_time} stream={stream_id} limit={limit}"
                        );
                    },

                    _ => self.record_qlog_stream_frame(
                        LocalDirection::Sent,
                        frame,
                        event_time,
                    )?,
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
        if let Some(rate) = mu
            .ex_data
            .get("cf_delivery_rate")
            .and_then(serde_json::Value::as_u64)
        {
            self.local_delivery_rate.push((ev_time, rate));
        }

        if let Some(rate) = mu
            .ex_data
            .get("cf_send_rate")
            .and_then(serde_json::Value::as_u64)
        {
            self.local_send_rate.push((ev_time, rate));
        }

        if let Some(rate) = mu
            .ex_data
            .get("cf_ack_rate")
            .and_then(serde_json::Value::as_u64)
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
    /// requests and responses and which DATA lengths are client/server bytes.
    fn consume_qlog_h3_frame(
        &mut self, stream_id: u64, frame: &Http3Frame, length: Option<u64>,
        ev_time: f64, direction: LocalDirection,
    ) -> Result<(), DatastoreError> {
        match frame {
            Http3Frame::Headers { headers, .. } => {
                let vantage = self.vantage_point;
                let req = self.get_or_insert_http_req(stream_id);
                req.observe_headers(
                    ev_time,
                    matches!(direction, LocalDirection::Sent),
                );
                if direction.is_client_data(vantage) {
                    req.set_request_info_from_qlog(headers);
                } else {
                    req.set_response_info_from_qlog(headers);
                }
            },

            Http3Frame::Data { raw } => {
                // The frame declares a payload length, not necessarily
                // delivery of its entire body. Unknown lengths still carry
                // timing evidence but cannot contribute numeric bytes.
                let length = length
                    .or_else(|| raw.as_ref().and_then(|raw| raw.payload_length));
                self.record_http_data(direction, stream_id, length, ev_time)?;
            },

            Http3Frame::PriorityUpdate {
                stream_id: Some(priority_stream_id),
                priority_field_value,
                ..
            } if direction.is_client_data(self.vantage_point) => {
                self.get_or_insert_http_req(*priority_stream_id)
                    .priority_updates
                    .push(priority_field_value.clone());
            },

            _ => (),
        }
        Ok(())
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

        let mut ds = Self {
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
                    error!("unhandled Json event {ev:?}");
                },
            }
        }

        ds.hydrate_http_requests();
        ds.finalize();

        Ok(ds)
    }
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
                    assert_eq!(tracker.sum_series(), vec![(2.0, 10)]);
                } else {
                    assert_eq!(tracker.get_stream_max(13), None);
                    assert_eq!(tracker.sum_series(), []);
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
        assert!(ds.stream_buffer_reads_tracker.streams().is_empty());
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
            .streams()
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
        assert_eq!(datastore.sent_max_data, []);
        assert_eq!(datastore.received_max_data, []);
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
    use std::collections::HashSet;
    use std::fmt::Write;
    use std::io::Cursor;

    fn constants() -> Result<netlog::constants::Constants, serde_json::Error> {
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
            }))?;
        constants.populate_id_keyed();
        Ok(constants)
    }

    fn consume(
        constants: &netlog::constants::Constants, datastore: &mut Datastore,
        time: u64, event: &netlog::Event,
    ) -> Result<(), DatastoreError> {
        datastore.consume_netlog_event(
            100,
            &netlog::EventHeader {
                time_num: time,
                ..Default::default()
            },
            event,
            constants,
            &StreamBindingMap::new(),
            None,
        )
    }

    fn quic_stream(length: u64) -> netlog::Event {
        netlog::Event::Quic(quic::Event::QuicSessionStreamFrameReceived(
            quic::QuicSessionStreamFrameEvent {
                params: quic::QuicSessionStreamFrameParams {
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
                params: h2::Http2SessionRecvDataParams {
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
            netlog::EventPayload {
                params: h3::Http3DataParams {
                    stream_id,
                    payload_length: size,
                },
            },
        ))
    }

    #[test]
    fn netlog_h3_sent_data_reaches_upload_plot_without_h2_credit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut datastore = Datastore::default();
        for (time, length) in [(101, 4), (105, 9), (108, 0)] {
            let event = netlog::Event::H3(h3::Event::Http3DataSent(
                netlog::EventPayload {
                    params: h3::Http3DataParams {
                        stream_id: 5,
                        payload_length: length,
                    },
                },
            ));
            consume(&constants, &mut datastore, time, &event)?;
        }
        let series = crate::seriesstore::SeriesStore::from_datastore(&datastore)?;
        assert_eq!(
            series.sent_data_frames_series.get(&5).map(Vec::as_slice),
            Some([(1.0, 0), (1.0, 4), (5.0, 13), (8.0, 13)].as_slice())
        );
        assert_eq!(series.received_data_frames_series.get(&5), None);
        assert_eq!(series.h2_send_window_series_balanced.get(&5), None);
        Ok(())
    }

    #[test]
    fn netlog_h2_h3_received_data_record_identical_per_stream_histories(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut h2 = Datastore {
            application_proto: ApplicationProto::Http2,
            ..Datastore::default()
        };
        let mut h3 = Datastore::default();

        for (time, length) in [(102, 5), (104, 7), (106, 0)] {
            consume(&constants, &mut h2, time, &h2_received(9, length))?;
            consume(
                &constants,
                &mut h3,
                time,
                &h3_received(9, u64::from(length)),
            )?;
        }

        for ds in [&h2, &h3] {
            let request = &ds.http_requests[&9];
            assert_eq!(request.received_data.first_time(), Some(2.0));
            assert_eq!(request.received_data.last_time(), Some(6.0));
            assert_eq!(request.received_data.observations(), [
                (2.0, Some(5)),
                (4.0, Some(7)),
                (6.0, Some(0))
            ]);
            assert_eq!(request.server_data().complete_bytes(), Some(12));
            assert_eq!(request.sent_data.observations(), []);
            let series = crate::seriesstore::SeriesStore::from_datastore(ds)?;
            assert_eq!(
                series
                    .received_data_frames_series
                    .get(&9)
                    .map(Vec::as_slice),
                Some([(2.0, 0), (2.0, 5), (4.0, 12), (6.0, 12)].as_slice())
            );
        }

        // Only HTTP/2 records connection-wide received DATA. HTTP/3 uses
        // QUIC STREAM frames for its separate connection aggregate.
        assert_eq!(h2.h2_received_data_total, 12);
        assert_eq!(h3.h2_received_data_total, 0);
        let h2_series = crate::seriesstore::SeriesStore::from_datastore(&h2)?;
        assert_eq!(h2_series.netlog_h2_stream_received_connection_cumulative, [
            (2.0, 0),
            (2.0, 0),
            (2.0, 5),
            (4.0, 5),
            (4.0, 12),
            (6.0, 12),
            (6.0, 12)
        ]);
        let h3_series = crate::seriesstore::SeriesStore::from_datastore(&h3)?;
        assert_eq!(
            h3_series.netlog_h2_stream_received_connection_cumulative,
            [] as [(f64, u64); 0]
        );
        Ok(())
    }

    #[test]
    fn netlog_h2_sent_data_updates_upload_histories_and_send_credit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut datastore = Datastore::default();
        for (time, length) in [(101, 4), (105, 9), (108, 0)] {
            consume(&constants, &mut datastore, time, &h2_sent(5, length))?;
        }

        assert_eq!(datastore.h2_send_windows.histories()[&5].changes, vec![
            (1.0, -4),
            (5.0, -9),
            (8.0, 0)
        ]);
        assert_eq!(
            datastore.h2_send_windows.histories()[&0].changes,
            datastore.h2_send_windows.histories()[&5].changes
        );
        let request = &datastore.http_requests[&5];
        assert_eq!(request.sent_data.first_time(), Some(1.0));
        assert_eq!(request.sent_data.last_time(), Some(8.0));
        assert_eq!(request.client_data().complete_bytes(), Some(13));
        assert_eq!(request.sent_data.observations(), [
            (1.0, Some(4)),
            (5.0, Some(9)),
            (8.0, Some(0))
        ]);
        assert_eq!(request.received_data.observations(), []);
        Ok(())
    }

    #[test]
    fn netlog_quic_reset_and_stop_sending_preserve_direction_and_error_names(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut datastore = Datastore::default();

        let reset_received =
            netlog::Event::Quic(quic::Event::QuicSessionRstStreamFrameReceived(
                quic::QuicSessionRstStreamFrameEvent {
                    params: quic::QuicSessionRstStreamFrameParams {
                        stream_id: 7,
                        offset: 11,
                        quic_rst_stream_error: 42,
                    },
                },
            ));
        let reset_sent =
            netlog::Event::Quic(quic::Event::QuicSessionRstStreamFrameSent(
                quic::QuicSessionRstStreamFrameEvent {
                    params: quic::QuicSessionRstStreamFrameParams {
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
        consume(&constants, &mut datastore, 101, &reset_received)?;
        consume(&constants, &mut datastore, 102, &reset_sent)?;
        consume(&constants, &mut datastore, 103, &stop)?;
        assert!(datastore.http_requests.is_empty());

        datastore.get_or_insert_http_req(7);
        for event in [&reset_received, &reset_sent, &stop] {
            consume(&constants, &mut datastore, 104, event)?;
        }
        let request = &datastore.http_requests[&7];
        let received = request
            .quic_stream_reset_received
            .as_ref()
            .ok_or("received reset recorded")?;
        let sent = request
            .quic_stream_reset_sent
            .as_ref()
            .ok_or("sent reset recorded")?;
        let stopped = request
            .quic_stream_stop_sending_sent
            .as_ref()
            .ok_or("sent stop-sending recorded")?;
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
                quic::QuicSessionRstStreamFrameEvent {
                    params: quic::QuicSessionRstStreamFrameParams {
                        stream_id: 7,
                        offset: u64::MAX,
                        quic_rst_stream_error: u64::MAX,
                    },
                },
            ));
        consume(&constants, &mut datastore, 105, &huge)?;
        let request = &datastore.http_requests[&7];
        let received = request
            .quic_stream_reset_received
            .as_ref()
            .ok_or("large-code received reset recorded")?;
        assert_eq!(received.offset, u64::MAX);
        assert_eq!(received.quic_rst_stream_error, u64::MAX);
        assert!(received.quic_rst_stream_error_friendly.is_none());
        assert_eq!(
            request
                .quic_stream_reset_sent
                .as_ref()
                .ok_or("sent reset preserved")?
                .offset,
            29
        );
        Ok(())
    }

    #[test]
    fn netlog_quic_credit_uses_high_water_marks_and_received_final_sizes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut datastore = Datastore::default();
        let frame = |stream_id, offset, length| {
            netlog::Event::Quic(quic::Event::QuicSessionStreamFrameReceived(
                quic::QuicSessionStreamFrameEvent {
                    params: quic::QuicSessionStreamFrameParams {
                        stream_id,
                        offset,
                        length,
                        fin: false,
                    },
                },
            ))
        };
        let reset = || {
            netlog::Event::Quic(quic::Event::QuicSessionRstStreamFrameReceived(
                quic::QuicSessionRstStreamFrameEvent {
                    params: quic::QuicSessionRstStreamFrameParams {
                        stream_id: 11,
                        offset: 100,
                        quic_rst_stream_error: 42,
                    },
                },
            ))
        };
        let grant = |byte_offset| {
            netlog::Event::Quic(quic::Event::QuicSessionWindowUpdateFrameSent(
                quic::QuicSessionWindowUpdateFrameEvent {
                    params: quic::QuicSessionWindowUpdateFrameParams {
                        byte_offset,
                        stream_id: -1,
                    },
                },
            ))
        };
        for (time, event) in [
            (101, grant(500)),
            (102, frame(7, 100, 50)),
            (103, frame(11, 0, 20)),
            (104, frame(7, 90, 30)),
            (105, frame(7, 140, 20)),
            (106, reset()),
            (107, reset()),
            (108, grant(600)),
            (109, grant(500)),
        ] {
            consume(&constants, &mut datastore, time, &event)?;
        }
        assert!(datastore.http_requests.is_empty());
        assert_eq!(datastore.received_quic_streams.sum_series(), [
            (2.0, 150),
            (3.0, 170),
            (4.0, 170),
            (5.0, 180),
            (6.0, 260),
            (7.0, 260)
        ]);
        let series = crate::seriesstore::SeriesStore::from_datastore(&datastore)?;
        assert_eq!(series.sent_max_data.last(), Some(&(9.0, 600)));
        assert_eq!(
            series.quic_receive_credit_consumed.last(),
            Some(&(7.0, 260))
        );
        assert_eq!(series.received_stream_frames_series[&11], [(3.0, 20)]);
        Ok(())
    }

    #[test]
    fn netlog_both_credit_directions_use_shared_initial_and_update_histories(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut data = Datastore::default();
        for (time, kind, payload) in [
            (
                101,
                "QUIC_SESSION_TRANSPORT_PARAMETERS_SENT",
                serde_json::json!({"quic_transport_parameters":"[Client initial_max_data 500 initial_max_stream_data_bidi_local 100]"}),
            ),
            (
                102,
                "QUIC_SESSION_TRANSPORT_PARAMETERS_RECEIVED",
                serde_json::json!({"quic_transport_parameters":"[Server initial_max_data 600 initial_max_stream_data_bidi_remote 200]"}),
            ),
            (
                103,
                "QUIC_SESSION_WINDOW_UPDATE_FRAME_SENT",
                serde_json::json!({"stream_id":0,"byte_offset":150}),
            ),
            (
                104,
                "QUIC_SESSION_WINDOW_UPDATE_FRAME_RECEIVED",
                serde_json::json!({"stream_id":0,"byte_offset":180}),
            ),
            (
                105,
                "QUIC_SESSION_WINDOW_UPDATE_FRAME_RECEIVED",
                serde_json::json!({"stream_id":-1,"byte_offset":"9007199254740993"}),
            ),
            (
                106,
                "QUIC_SESSION_WINDOW_UPDATE_FRAME_RECEIVED",
                serde_json::json!({"stream_id":-1,"byte_offset":700}),
            ),
        ] {
            let header = netlog::EventHeader {
                ty_string: kind.into(),
                time_num: time,
                ..Default::default()
            };
            let bytes =
                serde_json::to_vec(&serde_json::json!({"params":payload}))?;
            let event = netlog::parse_event(&header, &bytes)
                .ok_or("netlog credit event did not decode")?;
            consume(&constants, &mut data, time, &event)?;
        }
        assert_eq!(data.sent_max_data, [(1.0, 500)]);
        assert_eq!(data.received_max_data, [
            (2.0, 600),
            (5.0, 9_007_199_254_740_993),
            (6.0, 700)
        ]);
        assert_eq!(
            data.sent_stream_max_data_tracker.get_stream_max(0),
            Some(150)
        );
        assert_eq!(
            data.received_stream_max_data_tracker.get_stream_max(0),
            Some(200)
        );
        let series = crate::seriesstore::SeriesStore::from_datastore(&data)?;
        assert_eq!(
            series.received_max_data.last(),
            Some(&(6.0, 9_007_199_254_740_993))
        );
        assert_eq!(series.sent_stream_max_data[&0].last(), Some(&(3.0, 150)));
        assert_eq!(
            series.received_stream_max_data[&0].last(),
            Some(&(4.0, 200))
        );
        Ok(())
    }

    #[test]
    fn netlog_sent_stream_frames_are_decoded_and_counted_independently(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut data = Datastore::default();
        for (time, kind, offset, length) in [
            (105, "QUIC_SESSION_STREAM_FRAME_SENT", 100, 20),
            (102, "QUIC_SESSION_STREAM_FRAME_SENT", 0, 10),
            (106, "QUIC_SESSION_STREAM_FRAME_SENT", 90, 20),
            (103, "QUIC_SESSION_STREAM_FRAME_RECEIVED", 0, 5),
        ] {
            let header = netlog::EventHeader {
                ty_string: kind.into(),
                time_num: time,
                ..Default::default()
            };
            let payload = serde_json::to_vec(&serde_json::json!({
                "params": {"stream_id": 7, "offset": offset, "length": length, "fin": false}
            }))?;
            let event = netlog::parse_event(&header, &payload)
                .ok_or("STREAM event did not decode")?;
            consume(&constants, &mut data, time, &event)?;
        }
        let reset =
            netlog::Event::Quic(quic::Event::QuicSessionRstStreamFrameSent(
                quic::QuicSessionRstStreamFrameEvent {
                    params: quic::QuicSessionRstStreamFrameParams {
                        stream_id: 7,
                        offset: 200,
                        quic_rst_stream_error: 42,
                    },
                },
            ));
        consume(&constants, &mut data, 107, &reset)?;
        let series = crate::seriesstore::SeriesStore::from_datastore(&data)?;
        assert_eq!(data.sent_quic_streams.current_sum(), 200);
        assert_eq!(data.received_quic_streams.current_sum(), 5);
        assert_eq!(series.sent_stream_frames_series[&7], [
            (2.0, 10),
            (5.0, 120),
            (6.0, 110)
        ]);
        assert_eq!(series.received_stream_frames_series[&7], [(3.0, 5)]);
        assert_eq!(series.quic_send_credit_consumed.last(), Some(&(7.0, 200)));
        assert_eq!(series.quic_receive_credit_consumed.last(), Some(&(3.0, 5)));
        Ok(())
    }

    #[test]
    fn response_terminal_hydration_uses_the_response_direction_and_reset_evidence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for vantage in [VantagePoint::Client, VantagePoint::Server] {
            let mut ds = Datastore {
                vantage_point: vantage,
                ..Datastore::default()
            };
            let (request, response) = match vantage {
                VantagePoint::Client =>
                    (LocalDirection::Sent, LocalDirection::Received),
                VantagePoint::Server =>
                    (LocalDirection::Received, LocalDirection::Sent),
            };
            let fin = QuicStreamObservation::Frame {
                offset: Some(5),
                length: Some(0),
                fin: Some(true),
            };
            ds.record_quic_stream(request, 0, fin, 2.0)?;
            ds.record_quic_stream(request, 4, fin, 3.0)?;
            ds.record_quic_stream(response, 0, fin, 9.0)?;
            ds.record_quic_stream(response, 0, fin, 8.0)?;
            ds.record_quic_stream(
                response,
                8,
                QuicStreamObservation::Reset { final_size: 0 },
                6.0,
            )?;
            assert!(ds.http_requests.is_empty());
            for stream in [0, 4, 8] {
                ds.get_or_insert_http_req(stream);
            }
            ds.hydrate_http_requests();
            assert_eq!(ds.http_requests[&0].time_response_terminal, Some(8.0));
            assert_eq!(ds.http_requests[&4].time_response_terminal, None);
            assert_eq!(ds.http_requests[&8].time_response_terminal, Some(6.0));
        }
        Ok(())
    }

    #[test]
    fn h2_response_end_stream_and_resets_preserve_lifecycle_evidence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut ds = Datastore {
            application_proto: ApplicationProto::Http2,
            ..Datastore::default()
        };
        let send_headers = netlog::Event::H2(h2::Event::Http2SessionSendHeaders(
            h2::Http2SessionSendHeadersEvent {
                params: h2::Http2SessionSendHeadersParams {
                    stream_id: 1,
                    fin: true,
                    ..Default::default()
                },
            },
        ));
        let recv_headers = netlog::Event::H2(h2::Event::Http2SessionRecvHeaders(
            h2::Http2SessionRecvHeadersEvent {
                params: h2::Http2SessionRecvHeadersParams {
                    stream_id: 1,
                    fin: true,
                    ..Default::default()
                },
            },
        ));
        let reset = netlog::Event::H2(h2::Event::Http2SessionRecvRstStream(
            h2::Http2SessionRecvRstStreamEvent {
                params: h2::Http2SessionRecvRstStreamParams {
                    stream_id: 3,
                    error_code: "CANCEL".into(),
                },
            },
        ));
        consume(&constants, &mut ds, 101, &send_headers)?;
        assert_eq!(ds.http_requests[&1].time_response_terminal, None);
        consume(&constants, &mut ds, 103, &recv_headers)?;
        consume(&constants, &mut ds, 107, &reset)?;
        assert!(!ds.http_requests.contains_key(&3));
        consume(&constants, &mut ds, 104, &h2_received(3, 2))?;
        let recv_data_fin = netlog::Event::H2(h2::Event::Http2SessionRecvData(
            h2::Http2SessionRecvDataEvent {
                params: h2::Http2SessionRecvDataParams {
                    stream_id: 5,
                    size: 1,
                    fin: true,
                },
            },
        ));
        consume(&constants, &mut ds, 108, &recv_data_fin)?;
        ds.hydrate_http_requests();
        assert_eq!(ds.http_requests[&1].time_response_terminal, Some(3.0));
        assert_eq!(ds.http_requests[&3].time_response_terminal, Some(7.0));
        assert_eq!(ds.http_requests[&5].time_response_terminal, Some(8.0));
        assert_eq!(ds.last_event_time, 8.0);
        Ok(())
    }

    #[test]
    fn netlog_quic_stream_fin_preserves_final_size_without_inventing_requests(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut datastore = Datastore::default();
        let fin =
            netlog::Event::Quic(quic::Event::QuicSessionStreamFrameReceived(
                quic::QuicSessionStreamFrameEvent {
                    params: quic::QuicSessionStreamFrameParams {
                        stream_id: 7,
                        offset: 10,
                        length: 0,
                        fin: true,
                    },
                },
            ));
        consume(&constants, &mut datastore, 111, &fin)?;
        assert!(datastore.http_requests.is_empty());
        datastore.get_or_insert_http_req(7);
        consume(&constants, &mut datastore, 115, &fin)?;
        datastore.hydrate_http_requests();
        assert_eq!(
            datastore.http_requests[&7].time_response_terminal,
            Some(11.0)
        );
        assert_eq!(
            datastore.received_quic_streams.streams()[&7].points().len(),
            2
        );
        assert_eq!(datastore.received_quic_streams.sum_series(), [
            (11.0, 10),
            (15.0, 10)
        ]);
        Ok(())
    }

    #[test]
    fn netlog_signed_time_handles_events_before_session_and_wide_absolute_timestamps(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        assert_eq!(netlog_relative_time(90, 100), -10.0);
        assert_eq!(netlog_relative_time(110, 100), 10.0);
        assert_eq!(netlog_relative_time(100, 100), 0.0);
        assert_eq!(netlog_relative_time(u64::MAX, u64::MAX - 1), 1.0);
        assert_eq!(netlog_relative_time(u64::MAX - 1, u64::MAX), -1.0);
        assert_eq!(
            netlog_relative_time(0, u64::MAX),
            -18_446_744_073_709_551_616.0
        );
        let mut datastore = Datastore::default();
        assert!(consume(&constants, &mut datastore, 90, &quic_stream(1)).is_ok());
        assert_eq!(
            datastore.received_quic_streams.streams()[&7].points()[0].0,
            -10.0
        );
        assert_eq!(datastore.received_quic_streams.sum_series(), [(-10.0, 1)]);
        Ok(())
    }

    #[test]
    fn netlog_quic_credit_overflow_is_reported_without_mutation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut datastore = Datastore::default();
        datastore.received_quic_streams.observe(
            8,
            crate::trackers::QuicStreamObservation::Reset {
                final_size: u64::MAX,
            },
            0.0,
        )?;
        let event = quic_stream(1);
        assert!(matches!(
            consume(&constants, &mut datastore, 120, &event),
            Err(DatastoreError::Tracker(
                crate::trackers::TrackerError::RunningSumOverflow {
                    stream_id: 7,
                    total: u64::MAX,
                    increment: 1
                }
            ))
        ));
        assert_eq!(datastore.received_quic_streams.sum_series(), [(
            0.0,
            u64::MAX
        )]);
        assert!(!datastore.received_quic_streams.streams().contains_key(&7));
        let invalid =
            netlog::Event::Quic(quic::Event::QuicSessionStreamFrameReceived(
                quic::QuicSessionStreamFrameEvent {
                    params: quic::QuicSessionStreamFrameParams {
                        stream_id: 7,
                        offset: u64::MAX,
                        length: 1,
                        fin: true,
                    },
                },
            ));
        assert!(matches!(
            consume(&constants, &mut datastore, 121, &invalid),
            Err(DatastoreError::Tracker(
                crate::trackers::TrackerError::StreamEndOverflow {
                    stream_id: 7,
                    offset: u64::MAX,
                    length: 1
                }
            ))
        ));
        assert_eq!(datastore.received_quic_streams.sum_series(), [(
            0.0,
            u64::MAX
        )]);
        assert!(!datastore.received_quic_streams.streams().contains_key(&7));
        Ok(())
    }

    #[test]
    fn netlog_h3_and_h2_counter_overflow_is_rejected_before_mutation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        for (event, sent, field) in [
            (h3_received(9, 1), false, "received_data_bytes"),
            (h2_received(9, 1), false, "received_data_bytes"),
            (h2_sent(9, 1), true, "sent_data_bytes"),
        ] {
            let mut ds = Datastore::default();
            let request = ds.get_or_insert_http_req(9);
            let history = if sent {
                &mut request.sent_data
            } else {
                &mut request.received_data
            };
            history.record(0.0, Some(u64::MAX))?;
            let result = consume(&constants, &mut ds, 120, &event);
            assert!(
                matches!(result, Err(DatastoreError::CounterOverflow { field: actual }) if actual == field)
            );
            let request = &ds.http_requests[&9];
            let history = if sent {
                &request.sent_data
            } else {
                &request.received_data
            };
            assert_eq!(history.observations(), [(0.0, Some(u64::MAX))]);
            assert_eq!(history.complete_bytes(), Some(u64::MAX));
            assert!(ds.h2_send_windows.histories().is_empty());
            assert_eq!(ds.h2_received_data_total, 0);
        }

        let mut h2 = Datastore {
            application_proto: ApplicationProto::Http2,
            h2_received_data_total: u64::MAX,
            ..Datastore::default()
        };
        assert!(matches!(
            consume(&constants, &mut h2, 120, &h2_received(11, 1)),
            Err(DatastoreError::CounterOverflow {
                field: "h2_received_data_total"
            })
        ));
        assert!(!h2.http_requests.contains_key(&11));
        assert_eq!(h2.h2_received_data_total, u64::MAX);
        Ok(())
    }

    fn quic_ack_received(missing_packets: Vec<u64>) -> netlog::Event {
        netlog::Event::Quic(quic::Event::QuicSessionAckFrameReceived(
            quic::QuicSessionAckFrameEvent {
                params: quic::QuicSessionAckFrameParams {
                    missing_packets,
                    ..Default::default()
                },
            },
        ))
    }

    fn quic_ack_sent(missing_packets: Vec<u64>) -> netlog::Event {
        netlog::Event::Quic(quic::Event::QuicSessionAckFrameSent(
            quic::QuicSessionAckFrameEvent {
                params: quic::QuicSessionAckFrameParams {
                    missing_packets,
                    ..Default::default()
                },
            },
        ))
    }

    #[test]
    fn netlog_received_ack_without_packet_header_keeps_unknown_space_gaps(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut datastore = Datastore::default();
        consume(
            &constants,
            &mut datastore,
            105,
            &quic_ack_received(vec![3, 4, 4]),
        )?;
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
        consume(&constants, &mut datastore, 106, &header)?;
        consume(&constants, &mut datastore, 107, &quic_ack_received(vec![8]))?;
        assert_eq!(
            datastore.netlog_ack_received_missing_packet[&PacketType::OneRtt],
            BTreeSet::from([8])
        );
        assert_eq!(
            datastore.netlog_ack_received_missing_packet[&PacketType::Unknown],
            BTreeSet::from([3, 4])
        );
        Ok(())
    }

    #[test]
    fn netlog_sent_ack_gaps_reclassify_when_packet_header_follows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut datastore = Datastore::default();
        consume(&constants, &mut datastore, 101, &quic_ack_sent(vec![9, 11]))?;
        consume(
            &constants,
            &mut datastore,
            102,
            &quic_ack_sent(vec![11, 12]),
        )?;
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
            }))?;
        consume(
            &constants,
            &mut datastore,
            103,
            &netlog::Event::Quic(quic::Event::QuicSessionPacketSent(packet)),
        )?;
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
        consume(&constants, &mut datastore, 104, &quic_ack_sent(vec![]))?;
        assert_eq!(datastore.total_tx_ack, 3);
        assert_eq!(datastore.netlog_ack_sent_missing_packet.len(), 1);
        Ok(())
    }

    #[test]
    fn netlog_ack_count_overflow_does_not_change_gap_histories(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
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
                consume(&constants, &mut datastore, 120, &event),
                Err(DatastoreError::CounterOverflow {
                    field: actual
                }) if actual == field
            ));
        }
        assert!(datastore.netlog_ack_received_missing_packet.is_empty());
        assert!(datastore.netlog_ack_sent_missing_packet.is_empty());
        assert_eq!(datastore.netlog_ack_sent_missing_packets_raw, []);
        assert_eq!(datastore.max_ack_sent_missing_packets_size, 0);
        assert_eq!(datastore.max_ack_received_missing_packets_size, 0);
        Ok(())
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
    fn netlog_packet_gaps_are_counted_only_within_each_packet_number_space(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
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
            consume(&constants, &mut datastore, 101, &event)?;
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
            consume(&constants, &mut datastore, 102, &event)?;
            assert_eq!(datastore.discontinuous_packet_number_count, expected);
        }

        // Unclassified headers cannot establish a packet-number space.
        consume(
            &constants,
            &mut datastore,
            103,
            &quic_received_packet_header("UNRECOGNIZED", None, 9000),
        )?;
        consume(&constants, &mut datastore, 104, &initial(15))?;
        assert_eq!(datastore.discontinuous_packet_number_count, 3);
        assert_eq!(datastore.received_packets_netlog.len(), 12);
        assert_eq!(
            datastore
                .received_netlog_packet_numbers
                .previous(PacketType::Initial),
            Some(15)
        );
        Ok(())
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
    fn netlog_discontinuity_overflow_preserves_last_observed_packet_number(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
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
            consume(&constants, &mut datastore, 120, &event),
            Err(DatastoreError::CounterOverflow {
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
        Ok(())
    }

    #[test]
    fn netlog_recv_acks_have_independent_maximum_from_sent_acks(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut datastore = Datastore::default();
        let sent = netlog::Event::Quic(quic::Event::QuicSessionAckFrameSent(
            quic::QuicSessionAckFrameEvent {
                params: quic::QuicSessionAckFrameParams {
                    missing_packets: vec![1, 2, 3, 4, 5, 6, 7],
                    ..Default::default()
                },
            },
        ));
        let received =
            netlog::Event::Quic(quic::Event::QuicSessionAckFrameReceived(
                quic::QuicSessionAckFrameEvent {
                    params: quic::QuicSessionAckFrameParams {
                        missing_packets: vec![3, 4],
                        ..Default::default()
                    },
                },
            ));
        assert!(consume(&constants, &mut datastore, 101, &sent).is_ok());
        assert!(consume(&constants, &mut datastore, 102, &received).is_ok());
        assert_eq!(datastore.total_tx_ack, 1);
        assert_eq!(datastore.total_rx_ack, 1);
        assert_eq!(datastore.max_ack_sent_missing_packets_size, 7);
        assert_eq!(datastore.max_ack_received_missing_packets_size, 2);
        datastore.total_rx_ack = usize::MAX;
        assert!(matches!(
            consume(&constants, &mut datastore, 103, &received),
            Err(DatastoreError::CounterOverflow {
                field: "total_rx_ack"
            })
        ));
        Ok(())
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
    fn netlog_h2_close_preserves_error_label_and_session_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let event = netlog::Event::H2(h2::Event::Http2SessionClose(
            h2::Http2SessionCloseEvent {
                params: h2::Http2SessionCloseParams {
                    net_error: -337,
                    description: "protocol error".to_owned(),
                },
            },
        ));
        let mut datastore = Datastore::default();
        consume(&constants, &mut datastore, 120, &event)?;
        let close = datastore.h2_session_close.as_ref().ok_or("close record")?;
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
        consume(&constants, &mut datastore, 121, &event)?;
        let close = datastore.h2_session_close.as_ref().ok_or("close record")?;
        assert_eq!(close.session_id, 42);
        assert_eq!(close.sni, "server.example.test");
        assert_eq!(close.details, "protocol error");
        Ok(())
    }

    #[test]
    fn netlog_h2_stream_reset_preserves_direction_and_missing_description(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
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
        consume(&constants, &mut datastore, 102, &received)?;
        consume(&constants, &mut datastore, 103, &sent)?;
        assert!(datastore.http_requests.is_empty());

        datastore.get_or_insert_http_req(23);
        consume(&constants, &mut datastore, 104, &sent)?;
        consume(&constants, &mut datastore, 105, &received)?;
        let request = &datastore.http_requests[&23];
        let sent_reset = request
            .h2_stream_reset_sent
            .as_ref()
            .ok_or("sent reset retained")?;
        assert_eq!(sent_reset.error, "CANCEL");
        assert_eq!(sent_reset.description, "peer cancelled");
        let received_reset = request
            .h2_stream_reset_receive
            .as_ref()
            .ok_or("received reset retained")?;
        assert_eq!(received_reset.error, "REFUSED_STREAM");
        assert_eq!(received_reset.description, "");

        // Sending a later reset must not erase the received direction.
        consume(&constants, &mut datastore, 106, &sent)?;
        assert_eq!(
            datastore.http_requests[&23]
                .h2_stream_reset_receive
                .as_ref()
                .ok_or("received direction preserved")?
                .error,
            "REFUSED_STREAM"
        );
        Ok(())
    }

    #[test]
    fn h2_received_data_opens_only_observed_local_send_sides(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut data = Datastore::default();
        for (time, event) in [
            (103, h2_window_received(1, 50)),
            (101, h2_received(1, 10)),
            (102, h2_received(2, 20)),
            (104, h2_window_received(2, 100)),
            (105, h2_window_sent(2, 200)),
        ] {
            consume(&constants, &mut data, time, &event)?;
        }
        let histories = data.h2_send_windows.histories();
        assert_eq!(histories.len(), 1);
        assert_eq!(histories[&1].changes, [(3.0, 50)]);
        assert_eq!(histories[&1].opened_at.to_bits(), 1.0_f64.to_bits());
        assert_eq!(data.h2_recv_window_updates[&2], [(5.0, 200)]);
        Ok(())
    }

    #[test]
    fn netlog_h2_window_update_keeps_independent_stream_and_direction_series(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
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
            consume(&constants, &mut datastore, time, &event)?;
        }
        assert_eq!(datastore.h2_send_windows.histories()[&1].changes, vec![(
            1.0, 50
        )]);
        assert_eq!(datastore.h2_send_windows.histories()[&3].changes, vec![(
            3.0, 8
        )]);
        assert_eq!(datastore.h2_recv_window_updates[&1], vec![(2.0, 7)]);
        assert_eq!(datastore.h2_recv_window_updates[&3], vec![(4.0, 11)]);
        assert_eq!(datastore.h2_send_windows.histories().len(), 2);
        assert_eq!(datastore.h2_recv_window_updates.len(), 2);
        Ok(())
    }

    #[test]
    fn http2_window_updates_separate_peer_send_credit_and_our_receive_credit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut datastore = Datastore::default();
        assert!(consume(
            &constants,
            &mut datastore,
            110,
            &h2_window_received(3, 10)
        )
        .is_ok());
        assert!(
            consume(&constants, &mut datastore, 120, &h2_window_sent(3, 20))
                .is_ok()
        );
        assert!(
            consume(&constants, &mut datastore, 130, &h2_window_sent(3, -1))
                .is_ok()
        );
        assert!(consume(
            &constants,
            &mut datastore,
            140,
            &h2_window_received(3, 0)
        )
        .is_ok());
        assert_eq!(datastore.h2_send_windows.histories()[&3].changes, vec![(
            10.0, 10
        )]);
        assert_eq!(datastore.h2_recv_window_updates[&3], vec![(20.0, 20)]);
        assert_eq!(datastore.h2_send_windows.histories()[&3].changes.len(), 1);
        Ok(())
    }

    #[test]
    fn h2_initial_window_settings_affect_only_open_send_sides(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut datastore = Datastore {
            application_proto: ApplicationProto::Http2,
            ..Datastore::default()
        };
        let setting = |value| {
            netlog::Event::H2(h2::Event::Http2SessionRecvSetting(
                h2::Http2SessionRecvSettingEvent {
                    params: h2::Http2SessionRecvSettingParams {
                        id: "4 (SETTINGS_INITIAL_WINDOW_SIZE)".to_owned(),
                        value,
                    },
                },
            ))
        };
        let headers = |stream_id, fin| {
            netlog::Event::H2(h2::Event::Http2SessionSendHeaders(
                h2::Http2SessionSendHeadersEvent {
                    params: h2::Http2SessionSendHeadersParams {
                        stream_id,
                        fin,
                        ..Default::default()
                    },
                },
            ))
        };
        let send_fin = netlog::Event::H2(h2::Event::Http2SessionSendData(
            h2::Http2SessionSendDataEvent {
                params: h2::Http2SessionSendDataParams {
                    stream_id: 1,
                    size: 2,
                    fin: true,
                },
            },
        ));
        for (time, event) in [
            (101, setting(100)),
            (102, headers(1, false)),
            (103, h2_sent(1, 80)),
            (104, setting(50)),
            (105, headers(3, false)),
            (106, h2_window_received(1, 50)),
            (107, send_fin),
            (108, setting(120)),
            (109, headers(5, true)),
            (110, setting(0)),
            (111, setting(u32::MAX)),
            (112, h2_window_received(1, 100)),
            (113, h2_window_received(3, 20)),
        ] {
            consume(&constants, &mut datastore, time, &event)?;
        }
        let histories = datastore.h2_send_windows.histories();
        assert_eq!(histories[&1].initial, 100);
        assert_eq!(histories[&1].changes, [
            (3.0, -80),
            (4.0, -50),
            (6.0, 50),
            (7.0, -2)
        ]);
        assert_eq!(histories[&3].initial, 50);
        assert_eq!(histories[&3].changes, [(8.0, 70), (10.0, -120), (13.0, 20)]);
        assert_eq!(histories[&5].initial, 120);
        assert_eq!(histories[&5].changes.as_slice(), []);
        assert_eq!(histories[&0].initial, 65535);
        assert_eq!(histories[&0].changes, [(3.0, -80), (7.0, -2)]);
        assert_eq!(datastore.h2_server_settings.initial_window_size, Some(0));
        let series = crate::seriesstore::SeriesStore::from_datastore(&datastore)?;
        assert_eq!(series.h2_send_window_series_balanced[&1], [
            (2.0, 100),
            (3.0, 100),
            (3.0, 20),
            (4.0, 20),
            (4.0, -30),
            (6.0, -30),
            (6.0, 20),
            (7.0, 20),
            (7.0, 18),
        ]);
        assert_eq!(
            series.h2_send_window_series_balanced[&3].last(),
            Some(&(13.0, 20))
        );
        Ok(())
    }

    #[test]
    fn h2_connection_data_reconstructs_chronological_totals_across_streams(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut data = Datastore {
            application_proto: ApplicationProto::Http2,
            ..Datastore::default()
        };
        for (time, stream, length) in
            [(108, 1, 30), (103, 3, 5), (99, 1, 10), (106, 3, 7)]
        {
            consume(&constants, &mut data, time, &h2_received(stream, length))?;
        }
        assert_eq!(data.h2_received_data_total, 52);
        let series = crate::seriesstore::SeriesStore::from_datastore(&data)?;
        assert_eq!(series.netlog_h2_stream_received_connection_cumulative, [
            (-1.0, 0),
            (-1.0, 0),
            (-1.0, 10),
            (3.0, 10),
            (3.0, 15),
            (6.0, 15),
            (6.0, 22),
            (8.0, 22),
            (8.0, 52),
        ]);
        assert_eq!(series.h2_connection_receive_credit, [
            (-1.0, 65535),
            (8.0, 65535)
        ]);
        Ok(())
    }

    #[test]
    fn h2_connection_credit_uses_locally_sent_grants_and_all_outbound_data(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let constants = constants()?;
        let mut datastore = Datastore {
            application_proto: ApplicationProto::Http2,
            ..Datastore::default()
        };
        for (time, event) in [
            (101, h2_sent(1, 7)),
            (102, h2_window_received(0, 100)),
            (103, h2_sent(3, 11)),
            (104, h2_received(1, 13)),
            (105, h2_window_sent(3, 90)),
            (106, h2_window_sent(0, 20)),
            (107, h2_received(3, 17)),
        ] {
            consume(&constants, &mut datastore, time, &event)?;
        }
        assert_eq!(datastore.h2_send_windows.histories()[&0].changes, [
            (1.0, -7),
            (2.0, 100),
            (3.0, -11)
        ]);
        let series = crate::seriesstore::SeriesStore::from_datastore(&datastore)?;
        assert_eq!(series.h2_connection_receive_credit, [
            (0.0, 65535),
            (6.0, 65535),
            (6.0, 65555),
            (7.0, 65555)
        ]);
        assert_eq!(
            series
                .netlog_h2_stream_received_connection_cumulative
                .last(),
            Some(&(7.0, 30))
        );
        assert_eq!(
            series.h2_send_window_series_balanced[&0].last(),
            Some(&(3.0, 65617))
        );
        Ok(())
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
                    "stream_id": 8, "length": 1, "offset": 0, "fin": false
                }),
            ),
        ];
        write!(source, ",\n\"events\": [\n{}\n]\n}}", records.join(",\n"))?;
        let mut reader = Cursor::new(source.as_bytes());
        let parsed_constants = netlog::read_netlog_constants(&mut reader)?;
        let result =
            with_netlog_reader(&mut reader, &HashSet::new(), &parsed_constants);
        assert!(matches!(
            result,
            Err(DatastoreError::Tracker(
                crate::trackers::TrackerError::RunningSumOverflow {
                    stream_id: 8,
                    total: u64::MAX,
                    increment: 1
                }
            ))
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
    fn h3_frames_preserve_direction_and_complete_request_response_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
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

            let ds = Datastore::with_qlog_events(&events, &vantage, false)?;
            let req = ds.http_requests.get(&8).ok_or("request stream missing")?;
            assert_eq!(req.method.inner.as_deref(), Some("POST"));
            assert_eq!(req.host.inner.as_deref(), Some("example.test"));
            assert_eq!(req.path.inner.as_deref(), Some("/upload"));
            assert_eq!(req.client_pri_hdr.inner.as_deref(), Some("u=3"));
            assert_eq!(req.client_content_length.inner.as_deref(), Some("11"));
            assert_eq!(req.status.inner.as_deref(), Some("201"));
            assert_eq!(req.server_content_length.inner.as_deref(), Some("17"));

            assert_eq!(req.sent_data.first_time(), Some(3.0));
            assert_eq!(req.sent_data.last_time(), Some(3.0));
            assert_eq!(req.sent_data.observations(), [(3.0, Some(11))]);
            assert_eq!(req.received_data.first_time(), Some(4.0));
            assert_eq!(req.received_data.last_time(), Some(4.0));
            assert_eq!(req.received_data.observations(), [(4.0, Some(17))]);

            let priority_req =
                ds.http_requests.get(&12).ok_or("priority target missing")?;
            assert_eq!(priority_req.priority_updates, vec!["u=2"]);

            let (client_bytes, server_bytes) =
                if request_created { (11, 17) } else { (17, 11) };
            assert_eq!(req.client_data().complete_bytes(), Some(client_bytes));
            assert_eq!(req.server_data().complete_bytes(), Some(server_bytes));
        }
        Ok(())
    }
    #[test]
    fn data_accounting_preserves_known_zero_and_raw_payload_lengths(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use qlog::events::RawInfo;

        let mut events = vec![
            event(5.0, true, data(), Some(4)),
            event(2.0, true, data(), Some(0)),
            event(7.0, true, data(), None),
            event(
                8.0,
                false,
                Http3Frame::Data {
                    raw: Some(RawInfo {
                        payload_length: Some(12),
                        ..RawInfo::default()
                    }),
                },
                None,
            ),
        ];
        events.push(Event::with_time(
            9.0,
            EventData::Http3FrameParsed(FrameParsed {
                stream_id: 8,
                length: None,
                frame: data(),
                raw: Some(RawInfo {
                    payload_length: Some(3),
                    ..RawInfo::default()
                }),
            }),
        ));
        let sequential = events
            .iter()
            .cloned()
            .map(qlog::reader::Event::Qlog)
            .collect::<Vec<_>>();
        for ds in [
            Datastore::with_qlog_events(
                &events,
                &VantagePointType::Client,
                false,
            )?,
            Datastore::with_sqlog_reader_events(
                &sequential,
                &VantagePointType::Client,
                false,
            )?,
        ] {
            let request = ds.http_requests.get(&8).ok_or("missing request")?;
            assert_eq!(request.sent_data.first_time(), Some(2.0));
            assert_eq!(request.sent_data.last_time(), Some(7.0));
            assert_eq!(request.client_data().known_bytes(), 4);
            assert!(request.client_data().complete_bytes().is_none());
            assert!(request.upload_measurement().rate.inner.is_none());
            assert_eq!(request.server_data().complete_bytes(), Some(15));
            assert_eq!(request.sent_data.observations(), [
                (5.0, Some(4)),
                (2.0, Some(0)),
                (7.0, None)
            ]);
            assert_eq!(request.received_data.observations(), [
                (8.0, Some(12)),
                (9.0, Some(3))
            ]);
        }
        Ok(())
    }

    #[test]
    fn data_counter_overflow_is_atomic_for_both_qlog_directions(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for sent in [true, false] {
            let mut ds = Datastore::default();
            ds.consume_qlog_event(
                &event(1.0, sent, data(), Some(u64::MAX)),
                false,
            )?;
            let result =
                ds.consume_qlog_event(&event(2.0, sent, data(), Some(1)), false);
            let field = if sent {
                "sent_data_bytes"
            } else {
                "received_data_bytes"
            };
            assert!(
                matches!(result, Err(super::DatastoreError::CounterOverflow { field: actual }) if actual == field)
            );
            let request = ds.http_requests.get(&8).ok_or("missing request")?;
            let history = if sent {
                &request.sent_data
            } else {
                &request.received_data
            };
            assert_eq!(history.observations(), [(1.0, Some(u64::MAX))]);
            assert_eq!(history.last_time(), Some(1.0));
            assert_eq!(history.complete_bytes(), Some(u64::MAX));
            assert_eq!(ds.last_event_time, 1.0);
        }
        Ok(())
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

    fn receive_credit_events() -> Vec<Event> {
        use qlog::events::ApplicationError;
        let frame = |stream_id, offset, length: Option<u64>| QuicFrame::Stream {
            stream_id,
            offset,
            fin: None,
            raw: length.map(|payload_length| {
                Box::new(RawInfo {
                    payload_length: Some(payload_length),
                    ..RawInfo::default()
                })
            }),
        };
        let grant = |time, maximum| {
            Event::with_time(
                time,
                EventData::QuicPacketSent(PacketSent {
                    header: header(WirePacketType::OneRtt, None),
                    frames: Some(vec![QuicFrame::MaxData { maximum, raw: None }]),
                    ..PacketSent::default()
                }),
            )
        };
        vec![
            grant(1.0, 500),
            received(2.0, WirePacketType::OneRtt, None, vec![frame(
                7,
                Some(100),
                Some(50),
            )]),
            received(3.0, WirePacketType::OneRtt, None, vec![frame(
                11,
                Some(0),
                Some(20),
            )]),
            received(4.0, WirePacketType::OneRtt, None, vec![frame(
                7,
                Some(90),
                Some(30),
            )]),
            received(5.0, WirePacketType::OneRtt, None, vec![frame(
                7,
                Some(140),
                Some(20),
            )]),
            received(6.0, WirePacketType::OneRtt, None, vec![
                QuicFrame::ResetStream {
                    stream_id: 11,
                    final_size: 100,
                    error: ApplicationError::Unknown,
                    error_code: Some(42),
                    raw: None,
                },
            ]),
            received(7.0, WirePacketType::OneRtt, None, vec![frame(
                11,
                Some(100),
                None,
            )]),
            grant(8.0, 600),
            grant(9.0, 500),
            received(10.0, WirePacketType::OneRtt, None, vec![
                QuicFrame::DataBlocked {
                    limit: 600,
                    raw: None,
                },
            ]),
        ]
    }

    #[test]
    fn qlog_receive_credit_uses_frame_end_and_reset_final_size(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let events = receive_credit_events();
        let sequential = events
            .iter()
            .cloned()
            .map(qlog::reader::Event::Qlog)
            .collect::<Vec<_>>();
        for data in [
            Datastore::with_qlog_events(
                &events,
                &qlog::VantagePointType::Server,
                false,
            )?,
            Datastore::with_sqlog_reader_events(
                &sequential,
                &qlog::VantagePointType::Server,
                false,
            )?,
        ] {
            assert_eq!(data.received_quic_streams.sum_series(), [
                (2.0, 150),
                (3.0, 170),
                (4.0, 170),
                (5.0, 180),
                (6.0, 260),
                (7.0, 260)
            ]);
            let series = crate::seriesstore::SeriesStore::from_datastore(&data)?;
            assert_eq!(
                series.quic_receive_credit_consumed.last(),
                Some(&(7.0, 260))
            );
            assert_eq!(series.sent_max_data.last(), Some(&(9.0, 600)));
            assert_eq!(series.received_stream_frames_series[&11], [(3.0, 20)]);
            assert_eq!(data.quic_peer_window_blocked[&-1], [10.0]);
        }
        Ok(())
    }

    #[test]
    fn qlog_sent_stream_credit_preserves_partial_frames_and_send_time(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Reverse the directions of the same stream/credit fixture. For
        // outbound stream frames, use the actual send timestamp when present.
        let events = receive_credit_events()
            .into_iter()
            .map(|mut event| {
                event.data = match event.data {
                    EventData::QuicPacketReceived(packet) =>
                        EventData::QuicPacketSent(PacketSent {
                            header: packet.header,
                            frames: packet.frames,
                            send_at_time: Some(event.time + 10.0),
                            ..Default::default()
                        }),
                    EventData::QuicPacketSent(packet) =>
                        EventData::QuicPacketReceived(PacketReceived {
                            header: packet.header,
                            frames: packet.frames,
                            ..Default::default()
                        }),
                    other => other,
                };
                event
            })
            .collect::<Vec<_>>();
        let data = Datastore::with_qlog_events(
            &events,
            &qlog::VantagePointType::Client,
            false,
        )?;
        let series = crate::seriesstore::SeriesStore::from_datastore(&data)?;
        assert_eq!(data.sent_quic_streams.current_sum(), 260);
        assert_eq!(data.received_quic_streams.current_sum(), 0);
        assert_eq!(series.sent_stream_frames_series[&11], [(13.0, 20)]);
        assert_eq!(series.quic_send_credit_consumed.last(), Some(&(17.0, 260)));
        assert_eq!(series.received_max_data.last(), Some(&(9.0, 600)));
        assert_eq!(series.y_max_stream_send_plot, 600);
        Ok(())
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
                    data.sent_stream_max_data_tracker.streams()[&stream_id]
                        .initial(),
                    Some(local)
                );
                assert_eq!(
                    data.received_stream_max_data_tracker.streams()[&stream_id]
                        .initial(),
                    Some(peer)
                );
                assert_eq!(
                    data.sent_stream_max_data_tracker.streams()[&stream_id]
                        .points(),
                    [(3.0, 100)]
                );
                assert_eq!(
                    data.received_stream_max_data_tracker.streams()[&stream_id]
                        .points(),
                    [(2.0, 100)]
                );
            }
        }
        Ok(())
    }
}
