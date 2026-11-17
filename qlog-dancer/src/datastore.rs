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

use crate::request_stub::find_header_value;
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

#[derive(Default, Debug)]
pub struct PrintStatsConfig {
    pub rx_flow_control: bool,
    pub tx_flow_control: bool,
    pub reset_streams: bool,
    pub stream_buffering: bool,
    pub tx_stream_frames: bool,
    pub packet_stats: bool,
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

    pub local_init_max_stream_data_bidi_local: u64,
    pub local_init_max_stream_data_uni: u64,
    pub peer_init_max_stream_data_bidi_local: u64,
    pub peer_init_max_stream_data_bidi_remote: u64,
    pub peer_init_max_stream_data_uni: u64,

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

const fn is_bidi(stream_id: u64) -> bool {
    (stream_id & 0x2) == 0
}

impl Datastore {
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

    fn consume_netlog_quic(
        &mut self, session_start_time: u64, ev_hdr: &netlog::EventHeader,
        ev: &quic::Event, constants: &netlog::constants::Constants,
    ) -> Result<(), DatastoreError> {
        let rel_event_time =
            netlog_relative_time(ev_hdr.time_num, session_start_time);

        match ev {
            QuicSessionStreamFrameReceived(e) => {
                // Validate all counters before mutating any of this event's
                // state.
                let next_count = checked_netlog_sum(
                    self.total_received_stream_frame_count,
                    1,
                    "total_received_stream_frame_count",
                )?;
                let cumulative = cumulative_total(
                    &self.netlog_quic_stream_received_connection_cumulative,
                    e.params.length,
                    "netlog_quic_stream_received_connection_cumulative",
                )?;

                let s = self
                    .received_stream_frames
                    .entry(e.params.stream_id)
                    .or_default();
                s.push((rel_event_time, StreamDatapoint {
                    offset: e.params.offset,
                    length: e.params.length,
                }));

                let s = self
                    .received_stream_frames_count_based
                    .entry(e.params.stream_id)
                    .or_default();
                s.push((
                    self.total_received_stream_frame_count,
                    StreamDatapoint {
                        offset: e.params.offset,
                        length: e.params.length,
                    },
                ));

                self.total_received_stream_frame_count = next_count;

                if e.params.fin {
                    if let Some(req) =
                        self.http_requests.get_mut(&e.params.stream_id)
                    {
                        req.time_fin_rx = Some(rel_event_time);
                    }
                }

                self.netlog_quic_stream_received_connection_cumulative
                    .push((rel_event_time, cumulative));
            },

            QuicSessionUnauthenticatedPacketHeaderReceived(e) => {
                if let Some((_, last)) = self.received_packets_netlog.last() {
                    let gap = if e.params.packet_number > last.number {
                        e.params.packet_number - last.number
                    } else {
                        last.number.saturating_sub(e.params.packet_number)
                    };

                    if gap > 1 {
                        self.discontinuous_packet_number_count =
                            checked_netlog_sum(
                                self.discontinuous_packet_number_count,
                                1,
                                "discontinuous_packet_number_count",
                            )?;
                    }
                }

                let packet_type = PacketType::from_netlog_packet_header(
                    &e.params.header_format,
                    &e.params.long_header_type,
                );

                let packet_info = PacketInfoStub {
                    acked: None,
                    raw: None,
                    created_time: rel_event_time,
                    send_at_time: None,
                    ty: packet_type,
                    number: e.params.packet_number,
                };

                self.received_packets_netlog
                    .push((rel_event_time, packet_info.clone()));

                let s = self.packet_received.entry(packet_type).or_default();

                s.insert(e.params.packet_number, packet_info);
            },

            QuicSessionPacketSent(e) => {
                let packet_type = PacketType::from_netlog_encryption_level(
                    &e.params.encryption_level,
                );

                let packet_info = PacketInfoStub {
                    acked: None,
                    raw: None,
                    created_time: rel_event_time,
                    send_at_time: None,
                    ty: packet_type,
                    number: e.params.packet_number,
                };

                let s = self.packet_sent.entry(packet_type).or_default();

                s.insert(e.params.packet_number, packet_info);

                // Go back and update the Ack frame type if there was one
                if let Some(pkts) = self
                    .netlog_ack_sent_missing_packet
                    .get_mut(&PacketType::Unknown)
                {
                    if !pkts.is_empty() {
                        let old = std::mem::take(pkts);

                        let s = self
                            .netlog_ack_sent_missing_packet
                            .entry(packet_type)
                            .or_default();

                        for num in old {
                            s.insert(num);
                        }
                    }
                }
            },

            QuicSessionAckFrameSent(e) => {
                self.total_tx_ack =
                    checked_netlog_count(self.total_tx_ack, "total_tx_ack")?;
                self.max_ack_sent_missing_packets_size = std::cmp::max(
                    e.params.missing_packets.len(),
                    self.max_ack_sent_missing_packets_size,
                );

                if !e.params.missing_packets.is_empty() {
                    self.netlog_ack_sent_missing_packets_raw
                        .push((rel_event_time, e.params.missing_packets.clone()));
                }

                let s = self
                    .netlog_ack_sent_missing_packet
                    .entry(PacketType::Unknown)
                    .or_default();

                for pn in &e.params.missing_packets {
                    // At this stage, we don't know the packet type we sent the
                    // ACK in, because it comes later in the netlog. Insert with
                    // a placeholder now, and we'll update later in
                    // QuicSessionPacketSent handler. Ugly but functional.
                    s.insert(*pn);
                }
            },

            QuicSessionAckFrameReceived(e) => {
                self.total_rx_ack =
                    checked_netlog_count(self.total_rx_ack, "total_rx_ack")?;
                self.max_ack_received_missing_packets_size = std::cmp::max(
                    e.params.missing_packets.len(),
                    self.max_ack_received_missing_packets_size,
                );

                if !e.params.missing_packets.is_empty() {
                    // For netlogs, it is assumed that the last packet received
                    // relates to this event.
                    let parent_packet = self.received_packets_netlog.last();
                    if let Some((_, pkt_info)) = parent_packet {
                        let s = self
                            .netlog_ack_received_missing_packet
                            .entry(pkt_info.ty)
                            .or_default();

                        for missing in &e.params.missing_packets {
                            s.insert(*missing);
                        }
                    }
                }
            },

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

            QuicSessionRstStreamFrameReceived(e) => {
                // Non-request streams can be reset, we don't care about them
                // right now
                if let Some(req) = self.http_requests.get_mut(&e.params.stream_id)
                {
                    req.quic_stream_reset_received = Some(QuicStreamReset {
                        offset: e.params.offset,
                        quic_rst_stream_error: e.params.quic_rst_stream_error,
                        quic_rst_stream_error_friendly: i64::try_from(
                            e.params.quic_rst_stream_error,
                        )
                        .ok()
                        .and_then(|code| {
                            constants.quic_rst_stream_error_id_keyed.get(&code)
                        })
                        .cloned(),
                    });
                }
            },

            QuicSessionRstStreamFrameSent(e) => {
                // Non-request streams can be reset, we don't care about them
                // right now
                if let Some(req) = self.http_requests.get_mut(&e.params.stream_id)
                {
                    req.quic_stream_reset_sent = Some(QuicStreamReset {
                        offset: e.params.offset,
                        quic_rst_stream_error: e.params.quic_rst_stream_error,
                        quic_rst_stream_error_friendly: i64::try_from(
                            e.params.quic_rst_stream_error,
                        )
                        .ok()
                        .and_then(|code| {
                            constants.quic_rst_stream_error_id_keyed.get(&code)
                        })
                        .cloned(),
                    });
                }
            },

            QuicSessionStopSendingFrameSent(e) => {
                // Non-request streams can be stopped, we don't care about them
                // right now
                if let Some(req) = self.http_requests.get_mut(&e.params.stream_id)
                {
                    req.quic_stream_stop_sending_sent =
                        Some(QuicStreamStopSending {
                            quic_rst_stream_error: e.params.quic_rst_stream_error,
                            quic_rst_stream_error_friendly: i64::try_from(
                                e.params.quic_rst_stream_error,
                            )
                            .ok()
                            .and_then(|code| {
                                constants
                                    .quic_rst_stream_error_id_keyed
                                    .get(&code)
                            })
                            .cloned(),
                        });
                }
            },

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

            Http3DataFrameReceived(e) => {
                let length = e.params.payload_length;
                let next_count = checked_netlog_sum(
                    self.total_received_data_frame_count,
                    1,
                    "total_received_data_frame_count",
                )?;
                let next_cumulative = cumulative_total(
                    self.received_data_cumulative
                        .get(&e.params.stream_id)
                        .map_or(&[], Vec::as_slice),
                    length,
                    "received_data_cumulative",
                )?;

                let req = self.get_or_insert_http_req(e.params.stream_id);

                req.time_first_data_rx.get_or_insert(rel_event_time);

                let _ = req.time_last_data_rx.insert(rel_event_time);

                req.time_data_rx_set.push((rel_event_time, length));
                self.largest_data_frame_rx_length_global = std::cmp::max(
                    self.largest_data_frame_rx_length_global,
                    length,
                );

                let s = self
                    .received_data_frames
                    .entry(e.params.stream_id)
                    .or_default();

                s.push((rel_event_time, e.params.payload_length));

                let s = self
                    .received_data_frames_count_based
                    .entry(e.params.stream_id)
                    .or_default();
                s.push((
                    self.total_received_data_frame_count,
                    e.params.payload_length,
                ));

                self.total_received_data_frame_count = next_count;

                let s = self
                    .received_data_cumulative
                    .entry(e.params.stream_id)
                    .or_default();

                let received_data_cumulative = next_cumulative;

                s.push((rel_event_time, received_data_cumulative));

                let s = self
                    .received_data_cumulative_max
                    .entry(e.params.stream_id)
                    .or_default();

                *s = std::cmp::max(*s, received_data_cumulative);

                let s = self.http_requests.entry(e.params.stream_id).or_default();

                s.server_transferred_bytes = std::cmp::max(
                    s.server_transferred_bytes,
                    NaOption::new(Some(received_data_cumulative)),
                )
            },

            // TODO: add support for logging HTTP/2 sending
            Http3DataSent(_) => (),
        }
        Ok(())
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

            Http2SessionRecvData(e) => {
                let length = u64::from(e.params.size);
                let next_count = checked_netlog_sum(
                    self.total_received_data_frame_count,
                    1,
                    "total_received_data_frame_count",
                )?;
                let next_stream_cumulative = cumulative_total(
                    self.received_data_cumulative
                        .get(&u64::from(e.params.stream_id))
                        .map_or(&[], Vec::as_slice),
                    length,
                    "received_data_cumulative",
                )?;
                let next_connection_cumulative = cumulative_total(
                    &self.netlog_h2_stream_received_connection_cumulative,
                    length,
                    "netlog_h2_stream_received_connection_cumulative",
                )?;

                let req =
                    self.get_or_insert_http_req(u64::from(e.params.stream_id));

                req.time_first_data_rx.get_or_insert(rel_event_time);

                let _ = req.time_last_data_rx.insert(rel_event_time);

                req.time_data_rx_set.push((rel_event_time, length));
                self.largest_data_frame_rx_length_global = std::cmp::max(
                    self.largest_data_frame_rx_length_global,
                    length,
                );

                let s = self
                    .received_data_frames
                    .entry(u64::from(e.params.stream_id))
                    .or_default();

                s.push((rel_event_time, u64::from(e.params.size)));

                let s = self
                    .received_data_frames_count_based
                    .entry(u64::from(e.params.stream_id))
                    .or_default();
                s.push((
                    self.total_received_data_frame_count,
                    u64::from(e.params.size),
                ));

                self.total_received_data_frame_count = next_count;

                let s = self
                    .received_data_cumulative
                    .entry(u64::from(e.params.stream_id))
                    .or_default();

                let received_data_cumulative = next_stream_cumulative;

                s.push((rel_event_time, received_data_cumulative));

                let s = self
                    .received_data_cumulative_max
                    .entry(u64::from(e.params.stream_id))
                    .or_default();

                *s = std::cmp::max(*s, received_data_cumulative);

                let s = self
                    .http_requests
                    .entry(u64::from(e.params.stream_id))
                    .or_default();

                s.server_transferred_bytes = std::cmp::max(
                    s.server_transferred_bytes,
                    NaOption::new(Some(received_data_cumulative)),
                );

                let cumulative = next_connection_cumulative;

                self.netlog_h2_stream_received_connection_cumulative
                    .push((rel_event_time, cumulative));
            },

            Http2SessionSendData(e) => {
                let length = u64::from(e.params.size);
                let next_count = checked_netlog_sum(
                    self.total_sent_data_frame_count,
                    1,
                    "total_sent_data_frame_count",
                )?;
                let next_cumulative = cumulative_total(
                    self.sent_data_cumulative
                        .get(&u64::from(e.params.stream_id))
                        .map_or(&[], Vec::as_slice),
                    length,
                    "sent_data_cumulative",
                )?;

                let req =
                    self.get_or_insert_http_req(u64::from(e.params.stream_id));

                req.time_first_data_tx.get_or_insert(rel_event_time);

                let _ = req.time_last_data_tx.insert(rel_event_time);

                req.time_data_tx_set.push((rel_event_time, length));
                self.largest_data_frame_tx_length_global = std::cmp::max(
                    self.largest_data_frame_tx_length_global,
                    length,
                );

                let s = self
                    .sent_data_frames
                    .entry(u64::from(e.params.stream_id))
                    .or_default();

                s.push((rel_event_time, u64::from(e.params.size)));

                let s = self
                    .sent_data_frames_count_based
                    .entry(u64::from(e.params.stream_id))
                    .or_default();
                s.push((
                    self.total_sent_data_frame_count,
                    u64::from(e.params.size),
                ));

                self.total_sent_data_frame_count = next_count;

                // counterintuitively, reduces our local send window
                let s = self
                    .h2_send_window_updates_balanced
                    .entry(e.params.stream_id)
                    .or_default();
                s.push((rel_event_time, -i64::from(e.params.size)));

                let s = self
                    .sent_data_cumulative
                    .entry(u64::from(e.params.stream_id))
                    .or_default();

                let sent_data_cumulative = next_cumulative;

                s.push((rel_event_time, sent_data_cumulative));

                let s = self
                    .sent_data_cumulative_max
                    .entry(u64::from(e.params.stream_id))
                    .or_default();

                *s = std::cmp::max(*s, sent_data_cumulative);

                let s = self
                    .http_requests
                    .entry(u64::from(e.params.stream_id))
                    .or_default();

                s.client_transferred_bytes = std::cmp::max(
                    s.client_transferred_bytes,
                    NaOption::new(Some(sent_data_cumulative)),
                );
            },

            // A WINDOW_UPDATE from the peer grants us additional send credit.
            Http2SessionRecvWindowUpdate(e) => {
                if let Some(delta) = u64::try_from(e.params.delta)
                    .ok()
                    .filter(|increment| *increment > 0)
                {
                    self.h2_send_window_updates_balanced
                        .entry(e.params.stream_id)
                        .or_default()
                        .push((rel_event_time, i64::from(e.params.delta)));
                    self.h2_send_window_updates_absolute
                        .entry(e.params.stream_id)
                        .or_default()
                        .push((rel_event_time, delta));
                } else {
                    error!(
                        "ignoring nonpositive HTTP/2 received WINDOW_UPDATE increment: {}",
                        e.params.delta,
                    );
                }
            },

            // A WINDOW_UPDATE sent to the peer grants *their* send credit,
            // not ours. Keep local receive-window updates in their own series.
            Http2SessionSendWindowUpdate(e) =>
                if e.params.delta > 0 {
                    self.h2_recv_window_updates
                        .entry(e.params.stream_id)
                        .or_default()
                        .push((rel_event_time, e.params.delta));
                } else {
                    error!(
                        "ignoring nonpositive HTTP/2 sent WINDOW_UPDATE increment: {}",
                        e.params.delta,
                    );
                },

            Http2SessionClose(e) => {
                self.h2_session_close = Some(H2SessionClose {
                    session_id: self.session_id.unwrap_or(-1),
                    sni: self
                        .host
                        .clone()
                        .unwrap_or_else(|| "ERROR UNKNOWN".to_owned()),
                    details: e.params.description.clone(),
                    net_err: e.params.net_error,
                    net_err_pretty: NaOption::new(
                        constants
                            .net_error_id_keyed
                            .get(&e.params.net_error)
                            .cloned(),
                    ),
                });
            },

            Http2SessionSendRstStream(e) => {
                if let Some(req) =
                    self.http_requests.get_mut(&(u64::from(e.params.stream_id)))
                {
                    req.h2_stream_reset_sent = Some(H2StreamReset {
                        error: e.params.error_code.clone(),
                        description: e.params.description.clone(),
                    });
                }
            },

            Http2SessionRecvRstStream(e) => {
                if let Some(req) =
                    self.http_requests.get_mut(&(u64::from(e.params.stream_id)))
                {
                    req.h2_stream_reset_receive = Some(H2StreamReset {
                        error: e.params.error_code.clone(),
                        description: "".to_string(),
                    });
                }
            },

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

            EventData::Http3FrameCreated(v) => match self.vantage_point {
                VantagePoint::Client =>
                    self.consume_qlog_h3_frame_created_client(v, ev_time),
                VantagePoint::Server =>
                    self.consume_qlog_h3_frame_created_server(v, ev_time),
            },

            EventData::Http3FrameParsed(v) => match self.vantage_point {
                VantagePoint::Client =>
                    self.consume_qlog_h3_frame_parsed_client(v, ev_time),
                VantagePoint::Server =>
                    self.consume_qlog_h3_frame_parsed_server(v, ev_time),
            },

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
        match tp.initiator {
            Some(TransportInitiator::Local) => {
                if let Some(max_data) = tp.initial_max_data {
                    self.sent_max_data.push((0.0, max_data));
                }

                if let Some(max_stream_data) =
                    tp.initial_max_stream_data_bidi_local
                {
                    self.local_init_max_stream_data_bidi_local = max_stream_data;
                }

                if let Some(max_stream_data) = tp.initial_max_stream_data_uni {
                    self.local_init_max_stream_data_uni = max_stream_data;
                }
            },

            Some(TransportInitiator::Remote) => {
                if let Some(max_data) = tp.initial_max_data {
                    self.received_max_data.push((0.0, max_data));
                }

                if let Some(max_stream_data) =
                    tp.initial_max_stream_data_bidi_local
                {
                    self.peer_init_max_stream_data_bidi_local = max_stream_data;
                }

                if let Some(max_stream_data) =
                    tp.initial_max_stream_data_bidi_remote
                {
                    self.peer_init_max_stream_data_bidi_remote = max_stream_data;
                }

                if let Some(max_stream_data) = tp.initial_max_stream_data_uni {
                    self.peer_init_max_stream_data_uni = max_stream_data;
                }
            },

            // This is optional in qlog. Without an initiator we cannot
            // attribute limits to the local or peer transport parameters.
            None => trace!("ignoring transport parameters with no initiator"),
        }
    }

    fn consume_qlog_packet_received(
        &mut self, pr: &qlog::events::quic::PacketReceived, ev_time: f64,
        process_acks: bool,
    ) -> Result<(), TrackerError> {
        if let Some(frames) = &pr.frames {
            for frame in frames {
                match frame {
                    QuicFrame::Ack { acked_ranges, .. } => {
                        if process_acks {
                            if let Some(ack_ranges) = acked_ranges {
                                let ty = PacketType::from_qlog_packet_type(
                                    &pr.header.packet_type,
                                );
                                if let Some(pkt_space) =
                                    self.packet_sent.get_mut(&ty)
                                {
                                    for range in ack_ranges {
                                        // TODO: check ack ranges and rust
                                        // Range mapping is correct
                                        pkt_space
                                            .range_mut(range.as_range_inclusive())
                                            .for_each(|e| e.1.acked = Some(true));
                                    }
                                }
                            }
                        }
                    },

                    QuicFrame::MaxData { maximum, .. } => {
                        self.received_max_data.push((ev_time, *maximum));
                    },

                    QuicFrame::MaxStreamData {
                        stream_id, maximum, ..
                    } => {
                        let init_val = if is_bidi(*stream_id) {
                            self.peer_init_max_stream_data_bidi_remote
                        } else {
                            self.peer_init_max_stream_data_uni
                        };
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
                            .clone()
                            .unwrap_or_default()
                            .payload_length
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
        // Packet number is optional for some packet types.
        let Some(packet_number) = ps.header.packet_number else {
            return Ok(());
        };

        let packet_type =
            PacketType::from_qlog_packet_type(&ps.header.packet_type);
        let packet_info = PacketInfoStub {
            acked: None,
            raw: ps.raw.clone(),
            created_time: ev_time,
            send_at_time: ps.send_at_time,
            ty: packet_type,
            number: packet_number,
        };

        let s = self.packet_sent.entry(packet_type).or_default();

        s.insert(packet_number, packet_info);

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
                        let init_val = if is_bidi(*stream_id) {
                            self.local_init_max_stream_data_bidi_local
                        } else {
                            self.local_init_max_stream_data_uni
                        };
                        self.sent_stream_max_data_tracker
                            .update(*stream_id, *maximum, ev_time, init_val)?;
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
            self.local_pacing_rate.push((ev_time, pacing_rate));
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

    fn consume_qlog_h3_frame_created_client(
        &mut self, fc: &qlog::events::http3::FrameCreated, ev_time: f64,
    ) {
        match &fc.frame {
            Http3Frame::Headers { headers, .. } => {
                let req = self.get_or_insert_http_req(fc.stream_id);
                req.time_first_headers_tx.get_or_insert(ev_time);
                req.set_request_info_from_qlog(headers);
            },

            Http3Frame::Data { .. } => {
                let req = self.get_or_insert_http_req(fc.stream_id);

                req.time_first_data_tx.get_or_insert(ev_time);

                let _ = req.time_last_data_tx.insert(ev_time);

                let length = fc.length.unwrap_or_default();
                req.time_data_tx_set.push((ev_time, length));
                self.largest_data_frame_tx_length_global = std::cmp::max(
                    self.largest_data_frame_tx_length_global,
                    length,
                );
            },

            Http3Frame::PriorityUpdate {
                stream_id: Some(stream_id),
                priority_field_value,
                ..
            } => {
                let req: &mut HttpRequestStub =
                    self.get_or_insert_http_req(*stream_id);
                req.priority_updates.push(priority_field_value.clone());
            },

            // ignore other frames
            _ => (),
        }
    }

    fn consume_qlog_h3_frame_created_server(
        &mut self, fc: &qlog::events::http3::FrameCreated, ev_time: f64,
    ) {
        match &fc.frame {
            Http3Frame::Headers { headers, .. } => {
                let req = self.get_or_insert_http_req(fc.stream_id);
                req.time_first_headers_tx.get_or_insert(ev_time);
                req.set_response_info_from_qlog(headers);
            },

            Http3Frame::Data { .. } => {
                let req = self.get_or_insert_http_req(fc.stream_id);

                req.time_first_data_tx.get_or_insert(ev_time);

                let _ = req.time_last_data_tx.insert(ev_time);

                let length = fc.length.unwrap_or_default();
                req.time_data_tx_set.push((ev_time, length));
                self.largest_data_frame_tx_length_global = std::cmp::max(
                    self.largest_data_frame_tx_length_global,
                    length,
                );
            },

            // ignore other frames
            _ => (),
        }
    }

    fn consume_qlog_h3_frame_parsed_client(
        &mut self, fp: &qlog::events::http3::FrameParsed, ev_time: f64,
    ) {
        match &fp.frame {
            Http3Frame::Headers { headers, .. } => {
                let req = self.get_or_insert_http_req(fp.stream_id);
                req.time_first_headers_rx.get_or_insert(ev_time);

                req.set_response_info_from_qlog(headers);
            },

            Http3Frame::Data { .. } => {
                let req = self.get_or_insert_http_req(fp.stream_id);

                req.time_first_data_rx.get_or_insert(ev_time);

                let _ = req.time_last_data_rx.insert(ev_time);

                // TODO: is default length sensible here?
                let length = fp.length.unwrap_or_default();
                req.time_data_rx_set.push((ev_time, length));
                self.largest_data_frame_rx_length_global = std::cmp::max(
                    self.largest_data_frame_rx_length_global,
                    length,
                );

                let s =
                    self.received_data_frames.entry(fp.stream_id).or_default();

                s.push((ev_time, length));
            },

            // ignore other frames
            _ => (),
        }
    }

    fn consume_qlog_h3_frame_parsed_server(
        &mut self, fp: &qlog::events::http3::FrameParsed, ev_time: f64,
    ) {
        match &fp.frame {
            Http3Frame::Headers { headers, .. } => {
                let req = self.get_or_insert_http_req(fp.stream_id);
                req.time_first_headers_rx.get_or_insert(ev_time);
                req.path = NaOption::new(find_header_value(headers, ":path"));
                req.client_pri_hdr =
                    NaOption::new(find_header_value(headers, "priority"));
            },

            Http3Frame::Data { .. } => {
                let req = self.get_or_insert_http_req(fp.stream_id);

                req.time_first_data_rx.get_or_insert(ev_time);

                let _ = req.time_last_data_rx.insert(ev_time);

                let length = fp.length.unwrap_or_default();
                req.time_data_rx_set.push((ev_time, length));
                self.largest_data_frame_rx_length_global = std::cmp::max(
                    self.largest_data_frame_rx_length_global,
                    length,
                );
            },

            Http3Frame::PriorityUpdate {
                stream_id: Some(stream_id),
                priority_field_value,
                ..
            } => {
                let req = self.get_or_insert_http_req(*stream_id);
                req.priority_updates.push(priority_field_value.clone());
            },

            // ignore other frames
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
        assert_eq!(datastore.local_init_max_stream_data_bidi_local, 0);
        assert_eq!(datastore.peer_init_max_stream_data_bidi_local, 0);

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
                "netError": {},
                "quicError": {},
                "quicRstStreamError": {},
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

    #[test]
    fn http2_window_updates_separate_peer_send_credit_and_our_receive_credit() {
        let mut datastore = Datastore::default();
        let received = |delta: i32| {
            netlog::Event::H2(h2::Event::Http2SessionRecvWindowUpdate(
                h2::Http2SessionRecvWindowUpdateEvent {
                    params: h2::Http2SessionRecvWindowUpdateParams {
                        stream_id: 3,
                        delta,
                    },
                },
            ))
        };
        let sent = |delta: i32| {
            netlog::Event::H2(h2::Event::Http2SessionSendWindowUpdate(
                h2::Http2SessionSendWindowUpdateEvent {
                    params: h2::Http2SessionSendWindowUpdateParams {
                        stream_id: 3,
                        delta,
                    },
                },
            ))
        };
        assert!(consume(&mut datastore, 110, &received(10)).is_ok());
        assert!(consume(&mut datastore, 120, &sent(20)).is_ok());
        assert!(consume(&mut datastore, 130, &sent(-1)).is_ok());
        assert!(consume(&mut datastore, 140, &received(0)).is_ok());
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
