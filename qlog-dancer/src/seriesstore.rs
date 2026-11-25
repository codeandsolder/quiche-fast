// Copyright (C) 2022, Cloudflare, Inc.
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

use crate::datastore::ApplicationProto;
use crate::datastore::Datastore;
use crate::push_interp;
use crate::trackers::QuicStreamTracker;
use crate::trackers::StreamBufferTracker;
use crate::trackers::StreamExtent;
use crate::trackers::StreamMaxTracker;
use crate::trackers::StreamTracker;
use crate::QlogPointRtt;
use crate::QlogPointu64;
use netlog::h2::H2_DEFAULT_WINDOW_SIZE;

/// A log contains stream/window values whose sum cannot fit the chart's
/// integer coordinate type. Never wrap and render a fabricated measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeriesBuildError {
    pub stream_id: u64,
    pub series: &'static str,
}

impl std::fmt::Display for SeriesBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "numeric overflow in {} series for stream {}",
            self.series, self.stream_id
        )
    }
}

impl std::error::Error for SeriesBuildError {}

type SeriesResult<T> = Result<T, SeriesBuildError>;

#[derive(Clone, Copy)]
enum SeriesShape {
    Samples,
    Steps { opened_at: f64 },
}

/// Build a cumulative series in observation order. The first point establishes
/// the initial value at the first observation; all additions are checked.
fn cumulative_series<T: Copy>(
    points: &[(f64, T)], initial: T, checked_add: fn(T, T) -> Option<T>,
    shape: SeriesShape, error: SeriesBuildError,
) -> SeriesResult<Vec<(f64, T)>> {
    let start = match shape {
        SeriesShape::Samples => {
            let Some(first) = points.first() else {
                return Ok(Vec::new());
            };
            first.0
        },
        SeriesShape::Steps { opened_at } => opened_at,
    };
    let mut series = vec![(start, initial)];
    let mut value = initial;
    for &(time, delta) in points {
        value = checked_add(value, delta).ok_or(error)?;
        match shape {
            SeriesShape::Samples => series.push((time, value)),
            SeriesShape::Steps { .. } => push_interp(&mut series, (time, value)),
        }
    }
    Ok(series)
}

/// Sort packet samples by timestamp, with a deterministic packet-number
/// tie-break.
fn sort_packet_points(points: &mut [QlogPointu64]) {
    points
        .sort_unstable_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
}

#[derive(Default)]
pub struct SeriesStore {
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

    pub onertt_packet_created: Vec<QlogPointu64>,
    pub onertt_packet_sent: Vec<QlogPointu64>,
    pub onertt_packet_sent_aggregate_count: Vec<QlogPointu64>,
    /// Packets without a confirmed ACK, not proven packet losses.
    pub onertt_packet_without_observed_ack: Vec<QlogPointu64>,
    pub onertt_packet_without_observed_ack_aggregate_count: Vec<QlogPointu64>,
    pub onertt_packet_delivered_aggregate_count: Vec<QlogPointu64>,

    pub onertt_packet_received: Vec<QlogPointu64>,

    pub netlog_missing_packets: Vec<f64>,

    // this one is a little different, delta as a function of packet number
    pub onertt_packet_created_sent_delta: Vec<(u64, f64)>,

    pub sent_max_data: Vec<QlogPointu64>,
    pub sent_stream_max_data: BTreeMap<u64, Vec<QlogPointu64>>,

    pub received_max_data: Vec<QlogPointu64>,
    pub received_stream_max_data: BTreeMap<u64, Vec<QlogPointu64>>,

    pub stream_buffer_reads: BTreeMap<u64, Vec<QlogPointu64>>,
    pub sum_stream_buffer_reads: Vec<QlogPointu64>,

    pub stream_buffer_writes: BTreeMap<u64, Vec<QlogPointu64>>,
    pub sum_stream_buffer_writes: Vec<QlogPointu64>,

    pub stream_buffer_dropped: BTreeMap<u64, Vec<QlogPointu64>>,
    pub sum_stream_buffer_dropped: Vec<QlogPointu64>,

    pub sent_stream_frames_series: BTreeMap<u64, Vec<QlogPointu64>>,

    pub received_stream_frames_series: BTreeMap<u64, Vec<QlogPointu64>>,

    pub received_data_frames_series: BTreeMap<u64, Vec<QlogPointu64>>,
    pub sent_data_frames_series: BTreeMap<u64, Vec<QlogPointu64>>,

    pub h2_send_window_series_balanced: BTreeMap<u32, Vec<(f64, i64)>>,
    /// Cumulative connection credit we granted to the peer, including the
    /// default.
    pub h2_connection_receive_credit: Vec<QlogPointu64>,

    pub netlog_h2_stream_received_connection_cumulative: Vec<QlogPointu64>,
    pub quic_receive_credit_consumed: Vec<QlogPointu64>,
    pub quic_send_credit_consumed: Vec<QlogPointu64>,

    pub sum_received_stream_max_data: Vec<QlogPointu64>,
    pub sum_sent_stream_max_data: Vec<QlogPointu64>,

    pub sent_x_min: f64,
    pub sent_x_max: f64,

    pub received_x_min: f64,
    pub received_x_max: f64,

    pub y_max_stream_send_plot: u64,
    pub y_max_stream_recv_plot: u64,
    pub y_max_congestion_plot: u64,
    pub y_max_rtt_plot: f32,

    pub y_max_onertt_pkt_sent_plot: u64,
    pub y_min_onertt_packet_created_sent_delta: f64,
    pub y_max_onertt_packet_created_sent_delta: f64,

    pub y_max_onertt_pkt_received_plot: u64,

    pub max_pacing_rate: u64,
    pub max_delivery_rate: u64,
    pub max_send_rate: u64,
    pub max_ack_rate: u64,
}

impl SeriesStore {
    /// Builds plotting series from parsed events.
    ///
    /// # Errors
    /// Returns a stream-specific error when a length, byte count or window
    /// update cannot be represented without integer overflow.
    pub fn from_datastore(data_store: &Datastore) -> SeriesResult<Self> {
        let mut series_store = Self::default();
        series_store.populate_series_values(data_store)?;
        Ok(series_store)
    }

    const fn update_sent_x_axis_max(&mut self, x: f64) {
        self.sent_x_max = self.sent_x_max.max(x);
    }

    const fn update_received_x_axis_max(&mut self, x: f64) {
        self.received_x_max = self.received_x_max.max(x);
    }

    fn update_congestion_y_axis_max(&mut self, y: u64) {
        self.y_max_congestion_plot = self.y_max_congestion_plot.max(y);
    }

    const fn update_rtt_y_axis_max(&mut self, y: f32) {
        self.y_max_rtt_plot = self.y_max_rtt_plot.max(y);
    }

    fn cwnd(&mut self, data_store: &Datastore) {
        for point in &data_store.local_cwnd {
            self.update_sent_x_axis_max(point.0);
            self.update_congestion_y_axis_max(point.1);

            push_interp(&mut self.local_cwnd, *point);
        }
    }

    fn bif(&mut self, data_store: &Datastore) {
        for point in &data_store.local_bytes_in_flight {
            self.update_sent_x_axis_max(point.0);
            self.update_congestion_y_axis_max(point.1);

            push_interp(&mut self.local_bytes_in_flight, *point);
        }
    }

    fn min_rtt(&mut self, data_store: &Datastore) {
        for point in &data_store.local_min_rtt {
            self.update_sent_x_axis_max(point.0);
            self.update_rtt_y_axis_max(point.1);

            push_interp(&mut self.local_min_rtt, *point);
        }
    }

    fn latest_rtt(&mut self, data_store: &Datastore) {
        for point in &data_store.local_latest_rtt {
            self.update_sent_x_axis_max(point.0);
            self.update_rtt_y_axis_max(point.1);

            push_interp(&mut self.local_latest_rtt, *point);
        }
    }

    fn pacing_rate(&mut self, data_store: &Datastore) {
        for point in &data_store.local_pacing_rate {
            self.update_sent_x_axis_max(point.0);
            self.max_pacing_rate = self.max_pacing_rate.max(point.1);

            push_interp(&mut self.local_pacing_rate, *point);
        }
    }

    fn delivery_rate(&mut self, data_store: &Datastore) {
        for point in &data_store.local_delivery_rate {
            self.update_sent_x_axis_max(point.0);
            self.max_delivery_rate = self.max_delivery_rate.max(point.1);

            push_interp(&mut self.local_delivery_rate, *point);
        }
    }

    fn send_rate(&mut self, data_store: &Datastore) {
        for point in &data_store.local_send_rate {
            self.update_sent_x_axis_max(point.0);
            self.max_send_rate = self.max_send_rate.max(point.1);

            push_interp(&mut self.local_send_rate, *point);
        }
    }

    fn ack_rate(&mut self, data_store: &Datastore) {
        for point in &data_store.local_ack_rate {
            self.update_sent_x_axis_max(point.0);
            self.max_ack_rate = self.max_ack_rate.max(point.1);

            push_interp(&mut self.local_ack_rate, *point);
        }
    }

    fn ssthresh(&mut self, data_store: &Datastore) {
        for point in &data_store.local_ssthresh {
            self.update_sent_x_axis_max(point.0);
            // ssthresh tends to start off large and swamps the y-axis

            push_interp(&mut self.local_ssthresh, *point);
        }
    }

    fn smoothed_rtt(&mut self, data_store: &Datastore) {
        for point in &data_store.local_smoothed_rtt {
            self.update_sent_x_axis_max(point.0);
            // smoothed_rtt tends to start off large and swamps the y-axis

            push_interp(&mut self.local_smoothed_rtt, *point);
        }
    }

    fn max_data_series(
        points: &[QlogPointu64], initial: Option<u64>,
        output: &mut Vec<QlogPointu64>, x_min: &mut f64, x_max: &mut f64,
        y_max: &mut u64,
    ) {
        let mut points = points.to_vec();
        points.sort_by(|a, b| a.0.total_cmp(&b.0));
        let mut maximum = initial.unwrap_or_default();
        for (time, value) in points {
            maximum = maximum.max(value);
            *x_min = x_min.min(time);
            *x_max = x_max.max(time);
            *y_max = (*y_max).max(maximum);
            push_interp(output, (time, maximum));
        }
    }

    fn packet_sent(&mut self, data_store: &Datastore) {
        let Some(packets) =
            data_store.packet_sent.get(&crate::PacketType::OneRtt)
        else {
            return;
        };
        let mut observations = packets.values().collect::<Vec<_>>();
        // Packet numbers are identifiers, not a temporal ordering. The
        // cumulative counters must remain monotonic on their time axis.
        observations.sort_unstable_by(|a, b| {
            a.created_time
                .total_cmp(&b.created_time)
                .then_with(|| a.number.cmp(&b.number))
        });
        let mut sent_count = 0;
        let mut delivered_count = 0;
        let mut without_ack_count = 0;
        if let Some(first) = observations.first() {
            for series in [
                &mut self.onertt_packet_sent_aggregate_count,
                &mut self.onertt_packet_delivered_aggregate_count,
                &mut self.onertt_packet_without_observed_ack_aggregate_count,
            ] {
                series.push((first.created_time, 0));
            }
        }

        for packet in observations {
            let time = packet.created_time;
            self.sent_x_min = self.sent_x_min.min(time);
            self.update_sent_x_axis_max(time);
            self.y_max_onertt_pkt_sent_plot =
                self.y_max_onertt_pkt_sent_plot.max(packet.number);
            self.onertt_packet_created.push((time, packet.number));

            sent_count += 1;
            // Retrospective classification by packet observation time,
            // not the time at which an acknowledgement was received.
            if packet.acked == Some(true) {
                delivered_count += 1;
            } else {
                without_ack_count += 1;
                self.onertt_packet_without_observed_ack
                    .push((time, packet.number));
            }
            for (series, count) in [
                (&mut self.onertt_packet_sent_aggregate_count, sent_count),
                (
                    &mut self.onertt_packet_delivered_aggregate_count,
                    delivered_count,
                ),
                (
                    &mut self.onertt_packet_without_observed_ack_aggregate_count,
                    without_ack_count,
                ),
            ] {
                push_interp(series, (time, count));
            }

            if let Some(sent_at) = packet.send_at_time {
                self.onertt_packet_sent.push((sent_at, packet.number));
                self.sent_x_min = self.sent_x_min.min(sent_at);
                self.update_sent_x_axis_max(sent_at);
            }
        }
        sort_packet_points(&mut self.onertt_packet_sent);

        // This series is plotted against packet number, not time.
        for (&number, packet) in packets {
            if let Some(sent_at) = packet.send_at_time {
                let delta = sent_at - packet.created_time;
                self.onertt_packet_created_sent_delta.push((number, delta));
                self.y_min_onertt_packet_created_sent_delta =
                    self.y_min_onertt_packet_created_sent_delta.min(delta);
                self.y_max_onertt_packet_created_sent_delta =
                    self.y_max_onertt_packet_created_sent_delta.max(delta);
            }
        }
    }

    fn packet_recv(&mut self, data_store: &Datastore) {
        if let Some(packets) =
            data_store.packet_received.get(&crate::PacketType::OneRtt)
        {
            for (&number, packet) in packets {
                self.received_x_min =
                    self.received_x_min.min(packet.created_time);
                self.update_received_x_axis_max(packet.created_time);
                self.y_max_onertt_pkt_received_plot =
                    self.y_max_onertt_pkt_received_plot.max(number);
                self.onertt_packet_received
                    .push((packet.created_time, number));
            }
            sort_packet_points(&mut self.onertt_packet_received);
        }
    }

    fn missing_packets(&mut self, data_store: &Datastore) {
        // A marker identifies a change in the recorded missing-packet list,
        // not a proven new loss. Borrow the previous list rather than copying
        // it.
        let mut previous: &[u64] = &[];
        for (event_time, missing) in
            &data_store.netlog_ack_sent_missing_packets_raw
        {
            if previous != missing {
                self.netlog_missing_packets.push(*event_time);
                self.received_x_min = self.received_x_min.min(*event_time);
                self.update_received_x_axis_max(*event_time);
                previous = missing;
            }
        }
    }

    fn stream_max_data(
        tracker: &StreamMaxTracker,
        output: &mut BTreeMap<u64, Vec<QlogPointu64>>, x_min: &mut f64,
        x_max: &mut f64, y_max: &mut u64,
    ) {
        for (&stream, history) in tracker.streams() {
            Self::max_data_series(
                history.points(),
                history.initial(),
                output.entry(stream).or_default(),
                x_min,
                x_max,
                y_max,
            );
        }
    }

    fn stream_buffers(&mut self, data_store: &Datastore) -> SeriesResult<()> {
        for (tracker, series, output, sum_output, is_receive) in [
            (
                &data_store.stream_buffer_reads_tracker,
                "stream_buffer_reads",
                &mut self.stream_buffer_reads,
                &mut self.sum_stream_buffer_reads,
                true,
            ),
            (
                &data_store.stream_buffer_writes_tracker,
                "stream_buffer_writes",
                &mut self.stream_buffer_writes,
                &mut self.sum_stream_buffer_writes,
                false,
            ),
            (
                &data_store.stream_buffer_dropped_tracker,
                "stream_buffer_dropped",
                &mut self.stream_buffer_dropped,
                &mut self.sum_stream_buffer_dropped,
                false,
            ),
        ] {
            let y_max = if is_receive {
                &mut self.y_max_stream_recv_plot
            } else {
                &mut self.y_max_stream_send_plot
            };
            Self::build_buffer_series(
                tracker,
                series,
                output,
                sum_output,
                &mut self.sent_x_min,
                &mut self.sent_x_max,
                y_max,
            )?;
        }
        Ok(())
    }

    fn build_buffer_series(
        tracker: &StreamBufferTracker, series: &'static str,
        output: &mut BTreeMap<u64, Vec<QlogPointu64>>,
        sum_output: &mut Vec<QlogPointu64>, x_min: &mut f64, x_max: &mut f64,
        y_max: &mut u64,
    ) -> SeriesResult<()> {
        for (&stream_id, history) in tracker.streams() {
            let mut points = history
                .points()
                .iter()
                .map(|(time, access)| {
                    Ok((
                        *time,
                        access.extent(stream_id).map_err(|_| {
                            SeriesBuildError { stream_id, series }
                        })?,
                    ))
                })
                .collect::<SeriesResult<Vec<_>>>()?;
            points.sort_by(|a, b| a.0.total_cmp(&b.0));
            let mut steps = Vec::new();
            for point in points {
                push_interp(&mut steps, point);
            }
            output.insert(stream_id, steps);
        }
        Self::tracker_sum(tracker, sum_output, x_min, x_max, y_max, series)
    }

    fn quic_stream_frames(
        tracker: &QuicStreamTracker,
        output: &mut BTreeMap<u64, Vec<QlogPointu64>>, x_min: &mut f64,
        x_max: &mut f64, y_max: &mut u64,
    ) {
        for (&stream_id, history) in tracker.streams() {
            let mut points = Vec::new();
            for &(time, observation) in history.points() {
                let Some(end) = observation.frame_end() else {
                    continue;
                };
                *x_min = x_min.min(time);
                *x_max = x_max.max(time);
                *y_max = (*y_max).max(end);
                points.push((time, end));
            }
            if !points.is_empty() {
                points.sort_by(|a, b| a.0.total_cmp(&b.0));
                output.insert(stream_id, points);
            }
        }
    }

    fn data_frames(&mut self, data_store: &Datastore) -> SeriesResult<()> {
        for (&stream_id, request) in &data_store.http_requests {
            for (history, output, x_min, x_max, y_max, name) in [
                (
                    &request.received_data,
                    &mut self.received_data_frames_series,
                    &mut self.received_x_min,
                    &mut self.received_x_max,
                    &mut self.y_max_stream_recv_plot,
                    "received_data_frames",
                ),
                (
                    &request.sent_data,
                    &mut self.sent_data_frames_series,
                    &mut self.sent_x_min,
                    &mut self.sent_x_max,
                    &mut self.y_max_stream_send_plot,
                    "sent_data_frames",
                ),
            ] {
                if let Some(first) = history.first_time() {
                    *x_min = x_min.min(first);
                }
                if let Some(last) = history.last_time() {
                    *x_max = x_max.max(last);
                }
                let mut points = history
                    .observations()
                    .iter()
                    .filter_map(|&(time, length)| {
                        length.map(|length| (time, length))
                    })
                    .collect::<Vec<_>>();
                points.sort_by(|a, b| a.0.total_cmp(&b.0));
                let series = cumulative_series(
                    &points,
                    0,
                    u64::checked_add,
                    SeriesShape::Samples,
                    SeriesBuildError {
                        stream_id,
                        series: name,
                    },
                )?;
                if !series.is_empty() {
                    *y_max = (*y_max).max(history.known_bytes());
                    output.insert(stream_id, series);
                }
            }
        }
        Ok(())
    }

    fn h2_window_series(&mut self, data_store: &Datastore) -> SeriesResult<()> {
        self.h2_send_window_series_balanced = Self::build_h2_windows(
            &data_store.h2_send_windows,
            &mut self.sent_x_min,
            &mut self.sent_x_max,
        )?;
        self.netlog_h2_stream_received_connection_cumulative =
            Self::h2_connection_received_data(data_store)?;
        self.h2_connection_receive_credit = Self::h2_receive_credit(
            data_store,
            &self.netlog_h2_stream_received_connection_cumulative,
        )?;
        for &(time, _) in &self.h2_connection_receive_credit {
            self.received_x_min = self.received_x_min.min(time);
            self.received_x_max = self.received_x_max.max(time);
        }
        Ok(())
    }

    /// Connection-level receive credit starts at 65,535, unaffected by
    /// `SETTINGS_INITIAL_WINDOW_SIZE`. Compare only grants sent locally with
    /// inbound DATA; peer `WINDOW_UPDATE` events concern our outbound data.
    fn h2_receive_credit(
        data_store: &Datastore, data: &[QlogPointu64],
    ) -> SeriesResult<Vec<QlogPointu64>> {
        let mut updates = data_store
            .h2_recv_window_updates
            .get(&0)
            .cloned()
            .unwrap_or_default();
        if updates.is_empty() && data.is_empty() {
            return Ok(Vec::new());
        }
        updates.sort_by(|a, b| a.0.total_cmp(&b.0));
        let (start, end) = updates
            .iter()
            .chain(data)
            .fold((0.0_f64, 0.0_f64), |(start, end), &(time, _)| {
                (start.min(time), end.max(time))
            });
        let mut series = cumulative_series(
            &updates,
            u64::from(H2_DEFAULT_WINDOW_SIZE),
            u64::checked_add,
            SeriesShape::Steps { opened_at: start },
            SeriesBuildError {
                stream_id: 0,
                series: "h2_connection_receive_credit",
            },
        )?;
        if let Some(&(_, credit)) = series.last().filter(|point| point.0 < end) {
            series.push((end, credit));
        }
        Ok(series)
    }

    fn build_h2_windows(
        source: &crate::datastore::H2SendWindows, x_min: &mut f64,
        x_max: &mut f64,
    ) -> SeriesResult<BTreeMap<u32, Vec<(f64, i64)>>> {
        let mut output = BTreeMap::new();
        for (stream, history) in source.histories() {
            let series = cumulative_series(
                &history.changes,
                i64::from(history.initial),
                i64::checked_add,
                SeriesShape::Steps {
                    opened_at: history.opened_at,
                },
                SeriesBuildError {
                    stream_id: u64::from(stream),
                    series: "h2_fc_balanced",
                },
            )?;
            for &(time, _) in &series {
                *x_min = x_min.min(time);
                *x_max = x_max.max(time);
            }
            output.insert(stream, series);
        }
        Ok(output)
    }

    fn h2_connection_received_data(
        data_store: &Datastore,
    ) -> SeriesResult<Vec<QlogPointu64>> {
        if data_store.application_proto != ApplicationProto::Http2 {
            return Ok(Vec::new());
        }
        let mut points = data_store
            .http_requests
            .values()
            .flat_map(|req| {
                req.received_data.observations().iter().filter_map(
                    |&(time, length)| length.map(|length| (time, length)),
                )
            })
            .collect::<Vec<_>>();
        points.sort_by(|a, b| a.0.total_cmp(&b.0));
        let Some(first) = points.first() else {
            return Ok(Vec::new());
        };
        cumulative_series(
            &points,
            0,
            u64::checked_add,
            SeriesShape::Steps { opened_at: first.0 },
            SeriesBuildError {
                stream_id: 0,
                series: "h2_connection_received_data",
            },
        )
    }

    fn tracker_sum<T: StreamExtent>(
        tracker: &StreamTracker<T>, output: &mut Vec<QlogPointu64>,
        x_min: &mut f64, x_max: &mut f64, y_max: &mut u64, series: &'static str,
    ) -> SeriesResult<()> {
        let points = tracker.chronological_sum_series().map_err(|error| {
            let stream_id = match error {
                crate::trackers::TrackerError::StreamEndOverflow {
                    stream_id,
                    ..
                } |
                crate::trackers::TrackerError::RunningSumOverflow {
                    stream_id,
                    ..
                } => stream_id,
            };
            SeriesBuildError { stream_id, series }
        })?;
        for &(time, value) in points.as_ref() {
            *x_min = x_min.min(time);
            *x_max = x_max.max(time);
            *y_max = (*y_max).max(value);
            push_interp(output, (time, value));
        }
        Ok(())
    }

    fn stream_credit_series(
        &mut self, data_store: &Datastore,
    ) -> SeriesResult<()> {
        Self::max_data_series(
            &data_store.sent_max_data,
            None,
            &mut self.sent_max_data,
            &mut self.sent_x_min,
            &mut self.sent_x_max,
            &mut self.y_max_stream_recv_plot,
        );
        Self::tracker_sum(
            &data_store.sent_stream_max_data_tracker,
            &mut self.sum_sent_stream_max_data,
            &mut self.sent_x_min,
            &mut self.sent_x_max,
            &mut self.y_max_stream_recv_plot,
            "sum_sent_stream_max_data",
        )?;

        Self::stream_max_data(
            &data_store.sent_stream_max_data_tracker,
            &mut self.sent_stream_max_data,
            &mut self.sent_x_min,
            &mut self.sent_x_max,
            &mut self.y_max_stream_recv_plot,
        );
        Self::stream_max_data(
            &data_store.received_stream_max_data_tracker,
            &mut self.received_stream_max_data,
            &mut self.received_x_min,
            &mut self.received_x_max,
            &mut self.y_max_stream_send_plot,
        );

        Self::max_data_series(
            &data_store.received_max_data,
            None,
            &mut self.received_max_data,
            &mut self.received_x_min,
            &mut self.received_x_max,
            &mut self.y_max_stream_send_plot,
        );
        Self::tracker_sum(
            &data_store.received_stream_max_data_tracker,
            &mut self.sum_received_stream_max_data,
            &mut self.received_x_min,
            &mut self.received_x_max,
            &mut self.y_max_stream_send_plot,
            "sum_received_stream_max_data",
        )?;
        Ok(())
    }

    fn populate_series_values(
        &mut self, data_store: &Datastore,
    ) -> SeriesResult<()> {
        self.cwnd(data_store);
        self.bif(data_store);
        self.min_rtt(data_store);
        self.latest_rtt(data_store);
        self.pacing_rate(data_store);
        self.delivery_rate(data_store);
        self.send_rate(data_store);
        self.ack_rate(data_store);
        self.ssthresh(data_store);
        self.smoothed_rtt(data_store);

        self.stream_credit_series(data_store)?;
        self.packet_sent(data_store);
        self.packet_recv(data_store);
        self.missing_packets(data_store);

        self.stream_buffers(data_store)?;

        Self::quic_stream_frames(
            &data_store.sent_quic_streams,
            &mut self.sent_stream_frames_series,
            &mut self.sent_x_min,
            &mut self.sent_x_max,
            &mut self.y_max_stream_send_plot,
        );
        Self::quic_stream_frames(
            &data_store.received_quic_streams,
            &mut self.received_stream_frames_series,
            &mut self.received_x_min,
            &mut self.received_x_max,
            &mut self.y_max_stream_recv_plot,
        );

        self.data_frames(data_store)?;
        self.h2_window_series(data_store)?;

        Self::tracker_sum(
            &data_store.received_quic_streams,
            &mut self.quic_receive_credit_consumed,
            &mut self.received_x_min,
            &mut self.received_x_max,
            &mut self.y_max_stream_recv_plot,
            "quic_receive_credit_consumed",
        )?;
        Self::tracker_sum(
            &data_store.sent_quic_streams,
            &mut self.quic_send_credit_consumed,
            &mut self.sent_x_min,
            &mut self.sent_x_max,
            &mut self.y_max_stream_send_plot,
            "quic_send_credit_consumed",
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SeriesStore;
    use crate::datastore::Datastore;
    use crate::datastore::PacketInfoStub;
    use crate::request_stub::HttpDataHistory;
    use crate::request_stub::HttpRequestStub;
    use crate::PacketType;

    #[test]
    fn all_tracker_aggregate_plots_reconstruct_out_of_order_observations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::datastore::StreamAccess;
        let mut ds = Datastore::default();
        for (id, time, end) in [(0, 7.0, 80), (4, 3.0, 50), (0, -1.0, 10)] {
            ds.sent_stream_max_data_tracker
                .update(id, end, time, Some(20))?;
            ds.received_stream_max_data_tracker.update(
                id,
                end,
                time,
                Some(20),
            )?;
            ds.stream_buffer_reads_tracker.update(
                id,
                StreamAccess {
                    offset: 0,
                    length: end,
                },
                time,
            )?;
        }
        let series = SeriesStore::from_datastore(&ds)?;
        let grants = [(-1.0, 20), (3.0, 20), (3.0, 70), (7.0, 70), (7.0, 130)];
        assert_eq!(series.sum_sent_stream_max_data, grants);
        assert_eq!(series.sum_received_stream_max_data, grants);
        assert_eq!(series.sum_stream_buffer_reads, [
            (-1.0, 10),
            (3.0, 10),
            (3.0, 60),
            (7.0, 60),
            (7.0, 130)
        ]);
        assert_eq!(series.sent_stream_max_data[&0], [
            (-1.0, 20),
            (7.0, 20),
            (7.0, 80)
        ]);
        assert_eq!(series.stream_buffer_reads[&0], [
            (-1.0, 10),
            (7.0, 10),
            (7.0, 80)
        ]);
        assert_eq!(series.sent_x_min, -1.0);
        assert_eq!(series.received_x_min, -1.0);
        assert_eq!(series.y_max_stream_recv_plot, 130);
        assert_eq!(series.y_max_stream_send_plot, 130);
        Ok(())
    }

    #[test]
    fn packet_ack_counts_do_not_equate_unknown_status_with_loss_or_delivery() {
        let mut ds = Datastore::default();
        for (number, time, acked) in [
            (10, 1.0, None),
            (11, 2.0, Some(false)),
            (12, 3.0, Some(true)),
        ] {
            ds.packet_sent
                .entry(PacketType::OneRtt)
                .or_default()
                .insert(number, PacketInfoStub {
                    acked,
                    raw: None,
                    created_time: time,
                    send_at_time: None,
                    ty: PacketType::OneRtt,
                    number,
                });
        }
        let mut series = SeriesStore::default();
        series.packet_sent(&ds);
        assert_eq!(series.onertt_packet_without_observed_ack, vec![
            (1.0, 10),
            (2.0, 11)
        ]);
        assert_eq!(
            series
                .onertt_packet_without_observed_ack_aggregate_count
                .last()
                .map(|p| p.1),
            Some(2),
        );
        assert_eq!(
            series
                .onertt_packet_delivered_aggregate_count
                .last()
                .map(|p| p.1),
            Some(1),
        );
        assert_eq!(
            series
                .onertt_packet_sent_aggregate_count
                .last()
                .map(|p| p.1),
            Some(3),
        );
    }

    #[test]
    fn packet_timelines_use_observation_time_not_packet_number() {
        let mut ds = Datastore::default();
        for (number, created, sent, acked) in [
            (10, 4.0, Some(9.0), Some(true)),
            (20, -2.0, Some(6.0), None),
            (30, 4.0, Some(5.0), Some(true)),
        ] {
            let packet = PacketInfoStub {
                acked,
                raw: None,
                created_time: created,
                send_at_time: sent,
                ty: PacketType::OneRtt,
                number,
            };
            ds.packet_sent
                .entry(PacketType::OneRtt)
                .or_default()
                .insert(number, packet.clone());
            ds.packet_received
                .entry(PacketType::OneRtt)
                .or_default()
                .insert(number, packet);
        }
        let mut series = SeriesStore::default();
        series.packet_sent(&ds);
        series.packet_recv(&ds);
        assert_eq!(series.onertt_packet_created, [
            (-2.0, 20),
            (4.0, 10),
            (4.0, 30)
        ]);
        assert_eq!(series.onertt_packet_received, series.onertt_packet_created);
        assert_eq!(series.onertt_packet_sent, [(5.0, 30), (6.0, 20), (9.0, 10)]);
        assert_eq!((series.sent_x_min, series.sent_x_max), (-2.0, 9.0));
        assert_eq!((series.received_x_min, series.received_x_max), (-2.0, 4.0));
        assert_eq!(series.y_max_onertt_pkt_sent_plot, 30);
        assert_eq!(series.y_max_onertt_pkt_received_plot, 30);
        assert_eq!(series.onertt_packet_created_sent_delta, [
            (10, 5.0),
            (20, 8.0),
            (30, 1.0)
        ]);
        let counts = &series.onertt_packet_sent_aggregate_count;
        let confirmed = &series.onertt_packet_delivered_aggregate_count;
        let unconfirmed =
            &series.onertt_packet_without_observed_ack_aggregate_count;
        assert_eq!(counts.first(), Some(&(-2.0, 0)));
        assert_eq!(counts.last(), Some(&(4.0, 3)));
        assert!(counts
            .windows(2)
            .all(|pair| pair[0].0 <= pair[1].0 && pair[0].1 <= pair[1].1));
        assert_eq!(counts.len(), confirmed.len());
        assert_eq!(counts.len(), unconfirmed.len());
        for ((total, acked), unknown) in
            counts.iter().zip(confirmed).zip(unconfirmed)
        {
            assert_eq!(total.0, acked.0);
            assert_eq!(total.0, unknown.0);
            assert_eq!(total.1, acked.1 + unknown.1);
        }
    }

    #[test]
    fn received_time_range_is_independent_of_sent_packets_and_monotonic() {
        let mut series = SeriesStore {
            sent_x_max: 100.0,
            ..SeriesStore::default()
        };

        series.update_received_x_axis_max(5.0);
        assert_eq!(series.received_x_max, 5.0);

        series.update_received_x_axis_max(2.0);
        assert_eq!(series.received_x_max, 5.0);

        series.update_received_x_axis_max(14.0);
        assert_eq!(series.received_x_max, 14.0);
        assert_eq!(series.sent_x_max, 100.0);
    }

    #[test]
    fn h2_data_cumulative_series_has_exactly_one_point_per_frame(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut datastore = Datastore::default();
        datastore.http_requests.insert(3, HttpRequestStub {
            sent_data: HttpDataHistory::with_known_frames(&[(1.0, 4), (2.0, 5)])?,
            received_data: HttpDataHistory::with_known_frames(&[
                (1.5, 2),
                (2.5, 7),
            ])?,
            ..HttpRequestStub::default()
        });
        datastore
            .http_requests
            .insert(5, HttpRequestStub::default());
        let series = SeriesStore::from_datastore(&datastore)?;
        assert_eq!(
            series.sent_data_frames_series.get(&3),
            Some(&vec![(1.0, 0), (1.0, 4), (2.0, 9)])
        );
        assert_eq!(
            series.received_data_frames_series.get(&3),
            Some(&vec![(1.5, 0), (1.5, 2), (2.5, 9)])
        );
        assert_eq!(series.y_max_stream_send_plot, 9);
        assert_eq!(series.y_max_stream_recv_plot, 9);
        assert!(!series.sent_data_frames_series.contains_key(&5));
        assert!(!series.received_data_frames_series.contains_key(&5));
        Ok(())
    }

    #[test]
    fn data_cumulative_series_sorts_out_of_order_observations(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut datastore = Datastore::default();
        let mut request = HttpRequestStub::default();
        for (time, length) in [
            (5.0, Some(4)),
            (-2.0, None),
            (1.0, Some(7)),
            (9.0, None),
            (5.0, Some(2)),
        ] {
            request.received_data.record(time, length)?;
        }
        assert_eq!(request.received_data.known_bytes(), 13);
        assert_eq!(request.received_data.complete_bytes(), None);
        datastore.http_requests.insert(7, request);
        let series = SeriesStore::from_datastore(&datastore)?;
        assert_eq!(
            series.received_data_frames_series.get(&7),
            Some(&vec![(1.0, 0), (1.0, 7), (5.0, 11), (5.0, 13)])
        );
        assert_eq!(series.received_x_min, -2.0);
        assert_eq!(series.received_x_max, 9.0);
        assert_eq!(series.y_max_stream_recv_plot, 13);
        Ok(())
    }

    #[test]
    fn directional_credit_plots_only_known_stream_endpoints(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::trackers::QuicStreamObservation;
        let mut datastore = Datastore::default();
        let observations = [
            (5.0, QuicStreamObservation::Frame {
                offset: Some(10),
                length: Some(20),
                fin: None,
            }),
            (1.0, QuicStreamObservation::Frame {
                offset: Some(0),
                length: Some(5),
                fin: None,
            }),
            (6.0, QuicStreamObservation::Frame {
                offset: Some(40),
                length: None,
                fin: None,
            }),
            (7.0, QuicStreamObservation::Reset { final_size: 50 }),
        ];
        for (time, observation) in observations {
            datastore
                .received_quic_streams
                .observe(9, observation, time)?;
            datastore.sent_quic_streams.observe(9, observation, time)?;
        }
        let series = SeriesStore::from_datastore(&datastore)?;
        assert_eq!(series.received_stream_frames_series[&9], [
            (1.0, 5),
            (5.0, 30)
        ]);
        assert_eq!(
            series.sent_stream_frames_series,
            series.received_stream_frames_series
        );
        assert_eq!(
            series.quic_send_credit_consumed,
            series.quic_receive_credit_consumed
        );
        assert_eq!(series.quic_receive_credit_consumed, [
            (1.0, 5),
            (5.0, 5),
            (5.0, 30),
            (6.0, 30),
            (6.0, 40),
            (7.0, 40),
            (7.0, 50),
        ]);
        Ok(())
    }

    #[test]
    fn h2_receive_credit_without_updates_spans_observed_data(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut datastore = Datastore {
            application_proto: crate::datastore::ApplicationProto::Http2,
            ..Datastore::default()
        };
        datastore.http_requests.insert(1, HttpRequestStub {
            received_data: HttpDataHistory::with_known_frames(&[
                (-2.0, 8),
                (7.0, 4),
            ])?,
            ..HttpRequestStub::default()
        });
        let series = SeriesStore::from_datastore(&datastore)?;
        assert_eq!(series.h2_connection_receive_credit, [
            (-2.0, 65535),
            (7.0, 65535)
        ]);
        assert_eq!(series.received_x_min, -2.0);
        assert_eq!(series.received_x_max, 7.0);
        Ok(())
    }

    #[test]
    fn h2_windows_keep_initial_limit_and_reject_overflow() {
        let mut datastore = Datastore::default();
        datastore.h2_send_windows.change(1, 1.0, -5);
        datastore.h2_recv_window_updates.insert(0, vec![(1.0, 7)]);
        let result = SeriesStore::from_datastore(&datastore);
        assert!(result.is_ok());
        if let Ok(series) = result {
            assert_eq!(
                series
                    .h2_send_window_series_balanced
                    .get(&1)
                    .map(Vec::as_slice),
                Some([(1.0, 65535), (1.0, 65535), (1.0, 65530)].as_slice())
            );
            assert_eq!(series.h2_connection_receive_credit, [
                (0.0, 65535),
                (1.0, 65535),
                (1.0, 65542)
            ]);
        }

        let mut datastore = Datastore::default();
        datastore.h2_send_windows.change(4, 1.0, i64::MAX);
        let result = SeriesStore::from_datastore(&datastore);
        assert!(result.is_err_and(
            |error| error.stream_id == 4 && error.series == "h2_fc_balanced"
        ));

        let mut datastore = Datastore::default();
        datastore
            .h2_recv_window_updates
            .insert(0, vec![(1.0, u64::MAX)]);
        let result = SeriesStore::from_datastore(&datastore);
        assert!(result.is_err_and(|error| error.stream_id == 0 &&
            error.series == "h2_connection_receive_credit"));

        let mut datastore = Datastore::default();
        datastore
            .h2_send_windows
            .set_initial_credit(0.0, netlog::h2::H2_MAX_WINDOW_SIZE);
        datastore.h2_send_windows.change(1, 1.0, 0);
        let result = SeriesStore::from_datastore(&datastore);
        assert!(result.is_ok());
        if let Ok(series) = result {
            assert_eq!(
                series
                    .h2_send_window_series_balanced
                    .get(&1)
                    .and_then(|points| points.last())
                    .map(|point| point.1),
                Some(i64::from(netlog::h2::H2_MAX_WINDOW_SIZE))
            );
        }

        let mut datastore = Datastore::default();
        datastore
            .h2_send_windows
            .change(1, 1.0, -i64::from(u32::MAX));
        let result = SeriesStore::from_datastore(&datastore);
        assert!(result.is_ok());
        if let Ok(series) = result {
            assert_eq!(
                series
                    .h2_send_window_series_balanced
                    .get(&1)
                    .and_then(|v| v.last())
                    .map(|v| v.1),
                Some(i64::from(65535_u32) - i64::from(u32::MAX))
            );
        }
    }
}
