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

use crate::datastore::Datastore;
use crate::push_interp;
use crate::trackers::StreamBufferTracker;
use crate::QlogPointRtt;
use crate::QlogPointu64;
use netlog::h2::H2_DEFAULT_WINDOW_SIZE;

use qlog::events::quic::QuicFrame;

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
    Steps,
}

/// Build a cumulative series in observation order. The first point establishes
/// the initial value at the first observation; all additions are checked.
fn cumulative_series<T: Copy>(
    points: &[(f64, T)], initial: T, checked_add: fn(T, T) -> Option<T>,
    shape: SeriesShape, error: SeriesBuildError,
) -> SeriesResult<Vec<(f64, T)>> {
    let Some(first) = points.first() else {
        return Ok(Vec::new());
    };
    let mut series = vec![(first.0, initial)];
    let mut value = initial;
    for &(time, delta) in points {
        value = checked_add(value, delta).ok_or(error)?;
        match shape {
            SeriesShape::Samples => series.push((time, value)),
            SeriesShape::Steps => push_interp(&mut series, (time, value)),
        }
    }
    Ok(series)
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
    pub h2_send_window_series_absolute: BTreeMap<u32, Vec<(f64, u64)>>,

    pub netlog_h2_stream_received_connection_cumulative: Vec<QlogPointu64>,
    pub netlog_quic_stream_received_connection_cumulative: Vec<QlogPointu64>,

    pub netlog_quic_client_side_window_updates: BTreeMap<i64, Vec<(f64, u64)>>,

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

    fn update_stream_send_y_axis_max(&mut self, y: u64) {
        self.y_max_stream_send_plot = self.y_max_stream_send_plot.max(y);
    }

    fn update_stream_recv_y_axis_max(&mut self, y: u64) {
        self.y_max_stream_recv_plot = self.y_max_stream_recv_plot.max(y);
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

    fn sent_max_data(&mut self, data_store: &Datastore) {
        for point in &data_store.sent_max_data {
            self.update_sent_x_axis_max(point.0);
            self.update_stream_recv_y_axis_max(point.1);

            push_interp(&mut self.sent_max_data, *point);
        }
    }

    fn sum_sent_stream_max_data(&mut self, data_store: &Datastore) {
        for point in data_store.sent_stream_max_data_tracker.sum_series() {
            self.update_sent_x_axis_max(point.0);
            self.update_stream_recv_y_axis_max(point.1);

            push_interp(&mut self.sum_sent_stream_max_data, *point);
        }
    }

    fn packet_sent(&mut self, data_store: &Datastore) {
        if let Some(onertt_pkts) =
            &data_store.packet_sent.get(&crate::PacketType::OneRtt)
        {
            // TODO: Gather these counts during recovery-metric processing.
            let mut sent_count = 0;
            let mut delivered_count = 0;
            let mut without_ack_count = 0;

            for (pkt_num, pkt_info) in *onertt_pkts {
                sent_count += 1;
                push_interp(
                    &mut self.onertt_packet_created,
                    (pkt_info.created_time, *pkt_num),
                );
                push_interp(
                    &mut self.onertt_packet_sent_aggregate_count,
                    (pkt_info.created_time, sent_count),
                );

                // No ACK observation is not evidence of loss. Plot those
                // packets at creation time, since the observation timestamp is
                // unknown. Only Some(true) establishes that delivery was
                // confirmed.
                if pkt_info.acked == Some(true) {
                    delivered_count += 1;
                    push_interp(
                        &mut self.onertt_packet_delivered_aggregate_count,
                        (pkt_info.created_time, delivered_count),
                    );
                } else {
                    self.onertt_packet_without_observed_ack
                        .push((pkt_info.created_time, *pkt_num));
                    without_ack_count += 1;
                    push_interp(
                        &mut self
                            .onertt_packet_without_observed_ack_aggregate_count,
                        (pkt_info.created_time, without_ack_count),
                    );
                }

                self.y_max_onertt_pkt_sent_plot =
                    std::cmp::max(self.y_max_onertt_pkt_sent_plot, *pkt_num);

                // send_at_time is optional
                if let Some(packet_sent_at) = pkt_info.send_at_time {
                    push_interp(
                        &mut self.onertt_packet_sent,
                        (packet_sent_at, *pkt_num),
                    );

                    let delta = packet_sent_at - pkt_info.created_time;
                    push_interp(
                        &mut self.onertt_packet_created_sent_delta,
                        (*pkt_num, delta),
                    );

                    // std::cmp hates floats, so go old school
                    if delta > self.y_max_onertt_packet_created_sent_delta {
                        self.y_max_onertt_packet_created_sent_delta = delta;
                    }

                    if delta < self.y_min_onertt_packet_created_sent_delta {
                        self.y_min_onertt_packet_created_sent_delta = delta;
                    }
                }
            }
        }
    }

    fn packet_recv(&mut self, data_store: &Datastore) {
        if let Some(onertt_pkts) =
            &data_store.packet_received.get(&crate::PacketType::OneRtt)
        {
            for (pkt_num, pkt_info) in *onertt_pkts {
                self.update_received_x_axis_max(pkt_info.created_time);
                self.y_max_onertt_pkt_received_plot =
                    self.y_max_onertt_pkt_received_plot.max(*pkt_num);

                self.onertt_packet_received
                    .push((pkt_info.created_time, *pkt_num));
            }
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
                previous = missing;
            }
        }
    }

    fn sent_stream_max_data(&mut self, data_store: &Datastore) {
        for (stream, points) in data_store.sent_stream_max_data_tracker.streams()
        {
            let points = points.points();
            let mut series_points = vec![];

            for point in points {
                self.update_sent_x_axis_max(point.0);
                self.update_stream_recv_y_axis_max(point.1);

                push_interp(&mut series_points, *point);
            }

            self.sent_stream_max_data.insert(*stream, series_points);
        }
    }

    fn received_stream_max_data(&mut self, data_store: &Datastore) {
        for (stream, points) in
            data_store.received_stream_max_data_tracker.streams()
        {
            let points = points.points();
            let mut series_points = vec![];

            for point in points {
                self.update_sent_x_axis_max(point.0);
                self.update_stream_send_y_axis_max(point.1);

                push_interp(&mut series_points, *point);
            }

            self.received_stream_max_data.insert(*stream, series_points);
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
                &mut self.sent_x_max,
                y_max,
            )?;
        }
        Ok(())
    }

    fn build_buffer_series(
        tracker: &StreamBufferTracker, series: &'static str,
        output: &mut BTreeMap<u64, Vec<QlogPointu64>>,
        sum_output: &mut Vec<QlogPointu64>, x_max: &mut f64, y_max: &mut u64,
    ) -> SeriesResult<()> {
        for (&stream_id, history) in tracker.streams() {
            let mut points = Vec::new();
            for (time, access) in history.points() {
                let end = access
                    .offset
                    .checked_add(access.length)
                    .ok_or(SeriesBuildError { stream_id, series })?;
                *x_max = x_max.max(*time);
                *y_max = (*y_max).max(end);
                push_interp(&mut points, (*time, end));
            }
            output.insert(stream_id, points);
        }
        for &point in tracker.sum_series() {
            push_interp(sum_output, point);
        }
        // The aggregate may exceed any individual stream's extent.
        *y_max = (*y_max).max(tracker.current_sum());
        Ok(())
    }

    fn sent_stream_frames(&mut self, data_store: &Datastore) -> SeriesResult<()> {
        for (stream, points) in &data_store.sent_stream_frames {
            let mut series_points = vec![];

            for point in points {
                if let (_, QuicFrame::Stream { offset, raw, .. }) = point {
                    let offset = offset.unwrap_or_default();
                    let length = raw
                        .as_ref()
                        .and_then(|info| info.payload_length)
                        .unwrap_or_default();
                    let y =
                        offset.checked_add(length).ok_or(SeriesBuildError {
                            stream_id: *stream,
                            series: "sent_stream_frames",
                        })?;

                    self.update_sent_x_axis_max(point.0);
                    self.update_stream_send_y_axis_max(y);

                    series_points.push((point.0, y));
                }
            }

            self.sent_stream_frames_series
                .insert(*stream, series_points);
        }
        Ok(())
    }

    fn received_stream_frames(
        &mut self, data_store: &Datastore,
    ) -> SeriesResult<()> {
        for (stream, points) in &data_store.received_stream_frames {
            let mut series_points = vec![];

            for point in points {
                let y = point.1.offset.checked_add(point.1.length).ok_or(
                    SeriesBuildError {
                        stream_id: *stream,
                        series: "received_stream_frames",
                    },
                )?;

                self.received_x_max = self.received_x_max.max(point.0);
                self.update_stream_recv_y_axis_max(y);

                series_points.push((point.0, y));
            }

            self.received_stream_frames_series
                .insert(*stream, series_points);
        }
        Ok(())
    }

    fn data_frames(&mut self, data_store: &Datastore) -> SeriesResult<()> {
        for (source, output, x_max, y_max, name) in [
            (
                &data_store.received_data_frames,
                &mut self.received_data_frames_series,
                &mut self.received_x_max,
                &mut self.y_max_stream_recv_plot,
                "received_data_frames",
            ),
            (
                &data_store.sent_data_frames,
                &mut self.sent_data_frames_series,
                &mut self.sent_x_max,
                &mut self.y_max_stream_send_plot,
                "sent_data_frames",
            ),
        ] {
            for (&stream_id, points) in source {
                let series = cumulative_series(
                    points,
                    0,
                    u64::checked_add,
                    SeriesShape::Samples,
                    SeriesBuildError {
                        stream_id,
                        series: name,
                    },
                )?;
                if series.is_empty() {
                    continue;
                }
                for &(time, value) in &series {
                    *x_max = x_max.max(time);
                    *y_max = (*y_max).max(value);
                }
                output.insert(stream_id, series);
            }
        }
        Ok(())
    }

    // TODO: hack. Initial window size can theoretically vary through
    // the connection, which makes calculations hard. Practically,
    // nobody does that, so just assume the initial window was either
    // indicated in settings or omitted in order to use defaults.
    fn initial_h2_fc_value(stream_id: u32, data_store: &Datastore) -> u32 {
        if stream_id == 0 {
            // https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9.2
            // Connection-level flow control is 65,535 octets
            H2_DEFAULT_WINDOW_SIZE
        } else {
            data_store
                .h2_server_settings
                .initial_window_size
                .unwrap_or(H2_DEFAULT_WINDOW_SIZE)
        }
    }

    fn h2_window_series(&mut self, data_store: &Datastore) -> SeriesResult<()> {
        self.h2_send_window_series_balanced = Self::build_h2_windows(
            &data_store.h2_send_window_updates_balanced,
            data_store,
            i64::checked_add,
            "h2_fc_balanced",
            &mut self.sent_x_max,
        )?;
        self.h2_send_window_series_absolute = Self::build_h2_windows(
            &data_store.h2_send_window_updates_absolute,
            data_store,
            u64::checked_add,
            "h2_fc_absolute",
            &mut self.sent_x_max,
        )?;
        Ok(())
    }

    fn build_h2_windows<T: Copy + From<u32>>(
        source: &BTreeMap<u32, Vec<(f64, T)>>, data_store: &Datastore,
        checked_add: fn(T, T) -> Option<T>, name: &'static str, x_max: &mut f64,
    ) -> SeriesResult<BTreeMap<u32, Vec<(f64, T)>>> {
        let mut output = BTreeMap::new();
        for (&stream, points) in source {
            let series = cumulative_series(
                points,
                T::from(Self::initial_h2_fc_value(stream, data_store)),
                checked_add,
                SeriesShape::Steps,
                SeriesBuildError {
                    stream_id: u64::from(stream),
                    series: name,
                },
            )?;
            if series.is_empty() {
                continue;
            }
            for &(time, _) in points {
                *x_max = x_max.max(time);
            }
            output.insert(stream, series);
        }
        Ok(output)
    }

    fn netlog_quic_client_side_window_updates(&mut self, data_store: &Datastore) {
        for (stream, points) in &data_store.netlog_quic_client_side_window_updates
        {
            let s = self
                .netlog_quic_client_side_window_updates
                .entry(*stream)
                .or_default();

            for point in points {
                push_interp(s, *point);
            }
        }
    }

    fn netlog_h2_stream_received_connection_cumulative(
        &mut self, data_store: &Datastore,
    ) {
        for point in &data_store.netlog_h2_stream_received_connection_cumulative {
            push_interp(
                &mut self.netlog_h2_stream_received_connection_cumulative,
                *point,
            );
        }
    }

    fn netlog_quic_stream_received_connection_cumulative(
        &mut self, data_store: &Datastore,
    ) {
        for point in &data_store.netlog_quic_stream_received_connection_cumulative
        {
            push_interp(
                &mut self.netlog_quic_stream_received_connection_cumulative,
                *point,
            );
        }
    }

    fn received_max_data(&mut self, data_store: &Datastore) {
        for point in &data_store.received_max_data {
            push_interp(&mut self.received_max_data, *point);
        }
    }

    fn sum_received_stream_max_data(&mut self, data_store: &Datastore) {
        for point in data_store.received_stream_max_data_tracker.sum_series() {
            push_interp(&mut self.sum_received_stream_max_data, *point);
        }
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

        self.sent_max_data(data_store);
        self.sum_sent_stream_max_data(data_store);

        self.packet_sent(data_store);
        self.packet_recv(data_store);
        self.missing_packets(data_store);

        self.sent_stream_max_data(data_store);
        self.received_stream_max_data(data_store);

        self.stream_buffers(data_store)?;

        self.sent_stream_frames(data_store)?;
        self.received_stream_frames(data_store)?;

        self.data_frames(data_store)?;
        self.h2_window_series(data_store)?;

        self.netlog_h2_stream_received_connection_cumulative(data_store);
        self.netlog_quic_stream_received_connection_cumulative(data_store);
        self.netlog_quic_client_side_window_updates(data_store);

        self.received_max_data(data_store);
        self.sum_received_stream_max_data(data_store);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SeriesStore;
    use crate::datastore::Datastore;
    use crate::datastore::PacketInfoStub;
    use crate::datastore::StreamDatapoint;
    use crate::PacketType;
    use qlog::events::quic::QuicFrame;
    use qlog::events::RawInfo;

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
    fn h2_data_cumulative_series_has_exactly_one_point_per_frame() {
        let mut datastore = Datastore::default();
        datastore
            .sent_data_frames
            .insert(3, vec![(1.0, 4), (2.0, 5)]);
        datastore
            .received_data_frames
            .insert(3, vec![(1.5, 2), (2.5, 7)]);
        datastore.sent_data_frames.insert(5, Vec::new());
        datastore.received_data_frames.insert(5, Vec::new());
        let result = SeriesStore::from_datastore(&datastore);
        assert!(result.is_ok());
        if let Ok(series) = result {
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
        }
    }

    #[test]
    fn invalid_cumulative_lengths_are_rejected_without_wrapping() {
        for sent in [true, false] {
            let mut datastore = Datastore::default();
            let stream_id = 7;
            let points = vec![(1.0, u64::MAX), (2.0, 1)];
            if sent {
                datastore.sent_data_frames.insert(stream_id, points);
            } else {
                datastore.received_data_frames.insert(stream_id, points);
            }
            let result = SeriesStore::from_datastore(&datastore);
            assert!(result.is_err_and(|error| {
                error.stream_id == stream_id &&
                    error.series ==
                        if sent {
                            "sent_data_frames"
                        } else {
                            "received_data_frames"
                        }
            }));
        }
    }

    #[test]
    fn overflowing_stream_offsets_are_rejected() {
        let mut datastore = Datastore::default();
        datastore.received_stream_frames.insert(9, vec![(
            1.0,
            StreamDatapoint {
                offset: u64::MAX,
                length: 1,
            },
        )]);
        let result = SeriesStore::from_datastore(&datastore);
        assert!(result.is_err_and(|error| error.stream_id == 9 &&
            error.series == "received_stream_frames"));

        let mut datastore = Datastore::default();
        datastore
            .sent_stream_frames
            .insert(11, vec![(1.0, QuicFrame::Stream {
                stream_id: 11,
                offset: Some(u64::MAX),
                fin: None,
                raw: Some(Box::new(RawInfo {
                    payload_length: Some(1),
                    ..RawInfo::default()
                })),
            })]);
        let result = SeriesStore::from_datastore(&datastore);
        assert!(result
            .is_err_and(|error| error.stream_id == 11 &&
                error.series == "sent_stream_frames"));
    }

    #[test]
    fn h2_windows_keep_initial_limit_and_reject_overflow() {
        let mut datastore = Datastore::default();
        datastore
            .h2_send_window_updates_balanced
            .insert(1, vec![(1.0, -5)]);
        datastore
            .h2_send_window_updates_absolute
            .insert(0, vec![(1.0, 7)]);
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
            assert_eq!(
                series
                    .h2_send_window_series_absolute
                    .get(&0)
                    .map(Vec::as_slice),
                Some([(1.0, 65535), (1.0, 65535), (1.0, 65542)].as_slice())
            );
        }

        let mut datastore = Datastore::default();
        datastore
            .h2_send_window_updates_balanced
            .insert(4, vec![(1.0, i64::MAX)]);
        let result = SeriesStore::from_datastore(&datastore);
        assert!(result.is_err_and(
            |error| error.stream_id == 4 && error.series == "h2_fc_balanced"
        ));

        let mut datastore = Datastore::default();
        datastore
            .h2_send_window_updates_absolute
            .insert(0, vec![(1.0, u64::MAX)]);
        let result = SeriesStore::from_datastore(&datastore);
        assert!(result.is_err_and(
            |error| error.stream_id == 0 && error.series == "h2_fc_absolute"
        ));

        let mut datastore = Datastore::default();
        datastore.h2_server_settings.initial_window_size = Some(u32::MAX);
        datastore
            .h2_send_window_updates_balanced
            .insert(1, vec![(1.0, 0)]);
        let result = SeriesStore::from_datastore(&datastore);
        assert!(result.is_ok());
        if let Ok(series) = result {
            assert_eq!(
                series
                    .h2_send_window_series_balanced
                    .get(&1)
                    .and_then(|points| points.last())
                    .map(|point| point.1),
                Some(i64::from(u32::MAX))
            );
        }

        let mut datastore = Datastore::default();
        datastore
            .h2_send_window_updates_balanced
            .insert(1, vec![(1.0, -i64::from(u32::MAX))]);
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
