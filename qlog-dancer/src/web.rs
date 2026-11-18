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

use crate::config::AppConfig;
use crate::plots::congestion_control::plot_cc_plot;
use crate::plots::conn_flow_control::plot_conn_flow_control_canvas;
use crate::plots::conn_overview::plot_main_plot;
use crate::plots::packet_received::plot_packet_received;
use crate::plots::packet_sent::plot_packet_sent_ack_status_count_plot;
use crate::plots::packet_sent::plot_packet_sent_delta_plot_canvas;
use crate::plots::packet_sent::plot_packet_sent_pacing_rate_plot_canvas;
use crate::plots::packet_sent::plot_packet_sent_plot_canvas;
use crate::plots::pending::plot_pending;
use crate::plots::pending::PendingPlotParams;
use crate::plots::rtt::plot_rtt_plot;
use crate::plots::stream_multiplex::plot_stream_multiplexing;
use crate::plots::stream_multiplex::MultiplexPlotsParams;
use crate::plots::stream_sparks::plot_sparks;
use crate::plots::stream_sparks::SparkPlotsParams;
use crate::plots::AreaMargin;
use crate::plots::ChartMargin;
use crate::plots::ChartOutputType;
use crate::plots::ChartSize;
use crate::plots::ClampParams;
use crate::plots::PlotParameters;
use crate::reports::events::sqlog_event_list;
use crate::reports::html::event_list_html_from_table;

use crate::datastore::Datastore;
use crate::datastore::VantagePoint;

use plotters::chart::ChartContext;
use plotters::prelude::Cartesian2d;
use plotters::prelude::Ranged;
use plotters_canvas::CanvasBackend;
use wasm_bindgen::prelude::*;

use crate::seriesstore::SeriesStore;
use crate::sqlog_stream::SqlogStream;

use serde::Deserialize;
use serde::Serialize;

use web_sys::Document;
use web_sys::Element;
use web_sys::Window;

const AREA_MARGIN: AreaMargin = AreaMargin { x: 50, y: 100 };
const CHART_MARGIN: ChartMargin = ChartMargin {
    top: 20,
    bottom: 20,
    left: 20,
    right: 20,
};
const CHART_MARGIN_TIGHT: ChartMargin = ChartMargin {
    top: 10,
    bottom: 2,
    left: 5,
    right: 5,
};

#[wasm_bindgen]
pub struct Pointu64 {
    pub x: f64,
    pub y: u64,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct ChartBounds {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct PlotRanges<T, U> {
    pub x_min: T,
    pub x_max: T,
    pub y_min: U,
    pub y_max: U,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct ChartInfo<T, U> {
    pub chart_bounds: ChartBounds,
    pub plot_ranges: PlotRanges<T, U>,
}

impl<T, U> ChartInfo<T, U> {
    /// Extracts chart bounds and axis ranges without constraining the scalar
    /// types to a particular plot (e.g. f64/u64 or u64/f64).
    pub fn from_chart<X, Y>(
        chart: &ChartContext<CanvasBackend, Cartesian2d<X, Y>>,
    ) -> Self
    where
        X: Ranged<ValueType = T>,
        Y: Ranged<ValueType = U>,
    {
        let pixel_range = chart.plotting_area().get_pixel_range();
        Self {
            chart_bounds: ChartBounds {
                left: pixel_range.0.start,
                top: pixel_range.1.start,
                width: pixel_range.0.end - pixel_range.0.start,
                height: pixel_range.1.end - pixel_range.1.start,
            },
            plot_ranges: PlotRanges {
                x_min: chart.x_range().start,
                x_max: chart.x_range().end,
                y_min: chart.y_range().start,
                y_max: chart.y_range().end,
            },
        }
    }
}

/// Serialize chart metadata without panicking if a value cannot be encoded.
fn chart_info_js<T, U>(chart: Option<ChartInfo<T, U>>) -> Result<JsValue, JsValue>
where
    T: Serialize,
    U: Serialize,
{
    let Some(info) = chart else {
        return Ok(JsValue::null());
    };
    // Preserve the full u64 plot range. The default serializer rejects
    // integers above JS MAX_SAFE_INTEGER, which previously caused a WASM panic.
    let serializer = serde_wasm_bindgen::Serializer::new()
        .serialize_large_number_types_as_bigints(true);
    (info.chart_bounds, info.plot_ranges)
        .serialize(&serializer)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen]
/// Creates a QlogDancerWeb object to interact with logs.
///
/// The `display_name` parameter is reflected into drawn plots.
pub fn new_qlog_dancer(display_name: &str) -> QlogDancerWeb {
    let ds = Datastore {
        total_sent_stream_frame_count: 0,
        vantage_point: VantagePoint::Server,
        ..Default::default()
    };

    QlogDancerWeb {
        ds,
        ss: None,
        display_name: display_name.into(),
        sqlog_stream: SqlogStream::default(),

        mp_chart_info: None,
        cc_chart_info: None,
        rtt_chart_info: None,
        fc_chart_info: None,
        pkt_rx_chart_info: None,
        pkt_tx_chart_info: None,
        pkt_tx_counts_chart_info: None,
        pkt_tx_delta_chart_info: None,
        pkt_tx_pacing_chart_info: None,
    }
}

#[wasm_bindgen]
pub struct QlogDancerWeb {
    display_name: String,
    ds: Datastore,
    ss: Option<SeriesStore>,
    sqlog_stream: SqlogStream,

    mp_chart_info: Option<ChartInfo<f64, u64>>,
    cc_chart_info: Option<ChartInfo<f64, u64>>,
    rtt_chart_info: Option<ChartInfo<f64, f32>>,
    fc_chart_info: Option<ChartInfo<f64, u64>>,
    pkt_rx_chart_info: Option<ChartInfo<f64, u64>>,
    pkt_tx_chart_info: Option<ChartInfo<f64, u64>>,
    pkt_tx_counts_chart_info: Option<ChartInfo<f64, u64>>,
    pkt_tx_delta_chart_info: Option<ChartInfo<u64, f64>>,
    pkt_tx_pacing_chart_info: Option<ChartInfo<f64, u64>>,
}

#[wasm_bindgen]
impl QlogDancerWeb {
    #[wasm_bindgen]
    /// Add bytes to a JSON-SEQ stream. Records are not parsed until the
    /// following record separator, so arbitrary file and network chunks work.
    ///
    /// # Errors
    /// Returns a JavaScript error if framing, the header, or an event is
    /// invalid.
    pub fn process_chunk(&mut self, chunk: &[u8]) -> Result<(), JsValue> {
        self.sqlog_stream
            .push_chunk(chunk)
            .map_err(|err| JsValue::from_str(&err))
    }

    /// Finalize the stream and decode the last record at EOF.
    ///
    /// # Errors
    /// Returns a JavaScript error for a missing header or malformed final
    /// record.
    pub fn finish_stream(&mut self) -> Result<(), JsValue> {
        self.sqlog_stream
            .finish()
            .map_err(|err| JsValue::from_str(&err))
    }

    #[wasm_bindgen]
    /// Consume a ReadableStream as a qlog JSON-SEQ input.
    ///
    /// # Errors
    /// Propagates stream read failures and malformed/truncated qlog records.
    pub async fn read_stream(
        &mut self, readable: web_sys::ReadableStream,
    ) -> Result<(), JsValue> {
        use futures_util::StreamExt;

        let mut stream =
            wasm_streams::ReadableStream::from_raw(readable).into_stream();
        while let Some(chunk) = stream.next().await {
            let bytes = js_sys::Uint8Array::new(&chunk?).to_vec();
            self.process_chunk(&bytes)?;
        }
        self.finish_stream()
    }

    #[wasm_bindgen]
    /// Returns the total count of packets sent in a parsed file.
    ///
    /// A simple function to demonstrate how to access basic information from
    /// parsed log files.
    pub fn total_packets_sent(&self) -> usize {
        let mut ret = 0;
        for v in self.ds.packet_sent.values() {
            ret += v.len();
        }

        ret
    }

    #[wasm_bindgen]
    /// Construct plot data from the completed JSON-SEQ stream.
    ///
    /// # Errors
    /// Returns a JavaScript error if the input is incomplete or if the qlog
    /// vantage point or event data is unsupported.
    pub fn populate_datastore(&mut self) -> Result<(), JsValue> {
        self.finish_stream()?;
        let vantage_point = self
            .sqlog_stream
            .header()
            .and_then(|header| header.trace.vantage_point.as_ref())
            .map_or(qlog::VantagePointType::Unknown, |point| point.ty.clone());

        // Construct the datastore separately so a rejected event never exposes
        // partially updated stream stats or stale plot data.
        self.ss = None;
        let ds = Datastore::with_sqlog_reader_events(
            self.sqlog_stream.events(),
            &vantage_point,
            true,
        )
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
        self.ds = ds;
        Ok(())
    }

    #[wasm_bindgen]
    /// Run through the internal datastore to prepare data for plotting
    ///
    /// Some use cases don't need plots, so you can avoid calling this function
    /// if that's the case.
    pub fn populate_seriesstore(&mut self) -> Result<(), JsValue> {
        self.ss = None;
        let series = SeriesStore::from_datastore(&self.ds)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        self.ss = Some(series);
        Ok(())
    }

    #[wasm_bindgen]
    /// Return plot bounds and ranges for a rendered canvas, or null if the
    /// plot has not been rendered yet.
    ///
    /// # Errors
    /// Returns a JavaScript error if chart bounds cannot be serialized.
    pub fn get_chart_info(&self, canvas_id: &str) -> Result<JsValue, JsValue> {
        match canvas_id {
            "overview_canvas" => chart_info_js(self.mp_chart_info),
            "rtt_canvas" => chart_info_js(self.rtt_chart_info),
            "cc_canvas" => chart_info_js(self.cc_chart_info),
            "flow_control_canvas" => chart_info_js(self.fc_chart_info),
            "pkt-rx-canvas" => chart_info_js(self.pkt_rx_chart_info),
            "pkt-tx-canvas" => chart_info_js(self.pkt_tx_chart_info),
            "pkt-tx-counts-canvas" =>
                chart_info_js(self.pkt_tx_counts_chart_info),
            "pkt-tx-delta-canvas" => chart_info_js(self.pkt_tx_delta_chart_info),
            "pkt-tx-pacing-canvas" =>
                chart_info_js(self.pkt_tx_pacing_chart_info),
            _ => Ok(JsValue::null()),
        }
    }

    #[wasm_bindgen]
    #[cfg(target_arch = "wasm32")]
    /// Draws the multi-panel connection overview plot into the provided
    /// canvas_id.
    pub fn draw_connection_overview(
        &mut self, mp_canvas_id: &str, display_legend: bool,
        x_start: Option<f64>, x_end: Option<f64>,
    ) -> Result<(), JsValue> {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN,
                area_margin: AREA_MARGIN,
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            self.mp_chart_info = None;
            let chart =
                plot_main_plot(&params, &self.display_name, ss, &mp_canvas_id)
                    .map_err(|error| JsValue::from_str(&error.to_string()))?;

            self.mp_chart_info = Some(ChartInfo::from_chart(&chart));
        }
        Ok(())
    }

    #[wasm_bindgen]
    #[cfg(target_arch = "wasm32")]
    /// Draws the congestion plot into the provided canvas_id.
    pub fn draw_cc_plot(
        &mut self, cc_canvas_id: &str, display_legend: bool,
        x_start: Option<f64>, x_end: Option<f64>,
    ) -> Result<(), JsValue> {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN,
                area_margin: AREA_MARGIN,
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            self.cc_chart_info = None;
            let chart = plot_cc_plot(&params, ss, &self.ds, &cc_canvas_id)
                .map_err(|error| JsValue::from_str(&error.to_string()))?;

            self.cc_chart_info = Some(ChartInfo::from_chart(&chart));
        }
        Ok(())
    }

    #[wasm_bindgen]
    #[cfg(target_arch = "wasm32")]
    /// Draws the rtt plot into the provided canvas_id.
    pub fn draw_rtt_plot(
        &mut self, rtt_canvas_id: &str, display_legend: bool,
        x_start: Option<f64>, x_end: Option<f64>,
    ) -> Result<(), JsValue> {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN,
                area_margin: AREA_MARGIN,
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            self.rtt_chart_info = None;
            let chart = plot_rtt_plot(&params, ss, &rtt_canvas_id)
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
            self.rtt_chart_info = Some(ChartInfo::from_chart(&chart));
        }
        Ok(())
    }

    #[wasm_bindgen]
    /// Draws the flow control plot into the provided canvas_id.
    pub fn draw_flow_control(
        &mut self, canvas_id: &str, display_legend: bool,
    ) -> Result<(), JsValue> {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: None,
                    end: None,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN,
                area_margin: AreaMargin { x: 40, y: 80 },
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            let chart_type = ChartOutputType::Canvas {
                canvas_id: canvas_id.to_string(),
            };

            self.fc_chart_info = None;
            let chart = plot_conn_flow_control_canvas(
                &params,
                &self.display_name,
                ss,
                &self.ds,
                &chart_type,
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
            self.fc_chart_info = Some(ChartInfo::from_chart(&chart));
        }
        Ok(())
    }

    #[wasm_bindgen]
    /// Draws the stream sparks plot into the provided canvas_id.
    pub fn draw_sparks(
        &mut self, abs_dl_canvas_id: &str, abs_ul_canvas_id: &str,
        rel_dl_canvas_id: &str, rel_ul_canvas_id: &str,
    ) -> Result<(), JsValue> {
        if let Some(ss) = &self.ss {
            let spark_params = SparkPlotsParams {
                clamp: ClampParams {
                    start: None,
                    end: None,
                    stream_y_max: None,
                },
                colors: AppConfig::colors(false),
                sparks_per_row: 1,
                captions_on_top: false,
                spark_dimension_x: 600,
                caption_area_width: 600,
                label_area_height: 1,
                ..Default::default()
            };

            plot_sparks(
                &spark_params,
                &self.display_name,
                ss,
                &self.ds,
                crate::plots::stream_sparks::SparkOutputs {
                    download: crate::plots::stream_sparks::SparkPair {
                        absolute: &ChartOutputType::Canvas {
                            canvas_id: abs_dl_canvas_id.to_owned(),
                        },
                        relative: &ChartOutputType::Canvas {
                            canvas_id: rel_dl_canvas_id.to_owned(),
                        },
                    },
                    upload: crate::plots::stream_sparks::SparkPair {
                        absolute: &ChartOutputType::Canvas {
                            canvas_id: abs_ul_canvas_id.to_owned(),
                        },
                        relative: &ChartOutputType::Canvas {
                            canvas_id: rel_ul_canvas_id.to_owned(),
                        },
                    },
                },
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        }
        Ok(())
    }

    #[wasm_bindgen]
    /// Draws the packet received plot into the provided canvas_id.
    pub fn draw_packet_received(
        &mut self, canvas_id: &str, display_legend: bool,
    ) -> Result<(), JsValue> {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: None,
                    end: None,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN,
                area_margin: AreaMargin { x: 40, y: 80 },
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            let chart_type = ChartOutputType::Canvas {
                canvas_id: canvas_id.to_string(),
            };

            plot_packet_received(
                &params,
                &self.display_name,
                ss,
                &self.ds,
                &chart_type,
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        }
        Ok(())
    }

    #[wasm_bindgen]
    /// Draws the stream pending plot into the provided canvas_id.
    pub fn draw_pending(&mut self, canvas_id: &str) -> Result<(), JsValue> {
        if let Some(ss) = &self.ss {
            let pending_params = PendingPlotParams {
                clamp: ClampParams {
                    start: None,
                    end: None,
                    stream_y_max: None,
                },
                chart_size: ChartSize {
                    width: 1042,
                    height: 600,
                },
                colors: AppConfig::colors(false),
                display_chart_title: false,
            };

            let chart_type = ChartOutputType::Canvas {
                canvas_id: canvas_id.to_string(),
            };

            plot_pending(
                &pending_params,
                &self.display_name,
                ss,
                &self.ds,
                &chart_type,
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        }
        Ok(())
    }

    #[wasm_bindgen]
    /// Draws the packet sent plot into the provided canvas_id.
    pub fn draw_packet_sent_plot(
        &mut self, pkt_tx_canvas_id: &str, display_legend: bool,
        x_start: Option<f64>, x_end: Option<f64>,
    ) -> Result<(), JsValue> {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN_TIGHT,
                area_margin: AreaMargin { x: 40, y: 80 },
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            self.pkt_tx_chart_info = None;
            let chart = plot_packet_sent_plot_canvas(
                &params,
                &self.display_name,
                ss,
                pkt_tx_canvas_id,
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))?;

            self.pkt_tx_chart_info = Some(ChartInfo::from_chart(&chart));
        }
        Ok(())
    }

    #[wasm_bindgen]
    /// Draws the packet sent plot into the provided canvas_id.
    pub fn draw_packet_sent_ack_status_count_plot(
        &mut self, canvas_id: &str, display_legend: bool, x_start: Option<f64>,
        x_end: Option<f64>,
    ) -> Result<(), JsValue> {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN_TIGHT,
                area_margin: AreaMargin { x: 40, y: 80 },
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            self.pkt_tx_counts_chart_info = None;
            let chart =
                plot_packet_sent_ack_status_count_plot(&params, ss, canvas_id)
                    .map_err(|error| JsValue::from_str(&error.to_string()))?;

            self.pkt_tx_counts_chart_info = Some(ChartInfo::from_chart(&chart));
        }
        Ok(())
    }

    #[wasm_bindgen]
    /// Draws the packet sent plot into the provided canvas_id.
    pub fn draw_packet_sent_delta_plot(
        &mut self, pkt_tx_delta_canvas_id: &str, display_legend: bool,
        x_start: Option<f64>, x_end: Option<f64>,
    ) -> Result<(), JsValue> {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN_TIGHT,
                area_margin: AreaMargin { x: 40, y: 5 },
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            self.pkt_tx_delta_chart_info = None;
            let chart = plot_packet_sent_delta_plot_canvas(
                &params,
                ss,
                pkt_tx_delta_canvas_id,
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))?;

            self.pkt_tx_delta_chart_info = Some(ChartInfo::from_chart(&chart));
        }
        Ok(())
    }

    #[wasm_bindgen]
    /// Draws the packet sent plot into the provided canvas_id.
    pub fn draw_packet_sent_pacing_plot(
        &mut self, pkt_tx_pacing_canvas_id: &str, display_legend: bool,
        x_start: Option<f64>, x_end: Option<f64>,
    ) -> Result<(), JsValue> {
        if let Some(ss) = &self.ss {
            let params = PlotParameters {
                clamp: ClampParams {
                    start: x_start,
                    end: x_end,
                    stream_y_max: None,
                },
                cwnd_y_max: None,
                chart_size: ChartSize {
                    width: 1042,
                    height: 800,
                },
                colors: AppConfig::colors(false),
                chart_margin: CHART_MARGIN_TIGHT,
                area_margin: AreaMargin { x: 40, y: 80 },
                display_chart_title: false,
                display_legend,
                display_minor_lines: false,
            };

            self.pkt_tx_pacing_chart_info = None;
            let chart = plot_packet_sent_pacing_rate_plot_canvas(
                &params,
                ss,
                &self.ds,
                pkt_tx_pacing_canvas_id,
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))?;

            self.pkt_tx_pacing_chart_info = Some(ChartInfo::from_chart(&chart));
        }
        Ok(())
    }

    #[wasm_bindgen]
    /// Draws the stream multiplexing plot into the provided canvas_id.
    pub fn draw_stream_multiplexing(
        &mut self, canvas_id: &str,
    ) -> Result<(), JsValue> {
        if let Some(ss) = &self.ss {
            let multiplex_params = MultiplexPlotsParams {
                clamp: ClampParams {
                    start: None,
                    end: None,
                    stream_y_max: None,
                },
                colors: AppConfig::colors(false),
                ..Default::default()
            };

            let chart_type = ChartOutputType::Canvas {
                canvas_id: canvas_id.to_string(),
            };

            plot_stream_multiplexing(
                &multiplex_params,
                &self.display_name,
                ss,
                &self.ds,
                &chart_type,
            )
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        }
        Ok(())
    }

    #[wasm_bindgen]
    pub fn populate_event_table(
        &self, event_div_id: &str,
    ) -> Result<(), JsValue> {
        let window: Window = web_sys::window()
            .ok_or_else(|| JsValue::from_str("browser window unavailable"))?;
        let document: Document = window
            .document()
            .ok_or_else(|| JsValue::from_str("browser document unavailable"))?;
        let target_div: Element =
            document.get_element_by_id(event_div_id).ok_or_else(|| {
                JsValue::from_str(&format!(
                    "event table container {event_div_id:?} is missing"
                ))
            })?;

        let event_table = event_list_html_from_table(
            sqlog_event_list(self.sqlog_stream.events())
                .map_err(|error| JsValue::from_str(&error.to_string()))?,
        );
        target_div.set_inner_html(&event_table);
        Ok(())
    }

    #[wasm_bindgen]
    /// TODO: example of accessing richer data from a parsed log
    pub fn packet_sent(&self) -> Vec<Pointu64> {
        let v = vec![Pointu64 { x: 0.1, y: 1 }];
        v
    }
}
