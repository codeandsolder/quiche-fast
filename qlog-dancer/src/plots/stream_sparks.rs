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

//! Spark charts
//! These are a single image file containing a grid of mini plots. Each plot
//! represents a single stream, so it is easier to see how they all compare
//! at a glance.

use plotters::coord::ranged1d::ValueFormatter;
use plotters::coord::types::RangedCoordf64;
use plotters::coord::types::RangedCoordu64;
use plotters::drawing::DrawingAreaErrorKind;
use plotters::style::full_palette::PURPLE_500;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::ops::Range;

use tabled::Tabled;

use crate::datastore::ApplicationProto;
use crate::datastore::VantagePoint;
use crate::plots::chart_label_style;
use crate::plots::colors::PlotColors;
use crate::plots::colors::BROWN;
use crate::plots::colors::MUSTARD;
use crate::plots::colors::ORANGE;
use crate::plots::ChartConfig;
use crate::plots::ChartMargin;
use crate::plots::ChartOutputType;
use crate::plots::ChartSize;
use crate::plots::ClampParams;
use crate::request_stub::HttpRequestStub;
use plotters::prelude::Cartesian2d;
use plotters::prelude::ChartBuilder;
use plotters::prelude::ChartContext;
use plotters::prelude::Circle;
use plotters::prelude::DrawingArea;
use plotters::prelude::DrawingBackend;
use plotters::prelude::IntoTextStyle;
use plotters::prelude::LabelAreaPosition;
use plotters::prelude::LineSeries;
use plotters::prelude::PathElement;
use plotters::prelude::RGBColor;
use plotters::prelude::Ranged;
use plotters::prelude::TriangleMarker;
use plotters::prelude::CYAN;
use plotters::prelude::GREEN;
use plotters::prelude::MAGENTA;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

#[derive(Debug, Clone, Copy)]
struct SparkDirections<T> {
    download: T,
    upload: T,
}

#[derive(Debug, Clone, Copy)]
pub struct SparkPair<T> {
    pub absolute: T,
    pub relative: T,
}

/// Direction and time-domain are distinct: an upload-only stream has no
/// download data, but still occupies one cell in all four output charts.
#[derive(Debug, Clone, Copy)]
pub struct SparkOutputs<T> {
    pub download: SparkPair<T>,
    pub upload: SparkPair<T>,
}

impl<T: Clone> SparkOutputs<T> {
    /// Use one output type (typically a PNG directory) for all four charts.
    #[must_use = "the returned configuration applies the output to each plot"]
    pub fn all(output: T) -> Self {
        Self {
            download: SparkPair {
                absolute: output.clone(),
                relative: output.clone(),
            },
            upload: SparkPair {
                absolute: output.clone(),
                relative: output,
            },
        }
    }
}

impl<T> SparkOutputs<T> {
    fn map<U>(self, mut f: impl FnMut(T) -> U) -> SparkOutputs<U> {
        SparkOutputs {
            download: SparkPair {
                absolute: f(self.download.absolute),
                relative: f(self.download.relative),
            },
            upload: SparkPair {
                absolute: f(self.upload.absolute),
                relative: f(self.upload.relative),
            },
        }
    }

    /// Transform all four outputs in a stable order, stopping on the first
    /// backend error rather than continuing to initialize later outputs.
    fn try_map<U, E>(
        self, mut f: impl FnMut(T) -> Result<U, E>,
    ) -> Result<SparkOutputs<U>, E> {
        Ok(SparkOutputs {
            download: SparkPair {
                absolute: f(self.download.absolute)?,
                relative: f(self.download.relative)?,
            },
            upload: SparkPair {
                absolute: f(self.upload.absolute)?,
                relative: f(self.upload.relative)?,
            },
        })
    }

    pub(crate) const fn as_ref(&self) -> SparkOutputs<&T> {
        SparkOutputs {
            download: SparkPair {
                absolute: &self.download.absolute,
                relative: &self.download.relative,
            },
            upload: SparkPair {
                absolute: &self.upload.absolute,
                relative: &self.upload.relative,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransmissionType {
    Upload,
    Download,
}

#[derive(Debug)]
pub struct SparkPlotsParams {
    pub clamp: ClampParams,
    pub bidi_only: bool,
    pub label_area_width: u32,
    pub label_area_height: u32,
    pub caption_area_height: u32,
    pub caption_area_width: u32,
    pub spark_offset_x: u32,
    pub spark_offset_y: u32,
    pub spark_dimension_x: u32,
    pub spark_dimension_y: u32,
    pub sparks_per_row: u32,
    pub captions_on_top: bool,
    pub colors: PlotColors,
}

impl Default for SparkPlotsParams {
    fn default() -> Self {
        Self {
            clamp: ClampParams::default(),
            bidi_only: true,
            label_area_width: 20,
            label_area_height: 20,
            caption_area_height: 100,
            caption_area_width: 0,
            spark_offset_x: 50,
            spark_offset_y: 30,
            spark_dimension_x: 150,
            spark_dimension_y: 150,
            sparks_per_row: 10,
            captions_on_top: true,
            colors: PlotColors::default(),
        }
    }
}

#[derive(Tabled)]
enum SparkCaption {
    UniStream {
        summary: String,
    },

    RequestAtServer {
        summary: String,
        method: String,
        path: String,
        client_content_length: String,
        server_content_length: String,
        client_pri_hdr: String,
        server_pri_hdr: String,
        duration_rx_hdr_tx_hdr: String,
        duration_rx_hdr_tx_first_data: String,
        duration_rx_hdr_tx_last_data: String,
        duration_tx_first_data_tx_last_data: String,
    },

    RequestAtClient {
        summary: String,
        method: String,
        path: String,
        client_content_length: String,
        server_content_length: String,
        client_pri_hdr: String,
        client_pri_update: String,
        server_pri_hdr: String,
        duration_tx_hdr_rx_hdr: String,
        duration_tx_hdr_rx_first_data: String,
        duration_tx_hdr_rx_last_data: String,
        duration_tx_first_data_tx_last_data: String,
    },
}

type SparkDrawingResult<DB> =
    Result<(), DrawingAreaErrorKind<<DB as DrawingBackend>::ErrorType>>;

/// Retain any stream with recorded data in either direction. Both directions
/// occupy the *same* grid cell, even if only one side has data.
fn visible_stream_ids(
    download: &BTreeMap<u64, Vec<(f64, u64)>>,
    upload: &BTreeMap<u64, Vec<(f64, u64)>>, proto: ApplicationProto,
    bidi_only: bool,
) -> Vec<u64> {
    download
        .iter()
        .chain(upload)
        .filter(|(stream_id, points)| {
            !points.is_empty() &&
                (proto != ApplicationProto::Http3 ||
                    !bidi_only ||
                    (*stream_id & 2) == 0)
        })
        .map(|(stream_id, _)| *stream_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn invalid_plot_range(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason.to_string())
}

/// Bounds use every sample, not the first/last point (qlogs can arrive out
/// of order). All points and optional clamps must have finite timestamps.
fn time_range(
    points: impl IntoIterator<Item = f64>, start: Option<f64>, end: Option<f64>,
) -> io::Result<Range<f64>> {
    let mut bounds: Option<(f64, f64)> = None;
    for time in points {
        if !time.is_finite() {
            return Err(invalid_plot_range(
                "spark chart timestamps must be finite",
            ));
        }
        bounds = Some(match bounds {
            Some((low, high)) => (low.min(time), high.max(time)),
            None => (time, time),
        });
    }
    let (mut low, mut high) = bounds.unwrap_or((0.0, 1.0));
    if let Some(value) = start {
        low = value;
    }
    if let Some(value) = end {
        if !value.is_finite() {
            return Err(invalid_plot_range(
                "spark chart end clamp must be finite",
            ));
        }
        high = high.min(value);
    }
    if !low.is_finite() || !high.is_finite() || low > high {
        return Err(invalid_plot_range(
            "spark chart time range is nonfinite or reversed",
        ));
    }
    if low >= high {
        let padding = (low.abs() * f64::EPSILON * 64.0).max(1.0);
        let shifted_low = low - padding;
        let shifted_high = high + padding;
        if shifted_low.is_finite() && shifted_low < high {
            low = shifted_low;
        }
        if shifted_high.is_finite() && shifted_high > low {
            high = shifted_high;
        }
        if low >= high {
            low = low.next_down();
        }
    }
    if !low.is_finite() || !high.is_finite() || low >= high {
        return Err(invalid_plot_range(
            "spark chart time range cannot be represented",
        ));
    }
    Ok(low..high)
}

/// Avoid allocating for chronologically ordered traces; otherwise sort
/// stably before drawing so a line cannot travel backwards in time.
fn chronological(points: &[(f64, u64)]) -> Cow<'_, [(f64, u64)]> {
    if points.windows(2).all(|pair| pair[0].0 <= pair[1].0) {
        Cow::Borrowed(points)
    } else {
        let mut sorted = points.to_vec();
        sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
        Cow::Owned(sorted)
    }
}

fn stream_y_max(points: &[(f64, u64)], clamp: Option<u64>) -> io::Result<u64> {
    let value = clamp.unwrap_or_else(|| {
        points.iter().map(|point| point.1).max().unwrap_or(0).max(1)
    });
    if value == 0 {
        return Err(invalid_plot_range("spark chart y maximum must be nonzero"));
    }
    Ok(value)
}

/// Pixel coordinates are bounded by Plotters' signed coordinates. All layout
/// arithmetic is checked before constructing the rendering backends.
fn chart_coord(value: u64) -> io::Result<i32> {
    const RESERVE: u64 = 512; // legend, captions, and axis-label extents
    let max = i32::MAX as u64 - RESERVE;
    if value > max {
        return Err(invalid_plot_range(
            "spark chart pixel coordinates exceed i32",
        ));
    }
    i32::try_from(value)
        .map_err(|_| invalid_plot_range("invalid spark pixel coordinate"))
}

fn cell_origin(
    params: &SparkPlotsParams, slot: u32, width: u32, height: u32,
) -> io::Result<(u32, u32)> {
    let column = slot % params.sparks_per_row;
    let row = slot / params.sparks_per_row;
    let x =
        u64::from(params.spark_offset_x) + u64::from(column) * u64::from(width);
    let y = u64::from(params.spark_offset_y) + u64::from(row) * u64::from(height);
    chart_coord(x)?;
    chart_coord(y)?;
    let x = u32::try_from(x)
        .map_err(|_| invalid_plot_range("spark x coordinate overflow"))?;
    let y = u32::try_from(y)
        .map_err(|_| invalid_plot_range("spark y coordinate overflow"))?;
    Ok((x, y))
}

fn format_delta(value: Option<f64>, label: &str) -> String {
    value.map_or_else(String::new, |duration| format!("{label}{duration:.2}ms"))
}

impl SparkCaption {
    fn request_at_client_from_stub(
        application_proto: ApplicationProto, req: &HttpRequestStub,
    ) -> Self {
        let summary = format!(
            "ID= {}, status= {}, proto= {application_proto:?}",
            req.stream_id, req.status
        );
        let deltas = req.at_client_deltas.as_ref();
        let duration_tx_hdr_rx_hdr = format_delta(
            deltas.and_then(|value| value.tx_hdr_rx_hdr.inner),
            "d_tx_hdr_rx_hdr:               ",
        );
        let duration_tx_hdr_rx_first_data = format_delta(
            deltas.and_then(|value| value.tx_hdr_rx_first_data.inner),
            "d_tx_hdr_rx_data_first:        ",
        );
        let duration_tx_hdr_rx_last_data = format_delta(
            deltas.and_then(|value| value.tx_hdr_rx_last_data.inner),
            "d_tx_hdr_rx_data_last:         ",
        );
        let duration_tx_first_data_tx_last_data = format_delta(
            deltas.and_then(|value| value.tx_first_data_tx_last_data.inner),
            "d_tx_data_first_tx_data_last:  ",
        );

        Self::RequestAtClient {
            summary,
            method: format!("method= {}", req.method),
            path: format!("path= {}", req.path),

            client_content_length: format!(
                "client content length: {}",
                req.client_content_length
            ),
            server_content_length: format!(
                "server content length: {}",
                req.server_content_length
            ),

            client_pri_hdr: format!(
                "client pri hdr:         {}",
                req.client_pri_hdr
            ),

            client_pri_update: format!(
                "client pri updates:     {:?}",
                req.priority_updates
            ),

            server_pri_hdr: format!(
                "server pri hdr:         {}",
                req.server_pri_hdr
            ),

            duration_tx_hdr_rx_hdr,

            duration_tx_hdr_rx_first_data,

            duration_tx_hdr_rx_last_data,

            duration_tx_first_data_tx_last_data,
        }
    }

    fn request_at_server_from_stub(
        stream_id: u64, req: &HttpRequestStub,
    ) -> Self {
        let summary = format!("ID= {stream_id}, status= {}", req.status);
        let deltas = req.at_server_deltas.as_ref();
        let duration_rx_hdr_tx_hdr = format_delta(
            deltas.and_then(|value| value.rx_hdr_tx_hdr.inner),
            "d_rx_hdr_tx_hdr:               ",
        );
        let duration_rx_hdr_tx_first_data = format_delta(
            deltas.and_then(|value| value.rx_hdr_tx_first_data.inner),
            "d_rx_hdr_tx_data_first:        ",
        );
        let duration_rx_hdr_tx_last_data = format_delta(
            deltas.and_then(|value| value.rx_hdr_tx_last_data.inner),
            "d_rx_hdr_tx_data_last:         ",
        );
        let duration_tx_first_data_tx_last_data = format_delta(
            deltas.and_then(|value| value.tx_first_data_tx_last_data.inner),
            "d_tx_data_first_tx_data_last:  ",
        );

        Self::RequestAtServer {
            summary,
            method: format!("method= {}", req.method),
            path: format!("path= {}", req.path),

            client_content_length: format!(
                "client content length: {}",
                req.client_content_length
            ),
            server_content_length: format!(
                "server content length: {}",
                req.server_content_length
            ),

            client_pri_hdr: format!(
                "client pri hdr:         {}",
                req.client_pri_hdr
            ),

            server_pri_hdr: format!(
                "server pri hdr:         {}",
                req.server_pri_hdr
            ),

            duration_rx_hdr_tx_hdr,

            duration_rx_hdr_tx_first_data,

            duration_rx_hdr_tx_last_data,

            duration_tx_first_data_tx_last_data,
        }
    }

    fn from_data_store(ds: &Datastore, stream_id: u64) -> Option<Self> {
        let is_request = match ds.application_proto {
            ApplicationProto::Http3 => stream_id.is_multiple_of(4),
            ApplicationProto::Http2 => true,
        };

        if is_request {
            ds.http_requests
                .get(&stream_id)
                .map(|req| match ds.vantage_point {
                    VantagePoint::Client => Self::request_at_client_from_stub(
                        ds.application_proto,
                        req,
                    ),
                    VantagePoint::Server =>
                        Self::request_at_server_from_stub(stream_id, req),
                })
        } else {
            Some(Self::UniStream {
                summary: format!("ID= {stream_id}"),
            })
        }
    }

    /// Visit caption rows without allocating intermediate strings or lists.
    /// Server and client captions deliberately differ by one priority row.
    fn for_each_row<E>(
        &self, mut visitor: impl FnMut(i32, &str) -> Result<(), E>,
    ) -> Result<(), E> {
        match self {
            Self::UniStream { summary } => visitor(0, summary),
            Self::RequestAtServer {
                summary,
                method,
                path,
                client_content_length,
                server_content_length,
                client_pri_hdr,
                server_pri_hdr,
                duration_rx_hdr_tx_hdr,
                duration_rx_hdr_tx_first_data,
                duration_rx_hdr_tx_last_data,
                duration_tx_first_data_tx_last_data,
            } => {
                for (row, line) in [
                    (0, summary.as_str()),
                    (1, method),
                    (2, path),
                    (3, client_content_length),
                    (4, server_content_length),
                    (6, client_pri_hdr),
                    (7, server_pri_hdr),
                    (8, duration_rx_hdr_tx_hdr),
                    (9, duration_rx_hdr_tx_first_data),
                    (10, duration_rx_hdr_tx_last_data),
                    (11, duration_tx_first_data_tx_last_data),
                ] {
                    visitor(row, line)?;
                }
                Ok(())
            },
            Self::RequestAtClient {
                summary,
                method,
                path,
                client_content_length,
                server_content_length,
                client_pri_hdr,
                client_pri_update,
                server_pri_hdr,
                duration_tx_hdr_rx_hdr,
                duration_tx_hdr_rx_first_data,
                duration_tx_hdr_rx_last_data,
                duration_tx_first_data_tx_last_data,
            } => {
                for (row, line) in [
                    (0, summary.as_str()),
                    (1, method),
                    (2, path),
                    (3, client_content_length),
                    (4, server_content_length),
                    (6, client_pri_hdr),
                    (7, client_pri_update),
                    (8, server_pri_hdr),
                    (9, duration_tx_hdr_rx_hdr),
                    (10, duration_tx_hdr_rx_first_data),
                    (11, duration_tx_hdr_rx_last_data),
                    (12, duration_tx_first_data_tx_last_data),
                ] {
                    visitor(row, line)?;
                }
                Ok(())
            },
        }
    }

    fn draw<DB: DrawingBackend>(
        &self, color: RGBColor, root: &DrawingArea<DB, plotters::coord::Shift>,
        x: i32, y: i32,
    ) -> SparkDrawingResult<DB> {
        let style = ("monospace", 12).into_text_style(root).color(&color);
        self.for_each_row(|row, line| {
            root.draw_text(line, &style, (x + 20, y + row * 10))
        })
    }
}

/// Keep the legend faithful to what the corresponding panel can draw.
/// Download panes show buffered data and request timing markers; upload
/// panes show STREAM frames, a stream limit and possibly HTTP/2 send credit.
/// The fixed-size array avoids a heap allocation even with optional entries.
#[must_use = "the returned entries describe the available plot series"]
const fn spark_legend_entries(
    transmission_type: TransmissionType, vantage: VantagePoint,
    proto: ApplicationProto,
) -> [Option<(&'static str, RGBColor)>; 6] {
    let stream_limit = match (vantage, transmission_type) {
        (VantagePoint::Client, TransmissionType::Download) |
        (VantagePoint::Server, TransmissionType::Upload) =>
            "Max stream data sent",
        (VantagePoint::Client, TransmissionType::Upload) |
        (VantagePoint::Server, TransmissionType::Download) =>
            "Max stream data received",
    };
    match transmission_type {
        TransmissionType::Download => {
            let (first_data, last_data) = match vantage {
                VantagePoint::Client =>
                    ("First data frame read", "Last data frame read"),
                VantagePoint::Server =>
                    ("First data frame sent", "Last data frame sent"),
            };
            [
                Some(("Stream data read", PURPLE_500)),
                Some(("Stream data buffered", MAGENTA)),
                Some((stream_limit, MUSTARD)),
                Some(("Request headers sent", CYAN)),
                Some((first_data, ORANGE)),
                Some((last_data, BROWN)),
            ]
        },
        TransmissionType::Upload => {
            let window = match proto {
                ApplicationProto::Http2 => Some(("HTTP/2 send window", ORANGE)),
                ApplicationProto::Http3 => None,
            };
            [
                Some(("Stream data sent", PURPLE_500)),
                Some((stream_limit, MUSTARD)),
                window,
                None,
                None,
                None,
            ]
        },
    }
}

fn plot_legend<DB: DrawingBackend>(
    color: RGBColor, root: &DrawingArea<DB, plotters::coord::Shift>, x: i32,
    y: i32, transmission_type: TransmissionType, vantage: VantagePoint,
    proto: ApplicationProto,
) -> SparkDrawingResult<DB> {
    const LINE_LEN: i32 = 50;
    const ROW_HEIGHT: i32 = 20;
    let style = ("monospace", 12).into_text_style(root).color(&color);
    root.draw_text("Legend", &style, (x, y))?;

    for (row, (label, marker_color)) in (1_i32..).zip(
        spark_legend_entries(transmission_type, vantage, proto)
            .into_iter()
            .flatten(),
    ) {
        let line_y = y + row * ROW_HEIGHT;
        root.draw(&PathElement::new(
            [(x, line_y), (x + LINE_LEN, line_y)],
            marker_color,
        ))?;
        root.draw_text(label, &style, (x + LINE_LEN + 10, line_y - 5))?;
    }
    Ok(())
}

type SparkRoot<DB> = DrawingArea<DB, plotters::coord::Shift>;
type StreamChart<'a, DB> =
    ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>;
type FrameSeries = BTreeMap<u64, Vec<(f64, u64)>>;

/// All four panels use the same checked grid. Reserve a separate legend band
/// instead of drawing the legend over stream cells.
struct SparkLayout {
    size: ChartSize,
    column_width: u32,
    row_height: u32,
    caption_height: u32,
    legend_height: u32,
}

impl SparkLayout {
    fn new(params: &SparkPlotsParams, stream_count: usize) -> io::Result<Self> {
        const CAPTION_MIN_HEIGHT: u32 = 140;
        const LEGEND_HEIGHT: u32 = 160;
        if params.sparks_per_row == 0 ||
            params.spark_dimension_x == 0 ||
            params.spark_dimension_y == 0
        {
            return Err(invalid_plot_range(
                "spark grid and plot dimensions must be nonzero",
            ));
        }
        let overflow = || invalid_plot_range("spark chart dimensions overflow");
        let caption_height = if params.captions_on_top {
            params.caption_area_height.max(CAPTION_MIN_HEIGHT)
        } else {
            0
        };
        let caption_width = if params.captions_on_top {
            0
        } else {
            params.caption_area_width
        };
        let column_width = params
            .spark_dimension_x
            .checked_add(params.spark_offset_x)
            .and_then(|width| width.checked_add(caption_width))
            .ok_or_else(overflow)?;
        let content_height = params
            .spark_dimension_y
            .checked_add(params.label_area_height)
            .and_then(|height| height.checked_add(caption_height))
            .ok_or_else(overflow)?;
        let row_height = content_height
            .max(CAPTION_MIN_HEIGHT)
            .checked_add(params.spark_offset_y)
            .ok_or_else(overflow)?;
        let total_rows = u32::try_from(stream_count)
            .map_err(|_| overflow())?
            .div_ceil(params.sparks_per_row)
            .max(1);
        let width = params
            .sparks_per_row
            .checked_mul(column_width)
            .and_then(|width| width.checked_add(params.spark_offset_x))
            .ok_or_else(overflow)?
            .max(360);
        let height = total_rows
            .checked_mul(row_height)
            .and_then(|height| height.checked_add(LEGEND_HEIGHT))
            .ok_or_else(overflow)?;
        chart_coord(u64::from(width))?;
        chart_coord(u64::from(height))?;
        Ok(Self {
            size: ChartSize { width, height },
            column_width,
            row_height,
            caption_height,
            legend_height: LEGEND_HEIGHT,
        })
    }

    fn cell(
        &self, params: &SparkPlotsParams, slot: u32,
    ) -> io::Result<(u32, u32)> {
        let (x, y) =
            cell_origin(params, slot, self.column_width, self.row_height)?;
        let y = y
            .checked_add(self.legend_height)
            .ok_or_else(|| invalid_plot_range("spark cell origin overflow"))?;
        Ok((x, y))
    }
}

#[cfg(target_arch = "wasm32")]
fn spark_canvas_area(
    config: &ChartConfig, size: ChartSize, colors: PlotColors,
) -> Result<SparkRoot<plotters_canvas::CanvasBackend>, Box<dyn Error>> {
    use wasm_bindgen::JsCast;
    let canvas_id = config.canvas_id().ok_or_else(|| {
        invalid_plot_range("spark chart requires a canvas output")
    })?;
    let canvas = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(&canvas_id))
        .and_then(|element| element.dyn_into::<web_sys::HtmlCanvasElement>().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("spark canvas {canvas_id:?} not found"),
            )
        })?;
    canvas.set_width(size.width);
    canvas.set_height(size.height);
    super::fallible::canvas_area(&canvas_id, colors, ChartMargin::default())
}

/// Pick the data direction by transport and capture vantage, independently
/// of the output chart's absolute/relative time coordinate system.
const fn frame_series_for_vantage<'a>(
    ss: &'a SeriesStore, ds: &Datastore,
) -> SparkDirections<&'a FrameSeries> {
    let (download, upload) = match (ds.application_proto, ds.vantage_point) {
        (ApplicationProto::Http3, VantagePoint::Client) => (
            &ss.received_stream_frames_series,
            &ss.sent_stream_frames_series,
        ),
        (ApplicationProto::Http3, VantagePoint::Server) => (
            &ss.sent_stream_frames_series,
            &ss.received_stream_frames_series,
        ),
        (ApplicationProto::Http2, VantagePoint::Client) =>
            (&ss.received_data_frames_series, &ss.sent_data_frames_series),
        (ApplicationProto::Http2, VantagePoint::Server) =>
            (&ss.sent_data_frames_series, &ss.received_data_frames_series),
    };
    SparkDirections { download, upload }
}

struct SparkModel<'a> {
    layout: SparkLayout,
    frames: SparkDirections<&'a FrameSeries>,
    streams: Vec<u64>,
    absolute_range: Range<f64>,
}

impl<'a> SparkModel<'a> {
    fn new(
        params: &SparkPlotsParams, ss: &'a SeriesStore, ds: &Datastore,
    ) -> io::Result<Self> {
        let frames = frame_series_for_vantage(ss, ds);
        let streams = visible_stream_ids(
            frames.download,
            frames.upload,
            ds.application_proto,
            params.bidi_only,
        );
        let layout = SparkLayout::new(params, streams.len())?;
        let absolute_range = time_range(
            streams.iter().flat_map(|id| {
                frames
                    .download
                    .get(id)
                    .into_iter()
                    .chain(frames.upload.get(id))
                    .flat_map(|series| series.iter().map(|point| point.0))
            }),
            params.clamp.start,
            params.clamp.end,
        )?;
        Ok(Self {
            layout,
            frames,
            streams,
            absolute_range,
        })
    }
}

fn spark_configs(
    params: &SparkPlotsParams, filename: &str, ds: &Datastore,
    outputs: SparkOutputs<&ChartOutputType>,
) -> SparkOutputs<ChartConfig> {
    let config = |name, output| {
        ChartConfig::new(name, filename, &params.clamp, ds, output)
    };
    SparkOutputs {
        download: SparkPair {
            absolute: config(
                "stream-spark-dl-absolute",
                outputs.download.absolute,
            ),
            relative: config(
                "stream-spark-dl-relative",
                outputs.download.relative,
            ),
        },
        upload: SparkPair {
            absolute: config("stream-spark-ul-absolute", outputs.upload.absolute),
            relative: config("stream-spark-ul-relative", outputs.upload.relative),
        },
    }
}

/// Renders stream spark charts for the supported application protocols and
/// vantages.
/// # Errors
/// Returns an error on invalid layout sizes, output-directory/PNG I/O failures,
/// missing canvases, or drawing backend failures.
pub fn plot_sparks(
    params: &SparkPlotsParams, filename: &str, ss: &SeriesStore, ds: &Datastore,
    outputs: SparkOutputs<&ChartOutputType>,
) -> Result<(), Box<dyn Error>> {
    let model = SparkModel::new(params, ss, ds)?;
    let configs = spark_configs(params, filename, ds, outputs);
    #[cfg(not(target_arch = "wasm32"))]
    let paths = configs.as_ref().try_map(|config| {
        if !matches!(config.ty, ChartOutputType::Png { .. }) {
            return Err(invalid_plot_range("spark chart requires a PNG output"));
        }
        Ok(config.chart_filepath())
    })?;
    #[cfg(not(target_arch = "wasm32"))]
    let roots = paths.as_ref().try_map(|path| {
        super::fallible::bitmap_area(
            path,
            model.layout.size,
            params.colors,
            ChartMargin::default(),
        )
    })?;
    #[cfg(target_arch = "wasm32")]
    let roots = configs.as_ref().try_map(|config| {
        spark_canvas_area(config, model.layout.size, params.colors)
    })?;
    draw_sparks(&roots, params, &model, ss, ds)
}

fn draw_sparks<DB: DrawingBackend>(
    roots: &SparkOutputs<SparkRoot<DB>>, params: &SparkPlotsParams,
    model: &SparkModel<'_>, ss: &SeriesStore, ds: &Datastore,
) -> Result<(), Box<dyn Error>>
where
    DB::ErrorType: 'static,
{
    for (root, transmission) in [
        (&roots.download.absolute, TransmissionType::Download),
        (&roots.download.relative, TransmissionType::Download),
        (&roots.upload.absolute, TransmissionType::Upload),
        (&roots.upload.relative, TransmissionType::Upload),
    ] {
        plot_legend(
            params.colors.caption,
            root,
            20,
            10,
            transmission,
            ds.vantage_point,
            ds.application_proto,
        )?;
    }
    for (slot, stream_id) in model.streams.iter().copied().enumerate() {
        let cell = SparkCell {
            params,
            model,
            ss,
            ds,
            stream_id,
        };
        cell.draw(roots, u32::try_from(slot)?)?;
    }
    roots.as_ref().try_map(DrawingArea::present)?;
    Ok(())
}

fn build_stream_chart<'a, DB: DrawingBackend>(
    root: &SparkRoot<DB>, params: &SparkPlotsParams, range: Range<f64>,
    y_max: u64, secondary: bool,
) -> Result<StreamChart<'a, DB>, DrawingAreaErrorKind<DB::ErrorType>> {
    let mut builder = ChartBuilder::on(root);
    builder
        .set_label_area_size(LabelAreaPosition::Left, params.label_area_width)
        .set_label_area_size(LabelAreaPosition::Bottom, params.label_area_height);
    if secondary {
        builder.right_y_label_area_size(params.label_area_width);
    }
    let mut chart = builder.build_cartesian_2d(range, 0..y_max)?;
    draw_mesh(&params.colors, &mut chart)?;
    Ok(chart)
}

struct SparkCell<'a> {
    params: &'a SparkPlotsParams,
    model: &'a SparkModel<'a>,
    ss: &'a SeriesStore,
    ds: &'a Datastore,
    stream_id: u64,
}

impl SparkCell<'_> {
    fn draw<DB: DrawingBackend>(
        &self, roots: &SparkOutputs<SparkRoot<DB>>, slot: u32,
    ) -> Result<(), Box<dyn Error>>
    where
        DB::ErrorType: 'static,
    {
        let (x, y) = self.model.layout.cell(self.params, slot)?;
        let plot_y =
            y.checked_add(self.model.layout.caption_height)
                .ok_or_else(|| {
                    invalid_plot_range("spark chart row origin overflow")
                })?;
        let areas = roots.as_ref().map(|root| {
            root.clone().shrink(
                (x, plot_y),
                (self.params.spark_dimension_x, self.params.spark_dimension_y),
            )
        });
        let download = self
            .model
            .frames
            .download
            .get(&self.stream_id)
            .map_or(&[][..], Vec::as_slice);
        let upload = self
            .model
            .frames
            .upload
            .get(&self.stream_id)
            .map_or(&[][..], Vec::as_slice);
        let caption_offset = if self.params.captions_on_top {
            0
        } else {
            u64::from(self.params.spark_dimension_x)
        };
        draw_captions(
            roots,
            self.params,
            self.ds,
            self.stream_id,
            !upload.is_empty(),
            chart_coord(u64::from(x) + caption_offset)?,
            chart_coord(u64::from(y))?,
        )?;
        self.draw_download(&areas.download, download)?;
        if !upload.is_empty() {
            self.draw_upload(&areas.upload, upload)?;
        }
        Ok(())
    }

    fn draw_download<DB: DrawingBackend>(
        &self, areas: &SparkPair<SparkRoot<DB>>, frames: &[(f64, u64)],
    ) -> Result<(), Box<dyn Error>>
    where
        DB::ErrorType: 'static,
    {
        let y_max = stream_y_max(frames, self.params.clamp.stream_y_max)?;
        let mut absolute = build_stream_chart(
            &areas.absolute,
            self.params,
            self.model.absolute_range.clone(),
            y_max,
            false,
        )?;
        let mut relative = build_stream_chart(
            &areas.relative,
            self.params,
            time_range(frames.iter().map(|point| point.0), None, None)?,
            y_max,
            false,
        )?;
        draw_stream_frames_line(frames, &mut absolute, &mut relative)?;
        draw_buffered_data_line(
            self.stream_id,
            self.ss,
            self.ds.vantage_point,
            &mut absolute,
            &mut relative,
        )?;
        draw_stream_max_line(
            self.stream_id,
            self.ss,
            self.ds.vantage_point,
            TransmissionType::Download,
            &mut absolute,
            &mut relative,
        )?;
        draw_request_timing_lines(
            self.ds,
            self.stream_id,
            y_max,
            &mut absolute,
            &mut relative,
        )?;
        Ok(())
    }

    fn draw_upload<DB: DrawingBackend>(
        &self, areas: &SparkPair<SparkRoot<DB>>, frames: &[(f64, u64)],
    ) -> Result<(), Box<dyn Error>>
    where
        DB::ErrorType: 'static,
    {
        let relative_range =
            time_range(frames.iter().map(|point| point.0), None, None)?;
        let absolute_range = self.model.absolute_range.clone();
        let y_max = stream_y_max(frames, self.params.clamp.stream_y_max)?;
        let h2_window = (self.ds.application_proto == ApplicationProto::Http2)
            .then(|| u32::try_from(self.stream_id).ok())
            .flatten()
            .and_then(|id| self.ss.h2_send_window_series_balanced.get(&id));
        let mut absolute = build_stream_chart(
            &areas.absolute,
            self.params,
            absolute_range.clone(),
            y_max,
            h2_window.is_some(),
        )?;
        let mut relative = build_stream_chart(
            &areas.relative,
            self.params,
            relative_range.clone(),
            y_max,
            h2_window.is_some(),
        )?;
        if let Some(window) = h2_window {
            // Derive the secondary range from actual samples, including
            // negative credit. Include zero and avoid a degenerate range.
            let (low, high) = window
                .iter()
                .fold((0_i64, 0_i64), |(low, high), &(_, value)| {
                    (low.min(value), high.max(value))
                });
            let high = if low == high { 1 } else { high };
            let mut abs = absolute.set_secondary_coord(absolute_range, low..high);
            let mut rel = relative.set_secondary_coord(relative_range, low..high);
            abs.configure_secondary_axes().draw()?;
            rel.configure_secondary_axes().y_labels(5).draw()?;
            abs.draw_secondary_series(LineSeries::new(
                window.iter().copied(),
                ORANGE,
            ))?;
            rel.draw_secondary_series(LineSeries::new(
                window.iter().copied(),
                ORANGE,
            ))?;
            draw_stream_frames_line(frames, &mut abs, &mut rel)?;
        } else {
            draw_stream_max_line(
                self.stream_id,
                self.ss,
                self.ds.vantage_point,
                TransmissionType::Upload,
                &mut absolute,
                &mut relative,
            )?;
            draw_stream_frames_line(frames, &mut absolute, &mut relative)?;
        }
        Ok(())
    }
}

fn draw_mesh<XT, YT, X, Y, DB: DrawingBackend>(
    colors: &PlotColors, chart: &mut ChartContext<DB, Cartesian2d<X, Y>>,
) -> SparkDrawingResult<DB>
where
    X: Ranged<ValueType = XT> + ValueFormatter<XT>,
    Y: Ranged<ValueType = YT> + ValueFormatter<YT>,
{
    chart
        .configure_mesh()
        .disable_mesh()
        .x_labels(5)
        .y_labels(5)
        .axis_style(colors.axis)
        .label_style(chart_label_style(&colors.caption))
        .draw()?;
    Ok(())
}

fn draw_captions<DB: DrawingBackend>(
    roots: &SparkOutputs<DrawingArea<DB, plotters::coord::Shift>>,
    params: &SparkPlotsParams, ds: &Datastore, stream_id: u64, upload_data: bool,
    caption_x: i32, caption_y: i32,
) -> SparkDrawingResult<DB> {
    if let Some(caption) = SparkCaption::from_data_store(ds, stream_id) {
        for root in [&roots.download.absolute, &roots.download.relative] {
            caption.draw(params.colors.caption, root, caption_x, caption_y)?;
        }
        if upload_data {
            for root in [&roots.upload.absolute, &roots.upload.relative] {
                caption.draw(
                    params.colors.caption,
                    root,
                    caption_x,
                    caption_y,
                )?;
            }
        }
    }
    Ok(())
}

fn draw_stream_frames_line<DB: DrawingBackend>(
    stream_frames: &[(f64, u64)],
    abs_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    rel_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> SparkDrawingResult<DB> {
    let points = chronological(stream_frames);
    abs_chart.draw_series(LineSeries::new(points.iter().copied(), PURPLE_500))?;

    rel_chart.draw_series(LineSeries::new(points.iter().copied(), PURPLE_500))?;

    rel_chart.draw_series(
        points
            .iter()
            .copied()
            .map(|point| Circle::new(point, 2, PURPLE_500)),
    )?;
    Ok(())
}

fn draw_buffered_data_line<DB: DrawingBackend>(
    stream_id: u64, ss: &SeriesStore, vantage_point: VantagePoint,
    abs_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    rel_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> SparkDrawingResult<DB> {
    let buffered_data_to_plot = match vantage_point {
        VantagePoint::Client => ss.stream_buffer_reads.get(&stream_id),
        VantagePoint::Server => ss.stream_buffer_writes.get(&stream_id),
    };

    if let Some(buffered_data) = buffered_data_to_plot {
        let points = chronological(buffered_data);
        abs_chart
            .draw_series(LineSeries::new(points.iter().copied(), MAGENTA))?;

        rel_chart
            .draw_series(LineSeries::new(points.iter().copied(), MAGENTA))?;

        rel_chart.draw_series(
            points
                .iter()
                .map(|point| TriangleMarker::new(*point, 3, MAGENTA)),
        )?;
    }
    Ok(())
}

/// The peer's `MAX_STREAM_DATA` limits are sourced from the opposite direction
/// at each capture vantage. Do not confuse transport RX/TX with spark DL/UL.
fn stream_max_series(
    ss: &SeriesStore, stream_id: u64, vantage_point: VantagePoint,
    transmission_type: TransmissionType,
) -> Option<&[(f64, u64)]> {
    match (vantage_point, transmission_type) {
        (VantagePoint::Client, TransmissionType::Download) |
        (VantagePoint::Server, TransmissionType::Upload) =>
            ss.sent_stream_max_data.get(&stream_id),
        (VantagePoint::Client, TransmissionType::Upload) |
        (VantagePoint::Server, TransmissionType::Download) =>
            ss.received_stream_max_data.get(&stream_id),
    }
    .map(Vec::as_slice)
}

fn draw_stream_max_line<DB: DrawingBackend>(
    stream_id: u64, ss: &SeriesStore, vantage_point: VantagePoint,
    transmission_type: TransmissionType,
    abs_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    rel_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> SparkDrawingResult<DB> {
    let stream_max_data_to_plot =
        stream_max_series(ss, stream_id, vantage_point, transmission_type);

    if let Some(stream_max_data) = stream_max_data_to_plot {
        let points = chronological(stream_max_data);
        abs_chart
            .draw_series(LineSeries::new(points.iter().copied(), MUSTARD))?;

        rel_chart
            .draw_series(LineSeries::new(points.iter().copied(), MUSTARD))?;
    }
    Ok(())
}

fn draw_request_timing_lines<DB: DrawingBackend>(
    ds: &Datastore, stream_id: u64, y_max: u64,
    abs_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    rel_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> SparkDrawingResult<DB> {
    if let Some(req) = ds.http_requests.get(&stream_id) {
        if let Some(h) = req.time_first_headers_rx {
            abs_chart
                .draw_series(LineSeries::new([(h, 0), (h, y_max)], GREEN))?;

            // don't care about rx events on the relative spark chart
        }

        if let Some(h) = req.time_first_headers_tx {
            let points = [(h, 0), (h, y_max)];
            abs_chart.draw_series(LineSeries::new(points, CYAN))?;
            rel_chart.draw_series(LineSeries::new(points, CYAN))?;
        }

        let (first_data_to_plot, last_data_to_plot) = match ds.vantage_point {
            VantagePoint::Client =>
                (req.time_first_data_rx, req.time_last_data_rx),
            VantagePoint::Server =>
                (req.time_first_data_tx, req.time_last_data_tx),
        };

        if let Some(t) = first_data_to_plot {
            let points = [(t, 0), (t, y_max)];
            abs_chart.draw_series(LineSeries::new(points, ORANGE))?;
            rel_chart.draw_series(LineSeries::new(points, ORANGE))?;
        }

        if let Some(t) = last_data_to_plot {
            let points = [(t, 0), (t, y_max)];
            abs_chart.draw_series(LineSeries::new(points, BROWN))?;
            rel_chart.draw_series(LineSeries::new(points, BROWN))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::cell_origin;
    use super::format_delta;
    use super::plot_sparks;
    use super::spark_legend_entries;
    use super::stream_max_series;
    use super::stream_y_max;
    use super::time_range;
    use super::visible_stream_ids;
    use super::SparkCaption;
    use super::SparkPlotsParams;
    use super::TransmissionType;
    use super::BROWN;
    use super::MUSTARD;
    use super::ORANGE;
    use super::PURPLE_500;
    use crate::datastore::ApplicationProto;
    use crate::datastore::Datastore;
    use crate::datastore::VantagePoint;
    use crate::plots::ChartOutputType;
    use crate::request_stub::HttpRequestStub;
    use crate::seriesstore::SeriesStore;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    struct OutputDir(PathBuf);

    impl OutputDir {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let nonce = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let timestamp =
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir().join(format!(
                "qlog-spark-render-{}-{timestamp}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir(&path)?;
            Ok(Self(path))
        }

        fn png(&self) -> ChartOutputType {
            ChartOutputType::Png {
                output_dir: self.0.to_string_lossy().into_owned(),
                cwnd_y_max: None,
                stream_y_max: None,
            }
        }
    }

    impl Drop for OutputDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn render(
        params: &SparkPlotsParams, series: &SeriesStore, datastore: &Datastore,
        output: &ChartOutputType,
    ) -> Result<(), Box<dyn std::error::Error>> {
        plot_sparks(
            params,
            "spark-regression",
            series,
            datastore,
            super::SparkOutputs::all(output),
        )
    }

    #[test]
    fn caption_rows_preserve_client_server_offsets_and_propagate_errors() {
        let request = HttpRequestStub::default();
        let cases = [
            (
                SparkCaption::request_at_client_from_stub(
                    ApplicationProto::Http3,
                    &request,
                ),
                vec![0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12],
            ),
            (
                SparkCaption::request_at_server_from_stub(0, &request),
                vec![0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11],
            ),
            (
                SparkCaption::UniStream {
                    summary: "stream".to_string(),
                },
                vec![0],
            ),
        ];

        for (caption, expected_rows) in cases {
            let mut visited = Vec::new();
            let result = caption.for_each_row(|row, text| {
                visited.push((row, text.to_owned()));
                Ok::<(), std::convert::Infallible>(())
            });
            assert!(result.is_ok());
            assert_eq!(
                visited.iter().map(|(row, _)| *row).collect::<Vec<_>>(),
                expected_rows,
            );
            if expected_rows.len() == 12 {
                assert!(visited.iter().any(|(row, text)| {
                    *row == 7 && text.starts_with("client pri updates:")
                }));
            } else if expected_rows.len() == 11 {
                assert!(visited.iter().any(|(row, text)| {
                    *row == 7 && text.starts_with("server pri hdr:")
                }));
            }
        }

        let caption = SparkCaption::request_at_server_from_stub(0, &request);
        let result =
            caption.for_each_row(|row, _| if row == 7 { Err(7) } else { Ok(()) });
        assert_eq!(result, Err(7));
    }

    #[test]
    fn captions_tolerate_absent_timing_data(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let req = HttpRequestStub::default();
        if let SparkCaption::RequestAtClient {
            duration_tx_hdr_rx_hdr,
            duration_tx_hdr_rx_first_data,
            duration_tx_hdr_rx_last_data,
            duration_tx_first_data_tx_last_data,
            ..
        } = SparkCaption::request_at_client_from_stub(
            ApplicationProto::Http3,
            &req,
        ) {
            assert_eq!(duration_tx_hdr_rx_hdr, "");
            assert_eq!(duration_tx_hdr_rx_first_data, "");
            assert_eq!(duration_tx_hdr_rx_last_data, "");
            assert_eq!(duration_tx_first_data_tx_last_data, "");
        } else {
            return Err("client request must produce a client caption".into());
        }

        if let SparkCaption::RequestAtServer {
            duration_rx_hdr_tx_hdr,
            duration_rx_hdr_tx_first_data,
            duration_rx_hdr_tx_last_data,
            duration_tx_first_data_tx_last_data,
            ..
        } = SparkCaption::request_at_server_from_stub(4, &req)
        {
            assert_eq!(duration_rx_hdr_tx_hdr, "");
            assert_eq!(duration_rx_hdr_tx_first_data, "");
            assert_eq!(duration_rx_hdr_tx_last_data, "");
            assert_eq!(duration_tx_first_data_tx_last_data, "");
        } else {
            return Err("server request must produce a server caption".into());
        }
        assert_eq!(format_delta(Some(12.345), "duration="), "duration=12.35ms");
        Ok(())
    }

    #[test]
    fn invalid_layouts_are_errors_instead_of_panics() {
        let series = SeriesStore::default();
        let datastore = Datastore::default();
        let output = ChartOutputType::Canvas {
            canvas_id: String::new(),
        };
        for params in [
            SparkPlotsParams {
                sparks_per_row: 0,
                ..Default::default()
            },
            SparkPlotsParams {
                spark_dimension_x: 0,
                ..Default::default()
            },
            SparkPlotsParams {
                spark_dimension_y: 0,
                ..Default::default()
            },
            SparkPlotsParams {
                sparks_per_row: u32::MAX,
                ..Default::default()
            },
            SparkPlotsParams {
                spark_offset_x: i32::MAX as u32,
                ..Default::default()
            },
            SparkPlotsParams {
                spark_dimension_x: i32::MAX as u32,
                ..Default::default()
            },
        ] {
            assert!(render(&params, &series, &datastore, &output).is_err());
        }
    }

    #[test]
    fn frame_series_selection_preserves_transport_and_vantage() {
        let mut series = SeriesStore::default();
        series
            .received_stream_frames_series
            .insert(0, vec![(1.0, 11)]);
        series.sent_stream_frames_series.insert(0, vec![(2.0, 22)]);
        series
            .received_data_frames_series
            .insert(0, vec![(3.0, 33)]);
        series.sent_data_frames_series.insert(0, vec![(4.0, 44)]);

        for (protocol, vantage, expected_download, expected_upload) in [
            (ApplicationProto::Http3, VantagePoint::Client, 11, 22),
            (ApplicationProto::Http3, VantagePoint::Server, 22, 11),
            (ApplicationProto::Http2, VantagePoint::Client, 33, 44),
            (ApplicationProto::Http2, VantagePoint::Server, 44, 33),
        ] {
            let datastore = Datastore {
                application_proto: protocol,
                vantage_point: vantage,
                ..Datastore::default()
            };
            let selected = super::frame_series_for_vantage(&series, &datastore);
            assert_eq!(
                selected.download.get(&0).map(|points| points[0].1),
                Some(expected_download),
            );
            assert_eq!(
                selected.upload.get(&0).map(|points| points[0].1),
                Some(expected_upload),
            );
        }
    }

    #[test]
    fn spark_output_coordinates_are_not_interchanged() {
        let outputs = super::SparkOutputs {
            download: super::SparkPair {
                absolute: "download-absolute",
                relative: "download-relative",
            },
            upload: super::SparkPair {
                absolute: "upload-absolute",
                relative: "upload-relative",
            },
        };
        let mut visited = Vec::new();
        let mapped = outputs.map(|name| {
            visited.push(name);
            name.len()
        });
        assert_eq!(visited, [
            "download-absolute",
            "download-relative",
            "upload-absolute",
            "upload-relative",
        ]);
        assert_eq!(mapped.download.absolute, "download-absolute".len());
        assert_eq!(mapped.download.relative, "download-relative".len());
        assert_eq!(mapped.upload.absolute, "upload-absolute".len());
        assert_eq!(mapped.upload.relative, "upload-relative".len());
    }

    #[test]
    fn spark_output_initialization_is_ordered_and_short_circuits_on_error(
    ) -> Result<(), &'static str> {
        let outputs = super::SparkOutputs {
            download: super::SparkPair {
                absolute: 1_u8,
                relative: 2,
            },
            upload: super::SparkPair {
                absolute: 3,
                relative: 4,
            },
        };
        let mapped = outputs.try_map(|value| Ok::<u8, &'static str>(value * 2));
        let mapped = mapped?;
        assert_eq!(mapped.download.absolute, 2);
        assert_eq!(mapped.download.relative, 4);
        assert_eq!(mapped.upload.absolute, 6);
        assert_eq!(mapped.upload.relative, 8);

        let mut visited = Vec::new();
        let failed = outputs.try_map(|value| {
            visited.push(value);
            if value == 3 {
                Err("backend initialization failed")
            } else {
                Ok(value)
            }
        });
        assert!(matches!(failed, Err("backend initialization failed")));
        assert_eq!(visited, [1, 2, 3]);
        Ok(())
    }

    #[test]
    fn spark_legend_matches_direction_vantage_and_protocol() {
        let entries = |direction, vantage, proto| {
            spark_legend_entries(direction, vantage, proto)
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
        };
        let client_dl = entries(
            TransmissionType::Download,
            VantagePoint::Client,
            ApplicationProto::Http3,
        );
        assert_eq!(client_dl.len(), 6);
        assert_eq!(client_dl[0], ("Stream data read", PURPLE_500));
        assert_eq!(client_dl[2], ("Max stream data sent", MUSTARD));
        assert_eq!(client_dl[4], ("First data frame read", ORANGE));
        assert_eq!(client_dl[5], ("Last data frame read", BROWN));

        let server_dl = entries(
            TransmissionType::Download,
            VantagePoint::Server,
            ApplicationProto::Http3,
        );
        assert_eq!(server_dl[2], ("Max stream data received", MUSTARD));
        assert_eq!(server_dl[4], ("First data frame sent", ORANGE));
        assert_eq!(server_dl[5], ("Last data frame sent", BROWN));

        let client_ul = entries(
            TransmissionType::Upload,
            VantagePoint::Client,
            ApplicationProto::Http3,
        );
        assert_eq!(client_ul, [
            ("Stream data sent", PURPLE_500),
            ("Max stream data received", MUSTARD),
        ]);
        let server_ul = entries(
            TransmissionType::Upload,
            VantagePoint::Server,
            ApplicationProto::Http3,
        );
        assert_eq!(server_ul[1], ("Max stream data sent", MUSTARD));
        let http2_upload = entries(
            TransmissionType::Upload,
            VantagePoint::Client,
            ApplicationProto::Http2,
        );
        assert_eq!(http2_upload.len(), 3);
        assert_eq!(http2_upload[2], ("HTTP/2 send window", ORANGE));
    }

    #[test]
    fn stream_max_series_respects_vantage_and_direction() {
        let mut ss = SeriesStore::default();
        ss.sent_stream_max_data.insert(4, vec![(1.0, 123)]);
        ss.received_stream_max_data.insert(4, vec![(2.0, 456)]);
        for (vantage, direction, expected) in [
            (VantagePoint::Client, TransmissionType::Download, 123),
            (VantagePoint::Server, TransmissionType::Upload, 123),
            (VantagePoint::Client, TransmissionType::Upload, 456),
            (VantagePoint::Server, TransmissionType::Download, 456),
        ] {
            assert_eq!(
                stream_max_series(&ss, 4, vantage, direction),
                Some(&[(if expected == 123 { 1.0 } else { 2.0 }, expected)][..])
            );
            assert_eq!(stream_max_series(&ss, 8, vantage, direction), None);
        }
    }

    #[test]
    fn visible_streams_are_the_sorted_union_of_both_directions() {
        let download = BTreeMap::from([
            (1, vec![(5.0, 10)]),
            (2, vec![(6.0, 11)]),
            (3, Vec::new()),
        ]);
        let upload = BTreeMap::from([
            (1, vec![(7.0, 12)]),
            (3, vec![(8.0, 13)]),
            (5, Vec::new()),
        ]);
        assert_eq!(
            visible_stream_ids(&download, &upload, ApplicationProto::Http2, true),
            vec![1, 2, 3]
        );
        assert_eq!(
            visible_stream_ids(
                &download,
                &upload,
                ApplicationProto::Http3,
                false
            ),
            vec![1, 2, 3]
        );
        assert_eq!(
            visible_stream_ids(&download, &upload, ApplicationProto::Http3, true),
            vec![1]
        );
    }

    #[test]
    fn chronological_lines_borrow_sorted_input_and_stably_sort_unsorted_input() {
        let ordered = [(1.0, 2), (1.0, 3), (8.0, 7)];
        assert!(matches!(
            super::chronological(&ordered),
            std::borrow::Cow::Borrowed(_)
        ));
        let unsorted = [(8.0, 7), (1.0, 2), (1.0, 3)];
        let values = super::chronological(&unsorted);
        assert!(matches!(values, std::borrow::Cow::Owned(_)));
        assert_eq!(&*values, &ordered);
    }

    #[test]
    fn chart_ranges_account_for_out_of_order_samples_and_invalid_times(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(time_range([9.0, 1.0, 4.0], None, None)?, 1.0..9.0);
        assert_eq!(time_range([9.0, 1.0], Some(2.0), Some(8.0))?, 2.0..8.0);
        assert_eq!(time_range([], None, None)?, 0.0..1.0);
        let equal = time_range([4.0, 4.0], None, None);
        assert!(equal.is_ok_and(|range| range.start < 4.0 && range.end > 4.0));
        for times in
            [vec![f64::NAN], vec![f64::INFINITY], vec![f64::NEG_INFINITY]]
        {
            assert!(time_range(times, None, None).is_err());
        }
        assert!(time_range([1.0, 9.0], Some(10.0), None).is_err());
        assert!(time_range([1.0, 9.0], None, Some(f64::NAN)).is_err());
        assert!(time_range([1.0, 9.0], None, Some(f64::NEG_INFINITY)).is_err());
        assert_eq!(
            stream_y_max(&[(1.0, 900), (3.0, 2), (2.0, 300)], None)?,
            900
        );
        assert_eq!(stream_y_max(&[], None)?, 1);
        assert_eq!(stream_y_max(&[(0.0, 0)], None)?, 1);
        assert!(stream_y_max(&[(0.0, 10)], Some(0)).is_err());
        Ok(())
    }

    #[test]
    fn grid_origins_do_not_wrap_and_follow_row_and_column_order(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let params = SparkPlotsParams {
            sparks_per_row: 2,
            ..SparkPlotsParams::default()
        };
        assert_eq!(cell_origin(&params, 0, 200, 300)?, (50, 30));
        assert_eq!(cell_origin(&params, 1, 200, 300)?, (250, 30));
        assert_eq!(cell_origin(&params, 2, 200, 300)?, (50, 330));
        assert!(cell_origin(&params, u32::MAX, u32::MAX, u32::MAX).is_err());
        Ok(())
    }

    #[test]
    fn grid_reserves_legend_and_contains_every_plot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for captions_on_top in [false, true] {
            for streams in [0_usize, 1, 2, 3, 7, 12] {
                let params = SparkPlotsParams {
                    sparks_per_row: 3,
                    captions_on_top,
                    caption_area_width: 300,
                    ..SparkPlotsParams::default()
                };
                let layout = super::SparkLayout::new(&params, streams)?;
                for slot in 0..u32::try_from(streams)? {
                    let (x, y) = layout.cell(&params, slot)?;
                    assert!(y >= layout.legend_height);
                    assert!(x + params.spark_dimension_x <= layout.size.width);
                    assert!(
                        y + layout.caption_height + params.spark_dimension_y <=
                            layout.size.height
                    );
                    if slot > 0 {
                        let (prev_x, prev_y) = layout.cell(&params, slot - 1)?;
                        if prev_y == y {
                            assert!(x >= prev_x + params.spark_dimension_x);
                        } else {
                            assert!(
                                y >= prev_y +
                                    layout.caption_height +
                                    params.spark_dimension_y
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn http2_upload_credit_axis_handles_negative_and_zero_values(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output_dir = OutputDir::new()?;
        let mut series = SeriesStore::default();
        series
            .sent_data_frames_series
            .insert(1, vec![(1.0, 0), (3.0, 12)]);
        series.h2_send_window_series_balanced.insert(1, vec![
            (1.0, -16),
            (2.0, 0),
            (3.0, 8),
        ]);
        let ds = Datastore {
            application_proto: ApplicationProto::Http2,
            vantage_point: VantagePoint::Client,
            ..Datastore::default()
        };
        let params = SparkPlotsParams {
            sparks_per_row: 1,
            spark_dimension_x: 300,
            spark_dimension_y: 200,
            ..SparkPlotsParams::default()
        };
        render(&params, &series, &ds, &output_dir.png())?;
        let layout = super::SparkLayout::new(&params, 1)?;
        let mut count = 0;
        for entry in std::fs::read_dir(&output_dir.0)? {
            let path = entry?.path();
            if path.to_string_lossy().contains("-ul-") {
                let image = image::open(path)?.to_rgb8();
                assert!(image.enumerate_pixels().any(|(_, y, pixel)| {
                    y >= layout.legend_height &&
                        pixel.0 == [ORANGE.0, ORANGE.1, ORANGE.2]
                }));
                count += 1;
            }
        }
        assert_eq!(count, 2);
        series
            .h2_send_window_series_balanced
            .insert(1, vec![(1.0, 0), (3.0, 0)]);
        render(&params, &series, &ds, &output_dir.png())
    }

    #[test]
    fn png_layout_preserves_upload_only_streams_and_shared_slots(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output_dir = OutputDir::new()?;
        let mut series = SeriesStore {
            sent_x_min: 0.0,
            sent_x_max: 12.0,
            received_x_min: 0.0,
            received_x_max: 12.0,
            y_max_stream_send_plot: 100,
            y_max_stream_recv_plot: 100,
            ..SeriesStore::default()
        };
        series
            .sent_data_frames_series
            .insert(1, vec![(9.0, 900), (1.0, 2)]);
        series
            .received_data_frames_series
            .insert(1, vec![(3.0, 4), (10.0, 10)]);
        // This stream never appears in the download map and must still render.
        series
            .received_data_frames_series
            .insert(3, vec![(2.0, 4), (11.0, 16)]);
        let ds = Datastore {
            application_proto: ApplicationProto::Http2,
            vantage_point: VantagePoint::Server,
            ..Datastore::default()
        };
        let params = SparkPlotsParams {
            sparks_per_row: 1,
            spark_dimension_x: 260,
            spark_dimension_y: 200,
            ..SparkPlotsParams::default()
        };
        render(&params, &series, &ds, &output_dir.png())?;
        let layout = super::SparkLayout::new(&params, 2)?;
        let expected_height = layout.size.height;
        let second_row_y = layout.cell(&params, 1)?.1;
        let mut upload_found = false;
        let mut count = 0;
        for entry in std::fs::read_dir(&output_dir.0)? {
            let path = entry?.path();
            let (width, height) = image::image_dimensions(&path)?;
            assert!(width > 0);
            assert_eq!(height, expected_height, "{}", path.display());
            count += 1;
            if path.to_string_lossy().contains("ul-relative") {
                let image = image::open(&path)?.to_rgb8();
                // The second row is exclusively stream 3's upload plot.
                upload_found = image.enumerate_pixels().any(|(x, y, pixel)| {
                    x > 50 &&
                        x < 310 &&
                        y >= second_row_y &&
                        pixel.0 == [PURPLE_500.0, PURPLE_500.1, PURPLE_500.2]
                });
            }
        }
        assert_eq!(count, 4);
        assert!(
            upload_found,
            "upload-only stream must draw a visible line in its own grid slot"
        );
        Ok(())
    }

    #[test]
    fn http2_server_can_render_both_directions_and_empty_series(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output_dir = OutputDir::new()?;
        let mut series = SeriesStore {
            sent_x_min: 0.0,
            sent_x_max: 12.0,
            received_x_min: 0.0,
            received_x_max: 12.0,
            y_max_stream_send_plot: 10,
            y_max_stream_recv_plot: 10,
            ..SeriesStore::default()
        };
        series
            .sent_data_frames_series
            .insert(1, vec![(1.0, 2), (10.0, 8)]);
        series
            .received_data_frames_series
            .insert(1, vec![(2.0, 3), (11.0, 7)]);
        series.sent_data_frames_series.insert(3, Vec::new());
        let datastore = Datastore {
            application_proto: ApplicationProto::Http2,
            vantage_point: VantagePoint::Server,
            ..Datastore::default()
        };
        let params = SparkPlotsParams {
            sparks_per_row: 1,
            spark_dimension_x: 260,
            spark_dimension_y: 200,
            ..SparkPlotsParams::default()
        };
        render(&params, &series, &datastore, &output_dir.png())?;

        let files: Vec<_> = std::fs::read_dir(&output_dir.0)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<_, _>>()?;
        assert_eq!(files.len(), 4);
        for path in files {
            let png = std::fs::read(&path)?;
            assert!(
                png.starts_with(b"\x89PNG\r\n\x1a\n"),
                "bad PNG: {}",
                path.display()
            );
            assert!(png.len() > 100);
        }
        Ok(())
    }

    #[test]
    fn failed_output_directory_creation_is_reported(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output_dir = OutputDir::new()?;
        let blocked = output_dir.0.join("file-not-directory");
        std::fs::write(&blocked, b"block creation")?;
        let output = ChartOutputType::Png {
            output_dir: blocked.to_string_lossy().into_owned(),
            cwnd_y_max: None,
            stream_y_max: None,
        };
        let result = render(
            &SparkPlotsParams::default(),
            &SeriesStore::default(),
            &Datastore::default(),
            &output,
        );
        assert!(result.is_err());
        Ok(())
    }
}
