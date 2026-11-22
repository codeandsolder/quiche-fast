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
#[cfg(target_arch = "wasm32")]
use plotters_canvas::CanvasBackend;
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
#[cfg(not(target_arch = "wasm32"))]
use crate::plots::ChartSize;
use crate::plots::ClampParams;
use crate::request_stub::HttpRequestStub;
#[cfg(not(target_arch = "wasm32"))]
use plotters::prelude::BitMapBackend;
use plotters::prelude::Cartesian2d;
use plotters::prelude::ChartBuilder;
use plotters::prelude::ChartContext;
use plotters::prelude::Circle;
use plotters::prelude::DrawingArea;
use plotters::prelude::DrawingBackend;
use plotters::prelude::IntoDrawingArea;
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

    const fn as_ref(&self) -> SparkOutputs<&T> {
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
    let value = clamp
        .unwrap_or_else(|| points.iter().map(|point| point.1).max().unwrap_or(1));
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
            "ID= {}, status= {}, proto= {:?}",
            req.stream_id, req.status, application_proto
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
        let summary = format!("ID= {}, status= {}", stream_id, req.status);
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

#[cfg(not(target_arch = "wasm32"))]
fn spark_bitmap_area(
    path: &str, size: ChartSize, colors: PlotColors, margin: ChartMargin,
) -> Result<DrawingArea<BitMapBackend<'_>, plotters::coord::Shift>, Box<dyn Error>>
{
    let area =
        BitMapBackend::new(path, (size.width, size.height)).into_drawing_area();
    area.fill(&colors.fill)?;
    Ok(area.margin(margin.top, margin.bottom, margin.left, margin.right))
}

#[cfg(target_arch = "wasm32")]
fn required_canvas_id(
    config: &ChartConfig, chart: &str,
) -> Result<String, std::io::Error> {
    config.canvas_id().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("spark chart {chart:?} requires a canvas output"),
        )
    })
}

#[cfg(target_arch = "wasm32")]
fn spark_canvas_area(
    canvas_id: &str, colors: PlotColors, margin: ChartMargin,
) -> Result<DrawingArea<CanvasBackend, plotters::coord::Shift>, Box<dyn Error>> {
    let backend = CanvasBackend::new(canvas_id).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("spark canvas {canvas_id:?} not found"),
        )
    })?;
    let area = backend.into_drawing_area();
    area.fill(&colors.fill)?;
    Ok(area.margin(margin.top, margin.bottom, margin.left, margin.right))
}

/// Pick the data direction by transport and capture vantage, independently
/// of the output chart's absolute/relative time coordinate system.
const fn frame_series_for_vantage<'a>(
    ss: &'a SeriesStore, ds: &Datastore,
) -> SparkDirections<&'a BTreeMap<u64, Vec<(f64, u64)>>> {
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

/// Renders stream spark charts for the supported application protocols and
/// vantages.
///
/// # Errors
/// Returns an error on invalid layout sizes, output-directory/PNG I/O failures,
/// missing canvases, or drawing backend failures.
pub fn plot_sparks(
    params: &SparkPlotsParams, filename: &str, ss: &SeriesStore, ds: &Datastore,
    outputs: SparkOutputs<&ChartOutputType>,
) -> Result<(), Box<dyn Error>> {
    if params.sparks_per_row == 0 ||
        params.spark_dimension_x == 0 ||
        params.spark_dimension_y == 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sparks_per_row and spark dimensions must be nonzero",
        )
        .into());
    }

    let frame_series = frame_series_for_vantage(ss, ds);

    let visible_streams = visible_stream_ids(
        frame_series.download,
        frame_series.upload,
        ds.application_proto,
        params.bidi_only,
    );
    #[cfg(not(target_arch = "wasm32"))]
    let total_rows = u32::try_from(visible_streams.len())?
        .div_ceil(params.sparks_per_row)
        .max(1);

    #[cfg(not(target_arch = "wasm32"))]
    let caption_area_width = if params.captions_on_top {
        0
    } else {
        params.caption_area_width
    };

    let caption_area_height = if params.captions_on_top {
        params.caption_area_height
    } else {
        0
    };

    #[cfg(not(target_arch = "wasm32"))]
    let dimension_overflow = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "spark chart dimensions overflow u32",
        )
    };
    #[cfg(not(target_arch = "wasm32"))]
    let spark_and_captions_width = params
        .spark_dimension_x
        .checked_add(
            params
                .spark_offset_x
                .checked_mul(6)
                .ok_or_else(dimension_overflow)? /
                5,
        )
        .and_then(|width| width.checked_add(caption_area_width))
        .ok_or_else(dimension_overflow)?;
    #[cfg(not(target_arch = "wasm32"))]
    let spark_and_captions_height = params
        .spark_dimension_y
        .checked_add(params.spark_offset_y)
        .and_then(|height| height.checked_add(params.label_area_height))
        .and_then(|height| height.checked_add(caption_area_height))
        .ok_or_else(dimension_overflow)?;

    #[cfg(not(target_arch = "wasm32"))]
    let root_width = params
        .sparks_per_row
        .checked_mul(spark_and_captions_width)
        .ok_or_else(dimension_overflow)?;
    #[cfg(not(target_arch = "wasm32"))]
    let root_height = total_rows
        .checked_mul(spark_and_captions_height)
        .ok_or_else(dimension_overflow)?;
    #[cfg(not(target_arch = "wasm32"))]
    {
        chart_coord(u64::from(root_width))?;
        chart_coord(u64::from(root_height))?;
    }

    let absolute_time_range = time_range(
        visible_streams.iter().flat_map(|stream_id| {
            frame_series
                .download
                .get(stream_id)
                .into_iter()
                .chain(frame_series.upload.get(stream_id))
                .flat_map(|series| series.iter().map(|point| point.0))
        }),
        params.clamp.start,
        params.clamp.end,
    )?;
    let x_min = absolute_time_range.start;
    let x_max = absolute_time_range.end;

    let configs = SparkOutputs {
        download: SparkPair {
            absolute: ChartConfig::new(
                "stream-spark-dl-absolute",
                filename,
                &params.clamp,
                ds,
                outputs.download.absolute,
            ),
            relative: ChartConfig::new(
                "stream-spark-dl-relative",
                filename,
                &params.clamp,
                ds,
                outputs.download.relative,
            ),
        },
        upload: SparkPair {
            absolute: ChartConfig::new(
                "stream-spark-ul-absolute",
                filename,
                &params.clamp,
                ds,
                outputs.upload.absolute,
            ),
            relative: ChartConfig::new(
                "stream-spark-ul-relative",
                filename,
                &params.clamp,
                ds,
                outputs.upload.relative,
            ),
        },
    };

    #[cfg(not(target_arch = "wasm32"))]
    for config in [
        &configs.download.absolute,
        &configs.download.relative,
        &configs.upload.absolute,
        &configs.upload.relative,
    ] {
        if matches!(config.ty, ChartOutputType::Png { .. }) {
            if let Some(dir) =
                std::path::Path::new(&config.chart_filepath()).parent()
            {
                std::fs::create_dir_all(dir)?;
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    let size = ChartSize {
        width: root_width,
        height: root_height,
    };
    let margin = ChartMargin::default();

    #[cfg(not(target_arch = "wasm32"))]
    let paths = configs.as_ref().map(ChartConfig::chart_filepath);

    #[cfg(not(target_arch = "wasm32"))]
    let roots = paths
        .as_ref()
        .try_map(|path| spark_bitmap_area(path, size, params.colors, margin))?;

    #[cfg(target_arch = "wasm32")]
    let canvas_ids = SparkOutputs {
        download: SparkPair {
            absolute: required_canvas_id(
                &configs.download.absolute,
                "download-absolute",
            )?,
            relative: required_canvas_id(
                &configs.download.relative,
                "download-relative",
            )?,
        },
        upload: SparkPair {
            absolute: required_canvas_id(
                &configs.upload.absolute,
                "upload-absolute",
            )?,
            relative: required_canvas_id(
                &configs.upload.relative,
                "upload-relative",
            )?,
        },
    };

    #[cfg(target_arch = "wasm32")]
    let roots = canvas_ids.as_ref().try_map(|canvas_id| {
        spark_canvas_area(canvas_id, params.colors, margin)
    })?;

    let legend_x = chart_coord(
        u64::from(params.spark_offset_x) +
            u64::from(params.spark_dimension_x) +
            300,
    )?;
    let legend_y = chart_coord(u64::from(params.spark_offset_y))?;
    for (root, transmission) in [
        (&roots.download.absolute, TransmissionType::Download),
        (&roots.download.relative, TransmissionType::Download),
        (&roots.upload.absolute, TransmissionType::Upload),
        (&roots.upload.relative, TransmissionType::Upload),
    ] {
        plot_legend(
            params.colors.caption,
            root,
            legend_x,
            legend_y,
            transmission,
            ds.vantage_point,
            ds.application_proto,
        )?;
    }

    let column_width = u64::from(params.spark_dimension_x) +
        u64::from(params.spark_offset_x) +
        u64::from(if params.captions_on_top {
            0
        } else {
            params.caption_area_width
        });
    let row_height = u64::from(params.spark_dimension_y) +
        u64::from(params.spark_offset_y) +
        u64::from(params.label_area_height) +
        u64::from(caption_area_height);
    let column_width = u32::try_from(column_width)?;
    let row_height = u32::try_from(row_height)?;

    for (slot, stream_id) in visible_streams.iter().copied().enumerate() {
        let (upper_x, upper_y) =
            cell_origin(params, u32::try_from(slot)?, column_width, row_height)?;
        let area_y =
            upper_y.checked_add(caption_area_height).ok_or_else(|| {
                invalid_plot_range("spark chart row origin overflow")
            })?;
        chart_coord(u64::from(area_y) + u64::from(params.spark_dimension_y))?;
        let dl_stream_frames = frame_series
            .download
            .get(&stream_id)
            .map_or(&[][..], Vec::as_slice);

        let areas = roots.as_ref().map(|root| {
            (*root).clone().shrink(
                (upper_x, area_y),
                (params.spark_dimension_x, params.spark_dimension_y),
            )
        });

        let download_range =
            time_range(dl_stream_frames.iter().map(|point| point.0), None, None)?;
        let download_y_max =
            stream_y_max(dl_stream_frames, params.clamp.stream_y_max)?;

        let mut download_charts = SparkPair {
            absolute: ChartBuilder::on(&areas.download.absolute)
                .set_label_area_size(
                    LabelAreaPosition::Left,
                    params.label_area_width,
                )
                .set_label_area_size(
                    LabelAreaPosition::Bottom,
                    params.label_area_height,
                )
                .build_cartesian_2d(x_min..x_max, 0..download_y_max)?,
            relative: ChartBuilder::on(&areas.download.relative)
                .set_label_area_size(
                    LabelAreaPosition::Left,
                    params.label_area_width,
                )
                .set_label_area_size(
                    LabelAreaPosition::Bottom,
                    params.label_area_height,
                )
                .build_cartesian_2d(download_range, 0..download_y_max)?,
        };
        draw_mesh(&params.colors, &mut download_charts.absolute)?;
        draw_mesh(&params.colors, &mut download_charts.relative)?;

        let ul_stream_frames = frame_series
            .upload
            .get(&stream_id)
            .filter(|frames| !frames.is_empty());

        // TODO upload window
        let h2_stream_id = u32::try_from(stream_id).ok();
        let ul_h2_send_window = h2_stream_id
            .and_then(|id| ss.h2_send_window_series_balanced.get(&id));
        let ul_h2_send_window_max =
            h2_stream_id.and_then(|id| ss.h2_send_window_balanced_max.get(&id));
        let ul_h2_send_window_min =
            h2_stream_id.and_then(|id| ss.h2_send_window_balanced_min.get(&id));

        let upload_charts = match ul_stream_frames {
            Some(frames) => {
                let ul_relative_range =
                    time_range(frames.iter().map(|point| point.0), None, None)?;
                let ul_zoom_x_min = ul_relative_range.start;
                let ul_zoom_x_max = ul_relative_range.end;
                let ul_zoom_y_max =
                    stream_y_max(frames, params.clamp.stream_y_max)?;

                // TODO: this is a hack because the underlying chart types make
                // it hard to support optional secondary axis. And that axis
                // only makes sense for HTTP/2.
                let ul_h2_send_window_y_max = ul_h2_send_window_max.unwrap_or(&0);
                let ul_h2_send_window_y_min = ul_h2_send_window_min.unwrap_or(&0);

                let mut abs_ul_chart = ChartBuilder::on(&areas.upload.absolute)
                    .set_label_area_size(
                        LabelAreaPosition::Left,
                        params.label_area_width,
                    )
                    .set_label_area_size(
                        LabelAreaPosition::Bottom,
                        params.label_area_height,
                    )
                    .build_cartesian_2d(x_min..x_max, 0..ul_zoom_y_max)?
                    .set_secondary_coord(
                        x_min..x_max,
                        *ul_h2_send_window_y_min..*ul_h2_send_window_y_max,
                    );

                draw_mesh(&params.colors, &mut abs_ul_chart)?;

                if ul_h2_send_window_max.is_some() {
                    abs_ul_chart.configure_secondary_axes().draw()?;
                }

                let mut rel_ul_chart = ChartBuilder::on(&areas.upload.relative)
                    .set_label_area_size(
                        LabelAreaPosition::Left,
                        params.label_area_width,
                    )
                    .set_label_area_size(
                        LabelAreaPosition::Bottom,
                        params.label_area_height,
                    )
                    .right_y_label_area_size(params.label_area_width)
                    .build_cartesian_2d(
                        ul_zoom_x_min..ul_zoom_x_max,
                        0..ul_zoom_y_max,
                    )?
                    .set_secondary_coord(
                        ul_zoom_x_min..ul_zoom_x_max,
                        *ul_h2_send_window_y_min..*ul_h2_send_window_y_max,
                    );
                draw_mesh(&params.colors, &mut rel_ul_chart)?;

                if ul_h2_send_window_max.is_some() {
                    rel_ul_chart.configure_secondary_axes().y_labels(5).draw()?;
                }

                Some(SparkPair {
                    absolute: abs_ul_chart,
                    relative: rel_ul_chart,
                })
            },

            None => None,
        };

        let caption_offset = if params.captions_on_top {
            0_u64
        } else if ds.application_proto == ApplicationProto::Http2 {
            u64::from(params.spark_dimension_x) + 30
        } else {
            u64::from(params.spark_dimension_x)
        };
        let caption_x = chart_coord(u64::from(upper_x) + caption_offset)?;
        let caption_y = chart_coord(u64::from(upper_y))?;
        draw_captions(
            &roots,
            params,
            ds,
            stream_id,
            ul_stream_frames.is_some(),
            caption_x,
            caption_y,
        )?;

        draw_stream_frames_line(
            dl_stream_frames,
            &mut download_charts.absolute,
            &mut download_charts.relative,
        )?;

        if let (Some(mut charts), Some(frames)) =
            (upload_charts, ul_stream_frames)
        {
            if let Some(v) = ul_h2_send_window {
                charts.absolute.draw_secondary_series(LineSeries::new(
                    v.iter().copied(),
                    ORANGE,
                ))?;

                charts.relative.draw_secondary_series(LineSeries::new(
                    v.iter().copied(),
                    ORANGE,
                ))?;
            } else {
                draw_stream_max_line(
                    stream_id,
                    ss,
                    ds.vantage_point,
                    TransmissionType::Upload,
                    &mut charts.absolute,
                    &mut charts.relative,
                )?;
            }

            draw_stream_frames_line(
                frames,
                &mut charts.absolute,
                &mut charts.relative,
            )?;
        }

        draw_buffered_data_line(
            stream_id,
            ss,
            ds.vantage_point,
            &mut download_charts.absolute,
            &mut download_charts.relative,
        )?;

        draw_stream_max_line(
            stream_id,
            ss,
            ds.vantage_point,
            TransmissionType::Download,
            &mut download_charts.absolute,
            &mut download_charts.relative,
        )?;

        let y_max = match ds.vantage_point {
            VantagePoint::Client => ss.y_max_stream_recv_plot,
            VantagePoint::Server => ss.y_max_stream_send_plot,
        };

        draw_request_timing_lines(
            ds,
            stream_id,
            y_max,
            &mut download_charts.absolute,
            &mut download_charts.relative,
        )?;
    }

    roots.download.absolute.present()?;
    roots.download.relative.present()?;
    roots.upload.absolute.present()?;
    roots.upload.relative.present()?;
    Ok(())
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

/// The peer's MAX_STREAM_DATA limits are sourced from the opposite direction
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
    fn captions_tolerate_absent_timing_data() {
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
            panic!("client request must produce a client caption");
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
            panic!("server request must produce a server caption");
        }
        assert_eq!(format_delta(Some(12.345), "duration="), "duration=12.35ms");
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
    fn spark_output_initialization_is_ordered_and_short_circuits_on_error() {
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
        let mapped = mapped.expect("all outputs should initialize");
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
        let h2_ul = entries(
            TransmissionType::Upload,
            VantagePoint::Client,
            ApplicationProto::Http2,
        );
        assert_eq!(h2_ul.len(), 3);
        assert_eq!(h2_ul[2], ("HTTP/2 send window", ORANGE));
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
        let expected_height = 2 *
            (params.spark_dimension_y +
                params.spark_offset_y +
                params.label_area_height +
                params.caption_area_height);
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
                        y > expected_height / 2 &&
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
