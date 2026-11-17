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

use full_palette::PURPLE_500;
use plotters::coord::types::RangedCoordf64;
use plotters::coord::types::RangedCoordu64;
use plotters::drawing::DrawingAreaErrorKind;
#[cfg(target_arch = "wasm32")]
use plotters_canvas::CanvasBackend;
use std::error::Error;

use tabled::Tabled;

use crate::datastore::ApplicationProto;
use crate::datastore::VantagePoint;
use crate::plots::colors::*;
use crate::plots::*;
use crate::request_stub::HttpRequestStub;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

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
            clamp: Default::default(),
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
            colors: Default::default(),
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

        SparkCaption::RequestAtClient {
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

        SparkCaption::RequestAtServer {
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
            if let Some(req) = ds.http_requests.get(&stream_id) {
                match ds.vantage_point {
                    VantagePoint::Client =>
                        Some(SparkCaption::request_at_client_from_stub(
                            ds.application_proto,
                            req,
                        )),
                    VantagePoint::Server => Some(
                        SparkCaption::request_at_server_from_stub(stream_id, req),
                    ),
                }
            } else {
                None
            }
        } else {
            let summary = format!("ID= {}", stream_id);
            Some(SparkCaption::UniStream { summary })
        }
    }

    fn draw<DB: DrawingBackend>(
        &self, color: &RGBColor, root: &DrawingArea<DB, plotters::coord::Shift>,
        x: i32, y: i32,
    ) -> SparkDrawingResult<DB> {
        let style = &("monospace", 12).into_text_style(root).color(color);

        let newline_offset = 10;
        let x = x + 20;

        match self {
            SparkCaption::UniStream { summary } => {
                root.draw_text(summary, style, (x, y))?;
            },

            SparkCaption::RequestAtServer {
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
                ..
            } => {
                root.draw_text(summary, style, (x, y))?;

                root.draw_text(method, style, (x, y + newline_offset))?;

                root.draw_text(path, style, (x, y + newline_offset * 2))?;

                root.draw_text(
                    client_content_length,
                    style,
                    (x, y + newline_offset * 3),
                )?;

                root.draw_text(
                    server_content_length,
                    style,
                    (x, y + newline_offset * 4),
                )?;

                root.draw_text(
                    client_pri_hdr,
                    style,
                    (x, y + newline_offset * 6),
                )?;

                root.draw_text(
                    server_pri_hdr,
                    style,
                    (x, y + newline_offset * 7),
                )?;

                root.draw_text(
                    duration_rx_hdr_tx_hdr,
                    style,
                    (x, y + newline_offset * 8),
                )?;

                root.draw_text(
                    duration_rx_hdr_tx_first_data,
                    style,
                    (x, y + newline_offset * 9),
                )?;

                root.draw_text(
                    duration_rx_hdr_tx_last_data,
                    style,
                    (x, y + newline_offset * 10),
                )?;

                root.draw_text(
                    duration_tx_first_data_tx_last_data,
                    style,
                    (x, y + newline_offset * 11),
                )?;
            },

            SparkCaption::RequestAtClient {
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
                ..
            } => {
                root.draw_text(summary, style, (x, y))?;

                root.draw_text(method, style, (x, y + newline_offset))?;
                root.draw_text(path, style, (x, y + newline_offset * 2))?;

                root.draw_text(
                    client_content_length,
                    style,
                    (x, y + newline_offset * 3),
                )?;

                root.draw_text(
                    server_content_length,
                    style,
                    (x, y + newline_offset * 4),
                )?;

                root.draw_text(
                    client_pri_hdr,
                    style,
                    (x, y + newline_offset * 6),
                )?;

                root.draw_text(
                    client_pri_update,
                    style,
                    (x, y + newline_offset * 7),
                )?;

                root.draw_text(
                    server_pri_hdr,
                    style,
                    (x, y + newline_offset * 8),
                )?;

                root.draw_text(
                    duration_tx_hdr_rx_hdr,
                    style,
                    (x, y + newline_offset * 9),
                )?;

                root.draw_text(
                    duration_tx_hdr_rx_first_data,
                    style,
                    (x, y + newline_offset * 10),
                )?;

                root.draw_text(
                    duration_tx_hdr_rx_last_data,
                    style,
                    (x, y + newline_offset * 11),
                )?;

                root.draw_text(
                    duration_tx_first_data_tx_last_data,
                    style,
                    (x, y + newline_offset * 12),
                )?;
            },
        }
        Ok(())
    }
}

fn plot_legend<DB: DrawingBackend>(
    color: &RGBColor, root: &DrawingArea<DB, plotters::coord::Shift>, x: i32,
    y: i32, params: &SparkPlotsParams, transmission_type: TransmissionType,
) -> SparkDrawingResult<DB> {
    // TODO: only considers vert layout, needs to consider grid layout too
    let style = &("monospace", 12).into_text_style(root).color(color);
    let x: i32 = x + params.spark_dimension_x as i32 + 300;
    let y: i32 = y;
    let line_len: i32 = 50;
    let nl_off: i32 = 20;

    root.draw_text("Legend", style, (x, y))?;

    // stream data
    let label = match transmission_type {
        TransmissionType::Download => "Stream data read",
        TransmissionType::Upload => "Stream data sent",
    };
    root.draw(&PathElement::new(
        vec![(x, y + nl_off), (x + line_len, y + nl_off)],
        PURPLE_500,
    ))?;
    root.draw_text(label, style, (x + line_len + 10, y + (nl_off) - 5))?;

    // stream data buffered
    root.draw(&PathElement::new(
        vec![(x, y + nl_off * 2), (x + line_len, y + nl_off * 2)],
        MAGENTA,
    ))?;
    root.draw_text(
        "Stream data buffered",
        style,
        (x + line_len + 10, y + (nl_off * 2) - 5),
    )?;

    // max stream data
    let label = match transmission_type {
        TransmissionType::Download => "Max stream data sent",
        TransmissionType::Upload => "Max stream data received",
    };

    root.draw(&PathElement::new(
        vec![(x, y + nl_off * 3), (x + line_len, y + nl_off * 3)],
        MUSTARD,
    ))?;
    root.draw_text(label, style, (x + line_len + 10, y + (nl_off * 3) - 5))?;

    // headers transmitted
    root.draw(&PathElement::new(
        vec![(x, y + nl_off * 4), (x + line_len, y + nl_off * 4)],
        CYAN,
    ))?;
    root.draw_text(
        "Request headers sent",
        style,
        (x + line_len + 10, y + (nl_off * 4) - 5),
    )?;

    // first data frame
    root.draw(&PathElement::new(
        vec![(x, y + nl_off * 5), (x + line_len, y + nl_off * 5)],
        ORANGE,
    ))?;
    root.draw_text(
        "First data frame read",
        style,
        (x + line_len + 10, y + (nl_off * 5) - 5),
    )?;

    // last data frame
    root.draw(&PathElement::new(
        vec![(x, y + nl_off * 6), (x + line_len, y + nl_off * 6)],
        BROWN,
    ))?;
    root.draw_text(
        "Last data frame read",
        style,
        (x + line_len + 10, y + (nl_off * 6) - 5),
    )?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn spark_bitmap_area<'a>(
    path: &'a str, size: ChartSize, colors: PlotColors, margin: ChartMargin,
) -> Result<DrawingArea<BitMapBackend<'a>, plotters::coord::Shift>, Box<dyn Error>>
{
    let area =
        BitMapBackend::new(path, (size.width, size.height)).into_drawing_area();
    area.fill(&colors.fill)?;
    Ok(area.margin(margin.top, margin.bottom, margin.left, margin.right))
}

#[cfg(target_arch = "wasm32")]
fn required_canvas_id(config: &ChartConfig) -> Result<String, std::io::Error> {
    config.canvas_id().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("spark chart {:?} requires a canvas output", config.title),
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

/// Renders stream spark charts for the supported application protocols and
/// vantages.
///
/// # Errors
/// Returns an error on invalid layout sizes, output-directory/PNG I/O failures,
/// missing canvases, or drawing backend failures.
#[expect(
    clippy::too_many_arguments,
    reason = "The signature mirrors protocol state and grouping would obscure call sites"
)]
pub fn plot_sparks(
    params: &SparkPlotsParams, filename: &str, ss: &SeriesStore, ds: &Datastore,
    abs_dl_ty: &ChartOutputType, rel_dl_ty: &ChartOutputType,
    abs_ul_ty: &ChartOutputType, rel_ul_ty: &ChartOutputType,
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

    let (stream_frame_dl_series_to_plot, stream_frame_ul_series_to_plot) =
        match ds.application_proto {
            ApplicationProto::Http3 => match ds.vantage_point {
                VantagePoint::Client => (
                    &ss.received_stream_frames_series,
                    &ss.sent_stream_frames_series,
                ),
                VantagePoint::Server => (
                    &ss.sent_stream_frames_series,
                    &ss.received_stream_frames_series,
                ),
            },
            ApplicationProto::Http2 => match ds.vantage_point {
                VantagePoint::Client =>
                    (&ss.received_data_frames_series, &ss.sent_data_frames_series),
                VantagePoint::Server =>
                    (&ss.sent_data_frames_series, &ss.received_data_frames_series),
            },
        };

    #[cfg(not(target_arch = "wasm32"))]
    let (total_dl_sparks, total_ul_sparks): (u32, u32) =
        if params.bidi_only && ds.application_proto == ApplicationProto::Http3 {
            let total_dl = stream_frame_dl_series_to_plot
                .iter()
                .filter(|(k, points)| (*k & 0x2) == 0 && !points.is_empty())
                .count()
                .try_into()?;

            let total_ul = stream_frame_ul_series_to_plot
                .iter()
                .filter(|(k, points)| (*k & 0x2) == 0 && !points.is_empty())
                .count()
                .try_into()?;

            (total_dl, total_ul)
        } else {
            (
                stream_frame_dl_series_to_plot
                    .values()
                    .filter(|points| !points.is_empty())
                    .count()
                    .try_into()?,
                stream_frame_ul_series_to_plot
                    .values()
                    .filter(|points| !points.is_empty())
                    .count()
                    .try_into()?,
            )
        };

    #[cfg(not(target_arch = "wasm32"))]
    let total_dl_rows = total_dl_sparks.div_ceil(params.sparks_per_row).max(1);
    #[cfg(not(target_arch = "wasm32"))]
    let total_ul_rows = total_ul_sparks.div_ceil(params.sparks_per_row).max(1);

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
    let dl_root_height = total_dl_rows
        .checked_mul(spark_and_captions_height)
        .ok_or_else(dimension_overflow)?;
    #[cfg(not(target_arch = "wasm32"))]
    let ul_root_height = total_ul_rows
        .checked_mul(spark_and_captions_height)
        .ok_or_else(dimension_overflow)?;

    let mut x_min = match ds.vantage_point {
        VantagePoint::Client => ss.received_x_min,
        VantagePoint::Server => ss.sent_x_min,
    };

    let mut x_max = match ds.vantage_point {
        VantagePoint::Client => ss.received_x_max,
        VantagePoint::Server => ss.sent_x_max,
    };

    // Clamp plot x-axis if the user told us.
    if let Some(s) = params.clamp.start {
        x_min = s;
    }

    if let Some(e) = params.clamp.end {
        x_max = x_max.min(e);
    }

    let abs_dl_chart_config = ChartConfig {
        title: "stream-spark-dl-absolute".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: abs_dl_ty.clone(),
    };

    let rel_dl_chart_config = ChartConfig {
        title: "stream-spark-dl-relative".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: rel_dl_ty.clone(),
    };

    let abs_ul_chart_config = ChartConfig {
        title: "stream-spark-ul-absolute".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: abs_ul_ty.clone(),
    };

    let rel_ul_chart_config = ChartConfig {
        title: "stream-spark-ul-relative".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: rel_ul_ty.clone(),
    };

    #[cfg(not(target_arch = "wasm32"))]
    for config in [
        &abs_dl_chart_config,
        &rel_dl_chart_config,
        &abs_ul_chart_config,
        &rel_ul_chart_config,
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
    let dl_size = ChartSize {
        width: root_width,
        height: dl_root_height,
    };

    #[cfg(not(target_arch = "wasm32"))]
    let ul_size = ChartSize {
        width: root_width,
        height: ul_root_height,
    };
    let margin = ChartMargin::default();

    #[cfg(not(target_arch = "wasm32"))]
    let abs_dl_chart_path = abs_dl_chart_config.chart_filepath();

    #[cfg(not(target_arch = "wasm32"))]
    let rel_dl_chart_path = rel_dl_chart_config.chart_filepath();

    #[cfg(not(target_arch = "wasm32"))]
    let abs_ul_chart_path = abs_ul_chart_config.chart_filepath();

    #[cfg(not(target_arch = "wasm32"))]
    let rel_ul_chart_path = rel_ul_chart_config.chart_filepath();

    #[cfg(not(target_arch = "wasm32"))]
    let abs_dl_root =
        spark_bitmap_area(&abs_dl_chart_path, dl_size, params.colors, margin)?;

    #[cfg(not(target_arch = "wasm32"))]
    let rel_dl_root =
        spark_bitmap_area(&rel_dl_chart_path, dl_size, params.colors, margin)?;

    #[cfg(not(target_arch = "wasm32"))]
    let abs_ul_root =
        spark_bitmap_area(&abs_ul_chart_path, ul_size, params.colors, margin)?;

    #[cfg(not(target_arch = "wasm32"))]
    let rel_ul_root =
        spark_bitmap_area(&rel_ul_chart_path, ul_size, params.colors, margin)?;

    #[cfg(target_arch = "wasm32")]
    let abs_dl_canvas_id = required_canvas_id(&abs_dl_chart_config)?;

    #[cfg(target_arch = "wasm32")]
    let rel_dl_canvas_id = required_canvas_id(&rel_dl_chart_config)?;

    #[cfg(target_arch = "wasm32")]
    let abs_ul_canvas_id = required_canvas_id(&abs_ul_chart_config)?;

    #[cfg(target_arch = "wasm32")]
    let rel_ul_canvas_id = required_canvas_id(&rel_ul_chart_config)?;

    #[cfg(target_arch = "wasm32")]
    let abs_dl_root =
        spark_canvas_area(&abs_dl_canvas_id, params.colors, margin)?;
    #[cfg(target_arch = "wasm32")]
    let rel_dl_root =
        spark_canvas_area(&rel_dl_canvas_id, params.colors, margin)?;
    #[cfg(target_arch = "wasm32")]
    let abs_ul_root =
        spark_canvas_area(&abs_ul_canvas_id, params.colors, margin)?;
    #[cfg(target_arch = "wasm32")]
    let rel_ul_root =
        spark_canvas_area(&rel_ul_canvas_id, params.colors, margin)?;

    let mut upper_x = params.spark_offset_x;
    let mut dl_upper_y = params.spark_offset_y;
    let mut ul_upper_y = params.spark_offset_y;

    plot_legend(
        &params.colors.caption,
        &abs_dl_root,
        upper_x as i32,
        dl_upper_y as i32,
        params,
        TransmissionType::Download,
    )?;
    plot_legend(
        &params.colors.caption,
        &rel_dl_root,
        upper_x as i32,
        dl_upper_y as i32,
        params,
        TransmissionType::Download,
    )?;
    plot_legend(
        &params.colors.caption,
        &abs_ul_root,
        upper_x as i32,
        ul_upper_y as i32,
        params,
        TransmissionType::Upload,
    )?;
    plot_legend(
        &params.colors.caption,
        &rel_ul_root,
        upper_x as i32,
        ul_upper_y as i32,
        params,
        TransmissionType::Upload,
    )?;

    let mut dl_layout_count = 0;
    let mut ul_layout_count = 0;

    for (stream_id, dl_stream_frames) in stream_frame_dl_series_to_plot {
        if ds.application_proto == ApplicationProto::Http3 &&
            params.bidi_only &&
            (stream_id & 0x2) != 0
        {
            continue;
        }

        // Log traces can contain streams whose measured series is empty.
        if dl_stream_frames.is_empty() {
            continue;
        }

        let abs_dl_small_area = abs_dl_root.clone().shrink(
            (upper_x, dl_upper_y + caption_area_height),
            (params.spark_dimension_x, params.spark_dimension_y),
        );

        let rel_dl_small_area = rel_dl_root.clone().shrink(
            (upper_x, dl_upper_y + caption_area_height),
            (params.spark_dimension_x, params.spark_dimension_y),
        );

        let abs_ul_small_area = abs_ul_root.clone().shrink(
            (upper_x, ul_upper_y + caption_area_height),
            (params.spark_dimension_x, params.spark_dimension_y),
        );

        let rel_ul_small_area = rel_ul_root.clone().shrink(
            (upper_x, ul_upper_y + caption_area_height),
            (params.spark_dimension_x, params.spark_dimension_y),
        );

        let dl_zoom_x_min = dl_stream_frames[0].0;
        let dl_zoom_x_max = dl_stream_frames[dl_stream_frames.len() - 1].0;

        let dl_zoom_y_max = if let Some(y_max) = params.clamp.stream_y_max {
            y_max
        } else {
            dl_stream_frames[dl_stream_frames.len() - 1].1
        };

        let mut abs_dl_chart = ChartBuilder::on(&abs_dl_small_area)
            .set_label_area_size(LabelAreaPosition::Left, params.label_area_width)
            .set_label_area_size(
                LabelAreaPosition::Bottom,
                params.label_area_height,
            )
            .build_cartesian_2d(x_min..x_max, 0..dl_zoom_y_max)?;
        draw_mesh(&params.colors, &mut abs_dl_chart)?;

        let mut rel_dl_chart = ChartBuilder::on(&rel_dl_small_area)
            .set_label_area_size(LabelAreaPosition::Left, params.label_area_width)
            .set_label_area_size(
                LabelAreaPosition::Bottom,
                params.label_area_height,
            )
            .build_cartesian_2d(dl_zoom_x_min..dl_zoom_x_max, 0..dl_zoom_y_max)?;
        draw_mesh(&params.colors, &mut rel_dl_chart)?;

        dl_layout_count += 1;

        let ul_stream_frames = stream_frame_ul_series_to_plot
            .get(stream_id)
            .filter(|frames| !frames.is_empty());

        // TODO upload window
        let h2_stream_id = u32::try_from(*stream_id).ok();
        let ul_h2_send_window = h2_stream_id
            .and_then(|id| ss.h2_send_window_series_balanced.get(&id));
        let ul_h2_send_window_max =
            h2_stream_id.and_then(|id| ss.h2_send_window_balanced_max.get(&id));
        let ul_h2_send_window_min =
            h2_stream_id.and_then(|id| ss.h2_send_window_balanced_min.get(&id));

        let (abs_ul_chart, rel_ul_chart) = match ul_stream_frames {
            Some(frames) => {
                let ul_zoom_x_min = frames[0].0;
                let ul_zoom_x_max = frames[frames.len() - 1].0;

                let ul_zoom_y_max = if let Some(y_max) = params.clamp.stream_y_max
                {
                    y_max
                } else {
                    frames[frames.len() - 1].1
                };

                // TODO: this is a hack because the underlying chart types make
                // it hard to support optional secondary axis. And that axis
                // only makes sense for HTTP/2.
                let ul_h2_send_window_y_max = ul_h2_send_window_max.unwrap_or(&0);
                let ul_h2_send_window_y_min = ul_h2_send_window_min.unwrap_or(&0);

                let mut abs_ul_chart = ChartBuilder::on(&abs_ul_small_area)
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

                let mut rel_ul_chart = ChartBuilder::on(&rel_ul_small_area)
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

                ul_layout_count += 1;

                (Some(abs_ul_chart), Some(rel_ul_chart))
            },

            None => (None, None),
        };

        draw_captions(
            &abs_dl_root,
            &rel_dl_root,
            &abs_ul_root,
            &rel_ul_root,
            params,
            ds,
            *stream_id,
            ul_stream_frames.is_some(),
            upper_x,
            dl_upper_y,
            ul_upper_y,
        )?;

        upper_x += params.spark_dimension_x + params.spark_offset_x;

        // new row needed?
        if dl_layout_count == params.sparks_per_row {
            upper_x = params.spark_offset_x;

            let y_offset = if params.captions_on_top {
                params.caption_area_height
            } else {
                0
            };

            dl_upper_y +=
                params.spark_dimension_y + params.spark_offset_y + y_offset;

            dl_layout_count = 0;
        }

        if ul_layout_count == params.sparks_per_row {
            upper_x = params.spark_offset_x;

            let y_offset = if params.captions_on_top {
                params.caption_area_height
            } else {
                0
            };

            ul_upper_y +=
                params.spark_dimension_y + params.spark_offset_y + y_offset;

            ul_layout_count = 0;
        }

        draw_stream_frames_line(
            dl_stream_frames,
            &mut abs_dl_chart,
            &mut rel_dl_chart,
        )?;

        if let (Some(mut abs), Some(mut rel), Some(frames)) =
            (abs_ul_chart, rel_ul_chart, ul_stream_frames)
        {
            if let Some(v) = ul_h2_send_window {
                abs.draw_secondary_series(LineSeries::new(v.to_vec(), ORANGE))?;

                rel.draw_secondary_series(LineSeries::new(v.to_vec(), ORANGE))?;
            } else {
                draw_stream_max_line(
                    *stream_id,
                    ss,
                    &ds.vantage_point,
                    TransmissionType::Upload,
                    &mut abs,
                    &mut rel,
                )?;
            }

            draw_stream_frames_line(frames, &mut abs, &mut rel)?;
        }

        draw_buffered_data_line(
            *stream_id,
            ss,
            &ds.vantage_point,
            &mut abs_dl_chart,
            &mut rel_dl_chart,
        )?;

        draw_stream_max_line(
            *stream_id,
            ss,
            &ds.vantage_point,
            TransmissionType::Download,
            &mut abs_dl_chart,
            &mut rel_dl_chart,
        )?;

        let y_max = match ds.vantage_point {
            VantagePoint::Client => ss.y_max_stream_recv_plot,
            VantagePoint::Server => ss.y_max_stream_send_plot,
        };

        draw_request_timing_lines(
            ds,
            *stream_id,
            y_max,
            &mut abs_dl_chart,
            &mut rel_dl_chart,
        )?;
    }

    abs_dl_root.present()?;
    rel_dl_root.present()?;
    abs_ul_root.present()?;
    rel_ul_root.present()?;
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

#[expect(
    clippy::too_many_arguments,
    reason = "The signature mirrors protocol state and grouping would obscure call sites"
)]
fn draw_captions<DB: DrawingBackend>(
    abs_dl_root: &DrawingArea<DB, plotters::coord::Shift>,
    rel_dl_root: &DrawingArea<DB, plotters::coord::Shift>,
    abs_ul_root: &DrawingArea<DB, plotters::coord::Shift>,
    rel_ul_root: &DrawingArea<DB, plotters::coord::Shift>,
    params: &SparkPlotsParams, ds: &Datastore, stream_id: u64, upload_data: bool,
    upper_x: u32, dl_upper_y: u32, ul_upper_y: u32,
) -> SparkDrawingResult<DB> {
    if let Some(captions) = SparkCaption::from_data_store(ds, stream_id) {
        let x_offset = if params.captions_on_top {
            0
        } else if ds.application_proto == ApplicationProto::Http2 {
            params.spark_dimension_x + 30
        } else {
            params.spark_dimension_x
        };

        captions.draw(
            &params.colors.caption,
            abs_dl_root,
            (upper_x + x_offset) as i32,
            dl_upper_y as i32,
        )?;
        captions.draw(
            &params.colors.caption,
            rel_dl_root,
            (upper_x + x_offset) as i32,
            dl_upper_y as i32,
        )?;

        if upload_data {
            captions.draw(
                &params.colors.caption,
                abs_ul_root,
                (upper_x + x_offset) as i32,
                ul_upper_y as i32,
            )?;
            captions.draw(
                &params.colors.caption,
                rel_ul_root,
                (upper_x + x_offset) as i32,
                ul_upper_y as i32,
            )?;
        }
    }
    Ok(())
}

fn draw_stream_frames_line<DB: DrawingBackend>(
    stream_frames: &[(f64, u64)],
    abs_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    rel_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> SparkDrawingResult<DB> {
    abs_chart.draw_series(LineSeries::new(stream_frames.to_vec(), PURPLE_500))?;

    rel_chart.draw_series(LineSeries::new(stream_frames.to_vec(), PURPLE_500))?;

    let circles: Vec<Circle<(f64, u64), i32>> = stream_frames
        .iter()
        .map(|point| Circle::new(*point, 2, PURPLE_500))
        .collect();
    rel_chart.draw_series(circles)?;
    Ok(())
}

fn draw_buffered_data_line<DB: DrawingBackend>(
    stream_id: u64, ss: &SeriesStore, vantage_point: &VantagePoint,
    abs_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    rel_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> SparkDrawingResult<DB> {
    let buffered_data_to_plot = match vantage_point {
        VantagePoint::Client => ss.stream_buffer_reads.get(&stream_id),
        VantagePoint::Server => ss.stream_buffer_writes.get(&stream_id),
    };

    if let Some(buffered_data) = buffered_data_to_plot {
        abs_chart.draw_series(LineSeries::new(buffered_data.clone(), MAGENTA))?;

        rel_chart.draw_series(LineSeries::new(buffered_data.clone(), MAGENTA))?;

        rel_chart.draw_series(
            buffered_data
                .iter()
                .map(|point| TriangleMarker::new(*point, 3, MAGENTA)),
        )?;
    }
    Ok(())
}

fn draw_stream_max_line<DB: DrawingBackend>(
    stream_id: u64, ss: &SeriesStore, vantage_point: &VantagePoint,
    transmission_type: TransmissionType,
    abs_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    rel_chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> SparkDrawingResult<DB> {
    let stream_max_data_to_plot = match (vantage_point, transmission_type) {
        (VantagePoint::Client, TransmissionType::Download) =>
            ss.sent_stream_max_data.get(&stream_id),
        (VantagePoint::Client, TransmissionType::Upload) =>
            ss.received_stream_max_data.get(&stream_id),
        (VantagePoint::Server, TransmissionType::Download) =>
            ss.received_stream_max_data.get(&stream_id),
        (VantagePoint::Server, TransmissionType::Upload) =>
            ss.sent_stream_max_data.get(&stream_id),
    };

    if let Some(stream_max_data) = stream_max_data_to_plot {
        abs_chart
            .draw_series(LineSeries::new(stream_max_data.clone(), MUSTARD))?;

        rel_chart
            .draw_series(LineSeries::new(stream_max_data.clone(), MUSTARD))?;
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
            let points = vec![(h, 0), (h, y_max)];
            abs_chart.draw_series(LineSeries::new(points, GREEN))?;

            // don't care about rx events on the relative spark chart
        }

        if let Some(h) = req.time_first_headers_tx {
            let points = vec![(h, 0), (h, y_max)];
            abs_chart.draw_series(LineSeries::new(points.clone(), CYAN))?;
            rel_chart.draw_series(LineSeries::new(points, CYAN))?;
        }

        let (first_data_to_plot, last_data_to_plot) = match ds.vantage_point {
            VantagePoint::Client =>
                (req.time_first_data_rx, req.time_last_data_rx),
            VantagePoint::Server =>
                (req.time_first_data_tx, req.time_last_data_tx),
        };

        if let Some(t) = first_data_to_plot {
            let points = vec![(t, 0), (t, y_max)];
            abs_chart.draw_series(LineSeries::new(points.clone(), ORANGE))?;
            rel_chart.draw_series(LineSeries::new(points, ORANGE))?;
        }

        if let Some(t) = last_data_to_plot {
            let points = vec![(t, 0), (t, y_max)];
            abs_chart.draw_series(LineSeries::new(points.clone(), BROWN))?;
            rel_chart.draw_series(LineSeries::new(points, BROWN))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::format_delta;
    use super::plot_sparks;
    use super::SparkCaption;
    use super::SparkPlotsParams;
    use crate::datastore::ApplicationProto;
    use crate::datastore::Datastore;
    use crate::datastore::VantagePoint;
    use crate::plots::ChartOutputType;
    use crate::request_stub::HttpRequestStub;
    use crate::seriesstore::SeriesStore;
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
            output,
            output,
            output,
            output,
        )
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
        ] {
            assert!(render(&params, &series, &datastore, &output).is_err());
        }
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
