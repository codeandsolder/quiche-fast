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

#[cfg(not(target_arch = "wasm32"))]
use crate::plots::fallible::bitmap_area;
#[cfg(target_arch = "wasm32")]
use crate::plots::fallible::canvas_area;
use crate::plots::fallible::checked_time_range;
#[cfg(not(target_arch = "wasm32"))]
use crate::plots::fallible::invalid_chart;
use plotters::coord::types::RangedCoordf64;
use plotters::coord::types::RangedCoordu64;
use plotters::coord::Shift;
use plotters::drawing::DrawingAreaErrorKind;
#[cfg(not(target_arch = "wasm32"))]
use plotters::prelude::AsRelative;
use plotters::prelude::Cartesian2d;
use plotters::prelude::ChartBuilder;
use plotters::prelude::ChartContext;
use plotters::prelude::Color;
use plotters::prelude::DrawingBackend;
use plotters::prelude::RGBColor;
use plotters::prelude::SeriesLabelPosition;
use plotters::prelude::BLACK;
use plotters::prelude::BLUE;
use plotters::prelude::CYAN;
use plotters::prelude::GREEN;
use plotters::prelude::MAGENTA;
use plotters::style::full_palette::PURPLE_500;
#[cfg(target_arch = "wasm32")]
use plotters_canvas::CanvasBackend;
use std::collections::BTreeMap;
use std::error::Error;
use std::io;
use std::ops::Range;

use crate::plots::chart_label_style;
#[cfg(not(target_arch = "wasm32"))]
use crate::plots::chart_subtitle_style;
use crate::plots::chart_title_style;
use crate::plots::colors::FOREST_GREEN;
use crate::plots::colors::MID_GREY;
use crate::plots::colors::MUSTARD;
use crate::plots::colors::ORANGE;
use crate::plots::draw_line;
use crate::plots::draw_mesh;
#[cfg(not(target_arch = "wasm32"))]
use crate::plots::ChartConfig;
use crate::plots::ChartOutputType;
use crate::plots::PlotParameters;
use crate::QlogPointu64;

#[cfg(not(target_arch = "wasm32"))]
use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

#[cfg(not(target_arch = "wasm32"))]
use super::congestion_control::draw_congestion_plot;
#[cfg(not(target_arch = "wasm32"))]
use super::rtt::draw_rtt_plot;

struct XYMinMax {
    pub x: Range<f64>,
    pub y_min: u64,
    pub y_max: u64,
}

impl XYMinMax {
    fn init(
        params: &PlotParameters, ss: &SeriesStore, y_max: u64,
    ) -> io::Result<Self> {
        let x = checked_time_range(
            ss.sent_x_min.min(ss.received_x_min),
            ss.sent_x_max.max(ss.received_x_max),
            &params.clamp,
        )?;
        Ok(Self {
            x,
            y_min: 0,
            y_max: y_max.max(1),
        })
    }

    const fn y_range(&self) -> Range<u64> {
        self.y_min..self.y_max
    }
}

#[derive(Clone, Debug)]
pub enum OverviewChartOutputType {
    Png {
        output_dir: String,
        cwnd_y_max: Option<u64>,
        stream_y_max: Option<u64>,
    },

    Canvas {
        main_plot_canvas_id: String,
        congestion_plot_canvas_id: String,
        rtt_plot_canvas_id: String,
    },
}

impl From<OverviewChartOutputType> for ChartOutputType {
    fn from(val: OverviewChartOutputType) -> Self {
        match val {
            OverviewChartOutputType::Png {
                output_dir,
                cwnd_y_max,
                stream_y_max,
            } => Self::Png {
                output_dir,
                cwnd_y_max,
                stream_y_max,
            },

            OverviewChartOutputType::Canvas {
                main_plot_canvas_id,
                ..
            } => Self::Canvas {
                canvas_id: main_plot_canvas_id,
            },
        }
    }
}

/// Draw a group of stream-specific series in stream-id order.
///
/// Empty series do not consume the shared legend label. The first series
/// containing data receives the label, and subsequent streams share its color.
fn draw_stream_group<DB: DrawingBackend>(
    streams: &BTreeMap<u64, Vec<QlogPointu64>>, label: &'static str,
    colour: RGBColor,
    chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    let mut label = Some(label);
    for data in streams.values().filter(|data| !data.is_empty()) {
        draw_line(data, label.take(), colour, chart)?;
    }
    Ok(())
}

/// Draw the receive-side series shared by the combined browser overview and
/// native stream receive panel in their original order.
fn draw_receive_panel_series<DB: DrawingBackend>(
    ss: &SeriesStore,
    chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    draw_line(&ss.sent_max_data, Some("Sent MAX_DATA"), BLACK, chart)?;
    draw_line(
        &ss.sum_sent_stream_max_data,
        Some("Cumulative sent MAX_STREAM_DATA"),
        CYAN,
        chart,
    )?;
    draw_stream_group(
        &ss.sent_stream_max_data,
        "Sent MAX_STREAM_DATA",
        BLUE,
        chart,
    )?;
    draw_stream_group(
        &ss.stream_buffer_reads,
        "Stream buffer read",
        FOREST_GREEN,
        chart,
    )?;
    draw_line(
        &ss.sum_stream_buffer_reads,
        Some("Cumulative stream buffer read"),
        GREEN,
        chart,
    )?;
    Ok(())
}

/// Keep legend styling identical in native split views and the browser view.
fn draw_legend<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters,
    chart: &mut ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    if params.display_legend {
        chart
            .configure_series_labels()
            .label_font(chart_label_style(&params.colors.caption))
            .background_style(params.colors.fill.mix(0.8))
            .border_style(params.colors.axis)
            .position(SeriesLabelPosition::UpperLeft)
            .draw()?;
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn draw_main_plot<'a, DB: DrawingBackend + 'a>(
    filename: &str, params: &PlotParameters, axis: &XYMinMax, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
>
where
    DB::ErrorType: 'static,
{
    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        let caption = format!("{filename} Connection overview");
        builder.caption(caption, chart_title_style(&params.colors.caption));
    }

    let mut chart = builder.build_cartesian_2d(axis.x.clone(), axis.y_range())?;

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Data (bytes)",
        params.display_minor_lines,
        &mut chart,
    )?;

    draw_receive_panel_series(ss, &mut chart)?;
    draw_stream_group(
        &ss.stream_buffer_writes,
        "Stream buffer write",
        MAGENTA,
        &mut chart,
    )?;
    draw_line(
        &ss.sum_stream_buffer_writes,
        Some("Cumulative stream buffer writes"),
        RGBColor(255, 0, 0),
        &mut chart,
    )?;
    draw_stream_group(
        &ss.stream_buffer_dropped,
        "Stream buffer dropped",
        ORANGE,
        &mut chart,
    )?;
    draw_line(
        &ss.sum_stream_buffer_dropped,
        Some("Cumulative stream buffer dropped"),
        RGBColor(0, 0, 255),
        &mut chart,
    )?;
    draw_stream_group(
        &ss.sent_stream_frames_series,
        "Sent stream data",
        PURPLE_500,
        &mut chart,
    )?;
    draw_line(
        &ss.received_max_data,
        Some("Cumulative received MAX_DATA"),
        MID_GREY,
        &mut chart,
    )?;
    draw_line(
        &ss.sum_received_stream_max_data,
        Some("Cumulative received MAX_STREAM_DATA"),
        MUSTARD,
        &mut chart,
    )?;

    draw_legend(params, &mut chart)?;
    Ok(chart)
}

#[cfg(not(target_arch = "wasm32"))]
fn draw_stream_send_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, axis: &XYMinMax, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
>
where
    DB::ErrorType: 'static,
{
    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption(
            "Stream sends",
            chart_subtitle_style(&params.colors.caption),
        );
    }

    let mut chart = builder.build_cartesian_2d(axis.x.clone(), axis.y_range())?;

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Data (bytes)",
        false,
        &mut chart,
    )?;

    draw_line(
        &ss.sum_stream_buffer_writes,
        Some("Cumulative stream buffer writes"),
        RGBColor(255, 0, 0),
        &mut chart,
    )?;
    draw_line(
        &ss.sum_stream_buffer_dropped,
        Some("Cumulative stream buffer dropped"),
        RGBColor(0, 0, 255),
        &mut chart,
    )?;
    draw_stream_group(
        &ss.stream_buffer_writes,
        "Stream buffer write",
        MAGENTA,
        &mut chart,
    )?;
    draw_stream_group(
        &ss.stream_buffer_dropped,
        "Stream buffer dropped",
        ORANGE,
        &mut chart,
    )?;
    draw_stream_group(
        &ss.sent_stream_frames_series,
        "Sent stream data",
        PURPLE_500,
        &mut chart,
    )?;
    draw_line(
        &ss.received_max_data,
        Some("Cumulative received MAX_DATA"),
        MID_GREY,
        &mut chart,
    )?;
    draw_line(
        &ss.sum_received_stream_max_data,
        Some("Cumulative received MAX_STREAM_DATA"),
        MUSTARD,
        &mut chart,
    )?;

    draw_legend(params, &mut chart)?;
    Ok(chart)
}

#[cfg(not(target_arch = "wasm32"))]
fn draw_stream_recv_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, axis: &XYMinMax, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
>
where
    DB::ErrorType: 'static,
{
    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption(
            "Stream receives",
            chart_subtitle_style(&params.colors.caption),
        );
    }

    let mut chart = builder.build_cartesian_2d(axis.x.clone(), axis.y_range())?;

    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Data (bytes)",
        false,
        &mut chart,
    )?;

    draw_receive_panel_series(ss, &mut chart)?;

    draw_legend(params, &mut chart)?;
    Ok(chart)
}

#[cfg(not(target_arch = "wasm32"))]
/// Render the complete connection overview PNG.
///
/// # Errors
/// Returns backend, layout, timestamp and filesystem failures.
pub fn plot_connection_overview(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &OverviewChartOutputType,
) -> Result<(), Box<dyn Error>> {
    let chart_config = ChartConfig::new(
        "conn-overview",
        filename,
        &params.clamp,
        ds,
        &ty.clone().into(),
    );
    if !matches!(ty, OverviewChartOutputType::Png { .. }) {
        return Err(invalid_chart(
            "native connection overview requires PNG output",
        )
        .into());
    }
    let chart_path = chart_config.chart_filepath();
    let root = bitmap_area(
        &chart_path,
        params.chart_size,
        params.colors,
        params.chart_margin,
    )?;

    let (top_margin, bottom) = root.split_vertically((5).percent());
    let (stream_plots, cwnd_rtt_area) = bottom.split_vertically((60).percent());
    let (stream_send_plot, stream_recv_plot) =
        stream_plots.split_vertically((50).percent());
    let (congestion_plot, rtt_plot) =
        cwnd_rtt_area.split_vertically((60).percent());

    let send_y = params
        .clamp
        .stream_y_max
        .unwrap_or(ss.y_max_stream_send_plot);
    let recv_y = params
        .clamp
        .stream_y_max
        .unwrap_or(ss.y_max_stream_recv_plot);
    let stream_send_axis = XYMinMax::init(params, ss, send_y)?;
    let stream_recv_axis = XYMinMax::init(params, ss, recv_y)?;
    let cwnd_max = params
        .cwnd_y_max
        .unwrap_or_else(|| {
            let original = ss.y_max_congestion_plot;
            original.saturating_add(original / 10)
        })
        .max(1);
    let common_axis = super::minmax::XYMinMax::init(
        checked_time_range(ss.sent_x_min, ss.sent_x_max, &params.clamp)?,
        None,
        None,
        0..cwnd_max,
    );

    top_margin.draw_text(
        &format!("{filename} Connection overview"),
        &chart_title_style(&params.colors.caption),
        (0, 0),
    )?;
    draw_stream_send_plot(params, &stream_send_axis, ss, &stream_send_plot)?;
    draw_stream_recv_plot(params, &stream_recv_axis, ss, &stream_recv_plot)?;
    draw_congestion_plot(params, &common_axis, ss, ds, &congestion_plot)?;
    draw_rtt_plot(params, &common_axis, ss, &rtt_plot)?;
    root.present()?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
/// Render the connection-overview stream view into the browser canvas.
///
/// # Errors
/// Returns missing canvas, validation and Plotters drawing errors.
pub fn plot_main_plot<'a>(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, canvas_id: &str,
) -> Result<
    ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
> {
    let root = canvas_area(canvas_id, params.colors, params.chart_margin)?;
    let stream_y = params.clamp.stream_y_max.unwrap_or_else(|| {
        ss.y_max_stream_send_plot.max(ss.y_max_stream_recv_plot)
    });
    let axis = XYMinMax::init(params, ss, stream_y)?;
    draw_main_plot(filename, params, &axis, ss, &root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plots::fallible::test_support::chart_params;
    use crate::plots::fallible::test_support::TempCharts;
    use crate::plots::ClampParams;

    fn render_stream_group(
        streams: &BTreeMap<u64, Vec<QlogPointu64>>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        use plotters::drawing::IntoDrawingArea;
        use plotters::prelude::BitMapBackend;

        let mut pixels = vec![0_u8; 480 * 360 * 3];
        {
            let root = BitMapBackend::with_buffer(&mut pixels, (480, 360))
                .into_drawing_area();
            let mut chart = ChartBuilder::on(&root)
                .build_cartesian_2d(0.0..5.0, 0_u64..10)?;
            draw_stream_group(streams, "stream", BLUE, &mut chart)?;
            chart.configure_series_labels().draw()?;
            root.present()?;
        }
        Ok(pixels)
    }

    #[test]
    fn stream_groups_skip_empty_entries_without_stealing_legend_label(
    ) -> Result<(), Box<dyn Error>> {
        let nonempty = BTreeMap::from([
            (5, vec![(1.0, 3), (2.0, 4)]),
            (8, vec![(2.0, 5), (4.0, 6)]),
        ]);
        let mut with_empty = nonempty.clone();
        with_empty.insert(1, Vec::new());
        with_empty.insert(7, Vec::new());
        with_empty.insert(12, Vec::new());

        assert_eq!(
            render_stream_group(&nonempty)?,
            render_stream_group(&with_empty)?
        );
        // Nonempty stream data should change the rendered content.
        assert_ne!(
            render_stream_group(&nonempty)?,
            render_stream_group(&BTreeMap::new())?
        );
        Ok(())
    }

    #[test]
    fn empty_overview_renders_all_panels_and_bad_output_returns_error(
    ) -> Result<(), Box<dyn Error>> {
        let params = chart_params();
        let ss = SeriesStore::default();
        let ds = Datastore::default();
        let out = TempCharts::new()?;
        let output = OverviewChartOutputType::Png {
            output_dir: out.0.to_string_lossy().into_owned(),
            cwnd_y_max: None,
            stream_y_max: None,
        };
        plot_connection_overview(&params, "empty", &ss, &ds, &output)?;
        let png = out.only_file()?;
        assert_eq!(image::image_dimensions(png)?, (1000, 900));
        let blocked = TempCharts::new()?;
        let obstacle = blocked.0.join("not-a-directory");
        std::fs::write(&obstacle, b"block")?;
        let output = OverviewChartOutputType::Png {
            output_dir: obstacle.to_string_lossy().into_owned(),
            cwnd_y_max: None,
            stream_y_max: None,
        };
        assert!(
            plot_connection_overview(&params, "blocked", &ss, &ds, &output)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn overview_axes_include_received_times_and_reject_reversed_clamps(
    ) -> Result<(), Box<dyn Error>> {
        let series = SeriesStore {
            sent_x_min: 9.0,
            sent_x_max: 10.0,
            received_x_min: 2.0,
            received_x_max: 14.0,
            ..SeriesStore::default()
        };
        let params = chart_params();
        assert_eq!(XYMinMax::init(&params, &series, 0)?.x, 2.0..14.0);
        assert_eq!(XYMinMax::init(&params, &series, 0)?.y_range(), 0..1);
        let invalid = PlotParameters {
            clamp: ClampParams {
                start: Some(20.0),
                ..ClampParams::default()
            },
            ..chart_params()
        };
        assert!(XYMinMax::init(&invalid, &series, 1).is_err());
        Ok(())
    }
}
