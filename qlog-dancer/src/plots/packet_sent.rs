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
use crate::plots::fallible::draw_mesh as draw_mesh_checked;
use crate::plots::fallible::invalid_chart;
use std::error::Error;
use std::io;
use std::ops::Range;

use plotters::coord::types::RangedCoordf64;
use plotters::coord::types::RangedCoordu64;
use plotters::coord::Shift;

use crate::plots::colors::*;
use crate::plots::*;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

struct XYMinMax {
    pub x: Range<f64>,
    pub y_min: u64,
    pub y_max: u64,
}

impl XYMinMax {
    fn init(
        params: &PlotParameters, ss: &SeriesStore, y_max: u64, is_sent: bool,
    ) -> io::Result<Self> {
        let (min, max) = if is_sent {
            (ss.sent_x_min, ss.sent_x_max)
        } else {
            (ss.received_x_min, ss.received_x_max)
        };
        let x = checked_time_range(min, max, &params.clamp)?;
        Ok(Self {
            x,
            y_min: 0,
            y_max: y_max.max(1),
        })
    }

    fn y_range(&self) -> Range<u64> {
        self.y_min..self.y_max
    }
}

const Y_WIGGLE: f64 = 1.1;

/// Pad integer plot maxima without converting `u64` to lossy `f64`.
fn padded_upper(value: u64) -> u64 {
    value.saturating_add(value.div_ceil(10)).max(1)
}

pub fn draw_packet_sent_received_plot<'a, DB: DrawingBackend + 'a>(
    is_sent: bool, filename: &str, params: &PlotParameters, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
>
where
    DB::ErrorType: 'static,
{
    let (caption, y_max) = if is_sent {
        let y_max = padded_upper(ss.y_max_onertt_pkt_sent_plot);

        (format!("{} Packet Sent timeline", filename), y_max)
    } else {
        let y_max = padded_upper(ss.y_max_onertt_pkt_received_plot);

        (format!("{} Packet Received timeline", filename), y_max)
    };

    let axis = XYMinMax::init(params, ss, y_max, is_sent)?;

    let mut builder = ChartBuilder::on(plot);

    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption(caption, chart_title_style(&params.colors.caption));
    }

    let mut chart = builder.build_cartesian_2d(axis.x.clone(), axis.y_range())?;

    draw_mesh_checked(
        &params.colors,
        "Relative time (ms)",
        "Packet Number",
        params.display_minor_lines,
        &mut chart,
    )?;

    if is_sent {
        chart
            .draw_series(LineSeries::new(
                ss.onertt_packet_created.iter().copied(),
                GREEN,
            ))?
            .label("packet created")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], GREEN));

        chart
            .draw_series(LineSeries::new(
                ss.onertt_packet_sent.iter().copied(),
                ORANGE,
            ))?
            .label("packet sent (packet number)")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], ORANGE));

        let packet_losses = ss
            .onertt_packet_lost_hacky
            .iter()
            .map(|point| Cross::new(*point, 2, PURPLE));

        chart
            .draw_series(packet_losses)?
            .label("packet lost (packet number)")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], PURPLE));
    } else {
        let missing_packets_line = ss
            .netlog_missing_packets
            .iter()
            .map(|t| PathElement::new([(*t, 0), (*t, y_max)], BLUE));

        chart
            .draw_series(missing_packets_line)?
            .label("missing packets")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLUE));

        chart
            .draw_series(LineSeries::new(
                ss.onertt_packet_received.iter().copied(),
                ORANGE,
            ))?
            .label("packet received")
            .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], ORANGE));
    }

    if params.display_legend {
        chart
            .configure_series_labels()
            .label_font(chart_label_style(&params.colors.caption))
            .background_style(params.colors.fill.mix(0.8))
            .border_style(params.colors.axis)
            .position(SeriesLabelPosition::UpperLeft)
            .draw()?;
    }

    Ok(chart)
}

pub fn draw_packet_sent_lost_delivered_count_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
>
where
    DB::ErrorType: 'static,
{
    let caption = "Packet sent/lost/delivered counts";

    let y_max = padded_upper(ss.y_max_onertt_pkt_sent_plot);

    let axis = XYMinMax::init(params, ss, y_max, true)?;

    let mut builder = ChartBuilder::on(plot);

    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption(caption, chart_subtitle_style(&params.colors.caption));
    }

    let mut chart = builder.build_cartesian_2d(axis.x.clone(), axis.y_range())?;

    draw_mesh_checked(
        &params.colors,
        "Relative time (ms)",
        "Packet Count",
        params.display_minor_lines,
        &mut chart,
    )?;

    chart
        .draw_series(LineSeries::new(
            ss.onertt_packet_sent_aggregate_count.iter().copied(),
            TAUPE,
        ))?
        .label("packet sent count")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], TAUPE));

    chart
        .draw_series(LineSeries::new(
            ss.onertt_packet_delivered_aggregate_count.iter().copied(),
            BLUE,
        ))?
        .label("packet delivered count")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLUE));

    chart
        .draw_series(LineSeries::new(
            ss.onertt_packet_lost_aggregate_count.iter().copied(),
            SOFT_PINK,
        ))?
        .label("packet lost count")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], SOFT_PINK));

    if params.display_legend {
        chart
            .configure_series_labels()
            .label_font(chart_label_style(&params.colors.caption))
            .background_style(params.colors.fill.mix(0.8))
            .border_style(params.colors.axis)
            .position(SeriesLabelPosition::UpperLeft)
            .draw()?;
    }

    Ok(chart)
}

fn draw_delta_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordu64, RangedCoordf64>>,
    Box<dyn Error>,
>
where
    DB::ErrorType: 'static,
{
    let lower = ss.y_min_onertt_packet_created_sent_delta;
    let upper = ss.y_max_onertt_packet_created_sent_delta * Y_WIGGLE;
    let y_range = checked_time_range(lower, upper, &ClampParams::default())?;

    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption(
            "Packet created/sent Delta timing",
            chart_subtitle_style(&params.colors.caption),
        );
    }

    let mut chart = builder
        .build_cartesian_2d(0..ss.y_max_onertt_pkt_sent_plot.max(1), y_range)?;

    draw_mesh_checked(
        &params.colors,
        "Packet Number",
        "Delta time (ms)",
        params.display_minor_lines,
        &mut chart,
    )?;

    // Draw the series

    // not sure best way to render these, lines or points?
    let lines = LineSeries::new(
        ss.onertt_packet_created_sent_delta.iter().copied(),
        BLUE,
    );

    let _crosses = ss
        .onertt_packet_created_sent_delta
        .iter()
        .map(|point| Cross::new(*point, 2, BLUE));

    chart
        .draw_series(lines)?
        .label("packet created/sent delta")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLACK));

    if params.display_legend {
        chart
            .configure_series_labels()
            .label_font(chart_label_style(&params.colors.caption))
            .background_style(params.colors.fill.mix(0.8))
            .border_style(params.colors.axis)
            .position(SeriesLabelPosition::MiddleMiddle)
            .draw()?;
    }

    Ok(chart)
}

fn draw_pacing_rate_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, ss: &SeriesStore, _ds: &Datastore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
>
where
    DB::ErrorType: 'static,
{
    let y_max = ss
        .max_pacing_rate
        .max(ss.max_delivery_rate)
        .max(ss.max_send_rate)
        .max(ss.max_ack_rate);
    let y_max = padded_upper(y_max);
    let axis = XYMinMax::init(params, ss, y_max, true)?;
    let mut builder = ChartBuilder::on(plot);

    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);

    if params.display_chart_title {
        builder.caption(
            "Pacing Rate vs Delivery Rate",
            chart_subtitle_style(&params.colors.caption),
        );
    }

    let mut chart = builder.build_cartesian_2d(axis.x.clone(), axis.y_range())?;

    draw_mesh_checked(
        &params.colors,
        "Relative time (ms)",
        "Rate (bytes/sec)",
        params.display_minor_lines,
        &mut chart,
    )?;

    // Draw all 4 rate series
    chart
        .draw_series(LineSeries::new(
            ss.local_pacing_rate.iter().copied(),
            PURPLE,
        ))?
        .label("pacing rate")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], PURPLE));

    chart
        .draw_series(LineSeries::new(
            ss.local_delivery_rate.iter().copied(),
            TEAL,
        ))?
        .label("delivery rate")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], TEAL));

    chart
        .draw_series(LineSeries::new(ss.local_send_rate.iter().copied(), ORANGE))?
        .label("send rate")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], ORANGE));

    chart
        .draw_series(LineSeries::new(ss.local_ack_rate.iter().copied(), BLUE))?
        .label("ack rate")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], BLUE));

    if params.display_legend {
        chart
            .configure_series_labels()
            .label_font(chart_label_style(&params.colors.caption))
            .background_style(params.colors.fill.mix(0.8))
            .border_style(params.colors.axis)
            .position(SeriesLabelPosition::UpperLeft)
            .draw()?;
    }

    Ok(chart)
}

/// Render the four-panel packet-send PNG or canvas plot.
///
/// # Errors
/// Returns invalid input, filesystem/backend and drawing errors to the caller.
pub fn plot_packet_sent(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &ChartOutputType,
) -> Result<(), Box<dyn Error>> {
    let chart_config = ChartConfig {
        title: "packet-sent".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: ty.clone(),
    };

    #[cfg(not(target_arch = "wasm32"))]
    let chart_path = match ty {
        ChartOutputType::Png { .. } => chart_config.chart_filepath(),
        ChartOutputType::Canvas { .. } =>
            return Err(
                invalid_chart("native packet chart requires PNG output").into()
            ),
    };
    #[cfg(not(target_arch = "wasm32"))]
    let root = bitmap_area(
        &chart_path,
        params.chart_size,
        params.colors,
        params.chart_margin,
    )?;

    #[cfg(target_arch = "wasm32")]
    let canvas_id = chart_config.canvas_id().ok_or_else(|| {
        invalid_chart("browser packet chart requires canvas output")
    })?;
    #[cfg(target_arch = "wasm32")]
    let root = canvas_area(&canvas_id, params.colors, params.chart_margin)?;

    let (raw_timings, remainder) = root.split_vertically((33).percent());
    let (counts, remainder) = remainder.split_vertically((33).percent());
    let (delta_timings, pacing_rate) = remainder.split_vertically((50).percent());

    draw_packet_sent_received_plot(true, filename, params, ss, &raw_timings)?;
    draw_packet_sent_lost_delivered_count_plot(params, ss, &counts)?;
    draw_delta_plot(params, ss, &delta_timings)?;
    draw_pacing_rate_plot(params, ss, ds, &pacing_rate)?;
    root.present()?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
/// Render packet-send timeline, returning chart bounds only upon success.
///
/// # Errors
/// Returns browser canvas/backend or invalid chart errors.
pub fn plot_packet_sent_plot_canvas<'a>(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, canvas_id: &str,
) -> Result<
    ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
> {
    let root = canvas_area(canvas_id, params.colors, params.chart_margin)?;
    draw_packet_sent_received_plot(true, filename, params, ss, &root)
}

#[cfg(target_arch = "wasm32")]
/// Render packet-send cumulative counts.
///
/// # Errors
/// Returns browser canvas/backend or invalid chart errors.
pub fn plot_packet_sent_lost_delivered_count_plot<'a>(
    params: &PlotParameters, ss: &SeriesStore, canvas_id: &str,
) -> Result<
    ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
> {
    let root = canvas_area(canvas_id, params.colors, params.chart_margin)?;
    draw_packet_sent_lost_delivered_count_plot(params, ss, &root)
}

#[cfg(target_arch = "wasm32")]
/// Render packet-send delta chart.
///
/// # Errors
/// Returns browser canvas/backend or invalid chart errors.
pub fn plot_packet_sent_delta_plot_canvas<'a>(
    params: &PlotParameters, ss: &SeriesStore, canvas_id: &str,
) -> Result<
    ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordu64, RangedCoordf64>>,
    Box<dyn Error>,
> {
    let root = canvas_area(canvas_id, params.colors, params.chart_margin)?;
    draw_delta_plot(params, ss, &root)
}

#[cfg(target_arch = "wasm32")]
/// Render packet-send pacing-rate chart.
///
/// # Errors
/// Returns browser canvas/backend or invalid chart errors.
pub fn plot_packet_sent_pacing_rate_plot_canvas<'a>(
    params: &PlotParameters, ss: &SeriesStore, ds: &Datastore, canvas_id: &str,
) -> Result<
    ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
> {
    let root = canvas_area(canvas_id, params.colors, params.chart_margin)?;
    draw_pacing_rate_plot(params, ss, ds, &root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plots::fallible::test_support::TempCharts;

    fn test_params() -> PlotParameters {
        PlotParameters {
            clamp: ClampParams::default(),
            cwnd_y_max: None,
            chart_size: ChartSize {
                width: 750,
                height: 950,
            },
            colors: PlotColors::default(),
            chart_margin: ChartMargin::default(),
            area_margin: AreaMargin { x: 35, y: 45 },
            display_chart_title: false,
            display_legend: true,
            display_minor_lines: false,
        }
    }

    #[test]
    fn packet_y_padding_handles_zero_small_and_max_without_losing_precision() {
        assert_eq!(padded_upper(0), 1);
        assert_eq!(padded_upper(9), 10);
        assert_eq!(padded_upper(10), 11);
        assert_eq!(padded_upper(u64::MAX), u64::MAX);
    }

    #[test]
    fn received_timeline_uses_received_not_sent_time_range(
    ) -> Result<(), Box<dyn Error>> {
        let mut pixels = vec![0_u8; 720 * 540 * 3];
        let root = BitMapBackend::with_buffer(&mut pixels, (720, 540))
            .into_drawing_area();
        let series = SeriesStore {
            sent_x_min: 1.0,
            sent_x_max: 2.0,
            received_x_min: 15.0,
            received_x_max: 30.0,
            ..SeriesStore::default()
        };
        let chart = draw_packet_sent_received_plot(
            false,
            "test",
            &test_params(),
            &series,
            &root,
        )?;
        assert_eq!(chart.x_range(), 15.0..30.0);
        Ok(())
    }

    #[test]
    fn empty_packet_charts_render_and_output_failures_are_errors(
    ) -> Result<(), Box<dyn Error>> {
        let out = TempCharts::new()?;
        let series = SeriesStore::default();
        let ds = Datastore::default();
        plot_packet_sent(&test_params(), "empty", &series, &ds, &out.output())?;
        let png = std::fs::read(out.only_file()?)?;
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));

        let blocked = TempCharts::new()?;
        let blocker = blocked.0.join("file-instead-of-directory");
        std::fs::write(&blocker, b"no mkdir")?;
        let ty = ChartOutputType::Png {
            output_dir: blocker.to_string_lossy().into_owned(),
            cwnd_y_max: None,
            stream_y_max: None,
        };
        assert!(
            plot_packet_sent(&test_params(), "blocked", &series, &ds, &ty)
                .is_err()
        );
        Ok(())
    }
}
