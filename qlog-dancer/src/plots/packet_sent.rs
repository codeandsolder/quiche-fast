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
use plotters::drawing::DrawingAreaErrorKind;
use plotters::prelude::AsRelative;
use plotters::prelude::Cartesian2d;
use plotters::prelude::ChartBuilder;
use plotters::prelude::ChartContext;
use plotters::prelude::Color;
use plotters::prelude::Cross;
use plotters::prelude::DrawingBackend;
use plotters::prelude::LineSeries;
use plotters::prelude::PathElement;
use plotters::prelude::RGBColor;
use plotters::prelude::SeriesLabelPosition;
use plotters::prelude::BLACK;
use plotters::prelude::BLUE;
use plotters::prelude::GREEN;
#[cfg(target_arch = "wasm32")]
use plotters_canvas::CanvasBackend;

use crate::plots::chart_label_style;
use crate::plots::chart_subtitle_style;
use crate::plots::chart_title_style;
use crate::plots::colors::ORANGE;
use crate::plots::colors::PURPLE;
use crate::plots::colors::SOFT_PINK;
use crate::plots::colors::TAUPE;
use crate::plots::colors::TEAL;
use crate::plots::draw_line;
use crate::plots::ChartConfig;
use crate::plots::ChartOutputType;
use crate::plots::ClampParams;
use crate::plots::PlotParameters;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;
use crate::QlogPointu64;

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

    const fn y_range(&self) -> Range<u64> {
        self.y_min..self.y_max
    }
}

const Y_WIGGLE: f64 = 1.1;

/// Pad integer plot maxima without converting `u64` to lossy `f64`.
fn padded_upper(value: u64) -> u64 {
    value.saturating_add(value.div_ceil(10)).max(1)
}

/// The cumulative-count chart is not a packet-number chart. Packet numbers
/// can start arbitrarily high or contain gaps unrelated to observed counts.
fn packet_count_upper(ss: &SeriesStore) -> u64 {
    let largest_count = ss
        .onertt_packet_sent_aggregate_count
        .iter()
        .chain(&ss.onertt_packet_delivered_aggregate_count)
        .chain(&ss.onertt_packet_without_observed_ack_aggregate_count)
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(0);
    padded_upper(largest_count)
}

/// Series metadata is data, not repeated draw/label/legend code.
type LabeledPacketLine<'a> = (&'a [QlogPointu64], &'static str, RGBColor);

fn draw_packet_lines<DB: DrawingBackend>(
    chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    lines: &[LabeledPacketLine<'_>],
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    for &(series, label, color) in lines {
        draw_line(series, Some(label), color, chart)?;
    }
    Ok(())
}

/// Draw packet-number timelines for transmitted or received 1-RTT packets.
///
/// # Errors
/// Returns invalid chart ranges and drawing backend failures.
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

        (format!("{filename} Packet Sent timeline"), y_max)
    } else {
        let y_max = padded_upper(ss.y_max_onertt_pkt_received_plot);

        (format!("{filename} Packet Received timeline"), y_max)
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
        draw_line(
            &ss.onertt_packet_created,
            Some("packet created"),
            GREEN,
            &mut chart,
        )?;

        draw_line(
            &ss.onertt_packet_sent,
            Some("packet sent (packet number)"),
            ORANGE,
            &mut chart,
        )?;

        let packets_without_ack = ss
            .onertt_packet_without_observed_ack
            .iter()
            .map(|point| Cross::new(*point, 2, PURPLE));

        chart
            .draw_series(packets_without_ack)?
            .label("packet without observed ACK (not proven lost)")
            .legend(|(x, y)| PathElement::new([(x, y), (x + 20, y)], PURPLE));
    } else {
        let missing_packets_line = ss
            .netlog_missing_packets
            .iter()
            .map(|t| PathElement::new([(*t, 0), (*t, y_max)], BLUE));

        chart
            .draw_series(missing_packets_line)?
            .label("change in missing-packet report")
            .legend(|(x, y)| PathElement::new([(x, y), (x + 20, y)], BLUE));

        draw_line(
            &ss.onertt_packet_received,
            Some("packet received"),
            ORANGE,
            &mut chart,
        )?;
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

/// Render cumulative packet counts, independently of packet-number numbering.
///
/// # Errors
/// Returns invalid ranges or backend drawing failures.
pub fn draw_packet_sent_ack_status_count_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
>
where
    DB::ErrorType: 'static,
{
    let caption = "Packet observations by eventual ACK status";

    let y_max = packet_count_upper(ss);

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

    draw_packet_lines(&mut chart, &[
        (
            ss.onertt_packet_sent_aggregate_count.as_slice(),
            "observed sent packets",
            TAUPE,
        ),
        (
            ss.onertt_packet_delivered_aggregate_count.as_slice(),
            "eventually ACK-confirmed",
            BLUE,
        ),
        (
            ss.onertt_packet_without_observed_ack_aggregate_count
                .as_slice(),
            "without observed ACK",
            SOFT_PINK,
        ),
    ])?;

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

    let lines = LineSeries::new(
        ss.onertt_packet_created_sent_delta.iter().copied(),
        BLUE,
    );

    chart
        .draw_series(lines)?
        .label("packet created/sent delta")
        .legend(|(x, y)| PathElement::new([(x, y), (x + 20, y)], BLACK));

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

    draw_packet_lines(&mut chart, &[
        (ss.local_pacing_rate.as_slice(), "pacing rate", PURPLE),
        (ss.local_delivery_rate.as_slice(), "delivery rate", TEAL),
        (ss.local_send_rate.as_slice(), "send rate", ORANGE),
        (ss.local_ack_rate.as_slice(), "ack rate", BLUE),
    ])?;

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
    let chart_config =
        ChartConfig::new("packet-sent", filename, &params.clamp, ds, ty);

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
    draw_packet_sent_ack_status_count_plot(params, ss, &counts)?;
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
pub fn plot_packet_timeline_canvas<'a>(
    is_sent: bool, params: &PlotParameters, filename: &str, ss: &SeriesStore,
    canvas_id: &str,
) -> Result<
    ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
> {
    let root = canvas_area(canvas_id, params.colors, params.chart_margin)?;
    draw_packet_sent_received_plot(is_sent, filename, params, ss, &root)
}

#[cfg(target_arch = "wasm32")]
/// Render packet-send cumulative counts.
///
/// # Errors
/// Returns browser canvas/backend or invalid chart errors.
pub fn plot_packet_sent_ack_status_count_plot<'a>(
    params: &PlotParameters, ss: &SeriesStore, canvas_id: &str,
) -> Result<
    ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
> {
    let root = canvas_area(canvas_id, params.colors, params.chart_margin)?;
    draw_packet_sent_ack_status_count_plot(params, ss, &root)
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
    use crate::plots::AreaMargin;
    use crate::plots::ChartMargin;
    use crate::plots::ChartSize;
    use crate::plots::PlotColors;
    use plotters::drawing::IntoDrawingArea;
    use plotters::prelude::BitMapBackend;

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
    fn cumulative_packet_count_axis_uses_counts_not_packet_numbers(
    ) -> Result<(), Box<dyn Error>> {
        let mut series = SeriesStore {
            sent_x_min: 0.0,
            sent_x_max: 5.0,
            y_max_onertt_pkt_sent_plot: 1_000_000,
            onertt_packet_sent_aggregate_count: vec![(1.0, 2), (2.0, 3)],
            onertt_packet_delivered_aggregate_count: vec![(2.0, 1)],
            onertt_packet_without_observed_ack_aggregate_count: vec![(2.0, 2)],
            ..SeriesStore::default()
        };
        assert_eq!(packet_count_upper(&series), 4);
        let mut pixels = vec![0_u8; 720 * 540 * 3];
        let area = BitMapBackend::with_buffer(&mut pixels, (720, 540))
            .into_drawing_area();
        let chart = draw_packet_sent_ack_status_count_plot(
            &test_params(),
            &series,
            &area,
        )?;
        assert_eq!(chart.y_range(), 0..4);
        drop(chart);

        // Counts can also exceed the packet-number maximum, e.g. when
        // packet numbering is deliberately reset or the series is imported.
        series
            .onertt_packet_without_observed_ack_aggregate_count
            .push((3.0, 37));
        assert_eq!(packet_count_upper(&series), 41);
        series
            .onertt_packet_delivered_aggregate_count
            .push((4.0, u64::MAX));
        assert_eq!(packet_count_upper(&series), u64::MAX);
        assert_eq!(packet_count_upper(&SeriesStore::default()), 1);
        Ok(())
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

        let temp_dir = TempCharts::new()?;
        let blocker = temp_dir.0.join("file-instead-of-directory");
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
