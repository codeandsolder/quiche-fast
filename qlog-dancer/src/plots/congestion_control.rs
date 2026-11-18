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

#[cfg(target_arch = "wasm32")]
use crate::plots::fallible::canvas_area;
use crate::plots::fallible::checked_time_range;
use crate::plots::fallible::invalid_chart;
use plotters::coord::types::RangedCoordf64;
use plotters::coord::types::RangedCoordu64;
use plotters::coord::Shift;
use plotters::prelude::Cartesian2d;
use plotters::prelude::ChartBuilder;
use plotters::prelude::ChartContext;
use plotters::prelude::Color;
use plotters::prelude::DrawingBackend;
use plotters::prelude::EmptyElement;
use plotters::prelude::IntoFont;
use plotters::prelude::LineSeries;
use plotters::prelude::RGBColor;
use plotters::prelude::Rectangle;
use plotters::prelude::SeriesLabelPosition;
use plotters::prelude::Text;
use plotters::prelude::BLACK;
use plotters::prelude::WHITE;
use plotters::style::full_palette::PURPLE_500;
#[cfg(target_arch = "wasm32")]
use plotters_canvas::CanvasBackend;
use std::error::Error;

use crate::plots::chart_label_style;
use crate::plots::chart_subtitle_style;
use crate::plots::colors::ORANGE;
use crate::plots::colors::TAUPE;
use crate::plots::draw_line;
use crate::plots::draw_mesh;
use crate::plots::PlotParameters;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

use super::minmax::XYMinMax;

/// Render congestion-control state transitions and quantitative series.
///
/// # Errors
/// Returns invalid ranges, malformed labels and backend drawing errors.
pub fn draw_congestion_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, axis: &XYMinMax<u64>, ss: &SeriesStore,
    ds: &Datastore, plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
>
where
    DB::ErrorType: 'static,
{
    let range = checked_time_range(axis.x.min, axis.x.max, &params.clamp)?;
    let original_max = axis.y_range.end.max(1);
    let extended_max = original_max.saturating_add(original_max / 2);
    let y_range = 0..original_max;
    let extended_y = 0..extended_max;
    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);
    if params.display_chart_title {
        builder
            .caption("Congestion", chart_subtitle_style(&params.colors.caption));
    }
    let mut chart = builder.build_cartesian_2d(range, extended_y.clone())?;
    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Data (bytes)",
        false,
        &mut chart,
    )?;
    draw_cc_updates(
        &ds.congestion_state_updates,
        y_range,
        extended_y,
        &mut chart,
    )?;
    draw_line(
        &ss.local_bytes_in_flight,
        Some("bytes in flight"),
        TAUPE,
        &mut chart,
    )?;
    draw_line(&ss.local_cwnd, Some("cwnd"), PURPLE_500, &mut chart)?;
    draw_line(&ss.local_ssthresh, Some("ssthresh"), ORANGE, &mut chart)?;
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

#[cfg(target_arch = "wasm32")]
/// Render a browser congestion-control chart.
///
/// # Errors
/// Returns missing canvas, invalid axes or Plotters failures.
pub fn plot_cc_plot<'a>(
    params: &PlotParameters, ss: &SeriesStore, ds: &Datastore, canvas_id: &str,
) -> Result<
    ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
> {
    let root = canvas_area(canvas_id, params.colors, params.chart_margin)?;
    let cwnd_max = params
        .cwnd_y_max
        .unwrap_or_else(|| {
            let maximum = ss.y_max_congestion_plot;
            maximum.saturating_add(maximum / 10)
        })
        .max(1);
    let axis = super::minmax::XYMinMax::init(
        checked_time_range(ss.sent_x_min, ss.sent_x_max, &params.clamp)?,
        None,
        None,
        0..cwnd_max,
    );
    draw_congestion_plot(params, &axis, ss, ds, &root)
}

fn draw_cc_updates<DB: DrawingBackend>(
    data: &[(f64, u64, String)], y_range: std::ops::Range<u64>,
    y_range_extended: std::ops::Range<u64>,
    chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> Result<(), Box<dyn Error>>
where
    DB::ErrorType: 'static,
{
    let positions = [0, 1, 2, 3, 4].map(|index| {
        y_range
            .end
            .saturating_add(y_range.end.saturating_mul(index) / 10)
    });
    // Reverse event order to retain labels on top of earlier vertical lines.
    for (index, event) in data.iter().rev().enumerate() {
        let (time, _, name) = event;
        if !time.is_finite() {
            return Err(invalid_chart(
                "congestion state timestamps must be finite",
            )
            .into());
        }
        let color = cc_state_to_color(name);
        let text_right = label_right_edge(name.len())?;
        chart.draw_series(LineSeries::new(
            [
                (*time, y_range_extended.start),
                (*time, y_range_extended.end),
            ],
            color,
        ))?;
        let label = EmptyElement::at((*time, positions[index % positions.len()])) +
            Rectangle::new(
                [(1, -2), (text_right, 12)],
                WHITE.mix(0.7).filled(),
            ) +
            Text::new(
                name.clone(),
                (1, 0),
                ("sans-serif", 12.0).into_font().color(&color),
            );
        chart.plotting_area().draw(&label)?;
    }
    Ok(())
}

/// Text labels are positioned relative to the event, with a one-pixel
/// rectangle inset. Check the *final* x coordinate to avoid i32 overflow.
fn label_right_edge(byte_len: usize) -> std::io::Result<i32> {
    i32::try_from(byte_len)
        .ok()
        .and_then(|len| len.checked_mul(6))
        .and_then(|width| width.checked_add(1))
        .ok_or_else(|| invalid_chart("congestion state label is too wide"))
}

// Equivalent congestion-control states share colors across Cubic/Reno and BBR.
fn cc_state_to_color(cc_state: &str) -> RGBColor {
    match cc_state {
        "slow_start" | "bbr_startup" => RGBColor(204, 81, 81),
        "recovery" | "bbr_drain" => RGBColor(127, 51, 51),
        "congestion_avoidance" | "bbr_probe_bw" => RGBColor(81, 204, 204),
        "bbr_probe_rtt" => RGBColor(51, 127, 127),
        _ => BLACK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plots::fallible::test_support::chart_params;
    use plotters::drawing::IntoDrawingArea;
    use plotters::prelude::BitMapBackend;

    #[test]
    fn congestion_state_colors_are_shared_across_algorithms() {
        for (cubic, bbr, expected) in [
            ("slow_start", "bbr_startup", RGBColor(204, 81, 81)),
            ("recovery", "bbr_drain", RGBColor(127, 51, 51)),
            (
                "congestion_avoidance",
                "bbr_probe_bw",
                RGBColor(81, 204, 204),
            ),
        ] {
            assert_eq!(cc_state_to_color(cubic), expected);
            assert_eq!(cc_state_to_color(bbr), expected);
        }
        assert_eq!(cc_state_to_color("bbr_probe_rtt"), RGBColor(51, 127, 127));
        assert_eq!(cc_state_to_color("unknown"), BLACK);
    }

    #[test]
    fn label_rectangle_rejects_final_coordinate_overflow() {
        assert_eq!(label_right_edge(0).expect("empty state"), 1);
        assert_eq!(label_right_edge(8).expect("short state"), 49);
        let largest = ((i32::MAX as usize) - 1) / 6;
        assert_eq!(
            label_right_edge(largest).expect("largest valid label"),
            (largest * 6 + 1) as i32
        );
        assert!(label_right_edge(largest + 1).is_err());
        assert!(label_right_edge(usize::MAX).is_err());
    }

    #[test]
    fn empty_congestion_renders_and_invalid_timestamps_fail(
    ) -> Result<(), Box<dyn Error>> {
        let mut buffer = vec![0_u8; 1000 * 900 * 3];
        let area = BitMapBackend::with_buffer(&mut buffer, (1000, 900))
            .into_drawing_area();
        let params = chart_params();
        let ss = SeriesStore::default();
        let axis = XYMinMax::init(0.0..1.0, None, None, 0..1);
        let ds = Datastore::default();
        assert!(draw_congestion_plot(&params, &axis, &ss, &ds, &area).is_ok());
        let mut populated = Datastore::default();
        populated.congestion_state_updates.extend([
            (0.2, 0, "slow_start".to_owned()),
            (0.4, 0, "bbr_probe_bw".to_owned()),
        ]);
        assert!(
            draw_congestion_plot(&params, &axis, &ss, &populated, &area).is_ok()
        );
        let mut invalid = Datastore::default();
        invalid.congestion_state_updates.push((
            f64::NAN,
            0,
            "slow_start".to_string(),
        ));
        assert!(
            draw_congestion_plot(&params, &axis, &ss, &invalid, &area).is_err()
        );
        Ok(())
    }
}
