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
use minmax::XYMinMax;
use plotters::coord::types::RangedCoordf32;
use plotters::coord::types::RangedCoordf64;
use std::error::Error;

use plotters::coord::Shift;

use crate::plots::colors::*;
use crate::plots::*;

use crate::seriesstore::SeriesStore;

fn padded_rtt_max(value: f32) -> Result<f32, Box<dyn Error>> {
    if !value.is_finite() || value < 0.0 {
        return Err(
            invalid_chart("RTT maximum must be finite and nonnegative").into()
        );
    }
    Ok(((f64::from(value) * 1.1).max(1.0).min(f64::from(f32::MAX))) as f32)
}

/// Render all recorded RTT series.
///
/// # Errors
/// Returns backend errors or invalid/unrepresentable axis ranges.
pub fn draw_rtt_plot<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, axis: &XYMinMax<u64>, ss: &SeriesStore,
    plot: &plotters::drawing::DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordf32>>,
    Box<dyn Error>,
>
where
    DB::ErrorType: 'static,
{
    let x = checked_time_range(axis.x.min, axis.x.max, &params.clamp)?;
    let upper = padded_rtt_max(ss.y_max_rtt_plot)?;
    let mut builder = ChartBuilder::on(plot);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);
    if params.display_chart_title {
        builder.caption("RTT", chart_subtitle_style(&params.colors.caption));
    }
    let mut chart = builder.build_cartesian_2d(x, 0.0f32..upper)?;
    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "RTT (ms)",
        false,
        &mut chart,
    )?;
    for (points, label, colour) in [
        (&ss.local_min_rtt, "Min RTT", SOFT_PINK),
        (&ss.local_latest_rtt, "Latest RTT", ORANGE),
        (&ss.local_smoothed_rtt, "Smoothed RTT", BROWN),
    ] {
        chart
            .draw_series(LineSeries::new(points.iter().copied(), colour))?
            .label(label)
            .legend(move |(x, y)| {
                PathElement::new(vec![(x, y), (x + 20, y)], colour)
            });
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

#[cfg(target_arch = "wasm32")]
/// Render RTT to a browser canvas.
///
/// # Errors
/// Returns missing canvas, invalid range or backend failures.
pub fn plot_rtt_plot<'a>(
    params: &PlotParameters, ss: &SeriesStore, canvas_id: &str,
) -> Result<
    ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf64, RangedCoordf32>>,
    Box<dyn Error>,
> {
    let root = canvas_area(canvas_id, params.colors, params.chart_margin)?;
    let congestion_max = params
        .cwnd_y_max
        .unwrap_or_else(|| {
            let value = ss.y_max_congestion_plot;
            value.saturating_add(value / 10)
        })
        .max(1);
    let axis = super::minmax::XYMinMax::init(
        checked_time_range(ss.sent_x_min, ss.sent_x_max, &params.clamp)?,
        None,
        None,
        0..congestion_max,
    );
    draw_rtt_plot(params, &axis, ss, &root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plots::fallible::test_support::chart_params;

    #[test]
    fn rtt_bounds_are_nonempty_precise_and_validate_nonfinite_data(
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(padded_rtt_max(0.0)?, 1.0);
        assert_eq!(padded_rtt_max(100.0)?, 110.0);
        assert_eq!(padded_rtt_max(f32::MAX)?, f32::MAX);
        assert!(padded_rtt_max(f32::INFINITY).is_err());
        assert!(padded_rtt_max(-1.0).is_err());
        let mut buffer = vec![0_u8; 1000 * 900 * 3];
        let area = BitMapBackend::with_buffer(&mut buffer, (1000, 900))
            .into_drawing_area();
        let ss = SeriesStore::default();
        let axis = XYMinMax::init(0.0..0.0, None, None, 0..1);
        let chart = draw_rtt_plot(&chart_params(), &axis, &ss, &area)?;
        assert_eq!(chart.y_range(), 0.0..1.0);
        Ok(())
    }
}
