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
#[cfg(not(target_arch = "wasm32"))]
use crate::plots::fallible::PngBitmap;
use plotters::chart::ChartContext;
use plotters::coord::types::RangedCoordf64;
use plotters::coord::types::RangedCoordu64;
use plotters::coord::Shift;
use plotters::drawing::DrawingAreaErrorKind;
use plotters::prelude::Cartesian2d;
use plotters::prelude::ChartBuilder;
use plotters::prelude::Circle;
use plotters::prelude::Color;
use plotters::prelude::DrawingBackend;
use plotters::prelude::LineSeries;
use plotters::prelude::PathElement;
use plotters::prelude::SeriesLabelPosition;
use plotters::prelude::BLUE;
use plotters::prelude::GREEN;
#[cfg(target_arch = "wasm32")]
use plotters_canvas::CanvasBackend;
use std::error::Error;
use std::io;
use std::ops::Range;

use crate::datastore::ApplicationProto;
use crate::datastore::Datastore;
use crate::plots::chart_label_style;
use crate::plots::chart_title_style;
use crate::plots::colors::ORANGE;
use crate::plots::draw_mesh;
#[cfg(not(target_arch = "wasm32"))]
use crate::plots::ChartConfig;
use crate::plots::ChartOutputType;
use crate::plots::PlotParameters;
use crate::seriesstore::SeriesStore;

struct XYMinMax {
    pub x: Range<f64>,
    pub y_min: u64,
    pub y_max: u64,
}

impl XYMinMax {
    fn init(
        params: &PlotParameters, ss: &SeriesStore, ds: &Datastore,
    ) -> io::Result<Self> {
        let x = flow_control_time_range(ss, ds, &params.clamp)?;
        Ok(Self {
            x,
            y_min: 0,
            y_max: Self::y_max(ss, ds.application_proto),
        })
    }

    const fn y_range(&self) -> Range<u64> {
        self.y_min..self.y_max
    }

    fn y_max(ss: &SeriesStore, proto: ApplicationProto) -> u64 {
        let max_series = received_series(ss, proto)
            .iter()
            .map(|point| point.1)
            .max()
            .unwrap_or(0);
        let max_window = window_series(ss, proto)
            .into_iter()
            .flatten()
            .map(|point| point.1)
            .max()
            .unwrap_or(0);
        let max_value = max_series.max(max_window);
        max_value.saturating_add(max_value.div_ceil(5)).max(1)
    }
}

/// Only one protocol's series is represented by this chart at a time.
fn received_series(ss: &SeriesStore, proto: ApplicationProto) -> &[(f64, u64)] {
    match proto {
        ApplicationProto::Http2 =>
            &ss.netlog_h2_stream_received_connection_cumulative,
        ApplicationProto::Http3 => &ss.quic_receive_credit_consumed,
    }
}

fn window_series(
    ss: &SeriesStore, proto: ApplicationProto,
) -> Option<&[(f64, u64)]> {
    match proto {
        ApplicationProto::Http2 =>
            Some(ss.h2_connection_receive_credit.as_slice())
                .filter(|points| !points.is_empty()),
        ApplicationProto::Http3 =>
            Some(ss.sent_max_data.as_slice()).filter(|points| !points.is_empty()),
    }
}

fn blocked_connection_events(ds: &Datastore) -> Option<&[f64]> {
    match ds.application_proto {
        ApplicationProto::Http2 => None,
        ApplicationProto::Http3 =>
            ds.quic_peer_window_blocked.get(&-1).map(Vec::as_slice),
    }
    .filter(|events| !events.is_empty())
}

/// Base the X-axis on the exact points and markers being drawn, rather than
/// unrelated received-packet timestamps. Window-update series are populated
/// separately from packet timeline extrema and can extend past them.
fn flow_control_time_range(
    ss: &SeriesStore, ds: &Datastore, clamp: &crate::plots::ClampParams,
) -> io::Result<Range<f64>> {
    let times = received_series(ss, ds.application_proto)
        .iter()
        .map(|(time, _)| *time)
        .chain(
            window_series(ss, ds.application_proto)
                .into_iter()
                .flatten()
                .map(|(time, _)| *time),
        )
        .chain(blocked_connection_events(ds).into_iter().flatten().copied());

    // A fallible reduction rejects invalid samples before they reach Plotters,
    // while preserving true extrema independent of event ordering.
    let bounds = times.into_iter().try_fold(
        None,
        |bounds: Option<(f64, f64)>, time| {
            if !time.is_finite() {
                return Err(invalid_chart(
                    "flow-control event timestamps must be finite",
                ));
            }
            Ok::<_, io::Error>(Some(match bounds {
                Some((min, max)) => (min.min(time), max.max(time)),
                None => (time, time),
            }))
        },
    )?;
    let (min, max) = bounds.unwrap_or((ss.received_x_min, ss.received_x_max));
    checked_time_range(min, max, clamp)
}

fn blocked_lines<DB: DrawingBackend>(
    ds: &Datastore, y_max: u64,
    chart: &mut ChartContext<'_, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    if let Some(blocked) = blocked_connection_events(ds) {
        let lines = blocked
            .iter()
            .map(|time| PathElement::new([(*time, 0), (*time, y_max)], GREEN));
        chart
            .draw_series(lines)?
            .label("peer connection blocked")
            .legend(|(x, y)| PathElement::new([(x, y), (x + 20, y)], GREEN));
    }
    Ok(())
}

fn received_data<DB: DrawingBackend>(
    ss: &SeriesStore, proto: ApplicationProto,
    chart: &mut ChartContext<'_, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    let points = received_series(ss, proto);
    chart
        .draw_series(LineSeries::new(points.iter().copied(), ORANGE))?
        .label(match proto {
            ApplicationProto::Http2 => "observed inbound DATA bytes",
            ApplicationProto::Http3 =>
                "observed receive-credit consumption (lower bound)",
        })
        .legend(|(x, y)| PathElement::new([(x, y), (x + 20, y)], ORANGE));
    Ok(())
}

fn window_updates<DB: DrawingBackend>(
    ss: &SeriesStore, ds: &Datastore,
    chart: &mut ChartContext<'_, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    let points = window_series(ss, ds.application_proto);
    if let Some(points) = points {
        chart
            .draw_series(LineSeries::new(points.iter().copied(), BLUE))?
            .label("cumulative receive credit granted")
            .legend(|(x, y)| PathElement::new([(x, y), (x + 20, y)], BLUE));
        chart.draw_series(
            points.iter().map(|point| Circle::new(*point, 2, BLUE)),
        )?;
    }
    Ok(())
}

fn draw_series<'a, DB: DrawingBackend + 'a>(
    chart: &mut ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    params: &PlotParameters, ss: &SeriesStore, ds: &Datastore, y_max: u64,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>> {
    draw_mesh(
        &params.colors,
        "Relative time (ms)",
        "Bytes",
        params.display_minor_lines,
        chart,
    )?;
    blocked_lines(ds, y_max, chart)?;
    received_data(ss, ds.application_proto, chart)?;
    window_updates(ss, ds, chart)?;
    if params.display_legend {
        chart
            .configure_series_labels()
            .label_font(chart_label_style(&params.colors.caption))
            .background_style(params.colors.fill.mix(0.8))
            .border_style(params.colors.axis)
            .position(SeriesLabelPosition::LowerRight)
            .draw()?;
    }
    Ok(())
}

fn draw_flow_control<'a, DB: DrawingBackend + 'a>(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, ds: &Datastore,
    area: &plotters::drawing::DrawingArea<DB, Shift>,
) -> Result<
    ChartContext<'a, DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
>
where
    DB::ErrorType: 'static,
{
    let axis = XYMinMax::init(params, ss, ds)?;
    let mut builder = ChartBuilder::on(area);
    builder
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y);
    if params.display_chart_title {
        builder.caption(
            format!("{filename} Connection Flow Control timeline"),
            chart_title_style(&params.colors.caption),
        );
    }
    let mut chart = builder.build_cartesian_2d(axis.x.clone(), axis.y_range())?;
    draw_series(&mut chart, params, ss, ds, axis.y_max)?;
    Ok(chart)
}

#[cfg(target_arch = "wasm32")]
/// Render flow-control series to a browser canvas.
///
/// # Errors
/// Returns missing canvas, invalid timestamp or Plotters backend errors.
pub fn plot_conn_flow_control_canvas<'a>(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &ChartOutputType,
) -> Result<
    ChartContext<'a, CanvasBackend, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
    Box<dyn Error>,
> {
    let canvas_id = match ty {
        ChartOutputType::Canvas { canvas_id } => canvas_id.as_str(),
        ChartOutputType::Png { .. } =>
            return Err(invalid_chart(
                "browser flow-control plot requires canvas output",
            )
            .into()),
    };
    let root = canvas_area(canvas_id, params.colors, params.chart_margin)?;
    draw_flow_control(params, filename, ss, ds, &root)
}

#[cfg(not(target_arch = "wasm32"))]
/// Render flow-control series to PNG.
///
/// # Errors
/// Returns invalid filename, timestamp or Plotters backend errors.
pub fn plot_conn_flow_control(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &ChartOutputType,
) -> Result<(), Box<dyn Error>> {
    let config =
        ChartConfig::new("flow_control", filename, &params.clamp, ds, ty);
    if !matches!(ty, ChartOutputType::Png { .. }) {
        return Err(invalid_chart(
            "native flow-control plot requires PNG output",
        )
        .into());
    }
    let path = config.chart_filepath();
    let mut bitmap = PngBitmap::new(&path, params.chart_size)?;
    {
        let root = bitmap.area(params.colors, params.chart_margin)?;
        draw_flow_control(params, filename, ss, ds, &root)?;
        root.present()?;
    }
    bitmap.save()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plots::fallible::test_support::chart_params;
    use crate::plots::fallible::test_support::TempCharts;
    use plotters::drawing::IntoDrawingArea;

    #[test]
    fn flow_control_time_axis_uses_visible_protocol_series_not_packet_times(
    ) -> Result<(), Box<dyn Error>> {
        let params = chart_params();
        let mut series = SeriesStore {
            received_x_min: 0.0,
            received_x_max: 2.0,
            netlog_h2_stream_received_connection_cumulative: vec![(12.0, 15)],
            quic_receive_credit_consumed: vec![(20.0, 20)],
            ..SeriesStore::default()
        };
        series.h2_connection_receive_credit = vec![(85.0, 60)];
        series.sent_max_data = vec![(60.0, 80)];
        let mut ds = Datastore {
            application_proto: ApplicationProto::Http2,
            ..Datastore::default()
        };
        ds.quic_peer_window_blocked.insert(-1, vec![80.0]);
        assert_eq!(XYMinMax::init(&params, &series, &ds)?.x, 12.0..85.0);

        ds.application_proto = ApplicationProto::Http3;
        assert_eq!(XYMinMax::init(&params, &series, &ds)?.x, 20.0..80.0);
        assert!(blocked_connection_events(&ds).is_some());
        ds.application_proto = ApplicationProto::Http2;
        assert!(blocked_connection_events(&ds).is_none());

        // Verify the shared native/browser renderer uses exactly this axis,
        // not the unrelated received-packet range.
        let mut pixels = vec![0_u8; 640 * 480 * 3];
        let root = plotters::prelude::BitMapBackend::with_buffer(
            &mut pixels,
            (640, 480),
        )
        .into_drawing_area();
        let chart = draw_flow_control(&params, "h2", &series, &ds, &root)?;
        assert_eq!(chart.x_range(), 12.0..85.0);
        drop(chart);

        let mut clamped = chart_params();
        clamped.clamp.start = Some(30.0);
        clamped.clamp.end = Some(70.0);
        assert_eq!(XYMinMax::init(&clamped, &series, &ds)?.x, 30.0..70.0);
        Ok(())
    }

    #[test]
    fn flow_control_time_axis_handles_single_empty_and_invalid_series(
    ) -> Result<(), Box<dyn Error>> {
        let params = chart_params();
        let mut ds = Datastore {
            application_proto: ApplicationProto::Http3,
            ..Datastore::default()
        };
        let mut series = SeriesStore {
            received_x_min: 3.0,
            received_x_max: 4.0,
            ..SeriesStore::default()
        };
        assert_eq!(XYMinMax::init(&params, &series, &ds)?.x, 3.0..4.0);

        ds.quic_peer_window_blocked.insert(-1, vec![40.0]);
        let range = XYMinMax::init(&params, &series, &ds)?.x;
        assert!(range.start < 40.0 && range.end > 40.0);

        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            ds.quic_peer_window_blocked.insert(-1, vec![invalid]);
            assert!(XYMinMax::init(&params, &series, &ds).is_err());
        }
        ds.quic_peer_window_blocked.clear();
        series.quic_receive_credit_consumed.push((f64::NAN, 1));
        assert!(XYMinMax::init(&params, &series, &ds).is_err());
        series.quic_receive_credit_consumed.clear();
        series.sent_max_data = vec![(f64::INFINITY, 1)];
        assert!(XYMinMax::init(&params, &series, &ds).is_err());
        Ok(())
    }

    #[test]
    fn flow_control_max_follows_all_samples_and_saturates_large_values() {
        let mut series = SeriesStore {
            quic_receive_credit_consumed: vec![(2.0, 1000), (4.0, 1)],
            ..SeriesStore::default()
        };
        assert_eq!(XYMinMax::y_max(&series, ApplicationProto::Http3), 1200);
        series.quic_receive_credit_consumed[0].1 = u64::MAX;
        assert_eq!(XYMinMax::y_max(&series, ApplicationProto::Http3), u64::MAX);
        assert_eq!(
            XYMinMax::y_max(&SeriesStore::default(), ApplicationProto::Http2),
            1
        );
    }

    #[test]
    fn http2_and_http3_maxima_use_their_own_receive_and_window_series() {
        let mut series = SeriesStore {
            netlog_h2_stream_received_connection_cumulative: vec![(1.0, 150)],
            quic_receive_credit_consumed: vec![(1.0, 400)],
            ..SeriesStore::default()
        };
        series.h2_connection_receive_credit = vec![(0.0, 250), (1.0, 50)];
        series.sent_max_data = vec![(0.0, 500), (2.0, 20)];
        assert_eq!(XYMinMax::y_max(&series, ApplicationProto::Http2), 300);
        assert_eq!(XYMinMax::y_max(&series, ApplicationProto::Http3), 600);

        series.h2_connection_receive_credit = vec![(0.0, 1_000)];
        assert_eq!(XYMinMax::y_max(&series, ApplicationProto::Http2), 1_200);
        assert_eq!(XYMinMax::y_max(&series, ApplicationProto::Http3), 600);
    }

    #[test]
    fn empty_flow_chart_renders_and_blocked_output_returns_error(
    ) -> Result<(), Box<dyn Error>> {
        let params = chart_params();
        let ss = SeriesStore::default();
        let ds = Datastore::default();
        let out = TempCharts::new()?;
        plot_conn_flow_control(&params, "empty", &ss, &ds, &out.output())?;
        assert_eq!(image::image_dimensions(out.only_file()?)?, (1000, 900));
        let blocked = TempCharts::new()?;
        let obstacle = blocked.0.join("not-directory");
        std::fs::write(&obstacle, b"block")?;
        let ty = ChartOutputType::Png {
            output_dir: obstacle.to_string_lossy().into_owned(),
            cwnd_y_max: None,
            stream_y_max: None,
        };
        assert!(
            plot_conn_flow_control(&params, "blocked", &ss, &ds, &ty).is_err()
        );
        Ok(())
    }
}
