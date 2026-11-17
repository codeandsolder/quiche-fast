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

//! Pending charts
//! A single image file containing a view of pending vs. in-flight requests

use crate::datastore::Datastore;
use crate::datastore::VantagePoint;
#[cfg(not(target_arch = "wasm32"))]
use crate::plots::fallible::bitmap_area;
#[cfg(target_arch = "wasm32")]
use crate::plots::fallible::canvas_area;
use crate::plots::fallible::checked_time_range;
use crate::plots::fallible::invalid_chart;
use crate::plots::*;
use crate::seriesstore::SeriesStore;
use std::error::Error;
use std::io;

#[derive(Debug, Default)]
pub struct PendingPlotParams {
    pub clamp: ClampParams,
    pub chart_size: ChartSize,
    pub colors: PlotColors,
    pub display_chart_title: bool,
}

#[derive(Debug, PartialEq)]
struct PendingInterval {
    start: f64,
    end: f64,
    pending: u64,
    in_flight: u64,
}

/// Piecewise constant request occupancy. Unlike the old one-millisecond
/// resampling loop, cost depends on request events, not trace duration.
fn occupancy_intervals(
    ds: &Datastore, limit: f64,
) -> io::Result<Vec<PendingInterval>> {
    if !limit.is_finite() || limit < 0.0 {
        return Err(invalid_chart(
            "pending plot end time must be finite and nonnegative",
        ));
    }
    let mut events = Vec::<(f64, i64, i64)>::new();
    for request in ds.http_requests.values() {
        let discovery = request.time_discovery;
        let headers = request.time_first_headers_tx;
        let finish = request.time_fin_rx;
        for time in [discovery, headers, finish].into_iter().flatten() {
            if !time.is_finite() || time < 0.0 {
                return Err(invalid_chart(
                    "request timestamps must be finite and nonnegative",
                ));
            }
        }
        let Some(begin) = discovery.or(headers) else {
            continue;
        };
        let end = finish.unwrap_or(limit);
        if end < begin || headers.is_some_and(|h| h < begin || h > end) {
            return Err(invalid_chart(
                "request lifecycle timestamps are reversed",
            ));
        }
        // A completed request remains pending until headers are transmitted,
        // then in-flight until FIN. A header-only trace begins in-flight.
        if discovery.is_some() {
            let pending_end = headers.unwrap_or(end);
            if pending_end > begin {
                events.push((begin, 1, 0));
                events.push((pending_end, -1, 0));
            }
        }
        if let Some(headers) = headers {
            if end > headers {
                events.push((headers, 0, 1));
                events.push((end, 0, -1));
            }
        }
    }
    events.sort_by(|left, right| left.0.total_cmp(&right.0));
    let mut intervals = Vec::new();
    let mut pending = 0_i64;
    let mut inflight = 0_i64;
    let mut previous = 0.0;
    let mut index = 0;
    while index < events.len() {
        let time = events[index].0;
        if time > previous && (pending != 0 || inflight != 0) {
            intervals.push(PendingInterval {
                start: previous,
                end: time,
                pending: u64::try_from(pending).map_err(|_| {
                    invalid_chart("negative pending request count")
                })?,
                in_flight: u64::try_from(inflight).map_err(|_| {
                    invalid_chart("negative in-flight request count")
                })?,
            });
        }
        while index < events.len() && events[index].0 == time {
            pending = pending.checked_add(events[index].1).ok_or_else(|| {
                invalid_chart("pending request count overflows")
            })?;
            inflight =
                inflight.checked_add(events[index].2).ok_or_else(|| {
                    invalid_chart("in-flight request count overflows")
                })?;
            index += 1;
        }
        if pending < 0 || inflight < 0 {
            return Err(invalid_chart("request occupancy became negative"));
        }
        previous = time;
    }
    if previous < limit && (pending != 0 || inflight != 0) {
        intervals.push(PendingInterval {
            start: previous,
            end: limit,
            pending: u64::try_from(pending)
                .map_err(|_| invalid_chart("negative pending request count"))?,
            in_flight: u64::try_from(inflight)
                .map_err(|_| invalid_chart("negative in-flight request count"))?,
        });
    }
    Ok(intervals)
}

/// Render pending and in-flight request occupancy with event-driven intervals.
///
/// # Errors
/// Returns invalid times, impossible request counts, output and backend errors.
pub fn plot_pending(
    params: &PendingPlotParams, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &ChartOutputType,
) -> Result<(), Box<dyn Error>> {
    let observed_end = match ds.vantage_point {
        VantagePoint::Client => ss.received_x_max,
        VantagePoint::Server => ss.sent_x_max,
    };
    let mut end = observed_end;
    if !end.is_finite() {
        return Err(invalid_chart("trace duration must be finite").into());
    }
    for request in ds.http_requests.values() {
        for time in [
            request.time_discovery,
            request.time_first_headers_tx,
            request.time_fin_rx,
        ]
        .into_iter()
        .flatten()
        {
            if !time.is_finite() || time < 0.0 {
                return Err(invalid_chart(
                    "request timestamps must be finite and nonnegative",
                )
                .into());
            }
            end = end.max(time);
        }
    }
    let range = checked_time_range(0.0, end, &params.clamp)?;
    let intervals = occupancy_intervals(ds, end)?;
    let y_max = intervals.iter().try_fold(1_u64, |maximum, item| {
        let count = item
            .pending
            .checked_add(item.in_flight)
            .ok_or_else(|| invalid_chart("request occupancy exceeds u64"))?;
        Ok::<_, io::Error>(maximum.max(count))
    })?;
    let config = ChartConfig::new("pending", filename, &params.clamp, ds, ty);
    #[cfg(not(target_arch = "wasm32"))]
    let path = match ty {
        ChartOutputType::Png { .. } => config.chart_filepath(),
        ChartOutputType::Canvas { .. } =>
            return Err(
                invalid_chart("native pending plot requires PNG output").into()
            ),
    };
    #[cfg(not(target_arch = "wasm32"))]
    let root = bitmap_area(
        &path,
        params.chart_size,
        params.colors,
        ChartMargin::default(),
    )?;
    #[cfg(target_arch = "wasm32")]
    let canvas_id = config.canvas_id().ok_or_else(|| {
        invalid_chart("browser pending plot requires canvas output")
    })?;
    #[cfg(target_arch = "wasm32")]
    let root = canvas_area(&canvas_id, params.colors, ChartMargin::default())?;
    let mut builder = ChartBuilder::on(&root);
    builder
        .set_label_area_size(LabelAreaPosition::Left, 40)
        .set_label_area_size(LabelAreaPosition::Bottom, 40);
    if params.display_chart_title {
        builder.caption(
            format!("{filename} Pending vs. In-flight requests (stacked)"),
            chart_title_style(&params.colors.caption),
        );
    }
    let mut chart = builder.build_cartesian_2d(range, 0..y_max)?;
    chart
        .configure_mesh()
        .axis_style(params.colors.axis)
        .bold_line_style(params.colors.bold_line.mix(0.5))
        .light_line_style(params.colors.light_line.mix(0.2))
        .label_style(chart_label_style(&params.colors.caption))
        .draw()?;
    chart
        .draw_series(intervals.iter().map(|item| {
            Rectangle::new(
                [(item.start, 0), (item.end, item.in_flight)],
                colors::FOREST_GREEN.filled(),
            )
        }))?
        .label("In-flight requests")
        .legend(|(x, y)| {
            PathElement::new(vec![(x, y), (x + 20, y)], colors::FOREST_GREEN)
        });
    chart
        .draw_series(intervals.iter().map(|item| {
            Rectangle::new(
                [
                    (item.start, item.in_flight),
                    (item.end, item.in_flight + item.pending),
                ],
                colors::ORANGE.filled(),
            )
        }))?
        .label("Pending requests")
        .legend(|(x, y)| {
            PathElement::new(vec![(x, y), (x + 20, y)], colors::ORANGE)
        });
    chart
        .configure_series_labels()
        .label_font(chart_label_style(&params.colors.caption))
        .background_style(params.colors.fill.mix(0.8))
        .border_style(params.colors.axis)
        .position(SeriesLabelPosition::UpperRight)
        .draw()?;
    root.present()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plots::fallible::test_support::TempCharts;
    use crate::request_stub::HttpRequestStub;

    #[test]
    fn sparse_request_occupancy_uses_event_intervals_not_millisecond_samples(
    ) -> Result<(), Box<dyn Error>> {
        let mut ds = Datastore::default();
        ds.http_requests.insert(1, HttpRequestStub {
            time_discovery: Some(1.0),
            time_first_headers_tx: Some(3.0),
            time_fin_rx: Some(7.0),
            ..HttpRequestStub::default()
        });
        ds.http_requests.insert(3, HttpRequestStub {
            time_discovery: Some(2.0),
            time_first_headers_tx: Some(4.0),
            ..HttpRequestStub::default()
        });
        let points = occupancy_intervals(&ds, 1_000_000_000.0)?;
        assert_eq!(points, vec![
            PendingInterval {
                start: 1.0,
                end: 2.0,
                pending: 1,
                in_flight: 0
            },
            PendingInterval {
                start: 2.0,
                end: 3.0,
                pending: 2,
                in_flight: 0
            },
            PendingInterval {
                start: 3.0,
                end: 4.0,
                pending: 1,
                in_flight: 1
            },
            PendingInterval {
                start: 4.0,
                end: 7.0,
                pending: 0,
                in_flight: 2
            },
            PendingInterval {
                start: 7.0,
                end: 1_000_000_000.0,
                pending: 0,
                in_flight: 1
            },
        ]);
        assert!(occupancy_intervals(&ds, f64::INFINITY).is_err());
        Ok(())
    }

    #[test]
    fn empty_pending_png_and_failed_output_are_reported(
    ) -> Result<(), Box<dyn Error>> {
        let ss = SeriesStore::default();
        let ds = Datastore::default();
        let params = PendingPlotParams {
            chart_size: ChartSize {
                width: 640,
                height: 440,
            },
            ..PendingPlotParams::default()
        };
        let out = TempCharts::new()?;
        plot_pending(&params, "empty", &ss, &ds, &out.output())?;
        assert_eq!(image::image_dimensions(out.only_file()?)?, (640, 440));
        let blocked = TempCharts::new()?;
        let obstacle = blocked.0.join("not-a-directory");
        std::fs::write(&obstacle, b"block")?;
        let ty = ChartOutputType::Png {
            output_dir: obstacle.to_string_lossy().into_owned(),
            cwnd_y_max: None,
            stream_y_max: None,
        };
        assert!(plot_pending(&params, "blocked", &ss, &ds, &ty).is_err());
        Ok(())
    }
}
