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
use crate::plots::chart_label_style;
use crate::plots::chart_title_style;
use crate::plots::colors;
use crate::plots::fallible::checked_time_range;
use crate::plots::fallible::invalid_chart;
use crate::plots::ChartConfig;
use crate::plots::ChartMargin;
use crate::plots::ChartOutputType;
use crate::plots::ChartSize;
use crate::plots::ClampParams;
use crate::plots::PlotColors;
use crate::request_stub::HttpRequestStub;
use crate::seriesstore::SeriesStore;
use plotters::prelude::ChartBuilder;
use plotters::prelude::Color;
use plotters::prelude::LabelAreaPosition;
use plotters::prelude::PathElement;
use plotters::prelude::Rectangle;
use plotters::prelude::SeriesLabelPosition;
use std::cmp::Ordering;
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

fn request_times(request: &HttpRequestStub) -> impl Iterator<Item = f64> {
    [
        request.time_discovery,
        request.request_headers_time(),
        request.observed_response_end(),
    ]
    .into_iter()
    .flatten()
}

fn validate_request_time(time: f64) -> io::Result<()> {
    if time.is_finite() {
        Ok(())
    } else {
        Err(invalid_chart("request timestamps must be finite"))
    }
}

/// Piecewise constant request occupancy, clipped at a finite time limit.
/// Unlike millisecond resampling, cost depends on request events, not duration.
fn occupancy_intervals(
    ds: &Datastore, limit: f64,
) -> io::Result<Vec<PendingInterval>> {
    if !limit.is_finite() {
        return Err(invalid_chart("pending plot end time must be finite"));
    }
    let mut events = Vec::<(f64, i64, i64)>::new();
    for request in ds.http_requests.values() {
        let discovery = request.time_discovery;
        let headers = request.request_headers_time();
        let finish = [request.observed_response_end(), ds.time_session_close]
            .into_iter()
            .flatten()
            .min_by(f64::total_cmp);
        for time in request_times(request).chain(ds.time_session_close) {
            validate_request_time(time)?;
        }
        let Some(begin) = discovery.or(headers) else {
            continue;
        };
        // An unfinished request can legitimately begin after the plotting
        // horizon, or send headers after it. Validate only observed lifecycle
        // ordering; the artificial horizon must not act like a FIN event.
        if finish.is_some_and(|end| end < begin) ||
            headers.is_some_and(|h| {
                h < begin || finish.is_some_and(|end| h > end)
            })
        {
            return Err(invalid_chart(
                "request lifecycle timestamps are reversed",
            ));
        }
        if begin >= limit {
            continue;
        }
        let end = finish.unwrap_or(limit).min(limit);
        // Pending until request headers are observed at this endpoint,
        // then active until response-side terminal evidence or session close.
        // A header-only trace begins active; this does not establish delivery.
        // Clip events at the requested time limit *after* validating the full
        // lifecycle, so even malformed future events cannot be hidden by it.
        if discovery.is_some() {
            let pending_end = headers.unwrap_or(end).min(end);
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
    let mut previous = events.first().map_or(0.0, |event| event.0);
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
        // Events share a timestamp only when they are exactly equal. An
        // epsilon would merge distinct packet times; partial_cmp preserves
        // the old -0.0/+0.0 equivalence without floating-point ==.
        while index < events.len() &&
            events[index].0.partial_cmp(&time) == Some(Ordering::Equal)
        {
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

struct PendingPlotData {
    range: std::ops::Range<f64>,
    intervals: Vec<PendingInterval>,
    y_max: u64,
}

fn pending_plot_data(
    clamp: &ClampParams, ss: &SeriesStore, ds: &Datastore,
) -> io::Result<PendingPlotData> {
    let (mut start, mut end) = (0.0_f64, 0.0_f64);
    for time in [
        ss.sent_x_min,
        ss.received_x_min,
        ss.sent_x_max,
        ss.received_x_max,
        ds.last_event_time,
    ]
    .into_iter()
    .chain(ds.http_requests.values().flat_map(request_times))
    .chain(ds.time_session_close)
    {
        validate_request_time(time)?;
        start = start.min(time);
        end = end.max(time);
    }
    let range = checked_time_range(start, end, clamp)?;
    // Clip both ends before deriving the count axis.
    let visible_end = clamp.end.map_or(end, |clamp| end.min(clamp));
    let intervals = occupancy_intervals(ds, visible_end)?
        .into_iter()
        .filter_map(|mut item| {
            item.start = item.start.max(range.start);
            (item.start < item.end).then_some(item)
        })
        .collect::<Vec<_>>();
    let y_max = intervals.iter().try_fold(1_u64, |maximum, item| {
        let count = item
            .pending
            .checked_add(item.in_flight)
            .ok_or_else(|| invalid_chart("request occupancy exceeds u64"))?;
        Ok::<_, io::Error>(maximum.max(count))
    })?;
    Ok(PendingPlotData {
        range,
        intervals,
        y_max,
    })
}

/// Render pending and in-flight request occupancy with event-driven intervals.
///
/// # Errors
/// Returns invalid times, impossible request counts, output and backend errors.
pub fn plot_pending(
    params: &PendingPlotParams, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &ChartOutputType,
) -> Result<(), Box<dyn Error>> {
    let PendingPlotData {
        range,
        intervals,
        y_max,
    } = pending_plot_data(&params.clamp, ss, ds)?;
    let config = ChartConfig::new("pending", filename, &params.clamp, ds, ty);
    config.render(
        params.chart_size,
        params.colors,
        ChartMargin::default(),
        |root| {
            let mut builder = ChartBuilder::on(root);
            builder
                .set_label_area_size(LabelAreaPosition::Left, 40)
                .set_label_area_size(LabelAreaPosition::Bottom, 40);
            if params.display_chart_title {
                builder.caption(
                    format!(
                "{filename} Pending vs. awaiting observed response end (stacked)"
            ),
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
                .label("Awaiting observed response end")
                .legend(|(x, y)| {
                    PathElement::new([(x, y), (x + 20, y)], colors::FOREST_GREEN)
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
                    PathElement::new([(x, y), (x + 20, y)], colors::ORANGE)
                });
            chart
                .configure_series_labels()
                .label_font(chart_label_style(&params.colors.caption))
                .background_style(params.colors.fill.mix(0.8))
                .border_style(params.colors.axis)
                .position(SeriesLabelPosition::UpperRight)
                .draw()?;
            Ok(())
        },
    )
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
            time_response_terminal: Some(7.0),
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
    fn events_at_signed_zero_are_grouped_without_merging_distinct_times(
    ) -> Result<(), Box<dyn Error>> {
        let mut ds = Datastore::default();
        ds.http_requests.insert(1, HttpRequestStub {
            time_discovery: Some(-0.0),
            time_first_headers_tx: Some(1.0),
            time_response_terminal: Some(2.0),
            ..HttpRequestStub::default()
        });
        ds.http_requests.insert(3, HttpRequestStub {
            time_first_headers_tx: Some(0.0),
            time_response_terminal: Some(2.0),
            ..HttpRequestStub::default()
        });
        assert_eq!(occupancy_intervals(&ds, 3.0)?, vec![
            PendingInterval {
                start: 0.0,
                end: 1.0,
                pending: 1,
                in_flight: 1,
            },
            PendingInterval {
                start: 1.0,
                end: 2.0,
                pending: 0,
                in_flight: 2,
            },
        ]);
        Ok(())
    }

    #[test]
    fn finite_horizon_clips_active_requests_and_checks_future_lifecycles(
    ) -> Result<(), Box<dyn Error>> {
        let mut ds = Datastore::default();
        ds.http_requests.insert(1, HttpRequestStub {
            time_discovery: Some(1.0),
            time_first_headers_tx: Some(3.0),
            time_response_terminal: Some(20.0),
            ..HttpRequestStub::default()
        });
        ds.http_requests.insert(3, HttpRequestStub {
            time_discovery: Some(7.0),
            time_first_headers_tx: Some(8.0),
            time_response_terminal: Some(10.0),
            ..HttpRequestStub::default()
        });
        assert_eq!(occupancy_intervals(&ds, 5.0)?, vec![
            PendingInterval {
                start: 1.0,
                end: 3.0,
                pending: 1,
                in_flight: 0,
            },
            PendingInterval {
                start: 3.0,
                end: 5.0,
                pending: 0,
                in_flight: 1,
            },
        ]);
        assert_eq!(occupancy_intervals(&ds, 0.0)?, []);
        // An open request beginning after the horizon is valid, not a
        // reversed lifecycle caused by an invented FIN at the horizon.
        ds.http_requests.insert(7, HttpRequestStub {
            time_discovery: Some(8.0),
            time_first_headers_tx: Some(9.0),
            ..HttpRequestStub::default()
        });
        assert_eq!(occupancy_intervals(&ds, 5.0)?.len(), 2);

        // Validate all lifecycle events even when they would fall entirely
        // outside the requested plotting horizon.
        ds.http_requests.insert(5, HttpRequestStub {
            time_discovery: Some(6.0),
            time_first_headers_tx: Some(9.0),
            time_response_terminal: Some(8.0),
            ..HttpRequestStub::default()
        });
        assert!(occupancy_intervals(&ds, 5.0).is_err());
        Ok(())
    }

    #[test]
    fn unfinished_request_with_headers_beyond_horizon_remains_pending(
    ) -> Result<(), Box<dyn Error>> {
        let mut ds = Datastore::default();
        ds.http_requests.insert(1, HttpRequestStub {
            time_discovery: Some(2.0),
            time_first_headers_tx: Some(8.0),
            ..HttpRequestStub::default()
        });
        assert_eq!(occupancy_intervals(&ds, 5.0)?, vec![PendingInterval {
            start: 2.0,
            end: 5.0,
            pending: 1,
            in_flight: 0
        },]);
        Ok(())
    }

    #[test]
    fn server_occupancy_uses_received_request_headers_and_response_terminal_time(
    ) -> Result<(), Box<dyn Error>> {
        use crate::datastore::RequestActor;
        use crate::datastore::VantagePoint;
        let mut ds = Datastore {
            vantage_point: VantagePoint::Server,
            time_session_close: Some(9.0),
            ..Datastore::default()
        };
        ds.http_requests.insert(1, HttpRequestStub {
            request_actor: RequestActor::Server,
            time_first_headers_rx: Some(-4.0),
            time_first_headers_tx: Some(3.0),
            time_response_terminal: Some(5.0),
            time_last_headers_tx: Some(6.0),
            ..HttpRequestStub::default()
        });
        ds.http_requests.insert(3, HttpRequestStub {
            request_actor: RequestActor::Server,
            time_first_headers_rx: Some(7.0),
            ..HttpRequestStub::default()
        });
        assert_eq!(occupancy_intervals(&ds, 12.0)?, [
            PendingInterval {
                start: -4.0,
                end: 6.0,
                pending: 0,
                in_flight: 1
            },
            PendingInterval {
                start: 7.0,
                end: 9.0,
                pending: 0,
                in_flight: 1
            },
        ]);
        Ok(())
    }

    #[test]
    fn client_discovery_can_precede_session_origin() -> Result<(), Box<dyn Error>>
    {
        let mut ds = Datastore::default();
        ds.http_requests.insert(1, HttpRequestStub {
            time_discovery: Some(-5.0),
            time_first_headers_tx: Some(2.0),
            time_response_terminal: Some(3.0),
            ..HttpRequestStub::default()
        });
        assert_eq!(occupancy_intervals(&ds, 5.0)?, [
            PendingInterval {
                start: -5.0,
                end: 2.0,
                pending: 1,
                in_flight: 0
            },
            PendingInterval {
                start: 2.0,
                end: 3.0,
                pending: 0,
                in_flight: 1
            },
        ]);
        assert_eq!(occupancy_intervals(&ds, -1.0)?, [PendingInterval {
            start: -5.0,
            end: -1.0,
            pending: 1,
            in_flight: 0
        },]);
        Ok(())
    }

    #[test]
    fn occupancy_axis_uses_only_visible_intervals() -> Result<(), Box<dyn Error>>
    {
        let mut ds = Datastore {
            last_event_time: 10.0,
            ..Datastore::default()
        };
        for (id, end) in [(1, 3.0), (3, 4.0), (5, 9.0)] {
            ds.http_requests.insert(id, HttpRequestStub {
                time_first_headers_tx: Some(-2.0),
                time_response_terminal: Some(end),
                ..HttpRequestStub::default()
            });
        }
        let plot = pending_plot_data(
            &ClampParams {
                start: Some(5.0),
                end: Some(8.0),
                ..Default::default()
            },
            &SeriesStore::default(),
            &ds,
        )?;
        assert_eq!(plot.range, 5.0..8.0);
        assert_eq!(plot.y_max, 1);
        assert_eq!(plot.intervals, [PendingInterval {
            start: 5.0,
            end: 8.0,
            pending: 0,
            in_flight: 1
        }]);
        Ok(())
    }

    #[test]
    fn pending_png_respects_early_end_clamp() -> Result<(), Box<dyn Error>> {
        let mut ds = Datastore::default();
        ds.http_requests.insert(1, HttpRequestStub {
            time_discovery: Some(1.0),
            time_first_headers_tx: Some(2.0),
            time_response_terminal: Some(20.0),
            ..HttpRequestStub::default()
        });
        let ss = SeriesStore {
            received_x_max: 20.0,
            ..SeriesStore::default()
        };
        let params = PendingPlotParams {
            clamp: ClampParams {
                end: Some(5.0),
                ..ClampParams::default()
            },
            chart_size: ChartSize {
                width: 640,
                height: 440,
            },
            ..PendingPlotParams::default()
        };
        let out = TempCharts::new()?;
        plot_pending(&params, "early-end", &ss, &ds, &out.output())?;
        assert_eq!(image::image_dimensions(out.only_file()?)?, (640, 440));
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
