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

//! Multiplexing charts
//! A single image file containing various renderings of stream and H3 DATA

#[cfg(not(target_arch = "wasm32"))]
use crate::plots::fallible::bitmap_area;
#[cfg(target_arch = "wasm32")]
use crate::plots::fallible::canvas_area;
use crate::plots::fallible::checked_pixel;
use crate::plots::fallible::checked_time_range;
use crate::plots::fallible::invalid_chart;
use std::error::Error;
use std::io;

use crate::datastore::VantagePoint;
use crate::plots::colors::*;
use crate::plots::*;

use crate::datastore::Datastore;
use crate::request_stub::HttpRequestStub;
use crate::seriesstore::SeriesStore;

pub struct MultiplexPlotsParams {
    pub clamp: ClampParams,
    pub bidi_only: bool,
    pub width: u32,
    pub y_spacer: u32,
    pub right_shrink_margin: u32,
    pub combined_plot_height: u32,
    pub frame_swimlane_height: u32,
    pub bubbles_swimlane_height: u32,
    pub colors: PlotColors,
    pub area_margin: AreaMargin,
}

impl Default for MultiplexPlotsParams {
    fn default() -> Self {
        Self {
            bidi_only: true,
            width: 4000,
            y_spacer: 20,
            right_shrink_margin: 50,
            combined_plot_height: 300,
            frame_swimlane_height: 60,
            bubbles_swimlane_height: 100,
            clamp: ClampParams::default(),
            colors: PlotColors::default(),
            area_margin: AreaMargin { x: 40, y: 0 },
        }
    }
}

/// Determine stream visibility using the protocol's stream-ID rules. HTTP/2
/// stream IDs have no QUIC initiator/direction bits.
fn visible_stream(
    params: &MultiplexPlotsParams, protocol: crate::datastore::ApplicationProto,
    stream_id: u64,
) -> bool {
    !params.bidi_only ||
        protocol == crate::datastore::ApplicationProto::Http2 ||
        (stream_id & 2) == 0
}

/// An explicit, non-overlapping vertical layout. Row spacing follows the
/// configured swimlane heights, rather than fixed 20/70px increments that
/// overlapped adjacent charts in the original implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MultiplexLayout {
    width: u32,
    height: u32,
    chart_width: u32,
    data_mini_y: u32,
    bubbles_y: u32,
    stream_combined_y: u32,
    stream_mini_y: u32,
    frame_step: u32,
    bubble_step: u32,
}

impl MultiplexLayout {
    fn new(
        params: &MultiplexPlotsParams, request_count: usize,
    ) -> io::Result<Self> {
        let chart_width = params
            .width
            .checked_sub(params.right_shrink_margin)
            .filter(|width| *width > 0)
            .ok_or_else(|| {
                invalid_chart("multiplex width must exceed its right margin")
            })?;
        if params.combined_plot_height == 0 ||
            params.frame_swimlane_height == 0 ||
            params.bubbles_swimlane_height == 0
        {
            return Err(invalid_chart(
                "multiplex section heights must be nonzero",
            ));
        }
        let rows = u64::try_from(request_count)
            .map_err(|_| invalid_chart("too many multiplex request rows"))?;
        let overflow = || invalid_chart("multiplex layout arithmetic overflow");
        let add = |a: u64, b: u64| a.checked_add(b).ok_or_else(overflow);
        let mul = |a: u64, b: u64| a.checked_mul(b).ok_or_else(overflow);
        let spacing = u64::from(params.y_spacer);
        let frame_step = add(u64::from(params.frame_swimlane_height), spacing)?;
        let bubble_step =
            add(u64::from(params.bubbles_swimlane_height), spacing)?;
        let frame_rows_height = mul(rows, frame_step)?;
        let bubble_rows_height = mul(rows, bubble_step)?;
        let data_mini_y = add(u64::from(params.combined_plot_height), spacing)?;
        let bubbles_y = add(add(data_mini_y, frame_rows_height)?, spacing)?;
        let stream_combined_y =
            add(add(bubbles_y, bubble_rows_height)?, spacing)?;
        let stream_mini_y = add(
            add(stream_combined_y, u64::from(params.combined_plot_height))?,
            spacing,
        )?;
        let full_height =
            add(add(add(stream_mini_y, frame_rows_height)?, spacing)?, 40)?;
        checked_pixel(u64::from(params.width))?;
        checked_pixel(full_height)?;
        for position in [data_mini_y, bubbles_y, stream_combined_y, stream_mini_y]
        {
            checked_pixel(position)?;
        }
        let convert = |v: u64| {
            u32::try_from(v).map_err(|_| {
                invalid_chart("multiplex plot coordinate exceeds u32")
            })
        };
        Ok(Self {
            width: params.width,
            height: convert(full_height)?,
            chart_width,
            data_mini_y: convert(data_mini_y)?,
            bubbles_y: convert(bubbles_y)?,
            stream_combined_y: convert(stream_combined_y)?,
            stream_mini_y: convert(stream_mini_y)?,
            frame_step: convert(frame_step)?,
            bubble_step: convert(bubble_step)?,
        })
    }

    fn row_y(&self, offset: u32, step: u32, row: usize) -> io::Result<i32> {
        let row = u64::try_from(row)
            .map_err(|_| invalid_chart("row index exceeds u64"))?;
        let y = row
            .checked_mul(u64::from(step))
            .and_then(|offset_y| u64::from(offset).checked_add(offset_y))
            .ok_or_else(|| {
                invalid_chart("multiplex request row coordinate overflow")
            })?;
        checked_pixel(y)
    }
}

/// Select the recorded DATA frames for the trace vantage without collecting a
/// second vector of per-request references.
fn request_data_frames(
    request: &HttpRequestStub, vantage: VantagePoint,
) -> &[(f64, u64)] {
    match vantage {
        VantagePoint::Client => &request.time_data_rx_set,
        VantagePoint::Server => &request.time_data_tx_set,
    }
}

/// Draw per-stream DATA and STREAM events across combined and individual lanes.
///
/// # Errors
/// Returns invalid layout, nonfinite times, output filesystem/canvas, and
/// backend/drawing failures as errors rather than panicking.
pub fn plot_stream_multiplexing(
    params: &MultiplexPlotsParams, _filename: &str, ss: &SeriesStore,
    ds: &Datastore, ty: &ChartOutputType,
) -> Result<(), Box<dyn Error>> {
    let requests = ds.http_requests.iter().filter(|(stream_id, _)| {
        visible_stream(params, ds.application_proto, **stream_id)
    });
    let layout = MultiplexLayout::new(params, requests.clone().count())?;

    let stream_frame_series = match (ds.application_proto, ds.vantage_point) {
        (crate::datastore::ApplicationProto::Http2, VantagePoint::Client) =>
            &ss.received_data_frames_series,
        (crate::datastore::ApplicationProto::Http2, VantagePoint::Server) =>
            &ss.sent_data_frames_series,
        (crate::datastore::ApplicationProto::Http3, VantagePoint::Client) =>
            &ss.received_stream_frames_series,
        (crate::datastore::ApplicationProto::Http3, VantagePoint::Server) =>
            &ss.sent_stream_frames_series,
    };
    let (mut start, mut end) = match ds.vantage_point {
        VantagePoint::Client => (ss.received_x_min, ss.received_x_max),
        VantagePoint::Server => (ss.sent_x_min, ss.sent_x_max),
    };
    if !start.is_finite() || !end.is_finite() {
        return Err(
            invalid_chart("multiplex source time bounds must be finite").into()
        );
    }
    for time in requests
        .clone()
        .flat_map(|(_, request)| {
            request_data_frames(request, ds.vantage_point)
                .iter()
                .map(|point| point.0)
        })
        .chain(
            stream_frame_series
                .iter()
                .filter(|(id, _)| {
                    visible_stream(params, ds.application_proto, **id)
                })
                .flat_map(|(_, points)| points.iter().map(|point| point.0)),
        )
        .chain(
            requests
                .clone()
                .flat_map(|(_, request)| {
                    [request.time_first_headers_rx, request.time_first_headers_tx]
                })
                .flatten(),
        )
    {
        if !time.is_finite() {
            return Err(invalid_chart(
                "multiplex event timestamps must be finite",
            )
            .into());
        }
        start = start.min(time);
        end = end.max(time);
    }
    let x_range = checked_time_range(start, end, &params.clamp)?;

    let config =
        ChartConfig::new("stream-multiplexing", _filename, &params.clamp, ds, ty);
    let margin = ChartMargin {
        top: 20,
        bottom: 20,
        left: 20,
        right: 20,
    };
    #[cfg(not(target_arch = "wasm32"))]
    let chart_path = match ty {
        ChartOutputType::Png { .. } => config.chart_filepath(),
        ChartOutputType::Canvas { .. } =>
            return Err(invalid_chart(
                "native multiplex chart requires PNG output",
            )
            .into()),
    };
    #[cfg(not(target_arch = "wasm32"))]
    let root = bitmap_area(
        &chart_path,
        ChartSize {
            width: layout.width,
            height: layout.height,
        },
        params.colors,
        margin,
    )?;

    #[cfg(target_arch = "wasm32")]
    let canvas_id = config.canvas_id().ok_or_else(|| {
        invalid_chart("browser multiplex chart requires canvas output")
    })?;
    #[cfg(target_arch = "wasm32")]
    let root = canvas_area(&canvas_id, params.colors, margin)?;

    let mut palette = ColorCycle::default();
    let combined_data_area = root
        .clone()
        .shrink((0, 0), (layout.chart_width, params.combined_plot_height));
    let mut combined_data = ChartBuilder::on(&combined_data_area)
        .caption(
            "DATA frame events",
            chart_title_style(&params.colors.caption),
        )
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y)
        .build_cartesian_2d(x_range.clone(), 0..2)?;
    combined_data
        .configure_mesh()
        .disable_mesh()
        .axis_style(params.colors.axis)
        .label_style(chart_label_style(&params.colors.caption))
        .draw()?;
    for (_, request) in requests.clone() {
        let points = request_data_frames(request, ds.vantage_point);
        let color = palette.next_color();
        combined_data.draw_series(points.iter().map(|(time, _)| {
            PathElement::new([(*time, 2), (*time, 0)], color)
        }))?;
    }

    palette.reset();
    let combined_stream_area = root.clone().shrink(
        (0, checked_pixel(u64::from(layout.stream_combined_y))?),
        (layout.chart_width, params.combined_plot_height),
    );
    let mut combined_stream = ChartBuilder::on(&combined_stream_area)
        .caption(
            "STREAM frame events",
            chart_title_style(&params.colors.caption),
        )
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y)
        .build_cartesian_2d(x_range.clone(), 0..2)?;
    combined_stream
        .configure_mesh()
        .disable_mesh()
        .axis_style(params.colors.axis)
        .label_style(chart_label_style(&params.colors.caption))
        .draw()?;
    for (_, points) in stream_frame_series
        .iter()
        .filter(|(id, _)| visible_stream(params, ds.application_proto, **id))
    {
        let color = palette.next_color();
        combined_stream.draw_series(points.iter().map(|(time, _)| {
            PathElement::new([(*time, 2), (*time, 0)], color)
        }))?;
    }

    palette.reset();
    let max_data = requests
        .clone()
        .flat_map(|(_, request)| {
            request_data_frames(request, ds.vantage_point)
                .iter()
                .map(|point| point.1)
        })
        .max()
        .unwrap_or(0)
        .max(1);
    for (row, (stream_id, request)) in requests.enumerate() {
        let points = request_data_frames(request, ds.vantage_point);
        let color = palette.next_color();
        let frame_y = layout.row_y(layout.data_mini_y, layout.frame_step, row)?;
        let stream_y =
            layout.row_y(layout.stream_mini_y, layout.frame_step, row)?;
        let bubble_y = layout.row_y(layout.bubbles_y, layout.bubble_step, row)?;
        let data_area = root.clone().shrink(
            (0, frame_y),
            (layout.chart_width, params.frame_swimlane_height),
        );
        let stream_area = root.clone().shrink(
            (0, stream_y),
            (layout.chart_width, params.frame_swimlane_height),
        );
        let bubble_area = root.clone().shrink(
            (0, bubble_y),
            (layout.chart_width, params.bubbles_swimlane_height),
        );

        let mut data_chart = ChartBuilder::on(&data_area)
            .x_label_area_size(params.area_margin.x)
            .y_label_area_size(params.area_margin.y)
            .build_cartesian_2d(x_range.clone(), 0..4)?;
        data_chart
            .configure_mesh()
            .disable_y_mesh()
            .disable_y_axis()
            .axis_style(params.colors.axis)
            .draw()?;
        let mut stream_chart = ChartBuilder::on(&stream_area)
            .x_label_area_size(params.area_margin.x)
            .y_label_area_size(params.area_margin.y)
            .build_cartesian_2d(x_range.clone(), 0..4)?;
        stream_chart
            .configure_mesh()
            .disable_y_mesh()
            .disable_y_axis()
            .axis_style(params.colors.axis)
            .draw()?;

        for time in [
            match ds.vantage_point {
                VantagePoint::Client => request.time_first_headers_tx,
                VantagePoint::Server => request.time_first_headers_rx,
            },
            match ds.vantage_point {
                VantagePoint::Client => request.time_first_headers_rx,
                VantagePoint::Server => request.time_first_headers_tx,
            },
        ]
        .into_iter()
        .flatten()
        {
            data_chart.draw_series([TriangleMarker::new((time, 2), 5, color)])?;
            stream_chart.draw_series([TriangleMarker::new(
                (time, 2),
                5,
                color,
            )])?;
        }
        data_chart.draw_series(points.iter().map(|(time, _)| {
            PathElement::new([(*time, 2), (*time, 0)], color)
        }))?;
        if let Some(stream_frames) = stream_frame_series.get(stream_id) {
            stream_chart.draw_series(stream_frames.iter().map(|(time, _)| {
                PathElement::new([(*time, 2), (*time, 0)], color)
            }))?;
        }

        let mut length_chart = ChartBuilder::on(&bubble_area)
            .x_label_area_size(params.area_margin.x)
            .y_label_area_size(params.area_margin.y)
            .build_cartesian_2d(x_range.clone(), 0..max_data)?;
        length_chart
            .configure_mesh()
            .disable_y_mesh()
            .disable_y_axis()
            .axis_style(params.colors.axis)
            .draw()?;
        length_chart.draw_series(points.iter().map(|(time, length)| {
            PathElement::new([(*time, 0), (*time, *length)], color)
        }))?;
    }
    root.present()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datastore::ApplicationProto;
    use crate::plots::fallible::test_support::TempCharts;
    use crate::request_stub::HttpRequestStub;

    fn test_params() -> MultiplexPlotsParams {
        MultiplexPlotsParams {
            width: 760,
            combined_plot_height: 110,
            frame_swimlane_height: 68,
            bubbles_swimlane_height: 74,
            y_spacer: 12,
            right_shrink_margin: 35,
            area_margin: AreaMargin { x: 26, y: 10 },
            ..MultiplexPlotsParams::default()
        }
    }

    #[test]
    fn layout_never_overlaps_and_rejects_impossible_dimensions(
    ) -> Result<(), Box<dyn Error>> {
        let params = test_params();
        let layout = MultiplexLayout::new(&params, 3)?;
        assert!(layout.data_mini_y >= params.combined_plot_height);
        assert!(layout.bubbles_y >= layout.data_mini_y + 3 * layout.frame_step);
        assert!(
            layout.stream_combined_y >= layout.bubbles_y + 3 * layout.bubble_step
        );
        assert!(
            layout.stream_mini_y >=
                layout.stream_combined_y + params.combined_plot_height
        );
        assert!(layout.height > layout.stream_mini_y + 3 * layout.frame_step);
        let bad_width = MultiplexPlotsParams {
            right_shrink_margin: params.width + 1,
            ..test_params()
        };
        assert!(MultiplexLayout::new(&bad_width, 1).is_err());
        let bad_height = MultiplexPlotsParams {
            combined_plot_height: u32::MAX,
            ..test_params()
        };
        assert!(MultiplexLayout::new(&bad_height, 1).is_err());
        assert!(MultiplexLayout::new(&params, usize::MAX).is_err());
        Ok(())
    }

    #[test]
    fn empty_logs_render_and_bad_output_paths_return_errors(
    ) -> Result<(), Box<dyn Error>> {
        let params = test_params();
        let ss = SeriesStore::default();
        let ds = Datastore::default();
        let out = TempCharts::new()?;
        plot_stream_multiplexing(&params, "no-events", &ss, &ds, &out.output())?;
        let path = out.only_file()?;
        let (width, height) = image::image_dimensions(&path)?;
        assert_eq!(
            (width, height),
            (params.width, MultiplexLayout::new(&params, 0)?.height)
        );
        let blocked = TempCharts::new()?;
        let obstacle = blocked.0.join("occupied-file");
        std::fs::write(&obstacle, b"not a directory")?;
        let ty = ChartOutputType::Png {
            output_dir: obstacle.to_string_lossy().into_owned(),
            cwnd_y_max: None,
            stream_y_max: None,
        };
        assert!(
            plot_stream_multiplexing(&params, "blocked", &ss, &ds, &ty).is_err()
        );
        Ok(())
    }

    #[test]
    fn http2_request_ids_not_filtered_and_large_data_lengths_render(
    ) -> Result<(), Box<dyn Error>> {
        let params = test_params();
        let mut ds = Datastore {
            application_proto: ApplicationProto::Http2,
            vantage_point: VantagePoint::Server,
            ..Datastore::default()
        };
        let request = HttpRequestStub {
            time_data_tx_set: vec![(1.0, 9), (4.0, 7), (7.0, 1)],
            time_first_headers_rx: Some(0.5),
            ..HttpRequestStub::default()
        };
        // HTTP/2 stream ID 3 is not QUIC unidirectional and must survive
        // bidi_only.
        ds.http_requests.insert(3, request);
        let mut series = SeriesStore {
            sent_x_min: 0.0,
            sent_x_max: 8.0,
            ..SeriesStore::default()
        };
        series
            .sent_data_frames_series
            .insert(3, vec![(1.0, 3), (6.0, 5)]);
        let out = TempCharts::new()?;
        plot_stream_multiplexing(&params, "h2-id3", &series, &ds, &out.output())?;
        let path = out.only_file()?;
        let rendered = image::open(&path)?.to_rgb8();
        let layout = MultiplexLayout::new(&params, 1)?;
        assert_eq!(
            (rendered.width(), rendered.height()),
            (layout.width, layout.height)
        );
        // Compare to same request without STREAM/DATA samples. Chart geometry
        // remains identical; pixel differences prove the H2 stream was drawn.
        let no_frames = SeriesStore {
            sent_x_min: 0.0,
            sent_x_max: 8.0,
            ..SeriesStore::default()
        };
        // No frame series, preserving the source time bounds.
        let out_without = TempCharts::new()?;
        plot_stream_multiplexing(
            &params,
            "h2-id3",
            &no_frames,
            &ds,
            &out_without.output(),
        )?;
        let without = image::open(out_without.only_file()?)?.to_rgb8();
        assert_ne!(
            rendered.as_raw(),
            without.as_raw(),
            "HTTP/2 STREAM lane must render DATA frames"
        );

        // HTTP/3 does have unidirectional stream IDs; bidi-only filters them.
        ds.application_proto = ApplicationProto::Http3;
        let filtered = TempCharts::new()?;
        plot_stream_multiplexing(
            &params,
            "h3-id3",
            &series,
            &ds,
            &filtered.output(),
        )?;
        let (_, filtered_height) =
            image::image_dimensions(filtered.only_file()?)?;
        assert_eq!(filtered_height, MultiplexLayout::new(&params, 0)?.height);
        assert!(filtered_height < layout.height);
        Ok(())
    }

    #[test]
    fn multiple_requests_preserve_sorted_lanes_and_vantage_specific_data(
    ) -> Result<(), Box<dyn Error>> {
        let params = test_params();
        let mut datastore = Datastore {
            application_proto: ApplicationProto::Http2,
            vantage_point: VantagePoint::Client,
            ..Datastore::default()
        };
        // Insert out of stream-ID order; each request must retain its own
        // distinct payload and grid row, whichever vantage is selected.
        datastore.http_requests.insert(7, HttpRequestStub {
            time_data_rx_set: vec![(3.0, 8), (8.0, 12)],
            time_data_tx_set: vec![(2.0, 3)],
            ..HttpRequestStub::default()
        });
        datastore.http_requests.insert(3, HttpRequestStub {
            time_data_rx_set: vec![(1.0, 30)],
            time_data_tx_set: vec![(6.0, 5), (9.0, 11)],
            ..HttpRequestStub::default()
        });
        let series = SeriesStore {
            received_x_min: 0.0,
            received_x_max: 10.0,
            sent_x_min: 0.0,
            sent_x_max: 10.0,
            ..SeriesStore::default()
        };

        let client_output = TempCharts::new()?;
        plot_stream_multiplexing(
            &params,
            "multi-request",
            &series,
            &datastore,
            &client_output.output(),
        )?;
        let client_png = image::open(client_output.only_file()?)?.to_rgb8();
        let expected_height = MultiplexLayout::new(&params, 2)?.height;
        assert_eq!(client_png.dimensions(), (params.width, expected_height));

        datastore.vantage_point = VantagePoint::Server;
        let server_output = TempCharts::new()?;
        plot_stream_multiplexing(
            &params,
            "multi-request",
            &series,
            &datastore,
            &server_output.output(),
        )?;
        let server_png = image::open(server_output.only_file()?)?.to_rgb8();
        assert_eq!(server_png.dimensions(), client_png.dimensions());
        assert_ne!(
            client_png.as_raw(),
            server_png.as_raw(),
            "client RX and server TX data must produce different lane plots"
        );
        Ok(())
    }

    #[test]
    fn reject_nonfinite_event_timestamps_before_backend_rendering(
    ) -> Result<(), Box<dyn Error>> {
        let params = test_params();
        let mut ds = Datastore::default();
        ds.http_requests.insert(1, HttpRequestStub {
            time_data_tx_set: vec![(f64::NAN, 3)],
            ..HttpRequestStub::default()
        });
        ds.vantage_point = VantagePoint::Server;
        let out = TempCharts::new()?;
        assert!(plot_stream_multiplexing(
            &params,
            "nan-time",
            &SeriesStore::default(),
            &ds,
            &out.output()
        )
        .is_err());
        assert!(
            std::fs::read_dir(&out.0)?.next().is_none(),
            "no invalid partial PNG should be created"
        );
        Ok(())
    }
}
