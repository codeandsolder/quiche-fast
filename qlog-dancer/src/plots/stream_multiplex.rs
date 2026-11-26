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

use crate::plots::fallible::checked_pixel;
use crate::plots::fallible::checked_time_range;
use crate::plots::fallible::invalid_chart;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::ops::Range;

use plotters::coord::Shift;
use plotters::drawing::DrawingArea;
use plotters::prelude::ChartBuilder;
use plotters::prelude::DrawingBackend;
use plotters::prelude::PathElement;
use plotters::prelude::RGBColor;
use plotters::prelude::TriangleMarker;

use crate::datastore::ApplicationProto;
use crate::datastore::VantagePoint;
use crate::plots::chart_label_style;
use crate::plots::chart_title_style;
use crate::plots::colors::ColorCycle;
use crate::plots::colors::PlotColors;
use crate::plots::AreaMargin;
use crate::plots::ChartConfig;
use crate::plots::ChartMargin;
use crate::plots::ChartOutputType;
use crate::plots::ChartSize;
use crate::plots::ClampParams;
use crate::QlogPointu64;

use crate::datastore::Datastore;
use crate::request_stub::DataObservation;
use crate::request_stub::HttpRequestStub;
use crate::seriesstore::SeriesStore;

#[derive(Clone)]
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
    params: &MultiplexPlotsParams, protocol: ApplicationProto, stream_id: u64,
) -> bool {
    !params.bidi_only ||
        protocol == ApplicationProto::Http2 ||
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
    stream_section: Option<StreamSection>,
    frame_step: u32,
    bubble_step: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamSection {
    combined_y: u32,
    mini_y: u32,
}

impl MultiplexLayout {
    fn new(
        params: &MultiplexPlotsParams, request_count: usize,
        protocol: ApplicationProto,
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
        let data_end = add(add(bubbles_y, bubble_rows_height)?, spacing)?;
        let convert = |v: u64| {
            checked_pixel(v)?;
            u32::try_from(v).map_err(|_| {
                invalid_chart("multiplex plot coordinate exceeds u32")
            })
        };
        let (stream_section, content_end) = match protocol {
            ApplicationProto::Http2 => (None, data_end),
            ApplicationProto::Http3 => {
                let mini_y = add(
                    add(data_end, u64::from(params.combined_plot_height))?,
                    spacing,
                )?;
                let end = add(add(mini_y, frame_rows_height)?, spacing)?;
                (
                    Some(StreamSection {
                        combined_y: convert(data_end)?,
                        mini_y: convert(mini_y)?,
                    }),
                    end,
                )
            },
        };
        let full_height = add(content_end, 40)?;
        checked_pixel(u64::from(params.width))?;
        Ok(Self {
            width: params.width,
            height: convert(full_height)?,
            chart_width,
            data_mini_y: convert(data_mini_y)?,
            bubbles_y: convert(bubbles_y)?,
            stream_section,
            frame_step: convert(frame_step)?,
            bubble_step: convert(bubble_step)?,
        })
    }

    fn row_y(offset: u32, step: u32, row: usize) -> io::Result<i32> {
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
const fn request_data_frames(
    request: &HttpRequestStub, vantage: VantagePoint,
) -> &[DataObservation] {
    match vantage {
        VantagePoint::Client => request.received_data.observations(),
        VantagePoint::Server => request.sent_data.observations(),
    }
}

/// Assign one deterministic color to every visible stream ID represented by
/// either the request list or the STREAM/DATA frame series. Some streams appear
/// in only one source; independent palette iteration would shift the colors
/// of later streams between combined and per-request panels.
fn colors_for_visible_streams(
    params: &MultiplexPlotsParams, ds: &Datastore,
    stream_frame_series: Option<&BTreeMap<u64, Vec<QlogPointu64>>>,
) -> BTreeMap<u64, RGBColor> {
    let ids: BTreeSet<u64> = ds
        .http_requests
        .keys()
        .chain(stream_frame_series.into_iter().flat_map(BTreeMap::keys))
        .copied()
        .filter(|&id| visible_stream(params, ds.application_proto, id))
        .collect();

    let mut palette = ColorCycle::default();
    ids.into_iter()
        .map(|id| (id, palette.next_color()))
        .collect()
}

/// Borrowed observations for one stream. A stream may have received frames
/// even if the capture omitted its request headers.
struct MultiplexLane<'a> {
    color: RGBColor,
    data: &'a [DataObservation],
    frames: &'a [QlogPointu64],
    headers: [Option<f64>; 2],
}

struct MultiplexModel<'a> {
    lanes: BTreeMap<u64, MultiplexLane<'a>>,
    layout: MultiplexLayout,
    x_range: Range<f64>,
    max_data: u64,
}

impl<'a> MultiplexModel<'a> {
    fn new(
        params: &MultiplexPlotsParams, ss: &'a SeriesStore, ds: &'a Datastore,
    ) -> io::Result<Self> {
        let frame_series = match (ds.application_proto, ds.vantage_point) {
            (ApplicationProto::Http2, _) => None,
            (ApplicationProto::Http3, VantagePoint::Client) =>
                Some(&ss.received_stream_frames_series),
            (ApplicationProto::Http3, VantagePoint::Server) =>
                Some(&ss.sent_stream_frames_series),
        };
        let colors = colors_for_visible_streams(params, ds, frame_series);
        let lanes = colors
            .into_iter()
            .map(|(id, color)| {
                let request = ds.http_requests.get(&id);
                let data = request.map_or(&[][..], |request| {
                    request_data_frames(request, ds.vantage_point)
                });
                let frames = frame_series
                    .and_then(|series| series.get(&id))
                    .map_or(&[][..], Vec::as_slice);
                let headers = request.map_or([None, None], |request| {
                    [request.time_first_headers_rx, request.time_first_headers_tx]
                });
                (id, MultiplexLane {
                    color,
                    data,
                    frames,
                    headers,
                })
            })
            .collect::<BTreeMap<_, _>>();
        let (mut start, mut end) = match ds.vantage_point {
            VantagePoint::Client => (ss.received_x_min, ss.received_x_max),
            VantagePoint::Server => (ss.sent_x_min, ss.sent_x_max),
        };
        if !start.is_finite() || !end.is_finite() {
            return Err(invalid_chart(
                "multiplex source time bounds must be finite",
            ));
        }
        let mut max_data = 1;
        for lane in lanes.values() {
            for length in lane.data.iter().filter_map(|point| point.1) {
                max_data = max_data.max(length);
            }
            for time in lane
                .data
                .iter()
                .map(|point| point.0)
                .chain(lane.frames.iter().map(|point| point.0))
                .chain(lane.headers.into_iter().flatten())
            {
                if !time.is_finite() {
                    return Err(invalid_chart(
                        "multiplex event timestamps must be finite",
                    ));
                }
                start = start.min(time);
                end = end.max(time);
            }
        }
        let layout =
            MultiplexLayout::new(params, lanes.len(), ds.application_proto)?;
        let x_range = checked_time_range(start, end, &params.clamp)?;
        Ok(Self {
            lanes,
            layout,
            x_range,
            max_data,
        })
    }
}

#[derive(Clone, Copy)]
enum FrameKind {
    Data,
    Stream,
}

impl FrameKind {
    const fn caption(self) -> &'static str {
        match self {
            Self::Data => "DATA frame events",
            Self::Stream => "STREAM frame events",
        }
    }

    fn times<'a>(
        self, lane: &MultiplexLane<'a>,
    ) -> impl Iterator<Item = f64> + 'a {
        let (data, frames) = match self {
            Self::Data => (lane.data, &[][..]),
            Self::Stream => (&[][..], lane.frames),
        };
        data.iter()
            .map(|point| point.0)
            .chain(frames.iter().map(|point| point.0))
    }
}

fn draw_combined<DB: DrawingBackend>(
    area: &DrawingArea<DB, Shift>, params: &MultiplexPlotsParams,
    model: &MultiplexModel<'_>, kind: FrameKind,
) -> Result<(), Box<dyn Error>>
where
    DB::ErrorType: 'static,
{
    let mut chart = ChartBuilder::on(area)
        .caption(kind.caption(), chart_title_style(&params.colors.caption))
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y)
        .build_cartesian_2d(model.x_range.clone(), 0..2)?;
    chart
        .configure_mesh()
        .disable_mesh()
        .axis_style(params.colors.axis)
        .label_style(chart_label_style(&params.colors.caption))
        .draw()?;
    for lane in model.lanes.values() {
        chart
            .draw_series(kind.times(lane).map(|time| {
                PathElement::new([(time, 2), (time, 0)], lane.color)
            }))?;
    }
    Ok(())
}

fn draw_frame_lane<DB: DrawingBackend>(
    area: &DrawingArea<DB, Shift>, params: &MultiplexPlotsParams,
    range: &Range<f64>, lane: &MultiplexLane<'_>, kind: FrameKind,
) -> Result<(), Box<dyn Error>>
where
    DB::ErrorType: 'static,
{
    let mut chart = ChartBuilder::on(area)
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y)
        .build_cartesian_2d(range.clone(), 0..4)?;
    chart
        .configure_mesh()
        .disable_y_mesh()
        .disable_y_axis()
        .axis_style(params.colors.axis)
        .draw()?;
    chart.draw_series(
        lane.headers
            .into_iter()
            .flatten()
            .map(|time| TriangleMarker::new((time, 2), 5, lane.color)),
    )?;
    chart.draw_series(
        kind.times(lane)
            .map(|time| PathElement::new([(time, 2), (time, 0)], lane.color)),
    )?;
    Ok(())
}

fn draw_length_lane<DB: DrawingBackend>(
    area: &DrawingArea<DB, Shift>, params: &MultiplexPlotsParams,
    model: &MultiplexModel<'_>, lane: &MultiplexLane<'_>,
) -> Result<(), Box<dyn Error>>
where
    DB::ErrorType: 'static,
{
    let mut chart = ChartBuilder::on(area)
        .x_label_area_size(params.area_margin.x)
        .y_label_area_size(params.area_margin.y)
        .build_cartesian_2d(model.x_range.clone(), 0..model.max_data)?;
    chart
        .configure_mesh()
        .disable_y_mesh()
        .disable_y_axis()
        .axis_style(params.colors.axis)
        .draw()?;
    chart.draw_series(lane.data.iter().filter_map(|&(time, length)| {
        length.map(|length| {
            PathElement::new([(time, 0), (time, length)], lane.color)
        })
    }))?;
    Ok(())
}

fn draw_multiplex<DB: DrawingBackend>(
    root: &DrawingArea<DB, Shift>, params: &MultiplexPlotsParams,
    model: &MultiplexModel<'_>,
) -> Result<(), Box<dyn Error>>
where
    DB::ErrorType: 'static,
{
    let layout = &model.layout;
    let combined = std::iter::once((0, FrameKind::Data)).chain(
        layout
            .stream_section
            .as_ref()
            .map(|section| (section.combined_y, FrameKind::Stream)),
    );
    for (y, kind) in combined {
        let y = checked_pixel(u64::from(y))?;
        let area = root
            .clone()
            .shrink((0, y), (layout.chart_width, params.combined_plot_height));
        draw_combined(&area, params, model, kind)?;
    }
    for (row, lane) in model.lanes.values().enumerate() {
        let frames = std::iter::once((layout.data_mini_y, FrameKind::Data))
            .chain(
                layout
                    .stream_section
                    .as_ref()
                    .map(|section| (section.mini_y, FrameKind::Stream)),
            );
        for (offset, kind) in frames {
            let y = MultiplexLayout::row_y(offset, layout.frame_step, row)?;
            let area = root.clone().shrink(
                (0, y),
                (layout.chart_width, params.frame_swimlane_height),
            );
            draw_frame_lane(&area, params, &model.x_range, lane, kind)?;
        }
        let y =
            MultiplexLayout::row_y(layout.bubbles_y, layout.bubble_step, row)?;
        let area = root
            .clone()
            .shrink((0, y), (layout.chart_width, params.bubbles_swimlane_height));
        draw_length_lane(&area, params, model, lane)?;
    }
    root.present()?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn multiplex_canvas(
    ty: &ChartOutputType,
) -> io::Result<web_sys::HtmlCanvasElement> {
    use wasm_bindgen::JsCast;
    let ChartOutputType::Canvas { canvas_id } = ty else {
        return Err(invalid_chart(
            "browser multiplex chart requires canvas output",
        ));
    };
    web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(canvas_id))
        .and_then(|element| element.dyn_into().ok())
        .ok_or_else(|| invalid_chart("multiplex canvas not found"))
}

/// Draw per-stream DATA and STREAM events across combined and individual lanes.
/// # Errors
/// Returns invalid layout, nonfinite times, output filesystem/canvas, and
/// backend/drawing failures as errors rather than panicking.
pub fn plot_stream_multiplexing(
    params: &MultiplexPlotsParams, filename: &str, ss: &SeriesStore,
    ds: &Datastore, ty: &ChartOutputType,
) -> Result<(), Box<dyn Error>> {
    #[cfg(target_arch = "wasm32")]
    let canvas = multiplex_canvas(ty)?;
    #[cfg(target_arch = "wasm32")]
    let browser_params = MultiplexPlotsParams {
        width: canvas.width(),
        ..params.clone()
    };
    #[cfg(target_arch = "wasm32")]
    let params = &browser_params;

    let model = MultiplexModel::new(params, ss, ds)?;
    let config =
        ChartConfig::new("stream-multiplexing", filename, &params.clamp, ds, ty);
    let margin = ChartMargin {
        top: 20,
        bottom: 20,
        left: 20,
        right: 20,
    };
    #[cfg(target_arch = "wasm32")]
    canvas.set_height(model.layout.height);
    config.render(
        ChartSize {
            width: model.layout.width,
            height: model.layout.height,
        },
        params.colors,
        margin,
        |root| {
            draw_multiplex(root, params, &model)?;
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plots::fallible::test_support::TempCharts;
    use crate::request_stub::HttpDataHistory;

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
    fn stream_colors_use_union_of_visible_request_and_frame_ids() {
        let params = test_params();
        let mut ds = Datastore {
            application_proto: ApplicationProto::Http3,
            ..Datastore::default()
        };
        // A frame-only stream 1 shifts the positional palette: stream 9
        // would be color #2 in request lanes but color #3 in frame lanes.
        // QUIC unidirectional IDs 2 and 6 are excluded by bidi_only.
        for stream_id in [9, 2, 5] {
            ds.http_requests
                .insert(stream_id, HttpRequestStub::default());
        }
        let frame_series = BTreeMap::from([
            (1, vec![(0.0, 2)]),
            (5, vec![(0.2, 2)]),
            (6, vec![(0.5, 2)]),
            (9, vec![(1.0, 2)]),
        ]);

        let colors =
            colors_for_visible_streams(&params, &ds, Some(&frame_series));
        assert_eq!(colors.keys().copied().collect::<Vec<_>>(), vec![1, 5, 9]);

        let mut expected = ColorCycle::default();
        for stream_id in [1, 5, 9] {
            assert_eq!(colors[&stream_id], expected.next_color());
        }
        let mut former_request_palette = ColorCycle::default();
        let _first_request_color = former_request_palette.next_color();
        assert_ne!(colors[&9], former_request_palette.next_color());

        // The mapping is independent of insertion order and remains stable
        // when we repeat the same selection for all three plot sections.
        assert_eq!(
            colors_for_visible_streams(&params, &ds, Some(&frame_series)),
            colors
        );

        // HTTP/2 has no QUIC direction bits: IDs 2 and 6 become visible.
        ds.application_proto = ApplicationProto::Http2;
        let h2 = colors_for_visible_streams(&params, &ds, Some(&frame_series));
        assert_eq!(h2.keys().copied().collect::<Vec<_>>(), vec![1, 2, 5, 6, 9]);
    }

    #[test]
    fn frame_only_streams_receive_lanes_and_extend_time_bounds(
    ) -> Result<(), Box<dyn Error>> {
        let params = test_params();
        let mut ds = Datastore {
            application_proto: ApplicationProto::Http3,
            vantage_point: VantagePoint::Client,
            ..Datastore::default()
        };
        ds.http_requests.insert(5, HttpRequestStub {
            received_data: HttpDataHistory::with_known_frames(&[(3.0, 30)])?,
            time_first_headers_rx: Some(2.0),
            ..HttpRequestStub::default()
        });
        let ss = SeriesStore {
            received_stream_frames_series: BTreeMap::from([
                (1, vec![(9.0, 7)]),
                (2, vec![(1000.0, 1)]),
            ]),
            ..SeriesStore::default()
        };
        let model = MultiplexModel::new(&params, &ss, &ds)?;
        assert_eq!(model.lanes.keys().copied().collect::<Vec<_>>(), [1, 5]);
        assert_eq!(model.lanes[&1].frames, [(9.0, 7)]);
        assert_eq!(model.lanes[&1].data, []);
        assert_eq!(model.x_range, 0.0..9.0);
        assert_eq!(model.max_data, 30);
        assert_eq!(
            model.layout,
            MultiplexLayout::new(&params, 2, ApplicationProto::Http3)?
        );
        Ok(())
    }

    #[test]
    fn unknown_data_lengths_keep_event_markers_without_inflating_lengths(
    ) -> Result<(), Box<dyn Error>> {
        let params = test_params();
        let mut ds = Datastore {
            application_proto: ApplicationProto::Http3,
            vantage_point: VantagePoint::Client,
            ..Datastore::default()
        };
        let mut request = HttpRequestStub::default();
        request.received_data.record(2.0, Some(3))?;
        request.received_data.record(7.0, None)?;
        ds.http_requests.insert(1, request);
        let series = SeriesStore::from_datastore(&ds)?;
        let model = MultiplexModel::new(&params, &series, &ds)?;
        let lane = &model.lanes[&1];
        assert_eq!(FrameKind::Data.times(lane).collect::<Vec<_>>(), vec![
            2.0, 7.0
        ]);
        assert_eq!(lane.data, &[(2.0, Some(3)), (7.0, None)]);
        assert_eq!(model.max_data, 3);
        assert_eq!(model.x_range.end, 7.0);
        Ok(())
    }

    #[test]
    fn layout_never_overlaps_and_rejects_impossible_dimensions(
    ) -> Result<(), Box<dyn Error>> {
        let params = test_params();
        let layout = MultiplexLayout::new(&params, 3, ApplicationProto::Http3)?;
        assert!(layout.data_mini_y >= params.combined_plot_height);
        assert!(layout.bubbles_y >= layout.data_mini_y + 3 * layout.frame_step);
        let stream = layout
            .stream_section
            .as_ref()
            .ok_or("missing HTTP/3 STREAM section")?;
        assert!(stream.combined_y >= layout.bubbles_y + 3 * layout.bubble_step);
        assert!(stream.mini_y >= stream.combined_y + params.combined_plot_height);
        assert!(layout.height > stream.mini_y + 3 * layout.frame_step);
        let h2 = MultiplexLayout::new(&params, 3, ApplicationProto::Http2)?;
        assert!(h2.stream_section.is_none());
        assert!(h2.height > h2.bubbles_y + 3 * h2.bubble_step);
        assert!(h2.height < layout.height);
        let bad_width = MultiplexPlotsParams {
            right_shrink_margin: params.width + 1,
            ..test_params()
        };
        assert!(
            MultiplexLayout::new(&bad_width, 1, ApplicationProto::Http3).is_err()
        );
        let bad_height = MultiplexPlotsParams {
            combined_plot_height: u32::MAX,
            ..test_params()
        };
        assert!(
            MultiplexLayout::new(&bad_height, 1, ApplicationProto::Http3)
                .is_err()
        );
        assert!(MultiplexLayout::new(
            &params,
            usize::MAX,
            ApplicationProto::Http3
        )
        .is_err());
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
            (
                params.width,
                MultiplexLayout::new(&params, 0, ApplicationProto::Http3)?.height
            )
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
            sent_data: HttpDataHistory::with_known_frames(&[
                (1.0, 9),
                (4.0, 7),
                (7.0, 1),
            ])?,
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
        let layout = MultiplexLayout::new(&params, 1, ApplicationProto::Http2)?;
        assert_eq!(
            (rendered.width(), rendered.height()),
            (layout.width, layout.height)
        );
        let model = MultiplexModel::new(&params, &series, &ds)?;
        assert_eq!(model.lanes.keys().copied().collect::<Vec<_>>(), [3]);
        assert_eq!(model.lanes[&3].frames, []);
        assert!(model.layout.stream_section.is_none());
        // Cumulative DATA samples are not transport STREAM events and must
        // not influence the HTTP/2 multiplex output.
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
        assert_eq!(
            rendered.as_raw(),
            without.as_raw(),
            "HTTP/2 multiplex must render only actual DATA observations"
        );

        ds.http_requests
            .get_mut(&3)
            .ok_or("missing request")?
            .sent_data = HttpDataHistory::default();
        let empty_data = TempCharts::new()?;
        plot_stream_multiplexing(
            &params,
            "h2-empty-data",
            &series,
            &ds,
            &empty_data.output(),
        )?;
        let empty_png = image::open(empty_data.only_file()?)?.to_rgb8();
        assert_eq!(empty_png.dimensions(), rendered.dimensions());
        assert_ne!(empty_png.as_raw(), rendered.as_raw());

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
        assert_eq!(
            filtered_height,
            MultiplexLayout::new(&params, 0, ApplicationProto::Http3)?.height
        );
        assert!(
            filtered_height <
                MultiplexLayout::new(&params, 1, ApplicationProto::Http3)?
                    .height
        );
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
            received_data: HttpDataHistory::with_known_frames(&[
                (3.0, 8),
                (8.0, 12),
            ])?,
            sent_data: HttpDataHistory::with_known_frames(&[(2.0, 3)])?,
            ..HttpRequestStub::default()
        });
        datastore.http_requests.insert(3, HttpRequestStub {
            received_data: HttpDataHistory::with_known_frames(&[(1.0, 30)])?,
            sent_data: HttpDataHistory::with_known_frames(&[
                (6.0, 5),
                (9.0, 11),
            ])?,
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
        let expected_height =
            MultiplexLayout::new(&params, 2, ApplicationProto::Http2)?.height;
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
            sent_data: HttpDataHistory::with_known_frames(&[(f64::NAN, 3)])?,
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
