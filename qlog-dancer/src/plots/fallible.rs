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

// Reusable fallible drawing helpers for native PNG and browser canvas output.
use super::ChartMargin;
#[cfg(not(target_arch = "wasm32"))]
use super::ChartSize;
use super::ClampParams;
use super::PlotColors;
use plotters::coord::ranged1d::ValueFormatter;
use plotters::coord::Shift;
use plotters::drawing::DrawingArea;
use plotters::drawing::DrawingAreaErrorKind;
use plotters::prelude::*;
use std::error::Error;
use std::io;
use std::ops::Range;

#[cfg(not(target_arch = "wasm32"))]
use plotters::prelude::BitMapBackend;
#[cfg(target_arch = "wasm32")]
use plotters_canvas::CanvasBackend;

pub(super) fn invalid_chart(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

pub(super) fn checked_time_range(
    min: f64, max: f64, clamp: &ClampParams,
) -> io::Result<Range<f64>> {
    if !min.is_finite() ||
        !max.is_finite() ||
        clamp.start.is_some_and(|v| !v.is_finite()) ||
        clamp.end.is_some_and(|v| !v.is_finite())
    {
        return Err(invalid_chart("chart timestamps and clamps must be finite"));
    }
    let low = clamp.start.unwrap_or(min);
    let high = max.min(clamp.end.unwrap_or(max));
    if low > high {
        return Err(invalid_chart("chart time range is reversed"));
    }
    if low < high {
        return Ok(low..high);
    }
    let padding = (low.abs() * f64::EPSILON * 64.0).max(1.0);
    let lower = low - padding;
    let upper = high + padding;
    if lower.is_finite() && upper.is_finite() && lower < upper {
        Ok(lower..upper)
    } else {
        Err(invalid_chart("chart time range cannot be represented"))
    }
}

pub(super) fn checked_pixel(value: u64) -> io::Result<i32> {
    i32::try_from(value).map_err(|_| {
        invalid_chart("chart pixel coordinate exceeds signed renderer range")
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn bitmap_area<'a>(
    path: &'a str, size: ChartSize, colors: PlotColors, margin: ChartMargin,
) -> Result<DrawingArea<BitMapBackend<'a>, Shift>, Box<dyn Error>> {
    if size.width == 0 ||
        size.height == 0 ||
        u64::from(size.width) >= i32::MAX as u64 ||
        u64::from(size.height) >= i32::MAX as u64
    {
        return Err(invalid_chart(
            "chart bitmap dimensions must fit signed renderer coordinates",
        )
        .into());
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let area =
        BitMapBackend::new(path, (size.width, size.height)).into_drawing_area();
    area.fill(&colors.fill)?;
    Ok(area.margin(margin.top, margin.bottom, margin.left, margin.right))
}

#[cfg(target_arch = "wasm32")]
pub(super) fn canvas_area(
    canvas_id: &str, colors: PlotColors, margin: ChartMargin,
) -> Result<DrawingArea<CanvasBackend, Shift>, Box<dyn Error>> {
    let backend = CanvasBackend::new(canvas_id).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("chart canvas {canvas_id:?} not found"),
        )
    })?;
    let area = backend.into_drawing_area();
    area.fill(&colors.fill)?;
    Ok(area.margin(margin.top, margin.bottom, margin.left, margin.right))
}

pub(super) fn draw_mesh<XT, YT, X, Y, DB: DrawingBackend>(
    colors: &PlotColors, x_desc: &str, y_desc: &str, draw_minor_lines: bool,
    chart: &mut ChartContext<DB, Cartesian2d<X, Y>>,
) -> Result<(), DrawingAreaErrorKind<DB::ErrorType>>
where
    X: Ranged<ValueType = XT> + ValueFormatter<XT>,
    Y: Ranged<ValueType = YT> + ValueFormatter<YT>,
{
    let mut mesh = chart.configure_mesh();
    mesh.axis_style(colors.axis)
        .x_desc(x_desc)
        .y_desc(y_desc)
        .bold_line_style(colors.bold_line.mix(0.5));
    if draw_minor_lines {
        mesh.light_line_style(colors.light_line.mix(0.2));
    } else {
        mesh.light_line_style(colors.bold_line.mix(0.0));
    }
    mesh.label_style(super::chart_label_style(&colors.caption))
        .draw()?;
    Ok(())
}

#[cfg(test)]
pub(in crate::plots) mod test_support {
    use super::super::ChartOutputType;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    pub(in crate::plots) struct TempCharts(pub(in crate::plots) PathBuf);

    impl TempCharts {
        pub(in crate::plots) fn new() -> std::io::Result<Self> {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(std::io::Error::other)?
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "qlog-chart-tests-{}-{nanos}-{id}",
                std::process::id(),
            ));
            std::fs::create_dir(&path)?;
            Ok(Self(path))
        }

        pub(in crate::plots) fn output(&self) -> ChartOutputType {
            ChartOutputType::Png {
                output_dir: self.0.to_string_lossy().into_owned(),
                cwnd_y_max: None,
                stream_y_max: None,
            }
        }

        pub(in crate::plots) fn only_file(&self) -> std::io::Result<PathBuf> {
            let mut entries = std::fs::read_dir(&self.0)?;
            let path = entries
                .next()
                .ok_or_else(|| std::io::Error::other("no rendered chart"))??
                .path();
            if entries.next().is_some() {
                return Err(std::io::Error::other("expected exactly one chart"));
            }
            Ok(path)
        }
    }

    impl Drop for TempCharts {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_time_ranges_accept_empty_and_equal_time_but_reject_invalid_clamps(
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(
            checked_time_range(0.0, 0.0, &ClampParams::default())?,
            -1.0..1.0
        );
        assert_eq!(
            checked_time_range(1.0, 10.0, &ClampParams::default())?,
            1.0..10.0
        );
        assert!(checked_time_range(1.0, 10.0, &ClampParams {
            start: Some(20.0),
            ..ClampParams::default()
        })
        .is_err());
        assert!(checked_time_range(1.0, 10.0, &ClampParams {
            end: Some(f64::NAN),
            ..ClampParams::default()
        })
        .is_err());
        assert!(checked_time_range(1.0, 10.0, &ClampParams {
            start: Some(f64::INFINITY),
            ..ClampParams::default()
        })
        .is_err());
        assert!(
            checked_time_range(f64::NAN, 0.0, &ClampParams::default()).is_err()
        );
        assert!(checked_pixel(u64::from(i32::MAX as u32) + 1).is_err());
        Ok(())
    }
}
