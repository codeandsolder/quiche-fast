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
use std::fmt::Write;

#[cfg(not(target_arch = "wasm32"))]
use crate::datastore::ApplicationProto;
use crate::datastore::Datastore;
use colors::PlotColors;
use plotters::coord::types::RangedCoordf64;
use plotters::coord::types::RangedCoordu64;
use plotters::prelude::*;

#[derive(Clone, Debug)]
pub enum ChartOutputType {
    Png {
        output_dir: String,
        cwnd_y_max: Option<u64>,
        stream_y_max: Option<u64>,
    },

    Canvas {
        canvas_id: String,
    },
}

#[derive(Clone, Debug)]
struct ChartConfig {
    #[cfg(not(target_arch = "wasm32"))]
    pub title: String,
    #[cfg(not(target_arch = "wasm32"))]
    pub input_filename: String,
    // pub size: ChartSize,
    // pub margin: ChartMargin,
    // pub colors: PlotColors,
    #[cfg(not(target_arch = "wasm32"))]
    pub clamp: ClampParams,
    pub ty: ChartOutputType,
    #[cfg(not(target_arch = "wasm32"))]
    pub app_proto: ApplicationProto,
    #[cfg(not(target_arch = "wasm32"))]
    pub host: Option<String>,
    #[cfg(not(target_arch = "wasm32"))]
    pub session_id: Option<i64>,
}

/// Encode user-controlled names as single path components without losing
/// information or creating collisions between escaped and literal strings.
#[cfg(not(target_arch = "wasm32"))]
fn chart_filename_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut safe = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            safe.push(char::from(byte));
        } else {
            safe.push('~');
            safe.push(char::from(HEX[usize::from(byte >> 4)]));
            safe.push(char::from(HEX[usize::from(byte & 0x0F)]));
        }
    }
    safe
}

impl ChartConfig {
    /// Keep PNG filename metadata native-only. Browser plots need only their
    /// canvas output type, and constructing the configuration is identical
    /// across all plotters.
    fn new(
        title: &str, filename: &str, clamp: &ClampParams, ds: &Datastore,
        ty: &ChartOutputType,
    ) -> Self {
        // Canvas only needs its output ID. These inputs are used for native
        // PNG filenames, so keep one consistent constructor on both targets.
        #[cfg(target_arch = "wasm32")]
        let _ = (title, filename, clamp, ds);

        Self {
            #[cfg(not(target_arch = "wasm32"))]
            title: title.to_owned(),
            #[cfg(not(target_arch = "wasm32"))]
            input_filename: filename.to_owned(),
            #[cfg(not(target_arch = "wasm32"))]
            clamp: clamp.clone(),
            #[cfg(not(target_arch = "wasm32"))]
            app_proto: ds.application_proto,
            #[cfg(not(target_arch = "wasm32"))]
            host: ds.host.clone(),
            #[cfg(not(target_arch = "wasm32"))]
            session_id: ds.session_id,
            ty: ty.clone(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn chart_name(&self) -> String {
        let proto = match self.app_proto {
            ApplicationProto::Http2 => "h2",
            ApplicationProto::Http3 => "h3",
        };

        let host = match (&self.host, &self.ty) {
            (Some(host), ChartOutputType::Png { .. }) => {
                // Keep the established separator for native PNG files.
                let encoded = chart_filename_component(host);
                format!("-{encoded}")
            },
            (Some(host), ChartOutputType::Canvas { .. }) =>
                chart_filename_component(host),
            _ => String::new(),
        };
        let session = self
            .session_id
            .map_or_else(String::new, |id| format!("-session{id}"));
        let start = self
            .clamp
            .start
            .map_or_else(String::new, |value| format!("-s{value}"));
        let end = self
            .clamp
            .end
            .map_or_else(String::new, |value| format!("-e{value}"));

        let input_filename = chart_filename_component(&self.input_filename);
        let title = chart_filename_component(&self.title);
        let mut name = format!(
            "{input_filename}-{proto}{host}{session}-{title}{start}{end}"
        );

        if let ChartOutputType::Png {
            cwnd_y_max,
            stream_y_max,
            ..
        } = &self.ty
        {
            if let Some(maximum) = stream_y_max {
                let _ = write!(&mut name, "-stream_max_y{maximum}");
            }
            if let Some(maximum) = cwnd_y_max {
                let _ = write!(&mut name, "-cwnd_max_y{maximum}");
            }
        }

        name
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn chart_filepath(&self) -> String {
        match &self.ty {
            ChartOutputType::Png { output_dir, .. } => {
                let name = self.chart_name();
                format!("{output_dir}/{name}.png")
            },

            // Canvas doesn't have a file
            ChartOutputType::Canvas { .. } => self.chart_name(),
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn canvas_id(&self) -> Option<String> {
        match &self.ty {
            ChartOutputType::Canvas { canvas_id } => Some(canvas_id.clone()),
            ChartOutputType::Png { .. } => None,
        }
    }
}

#[must_use]
pub fn chart_title_style(color: &RGBColor) -> TextStyle<'_> {
    TextStyle::from(("sans-serif", 40).into_font()).color(color)
}

#[must_use]
pub fn chart_subtitle_style(color: &RGBColor) -> TextStyle<'_> {
    TextStyle::from(("sans-serif", 20).into_font()).color(color)
}

#[must_use]
pub fn chart_label_style(color: &RGBColor) -> TextStyle<'_> {
    TextStyle::from(("sans-serif", 15).into_font()).color(color)
}

use fallible::draw_mesh;

#[derive(Clone, Default, Debug)]
pub struct ClampParams {
    pub start: Option<f64>,
    pub end: Option<f64>,
    pub stream_y_max: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ChartSize {
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ChartMargin {
    pub top: u32,
    pub bottom: u32,
    pub left: u32,
    pub right: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AreaMargin {
    pub x: u32,
    pub y: u32,
}

pub struct PlotParameters {
    pub clamp: ClampParams,
    pub cwnd_y_max: Option<u64>,
    pub chart_size: ChartSize,
    pub colors: PlotColors,
    pub chart_margin: ChartMargin,
    pub area_margin: AreaMargin,
    pub display_chart_title: bool,
    pub display_legend: bool,
    pub display_minor_lines: bool,
}

fn draw_line<DB: DrawingBackend>(
    data: &[(f64, u64)], label: Option<&str>, colour: RGBColor,
    chart: &mut ChartContext<DB, Cartesian2d<RangedCoordf64, RangedCoordu64>>,
) -> Result<(), plotters::drawing::DrawingAreaErrorKind<DB::ErrorType>> {
    let drawn =
        chart.draw_series(LineSeries::new(data.iter().copied(), colour))?;
    if let Some(label) = label {
        drawn.label(label).legend(move |(x, y)| {
            PathElement::new([(x, y), (x + 20, y)], colour)
        });
    }
    Ok(())
}

mod fallible;

pub mod colors;
pub mod congestion_control;
pub mod conn_flow_control;
pub mod conn_overview;
pub mod minmax;
pub mod packet_received;
pub mod packet_sent;
pub mod pending;
pub mod rtt;
pub mod stream_multiplex;
pub mod stream_sparks;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datastore::ApplicationProto;
    use std::error::Error;
    use std::path::Path;

    #[test]
    fn chart_names_preserve_metadata_across_png_and_canvas() {
        let ds = Datastore {
            application_proto: ApplicationProto::Http2,
            host: Some("api.example:443".into()),
            session_id: Some(42),
            ..Datastore::default()
        };
        let clamp = ClampParams {
            start: Some(1.5),
            end: Some(3.25),
            stream_y_max: None,
        };
        let png = ChartOutputType::Png {
            output_dir: "/tmp/charts".into(),
            cwnd_y_max: Some(80),
            stream_y_max: Some(40),
        };
        let chart =
            ChartConfig::new("overview", "logs/input.qlog", &clamp, &ds, &png);
        let expected = "logs~2Finput.qlog-h2-api.example~3A443-session42-overview-s1.5-e3.25-stream_max_y40-cwnd_max_y80";
        assert_eq!(chart.chart_name(), expected);
        assert_eq!(
            chart.chart_filepath(),
            format!("/tmp/charts/{expected}.png")
        );

        let canvas = ChartOutputType::Canvas {
            canvas_id: "main".into(),
        };
        let chart =
            ChartConfig::new("overview", "logs/input.qlog", &clamp, &ds, &canvas);
        assert_eq!(
            chart.chart_name(),
            "logs~2Finput.qlog-h2api.example~3A443-session42-overview-s1.5-e3.25"
        );
        assert_eq!(chart.chart_filepath(), chart.chart_name());

        let default_ds = Datastore::default();
        let chart = ChartConfig::new(
            "overview",
            "input.qlog",
            &ClampParams::default(),
            &default_ds,
            &canvas,
        );
        assert_eq!(chart.chart_name(), "input.qlog-h3-overview");
    }

    #[test]
    fn chart_filenames_escape_untrusted_components() -> Result<(), Box<dyn Error>>
    {
        assert_eq!(chart_filename_component("a/b"), "a~2Fb");
        assert_eq!(chart_filename_component("a~2Fb"), "a~7E2Fb");
        assert_eq!(chart_filename_component(r"../\evil:"), "..~2F~5Cevil~3A");
        assert_eq!(chart_filename_component("é"), "~C3~A9");
        let ds = Datastore {
            host: Some("../../outside:443/".into()),
            ..Datastore::default()
        };
        let output_dir = "/tmp/qlog-test-chart-destination";
        let ty = ChartOutputType::Png {
            output_dir: output_dir.into(),
            cwnd_y_max: None,
            stream_y_max: None,
        };
        let config = ChartConfig::new(
            "conn-overview",
            "../sample.qlog",
            &ClampParams::default(),
            &ds,
            &ty,
        );
        let path = config.chart_filepath();
        assert_eq!(Path::new(&path).parent(), Some(Path::new(output_dir)));
        let component = Path::new(&path)
            .file_name()
            .ok_or("missing chart filename")?
            .to_string_lossy();
        assert!(component.contains("~2F"));
        assert!(!component.contains('/'));
        assert!(!component.contains('\\'));
        Ok(())
    }
}
