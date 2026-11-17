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
use crate::plots::fallible::invalid_chart;
use packet_sent::draw_packet_sent_received_plot;
use std::error::Error;

use crate::plots::*;

use crate::datastore::Datastore;
use crate::seriesstore::SeriesStore;

/// Render packet-received timeline.
///
/// # Errors
/// Propagates validation, output and drawing failures to callers.
pub fn plot_packet_received(
    params: &PlotParameters, filename: &str, ss: &SeriesStore, ds: &Datastore,
    ty: &ChartOutputType,
) -> Result<(), Box<dyn Error>> {
    let chart_config = ChartConfig {
        title: "packet-received".into(),
        input_filename: filename.into(),
        clamp: params.clamp.clone(),
        app_proto: ds.application_proto,
        host: ds.host.clone(),
        session_id: ds.session_id,
        ty: ty.clone(),
    };

    #[cfg(not(target_arch = "wasm32"))]
    let chart_path = match ty {
        ChartOutputType::Png { .. } => chart_config.chart_filepath(),
        ChartOutputType::Canvas { .. } =>
            return Err(invalid_chart(
                "native received chart requires PNG output",
            )
            .into()),
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
        invalid_chart("browser received chart requires canvas output")
    })?;
    #[cfg(target_arch = "wasm32")]
    let root = canvas_area(&canvas_id, params.colors, params.chart_margin)?;

    let (raw_timings, _remainder) = root.split_vertically((60).percent());
    draw_packet_sent_received_plot(false, filename, params, ss, &raw_timings)?;
    root.present()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plots::fallible::test_support::TempCharts;

    #[test]
    fn empty_received_chart_renders_and_invalid_output_fails_cleanly(
    ) -> Result<(), Box<dyn Error>> {
        let params = PlotParameters {
            clamp: ClampParams::default(),
            cwnd_y_max: None,
            chart_size: ChartSize {
                width: 640,
                height: 480,
            },
            colors: PlotColors::default(),
            chart_margin: ChartMargin::default(),
            area_margin: AreaMargin { x: 30, y: 40 },
            display_chart_title: false,
            display_legend: true,
            display_minor_lines: false,
        };
        let ds = Datastore::default();
        let ss = SeriesStore::default();
        let out = TempCharts::new()?;
        plot_packet_received(&params, "empty", &ss, &ds, &out.output())?;
        assert!(
            std::fs::read(out.only_file()?)?.starts_with(b"\x89PNG\r\n\x1a\n")
        );
        let blocked = TempCharts::new()?;
        let blocker = blocked.0.join("file-not-dir");
        std::fs::write(&blocker, b"not a dir")?;
        let ty = ChartOutputType::Png {
            output_dir: blocker.to_string_lossy().into_owned(),
            cwnd_y_max: None,
            stream_y_max: None,
        };
        assert!(plot_packet_received(&params, "blocked", &ss, &ds, &ty).is_err());
        Ok(())
    }
}
