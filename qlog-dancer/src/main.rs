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

use std::error::Error;
use std::process::ExitCode;
use std::time::Instant;

use log::debug;
use log::error;
use log::info;
use log::warn;
use qlog_dancer::config::AppConfig;
use qlog_dancer::config::ChartKind;
use qlog_dancer::config::ChartSelection;
use qlog_dancer::config::PlotConfig;
use qlog_dancer::parse_log_file;
use qlog_dancer::plots::conn_flow_control;
use qlog_dancer::plots::conn_overview;
use qlog_dancer::plots::conn_overview::OverviewChartOutputType;
use qlog_dancer::plots::packet_received;
use qlog_dancer::plots::packet_sent;
use qlog_dancer::plots::pending::PendingPlotParams;
use qlog_dancer::plots::stream_multiplex;
use qlog_dancer::plots::stream_multiplex::MultiplexPlotsParams;
use qlog_dancer::plots::stream_sparks;
use qlog_dancer::plots::AreaMargin;
use qlog_dancer::plots::ChartMargin;
use qlog_dancer::plots::ChartOutputType;
use qlog_dancer::plots::ChartSize;
use qlog_dancer::plots::PlotParameters;
use qlog_dancer::plots::{
    self,
};
use qlog_dancer::reports::report;
use qlog_dancer::seriesstore::SeriesStore;
use qlog_dancer::LogFileData;
use qlog_dancer::LogFileParseResult;
use qlog_dancer::SerializationFormat;

fn main() -> ExitCode {
    env_logger::builder().init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!("{error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result<(), String> {
    let mut config = AppConfig::from_clap().map_err(|error| {
        format!("Error loading configuration, exiting: {error}")
    })?;
    let log_file = parse_input(&mut config)?;
    print_log_details(&log_file);
    if config.plots.selection != ChartSelection::None {
        render_charts(&log_file, &config)?;
    }
    println!();
    report(&log_file, &config)
        .map_err(|error| format!("Unable to write log report: {error}"))?;
    println!("input logs parsed successfully, check output(s)");
    Ok(())
}

fn parse_input(config: &mut AppConfig) -> Result<LogFileParseResult, String> {
    match parse_log_file(config) {
        Ok(parsed) => Ok(parsed),
        Err(error)
            if error.is::<qlog_dancer::wirefilter::FilterError>() ||
                error.is::<qlog_dancer::datastore::DatastoreError>() =>
            Err(format!("Unable to process qlog: {error}")),
        Err(error) => {
            config.log_format = match config.log_format {
                SerializationFormat::QlogJson => {
                    warn!("Failed to parse as qlog: {error}, trying sqlog");
                    SerializationFormat::QlogJsonSeq
                },
                SerializationFormat::QlogJsonSeq => {
                    warn!("Failed to parse as sqlog: {error}, trying qlog");
                    SerializationFormat::QlogJson
                },
                _ => return Err(format!("Unable to parse log: {error}")),
            };
            parse_log_file(config).map_err(|error| {
                format!("Unable to parse log in either format: {error}")
            })
        },
    }
}

fn print_log_details(log_file: &LogFileParseResult) {
    println!();
    println!("== Log details ==");
    println!("  Format: {}", log_file.details.serialization_format);
    println!("  Version: {}", log_file.details.file_schema);
    for data in &log_file.data {
        if let Some(trace) = &data.trace {
            println!(
                "  {} — vantage point: {:?}",
                trace.label(),
                trace.vantage_point
            );
        }
    }
    println!();
}

fn chart_identity(
    data: &LogFileData, filename: &str, multiple: bool,
) -> (String, String) {
    // Per-entry identity prevents different traces/sessions overwriting one
    // another.
    let chart_filename = if multiple {
        data.trace.as_ref().map_or_else(
            || {
                data.datastore.session_id.map_or_else(
                    || filename.to_owned(),
                    |session| format!("{filename}-session-{session}"),
                )
            },
            |trace| format!("{filename}-trace-{:04}", trace.index + 1),
        )
    } else {
        filename.to_owned()
    };
    let label = data.trace.as_ref().map_or_else(
        || {
            format!(
                "session ID: {:?}, app proto: {:?}, host: {:?}",
                data.datastore.session_id,
                data.datastore.application_proto,
                data.datastore.host
            )
        },
        |trace| format!("{} ({:?})", trace.label(), trace.vantage_point),
    );
    (chart_filename, label)
}

struct ChartRenderer<'a> {
    config: &'a PlotConfig,
    params: PlotParameters,
    output: ChartOutputType,
    overview_output: OverviewChartOutputType,
}

impl<'a> ChartRenderer<'a> {
    fn new(config: &'a PlotConfig) -> Self {
        let params = PlotParameters {
            clamp: config.clamp.clone(),
            cwnd_y_max: config.cwnd_y_max,
            chart_size: ChartSize {
                width: 1600,
                height: 1200,
            },
            colors: config.theme.colors(),
            chart_margin: ChartMargin {
                top: 20,
                bottom: 20,
                left: 20,
                right: 20,
            },
            area_margin: AreaMargin { x: 40, y: 80 },
            display_chart_title: true,
            display_legend: true,
            display_minor_lines: true,
        };
        let overview_output = OverviewChartOutputType::Png {
            output_dir: config.directory.clone(),
            cwnd_y_max: params.cwnd_y_max,
            stream_y_max: params.clamp.stream_y_max,
        };
        let output = ChartOutputType::Png {
            output_dir: config.directory.clone(),
            cwnd_y_max: params.cwnd_y_max,
            stream_y_max: params.clamp.stream_y_max,
        };
        Self {
            config,
            params,
            output,
            overview_output,
        }
    }

    fn render(
        &self, kind: ChartKind, filename: &str, data: &LogFileData,
        ss: &SeriesStore,
    ) -> Result<(), Box<dyn Error>> {
        let ds = &data.datastore;
        match kind {
            ChartKind::ConnectionOverview =>
                conn_overview::plot_connection_overview(
                    &self.params,
                    filename,
                    ss,
                    ds,
                    &self.overview_output,
                ),
            ChartKind::PacketSent => packet_sent::plot_packet_sent(
                &self.params,
                filename,
                ss,
                ds,
                &self.output,
            ),
            ChartKind::PacketReceived => packet_received::plot_packet_received(
                &self.params,
                filename,
                ss,
                ds,
                &self.output,
            ),
            ChartKind::ConnectionFlowControl =>
                conn_flow_control::plot_conn_flow_control(
                    &self.params,
                    filename,
                    ss,
                    ds,
                    &self.output,
                ),
            ChartKind::Sparks => stream_sparks::plot_sparks(
                &self.config.spark_params(),
                filename,
                ss,
                ds,
                stream_sparks::SparkOutputs::all(&self.output),
            ),
            ChartKind::Multiplex => {
                let params = MultiplexPlotsParams {
                    clamp: self.config.clamp.clone(),
                    colors: self.config.theme.colors(),
                    ..MultiplexPlotsParams::default()
                };
                stream_multiplex::plot_stream_multiplexing(
                    &params,
                    filename,
                    ss,
                    ds,
                    &self.output,
                )
            },
            ChartKind::Pending => {
                let params = PendingPlotParams {
                    clamp: self.config.clamp.clone(),
                    chart_size: ChartSize {
                        width: 1600,
                        height: 600,
                    },
                    colors: self.config.theme.colors(),
                    display_chart_title: true,
                };
                plots::pending::plot_pending(
                    &params,
                    filename,
                    ss,
                    ds,
                    &self.output,
                )
            },
        }
    }
}

const CHARTS: [(ChartKind, &str); 7] = [
    (ChartKind::ConnectionOverview, "connection overview chart"),
    (ChartKind::PacketSent, "packet sent chart"),
    (ChartKind::PacketReceived, "packet received chart"),
    (
        ChartKind::ConnectionFlowControl,
        "connection flow control chart",
    ),
    (ChartKind::Sparks, "stream spark charts"),
    (ChartKind::Multiplex, "stream multiplexing chart"),
    (ChartKind::Pending, "pending chart"),
];

fn render_charts(
    log_file: &LogFileParseResult, config: &AppConfig,
) -> Result<(), String> {
    if log_file.data.is_empty() {
        return Err("File exists but trace information was empty or invalid. If you used a netlog-filter, check it exactly matched session host in the file.".into());
    }
    info!("populating plot series data...");
    let mark = Instant::now();
    let series = log_file
        .data
        .iter()
        .map(|data| SeriesStore::from_datastore(&data.datastore))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!("Unable to construct plotting series: {error}")
        })?;
    debug!("series prepared in {:?}", mark.elapsed());
    let renderer = ChartRenderer::new(&config.plots);
    for (data, ss) in log_file.data.iter().zip(&series) {
        let (filename, label) =
            chart_identity(data, &config.filename, log_file.data.len() > 1);
        for (kind, name) in CHARTS {
            if config.plots.selection.includes(kind) {
                info!("drawing {name} for {label}...");
                let mark = Instant::now();
                renderer
                    .render(kind, &filename, data, ss)
                    .map_err(|error| {
                        format!("Unable to draw {name} for {label}: {error}")
                    })?;
                debug!("complete in {:?}", mark.elapsed());
            }
        }
    }
    Ok(())
}
