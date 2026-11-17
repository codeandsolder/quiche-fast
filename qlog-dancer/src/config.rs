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

use std::collections::HashSet;

use clap::Arg;
use clap::ArgAction;
use clap::Command;

use crate::datastore::PrintStatsConfig;
use crate::plots::colors::PlotColors;
use crate::plots::colors::DARK_MODE;
use crate::plots::colors::LIGHT_MODE;
use crate::plots::stream_sparks::SparkPlotsParams;
use crate::plots::ClampParams;
use crate::SerializationFormat;

#[derive(Debug)]
pub struct AppConfig {
    pub file: String,
    pub filename: String,

    pub charts_dir: String,
    pub plot_conn_overview: bool,
    pub plot_pkt_sent: bool,
    pub plot_pkt_received: bool,
    pub plot_conn_flow_control: bool,
    pub plot_sparks: bool,
    pub plot_multiplex: bool,
    pub plot_pending: bool,
    pub sparks_layout: SparkPlotsParams,

    pub report_text: bool,
    pub report_omit_upload: bool,
    pub report_omit_priorities: bool,
    pub report_text_csv: bool,
    pub report_html: bool,

    pub dark_mode: bool,

    pub start: Option<f64>,
    pub end: Option<f64>,

    pub stream_y_max: Option<u64>,
    pub cwnd_y_max: Option<u64>,

    pub netlog_filter: HashSet<String>,
    pub qlog_wirefilter: Option<String>,

    pub stats_config: PrintStatsConfig,
    pub ignore_acks: bool,

    pub log_format: SerializationFormat,
}

impl AppConfig {
    pub fn colors(dark_mode: bool) -> PlotColors {
        if dark_mode {
            DARK_MODE
        } else {
            LIGHT_MODE
        }
    }

    pub fn from_clap() -> Result<Self, String> {
        Self::from_matches(Self::command().get_matches())
    }

    fn command() -> Command {
        Command::new("qlog-dancer")
        .version("v0.1.0")
        .about("dances with qlog (and more!)")
        .arg(
            Arg::new("LOG FILE")
                .help("Sets the input log file to use")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("charts")
                .long("charts")
                .help("Type of charts to plot")
                .value_parser([
                    "all",
                    "overview",
                    "pkt-rx",
                    "sparks",
                    "multiplex",
                    "pending",
                    "conn-flow",
                    "none",
                ])
                .default_value("none"),
        )
        .arg(
            Arg::new("charts_directory")
                .long("charts-directory")
                .help("Sets the output directory for charts"),
        )
        .arg(
            Arg::new("sparks_layout")
                .long("sparks-layout")
                .help("Layout of spark charts")
                .value_parser(["grid", "vert"])
                .default_value("vert"),
        )
        .arg(
            Arg::new("start")
                .short('s')
                .long("start")
                .value_parser(clap::value_parser!(f64))
                .help("Relative start time for plots")
        )
        .arg(
            Arg::new("end")
                .short('e')
                .long("end")
                .value_parser(clap::value_parser!(f64))
                .help("Relative end time for plots")
        )
        .arg(
            Arg::new("stream_y_axis_max")
                .long("stream-y-axis-max")
                .value_parser(clap::value_parser!(u64))
                .help("Maximum value of Y axis on stream-related charts")
        )
        .arg(
            Arg::new("cwnd_y_axis_max")
                .long("cwnd-y-axis-max")
                .value_parser(clap::value_parser!(u64))
                .help("Maximum value of Y axis on cwnd-related charts")
        )
        .arg(
            Arg::new("netlog_filter")
                .long("netlog-filter")
                .help("A comma-seperated list of hostnames to filter in to netlog analysis. By default, all hostname are analysed.")
        )
        .arg(
            Arg::new("qlog_wirefilter")
                .long("qlog-wirefilter")
                .help("A Wirefilter expression for Wireshark-like matching of qlog events.")
        )
        .arg(
            Arg::new("dark_mode")
                .long("dark-mode")
                .help("Generate outputs in a dark mode style")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("print_stats")
                .long("print-stats")
                .help("Print stats about qlog events")
                .value_parser(["all", "stream", "packets", "none"])
                .default_value("none"),
        )
        .arg(
            Arg::new("report_text")
                .long("report-text")
                .help("Generate log reports in text format")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("report_html")
                .long("report-html")
                .help("Generate log reports in HTML format")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("report_omit_upload")
                .long("report-omit-upload")
                .help("Omit printing columns about HTTP uploads")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("report_omit_priorities")
                .long("report-omit-priorities")
                .help("Omit printing columns about HTTP priorities")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("report_text_csv")
                .long("report-text-csv")
                .help("Tables printed in a CSV-compatible format")
                .action(ArgAction::SetTrue),
        )
    }

    fn from_matches(mut matches: clap::ArgMatches) -> Result<Self, String> {
        let file = matches
            .remove_one::<String>("LOG FILE")
            .ok_or("input log file is required")?;
        let filename = std::path::Path::new(&file)
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or("input log path must end in a UTF-8 filename")?
            .to_owned();

        let charts_dir = matches
            .remove_one::<String>("charts_directory")
            .unwrap_or_else(|| format!("{filename}-charts"));

        let start = matches.remove_one::<f64>("start");
        let end = matches.remove_one::<f64>("end");

        for (label, value) in [("Start", start), ("End", end)] {
            if value.is_some_and(|value| !value.is_finite() || value < 0.0) {
                return Err(format!(
                    "{label} time must be finite and nonnegative."
                ));
            }
        }
        if end.zip(start).is_some_and(|(end, start)| end < start) {
            return Err("End time cannot be earlier than start time.".into());
        }

        let stream_y_max = matches.remove_one::<u64>("stream_y_axis_max");
        let cwnd_y_max = matches.remove_one::<u64>("cwnd_y_axis_max");
        if stream_y_max == Some(0) || cwnd_y_max == Some(0) {
            return Err("Chart Y-axis maxima must be positive.".into());
        }

        let dark_mode = matches.get_flag("dark_mode");

        let charts = matches
            .remove_one::<String>("charts")
            .ok_or("missing chart selection")?;
        let (
            plot_conn_overview,
            plot_pkt_sent,
            plot_pkt_received,
            plot_sparks,
            plot_multiplex,
            plot_pending,
            plot_conn_flow_control,
        ) = match charts.as_str() {
            "all" => (true, true, true, true, true, true, true),

            "overview" => (true, true, false, false, false, false, false),

            "pkt-rx" => (false, false, true, false, false, false, false),

            "sparks" => (false, false, false, true, false, false, false),

            "multiplex" => (false, false, false, false, true, false, false),

            "pending" => (false, false, false, false, false, true, false),

            "conn-flow" => (false, false, false, false, false, false, true),

            "none" => (false, false, false, false, false, false, false),

            _ => return Err(format!("unknown chart selection: {charts}")),
        };

        let sparks_layout = matches
            .remove_one::<String>("sparks_layout")
            .ok_or("missing spark layout")?;
        let sparks_layout = if sparks_layout == "grid" {
            SparkPlotsParams {
                clamp: ClampParams {
                    start,
                    end,
                    stream_y_max,
                },
                colors: Self::colors(dark_mode),
                ..Default::default()
            }
        } else {
            SparkPlotsParams {
                clamp: ClampParams {
                    start,
                    end,
                    stream_y_max,
                },
                colors: Self::colors(dark_mode),
                sparks_per_row: 1,
                captions_on_top: false,
                spark_dimension_x: 600,
                caption_area_width: 600,
                label_area_height: 1,
                ..Default::default()
            }
        };

        let netlog_filter = match matches.remove_one::<String>("netlog_filter") {
            Some(filter_string) => filter_string
                .split(',')
                .map(|v| v.to_string())
                .collect::<HashSet<String>>(),

            None => HashSet::new(),
        };

        let qlog_wirefilter = matches.remove_one::<String>("qlog_wirefilter");

        let report_text = matches.get_flag("report_text");
        let report_omit_upload = matches.get_flag("report_omit_upload");
        let report_omit_priorities = matches.get_flag("report_omit_priorities");
        let report_text_csv = matches.get_flag("report_text_csv");
        let report_html = matches.get_flag("report_html");

        let print_stats = matches
            .remove_one::<String>("print_stats")
            .ok_or("missing stats selection")?;
        let stats_config = match print_stats.as_str() {
            "all" => PrintStatsConfig {
                rx_flow_control: true,
                tx_flow_control: true,
                reset_streams: true,
                stream_buffering: true,
                tx_stream_frames: true,
                packet_stats: true,
            },

            "stream" => PrintStatsConfig {
                rx_flow_control: true,
                tx_flow_control: true,
                reset_streams: true,
                stream_buffering: true,
                tx_stream_frames: true,
                packet_stats: false,
            },

            "packets" => PrintStatsConfig {
                rx_flow_control: false,
                tx_flow_control: false,
                reset_streams: false,
                stream_buffering: false,
                tx_stream_frames: false,
                packet_stats: true,
            },

            "none" => PrintStatsConfig {
                rx_flow_control: false,
                tx_flow_control: false,
                reset_streams: false,
                stream_buffering: false,
                tx_stream_frames: false,
                packet_stats: false,
            },

            _ => return Err(format!("unknown stats selection: {print_stats}")),
        };

        let ignore_acks = false;

        let log_format = SerializationFormat::from_filename(&file);

        let config = Self {
            file,
            filename,
            charts_dir,
            plot_conn_overview,
            plot_pkt_sent,
            plot_pkt_received,
            plot_conn_flow_control,
            plot_sparks,
            plot_multiplex,
            plot_pending,
            sparks_layout,
            report_text,
            report_omit_upload,
            report_omit_priorities,
            report_text_csv,
            report_html,
            dark_mode,
            start,
            end,
            stream_y_max,
            cwnd_y_max,
            netlog_filter,
            qlog_wirefilter,
            stats_config,
            ignore_acks,
            log_format,
        };

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::AppConfig;

    fn parse(args: &[&str]) -> Result<AppConfig, String> {
        let matches = AppConfig::command()
            .try_get_matches_from(args)
            .map_err(|err| err.to_string())?;
        AppConfig::from_matches(matches)
    }

    #[test]
    fn numeric_cli_options_are_typed_and_preserve_values() -> Result<(), String> {
        let config = parse(&[
            "qlog-dancer",
            "logs/capture.qlog",
            "--start",
            "1.25",
            "--end",
            "4.75",
            "--stream-y-axis-max",
            "4294967296",
            "--cwnd-y-axis-max",
            "18446744073709551615",
            "--charts",
            "sparks",
            "--sparks-layout",
            "grid",
            "--dark-mode",
        ])?;
        assert_eq!(config.filename, "capture.qlog");
        assert_eq!(config.charts_dir, "capture.qlog-charts");
        assert_eq!(config.start, Some(1.25));
        assert_eq!(config.end, Some(4.75));
        assert_eq!(config.stream_y_max, Some(4_294_967_296));
        assert_eq!(config.cwnd_y_max, Some(u64::MAX));
        assert!(config.dark_mode);
        assert!(config.plot_sparks);
        assert_eq!(config.sparks_layout.clamp.start, config.start);
        assert_eq!(config.sparks_layout.clamp.stream_y_max, config.stream_y_max);

        let defaults = parse(&["qlog-dancer", "capture.sqlog"])?;
        assert_eq!(defaults.start, None);
        assert_eq!(defaults.end, None);
        assert_eq!(defaults.stream_y_max, None);
        assert_eq!(defaults.cwnd_y_max, None);
        assert!(!defaults.plot_sparks);
        Ok(())
    }

    #[test]
    fn malformed_numeric_inputs_and_paths_are_reported_as_errors() {
        for (flag, value) in [
            ("--start", "NaN"),
            ("--start", "inf"),
            ("--start", "-0.25"),
            ("--start", "invalid"),
            ("--end", "-1"),
            ("--end", "Infinity"),
            ("--stream-y-axis-max", "-1"),
            ("--stream-y-axis-max", "0"),
            ("--stream-y-axis-max", "1.5"),
            ("--stream-y-axis-max", "18446744073709551616"),
            ("--cwnd-y-axis-max", "-2"),
            ("--cwnd-y-axis-max", "0"),
        ] {
            let input = ["qlog-dancer", "trace.qlog", flag, value];
            assert!(parse(&input).is_err(), "{flag}={value} must be rejected");
        }
        assert!(parse(&[
            "qlog-dancer",
            "trace.qlog",
            "--start",
            "4",
            "--end",
            "2"
        ])
        .is_err());
        assert!(parse(&["qlog-dancer", "/"]).is_err());
    }
}
