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

use crate::plots::colors::PlotColors;
use crate::plots::colors::DARK_MODE;
use crate::plots::colors::LIGHT_MODE;
use crate::plots::stream_sparks::SparkPlotsParams;
use crate::plots::ClampParams;
use crate::SerializationFormat;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChartKind {
    ConnectionOverview,
    PacketSent,
    PacketReceived,
    ConnectionFlowControl,
    Sparks,
    Multiplex,
    Pending,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ChartSelection {
    All,
    Overview,
    PacketReceived,
    ConnectionFlowControl,
    Sparks,
    Multiplex,
    Pending,
    #[default]
    None,
}

impl ChartSelection {
    fn parse(value: &str) -> Result<Self, String> {
        Ok(match value {
            "all" => Self::All,
            "overview" => Self::Overview,
            "pkt-rx" => Self::PacketReceived,
            "conn-flow" => Self::ConnectionFlowControl,
            "sparks" => Self::Sparks,
            "multiplex" => Self::Multiplex,
            "pending" => Self::Pending,
            "none" => Self::None,
            _ => return Err(format!("unknown chart selection: {value}")),
        })
    }

    #[must_use = "indicates whether the selected chart is enabled"]
    pub const fn includes(self, kind: ChartKind) -> bool {
        matches!(
            (self, kind),
            (Self::All, _) |
                (
                    Self::Overview,
                    ChartKind::ConnectionOverview | ChartKind::PacketSent
                ) |
                (Self::PacketReceived, ChartKind::PacketReceived) |
                (
                    Self::ConnectionFlowControl,
                    ChartKind::ConnectionFlowControl
                ) |
                (Self::Sparks, ChartKind::Sparks) |
                (Self::Multiplex, ChartKind::Multiplex) |
                (Self::Pending, ChartKind::Pending)
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PlotTheme {
    Dark,
    #[default]
    Light,
}

impl PlotTheme {
    #[must_use = "returns the selected chart palette"]
    pub const fn colors(self) -> PlotColors {
        match self {
            Self::Dark => DARK_MODE,
            Self::Light => LIGHT_MODE,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SparkLayout {
    Grid,
    #[default]
    Vertical,
}

#[derive(Debug)]
pub struct PlotConfig {
    pub selection: ChartSelection,
    pub directory: String,
    pub clamp: ClampParams,
    pub cwnd_y_max: Option<u64>,
    pub theme: PlotTheme,
    pub spark_layout: SparkLayout,
}

impl PlotConfig {
    #[must_use = "derives spark settings from the shared chart bounds and palette"]
    pub fn spark_params(&self) -> SparkPlotsParams {
        let mut params = SparkPlotsParams {
            clamp: self.clamp.clone(),
            colors: self.theme.colors(),
            ..SparkPlotsParams::default()
        };
        if self.spark_layout == SparkLayout::Vertical {
            params.sparks_per_row = 1;
            params.captions_on_top = false;
            params.spark_dimension_x = 600;
            params.caption_area_width = 600;
            params.label_area_height = 1;
        }
        params
    }

    fn from_matches(
        matches: &mut clap::ArgMatches, filename: &str,
    ) -> Result<Self, String> {
        let directory = matches
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
        let selection = ChartSelection::parse(
            &matches
                .remove_one::<String>("charts")
                .ok_or("missing chart selection")?,
        )?;
        let spark_layout =
            match matches.remove_one::<String>("sparks_layout").as_deref() {
                Some("grid") => SparkLayout::Grid,
                Some("vert") => SparkLayout::Vertical,
                _ => return Err("invalid or missing spark layout".into()),
            };
        let theme = if matches.get_flag("dark_mode") {
            PlotTheme::Dark
        } else {
            PlotTheme::Light
        };
        Ok(Self {
            selection,
            directory,
            clamp: ClampParams {
                start,
                end,
                stream_y_max,
            },
            cwnd_y_max,
            theme,
            spark_layout,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StatsSelection {
    All,
    Stream,
    Packets,
    #[default]
    None,
}

impl StatsSelection {
    fn parse(value: &str) -> Result<Self, String> {
        Ok(match value {
            "all" => Self::All,
            "stream" => Self::Stream,
            "packets" => Self::Packets,
            "none" => Self::None,
            _ => return Err(format!("unknown stats selection: {value}")),
        })
    }

    #[must_use = "indicates whether stream statistics are enabled"]
    pub const fn stream(self) -> bool {
        matches!(self, Self::All | Self::Stream)
    }

    #[must_use = "indicates whether packet statistics are enabled"]
    pub const fn packets(self) -> bool {
        matches!(self, Self::All | Self::Packets)
    }
}

#[derive(Debug)]
pub struct TextReportConfig {
    pub omit_upload: bool,
    pub omit_priorities: bool,
    pub csv: bool,
    pub stats: StatsSelection,
}

#[derive(Debug)]
pub struct ReportConfig {
    pub text: Option<TextReportConfig>,
    pub html: bool,
}

impl ReportConfig {
    fn from_matches(matches: &mut clap::ArgMatches) -> Result<Self, String> {
        let stats = StatsSelection::parse(
            &matches
                .remove_one::<String>("print_stats")
                .ok_or("missing stats selection")?,
        )?;
        Ok(Self {
            text: matches.get_flag("report_text").then(|| TextReportConfig {
                omit_upload: matches.get_flag("report_omit_upload"),
                omit_priorities: matches.get_flag("report_omit_priorities"),
                csv: matches.get_flag("report_text_csv"),
                stats,
            }),
            html: matches.get_flag("report_html"),
        })
    }
}

#[derive(Debug)]
pub struct AppConfig {
    pub file: String,
    pub filename: String,
    pub plots: PlotConfig,
    pub reports: ReportConfig,
    pub netlog_filter: HashSet<String>,
    pub qlog_wirefilter: Option<String>,
    pub ignore_acks: bool,
    pub log_format: SerializationFormat,
}

impl AppConfig {
    /// Read the command-line configuration.
    ///
    /// # Errors
    /// Returns an error if the selected plot bounds or input path are invalid.
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
            Arg::new("netlog_filter")
                .long("netlog-filter")
                .help("A comma-seperated list of hostnames to filter in to netlog analysis. By default, all hostname are analysed.")
        )
        .arg(
            Arg::new("qlog_wirefilter")
                .long("qlog-wirefilter")
                .help("A Wirefilter expression for Wireshark-like matching of qlog events.")
        )
        .args(Self::plot_args())
        .args(Self::report_args())
    }

    fn plot_args() -> Vec<Arg> {
        vec![
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
            Arg::new("charts_directory")
                .long("charts-directory")
                .help("Sets the output directory for charts"),
            Arg::new("sparks_layout")
                .long("sparks-layout")
                .help("Layout of spark charts")
                .value_parser(["grid", "vert"])
                .default_value("vert"),
            Arg::new("start")
                .short('s')
                .long("start")
                .value_parser(clap::value_parser!(f64))
                .help("Relative start time for plots"),
            Arg::new("end")
                .short('e')
                .long("end")
                .value_parser(clap::value_parser!(f64))
                .help("Relative end time for plots"),
            Arg::new("stream_y_axis_max")
                .long("stream-y-axis-max")
                .value_parser(clap::value_parser!(u64))
                .help("Maximum value of Y axis on stream-related charts"),
            Arg::new("cwnd_y_axis_max")
                .long("cwnd-y-axis-max")
                .value_parser(clap::value_parser!(u64))
                .help("Maximum value of Y axis on cwnd-related charts"),
            Arg::new("dark_mode")
                .long("dark-mode")
                .help("Generate outputs in a dark mode style")
                .action(ArgAction::SetTrue),
        ]
    }

    fn report_args() -> Vec<Arg> {
        vec![
            Arg::new("print_stats")
                .long("print-stats")
                .help("Print stats about qlog events")
                .value_parser(["all", "stream", "packets", "none"])
                .default_value("none"),
            Arg::new("report_text")
                .long("report-text")
                .help("Generate log reports in text format")
                .action(ArgAction::SetTrue),
            Arg::new("report_html")
                .long("report-html")
                .help("Generate log reports in HTML format")
                .action(ArgAction::SetTrue),
            Arg::new("report_omit_upload")
                .long("report-omit-upload")
                .help("Omit printing columns about HTTP uploads")
                .action(ArgAction::SetTrue),
            Arg::new("report_omit_priorities")
                .long("report-omit-priorities")
                .help("Omit printing columns about HTTP priorities")
                .action(ArgAction::SetTrue),
            Arg::new("report_text_csv")
                .long("report-text-csv")
                .help("Tables printed in a CSV-compatible format")
                .action(ArgAction::SetTrue),
        ]
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

        let plots = PlotConfig::from_matches(&mut matches, &filename)?;
        let reports = ReportConfig::from_matches(&mut matches)?;
        let netlog_filter = matches
            .remove_one::<String>("netlog_filter")
            .map_or_else(HashSet::new, |value| {
                value.split(',').map(str::to_owned).collect()
            });
        let qlog_wirefilter = matches.remove_one::<String>("qlog_wirefilter");
        let log_format = SerializationFormat::from_filename(&file);
        Ok(Self {
            file,
            filename,
            plots,
            reports,
            netlog_filter,
            qlog_wirefilter,
            ignore_acks: false,
            log_format,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::AppConfig;
    use super::ChartKind;
    use super::ChartSelection;
    use super::PlotTheme;
    use super::SparkLayout;
    use super::StatsSelection;

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
        assert_eq!(config.plots.directory, "capture.qlog-charts");
        assert_eq!(config.plots.clamp.start, Some(1.25));
        assert_eq!(config.plots.clamp.end, Some(4.75));
        assert_eq!(config.plots.clamp.stream_y_max, Some(4_294_967_296));
        assert_eq!(config.plots.cwnd_y_max, Some(u64::MAX));
        assert_eq!(config.plots.theme, PlotTheme::Dark);
        assert!(config.plots.selection.includes(ChartKind::Sparks));
        assert_eq!(
            config.plots.spark_params().clamp.start,
            config.plots.clamp.start
        );
        assert_eq!(
            config.plots.spark_params().clamp.stream_y_max,
            config.plots.clamp.stream_y_max
        );

        let defaults = parse(&["qlog-dancer", "capture.sqlog"])?;
        assert_eq!(defaults.plots.clamp.start, None);
        assert_eq!(defaults.plots.clamp.end, None);
        assert_eq!(defaults.plots.clamp.stream_y_max, None);
        assert_eq!(defaults.plots.cwnd_y_max, None);
        assert!(!defaults.plots.selection.includes(ChartKind::Sparks));
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

    #[test]
    fn chart_selections_preserve_exact_cli_behavior() -> Result<(), String> {
        let kinds = [
            ChartKind::ConnectionOverview,
            ChartKind::PacketSent,
            ChartKind::PacketReceived,
            ChartKind::ConnectionFlowControl,
            ChartKind::Sparks,
            ChartKind::Multiplex,
            ChartKind::Pending,
        ];
        for (flag, expected) in [
            ("all", kinds.as_slice()),
            ("overview", &kinds[..2]),
            ("pkt-rx", &kinds[2..3]),
            ("conn-flow", &kinds[3..4]),
            ("sparks", &kinds[4..5]),
            ("multiplex", &kinds[5..6]),
            ("pending", &kinds[6..7]),
            ("none", &[]),
        ] {
            let config = parse(&["qlog-dancer", "trace.qlog", "--charts", flag])?;
            let selected = kinds
                .iter()
                .copied()
                .filter(|kind| config.plots.selection.includes(*kind))
                .collect::<Vec<_>>();
            assert_eq!(selected, expected);
        }
        let mut config = parse(&["qlog-dancer", "trace.qlog"])?;
        assert_eq!(config.plots.selection, ChartSelection::None);
        assert_eq!(config.plots.spark_layout, SparkLayout::Vertical);
        config.plots.clamp.start = Some(12.0);
        assert_eq!(config.plots.spark_params().clamp.start, Some(12.0));
        assert_eq!(config.plots.spark_params().sparks_per_row, 1);
        config.plots.spark_layout = SparkLayout::Grid;
        assert_eq!(config.plots.spark_params().sparks_per_row, 10);
        Ok(())
    }

    #[test]
    fn report_stats_are_scoped_to_text_reporting() -> Result<(), String> {
        for (flag, selection, stream, packets) in [
            ("all", StatsSelection::All, true, true),
            ("stream", StatsSelection::Stream, true, false),
            ("packets", StatsSelection::Packets, false, true),
            ("none", StatsSelection::None, false, false),
        ] {
            let config = parse(&[
                "qlog-dancer",
                "trace.qlog",
                "--report-text",
                "--report-html",
                "--report-omit-upload",
                "--report-omit-priorities",
                "--report-text-csv",
                "--print-stats",
                flag,
            ])?;
            let text = config.reports.text.ok_or("expected text report")?;
            assert_eq!(text.stats, selection);
            assert_eq!(text.stats.stream(), stream);
            assert_eq!(text.stats.packets(), packets);
            assert!(
                text.omit_upload &&
                    text.omit_priorities &&
                    text.csv &&
                    config.reports.html
            );
        }
        assert!(
            parse(&["qlog-dancer", "trace.qlog", "--print-stats", "all"])?
                .reports
                .text
                .is_none()
        );
        Ok(())
    }
}
