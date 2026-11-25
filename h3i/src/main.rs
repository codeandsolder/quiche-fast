// Copyright (C) 2024, Cloudflare, Inc.
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

use std::env;
use std::io::BufReader;
use std::result::Result;
use std::time;
use std::time::Instant;

use h3i::actions::h3::Action;
use h3i::client::connection_summary::ConnectionSummary;
use h3i::client::ClientError;
use h3i::prompts::h3::Prompter;
use h3i::recordreplay::qlog::QlogEvent;
use h3i::recordreplay::qlog::*;
use qlog::events::HTTP3_URI;
use qlog::events::QUIC_URI;
use qlog::reader::QlogSeqReader;

use clap::value_parser;
use clap::Arg;
use clap::ArgAction;
use clap::ArgMatches;
use clap::Command;
use h3i::config::DatagramQueues;
use std::path::Path;
use std::path::PathBuf;

fn main() -> Result<(), ClientError> {
    let mut log_builder = env_logger::builder();
    if env::var_os("RUST_LOG").is_none() {
        log_builder.filter_level(log::LevelFilter::Info);
    }

    log_builder.format_timestamp_nanos().init();

    let config = match config_from_clap() {
        Ok(v) => v,

        Err(e) => {
            log::error!("Error loading configuration, exiting: {e}");
            return Err(ClientError::Other("Invalid configuration".into()));
        },
    };

    let actions = match &config.qlog_input {
        Some(v) => read_qlog(v, config.host_override.as_deref())?,
        None => prompt_frames(&config)?,
    };

    #[cfg(not(feature = "async"))]
    let summary = sync_client(config, actions);
    #[cfg(feature = "async")]
    let summary = async_client(config, actions);

    let summary = summary?;
    log::debug!(
        "received connection_summary: {}",
        serde_json::to_string_pretty(&summary)
            .map_err(|error| ClientError::Other(error.to_string()))?
    );

    Ok(())
}

struct Config {
    library_config: h3i::config::Config,
    pub qlog_input: Option<PathBuf>,
    pub qlog_actions_output: bool,
    pub host_override: Option<String>,
}

fn numeric(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .help(help)
        .value_parser(value_parser!(u64))
}

fn flag(name: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .help(help)
        .action(ArgAction::SetTrue)
}

fn optional_number<T: Copy + Send + Sync + 'static>(
    matches: &ArgMatches, name: &str, default: T,
) -> T {
    matches.get_one::<T>(name).copied().unwrap_or(default)
}

fn command() -> Command {
    Command::new("h3i")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Interactive HTTP/3 console debugger")
        .arg(
            Arg::new("host:port")
                .required(true)
                .index(1)
                .help("Server authority (HTTPS default port 443)"),
        )
        .arg(flag("omit-sni", "Omit SNI from TLS handshake"))
        .arg(
            Arg::new("connect-to")
                .long("connect-to")
                .value_parser(value_parser!(std::net::SocketAddr))
                .help("Override peer IP address and port"),
        )
        .arg(
            Arg::new("source-port")
                .long("source-port")
                .value_parser(value_parser!(u16))
                .help("Local UDP source port"),
        )
        .arg(flag("no-verify", "Do not verify server certificate"))
        .arg(flag("early-data", "Enable TLS early data"))
        .arg(flag(
            "no-qlog-actions-output",
            "Do not output action sequence as qlog",
        ))
        .arg(
            Arg::new("qlog-input")
                .long("qlog-input")
                .value_parser(value_parser!(PathBuf))
                .help("Drive connection via qlog"),
        )
        .arg(numeric("idle-timeout", "QUIC idle timeout in milliseconds"))
        .arg(
            Arg::new("send-capacity-factor")
                .long("send-capacity-factor")
                .value_parser(value_parser!(f64))
                .help("Send capacity multiplier"),
        )
        .arg(numeric(
            "max-data",
            "Initial connection flow-control limit in bytes",
        ))
        .arg(numeric(
            "max-stream-data-bidi-local",
            "Initial local bidirectional stream data limit",
        ))
        .arg(numeric(
            "max-stream-data-bidi-remote",
            "Initial remote bidirectional stream data limit",
        ))
        .arg(numeric(
            "max-stream-data-uni",
            "Initial unidirectional stream data limit",
        ))
        .arg(numeric(
            "max-streams-bidi",
            "Maximum concurrent remote bidirectional streams",
        ))
        .arg(numeric(
            "max-streams-uni",
            "Maximum concurrent remote unidirectional streams",
        ))
        .arg(numeric("max-window", "Connection receive window ceiling"))
        .arg(numeric(
            "max-stream-window",
            "Stream receive window ceiling",
        ))
        .arg(
            Arg::new("replay-host-override")
                .long("replay-host-override")
                .requires("qlog-input")
                .help("Override replayed request authority"),
        )
        .arg(flag("enable-dgram", "Enable QUIC DATAGRAM reception"))
        .arg(
            Arg::new("dgram-recv-queue-len")
                .long("dgram-recv-queue-len")
                .requires("enable-dgram")
                .value_parser(value_parser!(usize))
                .help("DATAGRAM receive queue length"),
        )
        .arg(
            Arg::new("dgram-send-queue-len")
                .long("dgram-send-queue-len")
                .requires("enable-dgram")
                .value_parser(value_parser!(usize))
                .help("DATAGRAM send queue length"),
        )
}

fn config_from_clap() -> std::result::Result<Config, String> {
    config_from_matches(&command().get_matches())
}

fn config_from_matches(matches: &ArgMatches) -> Result<Config, String> {
    let authority = matches
        .get_one::<String>("host:port")
        .ok_or("missing server authority")?;
    let mut library_config =
        h3i::config::Config::new(authority).map_err(|error| error.to_string())?;
    library_config.endpoint.connect_to = matches.get_one("connect-to").copied();
    library_config.endpoint.source_port =
        optional_number(matches, "source-port", 0);
    library_config.tls.omit_sni = matches.get_flag("omit-sni");
    library_config.tls.verify_peer = !matches.get_flag("no-verify");
    library_config.tls.early_data = matches.get_flag("early-data");
    library_config.idle_timeout =
        optional_number(matches, "idle-timeout", library_config.idle_timeout);
    library_config.send_capacity_factor = optional_number(
        matches,
        "send-capacity-factor",
        library_config.send_capacity_factor,
    );
    let flow = &mut library_config.flow;
    flow.max_data = optional_number(matches, "max-data", flow.max_data);
    flow.max_stream_data_bidi_local = optional_number(
        matches,
        "max-stream-data-bidi-local",
        flow.max_stream_data_bidi_local,
    );
    flow.max_stream_data_bidi_remote = optional_number(
        matches,
        "max-stream-data-bidi-remote",
        flow.max_stream_data_bidi_remote,
    );
    flow.max_stream_data_uni =
        optional_number(matches, "max-stream-data-uni", flow.max_stream_data_uni);
    flow.max_streams_bidi =
        optional_number(matches, "max-streams-bidi", flow.max_streams_bidi);
    flow.max_streams_uni =
        optional_number(matches, "max-streams-uni", flow.max_streams_uni);
    flow.max_window = optional_number(matches, "max-window", flow.max_window);
    flow.max_stream_window =
        optional_number(matches, "max-stream-window", flow.max_stream_window);
    if matches.get_flag("enable-dgram") {
        let defaults = DatagramQueues::default();
        library_config.datagrams = Some(DatagramQueues {
            receive: optional_number(
                matches,
                "dgram-recv-queue-len",
                defaults.receive,
            ),
            send: optional_number(matches, "dgram-send-queue-len", defaults.send),
        });
    }
    library_config
        .validate()
        .map_err(|error| error.to_string())?;
    Ok(Config {
        qlog_input: matches.get_one("qlog-input").cloned(),
        qlog_actions_output: !matches.get_flag("no-qlog-actions-output"),
        host_override: matches.get_one("replay-host-override").cloned(),
        library_config,
    })
}

#[cfg(feature = "async")]
fn async_client(
    config: Config, frame_actions: Vec<Action>,
) -> Result<ConnectionSummary, ClientError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| ClientError::Other(error.to_string()))?;

    rt.block_on(async {
        let summary = h3i::client::async_client::connect(
            &config.library_config,
            frame_actions,
            None,
        )
        .await?;
        summary.await
    })
}

#[cfg(not(feature = "async"))]
fn sync_client(
    config: Config, actions: Vec<Action>,
) -> Result<ConnectionSummary, ClientError> {
    // TODO: CLI/qlog don't support passing close trigger frames at the moment
    h3i::client::sync_client::connect(config.library_config, actions, None)
}

fn read_qlog(
    filename: &Path, host_override: Option<&str>,
) -> Result<Vec<Action>, ClientError> {
    let file = std::fs::File::open(filename).map_err(|error| {
        ClientError::Other(format!("open {}: {error}", filename.display()))
    })?;
    let reader = BufReader::new(file);

    let qlog_reader = QlogSeqReader::new(Box::new(reader))
        .map_err(|error| ClientError::Other(format!("qlog reader: {error:?}")))?;
    let mut actions = vec![];

    for event in qlog_reader {
        match event {
            qlog::reader::Event::Qlog(ev) => {
                let ac: H3Actions = actions_from_qlog(ev, host_override)?;
                actions.extend(ac.0);
            },

            qlog::reader::Event::Json(ev) => {
                let ac = H3Actions::try_from(ev)?;
                actions.extend(ac.0);
            },
        }
    }

    Ok(actions)
}

fn prompt_frames(config: &Config) -> Result<Vec<Action>, ClientError> {
    let mut prompter = Prompter::with_config(&config.library_config);
    let actions = prompter.prompt();

    if !actions.is_empty() && config.qlog_actions_output {
        let writer = make_qlog_writer()?;
        let mut streamer = make_streamer(Box::new(writer))?;

        for action in &actions {
            let events = QlogEvents::try_from(action)?;
            for event in events {
                match event {
                    QlogEvent::Event { data, ex_data } => {
                        streamer.add_event_data_ex_now(*data, ex_data).map_err(
                            |error| {
                                ClientError::Other(format!(
                                    "write qlog event: {error:?}"
                                ))
                            },
                        )?;
                    },

                    QlogEvent::JsonEvent(mut ev) => {
                        // need to rewrite the event time
                        ev.time = Instant::now()
                            .duration_since(streamer.start_time())
                            .as_secs_f64() *
                            1000.0;
                        streamer.add_event(ev).map_err(|error| {
                            ClientError::Other(format!(
                                "write qlog event: {error:?}"
                            ))
                        })?;
                    },
                }
            }
        }
        streamer.finish_log().map_err(|error| {
            ClientError::Other(format!("finish qlog: {error:?}"))
        })?;
    }

    Ok(actions)
}

fn make_qlog_writer() -> Result<std::io::BufWriter<std::fs::File>, ClientError> {
    let now = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .map_err(|error| {
            ClientError::Other(format!("qlog timestamp: {error}"))
        })?;
    let path = std::env::current_dir()
        .map_err(|error| {
            ClientError::Other(format!("qlog working directory: {error}"))
        })?
        .join(format!("{}-qlog.sqlog", now.as_millis()));
    let file = std::fs::File::create_new(&path).map_err(|error| {
        ClientError::Other(format!("create {}: {error}", path.display()))
    })?;
    log::info!("Session will be recorded to {}", path.display());
    Ok(std::io::BufWriter::new(file))
}

fn make_streamer(
    writer: Box<dyn std::io::Write + Send + Sync>,
) -> Result<qlog::streamer::QlogStreamer, ClientError> {
    let vp = qlog::VantagePointType::Client;

    let trace = qlog::TraceSeq::new(
        Some("h3i".into()),
        Some("h3i".into()),
        None,
        Some(qlog::VantagePoint {
            name: None,
            ty: vp,
            flow: None,
        }),
        vec![QUIC_URI.to_string(), HTTP3_URI.to_string()],
    );

    let mut streamer = qlog::streamer::QlogStreamer::new(
        Some("h3i".into()),
        Some("h3i".into()),
        time::Instant::now(),
        trace,
        qlog::events::EventImportance::Extra,
        qlog::streamer::EventTimePrecision::NanoSeconds,
        writer,
    );

    streamer
        .start_log()
        .map_err(|error| ClientError::Other(format!("start qlog: {error:?}")))?;

    Ok(streamer)
}

#[cfg(test)]
mod config_tests {
    use super::command;
    use super::config_from_matches;

    #[test]
    fn cli_defaults_and_explicit_overrides_share_the_library_model(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let defaults = config_from_matches(
            &command().try_get_matches_from(["h3i", "example.org"])?,
        )?;
        assert_eq!(defaults.library_config.flow.max_data, 10_000_000);
        assert_eq!(defaults.library_config.flow.max_stream_data_uni, 1_000_000);
        assert!(defaults.library_config.datagrams.is_none());
        let matches = command().try_get_matches_from([
            "h3i",
            "example.org:8443",
            "--connect-to=[::1]:4433",
            "--source-port=12345",
            "--omit-sni",
            "--no-verify",
            "--early-data",
            "--max-data=32",
            "--max-stream-data-uni=123",
            "--enable-dgram",
            "--dgram-recv-queue-len=10",
            "--qlog-input=fixtures/replay.sqlog",
        ])?;
        let config = config_from_matches(&matches)?;
        let library = config.library_config;
        assert_eq!(library.endpoint.authority(), "example.org:8443");
        assert_eq!(
            library.endpoint.socket_addresses()?.0.to_string(),
            "[::1]:4433"
        );
        assert_eq!(library.endpoint.source_port, 12_345);
        assert!(
            library.tls.omit_sni &&
                library.tls.early_data &&
                !library.tls.verify_peer
        );
        assert_eq!(library.flow.max_data, 32);
        assert_eq!(library.flow.max_stream_data_uni, 123);
        assert_eq!(
            library.datagrams.as_ref().map(|queues| queues.receive),
            Some(10)
        );
        assert_eq!(
            config.qlog_input.as_deref(),
            Some(std::path::Path::new("fixtures/replay.sqlog"))
        );
        Ok(())
    }

    #[test]
    fn typed_cli_rejects_invalid_inputs() -> Result<(), Box<dyn std::error::Error>>
    {
        for flag in [
            "--max-data=negative",
            "--source-port=65536",
            "--connect-to=not-an-address",
            "--dgram-send-queue-len=0",
        ] {
            assert!(command()
                .try_get_matches_from(["h3i", "example.org", flag])
                .is_err());
        }
        let matches = command().try_get_matches_from([
            "h3i",
            "example.org",
            "--send-capacity-factor=NaN",
        ])?;
        assert!(config_from_matches(&matches).is_err());
        Ok(())
    }
}
