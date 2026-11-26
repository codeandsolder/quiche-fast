// Copyright (C) 2020, Cloudflare, Inc.
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

use super::common::alpns;
use std::time::Duration;

use clap::Arg;
use clap::ArgAction;
use clap::ArgMatches;
use clap::Command;
use clap::Error;
use std::net::SocketAddr;
use std::str::FromStr;

/// Convert an already parsed command line into application settings.
pub trait Args: Sized {
    /// Decode and validate the arguments.
    ///
    /// # Errors
    /// Returns a descriptive argument error for invalid values.
    fn from_args(args: &ArgMatches) -> Result<Self, Error>;
}

fn invalid(option: &str, error: impl std::fmt::Display) -> Error {
    Error::raw(
        clap::error::ErrorKind::ValueValidation,
        format!("{option}: {error}"),
    )
}

fn number<T: FromStr>(args: &ArgMatches, option: &str) -> Result<T, Error>
where
    T::Err: std::fmt::Display,
{
    text(args, option)
        .parse()
        .map_err(|error| invalid(option, error))
}

fn text<'a>(args: &'a ArgMatches, option: &str) -> &'a str {
    args.get_one::<String>(option.trim_start_matches("--"))
        .map_or("", String::as_str)
}

fn optional(args: &ArgMatches, option: &str) -> Option<String> {
    let value = text(args, option);
    (!value.is_empty()).then(|| value.to_owned())
}

fn optional_number<T: FromStr>(
    args: &ArgMatches, option: &str,
) -> Result<Option<T>, Error>
where
    T::Err: std::fmt::Display,
{
    if text(args, option).is_empty() {
        Ok(None)
    } else {
        number(args, option).map(Some)
    }
}

/// Connection behavior independent of the selected congestion algorithm.
pub struct ConnectionBehavior {
    pub early_data: bool,
    pub grease: bool,
    pub active_migration: bool,
}

/// Congestion-control configuration.
pub struct CongestionSettings {
    pub algorithm: quiche::CongestionControlAlgorithm,
    pub hystart: bool,
    pub initial_rtt: Duration,
    pub initial_cwnd_packets: usize,
}

/// Enabled one-way DATAGRAM workload.
pub struct DatagramSettings {
    pub count: u64,
    pub data: String,
}

/// Shared arguments for creating a QUIC connection.
pub struct CommonArgs {
    pub alpns: Vec<&'static [u8]>,
    pub max_data: u64,
    pub max_window: u64,
    pub max_stream_data: u64,
    pub max_stream_window: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub idle_timeout: u64,
    pub behavior: ConnectionBehavior,
    pub congestion: CongestionSettings,
    pub datagrams: Option<DatagramSettings>,
    pub dump_packet_path: Option<String>,
    pub max_active_cids: u64,
    pub max_field_section_size: Option<u64>,
    pub qpack_max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
}

impl Args for CommonArgs {
    fn from_args(args: &ArgMatches) -> Result<Self, Error> {
        let http = text(args, "http-version");
        let protocol = text(args, "dgram-proto");
        let alpns = match (http, protocol) {
            ("HTTP/0.9", "none") => alpns::HTTP_09.to_vec(),
            ("HTTP/3", "none" | "oneway") => alpns::HTTP_3.to_vec(),
            ("all", "none") =>
                [alpns::HTTP_3.as_slice(), &alpns::HTTP_09].concat(),
            _ =>
                return Err(invalid(
                    "--http-version/--dgram-proto",
                    format!("unsupported combination {http}/{protocol}"),
                )),
        };
        let count = number(args, "--dgram-count")?;
        let datagrams = (protocol == "oneway").then(|| DatagramSettings {
            count,
            data: text(args, "dgram-data").to_owned(),
        });
        let algorithm = text(args, "cc-algorithm")
            .parse()
            .map_err(|error| invalid("--cc-algorithm", error))?;
        Ok(Self {
            alpns,
            max_data: number(args, "--max-data")?,
            max_window: number(args, "--max-window")?,
            max_stream_data: number(args, "--max-stream-data")?,
            max_stream_window: number(args, "--max-stream-window")?,
            max_streams_bidi: number(args, "--max-streams-bidi")?,
            max_streams_uni: number(args, "--max-streams-uni")?,
            idle_timeout: number(args, "--idle-timeout")?,
            behavior: ConnectionBehavior {
                early_data: args.get_flag("early-data"),
                grease: !args.get_flag("no-grease"),
                active_migration: args.get_flag("enable-active-migration"),
            },
            congestion: CongestionSettings {
                algorithm,
                hystart: !args.get_flag("disable-hystart"),
                initial_rtt: Duration::from_millis(number(
                    args,
                    "--initial-rtt",
                )?),
                initial_cwnd_packets: number(args, "--initial-cwnd-packets")?,
            },
            datagrams,
            dump_packet_path: optional(args, "--dump-packets"),
            max_active_cids: number(args, "--max-active-cids")?,
            max_field_section_size: optional_number(
                args,
                "--max-field-section-size",
            )?,
            qpack_max_table_capacity: optional_number(
                args,
                "--qpack-max-table-capacity",
            )?,
            qpack_blocked_streams: optional_number(
                args,
                "--qpack-blocked-streams",
            )?,
        })
    }
}

impl Default for CommonArgs {
    fn default() -> Self {
        Self {
            alpns: alpns::HTTP_3.to_vec(),
            max_data: 10_000_000,
            max_window: 25_165_824,
            max_stream_data: 1_000_000,
            max_stream_window: 16_777_216,
            max_streams_bidi: 100,
            max_streams_uni: 100,
            idle_timeout: 30_000,
            behavior: ConnectionBehavior {
                early_data: false,
                grease: true,
                active_migration: false,
            },
            congestion: CongestionSettings {
                algorithm: quiche::CongestionControlAlgorithm::Cubic,
                hystart: true,
                initial_rtt: Duration::from_millis(333),
                initial_cwnd_packets: 10,
            },
            datagrams: None,
            dump_packet_path: None,
            max_active_cids: 2,
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
        }
    }
}

impl CommonArgs {
    /// Apply shared transport settings to a client or server configuration.
    ///
    /// # Errors
    /// Returns an error if the application protocols cannot be configured.
    pub fn configure(
        &self, config: &mut quiche::Config, datagram_size: usize,
    ) -> quiche::Result<()> {
        config.set_application_protos(&self.alpns)?;
        config.set_initial_rtt(self.congestion.initial_rtt);
        config.set_max_idle_timeout(self.idle_timeout);
        config.set_max_recv_udp_payload_size(datagram_size);
        config.set_max_send_udp_payload_size(datagram_size);
        config.set_initial_max_data(self.max_data);
        config.set_initial_max_stream_data_bidi_local(self.max_stream_data);
        config.set_initial_max_stream_data_bidi_remote(self.max_stream_data);
        config.set_initial_max_stream_data_uni(self.max_stream_data);
        config.set_initial_max_streams_bidi(self.max_streams_bidi);
        config.set_initial_max_streams_uni(self.max_streams_uni);
        config.set_disable_active_migration(!self.behavior.active_migration);
        config.set_active_connection_id_limit(self.max_active_cids);
        config.set_initial_congestion_window_packets(
            self.congestion.initial_cwnd_packets,
        );
        config.set_max_connection_window(self.max_window);
        config.set_max_stream_window(self.max_stream_window);
        config.grease(self.behavior.grease);
        if self.behavior.early_data {
            config.enable_early_data();
        }
        config.set_cc_algorithm(self.congestion.algorithm);
        config.enable_hystart(self.congestion.hystart);
        if self.datagrams.is_some() {
            config.enable_dgram(true, 1000, 1000);
        }
        Ok(())
    }
}

fn common_command(name: &'static str, datagram_default: &'static str) -> Command {
    Command::new(name)
        .arg(Arg::new("max-data").long("max-data").help("Connection-wide flow control limit").value_name("BYTES").default_value("10000000"))
        .arg(Arg::new("max-window").long("max-window").help("Connection-wide max receiver window").value_name("BYTES").default_value("25165824"))
        .arg(Arg::new("max-stream-data").long("max-stream-data").help("Per-stream flow control limit").value_name("BYTES").default_value("1000000"))
        .arg(Arg::new("max-stream-window").long("max-stream-window").help("Per-stream max receiver window").value_name("BYTES").default_value("16777216"))
        .arg(Arg::new("max-streams-bidi").long("max-streams-bidi").help("Number of allowed concurrent streams").value_name("STREAMS").default_value("100"))
        .arg(Arg::new("max-streams-uni").long("max-streams-uni").help("Number of allowed concurrent streams").value_name("STREAMS").default_value("100"))
        .arg(Arg::new("idle-timeout").long("idle-timeout").help("Idle timeout in milliseconds").value_name("TIMEOUT").default_value("30000"))
        .arg(Arg::new("http-version").long("http-version").help("HTTP version to use").value_name("VERSION").default_value("all"))
        .arg(Arg::new("early-data").long("early-data").help("Enable sending early data.").action(ArgAction::SetTrue))
        .arg(Arg::new("dgram-proto").long("dgram-proto").help("DATAGRAM application protocol to use").value_name("PROTO").default_value("none"))
        .arg(Arg::new("dgram-count").long("dgram-count").help("Number of DATAGRAMs to send").value_name("COUNT").default_value("0"))
        .arg(Arg::new("dump-packets").long("dump-packets").help("Dump the incoming packets as files in the given directory.").value_name("PATH").allow_hyphen_values(true))
        .arg(Arg::new("no-grease").long("no-grease").help("Don't send GREASE.").action(ArgAction::SetTrue))
        .arg(Arg::new("cc-algorithm").long("cc-algorithm").help("Specify which congestion control algorithm to use").value_name("NAME").default_value("cubic"))
        .arg(Arg::new("disable-hystart").long("disable-hystart").help("Disable HyStart++.").action(ArgAction::SetTrue))
        .arg(Arg::new("max-active-cids").long("max-active-cids").help("The maximum number of active Connection IDs we can support").value_name("NUM").default_value("2"))
        .arg(Arg::new("enable-active-migration").long("enable-active-migration").help("Enable active connection migration.").action(ArgAction::SetTrue))
        .arg(Arg::new("max-field-section-size").long("max-field-section-size").help("Max size of uncompressed field section. Default is unlimited.").value_name("BYTES").allow_hyphen_values(true))
        .arg(Arg::new("qpack-max-table-capacity").long("qpack-max-table-capacity").help("Max capacity of dynamic QPACK decoding.. Any value other that 0 is currently unsupported.").value_name("BYTES").allow_hyphen_values(true))
        .arg(Arg::new("qpack-blocked-streams").long("qpack-blocked-streams").help("Limit of blocked streams while decoding. Any value other that 0 is currently unsupported.").value_name("STREAMS").allow_hyphen_values(true))
        .arg(Arg::new("initial-rtt").long("initial-rtt").help("The initial RTT in milliseconds").value_name("MILLIS").default_value("333"))
        .arg(Arg::new("initial-cwnd-packets").long("initial-cwnd-packets").help("The initial congestion window size in terms of packet count").value_name("PACKETS").default_value("10"))
        .arg(Arg::new("dgram-data").long("dgram-data").value_name("DATA").default_value(datagram_default).help("DATAGRAM payload"))
}

/// Command-line definition for the QUIC client.
#[must_use]
pub fn client_command() -> Command {
    common_command("quiche-client", "quack")
        .arg(Arg::new("method").long("method").help("Use the given HTTP request method").value_name("METHOD").default_value("GET"))
        .arg(Arg::new("body").long("body").help("Send the given file as request body.").value_name("FILE").allow_hyphen_values(true))
        .arg(Arg::new("wire-version").long("wire-version").help("The version number to send to the server").value_name("VERSION").default_value("babababa"))
        .arg(Arg::new("dump-responses").long("dump-responses").help("Dump response payload as files in the given directory.").value_name("PATH").allow_hyphen_values(true))
        .arg(Arg::new("dump-json").long("dump-json").help("Dump response headers and payload to stdout in JSON format.").action(ArgAction::SetTrue))
        .arg(Arg::new("max-json-payload").long("max-json-payload").help("Per-response payload limit when dumping JSON").value_name("BYTES").default_value("10000"))
        .arg(Arg::new("connect-to").long("connect-to").help("Override the server's address.").value_name("ADDRESS").allow_hyphen_values(true))
        .arg(Arg::new("no-verify").long("no-verify").help("Don't verify server's certificate.").action(ArgAction::SetTrue))
        .arg(Arg::new("trust-origin-ca-pem").long("trust-origin-ca-pem").help("Path to the pem file of the origin's CA, if not publicly trusted.").value_name("file").allow_hyphen_values(true))
        .arg(Arg::new("perform-migration").long("perform-migration").help("Perform connection migration on another source port.").action(ArgAction::SetTrue))
        .arg(Arg::new("header").long("header").help("Add a request header.").short('H').value_name("HEADER").action(ArgAction::Append))
        .arg(Arg::new("requests").long("requests").help("Send the given number of identical requests").short('n').value_name("REQUESTS").default_value("1"))
        .arg(Arg::new("send-priority-update").long("send-priority-update").help("Send HTTP/3 priority updates if the query string params 'u' or 'i' are present in URLs").action(ArgAction::SetTrue))
        .arg(Arg::new("session-file").long("session-file").help("File used to cache a TLS session for resumption.").value_name("PATH").allow_hyphen_values(true))
        .arg(Arg::new("source-port").long("source-port").help("Source port to use when connecting to the server").value_name("PORT").default_value("0"))
        .arg(Arg::new("URL").required(true).num_args(1..).action(ArgAction::Append))
}

/// Application-specific arguments that complement the `CommonArgs`.
pub struct ClientArgs {
    pub version: u32,
    pub dump_response_path: Option<String>,
    pub dump_json: Option<usize>,
    pub urls: Vec<url::Url>,
    pub reqs_cardinal: u64,
    pub req_headers: Vec<String>,
    pub no_verify: bool,
    pub trust_origin_ca_pem: Option<String>,
    pub body: Option<Vec<u8>>,
    pub method: String,
    pub connect_to: Option<SocketAddr>,
    pub session_file: Option<String>,
    pub source_port: u16,
    pub perform_migration: bool,
    pub send_priority_update: bool,
}

impl Args for ClientArgs {
    fn from_args(args: &ArgMatches) -> Result<Self, Error> {
        let version = u32::from_str_radix(text(args, "wire-version"), 16)
            .map_err(|error| invalid("--wire-version", error))?;
        let urls = args
            .get_many::<String>("URL")
            .into_iter()
            .flatten()
            .map(|value| {
                let url = url::Url::parse(value)
                    .map_err(|error| invalid("URL", error))?;
                if url.host().is_none() || url.port_or_known_default().is_none() {
                    return Err(invalid("URL", "expected a host and port"));
                }
                Ok(url)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let body = optional(args, "--body")
            .map(|path| {
                std::fs::read(&path).map_err(|error| {
                    invalid("--body", format!("{path}: {error}"))
                })
            })
            .transpose()?;
        Ok(Self {
            version,
            dump_response_path: optional(args, "--dump-responses"),
            dump_json: if args.get_flag("dump-json") {
                Some(number(args, "--max-json-payload")?)
            } else {
                None
            },
            urls,
            reqs_cardinal: number(args, "--requests")?,
            req_headers: args
                .get_many::<String>("header")
                .into_iter()
                .flatten()
                .cloned()
                .collect(),
            no_verify: args.get_flag("no-verify"),
            trust_origin_ca_pem: optional(args, "--trust-origin-ca-pem"),
            body,
            method: text(args, "method").to_owned(),
            connect_to: optional_number(args, "--connect-to")?,
            session_file: optional(args, "--session-file"),
            source_port: number(args, "--source-port")?,
            perform_migration: args.get_flag("perform-migration"),
            send_priority_update: args.get_flag("send-priority-update"),
        })
    }
}

impl Default for ClientArgs {
    fn default() -> Self {
        Self {
            version: 0xbaba_baba,
            dump_response_path: None,
            dump_json: None,
            urls: vec![],
            req_headers: vec![],
            reqs_cardinal: 1,
            no_verify: false,
            trust_origin_ca_pem: None,
            body: None,
            method: "GET".to_string(),
            connect_to: None,
            session_file: None,
            source_port: 0,
            perform_migration: false,
            send_priority_update: false,
        }
    }
}

/// Command-line definition for the QUIC server.
#[must_use]
pub fn server_command() -> Command {
    common_command("quiche-server", "brrr")
        .arg(
            Arg::new("listen")
                .long("listen")
                .help("Listen on the given IP:port")
                .value_name("addr")
                .default_value("127.0.0.1:4433"),
        )
        .arg(
            Arg::new("cert")
                .long("cert")
                .help("TLS certificate path")
                .value_name("file")
                .default_value("src/bin/cert.crt"),
        )
        .arg(
            Arg::new("key")
                .long("key")
                .help("TLS certificate key path")
                .value_name("file")
                .default_value("src/bin/cert.key"),
        )
        .arg(
            Arg::new("root")
                .long("root")
                .help("Root directory")
                .value_name("dir")
                .default_value("src/bin/root/"),
        )
        .arg(
            Arg::new("index")
                .long("index")
                .help("The file that will be used as index")
                .value_name("name")
                .default_value("index.html"),
        )
        .arg(
            Arg::new("name")
                .long("name")
                .help("Name of the server")
                .value_name("str")
                .default_value("quic.tech"),
        )
        .arg(
            Arg::new("no-retry")
                .long("no-retry")
                .help("Disable stateless retry.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("disable-gso")
                .long("disable-gso")
                .help("Disable GSO (linux only).")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("disable-pacing")
                .long("disable-pacing")
                .help("Disable pacing (linux only).")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("enable-pmtud")
                .long("enable-pmtud")
                .help("Enable path MTU discovery.")
                .action(ArgAction::SetTrue),
        )
}

/// UDP send acceleration settings for the server.
pub struct SocketSettings {
    pub gso: bool,
    pub pacing: bool,
}

/// Server-specific arguments.
pub struct ServerArgs {
    pub listen: SocketAddr,
    pub no_retry: bool,
    pub root: String,
    pub index: String,
    pub cert: String,
    pub key: String,
    pub socket: SocketSettings,
    pub enable_pmtud: bool,
}

impl Args for ServerArgs {
    fn from_args(args: &ArgMatches) -> Result<Self, Error> {
        Ok(Self {
            listen: number(args, "--listen")?,
            no_retry: args.get_flag("no-retry"),
            root: text(args, "root").to_owned(),
            index: text(args, "index").to_owned(),
            cert: text(args, "cert").to_owned(),
            key: text(args, "key").to_owned(),
            socket: SocketSettings {
                gso: !args.get_flag("disable-gso"),
                pacing: !args.get_flag("disable-pacing"),
            },
            enable_pmtud: args.get_flag("enable-pmtud"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::client_command;
    use super::server_command;
    use super::Args;
    use super::ClientArgs;
    use super::CommonArgs;
    use super::ServerArgs;
    use clap::ArgMatches;
    use clap::Error;

    fn parse(command: clap::Command, argv: &[&str]) -> Result<ArgMatches, Error> {
        command.try_get_matches_from(argv)
    }

    #[test]
    fn shared_options_and_datagram_workload(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parsed = parse(client_command(), &[
            "quiche-client",
            "--http-version=HTTP/3",
            "--dgram-proto=oneway",
            "--dgram-count=12",
            "--dgram-data=hello",
            "--cc-algorithm=bbr",
            "--early-data",
            "--no-grease",
            "--disable-hystart",
            "--enable-active-migration",
            "--initial-cwnd-packets=32",
            "--max-field-section-size=0",
            "https://example.org/",
        ])?;
        let common = CommonArgs::from_args(&parsed)?;
        assert_eq!(common.alpns, [b"h3".as_slice()]);
        assert!(common.behavior.early_data);
        assert!(!common.behavior.grease);
        assert!(common.behavior.active_migration);
        assert!(!common.congestion.hystart);
        assert_eq!(
            common.congestion.algorithm,
            quiche::CongestionControlAlgorithm::Bbr2Gcongestion
        );
        assert_eq!(common.congestion.initial_cwnd_packets, 32);
        assert_eq!(common.max_field_section_size, Some(0));
        let datagrams = common.datagrams.as_ref().ok_or("missing workload")?;
        assert_eq!(datagrams.count, 12);
        assert_eq!(datagrams.data, "hello");
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        common.configure(&mut config, 1350)?;
        Ok(())
    }

    #[test]
    fn invalid_connection_options_identify_argument() -> Result<(), Error> {
        for (flag, expected) in [
            ("--max-data=bad", "--max-data"),
            ("--max-streams-bidi=-1", "--max-streams-bidi"),
            (
                "--initial-cwnd-packets=18446744073709551616",
                "--initial-cwnd-packets",
            ),
            ("--cc-algorithm=invalid", "--cc-algorithm"),
            ("--dgram-proto=oneway", "--http-version/--dgram-proto"),
            ("--qpack-blocked-streams=no", "--qpack-blocked-streams"),
        ] {
            let parsed = parse(client_command(), &[
                "quiche-client",
                flag,
                "https://example.org/",
            ])?;
            assert!(CommonArgs::from_args(&parsed)
                .is_err_and(|error| error.to_string().contains(expected)));
        }
        Ok(())
    }

    #[test]
    fn invalid_client_options_are_errors_not_panics() -> Result<(), Error> {
        for (flag, expected) in [
            ("--source-port=65536", "--source-port"),
            ("--wire-version=no", "--wire-version"),
            ("--connect-to=not-an-address", "--connect-to"),
            ("--body=Cargo.toml/missing", "--body"),
        ] {
            let parsed = parse(client_command(), &[
                "quiche-client",
                flag,
                "https://example.org/",
            ])?;
            assert!(ClientArgs::from_args(&parsed)
                .is_err_and(|error| error.to_string().contains(expected)));
        }
        let parsed = parse(client_command(), &[
            "quiche-client",
            "mailto:local@example.org",
        ])?;
        assert!(ClientArgs::from_args(&parsed)
            .is_err_and(|error| error.to_string().contains("URL")));
        Ok(())
    }

    #[test]
    fn server_socket_options_and_client_address_are_typed() -> Result<(), Error> {
        let parsed = parse(server_command(), &[
            "quiche-server",
            "--listen=[::1]:4433",
            "--enable-pmtud",
            "--disable-gso",
            "--disable-pacing",
        ])?;
        let args = ServerArgs::from_args(&parsed)?;
        assert!(args.listen.is_ipv6());
        assert_eq!(args.listen.port(), 4433);
        assert!(args.enable_pmtud);
        assert!(!args.socket.gso);
        assert!(!args.socket.pacing);
        let common = CommonArgs::from_args(&parsed)?;
        assert_eq!(common.alpns, [b"h3".as_slice(), b"hq-interop", b"http/0.9"]);
        assert!(common.datagrams.is_none());
        let parsed = parse(client_command(), &[
            "quiche-client",
            "--connect-to=127.0.0.1:4433",
            "--dump-json",
            "--max-json-payload=42",
            "https://example.org/path",
        ])?;
        let args = ClientArgs::from_args(&parsed)?;
        assert_eq!(args.connect_to.map(|addr| addr.port()), Some(4433));
        assert_eq!(args.dump_json, Some(42));
        assert_eq!(args.urls[0].path(), "/path");
        Ok(())
    }
}
