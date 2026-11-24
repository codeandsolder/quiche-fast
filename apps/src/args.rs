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

use docopt::ArgvMap;
use docopt::Error;
use std::net::SocketAddr;
use std::str::FromStr;

/// Convert an already parsed command line into application settings.
pub trait Args: Sized {
    /// Decode and validate the arguments.
    ///
    /// # Errors
    /// Returns a descriptive argument error for invalid values.
    fn from_args(args: &ArgvMap) -> Result<Self, Error>;
}

fn invalid(option: &str, error: impl std::fmt::Display) -> Error {
    Error::Argv(format!("{option}: {error}"))
}

fn number<T: FromStr>(args: &ArgvMap, option: &str) -> Result<T, Error>
where
    T::Err: std::fmt::Display,
{
    args.get_str(option)
        .parse()
        .map_err(|error| invalid(option, error))
}

fn optional(args: &ArgvMap, option: &str) -> Option<String> {
    let value = args.get_str(option);
    (!value.is_empty()).then(|| value.to_owned())
}

fn optional_number<T: FromStr>(
    args: &ArgvMap, option: &str,
) -> Result<Option<T>, Error>
where
    T::Err: std::fmt::Display,
{
    if args.get_str(option).is_empty() {
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
    fn from_args(args: &ArgvMap) -> Result<Self, Error> {
        let http = args.get_str("--http-version");
        let protocol = args.get_str("--dgram-proto");
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
            data: args.get_str("--dgram-data").to_owned(),
        });
        let algorithm = args
            .get_str("--cc-algorithm")
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
                early_data: args.get_bool("--early-data"),
                grease: !args.get_bool("--no-grease"),
                active_migration: args.get_bool("--enable-active-migration"),
            },
            congestion: CongestionSettings {
                algorithm,
                hystart: !args.get_bool("--disable-hystart"),
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

pub const CLIENT_USAGE: &str = "Usage:
  quiche-client [options] URL...
  quiche-client -h | --help

Options:
  --method METHOD          Use the given HTTP request method [default: GET].
  --body FILE              Send the given file as request body.
  --max-data BYTES         Connection-wide flow control limit [default: 10000000].
  --max-window BYTES       Connection-wide max receiver window [default: 25165824].
  --max-stream-data BYTES  Per-stream flow control limit [default: 1000000].
  --max-stream-window BYTES   Per-stream max receiver window [default: 16777216].
  --max-streams-bidi STREAMS  Number of allowed concurrent streams [default: 100].
  --max-streams-uni STREAMS   Number of allowed concurrent streams [default: 100].
  --idle-timeout TIMEOUT   Idle timeout in milliseconds [default: 30000].
  --wire-version VERSION   The version number to send to the server [default: babababa].
  --http-version VERSION   HTTP version to use [default: all].
  --early-data             Enable sending early data.
  --dgram-proto PROTO      DATAGRAM application protocol to use [default: none].
  --dgram-count COUNT      Number of DATAGRAMs to send [default: 0].
  --dgram-data DATA        Data to send for certain types of DATAGRAM application protocol [default: quack].
  --dump-packets PATH      Dump the incoming packets as files in the given directory.
  --dump-responses PATH    Dump response payload as files in the given directory.
  --dump-json              Dump response headers and payload to stdout in JSON format.
  --max-json-payload BYTES  Per-response payload limit when dumping JSON [default: 10000].
  --connect-to ADDRESS     Override the server's address.
  --no-verify              Don't verify server's certificate.
  --trust-origin-ca-pem <file>  Path to the pem file of the origin's CA, if not publicly trusted.
  --no-grease              Don't send GREASE.
  --cc-algorithm NAME      Specify which congestion control algorithm to use [default: cubic].
  --disable-hystart        Disable HyStart++.
  --max-active-cids NUM    The maximum number of active Connection IDs we can support [default: 2].
  --enable-active-migration   Enable active connection migration.
  --perform-migration      Perform connection migration on another source port.
  -H --header HEADER ...   Add a request header.
  -n --requests REQUESTS   Send the given number of identical requests [default: 1].
  --send-priority-update   Send HTTP/3 priority updates if the query string params 'u' or 'i' are present in URLs
  --max-field-section-size BYTES    Max size of uncompressed field section. Default is unlimited.
  --qpack-max-table-capacity BYTES  Max capacity of dynamic QPACK decoding.. Any value other that 0 is currently unsupported.
  --qpack-blocked-streams STREAMS   Limit of blocked streams while decoding. Any value other that 0 is currently unsupported.
  --session-file PATH      File used to cache a TLS session for resumption.
  --source-port PORT       Source port to use when connecting to the server [default: 0].
  --initial-rtt MILLIS     The initial RTT in milliseconds [default: 333].
  --initial-cwnd-packets PACKETS   The initial congestion window size in terms of packet count [default: 10].
  -h --help                Show this screen.
";

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
    fn from_args(args: &ArgvMap) -> Result<Self, Error> {
        let version = u32::from_str_radix(args.get_str("--wire-version"), 16)
            .map_err(|error| invalid("--wire-version", error))?;
        let urls = args
            .get_vec("URL")
            .into_iter()
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
            dump_json: if args.get_bool("--dump-json") {
                Some(number(args, "--max-json-payload")?)
            } else {
                None
            },
            urls,
            reqs_cardinal: number(args, "--requests")?,
            req_headers: args
                .get_vec("--header")
                .into_iter()
                .map(str::to_owned)
                .collect(),
            no_verify: args.get_bool("--no-verify"),
            trust_origin_ca_pem: optional(args, "--trust-origin-ca-pem"),
            body,
            method: args.get_str("--method").to_owned(),
            connect_to: optional_number(args, "--connect-to")?,
            session_file: optional(args, "--session-file"),
            source_port: number(args, "--source-port")?,
            perform_migration: args.get_bool("--perform-migration"),
            send_priority_update: args.get_bool("--send-priority-update"),
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

pub const SERVER_USAGE: &str = "Usage:
  quiche-server [options]
  quiche-server -h | --help

Options:
  --listen <addr>             Listen on the given IP:port [default: 127.0.0.1:4433]
  --cert <file>               TLS certificate path [default: src/bin/cert.crt]
  --key <file>                TLS certificate key path [default: src/bin/cert.key]
  --root <dir>                Root directory [default: src/bin/root/]
  --index <name>              The file that will be used as index [default: index.html].
  --name <str>                Name of the server [default: quic.tech]
  --max-data BYTES            Connection-wide flow control limit [default: 10000000].
  --max-window BYTES          Connection-wide max receiver window [default: 25165824].
  --max-stream-data BYTES     Per-stream flow control limit [default: 1000000].
  --max-stream-window BYTES   Per-stream max receiver window [default: 16777216].
  --max-streams-bidi STREAMS  Number of allowed concurrent streams [default: 100].
  --max-streams-uni STREAMS   Number of allowed concurrent streams [default: 100].
  --idle-timeout TIMEOUT      Idle timeout in milliseconds [default: 30000].
  --dump-packets PATH         Dump the incoming packets as files in the given directory.
  --early-data                Enable receiving early data.
  --no-retry                  Disable stateless retry.
  --no-grease                 Don't send GREASE.
  --http-version VERSION      HTTP version to use [default: all].
  --dgram-proto PROTO         DATAGRAM application protocol to use [default: none].
  --dgram-count COUNT         Number of DATAGRAMs to send [default: 0].
  --dgram-data DATA           Data to send for certain types of DATAGRAM application protocol [default: brrr].
  --cc-algorithm NAME         Specify which congestion control algorithm to use [default: cubic].
  --disable-hystart           Disable HyStart++.
  --max-active-cids NUM       The maximum number of active Connection IDs we can support [default: 2].
  --enable-active-migration   Enable active connection migration.
  --max-field-section-size BYTES    Max size of uncompressed HTTP/3 field section. Default is unlimited.
  --qpack-max-table-capacity BYTES  Max capacity of QPACK dynamic table decoding. Any value other that 0 is currently unsupported.
  --qpack-blocked-streams STREAMS   Limit of streams that can be blocked while decoding. Any value other that 0 is currently unsupported.
  --disable-gso               Disable GSO (linux only).
  --disable-pacing            Disable pacing (linux only).
  --enable-pmtud              Enable path MTU discovery.
  --initial-rtt MILLIS     The initial RTT in milliseconds [default: 333].
  --initial-cwnd-packets PACKETS      The initial congestion window size in terms of packet count [default: 10].
  -h --help                   Show this screen.
";

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
    fn from_args(args: &ArgvMap) -> Result<Self, Error> {
        Ok(Self {
            listen: number(args, "--listen")?,
            no_retry: args.get_bool("--no-retry"),
            root: args.get_str("--root").to_owned(),
            index: args.get_str("--index").to_owned(),
            cert: args.get_str("--cert").to_owned(),
            key: args.get_str("--key").to_owned(),
            socket: SocketSettings {
                gso: !args.get_bool("--disable-gso"),
                pacing: !args.get_bool("--disable-pacing"),
            },
            enable_pmtud: args.get_bool("--enable-pmtud"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Args;
    use super::ClientArgs;
    use super::CommonArgs;
    use super::ServerArgs;
    use super::CLIENT_USAGE;
    use super::SERVER_USAGE;
    use docopt::ArgvMap;
    use docopt::Docopt;
    use docopt::Error;

    fn parse(usage: &str, argv: &[&str]) -> Result<ArgvMap, Error> {
        Docopt::new(usage)?.argv(argv.iter().copied()).parse()
    }

    #[test]
    fn shared_options_and_datagram_workload(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parsed = parse(CLIENT_USAGE, &[
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
            let parsed = parse(CLIENT_USAGE, &[
                "quiche-client",
                flag,
                "https://example.org/",
            ])?;
            assert!(
                matches!(CommonArgs::from_args(&parsed), Err(Error::Argv(message)) if message.starts_with(expected))
            );
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
            let parsed = parse(CLIENT_USAGE, &[
                "quiche-client",
                flag,
                "https://example.org/",
            ])?;
            assert!(
                matches!(ClientArgs::from_args(&parsed), Err(Error::Argv(message)) if message.starts_with(expected))
            );
        }
        let parsed =
            parse(CLIENT_USAGE, &["quiche-client", "mailto:local@example.org"])?;
        assert!(
            matches!(ClientArgs::from_args(&parsed), Err(Error::Argv(message)) if message.starts_with("URL"))
        );
        Ok(())
    }

    #[test]
    fn server_socket_options_and_client_address_are_typed() -> Result<(), Error> {
        let parsed = parse(SERVER_USAGE, &[
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
        let parsed = parse(CLIENT_USAGE, &[
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
