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

//! Configuration for the h3i client.

use std::io;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use url::Position;
use url::Url;

/// The logical HTTP authority and optional transport address override.
#[derive(Clone)]
pub struct Endpoint {
    url: Url,
    pub connect_to: Option<SocketAddr>,
    pub source_port: u16,
}

impl Endpoint {
    /// Parse a hostname, IPv4 address or bracketed IPv6 address, optionally
    /// followed by a port. HTTPS's default port is 443.
    ///
    /// # Errors
    /// Returns invalid input if the authority is malformed.
    pub fn new(authority: &str) -> io::Result<Self> {
        if authority.is_empty() ||
            authority.chars().any(|character| {
                character.is_control() ||
                    character.is_whitespace() ||
                    matches!(character, '/' | '?' | '#' | '@' | '\\')
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid server authority",
            ));
        }
        let url =
            Url::parse(&format!("https://{authority}")).map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidInput, error)
            })?;
        if url.host().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing server host",
            ));
        }
        Ok(Self {
            url,
            connect_to: None,
            source_port: 0,
        })
    }

    /// Canonical HTTP authority for request construction.
    #[must_use = "the authority identifies the HTTP origin"]
    pub fn authority(&self) -> &str {
        &self.url[Position::BeforeHost..Position::AfterPort]
    }

    /// Hostname without the port or IPv6 brackets.
    #[must_use = "the hostname is used for TLS identity"]
    pub fn host(&self) -> &str {
        self.url
            .host_str()
            .unwrap_or_default()
            .trim_matches(['[', ']'])
    }

    /// Resolve the peer and a compatible wildcard bind address.
    ///
    /// # Errors
    /// Returns address resolution errors or an empty DNS result.
    pub fn socket_addresses(&self) -> io::Result<(SocketAddr, SocketAddr)> {
        let peer = self.connect_to.map_or_else(
            || {
                self.url
                    .socket_addrs(|| None)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::AddrNotAvailable,
                            "no addresses for server",
                        )
                    })
            },
            Ok,
        )?;
        let ip = if peer.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        };
        Ok((peer, SocketAddr::new(ip, self.source_port)))
    }
}

/// TLS identity, verification and early-data policy.
#[derive(Clone)]
pub struct TlsSettings {
    pub omit_sni: bool,
    pub verify_peer: bool,
    pub early_data: bool,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            omit_sni: false,
            verify_peer: true,
            early_data: false,
        }
    }
}

/// Initial flow-control limits and receive window ceilings.
#[derive(Clone)]
pub struct FlowControl {
    pub max_data: u64,
    pub max_stream_data_bidi_local: u64,
    pub max_stream_data_bidi_remote: u64,
    pub max_stream_data_uni: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub max_window: u64,
    pub max_stream_window: u64,
}

impl Default for FlowControl {
    fn default() -> Self {
        Self {
            max_data: 10_000_000,
            max_stream_data_bidi_local: 1_000_000,
            max_stream_data_bidi_remote: 1_000_000,
            max_stream_data_uni: 1_000_000,
            max_streams_bidi: 100,
            max_streams_uni: 100,
            max_window: 25_165_824,
            max_stream_window: 16_777_216,
        }
    }
}

/// Queue limits for enabled QUIC DATAGRAM support.
#[derive(Clone)]
pub struct DatagramQueues {
    pub receive: usize,
    pub send: usize,
}

impl Default for DatagramQueues {
    fn default() -> Self {
        Self {
            receive: 65_536,
            send: 65_536,
        }
    }
}

/// Server details and QUIC connection properties.
#[derive(Clone)]
pub struct Config {
    pub endpoint: Endpoint,
    pub tls: TlsSettings,
    /// Idle timeout in milliseconds.
    pub idle_timeout: u64,
    /// Multiplier applied to the connection's send capacity.
    pub send_capacity_factor: f64,
    pub flow: FlowControl,
    /// Serialized session for resumption.
    pub session: Option<Vec<u8>>,
    /// Datagram support is enabled when queues are supplied.
    pub datagrams: Option<DatagramQueues>,
}

impl Config {
    /// Construct a configuration for a valid authority using the same defaults
    /// as the command line.
    ///
    /// # Errors
    /// Returns invalid input if the server authority is malformed.
    pub fn new(authority: &str) -> io::Result<Self> {
        Ok(Self {
            endpoint: Endpoint::new(authority)?,
            tls: TlsSettings::default(),
            idle_timeout: 5_000,
            send_capacity_factor: 1.0,
            flow: FlowControl::default(),
            session: None,
            datagrams: None,
        })
    }

    /// Validate mutable transport settings before opening a socket.
    ///
    /// # Errors
    /// Returns invalid input for a non-finite or negative capacity factor.
    pub fn validate(&self) -> io::Result<()> {
        if !self.send_capacity_factor.is_finite() ||
            self.send_capacity_factor < 0.0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "send capacity factor must be finite and nonnegative",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use super::DatagramQueues;
    use super::Endpoint;

    #[test]
    fn authority_and_transport_override_are_independent() -> std::io::Result<()> {
        let mut endpoint = Endpoint::new("example.org:8443")?;
        endpoint.connect_to =
            Some("[::1]:4433".parse().map_err(std::io::Error::other)?);
        endpoint.source_port = 12_345;
        let (peer, bind) = endpoint.socket_addresses()?;
        assert_eq!(endpoint.authority(), "example.org:8443");
        assert_eq!(endpoint.host(), "example.org");
        assert_eq!(peer.to_string(), "[::1]:4433");
        assert_eq!(bind.to_string(), "[::]:12345");
        for (authority, host, port) in
            [("127.0.0.1", "127.0.0.1", 443), ("[::1]:8443", "::1", 8443)]
        {
            let endpoint = Endpoint::new(authority)?;
            assert_eq!(endpoint.host(), host);
            assert_eq!(endpoint.socket_addresses()?.0.port(), port);
        }
        Ok(())
    }

    #[test]
    fn invalid_authorities_and_capacity_factors_return_errors(
    ) -> std::io::Result<()> {
        for authority in [
            "",
            "https://example.org",
            "example.org/path",
            "a@b",
            "example.org:65536",
            "[::1",
            "a b",
        ] {
            assert!(Endpoint::new(authority).is_err(), "{authority}");
        }
        let mut config = Config::new("example.org")?;
        for factor in [f64::NAN, f64::INFINITY, -1.0] {
            config.send_capacity_factor = factor;
            assert!(config.validate().is_err());
        }
        config.send_capacity_factor = 0.0;
        config.validate()?;
        config.session = Some(vec![1, 2, 3]);
        config.datagrams = Some(DatagramQueues::default());
        assert_eq!(config.clone().session, Some(vec![1, 2, 3]));
        Ok(())
    }
}
