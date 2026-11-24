// Copyright (C) 2018-2019, Cloudflare, Inc.
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

//! 🥧 Savoury implementation of the QUIC transport protocol and HTTP/3.
//!
//! [quiche] is an implementation of the QUIC transport protocol and HTTP/3 as
//! specified by the [IETF]. It provides a low level API for processing QUIC
//! packets and handling connection state. The application is responsible for
//! providing I/O (e.g. sockets handling) as well as an event loop with support
//! for timers.
//!
//! [quiche]: https://github.com/cloudflare/quiche/
//! [ietf]: https://quicwg.org/
//!
//! ## Configuring connections
//!
//! The first step in establishing a QUIC connection using quiche is creating a
//! [`Config`] object:
//!
//! ```
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! config.set_application_protos(&[b"example-proto"]);
//!
//! // Additional configuration specific to application and use case...
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The [`Config`] object controls important aspects of the QUIC connection such
//! as QUIC version, ALPN IDs, flow control, congestion control, idle timeout
//! and other properties or features.
//!
//! QUIC is a general-purpose transport protocol and there are several
//! configuration properties where there is no reasonable default value. For
//! example, the permitted number of concurrent streams of any particular type
//! is dependent on the application running over QUIC, and other use-case
//! specific concerns.
//!
//! quiche defaults several properties to zero, applications most likely need
//! to set these to something else to satisfy their needs using the following:
//!
//! - [`set_initial_max_streams_bidi()`]
//! - [`set_initial_max_streams_uni()`]
//! - [`set_initial_max_data()`]
//! - [`set_initial_max_stream_data_bidi_local()`]
//! - [`set_initial_max_stream_data_bidi_remote()`]
//! - [`set_initial_max_stream_data_uni()`]
//!
//! [`Config`] also holds TLS configuration. This can be changed by mutators on
//! the an existing object, or by constructing a TLS context manually and
//! creating a configuration using [`with_btls_ssl_ctx_builder()`].
//!
//! A configuration object can be shared among multiple connections.
//!
//! ### Connection setup
//!
//! On the client-side the [`connect()`] utility function can be used to create
//! a new connection, while [`accept()`] is for servers:
//!
//! ```
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let server_name = "quic.tech";
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! // Client connection.
//! let conn =
//!     quiche::connect(Some(&server_name), &scid, local, peer, &mut config)?;
//!
//! // Server connection.
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! let conn = quiche::accept(&scid, None, local, peer, &mut config)?;
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! In both cases, the application is responsible for generating a new source
//! connection ID that will be used to identify the new connection.
//!
//! The application also need to pass the address of the remote peer of the
//! connection: in the case of a client that would be the address of the server
//! it is trying to connect to, and for a server that is the address of the
//! client that initiated the connection.
//!
//! ## Handling incoming packets
//!
//! Using the connection's [`recv()`] method the application can process
//! incoming packets that belong to that connection from the network:
//!
//! ```no_run
//! # let mut buf = [0; 512];
//! # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
//! let to = socket.local_addr().unwrap();
//!
//! loop {
//!     let (read, from) = socket.recv_from(&mut buf).unwrap();
//!
//!     let recv_info = quiche::RecvInfo { from, to };
//!
//!     let read = match conn.recv(&mut buf[..read], recv_info) {
//!         Ok(v) => v,
//!
//!         Err(quiche::Error::Done) => {
//!             // Done reading.
//!             break;
//!         },
//!
//!         Err(e) => {
//!             // An error occurred, handle it.
//!             break;
//!         },
//!     };
//! }
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The application has to pass a [`RecvInfo`] structure in order to provide
//! additional information about the received packet (such as the address it
//! was received from).
//!
//! ## Generating outgoing packets
//!
//! Outgoing packet are generated using the connection's [`send()`] method
//! instead:
//!
//! ```no_run
//! # let mut out = [0; 512];
//! # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
//! loop {
//!     let (write, send_info) = match conn.send(&mut out) {
//!         Ok(v) => v,
//!
//!         Err(quiche::Error::Done) => {
//!             // Done writing.
//!             break;
//!         },
//!
//!         Err(e) => {
//!             // An error occurred, handle it.
//!             break;
//!         },
//!     };
//!
//!     socket.send_to(&out[..write], &send_info.to).unwrap();
//! }
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The application will be provided with a [`SendInfo`] structure providing
//! additional information about the newly created packet (such as the address
//! the packet should be sent to).
//!
//! When packets are sent, the application is responsible for maintaining a
//! timer to react to time-based connection events. The timer expiration can be
//! obtained using the connection's [`timeout()`] method.
//!
//! ```
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
//! let timeout = conn.timeout();
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The application is responsible for providing a timer implementation, which
//! can be specific to the operating system or networking framework used. When
//! a timer expires, the connection's [`on_timeout()`] method should be called,
//! after which additional packets might need to be sent on the network:
//!
//! ```no_run
//! # let mut out = [0; 512];
//! # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
//! // Timeout expired, handle it.
//! conn.on_timeout();
//!
//! // Send more packets as needed after timeout.
//! loop {
//!     let (write, send_info) = match conn.send(&mut out) {
//!         Ok(v) => v,
//!
//!         Err(quiche::Error::Done) => {
//!             // Done writing.
//!             break;
//!         },
//!
//!         Err(e) => {
//!             // An error occurred, handle it.
//!             break;
//!         },
//!     };
//!
//!     socket.send_to(&out[..write], &send_info.to).unwrap();
//! }
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! ### Pacing
//!
//! It is recommended that applications [pace] sending of outgoing packets to
//! avoid creating packet bursts that could cause short-term congestion and
//! losses in the network.
//!
//! quiche exposes pacing hints for outgoing packets through the [`at`] field
//! of the [`SendInfo`] structure that is returned by the [`send()`] method.
//! This field represents the time when a specific packet should be sent into
//! the network.
//!
//! Applications can use these hints by artificially delaying the sending of
//! packets through platform-specific mechanisms (such as the [`SO_TXTIME`]
//! socket option on Linux), or custom methods (for example by using user-space
//! timers).
//!
//! [pace]: https://datatracker.ietf.org/doc/html/rfc9002#section-7.7
//! [`SO_TXTIME`]: https://man7.org/linux/man-pages/man8/tc-etf.8.html
//!
//! ## Sending and receiving stream data
//!
//! After some back and forth, the connection will complete its handshake and
//! will be ready for sending or receiving application data.
//!
//! Data can be sent on a stream by using the [`stream_send()`] method:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
//! if conn.is_established() {
//!     // Handshake completed, send some data on stream 0.
//!     conn.stream_send(0, b"hello", true)?;
//! }
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The application can check whether there are any readable streams by using
//! the connection's [`readable()`] method, which returns an iterator over all
//! the streams that have outstanding data to read.
//!
//! The [`stream_recv()`] method can then be used to retrieve the application
//! data from the readable stream:
//!
//! ```no_run
//! # let mut buf = [0; 512];
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
//! if conn.is_established() {
//!     // Iterate over readable streams.
//!     for stream_id in conn.readable() {
//!         // Stream is readable, read until there's no more data.
//!         while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut buf) {
//!             println!("Got {} bytes on stream {}", read, stream_id);
//!         }
//!     }
//! }
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! ## HTTP/3
//!
//! The quiche [HTTP/3 module] provides a high level API for sending and
//! receiving HTTP requests and responses on top of the QUIC transport protocol.
//!
//! [`Config`]: https://docs.quic.tech/quiche/struct.Config.html
//! [`set_initial_max_streams_bidi()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_streams_bidi
//! [`set_initial_max_streams_uni()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_streams_uni
//! [`set_initial_max_data()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_data
//! [`set_initial_max_stream_data_bidi_local()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_stream_data_bidi_local
//! [`set_initial_max_stream_data_bidi_remote()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_stream_data_bidi_remote
//! [`set_initial_max_stream_data_uni()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_stream_data_uni
//! [`with_btls_ssl_ctx_builder()`]: https://docs.quic.tech/quiche/struct.Config.html#method.with_btls_ssl_ctx_builder
//! [`connect()`]: fn.connect.html
//! [`accept()`]: fn.accept.html
//! [`recv()`]: struct.Connection.html#method.recv
//! [`RecvInfo`]: struct.RecvInfo.html
//! [`send()`]: struct.Connection.html#method.send
//! [`SendInfo`]: struct.SendInfo.html
//! [`at`]: struct.SendInfo.html#structfield.at
//! [`timeout()`]: struct.Connection.html#method.timeout
//! [`on_timeout()`]: struct.Connection.html#method.on_timeout
//! [`stream_send()`]: struct.Connection.html#method.stream_send
//! [`readable()`]: struct.Connection.html#method.readable
//! [`stream_recv()`]: struct.Connection.html#method.stream_recv
//! [HTTP/3 module]: h3/index.html
//!
//! ## Congestion Control
//!
//! The quiche library provides a high-level API for configuring which
//! congestion control algorithm to use throughout the QUIC connection.
//!
//! When a QUIC connection is created, the application can optionally choose
//! which CC algorithm to use. See [`CongestionControlAlgorithm`] for currently
//! available congestion control algorithms.
//!
//! For example:
//!
//! ```
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! config.set_cc_algorithm(quiche::CongestionControlAlgorithm::Reno);
//! ```
//!
//! Alternatively, you can configure the congestion control algorithm to use
//! by its name.
//!
//! ```
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! config.set_cc_algorithm_name("reno").unwrap();
//! ```
//!
//! Note that the CC algorithm should be configured before calling [`connect()`]
//! or [`accept()`]. Otherwise the connection will use a default CC algorithm.
//!
//! [`CongestionControlAlgorithm`]: enum.CongestionControlAlgorithm.html
//!
//! ## Feature flags
//!
//! quiche defines a number of [feature flags] to reduce the amount of compiled
//! code and dependencies:
//!
//! * `boringssl-btls-crate` (default): Use the `BoringSSL` library provided by
//!   the [btls] crate.
//!
//! * `pkg-config-meta`: Generate pkg-config metadata file for libquiche.
//!
//! * `ffi`: Build and expose the FFI API.
//!
//! * `qlog`: Enable support for the [qlog] logging format.
//!
//! * `custom-client-dcid`: Allow clients to supply a custom DCID when
//!   initiating a connection. Dangerous if the DCID does not meet QUIC's
//!   unpredictability and length requirements.
//!
//! [feature flags]: https://doc.rust-lang.org/cargo/reference/manifest.html#the-features-section
//! [btls]: https://github.com/codeandsolder/btls-fast
//! [qlog]: https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema

#![deny(missing_docs)]
#![deny(unused_qualifications)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[macro_use]
extern crate log;

use std::cmp;

use std::collections::VecDeque;

use std::net::SocketAddr;

use std::str::FromStr;

use std::sync::Arc;

use std::time::Duration;
use std::time::Instant;

#[cfg(feature = "qlog")]
use qlog::events::quic::DataMovedAdditionalInfo;
#[cfg(feature = "qlog")]
use qlog::events::quic::QuicEventType;
#[cfg(feature = "qlog")]
use qlog::events::quic::TransportInitiator;
#[cfg(feature = "qlog")]
use qlog::events::DataRecipient;
#[cfg(feature = "qlog")]
use qlog::events::Event;
#[cfg(feature = "qlog")]
use qlog::events::EventData;
#[cfg(feature = "qlog")]
use qlog::events::EventImportance;
#[cfg(feature = "qlog")]
use qlog::events::EventType;
#[cfg(feature = "qlog")]
use qlog::events::RawInfo;

use smallvec::SmallVec;

use crate::buffers::DefaultBufFactory;

use crate::recovery::OnAckReceivedOutcome;
use crate::recovery::OnLossDetectionTimeoutOutcome;
use crate::recovery::RecoveryOps;
use crate::recovery::ReleaseDecision;

use crate::stream::RecvAction;

/// The current QUIC wire version.
pub const PROTOCOL_VERSION: u32 = PROTOCOL_VERSION_V1;

/// Supported QUIC versions.
const PROTOCOL_VERSION_V1: u32 = 0x0000_0001;

/// The maximum length of a connection ID.
pub const MAX_CONN_ID_LEN: usize = packet::MAX_CID_LEN as usize;

/// The minimum length of Initial packets sent by a client.
pub const MIN_CLIENT_INITIAL_LEN: usize = 1200;

/// The default initial RTT.
const DEFAULT_INITIAL_RTT: Duration = Duration::from_millis(333);

const PAYLOAD_MIN_LEN: usize = 4;

// PATH_CHALLENGE (9 bytes) + AEAD tag (16 bytes).
const MIN_PROBING_SIZE: usize = 25;

const MAX_AMPLIFICATION_FACTOR: usize = 3;

// The maximum number of tracked packet number ranges that need to be acked.
//
// This represents more or less how many ack blocks can fit in a typical packet.
const MAX_ACK_RANGES: usize = 68;

// The maximum stream count per stream type (the ID uses two type bits).
const MAX_STREAM_COUNT: u64 = 1 << 60;

// The default max_datagram_size used in congestion control.
const DEFAULT_SEND_UDP_PAYLOAD_SIZE: usize = MIN_CLIENT_INITIAL_LEN;

// Maximum non-jumbogram UDP payload (RFC 9000 default receive limit).
const MAX_SEND_UDP_PAYLOAD_SIZE: usize = 65_527;

// The default length of DATAGRAM queues.
const DEFAULT_MAX_DGRAM_QUEUE_LEN: usize = 0;

// The default length of PATH_CHALLENGE receive queue.
const DEFAULT_MAX_PATH_CHALLENGE_RX_QUEUE_LEN: usize = 3;

// The DATAGRAM standard recommends either none or 65536 as maximum DATAGRAM
// frames size. We enforce the recommendation for forward compatibility.
const MAX_DGRAM_FRAME_SIZE: u64 = 65536;

// The number of undecryptable that can be buffered.
const MAX_UNDECRYPTABLE_PACKETS: usize = 10;

const RESERVED_VERSION_MASK: u32 = 0xfafafafa;

// The maximum size of the receiver connection flow control window.
const MAX_CONNECTION_WINDOW: u64 = 24 * 1024 * 1024;

// How many probing packet timeouts do we tolerate before considering the path
// validation as failed.
const MAX_PROBING_TIMEOUTS: usize = 3;

// The default initial congestion window size in terms of packet count.
const DEFAULT_INITIAL_CONGESTION_WINDOW_PACKETS: usize = 10;

// The maximum data offset that can be stored in a crypto stream.
const MAX_CRYPTO_STREAM_OFFSET: u64 = 1 << 16;

// TODO: Remove once https://github.com/cloudflare/quiche/pull/2453 is done.
// Preserve the previous app-limited threshold independently of STREAM frame
// header sizing.
const LEGACY_APP_LIMITED_BYTE_THRESHOLD: usize = 12;

// The send capacity factor.
const TX_CAP_FACTOR: f64 = 1.0;

/// Ancillary information about incoming packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvInfo {
    /// The remote address the packet was received from.
    pub from: SocketAddr,

    /// The local address the packet was received on.
    pub to: SocketAddr,
}

/// Ancillary information about outgoing packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendInfo {
    /// The local address the packet should be sent from.
    pub from: SocketAddr,

    /// The remote address the packet should be sent to.
    pub to: SocketAddr,

    /// The time to send the packet out.
    ///
    /// See [Pacing] for more details.
    ///
    /// [Pacing]: index.html#pacing
    pub at: Instant,
}

/// The side of the stream to be shut down.
///
/// This should be used when calling [`stream_shutdown()`].
///
/// [`stream_shutdown()`]: struct.Connection.html#method.stream_shutdown
#[repr(C)]
#[derive(PartialEq, Eq)]
pub enum Shutdown {
    /// Stop receiving stream data.
    Read  = 0,

    /// Stop sending stream data.
    Write = 1,
}

/// Qlog logging level.
#[repr(C)]
#[cfg(feature = "qlog")]
#[cfg_attr(docsrs, doc(cfg(feature = "qlog")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QlogLevel {
    /// Logs any events of Core importance.
    Core  = 0,

    /// Logs any events of Core and Base importance.
    Base  = 1,

    /// Logs any events of Core, Base and Extra importance
    Extra = 2,
}

/// Stores configuration shared between multiple connections.
pub struct Config {
    local_transport_params: TransportParams,

    version: u32,

    tls_ctx: tls::Context,

    application_protos: Vec<Vec<u8>>,

    grease: bool,

    cc_algorithm: CongestionControlAlgorithm,
    custom_bbr_params: Option<BbrParams>,
    initial_congestion_window_packets: usize,
    enable_relaxed_loss_threshold: bool,
    enable_send_streams_blocked: bool,

    pmtud: bool,
    pmtud_max_probes: u8,

    hystart: bool,

    pacing: bool,
    /// Send rate limit in Mbps
    max_pacing_rate: Option<u64>,

    tx_cap_factor: f64,

    dgram_recv_max_queue_len: usize,
    dgram_send_max_queue_len: usize,

    path_challenge_recv_max_queue_len: usize,

    max_send_udp_payload_size: usize,

    max_connection_window: u64,
    max_stream_window: u64,

    max_amplification_factor: usize,

    disable_dcid_reuse: bool,

    track_unknown_transport_params: Option<usize>,

    initial_rtt: Duration,
}

// See https://quicwg.org/base-drafts/rfc9000.html#section-15
const fn is_reserved_version(version: u32) -> bool {
    version & RESERVED_VERSION_MASK == version
}

impl Config {
    /// Creates a config object with the given version.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnknownVersion` for an unsupported, non-reserved
    /// version, or a TLS error if the TLS context cannot be initialized.
    ///
    /// ## Examples:
    ///
    /// ```
    /// let config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn new(version: u32) -> Result<Self> {
        Self::with_tls_ctx(version, tls::Context::new()?)
    }

    /// Creates a config object with the given version and
    /// [`SslContextBuilder`].
    ///
    /// This is useful for applications that wish to manually configure
    /// [`SslContextBuilder`].
    ///
    /// # Errors
    ///
    /// Returns `Error::UnknownVersion` for an unsupported, non-reserved
    /// version, or `Error::TlsFail` if the TLS context cannot be created.
    ///
    /// [`SslContextBuilder`]: https://docs.rs/boring/latest/boring/ssl/struct.SslContextBuilder.html
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn with_btls_ssl_ctx_builder(
        version: u32, tls_ctx_builder: btls::ssl::SslContextBuilder,
    ) -> Result<Self> {
        Self::with_tls_ctx(version, tls::Context::from_boring(tls_ctx_builder)?)
    }

    fn with_tls_ctx(version: u32, tls_ctx: tls::Context) -> Result<Self> {
        if !is_reserved_version(version) && !version_is_supported(version) {
            return Err(Error::UnknownVersion);
        }

        Ok(Self {
            local_transport_params: TransportParams::default(),
            version,
            tls_ctx,
            application_protos: Vec::new(),
            grease: true,
            cc_algorithm: CongestionControlAlgorithm::Cubic,
            custom_bbr_params: None,
            initial_congestion_window_packets:
                DEFAULT_INITIAL_CONGESTION_WINDOW_PACKETS,
            enable_relaxed_loss_threshold: false,
            enable_send_streams_blocked: false,
            pmtud: false,
            pmtud_max_probes: pmtud::MAX_PROBES_DEFAULT,
            hystart: true,
            pacing: true,
            max_pacing_rate: None,

            tx_cap_factor: TX_CAP_FACTOR,

            dgram_recv_max_queue_len: DEFAULT_MAX_DGRAM_QUEUE_LEN,
            dgram_send_max_queue_len: DEFAULT_MAX_DGRAM_QUEUE_LEN,

            path_challenge_recv_max_queue_len:
                DEFAULT_MAX_PATH_CHALLENGE_RX_QUEUE_LEN,

            max_send_udp_payload_size: DEFAULT_SEND_UDP_PAYLOAD_SIZE,

            max_connection_window: MAX_CONNECTION_WINDOW,
            max_stream_window: stream::MAX_STREAM_WINDOW,

            max_amplification_factor: MAX_AMPLIFICATION_FACTOR,

            disable_dcid_reuse: false,

            track_unknown_transport_params: None,
            initial_rtt: DEFAULT_INITIAL_RTT,
        })
    }

    /// Configures the given certificate chain.
    ///
    /// The content of `file` is parsed as a PEM-encoded leaf certificate,
    /// followed by optional intermediate certificates.
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the path contains a NUL byte or the TLS
    /// backend cannot load the certificate chain.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.load_cert_chain_from_pem_file("/path/to/cert.pem")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn load_cert_chain_from_pem_file(&mut self, file: &str) -> Result<()> {
        self.tls_ctx.use_certificate_chain_file(file)
    }

    /// Configures the given private key.
    ///
    /// The content of `file` is parsed as a PEM-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the path contains a NUL byte or the TLS
    /// backend cannot load the private key.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.load_priv_key_from_pem_file("/path/to/key.pem")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn load_priv_key_from_pem_file(&mut self, file: &str) -> Result<()> {
        self.tls_ctx.use_privkey_file(file)
    }

    /// Specifies a file where trusted CA certificates are stored for the
    /// purposes of certificate verification.
    ///
    /// The content of `file` is parsed as a PEM-encoded certificate chain.
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the path contains a NUL byte or the TLS
    /// backend cannot load the trust store file.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.load_verify_locations_from_file("/path/to/cert.pem")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        self.tls_ctx.load_verify_locations_from_file(file)
    }

    /// Specifies a directory where trusted CA certificates are stored for the
    /// purposes of certificate verification.
    ///
    /// The content of `dir` a set of PEM-encoded certificate chains.
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the path contains a NUL byte or the TLS
    /// backend rejects the trust store directory.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.load_verify_locations_from_directory("/path/to/certs")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn load_verify_locations_from_directory(
        &mut self, dir: &str,
    ) -> Result<()> {
        self.tls_ctx.load_verify_locations_from_directory(dir)
    }

    /// Configures the TLS curve preference list.
    ///
    /// `curves` is a colon-separated list of curve (a.k.a. group) names, in
    /// order of preference, e.g. `"X25519MLKEM768:X25519:P-256:P-384"`.
    /// Corresponds to `SSL_CTX_set1_curves_list` (a.k.a.
    /// `SSL_CTX_set1_groups_list`).
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the list contains a NUL byte or is rejected
    /// by the TLS backend.
    pub fn set_curves_list(&mut self, curves: &str) -> Result<()> {
        self.tls_ctx.set_curves_list(curves)
    }

    /// Configures whether to verify the peer's certificate.
    ///
    /// This should usually be `true` for client-side connections and `false`
    /// for server-side ones.
    ///
    /// Note that by default, no verification is performed.
    ///
    /// Also note that on the server-side, enabling verification of the peer
    /// will trigger a certificate request and make authentication errors
    /// fatal, but will still allow anonymous clients (i.e. clients that
    /// don't present a certificate at all). Servers can check whether a
    /// client presented a certificate by calling [`peer_cert()`] if they
    /// need to.
    ///
    /// [`peer_cert()`]: struct.Connection.html#method.peer_cert
    pub fn verify_peer(&mut self, verify: bool) {
        self.tls_ctx.set_verify(verify);
    }

    /// Configures whether to do path MTU discovery.
    ///
    /// PMTUD-driven packet limit updates are reported to the application
    /// through [`PathEvent::PmtuUpdated`].
    ///
    /// The default value is `false`.
    pub const fn discover_pmtu(&mut self, discover: bool) {
        self.pmtud = discover;
    }

    /// Configures the maximum number of PMTUD probe attempts before treating
    /// a probe size as failed.
    ///
    /// Defaults to 3 per [RFC 8899 Section 5.1.2](https://datatracker.ietf.org/doc/html/rfc8899#section-5.1.2).
    /// If 0 is passed, the default value is used.
    pub const fn set_pmtud_max_probes(&mut self, max_probes: u8) {
        self.pmtud_max_probes = max_probes;
    }

    /// Configures whether to send GREASE values.
    ///
    /// The default value is `true`.
    pub const fn grease(&mut self, grease: bool) {
        self.grease = grease;
    }

    /// Enables logging of secrets.
    ///
    /// When logging is enabled, the [`set_keylog()`] method must be called on
    /// the connection for its cryptographic secrets to be logged in the
    /// [keylog] format to the specified writer.
    ///
    /// [`set_keylog()`]: struct.Connection.html#method.set_keylog
    /// [keylog]: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
    pub fn log_keys(&mut self) {
        self.tls_ctx.enable_keylog();
    }

    /// Configures the session ticket key material.
    ///
    /// On the server this key will be used to encrypt and decrypt session
    /// tickets, used to perform session resumption without server-side state.
    ///
    /// By default a key is generated internally, and rotated regularly, so
    /// applications don't need to call this unless they need to use a
    /// specific key (e.g. in order to support resumption across multiple
    /// servers), in which case the application is also responsible for
    /// rotating the key to provide forward secrecy.
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS backend rejects the supplied key
    /// material, for example because its length is incorrect.
    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        self.tls_ctx.set_ticket_key(key)
    }

    /// Enables sending or receiving early data.
    pub fn enable_early_data(&mut self) {
        self.tls_ctx.set_early_data_enabled(true);
    }

    /// Configures the list of supported application protocols.
    ///
    /// On the client this configures the list of protocols to send to the
    /// server as part of the ALPN extension.
    ///
    /// On the server this configures the list of supported protocols to match
    /// against the client-supplied list.
    ///
    /// Applications must set a value, but no default is provided.
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the list is empty, a protocol name is empty
    /// or exceeds 255 bytes, the encoded list exceeds the extension's size
    /// limit, or the TLS backend rejects the list.
    ///
    /// ## Examples:
    ///
    /// ```
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.set_application_protos(&[b"http/1.1", b"http/0.9"])?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn set_application_protos(
        &mut self, protos_list: &[&[u8]],
    ) -> Result<()> {
        self.tls_ctx.set_alpn(protos_list)?;
        self.application_protos =
            protos_list.iter().map(|s| s.to_vec()).collect();
        Ok(())
    }

    /// Configures the list of supported application protocols using wire
    /// format.
    ///
    /// The list of protocols `protos` must be a series of non-empty, 8-bit
    /// length-prefixed strings.
    ///
    /// See [`set_application_protos`](Self::set_application_protos) for more
    /// background about application protocols.
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the wire-format list is truncated or
    /// invalid, or if the decoded protocols are rejected by
    /// [`Config::set_application_protos`].
    ///
    /// ## Examples:
    ///
    /// ```
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.set_application_protos_wire_format(b"\x08http/1.1\x08http/0.9")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn set_application_protos_wire_format(
        &mut self, protos: &[u8],
    ) -> Result<()> {
        let mut b = octets::Octets::with_slice(protos);

        let mut protos_list = Vec::new();

        while b.cap() > 0 {
            let proto =
                b.get_bytes_with_u8_length().map_err(|_| Error::TlsFail)?;
            protos_list.push(proto.buf());
        }

        self.set_application_protos(&protos_list)
    }

    /// Sets the anti-amplification limit factor.
    ///
    /// The default value is `3`.
    pub const fn set_max_amplification_factor(&mut self, v: usize) {
        self.max_amplification_factor = v;
    }

    /// Sets the send capacity factor.
    ///
    /// Values above one allow buffering beyond the congestion window, but
    /// cannot increase the peer's connection-level flow-control credit.
    /// The default value is `1`.
    pub const fn set_send_capacity_factor(&mut self, v: f64) {
        self.tx_cap_factor = v;
    }

    /// Sets the connection's initial RTT.
    ///
    /// The default value is `333`.
    pub const fn set_initial_rtt(&mut self, v: Duration) {
        self.initial_rtt = v;
    }

    /// Sets the `max_idle_timeout` transport parameter, in milliseconds.
    ///
    /// The default value is infinite, that is, no timeout is used.
    pub fn set_max_idle_timeout(&mut self, v: u64) {
        self.local_transport_params.max_idle_timeout =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `max_udp_payload_size` transport parameter.
    ///
    /// Values below 1200 are raised to the QUIC minimum.
    /// The default value is `65527`.
    pub fn set_max_recv_udp_payload_size(&mut self, v: usize) {
        self.local_transport_params.max_udp_payload_size = (v as u64)
            .clamp(transport_params::MIN_UDP_PAYLOAD_SIZE, octets::MAX_VAR_INT);
    }

    /// Sets the maximum outgoing UDP payload size.
    ///
    /// The default and minimum value is `1200`; the maximum is `65527`.
    pub fn set_max_send_udp_payload_size(&mut self, v: usize) {
        self.max_send_udp_payload_size =
            v.clamp(MIN_CLIENT_INITIAL_LEN, MAX_SEND_UDP_PAYLOAD_SIZE);
    }

    /// Sets the `initial_max_data` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes of
    /// incoming stream data to be buffered for the whole connection (that is,
    /// data that is not yet read by the application) and will allow more data
    /// to be received as the buffer is consumed by the application.
    ///
    /// When set to zero, either explicitly or via the default, quiche will not
    /// give any flow control to the peer, preventing it from sending any stream
    /// data.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_data(&mut self, v: u64) {
        self.local_transport_params.initial_max_data =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `initial_max_stream_data_bidi_local` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for each locally-initiated
    /// bidirectional stream (that is, data that is not yet read by the
    /// application) and will allow more data to be received as the buffer is
    /// consumed by the application.
    ///
    /// When set to zero, either explicitly or via the default, quiche will not
    /// give any flow control to the peer, preventing it from sending any stream
    /// data.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_stream_data_bidi_local(&mut self, v: u64) {
        self.local_transport_params
            .initial_max_stream_data_bidi_local =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `initial_max_stream_data_bidi_remote` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for each remotely-initiated
    /// bidirectional stream (that is, data that is not yet read by the
    /// application) and will allow more data to be received as the buffer is
    /// consumed by the application.
    ///
    /// When set to zero, either explicitly or via the default, quiche will not
    /// give any flow control to the peer, preventing it from sending any stream
    /// data.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_stream_data_bidi_remote(&mut self, v: u64) {
        self.local_transport_params
            .initial_max_stream_data_bidi_remote =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `initial_max_stream_data_uni` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow at most `v` bytes
    /// of incoming stream data to be buffered for each unidirectional stream
    /// (that is, data that is not yet read by the application) and will allow
    /// more data to be received as the buffer is consumed by the application.
    ///
    /// When set to zero, either explicitly or via the default, quiche will not
    /// give any flow control to the peer, preventing it from sending any stream
    /// data.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_stream_data_uni(&mut self, v: u64) {
        self.local_transport_params.initial_max_stream_data_uni =
            cmp::min(v, octets::MAX_VAR_INT);
    }

    /// Sets the `initial_max_streams_bidi` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow `v` number of
    /// concurrent remotely-initiated bidirectional streams to be open at any
    /// given time and will increase the limit automatically as streams are
    /// completed.
    ///
    /// When set to zero, either explicitly or via the default, quiche will not
    /// not allow the peer to open any bidirectional streams.
    ///
    /// A bidirectional stream is considered completed when all incoming data
    /// has been read by the application (up to the `fin` offset) or the
    /// stream's read direction has been shutdown, and all outgoing data has
    /// been acked by the peer (up to the `fin` offset) or the stream's write
    /// direction has been shutdown.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_streams_bidi(&mut self, v: u64) {
        self.local_transport_params.initial_max_streams_bidi =
            cmp::min(v, MAX_STREAM_COUNT);
    }

    /// Sets the `initial_max_streams_uni` transport parameter.
    ///
    /// When set to a non-zero value quiche will only allow `v` number of
    /// concurrent remotely-initiated unidirectional streams to be open at any
    /// given time and will increase the limit automatically as streams are
    /// completed.
    ///
    /// When set to zero, either explicitly or via the default, quiche will not
    /// not allow the peer to open any unidirectional streams.
    ///
    /// A unidirectional stream is considered completed when all incoming data
    /// has been read by the application (up to the `fin` offset) or the
    /// stream's read direction has been shutdown.
    ///
    /// The default value is `0`.
    pub fn set_initial_max_streams_uni(&mut self, v: u64) {
        self.local_transport_params.initial_max_streams_uni =
            cmp::min(v, MAX_STREAM_COUNT);
    }

    /// Sets the `ack_delay_exponent` transport parameter.
    ///
    /// Values above the RFC 9000 maximum of
    /// [`MAX_ACK_DELAY_EXPONENT`] (20) are clamped to that
    /// maximum.
    ///
    /// The default value is `3`.
    pub fn set_ack_delay_exponent(&mut self, v: u64) {
        self.local_transport_params.ack_delay_exponent =
            cmp::min(v, MAX_ACK_DELAY_EXPONENT);
    }

    /// Sets the `max_ack_delay` transport parameter.
    ///
    /// Values above 16383 milliseconds are clamped to that protocol maximum.
    /// The default value is `25`.
    pub fn set_max_ack_delay(&mut self, v: u64) {
        self.local_transport_params.max_ack_delay =
            cmp::min(v, transport_params::MAX_ACK_DELAY);
    }

    /// Sets the `active_connection_id_limit` transport parameter.
    ///
    /// The default value is `2`. Lower values will be ignored.
    pub fn set_active_connection_id_limit(&mut self, v: u64) {
        if v >= 2 {
            self.local_transport_params.active_conn_id_limit =
                cmp::min(v, octets::MAX_VAR_INT);
        }
    }

    /// Sets the `disable_active_migration` transport parameter.
    ///
    /// The default value is `false`.
    pub const fn set_disable_active_migration(&mut self, v: bool) {
        self.local_transport_params.disable_active_migration = v;
    }

    /// Sets the congestion control algorithm used.
    ///
    /// The default value is `CongestionControlAlgorithm::Cubic`.
    pub const fn set_cc_algorithm(&mut self, algo: CongestionControlAlgorithm) {
        self.cc_algorithm = algo;
    }

    /// Sets custom BBR settings.
    ///
    /// This API is experimental and will be removed in the future.
    ///
    /// Currently this only applies if cc_algorithm is
    /// `CongestionControlAlgorithm::Bbr2Gcongestion` is set.
    ///
    /// The default value is `None`.
    #[cfg(feature = "internal")]
    #[doc(hidden)]
    pub const fn set_custom_bbr_params(
        &mut self, custom_bbr_settings: BbrParams,
    ) {
        self.custom_bbr_params = Some(custom_bbr_settings);
    }

    /// Sets the congestion control algorithm used by string.
    ///
    /// The default value is `cubic`. On error `Error::CongestionControl`
    /// will be returned.
    ///
    /// # Errors
    ///
    /// Returns `Error::CongestionControl` if the algorithm name is unknown.
    ///
    /// ## Examples:
    ///
    /// ```
    /// # let mut config = quiche::Config::new(0xbabababa)?;
    /// config.set_cc_algorithm_name("reno")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn set_cc_algorithm_name(&mut self, name: &str) -> Result<()> {
        self.cc_algorithm = CongestionControlAlgorithm::from_str(name)?;

        Ok(())
    }

    /// Sets initial congestion window size in terms of packet count.
    ///
    /// The default value is 10.
    pub const fn set_initial_congestion_window_packets(
        &mut self, packets: usize,
    ) {
        self.initial_congestion_window_packets = packets;
    }

    /// Configure whether to enable relaxed loss detection on spurious loss.
    ///
    /// The default value is false.
    pub const fn set_enable_relaxed_loss_threshold(&mut self, enable: bool) {
        self.enable_relaxed_loss_threshold = enable;
    }

    /// Configure whether to enable sending `STREAMS_BLOCKED` frames.
    ///
    /// `STREAMS_BLOCKED` frames are an optional advisory signal in the QUIC
    /// protocol which SHOULD be sent when the sender wishes to open a stream
    /// but is unable to do so due to the maximum stream limit set by its peer.
    ///
    /// The default value is false.
    pub const fn set_enable_send_streams_blocked(&mut self, enable: bool) {
        self.enable_send_streams_blocked = enable;
    }

    /// Configures whether to enable `HyStart`++.
    ///
    /// The default value is `true`.
    pub const fn enable_hystart(&mut self, v: bool) {
        self.hystart = v;
    }

    /// Configures whether to enable pacing.
    ///
    /// The default value is `true`.
    pub const fn enable_pacing(&mut self, v: bool) {
        self.pacing = v;
    }

    /// Sets the max value for pacing rate.
    ///
    /// By default pacing rate is not limited.
    pub const fn set_max_pacing_rate(&mut self, v: u64) {
        self.max_pacing_rate = Some(v);
    }

    /// Configures whether to enable receiving DATAGRAM frames.
    ///
    /// When enabled, the `max_datagram_frame_size` transport parameter is set
    /// to 65536 as recommended by draft-ietf-quic-datagram-01.
    ///
    /// The default is `false`.
    pub const fn enable_dgram(
        &mut self, enabled: bool, recv_queue_len: usize, send_queue_len: usize,
    ) {
        self.local_transport_params.max_datagram_frame_size = if enabled {
            Some(MAX_DGRAM_FRAME_SIZE)
        } else {
            None
        };
        self.dgram_recv_max_queue_len = recv_queue_len;
        self.dgram_send_max_queue_len = send_queue_len;
    }

    /// Configures the max number of queued received `PATH_CHALLENGE` frames.
    ///
    /// When an endpoint receives a `PATH_CHALLENGE` frame and the queue is
    /// full, the frame is discarded.
    ///
    /// The default is 3.
    pub const fn set_path_challenge_recv_max_queue_len(
        &mut self, queue_len: usize,
    ) {
        self.path_challenge_recv_max_queue_len = queue_len;
    }

    /// Sets the maximum size of the connection window.
    ///
    /// The default value is `MAX_CONNECTION_WINDOW` (24MBytes).
    pub const fn set_max_connection_window(&mut self, v: u64) {
        self.max_connection_window = v;
    }

    /// Sets the maximum size of the stream window.
    ///
    /// The default value is `MAX_STREAM_WINDOW` (16MBytes).
    pub const fn set_max_stream_window(&mut self, v: u64) {
        self.max_stream_window = v;
    }

    /// Sets the initial stateless reset token.
    ///
    /// This value is only advertised by servers. Setting a stateless retry
    /// token as a client has no effect on the connection.
    ///
    /// The default value is `None`.
    pub const fn set_stateless_reset_token(&mut self, v: Option<u128>) {
        self.local_transport_params.stateless_reset_token = v;
    }

    /// Sets whether the QUIC connection should avoid reusing DCIDs over
    /// different paths.
    ///
    /// When set to `true`, it ensures that a destination Connection ID is never
    /// reused on different paths. Such behaviour may lead to connection stall
    /// if the peer performs a non-voluntary migration (e.g., NAT rebinding) and
    /// does not provide additional destination Connection IDs to handle such
    /// event.
    ///
    /// The default value is `false`.
    pub const fn set_disable_dcid_reuse(&mut self, v: bool) {
        self.disable_dcid_reuse = v;
    }

    /// Enables tracking unknown transport parameters.
    ///
    /// Specify the maximum number of bytes used to track unknown transport
    /// parameters. The size includes the identifier and its value. If storing a
    /// transport parameter would cause the limit to be exceeded, it is quietly
    /// dropped.
    ///
    /// The default is that the feature is disabled.
    pub const fn enable_track_unknown_transport_parameters(
        &mut self, size: usize,
    ) {
        self.track_unknown_transport_params = Some(size);
    }
}

/// Tracks the health of the `tx_buffered` value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TxBufferTrackingState {
    /// The send buffer is in a good state
    #[default]
    Ok,
    /// The send buffer is in an inconsistent state, which could lead to
    /// connection stalls or excess buffering due to bugs we haven't
    /// tracked down yet.
    Inconsistent,
}

/// Tracks if the connection hit the peer stream limit and which
/// `STREAMS_BLOCKED` frames have been sent.
#[derive(Default)]
struct StreamsBlockedState {
    /// The peer's `max_streams` limit at which we last became blocked on
    /// opening new local streams, if any.
    blocked_at: Option<u64>,

    /// The stream limit sent on the most recently sent `STREAMS_BLOCKED`
    /// frame. If != to `blocked_at`, the connection has pending
    /// `STREAMS_BLOCKED` frames to send.
    blocked_sent: Option<u64>,
}

impl StreamsBlockedState {
    /// Returns true if there is a `STREAMS_BLOCKED` frame that needs sending.
    fn has_pending_stream_blocked_frame(&self) -> bool {
        self.blocked_sent < self.blocked_at
    }

    /// Update the stream blocked limit.
    fn update_at(&mut self, limit: u64) {
        self.blocked_at = self.blocked_at.max(Some(limit));
    }

    /// Clear `blocked_sent` to force retransmission of the most recently sent
    /// `STREAMS_BLOCKED` frame.
    fn force_retransmit_sent_limit_eq(&mut self, limit: u64) {
        // Only clear blocked_sent if the lost frame had the most recently sent
        // limit.
        if self.blocked_sent == Some(limit) {
            self.blocked_sent = None;
        }
    }
}

/// Which side of a stream an incoming frame addresses.
#[derive(Clone, Copy)]
enum PeerStreamSide {
    Sending,
    Receiving,
}

/// Origin of an explicit connection close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloseOrigin {
    Local,
    Peer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloseCause {
    Explicit(CloseOrigin),
    IdleTimeout,
    StatelessReset,
    PacketNumbersExhausted,
    NoViablePath,
}

/// The endpoint cannot return to active processing after entering draining
/// or closed state. A closed endpoint retains its final cause, not a timer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ConnectionLifecycle {
    #[default]
    Active,
    Draining {
        deadline: Instant,
        origin: CloseOrigin,
    },
    Closed(CloseCause),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum HandshakeDoneState {
    #[default]
    Pending,
    InFlight,
    Acknowledged,
}

/// STREAM emission, including a pending stream that could not fit.
#[derive(Default)]
struct StreamPacketEmission {
    emitted: bool,
    skipped: bool,
    retransmitted_bytes: u64,
    retransmitted_fin: bool,
}

/// Data-bearing frames emitted into one packet. DATAGRAM is intentionally
/// separate because the legacy congestion controller excludes it from data
/// accounting, while gcongestion includes it.
#[derive(Default)]
struct PacketDataEmission {
    crypto_retransmitted_bytes: Option<u64>,
    stream: StreamPacketEmission,
    datagram_emitted: bool,
}

impl PacketDataEmission {
    const fn has_data(&self) -> bool {
        self.crypto_retransmitted_bytes.is_some() || self.stream.emitted
    }

    const fn retransmitted_bytes(&self) -> u64 {
        let crypto_bytes = match self.crypto_retransmitted_bytes {
            Some(bytes) => bytes,
            None => 0,
        };
        crypto_bytes.saturating_add(self.stream.retransmitted_bytes)
    }
}

/// Wire layout fixed when the outgoing header and packet number are written.
struct TxPacketHeader {
    packet_type: Type,
    epoch: packet::Epoch,
    number: u64,
    number_len: usize,
    output_capacity: usize,
    payload_capacity: usize,
    payload_offset: usize,
    crypto_overhead: usize,
    length_field: Option<(usize, usize)>,
    trace: Option<String>,
    #[cfg(feature = "qlog")]
    qlog_header: Option<qlog::events::quic::PacketHeader>,
}

impl TxPacketHeader {
    const fn overhead(&self) -> usize {
        self.payload_offset + self.crypto_overhead
    }
}

#[derive(Default)]
struct TxPathProbes {
    has_path_frame: bool,
    challenge: Option<[u8; 8]>,
}

#[derive(Default)]
struct TxPacketAssembly {
    frames: SmallVec<[frame::Frame; 1]>,
    left: usize,
    flight: recovery::PacketFlight,
    probes: TxPathProbes,
    data: PacketDataEmission,
}

#[derive(Clone, Copy)]
struct TxAckBudget {
    elicit_required: bool,
    congestion_limit: usize,
}

/// An incoming packet has either been buffered pending its opening key or
/// authenticated in place. Speculative keys travel with the authenticated
/// payload until path selection and key-update validation.
enum RxAuthentication<'a> {
    Buffered(usize),
    Opened(OpenedRxPacket<'a>),
}

struct OpenedRxPacket<'a> {
    epoch: packet::Epoch,
    pn: u64,
    payload: octets::Octets<'a>,
    // Only successful key updates allocate the new key pair; ordinary
    // packets keep this result small and allocation-free.
    next_keys: Option<Box<(crypto::Open, crypto::Seal)>>,
}

struct RxPacketContext {
    epoch: packet::Epoch,
    pn: u64,
    recv_pid: usize,
    now: Instant,
    #[cfg(feature = "qlog")]
    packet_size: usize,
    #[cfg(feature = "qlog")]
    payload_len: usize,
}

#[derive(Clone, Copy)]
struct RxFrameEffects {
    ack_elicited: bool,
    probing: bool,
}

/// A QUIC connection.
pub struct Connection<F = DefaultBufFactory>
where
    F: BufFactory,
{
    /// QUIC wire version used for the connection.
    version: u32,

    /// Connection Identifiers.
    ids: cid::ConnectionIdentifiers,

    /// Unique opaque ID for the connection that can be used for logging.
    trace_id: String,

    /// Packet number spaces.
    pkt_num_spaces: [packet::PktNumSpace; packet::Epoch::count()],

    /// The crypto context.
    crypto_ctx: [packet::CryptoContext; packet::Epoch::count()],

    /// Next packet number.
    next_pkt_num: u64,

    // TODO
    // combine with `next_pkt_num`
    /// Track the packet skip context
    pkt_num_manager: packet::PktNumManager,

    /// Peer's transport parameters.
    peer_transport_params: TransportParams,

    /// If tracking unknown transport parameters from a peer, how much space to
    /// use in bytes.
    peer_transport_params_track_unknown: Option<usize>,

    /// Local transport parameters.
    local_transport_params: TransportParams,

    /// TLS handshake state.
    handshake: tls::Handshake,

    early_data_rejection_handled: bool,

    /// Serialized TLS session buffer.
    ///
    /// This field is populated when a new session ticket is processed on the
    /// client. On the server this is empty.
    session: Option<Vec<u8>>,

    /// The configuration for recovery.
    recovery_config: recovery::RecoveryConfig,

    /// The path manager.
    paths: path::PathMap,

    /// `PATH_CHALLENGE` receive queue max length.
    path_challenge_recv_max_queue_len: usize,

    /// Total number of received `PATH_CHALLENGE` frames.
    path_challenge_rx_count: u64,

    /// List of supported application protocols.
    application_protos: Vec<Vec<u8>>,

    /// Total number of received packets.
    recv_count: usize,

    /// Total number of sent packets.
    sent_count: usize,

    /// Total number of lost packets.
    lost_count: usize,

    /// Total number of lost packets that were later acked.
    spurious_lost_count: usize,

    /// Total number of packets sent with data retransmitted.
    retrans_count: usize,

    /// Total number of sent DATAGRAM frames.
    dgram_sent_count: usize,

    /// Total number of received DATAGRAM frames.
    dgram_recv_count: usize,

    /// Total number of bytes received from the peer.
    rx_data: u64,

    /// Receiver flow controller.
    flow_control: flowcontrol::FlowControl,

    /// Whether we send `MAX_DATA` frame.
    should_send_max_data: bool,

    /// True if there is a pending `MAX_STREAMS_BIDI` frame to send.
    should_send_max_streams_bidi: bool,

    /// True if there is a pending `MAX_STREAMS_UNI` frame to send.
    should_send_max_streams_uni: bool,

    /// Number of stream data bytes that can be buffered.
    tx_cap: usize,

    /// The send capacity factor.
    tx_cap_factor: f64,

    /// Total number of bytes sent to the peer.
    tx_data: u64,

    /// Peer's flow control limit for the connection.
    max_tx_data: u64,

    /// Last `tx_data` before running a full `send()` loop.
    last_tx_data: u64,

    /// Total number of bytes retransmitted over the connection.
    /// This counts only STREAM and CRYPTO data.
    stream_retrans_bytes: u64,

    /// Total number of bytes sent over the connection.
    sent_bytes: u64,

    /// Total number of bytes received over the connection.
    recv_bytes: u64,

    /// Total number of bytes sent acked over the connection.
    acked_bytes: u64,

    /// Total number of bytes sent lost over the connection.
    lost_bytes: u64,

    /// Streams map, indexed by stream ID.
    pub(crate) streams: stream::StreamMap<F>,

    /// Peer's original destination connection ID. Used by the client to
    /// validate the server's transport parameter.
    odcid: Option<ConnectionId<'static>>,

    /// Peer's retry source connection ID. Used by the client during stateless
    /// retry to validate the server's transport parameter.
    rscid: Option<ConnectionId<'static>>,

    /// Received address verification token.
    token: Option<Vec<u8>>,

    /// Error code and reason to be sent to the peer in a `CONNECTION_CLOSE`
    /// frame.
    local_error: Option<ConnectionError>,

    /// Error code and reason received from the peer in a `CONNECTION_CLOSE`
    /// frame.
    peer_error: Option<ConnectionError>,

    /// The connection-level limit at which send blocking occurred.
    blocked_limit: Option<u64>,

    /// Idle timeout expiration time.
    idle_timer: Option<Instant>,

    /// Connection processing lifecycle and terminal cause.
    lifecycle: ConnectionLifecycle,

    /// List of raw packets that were received before they could be decrypted.
    undecryptable_pkts: VecDeque<(Vec<u8>, RecvInfo)>,

    /// The negotiated ALPN protocol.
    alpn: Vec<u8>,

    /// Whether this is a server-side connection.
    is_server: bool,

    /// Whether the initial secrets have been derived.
    derived_initial_secrets: bool,

    /// Whether a version negotiation packet has already been received. Only
    /// relevant for client connections.
    did_version_negotiation: bool,

    /// Whether stateless retry has been performed.
    did_retry: bool,

    /// Whether the peer already updated its connection ID.
    got_peer_conn_id: bool,

    /// Whether the peer verified our initial address.
    peer_verified_initial_address: bool,

    /// Whether the peer's transport parameters were parsed.
    parsed_peer_transport_params: bool,

    /// Whether the connection handshake has been completed.
    handshake_completed: bool,

    /// Server's reliable `HANDSHAKE_DONE` transmission state.
    handshake_done: HandshakeDoneState,

    /// Whether the connection handshake has been confirmed.
    handshake_confirmed: bool,

    /// Key phase bit used for outgoing protected packets.
    key_phase: bool,

    /// Whether an ack-eliciting packet has been sent since last receiving a
    /// packet.
    ack_eliciting_sent: bool,

    /// Whether to send GREASE.
    grease: bool,

    /// Whether to send `STREAMS_BLOCKED` frames when bidi or uni stream quota
    /// exhausted.
    enable_send_streams_blocked: bool,

    /// TLS keylog writer.
    keylog: Option<Box<dyn std::io::Write + Send + Sync>>,

    #[cfg(feature = "qlog")]
    qlog: QlogInfo,

    /// DATAGRAM queues.
    dgram_recv_queue: dgram::DatagramQueue<F>,
    dgram_send_queue: dgram::DatagramQueue<F>,

    /// Whether to emit DATAGRAM frames in the next packet.
    emit_dgram: bool,

    /// Whether the connection should prevent from reusing destination
    /// Connection IDs when the peer migrates.
    disable_dcid_reuse: bool,

    /// The number of streams reset by local.
    reset_stream_local_count: u64,

    /// The number of streams stopped by local.
    stopped_stream_local_count: u64,

    /// The number of streams reset by remote.
    reset_stream_remote_count: u64,

    /// The number of streams stopped by remote.
    stopped_stream_remote_count: u64,

    /// The number of `DATA_BLOCKED` frames sent due to hitting the connection
    /// flow control limit.
    data_blocked_sent_count: u64,

    /// The number of `STREAM_DATA_BLOCKED` frames sent due to a stream hitting
    /// the stream flow control limit.
    stream_data_blocked_sent_count: u64,

    /// The number of `DATA_BLOCKED` frames received from the remote endpoint.
    data_blocked_recv_count: u64,

    /// The number of `STREAM_DATA_BLOCKED` frames received from the remote
    /// endpoint.
    stream_data_blocked_recv_count: u64,

    /// The number of `STREAMS_BLOCKED` frames received from the remote endpoint
    /// indicating the peer is blocked on opening new bidirectional streams.
    streams_blocked_bidi_recv_count: u64,

    /// The number of `STREAMS_BLOCKED` frames received from the remote endpoint
    /// indicating the peer is blocked on opening new unidirectional streams.
    streams_blocked_uni_recv_count: u64,

    /// The number of times `send()` was blocked because the anti-amplification
    /// budget (bytes received × `max_amplification_factor`) was exhausted.
    amplification_limited_count: u64,

    /// Tracks if the connection hit the peer's bidi or uni stream limit, and if
    /// `STREAMS_BLOCKED` frames are pending transmission.
    streams_blocked_bidi_state: StreamsBlockedState,
    streams_blocked_uni_state: StreamsBlockedState,

    /// The anti-amplification limit factor.
    max_amplification_factor: usize,
}

/// Creates a new server-side connection.
///
/// The `scid` parameter represents the server's source connection ID, while
/// the optional `odcid` parameter represents the original destination ID the
/// client sent before a Retry packet (this is only required when using the
/// [`retry()`] function). See also the [`accept_with_retry()`] function for
/// more advanced retry cases.
///
/// # Errors
///
/// Returns an error if the TLS handshake or connection state cannot be
/// initialized, including failure to encode local transport parameters.
///
/// [`retry()`]: fn.retry.html
///
/// ## Examples:
///
/// ```no_run
/// # let mut config = quiche::Config::new(0xbabababa)?;
/// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
/// # let local = "127.0.0.1:0".parse().unwrap();
/// # let peer = "127.0.0.1:1234".parse().unwrap();
/// let conn = quiche::accept(&scid, None, local, peer, &mut config)?;
/// # Ok::<(), quiche::Error>(())
/// ```
#[inline(always)]
pub fn accept(
    scid: &ConnectionId, odcid: Option<&ConnectionId>, local: SocketAddr,
    peer: SocketAddr, config: &mut Config,
) -> Result<Connection> {
    accept_with_buf_factory(scid, odcid, local, peer, config)
}

/// Creates a server-side connection with custom buffer generation.
///
/// The buffers generated can be anything that can be dereferenced as a byte
/// slice. See [`accept`] and [`BufFactory`] for more information.
///
/// # Errors
///
/// Returns the same connection-initialization errors as [`accept`].
#[inline]
pub fn accept_with_buf_factory<F: BufFactory>(
    scid: &ConnectionId, odcid: Option<&ConnectionId>, local: SocketAddr,
    peer: SocketAddr, config: &mut Config,
) -> Result<Connection<F>> {
    // Connections with `odcid` historically used `scid` as the retry source
    // CID. Preserve this behavior for backwards compatibility.
    // `accept_with_retry` allows the SCIDs to be specified separately.
    let retry_cids = odcid.map(|odcid| RetryConnectionIds {
        original_destination_cid: odcid,
        retry_source_cid: scid,
    });
    Connection::new(scid, retry_cids, None, local, peer, config, true)
}

/// A wrapper for connection IDs used in [`accept_with_retry`].
pub struct RetryConnectionIds<'a> {
    /// The DCID of the first Initial packet received by the server, which
    /// triggered the Retry packet.
    pub original_destination_cid: &'a ConnectionId<'a>,
    /// The SCID of the Retry packet sent by the server. This can be different
    /// from the new connection's SCID.
    pub retry_source_cid: &'a ConnectionId<'a>,
}

/// Creates a new server-side connection after the client responded to a Retry
/// packet.
///
/// To generate a Retry packet in the first place, use the [`retry()`] function.
///
/// The `scid` parameter represents the server's source connection ID, which can
/// be freshly generated after the application has successfully verified the
/// Retry. `retry_cids` is used to tie the new connection to the Initial + Retry
/// exchange that preceded the connection's creation.
///
/// The DCID of the client's Initial packet is inherently untrusted data. It is
/// safe to use the DCID in the `retry_source_cid` field of the
/// `RetryConnectionIds` provided to this function. However, using the Initial's
/// DCID for the `scid` parameter carries risks. Applications are advised to
/// implement their own DCID validation steps before using the DCID in that
/// manner.
///
/// # Errors
///
/// Returns the same connection-initialization errors as [`accept`].
#[inline]
pub fn accept_with_retry<F: BufFactory>(
    scid: &ConnectionId, retry_cids: RetryConnectionIds, local: SocketAddr,
    peer: SocketAddr, config: &mut Config,
) -> Result<Connection<F>> {
    Connection::new(scid, Some(retry_cids), None, local, peer, config, true)
}

/// Creates a new client-side connection.
///
/// The `scid` parameter is used as the connection's source connection ID,
/// while the optional `server_name` parameter is used to verify the peer's
/// certificate.
///
/// # Errors
///
/// Returns an error if connection initialization fails or the TLS backend
/// rejects the supplied server name.
///
/// ## Examples:
///
/// ```no_run
/// # let mut config = quiche::Config::new(0xbabababa)?;
/// # let server_name = "quic.tech";
/// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
/// # let local = "127.0.0.1:4321".parse().unwrap();
/// # let peer = "127.0.0.1:1234".parse().unwrap();
/// let conn =
///     quiche::connect(Some(&server_name), &scid, local, peer, &mut config)?;
/// # Ok::<(), quiche::Error>(())
/// ```
#[inline]
pub fn connect(
    server_name: Option<&str>, scid: &ConnectionId, local: SocketAddr,
    peer: SocketAddr, config: &mut Config,
) -> Result<Connection> {
    let mut conn = Connection::new(scid, None, None, local, peer, config, false)?;

    if let Some(server_name) = server_name {
        conn.handshake.set_host_name(server_name)?;
    }

    Ok(conn)
}

/// Creates a new client-side connection using the given DCID initially.
///
/// Be aware that [RFC 9000] places requirements for unpredictability and length
/// on the client DCID field. This function is dangerous if these  requirements
/// are not satisfied.
///
/// The `scid` parameter is used as the connection's source connection ID, while
/// the optional `server_name` parameter is used to verify the peer's
/// certificate.
///
/// # Errors
///
/// Returns `Error::InvalidDcidInitialization` if the supplied destination
/// connection ID is shorter than eight bytes, or a connection-initialization
/// or server-name error as in [`connect`].
///
/// [RFC 9000]: <https://datatracker.ietf.org/doc/html/rfc9000#section-7.2-3>
#[cfg(feature = "custom-client-dcid")]
#[cfg_attr(docsrs, doc(cfg(feature = "custom-client-dcid")))]
pub fn connect_with_dcid(
    server_name: Option<&str>, scid: &ConnectionId, dcid: &ConnectionId,
    local: SocketAddr, peer: SocketAddr, config: &mut Config,
) -> Result<Connection> {
    let mut conn =
        Connection::new(scid, None, Some(dcid), local, peer, config, false)?;

    if let Some(server_name) = server_name {
        conn.handshake.set_host_name(server_name)?;
    }

    Ok(conn)
}

/// Creates a new client-side connection, with a custom buffer generation
/// method.
///
/// The buffers generated can be anything that can be dereferenced as a byte
/// slice. See [`connect`] and [`BufFactory`] for more info.
///
/// # Errors
///
/// Returns the same connection-initialization and server-name errors as
/// [`connect`].
#[inline]
pub fn connect_with_buffer_factory<F: BufFactory>(
    server_name: Option<&str>, scid: &ConnectionId, local: SocketAddr,
    peer: SocketAddr, config: &mut Config,
) -> Result<Connection<F>> {
    let mut conn = Connection::new(scid, None, None, local, peer, config, false)?;

    if let Some(server_name) = server_name {
        conn.handshake.set_host_name(server_name)?;
    }

    Ok(conn)
}

/// Creates a new client-side connection, with a custom buffer generation
/// method using the given dcid initially.
/// Be aware the RFC places requirements for unpredictability and length
/// on the client DCID field.
///
/// # Errors
///
/// Returns the same errors as [`connect_with_dcid`], including
/// `Error::InvalidDcidInitialization` for a destination connection ID
/// shorter than eight bytes.
///
/// [`RFC9000`]:  https://datatracker.ietf.org/doc/html/rfc9000#section-7.2-3
///
/// The buffers generated can be anything that can be dereferenced as a byte
/// slice. See [`connect`] and [`BufFactory`] for more info.
#[cfg(feature = "custom-client-dcid")]
#[cfg_attr(docsrs, doc(cfg(feature = "custom-client-dcid")))]
pub fn connect_with_dcid_and_buffer_factory<F: BufFactory>(
    server_name: Option<&str>, scid: &ConnectionId, dcid: &ConnectionId,
    local: SocketAddr, peer: SocketAddr, config: &mut Config,
) -> Result<Connection<F>> {
    let mut conn =
        Connection::new(scid, None, Some(dcid), local, peer, config, false)?;

    if let Some(server_name) = server_name {
        conn.handshake.set_host_name(server_name)?;
    }

    Ok(conn)
}

/// Writes a version negotiation packet.
///
/// The `scid` and `dcid` parameters are the source connection ID and the
/// destination connection ID extracted from the received client's Initial
/// packet that advertises an unsupported version.
///
/// # Errors
///
/// Returns `Error::InvalidPacket` for a connection ID exceeding the
/// version-independent 255-byte limit, or `Error::BufferTooShort` if the output
/// buffer cannot hold the version negotiation packet.
///
/// ## Examples:
///
/// ```no_run
/// # let mut buf = [0; 512];
/// # let mut out = [0; 512];
/// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
/// let (len, src) = socket.recv_from(&mut buf).unwrap();
///
/// let hdr = quiche::Header::from_slice(&buf[..len], quiche::MAX_CONN_ID_LEN)?;
///
/// if hdr.version != quiche::PROTOCOL_VERSION {
///     let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)?;
///     socket.send_to(&out[..len], &src).unwrap();
/// }
/// # Ok::<(), quiche::Error>(())
/// ```
#[inline]
pub fn negotiate_version(
    scid: &ConnectionId, dcid: &ConnectionId, out: &mut [u8],
) -> Result<usize> {
    packet::negotiate_version(
        scid,
        dcid,
        &mut packet::PacketWriter::from_initialized(out),
    )
}

/// Writes a stateless retry packet.
///
/// The `scid` and `dcid` parameters are the source connection ID and the
/// destination connection ID extracted from the received client's Initial
/// packet, while `new_scid` is the server's new source connection ID and
/// `token` is the address validation token the client needs to echo back.
///
/// The application is responsible for generating the address validation
/// token to be sent to the client, and verifying tokens sent back by the
/// client. The generated token should include the `dcid` parameter, such
/// that it can be later extracted from the token and passed to the
/// [`accept()`] function as its `odcid` parameter.
///
/// # Errors
///
/// Returns `Error::UnknownVersion` for an unsupported version,
/// `Error::InvalidPacket` if a connection ID exceeds the version's limit,
/// `Error::BufferTooShort` if the output buffer is too small, or a
/// cryptographic error if Retry integrity tag generation fails.
///
/// [`accept()`]: fn.accept.html
///
/// ## Examples:
///
/// ```no_run
/// # let mut config = quiche::Config::new(0xbabababa)?;
/// # let mut buf = [0; 512];
/// # let mut out = [0; 512];
/// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
/// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
/// # let local = socket.local_addr().unwrap();
/// # fn mint_token(hdr: &quiche::Header, src: &std::net::SocketAddr) -> Vec<u8> {
/// #     vec![]
/// # }
/// # fn validate_token<'a>(src: &std::net::SocketAddr, token: &'a [u8]) -> Option<quiche::ConnectionId<'a>> {
/// #     None
/// # }
/// let (len, peer) = socket.recv_from(&mut buf).unwrap();
///
/// let hdr = quiche::Header::from_slice(&buf[..len], quiche::MAX_CONN_ID_LEN)?;
///
/// let token = hdr.token.as_ref().unwrap();
///
/// // No token sent by client, create a new one.
/// if token.is_empty() {
///     let new_token = mint_token(&hdr, &peer);
///
///     let len = quiche::retry(
///         &hdr.scid, &hdr.dcid, &scid, &new_token, hdr.version, &mut out,
///     )?;
///
///     socket.send_to(&out[..len], &peer).unwrap();
///     return Ok(());
/// }
///
/// // Client sent token, validate it.
/// let odcid = validate_token(&peer, token);
///
/// if odcid.is_none() {
///     // Invalid address validation token.
///     return Ok(());
/// }
///
/// let conn = quiche::accept(&scid, odcid.as_ref(), local, peer, &mut config)?;
/// # Ok::<(), quiche::Error>(())
/// ```
#[inline]
pub fn retry(
    scid: &ConnectionId, dcid: &ConnectionId, new_scid: &ConnectionId,
    token: &[u8], version: u32, out: &mut [u8],
) -> Result<usize> {
    packet::retry(
        scid,
        dcid,
        new_scid,
        token,
        version,
        &mut packet::PacketWriter::from_initialized(out),
    )
}

/// Returns true if the given protocol version is supported.
#[inline]
#[must_use = "the result determines whether the wire version can be negotiated"]
pub const fn version_is_supported(version: u32) -> bool {
    matches!(version, PROTOCOL_VERSION_V1)
}

/// Pushes a frame to the output packet if there is enough space.
///
/// Returns `true` on success, `false` otherwise. In case of failure it means
/// there is no room to add the frame in the packet. You may retry to add the
/// frame later.
fn push_frame_to_pkt(
    out: &mut impl frame::FrameSink, frames: &mut SmallVec<[frame::Frame; 1]>,
    frame: frame::Frame, left: &mut usize,
) -> Result<bool> {
    let wire_len = frame.wire_len()?;
    if wire_len > *left {
        return Ok(false);
    }
    frame.encode(out)?;
    *left -= wire_len;
    frames.push(frame);
    Ok(true)
}

/// Encode pending `PATH_RESPONSE` frames while packet space permits. Return
/// whether at least one response was emitted.
fn push_received_path_responses(
    path: &mut path::Path, out: &mut impl frame::FrameSink,
    frames: &mut SmallVec<[frame::Frame; 1]>, left: &mut usize,
) -> Result<bool> {
    let mut pushed = false;
    while let Some(challenge) = path.next_received_challenge() {
        let frame = frame::Frame::PathResponse { data: challenge };
        if !push_frame_to_pkt(out, frames, frame, left)? {
            // No packet space: retain this and later challenges for retry.
            break;
        }
        // A response obligation is consumed only after its frame is encoded.
        let consumed = path.pop_received_challenge();
        debug_assert_eq!(consumed, Some(challenge));
        pushed = true;
    }
    Ok(pushed)
}

/// Executes the provided body if the qlog feature is enabled, quiche has been
/// configured with a log writer, the event's importance is within the
/// configured level.
macro_rules! qlog_with_type {
    ($ty:expr, $qlog:expr, $qlog_streamer_ref:ident, $body:block) => {{
        #[cfg(feature = "qlog")]
        {
            if EventImportance::from($ty).is_contained_in(&$qlog.level) {
                if let Some($qlog_streamer_ref) = &mut $qlog.streamer {
                    $body
                }
            }
        }
    }};
}

#[cfg(feature = "qlog")]
const QLOG_PARAMS_SET: EventType =
    EventType::QuicEventType(QuicEventType::ParametersSet);

#[cfg(feature = "qlog")]
const QLOG_PACKET_RX: EventType =
    EventType::QuicEventType(QuicEventType::PacketReceived);

#[cfg(feature = "qlog")]
const QLOG_PACKET_TX: EventType =
    EventType::QuicEventType(QuicEventType::PacketSent);

#[cfg(feature = "qlog")]
const QLOG_DATA_MV: EventType =
    EventType::QuicEventType(QuicEventType::StreamDataMoved);

#[cfg(feature = "qlog")]
const QLOG_METRICS: EventType =
    EventType::QuicEventType(QuicEventType::RecoveryMetricsUpdated);

#[cfg(feature = "qlog")]
const QLOG_CONNECTION_CLOSED: EventType =
    EventType::QuicEventType(QuicEventType::ConnectionClosed);

#[cfg(feature = "qlog")]
struct QlogInfo {
    streamer: Option<qlog::streamer::QlogStreamer>,
    logged_peer_params: bool,
    level: EventImportance,
}

#[cfg(feature = "qlog")]
impl Default for QlogInfo {
    fn default() -> Self {
        Self {
            streamer: None,
            logged_peer_params: false,
            level: EventImportance::Base,
        }
    }
}

impl<F: BufFactory> Connection<F> {
    fn new(
        scid: &ConnectionId, retry_cids: Option<RetryConnectionIds>,
        client_dcid: Option<&ConnectionId>, local: SocketAddr, peer: SocketAddr,
        config: &mut Config, is_server: bool,
    ) -> Result<Self> {
        let tls = config.tls_ctx.new_handshake()?;
        Self::with_tls(
            scid,
            retry_cids,
            client_dcid,
            local,
            peer,
            config,
            tls,
            is_server,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The signature mirrors protocol state and grouping would obscure call sites"
    )]
    fn with_tls(
        scid: &ConnectionId, retry_cids: Option<RetryConnectionIds>,
        client_dcid: Option<&ConnectionId>, local: SocketAddr, peer: SocketAddr,
        config: &Config, tls: tls::Handshake, is_server: bool,
    ) -> Result<Self> {
        if retry_cids.is_some() && client_dcid.is_some() {
            // These are exclusive, the caller should only specify one or the
            // other.
            return Err(Error::InvalidDcidInitialization);
        }
        #[cfg(feature = "custom-client-dcid")]
        if let Some(client_dcid) = client_dcid {
            // The Minimum length is 8.
            // See https://datatracker.ietf.org/doc/html/rfc9000#section-7.2-3
            if client_dcid.len() < 8 {
                return Err(Error::InvalidDcidInitialization);
            }
        }
        #[cfg(not(feature = "custom-client-dcid"))]
        if client_dcid.is_some() {
            return Err(Error::InvalidDcidInitialization);
        }

        let max_rx_data = config.local_transport_params.initial_max_data;

        let trace_id = format!("{scid:?}");

        let reset_token = if is_server {
            config.local_transport_params.stateless_reset_token
        } else {
            None
        };

        let recovery_config = recovery::RecoveryConfig::from_config(config);

        let mut path = path::Path::new(
            local,
            peer,
            &recovery_config,
            config.path_challenge_recv_max_queue_len,
            true,
            Some(config),
        );

        // If we sent a Retry assume the peer's address is verified.
        path.verified_peer_address = retry_cids.is_some();

        // Do not allocate more than the number of active CIDs. A wire limit
        // above the addressable collection size cannot constrain it further.
        let active_conn_id_limit =
            usize::try_from(config.local_transport_params.active_conn_id_limit)
                .unwrap_or(usize::MAX);
        let paths = path::PathMap::new(path, active_conn_id_limit, is_server);

        let active_path_id = paths.get_active_path_id()?;

        let ids = cid::ConnectionIdentifiers::new(
            active_conn_id_limit,
            scid,
            active_path_id,
            reset_token,
        );

        let initial_flow_control_window = max_rx_data;
        let mut conn = Self {
            version: config.version,

            ids,

            trace_id,

            pkt_num_spaces: [
                packet::PktNumSpace::new(),
                packet::PktNumSpace::new(),
                packet::PktNumSpace::new(),
            ],

            crypto_ctx: [
                packet::CryptoContext::new(),
                packet::CryptoContext::new(),
                packet::CryptoContext::new(),
            ],

            next_pkt_num: 0,

            pkt_num_manager: packet::PktNumManager::new(),

            peer_transport_params: TransportParams::default(),

            peer_transport_params_track_unknown: config
                .track_unknown_transport_params,

            local_transport_params: config.local_transport_params.clone(),

            handshake: tls,

            early_data_rejection_handled: false,

            session: None,

            recovery_config,

            paths,
            path_challenge_recv_max_queue_len: config
                .path_challenge_recv_max_queue_len,
            path_challenge_rx_count: 0,

            application_protos: config.application_protos.clone(),

            recv_count: 0,
            sent_count: 0,
            lost_count: 0,
            spurious_lost_count: 0,
            retrans_count: 0,
            dgram_sent_count: 0,
            dgram_recv_count: 0,
            sent_bytes: 0,
            recv_bytes: 0,
            acked_bytes: 0,
            lost_bytes: 0,

            rx_data: 0,
            flow_control: flowcontrol::FlowControl::new(
                max_rx_data,
                initial_flow_control_window,
                config.max_connection_window,
            ),
            should_send_max_data: false,
            should_send_max_streams_bidi: false,
            should_send_max_streams_uni: false,

            tx_cap: 0,
            tx_cap_factor: config.tx_cap_factor,

            tx_data: 0,
            max_tx_data: 0,
            last_tx_data: 0,

            stream_retrans_bytes: 0,

            streams: stream::StreamMap::new(
                config.local_transport_params.initial_max_streams_bidi,
                config.local_transport_params.initial_max_streams_uni,
                config.max_stream_window,
            ),

            odcid: None,

            rscid: None,

            token: None,

            local_error: None,

            peer_error: None,

            blocked_limit: None,

            idle_timer: None,

            lifecycle: ConnectionLifecycle::Active,

            undecryptable_pkts: VecDeque::new(),

            alpn: Vec::new(),

            is_server,

            derived_initial_secrets: false,

            did_version_negotiation: false,

            did_retry: false,

            got_peer_conn_id: false,

            // Assume clients validate the server's address implicitly.
            peer_verified_initial_address: is_server,

            parsed_peer_transport_params: false,

            handshake_completed: false,

            handshake_done: HandshakeDoneState::Pending,

            handshake_confirmed: false,

            key_phase: false,

            ack_eliciting_sent: false,

            grease: config.grease,

            enable_send_streams_blocked: config.enable_send_streams_blocked,

            keylog: None,

            #[cfg(feature = "qlog")]
            qlog: QlogInfo::default(),

            dgram_recv_queue: dgram::DatagramQueue::new(
                config.dgram_recv_max_queue_len,
            ),

            dgram_send_queue: dgram::DatagramQueue::new(
                config.dgram_send_max_queue_len,
            ),

            emit_dgram: true,

            disable_dcid_reuse: config.disable_dcid_reuse,

            reset_stream_local_count: 0,
            stopped_stream_local_count: 0,
            reset_stream_remote_count: 0,
            stopped_stream_remote_count: 0,

            data_blocked_sent_count: 0,
            stream_data_blocked_sent_count: 0,
            data_blocked_recv_count: 0,
            stream_data_blocked_recv_count: 0,

            streams_blocked_bidi_recv_count: 0,
            streams_blocked_uni_recv_count: 0,

            amplification_limited_count: 0,

            streams_blocked_bidi_state: StreamsBlockedState::default(),
            streams_blocked_uni_state: StreamsBlockedState::default(),

            max_amplification_factor: config.max_amplification_factor,
        };
        if let Some(retry_cids) = retry_cids {
            conn.local_transport_params
                .original_destination_connection_id =
                Some(ConnectionId::copy_from_slice(
                    retry_cids.original_destination_cid.as_ref(),
                ));

            conn.local_transport_params.retry_source_connection_id =
                Some(ConnectionId::copy_from_slice(
                    retry_cids.retry_source_cid.as_ref(),
                ));

            conn.did_retry = true;
        }

        conn.local_transport_params.initial_source_connection_id =
            Some(conn.ids.get_scid(0)?.cid.clone());

        conn.handshake.init(is_server)?;

        conn.handshake
            .use_legacy_codepoint(config.version != PROTOCOL_VERSION_V1);

        conn.encode_transport_params()?;

        if !is_server {
            let dcid = client_dcid.map_or_else(
                || {
                    // Derive initial secrets for the client. We can do this
                    // here because the random DCID has not been assigned yet.
                    let mut dcid = [0; 16];
                    rand::rand_bytes(&mut dcid[..]);
                    ConnectionId::copy_from_slice(&dcid)
                },
                |dcid| ConnectionId::copy_from_slice(dcid.as_ref()),
            );

            let (aead_open, aead_seal) = crypto::derive_initial_key_material(
                &dcid,
                conn.is_server,
                crypto::CounterInitialization::FirstPacket,
            )?;

            let reset_token = conn.peer_transport_params.stateless_reset_token;
            conn.set_initial_dcid(dcid, reset_token, active_path_id)?;

            conn.crypto_ctx[packet::Epoch::Initial].crypto_open = Some(aead_open);
            conn.crypto_ctx[packet::Epoch::Initial].crypto_seal = Some(aead_seal);

            conn.derived_initial_secrets = true;
        }

        Ok(conn)
    }

    /// Sets keylog output to the designated [`Writer`].
    ///
    /// This needs to be called as soon as the connection is created, to avoid
    /// missing some early logs.
    ///
    /// [`Writer`]: https://doc.rust-lang.org/std/io/trait.Write.html
    #[inline]
    pub fn set_keylog(&mut self, writer: Box<dyn std::io::Write + Send + Sync>) {
        self.keylog = Some(writer);
    }

    /// Sets qlog output to the designated [`Writer`].
    ///
    /// Only events included in `QlogLevel::Base` are written. The serialization
    /// format is JSON-SEQ.
    ///
    /// This needs to be called as soon as the connection is created, to avoid
    /// missing some early logs.
    ///
    /// [`Writer`]: https://doc.rust-lang.org/std/io/trait.Write.html
    #[cfg(feature = "qlog")]
    #[cfg_attr(docsrs, doc(cfg(feature = "qlog")))]
    pub fn set_qlog(
        &mut self, writer: Box<dyn std::io::Write + Send + Sync>, title: String,
        description: String,
    ) {
        self.set_qlog_with_level(writer, title, description, QlogLevel::Base);
    }

    /// Sets qlog output to the designated [`Writer`].
    ///
    /// Only qlog events included in the specified `QlogLevel` are written. The
    /// serialization format is JSON-SEQ.
    ///
    /// This needs to be called as soon as the connection is created, to avoid
    /// missing some early logs.
    ///
    /// [`Writer`]: https://doc.rust-lang.org/std/io/trait.Write.html
    #[cfg(feature = "qlog")]
    #[cfg_attr(docsrs, doc(cfg(feature = "qlog")))]
    pub fn set_qlog_with_level(
        &mut self, writer: Box<dyn std::io::Write + Send + Sync>, title: String,
        description: String, qlog_level: QlogLevel,
    ) {
        use qlog::events::quic::TransportInitiator;
        use qlog::events::HTTP3_URI;
        use qlog::events::QUIC_URI;
        use qlog::CommonFields;
        use qlog::ReferenceTime;

        let vp = if self.is_server {
            qlog::VantagePointType::Server
        } else {
            qlog::VantagePointType::Client
        };

        let level = match qlog_level {
            QlogLevel::Core => EventImportance::Core,

            QlogLevel::Base => EventImportance::Base,

            QlogLevel::Extra => EventImportance::Extra,
        };

        self.qlog.level = level;

        // Best effort to get Instant::now() and SystemTime::now() as closely
        // together as possible.
        let now = Instant::now();
        let now_wall_clock = std::time::SystemTime::now();
        let common_fields = CommonFields {
            reference_time: ReferenceTime::new_monotonic(Some(now_wall_clock)),
            ..Default::default()
        };
        let trace = qlog::TraceSeq::new(
            Some(title.clone()),
            Some(description.clone()),
            Some(common_fields),
            Some(qlog::VantagePoint {
                name: None,
                ty: vp,
                flow: None,
            }),
            vec![QUIC_URI.to_string(), HTTP3_URI.to_string()],
        );

        let mut streamer = qlog::streamer::QlogStreamer::new(
            Some(title),
            Some(description),
            now,
            trace,
            self.qlog.level,
            qlog::streamer::EventTimePrecision::MicroSeconds,
            writer,
        );

        streamer.start_log().ok();

        let ev_data = self
            .local_transport_params
            .to_qlog(TransportInitiator::Local, self.handshake.cipher());

        // This event occurs very early, so just mark the relative time as 0.0.
        streamer.add_event(Event::with_time(0.0, ev_data)).ok();

        self.qlog.streamer = Some(streamer);
    }

    /// Returns a mutable reference to the `QlogStreamer`, if it exists.
    #[cfg(feature = "qlog")]
    #[cfg_attr(docsrs, doc(cfg(feature = "qlog")))]
    pub const fn qlog_streamer(
        &mut self,
    ) -> Option<&mut qlog::streamer::QlogStreamer> {
        self.qlog.streamer.as_mut()
    }

    /// Configures the given session for resumption.
    ///
    /// On the client, this can be used to offer the given serialized session,
    /// as returned by [`session()`], for resumption.
    ///
    /// This must only be called immediately after creating a connection, that
    /// is, before any packet is sent or received.
    ///
    /// # Errors
    /// Returns [`Error::BufferTooShort`] if a serialized field is truncated
    /// or its declared length cannot fit in the target's address space.
    /// Returns the transport parameter decoding or TLS error if the stored
    /// parameters or session are invalid.
    ///
    /// [`session()`]: struct.Connection.html#method.session
    #[inline]
    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        let mut b = octets::Octets::with_slice(session);

        let session_len =
            usize::try_from(b.get_u64()?).map_err(|_| Error::BufferTooShort)?;
        let session_bytes = b.get_bytes(session_len)?;

        let raw_params_len =
            usize::try_from(b.get_u64()?).map_err(|_| Error::BufferTooShort)?;
        let raw_params_bytes = b.get_bytes(raw_params_len)?;

        let peer_params = TransportParams::decode(
            raw_params_bytes.as_ref(),
            self.is_server,
            self.peer_transport_params_track_unknown,
        )?;

        // Validate both serialized fields before installing the TLS session.
        // In particular, a malformed transport-parameter suffix must not
        // leave a usable resumption ticket configured on error.
        self.handshake.set_session(session_bytes.as_ref())?;
        self.process_peer_transport_params(peer_params)?;

        Ok(())
    }

    /// Sets the `max_idle_timeout` transport parameter, in milliseconds.
    ///
    /// This must only be called immediately after creating a connection, that
    /// is, before any packet is sent or received.
    ///
    /// The default value is infinite, that is, no timeout is used unless
    /// already configured when creating the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the updated transport parameters cannot be encoded
    /// or installed in the TLS handshake.
    pub fn set_max_idle_timeout(&mut self, v: u64) -> Result<()> {
        self.local_transport_params.max_idle_timeout =
            cmp::min(v, octets::MAX_VAR_INT);

        self.encode_transport_params()
    }

    /// Sets the congestion control algorithm used.
    ///
    /// This function can only be called inside one of `BoringSSL`'s handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_cc_algorithm()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS object has no associated QUIC
    /// handshake state.
    ///
    /// [`Config::set_cc_algorithm()`]: struct.Config.html#method.set_cc_algorithm
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn set_cc_algorithm_in_handshake(
        ssl: &mut btls::ssl::SslRef, algo: CongestionControlAlgorithm,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.cc_algorithm = algo;

        Ok(())
    }

    /// Sets custom BBR settings.
    ///
    /// This API is experimental and will be removed in the future.
    ///
    /// Currently this only applies if cc_algorithm is
    /// `CongestionControlAlgorithm::Bbr2Gcongestion` is set.
    ///
    /// This function can only be called inside one of BoringSSL's handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_custom_bbr_settings()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS object has no associated QUIC
    /// handshake state.
    ///
    /// [`Config::set_custom_bbr_settings()`]: struct.Config.html#method.set_custom_bbr_settings
    #[cfg(all(feature = "boringssl-btls-crate", feature = "internal"))]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    #[doc(hidden)]
    pub fn set_custom_bbr_settings_in_handshake(
        ssl: &mut btls::ssl::SslRef, custom_bbr_params: BbrParams,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.custom_bbr_params = Some(custom_bbr_params);

        Ok(())
    }

    /// Sets the congestion control algorithm used by string.
    ///
    /// This function can only be called inside one of `BoringSSL`'s handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_cc_algorithm_name()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::CongestionControl` for an unknown algorithm name, or
    /// `Error::TlsFail` if the TLS object has no associated QUIC handshake
    /// state.
    ///
    /// [`Config::set_cc_algorithm_name()`]: struct.Config.html#method.set_cc_algorithm_name
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn set_cc_algorithm_name_in_handshake(
        ssl: &mut btls::ssl::SslRef, name: &str,
    ) -> Result<()> {
        let cc_algo = CongestionControlAlgorithm::from_str(name)?;
        Self::set_cc_algorithm_in_handshake(ssl, cc_algo)
    }

    /// Sets initial congestion window size in terms of packet count.
    ///
    /// This function can only be called inside one of `BoringSSL`'s handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_initial_congestion_window_packets()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS object has no associated QUIC
    /// handshake state.
    ///
    /// [`Config::set_initial_congestion_window_packets()`]: struct.Config.html#method.set_initial_congestion_window_packets
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn set_initial_congestion_window_packets_in_handshake(
        ssl: &mut btls::ssl::SslRef, packets: usize,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.initial_congestion_window_packets = packets;

        Ok(())
    }

    /// Configure whether to enable relaxed loss detection on spurious loss.
    ///
    /// This function can only be called inside one of `BoringSSL`'s handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_enable_relaxed_loss_threshold()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS object has no associated QUIC
    /// handshake state.
    ///
    /// [`Config::set_enable_relaxed_loss_threshold()`]: struct.Config.html#method.set_enable_relaxed_loss_threshold
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn set_enable_relaxed_loss_threshold_in_handshake(
        ssl: &mut btls::ssl::SslRef, enable: bool,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.enable_relaxed_loss_threshold = enable;

        Ok(())
    }

    /// Configures whether to enable `HyStart`++.
    ///
    /// This function can only be called inside one of `BoringSSL`'s handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::enable_hystart()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS object has no associated QUIC
    /// handshake state.
    ///
    /// [`Config::enable_hystart()`]: struct.Config.html#method.enable_hystart
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn set_hystart_in_handshake(
        ssl: &mut btls::ssl::SslRef, v: bool,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.hystart = v;

        Ok(())
    }

    /// Configures whether to enable pacing.
    ///
    /// This function can only be called inside one of `BoringSSL`'s handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::enable_pacing()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS object has no associated QUIC
    /// handshake state.
    ///
    /// [`Config::enable_pacing()`]: struct.Config.html#method.enable_pacing
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn set_pacing_in_handshake(
        ssl: &mut btls::ssl::SslRef, v: bool,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.pacing = v;

        Ok(())
    }

    /// Sets the max value for pacing rate.
    ///
    /// This function can only be called inside one of `BoringSSL`'s handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_max_pacing_rate()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS object has no associated QUIC
    /// handshake state.
    ///
    /// [`Config::set_max_pacing_rate()`]: struct.Config.html#method.set_max_pacing_rate
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn set_max_pacing_rate_in_handshake(
        ssl: &mut btls::ssl::SslRef, v: Option<u64>,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.max_pacing_rate = v;

        Ok(())
    }

    /// Sets the maximum outgoing UDP payload size.
    ///
    /// This function can only be called inside one of `BoringSSL`'s handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_max_send_udp_payload_size()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS object has no associated QUIC
    /// handshake state.
    ///
    /// [`Config::set_max_send_udp_payload_size()`]: struct.Config.html#method.set_max_send_udp_payload_size
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn set_max_send_udp_payload_size_in_handshake(
        ssl: &mut btls::ssl::SslRef, v: usize,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.recovery_config.max_send_udp_payload_size =
            v.clamp(MIN_CLIENT_INITIAL_LEN, MAX_SEND_UDP_PAYLOAD_SIZE);

        Ok(())
    }

    /// Sets the send capacity factor.
    ///
    /// This function can only be called inside one of `BoringSSL`'s handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_send_capacity_factor()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS object has no associated QUIC
    /// handshake state.
    ///
    /// [`Config::set_send_capacity_factor()`]: struct.Config.html#method.set_send_capacity_factor
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn set_send_capacity_factor_in_handshake(
        ssl: &mut btls::ssl::SslRef, v: f64,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.tx_cap_factor = v;

        Ok(())
    }

    /// Configures whether to do path MTU discovery.
    ///
    /// This function can only be called inside one of `BoringSSL`'s handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::discover_pmtu()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS object has no associated QUIC
    /// handshake state.
    ///
    /// [`Config::discover_pmtu()`]: struct.Config.html#method.discover_pmtu
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn set_discover_pmtu_in_handshake(
        ssl: &mut btls::ssl::SslRef, discover: bool, max_probes: u8,
    ) -> Result<()> {
        let ex_data = tls::ExData::from_ssl_ref(ssl).ok_or(Error::TlsFail)?;

        ex_data.pmtud = Some((discover, max_probes));

        Ok(())
    }

    /// Sets the `max_idle_timeout` transport parameter, in milliseconds.
    ///
    /// This function can only be called inside one of `BoringSSL`'s handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_max_idle_timeout()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS object has no associated QUIC
    /// handshake state, or an encoding or TLS error when applying the updated
    /// transport parameters.
    ///
    /// [`Config::set_max_idle_timeout()`]: struct.Config.html#method.set_max_idle_timeout
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn set_max_idle_timeout_in_handshake(
        ssl: &mut btls::ssl::SslRef, v: u64,
    ) -> Result<()> {
        tls::update_transport_params_in_handshake(ssl, |params| {
            params.max_idle_timeout = cmp::min(v, octets::MAX_VAR_INT);
        })
    }

    /// Sets the `initial_max_streams_bidi` transport parameter.
    ///
    /// This function can only be called inside one of `BoringSSL`'s handshake
    /// callbacks, before any packet has been sent. Calling this function any
    /// other time will have no effect.
    ///
    /// See [`Config::set_initial_max_streams_bidi()`].
    ///
    /// # Errors
    ///
    /// Returns `Error::TlsFail` if the TLS object has no associated QUIC
    /// handshake state, or an encoding or TLS error when applying the updated
    /// transport parameters.
    ///
    /// [`Config::set_initial_max_streams_bidi()`]: struct.Config.html#method.set_initial_max_streams_bidi
    #[cfg(feature = "boringssl-btls-crate")]
    #[cfg_attr(docsrs, doc(cfg(feature = "boringssl-btls-crate")))]
    pub fn set_initial_max_streams_bidi_in_handshake(
        ssl: &mut btls::ssl::SslRef, v: u64,
    ) -> Result<()> {
        tls::update_transport_params_in_handshake(ssl, |params| {
            params.initial_max_streams_bidi = cmp::min(v, MAX_STREAM_COUNT);
        })
    }

    /// Processes QUIC packets received from the peer.
    ///
    /// On success the number of bytes processed from the input buffer is
    /// returned. On error the connection will be closed by calling [`close()`]
    /// with the appropriate error code.
    ///
    /// Coalesced packets will be processed as necessary.
    ///
    /// Note that the contents of the input buffer `buf` might be modified by
    /// this function due to, for example, in-place decryption.
    ///
    /// # Errors
    ///
    /// Returns `Error::BufferTooShort` for an empty input buffer. Packet,
    /// transport, and TLS processing errors are propagated; fatal processing
    /// errors initiate connection closure. Unauthenticated packets that can be
    /// silently discarded do not produce an error.
    ///
    /// [`close()`]: struct.Connection.html#method.close
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// loop {
    ///     let (read, from) = socket.recv_from(&mut buf).unwrap();
    ///
    ///     let recv_info = quiche::RecvInfo {
    ///         from,
    ///         to: local,
    ///     };
    ///
    ///     let read = match conn.recv(&mut buf[..read], recv_info) {
    ///         Ok(v) => v,
    ///
    ///         Err(e) => {
    ///             // An error occurred, handle it.
    ///             break;
    ///         },
    ///     };
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn recv(&mut self, buf: &mut [u8], info: RecvInfo) -> Result<usize> {
        self.recv_inner::<fn(&[u8]) -> bool>(buf, info, None)
    }

    /// Processes received QUIC packets while allowing DATAGRAM payloads to be
    /// consumed synchronously before they are copied into the receive queue.
    ///
    /// The handler returns true when it consumed the DATAGRAM. Returning false
    /// preserves normal behavior and queues an owned copy for
    /// `dgram_recv_buf()`. To preserve FIFO delivery, the handler is not called
    /// while an older DATAGRAM remains in the receive queue.
    ///
    /// Delivery through the handler is intentionally non-transactional at the
    /// packet level: the handler can be called for an earlier DATAGRAM before a
    /// later frame in the same authenticated packet makes this method return an
    /// error. This matches the normal receive path, which can queue earlier
    /// frames before a later-frame error. Callers that require transactional
    /// side effects should stage handler output until this method returns.
    ///
    /// # Errors
    ///
    /// Returns the same receive errors as [`Self::recv`]. Handler side effects
    /// are not rolled back if a later frame fails processing.
    pub fn recv_with_dgram_handler<H>(
        &mut self, buf: &mut [u8], info: RecvInfo, handler: &mut H,
    ) -> Result<usize>
    where
        H: FnMut(&[u8]) -> bool,
    {
        self.recv_inner(buf, info, Some(handler))
    }

    fn recv_inner<H>(
        &mut self, buf: &mut [u8], info: RecvInfo,
        mut dgram_handler: Option<&mut H>,
    ) -> Result<usize>
    where
        H: FnMut(&[u8]) -> bool,
    {
        let len = buf.len();

        if len == 0 {
            return Err(Error::BufferTooShort);
        }

        let recv_pid = self.paths.path_id_from_addrs(&(info.to, info.from));

        if let Some(recv_pid) = recv_pid {
            let recv_path = self.paths.get_mut(recv_pid)?;

            // Keep track of how many bytes we received from the client, so we
            // can limit bytes sent back before address validation, to a
            // multiple of this. The limit needs to be increased early on, so
            // that if there is an error there is enough credit to send a
            // CONNECTION_CLOSE.
            //
            // It doesn't matter if the packets received were valid or not, we
            // only need to track the total amount of bytes received.
            //
            // Note that we also need to limit the number of bytes we sent on a
            // path if we are not the host that initiated its usage.
            if self.is_server && !recv_path.verified_peer_address {
                recv_path.grant_amplification_credit(
                    len,
                    self.max_amplification_factor,
                );
            }
        } else if !self.is_server {
            // If a client receives packets from an unknown server address,
            // the client MUST discard these packets.
            trace!(
                "{} client received packet from unknown address {info:?}, dropping",
                self.trace_id,
            );

            return Ok(len);
        }

        let mut done = 0;
        let mut left = len;

        // Process coalesced packets.
        while left > 0 {
            let recv_result = match dgram_handler.as_mut() {
                Some(handler) => self.recv_single(
                    &mut buf[len - left..len],
                    &info,
                    recv_pid,
                    Some(&mut **handler),
                ),

                None => self.recv_single::<H>(
                    &mut buf[len - left..len],
                    &info,
                    recv_pid,
                    None,
                ),
            };

            let read = match recv_result {
                Ok(v) => v,

                Err(Error::Done) => {
                    // If the packet can't be processed or decrypted, check if
                    // it's a stateless reset.
                    if self.is_stateless_reset(&buf[len - left..len]) {
                        trace!("{} packet is a stateless reset", self.trace_id);

                        self.mark_closed(CloseCause::StatelessReset);
                    }

                    // Long header packets carry their own length. A failed
                    // packet must not hide a valid packet coalesced after it.
                    // Short headers and malformed lengths have no reliable
                    // boundary, so discard the rest of the datagram.
                    packet::long_header_packet_len(
                        &buf[len - left..len],
                        self.source_id().len(),
                    )
                    .unwrap_or(left)
                },

                Err(e) => {
                    // In case of error processing the incoming packet, close
                    // the connection.
                    self.close(false, e.to_wire(), b"").ok();
                    return Err(e);
                },
            };

            done += read;
            left -= read;
        }

        // Even though the packet was previously "accepted", it
        // should be safe to forward the error, as it also comes
        // from the `recv()` method.
        self.process_undecrypted_0rtt_packets()?;

        Ok(done)
    }

    fn process_undecrypted_0rtt_packets(&mut self) -> Result<()> {
        // Process previously undecryptable 0-RTT packets if the decryption key
        // is now available.
        if self.crypto_ctx[packet::Epoch::Application]
            .crypto_0rtt_open
            .is_some()
        {
            while let Some((mut pkt, info)) = self.undecryptable_pkts.pop_front()
            {
                if let Err(e) = self.recv(&mut pkt, info) {
                    self.undecryptable_pkts.clear();

                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Returns true if a QUIC packet is a stateless reset.
    fn is_stateless_reset(&self, buf: &[u8]) -> bool {
        // If the packet is too small, then we just throw it away.
        let buf_len = buf.len();
        if buf_len < 21 {
            return false;
        }

        // All live peer DCIDs can have different reset tokens, including IDs
        // learned after the handshake through NEW_CONNECTION_ID frames.
        self.ids.matches_reset_token(
            &buf[buf_len - size_of::<u128>()..],
            self.peer_transport_params.stateless_reset_token,
        )
    }

    /// Processes a single QUIC packet received from the peer.
    ///
    /// On success the number of bytes processed from the input buffer is
    /// returned. When the [`Done`] error is returned, processing of the
    /// remainder of the incoming UDP datagram should be interrupted.
    ///
    /// Note that a server might observe a new 4-tuple, preventing to
    /// know in advance to which path the incoming packet belongs to (`recv_pid`
    /// is `None`). As a client, packets from unknown 4-tuple are dropped
    /// beforehand (see `recv()`).
    ///
    /// On error, an error other than [`Done`] is returned.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    fn recv_single<H>(
        &mut self, buf: &mut [u8], info: &RecvInfo, recv_pid: Option<usize>,
        dgram_handler: Option<&mut H>,
    ) -> Result<usize>
    where
        H: FnMut(&[u8]) -> bool,
    {
        let now = Instant::now();

        if buf.is_empty() {
            return Err(Error::Done);
        }

        if self.is_closed() || self.is_draining() {
            return Err(Error::Done);
        }

        let is_closing = self.local_error.is_some();

        if is_closing {
            return Err(Error::Done);
        }

        let buf_len = buf.len();

        let mut b = octets::OctetsMut::with_slice(buf);

        let mut hdr = Header::from_mutable_cursor(&mut b, self.source_id().len())
            .map_err(|e| self.unauthenticated_rx_error(e))?;

        match hdr.ty {
            Type::VersionNegotiation => {
                self.recv_version_negotiation(hdr, now)?;
                return Err(Error::Done);
            },
            Type::Retry => {
                self.recv_retry(hdr, &b, now)?;
                return Err(Error::Done);
            },
            _ => (),
        }

        let payload_len = self.prepare_rx_packet(&hdr, &mut b)?;
        let opened = match self.authenticate_rx_packet(
            &mut b,
            &mut hdr,
            payload_len,
            info,
        )? {
            RxAuthentication::Buffered(read) => return Ok(read),
            RxAuthentication::Opened(packet) => packet,
        };

        // Only authenticated, nonduplicate packets can select or create paths.
        let recv_pid = if hdr.ty == Type::Short && self.got_peer_conn_id {
            let pkt_dcid = ConnectionId::from_ref(&hdr.dcid);
            self.get_or_create_recv_path_id(recv_pid, &pkt_dcid, buf_len, info)?
        } else {
            self.paths.get_active_path_id()?
        };

        let context = RxPacketContext {
            epoch: opened.epoch,
            pn: opened.pn,
            recv_pid,
            now,
            #[cfg(feature = "qlog")]
            packet_size: buf_len,
            #[cfg(feature = "qlog")]
            payload_len,
        };

        if let Some(next_keys) = opened.next_keys {
            let (open_next, seal_next) = *next_keys;
            self.commit_rx_key_update(&context, open_next, seal_next)?;
        }

        self.install_rx_peer_connection_id(&hdr, recv_pid)?;
        let effects = self.process_rx_payload(
            opened.payload,
            &hdr,
            &context,
            dgram_handler,
        )?;
        self.acknowledge_sent_frames(context.epoch, context.now);
        self.assign_missing_destination_ids()?;

        let read = b.off() + crypto::TAG_LEN;
        self.record_rx_packet(&context, hdr.ty, effects, read)?;

        Ok(read)
    }

    /// Handle an unauthenticated version negotiation packet.
    fn recv_version_negotiation(
        &mut self, hdr: Header<'static>, now: Instant,
    ) -> Result<()> {
        // Version negotiation packets can only be sent by the server.
        if self.is_server {
            return Err(Error::Done);
        }

        // Ignore duplicate version negotiation.
        if self.did_version_negotiation {
            return Err(Error::Done);
        }

        // Ignore version negotiation if any other packet has already been
        // successfully processed.
        if self.recv_count > 0 {
            return Err(Error::Done);
        }

        if &hdr.dcid != self.source_id() {
            return Err(Error::Done);
        }

        if &hdr.scid != self.destination_id() {
            return Err(Error::Done);
        }

        trace!("{} rx pkt {hdr:?}", self.trace_id);

        let versions = hdr.versions.ok_or(Error::Done)?;

        // Ignore version negotiation if the version already selected is
        // listed.
        if versions.contains(&self.version) {
            return Err(Error::Done);
        }

        let supported_versions =
            versions.iter().filter(|&&v| version_is_supported(v));

        let mut found_version = false;

        for &v in supported_versions {
            found_version = true;

            // The final version takes precedence over draft ones.
            if v == PROTOCOL_VERSION_V1 {
                self.version = v;
                break;
            }

            self.version = cmp::max(self.version, v);
        }

        if !found_version {
            // We don't support any of the versions offered.
            //
            // While a man-in-the-middle attacker might be able to
            // inject a version negotiation packet that triggers this
            // failure, the window of opportunity is very small and
            // this error is quite useful for debugging, so don't just
            // ignore the packet.
            return Err(Error::UnknownVersion);
        }

        self.did_version_negotiation = true;

        // Derive Initial secrets based on the new version.
        let (aead_open, aead_seal) = crypto::derive_initial_key_material(
            self.destination_id(),
            self.is_server,
            crypto::CounterInitialization::Prime,
        )?;

        self.restart_initial_exchange(aead_open, aead_seal, now)?;

        self.handshake
            .use_legacy_codepoint(self.version != PROTOCOL_VERSION_V1);

        // Encode transport parameters again, as the new version might be
        // using a different format.
        self.encode_transport_params()?;

        Ok(())
    }

    /// Authenticate Retry integrity and restart the Initial exchange.
    fn recv_retry(
        &mut self, hdr: Header<'static>, b: &octets::OctetsMut<'_>, now: Instant,
    ) -> Result<()> {
        // Retry packets can only be sent by the server.
        if self.is_server {
            return Err(Error::Done);
        }

        // Ignore duplicate retry.
        if self.did_retry {
            return Err(Error::Done);
        }

        // Check if Retry packet is valid.
        if packet::verify_retry_integrity(b, self.destination_id(), self.version)
            .is_err()
        {
            return Err(Error::Done);
        }

        trace!("{} rx pkt {hdr:?}", self.trace_id);

        self.token = hdr.token;
        self.did_retry = true;

        // Remember peer's new connection ID.
        self.odcid = Some(self.destination_id().clone());

        self.set_initial_dcid(
            hdr.scid.clone(),
            None,
            self.paths.get_active_path_id()?,
        )?;

        self.rscid = Some(self.destination_id().clone());

        // Derive Initial secrets using the new connection ID.
        let (aead_open, aead_seal) = crypto::derive_initial_key_material(
            &hdr.scid,
            self.is_server,
            crypto::CounterInitialization::Prime,
        )?;

        self.restart_initial_exchange(aead_open, aead_seal, now)?;

        Ok(())
    }

    /// Restart Initial packet protection after negotiation or Retry.
    fn restart_initial_exchange(
        &mut self, aead_open: crypto::Open, aead_seal: crypto::Seal, now: Instant,
    ) -> Result<()> {
        // Reset connection state to force sending another Initial packet.
        self.drop_epoch_state(packet::Epoch::Initial, now);
        self.got_peer_conn_id = false;
        self.handshake.clear()?;

        self.crypto_ctx[packet::Epoch::Initial].crypto_open = Some(aead_open);
        self.crypto_ctx[packet::Epoch::Initial].crypto_seal = Some(aead_seal);
        Ok(())
    }

    /// Validate version and wire length before opening the packet.
    fn prepare_rx_packet(
        &mut self, hdr: &Header<'_>, b: &mut octets::OctetsMut<'_>,
    ) -> Result<usize> {
        if self.is_server && !self.did_version_negotiation {
            if !version_is_supported(hdr.version) {
                return Err(Error::UnknownVersion);
            }

            self.version = hdr.version;
            self.did_version_negotiation = true;

            self.handshake
                .use_legacy_codepoint(self.version != PROTOCOL_VERSION_V1);

            // Encode transport parameters again, as the new version might be
            // using a different format.
            self.encode_transport_params()?;
        }

        if hdr.ty != Type::Short && hdr.version != self.version {
            // At this point version negotiation was already performed, so
            // ignore packets that don't match the connection's version.
            return Err(Error::Done);
        }

        // Long header packets have an explicit payload length, but short
        // packets don't so just use the remaining capacity in the buffer.
        let payload_len = if hdr.ty == Type::Short {
            b.cap()
        } else {
            let len = b
                .get_varint()
                .map_err(|e| self.unauthenticated_rx_error(e.into()))?;

            // Reject unrepresentable or oversized lengths before processing
            // the packet. A wire length must never wrap into a valid slice.
            usize::try_from(len)
                .ok()
                .filter(|&len| len <= b.cap())
                .ok_or_else(|| {
                    self.unauthenticated_rx_error(Error::InvalidPacket)
                })?
        };

        // Derive initial secrets on the server.
        if !self.derived_initial_secrets {
            let (aead_open, aead_seal) = crypto::derive_initial_key_material(
                &hdr.dcid,
                self.is_server,
                crypto::CounterInitialization::FirstPacket,
            )?;

            self.crypto_ctx[packet::Epoch::Initial].crypto_open = Some(aead_open);
            self.crypto_ctx[packet::Epoch::Initial].crypto_seal = Some(aead_seal);

            self.derived_initial_secrets = true;
        }

        Ok(payload_len)
    }

    /// Maps an `Error` to `Error::Done`, or itself.
    ///
    /// When a received packet that hasn't yet been authenticated triggers a
    /// failure it should, in most cases, be ignored, instead of raising a
    /// connection error, to avoid potential man-in-the-middle and
    /// man-on-the-side attacks.
    ///
    /// However, if no other packet was previously received, the connection
    /// should indeed be closed as the received packet might just be network
    /// background noise, and it shouldn't keep resources occupied indefinitely.
    ///
    /// This function maps an error to `Error::Done` to ignore a packet failure
    /// without aborting the connection, except when no other packet was
    /// previously received, in which case the error itself is returned, but
    /// only on the server-side as the client will already have armed the idle
    /// timer.
    ///
    /// This must only be used for errors preceding packet authentication.
    /// Failures happening after a packet has been authenticated should still
    /// cause the connection to be aborted.
    fn unauthenticated_rx_error(&self, e: Error) -> Error {
        // On the server, if no other packet has been successfully processed,
        // abort the connection to avoid keeping the connection open when only
        // junk is received.
        if self.is_server && self.recv_count == 0 {
            return e;
        }

        trace!("{} dropped invalid packet", self.trace_id);

        // Ignore other invalid packets that haven't been authenticated to
        // prevent man-in-the-middle and man-on-the-side attacks.
        Error::Done
    }

    /// Open a packet, retaining speculative keys until authentication succeeds.
    fn authenticate_rx_packet<'a>(
        &mut self, b: &'a mut octets::OctetsMut<'_>, hdr: &mut Header<'_>,
        payload_len: usize, info: &RecvInfo,
    ) -> Result<RxAuthentication<'a>> {
        // Select packet number space epoch based on the received packet's type.
        let epoch = hdr.ty.to_epoch()?;

        // Select AEAD context used to open incoming packet.
        let aead = if hdr.ty == Type::ZeroRTT {
            // Only use 0-RTT key if incoming packet is 0-RTT.
            self.crypto_ctx[epoch].crypto_0rtt_open.as_ref()
        } else {
            // Otherwise use the packet number space's main key.
            self.crypto_ctx[epoch].crypto_open.as_ref()
        };

        // Finally, discard packet if no usable key is available.
        let Some(mut aead) = aead else {
            if hdr.ty == Type::ZeroRTT &&
                self.undecryptable_pkts.len() < MAX_UNDECRYPTABLE_PACKETS &&
                !self.is_established()
            {
                // Buffer 0-RTT packets when the required read key is not
                // available yet, and process them later.
                //
                // TODO: in the future we might want to buffer other types
                // of undecryptable packets as well.
                let pkt_len = b.off() + payload_len;
                let pkt = (b.buf()[..pkt_len]).to_vec();

                self.undecryptable_pkts.push_back((pkt, *info));
                return Ok(RxAuthentication::Buffered(pkt_len));
            }

            let e = self.unauthenticated_rx_error(Error::CryptoFail);

            return Err(e);
        };

        packet::decrypt_hdr(b, hdr, aead)
            .map_err(|e| self.unauthenticated_rx_error(e))?;

        // RFC 9000 requires the reserved bits to be zero after header
        // protection is removed. Keep the value until packet protection has
        // been authenticated; only then can a peer be penalized for it.
        let reserved_bits = reserved_bits(b.buf()[0], hdr.ty);

        let pn = packet::decode_pkt_num(
            self.pkt_num_spaces[epoch].largest_rx_pkt_num,
            hdr.pkt_num,
            hdr.pkt_num_len,
        )
        .map_err(|e| self.unauthenticated_rx_error(e))?;

        let pn_len = hdr.pkt_num_len;

        trace!(
            "{} rx pkt {hdr:?} len={payload_len} pn={pn} {}",
            self.trace_id,
            AddrTupleFmt(info.from, info.to)
        );

        // Check for key update.
        let mut aead_next = None;

        if self.handshake_confirmed &&
            hdr.ty == Type::Short &&
            hdr.key_phase != self.key_phase
        {
            // Check if this packet arrived before key update.
            if let Some(key_update) = self.crypto_ctx[epoch]
                .key_update
                .as_ref()
                .and_then(|key_update| {
                    (pn < key_update.pn_on_update).then_some(key_update)
                })
            {
                aead = &key_update.crypto_open;
            } else {
                trace!("{} peer-initiated key update", self.trace_id);

                // Only Short packets carry the application key phase.
                // The selected current opening key is already known here.
                // Keep speculative keys separate until packet authentication.
                let next = (|| {
                    let seal = self.crypto_ctx[epoch]
                        .crypto_seal
                        .as_ref()
                        .ok_or(Error::CryptoFail)?;
                    Ok((
                        aead.derive_next_packet_key()?,
                        seal.derive_next_packet_key()?,
                    ))
                })()
                .map_err(|e| self.unauthenticated_rx_error(e))?;
                aead = &aead_next.insert(next).0;
            }
        }

        let payload = packet::decrypt_pkt(b, pn, pn_len, payload_len, aead)
            .map_err(|e| self.unauthenticated_rx_error(e))?;

        // Deliberately not routed through `unauthenticated_rx_error` like the
        // other fallible calls above: RFC 9000 requires the reserved bits to
        // cause a connection error (PROTOCOL_VIOLATION), but
        // `unauthenticated_rx_error` downgrades everything but a server's first
        // packet to `Error::Done`, which `recv()` treats as "silently ignore
        // this packet". Keeping this check bare, rather than harmonizing it
        // with its neighbors, preserves the MUST from the spec.
        if reserved_bits != 0 {
            return Err(Error::InvalidPacket);
        }

        if self.pkt_num_spaces[epoch].recv_pkt_num.contains(pn) {
            trace!("{} ignored duplicate packet {pn}", self.trace_id);
            return Err(Error::Done);
        }

        // Packets with no frames are invalid.
        if payload.cap() == 0 {
            return Err(Error::InvalidPacket);
        }

        Ok(RxAuthentication::Opened(OpenedRxPacket {
            epoch,
            pn,
            payload,
            next_keys: aead_next.map(Box::new),
        }))
    }

    /// Commit a peer key update only after authenticating with the new key.
    fn commit_rx_key_update(
        &mut self, context: &RxPacketContext, open_next: crypto::Open,
        seal_next: crypto::Seal,
    ) -> Result<()> {
        let RxPacketContext {
            epoch,
            pn,
            recv_pid,
            now,
            ..
        } = *context;
        if !self.crypto_ctx[epoch]
            .key_update
            .as_ref()
            .is_none_or(|prev| prev.update_acked)
        {
            // Peer has updated keys twice without awaiting confirmation.
            return Err(Error::KeyUpdate);
        }

        trace!("{} key update verified", self.trace_id);

        // Resolve all fallible prerequisites before changing key state.
        let recv_path = self.paths.get(recv_pid)?;
        let timer = now
            .checked_add(recv_path.recovery.pto().saturating_mul(3))
            .ok_or(Error::InvalidState)?;
        let ctx = &mut self.crypto_ctx[epoch];
        let open_prev = ctx.crypto_open.take().ok_or(Error::InvalidState)?;
        ctx.crypto_open = Some(open_next);
        ctx.crypto_seal = Some(seal_next);
        ctx.key_update = Some(packet::KeyUpdate {
            crypto_open: open_prev,
            pn_on_update: pn,
            update_acked: false,
            timer,
        });

        self.key_phase = !self.key_phase;

        qlog_with_type!(QLOG_PACKET_RX, self.qlog, q, {
            let trigger =
                Some(qlog::events::quic::KeyUpdateOrRetiredTrigger::RemoteUpdate);

            let ev_data_client =
                EventData::QuicKeyUpdated(qlog::events::quic::KeyUpdated {
                    key_type: qlog::events::quic::KeyType::Client1RttSecret,
                    trigger: trigger.clone(),
                    ..Default::default()
                });

            q.add_event_data_with_instant(ev_data_client, now).ok();

            let ev_data_server =
                EventData::QuicKeyUpdated(qlog::events::quic::KeyUpdated {
                    key_type: qlog::events::quic::KeyType::Server1RttSecret,
                    trigger,
                    ..Default::default()
                });

            q.add_event_data_with_instant(ev_data_server, now).ok();
        });
        Ok(())
    }

    /// Install the peer's initial connection ID and transport parameters.
    fn install_rx_peer_connection_id(
        &mut self, hdr: &Header<'static>, recv_pid: usize,
    ) -> Result<()> {
        if self.got_peer_conn_id {
            return Ok(());
        }

        if self.is_server {
            self.set_initial_dcid(hdr.scid.clone(), None, recv_pid)?;

            if !self.did_retry {
                self.local_transport_params
                    .original_destination_connection_id =
                    Some(ConnectionId::copy_from_slice(hdr.dcid.as_ref()));

                self.encode_transport_params()?;
            }
        } else {
            if self.odcid.is_none() {
                self.odcid = Some(self.destination_id().clone());
            }

            // Replace the randomly generated destination connection ID with
            // the one supplied by the server.
            self.set_initial_dcid(
                hdr.scid.clone(),
                self.peer_transport_params.stateless_reset_token,
                recv_pid,
            )?;
        }

        self.got_peer_conn_id = true;
        Ok(())
    }

    /// Parse authenticated frames, retaining packet-level effects for
    /// accounting.
    fn process_rx_payload<H>(
        &mut self, mut payload: octets::Octets<'_>, hdr: &Header<'_>,
        context: &RxPacketContext, mut dgram_handler: Option<&mut H>,
    ) -> Result<RxFrameEffects>
    where
        H: FnMut(&[u8]) -> bool,
    {
        let RxPacketContext {
            epoch,
            recv_pid,
            now,
            ..
        } = *context;
        #[cfg(feature = "qlog")]
        let mut qlog_frames = vec![];
        // To avoid sending an ACK in response to an ACK-only packet, we need
        // to keep track of whether this packet contains any frame other than
        // ACK and PADDING.
        let mut ack_elicited = false;

        // Process packet payload. If a frame cannot be processed, store the
        // error and stop further packet processing.
        let mut frame_processing_err = None;

        // To know if the peer migrated the connection, we need to keep track
        // whether this is a non-probing packet.
        let mut probing = true;

        // Process packet payload.
        while payload.cap() > 0 {
            let frame = if let Some(handler) = dgram_handler.as_mut() {
                // Decode the frame type only once. DATAGRAM payloads can then
                // be consumed in place before the receive buffer is reused,
                // while every other frame follows the normal parser path.
                let frame_type = frame::read_frame_type(&mut payload, hdr.ty)?;

                if matches!(frame_type, 0x30 | 0x31) {
                    let data =
                        frame::parse_datagram_payload(frame_type, &mut payload)?;

                    qlog_with_type!(QLOG_PACKET_RX, self.qlog, _q, {
                        qlog_frames.push(
                            frame::Frame::DatagramHeader {
                                length: data.buf().len(),
                            }
                            .to_qlog(
                                self.peer_transport_params.ack_delay_exponent,
                            ),
                        );
                    });

                    ack_elicited = true;
                    probing = false;

                    if let Err(e) = self.process_direct_datagram(
                        data.buf(),
                        recv_pid,
                        &mut **handler,
                    ) {
                        frame_processing_err = Some(e);
                        break;
                    }

                    continue;
                }

                frame::Frame::from_bytes_with_type(frame_type, &mut payload)?
            } else {
                frame::Frame::from_bytes(&mut payload, hdr.ty)?
            };

            qlog_with_type!(QLOG_PACKET_RX, self.qlog, _q, {
                qlog_frames.push(
                    frame.to_qlog(self.peer_transport_params.ack_delay_exponent),
                );
            });

            if frame.ack_eliciting() {
                ack_elicited = true;
            }

            if !frame.probing() {
                probing = false;
            }

            if let Err(e) = self.process_frame(frame, hdr, recv_pid, epoch, now) {
                frame_processing_err = Some(e);
                break;
            }
        }

        #[cfg(feature = "qlog")]
        self.log_rx_packet(hdr, context, qlog_frames)?;

        if let Some(e) = frame_processing_err {
            // Any frame error is terminal, so now just return.
            return Err(e);
        }

        #[cfg(feature = "qlog")]
        self.log_peer_transport_params(now);

        Ok(RxFrameEffects {
            ack_elicited,
            probing,
        })
    }

    #[cfg(feature = "qlog")]
    fn log_rx_packet(
        &mut self, hdr: &Header<'_>, context: &RxPacketContext,
        qlog_frames: Vec<qlog::events::quic::QuicFrame>,
    ) -> Result<()> {
        let RxPacketContext {
            pn,
            packet_size,
            payload_len,
            recv_pid,
            now,
            ..
        } = *context;
        qlog_with_type!(QLOG_PACKET_RX, self.qlog, q, {
            let qlog_pkt_hdr = qlog::events::quic::PacketHeader::with_type(
                hdr.ty.to_qlog(),
                Some(pn),
                Some(hdr.version),
                Some(&hdr.scid),
                Some(&hdr.dcid),
            );

            let qlog_raw_info = RawInfo {
                length: Some(packet_size as u64),
                payload_length: Some(payload_len as u64),
                data: None,
            };

            let ev_data = EventData::QuicPacketReceived(
                qlog::events::quic::PacketReceived {
                    header: qlog_pkt_hdr,
                    frames: Some(qlog_frames),
                    raw: Some(qlog_raw_info),
                    ..Default::default()
                },
            );

            q.add_event_data_with_instant(ev_data, now).ok();
        });

        qlog_with_type!(QLOG_METRICS, self.qlog, q, {
            let recv_path = self.paths.get_mut(recv_pid)?;
            recv_path.recovery.maybe_qlog(q, now);
        });

        Ok(())
    }

    #[cfg(feature = "qlog")]
    fn log_peer_transport_params(&mut self, now: Instant) {
        // Only log the remote transport parameters once the connection is
        // established (i.e. after frames have been fully parsed) and only
        // once per connection.
        if self.is_established() {
            qlog_with_type!(QLOG_PARAMS_SET, self.qlog, q, {
                if !self.qlog.logged_peer_params {
                    let ev_data = self.peer_transport_params.to_qlog(
                        TransportInitiator::Remote,
                        self.handshake.cipher(),
                    );

                    q.add_event_data_with_instant(ev_data, now).ok();

                    self.qlog.logged_peer_params = true;
                }
            });
        }
    }

    /// Retire acknowledged frames across every path in the packet number space.
    fn acknowledge_sent_frames(&mut self, epoch: packet::Epoch, now: Instant) {
        #[cfg(not(feature = "qlog"))]
        let _ = now;
        // Process acked frames. Note that several packets from several paths
        // might have been acked by the received packet.
        let (paths, path_events) = self.paths.iter_mut_and_events();
        for (_, p) in paths {
            while let Some(acked) = p.recovery.next_acked_frame(epoch) {
                match acked {
                    frame::Frame::Ping {
                        mtu_probe: Some(mtu_probe),
                    } => {
                        Self::acknowledge_pmtu_probe(
                            p,
                            path_events,
                            mtu_probe,
                            &self.trace_id,
                            #[cfg(feature = "qlog")]
                            &mut self.qlog,
                            #[cfg(feature = "qlog")]
                            now,
                        );
                    },

                    frame::Frame::ACK { ranges, .. } => {
                        // Stop acknowledging packets less than or equal to the
                        // largest acknowledged in the sent ACK frame that, in
                        // turn, got acked.
                        if let Some(largest_acked) = ranges.last() {
                            self.pkt_num_spaces[epoch]
                                .recv_pkt_need_ack
                                .remove_until(largest_acked);
                        }
                    },

                    frame::Frame::CryptoHeader { offset, length } => {
                        self.crypto_ctx[epoch]
                            .crypto_stream
                            .send
                            .ack_and_drop(offset, length);
                    },

                    frame::Frame::StreamHeader {
                        stream_id,
                        offset,
                        length,
                        fin,
                    } => {
                        // Emit qlog before checking if the stream still exists.
                        // The client does need to ACK frames that were received
                        // after the client sends a ResetStream.

                        qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
                            let ev_data = EventData::QuicStreamDataMoved(
                                qlog::events::quic::StreamDataMoved {
                                    stream_id: Some(stream_id),
                                    offset: Some(offset),
                                    raw: Some(RawInfo {
                                        length: Some(length as u64),
                                        ..Default::default()
                                    }),
                                    from: Some(DataRecipient::Transport),
                                    to: Some(DataRecipient::Dropped),
                                    ..Default::default()
                                },
                            );

                            q.add_event_data_with_instant(ev_data, now).ok();
                        });

                        let Some(stream) = self.streams.get_mut(stream_id) else {
                            continue;
                        };

                        let dropped = stream.send.ack_and_drop(offset, length);

                        if fin {
                            stream.send.ack_fin();
                        }

                        self.streams.try_collect(stream_id);

                        // Update `tx_buffered` for data dropped from stream
                        // buffers, such as retransmission data acknowledged
                        // before it could be resent.
                        if dropped > 0 {
                            self.streams.sub_tx_buffered(dropped);
                        }
                    },

                    frame::Frame::HandshakeDone => {
                        // An acknowledgment cancels any scheduled
                        // retransmission.
                        self.handshake_done = HandshakeDoneState::Acknowledged;
                    },

                    frame::Frame::ResetStream { stream_id, .. } => {
                        self.streams.try_collect(stream_id);
                    },

                    _ => (),
                }
            }
        }
    }

    /// Apply a successful path MTU probe before advertising the new datagram
    /// size.
    fn acknowledge_pmtu_probe(
        p: &mut path::Path, path_events: &mut VecDeque<PathEvent>,
        mtu_probe: usize, trace_id: &str,
        #[cfg(feature = "qlog")] qlog: &mut QlogInfo,
        #[cfg(feature = "qlog")] now: Instant,
    ) {
        trace!("{trace_id} pmtud probe acked; probe size {mtu_probe:?}");

        let local = p.local_addr();
        let peer = p.peer_addr();
        if let Some(pmtud) = p.pmtud.as_mut() {
            let old_pmtu = pmtud.get_current_mtu();
            let current_mtu = pmtud.successful_probe(mtu_probe);
            let new_pmtu = pmtud.get_current_mtu();

            // Update the datagram size only after validating
            // the MTU.
            if let Some(current_mtu) = current_mtu {
                qlog_with_type!(
                    EventType::QuicEventType(QuicEventType::MtuUpdated),
                    qlog,
                    q,
                    {
                        let pmtu_data = EventData::QuicMtuUpdated(
                            qlog::events::quic::MtuUpdated {
                                old: Some(
                                    u32::try_from(p.recovery.max_datagram_size())
                                        .unwrap_or(u32::MAX),
                                ),
                                new: u32::try_from(current_mtu)
                                    .unwrap_or(u32::MAX),
                                done: Some(true),
                            },
                        );

                        q.add_event_data_with_instant(pmtu_data, now).ok();
                    }
                );

                p.recovery.pmtud_update_max_datagram_size(current_mtu);
            }

            if let Some(event) = path::pmtu_event(local, peer, old_pmtu, new_pmtu)
            {
                path_events.push_back(event);
            }
        }
    }

    /// Assign destination CIDs to paths waiting for one.
    fn assign_missing_destination_ids(&mut self) -> Result<()> {
        // Now that we processed all the frames, if there is a path that has no
        // Destination CID, try to allocate one.
        let no_dcid = self
            .paths
            .iter_mut()
            .filter(|(_, p)| p.active_dcid_seq.is_none());

        for (pid, p) in no_dcid {
            if self.ids.zero_length_dcid() {
                p.active_dcid_seq = Some(0);
                continue;
            }

            let Some(dcid_seq) = self.ids.lowest_available_dcid_seq() else {
                break;
            };

            self.ids.link_dcid_to_path_id(dcid_seq, pid)?;

            p.active_dcid_seq = Some(dcid_seq);
        }

        Ok(())
    }

    /// Publish successful packet effects only after its frames are processed.
    fn record_rx_packet(
        &mut self, context: &RxPacketContext, packet_type: Type,
        effects: RxFrameEffects, read: usize,
    ) -> Result<()> {
        let RxPacketContext {
            epoch,
            pn,
            recv_pid,
            now,
            ..
        } = *context;
        let RxFrameEffects {
            ack_elicited,
            probing,
        } = effects;
        // We only record the time of arrival of the largest packet number
        // that still needs to be acked, to be used for ACK delay calculation.
        if self.pkt_num_spaces[epoch].recv_pkt_need_ack.last() < Some(pn) {
            self.pkt_num_spaces[epoch].largest_rx_pkt_time = now;
        }

        self.pkt_num_spaces[epoch].recv_pkt_num.insert(pn);

        self.pkt_num_spaces[epoch].recv_pkt_need_ack.push_item(pn);

        self.pkt_num_spaces[epoch].ack_elicited =
            cmp::max(self.pkt_num_spaces[epoch].ack_elicited, ack_elicited);

        self.pkt_num_spaces[epoch].largest_rx_pkt_num =
            self.pkt_num_spaces[epoch].largest_rx_pkt_num.max(Some(pn));

        if !probing {
            self.pkt_num_spaces[epoch].largest_rx_non_probing_pkt_num = cmp::max(
                self.pkt_num_spaces[epoch].largest_rx_non_probing_pkt_num,
                pn,
            );

            // Did the peer migrated to another path?
            let active_path_id = self.paths.get_active_path_id()?;

            if self.is_server &&
                recv_pid != active_path_id &&
                self.pkt_num_spaces[epoch].largest_rx_non_probing_pkt_num == pn
            {
                self.on_peer_migrated(recv_pid, self.disable_dcid_reuse, now)?;
            }
        }

        if let Some(idle_timeout) = self.idle_timeout() {
            self.idle_timer = now.checked_add(idle_timeout);
        }

        // Update send capacity.
        self.update_tx_cap();

        self.recv_count += 1;
        self.paths.get_mut(recv_pid)?.recv_count += 1;

        self.recv_bytes += read as u64;
        self.paths.get_mut(recv_pid)?.recv_bytes += read as u64;

        // An Handshake packet has been received from the client and has been
        // successfully processed, so we can drop the initial state and consider
        // the client's address to be verified.
        if self.is_server && packet_type == Type::Handshake {
            self.drop_epoch_state(packet::Epoch::Initial, now);

            self.paths.get_mut(recv_pid)?.verified_peer_address = true;
        }

        self.ack_eliciting_sent = false;

        Ok(())
    }

    /// Writes a single QUIC packet to be sent to the peer.
    ///
    /// On success the number of bytes written to the output buffer is
    /// returned, or [`Done`] if there was nothing to write.
    ///
    /// The application should call `send()` multiple times until [`Done`] is
    /// returned, indicating that there are no more packets to send. It is
    /// recommended that `send()` be called in the following cases:
    ///
    ///  * When the application receives QUIC packets from the peer (that is,
    ///    any time [`recv()`] is also called).
    ///
    ///  * When the connection timer expires (that is, any time [`on_timeout()`]
    ///    is also called).
    ///
    ///  * When the application sends data to the peer (for example, any time
    ///    [`stream_send()`] or [`stream_shutdown()`] are called).
    ///
    ///  * When the application receives data from the peer (for example any
    ///    time [`stream_recv()`] is called).
    ///
    /// Once [`is_draining()`] returns `true`, it is no longer necessary to call
    /// `send()` and all calls will return [`Done`].
    ///
    /// # Errors
    ///
    /// Returns `Error::Done` when no packet can currently be emitted,
    /// `Error::BufferTooShort` for an empty output buffer, or a path, TLS, or
    /// packet-generation error.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`recv()`]: struct.Connection.html#method.recv
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    /// [`stream_send()`]: struct.Connection.html#method.stream_send
    /// [`stream_shutdown()`]: struct.Connection.html#method.stream_shutdown
    /// [`stream_recv()`]: struct.Connection.html#method.stream_recv
    /// [`is_draining()`]: struct.Connection.html#method.is_draining
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut out = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// loop {
    ///     let (write, send_info) = match conn.send(&mut out) {
    ///         Ok(v) => v,
    ///
    ///         Err(quiche::Error::Done) => {
    ///             // Done writing.
    ///             break;
    ///         },
    ///
    ///         Err(e) => {
    ///             // An error occurred, handle it.
    ///             break;
    ///         },
    ///     };
    ///
    ///     socket.send_to(&out[..write], &send_info.to).unwrap();
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn send(&mut self, out: &mut [u8]) -> Result<(usize, SendInfo)> {
        self.send_on_path(out, None, None)
    }

    /// Writes a single QUIC packet to be sent to the peer from the specified
    /// local address `from` to the destination address `to`.
    ///
    /// The behavior of this method differs depending on the value of the `from`
    /// and `to` parameters:
    ///
    ///  * If both are `Some`, then the method only consider the 4-tuple
    ///    (`from`, `to`). Application can monitor the 4-tuple availability,
    ///    either by monitoring [`path_event_next()`] events or by relying on
    ///    the [`paths_iter()`] method. If the provided 4-tuple does not exist
    ///    on the connection (anymore), it returns an [`InvalidState`].
    ///
    ///  * If `from` is `Some` and `to` is `None`, then the method only
    ///    considers sending packets on paths having `from` as local address.
    ///
    ///  * If `to` is `Some` and `from` is `None`, then the method only
    ///    considers sending packets on paths having `to` as peer address.
    ///
    ///  * If both are `None`, all available paths are considered.
    ///
    /// On success the number of bytes written to the output buffer is
    /// returned, or [`Done`] if there was nothing to write.
    ///
    /// The application should call `send_on_path()` multiple times until
    /// [`Done`] is returned, indicating that there are no more packets to
    /// send. It is recommended that `send_on_path()` be called in the
    /// following cases:
    ///
    ///  * When the application receives QUIC packets from the peer (that is,
    ///    any time [`recv()`] is also called).
    ///
    ///  * When the connection timer expires (that is, any time [`on_timeout()`]
    ///    is also called).
    ///
    ///  * When the application sends data to the peer (for examples, any time
    ///    [`stream_send()`] or [`stream_shutdown()`] are called).
    ///
    ///  * When the application receives data from the peer (for example any
    ///    time [`stream_recv()`] is called).
    ///
    /// Once [`is_draining()`] returns `true`, it is no longer necessary to call
    /// `send_on_path()` and all calls will return [`Done`].
    ///
    /// # Errors
    ///
    /// Returns the same send errors as [`Self::send`], including
    /// `Error::InvalidState` if an explicitly requested path does not exist.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`InvalidState`]: enum.Error.html#InvalidState
    /// [`recv()`]: struct.Connection.html#method.recv
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    /// [`stream_send()`]: struct.Connection.html#method.stream_send
    /// [`stream_shutdown()`]: struct.Connection.html#method.stream_shutdown
    /// [`stream_recv()`]: struct.Connection.html#method.stream_recv
    /// [`path_event_next()`]: struct.Connection.html#method.path_event_next
    /// [`paths_iter()`]: struct.Connection.html#method.paths_iter
    /// [`is_draining()`]: struct.Connection.html#method.is_draining
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut out = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// loop {
    ///     let (write, send_info) = match conn.send_on_path(&mut out, Some(local), Some(peer)) {
    ///         Ok(v) => v,
    ///
    ///         Err(quiche::Error::Done) => {
    ///             // Done writing.
    ///             break;
    ///         },
    ///
    ///         Err(e) => {
    ///             // An error occurred, handle it.
    ///             break;
    ///         },
    ///     };
    ///
    ///     socket.send_to(&out[..write], &send_info.to).unwrap();
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn send_on_path(
        &mut self, out: &mut [u8], from: Option<SocketAddr>,
        to: Option<SocketAddr>,
    ) -> Result<(usize, SendInfo)> {
        self.send_on_path_into(
            &mut packet::PacketWriter::from_initialized(out),
            from,
            to,
        )
    }

    fn send_on_path_into(
        &mut self, out: &mut packet::PacketWriter<'_>, from: Option<SocketAddr>,
        to: Option<SocketAddr>,
    ) -> Result<(usize, SendInfo)> {
        if out.cap() == 0 {
            return Err(Error::BufferTooShort);
        }

        if self.is_closed() || self.is_draining() {
            return Err(Error::Done);
        }

        if self.next_pkt_num >= octets::MAX_VAR_INT {
            self.mark_closed(CloseCause::PacketNumbersExhausted);
            return Err(Error::Done);
        }

        let now = Instant::now();

        if self.local_error.is_none() {
            self.do_handshake(now)?;
        }

        // Forwarding the error value here could confuse
        // applications, as they may not expect getting a `recv()`
        // error when calling `send()`.
        //
        // We simply fall-through to sending packets, which should
        // take care of terminating the connection as needed.
        let _ = self.process_undecrypted_0rtt_packets();

        // There's no point in trying to send a packet if the Initial secrets
        // have not been derived yet, so return early.
        if !self.derived_initial_secrets {
            return Err(Error::Done);
        }

        let mut has_initial = false;

        let mut done = 0;

        let send_pid = match (from, to) {
            (Some(f), Some(t)) => self
                .paths
                .path_id_from_addrs(&(f, t))
                .ok_or(Error::InvalidState)?,

            _ => self.get_send_path_id(from, to)?,
        };

        let send_path = self.paths.get_mut(send_pid)?;

        let peer_limit =
            usize::try_from(self.peer_transport_params.max_udp_payload_size)
                .unwrap_or(usize::MAX)
                .min(MAX_SEND_UDP_PAYLOAD_SIZE);
        let handshake_ready =
            self.handshake_confirmed && self.handshake_completed;
        let mut limit = if self.handshake_completed {
            send_path.recovery.max_datagram_size().min(peer_limit)
        } else {
            MIN_CLIENT_INITIAL_LEN
        };

        // Reserve output space for a probe without raising the congestion
        // controller's confirmed datagram size before an ACK.
        if let Some(pmtud) = send_path.pmtud.as_mut() {
            if handshake_ready {
                pmtud.limit_maximum(peer_limit);
            }
            limit = pmtud.get_current_mtu().min(peer_limit);
            if send_path.recovery.max_datagram_size() != limit {
                send_path.recovery.pmtud_update_max_datagram_size(limit);
            }
            if handshake_ready && pmtud.should_probe() {
                limit = limit.max(pmtud.get_probe_size().min(peer_limit));
            }
        }

        let mut left = out.cap().min(limit);

        // Limit data sent by the server based on the amount of data received
        // from the client before its address is validated.
        if !send_path.verified_peer_address && self.is_server {
            left = cmp::min(left, send_path.max_send_bytes);
        }

        // Generate coalesced packets.
        while left > 0 {
            let (ty, written) = match out.with_limit(left, |packet| {
                self.send_single(packet, send_pid, has_initial, now)
            }) {
                Ok(v) => v,

                Err(Error::BufferTooShort | Error::Done) => break,

                Err(e) => return Err(e),
            };

            done += written;
            left -= written;

            if self.is_closed() {
                // The final allowed packet has already been serialized.
                has_initial |= ty == Type::Initial;
                break;
            }

            match ty {
                Type::Initial => has_initial = true,

                // No more packets can be coalesced after a 1-RTT.
                Type::Short => break,

                _ => (),
            }

            // When sending multiple PTO probes, don't coalesce them together,
            // so they are sent on separate UDP datagrams.
            if let Ok(epoch) = ty.to_epoch() {
                if self.paths.get_mut(send_pid)?.recovery.loss_probes(epoch) > 0 {
                    break;
                }
            }

            // Don't coalesce packets that must go on different paths.
            if !(from.is_some() && to.is_some()) &&
                self.get_send_path_id(from, to)? != send_pid
            {
                break;
            }
        }

        if done == 0 {
            self.last_tx_data = self.tx_data;

            return Err(Error::Done);
        }

        if has_initial && left > 0 && done < MIN_CLIENT_INITIAL_LEN {
            let pad_len = cmp::min(left, MIN_CLIENT_INITIAL_LEN - done);

            // Fill padding area with null bytes, to avoid leaking information
            // in case the application reuses the packet buffer.
            frame::FrameSink::put_padding(out, pad_len)?;

            done += pad_len;
        }

        let send_path = self.paths.get(send_pid)?;

        let info = SendInfo {
            from: send_path.local_addr(),
            to: send_path.peer_addr(),

            at: send_path.recovery.get_packet_send_time(now),
        };

        Ok((done, info))
    }

    fn send_single(
        &mut self, out: &mut packet::PacketWriter<'_>, send_pid: usize,
        has_initial: bool, now: Instant,
    ) -> Result<(Type, usize)> {
        if out.cap() == 0 {
            return Err(Error::BufferTooShort);
        }

        if self.is_closed() || self.is_draining() {
            return Err(Error::Done);
        }

        let has_loss_probe = {
            let send_path = self.paths.get(send_pid)?;

            packet::Epoch::epochs(
                packet::Epoch::Initial..=packet::Epoch::Application,
            )
            .iter()
            .any(|&epoch| send_path.recovery.loss_probes(epoch) > 0)
        };

        if self.local_error.is_none() {
            for &epoch in packet::Epoch::epochs(
                packet::Epoch::Initial..=packet::Epoch::Application,
            ) {
                let has_probe = self.crypto_ctx[epoch].crypto_seal.is_some() &&
                    self.paths.get(send_pid)?.recovery.loss_probes(epoch) > 0;

                if !has_probe {
                    continue;
                }

                match self.send_single_for_type(
                    out,
                    send_pid,
                    has_initial,
                    now,
                    Type::from_epoch(epoch),
                    true,
                ) {
                    Err(Error::Done) => (),

                    result => return result,
                }
            }
        }

        let pkt_type = self.write_pkt_type(send_pid)?;
        let epoch = pkt_type.to_epoch()?;
        let bypass_cwnd = self.paths.get(send_pid)?.recovery.loss_probes(epoch) >
            0 ||
            (self.local_error.is_some() && has_loss_probe);

        self.send_single_for_type(
            out,
            send_pid,
            has_initial,
            now,
            pkt_type,
            bypass_cwnd,
        )
    }

    /// Consume loss notifications across paths and restore pending frame state
    /// before packet construction. This does not write to the packet buffer.
    fn requeue_lost_frames(
        &mut self, epoch: packet::Epoch, now: Instant,
    ) -> Result<()> {
        #[cfg(not(feature = "qlog"))]
        let _ = now;

        let pkt_space = &mut self.pkt_num_spaces[epoch];
        let crypto_ctx = &mut self.crypto_ctx[epoch];

        // Process lost frames. There might be several paths having lost frames.
        let (paths, path_events) = self.paths.iter_mut_and_events();
        for (_, p) in paths {
            while let Some(lost) = p.recovery.next_lost_frame(epoch) {
                match lost {
                    frame::Frame::CryptoHeader { offset, length } => {
                        crypto_ctx.crypto_stream.send.retransmit(offset, length);
                    },

                    frame::Frame::StreamHeader {
                        stream_id,
                        offset,
                        length,
                        fin,
                    } => {
                        let stream = match self.streams.get_mut(stream_id) {
                            // Only retransmit data if the stream is not closed
                            // or stopped.
                            Some(v) if !v.send.is_stopped() => v,

                            // Data on a closed stream will not be retransmitted
                            // or acked after it is declared lost, so just drop
                            // it.
                            _ => {
                                qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
                                    let ev_data = EventData::QuicStreamDataMoved(
                                        qlog::events::quic::StreamDataMoved {
                                            stream_id: Some(stream_id),
                                            offset: Some(offset),
                                            raw: Some(RawInfo {
                                                length: Some(length as u64),
                                                ..Default::default()
                                            }),
                                            from: Some(DataRecipient::Transport),
                                            to: Some(DataRecipient::Dropped),
                                            ..Default::default()
                                        },
                                    );

                                    q.add_event_data_with_instant(ev_data, now)
                                        .ok();
                                });

                                continue;
                            },
                        };

                        let was_flushable = stream.is_flushable();

                        let retransmitted =
                            stream.send.retransmit(offset, length);

                        if fin {
                            stream.send.retransmit_fin();
                        }

                        // If the stream is now flushable push it to the
                        // flushable queue, but only if it wasn't already
                        // queued.
                        if stream.is_flushable() && !was_flushable {
                            let priority_key = Arc::clone(stream.priority_key());
                            self.streams.enqueue(
                                &priority_key,
                                stream::PriorityQueue::Flushable,
                            );
                        }

                        // Update tx_buffered when data is marked for
                        // retransmission (it was decremented when emitted).
                        // Only increment by the actual amount retransmitted,
                        // which may be less than `length` if some data was
                        // already acked.
                        self.streams.add_tx_buffered(retransmitted);
                    },

                    frame::Frame::ACK { .. } => {
                        pkt_space.ack_elicited = true;
                    },

                    frame::Frame::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    } => {
                        self.streams
                            .insert_reset(stream_id, error_code, final_size);
                    },

                    frame::Frame::StopSending {
                        stream_id,
                        error_code,
                    } =>
                    // We only need to retransmit the STOP_SENDING frame if
                    // the stream is still active and not FIN'd. Even if the
                    // packet was lost, if the application has the final
                    // size at this point there is no need to retransmit.
                        if let Some(stream) = self.streams.get(stream_id) {
                            if !stream.recv.is_fin() {
                                self.streams
                                    .insert_stopped(stream_id, error_code);
                            }
                        },

                    // Retransmit HANDSHAKE_DONE only if it hasn't been acked at
                    // least once already.
                    frame::Frame::HandshakeDone =>
                        if self.handshake_done == HandshakeDoneState::InFlight {
                            self.handshake_done = HandshakeDoneState::Pending;
                        },

                    frame::Frame::MaxStreamData { stream_id, .. } => {
                        if self.streams.get(stream_id).is_some() {
                            self.streams.insert_almost_full(stream_id);
                        }
                    },

                    frame::Frame::MaxData { .. } => {
                        self.should_send_max_data = true;
                    },

                    frame::Frame::MaxStreamsUni { .. } => {
                        self.should_send_max_streams_uni = true;
                    },

                    frame::Frame::MaxStreamsBidi { .. } => {
                        self.should_send_max_streams_bidi = true;
                    },

                    // Retransmit STREAMS_BLOCKED frames if the frame with the
                    // most recent limit is lost.  These are informational
                    // signals to the peer, reliably sending them
                    // ensures the signal is used consistently and helps
                    // debugging.
                    frame::Frame::StreamsBlockedBidi { limit } => {
                        self.streams_blocked_bidi_state
                            .force_retransmit_sent_limit_eq(limit);
                    },

                    frame::Frame::StreamsBlockedUni { limit } => {
                        self.streams_blocked_uni_state
                            .force_retransmit_sent_limit_eq(limit);
                    },

                    frame::Frame::NewConnectionId { seq_num, .. } => {
                        self.ids.mark_advertise_new_scid_seq(seq_num, true);
                    },

                    frame::Frame::RetireConnectionId { seq_num } => {
                        self.ids.mark_retire_dcid_seq(seq_num, true)?;
                    },

                    frame::Frame::Ping { mtu_probe } => {
                        // Ping frames are not retransmitted.
                        if let Some(failed_probe) = mtu_probe {
                            trace!("pmtud probe dropped: {failed_probe}");

                            let local = p.local_addr();
                            let peer = p.peer_addr();
                            if let Some(pmtud) = p.pmtud.as_mut() {
                                let old_pmtu = pmtud.get_current_mtu();
                                pmtud.failed_probe(failed_probe);
                                let new_pmtu = pmtud.get_current_mtu();

                                if let Some(event) = path::pmtu_event(
                                    local, peer, old_pmtu, new_pmtu,
                                ) {
                                    p.recovery
                                        .pmtud_update_max_datagram_size(new_pmtu);
                                    path_events.push_back(event);
                                }
                            }
                        }
                    },

                    // Sent as StreamHeader frames. Stream frames are never
                    // generated by quiche.
                    frame::Frame::Stream { .. } => {
                        debug_assert!(
                            false,
                            "Unexpected frame lost: Stream. quiche should \
                             have tracked retransmittable stream data as \
                             StreamHeader frames."
                        );
                    },

                    // Sent as CryptoHeader frames. Crypto frames are never
                    // generated by quiche.
                    frame::Frame::Crypto { .. } => {
                        debug_assert!(
                            false,
                            "Unexpected frame lost: Crypto. quiche should \
                             have tracked retransmittable crypto data as \
                             CryptoHeader frames."
                        );
                    },

                    // NewToken frames are never sent by quiche; they are not
                    // implemented.
                    frame::Frame::NewToken { .. } => {
                        debug_assert!(
                            false,
                            "Unexpected frame lost: NewToken. quiche used to \
                             not implement NewToken frames, retransmission of \
                             these frames is not implemented."
                        );
                    },

                    // Advisory blocked frames are not retransmitted.
                    // Path challenges and responses have their own retry logic
                    // (RFC 9000, section 8.2.2).
                    // Connection close retransmission is governed by closing
                    // state, not packet loss (sections 10 and 13.3).
                    // Padding never needs retransmission.
                    frame::Frame::DataBlocked { .. } |
                    frame::Frame::StreamDataBlocked { .. } |
                    frame::Frame::PathChallenge { .. } |
                    frame::Frame::PathResponse { .. } |
                    frame::Frame::ConnectionClose { .. } |
                    frame::Frame::ApplicationClose { .. } |
                    frame::Frame::Padding { .. } => (),

                    frame::Frame::DatagramHeader { .. } |
                    frame::Frame::Datagram { .. } => {
                        // Datagrams do not require retransmission.  Just update
                        // stats.
                        p.dgram_lost_count = p.dgram_lost_count.saturating_add(1);
                    },
                    // IMPORTANT: Do not add an exhaustive catch
                    // all. We want to add explicit handling for frame
                    // types that can be safely ignored when lost.
                }
            }
        }

        #[cfg(debug_assertions)]
        self.streams.debug_check_tx_buffered_consistency();

        Ok(())
    }

    fn send_single_for_type(
        &mut self, b: &mut packet::PacketWriter<'_>, send_pid: usize,
        has_initial: bool, now: Instant, pkt_type: Type, bypass_cwnd: bool,
    ) -> Result<(Type, usize)> {
        let is_closing = self.local_error.is_some();

        b.reset();

        let max_dgram_len = if self.dgram_send_queue.is_empty() {
            None
        } else {
            self.dgram_max_writable_len()
        };

        let epoch = pkt_type.to_epoch()?;
        if self.next_pkt_num >= octets::MAX_VAR_INT {
            self.mark_closed(CloseCause::PacketNumbersExhausted);
            return Err(Error::Done);
        }
        // Don't skip the final usable packet number. The next increment
        // will exhaust the number space and silently close the connection.
        let should_skip = self.next_pkt_num < octets::MAX_VAR_INT - 1 &&
            self.pkt_num_manager
                .should_skip_pn(self.handshake_completed);
        let pn = self.next_pkt_num + u64::from(should_skip);
        let pn_len = packet::pkt_num_len(
            pn,
            self.pkt_num_spaces[epoch].largest_acked_pkt_num,
        )?;

        self.requeue_lost_frames(epoch, now)?;

        let is_app_limited = self.delivery_rate_check_if_app_limited();

        if should_skip {
            let skipped_pn = self.next_pkt_num;
            self.pkt_num_manager.set_skip_pn(Some(skipped_pn));
            for (_, path) in self.paths.iter_mut() {
                path.recovery.on_packet_number_skipped(skipped_pn);
            }
            self.next_pkt_num += 1;
        }

        let header =
            self.prepare_tx_header(b, send_pid, pkt_type, epoch, pn, pn_len)?;
        let mut assembly = TxPacketAssembly {
            left: header.payload_capacity,
            ..Default::default()
        };
        let budget = self.emit_tx_ack_frame(
            b,
            &header,
            &mut assembly,
            send_pid,
            is_closing,
            bypass_cwnd,
        )?;

        if pkt_type == Type::Short {
            self.emit_tx_path_probes(
                b,
                &header,
                &mut assembly,
                send_pid,
                is_closing,
            )?;
            if !is_closing {
                let frame_count = assembly.frames.len();
                self.emit_short_header_control_frames(
                    b,
                    &mut assembly.frames,
                    &mut assembly.left,
                    send_pid,
                    now,
                )?;
                if assembly.frames.len() != frame_count {
                    assembly.flight.record_ack_eliciting();
                }
            }
        }

        self.emit_tx_close_frame(b, &mut assembly, send_pid, pkt_type, now)?;
        assembly.data = self.emit_packet_data(
            b,
            &mut assembly.frames,
            &mut assembly.left,
            send_pid,
            pkt_type,
            max_dgram_len,
        )?;
        // Legacy recovery does not count DATAGRAM-only traffic as data;
        // gcongestion does. Preserve that backend policy in the one packet
        // classification carried through protection, ACK and loss processing.
        if assembly.data.has_data() ||
            (assembly.data.datagram_emitted &&
                self.paths.get(send_pid)?.recovery.gcongestion_enabled())
        {
            debug_assert!(!assembly.flight.is_pmtud_probe());
            assembly.flight = recovery::PacketFlight::Data;
        } else if assembly.data.datagram_emitted {
            assembly.flight.record_ack_eliciting();
        }

        Self::complete_tx_frames(
            b,
            &header,
            &mut assembly,
            budget,
            self.paths.get_mut(send_pid)?,
            has_initial,
            is_closing,
        )?;
        self.finalize_tx_packet(
            b,
            header,
            assembly,
            send_pid,
            now,
            is_app_limited,
        )
    }

    /// Encode the header and reserve the protected payload's wire capacity.
    fn prepare_tx_header(
        &mut self, b: &mut packet::PacketWriter<'_>, send_pid: usize,
        pkt_type: Type, epoch: packet::Epoch, pn: u64, pn_len: usize,
    ) -> Result<TxPacketHeader> {
        let path = self.paths.get_mut(send_pid)?;
        let crypto_ctx = &self.crypto_ctx[epoch];
        let out_len = b.cap();

        // Limit output buffer size by estimated path MTU if enabled.
        let mut left = path
            .pmtud
            .as_ref()
            .map_or(out_len, |pmtud| cmp::min(pmtud.get_current_mtu(), out_len));

        // The AEAD overhead at the current encryption level.
        let crypto_overhead = crypto_ctx.crypto_overhead().ok_or(Error::Done)?;

        let dcid_seq = path.active_dcid_seq.ok_or(Error::OutOfIdentifiers)?;

        let dcid =
            ConnectionId::from_ref(self.ids.get_dcid(dcid_seq)?.cid.as_ref());

        let scid = if let Some(scid_seq) = path.active_scid_seq {
            ConnectionId::from_ref(self.ids.get_scid(scid_seq)?.cid.as_ref())
        } else if pkt_type == Type::Short {
            ConnectionId::default()
        } else {
            return Err(Error::InvalidState);
        };

        let hdr = Header {
            ty: pkt_type,

            version: self.version,

            dcid,
            scid,

            pkt_num: 0,
            pkt_num_len: pn_len,

            // Only clone token for Initial packets, as other packets don't have
            // this field (Retry doesn't count, as it's not encoded as part of
            // this code path).
            token: if pkt_type == Type::Initial {
                self.token.clone()
            } else {
                None
            },

            versions: None,
            key_phase: self.key_phase,
        };

        hdr.to_bytes(b)?;

        let hdr_trace = if log::max_level() == log::LevelFilter::Trace {
            Some(format!("{hdr:?}"))
        } else {
            None
        };

        // Capture the header before packet construction can retire a CID.
        // Do not allocate it for a disabled packet event.
        #[cfg(feature = "qlog")]
        let qlog_pkt_hdr = (self.qlog.streamer.is_some() &&
            EventImportance::from(QLOG_PACKET_TX)
                .is_contained_in(&self.qlog.level))
        .then(|| {
            qlog::events::quic::PacketHeader::with_type(
                hdr.ty.to_qlog(),
                Some(pn),
                Some(hdr.version),
                Some(&hdr.scid),
                Some(&hdr.dcid),
            )
        });

        // Calculate the space required for the packet, including the header
        // the payload length, the packet number and the AEAD overhead.
        let mut overhead = b.off() + pn_len + crypto_overhead;

        // Reserve enough space for the long-header length including the
        // packet number and AEAD tag. Limit the packet at width transitions.
        let length_field = if pkt_type == Type::Short {
            None
        } else {
            let (capacity, width) = frame::payload_capacity(
                left.checked_sub(b.off()).ok_or(Error::Done)?,
            )
            .ok_or(Error::Done)?;
            left = b.off() + width + capacity;
            overhead += width;
            Some((b.off(), width))
        };

        // In the absence of room for the minimum protected payload, we
        // cannot use the current congestion window for another packet.
        let Some(payload_capacity) = left
            .checked_sub(overhead)
            .filter(|&left| left >= PAYLOAD_MIN_LEN)
        else {
            path.recovery.update_app_limited(false);
            return Err(Error::Done);
        };

        if let Some((_, width)) = length_field {
            frame::FrameSink::put_padding(b, width)?;
        }
        packet::encode_pkt_num(pn, pn_len, b)?;

        Ok(TxPacketHeader {
            packet_type: pkt_type,
            epoch,
            number: pn,
            number_len: pn_len,
            output_capacity: out_len,
            payload_capacity,
            payload_offset: b.off(),
            crypto_overhead,
            length_field,
            trace: hdr_trace,
            #[cfg(feature = "qlog")]
            qlog_header: qlog_pkt_hdr,
        })
    }

    /// ACK-only packets are not congestion controlled; reserve the
    /// congestion-controlled capacity only after attempting the ACK.
    fn emit_tx_ack_frame(
        &mut self, b: &mut packet::PacketWriter<'_>, header: &TxPacketHeader,
        assembly: &mut TxPacketAssembly, send_pid: usize, is_closing: bool,
        bypass_cwnd: bool,
    ) -> Result<TxAckBudget> {
        let path = self.paths.get_mut(send_pid)?;
        let pkt_space = &mut self.pkt_num_spaces[header.epoch];

        // Whether a PING frame must explicitly elicit an ACK when no other
        // frame does so implicitly.
        let ack_elicit_required =
            !is_closing && path.recovery.should_elicit_ack(header.epoch);

        // `usize::MAX` bypasses cwnd when authorized by packet selection;
        // `left` still bounds the packet. Keep this local so other cwnd users
        // see the actual window.
        let send_limit_from_cwnd = if bypass_cwnd {
            usize::MAX
        } else {
            path.recovery.cwnd_available()
        }
        .saturating_sub(header.overhead());

        let left_before_packing_ack_frame = assembly.left;

        // Create ACK frame.
        //
        // When we need to explicitly elicit an ACK via PING later, go ahead and
        // generate an ACK (if there's anything to ACK) since we're going to
        // send a packet with PING anyways, even if we haven't received anything
        // ACK eliciting.
        //
        // While closing, PING frames are suppressed, so ACK elicitation must
        // not generate ACK-only packets.
        if pkt_space.recv_pkt_need_ack.len() > 0 &&
            (pkt_space.ack_elicited || ack_elicit_required) &&
            (!is_closing ||
                (header.packet_type == Type::Handshake &&
                    self.local_error
                        .as_ref()
                        .is_some_and(|le| le.is_app))) &&
            path.active()
        {
            #[cfg(not(feature = "fuzzing"))]
            let ack_delay = pkt_space.largest_rx_pkt_time.elapsed();

            #[cfg(not(feature = "fuzzing"))]
            let ack_delay = encode_ack_delay(
                ack_delay,
                self.local_transport_params.ack_delay_exponent,
            );

            // pseudo-random reproducible ack delays when fuzzing
            #[cfg(feature = "fuzzing")]
            let ack_delay = rand::rand_u8() as u64 + 1;

            let frame = frame::Frame::ACK {
                ack_delay,
                ranges: pkt_space.recv_pkt_need_ack.clone(),
                ecn_counts: None, // sending ECN is not supported at this time
            };

            // When a PING frame needs to be sent, avoid sending the ACK if
            // there is not enough cwnd available for both (note that PING
            // frames are always 1 byte, so we just need to check that the
            // ACK's length is lower than cwnd).
            if pkt_space.ack_elicited || frame.wire_len()? < send_limit_from_cwnd
            {
                // ACK-only packets are not congestion controlled so ACKs must
                // be bundled considering the buffer capacity only, and not the
                // available cwnd.
                if push_frame_to_pkt(
                    b,
                    &mut assembly.frames,
                    frame,
                    &mut assembly.left,
                )? {
                    pkt_space.ack_elicited = false;
                }
            }
        }

        // Limit output packet size by congestion window size.
        assembly.left = cmp::min(
            assembly.left,
            // Bytes consumed by ACK frames.
            send_limit_from_cwnd
                .saturating_sub(left_before_packing_ack_frame - assembly.left),
        );

        Ok(TxAckBudget {
            elicit_required: ack_elicit_required,
            congestion_limit: send_limit_from_cwnd,
        })
    }

    /// Emit PMTU and address-validation probes on the selected path.
    fn emit_tx_path_probes(
        &mut self, b: &mut packet::PacketWriter<'_>, header: &TxPacketHeader,
        assembly: &mut TxPacketAssembly, send_pid: usize, is_closing: bool,
    ) -> Result<()> {
        let path = self.paths.get_mut(send_pid)?;
        // Create PMTUD probe.
        //
        // A PMTUD probe must ignore `left`, which is already limited by the
        // current PMTU. The probe remains limited by the output buffer and
        // congestion window.
        //
        // Generate PMTUD probes only after handshake confirmation to avoid
        // interference from anti-amplification limits.
        if let Some(probe_size) = path.pmtu_probe_size(
            self.handshake_confirmed && self.handshake_completed,
            header.output_capacity,
            is_closing || !assembly.frames.is_empty(),
        ) {
            trace!(
                "{} sending PMTUD probe of {probe_size} bytes",
                self.trace_id,
            );

            assembly.left = probe_size
                .checked_sub(header.overhead())
                .filter(|&size| size >= PAYLOAD_MIN_LEN)
                .ok_or(Error::Done)?;

            let padding = frame::Frame::Padding {
                len: assembly.left - 1,
            };
            let ping = frame::Frame::Ping {
                mtu_probe: Some(probe_size),
            };

            if !push_frame_to_pkt(
                b,
                &mut assembly.frames,
                padding,
                &mut assembly.left,
            )? || !push_frame_to_pkt(
                b,
                &mut assembly.frames,
                ping,
                &mut assembly.left,
            )? {
                return Err(Error::Done);
            }

            assembly.flight = recovery::PacketFlight::PmtuProbe;
        }

        // Create PATH_RESPONSE frames while space permits.
        if push_received_path_responses(
            path,
            b,
            &mut assembly.frames,
            &mut assembly.left,
        )? {
            assembly.probes.has_path_frame = true;
            assembly.flight.record_ack_eliciting();
        }

        // Create PATH_CHALLENGE frame if needed.
        if path.validation_requested() {
            // TODO: ensure that data is unique over paths.
            let data = rand::rand_u64().to_be_bytes();

            let frame = frame::Frame::PathChallenge { data };

            if push_frame_to_pkt(
                b,
                &mut assembly.frames,
                frame,
                &mut assembly.left,
            )? {
                // Let's notify the path once we know the packet size.
                assembly.probes.challenge = Some(data);
                assembly.probes.has_path_frame = true;

                assembly.flight.record_ack_eliciting();
            }
        }

        if let Some(key_update) =
            self.crypto_ctx[header.epoch].key_update.as_mut()
        {
            key_update.update_acked = true;
        }

        Ok(())
    }

    fn emit_tx_close_frame(
        &mut self, b: &mut packet::PacketWriter<'_>,
        assembly: &mut TxPacketAssembly, send_pid: usize, pkt_type: Type,
        now: Instant,
    ) -> Result<()> {
        let path = self.paths.get(send_pid)?;
        // Try to send closure on the active path, unless it is the last path.
        if let Some(conn_err) = self
            .local_error
            .as_ref()
            .filter(|_| path.active() || self.paths.len() == 1)
        {
            let frame = match (conn_err.is_app, pkt_type) {
                (false, _) => Some(frame::Frame::ConnectionClose {
                    error_code: conn_err.error_code,
                    frame_type: 0,
                    reason: conn_err.reason.clone(),
                }),
                (true, Type::Short) => Some(frame::Frame::ApplicationClose {
                    error_code: conn_err.error_code,
                    reason: conn_err.reason.clone(),
                }),
                (true, _) => None,
            };

            if let Some(frame) = frame {
                if push_frame_to_pkt(
                    b,
                    &mut assembly.frames,
                    frame,
                    &mut assembly.left,
                )? {
                    self.lifecycle = ConnectionLifecycle::Draining {
                        deadline: now + (path.recovery.pto() * 3),
                        origin: CloseOrigin::Local,
                    };
                    assembly.flight.record_ack_eliciting();
                }
            }
        }

        Ok(())
    }

    /// Satisfy pending ACK elicitation, then pad the protected payload.
    fn complete_tx_frames(
        b: &mut packet::PacketWriter<'_>, header: &TxPacketHeader,
        assembly: &mut TxPacketAssembly, budget: TxAckBudget,
        path: &mut path::Path, has_initial: bool, is_closing: bool,
    ) -> Result<()> {
        // If no other ack-eliciting frame is sent, include a PING frame
        // - if PTO probe needed; OR
        // - if we've sent too many non ack-eliciting packets without having
        // sent an ACK eliciting one; OR
        // - the application requested an ack-eliciting frame be sent.
        if (budget.elicit_required || path.needs_ack_eliciting) &&
            !assembly.flight.ack_eliciting() &&
            assembly.left >= 1 &&
            !is_closing
        {
            let frame = frame::Frame::Ping { mtu_probe: None };

            if push_frame_to_pkt(
                b,
                &mut assembly.frames,
                frame,
                &mut assembly.left,
            )? {
                assembly.flight.record_ack_eliciting();
            }
        }

        if assembly.flight.ack_eliciting() && !assembly.flight.is_pmtud_probe() {
            path.needs_ack_eliciting = false;
            path.recovery.ping_sent(header.epoch);
        }

        // Pending stream data means the sender is size-, not app-limited.
        if !assembly.data.has_data() &&
            !assembly.data.stream.skipped &&
            !assembly.data.datagram_emitted &&
            budget.congestion_limit > LEGACY_APP_LIMITED_BYTE_THRESHOLD
        {
            path.recovery.on_app_limited();
        }

        if assembly.frames.is_empty() {
            // When we reach this point we are not able to write more, so set
            // app_limited to false.
            path.recovery.update_app_limited(false);
            return Err(Error::Done);
        }

        // When coalescing a 1-RTT packet, we can't add padding in the UDP
        // datagram, so use PADDING frames instead.
        //
        // This is only needed if
        // 1) an Initial packet has already been written to the UDP datagram,
        // as Initial always requires padding.
        //
        // 2) this is a probing packet towards an unvalidated peer address.
        if header.packet_type == Type::Short && assembly.left >= 1 {
            let pad_len = if has_initial || !path.validated() {
                assembly.left
            } else if assembly.probes.has_path_frame {
                let pkt_len = b.off() + header.crypto_overhead;
                cmp::min(
                    assembly.left,
                    MIN_CLIENT_INITIAL_LEN.saturating_sub(pkt_len),
                )
            } else {
                0
            };

            if pad_len > 0 {
                let frame = frame::Frame::Padding { len: pad_len };

                if push_frame_to_pkt(
                    b,
                    &mut assembly.frames,
                    frame,
                    &mut assembly.left,
                )? {
                    assembly.flight.record_padding();
                }
            }
        }

        // Pad payload so that it's always at least 4 bytes.
        if b.off() - header.payload_offset < PAYLOAD_MIN_LEN {
            let payload_len = b.off() - header.payload_offset;

            let frame = frame::Frame::Padding {
                len: PAYLOAD_MIN_LEN - payload_len,
            };

            if push_frame_to_pkt(
                b,
                &mut assembly.frames,
                frame,
                &mut assembly.left,
            )? {
                assembly.flight.record_padding();
            }
        }

        Ok(())
    }

    /// Patch the long-header length, log the plaintext frame metadata, then
    /// seal the packet and verify the protected wire length.
    fn seal_tx_packet(
        &mut self, b: &mut packet::PacketWriter<'_>, header: TxPacketHeader,
        frames: &[frame::Frame], send_pid: usize, now: Instant,
    ) -> Result<usize> {
        let path = self.paths.get(send_pid)?;
        #[cfg(not(feature = "qlog"))]
        let _ = now;

        let payload_len = b.off() - header.payload_offset;

        if let Some((offset, width)) = header.length_field {
            let len = header.number_len + payload_len + header.crypto_overhead;
            b.patch(offset, width)?
                .put_varint_with_len(len as u64, width)?;
        }

        trace!(
            "{} tx pkt {} len={payload_len} pn={} {}",
            self.trace_id,
            header.trace.unwrap_or_default(),
            header.number,
            AddrTupleFmt(path.local_addr(), path.peer_addr())
        );

        for frame in frames {
            trace!("{} tx frm {frame:?}", self.trace_id);
        }

        #[cfg(feature = "qlog")]
        if let (Some(q), Some(qlog_header)) =
            (&mut self.qlog.streamer, header.qlog_header)
        {
            let qlog_frames = frames
                .iter()
                .map(|frame| {
                    frame.to_qlog(self.local_transport_params.ack_delay_exponent)
                })
                .collect();

            // Qlog packet raw info described at
            // https://datatracker.ietf.org/doc/html/draft-ietf-quic-qlog-main-schema-00#section-5.1
            //
            // `length` includes packet headers and trailers (AEAD tag).
            let length =
                payload_len + header.payload_offset + header.crypto_overhead;
            let qlog_raw_info = RawInfo {
                length: Some(length as u64),
                payload_length: Some(payload_len as u64),
                data: None,
            };

            let send_at_time =
                now.duration_since(q.start_time()).as_secs_f64() * 1000.0;

            let ev_data =
                EventData::QuicPacketSent(qlog::events::quic::PacketSent {
                    header: qlog_header,
                    frames: Some(qlog_frames),
                    raw: Some(qlog_raw_info),
                    send_at_time: Some(send_at_time),
                    ..Default::default()
                });

            q.add_event_data_with_instant(ev_data, now).ok();
        }

        let aead = self.crypto_ctx[header.epoch]
            .crypto_seal
            .as_mut()
            .ok_or(Error::InvalidState)?;

        // The AEAD interface needs an initialized output slice. Initialize only
        // the fixed tag bytes, not the caller's unused packet capacity.
        frame::FrameSink::put_padding(b, header.crypto_overhead)?;
        let mut encrypted = octets::OctetsMut::with_slice(b.written_mut());
        let written = packet::encrypt_pkt(
            &mut encrypted,
            header.number,
            header.number_len,
            payload_len,
            header.payload_offset,
            None,
            aead,
        )?;
        if written != b.off() {
            return Err(Error::CryptoFail);
        }

        Ok(written)
    }

    /// Hand the protected packet to recovery and commit its send accounting.
    fn finalize_tx_packet(
        &mut self, b: &mut packet::PacketWriter<'_>, header: TxPacketHeader,
        mut assembly: TxPacketAssembly, send_pid: usize, now: Instant,
        is_app_limited: bool,
    ) -> Result<(Type, usize)> {
        let pkt_type = header.packet_type;
        let epoch = header.epoch;
        let pn = header.number;
        let written =
            self.seal_tx_packet(b, header, &assembly.frames, send_pid, now)?;
        let path = self.paths.get_mut(send_pid)?;
        let in_flight = assembly.flight.in_flight();

        let sent_pkt = recovery::Sent {
            pkt_num: pn,
            frames: std::mem::take(&mut assembly.frames),
            time_sent: now,
            time_acked: None,
            time_lost: None,
            // RFC 9002, Section 2: a packet containing a PADDING frame is
            // counted toward bytes in flight even though it is not
            // ack-eliciting, so record the size of every in-flight packet.
            size: if in_flight { written } else { 0 },
            flight: assembly.flight,
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            is_app_limited: false,
            tx_in_flight: 0,
            lost: 0,
        };

        if in_flight && is_app_limited {
            path.recovery.delivery_rate_update_app_limited(true);
        }

        self.next_pkt_num += 1;

        let handshake_status = recovery::HandshakeStatus {
            has_handshake_keys: self.crypto_ctx[packet::Epoch::Handshake]
                .has_keys(),
            peer_verified_address: self.peer_verified_initial_address,
            completed: self.handshake_completed,
        };

        self.on_packet_sent(send_pid, sent_pkt, epoch, handshake_status, now)?;

        self.record_tx_packet(send_pid, written, now, pkt_type, &assembly)?;
        Ok((pkt_type, written))
    }

    /// Commit path statistics, retransmission attribution and connection
    /// timers after recovery has accepted the packet.
    fn record_tx_packet(
        &mut self, send_pid: usize, written: usize, now: Instant, pkt_type: Type,
        assembly: &TxPacketAssembly,
    ) -> Result<()> {
        let path = self.paths.get_mut(send_pid)?;
        if assembly.flight.is_pmtud_probe() {
            if let Some(pmtud) = path.pmtud.as_mut() {
                pmtud.set_in_flight(true);
            }
        }
        qlog_with_type!(QLOG_METRICS, self.qlog, q, {
            path.recovery.maybe_qlog(q, now);
        });

        // Record sent packet size if we probe the path.
        if let Some(data) = assembly.probes.challenge {
            path.add_challenge_sent(data, written, now);
        }

        // Attribute retransmission to the packet and path that actually
        // carried the repeated payload or FIN, not the lost frame's path.
        let retransmitted_bytes = assembly.data.retransmitted_bytes();
        if retransmitted_bytes != 0 || assembly.data.stream.retransmitted_fin {
            self.retrans_count = self.retrans_count.saturating_add(1);
            path.retrans_count = path.retrans_count.saturating_add(1);
            self.stream_retrans_bytes = self
                .stream_retrans_bytes
                .saturating_add(retransmitted_bytes);
            path.stream_retrans_bytes = path
                .stream_retrans_bytes
                .saturating_add(retransmitted_bytes);
        }

        self.sent_count += 1;
        self.sent_bytes += written as u64;
        path.sent_count += 1;
        path.sent_bytes += written as u64;

        if self.dgram_send_queue.byte_size() > path.recovery.cwnd_available() {
            path.recovery.update_app_limited(false);
        }

        let had_send_budget = path.max_send_bytes > 0;
        path.max_send_bytes = path.max_send_bytes.saturating_sub(written);
        if self.is_server &&
            !path.verified_peer_address &&
            had_send_budget &&
            path.max_send_bytes == 0
        {
            self.amplification_limited_count =
                self.amplification_limited_count.saturating_add(1);
        }

        // On the client, drop initial state after sending an Handshake packet.
        if !self.is_server && pkt_type == Type::Handshake {
            self.drop_epoch_state(packet::Epoch::Initial, now);
        }

        // (Re)start the idle timer if we are sending the first ack-eliciting
        // packet since last receiving a packet.
        if assembly.flight.ack_eliciting() && !self.ack_eliciting_sent {
            if let Some(idle_timeout) = self.idle_timeout() {
                self.idle_timer = now.checked_add(idle_timeout);
            }
        }

        if assembly.flight.ack_eliciting() {
            self.ack_eliciting_sent = true;
        }

        // RFC 9000 §12.3: when the send number reaches its maximum, close
        // silently, without attempting a CONNECTION_CLOSE packet.
        if self.next_pkt_num >= octets::MAX_VAR_INT {
            self.mark_closed(CloseCause::PacketNumbersExhausted);
        }

        Ok(())
    }

    /// Emit CRYPTO first, then choose between DATAGRAM and STREAM.
    fn emit_packet_data(
        &mut self, b: &mut packet::PacketWriter<'_>,
        frames: &mut SmallVec<[frame::Frame; 1]>, left: &mut usize,
        send_pid: usize, pkt_type: Type, max_dgram_len: Option<usize>,
    ) -> Result<PacketDataEmission> {
        let mut emission = PacketDataEmission::default();
        if self.local_error.is_some() || !self.paths.get(send_pid)?.active() {
            self.emit_dgram = true;
            return Ok(emission);
        }

        let crypto_stream =
            &mut self.crypto_ctx[pkt_type.to_epoch()?].crypto_stream;
        if crypto_stream.is_flushable() {
            emission.crypto_retransmitted_bytes =
                Self::emit_crypto_frame(crypto_stream, b, frames, left)?;
        }

        if matches!(pkt_type, Type::Short | Type::ZeroRTT) {
            // Alternate between the queues when both have data. Fall back to
            // STREAM when a preferred datagram cannot be emitted.
            if *left >= 3 && (self.emit_dgram || !self.streams.has_flushable()) {
                if let Some(max_payload) = max_dgram_len {
                    emission.datagram_emitted = self.emit_datagram_frames(
                        b,
                        frames,
                        left,
                        send_pid,
                        max_payload,
                    )?;
                }
            }
            if !emission.datagram_emitted {
                emission.stream = self.emit_stream_frames(b, frames, left)?;
            }
        }

        self.emit_dgram = !emission.datagram_emitted;
        Ok(emission)
    }

    /// Serialize CRYPTO directly, returning the retransmitted byte count
    /// only if a frame was actually written.
    fn emit_crypto_frame(
        crypto_stream: &mut stream::Stream, b: &mut packet::PacketWriter<'_>,
        frames: &mut SmallVec<[frame::Frame; 1]>, left: &mut usize,
    ) -> Result<Option<u64>> {
        let crypto_off = crypto_stream.send.off_front();

        // Encode the frame.
        //
        // Instead of creating a `frame::Frame` object, encode the frame
        // directly into the packet buffer.
        //
        // First we reserve some space in the output buffer for writing the
        // frame header, with a length width selected from the available
        // packet space.
        //
        // Then we emit the data from the crypto stream's send buffer.
        //
        // Finally we go back and encode the frame header with the now
        // available information.
        let hdr_off = b.off();
        let fixed = 1 + octets::varint_len(crypto_off);

        if let Some((max_len, width)) = left
            .checked_sub(fixed)
            .and_then(frame::payload_capacity)
            .filter(|(capacity, _)| *capacity > 0)
        {
            let hdr_len = fixed + width;
            frame::FrameSink::put_padding(b, hdr_len)?;
            let emission = crypto_stream
                .send
                .emit(bytes::BufMut::limit(&mut *b, max_len));
            let len = emission.len;
            let mut crypto_hdr = b.patch(hdr_off, hdr_len)?;
            frame::encode_crypto_header(
                crypto_off,
                len as u64,
                width,
                &mut crypto_hdr,
            )?;

            // The payload and its header were encoded above. Only
            // record recovery metadata and account for the written bytes.
            *left -= hdr_len + len;
            frames.push(frame::Frame::CryptoHeader {
                offset: crypto_off,
                length: len,
            });
            return Ok(Some(emission.retransmitted_bytes));
        }

        Ok(None)
    }

    fn emit_datagram_frames(
        &mut self, b: &mut packet::PacketWriter<'_>,
        frames: &mut SmallVec<[frame::Frame; 1]>, left: &mut usize,
        send_pid: usize, max_dgram_payload: usize,
    ) -> Result<bool> {
        let path = self.paths.get_mut(send_pid)?;
        let mut emitted = false;
        while let Some(len) = self.dgram_send_queue.peek_front_len() {
            let hdr_len = 1 + frame::payload_length_width(len as u64);

            if hdr_len + len <= *left {
                // The front datagram fits this packet. The payload is already
                // owned by the queue, so encode it directly into the writer.
                if let Some(data) = self.dgram_send_queue.pop() {
                    frame::encode_dgram_header(len as u64, b)?;
                    frame::FrameSink::put_bytes(b, data.as_ref())?;
                    *left -= hdr_len + len;
                    frames.push(frame::Frame::DatagramHeader { length: len });
                    emitted = true;
                    self.dgram_sent_count =
                        self.dgram_sent_count.saturating_add(1);
                    path.dgram_sent_count =
                        path.dgram_sent_count.saturating_add(1);
                }
            } else if len > max_dgram_payload {
                // This datagram will never fit; discard it.
                self.dgram_send_queue.pop();
            } else {
                break;
            }
        }
        Ok(emitted)
    }

    fn emit_stream_frames(
        &mut self, b: &mut packet::PacketWriter<'_>,
        frames: &mut SmallVec<[frame::Frame; 1]>, left: &mut usize,
    ) -> Result<StreamPacketEmission> {
        let mut emission_summary = StreamPacketEmission::default();
        while let Some(priority_key) = self.streams.peek_flushable() {
            let stream_id = priority_key.id;
            // Revalidate the intrusive queue entry before emission: ACKs may
            // have removed data, leaving a stale entry. Empty FIN remains
            // eligible.
            let Some(stream) =
                self.streams.get_mut(stream_id).filter(|s| s.is_flushable())
            else {
                self.streams.remove_flushable(&priority_key);
                continue;
            };

            let stream_off = stream.send.off_front();

            // Encode the frame.
            //
            // Instead of creating a `frame::Frame` object, encode the frame
            // directly into the packet buffer.
            //
            // First we reserve some space in the output buffer for writing
            // the frame header, choosing a length width that can encode
            // the largest payload fitting in the remaining space.
            //
            // Then we emit the data from the stream's send buffer.
            //
            // Finally we go back and encode the frame header with the now
            // available information.
            let hdr_off = b.off();
            let fixed = 1 +
                octets::varint_len(stream_id) +
                octets::varint_len(stream_off);

            // A non-FIN STREAM frame must carry at least one byte. If the
            // header and payload don't fit, leave the stream flushable for
            // a later packet. Empty FIN frames only need the header.
            let (max_len, width) =
                match left.checked_sub(fixed).and_then(frame::payload_capacity) {
                    Some((v, width)) if v > 0 || stream.send.empty_fin_next() =>
                        (v, width),
                    _ => {
                        emission_summary.skipped = true;

                        if stream.incremental() {
                            let priority_key = Arc::clone(stream.priority_key());
                            self.streams.remove_flushable(&priority_key);
                            self.streams.enqueue(
                                &priority_key,
                                stream::PriorityQueue::Flushable,
                            );
                        }

                        break;
                    },
                };

            let hdr_len = fixed + width;
            frame::FrameSink::put_padding(b, hdr_len)?;
            let emission =
                stream.send.emit(bytes::BufMut::limit(&mut *b, max_len));
            let len = emission.len;
            let fin = emission.fin;

            // ACK processing can leave a stream in the flushable queue
            // after removing all of its retransmission data. Unlink the
            // stale entry and continue with the next stream;
            // future retransmits or writedata will queue the stream again.
            if len == 0 && !fin {
                b.rewind(hdr_len)?;
                let priority_key = Arc::clone(stream.priority_key());
                self.streams.remove_flushable(&priority_key);
                continue;
            }

            let mut stream_hdr = b.patch(hdr_off, hdr_len)?;
            frame::encode_stream_header(
                stream_id,
                stream_off,
                len as u64,
                fin,
                width,
                &mut stream_hdr,
            )?;

            emission_summary.retransmitted_bytes = emission_summary
                .retransmitted_bytes
                .saturating_add(emission.retransmitted_bytes);
            emission_summary.retransmitted_fin = emission.retransmitted_fin;

            // The payload and its header were encoded above. Only
            // record recovery metadata and account for the written bytes.
            *left -= hdr_len + len;
            frames.push(frame::Frame::StreamHeader {
                stream_id,
                offset: stream_off,
                length: len,
                fin,
            });
            emission_summary.emitted = true;

            let priority_key = Arc::clone(stream.priority_key());
            // Remove the stream when it is no longer flushable.
            if !stream.is_flushable() {
                self.streams.remove_flushable(&priority_key);
            } else if stream.incremental() {
                // Shuffle the incremental stream to the back of the
                // queue.
                self.streams.remove_flushable(&priority_key);
                self.streams
                    .enqueue(&priority_key, stream::PriorityQueue::Flushable);
            }

            // Update tx_buffered when data is emitted.
            self.streams.sub_tx_buffered(len as u64);

            #[cfg(feature = "fuzzing")]
            // Coalesce STREAM frames when fuzzing.
            continue;

            #[cfg(not(feature = "fuzzing"))]
            break;
        }

        Ok(emission_summary)
    }

    /// Emit connection control frames in their wire scheduling order.
    fn emit_short_header_control_frames(
        &mut self, b: &mut packet::PacketWriter<'_>,
        frames: &mut SmallVec<[frame::Frame; 1]>, left: &mut usize,
        send_pid: usize, now: Instant,
    ) -> Result<()> {
        let path = self.paths.get(send_pid)?;
        let active = path.active();
        let rtt = path.recovery.rtt();
        let active_dcid_seq = path.active_dcid_seq;

        // Create NEW_CONNECTION_ID frames as needed.
        while let Some(seq_num) = self.ids.next_advertise_new_scid_seq() {
            let frame = self.ids.get_new_connection_id_frame_for(seq_num)?;

            if push_frame_to_pkt(b, frames, frame, left)? {
                self.ids.mark_advertise_new_scid_seq(seq_num, false);
            } else {
                break;
            }
        }

        if active {
            self.emit_stream_count_control_frames(b, frames, left)?;
            self.emit_receive_credit_frames(b, frames, left, now, rtt)?;
            self.emit_stream_signal_frames(b, frames, left)?;
            self.emit_retired_dcid_frames(b, frames, left, active_dcid_seq)?;
        }

        Ok(())
    }

    fn emit_stream_count_control_frames(
        &mut self, b: &mut packet::PacketWriter<'_>,
        frames: &mut SmallVec<[frame::Frame; 1]>, left: &mut usize,
    ) -> Result<()> {
        // Create HANDSHAKE_DONE frame.
        if self.should_send_handshake_done() {
            let frame = frame::Frame::HandshakeDone;

            if push_frame_to_pkt(b, frames, frame, left)? {
                self.handshake_done = HandshakeDoneState::InFlight;
            }
        }

        // Create MAX_STREAMS_BIDI frame.
        if self.streams.should_update_max_streams_bidi() ||
            self.should_send_max_streams_bidi
        {
            let frame = frame::Frame::MaxStreamsBidi {
                max: self.streams.max_streams_bidi_next(),
            };

            if push_frame_to_pkt(b, frames, frame, left)? {
                self.streams.update_max_streams_bidi();
                self.should_send_max_streams_bidi = false;
            }
        }

        // Create MAX_STREAMS_UNI frame.
        if self.streams.should_update_max_streams_uni() ||
            self.should_send_max_streams_uni
        {
            let frame = frame::Frame::MaxStreamsUni {
                max: self.streams.max_streams_uni_next(),
            };

            if push_frame_to_pkt(b, frames, frame, left)? {
                self.streams.update_max_streams_uni();
                self.should_send_max_streams_uni = false;
            }
        }

        // Create DATA_BLOCKED frame.
        if let Some(limit) = self.blocked_limit {
            let frame = frame::Frame::DataBlocked { limit };

            if push_frame_to_pkt(b, frames, frame, left)? {
                self.blocked_limit = None;
                self.data_blocked_sent_count =
                    self.data_blocked_sent_count.saturating_add(1);
            }
        }

        // Create STREAMS_BLOCKED (bidi) frame when the local endpoint has
        // exhausted the peer's bidirectional stream count limit.
        if self
            .streams_blocked_bidi_state
            .has_pending_stream_blocked_frame()
        {
            if let Some(limit) = self.streams_blocked_bidi_state.blocked_at {
                let frame = frame::Frame::StreamsBlockedBidi { limit };

                if push_frame_to_pkt(b, frames, frame, left)? {
                    // Record the limit we just notified the peer about so
                    // that redundant frames for the same limit are
                    // suppressed.
                    self.streams_blocked_bidi_state.blocked_sent = Some(limit);
                }
            }
        }

        // Create STREAMS_BLOCKED (uni) frame when the local endpoint has
        // exhausted the peer's unidirectional stream count limit.
        if self
            .streams_blocked_uni_state
            .has_pending_stream_blocked_frame()
        {
            if let Some(limit) = self.streams_blocked_uni_state.blocked_at {
                let frame = frame::Frame::StreamsBlockedUni { limit };

                if push_frame_to_pkt(b, frames, frame, left)? {
                    // Record the limit we just notified the peer about so
                    // that redundant frames for the same limit are
                    // suppressed.
                    self.streams_blocked_uni_state.blocked_sent = Some(limit);
                }
            }
        }

        Ok(())
    }

    fn emit_receive_credit_frames(
        &mut self, b: &mut packet::PacketWriter<'_>,
        frames: &mut SmallVec<[frame::Frame; 1]>, left: &mut usize, now: Instant,
        rtt: Duration,
    ) -> Result<()> {
        // Create MAX_STREAM_DATA frames as needed.
        for stream_id in self.streams.almost_full() {
            let Some(stream) = self.streams.get_mut(stream_id) else {
                // The stream doesn't exist anymore, so remove it from
                // the almost full set.
                self.streams.remove_almost_full(stream_id);
                continue;
            };

            // Autotune the stream window size, but only if this is not a
            // retransmission (on a retransmit the stream will be in
            // `self.streams.almost_full()` but it's `almost_full()`
            // method returns false.
            if stream.recv.almost_full() {
                stream.recv.autotune_window(now, rtt);
            }

            let frame = frame::Frame::MaxStreamData {
                stream_id,
                max: stream.recv.max_data_next(),
            };

            if push_frame_to_pkt(b, frames, frame, left)? {
                let recv_win = stream.recv.window();

                stream.recv.update_max_data(now);

                self.streams.remove_almost_full(stream_id);

                // Make sure the connection window always has some
                // room compared to the stream window.
                // Keep the connection window 50% larger, using exact
                // integer arithmetic rather than rounding a wire offset.
                self.flow_control.ensure_window_lower_bound(
                    recv_win.saturating_add(recv_win / 2),
                );
            }
        }

        // Create MAX_DATA frame as needed.
        if self.flow_control.should_update_max_data() &&
            self.flow_control.max_data() < self.flow_control.max_data_next()
        {
            // Autotune the connection window size. We only tune the window
            // if we are sending an "organic" update, not on retransmits.
            self.flow_control.autotune_window(now, rtt);
            self.should_send_max_data = true;
        }

        if self.should_send_max_data {
            let frame = frame::Frame::MaxData {
                max: self.flow_control.max_data_next(),
            };

            if push_frame_to_pkt(b, frames, frame, left)? {
                self.should_send_max_data = false;

                // Commits the new max_rx_data limit.
                self.flow_control.update_max_data(now);
            }
        }

        Ok(())
    }

    fn emit_stream_signal_frames(
        &mut self, b: &mut packet::PacketWriter<'_>,
        frames: &mut SmallVec<[frame::Frame; 1]>, left: &mut usize,
    ) -> Result<()> {
        // Create STOP_SENDING frames as needed.
        for (stream_id, error_code) in self
            .streams
            .stopped()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, u64)>>()
        {
            let frame = frame::Frame::StopSending {
                stream_id,
                error_code,
            };

            if push_frame_to_pkt(b, frames, frame, left)? {
                self.streams.remove_stopped(stream_id);
            }
        }

        // Create RESET_STREAM frames as needed.
        for (stream_id, (error_code, final_size)) in self
            .streams
            .reset()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, (u64, u64))>>()
        {
            let frame = frame::Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            };

            if push_frame_to_pkt(b, frames, frame, left)? {
                self.streams.remove_reset(stream_id);
            }
        }

        // Create STREAM_DATA_BLOCKED frames as needed.
        for (stream_id, limit) in self
            .streams
            .blocked()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, u64)>>()
        {
            let frame = frame::Frame::StreamDataBlocked { stream_id, limit };

            if push_frame_to_pkt(b, frames, frame, left)? {
                self.streams.remove_blocked(stream_id);
                self.stream_data_blocked_sent_count =
                    self.stream_data_blocked_sent_count.saturating_add(1);
            }
        }

        Ok(())
    }

    fn emit_retired_dcid_frames(
        &mut self, b: &mut packet::PacketWriter<'_>,
        frames: &mut SmallVec<[frame::Frame; 1]>, left: &mut usize,
        active_dcid_seq: Option<u64>,
    ) -> Result<()> {
        // Create RETIRE_CONNECTION_ID frames as needed.
        let retire_dcid_seqs = self.ids.retire_dcid_seqs();

        for seq_num in retire_dcid_seqs {
            // The sequence number specified in a RETIRE_CONNECTION_ID frame
            // MUST NOT refer to the Destination Connection ID field of the
            // packet in which the frame is contained.
            let dcid_seq = active_dcid_seq.ok_or(Error::InvalidState)?;

            if seq_num == dcid_seq {
                continue;
            }

            let frame = frame::Frame::RetireConnectionId { seq_num };

            if push_frame_to_pkt(b, frames, frame, left)? {
                self.ids.mark_retire_dcid_seq(seq_num, false)?;
            } else {
                break;
            }
        }

        Ok(())
    }

    fn on_packet_sent(
        &mut self, send_pid: usize, sent_pkt: recovery::Sent,
        epoch: packet::Epoch, handshake_status: recovery::HandshakeStatus,
        now: Instant,
    ) -> Result<()> {
        let path = self.paths.get_mut(send_pid)?;

        // The skip counter may use values from an inactive path.
        let cwnd = path.recovery.cwnd();
        let max_datagram_size = path.recovery.max_datagram_size();
        self.pkt_num_spaces[epoch].on_packet_sent(&sent_pkt);
        self.pkt_num_manager.on_packet_sent(
            cwnd,
            max_datagram_size,
            self.handshake_completed,
        );

        path.recovery.on_packet_sent(
            sent_pkt,
            epoch,
            handshake_status,
            now,
            &self.trace_id,
        );

        Ok(())
    }

    /// Returns the desired send time for the next packet.
    #[inline]
    #[must_use = "the result determines the next packet release time"]
    pub fn get_next_release_time(&self) -> Option<ReleaseDecision> {
        Some(
            self.paths
                .get_active()
                .ok()?
                .recovery
                .get_next_release_time(),
        )
    }

    /// Returns whether gcongestion is enabled.
    #[inline]
    #[must_use = "the result identifies the active path congestion controller"]
    pub fn gcongestion_enabled(&self) -> Option<bool> {
        Some(self.paths.get_active().ok()?.recovery.gcongestion_enabled())
    }

    /// Returns the maximum pacing into the future.
    ///
    /// Equals 1/8 of the smoothed RTT, but at least 1ms and not greater than
    /// 5ms.
    #[must_use = "the result bounds how far ahead to schedule packet release"]
    pub fn max_release_into_future(&self) -> Duration {
        self.paths
            .get_active()
            .map_or(Duration::from_millis(1), |p| {
                p.recovery.rtt().mul_f64(0.125)
            })
            .max(Duration::from_millis(1))
            .min(Duration::from_millis(5))
    }

    /// Returns whether pacing is enabled.
    #[inline]
    #[must_use = "the result indicates whether pacing is configured"]
    pub const fn pacing_enabled(&self) -> bool {
        self.recovery_config.pacing
    }

    /// Returns the size of the send quantum, in bytes.
    ///
    /// This represents the maximum size of a packet burst as determined by the
    /// congestion control algorithm in use.
    ///
    /// Applications can, for example, use it in conjunction with segmentation
    /// offloading mechanisms as the maximum limit for outgoing aggregates of
    /// multiple packets.
    #[inline]
    #[must_use = "the result bounds the next packet burst"]
    pub fn send_quantum(&self) -> usize {
        self.paths
            .get_active()
            .map_or(0, |path| path.recovery.send_quantum())
    }

    /// Returns the size of the send quantum over the given 4-tuple, in bytes.
    ///
    /// This represents the maximum size of a packet burst as determined by the
    /// congestion control algorithm in use.
    ///
    /// Applications can, for example, use it in conjunction with segmentation
    /// offloading mechanisms as the maximum limit for outgoing aggregates of
    /// multiple packets.
    ///
    /// If the (`local_addr`, `peer_addr`) 4-tuple relates to a non-existing
    /// path, this method returns 0.
    #[must_use = "the result bounds the next packet burst on the selected path"]
    pub fn send_quantum_on_path(
        &self, local_addr: SocketAddr, peer_addr: SocketAddr,
    ) -> usize {
        self.paths
            .path_id_from_addrs(&(local_addr, peer_addr))
            .and_then(|pid| self.paths.get(pid).ok())
            .map_or(0, |path| path.recovery.send_quantum())
    }

    /// Reads contiguous data from a stream into the provided slice.
    ///
    /// The slice must be sized by the caller and will be populated up to its
    /// capacity.
    ///
    /// On success the amount of bytes read and a flag indicating the fin state
    /// is returned as a tuple, or [`Done`] if there is no data to read.
    ///
    /// Reading data from a stream may trigger queueing of control messages
    /// (e.g. `MAX_STREAM_DATA`). [`send()`] should be called afterwards.
    ///
    /// # Errors
    ///
    /// Returns `Error::Done` when no data or final-size event is readable,
    /// `Error::InvalidStreamState` for a missing or unreadable-direction
    /// stream, or `Error::StreamReset` with the peer's application error code.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`send()`]: struct.Connection.html#method.send
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// # let stream_id = 0;
    /// while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut buf) {
    ///     println!("Got {} bytes on stream {}", read, stream_id);
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    #[inline]
    pub fn stream_recv(
        &mut self, stream_id: u64, out: &mut [u8],
    ) -> Result<(usize, bool)> {
        self.stream_recv_buf(stream_id, out)
    }

    /// Reads contiguous data from a stream into the provided [`bytes::BufMut`].
    ///
    /// **NOTE**:
    /// The `BufMut` will be populated with all available data up to its
    /// capacity. Since some `BufMut` implementations, e.g., [`Vec<u8>`],
    /// dynamically allocate additional memory, the caller may use
    /// [`BufMut::limit()`] to limit the maximum amount of data that can be
    /// written.
    ///
    /// On success the amount of bytes read and a flag indicating the fin state
    /// is returned as a tuple, or [`Done`] if there is no data to read.
    /// [`BufMut::advance_mut()`] will have been called with the same number of
    /// total bytes.
    ///
    /// Reading data from a stream may trigger queueing of control messages
    /// (e.g. `MAX_STREAM_DATA`). [`send()`] should be called afterwards.
    ///
    /// # Errors
    ///
    /// Returns the same receive errors as [`Self::stream_recv`].
    ///
    /// [`BufMut::limit()`]: bytes::BufMut::limit
    /// [`BufMut::advance_mut()`]: bytes::BufMut::advance_mut
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`send()`]: struct.Connection.html#method.send
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # use bytes::BufMut as _;
    /// # let mut buf = Vec::new().limit(1024);  // Read at most 1024 bytes
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// # let stream_id = 0;
    /// # let mut total_read = 0;
    /// while let Ok((read, fin)) = conn.stream_recv_buf(stream_id, &mut buf) {
    ///     println!("Got {} bytes on stream {}", read, stream_id);
    ///     total_read += read;
    ///     assert_eq!(buf.get_ref().len(), total_read);
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn stream_recv_buf<B: bytes::BufMut>(
        &mut self, stream_id: u64, out: B,
    ) -> Result<(usize, bool)> {
        self.do_stream_recv(stream_id, RecvAction::Emit { out })
    }

    /// Discard contiguous data from a stream without copying.
    ///
    /// On success the amount of bytes discarded and a flag indicating the fin
    /// state is returned as a tuple, or [`Done`] if there is no data to
    /// discard.
    ///
    /// Discarding data from a stream may trigger queueing of control messages
    /// (e.g. `MAX_STREAM_DATA`). [`send()`] should be called afterwards.
    ///
    /// # Errors
    ///
    /// Returns the same receive errors as [`Self::stream_recv`].
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`send()`]: struct.Connection.html#method.send
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// # let stream_id = 0;
    /// while let Ok((read, fin)) = conn.stream_discard(stream_id, 1) {
    ///     println!("Discarded {} byte(s) on stream {}", read, stream_id);
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn stream_discard(
        &mut self, stream_id: u64, len: usize,
    ) -> Result<(usize, bool)> {
        // `do_stream_recv()` is generic on the kind of `BufMut` in RecvAction.
        // Since we are discarding, it doesn't matter, but the compiler still
        // wants to know, so we say `&mut [u8]`.
        self.do_stream_recv::<&mut [u8]>(stream_id, RecvAction::Discard { len })
    }

    // Reads or discards contiguous data from a stream.
    //
    // Passing an `action` of `StreamRecvAction::Emit` results in a read into
    // the provided slice. It must be sized by the caller and will be populated
    // up to its capacity.
    //
    // Passing an `action` of `StreamRecvAction::Discard` results in discard up
    // to the indicated length.
    //
    // On success the amount of bytes read or discarded, and a flag indicating
    // the fin state, is returned as a tuple, or [`Done`] if there is no data to
    // read or discard.
    //
    // Reading or discarding data from a stream may trigger queueing of control
    // messages (e.g. MAX_STREAM_DATA). [`send()`] should be called afterwards.
    //
    // [`Done`]: enum.Error.html#variant.Done
    // [`send()`]: struct.Connection.html#method.send
    fn do_stream_recv<B: bytes::BufMut>(
        &mut self, stream_id: u64, action: RecvAction<B>,
    ) -> Result<(usize, bool)> {
        // We can't read on our own unidirectional streams.
        if !stream::is_bidi(stream_id) &&
            stream::is_local(stream_id, self.is_server)
        {
            return Err(Error::InvalidStreamState(stream_id));
        }

        let stream = self
            .streams
            .get_mut(stream_id)
            .ok_or(Error::InvalidStreamState(stream_id))?;

        if !stream.is_readable() {
            return Err(Error::Done);
        }

        let priority_key = Arc::clone(stream.priority_key());

        #[cfg(feature = "qlog")]
        let offset = stream.recv.off_front();

        #[cfg(feature = "qlog")]
        let to = match action {
            RecvAction::Emit { .. } => Some(DataRecipient::Application),

            RecvAction::Discard { .. } => Some(DataRecipient::Dropped),
        };

        let (read, fin) = match stream.recv.emit_or_discard(action) {
            Ok(v) => v,

            Err(e) => {
                // A StreamReset read completes the receive side, but an
                // unreported STOP error still needs the send-side state.
                if stream.is_collectable() {
                    self.streams.collect(stream_id);
                }

                self.streams.remove_readable(&priority_key);
                return Err(e);
            },
        };

        self.flow_control.add_consumed(read as u64);

        let readable = stream.is_readable();

        let collectable = stream.is_collectable();

        if stream.recv.almost_full() {
            self.streams.insert_almost_full(stream_id);
        }

        if !readable {
            self.streams.remove_readable(&priority_key);
        }

        if collectable {
            self.streams.collect(stream_id);
        }

        qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
            let ev_data = EventData::QuicStreamDataMoved(
                qlog::events::quic::StreamDataMoved {
                    stream_id: Some(stream_id),
                    offset: Some(offset),
                    raw: Some(RawInfo {
                        length: Some(read as u64),
                        ..Default::default()
                    }),
                    from: Some(DataRecipient::Transport),
                    to,
                    additional_info: fin
                        .then_some(DataMovedAdditionalInfo::FinSet),
                },
            );

            let now = Instant::now();
            q.add_event_data_with_instant(ev_data, now).ok();
        });

        if priority_key.incremental && readable {
            // Shuffle the incremental stream to the back of the queue.
            self.streams.remove_readable(&priority_key);
            self.streams
                .enqueue(&priority_key, stream::PriorityQueue::Readable);
        }

        Ok((read, fin))
    }

    /// Writes data to a stream.
    ///
    /// On success the number of bytes written is returned, or [`Done`] if no
    /// data was written (e.g. because the stream has no capacity).
    ///
    /// Applications can provide a 0-length buffer with the fin flag set to
    /// true. This will lead to a 0-length FIN STREAM frame being sent at the
    /// latest offset. The `Ok(0)` value is only returned when the application
    /// provided a 0-length buffer.
    ///
    /// In addition, if the peer has signalled that it doesn't want to receive
    /// any more data from this stream by sending the `STOP_SENDING` frame, the
    /// [`StreamStopped`] error will be returned instead of any data.
    ///
    /// Note that in order to avoid buffering an infinite amount of data in the
    /// stream's send buffer, streams are only allowed to buffer outgoing data
    /// up to the amount that the peer allows it to send (that is, up to the
    /// stream's outgoing flow control capacity).
    ///
    /// This means that the number of written bytes returned can be lower than
    /// the length of the input buffer when the stream doesn't have enough
    /// capacity for the operation to complete. The application should retry the
    /// operation once the stream is reported as writable again.
    ///
    /// Applications should call this method only after the handshake is
    /// completed (whenever [`is_established()`] returns `true`) or during
    /// early data if enabled (whenever [`is_in_early_data()`] returns `true`).
    ///
    /// # Errors
    ///
    /// Returns `Error::Done` when nonempty data cannot be buffered,
    /// `Error::StreamLimit` if opening a new stream exceeds the peer's limit,
    /// `Error::InvalidStreamState` for a disallowed stream,
    /// `Error::StreamStopped` if the peer stopped the stream, or
    /// `Error::FinalSize` for an incompatible final offset.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`StreamStopped`]: enum.Error.html#variant.StreamStopped
    /// [`is_established()`]: struct.Connection.html#method.is_established
    /// [`is_in_early_data()`]: struct.Connection.html#method.is_in_early_data
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = "127.0.0.1:4321".parse().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// # let stream_id = 0;
    /// conn.stream_send(stream_id, b"hello", true)?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn stream_send(
        &mut self, stream_id: u64, buf: &[u8], fin: bool,
    ) -> Result<usize> {
        self.stream_do_send(
            stream_id,
            buf,
            fin,
            |stream: &mut stream::Stream<F>,
             buf: &[u8],
             cap: usize,
             fin: bool| {
                stream.send.write(&buf[..cap], fin).map(|v| (v, v))
            },
        )
    }

    /// Writes data to a stream with zero copying, instead, it appends the
    /// provided buffer directly to the send queue if the capacity allows
    /// it.
    ///
    /// On a successful partial write the remaining, unwritten buffer is
    /// returned. The application should retry it once the stream is writable
    /// again.
    ///
    /// # Errors
    ///
    /// Returns the same send errors as [`Self::stream_send`]. On error the
    /// owned input buffer is not returned.
    pub fn stream_send_zc(
        &mut self, stream_id: u64, buf: F::Buf, fin: bool,
    ) -> Result<(usize, Option<F::Buf>)>
    where
        F::Buf: BufSplit,
    {
        self.stream_do_send(
            stream_id,
            buf,
            fin,
            |stream: &mut stream::Stream<F>,
             buf: F::Buf,
             cap: usize,
             fin: bool| {
                let (sent, remaining) = stream.send.append_buf(buf, cap, fin)?;
                Ok((sent, (sent, remaining)))
            },
        )
    }

    fn stream_do_send<B, R, SND>(
        &mut self, stream_id: u64, buf: B, fin: bool, write_fn: SND,
    ) -> Result<R>
    where
        B: AsRef<[u8]>,
        SND: FnOnce(&mut stream::Stream<F>, B, usize, bool) -> Result<(usize, R)>,
    {
        // We can't write on the peer's unidirectional streams.
        if !stream::is_bidi(stream_id) &&
            !stream::is_local(stream_id, self.is_server)
        {
            return Err(Error::InvalidStreamState(stream_id));
        }

        let len = buf.as_ref().len();

        // Mark the connection as blocked if the connection-level flow control
        // limit doesn't let us buffer all the data.
        //
        // Note that this is separate from "send capacity" as that also takes
        // congestion control into consideration.
        if self.max_tx_data.saturating_sub(self.tx_data) < len as u64 {
            self.blocked_limit = Some(self.max_tx_data);
        }

        let cap = self.tx_cap;

        // Get existing stream or create a new one.
        let stream = match self.get_or_create_stream(stream_id, true) {
            Ok(v) => v,

            Err(Error::StreamLimit) => {
                // If the local endpoint has exhausted the peer's stream count
                // limit, record the current limit so that a STREAMS_BLOCKED
                // frame can be sent.
                if self.enable_send_streams_blocked &&
                    stream::is_local(stream_id, self.is_server)
                {
                    if stream::is_bidi(stream_id) {
                        let limit = self.streams.peer_max_streams_bidi();
                        self.streams_blocked_bidi_state.update_at(limit);
                    } else {
                        let limit = self.streams.peer_max_streams_uni();
                        self.streams_blocked_uni_state.update_at(limit);
                    }
                }

                return Err(Error::StreamLimit);
            },

            Err(e) => return Err(e),
        };

        #[cfg(feature = "qlog")]
        let offset = stream.send.off_back();

        let was_writable = stream.is_writable();

        let was_flushable = stream.is_flushable();

        // Return the stop before collecting a completed stream.
        if let Err(Error::StreamStopped(e)) = stream.send.cap() {
            self.streams.mark_stop_reported(stream_id);
            return Err(Error::StreamStopped(e));
        }

        let priority_key = Arc::clone(stream.priority_key());

        // Truncate the input buffer based on the connection's send capacity if
        // necessary.
        //
        // When the cap is zero, the method returns Ok(0) *only* when the passed
        // buffer is empty. We return Error::Done otherwise.
        if cap == 0 && len > 0 {
            if was_writable {
                // When `stream_writable_next()` returns a stream, the writable
                // mark is removed, but because the stream is blocked by the
                // connection-level send capacity it won't be marked as writable
                // again once the capacity increases.
                //
                // Since the stream is writable already, mark it here instead.
                self.streams
                    .enqueue(&priority_key, stream::PriorityQueue::Writable);
            }

            return Err(Error::Done);
        }

        let (cap, fin, blocked_by_cap) = if cap < len {
            (cap, false, true)
        } else {
            (len, fin, false)
        };

        let (sent, ret) = match write_fn(stream, buf, cap, fin) {
            Ok(v) => v,

            Err(e) => {
                self.streams.remove_writable(&priority_key);
                return Err(e);
            },
        };

        let incremental = stream.incremental();
        let priority_key = Arc::clone(stream.priority_key());

        let flushable = stream.is_flushable();

        let writable = stream.is_writable();

        if sent < cap {
            let max_off = stream.send.max_off();

            if stream.send.blocked_at() != Some(max_off) {
                stream.send.update_blocked_at(Some(max_off));
                self.streams.insert_blocked(stream_id, max_off);
            }
        } else {
            stream.send.update_blocked_at(None);
            self.streams.remove_blocked(stream_id);
        }

        // If the stream is now flushable push it to the flushable queue, but
        // only if it wasn't already queued.
        if flushable && !was_flushable {
            self.streams
                .enqueue(&priority_key, stream::PriorityQueue::Flushable);
        }

        if !writable {
            self.streams.remove_writable(&priority_key);
        } else if was_writable && blocked_by_cap {
            // When `stream_writable_next()` returns a stream, the writable
            // mark is removed, but because the stream is blocked by the
            // connection-level send capacity it won't be marked as writable
            // again once the capacity increases.
            //
            // Since the stream is writable already, mark it here instead.
            self.streams
                .enqueue(&priority_key, stream::PriorityQueue::Writable);
        }

        self.tx_cap -= sent;

        self.tx_data += sent as u64;

        self.streams.add_tx_buffered(sent as u64);

        qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
            let ev_data = EventData::QuicStreamDataMoved(
                qlog::events::quic::StreamDataMoved {
                    stream_id: Some(stream_id),
                    offset: Some(offset),
                    raw: Some(RawInfo {
                        length: Some(sent as u64),
                        ..Default::default()
                    }),
                    from: Some(DataRecipient::Application),
                    to: Some(DataRecipient::Transport),
                    additional_info: fin
                        .then_some(DataMovedAdditionalInfo::FinSet),
                },
            );

            let now = Instant::now();
            q.add_event_data_with_instant(ev_data, now).ok();
        });

        if sent == 0 && cap > 0 {
            return Err(Error::Done);
        }

        if incremental && writable {
            // Shuffle the incremental stream to the back of the queue.
            self.streams.remove_writable(&priority_key);
            self.streams
                .enqueue(&priority_key, stream::PriorityQueue::Writable);
        }

        Ok(ret)
    }

    /// Sets the priority for a stream.
    ///
    /// A stream's priority determines the order in which stream data is sent
    /// on the wire (streams with lower priority are sent first). Streams are
    /// created with a default priority of `127`.
    ///
    /// The target stream is created if it did not exist before calling this
    /// method.
    ///
    /// # Errors
    ///
    /// Returns `Error::StreamLimit` if creating the stream exceeds the peer's
    /// limit, or `Error::InvalidStreamState` for an invalid stream identifier.
    pub fn stream_priority(
        &mut self, stream_id: u64, urgency: u8, incremental: bool,
    ) -> Result<()> {
        // Get existing stream or create a new one, but if the stream
        // has already been closed and collected, ignore the prioritization.
        match self.get_or_create_stream(stream_id, true) {
            Ok(_) => (),

            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        }

        self.streams.set_priority(stream_id, urgency, incremental);

        Ok(())
    }

    /// Shuts down reading or writing from/to the specified stream.
    ///
    /// When the `direction` argument is set to [`Shutdown::Read`], outstanding
    /// data in the stream's receive buffer is dropped, and no additional data
    /// is added to it. Data received after calling this method is still
    /// validated and acked but not stored, and [`stream_recv()`] will not
    /// return it to the application. In addition, a `STOP_SENDING` frame will
    /// be sent to the peer to signal it to stop sending data.
    ///
    /// When the `direction` argument is set to [`Shutdown::Write`], outstanding
    /// data in the stream's send buffer is dropped, and no additional data is
    /// added to it. Data passed to [`stream_send()`] after calling this method
    /// will be ignored. In addition, a `RESET_STREAM` frame will be sent to the
    /// peer to signal the reset.
    ///
    /// Locally-initiated unidirectional streams can only be closed in the
    /// [`Shutdown::Write`] direction. Remotely-initiated unidirectional streams
    /// can only be closed in the [`Shutdown::Read`] direction. Using an
    /// incorrect direction will return [`InvalidStreamState`].
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidStreamState` for an unsupported shutdown
    /// direction, or `Error::Done` if the stream does not exist or the selected
    /// side has already been shut down.
    ///
    /// [`Shutdown::Read`]: enum.Shutdown.html#variant.Read
    /// [`Shutdown::Write`]: enum.Shutdown.html#variant.Write
    /// [`stream_recv()`]: struct.Connection.html#method.stream_recv
    /// [`stream_send()`]: struct.Connection.html#method.stream_send
    /// [`InvalidStreamState`]: enum.Error.html#variant.InvalidStreamState
    pub fn stream_shutdown(
        &mut self, stream_id: u64, direction: Shutdown, err: u64,
    ) -> Result<()> {
        // Don't try to stop a local unidirectional stream.
        if direction == Shutdown::Read &&
            stream::is_local(stream_id, self.is_server) &&
            !stream::is_bidi(stream_id)
        {
            return Err(Error::InvalidStreamState(stream_id));
        }

        // Don't try to reset a remote unidirectional stream.
        if direction == Shutdown::Write &&
            !stream::is_local(stream_id, self.is_server) &&
            !stream::is_bidi(stream_id)
        {
            return Err(Error::InvalidStreamState(stream_id));
        }

        // Get existing stream.
        let stream = self.streams.get_mut(stream_id).ok_or(Error::Done)?;

        let priority_key = Arc::clone(stream.priority_key());

        match direction {
            Shutdown::Read => {
                let consumed = stream.recv.shutdown()?;
                self.flow_control.add_consumed(consumed);

                // Discarding unread data can complete the receive side, so no
                // later read would collect the stream.
                let collectable = stream.is_collectable();

                if !stream.recv.is_fin() {
                    self.streams.insert_stopped(stream_id, err);
                }

                // Once shutdown, the stream is guaranteed to be non-readable.
                self.streams.remove_readable(&priority_key);

                self.stopped_stream_local_count =
                    self.stopped_stream_local_count.saturating_add(1);

                if collectable {
                    self.streams.collect(stream_id);
                }
            },

            Shutdown::Write => {
                // Save the buffered length before shutdown (shutdown clears the
                // buffer).
                let buffered_len = stream.send.buffered_bytes();

                let (final_size, unsent) = stream.send.shutdown()?;

                // Claw back some flow control allowance from data that was
                // buffered but not actually sent before the stream was reset.
                self.tx_data = self.tx_data.saturating_sub(unsent);

                // Update tx_buffered: subtract only the buffered data, not
                // inflight data.
                self.streams.sub_tx_buffered(buffered_len);

                // Match App-to-Transport moves with Transport-to-Dropped moves.
                // A Network transition would distinguish sent bytes from drops
                // before transmission.
                qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
                    let ev_data = EventData::QuicStreamDataMoved(
                        qlog::events::quic::StreamDataMoved {
                            stream_id: Some(stream_id),
                            offset: Some(final_size),
                            raw: Some(RawInfo {
                                length: Some(unsent),
                                ..Default::default()
                            }),
                            from: Some(DataRecipient::Transport),
                            to: Some(DataRecipient::Dropped),
                            ..Default::default()
                        },
                    );

                    q.add_event_data_with_instant(ev_data, Instant::now()).ok();
                });

                // Update send capacity.
                self.update_tx_cap();

                self.streams.insert_reset(stream_id, err, final_size);

                // Once shutdown, the stream is guaranteed to be non-writable.
                self.streams.remove_writable(&priority_key);

                self.reset_stream_local_count =
                    self.reset_stream_local_count.saturating_add(1);
            },
        }

        Ok(())
    }

    /// Returns the stream's send capacity in bytes.
    ///
    /// The returned capacity takes into account the stream's flow control limit
    /// as well as connection level flow and congestion control.
    ///
    /// If the specified stream doesn't exist (including when it has already
    /// been completed and closed), the [`InvalidStreamState`] error will be
    /// returned.
    ///
    /// In addition, if the peer has signalled that it doesn't want to receive
    /// any more data from this stream by sending the `STOP_SENDING` frame, the
    /// [`StreamStopped`] error will be returned.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidStreamState` if the stream is absent, or
    /// `Error::StreamStopped` if the peer stopped the stream.
    ///
    /// [`InvalidStreamState`]: enum.Error.html#variant.InvalidStreamState
    /// [`StreamStopped`]: enum.Error.html#variant.StreamStopped
    #[inline]
    pub fn stream_capacity(&mut self, stream_id: u64) -> Result<usize> {
        if let Some(stream) = self.streams.get(stream_id) {
            let stream_cap = match stream.send.cap() {
                Ok(v) => v,

                Err(Error::StreamStopped(e)) => {
                    self.streams.mark_stop_reported(stream_id);
                    return Err(Error::StreamStopped(e));
                },

                Err(e) => return Err(e),
            };

            let cap = cmp::min(self.tx_cap, stream_cap);
            return Ok(cap);
        }

        Err(Error::InvalidStreamState(stream_id))
    }

    /// Returns the next stream that has data to read.
    ///
    /// Note that once returned by this method, a stream ID will not be returned
    /// again until it is "re-armed".
    ///
    /// The application will need to read all of the pending data on the stream,
    /// and new data has to be received before the stream is reported again.
    ///
    /// This is unlike the [`readable()`] method, that returns the same list of
    /// readable streams when called multiple times in succession.
    ///
    /// [`readable()`]: struct.Connection.html#method.readable
    pub fn stream_readable_next(&mut self) -> Option<u64> {
        self.streams.pop_readable()
    }

    /// Returns true if the stream has data that can be read.
    #[must_use = "the result indicates whether the stream can currently be read"]
    pub fn stream_readable(&self, stream_id: u64) -> bool {
        self.streams
            .get(stream_id)
            .is_some_and(stream::Stream::is_readable)
    }

    /// Returns the number of contiguous bytes buffered for a stream, up to
    /// `max_len`.
    ///
    /// This is the length of the contiguous, in-order data buffered at the
    /// stream's current read offset, i.e. the bytes a call to [`stream_recv`]
    /// would return right now. Data received out of order that sits behind a
    /// gap is not counted, so this never reports bytes that are not yet
    /// readable.
    ///
    /// This is a companion to [`stream_readable`], which only reports *whether*
    /// data is available; this reports *how much*. It is intended for sizing a
    /// receive buffer. The cost is proportional to the number of contiguous
    /// buffered chunks at the front of the stream, up to `max_len`, and no data
    /// is copied.
    ///
    /// Returns 0 if the stream does not exist.
    ///
    /// [`stream_recv`]: struct.Connection.html#method.stream_recv
    /// [`stream_readable`]: struct.Connection.html#method.stream_readable
    #[must_use = "the result bounds the immediately readable stream data"]
    pub fn stream_readable_len(&self, stream_id: u64, max_len: usize) -> usize {
        self.streams
            .get(stream_id)
            .map_or(0, |stream| stream.recv.readable_len(max_len))
    }

    /// Returns the next stream that can be written to.
    ///
    /// Note that once returned by this method, a stream ID will not be returned
    /// again until it is "re-armed".
    ///
    /// This is unlike the [`writable()`] method, that returns the same list of
    /// writable streams when called multiple times in succession. It is not
    /// advised to use both `stream_writable_next()` and [`writable()`] on the
    /// same connection, as it may lead to unexpected results.
    ///
    /// The [`stream_writable()`] method can also be used to fine-tune when a
    /// stream is reported as writable again.
    ///
    /// A stopped stream is returned even without send capacity. Querying its
    /// capacity or writing to it returns [`StreamStopped`].
    ///
    /// [`stream_writable()`]: struct.Connection.html#method.stream_writable
    /// [`writable()`]: struct.Connection.html#method.writable
    /// [`StreamStopped`]: enum.Error.html#variant.StreamStopped
    pub fn stream_writable_next(&mut self) -> Option<u64> {
        self.streams.pop_writable(self.tx_cap)
    }

    /// Returns true if the stream has enough send capacity.
    ///
    /// When `len` more bytes can be buffered into the given stream's send
    /// buffer, `true` will be returned, `false` otherwise.
    ///
    /// In the latter case, if the additional data can't be buffered due to
    /// flow control limits, the peer will also be notified, and a "low send
    /// watermark" will be set for the stream, such that it is not going to be
    /// reported as writable again by [`stream_writable_next()`] until its send
    /// capacity reaches `len`.
    ///
    /// If the specified stream doesn't exist (including when it has already
    /// been completed and closed), the [`InvalidStreamState`] error will be
    /// returned.
    ///
    /// In addition, if the peer has signalled that it doesn't want to receive
    /// any more data from this stream by sending the `STOP_SENDING` frame, the
    /// [`StreamStopped`] error will be returned.
    ///
    /// # Errors
    ///
    /// Returns the same stream-state and peer-stop errors as
    /// [`Self::stream_capacity`].
    ///
    /// [`stream_writable_next()`]: struct.Connection.html#method.stream_writable_next
    /// [`InvalidStreamState`]: enum.Error.html#variant.InvalidStreamState
    /// [`StreamStopped`]: enum.Error.html#variant.StreamStopped
    #[inline]
    pub fn stream_writable(
        &mut self, stream_id: u64, len: usize,
    ) -> Result<bool> {
        if self.stream_capacity(stream_id)? >= len {
            return Ok(true);
        }

        let Some(stream) = self.streams.get_mut(stream_id) else {
            return Err(Error::InvalidStreamState(stream_id));
        };

        stream.send_lowat = cmp::max(1, len);

        let is_writable = stream.is_writable();

        let priority_key = Arc::clone(stream.priority_key());

        if self.max_tx_data.saturating_sub(self.tx_data) < len as u64 {
            self.blocked_limit = Some(self.max_tx_data);
        }

        if stream.send.cap()? < len {
            let max_off = stream.send.max_off();
            if stream.send.blocked_at() != Some(max_off) {
                stream.send.update_blocked_at(Some(max_off));
                self.streams.insert_blocked(stream_id, max_off);
            }
        } else if is_writable {
            // When `stream_writable_next()` returns a stream, the writable
            // mark is removed, but because the stream is blocked by the
            // connection-level send capacity it won't be marked as writable
            // again once the capacity increases.
            //
            // Since the stream is writable already, mark it here instead.
            self.streams
                .enqueue(&priority_key, stream::PriorityQueue::Writable);
        }

        Ok(false)
    }

    /// Returns true if all the data has been read from the specified stream.
    ///
    /// This instructs the application that all the data received from the
    /// peer on the stream has been read, and there won't be anymore in the
    /// future.
    ///
    /// Basically this returns true when the peer either set the `fin` flag
    /// for the stream, or sent `RESET_STREAM`.
    #[inline]
    #[must_use = "the result indicates whether the stream receive side is complete"]
    pub fn stream_finished(&self, stream_id: u64) -> bool {
        self.streams
            .get(stream_id)
            .is_none_or(|stream| stream.recv.is_fin())
    }

    /// Returns true if the specified stream is closed.
    ///
    /// For bidirectional streams this happens when both the receive and send
    /// sides have signaled `fin`. For unidirectional streams only the
    /// relevant direction is checked, depending on whether the stream was
    /// created locally or not.
    ///
    /// This also returns true if the stream has already been collected, but
    /// returns false if the stream was never opened.
    #[inline]
    #[must_use = "the result indicates whether the stream is closed"]
    pub fn stream_closed(&self, stream_id: u64) -> bool {
        let Some(stream) = self.streams.get(stream_id) else {
            return self.streams.is_collected(stream_id);
        };

        match (stream.bidi, stream.local) {
            // For bidirectional streams both directions must have signaled
            // FIN.
            (true, _) => stream.recv.is_fin() && stream.send.is_fin(),

            // For unidirectional streams created locally, only the send side
            // is checked.
            (false, true) => stream.send.is_fin(),

            // For unidirectional streams created by the peer, only the
            // receive side is checked.
            (false, false) => stream.recv.is_fin(),
        }
    }

    /// Returns the number of bidirectional streams that can be created
    /// before the peer's stream count limit is reached.
    ///
    /// This can be useful to know if it's possible to create a bidirectional
    /// stream without trying it first.
    #[inline]
    #[must_use = "the result bounds additional bidirectional streams"]
    pub const fn peer_streams_left_bidi(&self) -> u64 {
        self.streams.peer_streams_left_bidi()
    }

    /// Returns the number of unidirectional streams that can be created
    /// before the peer's stream count limit is reached.
    ///
    /// This can be useful to know if it's possible to create a unidirectional
    /// stream without trying it first.
    #[inline]
    #[must_use = "the result bounds additional unidirectional streams"]
    pub const fn peer_streams_left_uni(&self) -> u64 {
        self.streams.peer_streams_left_uni()
    }

    /// Returns an iterator over streams that have outstanding data to read.
    ///
    /// Note that the iterator will only include streams that were readable at
    /// the time the iterator itself was created (i.e. when `readable()` was
    /// called). To account for newly readable streams, the iterator needs to
    /// be created again.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// // Iterate over readable streams.
    /// for stream_id in conn.readable() {
    ///     // Stream is readable, read until there's no more data.
    ///     while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut buf) {
    ///         println!("Got {} bytes on stream {}", read, stream_id);
    ///     }
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    #[inline]
    #[must_use = "the returned iterator identifies readable streams"]
    pub fn readable(&self) -> StreamIter {
        self.streams.readable()
    }

    /// Returns an iterator over streams that can be written in priority order.
    ///
    /// The priority order is based on RFC 9218 scheduling recommendations.
    /// Stream priority can be controlled using [`stream_priority()`]. In order
    /// to support fairness requirements, each time this method is called,
    /// internal state is updated. Therefore the iterator ordering can change
    /// between calls, even if no streams were added or removed.
    ///
    /// A "writable" stream is a stream that has enough flow control capacity to
    /// send data to the peer. To avoid buffering an infinite amount of data,
    /// streams are only allowed to buffer outgoing data up to the amount that
    /// the peer allows to send.
    ///
    /// Stopped streams are also included so that a write or capacity query can
    /// return [`StreamStopped`], even without connection send capacity.
    ///
    /// Note that the iterator will only include streams that were writable at
    /// the time the iterator itself was created (i.e. when `writable()` was
    /// called). To account for newly writable streams, the iterator needs to be
    /// created again.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let local = socket.local_addr().unwrap();
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// // Iterate over writable streams.
    /// for stream_id in conn.writable() {
    ///     // Stream is writable, write some data.
    ///     if let Ok(written) = conn.stream_send(stream_id, &buf, false) {
    ///         println!("Written {} bytes on stream {}", written, stream_id);
    ///     }
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    /// [`stream_priority()`]: struct.Connection.html#method.stream_priority
    /// [`StreamStopped`]: enum.Error.html#variant.StreamStopped
    #[inline]
    #[must_use = "the returned iterator identifies writable streams"]
    pub fn writable(&self) -> StreamIter {
        // Stopped streams must be reported even without send capacity.
        if self.tx_cap == 0 {
            return self.streams.stopped_writable();
        }

        self.streams.writable()
    }

    /// Returns the maximum possible size of egress UDP payloads.
    ///
    /// This is the maximum size of UDP payloads that can be sent, and depends
    /// on both the configured maximum send payload size of the local endpoint
    /// (as configured with [`set_max_send_udp_payload_size()`]), as well as
    /// the transport parameter advertised by the remote peer.
    ///
    /// Note that this value can change during the lifetime of the connection,
    /// but should remain stable across consecutive calls to [`send()`].
    ///
    /// [`set_max_send_udp_payload_size()`]:
    ///     struct.Config.html#method.set_max_send_udp_payload_size
    /// [`send()`]: struct.Connection.html#method.send
    #[must_use = "the result bounds the outgoing UDP payload size"]
    pub fn max_send_udp_payload_size(&self) -> usize {
        let max_datagram_size = self
            .paths
            .get_active()
            .ok()
            .map(|p| p.recovery.max_datagram_size());

        if let Some(max_datagram_size) = max_datagram_size {
            if self.is_established() {
                let peer = usize::try_from(
                    self.peer_transport_params.max_udp_payload_size,
                )
                .unwrap_or(usize::MAX);
                return max_datagram_size
                    .min(peer)
                    .min(MAX_SEND_UDP_PAYLOAD_SIZE);
            }
        }

        // Allow for 1200 bytes (minimum QUIC packet size) during the
        // handshake.
        MIN_CLIENT_INITIAL_LEN
    }

    /// Schedule an ack-eliciting packet on the active path.
    ///
    /// QUIC packets might not contain ack-eliciting frames during normal
    /// operating conditions. If the packet would already contain
    /// ack-eliciting frames, this method does not change any behavior.
    /// However, if the packet would not ordinarily contain ack-eliciting
    /// frames, this method ensures that a PING frame sent.
    ///
    /// Calling this method multiple times before [`send()`] has no effect.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidState` if no active path is available. A closed
    /// or draining connection is a successful no-op.
    ///
    /// [`send()`]: struct.Connection.html#method.send
    pub fn send_ack_eliciting(&mut self) -> Result<()> {
        if self.is_closed() || self.is_draining() {
            return Ok(());
        }
        self.paths.get_active_mut()?.needs_ack_eliciting = true;
        Ok(())
    }

    /// Schedule an ack-eliciting packet on the specified path.
    ///
    /// See [`send_ack_eliciting()`] for more detail. [`InvalidState`] is
    /// returned if there is no record of the path.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidState` if the requested path is unavailable.
    /// A closed or draining connection is a successful no-op.
    ///
    /// [`send_ack_eliciting()`]: struct.Connection.html#method.send_ack_eliciting
    /// [`InvalidState`]: enum.Error.html#variant.InvalidState
    pub fn send_ack_eliciting_on_path(
        &mut self, local: SocketAddr, peer: SocketAddr,
    ) -> Result<()> {
        if self.is_closed() || self.is_draining() {
            return Ok(());
        }
        let path_id = self
            .paths
            .path_id_from_addrs(&(local, peer))
            .ok_or(Error::InvalidState)?;
        self.paths.get_mut(path_id)?.needs_ack_eliciting = true;
        Ok(())
    }

    /// Reads the first received DATAGRAM.
    ///
    /// On success the DATAGRAM's data is returned along with its size.
    ///
    /// [`Done`] is returned if there is no data to read.
    ///
    /// [`BufferTooShort`] is returned if the provided buffer is too small for
    /// the DATAGRAM.
    ///
    /// # Errors
    ///
    /// Returns `Error::Done` if the receive queue is empty or
    /// `Error::BufferTooShort` if the first DATAGRAM does not fit. The DATAGRAM
    /// is removed from the queue even when the buffer is too small.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`BufferTooShort`]: enum.Error.html#variant.BufferTooShort
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// let mut dgram_buf = [0; 512];
    /// while let Ok((len)) = conn.dgram_recv(&mut dgram_buf) {
    ///     println!("Got {} bytes of DATAGRAM", len);
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    #[inline]
    pub fn dgram_recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.dgram_recv_into(buf)
    }

    /// Reads one DATAGRAM into a caller-provided buffer, which may contain
    /// uninitialized output storage. Like `dgram_recv`, this removes a
    /// datagram even when the output is too short.
    ///
    /// # Errors
    /// Returns `Error::Done` for an empty queue or `Error::BufferTooShort`
    /// when the first datagram does not fit.
    #[inline]
    pub fn dgram_recv_into<B: bytes::BufMut>(
        &mut self, mut buf: B,
    ) -> Result<usize> {
        let d = self.dgram_recv_buf()?;
        let bytes = d.as_ref();
        if bytes.len() > buf.remaining_mut() {
            return Err(Error::BufferTooShort);
        }
        buf.put_slice(bytes);
        Ok(bytes.len())
    }

    /// Reads the first received DATAGRAM.
    ///
    /// This is the same as [`dgram_recv()`] but returns the DATAGRAM as an
    /// owned buffer instead of copying into the provided buffer.
    ///
    /// # Errors
    ///
    /// Returns `Error::Done` if the receive queue is empty.
    ///
    /// [`dgram_recv()`]: struct.Connection.html#method.dgram_recv
    #[inline]
    pub fn dgram_recv_buf(&mut self) -> Result<F::DgramBuf> {
        self.dgram_recv_queue.pop().ok_or(Error::Done)
    }

    /// Reads the first received DATAGRAM without removing it from the queue.
    ///
    /// On success the DATAGRAM's data is returned along with the actual number
    /// of bytes peeked. The requested length cannot exceed the DATAGRAM's
    /// actual length.
    ///
    /// [`Done`] is returned if there is no data to read.
    ///
    /// [`BufferTooShort`] is returned if the provided buffer is smaller the
    /// number of bytes to peek.
    ///
    /// # Errors
    ///
    /// Returns `Error::Done` if the receive queue is empty or
    /// `Error::BufferTooShort` if the output buffer cannot hold the requested
    /// portion. The queued DATAGRAM is not removed.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`BufferTooShort`]: enum.Error.html#variant.BufferTooShort
    #[inline]
    pub fn dgram_recv_peek(&self, buf: &mut [u8], len: usize) -> Result<usize> {
        self.dgram_recv_queue.peek_front_bytes(buf, len)
    }

    /// Returns the length of the first stored DATAGRAM.
    #[inline]
    #[must_use = "the result gives the next datagram size if one is queued"]
    pub fn dgram_recv_front_len(&self) -> Option<usize> {
        self.dgram_recv_queue.peek_front_len()
    }

    /// Returns the number of items in the DATAGRAM receive queue.
    #[inline]
    #[must_use = "the result describes the incoming datagram queue occupancy"]
    pub const fn dgram_recv_queue_len(&self) -> usize {
        self.dgram_recv_queue.len()
    }

    /// Returns the total size of all items in the DATAGRAM receive queue.
    #[inline]
    #[must_use = "the result describes the incoming datagram queue byte occupancy"]
    pub const fn dgram_recv_queue_byte_size(&self) -> usize {
        self.dgram_recv_queue.byte_size()
    }

    /// Returns the number of items in the DATAGRAM send queue.
    #[inline]
    #[must_use = "the result describes the outgoing datagram queue occupancy"]
    pub const fn dgram_send_queue_len(&self) -> usize {
        self.dgram_send_queue.len()
    }

    /// Returns the total size of all items in the DATAGRAM send queue.
    #[inline]
    #[must_use = "the result describes the outgoing datagram queue byte occupancy"]
    pub const fn dgram_send_queue_byte_size(&self) -> usize {
        self.dgram_send_queue.byte_size()
    }

    /// Returns whether or not the DATAGRAM send queue is full.
    #[inline]
    #[must_use = "the result determines whether more datagrams can be queued"]
    pub const fn is_dgram_send_queue_full(&self) -> bool {
        self.dgram_send_queue.is_full()
    }

    /// Returns whether or not the DATAGRAM recv queue is full.
    #[inline]
    #[must_use = "the result indicates incoming datagram queue saturation"]
    pub const fn is_dgram_recv_queue_full(&self) -> bool {
        self.dgram_recv_queue.is_full()
    }

    /// Sends data in a DATAGRAM frame.
    ///
    /// [`Done`] is returned if no data was written.
    /// [`InvalidState`] is returned if the peer does not support DATAGRAM.
    /// [`BufferTooShort`] is returned if the DATAGRAM frame length is larger
    /// than peer's supported DATAGRAM frame length. Use
    /// [`dgram_max_writable_len()`] to get the largest supported DATAGRAM
    /// frame length.
    ///
    /// Note that there is no flow control of DATAGRAM frames, so in order to
    /// avoid buffering an infinite amount of frames we apply an internal
    /// limit.
    ///
    /// # Errors
    ///
    /// Returns `Error::Done` if the send queue has no room,
    /// `Error::InvalidState` if DATAGRAM support or the active path is
    /// unavailable, or `Error::BufferTooShort` if the payload exceeds the
    /// permitted size.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`InvalidState`]: enum.Error.html#variant.InvalidState
    /// [`BufferTooShort`]: enum.Error.html#variant.BufferTooShort
    /// [`dgram_max_writable_len()`]:
    /// struct.Connection.html#method.dgram_max_writable_len
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// conn.dgram_send(b"hello")?;
    /// # Ok::<(), quiche::Error>(())
    /// ```
    pub fn dgram_send(&mut self, buf: &[u8]) -> Result<()> {
        self.dgram_send_buf(F::dgram_buf_from_slice(buf))
    }

    /// Sends data in a DATAGRAM frame.
    ///
    /// This is the same as [`dgram_send()`] but takes an owned buffer
    /// instead of a slice and avoids copying.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::dgram_send`].
    ///
    /// [`dgram_send()`]: struct.Connection.html#method.dgram_send
    pub fn dgram_send_buf(&mut self, buf: F::DgramBuf) -> Result<()> {
        let max_payload_len =
            self.dgram_max_writable_len().ok_or(Error::InvalidState)?;

        if buf.as_ref().len() > max_payload_len {
            return Err(Error::BufferTooShort);
        }

        self.dgram_send_queue.push(buf)?;

        let active_path = self.paths.get_active_mut()?;

        if self.dgram_send_queue.byte_size() >
            active_path.recovery.cwnd_available()
        {
            active_path.recovery.update_app_limited(false);
        }

        Ok(())
    }

    /// Purges queued outgoing DATAGRAMs matching the predicate.
    ///
    /// In other words, remove all elements `e` such that `f(&e)` returns true.
    ///
    /// ## Examples:
    /// ```no_run
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// conn.dgram_send(b"hello")?;
    /// conn.dgram_purge_outgoing(&|d: &[u8]| -> bool { d[0] == 0 });
    /// # Ok::<(), quiche::Error>(())
    /// ```
    #[inline]
    pub fn dgram_purge_outgoing<FN: Fn(&[u8]) -> bool>(&mut self, f: FN) {
        self.dgram_send_queue.purge(f);
    }

    /// Returns the maximum DATAGRAM payload that can be sent.
    ///
    /// [`None`] is returned if the peer hasn't advertised a maximum DATAGRAM
    /// frame size.
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut buf = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let local = socket.local_addr().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// if let Some(payload_size) = conn.dgram_max_writable_len() {
    ///     if payload_size > 5 {
    ///         conn.dgram_send(b"hello")?;
    ///     }
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    #[inline]
    #[must_use = "the result bounds the next outgoing datagram payload"]
    pub fn dgram_max_writable_len(&self) -> Option<usize> {
        match self.peer_transport_params.max_datagram_frame_size {
            None => None,
            Some(peer_frame_len) => {
                let dcid = self.destination_id();
                // Start from the maximum packet size...
                let mut max_len = self.max_send_udp_payload_size();
                // ...subtract the Short packet header overhead...
                // (1 byte of pkt_len + len of dcid)
                max_len = max_len.saturating_sub(1 + dcid.len());
                // ...subtract the packet number (max len)...
                max_len = max_len.saturating_sub(packet::MAX_PKT_NUM_LEN);
                // ...subtract the crypto overhead...
                max_len = max_len.saturating_sub(
                    self.crypto_ctx[packet::Epoch::Application]
                        .crypto_overhead()?,
                );
                // ...clamp to what the peer can support. A limit larger
                // than the address space cannot constrain a local packet.
                max_len = cmp::min(
                    usize::try_from(peer_frame_len).unwrap_or(usize::MAX),
                    max_len,
                );
                // ...account for the type and the variable-width length.
                frame::payload_capacity(max_len.checked_sub(1)?)
                    .map(|(payload, _)| payload)
            },
        }
    }

    const fn dgram_enabled(&self) -> bool {
        self.local_transport_params
            .max_datagram_frame_size
            .is_some()
    }

    /// Returns when the next timeout event will occur.
    ///
    /// Once the timeout Instant has been reached, the [`on_timeout()`] method
    /// should be called. A timeout of `None` means that the timer should be
    /// disarmed.
    ///
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    #[must_use = "the result determines when connection timeout handling is due"]
    pub fn timeout_instant(&self) -> Option<Instant> {
        match self.lifecycle {
            ConnectionLifecycle::Closed(_) => None,
            ConnectionLifecycle::Draining { deadline, .. } => Some(deadline),
            ConnectionLifecycle::Active => {
                // Use the lowest timer value (i.e. "sooner") among idle and
                // loss detection timers. If they are both unset (i.e. `None`)
                // then the result is `None`, but if at least one of them is set
                // then a `Some(...)` value is returned.
                let path_timer = self
                    .paths
                    .iter()
                    .filter_map(|(_, p)| p.recovery.loss_detection_timer())
                    .min();

                let key_update_timer = self.crypto_ctx
                    [packet::Epoch::Application]
                    .key_update
                    .as_ref()
                    .map(|key_update| key_update.timer);

                let timers = [self.idle_timer, path_timer, key_update_timer];

                timers.into_iter().flatten().min()
            },
        }
    }

    /// Returns the amount of time until the next timeout event.
    ///
    /// Once the given duration has elapsed, the [`on_timeout()`] method should
    /// be called. A timeout of `None` means that the timer should be disarmed.
    ///
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    #[must_use = "the result determines how long to wait before timeout handling"]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout_instant().map(|timeout| {
            let now = Instant::now();

            if timeout <= now {
                Duration::ZERO
            } else {
                timeout.duration_since(now)
            }
        })
    }

    /// Processes a timeout event.
    ///
    /// If no timeout has occurred it does nothing.
    pub fn on_timeout(&mut self) {
        let now = Instant::now();

        match self.lifecycle {
            ConnectionLifecycle::Closed(_) => return,
            ConnectionLifecycle::Draining { deadline, origin } => {
                if deadline <= now {
                    trace!("{} draining timeout expired", self.trace_id);
                    self.mark_closed(CloseCause::Explicit(origin));
                }
                return;
            },
            ConnectionLifecycle::Active => (),
        }

        if let Some(timer) = self.idle_timer {
            if timer <= now {
                trace!("{} idle timeout expired", self.trace_id);

                self.mark_closed(CloseCause::IdleTimeout);
                return;
            }
        }

        if let Some(timer) = self.crypto_ctx[packet::Epoch::Application]
            .key_update
            .as_ref()
            .map(|key_update| key_update.timer)
        {
            if timer <= now {
                // Discard previous key once key update timer expired.
                let _ = self.crypto_ctx[packet::Epoch::Application]
                    .key_update
                    .take();
            }
        }

        let handshake_status = self.handshake_status();

        for (_, p) in self.paths.iter_mut() {
            if let Some(timer) = p.recovery.loss_detection_timer() {
                if timer <= now {
                    trace!("{} loss detection timeout expired", self.trace_id);

                    let OnLossDetectionTimeoutOutcome {
                        lost_packets,
                        lost_bytes,
                    } = p.on_loss_detection_timeout(
                        handshake_status,
                        now,
                        self.is_server,
                        &self.trace_id,
                    );

                    self.lost_count += lost_packets;
                    self.lost_bytes += lost_bytes as u64;

                    qlog_with_type!(QLOG_METRICS, self.qlog, q, {
                        p.recovery.maybe_qlog(q, now);
                    });
                }
            }
        }

        // Notify timeout events to the application.
        self.paths.notify_failed_validations();

        // If the active path failed, try to find a new candidate.
        if self.paths.get_active_path_id().is_err() {
            match self.paths.find_candidate_path() {
                Some(pid) => {
                    if self.set_active_path(pid, now).is_err() {
                        // The connection cannot continue.
                        self.mark_closed(CloseCause::NoViablePath);
                    }
                },

                // The connection cannot continue.
                None => {
                    self.mark_closed(CloseCause::NoViablePath);
                },
            }
        }
    }

    /// Requests the stack to perform path validation of the proposed 4-tuple.
    ///
    /// Probing new paths requires spare Connection IDs at both the host and the
    /// peer sides. If it is not the case, it raises an [`OutOfIdentifiers`].
    ///
    /// The probing of new addresses can only be done by the client. The server
    /// can only probe network paths that were previously advertised by
    /// [`PathEvent::New`]. If the server tries to probe such an unseen network
    /// path, this call raises an [`InvalidState`].
    ///
    /// The caller might also want to probe an existing path. In such case, it
    /// triggers a `PATH_CHALLENGE` frame, but it does not require spare CIDs.
    ///
    /// A server always probes a new path it observes. Calling this method is
    /// hence not required to validate a new path. However, a server can still
    /// request an additional path validation of the proposed 4-tuple.
    ///
    /// Calling this method several times before calling [`send()`] or
    /// [`send_on_path()`] results in a single probe being generated. An
    /// application wanting to send multiple in-flight probes must call this
    /// method again after having sent packets.
    ///
    /// Returns the Destination Connection ID sequence number associated to that
    /// path.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidState` if the path cannot be used (including an
    /// unseen path on a server), or `Error::OutOfIdentifiers` if a new path
    /// requires an unavailable connection ID.
    ///
    /// [`PathEvent::New`]: enum.PathEvent.html#variant.New
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    /// [`InvalidState`]: enum.Error.html#InvalidState
    /// [`send()`]: struct.Connection.html#method.send
    /// [`send_on_path()`]: struct.Connection.html#method.send_on_path
    pub fn probe_path(
        &mut self, local_addr: SocketAddr, peer_addr: SocketAddr,
    ) -> Result<u64> {
        // We may want to probe an existing path.
        let pid = match self.paths.path_id_from_addrs(&(local_addr, peer_addr)) {
            Some(pid) => pid,
            None => self.create_path_on_client(local_addr, peer_addr)?,
        };

        let path = self.paths.get_mut(pid)?;
        path.request_validation();

        path.active_dcid_seq.ok_or(Error::InvalidState)
    }

    /// Migrates the connection to a new local address `local_addr`.
    ///
    /// The behavior is similar to [`migrate()`], with the nuance that the
    /// connection only changes the local address, but not the peer one.
    ///
    /// See [`migrate()`] for the full specification of this method.
    ///
    /// # Errors
    ///
    /// Returns the same migration errors as [`Self::migrate`], or
    /// `Error::InvalidState` if there is no active path.
    ///
    /// [`migrate()`]: struct.Connection.html#method.migrate
    pub fn migrate_source(&mut self, local_addr: SocketAddr) -> Result<u64> {
        let peer_addr = self.paths.get_active()?.peer_addr();
        self.migrate(local_addr, peer_addr)
    }

    /// Migrates the connection over the given network path between `local_addr`
    /// and `peer_addr`.
    ///
    /// Connection migration can only be initiated by the client. Calling this
    /// method as a server returns [`InvalidState`].
    ///
    /// To initiate voluntary migration, there should be enough Connection IDs
    /// at both sides. If this requirement is not satisfied, this call returns
    /// [`OutOfIdentifiers`].
    ///
    /// Returns the Destination Connection ID associated to that migrated path.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidState` for server-initiated migration or an
    /// unusable path, or `Error::OutOfIdentifiers` when insufficient connection
    /// IDs are available.
    ///
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    /// [`InvalidState`]: enum.Error.html#InvalidState
    pub fn migrate(
        &mut self, local_addr: SocketAddr, peer_addr: SocketAddr,
    ) -> Result<u64> {
        if self.is_server {
            return Err(Error::InvalidState);
        }

        // If the path already exists, mark it as the active one.
        let (pid, dcid_seq) = if let Some(pid) =
            self.paths.path_id_from_addrs(&(local_addr, peer_addr))
        {
            let path = self.paths.get_mut(pid)?;

            // If it is already active, do nothing.
            if path.active() {
                return path.active_dcid_seq.ok_or(Error::OutOfIdentifiers);
            }

            // Ensures that a Source Connection ID has been dedicated to this
            // path, or a free one is available. This is only required if the
            // host uses non-zero length Source Connection IDs.
            if !self.ids.zero_length_scid() &&
                path.active_scid_seq.is_none() &&
                self.ids.available_scids() == 0
            {
                return Err(Error::OutOfIdentifiers);
            }

            // Ensures that the migrated path has a Destination Connection ID.
            let dcid_seq = if let Some(dcid_seq) = path.active_dcid_seq {
                dcid_seq
            } else {
                let dcid_seq = self
                    .ids
                    .lowest_available_dcid_seq()
                    .ok_or(Error::OutOfIdentifiers)?;

                self.ids.link_dcid_to_path_id(dcid_seq, pid)?;
                path.active_dcid_seq = Some(dcid_seq);

                dcid_seq
            };

            (pid, dcid_seq)
        } else {
            let pid = self.create_path_on_client(local_addr, peer_addr)?;

            let dcid_seq = self
                .paths
                .get(pid)?
                .active_dcid_seq
                .ok_or(Error::InvalidState)?;

            (pid, dcid_seq)
        };

        // Change the active path.
        self.set_active_path(pid, Instant::now())?;

        Ok(dcid_seq)
    }

    /// Provides additional source Connection IDs that the peer can use to reach
    /// this host.
    ///
    /// This triggers sending `NEW_CONNECTION_ID` frames if the provided Source
    /// Connection ID is not already present. In the case the caller tries to
    /// reuse a Connection ID with a different reset token, this raises an
    /// `InvalidState`.
    ///
    /// At any time, the peer cannot have more Destination Connection IDs than
    /// the maximum number of active Connection IDs it negotiated. In such case
    /// (i.e., when [`scids_left()`] returns 0), if the host agrees to
    /// request the removal of previous connection IDs, it sets the
    /// `retire_if_needed` parameter. Otherwise, an [`IdLimit`] is returned.
    ///
    /// Note that setting `retire_if_needed` does not prevent this function from
    /// returning an [`IdLimit`] in the case the caller wants to retire still
    /// unannounced Connection IDs.
    ///
    /// The caller is responsible for ensuring that the provided `scid` is not
    /// repeated several times over the connection. quiche ensures that as long
    /// as the provided Connection ID is still in use (i.e., not retired), it
    /// does not assign a different sequence number.
    ///
    /// Note that if the host uses zero-length Source Connection IDs, it cannot
    /// advertise Source Connection IDs and calling this method returns an
    /// [`InvalidState`].
    ///
    /// Returns the sequence number associated to the provided Connection ID.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidState` for zero-length IDs or conflicting
    /// ID/token reuse, or `Error::IdLimit` if the connection ID limit prevents
    /// insertion.
    ///
    /// [`scids_left()`]: struct.Connection.html#method.scids_left
    /// [`IdLimit`]: enum.Error.html#IdLimit
    /// [`InvalidState`]: enum.Error.html#InvalidState
    pub fn new_scid(
        &mut self, scid: &ConnectionId, reset_token: u128, retire_if_needed: bool,
    ) -> Result<u64> {
        self.ids.new_scid(
            ConnectionId::copy_from_slice(scid.as_ref()),
            Some(reset_token),
            true,
            None,
            retire_if_needed,
        )
    }

    /// Returns the number of source Connection IDs that are active. This is
    /// only meaningful if the host uses non-zero length Source Connection IDs.
    #[must_use = "the result counts active source connection IDs"]
    pub const fn active_scids(&self) -> usize {
        self.ids.active_source_cids()
    }

    /// Returns the number of additional source Connection IDs that can be
    /// provided to the peer without exceeding the limit it advertised.
    ///
    /// The limit is the minimum of the locally configured active connection
    /// ID limit and the peer's limit, subject to the addressable size of the
    /// internal connection ID collection.
    ///
    /// Returns `0` when the peer's limit is already reached or temporarily
    /// exceeded (e.g. during a SCID rotation where a retirement is in
    /// flight and `active_scids()` transiently exceeds the advertised
    /// limit).
    ///
    /// To obtain the maximum possible value allowed by the peer an application
    /// can instead inspect the [`peer_active_conn_id_limit`] value.
    ///
    /// [`peer_active_conn_id_limit`]: struct.Stats.html#structfield.peer_active_conn_id_limit
    #[inline]
    #[must_use = "the result bounds additional source connection IDs"]
    pub fn scids_left(&self) -> usize {
        self.ids
            .scids_left(self.local_transport_params.active_conn_id_limit)
    }

    /// Requests the retirement of the destination Connection ID used by the
    /// host to reach its peer.
    ///
    /// This triggers sending `RETIRE_CONNECTION_ID` frames.
    ///
    /// If the application tries to retire a non-existing Destination Connection
    /// ID sequence number, or if it uses zero-length Destination Connection ID,
    /// this method returns an [`InvalidState`].
    ///
    /// At any time, the host must have at least one Destination ID. If the
    /// application tries to retire the last one, or if the caller tries to
    /// retire the destination Connection ID used by the current active path
    /// while having neither spare Destination Connection IDs nor validated
    /// network paths, this method returns an [`OutOfIdentifiers`]. This
    /// behavior prevents the caller from stalling the connection due to the
    /// lack of validated path to send non-probing packets.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidState` for an unknown connection ID, zero-length
    /// IDs, or unavailable path state; `Error::OutOfIdentifiers` if retirement
    /// would leave no usable identifiers or path.
    ///
    /// [`InvalidState`]: enum.Error.html#InvalidState
    /// [`OutOfIdentifiers`]: enum.Error.html#OutOfIdentifiers
    pub fn retire_dcid(&mut self, dcid_seq: u64) -> Result<()> {
        if self.ids.zero_length_dcid() {
            return Err(Error::InvalidState);
        }

        let active_path_dcid_seq = self
            .paths
            .get_active()?
            .active_dcid_seq
            .ok_or(Error::InvalidState)?;

        let active_path_id = self.paths.get_active_path_id()?;

        if active_path_dcid_seq == dcid_seq &&
            self.ids.lowest_available_dcid_seq().is_none() &&
            !self
                .paths
                .iter()
                .any(|(pid, p)| pid != active_path_id && p.usable())
        {
            return Err(Error::OutOfIdentifiers);
        }

        if let Some(pid) = self.ids.retire_dcid(dcid_seq)? {
            // The retired Destination CID was associated to a given path. Let's
            // find an available DCID to associate to that path.
            let path = self.paths.get_mut(pid)?;
            let dcid_seq = self.ids.lowest_available_dcid_seq();

            if let Some(dcid_seq) = dcid_seq {
                self.ids.link_dcid_to_path_id(dcid_seq, pid)?;
            }

            path.active_dcid_seq = dcid_seq;
        }

        Ok(())
    }

    /// Processes path-specific events.
    ///
    /// On success it returns a [`PathEvent`], or `None` when there are no
    /// events to report. Please refer to [`PathEvent`] for the exhaustive event
    /// list.
    ///
    /// Note that all events are edge-triggered, meaning that once reported they
    /// will not be reported again by calling this method again, until the event
    /// is re-armed.
    ///
    /// [`PathEvent`]: enum.PathEvent.html
    pub fn path_event_next(&mut self) -> Option<PathEvent> {
        self.paths.pop_event()
    }

    /// Returns the number of source Connection IDs that are retired.
    #[must_use = "the result counts retired source connection IDs"]
    pub const fn retired_scids(&self) -> usize {
        self.ids.retired_source_cids()
    }

    /// Returns a source `ConnectionId` that has been retired.
    ///
    /// On success it returns a [`ConnectionId`], or `None` when there are no
    /// more retired connection IDs.
    ///
    /// [`ConnectionId`]: struct.ConnectionId.html
    pub fn retired_scid_next(&mut self) -> Option<ConnectionId<'static>> {
        self.ids.pop_retired_scid()
    }

    /// Returns the number of spare Destination Connection IDs, i.e.,
    /// Destination Connection IDs that are still unused.
    ///
    /// Note that this function returns 0 if the host uses zero length
    /// Destination Connection IDs.
    #[must_use = "the result counts unused destination connection IDs"]
    pub fn available_dcids(&self) -> usize {
        self.ids.available_dcids()
    }

    /// Returns an iterator over destination `SockAddr`s whose association
    /// with `from` forms a known QUIC path on which packets can be sent to.
    ///
    /// This function is typically used in combination with [`send_on_path()`].
    ///
    /// Note that the iterator includes all the possible combination of
    /// destination `SockAddr`s, even those whose sending is not required now.
    /// In other words, this is another way for the application to recall from
    /// past [`PathEvent::New`] events.
    ///
    /// [`PathEvent::New`]: enum.PathEvent.html#variant.New
    /// [`send_on_path()`]: struct.Connection.html#method.send_on_path
    ///
    /// ## Examples:
    ///
    /// ```no_run
    /// # let mut out = [0; 512];
    /// # let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    /// # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    /// # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
    /// # let local = socket.local_addr().unwrap();
    /// # let peer = "127.0.0.1:1234".parse().unwrap();
    /// # let mut conn = quiche::accept(&scid, None, local, peer, &mut config)?;
    /// // Iterate over possible destinations for the given local `SockAddr`.
    /// for dest in conn.paths_iter(local) {
    ///     loop {
    ///         let (write, send_info) =
    ///             match conn.send_on_path(&mut out, Some(local), Some(dest)) {
    ///                 Ok(v) => v,
    ///
    ///                 Err(quiche::Error::Done) => {
    ///                     // Done writing for this destination.
    ///                     break;
    ///                 },
    ///
    ///                 Err(e) => {
    ///                     // An error occurred, handle it.
    ///                     break;
    ///                 },
    ///             };
    ///
    ///         socket.send_to(&out[..write], &send_info.to).unwrap();
    ///     }
    /// }
    /// # Ok::<(), quiche::Error>(())
    /// ```
    #[inline]
    #[must_use = "the returned iterator identifies known paths for the source address"]
    pub fn paths_iter(&self, from: SocketAddr) -> SocketAddrIter {
        // Instead of trying to identify whether packets will be sent on the
        // given 4-tuple, simply filter paths that cannot be used.
        SocketAddrIter {
            sockaddrs: self
                .paths
                .iter()
                .filter(|(_, p)| p.active_dcid_seq.is_some())
                .filter(|(_, p)| p.usable() || p.probing_required())
                .filter(|(_, p)| p.local_addr() == from)
                .map(|(_, p)| p.peer_addr())
                .collect(),

            index: 0,
        }
    }

    /// Closes the connection with the given error and reason.
    ///
    /// The `app` parameter specifies whether an application close should be
    /// sent to the peer. Otherwise a normal connection close is sent.
    ///
    /// If `app` is true but the connection is not in a state that is safe to
    /// send an application error (not established nor in early data), in
    /// accordance with [RFC
    /// 9000](https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.3-3), the
    /// error code is changed to `APPLICATION_ERROR` and the reason phrase is
    /// cleared.
    ///
    /// Returns [`Done`] if the connection had already been closed.
    ///
    /// Note that the connection will not be closed immediately. An application
    /// should continue calling the [`recv()`], [`send()`], [`timeout()`] and
    /// [`on_timeout()`] methods as normal, until the [`is_closed()`] method
    /// returns `true`.
    ///
    /// # Errors
    ///
    /// Returns `Error::Done` if closure was already initiated, or the
    /// connection is closed or draining.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`recv()`]: struct.Connection.html#method.recv
    /// [`send()`]: struct.Connection.html#method.send
    /// [`timeout()`]: struct.Connection.html#method.timeout
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    /// [`is_closed()`]: struct.Connection.html#method.is_closed
    pub fn close(&mut self, app: bool, err: u64, reason: &[u8]) -> Result<()> {
        if self.is_closed() || self.is_draining() {
            return Err(Error::Done);
        }

        if self.local_error.is_some() {
            return Err(Error::Done);
        }

        let is_safe_to_send_app_data =
            self.is_established() || self.is_in_early_data();

        if app && !is_safe_to_send_app_data {
            // Clear error information.
            self.local_error = Some(ConnectionError {
                is_app: false,
                error_code: 0x0c,
                reason: vec![],
            });
        } else {
            self.local_error = Some(ConnectionError {
                is_app: app,
                error_code: err,
                reason: reason.to_vec(),
            });
        }

        // Close immediately if no packet was processed successfully.
        if self.recv_count == 0 {
            self.mark_closed(CloseCause::Explicit(CloseOrigin::Local));
        }

        Ok(())
    }

    /// Returns a string uniquely representing the connection.
    ///
    /// This can be used for logging purposes to differentiate between multiple
    /// connections.
    #[inline]
    #[must_use = "the returned identifier correlates connection log events"]
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Returns the negotiated ALPN protocol.
    ///
    /// If no protocol has been negotiated, the returned value is empty.
    #[inline]
    #[must_use = "the returned protocol identifies the negotiated ALPN"]
    pub fn application_proto(&self) -> &[u8] {
        self.alpn.as_ref()
    }

    /// Returns the server name requested by the client.
    #[inline]
    #[must_use = "the returned name identifies the TLS server if supplied"]
    pub fn server_name(&self) -> Option<&str> {
        self.handshake.server_name()
    }

    /// Returns the peer's leaf certificate (if any) as a DER-encoded buffer.
    #[inline]
    #[must_use = "the returned certificate can be used to inspect the peer identity"]
    pub fn peer_cert(&self) -> Option<&[u8]> {
        self.handshake.peer_cert()
    }

    /// Returns the peer's certificate chain (if any) as a vector of DER-encoded
    /// buffers.
    ///
    /// The certificate at index 0 is the peer's leaf certificate, the other
    /// certificates (if any) are the chain certificate authorities used to
    /// sign the leaf certificate.
    #[inline]
    #[must_use = "the returned chain can be used to inspect the peer certificates"]
    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        self.handshake.peer_cert_chain()
    }

    /// Returns the serialized cryptographic session for the connection.
    ///
    /// This can be used by a client to cache a connection's session, and resume
    /// it later using the [`set_session()`] method.
    ///
    /// [`set_session()`]: struct.Connection.html#method.set_session
    #[inline]
    #[must_use = "the returned session data is needed for session resumption"]
    pub fn session(&self) -> Option<&[u8]> {
        self.session.as_deref()
    }

    /// Returns the source connection ID.
    ///
    /// When there are multiple IDs, and if there is an active path, the ID used
    /// on that path is returned. Otherwise the oldest ID is returned.
    ///
    /// Note that the value returned can change throughout the connection's
    /// lifetime.
    #[inline]
    #[must_use = "the returned identifier identifies the local connection"]
    pub fn source_id(&self) -> &ConnectionId<'static> {
        let sequence = self
            .paths
            .get_active()
            .ok()
            .and_then(|path| path.active_scid_seq);
        self.ids
            .active_or_oldest(cid::CidDirection::Source, sequence)
    }

    /// Returns all active source connection IDs.
    ///
    /// An iterator is returned for all active IDs (i.e. ones that have not
    /// been explicitly retired yet).
    #[inline]
    pub fn source_ids(&self) -> impl Iterator<Item = &ConnectionId<'static>> {
        self.ids.scids_iter()
    }

    /// Returns the destination connection ID.
    ///
    /// Note that the value returned can change throughout the connection's
    /// lifetime.
    #[inline]
    #[must_use = "the returned identifier identifies the peer connection"]
    pub fn destination_id(&self) -> &ConnectionId<'static> {
        let sequence = self
            .paths
            .get_active()
            .ok()
            .and_then(|path| path.active_dcid_seq);
        self.ids
            .active_or_oldest(cid::CidDirection::Destination, sequence)
    }

    /// Returns the PMTU for the active path if it exists.
    ///
    /// This requires no additonal packets to be sent but simply checks if PMTUD
    /// has completed and has found a valid PMTU.
    #[inline]
    #[must_use = "the result describes the discovered path MTU"]
    pub fn pmtu(&self) -> Option<usize> {
        self.paths
            .get_active()
            .ok()
            .and_then(|path| path.pmtud.as_ref())
            .and_then(pmtud::Pmtud::get_pmtu)
    }

    /// Revalidates the PMTU for the active path by sending a new probe packet
    /// of PMTU size. If the probe is dropped PMTUD will restart and find a new
    /// valid PMTU.
    ///
    /// If revalidation invalidates a previously discovered larger size, a
    /// [`PathEvent::PmtuUpdated`] event is queued with QUIC's minimum packet
    /// size. Further events report larger sizes as probes validate them.
    #[inline]
    pub fn revalidate_pmtu(&mut self) {
        let Ok(active_path) = self.paths.get_active_mut() else {
            return;
        };

        let local = active_path.local_addr();
        let peer = active_path.peer_addr();
        let Some(pmtud) = active_path.pmtud.as_mut() else {
            return;
        };

        let old_pmtu = pmtud.get_current_mtu();
        pmtud.revalidate_pmtu();

        let current_mtu = pmtud.get_current_mtu();
        active_path
            .recovery
            .pmtud_update_max_datagram_size(current_mtu);

        let Some(event) = path::pmtu_event(local, peer, old_pmtu, current_mtu)
        else {
            return;
        };

        self.paths.notify_event(event);
    }

    /// Returns true if the connection handshake is complete.
    #[inline]
    #[must_use = "the result indicates whether handshake establishment is complete"]
    pub const fn is_established(&self) -> bool {
        self.handshake_completed
    }

    /// Returns true if the connection is resumed.
    #[inline]
    #[must_use = "the result indicates whether the TLS session was resumed"]
    pub fn is_resumed(&self) -> bool {
        self.handshake.is_resumed()
    }

    /// Returns true if the connection has a pending handshake that has
    /// progressed enough to send or receive early data.
    #[inline]
    #[must_use = "the result indicates whether early data can be used"]
    pub fn is_in_early_data(&self) -> bool {
        self.handshake.is_in_early_data()
    }

    /// Returns the early data reason for the connection.
    ///
    /// This status can be useful for logging and debugging. See [BoringSSL]
    /// documentation for a definition of the reasons.
    ///
    /// [BoringSSL]: https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#ssl_early_data_reason_t
    #[inline]
    #[must_use = "the result identifies the TLS early data outcome"]
    pub fn early_data_reason(&self) -> u32 {
        self.handshake.early_data_reason()
    }

    /// Returns whether the server rejected this client's 0-RTT data.
    ///
    /// Applications must recreate state bound to early streams and replay
    /// requests after the handshake completes.
    #[inline]
    #[must_use = "the result indicates whether early requests must be replayed"]
    pub const fn early_data_rejected(&self) -> bool {
        self.handshake.early_data_rejected()
    }

    /// Returns whether there is stream or DATAGRAM data available to read.
    #[inline]
    #[must_use = "the result indicates whether application data is available"]
    pub fn is_readable(&self) -> bool {
        self.streams.has_readable() || self.dgram_recv_front_len().is_some()
    }

    /// Returns whether the network path with local address `from` and remote
    /// address `peer` has been validated.
    ///
    /// If the 4-tuple does not exist over the connection, returns an
    /// [`InvalidState`].
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidState` if the network path does not exist.
    ///
    /// [`InvalidState`]: enum.Error.html#variant.InvalidState
    pub fn is_path_validated(
        &self, from: SocketAddr, to: SocketAddr,
    ) -> Result<bool> {
        let pid = self
            .paths
            .path_id_from_addrs(&(from, to))
            .ok_or(Error::InvalidState)?;

        Ok(self.paths.get(pid)?.validated())
    }

    /// Returns true if the connection is draining.
    ///
    /// If this returns `true`, the connection object cannot yet be dropped, but
    /// no new application data can be sent or received. An application should
    /// continue calling the [`recv()`], [`timeout()`], and [`on_timeout()`]
    /// methods as normal, until the [`is_closed()`] method returns `true`.
    ///
    /// In contrast, once `is_draining()` returns `true`, calling [`send()`]
    /// is not required because no new outgoing packets will be generated.
    ///
    /// [`recv()`]: struct.Connection.html#method.recv
    /// [`send()`]: struct.Connection.html#method.send
    /// [`timeout()`]: struct.Connection.html#method.timeout
    /// [`on_timeout()`]: struct.Connection.html#method.on_timeout
    /// [`is_closed()`]: struct.Connection.html#method.is_closed
    #[inline]
    #[must_use = "the result indicates whether the connection is draining"]
    pub const fn is_draining(&self) -> bool {
        matches!(self.lifecycle, ConnectionLifecycle::Draining { .. })
    }

    /// Returns true if the connection is closed.
    ///
    /// If this returns true, the connection object can be dropped.
    #[inline]
    #[must_use = "the result indicates whether the connection can be cleaned up"]
    pub const fn is_closed(&self) -> bool {
        matches!(self.lifecycle, ConnectionLifecycle::Closed(_))
    }

    /// Returns true if the connection was closed due to the idle timeout.
    #[inline]
    #[must_use = "the result indicates whether timeout closed the connection"]
    pub const fn is_timed_out(&self) -> bool {
        matches!(
            self.lifecycle,
            ConnectionLifecycle::Closed(CloseCause::IdleTimeout)
        )
    }

    /// Returns the error received from the peer, if any.
    ///
    /// Note that a `Some` return value does not necessarily imply
    /// [`is_closed()`] or any other connection state.
    ///
    /// [`is_closed()`]: struct.Connection.html#method.is_closed
    #[inline]
    #[must_use = "the returned error describes why the peer closed the connection"]
    pub const fn peer_error(&self) -> Option<&ConnectionError> {
        self.peer_error.as_ref()
    }

    /// Returns the error [`close()`] was called with, or internally
    /// created quiche errors, if any.
    ///
    /// Note that a `Some` return value does not necessarily imply
    /// [`is_closed()`] or any other connection state.
    /// `Some` also does not guarantee that the error has been sent to
    /// or received by the peer.
    ///
    /// [`close()`]: struct.Connection.html#method.close
    /// [`is_closed()`]: struct.Connection.html#method.is_closed
    #[inline]
    #[must_use = "the returned error describes why the local endpoint closed the connection"]
    pub const fn local_error(&self) -> Option<&ConnectionError> {
        self.local_error.as_ref()
    }

    /// Collects and returns statistics about the connection.
    #[inline]
    #[must_use = "the returned snapshot contains connection statistics"]
    pub fn stats(&self) -> Stats {
        Stats {
            recv: self.recv_count,
            sent: self.sent_count,
            lost: self.lost_count,
            spurious_lost: self.spurious_lost_count,
            retrans: self.retrans_count,
            sent_bytes: self.sent_bytes,
            recv_bytes: self.recv_bytes,
            acked_bytes: self.acked_bytes,
            lost_bytes: self.lost_bytes,
            stream_retrans_bytes: self.stream_retrans_bytes,
            dgram_recv: self.dgram_recv_count,
            dgram_sent: self.dgram_sent_count,
            paths_count: self.paths.len(),
            reset_stream_count_local: self.reset_stream_local_count,
            stopped_stream_count_local: self.stopped_stream_local_count,
            reset_stream_count_remote: self.reset_stream_remote_count,
            stopped_stream_count_remote: self.stopped_stream_remote_count,
            data_blocked_sent_count: self.data_blocked_sent_count,
            stream_data_blocked_sent_count: self.stream_data_blocked_sent_count,
            data_blocked_recv_count: self.data_blocked_recv_count,
            stream_data_blocked_recv_count: self.stream_data_blocked_recv_count,
            streams_blocked_bidi_recv_count: self.streams_blocked_bidi_recv_count,
            streams_blocked_uni_recv_count: self.streams_blocked_uni_recv_count,
            path_challenge_rx_count: self.path_challenge_rx_count,
            amplification_limited_count: self.amplification_limited_count,
            bytes_in_flight_duration: self.bytes_in_flight_duration(),
            tx_buffered_state: if self.streams.tx_buffered_is_consistent() {
                TxBufferTrackingState::Ok
            } else {
                TxBufferTrackingState::Inconsistent
            },
        }
    }

    /// Returns the sum of the durations when each path in the
    /// connection was actively sending bytes or waiting for acks.
    /// Note that this could result in a duration that is longer than
    /// the actual connection duration in cases where multiple paths
    /// are active for extended periods of time.  In practice only 1
    /// path is typically active at a time.
    /// TODO revisit computation if in the future multiple paths are
    /// often active at the same time.
    fn bytes_in_flight_duration(&self) -> Duration {
        self.paths.iter().fold(Duration::ZERO, |acc, (_, path)| {
            acc + path.bytes_in_flight_duration()
        })
    }

    /// Returns reference to peer's transport parameters. Returns `None` if we
    /// have not yet processed the peer's transport parameters.
    #[must_use = "the returned parameters describe negotiated peer limits"]
    pub const fn peer_transport_params(&self) -> Option<&TransportParams> {
        if !self.parsed_peer_transport_params {
            return None;
        }

        Some(&self.peer_transport_params)
    }

    /// Returns the peer's raw QUIC transport parameters in wire order.
    ///
    /// Unknown parameters and original encoding are preserved. Returns `None`
    /// until the peer's parameters have been validated. The data is borrowed
    /// from the TLS handshake and remains valid only while this connection
    /// lives.
    #[must_use = "the returned bytes contain the peer transport parameter encoding"]
    pub fn peer_transport_params_wire(&self) -> Option<&[u8]> {
        self.parsed_peer_transport_params
            .then(|| self.handshake.quic_transport_params())
    }

    /// Collects and returns statistics about each known path for the
    /// connection.
    pub fn path_stats(&self) -> impl Iterator<Item = PathStats> + '_ {
        self.paths.iter().map(|(_, p)| p.stats())
    }

    /// Returns whether or not this is a server-side connection.
    #[must_use = "the result identifies the local connection role"]
    pub const fn is_server(&self) -> bool {
        self.is_server
    }

    fn encode_transport_params(&mut self) -> Result<()> {
        self.handshake.set_quic_transport_params(
            &self.local_transport_params,
            self.is_server,
        )
    }

    fn parse_peer_transport_params(
        &mut self, peer_params: TransportParams,
    ) -> Result<()> {
        // Validate initial_source_connection_id.
        match &peer_params.initial_source_connection_id {
            Some(v) if v != self.destination_id() =>
                return Err(Error::InvalidTransportParam),

            Some(_) => (),

            // initial_source_connection_id must be sent by
            // both endpoints.
            None => return Err(Error::InvalidTransportParam),
        }

        // Validate original_destination_connection_id.
        if let Some(odcid) = &self.odcid {
            match &peer_params.original_destination_connection_id {
                Some(v) if v != odcid =>
                    return Err(Error::InvalidTransportParam),

                Some(_) => (),

                // original_destination_connection_id must be
                // sent by the server.
                None if !self.is_server =>
                    return Err(Error::InvalidTransportParam),

                None => (),
            }
        }

        // The server must advertise retry_source_connection_id if and only if
        // it sent a Retry packet. An unsolicited value is not merely redundant:
        // RFC 9000 section 7.3 requires TRANSPORT_PARAMETER_ERROR in this case.
        match (
            self.rscid.as_ref(),
            peer_params.retry_source_connection_id.as_ref(),
        ) {
            (None, None) => (),
            (Some(expected), Some(received)) if expected == received => (),
            _ => return Err(Error::InvalidTransportParam),
        }

        self.process_peer_transport_params(peer_params)?;

        self.parsed_peer_transport_params = true;

        Ok(())
    }

    fn process_peer_transport_params(
        &mut self, peer_params: TransportParams,
    ) -> Result<()> {
        self.max_tx_data = peer_params.initial_max_data;

        // Update send capacity.
        self.update_tx_cap();

        self.streams
            .update_peer_max_streams_bidi(peer_params.initial_max_streams_bidi);
        self.streams
            .update_peer_max_streams_uni(peer_params.initial_max_streams_uni);

        let max_ack_delay = Duration::from_millis(peer_params.max_ack_delay);

        self.recovery_config.max_ack_delay = max_ack_delay;

        let active_path = self.paths.get_active_mut()?;

        active_path.recovery.update_max_ack_delay(max_ack_delay);

        // The peer advertises a u64 wire limit, while recovery works with
        // locally addressable packet sizes. Oversized limits must not wrap.
        let peer_udp_limit = usize::try_from(peer_params.max_udp_payload_size)
            .unwrap_or(usize::MAX);
        if let Some(pmtud) = active_path.pmtud.as_ref() {
            active_path.recovery.pmtud_update_max_datagram_size(
                pmtud.get_current_mtu().min(peer_udp_limit),
            );
        } else {
            active_path
                .recovery
                .update_max_datagram_size(peer_udp_limit);
        }

        // Record the max_active_conn_id parameter advertised by the peer.
        self.ids
            .set_source_conn_id_limit(peer_params.active_conn_id_limit);

        self.peer_transport_params = peer_params;

        Ok(())
    }

    /// Continues the handshake.
    ///
    /// If the connection is already established, it does nothing.
    fn do_handshake(&mut self, now: Instant) -> Result<()> {
        let mut ex_data = tls::ExData {
            application_protos: &self.application_protos,

            crypto_ctx: &mut self.crypto_ctx,

            session: &mut self.session,

            local_error: &mut self.local_error,

            keylog: self.keylog.as_mut(),

            trace_id: &self.trace_id,

            local_transport_params: self.local_transport_params.clone(),

            recovery_config: self.recovery_config,

            tx_cap_factor: self.tx_cap_factor,

            pmtud: None,

            is_server: self.is_server,
        };

        if self.handshake_completed {
            return self.handshake.process_post_handshake(&mut ex_data);
        }

        let handshake_needs_retry =
            match self.handshake.do_handshake(&mut ex_data) {
                Ok(()) => false,
                Err(Error::Done) => true,
                Err(e) => return Err(e),
            };

        // BoringSSL reports success when entering early data before the
        // handshake completes. Apply callback configuration after either
        // non-fatal outcome so it is not lost on that path.
        if self
            .paths
            .get_active()
            .is_ok_and(path::Path::can_reinit_recovery)
        {
            if ex_data.recovery_config != self.recovery_config {
                if let Ok(path) = self.paths.get_active_mut() {
                    self.recovery_config = ex_data.recovery_config;
                    path.reinit_recovery(&self.recovery_config);
                }
            }

            // Preserve the exact callback-supplied IEEE-754 value while
            // avoiding redundant updates for unchanged NaNs. `f64 !=`
            // treats even a value compared with itself as different for NaN.
            if ex_data.tx_cap_factor.to_bits() != self.tx_cap_factor.to_bits() {
                self.tx_cap_factor = ex_data.tx_cap_factor;
            }

            if let Some((discover, max_probes)) = ex_data.pmtud {
                self.paths.set_discover_pmtu_on_existing_paths(
                    discover,
                    self.recovery_config.max_send_udp_payload_size,
                    max_probes,
                );
            }

            if ex_data.local_transport_params != self.local_transport_params {
                self.streams.set_max_streams_bidi(
                    ex_data.local_transport_params.initial_max_streams_bidi,
                );

                self.local_transport_params = ex_data.local_transport_params;
            }
        }

        if self.handshake.early_data_rejected() &&
            !self.early_data_rejection_handled
        {
            // Rejected 0-RTT shares the Application packet-number space with
            // 1-RTT, so discard recovery state without rewinding packet
            // numbers. No 1-RTT application packets can have been sent yet.
            let status = self.handshake_status();
            for (_, path) in self.paths.iter_mut() {
                path.recovery.on_pkt_num_space_discarded(
                    packet::Epoch::Application,
                    status,
                    now,
                );
            }

            // State created using remembered transport/application parameters
            // must not leak into the negotiated 1-RTT connection.
            self.streams.reset_for_early_data_rejection();
            self.tx_data = 0;
            self.last_tx_data = 0;
            self.blocked_limit = None;
            self.streams_blocked_bidi_state = StreamsBlockedState::default();
            self.streams_blocked_uni_state = StreamsBlockedState::default();
            self.dgram_send_queue.purge(|_| true);
            self.update_tx_cap();
            self.early_data_rejection_handled = true;
        }

        if handshake_needs_retry {
            // Try to parse transport parameters as soon as the first flight of
            // handshake data is processed.
            //
            // This is potentially dangerous as the handshake hasn't been
            // completed yet, though it's required to be able to send data in
            // 0.5 RTT.
            let raw_params = self.handshake.quic_transport_params();

            if !self.parsed_peer_transport_params && !raw_params.is_empty() {
                let peer_params = TransportParams::decode(
                    raw_params,
                    self.is_server,
                    self.peer_transport_params_track_unknown,
                )?;

                self.parse_peer_transport_params(peer_params)?;
            }

            return Ok(());
        }

        self.handshake_completed = self.handshake.is_completed();

        self.alpn = self.handshake.alpn_protocol().to_vec();

        let raw_params = self.handshake.quic_transport_params();

        if !self.parsed_peer_transport_params && !raw_params.is_empty() {
            let peer_params = TransportParams::decode(
                raw_params,
                self.is_server,
                self.peer_transport_params_track_unknown,
            )?;

            self.parse_peer_transport_params(peer_params)?;
        }

        if self.handshake_completed {
            // The handshake is considered confirmed at the server when the
            // handshake completes, at which point we can also drop the
            // handshake epoch.
            if self.is_server {
                self.handshake_confirmed = true;

                self.drop_epoch_state(packet::Epoch::Handshake, now);
            }

            // Once the handshake is completed there's no point in processing
            // 0-RTT packets anymore, so clear the buffer now.
            self.undecryptable_pkts.clear();

            trace!("{} connection established: proto={:?} cipher={:?} curve={:?} sigalg={:?} resumed={} {:?}",
                   self.trace_id,
                   std::str::from_utf8(self.application_proto()),
                   self.handshake.cipher(),
                   self.handshake.curve(),
                   self.handshake.sigalg(),
                   self.handshake.is_resumed(),
                   self.peer_transport_params);
        }

        Ok(())
    }

    /// Selects the packet type for the next outgoing packet.
    fn write_pkt_type(&self, send_pid: usize) -> Result<Type> {
        // On error send packet in the latest epoch available, but only send
        // 1-RTT ones when the handshake is completed.
        if self
            .local_error
            .as_ref()
            .is_some_and(|conn_err| !conn_err.is_app)
        {
            let epoch = match self.handshake.write_level() {
                crypto::Level::Initial => packet::Epoch::Initial,
                crypto::Level::ZeroRTT => unreachable!(),
                crypto::Level::Handshake => packet::Epoch::Handshake,
                crypto::Level::OneRTT => packet::Epoch::Application,
            };

            if !self.handshake_confirmed {
                match epoch {
                    // Downgrade the epoch to Handshake as the handshake is not
                    // completed yet.
                    packet::Epoch::Application => return Ok(Type::Handshake),

                    // Downgrade the epoch to Initial as the remote peer might
                    // not be able to decrypt handshake packets yet.
                    packet::Epoch::Handshake
                        if self.crypto_ctx[packet::Epoch::Initial].has_keys() =>
                        return Ok(Type::Initial),

                    _ => (),
                }
            }

            return Ok(Type::from_epoch(epoch));
        }

        // APPLICATION_CLOSE can only be sent in a 1-RTT packet. Prioritize it
        // over obsolete lower-epoch PTO probes, which cannot be consumed while
        // closing because PING frames are suppressed.
        if self.is_established() &&
            self.local_error
                .as_ref()
                .is_some_and(|conn_err| conn_err.is_app)
        {
            return Ok(Type::Short);
        }

        for &epoch in packet::Epoch::epochs(
            packet::Epoch::Initial..=packet::Epoch::Application,
        ) {
            let crypto_ctx = &self.crypto_ctx[epoch];
            let pkt_space = &self.pkt_num_spaces[epoch];

            // Only send packets in a space when we have the send keys for it.
            if crypto_ctx.crypto_seal.is_none() {
                continue;
            }

            // We are ready to send data for this packet number space.
            if crypto_ctx.data_available() || pkt_space.ready() {
                return Ok(Type::from_epoch(epoch));
            }

            // There are lost frames in this packet number space.
            for (_, p) in self.paths.iter() {
                if p.recovery.has_lost_frames(epoch) {
                    return Ok(Type::from_epoch(epoch));
                }

                // We need to send PTO probe packets.
                if p.recovery.loss_probes(epoch) > 0 {
                    return Ok(Type::from_epoch(epoch));
                }
            }
        }

        // If there are flushable, almost full or blocked streams, use the
        // Application epoch.
        let send_path = self.paths.get(send_pid)?;
        if (self.is_established() || self.is_in_early_data()) &&
            (self.should_send_handshake_done() ||
                self.flow_control.should_update_max_data() ||
                self.should_send_max_data ||
                self.blocked_limit.is_some() ||
                self.streams_blocked_bidi_state
                    .has_pending_stream_blocked_frame() ||
                self.streams_blocked_uni_state
                    .has_pending_stream_blocked_frame() ||
                self.dgram_send_queue.has_pending() ||
                self.local_error
                    .as_ref()
                    .is_some_and(|conn_err| conn_err.is_app) ||
                self.should_send_max_streams_bidi ||
                self.streams.should_update_max_streams_bidi() ||
                self.should_send_max_streams_uni ||
                self.streams.should_update_max_streams_uni() ||
                self.streams.has_flushable() ||
                self.streams.has_almost_full() ||
                self.streams.has_blocked() ||
                self.streams.has_reset() ||
                self.streams.has_stopped() ||
                self.ids.has_new_scids() ||
                self.ids.has_retire_dcids() ||
                send_path
                    .pmtud
                    .as_ref()
                    .is_some_and(pmtud::Pmtud::should_probe) ||
                send_path.needs_ack_eliciting ||
                send_path.probing_required())
        {
            // Only clients can send 0-RTT packets.
            if !self.is_server && self.is_in_early_data() {
                return Ok(Type::ZeroRTT);
            }

            return Ok(Type::Short);
        }

        Err(Error::Done)
    }

    /// Returns the mutable stream with the given ID if it exists, or creates
    /// a new one otherwise.
    fn get_or_create_stream(
        &mut self, id: u64, local: bool,
    ) -> Result<&mut stream::Stream<F>> {
        self.streams.get_or_create(
            id,
            &self.local_transport_params,
            &self.peer_transport_params,
            local,
            self.is_server,
        )
    }

    /// Validate the stream direction and opening state for an incoming frame.
    /// Collected streams can be referenced by late retransmissions; ignore
    /// those without recreating their state.
    fn get_or_create_stream_for_received_frame(
        &mut self, id: u64, side: PeerStreamSide,
    ) -> Result<Option<&mut stream::Stream<F>>> {
        let local = stream::is_local(id, self.is_server);
        if !stream::is_bidi(id) &&
            (local == matches!(side, PeerStreamSide::Sending))
        {
            return Err(Error::InvalidStreamState(id));
        }

        // Opening a higher-numbered stream also opens lower streams of the
        // same type, even if they do not have Stream objects yet.
        if local && !self.streams.local_stream_opened(id) {
            return Err(Error::InvalidStreamState(id));
        }

        match self.get_or_create_stream(id, local) {
            Ok(stream) => Ok(Some(stream)),
            Err(Error::Done) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Processes a DATAGRAM payload parsed directly from the decrypted
    /// packet buffer.
    fn process_direct_datagram<H>(
        &mut self, data: &[u8], recv_path_id: usize, handler: &mut H,
    ) -> Result<()>
    where
        H: FnMut(&[u8]) -> bool,
    {
        trace!("{} rx frm DATAGRAM len={}", self.trace_id, data.len());

        if !self.dgram_enabled() {
            return Err(Error::InvalidState);
        }

        // Preserve FIFO delivery with any DATAGRAMs already queued. Once a
        // payload falls back to the queue, newer payloads stay queued until the
        // application drains it instead of bypassing older data.
        let consumed = self.dgram_recv_queue.is_empty() && handler(data);

        if !consumed {
            self.enqueue_received_datagram(Vec::from(data))?;
        }

        self.record_received_datagram(recv_path_id)
    }

    /// Queue a datagram, evicting the oldest if the receive queue is full.
    fn enqueue_received_datagram(&mut self, data: Vec<u8>) -> Result<()> {
        if self.dgram_recv_queue.is_full() {
            self.dgram_recv_queue.pop();
        }

        self.dgram_recv_queue.push(data.into())
    }

    fn record_received_datagram(&mut self, recv_path_id: usize) -> Result<()> {
        self.dgram_recv_count = self.dgram_recv_count.saturating_add(1);
        let path = self.paths.get_mut(recv_path_id)?;
        path.dgram_recv_count = path.dgram_recv_count.saturating_add(1);
        Ok(())
    }

    /// Processes an incoming frame.
    fn process_frame(
        &mut self, frame: frame::Frame, hdr: &Header, recv_path_id: usize,
        epoch: packet::Epoch, now: Instant,
    ) -> Result<()> {
        trace!("{} rx frm {frame:?}", self.trace_id);

        match frame {
            frame::Frame::Padding { .. } | frame::Frame::Ping { .. } => (),

            frame::Frame::ACK {
                ranges, ack_delay, ..
            } => self.process_ack_frame(&ranges, ack_delay, epoch, now)?,

            frame::Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => self
                .process_reset_stream_frame(stream_id, error_code, final_size)?,

            frame::Frame::StopSending {
                stream_id,
                error_code,
            } => self.process_stop_sending_frame(stream_id, error_code, now)?,

            frame::Frame::Crypto { data } =>
                self.process_crypto_frame(data, epoch, now)?,

            // TODO: implement stateless retry
            frame::Frame::NewToken { .. } =>
                if self.is_server {
                    return Err(Error::InvalidPacket);
                },

            frame::Frame::Stream { stream_id, data } =>
                self.process_stream_frame(stream_id, data)?,

            frame::Frame::MaxData { max } => {
                self.max_tx_data = cmp::max(self.max_tx_data, max);
            },

            frame::Frame::MaxStreamData { stream_id, max } =>
                self.process_max_stream_data_frame(stream_id, max)?,

            frame::Frame::MaxStreamsBidi { max: count } |
            frame::Frame::MaxStreamsUni { max: count } |
            frame::Frame::StreamsBlockedBidi { limit: count } |
            frame::Frame::StreamsBlockedUni { limit: count }
                if count > MAX_STREAM_COUNT =>
            {
                return Err(Error::InvalidFrame);
            },

            frame::Frame::MaxStreamsBidi { max } => {
                self.streams.update_peer_max_streams_bidi(max);
            },

            frame::Frame::MaxStreamsUni { max } => {
                self.streams.update_peer_max_streams_uni(max);
            },

            frame::Frame::DataBlocked { .. } => {
                self.data_blocked_recv_count =
                    self.data_blocked_recv_count.saturating_add(1);
            },

            frame::Frame::StreamDataBlocked { stream_id, .. } => {
                // A blocked sender references its sending side and can open
                // a stream before the first byte of STREAM data arrives.
                if self
                    .get_or_create_stream_for_received_frame(
                        stream_id,
                        PeerStreamSide::Sending,
                    )?
                    .is_some()
                {
                    self.stream_data_blocked_recv_count =
                        self.stream_data_blocked_recv_count.saturating_add(1);
                }
            },

            frame::Frame::StreamsBlockedBidi { .. } => {
                self.streams_blocked_bidi_recv_count =
                    self.streams_blocked_bidi_recv_count.saturating_add(1);
            },

            frame::Frame::StreamsBlockedUni { .. } => {
                self.streams_blocked_uni_recv_count =
                    self.streams_blocked_uni_recv_count.saturating_add(1);
            },

            frame::Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => self.process_new_connection_id_frame(
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            )?,

            frame::Frame::RetireConnectionId { seq_num } =>
                self.process_retire_connection_id_frame(seq_num, &hdr.dcid)?,

            frame::Frame::PathChallenge { data } =>
                self.process_path_challenge(data, recv_path_id)?,

            frame::Frame::PathResponse { data } => {
                self.paths.on_response_received(data)?;
            },

            frame::Frame::ConnectionClose {
                error_code, reason, ..
            } => self.process_peer_close(
                ConnectionError {
                    is_app: false,
                    error_code,
                    reason,
                },
                now,
            )?,

            frame::Frame::ApplicationClose { error_code, reason } => self
                .process_peer_close(
                    ConnectionError {
                        is_app: true,
                        error_code,
                        reason,
                    },
                    now,
                )?,

            frame::Frame::HandshakeDone => self.process_handshake_done(now)?,

            frame::Frame::Datagram { data } =>
                self.process_datagram_frame(data, recv_path_id)?,

            // These metadata-only variants describe frames already encoded
            // by the sender; the wire parser never emits them.
            frame::Frame::CryptoHeader { .. } |
            frame::Frame::StreamHeader { .. } |
            frame::Frame::DatagramHeader { .. } => unreachable!(),
        }

        Ok(())
    }

    /// Validate connection-wide ACK ranges and update recovery on all paths.
    fn process_ack_frame(
        &mut self, ranges: &ranges::RangeSet, ack_delay: u64,
        epoch: packet::Epoch, now: Instant,
    ) -> Result<()> {
        let ack_delay = decode_ack_delay(
            ack_delay,
            self.peer_transport_params.ack_delay_exponent,
        )?;

        let skip_pn = self.pkt_num_manager.skip_pn();
        let largest_acked = recovery::validate_ack_ranges(ranges, skip_pn)?;
        // ACKs refer to the connection-global sent packet numbers in
        // this packet number space, not to one particular path.
        if self.pkt_num_spaces[epoch]
            .largest_tx_pkt_num
            .is_none_or(|largest_sent| largest_sent < largest_acked)
        {
            return Err(Error::InvalidAckRange);
        }

        if epoch == packet::Epoch::Handshake ||
            (epoch == packet::Epoch::Application && self.is_established())
        {
            self.peer_verified_initial_address = true;
        }

        let handshake_status = self.handshake_status();

        let is_app_limited = self.delivery_rate_check_if_app_limited();

        for (_, p) in self.paths.iter_mut() {
            if is_app_limited {
                p.recovery.delivery_rate_update_app_limited(true);
            }

            let OnAckReceivedOutcome {
                lost_packets,
                lost_bytes,
                acked_bytes,
                spurious_losses,
            } = p.recovery.on_ack_received(
                ranges,
                ack_delay,
                epoch,
                handshake_status,
                now,
                skip_pn,
                &self.trace_id,
            )?;

            self.lost_count += lost_packets;
            self.lost_bytes += lost_bytes as u64;
            self.acked_bytes += acked_bytes as u64;
            self.spurious_lost_count += spurious_losses;
        }

        let space = &mut self.pkt_num_spaces[epoch];
        space.largest_acked_pkt_num =
            space.largest_acked_pkt_num.max(Some(largest_acked));

        // Retire the skipped packet number after the entire ACK was
        // validated and processed across all paths.
        if skip_pn.is_some_and(|pn| largest_acked > pn) {
            self.pkt_num_manager.set_skip_pn(None);
        }

        Ok(())
    }

    /// Apply the peer's receive-side reset, flow control and stream lifecycle.
    fn process_reset_stream_frame(
        &mut self, stream_id: u64, error_code: u64, final_size: u64,
    ) -> Result<()> {
        let max_rx_data_left = self.max_rx_data() - self.rx_data;

        let Some(stream) = self.get_or_create_stream_for_received_frame(
            stream_id,
            PeerStreamSide::Sending,
        )?
        else {
            return Ok(());
        };

        let was_readable = stream.is_readable();
        let priority_key = Arc::clone(stream.priority_key());

        let stream::RecvBufResetReturn {
            max_data_delta,
            consumed_flowcontrol,
        } = stream
            .recv
            .reset(error_code, final_size, max_rx_data_left)?;

        // The receive side can complete without the stream becoming
        // readable, so no later read would collect it.
        let collectable = stream.is_collectable();

        if !was_readable && stream.is_readable() {
            self.streams
                .enqueue(&priority_key, stream::PriorityQueue::Readable);
        }

        self.rx_data += max_data_delta;
        // We dropped the receive buffer, return connection level
        // flow-control
        self.flow_control.add_consumed(consumed_flowcontrol);

        self.reset_stream_remote_count =
            self.reset_stream_remote_count.saturating_add(1);

        if collectable {
            self.streams.collect(stream_id);
        }

        Ok(())
    }

    /// Stop local transmission, refund unsent credit and schedule a reset.
    fn process_stop_sending_frame(
        &mut self, stream_id: u64, error_code: u64, now: Instant,
    ) -> Result<()> {
        #[cfg(not(feature = "qlog"))]
        let _ = now;

        let Some(stream) = self.get_or_create_stream_for_received_frame(
            stream_id,
            PeerStreamSide::Receiving,
        )?
        else {
            return Ok(());
        };

        let priority_key = Arc::clone(stream.priority_key());

        // Save the buffered length before stopping (stop clears the
        // buffer).
        let buffered_len = stream.send.buffered_bytes();

        // Try stopping the stream.
        if let Ok((final_size, unsent)) = stream.send.stop(error_code) {
            // Claw back some flow control allowance from data that was
            // buffered but not actually sent before the stream was
            // reset.
            //
            // Note that `tx_cap` will be updated later on, so no need
            // to touch it here.
            self.tx_data = self.tx_data.saturating_sub(unsent);

            // Update tx_buffered: subtract only the buffered data, not
            // inflight data.
            self.streams.sub_tx_buffered(buffered_len);

            // Match moves from App to Transport with moves from
            // Transport to Dropped.
            // A Network transition would distinguish sent bytes from
            // drops before transmission.
            qlog_with_type!(QLOG_DATA_MV, self.qlog, q, {
                let ev_data = EventData::QuicStreamDataMoved(
                    qlog::events::quic::StreamDataMoved {
                        stream_id: Some(stream_id),
                        offset: Some(final_size),
                        raw: Some(RawInfo {
                            length: Some(unsent),
                            ..Default::default()
                        }),
                        from: Some(DataRecipient::Transport),
                        to: Some(DataRecipient::Dropped),
                        ..Default::default()
                    },
                );

                q.add_event_data_with_instant(ev_data, now).ok();
            });

            self.streams.insert_reset(stream_id, error_code, final_size);

            self.streams
                .enqueue(&priority_key, stream::PriorityQueue::StoppedWritable);

            self.stopped_stream_remote_count =
                self.stopped_stream_remote_count.saturating_add(1);
            self.reset_stream_local_count =
                self.reset_stream_local_count.saturating_add(1);
        }

        Ok(())
    }

    /// Reassemble CRYPTO data and advance the TLS handshake.
    fn process_crypto_frame(
        &mut self, data: range_buf::RangeBuf, epoch: packet::Epoch, now: Instant,
    ) -> Result<()> {
        if data.max_off() >= MAX_CRYPTO_STREAM_OFFSET {
            return Err(Error::CryptoBufferExceeded);
        }

        // Push the data to the stream so it can be re-ordered.
        self.crypto_ctx[epoch].crypto_stream.recv.write(data)?;

        // Feed crypto data to the TLS state, if there's data
        // available at the expected offset.
        let mut crypto_buf = [0; 512];

        let level = crypto::Level::from_epoch(epoch);

        let stream = &mut self.crypto_ctx[epoch].crypto_stream;

        while let Ok((read, _)) = stream.recv.emit(&mut crypto_buf) {
            let recv_buf = &crypto_buf[..read];
            self.handshake.provide_data(level, recv_buf)?;
        }

        self.do_handshake(now)?;

        Ok(())
    }

    /// Apply incoming stream data and update connection receive credit.
    fn process_stream_frame(
        &mut self, stream_id: u64, data: range_buf::RangeBuf,
    ) -> Result<()> {
        let max_rx_data_left = self.max_rx_data() - self.rx_data;

        let Some(stream) = self.get_or_create_stream_for_received_frame(
            stream_id,
            PeerStreamSide::Sending,
        )?
        else {
            return Ok(());
        };

        // Check for the connection-level flow control limit.
        let max_off_delta = data.max_off().saturating_sub(stream.recv.max_off());

        if max_off_delta > max_rx_data_left {
            return Err(Error::FlowControl);
        }

        let was_readable = stream.is_readable();
        let priority_key = Arc::clone(stream.priority_key());

        let was_draining = stream.recv.is_draining();

        stream.recv.write(data)?;

        // The receive side can complete without the stream becoming
        // readable, so no later read would collect it.
        let collectable = stream.is_collectable();

        if !was_readable && stream.is_readable() {
            self.streams
                .enqueue(&priority_key, stream::PriorityQueue::Readable);
        }

        self.rx_data += max_off_delta;

        if was_draining {
            // When a stream is in draining state it will not queue
            // incoming data for the application to read, so consider
            // the received data as consumed, which might trigger a flow
            // control update.
            self.flow_control.add_consumed(max_off_delta);
        }

        if collectable {
            self.streams.collect(stream_id);
        }

        Ok(())
    }

    /// Update a stream's sending credit and scheduler eligibility.
    fn process_max_stream_data_frame(
        &mut self, stream_id: u64, max: u64,
    ) -> Result<()> {
        let Some(stream) = self.get_or_create_stream_for_received_frame(
            stream_id,
            PeerStreamSide::Receiving,
        )?
        else {
            return Ok(());
        };

        let was_flushable = stream.is_flushable();

        stream.send.update_max_data(max);

        let writable = stream.is_writable();

        let priority_key = Arc::clone(stream.priority_key());

        // If the stream became flushable, add it to the queue unless it
        // is already present.
        if stream.is_flushable() && !was_flushable {
            self.streams
                .enqueue(&priority_key, stream::PriorityQueue::Flushable);
        }

        if writable {
            self.streams
                .enqueue(&priority_key, stream::PriorityQueue::Writable);
        }

        Ok(())
    }

    /// Install a destination CID and reassign paths whose CID was retired.
    fn process_new_connection_id_frame(
        &mut self, seq_num: u64, retire_prior_to: u64,
        conn_id: ConnectionId<'static>, reset_token: [u8; 16],
    ) -> Result<()> {
        if self.ids.zero_length_dcid() {
            return Err(Error::InvalidState);
        }

        let mut retired_path_ids = SmallVec::new();

        // Retire pending path IDs before propagating the error code to
        // make sure retired connection IDs are not in use anymore.
        let new_dcid_res = self.ids.new_dcid(
            conn_id,
            seq_num,
            u128::from_be_bytes(reset_token),
            retire_prior_to,
            &mut retired_path_ids,
        );

        for (dcid_seq, pid) in retired_path_ids {
            let path = self.paths.get_mut(pid)?;

            // Maybe the path already switched to another DCID.
            if path.active_dcid_seq != Some(dcid_seq) {
                continue;
            }

            if let Some(new_dcid_seq) = self.ids.lowest_available_dcid_seq() {
                path.active_dcid_seq = Some(new_dcid_seq);

                self.ids.link_dcid_to_path_id(new_dcid_seq, pid)?;

                trace!(
                    "{} path ID {pid} changed DCID: old seq num {dcid_seq} new seq num {new_dcid_seq}",
                    self.trace_id,
                );
            } else {
                // We cannot use this path anymore for now.
                path.active_dcid_seq = None;

                trace!(
                    "{} path ID {pid} cannot be used; DCID seq num {dcid_seq} has been retired",
                    self.trace_id,
                );
            }
        }

        // Propagate error (if any) now.
        new_dcid_res
    }

    /// Retire a source CID and unlink it from its path when still active.
    fn process_retire_connection_id_frame(
        &mut self, seq_num: u64, packet_dcid: &ConnectionId,
    ) -> Result<()> {
        if self.ids.zero_length_scid() {
            return Err(Error::InvalidState);
        }

        if let Some(pid) = self.ids.retire_scid(seq_num, packet_dcid)? {
            let path = self.paths.get_mut(pid)?;

            // Maybe we already linked a new SCID to that path.
            if path.active_scid_seq == Some(seq_num) {
                // XXX: We do not remove unused paths now, we instead
                // wait until we need to maintain more paths than the
                // host is willing to.
                path.active_scid_seq = None;
            }
        }

        Ok(())
    }

    /// Record the challenge on the path that received it.
    fn process_path_challenge(
        &mut self, data: [u8; 8], recv_path_id: usize,
    ) -> Result<()> {
        self.path_challenge_rx_count += 1;
        self.paths
            .get_mut(recv_path_id)?
            .on_challenge_received(data);
        Ok(())
    }

    /// Confirm the client handshake and retire its handshake keys.
    fn process_handshake_done(&mut self, now: Instant) -> Result<()> {
        if self.is_server {
            return Err(Error::InvalidPacket);
        }

        self.peer_verified_initial_address = true;
        self.handshake_confirmed = true;
        self.drop_epoch_state(packet::Epoch::Handshake, now);
        Ok(())
    }

    /// Record peer closure and enter draining for three probe timeouts.
    fn process_peer_close(
        &mut self, error: ConnectionError, now: Instant,
    ) -> Result<()> {
        self.peer_error = Some(error);
        let path = self.paths.get_active()?;
        self.lifecycle = ConnectionLifecycle::Draining {
            deadline: now + (path.recovery.pto() * 3),
            origin: CloseOrigin::Peer,
        };
        Ok(())
    }

    /// Enqueue a received datagram and account for its path.
    fn process_datagram_frame(
        &mut self, data: Vec<u8>, recv_path_id: usize,
    ) -> Result<()> {
        // Close the connection if DATAGRAMs are not enabled.
        // quiche always advertises support for 64K sized DATAGRAM
        // frames, as recommended by the standard, so we don't need a
        // size check.
        if !self.dgram_enabled() {
            return Err(Error::InvalidState);
        }

        self.enqueue_received_datagram(data)?;
        self.record_received_datagram(recv_path_id)
    }

    /// Drops the keys and recovery state for the given epoch.
    fn drop_epoch_state(&mut self, epoch: packet::Epoch, now: Instant) {
        let crypto_ctx = &mut self.crypto_ctx[epoch];
        if crypto_ctx.crypto_open.is_none() {
            return;
        }
        crypto_ctx.clear();
        self.pkt_num_spaces[epoch].clear();

        let handshake_status = self.handshake_status();
        for (_, p) in self.paths.iter_mut() {
            p.recovery
                .on_pkt_num_space_discarded(epoch, handshake_status, now);
        }

        trace!("{} dropped epoch {epoch} state", self.trace_id);
    }

    /// Returns the connection level flow control limit.
    const fn max_rx_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    /// Returns true if the `HANDSHAKE_DONE` frame needs to be sent.
    const fn should_send_handshake_done(&self) -> bool {
        self.is_established() &&
            matches!(self.handshake_done, HandshakeDoneState::Pending) &&
            self.is_server
    }

    /// Returns the idle timeout value.
    ///
    /// `None` is returned if both end-points disabled the idle timeout.
    fn idle_timeout(&self) -> Option<Duration> {
        // If the transport parameter is set to 0, then the respective endpoint
        // decided to disable the idle timeout. If both are disabled we should
        // not set any timeout.
        if self.local_transport_params.max_idle_timeout == 0 &&
            self.peer_transport_params.max_idle_timeout == 0
        {
            return None;
        }

        // If the local endpoint or the peer disabled the idle timeout, use the
        // other peer's value, otherwise use the minimum of the two values.
        let idle_timeout = if self.local_transport_params.max_idle_timeout == 0 {
            self.peer_transport_params.max_idle_timeout
        } else if self.peer_transport_params.max_idle_timeout == 0 {
            self.local_transport_params.max_idle_timeout
        } else {
            cmp::min(
                self.local_transport_params.max_idle_timeout,
                self.peer_transport_params.max_idle_timeout,
            )
        };

        let path_pto = self
            .paths
            .get_active()
            .map_or(Duration::ZERO, |path| path.recovery.pto());

        let idle_timeout = Duration::from_millis(idle_timeout);
        let idle_timeout = cmp::max(idle_timeout, path_pto.saturating_mul(3));

        Some(idle_timeout)
    }

    /// Returns the connection's handshake status for use in loss recovery.
    fn handshake_status(&self) -> recovery::HandshakeStatus {
        recovery::HandshakeStatus {
            has_handshake_keys: self.crypto_ctx[packet::Epoch::Handshake]
                .has_keys(),

            peer_verified_address: self.peer_verified_initial_address,

            completed: self.is_established(),
        }
    }

    /// Updates send capacity.
    fn update_tx_cap(&mut self) {
        let cwin_available = self
            .paths
            .get_active()
            .map_or(0, |p| p.recovery.cwnd_available());
        let flow_credit = self.max_tx_data.saturating_sub(self.tx_data);
        let flow_credit = usize::try_from(flow_credit).unwrap_or(usize::MAX);
        let cap = cwin_available.min(flow_credit);
        // The capacity factor can relax congestion buffering, but never the
        // hard flow-control limit imposed by the peer.
        self.tx_cap =
            scale::scale_usize(cap, self.tx_cap_factor, scale::Rounding::Up)
                .min(flow_credit);
    }

    fn delivery_rate_check_if_app_limited(&self) -> bool {
        // Enter the app-limited phase of delivery rate when these conditions
        // are met:
        //
        // - The remaining capacity exceeds the available bytes in CWND (there
        //   is more room to send).
        // - New data since the last `send()` is smaller than available bytes in
        //   CWND (we queued less than what we can send).
        // - CWND has room for more data.
        //
        // In application-limited phases the transmission rate is limited by the
        // application rather than the congestion control algorithm.
        //
        // This mirrors `CheckIfApplicationLimited()` from the delivery-rate
        // draft but affects only delivery-rate calculation, not
        // `recovery.app_limited`.
        let cwin_available = self
            .paths
            .iter()
            .filter(|&(_, p)| p.active())
            .map(|(_, p)| p.recovery.cwnd_available() as u64)
            .fold(0, u64::saturating_add);

        (self
            .streams
            .tx_buffered()
            .saturating_add(self.dgram_send_queue_byte_size() as u64) <
            cwin_available) &&
            self.tx_data.saturating_sub(self.last_tx_data) < cwin_available &&
            cwin_available > 0
    }

    fn set_initial_dcid(
        &mut self, cid: ConnectionId<'static>, reset_token: Option<u128>,
        path_id: usize,
    ) -> Result<()> {
        self.ids.set_initial_dcid(cid, reset_token, Some(path_id));
        self.paths.get_mut(path_id)?.active_dcid_seq = Some(0);

        Ok(())
    }

    /// Selects the path that the incoming packet belongs to, or creates a new
    /// one if no existing path matches.
    fn get_or_create_recv_path_id(
        &mut self, recv_pid: Option<usize>, dcid: &ConnectionId, buf_len: usize,
        info: &RecvInfo,
    ) -> Result<usize> {
        let ids = &mut self.ids;

        if let Some(recv_pid) = recv_pid {
            // The overwhelmingly common case is that this path keeps using the
            // same SCID. Use the path's cached sequence number first so the
            // common lookup only compares integer sequence numbers rather than
            // searching local SCIDs by CID bytes on every short-header packet.
            // The SCID store is still a VecDeque, so get_scid() itself is a
            // short linear scan. Only return early when the CID entry is still
            // linked to this path; reused CIDs must fall through so the
            // original relink semantics are preserved.
            let recv_path = self.paths.get_mut(recv_pid)?;

            let cid_entry =
                recv_path.active_scid_seq.and_then(|v| ids.get_scid(v).ok());

            if cid_entry
                .is_some_and(|e| &e.cid == dcid && e.path_id == Some(recv_pid))
            {
                return Ok(recv_pid);
            }

            // The CID changed on an existing 4-tuple. Resolve the incoming CID
            // only on this uncommon path, then update the path association.
            let (in_scid_seq, _) =
                ids.find_scid_seq(dcid).ok_or(Error::InvalidState)?;
            let incoming_cid_entry = ids.get_scid(in_scid_seq)?;

            let prev_recv_pid = incoming_cid_entry.path_id.unwrap_or(recv_pid);

            if prev_recv_pid != recv_pid {
                trace!(
                    "{} peer reused CID {dcid:?} from path {prev_recv_pid} on path {recv_pid}",
                    self.trace_id
                );

                // TODO: reset congestion control.
            }

            trace!(
                "{} path ID {recv_pid} now see SCID with seq num {in_scid_seq}",
                self.trace_id
            );

            recv_path.active_scid_seq = Some(in_scid_seq);
            ids.link_scid_to_path_id(in_scid_seq, recv_pid)?;

            return Ok(recv_pid);
        }

        let (in_scid_seq, mut in_scid_pid) =
            ids.find_scid_seq(dcid).ok_or(Error::InvalidState)?;

        // This is a new 4-tuple. See if the CID has not been assigned on
        // another path.

        // Ignore this step if are using zero-length SCID.
        if ids.zero_length_scid() {
            in_scid_pid = None;
        }

        // Capture old path info before insert_path() so we can emit the
        // ReusedSourceConnectionId event after successful insertion. This
        // ensures the event count is bounded by path Slab capacity.
        let reused_cid_info = match in_scid_pid {
            Some(pid) => {
                let old_path = self.paths.get(pid)?;
                Some((pid, old_path.local_addr(), old_path.peer_addr()))
            },

            None => None,
        };

        // This is a new path using an unassigned CID; create it!
        let mut path = path::Path::new(
            info.to,
            info.from,
            &self.recovery_config,
            self.path_challenge_recv_max_queue_len,
            false,
            None,
        );

        path.grant_amplification_credit(buf_len, self.max_amplification_factor);
        path.active_scid_seq = Some(in_scid_seq);

        // Automatically probes the new path.
        path.request_validation();

        let (pid, released_dcid_seq) =
            self.paths.insert_path(path, self.is_server)?;

        // Notify the application of CID reuse only after the path was
        // successfully admitted. This bounds event queue growth by path Slab
        // capacity, preventing an attacker from growing the queue unboundedly
        // by rotating source ports.
        if let Some((old_pid, old_local_addr, old_peer_addr)) = reused_cid_info {
            trace!(
                "{} reused CID seq {in_scid_seq} of ({old_local_addr},{old_peer_addr}) (path {old_pid}) on ({},{})",
                self.trace_id,
                info.to,
                info.from
            );

            self.paths.notify_event(PathEvent::ReusedSourceConnectionId(
                in_scid_seq,
                (old_local_addr, old_peer_addr),
                (info.to, info.from),
            ));
        }

        // Preserve the existing CID owner while that original path still
        // exists. A later packet on the new, now-known 4-tuple will relink it
        // through the normal slow path. If insertion evicted the original
        // owner, relink immediately so the CID never points at a removed path.
        let original_owner_survived = reused_cid_info.as_ref().is_some_and(
            |(old_pid, old_local_addr, old_peer_addr)| {
                self.paths
                    .path_id_from_addrs(&(*old_local_addr, *old_peer_addr)) ==
                    Some(*old_pid)
            },
        );
        if reused_cid_info.is_none() || !original_owner_survived {
            ids.link_scid_to_path_id(in_scid_seq, pid)?;
        }

        if let Some(seq) = released_dcid_seq {
            self.release_dcid(seq)?;
        }

        Ok(pid)
    }

    /// Selects the path on which the next packet must be sent.
    fn get_send_path_id(
        &self, from: Option<SocketAddr>, to: Option<SocketAddr>,
    ) -> Result<usize> {
        // A probing packet must be sent, but only if the connection is fully
        // established.
        if self.is_established() {
            let mut probing = self
                .paths
                .iter()
                .filter(|(_, p)| from.is_none() || Some(p.local_addr()) == from)
                .filter(|(_, p)| to.is_none() || Some(p.peer_addr()) == to)
                .filter(|(_, p)| p.active_dcid_seq.is_some())
                .filter(|(_, p)| p.probing_required())
                .map(|(pid, _)| pid);

            if let Some(pid) = probing.next() {
                return Ok(pid);
            }
        }

        if let Some((pid, p)) = self.paths.get_active_with_pid() {
            if from.is_some() && Some(p.local_addr()) != from {
                return Err(Error::Done);
            }

            if to.is_some() && Some(p.peer_addr()) != to {
                return Err(Error::Done);
            }

            return Ok(pid);
        }

        Err(Error::InvalidState)
    }

    /// Sets the path with identifier '`path_id`' to be active.
    fn set_active_path(&mut self, path_id: usize, now: Instant) -> Result<()> {
        // A failed activation must not run loss detection or mutate the old
        // path's recovery state. Re-selecting the current path is a no-op.
        if self.paths.activation_target_is_current(path_id)? {
            return Ok(());
        }

        if let Ok(old_active_path) = self.paths.get_active_mut() {
            for &e in packet::Epoch::epochs(
                packet::Epoch::Initial..=packet::Epoch::Application,
            ) {
                let (lost_packets, lost_bytes) = old_active_path
                    .recovery
                    .on_path_change(e, now, &self.trace_id);

                self.lost_count += lost_packets;
                self.lost_bytes += lost_bytes as u64;
            }
        }

        self.paths.set_active_path(path_id)
    }

    /// Handles potential connection migration.
    fn on_peer_migrated(
        &mut self, new_pid: usize, disable_dcid_reuse: bool, now: Instant,
    ) -> Result<()> {
        let active_path_id = self.paths.get_active_path_id()?;

        if active_path_id == new_pid {
            return Ok(());
        }

        self.set_active_path(new_pid, now)?;

        let no_spare_dcid =
            self.paths.get_mut(new_pid)?.active_dcid_seq.is_none();

        if no_spare_dcid && !disable_dcid_reuse {
            self.paths.get_mut(new_pid)?.active_dcid_seq =
                self.paths.get_mut(active_path_id)?.active_dcid_seq;
        }

        Ok(())
    }

    /// Creates a new client-side path.
    fn create_path_on_client(
        &mut self, local_addr: SocketAddr, peer_addr: SocketAddr,
    ) -> Result<usize> {
        if self.is_server {
            return Err(Error::InvalidState);
        }

        // If we use zero-length SCID and go over our local active CID limit,
        // the `insert_path()` call will raise an error.
        if !self.ids.zero_length_scid() && self.ids.available_scids() == 0 {
            return Err(Error::OutOfIdentifiers);
        }

        // Do we have a spare DCID? If we are using zero-length DCID, just use
        // the default having sequence 0 (note that if we exceed our local CID
        // limit, the `insert_path()` call will raise an error.
        let dcid_seq = if self.ids.zero_length_dcid() {
            0
        } else {
            self.ids
                .lowest_available_dcid_seq()
                .ok_or(Error::OutOfIdentifiers)?
        };

        let mut path = path::Path::new(
            local_addr,
            peer_addr,
            &self.recovery_config,
            self.path_challenge_recv_max_queue_len,
            false,
            None,
        );
        path.active_dcid_seq = Some(dcid_seq);

        let (pid, released_dcid_seq) = self
            .paths
            .insert_path(path, false)
            .map_err(|_| Error::OutOfIdentifiers)?;

        if let Some(seq) = released_dcid_seq {
            self.release_dcid(seq)?;
        }

        self.ids.link_dcid_to_path_id(dcid_seq, pid)?;

        Ok(pid)
    }

    /// Releases the Destination Connection ID a removed path was using.
    ///
    /// The ID goes back to the pool of spare IDs a new path can take, unless
    /// DCID reuse is disabled, in which case it is retired.
    fn release_dcid(&mut self, dcid_seq: u64) -> Result<()> {
        if self.disable_dcid_reuse && !self.ids.zero_length_dcid() {
            self.ids.retire_dcid(dcid_seq)?;
        } else {
            self.ids.unlink_dcid(dcid_seq);
        }

        Ok(())
    }

    // Marks the connection as closed once, retaining the cause before
    // generating any terminal telemetry.
    fn mark_closed(&mut self, cause: CloseCause) {
        if self.is_closed() {
            return;
        }
        self.lifecycle = ConnectionLifecycle::Closed(cause);
        #[cfg(feature = "qlog")]
        {
            let event = self.close_event(cause);
            qlog_with_type!(QLOG_CONNECTION_CLOSED, self.qlog, q, {
                q.add_event_data_now(EventData::QuicConnectionClosed(event))
                    .ok();
            });
            self.qlog.streamer = None;
        }
    }

    #[cfg(feature = "qlog")]
    fn close_event(
        &self, cause: CloseCause,
    ) -> qlog::events::quic::ConnectionClosed {
        use qlog::events::quic::ConnectionClosed;
        use qlog::events::quic::ConnectionClosedTrigger as Trigger;

        let (initiator, error, trigger, reason) = match cause {
            CloseCause::Explicit(CloseOrigin::Local) => (
                TransportInitiator::Local,
                self.local_error.as_ref(),
                Trigger::Application,
                None,
            ),
            CloseCause::Explicit(CloseOrigin::Peer) => (
                TransportInitiator::Remote,
                self.peer_error.as_ref(),
                Trigger::Error,
                None,
            ),
            CloseCause::IdleTimeout if self.is_established() => (
                TransportInitiator::Local,
                None,
                Trigger::IdleTimeout,
                Some("Idle timeout"),
            ),
            CloseCause::IdleTimeout => (
                TransportInitiator::Local,
                None,
                Trigger::HandshakeTimeout,
                Some("Handshake timeout"),
            ),
            CloseCause::StatelessReset => (
                TransportInitiator::Remote,
                None,
                Trigger::StatelessReset,
                Some("Stateless reset"),
            ),
            CloseCause::PacketNumbersExhausted => (
                TransportInitiator::Local,
                None,
                Trigger::Error,
                Some("Packet numbers exhausted"),
            ),
            CloseCause::NoViablePath => (
                TransportInitiator::Local,
                None,
                Trigger::Error,
                Some("No viable path"),
            ),
        };
        let mut event = ConnectionClosed {
            initiator: Some(initiator),
            connection_error: None,
            application_error: None,
            error_code: None,
            internal_code: None,
            reason: reason.map(str::to_owned),
            trigger: Some(trigger),
        };
        if let Some(error) = error {
            event.error_code = Some(error.error_code);
            event.reason =
                Some(String::from_utf8_lossy(&error.reason).into_owned());
            if error.is_app {
                event.application_error =
                    Some(qlog::events::ApplicationError::Unknown);
                event.trigger = Some(Trigger::Application);
            } else {
                event.connection_error = Some(
                    qlog::events::ConnectionClosedEventError::TransportError(
                        qlog::events::quic::TransportError::Unknown,
                    ),
                );
                event.trigger =
                    Some(if error.error_code == WireErrorCode::NoError as u64 {
                        Trigger::Clean
                    } else {
                        Trigger::Error
                    });
            }
        }
        event
    }
}

#[cfg(feature = "boringssl-btls-crate")]
impl<F: BufFactory> AsMut<btls::ssl::SslRef> for Connection<F> {
    fn as_mut(&mut self) -> &mut btls::ssl::SslRef {
        self.handshake.ssl_mut()
    }
}

// Transport parameter validation limits the exponent to 20. Scale before
// narrowing the elapsed duration, and clamp to the largest wire integer.
#[cfg(any(not(feature = "fuzzing"), test))]
fn encode_ack_delay(delay: Duration, exponent: u64) -> u64 {
    let scaled = delay.as_micros() >> exponent;
    u64::try_from(scaled)
        .unwrap_or(u64::MAX)
        .min(octets::MAX_VAR_INT)
}

fn decode_ack_delay(encoded: u64, exponent: u64) -> Result<u64> {
    let exponent = u32::try_from(exponent).map_err(|_| Error::InvalidFrame)?;
    1_u64
        .checked_shl(exponent)
        .and_then(|factor| encoded.checked_mul(factor))
        .ok_or(Error::InvalidFrame)
}

/// Returns the reserved bits of a packet's first byte, after header
/// protection has been removed.
///
/// Per RFC 9000 section 17.2 (long header) and section 17.3.1 (short
/// header), these bits MUST be zero; a non-zero result means the caller
/// should treat receipt of the packet as a connection error, but only
/// after packet protection has also been removed (see the reserved-bits
/// check in `recv_single`).
fn reserved_bits(first_byte: u8, ty: Type) -> u8 {
    if ty == Type::Short {
        first_byte & 0x18
    } else {
        first_byte & 0x0c
    }
}

struct AddrTupleFmt(SocketAddr, SocketAddr);

impl std::fmt::Display for AddrTupleFmt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let Self(src, dst) = &self;

        if src.ip().is_unspecified() || dst.ip().is_unspecified() {
            return Ok(());
        }

        f.write_fmt(format_args!("src:{src} dst:{dst}"))
    }
}

/// Statistics about the connection.
///
/// A connection's statistics can be collected using the [`stats()`] method.
///
/// [`stats()`]: struct.Connection.html#method.stats
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Stats {
    /// The number of QUIC packets received.
    pub recv: usize,

    /// The number of QUIC packets sent.
    pub sent: usize,

    /// The number of QUIC packets that were lost.
    pub lost: usize,

    /// The number of QUIC packets that were marked as lost but later acked.
    pub spurious_lost: usize,

    /// The number of sent QUIC packets carrying retransmitted STREAM or
    /// CRYPTO data, or a retransmitted FIN.
    pub retrans: usize,

    /// The number of sent bytes.
    pub sent_bytes: u64,

    /// The number of received bytes.
    pub recv_bytes: u64,

    /// The number of bytes sent acked.
    pub acked_bytes: u64,

    /// The number of bytes sent lost.
    pub lost_bytes: u64,

    /// The number of STREAM and CRYPTO payload bytes actually retransmitted.
    pub stream_retrans_bytes: u64,

    /// The number of DATAGRAM frames received.
    pub dgram_recv: usize,

    /// The number of DATAGRAM frames sent.
    pub dgram_sent: usize,

    /// The number of known paths for the connection.
    pub paths_count: usize,

    /// The number of streams reset by local.
    pub reset_stream_count_local: u64,

    /// The number of streams stopped by local.
    pub stopped_stream_count_local: u64,

    /// The number of streams reset by remote.
    pub reset_stream_count_remote: u64,

    /// The number of streams stopped by remote.
    pub stopped_stream_count_remote: u64,

    /// The number of `DATA_BLOCKED` frames sent due to hitting the connection
    /// flow control limit.
    pub data_blocked_sent_count: u64,

    /// The number of `STREAM_DATA_BLOCKED` frames sent due to a stream hitting
    /// the stream flow control limit.
    pub stream_data_blocked_sent_count: u64,

    /// The number of `DATA_BLOCKED` frames received from the remote.
    pub data_blocked_recv_count: u64,

    /// The number of `STREAM_DATA_BLOCKED` frames received from the remote.
    pub stream_data_blocked_recv_count: u64,

    /// The number of `STREAMS_BLOCKED` frames for bidirectional streams
    /// received from the remote, indicating the peer is blocked on opening new
    /// bidirectional streams.
    pub streams_blocked_bidi_recv_count: u64,

    /// The number of `STREAMS_BLOCKED` frames for unidirectional streams
    /// received from the remote, indicating the peer is blocked on opening new
    /// unidirectional streams.
    pub streams_blocked_uni_recv_count: u64,

    /// The total number of `PATH_CHALLENGE` frames that were received.
    pub path_challenge_rx_count: u64,

    /// The number of times `send()` was blocked because the anti-amplification
    /// budget (bytes received × `max_amplification_factor`) was exhausted.
    pub amplification_limited_count: u64,

    /// Total duration during which this side of the connection was
    /// actively sending bytes or waiting for those bytes to be acked.
    pub bytes_in_flight_duration: Duration,

    /// Health state of the connection's `tx_buffered`.
    ///
    /// Indicates whether the `streams.tx_buffered` value is consistent with
    /// the actual sum of bytes buffered across all stream send buffers.
    /// Returns `Ok` if consistent, `Inconsistent` if there's a mismatch.
    pub tx_buffered_state: TxBufferTrackingState,
}

impl std::fmt::Debug for Stats {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "recv={} sent={} lost={} retrans={}",
            self.recv, self.sent, self.lost, self.retrans,
        )?;

        write!(
            f,
            " sent_bytes={} recv_bytes={} lost_bytes={}",
            self.sent_bytes, self.recv_bytes, self.lost_bytes,
        )?;

        Ok(())
    }
}

#[doc(hidden)]
#[cfg(any(test, feature = "internal"))]
pub mod test_utils;

#[cfg(test)]
mod tests;

pub use crate::packet::ConnectionId;
pub use crate::packet::Header;
pub use crate::packet::Type;

pub use crate::path::PathEvent;
pub use crate::path::PathStats;
pub use crate::path::SocketAddrIter;

pub use crate::recovery::BbrBwLoReductionStrategy;
pub use crate::recovery::BbrParams;
#[cfg(feature = "internal")]
pub use crate::recovery::BbrRttJumpDetector;
pub use crate::recovery::CongestionControlAlgorithm;
pub use crate::recovery::StartupExit;
pub use crate::recovery::StartupExitReason;

pub use crate::stream::StreamIter;

pub use crate::transport_params::TransportParams;
pub use crate::transport_params::UnknownTransportParameter;
pub use crate::transport_params::UnknownTransportParameters;
pub use crate::transport_params::MAX_ACK_DELAY_EXPONENT;

pub use crate::buffers::BufFactory;
pub use crate::buffers::BufSplit;

pub use crate::error::ConnectionError;
pub use crate::error::Error;
pub use crate::error::Result;
pub use crate::error::WireErrorCode;

mod buffers;
mod cid;
mod crypto;
mod dgram;
mod error;
#[cfg(feature = "ffi")]
pub(crate) mod ffi;
mod flowcontrol;
mod frame;
pub mod h3;
mod minmax;
mod packet;
mod path;
mod pmtud;
mod rand;
mod range_buf;
mod ranges;
mod recovery;
pub(crate) mod scale;
mod stream;
mod tls;
pub(crate) mod transport_params;
