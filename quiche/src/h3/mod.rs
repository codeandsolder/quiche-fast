// Copyright (C) 2019, Cloudflare, Inc.
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

//! HTTP/3 wire protocol and QPACK implementation.
//!
//! This module provides a high level API for sending and receiving HTTP/3
//! requests and responses on top of the QUIC transport protocol.
//!
//! ## Connection setup
//!
//! HTTP/3 connections require a QUIC transport-layer connection, see
//! [Connection setup] for a full description of the setup process.
//!
//! To use HTTP/3, the QUIC connection must be configured with a suitable
//! Application Layer Protocol Negotiation (ALPN) Protocol ID:
//!
//! ```
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The QUIC handshake is driven by [sending] and [receiving] QUIC packets.
//!
//! Once the handshake has completed, the first step in establishing an HTTP/3
//! connection is creating its configuration object:
//!
//! ```
//! let h3_config = quiche::h3::Config::new();
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! HTTP/3 client and server connections are both created using the
//! [`with_transport()`] function, the role is inferred from the type of QUIC
//! connection:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new();
//! let h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! ## Sending a request
//!
//! An HTTP/3 client can send a request by using the connection's
//! [`send_request()`] method to queue request headers; [sending] QUIC packets
//! causes the requests to get sent to the peer:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::connect(None, &scid, local, peer, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new();
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! let req = vec![
//!     quiche::h3::Header::new(b":method", b"GET"),
//!     quiche::h3::Header::new(b":scheme", b"https"),
//!     quiche::h3::Header::new(b":authority", b"quic.tech"),
//!     quiche::h3::Header::new(b":path", b"/"),
//!     quiche::h3::Header::new(b"user-agent", b"quiche"),
//! ];
//!
//! h3_conn.send_request(&mut conn, &req, true)?;
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! An HTTP/3 client can send a request with additional body data by using
//! the connection's [`send_body()`] method:
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:4321".parse().unwrap();
//! # let mut conn = quiche::connect(None, &scid, local, peer, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new();
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! let req = vec![
//!     quiche::h3::Header::new(b":method", b"GET"),
//!     quiche::h3::Header::new(b":scheme", b"https"),
//!     quiche::h3::Header::new(b":authority", b"quic.tech"),
//!     quiche::h3::Header::new(b":path", b"/"),
//!     quiche::h3::Header::new(b"user-agent", b"quiche"),
//! ];
//!
//! let stream_id = h3_conn.send_request(&mut conn, &req, false)?;
//! h3_conn.send_body(&mut conn, stream_id, b"Hello World!", true)?;
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! ## Handling requests and responses
//!
//! After [receiving] QUIC packets, HTTP/3 data is processed using the
//! connection's [`poll()`] method. On success, this returns an [`Event`] object
//! and an ID corresponding to the stream where the `Event` originated.
//!
//! An HTTP/3 server uses [`poll()`] to read requests and responds to them using
//! [`send_response()`] and [`send_body()`]:
//!
//! ```no_run
//! use quiche::h3::NameValue;
//!
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:1234".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, local, peer, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new();
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! loop {
//!     match h3_conn.poll(&mut conn) {
//!         Ok((stream_id, quiche::h3::Event::Headers{list, more_frames})) => {
//!             let mut headers = list.into_iter();
//!
//!             // Look for the request's method.
//!             let method = headers.find(|h| h.name() == b":method").unwrap();
//!
//!             // Look for the request's path.
//!             let path = headers.find(|h| h.name() == b":path").unwrap();
//!
//!             if method.value() == b"GET" && path.value() == b"/" {
//!                 let resp = vec![
//!                     quiche::h3::Header::new(b":status", 200.to_string().as_bytes()),
//!                     quiche::h3::Header::new(b"server", b"quiche"),
//!                 ];
//!
//!                 h3_conn.send_response(&mut conn, stream_id, &resp, false)?;
//!                 h3_conn.send_body(&mut conn, stream_id, b"Hello World!", true)?;
//!             }
//!         },
//!
//!         Ok((stream_id, quiche::h3::Event::Data)) => {
//!             // Request body data, handle it.
//!             # return Ok(());
//!         },
//!
//!         Ok((stream_id, quiche::h3::Event::Finished)) => {
//!             // Peer terminated stream, handle it.
//!         },
//!
//!         Ok((stream_id, quiche::h3::Event::Reset(err))) => {
//!             // Peer reset the stream, handle it.
//!         },
//!
//!         Ok((_flow_id, quiche::h3::Event::PriorityUpdate)) => (),
//!
//!         Ok((goaway_id, quiche::h3::Event::GoAway)) => {
//!              // Peer signalled it is going away, handle it.
//!         },
//!
//!         Err(quiche::h3::Error::Done) => {
//!             // Done reading.
//!             break;
//!         },
//!
//!         Err(e) => {
//!             // An error occurred, handle it.
//!             break;
//!         },
//!     }
//! }
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! An HTTP/3 client uses [`poll()`] to read responses:
//!
//! ```no_run
//! use quiche::h3::NameValue;
//!
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let peer = "127.0.0.1:1234".parse().unwrap();
//! # let local = "127.0.0.1:1234".parse().unwrap();
//! # let mut conn = quiche::connect(None, &scid, local, peer, &mut config).unwrap();
//! # let h3_config = quiche::h3::Config::new();
//! # let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
//! loop {
//!     match h3_conn.poll(&mut conn) {
//!         Ok((stream_id, quiche::h3::Event::Headers{list, more_frames})) => {
//!             let status = list.iter().find(|h| h.name() == b":status").unwrap();
//!             println!("Received {} response on stream {}",
//!                      std::str::from_utf8(status.value()).unwrap(),
//!                      stream_id);
//!         },
//!
//!         Ok((stream_id, quiche::h3::Event::Data)) => {
//!             let mut body = vec![0; 4096];
//!
//!             // Consume all body data received on the stream.
//!             while let Ok(read) =
//!                 h3_conn.recv_body(&mut conn, stream_id, &mut body)
//!             {
//!                 println!("Received {} bytes of payload on stream {}",
//!                          read, stream_id);
//!             }
//!         },
//!
//!         Ok((stream_id, quiche::h3::Event::Finished)) => {
//!             // Peer terminated stream, handle it.
//!         },
//!
//!         Ok((stream_id, quiche::h3::Event::Reset(err))) => {
//!             // Peer reset the stream, handle it.
//!         },
//!
//!         Ok((_prioritized_element_id, quiche::h3::Event::PriorityUpdate)) => (),
//!
//!         Ok((goaway_id, quiche::h3::Event::GoAway)) => {
//!              // Peer signalled it is going away, handle it.
//!         },
//!
//!         Err(quiche::h3::Error::Done) => {
//!             // Done reading.
//!             break;
//!         },
//!
//!         Err(e) => {
//!             // An error occurred, handle it.
//!             break;
//!         },
//!     }
//! }
//! # Ok::<(), quiche::h3::Error>(())
//! ```
//!
//! ## Detecting end of request or response
//!
//! A single HTTP/3 request or response may consist of several HEADERS and DATA
//! frames; it is finished when the QUIC stream is closed. Calling [`poll()`]
//! repeatedly will generate an [`Event`] for each of these. The application may
//! use these event to do additional HTTP semantic validation.
//!
//! ## HTTP/3 protocol errors
//!
//! Quiche is responsible for managing the HTTP/3 connection, ensuring it is in
//! a correct state and validating all messages received by a peer. This mainly
//! takes place in the [`poll()`] method. If an HTTP/3 error occurs, quiche will
//! close the connection and send an appropriate `CONNECTION_CLOSE` frame to the
//! peer. An [`Error`] is returned to the application so that it can perform any
//! required tidy up such as closing sockets.
//!
//! [`application_proto()`]: ../struct.Connection.html#method.application_proto
//! [`stream_finished()`]: ../struct.Connection.html#method.stream_finished
//! [Connection setup]: ../index.html#connection-setup
//! [sending]: ../index.html#generating-outgoing-packets
//! [receiving]: ../index.html#handling-incoming-packets
//! [`with_transport()`]: struct.Connection.html#method.with_transport
//! [`poll()`]: struct.Connection.html#method.poll
//! [`Event`]: enum.Event.html
//! [`Error`]: enum.Error.html
//! [`send_request()`]: struct.Connection.html#method.send_response
//! [`send_response()`]: struct.Connection.html#method.send_response
//! [`send_body()`]: struct.Connection.html#method.send_body

use std::collections::hash_map;
use std::collections::HashSet;
use std::collections::VecDeque;

#[cfg(feature = "sfv")]
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Write;

#[cfg(feature = "qlog")]
use qlog::events::http3::FrameCreated;
#[cfg(feature = "qlog")]
use qlog::events::http3::FrameParsed;
#[cfg(feature = "qlog")]
use qlog::events::http3::Http3EventType;
#[cfg(feature = "qlog")]
use qlog::events::http3::Http3Frame;
#[cfg(feature = "qlog")]
use qlog::events::http3::Initiator;
#[cfg(feature = "qlog")]
use qlog::events::http3::StreamType;
#[cfg(feature = "qlog")]
use qlog::events::http3::StreamTypeSet;
#[cfg(feature = "qlog")]
use qlog::events::EventData;
#[cfg(feature = "qlog")]
use qlog::events::EventImportance;
#[cfg(feature = "qlog")]
use qlog::events::EventType;

use crate::buffers::BufFactory;
use crate::BufSplit;

/// List of ALPN tokens of supported HTTP/3 versions.
///
/// This can be passed directly to the [`Config::set_application_protos()`]
/// method when implementing HTTP/3 applications.
///
/// [`Config::set_application_protos()`]:
/// ../struct.Config.html#method.set_application_protos
pub const APPLICATION_PROTOCOL: &[&[u8]] = &[b"h3"];

// The offset used when converting HTTP/3 urgency to quiche urgency.
const PRIORITY_URGENCY_OFFSET: u8 = 124;

// Parameter values as specified in [Extensible Priorities].
//
// [Extensible Priorities]: https://www.rfc-editor.org/rfc/rfc9218.html#section-4.
const PRIORITY_URGENCY_LOWER_BOUND: u8 = 0;
const PRIORITY_URGENCY_UPPER_BOUND: u8 = 7;
const PRIORITY_URGENCY_DEFAULT: u8 = 3;
const PRIORITY_INCREMENTAL_DEFAULT: bool = false;

/// The default value for the maximum size of `PRIORITY_UPDATE`
/// frame payload.
///
/// See <https://datatracker.ietf.org/doc/html/rfc9218#section-7.2>
pub const PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT: u64 = 256;

/// The default value for `SETTINGS_MAX_FIELD_SECTION_SIZE`
///
/// See <https://datatracker.ietf.org/doc/html/rfc9114#section-4.2.2>.
pub const SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT: u64 = 32_768;

#[cfg(feature = "qlog")]
const QLOG_FRAME_CREATED: EventType =
    EventType::Http3EventType(Http3EventType::FrameCreated);
#[cfg(feature = "qlog")]
const QLOG_FRAME_PARSED: EventType =
    EventType::Http3EventType(Http3EventType::FrameParsed);
#[cfg(feature = "qlog")]
const QLOG_STREAM_TYPE_SET: EventType =
    EventType::Http3EventType(Http3EventType::StreamTypeSet);

/// A specialized [`Result`] type for quiche HTTP/3 operations.
///
/// This type is used throughout quiche's HTTP/3 public API for any operation
/// that can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// An HTTP/3 error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// There is no error or no work to do
    Done,

    /// The provided buffer is too short.
    BufferTooShort,

    /// Internal error in the HTTP/3 stack.
    InternalError,

    /// Endpoint detected that the peer is exhibiting behavior that causes.
    /// excessive load.
    ExcessiveLoad,

    /// Stream ID or Push ID greater that current maximum was
    /// used incorrectly, such as exceeding a limit, reducing a limit,
    /// or being reused.
    IdError,

    /// The endpoint detected that its peer created a stream that it will not
    /// accept.
    StreamCreationError,

    /// A required critical stream was closed.
    ClosedCriticalStream,

    /// No SETTINGS frame at beginning of control stream.
    MissingSettings,

    /// A frame was received which is not permitted in the current state.
    FrameUnexpected,

    /// Frame violated layout or size rules.
    FrameError,

    /// QPACK Header block decompression failure.
    QpackDecompressionFailed,

    /// Error originated from the transport layer.
    TransportError(crate::Error),

    /// The underlying QUIC stream (or connection) doesn't have enough capacity
    /// for the operation to complete. The application should retry later on.
    StreamBlocked,

    /// Error in the payload of a SETTINGS frame.
    SettingsError,

    /// Server rejected request.
    RequestRejected,

    /// Request or its response cancelled.
    RequestCancelled,

    /// Client's request stream terminated without containing a full-formed
    /// request.
    RequestIncomplete,

    /// An HTTP message was malformed and cannot be processed.
    MessageError,

    /// The TCP connection established in response to a CONNECT request was
    /// reset or abnormally closed.
    ConnectError,

    /// The requested operation cannot be served over HTTP/3. Peer should retry
    /// over HTTP/1.1.
    VersionFallback,
}

/// HTTP/3 error codes sent on the wire.
///
/// As defined in [RFC9114](https://www.rfc-editor.org/rfc/rfc9114.html#http-error-codes).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WireErrorCode {
    /// No error. This is used when the connection or stream needs to be closed,
    /// but there is no error to signal.
    NoError              = 0x100,
    /// Peer violated protocol requirements in a way that does not match a more
    /// specific error code or endpoint declines to use the more specific
    /// error code.
    GeneralProtocolError = 0x101,
    /// An internal error has occurred in the HTTP stack.
    InternalError        = 0x102,
    /// The endpoint detected that its peer created a stream that it will not
    /// accept.
    StreamCreationError  = 0x103,
    /// A stream required by the HTTP/3 connection was closed or reset.
    ClosedCriticalStream = 0x104,
    /// A frame was received that was not permitted in the current state or on
    /// the current stream.
    FrameUnexpected      = 0x105,
    /// A frame that fails to satisfy layout requirements or with an invalid
    /// size was received.
    FrameError           = 0x106,
    /// The endpoint detected that its peer is exhibiting a behavior that might
    /// be generating excessive load.
    ExcessiveLoad        = 0x107,
    /// A stream ID or push ID was used incorrectly, such as exceeding a limit,
    /// reducing a limit, or being reused.
    IdError              = 0x108,
    /// An endpoint detected an error in the payload of a SETTINGS frame.
    SettingsError        = 0x109,
    /// No SETTINGS frame was received at the beginning of the control stream.
    MissingSettings      = 0x10a,
    /// A server rejected a request without performing any application
    /// processing.
    RequestRejected      = 0x10b,
    /// The request or its response (including pushed response) is cancelled.
    RequestCancelled     = 0x10c,
    /// The client's stream terminated without containing a fully formed
    /// request.
    RequestIncomplete    = 0x10d,
    /// An HTTP message was malformed and cannot be processed.
    MessageError         = 0x10e,
    /// The TCP connection established in response to a CONNECT request was
    /// reset or abnormally closed.
    ConnectError         = 0x10f,
    /// The requested operation cannot be served over HTTP/3. The peer should
    /// retry over HTTP/1.1.
    VersionFallback      = 0x110,
}

impl Error {
    const fn to_wire(self) -> u64 {
        match self {
            Self::Done => WireErrorCode::NoError as u64,
            Self::InternalError => WireErrorCode::InternalError as u64,
            Self::StreamCreationError =>
                WireErrorCode::StreamCreationError as u64,
            Self::ClosedCriticalStream =>
                WireErrorCode::ClosedCriticalStream as u64,
            Self::FrameUnexpected => WireErrorCode::FrameUnexpected as u64,
            Self::FrameError => WireErrorCode::FrameError as u64,
            Self::ExcessiveLoad => WireErrorCode::ExcessiveLoad as u64,
            Self::IdError => WireErrorCode::IdError as u64,
            Self::MissingSettings => WireErrorCode::MissingSettings as u64,
            Self::QpackDecompressionFailed => 0x200,
            Self::BufferTooShort => 0x999,
            Self::TransportError { .. } | Self::StreamBlocked => 0xFF,
            Self::SettingsError => WireErrorCode::SettingsError as u64,
            Self::RequestRejected => WireErrorCode::RequestRejected as u64,
            Self::RequestCancelled => WireErrorCode::RequestCancelled as u64,
            Self::RequestIncomplete => WireErrorCode::RequestIncomplete as u64,
            Self::MessageError => WireErrorCode::MessageError as u64,
            Self::ConnectError => WireErrorCode::ConnectError as u64,
            Self::VersionFallback => WireErrorCode::VersionFallback as u64,
        }
    }

    #[cfg(feature = "ffi")]
    const fn to_c(self) -> i16 {
        match self {
            Self::Done => -1,
            Self::BufferTooShort => -2,
            Self::InternalError => -3,
            Self::ExcessiveLoad => -4,
            Self::IdError => -5,
            Self::StreamCreationError => -6,
            Self::ClosedCriticalStream => -7,
            Self::MissingSettings => -8,
            Self::FrameUnexpected => -9,
            Self::FrameError => -10,
            Self::QpackDecompressionFailed => -11,
            // -12 was previously used for TransportError, skip it
            Self::StreamBlocked => -13,
            Self::SettingsError => -14,
            Self::RequestRejected => -15,
            Self::RequestCancelled => -16,
            Self::RequestIncomplete => -17,
            Self::MessageError => -18,
            Self::ConnectError => -19,
            Self::VersionFallback => -20,

            Self::TransportError(quic_error) => quic_error.to_c() - 1000,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TransportError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<super::Error> for Error {
    fn from(err: super::Error) -> Self {
        match err {
            super::Error::Done => Self::Done,

            _ => Self::TransportError(err),
        }
    }
}

impl From<octets::BufferTooShortError> for Error {
    fn from(_err: octets::BufferTooShortError) -> Self {
        Self::BufferTooShort
    }
}

/// An HTTP/3 configuration.
pub struct Config {
    max_field_section_size: Option<u64>,
    qpack_max_table_capacity: Option<u64>,
    qpack_blocked_streams: Option<u64>,
    connect_protocol_enabled: Option<u64>,
    /// additional settings are settings that are not part of the H3
    /// settings explicitly handled above
    additional_settings: Option<Vec<(u64, u64)>>,

    max_priority_update_size: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    /// Creates a new configuration object with default settings.
    #[must_use = "the returned configuration contains the HTTP/3 defaults"]
    pub const fn new() -> Self {
        Self {
            max_field_section_size: Some(SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT),
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            additional_settings: None,
            max_priority_update_size:
                PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT,
        }
    }

    /// Sets the `SETTINGS_MAX_FIELD_SECTION_SIZE` setting.
    ///
    /// The default is [`SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT`]. The value is
    /// measured in units of bytes, it is used as a limit when parsing frames
    /// that contain encoded HTTP headers when [`poll()`] is called. A first
    /// check is applied when handling HEADERS and `PUSH_PROMISE` frames
    /// themselves, with some margin allowed on top of the provided size. A
    /// second check is applied when decoding QPACK, implementing the rules
    /// described in <https://datatracker.ietf.org/doc/html/rfc9114#section-4.2.2>.
    ///
    /// When headers exceed the limit set by the application, the call to the
    /// [`poll()`] method will return the [`Error::ExcessiveLoad`] error, and
    /// the connection will be closed.
    ///
    /// [`poll()`]: struct.Connection.html#method.poll
    /// [`Error::ExcessiveLoad`]: enum.Error.html#variant.ExcessiveLoad
    pub const fn set_max_field_section_size(&mut self, v: u64) {
        self.max_field_section_size = Some(v);
    }

    /// Sets the `SETTINGS_QPACK_MAX_TABLE_CAPACITY` setting.
    ///
    /// The default value is `0`.
    pub const fn set_qpack_max_table_capacity(&mut self, v: u64) {
        self.qpack_max_table_capacity = Some(v);
    }

    /// Sets the `SETTINGS_QPACK_BLOCKED_STREAMS` setting.
    ///
    /// The default value is `0`.
    pub const fn set_qpack_blocked_streams(&mut self, v: u64) {
        self.qpack_blocked_streams = Some(v);
    }

    /// Sets or omits the `SETTINGS_ENABLE_CONNECT_PROTOCOL` setting.
    ///
    /// The default value is `false`.
    pub const fn enable_extended_connect(&mut self, enabled: bool) {
        if enabled {
            self.connect_protocol_enabled = Some(1);
        } else {
            self.connect_protocol_enabled = None;
        }
    }

    /// Sets additional HTTP/3 settings.
    ///
    /// The default value is no additional settings.
    /// The `additional_settings` parameter must not contain the following
    /// settings as they are already handled by this library:
    ///
    /// - `SETTINGS_QPACK_MAX_TABLE_CAPACITY`
    /// - `SETTINGS_MAX_FIELD_SECTION_SIZE`
    /// - `SETTINGS_QPACK_BLOCKED_STREAMS`
    /// - `SETTINGS_ENABLE_CONNECT_PROTOCOL`
    /// - `SETTINGS_H3_DATAGRAM`
    /// - `SETTINGS_H3_DATAGRAM_00`
    ///
    /// If such a setting is present in the `additional_settings`,
    /// the method will return the [`Error::SettingsError`] error.
    ///
    /// If a setting identifier is present twice in `additional_settings`,
    /// the method will return the [`Error::SettingsError`] error.
    ///
    /// # Errors
    ///
    /// Returns `Error::SettingsError` if an identifier is duplicated,
    /// reserved by HTTP/2, or managed by this library (including either
    /// DATAGRAM setting), or if an identifier or value exceeds the QUIC
    /// variable-length integer range.
    ///
    /// [`Error::SettingsError`]: enum.Error.html#variant.SettingsError
    pub fn set_additional_settings(
        &mut self, additional_settings: Vec<(u64, u64)>,
    ) -> Result<()> {
        let mut identifiers = HashSet::new();
        if additional_settings.iter().any(|&(id, value)| {
            id > octets::MAX_VAR_INT ||
                value > octets::MAX_VAR_INT ||
                matches!(
                    id,
                    0x0 | 0x2..=
                        0x5 | frame::SETTINGS_MAX_FIELD_SECTION_SIZE |
                            frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY |
                            frame::SETTINGS_QPACK_BLOCKED_STREAMS |
                            frame::SETTINGS_ENABLE_CONNECT_PROTOCOL |
                            frame::SETTINGS_H3_DATAGRAM |
                            frame::SETTINGS_H3_DATAGRAM_00
                ) ||
                !identifiers.insert(id)
        }) {
            return Err(Error::SettingsError);
        }
        self.additional_settings = Some(additional_settings);
        Ok(())
    }

    /// Sets the maximum size for the payload of `PRIORITY_UPDATE` frames.
    ///
    /// The default is [`PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE_DEFAULT`]. The
    /// value uses units of bytes.
    ///
    /// When a `PRIORITY_UPDATE` frame exceeds the limit set by the application,
    /// the call to the [`poll()`] method will return the
    /// [`Error::ExcessiveLoad`] error, and the connection will be closed.
    ///
    /// [`poll()`]: struct.Connection.html#method.poll
    /// [`Error::ExcessiveLoad`]: enum.Error.html#variant.ExcessiveLoad
    pub const fn set_max_priority_update_size(&mut self, v: u64) {
        self.max_priority_update_size = v;
    }
}

/// A trait for types with associated string name and value.
pub trait NameValue {
    /// Returns the object's name.
    fn name(&self) -> &[u8];

    /// Returns the object's value.
    fn value(&self) -> &[u8];
}

impl<N, V> NameValue for (N, V)
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    fn name(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn value(&self) -> &[u8] {
        self.1.as_ref()
    }
}

/// An owned name-value pair representing a raw HTTP header.
#[derive(Clone, PartialEq, Eq)]
pub struct Header(Vec<u8>, Vec<u8>);

fn try_print_as_readable(hdr: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    match std::str::from_utf8(hdr) {
        Ok(s) => f.write_str(&s.escape_default().to_string()),
        Err(_) => write!(f, "{hdr:?}"),
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('"')?;
        try_print_as_readable(&self.0, f)?;
        f.write_str(": ")?;
        try_print_as_readable(&self.1, f)?;
        f.write_char('"')
    }
}

impl Header {
    /// Creates a new header.
    ///
    /// Both `name` and `value` will be cloned.
    #[must_use = "the returned header owns the copied name and value"]
    pub fn new(name: &[u8], value: &[u8]) -> Self {
        Self(name.to_vec(), value.to_vec())
    }
}

impl NameValue for Header {
    fn name(&self) -> &[u8] {
        &self.0
    }

    fn value(&self) -> &[u8] {
        &self.1
    }
}

/// A non-owned name-value pair representing a raw HTTP header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRef<'a>(&'a [u8], &'a [u8]);

impl<'a> HeaderRef<'a> {
    /// Creates a new header.
    #[must_use = "the returned header borrows the supplied name and value"]
    pub const fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self(name, value)
    }
}

impl NameValue for HeaderRef<'_> {
    fn name(&self) -> &[u8] {
        self.0
    }

    fn value(&self) -> &[u8] {
        self.1
    }
}

/// An HTTP/3 connection event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Request/response headers were received.
    Headers {
        /// The list of received header fields. The application should validate
        /// pseudo-headers and headers.
        list: Vec<Header>,

        /// Whether more frames will follow the headers on the stream.
        more_frames: bool,
    },

    /// Data was received.
    ///
    /// This indicates that the application can use the [`recv_body()`] method
    /// to retrieve the data from the stream.
    ///
    /// Note that [`recv_body()`] will need to be called repeatedly until the
    /// [`Done`] value is returned, as the event will not be re-armed until all
    /// buffered data is read.
    ///
    /// [`recv_body()`]: struct.Connection.html#method.recv_body
    /// [`Done`]: enum.Error.html#variant.Done
    Data,

    /// Stream was closed,
    Finished,

    /// Stream was reset.
    ///
    /// The associated data represents the error code sent by the peer.
    Reset(u64),

    /// `PRIORITY_UPDATE` was received.
    ///
    /// This indicates that the application can use the
    /// [`take_last_priority_update()`] method to take the last received
    /// `PRIORITY_UPDATE` for a specified stream.
    ///
    /// This event is triggered once per stream until the last `PRIORITY_UPDATE`
    /// is taken. It is recommended that applications defer taking the
    /// `PRIORITY_UPDATE` until after [`poll()`] returns [`Done`].
    ///
    /// [`take_last_priority_update()`]: struct.Connection.html#method.take_last_priority_update
    /// [`poll()`]: struct.Connection.html#method.poll
    /// [`Done`]: enum.Error.html#variant.Done
    PriorityUpdate,

    /// GOAWAY was received.
    GoAway,
}

/// Extensible Priorities parameters.
///
/// The `TryFrom` trait supports constructing this object from the serialized
/// Structured Fields Dictionary field value. I.e, use `TryFrom` to parse the
/// value of a Priority header field or a `PRIORITY_UPDATE` frame. Using this
/// trait requires the `sfv` feature to be enabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Priority {
    urgency: u8,
    incremental: bool,
}

impl Default for Priority {
    fn default() -> Self {
        Self {
            urgency: PRIORITY_URGENCY_DEFAULT,
            incremental: PRIORITY_INCREMENTAL_DEFAULT,
        }
    }
}

impl Priority {
    /// Creates a new Priority.
    #[must_use = "the returned priority contains the supplied urgency and incremental flag"]
    pub const fn new(urgency: u8, incremental: bool) -> Self {
        Self {
            urgency,
            incremental,
        }
    }
}

#[cfg(feature = "sfv")]
#[cfg_attr(docsrs, doc(cfg(feature = "sfv")))]
impl TryFrom<&[u8]> for Priority {
    type Error = Error;

    /// Try to parse an Extensible Priority field value.
    ///
    /// The field value is expected to be a Structured Fields Dictionary; see
    /// [Extensible Priorities].
    ///
    /// If the `u` or `i` fields are contained with correct types, a constructed
    /// Priority object is returned. Note that urgency values outside of valid
    /// range (0 through 7) are clamped to 7.
    ///
    /// If the `u` or `i` fields are contained with the wrong types,
    /// Error::Done is returned.
    ///
    /// Omitted parameters will yield default values.
    ///
    /// [Extensible Priorities]: https://www.rfc-editor.org/rfc/rfc9218.html#section-4.
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let dict: sfv::Dictionary =
            match sfv::Parser::new(value).parse_dictionary() {
                Ok(v) => v,

                Err(_) => return Err(Error::Done),
            };

        let urgency = match dict.get("u") {
            // If there is a u parameter, try to read it as an Item of type
            // Integer. If the value out of the spec's allowed range
            // (0 through 7), that's an error so set it to the upper
            // bound (lowest priority) to avoid interference with
            // other streams.
            Some(sfv::ListEntry::Item(item)) => match item.bare_item.as_integer()
            {
                Some(v) => {
                    let v: i64 = v.into();

                    if !(PRIORITY_URGENCY_LOWER_BOUND as i64..=
                        PRIORITY_URGENCY_UPPER_BOUND as i64)
                        .contains(&v)
                    {
                        PRIORITY_URGENCY_UPPER_BOUND
                    } else {
                        v as u8
                    }
                },

                None => return Err(Error::Done),
            },

            Some(sfv::ListEntry::InnerList(_)) => return Err(Error::Done),

            // Omitted so use default value.
            None => PRIORITY_URGENCY_DEFAULT,
        };

        let incremental = match dict.get("i") {
            Some(sfv::ListEntry::Item(item)) =>
                item.bare_item.as_boolean().ok_or(Error::Done)?,

            // Omitted so use default value.
            _ => false,
        };

        Ok(Priority::new(urgency, incremental))
    }
}

struct ConnectionSettings {
    pub max_field_section_size: Option<u64>,
    pub qpack_max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
    pub connect_protocol_enabled: Option<u64>,
    pub h3_datagram: Option<u64>,
    pub additional_settings: Option<Vec<(u64, u64)>>,
    pub raw: Option<Vec<(u64, u64)>>,
}

#[derive(Default)]
struct QpackStreams {
    pub encoder_stream_id: Option<u64>,
    pub encoder_stream_bytes: u64,
    pub decoder_stream_id: Option<u64>,
    pub decoder_stream_bytes: u64,
}

/// Statistics about the connection.
///
/// A connection's statistics can be collected using the [`stats()`] method.
///
/// [`stats()`]: struct.Connection.html#method.stats
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Stats {
    /// The number of bytes received on the QPACK encoder stream.
    pub qpack_encoder_stream_recv_bytes: u64,
    /// The number of bytes received on the QPACK decoder stream.
    pub qpack_decoder_stream_recv_bytes: u64,
}

fn close_conn_critical_stream<F: BufFactory>(
    conn: &mut super::Connection<F>,
) -> Result<()> {
    conn.close(
        true,
        Error::ClosedCriticalStream.to_wire(),
        b"Critical stream closed.",
    )?;

    Err(Error::ClosedCriticalStream)
}

fn close_conn_if_critical_stream_finished<F: BufFactory>(
    conn: &mut super::Connection<F>, stream_id: u64,
) -> Result<()> {
    if conn.stream_finished(stream_id) {
        close_conn_critical_stream(conn)?;
    }

    Ok(())
}

/// An HTTP/3 connection.
pub struct Connection {
    is_server: bool,

    next_request_stream_id: u64,
    next_uni_stream_id: u64,

    streams: crate::stream::StreamIdHashMap<stream::Stream>,

    local_settings: ConnectionSettings,
    peer_settings: ConnectionSettings,

    control_stream_id: Option<u64>,
    peer_control_stream_id: Option<u64>,

    local_qpack_streams: QpackStreams,
    peer_qpack_streams: QpackStreams,

    max_push_id: u64,

    // Streams whose peer send side has finished and still need a Finished
    // event. If the local send side is already done, poll() removes the H3
    // stream state when returning the event. Otherwise the send path removes it
    // when the local side finishes later.
    finished_streams: VecDeque<u64>,

    frames_greased: bool,

    local_goaway_id: Option<u64>,
    peer_goaway_id: Option<u64>,

    max_priority_update_size: u64,
}

impl Connection {
    fn new(config: &Config, is_server: bool, enable_dgram: bool) -> Self {
        let initial_uni_stream_id = if is_server { 0x3 } else { 0x2 };
        let h3_datagram = if enable_dgram { Some(1) } else { None };

        Self {
            is_server,

            next_request_stream_id: 0,

            next_uni_stream_id: initial_uni_stream_id,

            streams: crate::stream::StreamIdHashMap::default(),

            local_settings: ConnectionSettings {
                max_field_section_size: config.max_field_section_size,
                qpack_max_table_capacity: config.qpack_max_table_capacity,
                qpack_blocked_streams: config.qpack_blocked_streams,
                connect_protocol_enabled: config.connect_protocol_enabled,
                h3_datagram,
                additional_settings: config.additional_settings.clone(),
                raw: None,
            },

            peer_settings: ConnectionSettings {
                max_field_section_size: None,
                qpack_max_table_capacity: None,
                qpack_blocked_streams: None,
                h3_datagram: None,
                connect_protocol_enabled: None,
                additional_settings: None,
                raw: None,
            },

            control_stream_id: None,
            peer_control_stream_id: None,

            local_qpack_streams: QpackStreams::default(),
            peer_qpack_streams: QpackStreams::default(),

            max_push_id: 0,

            finished_streams: VecDeque::new(),

            frames_greased: false,

            local_goaway_id: None,
            peer_goaway_id: None,

            max_priority_update_size: config.max_priority_update_size,
        }
    }

    /// Creates a new HTTP/3 connection using the provided QUIC connection.
    ///
    /// This will also initiate the HTTP/3 handshake with the peer by opening
    /// all control streams (including QPACK) and sending the local settings.
    ///
    /// On success the new connection is returned.
    ///
    /// The [`StreamLimit`] error is returned when the HTTP/3 control stream
    /// cannot be created due to stream limits.
    ///
    /// The [`InternalError`] error is returned when either the underlying QUIC
    /// connection is not in a suitable state, or the HTTP/3 control stream
    /// cannot be created due to flow control limits.
    ///
    /// # Errors
    ///
    /// Returns `Error::InternalError` if the client transport is not
    /// established or in early data, or if control-stream setup fails.
    /// Stream-creation and transport errors, including stream-limit errors, can
    /// also be propagated.
    ///
    /// [`StreamLimit`]: ../enum.Error.html#variant.StreamLimit
    /// [`InternalError`]: ../enum.Error.html#variant.InternalError
    pub fn with_transport<F: BufFactory>(
        conn: &mut super::Connection<F>, config: &Config,
    ) -> Result<Self> {
        let is_client = !conn.is_server;
        if is_client && !(conn.is_established() || conn.is_in_early_data()) {
            trace!("{} QUIC connection must be established or in early data before creating an HTTP/3 connection", conn.trace_id());
            return Err(Error::InternalError);
        }

        let mut http3_conn =
            Self::new(config, conn.is_server, conn.dgram_enabled());

        match http3_conn.send_settings(conn) {
            Ok(_) => (),

            Err(e) => {
                conn.close(true, e.to_wire(), b"Error opening control stream")?;
                return Err(e);
            },
        }

        // Try opening QPACK streams, but ignore errors if it fails since we
        // don't need them right now.
        http3_conn
            .open_qpack_stream(conn, stream::Type::QpackEncoder)
            .ok();
        http3_conn
            .open_qpack_stream(conn, stream::Type::QpackDecoder)
            .ok();

        if conn.grease {
            // Try opening a GREASE stream, but ignore errors since it's not
            // critical.
            http3_conn.open_grease_stream(conn).ok();
        }

        Ok(http3_conn)
    }

    /// Sends an HTTP/3 request.
    ///
    /// The request is encoded from the provided list of headers without a
    /// body, and sent on a newly allocated stream. To include a body,
    /// set `fin` as `false` and subsequently call [`send_body()`] with the
    /// same `conn` and the `stream_id` returned from this method.
    ///
    /// On success the newly allocated stream ID is returned.
    ///
    /// The [`StreamBlocked`] error is returned when the underlying QUIC stream
    /// doesn't have enough capacity for the operation to complete. When this
    /// happens the application should retry the **entire** `send_request` call
    /// once the stream is reported as writable again. Any partial state created
    /// by the failed call is rolled back, so repeating the call with the same
    /// arguments is safe.
    ///
    /// # Errors
    ///
    /// Returns `Error::FrameUnexpected` after receiving a GOAWAY,
    /// `Error::StreamBlocked` when the operation must be retried, or an error
    /// from stream creation or header encoding.
    ///
    /// [`send_body()`]: struct.Connection.html#method.send_body
    /// [`StreamBlocked`]: enum.Error.html#variant.StreamBlocked
    pub fn send_request<T: NameValue, F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, headers: &[T], fin: bool,
    ) -> Result<u64> {
        // If we received a GOAWAY from the peer, MUST NOT initiate new
        // requests.
        if self.peer_goaway_id.is_some() {
            return Err(Error::FrameUnexpected);
        }

        let stream_id = self.next_request_stream_id;

        self.streams.insert(
            stream_id,
            <stream::Stream>::new(
                stream_id,
                true,
                self.local_settings
                    .max_field_section_size
                    .unwrap_or(SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT),
                self.max_priority_update_size,
            ),
        );

        // The underlying QUIC stream does not exist yet, so calls to e.g.
        // stream_capacity() will fail. By writing a 0-length buffer, we force
        // the creation of the QUIC stream state, without actually writing
        // anything.
        if let Err(e) = conn.stream_send(stream_id, b"", false) {
            self.streams.remove(&stream_id);

            if e == super::Error::Done {
                return Err(Error::StreamBlocked);
            }

            return Err(e.into());
        }

        if let Err(e) = self.send_headers(
            conn,
            stream_id,
            headers,
            stream::HeaderSection::Final,
            fin,
        ) {
            // If the stream was blocked before any header bytes were written,
            // the QUIC stream exists but carries no H3 data yet. Roll back the
            // H3-layer stream entry so the stream ID is not consumed and a
            // subsequent retry of `send_request` starts from a clean state,
            // consistent with the `StreamBlocked` path above.
            if e == Error::StreamBlocked {
                self.streams.remove(&stream_id);
            }

            return Err(e);
        }

        // To avoid skipping stream IDs, we only calculate the next available
        // stream ID when a request has been successfully buffered.
        self.next_request_stream_id = self
            .next_request_stream_id
            .checked_add(4)
            .ok_or(Error::IdError)?;

        Ok(stream_id)
    }

    /// Sends an HTTP/3 response on the specified stream with default priority.
    ///
    /// This method sends the provided `headers` as a single initial response
    /// without a body.
    ///
    /// To send a non-final 1xx, then a final 200+ without body:
    ///   * `send_response()` with `fin` set to `false`.
    ///   * [`send_additional_headers()`] with fin set to `true` using the same
    ///     `stream_id` value.
    ///
    /// To send a non-final 1xx, then a final 200+ with body:
    ///   * `send_response()` with `fin` set to `false`.
    ///   * [`send_additional_headers()`] with fin set to `false` and same
    ///     `stream_id` value.
    ///   * [`send_body()`] with same `stream_id`.
    ///
    /// To send a final 200+ with body:
    ///   * `send_response()` with `fin` set to `false`.
    ///   * [`send_body()`] with same `stream_id`.
    ///
    /// Additional headers can only be sent during certain phases of an HTTP/3
    /// message exchange, see [Section 4.1 of RFC 9114]. The [`FrameUnexpected`]
    /// error is returned if this method, or [`send_response_with_priority()`],
    /// are called multiple times with the same `stream_id` value.
    ///
    /// The [`StreamBlocked`] error is returned when the underlying QUIC stream
    /// doesn't have enough capacity for the operation to complete. When this
    /// happens the application should retry the operation once the stream is
    /// reported as writable again.
    ///
    /// # Errors
    ///
    /// Returns the same response sequencing, stream-capacity, and transport
    /// errors as [`Self::send_response_with_priority`].
    ///
    /// [`send_body()`]: struct.Connection.html#method.send_body
    /// [`send_additional_headers()`]:
    ///     struct.Connection.html#method.send_additional_headers
    /// [`send_response_with_priority()`]:
    ///     struct.Connection.html#method.send_response_with_priority
    /// [`FrameUnexpected`]: enum.Error.html#variant.FrameUnexpected
    /// [`StreamBlocked`]: enum.Error.html#variant.StreamBlocked
    pub fn send_response<T: NameValue, F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64,
        headers: &[T], fin: bool,
    ) -> Result<()> {
        let priority = Priority::default();

        self.send_response_with_priority(
            conn, stream_id, headers, priority, fin,
        )?;

        Ok(())
    }

    /// Sends an HTTP/3 response on the specified stream with specified
    /// priority.
    ///
    /// This method sends the provided `headers` as a single initial response
    /// without a body.
    ///
    /// To send a non-final 1xx, then a final 200+ without body:
    ///   * `send_response_with_priority()` with `fin` set to `false`.
    ///   * [`send_additional_headers()`] with fin set to `true` using the same
    ///     `stream_id` value.
    ///
    /// To send a non-final 1xx, then a final 200+ with body:
    ///   * `send_response_with_priority()` with `fin` set to `false`.
    ///   * [`send_additional_headers()`] with fin set to `false` and same
    ///     `stream_id` value.
    ///   * [`send_body()`] with same `stream_id`.
    ///
    /// To send a final 200+ with body:
    ///   * `send_response_with_priority()` with `fin` set to `false`.
    ///   * [`send_body()`] with same `stream_id`.
    ///
    /// The `priority` parameter represents [Extensible Priority]
    /// parameters. If the urgency is outside the range 0-7, it will be clamped
    /// to 7.
    ///
    /// Additional headers can only be sent during certain phases of an HTTP/3
    /// message exchange, see [Section 4.1 of RFC 9114]. The [`FrameUnexpected`]
    /// error is returned if this method, or [`send_response()`],
    /// are called multiple times with the same `stream_id` value.
    ///
    /// The [`StreamBlocked`] error is returned when the underlying QUIC stream
    /// doesn't have enough capacity for the operation to complete. When this
    /// happens the application should retry the operation once the stream is
    /// reported as writable again.
    ///
    /// # Errors
    ///
    /// Returns `Error::FrameUnexpected` for an unknown stream or a duplicate
    /// initial response, `Error::StreamBlocked` when the operation must be
    /// retried, or header-encoding and transport errors.
    ///
    /// [`send_body()`]: struct.Connection.html#method.send_body
    /// [`send_additional_headers()`]:
    ///     struct.Connection.html#method.send_additional_headers
    /// [`send_response()`]:
    ///     struct.Connection.html#method.send_response
    /// [`FrameUnexpected`]: enum.Error.html#variant.FrameUnexpected
    /// [`StreamBlocked`]: enum.Error.html#variant.StreamBlocked
    /// [Extensible Priority]: https://www.rfc-editor.org/rfc/rfc9218.html#section-4.
    pub fn send_response_with_priority<T: NameValue, F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64,
        headers: &[T], priority: Priority, fin: bool,
    ) -> Result<()> {
        if !self
            .streams
            .get(&stream_id)
            .is_some_and(stream::Stream::can_send_initial_headers)
        {
            return Err(Error::FrameUnexpected);
        }

        let section = stream::HeaderSection::response(headers);
        self.send_headers(conn, stream_id, headers, section, fin)?;

        // Clamp and shift urgency into quiche-priority space
        let urgency = priority
            .urgency
            .clamp(PRIORITY_URGENCY_LOWER_BOUND, PRIORITY_URGENCY_UPPER_BOUND) +
            PRIORITY_URGENCY_OFFSET;

        conn.stream_priority(stream_id, urgency, priority.incremental)?;

        Ok(())
    }

    /// Sends additional HTTP/3 headers.
    ///
    /// After the initial request or response headers have been sent, using
    /// [`send_request()`] or [`send_response()`] respectively, this method can
    /// be used send an additional HEADERS frame. For example, to send a single
    /// instance of trailers after a request with a body, or to issue another
    /// non-final 1xx after a preceding 1xx, or to issue a final response after
    /// a preceding 1xx.
    ///
    /// Additional headers can only be sent during certain phases of an HTTP/3
    /// message exchange, see [Section 4.1 of RFC 9114]. The [`FrameUnexpected`]
    /// error is returned when this method is called during the wrong phase,
    /// such as before initial headers have been sent, or if trailers have
    /// already been sent.
    ///
    /// The [`StreamBlocked`] error is returned when the underlying QUIC stream
    /// doesn't have enough capacity for the operation to complete. When this
    /// happens the application should retry the operation once the stream is
    /// reported as writable again.
    ///
    /// # Errors
    ///
    /// Returns `Error::FrameUnexpected` for an invalid message phase or
    /// unknown stream, `Error::StreamBlocked` when the operation must be
    /// retried, or header-encoding and transport errors.
    ///
    /// [`send_request()`]: struct.Connection.html#method.send_request
    /// [`send_response()`]: struct.Connection.html#method.send_response
    /// [`StreamBlocked`]: enum.Error.html#variant.StreamBlocked
    /// [`FrameUnexpected`]: enum.Error.html#variant.FrameUnexpected
    /// [Section 4.1 of RFC 9114]:
    ///     https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.
    pub fn send_additional_headers<T: NameValue, F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64,
        headers: &[T], is_trailer_section: bool, fin: bool,
    ) -> Result<()> {
        let section = if is_trailer_section {
            stream::HeaderSection::Trailers
        } else if self.is_server {
            stream::HeaderSection::response(headers)
        } else {
            return Err(Error::FrameUnexpected);
        };

        if !self
            .streams
            .get(&stream_id)
            .is_some_and(|s| s.can_send_additional_headers(section))
        {
            return Err(Error::FrameUnexpected);
        }

        self.send_headers(conn, stream_id, headers, section, fin)?;

        Ok(())
    }

    /// Sends additional HTTP/3 headers with specified priority.
    ///
    /// After the initial request or response headers have been sent, using
    /// [`send_request()`] or [`send_response()`] respectively, this method can
    /// be used send an additional HEADERS frame. For example, to send a single
    /// instance of trailers after a request with a body, or to issue another
    /// non-final 1xx after a preceding 1xx, or to issue a final response after
    /// a preceding 1xx.
    ///
    /// The `priority` parameter represents [Extensible Priority]
    /// parameters. If the urgency is outside the range 0-7, it will be clamped
    /// to 7.
    ///
    /// Additional headers can only be sent during certain phases of an HTTP/3
    /// message exchange, see [Section 4.1 of RFC 9114]. The [`FrameUnexpected`]
    /// error is returned when this method is called during the wrong phase,
    /// such as before initial headers have been sent, or if trailers have
    /// already been sent.
    ///
    /// The [`StreamBlocked`] error is returned when the underlying QUIC stream
    /// doesn't have enough capacity for the operation to complete. When this
    /// happens the application should retry the operation once the stream is
    /// reported as writable again.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::send_additional_headers`], as well as
    /// any transport error while applying the stream priority.
    ///
    /// [`send_request()`]: struct.Connection.html#method.send_request
    /// [`send_response()`]: struct.Connection.html#method.send_response
    /// [`StreamBlocked`]: enum.Error.html#variant.StreamBlocked
    /// [`FrameUnexpected`]: enum.Error.html#variant.FrameUnexpected
    /// [Section 4.1 of RFC 9114]:
    ///     https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.
    /// [Extensible Priority]: https://www.rfc-editor.org/rfc/rfc9218.html#section-4.
    pub fn send_additional_headers_with_priority<T: NameValue, F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64,
        headers: &[T], priority: Priority, is_trailer_section: bool, fin: bool,
    ) -> Result<()> {
        self.send_additional_headers(
            conn,
            stream_id,
            headers,
            is_trailer_section,
            fin,
        )?;

        // Clamp and shift urgency into quiche-priority space
        let urgency = priority
            .urgency
            .clamp(PRIORITY_URGENCY_LOWER_BOUND, PRIORITY_URGENCY_UPPER_BOUND) +
            PRIORITY_URGENCY_OFFSET;

        conn.stream_priority(stream_id, urgency, priority.incremental)?;

        Ok(())
    }

    fn send_headers<T: NameValue, F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64,
        headers: &[T], section: stream::HeaderSection, fin: bool,
    ) -> Result<()> {
        if section == stream::HeaderSection::Informational && fin {
            return Err(Error::FrameUnexpected);
        }

        let mut d = [42; 10];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        if !self.frames_greased && conn.grease {
            self.send_grease_frames(conn, stream_id)?;
            self.frames_greased = true;
        }

        let header_block =
            qpack::encode(headers).map_err(|_| Error::InternalError)?;

        let overhead = octets::varint_len(frame::HEADERS_FRAME_TYPE_ID) +
            octets::varint_len(header_block.len() as u64);

        // Headers need to be sent atomically, so make sure the stream has
        // enough capacity.
        match conn.stream_writable(stream_id, overhead + header_block.len()) {
            Ok(true) => (),

            Ok(false) => return Err(Error::StreamBlocked),

            Err(e) => {
                if conn.stream_finished(stream_id) {
                    self.streams.remove(&stream_id);
                }

                return Err(e.into());
            },
        }

        b.put_varint(frame::HEADERS_FRAME_TYPE_ID)?;
        b.put_varint(header_block.len() as u64)?;
        let off = b.off();
        conn.stream_send(stream_id, &d[..off], false)?;

        // Sending header block separately avoids unnecessary copy.
        conn.stream_send(stream_id, &header_block, fin)?;

        trace!(
            "{} tx frm HEADERS stream={stream_id} len={} fin={fin}",
            conn.trace_id(),
            header_block.len()
        );

        qlog_with_type!(QLOG_FRAME_CREATED, conn.qlog, q, {
            let qlog_headers = headers
                .iter()
                .map(|h| qlog::events::http3::HttpHeader {
                    name: Some(String::from_utf8_lossy(h.name()).into_owned()),
                    name_bytes: None,
                    value: Some(String::from_utf8_lossy(h.value()).into_owned()),
                    value_bytes: None,
                })
                .collect();

            let frame = Http3Frame::Headers {
                headers: qlog_headers,
                raw: None,
            };
            let ev_data = EventData::Http3FrameCreated(FrameCreated {
                stream_id,
                length: Some(header_block.len() as u64),
                frame,
                ..Default::default()
            });

            q.add_event_data_now(ev_data).ok();
        });

        if fin {
            self.finish_local_stream(conn, stream_id);
        } else if let Some(s) = self.streams.get_mut(&stream_id) {
            s.on_sent_headers(section, false);
        }

        Ok(())
    }

    /// Sends an HTTP/3 body chunk on the given stream.
    ///
    /// On success the number of bytes written is returned, or [`Done`] if no
    /// bytes could be written (e.g. because the stream is blocked).
    ///
    /// Note that the number of written bytes returned can be lower than the
    /// length of the input buffer when the underlying QUIC stream doesn't have
    /// enough capacity for the operation to complete.
    ///
    /// When a partial write happens (including when [`Done`] is returned) the
    /// application should retry the operation once the stream is reported as
    /// writable again.
    /// After trailers, an empty body with `fin` set sends only the QUIC FIN
    /// without emitting another HTTP/3 DATA frame.
    ///
    /// # Errors
    ///
    /// Returns `Error::Done` when no DATA can be buffered (including an empty
    /// non-final input), `Error::FrameUnexpected` if DATA is not allowed on the
    /// stream at this phase, or a transport or frame-encoding error.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn send_body<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64, body: &[u8],
        fin: bool,
    ) -> Result<usize> {
        self.do_send_body(
            conn,
            stream_id,
            body,
            fin,
            |conn: &mut super::Connection<F>,
             header: &[u8],
             stream_id: u64,
             body: &[u8],
             body_len: usize,
             fin: bool| {
                conn.stream_send(stream_id, header, false)?;
                Ok(conn.stream_send(stream_id, &body[..body_len], fin)?)
            },
        )
    }

    /// Sends an HTTP/3 body chunk provided as a raw buffer on the given stream.
    ///
    /// If the capacity allows it the buffer will be appended to the stream's
    /// send queue with zero copying.
    ///
    /// On success the number of bytes written is returned, or [`Done`] if no
    /// bytes could be written (e.g. because the stream is blocked).
    ///
    /// Note that the number of written bytes returned can be lower than the
    /// length of the input buffer when the underlying QUIC stream doesn't have
    /// enough capacity for the operation to complete.
    ///
    /// When a partial write happens (including when [`Done`] is returned) the
    /// remaining (unwritten) buffer will also be returned. The application
    /// should retry the operation once the stream is reported as writable
    /// again.
    ///
    /// # Errors
    ///
    /// Returns the same body-send errors as [`Self::send_body`]. An unexpected
    /// partial write that cannot preserve the frame length is an
    /// `Error::InternalError`.
    ///
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn send_body_zc<F>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64,
        body: &mut F::Buf, fin: bool,
    ) -> Result<usize>
    where
        F: BufFactory,
        F::Buf: BufSplit,
    {
        self.do_send_body(
            conn,
            stream_id,
            body,
            fin,
            |conn: &mut super::Connection<F>,
             header: &[u8],
             stream_id: u64,
             body: &mut F::Buf,
             mut body_len: usize,
             fin: bool| {
                let with_prefix = body.try_add_prefix(header);
                if !with_prefix {
                    conn.stream_send(stream_id, header, false)?;
                } else {
                    body_len += header.len();
                }

                let remainder = body.split_at(body_len);
                // body now contains the first `body_len` bytes of the original
                // buffer
                debug_assert_eq!(body.as_ref().len(), body_len);

                let (mut n, rem) =
                    conn.stream_send_zc(stream_id, body.clone(), fin)?;
                if rem.as_ref().is_some_and(|v| !v.as_ref().is_empty()) {
                    // `do_send_body()` checked capacity before this write, so
                    // `rem` should always be `None` or empty.
                    debug_assert!(false);
                    return Err(Error::InternalError);
                }

                if with_prefix {
                    n -= header.len();
                }

                if !remainder.as_ref().is_empty() {
                    let _ = std::mem::replace(body, remainder);
                }

                Ok(n)
            },
        )
    }

    fn do_send_body<F, B, SND>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64, body: B,
        fin: bool, write_fn: SND,
    ) -> Result<usize>
    where
        F: BufFactory,
        B: AsRef<[u8]>,
        SND: FnOnce(
            &mut super::Connection<F>,
            &[u8],
            u64,
            B,
            usize,
            bool,
        ) -> Result<usize>,
    {
        let mut d = [42; 10];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let len = body.as_ref().len();

        // Validate that it is sane to send data on the stream.
        if !stream_id.is_multiple_of(4) {
            return Err(Error::FrameUnexpected);
        }

        let stream =
            self.streams.get(&stream_id).ok_or(Error::FrameUnexpected)?;
        if stream.awaiting_fin_after_trailers() && len == 0 && fin {
            // A QUIC FIN consumes no stream offset or flow-control credit.
            // A DATA frame, even an empty one, would be illegal here.
            let written = conn.stream_send(stream_id, &[], true)?;
            self.finish_local_stream(conn, stream_id);
            return Ok(written);
        }

        if !stream.can_send_body() {
            return Err(Error::FrameUnexpected);
        }

        // Avoid sending 0-length DATA frames when the fin flag is false.
        if len == 0 && !fin {
            return Err(Error::Done);
        }

        let stream_cap = match conn.stream_capacity(stream_id) {
            Ok(v) => v,

            Err(e) => {
                if conn.stream_finished(stream_id) {
                    self.streams.remove(&stream_id);
                }

                return Err(e.into());
            },
        };

        // Use the length of the chunk we can actually encode, rather than
        // charging the original input's (possibly larger) varint width.
        let Some(body_len) = data_payload_capacity(len, stream_cap) else {
            let _ = conn.stream_writable(stream_id, if len == 0 { 2 } else { 3 });
            return Err(Error::Done);
        };

        let fin = fin && body_len == len;
        if body_len == 0 && !fin {
            let _ = conn.stream_writable(stream_id, 3);
            return Err(Error::Done);
        }

        b.put_varint(frame::DATA_FRAME_TYPE_ID)?;
        b.put_varint(body_len as u64)?;
        let off = b.off();

        // Return how many bytes were written, excluding the frame header.
        // Sending body separately avoids unnecessary copy.
        let written = write_fn(conn, &d[..off], stream_id, body, body_len, fin)?;
        if written != body_len {
            // This should never happen. If it does, it means we wrote an
            // incorrect frame length and thus we can't really continue.
            debug_assert!(false);
            return Err(Error::InternalError);
        }

        trace!(
            "{} tx frm DATA stream={stream_id} len={written} fin={fin}",
            conn.trace_id()
        );

        qlog_with_type!(QLOG_FRAME_CREATED, conn.qlog, q, {
            let frame = Http3Frame::Data { raw: None };
            let ev_data = EventData::Http3FrameCreated(FrameCreated {
                stream_id,
                length: Some(written as u64),
                frame,
                ..Default::default()
            });

            q.add_event_data_now(ev_data).ok();
        });

        if written < len {
            // Ensure the peer is notified that the connection or stream is
            // blocked when the stream's capacity is limited by flow control.
            //
            // We only need enough capacity to send a few bytes, to make sure
            // the stream doesn't hang due to congestion window not growing
            // enough.
            let _ = conn.stream_writable(stream_id, 3);
        }

        if fin && written == len {
            self.finish_local_stream(conn, stream_id);
        }

        Ok(written)
    }

    /// Returns whether the peer enabled HTTP/3 DATAGRAM frame support.
    ///
    /// Support is signalled by the peer's SETTINGS, so this method always
    /// returns false until they have been processed using the [`poll()`]
    /// method.
    ///
    /// [`poll()`]: struct.Connection.html#method.poll
    #[must_use = "the result determines whether the peer permits HTTP datagrams"]
    pub fn dgram_enabled_by_peer<F: BufFactory>(
        &self, conn: &super::Connection<F>,
    ) -> bool {
        self.peer_settings.h3_datagram == Some(1) &&
            conn.dgram_max_writable_len().is_some()
    }

    /// Returns whether the peer enabled extended CONNECT support.
    ///
    /// Support is signalled by the peer's SETTINGS, so this method always
    /// returns false until they have been processed using the [`poll()`]
    /// method.
    ///
    /// [`poll()`]: struct.Connection.html#method.poll
    #[must_use = "the result determines whether the peer permits extended CONNECT"]
    pub fn extended_connect_enabled_by_peer(&self) -> bool {
        self.peer_settings.connect_protocol_enabled == Some(1)
    }

    /// Reads request or response body data into the provided buffer.
    ///
    /// Applications should call this method whenever the [`poll()`] method
    /// returns a [`Data`] event.
    ///
    /// On success the amount of bytes read is returned, or [`Done`] if there
    /// is no data to read.
    ///
    /// # Errors
    ///
    /// Returns `Error::Done` if no body data is currently readable, or an
    /// HTTP/3 parsing or transport error.
    ///
    /// [`poll()`]: struct.Connection.html#method.poll
    /// [`Data`]: enum.Event.html#variant.Data
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn recv_body<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64,
        out: &mut [u8],
    ) -> Result<usize> {
        self.recv_body_buf(conn, stream_id, out)
    }

    /// Reads request or response body data into the provided `BufMut` buffer.
    ///
    /// **NOTE**:
    /// The `BufMut` will be populated with all available data up to its
    /// capacity. Since some `BufMut` implementations, e.g., [`Vec<u8>`],
    /// dynamically allocate additional memory, the caller may use
    /// [`BufMut::limit()`] to limit the maximum amount of data that
    /// can be written.
    ///
    /// Applications should call this method (or [`recv_body()`]) whenever
    /// the [`poll()`] method returns a [`Data`] event.
    ///
    /// On success the amount of bytes read is returned, or [`Done`] if there
    /// is no data to read.
    ///
    /// # Errors
    ///
    /// Returns the same receive errors as [`Self::recv_body`].
    ///
    /// [`BufMut::limit()`]: bytes::BufMut::limit()
    /// [`recv_body()`]: Self::recv_body()
    /// [`poll()`]: struct.Connection.html#method.poll
    /// [`Data`]: enum.Event.html#variant.Data
    /// [`Done`]: enum.Error.html#variant.Done
    ///
    /// ## Example:
    /// ```no_run
    /// # use quiche::h3;
    /// fn receive(
    ///     qconn: &mut quiche::Connection, h3conn: &mut h3::Connection,
    /// ) -> Result<Vec<u8>, h3::Error> {
    ///     use bytes::BufMut as _;
    ///     let mut buffer = Vec::with_capacity(2048).limit(2048);
    ///     let bytes = h3conn.recv_body_buf(qconn, 0, &mut buffer)?;
    ///     let buffer = buffer.into_inner();
    ///     // The vec has been filled with exactly `bytes` number of bytes
    ///     assert_eq!(buffer.len(), bytes);
    ///     Ok(buffer)
    /// }
    /// ```
    pub fn recv_body_buf<F: BufFactory, OUT: bytes::BufMut>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64, mut out: OUT,
    ) -> Result<usize> {
        let mut total = 0;

        // Try to consume all buffered data for the stream, even across multiple
        // DATA frames.
        // Note, that even if the BufMut does not have a limit defined, we are
        // inherently limited by how much data is in quiche's receive buffer for
        // that stream, so the BufMut cannot grow unbounded.
        while out.has_remaining_mut() {
            let consume_result = {
                let stream =
                    self.streams.get_mut(&stream_id).ok_or(Error::Done)?;

                if stream.state() != stream::State::Data {
                    break;
                }

                stream.try_consume_data(conn, &mut out)
            };

            let (read, fin) = match consume_result {
                Ok(v) => v,

                Err(Error::Done) => break,

                Err(e @ Error::TransportError(crate::Error::StreamReset(_))) => {
                    self.remove_finished_stream(conn, stream_id);
                    return Err(e);
                },

                Err(e) => return Err(e),
            };

            total += read;

            // No more data to read, we are done.
            if read == 0 || fin {
                break;
            }

            // Process incoming data from the stream. For example, if a whole
            // DATA frame was consumed, and another one is queued behind it,
            // this will ensure the additional data will also be returned to
            // the application.
            match self.process_readable_stream(conn, stream_id, false) {
                Ok(_) => unreachable!(),

                Err(Error::Done) => (),

                Err(e @ Error::TransportError(crate::Error::StreamReset(_))) => {
                    self.remove_finished_stream(conn, stream_id);
                    return Err(e);
                },

                Err(e) => return Err(e),
            }

            if conn.stream_finished(stream_id) {
                break;
            }
        }

        // While body is being received, the stream is marked as finished only
        // when all data is read by the application.
        if conn.stream_finished(stream_id) {
            self.process_finished_stream(stream_id);
        }

        if total == 0 {
            return Err(Error::Done);
        }

        Ok(total)
    }

    /// Sends a `PRIORITY_UPDATE` frame on the control stream with specified
    /// request stream ID and priority.
    ///
    /// The `priority` parameter represents [Extensible Priority]
    /// parameters. If the urgency is outside the range 0-7, it will be clamped
    /// to 7.
    ///
    /// The [`StreamBlocked`] error is returned when the underlying QUIC stream
    /// doesn't have enough capacity for the operation to complete. When this
    /// happens the application should retry the operation once the stream is
    /// reported as writable again.
    ///
    /// # Errors
    ///
    /// Returns `Error::FrameUnexpected` when called by a server, for an invalid
    /// request stream ID, or without a control stream; `Error::StreamBlocked`
    /// if the control stream lacks capacity; or a transport/encoding error.
    ///
    /// [`StreamBlocked`]: enum.Error.html#variant.StreamBlocked
    /// [Extensible Priority]: https://www.rfc-editor.org/rfc/rfc9218.html#section-4.
    pub fn send_priority_update_for_request<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64,
        priority: Priority,
    ) -> Result<()> {
        let mut d = [42; 20];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        // Validate that it is sane to send PRIORITY_UPDATE.
        if self.is_server {
            return Err(Error::FrameUnexpected);
        }

        if !stream_id.is_multiple_of(4) {
            return Err(Error::FrameUnexpected);
        }

        let control_stream_id =
            self.control_stream_id.ok_or(Error::FrameUnexpected)?;

        let urgency = priority
            .urgency
            .clamp(PRIORITY_URGENCY_LOWER_BOUND, PRIORITY_URGENCY_UPPER_BOUND);

        let mut field_value = format!("u={urgency}");

        if priority.incremental {
            field_value.push_str(",i");
        }

        let priority_field_value = field_value.as_bytes();
        let frame_payload_len =
            octets::varint_len(stream_id) + priority_field_value.len();

        let overhead =
            octets::varint_len(frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID) +
                octets::varint_len(stream_id) +
                octets::varint_len(frame_payload_len as u64);

        // Make sure the control stream has enough capacity.
        match conn.stream_writable(
            control_stream_id,
            overhead + priority_field_value.len(),
        ) {
            Ok(true) => (),

            Ok(false) => return Err(Error::StreamBlocked),

            Err(e) => {
                return Err(e.into());
            },
        }

        b.put_varint(frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE_ID)?;
        b.put_varint(frame_payload_len as u64)?;
        b.put_varint(stream_id)?;
        let off = b.off();
        conn.stream_send(control_stream_id, &d[..off], false)?;

        // Sending field value separately avoids unnecessary copy.
        conn.stream_send(control_stream_id, priority_field_value, false)?;

        trace!(
            "{} tx frm PRIORITY_UPDATE request_stream={stream_id} priority_field_value={field_value}",
            conn.trace_id(),
        );

        qlog_with_type!(QLOG_FRAME_CREATED, conn.qlog, q, {
            let frame = Http3Frame::PriorityUpdate {
                stream_id: Some(stream_id),
                push_id: None,
                priority_field_value: field_value.clone(),
                raw: None,
            };

            let ev_data = EventData::Http3FrameCreated(FrameCreated {
                stream_id,
                length: Some(priority_field_value.len() as u64),
                frame,
                ..Default::default()
            });

            q.add_event_data_now(ev_data).ok();
        });

        Ok(())
    }

    /// Take the last `PRIORITY_UPDATE` for a prioritized element ID.
    ///
    /// When the [`poll()`] method returns a [`PriorityUpdate`] event for a
    /// prioritized element, the event has triggered and will not rearm until
    /// applications call this method. It is recommended that applications defer
    /// taking the `PRIORITY_UPDATE` until after [`poll()`] returns [`Done`].
    ///
    /// On success the Priority Field Value is returned, or [`Done`] if there is
    /// no `PRIORITY_UPDATE` to read (either because there is no value to take,
    /// or because the prioritized element does not exist).
    ///
    /// # Errors
    ///
    /// Returns `Error::Done` if there is no pending update for the identifier.
    ///
    /// [`poll()`]: struct.Connection.html#method.poll
    /// [`PriorityUpdate`]: enum.Event.html#variant.PriorityUpdate
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn take_last_priority_update(
        &mut self, prioritized_element_id: u64,
    ) -> Result<Vec<u8>> {
        if let Some(stream) = self.streams.get_mut(&prioritized_element_id) {
            return stream.take_last_priority_update().ok_or(Error::Done);
        }

        Err(Error::Done)
    }

    /// Processes HTTP/3 data received from the peer.
    ///
    /// On success it returns an [`Event`] and an ID, or [`Done`] when there are
    /// no events to report.
    ///
    /// Note that all events are edge-triggered, meaning that once reported they
    /// will not be reported again by calling this method again, until the event
    /// is re-armed.
    ///
    /// The events [`Headers`], [`Data`] and [`Finished`] return a stream ID,
    /// which is used in methods [`recv_body()`], [`send_response()`] or
    /// [`send_body()`].
    ///
    /// The event [`GoAway`] returns an ID that depends on the connection role.
    /// A client receives the largest processed stream ID. A server receives the
    /// the largest permitted push ID.
    ///
    /// The event [`PriorityUpdate`] only occurs at servers. It returns a
    /// prioritized element ID that is used in the method
    /// [`take_last_priority_update()`], which rearms the event for that ID.
    ///
    /// If an error occurs while processing data, the connection is closed with
    /// the appropriate error code, using the transport's [`close()`] method.
    ///
    /// # Errors
    ///
    /// Returns `Error::Done` when no event is available or local closure was
    /// initiated. Propagates HTTP/3 parsing and transport errors; a stream
    /// reset may instead be reported as an `Event::Reset`.
    ///
    /// [`Event`]: enum.Event.html
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`Headers`]: enum.Event.html#variant.Headers
    /// [`Data`]: enum.Event.html#variant.Data
    /// [`Finished`]: enum.Event.html#variant.Finished
    /// [`GoAway`]: enum.Event.html#variant.GoAWay
    /// [`PriorityUpdate`]: enum.Event.html#variant.PriorityUpdate
    /// [`recv_body()`]: struct.Connection.html#method.recv_body
    /// [`send_response()`]: struct.Connection.html#method.send_response
    /// [`send_body()`]: struct.Connection.html#method.send_body
    /// [`recv_dgram()`]: struct.Connection.html#method.recv_dgram
    /// [`take_last_priority_update()`]: struct.Connection.html#method.take_last_priority_update
    /// [`close()`]: ../struct.Connection.html#method.close
    pub fn poll<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>,
    ) -> Result<(u64, Event)> {
        // When connection close is initiated by the local application (e.g. due
        // to a protocol error), the connection itself might be in a broken
        // state, so return early.
        if conn.local_error.is_some() {
            return Err(Error::Done);
        }

        // Process critical streams first, in control/encoder/decoder order.
        for stream_id in [
            self.peer_control_stream_id,
            self.peer_qpack_streams.encoder_stream_id,
            self.peer_qpack_streams.decoder_stream_id,
        ]
        .into_iter()
        .flatten()
        {
            match self.process_control_stream(conn, stream_id) {
                Ok(ev) => return Ok(ev),

                Err(Error::Done) => (),

                Err(e) => return Err(e),
            }
        }

        // Process finished streams list.
        if let Some(ev) = self.pop_finished_stream(conn) {
            return Ok(ev);
        }

        // Process HTTP/3 data from readable streams.
        for s in conn.readable() {
            trace!("{} stream id {s} is readable", conn.trace_id());

            let ev = match self.process_readable_stream(conn, s, true) {
                Ok(v) => Some(v),

                Err(Error::Done) => None,

                // Return early if the stream was reset, to avoid returning
                // a Finished event later as well.
                Err(Error::TransportError(crate::Error::StreamReset(e))) => {
                    self.remove_finished_stream(conn, s);

                    return Ok((s, Event::Reset(e)));
                },

                Err(e) => return Err(e),
            };

            if conn.stream_finished(s) {
                self.process_finished_stream(s);
            }

            // TODO: check if stream is completed so it can be freed
            if let Some(ev) = ev {
                return Ok(ev);
            }
        }

        // Process finished streams list once again, to make sure `Finished`
        // events are returned when receiving empty stream frames with the fin
        // flag set.
        if let Some(ev) = self.pop_finished_stream(conn) {
            return Ok(ev);
        }

        Err(Error::Done)
    }

    /// Sends a GOAWAY frame to initiate graceful connection closure.
    ///
    /// When quiche is used in the server role, the `id` parameter is the stream
    /// ID of the highest processed request. This can be any valid ID between 0
    /// and 2^62-4. However, the ID cannot be increased. Failure to satisfy
    /// these conditions will return an error.
    ///
    /// This method does not close the QUIC connection. Applications are
    /// required to call [`close()`] themselves.
    ///
    /// # Errors
    ///
    /// Returns `Error::IdError` for an invalid server request-stream ID or an
    /// increase over the previously sent GOAWAY ID, `Error::StreamBlocked` for
    /// insufficient control-stream capacity, or a transport/encoding error.
    ///
    /// [`close()`]: ../struct.Connection.html#method.close
    pub fn send_goaway<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, id: u64,
    ) -> Result<()> {
        let mut id = id;

        // TODO: server push
        //
        // In the meantime always send 0 from client.
        if !self.is_server {
            id = 0;
        }

        if self.is_server && !id.is_multiple_of(4) {
            return Err(Error::IdError);
        }

        if let Some(sent_id) = self.local_goaway_id {
            if id > sent_id {
                return Err(Error::IdError);
            }
        }

        if let Some(stream_id) = self.control_stream_id {
            let mut d = [42; 10];
            let mut b = octets::OctetsMut::with_slice(&mut d);

            let frame = frame::Frame::GoAway { id };

            let wire_len = frame.to_bytes(&mut b)?;
            let stream_cap = conn.stream_capacity(stream_id)?;

            if stream_cap < wire_len {
                return Err(Error::StreamBlocked);
            }

            trace!("{} tx frm {frame:?}", conn.trace_id());

            qlog_with_type!(QLOG_FRAME_CREATED, conn.qlog, q, {
                let ev_data = EventData::Http3FrameCreated(FrameCreated {
                    stream_id,
                    length: Some(octets::varint_len(id) as u64),
                    frame: frame.to_qlog(),
                    ..Default::default()
                });

                q.add_event_data_now(ev_data).ok();
            });

            let off = b.off();
            conn.stream_send(stream_id, &d[..off], false)?;

            self.local_goaway_id = Some(id);
        }

        Ok(())
    }

    /// Gets the raw settings from peer including unknown and reserved types.
    ///
    /// The order of settings is the same as received in the SETTINGS frame.
    #[must_use = "the returned settings describe the peer HTTP/3 capabilities"]
    pub fn peer_settings_raw(&self) -> Option<&[(u64, u64)]> {
        self.peer_settings.raw.as_deref()
    }

    /// Open a unidirectional stream only when its entire initial sequence
    /// (type, initial payload, and optional FIN) can be buffered.
    fn open_uni_stream<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, ty: u64,
        initial_payload: &[u8], fin: bool,
    ) -> Result<u64> {
        let stream_id = self.next_uni_stream_id;
        if stream_id > octets::MAX_VAR_INT {
            return Err(Error::IdError);
        }
        let next_id = stream_id.checked_add(4).ok_or(Error::IdError)?;
        let prefix = octets::EncodedVarint::new(ty)?;
        let len = prefix
            .as_ref()
            .len()
            .checked_add(initial_payload.len())
            .ok_or(Error::ExcessiveLoad)?;

        match ty {
            // Control and QPACK streams are the most important to schedule.
            stream::HTTP3_CONTROL_STREAM_TYPE_ID |
            stream::QPACK_ENCODER_STREAM_TYPE_ID |
            stream::QPACK_DECODER_STREAM_TYPE_ID => {
                conn.stream_priority(stream_id, 0, false)?;
            },

            // Preserve the default QUIC priority for server push.
            stream::HTTP3_PUSH_STREAM_TYPE_ID => {
                conn.stream_send(stream_id, &[], false)?;
            },

            // Unknown stream types (e.g. GREASE) have lowest priority.
            _ => {
                conn.stream_priority(stream_id, 255, false)?;
            },
        }

        if conn.stream_capacity(stream_id)? < len {
            return Err(Error::Done);
        }

        // Common control, QPACK, and GREASE prefaces stay inline.
        let mut preface =
            smallvec::SmallVec::<[u8; 512]>::from_slice(prefix.as_ref());
        preface.extend_from_slice(initial_payload);
        if conn.stream_send(stream_id, &preface, fin)? != len {
            return Err(Error::InternalError);
        }

        self.next_uni_stream_id = next_id;
        Ok(stream_id)
    }

    fn open_qpack_stream<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, kind: stream::Type,
    ) -> Result<()> {
        let stream_type = match kind {
            stream::Type::QpackEncoder => stream::QPACK_ENCODER_STREAM_TYPE_ID,
            stream::Type::QpackDecoder => stream::QPACK_DECODER_STREAM_TYPE_ID,
            _ => return Err(Error::InternalError),
        };
        let stream_id = self.open_uni_stream(conn, stream_type, &[], false)?;

        match kind {
            stream::Type::QpackEncoder => {
                self.local_qpack_streams.encoder_stream_id = Some(stream_id);
            },
            stream::Type::QpackDecoder => {
                self.local_qpack_streams.decoder_stream_id = Some(stream_id);
            },
            _ => return Err(Error::InternalError),
        }

        qlog_with_type!(QLOG_STREAM_TYPE_SET, conn.qlog, q, {
            let ev_data = EventData::Http3StreamTypeSet(StreamTypeSet {
                stream_id,
                initiator: Some(Initiator::Local),
                stream_type: kind.to_qlog(),
                ..Default::default()
            });
            q.add_event_data_now(ev_data).ok();
        });

        Ok(())
    }

    /// Send GREASE frames on the provided stream ID.
    fn send_grease_frames<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64,
    ) -> Result<()> {
        const GREASE_PAYLOAD: &[u8] = b"GREASE is the word";
        let mut d = [0; 2 * 8 + 2 + GREASE_PAYLOAD.len()];

        let stream_cap = match conn.stream_capacity(stream_id) {
            Ok(v) => v,

            Err(e) => {
                if conn.stream_finished(stream_id) {
                    self.streams.remove(&stream_id);
                }

                return Err(e.into());
            },
        };

        let grease_frame1 = grease_value();
        let grease_frame2 = grease_value();

        // Encode both frames and queue them as one complete write.
        let mut b = octets::OctetsMut::with_slice(&mut d);
        b.put_varint(grease_frame1)?;
        b.put_varint(0)?;
        b.put_varint(grease_frame2)?;
        b.put_varint(GREASE_PAYLOAD.len() as u64)?;
        b.put_bytes(GREASE_PAYLOAD)?;
        let off = b.off();
        // Optional GREASE must not consume partial stream credit.
        if stream_cap < off {
            return Ok(());
        }
        if conn.stream_send(stream_id, &d[..off], false)? != off {
            return Err(Error::InternalError);
        }

        trace!("{} tx frm GREASE stream={stream_id} len=0", conn.trace_id());

        qlog_with_type!(QLOG_FRAME_CREATED, conn.qlog, q, {
            let frame = Http3Frame::Reserved {
                frame_type_bytes: grease_frame1,
                raw: None,
            };
            let ev_data = EventData::Http3FrameCreated(FrameCreated {
                stream_id,
                length: Some(0),
                frame,
                ..Default::default()
            });

            q.add_event_data_now(ev_data).ok();
        });

        trace!(
            "{} tx frm GREASE stream={stream_id} len={}",
            conn.trace_id(),
            GREASE_PAYLOAD.len()
        );

        qlog_with_type!(QLOG_FRAME_CREATED, conn.qlog, q, {
            let frame = Http3Frame::Reserved {
                frame_type_bytes: grease_frame2,
                raw: None,
            };
            let ev_data = EventData::Http3FrameCreated(FrameCreated {
                stream_id,
                length: Some(GREASE_PAYLOAD.len() as u64),
                frame,
                ..Default::default()
            });

            q.add_event_data_now(ev_data).ok();
        });

        Ok(())
    }

    /// Opens a new unidirectional stream with a GREASE type and sends some
    /// unframed payload.
    fn open_grease_stream<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>,
    ) -> Result<()> {
        let ty = grease_value();
        match self.open_uni_stream(conn, ty, b"GREASE is the word", true) {
            Ok(stream_id) => {
                trace!("{} open GREASE stream {stream_id}", conn.trace_id());

                qlog_with_type!(QLOG_STREAM_TYPE_SET, conn.qlog, q, {
                    let ev_data = EventData::Http3StreamTypeSet(StreamTypeSet {
                        stream_id,
                        initiator: Some(Initiator::Local),
                        stream_type: StreamType::Unknown,
                        stream_type_bytes: Some(ty),
                        ..Default::default()
                    });

                    q.add_event_data_now(ev_data).ok();
                });
            },

            Err(
                Error::IdError |
                Error::Done |
                Error::TransportError(super::Error::StreamLimit),
            ) => {
                trace!("{} GREASE stream blocked", conn.trace_id(),);

                return Ok(());
            },

            Err(e) => return Err(e),
        }

        Ok(())
    }

    /// Sends SETTINGS frame based on HTTP/3 configuration.
    fn send_settings<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>,
    ) -> Result<()> {
        let mut grease = if conn.grease {
            let id = grease_value();
            let collision = self
                .local_settings
                .additional_settings
                .as_deref()
                .is_some_and(|settings| {
                    settings.iter().any(|&(key, _)| key == id)
                });
            (!collision).then(|| (id, grease_value()))
        } else {
            None
        };

        let mut d = [0; frame::MAX_SETTINGS_PAYLOAD_SIZE + 3];

        let (stream_id, off, settings_frame) = loop {
            let settings_frame = frame::Frame::Settings {
                max_field_section_size: self
                    .local_settings
                    .max_field_section_size,
                qpack_max_table_capacity: self
                    .local_settings
                    .qpack_max_table_capacity,
                qpack_blocked_streams: self.local_settings.qpack_blocked_streams,
                connect_protocol_enabled: self
                    .local_settings
                    .connect_protocol_enabled,
                h3_datagram: self.local_settings.h3_datagram,
                grease,
                additional_settings: self
                    .local_settings
                    .additional_settings
                    .clone(),
                raw: None,
            };

            let result = settings_frame
                .to_bytes(&mut octets::OctetsMut::with_slice(&mut d))
                .and_then(|off| {
                    let id = self.open_uni_stream(
                        conn,
                        stream::HTTP3_CONTROL_STREAM_TYPE_ID,
                        &d[..off],
                        false,
                    )?;
                    Ok((id, off))
                });

            match result {
                Ok((id, off)) => break (id, off, settings_frame),

                Err(Error::ExcessiveLoad | Error::Done) if grease.is_some() => {
                    // GREASE is optional; never allow it to displace settings.
                    grease = None;
                },

                Err(Error::Done | Error::BufferTooShort) => {
                    trace!("{} Control stream blocked", conn.trace_id());
                    return Err(Error::InternalError);
                },

                Err(e) => return Err(e),
            }
        };

        self.control_stream_id = Some(stream_id);

        qlog_with_type!(QLOG_STREAM_TYPE_SET, conn.qlog, q, {
            let ev_data = EventData::Http3StreamTypeSet(StreamTypeSet {
                stream_id,
                initiator: Some(Initiator::Local),
                stream_type: StreamType::Control,
                ..Default::default()
            });

            q.add_event_data_now(ev_data).ok();
        });

        trace!(
            "{} tx frm {settings_frame:?} stream={stream_id} len={off}",
            conn.trace_id()
        );
        qlog_with_type!(QLOG_FRAME_CREATED, conn.qlog, q, {
            let frame = settings_frame.to_qlog();
            let ev_data = EventData::Http3FrameCreated(FrameCreated {
                stream_id,
                length: Some(off as u64),
                frame,
                ..Default::default()
            });

            q.add_event_data_now(ev_data).ok();
        });

        Ok(())
    }

    fn process_control_stream<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64,
    ) -> Result<(u64, Event)> {
        close_conn_if_critical_stream_finished(conn, stream_id)?;

        if !conn.stream_readable(stream_id) {
            return Err(Error::Done);
        }

        match self.process_readable_stream(conn, stream_id, true) {
            Ok(ev) => return Ok(ev),

            Err(Error::Done) => (),

            Err(e) => return Err(e),
        }

        close_conn_if_critical_stream_finished(conn, stream_id)?;

        Err(Error::Done)
    }

    /// Register a peer unidirectional stream after decoding its type.
    fn register_peer_stream<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64,
        ty: stream::Type,
    ) -> Result<()> {
        let (slot, duplicate_reason): (&mut Option<u64>, &[u8]) = match ty {
            stream::Type::Control => (
                &mut self.peer_control_stream_id,
                b"Received multiple control streams",
            ),
            stream::Type::QpackEncoder => (
                &mut self.peer_qpack_streams.encoder_stream_id,
                b"Received multiple QPACK encoder streams",
            ),
            stream::Type::QpackDecoder => (
                &mut self.peer_qpack_streams.decoder_stream_id,
                b"Received multiple QPACK decoder streams",
            ),
            stream::Type::Unknown => return Ok(()),
            stream::Type::Push | stream::Type::Request => {
                conn.close(
                    true,
                    Error::StreamCreationError.to_wire(),
                    b"Unexpected unidirectional stream type.",
                )?;
                return Err(Error::StreamCreationError);
            },
        };

        if slot.is_some() {
            conn.close(
                true,
                Error::StreamCreationError.to_wire(),
                duplicate_reason,
            )?;
            return Err(Error::StreamCreationError);
        }

        close_conn_if_critical_stream_finished(conn, stream_id)?;
        *slot = Some(stream_id);
        trace!(
            "{} opened peer critical stream {stream_id} {ty:?}",
            conn.trace_id()
        );

        Ok(())
    }

    fn process_readable_stream<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64, polling: bool,
    ) -> Result<(u64, Event)> {
        self.streams.entry(stream_id).or_insert_with(|| {
            <stream::Stream>::new(
                stream_id,
                false,
                self.local_settings
                    .max_field_section_size
                    .unwrap_or(SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT),
                self.max_priority_update_size,
            )
        });

        // We need to get a fresh reference to the stream for each
        // iteration, to avoid borrowing `self` for the entire duration
        // of the loop, because we'll need to borrow it again in the
        // `State::FramePayload` case below.
        while let Some(stream) = self.streams.get_mut(&stream_id) {
            match stream.state() {
                stream::State::StreamType => {
                    let varint = stream.read_varint(conn)?;

                    let ty = stream::Type::deserialize(varint);

                    if let Err(e) = stream.set_ty(ty) {
                        conn.close(true, e.to_wire(), b"")?;
                        return Err(e);
                    }

                    qlog_with_type!(QLOG_STREAM_TYPE_SET, conn.qlog, q, {
                        let ty_val = if matches!(ty, stream::Type::Unknown) {
                            Some(varint)
                        } else {
                            None
                        };

                        let ev_data =
                            EventData::Http3StreamTypeSet(StreamTypeSet {
                                stream_id,
                                initiator: Some(Initiator::Remote),
                                stream_type: ty.to_qlog(),
                                stream_type_bytes: ty_val,
                                ..Default::default()
                            });

                        q.add_event_data_now(ev_data).ok();
                    });

                    self.register_peer_stream(conn, stream_id, ty)?;
                },

                stream::State::PushId => {
                    let varint = stream.read_varint(conn)?;

                    if let Err(e) = stream.set_push_id(varint) {
                        conn.close(true, e.to_wire(), b"")?;
                        return Err(e);
                    }
                },

                stream::State::FrameType => {
                    let varint = stream.read_varint(conn)?;

                    match stream.set_frame_type(varint) {
                        Err(Error::FrameUnexpected) => {
                            let msg = format!("Unexpected frame type {varint}");

                            conn.close(
                                true,
                                Error::FrameUnexpected.to_wire(),
                                msg.as_bytes(),
                            )?;

                            return Err(Error::FrameUnexpected);
                        },

                        Err(e) => {
                            conn.close(
                                true,
                                e.to_wire(),
                                b"Error handling frame.",
                            )?;

                            return Err(e);
                        },

                        _ => (),
                    }
                },

                stream::State::FramePayloadLen => {
                    let payload_len = stream.read_varint(conn)?;

                    // DATA frames are handled uniquely. Log them here because
                    // DATA framing is no longer visible after this point.
                    if Some(frame::DATA_FRAME_TYPE_ID) == stream.frame_type() {
                        trace!(
                            "{} rx frm DATA stream={stream_id} wire_payload_len={payload_len}",
                            conn.trace_id()
                        );

                        qlog_with_type!(QLOG_FRAME_PARSED, conn.qlog, q, {
                            let frame = Http3Frame::Data { raw: None };

                            let ev_data =
                                EventData::Http3FrameParsed(FrameParsed {
                                    stream_id,
                                    length: Some(payload_len),
                                    frame,
                                    ..Default::default()
                                });

                            q.add_event_data_now(ev_data).ok();
                        });
                    }

                    let res = stream.set_frame_payload_len(payload_len);

                    if let Err(e) = res {
                        conn.close(true, e.to_wire(), b"")?;
                        return Err(e);
                    }
                },

                stream::State::FramePayload => {
                    // Do not emit events when not polling.
                    if !polling {
                        break;
                    }

                    stream.try_fill_buffer(conn)?;

                    let (frame, payload_len) = match stream.try_consume_frame() {
                        Ok(frame) => frame,

                        Err(Error::Done) => return Err(Error::Done),

                        Err(e) => {
                            conn.close(
                                true,
                                e.to_wire(),
                                b"Error handling frame.",
                            )?;

                            return Err(e);
                        },
                    };

                    match self.process_frame(conn, stream_id, frame, payload_len)
                    {
                        Ok(ev) => return Ok(ev),

                        Err(Error::Done) => {
                            // Internal frames do not produce events. Avoid
                            // reading again if QUIC marked the stream finished.
                            if conn.stream_finished(stream_id) {
                                break;
                            }
                        },

                        Err(e) => return Err(e),
                    }
                },

                stream::State::Data => {
                    // Do not emit events when not polling.
                    if !polling {
                        break;
                    }

                    if !stream.try_trigger_data_event() {
                        break;
                    }

                    return Ok((stream_id, Event::Data));
                },

                stream::State::QpackInstruction => {
                    let bytes = match stream.ty() {
                        Some(stream::Type::QpackEncoder) =>
                            &mut self.peer_qpack_streams.encoder_stream_bytes,
                        Some(stream::Type::QpackDecoder) =>
                            &mut self.peer_qpack_streams.decoder_stream_bytes,
                        _ => return Err(Error::InternalError),
                    };

                    // Dynamic table instructions are currently ignored.
                    // Discard directly from the receive buffer rather than
                    // copying them into an unused stack buffer.
                    loop {
                        let (recv, fin) =
                            conn.stream_discard(stream_id, usize::MAX)?;
                        *bytes = bytes.saturating_add(recv as u64);

                        if fin {
                            close_conn_critical_stream(conn)?;
                        }
                        if recv == 0 {
                            break;
                        }
                    }
                },

                stream::State::SkipFramePayload => {
                    stream.try_skip_frame(conn)?;

                    // Check whether the frame has FIN'd by QUIC to prevent
                    // trying to read again on a closed stream.
                    if conn.stream_finished(stream_id) {
                        break;
                    }
                },

                stream::State::Drain => {
                    // Discard incoming data on the stream.
                    conn.stream_shutdown(
                        stream_id,
                        crate::Shutdown::Read,
                        0x100,
                    )?;

                    break;
                },

                stream::State::Finished => break,
            }
        }

        Err(Error::Done)
    }

    fn process_finished_stream(&mut self, stream_id: u64) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };

        if stream.state() == stream::State::Finished {
            return;
        }

        match stream.ty() {
            Some(stream::Type::Request) | Some(stream::Type::Push) => {
                stream.finished();

                self.finished_streams.push_back(stream_id);
            },
            Some(stream::Type::Unknown) | None => {
                self.streams.remove(&stream_id);
            },
            // Closing any of the critical streams leads to connection close,
            // so there is no need for any cleanup actions here.
            Some(stream::Type::Control) |
            Some(stream::Type::QpackEncoder) |
            Some(stream::Type::QpackDecoder) => (),
        }
    }

    fn finish_local_stream<F: BufFactory>(
        &mut self, conn: &super::Connection<F>, stream_id: u64,
    ) {
        let hash_map::Entry::Occupied(mut stream) = self.streams.entry(stream_id)
        else {
            return;
        };

        stream.get_mut().finish_local();

        if conn.stream_finished(stream_id) {
            stream.remove();
        }
    }

    fn remove_finished_stream<F: BufFactory>(
        &mut self, conn: &super::Connection<F>, stream_id: u64,
    ) {
        if let hash_map::Entry::Occupied(stream) = self.streams.entry(stream_id) {
            if stream.get().local_finished() ||
                conn.streams.is_collected(stream_id)
            {
                stream.remove();
            }
        }
    }

    fn pop_finished_stream<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>,
    ) -> Option<(u64, Event)> {
        let finished = self.finished_streams.pop_front()?;

        self.remove_finished_stream(conn, finished);

        if conn.stream_readable(finished) {
            // The stream is finished, but is still readable, it may indicate
            // that there is a pending error, such as reset.
            if let Err(crate::Error::StreamReset(e)) =
                conn.stream_recv(finished, &mut [])
            {
                return Some((finished, Event::Reset(e)));
            }
        }

        Some((finished, Event::Finished))
    }

    fn process_frame<F: BufFactory>(
        &mut self, conn: &mut super::Connection<F>, stream_id: u64,
        frame: frame::Frame, payload_len: u64,
    ) -> Result<(u64, Event)> {
        trace!(
            "{} rx frm {frame:?} stream={stream_id} payload_len={payload_len}",
            conn.trace_id()
        );

        qlog_with_type!(QLOG_FRAME_PARSED, conn.qlog, q, {
            // HEADERS frames are special case and will be logged below.
            if !matches!(frame, frame::Frame::Headers { .. }) {
                let frame = frame.to_qlog();
                let ev_data = EventData::Http3FrameParsed(FrameParsed {
                    stream_id,
                    length: Some(payload_len),
                    frame,
                    ..Default::default()
                });

                q.add_event_data_now(ev_data).ok();
            }
        });

        match frame {
            frame::Frame::Settings {
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                connect_protocol_enabled,
                h3_datagram,
                additional_settings,
                raw,
                ..
            } => {
                if let Some(1) = h3_datagram {
                    // The peer MUST have also enabled DATAGRAM with a TP
                    if conn.dgram_max_writable_len().is_none() {
                        conn.close(
                            true,
                            Error::SettingsError.to_wire(),
                            b"H3_DATAGRAM sent with value 1 but max_datagram_frame_size TP not set.",
                        )?;

                        return Err(Error::SettingsError);
                    }
                }

                // A rejected SETTINGS frame must not expose negotiated
                // capabilities or a raw peer settings snapshot.
                self.peer_settings = ConnectionSettings {
                    max_field_section_size,
                    qpack_max_table_capacity,
                    qpack_blocked_streams,
                    connect_protocol_enabled,
                    h3_datagram,
                    additional_settings,
                    raw,
                };
            },

            frame::Frame::Headers { header_block } => {
                // Use "infinite" as default value for max_field_section_size if
                // it is not configured by the application.
                let max_size = self
                    .local_settings
                    .max_field_section_size
                    .unwrap_or(u64::MAX);

                let headers = match qpack::decode(&header_block, max_size) {
                    Ok(v) => v,

                    Err(e) => {
                        let e = match e {
                            qpack::Error::HeaderListTooLarge |
                            qpack::Error::AllocationFailed =>
                                Error::ExcessiveLoad,

                            _ => Error::QpackDecompressionFailed,
                        };

                        conn.close(true, e.to_wire(), b"Error parsing headers.")?;

                        return Err(e);
                    },
                };

                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.on_decoded_headers(&headers);
                }

                qlog_with_type!(QLOG_FRAME_PARSED, conn.qlog, q, {
                    let qlog_headers = headers
                        .iter()
                        .map(|h| qlog::events::http3::HttpHeader {
                            name: Some(
                                String::from_utf8_lossy(h.name()).into_owned(),
                            ),
                            name_bytes: None,
                            value: Some(
                                String::from_utf8_lossy(h.value()).into_owned(),
                            ),
                            value_bytes: None,
                        })
                        .collect();

                    let frame = Http3Frame::Headers {
                        headers: qlog_headers,
                        raw: None,
                    };

                    let ev_data = EventData::Http3FrameParsed(FrameParsed {
                        stream_id,
                        length: Some(payload_len),
                        frame,
                        ..Default::default()
                    });

                    q.add_event_data_now(ev_data).ok();
                });

                let more_frames = !conn.stream_finished(stream_id);

                return Ok((stream_id, Event::Headers {
                    list: headers,
                    more_frames,
                }));
            },

            frame::Frame::Data { .. } => {
                // Do nothing. The Data event is returned separately.
            },

            frame::Frame::GoAway { id } => {
                if !self.is_server && id % 4 != 0 {
                    conn.close(
                        true,
                        Error::IdError.to_wire(),
                        b"GOAWAY received with ID of non-request stream",
                    )?;

                    return Err(Error::IdError);
                }

                if let Some(received_id) = self.peer_goaway_id {
                    if id > received_id {
                        conn.close(
                            true,
                            Error::IdError.to_wire(),
                            b"GOAWAY received with ID larger than previously received",
                        )?;

                        return Err(Error::IdError);
                    }
                }

                self.peer_goaway_id = Some(id);

                return Ok((id, Event::GoAway));
            },

            frame::Frame::MaxPushId { push_id } => {
                if !self.is_server {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"MAX_PUSH_ID received by client",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                if push_id < self.max_push_id {
                    conn.close(
                        true,
                        Error::IdError.to_wire(),
                        b"MAX_PUSH_ID reduced limit",
                    )?;

                    return Err(Error::IdError);
                }

                self.max_push_id = push_id;
            },

            frame::Frame::PushPromise { .. } => {
                if self.is_server {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"PUSH_PROMISE received by server",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                if !stream_id.is_multiple_of(4) {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"PUSH_PROMISE received on non-request stream",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                // TODO: implement more checks and PUSH_PROMISE event
            },

            frame::Frame::CancelPush { .. } => {
                // TODO: implement CANCEL_PUSH frame
            },

            frame::Frame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => {
                if !self.is_server {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"PRIORITY_UPDATE received by client",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                if prioritized_element_id % 4 != 0 {
                    conn.close(
                        true,
                        Error::IdError.to_wire(),
                        b"PRIORITY_UPDATE for request stream type with wrong ID",
                    )?;

                    return Err(Error::IdError);
                }

                // MAX_STREAMS_BIDI is a count: the first forbidden request
                // stream ID is count * 4, not count * 4 + 4.
                if prioritized_element_id >= conn.streams.max_streams_bidi() * 4 {
                    conn.close(
                        true,
                        Error::IdError.to_wire(),
                        b"PRIORITY_UPDATE for request stream beyond max streams limit",
                    )?;

                    return Err(Error::IdError);
                }

                // PRIORITY_UPDATE can arrive before the request stream exists,
                // so a missing transport stream is allowed. Ignore updates only
                // once the transport stream was collected or both transport
                // directions are finished.
                if conn.stream_closed(prioritized_element_id) {
                    return Err(Error::Done);
                }

                // If the stream did not yet exist, create it and store.
                let stream = self
                    .streams
                    .entry(prioritized_element_id)
                    .or_insert_with(|| {
                        <stream::Stream>::new(
                            prioritized_element_id,
                            false,
                            self.local_settings.max_field_section_size.unwrap_or(
                                SETTINGS_MAX_FIELD_SECTION_SIZE_DEFAULT,
                            ),
                            self.max_priority_update_size,
                        )
                    });

                let had_priority_update = stream.has_last_priority_update();
                stream.set_last_priority_update(Some(priority_field_value));

                // Only trigger the event when there wasn't already a stored
                // PRIORITY_UPDATE.
                if !had_priority_update {
                    return Ok((prioritized_element_id, Event::PriorityUpdate));
                } else {
                    return Err(Error::Done);
                }
            },

            frame::Frame::PriorityUpdatePush { .. } => {
                if !self.is_server {
                    conn.close(
                        true,
                        Error::FrameUnexpected.to_wire(),
                        b"PRIORITY_UPDATE received by client",
                    )?;

                    return Err(Error::FrameUnexpected);
                }

                // This field is a push ID, not a QUIC stream ID. Server push
                // is not implemented, so no push IDs have been promised.
                // RFC 9218 requires H3_ID_ERROR for an unpromised push ID.
                conn.close(
                    true,
                    Error::IdError.to_wire(),
                    b"PRIORITY_UPDATE for an unpromised push ID",
                )?;
                return Err(Error::IdError);
            },

            frame::Frame::Unknown { .. } => (),
        }

        Err(Error::Done)
    }

    /// Collects and returns statistics about the connection.
    #[inline]
    #[must_use = "the returned snapshot contains connection statistics"]
    pub const fn stats(&self) -> Stats {
        Stats {
            qpack_encoder_stream_recv_bytes: self
                .peer_qpack_streams
                .encoder_stream_bytes,
            qpack_decoder_stream_recv_bytes: self
                .peer_qpack_streams
                .decoder_stream_bytes,
        }
    }
}

/// Generates an HTTP/3 GREASE variable length integer.
#[must_use = "the returned value is the generated reserved HTTP/3 integer"]
pub fn grease_value() -> u64 {
    let n = super::rand::rand_u64_uniform(148_764_065_110_560_899);
    31 * n + 33
}

/// Largest DATA payload fitting the available stream credit and the QUIC
/// varint domain. Each width contributes a candidate, including the gap
/// immediately before a length-field width increases.
fn data_payload_capacity(requested: usize, credit: usize) -> Option<usize> {
    [8_usize, 4, 2, 1].into_iter().find_map(|width| {
        let max = (1_u64 << (width * 8 - 2)) - 1;
        let payload = credit
            .checked_sub(1 + width)?
            .min(requested)
            .min(usize::try_from(max).unwrap_or(usize::MAX));
        (octets::varint_len(payload as u64) == width).then_some(payload)
    })
}

#[doc(hidden)]
#[cfg(any(test, feature = "internal"))]
pub mod testing {
    use super::*;

    use crate::test_utils;
    use crate::DefaultBufFactory;

    /// Session is an HTTP/3 test helper structure. It holds a client, server
    /// and pipe that allows them to communicate.
    ///
    /// `default()` creates a session with some sensible default
    /// configuration. `with_configs()` allows for providing a specific
    /// configuration.
    ///
    /// `handshake()` performs all the steps needed to establish an HTTP/3
    /// connection.
    ///
    /// Some utility functions are provided that make it less verbose to send
    /// request, responses and individual headers. The full quiche API remains
    /// available for any test that need to do unconventional things (such as
    /// bad behaviour that triggers errors).
    pub struct Session<F = DefaultBufFactory>
    where
        F: BufFactory,
    {
        pub pipe: test_utils::Pipe<F>,
        pub client: Connection,
        pub server: Connection,
    }

    #[cfg(test)]
    mod frame_encoding_tests {
        use super::*;

        #[test]
        fn test_frame_encoder_preserves_exact_65k_boundary() {
            // DATA uses one type byte and four length bytes here. Preserve
            // the old 65,535-byte test fixture bound without a stack array.
            let data = vec![0xa5; 65_530];
            let frame = frame::Frame::Data {
                payload: data.clone(),
            };
            let wire =
                Session::<DefaultBufFactory>::encode_test_frame(&frame).unwrap();
            assert_eq!(wire.len(), 65_535);
            let mut reader = octets::Octets::with_slice(&wire);
            assert_eq!(reader.get_varint().unwrap(), frame::DATA_FRAME_TYPE_ID);
            assert_eq!(reader.get_varint().unwrap(), data.len() as u64);
            assert_eq!(
                reader.get_bytes(data.len()).unwrap().as_ref(),
                data.as_slice()
            );

            let too_big = frame::Frame::Data {
                payload: vec![0; 65_531],
            };
            assert_eq!(
                Session::<DefaultBufFactory>::encode_test_frame(&too_big),
                Err(Error::BufferTooShort)
            );
        }
    }

    impl Session {
        pub fn new() -> Result<Self> {
            Self::new_with_buf()
        }

        pub fn with_configs(
            config: &mut crate::Config, h3_config: &Config,
        ) -> Result<Self> {
            Self::with_configs_and_buf(config, h3_config)
        }

        pub fn default_configs() -> Result<(crate::Config, Config)> {
            let mut config = test_utils::config_with_test_identity()?;
            config.set_application_protos(&[b"h3"])?;
            config.set_initial_max_data(1500);
            config.set_initial_max_stream_data_bidi_local(150);
            config.set_initial_max_stream_data_bidi_remote(150);
            config.set_initial_max_stream_data_uni(150);
            config.set_initial_max_streams_bidi(5);
            config.set_initial_max_streams_uni(5);
            config.verify_peer(false);
            config.enable_dgram(true, 3, 3);
            config.set_ack_delay_exponent(8);

            let h3_config = Config::new();
            Ok((config, h3_config))
        }
    }

    impl<F: BufFactory> Session<F> {
        /// Serialize a test frame without placing a maximum-size HTTP/3
        /// frame buffer on every caller's stack. Keep the existing fixture
        /// limit, so oversized frames still fail with BufferTooShort.
        fn encode_test_frame(frame: &frame::Frame) -> Result<Vec<u8>> {
            let mut data = vec![0; 65_535];
            let mut writer = octets::OctetsMut::with_slice(&mut data);
            let written = frame.to_bytes(&mut writer)?;
            data.truncate(written);
            Ok(data)
        }

        pub fn new_with_buf() -> Result<Self> {
            let (mut config, h3_config) = Session::default_configs()?;
            Self::with_configs_and_buf(&mut config, &h3_config)
        }

        pub fn with_configs_and_buf(
            config: &mut crate::Config, h3_config: &Config,
        ) -> Result<Self> {
            let pipe = test_utils::Pipe::with_config_and_buf(config)?;
            let client_dgram = pipe.client.dgram_enabled();
            let server_dgram = pipe.server.dgram_enabled();
            Ok(Self {
                pipe,
                client: Connection::new(h3_config, false, client_dgram),
                server: Connection::new(h3_config, true, server_dgram),
            })
        }

        /// Do the HTTP/3 handshake so both ends are in sane initial state.
        pub fn handshake(&mut self) -> Result<()> {
            self.pipe.handshake()?;

            // The two peers initialize their local streams in the same
            // order. Advance the transport after each stream to preserve
            // incremental flow-control and stream-count behavior.
            for is_client in [true, false] {
                if is_client {
                    self.client.send_settings(&mut self.pipe.client)?;
                } else {
                    self.server.send_settings(&mut self.pipe.server)?;
                }
                self.pipe.advance().ok();

                for kind in
                    [stream::Type::QpackEncoder, stream::Type::QpackDecoder]
                {
                    if is_client {
                        self.client
                            .open_qpack_stream(&mut self.pipe.client, kind)?;
                    } else {
                        self.server
                            .open_qpack_stream(&mut self.pipe.server, kind)?;
                    }
                    self.pipe.advance().ok();
                }

                if is_client && self.pipe.client.grease {
                    self.client.open_grease_stream(&mut self.pipe.client)?;
                } else if !is_client && self.pipe.server.grease {
                    self.server.open_grease_stream(&mut self.pipe.server)?;
                }
                self.pipe.advance().ok();
            }

            self.advance().ok();

            while self.client.poll(&mut self.pipe.client).is_ok() {
                // Do nothing.
            }

            while self.server.poll(&mut self.pipe.server).is_ok() {
                // Do nothing.
            }

            Ok(())
        }

        /// Advances the session pipe over the buffer.
        pub fn advance(&mut self) -> crate::Result<()> {
            self.pipe.advance()
        }

        /// Polls the client for events.
        pub fn poll_client(&mut self) -> Result<(u64, Event)> {
            self.client.poll(&mut self.pipe.client)
        }

        /// Polls the server for events.
        pub fn poll_server(&mut self) -> Result<(u64, Event)> {
            self.server.poll(&mut self.pipe.server)
        }

        /// Sends a request from client with default headers.
        ///
        /// On success it returns the newly allocated stream and the headers.
        pub fn send_request(&mut self, fin: bool) -> Result<(u64, Vec<Header>)> {
            let req = vec![
                Header::new(b":method", b"GET"),
                Header::new(b":scheme", b"https"),
                Header::new(b":authority", b"quic.tech"),
                Header::new(b":path", b"/test"),
                Header::new(b"user-agent", b"quiche-test"),
            ];

            let stream =
                self.client.send_request(&mut self.pipe.client, &req, fin)?;

            self.advance().ok();

            Ok((stream, req))
        }

        /// Sends a response from server with default headers.
        ///
        /// On success it returns the headers.
        pub fn send_response(
            &mut self, stream: u64, fin: bool,
        ) -> Result<Vec<Header>> {
            let resp = vec![
                Header::new(b":status", b"200"),
                Header::new(b"server", b"quiche-test"),
            ];

            self.server.send_response(
                &mut self.pipe.server,
                stream,
                &resp,
                fin,
            )?;

            self.advance().ok();

            Ok(resp)
        }

        /// Sends some default payload from client.
        ///
        /// On success it returns the payload.
        pub fn send_body_client(
            &mut self, stream: u64, fin: bool,
        ) -> Result<Vec<u8>> {
            let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

            self.client
                .send_body(&mut self.pipe.client, stream, &bytes, fin)?;

            self.advance().ok();

            Ok(bytes)
        }

        /// Fetches DATA payload from the server.
        ///
        /// On success it returns the number of bytes received.
        pub fn recv_body_client(
            &mut self, stream: u64, buf: &mut [u8],
        ) -> Result<usize> {
            self.client.recv_body(&mut self.pipe.client, stream, buf)
        }

        /// Fetches DATA payload from the server.
        ///
        /// On success it returns the number of bytes received.
        pub fn recv_body_buf_client<B: bytes::BufMut>(
            &mut self, stream: u64, buf: B,
        ) -> Result<usize> {
            self.client
                .recv_body_buf(&mut self.pipe.client, stream, buf)
        }

        /// Sends some default payload from server.
        ///
        /// On success it returns the payload.
        pub fn send_body_server(
            &mut self, stream: u64, fin: bool,
        ) -> Result<Vec<u8>> {
            let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

            self.server
                .send_body(&mut self.pipe.server, stream, &bytes, fin)?;

            self.advance().ok();

            Ok(bytes)
        }

        /// Fetches DATA payload from the client.
        ///
        /// On success it returns the number of bytes received.
        pub fn recv_body_server(
            &mut self, stream: u64, buf: &mut [u8],
        ) -> Result<usize> {
            self.server.recv_body(&mut self.pipe.server, stream, buf)
        }

        /// Fetches DATA payload from the client.
        ///
        /// On success it returns the number of bytes received.
        pub fn recv_body_buf_server<B: bytes::BufMut>(
            &mut self, stream: u64, buf: B,
        ) -> Result<usize> {
            self.server
                .recv_body_buf(&mut self.pipe.server, stream, buf)
        }

        /// Sends a single HTTP/3 frame from the client.
        pub fn send_frame_client(
            &mut self, frame: &frame::Frame, stream_id: u64, fin: bool,
        ) -> Result<()> {
            let data = Self::encode_test_frame(frame)?;
            self.pipe.client.stream_send(stream_id, &data, fin)?;

            self.advance().ok();

            Ok(())
        }

        /// Send an HTTP/3 DATAGRAM with default data from the client.
        ///
        /// On success it returns the data.
        pub fn send_dgram_client(&mut self, flow_id: u64) -> Result<Vec<u8>> {
            let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let len = octets::varint_len(flow_id) + bytes.len();
            let mut d = vec![0; len];
            let mut b = octets::OctetsMut::with_slice(&mut d);

            b.put_varint(flow_id)?;
            b.put_bytes(&bytes)?;

            self.pipe.client.dgram_send(&d)?;

            self.advance().ok();

            Ok(bytes)
        }

        /// Receives an HTTP/3 DATAGRAM from the server.
        ///
        /// On success it returns the DATAGRAM length, flow ID and flow ID
        /// length.
        pub fn recv_dgram_client(
            &mut self, buf: &mut [u8],
        ) -> Result<(usize, u64, usize)> {
            let len = self.pipe.client.dgram_recv(buf)?;
            let mut b = octets::Octets::with_slice(buf);
            let flow_id = b.get_varint()?;

            Ok((len, flow_id, b.off()))
        }

        /// Send an HTTP/3 DATAGRAM with default data from the server
        ///
        /// On success it returns the data.
        pub fn send_dgram_server(&mut self, flow_id: u64) -> Result<Vec<u8>> {
            let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let len = octets::varint_len(flow_id) + bytes.len();
            let mut d = vec![0; len];
            let mut b = octets::OctetsMut::with_slice(&mut d);

            b.put_varint(flow_id)?;
            b.put_bytes(&bytes)?;

            self.pipe.server.dgram_send(&d)?;

            self.advance().ok();

            Ok(bytes)
        }

        /// Receives an HTTP/3 DATAGRAM from the client.
        ///
        /// On success it returns the DATAGRAM length, flow ID and flow ID
        /// length.
        pub fn recv_dgram_server(
            &mut self, buf: &mut [u8],
        ) -> Result<(usize, u64, usize)> {
            let len = self.pipe.server.dgram_recv(buf)?;
            let mut b = octets::Octets::with_slice(buf);
            let flow_id = b.get_varint()?;

            Ok((len, flow_id, b.off()))
        }

        /// Sends a single HTTP/3 frame from the server.
        pub fn send_frame_server(
            &mut self, frame: &frame::Frame, stream_id: u64, fin: bool,
        ) -> Result<()> {
            let data = Self::encode_test_frame(frame)?;
            self.pipe.server.stream_send(stream_id, &data, fin)?;

            self.advance().ok();

            Ok(())
        }

        /// Sends an arbitrary buffer of HTTP/3 stream data from the client.
        pub fn send_arbitrary_stream_data_client(
            &mut self, data: &[u8], stream_id: u64, fin: bool,
        ) -> Result<()> {
            self.pipe.client.stream_send(stream_id, data, fin)?;

            self.advance().ok();

            Ok(())
        }

        /// Sends an arbitrary buffer of HTTP/3 stream data from the server.
        pub fn send_arbitrary_stream_data_server(
            &mut self, data: &[u8], stream_id: u64, fin: bool,
        ) -> Result<()> {
            self.pipe.server.stream_send(stream_id, data, fin)?;

            self.advance().ok();

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BufMut as _;

    use super::*;

    use super::testing::*;

    #[test]
    /// Make sure that random GREASE values is within the specified limit.
    fn grease_value_in_varint_limit() {
        assert!(grease_value() < 2u64.pow(62) - 1);
    }

    #[test]
    fn h3_handshake_0rtt() {
        let mut buf = [0; 65535];

        // Test drives the handshake one Initial at a time; requires a
        // single-Initial ClientHello.
        let mut config =
            crate::test_utils::config_no_pq(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config
            .set_application_protos(&[b"proto1", b"proto2"])
            .unwrap();
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(15);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.enable_early_data();
        config.verify_peer(false);

        let h3_config = Config::new();

        // Perform initial handshake.
        let mut pipe = crate::test_utils::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));

        // Extract session,
        let session = pipe.client.session().unwrap();

        // Configure session on new connection.
        let mut pipe = crate::test_utils::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.client.set_session(session), Ok(()));

        // Can't create an H3 connection until the QUIC connection is determined
        // to have made sufficient early data progress.
        assert!(matches!(
            Connection::with_transport(&mut pipe.client, &h3_config),
            Err(Error::InternalError)
        ));

        // Client sends initial flight.
        let (len, _) = pipe.client.send(&mut buf).unwrap();

        // Now an H3 connection can be created.
        assert!(Connection::with_transport(&mut pipe.client, &h3_config).is_ok());
        assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

        // Client sends 0-RTT packet.
        let pkt_type = crate::packet::Type::ZeroRTT;

        let frames = [crate::frame::Frame::Stream {
            stream_id: 6,
            data: <crate::range_buf::RangeBuf>::from(b"aaaaa", 0, true),
        }];

        assert_eq!(
            pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
            Ok(1200)
        );

        assert_eq!(pipe.server.undecryptable_pkts.len(), 0);

        // 0-RTT stream data is readable.
        let mut r = pipe.server.readable();
        assert_eq!(r.next(), Some(6));
        assert_eq!(r.next(), None);

        let mut b = [0; 15];
        assert_eq!(pipe.server.stream_recv(6, &mut b), Ok((5, true)));
        assert_eq!(&b[..5], b"aaaaa");
    }

    #[test]
    /// Send a request with no body, get a response with no body.
    fn request_no_body_response_no_body() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        assert_eq!(stream, 0);

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, true).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: false,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a request with no body, get a response with one DATA frame.
    fn request_no_body_response_one_chunk() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();
        assert_eq!(stream, 0);

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));

        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, false).unwrap();

        let body = s.send_body_server(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: true,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));

        assert_eq!(s.poll_client(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_client(stream, &mut recv_buf), Ok(body.len()));

        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a request with no body, get a response with multiple DATA frames.
    fn request_no_body_response_many_chunks() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let total_data_frames = 4;

        let resp = s.send_response(stream, false).unwrap();

        for _ in 0..total_data_frames - 1 {
            s.send_body_server(stream, false).unwrap();
        }

        let body = s.send_body_server(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: true,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Data)));
        assert_eq!(s.poll_client(), Err(Error::Done));

        for _ in 0..total_data_frames {
            assert_eq!(s.recv_body_client(stream, &mut recv_buf), Ok(body.len()));
        }

        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a request with no body, get a response with multiple DATA frames.
    fn request_no_body_response_many_chunks_with_buf() {
        let (mut config, h3_config) = Session::default_configs().unwrap();
        // we don't want to be limited by flow or cong. control
        config.set_initial_congestion_window_packets(100);
        config.set_initial_max_data(200_000);
        config.set_initial_max_stream_data_bidi_local(200_000);
        config.set_initial_max_stream_data_bidi_remote(200_000);
        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let total_data_frames = 4;

        // Use a large body
        let data = vec![0xab_u8; 16 * 1024];

        let resp = s.send_response(stream, false).unwrap();

        for _ in 0..total_data_frames - 1 {
            assert_eq!(
                s.server.send_body(&mut s.pipe.server, stream, &data, false),
                Ok(data.len())
            );
            s.advance().ok();
        }

        s.server
            .send_body(&mut s.pipe.server, stream, &data, true)
            .unwrap();
        s.advance().ok();

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: true,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Data)));
        assert_eq!(s.poll_client(), Err(Error::Done));

        // Reads may span multiple DATA frames and need not end at frame
        // boundaries. Read one and a half times the payload of one frame.
        let how_much_to_read_per_call = data.len() * 2 / 3;
        let mut remaining_to_read = total_data_frames * data.len();
        let mut recv_buf = Vec::new().limit(how_much_to_read_per_call);
        assert_eq!(
            s.recv_body_buf_client(stream, &mut recv_buf),
            Ok(how_much_to_read_per_call)
        );
        remaining_to_read -= how_much_to_read_per_call;
        assert_eq!(recv_buf.get_ref().len(), how_much_to_read_per_call);

        while remaining_to_read > 0 {
            // Set a different limit for the following reads.
            recv_buf.set_limit(data.len());
            // We should either read up to the limit we set above, or to
            // the end of buffered data.
            let expected = std::cmp::min(data.len(), remaining_to_read);
            assert_eq!(
                s.recv_body_buf_client(stream, &mut recv_buf),
                Ok(expected)
            );
            remaining_to_read -= expected;
        }
        // We've read everything now. Ensure the Vec reflects that
        assert_eq!(recv_buf.get_ref().len(), total_data_frames * data.len());

        // No more data to read.
        assert_eq!(
            s.recv_body_buf_client(stream, &mut recv_buf),
            Err(Error::Done)
        );

        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a request with one DATA frame, get a response with no body.
    fn request_one_chunk_response_no_body() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        let body = s.send_body_client(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));

        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));

        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, true).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: false,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
    }

    #[test]
    /// Send a request with multiple DATA frames, get a response with no body.
    fn request_many_chunks_response_no_body() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        let total_data_frames = 4;

        for _ in 0..total_data_frames - 1 {
            s.send_body_client(stream, false).unwrap();
        }

        let body = s.send_body_client(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        for _ in 0..total_data_frames {
            assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));
        }

        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, true).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: false,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
    }

    #[test]
    /// Send a request with multiple DATA frames, get a response with one DATA
    /// frame.
    fn many_requests_many_chunks_response_one_chunk() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let mut reqs = Vec::new();

        let (stream1, req1) = s.send_request(false).unwrap();
        assert_eq!(stream1, 0);
        reqs.push(req1);

        let (stream2, req2) = s.send_request(false).unwrap();
        assert_eq!(stream2, 4);
        reqs.push(req2);

        let (stream3, req3) = s.send_request(false).unwrap();
        assert_eq!(stream3, 8);
        reqs.push(req3);

        let body = s.send_body_client(stream1, false).unwrap();
        s.send_body_client(stream2, false).unwrap();
        s.send_body_client(stream3, false).unwrap();

        let mut recv_buf = vec![0; body.len()];

        // Reverse order of writes.

        s.send_body_client(stream3, true).unwrap();
        s.send_body_client(stream2, true).unwrap();
        s.send_body_client(stream1, true).unwrap();

        let (_, ev) = s.poll_server().unwrap();
        let ev_headers = Event::Headers {
            list: reqs[0].clone(),
            more_frames: true,
        };
        assert_eq!(ev, ev_headers);

        let (_, ev) = s.poll_server().unwrap();
        let ev_headers = Event::Headers {
            list: reqs[1].clone(),
            more_frames: true,
        };
        assert_eq!(ev, ev_headers);

        let (_, ev) = s.poll_server().unwrap();
        let ev_headers = Event::Headers {
            list: reqs[2].clone(),
            more_frames: true,
        };
        assert_eq!(ev, ev_headers);

        assert_eq!(s.poll_server(), Ok((0, Event::Data)));
        assert_eq!(s.recv_body_server(0, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_body_server(0, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.poll_server(), Ok((0, Event::Finished)));

        assert_eq!(s.poll_server(), Ok((4, Event::Data)));
        assert_eq!(s.recv_body_server(4, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_body_server(4, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.poll_server(), Ok((4, Event::Finished)));

        assert_eq!(s.poll_server(), Ok((8, Event::Data)));
        assert_eq!(s.recv_body_server(8, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_body_server(8, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.poll_server(), Ok((8, Event::Finished)));

        assert_eq!(s.poll_server(), Err(Error::Done));

        let mut resps = Vec::new();

        let resp1 = s.send_response(stream1, true).unwrap();
        resps.push(resp1);

        let resp2 = s.send_response(stream2, true).unwrap();
        resps.push(resp2);

        let resp3 = s.send_response(stream3, true).unwrap();
        resps.push(resp3);

        for _ in 0..resps.len() {
            let (stream, ev) = s.poll_client().unwrap();
            let ev_headers = Event::Headers {
                list: resps[(stream / 4) as usize].clone(),
                more_frames: false,
            };
            assert_eq!(ev, ev_headers);
            assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        }

        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a request with no body, get a response with one DATA frame and an
    /// empty FIN after reception from the client.
    fn request_no_body_response_one_chunk_empty_fin() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, false).unwrap();

        let body = s.send_body_server(stream, false).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: true,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));

        assert_eq!(s.poll_client(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_client(stream, &mut recv_buf), Ok(body.len()));

        assert_eq!(s.pipe.server.stream_send(stream, &[], true), Ok(0));
        s.advance().ok();

        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a request with no body, get a response with no body followed by
    /// GREASE that is STREAM frame with a FIN.
    fn request_no_body_response_no_body_with_grease() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        assert_eq!(stream, 0);

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let resp = s.send_response(stream, false).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: true,
        };

        // Inject a GREASE frame.
        let mut d = [42; 10];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame_type = b.put_varint(148_764_065_110_560_899).unwrap();
        s.pipe.server.stream_send(0, frame_type, false).unwrap();

        let frame_len = b.put_varint(10).unwrap();
        s.pipe.server.stream_send(0, frame_len, false).unwrap();

        s.pipe.server.stream_send(0, &d, true).unwrap();

        s.advance().ok();

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Try to send DATA frames before HEADERS.
    fn body_response_before_headers() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();
        assert_eq!(stream, 0);

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));

        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        assert_eq!(
            s.send_body_server(stream, true),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    /// DATA is invalid before a final response, even after informational
    /// HEADERS.
    fn received_data_before_final_response(#[case] informational: bool) {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, _) = s.send_request(true).unwrap();
        if informational {
            s.poll_server().unwrap();
            let headers = [Header::new(b":status", b"103")];
            s.server
                .send_response(&mut s.pipe.server, stream, &headers, false)
                .unwrap();
            s.advance().unwrap();
            assert!(matches!(s.poll_client(), Ok((_, Event::Headers { .. }))));
        }

        s.send_frame_server(
            &frame::Frame::Data { payload: vec![1] },
            stream,
            true,
        )
        .unwrap();
        assert_eq!(s.poll_client(), Err(Error::FrameUnexpected));
    }

    #[test]
    fn received_data_after_response_trailers_without_body() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();
        let (stream, _) = s.send_request(true).unwrap();
        s.poll_server().unwrap();
        let headers = [Header::new(b":status", b"200")];
        let trailers = [Header::new(b"foo", b"bar")];
        s.server
            .send_response(&mut s.pipe.server, stream, &headers, false)
            .unwrap();
        s.server
            .send_additional_headers(
                &mut s.pipe.server,
                stream,
                &trailers,
                true,
                false,
            )
            .unwrap();
        s.advance().unwrap();

        assert_eq!(
            s.poll_client(),
            Ok((stream, Event::Headers {
                list: headers.to_vec(),
                more_frames: true
            }))
        );
        assert_eq!(
            s.poll_client(),
            Ok((stream, Event::Headers {
                list: trailers.to_vec(),
                more_frames: true
            }))
        );
        s.send_frame_server(
            &frame::Frame::Data { payload: vec![1] },
            stream,
            true,
        )
        .unwrap();
        assert_eq!(s.poll_client(), Err(Error::FrameUnexpected));
    }

    #[test]
    /// Try to send DATA frames on wrong streams, ensure the API returns an
    /// error before anything hits the transport layer.
    fn send_body_invalid_client_stream() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        assert_eq!(s.send_body_client(0, true), Err(Error::FrameUnexpected));

        assert_eq!(
            s.send_body_client(s.client.control_stream_id.unwrap(), true),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_client(
                s.client.local_qpack_streams.encoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_client(
                s.client.local_qpack_streams.decoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_client(s.client.peer_control_stream_id.unwrap(), true),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_client(
                s.client.peer_qpack_streams.encoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_client(
                s.client.peer_qpack_streams.decoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );
    }

    #[test]
    /// Try to send DATA frames on wrong streams, ensure the API returns an
    /// error before anything hits the transport layer.
    fn send_body_invalid_server_stream() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        assert_eq!(s.send_body_server(0, true), Err(Error::FrameUnexpected));

        assert_eq!(
            s.send_body_server(s.server.control_stream_id.unwrap(), true),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_server(
                s.server.local_qpack_streams.encoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_server(
                s.server.local_qpack_streams.decoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_server(s.server.peer_control_stream_id.unwrap(), true),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_server(
                s.server.peer_qpack_streams.encoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );

        assert_eq!(
            s.send_body_server(
                s.server.peer_qpack_streams.decoder_stream_id.unwrap(),
                true
            ),
            Err(Error::FrameUnexpected)
        );
    }

    #[test]
    /// Client sends request with body and trailers.
    fn trailers() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        let body = s.send_body_client(stream, false).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let req_trailers = vec![Header::new(b"foo", b"bar")];

        s.client
            .send_additional_headers(
                &mut s.pipe.client,
                stream,
                &req_trailers,
                true,
                true,
            )
            .unwrap();

        s.advance().ok();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        let ev_trailers = Event::Headers {
            list: req_trailers,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));

        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));

        assert_eq!(s.poll_server(), Ok((stream, ev_trailers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));
    }

    #[test]
    /// Server responds with a 103, then a 200 with no body.
    fn informational_response() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        assert_eq!(stream, 0);

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let info_resp = vec![
            Header::new(b":status", b"103"),
            Header::new(b"link", b"<https://example.com>; rel=\"preconnect\""),
        ];

        let resp = vec![
            Header::new(b":status", b"200"),
            Header::new(b"server", b"quiche-test"),
        ];

        assert_eq!(
            s.server
                .send_response(&mut s.pipe.server, stream, &info_resp, true),
            Err(Error::FrameUnexpected)
        );

        s.server
            .send_response(&mut s.pipe.server, stream, &info_resp, false)
            .unwrap();

        assert_eq!(
            s.server
                .send_body(&mut s.pipe.server, stream, b"body", false),
            Err(Error::FrameUnexpected)
        );
        assert_eq!(
            s.server.send_additional_headers(
                &mut s.pipe.server,
                stream,
                &[Header::new(b"x-test", b"trailer")],
                true,
                false,
            ),
            Err(Error::FrameUnexpected)
        );
        assert_eq!(
            s.server.send_additional_headers(
                &mut s.pipe.server,
                stream,
                &info_resp,
                false,
                true
            ),
            Err(Error::FrameUnexpected)
        );

        s.server
            .send_additional_headers(
                &mut s.pipe.server,
                stream,
                &resp,
                false,
                true,
            )
            .unwrap();

        s.advance().ok();

        let ev_info_headers = Event::Headers {
            list: info_resp,
            more_frames: true,
        };

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: false,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_info_headers)));
        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Server responds with a 103, then attempts to send a 200 using
    /// send_response again, which should fail.
    fn no_multiple_response() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        assert_eq!(stream, 0);

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let info_resp = vec![
            Header::new(b":status", b"103"),
            Header::new(b"link", b"<https://example.com>; rel=\"preconnect\""),
        ];

        let resp = vec![
            Header::new(b":status", b"200"),
            Header::new(b"server", b"quiche-test"),
        ];

        s.server
            .send_response(&mut s.pipe.server, stream, &info_resp, false)
            .unwrap();

        assert_eq!(
            Err(Error::FrameUnexpected),
            s.server
                .send_response(&mut s.pipe.server, stream, &resp, true)
        );

        s.advance().ok();

        let ev_info_headers = Event::Headers {
            list: info_resp,
            more_frames: true,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_info_headers)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Server attempts to use send_additional_headers before initial response.
    fn no_send_additional_before_initial_response() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        assert_eq!(stream, 0);

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let info_resp = vec![
            Header::new(b":status", b"103"),
            Header::new(b"link", b"<https://example.com>; rel=\"preconnect\""),
        ];

        assert_eq!(
            Err(Error::FrameUnexpected),
            s.server.send_additional_headers(
                &mut s.pipe.server,
                stream,
                &info_resp,
                false,
                false
            )
        );

        s.advance().ok();

        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Client sends multiple HEADERS before data.
    fn additional_headers_before_data_client() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        let req_trailer = vec![Header::new(b"goodbye", b"world")];

        assert_eq!(
            s.client.send_additional_headers(
                &mut s.pipe.client,
                stream,
                &req_trailer,
                true,
                false
            ),
            Ok(())
        );

        s.advance().ok();

        let ev_initial_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        let ev_trailing_headers = Event::Headers {
            list: req_trailer,
            more_frames: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_initial_headers)));
        assert_eq!(s.poll_server(), Ok((stream, ev_trailing_headers)));
        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    /// Client sends multiple HEADERS before data.
    fn data_after_trailers_client(#[case] with_body: bool) {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        let body = if with_body {
            s.send_body_client(stream, false).unwrap()
        } else {
            Vec::new()
        };
        let mut recv_buf = vec![0; body.len()];

        let req_trailers = vec![Header::new(b"foo", b"bar")];

        s.client
            .send_additional_headers(
                &mut s.pipe.client,
                stream,
                &req_trailers,
                true,
                false,
            )
            .unwrap();

        s.advance().ok();

        s.send_frame_client(
            &frame::Frame::Data {
                payload: vec![1, 2, 3, 4],
            },
            stream,
            true,
        )
        .unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        let ev_trailers = Event::Headers {
            list: req_trailers,
            more_frames: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        if with_body {
            assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
            assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));
        }
        assert_eq!(s.poll_server(), Ok((stream, ev_trailers)));
        assert_eq!(s.poll_server(), Err(Error::FrameUnexpected));
    }

    #[rstest::rstest]
    #[case::max_push_id(frame::Frame::MaxPushId { push_id: 1 })]
    #[case::cancel_push(frame::Frame::CancelPush { push_id: 1 })]
    fn client_push_control_frame_on_control_stream(#[case] frame: frame::Frame) {
        let mut session = Session::new().unwrap();
        session.handshake().unwrap();
        let control = session.client.control_stream_id.unwrap();
        session.send_frame_client(&frame, control, false).unwrap();
        assert_eq!(session.poll_server(), Err(Error::Done));
    }

    #[rstest::rstest]
    #[case::max_push_id(frame::Frame::MaxPushId { push_id: 2 })]
    #[case::cancel_push(frame::Frame::CancelPush { push_id: 2 })]
    fn client_push_control_frame_on_request_stream(#[case] frame: frame::Frame) {
        let mut session = Session::new().unwrap();
        session.handshake().unwrap();
        let (stream_id, request) = session.send_request(false).unwrap();
        session.send_frame_client(&frame, stream_id, false).unwrap();
        assert_eq!(
            session.poll_server(),
            Ok((stream_id, Event::Headers {
                list: request,
                more_frames: true,
            }))
        );
        assert_eq!(session.poll_server(), Err(Error::FrameUnexpected));
    }

    #[test]
    /// Send a sequence of MAX_PUSH_ID frames from the client that attempt to
    /// reduce the limit.
    fn max_push_id_from_client_limit_reduction() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.send_frame_client(
            &frame::Frame::MaxPushId { push_id: 2 },
            s.client.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        s.send_frame_client(
            &frame::Frame::MaxPushId { push_id: 1 },
            s.client.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_server(), Err(Error::IdError));
    }

    #[test]
    /// Send a MAX_PUSH_ID frame from the server, which is forbidden.
    fn max_push_id_from_server() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.send_frame_server(
            &frame::Frame::MaxPushId { push_id: 1 },
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_client(), Err(Error::FrameUnexpected));
    }

    #[test]
    /// Send a PUSH_PROMISE frame from the client, which is forbidden.
    fn push_promise_from_client() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        let header_block = qpack::encode(&req).unwrap();

        s.send_frame_client(
            &frame::Frame::PushPromise {
                push_id: 1,
                header_block,
            },
            stream,
            false,
        )
        .unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Err(Error::FrameUnexpected));
    }

    #[test]
    /// Server push streams from client are not allowed by the protocol.
    fn push_stream_from_client() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.client
            .open_uni_stream(
                &mut s.pipe.client,
                stream::HTTP3_PUSH_STREAM_TYPE_ID,
                &[],
                false,
            )
            .unwrap();

        s.advance().ok();

        assert_eq!(s.poll_server(), Err(Error::StreamCreationError));
    }

    #[test]
    /// Server push streams from server are not allowed since the client does
    /// not advertise server push support by default.
    fn push_stream_from_server() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.server
            .open_uni_stream(
                &mut s.pipe.server,
                stream::HTTP3_PUSH_STREAM_TYPE_ID,
                &[],
                false,
            )
            .unwrap();

        s.advance().ok();

        assert_eq!(s.poll_client(), Err(Error::StreamCreationError));
    }

    #[test]
    /// Send a CANCEL_PUSH frame from the client.
    fn cancel_push_from_server() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.send_frame_server(
            &frame::Frame::CancelPush { push_id: 1 },
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send a GOAWAY frame from the client.
    fn goaway_from_client_good() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.client.send_goaway(&mut s.pipe.client, 100).unwrap();

        s.advance().ok();

        // TODO: server push
        assert_eq!(s.poll_server(), Ok((0, Event::GoAway)));
    }

    #[test]
    /// Send a GOAWAY frame from the server.
    fn goaway_from_server_good() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.server.send_goaway(&mut s.pipe.server, 4000).unwrap();

        s.advance().ok();

        assert_eq!(s.poll_client(), Ok((4000, Event::GoAway)));
    }

    #[test]
    /// A client MUST NOT send a request after it receives GOAWAY.
    fn client_request_after_goaway() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.server.send_goaway(&mut s.pipe.server, 4000).unwrap();

        s.advance().ok();

        assert_eq!(s.poll_client(), Ok((4000, Event::GoAway)));

        assert_eq!(s.send_request(true), Err(Error::FrameUnexpected));
    }

    #[test]
    /// Send a GOAWAY frame from the server, using an invalid goaway ID.
    fn goaway_from_server_invalid_id() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.send_frame_server(
            &frame::Frame::GoAway { id: 1 },
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_client(), Err(Error::IdError));
        assert_eq!(
            s.pipe.client.local_error().map(|err| err.error_code),
            Some(WireErrorCode::IdError as u64),
            "invalid GOAWAY stream ID must close with H3_ID_ERROR"
        );
        assert_eq!(s.client.peer_goaway_id, None);
    }

    #[test]
    /// Send a GOAWAY frame from the server with extra bytes after the ID.
    fn goaway_from_server_trailing_bytes() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        // GOAWAY (type 0x7) with a 3-byte payload: ID 0, then 2 extra bytes.
        s.send_arbitrary_stream_data_server(
            &[0x07, 0x03, 0x00, 0xaa, 0xbb],
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_client(), Err(Error::FrameError));
    }

    #[test]
    /// Send multiple GOAWAY frames from the server, that increase the goaway
    /// ID.
    fn goaway_from_server_increase_id() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.send_frame_server(
            &frame::Frame::GoAway { id: 0 },
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        s.send_frame_server(
            &frame::Frame::GoAway { id: 4 },
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_client(), Ok((0, Event::GoAway)));

        assert_eq!(s.poll_client(), Err(Error::IdError));
    }

    #[test]
    #[cfg(feature = "sfv")]
    fn parse_priority_field_value() {
        // Legal dicts
        assert_eq!(
            Ok(Priority::new(0, false)),
            Priority::try_from(b"u=0".as_slice())
        );
        assert_eq!(
            Ok(Priority::new(3, false)),
            Priority::try_from(b"u=3".as_slice())
        );
        assert_eq!(
            Ok(Priority::new(7, false)),
            Priority::try_from(b"u=7".as_slice())
        );

        assert_eq!(
            Ok(Priority::new(0, true)),
            Priority::try_from(b"u=0, i".as_slice())
        );
        assert_eq!(
            Ok(Priority::new(3, true)),
            Priority::try_from(b"u=3, i".as_slice())
        );
        assert_eq!(
            Ok(Priority::new(7, true)),
            Priority::try_from(b"u=7, i".as_slice())
        );

        assert_eq!(
            Ok(Priority::new(0, true)),
            Priority::try_from(b"u=0, i=?1".as_slice())
        );
        assert_eq!(
            Ok(Priority::new(3, true)),
            Priority::try_from(b"u=3, i=?1".as_slice())
        );
        assert_eq!(
            Ok(Priority::new(7, true)),
            Priority::try_from(b"u=7, i=?1".as_slice())
        );

        assert_eq!(
            Ok(Priority::new(3, false)),
            Priority::try_from(b"".as_slice())
        );

        assert_eq!(
            Ok(Priority::new(0, true)),
            Priority::try_from(b"u=0;foo, i;bar".as_slice())
        );
        assert_eq!(
            Ok(Priority::new(3, true)),
            Priority::try_from(b"u=3;hello, i;world".as_slice())
        );
        assert_eq!(
            Ok(Priority::new(7, true)),
            Priority::try_from(b"u=7;croeso, i;gymru".as_slice())
        );

        assert_eq!(
            Ok(Priority::new(0, true)),
            Priority::try_from(b"u=0, i, spinaltap=11".as_slice())
        );

        // Illegal formats
        assert_eq!(Err(Error::Done), Priority::try_from(b"0".as_slice()));
        assert_eq!(
            Ok(Priority::new(7, false)),
            Priority::try_from(b"u=-1".as_slice())
        );
        assert_eq!(Err(Error::Done), Priority::try_from(b"u=0.2".as_slice()));
        assert_eq!(
            Ok(Priority::new(7, false)),
            Priority::try_from(b"u=100".as_slice())
        );
        assert_eq!(
            Err(Error::Done),
            Priority::try_from(b"u=3, i=true".as_slice())
        );

        // Trailing comma in dict is malformed
        assert_eq!(Err(Error::Done), Priority::try_from(b"u=7, ".as_slice()));
    }

    #[test]
    /// Send a PRIORITY_UPDATE for request stream from the client.
    fn priority_update_request() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.client
            .send_priority_update_for_request(&mut s.pipe.client, 0, Priority {
                urgency: 3,
                incremental: false,
            })
            .unwrap();
        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((0, Event::PriorityUpdate)));
        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[test]
    /// Send a PRIORITY_UPDATE for request stream from the client that is too
    /// large.
    fn priority_update_request_max_size_limit_default() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(1500);
        config.set_initial_max_stream_data_bidi_local(1500);
        config.set_initial_max_stream_data_bidi_remote(1500);
        config.set_initial_max_stream_data_uni(1500);
        config.set_initial_max_streams_bidi(5);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let h3_config = Config::new();

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        s.handshake().unwrap();

        let mut d = vec![42; 600];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let pu = frame::Frame::PriorityUpdateRequest {
            prioritized_element_id: 0,
            priority_field_value: vec![0; 512],
        };

        pu.to_bytes(&mut b).unwrap();

        s.pipe.client.stream_send(2, &d, true).unwrap();

        s.advance().ok();

        assert_eq!(s.poll_server(), Err(Error::ExcessiveLoad));

        assert_eq!(
            s.pipe.server.local_error.as_ref().unwrap().error_code,
            Error::to_wire(Error::ExcessiveLoad)
        );
    }

    #[test]
    /// Send a PRIORITY_UPDATE for request stream from the client.
    fn priority_update_single_stream_rearm() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.client
            .send_priority_update_for_request(&mut s.pipe.client, 0, Priority {
                urgency: 3,
                incremental: false,
            })
            .unwrap();
        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((0, Event::PriorityUpdate)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        s.client
            .send_priority_update_for_request(&mut s.pipe.client, 0, Priority {
                urgency: 5,
                incremental: false,
            })
            .unwrap();
        s.advance().ok();

        assert_eq!(s.poll_server(), Err(Error::Done));

        // There is only one PRIORITY_UPDATE frame to read. Once read, the event
        // will rearm ready for more.
        assert_eq!(s.server.take_last_priority_update(0), Ok(b"u=5".to_vec()));
        assert_eq!(s.server.take_last_priority_update(0), Err(Error::Done));

        s.client
            .send_priority_update_for_request(&mut s.pipe.client, 0, Priority {
                urgency: 7,
                incremental: false,
            })
            .unwrap();
        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((0, Event::PriorityUpdate)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.server.take_last_priority_update(0), Ok(b"u=7".to_vec()));
        assert_eq!(s.server.take_last_priority_update(0), Err(Error::Done));
    }

    #[test]
    /// Send multiple PRIORITY_UPDATE frames for different streams from the
    /// client across multiple flights of exchange.
    fn priority_update_request_multiple_stream_arm_multiple_flights() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.client
            .send_priority_update_for_request(&mut s.pipe.client, 0, Priority {
                urgency: 3,
                incremental: false,
            })
            .unwrap();
        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((0, Event::PriorityUpdate)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        s.client
            .send_priority_update_for_request(&mut s.pipe.client, 4, Priority {
                urgency: 1,
                incremental: false,
            })
            .unwrap();
        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((4, Event::PriorityUpdate)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        s.client
            .send_priority_update_for_request(&mut s.pipe.client, 8, Priority {
                urgency: 2,
                incremental: false,
            })
            .unwrap();
        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((8, Event::PriorityUpdate)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.server.take_last_priority_update(0), Ok(b"u=3".to_vec()));
        assert_eq!(s.server.take_last_priority_update(4), Ok(b"u=1".to_vec()));
        assert_eq!(s.server.take_last_priority_update(8), Ok(b"u=2".to_vec()));
        assert_eq!(s.server.take_last_priority_update(0), Err(Error::Done));
    }

    #[test]
    /// Send multiple PRIORITY_UPDATE frames for different streams from the
    /// client across a single flight.
    fn priority_update_request_multiple_stream_arm_single_flight() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let mut d = [42; 65535];

        let mut b = octets::OctetsMut::with_slice(&mut d);

        let p1 = frame::Frame::PriorityUpdateRequest {
            prioritized_element_id: 0,
            priority_field_value: b"u=3".to_vec(),
        };

        let p2 = frame::Frame::PriorityUpdateRequest {
            prioritized_element_id: 4,
            priority_field_value: b"u=3".to_vec(),
        };

        let p3 = frame::Frame::PriorityUpdateRequest {
            prioritized_element_id: 8,
            priority_field_value: b"u=3".to_vec(),
        };

        p1.to_bytes(&mut b).unwrap();
        p2.to_bytes(&mut b).unwrap();
        p3.to_bytes(&mut b).unwrap();

        let off = b.off();
        s.pipe
            .client
            .stream_send(s.client.control_stream_id.unwrap(), &d[..off], false)
            .unwrap();

        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((0, Event::PriorityUpdate)));
        assert_eq!(s.poll_server(), Ok((4, Event::PriorityUpdate)));
        assert_eq!(s.poll_server(), Ok((8, Event::PriorityUpdate)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.server.take_last_priority_update(0), Ok(b"u=3".to_vec()));
        assert_eq!(s.server.take_last_priority_update(4), Ok(b"u=3".to_vec()));
        assert_eq!(s.server.take_last_priority_update(8), Ok(b"u=3".to_vec()));

        assert_eq!(s.server.take_last_priority_update(0), Err(Error::Done));
    }

    #[test]
    /// Send a PRIORITY_UPDATE for a request stream, before and after the stream
    /// has been completed.
    fn priority_update_request_collected_completed() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.client
            .send_priority_update_for_request(&mut s.pipe.client, 0, Priority {
                urgency: 3,
                incremental: false,
            })
            .unwrap();
        s.advance().ok();

        let (stream, req) = s.send_request(true).unwrap();
        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        // Priority event is generated before request headers.
        assert_eq!(s.poll_server(), Ok((0, Event::PriorityUpdate)));
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.server.take_last_priority_update(0), Ok(b"u=3".to_vec()));
        assert_eq!(s.server.take_last_priority_update(0), Err(Error::Done));

        let resp = s.send_response(stream, true).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: false,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));

        // Now send a PRIORITY_UPDATE for the completed request stream.
        s.client
            .send_priority_update_for_request(&mut s.pipe.client, 0, Priority {
                urgency: 3,
                incremental: false,
            })
            .unwrap();
        s.advance().ok();

        // No event generated at server
        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[test]
    /// Send a PRIORITY_UPDATE for a request stream after H3 has collected it,
    /// but before the transport stream has been collected.
    fn priority_update_request_after_h3_collection() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let init_streams_server = s.server.streams.len();

        let (stream, req) = s.send_request(true).unwrap();
        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        let resp = vec![
            Header::new(b":status", b"200"),
            Header::new(b"server", b"quiche-test"),
        ];

        s.server
            .send_response(&mut s.pipe.server, stream, &resp, true)
            .unwrap();

        // H3 no longer needs its stream state once it has sent the response
        // FIN and consumed the request FIN. The QUIC stream remains until the
        // response FIN is acknowledged by the peer.
        assert_eq!(s.server.streams.len(), init_streams_server);
        assert!(s.pipe.server.stream_finished(stream));
        assert!(s.pipe.server.stream_closed(stream));

        let stream_state = s.pipe.server.streams.get(stream).unwrap();
        assert!(stream_state.recv.is_fin());
        assert!(stream_state.send.is_fin());
        assert!(!s.pipe.server.streams.is_collected(stream));

        s.client
            .send_priority_update_for_request(
                &mut s.pipe.client,
                stream,
                Priority {
                    urgency: 3,
                    incremental: false,
                },
            )
            .unwrap();

        let flight = crate::test_utils::emit_flight(&mut s.pipe.client).unwrap();
        crate::test_utils::process_flight(&mut s.pipe.server, flight).unwrap();

        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.server.streams.len(), init_streams_server);
    }

    #[test]
    /// Send a PRIORITY_UPDATE for a request stream, before and after the stream
    /// has been stopped.
    fn priority_update_request_collected_stopped() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.client
            .send_priority_update_for_request(&mut s.pipe.client, 0, Priority {
                urgency: 3,
                incremental: false,
            })
            .unwrap();
        s.advance().ok();

        let (stream, req) = s.send_request(false).unwrap();
        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        // Priority event is generated before request headers.
        assert_eq!(s.poll_server(), Ok((0, Event::PriorityUpdate)));
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.server.take_last_priority_update(0), Ok(b"u=3".to_vec()));
        assert_eq!(s.server.take_last_priority_update(0), Err(Error::Done));

        s.pipe
            .client
            .stream_shutdown(stream, crate::Shutdown::Write, 0x100)
            .unwrap();
        s.pipe
            .client
            .stream_shutdown(stream, crate::Shutdown::Read, 0x100)
            .unwrap();

        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((0, Event::Reset(0x100))));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Now send a PRIORITY_UPDATE for the closed request stream.
        s.client
            .send_priority_update_for_request(&mut s.pipe.client, 0, Priority {
                urgency: 3,
                incremental: false,
            })
            .unwrap();
        s.advance().ok();

        // No event generated at server
        assert_eq!(s.poll_server(), Err(Error::Done));

        // The receive-side reset does not consume the STOP error.
        assert!(!s.pipe.server.streams.is_collected(0));
        assert_eq!(
            s.pipe.server.stream_capacity(0),
            Err(crate::Error::StreamStopped(0x100))
        );
        assert!(s.pipe.server.streams.is_collected(0));
        assert!(s.pipe.client.streams.is_collected(0));
    }

    /// RFC 9218 requires H3_ID_ERROR for a non-request stream ID in a
    /// request priority update or an unpromised push ID in a push update.
    /// Push IDs are not QUIC stream IDs, so they have no stream-type bits.
    #[rstest::rstest]
    #[case::server_bidi(1, false, false)]
    #[case::client_uni(2, false, false)]
    #[case::server_uni(3, false, false)]
    #[case::server_bidi_later(5, false, false)]
    #[case::first_request_beyond_limit(20, false, false)]
    #[case::push_zero(0, true, false)]
    #[case::push_one(1, true, false)]
    #[case::push_three(3, true, false)]
    #[case::push_five(5, true, false)]
    #[case::unpromised_push_within_limit(1, true, true)]
    fn priority_update_rejects_invalid_id(
        #[case] id: u64, #[case] push: bool, #[case] raise_push_limit: bool,
    ) {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();
        let control = s.client.control_stream_id.unwrap();
        if raise_push_limit {
            // MAX_PUSH_ID is only permission to promise pushes: no push was
            // actually promised by the server, so id=1 is still invalid.
            s.send_frame_client(
                &frame::Frame::MaxPushId { push_id: 10 },
                control,
                false,
            )
            .unwrap();
            assert_eq!(s.poll_server(), Err(Error::Done));
        }

        let priority_field_value = b"u=3".to_vec();
        let frame = if push {
            frame::Frame::PriorityUpdatePush {
                prioritized_element_id: id,
                priority_field_value,
            }
        } else {
            frame::Frame::PriorityUpdateRequest {
                prioritized_element_id: id,
                priority_field_value,
            }
        };
        s.send_frame_client(&frame, control, false).unwrap();
        assert_eq!(s.poll_server(), Err(Error::IdError));
        assert_eq!(
            s.pipe.server.local_error().map(|err| err.error_code),
            Some(WireErrorCode::IdError as u64)
        );
    }

    #[test]
    /// Send a PRIORITY_UPDATE for request stream from the server.
    fn priority_update_request_from_server() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.send_frame_server(
            &frame::Frame::PriorityUpdateRequest {
                prioritized_element_id: 0,
                priority_field_value: b"u=3".to_vec(),
            },
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_client(), Err(Error::FrameUnexpected));
    }

    #[test]
    /// Send a PRIORITY_UPDATE for request stream from the server.
    fn priority_update_push_from_server() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.send_frame_server(
            &frame::Frame::PriorityUpdatePush {
                prioritized_element_id: 0,
                priority_field_value: b"u=3".to_vec(),
            },
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.poll_client(), Err(Error::FrameUnexpected));
    }

    #[test]
    /// Ensure quiche allocates streams for client and server roles as expected.
    fn uni_stream_local_counting() {
        let config = Config::new();

        let h3_cln = Connection::new(&config, false, false);
        assert_eq!(h3_cln.next_uni_stream_id, 2);

        let h3_srv = Connection::new(&config, true, false);
        assert_eq!(h3_srv.next_uni_stream_id, 3);
    }

    #[test]
    fn uni_stream_preface_and_fin_are_atomic_at_every_varint_width() {
        for ty in [33, 64, 1 << 14, 1 << 30] {
            let prefix = octets::EncodedVarint::new(ty).unwrap();
            let credit = prefix.as_ref().len() + 3;
            let (mut config, h3_config) = Session::default_configs().unwrap();
            config.grease(false);
            config.set_initial_max_stream_data_uni(credit as u64);
            let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
            s.pipe.handshake().unwrap();

            let id = s.client.next_uni_stream_id;
            assert_eq!(
                s.client
                    .open_uni_stream(&mut s.pipe.client, ty, b"four", true),
                Err(Error::Done),
            );
            assert_eq!(s.client.next_uni_stream_id, id);
            assert_eq!(s.pipe.client.stream_capacity(id), Ok(credit));

            assert_eq!(
                s.client
                    .open_uni_stream(&mut s.pipe.client, ty, b"abc", true),
                Ok(id),
            );
            assert_eq!(s.client.next_uni_stream_id, id + 4);
            s.pipe.advance().unwrap();

            let mut out = [0; 11];
            let (len, fin) = s.pipe.server.stream_recv(id, &mut out).unwrap();
            assert_eq!(len, credit);
            assert!(fin);
            assert_eq!(&out[..prefix.as_ref().len()], prefix.as_ref());
            assert_eq!(&out[prefix.as_ref().len()..len], b"abc");
        }
    }

    #[rstest::rstest]
    #[case(stream::HTTP3_CONTROL_STREAM_TYPE_ID)]
    #[case(stream::QPACK_ENCODER_STREAM_TYPE_ID)]
    #[case(stream::QPACK_DECODER_STREAM_TYPE_ID)]
    /// Client duplicates a critical stream, which is forbidden.
    fn open_multiple_critical_streams(#[case] ty: u64) {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let stream_id = s.client.next_uni_stream_id;

        let mut d = [42; 8];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        s.pipe
            .client
            .stream_send(stream_id, b.put_varint(ty).unwrap(), false)
            .unwrap();

        s.advance().ok();

        assert_eq!(s.poll_server(), Err(Error::StreamCreationError));
    }

    #[test]
    /// Client closes the control stream, which is forbidden.
    fn close_control_stream_after_type() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.pipe
            .client
            .stream_send(s.client.control_stream_id.unwrap(), &[], true)
            .unwrap();

        s.advance().ok();

        assert_eq!(
            Err(Error::ClosedCriticalStream),
            s.server.poll(&mut s.pipe.server)
        );
        assert_eq!(Err(Error::Done), s.server.poll(&mut s.pipe.server));
    }

    #[test]
    /// Client closes the control stream after a frame is sent, which is
    /// forbidden.
    fn close_control_stream_after_frame() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.send_frame_client(
            &frame::Frame::MaxPushId { push_id: 1 },
            s.client.control_stream_id.unwrap(),
            true,
        )
        .unwrap();

        assert_eq!(
            Err(Error::ClosedCriticalStream),
            s.server.poll(&mut s.pipe.server)
        );
        assert_eq!(Err(Error::Done), s.server.poll(&mut s.pipe.server));
    }

    #[test]
    /// Client resets the control stream, which is forbidden.
    fn reset_control_stream_after_type() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.pipe
            .client
            .stream_shutdown(
                s.client.control_stream_id.unwrap(),
                crate::Shutdown::Write,
                0,
            )
            .unwrap();

        s.advance().ok();

        assert_eq!(
            Err(Error::ClosedCriticalStream),
            s.server.poll(&mut s.pipe.server)
        );
        assert_eq!(Err(Error::Done), s.server.poll(&mut s.pipe.server));
    }

    #[test]
    /// Client resets the control stream after a frame is sent, which is
    /// forbidden.
    fn reset_control_stream_after_frame() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.send_frame_client(
            &frame::Frame::MaxPushId { push_id: 1 },
            s.client.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(Err(Error::Done), s.server.poll(&mut s.pipe.server));

        s.pipe
            .client
            .stream_shutdown(
                s.client.control_stream_id.unwrap(),
                crate::Shutdown::Write,
                0,
            )
            .unwrap();

        s.advance().ok();

        assert_eq!(
            Err(Error::ClosedCriticalStream),
            s.server.poll(&mut s.pipe.server)
        );
        assert_eq!(Err(Error::Done), s.server.poll(&mut s.pipe.server));
    }

    #[test]
    /// Client closes QPACK stream, which is forbidden.
    fn close_qpack_stream_after_type() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.pipe
            .client
            .stream_send(
                s.client.local_qpack_streams.encoder_stream_id.unwrap(),
                &[],
                true,
            )
            .unwrap();

        s.advance().ok();

        assert_eq!(
            Err(Error::ClosedCriticalStream),
            s.server.poll(&mut s.pipe.server)
        );
        assert_eq!(Err(Error::Done), s.server.poll(&mut s.pipe.server));
    }

    #[test]
    /// Client closes QPACK stream after sending some stuff, which is forbidden.
    fn close_qpack_stream_after_data() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let stream_id = s.client.local_qpack_streams.encoder_stream_id.unwrap();
        let d = [0; 1];

        s.pipe.client.stream_send(stream_id, &d, false).unwrap();
        s.pipe.client.stream_send(stream_id, &d, true).unwrap();

        s.advance().ok();

        assert_eq!(
            Err(Error::ClosedCriticalStream),
            s.server.poll(&mut s.pipe.server)
        );
        assert_eq!(Err(Error::Done), s.server.poll(&mut s.pipe.server));
    }

    #[test]
    /// Client resets QPACK stream, which is forbidden.
    fn reset_qpack_stream_after_type() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        s.pipe
            .client
            .stream_shutdown(
                s.client.local_qpack_streams.encoder_stream_id.unwrap(),
                crate::Shutdown::Write,
                0,
            )
            .unwrap();

        s.advance().ok();

        assert_eq!(
            Err(Error::ClosedCriticalStream),
            s.server.poll(&mut s.pipe.server)
        );
        assert_eq!(Err(Error::Done), s.server.poll(&mut s.pipe.server));
    }

    #[test]
    /// Client resets QPACK stream after sending some stuff, which is forbidden.
    fn reset_qpack_stream_after_data() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let stream_id = s.client.local_qpack_streams.encoder_stream_id.unwrap();
        let d = [0; 1];

        s.pipe.client.stream_send(stream_id, &d, false).unwrap();
        s.pipe.client.stream_send(stream_id, &d, false).unwrap();

        s.advance().ok();

        assert_eq!(Err(Error::Done), s.server.poll(&mut s.pipe.server));

        s.pipe
            .client
            .stream_shutdown(stream_id, crate::Shutdown::Write, 0)
            .unwrap();

        s.advance().ok();

        assert_eq!(
            Err(Error::ClosedCriticalStream),
            s.server.poll(&mut s.pipe.server)
        );
        assert_eq!(Err(Error::Done), s.server.poll(&mut s.pipe.server));
    }

    #[test]
    /// QPACK bytes are accounted for even when discarded across QUIC packets.
    fn qpack_data() {
        // Dynamic table instructions are currently ignored.
        let (mut config, h3_config) = Session::default_configs().unwrap();
        config.set_initial_max_data(100_000);
        config.set_initial_max_stream_data_uni(40_000);
        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
        s.handshake().unwrap();

        let encoder = s.client.local_qpack_streams.encoder_stream_id.unwrap();
        let decoder = s.client.local_qpack_streams.decoder_stream_id.unwrap();

        // Larger than the former discard scratch buffer.
        let data = vec![0; 8192];
        for stream_id in [encoder, decoder] {
            for _ in 0..2 {
                assert_eq!(
                    s.pipe.client.stream_send(stream_id, &data, false),
                    Ok(data.len()),
                );
                s.advance().unwrap();
                assert_eq!(s.server.poll(&mut s.pipe.server), Err(Error::Done));
            }
        }

        let stats = s.server.stats();
        assert_eq!(stats.qpack_encoder_stream_recv_bytes, 16384);
        assert_eq!(stats.qpack_decoder_stream_recv_bytes, 16384);
    }

    #[test]
    /// Tests limits for the stream state buffer maximum size.
    fn max_state_buf_size() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let req = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"quic.tech"),
            Header::new(b":path", b"/test"),
            Header::new(b"user-agent", b"quiche-test"),
        ];

        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, false),
            Ok(0)
        );

        s.advance().ok();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        assert_eq!(s.server.poll(&mut s.pipe.server), Ok((0, ev_headers)));

        // DATA frames don't consume the state buffer, so can be of any size.
        let mut d = [42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame_type = b.put_varint(frame::DATA_FRAME_TYPE_ID).unwrap();
        s.pipe.client.stream_send(0, frame_type, false).unwrap();

        let frame_len = b.put_varint(1 << 24).unwrap();
        s.pipe.client.stream_send(0, frame_len, false).unwrap();

        s.pipe.client.stream_send(0, &d, false).unwrap();

        s.advance().ok();

        assert_eq!(s.server.poll(&mut s.pipe.server), Ok((0, Event::Data)));

        // GREASE frames consume the state buffer, so need to be limited.
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let mut d = [42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame_type = b.put_varint(148_764_065_110_560_899).unwrap();
        s.pipe.client.stream_send(0, frame_type, false).unwrap();

        let frame_len = b.put_varint(1 << 24).unwrap();
        s.pipe.client.stream_send(0, frame_len, false).unwrap();

        s.pipe.client.stream_send(0, &d, false).unwrap();

        s.advance().ok();

        assert_eq!(s.server.poll(&mut s.pipe.server), Err(Error::ExcessiveLoad));
    }

    #[test]
    /// Tests that DATA frames are properly truncated depending on the request
    /// stream's outgoing flow control capacity.
    fn stream_backpressure() {
        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        let total_data_frames = 6;

        for _ in 0..total_data_frames {
            assert_eq!(
                s.client
                    .send_body(&mut s.pipe.client, stream, &bytes, false),
                Ok(bytes.len())
            );

            s.advance().ok();
        }

        assert_eq!(
            s.client.send_body(&mut s.pipe.client, stream, &bytes, true),
            Ok(bytes.len() - 2)
        );

        s.advance().ok();

        let mut recv_buf = vec![0; bytes.len()];

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        for _ in 0..total_data_frames {
            assert_eq!(
                s.recv_body_server(stream, &mut recv_buf),
                Ok(bytes.len())
            );
        }

        assert_eq!(
            s.recv_body_server(stream, &mut recv_buf),
            Ok(bytes.len() - 2)
        );

        // Fin flag from last send_body() call was not sent as the buffer was
        // only partially written.
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.pipe.server.data_blocked_sent_count, 0);
        assert_eq!(s.pipe.server.stream_data_blocked_sent_count, 0);
        assert_eq!(s.pipe.server.data_blocked_recv_count, 0);
        assert_eq!(s.pipe.server.stream_data_blocked_recv_count, 1);

        assert_eq!(s.pipe.client.data_blocked_sent_count, 0);
        assert_eq!(s.pipe.client.stream_data_blocked_sent_count, 1);
        assert_eq!(s.pipe.client.data_blocked_recv_count, 0);
        assert_eq!(s.pipe.client.stream_data_blocked_recv_count, 0);
    }

    #[test]
    /// Tests that the max header list size setting allows larger headers than
    /// default.
    fn request_max_header_size_limit_accepts_large_headers() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(150000000);
        config.set_initial_max_stream_data_bidi_local(150000000);
        config.set_initial_max_stream_data_bidi_remote(150000000);
        config.set_initial_max_stream_data_uni(150000000);
        config.set_initial_max_streams_bidi(5);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);
        config.set_initial_congestion_window_packets(100);

        let mut h3_config = Config::new();
        h3_config.set_max_field_section_size(256 * 1024);

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        s.handshake().unwrap();

        let mut req = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"quic.tech"),
            Header::new(b":path", b"/test"),
        ];

        for _ in 1..5000 {
            req.push(Header::new(b"aaaaaaaaaa", b"aaaaaaaaa"));
        }

        let ev_headers = Event::Headers {
            list: req.clone(),
            more_frames: false,
        };

        let stream = s
            .client
            .send_request(&mut s.pipe.client, &req, true)
            .unwrap();

        s.advance().ok();

        assert_eq!(stream, 0);

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[test]
    /// Tests that the max header list size setting is enforced after decoding.
    fn request_max_header_size_limit_decoded_field_section() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(1500);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(5);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let mut h3_config = Config::new();
        h3_config.set_max_field_section_size(65);

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        s.handshake().unwrap();

        let req = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"quic.tech"),
            Header::new(b":path", b"/test"),
            Header::new(b"aaaaaaa", b"aaaaaaaa"),
        ];

        let stream = s
            .client
            .send_request(&mut s.pipe.client, &req, true)
            .unwrap();

        s.advance().ok();

        assert_eq!(stream, 0);

        assert_eq!(s.poll_server(), Err(Error::ExcessiveLoad));

        assert_eq!(
            s.pipe.server.local_error.as_ref().unwrap().error_code,
            Error::to_wire(Error::ExcessiveLoad)
        );
    }

    #[test]
    /// Tests that the max header list size setting is enforced when observing
    /// frame size before decode.
    fn request_max_header_size_limit_default_abort_before_decode() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(150000);
        config.set_initial_max_stream_data_bidi_local(150000);
        config.set_initial_max_stream_data_bidi_remote(150000);
        config.set_initial_max_stream_data_uni(150000);
        config.set_initial_max_streams_bidi(5);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let h3_config = Config::new();

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        s.handshake().unwrap();

        let mut d = vec![42; 200000];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let hdrs = frame::Frame::Headers {
            header_block: vec![0; 65536],
        };

        hdrs.to_bytes(&mut b).unwrap();

        s.pipe.client.stream_send(0, &d, true).unwrap();

        s.advance().ok();

        assert_eq!(s.poll_server(), Err(Error::ExcessiveLoad));

        assert_eq!(
            s.pipe.server.local_error.as_ref().unwrap().error_code,
            Error::to_wire(Error::ExcessiveLoad)
        );
    }

    #[test]
    fn wrapped_transport_error_exposes_its_source() {
        use std::error::Error as _;

        let transport = crate::Error::StreamLimit;
        let wrapped = Error::TransportError(transport);
        let source = wrapped.source().expect("transport error cause");
        assert_eq!(source.downcast_ref::<crate::Error>(), Some(&transport));
        assert!(Error::Done.source().is_none());
        assert!(Error::FrameError.source().is_none());
        assert!(Error::from(crate::Error::Done).source().is_none());
    }

    #[test]
    /// Tests that Error::TransportError contains a transport error.
    fn transport_error() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let req = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"quic.tech"),
            Header::new(b":path", b"/test"),
            Header::new(b"user-agent", b"quiche-test"),
        ];

        // We need to open all streams in the same flight, so we can't use the
        // Session::send_request() method because it also calls advance(),
        // otherwise the server would send a MAX_STREAMS frame and the client
        // wouldn't hit the streams limit.
        assert_eq!(s.client.send_request(&mut s.pipe.client, &req, true), Ok(0));
        assert_eq!(s.client.send_request(&mut s.pipe.client, &req, true), Ok(4));
        assert_eq!(s.client.send_request(&mut s.pipe.client, &req, true), Ok(8));
        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, true),
            Ok(12)
        );
        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, true),
            Ok(16)
        );

        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, true),
            Err(Error::TransportError(crate::Error::StreamLimit))
        );
    }

    #[test]
    /// Tests that sending DATA before HEADERS causes an error.
    fn data_before_headers() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let mut d = [42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame_type = b.put_varint(frame::DATA_FRAME_TYPE_ID).unwrap();
        s.pipe.client.stream_send(0, frame_type, false).unwrap();

        let frame_len = b.put_varint(5).unwrap();
        s.pipe.client.stream_send(0, frame_len, false).unwrap();

        s.pipe.client.stream_send(0, b"hello", false).unwrap();

        s.advance().ok();

        assert_eq!(
            s.server.poll(&mut s.pipe.server),
            Err(Error::FrameUnexpected)
        );
    }

    #[test]
    /// Tests that calling poll() after an error occurred does nothing.
    fn poll_after_error() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let mut d = [42; 128];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        let frame_type = b.put_varint(148_764_065_110_560_899).unwrap();
        s.pipe.client.stream_send(0, frame_type, false).unwrap();

        let frame_len = b.put_varint(1 << 24).unwrap();
        s.pipe.client.stream_send(0, frame_len, false).unwrap();

        s.pipe.client.stream_send(0, &d, false).unwrap();

        s.advance().ok();

        assert_eq!(s.server.poll(&mut s.pipe.server), Err(Error::ExcessiveLoad));

        // Try to call poll() again after an error occurred.
        assert_eq!(s.server.poll(&mut s.pipe.server), Err(Error::Done));
    }

    #[test]
    /// Tests that we limit sending HEADERS based on the stream capacity.
    fn headers_blocked() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(75);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let h3_config = Config::new();

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        s.handshake().unwrap();

        let req = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"quic.tech"),
            Header::new(b":path", b"/test"),
        ];

        assert_eq!(s.client.send_request(&mut s.pipe.client, &req, true), Ok(0));

        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, true),
            Err(Error::StreamBlocked)
        );

        // Clear the writable stream queue.
        assert_eq!(s.pipe.client.stream_writable_next(), Some(2));
        assert_eq!(s.pipe.client.stream_writable_next(), Some(6));
        assert_eq!(s.pipe.client.stream_writable_next(), Some(10));
        assert_eq!(s.pipe.client.stream_writable_next(), None);

        s.advance().ok();

        // Once the server gives flow control credits back, we can send the
        // request.
        assert_eq!(s.pipe.client.stream_writable_next(), Some(4));
        assert_eq!(s.client.send_request(&mut s.pipe.client, &req, true), Ok(4));

        assert_eq!(s.pipe.server.data_blocked_sent_count, 0);
        assert_eq!(s.pipe.server.stream_data_blocked_sent_count, 0);
        assert_eq!(s.pipe.server.data_blocked_recv_count, 1);
        assert_eq!(s.pipe.server.stream_data_blocked_recv_count, 0);

        assert_eq!(s.pipe.client.data_blocked_sent_count, 1);
        assert_eq!(s.pipe.client.stream_data_blocked_sent_count, 0);
        assert_eq!(s.pipe.client.data_blocked_recv_count, 0);
        assert_eq!(s.pipe.client.stream_data_blocked_recv_count, 0);
    }

    #[test]
    /// Ensure StreamBlocked when connection flow control prevents headers.
    fn headers_blocked_on_conn() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(75);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let h3_config = Config::new();

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        s.handshake().unwrap();

        // After the HTTP handshake, some bytes of connection flow control have
        // been consumed. Fill the connection with more grease data on the
        // control stream.
        let d = [42; 28];
        assert_eq!(s.pipe.client.stream_send(2, &d, false), Ok(23));

        let req = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"quic.tech"),
            Header::new(b":path", b"/test"),
        ];

        // There is 0 connection-level flow control, so sending a request is
        // blocked.
        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, true),
            Err(Error::StreamBlocked)
        );
        assert_eq!(s.pipe.client.stream_writable_next(), None);

        // Emit the control stream data and drain it at the server via poll() to
        // consumes it via poll() and gives back flow control.
        s.advance().ok();
        assert_eq!(s.poll_server(), Err(Error::Done));
        s.advance().ok();

        // Now we can send the request.
        assert_eq!(s.pipe.client.stream_writable_next(), Some(2));
        assert_eq!(s.pipe.client.stream_writable_next(), Some(6));
        assert_eq!(s.client.send_request(&mut s.pipe.client, &req, true), Ok(0));

        assert_eq!(s.pipe.server.data_blocked_sent_count, 0);
        assert_eq!(s.pipe.server.stream_data_blocked_sent_count, 0);
        assert_eq!(s.pipe.server.data_blocked_recv_count, 1);
        assert_eq!(s.pipe.server.stream_data_blocked_recv_count, 0);

        assert_eq!(s.pipe.client.data_blocked_sent_count, 1);
        assert_eq!(s.pipe.client.stream_data_blocked_sent_count, 0);
        assert_eq!(s.pipe.client.data_blocked_recv_count, 0);
        assert_eq!(s.pipe.client.stream_data_blocked_recv_count, 0);
    }

    #[test]
    /// Ensure that the connection does not consume a stream ID when
    /// send_request fails with StreamBlocked due to hitting the
    /// MAX_DATA flow control limit when attempting to send headers.
    /// The headers are sent successfully after a MAX_DATA update.
    fn headers_blocked_by_max_data_success_on_retry() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(70);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let h3_config = Config::new();

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        s.handshake().unwrap();

        let req = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"quic.tech"),
            Header::new(b":path", b"/test/with/long/url"),
        ];

        // After the HTTP handshake, some bytes of connection flow
        // control have been consumed.  The serialized request does
        // not fit in the remaining connection-level flow control
        // limit.  send_request fails without creating a stream.
        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, true),
            Err(Error::StreamBlocked)
        );

        // Verify that stream 0 does not exist in the H3 stream map after the
        // failed attempt.
        assert!(!s.client.streams.contains_key(&0));

        // Emit the control stream data and drain it at the server to give back
        // flow control.
        s.advance().ok();
        assert_eq!(s.poll_server(), Err(Error::Done));
        s.advance().ok();

        // Now we can send the request. The stream ID should be 0 (not 4),
        // confirming that the blocked attempt did not consume the stream ID.
        let stream_id = s.client.send_request(&mut s.pipe.client, &req, true);
        assert_eq!(stream_id, Ok(0));
        assert!(s.client.streams.contains_key(&0));
        assert!(!s.client.streams.contains_key(&4));

        // Subsequent request should use stream ID 4.
        let stream_id2 = s.client.send_request(&mut s.pipe.client, &req, true);
        assert_eq!(stream_id2, Ok(4));
        assert!(s.client.streams.contains_key(&0));
        assert!(s.client.streams.contains_key(&4));

        s.advance().ok();
    }

    /// Inject client frames and verify the server acknowledges their packet.
    /// ACK delay is a wall-clock-dependent varint, so the encrypted response
    /// length is not a stable way to verify an ACK-only packet.
    fn assert_client_packet_acknowledged(
        pipe: &mut crate::test_utils::Pipe, frames: &[crate::frame::Frame],
        buf: &mut [u8],
    ) {
        let packet_number = pipe.client.next_pkt_num;
        let len = pipe
            .send_pkt_to_server(crate::packet::Type::Short, frames, buf)
            .unwrap();
        assert!(len > 0, "server did not emit an ACK response");
        let response =
            crate::test_utils::decode_pkt(&mut pipe.client, &mut buf[..len])
                .unwrap();
        assert!(
            response.iter().any(|frame| matches!(frame,
                crate::frame::Frame::ACK { ranges, .. } if ranges.contains(packet_number)
            )),
            "server did not acknowledge packet {packet_number}: {response:?}",
        );
        assert!(
            response.iter().all(|frame| matches!(
                frame,
                crate::frame::Frame::ACK { .. } |
                    crate::frame::Frame::Padding { .. }
            )),
            "unexpected non-ACK response: {response:?}"
        );
    }

    #[test]
    /// Ensure STREAM_DATA_BLOCKED is not emitted multiple times with the same
    /// offset when trying to send large bodies.
    fn send_body_truncation_stream_blocked() {
        use crate::test_utils::decode_pkt;

        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        // Use generous connection-level flow control.
        config.set_initial_max_data(10000);
        config.set_initial_max_stream_data_bidi_local(80);
        config.set_initial_max_stream_data_bidi_remote(80);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let h3_config = Config::new();

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let _ = s.send_response(stream, false).unwrap();

        assert_eq!(s.pipe.server.streams.blocked().len(), 0);

        // The body must be larger than the stream window would allow
        let d = [42; 500];
        let mut off = 0;

        let sent = s
            .server
            .send_body(&mut s.pipe.server, stream, &d, true)
            .unwrap();
        assert_eq!(sent, 26);
        off += sent;

        // send_body wrote as much as it could (sent < size of buff).
        assert_eq!(s.pipe.server.streams.blocked().len(), 1);
        assert_eq!(
            s.server
                .send_body(&mut s.pipe.server, stream, &d[off..], true),
            Err(Error::Done)
        );
        assert_eq!(s.pipe.server.streams.blocked().len(), 1);

        // Now read raw frames to see what the QUIC layer did
        let mut buf = [0; 65535];
        let (len, _) = s.pipe.server.send(&mut buf).unwrap();

        let frames = decode_pkt(&mut s.pipe.client, &mut buf[..len]).unwrap();

        let mut iter = frames.iter();

        assert_eq!(
            iter.next(),
            Some(&crate::frame::Frame::StreamDataBlocked {
                stream_id: 0,
                limit: 80,
            })
        );

        // At the server, after sending the STREAM_DATA_BLOCKED frame, we clear
        // the mark.
        assert_eq!(s.pipe.server.streams.blocked().len(), 0);

        // Don't read any data from the client, so stream flow control is never
        // given back in the form of changing the stream's max offset.
        // Subsequent body send operations will still fail but no more
        // STREAM_DATA_BLOCKED frames should be submitted since the limit didn't
        // change. No frames means no packet to send.
        assert_eq!(
            s.server
                .send_body(&mut s.pipe.server, stream, &d[off..], true),
            Err(Error::Done)
        );
        assert_eq!(s.pipe.server.streams.blocked().len(), 0);
        assert_eq!(s.pipe.server.send(&mut buf), Err(crate::Error::Done));

        // Now update the client's max offset manually.
        let frames = [crate::frame::Frame::MaxStreamData {
            stream_id: 0,
            max: 100,
        }];

        assert_client_packet_acknowledged(&mut s.pipe, &frames, &mut buf);

        let sent = s
            .server
            .send_body(&mut s.pipe.server, stream, &d[off..], true)
            .unwrap();
        assert_eq!(sent, 18);

        // Same thing here...
        assert_eq!(s.pipe.server.streams.blocked().len(), 1);
        assert_eq!(
            s.server
                .send_body(&mut s.pipe.server, stream, &d[off..], true),
            Err(Error::Done)
        );
        assert_eq!(s.pipe.server.streams.blocked().len(), 1);

        let (len, _) = s.pipe.server.send(&mut buf).unwrap();

        let frames = decode_pkt(&mut s.pipe.client, &mut buf[..len]).unwrap();

        let mut iter = frames.iter();

        assert_eq!(
            iter.next(),
            Some(&crate::frame::Frame::StreamDataBlocked {
                stream_id: 0,
                limit: 100,
            })
        );
    }

    #[test]
    /// Ensure stream doesn't hang due to small cwnd.
    fn send_body_stream_blocked_by_small_cwnd() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        // Use generous connection-level flow control.
        config.set_initial_max_data(100000);
        config.set_initial_max_stream_data_bidi_local(100000);
        config.set_initial_max_stream_data_bidi_remote(50000);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let h3_config = Config::new();

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let _ = s.send_response(stream, false).unwrap();

        // Clear the writable stream queue.
        assert_eq!(s.pipe.server.stream_writable_next(), Some(3));
        assert_eq!(s.pipe.server.stream_writable_next(), Some(7));
        assert_eq!(s.pipe.server.stream_writable_next(), Some(11));
        assert_eq!(s.pipe.server.stream_writable_next(), Some(stream));
        assert_eq!(s.pipe.server.stream_writable_next(), None);

        // The body must be larger than the cwnd would allow.
        let send_buf = [42; 80000];

        let sent = s
            .server
            .send_body(&mut s.pipe.server, stream, &send_buf, true)
            .unwrap();

        // send_body wrote as much as it could (sent < size of buff).
        assert_eq!(sent, 11997);

        s.advance().ok();

        // Client reads received headers and body.
        let mut recv_buf = [42; 80000];
        assert!(s.poll_client().is_ok());
        assert_eq!(s.poll_client(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_client(stream, &mut recv_buf), Ok(11997));

        s.advance().ok();

        // Server send cap is smaller than remaining body buffer.
        assert!(s.pipe.server.tx_cap < send_buf.len() - sent);

        // Once the server cwnd opens up, we can send more body.
        assert_eq!(s.pipe.server.stream_writable_next(), Some(0));
    }

    #[test]
    /// Ensure stream doesn't hang due to small cwnd.
    fn send_body_stream_blocked_zero_length() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        // Use generous connection-level flow control.
        config.set_initial_max_data(100000);
        config.set_initial_max_stream_data_bidi_local(100000);
        config.set_initial_max_stream_data_bidi_remote(50000);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let h3_config = Config::new();

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        s.handshake().unwrap();

        let (stream, req) = s.send_request(true).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        let _ = s.send_response(stream, false).unwrap();

        // Clear the writable stream queue.
        assert_eq!(s.pipe.server.stream_writable_next(), Some(3));
        assert_eq!(s.pipe.server.stream_writable_next(), Some(7));
        assert_eq!(s.pipe.server.stream_writable_next(), Some(11));
        assert_eq!(s.pipe.server.stream_writable_next(), Some(stream));
        assert_eq!(s.pipe.server.stream_writable_next(), None);

        // Leave three bytes of capacity: exactly enough for a one-byte DATA
        // frame with a one-byte length field.
        let send_buf = [42; 11994];

        let sent = s
            .server
            .send_body(&mut s.pipe.server, stream, &send_buf, false)
            .unwrap();

        assert_eq!(sent, 11994);

        // The input size must not force a two-byte length field for a
        // one-byte partial write.
        assert_eq!(s.pipe.server.stream_capacity(stream).unwrap(), 3);
        assert_eq!(
            s.server
                .send_body(&mut s.pipe.server, stream, &send_buf, false),
            Ok(1)
        );
        assert_eq!(s.pipe.server.stream_capacity(stream).unwrap(), 0);
        assert_eq!(
            s.server
                .send_body(&mut s.pipe.server, stream, &send_buf, false),
            Err(Error::Done)
        );

        s.advance().ok();

        // Client reads received headers and body.
        let mut recv_buf = [42; 80000];
        assert!(s.poll_client().is_ok());
        assert_eq!(s.poll_client(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_client(stream, &mut recv_buf), Ok(11995));

        s.advance().ok();

        // Once the server cwnd opens up, we can send more body.
        assert_eq!(s.pipe.server.stream_writable_next(), Some(0));
    }

    #[test]
    fn data_payload_capacity_is_maximal() {
        let mut credits = (0..256).collect::<Vec<usize>>();
        for boundary in [64_u64, 16_384, 1 << 30, octets::MAX_VAR_INT] {
            if let Ok(boundary) = usize::try_from(boundary) {
                credits.extend(
                    boundary.saturating_sub(12)..=boundary.saturating_add(12),
                );
            }
        }
        credits.push(usize::MAX);
        for credit in credits {
            for requested in [0, 1, 63, 64, 65, 16_384, usize::MAX] {
                let Some(payload) = data_payload_capacity(requested, credit)
                else {
                    assert!(credit < 2);
                    continue;
                };
                assert!(payload <= requested);
                assert!(payload as u64 <= octets::MAX_VAR_INT);
                let overhead = 1 + octets::varint_len(payload as u64);
                assert!(payload <= credit - overhead);
                if payload < requested && (payload as u64) < octets::MAX_VAR_INT {
                    let next = payload + 1;
                    let next_overhead = 1 + octets::varint_len(next as u64);
                    assert!(credit
                        .checked_sub(next_overhead)
                        .is_none_or(|n| n < next));
                }
            }
        }
    }

    #[rstest::rstest]
    fn finish_after_trailers_without_data(#[values(false, true)] response: bool) {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();
        let (stream, _) = s.send_request(response).unwrap();
        assert!(matches!(s.poll_server(), Ok((_, Event::Headers { .. }))));
        if response {
            assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));
            s.send_response(stream, false).unwrap();
            assert!(matches!(s.poll_client(), Ok((_, Event::Headers { .. }))));
        }
        let trailers = [Header::new(b"foo", b"bar")];
        let (sender, transport) = if response {
            (&mut s.server, &mut s.pipe.server)
        } else {
            (&mut s.client, &mut s.pipe.client)
        };
        sender
            .send_additional_headers(transport, stream, &trailers, true, false)
            .unwrap();
        assert_eq!(
            sender.send_body(transport, stream, b"x", true),
            Err(Error::FrameUnexpected)
        );
        assert_eq!(
            sender.send_body(transport, stream, b"", false),
            Err(Error::FrameUnexpected)
        );
        let offset = transport.streams.get(stream).unwrap().send.off_back();
        assert_eq!(sender.send_body(transport, stream, b"", true), Ok(0));
        assert_eq!(
            transport.streams.get(stream).unwrap().send.off_back(),
            offset
        );
        assert_eq!(
            sender.send_body(transport, stream, b"", true),
            Err(Error::FrameUnexpected)
        );
        s.advance().unwrap();
        let event = if response {
            s.poll_client()
        } else {
            s.poll_server()
        };
        assert_eq!(
            event,
            Ok((stream, Event::Headers {
                list: trailers.to_vec(),
                more_frames: false
            }))
        );
        let event = if response {
            s.poll_client()
        } else {
            s.poll_server()
        };
        assert_eq!(event, Ok((stream, Event::Finished)));
    }

    #[test]
    /// Test handling of 0-length DATA writes with and without fin.
    fn zero_length_data() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();

        assert_eq!(
            s.client.send_body(&mut s.pipe.client, 0, b"", false),
            Err(Error::Done)
        );
        assert_eq!(s.client.send_body(&mut s.pipe.client, 0, b"", true), Ok(0));

        s.advance().ok();

        let mut recv_buf = vec![0; 100];

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));

        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_server(stream, &mut recv_buf), Err(Error::Done));

        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        let resp = s.send_response(stream, false).unwrap();

        assert_eq!(
            s.server.send_body(&mut s.pipe.server, 0, b"", false),
            Err(Error::Done)
        );
        assert_eq!(s.server.send_body(&mut s.pipe.server, 0, b"", true), Ok(0));

        s.advance().ok();

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: true,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));

        assert_eq!(s.poll_client(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_client(stream, &mut recv_buf), Err(Error::Done));

        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Tests that blocked 0-length DATA writes are reported correctly.
    fn zero_length_data_blocked() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(74);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);

        let h3_config = Config::new();

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        s.handshake().unwrap();

        let req = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"quic.tech"),
            Header::new(b":path", b"/test"),
        ];

        assert_eq!(
            s.client.send_request(&mut s.pipe.client, &req, false),
            Ok(0)
        );

        assert_eq!(
            s.client.send_body(&mut s.pipe.client, 0, b"", true),
            Err(Error::Done)
        );

        // Clear the writable stream queue.
        assert_eq!(s.pipe.client.stream_writable_next(), Some(2));
        assert_eq!(s.pipe.client.stream_writable_next(), Some(6));
        assert_eq!(s.pipe.client.stream_writable_next(), Some(10));
        assert_eq!(s.pipe.client.stream_writable_next(), None);

        s.advance().ok();

        // Flow-control credit from the server allows the body to be sent.
        assert_eq!(s.pipe.client.stream_writable_next(), Some(0));
        assert_eq!(s.client.send_body(&mut s.pipe.client, 0, b"", true), Ok(0));
    }

    #[test]
    /// Tests that receiving an empty SETTINGS frame is handled and reported.
    fn empty_settings() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(1500);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(5);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);
        config.set_ack_delay_exponent(8);
        config.grease(false);

        let h3_config = Config::new();
        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        s.handshake().unwrap();

        assert!(s.client.peer_settings_raw().is_some());
        assert!(s.server.peer_settings_raw().is_some());
    }

    #[test]
    /// Tests that receiving a H3_DATAGRAM setting is ok.
    fn dgram_setting() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(70);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.enable_dgram(true, 1000, 1000);
        config.verify_peer(false);

        let h3_config = Config::new();

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
        assert_eq!(s.pipe.handshake(), Ok(()));

        s.client.send_settings(&mut s.pipe.client).unwrap();
        assert_eq!(s.pipe.advance(), Ok(()));

        // Before processing SETTINGS (via poll), HTTP/3 DATAGRAMS are not
        // enabled.
        assert!(!s.server.dgram_enabled_by_peer(&s.pipe.server));

        // When everything is ok, poll returns Done and DATAGRAM is enabled.
        assert_eq!(s.server.poll(&mut s.pipe.server), Err(Error::Done));
        assert!(s.server.dgram_enabled_by_peer(&s.pipe.server));

        // Now detect things on the client
        s.server.send_settings(&mut s.pipe.server).unwrap();
        assert_eq!(s.pipe.advance(), Ok(()));
        assert!(!s.client.dgram_enabled_by_peer(&s.pipe.client));
        assert_eq!(s.client.poll(&mut s.pipe.client), Err(Error::Done));
        assert!(s.client.dgram_enabled_by_peer(&s.pipe.client));
    }

    #[test]
    /// Tests that receiving a H3_DATAGRAM setting when no TP is set generates
    /// an error.
    fn dgram_setting_no_tp() {
        let (mut config, h3_config) = Session::default_configs().unwrap();
        config.set_initial_max_data(70);
        config.enable_dgram(false, 0, 0);

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
        assert_eq!(s.pipe.handshake(), Ok(()));

        s.client.control_stream_id = Some(
            s.client
                .open_uni_stream(
                    &mut s.pipe.client,
                    stream::HTTP3_CONTROL_STREAM_TYPE_ID,
                    &[],
                    false,
                )
                .unwrap(),
        );

        let settings = frame::Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: Some(1),
            grease: None,
            additional_settings: Default::default(),
            raw: Default::default(),
        };

        s.send_frame_client(
            &settings,
            s.client.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.pipe.advance(), Ok(()));

        assert_eq!(s.server.poll(&mut s.pipe.server), Err(Error::SettingsError));
        assert_eq!(
            s.pipe.server.local_error().map(|err| err.error_code),
            Some(WireErrorCode::SettingsError as u64)
        );
        assert_eq!(
            s.server.peer_settings_raw(),
            None,
            "rejected SETTINGS must not publish peer negotiation state"
        );
        assert_eq!(s.server.peer_settings.h3_datagram, None);
        assert!(!s.server.dgram_enabled_by_peer(&s.pipe.server));
    }

    #[test]
    /// Tests that receiving SETTINGS with prohibited values generates an error.
    fn settings_h2_prohibited() {
        let (mut config, h3_config) = Session::default_configs().unwrap();
        config.set_initial_max_data(70);
        config.enable_dgram(false, 0, 0);

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
        assert_eq!(s.pipe.handshake(), Ok(()));

        s.client.control_stream_id = Some(
            s.client
                .open_uni_stream(
                    &mut s.pipe.client,
                    stream::HTTP3_CONTROL_STREAM_TYPE_ID,
                    &[],
                    false,
                )
                .unwrap(),
        );

        s.server.control_stream_id = Some(
            s.server
                .open_uni_stream(
                    &mut s.pipe.server,
                    stream::HTTP3_CONTROL_STREAM_TYPE_ID,
                    &[],
                    false,
                )
                .unwrap(),
        );

        let frame_payload_len = 2u64;
        let settings = [
            frame::SETTINGS_FRAME_TYPE_ID as u8,
            frame_payload_len as u8,
            0x2, // 0x2 is a reserved setting type
            1,
        ];

        s.send_arbitrary_stream_data_client(
            &settings,
            s.client.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        s.send_arbitrary_stream_data_server(
            &settings,
            s.server.control_stream_id.unwrap(),
            false,
        )
        .unwrap();

        assert_eq!(s.pipe.advance(), Ok(()));

        assert_eq!(s.server.poll(&mut s.pipe.server), Err(Error::SettingsError));

        assert_eq!(s.client.poll(&mut s.pipe.client), Err(Error::SettingsError));
    }

    #[test]
    /// Tests that setting SETTINGS with prohibited values generates an error.
    fn set_prohibited_additional_settings() {
        let mut h3_config = Config::new();
        assert_eq!(
            h3_config.set_additional_settings(vec![(
                frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY,
                43
            )]),
            Err(Error::SettingsError)
        );
        assert_eq!(
            h3_config.set_additional_settings(vec![(
                frame::SETTINGS_MAX_FIELD_SECTION_SIZE,
                43
            )]),
            Err(Error::SettingsError)
        );
        assert_eq!(
            h3_config.set_additional_settings(vec![(
                frame::SETTINGS_QPACK_BLOCKED_STREAMS,
                43
            )]),
            Err(Error::SettingsError)
        );
        assert_eq!(
            h3_config.set_additional_settings(vec![(
                frame::SETTINGS_ENABLE_CONNECT_PROTOCOL,
                43
            )]),
            Err(Error::SettingsError)
        );
        assert_eq!(
            h3_config
                .set_additional_settings(vec![(frame::SETTINGS_H3_DATAGRAM, 43)]),
            Err(Error::SettingsError)
        );
    }

    #[test]
    /// Tests that a client rejects a SETTINGS frame received on a request
    /// stream.
    fn settings_on_request_stream_client() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, _req) = s.send_request(true).unwrap();

        let settings = frame::Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            additional_settings: Default::default(),
            raw: Default::default(),
        };

        s.send_frame_server(&settings, stream, false).unwrap();

        // The client MUST treat this as H3_FRAME_UNEXPECTED.
        assert_eq!(s.poll_client(), Err(Error::FrameUnexpected));
        assert_eq!(
            s.pipe.client.local_error(),
            Some(&crate::ConnectionError {
                is_app: true,
                error_code: WireErrorCode::FrameUnexpected as u64,
                reason: format!(
                    "Unexpected frame type {}",
                    frame::SETTINGS_FRAME_TYPE_ID
                )
                .into_bytes(),
            })
        );
    }

    /// Server-to-client control frames are forbidden on request streams.
    /// Test each forbidden type and verify the exact HTTP/3 close reason.
    #[rstest::rstest]
    #[case::cancel_push(frame::Frame::CancelPush { push_id: 0 }, frame::CANCEL_PUSH_FRAME_TYPE_ID)]
    #[case::goaway(frame::Frame::GoAway { id: 0 }, frame::GOAWAY_FRAME_TYPE_ID)]
    #[case::max_push_id(frame::Frame::MaxPushId { push_id: 0 }, frame::MAX_PUSH_FRAME_TYPE_ID)]
    fn client_rejects_control_frame_on_request_stream(
        #[case] frame: frame::Frame, #[case] frame_type: u64,
    ) {
        let mut session = Session::new().unwrap();
        session.handshake().unwrap();

        let (stream_id, _) = session.send_request(true).unwrap();
        session.send_frame_server(&frame, stream_id, false).unwrap();

        assert_eq!(session.poll_client(), Err(Error::FrameUnexpected));
        assert_eq!(
            session.pipe.client.local_error(),
            Some(&crate::ConnectionError {
                is_app: true,
                error_code: WireErrorCode::FrameUnexpected as u64,
                reason: format!("Unexpected frame type {frame_type}")
                    .into_bytes(),
            })
        );
    }

    #[test]
    fn settings_send_full_budget_or_fail_without_partial_frame() {
        let mut additional: Vec<_> =
            (0..15).map(|n| ((1_u64 << 30) + n, 1_u64 << 30)).collect();
        additional.extend([((1_u64 << 30) + 15, 1 << 14), (9, 0)]);
        let mut expected = vec![(frame::SETTINGS_MAX_FIELD_SECTION_SIZE, 0)];
        expected.extend_from_slice(&additional);

        // 256 bytes of payload, a 3-byte frame header and the 1-byte
        // control stream type. GREASE must not consume required credit.
        for (grease, credit) in
            [(false, 260), (true, 260), (false, 259), (true, 259)]
        {
            let (mut config, mut h3_config) = Session::default_configs().unwrap();
            config.enable_dgram(false, 0, 0);
            config.grease(grease);
            config.set_initial_max_stream_data_uni(credit);
            h3_config.set_max_field_section_size(0);
            h3_config
                .set_additional_settings(additional.clone())
                .unwrap();
            let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
            s.pipe.handshake().unwrap();
            let stream_id = s.client.next_uni_stream_id;
            let sent = s.client.send_settings(&mut s.pipe.client);
            if credit == 260 {
                assert_eq!(sent, Ok(()));
                assert_eq!(s.client.control_stream_id, Some(stream_id));
                assert_eq!(s.client.next_uni_stream_id, stream_id + 4);
                s.pipe.advance().unwrap();
                assert_eq!(s.poll_server(), Err(Error::Done));
                assert_eq!(
                    s.server.peer_settings_raw(),
                    Some(expected.as_slice())
                );
            } else {
                assert_eq!(sent, Err(Error::InternalError));
                assert_eq!(s.client.control_stream_id, None);
                assert_eq!(s.client.next_uni_stream_id, stream_id);
                assert_eq!(s.pipe.client.stream_capacity(stream_id), Ok(259));
            }
        }
    }

    #[test]
    fn invalid_additional_settings_do_not_replace_configuration() {
        let mut config = Config::new();
        let original = vec![(9, 42)];
        config.set_additional_settings(original.clone()).unwrap();
        for invalid in [
            vec![(0, 1)],
            vec![(5, 1)],
            vec![(9, 0), (9, 1)],
            vec![(octets::MAX_VAR_INT + 1, 0)],
            vec![(9, octets::MAX_VAR_INT + 1)],
            vec![(frame::SETTINGS_H3_DATAGRAM_00, 1)],
        ] {
            assert_eq!(
                config.set_additional_settings(invalid),
                Err(Error::SettingsError)
            );
            assert_eq!(config.additional_settings.as_ref(), Some(&original));
        }
    }

    #[test]
    /// Tests additional settings are actually exchanged by the peers.
    fn set_additional_settings() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(70);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);
        config.grease(false);

        let mut h3_config = Config::new();
        h3_config
            .set_additional_settings(vec![(42, 43), (44, 45)])
            .unwrap();

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
        assert_eq!(s.pipe.handshake(), Ok(()));

        assert_eq!(s.pipe.advance(), Ok(()));

        s.client.send_settings(&mut s.pipe.client).unwrap();
        assert_eq!(s.pipe.advance(), Ok(()));
        assert_eq!(s.server.poll(&mut s.pipe.server), Err(Error::Done));

        s.server.send_settings(&mut s.pipe.server).unwrap();
        assert_eq!(s.pipe.advance(), Ok(()));
        assert_eq!(s.client.poll(&mut s.pipe.client), Err(Error::Done));

        assert_eq!(
            s.server.peer_settings_raw(),
            Some(&[(6, 32_768), (42, 43), (44, 45)][..])
        );
        assert_eq!(
            s.client.peer_settings_raw(),
            Some(&[(6, 32_768), (42, 43), (44, 45)][..])
        );
    }

    #[test]
    /// Send a single DATAGRAM.
    fn single_dgram() {
        let mut buf = [0; 65535];
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        // We'll send default data of 10 bytes on flow ID 0.
        let result = (11, 0, 1);

        s.send_dgram_client(0).unwrap();

        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(result));

        s.send_dgram_server(0).unwrap();
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(result));
    }

    #[test]
    /// Send multiple DATAGRAMs.
    fn multiple_dgram() {
        let mut buf = [0; 65535];
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        // We'll send default data of 10 bytes on flow ID 0.
        let result = (11, 0, 1);

        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(0).unwrap();

        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(result));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(result));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(result));
        assert_eq!(s.recv_dgram_server(&mut buf), Err(Error::Done));

        s.send_dgram_server(0).unwrap();
        s.send_dgram_server(0).unwrap();
        s.send_dgram_server(0).unwrap();

        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(result));
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(result));
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(result));
        assert_eq!(s.recv_dgram_client(&mut buf), Err(Error::Done));
    }

    #[test]
    /// Send more DATAGRAMs than the send queue allows.
    fn multiple_dgram_overflow() {
        let mut buf = [0; 65535];
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        // We'll send default data of 10 bytes on flow ID 0.
        let result = (11, 0, 1);

        // Five DATAGRAMs
        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(0).unwrap();

        // Only 3 independent DATAGRAMs to read events will fire.
        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(result));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(result));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(result));
        assert_eq!(s.recv_dgram_server(&mut buf), Err(Error::Done));
    }

    #[test]
    /// Send a single DATAGRAM and request.
    fn poll_datagram_cycling_no_read() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(1500);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);
        config.enable_dgram(true, 100, 100);

        let h3_config = Config::new();
        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
        s.handshake().unwrap();

        // Send request followed by DATAGRAM on client side.
        let (stream, req) = s.send_request(false).unwrap();

        s.send_body_client(stream, true).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        s.send_dgram_client(0).unwrap();

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));

        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[test]
    /// Send a single DATAGRAM and request.
    fn poll_datagram_single_read() {
        let mut buf = [0; 65535];

        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(1500);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);
        config.enable_dgram(true, 100, 100);

        let h3_config = Config::new();
        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
        s.handshake().unwrap();

        // We'll send default data of 10 bytes on flow ID 0.
        let result = (11, 0, 1);

        // Send request followed by DATAGRAM on client side.
        let (stream, req) = s.send_request(false).unwrap();

        let body = s.send_body_client(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        s.send_dgram_client(0).unwrap();

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));

        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.recv_dgram_server(&mut buf), Ok(result));

        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Send response followed by DATAGRAM on server side
        let resp = s.send_response(stream, false).unwrap();

        let body = s.send_body_server(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: true,
        };

        s.send_dgram_server(0).unwrap();

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Data)));

        assert_eq!(s.poll_client(), Err(Error::Done));

        assert_eq!(s.recv_dgram_client(&mut buf), Ok(result));

        assert_eq!(s.poll_client(), Err(Error::Done));

        assert_eq!(s.recv_body_client(stream, &mut recv_buf), Ok(body.len()));

        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Send multiple DATAGRAMs and requests.
    fn poll_datagram_multi_read() {
        let mut buf = [0; 65535];

        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(1500);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);
        config.enable_dgram(true, 100, 100);

        let h3_config = Config::new();
        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
        s.handshake().unwrap();

        // 10 bytes on flow ID 0 and 2.
        let flow_0_result = (11, 0, 1);
        let flow_2_result = (11, 2, 1);

        // Send requests followed by DATAGRAMs on client side.
        let (stream, req) = s.send_request(false).unwrap();

        let body = s.send_body_client(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(2).unwrap();
        s.send_dgram_client(2).unwrap();
        s.send_dgram_client(2).unwrap();
        s.send_dgram_client(2).unwrap();
        s.send_dgram_client(2).unwrap();

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));

        assert_eq!(s.poll_server(), Err(Error::Done));

        // Second cycle, start to read
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_0_result));
        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_0_result));
        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_0_result));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        assert_eq!(s.poll_server(), Err(Error::Done));

        // Third cycle.
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_0_result));
        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_0_result));
        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_2_result));
        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_2_result));
        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_2_result));
        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_2_result));
        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_2_result));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Send response followed by DATAGRAM on server side
        let resp = s.send_response(stream, false).unwrap();

        let body = s.send_body_server(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: true,
        };

        s.send_dgram_server(0).unwrap();
        s.send_dgram_server(0).unwrap();
        s.send_dgram_server(0).unwrap();
        s.send_dgram_server(0).unwrap();
        s.send_dgram_server(0).unwrap();
        s.send_dgram_server(2).unwrap();
        s.send_dgram_server(2).unwrap();
        s.send_dgram_server(2).unwrap();
        s.send_dgram_server(2).unwrap();
        s.send_dgram_server(2).unwrap();

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Data)));

        assert_eq!(s.poll_client(), Err(Error::Done));

        // Second cycle, start to read
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(flow_0_result));
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(flow_0_result));
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(flow_0_result));
        assert_eq!(s.poll_client(), Err(Error::Done));

        assert_eq!(s.recv_body_client(stream, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));

        assert_eq!(s.poll_client(), Err(Error::Done));

        // Third cycle.
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(flow_0_result));
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(flow_0_result));
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(flow_2_result));
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(flow_2_result));
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(flow_2_result));
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(flow_2_result));
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.recv_dgram_client(&mut buf), Ok(flow_2_result));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    /// Tests that the Finished event is not issued for streams of unknown type
    /// (e.g. GREASE).
    fn finished_is_for_requests() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.client.open_grease_stream(&mut s.pipe.client), Ok(()));
        assert_eq!(s.pipe.advance(), Ok(()));

        assert_eq!(s.poll_client(), Err(Error::Done));
        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[test]
    fn unknown_uni_stream_leaks_past_max_streams_uni() {
        let (mut config, h3_config) = Session::default_configs().unwrap();
        config.set_initial_max_data(100_000);
        config.set_initial_max_stream_data_uni(100_000);
        config.set_initial_max_streams_uni(5);
        config.grease(false);

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
        s.handshake().unwrap();

        let baseline = s.server.streams.len();
        let mut leaked_streams = Vec::new();
        let mut id = 14;

        let n = 500;
        for i in 0..n {
            s.pipe
                .client
                .stream_send(id, &[0x21], true)
                .unwrap_or_else(|e| {
                    panic!(
                        "stream credit was not re-issued after {} streams: {:?}",
                        i, e
                    )
                });

            s.pipe.advance().unwrap();
            assert_eq!(s.poll_server(), Err(Error::Done));
            assert!(s.pipe.server.streams.is_collected(id));
            s.pipe.advance().unwrap();

            leaked_streams.push(id);
            id += 4;
        }

        for id in leaked_streams {
            assert!(s.pipe.server.streams.is_collected(id));
        }

        assert_eq!(
            s.server.streams.len(),
            baseline,
            "expected {} allocated streams in stream map after {} streams with unknown type",
            baseline,
            n,
        );
    }

    #[test]
    fn empty_uni_stream_leaks_past_max_streams_uni() {
        let (mut config, h3_config) = Session::default_configs().unwrap();
        config.set_initial_max_data(100_000);
        config.set_initial_max_stream_data_uni(100_000);
        config.set_initial_max_streams_uni(5);
        config.grease(false);

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
        s.handshake().unwrap();

        let baseline = s.server.streams.len();
        let mut leaked_streams = Vec::new();
        let mut id = 14;

        let n = 500;
        for i in 0..n {
            s.pipe
                .client
                .stream_send(id, &[], true)
                .unwrap_or_else(|e| {
                    panic!(
                        "stream credit was not re-issued after {} streams: {:?}",
                        i, e
                    )
                });

            s.pipe.advance().unwrap();
            assert_eq!(s.poll_server(), Err(Error::Done));
            assert!(s.pipe.server.streams.is_collected(id));
            s.pipe.advance().unwrap();

            leaked_streams.push(id);
            id += 4;
        }

        for id in leaked_streams {
            assert!(s.pipe.server.streams.is_collected(id));
        }

        assert_eq!(
            s.server.streams.len(),
            baseline,
            "expected {} allocated streams in stream map after {} streams without stream type",
            baseline,
            n,
        );
    }

    #[test]
    /// Tests that streams are marked as finished only once.
    fn finished_once() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (stream, req) = s.send_request(false).unwrap();
        let body = s.send_body_client(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));

        assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        assert_eq!(s.recv_body_server(stream, &mut recv_buf), Err(Error::Done));
        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[test]
    /// Tests that the Data event is properly re-armed.
    fn data_event_rearm() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let (r1_id, r1_hdrs) = s.send_request(false).unwrap();

        let mut recv_buf = vec![0; bytes.len()];

        let r1_ev_headers = Event::Headers {
            list: r1_hdrs,
            more_frames: true,
        };

        // Manually send an incomplete DATA frame (i.e. the frame size is longer
        // than the actual data sent).
        {
            let mut d = [42; 10];
            let mut b = octets::OctetsMut::with_slice(&mut d);

            b.put_varint(frame::DATA_FRAME_TYPE_ID).unwrap();
            b.put_varint(bytes.len() as u64).unwrap();
            let off = b.off();
            s.pipe.client.stream_send(r1_id, &d[..off], false).unwrap();

            assert_eq!(
                s.pipe.client.stream_send(r1_id, &bytes[..5], false),
                Ok(5)
            );

            s.advance().ok();
        }

        assert_eq!(s.poll_server(), Ok((r1_id, r1_ev_headers)));
        assert_eq!(s.poll_server(), Ok((r1_id, Event::Data)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Read the available body data.
        assert_eq!(s.recv_body_server(r1_id, &mut recv_buf), Ok(5));

        // Send the remaining DATA payload.
        assert_eq!(s.pipe.client.stream_send(r1_id, &bytes[5..], false), Ok(5));
        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((r1_id, Event::Data)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Read the rest of the body data.
        assert_eq!(s.recv_body_server(r1_id, &mut recv_buf), Ok(5));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Send more data.
        let r1_body = s.send_body_client(r1_id, false).unwrap();

        assert_eq!(s.poll_server(), Ok((r1_id, Event::Data)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.recv_body_server(r1_id, &mut recv_buf), Ok(r1_body.len()));

        // Send a new request to test cross-stream event rearming.
        let (r2_id, r2_hdrs) = s.send_request(false).unwrap();
        let r2_ev_headers = Event::Headers {
            list: r2_hdrs,
            more_frames: true,
        };
        let r2_body = s.send_body_client(r2_id, false).unwrap();

        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((r2_id, r2_ev_headers)));
        assert_eq!(s.poll_server(), Ok((r2_id, Event::Data)));
        assert_eq!(s.recv_body_server(r2_id, &mut recv_buf), Ok(r2_body.len()));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Send more data on request 1, then trailing HEADERS.
        let r1_body = s.send_body_client(r1_id, false).unwrap();

        let trailers = vec![Header::new(b"hello", b"world")];

        s.client
            .send_additional_headers(
                &mut s.pipe.client,
                r1_id,
                &trailers,
                true,
                true,
            )
            .unwrap();

        let r1_ev_trailers = Event::Headers {
            list: trailers.clone(),
            more_frames: false,
        };

        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((r1_id, Event::Data)));
        assert_eq!(s.recv_body_server(r1_id, &mut recv_buf), Ok(r1_body.len()));

        assert_eq!(s.poll_server(), Ok((r1_id, r1_ev_trailers)));
        assert_eq!(s.poll_server(), Ok((r1_id, Event::Finished)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Send more data on request 2, then trailing HEADERS.
        let r2_body = s.send_body_client(r2_id, false).unwrap();

        s.client
            .send_additional_headers(
                &mut s.pipe.client,
                r2_id,
                &trailers,
                true,
                false,
            )
            .unwrap();

        let r2_ev_trailers = Event::Headers {
            list: trailers,
            more_frames: true,
        };

        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((r2_id, Event::Data)));
        assert_eq!(s.recv_body_server(r2_id, &mut recv_buf), Ok(r2_body.len()));
        assert_eq!(s.poll_server(), Ok((r2_id, r2_ev_trailers)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        let (r3_id, r3_hdrs) = s.send_request(false).unwrap();

        let r3_ev_headers = Event::Headers {
            list: r3_hdrs,
            more_frames: true,
        };

        // Manually send an incomplete DATA frame containing only its header.
        {
            let mut d = [42; 10];
            let mut b = octets::OctetsMut::with_slice(&mut d);

            b.put_varint(frame::DATA_FRAME_TYPE_ID).unwrap();
            b.put_varint(bytes.len() as u64).unwrap();
            let off = b.off();
            s.pipe.client.stream_send(r3_id, &d[..off], false).unwrap();

            s.advance().ok();
        }

        assert_eq!(s.poll_server(), Ok((r3_id, r3_ev_headers)));
        assert_eq!(s.poll_server(), Ok((r3_id, Event::Data)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.recv_body_server(r3_id, &mut recv_buf), Err(Error::Done));

        assert_eq!(s.pipe.client.stream_send(r3_id, &bytes[..5], false), Ok(5));

        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((r3_id, Event::Data)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.recv_body_server(r3_id, &mut recv_buf), Ok(5));

        assert_eq!(s.pipe.client.stream_send(r3_id, &bytes[5..], false), Ok(5));
        s.advance().ok();

        assert_eq!(s.poll_server(), Ok((r3_id, Event::Data)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.recv_body_server(r3_id, &mut recv_buf), Ok(5));

        // Buffer multiple data frames.
        let body = s.send_body_client(r3_id, false).unwrap();
        s.send_body_client(r3_id, false).unwrap();
        s.send_body_client(r3_id, false).unwrap();

        assert_eq!(s.poll_server(), Ok((r3_id, Event::Data)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        {
            let mut d = [42; 10];
            let mut b = octets::OctetsMut::with_slice(&mut d);

            b.put_varint(frame::DATA_FRAME_TYPE_ID).unwrap();
            b.put_varint(0).unwrap();
            let off = b.off();
            s.pipe.client.stream_send(r3_id, &d[..off], true).unwrap();

            s.advance().ok();
        }

        let mut recv_buf = vec![0; bytes.len() * 3];

        assert_eq!(s.recv_body_server(r3_id, &mut recv_buf), Ok(body.len() * 3));
    }

    #[test]
    /// Tests that the Datagram event is properly re-armed.
    fn dgram_event_rearm() {
        let mut buf = [0; 65535];

        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(1500);
        config.set_initial_max_stream_data_bidi_local(150);
        config.set_initial_max_stream_data_bidi_remote(150);
        config.set_initial_max_stream_data_uni(150);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(5);
        config.verify_peer(false);
        config.enable_dgram(true, 100, 100);

        let h3_config = Config::new();
        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();
        s.handshake().unwrap();

        // 10 bytes on flow ID 0 and 2.
        let flow_0_result = (11, 0, 1);
        let flow_2_result = (11, 2, 1);

        // Send requests followed by DATAGRAMs on client side.
        let (stream, req) = s.send_request(false).unwrap();

        let body = s.send_body_client(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(2).unwrap();
        s.send_dgram_client(2).unwrap();

        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));

        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_0_result));

        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_0_result));

        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_2_result));

        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_2_result));

        assert_eq!(s.poll_server(), Err(Error::Done));

        s.send_dgram_client(0).unwrap();
        s.send_dgram_client(2).unwrap();

        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_0_result));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.recv_dgram_server(&mut buf), Ok(flow_2_result));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        // Verify that dgram counts are incremented.
        assert_eq!(s.pipe.client.dgram_sent_count, 6);
        assert_eq!(s.pipe.client.dgram_recv_count, 0);
        assert_eq!(s.pipe.server.dgram_sent_count, 0);
        assert_eq!(s.pipe.server.dgram_recv_count, 6);

        let server_path = s.pipe.server.paths.get_active().expect("no active");
        let client_path = s.pipe.client.paths.get_active().expect("no active");
        assert_eq!(client_path.dgram_sent_count, 6);
        assert_eq!(client_path.dgram_recv_count, 0);
        assert_eq!(server_path.dgram_sent_count, 0);
        assert_eq!(server_path.dgram_recv_count, 6);
    }

    #[test]
    fn reset_stream() {
        let mut buf = [0; 65535];

        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        // Client sends request.
        let (stream, req) = s.send_request(false).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        // Server sends response and closes stream.
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        let resp = s.send_response(stream, true).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: false,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));

        // Client sends RESET_STREAM, closing stream.
        let frames = [crate::frame::Frame::ResetStream {
            stream_id: stream,
            error_code: 42,
            final_size: 68,
        }];

        assert_client_packet_acknowledged(&mut s.pipe, &frames, &mut buf);

        // Server issues Reset event for the stream.
        assert_eq!(s.poll_server(), Ok((stream, Event::Reset(42))));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Sending RESET_STREAM again shouldn't trigger another Reset event.
        assert_client_packet_acknowledged(&mut s.pipe, &frames, &mut buf);

        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    /// The client shuts down the stream's write direction, the server
    /// shuts down its side with fin
    #[test]
    fn client_shutdown_write_server_fin() {
        let mut buf = [0; 65535];
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        // Client sends request.
        let (stream, req) = s.send_request(false).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        // Server sends response and closes stream.
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        let resp = s.send_response(stream, true).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: false,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));

        // Client shuts down stream ==> sends RESET_STREAM
        assert_eq!(
            s.pipe
                .client
                .stream_shutdown(stream, crate::Shutdown::Write, 42),
            Ok(())
        );
        assert_eq!(s.advance(), Ok(()));

        // Server sees the Reset event for the stream.
        assert_eq!(s.poll_server(), Ok((stream, Event::Reset(42))));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Streams have been collected by quiche
        assert!(s.pipe.server.streams.is_collected(stream));
        assert!(s.pipe.client.streams.is_collected(stream));

        // Client sends another request, server sends response without fin
        //
        let (stream, req) = s.send_request(false).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        // Check that server has received the request.
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Server sends reponse without closing the stream.
        let resp = s.send_response(stream, false).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: true,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Err(Error::Done));

        // Client shuts down stream ==> sends RESET_STREAM
        assert_eq!(
            s.pipe
                .client
                .stream_shutdown(stream, crate::Shutdown::Write, 42),
            Ok(())
        );
        assert_eq!(s.advance(), Ok(()));

        // Server sees the Reset event for the stream.
        assert_eq!(s.poll_server(), Ok((stream, Event::Reset(42))));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Server sends body and closes the stream.
        s.send_body_server(stream, true).unwrap();

        // Stream has been collected on server by quiche
        assert!(s.pipe.server.streams.is_collected(stream));
        // Client stream has not been collected, the client needs to
        // read the fin from the stream first.
        assert!(!s.pipe.client.streams.is_collected(stream));
        assert_eq!(s.poll_client(), Ok((stream, Event::Data)));
        s.recv_body_client(stream, &mut buf).unwrap();
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
        assert!(s.pipe.client.streams.is_collected(stream));
    }

    #[test]
    fn client_shutdown_read() {
        let mut buf = [0; 65535];
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        // Client sends request and leaves stream open.
        let (stream, req) = s.send_request(false).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        // Server sends response and leaves stream open.
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        let resp = s.send_response(stream, false).unwrap();

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: true,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Err(Error::Done));
        // Client shuts down read
        assert_eq!(
            s.pipe
                .client
                .stream_shutdown(stream, crate::Shutdown::Read, 42),
            Ok(())
        );
        assert_eq!(s.advance(), Ok(()));

        // Stream is writable on server side, but returns StreamStopped
        assert_eq!(s.poll_server(), Err(Error::Done));
        let writables: Vec<u64> = s.pipe.server.writable().collect();
        assert!(writables.contains(&stream));
        assert_eq!(
            s.send_body_server(stream, false),
            Err(Error::TransportError(crate::Error::StreamStopped(42)))
        );

        // Client needs to finish its side by sending a fin
        assert_eq!(
            s.client.send_body(&mut s.pipe.client, stream, &[], true),
            Ok(0)
        );
        assert_eq!(s.advance(), Ok(()));
        // Note, we get an Event::Data for an empty buffer today. But it
        // would also be fine to not get it.
        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_server(stream, &mut buf), Err(Error::Done));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Since the client has already send a fin, the stream is collected
        // on both client and server
        assert!(s.pipe.client.streams.is_collected(stream));
        assert!(s.pipe.server.streams.is_collected(stream));
    }

    #[test]
    fn reset_finished_at_server() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        // Client sends HEADERS and doesn't fin
        let (stream, _req) = s.send_request(false).unwrap();

        // ..then Client sends RESET_STREAM
        assert_eq!(
            s.pipe.client.stream_shutdown(0, crate::Shutdown::Write, 0),
            Ok(())
        );

        assert_eq!(s.pipe.advance(), Ok(()));

        // Server receives just a reset
        assert_eq!(s.poll_server(), Ok((stream, Event::Reset(0))));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Client sends HEADERS and fin
        let (stream, req) = s.send_request(true).unwrap();

        // ..then Client sends RESET_STREAM
        assert_eq!(
            s.pipe.client.stream_shutdown(4, crate::Shutdown::Write, 0),
            Ok(())
        );

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        // Server receives headers and fin.
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[test]
    fn reset_finished_at_server_with_data_pending() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        // Client sends HEADERS and doesn't fin.
        let (stream, req) = s.send_request(false).unwrap();

        assert!(s.send_body_client(stream, false).is_ok());

        assert_eq!(s.pipe.advance(), Ok(()));

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        // Server receives headers and data...
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));

        // ..then Client sends RESET_STREAM.
        assert_eq!(
            s.pipe
                .client
                .stream_shutdown(stream, crate::Shutdown::Write, 0),
            Ok(())
        );

        assert_eq!(s.pipe.advance(), Ok(()));

        // The server does *not* attempt to read from the stream,
        // but polls and receives the reset and there are no more
        // readable streams.
        assert_eq!(s.poll_server(), Ok((stream, Event::Reset(0))));
        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.pipe.server.readable().len(), 0);
    }

    #[test]
    fn reset_finished_at_server_with_data_pending_2() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let init_streams_server = s.server.streams.len();

        // Client sends HEADERS and doesn't fin.
        let (stream, req) = s.send_request(false).unwrap();

        assert!(s.send_body_client(stream, false).is_ok());

        assert_eq!(s.pipe.advance(), Ok(()));

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        // Server receives headers and data...
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));

        // Finish the local H3 send side first. Once the peer resets its
        // receive side, the QUIC stream can be collected immediately.
        s.send_response(stream, true).unwrap();

        // ..then Client sends RESET_STREAM.
        assert_eq!(
            s.pipe
                .client
                .stream_shutdown(stream, crate::Shutdown::Write, 0),
            Ok(())
        );

        assert_eq!(s.pipe.advance(), Ok(()));

        // Server reads from the stream and receives the reset while
        // attempting to read.
        assert_eq!(
            s.recv_body_server(stream, &mut [0; 100]),
            Err(Error::TransportError(crate::Error::StreamReset(0)))
        );

        // No more events and there are no more readable streams.
        assert_eq!(s.poll_server(), Err(Error::Done));
        assert_eq!(s.pipe.server.readable().len(), 0);
        assert_eq!(s.server.streams.len(), init_streams_server);
    }

    #[test]
    fn reset_while_data_payload_pending_frees_h3_state() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let init_streams_server = s.server.streams.len();

        let (stream, req) = s.send_request(false).unwrap();
        assert_eq!(
            s.poll_server(),
            Ok((stream, Event::Headers {
                list: req,
                more_frames: true,
            }))
        );

        // Send only a DATA frame header for a ten-byte payload. H3 enters the
        // Data state, but no DATA payload is available to recv_body_buf().
        assert_eq!(
            s.pipe.client.stream_send(stream, &[0x00, 0x0a], false),
            Ok(2)
        );
        assert_eq!(s.pipe.advance(), Ok(()));
        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));

        // Finish the local H3 send side while the DATA payload is still
        // pending, so consuming the peer reset makes QUIC collect the stream.
        s.send_response(stream, true).unwrap();

        assert_eq!(
            s.pipe
                .client
                .stream_shutdown(stream, crate::Shutdown::Write, 0),
            Ok(())
        );
        assert_eq!(s.pipe.advance(), Ok(()));

        assert_eq!(
            s.recv_body_server(stream, &mut [0; 100]),
            Err(Error::TransportError(crate::Error::StreamReset(0)))
        );
        assert_eq!(s.server.streams.len(), init_streams_server);
    }

    #[test]
    fn reset_finished_at_client() {
        let mut buf = [0; 65535];
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        // Client sends HEADERS and doesn't fin
        let (stream, req) = s.send_request(false).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        // Server receives headers.
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Server sends response and doesn't fin
        s.send_response(stream, false).unwrap();

        assert_eq!(s.pipe.advance(), Ok(()));

        // .. then Server sends RESET_STREAM
        assert_eq!(
            s.pipe
                .server
                .stream_shutdown(stream, crate::Shutdown::Write, 0),
            Ok(())
        );

        assert_eq!(s.pipe.advance(), Ok(()));

        // Client receives Reset only
        assert_eq!(s.poll_client(), Ok((stream, Event::Reset(0))));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Client sends headers and fin.
        let (stream, req) = s.send_request(true).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: false,
        };

        // Server receives headers and fin.
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        // Server sends response and fin
        let resp = s.send_response(stream, true).unwrap();

        assert_eq!(s.pipe.advance(), Ok(()));

        // ..then Server sends RESET_STREAM
        let frames = [crate::frame::Frame::ResetStream {
            stream_id: stream,
            error_code: 42,
            final_size: 68,
        }];

        assert_client_packet_acknowledged(&mut s.pipe, &frames, &mut buf);

        assert_eq!(s.pipe.advance(), Ok(()));

        let ev_headers = Event::Headers {
            list: resp,
            more_frames: false,
        };

        // Client receives headers and fin.
        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    fn collect_completed_streams() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let init_streams_client = s.client.streams.len();
        let init_streams_server = s.server.streams.len();

        // Client sends HEADERS and doesn't fin
        let (stream, req) = s.send_request(false).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        // Server receives headers.
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.client.streams.len(), init_streams_client + 1);
        assert_eq!(s.server.streams.len(), init_streams_server + 1);

        // Client sends body and fin
        let body = s.send_body_client(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));

        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        assert_eq!(s.client.streams.len(), init_streams_client + 1);
        assert_eq!(s.server.streams.len(), init_streams_server + 1);

        // Server sends response and finishes the stream
        let resp_headers = s.send_response(stream, false).unwrap();
        s.send_body_server(stream, true).unwrap();

        let ev_headers = Event::Headers {
            list: resp_headers,
            more_frames: true,
        };

        assert_eq!(s.poll_client(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_client(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_client(stream, &mut recv_buf), Ok(body.len()));

        // The server stream should be gone now
        assert_eq!(s.client.streams.len(), init_streams_client + 1);
        assert_eq!(s.server.streams.len(), init_streams_server);

        // Polling again should clean up the client
        assert_eq!(s.poll_client(), Ok((stream, Event::Finished)));
        assert_eq!(s.poll_client(), Err(Error::Done));

        assert_eq!(s.client.streams.len(), init_streams_client);
    }

    #[test]
    fn collect_reset_streams() {
        let mut s = Session::new().unwrap();
        s.handshake().unwrap();

        let init_streams_client = s.client.streams.len();
        let init_streams_server = s.server.streams.len();

        // Client sends HEADERS and doesn't fin
        let (stream, req) = s.send_request(false).unwrap();

        let ev_headers = Event::Headers {
            list: req,
            more_frames: true,
        };

        // Server receives headers.
        assert_eq!(s.poll_server(), Ok((stream, ev_headers)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.client.streams.len(), init_streams_client + 1);
        assert_eq!(s.server.streams.len(), init_streams_server + 1);

        // Client sends body and fin
        let body = s.send_body_client(stream, true).unwrap();

        let mut recv_buf = vec![0; body.len()];

        assert_eq!(s.poll_server(), Ok((stream, Event::Data)));
        assert_eq!(s.recv_body_server(stream, &mut recv_buf), Ok(body.len()));

        assert_eq!(s.poll_server(), Ok((stream, Event::Finished)));

        assert_eq!(s.client.streams.len(), init_streams_client + 1);
        assert_eq!(s.server.streams.len(), init_streams_server + 1);

        // Server sends response and resets the stream.
        s.send_response(stream, false).unwrap();
        s.pipe
            .server
            .stream_shutdown(stream, crate::Shutdown::Write, 0)
            .unwrap();

        s.advance().ok();

        // TODO: need to notify resets better.
        //
        // This will trigger the h3 layer to check for the stream resets,
        // otherwise it wouldn't know that a reset happened.
        //
        // We will need to figure out a way to do this automatically to avoid
        // requiring applications to do this manually. For now just keep this
        // for testing purposes.
        let _ = s.send_body_server(stream, true);

        assert_eq!(s.poll_server(), Err(Error::Done));

        assert_eq!(s.poll_client(), Ok((stream, Event::Reset(0))));
        assert_eq!(s.poll_client(), Err(Error::Done));

        // The server stream should be gone now
        assert_eq!(s.client.streams.len(), init_streams_client);
        assert_eq!(s.server.streams.len(), init_streams_server);
    }
}

#[cfg(feature = "ffi")]
mod ffi;
#[cfg(feature = "internal")]
#[doc(hidden)]
pub mod frame;
#[cfg(not(feature = "internal"))]
mod frame;
#[doc(hidden)]
pub mod qpack;
mod stream;
