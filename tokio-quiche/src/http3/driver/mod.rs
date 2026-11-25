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

mod client;
/// Wrapper for running HTTP/3 connections.
pub mod connection;
mod datagram;
// `DriverHooks` must stay private to prevent users from creating their own
// H3Drivers.
mod hooks;
mod server;
mod streams;
#[cfg(test)]
pub mod test_utils;
#[cfg(test)]
mod tests;
mod waiting_streams;

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Instant;

use bytes::BufMut as _;
use bytes::Bytes;
use bytes::BytesMut;
use datagram_socket::DgramBuffer;
use datagram_socket::StreamClosureKind;
use foundations::telemetry::log;
use futures::FutureExt;
use quiche::h3;
use quiche::h3::WireErrorCode;
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::mpsc::UnboundedSender;
use tokio_stream::StreamExt;
use tokio_util::sync::PollSender;

use self::hooks::DriverHooks;
use self::hooks::InboundHeaders;
use self::streams::FlowCtx;
use self::streams::HaveUpstreamCapacity;
use self::streams::ReadState;
use self::streams::ReceivedDownstreamData;
use self::streams::StreamCtx;
use self::streams::StreamReady;
use self::waiting_streams::WaitingStreams;
use crate::http3::settings::Http3Settings;
use crate::http3::H3AuditStats;
use crate::metrics::Metrics;
use crate::quic::HandshakeError;
use crate::quic::HandshakeInfo;
use crate::quic::QuicCommand;
use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic;
use crate::QuicResult;

pub use self::client::ClientEventStream;
pub use self::client::ClientH3Command;
pub use self::client::ClientH3Controller;
pub use self::client::ClientH3Driver;
pub use self::client::ClientH3Event;
pub use self::client::ClientRequestSender;
pub use self::client::NewClientRequest;
pub use self::datagram::DatagramFlowSender;
use self::datagram::FlowDatagram;
pub use self::server::IsInEarlyData;
pub use self::server::RawPriorityValue;
pub use self::server::ServerEventStream;
pub use self::server::ServerH3Command;
pub use self::server::ServerH3Controller;
pub use self::server::ServerH3Driver;
pub use self::server::ServerH3Event;

// The default priority for HTTP/3 responses if the application didn't provide
// one.
const DEFAULT_PRIO: h3::Priority = h3::Priority::new(3, true);

// For a stream use a channel with 16 entries, which works out to 16 * 64KB =
// 1MB of max buffered data.
#[cfg(not(any(test, debug_assertions)))]
const STREAM_CAPACITY: usize = 16;
// A single entry stresses `write_pending` in test and debug builds.
#[cfg(any(test, debug_assertions))]
const STREAM_CAPACITY: usize = 1;

// For *all* flows use a shared channel with 2048 entries, which works out
// to 3MB of max buffered data at 1500 bytes per datagram.
const FLOW_CAPACITY: usize = 2048;
// Bound an uninterrupted outbound datagram burst to keep stream I/O responsive.
const FLOW_SEND_BATCH: usize = 64;

// Floor for the lazily-allocated body receive buffer. The buffer is sized to
// the amount currently readable on the stream (see [`process_h3_data`]), but we
// never allocate below this floor, for two reasons:
//
// - A `Limit<BytesMut>` with a zero limit reports no remaining capacity and
//   would make `recv_body_buf` a no-op.
// - Sizing strictly to the readable length defeats allocation amortization: a
//   body that trickles in a few bytes at a time (e.g. one byte per read) would
//   reallocate the buffer on every read. Allocating at least this many bytes
//   lets a single allocation absorb many small reads (each `split()` off)
//   before it is exhausted and reallocated.
//
// The floor is a soft hint, not a hard minimum: it never overrides the
// configured cap, so a cap smaller than the floor still bounds the allocation
// (see [`body_recv_buf_size`]).
const MIN_BODY_RECV_BUF_SIZE: usize = 1024;

// Default cap for the body receive buffer when
// [`Http3Settings::max_recv_body_buf_size`] is unset or zero. Chosen well below
// `BufFactory::MAX_BUF_SIZE` (64 KiB) so a request that carries a body doesn't
// pin a large allocation for the life of the stream; a larger streamed body
// simply reallocates once per driver read-cycle.
const DEFAULT_MAX_BODY_RECV_BUF_SIZE: usize = 16 * 1024;

/// Computes the capacity to use for the body receive buffer given the number of
/// bytes currently readable on the stream and the configured maximum.
///
/// The result is clamped to `[floor, max]`, where `floor` is
/// [`MIN_BODY_RECV_BUF_SIZE`] capped by `max`. Reads below the floor still
/// allocate the floor (so a trickle of tiny reads reuses one allocation instead
/// of reallocating each time), while a single (potentially adversarial) read
/// never allocates more than `max`. `max` is derived from
/// [`Http3Settings::max_recv_body_buf_size`], defaulting to
/// [`DEFAULT_MAX_BODY_RECV_BUF_SIZE`] when the setting is unset or zero.
///
/// `max` is the hard upper bound: when it is smaller than the floor it wins, so
/// the range passed to `clamp` is always valid (`floor <= max`). The
/// constructor guarantees `max >= 1`, so the result is never zero.
fn body_recv_buf_size(readable: usize, max: usize) -> usize {
    let floor = MIN_BODY_RECV_BUF_SIZE.min(max);
    readable.clamp(floor, max)
}

enum StreamStatus {
    Drained,
    ReceiverClosed,
    Reset(u64),
    Failed(h3::Error),
    FinDelivered,
    Blocked,
}

/// Read a chunk into reusable scratch storage and transfer its ownership.
/// A failed read may already have appended bytes; never reuse that partially
/// written buffer for another stream.
fn read_body_chunk(
    scratch: &mut Option<bytes::buf::Limit<BytesMut>>, want: usize,
    read: impl FnOnce(&mut bytes::buf::Limit<BytesMut>) -> h3::Result<usize>,
) -> h3::Result<BytesMut> {
    let buffer =
        scratch.get_or_insert_with(|| BytesMut::with_capacity(want).limit(want));
    if buffer.remaining_mut() < want {
        *buffer = BytesMut::with_capacity(want).limit(want);
    }
    match read(buffer) {
        Ok(n) => {
            let body = buffer.get_mut().split();
            debug_assert_eq!(body.len(), n);
            if !buffer.has_remaining_mut() {
                *scratch = None;
            }
            Ok(body)
        },
        Err(error) => {
            if !buffer.get_ref().is_empty() {
                *scratch = None;
            }
            Err(error)
        },
    }
}

/// Used by a local task to send [`OutboundFrame`]s to a peer on the
/// stream associated with this channel.
pub type OutboundFrameSender = PollSender<OutboundFrame>;

/// Used internally to receive [`OutboundFrame`]s which should be sent to a peer
/// on the stream associated with this channel.
type OutboundFrameStream = mpsc::Receiver<OutboundFrame>;

/// Used internally to send [`InboundFrame`]s (data) from the peer to a local
/// task on the stream associated with this channel.
type InboundFrameSender = PollSender<InboundFrame>;

/// Used by a local task to receive [`InboundFrame`]s (data) on the stream
/// associated with this channel.
pub type InboundFrameStream = mpsc::Receiver<InboundFrame>;

/// The error type used internally in [`H3Driver`].
///
/// Note that [`ApplicationOverQuic`] errors are not exposed to users at this
/// time. The type is public to document the failure modes in [`H3Driver`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum H3ConnectionError {
    /// The controller task was shut down and is no longer listening.
    ControllerWentAway,
    /// Other error at the connection, but not stream level.
    H3(h3::Error),
    /// Received data for a stream that was closed or never opened.
    NonexistentStream,
    /// The server's post-accept timeout was hit.
    /// The timeout can be configured in [`Http3Settings`].
    PostAcceptTimeout,
    /// A malformed HTTP/3 datagram prefix.
    InvalidDatagram,
    /// The HTTP/3 connection has not been initialized.
    NotEstablished,
    /// The driver was attached to the wrong transport endpoint role.
    InvalidDriverRole { expected_server: bool },
}

impl From<h3::Error> for H3ConnectionError {
    fn from(err: h3::Error) -> Self {
        Self::H3(err)
    }
}

impl From<quiche::Error> for H3ConnectionError {
    fn from(err: quiche::Error) -> Self {
        Self::H3(h3::Error::Transport(err))
    }
}

impl Error for H3ConnectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::H3(err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for H3ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s: &dyn fmt::Display = match self {
            Self::ControllerWentAway => &"controller went away",
            Self::H3(e) => e,
            Self::NonexistentStream => &"nonexistent stream",
            Self::PostAcceptTimeout => &"post accept timeout hit",
            Self::InvalidDatagram => &"invalid HTTP/3 datagram",
            Self::NotEstablished => &"HTTP/3 connection not initialized",
            Self::InvalidDriverRole {
                expected_server: true,
            } => &"server driver requires a server transport",
            Self::InvalidDriverRole {
                expected_server: false,
            } => &"client driver requires a client transport",
        };

        write!(f, "H3ConnectionError: {s}")
    }
}

type H3ConnectionResult<T> = Result<T, H3ConnectionError>;

/// HTTP/3 headers that were received on a stream.
///
/// `recv` is used to read the message body, while `send` is used to transmit
/// data back to the peer.
pub struct IncomingH3Headers {
    /// Stream ID of the frame.
    pub stream_id: u64,
    /// The actual [`h3::Header`]s which were received.
    pub headers: Vec<h3::Header>,
    /// An [`OutboundFrameSender`] for streaming body data to the peer. For
    /// [`ClientH3Driver`], note that the request body can also be passed a
    /// cloned sender via [`NewClientRequest`].
    pub send: OutboundFrameSender,
    /// An [`InboundFrameStream`] of body data received from the peer.
    pub recv: InboundFrameStream,
    /// Whether there is a body associated with the incoming headers.
    pub read_fin: bool,
    /// Handle to the [`H3AuditStats`] for the message's stream.
    pub h3_audit_stats: Arc<H3AuditStats>,
}

impl fmt::Debug for IncomingH3Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingH3Headers")
            .field("stream_id", &self.stream_id)
            .field("headers", &self.headers)
            .field("read_fin", &self.read_fin)
            .field("h3_audit_stats", &self.h3_audit_stats)
            .finish_non_exhaustive()
    }
}

/// [`H3Event`]s are produced by an [`H3Driver`] to describe HTTP/3 state
/// updates.
///
/// Both [`ServerH3Driver`] and [`ClientH3Driver`] may extend this enum with
/// endpoint-specific variants. The events must be consumed by users of the
/// drivers, like a higher-level `Server` or `Client` controller.
#[derive(Debug)]
pub enum H3Event {
    /// A SETTINGS frame was received.
    IncomingSettings {
        /// Raw HTTP/3 setting pairs, in the order received from the peer.
        settings: Vec<(u64, u64)>,
    },

    /// A HEADERS frame was received on the given stream. This is either a
    /// request or a response depending on the perspective of the [`H3Event`]
    /// receiver.
    IncomingHeaders(IncomingH3Headers),

    /// A datagram flow was created for an extended CONNECT request stream.
    /// The event precedes the corresponding request headers on the server.
    NewFlow {
        /// The request stream that owns the flow.
        stream_id: u64,
        /// A sender bound to this request.
        send: DatagramFlowSender,
        /// Unreliable payloads received from the peer.
        recv: mpsc::Receiver<DgramBuffer>,
    },
    /// A `RST_STREAM` frame was seen on the given `stream_id`. The user of the
    /// driver should clean up any state allocated for this stream.
    ResetStream { stream_id: u64 },
    /// The connection has irrecoverably errored and is shutting down.
    ConnectionError(h3::Error),
    /// The connection has been shutdown, optionally due to an
    /// [`H3ConnectionError`].
    ConnectionShutdown(Option<H3ConnectionError>),
    /// Body data has been received over a stream.
    BodyBytesReceived {
        /// Stream ID of the body data.
        stream_id: u64,
        /// Number of bytes received.
        num_bytes: u64,
        /// Whether the stream is finished and won't yield any more data.
        fin: bool,
    },
    /// The stream has been closed. This is used to signal stream closures that
    /// don't result from `RST_STREAM` frames, unlike the
    /// [`H3Event::ResetStream`] variant.
    StreamClosed { stream_id: u64 },
    /// A GOAWAY frame was received from the peer containing `id`,
    /// as described in <https://datatracker.ietf.org/doc/html/rfc9114#section-5.2>.
    GoAway { id: u64 },
}

impl H3Event {
    /// Generates an event from an applicable [`H3ConnectionError`].
    const fn from_error(err: H3ConnectionError) -> Self {
        match err {
            H3ConnectionError::H3(error) => Self::ConnectionError(error),
            other => Self::ConnectionShutdown(Some(other)),
        }
    }
}

/// An [`OutboundFrame`] is a data frame that should be sent from a local task
/// to a peer over a [`quiche::h3::Connection`].
///
/// This is used, for example, to send response body data to a peer, or proxied
/// UDP datagrams.
#[derive(Debug)]
pub enum OutboundFrame {
    /// Response headers to be sent to the peer, with optional priority.
    Headers(Vec<h3::Header>, Option<quiche::h3::Priority>),
    /// Response body/CONNECT downstream data plus FIN flag.
    Body(Bytes, bool),
    /// Close the stream with a trailers, with optional priority.
    Trailers(Vec<h3::Header>, Option<quiche::h3::Priority>),
}

/// Reliable body data received from the peer, together with its FIN flag.
#[derive(Debug)]
pub struct InboundFrame {
    /// Received body bytes (empty for a standalone FIN).
    pub body: BytesMut,
    /// The peer's end-of-body marker.
    pub fin: bool,
}

/// A ready-made [`ApplicationOverQuic`] which can handle HTTP/3 and MASQUE.
/// Depending on the `DriverHooks` in use, it powers either a client or a
/// server.
///
/// Use the [`ClientH3Driver`] and [`ServerH3Driver`] aliases to access the
/// respective driver types. The driver is passed into an I/O loop and
/// communicates with the driver's user (e.g., an HTTP client or a server) via
/// its associated [`H3Controller`]. The controller allows the application to
/// both listen for [`H3Event`]s of note and send [`H3Command`]s into the I/O
/// loop.
pub struct H3Driver<H: DriverHooks> {
    /// Configuration used to initialize `conn`. Created from [`Http3Settings`]
    /// in the constructor.
    h3_config: h3::Config,
    /// The underlying HTTP/3 connection. Initialized in
    /// `ApplicationOverQuic::on_application_ready`.
    conn: Option<h3::Connection>,
    /// State required by the client/server hooks.
    hooks: H,
    /// Sends [`H3Event`]s to the [`H3Controller`] paired with this driver.
    h3_event_sender: mpsc::UnboundedSender<H::Event>,
    /// Receives [`H3Command`]s from the [`H3Controller`] paired with this
    /// driver.
    cmd_recv: mpsc::UnboundedReceiver<H::Command>,

    /// A map of stream IDs to their [`StreamCtx`]. This is mainly used to
    /// retrieve the internal Tokio channels associated with the stream.
    stream_map: BTreeMap<u64, StreamCtx>,
    /// Datagram flows keyed by their owning HTTP request stream ID.
    flow_map: BTreeMap<u64, FlowCtx>,
    /// Set of [`WaitForStream`] futures. A stream is added to this set if
    /// we need to send to it and its channel is at capacity, or if we need
    /// data from its channel and the channel is empty.
    waiting_streams: WaitingStreams,

    /// Bounded queue shared by all outbound datagram flows.
    dgram_recv: mpsc::Receiver<FlowDatagram>,
    dgram_send: mpsc::Sender<FlowDatagram>,
    /// Reliable flow shutdown requests cannot be blocked by the data queue.
    flow_close_recv: UnboundedReceiver<u64>,
    flow_close_send: UnboundedSender<u64>,
    /// A buffer to receive H3 body data from quiche. Lazily allocated on the
    /// first body read and released once no streams remain, so idle
    /// connections hold no receive buffer. We `split()` off filled parts until
    /// we need to reallocate.
    body_recv_buf: Option<bytes::buf::Limit<BytesMut>>,
    /// Upper bound on the capacity of `body_recv_buf`, from
    /// [`Http3Settings::max_recv_body_buf_size`]. Unset or `0` defaults to
    /// [`DEFAULT_MAX_BODY_RECV_BUF_SIZE`], so this is always non-zero.
    max_recv_body_buf_size: usize,

    /// The maximum HTTP/3 stream ID seen on this connection.
    max_stream_seen: Option<u64>,

    /// Tracks whether we have forwarded the HTTP/3 SETTINGS frame
    /// to the [`H3Controller`] once.
    settings_received_and_forwarded: bool,
    /// Tracks whether the H3 event receiver has been dropped.
    /// Used to avoid busy-looping on `h3_event_sender.closed()`.
    h3_event_receiver_dropped: bool,
}

impl<H: DriverHooks> H3Driver<H> {
    /// Builds a new [`H3Driver`] and an associated [`H3Controller`].
    ///
    /// The driver should then be passed to
    /// [`InitialQuicConnection`](crate::InitialQuicConnection)'s `start`
    /// method.
    #[must_use = "the returned driver and controller must be paired"]
    pub fn new(http3_settings: &Http3Settings) -> (Self, H3Controller<H>) {
        let (dgram_send, dgram_recv) = mpsc::channel(FLOW_CAPACITY);
        let (flow_close_send, flow_close_recv) = mpsc::unbounded_channel();
        let (cmd_sender, cmd_recv) = mpsc::unbounded_channel();
        let (h3_event_sender, h3_event_recv) = mpsc::unbounded_channel();

        (
            Self {
                h3_config: http3_settings.into(),
                conn: None,
                hooks: H::new(http3_settings),
                h3_event_sender,
                cmd_recv,

                stream_map: BTreeMap::new(),
                flow_map: BTreeMap::new(),

                dgram_recv,
                dgram_send,
                flow_close_recv,
                flow_close_send,
                max_stream_seen: None,
                body_recv_buf: None,
                // `Some(0)` would make `recv_body_buf` a no-op, so treat it as
                // unset.
                max_recv_body_buf_size: http3_settings
                    .max_recv_body_buf_size
                    .filter(|&size| size > 0)
                    .unwrap_or(DEFAULT_MAX_BODY_RECV_BUF_SIZE),

                waiting_streams: WaitingStreams::new(),

                settings_received_and_forwarded: false,
                h3_event_receiver_dropped: false,
            },
            H3Controller {
                cmd_sender,
                h3_event_recv,
            },
        )
    }

    /// Register a flow only while processing an explicit extended CONNECT.
    /// QUIC stream IDs are unique, and inbound datagrams never create flows.
    fn register_flow(&mut self, stream_id: u64) -> H3ConnectionResult<()> {
        use std::collections::btree_map::Entry;
        let Entry::Vacant(entry) = self.flow_map.entry(stream_id) else {
            return Err(h3::Error::InvalidId.into());
        };
        let (flow, recv) = FlowCtx::new(FLOW_CAPACITY);
        let send = DatagramFlowSender::new(
            stream_id,
            self.dgram_send.clone(),
            self.flow_close_send.clone(),
        );
        self.h3_event_sender
            .send(
                H3Event::NewFlow {
                    stream_id,
                    send,
                    recv,
                }
                .into(),
            )
            .map_err(|_| H3ConnectionError::ControllerWentAway)?;
        entry.insert(flow);
        Ok(())
    }

    /// Adds a [`StreamCtx`] to the stream map with the given `stream_id`.
    fn insert_stream(&mut self, stream_id: u64, ctx: StreamCtx) {
        self.stream_map.insert(stream_id, ctx);
        self.max_stream_seen = Some(
            self.max_stream_seen
                .map_or(stream_id, |max| max.max(stream_id)),
        );
    }

    /// Fetches body chunks from the [`quiche::h3::Connection`] and forwards
    /// them to the stream's associated [`InboundFrameStream`].
    fn process_h3_data(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        let conn = self.conn.as_mut().ok_or(Self::connection_not_present())?;
        let ctx = self
            .stream_map
            .get_mut(&stream_id)
            .ok_or(H3ConnectionError::NonexistentStream)?;
        if ctx.read_state == ReadState::Closed {
            return Ok(());
        }

        let status = Self::drain_stream_body(
            conn,
            qconn,
            ctx,
            &mut self.body_recv_buf,
            self.max_recv_body_buf_size,
            &self.h3_event_sender,
        );

        match status {
            StreamStatus::Drained => {
                // Finished receive data may be observed before the next H3
                // poll.
                if ctx.read_state == ReadState::Open &&
                    qconn.stream_finished(stream_id)
                {
                    return self.process_h3_fin(qconn, stream_id);
                }
            },
            StreamStatus::ReceiverClosed => {
                if ctx.read_state == ReadState::FinPending {
                    ctx.close_read();
                    if ctx.both_directions_done() {
                        self.cleanup_stream(qconn, stream_id);
                    }
                } else if !self.flow_map.contains_key(&stream_id) {
                    // Datagram users may intentionally drop the reliable body
                    // receiver while retaining the associated flow.
                    return self.shutdown_stream(
                        qconn,
                        stream_id,
                        StreamShutdown::Read {
                            error_code: WireErrorCode::RequestCancelled as u64,
                        },
                    );
                } else if qconn.stream_finished(stream_id) {
                    return self.process_h3_fin(qconn, stream_id);
                }
            },
            StreamStatus::FinDelivered => {
                ctx.close_read();
                if ctx.both_directions_done() {
                    self.cleanup_stream(qconn, stream_id);
                }
            },
            StreamStatus::Reset(code) =>
                return self.process_h3_reset(qconn, stream_id, code),
            StreamStatus::Failed(h3::Error::MalformedMessage) => {
                return self.shutdown_stream(
                    qconn,
                    stream_id,
                    StreamShutdown::Both {
                        read_error_code: WireErrorCode::MessageError as u64,
                        write_error_code: WireErrorCode::MessageError as u64,
                    },
                );
            },
            StreamStatus::Failed(h3::Error::Transport(
                quiche::Error::InvalidStreamState(id),
            )) if id == stream_id => {
                self.cleanup_stream(qconn, stream_id);
            },
            StreamStatus::Failed(error) => return Err(error.into()),
            StreamStatus::Blocked => {
                self.waiting_streams.push(ctx.wait_for_send(stream_id)?)?;
            },
        }

        Ok(())
    }

    /// Transfer available body data without mutating stream lifecycle state.
    fn drain_stream_body(
        conn: &mut h3::Connection, qconn: &mut QuicheConnection, ctx: &StreamCtx,
        body_recv_buf: &mut Option<bytes::buf::Limit<BytesMut>>,
        max_recv_body_buf_size: usize,
        event_sender: &mpsc::UnboundedSender<H::Event>,
    ) -> StreamStatus {
        let stream_id = ctx.audit_stats.stream_id();
        loop {
            let Some(sender) = ctx.send.as_ref().and_then(PollSender::get_ref)
            else {
                return StreamStatus::Drained;
            };
            let permit = match sender.try_reserve() {
                Ok(permit) => permit,
                Err(TrySendError::Closed(())) =>
                    return StreamStatus::ReceiverClosed,
                Err(TrySendError::Full(())) => {
                    if ctx.read_state == ReadState::FinPending ||
                        qconn.stream_readable(stream_id)
                    {
                        return StreamStatus::Blocked;
                    }
                    return StreamStatus::Drained;
                },
            };

            if ctx.read_state == ReadState::FinPending {
                // FIN is delivered exactly once, even if the app was blocked.
                permit.send(InboundFrame {
                    body: BytesMut::new(),
                    fin: true,
                });
                return StreamStatus::FinDelivered;
            }

            let want = body_recv_buf_size(
                qconn.stream_readable_len(stream_id, max_recv_body_buf_size),
                max_recv_body_buf_size,
            );
            match read_body_chunk(body_recv_buf, want, |buffer| {
                conn.recv_body_buf(qconn, stream_id, buffer)
            }) {
                Ok(body) => {
                    let num_bytes = body.len() as u64;
                    ctx.audit_stats.add_downstream_bytes_recvd(num_bytes);
                    let _ = event_sender.send(
                        H3Event::BodyBytesReceived {
                            stream_id,
                            num_bytes,
                            fin: false,
                        }
                        .into(),
                    );
                    permit.send(InboundFrame { body, fin: false });
                },
                Err(h3::Error::Done) => return StreamStatus::Drained,
                Err(h3::Error::Transport(quiche::Error::StreamReset(code))) =>
                    return StreamStatus::Reset(code),
                Err(error) => return StreamStatus::Failed(error),
            }
        }
    }

    /// Processes an end-of-stream event from the [`quiche::h3::Connection`].
    fn process_h3_fin(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        let Some(ctx) = self.stream_map.get_mut(&stream_id) else {
            // Report a pending stop because no context remains to handle it.
            //
            // This removes its writable notification and permits transport
            // cleanup.
            let _ = qconn.stream_capacity(stream_id);
            return Ok(());
        };

        if ctx.read_state != ReadState::Open {
            return Ok(());
        }

        ctx.read_state = ReadState::FinPending;
        if let Some(flow) = self.flow_map.get_mut(&stream_id) {
            flow.close_read();
        }
        ctx.audit_stats
            .set_recvd_stream_fin(StreamClosureKind::Explicit);
        H::stream_recv_closed(self, stream_id);

        // It's important to send this H3Event before process_h3_data so that
        // a server can (potentially) generate the control response before the
        // corresponding receiver drops.
        let event = H3Event::BodyBytesReceived {
            stream_id,
            num_bytes: 0,
            fin: true,
        };
        let _ = self.h3_event_sender.send(event.into());

        // Communicate fin to upstream. Since the FIN is pending delivery,
        // there can't be a recursive loop.
        self.process_h3_data(qconn, stream_id)
    }

    fn process_h3_reset(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64, code: u64,
    ) -> H3ConnectionResult<()> {
        let Some(ctx) = self.stream_map.get_mut(&stream_id) else {
            let _ = qconn.stream_capacity(stream_id);
            return Ok(());
        };
        if ctx.audit_stats.recvd_reset_stream_error_code().is_some() {
            return Ok(());
        }
        ctx.handle_recvd_reset(code);
        if let Some(flow) = self.flow_map.get_mut(&stream_id) {
            flow.close_read();
        }
        self.waiting_streams.cancel_upstream(stream_id);
        let cleanup = ctx.both_directions_done();
        H::stream_recv_closed(self, stream_id);
        self.h3_event_sender
            .send(H3Event::ResetStream { stream_id }.into())
            .map_err(|_| H3ConnectionError::ControllerWentAway)?;
        if cleanup {
            self.cleanup_stream(qconn, stream_id);
        }
        Ok(())
    }

    /// Processes a single [`quiche::h3::Event`] received from the underlying
    /// [`quiche::h3::Connection`]. Some events are dispatched to helper
    /// methods.
    fn process_read_event(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64, event: h3::Event,
    ) -> H3ConnectionResult<()> {
        self.forward_settings()?;

        match event {
            // Requests/responses are exclusively handled by hooks.
            h3::Event::Headers { list, more_frames } =>
                H::headers_received(self, qconn, InboundHeaders {
                    stream_id,
                    headers: list,
                    has_body: more_frames,
                }),

            h3::Event::Data => self.process_h3_data(qconn, stream_id),
            h3::Event::Finished => self.process_h3_fin(qconn, stream_id),

            h3::Event::Reset(code) =>
                self.process_h3_reset(qconn, stream_id, code),

            h3::Event::PriorityUpdate => Ok(()),
            h3::Event::GoAway => {
                self.h3_event_sender
                    .send(H3Event::GoAway { id: stream_id }.into())
                    .map_err(|_| H3ConnectionError::ControllerWentAway)?;
                H::peer_goaway(self, stream_id)
            },
        }
    }

    /// The SETTINGS frame can be received at any point, so we
    /// need to check `peer_settings_raw` to decide if we've received it.
    ///
    /// Settings should only be sent once, so we generate a single event
    /// when `peer_settings_raw` transitions from None to Some.
    fn forward_settings(&mut self) -> H3ConnectionResult<()> {
        if self.settings_received_and_forwarded {
            return Ok(());
        }

        // capture the peer settings and forward it
        if let Some(settings) = self.conn_mut()?.peer_settings_raw() {
            let incoming_settings = H3Event::IncomingSettings {
                settings: settings.to_vec(),
            };

            self.h3_event_sender
                .send(incoming_settings.into())
                .map_err(|_| H3ConnectionError::ControllerWentAway)?;

            self.settings_received_and_forwarded = true;
        }
        Ok(())
    }

    /// Send an individual frame to the underlying [`quiche::h3::Connection`] to
    /// be flushed at a later time.
    ///
    /// `Self::process_writes` will iterate over all writable streams and call
    /// this method in a loop for each stream to send all writable packets.
    fn process_write_frame(
        conn: &mut h3::Connection, qconn: &mut QuicheConnection,
        ctx: &mut StreamCtx,
    ) -> h3::Result<()> {
        let audit_stats = &ctx.audit_stats;
        let stream_id = audit_stats.stream_id();

        match &mut ctx.queued_frame {
            Some(OutboundFrame::Headers(headers, priority)) => {
                let prio = priority.unwrap_or(DEFAULT_PRIO);

                let res = if ctx.initial_headers_sent {
                    // Initial headers were already sent, send additional
                    // headers now.
                    conn.send_additional_headers_with_priority(
                        qconn, stream_id, headers, prio, false, false,
                    )
                } else {
                    // Send initial headers.
                    conn.send_response_with_priority(
                        qconn, stream_id, headers, prio, false,
                    )
                    .inspect(|()| ctx.initial_headers_sent = true)
                };

                if res == Err(h3::Error::StreamBlocked) {
                    ctx.first_full_headers_flush_fail_time
                        .get_or_insert_with(Instant::now);
                }

                if res.is_ok() {
                    if let Some(first) =
                        ctx.first_full_headers_flush_fail_time.take()
                    {
                        ctx.audit_stats.add_header_flush_duration(
                            Instant::now().duration_since(first),
                        );
                    }
                }

                return res;
            },

            Some(OutboundFrame::Body(body, fin)) if !body.is_empty() || *fin => {
                let len = body.len();

                if *fin {
                    // Drop the receiver on FIN to prevent more frames.
                    // We cannot use `mpsc::Receiver::close()` because of a
                    // Tokio inconsistency when reading a closed channel.
                    // See https://github.com/tokio-rs/tokio/issues/7631.
                    ctx.recv = None;
                }

                let n = conn.send_body_zc(qconn, stream_id, body, *fin)?;

                audit_stats.add_downstream_bytes_sent(n as _);

                return if n == len {
                    if *fin {
                        Self::on_fin_sent(ctx);
                    }

                    Ok(())
                } else {
                    // Couldn't write the entire body, `send_body_zc` will
                    // have trimmed `body` accordingly. The driver keeps
                    // the remainder of the body to send in the future.
                    debug_assert_eq!(
                        n + body.len(),
                        len,
                        "send_body_zc() should have trimmed body but did not"
                    );
                    Err(h3::Error::StreamBlocked)
                };
            },

            Some(OutboundFrame::Trailers(headers, priority)) => {
                let prio = priority.unwrap_or(DEFAULT_PRIO);

                // trailers always set fin=true
                let res = conn.send_additional_headers_with_priority(
                    qconn, stream_id, headers, prio, true, true,
                );

                if res.is_ok() {
                    Self::on_fin_sent(ctx);
                }

                return res;
            },

            Some(OutboundFrame::Body(..)) | None => {
                // No nonempty frame to send; probe STOP_SENDING below.
            },
        }

        // H3 send methods normally report STOP_SENDING as a transport error,
        // but neither an idle stream nor an empty non-FIN body invokes them.
        //
        // Check for cancellation here so the caller can close the outbound
        // channel and record the stop code without waiting for another frame.
        if let Err(error @ quiche::Error::StreamStopped(_)) =
            qconn.stream_capacity(stream_id)
        {
            return Err(h3::Error::Transport(error));
        }

        Ok(())
    }

    fn on_fin_sent(ctx: &mut StreamCtx) {
        ctx.close_write();
        ctx.audit_stats
            .set_sent_stream_fin(StreamClosureKind::Explicit);
    }

    /// Resumes reads or writes to the connection when a stream channel becomes
    /// unblocked.
    ///
    /// If we were waiting for more data from a channel, we resume writing to
    /// the connection. Otherwise, we were blocked on channel capacity and
    /// continue reading from the connection. `Upstream` in this context is
    /// the consumer of the stream.
    fn upstream_ready(
        &mut self, qconn: &mut QuicheConnection, ready: StreamReady,
    ) -> H3ConnectionResult<()> {
        match ready {
            StreamReady::Downstream(r) => self.upstream_read_ready(qconn, r),
            StreamReady::Upstream(r) => self.upstream_write_ready(qconn, r),
        }
    }

    fn upstream_read_ready(
        &mut self, qconn: &mut QuicheConnection,
        read_ready: ReceivedDownstreamData,
    ) -> H3ConnectionResult<()> {
        let ReceivedDownstreamData {
            stream_id,
            chan,
            data,
        } = read_ready;

        let Some(stream) = self.stream_map.get_mut(&stream_id) else {
            return Ok(());
        };

        // After a stop, the closed parked receiver can still return frames
        // queued before it. The write side is done, so drop the receiver and
        // any such frame. Shutdown commands use the independent control queue.
        if stream.fin_or_reset_sent {
            return Ok(());
        }
        stream.recv = Some(chan);
        stream.queued_frame = data;

        self.process_writable_stream(qconn, stream_id)
    }

    fn upstream_write_ready(
        &mut self, qconn: &mut QuicheConnection,
        write_ready: HaveUpstreamCapacity,
    ) -> H3ConnectionResult<()> {
        let HaveUpstreamCapacity {
            stream_id,
            mut chan,
        } = write_ready;

        match self.stream_map.get_mut(&stream_id) {
            None => Ok(()),
            Some(stream) if stream.read_state == ReadState::Closed => Ok(()),
            Some(stream) => {
                // Release the associated permit before retaining the channel.
                chan.abort_send();
                stream.send = Some(chan);
                self.process_h3_data(qconn, stream_id)
            },
        }
    }

    /// Process a bounded burst, dropping stale or unnegotiated datagrams.
    fn dgram_ready(&mut self, qconn: &mut QuicheConnection, first: FlowDatagram) {
        let mut next = Some(first);
        for _ in 0..FLOW_SEND_BATCH {
            let Some(frame) =
                next.take().or_else(|| self.dgram_recv.try_recv().ok())
            else {
                break;
            };
            if self.flow_map.contains_key(&frame.stream_id) &&
                self.stream_map
                    .get(&frame.stream_id)
                    .is_some_and(|ctx| !ctx.fin_or_reset_sent) &&
                self.conn
                    .as_ref()
                    .is_some_and(|conn| conn.dgram_negotiated(qconn))
            {
                let _ = datagram::send_h3_dgram(
                    qconn,
                    frame.stream_id / 4,
                    frame.payload,
                );
            }
        }
    }

    fn shutdown_flow(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        if self.flow_map.contains_key(&stream_id) {
            self.shutdown_stream(qconn, stream_id, StreamShutdown::Both {
                read_error_code: WireErrorCode::NoError as u64,
                write_error_code: WireErrorCode::NoError as u64,
            })?;
        }
        Ok(())
    }

    /// Return a mutable reference to the driver's HTTP/3 connection.
    ///
    /// If the connection doesn't exist yet, this function returns
    /// a `Self::connection_not_present()` error.
    fn conn_mut(&mut self) -> H3ConnectionResult<&mut h3::Connection> {
        self.conn.as_mut().ok_or(Self::connection_not_present())
    }

    /// Error when the driver has not initialized its HTTP/3 connection.
    const fn connection_not_present() -> H3ConnectionError {
        H3ConnectionError::NotEstablished
    }

    /// Cleans up internal state for the indicated HTTP/3 stream.
    ///
    /// This function removes the stream from the stream map, closes any pending
    /// futures, removes associated DATAGRAM flows, and sends a
    /// [`H3Event::StreamClosed`] event (for servers).
    fn cleanup_stream(&mut self, qconn: &mut QuicheConnection, stream_id: u64) {
        let Some(mut stream_ctx) = self.stream_map.remove(&stream_id) else {
            return;
        };

        // Receive-side cleanup can precede the writable stop notification.
        if let Err(quiche::Error::StreamStopped(code)) =
            qconn.stream_capacity(stream_id)
        {
            stream_ctx.handle_recvd_stop_sending(code);
        }

        self.waiting_streams.cancel_upstream(stream_id);
        self.waiting_streams.cancel_downstream(stream_id);

        // Close any DATAGRAM-proxying channels associated with the stream.
        if self.flow_map.remove(&stream_id).is_some() {
            datagram::purge_stream_datagrams(qconn, stream_id);
        }

        H::stream_closed(self, stream_id);

        self.close_if_idle(qconn);
    }

    /// Handles connection cleanup once no streams or flows remain.
    ///
    /// Releases the body receive buffer (it is reallocated lazily on the next
    /// body read; body bytes only flow on active streams, so an empty stream
    /// map means it is unused) and closes the connection with `NoError` if the
    /// H3 event receiver has been dropped.
    fn close_if_idle(&mut self, qconn: &mut QuicheConnection) {
        if self.stream_map.is_empty() && self.flow_map.is_empty() {
            self.body_recv_buf = None;

            if self.h3_event_receiver_dropped {
                let _ = qconn.close(
                    true,
                    quiche::h3::WireErrorCode::NoError as u64,
                    &[],
                );
            }
        }
    }

    /// Shuts down only the requested directions. Keep the opposite direction
    /// alive until its data and final notification have been delivered.
    fn shutdown_stream(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
        shutdown: StreamShutdown,
    ) -> H3ConnectionResult<()> {
        let (read, write) = match shutdown {
            StreamShutdown::Read { error_code } => (Some(error_code), None),
            StreamShutdown::Write { error_code } => (None, Some(error_code)),
            StreamShutdown::Both {
                read_error_code,
                write_error_code,
            } => (Some(read_error_code), Some(write_error_code)),
        };
        let Some(ctx) = self.stream_map.get_mut(&stream_id) else {
            return Ok(());
        };

        // Validate both codes before mutating either direction.
        if read
            .into_iter()
            .chain(write)
            .any(|code| code > octets::MAX_VAR_INT)
        {
            return Err(H3ConnectionError::H3(h3::Error::Internal));
        }

        let mut read_closed = false;
        if let Some(code) = read {
            if ctx.read_state != ReadState::Closed {
                if ctx.read_state == ReadState::Open {
                    match qconn.stream_shutdown(
                        stream_id,
                        quiche::Shutdown::Read,
                        code,
                    ) {
                        Ok(()) => ctx.handle_sent_stop_sending(code),
                        Err(quiche::Error::Done) => ctx.close_read(),
                        Err(err) => return Err(err.into()),
                    }
                } else {
                    // FIN already arrived: discard the undelivered app frame.
                    ctx.close_read();
                }
                self.waiting_streams.cancel_upstream(stream_id);
                if let Some(flow) = self.flow_map.get_mut(&stream_id) {
                    flow.close_read();
                }
                read_closed = true;
            }
        }
        if let Some(code) = write {
            if !ctx.fin_or_reset_sent {
                match qconn.stream_shutdown(
                    stream_id,
                    quiche::Shutdown::Write,
                    code,
                ) {
                    Ok(()) => ctx.handle_sent_reset(code),
                    Err(quiche::Error::Done) => ctx.close_write(),
                    Err(err) => return Err(err.into()),
                }
                self.waiting_streams.cancel_downstream(stream_id);
                if self.flow_map.contains_key(&stream_id) {
                    datagram::purge_stream_datagrams(qconn, stream_id);
                }
            }
        }
        let done = ctx.both_directions_done();
        if read_closed {
            H::stream_recv_closed(self, stream_id);
        }
        if done {
            self.cleanup_stream(qconn, stream_id);
        }
        Ok(())
    }

    /// Handles a regular [`H3Command`]. May be called internally by
    /// [`DriverHooks`] for non-endpoint-specific [`H3Command`]s.
    fn handle_core_command(
        &mut self, qconn: &mut QuicheConnection, cmd: H3Command,
    ) -> H3ConnectionResult<()> {
        match cmd {
            H3Command::QuicCmd(cmd) => cmd.execute(qconn),
            H3Command::GoAway => {
                let max_id = self.max_stream_seen.unwrap_or_default();
                self.conn_mut()?.send_goaway(qconn, max_id)?;
            },
            H3Command::ShutdownStream {
                stream_id,
                shutdown,
            } => {
                self.shutdown_stream(qconn, stream_id, shutdown)?;
            },
        }
        Ok(())
    }
}

impl<H: DriverHooks> H3Driver<H> {
    /// Demultiplex only to existing request streams (RFC 9297).
    fn process_available_dgrams(
        &mut self, qconn: &mut QuicheConnection,
    ) -> H3ConnectionResult<()> {
        loop {
            let (stream_id, dgram) = match datagram::receive_h3_dgram(qconn) {
                Ok(frame) => frame,
                Err(quiche::Error::Done) => return Ok(()),
                Err(
                    quiche::Error::BufferTooShort | quiche::Error::InvalidFrame,
                ) => {
                    let _ = qconn.close(
                        true,
                        datagram::DATAGRAM_ERROR,
                        b"invalid quarter stream ID",
                    );
                    return Err(H3ConnectionError::InvalidDatagram);
                },
                Err(err) => return Err(err.into()),
            };
            // A datagram may beat the request's HEADERS or follow its FIN.
            // Discard these, rather than creating unbounded autonomous flows.
            let Some(ctx) = self.stream_map.get(&stream_id) else {
                continue;
            };
            if ctx.read_state != ReadState::Open {
                continue;
            }
            if let Some(flow) = self.flow_map.get(&stream_id) {
                flow.send_best_effort(dgram);
            } else {
                // Ordinary HTTP requests have no defined datagram semantics.
                self.shutdown_stream(qconn, stream_id, StreamShutdown::Both {
                    read_error_code: datagram::DATAGRAM_ERROR,
                    write_error_code: datagram::DATAGRAM_ERROR,
                })?;
            }
        }
    }

    /// Flushes any queued-up frames for `stream_id` into `qconn` until either
    /// there is no more capacity in `qconn` or no more frames to send.
    fn process_writable_stream(
        &mut self, qconn: &mut QuicheConnection, stream_id: u64,
    ) -> H3ConnectionResult<()> {
        // Split self borrow between conn and stream_map
        let conn = self.conn.as_mut().ok_or(Self::connection_not_present())?;
        let Some(ctx) = self.stream_map.get_mut(&stream_id) else {
            // Keep the stop pending while headers can still create a context.
            if qconn.stream_finished(stream_id) {
                let _ = qconn.stream_capacity(stream_id);
            }

            return Ok(());
        };

        loop {
            // Process each writable frame, queue the next frame for processing
            // and shut down any errored streams.
            let write_was_open = !ctx.fin_or_reset_sent;
            match Self::process_write_frame(conn, qconn, ctx) {
                Ok(()) => ctx.queued_frame = None,
                Err(h3::Error::StreamBlocked | h3::Error::Done) => break,
                Err(h3::Error::MalformedMessage) => {
                    return self.shutdown_stream(
                        qconn,
                        stream_id,
                        StreamShutdown::Both {
                            read_error_code: WireErrorCode::MessageError as u64,
                            write_error_code: WireErrorCode::MessageError as u64,
                        },
                    );
                },
                Err(h3::Error::Transport(quiche::Error::StreamStopped(e))) => {
                    ctx.handle_recvd_stop_sending(e);
                    if write_was_open && self.flow_map.contains_key(&stream_id) {
                        datagram::purge_stream_datagrams(qconn, stream_id);
                    }

                    // An idle stream's outbound receiver can be owned by a
                    // waiting future instead of ctx.recv. Cancel it so the
                    // application cannot send another frame.
                    self.waiting_streams.cancel_downstream(stream_id);

                    if ctx.both_directions_done() {
                        self.cleanup_stream(qconn, stream_id);
                        return Ok(());
                    }
                    return Ok(());
                },
                Err(h3::Error::Transport(quiche::Error::InvalidStreamState(
                    stream,
                ))) => {
                    self.cleanup_stream(qconn, stream);
                    return Ok(());
                },
                Err(_) => {
                    self.cleanup_stream(qconn, stream_id);
                    return Ok(());
                },
            }

            if write_was_open &&
                ctx.fin_or_reset_sent &&
                self.flow_map.contains_key(&stream_id)
            {
                datagram::purge_stream_datagrams(qconn, stream_id);
            }
            if ctx.both_directions_done() {
                self.cleanup_stream(qconn, stream_id);
                return Ok(());
            }

            let Some(recv) = ctx.recv.as_mut() else {
                // This stream is already waiting for data or we wrote a fin and
                // closed the channel.
                debug_assert!(
                    ctx.queued_frame.is_none(),
                    "We MUST NOT have a queued frame if we are already waiting on 
                    more data from the channel"
                );
                return Ok(());
            };

            // Attempt to queue the next frame for processing. The corresponding
            // sender is created at the same time as the `StreamCtx`
            // and ultimately ends up in an `H3Body`. The body then
            // determines which frames to send to the peer via
            // this processing loop.
            match recv.try_recv() {
                Ok(frame) => ctx.queued_frame = Some(frame),
                Err(TryRecvError::Disconnected) => {
                    if !ctx.fin_or_reset_sent &&
                        !self.flow_map.contains_key(&stream_id)
                    // The channel might be closed if the stream was used to
                    // initiate a datagram exchange.
                    // TODO: ideally, the application would still shut down the
                    // stream properly. Once applications code
                    // is fixed, we can remove this check.
                    {
                        // No FIN was written before closure. Send RESET_STREAM
                        // because no more data will follow.
                        let err = h3::WireErrorCode::RequestCancelled as u64;
                        let _ = qconn.stream_shutdown(
                            stream_id,
                            quiche::Shutdown::Write,
                            err,
                        );
                        ctx.handle_sent_reset(err);
                        if ctx.both_directions_done() {
                            self.cleanup_stream(qconn, stream_id);
                            return Ok(());
                        }
                    }
                    break;
                },
                Err(TryRecvError::Empty) => {
                    self.waiting_streams.push(ctx.wait_for_recv(stream_id)?)?;
                    break;
                },
            }
        }

        Ok(())
    }

    /// Tests `qconn` for either a local or peer error and increments
    /// the associated HTTP/3 or QUIC error counter.
    fn record_quiche_error(qconn: &QuicheConnection, metrics: &impl Metrics) {
        // split metrics between local/peer and QUIC/HTTP/3 level errors
        if let Some(err) = qconn.local_error() {
            if err.is_app {
                metrics.local_h3_conn_close_error_count(err.error_code.into())
            } else {
                metrics.local_quic_conn_close_error_count(err.error_code.into())
            }
            .inc();
        } else if let Some(err) = qconn.peer_error() {
            if err.is_app {
                metrics.peer_h3_conn_close_error_count(err.error_code.into())
            } else {
                metrics.peer_quic_conn_close_error_count(err.error_code.into())
            }
            .inc();
        }
    }
}

impl<H: DriverHooks> ApplicationOverQuic for H3Driver<H> {
    fn on_application_ready(
        &mut self, quiche_conn: &mut QuicheConnection,
        handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        let conn = h3::Connection::with_transport(quiche_conn, &self.h3_config)?;
        self.conn = Some(conn);

        H::application_ready(self, quiche_conn, handshake_info)?;
        Ok(())
    }

    #[inline]
    fn should_act(&self) -> bool {
        self.conn.is_some()
    }

    /// Poll the underlying [`quiche::h3::Connection`] for
    /// [`quiche::h3::Event`]s and DATAGRAMs, delegating processing to
    /// `Self::process_read_event`.
    ///
    /// If a DATAGRAM is found, it is sent to the receiver on its channel.
    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.hooks.check_deadlines(qconn)?;
        loop {
            match self.conn_mut()?.poll(qconn) {
                Ok((stream_id, event)) =>
                    self.process_read_event(qconn, stream_id, event)?,
                Err(h3::Error::Done) => break,
                Err(err) => {
                    // Don't bubble error up, instead keep the worker loop going
                    // until quiche reports the connection is
                    // closed.
                    log::debug!("connection closed due to h3 protocol error"; "error"=>?err);
                    return Ok(());
                },
            }
        }

        self.process_available_dgrams(qconn)?;
        Ok(())
    }

    /// Write as much data as possible into the [`quiche::h3::Connection`] from
    /// all sources. This will attempt to write any queued frames into their
    /// respective streams, if writable.
    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.hooks.check_deadlines(qconn)?;
        while let Some(stream_id) = qconn.stream_writable_next() {
            self.process_writable_stream(qconn, stream_id)?;
        }

        // Also optimistically check for any ready streams
        while let Some(Some(ready)) = self.waiting_streams.next().now_or_never() {
            self.upstream_ready(qconn, ready)?;
        }

        H::process_pending_writes(self, qconn)?;
        Ok(())
    }

    /// Reports connection-level error metrics and forwards
    /// `IOWorker` errors to the associated [`H3Controller`].
    fn on_conn_close<M: Metrics>(
        &mut self, quiche_conn: &mut QuicheConnection, metrics: &M,
        work_loop_result: &QuicResult<()>,
    ) {
        let request_count = self.max_stream_seen.map_or(0, |id| id / 4 + 1);
        metrics
            .request_streams_opened()
            .observe(crate::metrics::histogram_value(request_count));

        Self::record_quiche_error(quiche_conn, metrics);

        let Err(work_loop_error) = work_loop_result else {
            return;
        };

        let Some(h3_err) = work_loop_error.downcast_ref::<H3ConnectionError>()
        else {
            // Errors returned by the IoWorker rather than the driver are
            // expected and already counted in metrics:
            // - `HandshakeError`: with 0-RTT early data, the handshake can
            //   still fail (e.g. time out) after the application was started.
            // - `quiche::Error`: the connection was closed by quiche, typically
            //   because of a peer protocol violation.
            if work_loop_error.is::<HandshakeError>() ||
                work_loop_error.is::<quiche::Error>()
            {
                log::debug!("connection closed by IoWorker"; "error" => %work_loop_error);
            } else {
                log::error!("Found non-H3ConnectionError"; "error" => %work_loop_error);
            }
            return;
        };

        if matches!(h3_err, H3ConnectionError::ControllerWentAway) {
            // Inform client that we won't (can't) respond anymore
            let _ = quiche_conn.close(true, WireErrorCode::NoError as u64, &[]);
            return;
        }

        let _ = self
            .h3_event_sender
            .send(H3Event::from_error(*h3_err).into());
    }

    /// Wait for incoming data from the [`H3Controller`]. The next iteration of
    /// the I/O loop commences when one of the `select!`ed futures triggers.
    #[inline]
    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        self.hooks.check_deadlines(qconn)?;
        select! {
            biased;
            r = self.hooks.wait_for_action(qconn), if H::has_wait_action(self) => r,
            Some(ready) = self.waiting_streams.next() => self.upstream_ready(qconn, ready),
            Some(stream_id) = self.flow_close_recv.recv() => self.shutdown_flow(qconn, stream_id),
            Some(dgram) = self.dgram_recv.recv() => {
                self.dgram_ready(qconn, dgram);
                Ok(())
            },
            Some(cmd) = self.cmd_recv.recv() => H::conn_command(self, qconn, cmd),
            () = self.h3_event_sender.closed(), if !self.h3_event_receiver_dropped => {
                self.h3_event_receiver_dropped = true;
                self.close_if_idle(qconn);
                Ok(())
            }
        }?;

        // Make sure controller is not starved, but also not prioritized in the
        // biased select. So poll it last, however also perform a try_recv
        // each iteration.
        if let Ok(stream_id) = self.flow_close_recv.try_recv() {
            self.shutdown_flow(qconn, stream_id)?;
        }
        if let Ok(cmd) = self.cmd_recv.try_recv() {
            H::conn_command(self, qconn, cmd)?;
        }

        Ok(())
    }
}

impl<H: DriverHooks> Drop for H3Driver<H> {
    fn drop(&mut self) {
        for stream in self.stream_map.values() {
            if stream.read_state == ReadState::Open {
                stream
                    .audit_stats
                    .set_recvd_stream_fin(StreamClosureKind::Implicit);
            }
        }
    }
}

/// [`H3Command`]s are sent by the [`H3Controller`] to alter the [`H3Driver`]'s
/// state.
///
/// Both [`ServerH3Driver`] and [`ClientH3Driver`] may extend this enum with
/// endpoint-specific variants.
#[derive(Debug)]
pub enum H3Command {
    /// A connection-level command that executes directly on the
    /// [`quiche::Connection`].
    QuicCmd(QuicCommand),
    /// Send a GOAWAY frame to the peer to initiate a graceful connection
    /// shutdown.
    GoAway,
    /// Shuts down the requested stream direction(s).
    ///
    /// This preserves any open opposite direction and sends a `RESET_STREAM`
    /// frame (for write direction) and/or a `STOP_SENDING` frame (for read
    /// direction) to the peer. See [`quiche::Connection::stream_shutdown`]
    /// for details.
    ShutdownStream {
        stream_id: u64,
        shutdown: StreamShutdown,
    },
}

/// Specifies which direction(s) of a stream to shut down.
///
/// Used with [`H3Controller::shutdown_stream`] and the internal
/// `shutdown_stream` function to control whether to send a `STOP_SENDING` frame
/// (read direction), and/or a `RESET_STREAM` frame (write direction)
///
/// Note: Despite its name, "shutdown" here refers to signaling the peer about
/// stream termination, not sending a FIN flag. `STOP_SENDING` asks the peer to
/// stop sending data, while `RESET_STREAM` abruptly terminates the write side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamShutdown {
    /// Shut down only the read direction (sends `STOP_SENDING` frame with the
    /// given error code).
    Read { error_code: u64 },
    /// Shut down only the write direction (sends `RESET_STREAM` frame with the
    /// given error code).
    Write { error_code: u64 },
    /// Shut down both directions (sends both `STOP_SENDING` and `RESET_STREAM`
    /// frames).
    Both {
        read_error_code: u64,
        write_error_code: u64,
    },
}

/// Sends [`H3Command`]s to an [`H3Driver`]. The sender is typed and internally
/// wraps instances of `T` in the appropriate `H3Command` variant.
pub struct RequestSender<C, T> {
    sender: UnboundedSender<C>,
    // Required to work around dangling type parameter
    _r: PhantomData<fn() -> T>,
}

impl<C, T> RequestSender<C, T> {
    fn new(sender: UnboundedSender<C>) -> Self {
        Self {
            sender,
            _r: PhantomData,
        }
    }
}

impl<C, T: Into<C>> RequestSender<C, T> {
    /// Sends a request to the paired driver.
    ///
    /// # Errors
    /// Returns the converted command if the driver has stopped.
    pub fn send(&self, v: T) -> Result<(), mpsc::error::SendError<C>> {
        self.sender.send(v.into())
    }
}

impl<C, T> Clone for RequestSender<C, T> {
    fn clone(&self) -> Self {
        Self::new(self.sender.clone())
    }
}

/// Interface to communicate with a paired [`H3Driver`].
///
/// An [`H3Controller`] receives [`H3Event`]s from its driver, which must be
/// consumed by the application built on top of the driver to react to incoming
/// events. The controller also allows the application to send ad-hoc
/// [`H3Command`]s to the driver, which will be processed when the driver waits
/// for incoming data.
pub struct H3Controller<H: DriverHooks> {
    /// Sends [`H3Command`]s to the [`H3Driver`], like [`QuicCommand`]s or
    /// outbound HTTP requests.
    cmd_sender: UnboundedSender<H::Command>,
    /// Receives [`H3Event`]s from the [`H3Driver`]. Can be extracted and
    /// used independently of the [`H3Controller`].
    h3_event_recv: UnboundedReceiver<H::Event>,
}

impl<H: DriverHooks> H3Controller<H> {
    /// Borrows the event receiver for the paired driver.
    pub const fn event_receiver_mut(
        &mut self,
    ) -> &mut UnboundedReceiver<H::Event> {
        &mut self.h3_event_recv
    }

    /// Consumes the controller and returns its event receiver. Clone any
    /// required command senders before transferring ownership.
    #[must_use = "the returned receiver consumes the driver's events"]
    pub fn into_event_receiver(self) -> UnboundedReceiver<H::Event> {
        self.h3_event_recv
    }

    /// Creates a [`QuicCommand`] sender for the paired driver.
    #[must_use = "the returned sender controls the QUIC connection"]
    pub fn cmd_sender(&self) -> RequestSender<H::Command, QuicCommand> {
        RequestSender::new(self.cmd_sender.clone())
    }

    /// Sends a GOAWAY frame to initiate a graceful connection shutdown.
    pub fn send_goaway(&self) {
        let _ = self.cmd_sender.send(H3Command::GoAway.into());
    }

    /// Creates an [`H3Command`] sender for the paired [`H3Driver`].
    #[must_use = "the returned sender controls the HTTP/3 connection"]
    pub fn h3_cmd_sender(&self) -> RequestSender<H::Command, H3Command> {
        RequestSender::new(self.cmd_sender.clone())
    }

    /// Shuts down the requested stream direction(s).
    ///
    /// This preserves any open opposite direction and sends a `RESET_STREAM`
    /// frame (for write direction) and/or a `STOP_SENDING` frame (for read
    /// direction) to the peer, depending on the [`StreamShutdown`] variant.
    pub fn shutdown_stream(&self, stream_id: u64, shutdown: StreamShutdown) {
        let _ = self.cmd_sender.send(
            H3Command::ShutdownStream {
                stream_id,
                shutdown,
            }
            .into(),
        );
    }
}
