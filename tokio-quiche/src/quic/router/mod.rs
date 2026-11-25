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

pub(crate) mod acceptor;
#[cfg(target_os = "linux")]
mod linux_recv;

use super::connection::ConnectionMap;
use super::connection::ConnectionMapCommand;
use super::connection::HandshakeInfo;
use super::connection::Incoming;
use super::connection::InitialQuicConnection;
use super::connection::QuicConnectionParams;
use super::connection::RouteLease;
use super::io::worker::WriterConfig;
use super::QuicheConnection;
use crate::metrics::labels;
use crate::metrics::quic_expensive_metrics_ip_reduce;
use crate::metrics::Metrics;
use crate::quic::connection::SharedConnectionIdGenerator;
use crate::quic::DscpHandle;
use crate::settings::Config;
use datagram_socket::DatagramSocketRecv;
use datagram_socket::DatagramSocketSend;
use foundations::telemetry::log;
use quiche::ConnectionId;
use quiche::Header;
use quiche::MAX_CONN_ID_LEN;
use std::default::Default;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::ready;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use task_killswitch::spawn_with_killswitch;
use tokio::sync::mpsc;

type ConnStream<Tx, M> = mpsc::Receiver<io::Result<InitialQuicConnection<Tx, M>>>;

/// How many incoming packets (GRO batches) to process before checking the
/// `ConnectionMapCommand` queue again. 30 means "check the command queue once
/// every 30 packets".
const PACKET_RX_YIELD_AFTER: usize = 30;
/// `ConnectionMapCommand` processing batch size to amortize receive operations.
const CONN_MAP_CMD_BATCH_SIZE: usize = 128;
const RECEIVE_RETRY_MIN: Duration = Duration::from_millis(1);
const RECEIVE_RETRY_MAX: Duration = Duration::from_millis(100);

#[cfg(feature = "perf-quic-listener-metrics")]
mod listener_stage_timer {
    use foundations::telemetry::metrics::TimeHistogram;
    use std::time::Instant;

    pub(super) struct ListenerStageTimer {
        start: Instant,
        time_hist: TimeHistogram,
    }

    impl ListenerStageTimer {
        pub(super) fn new(
            start: Instant, time_hist: TimeHistogram,
        ) -> ListenerStageTimer {
            ListenerStageTimer { start, time_hist }
        }
    }

    impl Drop for ListenerStageTimer {
        fn drop(&mut self) {
            self.time_hist.observe(
                u64::try_from(self.start.elapsed().as_nanos())
                    .unwrap_or(u64::MAX),
            );
        }
    }
}

/// An `InboundPacketRouter` maintains a map of quic connections and routes
/// [`Incoming`] packets from the [recv half][rh] of a datagram socket to those
/// connections or some quic initials handler. There is only 1
/// `InboundPacketRouter` per socket.
///
/// [rh]: datagram_socket::DatagramSocketRecv
///
/// When a packet (or batch of packets) is received, the router will either
/// route those packets to an established
/// [`QuicConnection`](super::QuicConnection) or have a them handled by a
/// `InitialPacketHandler` which either acts as a quic listener or
/// quic connector, a server or client respectively.
///
/// If you only have a single connection, or if you need more control over the
/// socket, use `QuicConnection` directly instead.
pub struct InboundPacketRouter<Tx, Rx, M, I>
where
    Tx: DatagramSocketSend + Send + 'static,
    M: Metrics,
{
    socket_tx: Arc<Tx>,
    socket_rx: Rx,
    local_addr: SocketAddr,
    config: Config,
    conns: ConnectionMap,
    incoming_packet_handler: I,
    shutdown_tx: Option<mpsc::Sender<()>>,
    shutdown_rx: mpsc::Receiver<()>,
    conn_map_cmd_tx: mpsc::UnboundedSender<ConnectionMapCommand>,
    conn_map_cmd_rx: mpsc::UnboundedReceiver<ConnectionMapCommand>,
    /// Reusable buffer to receive a batch of `ConnectionMapCommand`s in
    /// `poll_conn_map_commands`. Always fully drained after use, so its length
    /// should be 0 outside of `poll_conn_map_commands`.
    conn_map_cmd_buf: Vec<ConnectionMapCommand>,
    accept_sink: mpsc::Sender<io::Result<InitialQuicConnection<Tx, M>>>,
    accept_sink_closed: Pin<Box<dyn Future<Output = ()> + Send>>,
    metrics: M,
    receive_retry: Option<Pin<Box<tokio::time::Sleep>>>,
    retry_delay: Duration,
    #[cfg(target_os = "linux")]
    receiver: linux_recv::LinuxReceiver,
}

impl<Tx, Rx, M, I> InboundPacketRouter<Tx, Rx, M, I>
where
    Tx: DatagramSocketSend + Send + 'static,
    Rx: DatagramSocketRecv,
    M: Metrics,
    I: InitialPacketHandler,
{
    pub(crate) fn new(
        config: Config, socket_tx: Arc<Tx>, socket_rx: Rx,
        local_addr: SocketAddr, incoming_packet_handler: I, metrics: M,
    ) -> (Self, ConnStream<Tx, M>) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let (accept_sink, accept_stream) = mpsc::channel(config.listen_backlog);
        let accept_sink_closed = accept_sink.clone();
        let accept_sink_closed = Box::pin(async move {
            accept_sink_closed.closed().await;
        });
        let (conn_map_cmd_tx, conn_map_cmd_rx) = mpsc::unbounded_channel();

        (
            Self {
                local_addr,
                socket_tx,
                socket_rx,
                conns: ConnectionMap::default(),
                incoming_packet_handler,
                shutdown_tx: Some(shutdown_tx),
                shutdown_rx,
                conn_map_cmd_tx,
                conn_map_cmd_rx,
                conn_map_cmd_buf: Vec::with_capacity(4),
                accept_sink,
                accept_sink_closed,
                config,
                #[cfg(target_os = "linux")]
                receiver: linux_recv::LinuxReceiver::new(&metrics),
                metrics,
                receive_retry: None,
                retry_delay: RECEIVE_RETRY_MIN,
            },
            accept_stream,
        )
    }

    fn on_incoming(&mut self, incoming: Incoming) -> io::Result<()> {
        #[cfg(feature = "perf-quic-listener-metrics")]
        let start = std::time::Instant::now();

        if let Some(dcid) = short_dcid(&incoming.buf) {
            if let Some(ev_sender) = self.conns.get(&dcid) {
                let _ = ev_sender.try_send(incoming);
                return Ok(());
            }
        }

        let hdr =
            Header::from_slice(&incoming.buf, MAX_CONN_ID_LEN).map_err(|e| {
                match e {
                    quiche::Error::BufferTooShort |
                    quiche::Error::InvalidPacket =>
                        labels::QuicInvalidInitialPacketError::FailedToParse
                            .into(),
                    e => io::Error::other(e),
                }
            })?;

        if let Some(ev_sender) = self.conns.get(&hdr.dcid) {
            let _ = ev_sender.try_send(incoming);
            return Ok(());
        }

        #[cfg(feature = "perf-quic-listener-metrics")]
        let _timer = listener_stage_timer::ListenerStageTimer::new(
            start,
            self.metrics.handshake_time_seconds(
                labels::QuicHandshakeStage::HandshakeProtocol,
            ),
        );

        if self.shutdown_tx.is_none() {
            return Ok(());
        }

        let local_addr = incoming.local_addr;
        let peer_addr = incoming.peer_addr;

        #[cfg(feature = "perf-quic-listener-metrics")]
        let init_rx_time = incoming.rx_time;

        let new_connection = self.incoming_packet_handler.handle_initials(
            incoming,
            hdr,
            self.config.as_mut(),
        )?;

        match new_connection {
            Some(new_connection) => self.spawn_new_connection(
                new_connection,
                local_addr,
                peer_addr,
                #[cfg(feature = "perf-quic-listener-metrics")]
                init_rx_time,
            ),
            None => Ok(()),
        }
    }

    /// Creates a new [`QuicConnection`](super::QuicConnection) and spawns an
    /// associated io worker.
    fn spawn_new_connection(
        &mut self, new_connection: NewConnection, local_addr: SocketAddr,
        peer_addr: SocketAddr,
        #[cfg(feature = "perf-quic-listener-metrics")] init_rx_time: Option<
            SystemTime,
        >,
    ) -> io::Result<()> {
        if self.shutdown_tx.is_none() {
            return Ok(());
        }
        // Own the permit so the shared registration path can mutably borrow
        // the router without a borrow of accept_sink.
        let Ok(send_permit) = self.accept_sink.clone().try_reserve_owned() else {
            return Err(
                labels::QuicInvalidInitialPacketError::AcceptQueueOverflow.into(),
            );
        };
        let conn = self.register_connection(
            new_connection,
            local_addr,
            peer_addr,
            #[cfg(feature = "perf-quic-listener-metrics")]
            init_rx_time,
            true,
        )?;
        self.metrics.accepted_initial_packet_count().inc();
        if self.config.enable_expensive_packet_count_metrics {
            if let Some(peer_ip) =
                quic_expensive_metrics_ip_reduce(conn.peer_addr().ip())
            {
                self.metrics
                    .expensive_accepted_initial_packet_count(peer_ip)
                    .inc();
            }
        }
        send_permit.send(Ok(conn));
        Ok(())
    }

    fn register_connection(
        &mut self, new_connection: NewConnection, local_addr: SocketAddr,
        peer_addr: SocketAddr,
        #[cfg(feature = "perf-quic-listener-metrics")] init_rx_time: Option<
            SystemTime,
        >,
        allow_early_data: bool,
    ) -> io::Result<InitialQuicConnection<Tx, M>> {
        let NewConnection {
            conn,
            pending_cid,
            cid_generator,
            handshake_start_time,
            initial_pkt,
            enable_per_connection_dscp,
        } = new_connection;

        let shutdown_tx = self
            .shutdown_tx
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "router is shutting down",
                )
            })?
            .clone();
        let scid = conn.source_id().clone();
        let pending_cid = pending_cid.filter(|cid| cid != &scid);
        let owner = self.conns.allocate_owner()?;
        let writer_cfg = WriterConfig {
            peer_addr,
            local_addr,
            pending_cid: pending_cid.clone(),
            with_gso: self.config.supports(crate::socket::SocketCapability::Gso),
            pacing_offload: self
                .config
                .supports(crate::socket::SocketCapability::TransmitTime),
            with_pktinfo: self.config.supports_pktinfo(self.local_addr),
            pool_send_buffer: self.config.pool_send_buffer,
        };

        let handshake_info = HandshakeInfo::new(
            handshake_start_time,
            self.config.handshake_timeout,
        );

        let conn = InitialQuicConnection::new(QuicConnectionParams {
            writer_cfg,
            initial_pkt,
            dscp_handle: enable_per_connection_dscp.then(DscpHandle::new),
            shutdown_tx,
            route_lease: RouteLease::new(owner, self.conn_map_cmd_tx.clone()),
            scid: scid.clone(),
            cid_generator,
            metrics: self.metrics.clone(),
            connection_hook: self.config.connection_hook.clone(),
            #[cfg(feature = "perf-quic-listener-metrics")]
            init_rx_time,
            handshake_info,
            allow_early_data,
            quiche_conn: conn,
            socket: Arc::clone(&self.socket_tx),
            local_addr,
            peer_addr,
        });

        if let Some(start) = instant_to_system(handshake_start_time) {
            conn.audit_log_stats.set_transport_handshake_start(start);
        }

        self.conns.insert(
            owner,
            conn.incoming_ev_sender.clone(),
            &scid,
            pending_cid.as_ref(),
        )?;

        Ok(conn)
    }
}

/// A client socket has a single pre-registered connection and no accept path.
pub(super) struct ClientOnly;

impl InitialPacketHandler for ClientOnly {
    fn handle_initials(
        &mut self, _incoming: Incoming, _hdr: Header<'static>,
        _config: &mut quiche::Config,
    ) -> io::Result<Option<NewConnection>> {
        Ok(None)
    }
}

impl<Tx, Rx, M> InboundPacketRouter<Tx, Rx, M, ClientOnly>
where
    Tx: DatagramSocketSend + Send + 'static,
    Rx: DatagramSocketRecv,
    M: Metrics,
{
    pub(super) fn new_client(
        config: Config, socket_tx: Arc<Tx>, socket_rx: Rx,
        local_addr: SocketAddr, peer_addr: SocketAddr,
        conn: Box<QuicheConnection>, metrics: M,
    ) -> io::Result<(Self, InitialQuicConnection<Tx, M>)> {
        let (mut router, accepts) = Self::new(
            config, socket_tx, socket_rx, local_addr, ClientOnly, metrics,
        );
        let connection = router.register_connection(
            NewConnection {
                conn,
                pending_cid: None,
                initial_pkt: None,
                enable_per_connection_dscp: false,
                cid_generator: None,
                handshake_start_time: Instant::now(),
            },
            local_addr,
            peer_addr,
            #[cfg(feature = "perf-quic-listener-metrics")]
            None,
            false,
        )?;
        // This also makes shutdown follow the lifetime of the registered
        // worker.
        drop(accepts);
        Ok((router, connection))
    }
}

impl<Tx, Rx, M, I> InboundPacketRouter<Tx, Rx, M, I>
where
    Tx: DatagramSocketSend + Send + Sync + 'static,
    Rx: DatagramSocketRecv,
    M: Metrics,
    I: InitialPacketHandler,
{
    /// [`InboundPacketRouter::poll_recv_from`] should be used if the underlying
    /// system or socket does not support `rx_time` nor GRO.
    fn poll_recv_from(
        &mut self, cx: &mut Context<'_>,
    ) -> Poll<io::Result<Incoming>> {
        let mut buf = Vec::with_capacity(datagram_socket::MAX_DATAGRAM_SIZE);
        // We use ReadBuf's ability to write to uninitialized memory to avoid
        // the cost of having to initialize the Vec.
        let mut read_buf = tokio::io::ReadBuf::uninit(buf.spare_capacity_mut());
        let addr = ready!(self.socket_rx.poll_recv_from(cx, &mut read_buf))?;
        let n = read_buf.filled().len();
        // SAFETY: ReadBuf has guaranteed that `n` initialized bytes have
        // been written to the buffer, so we can set the vec's length
        // accordingly.
        unsafe {
            buf.set_len(n);
        }
        Poll::Ready(Ok(Incoming {
            buf,
            peer_addr: addr,
            local_addr: self.local_addr,
            rx_time: None,
            gro: None,
            #[cfg(target_os = "linux")]
            so_mark_data: None,
        }))
    }

    fn poll_recv_and_rx_time(
        &mut self, cx: &mut Context<'_>,
    ) -> Poll<io::Result<Incoming>> {
        #[cfg(target_os = "linux")]
        if let Some(socket) = self.socket_rx.as_udp_socket() {
            return self.receiver.poll(socket, self.local_addr, cx);
        }
        self.poll_recv_from(cx)
    }

    fn poll_process_packet(
        &mut self, cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(retry) = self.receive_retry.as_mut() {
            ready!(retry.as_mut().poll(cx));
            self.receive_retry = None;
        }
        let pkt_data = match ready!(self.poll_recv_and_rx_time(cx)) {
            Ok(packet) => {
                self.retry_delay = RECEIVE_RETRY_MIN;
                packet
            },
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                // A malformed, already-consumed datagram does not imply the
                // receiving socket is broken.
                return Poll::Ready(Ok(()));
            },
            Err(error) if retryable_receive_error(error.kind()) => {
                let mut timer = Box::pin(tokio::time::sleep(self.retry_delay));
                self.retry_delay =
                    self.retry_delay.saturating_mul(2).min(RECEIVE_RETRY_MAX);
                // Register the wakeup before returning Pending.
                if timer.as_mut().poll(cx).is_ready() {
                    cx.waker().wake_by_ref();
                }
                self.receive_retry = Some(timer);
                return Poll::Pending;
            },
            Err(error) => {
                // Fatal socket failures cannot make progress by immediately
                // repeating recvmsg. Notify the accept stream and terminate.
                let _ = self.accept_sink.try_send(Err(io::Error::new(
                    error.kind(),
                    error.to_string(),
                )));
                return Poll::Ready(Err(error));
            },
        };

        let peer_addr = pkt_data.peer_addr;
        if pkt_data.local_addr != self.local_addr {
            log::trace!("overriding local address"; "actual_local" => pkt_data.local_addr, "configured_local" => self.local_addr);
        }
        let res = self.on_incoming(pkt_data);

        // Only error handling below - if `on_incoming` was successful,
        // we return here
        let Err(e) = res else {
            return Poll::Ready(Ok(()));
        };

        let err_type = initial_packet_error_type(&e);
        self.metrics
            .rejected_initial_packet_count(err_type.clone())
            .inc();

        if self.config.enable_expensive_packet_count_metrics {
            if let Some(peer_ip) =
                quic_expensive_metrics_ip_reduce(peer_addr.ip())
            {
                self.metrics
                    .expensive_rejected_initial_packet_count(
                        err_type.clone(),
                        peer_ip,
                    )
                    .inc();
            }
        }

        if matches!(err_type, labels::QuicInvalidInitialPacketError::Unexpected) {
            // don't block packet routing on errors
            let _ = self.accept_sink.try_send(Err(e));
        }

        Poll::Ready(Ok(()))
    }

    fn poll_conn_map_commands(&mut self, cx: &mut Context<'_>) {
        let buf = &mut self.conn_map_cmd_buf;
        debug_assert!(buf.is_empty());
        if let Poll::Ready(count) =
            self.conn_map_cmd_rx
                .poll_recv_many(cx, buf, CONN_MAP_CMD_BATCH_SIZE)
        {
            for cmd in buf.drain(..) {
                self.conns.apply(cmd);
            }
            if count > 0 {
                // A successful read does not necessarily register a waker
                // for more queued commands, even when the batch is short.
                cx.waker().wake_by_ref();
            }
        }
    }
}

/// ICMP and temporary OS errors can occur on an otherwise healthy UDP socket.
const fn retryable_receive_error(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::Interrupted |
            io::ErrorKind::ConnectionRefused |
            io::ErrorKind::ConnectionReset |
            io::ErrorKind::HostUnreachable |
            io::ErrorKind::NetworkUnreachable |
            io::ErrorKind::NetworkDown |
            io::ErrorKind::TimedOut
    )
}

// Quickly extract the connection id of a short quic packet without allocating
fn short_dcid(buf: &[u8]) -> Option<ConnectionId<'_>> {
    let is_short_dcid = buf.first()? >> 7 == 0;

    if is_short_dcid {
        buf.get(1..1 + MAX_CONN_ID_LEN).map(ConnectionId::from_ref)
    } else {
        None
    }
}

/// Converts an [`Instant`] to a [`SystemTime`], based on the current delta
/// between both clocks.
fn instant_to_system(ts: Instant) -> Option<SystemTime> {
    let now = Instant::now();
    let system_now = SystemTime::now();
    if let Some(delta) = now.checked_duration_since(ts) {
        system_now.checked_sub(delta)
    } else {
        system_now.checked_add(ts.checked_duration_since(now)?)
    }
}

impl<Tx, Rx, M, I> Future for InboundPacketRouter<Tx, Rx, M, I>
where
    Tx: DatagramSocketSend + Send + Sync + 'static,
    Rx: DatagramSocketRecv + Unpin,
    M: Metrics,
    I: InitialPacketHandler + Unpin,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // First, check whether the app stopped accepting connections.
        if self.shutdown_tx.is_some() &&
            self.accept_sink_closed.as_mut().poll(cx).is_ready()
        {
            self.shutdown_tx = None;
        }

        // Second, check if all connections have shut down and we can exit.
        if self.shutdown_tx.is_none() && self.shutdown_rx.poll_recv(cx).is_ready()
        {
            return Poll::Ready(Ok(()));
        }

        // Third, run the generic `InitialPacketHandler` update.
        if let Err(error) = self.incoming_packet_handler.update(cx) {
            // An error here is so rare that it's easier to spawn a separate
            // task
            let sender = self.accept_sink.clone();
            spawn_with_killswitch(async move {
                let _ = sender.send(Err(error)).await;
            });
        }

        // Fourth, update ConnectionMap before receiving packets so SCID
        // destinations are current. Process one bounded batch per poll.
        self.poll_conn_map_commands(cx);

        // Finally, process up to `PACKET_RX_YIELD_AFTER` packet batches. If
        // no more packets are available, wait to be woken again.
        for _ in 0..PACKET_RX_YIELD_AFTER {
            ready!(self.poll_process_packet(cx))?;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Categorizes errors that are returned when handling packets which are not
/// associated with an established connection. The purpose is to suppress
/// logging of 'expected' errors (e.g. junk data sent to the UDP socket) to
/// prevent `DoS`.
fn initial_packet_error_type(
    e: &io::Error,
) -> labels::QuicInvalidInitialPacketError {
    Some(e)
        .filter(|e| e.kind() == io::ErrorKind::Other)
        .and_then(io::Error::get_ref)
        .and_then(|e| e.downcast_ref())
        .map_or(
            labels::QuicInvalidInitialPacketError::Unexpected,
            Clone::clone,
        )
}

/// An [`InitialPacketHandler`] handles unknown quic initials and processes
/// them; generally accepting new connections (acting as a server), or
/// establishing a connection to a server (acting as a client). An
/// [`InboundPacketRouter`] holds an instance of this trait and routes
/// [`Incoming`] packets to it when it receives initials.
///
/// The handler produces [`quiche::Connection`]s which are then turned into
/// [`QuicConnection`](super::QuicConnection), `IoWorker` pair.
pub trait InitialPacketHandler {
    fn update(&mut self, _ctx: &mut Context<'_>) -> io::Result<()> {
        Ok(())
    }

    fn handle_initials(
        &mut self, incoming: Incoming, hdr: Header<'static>,
        quiche_config: &mut quiche::Config,
    ) -> io::Result<Option<NewConnection>>;
}

/// A [`NewConnection`] describes a new [`quiche::Connection`] that can be
/// driven by an io worker.
pub struct NewConnection {
    /// See [`QuicConnectionParams::quiche_conn`].
    conn: Box<QuicheConnection>,
    pending_cid: Option<ConnectionId<'static>>,
    initial_pkt: Option<Incoming>,
    enable_per_connection_dscp: bool,
    cid_generator: Option<SharedConnectionIdGenerator>,
    /// When the handshake started. Should be called before [`quiche::accept`]
    /// or [`quiche::connect`].
    handshake_start_time: Instant,
}

// TODO: the router module is private so we can't move these to /tests
// TODO: Rewrite tests to be Windows compatible
#[cfg(all(test, unix))]
mod tests {
    use super::acceptor::ConnectionAcceptor;
    use super::acceptor::ConnectionAcceptorConfig;
    use super::*;

    use crate::http3::settings::Http3Settings;
    use crate::metrics::DefaultMetrics;
    use crate::quic::connection::SimpleConnectionIdGenerator;
    use crate::quic::Dscp;
    use crate::settings::Config;
    use crate::settings::Hooks;
    use crate::settings::QuicSettings;
    use crate::settings::TlsCertificatePaths;
    use crate::socket::SocketCapabilities;
    use crate::ConnectionParams;
    use crate::ServerH3Driver;

    use datagram_socket::MAX_DATAGRAM_SIZE;
    use futures::FutureExt as _;
    use h3i::actions::h3::Action;
    use h3i::actions::h3::WaitType;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time;

    fn test_credentials() -> (&'static str, &'static str) {
        static CREDENTIALS: std::sync::OnceLock<(String, String)> =
            std::sync::OnceLock::new();

        let (cert, key) = CREDENTIALS.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!(
                "tokio-quiche-test-credentials-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();

            let cert = dir.join("cert.crt");
            let key = dir.join("cert.key");
            std::fs::write(
                &cert,
                include_bytes!("../../../../quiche/examples/cert.crt"),
            )
            .unwrap();
            std::fs::write(
                &key,
                include_bytes!("../../../../quiche/examples/cert.key"),
            )
            .unwrap();

            (
                cert.to_string_lossy().into_owned(),
                key.to_string_lossy().into_owned(),
            )
        });

        (cert.as_str(), key.as_str())
    }

    fn test_connect(host_port: String, wait_before_close: Option<Duration>) {
        let mut h3i_config = h3i::config::Config::new("test.com").unwrap();
        h3i_config.idle_timeout = 2000;
        h3i_config.endpoint.connect_to = Some(host_port.parse().unwrap());
        h3i_config.tls.verify_peer = false;
        h3i_config.datagrams = Some(h3i::config::DatagramQueues::default());

        let conn_close = h3i::quiche::ConnectionError {
            is_app: true,
            error_code: h3i::quiche::WireErrorCode::NoError as _,
            reason: Vec::new(),
        };
        let mut actions = Vec::new();
        if let Some(duration) = wait_before_close {
            actions.push(Action::Wait {
                wait_type: WaitType::WaitDuration(duration),
            });
        }
        actions.push(Action::ConnectionClose { error: conn_close });

        let _ = h3i::client::sync_client::connect(h3i_config, actions, None);
    }

    #[tokio::test]
    async fn test_timeout() -> crate::QuicResult<()> {
        // Configure a short idle timeout to speed up connection reclamation as
        // quiche doesn't support time mocking
        let quic_settings = QuicSettings {
            max_idle_timeout: Some(Duration::from_millis(1)),
            max_recv_udp_payload_size: MAX_DATAGRAM_SIZE,
            max_send_udp_payload_size: MAX_DATAGRAM_SIZE,
            ..Default::default()
        };

        let (cert, private_key) = test_credentials();
        let tls_cert_settings = TlsCertificatePaths {
            cert,
            private_key,
            kind: crate::settings::CertificateKind::X509,
        };

        let mut params = ConnectionParams::new_server(
            quic_settings,
            tls_cert_settings,
            Hooks::default(),
        );
        params.enable_per_connection_dscp = true;
        let config = Config::new(&params, SocketCapabilities::default())?;

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = socket.local_addr()?;
        let host_port = local_addr.to_string();
        let socket_tx = Arc::new(socket);
        let socket_rx = Arc::clone(&socket_tx);

        let acceptor = ConnectionAcceptor::new(
            ConnectionAcceptorConfig {
                disable_client_ip_validation: config.disable_client_ip_validation,
                reply_backlog: config.listen_backlog,
                enable_per_connection_dscp: params.enable_per_connection_dscp,
                qlog_dir: config.qlog_dir.clone(),
                qlog_compression: config.qlog_compression,
                keylog_file: config
                    .keylog_file
                    .as_ref()
                    .and_then(|f| f.try_clone().ok()),
                #[cfg(target_os = "linux")]
                with_pktinfo: false,
            },
            Arc::clone(&socket_tx),
            Arc::new(SimpleConnectionIdGenerator),
            DefaultMetrics,
        )?;

        let (socket_driver, mut incoming) = InboundPacketRouter::new(
            config,
            socket_tx,
            socket_rx,
            local_addr,
            acceptor,
            DefaultMetrics,
        );
        tokio::spawn(socket_driver);

        // Start a request and drop it after connection establishment
        std::thread::spawn(move || test_connect(host_port, None));

        // Wait for a new connection
        time::pause();

        let (h3_driver, _) = ServerH3Driver::new(&Http3Settings::default());
        let conn = incoming.recv().await.ok_or("listener closed")??;
        let dscp_handle =
            conn.dscp_handle().ok_or("missing DSCP handle")?.clone();
        assert_eq!(dscp_handle.get(), None);
        dscp_handle.set(Dscp::new(0));
        assert_eq!(
            conn.dscp_handle().ok_or("missing DSCP handle")?.get(),
            Dscp::new(0)
        );
        let drop_check = conn.incoming_ev_sender.clone();
        let _conn = conn.start(h3_driver);

        // Poll incoming events until the connection is dropped.
        time::advance(Duration::new(30, 0)).await;
        time::resume();

        // This is a smoke test. A failure leaves `notified()` unresolved and
        // hangs the test.
        drop_check.closed().await;
        Ok(())
    }

    #[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
    #[tokio::test]
    async fn test_worker_dscp_across_handshake_ipv4() {
        check_worker_dscp_across_handshake("127.0.0.1:0").await;
    }

    #[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
    #[tokio::test]
    async fn test_worker_dscp_across_handshake_ipv6() {
        check_worker_dscp_across_handshake("[::1]:0").await;
    }

    #[cfg(all(target_os = "linux", not(feature = "fuzzing")))]
    async fn check_worker_dscp_across_handshake(bind_addr: &str) {
        use crate::quic::io::gso::test::enable_tos;
        use crate::quic::io::gso::test::recv_tos;
        use futures::StreamExt;
        use nix::sys::socket::setsockopt;
        use nix::sys::socket::sockopt;

        let socket = std::net::UdpSocket::bind(bind_addr).unwrap();
        let server_addr = socket.local_addr().unwrap();
        if server_addr.is_ipv4() {
            setsockopt(&socket, sockopt::Ipv4Tos, &0).unwrap();
        } else {
            setsockopt(&socket, sockopt::Ipv6TClass, &0).unwrap();
        }

        let mut settings = QuicSettings::default();
        settings.disable_client_ip_validation = true;
        let (cert, private_key) = test_credentials();
        let tls_cert = TlsCertificatePaths {
            cert,
            private_key,
            kind: crate::settings::CertificateKind::X509,
        };
        let mut params =
            ConnectionParams::new_server(settings, tls_cert, Hooks::default());
        params.enable_per_connection_dscp = true;
        let mut incoming = crate::listen(vec![socket], params, DefaultMetrics)
            .unwrap()
            .remove(0);

        let frontend = UdpSocket::bind(bind_addr).await.unwrap();
        let backend = UdpSocket::bind(bind_addr).await.unwrap();
        enable_tos(&backend);
        let host_port = frontend.local_addr().unwrap().to_string();
        let (marks_tx, mut marks_rx) = tokio::sync::mpsc::unbounded_channel();
        let relay = tokio::spawn(async move {
            let mut client_addr = None;
            let mut buf = [0u8; 2048];
            loop {
                tokio::select! {
                    received = frontend.recv_from(&mut buf) => {
                        let (len, addr) = received.unwrap();
                        client_addr = Some(addr);
                        backend.send_to(&buf[..len], server_addr).await.unwrap();
                    }
                    (packet, tos) = recv_tos(&backend) => {
                        marks_tx.send(tos >> 2).unwrap();
                        frontend.send_to(&packet, client_addr.unwrap()).await.unwrap();
                    }
                }
            }
        });
        let client = tokio::task::spawn_blocking(move || {
            test_connect(host_port, Some(Duration::from_secs(1)))
        });

        let conn = time::timeout(Duration::from_secs(5), incoming.next())
            .await
            .expect("no initial packet")
            .expect("listener closed")
            .expect("initial packet rejected");
        let dscp = conn.dscp_handle().unwrap().clone();
        dscp.set(Dscp::new(34));
        let (driver, controller) = ServerH3Driver::new(&Http3Settings::default());
        let (_, mut worker) =
            time::timeout(Duration::from_secs(5), conn.handshake(driver))
                .await
                .expect("handshake timed out")
                .expect("handshake failed");

        // No stateless packets are sent when client IP validation is disabled.
        assert_eq!(
            time::timeout(Duration::from_secs(5), marks_rx.recv())
                .await
                .expect("no handshake packet"),
            Some(34)
        );

        // Force a packet in the running worker to verify the handle survives
        // handshake() and resume(), not just the initial atomic clone.
        dscp.set(Dscp::new(28));
        worker.qconn.send_ack_eliciting().unwrap();
        InitialQuicConnection::resume(worker);
        time::timeout(Duration::from_secs(5), async {
            loop {
                match marks_rx.recv().await.expect("UDP relay closed") {
                    34 => (), // Handshake packets already in flight.
                    28 => break,
                    mark => panic!("unexpected post-handshake DSCP {mark}"),
                }
            }
        })
        .await
        .expect("no post-handshake packet with DSCP 28");

        client.await.unwrap();
        drop(controller);
        relay.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_listener_releases_socket_after_stream_drop() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let streams =
            crate::listen([socket], ConnectionParams::default(), DefaultMetrics)
                .unwrap();

        time::sleep(Duration::from_millis(20)).await;
        drop(streams);

        time::timeout(Duration::from_secs(1), async {
            loop {
                match UdpSocket::bind(addr).await {
                    Ok(_) => break,
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                        time::sleep(Duration::from_millis(5)).await;
                    },
                    Err(error) => {
                        panic!("failed to rebind listener socket: {error}")
                    },
                }
            }
        })
        .await
        .expect("idle listener retained its socket after stream drop");
    }

    struct NoopDatagramSender;
    impl DatagramSocketSend for NoopDatagramSender {
        fn poll_send(
            &self, _cx: &mut Context, buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_send_to(
            &self, _cx: &mut Context, buf: &[u8], _addr: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
    }

    struct AlwaysReadyReceiver;
    impl DatagramSocketRecv for AlwaysReadyReceiver {
        fn poll_recv(
            &mut self, _cx: &mut Context, buf: &mut tokio::io::ReadBuf,
        ) -> Poll<io::Result<()>> {
            // Short header packet:
            // 1 byte descriptor + 20 byte DCID + 1 byte packet number + payload
            const DUMMY_QUIC_PACKET: &[u8] =
                b"\x40THIS_20_BYTE_CONN_ID\x06payload_payload_payload";
            buf.put_slice(DUMMY_QUIC_PACKET);
            Poll::Ready(Ok(()))
        }
    }

    struct NoopInitialHandler;
    impl InitialPacketHandler for NoopInitialHandler {
        fn handle_initials(
            &mut self, _incoming: Incoming, _hdr: Header<'static>,
            _quiche_config: &mut quiche::Config,
        ) -> io::Result<Option<NewConnection>> {
            Ok(None)
        }
    }

    fn test_router<R: DatagramSocketRecv>(
        receiver: R,
    ) -> crate::QuicResult<(
        InboundPacketRouter<
            NoopDatagramSender,
            R,
            DefaultMetrics,
            NoopInitialHandler,
        >,
        ConnStream<NoopDatagramSender, DefaultMetrics>,
    )> {
        let (cert, private_key) = test_credentials();
        let tls_cert_settings = TlsCertificatePaths {
            cert,
            private_key,
            kind: crate::settings::CertificateKind::X509,
        };
        let params = ConnectionParams::new_server(
            QuicSettings::default(),
            tls_cert_settings,
            Hooks::default(),
        );

        let config = Config::new(&params, SocketCapabilities::default())?;
        Ok(InboundPacketRouter::new(
            config,
            Arc::new(NoopDatagramSender),
            receiver,
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            NoopInitialHandler,
            DefaultMetrics,
        ))
    }

    struct ErrorReceiver {
        kind: io::ErrorKind,
        calls: usize,
    }
    impl DatagramSocketRecv for ErrorReceiver {
        fn poll_recv(
            &mut self, _cx: &mut Context<'_>, _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.calls += 1;
            Poll::Ready(Err(self.kind.into()))
        }
    }

    #[test]
    fn fatal_receive_error_terminates_router_and_reaches_accept_stream(
    ) -> crate::QuicResult<()> {
        let (mut router, mut accepts) = test_router(ErrorReceiver {
            kind: io::ErrorKind::PermissionDenied,
            calls: 0,
        })?;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(Err(error)) = router.poll_unpin(&mut cx) else {
            return Err("router did not terminate".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(router.socket_rx.calls, 1);
        let Err(error) = accepts.try_recv()? else {
            return Err("expected accept error".into());
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        Ok(())
    }

    #[tokio::test]
    async fn transient_receive_errors_back_off_and_shutdown_still_progresses(
    ) -> crate::QuicResult<()> {
        tokio::time::pause();
        let (mut router, accepts) = test_router(ErrorReceiver {
            kind: io::ErrorKind::ConnectionRefused,
            calls: 0,
        })?;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(router.poll_unpin(&mut cx).is_pending());
        assert_eq!(router.socket_rx.calls, 1);
        assert!(router.poll_unpin(&mut cx).is_pending());
        assert_eq!(router.socket_rx.calls, 1);
        // Wait on the actual registered deadline, including the runtime's
        // timer-wheel rounding, rather than assuming a one-tick advance.
        router
            .receive_retry
            .as_mut()
            .ok_or("missing retry timer")?
            .as_mut()
            .await;
        assert!(router.poll_unpin(&mut cx).is_pending());
        assert_eq!(router.socket_rx.calls, 2);
        assert_eq!(router.retry_delay, RECEIVE_RETRY_MIN * 4);
        drop(accepts);
        assert!(matches!(router.poll_unpin(&mut cx), Poll::Ready(Ok(()))));
        Ok(())
    }

    #[test]
    fn test_poll_packet_always_ready() -> crate::QuicResult<()> {
        let (mut ipr, accept_stream) = test_router(AlwaysReadyReceiver)?;
        let conn_map_cmd_tx = ipr.conn_map_cmd_tx.clone();
        let owner = ipr.conns.allocate_owner()?;

        let mut cx = Context::from_waker(std::task::Waker::noop());
        for _ in 0..CONN_MAP_CMD_BATCH_SIZE + 1 {
            conn_map_cmd_tx
                .send(ConnectionMapCommand::Close(owner))
                .map_err(|_| "router command channel closed")?;
        }
        assert!(ipr.poll_unpin(&mut cx).is_pending());
        assert_eq!(ipr.conn_map_cmd_rx.len(), 1);
        assert!(ipr.poll_unpin(&mut cx).is_pending());
        assert!(ipr.conn_map_cmd_rx.is_empty());
        drop(accept_stream);
        assert!(matches!(ipr.poll_unpin(&mut cx), Poll::Ready(Ok(()))));
        Ok(())
    }
}
