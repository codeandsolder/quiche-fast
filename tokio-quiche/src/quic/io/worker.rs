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

use std::future::Future;
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;
#[cfg(feature = "perf-quic-listener-metrics")]
use std::time::SystemTime;

use super::connection_stage::Close;
use super::connection_stage::ConnectionStage;
use super::connection_stage::ConnectionStageContext;
use super::connection_stage::Handshake;
use super::connection_stage::RunningApplication;
use super::gso::recoverable_send_error;
use super::gso::send_packets_before;
#[cfg(not(feature = "gcongestion"))]
use super::gso::tune_max_send_size;
use super::gso::PacketSend;
use super::gso::SendOutcome;
use super::gso::UDP_MAX_GSO_PACKET_SIZE;
use super::gso::UDP_MAX_SEGMENT_COUNT;
use super::utilization_estimator::BandwidthReporter;

use crate::metrics::labels;
use crate::metrics::Metrics;
use crate::quic::connection::replace_shared_stats;
use crate::quic::connection::ApplicationOverQuic;
use crate::quic::connection::HandshakeError;
use crate::quic::connection::HandshakeInfo;
use crate::quic::connection::Incoming;
use crate::quic::connection::QuicConnectionStats;
use crate::quic::connection::RouteLease;
use crate::quic::connection::SharedConnectionIdGenerator;
use crate::quic::hooks::ConnectionHook;
use crate::quic::DscpHandle;
use crate::quic::QuicheConnection;
use crate::socket::SocketCapabilities;
use crate::socket::SocketCapability;
use crate::QuicResult;

use btls::ssl::SslRef;
use datagram_socket::DatagramSocketSend;
use datagram_socket::MaybeConnectedSocket;
use datagram_socket::QuicAuditStats;
use datagram_socket::QuicCloseCode;
use foundations::telemetry::log;
use foundations::telemetry::metrics::Gauge;
use foundations::telemetry::metrics::GaugeGuard;
use quiche::ConnectionId;
use quiche::Error as QuicheError;
use quiche::SendInfo;
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time;
use tokio_util::sync::CancellationToken;

// Number of incoming packets to be buffered in the incoming channel.
pub const INCOMING_QUEUE_SIZE: usize = 2048;

// Check if there are any incoming packets while sending data every this number
// of sent packets
const CHECK_INCOMING_QUEUE_RATIO: usize = INCOMING_QUEUE_SIZE / 16;

// Only used when the core has no armed timer (e.g. idle timeout disabled).
// A permanently blocked custom transport must not retain an egress buffer
// forever.
const MAX_UNTIMED_SEND_WAIT: Duration = Duration::from_secs(60);
/// Final close notification is best effort; never hold the route indefinitely.
const CLOSE_SEND_WAIT: Duration = Duration::from_secs(1);

const RELEASE_TIMER_THRESHOLD: Duration = Duration::from_micros(250);

/// Stop queuing GSO packets, if packet size is below this threshold.
const GSO_THRESHOLD: usize = 1_000;

/// Size of each full egress buffer borrowed for a send burst.
///
/// Matches the maximum quiche buffer size so GSO batching is unaffected while
/// a connection is actively sending. Unlike a persistent per-connection
/// buffer, this memory is returned to the per-worker [`SEND_BUF_POOL`] before
/// the worker sleeps. The free list retains it for reuse (rather than truly
/// freeing it) but no idle connection owns an egress buffer.
const SEND_BUFFER_SIZE: usize = crate::buf_factory::BufFactory::MAX_BUF_SIZE;

/// Size of a temporary egress buffer when pooling is disabled.
///
/// The cold handshake and connection-close paths generate a single datagram at
/// a time. When pooling is enabled, they borrow a full-size buffer from
/// [`SEND_BUF_POOL`]; otherwise a one-MTU buffer is enough.
const TRANSIENT_SEND_BUFFER_SIZE: usize = 1500;

/// Allocates a zero-initialized egress buffer on the heap.
///
/// This is the cold path that fills [`SEND_BUF_POOL`] on a miss; steady-state
/// bursts borrow a recycled buffer via [`PooledSendBuf::acquire`] and never
/// hit this. The buffer is boxed (never a stack array) so that holding it
/// across the `.await` in [`IoWorker::flush_buffer_to_socket`] keeps the
/// worker's futures small and avoids uncontrolled stack growth.
fn alloc_send_buffer() -> Box<[u8]> {
    vec![0u8; SEND_BUFFER_SIZE].into_boxed_slice()
}

thread_local! {
    /// Per-runtime-worker free-list of egress scratch buffers.
    ///
    /// A buffer is borrowed for a single send burst and returned on drop, so
    /// its pages stay resident across bursts (no per-burst page fault or
    /// kernel zero-fill) while no idle connection retains a buffer: the pool
    /// holds at most [`SEND_BUF_POOL_CAP`] buffers per worker thread,
    /// independent of the connection count.
    static SEND_BUF_POOL: std::cell::RefCell<Vec<Box<[u8]>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Upper bound on egress buffers parked per worker thread. The natural
/// high-water mark is the number of connection tasks simultaneously suspended
/// at a flush `.await` on one runtime thread; returns beyond the cap are freed
/// so a burst spike cannot pin unbounded memory to a thread.
///
/// This is a fixed per-worker-thread reservation, independent of the
/// connection count: up to `SEND_BUF_POOL_CAP * SEND_BUFFER_SIZE`
/// (16 * 64 KiB = 1 MiB) per runtime worker thread. The pool is not shrunk
/// once grown, so after a burst it stays at its high-water mark for the
/// process lifetime.
const SEND_BUF_POOL_CAP: usize = 16;

/// Egress scratch buffer borrowed from the per-thread [`SEND_BUF_POOL`] and
/// returned to it on drop.
///
/// Behaves like the `Box<[u8]>` it replaces via `Deref`/`DerefMut`, so idle
/// connections still retain no egress buffer, but the backing pages are
/// recycled instead of re-faulted (and re-zeroed by the kernel) every burst.
struct PooledSendBuf(Box<[u8]>);

impl PooledSendBuf {
    fn acquire() -> Self {
        let buf = SEND_BUF_POOL
            .with(|pool| pool.borrow_mut().pop())
            .unwrap_or_else(|| {
                // Pool miss (cold path): allocate a fresh buffer and record it.
                // Re-using a parked buffer (the hot path) does not touch any
                // counter.
                crate::metrics::quic::send_buffer_pool_allocated().inc();
                alloc_send_buffer()
            });
        // No re-zeroing on reuse: quiche writes only the bytes it emits and
        // the flush path transmits solely `send_buf[..bytes_written]`, so any
        // stale bytes left by a previous burst are never sent.
        Self(buf)
    }
}

impl Drop for PooledSendBuf {
    fn drop(&mut self) {
        // Move the buffer out, leaving an empty (non-allocating) boxed slice
        // behind, so it can be returned to the pool. Storing a plain
        // `Box<[u8]>` rather than an `Option` keeps `Deref`/`DerefMut`
        // panic-free.
        let buf = std::mem::take(&mut self.0);
        // Returns to *this* thread's pool. With tokio work-stealing a task may
        // migrate across the flush `.await`, so a buffer can be acquired on one
        // worker and returned on another; this is benign, and the per-thread
        // cap keeps the total bounded by `cap * workers`.
        SEND_BUF_POOL.with(|pool| {
            let mut pool = pool.borrow_mut();
            if pool.len() < SEND_BUF_POOL_CAP {
                pool.push(buf);
            } else {
                // Pool already at capacity (cold path, only under burst
                // spikes): drop the buffer instead of parking it, and record
                // the discard. Returning to a non-full pool (the hot path)
                // does not touch any counter.
                crate::metrics::quic::send_buffer_pool_discarded().inc();
            }
        });
    }
}

impl std::ops::Deref for PooledSendBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::DerefMut for PooledSendBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Egress buffer used briefly outside the main write loop.
///
/// This preserves the runtime pooling switch for handshake and close paths:
/// pooling borrows a full-size recycled buffer, while disabling it allocates a
/// small one-off buffer.
enum TransientSendBuf {
    Pooled(PooledSendBuf),
    Unpooled(Box<[u8]>),
}

impl TransientSendBuf {
    fn acquire(pool_send_buffer: bool) -> Self {
        if pool_send_buffer {
            Self::Pooled(PooledSendBuf::acquire())
        } else {
            Self::Unpooled(
                vec![0u8; TRANSIENT_SEND_BUFFER_SIZE].into_boxed_slice(),
            )
        }
    }
}

impl AsRef<[u8]> for TransientSendBuf {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Pooled(buf) => &buf[..],
            Self::Unpooled(buf) => &buf[..],
        }
    }
}

impl AsMut<[u8]> for TransientSendBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Pooled(buf) => &mut buf[..],
            Self::Unpooled(buf) => &mut buf[..],
        }
    }
}

pub struct WriterConfig {
    pub pending_cid: Option<ConnectionId<'static>>,
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub socket_capabilities: SocketCapabilities,
    /// Whether the worker borrows its egress buffer from a per-worker-thread
    /// pool for each send burst. When `false`, the worker keeps a persistent
    /// per-connection buffer for its lifetime instead.
    pub pool_send_buffer: bool,
}

#[derive(Default)]
pub struct WriteState {
    conn_established: bool,
    bytes_written: usize,
    segment_size: usize,
    num_pkts: usize,
    tx_time: Option<Instant>,
    has_pending_data: bool,
    // If pacer schedules packets too far into the future, we want to pause
    // sending, until the future arrives
    next_release_time: Option<Instant>,
    // The selected source and destination addresses for the current write
    // cycle.
    selected_path: Option<(SocketAddr, SocketAddr)>,
    // Iterator over the network paths that haven't been flushed yet.
    pending_paths: quiche::SocketAddrIter,
}

pub struct IoWorkerParams<Tx, M> {
    pub(crate) socket: MaybeConnectedSocket<Tx>,
    pub(crate) shutdown_tx: mpsc::Sender<()>,
    pub(crate) cfg: WriterConfig,
    pub(crate) audit_log_stats: Arc<QuicAuditStats>,
    pub(crate) write_state: WriteState,
    pub(crate) dscp_handle: Option<DscpHandle>,
    pub(in crate::quic) route_lease: RouteLease,
    pub(crate) active_connection: GaugeGuard<Gauge>,
    pub(in crate::quic) bw_estimator: BandwidthReporter,
    pub(crate) cid_generator: Option<SharedConnectionIdGenerator>,
    #[cfg(feature = "perf-quic-listener-metrics")]
    pub(crate) init_rx_time: Option<SystemTime>,
    pub(crate) metrics: M,
    pub(crate) handshake_info: HandshakeInfo,
    pub(crate) shutdown_request: CancellationToken,
    // Dropped after the worker-owned route, gauge and socket handles.
    pub(crate) completion: oneshot::Sender<()>,
}

fn notify_path_events(
    connection_hook: Option<&(dyn ConnectionHook + Send + Sync + 'static)>,
    qconn: &mut QuicheConnection,
) {
    while let Some(path_event) = qconn.path_event_next() {
        if let Some(hook) = connection_hook {
            hook.on_path_event(qconn, &path_event);
        }
    }
}

pub struct IoWorker<Tx, M, S> {
    socket: MaybeConnectedSocket<Tx>,
    /// A field that signals to the listener task that the connection has gone
    /// away (nothing is sent here, listener task just detects the sender
    /// has dropped)
    shutdown_tx: mpsc::Sender<()>,
    cfg: WriterConfig,
    audit_log_stats: Arc<QuicAuditStats>,
    write_state: WriteState,
    dscp_handle: Option<DscpHandle>,
    route_lease: RouteLease,
    active_connection: GaugeGuard<Gauge>,
    cid_generator: Option<SharedConnectionIdGenerator>,
    #[cfg(feature = "perf-quic-listener-metrics")]
    init_rx_time: Option<SystemTime>,
    metrics: M,
    /// The handshake deadline is enforced by the worker until the handshake
    /// completes, regardless of the connection stage. With 0-RTT early data,
    /// the application is started before the handshake completes, and a peer
    /// that never completes it could otherwise keep the connection in early
    /// data indefinitely.
    handshake_info: HandshakeInfo,
    conn_stage: S,
    bw_estimator: BandwidthReporter,
    shutdown_request: CancellationToken,
    completion: oneshot::Sender<()>,
}

impl<Tx, M, S> IoWorker<Tx, M, S>
where
    Tx: DatagramSocketSend + Send,
    M: Metrics,
    S: ConnectionStage,
{
    pub(crate) fn new(params: IoWorkerParams<Tx, M>, conn_stage: S) -> Self {
        log::trace!("Creating IoWorker with stage: {conn_stage:?}");

        Self {
            socket: params.socket,
            shutdown_tx: params.shutdown_tx,
            cfg: params.cfg,
            audit_log_stats: params.audit_log_stats,
            write_state: params.write_state,
            dscp_handle: params.dscp_handle,
            route_lease: params.route_lease,
            active_connection: params.active_connection,
            cid_generator: params.cid_generator,
            #[cfg(feature = "perf-quic-listener-metrics")]
            init_rx_time: params.init_rx_time,
            metrics: params.metrics,
            handshake_info: params.handshake_info,
            conn_stage,
            bw_estimator: params.bw_estimator,
            shutdown_request: params.shutdown_request,
            completion: params.completion,
        }
    }

    async fn refresh_connection_ids(
        route_lease: &RouteLease,
        cid_generator: Option<&SharedConnectionIdGenerator>,
        qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        while let Some(retired_cid) = qconn.retired_scid_next() {
            route_lease.retire(retired_cid);
        }
        let Some(cid_generator) = cid_generator else {
            return Ok(());
        };
        for _ in 0..qconn.scids_left() {
            let reset_token = random_u128()?;
            let new_cid = crate::quic::connection::generate_routable_cid(
                cid_generator.as_ref(),
            )?;
            // The router must acknowledge ownership before the core can
            // advertise the CID. A collision must never reach the wire.
            route_lease.register(new_cid.clone()).await?;
            if let Err(error) = qconn.new_scid(&new_cid, reset_token, false) {
                route_lease.retire(new_cid);
                return Err(error.into());
            }
        }
        Ok(())
    }

    /// Cancellation covers the whole I/O loop, including blocked writes and
    /// CID registration. Egress generated before cancellation is never
    /// replayed; close emits a fresh best-effort `CONNECTION_CLOSE` flight.
    async fn work_loop<A: ApplicationOverQuic>(
        &mut self, qconn: &mut QuicheConnection,
        ctx: &mut ConnectionStageContext<A>,
    ) -> QuicResult<()> {
        let request = self.shutdown_request.clone();
        tokio::select! {
            biased;
            () = request.cancelled() => {
                let _ = qconn.close(false, quiche::WireErrorCode::NoError as u64, &[]);
                if qconn.is_established() {
                    Ok(())
                } else {
                    Err(HandshakeError::ConnectionClosed.into())
                }
            },
            result = self.drive_connection(qconn, ctx) => result,
        }
    }

    async fn drive_connection<A: ApplicationOverQuic>(
        &mut self, qconn: &mut QuicheConnection,
        ctx: &mut ConnectionStageContext<A>,
    ) -> QuicResult<()> {
        const DEFAULT_SLEEP: Duration = Duration::from_secs(60);
        let mut current_deadline: Option<Instant> = None;
        let sleep = time::sleep(DEFAULT_SLEEP);
        tokio::pin!(sleep);

        // Without pooling, the IO worker owns one egress buffer for the entire
        // connection, including idle periods. With pooling, this remains `None`
        // and each send burst borrows a buffer from the per-worker pool.
        let mut persistent_send_buf: Option<Box<[u8]>> =
            (!self.cfg.pool_send_buffer).then(alloc_send_buffer);

        loop {
            self.enforce_handshake_deadline(qconn)?;
            let now = Instant::now();

            if self
                .drive_io_burst(qconn, ctx, &mut persistent_send_buf)
                .await?
                .is_break()
            {
                return Ok(());
            }

            self.bw_estimator.update(qconn, Instant::now());

            self.audit_log_stats
                .set_max_bandwidth(self.bw_estimator.max_bandwidth);
            self.audit_log_stats
                .set_max_loss_pct(self.bw_estimator.max_loss.rounded_percent());

            let new_deadline = min_of_some(
                qconn.timeout_instant(),
                self.write_state.next_release_time,
            );
            let new_deadline =
                min_of_some(new_deadline, self.handshake_deadline(qconn));

            if new_deadline != current_deadline {
                current_deadline = new_deadline;

                sleep
                    .as_mut()
                    .reset(new_deadline.unwrap_or(now + DEFAULT_SLEEP).into());
            }

            let incoming_recv = &mut ctx.incoming_pkt_receiver;
            let application = &mut ctx.application;

            select! {
                biased;
                () = &mut sleep => {
                    // It's very important that we keep the timeout arm at the top of this loop so
                    // that we poll it every time we need to. Since this is a biased `select!`, if
                    // we put this behind another arm, we could theoretically starve the sleep arm
                    // and hang connections.
                    //
                    // See https://docs.rs/tokio/latest/tokio/macro.select.html#fairness for more
                    qconn.on_timeout();

                    self.write_state.next_release_time = None;
                    current_deadline = None;
                    sleep.as_mut().reset((now + DEFAULT_SLEEP).into());
                }
                packet = incoming_recv.recv() => {
                    ctx.in_pkt = Some(packet.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "incoming packet source closed"))?);
                },
                directive = self.wait_for_data_or_handshake(qconn, application) => {
                    match directive? {
                        WaitForDataOrHandshakeDirective::Flush(send_buf) => {
                            // The handshake data was gathered into this
                            // on-demand buffer; flush it here (outside the
                            // select!, but with an explicit protocol deadline).
                            // Return it to the pool or drop it after completion.
                            self.flush_active(qconn, send_buf.as_ref()).await?;
                        }
                        WaitForDataOrHandshakeDirective::Noop => {}
                    }
                },
            };

            self.enforce_handshake_deadline(qconn)?;
        }
    }

    /// Drain a wakeup's input and output, returning transient buffers before
    /// the connection goes idle.
    async fn drive_io_burst<A: ApplicationOverQuic>(
        &mut self, qconn: &mut QuicheConnection,
        ctx: &mut ConnectionStageContext<A>,
        persistent_send_buf: &mut Option<Box<[u8]>>,
    ) -> QuicResult<ControlFlow<()>> {
        self.write_state.has_pending_data = true;

        // Transient egress buffer for this wakeup's send burst when pooling
        // is enabled. Borrowed from the per-worker pool on demand (see
        // below) and returned after the burst, before the worker sleeps in
        // the `select!` further down, so idle connections still hold no
        // egress buffer. Stays `None` when a persistent buffer is used.
        let mut pooled_send_buf: Option<PooledSendBuf> = None;

        while self.write_state.has_pending_data ||
            !ctx.incoming_pkt_receiver.is_empty() ||
            ctx.in_pkt.is_some()
        {
            self.service_connection_timers(qconn)?;
            if qconn.is_closed() {
                return Ok(ControlFlow::Break(()));
            }
            let mut packets_sent = 0;

            // Drain received packets periodically because they contain ACKs
            // and the bounded receive queue stalls new packets when full.
            let mut did_recv = false;
            for _ in 0..CHECK_INCOMING_QUEUE_RATIO {
                let Some(pkt) = ctx
                    .in_pkt
                    .take()
                    .or_else(|| ctx.incoming_pkt_receiver.try_recv().ok())
                else {
                    break;
                };
                self.process_incoming(qconn, pkt)?;
                did_recv = true;
            }
            self.write_state.has_pending_data |= did_recv;

            // Deliver transport-generated events before the application can
            // consume them.
            notify_path_events(ctx.connection_hook.as_deref(), qconn);

            self.conn_stage.on_read(did_recv, qconn, ctx)?;

            // Deliver events generated by application reads or writes.
            notify_path_events(ctx.connection_hook.as_deref(), qconn);
            Self::refresh_connection_ids(
                &self.route_lease,
                self.cid_generator.as_ref(),
                qconn,
            )
            .await?;

            let can_release =
                self.write_state
                    .next_release_time
                    .is_none_or(|next_release| {
                        next_release.saturating_duration_since(Instant::now()) <
                            RELEASE_TIMER_THRESHOLD
                    });

            self.write_state.has_pending_data &= can_release;

            while self.write_state.has_pending_data &&
                packets_sent < CHECK_INCOMING_QUEUE_RATIO
            {
                // Use the persistent per-connection buffer when pooling is
                // disabled. Otherwise borrow a buffer from the per-worker
                // pool on the first gather of this send burst and reuse it
                // for the remainder of the burst; it is returned at the end
                // of the enclosing block (below), before the worker sleeps,
                // so idle connections hold no egress buffer.
                let send_buf =
                    persistent_send_buf.as_deref_mut().unwrap_or_else(|| {
                        &mut pooled_send_buf
                            .get_or_insert_with(PooledSendBuf::acquire)[..]
                    });

                self.service_connection_timers(qconn)?;
                if qconn.is_closed() {
                    return Ok(ControlFlow::Break(()));
                }
                self.gather_data_from_quiche_conn(qconn, send_buf, false)?;

                // Break if the connection is closed
                if qconn.is_closed() {
                    return Ok(ControlFlow::Break(()));
                }

                let mut flush_operation_token =
                    TrackMidHandshakeFlush::new(self.metrics.clone());

                self.flush_active(qconn, send_buf).await?;
                if qconn.is_closed() {
                    return Ok(ControlFlow::Break(()));
                }

                flush_operation_token.mark_complete();

                packets_sent += self.write_state.num_pkts;

                if let ControlFlow::Break(reason) =
                    self.conn_stage.on_flush(qconn, ctx)
                {
                    reason?;
                    return Ok(ControlFlow::Break(()));
                }
            }
            // Bound each uninterrupted receive/send burst even when the
            // transport and application always make immediate progress.
            if self.write_state.has_pending_data ||
                !ctx.incoming_pkt_receiver.is_empty()
            {
                tokio::task::yield_now().await;
            }
        }

        // Return the borrowed egress buffer to the per-worker pool before
        // sleeping so it is not held while the connection is idle. The
        // persistent buffer (when pooling is disabled) is intentionally
        // kept across sleeps for the connection's lifetime.
        drop(pooled_send_buf);

        Ok(ControlFlow::Continue(()))
    }

    #[cfg(feature = "perf-quic-listener-metrics")]
    fn measure_complete_handshake_time(&mut self) {
        if let Some(init_rx_time) = self.init_rx_time.take() {
            if let Ok(delta) = init_rx_time.elapsed() {
                self.metrics
                    .handshake_time_seconds(
                        labels::QuicHandshakeStage::HandshakeResponse,
                    )
                    .observe(u64::try_from(delta.as_nanos()).unwrap_or(u64::MAX));
            }
        }
    }

    /// Gathers one or more packets from quiche into `send_buf`.
    ///
    /// A single-packet gather leaves a full buffer available for the next
    /// packet instead of generating a short packet in the remaining tail.
    fn gather_data_from_quiche_conn(
        &mut self, qconn: &mut QuicheConnection, send_buf: &mut [u8],
        single_packet: bool,
    ) -> QuicResult<usize> {
        let mut segment_size = None;
        let mut send_info = None;

        self.write_state.num_pkts = 0;
        self.write_state.bytes_written = 0;

        self.write_state.selected_path = None;

        let now = Instant::now();

        let send_buf = {
            let trunc = UDP_MAX_GSO_PACKET_SIZE.min(send_buf.len());
            &mut send_buf[..trunc]
        };

        #[cfg(feature = "gcongestion")]
        let gcongestion_enabled = true;

        #[cfg(not(feature = "gcongestion"))]
        let gcongestion_enabled = qconn.gcongestion_enabled().unwrap_or(false);

        let initial_release_decision = if gcongestion_enabled {
            let initial_release_decision = qconn
                .get_next_release_time()
                .filter(|_| self.pacing_enabled(qconn));

            if let Some(future_release_time) =
                initial_release_decision.as_ref().and_then(|v| v.time(now))
            {
                let max_into_fut = qconn.max_release_into_future();

                if future_release_time.duration_since(now) >= max_into_fut {
                    self.write_state.next_release_time =
                        Some(now + max_into_fut.mul_f32(0.8));
                    self.write_state.has_pending_data = false;
                    return Ok(0);
                }
            }

            initial_release_decision
        } else {
            None
        };

        let buffer_write_outcome = loop {
            let outcome = self.write_packet_to_buffer(
                qconn,
                send_buf,
                &mut send_info,
                segment_size,
            );

            let packet_size = match outcome {
                Ok(0) => break Ok(0),

                Ok(bytes_written) => bytes_written,

                Err(e) => break Err(e),
            };

            // Flush after one packet when GSO is disabled or the caller needs
            // each packet to start with a full buffer.
            if single_packet ||
                !self.cfg.socket_capabilities.contains(SocketCapability::Gso)
            {
                break outcome;
            }

            if self.gso_batch_full(
                qconn,
                segment_size,
                send_buf.len(),
                gcongestion_enabled,
            ) {
                break outcome;
            }

            // Flush to network when the newly generated packet size is
            // different from previously written packet, as GSO needs packets
            // to have the same size, except for the last one in the buffer.
            // The last packet may be smaller than the previous size.
            match segment_size {
                Some(size)
                    if packet_size != size || packet_size < GSO_THRESHOLD =>
                    break outcome,
                None => segment_size = Some(packet_size),
                _ => (),
            }

            if gcongestion_enabled {
                // Start a new batch if the next packet has a different release
                // time or cannot be part of a burst.
                if let Some(initial_release_decision) = initial_release_decision {
                    match qconn.get_next_release_time() {
                        Some(release)
                            if release.can_burst() ||
                                release.time_eq(
                                    &initial_release_decision,
                                    now,
                                ) => {},
                        _ => break outcome,
                    }
                }
            }
        };

        let tx_time = if gcongestion_enabled {
            initial_release_decision
                .filter(|_| self.pacing_enabled(qconn))
                // Return the time from the release decision if
                // release_decision.time > now, else None.
                .and_then(|v| v.time(now))
        } else {
            send_info
                .filter(|_| self.pacing_enabled(qconn))
                .map(|v| v.at)
        };

        self.write_state.conn_established = qconn.is_established();
        self.write_state.tx_time = tx_time;
        self.write_state.segment_size =
            segment_size.unwrap_or(self.write_state.bytes_written);

        if !gcongestion_enabled && self.defer_legacy_pacing(tx_time, now) {
            return Ok(0);
        }

        buffer_write_outcome
    }

    /// Check both the kernel GSO segment limit and the legacy recovery send
    /// quantum.
    fn gso_batch_full(
        &self, qconn: &QuicheConnection, segment_size: Option<usize>,
        capacity: usize, gcongestion_enabled: bool,
    ) -> bool {
        if self.write_state.num_pkts >= UDP_MAX_SEGMENT_COUNT {
            return true;
        }
        #[cfg(not(feature = "gcongestion"))]
        if !gcongestion_enabled {
            return self.write_state.bytes_written >=
                tune_max_send_size(
                    segment_size,
                    qconn.send_quantum(),
                    capacity,
                );
        }
        #[cfg(feature = "gcongestion")]
        let _ = (qconn, segment_size, capacity, gcongestion_enabled);
        false
    }

    fn defer_legacy_pacing(
        &mut self, tx_time: Option<Instant>, now: Instant,
    ) -> bool {
        const MAX_INTO_FUTURE: Duration = Duration::from_millis(1);
        if tx_time.is_some_and(|time| {
            time.saturating_duration_since(now) > MAX_INTO_FUTURE
        }) {
            self.write_state.next_release_time =
                Some(now + MAX_INTO_FUTURE.mul_f32(0.8));
            self.write_state.has_pending_data = false;
            true
        } else {
            false
        }
    }

    /// Selects a network path, if none already selected.
    ///
    /// This will return the first path available in the write state's
    /// `pending_paths` iterator. If that is empty a new iterator will be
    /// created by querying quiche itself.
    ///
    /// Note that the connection's statically configured local address will be
    /// used to query quiche for available paths, so this can't handle multiple
    /// local addresses currently.
    fn select_path(
        &mut self, qconn: &QuicheConnection,
    ) -> Option<(SocketAddr, SocketAddr)> {
        if self.write_state.selected_path.is_some() {
            return self.write_state.selected_path;
        }

        let from = self.cfg.local_addr;

        // Initialize paths iterator.
        if self.write_state.pending_paths.len() == 0 {
            self.write_state.pending_paths = qconn.paths_iter(from);
        }

        let to = self.write_state.pending_paths.next()?;

        Some((from, to))
    }

    #[cfg(not(feature = "gcongestion"))]
    const fn pacing_enabled(&self, qconn: &QuicheConnection) -> bool {
        self.cfg
            .socket_capabilities
            .contains(SocketCapability::TransmitTime) &&
            qconn.pacing_enabled()
    }

    #[cfg(feature = "gcongestion")]
    fn pacing_enabled(&self, _qconn: &QuicheConnection) -> bool {
        self.cfg
            .socket_capabilities
            .contains(SocketCapability::TransmitTime)
    }

    fn write_packet_to_buffer(
        &mut self, qconn: &mut QuicheConnection, send_buf: &mut [u8],
        send_info: &mut Option<SendInfo>, segment_size: Option<usize>,
    ) -> QuicResult<usize> {
        let mut send_buf = &mut send_buf[self.write_state.bytes_written..];
        if send_buf.len() > segment_size.unwrap_or(usize::MAX) {
            // Never let the buffer be longer than segment size, for GSO to
            // function properly.
            send_buf = &mut send_buf[..segment_size.unwrap_or(usize::MAX)];
        }

        // On the first call to `select_path()` a path will be chosen based on
        // the local address the connection initially landed on. Once a path is
        // selected following calls to `select_path()` will return it, until it
        // is reset at the start of the next write cycle.
        //
        // The path is then passed to `send_on_path()` which will only generate
        // packets meant for that path, this way a single GSO buffer will only
        // contain packets that belong to the same network path, which is
        // required because the from/to addresses for each `sendmsg()` call
        // apply to the whole GSO buffer.
        let (from, to) = self.select_path(qconn).unzip();

        let result = qconn.send_on_path(send_buf, from, to);
        self.record_handshake_completion(qconn);
        match result {
            Ok((packet_size, info)) => {
                let _ = send_info.get_or_insert(info);

                self.write_state.bytes_written += packet_size;
                self.write_state.num_pkts += 1;

                let from = send_info.as_ref().map(|info| info.from);
                let to = send_info.as_ref().map(|info| info.to);

                self.write_state.selected_path = from.zip(to);

                self.write_state.has_pending_data = true;

                Ok(packet_size)
            },

            Err(QuicheError::Done) => {
                // Flush the current buffer to network. If no other path needs
                // to be flushed to the network also yield the work loop task.
                //
                // Otherwise the write loop will start again and the next path
                // will be selected.
                let has_pending_paths = self.write_state.pending_paths.len() > 0;

                // Keep writing if there are paths left to try.
                self.write_state.has_pending_data = has_pending_paths;

                Ok(0)
            },

            Err(e) => {
                if qconn.local_error().is_none() {
                    let _ = qconn.close(
                        false,
                        quiche::WireErrorCode::InternalError as u64,
                        &[],
                    );
                }

                Err(Box::new(e))
            },
        }
    }

    fn flush_buffer_to_socket<'a>(
        &'a self, send_buf: &'a [u8], deadline: Instant,
    ) -> impl Future<Output = std::io::Result<SendOutcome>> + Send + 'a {
        let bytes_written = self.write_state.bytes_written;
        let socket = &self.socket;
        let metrics = &self.metrics;
        let (from, to) = self.write_state.selected_path.unzip();
        let packet = PacketSend {
            to: to.unwrap_or(self.cfg.peer_addr),
            from: from.filter(|addr| {
                self.cfg.socket_capabilities.supports_pktinfo(*addr)
            }),
            segment_size: (self
                .cfg
                .socket_capabilities
                .contains(SocketCapability::Gso) &&
                self.write_state.num_pkts > 1)
                .then_some(self.write_state.segment_size),
            tx_time: self.write_state.tx_time,
            dscp: self.dscp_handle.as_ref().and_then(DscpHandle::get),
        };
        async move {
            if bytes_written == 0 {
                return Ok(SendOutcome::Sent);
            }
            let current_send_buf =
                send_buf.get(..bytes_written).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "gathered packet length exceeds send buffer",
                    )
                })?;
            send_packets_before(
                socket,
                current_send_buf,
                packet,
                metrics,
                deadline,
            )
            .await
        }
    }

    async fn flush_active(
        &mut self, qconn: &mut QuicheConnection, send_buf: &[u8],
    ) -> QuicResult<()> {
        self.enforce_handshake_deadline(qconn)?;
        let deadline =
            min_of_some(qconn.timeout_instant(), self.handshake_deadline(qconn))
                .unwrap_or_else(|| Instant::now() + MAX_UNTIMED_SEND_WAIT);
        match self.flush_buffer_to_socket(send_buf, deadline).await {
            #[cfg(feature = "perf-quic-listener-metrics")]
            Ok(SendOutcome::Sent) if self.write_state.bytes_written != 0 =>
                self.measure_complete_handshake_time(),
            Ok(SendOutcome::Sent) => (),
            Ok(SendOutcome::DeadlineExpired) => {
                // The core already assigned packet numbers. Do not replay the
                // buffer; recovery will generate new packets as needed.
                self.write_state.next_release_time = None;
            },
            Err(error) if recoverable_send_error(&error) => (),
            Err(error) => return Err(error.into()),
        }
        self.service_connection_timers(qconn)
    }

    fn record_handshake_completion(&mut self, qconn: &QuicheConnection) {
        if qconn.is_established() {
            if let Some(duration) = self.handshake_info.complete() {
                self.audit_log_stats
                    .set_transport_handshake_duration(duration);
                if let Some(cid) = self.cfg.pending_cid.take() {
                    self.route_lease.retire(cid);
                }
            }
        }
    }

    fn service_connection_timers(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        self.record_handshake_completion(qconn);
        self.enforce_handshake_deadline(qconn)?;
        if qconn
            .timeout_instant()
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            qconn.on_timeout();
            self.write_state.next_release_time = None;
            self.write_state.has_pending_data = true;
        }
        Ok(())
    }

    /// The deadline before which the handshake must complete, if it hasn't
    /// completed yet.
    fn handshake_deadline(&self, qconn: &QuicheConnection) -> Option<Instant> {
        if qconn.is_established() {
            return None;
        }

        self.handshake_info.deadline()
    }

    /// Closes the connection if the handshake didn't complete before its
    /// deadline.
    fn enforce_handshake_deadline(
        &self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        if !qconn.is_established() && self.handshake_info.is_expired() {
            let err = quiche::WireErrorCode::ApplicationError as u64;
            let _ = qconn.close(false, err, &[]);
            return Err(HandshakeError::Timeout.into());
        }

        Ok(())
    }

    /// Process the incoming packet
    fn process_incoming(
        &mut self, qconn: &mut QuicheConnection, mut pkt: Incoming,
    ) -> QuicResult<()> {
        // Checked for every packet, so that a peer flooding packets can't keep
        // the worker busy past the handshake deadline.
        self.enforce_handshake_deadline(qconn)?;

        let recv_info = quiche::RecvInfo {
            from: pkt.peer_addr,
            to: pkt.local_addr,
        };

        if let Some(gro) = pkt.gro {
            for dgram in pkt.buf.chunks_mut(gro.get()) {
                qconn.recv(dgram, recv_info)?;
                self.record_handshake_completion(qconn);
            }
        } else {
            qconn.recv(&mut pkt.buf, recv_info)?;
            self.record_handshake_completion(qconn);
        }

        Ok(())
    }

    // Process application data after establishment. Before then, a BoringSSL
    // wakeup might require quiche to send handshake packets.
    //
    // TODO(erittenhouse): Decouple `wait_for_data` from the application.
    // `wait_for_quiche` depends on IOW methods, preventing a default
    // `ConnectionStage` implementation.
    //
    // # Cancel safety
    //
    // This future is polled as an arm of the `select!` in `Self::work_loop`, so
    // it must be cancel-safe. Another arm may complete first and drop it at any
    // `.await`. `ApplicationOverQuic::wait_for_data` is also cancel-safe, and
    // the handshake branch retains only its local `send_buf` across `.await`.
    // Cancellation returns or frees that buffer. The next poll gathers its
    // bytes again. Preserve this property when modifying the function.
    async fn wait_for_data_or_handshake<A: ApplicationOverQuic>(
        &mut self, qconn: &mut QuicheConnection, quic_application: &mut A,
    ) -> QuicResult<WaitForDataOrHandshakeDirective> {
        if quic_application.should_act() {
            // Poll the application to make progress.
            //
            // Once the connection has been established (i.e. the handshake is
            // complete), we only poll the application.
            //
            // The exception is 0-RTT in TLS 1.3, where the full handshake is
            // still in progress but we have 0-RTT keys to process early data.
            // This means TLS callbacks might only be polled on the next timeout
            // or when a packet is received from the peer.
            quic_application.wait_for_data(qconn).await?;
            Ok(WaitForDataOrHandshakeDirective::Noop)
        } else {
            // Poll quiche to make progress on handshake callbacks, gathering
            // any handshake packets into an on-demand buffer that the caller
            // flushes. `wait_for_quiche()` returns it only after generating a
            // packet, so pending handshake waits do not retain a buffer.
            let send_buf = self.wait_for_quiche(qconn).await?;
            Ok(WaitForDataOrHandshakeDirective::Flush(send_buf))
        }
    }

    /// Check if Quiche has any packets to send
    ///
    /// If yes: fills buffer and updates `self.write_state.bytes_written`
    /// If no: `Poll::Pending`
    ///
    /// # Example
    ///
    /// This function can be used, for example, to drive an asynchronous TLS
    /// handshake. Each call to `gather_data_from_quiche_conn` attempts to
    /// progress the handshake via a call to `quiche::Connection.send()` -
    /// once one of the `gather_data_from_quiche_conn()` calls writes to the
    /// send buffer, we signal to the caller which has to take care of flushing
    ///
    /// # Cancel safety
    ///
    /// This future is awaited (indirectly) as an arm of the `select!` in
    /// [`Self::work_loop`], so it MUST be cancel safe. The `poll_fn` below
    /// holds no state across polls other than what lives in `self.write_state`,
    /// so dropping the future between polls loses nothing: the next call simply
    /// re-gathers. Take care to preserve this property when modifying it.
    async fn wait_for_quiche(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<TransientSendBuf> {
        let send_buf = std::future::poll_fn(|_| {
            // Allocate inside this closure so a pending poll immediately
            // returns its buffer to the pool instead of retaining it across
            // the select! wait.
            let mut send_buf =
                TransientSendBuf::acquire(self.cfg.pool_send_buffer);

            match self.gather_data_from_quiche_conn(
                qconn,
                send_buf.as_mut(),
                true,
            ) {
                Ok(bytes_written) => {
                    // Do not call `gather()` twice without an intervening
                    // `flush()`. Consecutive calls may overwrite data or delay
                    // handshake completion.
                    if bytes_written == 0 && self.write_state.bytes_written == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(send_buf))
                    }
                },
                Err(error) => Poll::Ready(Err(error)),
            }
        })
        .await?;
        Ok(send_buf)
    }
}

/// Whether caller of [`wait_for_data_or_handshake`] is required to
/// call [`flush_buffer_to_socket`].
///
/// `Flush` carries the on-demand buffer the handshake data was gathered into so
/// the caller can flush it and then return it to the pool or drop it.
#[must_use = "the worker must process the returned directive to flush pending output"]
enum WaitForDataOrHandshakeDirective {
    Noop,
    Flush(TransientSendBuf),
}

pub struct Running<Tx, M, A> {
    pub(crate) params: IoWorkerParams<Tx, M>,
    pub(crate) context: ConnectionStageContext<A>,
    /// See [`QuicConnectionParams::quiche_conn`].
    pub(crate) qconn: Box<QuicheConnection>,
}

impl<Tx, M, A> Running<Tx, M, A> {
    pub fn ssl(&mut self) -> &mut SslRef {
        // Deref to pick `Connection::as_mut` over `Box::as_mut`.
        (*self.qconn).as_mut()
    }
}

pub struct Closing<Tx, M, A> {
    pub(crate) params: IoWorkerParams<Tx, M>,
    pub(crate) context: ConnectionStageContext<A>,
    pub(crate) work_loop_result: QuicResult<()>,
    /// See [`QuicConnectionParams::quiche_conn`].
    pub(crate) qconn: Box<QuicheConnection>,
}

pub enum RunningOrClosing<Tx, M, A> {
    Running(Running<Tx, M, A>),
    Closing(Closing<Tx, M, A>),
}

impl<Tx, M> IoWorker<Tx, M, Handshake>
where
    Tx: DatagramSocketSend + Send,
    M: Metrics,
{
    pub(crate) async fn run<A>(
        mut self, mut qconn: Box<QuicheConnection>,
        mut ctx: ConnectionStageContext<A>,
    ) -> RunningOrClosing<Tx, M, A>
    where
        A: ApplicationOverQuic,
    {
        // The `ex_data` waker must remain stable for this task. Moving a future
        // with an async callback to another task leaves a stale waker that
        // wakes the wrong task.
        std::future::poll_fn(|cx| {
            // Deref to pick `Connection::as_mut` over `Box::as_mut`.
            let ssl = (*qconn).as_mut();
            ssl.set_task_waker(Some(cx.waker().clone()));

            Poll::Ready(())
        })
        .await;

        #[cfg(target_os = "linux")]
        if let Some(incoming) = ctx.in_pkt.as_mut() {
            self.audit_log_stats
                .set_initial_so_mark_data(incoming.so_mark_data.take());
        }

        let mut work_loop_result = self.work_loop(&mut qconn, &mut ctx).await;
        notify_path_events(ctx.connection_hook.as_deref(), &mut qconn);
        if work_loop_result.is_ok() && qconn.is_closed() {
            work_loop_result = Err(HandshakeError::ConnectionClosed.into());
        }

        if let Err(err) = &work_loop_result {
            self.metrics.failed_handshakes(err.into()).inc();

            return RunningOrClosing::Closing(Closing {
                params: self.into(),
                context: ctx,
                work_loop_result,
                qconn,
            });
        }

        let on_application_ready_result =
            self.on_application_ready(&mut qconn, &mut ctx.application);
        notify_path_events(ctx.connection_hook.as_deref(), &mut qconn);

        match on_application_ready_result {
            Ok(()) => RunningOrClosing::Running(Running {
                params: self.into(),
                context: ctx,
                qconn,
            }),
            Err(e) => {
                foundations::telemetry::log::warn!(
                    "Application startup failed"; "error"=>%e
                );

                RunningOrClosing::Closing(Closing {
                    params: self.into(),
                    context: ctx,
                    work_loop_result: Err(e),
                    qconn,
                })
            },
        }
    }

    fn on_application_ready<App: ApplicationOverQuic>(
        &mut self, qconn: &mut QuicheConnection, driver: &mut App,
    ) -> QuicResult<()> {
        self.record_handshake_completion(qconn);
        driver.on_application_ready(qconn, &self.handshake_info)
    }
}

impl<Tx, M, S> From<IoWorker<Tx, M, S>> for IoWorkerParams<Tx, M> {
    fn from(value: IoWorker<Tx, M, S>) -> Self {
        Self {
            socket: value.socket,
            shutdown_tx: value.shutdown_tx,
            cfg: value.cfg,
            audit_log_stats: value.audit_log_stats,
            write_state: value.write_state,
            dscp_handle: value.dscp_handle,
            route_lease: value.route_lease,
            active_connection: value.active_connection,
            bw_estimator: value.bw_estimator,
            cid_generator: value.cid_generator,
            #[cfg(feature = "perf-quic-listener-metrics")]
            init_rx_time: value.init_rx_time,
            metrics: value.metrics,
            handshake_info: value.handshake_info,
            shutdown_request: value.shutdown_request,
            completion: value.completion,
        }
    }
}

impl<Tx, M> IoWorker<Tx, M, RunningApplication>
where
    Tx: DatagramSocketSend + Send,
    M: Metrics,
{
    pub(crate) async fn run<A: ApplicationOverQuic>(
        mut self, mut qconn: Box<QuicheConnection>,
        mut ctx: ConnectionStageContext<A>,
    ) -> Closing<Tx, M, A> {
        // With 0-RTT early data, the application may be resumed after the
        // handshake deadline, in which case no data must be passed to it.
        let mut work_loop_result = self.enforce_handshake_deadline(&mut qconn);

        if work_loop_result.is_ok() && !self.shutdown_request.is_cancelled() {
            // Perform a single call to process_reads()/process_writes(),
            // unconditionally, to ensure that any application data (e.g.
            // STREAM frames or datagrams) processed by the Handshake
            // stage are properly passed to the application.
            work_loop_result =
                self.conn_stage.on_read(true, &mut qconn, &mut ctx);
            notify_path_events(ctx.connection_hook.as_deref(), &mut qconn);
        }

        if work_loop_result.is_ok() {
            work_loop_result = self.work_loop(&mut qconn, &mut ctx).await;
            notify_path_events(ctx.connection_hook.as_deref(), &mut qconn);
        }

        // Only connections started with 0-RTT early data can get here before
        // the handshake completes, in which case this is a failed handshake,
        // as in the Handshake stage.
        if !qconn.is_established() {
            let reason = match &work_loop_result {
                Err(err) => err.into(),
                Ok(()) => labels::HandshakeError::Disconnect,
            };

            self.metrics.failed_handshakes(reason).inc();
        }

        Closing {
            params: self.into(),
            context: ctx,
            work_loop_result,
            qconn,
        }
    }
}

impl<Tx, M> IoWorker<Tx, M, Close>
where
    Tx: DatagramSocketSend + Send,
    M: Metrics,
{
    pub(crate) async fn close<A: ApplicationOverQuic>(
        mut self, qconn: &mut QuicheConnection,
        ctx: &mut ConnectionStageContext<A>,
    ) {
        self.bw_estimator.update(qconn, Instant::now());
        self.audit_log_stats
            .set_max_bandwidth(self.bw_estimator.max_bandwidth);
        self.audit_log_stats
            .set_max_loss_pct(self.bw_estimator.max_loss.rounded_percent());
        if self.conn_stage.work_loop_result.is_ok() &&
            self.bw_estimator.max_bandwidth > 0
        {
            let metrics = &self.metrics;

            metrics.max_bandwidth_mbps().observe(
                crate::metrics::histogram_value(self.bw_estimator.max_bandwidth) *
                    1e-6,
            );

            metrics
                .max_loss_pct()
                .observe(self.bw_estimator.max_loss.percent());
        }

        if ctx.application.should_act() {
            ctx.application.on_conn_close(
                qconn,
                &self.metrics,
                &self.conn_stage.work_loop_result,
            );
            notify_path_events(ctx.connection_hook.as_deref(), qconn);
        }

        // The application may select its own close code. Otherwise turn a
        // local worker failure into a transport close, rather than generating
        // more ordinary application data from an abandoned connection.
        if self.conn_stage.work_loop_result.is_err() &&
            qconn.local_error().is_none() &&
            !qconn.is_closed() &&
            !qconn.is_draining()
        {
            let _ = qconn.close(
                false,
                quiche::WireErrorCode::InternalError as u64,
                &[],
            );
        }

        // Best-effort final CONNECTION_CLOSE flight. Waiting for a broken
        // socket must not retain the connection's routes or resources.
        let mut send_buf = TransientSendBuf::acquire(self.cfg.pool_send_buffer);
        let close_deadline = Instant::now() + CLOSE_SEND_WAIT;
        let close_result: QuicResult<()> = match self
            .gather_data_from_quiche_conn(qconn, send_buf.as_mut(), false)
        {
            Ok(_) => match self
                .flush_buffer_to_socket(send_buf.as_ref(), close_deadline)
                .await
            {
                Ok(SendOutcome::Sent) => {
                    #[cfg(feature = "perf-quic-listener-metrics")]
                    if self.write_state.bytes_written != 0 {
                        self.measure_complete_handshake_time();
                    }
                    Ok(())
                },
                Ok(SendOutcome::DeadlineExpired) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "final QUIC send deadline expired",
                )
                .into()),
                Err(error) => Err(error.into()),
            },
            Err(error) => Err(error),
        };
        // The first failure remains the authoritative close reason.
        if self.conn_stage.work_loop_result.is_ok() {
            self.conn_stage.work_loop_result = close_result;
        }

        replace_shared_stats(&ctx.stats, QuicConnectionStats::from_conn(qconn));

        if let Some(err) = qconn.peer_error() {
            self.audit_log_stats
                .set_peer_close_code(QuicCloseCode::from_parts(
                    err.is_app,
                    err.error_code,
                ));
        }

        if let Some(err) = qconn.local_error() {
            self.audit_log_stats
                .set_local_close_code(QuicCloseCode::from_parts(
                    err.is_app,
                    err.error_code,
                ));
        }

        self.close_connection();

        if let Err(work_loop_error) = self.conn_stage.work_loop_result {
            self.audit_log_stats
                .set_connection_close_reason(work_loop_error);
        }
    }

    fn close_connection(&mut self) {
        self.route_lease.close();
    }
}

/// Returns the minimum of `v1` and `v2`, ignoring `None`s.
fn min_of_some<T: Ord>(v1: Option<T>, v2: Option<T>) -> Option<T> {
    match (v1, v2) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(v), _) | (_, Some(v)) => Some(v),
        (None, None) => None,
    }
}

/// A Token which increment the `skipped_mid_handshake_flush_count` metric on
/// `Drop` unless it is marked complete.
struct TrackMidHandshakeFlush<M: Metrics> {
    complete: bool,
    metrics: M,
}

impl<M: Metrics> TrackMidHandshakeFlush<M> {
    const fn new(metrics: M) -> Self {
        Self {
            complete: false,
            metrics,
        }
    }

    const fn mark_complete(&mut self) {
        self.complete = true;
    }
}

impl<M: Metrics> Drop for TrackMidHandshakeFlush<M> {
    fn drop(&mut self) {
        if !self.complete {
            self.metrics.skipped_mid_handshake_flush_count().inc();
        }
    }
}

fn random_u128() -> QuicResult<u128> {
    let mut buf = [0; 16];
    btls::rand::rand_bytes(&mut buf)?;
    Ok(u128::from_ne_bytes(buf))
}

#[cfg(test)]
mod pooled_send_buf_tests {
    use super::*;

    // Each pool test runs on a freshly spawned thread so the thread-local
    // `SEND_BUF_POOL` starts empty (const-initialized) and cannot interfere
    // with other tests sharing the harness's worker threads.

    #[test]
    fn caps_retained_buffers() {
        std::thread::spawn(|| {
            // Acquire more than the cap at once (all misses, so all fresh
            // allocations), then drop them. Only `SEND_BUF_POOL_CAP` may be
            // parked; the remainder are freed.
            let bufs: Vec<PooledSendBuf> = (0..SEND_BUF_POOL_CAP + 4)
                .map(|_| PooledSendBuf::acquire())
                .collect();
            drop(bufs);

            let retained = SEND_BUF_POOL.with(|pool| pool.borrow().len());
            assert_eq!(retained, SEND_BUF_POOL_CAP);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn reuses_a_returned_buffer() {
        std::thread::spawn(|| {
            let first_ptr = {
                let buf = PooledSendBuf::acquire();
                assert_eq!(buf.len(), SEND_BUFFER_SIZE);
                buf.as_ptr()
            }; // returned to the pool here

            let reused = PooledSendBuf::acquire();
            assert_eq!(
                reused.as_ptr(),
                first_ptr,
                "acquire should hand back the pooled allocation"
            );
        })
        .join()
        .unwrap();
    }

    #[test]
    fn returns_to_the_dropping_thread() {
        // Acquire on one thread, drop on another: the buffer lands in the
        // dropping thread's pool (work-stealing migration across `.await` is
        // benign).
        let buf = std::thread::spawn(PooledSendBuf::acquire).join().unwrap();

        std::thread::spawn(move || {
            assert_eq!(SEND_BUF_POOL.with(|pool| pool.borrow().len()), 0);
            drop(buf);
            assert_eq!(SEND_BUF_POOL.with(|pool| pool.borrow().len()), 1);
        })
        .join()
        .unwrap();
    }
}
