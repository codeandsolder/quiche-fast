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

//! Responsible for creating a [`tokio_quiche::quic::QuicheConnection`] and
//! yielding I/O to tokio-quiche.

use quiche::PathStats;
use quiche::Stats;
use std::future::pending;
use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use tokio::select;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::sleep_until;
use tokio::time::Instant;
use tokio_quiche::metrics::Metrics;
use tokio_quiche::quic::HandshakeInfo;
use tokio_quiche::quic::QuicheConnection;
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::socket::Socket;
use tokio_quiche::ApplicationOverQuic;
use tokio_quiche::ConnectionParams;
use tokio_quiche::QuicResult;

use crate::actions::h3::Action;
use crate::client::parse_args;
use crate::client::parse_streams;
use crate::client::ClientError;
use crate::client::CloseTriggerFrames;
use crate::client::ConnectionSummary;
use crate::client::ParsedArgs;
use crate::client::StreamMap;
use crate::client::MAX_DATAGRAM_SIZE;
use crate::config::Config as H3iConfig;
use crate::frame::H3iFrame;
use crate::quiche;

use super::action_queue::ActionQueue;
use super::Client;
use super::ConnectionCloseDetails;
use super::StreamParserMap;

/// Connect to the socket.
///
/// # Errors
/// Returns a client error if connection setup or the handshake fails.
pub async fn connect(
    args: &H3iConfig, frame_actions: Vec<Action>,
    close_trigger_frames: Option<CloseTriggerFrames>,
) -> std::result::Result<BuildingConnectionSummary, ClientError> {
    let quic_settings = create_config(args);
    let mut connection_params =
        ConnectionParams::new_client(quic_settings, None, Hooks::default());

    connection_params.session = args.session.clone();

    let ParsedArgs {
        connect_url,
        bind_addr,
        peer_addr,
    } = parse_args(args)?;

    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|error| ClientError::Other(error.to_string()))?;
    socket
        .connect(peer_addr)
        .await
        .map_err(|error| ClientError::Other(error.to_string()))?;

    log::info!(
        "connecting to {:} from {:}",
        peer_addr,
        socket
            .local_addr()
            .map_err(|error| ClientError::Other(error.to_string()))?
    );

    let (h3i, conn_summary_fut) =
        H3iDriver::new(frame_actions, close_trigger_frames);
    match tokio_quiche::quic::connect_with_config(
        Socket::try_from(socket)
            .map_err(|error| ClientError::Other(error.to_string()))?,
        connect_url,
        &connection_params,
        h3i,
    )
    .await
    {
        Ok(_) => Ok(conn_summary_fut),
        Err(_) => Err(ClientError::HandshakeFail),
    }
}

fn create_config(args: &H3iConfig) -> QuicSettings {
    let mut quic_settings = QuicSettings::default();

    quic_settings.verify_peer = args.tls.verify_peer;
    quic_settings.max_idle_timeout =
        Some(Duration::from_millis(args.idle_timeout));
    quic_settings.send_capacity_factor = args.send_capacity_factor;
    quic_settings.max_recv_udp_payload_size = MAX_DATAGRAM_SIZE;
    quic_settings.max_send_udp_payload_size = MAX_DATAGRAM_SIZE;
    quic_settings.initial_max_data = args.flow.max_data;
    quic_settings.initial_max_stream_data_bidi_local =
        args.flow.max_stream_data_bidi_local;
    quic_settings.initial_max_stream_data_bidi_remote =
        args.flow.max_stream_data_bidi_remote;
    quic_settings.initial_max_stream_data_uni = args.flow.max_stream_data_uni;
    quic_settings.initial_max_streams_bidi = args.flow.max_streams_bidi;
    quic_settings.initial_max_streams_uni = args.flow.max_streams_uni;
    quic_settings.disable_active_migration = true;
    quic_settings.active_connection_id_limit = 0;
    quic_settings.max_connection_window = args.flow.max_window;
    quic_settings.max_stream_window = args.flow.max_stream_window;
    quic_settings.enable_send_streams_blocked = true;
    quic_settings.grease = false;

    quic_settings.capture_quiche_logs = true;
    quic_settings.keylog_file = std::env::var_os("SSLKEYLOGFILE")
        .and_then(|os_str| os_str.into_string().ok());

    quic_settings.enable_early_data = args.tls.early_data;
    quic_settings.enable_dgram = args.datagrams.is_some();
    if let Some(queues) = &args.datagrams {
        quic_settings.dgram_recv_max_queue_len = queues.receive;
        quic_settings.dgram_send_max_queue_len = queues.send;
    }

    quic_settings
}

/// The [`Future`] used to build a [`ConnectionSummary`].
///
/// At a high level, [`H3iDriver`] will interact with the UDP socket directly,
/// sending and receiving data as necessary. As new data is received, it will
/// send [`ConnectionRecord`]s to this struct, which uses these records to
/// construct the [`ConnectionSummary`].
#[must_use = "must await to get a ConnectionSummary"]
pub struct BuildingConnectionSummary {
    rx: mpsc::UnboundedReceiver<ConnectionRecord>,
    summary: Option<ConnectionSummary>,
    seen_all_close_trigger_frames:
        Option<oneshot::Sender<quiche::ConnectionError>>,
}

impl BuildingConnectionSummary {
    fn new(
        rx: mpsc::UnboundedReceiver<ConnectionRecord>,
        close_trigger_frames: Option<CloseTriggerFrames>,
        trigger_frame_tx: oneshot::Sender<quiche::ConnectionError>,
    ) -> Self {
        let summary = ConnectionSummary {
            stream_map: StreamMap::new(close_trigger_frames),
            ..ConnectionSummary::default()
        };

        Self {
            rx,
            summary: Some(summary),
            seen_all_close_trigger_frames: Some(trigger_frame_tx),
        }
    }
}

impl Future for BuildingConnectionSummary {
    type Output = Result<ConnectionSummary, ClientError>;

    fn poll(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        if self.summary.is_none() {
            return Poll::Ready(Err(ClientError::Other(
                "connection summary already consumed".into(),
            )));
        }
        loop {
            let record = match self.rx.poll_recv(cx) {
                Poll::Ready(Some(record)) => record,
                Poll::Ready(None) =>
                    return Poll::Ready(self.summary.take().ok_or_else(|| {
                        ClientError::Other(
                            "connection summary already consumed".into(),
                        )
                    })),
                Poll::Pending => return Poll::Pending,
            };
            let Some(summary) = self.summary.as_mut() else {
                return Poll::Ready(Err(ClientError::Other(
                    "connection summary already consumed".into(),
                )));
            };
            match record {
                ConnectionRecord::StreamedFrame { stream_id, frame } => {
                    summary.stream_map.insert(stream_id, frame);
                    let close_error =
                        summary.stream_map.triggered_close_error().cloned();
                    if let Some(error) = close_error {
                        if let Some(tx) =
                            self.seen_all_close_trigger_frames.take()
                        {
                            let _ = tx.send(error);
                        }
                    }
                },
                ConnectionRecord::ConnectionStats(stats) =>
                    summary.stats = Some(stats),
                ConnectionRecord::PathStats(stats) => summary.path_stats = stats,
                ConnectionRecord::Close(details) =>
                    summary.conn_close_details = details,
                ConnectionRecord::ActionFailed(error) => {
                    self.summary = None;
                    return Poll::Ready(Err(ClientError::Other(error)));
                },
            }
        }
    }
}

pub struct H3iDriver {
    queue: ActionQueue,
    record_tx: mpsc::UnboundedSender<ConnectionRecord>,
    stream_parsers: StreamParserMap,
    close_trigger_seen_rx: oneshot::Receiver<quiche::ConnectionError>,
}

impl H3iDriver {
    fn new(
        actions: Vec<Action>, close_trigger_frames: Option<CloseTriggerFrames>,
    ) -> (Self, BuildingConnectionSummary) {
        let (record_tx, record_rx) = mpsc::unbounded_channel();
        let (close_trigger_seen_tx, close_trigger_seen_rx) = oneshot::channel();
        let fut = BuildingConnectionSummary::new(
            record_rx,
            close_trigger_frames,
            close_trigger_seen_tx,
        );

        (
            Self {
                queue: ActionQueue::new(actions),
                record_tx,
                stream_parsers: StreamParserMap::default(),
                close_trigger_seen_rx,
            },
            fut,
        )
    }

    fn action_error(
        &self, error: String,
    ) -> Box<dyn std::error::Error + Send + Sync> {
        let _ = self
            .record_tx
            .send(ConnectionRecord::ActionFailed(error.clone()));
        error.into()
    }
}

impl Client for H3iDriver {
    fn stream_parsers_mut(&mut self) -> &mut StreamParserMap {
        &mut self.stream_parsers
    }

    fn handle_response_frame(
        &mut self, stream_id: u64, frame: crate::frame::H3iFrame,
    ) {
        let _ = self
            .record_tx
            .send(ConnectionRecord::StreamedFrame { stream_id, frame });
    }
}

impl ApplicationOverQuic for H3iDriver {
    fn on_conn_established(
        &mut self, _qconn: &mut QuicheConnection, _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        log::info!("h3i: HTTP/3 connection established");
        Ok(())
    }

    fn should_act(&self) -> bool {
        // Send terminal records even without an established connection.
        true
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        log::trace!("h3i: process_reads");

        self.queue
            .before_reads(Instant::now().into_std(), qconn)
            .map_err(|error| self.action_error(error))?;
        for event in parse_streams(qconn, self) {
            self.queue.on_stream_event(event);
        }
        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        log::trace!("h3i: process_writes");
        if qconn.is_draining() {
            return Ok(());
        }
        self.queue
            .advance(
                || Instant::now().into_std(),
                qconn,
                &mut self.stream_parsers,
            )
            .map_err(|error| self.action_error(error))
    }

    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        let deadline = if qconn.is_established() && !qconn.is_draining() {
            self.queue
                .wakeup(Instant::now().into_std())
                .map(Instant::from_std)
        } else {
            None
        };
        let sleep_fut = async {
            if let Some(deadline) = deadline {
                sleep_until(deadline).await;
            } else {
                pending::<()>().await;
            }
        };
        select! {
            result = &mut self.close_trigger_seen_rx, if !self.close_trigger_seen_rx.is_terminated() => {
                if let Ok(error) = result {
                    let _ = qconn.close(error.is_app, error.error_code, &error.reason);
                }
            }
            () = sleep_fut => {}
        }
        Ok(())
    }

    fn on_conn_close<M: Metrics>(
        &mut self, qconn: &mut QuicheConnection, _metrics: &M,
        _work_loop_result: &QuicResult<()>,
    ) {
        let _ = self
            .record_tx
            .send(ConnectionRecord::Close(ConnectionCloseDetails::new(qconn)));

        let _ = self
            .record_tx
            .send(ConnectionRecord::ConnectionStats(qconn.stats()));

        let conn_path_stats = qconn.path_stats().collect::<Vec<PathStats>>();
        let _ = self
            .record_tx
            .send(ConnectionRecord::PathStats(conn_path_stats));
    }
}

pub enum ConnectionRecord {
    ActionFailed(String),
    StreamedFrame { stream_id: u64, frame: H3iFrame },
    Close(ConnectionCloseDetails),
    PathStats(Vec<PathStats>),
    ConnectionStats(Stats),
}
