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

use std::future::pending;
use std::future::Future;
use std::time::Duration;
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
use crate::client::MAX_DATAGRAM_SIZE;
use crate::config::Config as H3iConfig;

use super::action_queue::ActionQueue;
use super::ClientState;

/// Connect to the socket.
///
/// # Errors
/// Returns a client error if connection setup or the handshake fails.
pub async fn connect(
    args: &H3iConfig, frame_actions: Vec<Action>,
    close_trigger_frames: Option<CloseTriggerFrames>,
) -> Result<
    impl Future<Output = Result<ConnectionSummary, ClientError>>,
    ClientError,
> {
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

    let local_addr = socket
        .local_addr()
        .map_err(|error| ClientError::Other(error.to_string()))?;
    log::info!("connecting to {peer_addr} from {local_addr}");

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
        Ok(_) => Ok(async move {
            conn_summary_fut.await.map_err(|_| {
                ClientError::Other(
                    "connection driver ended without a summary".into(),
                )
            })?
        }),
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
    quic_settings.initial_max_data = args.flow.data;
    quic_settings.initial_max_stream_data_bidi_local =
        args.flow.stream_data_bidi_local;
    quic_settings.initial_max_stream_data_bidi_remote =
        args.flow.stream_data_bidi_remote;
    quic_settings.initial_max_stream_data_uni = args.flow.stream_data_uni;
    quic_settings.initial_max_streams_bidi = args.flow.streams_bidi;
    quic_settings.initial_max_streams_uni = args.flow.streams_uni;
    quic_settings.disable_active_migration = true;
    quic_settings.active_connection_id_limit = 0;
    quic_settings.max_connection_window = args.flow.window;
    quic_settings.max_stream_window = args.flow.stream_window;
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

/// Owns the action scheduler and received frames on the I/O worker.
/// Close triggers are evaluated independently of summary polling.
struct H3iDriver {
    queue: ActionQueue,
    client: ClientState,
    summary_tx: Option<oneshot::Sender<Result<ConnectionSummary, ClientError>>>,
}

impl H3iDriver {
    fn new(
        actions: Vec<Action>, close_trigger_frames: Option<CloseTriggerFrames>,
    ) -> (
        Self,
        oneshot::Receiver<Result<ConnectionSummary, ClientError>>,
    ) {
        let (summary_tx, summary_rx) = oneshot::channel();
        (
            Self {
                queue: ActionQueue::new(actions),
                client: ClientState::new(close_trigger_frames),
                summary_tx: Some(summary_tx),
            },
            summary_rx,
        )
    }

    fn check_close_triggers(&self, qconn: &mut QuicheConnection) {
        if qconn.is_established() {
            self.client.streams.close_due_to_trigger_frames(qconn);
        }
    }
}

impl ApplicationOverQuic for H3iDriver {
    fn on_application_ready(
        &mut self, qconn: &mut QuicheConnection, _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        log::info!("h3i: HTTP/3 connection established");
        self.check_close_triggers(qconn);
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
            .map_err(ClientError::Other)?;
        for event in parse_streams(qconn, &mut self.client) {
            self.queue.on_stream_event(event);
        }
        self.check_close_triggers(qconn);
        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        log::trace!("h3i: process_writes");
        self.check_close_triggers(qconn);
        if qconn.is_draining() ||
            qconn.is_closed() ||
            qconn.local_error().is_some()
        {
            return Ok(());
        }
        self.queue
            .advance(
                || Instant::now().into_std(),
                qconn,
                &mut self.client.parsers,
            )
            .map_err(|error| ClientError::Other(error).into())
    }

    async fn wait_for_data(
        &mut self, qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        let deadline = if qconn.is_established() &&
            !qconn.is_draining() &&
            !qconn.is_closed() &&
            qconn.local_error().is_none()
        {
            self.queue
                .wakeup(Instant::now().into_std())
                .map(Instant::from_std)
        } else {
            None
        };
        if let Some(deadline) = deadline {
            sleep_until(deadline).await;
        } else {
            pending::<()>().await;
        }
        Ok(())
    }

    fn on_conn_close<M: Metrics>(
        &mut self, qconn: &mut QuicheConnection, _metrics: &M,
        work_loop_result: &QuicResult<()>,
    ) {
        if let Some(tx) = self.summary_tx.take() {
            let result = if !qconn.is_established() {
                Err(ClientError::HandshakeFail)
            } else if let Err(error) = work_loop_result {
                Err(ClientError::Other(error.to_string()))
            } else {
                Ok(ConnectionSummary::from_connection(
                    qconn,
                    std::mem::take(&mut self.client.streams),
                ))
            };
            let _ = tx.send(result);
        }
    }
}
