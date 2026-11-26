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

use crate::fixtures::TestLogs;
use crate::integration_tests::extract_host_ipv4;
use crate::integration_tests::h3i_fixtures;
use crate::integration_tests::start_server_with_settings;
use crate::integration_tests::Http3Settings;
use crate::integration_tests::QuicSettings;
use crate::integration_tests::TestConnectionHook;
use datagram_socket::QuicAuditStats;
use futures::SinkExt;
use h3i;
use h3i::actions::h3::send_headers_frame;
use h3i::actions::h3::Action;
use h3i::actions::h3::StreamEvent;
use h3i::actions::h3::StreamEventType;
use h3i::actions::h3::WaitType;
use h3i::client::connection_summary::ConnectionSummary;
use quiche::h3::NameValue;
use quiche::ConnectionError;
use quiche::WireErrorCode;
use std::future::Future;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::ServerH3Event;
use tokio_quiche::metrics::labels::HandshakeError as HandshakeErrorLabel;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::metrics::Metrics;
use tokio_quiche::quic::HandshakeError;
use tokio_quiche::quiche::h3::Header;
use tokio_quiche::QuicResult;
use tokio_quiche::ServerH3Connection;
use tracing::instrument::WithSubscriber;

#[derive(Debug, Default, Clone)]
struct TestContext {
    requests_handled_count: usize,
    requests_seen: Vec<(String, bool)>,
}

#[tokio::test]
async fn handle_0_rtt_request() -> QuicResult<()> {
    check_resumed_requests(false).await?;
    Ok(())
}

#[tokio::test]
async fn handle_0_rtt_request_with_retry() -> QuicResult<()> {
    check_resumed_requests(true).await?;
    Ok(())
}

async fn check_resumed_requests(retry: bool) -> QuicResult<()> {
    let context = Arc::new(Mutex::new(TestContext::default()));
    let early_stream_id = 0;
    let stream_id = 4;

    let context_clone = context.clone();
    let mut quic_settings = QuicSettings::default();
    quic_settings.enable_early_data = true;
    quic_settings.disable_client_ip_validation = !retry;
    let (handler_tx, mut handler_rx) = mpsc::unbounded_channel();
    let (url, _) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        TestConnectionHook::new(),
        move |h3_conn| {
            let handler = helper_server_handler(h3_conn, &context_clone);
            let handler_tx = handler_tx.clone();
            async move {
                let _ = handler_tx.send(handler.await);
            }
        },
    )?;

    let nst_data = {
        let summary = {
            let h3i_config = h3i_fixtures::h3i_config(&url)?;
            helper_connect_with_early_data(
                h3i_config,
                None,
                helper_frame_actions(stream_id),
            )
            .await?
        };

        {
            let context = context.lock().map_err(|_| "test context poisoned")?;
            assert_eq!(context.requests_seen, vec![(
                "test.com".to_owned(),
                false
            )]);
            assert_eq!(context.requests_handled_count, 1);
        }

        // Get Session data from this connection to resume the 0-RTT connection.
        summary
            .conn_close_details
            .session
            .ok_or("missing resumption session")?
    };

    timeout(Duration::from_secs(2), handler_rx.recv())
        .await?
        .ok_or("missing first server result")??;
    helper_reset_test(&context)?;

    {
        let early_frame_actions = vec![
            send_headers_frame(
                early_stream_id,
                false,
                h3i_fixtures::default_headers_with_authority("early.test.com"),
            ),
            Action::FlushPackets,
        ];

        let mut h3i_config = h3i_fixtures::h3i_config(&url)?;
        // Provide session to the client to enable resumption.
        h3i_config.session = Some(nst_data);
        h3i_config.tls.early_data = true;
        let _summary = helper_connect_with_early_data(
            h3i_config,
            Some(early_frame_actions),
            helper_frame_actions(stream_id),
        )
        .await?;

        {
            let context = context.lock().map_err(|_| "test context poisoned")?;
            // QUIC does not order requests across independent streams.
            let mut requests = context.requests_seen.clone();
            requests.sort_unstable();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[0].0, "early.test.com");
            assert_eq!(requests[1], ("test.com".to_owned(), false));
            // Retry can require recovery of early stream data after the
            // handshake. Without Retry, prove actual early delivery.
            if !retry {
                assert!(requests[0].1);
            }
            assert_eq!(context.requests_handled_count, 2);
        }
    }
    timeout(Duration::from_secs(2), handler_rx.recv())
        .await?
        .ok_or("missing resumed server result")??;
    Ok(())
}

pub async fn helper_connect_with_early_data(
    h3i_config: h3i::config::Config, early_actions: Option<Vec<Action>>,
    actions: Vec<Action>,
) -> QuicResult<ConnectionSummary> {
    tokio::task::spawn_blocking(move || {
        h3i::client::sync_client::connect_with_early_data(
            h3i_config,
            early_actions,
            actions,
            None,
        )
    })
    .await?
    .map_err(Into::into)
}

fn helper_reset_test(context: &Arc<Mutex<TestContext>>) -> QuicResult<()> {
    let mut context = context.lock().map_err(|_| "test context poisoned")?;
    *context = TestContext::default();
    drop(context);
    Ok(())
}

fn helper_frame_actions(stream_id: u64) -> Vec<Action> {
    vec![
        send_headers_frame(stream_id, true, h3i_fixtures::default_headers()),
        Action::FlushPackets,
        Action::Wait {
            wait_type: WaitType::StreamEvent(StreamEvent {
                stream_id,
                event_type: StreamEventType::Finished,
            }),
        },
        Action::ConnectionClose {
            error: ConnectionError {
                is_app: true,
                error_code: WireErrorCode::NoError as _,
                reason: Vec::new(),
            },
        },
    ]
}

fn helper_server_handler(
    mut h3_conn: ServerH3Connection, context: &Arc<Mutex<TestContext>>,
) -> impl Future<Output = QuicResult<()>> + use<> {
    let context = context.clone();

    async move {
        let event_rx = h3_conn.h3_controller.event_receiver_mut();

        while let Some(event) = event_rx.recv().await {
            match event {
                ServerH3Event::Core(event) => {
                    if let H3Event::ConnectionShutdown(_) = event {
                        break;
                    }
                },

                ServerH3Event::Headers {
                    incoming_headers,
                    is_in_early_data,
                    ..
                } => {
                    let IncomingH3Headers {
                        mut send, headers, ..
                    } = incoming_headers;

                    let authority = headers
                        .iter()
                        .find(|v| v.name() == b":authority")
                        .ok_or("missing authority")?;

                    {
                        let mut context = context
                            .lock()
                            .map_err(|_| "test context poisoned")?;
                        context.requests_handled_count += 1;
                        let host =
                            std::str::from_utf8(authority.value())?.to_string();
                        context.requests_seen.push((host, *is_in_early_data));
                    }

                    // Send headers.
                    send.send(OutboundFrame::Headers(
                        vec![Header::new(b":status", b"200")],
                        None,
                    ))
                    .await?;

                    send.send(OutboundFrame::Body(bytes::Bytes::new(), true))
                        .await?;
                },
            }
        }
        Ok(())
    }
}

/// A server accepting 0-RTT early data, with a session to resume with 0-RTT.
struct EarlyDataServer {
    url: String,
    audit_stats_rx: mpsc::UnboundedReceiver<Arc<QuicAuditStats>>,
    /// Set when the server application receives a request in early data,
    /// which proves that the server accepted 0-RTT and started the application
    /// before the handshake completed.
    recv_early_data_request: Arc<AtomicBool>,
    session: Vec<u8>,
}

impl EarlyDataServer {
    async fn start(handshake_timeout: Duration) -> QuicResult<Self> {
        let mut quic_settings = QuicSettings::default();
        quic_settings.enable_early_data = true;
        quic_settings.disable_client_ip_validation = true;
        quic_settings.handshake_timeout = Some(handshake_timeout);
        // The client keeps sending packets, so the idle timeout never fires.
        quic_settings.max_idle_timeout = Some(Duration::from_secs(60));

        let recv_early_data_request = Arc::new(AtomicBool::new(false));

        let recv_early_data_request_clone = recv_early_data_request.clone();
        let (url, mut audit_stats_rx) = start_server_with_settings(
            quic_settings,
            Http3Settings::default(),
            TestConnectionHook::new(),
            move |mut h3_conn: ServerH3Connection| {
                let recv_early_data_request =
                    recv_early_data_request_clone.clone();

                async move {
                    // Keep the connection alive until it is closed by the
                    // server.
                    let event_rx = h3_conn.h3_controller.event_receiver_mut();
                    while let Some(event) = event_rx.recv().await {
                        if let ServerH3Event::Headers {
                            is_in_early_data, ..
                        } = event
                        {
                            if *is_in_early_data {
                                recv_early_data_request
                                    .store(true, Ordering::SeqCst);
                            }
                        }
                    }
                }
            },
        )?;

        // Get a session to resume with 0-RTT.
        let session = {
            let h3i_config = h3i_fixtures::h3i_config(&url)?;
            let summary = helper_connect_with_early_data(
                h3i_config,
                None,
                helper_frame_actions(4),
            )
            .await?;

            summary
                .conn_close_details
                .session
                .ok_or("missing resumption session")?
        };

        // Wait for the first connection to be fully closed.
        timeout(Duration::from_secs(5), audit_stats_rx.recv())
            .await?
            .ok_or("first connection did not close")?;

        Ok(Self {
            url,
            audit_stats_rx,
            recv_early_data_request,
            session,
        })
    }

    /// Asserts that the connection resumed with 0-RTT was closed by the
    /// handshake timeout, after the application was started.
    fn assert_handshake_timeout(
        &self, audit_stats: &QuicAuditStats,
    ) -> QuicResult<()> {
        let close_reason = audit_stats.connection_close_reason();
        let close_reason = close_reason.ok_or("missing close reason")?;
        assert_eq!(audit_stats.transport_handshake_duration(), None);
        assert!(matches!(
            close_reason.downcast_ref::<HandshakeError>(),
            Some(HandshakeError::Timeout)
        ));

        assert!(self.recv_early_data_request.load(Ordering::SeqCst));
        Ok(())
    }
}

/// A client that resumes a session with 0-RTT, sends a request in early data,
/// and never processes the server's packets, so the handshake never completes.
struct EarlyDataClient {
    socket: std::net::UdpSocket,
    conn: quiche::Connection,
    h3_conn: quiche::h3::Connection,
    stream_id: u64,
}

impl EarlyDataClient {
    fn connect(server: &EarlyDataServer) -> QuicResult<Self> {
        let peer_addr = extract_host_ipv4(&server.url)?;

        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(peer_addr)?;

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.verify_peer(false);
        config.set_application_protos(&[b"h3"])?;
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.enable_early_data();

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        btls::rand::rand_bytes(&mut scid)?;
        let scid = quiche::ConnectionId::from_ref(&scid);

        let mut conn = quiche::connect(
            Some("test.com"),
            &scid,
            socket.local_addr()?,
            peer_addr,
            &mut config,
        )?;
        conn.set_session(&server.session)?;

        // Send the Initial flight, after which the client can send 0-RTT data.
        let mut out = vec![0; 65535];
        let (len, _) = conn.send(&mut out)?;
        socket.send(&out[..len])?;
        assert!(conn.is_in_early_data());

        let h3_config = quiche::h3::Config::new();
        let mut h3_conn =
            quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;
        let stream_id = h3_conn.send_request(
            &mut conn,
            &h3i_fixtures::default_headers(),
            false,
        )?;

        Ok(Self {
            socket,
            conn,
            h3_conn,
            stream_id,
        })
    }

    /// Sends request body data in 0-RTT packets.
    fn send_body(&mut self, body: &[u8]) -> QuicResult<()> {
        assert!(self.conn.is_in_early_data());
        let _ =
            self.h3_conn
                .send_body(&mut self.conn, self.stream_id, body, false);

        let mut out = vec![0; 65535];
        while let Ok((len, _)) = self.conn.send(&mut out) {
            self.socket.send(&out[..len])?;
        }
        Ok(())
    }
}

/// A client that resumes a session with 0-RTT, but never completes the
/// handshake while it keeps sending 0-RTT packets, must still be subject to
/// the handshake timeout, even though the application was already started.
#[tokio::test]
async fn handshake_timeout_after_0_rtt() -> QuicResult<()> {
    let cx = TestLogs::default();
    let subscriber = cx.subscriber();
    async move {
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);

    let mut server = EarlyDataServer::start(HANDSHAKE_TIMEOUT).await?;

    // Metrics are global and shared with tests running concurrently, so only
    // check that the counter was incremented.
    let failed_handshake_timeouts = || {
        DefaultMetrics
            .failed_handshakes(HandshakeErrorLabel::Timeout)
            .get()
    };
    let failed_handshake_timeouts_before = failed_handshake_timeouts();

    let mut client = EarlyDataClient::connect(&server)?;

    let audit_stats = timeout(HANDSHAKE_TIMEOUT * 5, async {
        loop {
            client.send_body(b"a")?;

            tokio::select! {
                stats = server.audit_stats_rx.recv() => return stats.ok_or_else(|| tokio_quiche::BoxError::from("missing audit stats")),
                () = tokio::time::sleep(Duration::from_millis(50)) => (),
            }
        }
    })
    .await
    ??;

    server.assert_handshake_timeout(&audit_stats)?;
    assert!(failed_handshake_timeouts() > failed_handshake_timeouts_before);

    // A handshake timeout is an expected outcome, it must not be logged as an
    // error by the application.
    let error_logs: Vec<_> = cx
        .records()
        .into_iter()
        .filter(|(level, _)| *level == tracing::Level::ERROR)
        .map(|(_, message)| message)
        .collect();
    assert!(
        error_logs.is_empty(),
        "unexpected error logs: {error_logs:?}"
    );
    Ok(())
    }.with_subscriber(subscriber).await
}
