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

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use btls::ssl::BoxSelectCertFinish;
use btls::ssl::ClientHello;
use btls::ssl::SslContextBuilder;
use btls::ssl::SslFiletype;
use btls::ssl::SslMethod;
use h3i::actions::h3::send_headers_frame;
use h3i::actions::h3::Action;
use h3i::actions::h3::WaitType;
use h3i::quiche::ConnectionError;
use h3i::quiche::{
    self,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tokio_quiche::http3::driver::H3ConnectionError;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::settings::TlsCertificatePaths;

use crate::fixtures::h3i_fixtures::*;
use crate::fixtures::*;

async fn assert_client_handshake_timeout<Tx, Rx>(
    socket: tokio_quiche::socket::Socket<Tx, Rx>,
) -> tokio_quiche::QuicResult<()>
where
    Tx: datagram_socket::DatagramSocketSend + Send + 'static,
    Rx: datagram_socket::DatagramSocketRecv + Unpin + 'static,
{
    let mut settings = QuicSettings::default();
    settings.handshake_timeout = Some(Duration::from_millis(100));
    settings.max_idle_timeout = Some(Duration::from_secs(10));
    let params = tokio_quiche::ConnectionParams::new_client(
        settings,
        None,
        tokio_quiche::settings::Hooks::default(),
    );
    let (app, _controller) =
        tokio_quiche::ClientH3Driver::new(&Http3Settings::default());
    let result = timeout(
        Duration::from_secs(3),
        tokio_quiche::quic::connect_with_config(
            socket,
            Some("test.com"),
            &params,
            app,
        ),
    )
    .await?;
    let error = result
        .err()
        .ok_or("silent peer unexpectedly completed handshake")?;
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::TimedOut)
    );
    Ok(())
}

#[tokio::test]
async fn native_client_handshake_timeout_includes_initial_packet_flight(
) -> tokio_quiche::QuicResult<()> {
    use tokio_quiche::socket::Socket;
    let silent_peer = UdpSocket::bind("127.0.0.1:0").await?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(silent_peer.local_addr()?).await?;
    assert_client_handshake_timeout(Socket::try_from(socket)?).await?;
    let mut initial = [0; 1500];
    let (length, _) =
        timeout(Duration::from_secs(1), silent_peer.recv_from(&mut initial))
            .await??;
    assert!(length >= quiche::MIN_CLIENT_INITIAL_LEN);
    Ok(())
}

struct BlockedSender(Arc<AtomicUsize>);

impl datagram_socket::DatagramSocketSend for BlockedSender {
    fn poll_send(
        &self, _cx: &mut std::task::Context<'_>, _buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        std::task::Poll::Pending
    }

    fn poll_send_to(
        &self, cx: &mut std::task::Context<'_>, buffer: &[u8],
        _addr: std::net::SocketAddr,
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.poll_send(cx, buffer)
    }
}

#[tokio::test]
async fn native_client_handshake_deadline_survives_permanently_blocked_send(
) -> tokio_quiche::QuicResult<()> {
    use tokio_quiche::socket::Socket;
    let silent_peer = UdpSocket::bind("127.0.0.1:0").await?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(silent_peer.local_addr()?).await?;
    let socket = Socket::try_from(socket)?;
    let send_polls = Arc::new(AtomicUsize::new(0));
    assert_client_handshake_timeout(Socket {
        send: BlockedSender(Arc::clone(&send_polls)),
        recv: socket.recv,
        local_addr: socket.local_addr,
        peer_addr: socket.peer_addr,
        capabilities: socket.capabilities,
    })
    .await?;
    assert!(send_polls.load(Ordering::Relaxed) > 0);
    Ok(())
}

// TODO(erittenhouse): figure out a way to avoid all of this duplication
#[tokio::test]
async fn test_handshake_duration_ioworker() -> QuicResult<()> {
    use h3i::client::ClientError;

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);
    struct TestAsyncCallbackConnectionHook {
        was_called: Arc<AtomicBool>,
    }

    impl ConnectionHook for TestAsyncCallbackConnectionHook {
        fn create_custom_ssl_context_builder(
            &self, settings: TlsCertificatePaths<'_>,
        ) -> QuicResult<Option<SslContextBuilder>> {
            let mut ssl_ctx_builder = SslContextBuilder::new(SslMethod::tls())?;
            let cloned_bool = Arc::clone(&self.was_called);

            ssl_ctx_builder.set_async_select_certificate_callback(move |_| {
                cloned_bool.store(true, Ordering::SeqCst);

                Ok(Box::pin(async {
                    // Pause during the handshake. Give some extra time to
                    // (hopefully) avoid flakiness.
                    tokio::time::sleep(HANDSHAKE_TIMEOUT.mul_f32(1.5)).await;
                    Ok(Box::new(|_: ClientHello<'_>| Ok(()))
                        as BoxSelectCertFinish)
                }))
            });

            ssl_ctx_builder
                .set_private_key_file(settings.private_key, SslFiletype::PEM)?;

            ssl_ctx_builder.set_certificate_chain_file(settings.cert)?;

            Ok(Some(ssl_ctx_builder))
        }
    }

    let hook = Arc::new(TestAsyncCallbackConnectionHook {
        was_called: Arc::new(AtomicBool::new(false)),
    });

    let mut quic_settings = QuicSettings::default();
    quic_settings.max_idle_timeout = Some(Duration::from_secs(5));
    quic_settings.handshake_timeout = Some(HANDSHAKE_TIMEOUT);

    let mut http3_settings = Http3Settings::default();
    http3_settings.post_accept_timeout = Some(HANDSHAKE_TIMEOUT);

    let (url, _) = start_server_with_settings(
        quic_settings,
        http3_settings,
        hook.clone(),
        handle_connection,
    )?;

    // TODO: Use the synchronous h3i client to assert that CONNECTION_CLOSE was
    // received while isolating the tokio-quiche IO loop.
    //
    // This test cannot use PCAP because its encryption keys are not dumped.
    //
    // `build()` spawns `InboundPacketRouter` and sends the Initial, starting
    // the server handshake. The server then closes the connection, and the
    // router times it out.
    let url = format!("{url}/1");
    let client_res = h3i_fixtures::request(&url, 1).await;

    assert!(matches!(client_res, Err(ClientError::HandshakeFail)));
    assert!(hook.was_called.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn test_handshake_timeout_with_one_client_flight() -> QuicResult<()> {
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(1);
    let hook = TestConnectionHook::new();
    let mut quic_settings = QuicSettings::default();
    quic_settings.handshake_timeout = Some(HANDSHAKE_TIMEOUT);

    let (url, _) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook.clone(),
        handle_connection,
    )?;

    let peer_addr = extract_host_ipv4(&url)?;

    let mut quiche_config = quiche::Config::new(1)?;
    quiche_config.verify_peer(false);
    quiche_config.set_application_protos(&[b"h3"])?;
    quiche_config.set_max_recv_udp_payload_size(1350);
    quiche_config.set_max_send_udp_payload_size(1350);

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(peer_addr).await?;

    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    btls::rand::rand_bytes(&mut scid)?;
    let scid = quiche::ConnectionId::from_ref(&scid);

    let local_addr = socket.local_addr()?;
    let mut quiche_conn = quiche::connect(
        Some("test.com"),
        &scid,
        local_addr,
        peer_addr,
        &mut quiche_config,
    )?;

    // Send first Initial packet
    let mut out = vec![0; 65535];
    let (write, _) = quiche_conn.send(&mut out)?;
    socket.send(&out[..write]).await?;

    // Receive Retry packet
    let (len, from) = socket.recv_from(&mut out).await?;
    let recv_info = quiche::RecvInfo {
        from,
        to: socket.local_addr()?,
    };
    let _ = quiche_conn.recv(&mut out[..len], recv_info);

    // Send second Initial packet, which will spawn the TQ Handshake IOW
    let (written, _) = quiche_conn.send(&mut out)?;
    socket.send(&out[..written]).await?;

    let err = timeout(
        // Give a small buffer for the handshake timeout to fire
        HANDSHAKE_TIMEOUT.mul_f32(1.5),
        async move {
            loop {
                let (len, from) = socket.recv_from(&mut out).await?;
                let recv_info = quiche::RecvInfo {
                    from,
                    to: socket.local_addr()?,
                };
                let _ = quiche_conn.recv(&mut out[..len], recv_info);

                if let Some(e) = quiche_conn.peer_error().cloned() {
                    return Ok::<_, tokio_quiche::BoxError>(e);
                }
            }
        },
    )
    .await;

    assert_eq!(err??, ConnectionError {
        is_app: false,
        error_code: quiche::WireErrorCode::ApplicationError as u64,
        reason: vec![]
    });
    Ok(())
}

#[tokio::test]
async fn test_post_accept_timeout() -> QuicResult<()> {
    const POST_ACCEPT_TIMEOUT: Duration = Duration::from_secs(1);

    // Absence of async callbacks should render the handshake portion of the
    // post-accept timeout (see test_handshake_duration_ioworker) calculation
    // negligble.
    let hook = TestConnectionHook::new();

    // Track if we've seen any requests over this connection.
    let request_counter = Arc::new(AtomicUsize::new(0));
    let clone = Arc::clone(&request_counter);

    let mut quic_settings = QuicSettings::default();
    // Since this is longer than the H3Driver's post-accept timeout, if
    // the connection fails we know that it's from the
    // post-accept timeout rather than Quiche's idle timeout.
    quic_settings.max_idle_timeout = Some(Duration::from_secs(5));

    let mut http3_settings = Http3Settings::default();
    http3_settings.post_accept_timeout = Some(POST_ACCEPT_TIMEOUT);

    let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
    let (url, _) = start_server_with_settings(
        quic_settings,
        http3_settings,
        hook,
        move |mut h3_conn| {
            let counter = Arc::clone(&clone);
            let result_tx = result_tx.clone();
            async move {
                let result =
                    serve_connection_details(&mut h3_conn.h3_controller, counter)
                        .await;
                let _ = result_tx.send(result);
            }
        },
    )?;

    let h3i_config = h3i_config(&url)?;
    let actions = vec![Action::Wait {
        wait_type: WaitType::WaitDuration(POST_ACCEPT_TIMEOUT.mul_f32(1.5)),
    }];

    let summary = summarize_connection(h3i_config, actions).await?;

    // Since the server's idle timeout is longer than the H3Driver's post-accept
    // timeout, the connection should have closed without any requests being
    // received.
    assert_eq!(request_counter.load(Ordering::SeqCst), 0);

    let err = summary
        .conn_close_details
        .peer_error()
        .ok_or("no error received")?;
    assert!(err.is_app);
    assert_eq!(err.error_code, quiche::h3::WireErrorCode::NoError as u64);
    let result = timeout(Duration::from_secs(2), result_rx.recv())
        .await?
        .ok_or("missing server result")?;
    let error = result
        .err()
        .ok_or("server did not report post-accept timeout")?;
    assert_eq!(
        error.downcast_ref::<H3ConnectionError>(),
        Some(&H3ConnectionError::PostAcceptTimeout)
    );
    Ok(())
}

#[tokio::test]
async fn test_post_accept_timeout_is_reset() -> QuicResult<()> {
    const POST_ACCEPT_TIMEOUT: Duration = Duration::from_secs(1);

    // Absence of async callbacks should render the handshake portion of the
    // post-accept timeout (see test_handshake_duration_ioworker) calculation
    // negligble.
    let hook = TestConnectionHook::new();

    let request_counter = Arc::new(AtomicUsize::new(0));
    let clone = Arc::clone(&request_counter);

    let mut quic_settings = QuicSettings::default();
    // Since this is longer than the H3Driver's post-accept timeout, if
    // the connection fails we know that it's from the
    // post-accept timeout rather than Quiche's idle timeout.
    quic_settings.max_idle_timeout = Some(Duration::from_secs(5));

    let mut http3_settings = Http3Settings::default();
    http3_settings.post_accept_timeout = Some(POST_ACCEPT_TIMEOUT);

    let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
    let (url, _) = start_server_with_settings(
        quic_settings,
        http3_settings,
        hook,
        move |mut h3_conn| {
            let counter = Arc::clone(&clone);
            let result_tx = result_tx.clone();
            async move {
                let result =
                    serve_connection_details(&mut h3_conn.h3_controller, counter)
                        .await;
                let _ = result_tx.send(result);
            }
        },
    )?;

    let h3i_config = h3i_config(&url)?;
    let actions = vec![
        // Just to ensure that normal waits don't accidentally trigger the
        // post-accept timeout
        Action::Wait {
            wait_type: WaitType::WaitDuration(POST_ACCEPT_TIMEOUT.mul_f32(0.50)),
        },
        send_headers_frame(0, true, default_headers()),
        Action::FlushPackets,
        // Post-accept timeout should be cancelled, so we can wait an arbitrary
        // period (less than the idle timeout of course) and the
        // post-accept timeout shouldn't fire
        Action::Wait {
            wait_type: WaitType::WaitDuration(POST_ACCEPT_TIMEOUT.mul_f32(1.1)),
        },
        send_headers_frame(4, true, default_headers()),
        Action::FlushPackets,
    ];

    let summary = summarize_connection(h3i_config, actions).await?;
    assert!(summary.conn_close_details.no_err());

    for i in [0, 4] {
        assert!(received_status_code_on_stream(&summary, i, 200));
    }

    assert_eq!(request_counter.load(Ordering::SeqCst), 2);
    let result = timeout(Duration::from_secs(2), result_rx.recv())
        .await?
        .ok_or("missing server result")?;
    result?;
    Ok(())
}
