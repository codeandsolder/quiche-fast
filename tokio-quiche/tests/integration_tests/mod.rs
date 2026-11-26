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

use crate::fixtures::*;
use h3i_fixtures::received_status_code_on_stream;

use futures::StreamExt;
use futures_util::future::try_join_all;
use std::time::Duration;
use tokio::time::timeout;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::settings::Hooks;
use tokio_quiche::ConnectionParams;
use tokio_quiche::InitialQuicConnection;
use tracing::instrument::WithSubscriber;

pub mod async_callbacks;
pub mod connection_close;
pub mod h3i_schedule;
pub mod headers;
pub mod migration;
pub mod path_events;
pub mod qlog_compression;
pub mod stream_limit;
pub mod timeouts;
pub mod zero_rtt;

#[tokio::test]
async fn echo() -> QuicResult<()> {
    const CONN_COUNT: usize = 5;

    let req_count = |conn_num| conn_num * 100;
    let (url, hook, _) = start_server()?;
    let mut reqs = vec![];

    for i in 1..=CONN_COUNT {
        let url = format!("{url}/{i}");

        reqs.push(request(url, req_count(i) as u64));
    }

    let results = try_join_all(reqs).await?;
    let res_map = map_responses(results)?;

    assert_eq!(res_map.len(), CONN_COUNT);

    for i in 1..=CONN_COUNT {
        let responses = res_map.get(&i).ok_or("missing connection response")?;

        assert_eq!(responses.len(), req_count(i));
    }

    assert!(hook.was_called());
    Ok(())
}

#[tokio::test]
async fn e2e() -> QuicResult<()> {
    let (url, hook, _) = start_server()?;
    let url = format!("{url}/1");

    let results = request(url, 1).await?;
    let res_map = map_responses(vec![results])?;

    assert_eq!(res_map.len(), 1);

    let responses = res_map.get(&1).ok_or("missing connection response")?;
    assert_eq!(responses.len(), 1);
    assert!(hook.was_called());
    Ok(())
}

#[tokio::test]
async fn e2e_client_ip_validation_disabled() -> QuicResult<()> {
    let mut quic_settings = QuicSettings::default();
    quic_settings.max_recv_udp_payload_size = 1400;
    quic_settings.max_send_udp_payload_size = 1400;
    quic_settings.max_idle_timeout = Some(Duration::from_secs(5));
    quic_settings.disable_client_ip_validation = true;

    let hook = TestConnectionHook::new();

    let (url, _) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook.clone(),
        handle_connection,
    )?;
    let url = format!("{url}/1");
    let reqs = vec![request(url, 1)];

    let results = try_join_all(reqs).await?;
    let res_map = map_responses(results)?;

    assert_eq!(res_map.len(), 1);

    let responses = res_map.get(&1).ok_or("missing connection response")?;
    assert_eq!(responses.len(), 1);
    assert!(hook.was_called());
    Ok(())
}

// Exercise the persistent per-connection egress buffer path, i.e. the IO
// worker with `QuicSettings::pool_send_buffer` disabled. The default (pooling
// enabled) path is covered by every other end-to-end test.
#[tokio::test]
async fn e2e_pooled_send_buffer_disabled() -> QuicResult<()> {
    let mut quic_settings = QuicSettings::default();
    quic_settings.max_recv_udp_payload_size = 1400;
    quic_settings.max_send_udp_payload_size = 1400;
    quic_settings.pool_send_buffer = false;

    let hook = TestConnectionHook::new();

    let (url, _) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook.clone(),
        handle_connection,
    )?;
    let url = format!("{url}/1");
    let reqs = vec![request(url, 1)];

    let results = try_join_all(reqs).await?;
    let res_map = map_responses(results)?;

    assert_eq!(res_map.len(), 1);

    let responses = res_map.get(&1).ok_or("missing connection response")?;
    assert_eq!(responses.len(), 1);
    assert!(hook.was_called());
    Ok(())
}

#[tokio::test]
async fn quiche_logs_forwarded_server_side() -> QuicResult<()> {
    let cx = TestLogs::default();
    let subscriber = cx.subscriber();
    async move {
        let mut quic_settings = QuicSettings::default();
        quic_settings.capture_quiche_logs = true;

        let hook = TestConnectionHook::new();

        let (url, _) = start_server_with_settings(
            quic_settings,
            Http3Settings::default(),
            hook,
            handle_connection,
        )?;
        let url = format!("{url}/1");
        let reqs = vec![request(url, 1)];

        let results = try_join_all(reqs).await?;
        let res_map = map_responses(results)?;

        assert_eq!(res_map.len(), 1);

        assert!(cx
            .records()
            .iter()
            .any(|(level, message)| (message.contains("rx pkt") ||
                message.contains("tx pkt")) &&
                *level == tracing::Level::TRACE));
        Ok(())
    }
    .with_subscriber(subscriber)
    .await
}

#[tokio::test]
async fn test_ioworker_state_machine_pause() -> QuicResult<()> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let url = format!("http://127.0.0.1:{}", socket.local_addr()?.port());

    let credentials = TestCredentials::new()?;
    let tls_cert_settings = test_certificate_paths(&credentials);

    let hooks = Hooks {
        connection_hook: Some(TestConnectionHook::new()),
    };

    let params = ConnectionParams::new_server(
        QuicSettings::default(),
        tls_cert_settings,
        hooks,
    );
    let mut stream = listen(vec![socket], &params, &DefaultMetrics)?
        .into_iter()
        .next()
        .ok_or("listener returned no stream")?;

    let server = tokio::spawn(async move {
        let (driver, controller) = ServerH3Driver::new(&Http3Settings::default());
        let conn = stream.next().await.ok_or("listener closed")??;
        let (connection, worker) = conn.handshake(driver).await?;
        InitialQuicConnection::resume(worker);
        handle_connection(ServerH3Connection::new(connection, controller)).await;
        Ok::<(), tokio_quiche::BoxError>(())
    });

    let url = format!("{url}/1");
    let summary =
        timeout(Duration::from_secs(2), h3i_fixtures::request(&url, 1)).await??;

    assert!(received_status_code_on_stream(&summary, 0, 200));
    timeout(Duration::from_secs(2), server).await???;
    Ok(())
}

#[tokio::test]
async fn native_client_handshakes_and_exchanges_http3_request(
) -> tokio_quiche::QuicResult<()> {
    use tokio_quiche::http3::driver::ClientH3Event;
    use tokio_quiche::http3::driver::H3Event;
    use tokio_quiche::http3::driver::NewClientRequest;
    use tokio_quiche::quiche::h3::NameValue;
    let (url, _hook, _audit) = start_server()?;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(extract_host_ipv4(&url)?).await?;
    let (connection, mut controller) = timeout(
        Duration::from_secs(5),
        tokio_quiche::quic::connect(socket, Some("test.com")),
    )
    .await??;
    assert!(connection
        .audit_log_stats()
        .transport_handshake_duration()
        .is_some());
    controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 17,
            headers: h3i_fixtures::default_headers(),
            body_writer: None,
        })
        .map_err(|_| "client request queue closed")?;
    timeout(Duration::from_secs(5), async {
        loop {
            match controller.event_receiver_mut().recv().await {
                Some(ClientH3Event::Core(H3Event::IncomingHeaders(headers))) => {
                    assert!(headers
                        .headers
                        .iter()
                        .any(|header| header.name() == b":status" &&
                            header.value() == b"200"));
                    return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
                },
                Some(ClientH3Event::Core(H3Event::ConnectionShutdown(_))) |
                None =>
                    return Err("client connection closed before response".into()),
                _ => (),
            }
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn native_client_shutdown_waits_for_worker_and_is_idempotent(
) -> tokio_quiche::QuicResult<()> {
    use datagram_socket::ShutdownConnectionExt as _;
    let (url, _hook, _audit) = start_server()?;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(extract_host_ipv4(&url)?).await?;
    let (mut connection, mut controller) = timeout(
        Duration::from_secs(5),
        tokio_quiche::quic::connect(socket, Some("test.com")),
    )
    .await??;

    // Keep the controller alive: shutdown must not depend on dropping it.
    timeout(Duration::from_secs(3), connection.shutdown_connection()).await??;
    connection.shutdown_connection().await?;
    timeout(Duration::from_secs(2), async {
        while controller.event_receiver_mut().recv().await.is_some() {}
    })
    .await?;
    Ok(())
}

#[tokio::test]
#[cfg(feature = "custom-client-dcid")]
async fn test_connect_with_custom_dcid() -> tokio_quiche::QuicResult<()> {
    use tokio_quiche::http3::settings::Http3Settings;
    use tokio_quiche::quic::connect_with_config;
    use tokio_quiche::socket::Socket;
    use tokio_quiche::ClientH3Driver;
    use tokio_quiche::ConnectionIdGenerator;

    let (url, _hook, _audit_stats_rx) = start_server()?;
    let addr = extract_host_ipv4(&url)?;

    let tokio_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    tokio_socket.connect(addr).await?;
    let socket = Socket::try_from(tokio_socket)?;
    let (h3_driver, _h3_controller) =
        ClientH3Driver::new(&Http3Settings::default());
    let dcid =
        tokio_quiche::quic::SimpleConnectionIdGenerator.new_connection_id()?;
    let mut params = ConnectionParams::default();
    params.dcid = Some(dcid);

    assert!(timeout(
        Duration::from_secs(5),
        connect_with_config(socket, Some("127.0.0.1"), &params, h3_driver,),
    )
    .await?
    .is_ok());
    Ok(())
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_so_mark_receive_data() -> QuicResult<()> {
    let (url, _, mut audit_stats_rx) = start_server()?;

    let url = format!("{url}/1");
    let summary =
        timeout(Duration::from_secs(2), h3i_fixtures::request(&url, 1)).await??;

    assert!(received_status_code_on_stream(&summary, 0, 200));

    let audit_stats = timeout(Duration::from_secs(2), audit_stats_rx.recv())
        .await?
        .ok_or("should receive stats")?;
    let so_mark_data = audit_stats.initial_so_mark_data();
    // SO_MARK is not set. Only verify that `Some` indicates receipt of the
    // socket control message.
    assert_eq!(so_mark_data.ok_or("missing SO_MARK data")?, &[0, 0, 0, 0]);
    Ok(())
}
