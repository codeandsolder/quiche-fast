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

use bytes::Bytes;
use datagram_socket::QuicAuditStats;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::InboundFrame;
use tokio_quiche::http3::driver::InboundFrameStream;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::OutboundFrameSender;
use tokio_quiche::http3::driver::ServerH3Event;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::quiche::h3::Header;
use tokio_quiche::quiche::h3::NameValue;
use tokio_quiche::quiche::h3::{
    self,
};
use tokio_quiche::settings::Hooks;
use tokio_quiche::settings::TlsCertificatePaths;
use tokio_quiche::ConnectionParams;
use tokio_quiche::ServerH3Controller;

use futures::stream::FuturesUnordered;
use futures::Future;
use futures::SinkExt;
use futures::StreamExt;
use regex::Regex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::select;
use tokio::sync::mpsc;

// Re-export for convenience
pub use tokio_quiche::http3::settings::Http3Settings;
pub use tokio_quiche::quic::ConnectionShutdownBehaviour;
pub use tokio_quiche::settings::QuicSettings;
pub use tokio_quiche::QuicResult;
pub use tokio_quiche::QuicResultExt;
pub use tokio_quiche::ServerH3Connection;
pub use tokio_quiche::ServerH3Driver;

pub mod h3i_fixtures;

use h3i_fixtures::stream_body;

#[path = "../../src/test_credentials.rs"]
mod credentials;
pub use credentials::TestCredentials;

pub fn test_certificate_paths(
    credentials: &TestCredentials,
) -> TlsCertificatePaths<'_> {
    let (cert, private_key) = credentials.paths();
    TlsCertificatePaths {
        cert,
        private_key,
        kind: tokio_quiche::settings::CertificateKind::X509,
    }
}

pub struct TestConnectionHook {
    was_called: Arc<AtomicBool>,
    path_events: Mutex<Vec<tokio_quiche::quiche::PathEvent>>,
}

impl TestConnectionHook {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            was_called: Arc::new(AtomicBool::new(false)),
            path_events: Mutex::new(Vec::new()),
        })
    }

    pub fn was_called(&self) -> bool {
        self.was_called.load(Ordering::SeqCst)
    }

    pub fn path_events(&self) -> Vec<tokio_quiche::quiche::PathEvent> {
        self.path_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl ConnectionHook for TestConnectionHook {
    fn create_custom_ssl_context_builder(
        &self, _settings: TlsCertificatePaths<'_>,
    ) -> QuicResult<Option<btls::ssl::SslContextBuilder>> {
        self.was_called.store(true, Ordering::SeqCst);
        Ok(None)
    }

    fn on_path_event(
        &self, _qconn: &mut tokio_quiche::quic::QuicheConnection,
        event: &tokio_quiche::quiche::PathEvent,
    ) {
        self.path_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.clone());
    }
}

pub async fn request(
    url: String, count: u64,
) -> QuicResult<HashMap<u64, String>> {
    let summary = h3i_fixtures::request(&url, count).await?;
    (0..count)
        .map(|req| {
            let stream_id = req * 4;
            let body = stream_body(&summary, stream_id)?.ok_or_else(|| {
                format!("missing response body on stream {stream_id}")
            })?;
            Ok((stream_id, body))
        })
        .collect()
}

pub async fn serve_connection_details(
    h3_controller: &mut ServerH3Controller, request_counter: Arc<AtomicUsize>,
) -> QuicResult<()> {
    let event_rx = h3_controller.event_receiver_mut();
    let mut request_futs = FuturesUnordered::new();

    loop {
        select! {
            Some(event) = event_rx.recv() => {
                match event {
                    ServerH3Event::Core(event) => {
                        match event {
                            H3Event::IncomingSettings {..} | H3Event::BodyBytesReceived { .. } | H3Event::StreamClosed { .. } | H3Event::IncomingHeaders(..) => {},
                            H3Event::ConnectionError(err) => { break Err(err.into()); }
                            H3Event::ConnectionShutdown(Some(err)) => { break Err(err.into()); }
                            H3Event::ConnectionShutdown(None) => { break Ok(()); }
                            H3Event::ResetStream { .. } | H3Event::GoAway { .. } => {},
                            H3Event::NewFlow { .. } => { break Err("unexpected datagram flow in HTTP fixture".into()); }
                        }
                    }

                    ServerH3Event::Headers{ incoming_headers, ..} => {
                        let IncomingH3Headers {
                                stream_id, headers, send, recv, ..
                            } = incoming_headers;

                            request_counter.fetch_add(1, Ordering::SeqCst);
                            request_futs.push(handle_forwarded_headers_frame(stream_id, headers, send, recv));
                    }
                }
            }
            Some(result) = request_futs.next() => { result?; }
            else => { break Ok(()); }
        }
    }
}

pub async fn handle_connection(mut connection: ServerH3Connection) {
    let _ = serve_connection_details(
        &mut connection.h3_controller,
        Default::default(),
    )
    .await;
}

pub async fn handle_forwarded_headers_frame(
    stream_id: u64, list: Vec<Header>, mut send: OutboundFrameSender,
    mut recv: InboundFrameStream,
) -> QuicResult<()> {
    let path = list
        .iter()
        .find(|header| header.name() == b":path")
        .ok_or("missing request path")?;
    let path = std::str::from_utf8(path.value())?;
    send.send(OutboundFrame::Headers(
        vec![h3::Header::new(b":status", b"200")],
        None,
    ))
    .await?;

    while let Some(InboundFrame { fin, .. }) = recv.recv().await {
        if fin {
            let res = format!("{stream_id},GET {path}|");
            send.send(OutboundFrame::Body(Bytes::from(res), true))
                .await?;
            return Ok(());
        }
    }
    // A reset can end the request without a FIN.
    Ok(())
}

pub fn start_server() -> QuicResult<(
    String,
    Arc<TestConnectionHook>,
    mpsc::UnboundedReceiver<Arc<QuicAuditStats>>,
)> {
    let quic_settings = QuicSettings {
        max_send_udp_payload_size: 1400,
        max_recv_udp_payload_size: 1400,
        ..QuicSettings::default()
    };

    let hook = TestConnectionHook::new();

    let (url, audit_stats_rx) = start_server_with_settings(
        quic_settings,
        Http3Settings::default(),
        hook.clone(),
        handle_connection,
    )?;
    Ok((url, hook, audit_stats_rx))
}

pub fn start_server_with_settings<F, Fut>(
    quic_settings: QuicSettings, http3_settings: Http3Settings,
    hook: Arc<impl ConnectionHook + Send + Sync + 'static>, hdl: F,
) -> QuicResult<(String, mpsc::UnboundedReceiver<Arc<QuicAuditStats>>)>
where
    F: Fn(ServerH3Connection) -> Fut + Send + Clone + 'static,
    Fut: Future<Output = ()> + Send,
{
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let url = format!("http://127.0.0.1:{}", socket.local_addr()?.port());

    let credentials = TestCredentials::new()?;
    let tls_cert_settings = test_certificate_paths(&credentials);

    let hooks = Hooks {
        connection_hook: Some(hook),
    };

    let params =
        ConnectionParams::new_server(quic_settings, tls_cert_settings, hooks);
    let mut stream = listen(vec![socket], &params, &DefaultMetrics)?
        .into_iter()
        .next()
        .ok_or("listener returned no stream")?;

    let (audit_stats_tx, audit_stats_rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        while let Some(accepted) = stream.next().await {
            let conn = match accepted {
                Ok(conn) => conn,
                Err(error) => {
                    log::error!("fixture listener failed: {error}");
                    break;
                },
            };
            let (h3_driver, h3_controller) = ServerH3Driver::new(&http3_settings);
            let conn = conn.start(h3_driver);
            let h3_over_quic = ServerH3Connection::new(conn, h3_controller);

            let audit_stats = Arc::clone(h3_over_quic.audit_log_stats());
            let hdl = hdl.clone();
            let tx = audit_stats_tx.clone();
            tokio::spawn(async move {
                hdl(h3_over_quic).await;
                let _ = tx.send(audit_stats);
            });
        }
    });

    Ok((url, audit_stats_rx))
}

pub fn extract_host_ipv4(url: &str) -> QuicResult<SocketAddr> {
    let url = url::Url::parse(url)?;
    match (url.host(), url.port()) {
        (Some(url::Host::Ipv4(addr)), Some(port)) =>
            Ok(SocketAddr::new(addr.into(), port)),
        _ => Err("invalid fixture server address".into()),
    }
}

pub fn map_responses(
    responses: Vec<HashMap<u64, String>>,
) -> QuicResult<HashMap<usize, HashSet<usize>>> {
    let mut map = HashMap::<_, HashSet<_>>::default();
    let res_info_re = Regex::new(r"^(?P<stream_id>\d+),GET /(?P<conn_num>\d+)$")?;

    for resp in responses {
        for (_, content) in resp {
            for res in content.split('|') {
                if res.is_empty() {
                    continue;
                }

                let caps = res_info_re
                    .captures(res)
                    .ok_or_else(|| format!("invalid response: {res}"))?;
                let conn_num = caps
                    .name("conn_num")
                    .ok_or("missing connection number")?
                    .as_str()
                    .parse()?;
                let stream_id = caps
                    .name("stream_id")
                    .ok_or("missing stream ID")?
                    .as_str()
                    .parse()?;

                map.entry(conn_num).or_default().insert(stream_id);
            }
        }
    }

    Ok(map)
}
