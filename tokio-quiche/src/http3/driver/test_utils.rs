use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use bytes::BufMut;
use bytes::BytesMut;
use foundations::telemetry::metrics::Counter;
use foundations::telemetry::metrics::Gauge;
use foundations::telemetry::metrics::Histogram;
use foundations::telemetry::metrics::TimeHistogram;
use futures::FutureExt as _;
use quiche::h3;
use quiche::h3::Header;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;

use crate::buf_factory::BufFactory;
use crate::http3::driver::client::ClientHooks;
use crate::http3::driver::hooks::DriverHooks;
use crate::http3::driver::server::ServerHooks;
use crate::http3::driver::ClientH3Event;
use crate::http3::driver::H3Controller;
use crate::http3::driver::H3Driver;
use crate::http3::driver::H3Event;
use crate::http3::driver::InboundFrame;
use crate::http3::driver::InboundFrameStream;
use crate::http3::driver::NewClientRequest;
use crate::http3::driver::OutboundFrameSender;
use crate::http3::driver::ServerH3Event;
use crate::http3::settings::Http3Settings;
use crate::metrics::labels;
use crate::metrics::Metrics;
use crate::quic::HandshakeInfo;
use crate::quic::QuicheConnection;
use crate::ApplicationOverQuic as _;

type Pipe = quiche::test_utils::Pipe<BufFactory>;

pub(super) fn default_quiche_config() -> quiche::Result<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"h3"])?;
    config.set_initial_max_data(1500);
    config.set_initial_max_stream_data_bidi_local(150);
    config.set_initial_max_stream_data_bidi_remote(150);
    config.set_initial_max_stream_data_uni(150);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(5);
    config.verify_peer(false);
    Ok(config)
}

pub(super) fn make_request_headers(method: &str) -> Vec<Header> {
    vec![
        Header::new(b":method", method.as_bytes()),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", b"quic.tech"),
        Header::new(b":path", b"/test"),
    ]
}

pub(super) fn make_response_headers() -> Vec<Header> {
    vec![
        Header::new(b":status", b"200"),
        Header::new(b"server", b"quiche-test"),
    ]
}

pub(super) fn make_response_trailers() -> Vec<Header> {
    vec![Header::new(b"trailers", b"1")]
}

/// Selects the transport endpoint used by the driver and by its peer.
pub(super) trait GetConnectionForHook {
    fn qconn(pipe: &mut Pipe) -> &mut QuicheConnection;
    fn peer_qconn(pipe: &mut Pipe) -> &mut QuicheConnection;
}

impl GetConnectionForHook for ClientHooks {
    fn qconn(pipe: &mut Pipe) -> &mut QuicheConnection {
        &mut pipe.client
    }

    fn peer_qconn(pipe: &mut Pipe) -> &mut QuicheConnection {
        &mut pipe.server
    }
}

impl GetConnectionForHook for ServerHooks {
    fn qconn(pipe: &mut Pipe) -> &mut QuicheConnection {
        &mut pipe.server
    }

    fn peer_qconn(pipe: &mut Pipe) -> &mut QuicheConnection {
        &mut pipe.client
    }
}

/// In-memory client/server fixture pairing an HTTP/3 driver with a raw peer.
///
/// One endpoint exercises `H3Driver`; the other uses `quiche::h3::Connection`.
pub(super) struct DriverTestHelper<H: DriverHooks + GetConnectionForHook> {
    pub(super) pipe: Pipe,
    pub(super) driver: H3Driver<H>,
    pub(super) controller: H3Controller<H>,
    /// Peer driven directly through `h3::Connection`.
    pub(super) peer: h3::Connection,
}

impl<H: DriverHooks + GetConnectionForHook> DriverTestHelper<H> {
    pub(super) fn new() -> anyhow::Result<Self> {
        Self::with_pipe_and_http3_settings(
            Pipe::with_config_and_buf(&mut default_quiche_config()?)?,
            &Http3Settings::default(),
        )
    }

    /// Creates an initialized driver with the initial settings exchange
    /// drained.
    pub(super) fn ready() -> anyhow::Result<Self> {
        let mut helper = Self::new()?;
        helper.complete_handshake()?;
        helper.advance_and_run_loop()?;
        Ok(helper)
    }

    pub(super) fn with_pipe(pipe: Pipe) -> anyhow::Result<Self> {
        Self::with_pipe_and_http3_settings(pipe, &Http3Settings::default())
    }

    pub(super) fn with_pipe_and_http3_settings(
        mut pipe: Pipe, h3_settings: &Http3Settings,
    ) -> anyhow::Result<Self> {
        pipe.handshake().context("Failed to handshake pipe")?;
        let (driver, controller) = H3Driver::<H>::new(h3_settings);
        let peer = h3::Connection::with_transport(
            H::peer_qconn(&mut pipe),
            &h3::Config::new(),
        )
        .context("create H3 peer connection")?;
        Ok(Self {
            pipe,
            driver,
            controller,
            peer,
        })
    }

    /// Advance the pipe and run driver iterations.
    /// TODO: We just run a couple of times to "make sure" all pending work has
    /// been processed. Ideally, we'd have some feedback from `work_loop_iter()`
    /// to decide if need to run `advance()` / `work_loop_iter()` instead of
    /// blindly calling it a couple of time...
    pub(super) fn advance_and_run_loop(&mut self) -> anyhow::Result<()> {
        self.pipe.advance()?;
        self.work_loop_iter()?;
        self.pipe.advance()?;
        self.work_loop_iter()?;
        self.pipe.advance()?;
        self.work_loop_iter()?;
        self.pipe.advance()?;
        Ok(())
    }

    /// call `on_application_ready()` on the driver and advance to pipe to
    /// complete the HTTP/3 handshake.
    pub(super) fn complete_handshake(&mut self) -> anyhow::Result<()> {
        self.driver
            .on_application_ready(
                H::qconn(&mut self.pipe),
                &HandshakeInfo::new(Instant::now(), None),
            )
            .map_err(anyhow::Error::from_boxed)
            .context("on_application_ready")?;
        // advance pipe to complete H3 handshake
        self.pipe.advance().context("advance pipe")?;
        self.driver.settings_received_and_forwarded = true;
        Ok(())
    }

    /// call `forward_settings()` on the driver. This will enqueue an
    /// `IncomingSettings` event for the controller.
    pub(super) fn forward_settings(&mut self) -> anyhow::Result<()> {
        self.driver.forward_settings().map_err(Into::into)
    }

    /// Run one iteration of the work loop *without* advancing the pipe
    pub(super) fn work_loop_iter(&mut self) -> anyhow::Result<()> {
        let qconn = H::qconn(&mut self.pipe);
        self.driver
            .process_reads(qconn)
            .map_err(anyhow::Error::from_boxed)
            .context("process_reads")?;
        self.driver
            .process_writes(qconn)
            .map_err(anyhow::Error::from_boxed)
            .context("process_writes")?;
        tokio::task::unconstrained(self.driver.wait_for_data(qconn))
            .now_or_never()
            .unwrap_or(Ok(()))
            .map_err(anyhow::Error::from_boxed)
            .context("wait_for_data")?;
        self.forward_settings()?;

        Ok(())
    }

    /// process any commands the driver might have received, returns
    /// the number of commands processed.
    /// Note that commands will also be processed by
    /// [`Self::work_loop_iter()`], but this function allows one to
    /// only process the events.
    pub(super) fn process_commands(&mut self) -> anyhow::Result<u64> {
        let mut iter = 0;
        while let Ok(cmd) = self.driver.cmd_recv.try_recv() {
            H::conn_command(&mut self.driver, H::qconn(&mut self.pipe), cmd)
                .with_context(|| format!("H::conn_command iter={iter}"))?;
            iter += 1;
        }
        Ok(iter)
    }

    /// Call [`h3::Connection::poll()`] on the peer
    fn poll_peer(&mut self) -> h3::Result<(u64, h3::Event)> {
        self.peer.poll(H::peer_qconn(&mut self.pipe))
    }

    /// Send a body from the peer
    fn peer_send_body(
        &mut self, stream_id: u64, body: &[u8], fin: bool,
    ) -> h3::Result<usize> {
        self.peer
            .send_body(H::peer_qconn(&mut self.pipe), stream_id, body, fin)
    }

    /// Call `h3::Connection::recv_body()` on the peer and read at most
    /// `max_read` bytes into a vector.
    fn peer_recv_body_vec(
        &mut self, stream_id: u64, max_read: usize,
    ) -> h3::Result<Vec<u8>> {
        let mut buf = vec![0; max_read];

        let written = self.peer.recv_body(
            H::peer_qconn(&mut self.pipe),
            stream_id,
            &mut buf,
        )?;
        buf.truncate(written);
        Ok(buf)
    }

    /// Drains the receiver and advances the driver between frames until empty
    /// or disconnected, collecting body bytes and the FIN marker.
    pub(super) fn driver_try_recv_body(
        &mut self, recv: &mut InboundFrameStream,
    ) -> anyhow::Result<(Vec<u8>, bool, TryRecvError)> {
        let mut buf = Vec::new();
        let mut had_fin = false;
        loop {
            match recv.try_recv() {
                Ok(InboundFrame { body: pooled, fin }) => {
                    anyhow::ensure!(!had_fin, "Received data after FIN");
                    buf.extend_from_slice(&pooled);
                    had_fin = fin;
                },
                Err(err) => return Ok((buf, had_fin, err)),
            }
            self.work_loop_iter()?;
        }
    }

    pub(super) fn driver_set_body_buf_size(&mut self, limit: usize) {
        self.driver.body_recv_buf =
            Some(BytesMut::with_capacity(limit).limit(limit));
    }
}

impl DriverTestHelper<ClientHooks> {
    /// Sends a new client request, by enqueuing a `NewClientRequest`
    /// command, processing it, and receiving the `NewOutboundRequest` from
    /// the controllers. It returns `stream_id`.
    ///
    /// This function assumes that there are no commands or events queued
    /// when called.
    pub(super) fn driver_send_request(
        &mut self, headers: Vec<Header>, fin: bool,
    ) -> anyhow::Result<u64> {
        let body_writer_oneshot_tx = if fin {
            None
        } else {
            let (tx, _) = oneshot::channel();
            Some(tx)
        };
        self.driver_enqueue_request(1, headers, body_writer_oneshot_tx)?;
        anyhow::ensure!(
            self.process_commands()? == 1,
            "More than one command processed"
        );
        match self.driver_recv_client_event() {
            Ok(ClientH3Event::NewOutboundRequest {
                stream_id,
                request_id: 1,
            }) => Ok(stream_id),
            other => Err(anyhow::anyhow!("Unexpected result: {other:?}")),
        }
    }

    /// enqueue a `NewClientRequest` command
    pub(super) fn driver_enqueue_request(
        &self, request_id: u64, headers: Vec<Header>,
        body_writer: Option<oneshot::Sender<OutboundFrameSender>>,
    ) -> anyhow::Result<()> {
        self.controller
            .request_sender()
            .send(NewClientRequest {
                request_id,
                headers,
                body_writer,
            })
            .map_err(|err| {
                anyhow::anyhow!("enqueue request {request_id}: {err:?}")
            })
    }

    /// Try to receive an event from the controller, returns an error if
    /// the receive fails
    pub(super) fn driver_recv_core_event(&mut self) -> anyhow::Result<H3Event> {
        match self.controller.event_receiver_mut().try_recv()? {
            ClientH3Event::Core(h3_event) => Ok(h3_event),
            ev @ (ClientH3Event::NewOutboundRequest { .. } |
            ClientH3Event::RequestRejected { .. }) =>
                Err(anyhow::anyhow!("Not a core event: {ev:?}")),
        }
    }

    /// Try to receive a `ClientH3Event` from the controller's event receiver
    pub(super) fn driver_recv_client_event(
        &mut self,
    ) -> anyhow::Result<ClientH3Event> {
        Ok(self.controller.event_receiver_mut().try_recv()?)
    }

    /// Sends a response from server with default headers.
    ///
    /// On success it returns the headers.
    pub(super) fn peer_server_send_response(
        &mut self, stream: u64, fin: bool,
    ) -> h3::Result<Vec<Header>> {
        let resp = vec![
            Header::new(b":status", b"200"),
            Header::new(b"server", b"quiche-test"),
        ];

        self.peer
            .send_response(&mut self.pipe.server, stream, &resp, fin)?;

        Ok(resp)
    }

    pub(super) fn peer_server_poll(&mut self) -> h3::Result<(u64, h3::Event)> {
        self.poll_peer()
    }

    /// Send a body from the server
    pub(super) fn peer_server_send_body(
        &mut self, stream_id: u64, body: &[u8], fin: bool,
    ) -> h3::Result<usize> {
        self.peer_send_body(stream_id, body, fin)
    }

    /// Receive at most `max_read` body bytes and return the read
    /// bytes as a `Vec`
    pub(super) fn peer_server_recv_body_vec(
        &mut self, stream_id: u64, max_read: usize,
    ) -> h3::Result<Vec<u8>> {
        self.peer_recv_body_vec(stream_id, max_read)
    }
}

impl DriverTestHelper<ServerHooks> {
    /// Sends a new client request
    pub(super) fn peer_client_send_request(
        &mut self, headers: &[Header], fin: bool,
    ) -> anyhow::Result<u64> {
        Ok(self
            .peer
            .send_request(&mut self.pipe.client, headers, fin)?)
    }

    /// Try to receive an event from the controller, returns an error if
    /// the receive fails
    pub(super) fn driver_recv_core_event(&mut self) -> anyhow::Result<H3Event> {
        match self.controller.event_receiver_mut().try_recv()? {
            ServerH3Event::Core(h3_event) => Ok(h3_event),
            ev @ ServerH3Event::Headers { .. } =>
                Err(anyhow::anyhow!("Not a core event: {ev:?}")),
        }
    }

    /// Try to receive a `ServerH3Event` from the controller's event receiver
    pub(super) fn driver_recv_server_event(
        &mut self,
    ) -> anyhow::Result<ServerH3Event> {
        Ok(self.controller.event_receiver_mut().try_recv()?)
    }

    pub(super) fn peer_client_poll(&mut self) -> h3::Result<(u64, h3::Event)> {
        self.poll_peer()
    }

    /// Send a body from the server
    pub(super) fn peer_client_send_body(
        &mut self, stream_id: u64, body: &[u8], fin: bool,
    ) -> h3::Result<usize> {
        self.peer_send_body(stream_id, body, fin)
    }

    /// Receive at most `max_read` body bytes and return the read
    /// bytes as a `Vec`
    pub(super) fn peer_client_recv_body_vec(
        &mut self, stream_id: u64, max_read: usize,
    ) -> h3::Result<Vec<u8>> {
        self.peer_recv_body_vec(stream_id, max_read)
    }
}

/// Minimal [`Metrics`] impl for unit tests. Tracks connection close error
/// counters; all other metrics are discarded.
#[derive(Clone, Default)]
pub(super) struct TestMetrics {
    pub(super) local_h3: Counter,
    pub(super) local_quic: Counter,
    pub(super) peer_h3: Counter,
    pub(super) peer_quic: Counter,
}

impl Metrics for TestMetrics {
    fn local_h3_conn_close_error_count(
        &self, _reason: labels::H3Error,
    ) -> Counter {
        self.local_h3.clone()
    }

    fn local_quic_conn_close_error_count(
        &self, _reason: labels::QuicError,
    ) -> Counter {
        self.local_quic.clone()
    }

    fn peer_h3_conn_close_error_count(
        &self, _reason: labels::H3Error,
    ) -> Counter {
        self.peer_h3.clone()
    }

    fn peer_quic_conn_close_error_count(
        &self, _reason: labels::QuicError,
    ) -> Counter {
        self.peer_quic.clone()
    }

    // -- everything below is unused by the code under test --

    fn connections_in_memory(&self) -> Gauge {
        Gauge::default()
    }

    fn request_streams_opened(&self) -> Histogram {
        Histogram::new(std::iter::empty())
    }

    fn handshake_time_seconds(
        &self, _: labels::QuicHandshakeStage,
    ) -> TimeHistogram {
        TimeHistogram::new(std::iter::empty())
    }

    fn write_errors(&self, _: labels::QuicWriteError) -> Counter {
        Counter::default()
    }

    fn send_to_wouldblock_duration_s(&self) -> TimeHistogram {
        TimeHistogram::new(std::iter::empty())
    }

    fn skipped_mid_handshake_flush_count(&self) -> Counter {
        Counter::default()
    }

    fn invalid_cid_packet_count(&self, _: crate::BoxError) -> Counter {
        Counter::default()
    }

    fn accepted_initial_packet_count(&self) -> Counter {
        Counter::default()
    }

    fn expensive_accepted_initial_packet_count(&self, _: IpAddr) -> Counter {
        Counter::default()
    }

    fn rejected_initial_packet_count(
        &self, _: labels::QuicInvalidInitialPacketError,
    ) -> Counter {
        Counter::default()
    }

    fn expensive_rejected_initial_packet_count(
        &self, _: labels::QuicInvalidInitialPacketError, _: IpAddr,
    ) -> Counter {
        Counter::default()
    }

    fn utilized_bandwidth(&self) -> Gauge {
        Gauge::default()
    }

    fn max_bandwidth_mbps(&self) -> Histogram {
        Histogram::new(std::iter::empty())
    }

    fn max_loss_pct(&self) -> Histogram {
        Histogram::new(std::iter::empty())
    }

    fn udp_drop_count(&self) -> Counter {
        Counter::default()
    }

    fn failed_handshakes(&self, _: labels::HandshakeError) -> Counter {
        Counter::default()
    }

    fn tokio_runtime_task_schedule_delay_histogram(
        &self, _: &Arc<str>,
    ) -> TimeHistogram {
        TimeHistogram::new(std::iter::empty())
    }

    fn tokio_runtime_task_poll_duration_histogram(
        &self, _: &Arc<str>,
    ) -> TimeHistogram {
        TimeHistogram::new(std::iter::empty())
    }

    fn tokio_runtime_task_total_poll_time_micros(&self, _: &Arc<str>) -> Counter {
        Counter::default()
    }
}
