type TestResult = crate::QuicResult<()>;
const REQUEST_CANCELED_ERR: u64 = h3::WireErrorCode::RequestCancelled as u64;

use assert_matches::assert_matches;
use rstest::rstest;

use crate::buf_factory::BufFactory;
use crate::http3::driver::client::ClientHooks;
use crate::http3::driver::server::ServerHooks;

use super::test_utils::*;
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StreamTermination {
    stop_sending: Option<u64>,
    reset: Option<u64>,
    fin: StreamClosureKind,
}

#[track_caller]
fn assert_stream_termination(
    audit: &H3AuditStats, received: StreamTermination, sent: StreamTermination,
) {
    assert_eq!(
        StreamTermination {
            stop_sending: audit.recvd_stop_sending_error_code(),
            reset: audit.recvd_reset_stream_error_code(),
            fin: audit.recvd_stream_fin(),
        },
        received,
        "received stream termination"
    );
    assert_eq!(
        StreamTermination {
            stop_sending: audit.sent_stop_sending_error_code(),
            reset: audit.sent_reset_stream_error_code(),
            fin: audit.sent_stream_fin(),
        },
        sent,
        "sent stream termination"
    );
}

#[test]
fn wrapped_http3_and_quic_errors_expose_their_sources() -> TestResult {
    use std::error::Error as _;

    let transport = quiche::Error::StreamLimit;
    let wrapped = H3ConnectionError::from(transport);
    let h3_source = wrapped.source().ok_or("HTTP/3 error source")?;
    let h3_error = h3_source
        .downcast_ref::<h3::Error>()
        .ok_or("wrapped HTTP/3 error")?;
    assert_eq!(h3_error, &h3::Error::Transport(transport));
    assert_eq!(
        h3_error
            .source()
            .ok_or("QUIC error source")?
            .downcast_ref::<quiche::Error>(),
        Some(&transport)
    );
    for standalone in [
        H3ConnectionError::ControllerWentAway,
        H3ConnectionError::NonexistentStream,
        H3ConnectionError::PostAcceptTimeout,
        H3ConnectionError::InvalidDatagram,
        H3ConnectionError::NotEstablished,
        H3ConnectionError::InvalidDriverRole {
            expected_server: true,
        },
    ] {
        assert!(standalone.source().is_none());
    }
    Ok(())
}

#[test]
fn controller_can_transfer_receiver_without_losing_command_senders(
) -> anyhow::Result<()> {
    let (mut driver, controller) =
        H3Driver::<ClientHooks>::new(&Http3Settings::default());
    let commands = controller.h3_cmd_sender();
    let _events = controller.into_event_receiver();
    commands.send(H3Command::GoAway).map_err(|_| {
        anyhow::anyhow!("controller transfer closed command channel")
    })?;
    assert!(matches!(
        driver.cmd_recv.try_recv(),
        Ok(ClientH3Command::Core(H3Command::GoAway))
    ));
    assert_eq!(
        driver.conn_mut().err(),
        Some(H3ConnectionError::NotEstablished)
    );
    Ok(())
}

/// The peer's first HEADERS are already queued when the deadline expires.
/// Processing the network input directly must not bypass timeout enforcement.
#[tokio::test(start_paused = true)]
async fn late_first_headers_are_rejected_without_polling_idle_timer(
) -> anyhow::Result<()> {
    use crate::http3::settings::Http3Settings;
    use std::time::Duration;

    let settings = Http3Settings {
        post_accept_timeout: Some(Duration::from_secs(5)),
        ..Http3Settings::default()
    };
    let pipe = quiche::test_utils::Pipe::with_config_and_buf(
        &mut default_quiche_config()?,
    )?;
    let mut helper =
        DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
            pipe, &settings,
        )?;
    helper.complete_handshake()?;
    helper.advance_and_run_loop()?;
    helper.peer_client_send_request(&make_request_headers("GET"), true)?;
    helper.pipe.advance()?;
    tokio::time::advance(Duration::from_secs(6)).await;
    let error = helper
        .driver
        .process_reads(&mut helper.pipe.server)
        .err()
        .ok_or_else(|| anyhow::anyhow!("late first request was accepted"))?;
    assert_eq!(
        error.downcast_ref::<H3ConnectionError>(),
        Some(&H3ConnectionError::PostAcceptTimeout)
    );
    assert!(helper.driver.stream_map.is_empty());
    assert_eq!(
        helper
            .pipe
            .server
            .local_error()
            .map(|err| (err.is_app, err.error_code)),
        Some((true, h3::WireErrorCode::NoError as u64))
    );
    Ok(())
}

/// Regression: a parser can append data before reporting a reset or error.
#[test]
fn failed_body_read_does_not_leak_bytes_into_another_stream() -> anyhow::Result<()>
{
    use bytes::BufMut as _;
    let mut scratch = None;
    let failure = read_body_chunk(&mut scratch, 16, |buffer| {
        buffer.put_slice(b"first stream");
        Err(h3::Error::Transport(quiche::Error::StreamReset(42)))
    });
    assert_eq!(
        failure,
        Err(h3::Error::Transport(quiche::Error::StreamReset(42)))
    );
    assert!(scratch.is_none());
    let body = read_body_chunk(&mut scratch, 16, |buffer| {
        buffer.put_slice(b"second");
        Ok(6)
    })?;
    assert_eq!(&body[..], b"second");
    Ok(())
}

/// Tests for the body receive buffer sizing helper.
mod body_recv_buf_size {
    use super::*;

    const MAX: usize = BufFactory::MAX_BUF_SIZE;

    #[test]
    fn zero_readable_uses_floor() {
        // Never build a zero-capacity buffer.
        assert_eq!(body_recv_buf_size(0, MAX), MIN_BODY_RECV_BUF_SIZE);
    }

    #[test]
    fn small_readable_uses_floor() {
        // A read below the floor is raised to the floor so a trickle of tiny
        // reads reuses one allocation instead of reallocating each time.
        assert_eq!(body_recv_buf_size(10, MAX), MIN_BODY_RECV_BUF_SIZE);
        assert_eq!(
            body_recv_buf_size(MIN_BODY_RECV_BUF_SIZE, MAX),
            MIN_BODY_RECV_BUF_SIZE
        );
    }

    #[test]
    fn readable_above_floor_tracks_size() {
        // Between the floor and the cap the buffer tracks the readable length.
        let readable = MIN_BODY_RECV_BUF_SIZE + 500;
        assert_eq!(body_recv_buf_size(readable, MAX), readable);
    }

    #[test]
    fn large_readable_caps_at_max() {
        assert_eq!(body_recv_buf_size(MAX, MAX), MAX);
        // Readable beyond the configured max is capped.
        assert_eq!(body_recv_buf_size(MAX + 1, MAX), MAX);
        assert_eq!(body_recv_buf_size(10 * MAX, MAX), MAX);
    }

    #[test]
    fn respects_configured_max() {
        // A configured cap above the floor bounds the buffer below
        // MAX_BUF_SIZE.
        let cap = MIN_BODY_RECV_BUF_SIZE * 4;
        assert_eq!(body_recv_buf_size(MAX, cap), cap);
        assert_eq!(body_recv_buf_size(cap / 2, cap), cap / 2);
        // A larger configured cap allows the buffer to grow past
        // MAX_BUF_SIZE.
        assert_eq!(body_recv_buf_size(2 * MAX, 4 * MAX), 2 * MAX);
    }

    #[test]
    fn cap_below_floor_wins() {
        // The cap is the hard upper bound: when it is smaller than the floor,
        // the floor yields to it and `clamp` never sees an inverted range.
        let cap = MIN_BODY_RECV_BUF_SIZE / 2;
        assert_eq!(body_recv_buf_size(0, cap), cap);
        assert_eq!(body_recv_buf_size(10, cap), cap);
        assert_eq!(body_recv_buf_size(MAX, cap), cap);
    }

    #[test]
    fn default_cap_is_16kib() {
        assert_eq!(DEFAULT_MAX_BODY_RECV_BUF_SIZE, 16 * 1024);
        // A body larger than the default is capped at 16 KiB.
        assert_eq!(
            body_recv_buf_size(MAX, DEFAULT_MAX_BODY_RECV_BUF_SIZE),
            DEFAULT_MAX_BODY_RECV_BUF_SIZE
        );
    }
}

/// `Some(0)` is normalized to the default (it would make `recv_body_buf` a
/// no-op); non-zero overrides are kept as-is.
#[test]
fn zero_configured_max_recv_body_buf_size_falls_back_to_default() {
    let settings_max = |max: Option<usize>| {
        let (driver, _controller) =
            H3Driver::<ClientHooks>::new(&Http3Settings {
                max_recv_body_buf_size: max,
                ..Default::default()
            });
        driver.max_recv_body_buf_size
    };

    // `Some(0)` and unset both fall back to the default.
    assert_eq!(settings_max(Some(0)), DEFAULT_MAX_BODY_RECV_BUF_SIZE);
    assert_eq!(settings_max(None), DEFAULT_MAX_BODY_RECV_BUF_SIZE);
    // A non-zero override is kept as-is, even below the sizing floor.
    assert_eq!(
        settings_max(Some(MIN_BODY_RECV_BUF_SIZE / 2)),
        MIN_BODY_RECV_BUF_SIZE / 2
    );
    assert_eq!(
        settings_max(Some(BufFactory::MAX_BUF_SIZE)),
        BufFactory::MAX_BUF_SIZE
    );
}

/// Tests for connection close error metrics recorded by
/// [`H3Driver::on_conn_close`].
mod conn_close_metrics {
    use crate::ApplicationOverQuic as _;

    use super::*;

    /// Peer sends a QUIC-level `CONNECTION_CLOSE` and the work loop
    /// completes with Ok. Verifies the peer QUIC error counter is
    /// incremented.
    #[test]
    fn peer_quic_error_on_ok_result() -> TestResult {
        let mut helper = DriverTestHelper::<ServerHooks>::new()?;
        helper.complete_handshake()?;

        // Peer (client) closes with a QUIC-level error
        helper.pipe.client.close(false, 0x1, b"internal error")?;
        helper.pipe.advance()?;

        let metrics = TestMetrics::default();
        helper
            .driver
            .on_conn_close(&mut helper.pipe.server, &metrics, &Ok(()));

        assert_eq!(metrics.peer_quic.get(), 1);
        assert_eq!(metrics.peer_h3.get(), 0);
        assert_eq!(metrics.local_quic.get(), 0);
        assert_eq!(metrics.local_h3.get(), 0);
        Ok(())
    }

    /// Peer sends an `APPLICATION_CLOSE` (H3-level) and the work loop
    /// completes with Ok. Verifies the peer H3 error counter is
    /// incremented.
    #[test]
    fn peer_h3_error_on_ok_result() -> TestResult {
        let mut helper = DriverTestHelper::<ServerHooks>::new()?;
        helper.complete_handshake()?;

        // Peer (client) closes with an H3-level error (is_app = true)
        helper.pipe.client.close(true, 0x100, b"no error")?;
        helper.pipe.advance()?;

        let metrics = TestMetrics::default();
        helper
            .driver
            .on_conn_close(&mut helper.pipe.server, &metrics, &Ok(()));

        assert_eq!(metrics.peer_h3.get(), 1);
        assert_eq!(metrics.peer_quic.get(), 0);
        assert_eq!(metrics.local_quic.get(), 0);
        assert_eq!(metrics.local_h3.get(), 0);
        Ok(())
    }

    /// Work loop returns an error and the local side has a QUIC-level
    /// error set. Verifies the local QUIC error counter is incremented.
    #[test]
    fn local_quic_error_on_err_result() -> TestResult {
        let mut helper = DriverTestHelper::<ServerHooks>::new()?;
        helper.complete_handshake()?;

        // Local side (server) closes with a QUIC-level error
        helper.pipe.server.close(false, 0x1, b"internal error")?;

        let err: crate::QuicResult<()> =
            Err(H3ConnectionError::PostAcceptTimeout.into());
        let metrics = TestMetrics::default();
        helper
            .driver
            .on_conn_close(&mut helper.pipe.server, &metrics, &err);

        assert_eq!(metrics.local_quic.get(), 1);
        assert_eq!(metrics.local_h3.get(), 0);
        assert_eq!(metrics.peer_quic.get(), 0);
        assert_eq!(metrics.peer_h3.get(), 0);
        Ok(())
    }
}

/// Tests that use an `H3Driver` for the client side. We mostly focus on testing
/// the driver's handling of stream state, and data, rather than H3 semantics.
/// Note that most of these tests could have just as easily been written for
/// the server side.
mod client_side_driver {
    use super::*;

    fn receive_response_chunk(
        helper: &mut DriverTestHelper<ClientHooks>,
        receiver: &mut InboundFrameStream, stream_id: u64, body: &[u8],
        fin: bool,
    ) -> TestResult {
        assert_eq!(
            helper.peer_server_send_body(stream_id, body, fin)?,
            body.len()
        );
        helper.advance_and_run_loop()?;
        let (received, received_fin, _) =
            helper.driver_try_recv_body(receiver)?;
        assert_eq!(received, body);
        assert_eq!(received_fin, fin);
        Ok(())
    }

    fn receive_request_reset(
        helper: &mut DriverTestHelper<ClientHooks>, stream_id: u64, code: u64,
    ) -> TestResult {
        helper.advance_and_run_loop()?;
        assert_eq!(
            helper.peer_server_poll(),
            Ok((stream_id, h3::Event::Reset(code)))
        );
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));
        helper.advance_and_run_loop()?;
        Ok(())
    }

    fn single_stream_client() -> anyhow::Result<DriverTestHelper<ClientHooks>> {
        let mut config = default_quiche_config()?;
        config.set_initial_max_streams_bidi(1);
        let pipe = quiche::test_utils::Pipe::with_config_and_buf(&mut config)?;
        let mut helper = DriverTestHelper::<ClientHooks>::with_pipe(pipe)?;
        helper.complete_handshake()?;
        helper.advance_and_run_loop()?;
        Ok(helper)
    }

    #[test]
    fn queued_requests_retry_in_order_after_stream_credit_returns(
    ) -> anyhow::Result<()> {
        let mut helper = single_stream_client()?;
        for request_id in 1..=3 {
            helper.driver_enqueue_request(
                request_id,
                make_request_headers("GET"),
                None,
            )?;
        }
        assert_eq!(helper.process_commands()?, 3);
        assert_matches!(
            helper.driver_recv_client_event()?,
            ClientH3Event::NewOutboundRequest {
                stream_id: 0,
                request_id: 1
            }
        );
        assert_eq!(helper.driver.hooks.queued_request_count(), 2);
        assert_eq!(helper.pipe.client.peer_streams_left_bidi(), 0);

        for (stream_id, next_id) in [(0, 2), (4, 3)] {
            helper.advance_and_run_loop()?;
            // The preceding bodyless request may still have its Finished
            // event queued. Drain only those already-completed streams.
            loop {
                match helper.peer_server_poll()? {
                    (id, h3::Event::Finished) if id < stream_id => (),
                    (id, h3::Event::Headers { .. }) if id == stream_id => break,
                    event => anyhow::bail!("unexpected peer event: {event:?}"),
                }
            }
            helper.peer_server_send_response(stream_id, true)?;
            helper.advance_and_run_loop()?;
            let mut allocated = Vec::new();
            while let Ok(event) = helper.driver_recv_client_event() {
                if let ClientH3Event::NewOutboundRequest {
                    stream_id,
                    request_id,
                } = event
                {
                    allocated.push((stream_id, request_id));
                }
            }
            assert_eq!(allocated, [(stream_id + 4, next_id)]);
        }
        assert_eq!(helper.driver.hooks.queued_request_count(), 0);
        Ok(())
    }

    #[test]
    fn peer_goaway_rejects_unassigned_requests_and_keeps_open_stream(
    ) -> anyhow::Result<()> {
        let mut helper = single_stream_client()?;
        helper.driver_enqueue_request(1, make_request_headers("GET"), None)?;
        helper.driver_enqueue_request(2, make_request_headers("GET"), None)?;
        assert_eq!(helper.process_commands()?, 2);
        assert_matches!(
            helper.driver_recv_client_event()?,
            ClientH3Event::NewOutboundRequest {
                stream_id: 0,
                request_id: 1
            }
        );
        assert_eq!(helper.driver.hooks.queued_request_count(), 1);
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (0, h3::Event::Headers { .. })
        );
        helper.peer.send_goaway(&mut helper.pipe.server, 4)?;
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.driver_recv_client_event()?,
            ClientH3Event::Core(H3Event::GoAway { id: 4 })
        );
        assert_matches!(
            helper.driver_recv_client_event()?,
            ClientH3Event::RequestRejected {
                request_id: 2,
                goaway_id: 4
            }
        );
        assert_eq!(helper.driver.hooks.queued_request_count(), 0);
        helper.driver_enqueue_request(3, make_request_headers("GET"), None)?;
        assert_eq!(helper.process_commands()?, 1);
        assert_matches!(
            helper.driver_recv_client_event()?,
            ClientH3Event::RequestRejected {
                request_id: 3,
                goaway_id: 4
            }
        );
        helper.peer_server_send_response(0, true)?;
        helper.advance_and_run_loop()?;
        assert_matches!(helper.driver_recv_core_event()?, H3Event::IncomingHeaders(headers) if headers.stream_id == 0);
        assert!(!helper.pipe.client.is_closed());
        Ok(())
    }

    #[derive(Clone, Copy)]
    enum PeerTermination {
        Fin,
        Reset,
    }

    #[rstest]
    #[case::fin(PeerTermination::Fin)]
    #[case::reset(PeerTermination::Reset)]
    fn termination_before_response_with_open_body_removes_pending_request(
        #[case] termination: PeerTermination,
    ) -> TestResult {
        let mut helper = DriverTestHelper::<ClientHooks>::ready()?;

        let (body_writer_tx, mut body_writer_rx) =
            tokio::sync::oneshot::channel();
        helper.driver_enqueue_request(
            1,
            make_request_headers("GET"),
            Some(body_writer_tx),
        )?;
        assert_eq!(helper.process_commands()?, 1);
        let stream_id = assert_matches!(
            helper.driver_recv_client_event()?,
            ClientH3Event::NewOutboundRequest {
                stream_id,
                request_id: 1,
            } => stream_id
        );
        let body_writer = body_writer_rx.try_recv()?;
        assert_eq!(helper.driver.hooks.pending_request_count(), 1);

        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (id, h3::Event::Headers { .. }) if id == stream_id
        );
        match termination {
            PeerTermination::Fin => {
                helper.pipe.server.stream_send(stream_id, &[], true)?;
                helper.advance_and_run_loop()?;
                assert_matches!(
                    helper.driver_recv_core_event(),
                    Ok(H3Event::BodyBytesReceived {
                        stream_id: id,
                        num_bytes: 0,
                        fin: true,
                    }) if id == stream_id
                );
            },
            PeerTermination::Reset => {
                helper.pipe.server.stream_shutdown(
                    stream_id,
                    quiche::Shutdown::Write,
                    4242,
                )?;
                helper.advance_and_run_loop()?;
                assert_matches!(
                    helper.driver_recv_core_event(),
                    Ok(H3Event::ResetStream { stream_id: id })
                        if id == stream_id
                );
            },
        }
        assert_eq!(helper.driver.hooks.pending_request_count(), 0);
        assert!(helper.driver.stream_map.contains_key(&stream_id));

        drop(body_writer);
        helper.advance_and_run_loop()?;
        assert!(!helper.driver.stream_map.contains_key(&stream_id));
        Ok(())
    }

    #[test]
    fn client_fin_before_server_body() -> TestResult {
        let mut helper = DriverTestHelper::<ClientHooks>::ready()?;

        // client sends a request
        let stream_id =
            helper.driver_send_request(make_request_headers("GET"), false)?;

        // servers reads request and sends response headers
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false)?;

        helper.advance_and_run_loop()?;

        // Client receives response headers
        let resp = assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        let to_server = resp
            .send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .clone();
        let mut from_server = resp.recv;
        // client sends body
        to_server.try_send(OutboundFrame::Body(
            Bytes::copy_from_slice(&[1; 5]),
            false,
        ))?;
        helper.advance_and_run_loop()?;

        // The server receives the client body.
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));
        assert_eq!(helper.peer_server_recv_body_vec(0, 1024), Ok(vec![1; 5]));

        // The client sends FIN. The server sends a body and FIN.
        to_server.try_send(OutboundFrame::Body(bytes::Bytes::new(), true))?;
        helper.peer_server_send_body(0, &[2; 10], true)?;

        // The server reads FIN.
        helper.advance_and_run_loop()?;
        // TODO: The server sees `h3::Event::Data`, but it contains an empty
        // buffer. Ideally, it wouldn't do that.
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Data)));
        // No data remains to be read.
        assert_eq!(
            helper.peer_server_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Finished)));
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));
        helper.advance_and_run_loop()?;

        // The client receives the server body.
        assert_matches!(from_server.try_recv(), Ok(InboundFrame { body: buf, fin }) => {
            assert_eq!(buf.to_vec(), vec![2; 10]);
            // TODO: It would be useful to receive FIN here, but `quiche::h3`
            // requires another receive call on the channel.
            assert!(!fin);
        });
        helper.work_loop_iter()?;

        // FIN must be delivered explicitly after the blocked body, before
        // the channel disconnects.
        assert_matches!(from_server.try_recv(), Ok(InboundFrame { body: buf, fin: true }) => {
            assert!(buf.is_empty());
        });
        assert_matches!(from_server.try_recv(), Err(TryRecvError::Disconnected));
        assert_eq!(helper.driver.stream_map.len(), 0);
        Ok(())
    }

    #[test]
    fn client_body_recv_buf() -> TestResult {
        let mut helper = DriverTestHelper::<ClientHooks>::ready()?;

        // The client sends a request with FIN.
        let stream_id =
            helper.driver_send_request(make_request_headers("GET"), true)?;

        // The server reads the request and sends response headers.
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false)?;
        helper.advance_and_run_loop()?;

        // The client receives response headers.
        let resp = assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        let mut from_server = resp.recv;

        // Set the buffer size.
        helper.driver_set_body_buf_size(30);
        // The server sends an initial 10-byte body.
        receive_response_chunk(
            &mut helper,
            &mut from_server,
            0,
            &[2; 10],
            false,
        )?;
        // Receive another ten bytes.
        receive_response_chunk(
            &mut helper,
            &mut from_server,
            0,
            &[3; 10],
            false,
        )?;
        // Receive another ten bytes using the initial buffer.
        receive_response_chunk(
            &mut helper,
            &mut from_server,
            0,
            &[4; 10],
            false,
        )?;
        // Receive another ten bytes using a new buffer transparently.
        receive_response_chunk(&mut helper, &mut from_server, 0, &[5; 10], true)?;
        // The client should clean up the stream after both directions close.
        assert_eq!(helper.driver.stream_map.len(), 0);
        Ok(())
    }

    /// An idle connection (and a request/response that exchanges only
    /// headers) must never allocate the body receive buffer.
    #[test]
    fn client_body_recv_buf_not_allocated_when_idle() -> TestResult {
        let mut helper = DriverTestHelper::<ClientHooks>::ready()?;

        // Idle: never received body bytes, so the buffer is not allocated.
        assert!(helper.driver.body_recv_buf.is_none());

        // Client sends a headers-only request (fin, no request body).
        let stream_id =
            helper.driver_send_request(make_request_headers("GET"), true)?;

        // Server reads the request and sends a headers-only response: `fin =
        // true` finishes the stream on its headers, so no body follows.
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, true)?;
        helper.advance_and_run_loop()?;

        // Client receives the response headers; `read_fin` confirms the
        // response carried no body.
        let resp = assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(resp.read_fin);

        // Only headers were exchanged, so the body receive buffer is still
        // not allocated.
        assert!(helper.driver.body_recv_buf.is_none());
        Ok(())
    }

    /// The body receive buffer is lazily allocated on the first body read
    /// and released once the last stream is cleaned up.
    #[test]
    fn client_body_recv_buf_allocated_on_body_and_released_on_close() -> TestResult
    {
        let mut helper = DriverTestHelper::<ClientHooks>::ready()?;

        let stream_id =
            helper.driver_send_request(make_request_headers("GET"), true)?;

        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false)?;
        helper.advance_and_run_loop()?;

        let resp = assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        let mut from_server = resp.recv;

        // No body yet: the buffer is still unallocated.
        assert!(helper.driver.body_recv_buf.is_none());

        // Server sends a body chunk (not fin).
        helper.peer_server_send_body(0, &[7; 10], false)?;
        helper.advance_and_run_loop()?;
        assert_eq!(helper.driver_try_recv_body(&mut from_server)?.0, vec![
            7;
            10
        ]);

        // The body read lazily allocated the buffer at the floor
        // (`MIN_BODY_RECV_BUF_SIZE`) rather than a fixed 64 KiB, because the
        // readable length was below the floor. The buffer therefore tracks the
        // floor -- far below the 64 KiB a fixed allocation would use.
        assert!(helper.driver.body_recv_buf.is_some());
        let cap = helper
            .driver
            .body_recv_buf
            .as_ref()
            .ok_or("missing allocated body buffer")?
            .get_ref()
            .capacity();
        assert!(
            cap <= MIN_BODY_RECV_BUF_SIZE,
            "body buffer should track the floor, not a fixed 64 KiB; cap = {cap}"
        );

        // Server finishes the stream.
        helper.peer_server_send_body(0, &[8; 10], true)?;
        helper.advance_and_run_loop()?;
        let (body, fin, _) = helper.driver_try_recv_body(&mut from_server)?;
        assert_eq!(body, vec![8; 10]);
        assert!(fin);

        // Stream cleaned up on both-directions-close, buffer released.
        assert_eq!(helper.driver.stream_map.len(), 0);
        assert!(helper.driver.body_recv_buf.is_none());
        Ok(())
    }

    /// A body larger than the receive buffer exercises the reallocation
    /// branch; the buffer stays allocated across reallocations and is
    /// released once the stream closes.
    #[test]
    fn client_body_recv_buf_reallocates_and_releases() -> TestResult {
        let mut helper = DriverTestHelper::<ClientHooks>::ready()?;

        let stream_id =
            helper.driver_send_request(make_request_headers("GET"), true)?;

        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false)?;
        helper.advance_and_run_loop()?;

        let resp = assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        let mut from_server = resp.recv;

        // Force a small receive buffer so it is smaller than the size we want
        // for each read, exercising the reallocation branch
        // (`*body_recv_buf = ...`).
        helper.driver_set_body_buf_size(20);

        // Send 40 bytes across four chunks, reallocating on the way.
        receive_response_chunk(
            &mut helper,
            &mut from_server,
            0,
            &[1; 10],
            false,
        )?;
        receive_response_chunk(
            &mut helper,
            &mut from_server,
            0,
            &[2; 10],
            false,
        )?;
        receive_response_chunk(
            &mut helper,
            &mut from_server,
            0,
            &[3; 10],
            false,
        )?;
        // Buffer remains allocated across reallocation.
        assert!(helper.driver.body_recv_buf.is_some());

        // Final chunk with fin.
        receive_response_chunk(&mut helper, &mut from_server, 0, &[4; 10], true)?;

        // Stream cleaned up, buffer released.
        assert_eq!(helper.driver.stream_map.len(), 0);
        assert!(helper.driver.body_recv_buf.is_none());
        Ok(())
    }

    /// An exhausted receive buffer is released while its stream remains
    /// active, then allocated again for subsequent body data.
    #[test]
    fn client_body_recv_buf_releases_when_exhausted() -> TestResult {
        // Permit one full floor-sized body in a single H3 DATA frame.
        let mut config = default_quiche_config()?;
        let max_data = 2 * MIN_BODY_RECV_BUF_SIZE as u64;
        config.set_initial_max_data(max_data);
        config.set_initial_max_stream_data_bidi_local(max_data);
        config.set_initial_max_stream_data_bidi_remote(max_data);
        config.set_initial_max_stream_data_uni(max_data);
        let mut helper = DriverTestHelper::<ClientHooks>::with_pipe(
            quiche::test_utils::Pipe::with_config_and_buf(&mut config)?,
        )?;
        helper.complete_handshake()?;
        helper.advance_and_run_loop()?;

        let stream_id =
            helper.driver_send_request(make_request_headers("GET"), true)?;

        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false)?;
        helper.advance_and_run_loop()?;

        let resp = assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        let mut from_server = resp.recv;

        let full_body = vec![1; MIN_BODY_RECV_BUF_SIZE];
        assert_eq!(
            helper.peer_server_send_body(0, &full_body, false),
            Ok(full_body.len())
        );
        helper.advance_and_run_loop()?;
        assert_eq!(helper.driver_try_recv_body(&mut from_server)?.0, full_body);
        assert_eq!(helper.driver.stream_map.len(), 1);
        assert!(helper.driver.body_recv_buf.is_none());

        // The next body chunk allocates a fresh buffer.
        receive_response_chunk(
            &mut helper,
            &mut from_server,
            0,
            &[2; 10],
            false,
        )?;
        assert!(helper.driver.body_recv_buf.is_some());

        receive_response_chunk(&mut helper, &mut from_server, 0, &[3; 10], true)?;
        assert_eq!(helper.driver.stream_map.len(), 0);
        assert!(helper.driver.body_recv_buf.is_none());
        Ok(())
    }

    /// Test that dropping the `OutboundFrame` channel causes the driver to
    /// send a `RESET_STREAM` frame to the peer.
    #[test]
    fn client_send_reset_stream_when_outbound_frame_channel_drops() -> TestResult
    {
        let mut helper = DriverTestHelper::<ClientHooks>::new()?;
        helper.complete_handshake()?;
        helper.advance_and_run_loop()?;

        // The client uses H3Driver
        // client sends a request
        let stream_id =
            helper.driver_send_request(make_request_headers("GET"), false)?;

        // servers reads request and sends response headers
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false)?;

        helper.advance_and_run_loop()?;

        // Client receives response headers
        let resp = assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        // the stream is waiting for the application to write data
        assert_eq!(helper.driver.waiting_streams.upstream_len(), 0);
        assert_eq!(helper.driver.waiting_streams.downstream_len(), 1);
        // take the InboundFrame receiver and stats
        let mut from_server = resp.recv;
        let audit_stats = resp.h3_audit_stats.clone();
        // ... and drop the outbound frame
        drop(resp.send);

        helper.advance_and_run_loop()?;

        // server receives the reset
        assert_eq!(
            helper.peer_server_poll(),
            Ok((0, h3::Event::Reset(REQUEST_CANCELED_ERR)))
        );
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));

        helper.peer_server_send_body(0, &[2; 10], true)?;
        helper.advance_and_run_loop()?;

        // client receives the server body
        assert_matches!(from_server.try_recv(), Ok(InboundFrame { body: buf, fin }) => {
            assert_eq!(buf.to_vec(), vec![2; 10]);
            // TODO: it would be nice if we could receive the fin here, but that's not
            // how quiche::h3 works. Instead we need another receive call on the channel
            assert!(!fin);
        });
        helper.work_loop_iter()?;
        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_stream_termination(
            &audit_stats,
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
            StreamTermination {
                stop_sending: None,
                reset: Some(REQUEST_CANCELED_ERR),
                fin: StreamClosureKind::None,
            },
        );
        assert_eq!(audit_stats.downstream_bytes_recvd(), 10);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
        Ok(())
    }

    /// Test that dropping the `OutboundFrame` channel causes the driver to
    /// send a `RESET_STREAM` frame to the peer.
    #[test]
    fn client_send_reset_stream_when_outbound_frame_channel_drops_2() -> TestResult
    {
        let mut helper = DriverTestHelper::<ClientHooks>::new()?;
        helper.complete_handshake()?;
        helper.advance_and_run_loop()?;

        // The client uses H3Driver
        // client sends a request
        let stream_id =
            helper.driver_send_request(make_request_headers("GET"), false)?;

        // servers reads request and sends response headers, body, and fin
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false)?;
        helper.peer_server_send_body(0, &[2; 10], true)?;

        helper.advance_and_run_loop()?;

        // Client receives response headers
        let mut resp = assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        // take the InboundFrame receiver and stats
        let mut from_server = resp.recv;
        let audit_stats = resp.h3_audit_stats.clone();
        let (body, fin, _) = helper.driver_try_recv_body(&mut from_server)?;
        assert_eq!(body, vec![2; 10]);
        assert!(fin);
        helper.advance_and_run_loop()?;

        // clsoe the channel.
        resp.send.close();

        receive_request_reset(&mut helper, 0, REQUEST_CANCELED_ERR)?;

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_stream_termination(
            &audit_stats,
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
            StreamTermination {
                stop_sending: None,
                reset: Some(REQUEST_CANCELED_ERR),
                fin: StreamClosureKind::None,
            },
        );
        assert_eq!(audit_stats.downstream_bytes_recvd(), 10);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
        Ok(())
    }

    /// Send data until the stream is no longer writable, then drop the
    /// `OutboundFrame` channel to trigger a `RESET_STREAM`
    #[test]
    fn client_send_reset_stream_with_full_stream() -> TestResult {
        let mut config = default_quiche_config()?;
        config.set_initial_max_stream_data_bidi_local(30);
        config.set_initial_max_stream_data_bidi_remote(30);
        let mut helper = DriverTestHelper::<ClientHooks>::with_pipe(
            quiche::test_utils::Pipe::with_config_and_buf(&mut config)?,
        )?;
        helper.complete_handshake()?;
        helper.advance_and_run_loop()?;

        // The client uses H3Driver
        // client sends a request
        let stream_id =
            helper.driver_send_request(make_request_headers("GET"), false)?;

        // servers reads request and sends response headers, and fin
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, true)?;

        helper.advance_and_run_loop()?;

        // Client receives response headers
        let resp = assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(resp.read_fin);
        let audit_stats = resp.h3_audit_stats.clone();
        // send a body the to server, but not enough flow control for the full
        // body
        resp.send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .try_send(OutboundFrame::Body(
                Bytes::copy_from_slice(&[23; 50]),
                false,
            ))?;
        assert_eq!(helper.driver.waiting_streams.upstream_len(), 0);
        assert_eq!(helper.driver.waiting_streams.downstream_len(), 1);
        // run `work_loop_iter()` to write the body into quiche
        helper.work_loop_iter()?;
        // make sure we couldn't write the full body
        assert!(audit_stats.downstream_bytes_sent() < 50);
        let written = audit_stats.downstream_bytes_sent();
        // advance the pipe, the stream is writable again, but
        // don't advance the work_loop yet.
        helper.pipe.advance()?;
        while helper.peer_server_poll().is_ok() {}
        assert_eq!(
            helper.peer_server_recv_body_vec(0, 1024)?.len(),
            usize::try_from(written)?
        );
        helper.pipe.advance()?;
        assert_eq!(helper.driver.waiting_streams.upstream_len(), 0);
        assert_eq!(helper.driver.waiting_streams.downstream_len(), 0);
        assert!(helper
            .driver
            .stream_map
            .get(&0)
            .ok_or("missing stream context")?
            .recv
            .is_some());
        assert!(helper
            .driver
            .stream_map
            .get(&0)
            .ok_or("missing stream context")?
            .queued_frame
            .is_some());

        // clsoe the channel.
        drop(resp.send);

        helper.work_loop_iter()?;
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            Some(REQUEST_CANCELED_ERR)
        );
        receive_request_reset(&mut helper, 0, REQUEST_CANCELED_ERR)?;

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_stream_termination(
            &audit_stats,
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
            StreamTermination {
                stop_sending: None,
                reset: Some(REQUEST_CANCELED_ERR),
                fin: StreamClosureKind::None,
            },
        );
        Ok(())
    }

    /// Test that dropping the `OutboundFrame` channel after we've send a fin
    /// is a no-op.
    #[test]
    fn client_drop_outbound_frame_channel_after_fin_no_reset() -> TestResult {
        let mut helper = DriverTestHelper::<ClientHooks>::ready()?;

        // The client uses H3Driver
        // client sends a request
        let stream_id =
            helper.driver_send_request(make_request_headers("GET"), false)?;

        // servers reads request and sends response headers, body, and fin
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false)?;

        helper.advance_and_run_loop()?;

        // Client receives response headers
        let mut resp = assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        // take the InboundFrame receiver and stats
        let mut from_server = resp.recv;
        let audit_stats = resp.h3_audit_stats.clone();
        helper.advance_and_run_loop()?;
        resp.send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .try_send(OutboundFrame::Body(bytes::Bytes::new(), true))?;
        helper.advance_and_run_loop()?;

        // clsoe the channel.
        resp.send.close();

        helper.advance_and_run_loop()?;
        assert_eq!(helper.peer_server_send_body(0, &[42], true), Ok(1));
        helper.advance_and_run_loop()?;

        // server receives the fin
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_server_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_server_poll(), Ok((0, h3::Event::Finished)));
        assert_eq!(helper.peer_server_poll(), Err(h3::Error::Done));

        helper.advance_and_run_loop()?;

        // client receives the body and fin
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_server)?;
        assert_eq!(body, &[42]);
        assert!(fin);

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_stream_termination(
            &audit_stats,
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
        );
        assert_eq!(audit_stats.downstream_bytes_recvd(), 1);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
        Ok(())
    }

    /// Verify that a GOAWAY received mid-stream does not kill in-flight
    /// request streams. The server sends GOAWAY with an ID above the
    /// active stream, indicating the stream was accepted. The client
    /// should continue receiving the remaining response body and
    /// complete the stream normally.
    #[test]
    fn client_receives_goaway_during_streaming_response() -> TestResult {
        let mut helper = DriverTestHelper::<ClientHooks>::ready()?;

        // Client sends a request with fin (GET, no body).
        let stream_id =
            helper.driver_send_request(make_request_headers("GET"), true)?;
        assert_eq!(stream_id, 0);

        // Server sees the request and starts a streaming response.
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_server_poll()?,
            (0, h3::Event::Headers { .. })
        );
        helper.peer_server_send_response(0, false)?;
        helper.peer_server_send_body(0, &[1; 10], false)?;
        helper.advance_and_run_loop()?;

        // Client receives response headers.
        let resp = assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::IncomingHeaders(headers) => { headers }
        );
        assert_eq!(resp.stream_id, stream_id);
        assert!(!resp.read_fin);
        let mut from_server = resp.recv;

        // Client receives first body chunk.
        assert_eq!(helper.driver_try_recv_body(&mut from_server)?.0, vec![
            1;
            10
        ]);

        // Server sends GOAWAY with id = stream_id + 4 (our stream was
        // accepted, but no future streams will be).
        helper
            .peer
            .send_goaway(&mut helper.pipe.server, stream_id + 4)?;
        // Server continues sending body data on the existing stream.
        helper.peer_server_send_body(0, &[2; 10], false)?;

        // Advance — the driver handles GOAWAY gracefully and keeps
        // the connection alive.
        helper.advance_and_run_loop()?;

        // Client should still receive the second body chunk.
        assert_eq!(helper.driver_try_recv_body(&mut from_server)?.0, vec![
            2;
            10
        ]);

        // Controller receives a GoAway event with the correct ID.
        // Drain any BodyBytesReceived notifications first — the
        // ordering between data and control stream events is not
        // guaranteed.
        loop {
            match helper.driver_recv_core_event()? {
                H3Event::GoAway { id } => {
                    assert_eq!(id, stream_id + 4);
                    break;
                },
                H3Event::BodyBytesReceived { .. } => (),
                other =>
                    return Err(format!("unexpected event: {other:?}").into()),
            }
        }

        // Server finishes the response.
        helper.peer_server_send_body(0, &[3; 10], true)?;
        helper.advance_and_run_loop()?;

        // Client receives the final chunk.
        let (body, _fin, _err) = helper.driver_try_recv_body(&mut from_server)?;
        assert_eq!(body, vec![3; 10]);
        Ok(())
    }
}

/// Tests that use an `H3Driver` for the server side. We mostly focus on testing
/// the driver's handling of stream state, and data, rather than H3 semantics.
/// Note that most of these tests could have just as easily been written for
/// the client side.
mod server_side_driver {

    use crate::ApplicationOverQuic as _;

    use super::*;

    struct OpenServerResponse {
        helper: DriverTestHelper<ServerHooks>,
        request: IncomingH3Headers,
        sender: mpsc::Sender<OutboundFrame>,
    }

    // Queue response headers without running the work loop: individual tests
    // choose when transport writes, reads and termination events are processed.
    fn open_server_response(
        headers: &[h3::Header], request_fin: bool,
    ) -> crate::QuicResult<OpenServerResponse> {
        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;
        let stream_id = helper.peer_client_send_request(headers, request_fin)?;
        helper.advance_and_run_loop()?;
        let request = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers { incoming_headers, .. } => incoming_headers
        );
        assert_eq!(request.stream_id, stream_id);
        assert_eq!(request.read_fin, request_fin);
        let sender = request
            .send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .clone();
        sender.try_send(OutboundFrame::Headers(make_response_headers(), None))?;
        Ok(OpenServerResponse {
            helper,
            request,
            sender,
        })
    }

    fn read_response_headers(
        helper: &mut DriverTestHelper<ServerHooks>, stream_id: u64,
    ) -> TestResult {
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_client_poll(),
            Ok((id, h3::Event::Headers { .. })) if id == stream_id
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        Ok(())
    }

    fn receive_request_chunk(
        helper: &mut DriverTestHelper<ServerHooks>,
        receiver: &mut InboundFrameStream, stream_id: u64, body: &[u8],
        fin: bool,
    ) -> TestResult {
        assert_eq!(
            helper.peer_client_send_body(stream_id, body, fin),
            Ok(body.len())
        );
        helper.advance_and_run_loop()?;
        let (received, received_fin, _) =
            helper.driver_try_recv_body(receiver)?;
        assert_eq!(received, body);
        assert_eq!(received_fin, fin);
        Ok(())
    }

    fn send_final_response_body(
        helper: &mut DriverTestHelper<ServerHooks>,
        sender: &mpsc::Sender<OutboundFrame>, stream_id: u64, body: &[u8],
    ) -> TestResult {
        sender
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(body), true))?;
        helper.advance_and_run_loop()?;
        assert_eq!(helper.peer_client_poll(), Ok((stream_id, h3::Event::Data)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        let read_size = body.len().max(1024);
        assert_eq!(
            helper.peer_client_recv_body_vec(stream_id, read_size),
            Ok(body.to_vec())
        );
        assert_eq!(
            helper.peer_client_recv_body_vec(stream_id, read_size),
            Err(h3::Error::Done)
        );
        assert_eq!(
            helper.peer_client_poll(),
            Ok((stream_id, h3::Event::Finished))
        );
        Ok(())
    }

    /// Server-side equivalent of
    /// [`client_side_driver::client_body_recv_buf_not_allocated_when_idle`]:
    /// `body_recv_buf` is `H3Driver` state shared by both `ClientHooks` and
    /// `ServerHooks`, so a headers-only request/response must not allocate it
    /// on the server either.
    #[test]
    fn server_body_recv_buf_not_allocated_when_idle() -> TestResult {
        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;

        // Idle: never received body bytes, so the buffer is not allocated.
        assert!(helper.driver.body_recv_buf.is_none());

        // Client sends a headers-only request (fin, no request body).
        let stream_id = helper
            .peer_client_send_request(&make_request_headers("GET"), true)?;

        // Server reads the request; `read_fin` confirms it finished on its
        // headers and carries no body.
        helper.advance_and_run_loop()?;
        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers { incoming_headers, .. } => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(req.read_fin);

        // The server read only headers (no body), so the buffer stays
        // unallocated.
        assert!(helper.driver.body_recv_buf.is_none());

        // Server replies with a headers-only response: response headers
        // followed by an empty body with fin to complete the exchange. The
        // per-stream channel holds a single frame in debug builds
        // (`STREAM_CAPACITY`), so drain the headers before sending the fin.
        let to_client = req
            .send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .clone();
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))?;
        helper.work_loop_iter()?;
        to_client.try_send(OutboundFrame::Body(bytes::Bytes::new(), true))?;
        helper.advance_and_run_loop()?;

        // Client receives the headers-only response.
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );

        // Still only headers were exchanged and the stream is closed, so the
        // body receive buffer was never allocated.
        assert!(helper.driver.body_recv_buf.is_none());
        assert_eq!(helper.driver.stream_map.len(), 0);
        Ok(())
    }

    #[test]
    fn client_fin_before_server_body() -> TestResult {
        let OpenServerResponse {
            mut helper,
            request: req,
            sender: to_client,
        } = open_server_response(&make_request_headers("GET"), false)?;
        let mut from_client = req.recv;

        // client reads response and sends body and fin
        read_response_headers(&mut helper, 0)?;
        receive_request_chunk(&mut helper, &mut from_client, 0, &[1; 5], true)?;

        // server sends body and fin
        send_final_response_body(&mut helper, &to_client, 0, &[42])?;

        assert_eq!(helper.driver.stream_map.len(), 0);
        Ok(())
    }

    #[test]
    fn verify_pr_2162() -> TestResult {
        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;

        // client sends a request but NO FIN.
        let stream_id = helper
            .peer_client_send_request(&make_request_headers("GET"), false)?;

        // servers reads request and sends response headers
        helper.advance_and_run_loop()?;
        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        assert!(!req.read_fin);
        let to_client = req
            .send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .clone();
        let mut from_client = req.recv;
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))?;
        helper.work_loop_iter()?;
        // server sends body and fin. This caused an infinite loop before #2162
        to_client
            .try_send(OutboundFrame::Body(Bytes::copy_from_slice(&[42]), true))?;
        helper.advance_and_run_loop()?;

        // client sends body and fin
        helper.advance_and_run_loop()?;
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], true), Ok(5));
        helper.advance_and_run_loop()?;

        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client)?;
        assert_eq!(body, &[1; 5]);
        assert!(fin);

        // Stream is done
        assert_eq!(helper.driver.stream_map.len(), 0);
        Ok(())
    }

    /// Test the case where the client sends a `STOP_SENDING` quiche frame.
    #[test]
    fn client_sends_stop_sending() -> TestResult {
        let OpenServerResponse {
            mut helper,
            request: req,
            sender: to_client,
        } = open_server_response(&make_request_headers("GET"), false)?;
        let mut from_client = req.recv;
        let audit_stats = req.h3_audit_stats;
        let stream_id = req.stream_id;

        // client sends a STOP_SENDING
        read_response_headers(&mut helper, 0)?;
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Read, 4242),
            Ok(())
        );

        let flight = quiche::test_utils::emit_flight(&mut helper.pipe.client)?;
        quiche::test_utils::process_flight(&mut helper.pipe.server, flight)?;

        // No additional client data leaves the server's `try_recv()` empty.
        assert_matches!(from_client.try_recv(), Err(TryRecvError::Empty));

        // An empty non-FIN body must not hide a stop when no H3 send occurs.
        let ctx = helper
            .driver
            .stream_map
            .get_mut(&stream_id)
            .ok_or("missing stream context")?;
        ctx.queued_frame = Some(OutboundFrame::Body(Bytes::new(), false));

        helper.driver.process_writes(&mut helper.pipe.server)?;

        assert!(to_client.is_closed());
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), Some(4242));

        let ctx = helper
            .driver
            .stream_map
            .get(&stream_id)
            .ok_or("missing stream context")?;
        assert!(ctx.queued_frame.is_none());
        assert!(ctx.recv.is_none());

        // A late channel completion must not restore canceled output.
        let (_, stale_recv) = tokio::sync::mpsc::channel(STREAM_CAPACITY);

        helper.driver.upstream_read_ready(
            &mut helper.pipe.server,
            ReceivedDownstreamData {
                stream_id,
                chan: stale_recv,
                data: Some(OutboundFrame::Headers(make_response_headers(), None)),
            },
        )?;

        let ctx = helper
            .driver
            .stream_map
            .get(&stream_id)
            .ok_or("missing stream context")?;
        assert!(ctx.queued_frame.is_none());
        assert!(ctx.recv.is_none());

        // STOP_SENDING only closes one half of the stream. The client
        // can still send data and it MUST send a `fin` to close the
        // other half.
        helper.peer_client_send_body(0, &[1, 2, 3], true)?;
        helper.advance_and_run_loop()?;
        let (body, fin, _err) = helper.driver_try_recv_body(&mut from_client)?;
        assert_eq!(body, &[1, 2, 3]);
        assert!(fin);

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), Some(4242));
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), None);
        assert_eq!(audit_stats.sent_stop_sending_error_code(), None);
        // technically quiche will automatically respond to a STOP_SENDING
        // frame with a STREAM_RESET echoing the error code, but the user
        // didn't *actively* send a STREAM_RESET.
        assert_eq!(audit_stats.sent_reset_stream_error_code(), None);
        assert_eq!(audit_stats.recvd_stream_fin(), StreamClosureKind::Explicit);
        assert_eq!(audit_stats.sent_stream_fin(), StreamClosureKind::None);
        assert_eq!(audit_stats.downstream_bytes_recvd(), 3);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
        Ok(())
    }

    /// Control-plane shutdown must still reach the read half after the
    /// peer has stopped the write half and its data channel was cancelled.
    #[test]
    fn control_shutdown_after_stop_closes_remaining_direction(
    ) -> anyhow::Result<()> {
        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;
        let stream_id = helper
            .peer_client_send_request(&make_request_headers("POST"), false)?;
        helper.advance_and_run_loop()?;
        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers { incoming_headers, .. } => incoming_headers
        );
        let to_client = req
            .send
            .get_ref()
            .ok_or_else(|| anyhow::anyhow!("missing sender"))?;
        to_client
            .try_send(OutboundFrame::Body(Bytes::from_static(b"body"), false))
            .map_err(|_| anyhow::anyhow!("queueing body"))?;
        helper.pipe.client.stream_shutdown(
            stream_id,
            quiche::Shutdown::Read,
            4242,
        )?;
        let flight = quiche::test_utils::emit_flight(&mut helper.pipe.client)?;
        quiche::test_utils::process_flight(&mut helper.pipe.server, flight)?;
        helper
            .driver
            .process_writes(&mut helper.pipe.server)
            .map_err(anyhow::Error::from_boxed)?;
        assert!(helper.driver.stream_map.contains_key(&stream_id));
        assert!(to_client.is_closed());
        let code = h3::WireErrorCode::MessageError as u64;
        helper
            .controller
            .shutdown_stream(stream_id, StreamShutdown::Both {
                read_error_code: code,
                write_error_code: code,
            });
        helper.advance_and_run_loop()?;
        assert!(!helper.driver.stream_map.contains_key(&stream_id));
        assert_eq!(
            req.h3_audit_stats.recvd_stop_sending_error_code(),
            Some(4242)
        );
        assert_eq!(
            req.h3_audit_stats.sent_stop_sending_error_code(),
            Some(code)
        );
        assert_eq!(req.h3_audit_stats.sent_reset_stream_error_code(), None);
        assert_eq!(
            helper.peer_client_send_body(stream_id, b"body", false),
            Err(h3::Error::Transport(quiche::Error::StreamStopped(code)))
        );
        Ok(())
    }

    #[derive(Clone, Copy, Debug)]
    enum RequestState {
        Open,
        Fin,
        Reset,
    }

    #[derive(Clone, Copy, Debug)]
    enum ResponseState {
        NotStarted,
        InformationalHeaders,
        FinalHeaders,
        BodyStalled,
    }

    #[rstest]
    fn stop_sending_closes_idle_responses_for_all_request_states(
        #[values(RequestState::Open, RequestState::Fin, RequestState::Reset)]
        request_state: RequestState,
        #[values(
            ResponseState::NotStarted,
            ResponseState::InformationalHeaders,
            ResponseState::FinalHeaders,
            ResponseState::BodyStalled
        )]
        response_state: ResponseState,
    ) -> TestResult {
        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;

        let stream_id = helper.peer_client_send_request(
            &make_request_headers("POST"),
            matches!(request_state, RequestState::Fin),
        )?;

        helper.advance_and_run_loop()?;

        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers { incoming_headers, .. } => {
                incoming_headers
            }
        );

        let to_client = req
            .send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .clone();
        let audit_stats = req.h3_audit_stats;

        if matches!(request_state, RequestState::Reset) {
            helper.pipe.client.stream_shutdown(
                stream_id,
                quiche::Shutdown::Write,
                1234,
            )?;

            helper.advance_and_run_loop()?;
        }

        let ctx = helper
            .driver
            .stream_map
            .get(&stream_id)
            .ok_or("missing stream context")?;
        assert_eq!(
            ctx.read_state != ReadState::Open,
            !matches!(request_state, RequestState::Open)
        );

        let headers = match response_state {
            ResponseState::NotStarted => None,
            ResponseState::InformationalHeaders =>
                Some(vec![h3::Header::new(b":status", b"103")]),
            ResponseState::FinalHeaders | ResponseState::BodyStalled =>
                Some(make_response_headers()),
        };

        if let Some(headers) = headers {
            to_client.try_send(OutboundFrame::Headers(headers, None))?;

            helper.advance_and_run_loop()?;

            let ctx = helper
                .driver
                .stream_map
                .get(&stream_id)
                .ok_or("missing stream context")?;
            assert!(ctx.initial_headers_sent);
        }

        if matches!(response_state, ResponseState::BodyStalled) {
            to_client.try_send(OutboundFrame::Body(
                Bytes::copy_from_slice(b"first chunk"),
                false,
            ))?;

            helper.advance_and_run_loop()?;

            assert!(audit_stats.downstream_bytes_sent() > 0);
        }

        helper.pipe.client.stream_shutdown(
            stream_id,
            quiche::Shutdown::Read,
            4242,
        )?;

        // Keep the automatic RESET_STREAM unacknowledged until the driver
        // has observed STOP_SENDING.
        let flight = quiche::test_utils::emit_flight(&mut helper.pipe.client)?;
        quiche::test_utils::process_flight(&mut helper.pipe.server, flight)?;

        // Process the stopped stream without another application frame.
        helper.driver.process_writes(&mut helper.pipe.server)?;

        assert!(
            to_client.is_closed(),
            "request={request_state:?}, response={response_state:?}"
        );
        assert_eq!(
            audit_stats.recvd_stop_sending_error_code(),
            Some(4242),
            "request={request_state:?}, response={response_state:?}"
        );
        Ok(())
    }

    #[test]
    fn stop_sending_before_headers_closes_new_context() -> TestResult {
        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;

        let stream_id = helper
            .peer_client_send_request(&make_request_headers("GET"), true)?;

        // Hold HEADERS+FIN until STOP_SENDING has been processed without a
        // stream context.
        let headers_flight =
            quiche::test_utils::emit_flight(&mut helper.pipe.client)?;

        helper.pipe.client.stream_shutdown(
            stream_id,
            quiche::Shutdown::Read,
            4242,
        )?;

        let stop_flight =
            quiche::test_utils::emit_flight(&mut helper.pipe.client)?;
        quiche::test_utils::process_flight(&mut helper.pipe.server, stop_flight)?;

        helper.work_loop_iter()?;
        assert!(!helper.driver.stream_map.contains_key(&stream_id));

        quiche::test_utils::process_flight(
            &mut helper.pipe.server,
            headers_flight,
        )?;
        helper.work_loop_iter()?;

        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers { incoming_headers, .. } => incoming_headers
        );

        assert!(req
            .send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .is_closed());
        assert_eq!(
            req.h3_audit_stats.recvd_stop_sending_error_code(),
            Some(4242)
        );

        assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::BodyBytesReceived { fin: true, .. }
        );
        assert_matches!(
            helper.driver_recv_core_event()?,
            H3Event::StreamClosed { stream_id: id } if id == stream_id
        );
        Ok(())
    }

    /// Test the case where the server's outbound channel closes and
    /// `audit_stats` records the `STOP_SENDING` error code from the client
    /// sent before the server has written any response to a `fin=true` request
    #[test]
    fn client_sends_stop_sending_before_first_write() -> TestResult {
        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(&make_request_headers("GET"), true)?;

        // server reads the request and creates the StreamCtx
        helper.advance_and_run_loop()?;
        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        let to_client = req
            .send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .clone();
        let audit_stats = req.h3_audit_stats;

        // client sends a STOP_SENDING before the server has written any
        // response bytes
        assert_eq!(
            helper.pipe.client.stream_shutdown(
                stream_id,
                quiche::Shutdown::Read,
                4242
            ),
            Ok(())
        );
        helper.advance_and_run_loop()?;

        assert!(to_client.is_closed());
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), Some(4242));
        Ok(())
    }

    /// A request body and FIN delivered with `STOP_SENDING` must close the
    /// response channel before the `RESET_STREAM` is acknowledged.
    #[test]
    fn client_sends_body_fin_and_stop_before_first_writable_poll() -> TestResult {
        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(&make_request_headers("POST"), false)?;

        // server reads the request and creates the StreamCtx
        helper.advance_and_run_loop()?;
        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        let to_client = req
            .send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .clone();
        let audit_stats = req.h3_audit_stats;

        // Deliver body, FIN, and STOP_SENDING together before the server
        // processes reads or writes. Keep the automatic RESET_STREAM
        // unacknowledged until the driver handles the stop.
        helper.peer_client_send_body(stream_id, b"body", true)?;

        assert_eq!(
            helper.pipe.client.stream_shutdown(
                stream_id,
                quiche::Shutdown::Read,
                4242
            ),
            Ok(())
        );
        let flight = quiche::test_utils::emit_flight(&mut helper.pipe.client)?;
        quiche::test_utils::process_flight(&mut helper.pipe.server, flight)?;

        // Run process_reads() and process_writes() back to back, exactly
        // as RunningApplication::on_read() does. process_writes() calls
        // stream_writable_next(), which pops the stream with nothing
        // queued to write, before the RESET_STREAM we just queued has
        // even reached the client.
        helper.driver.process_reads(&mut helper.pipe.server)?;
        helper.driver.process_writes(&mut helper.pipe.server)?;

        assert!(to_client.is_closed());
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), Some(4242));

        // Only now let the RESET_STREAM reach the client, and the
        // client's ack come back to the server.
        let flight = quiche::test_utils::emit_flight(&mut helper.pipe.server)?;
        quiche::test_utils::process_flight(&mut helper.pipe.client, flight)?;
        let flight = quiche::test_utils::emit_flight(&mut helper.pipe.client)?;
        quiche::test_utils::process_flight(&mut helper.pipe.server, flight)?;

        assert!(to_client.is_closed());
        assert_eq!(audit_stats.recvd_stop_sending_error_code(), Some(4242));
        Ok(())
    }

    #[test]
    fn stop_after_response_fin_returns_stream_credit() -> TestResult {
        let mut config = default_quiche_config()?;
        config.set_initial_max_streams_bidi(1);

        let pipe = quiche::test_utils::Pipe::with_config_and_buf(&mut config)?;
        let mut helper = DriverTestHelper::<ServerHooks>::with_pipe(pipe)?;
        helper.complete_handshake()?;
        helper.advance_and_run_loop()?;

        let stream_id = helper
            .peer_client_send_request(&make_request_headers("GET"), true)?;
        helper.advance_and_run_loop()?;

        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers { incoming_headers, .. } => incoming_headers
        );
        let to_client = req
            .send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .clone();

        // Leave the response flight unacknowledged after the driver closes
        // its stream context.
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))?;
        helper.work_loop_iter()?;

        to_client.try_send(OutboundFrame::Body(Bytes::new(), true))?;
        helper.work_loop_iter()?;

        assert!(!helper.driver.stream_map.contains_key(&stream_id));
        assert!(helper.pipe.server.stream_capacity(stream_id).is_ok());
        assert_eq!(helper.pipe.client.peer_streams_left_bidi(), 0);

        helper.pipe.client.stream_shutdown(
            stream_id,
            quiche::Shutdown::Read,
            4242,
        )?;
        let flight = quiche::test_utils::emit_flight(&mut helper.pipe.client)?;
        quiche::test_utils::process_flight(&mut helper.pipe.server, flight)?;

        helper.driver.process_writes(&mut helper.pipe.server)?;

        let flight = quiche::test_utils::emit_flight(&mut helper.pipe.server)?;
        quiche::test_utils::process_flight(&mut helper.pipe.client, flight)?;

        assert_eq!(helper.pipe.client.peer_streams_left_bidi(), 1);
        Ok(())
    }

    /// Test the case where the client sends a `RESET_STREAM` quiche frame.
    /// The peer sends its reset before we send a fin
    #[test]
    fn client_sends_reset_stream_before_server_fin() -> TestResult {
        let OpenServerResponse {
            mut helper,
            request: req,
            sender: to_client,
        } = open_server_response(&make_request_headers("GET"), false)?;
        let from_client = req.recv;
        let audit_stats = req.h3_audit_stats;

        // client sends a RESET_STREAM frame
        helper.advance_and_run_loop()?;
        assert_eq!(helper.driver.waiting_streams.downstream_len(), 1);
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Write, 4242),
            Ok(())
        );
        helper.advance_and_run_loop()?;
        assert_eq!(helper.driver.waiting_streams.downstream_len(), 1);

        // The channel is closed because the peer send us the reset.
        assert!(from_client.is_closed());
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), Some(4242));
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ResetStream { stream_id: 0 })
        );

        // We can still write to the peer and in fact, we must eventually send a
        // fin.
        to_client.try_send(OutboundFrame::Body(
            Bytes::copy_from_slice(&[5; 4]),
            false,
        ))?;
        helper.advance_and_run_loop()?;
        to_client.try_send(OutboundFrame::Body(
            Bytes::copy_from_slice(&[6; 4]),
            true,
        ))?;
        helper.advance_and_run_loop()?;

        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Ok(vec![5, 5, 5, 5, 6, 6, 6, 6])
        );

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_stream_termination(
            &audit_stats,
            StreamTermination {
                stop_sending: None,
                reset: Some(4242),
                fin: StreamClosureKind::None,
            },
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
        );
        assert_eq!(audit_stats.downstream_bytes_recvd(), 0);
        assert_eq!(audit_stats.downstream_bytes_sent(), 8);
        Ok(())
    }

    /// Test the case where the client sends a `RESET_STREAM` quiche frame.
    /// We send a fin before the client sends reset
    #[test]
    fn client_sends_reset_stream_after_server_fin() -> TestResult {
        let OpenServerResponse {
            mut helper,
            request: req,
            sender: to_client,
        } = open_server_response(&make_request_headers("GET"), false)?;
        let from_client = req.recv;
        let audit_stats = req.h3_audit_stats;
        helper.work_loop_iter()?;
        to_client.try_send(OutboundFrame::Body(
            Bytes::copy_from_slice(b"foobar 42"),
            true,
        ))?;
        helper.advance_and_run_loop()?;

        // client sends a RESET_STREAM frame
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_matches!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        helper.peer_client_recv_body_vec(0, 1024)?;
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Write, 4242),
            Ok(())
        );
        helper.advance_and_run_loop()?;

        // The channel is closed because the peer send us the reset.
        assert!(from_client.is_closed());
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ResetStream { stream_id: 0 })
        );

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_stream_termination(
            &audit_stats,
            StreamTermination {
                stop_sending: None,
                reset: Some(4242),
                fin: StreamClosureKind::None,
            },
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
        );
        assert_eq!(audit_stats.downstream_bytes_recvd(), 0);
        assert_eq!(
            audit_stats.downstream_bytes_sent(),
            b"foobar 42".len() as u64
        );
        Ok(())
    }

    /// Test the case where the client sends a `RESET_STREAM` quiche frame while
    /// we're in the middle of reading data. We want to excercise the
    /// code-path where `upstream_ready` is called before `process_reads`.
    /// If `process_reads()` is called first, it will get the Reset event.
    /// If `upstream_ready()` is called first, it will attempt to read from
    /// the `h3::Connection` and will get a
    /// `Transport(StreamReset(code))`
    #[test]
    fn client_sends_reset_stream_while_reading_wait_for_data() -> TestResult {
        let OpenServerResponse {
            mut helper,
            request: req,
            sender: to_client,
        } = open_server_response(&make_request_headers("GET"), false)?;
        let mut from_client = req.recv;
        let audit_stats = req.h3_audit_stats;
        helper.work_loop_iter()?;
        to_client.try_send(OutboundFrame::Body(
            Bytes::copy_from_slice(&[1, 2, 3, 4]),
            false,
        ))?;
        helper.advance_and_run_loop()?;

        // client sends data
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_matches!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        // The client sends the first half of the body.
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));

        // Advance the pipe and let the driver read the buffered body into the
        // `from_client` channel, filling it (`STREAM_CAPACITY` is 1 in tests).
        helper.pipe.advance()?;
        helper.work_loop_iter()?;

        // The client sends the second half. With the downstream channel full
        // and the stream readable again, the driver blocks the stream waiting
        // for capacity (registering it in `waiting_streams`) without reading
        // further.
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));
        helper.pipe.advance()?;
        helper.work_loop_iter()?;

        // Drain the first body frame; this frees downstream capacity so the
        // blocked stream can make progress on the next `wait_for_data`.
        assert_matches!(from_client.try_recv(), Ok(InboundFrame { body: buf, fin }) => {
            assert_eq!(buf.to_vec(), &[1; 5]);
            assert!(!fin);
        });
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::BodyBytesReceived {
                stream_id: 0,
                num_bytes: 5,
                fin: false
            })
        );
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(TryRecvError::Empty)
        );

        // The client resets the stream; the buffered-but-unread second half is
        // dropped when the reset is processed.
        // TODO: This is a bit finnicky to test properly. We don't want to run a
        // full `work_loop_iter()` because that would call `process_reads()`
        // first; we exercise the path where `wait_for_data` / `upstream_ready`
        // observes the reset while reading.
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Write, 4242),
            Ok(())
        );
        helper.pipe.advance()?;
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never()
        .unwrap_or(Ok(()))?;

        // The channel is closed because the peer send us the reset.
        assert!(from_client.is_closed());
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), Some(4242));
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ResetStream { stream_id: 0 })
        );

        // We can still write to the peer and in fact, we must eventually send a
        // fin.
        to_client.try_send(OutboundFrame::Body(
            Bytes::copy_from_slice(&[6; 4]),
            true,
        ))?;
        helper.advance_and_run_loop()?;

        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Ok(vec![1, 2, 3, 4, 6, 6, 6, 6])
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_stream_termination(
            &audit_stats,
            StreamTermination {
                stop_sending: None,
                reset: Some(4242),
                fin: StreamClosureKind::None,
            },
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
        );
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 8);
        Ok(())
    }

    /// Test the case where the client sends a `RESET_STREAM` quiche frame while
    /// we're in the middle of reading data. We want to excercise the
    /// code-path where where we call `process_reads` before
    /// `upstream_ready()`.
    #[test]
    fn server_sends_reset_stream_while_reading_process_reads() -> TestResult {
        let OpenServerResponse {
            mut helper,
            request: req,
            sender: to_client,
        } = open_server_response(&make_request_headers("GET"), false)?;
        let mut from_client = req.recv;
        let audit_stats = req.h3_audit_stats;
        helper.advance_and_run_loop()?;

        // client sends data
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        // The client sends the first half of the body.
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));

        // Advance the pipe and let the driver read the buffered body and put
        // it into the `from_client` channel.
        helper.pipe.advance()?;
        helper.work_loop_iter()?;
        assert_matches!(from_client.try_recv(), Ok(InboundFrame { body: buf, fin }) => {
            assert_eq!(buf.to_vec(), &[1; 5]);
            assert!(!fin);
        });
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::BodyBytesReceived {
                stream_id: 0,
                num_bytes: 5,
                fin: false
            })
        );

        // The client sends the second half of the body (delivered to the
        // server but not yet read by the driver), then resets the stream. The
        // buffered-but-unread bytes are dropped when the reset is processed, so
        // they are never counted.
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));
        helper.pipe.advance()?;
        assert_eq!(
            helper
                .pipe
                .client
                .stream_shutdown(0, quiche::Shutdown::Write, 4242),
            Ok(())
        );
        helper.advance_and_run_loop()?;

        // The channel is closed because the peer send us the reset.
        assert!(from_client.is_closed());
        assert_eq!(audit_stats.recvd_reset_stream_error_code(), Some(4242));
        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::ResetStream { stream_id: 0 })
        );

        // send fin to client
        to_client.try_send(OutboundFrame::Body(bytes::Bytes::new(), true))?;
        helper.advance_and_run_loop()?;

        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        assert_eq!(helper.driver.stream_map.len(), 0);
        assert_stream_termination(
            &audit_stats,
            StreamTermination {
                stop_sending: None,
                reset: Some(4242),
                fin: StreamClosureKind::None,
            },
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
        );
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 0);
        Ok(())
    }

    #[test]
    fn server_driver_send_stop_sending_after_channel_drop() -> TestResult {
        let OpenServerResponse {
            mut helper,
            request: req,
            sender: to_client,
        } = open_server_response(&make_request_headers("GET"), false)?;
        let audit_stats = req.h3_audit_stats.clone();
        let mut from_client = req.recv;

        // client reads response and sends body without fin
        read_response_headers(&mut helper, 0)?;
        receive_request_chunk(&mut helper, &mut from_client, 0, &[1; 5], false)?;

        // peer (client) sends more data
        assert_eq!(helper.peer_client_send_body(0, &[1; 6], false), Ok(6));
        // advance the pipe only
        helper.pipe.advance()?;
        // we drop the channel.
        drop(from_client);
        helper.advance_and_run_loop()?;

        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::BodyBytesReceived {
                stream_id: 0,
                num_bytes: 5,
                fin: false
            })
        );
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(TryRecvError::Empty)
        );

        // Make sure the peer has received our STOP_SENDING frame
        assert_eq!(
            helper.peer_client_send_body(0, &[1; 7], false),
            Err(h3::Error::Transport(quiche::Error::StreamStopped(
                REQUEST_CANCELED_ERR
            )))
        );
        helper.advance_and_run_loop()?;

        // we still need to send a fin
        send_final_response_body(&mut helper, &to_client, 0, &[42])?;

        assert_stream_termination(
            &audit_stats,
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::None,
            },
            StreamTermination {
                stop_sending: Some(REQUEST_CANCELED_ERR),
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
        );
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 1);
        assert_eq!(helper.driver.stream_map.len(), 0);
        Ok(())
    }

    // Verify we don't send a STOP_SENDING frame if we've already processed a
    // fin
    #[test]
    fn server_driver_drop_channel_after_fin() -> TestResult {
        let OpenServerResponse {
            mut helper,
            request: req,
            sender: to_client,
        } = open_server_response(&make_request_headers("GET"), false)?;
        let audit_stats = req.h3_audit_stats.clone();
        let mut from_client = req.recv;

        // client reads response and sends body WITH fin
        read_response_headers(&mut helper, 0)?;
        receive_request_chunk(&mut helper, &mut from_client, 0, &[1; 5], true)?;

        helper.advance_and_run_loop()?;
        // we drop the channel.
        drop(from_client);
        helper.advance_and_run_loop()?;

        // we still need to send a fin
        send_final_response_body(&mut helper, &to_client, 0, &[42])?;

        assert_stream_termination(
            &audit_stats,
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
        );
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 1);
        assert_eq!(helper.driver.stream_map.len(), 0);
        Ok(())
    }

    // Test the edge case where the driver has read a fin from the stream but
    // hasn't been able to deliver it before the channel is dropped.
    #[test]
    fn server_driver_drop_channel_after_fin_2() -> TestResult {
        let OpenServerResponse {
            mut helper,
            request: req,
            sender: to_client,
        } = open_server_response(&make_request_headers("GET"), false)?;
        let audit_stats = req.h3_audit_stats.clone();

        // client reads response and sends body without fin
        read_response_headers(&mut helper, 0)?;
        assert_eq!(helper.peer_client_send_body(0, &[1; 5], false), Ok(5));
        helper.advance_and_run_loop()?;

        // peer (client) sends more data and fin
        assert_eq!(helper.peer_client_send_body(0, &[1; 6], true), Ok(6));
        helper.advance_and_run_loop()?;
        // we drop the channel.
        drop(req.recv);
        helper.advance_and_run_loop()?;

        assert_matches!(
            helper.driver_recv_core_event(),
            Ok(H3Event::BodyBytesReceived {
                stream_id: 0,
                num_bytes: 5,
                fin: false
            })
        );
        assert_matches!(
            helper.controller.event_receiver_mut().try_recv(),
            Err(TryRecvError::Empty)
        );

        // we still need to send a fin
        send_final_response_body(&mut helper, &to_client, 0, &[42])?;

        assert_stream_termination(
            &audit_stats,
            StreamTermination {
                stop_sending: None,
                reset: None,
                fin: StreamClosureKind::None,
            },
            StreamTermination {
                stop_sending: Some(REQUEST_CANCELED_ERR),
                reset: None,
                fin: StreamClosureKind::Explicit,
            },
        );
        assert_eq!(audit_stats.downstream_bytes_recvd(), 5);
        assert_eq!(audit_stats.downstream_bytes_sent(), 1);
        assert_eq!(helper.driver.stream_map.len(), 0);
        Ok(())
    }

    #[test]
    fn server_send_trailers() -> TestResult {
        let OpenServerResponse {
            mut helper,
            request: req,
            sender: to_client,
        } = open_server_response(&make_request_headers("GET"), false)?;
        let mut from_client = req.recv;

        // client reads response and sends body and fin
        read_response_headers(&mut helper, 0)?;
        receive_request_chunk(&mut helper, &mut from_client, 0, &[1; 5], true)?;

        // server sends body
        to_client.try_send(OutboundFrame::Body(
            Bytes::copy_from_slice(&[42]),
            false,
        ))?;
        helper.advance_and_run_loop()?;
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![42]));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );

        // server sends trailers
        to_client
            .try_send(OutboundFrame::Trailers(make_response_trailers(), None))?;
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );

        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));
        assert_eq!(helper.peer_client_poll(), Err(h3::Error::Done));
        Ok(())
    }

    #[test]
    fn response_fin_does_not_discard_blocked_request_fin() -> anyhow::Result<()> {
        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;
        let stream_id = helper
            .peer_client_send_request(&make_request_headers("POST"), false)?;
        helper.advance_and_run_loop()?;
        let mut req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers { incoming_headers, .. } => incoming_headers
        );
        let sender = req
            .send
            .get_ref()
            .ok_or_else(|| anyhow::anyhow!("missing sender"))?
            .clone();
        sender
            .try_send(OutboundFrame::Headers(make_response_headers(), None))
            .map_err(|_| anyhow::anyhow!("queueing response headers"))?;
        helper.advance_and_run_loop()?;
        helper.peer_client_send_body(stream_id, b"body", true)?;
        helper.advance_and_run_loop()?;
        assert_eq!(
            helper
                .driver
                .stream_map
                .get(&stream_id)
                .map(|ctx| ctx.read_state),
            Some(ReadState::FinPending)
        );
        sender
            .try_send(OutboundFrame::Body(Bytes::new(), true))
            .map_err(|_| anyhow::anyhow!("queueing response FIN"))?;
        helper.advance_and_run_loop()?;
        assert!(helper.driver.stream_map.contains_key(&stream_id));
        let (body, fin, status) = helper.driver_try_recv_body(&mut req.recv)?;
        assert_eq!(body, b"body");
        assert!(fin);
        assert_eq!(status, TryRecvError::Disconnected);
        assert!(!helper.driver.stream_map.contains_key(&stream_id));
        Ok(())
    }

    /// Test that calling `H3Controller::shutdown_stream` with
    /// `StreamShutdown::Write` sends a `RESET_STREAM` frame to the peer.
    #[test]
    fn server_shutdown_stream_write_direction() -> TestResult {
        use crate::http3::driver::StreamShutdown;
        const CUSTOM_ERROR_CODE: u64 = 0x1234;

        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;

        // client sends a request
        let stream_id = helper
            .peer_client_send_request(&make_request_headers("GET"), false)?;

        // server reads request
        helper.advance_and_run_loop()?;
        let mut req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        let audit_stats = req.h3_audit_stats.clone();

        // Server calls shutdown_stream via the controller
        helper
            .controller
            .shutdown_stream(stream_id, StreamShutdown::Write {
                error_code: CUSTOM_ERROR_CODE,
            });

        helper.advance_and_run_loop()?;

        // Client should receive the RESET_STREAM
        // Note: quiche::h3 reports RESET_STREAM via a transport error when
        // trying to read from the stream
        assert_eq!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Reset(CUSTOM_ERROR_CODE)))
        );

        // Verify stats
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            Some(CUSTOM_ERROR_CODE)
        );
        assert_eq!(audit_stats.sent_stop_sending_error_code(), None);
        assert!(helper.driver.stream_map.contains_key(&stream_id));
        helper.peer_client_send_body(stream_id, b"still readable", true)?;
        helper.advance_and_run_loop()?;
        let (body, fin, status) = helper.driver_try_recv_body(&mut req.recv)?;
        assert_eq!(body, b"still readable");
        assert!(fin);
        assert_eq!(status, TryRecvError::Disconnected);
        assert!(!helper.driver.stream_map.contains_key(&stream_id));
        Ok(())
    }

    /// Test that calling `H3Controller::shutdown_stream` with
    /// `StreamShutdown::Read` sends a `STOP_SENDING` frame to the peer.
    #[test]
    fn server_shutdown_stream_read_direction() -> TestResult {
        use crate::http3::driver::StreamShutdown;
        const CUSTOM_ERROR_CODE: u64 = 0x5678;

        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;

        // client sends a request without fin (expecting to send body)
        let stream_id = helper
            .peer_client_send_request(&make_request_headers("POST"), false)?;

        // server reads request
        helper.advance_and_run_loop()?;
        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        let audit_stats = req.h3_audit_stats.clone();

        // Server calls shutdown_stream with Read direction (STOP_SENDING)
        helper
            .controller
            .shutdown_stream(stream_id, StreamShutdown::Read {
                error_code: CUSTOM_ERROR_CODE,
            });

        helper.advance_and_run_loop()?;

        // Client tries to send body - should get StreamStopped error
        assert_eq!(
            helper.peer_client_send_body(0, &[1, 2, 3], false),
            Err(h3::Error::Transport(quiche::Error::StreamStopped(
                CUSTOM_ERROR_CODE
            )))
        );

        // Verify stats
        assert_eq!(audit_stats.sent_reset_stream_error_code(), None);
        assert_eq!(
            audit_stats.sent_stop_sending_error_code(),
            Some(CUSTOM_ERROR_CODE)
        );
        assert!(helper.driver.stream_map.contains_key(&stream_id));
        let to_client =
            req.send.get_ref().ok_or("missing outbound stream sender")?;
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))?;
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        to_client.try_send(OutboundFrame::Body(Bytes::new(), true))?;
        helper.advance_and_run_loop()?;
        // An empty DATA frame carrying FIN still requires draining the
        // H3 body parser before its Finished event is available.
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Err(h3::Error::Done)
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));
        assert!(!helper.driver.stream_map.contains_key(&stream_id));
        Ok(())
    }

    /// Test that calling `H3Controller::shutdown_stream` with
    /// `StreamShutdown::Both` sends both `RESET_STREAM` and `STOP_SENDING`
    /// frames to the peer.
    #[test]
    fn server_shutdown_stream_both_directions() -> TestResult {
        use crate::http3::driver::StreamShutdown;
        const READ_ERROR_CODE: u64 = 0xAAAA;
        const WRITE_ERROR_CODE: u64 = 0xBBBB;

        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;

        // client sends a request without fin
        let stream_id = helper
            .peer_client_send_request(&make_request_headers("POST"), false)?;

        // server reads request
        helper.advance_and_run_loop()?;
        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        let audit_stats = req.h3_audit_stats;

        // Server calls shutdown_stream with Both directions
        helper
            .controller
            .shutdown_stream(stream_id, StreamShutdown::Both {
                read_error_code: READ_ERROR_CODE,
                write_error_code: WRITE_ERROR_CODE,
            });

        helper.advance_and_run_loop()?;

        // Client should see STOP_SENDING when trying to send
        assert_eq!(
            helper.peer_client_send_body(0, &[1, 2, 3], false),
            Err(h3::Error::Transport(quiche::Error::StreamStopped(
                READ_ERROR_CODE
            )))
        );

        // Client should see RESET_STREAM when trying to receive
        assert_eq!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Reset(WRITE_ERROR_CODE)))
        );

        // Verify stats
        assert_eq!(
            audit_stats.sent_reset_stream_error_code(),
            Some(WRITE_ERROR_CODE)
        );
        assert_eq!(
            audit_stats.sent_stop_sending_error_code(),
            Some(READ_ERROR_CODE)
        );
        Ok(())
    }

    /// Verify that a GOAWAY received from the client does not affect
    /// in-flight response streams. The client sends GOAWAY with push
    /// ID 0 (the only value currently supported, since server push is
    /// not implemented). The server should surface the `GoAway` event
    /// and continue sending response data normally.
    ///
    /// Per RFC 9114 Section 5.2, when a client sends GOAWAY, the ID
    /// is a push ID indicating the range of pushes the client will
    /// accept. Since server push is unimplemented, the client always
    /// sends 0.
    #[test]
    fn server_receiving_goaway_keeps_connection_intact() -> TestResult {
        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;

        // Client sends a request.
        let stream_id = helper
            .peer_client_send_request(&make_request_headers("GET"), true)?;
        assert_eq!(stream_id, 0);

        // Server receives the request and starts a streaming response.
        helper.advance_and_run_loop()?;
        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers{incoming_headers, ..} => { incoming_headers }
        );
        assert_eq!(req.stream_id, stream_id);
        let to_client = req
            .send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .clone();
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))?;
        helper.advance_and_run_loop()?;

        // Client receives response headers.
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );

        // Server sends first body chunk.
        to_client.try_send(OutboundFrame::Body(
            Bytes::copy_from_slice(&[1; 10]),
            false,
        ))?;
        helper.advance_and_run_loop()?;

        // Client receives the first body chunk.
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![1; 10]));

        // Client sends GOAWAY with push ID 0 (graceful shutdown).
        helper.peer.send_goaway(&mut helper.pipe.client, 0)?;
        helper.advance_and_run_loop()?;

        // Server driver surfaces the GoAway event.
        loop {
            match helper.driver_recv_core_event()? {
                H3Event::GoAway { id } => {
                    assert_eq!(id, 0);
                    break;
                },
                H3Event::BodyBytesReceived { .. } |
                H3Event::StreamClosed { .. } => (),
                other =>
                    return Err(format!("unexpected event: {other:?}").into()),
            }
        }

        // Server continues sending response body — the connection is
        // still alive.
        to_client.try_send(OutboundFrame::Body(
            Bytes::copy_from_slice(&[2; 10]),
            false,
        ))?;
        helper.advance_and_run_loop()?;

        // Client still receives the data.
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![2; 10]));

        // Server finishes the response.
        to_client.try_send(OutboundFrame::Body(
            Bytes::copy_from_slice(&[3; 10]),
            true,
        ))?;
        helper.advance_and_run_loop()?;

        // Client receives the final chunk and fin.
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(helper.peer_client_recv_body_vec(0, 1024), Ok(vec![3; 10]));
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));
        Ok(())
    }

    // Test that dropping the H3 event receiver when there are no active streams
    // and datagram flows causes the connection to close immediately.
    #[test]
    fn h3_controller_drop_closes_connection_when_maps_empty() -> TestResult {
        let mut helper = DriverTestHelper::<ServerHooks>::new()?;
        helper.complete_handshake()?;

        assert!(helper.driver.stream_map.is_empty());
        assert!(helper.driver.flow_map.is_empty());
        assert!(helper.pipe.server.local_error().is_none());

        // drop the controller to trigger receiver drop detection
        drop(helper.controller);

        // run wait_for_data to detect the receiver drop
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();

        // connection closed with H3 NoError
        let local_error = helper
            .pipe
            .server
            .local_error()
            .ok_or("connection should be closing")?;
        assert!(local_error.is_app, "should be application-level close");
        assert_eq!(
            local_error.error_code,
            h3::WireErrorCode::NoError as u64,
            "should close with H3 NoError"
        );
        Ok(())
    }

    // Test that dropping the H3Controller when there are active streams/flows
    // does NOT close the connection immediately (e.g. tunnel scenarios).
    #[test]
    fn h3_controller_drop_keeps_connection_alive_when_streams_exist() -> TestResult
    {
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                quiche::test_utils::Pipe::with_config_and_buf(
                    &mut default_quiche_config()?,
                )?,
                &Http3Settings {
                    enable_extended_connect: true,
                    ..Default::default()
                },
            )?;
        helper.complete_handshake()?;
        helper.advance_and_run_loop()?;

        // CONNECT-UDP request creates both a stream and a datagram flow
        let connect_headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":authority", b"quic.tech"),
            h3::Header::new(b":path", b"/"),
            h3::Header::new(b":protocol", b"connect-udp"),
        ];
        helper.peer_client_send_request(&connect_headers, false)?;
        helper.advance_and_run_loop()?;

        // Consume events to keep channels alive
        assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Core(H3Event::NewFlow { .. })
        );
        assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers { .. }
        );

        assert_eq!(helper.driver.stream_map.len(), 1);
        assert_eq!(helper.driver.flow_map.len(), 1);

        drop(helper.controller);
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();

        // Connection stays open (stream and flow still active)
        assert!(helper.pipe.server.local_error().is_none());
        Ok(())
    }

    /// Test that a CONNECT request with `:protocol` does NOT create a
    /// datagram flow when extended CONNECT is disabled.
    #[test]
    fn protocol_without_extended_connect_closes_on_controller_drop() -> TestResult
    {
        // Default settings have enable_extended_connect: false
        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;

        // CONNECT with :protocol, but extended CONNECT is disabled
        let connect_headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":authority", b"quic.tech"),
            h3::Header::new(b":path", b"/"),
            h3::Header::new(b":protocol", b"webtransport"),
        ];
        helper.peer_client_send_request(&connect_headers, true)?;
        helper.advance_and_run_loop()?;

        // No NewFlow event — flow was not created
        assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers { .. }
        );

        assert_eq!(helper.driver.stream_map.len(), 1);
        assert_eq!(helper.driver.flow_map.len(), 0);

        // Drop controller, then run wait_for_data
        drop(helper.controller);
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();

        // Connection closes because stream_map and flow_map are empty
        let local_error = helper
            .pipe
            .server
            .local_error()
            .ok_or("connection should be closing")?;
        assert!(local_error.is_app, "should be application-level close");
        assert_eq!(
            local_error.error_code,
            h3::WireErrorCode::NoError as u64,
            "should close with H3 NoError"
        );
        Ok(())
    }

    /// Drop the event receiver with an open stream, then close the
    /// stream via client fin. Verify the connection closes.
    #[test]
    fn controller_drop_then_stream_close_triggers_connection_close() -> TestResult
    {
        let mut helper = DriverTestHelper::<ServerHooks>::ready()?;

        // Client sends a request the stream stays open
        let stream_id = helper
            .peer_client_send_request(&make_request_headers("GET"), false)?;

        helper.advance_and_run_loop()?;
        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers{incoming_headers, ..} => {
                incoming_headers
            }
        );
        assert_eq!(req.stream_id, stream_id);
        let to_client = req
            .send
            .get_ref()
            .ok_or("missing outbound stream sender")?
            .clone();

        // Send response headers + body with fin
        to_client
            .try_send(OutboundFrame::Headers(make_response_headers(), None))?;
        helper.advance_and_run_loop()?;
        to_client
            .try_send(OutboundFrame::Body(Bytes::from_static(b"ok"), true))?;
        helper.advance_and_run_loop()?;

        assert_eq!(helper.driver.stream_map.len(), 1);

        // Drop the stream channels so cleanup_stream can remove
        // the stream from the map
        drop(to_client);
        drop(req);

        // Client reads response and sends fin to close the stream
        helper.advance_and_run_loop()?;
        assert_matches!(
            helper.peer_client_poll(),
            Ok((0, h3::Event::Headers { .. }))
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Data)));
        assert_eq!(
            helper.peer_client_recv_body_vec(0, 1024),
            Ok(vec![111, 107])
        );
        assert_eq!(helper.peer_client_poll(), Ok((0, h3::Event::Finished)));

        // Drop the controller
        drop(helper.controller);
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();

        // Connection should NOT close yet (stream still open)
        assert!(helper.pipe.server.local_error().is_none());

        // Client sends fin to close the stream
        assert_eq!(
            helper
                .peer
                .send_body(&mut helper.pipe.client, 0, b"done", true,),
            Ok(4)
        );
        // One IO worker iteration: deliver client fin, process it,
        // and close the connection.
        helper.pipe.advance()?;
        helper.driver.process_reads(&mut helper.pipe.server)?;
        helper.driver.process_writes(&mut helper.pipe.server)?;
        tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();

        assert_eq!(helper.driver.stream_map.len(), 0);

        // Now the connection should close with NoError
        let local_error = helper
            .pipe
            .server
            .local_error()
            .ok_or("connection should be closing")?;
        assert!(local_error.is_app, "should be application-level close");
        assert_eq!(
            local_error.error_code,
            h3::WireErrorCode::NoError as u64,
            "should close with H3 NoError"
        );
        Ok(())
    }

    fn datagram_helper() -> anyhow::Result<DriverTestHelper<ServerHooks>> {
        let mut config = default_quiche_config()?;
        config.enable_dgram(true, 100, 100);
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                quiche::test_utils::Pipe::with_config_and_buf(&mut config)?,
                &Http3Settings {
                    enable_extended_connect: true,
                    ..Http3Settings::default()
                },
            )?;
        helper.complete_handshake()?;
        helper.advance_and_run_loop()?;
        Ok(helper)
    }

    fn open_datagram_request(
        helper: &mut DriverTestHelper<ServerHooks>,
    ) -> anyhow::Result<(
        DatagramFlowSender,
        mpsc::Receiver<datagram_socket::DgramBuffer>,
        IncomingH3Headers,
    )> {
        let mut headers = make_request_headers("CONNECT");
        headers.push(h3::Header::new(b":protocol", b"connect-udp"));
        let request_stream_id =
            helper.peer_client_send_request(&headers, false)?;
        helper.advance_and_run_loop()?;
        let (send, recv) = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Core(H3Event::NewFlow { stream_id, send, recv }) => {
                assert_eq!(stream_id, request_stream_id);
                assert_eq!(send.stream_id(), stream_id);
                (send, recv)
            }
        );
        let headers = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers { incoming_headers, .. } => incoming_headers
        );
        assert_eq!(headers.stream_id, request_stream_id);
        Ok((send, recv, headers))
    }

    #[test]
    fn datagrams_before_headers_do_not_create_autonomous_flows(
    ) -> anyhow::Result<()> {
        let mut helper = datagram_helper()?;
        for prefix in 0..32 {
            helper.pipe.client.dgram_send(&[prefix, 0xaa])?;
        }
        helper.advance_and_run_loop()?;
        assert!(helper.driver.flow_map.is_empty());
        assert!(helper.driver.stream_map.is_empty());
        assert!(helper.driver_recv_server_event().is_err());

        let (send, mut recv, _headers) = open_datagram_request(&mut helper)?;
        assert_eq!(send.stream_id(), 0);
        assert_eq!(recv.try_recv().err(), Some(TryRecvError::Empty));
        helper.pipe.client.dgram_send(b"\x00hello")?;
        helper.advance_and_run_loop()?;
        assert_eq!(recv.try_recv()?.as_slice(), b"hello");
        Ok(())
    }

    #[test]
    fn flow_shutdown_does_not_wait_for_saturated_datagram_queue(
    ) -> anyhow::Result<()> {
        let mut helper = datagram_helper()?;
        let (send, _recv, _headers) = open_datagram_request(&mut helper)?;
        drop(helper.controller);
        let _ = tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();
        assert!(helper.pipe.server.local_error().is_none());

        for _ in 0..FLOW_CAPACITY {
            send.try_send(datagram_socket::DgramBuffer::from_slice(b"queued"))?;
        }
        assert!(matches!(
            send.try_send(datagram_socket::DgramBuffer::new()),
            Err(TrySendError::Full(_))
        ));
        send.shutdown()?;
        let _ = tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();
        assert!(helper.driver.stream_map.is_empty());
        assert!(helper.driver.flow_map.is_empty());
        assert_eq!(helper.pipe.server.dgram_send_queue_len(), 0);
        assert_eq!(
            helper
                .pipe
                .server
                .local_error()
                .map(|error| (error.is_app, error.error_code)),
            Some((true, h3::WireErrorCode::NoError as u64))
        );
        Ok(())
    }

    #[test]
    fn datagram_directions_follow_stream_halves_and_purge_stale_egress(
    ) -> anyhow::Result<()> {
        let mut helper = datagram_helper()?;
        let (send, mut recv, _headers) = open_datagram_request(&mut helper)?;
        let stream_id = send.stream_id();
        send.try_send(datagram_socket::DgramBuffer::from_slice(b"response"))?;
        helper.advance_and_run_loop()?;
        assert_eq!(
            helper.pipe.client.dgram_recv_buf()?.as_slice(),
            b"\x00response"
        );

        helper.peer_client_send_body(stream_id, b"", true)?;
        helper.advance_and_run_loop()?;
        assert_eq!(recv.try_recv().err(), Some(TryRecvError::Disconnected));
        assert!(helper.driver.flow_map.contains_key(&stream_id));

        // The opposite direction remains open even after peer FIN.
        send.try_send(datagram_socket::DgramBuffer::from_slice(b"still open"))?;
        let _ = tokio::task::unconstrained(
            helper.driver.wait_for_data(&mut helper.pipe.server),
        )
        .now_or_never();
        assert_eq!(helper.pipe.server.dgram_send_queue_len(), 1);
        helper.driver.shutdown_stream(
            &mut helper.pipe.server,
            stream_id,
            StreamShutdown::Write { error_code: 0 },
        )?;
        assert_eq!(helper.pipe.server.dgram_send_queue_len(), 0);
        assert!(!helper.driver.flow_map.contains_key(&stream_id));

        // A retained sender cannot recreate a closed stream or target a
        // different request.
        send.try_send(datagram_socket::DgramBuffer::from_slice(b"stale"))?;
        send.shutdown()?;
        helper.advance_and_run_loop()?;
        assert_eq!(helper.pipe.server.dgram_send_queue_len(), 0);
        assert!(helper.driver.flow_map.is_empty());
        Ok(())
    }

    #[test]
    fn datagram_on_normal_request_aborts_only_that_request() -> anyhow::Result<()>
    {
        let mut helper = datagram_helper()?;
        let stream_id = helper
            .peer_client_send_request(&make_request_headers("GET"), false)?;
        helper.advance_and_run_loop()?;
        let req = assert_matches!(
            helper.driver_recv_server_event()?,
            ServerH3Event::Headers { incoming_headers, .. } => incoming_headers
        );
        helper.pipe.client.dgram_send(b"\x00unexpected")?;
        helper.advance_and_run_loop()?;
        assert_eq!(
            req.h3_audit_stats.sent_reset_stream_error_code(),
            Some(datagram::DATAGRAM_ERROR)
        );
        assert_eq!(
            req.h3_audit_stats.sent_stop_sending_error_code(),
            Some(datagram::DATAGRAM_ERROR)
        );
        assert!(!helper.driver.stream_map.contains_key(&stream_id));
        assert!(helper.pipe.server.local_error().is_none());
        Ok(())
    }

    #[test]
    fn malformed_datagram_prefix_closes_connection_with_datagram_error(
    ) -> anyhow::Result<()> {
        let mut oversized = [0; 8];
        octets::OctetsMut::with_slice(&mut oversized)
            .put_varint(octets::MAX_VAR_INT / 4 + 1)?;
        for invalid in [&[0xc0][..], oversized.as_slice()] {
            let mut helper = datagram_helper()?;
            helper.pipe.client.dgram_send(invalid)?;
            helper.pipe.advance()?;
            let result = helper.driver.process_reads(&mut helper.pipe.server);
            let error = result
                .err()
                .ok_or_else(|| anyhow::anyhow!("invalid datagram accepted"))?;
            assert_eq!(
                error.downcast_ref::<H3ConnectionError>(),
                Some(&H3ConnectionError::InvalidDatagram)
            );
            assert_eq!(
                helper
                    .pipe
                    .server
                    .local_error()
                    .map(|error| (error.is_app, error.error_code)),
                Some((true, datagram::DATAGRAM_ERROR))
            );
        }
        Ok(())
    }

    /// Verify that datagrams are silently dropped and no flow is
    /// created when extended connect is disabled.
    #[test]
    fn process_dgram_skips_flow_creation_when_extended_connect_disabled(
    ) -> TestResult {
        let mut config = default_quiche_config()?;
        config.enable_dgram(true, 100, 100);

        // Default settings have enable_extended_connect: false
        let mut helper =
            DriverTestHelper::<ServerHooks>::with_pipe_and_http3_settings(
                quiche::test_utils::Pipe::with_config_and_buf(&mut config)?,
                &Http3Settings::default(),
            )?;
        helper.complete_handshake()?;
        helper.advance_and_run_loop()?;

        let flow_id: u64 = 8;
        let payload: &[u8] = b"hi";
        let prefix_len = octets::varint_len(flow_id);
        let mut wire = vec![0u8; prefix_len + payload.len()];
        {
            let mut enc = octets::OctetsMut::with_slice(&mut wire);
            enc.put_varint(flow_id)?;
            enc.put_bytes(payload)?;
        }
        helper.pipe.client.dgram_send(&wire)?;

        helper.advance_and_run_loop()?;

        // No flow should be created
        assert!(
            helper.driver.flow_map.is_empty(),
            "flow_map should remain empty when extended connect is disabled"
        );
        Ok(())
    }
}
