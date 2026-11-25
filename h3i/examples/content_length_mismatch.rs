use h3i::actions::h3::Action;
use h3i::actions::h3::StreamEvent;
use h3i::actions::h3::StreamEventType;
use h3i::actions::h3::WaitType;
use h3i::client::sync_client;
use h3i::config::Config;
use quiche::h3::frame::Frame;
use quiche::h3::Header;

/// The QUIC stream to send the frames on. See
/// https://datatracker.ietf.org/doc/html/rfc9000#name-streams and
/// https://datatracker.ietf.org/doc/html/rfc9114#request-streams for more.
const STREAM_ID: u64 = 0;

/// Send a request with a Content-Length header that specifies 5 bytes, but a
/// body that is only 4 bytes long. This verifies https://datatracker.ietf.org/doc/html/rfc9114#section-4.1.2-3 for
/// cloudflare-quic.com.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new("cloudflare-quic.com")?;
    config.idle_timeout = 2000;

    let headers = vec![
        Header::new(b":method", b"POST"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", b"cloudflare-quic.com"),
        Header::new(b":path", b"/"),
        // We say that we're going to send a body with 5 bytes...
        Header::new(b"content-length", b"5"),
    ];

    let header_block = encode_header_block(&headers)?;

    let actions = vec![
        Action::SendHeadersFrame {
            stream_id: STREAM_ID,
            fin_stream: false,
            headers,
            literal_headers: false,
            frame: Frame::Headers { header_block },
            expected_result: Default::default(),
        },
        Action::SendFrame {
            stream_id: STREAM_ID,
            fin_stream: true,
            frame: Frame::Data {
                // ...but, in actuality, we only send 4 bytes. This should yield
                // a 400 Bad Request response from an RFC-compliant
                // server: https://datatracker.ietf.org/doc/html/rfc9114#section-4.1.2-3
                payload: b"test".to_vec(),
            },
            expected_result: Default::default(),
        },
        Action::Wait {
            wait_type: WaitType::StreamEvent(StreamEvent {
                stream_id: STREAM_ID,
                event_type: StreamEventType::Headers,
            }),
        },
        Action::ConnectionClose {
            error: quiche::ConnectionError {
                is_app: true,
                error_code: quiche::h3::WireErrorCode::NoError as u64,
                reason: vec![],
            },
        },
    ];

    // This example needs no close-trigger frames because it closes the
    // connection after receiving HEADERS on stream 0.
    let close_trigger_frames = None;

    let summary = sync_client::connect(config, actions, close_trigger_frames)?;

    println!(
        "=== received connection summary! ===\n\n{}",
        serde_json::to_string_pretty(&summary)?
    );
    Ok(())
}

// SendHeadersFrame requires a QPACK-encoded header block. h3i provides a
// `send_headers_frame` helper function to abstract this, but for clarity, we do
// it here.
fn encode_header_block(
    headers: &[quiche::h3::Header],
) -> std::result::Result<Vec<u8>, String> {
    quiche::h3::qpack::encode(headers).map_err(|e| e.to_string())
}
