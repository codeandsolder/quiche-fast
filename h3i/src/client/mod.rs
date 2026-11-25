// Copyright (C) 2024, Cloudflare, Inc.
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

//! The main h3i client runner.
//!
//! The client is responsible for connecting to an indicated server, executing
//! a series of [`Action`]s, and capturing the results in a
//! [`connection_summary::ConnectionSummary`].

mod action_queue;
#[cfg(feature = "async")]
pub mod async_client;
pub mod connection_summary;
pub mod sync_client;
mod sync_io;

use connection_summary::CloseTriggerFrames;
use connection_summary::ConnectionSummary;
use connection_summary::StreamMap;
use qlog::events::http3::FrameParsed;
use qlog::events::http3::HttpHeader;
use quiche::ConnectionError;

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::actions::h3::Action;
use crate::actions::h3::ExpectedStreamSendResult;
use crate::actions::h3::StreamEvent;
use crate::actions::h3::StreamEventType;
use crate::config::Config;
use crate::frame::H3iFrame;
use crate::frame::ResetStream;
use crate::frame_parser::FrameParseResult;
use crate::frame_parser::FrameParser;
use crate::frame_parser::InterruptCause;
use crate::recordreplay::qlog::QlogEvent;
use qlog::events::http3::Http3Frame;
use qlog::events::EventData;
use qlog::streamer::QlogStreamer;
use serde::Serialize;

use crate::quiche;
use quiche::h3::frame::Frame as QFrame;
use quiche::h3::Error;
use quiche::h3::NameValue;

const MAX_DATAGRAM_SIZE: usize = 1350;
const QUIC_VERSION: u32 = 1;

fn handle_qlog(
    streamer: &mut QlogStreamer, qlog_frame: Http3Frame, stream_id: u64,
) {
    let ev_data = EventData::Http3FrameParsed(FrameParsed {
        stream_id,
        frame: qlog_frame,
        ..FrameParsed::default()
    });
    if let Err(error) = streamer.add_event_data_now(ev_data) {
        log::warn!("cannot record received frame: {error}");
    }
}

#[derive(Debug, Serialize)]
/// Represents different errors that can occur when the h3i client runs.
pub enum ClientError {
    /// An error during the QUIC handshake.
    HandshakeFail,
    /// An error during HTTP/3 exchanges.
    HttpFail,
    /// Some other type of error.
    Other(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HandshakeFail => formatter.write_str("QUIC handshake failed"),
            Self::HttpFail => formatter.write_str("HTTP/3 exchange failed"),
            Self::Other(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ClientError {}

pub(crate) type StreamParserMap = HashMap<u64, FrameParser>;

/// Shared receive state for both transports.
pub(crate) struct ClientState {
    pub(crate) streams: StreamMap,
    pub(crate) parsers: StreamParserMap,
}

impl ClientState {
    pub(crate) fn new(close_triggers: Option<CloseTriggerFrames>) -> Self {
        Self {
            streams: StreamMap::new(close_triggers),
            parsers: StreamParserMap::default(),
        }
    }
}

fn validate_stream_send_result(
    result: quiche::Result<usize>, expected: &ExpectedStreamSendResult,
    stream_id: u64,
) -> std::result::Result<(), String> {
    let matches = match (expected, &result) {
        (ExpectedStreamSendResult::Ok, Ok(_)) => true,
        (ExpectedStreamSendResult::OkExact(expected), Ok(actual)) =>
            expected == actual,
        (ExpectedStreamSendResult::Error(expected), Err(actual)) =>
            expected == actual,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(format!(
            "stream {stream_id}: expected {expected:?}, got {result:?}"
        ))
    }
}

fn record_frame_action<F: quiche::BufFactory>(
    action: &Action, conn: &mut quiche::Connection<F>,
) {
    if let Some(s) = conn.qlog_streamer() {
        match QlogEvent::try_from(action) {
            Ok(event) =>
                if let Err(error) = event.write(s) {
                    log::warn!("cannot write action: {error}");
                },
            Err(error) => log::warn!("cannot record action: {error}"),
        }
    }
}

fn send_stream_action<F: quiche::BufFactory>(
    conn: &mut quiche::Connection<F>, stream_parsers: &mut StreamParserMap,
    stream_id: u64, fin_stream: bool, bytes: &[u8],
    expected_result: &ExpectedStreamSendResult,
) -> std::result::Result<(), String> {
    let result = conn.stream_send(stream_id, bytes, fin_stream);
    validate_stream_send_result(result, expected_result, stream_id)?;
    if result.is_ok() {
        stream_parsers
            .entry(stream_id)
            .or_insert_with(|| FrameParser::new(stream_id));
    }
    Ok(())
}

fn encode_frame_action(action: &Action) -> std::result::Result<Vec<u8>, String> {
    match action {
        Action::SendFrame { frame, .. } =>
            frame.to_vec().map_err(|err| err.to_string()),
        Action::SendHeadersFrame {
            headers,
            literal_headers,
            ..
        } => {
            let header_block = if *literal_headers {
                crate::encode_header_block_literal(headers)
            } else {
                crate::encode_header_block(headers)
            }?;
            QFrame::Headers { header_block }
                .to_vec()
                .map_err(|err| err.to_string())
        },
        _ => Err("action does not contain an HTTP/3 frame".into()),
    }
}

pub(crate) fn execute_action<F: quiche::BufFactory>(
    action: &Action, conn: &mut quiche::Connection<F>,
    stream_parsers: &mut StreamParserMap,
) -> std::result::Result<(), String> {
    match action {
        Action::SendFrame {
            stream_id,
            fin_stream,
            expected_result,
            ..
        } |
        Action::SendHeadersFrame {
            stream_id,
            fin_stream,
            expected_result,
            ..
        } => {
            let bytes = encode_frame_action(action)?;
            record_frame_action(action, conn);
            send_stream_action(
                conn,
                stream_parsers,
                *stream_id,
                *fin_stream,
                &bytes,
                expected_result,
            )
        },
        Action::OpenUniStream {
            stream_id,
            fin_stream,
            stream_type,
            expected_result,
        } => {
            let mut bytes = [0; 8];
            let encoded = octets::OctetsMut::with_slice(&mut bytes)
                .put_varint(*stream_type)
                .map_err(|err| err.to_string())?
                .len();
            send_stream_action(
                conn,
                stream_parsers,
                *stream_id,
                *fin_stream,
                &bytes[..encoded],
                expected_result,
            )
        },
        Action::StreamBytes {
            stream_id,
            bytes,
            fin_stream,
            expected_result,
        } => send_stream_action(
            conn,
            stream_parsers,
            *stream_id,
            *fin_stream,
            bytes,
            expected_result,
        ),
        Action::SendDatagram { payload } =>
            conn.dgram_send(payload).map_err(|err| err.to_string()),
        Action::ResetStream {
            stream_id,
            error_code,
        } => shutdown_stream(
            conn,
            stream_parsers,
            *stream_id,
            *error_code,
            quiche::Shutdown::Write,
        ),
        Action::StopSending {
            stream_id,
            error_code,
        } => shutdown_stream(
            conn,
            stream_parsers,
            *stream_id,
            *error_code,
            quiche::Shutdown::Read,
        ),
        Action::ConnectionClose { error } => {
            let ConnectionError {
                is_app,
                error_code,
                reason,
            } = error;
            let _ = conn.close(*is_app, *error_code, reason);
            Ok(())
        },
        Action::FlushPackets | Action::Wait { .. } =>
            Err("scheduler action passed to the stream executor".into()),
    }
}

fn shutdown_stream<F: quiche::BufFactory>(
    conn: &mut quiche::Connection<F>, parsers: &mut StreamParserMap,
    stream_id: u64, error_code: u64, direction: quiche::Shutdown,
) -> Result<(), String> {
    conn.stream_shutdown(stream_id, direction, error_code)
        .map_err(|error| {
            let side = match direction {
                quiche::Shutdown::Read => "read",
                quiche::Shutdown::Write => "write",
            };
            format!("stream {stream_id} shutdown {side}: {error}")
        })?;
    parsers
        .entry(stream_id)
        .or_insert_with(|| FrameParser::new(stream_id));
    Ok(())
}

pub(crate) fn parse_streams<F: quiche::BufFactory>(
    conn: &mut quiche::Connection<F>, client: &mut ClientState,
) -> Vec<StreamEvent> {
    let mut responded_streams: Vec<StreamEvent> =
        Vec::with_capacity(conn.readable().len());

    for stream in conn.readable() {
        // TODO: ignoring control streams
        if stream % 4 != 0 {
            continue;
        }

        loop {
            let stream_parse_result = client
                .parsers
                .entry(stream)
                .or_insert_with(|| FrameParser::new(stream))
                .try_parse_frame(conn);

            match stream_parse_result {
                Ok(FrameParseResult::FrameParsed { h3i_frame, fin }) => {
                    if let H3iFrame::Headers(ref headers) = h3i_frame {
                        log::info!("hdrs={headers:?}");
                    }

                    handle_response_frame(
                        client,
                        conn.qlog_streamer(),
                        &mut responded_streams,
                        stream,
                        h3i_frame,
                    );

                    if fin {
                        handle_fin(
                            &mut responded_streams,
                            &mut client.parsers,
                            stream,
                        );
                        break;
                    }
                },
                Ok(FrameParseResult::Interrupted(cause)) => {
                    if let InterruptCause::ResetStream(error_code) = cause {
                        let frame = H3iFrame::ResetStream(ResetStream {
                            stream_id: stream,
                            error_code,
                        });

                        log::info!("received reset stream: {frame:?}");
                        handle_response_frame(
                            client,
                            None,
                            &mut responded_streams,
                            stream,
                            frame,
                        );
                    }

                    handle_fin(
                        &mut responded_streams,
                        &mut client.parsers,
                        stream,
                    );
                    break;
                },
                Err(e) => {
                    match e {
                        Error::Done => {
                            log::debug!("stream {stream} exhausted");
                        },
                        _ => {
                            log::warn!("stream read error: {e}");
                        },
                    }

                    break;
                },
            }
        }
    }

    responded_streams
}

fn handle_fin(
    responded_streams: &mut Vec<StreamEvent>,
    stream_parsers: &mut StreamParserMap, stream_id: u64,
) {
    responded_streams.push(StreamEvent {
        stream_id,
        event_type: StreamEventType::Finished,
    });

    stream_parsers.remove(&stream_id);
}

/// Record a response and notify the action scheduler without cloning its
/// payload.
fn handle_response_frame(
    client: &mut ClientState, qlog_streamer: Option<&mut QlogStreamer>,
    responded_streams: &mut Vec<StreamEvent>, stream_id: u64, frame: H3iFrame,
) {
    let event_type = match &frame {
        H3iFrame::Headers(_) => Some(StreamEventType::Headers),
        H3iFrame::QuicheH3(QFrame::Data { .. }) => Some(StreamEventType::Data),
        H3iFrame::ResetStream(_) | H3iFrame::QuicheH3(_) => None,
    };
    if let Some(event_type) = event_type {
        responded_streams.push(StreamEvent {
            stream_id,
            event_type,
        });
    }
    if let Some(streamer) = qlog_streamer {
        let frame = match &frame {
            H3iFrame::Headers(headers) => Some(Http3Frame::Headers {
                headers: headers
                    .headers()
                    .iter()
                    .map(|header| HttpHeader {
                        name: Some(
                            String::from_utf8_lossy(header.name()).into_owned(),
                        ),
                        name_bytes: None,
                        value: Some(
                            String::from_utf8_lossy(header.value()).into_owned(),
                        ),
                        value_bytes: None,
                    })
                    .collect(),
                raw: None,
            }),
            H3iFrame::QuicheH3(frame) => Some(frame.to_qlog()),
            H3iFrame::ResetStream(_) => None,
        };
        if let Some(frame) = frame {
            handle_qlog(streamer, frame, stream_id);
        }
    }
    client.streams.insert(stream_id, frame);
}

pub(crate) struct ParsedArgs<'a> {
    pub(crate) bind_addr: SocketAddr,
    pub(crate) peer_addr: SocketAddr,
    pub(crate) connect_url: Option<&'a str>,
}

pub(crate) fn parse_args(
    args: &Config,
) -> std::result::Result<ParsedArgs<'_>, ClientError> {
    args.validate()
        .map_err(|error| ClientError::Other(error.to_string()))?;
    let (peer_addr, bind_addr) =
        args.endpoint.socket_addresses().map_err(|error| {
            ClientError::Other(format!("resolve server: {error}"))
        })?;
    Ok(ParsedArgs {
        peer_addr,
        bind_addr,
        connect_url: (!args.tls.omit_sni).then(|| args.endpoint.host()),
    })
}

#[cfg(test)]
mod action_tests {
    use super::encode_frame_action;
    use super::validate_stream_send_result;
    use crate::actions::h3::send_headers_frame_literal;
    use crate::actions::h3::Action;
    use crate::actions::h3::ExpectedStreamSendResult;
    use crate::quiche;
    use quiche::h3::frame::Frame;
    use quiche::h3::Header;

    #[test]
    fn encodes_large_frames_without_fixed_buffer() -> Result<(), String> {
        let frame = Frame::Data {
            payload: vec![0x35; 65_536],
        };
        let action = Action::SendFrame {
            stream_id: 0,
            fin_stream: false,
            frame: frame.clone(),
            expected_result: ExpectedStreamSendResult::Ok,
        };
        assert_eq!(
            encode_frame_action(&action)?,
            frame.to_vec().map_err(|err| err.to_string())?
        );
        Ok(())
    }

    #[test]
    fn headers_encoded_from_authoritative_fields() -> Result<(), String> {
        let headers = vec![Header::new(b"X-Test", b"value")];
        let action = send_headers_frame_literal(0, false, headers.clone());
        let block = quiche::h3::qpack::encode_literal(&headers)
            .map_err(|err| err.to_string())?;
        let frame = Frame::Headers {
            header_block: block,
        };
        assert_eq!(
            encode_frame_action(&action)?,
            frame.to_vec().map_err(|err| err.to_string())?
        );
        Ok(())
    }

    #[test]
    fn mismatches_are_errors_not_panics() {
        use ExpectedStreamSendResult::Error;
        use ExpectedStreamSendResult::Ok as Any;
        use ExpectedStreamSendResult::OkExact;
        assert!(validate_stream_send_result(Ok(1), &Any, 0).is_ok());
        assert!(validate_stream_send_result(Ok(1), &OkExact(1), 0).is_ok());
        assert!(validate_stream_send_result(Ok(1), &OkExact(2), 0).is_err());
        assert!(
            validate_stream_send_result(Err(quiche::Error::Done), &Any, 0)
                .is_err()
        );
        assert!(validate_stream_send_result(
            Err(quiche::Error::Done),
            &Error(quiche::Error::Done),
            0
        )
        .is_ok());
        assert!(validate_stream_send_result(
            Ok(1),
            &Error(quiche::Error::Done),
            0
        )
        .is_err());
    }
}
