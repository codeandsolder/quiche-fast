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

use crate::body::ExampleBody;
use futures_util::Future;
use futures_util::SinkExt;
use http::request;
use http::uri::PathAndQuery;
use http::uri::{
    self,
};
use http::HeaderName;
use http::HeaderValue;
use http::Request;
use http::Response;
use http::Uri;
use quiche::h3::Header;
use quiche::h3::NameValue;
use std::sync::Arc;
use tokio_quiche::http3::driver::H3Command;
use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::OutboundFrameSender;
use tokio_quiche::http3::driver::RequestSender;
use tokio_quiche::http3::driver::ServerH3Command;
use tokio_quiche::http3::driver::ServerH3Controller;
use tokio_quiche::http3::driver::StreamShutdown;

type StreamCommands = RequestSender<ServerH3Command, H3Command>;
use tokio_quiche::http3::driver::ServerH3Event;
use tokio_quiche::QuicResult;

/// A simple [service function].
///
/// If the request's path follows the form `/stream-bytes/<num_bytes>`, the
/// response will come with a body that is `num_bytes` long.
///
/// For example, `https://test.com/stream-bytes/57` will return a 200 response with a body that is
/// 57 bytes long.
///
/// [service function]: https://docs.rs/hyper/latest/hyper/service/index.html
pub async fn service_fn(req: Request<()>) -> Response<ExampleBody> {
    let body = ExampleBody::new(&req);
    Response::new(body)
}

/// A basic asynchronous HTTP/3 server served by tokio-quiche.
///
/// Note that this is simply an example, and **should not be run in
/// production**. This merely shows how one could use tokio-quiche to write an
/// HTTP/3 server.
pub struct Server<S, R>
where
    S: Fn(Request<()>) -> R + Send + Sync + 'static,
{
    service_fn: Arc<S>,
}

impl<S, R> Server<S, R>
where
    S: Fn(Request<()>) -> R + Send + Sync + 'static,
    R: Future<Output = Response<ExampleBody>> + Send + 'static,
{
    /// Create the server by registering a [service function].
    ///
    /// [service function]: https://docs.rs/hyper/latest/hyper/service/index.html
    pub fn new(service_fn: S) -> Self {
        Self {
            service_fn: Arc::new(service_fn),
        }
    }

    /// Serve the connection.
    ///
    /// The [`Server`] will listen for [`ServerH3Event`]s, process them, and
    /// send response data back to tokio-quiche for quiche-side processing
    /// and flushing.
    ///
    /// tokio-quiche's `H3Driver` emits these events in response to data that
    /// comes off the underlying socket.
    pub async fn serve_connection(
        &self, controller: &mut ServerH3Controller,
    ) -> QuicResult<()> {
        let commands = controller.h3_cmd_sender();
        loop {
            match controller.event_receiver_mut().recv().await {
                Some(event) => self.handle_server_h3_event(event, &commands)?,
                None => return Ok(()), /* The sender was dropped, implying
                                        * connection was terminated */
            }
        }
    }

    /// Handle a [`H3Event`].
    ///
    /// For simplicity's sake, we only handle a couple of events here.
    fn handle_h3_event(event: &H3Event) -> QuicResult<()> {
        match event {
            H3Event::ConnectionError(error) => Err(Box::new(*error)),
            H3Event::ConnectionShutdown(Some(error)) => Err(Box::new(*error)),
            H3Event::ConnectionShutdown(None) => Ok(()),
            _ => {
                tracing::info!("received unhandled event: {event:?}");
                Ok(())
            },
        }
    }

    /// Handle a [`ServerH3Event`].
    ///
    /// TODO(evanrittenhouse): support POST requests
    fn handle_server_h3_event(
        &self, event: ServerH3Event, commands: &StreamCommands,
    ) -> QuicResult<()> {
        match event {
            ServerH3Event::Core(event) => Self::handle_h3_event(&event),

            ServerH3Event::Headers {
                incoming_headers, ..
            } => {
                // Received headers for a new stream from the H3Driver.
                self.handle_incoming_headers(incoming_headers, commands);
                Ok(())
            },
        }
    }

    /// Respond to the request corresponding to the [`IncomingH3Headers`].
    ///
    /// This function transforms the incoming headers into a [`Request`],
    /// creating the proper response body if requested. It then spawns a
    /// Tokio task which calls the `service_fn` on the [`Request`].
    fn handle_incoming_headers(
        &self, headers: IncomingH3Headers, commands: &StreamCommands,
    ) {
        tracing::info!("received headers: {headers:?}");

        let IncomingH3Headers {
            headers: list,
            stream_id,
            send: frame_sender,
            ..
        } = headers;

        let Ok((uri_builder, req_builder)) = convert_headers(list) else {
            Self::end_stream(commands, stream_id);
            return;
        };

        let Ok(uri) = uri_builder.build() else {
            Self::end_stream(commands, stream_id);
            return;
        };
        let Ok(req) = req_builder.uri(uri).body(()) else {
            Self::end_stream(commands, stream_id);
            return;
        };

        let service_fn = Arc::clone(&self.service_fn);

        let commands = commands.clone();
        tokio::spawn(async move {
            Self::handle_request(
                service_fn,
                req,
                frame_sender,
                &commands,
                stream_id,
            )
            .await;
        });
    }

    /// Get a [`Response`] for a [`Request`] by calling the `service_fn`.
    ///
    /// The `frame_sender` parameter connects back to tokio-quiche `H3Driver`,
    /// which communicates the data back to quiche.
    async fn handle_request(
        service_fn: Arc<S>, req: Request<()>,
        mut frame_sender: OutboundFrameSender, commands: &StreamCommands,
        stream_id: u64,
    ) {
        let res = service_fn(req).await;

        // Convert the result of the `service_fn` into headers and a body which
        // can be transmitted to tokio-quiche.
        let (h3_headers, body) = convert_response(res);
        if frame_sender
            .send(OutboundFrame::Headers(h3_headers, None))
            .await
            .is_err()
        {
            Self::end_stream(commands, stream_id);
            return;
        }
        if body.send(frame_sender).await.is_none() {
            Self::end_stream(commands, stream_id);
        }
    }

    /// Abort both directions through the independent control channel.
    fn end_stream(commands: &StreamCommands, stream_id: u64) {
        let code = quiche::h3::WireErrorCode::MessageError as u64;
        let _ = commands.send(H3Command::ShutdownStream {
            stream_id,
            shutdown: StreamShutdown::Both {
                read_error_code: code,
                write_error_code: code,
            },
        });
    }
}

/// Convert a list of [Header]s into a request object which can be processed by
/// the [`Server`].
///
/// This serves as an example, and does not ensure HTTP semantics by any means.
/// For example, this will not ensure that required pseudo-headers are present,
/// nor will it detect duplicate pseudo-headers.
fn convert_headers(
    headers: Vec<Header>,
) -> QuicResult<(uri::Builder, request::Builder)> {
    let mut req_builder = Request::builder();
    let mut uri_builder = Uri::builder();

    for header in headers {
        let name = header.name();
        let value = header.value();

        let Some(&first) = name.first() else {
            tracing::warn!("received header with no or invalid first character");
            continue;
        };

        if first == b':' {
            match name {
                b":method" => {
                    req_builder = req_builder.method(value);
                },
                b":scheme" => {
                    uri_builder = uri_builder.scheme(value);
                },
                b":authority" => {
                    let host = HeaderValue::from_bytes(value)?;
                    uri_builder = uri_builder.authority(host.as_bytes());
                    req_builder.headers_mut().map(|h| h.insert("host", host));
                },
                b":path" => {
                    let path = PathAndQuery::try_from(value)?;
                    uri_builder = uri_builder.path_and_query(path);
                },
                _ => {
                    tracing::warn!("received unknown pseudo-header: {name:?}");
                },
            }
        } else {
            let name = HeaderName::from_bytes(name)?;
            let value = HeaderValue::from_bytes(value)?;
            if let Some(headers) = req_builder.headers_mut() {
                headers.append(name, value);
            }
        }
    }

    Ok((uri_builder, req_builder))
}

/// Convert a [`Response`] into headers and a body, readable by tokio-quiche.
fn convert_response<B>(res: Response<B>) -> (Vec<Header>, B) {
    let mut h3_headers =
        vec![Header::new(b":status", res.status().as_str().as_bytes())];

    for (name, value) in res.headers() {
        h3_headers.push(Header::new(name.as_ref(), value.as_bytes()));
    }

    (h3_headers, res.into_body())
}
