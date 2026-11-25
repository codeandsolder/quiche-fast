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

use futures::SinkExt;

use tokio_quiche::http3::driver::H3Event;
use tokio_quiche::http3::driver::IncomingH3Headers;
use tokio_quiche::http3::driver::OutboundFrame;
use tokio_quiche::http3::driver::ServerH3Event;
use tokio_quiche::quiche::h3::Header;

#[tokio::test]
async fn test_additional_headers() -> QuicResult<()> {
    let hook = TestConnectionHook::new();

    let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
    let completion_tx =
        std::sync::Arc::new(std::sync::Mutex::new(Some(completion_tx)));
    let (url, _) = start_server_with_settings(
        QuicSettings::default(),
        Http3Settings::default(),
        hook,
        move |mut h3_conn| {
            let completion_tx = completion_tx.clone();
            async move {
                let result: QuicResult<()> = async {
                    let event_rx = h3_conn.h3_controller.event_receiver_mut();

                    while let Some(event) = event_rx.recv().await {
                        match event {
                            ServerH3Event::Core(event) =>
                                if let H3Event::ConnectionShutdown(_) = event {
                                    break;
                                },

                            ServerH3Event::Headers {
                                incoming_headers, ..
                            } => {
                                let IncomingH3Headers { mut send, .. } =
                                    incoming_headers;

                                // Send initial headers.
                                send.send(OutboundFrame::Headers(
                                    vec![Header::new(b":status", b"103")],
                                    None,
                                ))
                                .await?;

                                // Delay sending additional headers to the next
                                // cycle just to make sure things work properly
                                // if the frames aren't sent back to back.
                                tokio::task::yield_now().await;

                                // Send additional headers.
                                send.send(OutboundFrame::Headers(
                                    vec![Header::new(b":status", b"200")],
                                    None,
                                ))
                                .await?;

                                // Send fin
                                send.send(OutboundFrame::Body(
                                    bytes::Bytes::new(),
                                    true,
                                ))
                                .await?;
                            },
                        }
                    }
                    Ok(())
                }
                .await;
                let tx = completion_tx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(tx) = tx {
                    let _ = tx.send(result);
                }
            }
        },
    )?;

    let summary = h3i_fixtures::request(&url, 1).await?;

    let mut headers = summary.stream_map.headers_on_stream(0);

    assert_eq!(
        headers
            .next()
            .ok_or("initial headers missing")?
            .status_code(),
        Some(b"103".as_slice())
    );
    assert_eq!(
        headers
            .next()
            .ok_or("additional headers missing")?
            .status_code(),
        Some(b"200".as_slice())
    );
    assert!(headers.next().is_none());
    tokio::time::timeout(std::time::Duration::from_secs(2), completion_rx)
        .await???;
    Ok(())
}
