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

use h3i::actions::h3::send_headers_frame;
use h3i::actions::h3::Action;
use h3i::actions::h3::StreamEvent;
use h3i::actions::h3::StreamEventType;
use h3i::actions::h3::WaitType;
use h3i::client::connection_summary::ConnectionSummary;
use h3i::client::ClientError;
use h3i::frame::H3iFrame;
use h3i::quiche::h3::Header;
use h3i::quiche::h3::{
    self,
};
use h3i::quiche::ConnectionError;
use h3i::quiche::WireErrorCode;
use url::Url;

/// Default h3i config, connects to "test.com"
pub fn h3i_config(url: &str) -> Result<h3i::config::Config, ClientError> {
    let url = url.strip_prefix("http://").unwrap_or(url);
    let final_url = url.split('/').next().unwrap_or(url);

    let mut config = h3i::config::Config::new("test.com")?;
    config.idle_timeout = 2000;
    config.flow.data = 1_000_000;
    config.flow.stream_data_uni = 100_000;
    config.endpoint.connect_to = Some(final_url.parse().map_err(|error| {
        ClientError::Other(format!("invalid fixture address: {error}"))
    })?);
    config.tls.verify_peer = false;
    config.datagrams = Some(h3i::config::DatagramQueues::default());
    Ok(config)
}

pub fn default_headers() -> Vec<Header> {
    default_headers_with_authority("test.com")
}

pub fn default_headers_with_authority(host: &str) -> Vec<Header> {
    vec![
        Header::new(b":method", b"GET"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", host.as_bytes()),
        Header::new(b":path", b"/"),
    ]
}

pub fn url_headers(url: &Url) -> Vec<Header> {
    use url::Position::AfterQuery;
    use url::Position::BeforeHost;
    use url::Position::BeforePath;
    let authority = &url[BeforeHost..BeforePath];
    let path = &url[BeforePath..AfterQuery];

    vec![
        Header::new(b":method", b"GET"),
        Header::new(b":scheme", url.scheme().as_bytes()),
        Header::new(b":authority", authority.as_bytes()),
        Header::new(b":path", path.as_bytes()),
    ]
}

pub async fn summarize_connection(
    h3i: h3i::config::Config, actions: Vec<Action>,
) -> Result<ConnectionSummary, ClientError> {
    tokio::task::spawn_blocking(move || {
        h3i::client::sync_client::connect(h3i, actions, None)
    })
    .await
    .map_err(|error| ClientError::Other(format!("client task failed: {error}")))?
}

pub async fn request(
    url: &str, count: u64,
) -> Result<ConnectionSummary, ClientError> {
    let h3i = h3i_config(url)?;
    let url = Url::parse(url).map_err(|error| {
        ClientError::Other(format!("invalid request URL: {error}"))
    })?;
    let headers = url_headers(&url);

    let mut actions = Vec::new();
    for req in 0..count {
        let stream_id = req * 4;
        actions.push(send_headers_frame(stream_id, true, headers.clone()));
        actions.push(Action::FlushPackets);
        actions.push(Action::Wait {
            wait_type: WaitType::StreamEvent(StreamEvent {
                stream_id,
                event_type: StreamEventType::Finished,
            }),
        });
    }

    actions.push(Action::ConnectionClose {
        error: ConnectionError {
            is_app: true,
            error_code: WireErrorCode::NoError as _,
            reason: Vec::new(),
        },
    });

    summarize_connection(h3i, actions).await
}

pub fn received_status_code_on_stream(
    summary: &ConnectionSummary, stream: u64, code: u16,
) -> bool {
    summary.stream_map.headers_on_stream(stream).any(|event| {
        event
            .status_code()
            .filter(|status| {
                status.len() == 3 && status.iter().all(u8::is_ascii_digit)
            })
            .and_then(|status| std::str::from_utf8(status).ok())
            .and_then(|status| status.parse::<u16>().ok()) ==
            Some(code)
    })
}

pub fn stream_body(
    summary: &ConnectionSummary, stream: u64,
) -> Result<Option<String>, std::string::FromUtf8Error> {
    let mut body = None::<Vec<u8>>;
    for frame in summary.stream_map.stream(stream) {
        if let H3iFrame::QuicheH3(h3::frame::Frame::Data { payload }) = frame {
            body.get_or_insert_with(Vec::new).extend_from_slice(payload);
        }
    }
    body.map(String::from_utf8).transpose()
}
