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

use std::collections::BTreeMap;

use serde::Deserialize;

use super::EventHeader;
use super::SourceDependency;

#[derive(Debug)]
pub enum Event {
    HttpTransactionSendRequestHeaders(HttpTransactionSendRequestHeadersEvent),
    HttpTransactionHttp2SendRequestHeaders(
        HttpTransactionHttp2SendRequestHeadersEvent,
    ),
    HttpTransactionQuicSendRequestHeaders(
        HttpTransactionQuicSendRequestHeadersEvent,
    ),
    HttpTransactionReadResponseHeaders(HttpTransactionReadResponseHeadersEvent),
    HttpStreamJobBoundToRequest(HttpStreamJobBoundToRequestEvent),
    HttpStreamRequestBoundToJob(HttpStreamRequestBoundToJobEvent),
    HttpStreamRequestBoundToQuicSession(HttpStreamRequestBoundToQuicSessionEvent),
}
#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionSendRequestHeadersParams {
    pub headers: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionSendRequestHeadersEvent {
    pub params: HttpTransactionSendRequestHeadersParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionHttp2SendRequestHeadersParams {
    pub headers: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionHttp2SendRequestHeadersEvent {
    pub params: HttpTransactionHttp2SendRequestHeadersParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionQuicSendRequestHeadersParams {
    pub headers: Vec<String>,
    pub quic_priority_incremental: bool,
    pub quic_priority_type: String,
    pub quic_priority_urgency: u8,
    pub quic_stream_id: u64,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionQuicSendRequestHeadersEvent {
    pub params: HttpTransactionQuicSendRequestHeadersParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionReadResponseHeadersParams {
    pub headers: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpTransactionReadResponseHeadersEvent {
    pub params: HttpTransactionReadResponseHeadersParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpStreamJobBoundToRequestParams {
    pub source_dependency: SourceDependency,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpStreamRequestBoundToJobEvent {
    pub params: HttpStreamJobBoundToRequestParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpStreamRequestBoundToJobParams {
    pub source_dependency: SourceDependency,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpStreamJobBoundToRequestEvent {
    pub params: HttpStreamJobBoundToRequestParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpStreamRequestBoundToQuicSessionEvent {
    pub params: HttpStreamRequestBoundToQuicSessionParams,
}

#[derive(Deserialize, Debug, Default)]
pub struct HttpStreamRequestBoundToQuicSessionParams {
    pub source_dependency: SourceDependency,
}

#[must_use]
pub fn headers_to_map(hdrs: &[String]) -> BTreeMap<String, String> {
    let mut ret = BTreeMap::new();

    for hdr in hdrs {
        // Only the first ": " belongs to the header delimiter; values can
        // contain the same sequence (e.g. a Location URL or error message).
        let (name, value) = hdr.split_once(": ").unwrap_or((hdr, ""));
        ret.insert(name.to_owned(), value.to_owned());
    }

    ret
}

/// Parses the provided `event` based on the event type provided in `event_hdr`.
#[must_use]
pub fn parse_event(
    event_hdr: &EventHeader, event: &[u8],
) -> Option<super::Event> {
    match event_hdr.ty_string.as_str() {
        "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS" => {
            let ev: HttpTransactionHttp2SendRequestHeadersEvent =
                super::decode_event(event)?;
            return Some(super::Event::Http(
                Event::HttpTransactionHttp2SendRequestHeaders(ev),
            ));
        },

        "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS" => {
            let ev: HttpTransactionQuicSendRequestHeadersEvent =
                super::decode_event(event)?;
            return Some(super::Event::Http(
                Event::HttpTransactionQuicSendRequestHeaders(ev),
            ));
        },

        "HTTP_TRANSACTION_SEND_REQUEST_HEADERS" => {
            let ev: HttpTransactionSendRequestHeadersEvent =
                super::decode_event(event)?;
            return Some(super::Event::Http(
                Event::HttpTransactionSendRequestHeaders(ev),
            ));
        },

        "HTTP_TRANSACTION_READ_RESPONSE_HEADERS" => {
            let ev: HttpTransactionReadResponseHeadersEvent =
                super::decode_event(event)?;
            return Some(super::Event::Http(
                Event::HttpTransactionReadResponseHeaders(ev),
            ));
        },

        "HTTP_STREAM_REQUEST_BOUND_TO_JOB" => {
            let ev: HttpStreamRequestBoundToJobEvent =
                super::decode_event(event)?;
            return Some(super::Event::Http(Event::HttpStreamRequestBoundToJob(
                ev,
            )));
        },

        "HTTP_STREAM_JOB_BOUND_TO_REQUEST" => {
            let ev: HttpStreamJobBoundToRequestEvent =
                super::decode_event(event)?;
            return Some(super::Event::Http(Event::HttpStreamJobBoundToRequest(
                ev,
            )));
        },

        "HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION" => {
            let ev: HttpStreamRequestBoundToQuicSessionEvent =
                super::decode_event(event)?;
            return Some(super::Event::Http(
                Event::HttpStreamRequestBoundToQuicSession(ev),
            ));
        },

        // Known events that are intentionally ignored for now.
        "HTTP_TRANSACTION_READ_EARLY_HINTS_RESPONSE_HEADERS" |
        "HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS" |
        "HTTP_TRANSACTION_RESTART_AFTER_ERROR" |
        "HTTP_TRANSACTION_RESTART_MISDIRECTED_REQUEST" |
        "HTTP_TRANSACTION_SEND_REQUEST_BODY" |
        "HTTP_TRANSACTION_SEND_TUNNEL_HEADERS" |
        "HTTP_TRANSACTION_TUNNEL_READ_HEADERS" |
        "HTTP_TRANSACTION_TUNNEL_SEND_REQUEST" |
        "HTTP_TRANSACTION_SEND_REQUEST" |
        "HTTP_TRANSACTION_READ_HEADERS" |
        "HTTP_TRANSACTION_READ_BODY" => (),

        _ => log::trace!("skipping unknown type....{}", event_hdr.ty_string),
    }

    None
}

#[cfg(test)]
mod header_tests {
    use super::headers_to_map;

    #[test]
    fn header_values_keep_embedded_delimiters() {
        let headers = [
            ":method: GET",
            ":authority: example.test: 443",
            "location: https://example.test/path: detail",
            "x-error: reason: detail: suffix",
            "x-empty: ",
            "value-less",
            "x-repeat: earlier",
            "x-repeat: latest",
        ]
        .map(str::to_string);

        let mapped = headers_to_map(&headers);
        assert_eq!(mapped.len(), 7);
        assert_eq!(mapped[":method"], "GET");
        assert_eq!(mapped[":authority"], "example.test: 443");
        assert_eq!(mapped["location"], "https://example.test/path: detail");
        assert_eq!(mapped["x-error"], "reason: detail: suffix");
        assert_eq!(mapped["x-empty"], "");
        assert_eq!(mapped["value-less"], "");
        assert_eq!(mapped["x-repeat"], "latest");
    }
}
