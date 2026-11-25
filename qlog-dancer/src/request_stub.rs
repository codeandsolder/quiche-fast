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

use qlog::events::http3::HttpHeader;
use std::borrow::Cow;
use std::fmt::Display;

use crate::datastore::H2StreamReset;
use crate::datastore::QuicStreamReset;
use crate::datastore::QuicStreamStopSending;
use crate::datastore::RequestActor;
use crate::datastore::RequestAtClientDeltas;
use crate::datastore::RequestAtServerDeltas;
use netlog::http::headers_to_map;

pub const CLIENT_CONTENT_LENGTH: &str = "Request Content-Length";
pub const CLIENT_TRANSFERRED: &str = "Request Transferred";
pub const UPLOAD_TIME: &str = "Upload duration (ms)";
pub const UPLOAD_RATE: &str = "Upload rate (Mbps)";
pub const SERVER_RX_HDR_TX_HDR: &str = "Server Rx Hdr, Tx Hdr";
pub const SERVER_TX_HDR_TX_FIRST_HDR: &str = "Server Tx Hdr, Tx First Hdr";
pub const SERVER_TX_HDR_TX_LAST_HDR: &str = "Server Tx Hdr, Tx Last Hdr";
pub const SERVER_TX_FIRST_DATA_TX_LAST_DATA: &str =
    "Server Tx First Data, Tx Last Data (Download time)";

pub const CLIENT_PRI: &str = "Client Priority Header";
pub const SERVER_PRI: &str = "Server Priority Header";

const MAX_PATH_LENGTH: usize = 80;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct NaOption<T> {
    pub inner: Option<T>,
}

impl<T> NaOption<T> {
    #[must_use = "constructs a displayable optional value"]
    pub const fn new(value: Option<T>) -> Self {
        Self { inner: value }
    }

    /// Preserve an earlier value when a later header block omits this field.
    fn update_if_present(&mut self, value: Option<T>) {
        if let Some(value) = value {
            self.inner = Some(value);
        }
    }
}

impl<T: std::fmt::Display> Display for NaOption<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner.as_ref() {
            Some(v) => write!(f, "{v}"),
            None => write!(f, "n/a"),
        }
    }
}

#[derive(Debug, Default)]
pub struct HttpRequestStub {
    pub request_actor: RequestActor,
    pub stream_id: u64,
    pub host: NaOption<String>,
    pub method: NaOption<String>,
    pub path: NaOption<String>,
    pub status: NaOption<String>,
    pub client_content_length: NaOption<String>,
    pub server_content_length: NaOption<String>,
    pub client_pri_hdr: NaOption<String>,
    pub server_pri_hdr: NaOption<String>,
    pub priority_updates: Vec<String>,

    pub time_discovery: Option<f64>,
    pub time_first_headers_rx: Option<f64>,
    pub time_first_headers_tx: Option<f64>,

    pub time_first_data_rx: Option<f64>,
    pub time_first_data_tx: Option<f64>,

    pub time_last_data_rx: Option<f64>,
    pub time_last_data_tx: Option<f64>,

    pub time_fin_rx: Option<f64>,

    // TODO, Option<u64>
    pub time_data_rx_set: Vec<(f64, u64)>,
    pub time_data_tx_set: Vec<(f64, u64)>,

    pub client_transferred_bytes: NaOption<u64>,
    pub server_transferred_bytes: NaOption<u64>,

    pub avg_upload_rate: NaOption<f64>,
    pub avg_download_rate_d2d: NaOption<f64>,
    pub avg_download_rate_h2d: NaOption<f64>,

    pub at_client_deltas: Option<RequestAtClientDeltas>,
    pub at_server_deltas: Option<RequestAtServerDeltas>,

    pub quic_stream_stop_sending_sent: Option<QuicStreamStopSending>,
    pub quic_stream_stop_sending_received: Option<QuicStreamStopSending>,

    pub quic_stream_reset_sent: Option<QuicStreamReset>,
    pub quic_stream_reset_received: Option<QuicStreamReset>,

    pub h2_stream_reset_sent: Option<H2StreamReset>,
    pub h2_stream_reset_receive: Option<H2StreamReset>,
}

struct ClientDeltaStrings {
    pub discovery_tx_hdr: String,
    pub tx_hdr_rx_hdr: String,
    pub tx_hdr_rx_first_data: String,
    pub tx_hdr_rx_last_data: String,
    pub download_time_d2d: String,
    pub download_time_h2d: String,
    pub upload_time: String,
}

impl Default for ClientDeltaStrings {
    fn default() -> Self {
        let na = NaOption::<u8>::new(None);

        Self {
            discovery_tx_hdr: na.to_string(),
            tx_hdr_rx_hdr: na.to_string(),
            tx_hdr_rx_first_data: na.to_string(),
            tx_hdr_rx_last_data: na.to_string(),
            download_time_d2d: na.to_string(),
            download_time_h2d: na.to_string(),
            upload_time: na.to_string(),
        }
    }
}

impl HttpRequestStub {
    fn client_deltas(&self) -> ClientDeltaStrings {
        self.at_client_deltas
            .map_or_else(ClientDeltaStrings::default, |d| ClientDeltaStrings {
                discovery_tx_hdr: d.discover_tx_hdr.to_string(),
                tx_hdr_rx_hdr: d.tx_hdr_rx_hdr.to_string(),
                tx_hdr_rx_first_data: d.tx_hdr_rx_first_data.to_string(),
                tx_hdr_rx_last_data: d.tx_hdr_rx_last_data.to_string(),
                download_time_d2d: d.rx_first_data_rx_last_data.to_string(),
                download_time_h2d: d.tx_hdr_rx_last_data.to_string(),
                upload_time: d.tx_first_data_tx_last_data.to_string(),
            })
    }

    fn server_deltas(&self) -> (String, String, String, String) {
        self.at_server_deltas.map_or_else(
            || ("n/a".into(), "n/a".into(), "n/a".into(), "n/a".into()),
            |d| {
                (
                    d.rx_hdr_tx_hdr.to_string(),
                    d.rx_hdr_tx_first_data.to_string(),
                    d.rx_hdr_tx_last_data.to_string(),
                    d.tx_first_data_tx_last_data.to_string(),
                )
            },
        )
    }
}

const REQUEST_HEADERS: [&str; 31] = [
    "ID",
    "Method",
    "Host",
    "Path",
    "Status",
    "Response Content-Length (bytes)",
    "Response Transferred (bytes)",
    "Request Discovered Time",
    "Request Start Time",
    "Request End Time",
    "Stalled duration (ms)",
    "Download duration (h2d) (ms)",
    "Download rate (h2d) (Mbps)",
    "Download duration (d2d) (ms)",
    "Download rate (d2d) (Mbps)",
    "Client Tx Hdr, Rx Hdr",
    "Client Tx Hdr, Rx First Data",
    "Client Tx Hdr, Rx Last Data",
    CLIENT_CONTENT_LENGTH,
    CLIENT_TRANSFERRED,
    UPLOAD_TIME,
    UPLOAD_RATE,
    SERVER_RX_HDR_TX_HDR,
    SERVER_TX_HDR_TX_FIRST_HDR,
    SERVER_TX_HDR_TX_LAST_HDR,
    SERVER_TX_FIRST_DATA_TX_LAST_DATA,
    CLIENT_PRI,
    SERVER_PRI,
    "Reset Stream Sent",
    "Reset Stream Received",
    "Stop Sending Sent",
];

impl tabled::Tabled for HttpRequestStub {
    const LENGTH: usize = REQUEST_HEADERS.len();

    fn fields(&self) -> Vec<Cow<'_, str>> {
        // truncate long paths for
        let mut path = self.path.to_string();
        if path.len() > MAX_PATH_LENGTH {
            path.truncate(path.floor_char_boundary(MAX_PATH_LENGTH));
            path.push_str("<snip>");
        }

        let req_start = match self.request_actor {
            RequestActor::Client => self.time_first_headers_tx,
            RequestActor::Server => self.time_first_headers_rx,
        };
        let req_start = NaOption::new(req_start);

        // A response without a body ends at the response headers.
        let req_end = match self.request_actor {
            RequestActor::Client =>
                self.time_last_data_rx.or(self.time_first_headers_rx),
            RequestActor::Server =>
                self.time_last_data_tx.or(self.time_first_headers_tx),
        };

        let req_end = NaOption::new(req_end);

        let client_deltas = self.client_deltas();

        let (
            server_rx_hdr_tx_hdr,
            server_rx_hdr_tx_first_data,
            server_rx_hdr_tx_last_data,
            server_tx_first_data_tx_last_data,
        ) = self.server_deltas();

        let rst_stream_sent =
            match (&self.quic_stream_reset_sent, &self.h2_stream_reset_sent) {
                (Some(v), None) => v.to_string(),
                (None, Some(v)) => v.to_string(),
                _ => NaOption::<u8>::new(None).to_string(),
            };

        let rst_stream_received = match (
            &self.quic_stream_reset_received,
            &self.h2_stream_reset_receive,
        ) {
            (Some(v), None) => v.to_string(),
            (None, Some(v)) => v.to_string(),
            _ => NaOption::<u8>::new(None).to_string(),
        };

        let stop_sending_sent = self
            .quic_stream_stop_sending_sent
            .as_ref()
            .map_or_else(|| "n/a".to_owned(), ToString::to_string);

        vec![
            self.stream_id.to_string().into(),
            self.method.to_string().into(),
            self.host.to_string().into(),
            path.into(),
            self.status.to_string().into(),
            self.server_content_length.to_string().into(),
            self.server_transferred_bytes.to_string().into(),
            NaOption::new(self.time_discovery).to_string().into(),
            req_start.to_string().into(),
            req_end.to_string().into(),
            client_deltas.discovery_tx_hdr.into(),
            client_deltas.download_time_h2d.into(),
            self.avg_download_rate_h2d.to_string().into(),
            client_deltas.download_time_d2d.into(),
            self.avg_download_rate_d2d.to_string().into(),
            client_deltas.tx_hdr_rx_hdr.into(),
            client_deltas.tx_hdr_rx_first_data.into(),
            client_deltas.tx_hdr_rx_last_data.into(),
            self.client_content_length.to_string().into(),
            self.client_transferred_bytes.to_string().into(),
            client_deltas.upload_time.into(),
            self.avg_upload_rate.to_string().into(),
            server_rx_hdr_tx_hdr.into(),
            server_rx_hdr_tx_first_data.into(),
            server_rx_hdr_tx_last_data.into(),
            server_tx_first_data_tx_last_data.into(),
            self.client_pri_hdr.to_string().into(),
            self.server_pri_hdr.to_string().into(),
            rst_stream_sent.into(),
            rst_stream_received.into(),
            stop_sending_sent.into(),
        ]
    }

    fn headers() -> Vec<Cow<'static, str>> {
        REQUEST_HEADERS.iter().copied().map(Cow::Borrowed).collect()
    }
}

#[must_use = "returns the first matching header value"]
pub fn find_header_value(hdrs: &[HttpHeader], name: &str) -> Option<String> {
    hdrs.iter()
        .find(|&h| h.name.as_deref() == Some(name))
        .and_then(|h| h.value.clone())
}

impl HttpRequestStub {
    pub fn set_request_info_from_netlog(&mut self, hdrs: &[String]) {
        // TODO: case-sensitivity for HTTP/1.1
        let headers = headers_to_map(hdrs);

        self.method
            .update_if_present(headers.get(":method").cloned());
        self.host
            .update_if_present(headers.get(":authority").cloned());
        self.path.update_if_present(headers.get(":path").cloned());
        self.client_pri_hdr
            .update_if_present(headers.get("priority").cloned());
        self.client_content_length
            .update_if_present(headers.get("content-length").cloned());
    }

    pub fn set_response_info_from_netlog(&mut self, hdrs: &[String]) {
        // TODO: case-sensitivity for HTTP/1.1
        let headers = headers_to_map(hdrs);

        self.status
            .update_if_present(headers.get(":status").cloned());
        self.server_pri_hdr
            .update_if_present(headers.get("priority").cloned());
        self.server_content_length
            .update_if_present(headers.get("content-length").cloned());
    }

    pub fn set_request_info_from_qlog(&mut self, hdrs: &[HttpHeader]) {
        self.method
            .update_if_present(find_header_value(hdrs, ":method"));
        self.host
            .update_if_present(find_header_value(hdrs, ":authority"));
        self.path
            .update_if_present(find_header_value(hdrs, ":path"));
        self.client_pri_hdr
            .update_if_present(find_header_value(hdrs, "priority"));
        self.client_content_length
            .update_if_present(find_header_value(hdrs, "content-length"));
    }

    pub fn set_response_info_from_qlog(&mut self, hdrs: &[HttpHeader]) {
        self.status
            .update_if_present(find_header_value(hdrs, ":status"));
        self.server_pri_hdr
            .update_if_present(find_header_value(hdrs, "priority"));
        self.server_content_length
            .update_if_present(find_header_value(hdrs, "content-length"));
    }

    // Input times in milliseconds. Convert the byte count before scaling to
    // avoid integer overflow, including for very large cumulative traces.
    #[expect(
        clippy::cast_precision_loss,
        reason = "A throughput estimate is floating point; round the byte count once before scaling."
    )]
    fn maybe_megabits_per_second(
        start: Option<f64>, end: Option<f64>, bytes: Option<u64>,
    ) -> NaOption<f64> {
        let (Some(start), Some(end), Some(bytes)) = (start, end, bytes) else {
            return NaOption::new(None);
        };
        let elapsed = end - start;
        if !elapsed.is_finite() || elapsed < 0.0 {
            return NaOption::new(None);
        }
        // Preserve the one-millisecond convention for a single timestamp.
        let elapsed = if elapsed == 0.0 { 1.0 } else { elapsed };
        let rate = (bytes as f64 * 0.008) / elapsed;
        NaOption::new(rate.is_finite().then_some(rate))
    }

    pub fn calculate_upload_download_rate(&mut self) {
        match self.request_actor {
            RequestActor::Client => {
                self.avg_upload_rate = Self::maybe_megabits_per_second(
                    self.time_first_data_tx,
                    self.time_last_data_tx,
                    self.client_transferred_bytes.inner,
                );

                self.avg_download_rate_d2d = Self::maybe_megabits_per_second(
                    self.time_first_data_rx,
                    self.time_last_data_rx,
                    self.server_transferred_bytes.inner,
                );

                self.avg_download_rate_h2d = Self::maybe_megabits_per_second(
                    self.time_first_headers_tx,
                    self.time_last_data_rx,
                    self.server_transferred_bytes.inner,
                );
            },

            RequestActor::Server => {
                self.avg_upload_rate = Self::maybe_megabits_per_second(
                    self.time_first_data_rx,
                    self.time_last_data_rx,
                    self.client_transferred_bytes.inner,
                );

                self.avg_download_rate_d2d = Self::maybe_megabits_per_second(
                    self.time_first_data_tx,
                    self.time_last_data_tx,
                    self.server_transferred_bytes.inner,
                );
            },
        }
    }

    fn maybe_time_delta(start: Option<f64>, end: Option<f64>) -> NaOption<f64> {
        match (start, end) {
            (Some(start), Some(end)) => NaOption::new(Some(end - start)),

            _ => NaOption::<f64>::new(None),
        }
    }

    pub fn calculate_deltas(&mut self) {
        match self.request_actor {
            RequestActor::Client => {
                let discover_tx_hdr = Self::maybe_time_delta(
                    self.time_discovery,
                    self.time_first_headers_tx,
                );

                let tx_hdr_rx_hdr = Self::maybe_time_delta(
                    self.time_first_headers_tx,
                    self.time_first_headers_rx,
                );

                let tx_hdr_rx_first_data = Self::maybe_time_delta(
                    self.time_first_headers_tx,
                    self.time_first_data_rx,
                );

                let tx_hdr_rx_last_data = Self::maybe_time_delta(
                    self.time_first_headers_tx,
                    self.time_last_data_rx,
                );

                let tx_first_data_tx_last_data = Self::maybe_time_delta(
                    self.time_first_data_tx,
                    self.time_last_data_tx,
                );

                let rx_first_data_rx_last_data = Self::maybe_time_delta(
                    self.time_first_data_rx,
                    self.time_last_data_rx,
                );

                let rx_hdr_rx_last_data = Self::maybe_time_delta(
                    self.time_first_headers_rx,
                    self.time_last_data_rx,
                );

                self.at_client_deltas = Some(RequestAtClientDeltas {
                    discover_tx_hdr,
                    tx_hdr_rx_hdr,
                    tx_hdr_rx_first_data,
                    tx_hdr_rx_last_data,
                    tx_first_data_tx_last_data,
                    rx_first_data_rx_last_data,
                    rx_hdr_rx_last_data,
                });
            },

            RequestActor::Server => {
                let rx_hdr_tx_hdr = Self::maybe_time_delta(
                    self.time_first_headers_rx,
                    self.time_first_headers_tx,
                );
                let rx_hdr_tx_first_data = Self::maybe_time_delta(
                    self.time_first_headers_rx,
                    self.time_first_data_tx,
                );
                let rx_hdr_tx_last_data = Self::maybe_time_delta(
                    self.time_first_headers_rx,
                    self.time_last_data_tx,
                );
                let tx_first_data_tx_last_data = Self::maybe_time_delta(
                    self.time_first_data_tx,
                    self.time_last_data_tx,
                );

                self.at_server_deltas = Some(RequestAtServerDeltas {
                    rx_hdr_tx_hdr,
                    rx_hdr_tx_first_data,
                    rx_hdr_tx_last_data,
                    tx_first_data_tx_last_data,
                });
            },
        }
    }
}

#[cfg(test)]
mod header_metadata_tests {
    use super::HttpRequestStub;
    use super::NaOption;
    use qlog::events::http3::HttpHeader;

    #[test]
    fn trailers_preserve_request_response_metadata_for_qlog_and_netlog() {
        for qlog_format in [false, true] {
            let apply = |req: &mut HttpRequestStub,
                         request: bool,
                         fields: &[(&str, &str)]| {
                if qlog_format {
                    let headers: Vec<_> = fields
                        .iter()
                        .map(|&(name, value)| HttpHeader {
                            name: Some(name.into()),
                            name_bytes: None,
                            value: Some(value.into()),
                            value_bytes: None,
                        })
                        .collect();
                    if request {
                        req.set_request_info_from_qlog(&headers);
                    } else {
                        req.set_response_info_from_qlog(&headers);
                    }
                } else {
                    let headers: Vec<_> = fields
                        .iter()
                        .map(|(name, value)| format!("{name}: {value}"))
                        .collect();
                    if request {
                        req.set_request_info_from_netlog(&headers);
                    } else {
                        req.set_response_info_from_netlog(&headers);
                    }
                }
            };

            let mut req = HttpRequestStub::default();
            apply(&mut req, true, &[
                (":method", "POST"),
                (":authority", "example.test"),
                (":path", "/resource"),
                ("priority", "u=3"),
                ("content-length", "12"),
            ]);
            apply(&mut req, true, &[("grpc-status", "0")]);
            assert_eq!(
                (
                    req.method.inner.as_deref(),
                    req.host.inner.as_deref(),
                    req.path.inner.as_deref(),
                    req.client_pri_hdr.inner.as_deref(),
                    req.client_content_length.inner.as_deref(),
                ),
                (
                    Some("POST"),
                    Some("example.test"),
                    Some("/resource"),
                    Some("u=3"),
                    Some("12"),
                )
            );
            apply(&mut req, true, &[("priority", "u=1")]);
            assert_eq!(req.client_pri_hdr.inner.as_deref(), Some("u=1"));

            let mut response = HttpRequestStub::default();
            apply(&mut response, false, &[
                (":status", "200"),
                ("priority", "u=4"),
                ("content-length", "120"),
            ]);
            apply(&mut response, false, &[("grpc-status", "0")]);
            assert_eq!(response.status.inner.as_deref(), Some("200"));
            assert_eq!(response.server_pri_hdr.inner.as_deref(), Some("u=4"));
            assert_eq!(
                response.server_content_length.inner.as_deref(),
                Some("120")
            );

            apply(&mut response, false, &[("priority", "")]);
            assert_eq!(
                response.server_pri_hdr,
                NaOption::new(Some(String::new()))
            );
            assert_eq!(response.status.inner.as_deref(), Some("200"));
        }
    }
}

#[cfg(test)]
mod report_tests {
    use super::HttpRequestStub;
    use super::NaOption;
    use crate::datastore::RequestActor;
    use tabled::Tabled;

    #[test]
    fn report_fields_match_headers_and_use_last_response_timestamp() {
        for actor in [RequestActor::Client, RequestActor::Server] {
            let request = HttpRequestStub {
                request_actor: actor,
                time_first_headers_rx: Some(1.0),
                time_first_headers_tx: Some(2.0),
                time_first_data_rx: Some(3.0),
                time_first_data_tx: Some(4.0),
                time_last_data_rx: Some(5.0),
                time_last_data_tx: Some(6.0),
                path: NaOption::new(Some(format!("/{}", "é".repeat(50)))),
                ..HttpRequestStub::default()
            };
            let fields = request.fields();
            assert_eq!(fields.len(), HttpRequestStub::LENGTH);
            assert_eq!(HttpRequestStub::headers().len(), HttpRequestStub::LENGTH);
            assert_eq!(fields[3], format!("/{}<snip>", "é".repeat(39)));
            assert_eq!(fields[9], match request.request_actor {
                RequestActor::Client => "5",
                RequestActor::Server => "6",
            });
        }
    }

    #[test]
    fn throughput_is_finite_and_handles_large_counters() {
        let rate = HttpRequestStub::maybe_megabits_per_second;
        assert_eq!(rate(Some(1.0), Some(2.0), Some(1000)).inner, Some(8.0));
        assert_eq!(rate(Some(1.0), Some(1.0), Some(1000)).inner, Some(8.0));
        assert!(rate(Some(1.0), Some(2.0), Some(u64::MAX))
            .inner
            .is_some_and(f64::is_finite));
        for end in [None, Some(0.0), Some(f64::NAN), Some(f64::INFINITY)] {
            assert_eq!(rate(Some(1.0), end, Some(1000)).inner, None);
        }
    }
}
