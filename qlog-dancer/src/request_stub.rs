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
pub const CLIENT_OBSERVED_DATA: &str = "Request Observed DATA (bytes)";
pub const SERVER_OBSERVED_DATA: &str = "Response Observed DATA (bytes)";
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

/// One observation of a DATA frame, including frames whose length is absent.
pub type DataObservation = (f64, Option<u64>);

/// A request's DATA observations in one local direction. Keep a single
/// history; cumulative plot series are derived from it, not maintained as
/// independent copies of the same event stream.
#[derive(Debug, Default)]
pub struct HttpDataHistory {
    observations: Vec<DataObservation>,
    known_bytes: u64,
    incomplete: bool,
    first_time: Option<f64>,
    last_time: Option<f64>,
}

#[derive(Debug)]
pub struct DataLengthOverflow;

impl Display for DataLengthOverflow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DATA payload length total overflows u64")
    }
}

impl std::error::Error for DataLengthOverflow {}

/// Measured DATA interval and its observed-length rate, using the same
/// endpoints.
#[derive(Debug)]
pub(crate) struct TransferMeasurement {
    duration: NaOption<f64>,
    pub(crate) rate: NaOption<f64>,
}

fn time_delta(start: Option<f64>, end: Option<f64>) -> NaOption<f64> {
    let elapsed = start
        .zip(end)
        .map(|(start, end)| end - start)
        .filter(|elapsed| elapsed.is_finite() && *elapsed >= 0.0);
    NaOption::new(elapsed)
}

impl HttpDataHistory {
    /// Record an observation, preserving even an unknown length.
    ///
    /// # Errors
    /// Returns an error without changing the history if the sum of known
    /// payload lengths would overflow.
    pub fn record(
        &mut self, time: f64, length: Option<u64>,
    ) -> Result<(), DataLengthOverflow> {
        let known_bytes = self
            .known_bytes
            .checked_add(length.unwrap_or_default())
            .ok_or(DataLengthOverflow)?;
        self.observations.push((time, length));
        self.known_bytes = known_bytes;
        self.incomplete |= length.is_none();
        self.first_time =
            Some(self.first_time.map_or(time, |first| first.min(time)));
        self.last_time = Some(self.last_time.map_or(time, |last| last.max(time)));
        Ok(())
    }

    #[must_use = "the slice contains every DATA observation"]
    pub const fn observations(&self) -> &[DataObservation] {
        self.observations.as_slice()
    }

    #[must_use = "the timestamp identifies the first observed DATA frame"]
    pub const fn first_time(&self) -> Option<f64> {
        self.first_time
    }

    #[must_use = "the timestamp identifies the last observed DATA frame"]
    pub const fn last_time(&self) -> Option<f64> {
        self.last_time
    }

    #[must_use = "the total includes only observations with known lengths"]
    pub const fn known_bytes(&self) -> u64 {
        self.known_bytes
    }

    #[must_use = "an absent total indicates missing length evidence"]
    pub const fn complete_bytes(&self) -> Option<u64> {
        if self.incomplete || self.observations.is_empty() {
            None
        } else {
            Some(self.known_bytes)
        }
    }

    /// Rates are estimates of observed lengths, not confirmed throughput.
    #[expect(
        clippy::cast_precision_loss,
        reason = "Convert observed byte counts to floating point before scaling to megabits per second."
    )]
    fn measurement(&self, start: Option<f64>) -> TransferMeasurement {
        let duration = time_delta(start, self.last_time());
        let rate = duration
            .inner
            .filter(|elapsed| *elapsed > 0.0)
            .zip(self.complete_bytes())
            .map(|(elapsed, bytes)| (bytes as f64 * 0.008) / elapsed)
            .filter(|rate| rate.is_finite());
        TransferMeasurement {
            duration,
            rate: NaOption::new(rate),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_known_frames(
        frames: &[(f64, u64)],
    ) -> Result<Self, DataLengthOverflow> {
        let mut history = Self::default();
        for &(time, length) in frames {
            history.record(time, Some(length))?;
        }
        Ok(history)
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

    pub time_fin_rx: Option<f64>,
    pub sent_data: HttpDataHistory,
    pub received_data: HttpDataHistory,

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
}

impl Default for ClientDeltaStrings {
    fn default() -> Self {
        let na = NaOption::<u8>::new(None);

        Self {
            discovery_tx_hdr: na.to_string(),
            tx_hdr_rx_hdr: na.to_string(),
            tx_hdr_rx_first_data: na.to_string(),
            tx_hdr_rx_last_data: na.to_string(),
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
    SERVER_OBSERVED_DATA,
    "Request Discovered Time",
    "Request Start Time",
    "Last observed response activity",
    "Stalled duration (ms)",
    "Download duration (h2d) (ms)",
    "Download rate (h2d) (Mbps)",
    "Download duration (d2d) (ms)",
    "Download rate (d2d) (Mbps)",
    "Client Tx Hdr, Rx Hdr",
    "Client Tx Hdr, Rx First Data",
    "Client Tx Hdr, Rx Last Data",
    CLIENT_CONTENT_LENGTH,
    CLIENT_OBSERVED_DATA,
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

        // The final observation is not evidence that delivery completed.
        let req_end = NaOption::new(
            [self.response_headers_time(), self.server_data().last_time()]
                .into_iter()
                .flatten()
                .filter(|time| time.is_finite())
                .max_by(f64::total_cmp),
        );
        let download_from_headers =
            self.server_data().measurement(self.response_headers_time());
        let download_from_data = self
            .server_data()
            .measurement(self.server_data().first_time());
        let upload = self.upload_measurement();

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
            NaOption::new(self.server_data().complete_bytes())
                .to_string()
                .into(),
            NaOption::new(self.time_discovery).to_string().into(),
            req_start.to_string().into(),
            req_end.to_string().into(),
            client_deltas.discovery_tx_hdr.into(),
            download_from_headers.duration.to_string().into(),
            download_from_headers.rate.to_string().into(),
            download_from_data.duration.to_string().into(),
            download_from_data.rate.to_string().into(),
            client_deltas.tx_hdr_rx_hdr.into(),
            client_deltas.tx_hdr_rx_first_data.into(),
            client_deltas.tx_hdr_rx_last_data.into(),
            self.client_content_length.to_string().into(),
            NaOption::new(self.client_data().complete_bytes())
                .to_string()
                .into(),
            upload.duration.to_string().into(),
            upload.rate.to_string().into(),
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

    #[must_use = "the history describes client-originated DATA"]
    pub const fn client_data(&self) -> &HttpDataHistory {
        match self.request_actor {
            RequestActor::Client => &self.sent_data,
            RequestActor::Server => &self.received_data,
        }
    }

    #[must_use = "the history describes server-originated DATA"]
    pub const fn server_data(&self) -> &HttpDataHistory {
        match self.request_actor {
            RequestActor::Client => &self.received_data,
            RequestActor::Server => &self.sent_data,
        }
    }

    const fn response_headers_time(&self) -> Option<f64> {
        match self.request_actor {
            RequestActor::Client => self.time_first_headers_rx,
            RequestActor::Server => self.time_first_headers_tx,
        }
    }

    pub(crate) fn upload_measurement(&self) -> TransferMeasurement {
        let history = self.client_data();
        history.measurement(history.first_time())
    }

    pub fn calculate_deltas(&mut self) {
        match self.request_actor {
            RequestActor::Client => {
                let discover_tx_hdr =
                    time_delta(self.time_discovery, self.time_first_headers_tx);

                let tx_hdr_rx_hdr = time_delta(
                    self.time_first_headers_tx,
                    self.time_first_headers_rx,
                );

                let tx_hdr_rx_first_data = time_delta(
                    self.time_first_headers_tx,
                    self.received_data.first_time(),
                );

                let tx_hdr_rx_last_data = time_delta(
                    self.time_first_headers_tx,
                    self.received_data.last_time(),
                );

                let tx_first_data_tx_last_data = time_delta(
                    self.sent_data.first_time(),
                    self.sent_data.last_time(),
                );

                self.at_client_deltas = Some(RequestAtClientDeltas {
                    discover_tx_hdr,
                    tx_hdr_rx_hdr,
                    tx_hdr_rx_first_data,
                    tx_hdr_rx_last_data,
                    tx_first_data_tx_last_data,
                });
            },

            RequestActor::Server => {
                let rx_hdr_tx_hdr = time_delta(
                    self.time_first_headers_rx,
                    self.time_first_headers_tx,
                );
                let rx_hdr_tx_first_data = time_delta(
                    self.time_first_headers_rx,
                    self.sent_data.first_time(),
                );
                let rx_hdr_tx_last_data = time_delta(
                    self.time_first_headers_rx,
                    self.sent_data.last_time(),
                );
                let tx_first_data_tx_last_data = time_delta(
                    self.sent_data.first_time(),
                    self.sent_data.last_time(),
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
    fn report_fields_match_headers_and_use_last_response_timestamp(
    ) -> Result<(), super::DataLengthOverflow> {
        for actor in [RequestActor::Client, RequestActor::Server] {
            let request = HttpRequestStub {
                request_actor: actor,
                time_first_headers_rx: Some(1.0),
                time_first_headers_tx: Some(2.0),
                received_data: super::HttpDataHistory::with_known_frames(&[
                    (3.0, 1),
                    (5.0, 2),
                ])?,
                sent_data: super::HttpDataHistory::with_known_frames(&[
                    (4.0, 1),
                    (6.0, 2),
                ])?,
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
        Ok(())
    }

    #[test]
    fn transfer_measurement_does_not_invent_elapsed_time(
    ) -> Result<(), super::DataLengthOverflow> {
        let history = super::HttpDataHistory::with_known_frames(&[(1.0, 1000)])?;
        let single = history.measurement(Some(1.0));
        assert_eq!(single.duration.inner, Some(0.0));
        assert_eq!(single.rate.inner, None);
        let from_header = history.measurement(Some(0.0));
        assert_eq!(from_header.duration.inner, Some(1.0));
        assert_eq!(from_header.rate.inner, Some(8.0));
        for start in [None, Some(2.0), Some(f64::NAN), Some(f64::INFINITY)] {
            let measurement = history.measurement(start);
            assert_eq!(measurement.duration.inner, None);
            assert_eq!(measurement.rate.inner, None);
        }
        let large =
            super::HttpDataHistory::with_known_frames(&[(2.0, u64::MAX)])?;
        assert!(large
            .measurement(Some(1.0))
            .rate
            .inner
            .is_some_and(f64::is_finite));
        let zero =
            super::HttpDataHistory::with_known_frames(&[(1.0, 0), (2.0, 0)])?;
        assert_eq!(zero.measurement(Some(1.0)).rate.inner, Some(0.0));
        Ok(())
    }

    #[test]
    fn report_transfer_intervals_are_endpoint_independent(
    ) -> Result<(), super::DataLengthOverflow> {
        for actor in [RequestActor::Client, RequestActor::Server] {
            let client = super::HttpDataHistory::with_known_frames(&[
                (3.0, 250),
                (5.0, 750),
            ])?;
            let server = super::HttpDataHistory::with_known_frames(&[
                (12.0, 1000),
                (14.0, 1000),
            ])?;
            let mut req = match actor {
                RequestActor::Client => HttpRequestStub {
                    time_first_headers_tx: Some(1.0),
                    time_first_headers_rx: Some(10.0),
                    sent_data: client,
                    received_data: server,
                    request_actor: actor,
                    ..HttpRequestStub::default()
                },
                RequestActor::Server => HttpRequestStub {
                    time_first_headers_rx: Some(1.0),
                    time_first_headers_tx: Some(10.0),
                    sent_data: server,
                    received_data: client,
                    request_actor: actor,
                    ..HttpRequestStub::default()
                },
            };
            req.calculate_deltas();
            let fields = req.fields();
            assert_eq!(&fields[11..15], ["4", "4", "2", "8"]);
            assert_eq!(&fields[20..22], ["2", "4"]);
            assert_eq!(fields[9], "14");
        }
        Ok(())
    }
}
