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
pub const SERVER_RX_HDR_TX_FIRST_DATA: &str = "Server Rx Hdr, Tx First Data";
pub const SERVER_RX_HDR_TX_LAST_DATA: &str = "Server Rx Hdr, Tx Last Data";
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

/// Header metadata is selected independently of ingestion order.
#[derive(Debug, Default)]
pub(crate) struct HeaderSelection {
    request_time: Option<f64>,
    response: Option<(ResponseStatusClass, f64)>,
    request_priority_time: Option<f64>,
    response_priority_time: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ResponseStatusClass {
    Invalid,
    Informational,
    Final,
}

pub(crate) fn parse_http_status(status: &str) -> Option<u16> {
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    status
        .parse::<u16>()
        .ok()
        .filter(|code| (100..=599).contains(code))
}

impl ResponseStatusClass {
    fn classify(status: &str) -> Self {
        match parse_http_status(status) {
            Some(100..=199) => Self::Informational,
            Some(200..=599) => Self::Final,
            _ => Self::Invalid,
        }
    }
}

struct HeaderFields {
    method: Option<String>,
    host: Option<String>,
    path: Option<String>,
    status: Option<String>,
    priority: Option<String>,
    content_length: Option<String>,
}

impl HeaderFields {
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            method: lookup(":method"),
            host: lookup(":authority"),
            path: lookup(":path"),
            status: lookup(":status"),
            priority: lookup("priority"),
            content_length: lookup("content-length"),
        }
    }
}

fn record_priority(
    priority: Option<String>, time: f64, selected: &mut NaOption<String>,
    selected_time: &mut Option<f64>,
) {
    if let Some(priority) = priority {
        if selected_time.is_none_or(|old| time >= old) {
            *selected = NaOption::new(Some(priority));
            *selected_time = Some(time);
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
    pub(crate) header_selection: HeaderSelection,

    pub time_discovery: Option<f64>,
    pub time_first_headers_rx: Option<f64>,
    pub time_first_headers_tx: Option<f64>,
    pub time_last_headers_rx: Option<f64>,
    pub time_last_headers_tx: Option<f64>,

    /// Earliest response-side FIN or reset observation, not confirmed delivery.
    pub time_response_terminal: Option<f64>,
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
    "Final HEADERS to last DATA (ms)",
    "Final HEADERS to last DATA (Mbps)",
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
    SERVER_RX_HDR_TX_FIRST_DATA,
    SERVER_RX_HDR_TX_LAST_DATA,
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

        let req_start = NaOption::new(self.request_headers_time());
        let req_end = NaOption::new(self.last_response_activity());
        let download_from_headers = self
            .server_data()
            .measurement(self.final_response_headers_time());
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
fn find_header_value(hdrs: &[HttpHeader], name: &str) -> Option<String> {
    hdrs.iter()
        .find(|&h| h.name.as_deref() == Some(name))
        .and_then(|h| h.value.clone())
}

impl HttpRequestStub {
    pub(crate) fn observe_netlog_headers(
        &mut self, time: f64, sent: bool, hdrs: &[String],
    ) {
        let headers = headers_to_map(hdrs);
        self.record_header_block(
            time,
            sent,
            HeaderFields::from_lookup(|name| headers.get(name).cloned()),
        );
    }

    pub(crate) fn observe_qlog_headers(
        &mut self, time: f64, sent: bool, hdrs: &[HttpHeader],
    ) {
        self.record_header_block(
            time,
            sent,
            HeaderFields::from_lookup(|name| find_header_value(hdrs, name)),
        );
    }

    fn record_header_block(
        &mut self, time: f64, sent: bool, fields: HeaderFields,
    ) {
        self.observe_headers(time, sent);
        if matches!(
            (&self.request_actor, sent),
            (RequestActor::Client, true) | (RequestActor::Server, false)
        ) {
            self.record_request_metadata(time, fields);
        } else {
            self.record_response_metadata(time, fields);
        }
    }

    fn record_request_metadata(&mut self, time: f64, fields: HeaderFields) {
        record_priority(
            fields.priority,
            time,
            &mut self.client_pri_hdr,
            &mut self.header_selection.request_priority_time,
        );
        // A statusless trailer must not become a request header block.
        let has_pseudo_header = fields.method.is_some() ||
            fields.host.is_some() ||
            fields.path.is_some();
        if has_pseudo_header &&
            self.header_selection
                .request_time
                .is_none_or(|old| time < old)
        {
            self.method = NaOption::new(fields.method);
            self.host = NaOption::new(fields.host);
            self.path = NaOption::new(fields.path);
            self.client_content_length = NaOption::new(fields.content_length);
            self.header_selection.request_time = Some(time);
        }
    }

    fn record_response_metadata(&mut self, time: f64, fields: HeaderFields) {
        record_priority(
            fields.priority,
            time,
            &mut self.server_pri_hdr,
            &mut self.header_selection.response_priority_time,
        );
        let Some(status) = fields.status else {
            return;
        };
        let class = ResponseStatusClass::classify(&status);
        // Prefer the earliest final response to all informational or invalid
        // status observations, even when input records arrive out of order.
        if self
            .header_selection
            .response
            .is_none_or(|(old_class, old_time)| {
                class > old_class || (class == old_class && time < old_time)
            })
        {
            self.status = NaOption::new(Some(status));
            self.server_content_length =
                NaOption::new(if class == ResponseStatusClass::Final {
                    fields.content_length
                } else {
                    None
                });
            self.header_selection.response = Some((class, time));
        }
    }

    fn final_response_headers_time(&self) -> Option<f64> {
        self.header_selection.response.and_then(|(class, time)| {
            (class == ResponseStatusClass::Final).then_some(time)
        })
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

    pub(crate) const fn request_headers_time(&self) -> Option<f64> {
        match self.request_actor {
            RequestActor::Client => self.time_first_headers_tx,
            RequestActor::Server => self.time_first_headers_rx,
        }
    }

    pub(crate) fn observe_headers(&mut self, time: f64, sent: bool) {
        let (first, last) = if sent {
            (
                &mut self.time_first_headers_tx,
                &mut self.time_last_headers_tx,
            )
        } else {
            (
                &mut self.time_first_headers_rx,
                &mut self.time_last_headers_rx,
            )
        };
        *first = Some(first.map_or(time, |old| old.min(time)));
        *last = Some(last.map_or(time, |old| old.max(time)));
    }

    pub(crate) fn record_response_terminal(&mut self, time: f64) {
        self.time_response_terminal = Some(
            self.time_response_terminal
                .map_or(time, |old| old.min(time)),
        );
    }

    /// Latest HTTP response header or DATA observation, not a completion time.
    pub(crate) fn last_response_activity(&self) -> Option<f64> {
        let last_headers = match self.request_actor {
            RequestActor::Client => self.time_last_headers_rx,
            RequestActor::Server => self.time_last_headers_tx,
        };
        [
            self.response_headers_time(),
            last_headers,
            self.server_data().last_time(),
        ]
        .into_iter()
        .flatten()
        .filter(|time| time.is_finite())
        .max_by(f64::total_cmp)
    }

    /// A FIN may precede HTTP parsing (for example, blocked QPACK decoding).
    /// Include later observed response activity without calling it delivery.
    pub(crate) fn observed_response_end(&self) -> Option<f64> {
        self.time_response_terminal.map(|terminal| {
            self.last_response_activity()
                .map_or(terminal, |last| terminal.max(last))
        })
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
    use crate::datastore::RequestActor;
    use qlog::events::http3::HttpHeader;

    fn observe(
        req: &mut HttpRequestStub, qlog: bool, time: f64, sent: bool,
        fields: &[(&str, &str)],
    ) {
        if qlog {
            let headers: Vec<_> = fields
                .iter()
                .map(|&(name, value)| HttpHeader {
                    name: Some(name.into()),
                    name_bytes: None,
                    value: Some(value.into()),
                    value_bytes: None,
                })
                .collect();
            req.observe_qlog_headers(time, sent, &headers);
        } else {
            let headers: Vec<_> = fields
                .iter()
                .map(|(name, value)| format!("{name}: {value}"))
                .collect();
            req.observe_netlog_headers(time, sent, &headers);
        }
    }

    #[test]
    fn final_response_metadata_beats_informational_and_trailer_observations() {
        for qlog in [false, true] {
            for actor in [RequestActor::Client, RequestActor::Server] {
                let request_sent = matches!(actor, RequestActor::Client);
                let mut req = HttpRequestStub {
                    request_actor: actor,
                    ..HttpRequestStub::default()
                };
                observe(&mut req, qlog, 2.0, request_sent, &[
                    (":method", "POST"),
                    (":authority", "example.test"),
                    (":path", "/resource"),
                    ("priority", "u=3"),
                    ("content-length", "12"),
                ]);
                observe(&mut req, qlog, 4.0, request_sent, &[
                    ("grpc-status", "0"),
                    ("priority", "u=1"),
                    ("content-length", "999"),
                ]);
                observe(&mut req, qlog, 3.0, request_sent, &[(
                    "priority", "u=2",
                )]);
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
                        Some("u=1"),
                        Some("12")
                    )
                );

                observe(&mut req, qlog, 5.0, !request_sent, &[
                    (":status", "103"),
                    ("content-length", "999"),
                ]);
                assert_eq!(req.status.inner.as_deref(), Some("103"));
                assert_eq!(req.final_response_headers_time(), None);
                assert_eq!(req.server_content_length.inner, None);
                observe(&mut req, qlog, 8.0, !request_sent, &[
                    (":status", "200"),
                    ("priority", "u=4"),
                    ("content-length", "120"),
                ]);
                observe(&mut req, qlog, 6.0, !request_sent, &[
                    (":status", "100"),
                    ("content-length", "1"),
                ]);
                observe(&mut req, qlog, 12.0, !request_sent, &[
                    ("grpc-status", "0"),
                    ("content-length", "17"),
                    ("priority", ""),
                ]);
                observe(&mut req, qlog, 11.0, !request_sent, &[(
                    "priority", "u=2",
                )]);
                assert_eq!(req.status.inner.as_deref(), Some("200"));
                assert_eq!(req.server_pri_hdr.inner.as_deref(), Some(""));
                assert_eq!(
                    req.server_content_length.inner.as_deref(),
                    Some("120")
                );
                assert_eq!(req.final_response_headers_time(), Some(8.0));
                assert_eq!(req.response_headers_time(), Some(5.0));
                assert_eq!(req.last_response_activity(), Some(12.0));
                // Earlier final metadata replaces the entire selected block,
                // including removal of a Content-Length not present there.
                observe(&mut req, qlog, 7.0, !request_sent, &[(
                    ":status", "204",
                )]);
                assert_eq!(req.status.inner.as_deref(), Some("204"));
                assert_eq!(req.server_content_length.inner, None);
                assert_eq!(req.final_response_headers_time(), Some(7.0));
            }
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
    fn reordered_headers_and_trailers_extend_observed_activity_not_delivery() {
        for actor in [RequestActor::Client, RequestActor::Server] {
            let response_sent = matches!(actor, RequestActor::Server);
            let mut req = HttpRequestStub {
                request_actor: actor,
                ..HttpRequestStub::default()
            };
            req.observe_headers(4.0, !response_sent);
            req.observe_headers(9.0, response_sent);
            req.observe_headers(7.0, response_sent);
            req.observe_headers(6.0, response_sent);
            assert_eq!(req.request_headers_time(), Some(4.0));
            assert_eq!(req.response_headers_time(), Some(6.0));
            assert_eq!(req.last_response_activity(), Some(9.0));
            assert_eq!(req.observed_response_end(), None);
            req.record_response_terminal(8.0);
            req.record_response_terminal(7.0);
            assert_eq!(req.time_response_terminal, Some(7.0));
            assert_eq!(req.observed_response_end(), Some(9.0));
            assert_eq!(req.fields()[9], "9");
        }
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
            let response_sent = matches!(req.request_actor, RequestActor::Server);
            req.observe_netlog_headers(10.0, response_sent, &[
                ":status: 200".into()
            ]);
            req.calculate_deltas();
            let fields = req.fields();
            assert_eq!(&fields[11..15], ["4", "4", "2", "8"]);
            assert_eq!(&fields[20..22], ["2", "4"]);
            assert_eq!(fields[9], "14");
        }
        Ok(())
    }
}
