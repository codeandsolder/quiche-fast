// Copyright (C) 2020, Cloudflare, Inc.
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

//! Quiche application utilities.
//!
//! This module provides some utility functions that are common to quiche
//! applications.

use crate::args::ClientArgs;
use crate::args::CommonArgs;
use std::io::prelude::*;

use std::collections::HashMap;

#[cfg(feature = "sfv")]
use std::convert::TryFrom;

use std::rc::Rc;

use std::cell::RefCell;

mod response;
use response::resource;
use response::ResponseBody;

use ring::rand::SecureRandom;

use quiche::ConnectionId;

use quiche::h3::NameValue;
use quiche::h3::Priority;

pub fn stdout_sink(out: &str) {
    print!("{out}");
}

const H3_MESSAGE_ERROR: u64 = 0x10E;
const H3_INTERNAL_ERROR: u64 = 0x102;

/// ALPN helpers.
///
/// This module contains constants and functions for working with ALPN.
pub mod alpns {
    pub const HTTP_09: [&[u8]; 2] = [b"hq-interop", b"http/0.9"];
    pub const HTTP_3: [&[u8]; 1] = [b"h3"];
}

pub struct PartialRequest {
    pub req: Vec<u8>,
}

pub struct PartialResponse {
    headers: Option<(Vec<quiche::h3::Header>, Priority)>,
    body: ResponseBody,
}

pub type ClientId = u64;

pub struct ServerClient {
    pub conn: quiche::Connection,

    pub http_conn: Option<Box<dyn HttpConn>>,

    pub id: ClientId,

    pub app_proto_selected: bool,

    pub partial_requests: std::collections::HashMap<u64, PartialRequest>,

    pub partial_responses: std::collections::HashMap<u64, PartialResponse>,

    pub loss_rate: f64,

    pub max_send_burst: usize,
}

pub type ClientIdMap = HashMap<ConnectionId<'static>, ClientId>;
pub type ClientMap = HashMap<ClientId, ServerClient>;

/// Open the output file for a response, propagating filesystem errors.
fn make_resource_writer(
    url: &url::Url, target_path: Option<&str>, cardinal: u64,
) -> std::io::Result<Option<std::io::BufWriter<std::fs::File>>> {
    let Some(directory) = target_path else {
        return Ok(None);
    };
    let resource = url
        .path_segments()
        .and_then(Iterator::last)
        .filter(|name| !name.is_empty())
        .unwrap_or("index.html");
    let filename = if cardinal > 1 {
        format!("{resource}.{cardinal}")
    } else {
        resource.to_owned()
    };
    let path = std::path::Path::new(directory).join(filename);
    std::fs::File::create(path)
        .map(std::io::BufWriter::new)
        .map(Some)
}

/// Open a buffered qlog writer.
///
/// # Errors
/// Returns filesystem errors when the log cannot be opened.
pub fn make_qlog_writer(
    dir: &std::ffi::OsStr, role: &str, id: &str,
) -> std::io::Result<std::io::BufWriter<std::fs::File>> {
    let path = std::path::Path::new(dir).join(format!("{role}-{id}.sqlog"));
    std::fs::File::create(path).map(std::io::BufWriter::new)
}

#[derive(serde::Serialize)]
struct JsonHeader<'a> {
    name: std::borrow::Cow<'a, str>,
    value: std::borrow::Cow<'a, str>,
}

#[derive(serde::Serialize)]
struct JsonRequest<'a> {
    headers: Vec<JsonHeader<'a>>,
}

#[derive(serde::Serialize)]
struct JsonResponse<'a> {
    headers: Vec<JsonHeader<'a>>,
    body: &'a [u8],
}

#[derive(serde::Serialize)]
struct JsonEntry<'a> {
    request: JsonRequest<'a>,
    response: JsonResponse<'a>,
}

#[derive(serde::Serialize)]
struct JsonReport<'a> {
    entries: Vec<JsonEntry<'a>>,
}

fn json_headers(headers: &[quiche::h3::Header]) -> Vec<JsonHeader<'_>> {
    headers
        .iter()
        .map(|header| JsonHeader {
            name: String::from_utf8_lossy(header.name()),
            value: String::from_utf8_lossy(header.value()),
        })
        .collect()
}

fn response_json(reqs: &[Http3Request]) -> serde_json::Result<String> {
    let entries = reqs
        .iter()
        .map(|req| JsonEntry {
            request: JsonRequest {
                headers: json_headers(&req.hdrs),
            },
            response: JsonResponse {
                headers: json_headers(&req.response_hdrs),
                body: &req.response_body,
            },
        })
        .collect();
    serde_json::to_string_pretty(&JsonReport { entries })
}

fn dump_json(reqs: &[Http3Request], output_sink: &mut dyn FnMut(&str)) {
    match response_json(reqs) {
        Ok(mut json) => {
            json.push('\n');
            output_sink(&json);
        },
        Err(error) => error!("cannot serialize HTTP response report: {error}"),
    }
}

#[must_use = "the converted headers are needed by the caller"]
pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}

/// Generate a new source connection ID and reset token.
///
/// # Errors
/// Returns an error if the random source cannot supply bytes.
pub fn generate_cid_and_reset_token<T: SecureRandom>(
    rng: &T,
) -> Result<(quiche::ConnectionId<'static>, u128), ring::error::Unspecified> {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid)?;
    let scid = scid.to_vec().into();
    let mut reset_token = [0; 16];
    rng.fill(&mut reset_token)?;
    let reset_token = u128::from_be_bytes(reset_token);
    Ok((scid, reset_token))
}

/// Validated RFC 9218 query overrides. Missing or invalid parameters do not
/// replace a valid header, and the same parsed values drive both directions.
#[derive(Default)]
struct PriorityQuery {
    urgency: Option<u8>,
    incremental: bool,
}

impl PriorityQuery {
    fn parse(url: &url::Url) -> Self {
        let mut query = Self::default();
        for (name, value) in url.query_pairs() {
            match name.as_ref() {
                "u" => {
                    if let Some(urgency) =
                        value.parse::<u8>().ok().filter(|urgency| *urgency <= 7)
                    {
                        query.urgency = Some(urgency);
                    }
                },
                "i" if value == "1" => query.incremental = true,
                _ => (),
            }
        }
        query
    }

    fn field_value(&self) -> Option<String> {
        match (self.urgency, self.incremental) {
            (Some(urgency), true) => Some(format!("u={urgency},i")),
            (Some(urgency), false) => Some(format!("u={urgency}")),
            (None, true) => Some("i".to_owned()),
            (None, false) => None,
        }
    }

    fn priority(&self) -> Option<Priority> {
        if self.urgency.is_some() || self.incremental {
            Some(Priority::new(self.urgency.unwrap_or(3), self.incremental))
        } else {
            None
        }
    }
}

/// Construct a priority field from validated query overrides.
#[must_use = "the query override should be applied to the request or response"]
pub fn priority_field_value_from_query_string(url: &url::Url) -> Option<String> {
    PriorityQuery::parse(url).field_value()
}

/// Construct a priority from validated query overrides.
#[must_use = "the query override should be applied to the request or response"]
pub fn priority_from_query_string(url: &url::Url) -> Option<Priority> {
    PriorityQuery::parse(url).priority()
}

fn send_h3_dgram(
    conn: &mut quiche::Connection, flow_id: u64, dgram_content: &[u8],
) -> quiche::Result<()> {
    info!(
        "sending HTTP/3 DATAGRAM on flow_id={flow_id} with data {dgram_content:?}"
    );

    let len = octets::varint_len(flow_id) + dgram_content.len();
    let mut d = vec![0; len];
    let mut b = octets::OctetsMut::with_slice(&mut d);

    b.put_varint(flow_id)
        .map_err(|_| quiche::Error::BufferTooShort)?;
    b.put_bytes(dgram_content)
        .map_err(|_| quiche::Error::BufferTooShort)?;

    conn.dgram_send(&d)
}

fn h3_datagram(bytes: &[u8]) -> octets::Result<(u64, &[u8])> {
    let mut reader = octets::Octets::with_slice(bytes);
    let flow_id = reader.get_varint()?;
    Ok((flow_id, &bytes[reader.off()..]))
}

fn receive_h3_datagrams(conn: &mut quiche::Connection, buf: &mut [u8]) {
    while let Ok(len) = conn.dgram_recv(buf) {
        match h3_datagram(&buf[..len]) {
            Ok((flow_id, data)) => info!(
                "Received DATAGRAM flow_id={flow_id} len={len} data={data:?}"
            ),
            Err(error) =>
                debug!("Discarding malformed HTTP/3 DATAGRAM: {error:?}"),
        }
    }
}

type OutputSink = Rc<RefCell<dyn FnMut(&str)>>;
type ResponseWriter = std::io::BufWriter<std::fs::File>;

fn write_response(
    writer: &mut Option<ResponseWriter>, bytes: &[u8], sink: Option<&OutputSink>,
) -> Result<(), String> {
    if let Some(writer) = writer {
        writer
            .write_all(bytes)
            .map_err(|error| format!("write response: {error}"))?;
    } else if let Some(sink) = sink {
        sink.borrow_mut()(&String::from_utf8_lossy(bytes));
    }
    Ok(())
}

fn finish_response(writer: &mut Option<ResponseWriter>) -> Result<(), String> {
    if let Some(mut writer) = writer.take() {
        writer
            .flush()
            .map_err(|error| format!("flush response: {error}"))?;
    }
    Ok(())
}

fn close_completed(
    conn: &mut quiche::Connection, code: u64, count: usize,
    start: &std::time::Instant,
) -> Result<(), String> {
    info!(
        "{count} responses received in {:?}, closing",
        start.elapsed()
    );
    match conn.close(true, code, b"kthxbye") {
        Ok(()) | Err(quiche::Error::Done) => Ok(()),
        Err(error) => Err(format!("close connection: {error}")),
    }
}

pub trait HttpConn {
    /// Send available requests and retain blocked progress.
    ///
    /// # Errors
    /// Returns transport or response-output errors.
    fn send_requests(
        &mut self, conn: &mut quiche::Connection, target_path: Option<&str>,
    ) -> Result<(), String>;

    /// Process received responses.
    ///
    /// # Errors
    /// Returns invalid stream, transport or output errors.
    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    ) -> Result<(), String>;

    fn report_incomplete(&self, start: &std::time::Instant) -> bool;

    /// Process incoming request streams.
    ///
    /// # Errors
    /// Returns HTTP protocol or transport errors.
    fn handle_requests(
        &mut self, conn: &mut quiche::Connection,
        partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        index: &str, buf: &mut [u8],
    ) -> quiche::h3::Result<()>;

    fn handle_writable(
        &mut self, conn: &mut quiche::Connection,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    );
}

pub fn writable_response_streams(
    conn: &quiche::Connection,
) -> impl Iterator<Item = u64> {
    conn.writable().filter(|id| id % 4 == 0)
}

/// Represents an HTTP/0.9 formatted request.
pub struct Http09Request {
    url: url::Url,
    cardinal: u64,
    request_line: String,
    sent: usize,
    stream_id: Option<u64>,
    complete: bool,
    response_writer: Option<std::io::BufWriter<std::fs::File>>,
}

/// Represents an HTTP/3 formatted request.
struct Http3Request {
    url: url::Url,
    cardinal: u64,
    stream_id: Option<u64>,
    hdrs: Vec<quiche::h3::Header>,
    complete: bool,
    priority: Option<Priority>,
    response_hdrs: Vec<quiche::h3::Header>,
    response_body: Vec<u8>,
    response_body_max: usize,
    response_writer: Option<std::io::BufWriter<std::fs::File>>,
}

type Http3ResponseBuilderResult = std::result::Result<
    (Vec<quiche::h3::Header>, ResponseBody, Vec<u8>),
    (u64, String),
>;

pub struct Http09Conn {
    stream_id: u64,
    reqs_sent: usize,
    reqs_complete: usize,
    completion_reported: bool,
    reqs: Vec<Http09Request>,
    output_sink: OutputSink,
}

impl Default for Http09Conn {
    fn default() -> Self {
        Self {
            stream_id: Default::default(),
            reqs_sent: Default::default(),
            reqs_complete: 0,
            completion_reported: false,
            reqs: Vec::new(),
            output_sink: Rc::new(RefCell::new(stdout_sink)),
        }
    }
}

impl Http09Conn {
    pub fn with_urls(
        urls: &[url::Url], reqs_cardinal: u64, output_sink: OutputSink,
    ) -> Box<dyn HttpConn> {
        let mut reqs = Vec::new();
        for url in urls {
            for i in 1..=reqs_cardinal {
                let request_line = format!("GET {}\r\n", url.path());
                reqs.push(Http09Request {
                    url: url.clone(),
                    cardinal: i,
                    request_line,
                    sent: 0,
                    stream_id: None,
                    complete: false,
                    response_writer: None,
                });
            }
        }

        let h_conn = Self {
            stream_id: 0,
            reqs_sent: 0,
            reqs_complete: 0,
            completion_reported: false,
            reqs,
            output_sink,
        };

        Box::new(h_conn)
    }
}

impl HttpConn for Http09Conn {
    fn send_requests(
        &mut self, conn: &mut quiche::Connection, target_path: Option<&str>,
    ) -> Result<(), String> {
        for req in self.reqs.iter_mut().skip(self.reqs_sent) {
            let written = match conn.stream_send(
                self.stream_id,
                &req.request_line.as_bytes()[req.sent..],
                true,
            ) {
                Ok(written) => written,
                Err(quiche::Error::StreamLimit | quiche::Error::Done) => break,
                Err(error) =>
                    return Err(format!("send HTTP/0.9 request: {error}")),
            };
            if req.stream_id.is_none() {
                req.stream_id = Some(self.stream_id);
                req.response_writer =
                    make_resource_writer(&req.url, target_path, req.cardinal)
                        .map_err(|error| {
                            format!("response output for {}: {error}", req.url)
                        })?;
            }
            req.sent += written;
            if req.sent < req.request_line.len() {
                break;
            }
            self.stream_id += 4;
            self.reqs_sent += 1;
        }
        Ok(())
    }

    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    ) -> Result<(), String> {
        for stream_id in conn.readable() {
            let req = self
                .reqs
                .iter_mut()
                .find(|req| req.stream_id == Some(stream_id))
                .ok_or_else(|| {
                    format!("unexpected HTTP/0.9 response stream {stream_id}")
                })?;
            loop {
                let (read, fin) = match conn.stream_recv(stream_id, buf) {
                    Ok(value) => value,
                    Err(quiche::Error::Done) => break,
                    Err(error) =>
                        return Err(format!(
                            "receive stream {stream_id}: {error}"
                        )),
                };
                write_response(
                    &mut req.response_writer,
                    &buf[..read],
                    Some(&self.output_sink),
                )?;
                if fin {
                    if !req.complete {
                        finish_response(&mut req.response_writer)?;
                        req.complete = true;
                        self.reqs_complete += 1;
                    }
                    break;
                }
            }
        }
        if self.reqs_complete == self.reqs.len() && !self.completion_reported {
            self.completion_reported = true;
            close_completed(conn, 0, self.reqs_complete, req_start)?;
        }
        Ok(())
    }

    fn report_incomplete(&self, start: &std::time::Instant) -> bool {
        if self.reqs_complete != self.reqs.len() {
            error!(
                "connection timed out after {:?} and only completed {}/{} requests",
                start.elapsed(),
                self.reqs_complete,
                self.reqs.len()
            );

            return true;
        }

        false
    }

    fn handle_requests(
        &mut self, conn: &mut quiche::Connection,
        partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        index: &str, buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        const MAX_REQUEST_LINE: usize = 16 * 1024;

        for stream_id in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(stream_id, buf) {
                let partial = partial_requests
                    .entry(stream_id)
                    .or_insert_with(|| PartialRequest { req: Vec::new() });
                if partial.req.len().saturating_add(read) > MAX_REQUEST_LINE {
                    partial_requests.remove(&stream_id);
                    reject_http09(conn, stream_id);
                    break;
                }
                partial.req.extend_from_slice(&buf[..read]);
                if !partial.req.ends_with(b"\r\n") {
                    if fin {
                        partial_requests.remove(&stream_id);
                        reject_http09(conn, stream_id);
                        break;
                    }
                    continue;
                }
                let request = partial_requests
                    .remove(&stream_id)
                    .ok_or(quiche::h3::Error::Internal)?;
                let uri = request
                    .req
                    .strip_prefix(b"GET ")
                    .and_then(|request| request.strip_suffix(b"\r\n"))
                    .and_then(|request| std::str::from_utf8(request).ok())
                    .filter(|uri| {
                        uri.starts_with('/') && !uri.contains(['\r', '\n'])
                    });
                let Some(uri) = uri else {
                    reject_http09(conn, stream_id);
                    break;
                };
                let body = resource(root, uri, index)
                    .unwrap_or_else(|_| ResponseBody::bytes(b"Not Found!\r\n"));
                partial_responses.insert(stream_id, PartialResponse {
                    headers: None,
                    body,
                });
                // HTTP/0.9 has one request line per stream.
                let _ =
                    conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0);
                break;
            }
        }
        for stream_id in writable_response_streams(conn) {
            self.handle_writable(conn, partial_responses, stream_id);
        }
        Ok(())
    }

    fn handle_writable(
        &mut self, conn: &mut quiche::Connection,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    ) {
        send_pending_body(
            conn,
            partial_responses,
            stream_id,
            0,
            |conn, bytes, fin| {
                conn.stream_send(stream_id, bytes, fin).map_err(Into::into)
            },
        );
    }
}

fn reject_http09(conn: &mut quiche::Connection, stream_id: u64) {
    let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0);
    let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0);
}

fn send_pending_body(
    conn: &mut quiche::Connection,
    partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    reset_code: u64,
    mut write: impl FnMut(
        &mut quiche::Connection,
        &[u8],
        bool,
    ) -> quiche::h3::Result<usize>,
) {
    let Some(response) = partial_responses.get_mut(&stream_id) else {
        return;
    };
    match response.body.send(|bytes, fin| write(conn, bytes, fin)) {
        Ok(false) => (),
        Ok(true) => {
            partial_responses.remove(&stream_id);
        },
        Err(error) => {
            error!("{} response stream {stream_id}: {error}", conn.trace_id());
            partial_responses.remove(&stream_id);
            let _ = conn.stream_shutdown(
                stream_id,
                quiche::Shutdown::Write,
                reset_code,
            );
        },
    }
}

pub struct Http3DgramSender {
    dgram_count: u64,
    pub dgram_content: String,
    pub flow_id: u64,
    pub dgrams_sent: u64,
}

impl Http3DgramSender {
    #[must_use = "the sender retains datagram workload progress"]
    pub const fn new(
        dgram_count: u64, dgram_content: String, flow_id: u64,
    ) -> Self {
        Self {
            dgram_count,
            dgram_content,
            flow_id,
            dgrams_sent: 0,
        }
    }

    fn send_available(&mut self, conn: &mut quiche::Connection) {
        while self.dgrams_sent < self.dgram_count {
            match send_h3_dgram(conn, self.flow_id, self.dgram_content.as_bytes())
            {
                Ok(()) => self.dgrams_sent += 1,
                Err(error) => {
                    debug!("DATAGRAM send deferred: {error}");
                    break;
                },
            }
        }
    }
}

fn make_h3_config(
    max_field_section_size: Option<u64>, qpack_max_table_capacity: Option<u64>,
    qpack_blocked_streams: Option<u64>,
) -> quiche::h3::Config {
    let mut config = quiche::h3::Config::new();

    if let Some(v) = max_field_section_size {
        config.set_max_field_section_size(v);
    }

    if let Some(v) = qpack_max_table_capacity {
        // quiche doesn't support dynamic QPACK, so clamp to 0 for now.
        config.set_qpack_max_table_capacity(v.clamp(0, 0));
    }

    if let Some(v) = qpack_blocked_streams {
        // quiche doesn't support dynamic QPACK, so clamp to 0 for now.
        config.set_qpack_blocked_streams(v.clamp(0, 0));
    }

    config
}

type MessageError = (u64, String);

fn message_error(message: impl Into<String>) -> MessageError {
    (H3_MESSAGE_ERROR, message.into())
}

#[derive(Default)]
struct RequestFields<'a> {
    scheme: Option<&'a str>,
    authority: Option<&'a str>,
    host: Option<&'a str>,
    path: Option<&'a str>,
    method: Option<&'a str>,
    priority: Vec<u8>,
}

impl<'a> RequestFields<'a> {
    fn parse(headers: &'a [quiche::h3::Header]) -> Result<Self, MessageError> {
        let mut fields = Self::default();
        for header in headers {
            let (slot, name) = match header.name() {
                b":scheme" => (&mut fields.scheme, ":scheme"),
                b":authority" => (&mut fields.authority, ":authority"),
                b":path" => (&mut fields.path, ":path"),
                b":method" => (&mut fields.method, ":method"),
                b"host" => (&mut fields.host, "host"),
                b":protocol" =>
                    return Err(message_error(":protocol not supported")),
                b"priority" => {
                    fields.priority = header.value().to_vec();
                    continue;
                },
                _ => continue,
            };
            let value = std::str::from_utf8(header.value())
                .map_err(|error| message_error(format!("{name}: {error}")))?;
            if slot.replace(value).is_some() {
                return Err(message_error(format!(
                    "{name} cannot be duplicated"
                )));
            }
        }
        Ok(fields)
    }
}

pub struct Http3Conn {
    h3_conn: quiche::h3::Connection,
    reqs_hdrs_sent: usize,
    reqs_complete: usize,
    completion_reported: bool,
    largest_processed_request: u64,
    reqs: Vec<Http3Request>,
    body: Option<Vec<u8>>,
    sent_body_bytes: HashMap<u64, usize>,
    dump_json: bool,
    dgram_sender: Option<Http3DgramSender>,
    output_sink: OutputSink,
}

fn request_headers(
    url: &url::Url, args: &ClientArgs,
) -> Result<Vec<quiche::h3::Header>, String> {
    let host = url
        .host_str()
        .ok_or_else(|| format!("URL has no host: {url}"))?;
    let authority = url
        .port()
        .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"));
    let target = &url[url::Position::BeforePath..url::Position::AfterQuery];
    let mut headers = vec![
        quiche::h3::Header::new(b":method", args.method.as_bytes()),
        quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
        quiche::h3::Header::new(b":path", target.as_bytes()),
        quiche::h3::Header::new(b"user-agent", b"quiche"),
    ];
    for header in &args.req_headers {
        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| format!("malformed header: {header}"))?;
        if name.is_empty() ||
            !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
            }) ||
            value.contains(['\r', '\n', '\0'])
        {
            return Err(format!("invalid header: {header}"));
        }
        headers.push(quiche::h3::Header::new(
            name.to_ascii_lowercase().as_bytes(),
            value.trim_matches([' ', '\t']).as_bytes(),
        ));
    }
    if let Some(body) = &args.body {
        headers.push(quiche::h3::Header::new(
            b"content-length",
            body.len().to_string().as_bytes(),
        ));
    }
    Ok(headers)
}

impl Http3Conn {
    /// Create a client HTTP/3 session and validated requests.
    ///
    /// # Errors
    /// Returns invalid request parameters or HTTP/3 initialization errors.
    pub fn with_urls(
        conn: &mut quiche::Connection, args: &ClientArgs, common: &CommonArgs,
        output_sink: OutputSink,
    ) -> Result<Box<dyn HttpConn>, String> {
        let mut reqs = Vec::new();
        for url in &args.urls {
            let hdrs = request_headers(url, args)?;
            let priority = args
                .send_priority_update
                .then(|| priority_from_query_string(url))
                .flatten();
            for cardinal in 1..=args.reqs_cardinal {
                reqs.push(Http3Request {
                    url: url.clone(),
                    cardinal,
                    hdrs: hdrs.clone(),
                    priority,
                    complete: false,
                    response_hdrs: Vec::new(),
                    response_body: Vec::new(),
                    response_body_max: args.dump_json.unwrap_or_default(),
                    stream_id: None,
                    response_writer: None,
                });
            }
        }
        let mut session = Self::new(conn, common, 0, output_sink)?;
        session.reqs = reqs;
        session.body = args.body.clone().filter(|body| !body.is_empty());
        session.dump_json = args.dump_json.is_some();
        Ok(Box::new(session))
    }

    /// Create a server HTTP/3 session.
    ///
    /// # Errors
    /// Returns HTTP/3 initialization errors.
    pub fn with_conn(
        conn: &mut quiche::Connection, common: &CommonArgs,
        output_sink: OutputSink,
    ) -> Result<Box<dyn HttpConn>, String> {
        Ok(Box::new(Self::new(conn, common, 1, output_sink)?))
    }

    fn new(
        conn: &mut quiche::Connection, common: &CommonArgs, flow_id: u64,
        output_sink: OutputSink,
    ) -> Result<Self, String> {
        let h3_conn = quiche::h3::Connection::with_transport(
            conn,
            &make_h3_config(
                common.max_field_section_size,
                common.qpack_max_table_capacity,
                common.qpack_blocked_streams,
            ),
        )
        .map_err(|error| format!("initialize HTTP/3: {error}"))?;
        Ok(Self {
            h3_conn,
            reqs_hdrs_sent: 0,
            reqs_complete: 0,
            completion_reported: false,
            largest_processed_request: 0,
            reqs: Vec::new(),
            body: None,
            sent_body_bytes: HashMap::new(),
            dump_json: false,
            dgram_sender: common.datagrams.as_ref().map(|settings| {
                Http3DgramSender::new(
                    settings.count,
                    settings.data.clone(),
                    flow_id,
                )
            }),
            output_sink,
        })
    }

    /// Builds an HTTP/3 response given a request.
    fn build_h3_response(
        root: &str, index: &str, request: &[quiche::h3::Header],
    ) -> Http3ResponseBuilderResult {
        let RequestFields {
            scheme,
            authority,
            host,
            path,
            method,
            mut priority,
        } = RequestFields::parse(request)?;

        let method = required_field(method, ":method")?;
        if method == "CONNECT" {
            return Ok(response_parts(405, ResponseBody::bytes(b""), Vec::new()));
        }

        let scheme = required_field(scheme, ":scheme")?;
        if scheme != "http" && scheme != "https" {
            return Ok(response_parts(
                400,
                ResponseBody::bytes(b"Invalid scheme"),
                Vec::new(),
            ));
        }

        let decided_host = authority
            .filter(|value| !value.is_empty())
            .or_else(|| host.filter(|value| !value.is_empty()))
            .ok_or_else(|| {
                message_error("missing or empty :authority and host")
            })?;

        if decided_host.chars().any(|character| {
            character.is_whitespace() ||
                character.is_control() ||
                matches!(character, '/' | '?' | '#' | '@' | '\\')
        }) {
            return Err(message_error("invalid request authority"));
        }

        let target = required_field(path, ":path")?;
        if !target.starts_with('/') ||
            target.chars().any(|character| {
                character.is_control() || matches!(character, '#' | '\\')
            })
        {
            return Err(message_error("invalid absolute request path"));
        }
        let url = format!("{scheme}://{decided_host}{target}");
        let url = url::Url::parse(&url).map_err(|error| {
            message_error(format!("invalid request URL: {error}"))
        })?;

        // Priority query string takes precedence over the header.
        // So replace the header with one built here.
        let query_priority = priority_field_value_from_query_string(&url);

        if let Some(p) = query_priority {
            priority = p.as_bytes().to_vec();
        }

        let (status, body) = response_content(root, index, method, url.path());
        Ok(response_parts(status, body, priority))
    }

    fn prepare_response(
        &mut self, conn: &mut quiche::Connection, stream_id: u64, root: &str,
        index: &str, request: &[quiche::h3::Header],
    ) -> Option<PartialResponse> {
        info!(
            "{} got request {:?} on stream {stream_id}",
            conn.trace_id(),
            hdrs_to_strings(request)
        );
        self.largest_processed_request =
            self.largest_processed_request.max(stream_id);
        // The server chooses a response based on the headers alone.
        let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0);
        let (mut headers, body, mut priority) =
            match Self::build_h3_response(root, index, request) {
                Ok(value) => value,
                Err((code, message)) => {
                    debug!(
                        "{} invalid request on {stream_id}: {message}",
                        conn.trace_id()
                    );
                    let _ = conn.stream_shutdown(
                        stream_id,
                        quiche::Shutdown::Write,
                        code,
                    );
                    return None;
                },
            };
        match self.h3_conn.take_last_priority_update(stream_id) {
            Ok(value) => priority = value,
            Err(quiche::h3::Error::Done) => (),
            Err(error) => error!(
                "{} error taking PRIORITY_UPDATE: {error}",
                conn.trace_id()
            ),
        }
        if !priority.is_empty() {
            headers.push(quiche::h3::Header::new(b"priority", &priority));
        }
        #[cfg(feature = "sfv")]
        let priority =
            Priority::try_from(priority.as_slice()).unwrap_or_default();
        #[cfg(not(feature = "sfv"))]
        let priority = Priority::default();
        info!(
            "{} response on {stream_id} priority {priority:?}",
            conn.trace_id()
        );
        Some(PartialResponse {
            headers: Some((headers, priority)),
            body,
        })
    }
}

fn required_field<'a>(
    value: Option<&'a str>, name: &str,
) -> Result<&'a str, MessageError> {
    value.filter(|value| !value.is_empty()).ok_or_else(|| {
        message_error(format!("{name} cannot be missing or empty"))
    })
}

fn response_parts(
    status: u16, body: ResponseBody, priority: Vec<u8>,
) -> (Vec<quiche::h3::Header>, ResponseBody, Vec<u8>) {
    let headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"server", b"quiche"),
        quiche::h3::Header::new(
            b"content-length",
            body.len().to_string().as_bytes(),
        ),
    ];
    (headers, body, priority)
}

fn generated_response(suffix: &str) -> (u16, ResponseBody) {
    match suffix.parse::<u64>() {
        Ok(count) if count < (1_u64 << 62) =>
            (200, ResponseBody::repeat(0x57, count)),
        _ => (400, ResponseBody::bytes(b"Invalid stream length")),
    }
}

fn response_content(
    root: &str, index: &str, method: &str, path: &str,
) -> (u16, ResponseBody) {
    if method != "GET" {
        return (405, ResponseBody::bytes(b""));
    }
    path.strip_prefix("/stream-bytes/").map_or_else(
        || match resource(root, path, index) {
            Ok(body) => (200, body),
            Err(_) => (404, ResponseBody::bytes(b"Not Found!")),
        },
        generated_response,
    )
}

impl HttpConn for Http3Conn {
    fn send_requests(
        &mut self, conn: &mut quiche::Connection, target_path: Option<&str>,
    ) -> Result<(), String> {
        for req in self.reqs.iter_mut().skip(self.reqs_hdrs_sent) {
            let stream_id = match self.h3_conn.send_request(
                conn,
                &req.hdrs,
                self.body.is_none(),
            ) {
                Ok(value) => value,
                Err(
                    quiche::h3::Error::Transport(quiche::Error::StreamLimit) |
                    quiche::h3::Error::StreamBlocked |
                    quiche::h3::Error::Done,
                ) => break,
                Err(error) =>
                    return Err(format!("send HTTP/3 request: {error}")),
            };
            if let Some(priority) = req.priority {
                let _ = self
                    .h3_conn
                    .send_priority_update_for_request(conn, stream_id, priority);
            }
            req.stream_id = Some(stream_id);
            req.response_writer =
                make_resource_writer(&req.url, target_path, req.cardinal)
                    .map_err(|error| {
                        format!("response output for {}: {error}", req.url)
                    })?;
            if self.body.is_some() {
                self.sent_body_bytes.insert(stream_id, 0);
            }
            self.reqs_hdrs_sent += 1;
        }
        if let Some(body) = &self.body {
            for (stream_id, sent) in &mut self.sent_body_bytes {
                if *sent == body.len() {
                    continue;
                }
                match self.h3_conn.send_body(
                    conn,
                    *stream_id,
                    &body[*sent..],
                    true,
                ) {
                    Ok(written) => *sent += written,
                    Err(
                        quiche::h3::Error::Done |
                        quiche::h3::Error::StreamBlocked,
                    ) => (),
                    // Servers may deliberately stop reading the request body
                    // when they can respond based on headers alone.
                    Err(quiche::h3::Error::Transport(
                        quiche::Error::StreamStopped(_),
                    )) => *sent = body.len(),
                    Err(error) =>
                        return Err(format!(
                            "send request body on {stream_id}: {error}"
                        )),
                }
            }
            self.sent_body_bytes.retain(|_, sent| *sent < body.len());
        }
        if let Some(sender) = &mut self.dgram_sender {
            sender.send_available(conn);
        }
        Ok(())
    }

    fn handle_responses(
        &mut self, conn: &mut quiche::Connection, buf: &mut [u8],
        req_start: &std::time::Instant,
    ) -> Result<(), String> {
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    let req = self
                        .reqs
                        .iter_mut()
                        .find(|req| req.stream_id == Some(stream_id))
                        .ok_or_else(|| {
                            format!("unexpected response headers on {stream_id}")
                        })?;
                    req.response_hdrs.extend(list);
                },
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    let req = self
                        .reqs
                        .iter_mut()
                        .find(|req| req.stream_id == Some(stream_id))
                        .ok_or_else(|| {
                            format!("unexpected response data on {stream_id}")
                        })?;
                    loop {
                        let read =
                            match self.h3_conn.recv_body(conn, stream_id, buf) {
                                Ok(read) => read,
                                Err(quiche::h3::Error::Done) => break,
                                Err(error) =>
                                    return Err(format!(
                                    "receive response on {stream_id}: {error}"
                                )),
                            };
                        let len = read.min(
                            req.response_body_max
                                .saturating_sub(req.response_body.len()),
                        );
                        req.response_body.extend_from_slice(&buf[..len]);
                        write_response(
                            &mut req.response_writer,
                            &buf[..read],
                            (!self.dump_json).then_some(&self.output_sink),
                        )?;
                    }
                },
                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    let req = self
                        .reqs
                        .iter_mut()
                        .find(|req| req.stream_id == Some(stream_id))
                        .ok_or_else(|| {
                            format!("unexpected finished response on {stream_id}")
                        })?;
                    if !req.complete {
                        finish_response(&mut req.response_writer)?;
                        req.complete = true;
                        self.reqs_complete += 1;
                    }
                    self.sent_body_bytes.remove(&stream_id);
                },
                Ok((stream_id, quiche::h3::Event::Reset(code))) => {
                    return Err(format!(
                        "request {stream_id} reset by peer: {code}"
                    ));
                },
                Ok((stream_id, quiche::h3::Event::PriorityUpdate)) => {
                    info!("{} PRIORITY_UPDATE on {stream_id}", conn.trace_id());
                },
                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                    info!("{} GOAWAY {goaway_id}", conn.trace_id());
                },
                Err(quiche::h3::Error::Done) => break,
                Err(error) => return Err(format!("HTTP/3 processing: {error}")),
            }
        }
        receive_h3_datagrams(conn, buf);
        if self.reqs_complete == self.reqs.len() && !self.completion_reported {
            self.completion_reported = true;
            if self.dump_json {
                dump_json(&self.reqs, &mut *self.output_sink.borrow_mut());
            }
            close_completed(conn, 0x100, self.reqs_complete, req_start)?;
        }
        Ok(())
    }

    fn report_incomplete(&self, start: &std::time::Instant) -> bool {
        if self.reqs_complete != self.reqs.len() {
            error!(
                "connection timed out after {:?} and only completed {}/{} requests",
                start.elapsed(),
                self.reqs_complete,
                self.reqs.len()
            );

            if self.dump_json {
                dump_json(&self.reqs, &mut *self.output_sink.borrow_mut());
            }

            return true;
        }

        false
    }

    fn handle_requests(
        &mut self, conn: &mut quiche::Connection,
        _partial_requests: &mut HashMap<u64, PartialRequest>,
        partial_responses: &mut HashMap<u64, PartialResponse>, root: &str,
        index: &str, buf: &mut [u8],
    ) -> quiche::h3::Result<()> {
        // Process HTTP stream-related events.
        //
        // This loops over any and all received HTTP requests and sends just the
        // HTTP response headers.
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) =>
                    if let Some(response) =
                        self.prepare_response(conn, stream_id, root, index, &list)
                    {
                        partial_responses.insert(stream_id, response);
                        self.handle_writable(conn, partial_responses, stream_id);
                    },

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    info!("{} got data on stream {stream_id}", conn.trace_id());
                },

                Ok((_stream_id, quiche::h3::Event::Finished)) => (),

                Ok((stream_id, quiche::h3::Event::Reset { .. })) => {
                    partial_responses.remove(&stream_id);
                },

                Ok((
                    prioritized_element_id,
                    quiche::h3::Event::PriorityUpdate,
                )) => {
                    info!("{} PRIORITY_UPDATE triggered for {prioritized_element_id}", conn.trace_id());
                },

                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                    trace!("{} got GOAWAY {goaway_id}", conn.trace_id());
                    self.h3_conn
                        .send_goaway(conn, self.largest_processed_request)?;
                },

                Err(quiche::h3::Error::Done) => {
                    break;
                },

                Err(e) => {
                    error!("{} HTTP/3 error {e:?}", conn.trace_id());

                    return Err(e);
                },
            }
        }

        // Visit all writable response streams to send HTTP content.
        for stream_id in writable_response_streams(conn) {
            self.handle_writable(conn, partial_responses, stream_id);
        }

        receive_h3_datagrams(conn, buf);

        if let Some(sender) = &mut self.dgram_sender {
            sender.send_available(conn);
        }

        Ok(())
    }

    fn handle_writable(
        &mut self, conn: &mut quiche::Connection,
        partial_responses: &mut HashMap<u64, PartialResponse>, stream_id: u64,
    ) {
        let Some(response) = partial_responses.get_mut(&stream_id) else {
            return;
        };
        if let Some((headers, priority)) = &response.headers {
            match self.h3_conn.send_response_with_priority(
                conn, stream_id, headers, *priority, false,
            ) {
                Ok(()) => (),
                Err(quiche::h3::Error::StreamBlocked) => return,
                Err(error) => {
                    error!(
                        "{} response headers on {stream_id}: {error}",
                        conn.trace_id()
                    );
                    partial_responses.remove(&stream_id);
                    return;
                },
            }
        }
        response.headers = None;
        send_pending_body(
            conn,
            partial_responses,
            stream_id,
            H3_INTERNAL_ERROR,
            |conn, bytes, fin| {
                self.h3_conn.send_body(conn, stream_id, bytes, fin)
            },
        );
    }
}

#[cfg(test)]
mod input_output_tests {
    use super::h3_datagram;
    use super::priority_field_value_from_query_string;
    use super::priority_from_query_string;
    use super::response_json;
    use super::Http3Conn;
    use super::Http3Request;
    use super::H3_MESSAGE_ERROR;
    use quiche::h3::Header;
    use quiche::h3::NameValue;
    use quiche::h3::Priority;

    #[test]
    fn json_report_escapes_all_strings_and_preserves_payload(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let req = Http3Request {
            url: url::Url::parse("https://example.org/")?,
            cardinal: 1,
            stream_id: None,
            complete: false,
            hdrs: vec![Header::new(b"x-request", b"quote\"\\\t\n")],
            priority: None,
            response_hdrs: vec![Header::new(b"x-response", b"\xff\r\n")],
            response_body: vec![0, 128, 255],
            response_body_max: 3,
            response_writer: None,
        };
        let json: serde_json::Value =
            serde_json::from_str(&response_json(&[req])?)?;
        assert_eq!(
            json["entries"][0]["request"]["headers"][0]["value"],
            "quote\"\\\t\n"
        );
        assert_eq!(
            json["entries"][0]["response"]["headers"][0]["value"],
            "\u{fffd}\r\n"
        );
        assert_eq!(
            json["entries"][0]["response"]["body"],
            serde_json::json!([0, 128, 255])
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response_json(&[])?)?,
            serde_json::json!({"entries": []})
        );
        Ok(())
    }

    #[test]
    fn query_priority_is_validated_consistently() -> Result<(), url::ParseError> {
        for (query, field, priority) in [
            ("u=7&i=1", Some("u=7,i"), Some(Priority::new(7, true))),
            ("i=1", Some("i"), Some(Priority::new(3, true))),
            ("u=0", Some("u=0"), Some(Priority::new(0, false))),
            ("u=bad&i=0", None, None),
            ("u=255", None, None),
            ("u=1%2Ci", None, None),
            ("u=2&u=3", Some("u=3"), Some(Priority::new(3, false))),
        ] {
            let url = url::Url::parse(&format!("https://example.org/?{query}"))?;
            assert_eq!(
                priority_field_value_from_query_string(&url).as_deref(),
                field
            );
            assert_eq!(priority_from_query_string(&url), priority);
        }
        Ok(())
    }

    #[test]
    fn request_header_errors_are_returned_and_host_fallback_works(
    ) -> Result<(), String> {
        let valid = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"https"),
            Header::new(b"host", b"example.org"),
            Header::new(b":path", b"/stream-bytes/3"),
        ];
        let (headers, mut body, _) =
            Http3Conn::build_h3_response(".", "index.html", &valid)
                .map_err(|(_, message)| message)?;
        assert!(headers.iter().any(
            |header| header.name() == b":status" && header.value() == b"200"
        ));
        let mut received = Vec::new();
        assert!(body
            .send(|bytes, fin| {
                assert!(fin);
                received.extend_from_slice(bytes);
                Ok(bytes.len())
            })
            .map_err(|error| error.to_string())?);
        assert_eq!(received, [0x57; 3]);
        for invalid in [
            Header::new(b":path", b"/duplicate"),
            Header::new(b":authority", b"\xff"),
            Header::new(b":authority", b"[invalid"),
        ] {
            let mut request = valid.clone();
            request.push(invalid);
            assert!(matches!(
                Http3Conn::build_h3_response(".", "index.html", &request),
                Err((H3_MESSAGE_ERROR, _))
            ));
        }
        let mut request = valid;
        request[3] = Header::new(b":path", b"not-an-absolute-path");
        assert!(matches!(
            Http3Conn::build_h3_response(".", "index.html", &request),
            Err((H3_MESSAGE_ERROR, _))
        ));
        Ok(())
    }

    #[test]
    fn truncated_datagrams_cannot_read_stale_buffer_bytes() -> octets::Result<()>
    {
        assert!(h3_datagram(&[]).is_err());
        assert!(h3_datagram(&[0x40]).is_err());
        assert_eq!(h3_datagram(&[0x40, 0x40, 7, 8])?, (64, &[7, 8][..]));
        assert_eq!(h3_datagram(&[0])?, (0, &[][..]));
        Ok(())
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::finish_response;
    use super::make_resource_writer;
    use super::request_headers;
    use super::write_response;
    use crate::args::ClientArgs;
    use quiche::h3::NameValue;

    #[test]
    fn request_headers_exclude_fragment_and_validate_names(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = url::Url::parse("https://[::1]:8443/a?q=1#local")?;
        let mut args = ClientArgs {
            req_headers: vec!["X-Test: a:b".to_owned(), "empty:".to_owned()],
            body: Some(Vec::new()),
            ..ClientArgs::default()
        };
        let headers = request_headers(&url, &args)?;
        for (name, value) in [
            (b":authority".as_slice(), b"[::1]:8443".as_slice()),
            (b":path", b"/a?q=1"),
            (b"x-test", b"a:b"),
            (b"empty", b""),
            (b"content-length", b"0"),
        ] {
            assert!(headers
                .iter()
                .any(|header| header.name() == name && header.value() == value));
        }
        for invalid in [
            "missing-colon",
            ":authority: wrong",
            "bad name: x",
            "x: a\r\nb: c",
        ] {
            args.req_headers = vec![invalid.to_owned()];
            assert!(request_headers(&url, &args).is_err());
        }
        Ok(())
    }

    #[test]
    fn response_output_is_fallible_and_flushes_binary_content(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let url = url::Url::parse("https://example.org/")?;
        let directory_name =
            directory.path().to_str().ok_or("non-UTF8 fixture path")?;
        let mut writer = make_resource_writer(&url, Some(directory_name), 2)?;
        write_response(&mut writer, &[0, 128, 255], None)?;
        finish_response(&mut writer)?;
        assert!(writer.is_none());
        assert_eq!(std::fs::read(directory.path().join("index.html.2"))?, [
            0, 128, 255
        ]);
        let invalid = directory.path().join("missing");
        assert!(make_resource_writer(&url, invalid.to_str(), 1).is_err());
        Ok(())
    }
}
