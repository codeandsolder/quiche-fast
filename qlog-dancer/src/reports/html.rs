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

//! Reporting (tables etc.)

use tabled::Table;

use crate::create_file_recursive;
use crate::reports::events::event_list as build_event_list;
use crate::reports::text::request_timing_table;
use crate::AppConfig;
use crate::LogFileParseResult;
use std::io::Write;

const HTML_INCLUDES: &str = r#"
<script src="https://code.jquery.com/jquery-3.7.0.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
<link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/5.3.0/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css">
<link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
"#;

const TABLE_INIT_SCRIPT: &str = r#"
<script>
window.addEventListener("DOMContentLoaded", () => {
    const theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    document.documentElement.classList.add(theme);
    document.documentElement.setAttribute('data-bs-theme', theme);
    // Reports remain readable even when the optional CDN scripts are offline.
    if (typeof DataTable !== 'undefined') {
        new DataTable('table.log-dancer-table', {
            paging: false,
            dom: '<"center" flpti  >',
            columnDefs: [{targets: 'numeric', type: 'html-num'}]
        });
    }
});
</script>
"#;

const SESSIONS_STYLES: &str = r"
<style>
    table { border-collapse: collapse; margin: 1rem auto; }
    th, td { padding: .25rem .5rem; border: 1px solid currentColor; white-space: pre-wrap; }
    .center {
  margin: auto;
  width: 90%;
  padding: 10px;
}

.yellow {
    color: yellow
}

.red {
    color: red
}

.green {
    color: limegreen
}
</style>
";

fn open_report_file(filename: &str) -> std::io::Result<std::fs::File> {
    create_file_recursive(filename).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("cannot create report {filename}: {error}"),
        )
    })
}

fn open_page(filename: &str, title: &str) -> std::io::Result<std::fs::File> {
    let mut file = open_report_file(filename)?;
    file.write_all(b"<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>")?;
    file.write_all(escape_html_cell(title).as_bytes())?;
    file.write_all(b"</title>\n")?;
    file.write_all(HTML_INCLUDES.as_bytes())?;
    file.write_all(SESSIONS_STYLES.as_bytes())?;
    file.write_all(TABLE_INIT_SCRIPT.as_bytes())?;
    file.write_all(b"</head><body>\n")?;
    Ok(file)
}

fn finish_page(mut file: std::fs::File) -> std::io::Result<()> {
    file.write_all(b"</body></html>\n")?;
    file.flush()
}

// Chrome netlog provides session IDs; qlog has independent trace identities.
#[derive(tabled::Tabled)]
struct TraceOverview<'a> {
    #[tabled(rename = "Trace")]
    number: usize,
    #[tabled(rename = "Title")]
    title: &'a str,
    #[tabled(rename = "Vantage point")]
    vantage: String,
    #[tabled(rename = "Events")]
    events: usize,
}

/// Generate the overview HTML report.
///
/// # Errors
/// Returns an I/O error if the report file cannot be created or written.
pub fn overview(
    log_file: &LogFileParseResult, config: &AppConfig,
) -> std::io::Result<()> {
    let filename = format!("{}-reports/overview.html", config.filename);
    let mut file = open_page(&filename, "Session overview")?;
    file.write_all(r#"        <div>
            <h1 class="center">Session Overview</h1>
            <p class="center">This page lists all the sessions (aka connections)
            that were present in a log file. It is possible to filter only specific
            SNIs for analysis using the qlog-dancer `--netlog-filter` option.</p>
            <p class ="center">Analysed session detailed information is presented in
            <a href="closures.html">session terminations</a>
            and <a href="requests.html">requests breakdown</a>.</p>
            "#.as_bytes())?;

    let all_table = if log_file.data.iter().any(|entry| entry.trace.is_some()) {
        Table::builder(log_file.data.iter().filter_map(|entry| {
            entry.trace.as_ref().map(|trace| TraceOverview {
                number: trace.index + 1,
                title: trace.title.as_deref().unwrap_or(""),
                vantage: format!("{:?}", trace.vantage_point),
                events: match &entry.raw {
                    crate::RawLogEvents::QlogJson { events } => events.len(),
                    crate::RawLogEvents::QlogJsonSeq { events } => events.len(),
                    crate::RawLogEvents::Netlog { events } => events.len(),
                },
            })
        }))
    } else {
        Table::builder(log_file.details.sessions.values())
    };
    file.write_all(
        render_table(all_table, Some("all_sessions"), TableKind::Plain)
            .as_bytes(),
    )?;
    file.write_all(b"</div>\n")?;
    finish_page(file)
}

/// Generate the closures HTML report.
///
/// # Errors
/// Returns an I/O error if the report file cannot be created or written.
pub fn closures(
    log_file: &LogFileParseResult, config: &AppConfig,
) -> std::io::Result<()> {
    let mut h2 = vec![];
    let mut quic = vec![];

    for data in &log_file.data {
        if let Some(h2_close) = &data.datastore.h2_session_close {
            h2.push(h2_close);
        }

        if let Some(quic_close) = &data.datastore.quic_session_close {
            quic.push(quic_close);
        }
    }

    let filename = format!("{}-reports/closures.html", config.filename);
    let mut file = open_page(&filename, "Session terminations")?;
    file.write_all(r#"        <div>
            <h1 class="center">Session Overview</h1>
            <p class="center">This page lists all the sessions (aka connections)
            that were present in a log file and filtered into analysis using the
            `--netlog-filter` option. Connections are split by HTTP version. A single SNI might
            have multiple sessions, and it might use multiple HTTP versions. The reason that
            each session is closed is also captured in the Error column (and subsequent columns).
            A log that is closed before a session is terminated will not show any value in the
            columns.</p>
            <h2 class="center">HTTP/2 Connections</h2>"#.as_bytes())?;

    file.write_all(
        render_table(Table::builder(h2), Some("h2_close"), TableKind::H2Closure)
            .as_bytes(),
    )?;
    file.write_all(b"<h2 class=\"center\">HTTP/3 &amp; QUIC Connections</h2>")?;
    file.write_all(
        render_table(
            Table::builder(quic),
            Some("quic_close"),
            TableKind::QuicClosure,
        )
        .as_bytes(),
    )?;
    file.write_all(b"</div>\n")?;
    finish_page(file)
}

/// Generate the requests HTML report.
///
/// # Errors
/// Returns an I/O error if the report file cannot be created or written.
pub fn requests(
    log_file: &LogFileParseResult, config: &AppConfig,
) -> std::io::Result<()> {
    let filename = format!("{}-reports/requests.html", config.filename);

    let mut file = open_page(&filename, "HTTP requests")?;
    file.write_all(
        r#"        <h1 class="center">Summary of All HTTP Requests</h1>
        <div class="center">
            <p>This page provides information about the requests &amp; responses in a connection.</p>
            <p> Each individual table represents an HTTP session with a unique ID. Each session is bound
            to an SNI and has a version. There can be multiple connections to the same SNI depending on the
            client's behaviour.</p>
            <p>In each table, a single row represents a request &amp; response. The columns expressing different properties:</p>
            <details>
                <summary>Click to expand</summary>
                <p>
                <ul>
                    <li><strong>ID</strong> - the stream ID of the request &amp; response</li>
                    <li><strong>Method</strong> - the request Method</li>
                    <li><strong>Host</strong> - the request Host (or authority). Due to connection coalescing, this value can be different from the session SNI</li>
                    <li><strong>Path</strong> - the request Path</li>
                    <li><strong>Status</strong> - the response Status</li>
                    <li><strong>Response Content-Length</strong> - for downloads; the value of the response Content-Length, if any. A response can omit this header. </li>
                    <li><strong>Response Observed DATA</strong> - sum of known response DATA payload lengths. A missing length produces n/a. A qlog DATA frame may describe a declared payload before its body has been received, so matching Content-Length is not proof of completed delivery.</li>
                    <li><strong>Last observed response activity</strong> - latest of first observed response HEADERS and last observed response DATA. This does not establish completion.</li>
                    <li><strong>Download Duration (d2d) (ms)</strong> - the observed interval between first and last response DATA frames at the logged endpoint. Equal timestamps give zero duration.</li>
                    <li><strong>Download Rate (d2d) (Mbps)</strong> - the download rate, in megabits/s, between first and last DATA frames. This is an observed DATA-length rate, not confirmed delivered throughput. A zero, missing or reversed interval produces n/a; short positive durations can produce high values.</li>
                    <li><strong>Download Duration (h2d) (ms)</strong> - the observed interval between first response HEADERS and last response DATA at the logged endpoint.</li>
                    <li><strong>Download Rate (h2d) (Mbps)</strong> - the download rate, in megabits/s, between first HEADERS and last DATA frames. This is an observed DATA-length rate, not confirmed delivered throughput. A zero, missing or reversed interval produces n/a; short positive durations can produce high values.</li>
                    <li><strong>Client Tx Hdr, Rx First Data</strong> - the duration between the client sending a HEADERS frame, and the first DATA frame being received. This is analogous to TTFB.</li>
                    <li><strong>Client Tx Hdr, Rx Last Data</strong> - the duration between the client sending a HEADERS frame, and the last DATA frame being received. This is analogous to TTLB.</li>
                    <li><strong>Request Content-Length</strong> - for uploads; the value of the request Content-Length, if any. A request can omit this header. </li>
                    <li><strong>Request Observed DATA</strong> - sum of known request DATA payload lengths. Missing lengths produce n/a; logged DATA sizes do not prove peer delivery.</li>
                    <li><strong>Upload Duration (ms)</strong> - the observed interval between first and last request DATA at the logged endpoint.</li>
                    <li><strong>Upload Rate (Mbps)</strong> - the upload rate, in megabits/s, between first and last DATA frames. This is an observed DATA-length rate, not confirmed delivered throughput. A zero, missing or reversed interval produces n/a; short positive durations can produce high values.</li>
                    <li><strong>Client Priority Header</strong> - the value of the RFC 9218 request Priority header, if any.</li>
                    <li><strong>Server Priority Header</strong> - the value of the RFC 9218 response Priority header, if any.</li>
                    <li><strong>Reset Stream Sent</strong> - the value of the error code in a Reset Stream, if sent.</li>
                    <li><strong>Reset Stream Received</strong> - the value of the error code in a Reset Stream, if received.</li>
                    <li><strong>Stop Sending Sent</strong> - the value of the error code in a Stop Sending, if sent.</li>
                </ul>
                </p>
            </details>
        </div>
        <div id="tables">
            "#
            .as_bytes(),
    )
    ?;

    for data in &log_file.data {
        file.write_all(
            format!(
                "<h2 class=\"center\">{}</h2>",
                escape_html_cell(&data.trace.as_ref().map_or_else(
                    || format!(
                        "Session ID: {:?}, {:?}, {:?}",
                        data.datastore.session_id.unwrap_or(-1),
                        data.datastore.host.as_deref().unwrap_or("ERROR UNKNOWN"),
                        data.datastore.application_proto
                    ),
                    |trace| format!(
                        "{} ({:?})",
                        trace.label(),
                        trace.vantage_point
                    ),
                ))
            )
            .as_bytes(),
        )?;

        let table = request_timing_table(data, &config.reports.table).into();
        file.write_all(
            render_table(table, None, TableKind::Requests).as_bytes(),
        )?;
    }
    file.write_all(b"</div>\n")?;
    finish_page(file)
}

/// Escape log data, never HTML markup.
fn escape_html_cell(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    append_escaped(&mut escaped, value);
    escaped
}

fn append_escaped(output: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(ch),
        }
    }
}

#[derive(Clone, Copy)]
enum TableKind {
    Plain,
    H2Closure,
    QuicClosure,
    Requests,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowColor {
    Red,
    Yellow,
    Green,
}

impl RowColor {
    const fn class(self) -> &'static str {
        match self {
            Self::Red => "red",
            Self::Yellow => "yellow",
            Self::Green => "green",
        }
    }
}

struct RequestColumns {
    status: Option<usize>,
    length: Option<usize>,
    observed_data: Option<usize>,
    reset_sent: Option<usize>,
    reset_received: Option<usize>,
}

enum RowClassifier {
    Plain,
    H2Closure(Option<usize>),
    QuicClosure(Option<usize>),
    Requests(RequestColumns),
}

impl RowClassifier {
    fn new(kind: TableKind, headers: &[String]) -> Self {
        let column =
            |name: &str| headers.iter().position(|header| header == name);
        match kind {
            TableKind::Plain => Self::Plain,
            TableKind::H2Closure => Self::H2Closure(column("Error")),
            TableKind::QuicClosure => Self::QuicClosure(column("Error")),
            TableKind::Requests => Self::Requests(RequestColumns {
                status: column("Status"),
                length: column("Response Content-Length (bytes)"),
                observed_data: column(crate::request_stub::SERVER_OBSERVED_DATA),
                reset_sent: column("Reset Stream Sent"),
                reset_received: column("Reset Stream Received"),
            }),
        }
    }

    fn classify(&self, row: &[String]) -> Option<RowColor> {
        match self {
            Self::Plain => None,
            Self::H2Closure(error) =>
                match cell(row, *error)?.parse::<i64>().ok()? {
                    -3 => Some(RowColor::Yellow),
                    value if value < 0 => Some(RowColor::Red),
                    0 => Some(RowColor::Green),
                    _ => None,
                },
            Self::QuicClosure(error) =>
                match cell(row, *error)?.parse::<i64>().ok()? {
                    25 => Some(RowColor::Green),
                    70 => Some(RowColor::Yellow),
                    199 => Some(RowColor::Red),
                    _ => None,
                },
            Self::Requests(columns) => columns.classify(row),
        }
    }
}

fn cell(row: &[String], column: Option<usize>) -> Option<&str> {
    row.get(column?).map(String::as_str)
}

impl RequestColumns {
    fn classify(&self, row: &[String]) -> Option<RowColor> {
        let reset = |column| {
            cell(row, column)
                .is_some_and(|value| !value.is_empty() && value != "n/a")
        };
        let status =
            cell(row, self.status).and_then(|value| value.parse::<u16>().ok());
        if reset(self.reset_received) || status.is_some_and(|code| code >= 400) {
            return Some(RowColor::Red);
        }
        if reset(self.reset_sent) {
            return Some(RowColor::Yellow);
        }
        if !status.is_some_and(|code| (100..400).contains(&code)) {
            return Some(RowColor::Red);
        }
        // Only compare recorded DATA lengths; agreement is not proof of a
        // completed body.
        let length = cell(row, self.length)?.parse::<u64>().ok()?;
        let observed = cell(row, self.observed_data)?.parse::<u64>().ok()?;
        Some(if length == observed {
            RowColor::Green
        } else {
            RowColor::Red
        })
    }
}

fn numeric_request_header(name: &str) -> bool {
    !matches!(
        name,
        "Method" |
            "Host" |
            "Path" |
            "Client Priority Header" |
            "Server Priority Header" |
            "Reset Stream Sent" |
            "Reset Stream Received" |
            "Stop Sending Sent"
    )
}

/// Render directly from table records. Row classification uses the actual
/// header order after column removal, rather than offsets into HTML nodes.
fn render_table(
    table: tabled::builder::Builder, id: Option<&str>, kind: TableKind,
) -> String {
    let rows = Vec::<Vec<String>>::from(table);
    let mut output = String::from("<table class=\"log-dancer-table cell-border hover compact order-column\"");
    if let Some(id) = id {
        output.push_str(" id=\"");
        append_escaped(&mut output, id);
        output.push('"');
    }
    output.push('>');
    if let Some((headers, rows)) = rows.split_first() {
        let classifier = RowClassifier::new(kind, headers);
        output.push_str("<thead><tr>");
        for header in headers {
            if matches!(kind, TableKind::Requests) &&
                numeric_request_header(header)
            {
                output.push_str("<th class=\"numeric\">");
            } else {
                output.push_str("<th>");
            }
            append_escaped(&mut output, header);
            output.push_str("</th>");
        }
        output.push_str("</tr></thead><tbody>");
        for row in rows {
            if let Some(color) = classifier.classify(row) {
                output.push_str("<tr class=\"");
                output.push_str(color.class());
                output.push_str("\">");
            } else {
                output.push_str("<tr>");
            }
            for value in row {
                output.push_str("<td>");
                append_escaped(&mut output, value);
                output.push_str("</td>");
            }
            output.push_str("</tr>");
        }
        output.push_str("</tbody>");
    }
    output.push_str("</table>");
    output
}

/// Render the escaped event-list table for CLI and browser use.
#[must_use = "the returned HTML contains the rendered event table"]
pub fn event_list_html_from_table(table: tabled::builder::Builder) -> String {
    render_table(table, None, TableKind::Plain)
}

/// Writes the recognized-event list from any parsed log encoding.
///
/// # Errors
/// Returns an I/O error if the report directory or output file cannot be
/// created/written.
pub fn event_list(
    log_file: &LogFileParseResult, config: &AppConfig,
) -> std::io::Result<()> {
    let filename = format!("{}-reports/event-list.html", config.filename);
    let mut file = open_page(&filename, "Recognized log events")?;
    file.write_all(
        r#"        <div>
            <h1 class="center">Recognized log events</h1>
            <p class="center">This page lists the parsed events understood by qlog-dancer
            for each selected connection. Unrecognized Chrome netlog events are not included.</p>
            "#
        .as_bytes(),
    )?;

    for data in &log_file.data {
        let table = event_list_html_from_table(
            build_event_list(&data.raw).map_err(std::io::Error::other)?,
        );
        let session = data.trace.as_ref().map_or_else(
            || {
                data.datastore.session_id.map_or_else(
                    || "unnamed session".to_owned(),
                    |id| format!("session {id}"),
                )
            },
            |trace| format!("{} ({:?})", trace.label(), trace.vantage_point),
        );
        file.write_all(
            format!("<h2 class=\"center\">{}</h2>", escape_html_cell(&session))
                .as_bytes(),
        )?;
        file.write_all(table.as_bytes())?;
    }

    file.write_all(b"</div>\n")?;
    finish_page(file)
}

#[cfg(test)]
mod report_event_html_tests {
    use super::event_list_html_from_table;
    use super::render_table;
    use super::RowClassifier;
    use super::RowColor;
    use super::TableKind;
    use crate::reports::events::event_list as build_event_list;
    use qlog::events::EventImportance;
    use qlog::events::JsonEvent;
    use qlog::reader::Event;
    use tabled::builder::Builder;

    #[test]
    fn all_report_tables_escape_data_before_decoration() {
        let mut builder = Builder::default();
        builder.push_record(["Status", "Host", "Reset Stream Received"]);
        builder.push_record(["500", "<img src=x onerror='alert(1)'>&", "n/a"]);
        let html = render_table(builder, None, TableKind::Requests);
        assert!(
            html.contains("&lt;img src=x onerror=&#39;alert(1)&#39;&gt;&amp;"),
            "{html}"
        );
        assert!(!html.contains("<img src=x"), "{html}");
        assert!(html.contains("<tr class=\"red\">"), "{html}");

        let mut builder = Builder::default();
        builder.push_record(["Error", "Host", "ID"]);
        builder.push_record(["-3", "<script>injected</script>", "5"]);
        let html = render_table(builder, None, TableKind::H2Closure);
        assert!(
            html.contains("&lt;script&gt;injected&lt;/script&gt;"),
            "{html}"
        );
        assert!(html.contains("<tr class=\"yellow\">"), "{html}");
    }

    #[test]
    fn request_classification_is_independent_of_column_order_and_omissions() {
        let fields = [
            "Status",
            "Response Content-Length (bytes)",
            crate::request_stub::SERVER_OBSERVED_DATA,
            "Reset Stream Sent",
            "Reset Stream Received",
            "Client Priority Header",
        ];
        let cases = [
            (
                ["200", "00012", "12", "n/a", "n/a", "u=1"],
                Some(RowColor::Green),
            ),
            (["200", "12", "1", "n/a", "n/a", "u=1"], Some(RowColor::Red)),
            (["200", "12", "12", "n/a", "7", "u=1"], Some(RowColor::Red)),
            (
                ["n/a", "n/a", "n/a", "7", "n/a", "u=1"],
                Some(RowColor::Yellow),
            ),
            (["500", "12", "12", "7", "n/a", "u=1"], Some(RowColor::Red)),
            (["200", "n/a", "12", "n/a", "n/a", "u=1"], None),
        ];
        for columns in
            [[0, 1, 2, 3, 4, 5], [4, 3, 2, 1, 0, 5], [5, 2, 1, 3, 4, 0]]
        {
            for (row, expected) in cases {
                // Remove the optional priority column independently of
                // position.
                let order = columns
                    .iter()
                    .copied()
                    .filter(|index| *index != 5)
                    .collect::<Vec<_>>();
                let headers = order
                    .iter()
                    .map(|&index| fields[index].to_owned())
                    .collect::<Vec<_>>();
                let values = order
                    .iter()
                    .map(|&index| row[index].to_owned())
                    .collect::<Vec<_>>();
                assert_eq!(
                    RowClassifier::new(TableKind::Requests, &headers)
                        .classify(&values),
                    expected
                );
            }
        }
    }

    #[test]
    fn escapes_user_supplied_event_details_and_preserves_unicode(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let record = Event::Json(JsonEvent {
            time: 1.0,
            importance: EventImportance::default(),
            name: "custom:<img src=x onerror='alert(1)'>".to_string(),
            data: serde_json::json!({"key": "<script>alert(1)</script>&🏁"}),
        });
        let raw = crate::RawLogEvents::QlogJsonSeq {
            events: vec![record],
        };
        let html = event_list_html_from_table(build_event_list(&raw)?);
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&amp;🏁"));
        assert!(html.contains("&lt;img src=x onerror=&#39;alert(1)&#39;&gt;"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("<img src=x"));
        Ok(())
    }
}
