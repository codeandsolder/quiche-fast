use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct RunDir(PathBuf);

impl RunDir {
    fn new() -> std::io::Result<Self> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "quiche-qlog-reports-{}-{time}-{id}",
            std::process::id(),
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn native_qlog() -> Vec<u8> {
    serde_json::json!({
        "file_schema": "0.3", "serialization_format": "JSON",
        "traces": [{
            "vantage_point": { "type": "client" },
            "event_schemas": [],
            "events": [{
                "time": 1.0, "name": "quic:connection_state_updated",
                "data": { "new": "handshake_started" }
            }]
        }]
    })
    .to_string()
    .into_bytes()
}

fn sequential_qlog() -> Vec<u8> {
    let header = serde_json::json!({
        "file_schema": "0.3", "serialization_format": "JSON-SEQ",
        "trace": {
            "vantage_point": { "type": "client" },
            "event_schemas": []
        }
    });
    let record = serde_json::json!({
        "time": 1.0, "name": "quic:connection_state_updated",
        "data": { "new": "handshake_started" }
    });
    format!("\x1e{header}\n\x1e{record}\n").into_bytes()
}

fn chrome_netlog() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let constants = serde_json::json!({
        "constants": {
            "activeFieldTrialGroups": [], "addressFamily": {},
            "certPathBuilderDigestPolicy": {}, "certStatusFlag": {},
            "certVerifierFlags": {}, "clientInfo": {}, "dnsQueryType": {},
            "loadFlag": {}, "loadState": {},
            "logEventPhase": { "PHASE_BEGIN": 1 },
            "logEventTypes": { "HTTP2_SESSION": 101 },
            "logFormatVersion": 123, "logSourceType": {},
            "netError": {}, "quicError": {}, "quicRstStreamError": {},
            "secureDnsMode": {}, "timeTickOffset": 0
        }
    });
    let prefix = constants.to_string();
    let prefix = prefix.strip_suffix('}').ok_or("missing closing brace")?;
    let event = serde_json::json!({
        "phase": 1, "source": { "id": 7, "type": 5, "start_time": "0" },
        "time": "12345678901234567890", "type": 101,
        "params": { "host": "<script>alert(1)</script>&", "proxy": "" }
    });
    Ok(format!("{prefix},\n\"events\": [\n{event}\n]\n}}").into_bytes())
}

#[test]
fn text_and_html_event_reports_work_for_all_log_formats(
) -> Result<(), Box<dyn std::error::Error>> {
    let netlog = chrome_netlog()?;
    let cases = [
        ("qlog", native_qlog(), "connection_state_updated"),
        ("sqlog", sequential_qlog(), "connection_state_updated"),
        ("json", netlog, "HTTP2_SESSION"),
    ];

    for (extension, contents, expected_event) in cases {
        let run = RunDir::new()?;
        let filename = format!("sample.{extension}");
        let path = run.0.join(&filename);
        fs::write(&path, contents)?;
        for report in ["--report-text", "--report-html"] {
            let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
                .arg(&path)
                .arg(report)
                .args(if report == "--report-text" {
                    vec!["--print-stats", "stream"]
                } else {
                    Vec::new()
                })
                .current_dir(&run.0)
                .env("RUST_LOG", "error")
                .output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "{extension} {report}: code={:?}, stdout={stdout}, stderr={stderr}",
                output.status.code(),
            );
            assert!(
                !stderr.contains("panicked at"),
                "{extension} {report} panicked: {stderr}",
            );
            if report == "--report-text" {
                assert!(
                    stdout.contains("Recognized log events"),
                    "{extension}: {stdout}"
                );
                assert!(stdout.contains(expected_event), "{extension}: {stdout}");
                assert!(
                    stdout.contains("### sent MAX_DATA frames ###"),
                    "{extension}: {stdout}"
                );
                assert!(
                    stdout.contains("### received MAX_DATA frames ###"),
                    "{extension}: {stdout}"
                );
                assert!(stdout.contains("    None"), "{extension}: {stdout}");
            } else {
                let html = fs::read_to_string(
                    run.0.join(format!("{filename}-reports/event-list.html")),
                )?;
                assert!(html.contains(expected_event), "{extension}: {html}");
                assert!(html.contains("Recognized log events"));
                if extension == "json" {
                    let output_dir = run.0.join(format!("{filename}-reports"));
                    for report_file in
                        ["overview.html", "requests.html", "closures.html"]
                    {
                        let additional_html =
                            fs::read_to_string(output_dir.join(report_file))?;
                        assert!(!additional_html.contains("<script>alert(1)</script>"),
                                "unsanitized log content in {report_file}: {additional_html}");
                    }
                    let overview =
                        fs::read_to_string(output_dir.join("overview.html"))?;
                    let requests =
                        fs::read_to_string(output_dir.join("requests.html"))?;
                    assert!(
                        overview.contains(
                            "&lt;script&gt;alert(1)&lt;/script&gt;&amp;"
                        ),
                        "{overview}"
                    );
                    assert!(
                        requests.contains(
                            "&lt;script&gt;alert(1)&lt;/script&gt;&amp;"
                        ),
                        "{requests}"
                    );
                    assert!(html.contains("12345678901234567890"));
                    assert!(html
                        .contains("&lt;script&gt;alert(1)&lt;/script&gt;&amp;"));
                    assert!(!html.contains("<script>alert(1)</script>"));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn every_html_report_file_failure_is_returned_not_panicked(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in [
        "overview.html",
        "closures.html",
        "requests.html",
        "event-list.html",
    ] {
        let run = RunDir::new()?;
        let filename = "sample.qlog";
        let input = run.0.join(filename);
        fs::write(&input, native_qlog())?;
        let output_path = run.0.join(format!("{filename}-reports")).join(target);
        fs::create_dir_all(&output_path)?; // A directory at the output-file
                                           // path makes File::create fail.
        let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
            .arg(&input)
            .arg("--report-html")
            .current_dir(&run.0)
            .env("RUST_LOG", "error")
            .output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{target}: {stderr}");
        assert!(
            stderr.contains("Unable to write log report"),
            "{target}: {stderr}"
        );
        assert!(!stderr.contains("panicked at"), "{target}: {stderr}");
    }
    Ok(())
}

#[test]
fn packet_received_and_multiplex_cli_report_output_errors_without_panicking(
) -> Result<(), Box<dyn std::error::Error>> {
    let run = RunDir::new()?;
    let input = run.0.join("sample.qlog");
    fs::write(&input, native_qlog())?;
    let blocked = run.0.join("blocked-chart-directory");
    fs::write(&blocked, b"an output directory cannot be a file")?;
    for (plot, expected) in [
        ("pkt-rx", "Unable to draw packet received chart"),
        ("multiplex", "Unable to draw stream multiplexing chart"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
            .arg(&input)
            .args(["--charts", plot, "--charts-directory"])
            .arg(&blocked)
            .current_dir(&run.0)
            .env("RUST_LOG", "error")
            .output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{plot}: {stderr}");
        assert!(
            stderr.contains(expected),
            "{plot} missing diagnostic: {stderr}"
        );
        assert!(!stderr.contains("panicked at"), "{plot} panicked: {stderr}");
    }
    Ok(())
}

#[test]
fn overview_flow_and_pending_cli_fail_cleanly_when_output_is_blocked(
) -> Result<(), Box<dyn std::error::Error>> {
    let run = RunDir::new()?;
    let input = run.0.join("sample.qlog");
    fs::write(&input, native_qlog())?;
    let blocked = run.0.join("occupied-chart-directory");
    fs::write(&blocked, b"a file cannot contain PNG outputs")?;
    for (chart, error_label) in [
        ("overview", "Unable to draw connection overview chart"),
        ("conn-flow", "Unable to draw connection flow control chart"),
        ("pending", "Unable to draw pending chart"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
            .arg(&input)
            .args(["--charts", chart, "--charts-directory"])
            .arg(&blocked)
            .current_dir(&run.0)
            .env("RUST_LOG", "error")
            .output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{chart}: {stderr}");
        assert!(
            stderr.contains(error_label),
            "{chart} missing diagnostic: {stderr}"
        );
        assert!(
            !stderr.contains("panicked at"),
            "{chart} panicked: {stderr}"
        );
    }
    Ok(())
}

#[test]
fn conn_flow_cli_actually_creates_png_when_selected(
) -> Result<(), Box<dyn std::error::Error>> {
    let run = RunDir::new()?;
    let input = run.0.join("sample.qlog");
    fs::write(&input, native_qlog())?;
    let output_dir = run.0.join("flow-control-images");
    let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
        .arg(&input)
        .args(["--charts", "conn-flow", "--charts-directory"])
        .arg(&output_dir)
        .current_dir(&run.0)
        .env("RUST_LOG", "error")
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let images = fs::read_dir(&output_dir)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        images.len(),
        1,
        "--charts conn-flow must generate exactly one PNG"
    );
    let bytes = fs::read(images[0].path())?;
    assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
    Ok(())
}

fn multitrace_qlog() -> Vec<u8> {
    serde_json::json!({
        "file_schema": "0.3", "serialization_format": "JSON",
        "traces": [
            {
                "title": "<script>alert(1)</script>",
                "vantage_point": { "type": "client" },
                "event_schemas": [],
                "events": [{
                    "time": 1.0, "name": "quic:connection_state_updated",
                    "data": { "new": "handshake_started" }
                }]
            },
            {
                "title": "<script>alert(1)</script>",
                "vantage_point": { "type": "server" },
                "event_schemas": [],
                "events": [{
                    "time": 2.0, "name": "quic:connection_state_updated",
                    "data": { "new": "handshake_completed" }
                }]
            }
        ]
    })
    .to_string()
    .into_bytes()
}

#[test]
fn qlog_multiple_traces_retain_identity_and_generate_separate_charts(
) -> Result<(), Box<dyn std::error::Error>> {
    let run = RunDir::new()?;
    let file = run.0.join("multi.qlog");
    fs::write(&file, multitrace_qlog())?;
    let chart_dir = run.0.join("charts");
    let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
        .arg(&file)
        .args([
            "--report-text",
            "--report-html",
            "--charts",
            "conn-flow",
            "--charts-directory",
        ])
        .arg(&chart_dir)
        .current_dir(&run.0)
        .env("RUST_LOG", "warn")
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("trace 1: <script>alert(1)</script> (Client)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("trace 2: <script>alert(1)</script> (Server)"),
        "{stdout}"
    );
    assert_eq!(
        stdout.matches("Recognized log events").count(),
        2,
        "{stdout}"
    );
    assert!(stdout.contains("handshake_started"), "{stdout}");
    assert!(stdout.contains("handshake_completed"), "{stdout}");

    let chart_files = fs::read_dir(&chart_dir)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(chart_files.len(), 2);
    for suffix in ["trace-0001", "trace-0002"] {
        let entry = chart_files
            .iter()
            .find(|entry| entry.file_name().to_string_lossy().contains(suffix))
            .ok_or_else(|| format!("missing chart for {suffix}"))?;
        assert!(fs::read(entry.path())?.starts_with(b"\x89PNG\r\n\x1a\n"));
    }
    let html_dir = run.0.join("multi.qlog-reports");
    let events = fs::read_to_string(html_dir.join("event-list.html"))?;
    assert!(
        events.contains("trace 1: &lt;script&gt;alert(1)&lt;/script&gt;"),
        "{events}"
    );
    assert!(
        events.contains("trace 2: &lt;script&gt;alert(1)&lt;/script&gt;"),
        "{events}"
    );
    assert!(!events.contains("trace 1: <script>"), "{events}");
    let requests = fs::read_to_string(html_dir.join("requests.html"))?;
    assert!(
        requests.contains("trace 1: &lt;script&gt;alert(1)&lt;/script&gt;"),
        "{requests}"
    );
    assert!(
        requests.contains("trace 2: &lt;script&gt;alert(1)&lt;/script&gt;"),
        "{requests}"
    );
    assert!(!requests.contains("Session ID: -1"), "{requests}");
    let overview = fs::read_to_string(html_dir.join("overview.html"))?;
    assert!(overview.contains("Vantage point"), "{overview}");
    assert!(
        overview.contains("Client") && overview.contains("Server"),
        "{overview}"
    );
    assert!(
        overview.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "{overview}"
    );
    assert!(
        !overview.contains("<script>alert(1)</script>"),
        "{overview}"
    );
    Ok(())
}

#[test]
fn invalid_second_qlog_trace_rejects_entire_file_instead_of_silently_skipping_it(
) -> Result<(), Box<dyn std::error::Error>> {
    let run = RunDir::new()?;
    let file = run.0.join("multi.qlog");
    let mut qlog: serde_json::Value = serde_json::from_slice(&multitrace_qlog())?;
    qlog["traces"][1]["vantage_point"]["type"] = "network".into();
    fs::write(&file, serde_json::to_vec(&qlog)?)?;
    let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
        .arg(&file)
        .arg("--report-text")
        .current_dir(&run.0)
        .env("RUST_LOG", "error")
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("unsupported qlog vantage point"),
        "{stderr}"
    );
    assert!(!stderr.contains("panicked at"), "{stderr}");
    Ok(())
}

#[test]
fn chrome_netlog_sessions_produce_distinct_charts(
) -> Result<(), Box<dyn std::error::Error>> {
    let run = RunDir::new()?;
    let input = run.0.join("sessions.json");
    // Chrome netlog is line-oriented even though the enclosing structure is
    // JSON: each event must occupy its own physical record for the parser.
    let original = String::from_utf8(chrome_netlog()?)?;
    let netlog: serde_json::Value = serde_json::from_str(&original)?;
    let mut second = netlog["events"][0].clone();
    second["source"]["id"] = 8.into();
    second["params"]["host"] = "other.example".into();
    let prefix = original
        .strip_suffix("\n]\n}")
        .ok_or("netlog fixture missing event array terminator")?;
    fs::write(&input, format!("{prefix},\n{second}\n]\n}}"))?;
    let chart_dir = run.0.join("charts");
    let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
        .arg(&input)
        .args(["--charts", "conn-flow", "--charts-directory"])
        .arg(&chart_dir)
        .current_dir(&run.0)
        .env("RUST_LOG", "error")
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let files = fs::read_dir(&chart_dir)?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(files.len(), 2);
    for id in ["session-7", "session-8"] {
        let file = files
            .iter()
            .find(|entry| entry.file_name().to_string_lossy().contains(id))
            .ok_or_else(|| format!("missing chart for {id}"))?;
        assert!(fs::read(file.path())?.starts_with(b"\x89PNG\r\n\x1a\n"));
    }
    Ok(())
}
