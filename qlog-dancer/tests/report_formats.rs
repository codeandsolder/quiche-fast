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
