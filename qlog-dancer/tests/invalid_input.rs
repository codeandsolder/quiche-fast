use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(0);

struct TempLog(PathBuf);

impl TempLog {
    fn new(extension: &str, bytes: &[u8]) -> std::io::Result<Self> {
        let sequence = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "quiche-qlog-dancer-{}-{timestamp}-{sequence}.{extension}",
            std::process::id(),
        ));
        fs::write(&path, bytes)?;
        Ok(Self(path))
    }
}

impl Drop for TempLog {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn malformed_logs_fail_cleanly_for_all_input_formats(
) -> Result<(), Box<dyn std::error::Error>> {
    for extension in ["qlog", "sqlog", "json"] {
        let input = TempLog::new(extension, b"not a valid log")?;
        let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
            .arg(&input.0)
            .env("RUST_LOG", "error")
            .output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !output.status.success(),
            "malformed {extension} unexpectedly succeeded"
        );
        assert!(
            !stderr.contains("panicked at"),
            "malformed {extension} caused a panic: {stderr}",
        );
    }
    Ok(())
}

#[test]
fn malformed_wirefilter_reports_its_cause_instead_of_retrying_file_formats(
) -> Result<(), Box<dyn std::error::Error>> {
    let header = r#"{"file_schema":"0.3","serialization_format":"JSON-SEQ","trace":{"event_schemas":[]}}"#;
    let bytes = format!("\u{1e}{header}\n\u{1e}");
    let input = TempLog::new("sqlog", bytes.as_bytes())?;
    let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
        .arg(&input.0)
        .arg("--qlog-wirefilter")
        .arg("any(stream_id[*] ==")
        .env("RUST_LOG", "error")
        .output()?;

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "unexpected status: {stderr}");
    assert!(
        stderr.contains("invalid qlog wirefilter expression"),
        "missing filter error: {stderr}",
    );
    assert!(
        !stderr.contains("Unable to parse log in either format"),
        "format fallback masked the filter error: {stderr}",
    );
    Ok(())
}

#[test]
fn empty_qlog_traces_fail_cleanly() -> Result<(), Box<dyn std::error::Error>> {
    let input = TempLog::new(
        "qlog",
        br#"{"file_schema":"0.3","serialization_format":"JSON","traces":[]}"#,
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
        .arg(&input.0)
        .env("RUST_LOG", "error")
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked at"),
        "empty traces caused a panic: {stderr}"
    );
    Ok(())
}

#[test]
fn unsupported_qlog_vantage_is_reported_without_format_retry(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = TempLog::new(
        "qlog",
        br#"{"file_schema":"0.3","serialization_format":"JSON","traces":[{"event_schemas":[],"events":[]}]}"#,
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
        .arg(&input.0)
        .env("RUST_LOG", "error")
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "unexpected status: {stderr}");
    assert!(
        stderr.contains("unsupported qlog vantage point"),
        "missing vantage error: {stderr}",
    );
    assert!(
        !stderr.contains("Unable to parse log in either format"),
        "vantage validation retried unrelated formats: {stderr}",
    );
    Ok(())
}

#[test]
fn qlog_tracker_overflow_is_a_fatal_input_error_in_both_encodings(
) -> Result<(), Box<dyn std::error::Error>> {
    let overflow_event = serde_json::json!({
        "time": 2.0,
        "name": "quic:stream_data_moved",
        "data": {
            "stream_id": 42,
            "offset": u64::MAX,
            "to": "application",
            "raw": { "length": 1 }
        }
    });
    let json = serde_json::json!({
        "file_schema": "0.3",
        "serialization_format": "JSON",
        "traces": [{
            "vantage_point": { "type": "client" },
            "event_schemas": [],
            "events": [overflow_event]
        }]
    });
    let sequential_header = serde_json::json!({
        "file_schema": "0.3",
        "serialization_format": "JSON-SEQ",
        "trace": {
            "vantage_point": { "type": "client" },
            "event_schemas": []
        }
    });
    let sequential = format!("\x1e{sequential_header}\n\x1e{overflow_event}\n");

    for (extension, bytes) in [
        ("qlog", json.to_string().into_bytes()),
        ("sqlog", sequential.into_bytes()),
    ] {
        let input = TempLog::new(extension, &bytes)?;
        let output = Command::new(env!("CARGO_BIN_EXE_qlog-dancer"))
            .arg(&input.0)
            .env("RUST_LOG", "error")
            .output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{extension}: {stderr}");
        assert!(
            stderr.contains("stream 42 end offset overflows"),
            "{extension}: {stderr}"
        );
        assert!(
            !stderr.contains("Unable to parse log in either format"),
            "{extension}: {stderr}"
        );
        assert!(!stderr.contains("panicked at"), "{extension}: {stderr}");
    }
    Ok(())
}
