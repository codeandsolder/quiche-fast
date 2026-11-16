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
