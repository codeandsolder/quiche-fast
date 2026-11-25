use std::fs::File;
use std::fs::{
    self,
};
use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use serde::Deserialize;
use tempfile::TempDir;

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Process {
    fn wait(&mut self) -> io::Result<ExitStatus> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            if start.elapsed() >= Duration::from_secs(20) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "QUIC client timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn available_address() -> io::Result<SocketAddr> {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()
}

struct Server {
    process: Process,
    directory: TempDir,
    address: SocketAddr,
}

struct Captured {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Captured {
    fn successful(self) -> io::Result<Vec<u8>> {
        if self.status.success() {
            Ok(self.stdout)
        } else {
            Err(io::Error::other(format!(
                "client exited {}: {}",
                self.status,
                String::from_utf8_lossy(&self.stderr)
            )))
        }
    }
}

impl Server {
    fn start(options: &[&str]) -> io::Result<Self> {
        let directory = tempfile::tempdir()?;
        let address = available_address()?;
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin");
        let root = directory.path().join("www");
        fs::create_dir(&root)?;
        let log = File::create(directory.path().join("server.log"))?;
        let process = Process(
            Command::new(env!("CARGO_BIN_EXE_quiche-server"))
                .arg(format!("--listen={address}"))
                .arg("--root")
                .arg(root)
                .arg("--cert")
                .arg(fixture.join("cert.crt"))
                .arg("--key")
                .arg(fixture.join("cert.key"))
                .arg("--idle-timeout=5000")
                .args(options)
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()?,
        );
        Ok(Self {
            process,
            directory,
            address,
        })
    }

    fn root(&self) -> PathBuf {
        self.directory.path().join("www")
    }

    fn request(&mut self, path: &str, options: &[&str]) -> io::Result<Captured> {
        if let Some(status) = self.process.0.try_wait()? {
            return Err(io::Error::other(format!("server exited {status}")));
        }
        let stdout = self.directory.path().join("client.stdout");
        let stderr = self.directory.path().join("client.stderr");
        let mut client = Process(
            Command::new(env!("CARGO_BIN_EXE_quiche-client"))
                .args([
                    "--no-verify",
                    "--idle-timeout=5000",
                    "--max-stream-data=4096",
                    "--max-stream-window=4096",
                    "--max-data=32768",
                    "--max-window=32768",
                ])
                .args(options)
                .arg(format!("https://{}{path}", self.address))
                .stdout(Stdio::from(File::create(&stdout)?))
                .stderr(Stdio::from(File::create(&stderr)?))
                .spawn()?,
        );
        let status = client.wait()?;
        Ok(Captured {
            status,
            stdout: fs::read(stdout)?,
            stderr: fs::read(stderr)?,
        })
    }
}

#[derive(Deserialize)]
struct Report {
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    response: Response,
}

#[derive(Deserialize)]
struct Response {
    headers: Vec<Header>,
    body: Vec<u8>,
}

#[derive(Deserialize)]
struct Header {
    name: String,
    value: String,
}

fn assert_response(
    output: &[u8], status: &str, expected: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let report: Report = serde_json::from_slice(output)?;
    assert_eq!(report.entries.len(), 1);
    let response = &report.entries[0].response;
    assert_eq!(response.body, expected);
    for (name, value) in [
        (":status", status.to_owned()),
        ("content-length", expected.len().to_string()),
    ] {
        assert!(response
            .headers
            .iter()
            .any(|header| header.name == name && header.value == value));
    }
    Ok(())
}

#[test]
fn fragmented_http09_request_and_streamed_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut server = Server::start(&[
        "--max-stream-data=64",
        "--max-stream-window=4096",
        "--disable-gso",
        "--disable-pacing",
    ])?;
    let filename = "a".repeat(192);
    let payload = b"0123456789abcdef".repeat(14_000);
    fs::write(server.root().join(&filename), &payload)?;
    let output = server
        .request(&format!("/{filename}"), &["--http-version=HTTP/0.9"])?
        .successful()?;
    assert_eq!(output, payload);
    Ok(())
}

#[test]
fn http3_streaming_default_and_fallback() -> Result<(), Box<dyn std::error::Error>>
{
    let fallback = ["--disable-gso", "--disable-pacing"];
    let payload = (0..=255_u8).cycle().take(225_000).collect::<Vec<_>>();
    for options in [&fallback[..], &[]] {
        let mut server = Server::start(options)?;
        fs::write(server.root().join("index.html"), &payload)?;
        let output_path = server.directory.path().join("downloads");
        fs::create_dir(&output_path)?;
        let output_path = output_path.to_str().ok_or("invalid fixture path")?;
        let common = [
            "--http-version=HTTP/3",
            "--dump-json",
            "--max-json-payload=300000",
        ];
        let mut file_args = common.to_vec();
        file_args.extend(["--dump-responses", output_path]);
        let output = server.request("/", &file_args)?.successful()?;
        assert_response(&output, "200", &payload)?;
        assert_eq!(
            fs::read(Path::new(output_path).join("index.html"))?,
            payload
        );
        for (path, expected) in [
            ("/stream-bytes/262145", vec![0x57; 262_145]),
            ("/stream-bytes/0", Vec::new()),
        ] {
            let output = server.request(path, &common)?.successful()?;
            assert_response(&output, "200", &expected)?;
        }
    }
    Ok(())
}

#[test]
fn http3_empty_request_body_and_migration_with_fixed_source_port(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut server =
        Server::start(&["--enable-active-migration", "--early-data"])?;
    let body = server.directory.path().join("empty");
    fs::write(&body, [])?;
    let body = body.to_str().ok_or("invalid fixture path")?;
    let source = available_address()?.port().to_string();
    let output = server
        .request("/stream-bytes/3#client-only", &[
            "--http-version=HTTP/3",
            "--dump-json",
            "--body",
            body,
            "--enable-active-migration",
            "--perform-migration",
            "--source-port",
            &source,
        ])?
        .successful()?;
    assert_response(&output, "200", b"WWW")?;
    Ok(())
}

#[test]
fn http3_invalid_header_and_missing_output_directory_are_errors(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut server = Server::start(&[])?;
    let missing = server.directory.path().join("missing").join("subdirectory");
    let missing = missing.to_str().ok_or("invalid fixture path")?;
    for options in [["--http-version=HTTP/3", "--header", "not a header"], [
        "--http-version=HTTP/3",
        "--dump-responses",
        missing,
    ]] {
        let output = server.request("/stream-bytes/3", &options)?;
        assert!(!output.status.success());
        assert_ne!(output.status.code(), Some(101), "client panicked");
    }
    Ok(())
}

#[test]
fn http3_session_file_and_early_data_reuse(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut server = Server::start(&["--early-data"])?;
    let session = server.directory.path().join("session");
    let session_name = session.to_str().ok_or("invalid fixture path")?;
    let options = [
        "--http-version=HTTP/3",
        "--early-data",
        "--session-file",
        session_name,
        "--dump-json",
    ];
    for _ in 0..2 {
        let output = server
            .request("/stream-bytes/257", &options)?
            .successful()?;
        assert_response(&output, "200", &[0x57; 257])?;
        assert!(fs::metadata(&session)?.len() > 0);
    }
    Ok(())
}
