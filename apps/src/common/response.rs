use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::io::{
    self,
};
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

const CHUNK_SIZE: usize = 16 * 1024;

/// A length-delimited response source with one lazily allocated reusable chunk.
/// Unaccepted bytes survive flow-control blocking without rereading the source.
pub(super) struct ResponseBody {
    source: Box<dyn Read>,
    remaining: u64,
    buffer: Vec<u8>,
    offset: usize,
}

#[derive(Debug)]
pub(super) enum BodyError {
    Io(io::Error),
    Transport(quiche::h3::Error),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Transport(error) => write!(formatter, "{error}"),
        }
    }
}

impl From<io::Error> for BodyError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl ResponseBody {
    fn new(source: impl Read + 'static, length: u64) -> Self {
        Self {
            source: Box::new(source),
            remaining: length,
            buffer: Vec::new(),
            offset: 0,
        }
    }

    pub(super) fn bytes(bytes: &'static [u8]) -> Self {
        Self::new(Cursor::new(bytes), bytes.len() as u64)
    }

    pub(super) fn repeat(byte: u8, count: u64) -> Self {
        Self::new(io::repeat(byte), count)
    }

    pub(super) fn file(file: File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self::new(file, metadata.len()))
    }

    pub(super) const fn len(&self) -> u64 {
        self.remaining
    }

    /// Write until flow control blocks or the final bytes (possibly empty)
    /// are accepted. The send function must report the number of body bytes
    /// accepted, and only emit FIN when it accepts the entire supplied slice.
    pub(super) fn send(
        &mut self,
        mut write: impl FnMut(&[u8], bool) -> quiche::h3::Result<usize>,
    ) -> Result<bool, BodyError> {
        loop {
            if self.offset == self.buffer.len() {
                let count =
                    usize::try_from(self.remaining.min(CHUNK_SIZE as u64))
                        .map_err(io::Error::other)?;
                self.buffer.resize(count, 0);
                self.source.read_exact(&mut self.buffer)?;
                self.offset = 0;
            }

            let chunk = &self.buffer[self.offset..];
            let fin = chunk.len() as u64 == self.remaining;
            let accepted = match write(chunk, fin) {
                Ok(accepted) => accepted,
                Err(
                    quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked,
                ) => return Ok(false),
                Err(error) => return Err(BodyError::Transport(error)),
            };
            if accepted > chunk.len() {
                return Err(io::Error::from(io::ErrorKind::InvalidData).into());
            }
            if accepted == 0 && !chunk.is_empty() {
                return Ok(false);
            }
            self.offset += accepted;
            self.remaining -= accepted as u64;
            if self.remaining == 0 {
                return Ok(true);
            }
        }
    }
}

/// Resolve a request path under the canonical document root. Reject parent
/// traversal and paths that resolve outside the root through symbolic links.
fn resource_path(root: &Path, request: &str, index: &str) -> io::Result<PathBuf> {
    let root = root.canonicalize()?;
    if !root.is_dir() || !request.starts_with('/') {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut candidate = root.clone();
    for component in Path::new(request.trim_start_matches('/')).components() {
        match component {
            Component::Normal(name) => candidate.push(name),
            Component::CurDir => (),
            _ => return Err(io::ErrorKind::PermissionDenied.into()),
        }
    }
    if request.ends_with('/') || candidate.is_dir() {
        let mut components = Path::new(index).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(name)), None) => candidate.push(name),
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        }
    }
    let canonical = candidate.canonicalize()?;
    if !canonical.starts_with(&root) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(canonical)
}

pub(super) fn resource(
    root: &str, request: &str, index: &str,
) -> io::Result<ResponseBody> {
    let path = resource_path(Path::new(root), request, index)?;
    if !path.is_file() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    ResponseBody::file(File::open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_writes_keep_the_exact_suffix_and_fin() -> Result<(), BodyError> {
        let mut body = ResponseBody::bytes(b"abcdefgh");
        let mut accepted = Vec::new();
        let mut calls = 0;
        assert!(!body.send(|bytes, fin| {
            assert!(fin);
            calls += 1;
            if calls == 1 {
                assert_eq!(bytes, b"abcdefgh");
                accepted.extend_from_slice(&bytes[..3]);
                Ok(3)
            } else {
                assert_eq!(bytes, b"defgh");
                Err(quiche::h3::Error::Done)
            }
        })?);
        assert_eq!(body.len(), 5);
        assert!(body.send(|bytes, fin| {
            assert!(fin);
            assert_eq!(bytes, b"defgh");
            accepted.extend_from_slice(bytes);
            Ok(bytes.len())
        })?);
        assert_eq!(accepted, b"abcdefgh");
        assert_eq!(body.len(), 0);
        Ok(())
    }

    #[test]
    fn huge_generated_response_allocates_only_one_chunk() -> Result<(), BodyError>
    {
        let mut body = ResponseBody::repeat(0x57, 1_u64 << 40);
        assert_eq!(body.buffer.capacity(), 0);
        let mut calls = 0;
        assert!(!body.send(|bytes, fin| {
            assert!(!fin);
            assert_eq!(bytes.len(), CHUNK_SIZE);
            assert!(bytes.iter().all(|byte| *byte == 0x57));
            calls += 1;
            if calls == 1 {
                Ok(bytes.len())
            } else {
                Err(quiche::h3::Error::Done)
            }
        })?);
        assert_eq!(body.len(), (1_u64 << 40) - CHUNK_SIZE as u64);
        assert_eq!(body.buffer.capacity(), CHUNK_SIZE);
        Ok(())
    }

    #[test]
    fn empty_response_retries_fin_until_accepted() -> Result<(), BodyError> {
        let mut body = ResponseBody::bytes(b"");
        assert!(!body.send(|bytes, fin| {
            assert!(bytes.is_empty() && fin);
            Err(quiche::h3::Error::Done)
        })?);
        assert!(body.send(|bytes, fin| {
            assert!(bytes.is_empty() && fin);
            Ok(0)
        })?);
        Ok(())
    }

    #[test]
    fn truncated_reader_returns_error_before_emitting_fin() {
        let mut body = ResponseBody::new(Cursor::new(b"short"), 12);
        let result = body.send(|_, _| Err(quiche::h3::Error::Internal));
        assert!(
            matches!(result, Err(BodyError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn canonical_root_and_file_source_are_validated() -> Result<(), BodyError> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().join("root");
        std::fs::create_dir(&root)?;
        std::fs::write(root.join("index.html"), b"index")?;
        std::fs::write(fixture.path().join("outside"), b"outside")?;

        assert_eq!(
            resource_path(&root, "/", "index.html")?,
            root.join("index.html").canonicalize()?
        );
        assert!(resource_path(&root, "/../outside", "index.html").is_err());
        assert!(resource_path(&root, "/", "/index.html").is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                fixture.path().join("outside"),
                root.join("link"),
            )?;
            assert!(resource_path(&root, "/link", "index.html").is_err());
        }

        let mut body = ResponseBody::file(File::open(resource_path(
            &root,
            "/",
            "index.html",
        )?)?)?;
        assert_eq!(body.len(), 5);
        let mut received = Vec::new();
        assert!(body.send(|bytes, fin| {
            assert!(fin);
            received.extend_from_slice(bytes);
            Ok(bytes.len())
        })?);
        assert_eq!(received, b"index");
        Ok(())
    }
}
