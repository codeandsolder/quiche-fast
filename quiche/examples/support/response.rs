// Copyright (C) 2018-2019, Cloudflare, Inc.
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

use std::io;
use std::path::Component;
use std::path::Path;

/// Resolve a request target below the configured document root. Query
/// parameters are not filesystem names, and symlinks must stay in the root.
pub fn file_body(root: &Path, target: &[u8]) -> io::Result<Vec<u8>> {
    let invalid_path =
        || io::Error::new(io::ErrorKind::InvalidInput, "invalid request path");
    let target = std::str::from_utf8(target).map_err(|_| invalid_path())?;
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let root = root.canonicalize()?;
    let mut resolved = root.clone();
    for component in Path::new(path).components() {
        match component {
            Component::RootDir | Component::CurDir => (),
            Component::Normal(part) => resolved.push(part),
            _ => return Err(invalid_path()),
        }
    }
    let resolved = resolved.canonicalize()?;
    if !resolved.starts_with(&root) {
        return Err(invalid_path());
    }
    std::fs::read(resolved)
}

/// A response is complete only after the transport accepts the final write,
/// including an empty body. WouldBlock must not be confused with zero bytes
/// successfully written with FIN.
pub struct Body {
    bytes: Vec<u8>,
    offset: usize,
}

impl Body {
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn send<E>(
        &mut self, write: impl FnOnce(&[u8]) -> Result<Option<usize>, E>,
    ) -> Result<bool, E> {
        let Some(written) = write(&self.bytes[self.offset..])? else {
            return Ok(false);
        };
        self.offset += written;
        Ok(self.offset == self.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_body_requires_successful_fin_write() -> io::Result<()> {
        let mut body = Body::new(Vec::new());
        assert!(!body.send(|_| Ok::<_, io::Error>(None))?);
        assert!(body.send(|_| Ok::<_, io::Error>(Some(0)))?);
        Ok(())
    }

    #[test]
    fn partial_body_retains_only_unsent_suffix() -> io::Result<()> {
        let mut body = Body::new(b"abcde".to_vec());
        assert!(!body.send(|bytes| {
            assert_eq!(bytes, b"abcde");
            Ok::<_, io::Error>(Some(2))
        })?);
        assert!(!body.send(|bytes| {
            assert_eq!(bytes, b"cde");
            Ok::<_, io::Error>(None)
        })?);
        assert!(body.send(|bytes| {
            assert_eq!(bytes, b"cde");
            Ok::<_, io::Error>(Some(3))
        })?);
        Ok(())
    }
}
