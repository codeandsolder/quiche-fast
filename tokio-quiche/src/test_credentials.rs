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

use std::io;

/// Holds embedded test credentials for the lifetime of their configuration.
pub struct TestCredentials {
    _directory: tempfile::TempDir,
    cert: String,
    key: String,
}

impl TestCredentials {
    pub fn new() -> io::Result<Self> {
        let directory = tempfile::tempdir()?;
        let cert = directory.path().join("cert.crt");
        let key = directory.path().join("cert.key");
        std::fs::write(&cert, include_bytes!("../../quiche/examples/cert.crt"))?;
        std::fs::write(&key, include_bytes!("../../quiche/examples/cert.key"))?;
        Ok(Self {
            _directory: directory,
            cert: cert
                .into_os_string()
                .into_string()
                .map_err(|_| io::Error::other("certificate path is not UTF-8"))?,
            key: key
                .into_os_string()
                .into_string()
                .map_err(|_| io::Error::other("key path is not UTF-8"))?,
        })
    }

    pub fn paths(&self) -> (&str, &str) {
        (&self.cert, &self.key)
    }
}
