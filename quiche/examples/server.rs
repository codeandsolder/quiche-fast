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

#[path = "support/transport.rs"]
mod transport;

#[path = "support/response.rs"]
mod response;
#[path = "support/server.rs"]
mod server;

use std::collections::HashMap;
use std::path::Path;

const HTTP09_PROTOCOLS: &[&[u8]] =
    &[b"hq-interop", b"hq-29", b"hq-28", b"hq-27", b"http/0.9"];
const MAX_REQUEST_LINE: usize = 16 * 1024;

#[derive(Default)]
struct Http09 {
    requests: HashMap<u64, Vec<u8>>,
    responses: HashMap<u64, response::Body>,
}

impl Http09 {
    fn receive(
        &mut self, conn: &mut quiche::Connection, id: u64, buffer: &mut [u8],
        root: &Path,
    ) -> quiche::Result<()> {
        // Only client-initiated bidirectional streams carry requests.
        if !id.is_multiple_of(4) {
            conn.stream_shutdown(id, quiche::Shutdown::Read, 0)?;
            return Ok(());
        }
        loop {
            match conn.stream_recv(id, buffer) {
                Ok((read, fin)) => {
                    let request = self.requests.entry(id).or_default();
                    if request.len().saturating_add(read) > MAX_REQUEST_LINE {
                        self.requests.remove(&id);
                        conn.stream_shutdown(id, quiche::Shutdown::Read, 0)?;
                        return conn.stream_shutdown(
                            id,
                            quiche::Shutdown::Write,
                            0,
                        );
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if fin || request.contains(&b'\n') {
                        if let Some(request) = self.requests.remove(&id) {
                            let body = request_body(root, &request);
                            self.responses.insert(id, response::Body::new(body));
                        }
                        if !fin {
                            conn.stream_shutdown(id, quiche::Shutdown::Read, 0)?;
                        }
                        break;
                    }
                },
                Err(quiche::Error::Done) => break,
                Err(quiche::Error::StreamReset(_)) => {
                    self.requests.remove(&id);
                    self.responses.remove(&id);
                    break;
                },
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

impl server::Protocol for Http09 {
    fn process(
        &mut self, conn: &mut quiche::Connection, buffer: &mut [u8], root: &Path,
    ) -> transport::Result<()> {
        for id in conn.readable() {
            self.receive(conn, id, buffer, root)?;
        }
        self.responses.retain(|&id, body| {
            match body.send(|bytes| match conn.stream_send(id, bytes, true) {
                Ok(written) => Ok(Some(written)),
                Err(quiche::Error::Done) => Ok(None),
                Err(error) => Err(error),
            }) {
                Ok(complete) => !complete,
                Err(error) => {
                    log::debug!("response stream {id}: {error}");
                    false
                },
            }
        });
        Ok(())
    }
}

fn request_body(root: &Path, request: &[u8]) -> Vec<u8> {
    let Some(target) = request.strip_prefix(b"GET ") else {
        return b"Bad Request!\r\n".to_vec();
    };
    let target = target
        .split(|&byte| byte == b'\n')
        .next()
        .unwrap_or_default();
    let target = target.strip_suffix(b"\r").unwrap_or(target);
    response::file_body(root, target)
        .unwrap_or_else(|_| b"Not Found!\r\n".to_vec())
}

fn main() -> transport::Result<()> {
    server::run::<Http09>(HTTP09_PROTOCOLS)
}
