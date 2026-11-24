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

#[path = "support/http3.rs"]
mod http3;
#[path = "support/transport.rs"]
mod transport;

#[path = "support/response.rs"]
mod response;
#[path = "support/server.rs"]
mod server;

use quiche::h3::NameValue;
use quiche::h3::{
    self,
};
use std::collections::HashMap;
use std::path::Path;

struct Response {
    headers: Option<Vec<h3::Header>>,
    body: response::Body,
}

impl Response {
    fn new(root: &Path, request: &[h3::Header]) -> Self {
        let method = request.iter().find(|header| header.name() == b":method");
        let target = request.iter().find(|header| header.name() == b":path");
        let (status, body) =
            match (method.map(NameValue::value), target.map(NameValue::value)) {
                (Some(b"GET"), Some(target)) => response::file_body(root, target)
                    .map_or_else(
                        |_| (404, b"Not Found!".to_vec()),
                        |bytes| (200, bytes),
                    ),
                (Some(b"GET"), None) | (None, _) => (400, Vec::new()),
                _ => (405, Vec::new()),
            };
        Self {
            headers: Some(vec![
                h3::Header::new(b":status", status.to_string().as_bytes()),
                h3::Header::new(b"server", b"quiche"),
                h3::Header::new(
                    b"content-length",
                    body.len().to_string().as_bytes(),
                ),
            ]),
            body: response::Body::new(body),
        }
    }

    fn send(
        &mut self, http3: &mut h3::Connection, conn: &mut quiche::Connection,
        id: u64,
    ) -> h3::Result<bool> {
        if let Some(headers) = &self.headers {
            match http3.send_response(conn, id, headers, false) {
                Ok(()) => self.headers = None,
                Err(h3::Error::StreamBlocked) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        self.body
            .send(|bytes| match http3.send_body(conn, id, bytes, true) {
                Ok(written) => Ok(Some(written)),
                Err(h3::Error::Done) => Ok(None),
                Err(error) => Err(error),
            })
    }
}

#[derive(Default)]
struct Http3 {
    connection: Option<h3::Connection>,
    responses: HashMap<u64, Response>,
}

impl server::Protocol for Http3 {
    fn process(
        &mut self, conn: &mut quiche::Connection, buffer: &mut [u8], root: &Path,
    ) -> transport::Result<()> {
        let http3 = http3::connection(&mut self.connection, conn)?;
        loop {
            match http3.poll(conn) {
                Ok((id, h3::Event::Headers { list, .. })) => {
                    if self.responses.contains_key(&id) {
                        continue;
                    }
                    // The demo answers the request headers without a body.
                    match conn.stream_shutdown(id, quiche::Shutdown::Read, 0) {
                        Ok(()) | Err(quiche::Error::Done) => (),
                        Err(error) => return Err(error.into()),
                    }
                    self.responses.insert(id, Response::new(root, &list));
                },
                Ok((id, h3::Event::Data)) => loop {
                    match http3.recv_body(conn, id, buffer) {
                        Ok(_) => (),
                        Err(h3::Error::Done) => break,
                        Err(error) => return Err(error.into()),
                    }
                },
                Ok((id, h3::Event::Reset(_))) => {
                    self.responses.remove(&id);
                },
                Ok((
                    _,
                    h3::Event::Finished |
                    h3::Event::PriorityUpdate |
                    h3::Event::GoAway,
                )) => (),
                Err(h3::Error::Done) => break,
                Err(error) => return Err(error.into()),
            }
        }
        self.responses.retain(|&id, response| {
            match response.send(http3, conn, id) {
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

fn main() -> transport::Result<()> {
    server::run::<Http3>(h3::APPLICATION_PROTOCOL)
}
