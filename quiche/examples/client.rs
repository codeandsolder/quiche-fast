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

#[path = "support/client.rs"]
mod client;
#[path = "support/input.rs"]
mod input;

use std::io::Write;
use std::io::{
    self,
};
use std::time::Instant;

const HTTP_REQ_STREAM_ID: u64 = 4;
const HTTP09_PROTOCOLS: &[&[u8]] =
    &[b"hq-interop", b"hq-29", b"hq-28", b"hq-27", b"http/0.9"];

fn main() -> client::Result<()> {
    let url = client::request_url(input::one_argument("URL")?)?;
    let mut transport = client::ClientTransport::connect(&url, HTTP09_PROTOCOLS)?;
    let request = format!("GET {}\r\n", client::request_target(&url));
    let mut request_offset = 0;
    let mut finished = false;
    let start = Instant::now();
    let mut stdout = io::stdout().lock();

    transport.run(|conn, buffer| {
        if finished {
            return Ok(());
        }
        if conn.is_established() && request_offset < request.len() {
            match conn.stream_send(
                HTTP_REQ_STREAM_ID,
                &request.as_bytes()[request_offset..],
                true,
            ) {
                Ok(written) => request_offset += written,
                Err(quiche::Error::Done | quiche::Error::StreamLimit) => (),
                Err(error) => return Err(error.into()),
            }
        }

        for stream_id in conn.readable() {
            loop {
                match conn.stream_recv(stream_id, buffer) {
                    Ok((read, fin)) => {
                        stdout.write_all(&buffer[..read])?;
                        if stream_id == HTTP_REQ_STREAM_ID && fin {
                            log::info!(
                                "response received in {:?}",
                                start.elapsed()
                            );
                            finished = true;
                            conn.close(true, 0, b"response complete")?;
                        }
                        if fin {
                            break;
                        }
                    },
                    Err(quiche::Error::Done) => break,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(())
    })?;
    if !finished {
        return Err(client::incomplete_response());
    }
    stdout.flush()?;
    Ok(())
}
