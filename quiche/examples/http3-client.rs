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

#[path = "support/client.rs"]
mod client;
#[path = "support/input.rs"]
mod input;

use quiche::h3::NameValue;
use quiche::h3::{
    self,
};
use std::io::Write;
use std::io::{
    self,
};
use std::time::Instant;
use url::Url;

struct Request {
    headers: Vec<h3::Header>,
    connection: Option<h3::Connection>,
    stream_id: Option<u64>,
    start: Instant,
    finished: bool,
}

impl Request {
    fn new(url: &Url) -> transport::Result<Self> {
        let host = url.host_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "URL lacks a host")
        })?;
        let authority = url
            .port()
            .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"));
        let target = client::request_target(url);
        Ok(Self {
            headers: vec![
                h3::Header::new(b":method", b"GET"),
                h3::Header::new(b":scheme", url.scheme().as_bytes()),
                h3::Header::new(b":authority", authority.as_bytes()),
                h3::Header::new(b":path", target.as_bytes()),
                h3::Header::new(b"user-agent", b"quiche"),
            ],
            connection: None,
            stream_id: None,
            start: Instant::now(),
            finished: false,
        })
    }

    fn process(
        &mut self, conn: &mut quiche::Connection, buffer: &mut [u8],
        writer: &mut impl Write,
    ) -> transport::Result<()> {
        if self.finished || !conn.is_established() {
            return Ok(());
        }
        let http3 = http3::connection(&mut self.connection, conn)?;

        if self.stream_id.is_none() {
            match http3.send_request(conn, &self.headers, true) {
                Ok(id) => self.stream_id = Some(id),
                Err(h3::Error::StreamBlocked) => (),
                Err(error) => return Err(error.into()),
            }
        }

        loop {
            match http3.poll(conn) {
                Ok((id, h3::Event::Headers { list, .. })) =>
                    for header in list {
                        log::info!(
                            "stream {id}: {}: {}",
                            String::from_utf8_lossy(header.name()),
                            String::from_utf8_lossy(header.value())
                        );
                    },
                Ok((id, h3::Event::Data)) => {
                    read_body(http3, conn, id, buffer, writer)?;
                },
                Ok((id, h3::Event::Finished)) if Some(id) == self.stream_id => {
                    log::info!("response received in {:?}", self.start.elapsed());
                    self.finished = true;
                    conn.close(
                        true,
                        h3::WireErrorCode::NoError as u64,
                        b"response complete",
                    )?;
                    break;
                },
                Ok((id, h3::Event::Reset(code)))
                    if Some(id) == self.stream_id =>
                {
                    return Err(io::Error::other(format!(
                        "request reset with code {code}"
                    ))
                    .into());
                },
                Ok((id, h3::Event::GoAway)) => log::info!("GOAWAY id={id}"),
                Ok((
                    _,
                    h3::Event::Finished |
                    h3::Event::Reset(_) |
                    h3::Event::PriorityUpdate,
                )) => (),
                Err(h3::Error::Done) => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

fn read_body(
    http3: &mut h3::Connection, conn: &mut quiche::Connection, stream_id: u64,
    buffer: &mut [u8], writer: &mut impl Write,
) -> transport::Result<()> {
    loop {
        match http3.recv_body(conn, stream_id, buffer) {
            Ok(read) => writer.write_all(&buffer[..read])?,
            Err(h3::Error::Done) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
}

fn main() -> transport::Result<()> {
    let url = client::request_url(input::one_argument("URL")?)?;
    let mut transport =
        client::ClientTransport::connect(&url, h3::APPLICATION_PROTOCOL)?;
    let mut request = Request::new(&url)?;
    let mut stdout = io::stdout().lock();
    transport.run(|conn, buffer| request.process(conn, buffer, &mut stdout))?;
    if !request.finished {
        return Err(client::incomplete_response());
    }
    stdout.flush()?;
    Ok(())
}
