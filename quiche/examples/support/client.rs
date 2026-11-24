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

use std::error::Error;
use std::io;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::time::Duration;

use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use url::Url;

use crate::transport::DatagramOutput;
use crate::transport::Result;
use crate::transport::{
    self,
};

pub fn request_url(argument: std::ffi::OsString) -> Result<Url> {
    let argument = argument.into_string().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "URL must be Unicode")
    })?;
    let url = Url::parse(&argument)?;
    if url.host().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "URL lacks a host",
        )
        .into());
    }
    Ok(url)
}

pub fn request_target(url: &Url) -> String {
    let mut target = String::from(url.path());
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    target
}

pub struct ClientTransport {
    conn: quiche::Connection,
    poll: mio::Poll,
    events: mio::Events,
    socket: mio::net::UdpSocket,
    local_addr: SocketAddr,
    input: Vec<u8>,
    output: DatagramOutput,
}

impl ClientTransport {
    pub fn connect(url: &Url, protocols: &[&[u8]]) -> Result<Self> {
        let peer_addr = url
            .socket_addrs(|| None)?
            .into_iter()
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no resolved server address",
                )
            })?;
        let bind_addr = match peer_addr {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let poll = mio::Poll::new()?;
        let mut socket = mio::net::UdpSocket::bind(bind_addr)?;
        poll.registry().register(
            &mut socket,
            mio::Token(0),
            mio::Interest::READABLE,
        )?;

        let mut config = transport::demo_config(protocols)?;
        // Demo certificates only. Production clients must verify their peer.
        config.verify_peer(false);

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new().fill(&mut scid).map_err(|_| {
            io::Error::other("could not generate a connection ID")
        })?;
        let scid = quiche::ConnectionId::from_ref(&scid);
        let local_addr = socket.local_addr()?;
        let conn = quiche::connect(
            url.domain(),
            &scid,
            local_addr,
            peer_addr,
            &mut config,
        )?;
        log::info!(
            "connecting to {peer_addr} from {local_addr} with scid {scid:?}"
        );

        Ok(Self {
            conn,
            poll,
            events: mio::Events::with_capacity(1024),
            socket,
            local_addr,
            input: vec![0; transport::MAX_UDP_PAYLOAD],
            output: DatagramOutput::default(),
        })
    }

    /// Drive the transport until it closes, letting the protocol handler
    /// process available stream data and enqueue writes between UDP batches.
    pub fn run(
        &mut self,
        mut process: impl FnMut(&mut quiche::Connection, &mut [u8]) -> Result<()>,
    ) -> Result<()> {
        self.flush()?;
        while !self.conn.is_closed() {
            self.poll.poll(&mut self.events, self.conn.timeout())?;
            self.receive_available()?;
            if self
                .conn
                .timeout()
                .is_some_and(|timeout| timeout == Duration::ZERO)
            {
                self.conn.on_timeout();
            }
            if self.conn.is_closed() {
                break;
            }
            if !self.conn.is_draining() {
                process(&mut self.conn, &mut self.input)?;
            }
            self.flush()?;
        }
        log::info!("connection closed, {:?}", self.conn.stats());
        Ok(())
    }

    fn receive_available(&mut self) -> io::Result<()> {
        while let Some((length, from)) =
            transport::receive_datagram(&self.socket, &mut self.input)?
        {
            let info = quiche::RecvInfo {
                to: self.local_addr,
                from,
            };
            match self.conn.recv(&mut self.input[..length], info) {
                Ok(read) => log::debug!("processed {read} bytes"),
                Err(error) => log::debug!("recv failed: {error:?}"),
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        let was_blocked = self.output.blocked();
        self.output.flush(&self.socket)?;
        while !self.output.blocked() {
            match self.conn.send(self.output.buffer()) {
                Ok((length, info)) =>
                    self.output.send(&self.socket, length, info.to)?,
                Err(quiche::Error::Done) => break,
                Err(error) => return Err(error.into()),
            }
        }
        let blocked = self.output.blocked();
        if blocked != was_blocked {
            let interest = if blocked {
                mio::Interest::READABLE | mio::Interest::WRITABLE
            } else {
                mio::Interest::READABLE
            };
            self.poll.registry().reregister(
                &mut self.socket,
                mio::Token(0),
                interest,
            )?;
        }
        Ok(())
    }
}

pub fn incomplete_response() -> Box<dyn Error> {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "connection closed before a complete response",
    )
    .into()
}
