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

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use crate::transport::DatagramOutput;
use crate::transport::Result;
use crate::transport::{
    self,
};

pub trait Protocol: Default {
    fn process(
        &mut self, conn: &mut quiche::Connection, buffer: &mut [u8], root: &Path,
    ) -> Result<()>;
}

struct Session<P> {
    connection: quiche::Connection,
    protocol: P,
}

struct RetryTokens {
    cid_key: [u8; 32],
    token_key: [u8; 32],
}

impl RetryTokens {
    fn new() -> io::Result<Self> {
        let generate = || {
            let mut key = [0; 32];
            btls::rand::rand_bytes(&mut key)
                .map_err(|error| io::Error::other(error.to_string()))?;
            Ok::<_, io::Error>(key)
        };
        Ok(Self {
            cid_key: generate()?,
            token_key: generate()?,
        })
    }

    fn cid(&self, original: &[u8]) -> Result<quiche::ConnectionId<'static>> {
        let tag = btls::hash::hmac_sha256(&self.cid_key, original)?;
        Ok(quiche::ConnectionId::from_vec(
            tag[..quiche::MAX_CONN_ID_LEN].to_vec(),
        ))
    }

    fn address_prefix(ip: IpAddr) -> Vec<u8> {
        match ip {
            IpAddr::V4(address) => [vec![4], address.octets().to_vec()].concat(),
            IpAddr::V6(address) => [vec![6], address.octets().to_vec()].concat(),
        }
    }

    fn mint(&self, peer: SocketAddr, original: &[u8]) -> Result<Vec<u8>> {
        let mut token = Self::address_prefix(peer.ip());
        token.extend_from_slice(original);
        let tag = btls::hash::hmac_sha256(&self.token_key, &token)?;
        token.extend_from_slice(&tag);
        Ok(token)
    }

    fn validate<'a>(
        &self, peer: SocketAddr, token: &'a [u8], destination: &[u8],
    ) -> Option<quiche::ConnectionId<'a>> {
        // HMAC-SHA256 uses a 32-byte tag.
        let (payload, tag) =
            token.split_at_checked(token.len().checked_sub(32)?)?;
        let expected = btls::hash::hmac_sha256(&self.token_key, payload).ok()?;
        if !btls::memcmp::eq(&expected, tag) {
            return None;
        }
        let original =
            payload.strip_prefix(Self::address_prefix(peer.ip()).as_slice())?;
        if !(8..=quiche::MAX_CONN_ID_LEN).contains(&original.len()) ||
            self.cid(original).ok()?.as_ref() != destination
        {
            return None;
        }
        Some(quiche::ConnectionId::from_ref(original))
    }
}

struct Router<P> {
    config: quiche::Config,
    tokens: RetryTokens,
    sessions: HashMap<quiche::ConnectionId<'static>, Session<P>>,
    local: SocketAddr,
}

impl<P: Protocol> Router<P> {
    fn route(
        &mut self, header: &quiche::Header<'static>, peer: SocketAddr,
        output: &mut DatagramOutput, socket: &mio::net::UdpSocket,
    ) -> Result<Option<&mut Session<P>>> {
        if self.sessions.contains_key(&header.dcid) {
            return Ok(self.sessions.get_mut(&header.dcid));
        }
        if header.ty != quiche::Type::Initial {
            return Ok(None);
        }
        if !quiche::version_is_supported(header.version) {
            let length = quiche::negotiate_version(
                &header.scid,
                &header.dcid,
                output.buffer(),
            )?;
            output.send(socket, length, peer)?;
            return Ok(None);
        }
        let Some(token) = header.token.as_deref() else {
            return Ok(None);
        };
        if token.is_empty() {
            if !(8..=quiche::MAX_CONN_ID_LEN).contains(&header.dcid.len()) {
                return Ok(None);
            }
            let scid = self.tokens.cid(&header.dcid)?;
            let token = self.tokens.mint(peer, &header.dcid)?;
            let length = quiche::retry(
                &header.scid,
                &header.dcid,
                &scid,
                &token,
                header.version,
                output.buffer(),
            )?;
            output.send(socket, length, peer)?;
            return Ok(None);
        }
        let Some(original) = self.tokens.validate(peer, token, &header.dcid)
        else {
            return Ok(None);
        };

        let cid = header.dcid.clone().into_owned();
        let connection = quiche::accept(
            &cid,
            Some(&original),
            self.local,
            peer,
            &mut self.config,
        )?;
        Ok(Some(self.sessions.entry(cid).or_insert(Session {
            connection,
            protocol: P::default(),
        })))
    }
}

struct Server<P> {
    router: Router<P>,
    poll: mio::Poll,
    events: mio::Events,
    socket: mio::net::UdpSocket,
    input: Vec<u8>,
    output: DatagramOutput,
    root: PathBuf,
}

impl<P: Protocol> Server<P> {
    fn new(protocols: &[&[u8]], root: PathBuf) -> Result<Self> {
        let poll = mio::Poll::new()?;
        let mut socket = mio::net::UdpSocket::bind(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            4433,
        )))?;
        poll.registry().register(
            &mut socket,
            mio::Token(0),
            mio::Interest::READABLE,
        )?;
        let local = socket.local_addr()?;

        let mut config = transport::demo_config(protocols)?;
        config.load_cert_chain_from_pem_file("examples/cert.crt")?;
        config.load_priv_key_from_pem_file("examples/cert.key")?;
        config.enable_early_data();

        Ok(Self {
            router: Router {
                config,
                tokens: RetryTokens::new()?,
                sessions: HashMap::new(),
                local,
            },
            poll,
            events: mio::Events::with_capacity(1024),
            socket,
            input: vec![0; transport::MAX_UDP_PAYLOAD],
            output: DatagramOutput::default(),
            root,
        })
    }

    fn run(&mut self) -> Result<()> {
        loop {
            let blocked = self.output.blocked();
            let timeout = self
                .router
                .sessions
                .values()
                .filter_map(|session| session.connection.timeout())
                .min();
            self.poll.poll(&mut self.events, timeout)?;
            self.output.flush(&self.socket)?;
            if !self.output.blocked() {
                self.receive_available()?;
            }
            self.process_sessions();
            if !self.output.blocked() {
                self.flush_connections()?;
            }
            if blocked != self.output.blocked() {
                // Stop reading while the single output slot is occupied.
                // Re-registering READABLE resumes the receive queue once
                // the socket accepts the pending datagram.
                let interest = if self.output.blocked() {
                    mio::Interest::WRITABLE
                } else {
                    mio::Interest::READABLE
                };
                self.poll.registry().reregister(
                    &mut self.socket,
                    mio::Token(0),
                    interest,
                )?;
            }
            self.router
                .sessions
                .retain(|_, session| !session.connection.is_closed());
        }
    }

    fn receive_available(&mut self) -> Result<()> {
        while !self.output.blocked() {
            let Some((length, peer)) =
                transport::receive_datagram(&self.socket, &mut self.input)?
            else {
                break;
            };
            let packet = &mut self.input[..length];
            let header =
                match quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN)
                {
                    Ok(header) => header,
                    Err(error) => {
                        log::debug!("invalid packet header: {error}");
                        continue;
                    },
                };
            let local = self.router.local;
            let session = match self.router.route(
                &header,
                peer,
                &mut self.output,
                &self.socket,
            ) {
                Ok(session) => session,
                Err(error) => {
                    // A failed QUIC operation on an untrusted packet is local
                    // to that packet. Socket failures are server-wide errors.
                    if error.is::<io::Error>() {
                        return Err(error);
                    }
                    log::debug!("could not route packet: {error}");
                    continue;
                },
            };
            if let Some(session) = session {
                let info = quiche::RecvInfo {
                    from: peer,
                    to: local,
                };
                if let Err(error) = session.connection.recv(packet, info) {
                    log::debug!("packet receive failed: {error}");
                }
            }
        }
        Ok(())
    }

    fn process_sessions(&mut self) {
        for session in self.router.sessions.values_mut() {
            let conn = &mut session.connection;
            conn.on_timeout();
            if !conn.is_closed() &&
                !conn.is_draining() &&
                (conn.is_established() || conn.is_in_early_data())
            {
                if let Err(error) =
                    session.protocol.process(conn, &mut self.input, &self.root)
                {
                    log::warn!("{} application error: {error}", conn.trace_id());
                    let _ = conn.close(false, 1, b"application error");
                }
            }
        }
    }

    fn flush_connections(&mut self) -> io::Result<()> {
        for session in self.router.sessions.values_mut() {
            while !self.output.blocked() {
                match session.connection.send(self.output.buffer()) {
                    Ok((length, info)) =>
                        self.output.send(&self.socket, length, info.to)?,
                    Err(quiche::Error::Done) => break,
                    Err(error) => {
                        log::debug!("packet send failed: {error}");
                        let _ = session.connection.close(false, 1, b"send error");
                        break;
                    },
                }
            }
            if self.output.blocked() {
                break;
            }
        }
        Ok(())
    }
}

pub fn run<P: Protocol>(protocols: &[&[u8]]) -> Result<()> {
    let mut args = std::env::args_os();
    let command = args.next().unwrap_or_default();
    let root = args
        .next()
        .map_or_else(|| PathBuf::from("examples/root"), PathBuf::from);
    if args.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Usage: {} [DOCUMENT_ROOT]", command.to_string_lossy()),
        )
        .into());
    }
    Server::<P>::new(protocols, root)?.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_token_binds_original_cid_address_and_destination() -> Result<()> {
        let tokens = RetryTokens::new()?;
        let original = [3; 16];
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
        let destination = tokens.cid(&original)?;
        let token = tokens.mint(peer, &original)?;
        assert_eq!(
            tokens.validate(peer, &token, &destination).as_deref(),
            Some(original.as_slice())
        );
        assert!(tokens
            .validate(
                SocketAddr::from(([127, 0, 0, 2], 1234)),
                &token,
                &destination
            )
            .is_none());
        assert!(tokens.validate(peer, &token, &[0; 16]).is_none());
        for index in 0..token.len() {
            let mut corrupted = token.clone();
            corrupted[index] ^= 1;
            assert!(tokens.validate(peer, &corrupted, &destination).is_none());
        }
        Ok(())
    }
}
