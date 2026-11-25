// Copyright (C) 2020, Cloudflare, Inc.
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

use log::debug;
use log::error;
use log::info;
use log::trace;
use log::warn;
use quiche::Connection;
use quiche::ConnectionId;
use quiche::Header;
use quiche::RecvInfo;
use quiche::SendInfo;
use quiche_apps::args::Args;
use quiche_apps::args::CommonArgs;
use quiche_apps::args::ServerArgs;
use quiche_apps::args::SERVER_USAGE;
use quiche_apps::common::alpns;
use quiche_apps::common::generate_cid_and_reset_token;
use quiche_apps::common::stdout_sink;
use quiche_apps::common::Http09Conn;
use quiche_apps::common::Http3Conn;
use quiche_apps::common::HttpConn;
use quiche_apps::common::PartialRequest;
use quiche_apps::common::PartialResponse;
use quiche_apps::sendto::detect_gso;
use quiche_apps::sendto::DatagramBatch;
use quiche_apps::sendto::DatagramQueue;
use ring::hmac;
use ring::rand::SystemRandom;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;
use std::time::Instant;

const MAX_BUF_SIZE: usize = 65_507;
const MAX_DATAGRAM_SIZE: usize = 1350;
const MAX_READ_BURST: usize = 64;
const SOCKET_TOKEN: mio::Token = mio::Token(0);
const RETRY_TOKEN_LIFETIME: u64 = 60;

type ClientId = u64;

fn failure(context: &str, error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("{context}: {error}"))
}

fn main() {
    env_logger::builder().format_timestamp_nanos().init();
    let parsed = docopt::Docopt::new(SERVER_USAGE)
        .and_then(|parser| parser.parse())
        .unwrap_or_else(|error| error.exit());
    let common =
        CommonArgs::from_args(&parsed).unwrap_or_else(|error| error.exit());
    let args =
        ServerArgs::from_args(&parsed).unwrap_or_else(|error| error.exit());
    if let Err(error) = run(&args, &common) {
        error!("server: {error}");
        std::process::exit(1);
    }
}

fn run(args: &ServerArgs, common: &CommonArgs) -> io::Result<()> {
    let mut io = ServerIo::new(args)?;
    let mut connections = Connections::new(args, common, io.pacing)?;
    let mut immediate = false;

    loop {
        let timeout = if immediate {
            Some(Duration::ZERO)
        } else {
            connections.timeout()
        };
        match io.poll.poll(&mut io.events, timeout) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(failure("poll", error)),
        }

        // A readable socket can remain continuously ready. Timers are due
        // according to their deadlines, not the absence of readiness events.
        connections.expire();
        let drained = io.flush()?;
        let more_input = drained && io.receive(&mut connections)?;
        connections.expire();
        let more_output = connections.send_available(&mut io)?;
        connections.collect_closed();
        immediate = !io.tx.is_pending() && (more_input || more_output);
    }
}

struct ServerIo {
    poll: mio::Poll,
    events: mio::Events,
    socket: mio::net::UdpSocket,
    local: SocketAddr,
    pacing: bool,
    tx: DatagramQueue,
    input: Vec<u8>,
    output: Vec<u8>,
    batches: Vec<DatagramBatch>,
    packet_count: u64,
}

impl ServerIo {
    fn new(args: &ServerArgs) -> io::Result<Self> {
        let poll = mio::Poll::new()?;
        let mut socket = mio::net::UdpSocket::bind(args.listen)?;
        let pacing = args.socket.pacing &&
            match set_txtime_sockopt(&socket) {
                Ok(()) => true,
                Err(error) => {
                    debug!("SO_TXTIME unavailable: {error}");
                    false
                },
            };
        let gso = args.socket.gso && detect_gso(&socket, MAX_DATAGRAM_SIZE);
        let local = socket.local_addr()?;
        info!("listening on {local}; GSO={gso}, pacing={pacing}");
        poll.registry().register(
            &mut socket,
            SOCKET_TOKEN,
            mio::Interest::READABLE,
        )?;
        Ok(Self {
            poll,
            events: mio::Events::with_capacity(1024),
            socket,
            local,
            pacing,
            tx: DatagramQueue::new(MAX_BUF_SIZE, gso),
            input: vec![0; MAX_BUF_SIZE],
            output: vec![0; MAX_BUF_SIZE],
            batches: Vec::new(),
            packet_count: 0,
        })
    }

    fn flush(&mut self) -> io::Result<bool> {
        self.tx
            .flush(&mut self.socket, self.poll.registry(), SOCKET_TOKEN)
    }

    fn submit(&mut self) -> io::Result<bool> {
        self.tx.submit(
            &mut self.output,
            &mut self.batches,
            &mut self.socket,
            self.poll.registry(),
            SOCKET_TOKEN,
        )
    }

    fn receive(&mut self, connections: &mut Connections<'_>) -> io::Result<bool> {
        for _ in 0..MAX_READ_BURST {
            if self.tx.is_pending() {
                return Ok(false);
            }
            let (len, peer) = match self.socket.recv_from(&mut self.input) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock =>
                    return Ok(false),
                Err(error) if error.kind() == io::ErrorKind::Interrupted =>
                    continue,
                Err(error) => return Err(failure("receive UDP", error)),
            };
            if let Some(directory) = &connections.common.dump_packet_path {
                let path = std::path::Path::new(directory)
                    .join(format!("{}.pkt", self.packet_count));
                std::fs::write(path, &self.input[..len])
                    .map_err(|error| failure("dump UDP packet", error))?;
            }
            self.packet_count += 1;

            let header = match Header::from_slice(
                &self.input[..len],
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(header) => header,
                Err(error) => {
                    debug!("invalid QUIC header from {peer}: {error}");
                    continue;
                },
            };
            let route = match connections.route(
                &header,
                len,
                self.local,
                peer,
                &mut self.output,
            ) {
                Ok(route) => route,
                Err(error) => {
                    debug!("admission from {peer}: {error}");
                    continue;
                },
            };
            match route {
                Route::Drop => (),
                Route::Reply(written) => {
                    let info = SendInfo {
                        from: self.local,
                        to: peer,
                        at: Instant::now(),
                    };
                    DatagramBatch::push(
                        &mut self.batches,
                        0..written,
                        info,
                        false,
                    );
                    self.submit()?;
                },
                Route::Client(id) => {
                    connections.receive(
                        id,
                        RecvInfo {
                            to: self.local,
                            from: peer,
                        },
                        len,
                        &mut self.input,
                    );
                },
            }
        }
        // Edge-triggered readiness may not repeat; explicitly revisit unread
        // packets after giving timers and transmit work a chance to run.
        Ok(true)
    }
}

enum Route {
    Drop,
    Reply(usize),
    Client(ClientId),
}

struct Connections<'a> {
    args: &'a ServerArgs,
    common: &'a CommonArgs,
    config: quiche::Config,
    keylog: Option<std::fs::File>,
    rng: SystemRandom,
    cid_key: hmac::Key,
    retry: RetryTokens,
    next_id: ClientId,
    clients: HashMap<ClientId, Client>,
    ids: HashMap<ConnectionId<'static>, ClientId>,
    schedule: VecDeque<ClientId>,
}

impl<'a> Connections<'a> {
    fn new(
        args: &'a ServerArgs, common: &'a CommonArgs, pacing: bool,
    ) -> io::Result<Self> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|error| failure("QUIC configuration", error))?;
        config
            .load_cert_chain_from_pem_file(&args.cert)
            .map_err(|error| failure("certificate", error))?;
        config
            .load_priv_key_from_pem_file(&args.key)
            .map_err(|error| failure("private key", error))?;
        common
            .configure(&mut config, MAX_DATAGRAM_SIZE)
            .map_err(|error| failure("transport configuration", error))?;
        config.discover_pmtu(args.enable_pmtud);
        config.enable_pacing(pacing);
        let keylog = std::env::var_os("SSLKEYLOGFILE")
            .map(|path| {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
            })
            .transpose()?;
        if keylog.is_some() {
            config.log_keys();
        }
        let rng = SystemRandom::new();
        let cid_key = hmac::Key::generate(hmac::HMAC_SHA256, &rng)
            .map_err(|error| failure("CID key", error))?;
        let retry = RetryTokens::new(&rng)?;
        Ok(Self {
            args,
            common,
            config,
            keylog,
            rng,
            cid_key,
            retry,
            next_id: 0,
            clients: HashMap::new(),
            ids: HashMap::new(),
            schedule: VecDeque::new(),
        })
    }

    fn derived_cid(&self, dcid: &ConnectionId<'_>) -> ConnectionId<'static> {
        if cfg!(feature = "fuzzing") {
            return ConnectionId::copy_from_slice(&[0; quiche::MAX_CONN_ID_LEN]);
        }
        let tag = hmac::sign(&self.cid_key, dcid);
        ConnectionId::copy_from_slice(&tag.as_ref()[..quiche::MAX_CONN_ID_LEN])
    }

    fn route(
        &mut self, header: &Header<'static>, len: usize, local: SocketAddr,
        peer: SocketAddr, output: &mut [u8],
    ) -> quiche::Result<Route> {
        if let Some(&id) = self.ids.get(&header.dcid) {
            return Ok(Route::Client(id));
        }
        let derived = self.derived_cid(&header.dcid);
        if let Some(&id) = self.ids.get(&derived) {
            return Ok(Route::Client(id));
        }
        if header.ty != quiche::Type::Initial ||
            len < quiche::MIN_CLIENT_INITIAL_LEN
        {
            return Ok(Route::Drop);
        }
        if !quiche::version_is_supported(header.version) {
            return quiche::negotiate_version(&header.scid, &header.dcid, output)
                .map(Route::Reply);
        }

        let (scid, odcid) = if self.args.no_retry {
            (derived, None)
        } else {
            let Some(token) = header.token.as_deref() else {
                return Ok(Route::Drop);
            };
            if token.is_empty() {
                let token = self.retry.mint(peer.ip(), &derived, &header.dcid);
                return quiche::retry(
                    &header.scid,
                    &header.dcid,
                    &derived,
                    &token,
                    header.version,
                    output,
                )
                .map(Route::Reply);
            }
            let Some(original) =
                self.retry.validate(peer.ip(), &header.dcid, token)
            else {
                return Ok(Route::Drop);
            };
            (header.dcid.clone(), Some(original))
        };
        let mut conn =
            quiche::accept(&scid, odcid.as_ref(), local, peer, &mut self.config)?;
        self.attach_logs(&mut conn, &scid);
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(quiche::Error::InvalidState)?;
        self.clients.insert(id, Client::new(conn));
        self.ids.insert(scid, id);
        self.schedule.push_back(id);
        Ok(Route::Client(id))
    }

    fn attach_logs(&self, conn: &mut Connection, scid: &ConnectionId<'_>) {
        if let Some(log) = &self.keylog {
            match log.try_clone() {
                Ok(file) => conn.set_keylog(Box::new(file)),
                Err(error) => error!("clone key log: {error}"),
            }
        }
        #[cfg(feature = "qlog")]
        if let Some(directory) = std::env::var_os("QLOGDIR") {
            let id = format!("{scid:?}");
            match quiche_apps::common::make_qlog_writer(&directory, "server", &id)
            {
                Ok(writer) => conn.set_qlog(
                    Box::new(writer),
                    "quiche-server qlog".to_owned(),
                    format!("quiche-server qlog id={id}"),
                ),
                Err(error) => error!("open qlog: {error}"),
            }
        }
        #[cfg(not(feature = "qlog"))]
        let _ = scid;
    }

    fn receive(
        &mut self, id: ClientId, info: RecvInfo, len: usize, buffer: &mut [u8],
    ) {
        let Some(client) = self.clients.get_mut(&id) else {
            error!("CID references missing connection {id}");
            return;
        };
        if let Err(error) = client.conn.recv(&mut buffer[..len], info) {
            debug!("{} receive: {error}", client.conn.trace_id());
            return;
        }
        client.process_http(self.args, self.common, buffer);
        client.path_events();
        while let Some(retired) = client.conn.retired_scid_next() {
            self.ids.remove(&retired);
        }
        while client.conn.scids_left() > 0 {
            let (cid, reset) = match generate_cid_and_reset_token(&self.rng) {
                Ok(value) => value,
                Err(error) => {
                    error!("generate CID: {error}");
                    break;
                },
            };
            if self.ids.contains_key(&cid) ||
                client.conn.new_scid(&cid, reset, false).is_err()
            {
                break;
            }
            self.ids.insert(cid, id);
        }
    }

    fn timeout(&self) -> Option<Duration> {
        self.clients
            .values()
            .filter_map(|client| client.conn.timeout())
            .min()
    }

    fn expire(&mut self) {
        let now = Instant::now();
        for client in self.clients.values_mut() {
            if client
                .conn
                .timeout_instant()
                .is_some_and(|deadline| deadline <= now)
            {
                client.conn.on_timeout();
            }
        }
    }

    fn send_available(&mut self, io: &mut ServerIo) -> io::Result<bool> {
        let mut more = false;
        // Rotate after each visited connection, including one whose burst
        // blocks, so a single large stream cannot monopolize the socket.
        for _ in 0..self.schedule.len() {
            if io.tx.is_pending() {
                break;
            }
            let Some(id) = self.schedule.pop_front() else {
                break;
            };
            let Some(client) = self.clients.get_mut(&id) else {
                continue;
            };
            self.schedule.push_back(id);
            more |= client.generate(&mut io.output, &mut io.batches, io.pacing);
            if !io.batches.is_empty() && !io.submit()? {
                break;
            }
        }
        Ok(more)
    }

    fn collect_closed(&mut self) {
        let previous = self.clients.len();
        self.clients.retain(|_, client| {
            if client.conn.is_closed() {
                info!(
                    "{} collected {:?}",
                    client.conn.trace_id(),
                    client.conn.stats()
                );
                false
            } else {
                true
            }
        });
        if self.clients.len() != previous {
            self.ids.retain(|_, id| self.clients.contains_key(id));
            self.schedule.retain(|id| self.clients.contains_key(id));
        }
    }
}

struct Client {
    conn: Connection,
    http: Option<Box<dyn HttpConn>>,
    requests: HashMap<u64, PartialRequest>,
    responses: HashMap<u64, PartialResponse>,
    burst: BurstLimit,
}

impl Client {
    fn new(conn: Connection) -> Self {
        Self {
            conn,
            http: None,
            requests: HashMap::new(),
            responses: HashMap::new(),
            burst: BurstLimit::new(),
        }
    }

    fn process_http(
        &mut self, args: &ServerArgs, common: &CommonArgs, buffer: &mut [u8],
    ) {
        if self.http.is_none() &&
            (self.conn.is_established() || self.conn.is_in_early_data())
        {
            let protocol = self.conn.application_proto();
            let result: Result<Box<dyn HttpConn>, String> =
                if alpns::HTTP_09.contains(&protocol) {
                    Ok(Box::<Http09Conn>::default())
                } else if alpns::HTTP_3.contains(&protocol) {
                    Http3Conn::with_conn(
                        &mut self.conn,
                        common,
                        Rc::new(RefCell::new(stdout_sink)),
                    )
                } else {
                    Err(format!("unsupported ALPN {protocol:?}"))
                };
            match result {
                Ok(http) => self.http = Some(http),
                Err(error) => {
                    error!(
                        "{} application initialization: {error}",
                        self.conn.trace_id()
                    );
                    let _ = self.conn.close(
                        true,
                        0x102,
                        b"application initialization failed",
                    );
                    return;
                },
            }
        }
        if let Some(http) = &mut self.http {
            if let Err(error) = http.handle_requests(
                &mut self.conn,
                &mut self.requests,
                &mut self.responses,
                &args.root,
                &args.index,
                buffer,
            ) {
                debug!("{} HTTP processing: {error}", self.conn.trace_id());
                let _ = self.conn.close(true, 0x102, b"HTTP processing failed");
            }
        }
    }

    fn path_events(&mut self) {
        while let Some(event) = self.conn.path_event_next() {
            if let quiche::PathEvent::New(local, peer) = event {
                if let Err(error) = self.conn.probe_path(local, peer) {
                    debug!(
                        "{} probe {local} -> {peer}: {error}",
                        self.conn.trace_id()
                    );
                }
            } else {
                info!("{} path event {event:?}", self.conn.trace_id());
            }
        }
    }

    fn generate(
        &mut self, output: &mut [u8], batches: &mut Vec<DatagramBatch>,
        pacing: bool,
    ) -> bool {
        if self.conn.is_closed() {
            return false;
        }
        let stats = self.conn.stats();
        self.burst.observe(
            stats.lost,
            stats.sent,
            self.conn.max_send_udp_payload_size(),
        );
        let budget = self
            .conn
            .send_quantum()
            .min(self.burst.bytes)
            .max(MAX_DATAGRAM_SIZE)
            .min(output.len());
        let mut written = 0;
        // Reserve one maximum-sized packet before calling send. A short
        // remainder is not a transport failure and must not close a client.
        while budget - written >= MAX_DATAGRAM_SIZE {
            match self.conn.send(&mut output[written..budget]) {
                Ok((len, info)) if len > 0 => {
                    DatagramBatch::push(
                        batches,
                        written..written + len,
                        info,
                        pacing,
                    );
                    written += len;
                },
                Ok(_) | Err(quiche::Error::Done) => return false,
                Err(error) => {
                    debug!("{} generate UDP: {error}", self.conn.trace_id());
                    let _ = self.conn.close(false, 0x1, b"send failed");
                    return false;
                },
            }
        }
        written > 0
    }
}

struct BurstLimit {
    bytes: usize,
    previous_lost: usize,
    previous_sent: usize,
}

impl BurstLimit {
    const fn new() -> Self {
        Self {
            bytes: MAX_BUF_SIZE,
            previous_lost: 0,
            previous_sent: 1,
        }
    }

    fn observe(&mut self, lost: usize, sent: usize, mss: usize) {
        if sent == 0 {
            return;
        }
        // Compare exact rational loss rates. Avoid a lossy float conversion
        // and division by zero; usize products fit in u128 on supported hosts.
        let current = lost as u128 * self.previous_sent as u128;
        let previous = self.previous_lost as u128 * sent as u128;
        let denominator = sent as u128 * self.previous_sent as u128;
        if current.saturating_sub(previous) > denominator / 1000 {
            self.bytes = (self.bytes / 4 * 3).max(mss.saturating_mul(10));
            self.previous_lost = lost;
            self.previous_sent = sent;
        }
    }
}

struct RetryTokens {
    key: hmac::Key,
    start: Instant,
}

impl RetryTokens {
    fn new(rng: &SystemRandom) -> io::Result<Self> {
        let key = hmac::Key::generate(hmac::HMAC_SHA256, rng)
            .map_err(|error| failure("Retry token key", error))?;
        Ok(Self {
            key,
            start: Instant::now(),
        })
    }

    fn mint(
        &self, ip: IpAddr, retry_cid: &ConnectionId<'_>,
        original: &ConnectionId<'_>,
    ) -> Vec<u8> {
        self.mint_at(ip, retry_cid, original, self.start.elapsed().as_secs())
    }

    fn mint_at(
        &self, ip: IpAddr, retry_cid: &ConnectionId<'_>,
        original: &ConnectionId<'_>, now: u64,
    ) -> Vec<u8> {
        let mut token = now.to_be_bytes().to_vec();
        append_ip(&mut token, ip);
        token.extend_from_slice(retry_cid);
        token.extend_from_slice(original);
        let tag = hmac::sign(&self.key, &token);
        token.extend_from_slice(tag.as_ref());
        token
    }

    fn validate<'a>(
        &self, ip: IpAddr, retry_cid: &ConnectionId<'_>, token: &'a [u8],
    ) -> Option<ConnectionId<'a>> {
        self.validate_at(ip, retry_cid, token, self.start.elapsed().as_secs())
    }

    fn validate_at<'a>(
        &self, ip: IpAddr, retry_cid: &ConnectionId<'_>, token: &'a [u8],
        now: u64,
    ) -> Option<ConnectionId<'a>> {
        if retry_cid.len() != quiche::MAX_CONN_ID_LEN {
            return None;
        }
        let (payload, tag) =
            token.split_at_checked(token.len().checked_sub(
                hmac::HMAC_SHA256.digest_algorithm().output_len(),
            )?)?;
        hmac::verify(&self.key, payload, tag).ok()?;
        let (issued, rest) = payload.split_at_checked(8)?;
        let issued = u64::from_be_bytes(issued.try_into().ok()?);
        if now.checked_sub(issued)? > RETRY_TOKEN_LIFETIME {
            return None;
        }
        let mut binding = Vec::new();
        append_ip(&mut binding, ip);
        binding.extend_from_slice(retry_cid);
        let original = rest.strip_prefix(binding.as_slice())?;
        if original.len() > quiche::MAX_CONN_ID_LEN {
            return None;
        }
        Some(ConnectionId::from_ref(original))
    }
}

fn append_ip(buffer: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(address) => {
            buffer.push(4);
            buffer.extend_from_slice(&address.octets());
        },
        IpAddr::V6(address) => {
            buffer.push(6);
            buffer.extend_from_slice(&address.octets());
        },
    }
}

#[cfg(test)]
mod tests {
    use super::BurstLimit;
    use super::RetryTokens;
    use super::RETRY_TOKEN_LIFETIME;
    use quiche::ConnectionId;
    use ring::rand::SystemRandom;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;

    #[test]
    fn retry_tokens_bind_ip_connection_and_expiry() -> std::io::Result<()> {
        let rng = SystemRandom::new();
        let tokens = RetryTokens::new(&rng)?;
        let foreign = RetryTokens::new(&rng)?;
        let retry = ConnectionId::copy_from_slice(&[1; quiche::MAX_CONN_ID_LEN]);
        let other = ConnectionId::copy_from_slice(&[2; quiche::MAX_CONN_ID_LEN]);
        let original = ConnectionId::copy_from_slice(b"original");
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let token = tokens.mint_at(ip, &retry, &original, 10);
            assert_eq!(
                tokens.validate_at(ip, &retry, &token, 10),
                Some(original.clone())
            );
            assert_eq!(
                tokens.validate_at(ip, &retry, &token, 10 + RETRY_TOKEN_LIFETIME),
                Some(original.clone())
            );
            assert!(tokens.validate_at(ip, &retry, &token, 9).is_none());
            assert!(tokens
                .validate_at(ip, &retry, &token, 11 + RETRY_TOKEN_LIFETIME)
                .is_none());
            assert!(tokens.validate_at(ip, &other, &token, 10).is_none());
            assert!(foreign.validate_at(ip, &retry, &token, 10).is_none());
            assert!(tokens
                .validate_at(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    &retry,
                    &token,
                    10
                )
                .is_none());
            for len in 0..token.len() {
                assert!(tokens
                    .validate_at(ip, &retry, &token[..len], 10)
                    .is_none());
            }
            for index in 0..token.len() {
                let mut damaged = token.clone();
                damaged[index] ^= 1;
                assert!(tokens.validate_at(ip, &retry, &damaged, 10).is_none());
            }
        }
        Ok(())
    }

    #[test]
    fn burst_loss_threshold_is_exact_even_for_large_counters() {
        let mut limit = BurstLimit::new();
        let initial = limit.bytes;
        limit.observe(0, 0, 1350);
        limit.observe(1, 1000, 1350);
        assert_eq!(limit.bytes, initial);
        limit.observe(2, 1000, 1350);
        assert_eq!(limit.bytes, initial / 4 * 3);
        limit.observe(2, 1000, 1350);
        assert_eq!(limit.bytes, initial / 4 * 3);
        limit.observe(usize::MAX / 2, usize::MAX, 1350);
        assert_eq!(limit.bytes, initial / 4 * 3 / 4 * 3);
    }
}
/// Set `SO_TXTIME` socket option.
///
/// This socket option is set to send to kernel the outgoing UDP
/// packet transmission time in the `sendmsg` syscall.
///
/// Note that this socket option is set only on linux platforms.
#[cfg(target_os = "linux")]
fn set_txtime_sockopt(sock: &mio::net::UdpSocket) -> io::Result<()> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::TxTime;
    use std::os::unix::io::AsFd;

    let config = nix::libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };

    setsockopt(&sock.as_fd(), TxTime, &config)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_txtime_sockopt(_: &mio::net::UdpSocket) -> io::Result<()> {
    use std::io::Error;

    Err(Error::other("Not supported on this platform"))
}
