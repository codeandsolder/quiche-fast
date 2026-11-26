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

use crate::args::ClientArgs;
use crate::args::CommonArgs;
use crate::common::alpns;
use crate::common::generate_cid_and_reset_token;
#[cfg(feature = "qlog")]
use crate::common::make_qlog_writer;
use crate::common::Http09Conn;
use crate::common::Http3Conn;
use crate::common::HttpConn;
use crate::sendto::DatagramBatch;
use crate::sendto::DatagramQueue;

use std::rc::Rc;

use std::cell::RefCell;

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    HttpFail,
    Other(String),
}

fn failure(context: &str, error: impl std::fmt::Display) -> ClientError {
    ClientError::Other(format!("{context}: {error}"))
}

fn bind_socket(
    poll: &mio::Poll, addr: std::net::SocketAddr, token: mio::Token,
) -> Result<mio::net::UdpSocket, ClientError> {
    let mut socket = mio::net::UdpSocket::bind(addr)
        .map_err(|error| failure("bind UDP socket", error))?;
    poll.registry()
        .register(&mut socket, token, mio::Interest::READABLE)
        .map_err(|error| failure("register UDP socket", error))?;
    Ok(socket)
}

fn finish_connection(
    conn: &quiche::Connection, http_conn: Option<&dyn HttpConn>,
    args: &ClientArgs, start: &std::time::Instant,
) -> Result<(), ClientError> {
    info!(
        "connection closed, {:?} {:?}",
        conn.stats(),
        conn.path_stats().collect::<Vec<_>>()
    );
    if !conn.is_established() {
        error!("connection timed out after {:?}", start.elapsed());
        return Err(ClientError::HandshakeFail);
    }
    if let (Some(path), Some(session)) = (&args.session_file, conn.session()) {
        std::fs::write(path, session)
            .map_err(|error| failure("write session", error))?;
    }
    if http_conn.is_none_or(|http| http.report_incomplete(start)) {
        return Err(ClientError::HttpFail);
    }
    Ok(())
}

struct PathSocket {
    socket: mio::net::UdpSocket,
    tx: DatagramQueue,
    token: mio::Token,
}

impl PathSocket {
    fn bind(
        poll: &mio::Poll, addr: std::net::SocketAddr, token: mio::Token,
    ) -> Result<Self, ClientError> {
        Ok(Self {
            socket: bind_socket(poll, addr, token)?,
            tx: DatagramQueue::new(MAX_DATAGRAM_SIZE, false),
            token,
        })
    }

    fn address(&self) -> Result<std::net::SocketAddr, ClientError> {
        self.socket
            .local_addr()
            .map_err(|error| failure("local address", error))
    }

    fn send_available(
        &mut self, conn: &mut quiche::Connection, registry: &mio::Registry,
        output: &mut Vec<u8>, batches: &mut Vec<DatagramBatch>,
    ) -> Result<(), ClientError> {
        if !self
            .tx
            .flush(&mut self.socket, registry, self.token)
            .map_err(|error| failure("UDP flush", error))?
        {
            return Ok(());
        }
        let local = self.address()?;
        for peer in conn.paths_iter(local) {
            loop {
                let (written, info) =
                    match conn.send_on_path(output, Some(local), Some(peer)) {
                        Ok(value) => value,
                        Err(quiche::Error::Done) => break,
                        Err(error) =>
                            return Err(failure("generate UDP packet", error)),
                    };
                DatagramBatch::push(batches, 0..written, info, false);
                if !self
                    .tx
                    .submit(
                        output,
                        batches,
                        &mut self.socket,
                        registry,
                        self.token,
                    )
                    .map_err(|error| failure("send UDP packet", error))?
                {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

struct ClientIo {
    poll: mio::Poll,
    events: mio::Events,
    primary: PathSocket,
    migration: Option<PathSocket>,
    input: Vec<u8>,
    output: Vec<u8>,
    batches: Vec<DatagramBatch>,
    packet_count: u64,
}

impl ClientIo {
    fn new(
        peer: std::net::SocketAddr, args: &ClientArgs,
    ) -> Result<Self, ClientError> {
        let poll =
            mio::Poll::new().map_err(|error| failure("create poll", error))?;
        let ip = if peer.is_ipv4() {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        };
        let primary = PathSocket::bind(
            &poll,
            std::net::SocketAddr::new(ip, args.source_port),
            mio::Token(0),
        )?;
        let migration = if args.perform_migration {
            Some(PathSocket::bind(
                &poll,
                std::net::SocketAddr::new(ip, 0),
                mio::Token(1),
            )?)
        } else {
            None
        };
        Ok(Self {
            poll,
            events: mio::Events::with_capacity(1024),
            primary,
            migration,
            input: vec![0; 65_535],
            output: vec![0; MAX_DATAGRAM_SIZE],
            batches: Vec::new(),
            packet_count: 0,
        })
    }

    fn send_initial(
        &mut self, conn: &mut quiche::Connection,
    ) -> Result<(), ClientError> {
        let (written, info) = conn
            .send(&mut self.output)
            .map_err(|error| failure("initial send", error))?;
        DatagramBatch::push(&mut self.batches, 0..written, info, false);
        self.primary
            .tx
            .submit(
                &mut self.output,
                &mut self.batches,
                &mut self.primary.socket,
                self.poll.registry(),
                self.primary.token,
            )
            .map_err(|error| failure("initial UDP send", error))?;
        Ok(())
    }

    fn poll_receive(
        &mut self, conn: &mut quiche::Connection, dump_path: Option<&str>,
        ready_for_early_data: bool,
    ) -> Result<(), ClientError> {
        let pending = self.primary.tx.is_pending() ||
            self.migration
                .as_ref()
                .is_some_and(|path| path.tx.is_pending());
        if ready_for_early_data && !pending {
            // Issue early requests before blocking. There has been no poll,
            // so do not reuse a previous readiness set or fire a timer.
            return Ok(());
        }
        loop {
            match self.poll.poll(&mut self.events, conn.timeout()) {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted =>
                    (),
                Err(error) => return Err(failure("poll", error)),
            }
        }
        if self.events.is_empty() {
            conn.on_timeout();
        }
        for event in &self.events {
            if !event.is_readable() {
                continue;
            }
            let socket = match event.token() {
                mio::Token(0) => &self.primary.socket,
                mio::Token(1) => {
                    let Some(path) = &self.migration else {
                        continue;
                    };
                    &path.socket
                },
                _ => continue,
            };
            receive_packets(
                conn,
                socket,
                &mut self.input,
                dump_path,
                &mut self.packet_count,
            )?;
        }
        Ok(())
    }

    fn send_available(
        &mut self, conn: &mut quiche::Connection,
    ) -> Result<(), ClientError> {
        self.primary.send_available(
            conn,
            self.poll.registry(),
            &mut self.output,
            &mut self.batches,
        )?;
        if let Some(path) = &mut self.migration {
            path.send_available(
                conn,
                self.poll.registry(),
                &mut self.output,
                &mut self.batches,
            )?;
        }
        Ok(())
    }
}

enum MigrationState {
    Disabled,
    AwaitingCid { advertised: bool },
    Probing(std::net::SocketAddr),
    Migrated,
}

impl MigrationState {
    const fn ready(&self) -> bool {
        matches!(self, Self::Disabled | Self::Migrated)
    }

    fn update(
        &mut self, conn: &mut quiche::Connection, io: &ClientIo,
        peer: std::net::SocketAddr,
    ) -> Result<(), ClientError> {
        while let Some(event) = conn.path_event_next() {
            match event {
                quiche::PathEvent::Validated(local, remote) => {
                    info!("Path ({local}, {remote}) is now validated");
                    if matches!(self, Self::Probing(expected) if *expected == local)
                    {
                        conn.migrate(local, remote)
                            .map_err(|error| failure("migrate path", error))?;
                        *self = Self::Migrated;
                    }
                },
                quiche::PathEvent::FailedValidation(local, remote) => {
                    info!("Path ({local}, {remote}) failed validation");
                    if matches!(self, Self::Probing(expected) if *expected == local)
                    {
                        return Err(ClientError::Other(
                            "migration path validation failed".into(),
                        ));
                    }
                },
                other => debug!("Path event: {other:?}"),
            }
        }
        while let Some(retired) = conn.retired_scid_next() {
            info!("Retiring source CID {retired:?}");
        }
        while conn.scids_left() > 0 {
            let (scid, reset) = generate_cid_and_reset_token()
                .map_err(|error| failure("generate CID", error))?;
            if conn.new_scid(&scid, reset, false).is_err() {
                break;
            }
            if let Self::AwaitingCid { advertised } = self {
                *advertised = true;
            }
        }
        if matches!(self, Self::AwaitingCid { advertised: true }) &&
            conn.available_dcids() > 0
        {
            let local = io
                .migration
                .as_ref()
                .ok_or_else(|| {
                    ClientError::Other("missing migration socket".into())
                })?
                .address()?;
            conn.probe_path(local, peer)
                .map_err(|error| failure("probe path", error))?;
            *self = Self::Probing(local);
        }
        Ok(())
    }
}

fn open_connection(
    args: &ClientArgs, conn_args: &CommonArgs, connect_url: &url::Url,
    local_addr: std::net::SocketAddr, peer_addr: std::net::SocketAddr,
) -> Result<quiche::Connection, ClientError> {
    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(args.version)
        .map_err(|error| failure("QUIC configuration", error))?;

    if let Some(ref trust_origin_ca_pem) = args.trust_origin_ca_pem {
        config
            .load_verify_locations_from_file(trust_origin_ca_pem)
            .map_err(|e| {
                ClientError::Other(format!("error loading origin CA file : {e}"))
            })?;
    }

    config.verify_peer(!args.no_verify);

    conn_args
        .configure(&mut config, MAX_DATAGRAM_SIZE)
        .map_err(|error| {
            ClientError::Other(format!("connection configuration: {error}"))
        })?;

    let mut keylog = None;

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .map_err(|error| failure("open key log", error))?;

        keylog = Some(file);

        config.log_keys();
    }

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    if !cfg!(feature = "fuzzing") {
        btls::rand::rand_bytes(&mut scid)
            .map_err(|error| failure("generate source CID", error))?;
    }

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Create a QUIC connection and initiate handshake.
    let mut conn = quiche::connect(
        connect_url.domain(),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )
    .map_err(|error| failure("connect QUIC", error))?;

    if let Some(keylog) = keylog {
        conn.set_keylog(Box::new(keylog));
    }

    // Only bother with qlog if the user specified it.
    #[cfg(feature = "qlog")]
    {
        if let Some(dir) = std::env::var_os("QLOGDIR") {
            let id = format!("{scid:?}");
            let writer =
                make_qlog_writer(&dir, "client", &id).map_err(|error| {
                    ClientError::Other(format!("open qlog: {error}"))
                })?;

            conn.set_qlog(
                std::boxed::Box::new(writer),
                "quiche-client qlog".to_string(),
                format!("quiche-client qlog id={id}"),
            );
        }
    }

    if let Some(session_file) = &args.session_file {
        match std::fs::read(session_file) {
            Ok(session) => conn
                .set_session(&session)
                .map_err(|error| failure("restore session", error))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(failure("read session", error)),
        }
    }

    info!("connecting to {peer_addr} from {local_addr} with scid {scid:?}");

    Ok(conn)
}

/// Run a QUIC client until all requested responses complete.
///
/// # Errors
/// Returns handshake, HTTP, configuration or socket errors.
pub fn connect(
    args: &ClientArgs, conn_args: &CommonArgs,
    output_sink: impl FnMut(&str) + 'static,
) -> Result<(), ClientError> {
    let connect_url = args
        .urls
        .first()
        .ok_or_else(|| ClientError::Other("no request URL".into()))?;
    let peer = if let Some(address) = args.connect_to {
        address
    } else {
        connect_url
            .socket_addrs(|| None)
            .map_err(|error| failure("resolve request URL", error))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                ClientError::Other("no addresses for request URL".into())
            })?
    };
    let mut io = ClientIo::new(peer, args)?;
    let mut conn = open_connection(
        args,
        conn_args,
        connect_url,
        io.primary.address()?,
        peer,
    )?;
    io.send_initial(&mut conn)?;

    let output_sink =
        Rc::new(RefCell::new(output_sink)) as Rc<RefCell<dyn FnMut(&str)>>;
    let start = std::time::Instant::now();
    let mut http: Option<Box<dyn HttpConn>> = None;
    let mut early_data_rejection_handled = false;
    let mut migration = if args.perform_migration {
        MigrationState::AwaitingCid { advertised: false }
    } else {
        MigrationState::Disabled
    };

    loop {
        let ready_for_early_data =
            conn.is_in_early_data() && http.is_none() && migration.ready();
        io.poll_receive(
            &mut conn,
            conn_args.dump_packet_path.as_deref(),
            ready_for_early_data,
        )?;
        if conn.is_closed() {
            return finish_connection(&conn, http.as_deref(), args, &start);
        }

        if conn.early_data_rejected() && !early_data_rejection_handled {
            http = None;
            early_data_rejection_handled = true;
        }
        if (conn.is_established() || conn.is_in_early_data()) &&
            migration.ready() &&
            http.is_none()
        {
            let protocol = conn.application_proto();
            http = if alpns::HTTP_09.contains(&protocol) {
                Some(Http09Conn::with_urls(
                    &args.urls,
                    args.reqs_cardinal,
                    Rc::clone(&output_sink),
                ))
            } else if alpns::HTTP_3.contains(&protocol) {
                Some(
                    Http3Conn::with_urls(
                        &mut conn,
                        args,
                        conn_args,
                        Rc::clone(&output_sink),
                    )
                    .map_err(ClientError::Other)?,
                )
            } else {
                return Err(ClientError::Other(format!(
                    "unsupported ALPN: {protocol:?}"
                )));
            };
        }

        if let Some(session) = &mut http {
            session
                .send_requests(&mut conn, args.dump_response_path.as_deref())
                .map_err(ClientError::Other)?;
            session
                .handle_responses(&mut conn, &mut io.input, &start)
                .map_err(ClientError::Other)?;
        }
        migration.update(&mut conn, &io, peer)?;
        io.send_available(&mut conn)?;
        if conn.is_closed() {
            return finish_connection(&conn, http.as_deref(), args, &start);
        }
    }
}

fn receive_packets(
    conn: &mut quiche::Connection, socket: &mio::net::UdpSocket, buf: &mut [u8],
    dump_path: Option<&str>, pkt_count: &mut u64,
) -> Result<(), ClientError> {
    let local_addr = socket
        .local_addr()
        .map_err(|error| failure("local address", error))?;
    'read: loop {
        let (len, from) = match socket.recv_from(buf) {
            Ok(v) => v,

            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                // There are no more UDP packets to read on this socket.
                // Process subsequent events.
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    trace!("{local_addr}: recv() would block");
                    break 'read;
                }

                return Err(ClientError::Other(format!(
                    "{local_addr}: recv() failed: {e:?}"
                )));
            },
        };

        trace!("got {len} bytes from {from} to {local_addr}");

        if let Some(target_path) = dump_path {
            let path = format!("{target_path}/{pkt_count}.pkt");

            std::fs::write(path, &buf[..len])
                .map_err(|error| failure("dump received packet", error))?;
        }

        *pkt_count += 1;

        let recv_info = quiche::RecvInfo {
            to: local_addr,
            from,
        };

        // Process potentially coalesced packets.
        let read = match conn.recv(&mut buf[..len], recv_info) {
            Ok(v) => v,

            Err(e) => {
                error!("{local_addr}: recv failed: {e:?}");
                continue 'read;
            },
        };

        trace!("{local_addr}: processed {read} bytes");
    }
    Ok(())
}
