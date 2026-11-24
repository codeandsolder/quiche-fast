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

use crate::args::*;
use crate::common::*;
use crate::sendto::DatagramBatch;
use crate::sendto::DatagramQueue;

use std::io::prelude::*;

use std::rc::Rc;

use std::cell::RefCell;

use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    HttpFail,
    Other(String),
}

pub fn connect(
    args: ClientArgs, conn_args: CommonArgs,
    output_sink: impl FnMut(String) + 'static,
) -> Result<(), ClientError> {
    let mut buf = vec![0; 65_535];
    let mut out = vec![0; MAX_DATAGRAM_SIZE];
    let mut batches = Vec::new();
    let mut tx = DatagramQueue::new(MAX_DATAGRAM_SIZE, false);
    let mut migrate_tx = DatagramQueue::new(MAX_DATAGRAM_SIZE, false);

    let output_sink =
        Rc::new(RefCell::new(output_sink)) as Rc<RefCell<dyn FnMut(_)>>;

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // We'll only connect to the first server provided in URL list.
    let connect_url = args
        .urls
        .first()
        .ok_or_else(|| ClientError::Other("no request URL".into()))?;

    // Resolve server address.
    let peer_addr = if let Some(addr) = args.connect_to {
        addr
    } else {
        connect_url
            .socket_addrs(|| None)
            .map_err(|error| {
                ClientError::Other(format!("resolve {connect_url}: {error}"))
            })?
            .into_iter()
            .next()
            .ok_or_else(|| {
                ClientError::Other(format!("no addresses for {connect_url}"))
            })?
    };

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => format!("0.0.0.0:{}", args.source_port),
        std::net::SocketAddr::V6(_) => format!("[::]:{}", args.source_port),
    };

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let mut migrate_socket = if args.perform_migration {
        let mut socket =
            mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
        poll.registry()
            .register(&mut socket, mio::Token(1), mio::Interest::READABLE)
            .unwrap();

        Some(socket)
    } else {
        None
    };

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(args.version).unwrap();

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
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    let mut http_conn: Option<Box<dyn HttpConn>> = None;

    let mut app_proto_selected = false;

    let mut early_data_rejection_handled = false;

    // Generate a random source connection ID for the connection.
    let rng = SystemRandom::new();

    let scid = if !cfg!(feature = "fuzzing") {
        let mut conn_id = [0; quiche::MAX_CONN_ID_LEN];
        rng.fill(&mut conn_id[..]).unwrap();

        conn_id.to_vec()
    } else {
        // When fuzzing use an all zero connection ID.
        [0; quiche::MAX_CONN_ID_LEN].to_vec()
    };

    let scid = quiche::ConnectionId::from_ref(&scid);

    let local_addr = socket.local_addr().unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut conn = quiche::connect(
        connect_url.domain(),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )
    .unwrap();

    if let Some(keylog) = &mut keylog {
        if let Ok(keylog) = keylog.try_clone() {
            conn.set_keylog(Box::new(keylog));
        }
    }

    // Only bother with qlog if the user specified it.
    #[cfg(feature = "qlog")]
    {
        if let Some(dir) = std::env::var_os("QLOGDIR") {
            let id = format!("{scid:?}");
            let writer = make_qlog_writer(&dir, "client", &id);

            conn.set_qlog(
                std::boxed::Box::new(writer),
                "quiche-client qlog".to_string(),
                format!("{} id={}", "quiche-client qlog", id),
            );
        }
    }

    if let Some(session_file) = &args.session_file {
        if let Ok(session) = std::fs::read(session_file) {
            conn.set_session(&session).ok();
        }
    }

    info!(
        "connecting to {:} from {:} with scid {:?}",
        peer_addr,
        socket.local_addr().unwrap(),
        scid,
    );

    let (write, send_info) = conn
        .send(&mut out)
        .map_err(|error| ClientError::Other(format!("initial send: {error}")))?;
    DatagramBatch::push(&mut batches, 0..write, send_info, false);
    tx.submit(
        &mut out,
        &mut batches,
        &mut socket,
        poll.registry(),
        mio::Token(0),
    )
    .map_err(|error| ClientError::Other(format!("initial UDP send: {error}")))?;

    let app_data_start = std::time::Instant::now();

    let mut pkt_count = 0;

    let mut scid_sent = false;
    let mut new_path_probed = false;
    let mut migrated = false;

    loop {
        if tx.is_pending() ||
            migrate_tx.is_pending() ||
            !conn.is_in_early_data() ||
            app_proto_selected
        {
            poll.poll(&mut events, conn.timeout()).unwrap();
        }

        // If the event loop reported no events, it means that the timeout
        // has expired, so handle it without attempting to read packets. We
        // will then proceed with the send loop.
        if events.is_empty() {
            trace!("timed out");

            conn.on_timeout();
        }

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        for event in &events {
            if !event.is_readable() {
                continue;
            }
            let socket = match event.token() {
                mio::Token(0) => &socket,

                mio::Token(1) => migrate_socket.as_ref().unwrap(),

                _ => unreachable!(),
            };

            let local_addr = socket.local_addr().unwrap();
            'read: loop {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,

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

                if let Some(target_path) = conn_args.dump_packet_path.as_ref() {
                    let path = format!("{target_path}/{pkt_count}.pkt");

                    if let Ok(f) = std::fs::File::create(path) {
                        let mut f = std::io::BufWriter::new(f);
                        f.write_all(&buf[..len]).ok();
                    }
                }

                pkt_count += 1;

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
        }

        trace!("done reading");

        if conn.is_closed() {
            info!(
                "connection closed, {:?} {:?}",
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            if !conn.is_established() {
                error!(
                    "connection timed out after {:?}",
                    app_data_start.elapsed(),
                );

                return Err(ClientError::HandshakeFail);
            }

            if let Some(session_file) = &args.session_file {
                if let Some(session) = conn.session() {
                    std::fs::write(session_file, session).ok();
                }
            }

            if let Some(h_conn) = http_conn {
                if h_conn.report_incomplete(&app_data_start) {
                    return Err(ClientError::HttpFail);
                }
            }

            break;
        }

        if conn.early_data_rejected() && !early_data_rejection_handled {
            // The server never processed the early request streams. Recreate
            // the HTTP state and replay requests after the handshake.
            http_conn = None;
            app_proto_selected = false;
            early_data_rejection_handled = true;
        }

        // Create a new application protocol session once the QUIC connection is
        // established.
        if (conn.is_established() || conn.is_in_early_data()) &&
            (!args.perform_migration || migrated) &&
            !app_proto_selected
        {
            // At this stage the ALPN negotiation succeeded and selected a
            // single application protocol name. We'll use this to construct
            // the correct type of HttpConn but `application_proto()`
            // returns a slice, so we have to convert it to a str in order
            // to compare to our lists of protocols. We `unwrap()` because
            // we need the value and if something fails at this stage, there
            // is not much anyone can do to recover.

            let app_proto = conn.application_proto();

            if alpns::HTTP_09.contains(&app_proto) {
                http_conn = Some(Http09Conn::with_urls(
                    &args.urls,
                    args.reqs_cardinal,
                    Rc::clone(&output_sink),
                ));

                app_proto_selected = true;
            } else if alpns::HTTP_3.contains(&app_proto) {
                let dgram_sender = conn_args.datagrams.as_ref().map(|settings| {
                    Http3DgramSender::new(
                        settings.count,
                        settings.data.clone(),
                        0,
                    )
                });

                http_conn = Some(Http3Conn::with_urls(
                    &mut conn,
                    &args.urls,
                    args.reqs_cardinal,
                    &args.req_headers,
                    &args.body,
                    &args.method,
                    args.send_priority_update,
                    conn_args.max_field_section_size,
                    conn_args.qpack_max_table_capacity,
                    conn_args.qpack_blocked_streams,
                    args.dump_json,
                    dgram_sender,
                    Rc::clone(&output_sink),
                ));

                app_proto_selected = true;
            }
        }

        // If we have an HTTP connection, first issue the requests then
        // process received data.
        if let Some(h_conn) = http_conn.as_mut() {
            h_conn.send_requests(&mut conn, &args.dump_response_path);
            h_conn.handle_responses(&mut conn, &mut buf, &app_data_start);
        }

        // Handle path events.
        while let Some(qe) = conn.path_event_next() {
            match qe {
                quiche::PathEvent::New(..) => unreachable!(),

                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    info!("Path ({local_addr}, {peer_addr}) is now validated");
                    conn.migrate(local_addr, peer_addr).unwrap();
                    migrated = true;
                },

                quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                    info!("Path ({local_addr}, {peer_addr}) failed validation");
                },

                quiche::PathEvent::Closed(local_addr, peer_addr) => {
                    info!(
                        "Path ({local_addr}, {peer_addr}) is now closed and unusable"
                    );
                },

                quiche::PathEvent::ReusedSourceConnectionId(
                    cid_seq,
                    old,
                    new,
                ) => {
                    info!(
                        "Peer reused cid seq {cid_seq} (initially {old:?}) on {new:?}"
                    );
                },

                quiche::PathEvent::PeerMigrated(..) => unreachable!(),

                quiche::PathEvent::PmtuUpdated { local, peer, pmtu } => {
                    info!("Path ({local}, {peer}) validated PMTU {pmtu}")
                },

                _ => (),
            }
        }

        // See whether source Connection IDs have been retired.
        while let Some(retired_scid) = conn.retired_scid_next() {
            info!("Retiring source CID {retired_scid:?}");
        }

        // Provides as many CIDs as possible.
        while conn.scids_left() > 0 {
            let (scid, reset_token) = generate_cid_and_reset_token(&rng);

            if conn.new_scid(&scid, reset_token, false).is_err() {
                break;
            }

            scid_sent = true;
        }

        if args.perform_migration &&
            !new_path_probed &&
            scid_sent &&
            conn.available_dcids() > 0
        {
            let additional_local_addr =
                migrate_socket.as_ref().unwrap().local_addr().unwrap();
            conn.probe_path(additional_local_addr, peer_addr).unwrap();

            new_path_probed = true;
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        let mut sockets = vec![(&mut socket, &mut tx, mio::Token(0))];
        if let Some(migrate_socket) = migrate_socket.as_mut() {
            sockets.push((migrate_socket, &mut migrate_tx, mio::Token(1)));
        }

        for (socket, tx, token) in sockets {
            let local_addr = socket.local_addr().map_err(|error| {
                ClientError::Other(format!("local address: {error}"))
            })?;
            if !tx.flush(socket, poll.registry(), token).map_err(|error| {
                ClientError::Other(format!("UDP flush: {error}"))
            })? {
                continue;
            }

            'paths: for peer_addr in conn.paths_iter(local_addr) {
                loop {
                    let (write, send_info) = match conn.send_on_path(
                        &mut out,
                        Some(local_addr),
                        Some(peer_addr),
                    ) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            trace!("{local_addr} -> {peer_addr}: done writing");
                            break;
                        },

                        Err(e) => {
                            error!(
                                "{local_addr} -> {peer_addr}: send failed: {e:?}"
                            );

                            conn.close(false, 0x1, b"fail").ok();
                            break;
                        },
                    };

                    DatagramBatch::push(&mut batches, 0..write, send_info, false);
                    let drained = tx
                        .submit(
                            &mut out,
                            &mut batches,
                            socket,
                            poll.registry(),
                            token,
                        )
                        .map_err(|error| {
                            ClientError::Other(format!(
                                "UDP send {local_addr} -> {peer_addr}: {error}"
                            ))
                        })?;
                    if !drained {
                        break 'paths;
                    }

                    trace!(
                        "written {write} bytes from {local_addr} to {}",
                        send_info.to
                    );
                }
            }
        }

        if conn.is_closed() {
            info!(
                "connection closed, {:?} {:?}",
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            if !conn.is_established() {
                error!(
                    "connection timed out after {:?}",
                    app_data_start.elapsed(),
                );

                return Err(ClientError::HandshakeFail);
            }

            if let Some(session_file) = &args.session_file {
                if let Some(session) = conn.session() {
                    std::fs::write(session_file, session).ok();
                }
            }

            if let Some(h_conn) = http_conn {
                if h_conn.report_incomplete(&app_data_start) {
                    return Err(ClientError::HttpFail);
                }
            }

            break;
        }
    }

    Ok(())
}
