// Copyright (C) 2024, Cloudflare, Inc.
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

//! Responsible for creating a [`quiche::Connection`] and managing I/O.

use std::time::Instant;

use crate::actions::h3::Action;
use crate::config::Config;
use crate::quiche;

use super::action_queue::ActionQueue;
use super::parse_args;
use super::parse_streams;
use super::sync_io::SyncIo;
use super::sync_io::TxStatus;
use super::ClientError;
use super::ClientState;
use super::CloseTriggerFrames;
use super::ConnectionSummary;
use super::ParsedArgs;
use super::MAX_DATAGRAM_SIZE;
use super::QUIC_VERSION;

fn create_config(
    args: &Config, should_log_keys: bool,
) -> std::result::Result<quiche::Config, ClientError> {
    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(QUIC_VERSION)
        .map_err(|error| ClientError::Other(error.to_string()))?;

    config.verify_peer(args.tls.verify_peer);
    config
        .set_application_protos(&[b"h3"])
        .map_err(|error| ClientError::Other(error.to_string()))?;
    config.set_max_idle_timeout(args.idle_timeout);
    config.set_send_capacity_factor(args.send_capacity_factor);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(args.flow.data);
    config
        .set_initial_max_stream_data_bidi_local(args.flow.stream_data_bidi_local);
    config.set_initial_max_stream_data_bidi_remote(
        args.flow.stream_data_bidi_remote,
    );
    config.set_initial_max_stream_data_uni(args.flow.stream_data_uni);
    config.set_initial_max_streams_bidi(args.flow.streams_bidi);
    config.set_initial_max_streams_uni(args.flow.streams_uni);
    config.set_disable_active_migration(true);
    config.set_active_connection_id_limit(0);

    config.set_max_connection_window(args.flow.window);
    config.set_max_stream_window(args.flow.stream_window);
    config.set_enable_send_streams_blocked(true);
    config.grease(false);

    if args.tls.early_data {
        config.enable_early_data();
    }

    if let Some(queues) = &args.datagrams {
        config.enable_dgram(true, queues.receive, queues.send);
    }
    if should_log_keys {
        config.log_keys();
    }

    Ok(config)
}

/// Connect to a server and execute the provided actions.
///
/// If close triggers are supplied, close as soon as every trigger is observed.
///
/// # Errors
/// Returns a client error if connection setup, the handshake, I/O, or an
/// action fails.
pub fn connect(
    args: Config, actions: Vec<Action>,
    close_trigger_frames: Option<CloseTriggerFrames>,
) -> Result<ConnectionSummary, ClientError> {
    connect_with_early_data(args, None, actions, close_trigger_frames)
}

/// Connect and execute the early-action queue when 0-RTT is available,
/// followed by the regular action queue after the handshake.
///
/// # Errors
/// Returns a client error if connection setup, the handshake, I/O, or an
/// action fails.
pub fn connect_with_early_data(
    args: Config, early_actions: Option<Vec<Action>>, actions: Vec<Action>,
    close_trigger_frames: Option<CloseTriggerFrames>,
) -> Result<ConnectionSummary, ClientError> {
    let (mut conn, mut io) = create_connection(args)?;
    io.stage_initial(&mut conn)?;
    let mut early = if conn.is_in_early_data() {
        early_actions.map(ActionQueue::new)
    } else {
        None
    };
    let mut normal = ActionQueue::new(actions);
    let mut client = ClientState::new(close_trigger_frames);
    // Queue early data before the ClientHello reaches the peer. Once the
    // socket accepts the first datagram, flush can generate the 0-RTT packets
    // immediately, without processing a handshake response first.
    if let Some(queue) = early.as_mut() {
        queue
            .advance(Instant::now, &mut conn, &mut client.parsers)
            .map_err(ClientError::Other)?;
    }
    let mut tx_status = io.flush(&mut conn)?;

    while !conn.is_closed() {
        let now = Instant::now();
        if conn
            .timeout_instant()
            .is_some_and(|deadline| deadline <= now)
        {
            conn.on_timeout();
            if conn.is_closed() {
                break;
            }
        }
        if let Some(queue) = active_queue(&mut early, &mut normal, &conn) {
            process_application(queue, &mut client, &mut conn, tx_status)?;
        }
        provide_connection_ids(&mut conn)?;
        tx_status = io.flush(&mut conn)?;
        if conn.is_closed() {
            break;
        }
        if let Some(previous) = early.take_if(|queue| queue.is_finished()) {
            normal.inherit_finished_streams(previous);
        }
        let now = Instant::now();
        let action_deadline = if tx_status == TxStatus::Idle {
            active_queue(&mut early, &mut normal, &conn)
                .and_then(|queue| queue.wakeup(now))
        } else {
            None
        };
        let deadline = [
            conn.timeout_instant(),
            tx_status.deadline(now),
            action_deadline,
        ]
        .into_iter()
        .flatten()
        .min();
        io.wait(&mut conn, deadline)?;
    }
    if !conn.is_established() {
        return Err(ClientError::HandshakeFail);
    }
    Ok(ConnectionSummary::from_connection(&conn, client.streams))
}

fn active_queue<'a>(
    early: &'a mut Option<ActionQueue>, normal: &'a mut ActionQueue,
    conn: &quiche::Connection,
) -> Option<&'a mut ActionQueue> {
    if conn.is_draining() || conn.is_closed() || conn.local_error().is_some() {
        return None;
    }
    if conn.is_established() || conn.is_in_early_data() {
        if let Some(early) = early.as_mut() {
            return Some(early);
        }
        if conn.is_established() {
            return Some(normal);
        }
    }
    None
}

fn process_application(
    queue: &mut ActionQueue, client: &mut ClientState,
    conn: &mut quiche::Connection, tx_status: TxStatus,
) -> Result<(), ClientError> {
    queue
        .before_reads(Instant::now(), conn)
        .map_err(ClientError::Other)?;
    for event in parse_streams(conn, client) {
        queue.on_stream_event(event);
    }
    if client.streams.all_close_trigger_frames_seen() {
        client.streams.close_due_to_trigger_frames(conn);
    } else if tx_status == TxStatus::Idle && !conn.is_draining() {
        queue
            .advance(Instant::now, conn, &mut client.parsers)
            .map_err(ClientError::Other)?;
    }
    Ok(())
}

fn create_connection(
    args: Config,
) -> Result<(quiche::Connection, SyncIo), ClientError> {
    let ParsedArgs {
        connect_url,
        bind_addr,
        peer_addr,
    } = parse_args(&args)?;
    let io = SyncIo::bind(bind_addr)?;
    let keylog = std::env::var_os("SSLKEYLOGFILE")
        .map(|path| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|error| {
                    ClientError::Other(format!("open key log: {error}"))
                })
        })
        .transpose()?;
    let mut config = create_config(&args, keylog.is_some())?;
    let mut scid_bytes = [0; quiche::MAX_CONN_ID_LEN];
    btls::rand::rand_bytes(&mut scid_bytes)
        .map_err(|error| ClientError::Other(error.to_string()))?;
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let local_addr = io.local_addr();
    let mut conn =
        quiche::connect(connect_url, &scid, local_addr, peer_addr, &mut config)
            .map_err(|error| ClientError::Other(error.to_string()))?;
    if let Some(session) = args.session {
        conn.set_session(&session)
            .map_err(|error| ClientError::Other(error.to_string()))?;
    }
    if let Some(keylog) = keylog {
        conn.set_keylog(Box::new(keylog));
    }
    log::info!("connecting to {peer_addr} from {local_addr} with scid {scid:?}");
    Ok((conn, io))
}

fn provide_connection_ids(
    conn: &mut quiche::Connection,
) -> Result<(), ClientError> {
    while conn.scids_left() > 0 {
        let (scid, reset_token) = generate_cid_and_reset_token()?;
        if conn.new_scid(&scid, reset_token, false).is_err() {
            break;
        }
    }
    Ok(())
}

/// Generate a source connection ID and stateless reset token.
///
/// # Errors
/// Returns an error if the operating system random source fails.
pub fn generate_cid_and_reset_token(
) -> Result<(quiche::ConnectionId<'static>, u128), ClientError> {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    btls::rand::rand_bytes(&mut scid)
        .map_err(|error| ClientError::Other(error.to_string()))?;
    let mut reset_token = [0; 16];
    btls::rand::rand_bytes(&mut reset_token)
        .map_err(|error| ClientError::Other(error.to_string()))?;
    Ok((scid.to_vec().into(), u128::from_be_bytes(reset_token)))
}
