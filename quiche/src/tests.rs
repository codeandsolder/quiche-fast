// Copyright (C) 2025, Cloudflare, Inc.
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

use super::*;
use crate::stream::StreamDirection;
use crate::stream::StreamDirection::Bidirectional;
use crate::stream::StreamDirection::Unidirectional;

use crate::range_buf::RangeBuf;
use crate::test_utils::stream_recv_discard;
use crate::Header;

use rstest::rstest;

// Preserve original setup and protocol errors at the test boundary.
type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn transport_config(cc_algorithm_name: &str) -> Result<Config> {
    let mut config = test_utils::config_with_test_identity()?;
    config.set_cc_algorithm_name(cc_algorithm_name)?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    Ok(config)
}

/// The long-header length slot is chosen before frames are encoded and
/// patched after the payload is finalized. Near a varint width transition,
/// the spare bytes must not leak into the protected packet.
#[test]
fn tx_header_length_patch_matches_protected_wire_size() -> TestResult {
    let mut config = test_utils::Pipe::default_config("cubic")?;
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    let conn = &mut pipe.client;
    let path_id = conn.paths.get_active_path_id()?;
    conn.paths.get_mut(path_id)?.pmtud = None;
    let epoch = packet::Epoch::Initial;
    let pn_len = 2;

    let mut scratch = [0; 256];
    let mut writer = packet::PacketWriter::from_initialized(&mut scratch);
    let initial_header = conn.prepare_tx_header(
        &mut writer,
        path_id,
        Type::Initial,
        epoch,
        0,
        pn_len,
    )?;
    let (prefix, _) = initial_header
        .length_field
        .ok_or("long header length field missing")?;
    let tag_len = initial_header.crypto_overhead;

    // One byte short of the minimum protected payload must not succeed.
    let mut small = vec![0; prefix + 2 + pn_len + tag_len + PAYLOAD_MIN_LEN - 1];
    let mut writer = packet::PacketWriter::from_initialized(&mut small);
    assert!(matches!(
        conn.prepare_tx_header(
            &mut writer,
            path_id,
            Type::Initial,
            epoch,
            0,
            pn_len
        ),
        Err(Error::Done)
    ));

    // The two-byte length can encode 16383. A four-byte slot only becomes
    // usable when there is room for both the wider slot and 16384 bytes.
    for (index, (available, width, encoded_len)) in [
        (2 + 16383, 2, 16383),
        (2 + 16384, 2, 16383),
        (4 + 16384, 4, 16384),
    ]
    .into_iter()
    .enumerate()
    {
        let mut out = vec![0; prefix + available];
        let mut writer = packet::PacketWriter::from_initialized(&mut out);
        let header = conn.prepare_tx_header(
            &mut writer,
            path_id,
            Type::Initial,
            epoch,
            index as u64,
            pn_len,
        )?;
        assert_eq!(header.length_field, Some((prefix, width)));
        assert_eq!(header.payload_offset, prefix + width + pn_len);
        assert_eq!(header.payload_capacity, encoded_len - pn_len - tag_len);
        let frames = [frame::Frame::Padding {
            len: header.payload_capacity,
        }];
        frames[0].encode(&mut writer)?;
        let written = conn.seal_tx_packet(
            &mut writer,
            header,
            &frames,
            path_id,
            Instant::now(),
        )?;
        assert_eq!(written, prefix + width + encoded_len);
        assert_eq!(writer.off(), written);
        let mut length = octets::Octets::with_slice(
            &writer.written_mut()[prefix..prefix + width],
        );
        assert_eq!(length.get_varint(), Ok(encoded_len as u64));
        assert_eq!(length.cap(), 0);
    }
    Ok(())
}

/// A preferred datagram must remain queued when only stream data fits.
/// Insufficient stream space is not application-limited.
#[test]
fn packet_data_falls_back_to_stream_without_consuming_datagram() -> TestResult {
    let mut config = test_utils::Pipe::default_config("cubic")?;
    config.enable_dgram(true, 10, 10);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));
    let conn = &mut pipe.client;
    let path_id = conn.paths.get_active_path_id()?;
    let max_dgram_len = conn.dgram_max_writable_len();
    let datagram = b"abcde";
    assert_eq!(conn.dgram_send(datagram), Ok(()));
    assert_eq!(conn.stream_send(0, b"s", true), Ok(1));
    conn.payload_preference = PayloadPreference::Datagram;

    // STREAM uses type, stream ID, offset, two-byte length, one payload byte.
    // DATAGRAM uses type, two-byte length, five payload bytes.
    for capacity in [5, 6, 8] {
        let mut storage = [0; 8];
        let mut writer =
            packet::PacketWriter::from_initialized(&mut storage[..capacity]);
        let mut frames = SmallVec::new();
        let mut left = capacity;
        let emission = conn.emit_packet_data(
            &mut writer,
            &mut frames,
            &mut left,
            path_id,
            Type::Short,
            max_dgram_len,
        )?;
        assert_eq!(emission.retransmitted_bytes(), 0);
        assert!(!emission.stream.retransmitted_fin);
        assert_eq!(writer.off() + left, capacity);

        match capacity {
            5 => {
                assert!(emission.stream.skipped);
                assert!(!emission.has_data());
                assert!(frames.is_empty());
                assert_eq!(left, 5);
                assert_eq!(conn.streams.tx_buffered(), 1);
            },
            6 => {
                assert!(emission.has_data());
                assert!(!emission.stream.skipped);
                assert!(!emission.datagram_emitted);
                assert_eq!(frames.as_slice(), &[frame::Frame::StreamHeader {
                    stream_id: 0,
                    offset: 0,
                    length: 1,
                    fin: true,
                }]);
                assert_eq!(
                    frame::Frame::from_bytes(
                        &mut octets::Octets::with_slice(writer.written_mut()),
                        Type::Short
                    ),
                    Ok(frame::Frame::Stream {
                        stream_id: 0,
                        data: <RangeBuf>::from(b"s", 0, true),
                    })
                );
                assert_eq!(conn.streams.tx_buffered(), 0);
            },
            8 => {
                assert!(emission.datagram_emitted);
                assert!(!emission.has_data());
                assert_eq!(frames.as_slice(), &[frame::Frame::DatagramHeader {
                    length: datagram.len()
                }]);
                assert_eq!(
                    frame::Frame::from_bytes(
                        &mut octets::Octets::with_slice(writer.written_mut()),
                        Type::Short
                    ),
                    Ok(frame::Frame::Datagram {
                        data: datagram.to_vec(),
                    })
                );
            },
            _ => unreachable!(),
        }
        assert_eq!(conn.dgram_send_queue.is_empty(), capacity == 8);
        assert_eq!(
            conn.payload_preference == PayloadPreference::Datagram,
            capacity != 8
        );
    }
    Ok(())
}

/// Pending control frames survive a full packet and are committed only when
/// they fit, in the same order as the packet scheduler.
#[test]
fn stream_count_control_frames_preserve_order_across_packet_boundaries(
) -> TestResult {
    let mut config = test_utils::Pipe::default_config("cubic")?;
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));
    let conn = &mut pipe.client;
    conn.streams.quota_mut(Bidirectional).credit_retransmit = true;
    conn.streams.quota_mut(Unidirectional).credit_retransmit = true;
    conn.blocked_limit = Some(17);
    conn.streams.quota_mut(Bidirectional).update_peer_limit(3);
    conn.streams.quota_mut(Bidirectional).note_blocked();
    conn.streams.quota_mut(Unidirectional).update_peer_limit(4);
    conn.streams.quota_mut(Unidirectional).note_blocked();

    let expected = [
        frame::Frame::MaxStreams {
            direction: Bidirectional,
            max: conn.streams.quota(Bidirectional).next_local_limit(),
        },
        frame::Frame::MaxStreams {
            direction: Unidirectional,
            max: conn.streams.quota(Unidirectional).next_local_limit(),
        },
        frame::Frame::DataBlocked { limit: 17 },
        frame::Frame::StreamsBlocked {
            direction: Bidirectional,
            limit: 3,
        },
        frame::Frame::StreamsBlocked {
            direction: Unidirectional,
            limit: 4,
        },
    ];
    let previous_blocked_count = conn.counters.data_blocked_sent_count;
    for expected_frame in expected {
        // First try without enough room for any of the pending frames.
        for capacity in [0, 1, expected_frame.wire_len()?] {
            let mut storage = [0; 16];
            let mut writer =
                packet::PacketWriter::from_initialized(&mut storage[..capacity]);
            let mut frames = SmallVec::new();
            let mut left = capacity;
            conn.emit_stream_count_control_frames(
                &mut writer,
                &mut frames,
                &mut left,
            )?;
            if capacity < expected_frame.wire_len()? {
                assert!(frames.is_empty());
                assert_eq!(left, capacity);
                assert_eq!(writer.off(), 0);
            } else {
                assert_eq!(
                    frames.as_slice(),
                    std::slice::from_ref(&expected_frame)
                );
                assert_eq!(left, 0);
                assert_eq!(writer.off(), capacity);
            }
        }
    }
    assert!(!conn.streams.quota(Bidirectional).credit_retransmit);
    assert!(!conn.streams.quota(Unidirectional).credit_retransmit);
    assert_eq!(conn.blocked_limit, None);
    assert_eq!(
        conn.counters.data_blocked_sent_count,
        previous_blocked_count + 1
    );
    assert!(conn
        .streams
        .quota(Bidirectional)
        .pending_blocked_limit()
        .is_none());
    assert!(conn
        .streams
        .quota(Unidirectional)
        .pending_blocked_limit()
        .is_none());
    Ok(())
}

/// A `PATH_CHALLENGE` must remain queued if its nine-byte response does not
/// fit in the current packet. Packet construction can then retry later, and
/// consecutive challenges must keep their original order.
#[test]
fn queued_path_responses_are_consumed_only_when_encoded() -> TestResult {
    let config = Config::new(PROTOCOL_VERSION)?;
    let recovery = config.recovery;
    let local = "127.0.0.1:1234".parse()?;
    let peer = "127.0.0.1:4321".parse()?;
    let first = [0x11; 8];
    let second = [0x22; 8];

    // Each response takes exactly one type byte and eight challenge bytes.
    for available in [0, 1, 8, 9, 10, 17, 18] {
        let mut path = path::Path::new(local, peer, &recovery, 4, true, None);
        path.on_challenge_received(first);
        path.on_challenge_received(second);

        let mut storage = [0xAA; 18];
        let mut writer = octets::OctetsMut::with_slice(&mut storage[..available]);
        let mut left = available;
        let mut frames = SmallVec::<[frame::Frame; 1]>::new();
        let emitted = push_received_path_responses(
            &mut path,
            &mut writer,
            &mut frames,
            &mut left,
        )?;
        let count = available / 9;
        assert_eq!(emitted, count != 0, "space={available}");
        assert_eq!(frames.len(), count, "space={available}");
        assert_eq!(writer.off(), count * 9, "space={available}");
        assert_eq!(left, available - count * 9, "space={available}");
        assert_eq!(path.probing_required(), count < 2, "space={available}");
        for (idx, frame) in frames.into_iter().enumerate() {
            let expected = if idx == 0 { first } else { second };
            assert_eq!(frame, frame::Frame::PathResponse { data: expected });
            assert_eq!(storage[idx * 9], 0x1b);
            assert_eq!(&storage[idx * 9 + 1..(idx + 1) * 9], &expected);
        }
        for expected in [first, second].into_iter().skip(count) {
            assert_eq!(
                path.pop_received_challenge(),
                Some(expected),
                "space={available}"
            );
        }
        assert_eq!(path.pop_received_challenge(), None);
    }
    Ok(())
}

#[test]
fn stateless_reset_recognizes_rotated_peer_cid_tokens() -> TestResult {
    let mut pipe = test_utils::Pipe::new("cubic")?;
    let client = &mut pipe.client;
    let initial_token = u128::from_be_bytes([0x61; 16]);
    let rotated_token = u128::from_be_bytes([0x72; 16]);
    // The initial peer CID often precedes receipt of TLS transport
    // parameters, so its saved token is still None when the TP arrives.
    client
        .ids
        .set_initial_dcid(vec![1, 2, 3].into(), None, Some(0));
    client.peer_parameters = PeerParameters::Remembered(TransportParams {
        stateless_reset_token: Some(initial_token),
        ..TransportParams::default()
    });
    let mut retired_path_ids = SmallVec::new();
    client.ids.new_dcid(
        vec![4, 5, 6].into(),
        1,
        rotated_token,
        0,
        &mut retired_path_ids,
    )?;
    assert!(retired_path_ids.is_empty());

    let mut packet = [0x40; 21];
    for token in [initial_token, rotated_token] {
        packet[5..].copy_from_slice(&token.to_be_bytes());
        assert!(client.is_stateless_reset(&packet));
    }
    packet[5..].copy_from_slice(&[0x83; 16]);
    assert!(!client.is_stateless_reset(&packet));
    packet[5..].copy_from_slice(&rotated_token.to_be_bytes());
    assert!(!client.is_stateless_reset(&packet[1..]));

    // Once an ID is retired, its reset token is no longer accepted.
    client.ids.retire_dcid(1)?;
    assert!(!client.is_stateless_reset(&packet));
    packet[5..].copy_from_slice(&initial_token.to_be_bytes());
    assert!(client.is_stateless_reset(&packet));
    Ok(())
}

#[test]
fn retry_source_cid_transport_parameter_matches_retry_history() -> TestResult {
    // The server must not invent a Retry identifier on a handshake that never
    // involved Retry, and a real Retry requires the exact remembered ID.
    for (observed_retry, advertised_retry, accepted) in [
        (None, None, true),
        (None, Some(b"retry".as_slice()), false),
        (Some(b"retry".as_slice()), None, false),
        (Some(b"retry".as_slice()), Some(b"wrong".as_slice()), false),
        (Some(b"retry".as_slice()), Some(b"retry".as_slice()), true),
    ] {
        let mut pipe = test_utils::Pipe::new("cubic")?;
        let client = &mut pipe.client;
        let original_dcid = ConnectionId::from(b"original".to_vec());
        client.initial.odcid = Some(original_dcid.clone());
        client.initial.rscid =
            observed_retry.map(|id| ConnectionId::from(id.to_vec()));
        let params = TransportParams {
            initial_source_connection_id: Some(client.destination_id().clone()),
            original_destination_connection_id: Some(original_dcid),
            retry_source_connection_id: advertised_retry
                .map(|id| ConnectionId::from(id.to_vec())),
            ..Default::default()
        };
        let result = client.parse_peer_transport_params(params);
        assert_eq!(
            result.is_ok(),
            accepted,
            "observed={observed_retry:?} advertised={advertised_retry:?}: {result:?}",
        );
        if !accepted {
            assert_eq!(result, Err(Error::InvalidTransportParam));
        }
    }
    Ok(())
}

#[test]
fn transport_params() -> TestResult {
    // Server encodes, client decodes.
    let tp = TransportParams {
        original_destination_connection_id: None,
        max_idle_timeout: 30,
        stateless_reset_token: Some(u128::from_be_bytes([0xba; 16])),
        max_udp_payload_size: 23_421,
        initial_max_data: 424_645_563,
        initial_max_stream_data_bidi_local: 154_323_123,
        initial_max_stream_data_bidi_remote: 6_587_456,
        initial_max_stream_data_uni: 2_461_234,
        initial_max_streams_bidi: 12_231,
        initial_max_streams_uni: 18_473,
        ack_delay_exponent: 20,
        max_ack_delay: 2_u64.pow(14) - 1,
        disable_active_migration: true,
        active_conn_id_limit: 8,
        initial_source_connection_id: Some(b"woot woot".to_vec().into()),
        retry_source_connection_id: Some(b"retry".to_vec().into()),
        max_datagram_frame_size: Some(32),
        unknown_params: None,
    };

    let mut raw_params = [42; 256];
    let raw_params = TransportParams::encode(&tp, true, &mut raw_params)?;
    assert_eq!(raw_params.len(), 94);

    let new_tp = TransportParams::decode(raw_params, false, None)?;

    assert_eq!(new_tp, tp);

    // Client encodes, server decodes.
    let tp = TransportParams {
        original_destination_connection_id: None,
        max_idle_timeout: 30,
        stateless_reset_token: None,
        max_udp_payload_size: 23_421,
        initial_max_data: 424_645_563,
        initial_max_stream_data_bidi_local: 154_323_123,
        initial_max_stream_data_bidi_remote: 6_587_456,
        initial_max_stream_data_uni: 2_461_234,
        initial_max_streams_bidi: 12_231,
        initial_max_streams_uni: 18_473,
        ack_delay_exponent: 20,
        max_ack_delay: 2_u64.pow(14) - 1,
        disable_active_migration: true,
        active_conn_id_limit: 8,
        initial_source_connection_id: Some(b"woot woot".to_vec().into()),
        retry_source_connection_id: None,
        max_datagram_frame_size: Some(32),
        unknown_params: None,
    };

    let mut raw_params = [42; 256];
    let raw_params = TransportParams::encode(&tp, false, &mut raw_params)?;
    assert_eq!(raw_params.len(), 69);

    let new_tp = TransportParams::decode(raw_params, true, None)?;

    assert_eq!(new_tp, tp);
    Ok(())
}

#[test]
fn ack_delay_scaling_preserves_integer_bounds() {
    for exponent in 0..=MAX_ACK_DELAY_EXPONENT {
        assert_eq!(
            encode_ack_delay(Duration::MAX, exponent),
            octets::MAX_VAR_INT
        );
        let factor = 1_u64 << exponent;
        let encoded = u64::MAX / factor;
        assert_eq!(decode_ack_delay(encoded, exponent), Ok(encoded * factor));
        if exponent != 0 {
            assert_eq!(
                decode_ack_delay(encoded + 1, exponent),
                Err(Error::InvalidFrame)
            );
        }
        let delay = Duration::from_micros(3 * factor + factor - 1);
        assert_eq!(encode_ack_delay(delay, exponent), 3);
    }
    assert_eq!(decode_ack_delay(1, 64), Err(Error::InvalidFrame));
    assert_eq!(decode_ack_delay(1, u64::MAX), Err(Error::InvalidFrame));
}

#[test]
fn transport_params_preserve_zero_ack_delays() -> TestResult {
    let default = TransportParams::decode(&[], false, None)?;
    assert_eq!(default.ack_delay_exponent, 3);
    assert_eq!(default.max_ack_delay, 25);

    let mut config = test_utils::Pipe::default_config("cubic")?;
    config.set_ack_delay_exponent(0);
    config.set_max_ack_delay(0);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    pipe.handshake()?;
    for conn in [&pipe.client, &pipe.server] {
        let peer = conn
            .peer_transport_params()
            .ok_or("negotiated peer parameters missing")?;
        assert_eq!(peer.ack_delay_exponent, 0);
        assert_eq!(peer.max_ack_delay, 0);
    }
    Ok(())
}

#[test]
fn transport_integer_payload_requires_exactly_one_varint() -> TestResult {
    for id in [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 32] {
        for bytes in [[id, 2, 1, 0], [id, 2, 0x40, 0x80]] {
            // A valid two-byte value (128) is permitted for fields whose
            // protocol range admits it. A one-byte value plus trailing bytes
            // is never a valid representation.
            if bytes[2] == 1 {
                assert_eq!(
                    TransportParams::decode(&bytes, false, None),
                    Err(Error::InvalidTransportParam)
                );
            } else if !matches!(id, 3 | 10) {
                assert!(
                    TransportParams::decode(&bytes, false, None).is_ok(),
                    "id={id}"
                );
            }
        }
        assert_eq!(
            TransportParams::decode(&[id, 0], false, None),
            Err(Error::InvalidTransportParam)
        );
        assert_eq!(
            TransportParams::decode(&[id, 1, 0x40], false, None),
            Err(Error::InvalidTransportParam)
        );
    }
    // A non-minimal but complete integer encoding is valid.
    assert_eq!(
        TransportParams::decode(&[10, 2, 0x40, 3], false, None)?
            .ack_delay_exponent,
        3
    );
    assert_eq!(
        TransportParams::decode(&[12, 1, 0], false, None),
        Err(Error::InvalidTransportParam)
    );
    assert!(
        TransportParams::decode(&[12, 0], false, None)?.disable_active_migration
    );
    Ok(())
}

#[test]
fn transport_params_local_encoding_rejects_invalid_ranges() {
    let baseline = TransportParams::default();
    let mut buf = [0; 256];
    for invalid in [
        TransportParams {
            max_udp_payload_size: 1199,
            ..baseline.clone()
        },
        TransportParams {
            initial_max_streams_bidi: MAX_STREAM_COUNT + 1,
            ..baseline.clone()
        },
        TransportParams {
            initial_max_streams_uni: MAX_STREAM_COUNT + 1,
            ..baseline.clone()
        },
        TransportParams {
            ack_delay_exponent: MAX_ACK_DELAY_EXPONENT + 1,
            ..baseline.clone()
        },
        TransportParams {
            max_ack_delay: transport_params::MAX_ACK_DELAY + 1,
            ..baseline.clone()
        },
        TransportParams {
            active_conn_id_limit: 1,
            ..baseline.clone()
        },
        TransportParams {
            initial_max_data: octets::MAX_VAR_INT + 1,
            ..baseline.clone()
        },
        TransportParams {
            max_datagram_frame_size: Some(octets::MAX_VAR_INT + 1),
            ..baseline.clone()
        },
        TransportParams {
            initial_source_connection_id: Some(
                vec![1; MAX_CONN_ID_LEN + 1].into(),
            ),
            ..baseline
        },
    ] {
        assert_eq!(
            TransportParams::encode(&invalid, false, &mut buf),
            Err(Error::InvalidTransportParam)
        );
    }
}

#[test]
fn transport_params_validate_connection_id_lengths_and_preferred_address() {
    for id in [0, 15, 16] {
        let mut wire = vec![id, 21];
        wire.extend_from_slice(&[0; 21]);
        assert_eq!(
            TransportParams::decode(&wire, false, None),
            Err(Error::InvalidTransportParam)
        );
    }

    let mut wire = vec![13, 42];
    wire.extend_from_slice(&[0; 42]);
    wire[2 + 24] = 1;
    assert!(TransportParams::decode(&wire, false, None).is_ok());
    assert_eq!(
        TransportParams::decode(&wire, true, None),
        Err(Error::InvalidTransportParam)
    );
    wire[2 + 24] = 0;
    assert_eq!(
        TransportParams::decode(&wire, false, None),
        Err(Error::InvalidTransportParam)
    );
    wire[2 + 24] = 2;
    assert_eq!(
        TransportParams::decode(&wire, false, None),
        Err(Error::InvalidTransportParam)
    );
}

#[test]
fn peer_transport_params_wire_preserves_original_encoding() -> TestResult {
    let mut pipe = test_utils::Pipe::new("cubic")?;
    assert!(pipe.client.peer_transport_params_wire().is_none());
    assert!(pipe.server.peer_transport_params_wire().is_none());

    pipe.handshake()?;

    for conn in [&pipe.client, &pipe.server] {
        let raw = conn
            .peer_transport_params_wire()
            .ok_or("validated raw QUIC parameters")?;
        assert_ne!(raw, [] as [u8; 0]);
        let parsed = TransportParams::decode(raw, conn.is_server(), None)?;
        assert_eq!(
            &parsed,
            conn.peer_transport_params()
                .ok_or("negotiated peer parameters missing")?
        );
        assert_eq!(conn.peer_transport_params_wire(), Some(raw));
    }
    Ok(())
}

#[test]
fn transport_params_forbid_duplicates() -> TestResult {
    // Given an encoded param.
    let initial_source_connection_id = b"id";
    let initial_source_connection_id_raw = [
        15,
        u8::try_from(initial_source_connection_id.len())?,
        initial_source_connection_id[0],
        initial_source_connection_id[1],
    ];

    // No error when decoding the param.
    let tp = TransportParams::decode(
        initial_source_connection_id_raw.as_slice(),
        true,
        None,
    )?;

    assert_eq!(
        tp.initial_source_connection_id,
        Some(initial_source_connection_id.to_vec().into())
    );

    // Duplicate the param.
    let mut raw_params = Vec::new();
    raw_params.append(&mut initial_source_connection_id_raw.to_vec());
    raw_params.append(&mut initial_source_connection_id_raw.to_vec());

    // Decoding fails.
    assert_eq!(
        TransportParams::decode(raw_params.as_slice(), true, None),
        Err(Error::InvalidTransportParam)
    );
    Ok(())
}

#[test]
fn transport_params_unknown_zero_space() {
    let mut unknown_params = UnknownTransportParameters::new(0);
    let massive_unknown_param = UnknownTransportParameter::<&[u8]> {
        id: 5,
        value: &[0xau8; 280],
    };
    assert!(unknown_params.push(massive_unknown_param).is_err());
    assert_eq!(unknown_params.remaining_capacity(), 0);
    assert_eq!(unknown_params.iter().len(), 0);
}

#[test]
fn transport_params_unknown_max_space_respected() -> TestResult {
    let mut unknown_params = UnknownTransportParameters::new(256);

    let massive_unknown_param = UnknownTransportParameter::<&[u8]> {
        id: 5,
        value: &[0xau8; 280],
    };
    let big_unknown_param = UnknownTransportParameter::<&[u8]> {
        id: 5,
        value: &[0xau8; 232],
    };
    let little_unknown_param = UnknownTransportParameter::<&[u8]> {
        id: 6,
        value: &[0xau8; 7],
    };

    assert!(unknown_params.push(massive_unknown_param).is_err());
    assert_eq!(unknown_params.remaining_capacity(), 256);
    assert_eq!(unknown_params.iter().len(), 0);

    unknown_params.push(big_unknown_param)?;
    assert_eq!(unknown_params.remaining_capacity(), 16);
    assert_eq!(unknown_params.iter().len(), 1);

    unknown_params.push(little_unknown_param)?;
    assert_eq!(unknown_params.remaining_capacity(), 1);
    assert_eq!(unknown_params.iter().len(), 2);

    assert!(unknown_params.push(little_unknown_param).is_err());

    let mut unknown_params_iter = unknown_params.into_iter();

    let unknown_params_first = unknown_params_iter
        .next()
        .ok_or("Should have a 0th element.")?;
    assert!(
        unknown_params_first.id == 5 &&
            unknown_params_first.value == vec![0xau8; 232]
    );

    let unknown_params_second = unknown_params_iter
        .next()
        .ok_or("Should have a 1th element.")?;
    assert!(
        unknown_params_second.id == 6 &&
            unknown_params_second.value == vec![0xau8; 7]
    );
    Ok(())
}

#[test]
fn transport_params_unknown_is_reserved() {
    let reserved_unknown_param = UnknownTransportParameter::<&[u8]> {
        id: 31 * 17 + 27,
        value: &[0xau8; 280],
    };
    let not_reserved_unknown_param = UnknownTransportParameter::<&[u8]> {
        id: 32 * 17 + 27,
        value: &[0xau8; 280],
    };

    assert!(reserved_unknown_param.is_reserved());
    assert!(!not_reserved_unknown_param.is_reserved());
}
#[test]
fn unknown_version() -> TestResult {
    let mut config = Config::new(0xbaba_baba)?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config)?;
    assert_eq!(pipe.handshake(), Err(Error::UnknownVersion));
    Ok(())
}

#[test]
fn recovery_configuration_is_snapshotted_at_connection_creation() -> TestResult {
    let mut config = test_utils::Pipe::default_config("cubic")?;
    let initial_rtt = Duration::from_millis(73);
    config.set_initial_rtt(initial_rtt);
    config.set_initial_congestion_window_packets(17);
    config.set_max_send_udp_payload_size(1400);
    config.set_max_pacing_rate(123_456);
    config.enable_pacing(false);
    config.enable_hystart(false);
    config.set_enable_relaxed_loss_threshold(true);
    config.set_max_ack_delay(42);
    let expected = config.recovery;

    let pipe = test_utils::Pipe::with_config(&mut config)?;
    for conn in [&pipe.client, &pipe.server] {
        assert!(conn.recovery_config == expected);
        assert_eq!(conn.recovery_config.max_ack_delay, Duration::ZERO);
        assert_eq!(conn.local_transport_params.max_ack_delay, 42);
        assert_eq!(conn.paths.get_active()?.recovery.rtt(), initial_rtt);
        assert_eq!(conn.paths.get_active()?.recovery.max_datagram_size(), 1400);
    }

    config.set_initial_rtt(Duration::from_millis(200));
    config.set_cc_algorithm(CongestionControlAlgorithm::Reno);
    assert!(pipe.client.recovery_config == expected);
    assert!(pipe.server.recovery_config == expected);
    Ok(())
}

#[test]
fn config_version_reserved() -> TestResult {
    Config::new(0xbaba_baba)?;
    Config::new(0x1a2a_3a4a)?;
    Ok(())
}

#[test]
fn config_version_invalid() {
    assert!(matches!(
        Config::new(0xb1ba_baba),
        Err(Error::UnknownVersion)
    ));
}

#[test]
fn version_negotiation() -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = Config::new(0xbaba_baba)?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config)?;

    let (mut len, _) = pipe.client.send(&mut buf)?;

    let hdr = Header::from_slice(&buf[..len], 0)?;
    len = negotiate_version(&hdr.scid, &hdr.dcid, &mut buf)?;

    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.version, PROTOCOL_VERSION);
    assert_eq!(pipe.server.version, PROTOCOL_VERSION);
    Ok(())
}

#[test]
fn verify_custom_root() -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    config.verify_peer(true);
    config.load_verify_locations_from_file("examples/rootca.crt")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;

    let mut pipe = test_utils::Pipe::with_client_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));
    Ok(())
}

#[test]
fn verify_client_invalid() -> TestResult {
    let mut server_config = Config::new(PROTOCOL_VERSION)?;
    server_config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    server_config.load_priv_key_from_pem_file("examples/cert.key")?;
    server_config.set_application_protos(&[b"proto1", b"proto2"])?;
    server_config.set_initial_max_data(30);
    server_config.set_initial_max_stream_data_bidi_local(15);
    server_config.set_initial_max_stream_data_bidi_remote(15);
    server_config.set_initial_max_streams_bidi(3);

    // The server shouldn't be able to verify the client's certificate due
    // to missing CA.
    server_config.verify_peer(true);

    let mut client_config = Config::new(PROTOCOL_VERSION)?;
    client_config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    client_config.load_priv_key_from_pem_file("examples/cert.key")?;
    client_config.set_application_protos(&[b"proto1", b"proto2"])?;
    client_config.set_initial_max_data(30);
    client_config.set_initial_max_stream_data_bidi_local(15);
    client_config.set_initial_max_stream_data_bidi_remote(15);
    client_config.set_initial_max_streams_bidi(3);

    // The client is able to verify the server's certificate with the
    // appropriate CA.
    client_config.load_verify_locations_from_file("examples/rootca.crt")?;
    client_config.verify_peer(true);

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )?;
    assert_eq!(pipe.handshake(), Err(Error::TlsFail));

    // Client did send a certificate.
    assert!(pipe.server.peer_cert().is_some());
    Ok(())
}

#[test]
fn verify_client_anonymous() -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);

    // Try to validate client certificate.
    config.verify_peer(true);

    let mut pipe = test_utils::Pipe::with_server_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client didn't send a certificate.
    assert!(pipe.server.peer_cert().is_none());
    Ok(())
}

#[rstest]
fn missing_initial_source_connection_id(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    // Reset initial_source_connection_id.
    pipe.client
        .local_transport_params
        .initial_source_connection_id = None;
    assert_eq!(pipe.client.encode_transport_params(), Ok(()));

    // Client sends initial flight. The ClientHello may span multiple Initial
    // packets (e.g. when post-quantum key shares are advertised), so deliver
    // the whole flight before checking the server's reaction.
    let flight = test_utils::emit_flight(&mut pipe.client)?;

    // Server rejects transport parameters.
    assert_eq!(
        test_utils::process_flight(&mut pipe.server, flight),
        Err(Error::InvalidTransportParam)
    );
    Ok(())
}

#[rstest]
fn invalid_initial_source_connection_id(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    // Scramble initial_source_connection_id.
    pipe.client
        .local_transport_params
        .initial_source_connection_id = Some(b"bogus value".to_vec().into());
    assert_eq!(pipe.client.encode_transport_params(), Ok(()));

    // Client sends initial flight. The ClientHello may span multiple Initial
    // packets (e.g. when post-quantum key shares are advertised), so deliver
    // the whole flight before checking the server's reaction.
    let flight = test_utils::emit_flight(&mut pipe.client)?;

    // Server rejects transport parameters.
    assert_eq!(
        test_utils::process_flight(&mut pipe.server, flight),
        Err(Error::InvalidTransportParam)
    );
    Ok(())
}

#[rstest]
fn change_idle_timeout(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = Config::new(0x1)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_max_idle_timeout(999_999);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config)?;
    assert_eq!(pipe.client.local_transport_params.max_idle_timeout, 999_999);
    assert_eq!(pipe.client.peer_parameters.effective().max_idle_timeout, 0);
    assert_eq!(pipe.server.local_transport_params.max_idle_timeout, 0);
    assert_eq!(pipe.server.peer_parameters.effective().max_idle_timeout, 0);

    pipe.client.set_max_idle_timeout(456_000)?;
    pipe.server.set_max_idle_timeout(234_000)?;
    assert_eq!(pipe.client.local_transport_params.max_idle_timeout, 456_000);
    assert_eq!(pipe.client.peer_parameters.effective().max_idle_timeout, 0);
    assert_eq!(pipe.server.local_transport_params.max_idle_timeout, 234_000);
    assert_eq!(pipe.server.peer_parameters.effective().max_idle_timeout, 0);

    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.idle_timeout(), Some(Duration::from_secs(234)));
    assert_eq!(pipe.server.idle_timeout(), Some(Duration::from_secs(234)));
    Ok(())
}

#[rstest]
fn handshake(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.application_proto(),
        pipe.server.application_proto()
    );

    assert_eq!(pipe.server.server_name(), Some("quic.tech"));
    Ok(())
}

#[rstest]
fn handshake_done(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    // Disable session tickets on the server (SSL_OP_NO_TICKET) to avoid
    // triggering 1-RTT packet send with a CRYPTO frame.
    pipe.server.handshake.set_options(0x0000_4000);

    assert_eq!(pipe.handshake(), Ok(()));

    assert_ne!(pipe.server.handshake_done, HandshakeDoneState::Pending);
    Ok(())
}

#[rstest]
fn handshake_confirmation(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    // Client sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    assert_handshake_confirmation(&mut pipe)?;
    Ok(())
}

fn assert_handshake_confirmation(pipe: &mut test_utils::Pipe) -> TestResult {
    // Server sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.server)?;

    assert!(!pipe.client.is_established());
    assert!(!pipe.client.handshake_progress.confirmed());

    assert!(!pipe.server.is_established());
    assert!(!pipe.server.handshake_progress.confirmed());

    test_utils::process_flight(&mut pipe.client, flight)?;

    // Client sends Handshake packet and completes handshake.
    let flight = test_utils::emit_flight(&mut pipe.client)?;

    assert!(pipe.client.is_established());
    assert!(!pipe.client.handshake_progress.confirmed());

    assert!(!pipe.server.is_established());
    assert!(!pipe.server.handshake_progress.confirmed());

    test_utils::process_flight(&mut pipe.server, flight)?;

    // Server completes and confirms handshake, and sends HANDSHAKE_DONE.
    let flight = test_utils::emit_flight(&mut pipe.server)?;

    assert!(pipe.client.is_established());
    assert!(!pipe.client.handshake_progress.confirmed());

    assert!(pipe.server.is_established());
    assert!(pipe.server.handshake_progress.confirmed());

    test_utils::process_flight(&mut pipe.client, flight)?;

    // Client acks 1-RTT packet, and confirms handshake.
    let flight = test_utils::emit_flight(&mut pipe.client)?;

    assert!(pipe.client.is_established());
    assert!(pipe.client.handshake_progress.confirmed());

    assert!(pipe.server.is_established());
    assert!(pipe.server.handshake_progress.confirmed());

    test_utils::process_flight(&mut pipe.server, flight)?;

    assert!(pipe.client.is_established());
    assert!(pipe.client.handshake_progress.confirmed());

    assert!(pipe.server.is_established());
    assert!(pipe.server.handshake_progress.confirmed());
    Ok(())
}

#[rstest]
fn handshake_resumption(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    const SESSION_TICKET_KEY: [u8; 48] = [0xa; 48];

    let mut config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));

    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.set_ticket_key(&SESSION_TICKET_KEY)?;

    // Perform initial handshake.
    let mut pipe = test_utils::Pipe::with_server_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert!(pipe.client.is_established());
    assert!(pipe.server.is_established());

    assert!(!pipe.client.is_resumed());
    assert!(!pipe.server.is_resumed());

    // Extract session,
    let session = pipe.client.session().ok_or("TLS session was not issued")?;

    // Configure session on new connection and perform handshake.
    let mut config = Config::new(PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.set_ticket_key(&SESSION_TICKET_KEY)?;

    // Use a genuine resumable session so a truncated 64-bit length would
    // otherwise select valid TLS bytes/transport parameters on 32-bit targets.
    let session_len = u64::from_be_bytes(session[..8].try_into()?);
    let params_offset = 8 + usize::try_from(session_len)?;
    let params_len =
        u64::from_be_bytes(session[params_offset..params_offset + 8].try_into()?);
    let mut oversized_session = session.to_vec();
    oversized_session[..8]
        .copy_from_slice(&(session_len + (1_u64 << 32)).to_be_bytes());
    let mut oversized_params = session.to_vec();
    oversized_params[params_offset..params_offset + 8]
        .copy_from_slice(&(params_len + (1_u64 << 32)).to_be_bytes());
    // A structurally complete suffix can still contain an invalid varint.
    let mut invalid_params = session[..params_offset].to_vec();
    invalid_params.extend_from_slice(&1_u64.to_be_bytes());
    invalid_params.push(0x40);

    for (malformed, expected) in [
        (oversized_session.as_slice(), Error::BufferTooShort),
        (oversized_params.as_slice(), Error::BufferTooShort),
        (invalid_params.as_slice(), Error::InvalidTransportParam),
        (&session[..params_offset + 7], Error::BufferTooShort),
        (&session[..session.len() - 1], Error::BufferTooShort),
    ] {
        let mut rejected = test_utils::Pipe::with_server_config(&mut config)?;
        let original_params = rejected.client.peer_parameters.clone();
        assert_eq!(rejected.client.set_session(malformed), Err(expected),);
        assert_eq!(rejected.client.peer_parameters, original_params);
        rejected.handshake()?;
        assert!(!rejected.client.is_resumed());
        assert!(!rejected.server.is_resumed());
    }

    let mut pipe = test_utils::Pipe::with_server_config(&mut config)?;

    assert_eq!(pipe.client.set_session(session), Ok(()));
    assert_eq!(pipe.handshake(), Ok(()));

    assert!(pipe.client.is_established());
    assert!(pipe.server.is_established());

    assert!(pipe.client.is_resumed());
    assert!(pipe.server.is_resumed());
    Ok(())
}

#[rstest]
fn handshake_alpn_mismatch(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config.set_application_protos(&[b"proto3\x06proto4"])?;
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config)?;
    assert_eq!(pipe.handshake(), Err(Error::TlsFail));

    assert_eq!(pipe.client.application_proto(), b"");
    assert_eq!(pipe.server.application_proto(), b"");

    // Server should only send one packet in response to ALPN mismatch.
    let (len, _) = pipe.server.send(&mut buf)?;
    assert_eq!(len, 1200);

    assert_eq!(pipe.server.send(&mut buf), Err(Error::Done));
    assert_eq!(pipe.server.counters.sent_count, 1);
    Ok(())
}

fn early_data_pipe(
    cc_algorithm_name: &str, single_initial: bool,
) -> TestResult<test_utils::Pipe> {
    let mut config = if single_initial {
        test_utils::config_no_pq(PROTOCOL_VERSION)?
    } else {
        Config::new(PROTOCOL_VERSION)?
    };
    config.set_cc_algorithm_name(cc_algorithm_name)?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.enable_early_data();
    config.verify_peer(false);
    resumed_pipe(&mut config)
}

fn resumed_pipe(config: &mut Config) -> TestResult<test_utils::Pipe> {
    let mut first = test_utils::Pipe::with_config(config)?;
    first.handshake()?;
    let session = first.client.session().ok_or("TLS session was not issued")?;
    let mut resumed = test_utils::Pipe::with_config(config)?;
    resumed.client.set_session(session)?;
    Ok(resumed)
}

#[rstest]
fn handshake_0rtt(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = early_data_pipe(cc_algorithm_name, true)?;

    // Client sends initial flight.
    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    // Client sends 0-RTT packet.
    let pkt_type = Type::ZeroRTT;

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"aaaaa", 0, true),
    }];

    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Ok(1200)
    );

    assert_eq!(pipe.server.undecryptable_pkts.len(), 0);

    // 0-RTT stream data is readable.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((5, true)));
    assert_eq!(&b[..5], b"aaaaa");
    Ok(())
}

#[rstest]
fn handshake_0rtt_reordered(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = early_data_pipe(cc_algorithm_name, true)?;

    // Client sends initial flight.
    let (len, _) = pipe.client.send(&mut buf)?;
    let mut initial = buf[..len].to_vec();

    // Client sends 0-RTT packet.
    let pkt_type = Type::ZeroRTT;

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"aaaaa", 0, true),
    }];

    let len =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)?;
    let mut zrtt = buf[..len].to_vec();

    // 0-RTT packet is received before the Initial one.
    assert_eq!(pipe.server_recv(&mut zrtt), Ok(zrtt.len()));

    assert_eq!(pipe.server.undecryptable_pkts.len(), 1);
    assert_eq!(pipe.server.undecryptable_pkts[0].0.len(), zrtt.len());

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Initial packet is also received.
    assert_eq!(pipe.server_recv(&mut initial), Ok(initial.len()));

    // 0-RTT stream data is readable.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((5, true)));
    assert_eq!(&b[..5], b"aaaaa");
    Ok(())
}

#[rstest]
fn handshake_0rtt_truncated(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = early_data_pipe(cc_algorithm_name, false)?;

    // Client sends initial flight.
    pipe.client.send(&mut buf)?;

    // Client sends 0-RTT packet.
    let pkt_type = Type::ZeroRTT;

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"aaaaa", 0, true),
    }];

    let len =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)?;

    // Simulate a truncated packet by sending one byte less.
    let mut zrtt = buf[..len - 1].to_vec();

    // 0-RTT packet is received before the Initial one.
    assert_eq!(pipe.server_recv(&mut zrtt), Err(Error::InvalidPacket));

    assert_eq!(pipe.server.undecryptable_pkts.len(), 0);

    assert!(pipe.server.is_closed());
    Ok(())
}

fn assert_rejected_packet(
    pipe: &mut test_utils::Pipe, buf: &mut [u8], written: usize,
    expected_error: Error, error_code: u64,
) -> TestResult {
    let active_path = pipe.server.paths.get_active()?;
    let info = RecvInfo {
        to: active_path.local_addr(),
        from: active_path.peer_addr(),
    };
    assert_eq!(
        pipe.server.recv(&mut buf[..written], info),
        Err(expected_error)
    );
    let (written, _) = pipe.server.send(buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..written])?;
    assert_eq!(
        frames.first(),
        Some(&frame::Frame::ConnectionClose {
            error_code,
            frame_type: 0,
            reason: Vec::new(),
        })
    );
    Ok(())
}

#[rstest]
fn crypto_limit(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.enable_early_data();
    config.verify_peer(false);

    // Perform initial handshake.
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client send a 1-byte frame that starts from the crypto stream offset
    // limit.
    let frames = [frame::Frame::Crypto {
        data: RangeBuf::from(b"a", MAX_CRYPTO_STREAM_OFFSET, false),
    }];

    let pkt_type = Type::Short;

    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)?;

    assert_rejected_packet(
        &mut pipe,
        &mut buf,
        written,
        Error::CryptoBufferExceeded,
        0x0d,
    )?;
    Ok(())
}

#[rstest]
fn limit_handshake_data(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    // This test relies on `cert-big.crt` forcing the server's handshake
    // flight above the default `client_sent * MAX_AMPLIFICATION_FACTOR`
    // anti-amplification cap, which in turn relies on the ClientHello
    // fitting in a single Initial packet (so `client_sent` stays small).
    // Use a no-PQ client config to guarantee that.
    let mut config = test_utils::config_no_pq(PROTOCOL_VERSION)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config.load_cert_chain_from_pem_file("examples/cert-big.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    let client_sent = flight.iter().fold(0, |out, p| out + p.0.len());
    test_utils::process_flight(&mut pipe.server, flight)?;

    let flight = test_utils::emit_flight(&mut pipe.server)?;
    let server_sent = flight.iter().fold(0, |out, p| out + p.0.len());

    assert_eq!(server_sent, client_sent * MAX_AMPLIFICATION_FACTOR);
    Ok(())
}

#[rstest]
fn custom_limit_handshake_data(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    const CUSTOM_AMPLIFICATION_FACTOR: usize = 2;

    let mut config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config.load_cert_chain_from_pem_file("examples/cert-big.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_max_amplification_factor(CUSTOM_AMPLIFICATION_FACTOR);

    let mut pipe = test_utils::Pipe::with_server_config(&mut config)?;

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    let client_sent = flight.iter().fold(0, |out, p| out + p.0.len());
    test_utils::process_flight(&mut pipe.server, flight)?;

    let flight = test_utils::emit_flight(&mut pipe.server)?;
    let server_sent = flight.iter().fold(0, |out, p| out + p.0.len());

    assert_eq!(server_sent, client_sent * CUSTOM_AMPLIFICATION_FACTOR);
    Ok(())
}

#[test]
fn large_amplification_factor_does_not_overflow_received_credit() -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    config.set_max_amplification_factor(usize::MAX);
    let mut pipe = test_utils::Pipe::with_server_config(&mut config)?;
    let mut buf = [0; 2048];
    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));
    assert_eq!(pipe.server.paths.get_active()?.max_send_bytes, usize::MAX,);

    // Receiving another datagram must not wrap the already saturated budget.
    let _ = pipe.server_recv(&mut buf[..len]);
    assert_eq!(pipe.server.paths.get_active()?.max_send_bytes, usize::MAX,);
    Ok(())
}

#[rstest]
fn amplification_limited_stat() -> TestResult {
    // `cert-big.crt` is sized so the server's handshake flight exceeds the
    // default `client_sent * MAX_AMPLIFICATION_FACTOR` anti-amplification
    // cap; that only holds when the ClientHello fits in a single Initial,
    // so use a no-PQ config.
    let mut config = test_utils::config_no_pq(PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file("examples/cert-big.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;
    // Server sends handshake until amplification budget is exhausted.
    let flight = test_utils::emit_flight(&mut pipe.server)?;
    assert_ne!(flight, [] as [(Vec<u8>, SendInfo); 0]);
    assert!(pipe.server.stats().amplification_limited_count > 0);
    // Complete handshake and verifies client address.
    test_utils::process_flight(&mut pipe.client, flight)?;
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;
    // Counter should not increment after address verification.
    let count_after_handshake = pipe.server.stats().amplification_limited_count;
    let flight = test_utils::emit_flight(&mut pipe.server);
    assert!(flight.is_ok() || flight == Err(Error::Done));
    assert_eq!(
        pipe.server.stats().amplification_limited_count,
        count_after_handshake
    );
    Ok(())
}

#[rstest]
fn streamio(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"hello, world", true), Ok(12));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.server.stream_finished(4));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((12, true)));
    assert_eq!(&b[..12], b"hello, world");

    assert!(pipe.server.stream_finished(4));
    Ok(())
}

#[rstest]
fn stream_closed_bidi(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert!(!pipe.client.stream_closed(0));
    assert!(!pipe.server.stream_closed(0));

    assert_eq!(pipe.client.stream_send(0, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.client.stream_closed(0));
    assert!(!pipe.server.stream_closed(0));

    let mut buf = [0; 5];
    assert_eq!(pipe.server.stream_recv(0, &mut buf), Ok((5, true)));

    assert!(!pipe.server.stream_closed(0));

    assert_eq!(pipe.server.stream_send(0, b"world", true), Ok(5));
    assert!(pipe.server.stream_closed(0));

    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.client.stream_closed(0));
    assert_eq!(pipe.client.stream_recv(0, &mut buf), Ok((5, true)));
    assert!(pipe.client.stream_closed(0));
    Ok(())
}

#[rstest]
fn stream_closed_uni(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert!(!pipe.client.stream_closed(2));
    assert!(!pipe.server.stream_closed(2));

    assert_eq!(pipe.client.stream_send(2, b"hello", true), Ok(5));

    assert!(pipe.client.stream_closed(2));

    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.server.stream_closed(2));

    let mut buf = [0; 5];
    assert_eq!(pipe.server.stream_recv(2, &mut buf), Ok((5, true)));

    assert!(pipe.server.stream_closed(2));
    Ok(())
}

/// Test receiving into `BufMut`
#[rstest]
fn stream_recv_buf(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    use bytes::BufMut as _;

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"hello, world", true), Ok(12));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.server.stream_finished(4));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = Vec::with_capacity(15).limit(15);
    assert_eq!(b.get_ref().len(), 0);
    assert_eq!(pipe.server.stream_recv_buf(4, &mut b), Ok((12, true)));
    let b = b.into_inner();
    assert_eq!(b.len(), 12);
    assert_eq!(&b, b"hello, world");

    assert!(pipe.server.stream_finished(4));
    Ok(())
}

/// Test receiving into a `BufMut`. We test that a `Vec` used as `BufMut` will
/// indeed grow automatically, and that `limit` is honored, and that we can
/// adjust the limit, (and that we properly append once the limit is increased)
#[rstest]
fn stream_recv_buf_empty(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    use bytes::BufMut as _;

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"hello, world", true), Ok(12));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.server.stream_finished(4));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = Vec::new().limit(2);
    assert_eq!(b.get_ref().len(), 0);
    assert_eq!(pipe.server.stream_recv_buf(4, &mut b), Ok((2, false)));
    // The buffer won't accept additional writes
    assert_eq!(pipe.server.stream_recv_buf(4, &mut b), Ok((0, false)));

    b.set_limit(15);
    assert_eq!(pipe.server.stream_recv_buf(4, &mut b), Ok((10, true)));
    let b = b.into_inner();
    assert_eq!(b.len(), 12);
    assert_eq!(&b, b"hello, world");

    assert!(pipe.server.stream_finished(4));
    Ok(())
}

#[rstest]
fn streamio_mixed_actions(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"helloworldttfn", true), Ok(14));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.server.stream_finished(4));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(4, &mut b[..5]), Ok((5, false)));
    assert_eq!(&b[..5], b"hello");
    assert_eq!(pipe.server.stream_discard(4, 5), Ok((5, false)));
    assert_eq!(pipe.server.stream_recv(4, &mut b[..2]), Ok((2, false)));
    assert_eq!(&b[..2], b"tt");
    assert_eq!(pipe.server.stream_discard(4, 2), Ok((2, true)));

    assert!(pipe.server.stream_finished(4));
    Ok(())
}

#[rstest]
fn zero_rtt(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = early_data_pipe(cc_algorithm_name, true)?;

    // Client sends initial flight.
    let (len, _) = pipe.client.send(&mut buf)?;
    let mut initial = buf[..len].to_vec();

    assert!(pipe.client.is_in_early_data());

    // Client sends 0-RTT data.
    assert_eq!(pipe.client.stream_send(4, b"hello, world", true), Ok(12));

    let (len, _) = pipe.client.send(&mut buf)?;
    let mut zrtt = buf[..len].to_vec();

    // Server receives packets.
    assert_eq!(pipe.server_recv(&mut initial), Ok(initial.len()));
    assert!(pipe.server.is_in_early_data());

    assert_eq!(pipe.server_recv(&mut zrtt), Ok(zrtt.len()));

    // 0-RTT stream data is readable.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut b = [0; 15];
    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((12, true)));
    assert_eq!(&b[..12], b"hello, world");
    Ok(())
}

#[rstest]
fn stream_send_on_32bit_arch(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(2_u64.pow(32) + 5);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // In 32bit arch, send_capacity() should be min(2^32+5, cwnd),
    // not min(5, cwnd)
    assert_eq!(pipe.client.stream_send(4, b"hello, world", true), Ok(12));

    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.server.stream_finished(4));
    Ok(())
}

fn assert_stream_packet_acknowledged(
    pipe: &mut test_utils::Pipe, frames: &[frame::Frame], buf: &mut [u8],
) -> TestResult {
    let pn = pipe.client.next_pkt_num;
    let len = pipe.send_pkt_to_server(Type::Short, frames, buf)?;
    let response = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    assert!(
        response.iter().any(|frame| matches!(
            frame,
            frame::Frame::Ack { ranges, .. } if ranges.contains(pn)
        )),
        "response must acknowledge packet {pn}: {response:?}"
    );
    Ok(())
}

#[rstest]
fn empty_stream_frame(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"aaaaa", 0, false),
    }];

    assert_stream_packet_acknowledged(&mut pipe, &frames, &mut buf)?;

    let mut readable = pipe.server.readable();
    assert_eq!(readable.next(), Some(4));

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 4),
        Ok((5, false))
    );

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"", 5, true),
    }];

    assert_stream_packet_acknowledged(&mut pipe, &frames, &mut buf)?;

    let mut readable = pipe.server.readable();
    assert_eq!(readable.next(), Some(4));

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 4),
        Ok((0, true))
    );

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"", 15, true),
    }];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::FinalSize)
    );
    Ok(())
}

#[rstest]
fn update_key_request(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut b = [0; 15];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends message with key update request.
    assert_eq!(pipe.client_update_key(), Ok(()));
    assert_eq!(pipe.client.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Ensure server updates key and it correctly decrypts the message.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);
    assert_eq!(pipe.server.stream_recv(4, &mut b), Ok((5, false)));
    assert_eq!(&b[..5], b"hello");

    // Ensure ACK for key update.
    assert!(
        pipe.server.crypto_ctx[packet::Epoch::Application]
            .key_update
            .as_ref()
            .ok_or("key update state missing")?
            .update_acked
    );

    // Server sends message with the new key.
    assert_eq!(pipe.server.stream_send(4, b"world", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Ensure update key is completed and client can decrypt packet.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);
    assert_eq!(pipe.client.stream_recv(4, &mut b), Ok((5, false)));
    assert_eq!(&b[..5], b"world");

    // Server keeps sending packets to ensure encryption still works.
    for _ in 0..10 {
        assert_eq!(pipe.server.stream_send(4, b"world", false), Ok(5));
        assert_eq!(pipe.advance(), Ok(()));

        let mut r = pipe.client.readable();
        assert_eq!(r.next(), Some(4));
        assert_eq!(r.next(), None);
        if discard {
            assert_eq!(pipe.client.stream_discard(4, 5), Ok((5, false)));
        } else {
            assert_eq!(pipe.client.stream_recv(4, &mut b), Ok((5, false)));
            assert_eq!(&b[..5], b"world");
        }
    }
    Ok(())
}

#[rstest]
fn unauthenticated_key_phase_change_does_not_install_new_keys(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    pipe.handshake()?;
    pipe.advance()?;
    let previous_phase = pipe.server.key_phase;

    pipe.client_update_key()?;
    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"hello", 0, false),
    }];
    let mut buf = [0; 1500];
    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)?;

    // Flip a tag byte without changing the header protection sample.
    let mut corrupted = buf[..written].to_vec();
    corrupted[written - 1] ^= 1;
    assert_eq!(pipe.server_recv(&mut corrupted), Ok(written));
    assert_eq!(pipe.server.key_phase, previous_phase);
    assert!(pipe.server.crypto_ctx[packet::Epoch::Application]
        .key_update
        .is_none());
    assert!(pipe.server.local_error.is_none());

    // The authentic packet must still decrypt and advance the key phase.
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));
    assert_eq!(pipe.server.key_phase, !previous_phase);
    assert!(pipe.server.crypto_ctx[packet::Epoch::Application]
        .key_update
        .is_some());
    let mut data = [0; 5];
    assert_eq!(pipe.server.stream_recv(4, &mut data), Ok((5, false)));
    assert_eq!(&data, b"hello");
    Ok(())
}

#[rstest]
fn update_key_request_twice_error(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"hello", 0, false),
    }];

    // Client sends stream frame with key update request.
    assert_eq!(pipe.client_update_key(), Ok(()));
    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)?;

    // Server correctly decode with new key.
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    // Client sends stream frame with another key update request before server
    // ACK.
    assert_eq!(pipe.client_update_key(), Ok(()));
    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)?;

    // Check server correctly closes the connection with a key update error
    // for the peer.
    assert_eq!(pipe.server_recv(&mut buf[..written]), Err(Error::KeyUpdate));
    Ok(())
}

#[rstest]
/// Tests that receiving a `MAX_STREAM_DATA` frame for a receive-only
/// unidirectional stream is forbidden.
fn max_stream_data_receive_uni(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client opens unidirectional stream.
    assert_eq!(pipe.client.stream_send(2, b"hello", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends MAX_STREAM_DATA on local unidirectional stream.
    let frames = [frame::Frame::MaxStreamData {
        stream_id: 2,
        max: 1024,
    }];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::InvalidStreamState(2)),
    );
    Ok(())
}

#[rstest]
fn empty_payload(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Send a packet with no frames.
    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &[], &mut buf),
        Err(Error::InvalidPacket)
    );
    Ok(())
}

#[rstest]
fn min_payload(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    // Send a non-ack-eliciting packet.
    let frames = [frame::Frame::Padding { len: 4 }];

    let pkt_type = Type::Initial;
    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)?;
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    let initial_path = pipe.server.paths.get_active()?;

    assert_eq!(initial_path.max_send_bytes, 195);

    // Force server to send a single PING frame.
    pipe.server
        .paths
        .get_active_mut()?
        .recovery
        .inc_loss_probes(packet::Epoch::Initial);

    let initial_path = pipe.server.paths.get_active_mut()?;

    // Artificially limit the amount of bytes the server can send.
    initial_path.max_send_bytes = 60;

    assert_eq!(pipe.server.send(&mut buf), Err(Error::Done));
    Ok(())
}

#[rstest]
fn flow_control_limit(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(b"a", 0, false),
        },
    ];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::FlowControl),
    );
    Ok(())
}

#[rstest]
fn flow_control_limit_dup(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        // One byte less than stream limit.
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaa", 0, false),
        },
        // Same stream, but one byte more.
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        },
    ];

    let pkt_type = Type::Short;
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());
    Ok(())
}

fn initial_flow_control_pipe(
    cc_algorithm_name: &str,
) -> TestResult<test_utils::Pipe> {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    pipe.handshake()?;
    assert_eq!(pipe.server.max_rx_data(), 30);
    Ok(pipe)
}

#[rstest]
fn flow_control_empty_stream_frame_not_double_counted(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = initial_flow_control_pipe(cc_algorithm_name)?;

    // The empty frame advances the largest received offset to 15, which is
    // charged to connection flow control before the data covering 5..15
    // arrives.
    let frames = [
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaa", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"", 15, false),
        },
    ];

    let pkt_type = Type::Short;
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());
    assert_eq!(pipe.server.rx_data, 15);

    // Filling the gap must not be charged again: the remaining 15 bytes of
    // credit go entirely to the second stream.
    let frames = [
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaaaaaaa", 5, false),
        },
        frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        },
    ];

    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());
    assert_eq!(pipe.server.rx_data, 30);
    Ok(())
}

#[rstest]
fn flow_control_empty_stream_frame_after_shutdown(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let pkt_type = Type::Short;

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::Stream {
        stream_id: 0,
        data: <RangeBuf>::from(b"aaaaa", 0, false),
    }];
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    // A draining stream counts incoming data as consumed as it arrives.
    assert_eq!(pipe.server.stream_shutdown(0, Shutdown::Read, 42), Ok(()));
    assert_eq!(pipe.server.rx_data, 5);
    assert_eq!(pipe.server.flow_control.consumed(), 5);

    let frames = [frame::Frame::Stream {
        stream_id: 0,
        data: <RangeBuf>::from(b"", 10, false),
    }];
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());
    assert_eq!(pipe.server.rx_data, 10);
    assert_eq!(pipe.server.flow_control.consumed(), 10);

    // The reset charges and consumes only the bytes beyond the largest
    // received offset; 5..10 was already consumed above.
    let frames = [frame::Frame::ResetStream {
        stream_id: 0,
        error_code: 42,
        final_size: 15,
    }];
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());
    assert_eq!(pipe.server.rx_data, 15);
    assert_eq!(pipe.server.flow_control.consumed(), 15);
    Ok(())
}

#[rstest]
fn zero_length_stream_frame_not_sent(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    const STREAM_ID: u64 = 1 << 14;

    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(4_000_000_000);
    config.set_initial_max_stream_data_bidi_local(2_000_000_000);
    config.set_initial_max_stream_data_bidi_remote(2_000_000_000);
    config.set_initial_max_streams_bidi((STREAM_ID >> 2) + 1);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Use four-byte stream ID and eight-byte offset varints, producing a
    // 15-byte STREAM header. Seed the offset rather than transferring a
    // gigabyte.
    assert_eq!(pipe.client.stream_send(STREAM_ID, b"", false), Ok(0));
    pipe.client
        .streams
        .get_mut(STREAM_ID)
        .ok_or("expected stream is absent")?
        .send
        .seed_offsets_for_test(1 << 30);

    let data = [0xa; 4096];
    assert_eq!(pipe.client.stream_send(STREAM_ID, &data, false), Ok(4096));

    // Sweep output buffer sizes across the range where the packet has room
    // for the STREAM frame header but not for any payload.
    for cap in 25..80 {
        match pipe.client.send(&mut buf[..cap]) {
            Ok((written, _)) => {
                let frames =
                    test_utils::decode_pkt(&pipe.server, &mut buf[..written])?;

                for frame in &frames {
                    if let frame::Frame::Stream { data, .. } = frame {
                        assert!(
                            !data.is_empty() || data.fin(),
                            "zero-length non-fin STREAM frame sent at cap {cap}",
                        );
                    }
                }
            },

            Err(Error::Done | Error::BufferTooShort) => (),

            Err(e) => return Err(e.into()),
        }
    }

    // The skipped data is delivered once packets have room.
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.server
            .streams
            .get(STREAM_ID)
            .ok_or("expected stream is absent")?
            .recv
            .max_off(),
        (1 << 30) + 4096
    );
    Ok(())
}

#[rstest]
fn zero_length_stream_frame_skip_rotates_incremental(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(4_000_000_000);
    config.set_initial_max_stream_data_bidi_local(2_000_000_000);
    config.set_initial_max_stream_data_bidi_remote(2_000_000_000);
    config.set_initial_max_streams_bidi(20);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Stream 64 heads the flushable queue with a 13-byte STREAM header;
    // stream 0 follows with a 5-byte one.
    assert_eq!(pipe.client.stream_send(64, b"", false), Ok(0));
    pipe.client
        .streams
        .get_mut(64)
        .ok_or("expected stream is absent")?
        .send
        .seed_offsets_for_test(1 << 30);

    let data = [0xa; 4096];
    assert_eq!(pipe.client.stream_send(64, &data, false), Ok(4096));
    assert_eq!(pipe.client.stream_send(0, &data, false), Ok(4096));

    // Growing the output buffer one byte at a time first reaches the size
    // where only stream 64's header fits. Skipping it must rotate it behind
    // stream 0, so the first STREAM frame produced is stream 0's, not 64's.
    let mut first_stream_id = None;

    for cap in 25..80 {
        match pipe.client.send(&mut buf[..cap]) {
            Ok((written, _)) => {
                let frames =
                    test_utils::decode_pkt(&pipe.server, &mut buf[..written])?;

                first_stream_id = frames.iter().find_map(|frame| match frame {
                    frame::Frame::Stream { stream_id, .. } => Some(*stream_id),
                    _ => None,
                });

                if first_stream_id.is_some() {
                    break;
                }
            },

            Err(Error::Done | Error::BufferTooShort) => (),

            Err(e) => return Err(e.into()),
        }
    }

    assert_eq!(first_stream_id, Some(0));
    Ok(())
}

#[rstest]
fn flow_control_update(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = initial_flow_control_pipe(cc_algorithm_name)?;

    let frames = [
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"a", 0, false),
        },
    ];

    let pkt_type = Type::Short;

    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    stream_recv_discard(&mut pipe.server, discard, 0)?;
    stream_recv_discard(&mut pipe.server, discard, 4)?;

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"a", 1, false),
    }];

    let len = pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;

    assert!(len > 0);

    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    let mut iter = frames.iter();

    // Ignore ACK.
    iter.next().ok_or("expected another iterator item")?;

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::MaxStreamData {
            stream_id: 0,
            max: 30
        })
    );
    // Initial max_data/window was 30, we consumed/read 16 bytes, which is
    // more than 1/2 the window ==> new max data is 30 + 16
    assert_eq!(iter.next(), Some(&frame::Frame::MaxData { max: 46 }));
    Ok(())
}

#[rstest]
/// Tests that flow control is properly updated even when a stream is shut
/// down.
fn flow_control_drain(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_536];

    let mut config = transport_config(cc_algorithm_name)?;
    // Set large initial max_data so we don't have to deal with MAX_DATA
    // or STREAM_MAX_DATA frames
    config.set_initial_max_data(15_000);
    config.set_initial_max_stream_data_bidi_local(15_000);
    config.set_initial_max_stream_data_bidi_remote(15_000);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_idle_timeout(180_000);
    config.verify_peer(false);
    config.set_ack_delay_exponent(8);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client opens a stream and sends some data.
    assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));
    // And also sends on a different stream
    assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.client.stream_send(8, b"aaaaa", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server receives data, without reading it.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), Some(8));
    assert_eq!(r.next(), None);

    // check flow control accounting
    assert_eq!(pipe.server.rx_data, 20);
    assert_eq!(pipe.server.flow_control.consumed(), 0);

    // Helper function that sends STREAM frames to the server on stream 4
    let mut send_frame_helper =
        |pipe: &mut test_utils::Pipe, data: RangeBuf| -> Result<()> {
            let frames = [frame::Frame::Stream { stream_id: 4, data }];
            let written = test_utils::encode_pkt(
                &mut pipe.client,
                Type::Short,
                &frames,
                &mut buf,
            )?;
            assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));
            Ok(())
        };

    // Client sends more data on stream 4, but with a gap.
    // server now has [0..5] and [10..15]
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 5], 10, false))?;

    // check flow control accounting
    assert_eq!(pipe.server.rx_data, 30);
    assert_eq!(pipe.server.flow_control.consumed(), 0);

    // Server shuts down one stream. We do not advance the pipe
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Read, 42), Ok(()));

    // check flow control accounting
    // 15 bytes have been consumed, since that was the highest offset we have
    // received.
    assert_eq!(pipe.server.flow_control.consumed(), 15);
    assert_eq!(pipe.server.rx_data, 30);

    // client sends frame that partially closes the gap
    // now we have [0..8] and [10..15]
    // verify flow control. Should be no change.
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 3], 5, false))?;
    assert_eq!(pipe.server.rx_data, 30);
    assert_eq!(pipe.server.flow_control.consumed(), 15);

    // client sends partially overlapping data and partially new data
    // now we have [0..8] and [10..20]
    // verify flow control. we should account for an additional 5 bytes
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 10], 10, false))?;
    assert_eq!(pipe.server.rx_data, 35);
    assert_eq!(pipe.server.flow_control.consumed(), 20);

    // client sends a fin, but again with a gap
    // this should add another 5 bytes to flow control
    send_frame_helper(&mut pipe, RangeBuf::from(&[0; 0], 25, true))?;
    assert_eq!(pipe.server.rx_data, 40);
    assert_eq!(pipe.server.flow_control.consumed(), 25);
    Ok(())
}

#[rstest]
/// Tests that flow control is properly updated when a stream receives a RESET
fn flow_control_reset_stream(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values("reset", "fin")] inconsistent_final_size_frame: &str,
) -> TestResult {
    let mut buf = vec![0; 65_536];

    let mut config = transport_config(cc_algorithm_name)?;
    // Set large initial max_data so we don't have to deal with MAX_DATA
    // or STREAM_MAX_DATA frames
    config.set_initial_max_data(15_000);
    config.set_initial_max_stream_data_bidi_local(15_000);
    config.set_initial_max_stream_data_bidi_remote(15_000);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_idle_timeout(180_000);
    config.verify_peer(false);
    config.set_ack_delay_exponent(8);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client opens a stream and sends some data.
    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server receives data, without reading it.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    // check flow control accounting
    assert_eq!(pipe.server.rx_data, 5);
    assert_eq!(pipe.server.flow_control.consumed(), 0);

    // Helper function that sends STREAM frames to the server on stream 0
    let send_frame_helper =
        |pipe: &mut test_utils::Pipe, data: RangeBuf| -> Result<()> {
            let mut buf = vec![0; 65_536];
            let frames = [frame::Frame::Stream { stream_id: 0, data }];
            let written = test_utils::encode_pkt(
                &mut pipe.client,
                Type::Short,
                &frames,
                &mut buf,
            )?;
            assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));
            Ok(())
        };

    // Client sends more data on stream 4, but with a gap.
    // server now has [0..5] and [10..15]
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 5], 10, false))?;

    // check flow control accounting
    assert_eq!(pipe.server.rx_data, 15);
    assert_eq!(pipe.server.flow_control.consumed(), 0);

    // Client sends a RESET_STREAM with final size 20
    let frames = [frame::Frame::ResetStream {
        stream_id: 0,
        final_size: 20,
        error_code: 42,
    }];
    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)?;
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    // check flow control accounting
    // 20 bytes have been consumed, since that was the final_size
    assert_eq!(pipe.server.flow_control.consumed(), 20);
    assert_eq!(pipe.server.rx_data, 20);

    // client sends more frames, some overlap, some new data
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 3], 5, false))?;
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 7], 10, false))?;
    send_frame_helper(&mut pipe, RangeBuf::from(&[1; 3], 5, false))?;

    // no change in flow control
    assert_eq!(pipe.server.flow_control.consumed(), 20);
    assert_eq!(pipe.server.rx_data, 20);

    // Send the RESET again. Nothing happens
    let frames = [frame::Frame::ResetStream {
        stream_id: 0,
        final_size: 20,
        error_code: 42,
    }];
    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)?;
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    // no change in flow control
    assert_eq!(pipe.server.flow_control.consumed(), 20);
    assert_eq!(pipe.server.rx_data, 20);

    if inconsistent_final_size_frame == "reset" {
        // send another reset with inconsistent final size
        // Send the RESET again. Nothing happens
        let frames = [frame::Frame::ResetStream {
            stream_id: 0,
            final_size: 42,
            error_code: 42,
        }];
        let written = test_utils::encode_pkt(
            &mut pipe.client,
            Type::Short,
            &frames,
            &mut buf,
        )?;
        assert_eq!(pipe.server_recv(&mut buf[..written]), Err(Error::FinalSize));
    } else if inconsistent_final_size_frame == "fin" {
        let frames = [frame::Frame::Stream {
            stream_id: 0,
            data: RangeBuf::from(&[], 42, true),
        }];
        let written = test_utils::encode_pkt(
            &mut pipe.client,
            Type::Short,
            &frames,
            &mut buf,
        )?;
        assert_eq!(pipe.server_recv(&mut buf[..written]), Err(Error::FinalSize));
    } else {
        return Err(format!(
            "unexpected final-size scenario: {inconsistent_final_size_frame}"
        )
        .into());
    }
    Ok(())
}

#[rstest]
fn stream_flow_control_limit_bidi(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"aaaaaaaaaaaaaaaa", 0, true),
    }];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::FlowControl),
    );
    Ok(())
}

#[rstest]
fn stream_flow_control_limit_uni(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::Stream {
        stream_id: 2,
        data: <RangeBuf>::from(b"aaaaaaaaaaa", 0, true),
    }];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::FlowControl),
    );
    Ok(())
}

#[rstest]
fn stream_flow_control_update(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"aaaaaaaaa", 0, false),
    }];

    let pkt_type = Type::Short;

    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    stream_recv_discard(&mut pipe.server, discard, 4)?;

    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"a", 9, false),
    }];

    let len = pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;

    assert!(len > 0);

    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    let mut iter = frames.iter();

    // Ignore ACK.
    iter.next().ok_or("expected another iterator item")?;

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::MaxStreamData {
            stream_id: 4,
            max: 24,
        })
    );
    Ok(())
}

#[rstest]
fn stream_left(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] uni: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let remaining = |c: &Connection| {
        if uni {
            c.peer_streams_left_uni()
        } else {
            c.peer_streams_left_bidi()
        }
    };
    assert_eq!(remaining(&pipe.client), 3);
    assert_eq!(remaining(&pipe.server), 3);

    for i in 0..3 {
        let id = 4 * i + if uni { 3 } else { 1 };
        assert_eq!(pipe.server.stream_send(id, b"a", false), Ok(1));
        assert_eq!(remaining(&pipe.server), 2 - i);
    }

    let frame = if uni {
        frame::Frame::MaxStreams {
            direction: Unidirectional,
            max: MAX_STREAM_COUNT,
        }
    } else {
        frame::Frame::MaxStreams {
            direction: Bidirectional,
            max: MAX_STREAM_COUNT,
        }
    };
    assert!(pipe
        .send_pkt_to_server(Type::Short, &[frame], &mut buf)
        .is_ok());
    assert_eq!(remaining(&pipe.server), MAX_STREAM_COUNT - 3);
    Ok(())
}

#[rstest]
fn stream_limit(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] uni: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = std::array::from_fn::<_, 7, _>(|i| frame::Frame::Stream {
        stream_id: if uni {
            2 + 4 * i as u64
        } else {
            4 + 4 * i as u64
        },
        data: <RangeBuf>::from(b"a", 0, false),
    });
    assert_eq!(
        pipe.send_pkt_to_server(Type::Short, &frames, &mut buf),
        Err(Error::StreamLimit),
    );
    Ok(())
}

#[rstest]
fn stream_count_frame_bounds(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] uni: bool, #[values(false, true)] blocked: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let make_frame = |count| match (uni, blocked) {
        (false, false) => frame::Frame::MaxStreams {
            direction: Bidirectional,
            max: count,
        },
        (true, false) => frame::Frame::MaxStreams {
            direction: Unidirectional,
            max: count,
        },
        (false, true) => frame::Frame::StreamsBlocked {
            direction: Bidirectional,
            limit: count,
        },
        (true, true) => frame::Frame::StreamsBlocked {
            direction: Unidirectional,
            limit: count,
        },
    };
    assert!(pipe
        .send_pkt_to_server(
            Type::Short,
            &[make_frame(MAX_STREAM_COUNT)],
            &mut buf
        )
        .is_ok());
    assert_eq!(
        pipe.send_pkt_to_server(
            Type::Short,
            &[make_frame(MAX_STREAM_COUNT + 1)],
            &mut buf
        ),
        Err(Error::InvalidFrame),
    );
    Ok(())
}

#[rstest]
fn stream_left_reset_bidi(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(3, pipe.client.peer_streams_left_bidi());
    assert_eq!(3, pipe.server.peer_streams_left_bidi());

    pipe.client.stream_send(0, b"a", false).ok();
    assert_eq!(2, pipe.client.peer_streams_left_bidi());
    pipe.client.stream_send(4, b"a", false).ok();
    assert_eq!(1, pipe.client.peer_streams_left_bidi());
    pipe.client.stream_send(8, b"a", false).ok();
    assert_eq!(0, pipe.client.peer_streams_left_bidi());

    // Client resets the stream.
    pipe.client.stream_shutdown(0, Shutdown::Write, 1001)?;
    pipe.advance()?;

    assert_eq!(0, pipe.client.peer_streams_left_bidi());
    let mut r = pipe.server.readable();
    assert_eq!(Some(0), r.next());
    assert_eq!(Some(4), r.next());
    assert_eq!(Some(8), r.next());
    assert_eq!(None, r.next());

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 0),
        Err(Error::StreamReset(1001))
    );

    let mut r = pipe.server.readable();
    assert_eq!(Some(4), r.next());
    assert_eq!(Some(8), r.next());
    assert_eq!(None, r.next());

    // Server resets the stream in reaction.
    pipe.server.stream_shutdown(0, Shutdown::Write, 1001)?;
    pipe.advance()?;

    assert_eq!(1, pipe.client.peer_streams_left_bidi());

    // Repeat for the other 2 streams
    pipe.client.stream_shutdown(4, Shutdown::Write, 1001)?;
    pipe.client.stream_shutdown(8, Shutdown::Write, 1001)?;
    pipe.advance()?;

    let mut r = pipe.server.readable();
    assert_eq!(Some(4), r.next());
    assert_eq!(Some(8), r.next());
    assert_eq!(None, r.next());

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 4),
        Err(Error::StreamReset(1001))
    );

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 8),
        Err(Error::StreamReset(1001))
    );

    let mut r = pipe.server.readable();
    assert_eq!(None, r.next());

    pipe.server.stream_shutdown(4, Shutdown::Write, 1001)?;
    pipe.server.stream_shutdown(8, Shutdown::Write, 1001)?;
    pipe.advance()?;

    assert_eq!(3, pipe.client.peer_streams_left_bidi());
    Ok(())
}

fn stream_stats_pipe(cc_algorithm_name: &str) -> TestResult<test_utils::Pipe> {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    pipe.handshake()?;
    for id in [0, 2, 4, 8] {
        assert_eq!(pipe.client.stream_send(id, b"a", false), Ok(1));
    }
    pipe.advance()?;
    assert_eq!(pipe.client.stats().reset_stream_count_local, 0);
    Ok(pipe)
}

#[rstest]
fn stream_reset_counts(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = stream_stats_pipe(cc_algorithm_name)?;

    // Client resets the stream.
    pipe.client.stream_shutdown(0, Shutdown::Write, 1001)?;
    pipe.advance()?;

    let stats = pipe.client.stats();
    assert_eq!(stats.reset_stream_count_local, 1);
    assert_eq!(stats.reset_stream_count_remote, 0);
    let stats = pipe.server.stats();
    assert_eq!(stats.reset_stream_count_local, 0);
    assert_eq!(stats.reset_stream_count_remote, 1);

    // Server resets the stream in reaction.
    pipe.server.stream_shutdown(0, Shutdown::Write, 1001)?;
    pipe.advance()?;

    let stats = pipe.client.stats();
    assert_eq!(stats.reset_stream_count_local, 1);
    assert_eq!(stats.reset_stream_count_remote, 1);
    let stats = pipe.server.stats();
    assert_eq!(stats.reset_stream_count_local, 1);
    assert_eq!(stats.reset_stream_count_remote, 1);

    // Repeat for the other streams
    pipe.client.stream_shutdown(2, Shutdown::Write, 1001)?;
    pipe.client.stream_shutdown(4, Shutdown::Write, 1001)?;
    pipe.client.stream_shutdown(8, Shutdown::Write, 1001)?;
    pipe.advance()?;

    pipe.server.stream_shutdown(4, Shutdown::Write, 1001)?;
    pipe.server.stream_shutdown(8, Shutdown::Write, 1001)?;
    pipe.advance()?;

    let stats = pipe.client.stats();
    assert_eq!(stats.reset_stream_count_local, 4);
    assert_eq!(stats.reset_stream_count_remote, 3);
    let stats = pipe.server.stats();
    assert_eq!(stats.reset_stream_count_local, 3);
    assert_eq!(stats.reset_stream_count_remote, 4);
    Ok(())
}

#[rstest]
fn stream_stop_counts(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = stream_stats_pipe(cc_algorithm_name)?;

    // Server stops the stream and client automatically resets.
    pipe.server.stream_shutdown(0, Shutdown::Read, 1001)?;
    pipe.advance()?;

    let stats = pipe.client.stats();
    assert_eq!(stats.stopped_stream_count_local, 0);
    assert_eq!(stats.stopped_stream_count_remote, 1);
    assert_eq!(stats.reset_stream_count_local, 1);
    assert_eq!(stats.reset_stream_count_remote, 0);

    let stats = pipe.server.stats();
    assert_eq!(stats.stopped_stream_count_local, 1);
    assert_eq!(stats.stopped_stream_count_remote, 0);
    assert_eq!(stats.reset_stream_count_local, 0);
    assert_eq!(stats.reset_stream_count_remote, 1);

    // Repeat for the other streams
    pipe.server.stream_shutdown(2, Shutdown::Read, 1001)?;
    pipe.server.stream_shutdown(4, Shutdown::Read, 1001)?;
    pipe.server.stream_shutdown(8, Shutdown::Read, 1001)?;
    pipe.advance()?;

    let stats = pipe.client.stats();
    assert_eq!(stats.stopped_stream_count_local, 0);
    assert_eq!(stats.stopped_stream_count_remote, 4);
    assert_eq!(stats.reset_stream_count_local, 4);
    assert_eq!(stats.reset_stream_count_remote, 0);

    let stats = pipe.server.stats();
    assert_eq!(stats.stopped_stream_count_local, 4);
    assert_eq!(stats.stopped_stream_count_remote, 0);
    assert_eq!(stats.reset_stream_count_local, 0);
    assert_eq!(stats.reset_stream_count_remote, 4);
    Ok(())
}

#[rstest]
fn streams_blocked_stat(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(Bidirectional, Unidirectional)] direction: StreamDirection,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));
    for direction in StreamDirection::ALL {
        assert_eq!(pipe.server.streams.quota(direction).blocked_received, 0);
        assert_eq!(pipe.client.streams.quota(direction).blocked_received, 0);
    }

    let frames = [frame::Frame::StreamsBlocked {
        direction,
        limit: MAX_STREAM_COUNT,
    }];
    for received in 1..=2 {
        pipe.send_pkt_to_server(Type::Short, &frames, &mut buf)?;
        for other in StreamDirection::ALL {
            assert_eq!(
                pipe.server.streams.quota(other).blocked_received,
                if other == direction { received } else { 0 },
            );
            assert_eq!(pipe.client.streams.quota(other).blocked_received, 0);
        }
    }
    Ok(())
}

/// Opening past a peer limit arms one notice; only a new limit rearms it.
#[rstest]
fn streams_blocked_sent(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] enabled: bool,
    #[values(Bidirectional, Unidirectional)] direction: StreamDirection,
) -> TestResult {
    let mut config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    config.set_enable_send_streams_blocked(enabled);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));
    let id = |ordinal: u64| ordinal * 4 + 2 * direction.wire_bit();
    for ordinal in 0..3 {
        assert_eq!(pipe.client.stream_send(id(ordinal), b"a", false), Ok(1));
    }
    assert_eq!(
        pipe.client.stream_send(id(3), b"a", false),
        Err(Error::StreamLimit)
    );
    assert_eq!(
        pipe.client.streams.quota(direction).pending_blocked_limit(),
        enabled.then_some(3)
    );
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        pipe.client.streams.quota(direction).pending_blocked_limit(),
        None
    );
    assert_eq!(
        pipe.server.streams.quota(direction).blocked_received,
        u64::from(enabled)
    );

    assert_eq!(
        pipe.client.stream_send(id(3), b"a", false),
        Err(Error::StreamLimit)
    );
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        pipe.client.streams.quota(direction).pending_blocked_limit(),
        None
    );
    assert_eq!(
        pipe.server.streams.quota(direction).blocked_received,
        u64::from(enabled)
    );

    // Raise only the client's view of the peer limit. The server still
    // rejects the newly opened stream, after consuming the blocked notice.
    pipe.client
        .streams
        .quota_mut(direction)
        .update_peer_limit(4);
    assert_eq!(pipe.client.stream_send(id(3), b"a", false), Ok(1));
    assert_eq!(
        pipe.client.stream_send(id(4), b"a", false),
        Err(Error::StreamLimit)
    );
    assert_eq!(
        pipe.client.streams.quota(direction).pending_blocked_limit(),
        enabled.then_some(4)
    );
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    assert_eq!(
        test_utils::process_flight(&mut pipe.server, flight),
        Err(Error::StreamLimit)
    );
    assert_eq!(
        pipe.server.streams.quota(direction).blocked_received,
        2 * u64::from(enabled)
    );
    assert_eq!(
        pipe.client.streams.quota(direction).pending_blocked_limit(),
        None
    );
    Ok(())
}

/// ACK-based loss detection rearms the most recently sent blocked limit.
#[rstest]
fn streams_blocked_retransmit(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(Bidirectional, Unidirectional)] direction: StreamDirection,
) -> Result<()> {
    let mut buf = vec![0; 65_535];
    let mut config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    config.set_enable_send_streams_blocked(true);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));
    let id = |ordinal: u64| ordinal * 4 + 2 * direction.wire_bit();
    for ordinal in 0..3 {
        assert_eq!(pipe.client.stream_send(id(ordinal), b"a", false), Ok(1));
    }
    assert_eq!(
        pipe.client.stream_send(id(3), b"a", false),
        Err(Error::StreamLimit)
    );
    assert_eq!(
        pipe.client.streams.quota(direction).pending_blocked_limit(),
        Some(3)
    );

    // Drop the first flight and force ACK-based loss detection.
    assert!(test_utils::emit_flight(&mut pipe.client).is_ok());
    assert_eq!(
        pipe.client.streams.quota(direction).pending_blocked_limit(),
        None
    );
    assert_eq!(pipe.server.streams.quota(direction).blocked_received, 0);
    test_utils::trigger_ack_based_loss(&mut pipe.client, &mut pipe.server)?;
    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(
        pipe.client.streams.quota(direction).pending_blocked_limit(),
        None
    );
    assert_eq!(pipe.server.streams.quota(direction).blocked_received, 0);
    pipe.server_recv(&mut buf[..len])?;
    assert_eq!(pipe.server.streams.quota(direction).blocked_received, 1);
    Ok(())
}

#[rstest]
fn stream_data_overlap(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool, #[values(false, true)] reordered: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let mut frames = [
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaa", 0, false),
        },
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"bbbbb", 3, false),
        },
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"ccccc", 6, false),
        },
    ];

    if reordered {
        frames.swap(1, 2);
    }
    let pkt_type = Type::Short;
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    if discard {
        pipe.server.stream_discard(0, 11)?;
    } else {
        let mut b = [0; 15];
        assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((11, false)));
        assert_eq!(
            &b[..11],
            if reordered {
                b"aaaaabccccc"
            } else {
                b"aaaaabbbccc"
            }
        );
    }
    assert_eq!(pipe.server.flow_control.consumed(), pipe.server.rx_data);
    Ok(())
}

#[rstest]
/// A reset notifies the application and consumes the complete final size,
/// whether all bytes arrived or only a prefix.
fn reset_stream_data_final_size(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool, #[values(1, 5)] arrived: usize,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data.
    assert_eq!(
        pipe.client.stream_send(0, &b"hello"[..arrived], false),
        Ok(arrived)
    );
    assert_eq!(pipe.advance(), Ok(()));

    // Server gets data and sends data back, closing stream.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 0),
        Ok((arrived, false))
    );

    assert!(!pipe.server.stream_finished(0));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_send(0, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);
    assert_eq!(
        stream_recv_discard(&mut pipe.client, discard, 0),
        Ok((0, true))
    );

    assert!(pipe.client.stream_finished(0));

    // Client sends RESET_STREAM, closing stream.
    let frames = [frame::Frame::ResetStream {
        stream_id: 0,
        error_code: 42,
        final_size: 5,
    }];

    let pkt_type = Type::Short;
    // The server response carries an ACK. Its encoded size is not stable: the
    // optimistic-ACK defense intentionally skips packet numbers, which can add
    // another ACK range. This test cares about RESET_STREAM semantics, not the
    // exact ACK encoding length.
    assert!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf).is_ok());

    // Server is notified of stream readability, due to reset.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 0),
        Err(Error::StreamReset(42))
    );

    assert!(pipe.server.stream_finished(0));

    // Sending RESET_STREAM again shouldn't make stream readable again.
    pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.flow_control.consumed(), pipe.server.rx_data);
    assert_eq!(pipe.server.flow_control.consumed(), 5);
    Ok(())
}

#[rstest]
/// Tests that `RESET_STREAM` frames exceeding the connection-level flow
/// control limit cause an error.
fn reset_stream_flow_control(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(&[1; 15], 0, false),
        },
        frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::ResetStream {
            stream_id: 4,
            error_code: 0,
            final_size: 15,
        },
        frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(b"a", 0, false),
        },
    ];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::FlowControl),
    );
    Ok(())
}

#[rstest]
/// Tests that `RESET_STREAM` frames exceeding the stream-level flow control
/// limit cause an error.
fn reset_stream_flow_control_stream(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [
        frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"a", 0, false),
        },
        frame::Frame::ResetStream {
            stream_id: 4,
            error_code: 0,
            final_size: 16, // Past stream's flow control limit.
        },
    ];

    let pkt_type = Type::Short;
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::FlowControl),
    );
    Ok(())
}

#[rstest]
fn path_challenge(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::PathChallenge { data: [0xba; 8] }];

    let pkt_type = Type::Short;

    let len = pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;

    assert_eq!(len, MIN_CLIENT_INITIAL_LEN);

    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    let mut iter = frames.iter();

    // Ignore ACK.
    iter.next().ok_or("expected another iterator item")?;

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::PathResponse { data: [0xba; 8] })
    );
    assert!(matches!(iter.next(), Some(&frame::Frame::Padding { .. })));
    Ok(())
}

#[rstest]
/// Simulates reception of an early 1-RTT packet on the server, by
/// delaying the client's Handshake packet that completes the handshake.
fn early_1rtt_packet(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    // Client sends initial flight
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    // Server sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;

    // Client sends Handshake packet.
    let flight = test_utils::emit_flight(&mut pipe.client)?;

    // Emulate handshake packet delay by not making server process client
    // packet.
    let delayed = flight;

    test_utils::emit_flight(&mut pipe.server).ok();

    assert!(pipe.client.is_established());

    // Send 1-RTT packet #0.
    let frames = [frame::Frame::Stream {
        stream_id: 0,
        data: <RangeBuf>::from(b"hello, world", 0, true),
    }];

    let pkt_type = Type::Short;
    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)?;

    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    // Send 1-RTT packet #1.
    let frames = [frame::Frame::Stream {
        stream_id: 4,
        data: <RangeBuf>::from(b"hello, world", 0, true),
    }];

    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)?;

    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    assert!(!pipe.server.is_established());

    // Client sent 1-RTT packets 0 and 1, but server hasn't received them.
    // Neither has been authenticated yet.
    assert_eq!(
        pipe.server.pkt_num_spaces[packet::Epoch::Application].largest_rx_pkt_num,
        None
    );

    // Process delayed packet.
    test_utils::process_flight(&mut pipe.server, delayed)?;

    assert!(pipe.server.is_established());

    assert_eq!(
        pipe.server.pkt_num_spaces[packet::Epoch::Application].largest_rx_pkt_num,
        None
    );
    Ok(())
}

#[rstest]
fn packet_number_exhaustion_closes_without_sending_close_frame(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    pipe.handshake()?;
    let max = octets::MAX_VAR_INT;
    pipe.client.next_pkt_num = max;
    let sent = pipe.client.counters.sent_count;
    let mut out = [0x5a; 1500];
    assert!(matches!(pipe.client.send(&mut out), Err(Error::Done)));
    assert!(pipe.client.is_closed());
    assert!(pipe.client.local_error().is_none());
    assert_eq!(pipe.client.counters.sent_count, sent);
    assert_eq!(out, [0x5a; 1500]);
    Ok(())
}

#[rstest]
fn packet_number_width_uses_connection_space_ack_history(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    pipe.handshake()?;
    let epoch = packet::Epoch::Application;
    // The connection-wide acknowledgment is newer than the path's local
    // recovery state (as when a fresh path is selected).
    let base = 1_u64 << 40;
    pipe.client.pkt_num_spaces[epoch].largest_acked_pkt_num = Some(base);
    pipe.client.next_pkt_num = base + 1;
    pipe.server.pkt_num_spaces[epoch].largest_rx_pkt_num = Some(base);
    pipe.client.stream_send(0, b"packet number", true)?;
    let mut out = [0; 1500];
    let (len, _) = pipe.client.send(&mut out)?;
    assert_eq!(pipe.server_recv(&mut out[..len]), Ok(len));
    let mut received = [0; 32];
    assert_eq!(pipe.server.stream_recv(0, &mut received), Ok((13, true)));
    assert_eq!(&received[..13], b"packet number");
    Ok(())
}

fn receive_client_fin(
    pipe: &mut test_utils::Pipe, discard: bool, stream: u64,
) -> TestResult {
    assert_eq!(pipe.client.stream_send(stream, b"hello", true), Ok(5));
    pipe.advance()?;
    assert_eq!(pipe.server.readable().collect::<Vec<_>>(), [stream]);
    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, stream),
        Ok((5, true))
    );
    assert!(pipe.server.stream_finished(stream));
    assert_eq!(pipe.server.readable().next(), None);
    Ok(())
}

fn send_stop_and_expect_reset(
    pipe: &mut test_utils::Pipe, stream: u64, final_size: u64, buf: &mut [u8],
) -> TestResult {
    let frames = [frame::Frame::StopSending {
        stream_id: stream,
        error_code: 42,
    }];
    let len = pipe.send_pkt_to_server(Type::Short, &frames, buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    assert!(
        matches!(frames.first(), Some(frame::Frame::Ack { .. })),
        "expected ACK: {frames:?}"
    );
    assert_eq!(
        frames.get(1),
        Some(&frame::Frame::ResetStream {
            stream_id: stream,
            error_code: 42,
            final_size
        })
    );
    Ok(())
}

fn fill_response_until_blocked(
    pipe: &mut test_utils::Pipe, flush: bool,
) -> TestResult {
    loop {
        match pipe.server.stream_send(0, b"world", false) {
            Ok(written) => {
                assert!(written > 0);
                if flush {
                    pipe.advance()?;
                }
            },
            Err(Error::Done) => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn blocked_response_pipe(
    cc_algorithm_name: &str, discard: bool, flush: bool, buf: &mut [u8],
) -> TestResult<test_utils::Pipe> {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    receive_client_fin(&mut pipe, discard, 0)?;

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    fill_response_until_blocked(&mut pipe, flush)?;

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), None);

    send_stop_and_expect_reset(&mut pipe, 0, if flush { 15 } else { 0 }, buf)?;
    Ok(pipe)
}

fn consume_stopped_stream(pipe: &mut test_utils::Pipe) {
    assert_eq!(pipe.server.writable().collect::<Vec<_>>(), [0]);
    assert_eq!(
        pipe.server.stream_send(0, b"world", true),
        Err(Error::StreamStopped(42))
    );
    assert_eq!(pipe.server.streams.len(), 0);
}

#[rstest]
fn stop_sending(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe =
        blocked_response_pipe(cc_algorithm_name, discard, true, &mut buf)?;
    let pkt_type = Type::Short;

    consume_stopped_stream(&mut pipe);

    // Client acks RESET_STREAM frame.
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(pipe.server.next_pkt_num - 5..pipe.server.next_pkt_num);

    let frames = [frame::Frame::Ack {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];

    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(0));

    assert_duplicate_stop_only_acks(&mut pipe, &mut buf)
}

#[rstest]
fn stop_sending_fin(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    receive_client_fin(&mut pipe, discard, 4)?;

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_send(4, b"world", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // ...and buffers more, and closes stream.
    assert_eq!(pipe.server.stream_send(4, b"world", true), Ok(5));

    // Client sends STOP_SENDING before server flushes stream.
    let frames = [frame::Frame::StopSending {
        stream_id: 4,
        error_code: 42,
    }];

    let pkt_type = Type::Short;
    let len = pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;

    // Server sent a RESET_STREAM frame in response.
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ResetStream {
            stream_id: 4,
            error_code: 42,
            final_size: 5,
        })
    );

    // No more frames are sent by the server.
    assert_eq!(iter.next(), None);

    let max_streams = pipe.server.streams.quota(Bidirectional).next_local_limit();
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Write, 42), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));
    assert!(pipe.server.streams.is_collected(4));
    assert_eq!(
        pipe.server.streams.quota(Bidirectional).next_local_limit(),
        max_streams + 1
    );
    Ok(())
}

#[rstest]
/// A completed receive side must not discard an unreported STOP error.
fn stop_sending_recv_completion_preserves_unreported_error(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
    #[values(true, false)] stop_first: bool,
    #[values("data_fin", "empty_fin", "reset")] receive_end: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let stop = frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    };
    let receive = match receive_end {
        "data_fin" => frame::Frame::Stream {
            stream_id: 0,
            data: RangeBuf::from(b"req", 0, true),
        },

        "empty_fin" => frame::Frame::Stream {
            stream_id: 0,
            data: RangeBuf::from(b"", 0, true),
        },

        "reset" => frame::Frame::ResetStream {
            stream_id: 0,
            error_code: 77,
            final_size: 0,
        },

        _ => unreachable!(),
    };
    let frames = if stop_first {
        [stop, receive]
    } else {
        [receive, stop]
    };
    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)?;
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    let expected = match receive_end {
        "data_fin" => Ok((3, true)),
        "empty_fin" => Ok((0, true)),
        "reset" => Err(Error::StreamReset(77)),
        _ => unreachable!(),
    };
    assert_eq!(stream_recv_discard(&mut pipe.server, discard, 0), expected);
    assert_eq!(pipe.server.streams.len(), 1);
    let max_streams = pipe.server.streams.quota(Bidirectional).next_local_limit();

    assert_eq!(
        pipe.server.stream_capacity(0),
        Err(Error::StreamStopped(42))
    );
    assert_eq!(pipe.server.streams.len(), 0);
    assert!(pipe.server.streams.is_collected(0));
    assert_eq!(
        pipe.server.streams.quota(Bidirectional).next_local_limit(),
        max_streams + 1
    );
    Ok(())
}

/// The first FIN on previously consumed data must be delivered before
/// collecting a stopped stream. Repeating the FIN must not reopen it.
#[rstest]
fn stop_sending_late_fin_collects_after_notification(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));
    assert_eq!(pipe.client.stream_send(0, b"req", false), Ok(3));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.server.stream_recv(0, &mut buf), Ok((3, false)));

    assert_eq!(pipe.client.stream_shutdown(0, Shutdown::Read, 42), Ok(()));
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;
    assert_eq!(
        pipe.server.stream_capacity(0),
        Err(Error::StreamStopped(42))
    );
    assert_eq!(pipe.advance(), Ok(()));
    assert!(!pipe.server.stream_readable(0));
    assert_eq!(pipe.server.writable().next(), None);
    let max_streams = pipe.server.streams.quota(Bidirectional).next_local_limit();

    // Only the data is duplicate. This is the first FIN; the application
    // must observe the terminal event independently of the send-side STOP.
    let frames = [frame::Frame::Stream {
        stream_id: 0,
        data: RangeBuf::from(b"req", 0, true),
    }];
    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)?;
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    assert!(pipe.server.stream_finished(0));
    assert!(pipe.server.stream_readable(0));
    assert!(!pipe.server.streams.is_collected(0));
    assert_eq!(pipe.server.stream_recv(0, &mut []), Ok((0, true)));
    assert!(!pipe.server.stream_readable(0));
    assert_eq!(pipe.server.writable().next(), None);
    assert!(pipe.server.streams.is_collected(0));
    assert_eq!(
        pipe.server.streams.quota(Bidirectional).next_local_limit(),
        max_streams + 1
    );

    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)?;
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));
    assert!(!pipe.server.stream_readable(0));
    assert!(pipe.server.streams.is_collected(0));
    assert_eq!(
        pipe.server.streams.quota(Bidirectional).next_local_limit(),
        max_streams + 1
    );
    Ok(())
}

/// Read-side completion collects completed streams without dropping queued
/// FINs.
#[rstest]
fn stream_shutdown_read_collects_completed_streams(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(
        "fin_before_shutdown",
        "fin_after_shutdown",
        "reset_after_shutdown"
    )]
    receive_end: &str,
    #[values("stopped", "fin_acked", "fin_queued")] send_end: &str,
) -> TestResult {
    let fin_before_shutdown = receive_end == "fin_before_shutdown";
    let collected = send_end != "fin_queued";
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.stream_send(0, b"req", fin_before_shutdown),
        Ok(3)
    );
    assert_eq!(pipe.advance(), Ok(()));

    if send_end == "stopped" {
        assert_eq!(pipe.client.stream_shutdown(0, Shutdown::Read, 42), Ok(()));
        let flight = test_utils::emit_flight(&mut pipe.client)?;
        test_utils::process_flight(&mut pipe.server, flight)?;
        assert_eq!(
            pipe.server.stream_capacity(0),
            Err(Error::StreamStopped(42))
        );

        // ACK the reset while the request remains unread.
        assert_eq!(pipe.advance(), Ok(()));
    } else {
        let fin_acked = send_end == "fin_acked";
        assert_eq!(pipe.server.stream_send(0, b"rsp", fin_acked), Ok(3));
        assert_eq!(pipe.advance(), Ok(()));
        assert_eq!(pipe.client.stream_recv(0, &mut [0; 3]), Ok((3, fin_acked)));

        if !fin_acked {
            // Queue FIN after its preceding data was ACKed, but do not send it
            // yet.
            assert_eq!(pipe.server.stream_send(0, b"", true), Ok(0));
        }
    }

    assert!(pipe.server.stream_readable(0));
    let max_streams = pipe.server.streams.quota(Bidirectional).next_local_limit();

    assert_eq!(pipe.server.stream_shutdown(0, Shutdown::Read, 77), Ok(()));
    match receive_end {
        "fin_before_shutdown" => (),

        "fin_after_shutdown" => {
            assert_eq!(pipe.client.stream_send(0, b"", true), Ok(0));
        },

        "reset_after_shutdown" => {
            assert_eq!(
                pipe.client.stream_shutdown(0, Shutdown::Write, 77),
                Ok(())
            );
        },

        _ => unreachable!(),
    }

    if !fin_before_shutdown {
        assert!(!pipe.server.streams.is_collected(0));
        assert_eq!(
            pipe.server.streams.quota(Bidirectional).next_local_limit(),
            max_streams
        );

        let flight = test_utils::emit_flight(&mut pipe.client)?;
        test_utils::process_flight(&mut pipe.server, flight)?;
    }

    assert_eq!(pipe.server.streams.is_collected(0), collected);
    assert_eq!(
        pipe.server.streams.quota(Bidirectional).next_local_limit(),
        max_streams + u64::from(collected)
    );

    if !collected {
        let flight = test_utils::emit_flight(&mut pipe.server)?;
        test_utils::process_flight(&mut pipe.client, flight)?;
        assert_eq!(pipe.client.stream_recv(0, &mut []), Ok((0, true)));
        assert_eq!(pipe.advance(), Ok(()));
        assert!(pipe.server.streams.is_collected(0));
        assert_eq!(
            pipe.server.streams.quota(Bidirectional).next_local_limit(),
            max_streams + 1
        );
    }
    Ok(())
}

#[rstest]
/// A stopped stream remains writable when the peer grants no send credit.
fn stop_sending_writable_with_no_connection_capacity(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut client_config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    client_config.set_initial_max_data(0);
    let mut server_config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"req", false), Ok(3));
    assert_eq!(pipe.client.stream_send(4, b"req", false), Ok(3));
    assert_eq!(pipe.client.stream_send(8, b"req", false), Ok(3));
    assert_eq!(pipe.advance(), Ok(()));

    let stop = [
        frame::Frame::StopSending {
            stream_id: 0,
            error_code: 42,
        },
        frame::Frame::StopSending {
            stream_id: 8,
            error_code: 43,
        },
    ];
    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &stop, &mut buf)?;
    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));
    assert_eq!(pipe.server.stream_priority(0, 42, false), Ok(()));
    assert_eq!(pipe.server.stream_priority(8, 10, false), Ok(()));

    assert_eq!(pipe.server.stream_capacity(4), Ok(0));

    assert_eq!(pipe.server.writable().collect::<Vec<_>>(), vec![8, 0]);
    assert_eq!(pipe.server.stream_writable_next(), Some(8));
    assert_eq!(pipe.server.writable().collect::<Vec<_>>(), vec![0]);
    assert_eq!(pipe.server.stream_writable_next(), Some(0));
    assert_eq!(pipe.server.stream_writable_next(), None);
    assert_eq!(pipe.server.writable().next(), None);
    assert_eq!(
        pipe.server.stream_capacity(0),
        Err(Error::StreamStopped(42))
    );
    assert_eq!(
        pipe.server.stream_capacity(8),
        Err(Error::StreamStopped(43))
    );
    Ok(())
}

#[rstest]
/// A peer can stop a local stream opened implicitly by a higher stream ID.
fn stop_sending_implicitly_opened_local_stream(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(0, 2)] stream_id: u64,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.stream_send(stream_id + 4, b"data", false),
        Ok(4)
    );
    assert!(pipe.client.streams.get(stream_id).is_none());

    let stop = [frame::Frame::StopSending {
        stream_id,
        error_code: 42,
    }];
    let written =
        test_utils::encode_pkt(&mut pipe.server, Type::Short, &stop, &mut buf)?;
    assert_eq!(pipe.client_recv(&mut buf[..written]), Ok(written));
    assert_eq!(
        pipe.client.stream_capacity(stream_id),
        Err(Error::StreamStopped(42))
    );

    if stream_id == 2 {
        assert!(pipe.client.streams.is_collected(stream_id));
        let written = test_utils::encode_pkt(
            &mut pipe.server,
            Type::Short,
            &stop,
            &mut buf,
        )?;
        assert_eq!(pipe.client_recv(&mut buf[..written]), Ok(written));
        assert!(pipe.client.streams.is_collected(stream_id));
    } else {
        assert!(pipe.client.streams.get(stream_id).is_some());
    }
    Ok(())
}

#[rstest]
/// Peer frames may reference local streams without an existing Stream object.
fn peer_frames_on_implicitly_opened_local_streams(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"a", false), Ok(1));
    assert_eq!(pipe.client.stream_send(6, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));
    assert!([0, 2, 4]
        .iter()
        .all(|&id| pipe.client.streams.get(id).is_none()));

    let frames = [
        frame::Frame::Stream {
            stream_id: 0,
            data: RangeBuf::from(b"response", 0, false),
        },
        frame::Frame::ResetStream {
            stream_id: 4,
            error_code: 77,
            final_size: 0,
        },
        frame::Frame::MaxStreamData {
            stream_id: 2,
            max: 1024,
        },
    ];
    let written =
        test_utils::encode_pkt(&mut pipe.server, Type::Short, &frames, &mut buf)?;
    assert_eq!(pipe.client_recv(&mut buf[..written]), Ok(written));

    assert_eq!(pipe.client.stream_recv(0, &mut buf), Ok((8, false)));
    assert_eq!(
        pipe.client.stream_recv(4, &mut buf),
        Err(Error::StreamReset(77))
    );
    assert_eq!(
        pipe.client
            .streams
            .get(2)
            .ok_or("expected stream is absent")?
            .send
            .cap(),
        Ok(1024)
    );
    Ok(())
}

#[rstest]
/// Peer frames cannot open a local stream beyond those opened by the app.
fn stop_sending_unopened_local_stream_rejected(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(2, 8)] stream_id: u64,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"data", false), Ok(4));

    let stop = [frame::Frame::StopSending {
        stream_id,
        error_code: 42,
    }];
    let written =
        test_utils::encode_pkt(&mut pipe.server, Type::Short, &stop, &mut buf)?;
    assert_eq!(
        pipe.client_recv(&mut buf[..written]),
        Err(Error::InvalidStreamState(stream_id))
    );
    assert!(pipe.client.streams.get(stream_id).is_none());
    Ok(())
}

fn exhausted_send_credit(
    cc_algorithm_name: &str, discard: bool,
) -> TestResult<test_utils::Pipe> {
    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(15);
    config.set_initial_max_stream_data_bidi_local(30);
    config.set_initial_max_stream_data_bidi_remote(30);
    config.set_initial_max_stream_data_uni(30);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data.
    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 4),
        Ok((5, true))
    );

    // Server sends some data.
    assert_eq!(pipe.server.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server buffers some data, until send capacity limit reached.
    assert_eq!(pipe.server.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(pipe.server.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(
        pipe.server.stream_send(4, b"hello", false),
        Err(Error::Done)
    );

    Ok(pipe)
}

fn assert_reclaimed_send_credit(pipe: &mut test_utils::Pipe) -> TestResult {
    assert_eq!(pipe.client.stream_send(8, b"hello", true), Ok(5));
    pipe.advance()?;
    for _ in 0..2 {
        assert_eq!(pipe.server.stream_send(8, b"hello", false), Ok(5));
    }
    assert_eq!(
        pipe.server.stream_send(8, b"hello", false),
        Err(Error::Done)
    );
    pipe.advance()?;
    Ok(())
}

#[rstest]
/// Tests that resetting a stream restores flow control for unsent data.
fn stop_sending_unsent_tx_cap(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = exhausted_send_credit(cc_algorithm_name, discard)?;

    // Client sends STOP_SENDING.
    let frames = [frame::Frame::StopSending {
        stream_id: 4,
        error_code: 42,
    }];

    let pkt_type = Type::Short;
    pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;

    assert_reclaimed_send_credit(&mut pipe)?;
    Ok(())
}

fn acknowledge_reset_before_application(
    pipe: &mut test_utils::Pipe, buf: &mut [u8],
) -> TestResult {
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(pipe.server.next_pkt_num - 5..pipe.server.next_pkt_num);
    let frames = [frame::Frame::Ack {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];
    assert_eq!(pipe.send_pkt_to_server(Type::Short, &frames, buf), Ok(0));
    assert_eq!(pipe.server.streams.len(), 1);
    consume_stopped_stream(pipe);
    assert_duplicate_stop_only_acks(pipe, buf)
}

fn assert_duplicate_stop_only_acks(
    pipe: &mut test_utils::Pipe, buf: &mut [u8],
) -> TestResult {
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];
    let len = pipe.send_pkt_to_server(Type::Short, &frames, buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    assert_eq!(frames.len(), 1);
    assert!(
        matches!(frames.first(), Some(frame::Frame::Ack { .. })),
        "expected ACK: {frames:?}"
    );
    assert_eq!(pipe.server.writable().next(), None);
    Ok(())
}

#[rstest]
/// Tests that the `StreamStopped` error is propagated even if the
/// `RESET_STREAM` in response to `STOP_SENDING` is acked before the application
/// processes writable streams.
fn stop_sending_ack_race(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe =
        blocked_response_pipe(cc_algorithm_name, discard, true, &mut buf)?;

    acknowledge_reset_before_application(&mut pipe, &mut buf)?;
    Ok(())
}

#[rstest]
/// Tests that the `StreamStopped` error is propagated even if a STREAM frame
/// is acked before the application processes writable streams.
fn stop_sending_stream_ack_race(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    receive_client_fin(&mut pipe, discard, 0)?;

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_send(0, b"world", true), Ok(5));

    // Client receives STREAM frame but doesn't ack yet.
    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;

    send_stop_and_expect_reset(&mut pipe, 0, 5, &mut buf)?;

    acknowledge_reset_before_application(&mut pipe, &mut buf)?;
    Ok(())
}

fn finish_shutdown_read(pipe: &mut test_utils::Pipe, discard: bool) {
    // Server sends some data, without reading the incoming data, and closes
    // the stream.
    assert_eq!(pipe.server.stream_send(4, b"hello, world", true), Ok(12));
    assert_eq!(pipe.advance(), Ok(()));

    // Client reads the data.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(
        stream_recv_discard(&mut pipe.client, discard, 4),
        Ok((12, true))
    );

    // Stream is collected on both sides.
    assert_eq!(pipe.client.streams.len(), 0);
    assert_eq!(pipe.server.streams.len(), 0);
    assert_eq!(pipe.client.flow_control.consumed(), pipe.client.rx_data);
    assert_eq!(pipe.server.flow_control.consumed(), pipe.server.rx_data);

    assert_eq!(
        pipe.server.stream_shutdown(4, Shutdown::Read, 0),
        Err(Error::Done)
    );
}

#[rstest]
fn stream_shutdown_read(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data.
    assert_eq!(pipe.client.stream_send(4, b"hello, world", false), Ok(12));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.client.streams.len(), 1);
    assert_eq!(pipe.server.streams.len(), 1);

    // Server shuts down stream.
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Read, 42), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    let (len, _) = pipe.server.send(&mut buf)?;

    let mut dummy = buf[..len].to_vec();

    let frames = test_utils::decode_pkt(&pipe.client, &mut dummy[..len])?;
    // make sure the pkt contains the expected StopSending frame
    assert!(frames.iter().any(|f| {
        *f == frame::Frame::StopSending {
            stream_id: 4,
            error_code: 42,
        }
    }));

    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    assert_eq!(pipe.advance(), Ok(()));

    // Sending more data is forbidden.
    let mut r = pipe.client.writable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(
        pipe.client.stream_send(4, b"bye", false),
        Err(Error::StreamStopped(42))
    );
    assert_eq!(pipe.client.streams.len(), 1);
    assert!(!pipe.client.writable().any(|id| id == 4));

    // A duplicate STOP must not replace the reported code or rearm readiness.
    pipe.server.streams.insert_stopped(4, 99);
    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;
    assert_eq!(
        pipe.client.stream_capacity(4),
        Err(Error::StreamStopped(42))
    );
    assert!(!pipe.client.writable().any(|id| id == 4));

    finish_shutdown_read(&mut pipe, discard);
    Ok(())
}

#[rstest]
fn stream_shutdown_read_after_fin(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data and a FIN.
    assert_eq!(pipe.client.stream_send(4, b"hello, world123", true), Ok(15));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.client.streams.len(), 1);
    assert_eq!(pipe.server.streams.len(), 1);

    // Server shuts down stream.
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Read, 42), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Server does NOT send STOP_SENDING frame, since it has already received a
    // FIN from the client.
    assert_eq!(pipe.server.send(&mut buf), Err(Error::Done));

    assert_eq!(pipe.advance(), Ok(()));

    finish_shutdown_read(&mut pipe, discard);
    Ok(())
}

fn shutdown_credit_pipe(
    cc_algorithm_name: &str, discard: bool,
) -> TestResult<test_utils::Pipe> {
    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(10000);
    config.set_initial_max_stream_data_bidi_remote(10000);
    config.set_initial_max_streams_bidi(10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 0),
        Ok((1, false))
    );

    Ok(pipe)
}

#[rstest]
fn stream_shutdown_read_update_max_data(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let buf = vec![0; 65_535];

    let mut pipe = shutdown_credit_pipe(cc_algorithm_name, discard)?;

    // The client sends data that the server does not read before shutting down
    // the read direction.
    assert_eq!(pipe.client.stream_send(0, &buf[0..20], false), Ok(20));
    assert_eq!(pipe.advance(), Ok(()));

    // The server received 21 bytes but consumed only one.
    assert_eq!(pipe.server.rx_data, 21);
    assert_eq!(pipe.server.flow_control.consumed(), 1);

    assert_eq!(pipe.client.stream_send(0, &buf, false), Ok(9));
    // The connection-level flow-control limit has been reached.
    assert_eq!(pipe.client.stream_send(0, &[0], false), Err(Error::Done));
    assert_eq!(pipe.client.stream_send(4, &[0], false), Err(Error::Done));

    // Shutting down the read side returns buffered data to the flow-control
    // budget. The client limit is unchanged until the pipe advances.
    assert_eq!(pipe.server.stream_shutdown(0, Shutdown::Read, 123), Ok(()));

    assert!(!pipe.server.stream_readable(0)); // Nothing can be consumed.

    assert_eq!(pipe.server.rx_data, 21);
    // All bytes in the read buffer have been marked as consumed.
    assert_eq!(pipe.server.flow_control.consumed(), 21);
    assert_eq!(pipe.client.tx_data, 30);
    assert_eq!(pipe.client.max_tx_data, 30);

    // Client is still blocked
    assert_eq!(pipe.client.stream_send(0, &[0], false), Err(Error::Done));
    assert_eq!(pipe.client.stream_send(4, &[0], false), Err(Error::Done));

    // Send a flight of packet from server -> client. We only send in this
    // direction so ensure that the server sends a MAX_DATA frame on its own,
    // if we advance the pipe, the client would respond with RESET and that
    // would increase the window
    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;

    // The client has dropped the 9 unset bytes in its buffer
    assert_eq!(pipe.client.tx_data, 21);
    // The 21 consumed bytes have been added on the client
    assert_eq!(pipe.client.max_tx_data, 30 + 21);
    // ... and the client can send again
    assert_eq!(pipe.client.stream_send(4, &[0], false), Ok(1));

    // Server side is unchanged
    assert_eq!(pipe.server.rx_data, 21);
    assert_eq!(pipe.server.flow_control.consumed(), 21);

    assert_eq!(
        pipe.client.stream_send(0, b"hello, world", false),
        Err(Error::StreamStopped(123))
    );

    // fully advance pipe
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.tx_data, 22);
    assert_eq!(pipe.server.rx_data, 22);
    assert!(!pipe.server.stream_readable(0)); // nothing can be consumed

    // Server sends fin to fully close the stream.
    assert_eq!(pipe.server.stream_send(0, &[], true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        stream_recv_discard(&mut pipe.client, discard, 0),
        Ok((0, true))
    );

    assert!(pipe.server.streams.is_collected(0));
    assert!(pipe.client.streams.is_collected(0));
    Ok(())
}

/// Tests that sending a reset should drop the receive buffer on the peer and
/// return flow control credit.
#[rstest]
fn stream_shutdown_write_update_max_data(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut pipe = shutdown_credit_pipe(cc_algorithm_name, discard)?;

    // Client sends data until blocked that the server does not read
    while pipe.client.stream_send(0, b"world", false) != Err(Error::Done) {
        assert_eq!(pipe.advance(), Ok(()));
    }
    // sending on a different stream is blocked by flow control
    assert_eq!(pipe.client.stream_send(4, b"a", false), Err(Error::Done));
    assert_eq!(pipe.client.max_tx_data, 30);
    assert_eq!(pipe.client.tx_data, 30);

    // Server has received 30 bytes, but only 1 has been read/consumed
    assert_eq!(pipe.server.rx_data, 30);
    assert_eq!(pipe.server.flow_control.consumed(), 1);

    // The client shuts down its write and sends a reset
    assert_eq!(pipe.client.stream_shutdown(0, Shutdown::Write, 42), Ok(()));
    pipe.advance()?;

    // Receiving the reset drops the receive buffer and returns flow control
    // credit
    assert_eq!(pipe.server.rx_data, 30);
    assert_eq!(pipe.server.flow_control.consumed(), 30);
    assert_eq!(pipe.client.tx_data, 30);
    // initial window == initial_max_data == 30; consumed == 30
    // ==> new max_tx_data is 60
    assert_eq!(pipe.client.max_tx_data, 60);

    // client can send again on a different stream
    assert_eq!(pipe.client.stream_send(4, b"a", false), Ok(1));
    Ok(())
}

#[rstest]
fn stream_shutdown_uni(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Exchange some data on uni streams.
    assert_eq!(pipe.client.stream_send(2, b"hello, world", false), Ok(10));
    assert_eq!(pipe.server.stream_send(3, b"hello, world", false), Ok(10));
    assert_eq!(pipe.advance(), Ok(()));

    // Test local and remote shutdown.
    assert_eq!(pipe.client.stream_shutdown(2, Shutdown::Write, 42), Ok(()));
    assert_eq!(
        pipe.client.stream_shutdown(2, Shutdown::Read, 42),
        Err(Error::InvalidStreamState(2))
    );

    assert_eq!(
        pipe.client.stream_shutdown(3, Shutdown::Write, 42),
        Err(Error::InvalidStreamState(3))
    );
    assert_eq!(pipe.client.stream_shutdown(3, Shutdown::Read, 42), Ok(()));
    Ok(())
}

#[rstest]
fn stream_shutdown_write(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data.
    assert_eq!(pipe.client.stream_send(4, b"hello, world", false), Ok(12));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.client.streams.len(), 1);
    assert_eq!(pipe.server.streams.len(), 1);

    // Server sends some data.
    assert_eq!(pipe.server.stream_send(4, b"goodbye, world", false), Ok(14));
    assert_eq!(pipe.advance(), Ok(()));

    // Server shuts down stream.
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Write, 42), Ok(()));

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), None);

    let (len, _) = pipe.server.send(&mut buf)?;

    let mut dummy = buf[..len].to_vec();

    let frames = test_utils::decode_pkt(&pipe.client, &mut dummy[..len])?;
    let mut iter = frames.iter();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ResetStream {
            stream_id: 4,
            error_code: 42,
            final_size: 14,
        })
    );

    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    assert_eq!(pipe.advance(), Ok(()));

    // Sending more data is forbidden.
    assert_eq!(
        pipe.server.stream_send(4, b"bye", false),
        Err(Error::FinalSize)
    );

    // Client sends some data and closes the stream.
    assert_eq!(pipe.client.stream_send(4, b"bye", true), Ok(3));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads the data.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 4),
        Ok((15, true))
    );

    // Client processes readable streams.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), None);

    assert_eq!(
        stream_recv_discard(&mut pipe.client, discard, 4),
        Err(Error::StreamReset(42))
    );

    // Stream is collected on both sides.
    assert_eq!(pipe.client.streams.len(), 0);
    assert_eq!(pipe.server.streams.len(), 0);

    assert_eq!(
        pipe.server.stream_shutdown(4, Shutdown::Write, 0),
        Err(Error::Done)
    );
    Ok(())
}

#[rstest]
/// Tests that shutting down a stream restores flow control for unsent data.
fn stream_shutdown_write_unsent_tx_cap(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut pipe = exhausted_send_credit(cc_algorithm_name, discard)?;

    assert_eq!(pipe.server.tx_data, 15);

    // Client shouldn't update flow control.
    assert!(!pipe.client.flow_control.should_update_max_data());

    // Server shuts down stream.
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Write, 42), Ok(()));
    // Unsend data is dropped and returned to flow control credit
    assert_eq!(pipe.server.tx_data, 5);

    assert_reclaimed_send_credit(&mut pipe)?;
    Ok(())
}

#[rstest]
/// Tests that the order of flushable streams scheduled on the wire is the
/// same as the order of `stream_send()` calls done by the application.
fn stream_round_robin(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));

    let (len, _) = pipe.client.send(&mut buf)?;

    let frames = test_utils::decode_pkt(&pipe.server, &mut buf[..len])?;

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(b"aaaaa", 0, false),
        })
    );

    for id in [0, 4] {
        assert_next_packet_frame(
            &mut pipe.client,
            &pipe.server,
            &mut buf,
            &frame::Frame::Stream {
                stream_id: id,
                data: RangeBuf::from(b"aaaaa", 0, false),
            },
        )?;
    }
    Ok(())
}

#[rstest]
/// Tests the readable iterator.
fn stream_readable(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // No readable streams.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), None);

    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));

    let mut r = pipe.client.readable();
    assert_eq!(r.next(), None);

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    assert_eq!(pipe.advance(), Ok(()));

    // Server received stream.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(
        pipe.server.stream_send(0, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    // Client drains stream.
    stream_recv_discard(&mut pipe.client, discard, 0)?;
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.client.readable();
    assert_eq!(r.next(), None);

    // Server shuts down stream.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_shutdown(0, Shutdown::Read, 0), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Client creates multiple streams.
    assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.len(), 2);

    assert!(r.next().is_some());
    assert!(r.next().is_some());
    assert!(r.next().is_none());

    assert_eq!(r.len(), 0);
    Ok(())
}

#[rstest]
/// Tests `stream_readable_len`.
fn stream_readable_len(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Unknown stream has no readable data.
    assert_eq!(pipe.server.stream_readable_len(0, 64 * 1024), 0);

    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server has 5 buffered bytes to read.
    assert_eq!(pipe.server.stream_readable_len(0, 64 * 1024), 5);
    assert_eq!(pipe.server.stream_readable_len(0, 3), 3);

    // Sending more data grows the readable count.
    assert_eq!(pipe.client.stream_send(0, b"bbbbb", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.server.stream_readable_len(0, 64 * 1024), 10);

    // Reading some data shrinks the readable count.
    let mut b = [0; 4];
    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((4, false)));
    assert_eq!(pipe.server.stream_readable_len(0, 64 * 1024), 6);

    // Draining the rest brings it back to 0.
    let mut b = [0; 6];
    assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((6, false)));
    assert_eq!(pipe.server.stream_readable_len(0, 64 * 1024), 0);
    Ok(())
}

#[rstest]
/// Tests the writable iterator.
fn stream_writable(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // No writable streams.
    let mut w = pipe.client.writable();
    assert_eq!(w.next(), None);

    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));

    // Client created stream.
    let mut w = pipe.client.writable();
    assert_eq!(w.next(), Some(0));
    assert_eq!(w.next(), None);

    assert_eq!(pipe.advance(), Ok(()));

    // Server created stream.
    let mut w = pipe.server.writable();
    assert_eq!(w.next(), Some(0));
    assert_eq!(w.next(), None);

    assert_eq!(
        pipe.server.stream_send(0, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );

    // Server stream is full.
    let mut w = pipe.server.writable();
    assert_eq!(w.next(), None);

    assert_eq!(pipe.advance(), Ok(()));

    // Client drains stream.
    stream_recv_discard(&mut pipe.client, discard, 0)?;
    assert_eq!(pipe.advance(), Ok(()));

    // Server stream is writable again.
    let mut w = pipe.server.writable();
    assert_eq!(w.next(), Some(0));
    assert_eq!(w.next(), None);

    // Server shuts down stream.
    assert_eq!(pipe.server.stream_shutdown(0, Shutdown::Write, 0), Ok(()));

    let mut w = pipe.server.writable();
    assert_eq!(w.next(), None);

    // Client creates multiple streams.
    assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    let mut w = pipe.server.writable();
    assert_eq!(w.len(), 2);

    assert!(w.next().is_some());
    assert!(w.next().is_some());
    assert!(w.next().is_none());

    assert_eq!(w.len(), 0);

    // Server finishes stream.
    assert_eq!(pipe.server.stream_send(8, b"aaaaa", true), Ok(5));

    let mut w = pipe.server.writable();
    assert_eq!(w.next(), Some(4));
    assert_eq!(w.next(), None);
    Ok(())
}

#[rstest]
fn stream_writable_blocked(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"h3"])?;
    config.set_initial_max_data(70);
    config.set_initial_max_stream_data_bidi_local(150_000);
    config.set_initial_max_stream_data_bidi_remote(150_000);
    config.set_initial_max_stream_data_uni(150_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(5);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client creates stream and sends some data.
    let send_buf = [0; 35];
    assert_eq!(pipe.client.stream_send(0, &send_buf, false), Ok(35));

    // Stream is still writable as it still has capacity.
    assert_eq!(pipe.client.stream_writable_next(), Some(0));
    assert_eq!(pipe.client.stream_writable_next(), None);

    // Client fills stream, which becomes unwritable due to connection
    // capacity.
    let send_buf = [0; 36];
    assert_eq!(pipe.client.stream_send(0, &send_buf, false), Ok(35));

    assert_eq!(pipe.client.stream_writable_next(), None);

    assert_eq!(pipe.client.tx_cap, 0);

    assert_eq!(pipe.advance(), Ok(()));

    stream_recv_discard(&mut pipe.server, discard, 0)?;

    assert_eq!(pipe.advance(), Ok(()));

    // The connection capacity has increased and the stream is now writable
    // again.
    assert_ne!(pipe.client.tx_cap, 0);

    assert_eq!(pipe.client.stream_writable_next(), Some(0));
    assert_eq!(pipe.client.stream_writable_next(), None);
    Ok(())
}

#[rstest]
/// Tests that we don't exceed the per-connection flow control limit set by
/// the peer.
fn flow_control_limit_send(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.stream_send(0, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        pipe.client.stream_send(4, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.client.stream_send(8, b"a", false), Err(Error::Done));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert!(r.next().is_some());
    assert!(r.next().is_some());
    assert!(r.next().is_none());

    assert_eq!(pipe.server.counters.data_blocked_sent_count, 0);
    assert_eq!(pipe.server.counters.stream_data_blocked_sent_count, 0);
    assert_eq!(pipe.server.counters.data_blocked_recv_count, 1);
    assert_eq!(pipe.server.counters.stream_data_blocked_recv_count, 0);

    assert_eq!(pipe.client.counters.data_blocked_sent_count, 1);
    assert_eq!(pipe.client.counters.stream_data_blocked_sent_count, 0);
    assert_eq!(pipe.client.counters.data_blocked_recv_count, 0);
    assert_eq!(pipe.client.counters.stream_data_blocked_recv_count, 0);
    Ok(())
}

#[rstest]
/// Tests that invalid packets received before any other valid ones cause
/// the server to close the connection immediately.
fn invalid_initial_server(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    let frames = [frame::Frame::Padding { len: 10 }];

    let written = test_utils::encode_pkt(
        &mut pipe.client,
        Type::Initial,
        &frames,
        &mut buf,
    )?;

    // Corrupt the packets's last byte to make decryption fail (the last
    // byte is part of the AEAD tag, so changing it means that the packet
    // cannot be authenticated during decryption).
    buf[written - 1] = !buf[written - 1];

    assert_eq!(pipe.server.timeout(), None);

    assert_eq!(
        pipe.server_recv(&mut buf[..written]),
        Err(Error::CryptoFail)
    );

    assert!(pipe.server.is_closed());
    Ok(())
}

#[rstest]
/// Tests that invalid Initial packets received to cause
/// the client to close the connection immediately.
fn invalid_initial_client(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    // Client sends initial flight.
    let (len, _) = pipe.client.send(&mut buf)?;

    // Server sends initial flight.
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(1200));

    let frames = [frame::Frame::Padding { len: 10 }];

    let written = test_utils::encode_pkt(
        &mut pipe.server,
        Type::Initial,
        &frames,
        &mut buf,
    )?;

    // Corrupt the packets's last byte to make decryption fail (the last
    // byte is part of the AEAD tag, so changing it means that the packet
    // cannot be authenticated during decryption).
    buf[written - 1] = !buf[written - 1];

    // Client will ignore invalid packet.
    assert_eq!(pipe.client_recv(&mut buf[..written]), Ok(71));

    // The connection should be alive...
    assert!(!pipe.client.is_closed());

    // ...and the idle timeout should be armed.
    assert!(pipe.client.idle.deadline.is_some());
    Ok(())
}

#[rstest]
fn invalid_coalesced_initial_does_not_hide_valid_initial(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    let frames = [frame::Frame::Padding { len: 10 }];
    let first = test_utils::encode_pkt(
        &mut pipe.server,
        Type::Initial,
        &frames,
        &mut buf,
    )?;
    buf[first - 1] ^= 0xff;

    let second = test_utils::encode_pkt(
        &mut pipe.server,
        Type::Initial,
        &frames,
        &mut buf[first..],
    )?;

    assert_eq!(pipe.client.counters.recv_count, 0);
    assert_eq!(
        pipe.client_recv(&mut buf[..first + second]),
        Ok(first + second)
    );
    assert_eq!(pipe.client.counters.recv_count, 1);
    assert!(!pipe.client.is_closed());
    Ok(())
}

#[rstest]
/// Tests that packets with invalid payload length received before any other
/// valid packet cause the server to close the connection immediately.
fn invalid_initial_payload(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] exceeds_address_width: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    let mut b = octets::OctetsMut::with_slice(&mut buf);

    let epoch = Type::Initial.to_epoch()?;

    let pn = 0;
    let pn_len = packet::pkt_num_len(pn, None)?;

    let dcid = pipe.client.destination_id();
    let scid = pipe.client.source_id();

    let hdr = Header {
        ty: Type::Initial,
        version: pipe.client.version,
        dcid: ConnectionId::from_ref(dcid.as_ref()),
        scid: ConnectionId::from_ref(scid.as_ref()),
        pkt_num: 0,
        pkt_num_len: pn_len,
        token: pipe.client.initial.token.clone(),
        versions: None,
        key_phase: false,
    };

    hdr.to_bytes(&mut b)?;

    let frames = [frame::Frame::Padding {
        len: MIN_CLIENT_INITIAL_LEN,
    }];
    let payload_len = frames
        .iter()
        .map(frame::Frame::wire_len)
        .sum::<Result<usize>>()?;
    let crypto_ctx = &mut pipe.client.crypto_ctx[epoch];
    let aead = crypto_ctx
        .crypto_seal
        .as_mut()
        .ok_or("packet sealing key missing")?;

    // In the wide case, narrowing the varint to u32 would make it match
    // the exact packet size, including the authentication tag.
    let len = if exceeds_address_width {
        (1_u64 << 32) + (pn_len + payload_len + crypto::TAG_LEN) as u64
    } else {
        (pn_len + 4096) as u64
    };
    b.put_varint(len)?;
    packet::encode_pkt_num(pn, pn_len, &mut b)?;
    let payload_offset = b.off();
    for frame in &frames {
        frame.to_bytes(&mut b)?;
    }

    let written = packet::encrypt_pkt(
        &mut b,
        pn,
        pn_len,
        payload_len,
        payload_offset,
        None,
        aead,
    )?;

    assert_eq!(pipe.server.timeout(), None);

    assert_eq!(
        pipe.server_recv(&mut buf[..written]),
        Err(Error::InvalidPacket)
    );

    assert!(pipe.server.is_closed());
    Ok(())
}

#[rstest]
/// Tests that invalid packets don't cause the connection to be closed.
fn invalid_packet(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = [frame::Frame::Padding { len: 10 }];

    let written =
        test_utils::encode_pkt(&mut pipe.client, Type::Short, &frames, &mut buf)?;

    // Corrupt the packets's last byte to make decryption fail (the last
    // byte is part of the AEAD tag, so changing it means that the packet
    // cannot be authenticated during decryption).
    buf[written - 1] = !buf[written - 1];

    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));

    // Corrupt the packets's first byte to make the header fail decoding.
    buf[0] = 255;

    assert_eq!(pipe.server_recv(&mut buf[..written]), Ok(written));
    Ok(())
}

#[rstest]
fn recv_empty_buffer(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.server_recv(&mut buf[..0]), Err(Error::BufferTooShort));
    Ok(())
}

#[rstest]
fn stop_sending_before_flushed_packets(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe =
        blocked_response_pipe(cc_algorithm_name, discard, false, &mut buf)?;
    let pkt_type = Type::Short;

    consume_stopped_stream(&mut pipe);

    // Client acks RESET_STREAM frame.
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(0..6);

    let frames = [frame::Frame::Ack {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];

    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(0));
    Ok(())
}

#[rstest]
fn reset_before_flushed_packets(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(5);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_streams_bidi(3);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    receive_client_fin(&mut pipe, discard, 0)?;

    let mut r = pipe.server.writable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    assert_eq!(pipe.server.stream_send(0, b"helloworld", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Client reads to give flow control back.
    assert_eq!(
        stream_recv_discard(&mut pipe.client, discard, 0),
        Ok((5, false))
    );
    assert_eq!(pipe.advance(), Ok(()));

    // Server writes stream data and resets the stream before sending a
    // packet.
    assert_eq!(pipe.server.stream_send(0, b"world", false), Ok(5));
    pipe.server.stream_shutdown(0, Shutdown::Write, 42)?;
    assert_eq!(pipe.advance(), Ok(()));

    // Client has ACK'd the RESET_STREAM so the stream is collected.
    assert_eq!(pipe.server.streams.len(), 0);

    assert_eq!(pipe.server.counters.data_blocked_sent_count, 0);
    assert_eq!(pipe.server.counters.stream_data_blocked_sent_count, 1);
    assert_eq!(pipe.server.counters.data_blocked_recv_count, 0);
    assert_eq!(pipe.server.counters.stream_data_blocked_recv_count, 0);

    assert_eq!(pipe.client.counters.data_blocked_sent_count, 0);
    assert_eq!(pipe.client.counters.stream_data_blocked_sent_count, 0);
    assert_eq!(pipe.client.counters.data_blocked_recv_count, 0);
    assert_eq!(pipe.client.counters.stream_data_blocked_recv_count, 1);
    Ok(())
}

#[rstest]
/// Completing streams restores the direction-specific stream-count credit.
fn stream_limit_update(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
    #[values(Bidirectional, Unidirectional)] direction: StreamDirection,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    let bidi = direction == Bidirectional;
    config.set_initial_max_streams_bidi(if bidi { 3 } else { 0 });
    config.set_initial_max_streams_uni(if bidi { 0 } else { 3 });
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    pipe.handshake()?;
    let first = if bidi { 0 } else { 2 };
    let second = first + 4;
    let writes = [
        (first, b"a", false),
        (second, b"a", false),
        (second, b"b", true),
        (first, b"b", true),
    ];
    for (id, data, fin) in writes {
        assert_eq!(pipe.client.stream_send(id, data, fin), Ok(1));
        pipe.advance()?;
    }
    for id in [first, second] {
        assert_eq!(
            stream_recv_discard(&mut pipe.server, discard, id),
            Ok((2, true))
        );
    }
    pipe.advance()?;
    if bidi {
        for (id, data, fin) in writes {
            assert_eq!(pipe.server.stream_send(id, data, fin), Ok(1));
            pipe.advance()?;
        }
    }
    for id in [first + 8, first + 12, first + 16] {
        assert_eq!(pipe.client.stream_send(id, b"a", false), Ok(1));
        pipe.advance()?;
    }
    assert_eq!(
        pipe.client.stream_send(first + 20, b"a", false),
        Err(Error::StreamLimit)
    );
    assert_eq!(pipe.server.readable().len(), 3);
    Ok(())
}

#[rstest]
/// Tests that `MAX_STREAMS` is correctly sent only when available capacity
/// reaches the threshold (50% of initial).
fn max_streams_sent_only_when_at_threshold(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(1000);
    config.set_initial_max_stream_data_bidi_local(100);
    config.set_initial_max_stream_data_bidi_remote(100);
    config.set_initial_max_streams_bidi(6);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let mut buf = [0; 100];

    // Simulate an aged connection by completing ten batches of six streams.
    // Starting at six with a threshold of three raises the next limit to 66.
    for batch in 0..=9 {
        // Client side: send 6 streams with fin
        for i in 0..6 {
            let stream_id = (batch * 6 + i) * 4;
            pipe.client.stream_send(stream_id, b"a", true).ok();
        }
        pipe.advance().ok();

        // Server side: receive and send back with fin
        for i in 0..6 {
            let stream_id = (batch * 6 + i) * 4;
            pipe.server.stream_recv(stream_id, &mut buf).ok();
            pipe.server.stream_send(stream_id, b"a", true).ok();
        }
        pipe.advance().ok();

        // Client side: receive to complete
        for i in 0..6 {
            let stream_id = (batch * 6 + i) * 4;
            pipe.client.stream_recv(stream_id, &mut buf).ok();
        }
        pipe.advance().ok();
    }

    // At this point: next = 66, completed = 60, available = 6
    // Complete 2 more streams → available = 4 (> 3)
    // MAX_STREAMS should NOT be sent
    assert_eq!(
        pipe.server.streams.quota(Bidirectional).next_local_limit(),
        66
    );
    assert_eq!(pipe.client.streams.quota(Bidirectional).peer_available(), 6);
    pipe.client.stream_send(240, b"a", true).ok();
    pipe.client.stream_send(244, b"a", true).ok();
    pipe.advance().ok();

    pipe.server.stream_recv(240, &mut buf).ok();
    pipe.server.stream_recv(244, &mut buf).ok();
    pipe.server.stream_send(240, b"a", true).ok();
    pipe.server.stream_send(244, b"a", true).ok();
    pipe.advance().ok();

    pipe.client.stream_recv(240, &mut buf).ok();
    pipe.client.stream_recv(244, &mut buf).ok();
    pipe.advance().ok();

    // Verify MAX_STREAMS was NOT sent (4 > 3 threshold)
    assert_eq!(pipe.client.streams.quota(Bidirectional).peer_available(), 4);

    // Complete 1 more stream → available = 3 (== 3)
    // MAX_STREAMS should be sent (new limit: 72)
    pipe.client.stream_send(248, b"a", true).ok();
    pipe.advance().ok();

    pipe.server.stream_recv(248, &mut buf).ok();
    pipe.server.stream_send(248, b"a", true).ok();
    pipe.advance().ok();

    pipe.client.stream_recv(248, &mut buf).ok();
    pipe.advance().ok();

    // Verify MAX_STREAMS was sent (limit increased from 66)
    let left_after = pipe.client.streams.quota(Bidirectional).peer_available();
    assert!(
        left_after > 4,
        "MAX_STREAMS should have been sent, expected > 4 streams left, got {left_after}"
    );
    Ok(())
}

#[rstest]
/// Tests that applications maintaining high concurrent stream usage
/// can reliably recreate streams after aging the connection.
///
/// This exercises the feedback scenario: an app that maintains 9 concurrent
/// streams with a limit of 10. After aging the connection, when streams
/// complete, the app should be able to recreate them without starvation.
fn high_utilization_maintains_streams_in_aged_connection(
    #[values("cubic", "bbr2", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(100_000);
    config.set_initial_max_stream_data_bidi_local(10000);
    config.set_initial_max_stream_data_bidi_remote(10000);
    config.set_initial_max_streams_bidi(10);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let mut buf = [0; 100];

    // Age the connection by completing batches of streams
    // Complete 5 batches of 10 streams = 50 total streams
    for batch in 0..5 {
        for i in 0..10 {
            let stream_id = (batch * 10 + i) * 4;

            // Client opens stream and sends data with FIN
            assert_eq!(
                pipe.client.stream_send(stream_id, b"request", true),
                Ok(7)
            );
        }
        assert_eq!(pipe.advance(), Ok(()));

        // Server receives and responds with FIN
        for i in 0..10 {
            let stream_id = (batch * 10 + i) * 4;
            pipe.server.stream_recv(stream_id, &mut buf).ok();
            assert_eq!(
                pipe.server.stream_send(stream_id, b"response", true),
                Ok(8)
            );
        }
        assert_eq!(pipe.advance(), Ok(()));

        // Client receives responses to complete bidirectional exchange
        for i in 0..10 {
            let stream_id = (batch * 10 + i) * 4;
            pipe.client.stream_recv(stream_id, &mut buf).ok();
        }
        assert_eq!(pipe.advance(), Ok(()));
    }

    // Verify connection is aged: server's max should have grown from 10 to 60
    assert_eq!(pipe.server.streams.quota(Bidirectional).local_limit(), 60);
    assert_eq!(
        pipe.server.streams.quota(Bidirectional).next_local_limit(),
        60
    );

    // Now open 9 concurrent streams (high utilization)
    for i in 0..9 {
        let stream_id = (50 + i) * 4; // Continue from stream 50
        assert_eq!(pipe.client.stream_send(stream_id, b"data", false), Ok(4));
    }
    assert_eq!(pipe.advance(), Ok(()));

    // Server receives the 9 streams
    for i in 0..9 {
        let stream_id = (50 + i) * 4;
        pipe.server.stream_recv(stream_id, &mut buf).ok();
    }

    // Check available capacity from client perspective
    let available_before =
        pipe.client.streams.quota(Bidirectional).peer_available();
    assert_eq!(available_before, 1, "Should have 1 stream slot available");

    // Now complete 2 of the 9 active streams (bidirectionally)
    let stream_1 = 50 * 4;
    let stream_2 = 51 * 4;

    // Client sends FIN
    assert_eq!(pipe.client.stream_send(stream_1, b"", true), Ok(0));
    assert_eq!(pipe.client.stream_send(stream_2, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    // Server receives FIN and responds with FIN
    pipe.server.stream_recv(stream_1, &mut buf).ok();
    pipe.server.stream_recv(stream_2, &mut buf).ok();
    assert_eq!(pipe.server.stream_send(stream_1, b"resp", true), Ok(4));
    assert_eq!(pipe.server.stream_send(stream_2, b"resp", true), Ok(4));
    assert_eq!(pipe.advance(), Ok(()));

    // Client receives responses to complete the streams
    pipe.client.stream_recv(stream_1, &mut buf).ok();
    pipe.client.stream_recv(stream_2, &mut buf).ok();
    assert_eq!(pipe.advance(), Ok(()));

    // Verify streams were collected on server side
    assert_eq!(
        pipe.server.streams.quota(Bidirectional).next_local_limit(),
        62,
        "Server should have incremented next by 2"
    );

    // Check the threshold logic with current fix (initial/2 = 5)
    // available = max - peer_opened = 60 - 59 = 1
    // Check: (62 != 60) AND (1 <= 5) → TRUE, should send MAX_STREAMS

    // Verify MAX_STREAMS was sent by checking if client's available increased
    let available_after =
        pipe.client.streams.quota(Bidirectional).peer_available();
    assert!(
        available_after == 3,
        "After completing 2 streams, client should have capacity for at 3 streams \
         (1 original + 2 reclaimed). Got {available_after} available. This indicates MAX_STREAMS was sent."
    );
    Ok(())
}

fn empty_fin_pipe(
    cc_algorithm_name: &str, discard: bool,
) -> TestResult<test_utils::Pipe> {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.stream_send(0, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert!(r.next().is_none());

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 0),
        Ok((15, false))
    );
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends zero-length frame.
    assert_eq!(pipe.client.stream_send(0, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    Ok(pipe)
}

#[rstest]
/// Tests that the stream's fin flag is properly flushed even if there's no
/// data in the buffer, and that the buffer becomes readable on the other
/// side.
fn stream_zero_length_fin(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut pipe = empty_fin_pipe(cc_algorithm_name, discard)?;

    // Stream should be readable on the server after receiving empty fin.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert!(r.next().is_none());

    stream_recv_discard(&mut pipe.server, discard, 0)?;
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends zero-length frame (again).
    assert_eq!(pipe.client.stream_send(0, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    // Stream should _not_ be readable on the server after receiving empty
    // fin, because it was already finished.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);
    Ok(())
}

#[rstest]
/// Tests that the stream's fin flag is properly flushed even if there's no
/// data in the buffer, that the buffer becomes readable on the other
/// side and stays readable even if the stream is fin'd locally.
fn stream_zero_length_fin_deferred_collection(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut pipe = empty_fin_pipe(cc_algorithm_name, discard)?;

    // Server sends zero-length frame.
    assert_eq!(pipe.server.stream_send(0, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    // Stream should be readable on the server after receiving empty fin.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert!(r.next().is_none());

    // Use zero capacity to exercise FIN consumption. stream_recv_discard()
    // always uses a capacity of 65535.
    let fin = if discard {
        pipe.server.stream_discard(0, 0)
    } else {
        pipe.server.stream_recv(0, &mut [])
    };
    assert_eq!(fin, Ok((0, true)));
    assert!(pipe.server.streams.is_collected(0));
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends zero-length frame (again).
    assert_eq!(pipe.client.stream_send(0, b"", true), Ok(0));
    assert_eq!(pipe.advance(), Ok(()));

    // Stream should _not_ be readable on the server after receiving empty
    // fin, because it was already finished.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), None);

    // Stream _is_readable on the client side.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(0));

    stream_recv_discard(&mut pipe.client, discard, 0)?;
    assert_eq!(pipe.advance(), Ok(()));

    // Stream is completed and _is not_ readable.
    let mut r = pipe.client.readable();
    assert_eq!(r.next(), None);
    Ok(())
}

#[rstest]
/// Tests that the stream gets created with `stream_send()` even if there's
/// no data in the buffer and the fin flag is not set.
fn stream_zero_length_non_fin(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"", false), Ok(0));

    // The stream now should have been created.
    assert_eq!(pipe.client.streams.len(), 1);
    assert_eq!(pipe.advance(), Ok(()));

    // Sending an empty non-fin should not change any stream state on the
    // other side.
    let mut r = pipe.server.readable();
    assert!(r.next().is_none());
    Ok(())
}

#[rstest]
/// Tests that completed streams are garbage collected.
fn collect_streams(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.streams.len(), 0);
    assert_eq!(pipe.server.streams.len(), 0);

    assert_eq!(pipe.client.stream_send(0, b"aaaaa", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.client.stream_finished(0));
    assert!(!pipe.server.stream_finished(0));

    assert_eq!(pipe.client.streams.len(), 1);
    assert_eq!(pipe.server.streams.len(), 1);

    stream_recv_discard(&mut pipe.server, discard, 0)?;
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.stream_send(0, b"aaaaa", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.client.stream_finished(0));
    assert!(pipe.server.stream_finished(0));

    assert_eq!(pipe.client.streams.len(), 1);
    assert_eq!(pipe.server.streams.len(), 0);

    stream_recv_discard(&mut pipe.client, discard, 0)?;
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.streams.len(), 0);
    assert_eq!(pipe.server.streams.len(), 0);

    assert!(pipe.client.stream_finished(0));
    assert!(pipe.server.stream_finished(0));

    assert_eq!(pipe.client.stream_send(0, b"", true), Err(Error::Done));

    let frames = [frame::Frame::Stream {
        stream_id: 0,
        data: <RangeBuf>::from(b"aa", 0, false),
    }];

    assert_stream_packet_acknowledged(&mut pipe, &frames, &mut buf)?;
    Ok(())
}

#[test]
fn config_set_cc_algorithm_name() -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;

    assert_eq!(config.set_cc_algorithm_name("reno"), Ok(()));

    // Unknown name.
    assert_eq!(
        config.set_cc_algorithm_name("???"),
        Err(Error::CongestionControl)
    );
    Ok(())
}

#[rstest]
fn peer_cert(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert!(pipe.client.peer_cert().is_none());
    assert!(pipe.client.peer_cert_chain().is_none());
    assert_eq!(pipe.handshake(), Ok(()));
    assert!(pipe.server.peer_cert().is_none());
    assert!(pipe.server.peer_cert_chain().is_none());

    match pipe.client.peer_cert() {
        Some(c) => assert_eq!(c.len(), 753),

        None => return Err("missing server certificate".into()),
    }
    Ok(())
}

#[rstest]
fn peer_cert_chain(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config.load_cert_chain_from_pem_file("examples/cert-big.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;

    let mut pipe = test_utils::Pipe::with_server_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    match pipe.client.peer_cert_chain() {
        Some(c) => {
            assert_eq!(c.len(), 5);
            assert_eq!(pipe.client.peer_cert(), c.first().copied());
        },

        None => return Err("missing server certificate chain".into()),
    }
    Ok(())
}

const TEST_RETRY_TOKEN: &[u8] = b"quiche test retry token";

fn retry_client(
    cc_algorithm_name: &str, buf: &mut [u8],
) -> TestResult<(
    Config,
    test_utils::Pipe,
    ConnectionId<'static>,
    ConnectionId<'static>,
)> {
    let mut config = transport_config(cc_algorithm_name)?;
    let mut pipe = test_utils::Pipe::with_server_config(&mut config)?;

    // Complete the stateless Retry exchange; the next client flight contains
    // the original destination ID relationship and echoed token.
    let (len, _) = pipe.client.send(buf)?;
    let hdr = Header::from_slice(&buf[..len], MAX_CONN_ID_LEN)?;
    let odcid = hdr.dcid.into_owned();
    let (retry_scid, _) = test_utils::create_cid_and_reset_token(MAX_CONN_ID_LEN);
    let len = crate::retry(
        &hdr.scid,
        &odcid,
        &retry_scid,
        TEST_RETRY_TOKEN,
        hdr.version,
        buf,
    )?;
    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));
    Ok((config, pipe, odcid, retry_scid))
}

#[rstest]
fn retry(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] wait_for_pto: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let (mut config, mut pipe, odcid, scid) =
        retry_client(cc_algorithm_name, &mut buf)?;
    let (len, send_info) = pipe.client.send(&mut buf)?;
    let hdr = Header::from_slice(&buf[..len], MAX_CONN_ID_LEN)?;
    assert_eq!(hdr.token.as_deref(), Some(TEST_RETRY_TOKEN));
    pipe.server = accept(
        &scid,
        Some(&odcid),
        test_utils::Pipe::server_addr(),
        send_info.from,
        &mut config,
    )?;
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    if wait_for_pto {
        let timer = pipe.client.timeout().ok_or("connection timer not armed")?;
        std::thread::sleep(timer + Duration::from_millis(1));
        pipe.client.on_timeout();
    }

    assert_eq!(pipe.advance(), Ok(()));
    assert!(pipe.client.is_established());
    assert!(pipe.server.is_established());
    Ok(())
}

#[rstest]
fn retry_original_destination_connection_id_invalid(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] missing: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let (mut config, mut pipe, _, scid) =
        retry_client(cc_algorithm_name, &mut buf)?;
    let client_flight = test_utils::emit_flight(&mut pipe.client)?;
    let invalid = ConnectionId::from_ref(b"bogus value");
    let odcid = (!missing).then_some(&invalid);
    pipe.server = accept(
        &scid,
        odcid,
        test_utils::Pipe::server_addr(),
        client_flight[0].1.from,
        &mut config,
    )?;
    test_utils::process_flight(&mut pipe.server, client_flight)?;
    let flight = test_utils::emit_flight(&mut pipe.server)?;
    assert_eq!(
        test_utils::process_flight(&mut pipe.client, flight),
        Err(Error::InvalidTransportParam)
    );
    Ok(())
}

#[rstest]
fn retry_separate_source_connection_id(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let (mut config, mut pipe, odcid, retry_scid) =
        retry_client(cc_algorithm_name, &mut buf)?;
    let (len, send_info) = pipe.client.send(&mut buf)?;
    let hdr = Header::from_slice(&buf[..len], MAX_CONN_ID_LEN)?;
    assert_eq!(hdr.token.as_deref(), Some(TEST_RETRY_TOKEN));

    let (scid, _) = test_utils::create_cid_and_reset_token(MAX_CONN_ID_LEN);
    let retry_cids = RetryConnectionIds {
        original_destination_cid: &odcid,
        retry_source_cid: &retry_scid,
    };
    pipe.server = accept_with_retry(
        &scid,
        retry_cids,
        test_utils::Pipe::server_addr(),
        send_info.from,
        &mut config,
    )?;
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));
    assert_eq!(pipe.advance(), Ok(()));
    assert!(pipe.client.is_established());
    assert!(pipe.server.is_established());
    Ok(())
}

#[rstest]
fn retry_invalid_source_connection_id(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let (mut config, mut pipe, odcid, scid) =
        retry_client(cc_algorithm_name, &mut buf)?;
    let client_flight = test_utils::emit_flight(&mut pipe.client)?;
    let retry_scid = ConnectionId::from_ref(b"bogus value");
    let retry_cids = RetryConnectionIds {
        original_destination_cid: &odcid,
        retry_source_cid: &retry_scid,
    };
    pipe.server = accept_with_retry(
        &scid,
        retry_cids,
        test_utils::Pipe::server_addr(),
        client_flight[0].1.from,
        &mut config,
    )?;
    test_utils::process_flight(&mut pipe.server, client_flight)?;
    let flight = test_utils::emit_flight(&mut pipe.server)?;
    assert_eq!(
        test_utils::process_flight(&mut pipe.client, flight),
        Err(Error::InvalidTransportParam)
    );
    Ok(())
}

#[rstest]
/// Tests that a zero-length `NEW_TOKEN` frame is detected as an error.
fn zero_length_new_token(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = vec![frame::Frame::NewToken { token: vec![] }];

    let pkt_type = Type::Short;

    let written =
        test_utils::encode_pkt(&mut pipe.server, pkt_type, &frames, &mut buf)?;

    assert_eq!(
        pipe.client_recv(&mut buf[..written]),
        Err(Error::InvalidFrame)
    );
    Ok(())
}

#[rstest]
/// Tests that a `NEW_TOKEN` frame sent by client is detected as an error.
fn client_sent_new_token(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let frames = vec![frame::Frame::NewToken {
        token: vec![1, 2, 3],
    }];

    let pkt_type = Type::Short;

    let pn = pipe.client.next_pkt_num;
    let epoch = packet::Epoch::Application;
    let largest_rx = pipe.server.pkt_num_spaces[epoch].largest_rx_pkt_num;
    let recv_count = pipe.server.counters.recv_count;
    let recv_bytes = pipe.server.counters.recv_bytes;
    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)?;

    assert_eq!(
        pipe.server_recv(&mut buf[..written]),
        Err(Error::InvalidPacket)
    );
    // An authenticated but semantically invalid frame closes the connection,
    // without publishing this packet as successfully received or ackable.
    let space = &pipe.server.pkt_num_spaces[epoch];
    assert_eq!(space.largest_rx_pkt_num, largest_rx);
    assert!(!space.recv_pkt_num.contains(pn));
    assert!(!space.recv_pkt_need_ack.contains(pn));
    assert_eq!(pipe.server.counters.recv_count, recv_count);
    assert_eq!(pipe.server.counters.recv_bytes, recv_bytes);
    assert!(pipe.server.local_error.is_some());
    Ok(())
}

fn check_send(_: &mut impl Send) {}

#[rstest]
fn config_must_be_send(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    check_send(&mut config);
    Ok(())
}

#[rstest]
fn connection_must_be_send(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    check_send(&mut pipe.client);
    Ok(())
}

fn check_sync(_: &mut impl Sync) {}

#[rstest]
fn config_must_be_sync(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    check_sync(&mut config);
    Ok(())
}

#[rstest]
fn connection_must_be_sync(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    check_sync(&mut pipe.client);
    Ok(())
}

#[rstest]
fn data_blocked(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"aaaaaaaaaa", false), Ok(10));
    assert_eq!(pipe.client.blocked_limit, None);
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"aaaaaaaaaa", false), Ok(10));
    assert_eq!(pipe.client.blocked_limit, None);
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"aaaaaaaaaaa", false), Ok(10));
    assert_eq!(pipe.client.blocked_limit, Some(30));

    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(pipe.client.blocked_limit, None);

    let frames = test_utils::decode_pkt(&pipe.server, &mut buf[..len])?;

    let mut iter = frames.iter();

    assert_eq!(iter.next(), Some(&frame::Frame::DataBlocked { limit: 30 }));

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::Stream {
            stream_id: 8,
            data: <RangeBuf>::from(b"aaaaaaaaaa", 0, false),
        })
    );

    assert_eq!(iter.next(), None);
    Ok(())
}

#[rstest]
fn stream_data_blocked_validates_stream_opening_and_direction(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(0, 2, 1, 3, 42)] stream_id: u64,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));
    let frame = frame::Frame::StreamDataBlocked {
        stream_id,
        limit: 0,
    };
    let result = pipe.send_pkt_to_server(Type::Short, &[frame], &mut [0; 1500]);
    match stream_id {
        0 | 2 => {
            assert!(result.is_ok());
            assert!(pipe.server.streams.get(stream_id).is_some());
            assert_eq!(pipe.server.counters.stream_data_blocked_recv_count, 1);
        },
        1 | 3 => assert_eq!(result, Err(Error::InvalidStreamState(stream_id))),
        _ => assert_eq!(result, Err(Error::StreamLimit)),
    }
    Ok(())
}

#[rstest]
fn late_fin_on_consumed_data_is_readable_once(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));
    let mut packet = [0; 1500];
    for (index, fin) in [false, true, true].into_iter().enumerate() {
        let frame = frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"hello", 0, fin),
        };
        assert!(pipe
            .send_pkt_to_server(Type::Short, &[frame], &mut packet)
            .is_ok());
        if !fin {
            assert_eq!(pipe.server.readable().next(), Some(0));
            let mut buf = [0; 5];
            assert_eq!(pipe.server.stream_recv(0, &mut buf), Ok((5, false)));
            assert_eq!(&buf, b"hello");
        } else if index == 1 {
            assert_eq!(pipe.server.readable().next(), Some(0));
            assert_eq!(pipe.server.stream_recv(0, &mut []), Ok((0, true)));
        } else {
            assert_eq!(pipe.server.readable().next(), None);
        }
    }
    assert_eq!(pipe.server.readable().next(), None);
    assert_eq!(pipe.server.stream_recv(0, &mut []), Err(Error::Done));
    assert_eq!(pipe.server.flow_control.consumed(), 5);
    Ok(())
}

#[rstest]
fn reset_after_out_of_order_fin_delivers_error(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));
    let mut packet = [0; 1500];
    let tail = frame::Frame::Stream {
        stream_id: 2,
        data: <RangeBuf>::from(b"tail", 6, true),
    };
    assert!(pipe
        .send_pkt_to_server(Type::Short, &[tail], &mut packet)
        .is_ok());
    assert_eq!(pipe.server.readable().next(), None);
    let reset = frame::Frame::ResetStream {
        stream_id: 2,
        error_code: 42,
        final_size: 10,
    };
    assert!(pipe
        .send_pkt_to_server(Type::Short, &[reset], &mut packet)
        .is_ok());
    assert_eq!(pipe.server.readable().next(), Some(2));
    assert_eq!(
        pipe.server.stream_recv(2, &mut [0; 10]),
        Err(Error::StreamReset(42))
    );
    assert_eq!(pipe.server.readable().next(), None);
    assert_eq!(pipe.server.flow_control.consumed(), 10);
    Ok(())
}

#[rstest]
fn stream_data_blocked(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    assert_eq!(pipe.client.stream_send(0, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    assert_eq!(pipe.client.stream_send(0, b"aaaaaa", false), Ok(5));
    assert_eq!(pipe.client.streams.blocked().len(), 1);

    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    let frames = test_utils::decode_pkt(&pipe.server, &mut buf[..len])?;

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::StreamDataBlocked {
            stream_id: 0,
            limit: 15,
        })
    );

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::Stream {
            stream_id: 0,
            data: <RangeBuf>::from(b"aaaaaaaaaaaaaaa", 0, false),
        })
    );

    assert_eq!(iter.next(), None);

    // Send from another stream, make sure we don't send STREAM_DATA_BLOCKED
    // again.
    assert_eq!(pipe.client.stream_send(4, b"a", false), Ok(1));

    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    let frames = test_utils::decode_pkt(&pipe.server, &mut buf[..len])?;

    let mut iter = frames.iter();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"a", 0, false),
        })
    );

    assert_eq!(iter.next(), None);

    // Send again from blocked stream and make sure it is not marked as
    // blocked again.
    assert_eq!(
        pipe.client.stream_send(0, b"aaaaaa", false),
        Err(Error::Done)
    );
    assert_eq!(pipe.client.streams.blocked().len(), 0);
    assert_eq!(pipe.client.send(&mut buf), Err(Error::Done));
    Ok(())
}

#[rstest]
fn stream_data_blocked_unblocked_flow_control(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.stream_send(0, b"aaaaaaaaaaaaaaah", false),
        Ok(15)
    );
    assert_eq!(pipe.client.streams.blocked().len(), 1);
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    // Send again on blocked stream. It's blocked at the same offset as
    // previously, so it should not be marked as blocked again.
    assert_eq!(pipe.client.stream_send(0, b"h", false), Err(Error::Done));
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    // No matter how many times we try to write stream data tried, no
    // packets containing STREAM_BLOCKED should be emitted.
    assert_eq!(pipe.client.stream_send(0, b"h", false), Err(Error::Done));
    assert_eq!(pipe.client.send(&mut buf), Err(Error::Done));

    assert_eq!(pipe.client.stream_send(0, b"h", false), Err(Error::Done));
    assert_eq!(pipe.client.send(&mut buf), Err(Error::Done));

    assert_eq!(pipe.client.stream_send(0, b"h", false), Err(Error::Done));
    assert_eq!(pipe.client.send(&mut buf), Err(Error::Done));

    // Now read some data at the server to release flow control.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), None);

    if discard {
        pipe.server.stream_discard(0, 10)?;
    } else {
        let mut b = [0; 10];
        assert_eq!(pipe.server.stream_recv(0, &mut b), Ok((10, false)));
        assert_eq!(&b[..10], b"aaaaaaaaaa");
    }
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"hhhhhhhhhh!", false), Ok(10));
    assert_eq!(pipe.client.streams.blocked().len(), 1);

    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(pipe.client.streams.blocked().len(), 0);

    let frames = test_utils::decode_pkt(&pipe.server, &mut buf[..len])?;

    let mut iter = frames.iter();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::StreamDataBlocked {
            stream_id: 0,
            limit: 25,
        })
    );

    // don't care about remaining received frames

    assert_eq!(pipe.client.stream_send(0, b"!", false), Err(Error::Done));
    assert_eq!(pipe.client.streams.blocked().len(), 0);
    assert_eq!(pipe.client.send(&mut buf), Err(Error::Done));
    Ok(())
}

fn app_limited_pipe(
    cc_algorithm_name: &str, discard: bool, peer_udp_limit: usize,
) -> TestResult<test_utils::Pipe> {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(50000);
    config.set_initial_max_stream_data_bidi_remote(50000);
    config.set_max_recv_udp_payload_size(peer_udp_limit);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads stream data.
    stream_recv_discard(&mut pipe.server, discard, 0)?;
    assert_eq!(pipe.advance(), Ok(()));

    Ok(pipe)
}

#[rstest]
fn app_limited_true(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut pipe = app_limited_pipe(cc_algorithm_name, discard, 1200)?;

    // Server sends stream data smaller than cwnd.
    let send_buf = [0; 10000];
    assert_eq!(pipe.server.stream_send(0, &send_buf, false), Ok(10000));
    assert_eq!(pipe.advance(), Ok(()));

    // app_limited should be true because we send less than cwnd.
    assert!(pipe.server.paths.get_active()?.recovery.app_limited());
    Ok(())
}

#[rstest]
fn app_limited_false(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
    #[values(1200, 1405, 1406)] peer_udp_limit: usize,
) -> TestResult {
    let mut pipe = app_limited_pipe(cc_algorithm_name, discard, peer_udp_limit)?;

    // Server sends stream data bigger than cwnd.
    let send_buf1 = vec![0; 20_000];
    assert_eq!(pipe.server.stream_send(0, &send_buf1, false), Ok(12000));

    test_utils::emit_flight(&mut pipe.server).ok();

    // We can't create a new packet header because there is no room by cwnd.
    // app_limited should be false because we can't send more by cwnd.
    assert!(!pipe.server.paths.get_active()?.recovery.app_limited());
    Ok(())
}

#[rstest]
fn tx_cap_factor(#[values(true, false)] discard: bool) -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(12000);
    config.set_initial_max_stream_data_bidi_remote(12000);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    config.set_send_capacity_factor(2.0);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", true), Ok(1));
    assert_eq!(pipe.client.stream_send(4, b"a", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads stream data.
    stream_recv_discard(&mut pipe.server, discard, 0)?;
    assert_eq!(pipe.advance(), Ok(()));

    // Server sends stream data bigger than cwnd.
    let send_buf = vec![0; 50_000];
    assert_eq!(pipe.server.stream_send(0, &send_buf, false), Ok(12000));
    assert_eq!(pipe.server.stream_send(4, &send_buf, false), Ok(12000));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.client.readable();
    assert_eq!(r.next(), Some(0));
    assert_eq!(
        stream_recv_discard(&mut pipe.client, discard, 0),
        Ok((12000, false))
    );

    assert_eq!(r.next(), Some(4));
    assert_eq!(
        stream_recv_discard(&mut pipe.client, discard, 4),
        Ok((12000, false))
    );

    assert_eq!(r.next(), None);
    Ok(())
}

#[rstest]
fn capacity_factor_respects_connection_flow_credit(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(0.5, 1.0, 2.0, f64::MAX)] factor: f64,
) -> TestResult {
    let mut config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_remote(100);
    config.set_initial_max_stream_data_bidi_local(100);
    config.set_send_capacity_factor(factor);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    pipe.handshake()?;
    let accepted = if factor < 1.0 { 15 } else { 30 };
    assert_eq!(pipe.client.stream_send(0, &[42; 40], false), Ok(accepted));
    assert_eq!(pipe.client.tx_data, accepted as u64);
    assert_eq!(pipe.client.stream_capacity(0), Ok(0));
    assert_eq!(pipe.client.stream_send(4, b"x", false), Err(Error::Done));
    assert_eq!(pipe.client.blocked_limit, Some(30));
    pipe.advance()?;
    let mut out = [0; 40];
    assert_eq!(pipe.server.stream_recv(0, &mut out), Ok((accepted, false)));
    assert_eq!(&out[..accepted], &[42; 30][..accepted]);
    assert!(pipe.client.tx_data <= pipe.client.max_tx_data);
    Ok(())
}

fn inflight_reset_pipe(
    cc_algorithm_name: &str, use_stop_sending: bool, discard: bool,
    send_buf: &[u8],
) -> TestResult<test_utils::Pipe> {
    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(120_000);
    config.set_initial_max_stream_data_bidi_remote(120_000);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", true), Ok(1));
    // Send FIN if we want to exercise the case of the client sending
    // STOP_SENDING instead of RESET_STREAM.
    assert_eq!(pipe.client.stream_send(4, b"a", use_stop_sending), Ok(1));
    assert_eq!(pipe.client.stream_send(8, b"a", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads stream data.
    stream_recv_discard(&mut pipe.server, discard, 0)?;
    stream_recv_discard(&mut pipe.server, discard, 4)?;
    stream_recv_discard(&mut pipe.server, discard, 8)?;
    assert_eq!(pipe.advance(), Ok(()));

    // Server sends stream data bigger than cwnd.
    assert_eq!(
        pipe.server.stream_send(4, send_buf, false),
        if cc_algorithm_name == "cubic" {
            Ok(12000)
        } else {
            Ok(15035)
        }
    );
    Ok(pipe)
}

#[rstest]
fn client_rst_stream_while_bytes_in_flight(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] use_stop_sending: bool,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let send_buf = vec![0; 50_000];
    let mut pipe = inflight_reset_pipe(
        cc_algorithm_name,
        use_stop_sending,
        discard,
        &send_buf,
    )?;
    let server_flight = test_utils::emit_flight(&mut pipe.server)?;

    // And generate a stop sending or reset at the client.
    assert_eq!(pipe.client.stream_shutdown(4, Shutdown::Read, 42), Ok(()));
    if !use_stop_sending {
        // Client did not send a FIN on stream 4, shutdown both sides to send a
        // RESET_STREAM.
        assert_eq!(pipe.client.stream_shutdown(4, Shutdown::Write, 42), Ok(()));
    }
    let client_flight = test_utils::emit_flight(&mut pipe.client)?;

    test_utils::process_flight(&mut pipe.server, client_flight)?;
    test_utils::process_flight(&mut pipe.client, server_flight)?;
    assert_eq!(pipe.advance(), Ok(()));

    // tx_buffered goes down to 0 after the reset and acks are
    // processed.  A full cwnd's worth of packets can be sent.
    let expected_cwnd = match cc_algorithm_name {
        "bbr2" | "bbr2_gcongestion" => 30070,
        _ => 24000,
    };

    assert_eq!(pipe.server.streams.tx_buffered(), 0);
    assert_eq!(
        pipe.server.stream_send(8, &send_buf, false),
        Ok(expected_cwnd)
    );
    assert_eq!(pipe.server.streams.tx_buffered(), expected_cwnd as u64);
    assert_eq!(
        pipe.server.paths.get_active()?.recovery.cwnd(),
        expected_cwnd
    );
    assert_eq!(pipe.advance(), Ok(()));
    Ok(())
}

#[rstest]
fn client_rst_stream_while_bytes_in_flight_with_packet_loss(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let send_buf = vec![0; 50_000];
    let mut pipe =
        inflight_reset_pipe(cc_algorithm_name, true, discard, &send_buf)?;
    let mut server_flight = test_utils::emit_flight(&mut pipe.server)?;

    // And generate a STOP_SENDING at the client.
    assert_eq!(pipe.client.stream_shutdown(4, Shutdown::Read, 42), Ok(()));
    let client_flight = test_utils::emit_flight(&mut pipe.client)?;

    // Lose the first packet of the server flight.
    server_flight.remove(0);

    test_utils::process_flight(&mut pipe.server, client_flight)?;
    test_utils::process_flight(&mut pipe.client, server_flight)?;

    assert_eq!(pipe.advance(), Ok(()));

    // tx_buffered goes down to 0 after the reset and acks are
    // processed.  A full cwnd's worth of packets can be sent.
    let expected_cwnd = match cc_algorithm_name {
        "bbr2" | "bbr2_gcongestion" => 28870,
        _ => 8400,
    };

    assert_eq!(pipe.server.streams.tx_buffered(), 0);

    let send_result = pipe.server.stream_send(8, &send_buf, false)?;
    if cc_algorithm_name == "cubic" {
        // cubic adjusts the congestion window downwards due to the
        // lost packet.  The exact send size varies.
        assert!((15_000..17_000).contains(&send_result));
    } else {
        assert_eq!(send_result, expected_cwnd);
    }
    assert_eq!(pipe.server.streams.tx_buffered(), send_result as u64);
    assert_eq!(
        pipe.server.paths.get_active()?.recovery.cwnd(),
        expected_cwnd
    );
    assert_eq!(pipe.advance(), Ok(()));
    Ok(())
}

fn full_client_cwnd_pipe(
    cc_algorithm_name: &str,
) -> TestResult<test_utils::Pipe> {
    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(50000);
    config.set_initial_max_stream_data_bidi_remote(50000);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data bigger than cwnd (it will never arrive to the
    // server).
    let send_buf1 = vec![0; 20_000];
    let send_cap = pipe.client.tx_cap;
    assert!(send_cap < send_buf1.len());
    assert_eq!(pipe.client.stream_send(0, &send_buf1, false), Ok(send_cap));

    let _ = test_utils::emit_flight(&mut pipe.client)?;

    Ok(pipe)
}

#[rstest]
fn sends_ack_only_pkt_when_full_cwnd_and_ack_elicited(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = full_client_cwnd_pipe(cc_algorithm_name)?;

    // Server sends some stream data that will need ACKs.
    assert_eq!(pipe.server.stream_send(1, &[0; 500], false), Ok(500));

    test_utils::process_flight(
        &mut pipe.client,
        test_utils::emit_flight(&mut pipe.server)?,
    )?;

    let mut buf = [0; 2000];

    let ret = pipe.client.send(&mut buf);

    assert_eq!(pipe.client.tx_cap, 0);

    assert!(matches!(ret, Ok((_, _))), "the client should at least send one packet to acknowledge the newly received data");

    let (sent, _) = ret?;

    assert_ne!(sent, 0, "the client should at least send a pure ACK packet");

    let frames = test_utils::decode_pkt(&pipe.server, &mut buf[..sent])?;
    assert_eq!(1, frames.len());
    assert!(
        matches!(frames[0], frame::Frame::Ack { .. }),
        "the packet sent by the client must be an ACK only packet"
    );
    Ok(())
}

/// Like `sends_ack_only_pkt_when_full_cwnd_and_ack_elicited`, but when
/// `ack_eliciting` is explicitly requested.
#[rstest]
fn sends_ack_only_pkt_when_full_cwnd_and_ack_elicited_despite_max_unacknowledging(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = full_client_cwnd_pipe(cc_algorithm_name)?;

    // Client gets PING frames from server, which elicit ACK
    let mut buf = [0; 2000];
    for _ in 0..recovery::MAX_OUTSTANDING_NON_ACK_ELICITING {
        let written = test_utils::encode_pkt(
            &mut pipe.server,
            Type::Short,
            &[frame::Frame::Ping { mtu_probe: None }],
            &mut buf,
        )?;

        pipe.client_recv(&mut buf[..written])?;

        // Client acknowledges despite a full congestion window
        let ret = pipe.client.send(&mut buf);

        assert!(matches!(ret, Ok((_, _))), "the client should at least send one packet to acknowledge the newly received data");

        let (sent, _) = ret?;

        assert_ne!(sent, 0, "the client should at least send a pure ACK packet");

        let frames = test_utils::decode_pkt(&pipe.server, &mut buf[..sent])?;

        assert_eq!(1, frames.len());

        assert!(
            matches!(frames[0], frame::Frame::Ack { .. }),
            "the packet sent by the client must be an ACK only packet"
        );
    }

    // The client shouldn't need to send any more packets after the ACK only
    // packet it just sent.
    assert_eq!(
        pipe.client.send(&mut buf),
        Err(Error::Done),
        "nothing for client to send after ACK-only packet"
    );
    Ok(())
}

#[rstest]
fn reject_ack_for_unsent_packet_number_space(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    let epoch = packet::Epoch::Handshake;
    assert_eq!(pipe.client.pkt_num_spaces[epoch].largest_tx_pkt_num, None);
    assert!(!pipe.client.initial.peer_verified_address);
    let hdr = Header {
        ty: Type::Handshake,
        version: PROTOCOL_VERSION,
        dcid: ConnectionId::default(),
        scid: ConnectionId::default(),
        pkt_num: 0,
        pkt_num_len: 1,
        token: None,
        versions: None,
        key_phase: false,
    };
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(0..1);
    let frame = frame::Frame::Ack {
        ack_delay: 0,
        ranges,
        ecn_counts: None,
    };
    assert_eq!(
        pipe.client
            .process_frame(frame, &hdr, 0, epoch, Instant::now()),
        Err(Error::InvalidAckRange)
    );
    assert!(!pipe.client.initial.peer_verified_address);
    assert_eq!(
        pipe.client
            .paths
            .get_active()?
            .recovery
            .get_largest_acked_on_epoch(epoch),
        None
    );
    Ok(())
}

#[rstest]
fn validate_peer_sent_ack_range(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    config.set_cc_algorithm_name(cc_algorithm_name)?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;

    config.set_initial_max_data(50000);
    config.set_initial_max_stream_data_bidi_local(30);
    config.set_initial_max_stream_data_bidi_remote(30);
    config.set_initial_max_stream_data_uni(30);
    config.set_initial_max_streams_bidi(10);
    config.set_initial_max_streams_uni(10);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    pipe.handshake()?;

    let mut buf = [0; 2000];
    let epoch = packet::Epoch::Application;
    let pkt_type = Type::Short;

    // Elicit client to send an ACK to the server
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    // Expected pkt counts below reflect the post-handshake state. When the
    // ClientHello spans multiple Initial packets (as with post-quantum
    // keyshares), the handshake exchanges one extra packet
    // per side compared to a classical-only handshake.
    let expected_max_active_pkt_sent = 4;
    let recovery = &pipe.server.paths.get_active()?.recovery;
    assert_eq!(
        recovery
            .largest_sent_pkt_num_on_path(epoch)
            .ok_or("path has no transmitted packet")?,
        expected_max_active_pkt_sent
    );
    assert_eq!(
        recovery
            .get_largest_acked_on_epoch(epoch)
            .ok_or("epoch has no acknowledged packet")?,
        4
    );
    assert_eq!(recovery.sent_packets_len(epoch), 0);
    // Verify largest sent on the connection
    assert_eq!(
        pipe.server.pkt_num_spaces[epoch]
            .largest_tx_pkt_num
            .ok_or("packet number space has no transmitted packet")?,
        expected_max_active_pkt_sent
    );

    // Elicit server to send a packet(ACK) by sending it a packet first. This
    // will result in Server sent packets that require an ACK
    let frames = [frame::Frame::Stream {
        stream_id: 0,
        data: <RangeBuf>::from(b"aa", 0, false),
    }];
    pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;
    let recovery = &pipe.server.paths.get_active()?.recovery;
    assert_eq!(
        recovery
            .largest_sent_pkt_num_on_path(epoch)
            .ok_or("path has no transmitted packet")?,
        5
    );
    assert_eq!(
        recovery
            .get_largest_acked_on_epoch(epoch)
            .ok_or("epoch has no acknowledged packet")?,
        4
    );
    assert_eq!(recovery.sent_packets_len(epoch), 1);

    // Send an invalid ACK range to the server and expect server error
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(0..10);
    let frames = [frame::Frame::Ack {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::InvalidAckRange)
    );

    // https://www.rfc-editor.org/rfc/rfc9000#section-13.1
    // An endpoint SHOULD treat receipt of an acknowledgment for a packet it
    // did not send as a connection error of type PROTOCOL_VIOLATION
    assert_eq!(
        pipe.server
            .local_error
            .ok_or("expected local connection error")?
            .error_code,
        WireErrorCode::ProtocolViolation as u64
    );
    Ok(())
}

#[rstest]
fn validate_peer_sent_ack_range_for_multi_path(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1)?;

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse()?;
    let probed_pid =
        usize::try_from(pipe.client.probe_path(client_addr_2, server_addr)?)?;

    // Exchange path challenge/response and establish the second path
    pipe.advance()?;
    assert_eq!(pipe.server.paths.len(), 2);

    let mut buf = [0; 2000];
    let epoch = packet::Epoch::Application;
    let pkt_type = Type::Short;

    // active path. Packet counts include the extra Initial because the
    // ClientHello spans two Initial packets (post-quantum keyshares);
    // see `validate_peer_sent_ack_range` above for details.
    let expected_max_active_pkt_sent = 8;
    let active_path = &pipe.server.paths.get_mut(0)?;
    let p1_recovery = &active_path.recovery;
    assert_eq!(
        p1_recovery
            .largest_sent_pkt_num_on_path(epoch)
            .ok_or("path has no transmitted packet")?,
        expected_max_active_pkt_sent
    );
    assert_eq!(
        p1_recovery
            .get_largest_acked_on_epoch(epoch)
            .ok_or("epoch has no acknowledged packet")?,
        7
    );
    assert_eq!(p1_recovery.sent_packets_len(epoch), 1);

    // non-active path
    let expected_max_second_pkt_sent = 6;
    let second_path = &pipe.server.paths.get_mut(probed_pid)?;
    let p2_recovery = &second_path.recovery;
    assert_eq!(
        p2_recovery
            .largest_sent_pkt_num_on_path(epoch)
            .ok_or("path has no transmitted packet")?,
        expected_max_second_pkt_sent
    );
    assert_eq!(
        p2_recovery
            .get_largest_acked_on_epoch(epoch)
            .ok_or("epoch has no acknowledged packet")?,
        7
    );
    assert_eq!(p2_recovery.sent_packets_len(epoch), 0);

    // Verify largest sent on the connection is the max of the two paths
    let global_max_sent = pipe.server.pkt_num_spaces[epoch]
        .largest_tx_pkt_num
        .ok_or("packet number space has no transmitted packet")?;
    assert_eq!(
        global_max_sent,
        expected_max_active_pkt_sent.max(expected_max_second_pkt_sent)
    );

    // Send a valid ACK range based on the global max.  Range is not inclusive
    // so +1 to include global_max_sent pkt
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(0..global_max_sent + 1);
    let frames = [frame::Frame::Ack {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];
    pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;

    // active path
    let active_path = &pipe.server.paths.get_mut(0)?;
    assert!(active_path.active());
    let p1_recovery = &active_path.recovery;
    assert_eq!(
        p1_recovery
            .largest_sent_pkt_num_on_path(epoch)
            .ok_or("path has no transmitted packet")?,
        8
    );
    assert_eq!(
        p1_recovery
            .get_largest_acked_on_epoch(epoch)
            .ok_or("epoch has no acknowledged packet")?,
        8
    );
    assert_eq!(p1_recovery.sent_packets_len(epoch), 0);

    // non-active path
    let second_path = &pipe.server.paths.get_mut(probed_pid)?;
    let p2_recovery = &second_path.recovery;
    assert_eq!(
        p2_recovery
            .largest_sent_pkt_num_on_path(epoch)
            .ok_or("path has no transmitted packet")?,
        6
    );
    assert_eq!(
        p2_recovery
            .get_largest_acked_on_epoch(epoch)
            .ok_or("epoch has no acknowledged packet")?,
        8
    );
    assert_eq!(p2_recovery.sent_packets_len(epoch), 0);

    // Send a large invalid ACK range to the server. Range is not inclusive so
    // +2 to include a packet greater than global_max_sent pkt
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(0..global_max_sent + 2);
    let frames = [frame::Frame::Ack {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::InvalidAckRange)
    );

    // https://www.rfc-editor.org/rfc/rfc9000#section-13.1
    // An endpoint SHOULD treat receipt of an acknowledgment for a packet it
    // did not send as a connection error of type PROTOCOL_VIOLATION
    assert_eq!(
        pipe.server
            .local_error
            .ok_or("expected local connection error")?
            .error_code,
        WireErrorCode::ProtocolViolation as u64
    );
    Ok(())
}

// Both Client and Server should skip pn to prevent an optimistic ack attack
#[rstest]
fn optimistic_ack_mitigation_via_skip_pn(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    config.set_cc_algorithm_name(cc_algorithm_name)?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(100_0000);
    config.set_initial_max_stream_data_bidi_local(100_000);
    config.set_initial_max_stream_data_bidi_remote(100_000);
    config.set_initial_max_streams_bidi(10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    pipe.handshake()?;

    let mut server_skip_pn = None;
    let mut client_skip_pn = None;
    let buf = [42; 100];
    while server_skip_pn.is_none() || client_skip_pn.is_none() {
        // Server should send some data
        assert_eq!(pipe.server.stream_send(1, &buf, false)?, 100);

        // Advance server tx and client rx
        let flight = test_utils::emit_flight(&mut pipe.server)?;
        test_utils::process_flight(&mut pipe.client, flight)?;

        // Check if server skipped a pn
        let server_num_manager = &pipe.server.pkt_num_manager;
        if let Some(skip_pn) = server_num_manager.skip_pn() {
            server_skip_pn = Some(skip_pn);
        }

        // Advance client tx and server rx
        let flight = test_utils::emit_flight(&mut pipe.client)?;
        test_utils::process_flight(&mut pipe.server, flight)?;

        // Check if client skipped a pn
        let client_num_manager = &pipe.client.pkt_num_manager;
        if let Some(skip_pn) = client_num_manager.skip_pn() {
            client_skip_pn = Some(skip_pn);
        }
    }

    // Confirm both server and client skip pn
    assert!(server_skip_pn.is_some() && client_skip_pn.is_some());
    Ok(())
}

// Connection should validate skip pn to prevent an optimistic ack attack
#[rstest]
fn prevent_optimistic_ack(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    config.set_cc_algorithm_name(cc_algorithm_name)?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(100_0000);
    config.set_initial_max_stream_data_bidi_local(100_000);
    config.set_initial_max_stream_data_bidi_remote(100_000);
    config.set_initial_max_streams_bidi(10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    pipe.handshake()?;

    let mut server_skip_pn = None;
    let buf = [42; 100];
    while server_skip_pn.is_none() {
        // Server should send some data
        pipe.server.stream_send(1, &buf, false)?;

        // Advance server tx and client rx
        let flight = test_utils::emit_flight(&mut pipe.server)?;
        test_utils::process_flight(&mut pipe.client, flight)?;

        // Check if server skipped a pn
        if let Some(skip_pn) = pipe.server.pkt_num_manager.skip_pn() {
            server_skip_pn = Some(skip_pn);
        }
    }

    let pkt_type = Type::Short;
    let mut buf = [0; 2000];

    // Construct an ACK with the skip_pn to send to the server
    let skip_pn =
        server_skip_pn.ok_or("skipped packet number was not generated")?;
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(skip_pn..skip_pn + 1);
    let frames = [frame::Frame::Ack {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];

    // Receiving an ACK for the skip_pn results in an error
    assert_eq!(
        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf),
        Err(Error::OptimisticAckDetected)
    );

    // https://www.rfc-editor.org/rfc/rfc9000#section-13.1
    // An endpoint SHOULD treat receipt of an acknowledgment for a packet it
    // did not send as a connection error of type PROTOCOL_VIOLATION
    assert_eq!(
        pipe.server
            .local_error
            .ok_or("expected local connection error")?
            .error_code,
        WireErrorCode::ProtocolViolation as u64
    );
    Ok(())
}

#[rstest]
fn app_limited_not_changed_on_no_new_frames(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut pipe = app_limited_pipe(cc_algorithm_name, discard, 1200)?;

    // Client's app_limited is true because its bytes-in-flight
    // is much smaller than the current cwnd.
    assert!(pipe.client.paths.get_active()?.recovery.app_limited());

    // Client has no new frames to send - returns Done.
    assert_eq!(test_utils::emit_flight(&mut pipe.client), Err(Error::Done));

    // Client's app_limited should remain the same.
    assert!(pipe.client.paths.get_active()?.recovery.app_limited());
    Ok(())
}

#[rstest]
fn limit_ack_ranges(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let epoch = packet::Epoch::Application;

    assert_eq!(pipe.server.pkt_num_spaces[epoch].recv_pkt_need_ack.len(), 0);

    let frames = [
        frame::Frame::Ping { mtu_probe: None },
        frame::Frame::Padding { len: 3 },
    ];

    let pkt_type = Type::Short;

    let mut last_packet_sent = 0;

    for _ in 0..512 {
        let recv_count = pipe.server.counters.recv_count;

        last_packet_sent = pipe.client.next_pkt_num;

        pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;

        assert_eq!(pipe.server.counters.recv_count, recv_count + 1);

        // Skip packet number.
        pipe.client.next_pkt_num += 1;
    }

    assert_eq!(
        pipe.server.pkt_num_spaces[epoch].recv_pkt_need_ack.len(),
        MAX_ACK_RANGES
    );

    assert_eq!(
        pipe.server.pkt_num_spaces[epoch].recv_pkt_need_ack.first(),
        Some(last_packet_sent - ((MAX_ACK_RANGES as u64) - 1) * 2)
    );

    assert_eq!(
        pipe.server.pkt_num_spaces[epoch].recv_pkt_need_ack.last(),
        Some(last_packet_sent)
    );
    Ok(())
}

fn assert_next_packet_frame(
    sender: &mut Connection, receiver: &Connection, buf: &mut [u8],
    expected: &frame::Frame,
) -> TestResult<usize> {
    let (len, _) = sender.send(buf)?;
    let frames = test_utils::decode_pkt(receiver, &mut buf[..len])?;
    assert_eq!(frames.first(), Some(expected));
    Ok(frames.len())
}

// Packet headers can change size as stream offsets cross varint boundaries.
// Check actual contiguous payload ranges, rather than assuming that one
// application write corresponds to exactly one STREAM frame.
fn assert_priority_stream_chunk(
    pipe: &mut test_utils::Pipe, buf: &mut [u8], id: u64, offset: &mut u64,
) -> TestResult<usize> {
    let (len, _) = pipe.server.send(buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    let Some(frame::Frame::Stream { stream_id, data }) = frames.first() else {
        return Err(format!("expected STREAM {id}, got {frames:?}").into());
    };
    assert_eq!(*stream_id, id);
    assert_eq!(data.off(), *offset);
    assert!(!data.is_empty());
    assert!(!data.fin());
    assert!(data.iter().all(|&byte| byte == b'b'));
    *offset = data.max_off();
    assert!(*offset <= 1500);
    Ok(frames.len())
}

fn open_streams_for_priority(
    pipe: &mut test_utils::Pipe, ids: &[u64],
) -> TestResult {
    for &id in ids {
        assert_eq!(pipe.client.stream_send(id, b"a", false), Ok(1));
        pipe.advance()?;
    }
    Ok(())
}

#[rstest]
/// Tests that streams are correctly scheduled based on their priority.
fn stream_priority(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    // Limit 1-RTT packet size to avoid congestion control interference.
    const MAX_TEST_PACKET_SIZE: usize = 541;

    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(0);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    open_streams_for_priority(&mut pipe, &[0, 4, 8, 12, 16, 20])?;

    let out = [b'b'; 500];

    // Server prioritizes streams as follows:
    //  * Stream 8 and 16 have the same priority but are non-incremental.
    //  * Stream 4, 12 and 20 have the same priority but 20 is non-incremental
    //    and 4 and 12 are incremental.
    //  * Stream 0 is on its own.

    for (id, urgency, incremental) in [
        (0, 255, true),
        (12, 42, true),
        (16, 10, false),
        (4, 42, true),
        (8, 10, false),
        (20, 42, false),
    ] {
        stream_recv_discard(&mut pipe.server, discard, id)?;
        assert_eq!(
            pipe.server.stream_priority(id, urgency, incremental),
            Ok(())
        );
        for _ in 0..3 {
            assert_eq!(pipe.server.stream_send(id, &out, false), Ok(out.len()));
        }
    }

    // Non-incremental streams drain completely; equal-priority
    // incremental streams alternate at each payload offset.
    for ids in [&[8][..], &[16], &[20], &[12, 4], &[0]] {
        let mut offsets = vec![0; ids.len()];
        for _ in 0..3 {
            for (&id, offset) in ids.iter().zip(&mut offsets) {
                assert_priority_stream_chunk(
                    &mut pipe,
                    &mut buf[..MAX_TEST_PACKET_SIZE],
                    id,
                    offset,
                )?;
            }
        }
        assert!(offsets.iter().all(|&offset| offset == 1500));
    }
    assert_eq!(pipe.server.send(&mut buf), Err(Error::Done));
    Ok(())
}

#[rstest]
/// Tests that changing a stream's priority is correctly propagated.
fn stream_reprioritize(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(0);
    config.set_initial_max_streams_bidi(5);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    open_streams_for_priority(&mut pipe, &[0, 4, 8, 12])?;

    stream_recv_discard(&mut pipe.server, discard, 0)?;
    assert_eq!(pipe.server.stream_priority(0, 255, true), Ok(()));
    pipe.server.stream_send(0, b"b", false)?;

    stream_recv_discard(&mut pipe.server, discard, 12)?;
    assert_eq!(pipe.server.stream_priority(12, 42, true), Ok(()));
    pipe.server.stream_send(12, b"b", false)?;

    stream_recv_discard(&mut pipe.server, discard, 8)?;
    assert_eq!(pipe.server.stream_priority(8, 10, true), Ok(()));
    pipe.server.stream_send(8, b"b", false)?;

    stream_recv_discard(&mut pipe.server, discard, 4)?;
    assert_eq!(pipe.server.stream_priority(4, 42, true), Ok(()));
    pipe.server.stream_send(4, b"b", false)?;

    // Stream 0 is re-prioritized!!!
    assert_eq!(pipe.server.stream_priority(0, 20, true), Ok(()));

    for id in [8, 0, 12, 4] {
        assert_next_packet_frame(
            &mut pipe.server,
            &pipe.client,
            &mut buf,
            &frame::Frame::Stream {
                stream_id: id,
                data: RangeBuf::from(b"b", 0, false),
            },
        )?;
    }

    assert_eq!(pipe.server.send(&mut buf), Err(Error::Done));
    Ok(())
}

#[rstest]
/// Tests that streams and datagrams are correctly scheduled.
fn stream_datagram_priority(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    // Limit 1-RTT packet size to avoid congestion control interference.
    const MAX_TEST_PACKET_SIZE: usize = 540;

    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(0);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(0);
    config.enable_dgram(true, 10, 10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    open_streams_for_priority(&mut pipe, &[0, 4])?;

    let out = [b'b'; 500];

    // Server prioritizes Stream 0 and 4 with the same urgency with
    // incremental, meaning the frames should be sent in round-robin
    // fashion. It also sends DATAGRAMS which are always interleaved with
    // STREAM frames. So we'll expect a mix of frame types regardless
    // of the order that the application writes things in.

    stream_recv_discard(&mut pipe.server, discard, 0)?;
    assert_eq!(pipe.server.stream_priority(0, 255, true), Ok(()));
    pipe.server.stream_send(0, &out, false)?;
    pipe.server.stream_send(0, &out, false)?;
    pipe.server.stream_send(0, &out, false)?;

    assert_eq!(pipe.server.stream_priority(4, 255, true), Ok(()));
    pipe.server.stream_send(4, &out, false)?;
    pipe.server.stream_send(4, &out, false)?;
    pipe.server.stream_send(4, &out, false)?;

    for _ in 1..=6 {
        assert_eq!(pipe.server.dgram_send(&out), Ok(()));
    }

    let mut offsets = [0; 2];
    for _ in 0..3 {
        for (id, offset) in [0, 4].into_iter().zip(&mut offsets) {
            assert_eq!(
                assert_next_packet_frame(
                    &mut pipe.server,
                    &pipe.client,
                    &mut buf[..MAX_TEST_PACKET_SIZE],
                    &frame::Frame::Datagram { data: out.into() },
                )?,
                1
            );
            assert_eq!(
                assert_priority_stream_chunk(
                    &mut pipe,
                    &mut buf[..MAX_TEST_PACKET_SIZE],
                    id,
                    offset
                )?,
                1
            );
        }
    }
    Ok(())
}

#[rstest]
/// Tests that old data is retransmitted on PTO.
fn early_retransmit(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, b"a", false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Client sends more stream data, but packet is lost
    assert_eq!(pipe.client.stream_send(4, b"b", false), Ok(1));
    assert!(pipe.client.send(&mut buf).is_ok());

    // Wait until PTO expires. Since the RTT is very low, wait a bit more.
    let timer = pipe.client.timeout().ok_or("connection timer not armed")?;
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.client.on_timeout();

    let epoch = packet::Epoch::Application;
    assert_eq!(
        pipe.client.paths.get_active()?.recovery.loss_probes(epoch),
        1,
    );
    // The PTO exception is local to packet generation. Other users, including
    // send-capacity and PMTUD calculations, observe the actual congestion
    // window.
    assert_ne!(
        pipe.client.paths.get_active()?.recovery.cwnd_available(),
        usize::MAX,
    );

    // Client retransmits stream data in PTO probe.
    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(
        pipe.client.paths.get_active()?.recovery.loss_probes(epoch),
        0,
    );

    let frames = test_utils::decode_pkt(&pipe.server, &mut buf[..len])?;

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::Stream {
            stream_id: 4,
            data: <RangeBuf>::from(b"b", 0, false),
        })
    );
    assert_eq!(pipe.client.stats().retrans, 1);
    Ok(())
}

#[rstest]
fn pto_probe_not_stranded_by_earlier_epoch_data(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(0, 1, 2_400)] remaining_cwnd: usize,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    // Advance until the client has Application keys but retains Handshake
    // state.
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    assert!(pipe.client.is_established());
    assert!(!pipe.client.handshake_progress.confirmed());

    // Queue Handshake CRYPTO data ahead of an Application PTO probe.
    let handshake_send = &mut pipe.client.crypto_ctx[packet::Epoch::Handshake]
        .crypto_stream
        .send;
    let handshake_len = usize::try_from(handshake_send.off_back())?;
    assert!(handshake_send.retransmit(0, handshake_len) > 0);

    let active_pid = pipe.client.paths.get_active_path_id()?;
    let handshake_status = pipe.client.handshake_status();
    let pkt_num = pipe.client.next_pkt_num;
    pipe.client.next_pkt_num += 1;
    let now = Instant::now();
    let path = pipe.client.paths.get_mut(active_pid)?;
    let cwnd_available = path.recovery.cwnd_available();
    assert!(cwnd_available > remaining_cwnd);

    path.recovery.on_packet_sent(
        test_utils::helper_packet_sent(
            pkt_num,
            now,
            cwnd_available - remaining_cwnd,
        ),
        packet::Epoch::Application,
        handshake_status,
        now,
        "",
    );
    assert_eq!(path.recovery.cwnd_available(), remaining_cwnd);
    path.recovery.inc_loss_probes(packet::Epoch::Application);

    // The Application probe bypasses cwnd instead of being stranded behind
    // the earlier Handshake data.
    let (ty, _) = pipe.client.send_single(
        &mut packet::PacketWriter::from_initialized(&mut buf),
        active_pid,
        false,
        Instant::now(),
    )?;
    assert_eq!(ty, Type::Short);
    assert_eq!(
        pipe.client
            .paths
            .get(active_pid)?
            .recovery
            .loss_probes(packet::Epoch::Application),
        0,
    );
    Ok(())
}

#[rstest]
/// Tests that `sub_tx_buffered()` is called when data marked for retransmission
/// is acknowledged before being fully re-emitted.
///
/// Send 11KB, trigger PTO timeout, call `send()` which marks data for
/// retransmit but can't emit it all due to cwnd limits. Then deliver the
/// original packets and process ACKs. The `ack_and_drop()` for data still in
/// the retransmit buffer must call `sub_tx_buffered()` to maintain correct
/// accounting.
fn retransmit_data_acked_before_fully_retransmitted(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    config.set_initial_max_data(100_000);
    config.set_initial_max_stream_data_bidi_local(100_000);
    config.set_initial_max_stream_data_bidi_remote(100_000);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Establish stream.
    assert_eq!(pipe.client.stream_send(0, b"init", false), Ok(4));
    assert_eq!(pipe.advance(), Ok(()));

    // Send 11KB.
    let data_size = 11000;
    let large_data = vec![0xAB; data_size];
    assert_eq!(
        pipe.client.stream_send(0, &large_data, false),
        Ok(data_size)
    );

    // Emit but don't deliver (simulating loss).
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    assert_eq!(pipe.client.streams.tx_buffered(), 0);

    // Trigger PTO timeout.
    let timer = pipe.client.timeout().ok_or("connection timer not armed")?;
    std::thread::sleep(timer + Duration::from_millis(1));
    pipe.client.on_timeout();

    // Send PTO probe. retransmit() adds data to tx_buffered, but PTO cwnd
    // limits prevent emitting all of it.
    pipe.client.send(&mut buf)?;

    assert!(
        pipe.client.streams.tx_buffered() > 0,
        "Expected data in tx_buffered after retransmit"
    );

    // Deliver original packets (delayed arrival).
    let server_path = &pipe.server.paths.get_active()?;
    let server_info = RecvInfo {
        to: server_path.local_addr(),
        from: server_path.peer_addr(),
    };
    for (pkt, _) in &flight {
        let mut pkt_mut = pkt.clone();
        pipe.server.recv(&mut pkt_mut, server_info)?;
    }

    // Process ACKs. ack_and_drop() returns non-zero for data in retransmit
    // buffer and sub_tx_buffered() must be called.
    pipe.advance().ok();

    assert_eq!(
        pipe.client.streams.tx_buffered(),
        0,
        "tx_buffered should be 0 after ACK"
    );
    assert!(!pipe.client.streams.has_flushable());

    assert_eq!(pipe.client.stream_send(0, b"more", false), Ok(4));
    assert!(pipe.client.streams.has_flushable());
    Ok(())
}

fn assert_flow_control_credit_frames(frames: &[frame::Frame]) {
    let mut connection_credit = false;
    let mut stream_credit = false;
    for frame in frames {
        match frame {
            frame::Frame::MaxData { max } => {
                assert_eq!(*max, 75);
                connection_credit = true;
            },
            frame::Frame::MaxStreamData { stream_id, max } => {
                assert_eq!(*stream_id, 0);
                assert_eq!(*max, 60);
                stream_credit = true;
            },
            _ => (),
        }
    }
    assert!(connection_credit && stream_credit);
}

#[rstest]
/// Tests that `MAX_DATA`, `STREAM_MAX_DATA` frames are retransmitted if lost
fn max_data_frames_retransmit(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> Result<()> {
    let mut buf = vec![0; 65_535];

    let mut config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    config.set_initial_max_stream_data_bidi_local(30);
    config.set_initial_max_stream_data_bidi_remote(30);
    config.set_initial_max_data(30);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));
    assert_eq!(pipe.client.max_tx_data, 30);
    assert_eq!(pipe.server.max_rx_data(), 30);

    // Client sends stream data.
    assert_eq!(pipe.client.stream_send(0, &[42u8; 30], false), Ok(30));
    // The client is out of flow-control capacity.
    assert_eq!(
        pipe.client.stream_send(0, &[42u8; 30], false),
        Err(Error::Done)
    );
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.stream_recv(0, &mut buf), Ok((30, false)));
    // The client's `max_tx_data` remains unchanged.
    assert_eq!(pipe.client.max_tx_data, 30);
    // The server's `max_rx_data` also remains unchanged because it has not sent
    // a MAX_DATA frame yet.
    assert_eq!(pipe.server.max_rx_data(), 30);

    let (len, _) = pipe.server.send(&mut buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;

    assert_flow_control_credit_frames(&frames);

    // flow control on client is unchanged
    assert_eq!(pipe.client.max_tx_data, 30);
    assert_eq!(pipe.client.stream_capacity(0), Ok(0));
    // the server sent MAX_DATA (even though it got lost, so it has updated
    // its max_rx_data
    assert_eq!(pipe.server.max_rx_data(), 75);

    // Trigger loss detection
    test_utils::trigger_ack_based_loss(&mut pipe.server, &mut pipe.client)?;

    let (len, _) = pipe.server.send(&mut buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;

    assert_flow_control_credit_frames(&frames);
    // only stream_data and crypto frames increment retrans
    assert_eq!(pipe.client.stats().retrans, 0);
    Ok(())
}

#[rstest]
/// Tests that PTO probe packets are not coalesced together.
fn dont_coalesce_probes(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    // Client sends Initial packet.
    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(len, 1200);
    assert_eq!(
        pipe.client
            .path_stats()
            .next()
            .ok_or("expected path statistics")?
            .total_pto_count,
        0
    );

    // Wait for PTO to expire.
    let timer = pipe.client.timeout().ok_or("connection timer not armed")?;
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.client.on_timeout();
    assert_eq!(
        pipe.client
            .path_stats()
            .next()
            .ok_or("expected path statistics")?
            .total_pto_count,
        1
    );

    let epoch = packet::Epoch::Initial;
    assert_eq!(
        pipe.client.paths.get_active()?.recovery.loss_probes(epoch),
        1,
    );

    // Client sends PTO probe.
    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(len, 1200);
    assert_eq!(
        pipe.client.paths.get_active()?.recovery.loss_probes(epoch),
        0,
    );

    // Wait for PTO to expire.
    let timer = pipe.client.timeout().ok_or("connection timer not armed")?;
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.client.on_timeout();
    assert_eq!(
        pipe.client
            .path_stats()
            .next()
            .ok_or("expected path statistics")?
            .total_pto_count,
        2
    );

    assert_eq!(
        pipe.client.paths.get_active()?.recovery.loss_probes(epoch),
        2,
    );

    // Client sends first PTO probe.
    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(len, 1200);
    assert_eq!(
        pipe.client.paths.get_active()?.recovery.loss_probes(epoch),
        1,
    );

    // Client sends second PTO probe.
    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(len, 1200);
    assert_eq!(
        pipe.client.paths.get_active()?.recovery.loss_probes(epoch),
        0,
    );
    Ok(())
}

#[rstest]
fn coalesce_padding_short(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    // Test asserts a specific coalesce/pad shape that assumes a
    // single-Initial ClientHello.
    let mut config = test_utils::Pipe::default_config_no_pq(cc_algorithm_name)?;
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;

    // Client sends first flight.
    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(len, MIN_CLIENT_INITIAL_LEN);
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    // Server sends first flight.
    let (len, _) = pipe.server.send(&mut buf)?;
    assert_eq!(len, MIN_CLIENT_INITIAL_LEN);
    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    let (len, _) = pipe.server.send(&mut buf)?;
    assert_eq!(pipe.client_recv(&mut buf[..len]), Ok(len));

    // Client sends stream data.
    assert!(pipe.client.is_established());
    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));

    // Client sends second flight.
    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(len, MIN_CLIENT_INITIAL_LEN);
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    // None of the sent packets should have been dropped.
    assert_eq!(
        pipe.client.counters.sent_count,
        pipe.server.counters.recv_count
    );
    assert_eq!(
        pipe.server.counters.sent_count,
        pipe.client.counters.recv_count
    );
    Ok(())
}

#[rstest]
/// Tests that client avoids handshake deadlock by arming PTO.
fn handshake_anti_deadlock(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    // Test drives the handshake one packet at a time and expects the
    // server to have handshake keys after a single `server_recv`; that
    // requires a single-Initial ClientHello.
    let mut config = test_utils::config_no_pq(PROTOCOL_VERSION)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config.load_cert_chain_from_pem_file("examples/cert-big.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;

    assert!(!pipe.client.handshake_status().has_handshake_keys);
    assert!(!pipe.client.handshake_status().peer_verified_address);
    assert!(!pipe.server.handshake_status().has_handshake_keys);
    assert!(pipe.server.handshake_status().peer_verified_address);

    // Client sends padded Initial.
    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(len, 1200);

    // Server receives client's Initial and sends own Initial and Handshake
    // until it's blocked by the anti-amplification limit.
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));
    let flight = test_utils::emit_flight(&mut pipe.server)?;

    assert!(!pipe.client.handshake_status().has_handshake_keys);
    assert!(!pipe.client.handshake_status().peer_verified_address);
    assert!(pipe.server.handshake_status().has_handshake_keys);
    assert!(pipe.server.handshake_status().peer_verified_address);

    // Client receives the server flight and sends Handshake ACK, but it is
    // lost.
    test_utils::process_flight(&mut pipe.client, flight)?;
    test_utils::emit_flight(&mut pipe.client)?;

    assert!(pipe.client.handshake_status().has_handshake_keys);
    assert!(!pipe.client.handshake_status().peer_verified_address);
    assert!(pipe.server.handshake_status().has_handshake_keys);
    assert!(pipe.server.handshake_status().peer_verified_address);

    // Make sure client's PTO timer is armed.
    assert!(pipe.client.timeout().is_some());
    Ok(())
}

#[rstest]
/// Tests that packets with corrupted type (from Handshake to Initial) are
/// properly ignored.
fn handshake_packet_type_corruption(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    // Test drives the handshake one packet at a time, which assumes a
    // single-Initial ClientHello.
    let mut config = test_utils::Pipe::default_config_no_pq(cc_algorithm_name)?;
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;

    // Client sends padded Initial.
    let (len, _) = pipe.client.send(&mut buf)?;
    assert_eq!(len, 1200);

    // Server receives client's Initial and sends own Initial and Handshake.
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;

    // Client sends Initial packet with ACK.
    let active_pid = pipe.client.paths.get_active_path_id()?;
    let (ty, len) = pipe.client.send_single(
        &mut packet::PacketWriter::from_initialized(&mut buf),
        active_pid,
        false,
        Instant::now(),
    )?;
    assert_eq!(ty, Type::Initial);

    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    // Client sends Handshake packet.
    let (ty, len) = pipe.client.send_single(
        &mut packet::PacketWriter::from_initialized(&mut buf),
        active_pid,
        false,
        Instant::now(),
    )?;
    assert_eq!(ty, Type::Handshake);

    // Packet type is corrupted to Initial.
    buf[0] &= !(0x20);

    let hdr = Header::from_slice(&buf[..len], 0)?;
    assert_eq!(hdr.ty, Type::Initial);

    // Server receives corrupted packet without returning an error.
    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));
    Ok(())
}

#[rstest]
fn dgram_send_fails_invalidstate(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(
        pipe.client.dgram_send(b"hello, world"),
        Err(Error::InvalidState)
    );
    Ok(())
}

#[rstest]
fn dgram_send_app_limited(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];
    let send_buf = [0xcf; 1000];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.enable_dgram(true, 1000, 1000);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    for _ in 0..1000 {
        assert_eq!(pipe.client.dgram_send(&send_buf), Ok(()));
    }

    // bbr2_gcongestion uses different logic to set app_limited
    // TODO fix
    let should_be_app_limited =
        cc_algorithm_name == "cubic" || cc_algorithm_name == "reno";
    assert_eq!(
        !pipe.client.paths.get_active()?.recovery.app_limited(),
        should_be_app_limited
    );
    assert_eq!(pipe.client.dgram_send_queue.byte_size(), 1_000_000);

    let (len, _) = pipe.client.send(&mut buf)?;

    assert_ne!(pipe.client.dgram_send_queue.byte_size(), 0);
    assert_ne!(pipe.client.dgram_send_queue.byte_size(), 1_000_000);
    assert_eq!(
        !pipe.client.paths.get_active()?.recovery.app_limited(),
        should_be_app_limited
    );

    assert_eq!(pipe.server_recv(&mut buf[..len]), Ok(len));

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;

    assert_ne!(pipe.client.dgram_send_queue.byte_size(), 0);
    assert_ne!(pipe.client.dgram_send_queue.byte_size(), 1_000_000);

    assert_eq!(
        !pipe.client.paths.get_active()?.recovery.app_limited(),
        should_be_app_limited
    );
    Ok(())
}

#[rstest]
fn dgram_single_datagram(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.enable_dgram(true, 10, 10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.dgram_send(b"hello, world"), Ok(()));

    assert_eq!(pipe.advance(), Ok(()));

    let result1 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result1, Ok(12));

    let result2 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result2, Err(Error::Done));
    Ok(())
}

#[rstest]
fn dgram_direct_handler(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] consume: bool,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.enable_dgram(true, 10, 10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let expected = b"hello, direct datagram";
    assert_eq!(pipe.client.dgram_send(expected), Ok(()));

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    let mut received = Vec::new();
    let mut calls = 0;

    for (mut pkt, si) in flight {
        let info = RecvInfo {
            to: si.to,
            from: si.from,
        };
        let mut handler = |data: &[u8]| {
            calls += 1;
            received.extend_from_slice(data);
            consume
        };

        pipe.server
            .recv_with_dgram_handler(&mut pkt, info, &mut handler)?;
    }

    assert_eq!(calls, 1);
    assert_eq!(received, expected);

    let mut out = [0u8; 64];
    if !consume {
        assert_eq!(pipe.server.dgram_recv(&mut out), Ok(expected.len()));
        assert_eq!(&out[..expected.len()], expected);
    }
    assert_eq!(pipe.server.dgram_recv(&mut out), Err(Error::Done));
    Ok(())
}

#[rstest]
fn dgram_direct_handler_fallback_preserves_fifo(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.enable_dgram(true, 10, 10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let first = b"first";
    let second = b"second";
    let third = b"third";
    assert_eq!(pipe.client.dgram_send(first), Ok(()));
    assert_eq!(pipe.client.dgram_send(second), Ok(()));
    assert_eq!(pipe.client.dgram_send(third), Ok(()));

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    let mut seen = Vec::new();
    let mut calls = 0usize;

    for (mut pkt, si) in flight {
        let info = RecvInfo {
            to: si.to,
            from: si.from,
        };
        let mut handler = |data: &[u8]| {
            calls += 1;
            seen.push(data.to_vec());

            // Consume the first DATAGRAM directly, but force the second into
            // the queue. The third must then stay queued behind the second.
            calls == 1
        };

        pipe.server
            .recv_with_dgram_handler(&mut pkt, info, &mut handler)?;
    }

    assert_eq!(calls, 2);
    assert_eq!(seen, vec![first.to_vec(), second.to_vec()]);

    let mut out = [0u8; 64];
    assert_eq!(pipe.server.dgram_recv(&mut out), Ok(second.len()));
    assert_eq!(&out[..second.len()], second);
    assert_eq!(pipe.server.dgram_recv(&mut out), Ok(third.len()));
    assert_eq!(&out[..third.len()], third);
    assert_eq!(pipe.server.dgram_recv(&mut out), Err(Error::Done));
    Ok(())
}

#[rstest]
fn dgram_multiple_datagrams(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.enable_dgram(true, 2, 3);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.dgram_send_queue_len(), 0);
    assert_eq!(pipe.client.dgram_send_queue_byte_size(), 0);

    assert_eq!(pipe.client.dgram_send(b"hello, world"), Ok(()));
    assert_eq!(pipe.client.dgram_send(b"ciao, mondo"), Ok(()));
    assert_eq!(pipe.client.dgram_send(b"hola, mundo"), Ok(()));
    assert!(pipe.client.is_dgram_send_queue_full());

    assert_eq!(pipe.client.dgram_send_queue_byte_size(), 34);

    pipe.client
        .dgram_purge_outgoing(|d: &[u8]| -> bool { d[0] == b'c' });

    assert_eq!(pipe.client.dgram_send_queue_len(), 2);
    assert_eq!(pipe.client.dgram_send_queue_byte_size(), 23);
    assert!(!pipe.client.is_dgram_send_queue_full());

    // Before packets exchanged, no dgrams on server receive side.
    assert_eq!(pipe.server.dgram_recv_queue_len(), 0);

    assert_eq!(pipe.advance(), Ok(()));

    // After packets exchanged, no dgrams on client send side.
    assert_eq!(pipe.client.dgram_send_queue_len(), 0);
    assert_eq!(pipe.client.dgram_send_queue_byte_size(), 0);

    assert_eq!(pipe.server.dgram_recv_queue_len(), 2);
    assert_eq!(pipe.server.dgram_recv_queue_byte_size(), 23);
    assert!(pipe.server.is_dgram_recv_queue_full());

    let result1 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result1, Ok(12));
    assert_eq!(buf[0], b'h');
    assert_eq!(buf[1], b'e');
    assert!(!pipe.server.is_dgram_recv_queue_full());

    let result2 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result2, Ok(11));
    assert_eq!(buf[0], b'h');
    assert_eq!(buf[1], b'o');

    let result3 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result3, Err(Error::Done));

    assert_eq!(pipe.server.dgram_recv_queue_len(), 0);
    assert_eq!(pipe.server.dgram_recv_queue_byte_size(), 0);
    Ok(())
}

#[rstest]
fn dgram_queue_overflow(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] receive_overflow: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    if receive_overflow {
        config.enable_dgram(true, 2, 10);
        config.set_max_recv_udp_payload_size(1200);
    } else {
        config.enable_dgram(true, 10, 2);
    }
    config.verify_peer(false);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    pipe.handshake()?;

    let messages: [&[u8]; 3] = [b"hello, world", b"ciao, mondo", b"hola, mundo"];
    for message in &messages[..2] {
        assert_eq!(pipe.client.dgram_send(message), Ok(()));
    }
    assert_eq!(
        pipe.client.dgram_send(messages[2]),
        if receive_overflow {
            Ok(())
        } else {
            Err(Error::Done)
        }
    );
    pipe.advance()?;
    let expected = if receive_overflow {
        &messages[1..]
    } else {
        &messages[..2]
    };
    for message in expected {
        assert_eq!(pipe.server.dgram_recv(&mut buf), Ok(message.len()));
        assert_eq!(&buf[..message.len()], *message);
    }
    assert_eq!(pipe.server.dgram_recv(&mut buf), Err(Error::Done));
    Ok(())
}

#[rstest]
fn dgram_send_max_size(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; usize::try_from(MAX_DGRAM_FRAME_SIZE)?];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.enable_dgram(true, 10, 10);
    config.set_max_recv_udp_payload_size(1452);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;

    // Before handshake (before peer settings) we don't know max dgram size
    assert_eq!(pipe.client.dgram_max_writable_len(), None);

    assert_eq!(pipe.handshake(), Ok(()));

    let max_dgram_size = pipe
        .client
        .dgram_max_writable_len()
        .ok_or("datagrams not available")?;

    // Tests use a 16-byte connection ID, so the max datagram frame payload
    // size is (1200 byte-long packet - 40 bytes overhead)
    assert_eq!(max_dgram_size, 1160);

    let dgram_packet: Vec<u8> = vec![42; max_dgram_size];

    assert_eq!(pipe.client.dgram_send(&dgram_packet), Ok(()));

    assert_eq!(pipe.advance(), Ok(()));

    let result1 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result1, Ok(max_dgram_size));

    let result2 = pipe.server.dgram_recv(&mut buf);
    assert_eq!(result2, Err(Error::Done));
    Ok(())
}

#[rstest]
fn large_udp_payloads_preserve_frame_lengths(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(16_383, 16_425, 16_426, 32_768, 65_527)] mtu: usize,
) -> TestResult {
    let mut config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    config.set_max_send_udp_payload_size(mtu);
    config.set_max_recv_udp_payload_size(mtu);
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.enable_dgram(true, 10, 10);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    pipe.handshake()?;
    pipe.advance()?;
    assert_eq!(pipe.client.max_send_udp_payload_size(), mtu);

    let payload_len = pipe
        .client
        .dgram_max_writable_len()
        .ok_or("datagrams not available")?;
    let payload = vec![0x37; payload_len];
    assert_eq!(
        pipe.client.dgram_send(&vec![0; payload_len + 1]),
        Err(Error::BufferTooShort)
    );
    pipe.client.dgram_send(&payload)?;
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    assert_eq!(flight.len(), 1);
    let (packet, _) = &flight[0];
    assert!(packet.len() <= mtu);
    assert!(packet.len() >= payload_len);
    test_utils::process_flight(&mut pipe.server, flight)?;
    let mut recv = vec![0; payload_len];
    assert_eq!(pipe.server.dgram_recv(&mut recv), Ok(payload_len));
    assert_eq!(recv, payload);
    pipe.advance()?;

    assert_eq!(pipe.client.stream_send(0, &payload, true), Ok(payload_len));
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    assert_eq!(flight.len(), 1);
    let (packet, _) = &flight[0];
    assert!(packet.len() <= mtu);
    test_utils::process_flight(&mut pipe.server, flight)?;
    assert_eq!(
        pipe.server.stream_recv(0, &mut recv),
        Ok((payload_len, true))
    );
    assert_eq!(recv, payload);
    Ok(())
}

#[test]
fn outbound_udp_size_configuration_stays_within_udp_limits() -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    for (requested, expected) in [
        (0, MIN_CLIENT_INITIAL_LEN),
        (16_384, 16_384),
        (usize::MAX, MAX_SEND_UDP_PAYLOAD_SIZE),
    ] {
        config.set_max_send_udp_payload_size(requested);
        assert_eq!(config.recovery.max_send_udp_payload_size, expected);
    }
    Ok(())
}

#[rstest]
fn large_peer_datagram_limits_do_not_truncate(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] discover_pmtu: bool,
) -> TestResult {
    const LARGE_LIMIT: u64 = 1_u64 << 32;
    let mut config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    config.set_max_send_udp_payload_size(1400);
    config.discover_pmtu(discover_pmtu);
    config.enable_dgram(true, 10, 10);
    // Set the original wire-domain values directly: the public usize setter
    // cannot express them on a 32-bit test target.
    config.local_transport_params.max_udp_payload_size = LARGE_LIMIT;
    config.local_transport_params.max_datagram_frame_size = Some(LARGE_LIMIT);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    pipe.handshake()?;
    pipe.advance()?;

    assert_eq!(
        pipe.client.peer_parameters.effective().max_udp_payload_size,
        LARGE_LIMIT
    );
    assert_eq!(
        pipe.client
            .peer_parameters
            .effective()
            .max_datagram_frame_size,
        Some(LARGE_LIMIT)
    );
    assert_eq!(pipe.client.max_send_udp_payload_size(), 1400);
    assert_eq!(pipe.server.max_send_udp_payload_size(), 1400);
    let payload_len = pipe
        .client
        .dgram_max_writable_len()
        .ok_or("datagrams not available")?;
    assert_eq!(payload_len, 1360);
    let payload = vec![42; payload_len];
    pipe.client.dgram_send(&payload)?;
    pipe.advance()?;
    let mut received = vec![0; payload_len];
    assert_eq!(pipe.server.dgram_recv(&mut received), Ok(payload_len));
    assert_eq!(received, payload);
    Ok(())
}

#[rstest]
/// Tests `is_readable` check.
fn is_readable(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.enable_dgram(true, 10, 10);
    config.set_max_recv_udp_payload_size(1452);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // No readable data.
    assert!(!pipe.client.is_readable());
    assert!(!pipe.server.is_readable());

    assert_eq!(pipe.client.stream_send(4, b"aaaaa", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server received stream.
    assert!(!pipe.client.is_readable());
    assert!(pipe.server.is_readable());

    assert_eq!(
        pipe.server.stream_send(4, b"aaaaaaaaaaaaaaa", false),
        Ok(15)
    );
    assert_eq!(pipe.advance(), Ok(()));

    // Client received stream.
    assert!(pipe.client.is_readable());
    assert!(pipe.server.is_readable());

    // Client drains stream.
    stream_recv_discard(&mut pipe.client, discard, 4)?;
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.client.is_readable());
    assert!(pipe.server.is_readable());

    // Server shuts down stream.
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Read, 0), Ok(()));
    assert!(!pipe.server.is_readable());

    // Server received dgram.
    assert_eq!(pipe.client.dgram_send(b"dddddddddddddd"), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(!pipe.client.is_readable());
    assert!(pipe.server.is_readable());

    // Client received dgram.
    assert_eq!(pipe.server.dgram_send(b"dddddddddddddd"), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    assert!(pipe.client.is_readable());
    assert!(pipe.server.is_readable());

    // Drain the dgram queues.
    let r = pipe.server.dgram_recv(&mut buf);
    assert_eq!(r, Ok(14));
    assert!(!pipe.server.is_readable());

    let r = pipe.client.dgram_recv(&mut buf);
    assert_eq!(r, Ok(14));
    assert!(!pipe.client.is_readable());
    Ok(())
}

/// Tests that the `dgram_lost` stat is incremented when a DATAGRAM frame is
/// declared lost.
#[rstest]
fn dgram_lost_stat(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> Result<()> {
    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.enable_dgram(true, 10, 10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Verify initial state: no datagrams lost.
    assert_eq!(
        pipe.client
            .path_stats()
            .next()
            .ok_or(Error::InvalidState)?
            .dgram_lost,
        0
    );

    // Client sends a datagram.
    assert_eq!(pipe.client.dgram_send(b"hello, world"), Ok(()));

    // Emit the datagram packet but don't deliver it to the server.
    assert!(test_utils::emit_flight(&mut pipe.client).is_ok());

    // Trigger loss detection.
    test_utils::trigger_ack_based_loss(&mut pipe.client, &mut pipe.server)?;

    // Trigger the lost-frames processing by calling send().
    pipe.client.send(&mut buf)?;

    // Verify dgram_lost stat is incremented.
    assert_eq!(
        pipe.client
            .path_stats()
            .next()
            .ok_or(Error::InvalidState)?
            .dgram_lost,
        1
    );
    Ok(())
}

#[rstest]
fn terminal_connection_lifecycle(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] drain: bool,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));
    let conn = &mut pipe.client;
    assert_eq!(conn.lifecycle, ConnectionLifecycle::Active);
    let past = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .ok_or("monotonic clock underflow")?;
    let cause = if drain {
        assert_eq!(conn.close(false, 0, b""), Ok(()));
        assert!(conn.send(&mut vec![0; 65_535]).is_ok());
        assert!(conn.is_draining());
        assert!(!conn.is_closed());
        assert!(matches!(conn.lifecycle, ConnectionLifecycle::Draining {
            origin: CloseOrigin::Local,
            ..
        }));
        conn.lifecycle = ConnectionLifecycle::Draining {
            deadline: past,
            origin: CloseOrigin::Local,
        };
        CloseCause::Explicit(CloseOrigin::Local)
    } else {
        conn.idle.deadline = Some(past);
        CloseCause::IdleTimeout
    };
    assert_eq!(conn.timeout_instant(), Some(past));
    conn.on_timeout();
    assert_eq!(conn.lifecycle, ConnectionLifecycle::Closed(cause));
    assert!(conn.is_closed());
    assert!(!conn.is_draining());
    assert_eq!(conn.is_timed_out(), !drain);
    assert_eq!(conn.timeout(), None);
    // A stale timer or repeated event must not change the terminal cause.
    conn.idle.deadline = Some(past);
    conn.on_timeout();
    conn.mark_closed(CloseCause::NoViablePath);
    assert_eq!(conn.lifecycle, ConnectionLifecycle::Closed(cause));
    assert_eq!(conn.send(&mut [0; 100]), Err(Error::Done));
    Ok(())
}

#[cfg(feature = "qlog")]
#[test]
fn close_qlog_reports_actual_terminal_cause() -> TestResult {
    use qlog::events::quic::ConnectionClosedTrigger as Trigger;
    let mut pipe = test_utils::Pipe::new("cubic")?;
    assert_eq!(
        pipe.client.close_event(CloseCause::IdleTimeout).trigger,
        Some(Trigger::HandshakeTimeout)
    );
    assert_eq!(pipe.handshake(), Ok(()));
    for (cause, trigger) in [
        (CloseCause::IdleTimeout, Trigger::IdleTimeout),
        (CloseCause::StatelessReset, Trigger::StatelessReset),
        (CloseCause::NoViablePath, Trigger::Error),
        (CloseCause::PacketNumbersExhausted, Trigger::Error),
    ] {
        assert_eq!(pipe.client.close_event(cause).trigger, Some(trigger));
    }
    let now = Instant::now();
    pipe.client
        .set_qlog(Box::new(std::io::sink()), String::new(), String::new());
    pipe.client.idle.deadline = Some(now);
    pipe.client.on_timeout();
    assert!(pipe.client.is_timed_out());
    assert_eq!(
        pipe.client.lifecycle,
        ConnectionLifecycle::Closed(CloseCause::IdleTimeout)
    );
    Ok(())
}

#[rstest]
fn close(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.close(false, 0x1234, b"hello?"), Ok(()));

    assert_eq!(
        pipe.client.close(false, 0x4321, b"hello?"),
        Err(Error::Done)
    );

    let (len, _) = pipe.client.send(&mut buf)?;

    let frames = test_utils::decode_pkt(&pipe.server, &mut buf[..len])?;

    assert_eq!(
        frames.first(),
        Some(&frame::Frame::ConnectionClose {
            error_code: 0x1234,
            frame_type: 0,
            reason: b"hello?".to_vec(),
        })
    );
    Ok(())
}

/// A close-only packet does not elicit ACKs (RFC 9000 section 13.2).
/// Closing must not consume a pending ACK-elicitation request or restart
/// the idle timer, and the packet must not enter congestion flight accounting.
#[rstest]
fn close_only_packet_does_not_elicit_ack(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] application: bool,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));
    let conn = &mut pipe.client;
    let path = conn.paths.get_active_mut()?;
    assert!(path.validated());
    path.needs_ack_eliciting = true;
    let before = path.recovery.bytes_in_flight();
    let idle_timer = conn.idle.deadline;
    conn.idle.ack_eliciting_sent = false;

    assert_eq!(conn.close(application, 42, b"closing"), Ok(()));
    let mut buf = [0; 1500];
    let (written, _) = conn.send(&mut buf)?;
    let frames = test_utils::decode_pkt(&pipe.server, &mut buf[..written])?;
    assert_eq!(frames.len(), 1);
    assert!(matches!(
        frames[0],
        frame::Frame::ConnectionClose { .. } |
            frame::Frame::ApplicationClose { .. }
    ));
    assert!(!frames[0].ack_eliciting());
    let path = pipe.client.paths.get_active()?;
    assert_eq!(path.recovery.bytes_in_flight(), before);
    assert!(path.needs_ack_eliciting);
    assert!(!pipe.client.idle.ack_eliciting_sent);
    assert_eq!(pipe.client.idle.deadline, idle_timer);
    assert!(pipe.client.is_draining());
    Ok(())
}

#[rstest]
fn app_close_by_client(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] simulate_pto: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    if simulate_pto {
        // Advance the handshake until the client is established, but has not
        // yet received HANDSHAKE_DONE from the server.
        let flight = test_utils::emit_flight(&mut pipe.client)?;
        test_utils::process_flight(&mut pipe.server, flight)?;

        let flight = test_utils::emit_flight(&mut pipe.server)?;
        test_utils::process_flight(&mut pipe.client, flight)?;

        let flight = test_utils::emit_flight(&mut pipe.client)?;
        test_utils::process_flight(&mut pipe.server, flight)?;

        assert!(pipe.client.is_established());
        assert!(!pipe.client.handshake_progress.confirmed());

        // Exhaust cwnd and model a Handshake PTO expiring before the client
        // closes the connection.
        let active_pid = pipe.client.paths.get_active_path_id()?;
        let handshake_status = pipe.client.handshake_status();
        let pkt_num = pipe.client.next_pkt_num;
        pipe.client.next_pkt_num += 1;
        let now = Instant::now();
        let path = pipe.client.paths.get_mut(active_pid)?;
        let cwnd_available = path.recovery.cwnd_available();
        assert!(cwnd_available > 0);

        path.recovery.on_packet_sent(
            test_utils::helper_packet_sent(pkt_num, now, cwnd_available),
            packet::Epoch::Application,
            handshake_status,
            now,
            "",
        );
        assert_eq!(path.recovery.cwnd_available(), 0);
        path.recovery.inc_loss_probes(packet::Epoch::Handshake);
    } else {
        assert_eq!(pipe.handshake(), Ok(()));
    }

    assert_eq!(pipe.client.close(true, 0x1234, b"hello!"), Ok(()));

    assert_eq!(pipe.client.close(true, 0x4321, b"hello!"), Err(Error::Done));

    let (len, _) = pipe.client.send(&mut buf)?;

    let frames = test_utils::decode_pkt(&pipe.server, &mut buf[..len])?;

    assert_eq!(
        frames.first(),
        Some(&frame::Frame::ApplicationClose {
            error_code: 0x1234,
            reason: b"hello!".to_vec(),
        })
    );
    assert!(pipe.client.is_draining());

    // A pending Handshake PTO does not cause ACK-only packets after
    // the application close is sent.
    assert_eq!(pipe.client.send(&mut buf), Err(Error::Done));
    Ok(())
}

#[rstest]
fn app_close_by_server_during_handshake_private_key_failure(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    pipe.server.handshake.set_failing_private_key_method();

    // Client sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    assert_eq!(
        test_utils::process_flight(&mut pipe.server, flight),
        Err(Error::TlsFail)
    );

    let flight = test_utils::emit_flight(&mut pipe.server)?;

    // Both connections are not established.
    assert!(!pipe.server.is_established());
    assert!(!pipe.client.is_established());

    // Connection should already be closed due the failure during key signing.
    assert_eq!(
        pipe.server.close(true, 123, b"fail whale"),
        Err(Error::Done)
    );

    test_utils::process_flight(&mut pipe.client, flight)?;

    // Connection should already be closed due the failure during key signing.
    assert_eq!(
        pipe.client.close(true, 123, b"fail whale"),
        Err(Error::Done)
    );

    // Connection is not established on the server / client (and never
    // will be)
    assert!(!pipe.server.is_established());
    assert!(!pipe.client.is_established());

    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.server.local_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 0x01,
            reason: vec![],
        })
    );
    assert_eq!(
        pipe.client.peer_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 0x01,
            reason: vec![],
        })
    );
    Ok(())
}

#[rstest]
fn app_close_by_server_during_handshake_not_established(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    // Client sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    let flight = test_utils::emit_flight(&mut pipe.server)?;

    // Both connections are not established.
    assert!(!pipe.client.is_established() && !pipe.server.is_established());

    // Server closes before connection is established.
    pipe.server.close(true, 123, b"fail whale")?;

    test_utils::process_flight(&mut pipe.client, flight)?;

    // Connection is established on the client.
    assert!(pipe.client.is_established());

    // Client sends after connection is established.
    pipe.client.stream_send(0, b"badauthtoken", true)?;

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    // Connection is not established on the server (and never will be)
    assert!(!pipe.server.is_established());

    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.server.local_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 0x0c,
            reason: vec![],
        })
    );
    assert_eq!(
        pipe.client.peer_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 0x0c,
            reason: vec![],
        })
    );
    Ok(())
}

#[rstest]
fn app_close_by_server_during_handshake_established(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    // Client sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    let flight = test_utils::emit_flight(&mut pipe.server)?;

    // Both connections are not established.
    assert!(!pipe.client.is_established() && !pipe.server.is_established());

    test_utils::process_flight(&mut pipe.client, flight)?;

    // Connection is established on the client.
    assert!(pipe.client.is_established());

    // Client sends after connection is established.
    pipe.client.stream_send(0, b"badauthtoken", true)?;

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    // Connection is established on the server but the Handshake ACK has not
    // been sent yet.
    assert!(pipe.server.is_established());

    // Server closes after connection is established.
    pipe.server.close(true, 123, b"Invalid authentication")?;

    // Server sends Handshake ACK and then 1RTT CONNECTION_CLOSE.
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.server.local_error(),
        Some(&ConnectionError {
            is_app: true,
            error_code: 123,
            reason: b"Invalid authentication".to_vec()
        })
    );
    assert_eq!(
        pipe.client.peer_error(),
        Some(&ConnectionError {
            is_app: true,
            error_code: 123,
            reason: b"Invalid authentication".to_vec()
        })
    );
    Ok(())
}

#[rstest]
fn transport_close_by_client_during_handshake_established(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;

    // Client sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    let flight = test_utils::emit_flight(&mut pipe.server)?;

    // Both connections are not established.
    assert!(!pipe.client.is_established() && !pipe.server.is_established());

    test_utils::process_flight(&mut pipe.client, flight)?;

    // Connection is established on the client.
    assert!(pipe.client.is_established());

    // Client sends after connection is established.
    pipe.client.close(false, 123, b"connection close")?;

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    assert_eq!(
        pipe.server.peer_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 123,
            reason: b"connection close".to_vec()
        })
    );
    assert_eq!(
        pipe.client.local_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 123,
            reason: b"connection close".to_vec()
        })
    );
    Ok(())
}

#[rstest]
fn peer_error(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.server.close(false, 0x1234, b"hello?"), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.client.peer_error(),
        Some(&ConnectionError {
            is_app: false,
            error_code: 0x1234u64,
            reason: b"hello?".to_vec()
        })
    );
    Ok(())
}

#[rstest]
fn app_peer_error(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.server.close(true, 0x1234, b"hello!"), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        pipe.client.peer_error(),
        Some(&ConnectionError {
            is_app: true,
            error_code: 0x1234u64,
            reason: b"hello!".to_vec()
        })
    );
    Ok(())
}

#[rstest]
fn local_error(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.server.local_error(), None);

    assert_eq!(pipe.server.close(true, 0x1234, b"hello!"), Ok(()));

    assert_eq!(
        pipe.server.local_error(),
        Some(&ConnectionError {
            is_app: true,
            error_code: 0x1234u64,
            reason: b"hello!".to_vec()
        })
    );
    Ok(())
}

#[rstest]
fn skip_ping_ack_while_closing_in_early_data(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = test_utils::Pipe::default_config_no_pq(cc_algorithm_name)?;
    config.enable_early_data();

    // Establish an initial connection to obtain a resumption ticket.
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));
    let session = pipe.client.session().ok_or("TLS session was not issued")?;

    // Start a resumed connection and advance the server into early data.
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.client.set_session(session), Ok(()));

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;
    assert!(pipe.server.is_in_early_data());
    assert!(!pipe.server.is_established());

    // Leave the server's Handshake CRYPTO unacknowledged.
    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;

    // Send a valid Handshake PING without the client's queued Finished. This
    // gives the server something to ACK without completing its handshake.
    let mut out = vec![0u8; 65_535];
    let frames = [frame::Frame::Ping { mtu_probe: None }];
    let len = test_utils::encode_pkt(
        &mut pipe.client,
        Type::Handshake,
        &frames,
        &mut out,
    )?;
    assert_eq!(pipe.server_recv(&mut out[..len]), Ok(len));

    // Send and discard the resulting ACK so ack_elicited is clear while the
    // received packet remains in the server's ACK ranges.
    pipe.server.send(&mut out)?;

    let epoch = packet::Epoch::Handshake;
    assert!(!pipe.server.pkt_num_spaces[epoch].ack_elicited);
    assert!(pipe.server.pkt_num_spaces[epoch].recv_pkt_need_ack.len() > 0);

    // The server detects the lost client response through the PTO path.
    let timer = pipe.server.timeout().ok_or("connection timer not armed")?;
    std::thread::sleep(timer + Duration::from_millis(1));
    pipe.server.on_timeout();

    assert!(pipe.server.paths.get_active()?.recovery.loss_probes(epoch) > 0);

    // An application close is valid during early data
    assert_eq!(pipe.server.close(true, 0x1234, b"app close"), Ok(()));
    assert!(pipe.server.is_in_early_data());
    assert!(!pipe.server.is_established());

    assert_eq!(pipe.server.send(&mut out), Err(Error::Done));
    Ok(())
}

#[rstest]
fn update_max_datagram_size(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut client_scid = [0; 16];
    rand::rand_bytes(&mut client_scid[..]);
    let client_scid = ConnectionId::from_ref(&client_scid);
    let client_addr = "127.0.0.1:1234".parse()?;

    let mut server_scid = [0; 16];
    rand::rand_bytes(&mut server_scid[..]);
    let server_scid = ConnectionId::from_ref(&server_scid);
    let server_addr = "127.0.0.1:4321".parse()?;

    let mut client_config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(
        client_config.set_cc_algorithm_name(cc_algorithm_name),
        Ok(())
    );
    client_config.set_application_protos(&[b"proto1", b"proto2"])?;
    client_config.set_max_recv_udp_payload_size(1200);

    let mut server_config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(
        server_config.set_cc_algorithm_name(cc_algorithm_name),
        Ok(())
    );
    server_config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    server_config.load_priv_key_from_pem_file("examples/cert.key")?;
    server_config.set_application_protos(&[b"proto1", b"proto2"])?;
    server_config.verify_peer(false);
    server_config.set_application_protos(&[b"proto1", b"proto2"])?;
    // Larger than the client
    server_config.set_max_send_udp_payload_size(1500);

    let mut pipe = test_utils::Pipe {
        client: connect(
            Some("quic.tech"),
            &client_scid,
            client_addr,
            server_addr,
            &mut client_config,
        )?,
        server: accept(
            &server_scid,
            None,
            server_addr,
            client_addr,
            &mut server_config,
        )?,
    };

    // Before handshake
    assert_eq!(
        pipe.server.paths.get_active()?.recovery.max_datagram_size(),
        1500,
    );

    assert_eq!(pipe.handshake(), Ok(()));

    // After handshake, max_datagram_size should match to client's
    // max_recv_udp_payload_size which is smaller
    assert_eq!(
        pipe.server.paths.get_active()?.recovery.max_datagram_size(),
        1200,
    );
    assert_eq!(
        pipe.server.paths.get_active()?.recovery.cwnd(),
        if cc_algorithm_name == "cubic" {
            12000
        } else {
            14577
        },
    );
    Ok(())
}

#[rstest]
/// Tests that connection-level send capacity decreases as more stream data
/// is buffered.
fn send_capacity(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(100_000);
    config.set_initial_max_stream_data_bidi_local(10000);
    config.set_initial_max_stream_data_bidi_remote(10000);
    config.set_initial_max_streams_bidi(10);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(0, b"hello!", true), Ok(6));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"hello!", true), Ok(6));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(8, b"hello!", true), Ok(6));
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.stream_send(12, b"hello!", true), Ok(6));
    assert_eq!(pipe.advance(), Ok(()));

    let mut r = pipe.server.readable().collect::<Vec<u64>>();
    assert_eq!(r.len(), 4);

    r.sort_unstable();

    assert_eq!(r, [0, 4, 8, 12]);

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 0),
        Ok((6, true))
    );
    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 4),
        Ok((6, true))
    );
    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 8),
        Ok((6, true))
    );
    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 12),
        Ok((6, true))
    );

    assert_eq!(
        pipe.server.tx_cap,
        if cc_algorithm_name == "cubic" {
            12000
        } else {
            15030
        }
    );

    assert_eq!(pipe.server.stream_send(0, &buf[..5000], false), Ok(5000));
    assert_eq!(pipe.server.stream_send(4, &buf[..5000], false), Ok(5000));
    // Offer enough bytes on the third stream that the connection-level
    // `tx_cap` is the binding constraint rather than the input buffer;
    // this keeps the test invariant "no connection send capacity left after
    // three sends" true across backends with different handshake sizes.
    assert_eq!(
        pipe.server.stream_send(8, &buf[..6000], false),
        if cc_algorithm_name == "cubic" {
            Ok(2000)
        } else {
            Ok(5030)
        }
    );

    // No more connection send capacity.
    assert_eq!(
        pipe.server.stream_send(12, &buf[..5000], false),
        Err(Error::Done)
    );
    assert_eq!(pipe.server.tx_cap, 0);

    assert_eq!(pipe.advance(), Ok(()));
    Ok(())
}

#[cfg(feature = "boringssl-btls-crate")]
#[rstest]
fn user_provided_boring_ctx(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    // Manually construct boring ssl ctx for server
    let mut server_tls_ctx_builder =
        btls::ssl::SslContextBuilder::new(btls::ssl::SslMethod::tls())?;
    server_tls_ctx_builder.set_certificate_chain_file("examples/cert.crt")?;
    server_tls_ctx_builder
        .set_private_key_file("examples/cert.key", btls::ssl::SslFiletype::PEM)?;

    let mut server_config = Config::with_btls_ssl_ctx_builder(
        PROTOCOL_VERSION,
        server_tls_ctx_builder,
    )?;
    let mut client_config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(
        client_config.set_cc_algorithm_name(cc_algorithm_name),
        Ok(())
    );
    client_config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    client_config.load_priv_key_from_pem_file("examples/cert.key")?;

    for config in [&mut client_config, &mut server_config] {
        config.set_application_protos(&[b"proto1", b"proto2"])?;
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_max_idle_timeout(180_000);
        config.verify_peer(false);
        config.set_ack_delay_exponent(8);
    }

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )?;

    assert_eq!(pipe.handshake(), Ok(()));

    Ok(())
}

#[cfg(feature = "boringssl-btls-crate")]
#[rstest]
fn handshake_callback_state_is_not_retained(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    for conn in [&mut pipe.client, &mut pipe.server] {
        assert_eq!(
            <Connection>::set_hystart_in_handshake(conn.as_mut(), true),
            Err(Error::TlsFail),
        );
        assert_eq!(
            <Connection>::set_max_idle_timeout_in_handshake(conn.as_mut(), 1000),
            Err(Error::TlsFail),
        );
        assert_eq!(
            <Connection>::set_initial_max_streams_bidi_in_handshake(
                conn.as_mut(),
                10
            ),
            Err(Error::TlsFail),
        );
    }
    pipe.handshake()?;
    for conn in [&mut pipe.client, &mut pipe.server] {
        assert_eq!(
            <Connection>::set_hystart_in_handshake(conn.as_mut(), true),
            Err(Error::TlsFail),
        );
        assert_eq!(
            <Connection>::set_max_idle_timeout_in_handshake(conn.as_mut(), 1000),
            Err(Error::TlsFail),
        );
        assert_eq!(
            <Connection>::set_initial_max_streams_bidi_in_handshake(
                conn.as_mut(),
                10
            ),
            Err(Error::TlsFail),
        );
    }
    Ok(())
}

#[cfg(feature = "boringssl-btls-crate")]
#[rstest]
fn in_handshake_config(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] use_session: bool,
    #[values(false, true)] enable_early_data: bool,
) -> TestResult {
    const CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS: usize = 30;
    const CUSTOM_INITIAL_MAX_STREAMS_BIDI: u64 = 30;
    const CUSTOM_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(3);

    let mut buf = vec![0; 65_535];

    let custom_cc_algorithm = if cc_algorithm_name == "cubic" {
        CongestionControlAlgorithm::Bbr2Gcongestion
    } else {
        CongestionControlAlgorithm::Cubic
    };

    // Manually construct `SslContextBuilder` for the server so we can modify
    // CWND during the handshake.
    let mut server_tls_ctx_builder =
        btls::ssl::SslContextBuilder::new(btls::ssl::SslMethod::tls())?;
    server_tls_ctx_builder.set_certificate_chain_file("examples/cert.crt")?;
    server_tls_ctx_builder
        .set_private_key_file("examples/cert.key", btls::ssl::SslFiletype::PEM)?;
    server_tls_ctx_builder.set_select_certificate_callback(move |mut hello| {
        <Connection>::set_cc_algorithm_in_handshake(
            hello.ssl_mut(),
            custom_cc_algorithm,
        )
        .map_err(|_| btls::ssl::SelectCertError::ERROR)?;

        <Connection>::set_initial_congestion_window_packets_in_handshake(
            hello.ssl_mut(),
            CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS,
        )
        .map_err(|_| btls::ssl::SelectCertError::ERROR)?;

        <Connection>::set_max_send_udp_payload_size_in_handshake(
            hello.ssl_mut(),
            0,
        )
        .map_err(|_| btls::ssl::SelectCertError::ERROR)?;

        <Connection>::set_max_idle_timeout_in_handshake(
            hello.ssl_mut(),
            CUSTOM_MAX_IDLE_TIMEOUT.as_secs() * 1_000,
        )
        .map_err(|_| btls::ssl::SelectCertError::ERROR)?;

        <Connection>::set_initial_max_streams_bidi_in_handshake(
            hello.ssl_mut(),
            CUSTOM_INITIAL_MAX_STREAMS_BIDI,
        )
        .map_err(|_| btls::ssl::SelectCertError::ERROR)?;

        Ok(())
    });

    let mut server_config = Config::with_btls_ssl_ctx_builder(
        PROTOCOL_VERSION,
        server_tls_ctx_builder,
    )?;
    assert_eq!(
        server_config.set_cc_algorithm_name(cc_algorithm_name),
        Ok(())
    );

    // Test drives the handshake one packet at a time; requires a
    // single-Initial ClientHello.
    let mut client_config = test_utils::config_no_pq(PROTOCOL_VERSION)?;
    client_config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    client_config.load_priv_key_from_pem_file("examples/cert.key")?;

    for config in [&mut client_config, &mut server_config] {
        config.set_application_protos(&[b"proto1", b"proto2"])?;
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_max_idle_timeout(180_000);
        config.verify_peer(false);
        config.set_ack_delay_exponent(8);

        if enable_early_data {
            config.enable_early_data();
        }
    }

    let session = if use_session {
        let mut pipe = test_utils::Pipe::with_client_and_server_config(
            &mut client_config,
            &mut server_config,
        )?;

        assert_eq!(pipe.handshake(), Ok(()));

        Some(
            pipe.client
                .session()
                .ok_or("TLS session was not issued")?
                .to_vec(),
        )
    } else {
        None
    };

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )?;

    if let Some(session) = session {
        pipe.client.set_session(&session)?;
    }

    // Client sends initial flight.
    let (len, _) = pipe.client.send(&mut buf)?;

    assert_eq!(pipe.server.tx_cap, 0);

    // Server receives client's initial flight and updates its config.
    pipe.server_recv(&mut buf[..len])?;

    assert_eq!(
        pipe.server.is_in_early_data(),
        use_session && enable_early_data
    );
    assert_eq!(
        pipe.server.recovery_config.cc_algorithm,
        custom_cc_algorithm
    );
    assert_eq!(
        pipe.server.recovery_config.max_send_udp_payload_size,
        DEFAULT_SEND_UDP_PAYLOAD_SIZE
    );
    assert_eq!(
        pipe.server.paths.get_active()?.recovery.cwnd(),
        CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS * 1200
    );

    assert_eq!(
        pipe.server.tx_cap,
        CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS * 1200
    );

    assert_eq!(pipe.server.idle_timeout(), Some(CUSTOM_MAX_IDLE_TIMEOUT));

    // Server sends initial flight.
    let (len, _) = pipe.server.send(&mut buf)?;
    pipe.client_recv(&mut buf[..len])?;

    // Ensure the client received the new transport parameters.
    assert_eq!(pipe.client.idle_timeout(), Some(CUSTOM_MAX_IDLE_TIMEOUT));

    assert_eq!(
        pipe.client.peer_streams_left_bidi(),
        CUSTOM_INITIAL_MAX_STREAMS_BIDI
    );

    assert_eq!(pipe.handshake(), Ok(()));
    assert_eq!(pipe.server.is_resumed(), use_session);

    Ok(())
}

#[cfg(feature = "boringssl-btls-crate")]
#[rstest]
/// Tests that the `MAX_STREAMS` threshold is recalculated after a handshake
/// callback changes `initial_max_streams_bidi`.
fn max_streams_threshold_after_handshake_callback_update(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    // The original value of four yields a threshold of two.
    const CONFIG_INITIAL_MAX_STREAMS_BIDI: u64 = 4;
    // The callback value of 100 yields a threshold of 50.
    const CALLBACK_INITIAL_MAX_STREAMS_BIDI: u64 = 100;

    let mut buf = vec![0; 65_535];

    // Configure a server callback that changes `initial_max_streams_bidi`.
    let mut server_tls_ctx_builder = test_utils::Pipe::default_tls_ctx_builder()?;
    server_tls_ctx_builder.set_select_certificate_callback(|mut hello| {
        // Change `initial_max_streams_bidi` from 4 to 100 during the handshake.
        <Connection>::set_initial_max_streams_bidi_in_handshake(
            hello.ssl_mut(),
            CALLBACK_INITIAL_MAX_STREAMS_BIDI,
        )
        .map_err(|_| btls::ssl::SelectCertError::ERROR)?;

        Ok(())
    });

    let mut server_config = Config::with_btls_ssl_ctx_builder(
        PROTOCOL_VERSION,
        server_tls_ctx_builder,
    )?;

    // Test drives the handshake one packet at a time; requires a
    // single-Initial ClientHello.
    let mut client_config =
        test_utils::Pipe::default_config_no_pq(cc_algorithm_name)?;

    for config in [&mut client_config, &mut server_config] {
        config.set_application_protos(&[b"proto1", b"proto2"])?;
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1000);
        // The server configuration uses `CONFIG_INITIAL_MAX_STREAMS_BIDI`, but
        // the callback changes it to `CALLBACK_INITIAL_MAX_STREAMS_BIDI`.
        config.set_initial_max_streams_bidi(CONFIG_INITIAL_MAX_STREAMS_BIDI);
        config.set_cc_algorithm_name(cc_algorithm_name)?;
        config.verify_peer(false);
    }

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )?;

    // Complete the handshake and verify that the client received the callback's
    // `CALLBACK_INITIAL_MAX_STREAMS_BIDI` value.
    let (len, _) = pipe.client.send(&mut buf)?;
    pipe.server_recv(&mut buf[..len])?;

    let (len, _) = pipe.server.send(&mut buf)?;
    pipe.client_recv(&mut buf[..len])?;

    assert_eq!(
        pipe.client.peer_streams_left_bidi(),
        CALLBACK_INITIAL_MAX_STREAMS_BIDI
    );

    assert_eq!(pipe.handshake(), Ok(()));

    let pre_threshold_streams = CALLBACK_INITIAL_MAX_STREAMS_BIDI / 2 - 1;
    // Complete 49 streams to reduce the available count to 51. The correct
    // threshold of 50 does not send MAX_STREAMS yet, while the incorrect
    // threshold of two sends it too early.
    for i in 0..pre_threshold_streams {
        let stream_id = i * 4;
        pipe.client.stream_send(stream_id, b"a", true).ok();
    }
    pipe.advance().ok();

    for i in 0..pre_threshold_streams {
        let stream_id = i * 4;
        pipe.server.stream_recv(stream_id, &mut buf).ok();
        pipe.server.stream_send(stream_id, b"b", true).ok();
    }
    pipe.advance().ok();

    for i in 0..pre_threshold_streams {
        let stream_id = i * 4;
        pipe.client.stream_recv(stream_id, &mut buf).ok();
    }
    pipe.advance().ok();

    assert_eq!(
        pipe.server.streams.quota(Bidirectional).next_local_limit(),
        CALLBACK_INITIAL_MAX_STREAMS_BIDI + pre_threshold_streams
    );

    // Verify that MAX_STREAMS was not sent while availability exceeds the
    // threshold. The incorrect threshold would already have sent it and given
    // the client more available streams.
    assert_eq!(
        pipe.client.streams.quota(Bidirectional).peer_available(),
        CALLBACK_INITIAL_MAX_STREAMS_BIDI - pre_threshold_streams,
        "MAX_STREAMS should NOT have been sent yet."
    );

    // Complete one more stream to reach the threshold of 50. MAX_STREAMS should
    // now be sent.
    let stream_id = pre_threshold_streams * 4;
    pipe.client.stream_send(stream_id, b"a", true).ok();
    pipe.advance().ok();

    pipe.server.stream_recv(stream_id, &mut buf).ok();
    pipe.server.stream_send(stream_id, b"b", true).ok();
    pipe.advance().ok();

    pipe.client.stream_recv(stream_id, &mut buf).ok();
    pipe.advance().ok();

    // The server's next limit should have increased by one.
    assert_eq!(
        pipe.server.streams.quota(Bidirectional).next_local_limit(),
        CALLBACK_INITIAL_MAX_STREAMS_BIDI + CALLBACK_INITIAL_MAX_STREAMS_BIDI / 2
    );

    // Verify that MAX_STREAMS was sent once availability reached the threshold.
    // With the incorrect threshold of two, this test would never send it.
    let streams_left = pipe.client.streams.quota(Bidirectional).peer_available();
    assert!(
        streams_left > CALLBACK_INITIAL_MAX_STREAMS_BIDI / 2 + 1,
        "MAX_STREAMS was not sent when available hit the correct threshold (50)"
    );
    Ok(())
}

/// Tests that the initial flow control window equals `initial_max_data`
/// for both connection and stream level.
#[test]
fn initial_max_data_is_flow_control_win() -> TestResult {
    let mut config = test_utils::Pipe::default_config("cubic")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(500_000);
    config.set_initial_max_stream_data_bidi_local(500_000);
    config.set_initial_max_streams_bidi(10);
    config.verify_peer(false);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Both sides use initial_max_data as their connection flow control
    // window.
    assert_eq!(pipe.server.flow_control.window(), 1_000_000);
    assert_eq!(pipe.client.flow_control.window(), 1_000_000);

    // Create a new stream
    pipe.client.stream_send(0, &[1, 2, 3], false)?;
    assert_eq!(pipe.advance(), Ok(()));

    // Stream flow control windows equal initial_max_stream_data.
    assert_eq!(
        pipe.client
            .get_or_create_stream(0, stream::StreamOpenIntent::Local)?
            .recv
            .flow_control_for_tests()
            .window(),
        500_000
    );
    assert_eq!(
        pipe.server
            .get_or_create_stream(0, stream::StreamOpenIntent::Peer)?
            .recv
            .flow_control_for_tests()
            .window(),
        500_000
    );
    Ok(())
}

#[rstest]
fn initial_cwnd(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    const CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS: usize = 30;

    let mut config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config.set_initial_congestion_window_packets(
        CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS,
    );
    // From Pipe::new()
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(1_000_000);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);
    config.set_initial_max_streams_uni(3);
    config.set_max_idle_timeout(180_000);
    config.verify_peer(false);
    config.set_ack_delay_exponent(8);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    if cc_algorithm_name == "cubic" {
        assert_eq!(
            pipe.server.tx_cap,
            CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS * 1200
        );
    } else {
        const TOLERANCE: usize = 4;

        // For BBR2 in Startup mode the cwnd grows by exactly
        // `bytes_acked` per ACK (see `BBRv2::update_congestion_window`),
        // so `tx_cap` here equals `initial_cwnd` plus the bytes the
        // server sent during the handshake that have already been
        // acknowledged. That total varies a byte or two across architectures,
        // primarily because the ACK frame's `ack_delay` field is a VarInt
        // of microseconds since receipt and the elapsed time differs by a
        // tick or two between platforms.
        //
        // Pin the lower bound (catches gross regressions like initial
        // cwnd not being honored) and allow a small upper-bound
        // tolerance, well below a packet so any meaningful regression
        // would still trip the assertion.
        // Handshake size (and hence the extra acked bytes on top of
        // `initial_cwnd`) includes an extra packet because the
        // ClientHello carries a post-quantum key share by default.
        let expected = CUSTOM_INITIAL_CONGESTION_WINDOW_PACKETS * 1200 + 2600;

        assert!(
            pipe.server.tx_cap >= expected,
            "{} vs {expected}",
            pipe.server.tx_cap
        );
        assert!(
            pipe.server.tx_cap <= expected + TOLERANCE,
            "{} vs {}",
            pipe.server.tx_cap,
            expected + TOLERANCE
        );
    }

    Ok(())
}

#[rstest]
/// Tests that resetting a stream restores flow control for unsent data.
fn last_tx_data_larger_than_tx_data(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    assert_eq!(config.set_cc_algorithm_name(cc_algorithm_name), Ok(()));
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(12000);
    config.set_initial_max_stream_data_bidi_local(20000);
    config.set_initial_max_stream_data_bidi_remote(20000);
    config.set_max_recv_udp_payload_size(1200);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client opens stream 4 and 8.
    assert_eq!(pipe.client.stream_send(4, b"a", true), Ok(1));
    assert_eq!(pipe.client.stream_send(8, b"b", true), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Server reads stream data.
    stream_recv_discard(&mut pipe.server, discard, 4)?;

    // Server sends stream data close to cwnd (12000).
    let buf = [0; 10000];
    assert_eq!(pipe.server.stream_send(4, &buf, false), Ok(10000));

    test_utils::emit_flight(&mut pipe.server)?;

    // Server buffers some data, until send capacity limit reached.
    let mut buf = [0; 1200];
    assert_eq!(pipe.server.stream_send(4, &buf, false), Ok(1200));
    assert_eq!(pipe.server.stream_send(8, &buf, false), Ok(800));
    assert_eq!(pipe.server.stream_send(4, &buf, false), Err(Error::Done));

    // Wait for PTO to expire.
    let timer = pipe.server.timeout().ok_or("connection timer not armed")?;
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.server.on_timeout();

    // Server sends PTO probe (not limited to cwnd),
    // to update last_tx_data.
    let (len, _) = pipe.server.send(&mut buf)?;
    assert_eq!(len, 1200);

    // Client sends STOP_SENDING to decrease tx_data
    // by unsent data. It will make last_tx_data > tx_data
    // and trigger #1232 bug.
    let frames = [frame::Frame::StopSending {
        stream_id: 4,
        error_code: 42,
    }];

    let pkt_type = Type::Short;
    pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;
    Ok(())
}

/// Tests that when the client provides a new `ConnectionId`, it eventually
/// reaches the server and notifies the application.
fn cid_exchange_pipe(
    cc_algorithm_name: &str, limit: u64,
) -> TestResult<test_utils::Pipe> {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(limit);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    pipe.handshake()?;
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), usize::try_from(limit - 1)?);
    Ok(pipe)
}

fn exchange_client_cid(
    pipe: &mut test_utils::Pipe, seq: u64, remaining: usize,
) -> TestResult {
    let (scid, reset_token) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid, reset_token, false), Ok(seq));
    pipe.advance()?;
    assert_eq!(pipe.server.available_dcids(), usize::try_from(seq)?);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), remaining);
    Ok(())
}

#[rstest]
fn send_connection_ids(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut pipe = cid_exchange_pipe(cc_algorithm_name, 3)?;
    exchange_client_cid(&mut pipe, 1, 1)?;
    exchange_client_cid(&mut pipe, 2, 0)?;

    // If now the client tries to send another CID, it reports an error
    // since it exceeds the limit of active CIDs.
    let (scid, reset_token) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(
        pipe.client.new_scid(&scid, reset_token, false),
        Err(Error::IdLimit),
    );
    Ok(())
}

#[rstest]
/// Tests that `NEW_CONNECTION_ID` with invalid CID lengths is rejected.
fn connection_id_invalid_length(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(0, MAX_CONN_ID_LEN + 1)] cid_len: usize,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let (scid, reset_token) = test_utils::create_cid_and_reset_token(cid_len);
    let mut payload = [0; 64];
    let mut writer = octets::OctetsMut::with_slice(&mut payload);
    writer.put_varint(0x18)?; // NEW_CONNECTION_ID
    writer.put_varint(1)?;
    writer.put_varint(0)?;
    writer.put_u8(u8::try_from(cid_len)?)?;
    writer.put_bytes(&scid)?;
    writer.put_bytes(&reset_token.to_be_bytes())?;
    let len = writer.off();
    let written = test_utils::encode_raw_pkt(
        &mut pipe.client,
        Type::Short,
        &payload[..len],
        &mut buf,
    )?;

    assert_rejected_packet(
        &mut pipe,
        &mut buf,
        written,
        Error::InvalidFrame,
        0x7,
    )?;
    Ok(())
}

#[rstest]
/// Exercises the handling of `NEW_CONNECTION_ID` and `RETIRE_CONNECTION_ID`
/// frames.
fn connection_id_handling(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // So far, there should not have any QUIC event.
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), 1);

    let scid = pipe.client.source_id().clone();

    let (scid_1, reset_token_1) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid_1, reset_token_1, false), Ok(1));

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    // At this point, the server should be notified that it has a new CID.
    assert_eq!(pipe.server.available_dcids(), 1);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), 0);

    // Now we assume that the client wants to advertise more source
    // Connection IDs than the advertised limit. This is valid if it
    // requests its peer to retire enough Connection IDs to fit within the
    // limits.

    let (scid_2, reset_token_2) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid_2, reset_token_2, true), Ok(2));

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    // At this point, the server still have a spare DCID.
    assert_eq!(pipe.server.available_dcids(), 1);
    assert_eq!(pipe.server.path_event_next(), None);

    // Client should have received a retired notification.
    assert_eq!(pipe.client.retired_scid_next(), Some(scid));
    assert_eq!(pipe.client.retired_scid_next(), None);

    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.client.scids_left(), 0);

    // The active Destination Connection ID of the server should now be the
    // one with sequence number 1.
    assert_eq!(pipe.server.destination_id(), &scid_1);

    // Now tries to experience CID retirement. If the server tries to remove
    // non-existing DCIDs, it fails.
    assert_eq!(pipe.server.retire_dcid(0), Err(Error::InvalidState));
    assert_eq!(pipe.server.retire_dcid(3), Err(Error::InvalidState));

    // Now it removes DCID with sequence 1.
    assert_eq!(pipe.server.retire_dcid(1), Ok(()));

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.retired_scid_next(), Some(scid_1));
    assert_eq!(pipe.client.retired_scid_next(), None);

    assert_eq!(pipe.server.destination_id(), &scid_2);
    assert_eq!(pipe.server.available_dcids(), 0);

    // Trying to remove the last DCID triggers an error.
    assert_eq!(pipe.server.retire_dcid(2), Err(Error::OutOfIdentifiers));
    Ok(())
}

#[rstest]
fn lost_connection_id_frames(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let scid = pipe.client.source_id().clone();

    let (scid_1, reset_token_1) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid_1, reset_token_1, false), Ok(1));

    // Packets are sent, but never received.
    test_utils::emit_flight(&mut pipe.client)?;

    // Wait until timer expires. Since the RTT is very low, wait a bit more.
    let timer = pipe.client.timeout().ok_or("connection timer not armed")?;
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.client.on_timeout();

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    // At this point, the server should be notified that it has a new CID.
    assert_eq!(pipe.server.available_dcids(), 1);

    // Now the server retires the first Destination CID.
    assert_eq!(pipe.server.retire_dcid(0), Ok(()));

    // But the packet never reaches the client.
    test_utils::emit_flight(&mut pipe.server)?;

    // Wait until timer expires. Since the RTT is very low, wait a bit more.
    let timer = pipe.server.timeout().ok_or("connection timer not armed")?;
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.server.on_timeout();

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.client.retired_scid_next(), Some(scid));
    assert_eq!(pipe.client.retired_scid_next(), None);
    Ok(())
}

#[rstest]
fn sending_duplicate_scids(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(3);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let (scid_1, reset_token_1) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid_1, reset_token_1, false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));

    // Trying to send the same CID with a different reset token raises an
    // InvalidState error.
    let reset_token_2 = reset_token_1.wrapping_add(1);
    assert_eq!(
        pipe.client.new_scid(&scid_1, reset_token_2, false),
        Err(Error::InvalidState),
    );

    // Retrying to send the exact same CID with the same token returns the
    // previously assigned CID seq, but without sending anything.
    assert_eq!(pipe.client.new_scid(&scid_1, reset_token_1, false), Ok(1));
    assert!(!pipe.client.ids.has_new_scids());

    // Now retire this new CID.
    assert_eq!(pipe.server.retire_dcid(1), Ok(()));
    assert_eq!(pipe.advance(), Ok(()));

    // It is up to the application to ensure that a given SCID is not reused
    // later.
    assert_eq!(pipe.client.new_scid(&scid_1, reset_token_1, false), Ok(2));
    Ok(())
}

#[rstest]
/// Tests the limit to retired DCID sequence numbers.
fn connection_id_retire_limit(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = cid_exchange_pipe(cc_algorithm_name, 2)?;
    exchange_client_cid(&mut pipe, 1, 0)?;

    let mut frames = Vec::new();

    // Client retires more than 3x the number of allowed active CIDs.
    for i in 2..=7 {
        let (scid, reset_token) = test_utils::create_cid_and_reset_token(16);

        frames.push(frame::Frame::NewConnectionId {
            seq_num: i,
            retire_prior_to: i,
            conn_id: scid.clone(),
            reset_token: reset_token.to_be_bytes(),
        });
    }

    let pkt_type = Type::Short;

    let written =
        test_utils::encode_pkt(&mut pipe.client, pkt_type, &frames, &mut buf)?;

    assert_rejected_packet(&mut pipe, &mut buf, written, Error::IdLimit, 0x9)?;
    Ok(())
}

#[rstest]
fn large_advertised_connection_id_limit_preserves_slots(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    const LIMIT: u64 = 1_u64 << 32;
    let mut config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    config.set_active_connection_id_limit(LIMIT);
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    pipe.handshake()?;
    let limit = usize::try_from(LIMIT)
        .unwrap_or(usize::MAX)
        .min(usize::MAX / 2);
    assert_eq!(
        pipe.client.peer_parameters.effective().active_conn_id_limit,
        LIMIT
    );
    assert_eq!(pipe.client.scids_left(), limit - 1);
    let (scid, token) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid, token, false), Ok(1));
    pipe.advance()?;
    assert_eq!(pipe.client.scids_left(), limit - 2);
    assert_eq!(pipe.server.available_dcids(), 1);
    Ok(())
}

#[rstest]
fn avoid_scids_left_underflow_during_rotation(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    // Default active_conn_id_limit is 2, sufficient to trigger the rotation.
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Fill up to the advertised limit.
    let (scid_1, token_1) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid_1, token_1, false), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.client.scids_left(), 0);

    // Issue a new SCID with retire_prior_to=true. This forces a rotation:
    // the client now holds 3 SCIDs internally (seq 0 retiring, seq 1, seq 2)
    // while the advertised limit is still 2. active_scids() = 3,
    // max_active_source_cids = 2 => underflow.
    let (scid_2, token_2) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.client.new_scid(&scid_2, token_2, true), Ok(2));

    // Before advancing (retirement not yet acknowledged), active_scids()
    // exceeds the advertised limit. scids_left() should return 0.
    let active = pipe.client.active_scids();
    let left = pipe.client.scids_left();

    assert!(
        active > 2,
        "expected active_scids ({active}) > limit (2) during rotation"
    );
    assert_eq!(
        left, 0,
        "scids_left() should be 0 during rotation but returned {left}"
    );
    Ok(())
}

#[rstest]
fn connection_id_retire_exotic_sequence(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_uni(3);
    config.set_initial_max_streams_bidi(3);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Inject an exotic sequence of NEW_CONNECTION_ID frames, unbeknowst to
    // quiche client connection object.
    let frames = [
        frame::Frame::NewConnectionId {
            seq_num: 8,
            retire_prior_to: 1,
            conn_id: ConnectionId::copy_from_slice(&[0]),
            reset_token: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        },
        frame::Frame::NewConnectionId {
            seq_num: 1,
            retire_prior_to: 0,
            conn_id: ConnectionId::copy_from_slice(&[2]),
            reset_token: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        },
        frame::Frame::NewConnectionId {
            seq_num: 6,
            retire_prior_to: 6,
            conn_id: ConnectionId::copy_from_slice(&[0x15]),
            reset_token: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
        },
        frame::Frame::NewConnectionId {
            seq_num: 8,
            retire_prior_to: 1,
            conn_id: ConnectionId::copy_from_slice(&[0]),
            reset_token: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        },
        frame::Frame::NewConnectionId {
            seq_num: 48,
            retire_prior_to: 8,
            conn_id: ConnectionId::copy_from_slice(&[1]),
            reset_token: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5],
        },
    ];

    let pkt_type = Type::Short;
    pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;

    // Ensure operations continue to be allowed.
    assert_eq!(pipe.client.stream_send(0, b"data", true), Ok(4));
    assert_eq!(pipe.server.stream_send(1, b"data", true), Ok(4));
    assert_eq!(pipe.client.stream_send(2, b"data", true), Ok(4));
    assert_eq!(pipe.server.stream_send(3, b"data", true), Ok(4));

    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 0),
        Ok((4, true))
    );
    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 2),
        Ok((4, true))
    );

    // The exotic sequence insertion messes with the client object's
    // worldview so we can't check its side of things.
    Ok(())
}

// Utility function.
fn pipe_with_exchanged_cids(
    config: &mut Config, client_scid_len: usize, server_scid_len: usize,
    additional_cids: usize,
) -> TestResult<test_utils::Pipe> {
    let mut pipe = test_utils::Pipe::with_config_and_scid_lengths(
        config,
        client_scid_len,
        server_scid_len,
    )?;
    assert_eq!(pipe.handshake(), Ok(()));

    let mut c_cids = Vec::new();
    let mut c_reset_tokens = Vec::new();
    let mut s_cids = Vec::new();
    let mut s_reset_tokens = Vec::new();

    for i in 0..additional_cids {
        if client_scid_len > 0 {
            let (c_cid, c_reset_token) =
                test_utils::create_cid_and_reset_token(client_scid_len);
            c_cids.push(c_cid);
            c_reset_tokens.push(c_reset_token);

            assert_eq!(
                pipe.client.new_scid(&c_cids[i], c_reset_tokens[i], true),
                Ok(i as u64 + 1)
            );
        }

        if server_scid_len > 0 {
            let (s_cid, s_reset_token) =
                test_utils::create_cid_and_reset_token(server_scid_len);
            s_cids.push(s_cid);
            s_reset_tokens.push(s_reset_token);
            assert_eq!(
                pipe.server.new_scid(&s_cids[i], s_reset_tokens[i], true),
                Ok(i as u64 + 1)
            );
        }
    }

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    if client_scid_len > 0 {
        assert_eq!(pipe.server.available_dcids(), additional_cids);
    }

    if server_scid_len > 0 {
        assert_eq!(pipe.client.available_dcids(), additional_cids);
    }

    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.path_event_next(), None);

    Ok(pipe)
}

#[rstest]
fn path_validation(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse()?;

    // We cannot probe a new path if there are not enough identifiers.
    assert_eq!(
        pipe.client.probe_path(client_addr_2, server_addr),
        Err(Error::OutOfIdentifiers)
    );

    let (c_cid, c_reset_token) = test_utils::create_cid_and_reset_token(16);

    assert_eq!(pipe.client.new_scid(&c_cid, c_reset_token, true), Ok(1));

    let (s_cid, s_reset_token) = test_utils::create_cid_and_reset_token(16);
    assert_eq!(pipe.server.new_scid(&s_cid, s_reset_token, true), Ok(1));

    // We need to exchange the CIDs first.
    assert_eq!(
        pipe.client.probe_path(client_addr_2, server_addr),
        Err(Error::OutOfIdentifiers)
    );

    // Let exchange packets over the connection.
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(pipe.server.available_dcids(), 1);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.client.available_dcids(), 1);
    assert_eq!(pipe.client.path_event_next(), None);

    // Now the path probing can work.
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));

    // But the server cannot probe a yet-unseen path.
    assert_eq!(
        pipe.server.probe_path(server_addr, client_addr_2),
        Err(Error::InvalidState),
    );

    assert_eq!(pipe.advance(), Ok(()));

    // The path should be validated at some point.
    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::Validated(client_addr_2, server_addr)),
    );
    assert_eq!(pipe.client.path_event_next(), None);

    // The server should be notified of this new path.
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server_addr, client_addr_2)),
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::Validated(server_addr, client_addr_2)),
    );
    assert_eq!(pipe.server.path_event_next(), None);

    // The server can later probe the path again.
    assert_eq!(pipe.server.probe_path(server_addr, client_addr_2), Ok(1));

    // This should not trigger any event at client side.
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.server.path_event_next(), None);
    Ok(())
}

#[rstest]
fn losing_probing_packets(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1)?;

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse()?;
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));

    // The client creates the PATH CHALLENGE, but it is lost.
    test_utils::emit_flight(&mut pipe.client)?;

    // Wait until probing timer expires. Since the RTT is very low,
    // wait a bit more.
    let probed_pid = pipe
        .client
        .paths
        .path_id_from_addrs(&(client_addr_2, server_addr))
        .ok_or("expected path is absent")?;
    let probe_instant = pipe
        .client
        .paths
        .get(probed_pid)?
        .recovery
        .loss_detection_timer()
        .ok_or("loss detection timer not armed")?;
    let timer = probe_instant.duration_since(Instant::now());
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.client.on_timeout();

    assert_eq!(pipe.advance(), Ok(()));

    // The path should be validated at some point.
    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::Validated(client_addr_2, server_addr))
    );
    assert_eq!(pipe.client.path_event_next(), None);

    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server_addr, client_addr_2))
    );
    // The path should be validated at some point.
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::Validated(server_addr, client_addr_2))
    );
    assert_eq!(pipe.server.path_event_next(), None);
    Ok(())
}

#[rstest]
fn failed_path_validation(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1)?;

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse()?;
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));

    for _ in 0..MAX_PROBING_TIMEOUTS {
        // The client creates the PATH CHALLENGE, but it is always lost.
        test_utils::emit_flight(&mut pipe.client)?;

        // Wait until probing timer expires. Since the RTT is very low,
        // wait a bit more.
        let probed_pid = pipe
            .client
            .paths
            .path_id_from_addrs(&(client_addr_2, server_addr))
            .ok_or("expected path is absent")?;
        let probe_instant = pipe
            .client
            .paths
            .get(probed_pid)?
            .recovery
            .loss_detection_timer()
            .ok_or("loss detection timer not armed")?;
        let timer = probe_instant.duration_since(Instant::now());
        std::thread::sleep(timer + Duration::from_millis(1));

        pipe.client.on_timeout();
    }

    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::FailedValidation(client_addr_2, server_addr)),
    );
    Ok(())
}

#[rstest]
fn client_discard_unknown_address(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_uni(3);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Server sends stream data.
    assert_eq!(pipe.server.stream_send(3, b"a", true), Ok(1));

    let mut flight = test_utils::emit_flight(&mut pipe.server)?;
    // Let's change the address info.
    for (_, si) in &mut flight {
        si.from = SocketAddr::from(([127, 0, 0, 1], 9292));
    }
    assert_eq!(test_utils::process_flight(&mut pipe.client, flight), Ok(()));
    assert_eq!(pipe.client.paths.len(), 1);
    Ok(())
}

#[rstest]
fn path_validation_limited_mtu(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1)?;

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse()?;
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));
    // Limited MTU of 1199 bytes for some reason.
    test_utils::process_flight(
        &mut pipe.server,
        test_utils::emit_flight_with_max_buffer(
            &mut pipe.client,
            1199,
            None,
            None,
        )?,
    )?;
    test_utils::process_flight(
        &mut pipe.client,
        test_utils::emit_flight(&mut pipe.server)?,
    )?;
    let probed_pid = pipe
        .client
        .paths
        .path_id_from_addrs(&(client_addr_2, server_addr))
        .ok_or("expected path is absent")?;
    assert!(!pipe.client.paths.get(probed_pid)?.validated(),);
    assert_eq!(pipe.client.path_event_next(), None);
    // Now let the client probe at its MTU.
    assert_eq!(pipe.advance(), Ok(()));
    assert!(pipe.client.paths.get(probed_pid)?.validated());
    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::Validated(client_addr_2, server_addr))
    );
    Ok(())
}

fn validate_secondary_path(
    pipe: &mut test_utils::Pipe, client: SocketAddr, server: SocketAddr,
) -> TestResult {
    assert_eq!(pipe.client.probe_path(client, server), Ok(1));
    pipe.advance()?;
    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::Validated(client, server))
    );
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server, client))
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::Validated(server, client))
    );
    assert_eq!(pipe.server.path_event_next(), None);
    Ok(())
}

#[rstest]
fn path_probing_dos(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1)?;

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse()?;
    validate_secondary_path(&mut pipe, client_addr_2, server_addr)?;

    assert_eq!(pipe.server.paths.len(), 2);

    // Now forge a packet reusing the unverified path's CID over another
    // 4-tuple.
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));
    let client_addr_3 = "127.0.0.1:9012".parse()?;
    let mut flight = test_utils::emit_flight(&mut pipe.client)?;
    for (_, si) in &mut flight {
        si.from = client_addr_3;
    }
    // Both paths have DCIDs, so `make_room_for_new_path()` cannot evict either
    // and returns `Error::Done`. `ReusedSourceConnectionId` is emitted only
    // after successful insertion, so no event is queued.
    test_utils::process_flight(&mut pipe.server, flight)?;
    assert_eq!(pipe.server.paths.len(), 2);
    assert_eq!(pipe.server.path_event_next(), None);
    Ok(())
}

#[rstest]
fn retiring_active_path_dcid(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1)?;
    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse()?;
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));

    assert_eq!(pipe.client.retire_dcid(0), Err(Error::OutOfIdentifiers));
    Ok(())
}

#[rstest]
fn send_on_path_test(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_initial_max_data(100_000);
    config.set_initial_max_stream_data_bidi_local(100_000);
    config.set_initial_max_stream_data_bidi_remote(100_000);
    config.set_initial_max_streams_bidi(2);
    config.set_active_connection_id_limit(4);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 3)?;

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr = test_utils::Pipe::client_addr();
    let client_addr_2 = "127.0.0.1:5678".parse()?;
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));

    let mut buf = vec![0; 65_535];
    // There is nothing to send on the initial path.
    assert_eq!(
        pipe.client
            .send_on_path(&mut buf, Some(client_addr), Some(server_addr)),
        Err(Error::Done)
    );

    // Client should send padded PATH_CHALLENGE.
    let (sent, si) = pipe.client.send_on_path(
        &mut buf,
        Some(client_addr_2),
        Some(server_addr),
    )?;
    assert_eq!(sent, MIN_CLIENT_INITIAL_LEN);
    assert_eq!(si.from, client_addr_2);
    assert_eq!(si.to, server_addr);

    let ri = RecvInfo {
        to: si.to,
        from: si.from,
    };
    assert_eq!(pipe.server.recv(&mut buf[..sent], ri), Ok(sent));

    let stats = pipe.server.stats();
    assert_eq!(stats.path_challenge_rx_count, 1);

    // A non-existing 4-tuple raises an InvalidState.
    let client_addr_3 = "127.0.0.1:9012".parse()?;
    let server_addr_2 = "127.0.0.1:9876".parse()?;
    assert_eq!(
        pipe.client.send_on_path(
            &mut buf,
            Some(client_addr_3),
            Some(server_addr)
        ),
        Err(Error::InvalidState)
    );
    assert_eq!(
        pipe.client.send_on_path(
            &mut buf,
            Some(client_addr),
            Some(server_addr_2)
        ),
        Err(Error::InvalidState)
    );

    // Let's introduce some additional path challenges and data exchange.
    assert_eq!(pipe.client.probe_path(client_addr, server_addr_2), Ok(2));
    assert_eq!(pipe.client.probe_path(client_addr_3, server_addr), Ok(3));
    // Just to fit in two packets.
    assert_eq!(pipe.client.stream_send(0, &buf[..1201], true), Ok(1201));

    // PATH_CHALLENGE
    let (sent, si) =
        pipe.client
            .send_on_path(&mut buf, Some(client_addr), None)?;
    assert_eq!(sent, MIN_CLIENT_INITIAL_LEN);
    assert_eq!(si.from, client_addr);
    assert_eq!(si.to, server_addr_2);

    let ri = RecvInfo {
        to: si.to,
        from: si.from,
    };
    assert_eq!(pipe.server.recv(&mut buf[..sent], ri), Ok(sent));

    let stats = pipe.server.stats();
    assert_eq!(stats.path_challenge_rx_count, 2);

    // STREAM frame on active path.
    let (sent, si) =
        pipe.client
            .send_on_path(&mut buf, Some(client_addr), None)?;
    assert_eq!(si.from, client_addr);
    assert_eq!(si.to, server_addr);

    let ri = RecvInfo {
        to: si.to,
        from: si.from,
    };
    assert_eq!(pipe.server.recv(&mut buf[..sent], ri), Ok(sent));

    let stats = pipe.server.stats();
    assert_eq!(stats.path_challenge_rx_count, 2);

    // PATH_CHALLENGE
    let (sent, si) =
        pipe.client
            .send_on_path(&mut buf, None, Some(server_addr))?;
    assert_eq!(sent, MIN_CLIENT_INITIAL_LEN);
    assert_eq!(si.from, client_addr_3);
    assert_eq!(si.to, server_addr);

    let ri = RecvInfo {
        to: si.to,
        from: si.from,
    };
    assert_eq!(pipe.server.recv(&mut buf[..sent], ri), Ok(sent));

    let stats = pipe.server.stats();
    assert_eq!(stats.path_challenge_rx_count, 3);

    // STREAM frame on active path.
    let (sent, si) =
        pipe.client
            .send_on_path(&mut buf, None, Some(server_addr))?;
    assert_eq!(si.from, client_addr);
    assert_eq!(si.to, server_addr);

    let ri = RecvInfo {
        to: si.to,
        from: si.from,
    };
    assert_eq!(pipe.server.recv(&mut buf[..sent], ri), Ok(sent));

    // No more data to exchange leads to Error::Done.
    assert_eq!(
        pipe.client.send_on_path(&mut buf, Some(client_addr), None),
        Err(Error::Done)
    );
    assert_eq!(
        pipe.client.send_on_path(&mut buf, None, Some(server_addr)),
        Err(Error::Done)
    );

    assert_eq!(pipe.advance(), Ok(()));

    let mut v1 = pipe.client.paths_iter(client_addr).collect::<Vec<_>>();
    let mut v2 = vec![server_addr, server_addr_2];

    v1.sort();
    v2.sort();

    assert_eq!(v1, v2);

    let mut v1 = pipe.client.paths_iter(client_addr_2).collect::<Vec<_>>();
    let mut v2 = vec![server_addr];

    v1.sort();
    v2.sort();

    assert_eq!(v1, v2);

    let mut v1 = pipe.client.paths_iter(client_addr_3).collect::<Vec<_>>();
    let mut v2 = vec![server_addr];

    v1.sort();
    v2.sort();

    assert_eq!(v1, v2);

    let stats = pipe.server.stats();
    assert_eq!(stats.path_challenge_rx_count, 3);
    Ok(())
}

fn assert_new_migration(
    pipe: &mut test_utils::Pipe, client: SocketAddr, server: SocketAddr,
) -> TestResult {
    assert_eq!(pipe.client.paths.get_active()?.local_addr(), client);
    assert_eq!(pipe.client.paths.get_active()?.peer_addr(), server);
    for event in [
        PathEvent::New(server, client),
        PathEvent::Validated(server, client),
        PathEvent::PeerMigrated(server, client),
    ] {
        assert_eq!(pipe.server.path_event_next(), Some(event));
    }
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.server.paths.get_active()?.local_addr(), server);
    assert_eq!(pipe.server.paths.get_active()?.peer_addr(), client);
    Ok(())
}

#[rstest]
fn connection_migration(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(3);
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 2)?;

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse()?;
    let client_addr_3 = "127.0.0.1:9012".parse()?;
    let client_addr_4 = "127.0.0.1:8908".parse()?;

    // Case 1: the client first probes the new address, the server too, and
    // then migrates.
    assert_eq!(pipe.client.probe_path(client_addr_2, server_addr), Ok(1));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::Validated(client_addr_2, server_addr))
    );
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server_addr, client_addr_2))
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::Validated(server_addr, client_addr_2))
    );
    assert_eq!(
        pipe.client.is_path_validated(client_addr_2, server_addr),
        Ok(true)
    );
    assert_eq!(
        pipe.server.is_path_validated(server_addr, client_addr_2),
        Ok(true)
    );
    // The server can never initiates the connection migration.
    assert_eq!(
        pipe.server.migrate(server_addr, client_addr_2),
        Err(Error::InvalidState)
    );
    assert_eq!(pipe.client.migrate(client_addr_2, server_addr), Ok(1));
    assert_eq!(pipe.client.stream_send(0, b"data", true), Ok(4));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.client.paths.get_active()?.local_addr(), client_addr_2);
    assert_eq!(pipe.client.paths.get_active()?.peer_addr(), server_addr);
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::PeerMigrated(server_addr, client_addr_2))
    );
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.server.paths.get_active()?.local_addr(), server_addr);
    assert_eq!(pipe.server.paths.get_active()?.peer_addr(), client_addr_2);

    // Case 2: the client migrates on a path that was not previously
    // validated, and has spare SCIDs/DCIDs to do so.
    assert_eq!(pipe.client.migrate(client_addr_3, server_addr), Ok(2));
    assert_eq!(pipe.client.stream_send(4, b"data", true), Ok(4));
    assert_eq!(pipe.advance(), Ok(()));
    assert_new_migration(&mut pipe, client_addr_3, server_addr)?;

    // Case 3: the client tries to migrate on the current active path.
    // This is not an error, but it triggers nothing.
    assert_eq!(pipe.client.migrate(client_addr_3, server_addr), Ok(2));
    assert_eq!(pipe.client.stream_send(8, b"data", true), Ok(4));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.client.path_event_next(), None);
    assert_eq!(pipe.client.paths.get_active()?.local_addr(), client_addr_3);
    assert_eq!(pipe.client.paths.get_active()?.peer_addr(), server_addr);
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.server.paths.get_active()?.local_addr(), server_addr);
    assert_eq!(pipe.server.paths.get_active()?.peer_addr(), client_addr_3);

    // Case 4: the client tries to migrate on a path that was not previously
    // validated, and has no spare SCIDs/DCIDs. Prevent active migration.
    assert_eq!(
        pipe.client.migrate(client_addr_4, server_addr),
        Err(Error::OutOfIdentifiers)
    );
    assert_eq!(pipe.client.paths.get_active()?.local_addr(), client_addr_3);
    assert_eq!(pipe.client.paths.get_active()?.peer_addr(), server_addr);
    Ok(())
}

#[rstest]
fn connection_migration_zero_length_cid(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 0, 16, 1)?;

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse()?;

    // The client migrates on a path that was not previously
    // validated, and has spare SCIDs/DCIDs to do so.
    assert_eq!(pipe.client.migrate(client_addr_2, server_addr), Ok(1));
    assert_eq!(pipe.client.stream_send(4, b"data", true), Ok(4));
    assert_eq!(pipe.advance(), Ok(()));
    assert_new_migration(&mut pipe, client_addr_2, server_addr)?;
    Ok(())
}

#[rstest]
fn connection_migration_reordered_non_probing(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1)?;

    let client_addr = test_utils::Pipe::client_addr();
    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse()?;

    validate_secondary_path(&mut pipe, client_addr_2, server_addr)?;

    // A first flight sent from secondary address.
    assert_eq!(pipe.client.stream_send(0, b"data", true), Ok(4));
    let mut first = test_utils::emit_flight(&mut pipe.client)?;
    for (_, si) in &mut first {
        si.from = client_addr_2;
    }
    // A second one, but sent from the original one.
    assert_eq!(pipe.client.stream_send(4, b"data", true), Ok(4));
    let second = test_utils::emit_flight(&mut pipe.client)?;
    // Second flight is received before first one.
    assert_eq!(test_utils::process_flight(&mut pipe.server, second), Ok(()));
    assert_eq!(test_utils::process_flight(&mut pipe.server, first), Ok(()));

    // Server does not perform connection migration because of packet
    // reordering.
    assert_eq!(pipe.server.path_event_next(), None);
    assert_eq!(pipe.server.paths.get_active()?.peer_addr(), client_addr);
    Ok(())
}

#[rstest]
fn resilience_against_migration_attack(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    const DATA_BYTES: usize = 24000;

    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(3);
    config.set_initial_max_data(100_000);
    config.set_initial_max_stream_data_bidi_local(100_000);
    config.set_initial_max_stream_data_bidi_remote(100_000);
    config.set_initial_max_streams_bidi(2);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1)?;

    let client_addr = test_utils::Pipe::client_addr();
    let server_addr = test_utils::Pipe::server_addr();
    let spoofed_client_addr = "127.0.0.1:6666".parse()?;

    let buf = vec![42; DATA_BYTES];
    let mut recv_buf = vec![0; DATA_BYTES];
    let send1_bytes = pipe.server.stream_send(1, &buf, true)?;
    assert_eq!(send1_bytes, match cc_algorithm_name {
        "bbr2" | "bbr2_gcongestion" => 15037,
        _ => 12000,
    });
    assert_eq!(
        test_utils::process_flight(
            &mut pipe.client,
            test_utils::emit_flight(&mut pipe.server)?
        ),
        Ok(())
    );
    let (rcv_data_1, _) = pipe.client.stream_recv(1, &mut recv_buf)?;

    // Fake the source address of client.
    let mut faked_addr_flight = test_utils::emit_flight(&mut pipe.client)?;
    for (_, si) in &mut faked_addr_flight {
        si.from = spoofed_client_addr;
    }
    assert_eq!(
        test_utils::process_flight(&mut pipe.server, faked_addr_flight),
        Ok(())
    );
    assert_eq!(
        pipe.server.stream_send(1, &buf[send1_bytes..], true),
        Ok(24000 - send1_bytes)
    );
    // PathEvent::New is emitted during insert_path(), then
    // ReusedSourceConnectionId is emitted after successful insertion.
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::New(server_addr, spoofed_client_addr))
    );
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::ReusedSourceConnectionId(
            0,
            (server_addr, client_addr),
            (server_addr, spoofed_client_addr)
        ))
    );

    assert_eq!(
        pipe.server.is_path_validated(server_addr, client_addr),
        Ok(true)
    );
    assert_eq!(
        pipe.server
            .is_path_validated(server_addr, spoofed_client_addr),
        Ok(false)
    );

    // The client creates the PATH CHALLENGE, but it is always lost.
    test_utils::emit_flight(&mut pipe.server)?;

    // Wait until probing timer expires. Since the RTT is very low,
    // wait a bit more.
    let probed_pid = pipe
        .server
        .paths
        .path_id_from_addrs(&(server_addr, spoofed_client_addr))
        .ok_or("expected path is absent")?;
    let probe_instant = pipe
        .server
        .paths
        .get(probed_pid)?
        .recovery
        .loss_detection_timer()
        .ok_or("loss detection timer not armed")?;
    let timer = probe_instant.duration_since(Instant::now());
    std::thread::sleep(timer + Duration::from_millis(1));

    pipe.server.on_timeout();

    // Because of the small ACK size, the server cannot send more to the
    // client. Fallback on the previous active path.
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::FailedValidation(
            server_addr,
            spoofed_client_addr
        ))
    );

    assert_eq!(
        pipe.server.is_path_validated(server_addr, client_addr),
        Ok(true)
    );
    assert_eq!(
        pipe.server
            .is_path_validated(server_addr, spoofed_client_addr),
        Ok(false)
    );

    let server_active_path = pipe.server.paths.get_active()?;
    assert_eq!(server_active_path.local_addr(), server_addr);
    assert_eq!(server_active_path.peer_addr(), client_addr);
    assert_eq!(pipe.advance(), Ok(()));
    let (rcv_data_2, fin) = pipe.client.stream_recv(1, &mut recv_buf)?;
    assert!(fin);
    assert_eq!(rcv_data_1 + rcv_data_2, DATA_BYTES);
    Ok(())
}

#[rstest]
fn reused_scid_existing_path_relinks_owner(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(3);

    let mut pipe = pipe_with_exchanged_cids(&mut config, 16, 16, 1)?;
    let server_addr = test_utils::Pipe::server_addr();
    let client_addr = test_utils::Pipe::client_addr();
    let reused_addr = "127.0.0.1:6666".parse()?;

    let original_pid = pipe
        .server
        .paths
        .path_id_from_addrs(&(server_addr, client_addr))
        .ok_or("expected path is absent")?;
    assert_eq!(pipe.server.ids.get_scid(0)?.path_id, Some(original_pid));

    let mut buf = [0u8; 1500];

    // The first packet creates a second path that reuses SCID 0. As before the
    // fast path existed, creation reports the reuse but leaves the SCID linked
    // to the original path until a packet arrives on the now-known 4-tuple.
    let written = test_utils::encode_pkt(
        &mut pipe.client,
        Type::Short,
        &[frame::Frame::Ping { mtu_probe: None }],
        &mut buf,
    )?;
    pipe.server.recv(&mut buf[..written], RecvInfo {
        to: server_addr,
        from: reused_addr,
    })?;

    let reused_pid = pipe
        .server
        .paths
        .path_id_from_addrs(&(server_addr, reused_addr))
        .ok_or("expected path is absent")?;
    assert_ne!(reused_pid, original_pid);
    assert_eq!(pipe.server.ids.get_scid(0)?.path_id, Some(original_pid));

    // On the existing reused path, preserve the original slow-path behavior:
    // relink the SCID entry to the path that just received it. The common-path
    // shortcut may return early only when this association already matches.
    let written = test_utils::encode_pkt(
        &mut pipe.client,
        Type::Short,
        &[frame::Frame::Ping { mtu_probe: None }],
        &mut buf,
    )?;
    pipe.server.recv(&mut buf[..written], RecvInfo {
        to: server_addr,
        from: reused_addr,
    })?;

    assert_eq!(pipe.server.ids.get_scid(0)?.path_id, Some(reused_pid));
    Ok(())
}

#[rstest]
fn path_event_queue_bounded_on_port_rotation(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    const N: u16 = 5000;

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    let server_addr = test_utils::Pipe::server_addr();
    let mut buf = [0u8; 1500];

    // Emulate an attack that sends N valid 1-RTT PING packets, each from a
    // fresh source port, all targeting the same server SCID.
    for port in 0..N {
        let written = test_utils::encode_pkt(
            &mut pipe.client,
            Type::Short,
            &[frame::Frame::Ping { mtu_probe: None }],
            &mut buf,
        )?;

        let info = RecvInfo {
            to: server_addr,
            from: format!("127.0.0.1:{}", 20000 + port).parse()?,
        };

        // Ignore errors - Error::Done is expected once path Slab is full.
        let _ = pipe.server.recv(&mut buf[..written], info);
    }

    // Path count is bounded by active_connection_id_limit (default 2).
    assert!(
        pipe.server.paths.len() <= 2,
        "path count should be bounded by active_connection_id_limit: got {}",
        pipe.server.paths.len()
    );

    // Events are only emitted after successful path insertion, so the event
    // count is bounded by path Slab capacity (max_concurrent_paths), not by
    // attacker packet count. With default active_connection_id_limit=2, we
    // can have at most 2 paths, so at most a few events (New, Closed for
    // eviction, ReusedSourceConnectionId) - far fewer than N=5000.
    let mut event_count = 0usize;
    while pipe.server.path_event_next().is_some() {
        event_count += 1;
    }

    // The key security property: events are bounded, not O(N).
    // With 2 path slots, we expect roughly:
    // - Path 0: original (no event, client-side)
    // - Each new path triggers: possibly Closed (eviction) + New +
    //   ReusedSourceConnectionId
    // But only ~2 paths can exist at once, and unused paths get evicted.
    // The exact count depends on timing, but must be << N.
    assert!(
        event_count < 100,
        "event queue should be bounded by path capacity, not packet count: \
         got {event_count} events for {N} packets"
    );
    Ok(())
}

#[rstest]
fn repeated_nat_rebinding(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(0, 1)] additional_cids: usize,
) -> TestResult {
    // Like `Pipe::advance()`, but the client's packets reach the server from
    // `rebound_addr`, and the server's packets to that address still reach the
    // client, as if a NAT translated them.
    fn advance_rebound(
        pipe: &mut test_utils::Pipe, client_addr: SocketAddr,
        rebound_addr: SocketAddr,
    ) -> Result<()> {
        let mut client_done = false;
        let mut server_done = false;

        while !client_done || !server_done {
            match test_utils::emit_flight(&mut pipe.client) {
                Ok(mut flight) => {
                    for (_, si) in &mut flight {
                        si.from = rebound_addr;
                    }
                    test_utils::process_flight(&mut pipe.server, flight)?;
                },

                Err(Error::Done) => client_done = true,

                Err(e) => return Err(e),
            }

            match test_utils::emit_flight(&mut pipe.server) {
                Ok(mut flight) => {
                    for (_, si) in &mut flight {
                        si.to = client_addr;
                    }
                    test_utils::process_flight(&mut pipe.client, flight)?;
                },

                Err(Error::Done) => server_done = true,

                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(2);
    config.set_initial_max_data(100_000);
    config.set_initial_max_stream_data_bidi_local(100_000);
    config.set_initial_max_stream_data_bidi_remote(100_000);
    config.set_initial_max_streams_bidi(2);

    let mut pipe =
        pipe_with_exchanged_cids(&mut config, 16, 16, additional_cids)?;

    let client_addr = test_utils::Pipe::client_addr();
    let server_addr = test_utils::Pipe::server_addr();

    // The server can hold two paths, so every rebinding after the first one
    // requires the path superseded by the previous migration to be removed.
    let mut prev_addr = client_addr;
    let mut superseded_addr = None;

    for port in 1..=4 {
        let rebound_addr: SocketAddr =
            format!("127.0.0.1:{}", 20000 + port).parse()?;

        // The client is unaware of the rebinding and keeps sending as usual.
        assert_eq!(pipe.client.stream_send(0, b"data", false), Ok(4));
        assert_eq!(
            advance_rebound(&mut pipe, client_addr, rebound_addr),
            Ok(())
        );

        if let Some(superseded_addr) = superseded_addr {
            assert_eq!(
                pipe.server.path_event_next(),
                Some(PathEvent::Closed(server_addr, superseded_addr))
            );
        }
        assert_eq!(
            pipe.server.path_event_next(),
            Some(PathEvent::New(server_addr, rebound_addr))
        );
        assert_eq!(
            pipe.server.path_event_next(),
            Some(PathEvent::ReusedSourceConnectionId(
                0,
                (server_addr, prev_addr),
                (server_addr, rebound_addr)
            ))
        );
        assert_eq!(
            pipe.server.path_event_next(),
            Some(PathEvent::Validated(server_addr, rebound_addr))
        );
        assert_eq!(
            pipe.server.path_event_next(),
            Some(PathEvent::PeerMigrated(server_addr, rebound_addr))
        );
        assert_eq!(pipe.server.path_event_next(), None);

        assert_eq!(pipe.server.paths.len(), 2);
        assert_eq!(pipe.server.paths.get_active()?.peer_addr(), rebound_addr);

        superseded_addr = Some(prev_addr);
        prev_addr = rebound_addr;
    }

    // Data kept flowing throughout.
    let mut buf = [0; 16];
    assert_eq!(pipe.server.stream_recv(0, &mut buf), Ok((16, false)));
    assert_eq!(&buf, b"datadatadatadata");
    Ok(())
}

#[rstest]
fn consecutive_non_ack_eliciting(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends a bunch of PING frames, causing server to ACK (ACKs aren't
    // ack-eliciting)
    let frames = [frame::Frame::Ping { mtu_probe: None }];
    let pkt_type = Type::Short;
    for _ in 0..24 {
        let len = pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;
        assert!(len > 0);

        let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
        assert!(
            frames
                .iter()
                .all(|frame| matches!(frame, frame::Frame::Ack { .. })),
            "ACK only"
        );
    }

    // After 24 non-ack-eliciting, an ACK is explicitly elicited with a PING
    let len = pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;
    assert!(len > 0);

    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    assert!(
        frames
            .iter()
            .any(|frame| matches!(frame, frame::Frame::Ping { mtu_probe: None })),
        "found a PING"
    );
    Ok(())
}

#[rstest]
fn send_ack_eliciting_causes_ping(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    // First establish a connection
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Queue a PING frame
    pipe.server.send_ack_eliciting()?;

    // Make sure ping is sent
    let mut buf = [0; 1500];
    let (len, _) = pipe.server.send(&mut buf)?;

    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    let mut iter = frames.iter();

    assert_eq!(iter.next(), Some(&frame::Frame::Ping { mtu_probe: None }));
    Ok(())
}

#[rstest]
fn send_ack_eliciting_no_ping(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    // First establish a connection
    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Queue a PING frame
    pipe.server.send_ack_eliciting()?;

    // Send a stream frame, which is ACK-eliciting to make sure the ping is
    // not sent
    assert_eq!(pipe.server.stream_send(1, b"a", false), Ok(1));

    // Make sure ping is not sent
    let mut buf = [0; 1500];
    let (len, _) = pipe.server.send(&mut buf)?;

    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    let mut iter = frames.iter();

    assert!(matches!(
        iter.next(),
        Some(&frame::Frame::Stream {
            stream_id: 1,
            data: _
        })
    ));
    assert!(iter.next().is_none());
    Ok(())
}

/// Tests that streams do not keep being "writable" after being collected
/// on reset.
#[rstest]
fn stop_sending_stream_send_after_reset_stream_ack(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] discard: bool,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = transport_config(cc_algorithm_name)?;
    config.set_initial_max_data(999_999_999);
    config.set_initial_max_stream_data_bidi_local(30);
    config.set_initial_max_stream_data_bidi_remote(30);
    config.set_initial_max_stream_data_uni(30);
    config.set_initial_max_streams_bidi(1000);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.server.streams.len(), 0);
    assert_eq!(pipe.server.readable().len(), 0);
    assert_eq!(pipe.server.writable().len(), 0);

    // Client opens a load of streams
    assert_eq!(pipe.client.stream_send(0, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(8, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(12, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(16, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(20, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(24, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(28, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(32, b"hello", true), Ok(5));
    assert_eq!(pipe.client.stream_send(36, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server iterators are populated
    let mut r = pipe.server.readable();
    assert_eq!(r.len(), 10);
    assert_eq!(r.next(), Some(0));
    assert_eq!(r.next(), Some(4));
    assert_eq!(r.next(), Some(8));
    assert_eq!(r.next(), Some(12));
    assert_eq!(r.next(), Some(16));
    assert_eq!(r.next(), Some(20));
    assert_eq!(r.next(), Some(24));
    assert_eq!(r.next(), Some(28));
    assert_eq!(r.next(), Some(32));
    assert_eq!(r.next(), Some(36));

    assert_eq!(r.next(), None);

    let mut w = pipe.server.writable();
    assert_eq!(w.len(), 10);
    assert_eq!(w.next(), Some(0));
    assert_eq!(w.next(), Some(4));
    assert_eq!(w.next(), Some(8));
    assert_eq!(w.next(), Some(12));
    assert_eq!(w.next(), Some(16));
    assert_eq!(w.next(), Some(20));
    assert_eq!(w.next(), Some(24));
    assert_eq!(w.next(), Some(28));
    assert_eq!(w.next(), Some(32));
    assert_eq!(w.next(), Some(36));
    assert_eq!(w.next(), None);

    // Read one stream
    assert_eq!(
        stream_recv_discard(&mut pipe.server, discard, 0),
        Ok((5, true))
    );
    assert!(pipe.server.stream_finished(0));

    assert_eq!(pipe.server.readable().len(), 9);
    assert_eq!(pipe.server.writable().len(), 10);

    assert_eq!(pipe.server.stream_writable(0, 0), Ok(true));

    // Server sends data on stream 0, until blocked.
    while pipe.server.stream_send(0, b"world", false) != Err(Error::Done) {
        assert_eq!(pipe.advance(), Ok(()));
    }

    assert_eq!(pipe.server.writable().len(), 9);
    assert_eq!(pipe.server.stream_writable(0, 0), Ok(true));

    // Client sends STOP_SENDING.
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];

    let pkt_type = Type::Short;
    let len = pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;

    // Server sent a RESET_STREAM frame in response.
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;

    let mut iter = frames.iter();

    // Skip ACK frame.
    iter.next();

    assert_eq!(
        iter.next(),
        Some(&frame::Frame::ResetStream {
            stream_id: 0,
            error_code: 42,
            final_size: 30,
        })
    );

    // Stream 0 is now writable in order to make apps aware of STOP_SENDING
    // via returning an error.
    let mut w = pipe.server.writable();
    assert_eq!(w.len(), 10);

    assert!(w.any(|s| s == 0));
    assert_eq!(
        pipe.server.stream_writable(0, 1),
        Err(Error::StreamStopped(42))
    );

    // Returning `StreamStopped` causes the stream to be collected.
    assert_eq!(pipe.server.streams.len(), 9);
    assert_eq!(pipe.server.writable().len(), 9);

    // Client acks RESET_STREAM frame.
    let mut ranges = ranges::RangeSet::default();
    ranges.insert(0..12);

    let frames = [frame::Frame::Ack {
        ack_delay: 15,
        ranges,
        ecn_counts: None,
    }];

    assert_eq!(pipe.send_pkt_to_server(pkt_type, &frames, &mut buf), Ok(0));

    // Stream is collected on the server after RESET_STREAM is acked.
    assert_eq!(pipe.server.streams.len(), 9);

    // Sending STOP_SENDING again shouldn't trigger RESET_STREAM again.
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];

    let len = pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;

    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;

    assert_eq!(frames.len(), 1);

    assert!(
        matches!(frames.first(), Some(frame::Frame::Ack { .. })),
        "expected ACK frame: {frames:?}"
    );

    assert_eq!(pipe.server.streams.len(), 9);

    // Stream 0 has been collected and must not be writable anymore.
    let mut w = pipe.server.writable();
    assert_eq!(w.len(), 9);
    assert!(!w.any(|s| s == 0));

    // If we called send before the client ACK of reset stream, it would
    // have failed with StreamStopped.
    assert_eq!(pipe.server.stream_send(0, b"world", true), Err(Error::Done),);

    // Stream 0 is still not writable.
    let mut w = pipe.server.writable();
    assert_eq!(w.len(), 9);
    assert!(!w.any(|s| s == 0));
    Ok(())
}

/// Verify that a stream stopped by the peer still surfaces `StreamStopped`
/// to the application when it was unlinked from the writable queue before
/// the `RESET_STREAM` ack arrived.
///
/// Poll `stream_writable_next()` to unlink the stopped stream, then deliver
/// the `RESET_STREAM` ack. The stream stays uncollected and the next
/// `stream_send()` returns `StreamStopped`.
#[test]
fn stop_sending_signal_survives_writable_unlink_before_ack() -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = Config::new(PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(999_999_999);
    config.set_initial_max_stream_data_bidi_local(30);
    config.set_initial_max_stream_data_bidi_remote(30);
    config.set_initial_max_streams_bidi(10);
    config.set_initial_max_streams_uni(0);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client opens a bidi stream with fin; the server reads the whole
    // request so the stream's receive side is complete.
    assert_eq!(pipe.client.stream_send(0, b"req", true), Ok(3));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.server.stream_recv(0, &mut buf), Ok((3, true)));
    // Ordinary readiness can be consumed before STOP arrives.
    assert_eq!(pipe.server.stream_writable_next(), Some(0));
    assert_eq!(pipe.server.stream_writable_next(), None);

    // Client no longer wants the response and sends STOP_SENDING. Deliver
    // only that packet to the server, without letting the server's
    // RESET_STREAM reply or its ack go anywhere yet.
    assert_eq!(pipe.client.stream_shutdown(0, Shutdown::Read, 42), Ok(()));
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    // STOP restores the queue entry even though the stream was writable.
    assert_eq!(pipe.server.writable().collect::<Vec<_>>(), vec![0]);

    // Polling the stopped entry unlinks it without consuming the error.
    assert_eq!(pipe.server.stream_writable_next(), Some(0));

    // Let the RESET_STREAM reach the client and its ack come back to the
    // server, which processes the ack with the stream already unlinked.
    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;
    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    // The stream must not have been collected yet: the application has not
    // observed the STOP_SENDING.
    assert_eq!(pipe.server.streams.len(), 1);

    // The application finally writes its response and must see
    // StreamStopped, not Done.
    assert_eq!(
        pipe.server.stream_send(0, b"resp", true),
        Err(Error::StreamStopped(42))
    );
    Ok(())
}

#[rstest]
fn challenge_no_cids(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = transport_config(cc_algorithm_name)?;
    config.verify_peer(false);
    config.set_active_connection_id_limit(4);
    config.set_initial_max_data(30);
    config.set_initial_max_stream_data_bidi_local(15);
    config.set_initial_max_stream_data_bidi_remote(15);
    config.set_initial_max_stream_data_uni(10);
    config.set_initial_max_streams_bidi(3);

    let mut pipe =
        test_utils::Pipe::with_config_and_scid_lengths(&mut config, 16, 16)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Server send CIDs to client
    let mut server_cids = Vec::new();
    for _ in 0..2 {
        let (cid, reset_token) = test_utils::create_cid_and_reset_token(16);
        pipe.server.new_scid(&cid, reset_token, true)?;
        server_cids.push(cid);
    }
    assert_eq!(pipe.advance(), Ok(()));

    let server_addr = test_utils::Pipe::server_addr();
    let client_addr_2 = "127.0.0.1:5678".parse()?;

    // Client probes path before sending CIDs (simulating race condition)
    let frames = [frame::Frame::PathChallenge {
        data: [0, 1, 2, 3, 4, 5, 6, 7],
    }];
    let mut pkt_buf = [0u8; 1500];
    let mut b = octets::OctetsMut::with_slice(&mut pkt_buf);
    let epoch = Type::Short.to_epoch()?;
    let crypto_ctx = &mut pipe.client.crypto_ctx[epoch];
    let pn = pipe.client.next_pkt_num;
    let pn_len = 4;

    let hdr = Header {
        ty: Type::Short,
        version: pipe.client.version,
        dcid: server_cids[0].clone(),
        scid: ConnectionId::from_ref(&[5, 4, 3, 2, 1]),
        pkt_num: 0,
        pkt_num_len: pn_len,
        token: pipe.client.initial.token.clone(),
        versions: None,
        key_phase: pipe.client.key_phase,
    };
    hdr.to_bytes(&mut b)?;
    let payload_len: usize = frames
        .iter()
        .map(frame::Frame::wire_len)
        .sum::<Result<usize>>()?;
    b.put_u32(u32::try_from(pn)?)?;

    let payload_offset = b.off();

    for frame in frames {
        frame.to_bytes(&mut b)?;
    }

    let aead = crypto_ctx.crypto_seal.as_mut().ok_or("crypto seal")?;

    let written = packet::encrypt_pkt(
        &mut b,
        pn,
        pn_len,
        payload_len,
        payload_offset,
        None,
        aead,
    )?;
    pipe.client.next_pkt_num += 1;

    pipe.server.recv(&mut pkt_buf[..written], RecvInfo {
        to: server_addr,
        from: client_addr_2,
    })?;

    // Show that the new path is not considered a destination path by quiche
    assert!(!pipe
        .server
        .paths_iter(server_addr)
        .any(|path| path == client_addr_2));
    Ok(())
}

#[rstest]
fn pmtud_peer_limit_and_confirmed_size(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    config.set_max_send_udp_payload_size(1400);
    config.discover_pmtu(true);

    let mut server_config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    server_config.set_max_recv_udp_payload_size(1280);
    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut config,
        &mut server_config,
    )?;
    assert_eq!(pipe.handshake(), Ok(()));
    assert_eq!(
        pipe.client.paths.get_active()?.recovery.max_datagram_size(),
        MIN_CLIENT_INITIAL_LEN,
    );

    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        pipe.client
            .paths
            .get_active()?
            .pmtud
            .as_ref()
            .ok_or("PMTUD is not enabled")?
            .get_pmtu(),
        Some(1280)
    );
    assert_eq!(pipe.client.max_send_udp_payload_size(), 1280);

    pipe.client.revalidate_pmtu();
    assert_eq!(
        pipe.client.max_send_udp_payload_size(),
        MIN_CLIENT_INITIAL_LEN
    );
    Ok(())
}

#[rstest]
fn pmtud_probe_success(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    config.set_cc_algorithm_name(cc_algorithm_name)?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1"])?;
    config.verify_peer(false);
    config.set_max_send_udp_payload_size(1400);
    config.discover_pmtu(true);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));
    assert_eq!(pipe.client.path_event_next(), None);

    // Send probe and let it be acknowledged
    assert_eq!(pipe.advance(), Ok(()));

    // Verify probing is disabled after successful probe
    let pmtud = pipe
        .client
        .paths
        .get_active_mut()?
        .pmtud
        .as_mut()
        .ok_or("PMTUD is not enabled")?;
    assert!(!pmtud.should_probe());

    // Verify MTU was updated
    let current_mtu = pmtud.get_current_mtu();
    assert_eq!(current_mtu, 1400);

    let path_stats = pipe
        .client
        .path_stats()
        .next()
        .ok_or("expected path statistics")?;
    assert_eq!(path_stats.pmtu, current_mtu);
    let expected_valid = PathEvent::PmtuUpdated {
        local: path_stats.local_addr,
        peer: path_stats.peer_addr,
        pmtu: current_mtu,
    };
    assert_eq!(pipe.client.path_event_next(), Some(expected_valid.clone()));
    assert_eq!(pipe.client.path_event_next(), None);

    pipe.client.revalidate_pmtu();
    assert_eq!(
        pipe.client.path_event_next(),
        Some(PathEvent::PmtuUpdated {
            local: path_stats.local_addr,
            peer: path_stats.peer_addr,
            pmtu: MIN_CLIENT_INITIAL_LEN,
        })
    );

    pipe.client.revalidate_pmtu();
    assert_eq!(pipe.client.path_event_next(), None);

    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.client.path_event_next(), Some(expected_valid));
    assert_eq!(pipe.client.path_event_next(), None);
    Ok(())
}

#[rstest]
/// This test verifies that multiple `send()` calls after handshake completion
/// only generate one PMTUD probe packet, not multiple identical probes.
fn pmtud_no_duplicate_probes(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    config.set_cc_algorithm_name(cc_algorithm_name)?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.verify_peer(false);
    config.set_max_send_udp_payload_size(1400);
    config.discover_pmtu(true);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Verify PMTUD is enabled and ready to probe
    let pmtud = pipe
        .client
        .paths
        .get_active_mut()?
        .pmtud
        .as_mut()
        .ok_or("PMTUD is not enabled")?;
    assert!(pmtud.should_probe());
    let initial_probe_size = pmtud.get_probe_size();
    assert_eq!(initial_probe_size, 1400);

    let mut frames: Vec<frame::Frame> = Vec::new();
    for _ in 0..2 {
        let mut buf = [0; 1400];
        let (len, _) = pipe.client.send(&mut buf)?;
        frames.append(
            test_utils::decode_pkt(&pipe.server, &mut buf[..len])?.as_mut(),
        );
    }

    assert_eq!(frames.len(), 3);
    assert!(matches!(frames[0], frame::Frame::Ack { .. }));
    assert!(matches!(frames[1], frame::Frame::Padding { .. }));
    assert!(matches!(frames[2], frame::Frame::Ping { .. }));

    let mut buf = [0; 1400];
    assert_eq!(pipe.client.send(&mut buf), Err(Error::Done));

    // Verify probe flag was reset after sending
    assert!(!pipe
        .client
        .paths
        .get_active_mut()?
        .pmtud
        .as_mut()
        .ok_or("PMTUD is not enabled")?
        .should_probe());
    Ok(())
}

#[rstest]
/// Test that PMTUD retries with smaller probe size after loss.
fn pmtud_probe_retry_after_loss(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut config = Config::new(PROTOCOL_VERSION)?;
    config.set_cc_algorithm_name(cc_algorithm_name)?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1"])?;
    config.verify_peer(false);
    config.set_max_send_udp_payload_size(1400);
    config.discover_pmtu(true);
    config.set_pmtud_max_probes(2);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Get initial probe size
    let active_path = pipe.client.paths.get_active_mut()?;
    let initial_probe_size = active_path
        .pmtud
        .as_mut()
        .ok_or("PMTUD is not enabled")?
        .get_probe_size();
    assert_eq!(initial_probe_size, 1400);

    // Send first probe
    let mut out = [0; 4096];
    // ACK frame
    let _ = pipe.client.send(&mut out)?;
    // PING + PADDING frames
    let (len, _) = pipe.client.send(&mut out)?;
    assert_eq!(len, 1400);

    // Verify probe flag was reset after sending
    let pmtud = pipe
        .client
        .paths
        .get_active_mut()?
        .pmtud
        .as_mut()
        .ok_or("PMTUD is not enabled")?;
    assert!(!pmtud.should_probe());

    // Two probe failures are required before the size changes. The first
    // failure should retry at the same size.
    pmtud.failed_probe(initial_probe_size);
    assert_eq!(pmtud.get_current_mtu(), 1200);
    assert!(pmtud.should_probe());
    assert_eq!(pmtud.get_probe_size(), 1400); // Still trying 1400

    // Second failure (max_probes reached) - now size should change
    pmtud.failed_probe(initial_probe_size);
    assert_eq!(pmtud.get_current_mtu(), 1200);
    assert!(pmtud.should_probe());
    assert_eq!(pmtud.get_probe_size(), 1300);

    // Send second probe
    let mut out = [0; 4096];
    // PING + PADDING frames
    let (len, _) = pipe.client.send(&mut out)?;
    assert_eq!(len, 1300);

    // Verify should_probe flag gets reset
    let pmtud = pipe
        .client
        .paths
        .get_active_mut()?
        .pmtud
        .as_mut()
        .ok_or("PMTUD is not enabled")?;
    assert!(!pmtud.should_probe());

    // Simulate second probe loss (2 failures needed)
    pmtud.failed_probe(1300);
    pmtud.failed_probe(1300);

    // Verify MTU is not updated
    assert_eq!(pmtud.get_current_mtu(), 1200);

    // Verify probe flag is re-enabled and probe size is reduced
    assert!(pmtud.should_probe());
    // Third probe should be 1250 bytes which is halfway between 1200 and the
    // second probe size=1300.
    assert_eq!(pmtud.get_probe_size(), 1250);

    let path_stats = pipe
        .client
        .path_stats()
        .next()
        .ok_or("expected path statistics")?;
    assert_eq!(path_stats.pmtu, 1200);
    assert_eq!(pipe.client.path_event_next(), None);

    // Make probes succeed til pmtu is found
    assert_eq!(pipe.advance(), Ok(()));

    let pmtud = pipe
        .client
        .paths
        .get_active_mut()?
        .pmtud
        .as_mut()
        .ok_or("PMTUD is not enabled")?;

    // MTU should finally update
    let current_mtu = pmtud.get_current_mtu();
    assert_eq!(current_mtu, 1299);

    // Verify should_probe gets reset
    assert!(!pmtud.should_probe());

    let path_stats = pipe
        .client
        .path_stats()
        .next()
        .ok_or("expected path statistics")?;
    assert_eq!(path_stats.pmtu, current_mtu);
    let pmtu_events: Vec<_> =
        std::iter::from_fn(|| pipe.client.path_event_next()).collect();
    let mut pmtus = Vec::new();
    for event in pmtu_events {
        let PathEvent::PmtuUpdated { local, peer, pmtu } = event else {
            return Err(format!("unexpected path event: {event:?}").into());
        };
        assert_eq!(local, path_stats.local_addr);
        assert_eq!(peer, path_stats.peer_addr);
        pmtus.push(pmtu);
    }
    assert!(pmtus.len() > 1);
    assert!(pmtus.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(pmtus.last(), Some(&current_mtu));
    Ok(())
}

#[cfg(feature = "boringssl-btls-crate")]
#[rstest]
fn enable_pmtud_mid_handshake(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    // Manually construct `SslContextBuilder` for the server so we can enable
    // PMTUD during the handshake.
    let mut server_tls_ctx_builder =
        btls::ssl::SslContextBuilder::new(btls::ssl::SslMethod::tls())?;
    server_tls_ctx_builder.set_certificate_chain_file("examples/cert.crt")?;
    server_tls_ctx_builder
        .set_private_key_file("examples/cert.key", btls::ssl::SslFiletype::PEM)?;
    server_tls_ctx_builder.set_select_certificate_callback(|mut hello| {
        <Connection>::set_discover_pmtu_in_handshake(hello.ssl_mut(), true, 1)
            .map_err(|_| btls::ssl::SelectCertError::ERROR)?;

        Ok(())
    });

    let mut server_config = Config::with_btls_ssl_ctx_builder(
        PROTOCOL_VERSION,
        server_tls_ctx_builder,
    )?;
    assert_eq!(
        server_config.set_cc_algorithm_name(cc_algorithm_name),
        Ok(())
    );

    let mut client_config = Config::new(PROTOCOL_VERSION)?;
    client_config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    client_config.load_priv_key_from_pem_file("examples/cert.key")?;

    for config in [&mut client_config, &mut server_config] {
        config.set_application_protos(&[b"proto1", b"proto2"])?;
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_max_idle_timeout(180_000);
        config.verify_peer(false);
        config.set_ack_delay_exponent(8);
        config.set_max_send_udp_payload_size(1350);
    }

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )?;

    let active_path = pipe.server.paths.get_active_mut()?;
    assert!(active_path.pmtud.is_none());

    assert_eq!(pipe.handshake(), Ok(()));

    let active_path = pipe.server.paths.get_active_mut()?;
    assert!(active_path.pmtud.is_some());
    assert_eq!(
        active_path
            .pmtud
            .as_mut()
            .ok_or("PMTUD is not enabled")?
            .get_current_mtu(),
        1200
    );

    let path_stats = pipe
        .server
        .path_stats()
        .next()
        .ok_or("expected path statistics")?;
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::PmtuUpdated {
            local: path_stats.local_addr,
            peer: path_stats.peer_addr,
            pmtu: MIN_CLIENT_INITIAL_LEN,
        })
    );
    assert_eq!(pipe.server.path_event_next(), None);

    assert_eq!(pipe.advance(), Ok(()));

    let current_mtu = pipe
        .server
        .paths
        .get_active_mut()?
        .pmtud
        .as_mut()
        .ok_or("PMTUD is not enabled")?
        .get_current_mtu();
    assert_eq!(current_mtu, 1350);

    let path_stats = pipe
        .server
        .path_stats()
        .next()
        .ok_or("expected path statistics")?;
    assert_eq!(path_stats.pmtu, current_mtu);
    assert_eq!(
        pipe.server.path_event_next(),
        Some(PathEvent::PmtuUpdated {
            local: path_stats.local_addr,
            peer: path_stats.peer_addr,
            pmtu: current_mtu,
        })
    );
    assert_eq!(pipe.server.path_event_next(), None);
    Ok(())
}

#[cfg(feature = "boringssl-btls-crate")]
#[rstest]
fn disable_pmtud_mid_handshake(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    // Manually construct `SslContextBuilder` for the server so we can disable
    // PMTUD during the handshake.
    let mut server_tls_ctx_builder =
        btls::ssl::SslContextBuilder::new(btls::ssl::SslMethod::tls())?;
    server_tls_ctx_builder.set_certificate_chain_file("examples/cert.crt")?;
    server_tls_ctx_builder
        .set_private_key_file("examples/cert.key", btls::ssl::SslFiletype::PEM)?;
    server_tls_ctx_builder.set_select_certificate_callback(|mut hello| {
        <Connection>::set_discover_pmtu_in_handshake(hello.ssl_mut(), false, 0)
            .map_err(|_| btls::ssl::SelectCertError::ERROR)?;

        Ok(())
    });

    let mut server_config = Config::with_btls_ssl_ctx_builder(
        PROTOCOL_VERSION,
        server_tls_ctx_builder,
    )?;
    assert_eq!(
        server_config.set_cc_algorithm_name(cc_algorithm_name),
        Ok(())
    );

    let mut client_config = Config::new(PROTOCOL_VERSION)?;
    client_config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    client_config.load_priv_key_from_pem_file("examples/cert.key")?;

    for config in [&mut client_config, &mut server_config] {
        config.set_application_protos(&[b"proto1", b"proto2"])?;
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.set_max_idle_timeout(180_000);
        config.verify_peer(false);
        config.set_ack_delay_exponent(8);
        config.set_max_send_udp_payload_size(1350);
        config.discover_pmtu(true);
    }

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )?;

    let active_path = pipe.server.paths.get_active_mut()?;
    assert!(active_path.pmtud.is_some());
    assert_eq!(pipe.server.path_event_next(), None);

    assert_eq!(pipe.handshake(), Ok(()));

    let active_path = pipe.server.paths.get_active_mut()?;
    assert!(active_path.pmtud.is_none());
    assert_eq!(pipe.server.path_event_next(), None);

    assert_eq!(pipe.advance(), Ok(()));

    let active_path = pipe.server.paths.get_active_mut()?;
    assert!(active_path.pmtud.is_none());
    assert_eq!(pipe.server.path_event_next(), None);
    Ok(())
}

#[rstest]
fn configuration_values_clamping() -> TestResult {
    let mut config = Config::new(0x1)?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    let v = octets::MAX_VAR_INT + 1;
    let uv = usize::MAX;
    config.set_max_idle_timeout(v);
    config.set_max_recv_udp_payload_size(0);
    assert_eq!(
        config.local_transport_params.max_udp_payload_size,
        transport_params::MIN_UDP_PAYLOAD_SIZE
    );
    config.set_max_recv_udp_payload_size(uv);
    config.set_initial_max_data(v);
    config.set_initial_max_stream_data_bidi_local(v);
    config.set_initial_max_stream_data_bidi_remote(v);
    config.set_initial_max_stream_data_uni(v);
    config.set_initial_max_streams_bidi(v);
    config.set_initial_max_streams_uni(v);
    config.set_ack_delay_exponent(v);
    config.set_max_ack_delay(v);
    config.set_active_connection_id_limit(v);
    config.verify_peer(false);

    let mut pipe = test_utils::Pipe::with_client_config(&mut config)?;
    assert_eq!(
        pipe.client.local_transport_params.max_idle_timeout,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client.local_transport_params.max_udp_payload_size,
        cmp::min(octets::MAX_VAR_INT, uv as u64)
    );
    assert_eq!(
        pipe.client.local_transport_params.initial_max_data,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client
            .local_transport_params
            .initial_max_stream_data_bidi_local,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client
            .local_transport_params
            .initial_max_stream_data_bidi_remote,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client
            .local_transport_params
            .initial_max_stream_data_uni,
        octets::MAX_VAR_INT
    );
    assert_eq!(
        pipe.client.local_transport_params.initial_max_streams_bidi,
        MAX_STREAM_COUNT
    );
    assert_eq!(
        pipe.client.local_transport_params.initial_max_streams_uni,
        MAX_STREAM_COUNT
    );
    assert_eq!(
        pipe.client.local_transport_params.ack_delay_exponent,
        MAX_ACK_DELAY_EXPONENT
    );
    assert_eq!(
        pipe.client.local_transport_params.active_conn_id_limit,
        octets::MAX_VAR_INT
    );

    assert_eq!(
        pipe.client.local_transport_params.max_ack_delay,
        transport_params::MAX_ACK_DELAY
    );
    pipe.handshake()?;
    assert_eq!(
        pipe.server
            .peer_transport_params()
            .ok_or("negotiated peer parameters missing")?
            .initial_max_streams_bidi,
        MAX_STREAM_COUNT
    );
    assert_eq!(
        pipe.server
            .peer_transport_params()
            .ok_or("negotiated peer parameters missing")?
            .max_ack_delay,
        transport_params::MAX_ACK_DELAY
    );
    Ok(())
}

#[cfg(feature = "custom-client-dcid")]
#[rstest]
fn connect_custom_client_dcid() -> TestResult {
    let mut client_scid = [0; 16];
    rand::rand_bytes(&mut client_scid[..]);
    let client_scid = ConnectionId::from_ref(&client_scid);
    let client_addr = "127.0.0.1:1234".parse()?;

    let mut server_scid = [0; 16];
    rand::rand_bytes(&mut server_scid[..]);
    let server_scid = ConnectionId::from_ref(&server_scid);
    let server_addr = "127.0.0.1:4321".parse()?;

    // 8 is the minimum required.
    let mut client_dcid = [0; 8];
    rand::rand_bytes(&mut client_dcid[..]);
    let client_dcid = ConnectionId::from_ref(&client_dcid);

    let mut client_config = Config::new(PROTOCOL_VERSION)?;
    client_config.set_application_protos(&[b"proto1", b"proto2"])?;

    let client = connect_with_dcid(
        Some("quic.tech"),
        &client_scid,
        &client_dcid,
        client_addr,
        server_addr,
        &mut client_config,
    );

    let mut server_config = Config::new(PROTOCOL_VERSION)?;
    server_config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    server_config.load_priv_key_from_pem_file("examples/cert.key")?;
    server_config.set_application_protos(&[b"proto1", b"proto2"])?;
    server_config.verify_peer(false);

    let mut pipe = test_utils::Pipe {
        client: client?,
        server: accept(
            &server_scid,
            None,
            server_addr,
            client_addr,
            &mut server_config,
        )?,
    };

    // Client sends initial flight.
    let flight = test_utils::emit_flight(&mut pipe.client)?;

    let (pkt, _info) = flight.first().ok_or("expected nonempty packet flight")?;
    let header = Header::from_slice(pkt, client_dcid.len())?;

    // Validate that the dcid is the same as the one we provided.
    assert_eq!(client_dcid, header.dcid);

    test_utils::process_flight(&mut pipe.server, flight)?;

    assert_handshake_confirmation(&mut pipe)?;
    Ok(())
}

#[rstest]
/// Tests that `RESET_STREAM` is retransmitted when the packet containing it is
/// lost, even if the stream has been collected.
fn reset_stream_retransmit_after_stream_collected(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> Result<()> {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data on stream 0.
    assert_eq!(pipe.client.stream_send(0, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server receives and reads the data.
    assert_eq!(
        stream_recv_discard(&mut pipe.server, false, 0),
        Ok((5, true))
    );
    assert!(pipe.server.stream_finished(0));

    // Server sends data back on stream 0, until blocked by flow control.
    loop {
        match pipe.server.stream_send(0, b"world", false) {
            Ok(_) => pipe.advance()?,
            Err(Error::Done) => break,
            Err(error) => return Err(error),
        }
    }

    // Client sends STOP_SENDING to trigger RESET_STREAM from server.
    let frames = [frame::Frame::StopSending {
        stream_id: 0,
        error_code: 42,
    }];

    let pkt_type = Type::Short;

    // send_pkt_to_server() causes the server to receive a STOP_SENDING and
    // respond with a RESET_STREAM. However, we won't deliver the packet back to
    // the client and instead just check its contents with decode_pkt()
    let len = pipe.send_pkt_to_server(pkt_type, &frames, &mut buf)?;

    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    let has_reset_stream = frames.contains(&frame::Frame::ResetStream {
        stream_id: 0,
        error_code: 42,
        final_size: 15,
    });
    assert!(has_reset_stream, "Expected RESET_STREAM in response");

    // Now the application tries to write to the stream, which will return
    // StreamStopped error and cause the stream to be collected.
    assert_eq!(
        pipe.server.stream_writable(0, 1),
        Err(Error::StreamStopped(42))
    );

    // Stream 0 should now be collected.
    assert_eq!(pipe.server.streams.len(), 0);

    // Trigger loss detection for the first RESET_STREAM packet and subsequent
    // retransmission. Confirm the new packet contains RESET_STREAM.
    test_utils::trigger_ack_based_loss(&mut pipe.server, &mut pipe.client)?;

    let (len, _) = pipe.server.send(&mut buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    let has_reset_stream = frames.contains(&frame::Frame::ResetStream {
        stream_id: 0,
        error_code: 42,
        final_size: 15,
    });

    assert!(
        has_reset_stream,
        "RESET_STREAM should be retransmitted even after stream is collected"
    );
    Ok(())
}

#[rstest]
/// The `STOP_SENDING` obligation survives packet loss until the peer finishes
/// the send side. A received FIN cancels that obligation.
fn stop_sending_retransmit(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(false, true)] fin_before_loss: bool,
) -> Result<()> {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Client sends some data on stream 4 (no fin).
    assert_eq!(pipe.client.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));

    // Server receives the data.
    let mut r = pipe.server.readable();
    assert_eq!(r.next(), Some(4));

    // Server shuts down the read side, triggering STOP_SENDING.
    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Read, 42), Ok(()));

    // Server sends STOP_SENDING, but we don't deliver it (simulating loss).
    let (len, _) = pipe.server.send(&mut buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    let expected = frame::Frame::StopSending {
        stream_id: 4,
        error_code: 42,
    };
    assert!(
        frames.contains(&expected),
        "Expected STOP_SENDING in packet"
    );

    if fin_before_loss {
        assert_eq!(pipe.client.stream_send(4, b"", true), Ok(0));
        assert_eq!(pipe.advance(), Ok(()));
    }

    test_utils::trigger_ack_based_loss(&mut pipe.server, &mut pipe.client)?;
    if fin_before_loss {
        assert_eq!(pipe.server.send(&mut buf), Err(Error::Done));
    } else {
        let (len, _) = pipe.server.send(&mut buf)?;
        let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
        assert!(
            frames.contains(&expected),
            "STOP_SENDING should be retransmitted"
        );
    }
    Ok(())
}

#[rstest]
/// Tests that a zero-length FIN is sent and acknowledged before the stream is
/// collected.
fn stream_empty_fin_is_not_complete_until_fin_acked(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.server.stream_recv(4, &mut buf), Ok((5, true)));

    assert_eq!(pipe.server.stream_send(4, b"response", false), Ok(8));

    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;

    assert_eq!(pipe.client.stream_recv(4, &mut buf), Ok((8, false)));

    assert_eq!(pipe.server.stream_send(4, b"", true), Ok(0));

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;

    assert!(!pipe.server.streams.is_collected(4));

    let flight = test_utils::emit_flight(&mut pipe.server)?;
    let mut frames = Vec::new();

    for (mut pkt, _) in flight {
        frames.extend(test_utils::decode_pkt(&pipe.client, &mut pkt)?);
    }

    assert!(frames.iter().any(|f| matches!(
        f,
        frame::Frame::Stream { stream_id: 4, data }
            if data.off() == 8 && data.is_empty() && data.fin()
    )));
    Ok(())
}

#[rstest]
/// Tests that a lost zero-length FIN is retransmitted after all stream data has
/// already been acknowledged.
fn stream_empty_fin_is_retransmitted(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> Result<()> {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.server.stream_recv(4, &mut buf), Ok((5, true)));

    assert_eq!(pipe.server.stream_send(4, b"response", false), Ok(8));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.client.stream_recv(4, &mut buf), Ok((8, false)));

    assert_eq!(pipe.server.stream_send(4, b"", true), Ok(0));

    let (len, _) = pipe.server.send(&mut buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;

    assert!(frames.iter().any(|f| matches!(
        f,
        frame::Frame::Stream { stream_id: 4, data }
            if data.off() == 8 && data.is_empty() && data.fin()
    )));

    test_utils::trigger_ack_based_loss(&mut pipe.server, &mut pipe.client)?;

    let (len, _) = pipe.server.send(&mut buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;

    assert!(frames.iter().any(|f| matches!(
        f,
        frame::Frame::Stream { stream_id: 4, data }
            if data.off() == 8 && data.is_empty() && data.fin()
    )));
    Ok(())
}

#[rstest]
/// Tests that a lost FIN is retransmitted when the data of the lost STREAM
/// frame was acknowledged in another packet.
fn stream_fin_is_retransmitted_after_data_acked_separately(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> Result<()> {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.server.stream_recv(4, &mut buf), Ok((5, true)));

    let baseline = pipe.server.stats();
    assert_eq!(pipe.server.stream_send(4, b"response", false), Ok(8));
    let data_flight = test_utils::emit_flight(&mut pipe.server)?;

    // The PTO probe retransmits the data together with the FIN.
    let timer = pipe.server.timeout().ok_or(Error::InvalidState)?;
    std::thread::sleep(timer + Duration::from_millis(1));
    pipe.server.on_timeout();

    assert_eq!(pipe.server.stream_send(4, b"", true), Ok(0));

    let (len, _) = pipe.server.send(&mut buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;

    assert!(frames.iter().any(|f| matches!(
        f,
        frame::Frame::Stream { stream_id: 4, data }
            if data.off() == 0 && data.len() == 8 && data.fin()
    )));

    assert_eq!(pipe.server.stats().retrans, baseline.retrans + 1);
    assert_eq!(
        pipe.server.stats().stream_retrans_bytes,
        baseline.stream_retrans_bytes + 8
    );

    // Lose the probe, but deliver and acknowledge the original data.
    test_utils::process_flight(&mut pipe.client, data_flight)?;
    assert_eq!(pipe.client.stream_recv(4, &mut buf), Ok((8, false)));

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, flight)?;
    assert_eq!(
        pipe.server
            .streams
            .get(4)
            .ok_or(Error::InvalidState)?
            .send
            .ack_off(),
        8
    );

    test_utils::trigger_ack_based_loss(&mut pipe.server, &mut pipe.client)?;

    let flight = test_utils::emit_flight(&mut pipe.server)?;
    let mut frames = Vec::new();

    for (mut pkt, _) in flight.clone() {
        frames.extend(test_utils::decode_pkt(&pipe.client, &mut pkt)?);
    }

    assert!(frames.iter().any(|f| matches!(
        f,
        frame::Frame::Stream { stream_id: 4, data }
            if data.off() == 8 && data.is_empty() && data.fin()
    )));

    assert_eq!(pipe.server.stats().retrans, baseline.retrans + 2);
    assert_eq!(
        pipe.server.stats().stream_retrans_bytes,
        baseline.stream_retrans_bytes + 8
    );
    test_utils::process_flight(&mut pipe.client, flight)?;
    assert_eq!(pipe.client.stream_recv(4, &mut buf), Ok((0, true)));
    Ok(())
}

fn fin_retransmission_pipe(
    cc_algorithm_name: &str, buf: &mut [u8],
) -> Result<test_utils::Pipe> {
    let mut config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    config.set_initial_max_data(4096);
    config.set_initial_max_stream_data_bidi_local(1024);
    config.set_initial_max_stream_data_bidi_remote(1024);

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));

    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.server.stream_recv(4, buf), Ok((5, true)));

    Ok(pipe)
}

#[rstest]
/// Tests that a FIN is sent when retransmitted data ends before an already
/// acknowledged tail.
fn stream_fin_is_sent_after_retransmission_before_acked_tail(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> Result<()> {
    let mut buf = vec![0; 65_535];

    let mut pipe = fin_retransmission_pipe(cc_algorithm_name, &mut buf)?;

    let data = vec![42; 256];
    assert_eq!(pipe.server.stream_send(4, &data, false), Ok(256));

    let mut flight = test_utils::emit_flight_with_max_buffer(
        &mut pipe.server,
        64,
        None,
        None,
    )?;
    assert!(flight.len() > 3);

    // Only deliver the last packet. Its ACK declares all the others lost.
    let tail = flight.pop().ok_or(Error::InvalidState)?;
    test_utils::process_flight(&mut pipe.client, vec![tail])?;
    test_utils::trigger_ack_based_loss(&mut pipe.server, &mut pipe.client)?;

    assert_eq!(pipe.server.stream_send(4, b"", true), Ok(0));

    let flight = test_utils::emit_flight(&mut pipe.server)?;
    let mut frames = Vec::new();

    for (mut pkt, _) in flight.clone() {
        frames.extend(test_utils::decode_pkt(&pipe.client, &mut pkt)?);
    }

    assert!(frames.iter().any(|f| matches!(
        f,
        frame::Frame::Stream { stream_id: 4, data }
            if data.off() == 256 && data.is_empty() && data.fin()
    )));

    test_utils::process_flight(&mut pipe.client, flight)?;
    assert_eq!(pipe.client.stream_recv(4, &mut buf), Ok((256, true)));
    Ok(())
}

#[rstest]
/// Tests that retransmitting lost stream data does not resend a FIN that is
/// still in flight.
fn stream_inflight_fin_is_not_resent_after_data_retransmission(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut pipe = fin_retransmission_pipe(cc_algorithm_name, &mut buf)?;

    let data = vec![42; 256];
    assert_eq!(pipe.server.stream_send(4, &data, true), Ok(256));

    let mut flight = test_utils::emit_flight_with_max_buffer(
        &mut pipe.server,
        64,
        None,
        None,
    )?;
    assert!(flight.len() > 4);

    // Lose the first packet and hold back the FIN-bearing last packet. The ACK
    // for the packets in between declares the first one lost.
    let lost = flight.remove(0);
    let fin = flight.pop().ok_or("expected nonempty packet flight")?;

    let mut lost_pkt = lost.0;
    let frames = test_utils::decode_pkt(&pipe.client, &mut lost_pkt)?;
    assert!(frames.iter().any(|f| matches!(
        f,
        frame::Frame::Stream { stream_id: 4, data } if !data.fin()
    )));

    let mut fin_pkt = fin.0.clone();
    let frames = test_utils::decode_pkt(&pipe.client, &mut fin_pkt)?;
    assert!(frames.iter().any(|f| matches!(
        f,
        frame::Frame::Stream { stream_id: 4, data } if data.fin()
    )));

    test_utils::process_flight(&mut pipe.client, flight)?;
    let ack = test_utils::emit_flight(&mut pipe.client)?;
    test_utils::process_flight(&mut pipe.server, ack)?;

    let flight = test_utils::emit_flight(&mut pipe.server)?;
    let mut frames = Vec::new();
    for (pkt, _) in &flight {
        frames.extend(test_utils::decode_pkt(&pipe.client, &mut pkt.clone())?);
    }

    assert!(frames.iter().any(|f| matches!(
        f,
        frame::Frame::Stream { stream_id: 4, data } if data.off() == 0
    )));
    assert!(
        !frames.iter().any(|f| matches!(
            f,
            frame::Frame::Stream { stream_id: 4, data } if data.fin()
        )),
        "in-flight FIN was resent: {frames:?}"
    );

    test_utils::process_flight(&mut pipe.client, flight)?;
    test_utils::process_flight(&mut pipe.client, vec![fin])?;
    assert_eq!(pipe.client.stream_recv(4, &mut buf), Ok((256, true)));
    Ok(())
}

#[rstest]
/// Tests that a lost FIN is not retransmitted after the stream was reset, as
/// no STREAM frame can follow `RESET_STREAM`.
fn stream_lost_fin_is_not_retransmitted_after_reset(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(true, false)] empty_fin: bool,
) -> Result<()> {
    let mut buf = vec![0; 65_535];

    let mut pipe = test_utils::Pipe::new(cc_algorithm_name)?;
    assert_eq!(pipe.handshake(), Ok(()));

    // Keep the receive side open so the stream isn't collected on reset.
    assert_eq!(pipe.client.stream_send(4, b"hello", false), Ok(5));
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(pipe.server.stream_recv(4, &mut buf), Ok((5, false)));

    if empty_fin {
        assert_eq!(pipe.server.stream_send(4, b"response", false), Ok(8));
        assert_eq!(pipe.advance(), Ok(()));
        assert_eq!(pipe.client.stream_recv(4, &mut buf), Ok((8, false)));

        assert_eq!(pipe.server.stream_send(4, b"", true), Ok(0));
    } else {
        assert_eq!(pipe.server.stream_send(4, b"response", true), Ok(8));
    }

    // Lose the FIN-bearing packet.
    let (len, _) = pipe.server.send(&mut buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;

    assert!(frames.iter().any(|f| matches!(
        f,
        frame::Frame::Stream { stream_id: 4, data } if data.fin()
    )));

    assert_eq!(pipe.server.stream_shutdown(4, Shutdown::Write, 42), Ok(()));

    test_utils::trigger_ack_based_loss(&mut pipe.server, &mut pipe.client)?;
    assert!(!pipe.server.streams.is_collected(4));

    let flight = match test_utils::emit_flight(&mut pipe.server) {
        Ok(flight) => flight,
        Err(Error::Done) => Vec::new(),
        Err(error) => return Err(error),
    };
    let mut frames = Vec::new();

    for (mut pkt, _) in flight {
        frames.extend(test_utils::decode_pkt(&pipe.client, &mut pkt)?);
    }

    assert!(
        !frames
            .iter()
            .any(|f| matches!(f, frame::Frame::Stream { stream_id: 4, .. })),
        "STREAM frame sent after RESET_STREAM: {frames:?}"
    );
    Ok(())
}

/// Lost `MAX_STREAMS` credit survives an undersized output buffer and is
/// retransmitted with the correct direction and updated limit.
#[rstest]
fn max_streams_frame_retransmit(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
    #[values(Bidirectional, Unidirectional)] direction: StreamDirection,
) -> Result<()> {
    const NUM_STREAMS: u64 = 4;
    let mut buf = vec![0; 65_535];
    let mut config = test_utils::Pipe::default_config(cc_algorithm_name)?;
    config.set_initial_max_streams_bidi(if direction == Bidirectional {
        NUM_STREAMS
    } else {
        0
    });
    config.set_initial_max_streams_uni(if direction == Unidirectional {
        NUM_STREAMS
    } else {
        0
    });
    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));
    let id = |ordinal: u64| ordinal * 4 + 2 * direction.wire_bit();
    for ordinal in 0..NUM_STREAMS {
        assert_eq!(pipe.client.stream_send(id(ordinal), b"a", true), Ok(1));
    }
    pipe.advance()?;
    assert_eq!(
        pipe.server.streams.quota(direction).next_local_limit(),
        NUM_STREAMS
    );
    for ordinal in 0..NUM_STREAMS {
        assert_eq!(
            pipe.server.stream_recv(id(ordinal), &mut buf),
            Ok((1, true))
        );
    }

    // Bidi streams require the server's FIN to be acknowledged before
    // collection; uni streams are collected as soon as the receiver drains.
    let limit = match direction {
        Bidirectional => {
            pipe.server.stream_send(id(0), b"a", true)?;
            let (len, _) = pipe.server.send(&mut buf)?;
            assert_eq!(
                pipe.server.streams.quota(direction).next_local_limit(),
                NUM_STREAMS
            );
            assert_eq!(pipe.client.streams.quota(direction).peer_available(), 0);
            pipe.client_recv(&mut buf[..len])?;
            let (len, _) = pipe.client.send(&mut buf)?;
            pipe.server_recv(&mut buf[..len])?;
            NUM_STREAMS + 1
        },
        Unidirectional => NUM_STREAMS * 2,
    };
    assert_eq!(
        pipe.server.streams.quota(direction).next_local_limit(),
        limit
    );
    let expected = frame::Frame::MaxStreams {
        direction,
        max: limit,
    };

    // Drop the original packet without processing it at the peer.
    let (len, _) = pipe.server.send(&mut buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    assert!(
        frames.contains(&expected),
        "missing {expected:?}: {frames:?}"
    );
    assert_eq!(pipe.client.streams.quota(direction).peer_available(), 0);

    test_utils::trigger_ack_based_loss(&mut pipe.server, &mut pipe.client)?;
    assert_eq!(pipe.server.send(&mut buf[..1]), Err(Error::Done));
    let (len, _) = pipe.server.send(&mut buf)?;
    let frames = test_utils::decode_pkt(&pipe.client, &mut buf[..len])?;
    assert!(
        frames.contains(&expected),
        "missing {expected:?}: {frames:?}"
    );
    Ok(())
}

#[cfg(feature = "custom-client-dcid")]
#[rstest]
fn connect_custom_client_dcid_too_short() -> TestResult {
    let mut client_scid = [0; 16];
    rand::rand_bytes(&mut client_scid[..]);
    let client_scid = ConnectionId::from_ref(&client_scid);
    let client_addr = "127.0.0.1:1234".parse()?;

    let server_addr = "127.0.0.1:4321".parse()?;

    // Just use something which is smaller than 8 (which is the minimum)
    let mut client_dcid = [0; 6];
    rand::rand_bytes(&mut client_dcid[..]);
    let client_dcid = ConnectionId::from_ref(&client_dcid);

    let mut client_config = Config::new(PROTOCOL_VERSION)?;
    client_config.set_application_protos(&[b"proto1", b"proto2"])?;

    let client = connect_with_dcid(
        Some("quic.tech"),
        &client_scid,
        &client_dcid,
        client_addr,
        server_addr,
        &mut client_config,
    );
    assert!(matches!(client, Err(Error::InvalidDcidInitialization)));
    Ok(())
}

#[cfg(feature = "qlog")]
struct TestQlogWriter(Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(feature = "qlog")]
impl std::io::Write for TestQlogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("qlog buffer poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "qlog")]
#[test]
fn server_qlog() -> TestResult {
    use qlog::reader::QlogSeqReader;

    let mut pipe = test_utils::Pipe::new("cubic")?;

    let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
    pipe.server.set_qlog(
        Box::new(TestQlogWriter(Arc::clone(&buffer))),
        "test qlog".to_string(),
        "test qlog description".to_string(),
    );

    assert_eq!(pipe.handshake(), Ok(()));

    pipe.server
        .qlog_streamer()
        .ok_or("qlog is not enabled")?
        .finish_log()?;

    let bytes =
        std::mem::take(&mut *buffer.lock().map_err(|_| "qlog buffer poisoned")?);

    let mut reader = QlogSeqReader::new(Box::new(std::io::BufReader::new(
        std::io::Cursor::new(bytes),
    )))?;

    // Header is parsed by QlogSeqReader::new into reader.qlog.
    let header = reader.qlog.clone();
    assert_eq!(header.title.as_deref(), Some("test qlog"));
    assert_eq!(header.description.as_deref(), Some("test qlog description"));
    assert_eq!(
        header
            .trace
            .vantage_point
            .ok_or("qlog vantage point missing")?
            .ty,
        qlog::VantagePointType::Server
    );
    let ref_time = header
        .trace
        .common_fields
        .ok_or("qlog common fields missing")?
        .reference_time;
    assert_eq!(ref_time.clock_type, "monotonic");
    assert_eq!(ref_time.epoch, "unknown");
    assert!(ref_time.wall_clock_time.is_some());

    // First event yielded by the iterator is TransportParametersSet.
    let first = reader.next().ok_or("qlog event stream is empty")??;
    let qlog::reader::Event::Qlog(event) = first else {
        return Err("expected Qlog event".into());
    };
    let EventData::QuicParametersSet(params) = event.data else {
        return Err("expected QuicParametersSet event".into());
    };
    assert_eq!(params.initiator, Some(TransportInitiator::Local));
    Ok(())
}

// Pins the reserved-bits masks to the values required by RFC 9000 section
// 17.2 (long header) and section 17.3.1 (short header), so an accidental
// change to `reserved_bits()` (e.g. `0x0c` becoming `0x0d`) fails a test
// instead of silently drifting from a MUST-level spec requirement. See
// `recv_single`'s reserved-bits check, which relies on this function.
#[test]
fn reserved_bits_long_header_mask() {
    // Bits 0b0000_1100 are reserved on a long header; everything else must
    // be masked away.
    assert_eq!(reserved_bits(0b1111_1111, Type::Initial), 0x0c);
    assert_eq!(reserved_bits(0b0000_0000, Type::Initial), 0x00);
    assert_eq!(reserved_bits(0b0000_1100, Type::Initial), 0x0c);
    assert_eq!(reserved_bits(0b1111_0011, Type::Initial), 0x00);
}

#[test]
fn reserved_bits_short_header_mask() {
    // Bits 0b0001_1000 are reserved on a short header; everything else must
    // be masked away.
    assert_eq!(reserved_bits(0b1111_1111, Type::Short), 0x18);
    assert_eq!(reserved_bits(0b0000_0000, Type::Short), 0x00);
    assert_eq!(reserved_bits(0b0001_1000, Type::Short), 0x18);
    assert_eq!(reserved_bits(0b1110_0111, Type::Short), 0x00);
}

#[rstest]
fn rejected_zero_rtt_resets_stream_state(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    const TICKET_KEY: [u8; 48] = [0xa; 48];

    let mut config = test_utils::Pipe::default_config_no_pq(cc_algorithm_name)?;
    config.set_ticket_key(&TICKET_KEY)?;
    config.enable_early_data();

    let mut pipe = test_utils::Pipe::with_config(&mut config)?;
    assert_eq!(pipe.handshake(), Ok(()));
    let session = pipe.client.session().ok_or("TLS session was not issued")?;

    let mut client_config =
        test_utils::Pipe::default_config_no_pq(cc_algorithm_name)?;
    client_config.enable_early_data();
    let mut server_config =
        test_utils::Pipe::default_config_no_pq(cc_algorithm_name)?;
    server_config.set_ticket_key(&TICKET_KEY)?;

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )?;
    assert_eq!(pipe.client.set_session(session), Ok(()));

    let mut buf = vec![0; 65_535];
    let (len, _) = pipe.client.send(&mut buf)?;
    let mut initial = buf[..len].to_vec();
    assert!(pipe.client.is_in_early_data());

    assert_eq!(pipe.client.stream_send(4, b"hello", true), Ok(5));
    let (len, _) = pipe.client.send(&mut buf)?;
    assert!(len > 0);
    assert!(pipe.client.streams.get(4).is_some());
    let next_packet_number = pipe.client.next_pkt_num;
    assert_eq!(pipe.client.tx_data, 5);

    // The server never receives the 0-RTT packet.
    assert_eq!(pipe.server_recv(&mut initial), Ok(initial.len()));
    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;

    assert!(!pipe.client.is_in_early_data());
    assert!(pipe.client.early_data_rejected());
    assert_eq!(pipe.client.next_pkt_num, next_packet_number);
    assert_eq!(pipe.client.streams.len(), 0);
    assert_eq!(pipe.client.tx_data, 0);
    assert_eq!(
        pipe.client
            .paths
            .get_active()?
            .recovery
            .sent_packets_len(packet::Epoch::Application),
        0
    );

    assert_eq!(pipe.handshake(), Ok(()));
    assert_eq!(pipe.client.stream_send(4, b"replay", true), Ok(6));
    assert_eq!(pipe.client.tx_data, 6);
    assert_eq!(pipe.advance(), Ok(()));

    let mut received = [0; 6];
    assert_eq!(pipe.server.stream_recv(4, &mut received), Ok((6, true)));
    assert_eq!(&received, b"replay");
    assert!(pipe.client.next_pkt_num > next_packet_number);
    Ok(())
}

#[rstest]
fn rejected_zero_rtt_clears_auxiliary_send_state(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    const TICKET_KEY: [u8; 48] = [0xb; 48];

    let mut ticket_config =
        test_utils::Pipe::default_config_no_pq(cc_algorithm_name)?;
    ticket_config.set_ticket_key(&TICKET_KEY)?;
    ticket_config.enable_early_data();
    ticket_config.set_initial_max_data(1);
    ticket_config.set_initial_max_stream_data_bidi_remote(8);
    ticket_config.set_initial_max_streams_bidi(1);
    ticket_config.set_enable_send_streams_blocked(true);
    ticket_config.enable_dgram(true, 8, 8);

    let mut first = test_utils::Pipe::with_config(&mut ticket_config)?;
    assert_eq!(first.handshake(), Ok(()));
    let session = first.client.session().ok_or("TLS session was not issued")?;

    let mut client_config =
        test_utils::Pipe::default_config_no_pq(cc_algorithm_name)?;
    client_config.enable_early_data();
    client_config.set_enable_send_streams_blocked(true);
    client_config.enable_dgram(true, 8, 8);

    let mut server_config =
        test_utils::Pipe::default_config_no_pq(cc_algorithm_name)?;
    server_config.set_ticket_key(&TICKET_KEY)?;
    server_config.enable_dgram(true, 8, 8);

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )?;
    assert_eq!(pipe.client.set_session(session), Ok(()));

    let mut buf = vec![0; 65_535];
    let (len, _) = pipe.client.send(&mut buf)?;
    let mut initial = buf[..len].to_vec();
    assert!(pipe.client.is_in_early_data());

    assert_eq!(pipe.client.stream_send(0, b"ab", false), Ok(1));
    assert_eq!(pipe.client.blocked_limit, Some(1));

    assert_eq!(
        pipe.client.stream_send(4, b"x", false),
        Err(Error::StreamLimit)
    );
    assert!(pipe
        .client
        .streams
        .quota(Bidirectional)
        .pending_blocked_limit()
        .is_some());

    assert_eq!(pipe.client.dgram_send(b"early-dgram"), Ok(()));
    assert_eq!(pipe.client.dgram_send_queue_len(), 1);

    // Reject early data before any of the queued 0-RTT application state is
    // delivered to the server.
    assert_eq!(pipe.server_recv(&mut initial), Ok(initial.len()));
    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;

    assert!(pipe.client.early_data_rejected());
    assert_eq!(pipe.client.blocked_limit, None);
    assert!(pipe
        .client
        .streams
        .quota(Bidirectional)
        .pending_blocked_limit()
        .is_none());
    assert!(pipe
        .client
        .streams
        .quota(Unidirectional)
        .pending_blocked_limit()
        .is_none());
    assert_eq!(pipe.client.dgram_send_queue_len(), 0);
    Ok(())
}

#[rstest]
fn rejected_zero_rtt_replays_http3_request(
    #[values("cubic", "bbr2_gcongestion")] cc_algorithm_name: &str,
) -> TestResult {
    const TICKET_KEY: [u8; 48] = [0xa; 48];

    let configure = || -> Result<Config> {
        let mut config =
            test_utils::Pipe::default_config_no_pq(cc_algorithm_name)?;
        config.set_application_protos(&[b"h3"])?;
        config.set_initial_max_data(10000);
        config.set_initial_max_stream_data_bidi_local(1000);
        config.set_initial_max_stream_data_bidi_remote(1000);
        config.set_initial_max_stream_data_uni(1000);
        config.set_initial_max_streams_bidi(5);
        config.set_initial_max_streams_uni(5);
        Ok(config)
    };

    let mut ticket_config = configure()?;
    ticket_config.set_ticket_key(&TICKET_KEY)?;
    ticket_config.enable_early_data();

    let mut first = test_utils::Pipe::with_config(&mut ticket_config)?;
    assert_eq!(first.handshake(), Ok(()));
    let session = first.client.session().ok_or("TLS session was not issued")?;

    let mut client_config = configure()?;
    client_config.enable_early_data();
    let mut server_config = configure()?;
    server_config.set_ticket_key(&TICKET_KEY)?;

    let mut pipe = test_utils::Pipe::with_client_and_server_config(
        &mut client_config,
        &mut server_config,
    )?;
    assert_eq!(pipe.client.set_session(session), Ok(()));

    let mut buf = vec![0; 65_535];
    let (len, _) = pipe.client.send(&mut buf)?;
    let mut initial = buf[..len].to_vec();
    assert!(pipe.client.is_in_early_data());

    let h3_config = h3::Config::new();
    let request = vec![
        h3::Header::new(b":method", b"GET"),
        h3::Header::new(b":scheme", b"https"),
        h3::Header::new(b":authority", b"quic.tech"),
        h3::Header::new(b":path", b"/replay"),
    ];

    let mut early_h3 =
        h3::Connection::with_transport(&mut pipe.client, &h3_config)?;
    let early_stream = early_h3.send_request(&mut pipe.client, &request, true)?;
    let early_flight = test_utils::emit_flight(&mut pipe.client)?;
    assert_ne!(early_flight, [] as [(Vec<u8>, SendInfo); 0]);

    assert_eq!(pipe.server_recv(&mut initial), Ok(initial.len()));
    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;
    assert!(pipe.client.early_data_rejected());

    drop(early_h3);
    assert_eq!(pipe.handshake(), Ok(()));

    let mut client_h3 =
        h3::Connection::with_transport(&mut pipe.client, &h3_config)?;
    let mut server_h3 =
        h3::Connection::with_transport(&mut pipe.server, &h3_config)?;

    let replay_stream =
        client_h3.send_request(&mut pipe.client, &request, true)?;
    assert_eq!(replay_stream, early_stream);
    assert_eq!(pipe.advance(), Ok(()));

    assert_eq!(
        server_h3.poll(&mut pipe.server),
        Ok((replay_stream, h3::Event::Headers {
            list: request,
            more_frames: false,
        },)),
    );

    let response = vec![h3::Header::new(b":status", b"200")];
    assert_eq!(
        server_h3
            .send_response(&mut pipe.server, replay_stream, &response, true,),
        Ok(()),
    );
    assert_eq!(pipe.advance(), Ok(()));
    assert_eq!(
        client_h3.poll(&mut pipe.client),
        Ok((replay_stream, h3::Event::Headers {
            list: response,
            more_frames: false,
        },)),
    );
    Ok(())
}

/// PADDING is not ack-eliciting, but RFC 9002 Section 2 still counts packets
/// containing PADDING toward bytes in flight.
#[test]
fn padding_only_packet_counts_toward_bytes_in_flight() -> TestResult {
    let mut buf = vec![0; 65_535];

    let mut config = test_utils::config_no_pq(PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file("examples/cert.crt")?;
    config.load_priv_key_from_pem_file("examples/cert.key")?;
    config.set_application_protos(&[b"proto1", b"proto2"])?;
    config.set_initial_max_data(30000);
    config.set_initial_max_stream_data_bidi_local(15000);
    config.set_initial_max_stream_data_bidi_remote(15000);
    config.set_initial_max_streams_bidi(3);
    config.enable_early_data();
    config.verify_peer(false);

    let mut pipe = resumed_pipe(&mut config)?;

    let (len, _) = pipe.client.send(&mut buf)?;
    let mut initial = buf[..len].to_vec();
    assert!(pipe.client.is_in_early_data());

    assert_eq!(pipe.client.stream_send(4, b"hello, world", true), Ok(12));
    let (len, _) = pipe.client.send(&mut buf)?;
    let mut zrtt = buf[..len].to_vec();

    assert_eq!(pipe.server_recv(&mut initial), Ok(initial.len()));
    assert_eq!(pipe.server_recv(&mut zrtt), Ok(zrtt.len()));

    let flight = test_utils::emit_flight(&mut pipe.server)?;
    test_utils::process_flight(&mut pipe.client, flight)?;

    let flight = test_utils::emit_flight(&mut pipe.client)?;
    let sent: usize = flight.iter().map(|(b, _)| b.len()).sum();

    let bytes_in_flight =
        pipe.client.paths.get_active()?.recovery.bytes_in_flight();

    assert!(
        bytes_in_flight >= sent * 3 / 4,
        "padded packets should be accounted for: sent {sent} bytes, \
         {bytes_in_flight} in flight"
    );
    Ok(())
}

#[test]
fn alpn_rejects_invalid_lengths_without_changing_configuration() -> TestResult {
    let mut config = Config::new(0xbaba_baba)?;
    config.set_application_protos(&[b"h3"])?;

    for invalid in [&[][..], &[b'x'; 256][..]] {
        assert!(config.set_application_protos(&[invalid]).is_err());
        assert_eq!(config.application_protos, vec![b"h3".to_vec()]);
    }

    assert!(config
        .set_application_protos(&[b"h3", &[b'x'; 256]])
        .is_err());
    assert_eq!(config.application_protos, vec![b"h3".to_vec()]);
    Ok(())
}

#[test]
fn alpn_wire_format_rejects_truncated_entries() -> TestResult {
    let mut config = Config::new(0xbaba_baba)?;
    config.set_application_protos(&[b"h3"])?;

    for invalid in [&b"\x04h3"[..], &b"\x02h3\x03x"[..], &b"\x00"[..]] {
        assert!(config.set_application_protos_wire_format(invalid).is_err());
        assert_eq!(config.application_protos, vec![b"h3".to_vec()]);
    }
    Ok(())
}

#[test]
fn alpn_rejects_empty_and_oversized_protocol_lists() -> TestResult {
    let mut config = Config::new(0xbaba_baba)?;
    config.set_application_protos(&[b"h3"])?;

    assert!(config.set_application_protos(&[]).is_err());
    assert!(config.set_application_protos_wire_format(b"").is_err());
    assert_eq!(config.application_protos, vec![b"h3".to_vec()]);

    // 255 * (1 + 255) + (1 + 252) = 65_533: the largest ALPN list
    // that fits into the TLS extension's 16-bit length.
    let long_proto = [b'a'; 255];
    let last_proto = [b'b'; 252];
    let mut protos: Vec<&[u8]> = vec![&long_proto; 255];
    protos.push(&last_proto);

    config.set_application_protos(&protos)?;
    let previous = config.application_protos.clone();

    protos.push(b"c");
    assert!(config.set_application_protos(&protos).is_err());
    assert_eq!(config.application_protos, previous);

    let mut wire = Vec::new();
    for proto in &protos {
        wire.push(u8::try_from(proto.len())?);
        wire.extend_from_slice(proto);
    }
    assert!(config.set_application_protos_wire_format(&wire).is_err());
    assert_eq!(config.application_protos, previous);
    Ok(())
}

#[test]
fn remembered_peer_limits_are_not_negotiated_parameters() -> TestResult {
    let mut pipe = test_utils::Pipe::new("cubic")?;
    assert!(pipe.client.peer_transport_params().is_none());
    let remembered = TransportParams {
        initial_max_data: 1234,
        ..TransportParams::default()
    };
    pipe.client
        .apply_peer_parameters(PeerParameters::Remembered(remembered))?;
    assert_eq!(
        pipe.client.peer_parameters.effective().initial_max_data,
        1234
    );
    assert!(pipe.client.peer_transport_params().is_none());
    assert!(pipe.client.peer_transport_params_wire().is_none());
    pipe.handshake()?;
    assert!(pipe.client.peer_transport_params().is_some());
    assert!(pipe.client.peer_transport_params_wire().is_some());
    assert_ne!(
        pipe.client.peer_parameters.effective().initial_max_data,
        1234
    );
    Ok(())
}

#[test]
fn handshake_progress_is_monotonic_in_either_order() {
    for confirmation_first in [false, true] {
        let mut progress = HandshakeProgress::default();
        assert!(!progress.completed());
        assert!(!progress.confirmed());
        if confirmation_first {
            progress.confirm();
            assert_eq!(progress, HandshakeProgress::PeerConfirmed);
            assert!(!progress.completed());
            assert!(progress.confirmed());
            progress.confirm();
            progress.mark_completed();
        } else {
            progress.mark_completed();
            assert_eq!(progress, HandshakeProgress::Established);
            assert!(progress.completed());
            assert!(!progress.confirmed());
            progress.mark_completed();
            progress.confirm();
        }
        assert_eq!(progress, HandshakeProgress::Confirmed);
        assert!(progress.completed());
        assert!(progress.confirmed());
        progress.confirm();
        progress.mark_completed();
        assert_eq!(progress, HandshakeProgress::Confirmed);
    }
}
