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

use serde::Deserialize;
use serde::Serialize;

use super::EventHeader;

#[cfg_attr(
    feature = "nightly-clippy-expects",
    expect(
        clippy::enum_variant_names,
        reason = "Variants mirror Chrome netlog QUIC event names and are part of the public API"
    )
)]
#[derive(Debug)]
pub enum Event {
    QuicSession(QuicSessionEvent),
    QuicSessionTransportParametersSent(QuicSessionTransportParametersEvent),
    QuicSessionTransportParametersReceived(QuicSessionTransportParametersEvent),
    QuicSessionUnauthenticatedPacketHeaderReceived(
        QuicSessionUnauthenticatedPacketHeaderReceived,
    ),
    QuicSessionPacketSent(QuicSessionPacketSent),
    QuicSessionAckFrameSent(QuicSessionAckFrameEvent),
    QuicSessionAckFrameReceived(QuicSessionAckFrameEvent),
    QuicSessionStreamFrameReceived(QuicSessionStreamFrameEvent),
    QuicSessionStreamFrameSent(QuicSessionStreamFrameEvent),
    QuicSessionStopSendingFrameSent(QuicSessionStopSendingFrameSentEvent),
    QuicSessionRstStreamFrameSent(QuicSessionRstStreamFrameEvent),
    QuicSessionRstStreamFrameReceived(QuicSessionRstStreamFrameEvent),
    QuicSessionBlockedFrameReceived(QuicSessionBlockedFrameReceivedEvent),
    QuicSessionWindowUpdateFrameSent(QuicSessionWindowUpdateFrameEvent),
    QuicSessionWindowUpdateFrameReceived(QuicSessionWindowUpdateFrameEvent),
    QuicSessionClosed(QuicSessionClosedEvent),
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionParams {
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub cert_verify_flags: u64,
    pub connection_id: String,
    pub host: String,
    pub port: u16,
    #[serde(alias = "network_anonymization_key")]
    pub network_isolation_key: String,
    pub privacy_mode: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionEvent {
    pub params: QuicSessionParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionTransportParametersParams {
    pub quic_transport_parameters: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionTransportParametersEvent {
    pub params: QuicSessionTransportParametersParams,
}

// TODO: this should really be done using serde, not hacked like this. What
// makes it difficult is netlogs concats all these fields into one string.
#[derive(Debug, Default)]
pub struct TransportParameters {
    pub versions: String,
    pub max_idle_timeout: Option<u64>,
    pub max_udp_payload_size: Option<u64>,
    pub initial_max_data: Option<u64>,
    pub initial_max_stream_data_bidi_local: Option<u64>,
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    pub initial_max_stream_data_uni: Option<u64>,
    pub initial_max_streams_bidi: Option<u64>,
    pub initial_max_streams_uni: Option<u64>,
    pub initial_source_connection_id: Option<String>,
    pub max_datagram_frame_size: Option<u64>,
}

/// Split Chrome's bracketed transport-parameter debug format into top-level
/// words, retaining nested version/address groups as single tokens.
fn parameter_words(value: &str) -> Option<Vec<&str>> {
    let inner = value.trim().strip_prefix('[')?.strip_suffix(']')?;
    let mut words = Vec::new();
    let mut start = 0;
    let mut depth = 0_usize;
    for (index, character) in inner.char_indices() {
        match character {
            '[' => depth += 1,
            ']' => depth = depth.checked_sub(1)?,
            ch if depth == 0 && ch.is_whitespace() => {
                if start < index {
                    words.push(&inner[start..index]);
                }
                start = index + ch.len_utf8();
            },
            _ => (),
        }
    }
    if depth != 0 {
        return None;
    }
    if start < inner.len() {
        words.push(&inner[start..]);
    }
    Some(words)
}

impl From<&str> for TransportParameters {
    fn from(value: &str) -> Self {
        let Some(words) = parameter_words(value) else {
            return Self::default();
        };
        if !matches!(words.first(), Some(&"Client" | &"Server")) {
            return Self::default();
        }
        let mut parameters = Self {
            versions: words
                .iter()
                .copied()
                .skip(1)
                .take_while(|word| {
                    word.starts_with('[') || word.starts_with("legacy[")
                })
                .collect::<Vec<_>>()
                .join(" "),
            ..Self::default()
        };
        for pair in words.windows(2) {
            let [name, value] = pair else {
                continue;
            };
            let target = match *name {
                "max_idle_timeout" => &mut parameters.max_idle_timeout,
                "max_udp_payload_size" => &mut parameters.max_udp_payload_size,
                "initial_max_data" => &mut parameters.initial_max_data,
                "initial_max_stream_data_bidi_local" =>
                    &mut parameters.initial_max_stream_data_bidi_local,
                "initial_max_stream_data_bidi_remote" =>
                    &mut parameters.initial_max_stream_data_bidi_remote,
                "initial_max_stream_data_uni" =>
                    &mut parameters.initial_max_stream_data_uni,
                "initial_max_streams_bidi" =>
                    &mut parameters.initial_max_streams_bidi,
                "initial_max_streams_uni" =>
                    &mut parameters.initial_max_streams_uni,
                "max_datagram_frame_size" =>
                    &mut parameters.max_datagram_frame_size,
                "initial_source_connection_id" => {
                    parameters.initial_source_connection_id = value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                        .then(|| (*value).to_owned());
                    continue;
                },
                _ => continue,
            };
            *target = value.parse().ok();
        }
        parameters
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionUnauthenticatedPacketHeaderReceivedParams {
    pub connection_id: String,
    pub header_format: String,
    pub long_header_type: Option<String>,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub packet_number: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionUnauthenticatedPacketHeaderReceived {
    pub params: QuicSessionUnauthenticatedPacketHeaderReceivedParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionPacketSentParams {
    pub encryption_level: String,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub packet_number: u64,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub sent_time_us: u64,
    transmission_type: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionPacketSent {
    pub params: QuicSessionPacketSentParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicReceivedPacketTime {
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub packet_number: u64,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub received: i64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionAckFrameParams {
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub delta_time_largest_observed_us: u64,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub largest_observed: u64,
    #[serde(deserialize_with = "crate::wire_number::deserialize_vec")]
    pub missing_packets: Vec<u64>,
    pub received_packet_times: Vec<QuicReceivedPacketTime>,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub smallest_observed: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionAckFrameEvent {
    pub params: QuicSessionAckFrameParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionStreamFrameParams {
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub stream_id: u64,
    pub fin: bool,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub offset: u64,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub length: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionStreamFrameEvent {
    pub params: QuicSessionStreamFrameParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionStopSendingFrameSentParams {
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub stream_id: u64,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub quic_rst_stream_error: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionStopSendingFrameSentEvent {
    pub params: QuicSessionStopSendingFrameSentParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionRstStreamFrameParams {
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub stream_id: u64,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub quic_rst_stream_error: u64,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub offset: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionRstStreamFrameEvent {
    pub params: QuicSessionRstStreamFrameParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionBlockedFrameReceivedParams {
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub stream_id: i64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionBlockedFrameReceivedEvent {
    pub params: QuicSessionBlockedFrameReceivedParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionWindowUpdateFrameParams {
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub byte_offset: u64,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub stream_id: i64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionWindowUpdateFrameEvent {
    pub params: QuicSessionWindowUpdateFrameParams,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionClosedParams {
    pub details: String,
    pub from_peer: bool,
    #[serde(deserialize_with = "crate::wire_number::deserialize")]
    pub quic_error: i64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct QuicSessionClosedEvent {
    pub params: QuicSessionClosedParams,
}

/// Parses the provided `event` based on the event type provided in `event_hdr`.
#[must_use = "the result contains the decoded event, or indicates that it could not be decoded"]
#[expect(
    clippy::too_many_lines,
    reason = "Explicit wire-event dispatch is easier to audit than splitting the protocol mapping across helpers"
)]
pub fn parse_event(
    event_hdr: &EventHeader, event: &[u8],
) -> Option<super::Event> {
    match event_hdr.ty_string.as_str() {
        "QUIC_SESSION" =>
            if event_hdr.phase_string == "PHASE_BEGIN" {
                let ev: QuicSessionEvent = super::decode_event(event)?;
                return Some(super::Event::Quic(Event::QuicSession(ev)));
            },

        "QUIC_SESSION_TRANSPORT_PARAMETERS_SENT" => {
            let ev: QuicSessionTransportParametersEvent =
                super::decode_event(event)?;
            return Some(super::Event::Quic(
                Event::QuicSessionTransportParametersSent(ev),
            ));
        },

        "QUIC_SESSION_TRANSPORT_PARAMETERS_RECEIVED" => {
            let ev: QuicSessionTransportParametersEvent =
                super::decode_event(event)?;
            return Some(super::Event::Quic(
                Event::QuicSessionTransportParametersReceived(ev),
            ));
        },

        "QUIC_SESSION_STREAM_FRAME_RECEIVED" => {
            let ev: QuicSessionStreamFrameEvent = super::decode_event(event)?;
            return Some(super::Event::Quic(
                Event::QuicSessionStreamFrameReceived(ev),
            ));
        },

        "QUIC_SESSION_STREAM_FRAME_SENT" => {
            let ev: QuicSessionStreamFrameEvent = super::decode_event(event)?;
            return Some(super::Event::Quic(Event::QuicSessionStreamFrameSent(
                ev,
            )));
        },

        "QUIC_SESSION_STOP_SENDING_FRAME_SENT" => {
            let ev: QuicSessionStopSendingFrameSentEvent =
                super::decode_event(event)?;
            return Some(super::Event::Quic(
                Event::QuicSessionStopSendingFrameSent(ev),
            ));
        },

        "QUIC_SESSION_RST_STREAM_FRAME_SENT" => {
            let ev: QuicSessionRstStreamFrameEvent = super::decode_event(event)?;
            return Some(super::Event::Quic(
                Event::QuicSessionRstStreamFrameSent(ev),
            ));
        },

        "QUIC_SESSION_RST_STREAM_FRAME_RECEIVED" => {
            let ev: QuicSessionRstStreamFrameEvent = super::decode_event(event)?;
            return Some(super::Event::Quic(
                Event::QuicSessionRstStreamFrameReceived(ev),
            ));
        },

        "QUIC_SESSION_UNAUTHENTICATED_PACKET_HEADER_RECEIVED" => {
            let ev: QuicSessionUnauthenticatedPacketHeaderReceived =
                super::decode_event(event)?;

            return Some(super::Event::Quic(
                Event::QuicSessionUnauthenticatedPacketHeaderReceived(ev),
            ));
        },

        "QUIC_SESSION_PACKET_SENT" => {
            let ev: QuicSessionPacketSent = super::decode_event(event)?;

            return Some(super::Event::Quic(Event::QuicSessionPacketSent(ev)));
        },

        "QUIC_SESSION_ACK_FRAME_SENT" => {
            let ev: QuicSessionAckFrameEvent = super::decode_event(event)?;

            return Some(super::Event::Quic(Event::QuicSessionAckFrameSent(ev)));
        },

        "QUIC_SESSION_ACK_FRAME_RECEIVED" => {
            let ev: QuicSessionAckFrameEvent = super::decode_event(event)?;

            return Some(super::Event::Quic(Event::QuicSessionAckFrameReceived(
                ev,
            )));
        },

        "QUIC_SESSION_CLOSED" => {
            let ev: QuicSessionClosedEvent = super::decode_event(event)?;

            return Some(super::Event::Quic(Event::QuicSessionClosed(ev)));
        },

        "QUIC_SESSION_BLOCKED_FRAME_RECEIVED" => {
            let ev: QuicSessionBlockedFrameReceivedEvent =
                super::decode_event(event)?;
            return Some(super::Event::Quic(
                Event::QuicSessionBlockedFrameReceived(ev),
            ));
        },

        "QUIC_SESSION_WINDOW_UPDATE_FRAME_SENT" => {
            let ev: QuicSessionWindowUpdateFrameEvent =
                super::decode_event(event)?;
            return Some(super::Event::Quic(
                Event::QuicSessionWindowUpdateFrameSent(ev),
            ));
        },

        "QUIC_SESSION_WINDOW_UPDATE_FRAME_RECEIVED" => {
            let ev: QuicSessionWindowUpdateFrameEvent =
                super::decode_event(event)?;
            return Some(super::Event::Quic(
                Event::QuicSessionWindowUpdateFrameReceived(ev),
            ));
        },

        // Known events that are intentionally ignored for now.
        "QUIC_SESSION_STOP_SENDING_FRAME_RECEIVED" |
        "QUIC_SESSION_PACKET_RETRANSMITTED" |
        "QUIC_SESSION_PACKET_LOST" |
        "QUIC_SESSION_STREAMS_BLOCKED_FRAME_RECEIVED" |
        "QUIC_ACCEPT_CH_FRAME_RECEIVED" |
        "QUIC_CHROMIUM_CLIENT_STREAM_READ_EARLY_HINTS_RESPONSE_HEADERS" |
        "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS" |
        "QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_TRAILERS" |
        "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS" |
        "QUIC_CONNECTION_MIGRATION_FAILURE" |
        "QUIC_CONNECTION_MIGRATION_FAILURE_AFTER_PROBING" |
        "QUIC_CONNECTION_MIGRATION_ON_MIGRATE_BACK" |
        "QUIC_CONNECTION_MIGRATION_ON_NETWORK_CONNECTED" |
        "QUIC_CONNECTION_MIGRATION_ON_NETWORK_DISCONNECTED" |
        "QUIC_CONNECTION_MIGRATION_ON_NETWORK_MADE_DEFAULT" |
        "QUIC_CONNECTION_MIGRATION_ON_PATH_DEGRADING" |
        "QUIC_CONNECTION_MIGRATION_ON_WRITE_ERROR" |
        "QUIC_CONNECTION_MIGRATION_PLATFORM_NOTIFICATION" |
        "QUIC_CONNECTION_MIGRATION_SUCCESS" |
        "QUIC_CONNECTION_MIGRATION_SUCCESS_AFTER_PROBING" |
        "QUIC_CONNECTION_MIGRATION_TRIGGERED" |
        "QUIC_CONNECTIVITY_PROBING_MANAGER_CANCEL_PROBING" |
        "QUIC_CONNECTIVITY_PROBING_MANAGER_PROBE_RECEIVED" |
        "QUIC_CONNECTIVITY_PROBING_MANAGER_PROBE_SENT" |
        "QUIC_CONNECTIVITY_PROBING_MANAGER_START_PROBING" |
        "QUIC_CONNECTIVITY_PROBING_MANAGER_STATELESS_RESET_RECEIVED" |
        "QUIC_HTTP_STREAM_ADOPTED_PUSH_STREAM" |
        "QUIC_HTTP_STREAM_PUSH_PROMISE_RENDEZVOUS" |
        "QUIC_PORT_MIGRATION_FAILURE" |
        "QUIC_PORT_MIGRATION_SUCCESS" |
        "QUIC_PORT_MIGRATION_TRIGGERED" |
        "QUIC_READ_ERROR" |
        "QUIC_SESSION_ATTEMPTING_TO_PROCESS_UNDECRYPTABLE_PACKET" |
        "QUIC_SESSION_BLOCKED_FRAME_SENT" |
        "QUIC_SESSION_BUFFERED_UNDECRYPTABLE_PACKET" |
        "QUIC_SESSION_CLIENT_GOAWAY_ON_PATH_DEGRADING" |
        "QUIC_SESSION_CLOSE_ON_ERROR" |
        "QUIC_SESSION_CONNECTION_CLOSE_FRAME_RECEIVED" |
        "QUIC_SESSION_CONNECTION_CLOSE_FRAME_SENT" |
        "QUIC_SESSION_CONNECTIVITY_PROBING_FINISHED" |
        "QUIC_SESSION_DROPPED_UNDECRYPTABLE_PACKET" |
        "QUIC_SESSION_DUPLICATE_PACKET_RECEIVED" |
        "QUIC_SESSION_GOAWAY_FRAME_RECEIVED" |
        "QUIC_SESSION_GOAWAY_FRAME_SENT" |
        "QUIC_SESSION_KEY_UPDATE" |
        "QUIC_SESSION_MAX_STREAMS_FRAME_RECEIVED" |
        "QUIC_SESSION_MAX_STREAMS_FRAME_SENT" |
        "QUIC_SESSION_MESSAGE_FRAME_RECEIVED" |
        "QUIC_SESSION_MESSAGE_FRAME_SENT" |
        "QUIC_SESSION_MTU_DISCOVERY_FRAME_SENT" |
        "QUIC_SESSION_NEW_CONNECTION_ID_FRAME_RECEIVED" |
        "QUIC_SESSION_NEW_CONNECTION_ID_FRAME_SENT" |
        "QUIC_SESSION_NEW_TOKEN_FRAME_RECEIVED" |
        "QUIC_SESSION_NEW_TOKEN_FRAME_SENT" |
        "QUIC_SESSION_PATH_CHALLENGE_FRAME_RECEIVED" |
        "QUIC_SESSION_PATH_CHALLENGE_FRAME_SENT" |
        "QUIC_SESSION_PATH_RESPONSE_FRAME_RECEIVED" |
        "QUIC_SESSION_PATH_RESPONSE_FRAME_SENT" |
        "QUIC_SESSION_PING_FRAME_RECEIVED" |
        "QUIC_SESSION_PING_FRAME_SENT" |
        "QUIC_SESSION_PUBLIC_RESET_PACKET_RECEIVED" |
        "QUIC_SESSION_PUSH_PROMISE_RECEIVED" |
        "QUIC_SESSION_RETIRE_CONNECTION_ID_FRAME_RECEIVED" |
        "QUIC_SESSION_RETIRE_CONNECTION_ID_FRAME_SENT" |
        "QUIC_SESSION_STOP_WAITING_FRAME_RECEIVED" |
        "QUIC_SESSION_STOP_WAITING_FRAME_SENT" |
        "QUIC_SESSION_TRANSPORT_PARAMETERS_RESUMED" |
        "QUIC_SESSION_WEBTRANSPORT_CLIENT_ALIVE" |
        "QUIC_SESSION_WEBTRANSPORT_CLIENT_STATE_CHANGED" |
        "QUIC_SESSION_ZERO_RTT_REJECTED" |
        "QUIC_SESSION_CERTIFICATE_VERIFIED" |
        "QUIC_SESSION_CERTIFICATE_VERIFY_FAILED" |
        "QUIC_SESSION_COALESCED_PACKET_SENT" |
        "QUIC_SESSION_CRYPTO_FRAME_RECEIVED" |
        "QUIC_SESSION_CRYPTO_FRAME_SENT" |
        "QUIC_SESSION_CRYPTO_HANDSHAKE_MESSAGE_RECEIVED" |
        "QUIC_SESSION_CRYPTO_HANDSHAKE_MESSAGE_SENT" |
        "QUIC_SESSION_HANDSHAKE_DONE_FRAME_RECEIVED" |
        "QUIC_SESSION_PACKET_HEADER_REVIVED" |
        "QUIC_SESSION_PADDING_FRAME_RECEIVED" |
        "QUIC_SESSION_PADDING_FRAME_SENT" |
        "QUIC_SESSION_STREAMS_BLOCKED_FRAME_SENT" |
        "QUIC_SESSION_STREAM_FRAME_COALESCED" |
        "QUIC_SESSION_VERSION_NEGOTIATED" |
        "QUIC_SESSION_VERSION_NEGOTIATION_PACKET_RECEIVED" |
        "QUIC_SESSION_PACKET_RECEIVED" |
        "QUIC_CONNECTION_MIGRATION_MODE" |
        "QUIC_STREAM_FACTORY_JOB" |
        "QUIC_STREAM_FACTORY_JOB_BOUND_TO_HTTP_STREAM_JOB" |
        "QUIC_STREAM_FACTORY_JOB_CONNECT" |
        "QUIC_STREAM_FACTORY_JOB_RETRY_ON_ALTERNATE_NETWORK" |
        "QUIC_STREAM_FACTORY_JOB_STALE_HOST_NOT_USED_ON_CONNECTION" |
        "QUIC_STREAM_FACTORY_JOB_STALE_HOST_RESOLUTION_MATCHED" |
        "QUIC_STREAM_FACTORY_JOB_STALE_HOST_RESOLUTION_NO_MATCH" |
        "QUIC_STREAM_FACTORY_JOB_STALE_HOST_TRIED_ON_CONNECTION" |
        "QUIC_SESSION_PACKET_AUTHENTICATED" => (),

        // The netlog format is continually evolving, log any unknown types
        // in case they are interesting.
        _ => log::trace!("skipping unknown QUIC type....{}", event_hdr.ty_string),
    }

    None
}

#[cfg(test)]
mod tests {
    use super::QuicSessionAckFrameEvent;
    use super::TransportParameters;

    #[test]
    fn parses_transport_parameters_without_panics_or_fake_zero_values() {
        let p = TransportParameters::from("[Client legacy[version 00000001] [chosen_version 00000001 other_versions 00000001] initial_max_data 9007199254740993 initial_max_stream_data_bidi_local 0 initial_max_stream_data_bidi_remote malformed preferred_address [initial_max_data 9 [::1]:443] max_datagram_frame_size 65536]");
        assert_eq!(p.initial_max_data, Some(9_007_199_254_740_993));
        assert_eq!(p.initial_max_stream_data_bidi_local, Some(0));
        assert_eq!(p.initial_max_stream_data_bidi_remote, None);
        assert_eq!(p.max_datagram_frame_size, Some(65536));
        assert_eq!(p.versions, "legacy[version 00000001] [chosen_version 00000001 other_versions 00000001]");
        let p = TransportParameters::from(
            "[Server initial_max_data 42 initial_max_stream_data_uni 17]",
        );
        assert_eq!(p.initial_max_data, Some(42));
        assert_eq!(p.initial_max_stream_data_uni, Some(17));
        for invalid in [
            "",
            "éé",
            "[Client",
            "[Server]",
            "[Client initial_max_data]",
            "[Client initial_max_data bad]",
            "[Client [initial_max_data 10]",
            "[Client initial_max_data 18446744073709551616]",
        ] {
            assert_eq!(
                TransportParameters::from(invalid).initial_max_data,
                None,
                "{invalid}"
            );
        }
    }

    #[test]
    fn ack_records_preserve_numeric_strings_and_timestamp_objects(
    ) -> Result<(), serde_json::Error> {
        let decoded: QuicSessionAckFrameEvent = serde_json::from_str(
            r#"{"params":{"delta_time_largest_observed_us":"123","largest_observed":"9007199254740995","missing_packets":[2,"9007199254740993"],"received_packet_times":[{"packet_number":"9007199254740994","received":"-12"}],"smallest_observed":1}}"#,
        )?;
        assert_eq!(decoded.params.missing_packets, [2, 9_007_199_254_740_993]);
        assert_eq!(decoded.params.largest_observed, 9_007_199_254_740_995);
        let packet_time = &decoded.params.received_packet_times[0];
        assert_eq!(packet_time.packet_number, 9_007_199_254_740_994);
        assert_eq!(packet_time.received, -12);
        Ok(())
    }
}
