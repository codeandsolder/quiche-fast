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

//! Actions for HTTP/3 and QUIC.
//!
//! The client executes a sequence of actions to send frames and manage streams.

use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;

use crate::quiche;
use quiche::h3::frame::Frame;
use quiche::h3::Header;
use quiche::ConnectionError;
use serde::Deserialize;
use serde::Serialize;
use serde_with::serde_as;

/// Expected result from a `stream_send` operation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedStreamSendResult {
    /// Expect success with any number of bytes written.
    #[default]
    Ok,
    /// Expect success with exactly the specified number of bytes written.
    OkExact(usize),
    /// Expect the operation to fail with the specified error.
    Error(quiche::Error),
}

/// An action which the HTTP/3 client should take.
///
/// The client iterates over a vector of said actions, executing each one
/// sequentially. Note that packets will be flushed when said iteration has
/// completed, regardless of if an [`Action::FlushPackets`] was the terminal
/// action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send a [`quiche::h3::frame::Frame`] over a stream.
    SendFrame {
        stream_id: u64,
        fin_stream: bool,
        frame: Frame,
        expected_result: ExpectedStreamSendResult,
    },

    /// Send a HEADERS frame over a stream.
    SendHeadersFrame {
        stream_id: u64,
        fin_stream: bool,
        literal_headers: bool,
        headers: Vec<Header>,
        expected_result: ExpectedStreamSendResult,
    },

    /// Send arbitrary bytes over a stream.
    StreamBytes {
        stream_id: u64,
        fin_stream: bool,
        bytes: Vec<u8>,
        expected_result: ExpectedStreamSendResult,
    },

    /// Send a DATAGRAM frame.
    SendDatagram {
        payload: Vec<u8>,
    },

    /// Open a new unidirectional stream.
    OpenUniStream {
        stream_id: u64,
        fin_stream: bool,
        stream_type: u64,
        expected_result: ExpectedStreamSendResult,
    },

    /// Send a RESET_STREAM frame with the given error code.
    ResetStream {
        stream_id: u64,
        error_code: u64,
    },

    /// Send a STOP_SENDING frame with the given error code.
    StopSending {
        stream_id: u64,
        error_code: u64,
    },

    /// Send a CONNECTION_CLOSE frame with the given [`ConnectionError`].
    ConnectionClose {
        error: ConnectionError,
    },

    FlushPackets,

    /// Wait for an event. See [`WaitType`] for the events.
    Wait {
        wait_type: WaitType,
    },
}

/// Configure the wait behavior for a connection.
#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WaitType {
    /// Wait for a time before firing the next action
    #[serde(rename = "duration")]
    WaitDuration(
        #[serde_as(as = "serde_with::DurationMilliSecondsWithFrac<f64>")]
        Duration,
    ),
    /// Wait for some form of a response before firing the next action. This can
    /// be superseded in several cases:
    /// 1. The peer resets the specified stream.
    /// 2. The peer sends a `fin` over the specified stream
    StreamEvent(StreamEvent),

    /// Wait until the peer has updated MAX_STREAMS to allow creation
    /// of the required additional streams.
    ///
    /// Typically requires processing of a MAX_STREAMS frame sent by
    /// the peer.  The peer may decide to send MAX_STREAMS updates as
    /// the number of active streams changes due to stream termination
    /// or stream creation. Typical goals being:
    /// - Limit the number of active streams to the configured limit.
    /// - Ensure that available quota is non-zero when number of active streams
    ///   is below the configured limit.
    /// - Minimize the number of MAX_STREAM updates sent.
    CanOpenNumStreams(RequiredStreamsQuota),
}

impl From<WaitType> for Action {
    fn from(value: WaitType) -> Self {
        Self::Wait { wait_type: value }
    }
}

/// A response event, received over a stream, which will terminate the wait
/// period.
///
/// See [`StreamEventType`] for the types of events.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename = "snake_case")]
pub struct StreamEvent {
    pub stream_id: u64,
    #[serde(rename = "type")]
    pub event_type: StreamEventType,
}

/// A check for stream creation quota which will terminate the wait period.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename = "snake_case")]
pub struct RequiredStreamsQuota {
    /// Required stream quota
    pub num: u64,

    /// True for bidirectional streams, false for unidirectional streams
    pub bidi: bool,
}

/// Response that can terminate a wait period.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamEventType {
    /// A HEADERS frame was received.
    Headers,
    /// A DATA frame was received.
    Data,
    /// The stream was somehow finished, either by a RESET_STREAM frame or via
    /// the `fin` bit being set.
    Finished,
}

#[derive(Debug, Default)]
pub(crate) struct WaitingFor {
    stream_events: HashMap<u64, HashSet<StreamEventType>>,
    required_bidi: Option<u64>,
    required_uni: Option<u64>,
}

impl WaitingFor {
    pub(crate) fn is_empty(&self) -> bool {
        self.stream_events.is_empty() &&
            self.required_bidi.is_none() &&
            self.required_uni.is_none()
    }

    pub(crate) fn add_wait(&mut self, stream_event: &StreamEvent) {
        self.stream_events
            .entry(stream_event.stream_id)
            .or_default()
            .insert(stream_event.event_type);
    }

    pub(crate) fn set_required_stream_quota(
        &mut self, required: RequiredStreamsQuota,
    ) {
        let quota = if required.bidi {
            &mut self.required_bidi
        } else {
            &mut self.required_uni
        };
        *quota = Some(quota.unwrap_or_default().max(required.num));
    }

    /// Check and clear the stream quota conditions independently.
    pub(crate) fn check_can_open_num_streams<F: quiche::BufFactory>(
        &mut self, conn: &quiche::Connection<F>,
    ) {
        self.check_quotas(
            conn.peer_streams_left_bidi(),
            conn.peer_streams_left_uni(),
        );
    }

    fn check_quotas(&mut self, bidi: u64, uni: u64) {
        for (quota, available) in [
            (&mut self.required_bidi, bidi),
            (&mut self.required_uni, uni),
        ] {
            if quota.is_some_and(|required| available >= required) {
                *quota = None;
            }
        }
    }

    pub(crate) fn remove_wait(&mut self, stream_event: StreamEvent) {
        if stream_event.event_type == StreamEventType::Finished {
            self.stream_events.remove(&stream_event.stream_id);
            return;
        }
        if let Some(waits) = self.stream_events.get_mut(&stream_event.stream_id) {
            waits.remove(&stream_event.event_type);
            if waits.is_empty() {
                self.stream_events.remove(&stream_event.stream_id);
            }
        }
    }
}

/// Constructs a header action with ordinary QPACK encoding.
#[must_use = "the returned action must be executed by the client"]
pub const fn send_headers_frame(
    stream_id: u64, fin_stream: bool, headers: Vec<Header>,
) -> Action {
    send_headers_frame_with_expected_result(
        stream_id,
        fin_stream,
        headers,
        ExpectedStreamSendResult::Ok,
    )
}

/// Constructs a header action with an explicit expected send result.
#[must_use = "the returned action must be executed by the client"]
pub const fn send_headers_frame_with_expected_result(
    stream_id: u64, fin_stream: bool, headers: Vec<Header>,
    expected_result: ExpectedStreamSendResult,
) -> Action {
    Action::SendHeadersFrame {
        stream_id,
        fin_stream,
        headers,
        literal_headers: false,
        expected_result,
    }
}

/// Constructs a header action with literal encoding that preserves names.
#[must_use = "the returned action must be executed by the client"]
pub const fn send_headers_frame_literal(
    stream_id: u64, fin_stream: bool, headers: Vec<Header>,
) -> Action {
    send_headers_frame_literal_with_expected_result(
        stream_id,
        fin_stream,
        headers,
        ExpectedStreamSendResult::Ok,
    )
}

/// Constructs a literal header action with an explicit expected send result.
#[must_use = "the returned action must be executed by the client"]
pub const fn send_headers_frame_literal_with_expected_result(
    stream_id: u64, fin_stream: bool, headers: Vec<Header>,
    expected_result: ExpectedStreamSendResult,
) -> Action {
    Action::SendHeadersFrame {
        stream_id,
        fin_stream,
        headers,
        literal_headers: true,
        expected_result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_clear_per_stream_and_direction() {
        let mut waits = WaitingFor::default();
        for event_type in [
            StreamEventType::Headers,
            StreamEventType::Data,
            StreamEventType::Finished,
        ] {
            waits.add_wait(&StreamEvent {
                stream_id: 0,
                event_type,
            });
            waits.add_wait(&StreamEvent {
                stream_id: 4,
                event_type,
            });
        }
        waits.remove_wait(StreamEvent {
            stream_id: 0,
            event_type: StreamEventType::Finished,
        });
        assert_eq!(waits.stream_events.len(), 1);
        for (num, bidi) in [(4, true), (2, false), (1, true)] {
            waits.set_required_stream_quota(RequiredStreamsQuota { num, bidi });
        }
        waits.remove_wait(StreamEvent {
            stream_id: 4,
            event_type: StreamEventType::Finished,
        });
        waits.check_quotas(3, 2);
        assert!(!waits.is_empty());
        waits.check_quotas(4, 2);
        assert!(waits.is_empty());
    }

    #[test]
    fn repeated_waits_are_idempotent() {
        let mut waits = WaitingFor::default();
        let event = StreamEvent {
            stream_id: 0,
            event_type: StreamEventType::Headers,
        };
        waits.add_wait(&event);
        waits.add_wait(&event);
        waits.remove_wait(event);
        assert!(waits.is_empty());
    }
}
