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

//! A collection of interactive CLI prompts for HTTP/3 based on [inquire].

use inquire::error::CustomUserError;
use inquire::error::InquireResult;
use inquire::validator::ErrorMessage;
use inquire::validator::Validation;
use inquire::InquireError;
use inquire::Select;
use inquire::Text;
use qlog::events::quic::ErrorSpace;
use quiche::ConnectionError;

use crate::actions::h3::Action;
use crate::actions::h3::ExpectedStreamSendResult;
use crate::config::Config;
use crate::prompts::h3::headers::prompt_push_promise;
use crate::StreamIdAllocator;

use crate::quiche;

use self::stream::prompt_fin_stream;
use self::wait::prompt_wait;

/// A specialized [`Result`] type for internal prompt suggestion.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
type SuggestionResult<T> = std::result::Result<T, CustomUserError>;

const HEADERS: &str = "headers";
const HEADERS_NO_PSEUDO: &str = "headers_no_pseudo";
const HEADERS_LITERAL: &str = "headers_literal";
const HEADERS_NO_PSEUDO_LITERAL: &str = "headers_no_pseudo_literal";
const DATA: &str = "data";
const SETTINGS: &str = "settings";
const PUSH_PROMISE: &str = "push_promise";
const CANCEL_PUSH: &str = "cancel_push";
const GOAWAY: &str = "goaway";
const MAX_PUSH_ID: &str = "max_push_id";
const PRIORITY_UPDATE: &str = "priority_update";
const GREASE: &str = "grease";
const EXTENSION: &str = "extension_frame";
const OPEN_UNI_STREAM: &str = "open_uni_stream";
const RESET_STREAM: &str = "reset_stream";
const STOP_SENDING: &str = "stop_sending";
const CONNECTION_CLOSE: &str = "connection_close";
const STREAM_BYTES: &str = "stream_bytes";
const DATAGRAM_QUARTER_STREAM_ID: &str = "datagram_quarter_stream_id";
const DATAGRAM_RAW_PAYLOAD: &str = "datagram_raw_payload";

const COMMIT: &str = "commit";
const FLUSH_PACKETS: &str = "flush_packets";
const WAIT: &str = "wait";
const QUIT: &str = "quit";

const YES: &str = "Yes";
const NO: &str = "No";

const ESC_TO_RET: &str = "ESC to return to actions";
const STREAM_ID_PROMPT: &str = "stream ID:";
const EMPTY_PICKS: &str = "empty picks next available ID";
const AUTO_PICK: &str = "autopick StreamID";
const PUSH_ID_PROMPT: &str = "push ID:";

enum PromptOutcome {
    Action(Action),
    Repeat,
    Commit,
    Clear,
}

/// The main prompter interface and state management.
pub struct Prompter {
    host_port: String,
    idle_timeout: u64,
    bidi_sid_alloc: StreamIdAllocator,
    uni_sid_alloc: StreamIdAllocator,
}

impl Prompter {
    /// Construct a prompter with the provided `config`.
    #[must_use = "the prompter owns the configuration and queued stream IDs"]
    pub fn with_config(config: &Config) -> Self {
        Self {
            host_port: config.endpoint.authority().to_owned(),
            idle_timeout: config.idle_timeout,
            bidi_sid_alloc: StreamIdAllocator { id: 0 },
            uni_sid_alloc: StreamIdAllocator { id: 2 },
        }
    }

    fn handle_action(&mut self, action: &str) -> InquireResult<PromptOutcome> {
        let res = match action {
            HEADERS |
            HEADERS_NO_PSEUDO |
            HEADERS_LITERAL |
            HEADERS_NO_PSEUDO_LITERAL => {
                let literal = action == HEADERS_LITERAL ||
                    action == HEADERS_NO_PSEUDO_LITERAL;
                let raw = action == HEADERS_NO_PSEUDO ||
                    action == HEADERS_NO_PSEUDO_LITERAL;
                headers::prompt_headers(
                    &self.bidi_sid_alloc,
                    &self.host_port,
                    raw,
                    literal,
                )
            },

            DATA => prompt_data(),
            SETTINGS => settings::prompt_settings(),
            OPEN_UNI_STREAM =>
                stream::prompt_open_uni_stream(&self.uni_sid_alloc),
            RESET_STREAM => stream::prompt_reset_stream(),
            STOP_SENDING => stream::prompt_stop_sending(),
            GREASE | EXTENSION => prompt_unknown_frame(action == GREASE),
            GOAWAY => prompt_goaway(),
            MAX_PUSH_ID => prompt_max_push_id(),
            CANCEL_PUSH => prompt_cancel_push(),
            PUSH_PROMISE => prompt_push_promise(),
            PRIORITY_UPDATE => priority::prompt_priority(),
            CONNECTION_CLOSE => prompt_connection_close(),
            STREAM_BYTES => prompt_stream_bytes(),
            DATAGRAM_QUARTER_STREAM_ID | DATAGRAM_RAW_PAYLOAD =>
                prompt_send_datagram(action == DATAGRAM_QUARTER_STREAM_ID),
            FLUSH_PACKETS =>
                return Ok(PromptOutcome::Action(Action::FlushPackets)),
            COMMIT => return Ok(PromptOutcome::Commit),
            WAIT => prompt_wait(self.idle_timeout),
            QUIT => return Ok(PromptOutcome::Clear),

            _ => {
                println!("error: unknown action {action}");
                return Ok(PromptOutcome::Repeat);
            },
        };

        match res {
            Ok(action) => Ok(PromptOutcome::Action(action)),
            Err(InquireError::OperationCanceled) => Ok(PromptOutcome::Repeat),
            Err(error) => Err(error),
        }
    }

    fn observe_action(&mut self, action: &Action) {
        match action {
            Action::SendFrame { stream_id, .. } |
            Action::SendHeadersFrame { stream_id, .. } |
            Action::StreamBytes { stream_id, .. } |
            Action::OpenUniStream { stream_id, .. } => {
                self.bidi_sid_alloc.observe(*stream_id);
                self.uni_sid_alloc.observe(*stream_id);
            },
            _ => (),
        }
    }

    /// Collect actions until explicit commit or quit. Escape at the action
    /// menu discards the queue; Escape inside an action cancels only that
    /// action. Interruptions and terminal failures never commit a partial
    /// queue.
    ///
    /// Returns `None` for quit or cancellation, or the explicitly committed
    /// queue (which may be empty).
    ///
    /// # Errors
    /// Returns terminal errors and interruptions.
    pub fn prompt(&mut self) -> InquireResult<Option<Vec<Action>>> {
        self.bidi_sid_alloc = StreamIdAllocator { id: 0 };
        self.uni_sid_alloc = StreamIdAllocator { id: 2 };
        let mut actions = Vec::new();
        loop {
            println!();
            let action = match prompt_action() {
                Ok(action) => action,
                Err(InquireError::OperationCanceled) => return Ok(None),
                Err(error) => return Err(error),
            };
            match self.handle_action(&action)? {
                PromptOutcome::Action(action) => {
                    self.observe_action(&action);
                    actions.push(action);
                },
                PromptOutcome::Repeat => (),
                PromptOutcome::Commit => return Ok(Some(actions)),
                PromptOutcome::Clear => return Ok(None),
            }
        }
    }
}

fn prompt_action() -> InquireResult<String> {
    Text::new("Select an action to queue. `commit` sends queued actions.")
        .with_autocomplete(&action_suggester)
        .with_page_size(18)
        .prompt()
}

fn action_suggester(val: &str) -> SuggestionResult<Vec<String>> {
    // TODO: make this an enum to automatically pick up new actions
    let suggestions = [
        HEADERS,
        HEADERS_NO_PSEUDO,
        HEADERS_LITERAL,
        HEADERS_NO_PSEUDO_LITERAL,
        DATA,
        SETTINGS,
        GOAWAY,
        PRIORITY_UPDATE,
        PUSH_PROMISE,
        CANCEL_PUSH,
        MAX_PUSH_ID,
        GREASE,
        EXTENSION,
        OPEN_UNI_STREAM,
        RESET_STREAM,
        STOP_SENDING,
        CONNECTION_CLOSE,
        STREAM_BYTES,
        DATAGRAM_QUARTER_STREAM_ID,
        DATAGRAM_RAW_PAYLOAD,
        FLUSH_PACKETS,
        COMMIT,
        WAIT,
        QUIT,
    ];

    squish_suggester(&suggestions, val)
}

fn squish_suggester(
    suggestions: &[&str], val: &str,
) -> SuggestionResult<Vec<String>> {
    let val_lower = val.to_lowercase();

    Ok(suggestions
        .iter()
        .filter(|s| s.to_lowercase().contains(&val_lower))
        .map(|s| String::from(*s))
        .collect())
}

fn parse_varint(input: &str) -> InquireResult<u64> {
    input
        .parse::<u64>()
        .ok()
        .filter(|&value| value <= octets::MAX_VAR_INT)
        .ok_or_else(|| {
            InquireError::Custom(format!("invalid QUIC varint: {input:?}").into())
        })
}

fn validate_varint(input: &str) -> SuggestionResult<Validation> {
    Ok(if parse_varint(input).is_ok() {
        Validation::Valid
    } else {
        Validation::Invalid(ErrorMessage::Default)
    })
}

/// One definition supplies both the numeric parser and completion labels.
fn parse_named_varint(input: &str, names: &[(&str, u64)]) -> InquireResult<u64> {
    names
        .iter()
        .find(|(name, _)| *name == input)
        .map_or_else(|| parse_varint(input), |(_, value)| Ok(*value))
}

fn validate_named_varint(
    input: &str, names: &[(&str, u64)],
) -> SuggestionResult<Validation> {
    Ok(if parse_named_varint(input, names).is_ok() {
        Validation::Valid
    } else {
        Validation::Invalid(ErrorMessage::Default)
    })
}

fn suggest_named_varint(
    input: &str, names: &[(&str, u64)],
) -> SuggestionResult<Vec<String>> {
    let input = input.to_lowercase();
    Ok(names
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| name.to_lowercase().contains(&input))
        .map(str::to_owned)
        .collect())
}

fn prompt_stream_id() -> InquireResult<u64> {
    prompt_varint(STREAM_ID_PROMPT)
}

fn prompt_control_stream_id() -> InquireResult<u64> {
    let id = Text::new(STREAM_ID_PROMPT)
        .with_validator(validate_varint)
        .with_autocomplete(&control_stream_suggestor)
        .with_help_message(ESC_TO_RET)
        .prompt()?;

    parse_varint(&id)
}

fn prompt_varint(message: &str) -> InquireResult<u64> {
    let id = Text::new(message)
        .with_validator(validate_varint)
        .with_placeholder("Integer <= 2^62 -1")
        .with_help_message(ESC_TO_RET)
        .prompt()?;

    parse_varint(&id)
}

fn control_stream_suggestor(val: &str) -> SuggestionResult<Vec<String>> {
    let suggestions = ["2"];

    squish_suggester(&suggestions, val)
}

fn send_frame(
    stream_id: u64, frame: quiche::h3::frame::Frame,
) -> InquireResult<Action> {
    Ok(Action::SendFrame {
        stream_id,
        frame,
        fin_stream: prompt_fin_stream()?,
        expected_result: ExpectedStreamSendResult::default(),
    })
}

fn prompt_data() -> InquireResult<Action> {
    let stream_id = prompt_stream_id()?;
    let payload = Text::new("payload:").prompt()?.into_bytes();
    send_frame(stream_id, quiche::h3::frame::Frame::Data { payload })
}

fn prompt_max_push_id() -> InquireResult<Action> {
    let stream_id = prompt_stream_id()?;
    let push_id = prompt_varint(PUSH_ID_PROMPT)?;
    send_frame(stream_id, quiche::h3::frame::Frame::MaxPushId { push_id })
}

fn prompt_cancel_push() -> InquireResult<Action> {
    let stream_id = prompt_stream_id()?;
    let push_id = prompt_varint(PUSH_ID_PROMPT)?;
    send_frame(stream_id, quiche::h3::frame::Frame::CancelPush { push_id })
}

fn prompt_goaway() -> InquireResult<Action> {
    let stream_id = prompt_stream_id()?;
    let id = prompt_varint("ID:")?;
    send_frame(stream_id, quiche::h3::frame::Frame::GoAway { id })
}

fn prompt_unknown_frame(grease: bool) -> InquireResult<Action> {
    let stream_id = prompt_control_stream_id()?;
    let raw_type = if grease {
        quiche::h3::grease_value()
    } else {
        prompt_varint("frame type:")?
    };
    let payload = Text::new("payload:")
        .with_help_message(ESC_TO_RET)
        .prompt()?
        .into_bytes();
    send_frame(stream_id, quiche::h3::frame::Frame::Unknown {
        raw_type,
        payload,
    })
}

fn prompt_connection_close() -> InquireResult<Action> {
    let (error_space, error_code) = errors::prompt_transport_or_app_error()?;
    let reason = Text::new("reason phrase:")
        .with_placeholder("optional reason phrase")
        .prompt()?;

    Ok(Action::ConnectionClose {
        error: ConnectionError {
            is_app: matches!(error_space, ErrorSpace::Application),
            error_code,
            reason: reason.into_bytes(),
        },
    })
}

fn prompt_stream_bytes() -> InquireResult<Action> {
    let stream_id = prompt_stream_id()?;
    let bytes = Text::new("bytes:").prompt()?;
    let fin_stream = prompt_fin_stream()?;

    Ok(Action::StreamBytes {
        stream_id,
        fin_stream,
        bytes: bytes.into_bytes(),
        expected_result: ExpectedStreamSendResult::default(),
    })
}

fn prompt_send_datagram(with_quarter_stream: bool) -> InquireResult<Action> {
    if with_quarter_stream {
        let stream_id = prompt_varint("stream ID to be quartered:")?;
        // https://www.rfc-editor.org/rfc/rfc9297#name-http-3-datagrams
        let quarter_stream_id = stream_id / 4;

        let payload = Text::new("payload bytes:").prompt()?;

        Ok(Action::SendDatagram {
            payload: encode_datagram(quarter_stream_id, payload.as_bytes())?,
        })
    } else {
        let payload_str = Text::new("payload bytes:").prompt()?;
        Ok(Action::SendDatagram {
            payload: payload_str.into_bytes(),
        })
    }
}

fn encode_datagram(
    quarter_stream_id: u64, payload: &[u8],
) -> InquireResult<Vec<u8>> {
    if quarter_stream_id > octets::MAX_VAR_INT {
        return Err(InquireError::Custom("invalid quarter stream ID".into()));
    }
    let mut bytes = [0; 8];
    let len = octets::OctetsMut::with_slice(&mut bytes)
        .put_varint(quarter_stream_id)
        .map_err(|error| InquireError::Custom(error.to_string().into()))?
        .len();
    let mut result = bytes[..len].to_vec();
    result.extend_from_slice(payload);
    Ok(result)
}

fn prompt_yes_no(msg: &str) -> InquireResult<bool> {
    let res = Select::new(msg, vec![NO, YES]).prompt()?;

    Ok(res == YES)
}

mod errors;
mod headers;
mod priority;
mod settings;
mod stream;
mod wait;

#[cfg(test)]
mod tests {
    use super::encode_datagram;
    use super::parse_varint;
    use super::Prompter;
    use crate::actions::h3::Action;
    use crate::actions::h3::ExpectedStreamSendResult;
    use crate::config::Config;

    #[test]
    fn varint_bounds_and_datagram_wire_encoding(
    ) -> Result<(), inquire::InquireError> {
        for value in [
            0,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            octets::MAX_VAR_INT,
        ] {
            assert_eq!(parse_varint(&value.to_string())?, value);
            let bytes = encode_datagram(value, b"test")?;
            let mut wire = octets::Octets::with_slice(&bytes);
            assert_eq!(wire.get_varint().ok(), Some(value));
            assert_eq!(
                wire.get_bytes(4).ok().map(|v| v.to_vec()),
                Some(b"test".to_vec())
            );
            assert_eq!(wire.cap(), 0);
        }
        for input in [
            "",
            "-1",
            "4611686018427387904",
            "18446744073709551616",
            "not a number",
        ] {
            assert!(parse_varint(input).is_err());
        }
        assert!(encode_datagram(octets::MAX_VAR_INT + 1, b"test").is_err());
        Ok(())
    }

    #[test]
    fn stream_ids_follow_completed_sends_and_keep_directions_separate(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::new("example.org")?;
        let mut prompter = Prompter::with_config(&config);
        assert_eq!(prompter.bidi_sid_alloc.next_id(), Some(0));
        assert_eq!(prompter.uni_sid_alloc.next_id(), Some(2));
        for (id, bidi, uni) in [(8, 12, 2), (4, 12, 2), (5, 12, 2), (14, 12, 18)]
        {
            prompter.observe_action(&Action::StreamBytes {
                stream_id: id,
                fin_stream: false,
                bytes: vec![],
                expected_result: ExpectedStreamSendResult::default(),
            });
            assert_eq!(prompter.bidi_sid_alloc.next_id(), Some(bidi));
            assert_eq!(prompter.uni_sid_alloc.next_id(), Some(uni));
        }
        prompter.uni_sid_alloc.observe(octets::MAX_VAR_INT - 1);
        assert_eq!(prompter.uni_sid_alloc.next_id(), None);
        Ok(())
    }
}
