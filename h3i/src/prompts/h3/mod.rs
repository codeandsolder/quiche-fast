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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionChoice {
    Headers { raw: bool, literal: bool },
    Data,
    Settings,
    PushPromise,
    CancelPush,
    Goaway,
    MaxPushId,
    PriorityUpdate,
    UnknownFrame { grease: bool },
    OpenUniStream,
    ResetStream,
    StopSending,
    ConnectionClose,
    StreamBytes,
    Datagram { quarter_stream: bool },
    FlushPackets,
    Commit,
    Wait,
    Quit,
}

const ACTIONS: &[(&str, ActionChoice)] = &[
    ("headers", ActionChoice::Headers {
        raw: false,
        literal: false,
    }),
    ("headers_no_pseudo", ActionChoice::Headers {
        raw: true,
        literal: false,
    }),
    ("headers_literal", ActionChoice::Headers {
        raw: false,
        literal: true,
    }),
    ("headers_no_pseudo_literal", ActionChoice::Headers {
        raw: true,
        literal: true,
    }),
    ("data", ActionChoice::Data),
    ("settings", ActionChoice::Settings),
    ("goaway", ActionChoice::Goaway),
    ("priority_update", ActionChoice::PriorityUpdate),
    ("push_promise", ActionChoice::PushPromise),
    ("cancel_push", ActionChoice::CancelPush),
    ("max_push_id", ActionChoice::MaxPushId),
    ("grease", ActionChoice::UnknownFrame { grease: true }),
    ("extension_frame", ActionChoice::UnknownFrame {
        grease: false,
    }),
    ("open_uni_stream", ActionChoice::OpenUniStream),
    ("reset_stream", ActionChoice::ResetStream),
    ("stop_sending", ActionChoice::StopSending),
    ("connection_close", ActionChoice::ConnectionClose),
    ("stream_bytes", ActionChoice::StreamBytes),
    ("datagram_quarter_stream_id", ActionChoice::Datagram {
        quarter_stream: true,
    }),
    ("datagram_raw_payload", ActionChoice::Datagram {
        quarter_stream: false,
    }),
    ("flush_packets", ActionChoice::FlushPackets),
    ("commit", ActionChoice::Commit),
    ("wait", ActionChoice::Wait),
    ("quit", ActionChoice::Quit),
];

const YES: &str = "Yes";
const NO: &str = "No";

const ESC_TO_RET: &str = "ESC to return to actions";
const STREAM_ID_PROMPT: &str = "stream ID:";
const EMPTY_PICKS: &str = "empty picks next available ID";
const AUTO_PICK: &str = "autopick StreamID";
const PUSH_ID_PROMPT: &str = "push ID:";

enum PromptOutcome {
    Action(Action),
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

    fn handle_action(
        &self, choice: ActionChoice,
    ) -> InquireResult<PromptOutcome> {
        let action = match choice {
            ActionChoice::Headers { raw, literal } => headers::prompt_headers(
                self.bidi_sid_alloc,
                &self.host_port,
                raw,
                literal,
            )?,
            ActionChoice::Data => prompt_data()?,
            ActionChoice::Settings => settings::prompt_settings()?,
            ActionChoice::OpenUniStream =>
                stream::prompt_open_uni_stream(self.uni_sid_alloc)?,
            ActionChoice::ResetStream => stream::prompt_reset_stream()?,
            ActionChoice::StopSending => stream::prompt_stop_sending()?,
            ActionChoice::UnknownFrame { grease } =>
                prompt_unknown_frame(grease)?,
            ActionChoice::Goaway => prompt_goaway()?,
            ActionChoice::MaxPushId => prompt_max_push_id()?,
            ActionChoice::CancelPush => prompt_cancel_push()?,
            ActionChoice::PushPromise => prompt_push_promise()?,
            ActionChoice::PriorityUpdate => priority::prompt_priority()?,
            ActionChoice::ConnectionClose => prompt_connection_close()?,
            ActionChoice::StreamBytes => prompt_stream_bytes()?,
            ActionChoice::Datagram { quarter_stream } =>
                prompt_send_datagram(quarter_stream)?,
            ActionChoice::FlushPackets => Action::FlushPackets,
            ActionChoice::Commit => return Ok(PromptOutcome::Commit),
            ActionChoice::Wait => prompt_wait(self.idle_timeout)?,
            ActionChoice::Quit => return Ok(PromptOutcome::Clear),
        };
        Ok(PromptOutcome::Action(action))
    }

    const fn observe_action(&mut self, action: &Action) {
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
        self.collect_actions(prompt_action, Self::handle_action)
    }

    fn collect_actions(
        &mut self, mut next_choice: impl FnMut() -> InquireResult<ActionChoice>,
        mut handle: impl FnMut(&Self, ActionChoice) -> InquireResult<PromptOutcome>,
    ) -> InquireResult<Option<Vec<Action>>> {
        self.bidi_sid_alloc = StreamIdAllocator { id: 0 };
        self.uni_sid_alloc = StreamIdAllocator { id: 2 };
        let mut actions = Vec::new();
        loop {
            let choice = match next_choice() {
                Ok(choice) => choice,
                Err(InquireError::OperationCanceled) => return Ok(None),
                Err(error) => return Err(error),
            };
            match handle(self, choice) {
                Ok(PromptOutcome::Action(action)) => {
                    self.observe_action(&action);
                    actions.push(action);
                },
                Ok(PromptOutcome::Commit) => return Ok(Some(actions)),
                Ok(PromptOutcome::Clear) => return Ok(None),
                Err(InquireError::OperationCanceled) => (),
                Err(error) => return Err(error),
            }
        }
    }
}

fn parse_action(input: &str) -> Option<ActionChoice> {
    ACTIONS
        .iter()
        .find_map(|(label, choice)| (*label == input).then_some(*choice))
}

fn prompt_action() -> InquireResult<ActionChoice> {
    println!();
    let input =
        Text::new("Select an action to queue. `commit` sends queued actions.")
            .with_autocomplete(&|input: &str| {
                Ok(suggestions(ACTIONS.iter().map(|(label, _)| *label), input))
            })
            .with_validator(|input: &str| {
                Ok(validation(parse_action(input).is_some()))
            })
            .with_page_size(18)
            .prompt()?;
    parse_action(&input).ok_or_else(|| {
        InquireError::Custom(format!("unknown action {input:?}").into())
    })
}

fn suggestions<'a>(
    labels: impl IntoIterator<Item = &'a str>, input: &str,
) -> Vec<String> {
    let input = input.to_lowercase();
    labels
        .into_iter()
        .filter(|label| label.to_lowercase().contains(&input))
        .map(str::to_owned)
        .collect()
}

const fn validation(valid: bool) -> Validation {
    if valid {
        Validation::Valid
    } else {
        Validation::Invalid(ErrorMessage::Default)
    }
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

fn validate_varint(input: &str) -> Validation {
    validation(parse_varint(input).is_ok())
}

/// One definition supplies both the numeric parser and completion labels.
fn parse_named_varint(input: &str, names: &[(&str, u64)]) -> InquireResult<u64> {
    names
        .iter()
        .find(|(name, _)| *name == input)
        .map_or_else(|| parse_varint(input), |(_, value)| Ok(*value))
}

fn validate_named_varint(input: &str, names: &[(&str, u64)]) -> Validation {
    validation(parse_named_varint(input, names).is_ok())
}

fn suggest_named_varint(input: &str, names: &[(&str, u64)]) -> Vec<String> {
    suggestions(names.iter().map(|(label, _)| *label), input)
}

fn prompt_stream_id() -> InquireResult<u64> {
    prompt_varint(STREAM_ID_PROMPT)
}

fn prompt_control_stream_id() -> InquireResult<u64> {
    let id = Text::new(STREAM_ID_PROMPT)
        .with_validator(|input: &str| Ok(validate_varint(input)))
        .with_autocomplete(&|input: &str| Ok(suggestions(["2"], input)))
        .with_help_message(ESC_TO_RET)
        .prompt()?;

    parse_varint(&id)
}

fn prompt_varint(message: &str) -> InquireResult<u64> {
    let id = Text::new(message)
        .with_validator(|input: &str| Ok(validate_varint(input)))
        .with_placeholder("Integer <= 2^62 -1")
        .with_help_message(ESC_TO_RET)
        .prompt()?;

    parse_varint(&id)
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
    use super::parse_action;
    use super::parse_varint;
    use super::ActionChoice;
    use super::PromptOutcome;
    use super::Prompter;
    use super::ACTIONS;
    use crate::actions::h3::Action;
    use crate::actions::h3::ExpectedStreamSendResult;
    use crate::config::Config;
    use inquire::InquireError;

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
    #[test]
    fn menu_labels_and_dispatch_are_one_to_one() {
        for &(name, choice) in ACTIONS {
            assert_eq!(parse_action(name), Some(choice));
        }
        assert_eq!(parse_action("invalid"), None);
    }

    fn scripted_action(
        prompter: &Prompter, choice: ActionChoice,
    ) -> inquire::error::InquireResult<PromptOutcome> {
        match choice {
            ActionChoice::Commit => Ok(PromptOutcome::Commit),
            ActionChoice::Quit => Ok(PromptOutcome::Clear),
            ActionChoice::Data => Err(InquireError::OperationCanceled),
            ActionChoice::Wait => Err(InquireError::OperationInterrupted),
            ActionChoice::Headers { .. } =>
                Ok(PromptOutcome::Action(Action::StreamBytes {
                    stream_id: prompter.bidi_sid_alloc.next_id().ok_or_else(
                        || InquireError::Custom("exhausted".into()),
                    )?,
                    fin_stream: false,
                    bytes: vec![],
                    expected_result: ExpectedStreamSendResult::default(),
                })),
            _ => Ok(PromptOutcome::Action(Action::FlushPackets)),
        }
    }

    #[test]
    fn only_explicit_commit_sends_and_nested_cancel_does_not_consume_ids(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::new("example.org")?;
        let mut prompter = Prompter::with_config(&config);
        let headers = ActionChoice::Headers {
            raw: false,
            literal: false,
        };
        let choices =
            [headers, ActionChoice::Data, headers, ActionChoice::Commit];
        let mut choices = choices.into_iter();
        let committed = prompter.collect_actions(
            || choices.next().ok_or(InquireError::OperationInterrupted),
            scripted_action,
        )?;
        assert!(matches!(
            committed.as_deref(),
            Some([
                Action::StreamBytes { stream_id: 0, .. },
                Action::StreamBytes { stream_id: 4, .. }
            ])
        ));
        for terminal in
            [Ok(ActionChoice::Quit), Err(InquireError::OperationCanceled)]
        {
            let mut choices = [Ok(headers), terminal].into_iter();
            assert_eq!(
                prompter.collect_actions(
                    || choices
                        .next()
                        .ok_or(InquireError::OperationInterrupted)?,
                    scripted_action
                )?,
                None
            );
        }
        let mut choices = [headers, ActionChoice::Wait].into_iter();
        assert!(matches!(
            prompter.collect_actions(
                || choices.next().ok_or(InquireError::OperationInterrupted),
                scripted_action
            ),
            Err(InquireError::OperationInterrupted)
        ));
        let mut choices = std::iter::once(ActionChoice::Commit);
        assert_eq!(
            prompter.collect_actions(
                || choices.next().ok_or(InquireError::OperationInterrupted),
                scripted_action
            )?,
            Some(Vec::new())
        );
        Ok(())
    }
}
