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

use inquire::error::InquireResult;
use inquire::validator::Validation;
use inquire::Text;

use crate::actions::h3::Action;
use crate::actions::h3::ExpectedStreamSendResult;
use crate::prompts::h3;
use crate::prompts::h3::errors::prompt_transport_or_app_error;
use crate::prompts::h3::prompt_yes_no;
use crate::StreamIdAllocator;

use super::parse_named_varint;
use super::parse_varint;
use super::suggest_named_varint;
use super::validate_named_varint;
use super::AUTO_PICK;
use super::EMPTY_PICKS;
use super::ESC_TO_RET;
use super::STREAM_ID_PROMPT;

const STREAM_TYPES: &[(&str, u64)] = &[
    ("Control Stream", crate::HTTP3_CONTROL_STREAM_TYPE_ID),
    ("Push Stream", crate::HTTP3_PUSH_STREAM_TYPE_ID),
    ("QPACK Encoder Stream", crate::QPACK_ENCODER_STREAM_TYPE_ID),
    ("QPACK Decoder Stream", crate::QPACK_DECODER_STREAM_TYPE_ID),
];

fn validate_stream_id(id: &str) -> Validation {
    if id.is_empty() {
        return Validation::Valid;
    }

    h3::validate_varint(id)
}

pub(super) fn autopick_stream_id(
    sid_alloc: &StreamIdAllocator,
) -> InquireResult<u64> {
    let stream_id = Text::new(STREAM_ID_PROMPT)
        .with_placeholder(EMPTY_PICKS)
        .with_help_message(ESC_TO_RET)
        .with_validator(|input: &str| Ok(validate_stream_id(input)))
        .prompt()?;

    Ok(match stream_id.as_str() {
        "" => {
            let id = sid_alloc.next_id().ok_or_else(|| {
                inquire::InquireError::Custom("stream ID space exhausted".into())
            })?;
            println!("{AUTO_PICK}={id}");
            id
        },

        _ => parse_varint(&stream_id)?,
    })
}

pub(super) fn prompt_open_uni_stream(
    sid_alloc: &StreamIdAllocator,
) -> InquireResult<Action> {
    let stream_id = autopick_stream_id(sid_alloc)?;
    let stream_type = Text::new("stream type:")
        .with_validator(|input: &str| {
            Ok(validate_named_varint(input, STREAM_TYPES))
        })
        .with_autocomplete(&|input: &str| {
            Ok(suggest_named_varint(input, STREAM_TYPES))
        })
        .prompt()?;

    let ty = parse_named_varint(&stream_type, STREAM_TYPES)?;

    let fin_stream = prompt_fin_stream()?;

    Ok(Action::OpenUniStream {
        stream_id,
        fin_stream,
        stream_type: ty,
        expected_result: ExpectedStreamSendResult::default(),
    })
}

pub(super) fn prompt_fin_stream() -> InquireResult<bool> {
    prompt_yes_no("fin stream:")
}

pub(super) fn prompt_reset_stream() -> InquireResult<Action> {
    let (stream_id, error_code) = prompt_close_stream()?;

    Ok(Action::ResetStream {
        stream_id,
        error_code,
    })
}

pub(super) fn prompt_stop_sending() -> InquireResult<Action> {
    let (stream_id, error_code) = prompt_close_stream()?;

    Ok(Action::StopSending {
        stream_id,
        error_code,
    })
}

fn prompt_close_stream() -> InquireResult<(u64, u64)> {
    let id = h3::prompt_stream_id()?;

    let (_, error_code) = prompt_transport_or_app_error()?;

    Ok((id, error_code))
}
