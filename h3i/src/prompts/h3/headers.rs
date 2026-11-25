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

//! Prompts for HTTP/3 header fields.

use crate::quiche;
use inquire::error::InquireResult;
use inquire::Text;
use quiche::h3::frame::Frame;

use crate::encode_header_block;
use crate::prompts::h3;
use crate::StreamIdAllocator;

use super::stream::autopick_stream_id;
use super::stream::prompt_fin_stream;
use super::suggestions;
use super::ESC_TO_RET;
use super::PUSH_ID_PROMPT;
use crate::actions::h3::Action;
use crate::actions::h3::ExpectedStreamSendResult;

pub(super) fn prompt_headers(
    sid_alloc: &StreamIdAllocator, host_port: &str, raw: bool, literal: bool,
) -> InquireResult<Action> {
    let stream_id = autopick_stream_id(sid_alloc)?;
    let mut headers = if raw {
        Vec::new()
    } else {
        pseudo_headers(host_port)?
    };
    headers.extend(headers_read_loop()?);
    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendHeadersFrame {
        stream_id,
        fin_stream,
        headers,
        literal_headers: literal,
        expected_result: ExpectedStreamSendResult::default(),
    };

    Ok(action)
}

pub(super) fn prompt_push_promise() -> InquireResult<Action> {
    let stream_id = h3::prompt_stream_id()?;
    let push_id = h3::prompt_varint(PUSH_ID_PROMPT)?;

    let headers = headers_read_loop()?;
    let header_block = if headers.is_empty() {
        vec![]
    } else {
        encode_header_block(&headers)
            .map_err(|err| inquire::InquireError::Custom(err.into()))?
    };

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: Frame::PushPromise {
            push_id,
            header_block,
        },
        expected_result: ExpectedStreamSendResult::default(),
    };

    Ok(action)
}

fn pseudo_headers(host_port: &str) -> InquireResult<Vec<quiche::h3::Header>> {
    let method = Text::new("method:")
        .with_autocomplete(&|input: &str| {
            Ok(suggestions(["GET", "POST", "PUT", "DELETE"], input))
        })
        .with_default("GET")
        .with_help_message(ESC_TO_RET)
        .prompt()?;

    let help = format!("Press enter/return for default ({host_port})");
    let authority = Text::new("authority:")
        .with_default(host_port)
        .with_help_message(&help)
        .prompt()?;

    let path = Text::new("path:").with_default("/").prompt()?;

    let scheme = Text::new("scheme:")
        .with_default("https")
        .with_help_message(ESC_TO_RET)
        .prompt()?;

    Ok(vec![
        quiche::h3::Header::new(b":method", method.as_bytes()),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b":scheme", scheme.as_bytes()),
    ])
}

fn headers_read_loop() -> InquireResult<Vec<quiche::h3::Header>> {
    let mut headers = vec![];
    loop {
        let name = Text::new("field name:")
            .with_help_message(
                "type 'q!' to complete headers, or ESC to return to actions",
            )
            .prompt()?;

        if name == "q!" {
            break;
        }

        let value = Text::new("field value:")
            .with_help_message(ESC_TO_RET)
            .prompt()?;

        headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
    }

    Ok(headers)
}
