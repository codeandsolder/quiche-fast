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

use super::parse_named_varint;
use super::stream::prompt_fin_stream;
use super::suggest_named_varint;
use super::validate_named_varint;
use crate::actions::h3::Action;
use crate::actions::h3::ExpectedStreamSendResult;
use crate::prompts::h3;

use crate::quiche;

const SETTINGS: &[(&str, u64)] = &[
    ("QPACK_MAX_TABLE_CAPACITY", 0x1),
    ("MAX_FIELD_SECTION_SIZE", 0x6),
    ("QPACK_BLOCKED_STREAMS", 0x7),
    ("ENABLE_CONNECT_PROTOCOL", 0x8),
    ("H3_DATAGRAM", 0x33),
];

type RawSettings = Vec<(u64, u64)>;

pub fn prompt_settings() -> InquireResult<Action> {
    let stream_id = h3::prompt_control_stream_id()?;
    let settings = settings_read_loop()?;

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: None,
            additional_settings: Some(settings),
        },
        expected_result: ExpectedStreamSendResult::default(),
    };

    Ok(action)
}

fn settings_read_loop() -> InquireResult<RawSettings> {
    let mut settings = Vec::new();
    loop {
        let ty = Text::new("setting type:")
            .with_validator(|input: &str| Ok(validate_setting_type(input)))
            .with_autocomplete(&|input: &str| {
                Ok(suggest_named_varint(input, SETTINGS))
            })
            .with_help_message("type 'q!' to stop adding settings")
            .prompt()?;
        if ty == "q!" {
            return Ok(settings);
        }
        let id = parse_named_varint(&ty, SETTINGS)?;
        let value = h3::prompt_varint("setting value:")?;
        settings.push((id, value));
    }
}

fn validate_setting_type(id: &str) -> Validation {
    if id == "q!" {
        return Validation::Valid;
    }
    validate_named_varint(id, SETTINGS)
}
