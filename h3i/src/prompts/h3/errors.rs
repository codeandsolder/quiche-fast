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

//! QUIC and HTTP/3 errors for the h3i client.
use inquire::error::InquireResult;
use inquire::Select;
use inquire::Text;
use qlog::events::quic::ErrorSpace;

use super::parse_named_varint;
use super::suggest_named_varint;
use super::validate_named_varint;

const TRANSPORT_CODES: &[(&str, u64)] = &[
    ("NO_ERROR", 0x0),
    ("INTERNAL_ERROR", 0x1),
    ("CONNECTION_REFUSED", 0x2),
    ("FLOW_CONTROL_ERROR", 0x3),
    ("STREAM_LIMIT_ERROR", 0x4),
    ("STREAM_STATE_ERROR", 0x5),
    ("FINAL_SIZE_ERROR", 0x6),
    ("FRAME_ENCODING_ERROR", 0x7),
    ("TRANSPORT_PARAMETER_ERROR", 0x8),
    ("CONNECTION_ID_LIMIT_ERROR", 0x9),
    ("PROTOCOL_VIOLATION", 0x0a),
    ("INVALID_TOKEN", 0x0b),
    ("APPLICATION_ERROR", 0x0c),
    ("CRYPTO_BUFFER_EXCEEDED", 0x0d),
    ("KEY_UPDATE_ERROR", 0x0e),
    ("AEAD_LIMIT_REACHED", 0x0f),
    ("NO_VIABLE_PATH", 0x10),
    ("VERSION_NEGOTIATION_ERROR", 0x11),
];

const APPLICATION_CODES: &[(&str, u64)] = &[
    ("H3_DATAGRAM_ERROR", 0x33),
    ("H3_NO_ERROR", 0x100),
    ("H3_GENERAL_PROTOCOL_ERROR", 0x101),
    ("H3_INTERNAL_ERROR", 0x102),
    ("H3_STREAM_CREATION_ERROR", 0x103),
    ("H3_CLOSED_CRITICAL_STREAM", 0x104),
    ("H3_FRAME_UNEXPECTED", 0x105),
    ("H3_FRAME_ERROR", 0x106),
    ("H3_EXCESSIVE_LOAD", 0x107),
    ("H3_ID_ERROR", 0x108),
    ("H3_SETTINGS_ERROR", 0x109),
    ("H3_MISSING_SETTINGS", 0x10a),
    ("H3_REQUEST_REJECTED", 0x10b),
    ("H3_REQUEST_CANCELLED", 0x10c),
    ("H3_REQUEST_INCOMPLETE", 0x10d),
    ("H3_MESSAGE_ERROR", 0x10e),
    ("H3_CONNECT_ERROR", 0x10f),
    ("H3_VERSION_FALLBACK", 0x110),
    ("QPACK_DECOMPRESSION_FAILED", 0x200),
    ("QPACK_ENCODER_STREAM_ERROR", 0x201),
    ("QPACK_DECODER_STREAM_ERROR", 0x202),
];

#[derive(Clone, Copy)]
enum ErrorChoice {
    Transport,
    Application,
}

impl std::fmt::Display for ErrorChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Transport => "transport",
            Self::Application => "application",
        })
    }
}

pub(super) fn prompt_transport_or_app_error() -> InquireResult<(ErrorSpace, u64)>
{
    let choice = Select::new("transport or application:", vec![
        ErrorChoice::Transport,
        ErrorChoice::Application,
    ])
    .prompt()?;
    let (space, codes) = match choice {
        ErrorChoice::Transport => (ErrorSpace::Transport, TRANSPORT_CODES),
        ErrorChoice::Application => (ErrorSpace::Application, APPLICATION_CODES),
    };
    let suggester = move |input: &str| suggest_named_varint(input, codes);
    let code = Text::new("error code:")
        .with_validator(move |input: &str| validate_named_varint(input, codes))
        .with_autocomplete(&suggester)
        .with_page_size(codes.len())
        .prompt()?;
    Ok((space, parse_named_varint(&code, codes)?))
}

#[cfg(test)]
mod tests {
    use super::parse_named_varint;
    use super::suggest_named_varint;
    use super::validate_named_varint;
    use super::APPLICATION_CODES;
    use super::TRANSPORT_CODES;
    use inquire::validator::Validation;

    #[test]
    fn all_named_codes_are_valid_and_suggested(
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for codes in [TRANSPORT_CODES, APPLICATION_CODES] {
            for &(name, code) in codes {
                assert_eq!(parse_named_varint(name, codes)?, code);
                assert!(matches!(
                    validate_named_varint(name, codes)?,
                    Validation::Valid
                ));
                assert!(suggest_named_varint(name, codes)?
                    .iter()
                    .any(|label| label == name));
            }
        }
        assert_eq!(
            parse_named_varint("H3_DATAGRAM_ERROR", APPLICATION_CODES)?,
            0x33
        );
        assert!(parse_named_varint("H3_DATAGRAM_ERROR", TRANSPORT_CODES).is_err());
        Ok(())
    }
}
