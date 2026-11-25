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

use std::time::Duration;

use inquire::error::InquireResult;
use inquire::validator::ErrorMessage;
use inquire::validator::Validation;
use inquire::InquireError;
use inquire::Select;
use inquire::Text;

use crate::actions::h3::Action;
use crate::actions::h3::StreamEvent;
use crate::actions::h3::StreamEventType;
use crate::actions::h3::WaitType;

use super::prompt_stream_id;

#[derive(Clone, Copy)]
enum WaitChoice {
    Duration,
    Stream(StreamEventType),
}

impl std::fmt::Display for WaitChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Duration => "duration",
            Self::Stream(StreamEventType::Headers) => "headers",
            Self::Stream(StreamEventType::Data) => "data",
            Self::Stream(StreamEventType::Finished) => "stream finished",
        })
    }
}

pub(super) fn prompt_wait(idle_timeout: u64) -> InquireResult<Action> {
    let choice = Select::new("wait type:", vec![
        WaitChoice::Duration,
        WaitChoice::Stream(StreamEventType::Headers),
        WaitChoice::Stream(StreamEventType::Data),
        WaitChoice::Stream(StreamEventType::Finished),
    ])
    .prompt()?;
    let wait_type = match choice {
        WaitChoice::Duration => {
            let period = Text::new("wait period (ms):")
                .with_validator(move |input: &str| {
                    Ok(validate_wait_period(input, idle_timeout))
                })
                .prompt()?;
            WaitType::WaitDuration(parse_wait_period(&period, idle_timeout)?)
        },
        WaitChoice::Stream(event_type) => WaitType::StreamEvent(StreamEvent {
            stream_id: prompt_stream_id()?,
            event_type,
        }),
    };
    Ok(Action::Wait { wait_type })
}

fn parse_wait_period(input: &str, idle_timeout: u64) -> InquireResult<Duration> {
    let millis = input
        .parse::<u64>()
        .map_err(|error| InquireError::Custom(error.into()))?;
    if idle_timeout != 0 && millis >= idle_timeout {
        return Err(InquireError::Custom(
            format!("wait time >= local connection idle timeout {idle_timeout}")
                .into(),
        ));
    }
    Ok(Duration::from_millis(millis))
}

fn validate_wait_period(input: &str, idle_timeout: u64) -> Validation {
    match parse_wait_period(input, idle_timeout) {
        Ok(_) => Validation::Valid,
        Err(error) =>
            Validation::Invalid(ErrorMessage::Custom(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_wait_period;
    use std::time::Duration;

    #[test]
    fn wait_limit_is_connection_specific_and_zero_is_unlimited(
    ) -> Result<(), inquire::InquireError> {
        assert_eq!(parse_wait_period("100", 0)?, Duration::from_millis(100));
        assert_eq!(parse_wait_period("99", 100)?, Duration::from_millis(99));
        assert!(parse_wait_period("100", 100).is_err());
        assert!(parse_wait_period("invalid", 0).is_err());
        assert!(parse_wait_period("-1", 0).is_err());
        Ok(())
    }
}
