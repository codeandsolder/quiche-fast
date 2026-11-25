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

//! Chromium serializes integers either directly or as decimal strings.
use serde::de::Error;
use serde::Deserialize;
use serde::Deserializer;
use std::fmt::Display;
use std::str::FromStr;

#[derive(Deserialize)]
#[serde(untagged)]
enum WireNumber<T> {
    Integer(T),
    Decimal(String),
}

impl<T: FromStr> WireNumber<T>
where
    T::Err: Display,
{
    fn into_integer<E: Error>(self) -> Result<T, E> {
        match self {
            Self::Integer(value) => Ok(value),
            Self::Decimal(value) => value.parse().map_err(E::custom),
        }
    }
}

pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + FromStr,
    T::Err: Display,
{
    WireNumber::deserialize(deserializer)?.into_integer()
}

pub fn deserialize_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + FromStr,
    T::Err: Display,
{
    Vec::<WireNumber<T>>::deserialize(deserializer)?
        .into_iter()
        .map(WireNumber::into_integer)
        .collect()
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Record {
        #[serde(deserialize_with = "super::deserialize")]
        value: u64,
        #[serde(deserialize_with = "super::deserialize_vec")]
        values: Vec<u64>,
    }

    #[test]
    fn exact_integer_encodings_accept_mixed_values_and_reject_invalid_ones(
    ) -> Result<(), serde_json::Error> {
        let record: Record = serde_json::from_str(
            r#"{"value":"18446744073709551615","values":[0,"9007199254740993",42]}"#,
        )?;
        assert_eq!(record.value, u64::MAX);
        assert_eq!(record.values, [0, 9_007_199_254_740_993, 42]);
        for value in [
            "-1",
            "1.5",
            r#""-1""#,
            r#""1.5""#,
            r#""18446744073709551616""#,
            "null",
        ] {
            assert!(serde_json::from_str::<Record>(&format!(
                r#"{{"value":{value},"values":[]}}"#
            ))
            .is_err());
        }
        Ok(())
    }
}
