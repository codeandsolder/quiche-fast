// Copyright (C) 2019, Cloudflare, Inc.
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

//! HTTP/3 header compression (QPACK).

pub use encoder::encode_int;
pub use encoder::encode_str;

pub const INDEXED: u8 = 0b1000_0000;
pub const INDEXED_WITH_POST_BASE: u8 = 0b0001_0000;
pub const LITERAL: u8 = 0b0010_0000;
pub const LITERAL_WITH_NAME_REF: u8 = 0b0100_0000;

/// A specialized [`Result`] type for quiche QPACK operations.
///
/// This type is used throughout quiche's QPACK public API for any operation
/// that can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// A QPACK error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The provided buffer is too short.
    BufferTooShort,

    /// The integer prefix width or representation flags are invalid.
    InvalidPrefix,

    /// The QPACK header block's huffman encoding is invalid.
    InvalidHuffmanEncoding,

    /// The QPACK static table index provided doesn't exist.
    InvalidStaticTableIndex,

    /// The decoded QPACK header name or value is not valid.
    InvalidHeaderValue,

    /// The decoded header list exceeded the size limit.
    HeaderListTooLarge,

    /// The field-section prefix requires unsupported dynamic table state.
    InvalidFieldSectionPrefix,

    /// Storage for a decoded string could not be reserved.
    AllocationFailed,
}

/// QPACK integers have a prefix of one through eight bits. Keeping the
/// mask in the byte domain also makes the representation flags disjoint.
const fn prefix_mask(prefix: usize) -> Result<u8> {
    match prefix {
        1..=8 => Ok(u8::MAX >> (8 - prefix)),
        _ => Err(Error::InvalidPrefix),
    }
}

/// A string has one additional bit for the Huffman encoding flag.
fn string_huffman_bit(prefix: usize) -> Result<u8> {
    prefix_mask(prefix)?
        .checked_add(1)
        .ok_or(Error::InvalidPrefix)
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<std::collections::TryReserveError> for Error {
    fn from(_: std::collections::TryReserveError) -> Self {
        Self::AllocationFailed
    }
}

impl From<octets::BufferTooShortError> for Error {
    fn from(_err: octets::BufferTooShortError) -> Self {
        Self::BufferTooShort
    }
}

#[cfg(test)]
mod tests {
    use crate::h3::qpack::Error::HeaderListTooLarge;
    use crate::*;

    use super::*;

    #[test]
    fn owned_and_fixed_output_agree() {
        let fields = [
            h3::Header::new(b":method", b"GET"),
            h3::Header::new(b"X-Custom", b"Mixed case value"),
        ];
        let owned = encode(&fields).unwrap();
        let mut fixed = vec![0; owned.len()];
        assert_eq!(encode_into(&fields, &mut fixed), Ok(owned.len()));
        assert_eq!(fixed, owned);
        let short = &mut fixed[..owned.len() - 1];
        assert_eq!(encode_into(&fields, short), Err(Error::BufferTooShort));
        assert_eq!(decode(&owned, u64::MAX).unwrap()[1].name(), b"x-custom");
        assert_eq!(
            decode(&encode_literal(&fields).unwrap(), u64::MAX).unwrap(),
            fields
        );
    }

    #[test]
    fn empty_field_section_has_prefix() {
        let fields: [h3::Header; 0] = [];
        assert_eq!(encode(&fields), Ok(vec![0, 0]));
        assert_eq!(encode_literal(&fields), Ok(vec![0, 0]));
        assert_eq!(decode(&[0, 0], 0), Ok(Vec::new()));
    }

    #[test]
    fn encode_decode() {
        let mut encoded = [0u8; 240];

        let headers = vec![
            h3::Header::new(b":path", b"/rsrc.php/v3/yn/r/rIPZ9Qkrdd9.png"),
            h3::Header::new(b"accept-encoding", b"gzip, deflate, br"),
            h3::Header::new(b"accept-language", b"en-US,en;q=0.9"),
            h3::Header::new(b"user-agent", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.70 Safari/537.36"),
            h3::Header::new(b"accept", b"image/webp,image/apng,image/*,*/*;q=0.8"),
            h3::Header::new(b"referer", b"https://static.xx.fbcdn.net/rsrc.php/v3/yT/l/0,cross/dzXGESIlGQQ.css"),
            h3::Header::new(b":authority", b"static.xx.fbcdn.net"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":method", b"GET"),
        ];

        assert_eq!(encode_into(&headers, &mut encoded), Ok(240));

        assert_eq!(decode(&encoded, u64::MAX), Ok(headers));
    }

    #[test]
    fn encode_decode_small_max_field_section_size() {
        let mut encoded = [0u8; 102];

        const NUM_HDRS: usize = 10;

        let headers = vec![h3::Header::new(b"hello", b"world"); NUM_HDRS];

        // The size of a field list is calculated based on the uncompressed size
        // of fields, including the length of the name and value in bytes plus
        // an overhead of 32 bytes for each field. See
        // https://datatracker.ietf.org/doc/html/rfc9114#section-4.2.2
        let qpack_field_section_size =
            (b"hello".len() + b"world".len() + 32) * NUM_HDRS;

        assert_eq!(encode_into(&headers, &mut encoded), Ok(102));

        // Equal max_size param ok
        assert_eq!(
            decode(&encoded, qpack_field_section_size as u64),
            Ok(headers.clone())
        );

        // Oversized max_size param ok
        assert_eq!(
            decode(&encoded, qpack_field_section_size as u64 + 1),
            Ok(headers.clone())
        );

        // Smaller max_size param (forgetting 32 byte overhead) fails
        let wrong_qpack_field_section_size =
            (b"hello".len() + b"world".len()) * NUM_HDRS;
        assert_eq!(
            decode(&encoded, wrong_qpack_field_section_size as u64),
            Err(HeaderListTooLarge)
        );
    }

    #[test]
    fn lower_case() {
        let mut encoded = [0u8; 35];

        let headers_expected = vec![
            h3::Header::new(b":status", b"200"),
            h3::Header::new(b":path", b"/HeLlO"),
            h3::Header::new(b"woot", b"woot"),
            h3::Header::new(b"hello", b"WorlD"),
            h3::Header::new(b"foo", b"BaR"),
        ];

        // Header.
        let headers_in = vec![
            h3::Header::new(b":StAtUs", b"200"),
            h3::Header::new(b":PaTh", b"/HeLlO"),
            h3::Header::new(b"WooT", b"woot"),
            h3::Header::new(b"hello", b"WorlD"),
            h3::Header::new(b"fOo", b"BaR"),
        ];

        assert_eq!(encode_into(&headers_in, &mut encoded), Ok(35));

        let headers_out = decode(&encoded, u64::MAX).unwrap();

        assert_eq!(headers_expected, headers_out);

        // HeaderRef.
        let headers_in = vec![
            h3::HeaderRef::new(b":StAtUs", b"200"),
            h3::HeaderRef::new(b":PaTh", b"/HeLlO"),
            h3::HeaderRef::new(b"WooT", b"woot"),
            h3::HeaderRef::new(b"hello", b"WorlD"),
            h3::HeaderRef::new(b"fOo", b"BaR"),
        ];

        assert_eq!(encode_into(&headers_in, &mut encoded), Ok(35));

        let headers_out = decode(&encoded, u64::MAX).unwrap();

        assert_eq!(headers_expected, headers_out);
    }

    #[test]
    fn lower_ascii_range() {
        let mut encoded = [0u8; 50];

        // Indexed name with literal value
        let headers1 = vec![h3::Header::new(b"location", b"															")];
        assert_eq!(encode_into(&headers1, &mut encoded), Ok(19));

        // Literal name and value
        let headers2 = vec![h3::Header::new(b"a", b"")];
        assert_eq!(encode_into(&headers2, &mut encoded), Ok(20));

        let headers3 = vec![h3::Header::new(b"															", b"hello")];
        assert_eq!(encode_into(&headers3, &mut encoded), Ok(24));
    }

    #[test]
    fn extended_ascii_range() {
        let mut encoded = [0u8; 50];

        let name = b"location";
        let value = "£££££££££££££££";

        // Indexed name with literal value
        let headers1 = vec![h3::Header::new(name, value.as_bytes())];
        assert_eq!(encode_into(&headers1, &mut encoded), Ok(34));

        // Literal name and value
        let value = "ððððððððððððððð";
        let headers2 = vec![h3::Header::new(b"a", value.as_bytes())];
        assert_eq!(encode_into(&headers2, &mut encoded), Ok(35));

        let headers3 = vec![h3::Header::new(value.as_bytes(), b"hello")];
        assert_eq!(encode_into(&headers3, &mut encoded), Ok(39));
    }
}

pub use decoder::decode;
pub use encoder::encode;
pub use encoder::encode_into;
pub use encoder::encode_literal;

mod decoder;
mod encoder;
mod static_table;
