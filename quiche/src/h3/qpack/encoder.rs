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

use super::prefix_mask;
use super::string_huffman_bit;
use super::Error;
use super::Result;

use crate::h3::NameValue;

use super::INDEXED;
use super::LITERAL;
use super::LITERAL_WITH_NAME_REF;

/// Encodes a field section using the static table and lowercase header names.
pub fn encode<T: NameValue>(headers: &[T]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_fields::<true, T>(headers, &mut out)?;
    Ok(out)
}

/// Encodes a field section into caller-provided storage.
pub fn encode_into<T: NameValue>(headers: &[T], out: &mut [u8]) -> Result<usize> {
    let mut b = octets::OctetsMut::with_slice(out);
    encode_fields::<true, T>(headers, &mut b)?;
    Ok(b.off())
}

/// Encodes literal fields without static lookup or header-name normalization.
/// Huffman coding is still used when it saves space.
pub fn encode_literal<T: NameValue>(headers: &[T]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_fields::<false, T>(headers, &mut out)?;
    Ok(out)
}

fn encode_fields<const USE_STATIC: bool, T: NameValue>(
    headers: &[T], b: &mut impl octets::OctetsWriter<Error: Into<Error>>,
) -> Result<()> {
    // Static-only QPACK: required insert count and delta base are both zero.
    b.put_bytes(&[0, 0]).map_err(Into::into)?;
    for h in headers {
        match if USE_STATIC { lookup_static(h) } else { None } {
            Some((idx, true)) => encode_int(idx, INDEXED | 0x40, 6, b)?,
            Some((idx, false)) => {
                encode_int(idx, LITERAL_WITH_NAME_REF | 0x10, 4, b)?;
                encode_str::<false>(h.value(), 0, 7, b)?;
            },
            None => {
                encode_str::<USE_STATIC>(h.name(), LITERAL, 3, b)?;
                encode_str::<false>(h.value(), 0, 7, b)?;
            },
        }
    }
    Ok(())
}

fn lookup_static<T: NameValue>(h: &T) -> Option<(u64, bool)> {
    // Fetch the right encoding table for this header length.
    let table_for_len =
        super::static_table::STATIC_ENCODE_TABLE.get(h.name().len())?;

    // Similar to [`eq_ignore_ascii_case`], but only lowercases the second
    // operand, as the entries in the table are already lower cased.
    let cmp_lowercase = |a: &[u8], b: &[u8]| {
        std::iter::zip(a, b).all(|(a, b)| a.eq(&b.to_ascii_lowercase()))
    };

    for (name, values) in *table_for_len {
        // Match header name first.
        if cmp_lowercase(name, h.name()) {
            // Second iterate over possible values for the header.
            for (value, enc) in *values {
                // Match header value.
                if value.is_empty() {
                    return Some((*enc, false));
                }

                if h.value() == *value {
                    return Some((*enc, true));
                }
            }
            // Only matched the header, not the value.
            return Some((values.first()?.1, false));
        }
    }

    None
}

/// Encodes an unsigned integer with a 1-8 bit QPACK prefix.
/// Representation flags must not overlap the integer prefix.
pub fn encode_int(
    mut v: u64, first: u8, prefix: usize,
    b: &mut impl octets::OctetsWriter<Error: Into<Error>>,
) -> Result<()> {
    let mask = prefix_mask(prefix)?;
    if first & mask != 0 {
        return Err(Error::InvalidPrefix);
    }

    // I fits in the prefix without a continuation.
    if v < u64::from(mask) {
        b.put_bytes(&[first | v.to_le_bytes()[0]])
            .map_err(Into::into)?;
        return Ok(());
    }

    b.put_bytes(&[first | mask]).map_err(Into::into)?;
    v -= u64::from(mask);

    // Continuations consist of seven low-order bits plus the continuation flag.
    while v >= 128 {
        b.put_bytes(&[(v.to_le_bytes()[0] & 0x7f) | 0x80])
            .map_err(Into::into)?;
        v >>= 7;
    }
    b.put_bytes(&[v.to_le_bytes()[0]]).map_err(Into::into)?;
    Ok(())
}

/// Encodes a string literal, choosing Huffman coding when it saves space.
#[inline]
pub fn encode_str<const LOWER_CASE: bool>(
    v: &[u8], first: u8, prefix: usize,
    b: &mut impl octets::OctetsWriter<Error: Into<Error>>,
) -> Result<()> {
    let huffman_bit = string_huffman_bit(prefix)?;
    if first & (huffman_bit | prefix_mask(prefix)?) != 0 {
        return Err(Error::InvalidPrefix);
    }

    // Huffman-encoding generally saves space but in some cases it doesn't, for
    // those just encode the literal string.
    if let Ok(len) = octets::huffman_encoding_len::<LOWER_CASE>(v) {
        encode_int(len as u64, first | huffman_bit, prefix, b)?;
        b.put_huffman_encoded::<LOWER_CASE>(v).map_err(Into::into)?;
    } else {
        encode_int(v.len() as u64, first, prefix, b)?;
        if LOWER_CASE && v.iter().any(u8::is_ascii_uppercase) {
            let mut chunk = [0; 128];
            for input in v.chunks(chunk.len()) {
                let dst = &mut chunk[..input.len()];
                dst.copy_from_slice(input);
                dst.make_ascii_lowercase();
                b.put_bytes(dst).map_err(Into::into)?;
            }
        } else {
            b.put_bytes(v).map_err(Into::into)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_int1() {
        let expected = [0b01010];
        let mut encoded = [0; 1];
        let mut b = octets::OctetsMut::with_slice(&mut encoded);

        assert!(encode_int(10, 0, 5, &mut b).is_ok());

        assert_eq!(expected, encoded);
    }

    #[test]
    fn encode_int2() {
        let expected = [0b11111, 0b10011010, 0b00001010];
        let mut encoded = [0; 3];
        let mut b = octets::OctetsMut::with_slice(&mut encoded);

        assert!(encode_int(1337, 0, 5, &mut b).is_ok());

        assert_eq!(expected, encoded);
    }

    #[test]
    fn encode_int3() {
        let expected = [0b101010];
        let mut encoded = [0; 1];
        let mut b = octets::OctetsMut::with_slice(&mut encoded);

        assert!(encode_int(42, 0, 8, &mut b).is_ok());

        assert_eq!(expected, encoded);
    }

    #[test]
    fn encode_static_header() {
        let mut encoded = [0; 3];
        encode_into(&[(b":method", b"GET")], &mut encoded).unwrap();
        assert_eq!(encoded, [0, 0, INDEXED | 0x40 | 17]);
    }

    #[test]
    fn encode_static_header_name_only() {
        let mut encoded = [0; 11];
        let mut expected = [0; 11];
        let mut buf = octets::OctetsMut::with_slice(&mut expected[..]);
        buf.put_u16(0).unwrap();
        buf.put_u8(LITERAL_WITH_NAME_REF | 0x10 | 15).unwrap();
        buf.put_u8(0).unwrap();
        encode_str::<false>(b"FORGET", 0, 7, &mut buf).unwrap();

        encode_into(&[(b":method", b"FORGET")], &mut encoded).unwrap();
        assert_eq!(encoded, expected);
    }
}
