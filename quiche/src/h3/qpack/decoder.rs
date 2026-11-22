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

use crate::h3::Header;

use super::INDEXED;
use super::INDEXED_WITH_POST_BASE;
use super::LITERAL;
use super::LITERAL_WITH_NAME_REF;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Representation {
    Indexed,
    IndexedWithPostBase,
    Literal,
    LiteralWithNameRef,
    LiteralWithPostBase,
}

impl Representation {
    pub const fn from_byte(b: u8) -> Self {
        if b & INDEXED == INDEXED {
            return Self::Indexed;
        }

        if b & LITERAL_WITH_NAME_REF == LITERAL_WITH_NAME_REF {
            return Self::LiteralWithNameRef;
        }

        if b & LITERAL == LITERAL {
            return Self::Literal;
        }

        if b & INDEXED_WITH_POST_BASE == INDEXED_WITH_POST_BASE {
            return Self::IndexedWithPostBase;
        }

        Self::LiteralWithPostBase
    }
}

/// Helper for tracking decoded field list sizes.
///
/// The size of a field list is calculated based on the uncompressed size of
/// fields, including the length of the name and value in bytes plus an overhead
/// of 32 bytes for each field. See
/// <https://datatracker.ietf.org/doc/html/rfc9114#section-4.2.2>
struct FieldListSizeTracker {
    remaining: u64,
}

impl FieldListSizeTracker {
    /// Initialize tracker with the maximum field list size.
    ///
    /// The `max_size` parameter is the maximum size in bytes of the full
    /// decoded field list. See
    /// <https://datatracker.ietf.org/doc/html/rfc9114#section-4.2.2>
    const fn new(max_size: u64) -> Self {
        Self {
            remaining: max_size,
        }
    }

    /// Mark the start of parsing a new field.
    ///
    /// Must be called when a new field is ready to be parsed.
    fn on_field_start(&mut self) -> Result<()> {
        // Each complete field has a 32-byte overhead, so subtract that first.
        self.remaining = self
            .remaining
            .checked_sub(32)
            .ok_or(Error::HeaderListTooLarge)?;

        Ok(())
    }

    /// Marks when a field part (either name or value) has been decoded.
    ///
    /// The `len` parameter is the size in bytes of the decoded part.
    ///
    /// Must be called when a new field part has been decoded.
    fn on_field_part_decoded(&mut self, len: u64) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(len)
            .ok_or(Error::HeaderListTooLarge)?;

        Ok(())
    }

    /// The addressable portion of the remaining decoded-size budget.
    /// A larger wire-domain limit cannot constrain an in-memory string.
    fn addressable_remaining(&self) -> usize {
        usize::try_from(self.remaining).unwrap_or(usize::MAX)
    }
}

/// A QPACK decoder.
#[derive(Default)]
pub struct Decoder {}

impl Decoder {
    /// Creates a new QPACK decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Processes control instructions from the encoder.
    pub const fn control(&mut self, _buf: &mut [u8]) -> Result<()> {
        // TODO: process control instructions
        Ok(())
    }

    /// Decodes a QPACK header block into a list of headers.
    pub fn decode(&mut self, buf: &[u8], max_size: u64) -> Result<Vec<Header>> {
        let mut b = octets::Octets::with_slice(buf);

        let mut out = Vec::new();

        let mut size_tracker = FieldListSizeTracker::new(max_size);

        // RFC 9204 sections 4.5.1.1 and 4.5.1.2. The static-only
        // decoder cannot resolve any dynamic table insert count. With zero
        // required inserts a negative Delta Base is necessarily invalid;
        // a nonnegative Base is allowed even when no dynamic entries are used.
        let req_insert_count = decode_int(&mut b, 8)?;
        let negative_base = b.peek_u8()? & 0x80 != 0;
        let delta_base = decode_int(&mut b, 7)?;
        if req_insert_count != 0 || negative_base {
            return Err(Error::InvalidFieldSectionPrefix);
        }
        trace!("Header count={req_insert_count} base={delta_base}");

        while b.cap() > 0 {
            let first = b.peek_u8()?;

            size_tracker.on_field_start()?;

            match Representation::from_byte(first) {
                Representation::Indexed => {
                    const STATIC: u8 = 0x40;

                    let s = first & STATIC == STATIC;
                    let index = decode_int(&mut b, 6)?;

                    trace!("Indexed index={index} static={s}");

                    if !s {
                        // TODO: implement dynamic table
                        return Err(Error::InvalidHeaderValue);
                    }

                    let (name, value) = lookup_static(index)?;

                    size_tracker.on_field_part_decoded(
                        (name.len() + value.len()) as u64,
                    )?;

                    let hdr = Header::new(name, value);
                    out.push(hdr);
                },

                Representation::IndexedWithPostBase => {
                    let index = decode_int(&mut b, 4)?;

                    trace!("Indexed With Post Base index={index}");

                    // TODO: implement dynamic table
                    return Err(Error::InvalidHeaderValue);
                },

                Representation::Literal => {
                    let name = decode_str(
                        &mut b,
                        3,
                        size_tracker.addressable_remaining(),
                    )?;

                    size_tracker.on_field_part_decoded(name.len() as u64)?;

                    let value = decode_str(
                        &mut b,
                        7,
                        size_tracker.addressable_remaining(),
                    )?;

                    trace!(
                        "Literal Without Name Reference name={name:?} value={value:?}",
                    );

                    size_tracker.on_field_part_decoded(value.len() as u64)?;

                    // Instead of calling Header::new(), create Header directly
                    // from `name` and `value`.
                    let hdr = Header(name, value);
                    out.push(hdr);
                },

                Representation::LiteralWithNameRef => {
                    const STATIC: u8 = 0x10;

                    let s = first & STATIC == STATIC;

                    if !s {
                        // TODO: implement dynamic table
                        return Err(Error::InvalidHeaderValue);
                    }

                    let name_idx = decode_int(&mut b, 4)?;

                    let (name, _) = lookup_static(name_idx)?;

                    size_tracker.on_field_part_decoded(name.len() as u64)?;

                    let value = decode_str(
                        &mut b,
                        7,
                        size_tracker.addressable_remaining(),
                    )?;

                    trace!(
                        "Literal name_idx={name_idx} static={s} value={value:?}"
                    );

                    size_tracker.on_field_part_decoded(value.len() as u64)?;

                    // Instead of calling Header::new(), create Header directly
                    // from `value`, but clone `name` as it is just a reference.
                    let hdr = Header(name.to_vec(), value);
                    out.push(hdr);
                },

                Representation::LiteralWithPostBase => {
                    trace!("Literal With Post Base");

                    // TODO: implement dynamic table
                    return Err(Error::InvalidHeaderValue);
                },
            }
        }

        Ok(out)
    }
}

fn lookup_static(idx: u64) -> Result<(&'static [u8], &'static [u8])> {
    let idx = usize::try_from(idx).map_err(|_| Error::InvalidStaticTableIndex)?;
    super::static_table::STATIC_DECODE_TABLE
        .get(idx)
        .copied()
        .ok_or(Error::InvalidStaticTableIndex)
}

fn decode_int(b: &mut octets::Octets, prefix: usize) -> Result<u64> {
    let mask = u64::from(prefix_mask(prefix)?);

    let mut val = u64::from(b.get_u8()?);
    val &= mask;

    if val < mask {
        return Ok(val);
    }

    let mut shift = 0;

    while b.cap() > 0 {
        let byte = b.get_u8()?;

        // Checking the shift count alone does not detect discarded high bits.
        let place = 1_u64.checked_shl(shift).ok_or(Error::BufferTooShort)?;
        let inc = u64::from(byte & 0x7f)
            .checked_mul(place)
            .ok_or(Error::BufferTooShort)?;

        val = val.checked_add(inc).ok_or(Error::BufferTooShort)?;

        shift += 7;

        if byte & 0x80 == 0 {
            return Ok(val);
        }
    }

    Err(Error::BufferTooShort)
}

fn decode_str(
    b: &mut octets::Octets, prefix: usize, max_len: usize,
) -> Result<Vec<u8>> {
    let first = b.peek_u8()?;

    let huff = first & string_huffman_bit(prefix)? != 0;

    let len = usize::try_from(decode_int(b, prefix)?)
        .map_err(|_| Error::BufferTooShort)?;

    let mut val = b.get_bytes(len)?;

    let val = if huff {
        val.get_huffman_decoded_with_max_length(max_len)
            .map_err(|e| match e {
                octets::HuffmanDecodeError::InvalidEncoding =>
                    Error::InvalidHuffmanEncoding,
                octets::HuffmanDecodeError::OutputLimitExceeded =>
                    Error::HeaderListTooLarge,
                octets::HuffmanDecodeError::AllocationFailed =>
                    Error::AllocationFailed,
            })?
    } else {
        if len > max_len {
            return Err(Error::HeaderListTooLarge);
        }
        val.to_vec()
    };

    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_int1() {
        let encoded = [0b01010, 0x02];
        let mut b = octets::Octets::with_slice(&encoded);

        assert_eq!(decode_int(&mut b, 5), Ok(10));
    }

    #[test]
    fn decode_int2() {
        let encoded = [0b11111, 0b10011010, 0b00001010];
        let mut b = octets::Octets::with_slice(&encoded);

        assert_eq!(decode_int(&mut b, 5), Ok(1337));
    }

    #[test]
    fn decode_int3() {
        let encoded = [0b101010];
        let mut b = octets::Octets::with_slice(&encoded);

        assert_eq!(decode_int(&mut b, 8), Ok(42));
    }

    #[test]
    fn prefixed_integer_boundaries() {
        for prefix in 1..=8 {
            let mut storage = [0_u8; 16];
            let mut writer = octets::OctetsMut::with_slice(&mut storage);
            super::super::encode_int(u64::MAX, 0, prefix, &mut writer).unwrap();
            let used = writer.off();
            let mut reader = octets::Octets::with_slice(&storage[..used]);
            assert_eq!(decode_int(&mut reader, prefix), Ok(u64::MAX));
            assert_eq!(reader.cap(), 0);
        }

        // The last base-128 digit occupies bit 63; values >= 2 are not
        // representable. The old checked_shl silently discarded their bits.
        for final_digit in [2, 3, 126, 127] {
            let mut wire = [0x80_u8; 11];
            wire[0] = 0xff;
            wire[10] = final_digit;
            let mut reader = octets::Octets::with_slice(&wire);
            assert_eq!(decode_int(&mut reader, 8), Err(Error::BufferTooShort));
        }
        // A representable shifted digit may still overflow the accumulator.
        let mut wire = [0xff_u8; 11];
        wire[10] = 1;
        let mut reader = octets::Octets::with_slice(&wire);
        assert_eq!(decode_int(&mut reader, 8), Err(Error::BufferTooShort));
    }

    #[test]
    fn integer_prefix_flags_and_widths() {
        for prefix in 1..=8 {
            let mask = prefix_mask(prefix).unwrap();
            let first = !mask;
            let boundary = u64::from(mask);
            for value in
                [0, boundary - 1, boundary, boundary + 1, 127, 128, u64::MAX]
            {
                let mut storage = [0; 16];
                let mut writer = octets::OctetsMut::with_slice(&mut storage);
                super::super::encode_int(value, first, prefix, &mut writer)
                    .unwrap();
                let len = writer.off();
                assert_eq!(storage[0] & !mask, first);
                let mut reader = octets::Octets::with_slice(&storage[..len]);
                assert_eq!(decode_int(&mut reader, prefix), Ok(value));
                assert_eq!(reader.cap(), 0);
            }
            let mut storage = [0; 16];
            let mut writer = octets::OctetsMut::with_slice(&mut storage);
            assert_eq!(
                super::super::encode_int(1, 1, prefix, &mut writer),
                Err(Error::InvalidPrefix)
            );
            assert_eq!(writer.off(), 0);
        }
        for prefix in [0, 9, usize::MAX] {
            let mut storage = [0; 16];
            let mut writer = octets::OctetsMut::with_slice(&mut storage);
            assert_eq!(
                super::super::encode_int(1, 0, prefix, &mut writer),
                Err(Error::InvalidPrefix)
            );
            assert_eq!(writer.off(), 0);
            let mut reader = octets::Octets::with_slice(&storage);
            assert_eq!(
                decode_int(&mut reader, prefix),
                Err(Error::InvalidPrefix)
            );
            assert_eq!(reader.off(), 0);
        }
    }

    #[test]
    fn string_prefix_reserves_huffman_flag() {
        let mut storage = [0; 16];
        let mut writer = octets::OctetsMut::with_slice(&mut storage);
        for (first, prefix) in
            [(0, 0), (0, 8), (0, 9), (0, usize::MAX), (0x80, 7), (1, 7)]
        {
            assert_eq!(
                super::super::encode_str::<false>(
                    b"x",
                    first,
                    prefix,
                    &mut writer
                ),
                Err(Error::InvalidPrefix)
            );
            assert_eq!(writer.off(), 0);
        }
        let mut reader = octets::Octets::with_slice(&storage);
        assert_eq!(decode_str(&mut reader, 8, 16), Err(Error::InvalidPrefix));
        assert_eq!(reader.off(), 0);
    }

    #[test]
    fn oversized_literal_string_lengths_cannot_wrap() {
        // Exercise both length-prefix widths, Huffman and plain literals.
        for (prefix, first) in [(3, 0x20), (3, 0x28), (7, 0), (7, 0x80)] {
            let mut storage = [0_u8; 16];
            let mut writer = octets::OctetsMut::with_slice(&mut storage);
            super::super::encode_int(1_u64 << 32, first, prefix, &mut writer)
                .unwrap();
            let used = writer.off();
            let mut reader = octets::Octets::with_slice(&storage[..used]);
            assert_eq!(
                decode_str(&mut reader, prefix, usize::MAX),
                Err(Error::BufferTooShort)
            );
        }
    }

    #[test]
    fn static_field_section_prefix_checks_insert_count_and_signed_base() {
        let mut dec = Decoder::new();
        let header = Header::new(b":method", b"GET");
        assert_eq!(dec.decode(&[0, 1, 0xd1], u64::MAX), Ok(vec![header]));
        for wire in [[1, 0, 0xd1], [0, 0x80, 0xd1], [0, 0x81, 0xd1]] {
            assert_eq!(
                dec.decode(&wire, u64::MAX),
                Err(Error::InvalidFieldSectionPrefix)
            );
        }
    }

    #[test]
    fn huffman_invalid_encoding_is_not_header_size_exhaustion() {
        // Literal name "x"; value is one Huffman byte with invalid padding.
        let malformed = [0, 0, 0x21, b'x', 0x81, 0xff];
        assert_eq!(
            Decoder::new().decode(&malformed, u64::MAX),
            Err(Error::InvalidHuffmanEncoding)
        );
        // Same representation with valid HPACK encoding of "no-cache".
        let valid = b"\x00\x00\x21x\x86\xa8\xeb\x10\x64\x9c\xbf";
        assert_eq!(
            Decoder::new().decode(valid, 40),
            Err(Error::HeaderListTooLarge)
        );
        assert_eq!(
            Decoder::new().decode(valid, 41),
            Ok(vec![Header::new(b"x", b"no-cache")])
        );
    }

    #[test]
    fn large_field_budget_preserves_addressable_capacity() {
        // The remaining budget is exactly 2^32 after charging the overhead.
        // On 32-bit the previous cast made it zero.
        let wire = [0x00, 0x00, 0x21, b'x', 0x01, b'y'];
        assert_eq!(
            Decoder::new().decode(&wire, (1_u64 << 32) + 32),
            Ok(vec![Header::new(b"x", b"y")])
        );
        assert_eq!(
            Decoder::new().decode(&wire, u64::MAX),
            Ok(vec![Header::new(b"x", b"y")])
        );
    }

    /// LiteralWithNameRef with the dynamic table flag (S=0) must be
    /// rejected since the dynamic table is not implemented.
    #[test]
    fn literal_with_name_ref_dynamic_table_rejected() {
        let mut dec = Decoder::new();

        // QPACK header block:
        //   [0x00, 0x00]  required insert count=0, base=0
        //   [0x40]        LiteralWithNameRef (0b0100_0000), S=0 (dynamic),
        //                 name_idx=0
        //   [0x01, 0x61]  value: non-huffman, length=1, 'a'
        let encoded = [0x00, 0x00, 0x40, 0x01, 0x61];

        assert_eq!(
            dec.decode(&encoded, u64::MAX),
            Err(Error::InvalidHeaderValue),
        );
    }

    /// Non-Huffman value in decode_str must be rejected before allocation
    /// when it exceeds the remaining budget (max_len).
    ///
    /// Uses a LiteralWithNameRef with static `:authority` (index 0, 10
    /// bytes) and a non-Huffman value of 5 bytes. Budget is set so only
    /// 4 bytes remain for the value after the name is charged.
    #[test]
    fn non_huffman_value_exceeding_budget_rejected() {
        // QPACK header block:
        //   [0x00, 0x00]  required insert count=0, base=0
        //   [0x50]        LiteralWithNameRef, S=1 (static), name_idx=0
        //                 (:authority, 10 bytes)
        //   [0x05]        value: non-huffman (bit 7=0), length=5
        //   "abcde"       value bytes
        let encoded = [0x00, 0x00, 0x50, 0x05, 0x61, 0x62, 0x63, 0x64, 0x65];

        // Exact fit: 32 (overhead) + 10 (name) + 5 (value) = 47.
        assert!(Decoder::new().decode(&encoded, 47).is_ok());

        // One byte too small: budget = 46.
        // After overhead (32) and name (10): 4 bytes remain, but
        // value is 5 bytes → rejected.
        assert_eq!(
            Decoder::new().decode(&encoded, 46),
            Err(Error::HeaderListTooLarge),
        );
    }

    /// Non-Huffman name in the Literal arm must be rejected before
    /// allocation when it exceeds the remaining budget.
    ///
    /// Uses a Literal with a 10-byte non-Huffman name and a 1-byte
    /// non-Huffman value. Budget is set so only 9 bytes remain for the
    /// name after overhead.
    #[test]
    fn non_huffman_name_exceeding_budget_rejected() {
        // QPACK header block:
        //   [0x00, 0x00]  required insert count=0, base=0
        //   [0x27, 0x03]  Literal (0b0010_0000), N=0, H=0 (no huffman),
        //                 name_len=10 (3-bit prefix 0b111 + overflow 0x03)
        //   "x-custom99"  name bytes (10 bytes)
        //   [0x01, 0x61]  value: non-huffman, length=1, 'a'
        let encoded = [
            0x00, 0x00, // header block prefix
            0x27, 0x03, // Literal, name_len=10
            0x78, 0x2d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x39,
            0x39, // "x-custom99"
            0x01, 0x61, // value: length=1, 'a'
        ];

        // Exact fit: 32 (overhead) + 10 (name) + 1 (value) = 43.
        assert!(Decoder::new().decode(&encoded, 43).is_ok());

        // Two bytes too small: budget = 41.
        // After overhead (32): 9 bytes remain, name is 10 bytes →
        // rejected at name check.
        assert_eq!(
            Decoder::new().decode(&encoded, 41),
            Err(Error::HeaderListTooLarge),
        );
    }

    /// Verify that both Literal and LiteralWithNameRef charge the name to
    /// the budget *before* Huffman-decoding the value, so the max_len
    /// passed to the Huffman decoder is equally strict in both paths.
    #[test]
    fn literal_with_name_ref_value_budget_ordering() {
        use crate::h3::qpack;

        // Static table index 0 = `:authority` (10 bytes).
        // We'll encode the same value two ways:
        //   1. LiteralWithNameRef using `:authority` (encoder matches static
        //      table)
        //   2. Literal using a custom 10-byte name not in the static table
        //
        // Both have name_len=10, so budget arithmetic is comparable.
        let value = b"aaaaaaaaaaaaaaaa"; // 16 bytes; Huffman compresses to 10

        // -- Encode as LiteralWithNameRef --
        let headers_nameref = vec![Header::new(b":authority", value)];
        let mut buf = [0u8; 64];
        let mut enc = qpack::Encoder::new();
        let nameref_len = enc.encode(&headers_nameref, &mut buf).unwrap();
        let encoded_nameref = buf[..nameref_len].to_vec();

        // -- Encode as Literal (name not in static table) --
        let headers_literal = vec![Header::new(b"x-custom99", value)];
        let mut buf = [0u8; 64];
        let mut enc = qpack::Encoder::new();
        let literal_len = enc.encode(&headers_literal, &mut buf).unwrap();
        let encoded_literal = buf[..literal_len].to_vec();

        // Exact budget: 32 (overhead) + 10 (name) + 16 (value) = 58.
        // Both representations succeed.
        assert_eq!(
            Decoder::new().decode(&encoded_nameref, 58),
            Ok(headers_nameref.clone()),
        );
        assert_eq!(
            Decoder::new().decode(&encoded_literal, 58),
            Ok(headers_literal.clone()),
        );

        // One byte too small: budget = 57.
        // Total decoded field size = 10 + 16 = 26, overhead = 32,
        // so 32 + 26 = 58 > 57. Both reject with HeaderListTooLarge.
        //
        // Both paths now follow the same budget ordering:
        //   1. name charged first (10 bytes) → remaining = 15
        //   2. decode_str max_len = 15
        //   3. Huffman decode produces 16 bytes > 15 → rejected
        assert_eq!(
            Decoder::new().decode(&encoded_nameref, 57),
            Err(Error::HeaderListTooLarge),
        );
        assert_eq!(
            Decoder::new().decode(&encoded_literal, 57),
            Err(Error::HeaderListTooLarge),
        );
    }
}
