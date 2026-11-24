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

#[path = "support/input.rs"]
mod input;

use std::error::Error;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::io::{
    self,
};

use quiche::h3::qpack;
use quiche::h3::NameValue;

fn main() -> Result<(), Box<dyn Error>> {
    let mut file = BufReader::new(File::open(input::one_argument("FILE")?)?);
    decode_records(&mut file, &mut io::stdout().lock())
}

/// Consume framed QPACK records, distinguishing a clean EOF from a truncated
/// header or payload. Stream zero carries dynamic-table instructions, which
/// are intentionally skipped by this static-only example.
fn decode_records(
    reader: &mut impl BufRead, writer: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    while !reader.fill_buf()?.is_empty() {
        let mut stream_id = [0; 8];
        let mut length = [0; 4];
        reader.read_exact(&mut stream_id)?;
        reader.read_exact(&mut length)?;

        let stream_id = u64::from_be_bytes(stream_id);
        let length = u64::from(u32::from_be_bytes(length));
        log::debug!("Got stream={stream_id} len={length}");

        let mut payload = reader.by_ref().take(length);
        if stream_id == 0 {
            io::copy(&mut payload, &mut io::sink())?;
            ensure_complete(&payload)?;
            continue;
        }

        // Grow in proportion to bytes actually read, rather than allocating
        // the entire advertised length before checking that those bytes exist.
        let mut encoded = Vec::new();
        payload.read_to_end(&mut encoded)?;
        ensure_complete(&payload)?;

        for header in qpack::decode(&encoded, u64::MAX)? {
            writer.write_all(header.name())?;
            writer.write_all(b"\t")?;
            writer.write_all(header.value())?;
            writer.write_all(b"\n")?;
        }
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn ensure_complete(payload: &io::Take<&mut impl BufRead>) -> io::Result<()> {
    if payload.limit() == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated QPACK record",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quiche::h3::Header;

    #[test]
    fn exact_records_decode_through_short_reads() -> Result<(), Box<dyn Error>> {
        let mut bytes = Vec::new();
        // An ignored dynamic-table record is followed by a static block.
        bytes.extend_from_slice(&0_u64.to_be_bytes());
        bytes.extend_from_slice(&3_u32.to_be_bytes());
        bytes.extend_from_slice(b"abc");
        let encoded = qpack::encode(&[Header::new(b":method", b"GET")])?;
        bytes.extend_from_slice(&1_u64.to_be_bytes());
        bytes.extend_from_slice(&u32::try_from(encoded.len())?.to_be_bytes());
        bytes.extend_from_slice(&encoded);

        let mut input = BufReader::with_capacity(1, bytes.as_slice());
        let mut output = Vec::new();
        decode_records(&mut input, &mut output)?;
        assert_eq!(output, b":method\tGET\n\n");

        for end in 1..bytes.len() {
            // The boundary between two complete records is a valid EOF.
            if end == 15 {
                continue;
            }
            let mut truncated = &bytes[..end];
            assert!(decode_records(&mut truncated, &mut Vec::new()).is_err());
        }
        Ok(())
    }

    #[test]
    fn oversized_truncated_record_fails_without_preallocating() {
        let mut input = [0; 12];
        input[7] = 1;
        input[8..].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_records(&mut input.as_slice(), &mut Vec::new()).is_err());
    }
}
