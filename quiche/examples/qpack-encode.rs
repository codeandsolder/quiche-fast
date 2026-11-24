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
use std::io::Write;
use std::io::{
    self,
};

use quiche::h3::qpack;
use quiche::h3::{
    self,
};

fn main() -> Result<(), Box<dyn Error>> {
    let file = BufReader::new(File::open(input::input_path()?)?);
    encode_records(file, &mut io::stdout().lock())
}

/// Encode tab-delimited field sections separated by empty lines, including
/// a final nonempty section that ends at EOF without a trailing separator.
fn encode_records(
    reader: impl BufRead, writer: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let mut headers = Vec::new();
    let mut stream_id = 1_u64;

    for line in reader.split(b'\n') {
        let line = line?;
        let line = line.strip_suffix(b"\r").unwrap_or(&line);
        if line.starts_with(b"#") {
            continue;
        }
        if line.is_empty() {
            write_record(writer, stream_id, &headers)?;
            stream_id = stream_id.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "stream ID overflow")
            })?;
            headers.clear();
            continue;
        }

        let separator =
            line.iter().position(|&byte| byte == b'\t').ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "header line lacks a tab separator",
                )
            })?;
        let (name, rest) = line.split_at(separator);
        headers.push(h3::Header::new(name, &rest[1..]));
    }

    if !headers.is_empty() {
        write_record(writer, stream_id, &headers)?;
    }
    Ok(())
}

fn write_record(
    writer: &mut impl Write, stream_id: u64, headers: &[h3::Header],
) -> Result<(), Box<dyn Error>> {
    let encoded = qpack::encode(headers)?;
    let length = u32::try_from(encoded.len())?;
    log::debug!("Writing header block stream={stream_id} len={length}");
    writer.write_all(&stream_id.to_be_bytes())?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&encoded)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quiche::h3::NameValue;

    #[test]
    fn final_section_and_literal_tabs_survive_encoding(
    ) -> Result<(), Box<dyn Error>> {
        let mut output = Vec::new();
        encode_records(
            &b"# comment\r\nx-test\tvalue\twith tab\r\n\r\n:method\tGET"[..],
            &mut output,
        )?;
        let mut cursor = io::Cursor::new(output);
        for (id, name, value) in [
            (1_u64, &b"x-test"[..], &b"value\twith tab"[..]),
            (2_u64, &b":method"[..], &b"GET"[..]),
        ] {
            use std::io::Read;
            let mut stream_id = [0; 8];
            let mut length = [0; 4];
            cursor.read_exact(&mut stream_id)?;
            cursor.read_exact(&mut length)?;
            assert_eq!(u64::from_be_bytes(stream_id), id);
            let mut encoded =
                vec![0; usize::try_from(u32::from_be_bytes(length))?];
            cursor.read_exact(&mut encoded)?;
            let decoded = qpack::decode(&encoded, u64::MAX)?;
            assert_eq!(decoded.len(), 1);
            assert_eq!(decoded[0].name(), name);
            assert_eq!(decoded[0].value(), value);
        }
        assert!(cursor.fill_buf()?.is_empty());
        Ok(())
    }

    #[test]
    fn missing_separator_is_an_error() {
        assert!(encode_records(&b"invalid header"[..], &mut Vec::new()).is_err());
    }
}
