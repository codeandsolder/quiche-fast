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

use quiche::ConnectionId;
use quiche::MAX_CONN_ID_LEN;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;

use crate::QuicResultExt;

const HMAC_KEY_LEN: usize = 32;
const HMAC_TAG_LEN: usize = 32;

pub(super) struct AddrValidationTokenManager {
    sign_key: [u8; HMAC_KEY_LEN],
}

/// Encode the IP address with an explicit family discriminator. The source
/// port is deliberately excluded so NAT rebinding does not invalidate Retry.
fn address_binding(ip: IpAddr) -> ([u8; 17], usize) {
    let mut bytes = [0; 17];
    let length = match ip {
        IpAddr::V4(address) => {
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&address.octets());
            5
        },
        IpAddr::V6(address) => {
            bytes[0] = 6;
            bytes[1..].copy_from_slice(&address.octets());
            17
        },
    };
    (bytes, length)
}

impl AddrValidationTokenManager {
    pub(super) fn new() -> io::Result<Self> {
        let mut sign_key = [0; HMAC_KEY_LEN];
        btls::rand::rand_bytes(&mut sign_key).into_io()?;
        Ok(Self { sign_key })
    }

    pub(super) fn gen(
        &self, original_dcid: &[u8], client_addr: SocketAddr,
    ) -> io::Result<Vec<u8>> {
        if original_dcid.len() > MAX_CONN_ID_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "original DCID too long",
            ));
        }
        let (address, length) = address_binding(client_addr.ip());
        let mut token =
            Vec::with_capacity(HMAC_TAG_LEN + length + original_dcid.len());
        token.resize(HMAC_TAG_LEN, 0);
        token.extend_from_slice(&address[..length]);
        token.extend_from_slice(original_dcid);
        let tag = btls::hash::hmac_sha256(&self.sign_key, &token[HMAC_TAG_LEN..])
            .into_io()?;
        token[..HMAC_TAG_LEN].copy_from_slice(&tag);
        Ok(token)
    }

    pub(super) fn validate_and_extract_original_dcid<'t>(
        &self, token: &'t [u8], client_addr: SocketAddr,
    ) -> io::Result<ConnectionId<'t>> {
        let (address, length) = address_binding(client_addr.ip());
        let invalid =
            |message| io::Error::new(io::ErrorKind::InvalidData, message);
        let (tag, payload) = token
            .split_at_checked(HMAC_TAG_LEN)
            .ok_or_else(|| invalid("token is too short"))?;
        let dcid = payload
            .strip_prefix(&address[..length])
            .ok_or_else(|| invalid("address binding does not match"))?;
        if dcid.len() > MAX_CONN_ID_LEN {
            return Err(invalid("original DCID too long"));
        }
        let expected_tag =
            btls::hash::hmac_sha256(&self.sign_key, payload).into_io()?;
        if !btls::memcmp::eq(&expected_tag, tag) {
            return Err(invalid("signature verification failed"));
        }
        Ok(ConnectionId::from_ref(dcid))
    }
}

#[cfg(test)]
mod tests {
    use super::AddrValidationTokenManager;
    use super::HMAC_TAG_LEN;
    use super::MAX_CONN_ID_LEN;
    use quiche::ConnectionId;
    use std::net::SocketAddr;

    #[test]
    fn round_trip_all_cid_lengths_and_address_families(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = AddrValidationTokenManager::new()?;
        for (address, expected_binding) in [
            ("127.0.0.1:1337", &[4, 127, 0, 0, 1][..]),
            (
                "[::1]:1338",
                &[6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1][..],
            ),
        ] {
            let address: SocketAddr = address.parse()?;
            for length in 0..=MAX_CONN_ID_LEN {
                let dcid = vec![42; length];
                let token = manager.gen(&dcid, address)?;
                assert_ne!(token[..HMAC_TAG_LEN], [0; HMAC_TAG_LEN]);
                assert_eq!(
                    &token[HMAC_TAG_LEN..HMAC_TAG_LEN + expected_binding.len()],
                    expected_binding
                );
                assert_eq!(
                    manager
                        .validate_and_extract_original_dcid(&token, address)?,
                    ConnectionId::from_ref(&dcid)
                );
                let mut rebound = address;
                rebound.set_port(65535);
                assert_eq!(
                    manager
                        .validate_and_extract_original_dcid(&token, rebound)?,
                    ConnectionId::from_ref(&dcid)
                );
            }
            assert!(manager.gen(&[0; MAX_CONN_ID_LEN + 1], address).is_err());
        }
        Ok(())
    }

    #[test]
    fn reject_truncated_and_tampered_tokens(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = AddrValidationTokenManager::new()?;
        for address in ["127.0.0.1:1337", "[::1]:1338"] {
            let address: SocketAddr = address.parse()?;
            let token = manager.gen(b"example", address)?;
            for end in 0..token.len() {
                assert!(manager
                    .validate_and_extract_original_dcid(&token[..end], address)
                    .is_err());
            }
            for index in 0..token.len() {
                let mut tampered = token.clone();
                tampered[index] ^= 1;
                assert!(manager
                    .validate_and_extract_original_dcid(&tampered, address)
                    .is_err());
            }
            let other = AddrValidationTokenManager::new()?;
            assert!(other
                .validate_and_extract_original_dcid(&token, address)
                .is_err());
        }
        Ok(())
    }

    #[test]
    fn valid_mac_cannot_authorize_oversized_connection_id(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = AddrValidationTokenManager::new()?;
        let address = "127.0.0.1:1337".parse()?;
        let mut token = manager.gen(&[42; MAX_CONN_ID_LEN], address)?;
        token.push(42);
        let tag =
            btls::hash::hmac_sha256(&manager.sign_key, &token[HMAC_TAG_LEN..])?;
        token[..HMAC_TAG_LEN].copy_from_slice(&tag);
        assert!(manager
            .validate_and_extract_original_dcid(&token, address)
            .is_err());
        Ok(())
    }

    #[test]
    fn reject_wrong_address_and_cross_family_prefix_collisions(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let manager = AddrValidationTokenManager::new()?;
        for (source, wrong) in [
            ("127.0.0.1:1337", "127.0.0.2:1337"),
            ("[::1]:1338", "[::2]:1338"),
            ("[7f00:1::1]:1338", "127.0.0.1:1337"),
            ("[::ffff:127.0.0.1]:1338", "127.0.0.1:1337"),
        ] {
            let source = source.parse()?;
            let wrong = wrong.parse()?;
            let token = manager.gen(b"example", source)?;
            assert!(manager
                .validate_and_extract_original_dcid(&token, wrong)
                .is_err());
        }
        Ok(())
    }
}
