// Copyright (C) 2018-2019, Cloudflare, Inc.
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

use libc::c_int;
use libc::c_void;

use crate::Error;
use crate::Result;

use crate::packet;

// All supported AEAD algorithms have the same nonce and authentication tag
// widths. The only variable-width key material is the cryptographic key.
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
const MAX_KEY_LEN: usize = 32;

// Length of header protection mask.
pub const HP_MASK_LEN: usize = 5;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Initial   = 0,
    ZeroRTT   = 1,
    Handshake = 2,
    OneRTT    = 3,
}

impl Level {
    pub const fn from_epoch(e: packet::Epoch) -> Self {
        match e {
            packet::Epoch::Initial => Self::Initial,

            packet::Epoch::Handshake => Self::Handshake,

            packet::Epoch::Application => Self::OneRTT,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    #[expect(
        non_camel_case_types,
        reason = "Name mirrors the external C/BoringSSL ABI"
    )]
    AES128_GCM,

    #[expect(
        non_camel_case_types,
        reason = "Name mirrors the external C/BoringSSL ABI"
    )]
    AES256_GCM,

    #[expect(
        non_camel_case_types,
        reason = "Name mirrors the external C/BoringSSL ABI"
    )]
    ChaCha20_Poly1305,
}

// Note: some vendor-specific methods are implemented in the boringssl
// submodule.
impl Algorithm {
    fn get_evp_digest(self) -> *const EVP_MD {
        // SAFETY: These parameterless BoringSSL functions return static
        // digest descriptors owned by the library.
        unsafe {
            match self {
                Self::AES128_GCM | Self::ChaCha20_Poly1305 => EVP_sha256(),
                Self::AES256_GCM => EVP_sha384(),
            }
        }
    }

    pub const fn key_len(self) -> usize {
        match self {
            Self::AES128_GCM => 16,
            Self::AES256_GCM | Self::ChaCha20_Poly1305 => 32,
        }
    }
}

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
pub struct EVP_AEAD {
    _unused: c_void,
}

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
struct EVP_MD {
    _unused: c_void,
}

type HeaderProtectionMask = [u8; HP_MASK_LEN];

/// Whether the context can start at packet number zero or must already
/// have its nonce mask initialized for an arbitrary packet number.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CounterInitialization {
    FirstPacket,
    Prime,
}

/// Shared packet-protection state. The direction is part of the type so only
/// the appropriate open or seal operation is exposed to callers.
pub struct PacketProtection<const SEALING: bool> {
    alg: Algorithm,

    secret: Vec<u8>,

    header: HeaderProtectionKey,

    packet: PacketKey,
}

pub type Open = PacketProtection<false>;
pub type Seal = PacketProtection<true>;

impl<const SEALING: bool> PacketProtection<SEALING> {
    pub fn from_secret(
        aead: Algorithm, secret: &[u8], initialization: CounterInitialization,
    ) -> Result<Self> {
        Ok(Self {
            alg: aead,
            secret: secret.to_vec(),
            header: HeaderProtectionKey::from_secret(aead, secret)?,
            packet: PacketKey::from_secret(aead, secret, initialization)?,
        })
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if cfg!(feature = "fuzzing") {
            return Ok(<[u8; 5]>::default());
        }

        self.header.new_mask(sample)
    }

    pub fn derive_next_packet_key(&self) -> Result<Self> {
        let next_secret = derive_next_secret(self.alg, &self.secret)?;

        let next_packet_key = PacketKey::from_secret(
            self.alg,
            &next_secret,
            CounterInitialization::Prime,
        )?;

        Ok(Self {
            alg: self.alg,

            secret: next_secret,

            header: self.header.clone(),

            packet: next_packet_key,
        })
    }
}

impl PacketProtection<false> {
    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        if cfg!(feature = "fuzzing") {
            let tag_len = TAG_LEN;
            let Some(out_len) = buf.len().checked_sub(tag_len) else {
                return Err(Error::CryptoFail);
            };
            if ad.len() > tag_len && buf[out_len..] == ad[..tag_len] {
                return Err(Error::CryptoFail);
            }
            return Ok(out_len);
        }

        self.packet.open_with_u64_counter(counter, ad, buf)
    }
}

impl PacketProtection<true> {
    pub fn seal_with_u64_counter(
        &mut self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        if cfg!(feature = "fuzzing") {
            let tag_len = TAG_LEN;

            let remaining =
                buf.len().checked_sub(in_len).ok_or(Error::CryptoFail)?;
            let available =
                remaining.checked_sub(tag_len).ok_or(Error::CryptoFail)?;
            if let Some(extra) = extra_in {
                if extra.len() > available {
                    return Err(Error::CryptoFail);
                }
                buf[in_len..in_len + extra.len()].copy_from_slice(extra);
                return Ok(in_len + extra.len());
            }
            return Ok(in_len + tag_len);
        }

        self.packet
            .seal_with_u64_counter(counter, ad, buf, in_len, extra_in)
    }
}

impl HeaderProtectionKey {
    pub fn from_secret(aead: Algorithm, secret: &[u8]) -> Result<Self> {
        let key_len = aead.key_len();

        let mut hp_key = [0; MAX_KEY_LEN];
        let hp_key = &mut hp_key[..key_len];

        derive_hdr_key(aead, secret, hp_key)?;

        Self::new(aead, hp_key)
    }
}

/// QUIC v1 is the only implemented version. Reserved-version probes use
/// the same initial key derivation until version negotiation selects v1.
pub fn derive_initial_key_material(
    cid: &[u8], is_server: bool, initialization: CounterInitialization,
) -> Result<(Open, Seal)> {
    let mut initial_secret = [0; 32];
    let mut client_secret = [0; 32];
    let mut server_secret = [0; 32];

    let aead = Algorithm::AES128_GCM;
    derive_initial_secret(cid, &mut initial_secret)?;
    derive_client_initial_secret(aead, &initial_secret, &mut client_secret)?;
    derive_server_initial_secret(aead, &initial_secret, &mut server_secret)?;

    let (open_secret, seal_secret) = if is_server {
        (&client_secret, &server_secret)
    } else {
        (&server_secret, &client_secret)
    };
    Ok((
        Open::from_secret(aead, open_secret, initialization)?,
        Seal::from_secret(aead, seal_secret, initialization)?,
    ))
}

fn derive_initial_secret(secret: &[u8], out_prk: &mut [u8]) -> Result<()> {
    const INITIAL_SALT_V1: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6,
        0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];

    hkdf_extract(Algorithm::AES128_GCM, out_prk, secret, &INITIAL_SALT_V1)
}

fn derive_client_initial_secret(
    aead: Algorithm, prk: &[u8], out: &mut [u8],
) -> Result<()> {
    const LABEL: &[u8] = b"client in";
    hkdf_expand_label(aead, prk, LABEL, out)
}

fn derive_server_initial_secret(
    aead: Algorithm, prk: &[u8], out: &mut [u8],
) -> Result<()> {
    const LABEL: &[u8] = b"server in";
    hkdf_expand_label(aead, prk, LABEL, out)
}

fn derive_next_secret(aead: Algorithm, secret: &[u8]) -> Result<Vec<u8>> {
    const LABEL: &[u8] = b"quic ku";

    let mut next_secret = vec![0u8; secret.len()];

    hkdf_expand_label(aead, secret, LABEL, &mut next_secret)?;

    Ok(next_secret)
}

pub fn derive_hdr_key(
    aead: Algorithm, secret: &[u8], out: &mut [u8],
) -> Result<()> {
    const LABEL: &[u8] = b"quic hp";

    let key_len = aead.key_len();

    if key_len > out.len() {
        return Err(Error::CryptoFail);
    }

    hkdf_expand_label(aead, secret, LABEL, &mut out[..key_len])
}

pub fn derive_pkt_key(aead: Algorithm, prk: &[u8], out: &mut [u8]) -> Result<()> {
    const LABEL: &[u8] = b"quic key";

    let key_len: usize = aead.key_len();

    if key_len > out.len() {
        return Err(Error::CryptoFail);
    }

    hkdf_expand_label(aead, prk, LABEL, &mut out[..key_len])
}

pub fn derive_pkt_iv(aead: Algorithm, prk: &[u8], out: &mut [u8]) -> Result<()> {
    const LABEL: &[u8] = b"quic iv";

    let nonce_len = NONCE_LEN;

    if nonce_len > out.len() {
        return Err(Error::CryptoFail);
    }

    hkdf_expand_label(aead, prk, LABEL, &mut out[..nonce_len])
}

fn hkdf_expand_label(
    alg: Algorithm, prk: &[u8], label: &[u8], out: &mut [u8],
) -> Result<()> {
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let out_len = u16::try_from(out.len())
        .map_err(|_| Error::CryptoFail)?
        .to_be_bytes();
    let label_len = u8::try_from(LABEL_PREFIX.len() + label.len())
        .map_err(|_| Error::CryptoFail)?;

    // TLS HkdfLabel: u16 length, u8 label length, label, empty context.
    // The label length was validated above, so it fits in this stack buffer.
    let mut info = [0; 2 + 1 + u8::MAX as usize + 1];
    let mut cursor = octets::OctetsMut::with_slice(&mut info);
    cursor.put_bytes(&out_len)?;
    cursor.put_u8(label_len)?;
    cursor.put_bytes(LABEL_PREFIX)?;
    cursor.put_bytes(label)?;
    cursor.put_u8(0)?;
    let len = cursor.off();

    hkdf_expand(alg, out, prk, &info[..len])?;

    Ok(())
}

fn make_nonce(iv: &[u8; NONCE_LEN], counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = *iv;

    // XOR the last bytes of the IV with the counter. This is equivalent to
    // left-padding the counter with zero bytes.
    for (a, b) in nonce[4..].iter_mut().zip(counter.to_be_bytes().iter()) {
        *a ^= b;
    }

    nonce
}

pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<()> {
    if a.len() != b.len() {
        return Err(Error::CryptoFail);
    }

    // SAFETY: Both slices are readable for the same checked length.
    let rc = unsafe { CRYPTO_memcmp(a.as_ptr(), b.as_ptr(), a.len()) };

    if rc == 0 {
        return Ok(());
    }

    Err(Error::CryptoFail)
}

extern "C" {
    fn EVP_sha256() -> *const EVP_MD;

    fn EVP_sha384() -> *const EVP_MD;

    // CRYPTO
    fn CRYPTO_memcmp(a: *const u8, b: *const u8, len: usize) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_ffi_checks_lengths_before_access() {
        for alg in [
            Algorithm::AES128_GCM,
            Algorithm::AES256_GCM,
            Algorithm::ChaCha20_Poly1305,
        ] {
            let key = [0; MAX_KEY_LEN];
            let key = &key[..alg.key_len()];
            let nonce = [0; NONCE_LEN];
            assert!(PacketKey::new(alg, &key[..key.len() - 1], &nonce).is_err());
            assert!(PacketKey::new(alg, key, &nonce[..nonce.len() - 1]).is_err());
            assert!(HeaderProtectionKey::new(alg, &key[..key.len() - 1]).is_err());
            let hp = HeaderProtectionKey::new(alg, key).unwrap();
            assert_eq!(hp.new_mask(&[0; 15]), Err(Error::CryptoFail));
            assert!(hp.new_mask(&[0; 16]).is_ok());

            let mut pkt = PacketKey::new(alg, key, &nonce).unwrap();
            let mut buf = [0; 32];
            assert_eq!(
                pkt.seal_with_u64_counter(0, b"", &mut buf, usize::MAX, None),
                Err(Error::CryptoFail)
            );
            assert_eq!(
                pkt.seal_with_u64_counter(0, b"", &mut buf, 17, None),
                Err(Error::CryptoFail)
            );
            assert_eq!(
                pkt.seal_with_u64_counter(0, b"", &mut buf, 16, Some(&[0])),
                Err(Error::CryptoFail)
            );

            let mut seal = Seal::from_secret(
                alg,
                &[0; 32],
                CounterInitialization::FirstPacket,
            )
            .unwrap();
            assert_eq!(
                seal.seal_with_u64_counter(0, b"", &mut buf, usize::MAX, None),
                Err(Error::CryptoFail)
            );
            assert_eq!(
                seal.seal_with_u64_counter(
                    0,
                    b"",
                    &mut buf,
                    usize::MAX,
                    Some(&[0])
                ),
                Err(Error::CryptoFail)
            );

            let required = if alg == Algorithm::AES256_GCM { 48 } else { 32 };
            let mut out = vec![0xA5; required];
            assert_eq!(
                hkdf_extract(alg, &mut out[..required - 1], b"secret", b"salt"),
                Err(Error::CryptoFail)
            );
            assert!(out.iter().all(|&b| b == 0xA5));
            assert!(hkdf_extract(alg, &mut out, b"secret", b"salt").is_ok());
        }
        let mut out = [0; 32];
        assert_eq!(
            hkdf_expand_label(
                Algorithm::AES128_GCM,
                b"secret",
                &[0; 250],
                &mut out
            ),
            Err(Error::CryptoFail)
        );
    }

    #[test]
    fn key_derivation_preserves_counter_initialization() {
        for alg in [
            Algorithm::AES128_GCM,
            Algorithm::AES256_GCM,
            Algorithm::ChaCha20_Poly1305,
        ] {
            for (initialization, counter) in [
                (CounterInitialization::FirstPacket, 0),
                (CounterInitialization::Prime, 91),
            ] {
                let secret = [0xa5; 48];
                let mut seal =
                    PacketKey::from_secret(alg, &secret, initialization).unwrap();
                let open =
                    PacketKey::from_secret(alg, &secret, initialization).unwrap();
                let mut buf = [0; 7 + TAG_LEN];
                buf[..7].copy_from_slice(b"payload");
                assert_eq!(
                    seal.seal_with_u64_counter(
                        counter, b"header", &mut buf, 7, None
                    ),
                    Ok(buf.len())
                );
                assert_eq!(
                    open.open_with_u64_counter(counter, b"header", &mut buf),
                    Ok(7)
                );
                assert_eq!(&buf[..7], b"payload");
            }
        }
    }

    #[test]
    fn hkdf_label_encoding_matches_reference_at_width_boundaries() {
        let alg = Algorithm::AES128_GCM;
        for len in [0, 1, 6, 32, 248, 249] {
            let label = vec![0x93; len];
            let mut actual = [0; 32];
            let mut expected = [0; 32];
            let mut info = vec![0, 32, u8::try_from(6 + len).unwrap()];
            info.extend_from_slice(b"tls13 ");
            info.extend_from_slice(&label);
            info.push(0);
            hkdf_expand(alg, &mut expected, b"secret", &info).unwrap();
            hkdf_expand_label(alg, b"secret", &label, &mut actual).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn derive_initial_secrets_v1() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        let mut initial_secret = [0; 32];

        let mut secret = [0; 32];
        let mut pkt_key = [0; 16];
        let mut pkt_iv = [0; 12];
        let mut hdr_key = [0; 16];

        let aead = Algorithm::AES128_GCM;

        assert!(derive_initial_secret(&dcid, &mut initial_secret,).is_ok());

        // Client.
        assert!(
            derive_client_initial_secret(aead, &initial_secret, &mut secret)
                .is_ok()
        );
        let expected_client_initial_secret = [
            0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf,
            0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81,
            0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
        ];
        assert_eq!(&secret, &expected_client_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_client_pkt_key = [
            0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef,
            0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
        ];
        assert_eq!(&pkt_key, &expected_client_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_client_pkt_iv = [
            0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25,
            0x5c,
        ];
        assert_eq!(&pkt_iv, &expected_client_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_client_hdr_key = [
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e,
            0x99, 0x33, 0xad, 0xed, 0xd2,
        ];
        assert_eq!(&hdr_key, &expected_client_hdr_key);

        // Server.
        assert!(
            derive_server_initial_secret(aead, &initial_secret, &mut secret)
                .is_ok()
        );

        let expected_server_initial_secret = [
            0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15,
            0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46,
            0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b,
        ];
        assert_eq!(&secret, &expected_server_initial_secret);

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_server_pkt_key = [
            0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3,
            0x79, 0xb6, 0x06, 0x7e, 0x37,
        ];
        assert_eq!(&pkt_key, &expected_server_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_server_pkt_iv = [
            0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0,
            0x3e,
        ];
        assert_eq!(&pkt_iv, &expected_server_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_server_hdr_key = [
            0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b,
            0x49, 0x0e, 0xea, 0xa3, 0x14,
        ];
        assert_eq!(&hdr_key, &expected_server_hdr_key);
    }

    #[test]
    fn derive_chacha20_secrets() {
        let secret = [
            0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42,
            0x27, 0x48, 0xad, 0x00, 0xa1, 0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0,
            0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b,
        ];

        let aead = Algorithm::ChaCha20_Poly1305;

        let mut pkt_key = [0; 32];
        let mut pkt_iv = [0; 12];
        let mut hdr_key = [0; 32];

        assert!(derive_pkt_key(aead, &secret, &mut pkt_key).is_ok());
        let expected_pkt_key = [
            0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1, 0xb2, 0x18, 0x20,
            0x94, 0xf6, 0x9c, 0xaa, 0x2e, 0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88,
            0x96, 0x0a, 0x7a, 0x98, 0x49, 0x79, 0xfb, 0x23, 0xe1, 0xc8,
        ];
        assert_eq!(&pkt_key, &expected_pkt_key);

        assert!(derive_pkt_iv(aead, &secret, &mut pkt_iv).is_ok());
        let expected_pkt_iv = [
            0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1,
            0x44,
        ];
        assert_eq!(&pkt_iv, &expected_pkt_iv);

        assert!(derive_hdr_key(aead, &secret, &mut hdr_key).is_ok());
        let expected_hdr_key = [
            0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2, 0x1f, 0x48, 0x89,
            0x17, 0xa4, 0xfc, 0x8f, 0x1b, 0x73, 0x57, 0x36, 0x85, 0x60, 0x85,
            0x97, 0xd0, 0xef, 0xcb, 0x07, 0x6b, 0x0a, 0xb7, 0xa7, 0xa4,
        ];
        assert_eq!(&hdr_key, &expected_hdr_key);

        let next_secret = derive_next_secret(aead, &secret).unwrap();
        let expected_secret = [
            0x12, 0x23, 0x50, 0x47, 0x55, 0x03, 0x6d, 0x55, 0x63, 0x42, 0xee,
            0x93, 0x61, 0xd2, 0x53, 0x42, 0x1a, 0x82, 0x6c, 0x9e, 0xcd, 0xf3,
            0xc7, 0x14, 0x86, 0x84, 0xb3, 0x6b, 0x71, 0x48, 0x81, 0xf9,
        ];
        assert_eq!(&next_secret, &expected_secret);
    }
}

mod boringssl;
pub use boringssl::*;
