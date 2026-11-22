use super::*;

use std::ptr::NonNull;

use libc::c_int;
use libc::c_uint;
use libc::c_void;

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
struct EVP_AEAD_CTX {
    _unused: c_void,
}

#[derive(Clone)]
#[repr(C)]
pub(crate) struct AES_KEY {
    rd_key: [u32; 4 * (14 + 1)],
    rounds: c_uint,
}

impl Algorithm {
    fn get_evp_aead(self) -> *const EVP_AEAD {
        // SAFETY: These parameterless BoringSSL functions return pointers to
        // static AEAD descriptors owned by the library.
        unsafe {
            match self {
                Self::AES128_GCM => EVP_aead_aes_128_gcm_tls13(),
                Self::AES256_GCM => EVP_aead_aes_256_gcm_tls13(),
                Self::ChaCha20_Poly1305 => EVP_aead_chacha20_poly1305(),
            }
        }
    }
}

pub(crate) struct PacketKey {
    alg: Algorithm,

    ctx: NonNull<EVP_AEAD_CTX>,

    nonce: [u8; MAX_NONCE_LEN],
}

impl PacketKey {
    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, _enc: u32,
    ) -> Result<Self> {
        let nonce = iv.try_into().map_err(|_| Error::CryptoFail)?;
        Ok(Self {
            alg,
            ctx: make_aead_ctx(alg, &key)?,
            nonce,
        })
    }

    pub fn from_secret(aead: Algorithm, secret: &[u8], enc: u32) -> Result<Self> {
        let key_len = aead.key_len();
        let nonce_len = aead.nonce_len();

        let mut key = vec![0; key_len];
        let mut iv = vec![0; nonce_len];

        derive_pkt_key(aead, secret, &mut key)?;
        derive_pkt_iv(aead, secret, &mut iv)?;

        let mut pkt_key = Self::new(aead, key, iv, enc)?;

        // Dummy seal operation to prime the AEAD context with the nonce mask.
        //
        // This is needed because BoringCrypto requires the first counter (i.e.
        // packet number) to be zero, which would not be the case for packet
        // number spaces after Initial as the same packet number sequence is
        // shared.
        let _ = pkt_key.seal_with_u64_counter(0, b"", &mut [0_u8; 16], 0, None);

        Ok(pkt_key)
    }

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        let tag_len = self.alg.tag_len();

        let mut out_len = match buf.len().checked_sub(tag_len) {
            Some(n) => n,
            None => return Err(Error::CryptoFail),
        };

        let max_out_len = out_len;

        let nonce = make_nonce(&self.nonce, counter);

        let ptr = buf.as_mut_ptr();
        // SAFETY: The context is live, the nonce has the required length,
        // all slices remain valid for the call, and BoringSSL explicitly
        // permits in-place decryption with identical input/output pointers.
        let rc = unsafe {
            EVP_AEAD_CTX_open(
                self.ctx.as_ptr(),  // ctx
                ptr,                // out
                &mut out_len,       // out_len
                max_out_len,        // max_out_len
                nonce[..].as_ptr(), // nonce
                nonce.len(),        // nonce_len
                ptr.cast_const(),   // inp
                buf.len(),          // in_len
                ad.as_ptr(),        // ad
                ad.len(),           // ad_len
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        Ok(out_len)
    }

    pub fn seal_with_u64_counter(
        &mut self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        let tag_len = self.alg.tag_len();

        let mut out_tag_len = tag_len;

        let (extra_in_ptr, extra_in_len) = match extra_in {
            Some(v) => (v.as_ptr(), v.len()),

            None => (std::ptr::null(), 0),
        };

        // Make sure all the outputs combined fit in the buffer.
        let tag_capacity =
            tag_len.checked_add(extra_in_len).ok_or(Error::CryptoFail)?;
        let (data, tag) =
            buf.split_at_mut_checked(in_len).ok_or(Error::CryptoFail)?;
        if tag.len() < tag_capacity {
            return Err(Error::CryptoFail);
        }

        let nonce = make_nonce(&self.nonce, counter);
        let ptr = data.as_mut_ptr();

        // SAFETY: The context and nonce are valid. The data and tag buffers
        // are disjoint and large enough for all output, and the primary
        // input/output pointers are identical as permitted by seal_scatter.
        // Any extra input and associated data are valid shared slices.
        let rc = unsafe {
            EVP_AEAD_CTX_seal_scatter(
                self.ctx.as_ptr(),  // ctx
                ptr,                // out
                tag.as_mut_ptr(),   // out_tag
                &mut out_tag_len,   // out_tag_len
                tag_capacity,       // max_out_tag_len
                nonce[..].as_ptr(), // nonce
                nonce.len(),        // nonce_len
                ptr.cast_const(),   // inp
                in_len,             // in_len
                extra_in_ptr,       // extra_in
                extra_in_len,       // extra_in_len
                ad.as_ptr(),        // ad
                ad.len(),           // ad_len
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        Ok(in_len + out_tag_len)
    }
}

// SAFETY: PacketKey uniquely owns its context; moving it transfers ownership
// without moving the BoringSSL allocation or borrowing thread-local state.
unsafe impl Send for PacketKey {}
// SAFETY: BoringSSL documents concurrent open/seal calls on the same context
// as safe. Rust additionally requires exclusive access for stateful sealing.
unsafe impl Sync for PacketKey {}

impl Drop for PacketKey {
    fn drop(&mut self) {
        // SAFETY: This context was allocated by EVP_AEAD_CTX_new and is
        // uniquely owned by self, so it is freed exactly once.
        unsafe { EVP_AEAD_CTX_free(self.ctx.as_ptr()) }
    }
}

#[derive(Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "Boxing the large variant would add unnecessary indirection"
)]
pub(crate) enum HeaderProtectionKey {
    Aes(AES_KEY),

    ChaCha([u8; 32]),
}

impl HeaderProtectionKey {
    pub fn new(alg: Algorithm, hp_key: Vec<u8>) -> Result<Self> {
        if hp_key.len() != alg.key_len() {
            return Err(Error::CryptoFail);
        }
        match alg {
            Algorithm::AES128_GCM | Algorithm::AES256_GCM => {
                let key_len_bits = if alg == Algorithm::AES128_GCM {
                    128
                } else {
                    256
                };
                // Initialize all round-key storage, including unused words for
                // AES-128, before passing it to the C key schedule function.
                let mut aes_key = AES_KEY {
                    rd_key: [0; 4 * (14 + 1)],
                    rounds: 0,
                };
                // SAFETY: The key length was checked against the selected
                // algorithm, and aes_key is writable storage matching AES_KEY.
                let rc = unsafe {
                    AES_set_encrypt_key(
                        hp_key.as_ptr(),
                        key_len_bits,
                        &mut aes_key,
                    )
                };
                if rc != 0 {
                    return Err(Error::CryptoFail);
                }
                Ok(Self::Aes(aes_key))
            },
            Algorithm::ChaCha20_Poly1305 => Ok(Self::ChaCha(
                hp_key.try_into().map_err(|_| Error::CryptoFail)?,
            )),
        }
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<HeaderProtectionMask> {
        let sample = sample.get(..16).ok_or(Error::CryptoFail)?;
        match self {
            Self::Aes(aes_key) => {
                let mut block = [0_u8; 16];

                // SAFETY: The sample and output contain a full AES block;
                // aes_key is initialized by AES_set_encrypt_key on success.
                unsafe {
                    AES_ecb_encrypt(
                        sample.as_ptr(),
                        block.as_mut_ptr(),
                        aes_key as _,
                        1,
                    )
                };

                let mut new_mask = HeaderProtectionMask::default();
                new_mask.copy_from_slice(&block[..HP_MASK_LEN]);
                Ok(new_mask)
            },

            Self::ChaCha(key) => {
                const PLAINTEXT: &[u8; HP_MASK_LEN] = &[0_u8; HP_MASK_LEN];

                let mut new_mask = HeaderProtectionMask::default();

                let counter = u32::from_le_bytes([
                    sample[0], sample[1], sample[2], sample[3],
                ]);

                // SAFETY: The key is exactly 32 bytes, the remaining sample
                // is a 12-byte nonce, and both data buffers are HP_MASK_LEN.
                unsafe {
                    CRYPTO_chacha_20(
                        new_mask.as_mut_ptr(),
                        PLAINTEXT.as_ptr(),
                        PLAINTEXT.len(),
                        key.as_ptr(),
                        sample[size_of::<u32>()..].as_ptr(),
                        counter,
                    );
                };

                Ok(new_mask)
            },
        }
    }
}

fn make_aead_ctx(alg: Algorithm, key: &[u8]) -> Result<NonNull<EVP_AEAD_CTX>> {
    if key.len() != alg.key_len() {
        return Err(Error::CryptoFail);
    }
    // SAFETY: The descriptor is static and key has the exact required
    // length. BoringSSL copies the key into its newly allocated context.
    let ctx = unsafe {
        EVP_AEAD_CTX_new(
            alg.get_evp_aead(),
            key.as_ptr(),
            key.len(),
            alg.tag_len(),
        )
    };

    NonNull::new(ctx).ok_or(Error::CryptoFail)
}

pub(crate) fn hkdf_extract(
    alg: Algorithm, out: &mut [u8], secret: &[u8], salt: &[u8],
) -> Result<()> {
    // HKDF_extract treats out_len as an output, not a capacity. It writes
    // the entire digest, so validate the buffer before calling it.
    let digest_len = match alg {
        Algorithm::AES256_GCM => 48,
        Algorithm::AES128_GCM | Algorithm::ChaCha20_Poly1305 => 32,
    };
    if out.len() < digest_len {
        return Err(Error::CryptoFail);
    }
    let mut out_len = 0;

    // SAFETY: The output has space for the selected digest. All input slices
    // and the digest descriptor remain valid throughout this call.
    let rc = unsafe {
        HKDF_extract(
            out.as_mut_ptr(),
            &mut out_len,
            alg.get_evp_digest(),
            secret.as_ptr(),
            secret.len(),
            salt.as_ptr(),
            salt.len(),
        )
    };

    if rc != 1 {
        return Err(Error::CryptoFail);
    }

    Ok(())
}

pub(crate) fn hkdf_expand(
    alg: Algorithm, out: &mut [u8], secret: &[u8], info: &[u8],
) -> Result<()> {
    // SAFETY: All slice pointers are valid for their associated lengths,
    // the output is writable and disjoint, and the digest is static.
    let rc = unsafe {
        HKDF_expand(
            out.as_mut_ptr(),
            out.len(),
            alg.get_evp_digest(),
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        )
    };

    if rc != 1 {
        return Err(Error::CryptoFail);
    }

    Ok(())
}

extern "C" {
    fn EVP_aead_aes_128_gcm_tls13() -> *const EVP_AEAD;

    fn EVP_aead_aes_256_gcm_tls13() -> *const EVP_AEAD;

    fn EVP_aead_chacha20_poly1305() -> *const EVP_AEAD;

    // HKDF
    fn HKDF_extract(
        out_key: *mut u8, out_len: *mut usize, digest: *const EVP_MD,
        secret: *const u8, secret_len: usize, salt: *const u8, salt_len: usize,
    ) -> c_int;

    fn HKDF_expand(
        out_key: *mut u8, out_len: usize, digest: *const EVP_MD, prk: *const u8,
        prk_len: usize, info: *const u8, info_len: usize,
    ) -> c_int;

    // EVP_AEAD_CTX
    fn EVP_AEAD_CTX_new(
        aead: *const EVP_AEAD, key: *const u8, key_len: usize, tag_len: usize,
    ) -> *mut EVP_AEAD_CTX;

    fn EVP_AEAD_CTX_free(ctx: *mut EVP_AEAD_CTX);

    fn EVP_AEAD_CTX_open(
        ctx: *const EVP_AEAD_CTX, out: *mut u8, out_len: *mut usize,
        max_out_len: usize, nonce: *const u8, nonce_len: usize, inp: *const u8,
        in_len: usize, ad: *const u8, ad_len: usize,
    ) -> c_int;

    fn EVP_AEAD_CTX_seal_scatter(
        ctx: *mut EVP_AEAD_CTX, out: *mut u8, out_tag: *mut u8,
        out_tag_len: *mut usize, max_out_tag_len: usize, nonce: *const u8,
        nonce_len: usize, inp: *const u8, in_len: usize, extra_in: *const u8,
        extra_in_len: usize, ad: *const u8, ad_len: usize,
    ) -> c_int;

    // AES
    fn AES_set_encrypt_key(
        key: *const u8, bits: c_uint, aeskey: *mut AES_KEY,
    ) -> c_int;

    fn AES_ecb_encrypt(
        inp: *const u8, out: *mut u8, key: *const AES_KEY, enc: c_int,
    );

    // ChaCha20
    fn CRYPTO_chacha_20(
        out: *mut u8, inp: *const u8, in_len: usize, key: *const u8,
        nonce: *const u8, counter: u32,
    );
}
