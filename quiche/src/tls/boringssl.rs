use super::*;

use libc::c_long;

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
struct CRYPTO_BUFFER {
    _unused: c_void,
}

#[repr(C)]
pub(super) struct SSL_QUIC_METHOD {
    set_read_secret: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            level: crypto::Level,
            cipher: *const SSL_CIPHER,
            secret: *const u8,
            secret_len: usize,
        ) -> c_int,
    >,

    set_write_secret: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            level: crypto::Level,
            cipher: *const SSL_CIPHER,
            secret: *const u8,
            secret_len: usize,
        ) -> c_int,
    >,

    add_handshake_data: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            level: crypto::Level,
            data: *const u8,
            len: usize,
        ) -> c_int,
    >,

    flush_flight: Option<extern "C" fn(ssl: *mut SSL) -> c_int>,

    send_alert: Option<
        extern "C" fn(ssl: *mut SSL, level: crypto::Level, alert: u8) -> c_int,
    >,
}

#[cfg(test)]
#[repr(C)]
struct SSL_PRIVATE_KEY_METHOD {
    sign: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            out: *mut u8,
            out_len: *mut usize,
            max_out: usize,
            signature_algorithm: u16,
            r#in: *const u8,
            in_len: usize,
        ) -> ssl_private_key_result_t,
    >,

    decrypt: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            out: *mut u8,
            out_len: *mut usize,
            max_out: usize,
            r#in: *const u8,
            in_len: usize,
        ) -> ssl_private_key_result_t,
    >,

    complete: Option<
        unsafe extern "C" fn(
            ssl: *mut SSL,
            out: *mut u8,
            out_len: *mut usize,
            max_out: usize,
        ) -> ssl_private_key_result_t,
    >,
}

pub(super) static QUICHE_STREAM_METHOD: SSL_QUIC_METHOD = SSL_QUIC_METHOD {
    set_read_secret: Some(set_read_secret),
    set_write_secret: Some(set_write_secret),
    add_handshake_data: Some(add_handshake_data),
    flush_flight: Some(flush_flight),
    send_alert: Some(send_alert),
};

impl Context {
    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        // SAFETY: The live context is exclusively borrowed.
        unsafe {
            SSL_CTX_set_early_data_enabled(self.as_mut_ptr(), i32::from(enabled));
        }
    }
}

impl Handshake {
    pub fn set_quic_early_data_context(&mut self, context: &[u8]) -> Result<()> {
        // SAFETY: The live SSL is exclusively borrowed and BoringSSL
        // copies the supplied early-data context bytes.
        map_result(unsafe {
            SSL_set_quic_early_data_context(
                self.as_mut_ptr(),
                context.as_ptr(),
                context.len(),
            )
        })
    }

    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        // SAFETY: The live SSL is exclusively borrowed; its context is owned
        // by the SSL. The serialized session bytes are readable. On success,
        // SSL_set_session retains a reference; release the decoded reference.
        unsafe {
            let ctx = SSL_get_SSL_CTX(self.as_ptr());

            if ctx.is_null() {
                return Err(Error::TlsFail);
            }

            let session =
                SSL_SESSION_from_bytes(session.as_ptr(), session.len(), ctx);

            if session.is_null() {
                return Err(Error::TlsFail);
            }

            let rc = SSL_set_session(self.as_mut_ptr(), session);
            SSL_SESSION_free(session);

            map_result(rc)
        }
    }

    pub fn reset_early_data_reject(&mut self) {
        // SAFETY: The live SSL is exclusively borrowed and the operation
        // is called after the backend reports early-data rejection.
        unsafe { SSL_reset_early_data_reject(self.as_mut_ptr()) };
    }

    pub fn curve(&self) -> Option<String> {
        // SAFETY: SSL is live. BoringSSL's non-null curve names are
        // static NUL-terminated strings.
        let curve = unsafe {
            let curve_id = SSL_get_curve_id(self.as_ptr());
            if curve_id == 0 {
                return None;
            }

            let curve_name = SSL_get_curve_name(curve_id);
            if curve_name.is_null() {
                return None;
            }
            match ffi::CStr::from_ptr(curve_name).to_str() {
                Ok(v) => v,

                Err(_) => return None,
            }
        };

        Some(curve.to_string())
    }

    pub fn sigalg(&self) -> Option<String> {
        // SAFETY: SSL is live. BoringSSL's non-null algorithm names are
        // static NUL-terminated strings.
        let sigalg = unsafe {
            let sigalg_id = SSL_get_peer_signature_algorithm(self.as_ptr());
            if sigalg_id == 0 {
                return None;
            }

            let sigalg_name = SSL_get_signature_algorithm_name(sigalg_id, 1);
            if sigalg_name.is_null() {
                return None;
            }
            match ffi::CStr::from_ptr(sigalg_name).to_str() {
                Ok(v) => v,

                Err(_) => return None,
            }
        };

        Some(sigalg.to_string())
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        let chain = self.peer_certificates()?;
        (0..chain.len).map(|i| chain.get(i)).collect()
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        self.peer_certificates()?.get(0)
    }

    fn peer_certificates(&self) -> Option<PeerCertificates<'_>> {
        // SAFETY: self owns a live SSL object. The returned chain is
        // borrowed from that object and remains valid under a shared borrow.
        let chain = unsafe { SSL_get0_peer_certificates(self.as_ptr()) };
        let chain = NonNull::new(chain.cast_mut())?;
        // SAFETY: The non-null pointer identifies a live certificate stack.
        let len = unsafe { sk_num(chain.as_ptr()) };
        if len == 0 {
            return None;
        }
        Some(PeerCertificates {
            chain,
            len,
            _owner: self,
        })
    }

    // Only used for testing handling of failure during key signing.
    #[cfg(test)]
    pub fn set_failing_private_key_method(&mut self) {
        extern "C" fn failing_sign(
            _ssl: *mut SSL, _out: *mut u8, _out_len: *mut usize, _max_out: usize,
            _signature_algorithm: u16, _in: *const u8, _in_len: usize,
        ) -> ssl_private_key_result_t {
            ssl_private_key_result_t::ssl_private_key_failure
        }

        extern "C" fn failing_decrypt(
            _ssl: *mut SSL, _out: *mut u8, _out_len: *mut usize, _max_out: usize,
            _in: *const u8, _in_len: usize,
        ) -> ssl_private_key_result_t {
            ssl_private_key_result_t::ssl_private_key_failure
        }

        extern "C" fn failing_complete(
            _ssl: *mut SSL, _out: *mut u8, _out_len: *mut usize, _max_out: usize,
        ) -> ssl_private_key_result_t {
            ssl_private_key_result_t::ssl_private_key_failure
        }

        static QUICHE_PRIVATE_KEY_METHOD: SSL_PRIVATE_KEY_METHOD =
            SSL_PRIVATE_KEY_METHOD {
                decrypt: Some(failing_decrypt),
                sign: Some(failing_sign),
                complete: Some(failing_complete),
            };

        unsafe {
            SSL_set_private_key_method(
                self.as_mut_ptr(),
                &QUICHE_PRIVATE_KEY_METHOD,
            );
        }
    }

    pub fn is_in_early_data(&self) -> bool {
        unsafe { SSL_in_early_data(self.as_ptr()) == 1 }
    }

    pub fn early_data_reason(&self) -> u32 {
        let reuse_reason_status =
            unsafe { SSL_get_early_data_reason(self.as_ptr()) };
        reuse_reason_status.0
    }
}

/// A non-owning view of the certificates of one live handshake.
struct PeerCertificates<'a> {
    chain: NonNull<STACK_OF>,
    len: usize,
    _owner: &'a Handshake,
}

impl<'a> PeerCertificates<'a> {
    fn get(&self, index: usize) -> Option<&'a [u8]> {
        if index >= self.len {
            return None;
        }
        // SAFETY: The owner keeps the certificate stack alive and the index
        // is bounded by its length. Certificate buffers belong to the stack.
        let buffer = unsafe { sk_value(self.chain.as_ptr(), index) }
            .cast::<CRYPTO_BUFFER>();
        let buffer = NonNull::new(buffer)?;
        // SAFETY: buffer is a live CRYPTO_BUFFER borrowed from the stack.
        let (data, len) = unsafe {
            (
                CRYPTO_BUFFER_data(buffer.as_ptr()),
                CRYPTO_BUFFER_len(buffer.as_ptr()),
            )
        };
        if data.is_null() || len == 0 || len > isize::MAX as usize {
            return None;
        }
        // SAFETY: BoringSSL provides len readable bytes, owned by the SSL
        // session; the returned slice is bounded by the handshake borrow.
        Some(unsafe { slice::from_raw_parts(data, len) })
    }
}

/// Serialize a borrowed session into Rust-owned storage.
///
/// # Safety
/// session must point to a live `SSL_SESSION` for the duration of the call.
pub(super) unsafe fn get_session_bytes(
    session: NonNull<SSL_SESSION>,
) -> Result<Vec<u8>> {
    // SAFETY: The caller guarantees a live session. BoringSSL allocates the
    // returned buffer and transfers ownership on success.
    let session_bytes = unsafe {
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;

        if SSL_SESSION_to_bytes(session.as_ptr(), &raw mut out, &raw mut out_len) ==
            0
        {
            return Err(Error::TlsFail);
        }
        let encoded = if out_len == 0 {
            Ok(Vec::new())
        } else if out.is_null() || out_len > isize::MAX as usize {
            Err(Error::TlsFail)
        } else {
            Ok(slice::from_raw_parts(out, out_len).to_vec())
        };
        OPENSSL_free(out.cast());
        encoded?
    };

    Ok(session_bytes)
}
pub(super) const TLS_ERROR: c_int = 3;

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct ssl_early_data_reason_t(pub ::std::os::raw::c_uint);
extern "C" {
    // SSL_METHOD specific for boringssl.
    pub(super) fn SSL_CTX_set_tlsext_ticket_keys(
        ctx: *mut SSL_CTX, key: *const u8, key_len: usize,
    ) -> c_int;
    fn SSL_CTX_set_early_data_enabled(ctx: *mut SSL_CTX, enabled: i32);

    // BoringSSL exports `SSL_CTX_set1_groups_list` as a real symbol; on
    // OpenSSL it is a header macro. See `openssl_quictls.rs` for the
    // OpenSSL shim.
    pub(super) fn SSL_CTX_set1_groups_list(
        ctx: *mut SSL_CTX, groups: *const c_char,
    ) -> c_int;

    pub(super) fn SSL_CTX_set_session_cache_mode(
        ctx: *mut SSL_CTX, mode: c_int,
    ) -> c_int;
    pub(super) fn SSL_get_ex_new_index(
        argl: c_long, argp: *const c_void, unused: *const c_void,
        dup_unused: *const c_void, free_func: *const c_void,
    ) -> c_int;

    fn SSL_get_curve_id(ssl: *const SSL) -> u16;
    fn SSL_get_curve_name(curve: u16) -> *const c_char;

    fn SSL_get_peer_signature_algorithm(ssl: *const SSL) -> u16;
    fn SSL_get_signature_algorithm_name(
        sigalg: u16, include_curve: i32,
    ) -> *const c_char;

    fn SSL_get0_peer_certificates(ssl: *const SSL) -> *const STACK_OF;

    pub(super) fn SSL_set_min_proto_version(ssl: *mut SSL, version: u16)
        -> c_int;

    pub(super) fn SSL_set_max_proto_version(ssl: *mut SSL, version: u16)
        -> c_int;

    pub(super) fn SSL_set_tlsext_host_name(
        ssl: *mut SSL, name: *const c_char,
    ) -> c_int;

    fn SSL_set_quic_early_data_context(
        ssl: *mut SSL, context: *const u8, context_len: usize,
    ) -> c_int;

    #[cfg(test)]
    fn SSL_set_private_key_method(
        ssl: *mut SSL, key_method: *const SSL_PRIVATE_KEY_METHOD,
    );

    fn SSL_reset_early_data_reject(ssl: *mut SSL);

    fn SSL_in_early_data(ssl: *const SSL) -> c_int;

    fn SSL_get_early_data_reason(ssl: *const SSL) -> ssl_early_data_reason_t;

    fn SSL_SESSION_to_bytes(
        session: *const SSL_SESSION, out: *mut *mut u8, out_len: *mut usize,
    ) -> c_int;

    fn SSL_SESSION_from_bytes(
        input: *const u8, input_len: usize, ctx: *const SSL_CTX,
    ) -> *mut SSL_SESSION;

    // STACK_OF

    fn sk_num(stack: *const STACK_OF) -> usize;

    fn sk_value(stack: *const STACK_OF, idx: usize) -> *mut c_void;

    // CRYPTO_BUFFER

    fn CRYPTO_BUFFER_len(buffer: *const CRYPTO_BUFFER) -> usize;

    fn CRYPTO_BUFFER_data(buffer: *const CRYPTO_BUFFER) -> *const u8;
}
