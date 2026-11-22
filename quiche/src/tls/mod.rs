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

use std::ffi;
use std::mem::ManuallyDrop;
use std::ptr;
use std::ptr::NonNull;
use std::slice;

use std::io::Write;

use std::sync::LazyLock;

use libc::c_char;
use libc::c_int;
use libc::c_uint;
use libc::c_void;

use crate::Error;
use crate::Result;

use crate::ConnectionError;

use crate::crypto;
use crate::packet;

const TLS1_3_VERSION: u16 = 0x0304;
const TLS_ALERT_ERROR: u64 = 0x100;
const INTERNAL_ERROR: u64 = 0x01;

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
struct SSL_METHOD {
    _unused: c_void,
}

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
struct SSL_CTX {
    _unused: c_void,
}

#[expect(
    clippy::upper_case_acronyms,
    reason = "SSL mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
struct SSL {
    _unused: c_void,
}

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
struct SSL_CIPHER {
    _unused: c_void,
}

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
struct SSL_SESSION {
    _unused: c_void,
}

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
struct X509_VERIFY_PARAM {
    _unused: c_void,
}

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
#[cfg(windows)]
struct X509_STORE {
    _unused: c_void,
}

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
struct X509_STORE_CTX {
    _unused: c_void,
}

#[repr(transparent)]
#[cfg(windows)]
struct X509 {
    _unused: c_void,
}

#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[repr(transparent)]
struct STACK_OF {
    _unused: c_void,
}

#[cfg(test)]
#[repr(C)]
#[expect(
    non_camel_case_types,
    reason = "Name mirrors the external C/BoringSSL ABI"
)]
#[expect(
    dead_code,
    reason = "test-only BoringSSL callback ABI mirror includes result variants not exercised by every test"
)]
enum ssl_private_key_result_t {
    ssl_private_key_success,
    ssl_private_key_retry,
    ssl_private_key_failure,
}

/// `BoringSSL` `ex_data` index for quiche connections.
static QUICHE_EX_DATA_INDEX: LazyLock<Option<c_int>> = LazyLock::new(|| {
    // SAFETY: Allocate one process-wide SSL ex_data index. There are no
    // allocation, duplication or destruction callbacks for this borrowed slot.
    let index = unsafe {
        SSL_get_ex_new_index(
            0,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    (index >= 0).then_some(index)
});

pub struct Context(NonNull<SSL_CTX>);

impl Context {
    // Note: some vendor-specific methods are implemented in the boringssl
    // submodule.
    pub fn new() -> Result<Self> {
        // SAFETY: TLS_method returns a static method descriptor. SSL_CTX_new
        // transfers ownership of a fresh context or returns null.
        let ctx_raw = NonNull::new(unsafe { SSL_CTX_new(TLS_method()) })
            .ok_or(Error::TlsFail)?;
        let mut ctx = Self(ctx_raw);
        ctx.set_session_callback();
        ctx.load_ca_certs()?;
        Ok(ctx)
    }

    #[cfg(feature = "boringssl-btls-crate")]
    pub fn from_boring(
        ssl_ctx_builder: btls::ssl::SslContextBuilder,
    ) -> Result<Self> {
        use foreign_types_shared::ForeignType;

        let ctx_raw = NonNull::new(ssl_ctx_builder.build().into_ptr().cast())
            .ok_or(Error::TlsFail)?;

        let mut ctx = Self(ctx_raw);
        ctx.set_session_callback();

        Ok(ctx)
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        // SAFETY: The live context is exclusively borrowed. SSL_new retains
        // its own context reference and returns a newly owned SSL or null.
        let ssl = NonNull::new(unsafe { SSL_new(self.as_mut_ptr()) })
            .ok_or(Error::TlsFail)?;
        Ok(Handshake::new(ssl))
    }

    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        let file = ffi::CString::new(file).map_err(|_| Error::TlsFail)?;
        // SAFETY: The context is live and exclusively borrowed; the non-null
        // path is a C string valid for the call.
        map_result(unsafe {
            SSL_CTX_load_verify_locations(
                self.as_mut_ptr(),
                file.as_ptr(),
                ptr::null(),
            )
        })
    }

    pub fn load_verify_locations_from_directory(
        &mut self, path: &str,
    ) -> Result<()> {
        let path = ffi::CString::new(path).map_err(|_| Error::TlsFail)?;
        // SAFETY: The context is live and exclusively borrowed; the non-null
        // path is a C string valid for the call.
        map_result(unsafe {
            SSL_CTX_load_verify_locations(
                self.as_mut_ptr(),
                ptr::null(),
                path.as_ptr(),
            )
        })
    }

    pub fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        let cstr = ffi::CString::new(file).map_err(|_| Error::TlsFail)?;
        // SAFETY: The live context is exclusively borrowed and the path is a
        // valid C string.
        map_result(unsafe {
            SSL_CTX_use_certificate_chain_file(self.as_mut_ptr(), cstr.as_ptr())
        })
    }

    pub fn use_privkey_file(&mut self, file: &str) -> Result<()> {
        let cstr = ffi::CString::new(file).map_err(|_| Error::TlsFail)?;
        // SAFETY: The live context is exclusively borrowed and the path is a
        // valid C string. Type 1 selects PEM.
        map_result(unsafe {
            SSL_CTX_use_PrivateKey_file(self.as_mut_ptr(), cstr.as_ptr(), 1)
        })
    }

    #[cfg(not(windows))]
    pub(super) fn load_ca_certs(&mut self) -> Result<()> {
        // SAFETY: The live context is exclusively borrowed.
        unsafe { map_result(SSL_CTX_set_default_verify_paths(self.as_mut_ptr())) }
    }

    #[cfg(windows)]
    pub(super) fn load_ca_certs(&mut self) -> Result<()> {
        use windows_sys::Win32::Security::Cryptography::CertCloseStore;
        use windows_sys::Win32::Security::Cryptography::CertEnumCertificatesInStore;
        use windows_sys::Win32::Security::Cryptography::CertOpenSystemStoreA;

        // SAFETY: The context is live and owns the returned X509_STORE.
        let ctx_store = unsafe { SSL_CTX_get_cert_store(self.as_mut_ptr()) };
        if ctx_store.is_null() {
            return Err(Error::TlsFail);
        }

        // SAFETY: The store name is NUL-terminated and static. The returned
        // non-null store is owned until CertCloseStore below.
        let sys_store =
            unsafe { CertOpenSystemStoreA(0, c"Root".as_ptr().cast()) };
        if sys_store.is_null() {
            return Err(Error::TlsFail);
        }

        // Each enumeration call consumes the previous certificate context.
        // No early exit between opening and closing the Windows store.
        let mut previous = ptr::null();
        loop {
            // SAFETY: The store is open; previous is null or is the owned
            // certificate context returned by the preceding enumeration.
            let current =
                unsafe { CertEnumCertificatesInStore(sys_store, previous) };
            if current.is_null() {
                break;
            }
            previous = current;

            // SAFETY: current identifies a live certificate context whose
            // encoded buffer remains readable until the next enumeration.
            let (mut input, length) = unsafe {
                (
                    (*current).pbCertEncoded.cast_const(),
                    (*current).cbCertEncoded,
                )
            };
            let Ok(length) = libc::c_long::try_from(length) else {
                continue;
            };
            if input.is_null() || length == 0 {
                continue;
            }

            // SAFETY: input contains length readable bytes and d2i_X509
            // advances the writable local cursor. A successful decode
            // transfers ownership of one certificate reference.
            let cert = unsafe { d2i_X509(ptr::null_mut(), &mut input, length) };
            if !cert.is_null() {
                // SAFETY: Both objects are live. The store retains a
                // reference on success, so release the decoded reference.
                unsafe {
                    X509_STORE_add_cert(ctx_store, cert);
                    X509_free(cert);
                }
            }
        }

        // SAFETY: All enumeration contexts have been consumed; release the
        // one owned Windows store reference.
        unsafe { CertCloseStore(sys_store, 0) };
        Ok(())
    }

    fn set_session_callback(&mut self) {
        // SAFETY: The live context is exclusively borrowed. The registered
        // callback has static lifetime and matches the C ABI.
        unsafe {
            // This is needed to enable the session callback on the client. On
            // the server it doesn't do anything.
            SSL_CTX_set_session_cache_mode(
                self.as_mut_ptr(),
                0x0001, // SSL_SESS_CACHE_CLIENT
            );

            SSL_CTX_sess_set_new_cb(self.as_mut_ptr(), Some(new_session));
        };
    }

    pub fn set_verify(&mut self, verify: bool) {
        // true  -> 0x01 SSL_VERIFY_PEER
        // false -> 0x00 SSL_VERIFY_NONE
        let mode = i32::from(verify);

        // The two modes above work for both BoringSSL and OpenSSL. This may
        // need adjustment if modes must be combined.
        // SAFETY: The live context is exclusively borrowed; mode is a valid
        // verification flag and no verification callback is installed.
        unsafe {
            SSL_CTX_set_verify(self.as_mut_ptr(), mode, None);
        }
    }

    pub fn enable_keylog(&mut self) {
        // SAFETY: The live context is exclusively borrowed. The callback
        // has static lifetime and matches the C ABI.
        unsafe {
            SSL_CTX_set_keylog_callback(self.as_mut_ptr(), Some(keylog));
        }
    }

    pub fn set_alpn(&mut self, v: &[&[u8]]) -> Result<()> {
        if v.is_empty() {
            return Err(Error::TlsFail);
        }

        // The ALPN extension's u16 length includes the u16 list length.
        const MAX_WIRE_LEN: usize = u16::MAX as usize - 2;
        let mut protos: Vec<u8> = Vec::new();

        for proto in v {
            let len = u8::try_from(proto.len()).map_err(|_| Error::TlsFail)?;
            if len == 0 || protos.len() + 1 + usize::from(len) > MAX_WIRE_LEN {
                return Err(Error::TlsFail);
            }
            protos.push(len);
            protos.extend_from_slice(proto);
        }

        // Configure ALPN for servers.
        // SAFETY: The context is live, the callback is static, and the
        // unused callback argument is null.
        unsafe {
            SSL_CTX_set_alpn_select_cb(
                self.as_mut_ptr(),
                Some(select_alpn),
                ptr::null_mut(),
            );
        }

        // Configure ALPN for clients.
        // SAFETY: The context is live and BoringSSL copies the validated
        // length-prefixed protocol list before returning.
        map_result_zero_is_success(unsafe {
            SSL_CTX_set_alpn_protos(
                self.as_mut_ptr(),
                protos.as_ptr(),
                protos.len(),
            )
        })
    }

    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        // SAFETY: The live context is exclusively borrowed; key provides
        // exactly key.len() readable bytes.
        map_result(unsafe {
            SSL_CTX_set_tlsext_ticket_keys(
                self.as_mut_ptr(),
                key.as_ptr(),
                key.len(),
            )
        })
    }

    pub fn set_curves_list(&mut self, curves: &str) -> Result<()> {
        // Note: BoringSSL exports `SSL_CTX_set1_groups_list` as a real
        // function; OpenSSL (and openssl-quictls) defines it as a macro
        // that expands to `SSL_CTX_ctrl`. Each backend provides a
        // `SSL_CTX_set1_groups_list` shim in the per-vendor module so this
        // call site can be backend-agnostic.
        let cstr = ffi::CString::new(curves).map_err(|_| Error::TlsFail)?;
        // SAFETY: The live context is exclusively borrowed and cstr is a valid
        // C string.
        map_result(unsafe {
            SSL_CTX_set1_groups_list(self.as_mut_ptr(), cstr.as_ptr())
        })
    }

    const fn as_mut_ptr(&mut self) -> *mut SSL_CTX {
        self.0.as_ptr()
    }
}

// SAFETY: Moving Context transfers its owned BoringSSL context reference.
unsafe impl Send for Context {}
// SAFETY: Mutating context configuration requires an exclusive Rust borrow.
// BoringSSL manages references held by the SSL objects created from it.
unsafe impl Sync for Context {}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: Drop releases precisely the owned context reference.
        unsafe { SSL_CTX_free(self.as_mut_ptr()) }
    }
}

enum HandshakeOperation {
    Handshake,
    PostHandshake,
}

pub struct Handshake {
    ptr: NonNull<SSL>,
    /// `SSL_process_quic_post_handshake` should be called when whenever
    /// `SSL_provide_quic_data` is called to process the provided data.
    provided_data_outstanding: bool,

    early_data_rejected: bool,
}

impl Handshake {
    // Note: some vendor-specific methods are implemented in the boringssl
    // submodule.
    /// # Safety
    /// The pointer must be null or a live, exclusively owned SSL reference
    /// transferred to this Handshake. It must not be freed by the caller.
    #[cfg(any(feature = "ffi", feature = "boringssl-btls-crate"))]
    pub unsafe fn from_ptr(ssl: *mut c_void) -> Result<Self> {
        let ptr = NonNull::new(ssl.cast()).ok_or(Error::TlsFail)?;

        Ok(Self::new(ptr))
    }

    const fn new(ptr: NonNull<SSL>) -> Self {
        Self {
            ptr,
            provided_data_outstanding: false,
            early_data_rejected: false,
        }
    }

    pub fn get_error(&self, ret_code: c_int) -> c_int {
        // SAFETY: The live SSL is borrowed, and ret_code is the preceding SSL
        // operation result.
        unsafe { SSL_get_error(self.as_ptr(), ret_code) }
    }

    pub fn init(&mut self, is_server: bool) -> Result<()> {
        self.set_state(is_server);

        self.set_min_proto_version(TLS1_3_VERSION)?;
        self.set_max_proto_version(TLS1_3_VERSION)?;

        self.set_quic_method()?;

        // TODO: the early data context should include transport parameters and
        // HTTP/3 SETTINGS in wire format.
        self.set_quic_early_data_context(b"quiche")?;

        self.set_quiet_shutdown(true);

        Ok(())
    }

    pub fn use_legacy_codepoint(&mut self, use_legacy: bool) {
        // SAFETY: The live SSL is exclusively borrowed.
        unsafe {
            SSL_set_quic_use_legacy_codepoint(
                self.as_mut_ptr(),
                c_int::from(use_legacy),
            );
        }
    }

    pub fn set_state(&mut self, is_server: bool) {
        // SAFETY: The live SSL is exclusively borrowed; both calls configure
        // its endpoint role before the handshake.
        unsafe {
            if is_server {
                SSL_set_accept_state(self.as_mut_ptr());
            } else {
                SSL_set_connect_state(self.as_mut_ptr());
            }
        }
    }

    pub fn set_quic_method(&mut self) -> Result<()> {
        // SAFETY: The live SSL is exclusively borrowed and the static method
        // table outlives it.
        map_result(unsafe {
            SSL_set_quic_method(
                self.as_mut_ptr(),
                &raw const QUICHE_STREAM_METHOD,
            )
        })
    }

    pub fn set_min_proto_version(&mut self, version: u16) -> Result<()> {
        // SAFETY: The live SSL is exclusively borrowed; BoringSSL validates the
        // version.
        map_result(unsafe {
            SSL_set_min_proto_version(self.as_mut_ptr(), version)
        })
    }

    pub fn set_max_proto_version(&mut self, version: u16) -> Result<()> {
        // SAFETY: The live SSL is exclusively borrowed; BoringSSL validates the
        // version.
        map_result(unsafe {
            SSL_set_max_proto_version(self.as_mut_ptr(), version)
        })
    }

    pub fn set_quiet_shutdown(&mut self, mode: bool) {
        // SAFETY: The live SSL is exclusively borrowed; mode is 0 or 1.
        unsafe { SSL_set_quiet_shutdown(self.as_mut_ptr(), i32::from(mode)) }
    }

    pub fn set_host_name(&mut self, name: &str) -> Result<()> {
        let cstr = ffi::CString::new(name).map_err(|_| Error::TlsFail)?;
        // SAFETY: The live SSL is exclusively borrowed and BoringSSL copies
        // the hostname from the NUL-terminated string.
        let rc =
            unsafe { SSL_set_tlsext_host_name(self.as_mut_ptr(), cstr.as_ptr()) };
        self.map_result_ssl(rc)?;

        // SAFETY: the SSL object is live and exclusively borrowed.
        let param = unsafe { SSL_get0_param(self.as_mut_ptr()) };
        if param.is_null() {
            return Err(Error::TlsFail);
        }

        // SAFETY: param is borrowed from self, and cstr is valid for the
        // specified length and the duration of the call.
        map_result(unsafe {
            X509_VERIFY_PARAM_set1_host(param, cstr.as_ptr(), name.len())
        })
    }

    pub fn set_quic_transport_params(
        &mut self, params: &crate::TransportParams, is_server: bool,
    ) -> Result<()> {
        let mut raw_params = [0; 128];

        let raw_params =
            crate::TransportParams::encode(params, is_server, &mut raw_params)?;

        // SAFETY: The live SSL is exclusively borrowed and BoringSSL copies
        // the encoded transport parameters.
        let rc = unsafe {
            SSL_set_quic_transport_params(
                self.as_mut_ptr(),
                raw_params.as_ptr(),
                raw_params.len(),
            )
        };
        self.map_result_ssl(rc)
    }

    pub fn quic_transport_params(&self) -> &[u8] {
        let mut ptr: *const u8 = ptr::null();
        let mut len: usize = 0;

        // SAFETY: The SSL is live and the two output slots are writable.
        unsafe {
            SSL_get_peer_quic_transport_params(
                self.as_ptr(),
                &raw mut ptr,
                &raw mut len,
            );
        }

        if ptr.is_null() || len == 0 || len > isize::MAX as usize {
            return &[];
        }

        // SAFETY: BoringSSL supplies len bytes valid for the SSL lifetime.
        unsafe { slice::from_raw_parts(ptr, len) }
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        let mut ptr: *const u8 = ptr::null();
        let mut len: u32 = 0;

        // SAFETY: The SSL is live and the two output slots are writable.
        unsafe {
            SSL_get0_alpn_selected(self.as_ptr(), &raw mut ptr, &raw mut len);
        }

        let len = len as usize;
        if ptr.is_null() || len == 0 || len > isize::MAX as usize {
            return &[];
        }

        // SAFETY: The selected ALPN name belongs to the SSL object, which
        // cannot be changed during this shared borrow.
        unsafe { slice::from_raw_parts(ptr, len) }
    }

    pub fn server_name(&self) -> Option<&str> {
        // SAFETY: The SSL is live. A non-null server name points to a
        // NUL-terminated string borrowed from it.
        let s = unsafe {
            let ptr = SSL_get_servername(
                self.as_ptr(),
                0, // TLSEXT_NAMETYPE_host_name
            );

            if ptr.is_null() {
                return None;
            }

            ffi::CStr::from_ptr(ptr)
        };

        s.to_str().ok()
    }

    pub fn provide_data(
        &mut self, level: crypto::Level, buf: &[u8],
    ) -> Result<()> {
        // SAFETY: The live SSL is exclusively borrowed; buf is readable
        // for its length and BoringSSL copies the handshake data.
        let rc = unsafe {
            SSL_provide_quic_data(
                self.as_mut_ptr(),
                level,
                buf.as_ptr(),
                buf.len(),
            )
        };
        self.map_result_ssl(rc)?;
        self.provided_data_outstanding = true;
        Ok(())
    }

    pub fn do_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        self.run_with_ex_data(ex_data, HandshakeOperation::Handshake)
    }

    pub fn process_post_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        if !self.provided_data_outstanding {
            return Ok(());
        }
        self.provided_data_outstanding = false;
        self.run_with_ex_data(ex_data, HandshakeOperation::PostHandshake)
    }

    fn run_with_ex_data(
        &mut self, ex_data: &mut ExData, operation: HandshakeOperation,
    ) -> Result<()> {
        let index = (*QUICHE_EX_DATA_INDEX).ok_or(Error::TlsFail)?;

        // SAFETY: self owns a live SSL object. The reserved index may only
        // contain a pointer installed by this method while a TLS operation
        // is in progress. Reject recursive installation.
        if !unsafe { SSL_get_ex_data(self.as_ptr(), index) }.is_null() {
            return Err(Error::TlsFail);
        }

        let data = ptr::from_mut(ex_data).cast::<c_void>();
        // SAFETY: ex_data remains exclusively borrowed until the synchronous
        // TLS call finishes. The slot has no C destructor and is cleared
        // before ex_data is used again or this method returns.
        map_result(unsafe { SSL_set_ex_data(self.as_mut_ptr(), index, data) })?;

        // SAFETY: The live SSL is exclusively borrowed. Both operations
        // synchronously invoke callbacks with the installed ExData pointer.
        let rc = unsafe {
            match operation {
                HandshakeOperation::Handshake =>
                    SSL_do_handshake(self.as_mut_ptr()),
                HandshakeOperation::PostHandshake =>
                    SSL_process_quic_post_handshake(self.as_mut_ptr()),
            }
        };

        // Snapshot the failing SSL operation's error before making another
        // BoringSSL call, which may interact with its thread-local error queue.
        let error = (rc != 1).then(|| self.get_error(rc));

        // SAFETY: The slot already exists, so BoringSSL replaces its value
        // without allocating. It must not retain the borrowed pointer after
        // the operation ends. If this invariant ever fails, abort rather
        // than return with a dangling pointer in the SSL object.
        if unsafe { SSL_set_ex_data(self.as_mut_ptr(), index, ptr::null_mut()) } !=
            1
        {
            std::process::abort();
        }

        let Some(error) = error else {
            return Ok(());
        };
        if error == 1 && ex_data.local_error.is_none() {
            *ex_data.local_error = Some(ConnectionError {
                is_app: false,
                error_code: INTERNAL_ERROR,
                reason: Vec::new(),
            });
        }
        self.map_ssl_error(error)
    }

    pub fn write_level(&self) -> crypto::Level {
        // SAFETY: The live SSL is borrowed and initialized with the QUIC
        // method.
        unsafe { SSL_quic_write_level(self.as_ptr()) }
    }

    pub fn cipher(&self) -> Option<crypto::Algorithm> {
        // SAFETY: self owns a live SSL object. The returned cipher is a
        // static descriptor (or null if one has not been selected).
        let cipher = unsafe { SSL_get_current_cipher(self.as_ptr()) };
        // SAFETY: the pointer came from SSL_get_current_cipher; null is
        // checked by get_cipher_from_ptr.
        unsafe { get_cipher_from_ptr(cipher) }.ok()
    }

    #[cfg(test)]
    pub fn set_options(&mut self, opts: u32) {
        unsafe {
            SSL_set_options(self.as_mut_ptr(), opts);
        }
    }

    pub fn is_completed(&self) -> bool {
        // SAFETY: The live SSL is borrowed.
        unsafe { SSL_in_init(self.as_ptr()) == 0 }
    }

    pub fn is_resumed(&self) -> bool {
        // SAFETY: The live SSL is borrowed.
        unsafe { SSL_session_reused(self.as_ptr()) == 1 }
    }

    pub fn clear(&mut self) -> Result<()> {
        // SAFETY: The live SSL is exclusively borrowed.
        let rc = unsafe { SSL_clear(self.as_mut_ptr()) };
        self.map_result_ssl(rc)?;
        self.early_data_rejected = false;
        self.provided_data_outstanding = false;
        Ok(())
    }

    pub const fn early_data_rejected(&self) -> bool {
        self.early_data_rejected
    }

    const fn as_ptr(&self) -> *const SSL {
        self.ptr.as_ptr()
    }

    const fn as_mut_ptr(&mut self) -> *mut SSL {
        self.ptr.as_ptr()
    }

    fn map_result_ssl(&mut self, result: c_int) -> Result<()> {
        if result == 1 {
            return Ok(());
        }
        let error = self.get_error(result);
        self.map_ssl_error(error)
    }

    fn map_ssl_error(&mut self, error: c_int) -> Result<()> {
        match error {
            // SSL_ERROR_SSL
            1 => {
                log_ssl_error();
                Err(Error::TlsFail)
            },
            // SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE,
            // SSL_ERROR_WANT_X509_LOOKUP, SSL_ERROR_PENDING_SESSION,
            // SSL_ERROR_PENDING_CERTIFICATE,
            // SSL_ERROR_WANT_PRIVATE_KEY_OPERATION, SSL_ERROR_PENDING_TICKET,
            // SSL_ERROR_WANT_CERTIFICATE_VERIFY
            2..=4 | 11..=14 | 16 => Err(Error::Done),
            // SSL_ERROR_EARLY_DATA_REJECTED
            15 => {
                self.reset_early_data_reject();
                self.early_data_rejected = true;
                Err(Error::Done)
            },
            _ => Err(Error::TlsFail),
        }
    }

    #[cfg(feature = "boringssl-btls-crate")]
    pub(crate) fn ssl_mut(&mut self) -> &mut btls::ssl::SslRef {
        use foreign_types_shared::ForeignTypeRef;

        // SAFETY: This is the same BoringSSL SSL type used by boring.
        // The reference borrows the owned SSL exclusively without transferring
        // it.
        unsafe { btls::ssl::SslRef::from_ptr_mut(self.as_mut_ptr().cast()) }
    }
}

// SAFETY: Handshake owns the SSL reference; moving transfers ownership.
// The temporary callback slot cannot outlive the exclusive TLS operation.
unsafe impl Send for Handshake {}
// SAFETY: Shared access exposes only read-only SSL queries and borrowed
// immutable data. State-changing TLS operations require an exclusive borrow.
unsafe impl Sync for Handshake {}

impl Drop for Handshake {
    fn drop(&mut self) {
        // SAFETY: Drop releases precisely the owned SSL reference.
        unsafe { SSL_free(self.as_mut_ptr()) }
    }
}

pub struct ExData<'a> {
    pub application_protos: &'a Vec<Vec<u8>>,

    pub crypto_ctx: &'a mut [packet::CryptoContext; packet::Epoch::count()],

    pub session: &'a mut Option<Vec<u8>>,

    pub local_error: &'a mut Option<ConnectionError>,

    pub keylog: Option<&'a mut Box<dyn Write + Send + Sync>>,

    pub trace_id: &'a str,

    pub local_transport_params: crate::TransportParams,

    pub recovery_config: crate::recovery::RecoveryConfig,

    pub tx_cap_factor: f64,

    /// PMTUD configuration: (enable, `max_probes`)
    pub pmtud: Option<(bool, u8)>,

    pub is_server: bool,
}

impl ExData<'_> {
    /// # Safety
    /// A non-null SSL pointer must be live. The returned mutable borrow is
    /// valid only for the current synchronous TLS callback, and no other
    /// callback or Rust code may access the installed `ExData` concurrently.
    unsafe fn from_ssl_ptr<'callback>(
        ptr: *const SSL,
    ) -> Option<&'callback mut Self> {
        let index = (*QUICHE_EX_DATA_INDEX)?;
        if ptr.is_null() {
            return None;
        }
        // SAFETY: The caller guarantees a live SSL and exclusive callback
        // access. run_with_ex_data installs only ExData at this index, and
        // clears the slot before the borrowed value goes out of scope.
        unsafe { SSL_get_ex_data(ptr, index).cast::<Self>().as_mut() }
    }

    #[cfg(feature = "boringssl-btls-crate")]
    pub fn from_ssl_ref(ssl: &mut btls::ssl::SslRef) -> Option<&mut Self> {
        use btls::ex_data::Index;

        let index = (*QUICHE_EX_DATA_INDEX)?;
        // SAFETY: The reserved index is private to this module and only
        // run_with_ex_data installs a value, always of type ExData.
        let idx: Index<btls::ssl::Ssl, ExData> =
            unsafe { Index::from_raw(index) };

        ssl.ex_data_mut(idx)
    }
}

/// # Safety
/// A non-null cipher must point to a live `BoringSSL` cipher descriptor.
unsafe fn get_cipher_from_ptr(
    cipher: *const SSL_CIPHER,
) -> Result<crypto::Algorithm> {
    if cipher.is_null() {
        return Err(Error::TlsFail);
    }
    // SAFETY: The caller guarantees the validity of the non-null pointer.
    let cipher_id = unsafe { SSL_CIPHER_get_id(cipher) };

    let alg = match cipher_id {
        0x0300_1301 => crypto::Algorithm::AES128_GCM,
        0x0300_1302 => crypto::Algorithm::AES256_GCM,
        0x0300_1303 => crypto::Algorithm::ChaCha20_Poly1305,
        _ => return Err(Error::TlsFail),
    };

    Ok(alg)
}

unsafe extern "C" fn set_read_secret(
    ssl: *mut SSL, level: crypto::Level, cipher: *const SSL_CIPHER,
    secret: *const u8, secret_len: usize,
) -> c_int {
    // SAFETY: BoringSSL supplies live callback arguments.
    unsafe { install_secret::<true>(ssl, level, cipher, secret, secret_len) }
}

unsafe extern "C" fn set_write_secret(
    ssl: *mut SSL, level: crypto::Level, cipher: *const SSL_CIPHER,
    secret: *const u8, secret_len: usize,
) -> c_int {
    // SAFETY: BoringSSL supplies live callback arguments.
    unsafe { install_secret::<false>(ssl, level, cipher, secret, secret_len) }
}

/// # Safety
/// Called synchronously by `BoringSSL` with a live SSL, valid cipher descriptor
/// and a secret buffer readable for `secret_len` bytes.
unsafe fn install_secret<const READ: bool>(
    ssl: *mut SSL, level: crypto::Level, cipher: *const SSL_CIPHER,
    secret: *const u8, secret_len: usize,
) -> c_int {
    // SAFETY: the caller guarantees exclusive synchronous callback access.
    let Some(ex_data) = (unsafe { ExData::from_ssl_ptr(ssl) }) else {
        return 0;
    };

    trace!(
        "{} set {} secret lvl={level:?}",
        ex_data.trace_id,
        if READ { "read" } else { "write" }
    );
    // SAFETY: the cipher descriptor is supplied by BoringSSL.
    let Ok(aead) = (unsafe { get_cipher_from_ptr(cipher) }) else {
        return 0;
    };

    // Early data is read by the server and written by the client.
    if level == crypto::Level::ZeroRTT && READ != ex_data.is_server {
        return 1;
    }

    if secret.is_null() || secret_len == 0 || secret_len > isize::MAX as usize {
        return 0;
    }
    // SAFETY: the callback borrows this buffer for its duration.
    let secret = unsafe { slice::from_raw_parts(secret, secret_len) };
    let epoch = match level {
        crypto::Level::Initial => packet::Epoch::Initial,
        crypto::Level::Handshake => packet::Epoch::Handshake,
        crypto::Level::ZeroRTT | crypto::Level::OneRTT =>
            packet::Epoch::Application,
    };
    let space = &mut ex_data.crypto_ctx[epoch];

    if READ {
        let Ok(open) = crypto::Open::from_secret(
            aead,
            secret,
            crypto::CounterInitialization::Prime,
        ) else {
            return 0;
        };
        if level == crypto::Level::ZeroRTT {
            space.crypto_0rtt_open = Some(open);
        } else {
            space.crypto_open = Some(open);
        }
    } else {
        let Ok(seal) = crypto::Seal::from_secret(
            aead,
            secret,
            crypto::CounterInitialization::Prime,
        ) else {
            return 0;
        };
        space.crypto_seal = Some(seal);
    }
    1
}

extern "C" fn add_handshake_data(
    ssl: *mut SSL, level: crypto::Level, data: *const u8, len: usize,
) -> c_int {
    // SAFETY: BoringSSL invokes this callback synchronously on its live SSL
    // object; the installed callback state is exclusively borrowed here.
    let Some(ex_data) = (unsafe { ExData::from_ssl_ptr(ssl) }) else {
        return 0;
    };

    trace!("{} write message lvl={level:?} len={len}", ex_data.trace_id);

    if len == 0 {
        return 1;
    }
    if data.is_null() || len > isize::MAX as usize {
        return 0;
    }
    // SAFETY: BoringSSL supplies len readable bytes for this callback.
    let buf = unsafe { slice::from_raw_parts(data, len) };

    let space = match level {
        crypto::Level::Initial => &mut ex_data.crypto_ctx[packet::Epoch::Initial],
        // TLS handshake messages are never supplied at the early-data level.
        crypto::Level::ZeroRTT => return 0,
        crypto::Level::Handshake =>
            &mut ex_data.crypto_ctx[packet::Epoch::Handshake],
        crypto::Level::OneRTT =>
            &mut ex_data.crypto_ctx[packet::Epoch::Application],
    };

    if space.crypto_stream.send.write(buf, false).is_err() {
        return 0;
    }

    1
}

const extern "C" fn flush_flight(_ssl: *mut SSL) -> c_int {
    // We don't really need to anything here since the output packets are
    // generated separately, when conn.send() is called.

    1
}

extern "C" fn send_alert(
    ssl: *mut SSL, level: crypto::Level, alert: u8,
) -> c_int {
    // SAFETY: BoringSSL invokes this callback synchronously on its live SSL
    // object; the installed callback state is exclusively borrowed here.
    let Some(ex_data) = (unsafe { ExData::from_ssl_ptr(ssl) }) else {
        return 0;
    };

    trace!(
        "{} send alert lvl={level:?} alert={alert:x}",
        ex_data.trace_id
    );

    let error: u64 = TLS_ALERT_ERROR + u64::from(alert);
    *ex_data.local_error = Some(ConnectionError {
        is_app: false,
        error_code: error,
        reason: Vec::new(),
    });

    1
}

extern "C" fn keylog(ssl: *const SSL, line: *const c_char) {
    // SAFETY: BoringSSL invokes this callback synchronously on its live SSL
    // object; the installed callback state is exclusively borrowed here.
    let Some(ex_data) = (unsafe { ExData::from_ssl_ptr(ssl) }) else {
        return;
    };

    if line.is_null() {
        return;
    }
    if let Some(keylog) = &mut ex_data.keylog {
        // SAFETY: BoringSSL passes a NUL-terminated string for this callback.
        let data = unsafe { ffi::CStr::from_ptr(line).to_bytes() };

        let mut full_line = Vec::with_capacity(data.len() + 1);
        full_line.extend_from_slice(data);
        full_line.push(b'\n');

        keylog.write_all(&full_line[..]).ok();
        keylog.flush().ok();
    }
}

// Select the first offered protocol that is supported locally. Returning
// the peer's actual entry avoids borrowing the mutable callback configuration
// across the FFI boundary.
fn select_offered_alpn<'a>(
    mut offered: &'a [u8], supported: &[Vec<u8>],
) -> Option<&'a [u8]> {
    let mut selected = None;
    while let Some((&len, rest)) = offered.split_first() {
        let len = usize::from(len);
        if len == 0 {
            return None;
        }
        let (proto, remaining) = rest.split_at_checked(len)?;
        if selected.is_none() &&
            supported.iter().any(|expected| expected == proto)
        {
            selected = Some(proto);
        }
        offered = remaining;
    }
    selected
}

extern "C" fn select_alpn(
    ssl: *mut SSL, out: *mut *const u8, out_len: *mut u8, inp: *const u8,
    in_len: c_uint, _arg: *mut c_void,
) -> c_int {
    // SAFETY: BoringSSL invokes this callback synchronously on its live SSL
    // object; the installed callback state is exclusively borrowed here.
    let Some(ex_data) = (unsafe { ExData::from_ssl_ptr(ssl) }) else {
        return TLS_ERROR;
    };
    let Ok(len) = usize::try_from(in_len) else {
        return TLS_ERROR;
    };
    if inp.is_null() ||
        out.is_null() ||
        out_len.is_null() ||
        len == 0 ||
        len > isize::MAX as usize
    {
        return TLS_ERROR;
    }
    // SAFETY: BoringSSL supplies the offered list, readable for len bytes.
    let input = unsafe { slice::from_raw_parts(inp, len) };
    let Some(proto) = select_offered_alpn(input, ex_data.application_protos)
    else {
        return TLS_ERROR;
    };
    let Ok(proto_len) = u8::try_from(proto.len()) else {
        return TLS_ERROR;
    };
    // SAFETY: BoringSSL supplies writable output slots and explicitly
    // permits returning a pointer to the matching entry in the input list.
    unsafe {
        *out = proto.as_ptr();
        *out_len = proto_len;
    }
    0 // SSL_TLSEXT_ERR_OK
}

extern "C" fn new_session(ssl: *mut SSL, session: *mut SSL_SESSION) -> c_int {
    let Some(ssl) = NonNull::new(ssl) else {
        return 0;
    };

    // SAFETY: BoringSSL invokes this callback synchronously on its live SSL
    // object; the installed callback state is exclusively borrowed here.
    let Some(ex_data) = (unsafe { ExData::from_ssl_ptr(ssl.as_ptr()) }) else {
        return 0;
    };

    // This callback receives a borrowed `SSL*`, so the temporary `Handshake`
    // must not free it on any return path.
    let handshake = ManuallyDrop::new(Handshake::new(ssl));
    let peer_params = handshake.quic_transport_params();

    // Serialize session object into buffer.
    let Some(session) = NonNull::new(session) else {
        return 0;
    };
    // SAFETY: BoringSSL supplies a live, borrowed session to this callback.
    let Ok(session_bytes) = (unsafe { get_session_bytes(session) }) else {
        return 0;
    };

    let Some(capacity) = session_bytes
        .len()
        .checked_add(peer_params.len())
        .and_then(|len| len.checked_add(16))
    else {
        return 0;
    };
    let mut buffer = Vec::new();
    if buffer.try_reserve_exact(capacity).is_err() {
        return 0;
    }
    buffer.extend_from_slice(&(session_bytes.len() as u64).to_be_bytes());
    buffer.extend_from_slice(&session_bytes);
    buffer.extend_from_slice(&(peer_params.len() as u64).to_be_bytes());
    buffer.extend_from_slice(peer_params);

    *ex_data.session = Some(buffer);

    0
}

pub const fn map_result(bssl_result: c_int) -> Result<()> {
    match bssl_result {
        1 => Ok(()),
        _ => Err(Error::TlsFail),
    }
}

pub const fn map_result_zero_is_success(bssl_result: c_int) -> Result<()> {
    match bssl_result {
        0 => Ok(()),
        _ => Err(Error::TlsFail),
    }
}

fn log_ssl_error() {
    let mut err = [0u8; 1024];

    // SAFETY: The error queue is thread-local. The output buffer is writable
    // for its entire length and ERR_error_string_n bounds its writes.
    unsafe {
        let e = ERR_peek_error();
        ERR_error_string_n(e, err.as_mut_ptr().cast(), err.len());
    }

    if let Ok(message) = ffi::CStr::from_bytes_until_nul(&err) {
        trace!("{}", message.to_string_lossy());
    }
}

extern "C" {
    // Note: some vendor-specific methods are implemented in the boringssl
    // submodule.

    // SSL_METHOD
    fn TLS_method() -> *const SSL_METHOD;

    // SSL_CTX
    fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
    fn SSL_CTX_free(ctx: *mut SSL_CTX);

    fn SSL_CTX_use_certificate_chain_file(
        ctx: *mut SSL_CTX, file: *const c_char,
    ) -> c_int;

    fn SSL_CTX_use_PrivateKey_file(
        ctx: *mut SSL_CTX, file: *const c_char, ty: c_int,
    ) -> c_int;

    fn SSL_CTX_load_verify_locations(
        ctx: *mut SSL_CTX, file: *const c_char, path: *const c_char,
    ) -> c_int;

    #[cfg(not(windows))]
    fn SSL_CTX_set_default_verify_paths(ctx: *mut SSL_CTX) -> c_int;

    #[cfg(windows)]
    fn SSL_CTX_get_cert_store(ctx: *mut SSL_CTX) -> *mut X509_STORE;

    fn SSL_CTX_set_verify(
        ctx: *mut SSL_CTX, mode: c_int,
        cb: Option<
            unsafe extern "C" fn(
                ok: c_int,
                store_ctx: *mut X509_STORE_CTX,
            ) -> c_int,
        >,
    );

    fn SSL_CTX_set_keylog_callback(
        ctx: *mut SSL_CTX,
        cb: Option<unsafe extern "C" fn(ssl: *const SSL, line: *const c_char)>,
    );

    fn SSL_CTX_set_alpn_protos(
        ctx: *mut SSL_CTX, protos: *const u8, protos_len: usize,
    ) -> c_int;

    fn SSL_CTX_set_alpn_select_cb(
        ctx: *mut SSL_CTX,
        cb: Option<
            unsafe extern "C" fn(
                ssl: *mut SSL,
                out: *mut *const u8,
                out_len: *mut u8,
                inp: *const u8,
                in_len: c_uint,
                arg: *mut c_void,
            ) -> c_int,
        >,
        arg: *mut c_void,
    );

    fn SSL_CTX_sess_set_new_cb(
        ctx: *mut SSL_CTX,
        cb: Option<
            unsafe extern "C" fn(
                ssl: *mut SSL,
                session: *mut SSL_SESSION,
            ) -> c_int,
        >,
    );

    fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;

    fn SSL_get_error(ssl: *const SSL, ret_code: c_int) -> c_int;

    fn SSL_set_accept_state(ssl: *mut SSL);
    fn SSL_set_connect_state(ssl: *mut SSL);

    fn SSL_get0_param(ssl: *mut SSL) -> *mut X509_VERIFY_PARAM;

    fn SSL_set_ex_data(ssl: *mut SSL, idx: c_int, ptr: *mut c_void) -> c_int;
    fn SSL_get_ex_data(ssl: *const SSL, idx: c_int) -> *mut c_void;

    fn SSL_get_current_cipher(ssl: *const SSL) -> *const SSL_CIPHER;

    fn SSL_set_session(ssl: *mut SSL, session: *mut SSL_SESSION) -> c_int;

    fn SSL_get_SSL_CTX(ssl: *const SSL) -> *mut SSL_CTX;

    fn SSL_set_quiet_shutdown(ssl: *mut SSL, mode: c_int);

    fn SSL_set_quic_transport_params(
        ssl: *mut SSL, params: *const u8, params_len: usize,
    ) -> c_int;

    fn SSL_set_quic_method(
        ssl: *mut SSL, quic_method: *const SSL_QUIC_METHOD,
    ) -> c_int;

    fn SSL_set_quic_use_legacy_codepoint(ssl: *mut SSL, use_legacy: c_int);

    #[cfg(test)]
    fn SSL_set_options(ssl: *mut SSL, opts: u32) -> u32;

    fn SSL_get_peer_quic_transport_params(
        ssl: *const SSL, out_params: *mut *const u8, out_params_len: *mut usize,
    );

    fn SSL_get0_alpn_selected(
        ssl: *const SSL, out: *mut *const u8, out_len: *mut u32,
    );

    fn SSL_get_servername(ssl: *const SSL, ty: c_int) -> *const c_char;

    fn SSL_provide_quic_data(
        ssl: *mut SSL, level: crypto::Level, data: *const u8, len: usize,
    ) -> c_int;

    fn SSL_process_quic_post_handshake(ssl: *mut SSL) -> c_int;

    fn SSL_do_handshake(ssl: *mut SSL) -> c_int;

    fn SSL_quic_write_level(ssl: *const SSL) -> crypto::Level;

    fn SSL_session_reused(ssl: *const SSL) -> c_int;

    fn SSL_in_init(ssl: *const SSL) -> c_int;

    fn SSL_clear(ssl: *mut SSL) -> c_int;

    fn SSL_free(ssl: *mut SSL);

    // SSL_CIPHER
    fn SSL_CIPHER_get_id(cipher: *const SSL_CIPHER) -> c_uint;

    // SSL_SESSION

    fn SSL_SESSION_free(session: *mut SSL_SESSION);

    // X509_VERIFY_PARAM
    fn X509_VERIFY_PARAM_set1_host(
        param: *mut X509_VERIFY_PARAM, name: *const c_char, namelen: usize,
    ) -> c_int;

    // X509_STORE
    #[cfg(windows)]
    fn X509_STORE_add_cert(ctx: *mut X509_STORE, x: *mut X509) -> c_int;

    // X509
    #[cfg(windows)]
    fn X509_free(x: *mut X509);
    #[cfg(windows)]
    fn d2i_X509(
        px: *mut *mut X509, input: *mut *const u8, len: libc::c_long,
    ) -> *mut X509;

    // ERR
    fn ERR_peek_error() -> c_uint;

    fn ERR_error_string_n(err: c_uint, buf: *mut c_char, len: usize);

    // OPENSSL
    fn OPENSSL_free(ptr: *mut c_void);

}

mod boringssl;
use boringssl::*;

#[cfg(test)]
mod tests {
    use super::select_offered_alpn;

    #[test]
    fn offered_alpn_selection_preserves_peer_order_and_validates_entire_list() {
        let supported = vec![b"h3".to_vec(), b"hq".to_vec()];
        let offered = b"\x02hq\x02h3";
        let selected = select_offered_alpn(offered, &supported).unwrap();
        assert_eq!(selected, b"hq");
        assert_eq!(selected.as_ptr(), offered[1..].as_ptr());
        for malformed in [
            b"".as_slice(),
            b"\x00",
            b"\x03h3",
            b"\x02h3\x00",
            b"\x02h3\x03hq",
            b"\x02xx",
        ] {
            assert_eq!(select_offered_alpn(malformed, &supported), None);
        }
    }
}
