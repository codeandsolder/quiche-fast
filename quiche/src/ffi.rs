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
use std::mem::MaybeUninit;
use std::ptr;
use std::slice;
use std::sync::atomic;

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;

#[cfg(unix)]
use std::os::unix::io::FromRawFd;

use libc::c_char;
use libc::c_int;
use libc::c_void;
use libc::size_t;
use libc::sockaddr;
use libc::ssize_t;
use libc::timespec;

#[cfg(not(windows))]
use libc::AF_INET;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::AF_INET;

#[cfg(not(windows))]
use libc::AF_INET6;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::AF_INET6;

#[cfg(not(windows))]
use libc::in_addr;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::IN_ADDR as in_addr;

#[cfg(not(windows))]
use libc::in6_addr;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::IN6_ADDR as in6_addr;

#[cfg(not(windows))]
use libc::sa_family_t;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::ADDRESS_FAMILY as sa_family_t;

#[cfg(not(windows))]
use libc::sockaddr_in;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN as sockaddr_in;

#[cfg(not(windows))]
use libc::sockaddr_in6;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6 as sockaddr_in6;

#[cfg(not(windows))]
use libc::sockaddr_storage;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::SOCKADDR_STORAGE as sockaddr_storage;

#[cfg(windows)]
use libc::c_int as socklen_t;
#[cfg(not(windows))]
use libc::socklen_t;

#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::IN6_ADDR_0;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::IN_ADDR_0;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6_0;

use crate::*;

const FFI_ERR_INVALID_ARGUMENT: i16 = -24;

/// Borrow an initialized C object, rejecting null and misaligned pointers.
///
/// # Safety
/// A non-null, aligned pointer must identify a live initialized T for the
/// returned lifetime. The C caller must not mutate it during that borrow.
pub(super) unsafe fn ffi_ptr_ref<'a, T>(ptr: *const T) -> Option<&'a T> {
    if ptr.is_null() || !ptr.is_aligned() {
        return None;
    }

    // SAFETY: null and alignment are checked above. Allocation validity and
    // lifetime remain part of the C caller contract.
    Some(unsafe { &*ptr })
}

/// Exclusively borrow an initialized C object, rejecting null and misalignment.
///
/// # Safety
/// A non-null, aligned pointer must identify a live initialized T, with
/// exclusive access for the returned lifetime.
pub(super) unsafe fn ffi_ptr_mut<'a, T>(ptr: *mut T) -> Option<&'a mut T> {
    if ptr.is_null() || !ptr.is_aligned() {
        return None;
    }

    // SAFETY: null and alignment are checked above. Allocation validity,
    // lifetime and exclusivity remain part of the C caller contract.
    Some(unsafe { &mut *ptr })
}

macro_rules! ffi_addr {
    ($ptr:expr, $len:expr, $ret:expr) => {{
        // SAFETY: the C API requires readable address fields for the
        // supplied length. The decoder checks null, length and alignment.
        match unsafe { std_addr_from_c($ptr, $len) } {
            Ok(addr) => addr,
            Err(()) => return $ret,
        }
    }};
}

macro_rules! ffi_optional_addr {
    ($ptr:expr, $len:expr, $ret:expr) => {{
        // SAFETY: present addresses have the same C input contract.
        match unsafe { optional_std_addr_from_c($ptr, $len) } {
            Ok(addr) => addr,
            Err(()) => return $ret,
        }
    }};
}

macro_rules! ffi_ref {
    ($ptr:expr) => {{
        // SAFETY: C callers may pass null. Non-null pointers retain the same
        // validity/alignment/lifetime requirements as the public C API.
        match unsafe { $crate::ffi::ffi_ptr_ref($ptr) } {
            Some(value) => value,
            None => return,
        }
    }};
    ($ptr:expr, $ret:expr) => {{
        // SAFETY: C callers may pass null. Non-null pointers retain the same
        // validity/alignment/lifetime requirements as the public C API.
        match unsafe { $crate::ffi::ffi_ptr_ref($ptr) } {
            Some(value) => value,
            None => return $ret,
        }
    }};
}

macro_rules! ffi_mut {
    ($ptr:expr) => {{
        // SAFETY: C callers may pass null. Non-null pointers retain the same
        // validity/alignment/lifetime/exclusivity requirements as the public C
        // API.
        match unsafe { $crate::ffi::ffi_ptr_mut($ptr) } {
            Some(value) => value,
            None => return,
        }
    }};
    ($ptr:expr, $ret:expr) => {{
        // SAFETY: C callers may pass null. Non-null pointers retain the same
        // validity/alignment/lifetime/exclusivity requirements as the public
        // C API.
        match unsafe { $crate::ffi::ffi_ptr_mut($ptr) } {
            Some(value) => value,
            None => return $ret,
        }
    }};
}

fn ffi_slice_layout_valid<T>(ptr: *const T, len: usize) -> bool {
    if len == 0 {
        return true;
    }

    if ptr.is_null() || !ptr.is_aligned() {
        return false;
    }

    size_of::<T>().checked_mul(len).is_some_and(|bytes| {
        bytes <= isize::MAX as usize && ptr.addr().checked_add(bytes).is_some()
    })
}

/// Builds a shared slice from a C pointer after checking the parts that can be
/// validated without dereferencing caller memory.
///
/// # Safety
///
/// For non-empty slices, \`ptr\` must still point to \`len\` initialized \`T\`
/// values in one live allocation for the returned lifetime.
pub(super) unsafe fn ffi_slice_from_raw_parts<'a, T>(
    ptr: *const T, len: usize,
) -> Option<&'a [T]> {
    if len == 0 {
        return Some(&[]);
    }

    if !ffi_slice_layout_valid(ptr, len) {
        return None;
    }

    // SAFETY: null/alignment/size arithmetic were checked above. Allocation
    // validity and lifetime remain part of the C caller contract.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Builds a mutable slice from a C pointer after checking the parts that can be
/// validated without dereferencing caller memory.
///
/// # Safety
///
/// For non-empty slices, \`ptr\` must point to \`len\` initialized \`T\` values
/// in one live allocation and be exclusively borrowed for the returned
/// lifetime.
pub(super) unsafe fn ffi_slice_from_raw_parts_mut<'a, T>(
    ptr: *mut T, len: usize,
) -> Option<&'a mut [T]> {
    if len == 0 {
        return Some(&mut []);
    }

    if !ffi_slice_layout_valid(ptr.cast_const(), len) {
        return None;
    }

    // SAFETY: null/alignment/size arithmetic were checked above. Allocation
    // validity, lifetime and exclusivity remain part of the C caller contract.
    Some(unsafe { slice::from_raw_parts_mut(ptr, len) })
}

macro_rules! ffi_slice {
    ($ptr:expr, $len:expr) => {{
        // SAFETY: the C caller supplies one allocation of initialized elements,
        // valid and shared for this call; the helper verifies layout bounds.
        match unsafe { $crate::ffi::ffi_slice_from_raw_parts($ptr, $len) } {
            Some(value) => value,
            None => return,
        }
    }};
    ($ptr:expr, $len:expr, $ret:expr) => {{
        // SAFETY: the C caller supplies one allocation of initialized elements,
        // valid and shared for this call; the helper verifies layout bounds.
        match unsafe { $crate::ffi::ffi_slice_from_raw_parts($ptr, $len) } {
            Some(value) => value,
            None => return $ret,
        }
    }};
}

macro_rules! ffi_slice_mut {
    ($ptr:expr, $len:expr, $ret:expr) => {{
        // SAFETY: the C caller supplies exclusive access to initialized
        // elements for this call; the helper verifies layout bounds.
        match unsafe { $crate::ffi::ffi_slice_from_raw_parts_mut($ptr, $len) } {
            Some(value) => value,
            None => return $ret,
        }
    }};
}

pub(super) use ffi_mut;
pub(super) use ffi_ref;
pub(super) use ffi_slice;
pub(super) use ffi_slice_mut;

fn validate_ssize_len(len: size_t) -> std::result::Result<(), ssize_t> {
    if len > ssize_t::MAX as usize {
        Err(ssize_t::from(FFI_ERR_INVALID_ARGUMENT))
    } else {
        Ok(())
    }
}

/// Borrows a non-null NUL-terminated C string as UTF-8.
///
/// # Safety
///
/// `value` must point to a valid NUL-terminated C string for the duration of
/// the returned borrow, without mutation.
unsafe fn c_str_to_str<'a>(
    value: *const c_char,
) -> std::result::Result<&'a str, ()> {
    if value.is_null() {
        return Err(());
    }

    // SAFETY: null was checked above; the C caller owns the valid string.
    unsafe { ffi::CStr::from_ptr(value) }
        .to_str()
        .map_err(|_| ())
}

#[no_mangle]
pub extern "C" fn quiche_version() -> *const u8 {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr()
}

struct Logger {
    cb: extern "C" fn(line: *const u8, argp: *mut c_void),
    argp: atomic::AtomicPtr<c_void>,
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let line = format!("{}: {}\0", record.target(), record.args());
        (self.cb)(line.as_ptr(), self.argp.load(atomic::Ordering::Relaxed));
    }

    fn flush(&self) {}
}

#[no_mangle]
pub extern "C" fn quiche_enable_debug_logging(
    cb: extern "C" fn(line: *const u8, argp: *mut c_void), argp: *mut c_void,
) -> c_int {
    let argp = atomic::AtomicPtr::new(argp);
    let logger = Box::new(Logger { cb, argp });

    if log::set_boxed_logger(logger).is_err() {
        return -1;
    }

    log::set_max_level(log::LevelFilter::Trace);

    0
}

#[no_mangle]
pub extern "C" fn quiche_config_new(version: u32) -> *mut Config {
    match Config::new(version) {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
}

// The C string configuration entry points have one common validation and
// conversion path; only the Rust operation differs.
fn config_string_operation(
    config: *mut Config, value: *const c_char,
    op: impl FnOnce(&mut Config, &str) -> Result<()>,
) -> c_int {
    let config = ffi_mut!(config, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    // SAFETY: the C entry point requires a live NUL-terminated string.
    let Ok(value) = (unsafe { c_str_to_str(value) }) else {
        return c_int::from(FFI_ERR_INVALID_ARGUMENT);
    };
    op(config, value).map_or_else(|e| c_int::from(e.to_c()), |()| 0)
}

// Likewise, the byte-input operations all borrow the validated input for
// the duration of the call and return a C status code, not a byte count.
fn bytes_operation<T>(
    receiver: *mut T, input: *const u8, len: size_t,
    op: impl FnOnce(&mut T, &[u8]) -> Result<()>,
) -> c_int {
    let receiver = ffi_mut!(receiver, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let input = ffi_slice!(input, len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    op(receiver, input).map_or_else(|e| c_int::from(e.to_c()), |()| 0)
}

#[no_mangle]
pub extern "C" fn quiche_config_load_cert_chain_from_pem_file(
    config: *mut Config, path: *const c_char,
) -> c_int {
    config_string_operation(config, path, Config::load_cert_chain_from_pem_file)
}

#[no_mangle]
pub extern "C" fn quiche_config_load_priv_key_from_pem_file(
    config: *mut Config, path: *const c_char,
) -> c_int {
    config_string_operation(config, path, Config::load_priv_key_from_pem_file)
}

#[no_mangle]
pub extern "C" fn quiche_config_load_verify_locations_from_file(
    config: *mut Config, path: *const c_char,
) -> c_int {
    config_string_operation(config, path, Config::load_verify_locations_from_file)
}

#[no_mangle]
pub extern "C" fn quiche_config_load_verify_locations_from_directory(
    config: *mut Config, path: *const c_char,
) -> c_int {
    config_string_operation(
        config,
        path,
        Config::load_verify_locations_from_directory,
    )
}

#[no_mangle]
pub extern "C" fn quiche_config_set_curves_list(
    config: *mut Config, curves: *const c_char,
) -> c_int {
    config_string_operation(config, curves, Config::set_curves_list)
}

#[no_mangle]
pub extern "C" fn quiche_config_verify_peer(config: *mut Config, v: bool) {
    let config = ffi_mut!(config);

    config.verify_peer(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_grease(config: *mut Config, v: bool) {
    let config = ffi_mut!(config);

    config.grease(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_discover_pmtu(config: *mut Config, v: bool) {
    let config = ffi_mut!(config);

    config.discover_pmtu(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_pmtud_max_probes(
    config: *mut Config, max_probes: u8,
) {
    let config = ffi_mut!(config);

    config.set_pmtud_max_probes(max_probes);
}

#[no_mangle]
pub extern "C" fn quiche_config_log_keys(config: *mut Config) {
    let config = ffi_mut!(config);

    config.log_keys();
}

#[no_mangle]
pub extern "C" fn quiche_config_enable_early_data(config: *mut Config) {
    let config = ffi_mut!(config);

    config.enable_early_data();
}

#[no_mangle]
/// Corresponds to the `Config::set_application_protos_wire_format` Rust
/// function.
pub extern "C" fn quiche_config_set_application_protos(
    config: *mut Config, protos: *const u8, protos_len: size_t,
) -> c_int {
    bytes_operation(
        config,
        protos,
        protos_len,
        Config::set_application_protos_wire_format,
    )
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_amplification_factor(
    config: *mut Config, v: usize,
) {
    let config = ffi_mut!(config);

    config.set_max_amplification_factor(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_idle_timeout(
    config: *mut Config, v: u64,
) {
    let config = ffi_mut!(config);

    config.set_max_idle_timeout(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_recv_udp_payload_size(
    config: *mut Config, v: size_t,
) {
    let config = ffi_mut!(config);

    config.set_max_recv_udp_payload_size(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_max_data(
    config: *mut Config, v: u64,
) {
    let config = ffi_mut!(config);

    config.set_initial_max_data(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_max_stream_data_bidi_local(
    config: *mut Config, v: u64,
) {
    let config = ffi_mut!(config);

    config.set_initial_max_stream_data_bidi_local(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_max_stream_data_bidi_remote(
    config: *mut Config, v: u64,
) {
    let config = ffi_mut!(config);

    config.set_initial_max_stream_data_bidi_remote(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_max_stream_data_uni(
    config: *mut Config, v: u64,
) {
    let config = ffi_mut!(config);

    config.set_initial_max_stream_data_uni(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_max_streams_bidi(
    config: *mut Config, v: u64,
) {
    let config = ffi_mut!(config);

    config.set_initial_max_streams_bidi(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_max_streams_uni(
    config: *mut Config, v: u64,
) {
    let config = ffi_mut!(config);

    config.set_initial_max_streams_uni(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_ack_delay_exponent(
    config: *mut Config, v: u64,
) {
    let config = ffi_mut!(config);

    config.set_ack_delay_exponent(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_ack_delay(config: *mut Config, v: u64) {
    let config = ffi_mut!(config);

    config.set_max_ack_delay(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_disable_active_migration(
    config: *mut Config, v: bool,
) {
    let config = ffi_mut!(config);

    config.set_disable_active_migration(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_cc_algorithm_name(
    config: *mut Config, name: *const c_char,
) -> c_int {
    config_string_operation(config, name, Config::set_cc_algorithm_name)
}

#[no_mangle]
pub extern "C" fn quiche_config_set_cc_algorithm(
    config: *mut Config, algo: CongestionControlAlgorithm,
) {
    let config = ffi_mut!(config);

    config.set_cc_algorithm(algo);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_initial_congestion_window_packets(
    config: *mut Config, packets: size_t,
) {
    let config = ffi_mut!(config);

    config.set_initial_congestion_window_packets(packets);
}

#[no_mangle]
pub extern "C" fn quiche_config_enable_hystart(config: *mut Config, v: bool) {
    let config = ffi_mut!(config);

    config.enable_hystart(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_enable_pacing(config: *mut Config, v: bool) {
    let config = ffi_mut!(config);

    config.enable_pacing(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_enable_cubic_idle_restart_fix(
    config: *mut Config, v: bool,
) {
    let config = ffi_mut!(config);

    config.set_enable_cubic_idle_restart_fix(v);
}

/// Deprecated: this is now always enabled and this function is a no-op.
#[no_mangle]
pub extern "C" fn quiche_config_set_use_initial_max_data_as_flow_control_win(
    _config: *mut Config, _v: bool,
) {
    let _config = ffi_mut!(_config);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_pacing_rate(config: *mut Config, v: u64) {
    let config = ffi_mut!(config);

    config.set_max_pacing_rate(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_enable_dgram(
    config: *mut Config, enabled: bool, recv_queue_len: size_t,
    send_queue_len: size_t,
) {
    let config = ffi_mut!(config);

    config.enable_dgram(enabled, recv_queue_len, send_queue_len);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_send_udp_payload_size(
    config: *mut Config, v: size_t,
) {
    let config = ffi_mut!(config);

    config.set_max_send_udp_payload_size(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_connection_window(
    config: *mut Config, v: u64,
) {
    let config = ffi_mut!(config);

    config.set_max_connection_window(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_max_stream_window(
    config: *mut Config, v: u64,
) {
    let config = ffi_mut!(config);

    config.set_max_stream_window(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_active_connection_id_limit(
    config: *mut Config, v: u64,
) {
    let config = ffi_mut!(config);

    config.set_active_connection_id_limit(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_stateless_reset_token(
    config: *mut Config, v: *const u8,
) {
    let config = ffi_mut!(config);

    let reset_token = ffi_slice!(v, 16);
    let reset_token = match reset_token.try_into() {
        Ok(rt) => rt,
        Err(_) => unreachable!(),
    };
    let reset_token = u128::from_be_bytes(reset_token);
    config.set_stateless_reset_token(Some(reset_token));
}

#[no_mangle]
pub extern "C" fn quiche_config_set_disable_dcid_reuse(
    config: *mut Config, v: bool,
) {
    let config = ffi_mut!(config);

    config.set_disable_dcid_reuse(v);
}

#[no_mangle]
pub extern "C" fn quiche_config_set_ticket_key(
    config: *mut Config, key: *const u8, key_len: size_t,
) -> c_int {
    bytes_operation(config, key, key_len, Config::set_ticket_key)
}

#[no_mangle]
pub extern "C" fn quiche_config_free(config: *mut Config) {
    if !config.is_null() {
        drop(unsafe { Box::from_raw(config) });
    }
}

#[no_mangle]
pub extern "C" fn quiche_header_info(
    buf: *mut u8, buf_len: size_t, dcil: size_t, version: *mut u32, ty: *mut u8,
    scid: *mut u8, scid_len: *mut size_t, dcid: *mut u8, dcid_len: *mut size_t,
    token: *mut u8, token_len: *mut size_t,
) -> c_int {
    let version = ffi_mut!(version, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let ty = ffi_mut!(ty, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let scid_len = ffi_mut!(scid_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let dcid_len = ffi_mut!(dcid_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let token_len = ffi_mut!(token_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let buf = ffi_slice_mut!(buf, buf_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let hdr = match Header::from_slice(buf, dcil) {
        Ok(v) => v,

        Err(e) => return c_int::from(e.to_c()),
    };

    *version = hdr.version;

    *ty = match hdr.ty {
        Type::Initial => 1,
        Type::Retry => 2,
        Type::Handshake => 3,
        Type::ZeroRTT => 4,
        Type::Short => 5,
        Type::VersionNegotiation => 6,
    };

    if *scid_len < hdr.scid.len() {
        return -1;
    }

    let scid =
        ffi_slice_mut!(scid, *scid_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let scid = &mut scid[..hdr.scid.len()];
    scid.copy_from_slice(&hdr.scid);

    *scid_len = hdr.scid.len();

    if *dcid_len < hdr.dcid.len() {
        return -1;
    }

    let dcid =
        ffi_slice_mut!(dcid, *dcid_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let dcid = &mut dcid[..hdr.dcid.len()];
    dcid.copy_from_slice(&hdr.dcid);

    *dcid_len = hdr.dcid.len();

    match hdr.token {
        Some(tok) => {
            if *token_len < tok.len() {
                return -1;
            }

            let token = ffi_slice_mut!(
                token,
                *token_len,
                c_int::from(FFI_ERR_INVALID_ARGUMENT)
            );
            let token = &mut token[..tok.len()];
            token.copy_from_slice(&tok);

            *token_len = tok.len();
        },

        None => *token_len = 0,
    }

    0
}

#[no_mangle]
pub extern "C" fn quiche_accept(
    scid: *const u8, scid_len: size_t, odcid: *const u8, odcid_len: size_t,
    local: *const sockaddr, local_len: socklen_t, peer: *const sockaddr,
    peer_len: socklen_t, config: *mut Config,
) -> *mut Connection {
    let config = ffi_mut!(config, ptr::null_mut());

    let scid = ffi_slice!(scid, scid_len, ptr::null_mut());
    let scid = ConnectionId::from_ref(scid);

    let odcid = if odcid_len == 0 {
        None
    } else {
        Some(ConnectionId::from_ref(ffi_slice!(
            odcid,
            odcid_len,
            ptr::null_mut()
        )))
    };

    let local = ffi_addr!(local, local_len, ptr::null_mut());
    let peer = ffi_addr!(peer, peer_len, ptr::null_mut());

    match accept(&scid, odcid.as_ref(), local, peer, config) {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_connect(
    server_name: *const c_char, scid: *const u8, scid_len: size_t,
    local: *const sockaddr, local_len: socklen_t, peer: *const sockaddr,
    peer_len: socklen_t, config: *mut Config,
) -> *mut Connection {
    let config = ffi_mut!(config, ptr::null_mut());

    let server_name = if server_name.is_null() {
        None
    } else {
        let Ok(server_name) = (unsafe { c_str_to_str(server_name) }) else {
            return ptr::null_mut();
        };
        Some(server_name)
    };

    let scid = ffi_slice!(scid, scid_len, ptr::null_mut());
    let scid = ConnectionId::from_ref(scid);

    let local = ffi_addr!(local, local_len, ptr::null_mut());
    let peer = ffi_addr!(peer, peer_len, ptr::null_mut());

    match connect(server_name, &scid, local, peer, config) {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_negotiate_version(
    scid: *const u8, scid_len: size_t, dcid: *const u8, dcid_len: size_t,
    out: *mut u8, out_len: size_t,
) -> ssize_t {
    let scid =
        ffi_slice!(scid, scid_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let scid = ConnectionId::from_ref(scid);

    let dcid =
        ffi_slice!(dcid, dcid_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let dcid = ConnectionId::from_ref(dcid);

    let out =
        ffi_slice_mut!(out, out_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match negotiate_version(&scid, &dcid, out) {
        Ok(v) => ssize_t::try_from(v).unwrap_or(ssize_t::MAX),

        Err(e) => ssize_t::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_version_is_supported(version: u32) -> bool {
    version_is_supported(version)
}

#[no_mangle]
pub extern "C" fn quiche_retry(
    scid: *const u8, scid_len: size_t, dcid: *const u8, dcid_len: size_t,
    new_scid: *const u8, new_scid_len: size_t, token: *const u8,
    token_len: size_t, version: u32, out: *mut u8, out_len: size_t,
) -> ssize_t {
    let scid =
        ffi_slice!(scid, scid_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let scid = ConnectionId::from_ref(scid);

    let dcid =
        ffi_slice!(dcid, dcid_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let dcid = ConnectionId::from_ref(dcid);

    let new_scid = ffi_slice!(
        new_scid,
        new_scid_len,
        ssize_t::from(FFI_ERR_INVALID_ARGUMENT)
    );
    let new_scid = ConnectionId::from_ref(new_scid);

    let token =
        ffi_slice!(token, token_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let out =
        ffi_slice_mut!(out, out_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match retry(&scid, &dcid, &new_scid, token, version, out) {
        Ok(v) => ssize_t::try_from(v).unwrap_or(ssize_t::MAX),

        Err(e) => ssize_t::from(e.to_c()),
    }
}

#[no_mangle]
#[cfg(feature = "custom-client-dcid")]
pub extern "C" fn quiche_conn_new_with_tls_and_client_dcid(
    scid: *const u8, scid_len: size_t, dcid: *const u8, dcid_len: size_t,
    local: *const sockaddr, local_len: socklen_t, peer: *const sockaddr,
    peer_len: socklen_t, config: *const Config, ssl: *mut c_void,
) -> *mut Connection {
    let config = ffi_ref!(config, ptr::null_mut());

    {
        let scid = ffi_slice!(scid, scid_len, ptr::null_mut());
        let scid = ConnectionId::from_ref(scid);

        let dcid = if dcid_len == 0 {
            None
        } else {
            Some(ConnectionId::from_ref(ffi_slice!(
                dcid,
                dcid_len,
                ptr::null_mut()
            )))
        };

        let local = ffi_addr!(local, local_len, ptr::null_mut());
        let peer = ffi_addr!(peer, peer_len, ptr::null_mut());

        let tls = match unsafe { tls::Handshake::from_ptr(ssl) } {
            Ok(v) => v,

            Err(_) => return ptr::null_mut(),
        };

        match Connection::with_tls(
            &scid,
            None, // retry_cids
            dcid.as_ref(),
            local,
            peer,
            config,
            tls,
            false,
        ) {
            Ok(c) => Box::into_raw(Box::new(c)),

            Err(_) => ptr::null_mut(),
        }
    }
}

#[no_mangle]
#[cfg(not(feature = "custom-client-dcid"))]
pub extern "C" fn quiche_conn_new_with_tls_and_client_dcid(
    _scid: *const u8, _scid_len: size_t, _dcid: *const u8, _dcid_len: size_t,
    _local: *const sockaddr, _local_len: socklen_t, _peer: *const sockaddr,
    _peer_len: socklen_t, _config: *const Config, _ssl: *mut c_void,
) -> *mut Connection {
    // It's always an error to call this function without the custom-client-dcid
    // feature enabled.
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn quiche_conn_new_with_tls(
    scid: *const u8, scid_len: size_t, odcid: *const u8, odcid_len: size_t,
    local: *const sockaddr, local_len: socklen_t, peer: *const sockaddr,
    peer_len: socklen_t, config: *const Config, ssl: *mut c_void,
    is_server: bool,
) -> *mut Connection {
    let config = ffi_ref!(config, ptr::null_mut());

    let scid = ffi_slice!(scid, scid_len, ptr::null_mut());
    let scid = ConnectionId::from_ref(scid);

    let odcid = if odcid_len == 0 {
        None
    } else {
        Some(ConnectionId::from_ref(ffi_slice!(
            odcid,
            odcid_len,
            ptr::null_mut()
        )))
    };

    let retry_cids = odcid.as_ref().map(|odcid| RetryConnectionIds {
        original_destination_cid: odcid,
        retry_source_cid: &scid,
    });

    let local = ffi_addr!(local, local_len, ptr::null_mut());
    let peer = ffi_addr!(peer, peer_len, ptr::null_mut());

    let tls = match unsafe { tls::Handshake::from_ptr(ssl) } {
        Ok(v) => v,

        Err(_) => return ptr::null_mut(),
    };

    match Connection::with_tls(
        &scid, retry_cids, None, local, peer, config, tls, is_server,
    ) {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_set_keylog_path(
    conn: *mut Connection, path: *const c_char,
) -> bool {
    let conn = ffi_mut!(conn, false);

    let Ok(filename) = (unsafe { c_str_to_str(path) }) else {
        return false;
    };

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename);

    let writer = match file {
        Ok(f) => std::io::BufWriter::new(f),

        Err(_) => return false,
    };

    conn.set_keylog(Box::new(writer));

    true
}

#[no_mangle]
#[cfg(unix)]
pub extern "C" fn quiche_conn_set_keylog_fd(conn: *mut Connection, fd: c_int) {
    let conn = ffi_mut!(conn);

    let f = unsafe { std::fs::File::from_raw_fd(fd) };
    let writer = std::io::BufWriter::new(f);

    conn.set_keylog(Box::new(writer));
}

#[no_mangle]
#[cfg(feature = "qlog")]
pub extern "C" fn quiche_conn_set_qlog_path(
    conn: *mut Connection, path: *const c_char, log_title: *const c_char,
    log_desc: *const c_char,
) -> bool {
    let conn = ffi_mut!(conn, false);

    let Ok(filename) = (unsafe { c_str_to_str(path) }) else {
        return false;
    };
    let Ok(title) = (unsafe { c_str_to_str(log_title) }) else {
        return false;
    };
    let Ok(description) = (unsafe { c_str_to_str(log_desc) }) else {
        return false;
    };

    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(filename);

    let writer = match file {
        Ok(f) => std::io::BufWriter::new(f),

        Err(_) => return false,
    };

    conn.set_qlog(
        Box::new(writer),
        title.to_owned(),
        format!("{} id={}", description, conn.trace_id),
    );

    true
}

#[no_mangle]
#[cfg(all(unix, feature = "qlog"))]
pub extern "C" fn quiche_conn_set_qlog_fd(
    conn: *mut Connection, fd: c_int, log_title: *const c_char,
    log_desc: *const c_char,
) {
    let conn = ffi_mut!(conn);

    let Ok(title) = (unsafe { c_str_to_str(log_title) }) else {
        return;
    };
    let Ok(description) = (unsafe { c_str_to_str(log_desc) }) else {
        return;
    };

    let f = unsafe { std::fs::File::from_raw_fd(fd) };
    let writer = std::io::BufWriter::new(f);

    conn.set_qlog(
        Box::new(writer),
        title.to_owned(),
        format!("{} id={}", description, conn.trace_id),
    );
}

#[no_mangle]
pub extern "C" fn quiche_conn_set_session(
    conn: *mut Connection, buf: *const u8, buf_len: size_t,
) -> c_int {
    bytes_operation(conn, buf, buf_len, Connection::set_session)
}

#[no_mangle]
pub extern "C" fn quiche_conn_set_max_idle_timeout(
    conn: *mut Connection, v: u64,
) -> c_int {
    let conn = ffi_mut!(conn, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.set_max_idle_timeout(v) {
        Ok(()) => 0,

        Err(e) => c_int::from(e.to_c()),
    }
}

#[repr(C)]
pub struct RecvInfo {
    from: *const sockaddr,
    from_len: socklen_t,
    to: *const sockaddr,
    to_len: socklen_t,
}

impl RecvInfo {
    /// Decode both addresses without borrowing a foreign sockaddr.
    ///
    /// # Safety
    /// Each non-null pointer with an accepted length must identify readable
    /// address fields for the duration of this call.
    unsafe fn decode(&self) -> std::result::Result<crate::RecvInfo, ()> {
        // SAFETY: the caller guarantees readability of both address inputs.
        unsafe {
            Ok(crate::RecvInfo {
                from: std_addr_from_c(self.from, self.from_len)?,
                to: std_addr_from_c(self.to, self.to_len)?,
            })
        }
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_recv(
    conn: *mut Connection, buf: *mut u8, buf_len: size_t, info: *const RecvInfo,
) -> ssize_t {
    let conn = ffi_mut!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let info = ffi_ref!(info, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    if let Err(e) = validate_ssize_len(buf_len) {
        return e;
    }

    // SAFETY: the C receive API requires readable address inputs during the
    // call.
    let Ok(info) = (unsafe { info.decode() }) else {
        return ssize_t::from(FFI_ERR_INVALID_ARGUMENT);
    };

    let buf =
        ffi_slice_mut!(buf, buf_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.recv(buf, info) {
        Ok(v) => ssize_t::try_from(v).unwrap_or(ssize_t::MAX),

        Err(e) => ssize_t::from(e.to_c()),
    }
}

#[repr(C)]
pub struct SendInfo {
    from: sockaddr_storage,
    from_len: socklen_t,
    to: sockaddr_storage,
    to_len: socklen_t,

    at: timespec,
}

impl From<crate::SendInfo> for SendInfo {
    fn from(info: crate::SendInfo) -> Self {
        // SAFETY: sockaddr_storage contains integer/byte fields; zero
        // initializes all storage before writing the actual address.
        let mut from = unsafe { std::mem::zeroed() };
        // SAFETY: same layout as from.
        let mut to = unsafe { std::mem::zeroed() };
        let from_len = std_addr_to_c(&info.from, &mut from);
        let to_len = std_addr_to_c(&info.to, &mut to);
        let mut at = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        std_time_to_c(&info.at, &mut at);
        Self {
            from,
            from_len,
            to,
            to_len,
            at,
        }
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_send(
    conn: *mut Connection, out: *mut u8, out_len: size_t, out_info: *mut SendInfo,
) -> ssize_t {
    let conn = ffi_mut!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let out_info = ffi_mut!(
        out_info.cast::<MaybeUninit<SendInfo>>(),
        ssize_t::from(FFI_ERR_INVALID_ARGUMENT)
    );

    if let Err(e) = validate_ssize_len(out_len) {
        return e;
    }

    let out =
        ffi_slice_mut!(out, out_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.send(out) {
        Ok((v, info)) => {
            out_info.write(info.into());

            ssize_t::try_from(v).unwrap_or(ssize_t::MAX)
        },

        Err(e) => ssize_t::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_send_on_path(
    conn: *mut Connection, out: *mut u8, out_len: size_t, from: *const sockaddr,
    from_len: socklen_t, to: *const sockaddr, to_len: socklen_t,
    out_info: *mut SendInfo,
) -> ssize_t {
    let conn = ffi_mut!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let out_info = ffi_mut!(
        out_info.cast::<MaybeUninit<SendInfo>>(),
        ssize_t::from(FFI_ERR_INVALID_ARGUMENT)
    );

    if let Err(e) = validate_ssize_len(out_len) {
        return e;
    }

    let from = ffi_optional_addr!(
        from,
        from_len,
        ssize_t::from(FFI_ERR_INVALID_ARGUMENT)
    );
    let to =
        ffi_optional_addr!(to, to_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let out =
        ffi_slice_mut!(out, out_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.send_on_path(out, from, to) {
        Ok((v, info)) => {
            out_info.write(info.into());

            ssize_t::try_from(v).unwrap_or(ssize_t::MAX)
        },

        Err(e) => ssize_t::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_recv(
    conn: *mut Connection, stream_id: u64, out: *mut u8, out_len: size_t,
    fin: *mut bool, out_error_code: *mut u64,
) -> ssize_t {
    let conn = ffi_mut!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let fin = ffi_mut!(fin, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let out_error_code =
        ffi_mut!(out_error_code, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    if let Err(e) = validate_ssize_len(out_len) {
        return e;
    }

    let out =
        ffi_slice_mut!(out, out_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    let (out_len, out_fin) = match conn.stream_recv(stream_id, out) {
        Ok(v) => v,

        Err(e) => {
            match e {
                Error::StreamReset(error) => *out_error_code = error,
                Error::StreamStopped(error) => *out_error_code = error,
                _ => {},
            }
            return ssize_t::from(e.to_c());
        },
    };

    *fin = out_fin;

    ssize_t::try_from(out_len).unwrap_or(ssize_t::MAX)
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_send(
    conn: *mut Connection, stream_id: u64, buf: *const u8, buf_len: size_t,
    fin: bool, out_error_code: *mut u64,
) -> ssize_t {
    let conn = ffi_mut!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let out_error_code =
        ffi_mut!(out_error_code, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    if let Err(e) = validate_ssize_len(buf_len) {
        return e;
    }

    let buf = ffi_slice!(buf, buf_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.stream_send(stream_id, buf, fin) {
        Ok(v) => ssize_t::try_from(v).unwrap_or(ssize_t::MAX),

        Err(e) => {
            match e {
                Error::StreamReset(error) => *out_error_code = error,
                Error::StreamStopped(error) => *out_error_code = error,
                _ => {},
            }
            ssize_t::from(e.to_c())
        },
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_priority(
    conn: *mut Connection, stream_id: u64, urgency: u8, incremental: bool,
) -> c_int {
    let conn = ffi_mut!(conn, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.stream_priority(stream_id, urgency, incremental) {
        Ok(_) => 0,

        Err(e) => c_int::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_shutdown(
    conn: *mut Connection, stream_id: u64, direction: Shutdown, err: u64,
) -> c_int {
    let conn = ffi_mut!(conn, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.stream_shutdown(stream_id, direction, err) {
        Ok(_) => 0,

        Err(e) => c_int::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_capacity(
    conn: *mut Connection, stream_id: u64,
) -> ssize_t {
    let conn = ffi_mut!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.stream_capacity(stream_id) {
        Ok(v) => ssize_t::try_from(v).unwrap_or(ssize_t::MAX),

        Err(e) => ssize_t::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_readable(
    conn: *const Connection, stream_id: u64,
) -> bool {
    let conn = ffi_ref!(conn, false);

    conn.stream_readable(stream_id)
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_readable_next(conn: *mut Connection) -> i64 {
    let conn = ffi_mut!(conn, i64::from(FFI_ERR_INVALID_ARGUMENT));

    conn.stream_readable_next()
        .and_then(|v| i64::try_from(v).ok())
        .unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_writable(
    conn: *mut Connection, stream_id: u64, len: usize,
) -> c_int {
    let conn = ffi_mut!(conn, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.stream_writable(stream_id, len) {
        Ok(true) => 1,

        Ok(false) => 0,

        Err(e) => c_int::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_writable_next(conn: *mut Connection) -> i64 {
    let conn = ffi_mut!(conn, i64::from(FFI_ERR_INVALID_ARGUMENT));

    conn.stream_writable_next()
        .and_then(|v| i64::try_from(v).ok())
        .unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_finished(
    conn: *const Connection, stream_id: u64,
) -> bool {
    let conn = ffi_ref!(conn, false);

    conn.stream_finished(stream_id)
}

#[no_mangle]
pub extern "C" fn quiche_conn_readable(
    conn: *const Connection,
) -> *mut StreamIter {
    let conn = ffi_ref!(conn, ptr::null_mut());

    Box::into_raw(Box::new(conn.readable()))
}

#[no_mangle]
pub extern "C" fn quiche_conn_writable(
    conn: *const Connection,
) -> *mut StreamIter {
    let conn = ffi_ref!(conn, ptr::null_mut());

    Box::into_raw(Box::new(conn.writable()))
}

#[no_mangle]
pub extern "C" fn quiche_conn_max_send_udp_payload_size(
    conn: *const Connection,
) -> usize {
    let conn = ffi_ref!(conn, 0);

    conn.max_send_udp_payload_size()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_readable(conn: *const Connection) -> bool {
    let conn = ffi_ref!(conn, false);

    conn.is_readable()
}

#[no_mangle]
pub extern "C" fn quiche_conn_close(
    conn: *mut Connection, app: bool, err: u64, reason: *const u8,
    reason_len: size_t,
) -> c_int {
    let conn = ffi_mut!(conn, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    let reason =
        ffi_slice!(reason, reason_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.close(app, err, reason) {
        Ok(_) => 0,

        Err(e) => c_int::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_timeout_as_nanos(conn: *const Connection) -> u64 {
    let conn = ffi_ref!(conn, 0);

    match conn.timeout() {
        Some(timeout) => u64::try_from(timeout.as_nanos())
            .unwrap_or(u64::MAX - 1)
            .min(u64::MAX - 1),

        None => u64::MAX,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_timeout_as_millis(conn: *const Connection) -> u64 {
    let conn = ffi_ref!(conn, 0);

    match conn.timeout() {
        Some(timeout) => u64::try_from(timeout.as_millis())
            .unwrap_or(u64::MAX - 1)
            .min(u64::MAX - 1),

        None => u64::MAX,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_on_timeout(conn: *mut Connection) {
    let conn = ffi_mut!(conn);

    conn.on_timeout()
}

#[no_mangle]
pub extern "C" fn quiche_conn_trace_id(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_mut!(out);
    let out_len = ffi_mut!(out_len);

    let trace_id = conn.trace_id();

    *out = trace_id.as_ptr();
    *out_len = trace_id.len();
}

/// An iterator over connection ids.
#[derive(Default)]
pub struct ConnectionIdIter {
    cids: Vec<ConnectionId<'static>>,
    index: usize,
}

#[no_mangle]
pub extern "C" fn quiche_conn_source_ids(
    conn: *const Connection,
) -> *mut ConnectionIdIter {
    let conn = ffi_ref!(conn, ptr::null_mut());

    let cids = conn
        .source_ids()
        .map(|cid| cid.clone().into_owned())
        .collect();
    Box::into_raw(Box::new(ConnectionIdIter { cids, index: 0 }))
}

#[no_mangle]
pub extern "C" fn quiche_connection_id_iter_next(
    iter: *mut ConnectionIdIter, out: *mut *const u8, out_len: *mut size_t,
) -> bool {
    let iter = ffi_mut!(iter, false);
    let out = ffi_mut!(out, false);
    let out_len = ffi_mut!(out_len, false);

    if let Some(conn_id) = iter.cids.get(iter.index) {
        let id = conn_id.as_ref();
        *out = id.as_ptr();
        *out_len = id.len();
        iter.index += 1;
        return true;
    }

    false
}

#[no_mangle]
pub extern "C" fn quiche_connection_id_iter_free(iter: *mut ConnectionIdIter) {
    if !iter.is_null() {
        drop(unsafe { Box::from_raw(iter) });
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_source_id(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_mut!(out);
    let out_len = ffi_mut!(out_len);

    let conn_id = conn.source_id();
    let id = conn_id.as_ref();
    *out = id.as_ptr();
    *out_len = id.len();
}

#[no_mangle]
pub extern "C" fn quiche_conn_destination_id(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_mut!(out);
    let out_len = ffi_mut!(out_len);

    let conn_id = conn.destination_id();
    let id = conn_id.as_ref();

    *out = id.as_ptr();
    *out_len = id.len();
}

#[no_mangle]
pub extern "C" fn quiche_conn_application_proto(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_mut!(out);
    let out_len = ffi_mut!(out_len);

    let proto = conn.application_proto();

    *out = proto.as_ptr();
    *out_len = proto.len();
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_cert(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_mut!(out);
    let out_len = ffi_mut!(out_len);

    match conn.peer_cert() {
        Some(peer_cert) => {
            *out = peer_cert.as_ptr();
            *out_len = peer_cert.len();
        },

        None => *out_len = 0,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_session(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_mut!(out);
    let out_len = ffi_mut!(out_len);

    match conn.session() {
        Some(session) => {
            *out = session.as_ptr();
            *out_len = session.len();
        },

        None => *out_len = 0,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_server_name(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_mut!(out);
    let out_len = ffi_mut!(out_len);

    match conn.server_name() {
        Some(server_name) => {
            *out = server_name.as_ptr();
            *out_len = server_name.len();
        },

        None => *out_len = 0,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_established(conn: *const Connection) -> bool {
    let conn = ffi_ref!(conn, false);

    conn.is_established()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_resumed(conn: *const Connection) -> bool {
    let conn = ffi_ref!(conn, false);

    conn.is_resumed()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_in_early_data(conn: *const Connection) -> bool {
    let conn = ffi_ref!(conn, false);

    conn.is_in_early_data()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_draining(conn: *const Connection) -> bool {
    let conn = ffi_ref!(conn, false);

    conn.is_draining()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_closed(conn: *const Connection) -> bool {
    let conn = ffi_ref!(conn, false);

    conn.is_closed()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_timed_out(conn: *const Connection) -> bool {
    let conn = ffi_ref!(conn, false);

    conn.is_timed_out()
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_error(
    conn: *const Connection, is_app: *mut bool, error_code: *mut u64,
    reason: *mut *const u8, reason_len: *mut size_t,
) -> bool {
    let conn = ffi_ref!(conn, false);
    let is_app = ffi_mut!(is_app, false);
    let error_code = ffi_mut!(error_code, false);
    let reason = ffi_mut!(reason, false);
    let reason_len = ffi_mut!(reason_len, false);

    match &conn.peer_error {
        Some(conn_err) => {
            *is_app = conn_err.is_app;
            *error_code = conn_err.error_code;
            *reason = conn_err.reason.as_ptr();
            *reason_len = conn_err.reason.len();

            true
        },

        None => false,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_local_error(
    conn: *const Connection, is_app: *mut bool, error_code: *mut u64,
    reason: *mut *const u8, reason_len: *mut size_t,
) -> bool {
    let conn = ffi_ref!(conn, false);
    let is_app = ffi_mut!(is_app, false);
    let error_code = ffi_mut!(error_code, false);
    let reason = ffi_mut!(reason, false);
    let reason_len = ffi_mut!(reason_len, false);

    match &conn.local_error {
        Some(conn_err) => {
            *is_app = conn_err.is_app;
            *error_code = conn_err.error_code;
            *reason = conn_err.reason.as_ptr();
            *reason_len = conn_err.reason.len();

            true
        },

        None => false,
    }
}

#[no_mangle]
pub extern "C" fn quiche_stream_iter_next(
    iter: *mut StreamIter, stream_id: *mut u64,
) -> bool {
    let iter = ffi_mut!(iter, false);
    let stream_id = ffi_mut!(stream_id, false);

    if let Some(v) = iter.next() {
        *stream_id = v;
        return true;
    }

    false
}

#[no_mangle]
pub extern "C" fn quiche_stream_iter_free(iter: *mut StreamIter) {
    if !iter.is_null() {
        drop(unsafe { Box::from_raw(iter) });
    }
}

#[repr(C)]
pub struct Stats {
    recv: usize,
    sent: usize,
    lost: usize,
    spurious_lost: usize,
    retrans: usize,
    sent_bytes: u64,
    recv_bytes: u64,
    acked_bytes: u64,
    lost_bytes: u64,
    stream_retrans_bytes: u64,
    dgram_recv: usize,
    dgram_sent: usize,
    paths_count: usize,
    reset_stream_count_local: u64,
    stopped_stream_count_local: u64,
    reset_stream_count_remote: u64,
    stopped_stream_count_remote: u64,
    data_blocked_sent_count: u64,
    stream_data_blocked_sent_count: u64,
    data_blocked_recv_count: u64,
    stream_data_blocked_recv_count: u64,
    streams_blocked_bidi_recv_count: u64,
    streams_blocked_uni_recv_count: u64,
    path_challenge_rx_count: u64,
    bytes_in_flight_duration_msec: u64,
    tx_buffered_inconsistent: bool,
}

#[repr(C)]
pub struct TransportParams {
    max_idle_timeout: u64,
    max_udp_payload_size: u64,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    ack_delay_exponent: u64,
    max_ack_delay: u64,
    disable_active_migration: bool,
    active_conn_id_limit: u64,
    max_datagram_frame_size: i64,
}

#[no_mangle]
pub extern "C" fn quiche_conn_stats(conn: *const Connection, out: *mut Stats) {
    let conn = ffi_ref!(conn);
    let out = ffi_mut!(out.cast::<MaybeUninit<Stats>>());

    let stats = conn.stats();

    out.write(Stats {
        recv: stats.recv,
        sent: stats.sent,
        lost: stats.lost,
        spurious_lost: stats.spurious_lost,
        retrans: stats.retrans,
        sent_bytes: stats.sent_bytes,
        recv_bytes: stats.recv_bytes,
        acked_bytes: stats.acked_bytes,
        lost_bytes: stats.lost_bytes,
        stream_retrans_bytes: stats.stream_retrans_bytes,
        dgram_recv: stats.dgram_recv,
        dgram_sent: stats.dgram_sent,
        paths_count: stats.paths_count,
        reset_stream_count_local: stats.reset_stream_count_local,
        stopped_stream_count_local: stats.stopped_stream_count_local,
        reset_stream_count_remote: stats.reset_stream_count_remote,
        stopped_stream_count_remote: stats.stopped_stream_count_remote,
        data_blocked_sent_count: stats.data_blocked_sent_count,
        stream_data_blocked_sent_count: stats.stream_data_blocked_sent_count,
        data_blocked_recv_count: stats.data_blocked_recv_count,
        stream_data_blocked_recv_count: stats.stream_data_blocked_recv_count,
        streams_blocked_bidi_recv_count: stats.streams_blocked_bidi_recv_count,
        streams_blocked_uni_recv_count: stats.streams_blocked_uni_recv_count,
        path_challenge_rx_count: stats.path_challenge_rx_count,
        bytes_in_flight_duration_msec: u64::try_from(
            stats.bytes_in_flight_duration.as_millis(),
        )
        .unwrap_or(u64::MAX),
        tx_buffered_inconsistent: stats.tx_buffered_state !=
            TxBufferTrackingState::Ok,
    });
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_transport_params(
    conn: *const Connection, out: *mut TransportParams,
) -> bool {
    let conn = ffi_ref!(conn, false);
    let out = ffi_mut!(out.cast::<MaybeUninit<TransportParams>>(), false);

    let Some(tps) = conn.peer_transport_params() else {
        return false;
    };
    let max_datagram_frame_size = match tps.max_datagram_frame_size {
        None => i64::from(Error::Done.to_c()),
        Some(v) => {
            let Ok(v) = i64::try_from(v) else {
                return false;
            };
            v
        },
    };

    // Write the complete value without borrowing uninitialized fields.
    out.write(TransportParams {
        max_idle_timeout: tps.max_idle_timeout,
        max_udp_payload_size: tps.max_udp_payload_size,
        initial_max_data: tps.initial_max_data,
        initial_max_stream_data_bidi_local: tps
            .initial_max_stream_data_bidi_local,
        initial_max_stream_data_bidi_remote: tps
            .initial_max_stream_data_bidi_remote,
        initial_max_stream_data_uni: tps.initial_max_stream_data_uni,
        initial_max_streams_bidi: tps.initial_max_streams_bidi,
        initial_max_streams_uni: tps.initial_max_streams_uni,
        ack_delay_exponent: tps.ack_delay_exponent,
        max_ack_delay: tps.max_ack_delay,
        disable_active_migration: tps.disable_active_migration,
        active_conn_id_limit: tps.active_conn_id_limit,
        max_datagram_frame_size,
    });

    true
}

#[repr(C)]
pub struct PathStats {
    local_addr: sockaddr_storage,
    local_addr_len: socklen_t,
    peer_addr: sockaddr_storage,
    peer_addr_len: socklen_t,
    validation_state: ssize_t,
    active: bool,
    recv: usize,
    sent: usize,
    lost: usize,
    retrans: usize,
    total_pto_count: usize,
    dgram_recv: usize,
    dgram_sent: usize,
    rtt: u64,
    min_rtt: u64,
    max_rtt: u64,
    rttvar: u64,
    cwnd: usize,
    sent_bytes: u64,
    recv_bytes: u64,
    lost_bytes: u64,
    stream_retrans_bytes: u64,
    pmtu: usize,
    delivery_rate: u64,
    max_bandwidth: u64,
    startup_exit_cwnd: u64,
}

#[no_mangle]
pub extern "C" fn quiche_conn_path_stats(
    conn: *const Connection, idx: usize, out: *mut PathStats,
) -> c_int {
    let conn = ffi_ref!(conn, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let out = ffi_mut!(
        out.cast::<MaybeUninit<PathStats>>(),
        c_int::from(FFI_ERR_INVALID_ARGUMENT)
    );

    let stats = match conn.path_stats().nth(idx) {
        Some(p) => p,
        None => return c_int::from(Error::Done.to_c()),
    };

    // SAFETY: sockaddr_storage is a C integer/byte storage type; zero
    // is valid for every field on the supported platforms.
    let mut local_addr: sockaddr_storage = unsafe { std::mem::zeroed() };
    // SAFETY: same storage invariant as for local_addr.
    let mut peer_addr: sockaddr_storage = unsafe { std::mem::zeroed() };
    let local_addr_len = std_addr_to_c(&stats.local_addr, &mut local_addr);
    let peer_addr_len = std_addr_to_c(&stats.peer_addr, &mut peer_addr);
    out.write(PathStats {
        local_addr,
        peer_addr,
        local_addr_len,
        peer_addr_len,
        validation_state: stats.validation_state.to_c(),
        active: stats.active,
        recv: stats.recv,
        sent: stats.sent,
        lost: stats.lost,
        retrans: stats.retrans,
        total_pto_count: stats.total_pto_count,
        dgram_recv: stats.dgram_recv,
        dgram_sent: stats.dgram_sent,
        rtt: u64::try_from(stats.rtt.as_nanos()).unwrap_or(u64::MAX),
        min_rtt: u64::try_from(stats.min_rtt.unwrap_or_default().as_nanos())
            .unwrap_or(u64::MAX),
        max_rtt: u64::try_from(stats.max_rtt.unwrap_or_default().as_nanos())
            .unwrap_or(u64::MAX),
        rttvar: u64::try_from(stats.rttvar.as_nanos()).unwrap_or(u64::MAX),
        cwnd: stats.cwnd,
        sent_bytes: stats.sent_bytes,
        recv_bytes: stats.recv_bytes,
        lost_bytes: stats.lost_bytes,
        stream_retrans_bytes: stats.stream_retrans_bytes,
        pmtu: stats.pmtu,
        delivery_rate: stats.delivery_rate,
        max_bandwidth: stats.max_bandwidth.unwrap_or(0),
        startup_exit_cwnd: stats.startup_exit.map(|s| s.cwnd as u64).unwrap_or(0),
    });

    0
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_server(conn: *const Connection) -> bool {
    let conn = ffi_ref!(conn, false);

    conn.is_server()
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_max_writable_len(
    conn: *const Connection,
) -> ssize_t {
    let conn = ffi_ref!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.dgram_max_writable_len() {
        None => ssize_t::from(Error::Done.to_c()),

        Some(v) => ssize_t::try_from(v).unwrap_or(ssize_t::MAX),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_recv_front_len(
    conn: *const Connection,
) -> ssize_t {
    let conn = ffi_ref!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.dgram_recv_front_len() {
        None => ssize_t::from(Error::Done.to_c()),

        Some(v) => ssize_t::try_from(v).unwrap_or(ssize_t::MAX),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_recv_queue_len(
    conn: *const Connection,
) -> ssize_t {
    let conn = ffi_ref!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    ssize_t::try_from(conn.dgram_recv_queue_len()).unwrap_or(ssize_t::MAX)
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_recv_queue_byte_size(
    conn: *const Connection,
) -> ssize_t {
    let conn = ffi_ref!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    ssize_t::try_from(conn.dgram_recv_queue_byte_size()).unwrap_or(ssize_t::MAX)
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_send_queue_len(
    conn: *const Connection,
) -> ssize_t {
    let conn = ffi_ref!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    ssize_t::try_from(conn.dgram_send_queue_len()).unwrap_or(ssize_t::MAX)
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_send_queue_byte_size(
    conn: *const Connection,
) -> ssize_t {
    let conn = ffi_ref!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    ssize_t::try_from(conn.dgram_send_queue_byte_size()).unwrap_or(ssize_t::MAX)
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_send(
    conn: *mut Connection, buf: *const u8, buf_len: size_t,
) -> ssize_t {
    let conn = ffi_mut!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    if let Err(e) = validate_ssize_len(buf_len) {
        return e;
    }

    let buf = ffi_slice!(buf, buf_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.dgram_send(buf) {
        Ok(_) => ssize_t::try_from(buf_len).unwrap_or(ssize_t::MAX),

        Err(e) => ssize_t::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_recv(
    conn: *mut Connection, out: *mut u8, out_len: size_t,
) -> ssize_t {
    let conn = ffi_mut!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    if let Err(e) = validate_ssize_len(out_len) {
        return e;
    }

    let out =
        ffi_slice_mut!(out, out_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    let out_len = match conn.dgram_recv(out) {
        Ok(v) => v,

        Err(e) => return ssize_t::from(e.to_c()),
    };

    ssize_t::try_from(out_len).unwrap_or(ssize_t::MAX)
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_purge_outgoing(
    conn: *mut Connection, f: extern "C" fn(*const u8, size_t) -> bool,
) {
    let conn = ffi_mut!(conn);

    conn.dgram_purge_outgoing(|d: &[u8]| -> bool {
        let ptr: *const u8 = d.as_ptr();
        let len: size_t = d.len();

        f(ptr, len)
    });
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_dgram_send_queue_full(
    conn: *const Connection,
) -> bool {
    let conn = ffi_ref!(conn, false);

    conn.is_dgram_send_queue_full()
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_dgram_recv_queue_full(
    conn: *const Connection,
) -> bool {
    let conn = ffi_ref!(conn, false);

    conn.is_dgram_recv_queue_full()
}

#[no_mangle]
pub extern "C" fn quiche_conn_send_ack_eliciting(
    conn: *mut Connection,
) -> ssize_t {
    let conn = ffi_mut!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.send_ack_eliciting() {
        Ok(()) => 0,
        Err(e) => ssize_t::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_send_ack_eliciting_on_path(
    conn: *mut Connection, local: *const sockaddr, local_len: socklen_t,
    peer: *const sockaddr, peer_len: socklen_t,
) -> ssize_t {
    let conn = ffi_mut!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    let local =
        ffi_addr!(local, local_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let peer = ffi_addr!(peer, peer_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    match conn.send_ack_eliciting_on_path(local, peer) {
        Ok(()) => 0,
        Err(e) => ssize_t::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_free(conn: *mut Connection) {
    if !conn.is_null() {
        drop(unsafe { Box::from_raw(conn) });
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_streams_left_bidi(
    conn: *const Connection,
) -> u64 {
    let conn = ffi_ref!(conn, 0);

    conn.peer_streams_left_bidi()
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_streams_left_uni(
    conn: *const Connection,
) -> u64 {
    let conn = ffi_ref!(conn, 0);

    conn.peer_streams_left_uni()
}

#[no_mangle]
pub extern "C" fn quiche_conn_send_quantum(conn: *const Connection) -> size_t {
    let conn = ffi_ref!(conn, 0);

    conn.send_quantum() as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_active_scids(conn: *const Connection) -> size_t {
    let conn = ffi_ref!(conn, 0);

    conn.active_scids() as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_scids_left(conn: *const Connection) -> size_t {
    let conn = ffi_ref!(conn, 0);

    conn.scids_left() as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_new_scid(
    conn: *mut Connection, scid: *const u8, scid_len: size_t,
    reset_token: *const u8, retire_if_needed: bool, scid_seq: *mut u64,
) -> c_int {
    let conn = ffi_mut!(conn, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let scid_seq = ffi_mut!(scid_seq, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    let scid = ffi_slice!(scid, scid_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let scid = ConnectionId::from_ref(scid);

    let reset_token =
        ffi_slice!(reset_token, 16, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let reset_token = match reset_token.try_into() {
        Ok(rt) => rt,
        Err(_) => unreachable!(),
    };
    let reset_token = u128::from_be_bytes(reset_token);

    match conn.new_scid(&scid, reset_token, retire_if_needed) {
        Ok(c) => {
            *scid_seq = c;
            0
        },
        Err(e) => c_int::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_retire_dcid(
    conn: *mut Connection, dcid_seq: u64,
) -> c_int {
    let conn = ffi_mut!(conn, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.retire_dcid(dcid_seq) {
        Ok(_) => 0,
        Err(e) => c_int::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_available_dcids(conn: *const Connection) -> size_t {
    let conn = ffi_ref!(conn, 0);

    conn.available_dcids() as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_retired_scids(conn: *const Connection) -> size_t {
    let conn = ffi_ref!(conn, 0);

    conn.retired_scids() as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_retired_scid_iter(
    conn: *mut Connection,
) -> *mut ConnectionIdIter {
    let conn = ffi_mut!(conn, ptr::null_mut());

    let mut cids = Vec::with_capacity(conn.retired_scids());
    while let Some(cid) = conn.retired_scid_next() {
        cids.push(cid);
    }
    Box::into_raw(Box::new(ConnectionIdIter { cids, index: 0 }))
}

#[no_mangle]
pub extern "C" fn quiche_conn_send_quantum_on_path(
    conn: *const Connection, local: *const sockaddr, local_len: socklen_t,
    peer: *const sockaddr, peer_len: socklen_t,
) -> size_t {
    let conn = ffi_ref!(conn, 0);

    let local = ffi_addr!(local, local_len, 0);
    let peer = ffi_addr!(peer, peer_len, 0);

    conn.send_quantum_on_path(local, peer) as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_paths_iter(
    conn: *const Connection, from: *const sockaddr, from_len: socklen_t,
) -> *mut SocketAddrIter {
    let conn = ffi_ref!(conn, ptr::null_mut());

    let addr = ffi_addr!(from, from_len, ptr::null_mut());

    Box::into_raw(Box::new(conn.paths_iter(addr)))
}

#[no_mangle]
pub extern "C" fn quiche_socket_addr_iter_next(
    iter: *mut SocketAddrIter, peer: *mut sockaddr_storage,
    peer_len: *mut socklen_t,
) -> bool {
    let iter = ffi_mut!(iter, false);
    let peer = ffi_mut!(peer.cast::<MaybeUninit<sockaddr_storage>>(), false);
    let peer_len = ffi_mut!(peer_len.cast::<MaybeUninit<socklen_t>>(), false);

    if let Some(v) = iter.next() {
        // SAFETY: sockaddr_storage is an integer/byte storage type.
        let mut address = unsafe { std::mem::zeroed() };
        let len = std_addr_to_c(&v, &mut address);
        peer.write(address);
        peer_len.write(len);
        return true;
    }

    false
}

#[no_mangle]
pub extern "C" fn quiche_socket_addr_iter_free(iter: *mut SocketAddrIter) {
    if !iter.is_null() {
        drop(unsafe { Box::from_raw(iter) });
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_is_path_validated(
    conn: *const Connection, from: *const sockaddr, from_len: socklen_t,
    to: *const sockaddr, to_len: socklen_t,
) -> c_int {
    let conn = ffi_ref!(conn, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    let from = ffi_addr!(from, from_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let to = ffi_addr!(to, to_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    match conn.is_path_validated(from, to) {
        Ok(v) => c_int::from(v),
        Err(e) => c_int::from(e.to_c()),
    }
}

// Probing and migration both consume two addresses and produce a CID
// sequence on success. Validate all C arguments before mutating the connection.
fn path_operation(
    conn: *mut Connection, local: (*const sockaddr, socklen_t),
    peer: (*const sockaddr, socklen_t), seq: *mut u64,
    op: impl FnOnce(&mut Connection, SocketAddr, SocketAddr) -> Result<u64>,
) -> c_int {
    let conn = ffi_mut!(conn, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let seq = ffi_mut!(
        seq.cast::<MaybeUninit<u64>>(),
        c_int::from(FFI_ERR_INVALID_ARGUMENT)
    );
    let local =
        ffi_addr!(local.0, local.1, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let peer = ffi_addr!(peer.0, peer.1, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    match op(conn, local, peer) {
        Ok(v) => {
            seq.write(v);
            0
        },
        Err(e) => c_int::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_probe_path(
    conn: *mut Connection, local: *const sockaddr, local_len: socklen_t,
    peer: *const sockaddr, peer_len: socklen_t, seq: *mut u64,
) -> c_int {
    path_operation(
        conn,
        (local, local_len),
        (peer, peer_len),
        seq,
        Connection::probe_path,
    )
}

#[no_mangle]
pub extern "C" fn quiche_conn_migrate_source(
    conn: *mut Connection, local: *const sockaddr, local_len: socklen_t,
    seq: *mut u64,
) -> c_int {
    let conn = ffi_mut!(conn, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let seq = ffi_mut!(seq, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    let local =
        ffi_addr!(local, local_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    match conn.migrate_source(local) {
        Ok(v) => {
            *seq = v;
            0
        },
        Err(e) => c_int::from(e.to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_migrate(
    conn: *mut Connection, local: *const sockaddr, local_len: socklen_t,
    peer: *const sockaddr, peer_len: socklen_t, seq: *mut u64,
) -> c_int {
    path_operation(
        conn,
        (local, local_len),
        (peer, peer_len),
        seq,
        Connection::migrate,
    )
}

#[no_mangle]
pub extern "C" fn quiche_conn_path_event_next(
    conn: *mut Connection,
) -> *mut PathEvent {
    let conn = ffi_mut!(conn, ptr::null_mut());

    match conn.path_event_next() {
        Some(v) => Box::into_raw(Box::new(v)),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_type(ev: *const PathEvent) -> c_int {
    let ev = ffi_ref!(ev, -1);

    match ev {
        PathEvent::New { .. } => 0,

        PathEvent::Validated { .. } => 1,

        PathEvent::FailedValidation { .. } => 2,

        PathEvent::Closed { .. } => 3,

        PathEvent::ReusedSourceConnectionId { .. } => 4,

        PathEvent::PeerMigrated { .. } => 5,

        PathEvent::PmtuUpdated { .. } => 6,
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_new(
    ev: *const PathEvent, local_addr: *mut sockaddr_storage,
    local_addr_len: *mut socklen_t, peer_addr: *mut sockaddr_storage,
    peer_addr_len: *mut socklen_t,
) {
    let ev = ffi_ref!(ev);
    let local_addr = ffi_mut!(local_addr);
    let local_addr_len = ffi_mut!(local_addr_len);
    let peer_addr = ffi_mut!(peer_addr);
    let peer_addr_len = ffi_mut!(peer_addr_len);

    if let PathEvent::New(local, peer) = ev {
        *local_addr_len = std_addr_to_c(local, local_addr);
        *peer_addr_len = std_addr_to_c(peer, peer_addr);
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_validated(
    ev: *const PathEvent, local_addr: *mut sockaddr_storage,
    local_addr_len: *mut socklen_t, peer_addr: *mut sockaddr_storage,
    peer_addr_len: *mut socklen_t,
) {
    let ev = ffi_ref!(ev);
    let local_addr = ffi_mut!(local_addr);
    let local_addr_len = ffi_mut!(local_addr_len);
    let peer_addr = ffi_mut!(peer_addr);
    let peer_addr_len = ffi_mut!(peer_addr_len);

    if let PathEvent::Validated(local, peer) = ev {
        *local_addr_len = std_addr_to_c(local, local_addr);
        *peer_addr_len = std_addr_to_c(peer, peer_addr);
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_failed_validation(
    ev: *const PathEvent, local_addr: *mut sockaddr_storage,
    local_addr_len: *mut socklen_t, peer_addr: *mut sockaddr_storage,
    peer_addr_len: *mut socklen_t,
) {
    let ev = ffi_ref!(ev);
    let local_addr = ffi_mut!(local_addr);
    let local_addr_len = ffi_mut!(local_addr_len);
    let peer_addr = ffi_mut!(peer_addr);
    let peer_addr_len = ffi_mut!(peer_addr_len);

    if let PathEvent::FailedValidation(local, peer) = ev {
        *local_addr_len = std_addr_to_c(local, local_addr);
        *peer_addr_len = std_addr_to_c(peer, peer_addr);
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_closed(
    ev: *const PathEvent, local_addr: *mut sockaddr_storage,
    local_addr_len: *mut socklen_t, peer_addr: *mut sockaddr_storage,
    peer_addr_len: *mut socklen_t,
) {
    let ev = ffi_ref!(ev);
    let local_addr = ffi_mut!(local_addr);
    let local_addr_len = ffi_mut!(local_addr_len);
    let peer_addr = ffi_mut!(peer_addr);
    let peer_addr_len = ffi_mut!(peer_addr_len);

    if let PathEvent::Closed(local, peer) = ev {
        *local_addr_len = std_addr_to_c(local, local_addr);
        *peer_addr_len = std_addr_to_c(peer, peer_addr);
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_reused_source_connection_id(
    ev: *const PathEvent, cid_sequence_number: *mut u64,
    old_local_addr: *mut sockaddr_storage, old_local_addr_len: *mut socklen_t,
    old_peer_addr: *mut sockaddr_storage, old_peer_addr_len: *mut socklen_t,
    local_addr: *mut sockaddr_storage, local_addr_len: *mut socklen_t,
    peer_addr: *mut sockaddr_storage, peer_addr_len: *mut socklen_t,
) {
    let ev = ffi_ref!(ev);
    let cid_sequence_number = ffi_mut!(cid_sequence_number);
    let old_local_addr = ffi_mut!(old_local_addr);
    let old_local_addr_len = ffi_mut!(old_local_addr_len);
    let old_peer_addr = ffi_mut!(old_peer_addr);
    let old_peer_addr_len = ffi_mut!(old_peer_addr_len);
    let local_addr = ffi_mut!(local_addr);
    let local_addr_len = ffi_mut!(local_addr_len);
    let peer_addr = ffi_mut!(peer_addr);
    let peer_addr_len = ffi_mut!(peer_addr_len);

    if let PathEvent::ReusedSourceConnectionId(id, old, new) = ev {
        *cid_sequence_number = *id;
        *old_local_addr_len = std_addr_to_c(&old.0, old_local_addr);
        *old_peer_addr_len = std_addr_to_c(&old.1, old_peer_addr);

        *local_addr_len = std_addr_to_c(&new.0, local_addr);
        *peer_addr_len = std_addr_to_c(&new.1, peer_addr);
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_peer_migrated(
    ev: *const PathEvent, local_addr: *mut sockaddr_storage,
    local_addr_len: *mut socklen_t, peer_addr: *mut sockaddr_storage,
    peer_addr_len: *mut socklen_t,
) {
    let ev = ffi_ref!(ev);
    let local_addr = ffi_mut!(local_addr);
    let local_addr_len = ffi_mut!(local_addr_len);
    let peer_addr = ffi_mut!(peer_addr);
    let peer_addr_len = ffi_mut!(peer_addr_len);

    if let PathEvent::PeerMigrated(local, peer) = ev {
        *local_addr_len = std_addr_to_c(local, local_addr);
        *peer_addr_len = std_addr_to_c(peer, peer_addr);
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_pmtu_updated(
    ev: *const PathEvent, local_addr: *mut sockaddr_storage,
    local_addr_len: *mut socklen_t, peer_addr: *mut sockaddr_storage,
    peer_addr_len: *mut socklen_t, pmtu: *mut size_t,
) {
    let ev = ffi_ref!(ev);
    let local_addr = ffi_mut!(local_addr);
    let local_addr_len = ffi_mut!(local_addr_len);
    let peer_addr = ffi_mut!(peer_addr);
    let peer_addr_len = ffi_mut!(peer_addr_len);
    let pmtu = ffi_mut!(pmtu);

    if let PathEvent::PmtuUpdated {
        local,
        peer,
        pmtu: value,
    } = ev
    {
        *local_addr_len = std_addr_to_c(local, local_addr);
        *peer_addr_len = std_addr_to_c(peer, peer_addr);
        *pmtu = *value;
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_free(ev: *mut PathEvent) {
    if !ev.is_null() {
        drop(unsafe { Box::from_raw(ev) });
    }
}

#[no_mangle]
pub extern "C" fn quiche_put_varint(
    buf: *mut u8, buf_len: size_t, val: u64,
) -> c_int {
    let buf = ffi_slice_mut!(buf, buf_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    let mut b = octets::OctetsMut::with_slice(buf);
    match b.put_varint(val) {
        Ok(_) => 0,

        Err(e) => {
            let err: Error = e.into();
            c_int::from(err.to_c())
        },
    }
}

#[no_mangle]
pub extern "C" fn quiche_get_varint(
    buf: *const u8, buf_len: size_t, val: *mut u64,
) -> ssize_t {
    let val = ffi_mut!(val, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let buf = ffi_slice!(buf, buf_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    let mut b = octets::Octets::with_slice(buf);
    match b.get_varint() {
        Ok(v) => *val = v,

        Err(e) => {
            let err: Error = e.into();
            return ssize_t::from(err.to_c());
        },
    };

    ssize_t::try_from(b.off()).unwrap_or(ssize_t::MAX)
}

/// Decode a possibly absent C address.
///
/// # Safety
/// A present pointer with an accepted length must identify readable address
/// fields for the duration of this call.
unsafe fn optional_std_addr_from_c(
    addr: *const sockaddr, addr_len: socklen_t,
) -> std::result::Result<Option<SocketAddr>, ()> {
    if addr.is_null() || addr_len == 0 {
        return Ok(None);
    }

    // SAFETY: the caller supplies the same readable address contract.
    unsafe { std_addr_from_c(addr, addr_len) }.map(Some)
}

/// Decode a C address by reading only its initialized address fields.
///
/// # Safety
/// If non-null and its length matches a supported address structure, the
/// pointer must refer to readable storage for that structure's address fields.
/// No Rust reference is formed to caller memory or its unused padding.
unsafe fn std_addr_from_c(
    addr: *const sockaddr, addr_len: socklen_t,
) -> std::result::Result<SocketAddr, ()> {
    let len = usize::try_from(addr_len).map_err(|_| ())?;
    if addr.is_null() ||
        !addr.is_aligned() ||
        (len != size_of::<sockaddr_in>() && len != size_of::<sockaddr_in6>())
    {
        return Err(());
    }

    // SAFETY: both accepted layouts contain sa_family at the sockaddr offset;
    // the caller guarantees the corresponding field is readable.
    let family = unsafe { (&raw const (*addr).sa_family).read() };
    match family as _ {
        AF_INET => {
            let in4 = addr.cast::<sockaddr_in>();
            if len != size_of::<sockaddr_in>() || !in4.is_aligned() {
                return Err(());
            }

            // SAFETY: length, family and alignment match sockaddr_in. Read
            // the port and address, not the unused sin_zero bytes.
            let (sin_addr, sin_port) = unsafe {
                (
                    (&raw const (*in4).sin_addr).read(),
                    (&raw const (*in4).sin_port).read(),
                )
            };

            #[cfg(not(windows))]
            let ip_addr = Ipv4Addr::from(u32::from_be(sin_addr.s_addr));
            #[cfg(windows)]
            let ip_addr = {
                let ip_bytes = unsafe { sin_addr.S_un.S_un_b };

                Ipv4Addr::from([
                    ip_bytes.s_b1,
                    ip_bytes.s_b2,
                    ip_bytes.s_b3,
                    ip_bytes.s_b4,
                ])
            };

            let port = u16::from_be(sin_port);

            let out = SocketAddrV4::new(ip_addr, port);

            Ok(out.into())
        },

        AF_INET6 => {
            let in6 = addr.cast::<sockaddr_in6>();
            if len != size_of::<sockaddr_in6>() || !in6.is_aligned() {
                return Err(());
            }

            // SAFETY: length, family and alignment match sockaddr_in6.
            let (sin6_addr, sin6_port, flowinfo) = unsafe {
                (
                    (&raw const (*in6).sin6_addr).read(),
                    (&raw const (*in6).sin6_port).read(),
                    (&raw const (*in6).sin6_flowinfo).read(),
                )
            };

            let ip_addr = Ipv6Addr::from(
                #[cfg(not(windows))]
                sin6_addr.s6_addr,
                #[cfg(windows)]
                unsafe {
                    sin6_addr.u.Byte
                },
            );

            let port = u16::from_be(sin6_port);

            #[cfg(not(windows))]
            // SAFETY: the validated IPv6 layout contains this initialized field.
            let scope_id = unsafe { (&raw const (*in6).sin6_scope_id).read() };
            #[cfg(windows)]
            // SAFETY: read the scope ID from the validated IPv6 union layout.
            let scope_id =
                unsafe { (&raw const (*in6).Anonymous.sin6_scope_id).read() };

            let out = SocketAddrV6::new(ip_addr, port, flowinfo, scope_id);

            Ok(out.into())
        },

        _ => Err(()),
    }
}

fn std_addr_to_c(addr: &SocketAddr, out: &mut sockaddr_storage) -> socklen_t {
    let sin_port = addr.port().to_be();

    match addr {
        SocketAddr::V4(addr) => unsafe {
            let sa_len = size_of::<sockaddr_in>();
            let out_in = out as *mut _ as *mut sockaddr_in;

            let s_addr = u32::from_ne_bytes(addr.ip().octets());

            #[cfg(not(windows))]
            let sin_addr = in_addr { s_addr };
            #[cfg(windows)]
            let sin_addr = in_addr {
                S_un: IN_ADDR_0 { S_addr: s_addr },
            };

            *out_in = sockaddr_in {
                sin_family: AF_INET as sa_family_t,

                sin_addr,

                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "watchos",
                    target_os = "freebsd",
                    target_os = "dragonfly",
                    target_os = "openbsd",
                    target_os = "netbsd"
                ))]
                sin_len: sa_len as u8,

                sin_port,

                sin_zero: std::mem::zeroed(),
            };

            sa_len as socklen_t
        },

        SocketAddr::V6(addr) => unsafe {
            let sa_len = size_of::<sockaddr_in6>();
            let out_in6 = out as *mut _ as *mut sockaddr_in6;

            #[cfg(not(windows))]
            let sin6_addr = in6_addr {
                s6_addr: addr.ip().octets(),
            };
            #[cfg(windows)]
            let sin6_addr = in6_addr {
                u: IN6_ADDR_0 {
                    Byte: addr.ip().octets(),
                },
            };

            *out_in6 = sockaddr_in6 {
                sin6_family: AF_INET6 as sa_family_t,

                sin6_addr,

                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "watchos",
                    target_os = "freebsd",
                    target_os = "dragonfly",
                    target_os = "openbsd",
                    target_os = "netbsd"
                ))]
                sin6_len: sa_len as u8,

                sin6_port: sin_port,

                sin6_flowinfo: addr.flowinfo(),

                #[cfg(not(windows))]
                sin6_scope_id: addr.scope_id(),
                #[cfg(windows)]
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: addr.scope_id(),
                },
            };

            sa_len as socklen_t
        },
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "windows")))]
fn monotonic_deadline_timespec(
    deadline: Instant, anchor: Instant, clock: timespec,
) -> Option<timespec> {
    // A kernel CLOCK_MONOTONIC reading must be normalized and nonnegative.
    // Validate it before using it as the anchor for Rust's opaque Instant.
    if clock.tv_sec < 0 || !(0..1_000_000_000).contains(&clock.tv_nsec) {
        return None;
    }

    let base = i128::from(clock.tv_sec)
        .checked_mul(1_000_000_000)?
        .checked_add(i128::from(clock.tv_nsec))?;
    let offset = if deadline >= anchor {
        i128::try_from(deadline.duration_since(anchor).as_nanos()).ok()?
    } else {
        i128::try_from(anchor.duration_since(deadline).as_nanos())
            .ok()?
            .checked_neg()?
    };

    let ns = base.checked_add(offset)?;
    if ns < 0 {
        return None;
    }

    Some(timespec {
        tv_sec: libc::time_t::try_from(ns.div_euclid(1_000_000_000)).ok()?,
        tv_nsec: libc::c_long::try_from(ns.rem_euclid(1_000_000_000)).ok()?,
    })
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "windows")))]
fn std_time_to_c(time: &Instant, out: &mut timespec) {
    // Bracket the kernel clock reading with Instant samples. Their midpoint
    // bounds scheduling skew without depending on Instant's private layout.
    let before = Instant::now();
    let mut clock = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock is initialized, writable, and the kernel writes a
    // timespec to it on success.
    let sampled = unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut clock) == 0
    };
    let after = Instant::now();

    let converted = if sampled {
        after
            .checked_duration_since(before)
            .and_then(|span| before.checked_add(span / 2))
            .and_then(|anchor| monotonic_deadline_timespec(*time, anchor, clock))
    } else {
        None
    };

    // The C-facing API historically encodes unrepresentable times as zero.
    *out = converted.unwrap_or(timespec {
        tv_sec: 0,
        tv_nsec: 0,
    });
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "windows"))]
fn std_time_to_c(_time: &Instant, out: &mut timespec) {
    // TODO: implement Instant conversion for systems that don't use timespec.
    out.tv_sec = 0;
    out.tv_nsec = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    use libc::c_void;
    #[cfg(windows)]
    use windows_sys::Win32::Networking::WinSock::inet_ntop;

    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )))]
    #[test]
    fn ffi_monotonic_timestamp_preserves_deadline_spacing() {
        let anchor = Instant::now();
        let clock = timespec {
            tv_sec: 10,
            tv_nsec: 100,
        };

        let first = monotonic_deadline_timespec(anchor, anchor, clock)
            .expect("valid monotonic anchor");
        assert_eq!(first.tv_sec, 10);
        assert_eq!(first.tv_nsec, 100);

        let later = monotonic_deadline_timespec(
            anchor + Duration::from_millis(50),
            anchor,
            clock,
        )
        .expect("valid later deadline");
        assert_eq!(later.tv_sec, 10);
        assert_eq!(later.tv_nsec, 50_000_100);

        let earlier = monotonic_deadline_timespec(
            anchor - Duration::from_millis(200),
            anchor,
            clock,
        )
        .expect("valid earlier deadline");
        assert_eq!(earlier.tv_sec, 9);
        assert_eq!(earlier.tv_nsec, 800_000_100);

        let crossing = monotonic_deadline_timespec(
            anchor + Duration::from_secs(2),
            anchor,
            timespec {
                tv_sec: 10,
                tv_nsec: 999_999_999,
            },
        )
        .expect("valid second rollover");
        assert_eq!(crossing.tv_sec, 12);
        assert_eq!(crossing.tv_nsec, 999_999_999);
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )))]
    #[test]
    fn ffi_monotonic_conversion_rejects_invalid_or_unrepresentable_times() {
        let anchor = Instant::now();
        let ts = |seconds, nanos| timespec {
            tv_sec: seconds,
            tv_nsec: nanos,
        };
        assert!(monotonic_deadline_timespec(anchor, anchor, ts(2, -1)).is_none());
        assert!(monotonic_deadline_timespec(
            anchor,
            anchor,
            ts(2, 1_000_000_000)
        )
        .is_none());
        assert!(monotonic_deadline_timespec(anchor, anchor, ts(-1, 0)).is_none());
        assert!(monotonic_deadline_timespec(
            anchor - Duration::from_secs(2),
            anchor,
            ts(1, 0)
        )
        .is_none());

        let too_large = anchor + Duration::from_secs(2);
        assert!(monotonic_deadline_timespec(
            too_large,
            anchor,
            ts(libc::time_t::MAX, 999_999_999)
        )
        .is_none());
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )))]
    #[test]
    fn ffi_real_monotonic_timestamp_is_normalized() {
        let now = Instant::now();
        let mut ts = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        std_time_to_c(&now, &mut ts);
        assert!(ts.tv_sec > 0);
        assert!((0..1_000_000_000).contains(&ts.tv_nsec));
    }

    #[test]
    fn invalid_utf8_ffi_string_returns_invalid_argument() {
        let mut config = Config::new(PROTOCOL_VERSION).unwrap();
        let invalid = [0xff_u8, 0];

        assert_eq!(
            quiche_config_set_cc_algorithm_name(
                &mut config,
                invalid.as_ptr().cast(),
            ),
            c_int::from(FFI_ERR_INVALID_ARGUMENT)
        );
    }

    #[test]
    fn peer_transport_params_write_full_width_into_uninitialized_storage() {
        let mut config = test_utils::Pipe::default_config("cubic").unwrap();
        config.local_transport_params.max_datagram_frame_size =
            Some(octets::MAX_VAR_INT);
        config.local_transport_params.disable_active_migration = true;
        let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
        let mut out = MaybeUninit::<TransportParams>::uninit();
        assert!(!quiche_conn_peer_transport_params(
            &pipe.client,
            out.as_mut_ptr()
        ));
        pipe.handshake().unwrap();
        assert!(quiche_conn_peer_transport_params(
            &pipe.client,
            out.as_mut_ptr()
        ));
        // SAFETY: the API returned true, so every field has been initialized.
        let out = unsafe { out.assume_init() };
        let peer = pipe.client.peer_transport_params().unwrap();
        assert_eq!(
            out.max_datagram_frame_size,
            i64::try_from(octets::MAX_VAR_INT).unwrap()
        );
        assert_eq!(out.max_udp_payload_size, peer.max_udp_payload_size);
        assert_eq!(out.active_conn_id_limit, peer.active_conn_id_limit);
        assert!(out.disable_active_migration);
    }

    #[test]
    fn connection_and_path_stats_initialize_output_storage() {
        let mut config = test_utils::Pipe::default_config("cubic").unwrap();
        let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();
        let mut stats = MaybeUninit::<Stats>::uninit();
        quiche_conn_stats(&pipe.client, stats.as_mut_ptr());
        // SAFETY: the connection and output pointer are valid.
        let stats = unsafe { stats.assume_init() };
        assert_eq!(stats.paths_count, pipe.client.stats().paths_count);
        assert_eq!(stats.recv, pipe.client.stats().recv);
        let mut path = MaybeUninit::<PathStats>::uninit();
        assert_eq!(
            quiche_conn_path_stats(&pipe.client, 0, path.as_mut_ptr()),
            0
        );
        // SAFETY: the successful call initialized all fields.
        let path = unsafe { path.assume_init() };
        assert_eq!(path.pmtu, pipe.client.max_send_udp_payload_size());
    }

    #[test]
    fn oversized_ffi_length_returns_invalid_argument() {
        assert_eq!(validate_ssize_len(ssize_t::MAX as usize), Ok(()));
        assert_eq!(
            validate_ssize_len(ssize_t::MAX as usize + 1),
            Err(ssize_t::from(FFI_ERR_INVALID_ARGUMENT))
        );
    }

    #[rstest::rstest]
    fn send_initializes_c_packet_metadata(
        #[values(false, true)] specified_path: bool,
    ) {
        let mut pipe = test_utils::Pipe::new("cubic").unwrap();
        let mut info = MaybeUninit::<SendInfo>::uninit();
        let mut buf = [0; 1500];
        let written = if specified_path {
            let mut from = unsafe { std::mem::zeroed() };
            let mut to = unsafe { std::mem::zeroed() };
            let from_len =
                std_addr_to_c(&test_utils::Pipe::client_addr(), &mut from);
            let to_len = std_addr_to_c(&test_utils::Pipe::server_addr(), &mut to);
            quiche_conn_send_on_path(
                &mut pipe.client,
                buf.as_mut_ptr(),
                buf.len(),
                (&raw const from).cast(),
                from_len,
                (&raw const to).cast(),
                to_len,
                info.as_mut_ptr(),
            )
        } else {
            quiche_conn_send(
                &mut pipe.client,
                buf.as_mut_ptr(),
                buf.len(),
                info.as_mut_ptr(),
            )
        };
        assert!(written > 0);
        // SAFETY: positive send return means the complete SendInfo was written.
        let info = unsafe { info.assume_init() };
        assert_eq!(
            unsafe {
                std_addr_from_c((&raw const info.from).cast(), info.from_len)
            },
            Ok(test_utils::Pipe::client_addr())
        );
        assert_eq!(
            unsafe { std_addr_from_c((&raw const info.to).cast(), info.to_len) },
            Ok(test_utils::Pipe::server_addr())
        );
    }

    #[test]
    fn receive_info_rejects_null_nested_address() {
        let mut pipe = test_utils::Pipe::new("cubic").unwrap();
        let info = RecvInfo {
            from: ptr::null(),
            from_len: size_of::<sockaddr_in>() as socklen_t,
            to: ptr::null(),
            to_len: 0,
        };
        let mut buf = [0; 32];
        assert_eq!(
            quiche_conn_recv(
                &mut pipe.server,
                buf.as_mut_ptr(),
                buf.len(),
                &info
            ),
            ssize_t::from(FFI_ERR_INVALID_ARGUMENT)
        );
    }

    #[test]
    fn address_decoder_checks_length_before_reading_memory() {
        // SAFETY: invalid lengths and nulls are rejected before reading.
        let dangling = ptr::NonNull::<sockaddr>::dangling().as_ptr();
        for len in [0, 1, 2, 3, 7] {
            assert_eq!(unsafe { std_addr_from_c(dangling, len) }, Err(()));
        }
        assert_eq!(
            unsafe {
                std_addr_from_c(
                    ptr::null(),
                    size_of::<sockaddr_in6>() as socklen_t,
                )
            },
            Err(())
        );
    }

    #[test]
    fn malformed_sockaddr_is_rejected() {
        let mut addr: sockaddr = unsafe { std::mem::zeroed() };
        addr.sa_family = AF_INET as sa_family_t;

        assert_eq!(unsafe { std_addr_from_c(&addr, 0) }, Err(()));

        addr.sa_family = 0;
        assert_eq!(
            unsafe {
                std_addr_from_c(&addr, size_of::<sockaddr_in>() as socklen_t)
            },
            Err(())
        );
    }

    #[test]
    fn mismatched_path_event_accessor_is_noop() {
        let local = "127.0.0.1:8080".parse().unwrap();
        let peer = "127.0.0.2:443".parse().unwrap();
        let event = PathEvent::New(local, peer);
        let mut local_out: sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut peer_out: sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut local_len = 11;
        let mut peer_len = 12;
        let mut pmtu = 13;

        quiche_path_event_pmtu_updated(
            &event,
            &mut local_out,
            &mut local_len,
            &mut peer_out,
            &mut peer_len,
            &mut pmtu,
        );

        assert_eq!(local_len, 11);
        assert_eq!(peer_len, 12);
        assert_eq!(pmtu, 13);
    }

    #[test]
    fn pmtu_updated_path_event() {
        let local = "127.0.0.1:8080".parse().unwrap();
        let peer = "127.0.0.2:443".parse().unwrap();

        let event = PathEvent::PmtuUpdated {
            local,
            peer,
            pmtu: 1400,
        };
        assert_eq!(quiche_path_event_type(&event), 6);

        let mut local_out: sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut peer_out: sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut local_len = 0;
        let mut peer_len = 0;
        let mut pmtu = usize::MAX;

        quiche_path_event_pmtu_updated(
            &event,
            &mut local_out,
            &mut local_len,
            &mut peer_out,
            &mut peer_len,
            &mut pmtu,
        );
        assert_eq!(pmtu, 1400);
        assert_eq!(
            unsafe {
                std_addr_from_c(
                    (&raw const local_out).cast::<sockaddr>(),
                    local_len,
                )
            },
            Ok(local)
        );
        assert_eq!(
            unsafe {
                std_addr_from_c(
                    (&raw const peer_out).cast::<sockaddr>(),
                    peer_len,
                )
            },
            Ok(peer)
        );
    }

    #[test]
    fn addr_v4() {
        let addr = "127.0.0.1:8080".parse().unwrap();

        let mut out: sockaddr_storage = unsafe { std::mem::zeroed() };

        assert_eq!(
            std_addr_to_c(&addr, &mut out),
            size_of::<sockaddr_in>() as socklen_t
        );

        let s = ffi::CString::new("ddd.ddd.ddd.ddd").unwrap();

        let s = unsafe {
            let in_addr = &out as *const _ as *const sockaddr_in;
            assert_eq!(u16::from_be((*in_addr).sin_port), addr.port());

            let dst = s.into_raw();

            inet_ntop(
                AF_INET as _,
                &((*in_addr).sin_addr) as *const _ as *const c_void,
                dst as _,
                16,
            );

            ffi::CString::from_raw(dst).into_string().unwrap()
        };

        assert_eq!(s, "127.0.0.1");

        let addr = unsafe {
            std_addr_from_c(
                (&raw const out).cast::<sockaddr>(),
                size_of::<sockaddr_in>() as socklen_t,
            )
        };

        assert_eq!(addr, Ok("127.0.0.1:8080".parse().unwrap()));
    }

    #[test]
    fn addr_v6() {
        let addr = "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080"
            .parse()
            .unwrap();

        let mut out: sockaddr_storage = unsafe { std::mem::zeroed() };

        assert_eq!(
            std_addr_to_c(&addr, &mut out),
            size_of::<sockaddr_in6>() as socklen_t
        );

        let s =
            ffi::CString::new("dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd").unwrap();

        let s = unsafe {
            let in6_addr = &out as *const _ as *const sockaddr_in6;
            assert_eq!(u16::from_be((*in6_addr).sin6_port), addr.port());

            let dst = s.into_raw();

            inet_ntop(
                AF_INET6 as _,
                &((*in6_addr).sin6_addr) as *const _ as *const c_void,
                dst as _,
                45,
            );

            ffi::CString::from_raw(dst).into_string().unwrap()
        };

        assert_eq!(s, "2001:db8:85a3::8a2e:370:7334");

        let addr = unsafe {
            std_addr_from_c(
                (&raw const out).cast::<sockaddr>(),
                size_of::<sockaddr_in6>() as socklen_t,
            )
        };

        assert_eq!(
            addr,
            Ok("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080"
                .parse()
                .unwrap())
        );
    }

    #[test]
    fn connection_id_iter_next() {
        let cids = vec![
            ConnectionId::from_vec(vec![1, 2, 3, 4]),
            ConnectionId::from_vec(vec![5, 6]),
        ];

        let mut iter = ConnectionIdIter { cids, index: 0 };

        let mut out: *const u8 = ptr::null();
        let mut out_len: size_t = 0;

        // First CID.
        assert!(quiche_connection_id_iter_next(
            &mut iter,
            &mut out,
            &mut out_len
        ));
        assert_eq!(out_len, 4);
        let slice = unsafe { slice::from_raw_parts(out, out_len) };
        assert_eq!(slice, &[1, 2, 3, 4]);

        // Second CID.
        assert!(quiche_connection_id_iter_next(
            &mut iter,
            &mut out,
            &mut out_len
        ));
        assert_eq!(out_len, 2);
        let slice = unsafe { slice::from_raw_parts(out, out_len) };
        assert_eq!(slice, &[5, 6]);

        // Exhausted.
        assert!(!quiche_connection_id_iter_next(
            &mut iter,
            &mut out,
            &mut out_len
        ));
    }

    #[test]
    fn retired_scid_iter() {
        let mut config = Config::new(PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config
            .set_application_protos(&[b"proto1", b"proto2"])
            .unwrap();
        config.verify_peer(false);
        config.set_active_connection_id_limit(2);

        let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));

        let scid = pipe.client.source_id().into_owned();

        let (scid_1, reset_token_1) = test_utils::create_cid_and_reset_token(16);
        assert_eq!(pipe.client.new_scid(&scid_1, reset_token_1, false), Ok(1));
        assert_eq!(pipe.advance(), Ok(()));

        // Retire the initial SCID by advertising a new one with
        // retire_prior_to.
        let (scid_2, reset_token_2) = test_utils::create_cid_and_reset_token(16);
        assert_eq!(pipe.client.new_scid(&scid_2, reset_token_2, true), Ok(2));
        assert_eq!(pipe.advance(), Ok(()));

        // Use the FFI iterator to collect retired SCIDs.
        let iter = quiche_conn_retired_scid_iter(&mut pipe.client);
        let iter = unsafe { &mut *iter };

        let mut out: *const u8 = ptr::null();
        let mut out_len: size_t = 0;

        // The initial SCID should have been retired.
        assert!(quiche_connection_id_iter_next(iter, &mut out, &mut out_len));
        let slice = unsafe { slice::from_raw_parts(out, out_len) };
        assert_eq!(slice, scid.as_ref());

        // No more retired SCIDs.
        assert!(!quiche_connection_id_iter_next(
            iter,
            &mut out,
            &mut out_len
        ));

        quiche_connection_id_iter_free(iter);
    }

    #[test]
    fn null_reference_parameters_are_rejected_at_ffi_boundary() {
        // Void setters become safe no-ops.
        quiche_config_grease(ptr::null_mut(), true);

        // APIs with an explicit error channel use the existing C-only
        // invalid-argument code.
        assert_eq!(
            quiche_conn_stream_writable(ptr::null_mut(), 0, 0),
            c_int::from(FFI_ERR_INVALID_ARGUMENT)
        );
        assert_eq!(
            quiche_conn_dgram_recv_front_len(ptr::null()),
            ssize_t::from(FFI_ERR_INVALID_ARGUMENT)
        );
        assert_eq!(
            quiche_conn_stream_readable_next(ptr::null_mut()),
            i64::from(FFI_ERR_INVALID_ARGUMENT)
        );

        // APIs without an error channel use their documented neutral sentinel.
        assert!(!quiche_conn_stream_readable(ptr::null(), 0));
        assert!(quiche_conn_readable(ptr::null()).is_null());
        assert_eq!(quiche_conn_max_send_udp_payload_size(ptr::null()), 0);
        assert_eq!(quiche_conn_timeout_as_nanos(ptr::null()), 0);
        assert_eq!(quiche_conn_send_quantum(ptr::null()), 0);
        assert_eq!(quiche_path_event_type(ptr::null()), -1);
    }

    #[test]
    fn checked_raw_pointers_reject_null_and_misalignment() {
        // SAFETY: these helpers validate pointer metadata before dereference.
        assert!(unsafe { ffi_ptr_ref::<u16>(ptr::null()) }.is_none());
        assert!(unsafe { ffi_ptr_mut::<u16>(ptr::null_mut()) }.is_none());

        let aligned = ptr::NonNull::<u16>::dangling().as_ptr();
        let misaligned = aligned.cast::<u8>().wrapping_add(1).cast::<u16>();
        assert!(unsafe { ffi_ptr_ref(misaligned) }.is_none());
        assert!(unsafe { ffi_ptr_mut(misaligned) }.is_none());

        let addr = ptr::NonNull::<sockaddr>::dangling().as_ptr();
        let misaligned_addr =
            addr.cast::<u8>().wrapping_add(1).cast::<sockaddr>();
        assert!(unsafe {
            optional_std_addr_from_c(
                misaligned_addr,
                size_of::<sockaddr>() as socklen_t,
            )
        }
        .is_err());
    }

    #[test]
    fn checked_raw_slices_accept_null_zero_and_reject_invalid_parts() {
        // SAFETY: zero-length slices do not access their pointer.
        let shared =
            unsafe { ffi_slice_from_raw_parts::<u8>(ptr::null(), 0) }.unwrap();
        assert!(shared.is_empty());

        // SAFETY: zero-length slices do not access their pointer.
        let mutable =
            unsafe { ffi_slice_from_raw_parts_mut::<u8>(ptr::null_mut(), 0) }
                .unwrap();
        assert!(mutable.is_empty());

        // SAFETY: these calls only validate pointer metadata and return before
        // dereferencing the deliberately invalid pointers.
        assert!(
            unsafe { ffi_slice_from_raw_parts::<u8>(ptr::null(), 1) }.is_none()
        );
        assert!(unsafe {
            ffi_slice_from_raw_parts_mut::<u8>(ptr::null_mut(), 1)
        }
        .is_none());

        let aligned = ptr::NonNull::<u16>::dangling().as_ptr();
        let misaligned = aligned.cast::<u8>().wrapping_add(1).cast::<u16>();
        // SAFETY: the helper rejects the misaligned pointer before dereference.
        assert!(unsafe { ffi_slice_from_raw_parts(misaligned, 1) }.is_none());

        let too_long = (isize::MAX as usize / size_of::<u16>()) + 1;
        // SAFETY: the helper rejects the oversized slice before dereference.
        assert!(unsafe { ffi_slice_from_raw_parts(aligned, too_long) }.is_none());
    }

    #[test]
    fn raw_buffer_outputs_reject_null_without_breaking_null_zero_buffers() {
        let mut value = 0_u64;

        assert_eq!(
            quiche_get_varint(ptr::null(), 0, ptr::null_mut()),
            ssize_t::from(FFI_ERR_INVALID_ARGUMENT)
        );

        // NULL,0 is a valid empty input buffer. Parsing still fails normally
        // because an empty buffer contains no varint, rather than because the
        // pointer itself is null.
        assert_eq!(
            quiche_get_varint(ptr::null(), 0, &mut value),
            ssize_t::from(Error::BufferTooShort.to_c())
        );
        assert_eq!(
            quiche_put_varint(ptr::null_mut(), 0, 0),
            c_int::from(Error::BufferTooShort.to_c())
        );

        assert_eq!(
            quiche_header_info(
                ptr::null_mut(),
                0,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            ),
            c_int::from(FFI_ERR_INVALID_ARGUMENT)
        );
    }

    #[cfg(not(windows))]
    extern "C" {
        fn inet_ntop(
            af: c_int, src: *const c_void, dst: *mut c_char, size: socklen_t,
        ) -> *mut c_char;
    }
}
