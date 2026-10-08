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

const FFI_ERR_INVALID_ARGUMENT: ssize_t = -24;

unsafe fn ffi_ptr_ref<'a, T>(ptr: *const T) -> Option<&'a T> {
    if ptr.is_null() || !(ptr as usize).is_multiple_of(align_of::<T>()) {
        return None;
    }

    // SAFETY: null and alignment are checked above. Allocation validity and
    // lifetime remain part of the C caller contract.
    Some(unsafe { &*ptr })
}

unsafe fn ffi_ptr_mut<'a, T>(ptr: *mut T) -> Option<&'a mut T> {
    if ptr.is_null() || !(ptr as usize).is_multiple_of(align_of::<T>()) {
        return None;
    }

    // SAFETY: null and alignment are checked above. Allocation validity,
    // lifetime and exclusivity remain part of the C caller contract.
    Some(unsafe { &mut *ptr })
}

macro_rules! ffi_ref {
    ($ptr:expr) => {{
        // SAFETY: C callers may pass null. Non-null pointers retain the same
        // validity/alignment/lifetime requirements as the public C API.
        match unsafe { ffi_ptr_ref($ptr) } {
            Some(value) => value,
            None => return,
        }
    }};
    ($ptr:expr, $ret:expr) => {{
        // SAFETY: C callers may pass null. Non-null pointers retain the same
        // validity/alignment/lifetime requirements as the public C API.
        match unsafe { ffi_ptr_ref($ptr) } {
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
        match unsafe { ffi_ptr_mut($ptr) } {
            Some(value) => value,
            None => return,
        }
    }};
    ($ptr:expr, $ret:expr) => {{
        // SAFETY: C callers may pass null. Non-null pointers retain the same
        // validity/alignment/lifetime/exclusivity requirements as the public
        // C API.
        match unsafe { ffi_ptr_mut($ptr) } {
            Some(value) => value,
            None => return $ret,
        }
    }};
}

fn ffi_slice_layout_valid<T>(ptr: *const T, len: usize) -> bool {
    if len == 0 {
        return true;
    }

    if ptr.is_null() || !(ptr as usize).is_multiple_of(align_of::<T>()) {
        return false;
    }

    size_of::<T>()
        .checked_mul(len)
        .is_some_and(|bytes| bytes <= isize::MAX as usize)
}

/// Builds a shared slice from a C pointer after checking the parts that can be
/// validated without dereferencing caller memory.
///
/// # Safety
///
/// For non-empty slices, \`ptr\` must still point to \`len\` initialized \`T\`
/// values in one live allocation for the returned lifetime.
unsafe fn ffi_slice_from_raw_parts<'a, T>(
    ptr: *const T, len: usize,
) -> Option<&'a [T]> {
    if len == 0 {
        // SAFETY: NonNull::dangling() is non-null and correctly aligned, and a
        // zero-length slice does not access the pointee.
        return Some(unsafe {
            slice::from_raw_parts(ptr::NonNull::<T>::dangling().as_ptr(), 0)
        });
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
unsafe fn ffi_slice_from_raw_parts_mut<'a, T>(
    ptr: *mut T, len: usize,
) -> Option<&'a mut [T]> {
    if len == 0 {
        // SAFETY: NonNull::dangling() is non-null and correctly aligned, and a
        // zero-length slice does not access the pointee.
        return Some(unsafe {
            slice::from_raw_parts_mut(ptr::NonNull::<T>::dangling().as_ptr(), 0)
        });
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
        match unsafe { ffi_slice_from_raw_parts($ptr, $len) } {
            Some(value) => value,
            None => return,
        }
    }};
    ($ptr:expr, $len:expr, $ret:expr) => {{
        match unsafe { ffi_slice_from_raw_parts($ptr, $len) } {
            Some(value) => value,
            None => return $ret,
        }
    }};
}

macro_rules! ffi_slice_mut {
    ($ptr:expr, $len:expr, $ret:expr) => {{
        match unsafe { ffi_slice_from_raw_parts_mut($ptr, $len) } {
            Some(value) => value,
            None => return $ret,
        }
    }};
}

fn validate_ssize_len(len: size_t) -> std::result::Result<(), ssize_t> {
    if len > ssize_t::MAX as usize {
        Err(FFI_ERR_INVALID_ARGUMENT)
    } else {
        Ok(())
    }
}

/// Converts a non-null NUL-terminated C string to owned UTF-8.
///
/// # Safety
///
/// `value` must point to a valid NUL-terminated C string for the duration of
/// this call.
unsafe fn c_str_to_string(
    value: *const c_char,
) -> std::result::Result<String, ()> {
    if value.is_null() {
        return Err(());
    }

    unsafe { ffi::CStr::from_ptr(value) }
        .to_str()
        .map(str::to_owned)
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

#[no_mangle]
pub extern "C" fn quiche_config_load_cert_chain_from_pem_file(
    config: *mut Config, path: *const c_char,
) -> c_int {
    let config = ffi_mut!(config, FFI_ERR_INVALID_ARGUMENT as c_int);

    let Ok(path) = (unsafe { c_str_to_string(path) }) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };

    match config.load_cert_chain_from_pem_file(&path) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_config_load_priv_key_from_pem_file(
    config: *mut Config, path: *const c_char,
) -> c_int {
    let config = ffi_mut!(config, FFI_ERR_INVALID_ARGUMENT as c_int);

    let Ok(path) = (unsafe { c_str_to_string(path) }) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };

    match config.load_priv_key_from_pem_file(&path) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_config_load_verify_locations_from_file(
    config: *mut Config, path: *const c_char,
) -> c_int {
    let config = ffi_mut!(config, FFI_ERR_INVALID_ARGUMENT as c_int);

    let Ok(path) = (unsafe { c_str_to_string(path) }) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };

    match config.load_verify_locations_from_file(&path) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_config_load_verify_locations_from_directory(
    config: *mut Config, path: *const c_char,
) -> c_int {
    let config = ffi_mut!(config, FFI_ERR_INVALID_ARGUMENT as c_int);

    let Ok(path) = (unsafe { c_str_to_string(path) }) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };

    match config.load_verify_locations_from_directory(&path) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_config_set_curves_list(
    config: *mut Config, curves: *const c_char,
) -> c_int {
    let config = ffi_mut!(config, FFI_ERR_INVALID_ARGUMENT as c_int);

    let Ok(curves) = (unsafe { c_str_to_string(curves) }) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };

    match config.set_curves_list(&curves) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
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
    let config = ffi_mut!(config, FFI_ERR_INVALID_ARGUMENT as c_int);

    let protos =
        ffi_slice!(protos, protos_len, FFI_ERR_INVALID_ARGUMENT as c_int);

    match config.set_application_protos_wire_format(protos) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
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
    let config = ffi_mut!(config, FFI_ERR_INVALID_ARGUMENT as c_int);

    let Ok(name) = (unsafe { c_str_to_string(name) }) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };
    match config.set_cc_algorithm_name(&name) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
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
    let config = ffi_mut!(config, FFI_ERR_INVALID_ARGUMENT as c_int);

    let key = ffi_slice!(key, key_len, FFI_ERR_INVALID_ARGUMENT as c_int);

    match config.set_ticket_key(key) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
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
    let version = ffi_mut!(version, FFI_ERR_INVALID_ARGUMENT as c_int);
    let ty = ffi_mut!(ty, FFI_ERR_INVALID_ARGUMENT as c_int);
    let scid_len = ffi_mut!(scid_len, FFI_ERR_INVALID_ARGUMENT as c_int);
    let dcid_len = ffi_mut!(dcid_len, FFI_ERR_INVALID_ARGUMENT as c_int);
    let token_len = ffi_mut!(token_len, FFI_ERR_INVALID_ARGUMENT as c_int);
    let buf = ffi_slice_mut!(buf, buf_len, FFI_ERR_INVALID_ARGUMENT as c_int);
    let hdr = match Header::from_slice(buf, dcil) {
        Ok(v) => v,

        Err(e) => return e.to_c() as c_int,
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

    let scid = ffi_slice_mut!(scid, *scid_len, FFI_ERR_INVALID_ARGUMENT as c_int);
    let scid = &mut scid[..hdr.scid.len()];
    scid.copy_from_slice(&hdr.scid);

    *scid_len = hdr.scid.len();

    if *dcid_len < hdr.dcid.len() {
        return -1;
    }

    let dcid = ffi_slice_mut!(dcid, *dcid_len, FFI_ERR_INVALID_ARGUMENT as c_int);
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
                FFI_ERR_INVALID_ARGUMENT as c_int
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
    let local = ffi_ref!(local, ptr::null_mut());
    let peer = ffi_ref!(peer, ptr::null_mut());
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

    let Ok(local) = std_addr_from_c(local, local_len) else {
        return ptr::null_mut();
    };
    let Ok(peer) = std_addr_from_c(peer, peer_len) else {
        return ptr::null_mut();
    };

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
    let local = ffi_ref!(local, ptr::null_mut());
    let peer = ffi_ref!(peer, ptr::null_mut());
    let config = ffi_mut!(config, ptr::null_mut());

    let server_name = if server_name.is_null() {
        None
    } else {
        let Ok(server_name) = (unsafe { c_str_to_string(server_name) }) else {
            return ptr::null_mut();
        };
        Some(server_name)
    };

    let scid = ffi_slice!(scid, scid_len, ptr::null_mut());
    let scid = ConnectionId::from_ref(scid);

    let Ok(local) = std_addr_from_c(local, local_len) else {
        return ptr::null_mut();
    };
    let Ok(peer) = std_addr_from_c(peer, peer_len) else {
        return ptr::null_mut();
    };

    match connect(server_name.as_deref(), &scid, local, peer, config) {
        Ok(c) => Box::into_raw(Box::new(c)),

        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_negotiate_version(
    scid: *const u8, scid_len: size_t, dcid: *const u8, dcid_len: size_t,
    out: *mut u8, out_len: size_t,
) -> ssize_t {
    let scid = ffi_slice!(scid, scid_len, FFI_ERR_INVALID_ARGUMENT);
    let scid = ConnectionId::from_ref(scid);

    let dcid = ffi_slice!(dcid, dcid_len, FFI_ERR_INVALID_ARGUMENT);
    let dcid = ConnectionId::from_ref(dcid);

    let out = ffi_slice_mut!(out, out_len, FFI_ERR_INVALID_ARGUMENT);

    match negotiate_version(&scid, &dcid, out) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
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
    let scid = ffi_slice!(scid, scid_len, FFI_ERR_INVALID_ARGUMENT);
    let scid = ConnectionId::from_ref(scid);

    let dcid = ffi_slice!(dcid, dcid_len, FFI_ERR_INVALID_ARGUMENT);
    let dcid = ConnectionId::from_ref(dcid);

    let new_scid = ffi_slice!(new_scid, new_scid_len, FFI_ERR_INVALID_ARGUMENT);
    let new_scid = ConnectionId::from_ref(new_scid);

    let token = ffi_slice!(token, token_len, FFI_ERR_INVALID_ARGUMENT);
    let out = ffi_slice_mut!(out, out_len, FFI_ERR_INVALID_ARGUMENT);

    match retry(&scid, &dcid, &new_scid, token, version, out) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
#[cfg(feature = "custom-client-dcid")]
pub extern "C" fn quiche_conn_new_with_tls_and_client_dcid(
    scid: *const u8, scid_len: size_t, dcid: *const u8, dcid_len: size_t,
    local: *const sockaddr, local_len: socklen_t, peer: *const sockaddr,
    peer_len: socklen_t, config: *const Config, ssl: *mut c_void,
) -> *mut Connection {
    let local = ffi_ref!(local, ptr::null_mut());
    let peer = ffi_ref!(peer, ptr::null_mut());
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

        let Ok(local) = std_addr_from_c(local, local_len) else {
            return ptr::null_mut();
        };
        let Ok(peer) = std_addr_from_c(peer, peer_len) else {
            return ptr::null_mut();
        };

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
#[allow(
    unused_variables,
    reason = "Feature-disabled FFI stub preserves the public ABI while rejecting every call"
)]
pub extern "C" fn quiche_conn_new_with_tls_and_client_dcid(
    scid: *const u8, scid_len: size_t, dcid: *const u8, dcid_len: size_t,
    local: *const sockaddr, local_len: socklen_t, peer: *const sockaddr,
    peer_len: socklen_t, config: *const Config, ssl: *mut c_void,
) -> *mut Connection {
    let local = ffi_ref!(local, ptr::null_mut());
    let peer = ffi_ref!(peer, ptr::null_mut());
    let config = ffi_ref!(config, ptr::null_mut());

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
    let local = ffi_ref!(local, ptr::null_mut());
    let peer = ffi_ref!(peer, ptr::null_mut());
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

    let Ok(local) = std_addr_from_c(local, local_len) else {
        return ptr::null_mut();
    };
    let Ok(peer) = std_addr_from_c(peer, peer_len) else {
        return ptr::null_mut();
    };

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

    let Ok(filename) = (unsafe { c_str_to_string(path) }) else {
        return false;
    };

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&filename);

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

    let Ok(filename) = (unsafe { c_str_to_string(path) }) else {
        return false;
    };
    let Ok(title) = (unsafe { c_str_to_string(log_title) }) else {
        return false;
    };
    let Ok(description) = (unsafe { c_str_to_string(log_desc) }) else {
        return false;
    };

    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&filename);

    let writer = match file {
        Ok(f) => std::io::BufWriter::new(f),

        Err(_) => return false,
    };

    conn.set_qlog(
        Box::new(writer),
        title,
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

    let Ok(title) = (unsafe { c_str_to_string(log_title) }) else {
        return;
    };
    let Ok(description) = (unsafe { c_str_to_string(log_desc) }) else {
        return;
    };

    let f = unsafe { std::fs::File::from_raw_fd(fd) };
    let writer = std::io::BufWriter::new(f);

    conn.set_qlog(
        Box::new(writer),
        title,
        format!("{} id={}", description, conn.trace_id),
    );
}

#[no_mangle]
pub extern "C" fn quiche_conn_set_session(
    conn: *mut Connection, buf: *const u8, buf_len: size_t,
) -> c_int {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);

    let buf = ffi_slice!(buf, buf_len, FFI_ERR_INVALID_ARGUMENT as c_int);

    match conn.set_session(buf) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_set_max_idle_timeout(
    conn: *mut Connection, v: u64,
) -> c_int {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);

    match conn.set_max_idle_timeout(v) {
        Ok(()) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[repr(C)]
pub struct RecvInfo<'a> {
    from: &'a sockaddr,
    from_len: socklen_t,
    to: &'a sockaddr,
    to_len: socklen_t,
}

impl TryFrom<&RecvInfo<'_>> for crate::RecvInfo {
    type Error = ();

    fn try_from(info: &RecvInfo) -> std::result::Result<Self, Self::Error> {
        Ok(crate::RecvInfo {
            from: std_addr_from_c(info.from, info.from_len)?,
            to: std_addr_from_c(info.to, info.to_len)?,
        })
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_recv(
    conn: *mut Connection, buf: *mut u8, buf_len: size_t, info: *const RecvInfo,
) -> ssize_t {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);
    let info = ffi_ref!(info, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    if let Err(e) = validate_ssize_len(buf_len) {
        return e;
    }

    let Ok(info) = crate::RecvInfo::try_from(info) else {
        return FFI_ERR_INVALID_ARGUMENT;
    };

    let buf = ffi_slice_mut!(buf, buf_len, FFI_ERR_INVALID_ARGUMENT);

    match conn.recv(buf, info) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
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

#[no_mangle]
pub extern "C" fn quiche_conn_send(
    conn: *mut Connection, out: *mut u8, out_len: size_t, out_info: *mut SendInfo,
) -> ssize_t {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);
    let out_info = ffi_mut!(out_info, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    if let Err(e) = validate_ssize_len(out_len) {
        return e;
    }

    let out = ffi_slice_mut!(out, out_len, FFI_ERR_INVALID_ARGUMENT);

    match conn.send(out) {
        Ok((v, info)) => {
            out_info.from_len = std_addr_to_c(&info.from, &mut out_info.from);
            out_info.to_len = std_addr_to_c(&info.to, &mut out_info.to);

            std_time_to_c(&info.at, &mut out_info.at);

            v as ssize_t
        },

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_send_on_path(
    conn: *mut Connection, out: *mut u8, out_len: size_t, from: *const sockaddr,
    from_len: socklen_t, to: *const sockaddr, to_len: socklen_t,
    out_info: *mut SendInfo,
) -> ssize_t {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);
    let out_info = ffi_mut!(out_info, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    if let Err(e) = validate_ssize_len(out_len) {
        return e;
    }

    let Ok(from) = optional_std_addr_from_c(from, from_len) else {
        return FFI_ERR_INVALID_ARGUMENT;
    };
    let Ok(to) = optional_std_addr_from_c(to, to_len) else {
        return FFI_ERR_INVALID_ARGUMENT;
    };
    let out = ffi_slice_mut!(out, out_len, FFI_ERR_INVALID_ARGUMENT);

    match conn.send_on_path(out, from, to) {
        Ok((v, info)) => {
            out_info.from_len = std_addr_to_c(&info.from, &mut out_info.from);
            out_info.to_len = std_addr_to_c(&info.to, &mut out_info.to);

            std_time_to_c(&info.at, &mut out_info.at);

            v as ssize_t
        },

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_recv(
    conn: *mut Connection, stream_id: u64, out: *mut u8, out_len: size_t,
    fin: *mut bool, out_error_code: *mut u64,
) -> ssize_t {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);
    let fin = ffi_mut!(fin, FFI_ERR_INVALID_ARGUMENT as ssize_t);
    let out_error_code =
        ffi_mut!(out_error_code, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    if let Err(e) = validate_ssize_len(out_len) {
        return e;
    }

    let out = ffi_slice_mut!(out, out_len, FFI_ERR_INVALID_ARGUMENT);

    let (out_len, out_fin) = match conn.stream_recv(stream_id, out) {
        Ok(v) => v,

        Err(e) => {
            match e {
                Error::StreamReset(error) => *out_error_code = error,
                Error::StreamStopped(error) => *out_error_code = error,
                _ => {},
            }
            return e.to_c();
        },
    };

    *fin = out_fin;

    out_len as ssize_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_send(
    conn: *mut Connection, stream_id: u64, buf: *const u8, buf_len: size_t,
    fin: bool, out_error_code: *mut u64,
) -> ssize_t {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);
    let out_error_code =
        ffi_mut!(out_error_code, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    if let Err(e) = validate_ssize_len(buf_len) {
        return e;
    }

    let buf = ffi_slice!(buf, buf_len, FFI_ERR_INVALID_ARGUMENT);

    match conn.stream_send(stream_id, buf, fin) {
        Ok(v) => v as ssize_t,

        Err(e) => {
            match e {
                Error::StreamReset(error) => *out_error_code = error,
                Error::StreamStopped(error) => *out_error_code = error,
                _ => {},
            }
            e.to_c()
        },
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_priority(
    conn: *mut Connection, stream_id: u64, urgency: u8, incremental: bool,
) -> c_int {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);

    match conn.stream_priority(stream_id, urgency, incremental) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_shutdown(
    conn: *mut Connection, stream_id: u64, direction: Shutdown, err: u64,
) -> c_int {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);

    match conn.stream_shutdown(stream_id, direction, err) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_capacity(
    conn: *mut Connection, stream_id: u64,
) -> ssize_t {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    match conn.stream_capacity(stream_id) {
        Ok(v) => v as ssize_t,

        Err(e) => e.to_c(),
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
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as i64);

    conn.stream_readable_next().map(|v| v as i64).unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_writable(
    conn: *mut Connection, stream_id: u64, len: usize,
) -> c_int {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);

    match conn.stream_writable(stream_id, len) {
        Ok(true) => 1,

        Ok(false) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_writable_next(conn: *mut Connection) -> i64 {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as i64);

    conn.stream_writable_next().map(|v| v as i64).unwrap_or(-1)
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
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);

    let reason =
        ffi_slice!(reason, reason_len, FFI_ERR_INVALID_ARGUMENT as c_int);

    match conn.close(app, err, reason) {
        Ok(_) => 0,

        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_timeout_as_nanos(conn: *const Connection) -> u64 {
    let conn = ffi_ref!(conn, 0);

    match conn.timeout() {
        Some(timeout) => timeout.as_nanos() as u64,

        None => u64::MAX,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_timeout_as_millis(conn: *const Connection) -> u64 {
    let conn = ffi_ref!(conn, 0);

    match conn.timeout() {
        Some(timeout) => timeout.as_millis() as u64,

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
    max_datagram_frame_size: ssize_t,
}

#[no_mangle]
pub extern "C" fn quiche_conn_stats(conn: *const Connection, out: *mut Stats) {
    let conn = ffi_ref!(conn);
    let out = ffi_mut!(out);

    let stats = conn.stats();

    out.recv = stats.recv;
    out.sent = stats.sent;
    out.lost = stats.lost;
    out.spurious_lost = stats.spurious_lost;
    out.retrans = stats.retrans;
    out.sent_bytes = stats.sent_bytes;
    out.recv_bytes = stats.recv_bytes;
    out.acked_bytes = stats.acked_bytes;
    out.lost_bytes = stats.lost_bytes;
    out.stream_retrans_bytes = stats.stream_retrans_bytes;
    out.dgram_recv = stats.dgram_recv;
    out.dgram_sent = stats.dgram_sent;
    out.paths_count = stats.paths_count;
    out.reset_stream_count_local = stats.reset_stream_count_local;
    out.stopped_stream_count_local = stats.stopped_stream_count_local;
    out.reset_stream_count_remote = stats.reset_stream_count_remote;
    out.stopped_stream_count_remote = stats.stopped_stream_count_remote;
    out.data_blocked_sent_count = stats.data_blocked_sent_count;
    out.stream_data_blocked_sent_count = stats.stream_data_blocked_sent_count;
    out.data_blocked_recv_count = stats.data_blocked_recv_count;
    out.stream_data_blocked_recv_count = stats.stream_data_blocked_recv_count;
    out.streams_blocked_bidi_recv_count = stats.streams_blocked_bidi_recv_count;
    out.streams_blocked_uni_recv_count = stats.streams_blocked_uni_recv_count;
    out.path_challenge_rx_count = stats.path_challenge_rx_count;
    out.bytes_in_flight_duration_msec =
        stats.bytes_in_flight_duration.as_millis() as u64;
    out.tx_buffered_inconsistent =
        stats.tx_buffered_state != TxBufferTrackingState::Ok;
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_transport_params(
    conn: *const Connection, out: *mut TransportParams,
) -> bool {
    let conn = ffi_ref!(conn, false);
    let out = ffi_mut!(out, false);

    let tps = match conn.peer_transport_params() {
        Some(v) => v,
        None => return false,
    };

    out.max_idle_timeout = tps.max_idle_timeout;
    out.max_udp_payload_size = tps.max_udp_payload_size;
    out.initial_max_data = tps.initial_max_data;
    out.initial_max_stream_data_bidi_local =
        tps.initial_max_stream_data_bidi_local;
    out.initial_max_stream_data_bidi_remote =
        tps.initial_max_stream_data_bidi_remote;
    out.initial_max_stream_data_uni = tps.initial_max_stream_data_uni;
    out.initial_max_streams_bidi = tps.initial_max_streams_bidi;
    out.initial_max_streams_uni = tps.initial_max_streams_uni;
    out.ack_delay_exponent = tps.ack_delay_exponent;
    out.max_ack_delay = tps.max_ack_delay;
    out.disable_active_migration = tps.disable_active_migration;
    out.active_conn_id_limit = tps.active_conn_id_limit;
    out.max_datagram_frame_size = match tps.max_datagram_frame_size {
        None => Error::Done.to_c(),

        Some(v) => v as ssize_t,
    };

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
    let conn = ffi_ref!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);
    let out = ffi_mut!(out, FFI_ERR_INVALID_ARGUMENT as c_int);

    let stats = match conn.path_stats().nth(idx) {
        Some(p) => p,
        None => return Error::Done.to_c() as c_int,
    };

    out.local_addr_len = std_addr_to_c(&stats.local_addr, &mut out.local_addr);
    out.peer_addr_len = std_addr_to_c(&stats.peer_addr, &mut out.peer_addr);
    out.validation_state = stats.validation_state.to_c();
    out.active = stats.active;
    out.recv = stats.recv;
    out.sent = stats.sent;
    out.lost = stats.lost;
    out.retrans = stats.retrans;
    out.total_pto_count = stats.total_pto_count;
    out.dgram_recv = stats.dgram_recv;
    out.dgram_sent = stats.dgram_sent;
    out.rtt = stats.rtt.as_nanos() as u64;
    out.min_rtt = stats.min_rtt.unwrap_or_default().as_nanos() as u64;
    out.max_rtt = stats.max_rtt.unwrap_or_default().as_nanos() as u64;
    out.rttvar = stats.rttvar.as_nanos() as u64;
    out.cwnd = stats.cwnd;
    out.sent_bytes = stats.sent_bytes;
    out.recv_bytes = stats.recv_bytes;
    out.lost_bytes = stats.lost_bytes;
    out.stream_retrans_bytes = stats.stream_retrans_bytes;
    out.pmtu = stats.pmtu;
    out.delivery_rate = stats.delivery_rate;
    out.max_bandwidth = stats.max_bandwidth.unwrap_or(0);
    out.startup_exit_cwnd =
        stats.startup_exit.map(|s| s.cwnd as u64).unwrap_or(0);

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
    let conn = ffi_ref!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    match conn.dgram_max_writable_len() {
        None => Error::Done.to_c(),

        Some(v) => v as ssize_t,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_recv_front_len(
    conn: *const Connection,
) -> ssize_t {
    let conn = ffi_ref!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    match conn.dgram_recv_front_len() {
        None => Error::Done.to_c(),

        Some(v) => v as ssize_t,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_recv_queue_len(
    conn: *const Connection,
) -> ssize_t {
    let conn = ffi_ref!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    conn.dgram_recv_queue_len() as ssize_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_recv_queue_byte_size(
    conn: *const Connection,
) -> ssize_t {
    let conn = ffi_ref!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    conn.dgram_recv_queue_byte_size() as ssize_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_send_queue_len(
    conn: *const Connection,
) -> ssize_t {
    let conn = ffi_ref!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    conn.dgram_send_queue_len() as ssize_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_send_queue_byte_size(
    conn: *const Connection,
) -> ssize_t {
    let conn = ffi_ref!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    conn.dgram_send_queue_byte_size() as ssize_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_send(
    conn: *mut Connection, buf: *const u8, buf_len: size_t,
) -> ssize_t {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    if let Err(e) = validate_ssize_len(buf_len) {
        return e;
    }

    let buf = ffi_slice!(buf, buf_len, FFI_ERR_INVALID_ARGUMENT);

    match conn.dgram_send(buf) {
        Ok(_) => buf_len as ssize_t,

        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_dgram_recv(
    conn: *mut Connection, out: *mut u8, out_len: size_t,
) -> ssize_t {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    if let Err(e) = validate_ssize_len(out_len) {
        return e;
    }

    let out = ffi_slice_mut!(out, out_len, FFI_ERR_INVALID_ARGUMENT);

    let out_len = match conn.dgram_recv(out) {
        Ok(v) => v,

        Err(e) => return e.to_c(),
    };

    out_len as ssize_t
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
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    match conn.send_ack_eliciting() {
        Ok(()) => 0,
        Err(e) => e.to_c(),
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_send_ack_eliciting_on_path(
    conn: *mut Connection, local: *const sockaddr, local_len: socklen_t,
    peer: *const sockaddr, peer_len: socklen_t,
) -> ssize_t {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as ssize_t);
    let local = ffi_ref!(local, FFI_ERR_INVALID_ARGUMENT as ssize_t);
    let peer = ffi_ref!(peer, FFI_ERR_INVALID_ARGUMENT as ssize_t);

    let Ok(local) = std_addr_from_c(local, local_len) else {
        return FFI_ERR_INVALID_ARGUMENT;
    };
    let Ok(peer) = std_addr_from_c(peer, peer_len) else {
        return FFI_ERR_INVALID_ARGUMENT;
    };
    match conn.send_ack_eliciting_on_path(local, peer) {
        Ok(()) => 0,
        Err(e) => e.to_c(),
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
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);
    let scid_seq = ffi_mut!(scid_seq, FFI_ERR_INVALID_ARGUMENT as c_int);

    let scid = ffi_slice!(scid, scid_len, FFI_ERR_INVALID_ARGUMENT as c_int);
    let scid = ConnectionId::from_ref(scid);

    let reset_token =
        ffi_slice!(reset_token, 16, FFI_ERR_INVALID_ARGUMENT as c_int);
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
        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_retire_dcid(
    conn: *mut Connection, dcid_seq: u64,
) -> c_int {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);

    match conn.retire_dcid(dcid_seq) {
        Ok(_) => 0,
        Err(e) => e.to_c() as c_int,
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
    let local = ffi_ref!(local, 0);
    let peer = ffi_ref!(peer, 0);

    let Ok(local) = std_addr_from_c(local, local_len) else {
        return 0;
    };
    let Ok(peer) = std_addr_from_c(peer, peer_len) else {
        return 0;
    };

    conn.send_quantum_on_path(local, peer) as size_t
}

#[no_mangle]
pub extern "C" fn quiche_conn_paths_iter(
    conn: *const Connection, from: *const sockaddr, from_len: socklen_t,
) -> *mut SocketAddrIter {
    let conn = ffi_ref!(conn, ptr::null_mut());
    let from = ffi_ref!(from, ptr::null_mut());

    let Ok(addr) = std_addr_from_c(from, from_len) else {
        return ptr::null_mut();
    };

    Box::into_raw(Box::new(conn.paths_iter(addr)))
}

#[no_mangle]
pub extern "C" fn quiche_socket_addr_iter_next(
    iter: *mut SocketAddrIter, peer: *mut sockaddr_storage,
    peer_len: *mut socklen_t,
) -> bool {
    let iter = ffi_mut!(iter, false);
    let peer = ffi_mut!(peer, false);
    let peer_len = ffi_mut!(peer_len, false);

    if let Some(v) = iter.next() {
        *peer_len = std_addr_to_c(&v, peer);
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
    let conn = ffi_ref!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);
    let from = ffi_ref!(from, FFI_ERR_INVALID_ARGUMENT as c_int);
    let to = ffi_ref!(to, FFI_ERR_INVALID_ARGUMENT as c_int);

    let Ok(from) = std_addr_from_c(from, from_len) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };
    let Ok(to) = std_addr_from_c(to, to_len) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };
    match conn.is_path_validated(from, to) {
        Ok(v) => v as c_int,
        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_probe_path(
    conn: *mut Connection, local: *const sockaddr, local_len: socklen_t,
    peer: *const sockaddr, peer_len: socklen_t, seq: *mut u64,
) -> c_int {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);
    let local = ffi_ref!(local, FFI_ERR_INVALID_ARGUMENT as c_int);
    let peer = ffi_ref!(peer, FFI_ERR_INVALID_ARGUMENT as c_int);
    let seq = ffi_mut!(seq, FFI_ERR_INVALID_ARGUMENT as c_int);

    let Ok(local) = std_addr_from_c(local, local_len) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };
    let Ok(peer) = std_addr_from_c(peer, peer_len) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };
    match conn.probe_path(local, peer) {
        Ok(v) => {
            *seq = v;
            0
        },
        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_migrate_source(
    conn: *mut Connection, local: *const sockaddr, local_len: socklen_t,
    seq: *mut u64,
) -> c_int {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);
    let local = ffi_ref!(local, FFI_ERR_INVALID_ARGUMENT as c_int);
    let seq = ffi_mut!(seq, FFI_ERR_INVALID_ARGUMENT as c_int);

    let Ok(local) = std_addr_from_c(local, local_len) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };
    match conn.migrate_source(local) {
        Ok(v) => {
            *seq = v;
            0
        },
        Err(e) => e.to_c() as c_int,
    }
}

#[no_mangle]
pub extern "C" fn quiche_conn_migrate(
    conn: *mut Connection, local: *const sockaddr, local_len: socklen_t,
    peer: *const sockaddr, peer_len: socklen_t, seq: *mut u64,
) -> c_int {
    let conn = ffi_mut!(conn, FFI_ERR_INVALID_ARGUMENT as c_int);
    let local = ffi_ref!(local, FFI_ERR_INVALID_ARGUMENT as c_int);
    let peer = ffi_ref!(peer, FFI_ERR_INVALID_ARGUMENT as c_int);
    let seq = ffi_mut!(seq, FFI_ERR_INVALID_ARGUMENT as c_int);

    let Ok(local) = std_addr_from_c(local, local_len) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };
    let Ok(peer) = std_addr_from_c(peer, peer_len) else {
        return FFI_ERR_INVALID_ARGUMENT as c_int;
    };
    match conn.migrate(local, peer) {
        Ok(v) => {
            *seq = v;
            0
        },
        Err(e) => e.to_c() as c_int,
    }
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
    let buf = ffi_slice_mut!(buf, buf_len, FFI_ERR_INVALID_ARGUMENT as c_int);

    let mut b = octets::OctetsMut::with_slice(buf);
    match b.put_varint(val) {
        Ok(_) => 0,

        Err(e) => {
            let err: Error = e.into();
            err.to_c() as c_int
        },
    }
}

#[no_mangle]
pub extern "C" fn quiche_get_varint(
    buf: *const u8, buf_len: size_t, val: *mut u64,
) -> ssize_t {
    let val = ffi_mut!(val, FFI_ERR_INVALID_ARGUMENT);
    let buf = ffi_slice!(buf, buf_len, FFI_ERR_INVALID_ARGUMENT);

    let mut b = octets::Octets::with_slice(buf);
    match b.get_varint() {
        Ok(v) => *val = v,

        Err(e) => {
            let err: Error = e.into();
            return err.to_c();
        },
    };

    b.off() as ssize_t
}

fn optional_std_addr_from_c(
    addr: *const sockaddr, addr_len: socklen_t,
) -> std::result::Result<Option<SocketAddr>, ()> {
    if addr.is_null() || addr_len == 0 {
        return Ok(None);
    }

    let Some(addr) = (unsafe { ffi_ptr_ref(addr) }) else {
        return Err(());
    };

    std_addr_from_c(addr, addr_len).map(Some)
}

fn std_addr_from_c(
    addr: &sockaddr, addr_len: socklen_t,
) -> std::result::Result<SocketAddr, ()> {
    match addr.sa_family as _ {
        AF_INET => {
            if addr_len as usize != size_of::<sockaddr_in>() {
                return Err(());
            }

            let in4 = unsafe { *(addr as *const _ as *const sockaddr_in) };

            #[cfg(not(windows))]
            let ip_addr = Ipv4Addr::from(u32::from_be(in4.sin_addr.s_addr));
            #[cfg(windows)]
            let ip_addr = {
                let ip_bytes = unsafe { in4.sin_addr.S_un.S_un_b };

                Ipv4Addr::from([
                    ip_bytes.s_b1,
                    ip_bytes.s_b2,
                    ip_bytes.s_b3,
                    ip_bytes.s_b4,
                ])
            };

            let port = u16::from_be(in4.sin_port);

            let out = SocketAddrV4::new(ip_addr, port);

            Ok(out.into())
        },

        AF_INET6 => {
            if addr_len as usize != size_of::<sockaddr_in6>() {
                return Err(());
            }

            let in6 = unsafe { *(addr as *const _ as *const sockaddr_in6) };

            let ip_addr = Ipv6Addr::from(
                #[cfg(not(windows))]
                in6.sin6_addr.s6_addr,
                #[cfg(windows)]
                unsafe {
                    in6.sin6_addr.u.Byte
                },
            );

            let port = u16::from_be(in6.sin6_port);

            #[cfg(not(windows))]
            let scope_id = in6.sin6_scope_id;
            #[cfg(windows)]
            let scope_id = unsafe { in6.Anonymous.sin6_scope_id };

            let out =
                SocketAddrV6::new(ip_addr, port, in6.sin6_flowinfo, scope_id);

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
fn std_time_to_c(time: &Instant, out: &mut timespec) {
    const INSTANT_ZERO: Instant =
        unsafe { std::mem::transmute(std::time::UNIX_EPOCH) };

    let raw_time = time.duration_since(INSTANT_ZERO);

    out.tv_sec = raw_time.as_secs() as libc::time_t;
    out.tv_nsec = raw_time.subsec_nanos() as libc::c_long;
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

    #[test]
    fn invalid_utf8_ffi_string_returns_invalid_argument() {
        let mut config = Config::new(PROTOCOL_VERSION).unwrap();
        let invalid = [0xff_u8, 0];

        assert_eq!(
            quiche_config_set_cc_algorithm_name(
                &mut config,
                invalid.as_ptr().cast(),
            ),
            FFI_ERR_INVALID_ARGUMENT as c_int
        );
    }

    #[test]
    fn oversized_ffi_length_returns_invalid_argument() {
        assert_eq!(validate_ssize_len(ssize_t::MAX as usize), Ok(()));
        assert_eq!(
            validate_ssize_len(ssize_t::MAX as usize + 1),
            Err(FFI_ERR_INVALID_ARGUMENT)
        );
    }

    #[test]
    fn malformed_sockaddr_is_rejected() {
        let mut addr: sockaddr = unsafe { std::mem::zeroed() };
        addr.sa_family = AF_INET as sa_family_t;

        assert_eq!(std_addr_from_c(&addr, 0), Err(()));

        addr.sa_family = 0;
        assert_eq!(
            std_addr_from_c(&addr, size_of::<sockaddr_in>() as socklen_t,),
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
                    &*(&local_out as *const _ as *const sockaddr),
                    local_len,
                )
            },
            Ok(local)
        );
        assert_eq!(
            unsafe {
                std_addr_from_c(
                    &*(&peer_out as *const _ as *const sockaddr),
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
                &*(&out as *const _ as *const sockaddr),
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
                &*(&out as *const _ as *const sockaddr),
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
            FFI_ERR_INVALID_ARGUMENT as c_int
        );
        assert_eq!(
            quiche_conn_dgram_recv_front_len(ptr::null()),
            FFI_ERR_INVALID_ARGUMENT as ssize_t
        );
        assert_eq!(
            quiche_conn_stream_readable_next(ptr::null_mut()),
            FFI_ERR_INVALID_ARGUMENT as i64
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
        assert!(unsafe { ffi_ptr_mut(misaligned.cast_mut()) }.is_none());

        let addr = ptr::NonNull::<sockaddr>::dangling().as_ptr();
        let misaligned_addr = addr.cast::<u8>().wrapping_add(1).cast::<sockaddr>();
        assert!(optional_std_addr_from_c(misaligned_addr, size_of::<sockaddr>() as socklen_t).is_err());
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
            FFI_ERR_INVALID_ARGUMENT
        );

        // NULL,0 is a valid empty input buffer. Parsing still fails normally
        // because an empty buffer contains no varint, rather than because the
        // pointer itself is null.
        assert_eq!(
            quiche_get_varint(ptr::null(), 0, &mut value),
            Error::BufferTooShort.to_c()
        );
        assert_eq!(
            quiche_put_varint(ptr::null_mut(), 0, 0),
            Error::BufferTooShort.to_c() as c_int
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
            FFI_ERR_INVALID_ARGUMENT as c_int
        );
    }

    #[cfg(not(windows))]
    extern "C" {
        fn inet_ntop(
            af: c_int, src: *const c_void, dst: *mut c_char, size: socklen_t,
        ) -> *mut c_char;
    }
}
