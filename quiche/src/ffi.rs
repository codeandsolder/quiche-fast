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

use bytes::BufMut as _;

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
pub(crate) unsafe fn ffi_ptr_ref<'a, T>(ptr: *const T) -> Option<&'a T> {
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
pub(crate) unsafe fn ffi_ptr_mut<'a, T>(ptr: *mut T) -> Option<&'a mut T> {
    if ptr.is_null() || !ptr.is_aligned() {
        return None;
    }

    // SAFETY: null and alignment are checked above. Allocation validity,
    // lifetime and exclusivity remain part of the C caller contract.
    Some(unsafe { &mut *ptr })
}

/// Reclaim an allocation returned by a C constructor once.
///
/// # Safety
/// A non-null, aligned pointer must come from `Box::into_raw` for the same
/// type and transfer sole ownership to this call.
pub(crate) unsafe fn ffi_drop_box<T>(ptr: *mut T) {
    if !ptr.is_null() && ptr.is_aligned() {
        // SAFETY: the caller supplies the original owned box pointer.
        unsafe { drop(Box::from_raw(ptr)) };
    }
}

macro_rules! ffi_free {
    ($ptr:expr) => {{
        // SAFETY: the C destructor requires the corresponding constructor's
        // allocation, with exclusive ownership transferred exactly once.
        unsafe { $crate::ffi::ffi_drop_box($ptr) }
    }};
}

pub(crate) use ffi_free;

macro_rules! ffi_c_str {
    ($ptr:expr, $ret:expr) => {{
        // SAFETY: a non-null C string must be readable through its terminator
        // for the duration of the call.
        match unsafe { c_str_to_str($ptr) } {
            Ok(value) => value,
            Err(()) => return $ret,
        }
    }};
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

/// Borrow writable C output storage without requiring an initialized value.
///
/// # Safety
/// A non-null, aligned pointer must identify writable storage for one T with
/// exclusive access for the returned lifetime.
pub(crate) unsafe fn ffi_ptr_out<'a, T>(
    ptr: *mut T,
) -> Option<&'a mut MaybeUninit<T>> {
    // SAFETY: MaybeUninit has the same layout as T and permits uninitialized
    // storage. The caller provides the exclusive writable allocation.
    unsafe { ffi_ptr_mut(ptr.cast::<MaybeUninit<T>>()) }
}

macro_rules! ffi_out {
    ($ptr:expr) => {{
        // SAFETY: a C output parameter must be exclusively writable.
        match unsafe { $crate::ffi::ffi_ptr_out($ptr) } {
            Some(value) => value,
            None => return,
        }
    }};
    ($ptr:expr, $ret:expr) => {{
        // SAFETY: a C output parameter must be exclusively writable.
        match unsafe { $crate::ffi::ffi_ptr_out($ptr) } {
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
pub(crate) unsafe fn ffi_slice_from_raw_parts<'a, T>(
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
pub(crate) unsafe fn ffi_slice_from_raw_parts_mut<'a, T>(
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

/// Borrows a C output buffer without assuming that any bytes are initialized.
///
/// # Safety
/// Non-empty storage must be writable and exclusive for the returned lifetime.
pub(crate) unsafe fn ffi_slice_output<'a, T>(
    ptr: *mut T, len: usize,
) -> Option<&'a mut [MaybeUninit<T>]> {
    // SAFETY: MaybeUninit has T's layout and permits uninitialized storage;
    // the caller supplies the exclusive output allocation.
    unsafe { ffi_slice_from_raw_parts_mut(ptr.cast::<MaybeUninit<T>>(), len) }
}

macro_rules! ffi_slice_out {
    ($ptr:expr, $len:expr, $ret:expr) => {{
        // SAFETY: the C caller supplies writable, exclusive output storage.
        match unsafe { $crate::ffi::ffi_slice_output($ptr, $len) } {
            Some(value) => value,
            None => return $ret,
        }
    }};
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
pub(super) use ffi_out;
pub(super) use ffi_ref;
pub(super) use ffi_slice;
pub(super) use ffi_slice_out;

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
    cb: Option<extern "C" fn(line: *const u8, argp: *mut c_void)>,
    argp: *mut c_void,
) -> c_int {
    let Some(cb) = cb else {
        return c_int::from(FFI_ERR_INVALID_ARGUMENT);
    };
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
    let value = ffi_c_str!(value, c_int::from(FFI_ERR_INVALID_ARGUMENT));
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
    config: *mut Config, algo: c_int,
) -> c_int {
    let config = ffi_mut!(config, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    // The C caller supplies an integer, not a valid Rust enum discriminant.
    let algorithm = match algo {
        v if v == CongestionControlAlgorithm::Reno as c_int =>
            CongestionControlAlgorithm::Reno,
        v if v == CongestionControlAlgorithm::CUBIC as c_int =>
            CongestionControlAlgorithm::CUBIC,
        v if v == CongestionControlAlgorithm::Bbr2Gcongestion as c_int =>
            CongestionControlAlgorithm::Bbr2Gcongestion,
        _ => return c_int::from(FFI_ERR_INVALID_ARGUMENT),
    };
    config.set_cc_algorithm(algorithm);
    0
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
    let Ok(reset_token) = reset_token.try_into() else {
        return;
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
    ffi_free!(config);
}

#[no_mangle]
pub extern "C" fn quiche_header_info(
    buf: *mut u8, buf_len: size_t, dcil: size_t, version: *mut u32, ty: *mut u8,
    scid: *mut u8, scid_len: *mut size_t, dcid: *mut u8, dcid_len: *mut size_t,
    token: *mut u8, token_len: *mut size_t,
) -> c_int {
    let version = ffi_out!(version, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let ty = ffi_out!(ty, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let scid_len = ffi_mut!(scid_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let dcid_len = ffi_mut!(dcid_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let token_len = ffi_mut!(token_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let buf = ffi_slice_mut!(buf, buf_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let hdr = match Header::from_slice(buf, dcil) {
        Ok(v) => v,

        Err(e) => return c_int::from(e.to_c()),
    };

    let token_bytes = hdr.token.as_deref().unwrap_or(&[]);
    if *scid_len < hdr.scid.len() ||
        *dcid_len < hdr.dcid.len() ||
        *token_len < token_bytes.len()
    {
        return c_int::from(Error::BufferTooShort.to_c());
    }
    let mut scid =
        ffi_slice_out!(scid, *scid_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let mut dcid =
        ffi_slice_out!(dcid, *dcid_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let mut token = if hdr.token.is_some() {
        ffi_slice_out!(token, *token_len, c_int::from(FFI_ERR_INVALID_ARGUMENT))
    } else {
        &mut []
    };

    scid.put_slice(&hdr.scid);
    dcid.put_slice(&hdr.dcid);
    token.put_slice(token_bytes);
    *scid_len = hdr.scid.len();
    *dcid_len = hdr.dcid.len();
    *token_len = token_bytes.len();
    version.write(hdr.version);
    ty.write(match hdr.ty {
        Type::Initial => 1,
        Type::Retry => 2,
        Type::Handshake => 3,
        Type::ZeroRTT => 4,
        Type::Short => 5,
        Type::VersionNegotiation => 6,
    });

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
        let server_name = ffi_c_str!(server_name, ptr::null_mut());
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
        ffi_slice_out!(out, out_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match packet::negotiate_version(
        &scid,
        &dcid,
        &mut packet::PacketWriter::new(out),
    ) {
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
        ffi_slice_out!(out, out_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match packet::retry(
        &scid,
        &dcid,
        &new_scid,
        token,
        version,
        &mut packet::PacketWriter::new(out),
    ) {
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

        // SAFETY: the caller transfers ownership of a live SSL object here.
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

    // SAFETY: the caller transfers ownership of a live SSL object here.
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

    let filename = ffi_c_str!(path, false);

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

/// Adopt a live descriptor supplied by the caller.
///
/// # Safety
/// A valid descriptor must be exclusively owned by the caller, who transfers
/// ownership on success and must not close it thereafter.
#[cfg(unix)]
unsafe fn file_from_owned_fd(fd: c_int) -> Option<std::fs::File> {
    // SAFETY: F_GETFD only queries a descriptor and takes no variadic argument.
    if fd < 0 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return None;
    }

    // SAFETY: the descriptor exists and the caller transfers its ownership.
    Some(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[no_mangle]
#[cfg(unix)]
pub extern "C" fn quiche_conn_set_keylog_fd(
    conn: *mut Connection, fd: c_int,
) -> bool {
    let conn = ffi_mut!(conn, false);

    // SAFETY: this API takes ownership of the descriptor only on acceptance.
    let Some(f) = (unsafe { file_from_owned_fd(fd) }) else {
        return false;
    };
    let writer = std::io::BufWriter::new(f);

    conn.set_keylog(Box::new(writer));
    true
}

#[no_mangle]
#[cfg(feature = "qlog")]
pub extern "C" fn quiche_conn_set_qlog_path(
    conn: *mut Connection, path: *const c_char, log_title: *const c_char,
    log_desc: *const c_char,
) -> bool {
    let conn = ffi_mut!(conn, false);

    let filename = ffi_c_str!(path, false);
    let title = ffi_c_str!(log_title, false);
    let description = ffi_c_str!(log_desc, false);

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
) -> bool {
    let conn = ffi_mut!(conn, false);

    let title = ffi_c_str!(log_title, false);
    let description = ffi_c_str!(log_desc, false);

    // SAFETY: this API takes ownership of the descriptor only on acceptance.
    let Some(f) = (unsafe { file_from_owned_fd(fd) }) else {
        return false;
    };
    let writer = std::io::BufWriter::new(f);

    conn.set_qlog(
        Box::new(writer),
        title.to_owned(),
        format!("{} id={}", description, conn.trace_id),
    );
    true
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
        let (from, from_len) = std_addr_to_c(&info.from);
        let (to, to_len) = std_addr_to_c(&info.to);
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
    let out_info = ffi_out!(out_info, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    if let Err(e) = validate_ssize_len(out_len) {
        return e;
    }

    let out =
        ffi_slice_out!(out, out_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.send_on_path_into(&mut packet::PacketWriter::new(out), None, None)
    {
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
    let out_info = ffi_out!(out_info, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

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
        ffi_slice_out!(out, out_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.send_on_path_into(&mut packet::PacketWriter::new(out), from, to) {
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
    let fin = ffi_out!(fin, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let out_error_code =
        ffi_out!(out_error_code, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    if let Err(e) = validate_ssize_len(out_len) {
        return e;
    }

    let out =
        ffi_slice_out!(out, out_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    let (out_len, out_fin) = match conn.stream_recv_buf(stream_id, out) {
        Ok(v) => v,

        Err(e) => {
            match e {
                Error::StreamReset(error) | Error::StreamStopped(error) => {
                    out_error_code.write(error);
                },
                _ => {},
            }
            return ssize_t::from(e.to_c());
        },
    };

    fin.write(out_fin);

    ssize_t::try_from(out_len).unwrap_or(ssize_t::MAX)
}

#[no_mangle]
pub extern "C" fn quiche_conn_stream_send(
    conn: *mut Connection, stream_id: u64, buf: *const u8, buf_len: size_t,
    fin: bool, out_error_code: *mut u64,
) -> ssize_t {
    let conn = ffi_mut!(conn, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let out_error_code =
        ffi_out!(out_error_code, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    if let Err(e) = validate_ssize_len(buf_len) {
        return e;
    }

    let buf = ffi_slice!(buf, buf_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    match conn.stream_send(stream_id, buf, fin) {
        Ok(v) => ssize_t::try_from(v).unwrap_or(ssize_t::MAX),

        Err(e) => {
            match e {
                Error::StreamReset(error) | Error::StreamStopped(error) => {
                    out_error_code.write(error);
                },
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
    conn: *mut Connection, stream_id: u64, direction: c_int, err: u64,
) -> c_int {
    let conn = ffi_mut!(conn, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let direction = match direction {
        v if v == Shutdown::Read as c_int => Shutdown::Read,
        v if v == Shutdown::Write as c_int => Shutdown::Write,
        _ => return c_int::from(FFI_ERR_INVALID_ARGUMENT),
    };

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

fn write_borrowed_bytes(
    out: &mut MaybeUninit<*const u8>, out_len: &mut MaybeUninit<size_t>,
    bytes: Option<&[u8]>,
) {
    let (ptr, len) = bytes.map_or((ptr::null(), 0), |v| (v.as_ptr(), v.len()));
    out.write(ptr);
    out_len.write(len);
}

#[no_mangle]
pub extern "C" fn quiche_conn_trace_id(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_out!(out);
    let out_len = ffi_out!(out_len);
    write_borrowed_bytes(out, out_len, Some(conn.trace_id().as_bytes()));
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
    let out = ffi_out!(out, false);
    let out_len = ffi_out!(out_len, false);

    if let Some(conn_id) = iter.cids.get(iter.index) {
        write_borrowed_bytes(out, out_len, Some(conn_id.as_ref()));
        iter.index += 1;
        return true;
    }

    false
}

#[no_mangle]
pub extern "C" fn quiche_connection_id_iter_free(iter: *mut ConnectionIdIter) {
    ffi_free!(iter);
}

#[no_mangle]
pub extern "C" fn quiche_conn_source_id(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_out!(out);
    let out_len = ffi_out!(out_len);
    write_borrowed_bytes(out, out_len, Some(conn.source_id().as_ref()));
}

#[no_mangle]
pub extern "C" fn quiche_conn_destination_id(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_out!(out);
    let out_len = ffi_out!(out_len);
    write_borrowed_bytes(out, out_len, Some(conn.destination_id().as_ref()));
}

#[no_mangle]
pub extern "C" fn quiche_conn_application_proto(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_out!(out);
    let out_len = ffi_out!(out_len);
    write_borrowed_bytes(out, out_len, Some(conn.application_proto()));
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_cert(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_out!(out);
    let out_len = ffi_out!(out_len);
    write_borrowed_bytes(out, out_len, conn.peer_cert());
}

#[no_mangle]
pub extern "C" fn quiche_conn_session(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_out!(out);
    let out_len = ffi_out!(out_len);
    write_borrowed_bytes(out, out_len, conn.session());
}

#[no_mangle]
pub extern "C" fn quiche_conn_server_name(
    conn: *const Connection, out: *mut *const u8, out_len: *mut size_t,
) {
    let conn = ffi_ref!(conn);
    let out = ffi_out!(out);
    let out_len = ffi_out!(out_len);
    write_borrowed_bytes(out, out_len, conn.server_name().map(str::as_bytes));
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

fn write_connection_error(
    error: Option<&ConnectionError>, is_app: *mut bool, error_code: *mut u64,
    reason: *mut *const u8, reason_len: *mut size_t,
) -> bool {
    let Some(error) = error else {
        return false;
    };
    let is_app = ffi_out!(is_app, false);
    let error_code = ffi_out!(error_code, false);
    let reason = ffi_out!(reason, false);
    let reason_len = ffi_out!(reason_len, false);
    is_app.write(error.is_app);
    error_code.write(error.error_code);
    write_borrowed_bytes(reason, reason_len, Some(&error.reason));
    true
}

#[no_mangle]
pub extern "C" fn quiche_conn_peer_error(
    conn: *const Connection, is_app: *mut bool, error_code: *mut u64,
    reason: *mut *const u8, reason_len: *mut size_t,
) -> bool {
    let conn = ffi_ref!(conn, false);
    write_connection_error(
        conn.peer_error.as_ref(),
        is_app,
        error_code,
        reason,
        reason_len,
    )
}

#[no_mangle]
pub extern "C" fn quiche_conn_local_error(
    conn: *const Connection, is_app: *mut bool, error_code: *mut u64,
    reason: *mut *const u8, reason_len: *mut size_t,
) -> bool {
    let conn = ffi_ref!(conn, false);
    write_connection_error(
        conn.local_error.as_ref(),
        is_app,
        error_code,
        reason,
        reason_len,
    )
}

#[no_mangle]
pub extern "C" fn quiche_stream_iter_next(
    iter: *mut StreamIter, stream_id: *mut u64,
) -> bool {
    let iter = ffi_mut!(iter, false);
    let stream_id = ffi_out!(stream_id, false);

    if let Some(v) = iter.next() {
        stream_id.write(v);
        return true;
    }

    false
}

#[no_mangle]
pub extern "C" fn quiche_stream_iter_free(iter: *mut StreamIter) {
    ffi_free!(iter);
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
    let out = ffi_out!(out);

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
    let out = ffi_out!(out, false);

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
    let out = ffi_out!(out, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    let stats = match conn.path_stats().nth(idx) {
        Some(p) => p,
        None => return c_int::from(Error::Done.to_c()),
    };

    let (local_addr, local_addr_len) = std_addr_to_c(&stats.local_addr);
    let (peer_addr, peer_addr_len) = std_addr_to_c(&stats.peer_addr);
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
        ffi_slice_out!(out, out_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    let out_len = match conn.dgram_recv_into(out) {
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
    ffi_free!(conn);
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
    let scid_seq = ffi_out!(scid_seq, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    let scid = ffi_slice!(scid, scid_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let scid = ConnectionId::from_ref(scid);

    let reset_token =
        ffi_slice!(reset_token, 16, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let Ok(reset_token) = reset_token.try_into() else {
        return c_int::from(FFI_ERR_INVALID_ARGUMENT);
    };
    let reset_token = u128::from_be_bytes(reset_token);

    match conn.new_scid(&scid, reset_token, retire_if_needed) {
        Ok(c) => {
            scid_seq.write(c);
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
    let peer = ffi_out!(peer, false);
    let peer_len = ffi_out!(peer_len, false);

    if let Some(v) = iter.next() {
        let (address, len) = std_addr_to_c(&v);
        peer.write(address);
        peer_len.write(len);
        return true;
    }

    false
}

#[no_mangle]
pub extern "C" fn quiche_socket_addr_iter_free(iter: *mut SocketAddrIter) {
    ffi_free!(iter);
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
    let seq = ffi_out!(seq, c_int::from(FFI_ERR_INVALID_ARGUMENT));
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
    let seq = ffi_out!(seq, c_int::from(FFI_ERR_INVALID_ARGUMENT));

    let local =
        ffi_addr!(local, local_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    match conn.migrate_source(local) {
        Ok(v) => {
            seq.write(v);
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

// Each tuple is a value plus its C storage and length output. A path event
// writes all its addresses or none if any output pointer is invalid.
fn write_path_addresses<const N: usize>(
    outputs: [(&SocketAddr, *mut sockaddr_storage, *mut socklen_t); N],
) -> bool {
    for &(_, address, len) in &outputs {
        if address.is_null() ||
            !address.is_aligned() ||
            len.is_null() ||
            !len.is_aligned()
        {
            return false;
        }
    }
    for (addr, address, len) in outputs {
        let (value, size) = std_addr_to_c(addr);
        // SAFETY: metadata was validated for every output before any write;
        // the C caller supplies writable storage for the declared types.
        // No references are formed to caller storage, which may be
        // uninitialized.
        unsafe {
            address.write(value);
            len.write(size);
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn quiche_path_event_new(
    ev: *const PathEvent, local_addr: *mut sockaddr_storage,
    local_addr_len: *mut socklen_t, peer_addr: *mut sockaddr_storage,
    peer_addr_len: *mut socklen_t,
) {
    let ev = ffi_ref!(ev);
    if let PathEvent::New(local, peer) = ev {
        write_path_addresses([
            (local, local_addr, local_addr_len),
            (peer, peer_addr, peer_addr_len),
        ]);
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_validated(
    ev: *const PathEvent, local_addr: *mut sockaddr_storage,
    local_addr_len: *mut socklen_t, peer_addr: *mut sockaddr_storage,
    peer_addr_len: *mut socklen_t,
) {
    let ev = ffi_ref!(ev);
    if let PathEvent::Validated(local, peer) = ev {
        write_path_addresses([
            (local, local_addr, local_addr_len),
            (peer, peer_addr, peer_addr_len),
        ]);
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_failed_validation(
    ev: *const PathEvent, local_addr: *mut sockaddr_storage,
    local_addr_len: *mut socklen_t, peer_addr: *mut sockaddr_storage,
    peer_addr_len: *mut socklen_t,
) {
    let ev = ffi_ref!(ev);
    if let PathEvent::FailedValidation(local, peer) = ev {
        write_path_addresses([
            (local, local_addr, local_addr_len),
            (peer, peer_addr, peer_addr_len),
        ]);
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_closed(
    ev: *const PathEvent, local_addr: *mut sockaddr_storage,
    local_addr_len: *mut socklen_t, peer_addr: *mut sockaddr_storage,
    peer_addr_len: *mut socklen_t,
) {
    let ev = ffi_ref!(ev);
    if let PathEvent::Closed(local, peer) = ev {
        write_path_addresses([
            (local, local_addr, local_addr_len),
            (peer, peer_addr, peer_addr_len),
        ]);
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_peer_migrated(
    ev: *const PathEvent, local_addr: *mut sockaddr_storage,
    local_addr_len: *mut socklen_t, peer_addr: *mut sockaddr_storage,
    peer_addr_len: *mut socklen_t,
) {
    let ev = ffi_ref!(ev);
    if let PathEvent::PeerMigrated(local, peer) = ev {
        write_path_addresses([
            (local, local_addr, local_addr_len),
            (peer, peer_addr, peer_addr_len),
        ]);
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
    let cid_sequence_number = ffi_out!(cid_sequence_number);

    if let PathEvent::ReusedSourceConnectionId(id, old, new) = ev {
        if write_path_addresses([
            (&old.0, old_local_addr, old_local_addr_len),
            (&old.1, old_peer_addr, old_peer_addr_len),
            (&new.0, local_addr, local_addr_len),
            (&new.1, peer_addr, peer_addr_len),
        ]) {
            cid_sequence_number.write(*id);
        }
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_pmtu_updated(
    ev: *const PathEvent, local_addr: *mut sockaddr_storage,
    local_addr_len: *mut socklen_t, peer_addr: *mut sockaddr_storage,
    peer_addr_len: *mut socklen_t, pmtu: *mut size_t,
) {
    let ev = ffi_ref!(ev);
    let pmtu = ffi_out!(pmtu);
    if let PathEvent::PmtuUpdated {
        local,
        peer,
        pmtu: value,
    } = ev
    {
        if write_path_addresses([
            (local, local_addr, local_addr_len),
            (peer, peer_addr, peer_addr_len),
        ]) {
            pmtu.write(*value);
        }
    }
}

#[no_mangle]
pub extern "C" fn quiche_path_event_free(ev: *mut PathEvent) {
    ffi_free!(ev);
}

#[no_mangle]
pub extern "C" fn quiche_put_varint(
    buf: *mut u8, buf_len: size_t, val: u64,
) -> c_int {
    let mut buf =
        ffi_slice_out!(buf, buf_len, c_int::from(FFI_ERR_INVALID_ARGUMENT));
    let mut encoded = [0; 8];
    let mut b = octets::OctetsMut::with_slice(&mut encoded);
    match b.put_varint(val) {
        Ok(bytes) if bytes.len() <= buf.len() => {
            buf.put_slice(bytes);
            0
        },
        Ok(_) => c_int::from(Error::BufferTooShort.to_c()),
        Err(e) => c_int::from(Error::from(e).to_c()),
    }
}

#[no_mangle]
pub extern "C" fn quiche_get_varint(
    buf: *const u8, buf_len: size_t, val: *mut u64,
) -> ssize_t {
    let val = ffi_out!(val, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));
    let buf = ffi_slice!(buf, buf_len, ssize_t::from(FFI_ERR_INVALID_ARGUMENT));

    let mut b = octets::Octets::with_slice(buf);
    match b.get_varint() {
        Ok(v) => {
            val.write(v);
        },

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

fn std_addr_to_c(addr: &SocketAddr) -> (sockaddr_storage, socklen_t) {
    // SAFETY: the platform sockaddr_storage type consists of integer/byte
    // fields, all of which admit zero initialization.
    let mut out: sockaddr_storage = unsafe { std::mem::zeroed() };
    let sin_port = addr.port().to_be();

    let len = match addr {
        SocketAddr::V4(addr) => {
            let sa_len = size_of::<sockaddr_in>();
            let out_in = (&raw mut out).cast::<sockaddr_in>();

            let s_addr = u32::from_ne_bytes(addr.ip().octets());

            #[cfg(not(windows))]
            let sin_addr = in_addr { s_addr };
            #[cfg(windows)]
            let sin_addr = in_addr {
                S_un: IN_ADDR_0 { S_addr: s_addr },
            };

            let address = sockaddr_in {
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

                sin_zero: [0; 8],
            };

            // SAFETY: sockaddr_storage has sufficient size and alignment
            // for sockaddr_in; the raw pointer comes from this local object.
            unsafe { out_in.write(address) };
            sa_len as socklen_t
        },

        SocketAddr::V6(addr) => {
            let sa_len = size_of::<sockaddr_in6>();
            let out_in6 = (&raw mut out).cast::<sockaddr_in6>();

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

            let address = sockaddr_in6 {
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

            // SAFETY: sockaddr_storage has sufficient size and alignment
            // for sockaddr_in6; the raw pointer comes from this local object.
            unsafe { out_in6.write(address) };
            sa_len as socklen_t
        },
    };
    (out, len)
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
    fn borrowed_optional_outputs_are_initialized_when_absent() {
        let pipe = test_utils::Pipe::new("cubic").unwrap();
        let mut data = MaybeUninit::<*const u8>::uninit();
        let mut len = MaybeUninit::<size_t>::uninit();
        quiche_conn_peer_cert(&pipe.client, data.as_mut_ptr(), len.as_mut_ptr());
        // SAFETY: the getter writes both outputs even for absence.
        assert!(unsafe { data.assume_init() }.is_null());
        assert_eq!(unsafe { len.assume_init() }, 0);
        quiche_conn_trace_id(&pipe.client, data.as_mut_ptr(), len.as_mut_ptr());
        // SAFETY: the getter writes both outputs with a live borrowed view.
        let (data, len) = unsafe { (data.assume_init(), len.assume_init()) };
        assert_eq!(
            unsafe { slice::from_raw_parts(data, len) },
            pipe.client.trace_id().as_bytes()
        );
    }

    #[test]
    fn connection_error_outputs_accept_uninitialized_storage() {
        let mut pipe = test_utils::Pipe::new("cubic").unwrap();
        pipe.handshake().unwrap();
        pipe.client.close(true, 42, b"reason").unwrap();
        let mut app = MaybeUninit::<bool>::uninit();
        let mut code = MaybeUninit::<u64>::uninit();
        let mut reason = MaybeUninit::<*const u8>::uninit();
        let mut len = MaybeUninit::<size_t>::uninit();
        assert!(quiche_conn_local_error(
            &pipe.client,
            app.as_mut_ptr(),
            code.as_mut_ptr(),
            reason.as_mut_ptr(),
            len.as_mut_ptr()
        ));
        // SAFETY: true indicates the error output was completely written.
        let (app, code, reason, len) = unsafe {
            (
                app.assume_init(),
                code.assume_init(),
                reason.assume_init(),
                len.assume_init(),
            )
        };
        assert!(app);
        assert_eq!(code, 42);
        assert_eq!(unsafe { slice::from_raw_parts(reason, len) }, b"reason");
    }

    #[test]
    fn c_algorithm_discriminants_are_checked_before_configuration() {
        let mut config = Config::new(PROTOCOL_VERSION).unwrap();
        assert_eq!(quiche_config_set_cc_algorithm(&mut config, 0), 0);
        assert_eq!(config.cc_algorithm, CongestionControlAlgorithm::Reno);
        for invalid in [-1, 2, 3, 5, c_int::MAX] {
            assert_eq!(
                quiche_config_set_cc_algorithm(&mut config, invalid),
                c_int::from(FFI_ERR_INVALID_ARGUMENT)
            );
            assert_eq!(config.cc_algorithm, CongestionControlAlgorithm::Reno);
        }
        for (value, algorithm) in [
            (1, CongestionControlAlgorithm::CUBIC),
            (4, CongestionControlAlgorithm::Bbr2Gcongestion),
        ] {
            assert_eq!(quiche_config_set_cc_algorithm(&mut config, value), 0);
            assert_eq!(config.cc_algorithm, algorithm);
        }
    }

    #[test]
    fn c_shutdown_discriminant_rejects_invalid_values() {
        let mut pipe = test_utils::Pipe::new("cubic").unwrap();
        pipe.handshake().unwrap();
        pipe.client.stream_send(4, b"a", false).unwrap();
        pipe.advance().unwrap();
        for invalid in [-1, 2, c_int::MAX] {
            assert_eq!(
                quiche_conn_stream_shutdown(&mut pipe.server, 4, invalid, 42),
                c_int::from(FFI_ERR_INVALID_ARGUMENT)
            );
        }
        let mut data = [0; 1];
        assert_eq!(pipe.server.stream_recv(4, &mut data), Ok((1, false)));
        assert_eq!(&data, b"a");
        assert_eq!(quiche_conn_stream_shutdown(&mut pipe.server, 4, 0, 42), 0);
    }

    #[rstest::rstest]
    fn c_varint_writes_uninitialized_prefix(
        #[values(0, 63, 64, 16383, 16384, 1_073_741_824, octets::MAX_VAR_INT)]
        value: u64,
    ) {
        let mut out = [MaybeUninit::<u8>::uninit(); 8];
        let len = octets::varint_len(value);
        assert_eq!(quiche_put_varint(out.as_mut_ptr().cast(), len, value), 0);
        let mut decoded = MaybeUninit::<u64>::uninit();
        assert_eq!(
            quiche_get_varint(out.as_ptr().cast(), len, decoded.as_mut_ptr()),
            ssize_t::try_from(len).unwrap()
        );
        // SAFETY: successful getter initialized decoded.
        assert_eq!(unsafe { decoded.assume_init() }, value);
        let mut sentinel = [0xaa; 8];
        assert_eq!(
            quiche_put_varint(sentinel.as_mut_ptr(), len - 1, value),
            c_int::from(Error::BufferTooShort.to_c())
        );
        assert_eq!(sentinel, [0xaa; 8]);
    }

    #[test]
    fn c_header_info_writes_uninitialized_connection_ids() {
        // Version negotiation with 2-byte DCID, 3-byte SCID and one version.
        let mut packet = [0x80, 0, 0, 0, 0, 2, 1, 2, 3, 3, 4, 5, 0, 0, 0, 1];
        let mut scid = [MaybeUninit::<u8>::uninit(); 20];
        let mut dcid = [MaybeUninit::<u8>::uninit(); 20];
        let mut version = MaybeUninit::<u32>::uninit();
        let mut ty = MaybeUninit::<u8>::uninit();
        let mut sl = scid.len();
        let mut dl = dcid.len();
        let mut tl = 0;
        assert_eq!(
            quiche_header_info(
                packet.as_mut_ptr(),
                packet.len(),
                0,
                version.as_mut_ptr(),
                ty.as_mut_ptr(),
                scid.as_mut_ptr().cast(),
                &mut sl,
                dcid.as_mut_ptr().cast(),
                &mut dl,
                ptr::null_mut(),
                &mut tl
            ),
            0
        );
        let (version, ty) = unsafe { (version.assume_init(), ty.assume_init()) };
        assert_eq!((version, ty, sl, dl, tl), (0, 6, 3, 2, 0));
        // SAFETY: reported lengths delimit initialized output prefixes.
        let (scid, dcid) = unsafe {
            (
                slice::from_raw_parts(scid.as_ptr().cast::<u8>(), sl),
                slice::from_raw_parts(dcid.as_ptr().cast::<u8>(), dl),
            )
        };
        assert_eq!(scid, &[3, 4, 5]);
        assert_eq!(dcid, &[1, 2]);
    }

    #[test]
    fn c_receive_writes_only_initialized_payload_prefix() {
        let mut config = test_utils::Pipe::default_config("cubic").unwrap();
        config.enable_dgram(true, 4, 4);
        let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();
        pipe.client.stream_send(4, b"payload", true).unwrap();
        pipe.client.dgram_send(b"datagram").unwrap();
        pipe.advance().unwrap();

        let mut out = [MaybeUninit::<u8>::uninit(); 32];
        let mut fin = MaybeUninit::<bool>::uninit();
        let mut err = MaybeUninit::<u64>::uninit();
        let len = quiche_conn_stream_recv(
            &mut pipe.server,
            4,
            out.as_mut_ptr().cast(),
            out.len(),
            fin.as_mut_ptr(),
            err.as_mut_ptr(),
        );
        assert_eq!(len, 7);
        // SAFETY: success initialized FIN and the first seven bytes of out.
        let (fin, payload) = unsafe {
            (
                fin.assume_init(),
                slice::from_raw_parts(out.as_ptr().cast::<u8>(), 7),
            )
        };
        assert!(fin);
        assert_eq!(payload, b"payload");
        let mut datagram = [MaybeUninit::<u8>::uninit(); 32];
        assert_eq!(
            quiche_conn_dgram_recv(
                &mut pipe.server,
                datagram.as_mut_ptr().cast(),
                datagram.len()
            ),
            8
        );
        // SAFETY: an eight-byte datagram was written into the output prefix.
        assert_eq!(
            unsafe { slice::from_raw_parts(datagram.as_ptr().cast::<u8>(), 8) },
            b"datagram"
        );
        assert_eq!(pipe.server.dgram_recv_queue_len(), 0);
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
        let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
        let written = if specified_path {
            let (from, from_len) =
                std_addr_to_c(&test_utils::Pipe::client_addr());
            let (to, to_len) = std_addr_to_c(&test_utils::Pipe::server_addr());
            quiche_conn_send_on_path(
                &mut pipe.client,
                buf.as_mut_ptr().cast(),
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
                buf.as_mut_ptr().cast(),
                buf.len(),
                info.as_mut_ptr(),
            )
        };
        assert!(written > 0);
        let len = usize::try_from(written).unwrap();
        // SAFETY: the successful send initialized exactly the returned prefix.
        let packet = unsafe {
            slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), len)
        };
        assert_eq!(pipe.server_recv(packet), Ok(len));
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
    fn c_send_protects_stream_and_datagram_in_uninitialized_storage() {
        let mut config = test_utils::Pipe::default_config("cubic").unwrap();
        config.enable_dgram(true, 4, 4);
        let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();
        pipe.handshake().unwrap();
        pipe.client.stream_send(4, b"stream payload", true).unwrap();
        pipe.client.dgram_send(b"datagram").unwrap();
        // Each successful output is consumed by the actual packet decryptor.
        for _ in 0..2 {
            let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
            let mut info = MaybeUninit::<SendInfo>::uninit();
            let len = usize::try_from(quiche_conn_send(
                &mut pipe.client,
                buf.as_mut_ptr().cast(),
                buf.len(),
                info.as_mut_ptr(),
            ))
            .unwrap();
            assert!(len > 0);
            // SAFETY: successful send initialized the reported packet prefix.
            let packet = unsafe {
                slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), len)
            };
            assert_eq!(pipe.server_recv(packet), Ok(len));
        }
        let mut payload = [0; 32];
        assert_eq!(pipe.server.stream_recv(4, &mut payload), Ok((14, true)));
        assert_eq!(&payload[..14], b"stream payload");
        assert_eq!(pipe.server.dgram_recv(&mut payload), Ok(8));
        assert_eq!(&payload[..8], b"datagram");
    }

    #[test]
    fn stateless_c_packets_initialize_uninitialized_output() {
        let scid = [1, 2, 3];
        let dcid = [4, 5];
        let new_scid = [6, 7, 8, 9];
        let token = b"token";
        let mut out = [MaybeUninit::<u8>::uninit(); 128];
        let len = usize::try_from(quiche_negotiate_version(
            scid.as_ptr(),
            scid.len(),
            dcid.as_ptr(),
            dcid.len(),
            out.as_mut_ptr().cast(),
            out.len(),
        ))
        .unwrap();
        // SAFETY: successful negotiation initialized the returned prefix.
        let packet = unsafe {
            slice::from_raw_parts_mut(out.as_mut_ptr().cast::<u8>(), len)
        };
        let hdr = Header::from_slice(packet, 0).unwrap();
        assert_eq!(hdr.ty, Type::VersionNegotiation);
        assert_eq!(hdr.dcid.as_ref(), scid);
        assert_eq!(hdr.scid.as_ref(), dcid);

        let mut out = [MaybeUninit::<u8>::uninit(); 128];
        let len = usize::try_from(quiche_retry(
            scid.as_ptr(),
            scid.len(),
            dcid.as_ptr(),
            dcid.len(),
            new_scid.as_ptr(),
            new_scid.len(),
            token.as_ptr(),
            token.len(),
            PROTOCOL_VERSION,
            out.as_mut_ptr().cast(),
            out.len(),
        ))
        .unwrap();
        // SAFETY: successful Retry initialized the returned prefix.
        let packet = unsafe {
            slice::from_raw_parts_mut(out.as_mut_ptr().cast::<u8>(), len)
        };
        let mut reader = octets::OctetsMut::with_slice(packet);
        let hdr = Header::from_bytes(&mut reader, 0).unwrap();
        assert_eq!(hdr.ty, Type::Retry);
        assert_eq!(hdr.dcid.as_ref(), scid);
        assert_eq!(hdr.scid.as_ref(), new_scid);
        assert_eq!(hdr.token.as_deref(), Some(token.as_slice()));
        assert_eq!(
            packet::verify_retry_integrity(&reader, &dcid, PROTOCOL_VERSION),
            Ok(())
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

    #[rstest::rstest]
    fn path_event_pair_initializes_c_outputs(#[values(0, 1, 2, 3, 5)] kind: u8) {
        let local: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let peer: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        type Accessor = extern "C" fn(
            *const PathEvent,
            *mut sockaddr_storage,
            *mut socklen_t,
            *mut sockaddr_storage,
            *mut socklen_t,
        );
        let (event, accessor): (PathEvent, Accessor) = match kind {
            0 => (PathEvent::New(local, peer), quiche_path_event_new),
            1 => (
                PathEvent::Validated(local, peer),
                quiche_path_event_validated,
            ),
            2 => (
                PathEvent::FailedValidation(local, peer),
                quiche_path_event_failed_validation,
            ),
            3 => (PathEvent::Closed(local, peer), quiche_path_event_closed),
            5 => (
                PathEvent::PeerMigrated(local, peer),
                quiche_path_event_peer_migrated,
            ),
            _ => unreachable!(),
        };
        let mut local_out = MaybeUninit::<sockaddr_storage>::uninit();
        let mut peer_out = MaybeUninit::<sockaddr_storage>::uninit();
        let mut local_len = MaybeUninit::<socklen_t>::uninit();
        let mut peer_len = MaybeUninit::<socklen_t>::uninit();
        accessor(
            &event,
            local_out.as_mut_ptr(),
            local_len.as_mut_ptr(),
            peer_out.as_mut_ptr(),
            peer_len.as_mut_ptr(),
        );
        // SAFETY: matching accessor has written the complete results.
        let (local_len, peer_len) =
            unsafe { (local_len.assume_init(), peer_len.assume_init()) };
        assert_eq!(
            unsafe { std_addr_from_c(local_out.as_ptr().cast(), local_len) },
            Ok(local)
        );
        assert_eq!(
            unsafe { std_addr_from_c(peer_out.as_ptr().cast(), peer_len) },
            Ok(peer)
        );

        // An invalid second output must not change the first.
        let mut unchanged_len: socklen_t = 77;
        let mut unused_len: socklen_t = 0;
        accessor(
            &event,
            local_out.as_mut_ptr(),
            &mut unchanged_len,
            ptr::null_mut(),
            &mut unused_len,
        );
        assert_eq!(unchanged_len, 77);
    }

    #[test]
    fn reused_cid_event_initializes_all_four_addresses() {
        let endpoints: [SocketAddr; 4] = [
            "127.0.0.1:8080".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
            "127.0.0.2:8081".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
        ];
        let event = PathEvent::ReusedSourceConnectionId(
            42,
            (endpoints[0], endpoints[1]),
            (endpoints[2], endpoints[3]),
        );
        let mut seq = MaybeUninit::<u64>::uninit();
        let mut addrs = [const { MaybeUninit::<sockaddr_storage>::uninit() }; 4];
        let mut lengths = [MaybeUninit::<socklen_t>::uninit(); 4];
        let [a, b, c, d] = &mut addrs;
        let [al, bl, cl, dl] = &mut lengths;
        quiche_path_event_reused_source_connection_id(
            &event,
            seq.as_mut_ptr(),
            a.as_mut_ptr(),
            al.as_mut_ptr(),
            b.as_mut_ptr(),
            bl.as_mut_ptr(),
            c.as_mut_ptr(),
            cl.as_mut_ptr(),
            d.as_mut_ptr(),
            dl.as_mut_ptr(),
        );
        // SAFETY: the matching accessor wrote all four addresses and the ID.
        assert_eq!(unsafe { seq.assume_init() }, 42);
        for ((addr, len), expected) in addrs.iter().zip(lengths).zip(endpoints) {
            assert_eq!(
                unsafe {
                    std_addr_from_c(addr.as_ptr().cast(), len.assume_init())
                },
                Ok(expected)
            );
        }
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

        let mut local_out = MaybeUninit::<sockaddr_storage>::uninit();
        let mut peer_out = MaybeUninit::<sockaddr_storage>::uninit();
        let mut local_len = MaybeUninit::<socklen_t>::uninit();
        let mut peer_len = MaybeUninit::<socklen_t>::uninit();
        let mut pmtu = MaybeUninit::<size_t>::uninit();

        quiche_path_event_pmtu_updated(
            &event,
            local_out.as_mut_ptr(),
            local_len.as_mut_ptr(),
            peer_out.as_mut_ptr(),
            peer_len.as_mut_ptr(),
            pmtu.as_mut_ptr(),
        );
        // SAFETY: the matching event writes each output.
        assert_eq!(unsafe { pmtu.assume_init() }, 1400);
        assert_eq!(
            unsafe {
                std_addr_from_c(
                    local_out.as_ptr().cast(),
                    local_len.assume_init(),
                )
            },
            Ok(local)
        );
        assert_eq!(
            unsafe {
                std_addr_from_c(peer_out.as_ptr().cast(), peer_len.assume_init())
            },
            Ok(peer)
        );
    }

    #[rstest::rstest]
    #[case("127.0.0.1:8080")]
    #[case("[2001:db8:85a3::8a2e:370:7334]:8080")]
    fn address_round_trip(#[case] address: &str) {
        let addr: SocketAddr = address.parse().unwrap();
        let (out, len) = std_addr_to_c(&addr);

        // Independently verify the C layout using inet_ntop rather than only
        // round-tripping through our own encoder and decoder.
        let mut dst = [0u8; 46];
        // SAFETY: the encoder initialized the matching sockaddr layout.
        let (family, source, port, expected_len) = unsafe {
            match addr {
                SocketAddr::V4(_) => {
                    let p = (&raw const out).cast::<sockaddr_in>();
                    (
                        AF_INET,
                        (&raw const (*p).sin_addr).cast::<c_void>(),
                        (*p).sin_port,
                        size_of::<sockaddr_in>(),
                    )
                },
                SocketAddr::V6(_) => {
                    let p = (&raw const out).cast::<sockaddr_in6>();
                    (
                        AF_INET6,
                        (&raw const (*p).sin6_addr).cast::<c_void>(),
                        (*p).sin6_port,
                        size_of::<sockaddr_in6>(),
                    )
                },
            }
        };
        assert_eq!(usize::try_from(len).unwrap(), expected_len);
        assert_eq!(u16::from_be(port), addr.port());
        // SAFETY: both the address and the output buffer have the required
        // size and remain valid for the call.
        let result = unsafe {
            inet_ntop(
                family as _,
                source,
                dst.as_mut_ptr().cast(),
                dst.len() as _,
            )
        };
        assert!(!result.is_null());
        // SAFETY: successful inet_ntop writes a NUL-terminated string.
        let text = unsafe { ffi::CStr::from_ptr(dst.as_ptr().cast()) };
        assert_eq!(text.to_str().unwrap(), addr.ip().to_string());

        // SAFETY: out contains the initialized address of length len.
        assert_eq!(
            unsafe { std_addr_from_c((&raw const out).cast(), len) },
            Ok(addr)
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

#[cfg(test)]
mod foreign_ownership_tests {
    use super::*;

    #[test]
    fn null_log_callback_is_rejected() {
        assert_eq!(
            quiche_enable_debug_logging(None, ptr::null_mut()),
            c_int::from(FFI_ERR_INVALID_ARGUMENT)
        );
    }

    #[test]
    fn free_rejects_null_and_misaligned_pointers() {
        quiche_config_free(ptr::null_mut());
        let config = quiche_config_new(PROTOCOL_VERSION);
        assert!(!config.is_null());
        quiche_config_free(config.cast::<u8>().wrapping_add(1).cast());
        quiche_config_free(config);
    }

    #[cfg(unix)]
    #[test]
    fn keylog_descriptor_ownership_is_transferred_only_on_acceptance() {
        use std::os::fd::AsRawFd;
        use std::os::fd::IntoRawFd;

        let mut pipe = test_utils::Pipe::new("cubic").unwrap();
        let file = std::fs::File::options()
            .write(true)
            .open("/dev/null")
            .unwrap();
        assert!(!quiche_conn_set_keylog_fd(
            ptr::null_mut(),
            file.as_raw_fd()
        ));
        // The caller still owns this descriptor; the function has not closed
        // it.
        assert!(file.metadata().is_ok());
        assert!(quiche_conn_set_keylog_fd(
            &mut pipe.client,
            file.into_raw_fd()
        ));
        assert!(!quiche_conn_set_keylog_fd(&mut pipe.client, -1));
    }

    #[cfg(unix)]
    #[test]
    fn invalid_owned_descriptors_are_rejected() {
        for fd in [-1, c_int::MAX] {
            // SAFETY: neither descriptor is open; no ownership is transferred.
            assert!(unsafe { file_from_owned_fd(fd) }.is_none());
        }
    }
}
