//! The C ABI. See ADR-0002, part 4, and `bindings/c/README.md`.
//!
//! - Handles are opaque, and each has its own `_free`.
//! - Every fallible call returns a status, whose values are the IDL's error codes.
//! - Bytes from the core come in a `qalqon_buffer_t`, released with `qalqon_buffer_free`.
//!   Bytes into the core are borrowed for the duration of the call.
//! - Nothing calls back: events, frames and host effects are all polled.
//! - A panic never crosses this boundary. It becomes `QALQON_INTERNAL`.
//!
//! Every `unsafe` below has one justification: a C caller promises that each pointer is
//! valid for the call, which is the contract of this ABI and cannot be checked here. Null
//! is checked everywhere it could plausibly be passed by mistake.
#![allow(clippy::missing_safety_doc)]

#[rustfmt::skip]
mod generated;

pub use generated::*;

use qalqon_sdk::api;
use qalqon_sdk::{ApiError, ErrorKind};
use serde::de::DeserializeOwned;
use std::ffi::{CStr, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// A status: 0 for success, otherwise one of the IDL's error codes.
pub type qalqon_status_t = u32;

/// The ABI's version. A binding compares this at load time.
pub const QALQON_ABI_VERSION: u32 = 0;

/// Bytes owned by this library. Release them with `qalqon_buffer_free`. Text is also
/// followed by a NUL that `len` does not count, so `data` can be used as a C string.
#[repr(C)]
pub struct qalqon_buffer_t {
    /// The bytes. Null when empty.
    pub data: *mut u8,
    /// How many there are.
    pub len: usize,
}

fn guard(body: impl FnOnce() -> Result<(), ApiError>) -> qalqon_status_t {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => e.0.code(),
        Err(_) => ErrorKind::Internal.code(),
    }
}

unsafe fn handle_ref<'a, T>(handle: *const T) -> Result<&'a T, ApiError> {
    // SAFETY: the caller promises a live handle from this library. Null is refused.
    unsafe { handle.as_ref() }.ok_or_else(|| ErrorKind::InvalidArgument.into())
}

unsafe fn str_arg<'a>(value: *const c_char) -> Result<&'a str, ApiError> {
    if value.is_null() {
        return Err(ErrorKind::InvalidArgument.into());
    }
    // SAFETY: the caller promises a NUL-terminated string that outlives the call.
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map_err(|_| ErrorKind::InvalidArgument.into())
}

unsafe fn bytes_arg<'a>(data: *const u8, len: usize) -> Result<&'a [u8], ApiError> {
    if len == 0 {
        return Ok(&[]);
    }
    if data.is_null() {
        return Err(ErrorKind::InvalidArgument.into());
    }
    // SAFETY: the caller promises `len` readable bytes at `data` for the call.
    Ok(unsafe { std::slice::from_raw_parts(data, len) })
}

unsafe fn optional_bytes_arg(data: *const u8, len: usize) -> Result<Option<Vec<u8>>, ApiError> {
    if data.is_null() {
        return Ok(None);
    }
    // SAFETY: as in `bytes_arg`.
    Ok(Some(unsafe { bytes_arg(data, len) }?.to_vec()))
}

/// A JSON argument. Null is JSON `null`, so an optional value can simply be left out.
unsafe fn json_arg<T: DeserializeOwned>(value: *const c_char) -> Result<T, ApiError> {
    let text = if value.is_null() {
        "null"
    } else {
        unsafe { str_arg(value) }?
    };
    serde_json::from_str(text).map_err(|_| ErrorKind::InvalidArgument.into())
}

unsafe fn write_out<T>(out: *mut T, value: T) -> Result<(), ApiError> {
    if out.is_null() {
        return Err(ErrorKind::InvalidArgument.into());
    }
    // SAFETY: the caller promises writable storage for one value at `out`.
    unsafe { out.write(value) };
    Ok(())
}

fn make_buffer(mut bytes: Vec<u8>) -> qalqon_buffer_t {
    let len = bytes.len();
    bytes.push(0);
    let mut boxed = bytes.into_boxed_slice();
    let data = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    qalqon_buffer_t { data, len }
}

unsafe fn write_buffer(out: *mut qalqon_buffer_t, bytes: Vec<u8>) -> Result<(), ApiError> {
    // SAFETY: passed through to `write_out`.
    unsafe { write_out(out, make_buffer(bytes)) }
}

unsafe fn write_json<T: serde::Serialize>(
    out: *mut qalqon_buffer_t,
    value: &T,
) -> Result<(), ApiError> {
    let text = serde_json::to_vec(value).map_err(|_| ErrorKind::Internal)?;
    // SAFETY: passed through to `write_out`.
    unsafe { write_buffer(out, text) }
}

unsafe fn write_optional_buffer(
    out: *mut qalqon_buffer_t,
    present: *mut bool,
    value: Option<Vec<u8>>,
) -> Result<(), ApiError> {
    // SAFETY: passed through to `write_out`.
    unsafe {
        write_out(present, value.is_some())?;
        write_buffer(out, value.unwrap_or_default())
    }
}

unsafe fn write_optional_json<T: serde::Serialize>(
    out: *mut qalqon_buffer_t,
    present: *mut bool,
    value: Option<T>,
) -> Result<(), ApiError> {
    // SAFETY: passed through to `write_out`.
    unsafe {
        write_out(present, value.is_some())?;
        match value {
            Some(v) => write_json(out, &v),
            None => write_buffer(out, Vec::new()),
        }
    }
}

/// Releases a buffer. Passing null, or a buffer already released, does nothing.
///
/// # Safety
/// `buffer` must point to a buffer from this library, or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qalqon_buffer_free(buffer: *mut qalqon_buffer_t) {
    if buffer.is_null() {
        return;
    }
    // SAFETY: the caller promises this is our buffer. `make_buffer` allocated `len + 1` bytes.
    unsafe {
        let b = &mut *buffer;
        if !b.data.is_null() {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                b.data,
                b.len + 1,
            )));
        }
        b.data = std::ptr::null_mut();
        b.len = 0;
    }
}

/// The ABI's version. A binding refuses to run on a different major version.
#[unsafe(no_mangle)]
pub extern "C" fn qalqon_abi_version() -> u32 {
    QALQON_ABI_VERSION
}

/// Identifies this build, so a binding can detect a mismatched library at load time. The
/// string is static, and the caller must not free it.
#[unsafe(no_mangle)]
pub extern "C" fn qalqon_build_id() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// The name of the crypto provider in this build. A test-only build says so here. The
/// string is static, and the caller must not free it.
#[unsafe(no_mangle)]
pub extern "C" fn qalqon_provider_name() -> *const c_char {
    static NAME: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
    NAME.get_or_init(|| std::ffi::CString::new(qalqon_sdk::provider_name()).unwrap_or_default())
        .as_ptr()
}

/// The name of a status code, such as `peerRevoked`. The string is static, and the caller
/// must not free it.
#[unsafe(no_mangle)]
pub extern "C" fn qalqon_status_name(status: qalqon_status_t) -> *const c_char {
    static NAMES: std::sync::OnceLock<Vec<(u32, std::ffi::CString)>> = std::sync::OnceLock::new();
    let names = NAMES.get_or_init(|| {
        (0..=1000)
            .filter_map(ErrorKind::from_code)
            .map(|k| {
                (
                    k.code(),
                    std::ffi::CString::new(k.name()).unwrap_or_default(),
                )
            })
            .collect()
    });
    match names.iter().find(|(code, _)| *code == status) {
        Some((_, name)) => name.as_ptr(),
        None => c"unknown".as_ptr(),
    }
}

/// Reads a string field from a JSON value this library returned, such as an event's `type`,
/// for a C program with no JSON parser. A missing field is `QALQON_INVALID_ARGUMENT`.
///
/// # Safety
/// `json` and `key` must be NUL-terminated strings, and `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qalqon_json_get_string(
    json: *const c_char,
    key: *const c_char,
    out: *mut qalqon_buffer_t,
) -> qalqon_status_t {
    guard(|| {
        let value: serde_json::Value = unsafe { json_arg(json) }?;
        let key = unsafe { str_arg(key) }?;
        let text = value
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or(ErrorKind::InvalidArgument)?;
        unsafe { write_buffer(out, text.as_bytes().to_vec()) }
    })
}

/// Reads a whole-number field from a JSON value this library returned, such as an event's
/// `channelId`.
///
/// # Safety
/// `json` and `key` must be NUL-terminated strings, and `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qalqon_json_get_u64(
    json: *const c_char,
    key: *const c_char,
    out: *mut u64,
) -> qalqon_status_t {
    guard(|| {
        let value: serde_json::Value = unsafe { json_arg(json) }?;
        let key = unsafe { str_arg(key) }?;
        let number = value
            .get(key)
            .and_then(|v| v.as_u64())
            .ok_or(ErrorKind::InvalidArgument)?;
        unsafe { write_out(out, number) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn a_panic_does_not_cross_the_boundary() {
        assert_eq!(guard(|| panic!("boom")), ErrorKind::Internal.code());
    }

    #[test]
    fn buffers_are_nul_terminated_and_free_twice_safely() {
        let mut buffer = make_buffer(b"hello".to_vec());
        assert_eq!(buffer.len, 5);
        let text = unsafe { CStr::from_ptr(buffer.data.cast()) };
        assert_eq!(text.to_bytes(), b"hello");
        unsafe {
            qalqon_buffer_free(&mut buffer);
            qalqon_buffer_free(&mut buffer);
            qalqon_buffer_free(std::ptr::null_mut());
        }
        assert!(buffer.data.is_null());
    }

    #[test]
    fn null_and_bad_arguments_are_errors_not_crashes() {
        let mut out = qalqon_buffer_t {
            data: std::ptr::null_mut(),
            len: 0,
        };
        assert_eq!(
            unsafe { qalqon_conformance_run(std::ptr::null(), &mut out) },
            ErrorKind::InvalidArgument.code()
        );
        let bad_utf8 = CString::new(vec![0xFFu8, 0xFE]).unwrap();
        assert_eq!(
            unsafe { qalqon_conformance_run(bad_utf8.as_ptr(), &mut out) },
            ErrorKind::InvalidArgument.code()
        );
        assert_eq!(
            unsafe { qalqon_session_close(std::ptr::null()) },
            ErrorKind::InvalidArgument.code()
        );
    }

    #[test]
    fn status_names_match_the_idl() {
        let name = unsafe { CStr::from_ptr(qalqon_status_name(204)) };
        assert_eq!(name.to_str().unwrap(), "peerRevoked");
        assert_eq!(
            unsafe { CStr::from_ptr(qalqon_status_name(9999)) }
                .to_str()
                .unwrap(),
            "unknown"
        );
    }

    #[test]
    fn json_helpers_read_fields() {
        let json = CString::new(r#"{"type":"messageAvailable","channelId":7}"#).unwrap();
        let (key_type, key_id, key_missing) = (
            CString::new("type").unwrap(),
            CString::new("channelId").unwrap(),
            CString::new("nope").unwrap(),
        );
        let mut buffer = qalqon_buffer_t {
            data: std::ptr::null_mut(),
            len: 0,
        };
        assert_eq!(
            unsafe { qalqon_json_get_string(json.as_ptr(), key_type.as_ptr(), &mut buffer) },
            0
        );
        assert_eq!(
            unsafe { CStr::from_ptr(buffer.data.cast()) }
                .to_str()
                .unwrap(),
            "messageAvailable"
        );
        unsafe { qalqon_buffer_free(&mut buffer) };
        let mut id = 0u64;
        assert_eq!(
            unsafe { qalqon_json_get_u64(json.as_ptr(), key_id.as_ptr(), &mut id) },
            0
        );
        assert_eq!(id, 7);
        assert_ne!(
            unsafe { qalqon_json_get_u64(json.as_ptr(), key_missing.as_ptr(), &mut id) },
            0
        );
    }
}
