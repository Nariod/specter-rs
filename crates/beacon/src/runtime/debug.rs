//! Debug channel (the generation dialog's `debug` checkbox): a plain
//! append-only `specter.log` next to the implant — the operator's lifeline
//! when a demo beacon refuses to check in.
//!
//! The log calls sit behind `config::DEBUG` (a compile-time constant), so a
//! production build (`debug: false`) folds every log site away under -Oz:
//! no handles, no writes, no strings in the blob. The literals stay in the
//! anti-strings manifest regardless (absence is fine for the guardrail).

use specter_core::config;
use specter_core::fnv::fnv1a64;
use specter_core::peb;

use crate::runtime::bootstrap::Instance;

const H_CREATE_FILE_A: u64 = fnv1a64(b"CreateFileA");
const H_WRITE_FILE: u64 = fnv1a64(b"WriteFile");
const H_CLOSE_HANDLE: u64 = fnv1a64(b"CloseHandle");
const H_SET_FILE_POINTER: u64 = fnv1a64(b"SetFilePointer");

const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x1;
const OPEN_ALWAYS: u32 = 4;
const FILE_END: u32 = 2;

/// The log file name, NUL-terminated for the ANSI API.
const LOG_PATH: &[u8] = b"specter.log\0";

/// Whether this build carries the debug channel (compile-time).
pub fn enabled() -> bool {
    config::DEBUG
}

/// Open (or create) the log file and seek to its end. Failures leave the
/// handle at 0: every log call is then a no-op — the beacon never behaves
/// differently because of the debug channel.
///
/// # Safety
///
/// Beacon thread; kernel32 resolved on the instance.
pub unsafe fn open(instance: &mut Instance) {
    if !enabled() {
        return;
    }
    let kernel32 = instance.kernel32;
    if kernel32.is_null() {
        return;
    }
    let create = peb::find_export(kernel32, H_CREATE_FILE_A);
    let tell = peb::find_export(kernel32, H_SET_FILE_POINTER);
    if create.is_null() || tell.is_null() {
        return;
    }
    let create = *(create
        as *const unsafe extern "system" fn(
            *const u8,
            u32,
            u32,
            *const core::ffi::c_void,
            u32,
            u32,
            *const core::ffi::c_void,
        ) -> isize);
    let handle = create(
        LOG_PATH.as_ptr(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        core::ptr::null(),
        OPEN_ALWAYS,
        0,
        core::ptr::null(),
    );
    if handle == -1 {
        return;
    }
    let tell = *(tell as *const unsafe extern "system" fn(isize, i32, *mut i32, u32) -> u32);
    let _ = tell(handle, 0, core::ptr::null_mut(), FILE_END);
    instance.debug_handle = handle;
}

/// Append one line to the log. Static strings only — the beacon has no
/// formatting, so every message is a plain literal in the manifest.
///
/// # Safety
///
/// Beacon thread (or any thread with the instance in its TEB).
pub unsafe fn log(instance: &Instance, msg: &[u8]) {
    if !enabled() || msg.is_empty() {
        return;
    }
    let handle = instance.debug_handle;
    if handle == 0 || handle == -1 {
        return;
    }
    let kernel32 = instance.kernel32;
    if kernel32.is_null() {
        return;
    }
    let write = peb::find_export(kernel32, H_WRITE_FILE);
    if write.is_null() {
        return;
    }
    let write = *(write
        as *const unsafe extern "system" fn(
            isize,
            *const u8,
            u32,
            *mut u32,
            *const core::ffi::c_void,
        ) -> i32);
    let mut written: u32 = 0;
    let _ = write(
        handle,
        msg.as_ptr(),
        msg.len() as u32,
        &mut written,
        core::ptr::null(),
    );
}

/// Close the log handle (the silent exit path).
///
/// # Safety
///
/// Beacon thread.
pub unsafe fn close(instance: &mut Instance) {
    let handle = instance.debug_handle;
    if handle == 0 || handle == -1 {
        return;
    }
    let kernel32 = instance.kernel32;
    if kernel32.is_null() {
        return;
    }
    let close = peb::find_export(kernel32, H_CLOSE_HANDLE);
    if close.is_null() {
        return;
    }
    (*(close as *const unsafe extern "system" fn(isize) -> i32))(handle);
    instance.debug_handle = 0;
}
