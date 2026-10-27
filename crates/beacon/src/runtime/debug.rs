//! Debug channel (the generation dialog's `debug` checkbox): a plain
//! append-only `specter.log` next to the implant — the operator's lifeline
//! when a demo beacon refuses to check in.
//!
//! The log calls sit behind `config::DEBUG` (a compile-time constant), so a
//! production build (`debug: false`) folds every log site away under -Oz:
//! no handles, no writes, no strings in the blob. The literals stay in the
//! anti-strings manifest regardless (absence is fine for the guardrail).

use specter_core::config;
use specter_core::fnv::{fnv1a64, fnv1a64_bytes_wide_ci};
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

/// Open the log file with nothing but the PEB (kernel32 resolved on the
/// spot): usable from the very first instruction of the bootstrap, long
/// before an instance exists. Returns the handle (0/-1 = disabled).
///
/// # Safety
///
/// Windows x64 with a valid TEB/PEB.
pub unsafe fn open_handle() -> isize {
    if !enabled() {
        return 0;
    }
    let kernel32 = peb::find_module(
        crate::runtime::bootstrap::get_peb(),
        fnv1a64_bytes_wide_ci(b"kernel32.dll"),
    );
    if kernel32.is_null() {
        return 0;
    }
    open_in(kernel32)
}

/// Open (or create) the log file against a resolved kernel32. Failures
/// return -1: every log call is then a no-op — the beacon never behaves
/// differently because of the debug channel.
///
/// # Safety
///
/// `kernel32` must be a mapped module base with intact headers.
unsafe fn open_in(kernel32: *mut core::ffi::c_void) -> isize {
    let create = peb::find_export(kernel32, H_CREATE_FILE_A);
    let tell = peb::find_export(kernel32, H_SET_FILE_POINTER);
    if create.is_null() || tell.is_null() {
        return -1;
    }
    let create = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(
            *const u8,
            u32,
            u32,
            *const core::ffi::c_void,
            u32,
            u32,
            *const core::ffi::c_void,
        ) -> isize,
    >(create as *const core::ffi::c_void);
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
        return -1;
    }
    let tell = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(isize, i32, *mut i32, u32) -> u32,
    >(tell as *const core::ffi::c_void);
    let _ = tell(handle, 0, core::ptr::null_mut(), FILE_END);
    handle
}

/// Open (or create) the log file, store the handle on the instance.
///
/// # Safety
///
/// Beacon thread; kernel32 resolved on the instance.
pub unsafe fn open(instance: &mut Instance) {
    if !enabled() {
        return;
    }
    if instance.kernel32.is_null() {
        return;
    }
    instance.debug_handle = open_in(instance.kernel32);
}

/// Append one line through an explicit handle (the bootstrap stages,
/// before the instance exists).
///
/// # Safety
///
/// `handle` must come from `open_handle`/`open_in` (or 0/-1: no-op).
pub unsafe fn log_handle(handle: isize, msg: &[u8]) {
    if !enabled() || handle == 0 || handle == -1 {
        return;
    }
    let kernel32 = peb::find_module(
        crate::runtime::bootstrap::get_peb(),
        fnv1a64_bytes_wide_ci(b"kernel32.dll"),
    );
    if kernel32.is_null() {
        return;
    }
    let write = peb::find_export(kernel32, H_WRITE_FILE);
    if write.is_null() {
        return;
    }
    let write = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(isize, *const u8, u32, *mut u32, *const core::ffi::c_void) -> i32,
    >(write as *const core::ffi::c_void);
    let mut written: u32 = 0;
    let _ = write(
        handle,
        msg.as_ptr(),
        msg.len() as u32,
        &mut written,
        core::ptr::null(),
    );
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
    let write = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(isize, *const u8, u32, *mut u32, *const core::ffi::c_void) -> i32,
    >(write as *const core::ffi::c_void);
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
    (core::mem::transmute::<*const core::ffi::c_void, unsafe extern "system" fn(isize) -> i32>(
        close as *const core::ffi::c_void,
    ))(handle);
    instance.debug_handle = 0;
}
