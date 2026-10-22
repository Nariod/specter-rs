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

/// Probe loop, page by page (x64 page = 0x1000).
///
/// # Safety
///
/// Naked function: the whole body is assembly; never call from Rust.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ___chkstk_ms() {
    naked_asm!(
        "push rcx",
        "cmp rax, 0x1000",
        "lea rcx, [rsp + 8]", // rcx = top of the probed region
        "jb 1f",              // smaller than a page: single probe below
        "2:",
        "sub rcx, 0x1000",
        "test qword ptr [rcx], rcx", // touch the page (grows the stack)
        "sub rax, 0x1000",
        "cmp rax, 0x1000",
        "ja 2b", // keep probing while > 1 page remains
        "1:",
        "sub rcx, rax",
        "test qword ptr [rcx], rcx", // final probe at the exact bottom
        "pop rax",
        "pop rcx",
        "ret",
    );
}
