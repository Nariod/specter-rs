// Diagnostic BOF: dumps the raw PROCESSENTRY32W bytes filled by
// Process32FirstW, to pin the real x64 field offsets (iteration 16:
// the ps list lost 2 chars of every name, and the "canonical" layout
// contradicts the observed ppid values).
//
// Build:
//   rustc --target x86_64-pc-windows-gnu --emit=obj -C opt-level=z \
//       -C panic=abort dump_entry.rs -o dump_entry.o
//
// Imports follow the loader convention (WIRE.md, BOF contract):
// __imp_MODULE$Func extern statics (indirect through the mapFuncs
// slot), Beacon API by plain name.

#![no_std]
#![crate_type = "cdylib"]
#![allow(clippy::missing_safety_doc)]

use core::ffi::c_void;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

extern "C" {
    #[link_name = "__imp_KERNEL32$CreateToolhelp32Snapshot"]
    static CREATE_SNAP: *const c_void;
    #[link_name = "__imp_KERNEL32$Process32FirstW"]
    static P32_FIRST: *const c_void;
    #[link_name = "__imp_KERNEL32$Process32NextW"]
    static P32_NEXT: *const c_void;
    #[link_name = "__imp_KERNEL32$CloseHandle"]
    static CLOSE: *const c_void;
    #[link_name = "BeaconOutput"]
    static BEACON_OUTPUT: *const c_void;
}

const TH32CS_SNAPPROCESS: u32 = 0x2;
/// sizeof(PROCESSENTRY32W) per the beacon's own constant (0x238).
const ENTRY_SIZE: usize = 0x238;

#[no_mangle]
pub unsafe extern "C" fn go(_args: *mut u8, _alen: i32) {
    let create: unsafe extern "system" fn(u32, u32) -> isize =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(CREATE_SNAP)));
    let first: unsafe extern "system" fn(isize, *mut u8) -> i32 =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(P32_FIRST)));
    let next: unsafe extern "system" fn(isize, *mut u8) -> i32 =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(P32_NEXT)));
    let close: unsafe extern "system" fn(isize) -> i32 =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(CLOSE)));
    let output: unsafe extern "system" fn(i32, *const u8, i32) =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(BEACON_OUTPUT)));

    let mut entry = [0u8; ENTRY_SIZE];
    entry[..4].copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
    let snap = create(TH32CS_SNAPPROCESS, 0);
    if snap == -1 {
        output(0, b"dump_entry: snapshot failed\n\0".as_ptr(), 26);
        return;
    }
    let mut ok = first(snap, entry.as_mut_ptr());
    // Walk to a user-space entry (pid >= 5000: distinctive ppid/pri).
    while ok != 0 {
        let pid = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
        if pid >= 5000 {
            break;
        }
        entry[..4].copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
        ok = next(snap, entry.as_mut_ptr());
    }
    close(snap);
    if ok == 0 {
        output(0, b"dump_entry: walk failed\n\0".as_ptr(), 21);
        return;
    }
    // Raw dump of the chosen entry: 0x60 bytes from dwSize.
    output(0, entry.as_ptr(), 0x60);
}
