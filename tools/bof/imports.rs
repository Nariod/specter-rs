// Test BOF: dynamic import resolution â the loader must resolve
// __imp_KERNEL32$GetTickCount by FNV-64 hash through the PEB, then the BOF
// calls it through the mapFuncs slot and reports via BeaconPrintf.
//
// Build:
//   rustc --target x86_64-pc-windows-gnu --emit=obj -C opt-level=z \
//       -C panic=abort imports.rs -o imports.o
//
// Convention: extern *static* (refptr), never a direct extern fn â see
// docs/WIRE.md (BOF contract) and tools/bof/hello.rs.

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
    #[link_name = "__imp_KERNEL32$GetTickCount"]
    static IMP_GET_TICK_COUNT: *const c_void;
    #[link_name = "BeaconPrintf"]
    static B_PRINTF: *const c_void;
}

#[no_mangle]
pub unsafe extern "C" fn go(_args: *mut u8, _alen: i32) {
    let get_tick_count: unsafe extern "system" fn() -> u32 =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(IMP_GET_TICK_COUNT)));
    let printf: unsafe extern "C" fn(i32, *const u8, ...) =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_PRINTF)));

    let t = get_tick_count();
    printf(0, b"imports: GetTickCount=%u (0x%x)\n\0".as_ptr(), t, t);
}
