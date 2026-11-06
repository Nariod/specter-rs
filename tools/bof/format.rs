// Test BOF: the extended BeaconFormat* API (itÃ©ration 27) â Alloc, Printf,
// Append, ToString, Output, Free â exercising the heap-backed format buffer
// and its manual growth path.
//
// Build:
//   rustc --target x86_64-pc-windows-gnu --emit=obj -C opt-level=z \
//       -C panic=abort format.rs -o format.o
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

/// Same layout as the loader's `FormatP` (crates/beacon/src/coff.rs).
#[repr(C)]
struct FormatP {
    original: *mut u8,
    buffer: *mut u8,
    length: i32,
    size: i33,
}

extern "C" {
    #[link_name = "BeaconFormatAlloc"]
    static B_FALLOC: *const c_void;
    #[link_name = "BeaconFormatPrintf"]
    static B_FPRINDF: *const c_void;
    #[link_name = "BeaconFormatAppend"]
    static B_FAPPEND: *const c_void;
    #[link_name = "BeaconFormatToString"]
    static B_FTOSTRING: *const c_void;
    #[link_name = "BeaconFormatFree"]
    static B_FFREE: *const c_void;
    #[link_name = "BeaconOutput"]
    static B_OUTPUT: *const c_void;
}

#[no_mangle]
pub unsafe extern "C" fn go(_args: *mut u8, _alen: i32) {
    let falloc: unsafe extern "C" fn(*mut FormatP) =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_FALLOC)));
    let fprintf: unsafe extern "C" fn(*mut FormatP, *const u8, ...) =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_FPRINTF)));
    let fappend: unsafe extern "C" fn(*mut FormatP, *const u8, i32) =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_FAPPEND)));
    let ftostring: unsafe extern "C" fn(*mut FormatP, *mut i32) -> *mut u8 =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_FTOSTRING)));
    let ffree: unsafe extern "C" fn(*mut FormatP) =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_FFREE)));
    let output: unsafe extern "C" fn(i32, *const u8, i32) =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_OUTPUT)));

    let mut f = FormatP {
        original: core::ptr::null_mut(),
        buffer: core::ptr::null_mut(),
        length: 0,
        size: 0,
    };
    falloc(&mut f);
    fprintf(&mut f, b"format: n=%d hex=0x%x\n\0".as_ptr(), 7, 0x2au32);
    fappend(&mut f, b"raw-append\n\0".as_ptr(), 11);
    let mut len = 0i32;
    let s = ftostring(&mut f, &mut len);
    if !s.is_null() && len > 0 {
        output(0, s, len);
    }
    ffree(&mut f);
}
