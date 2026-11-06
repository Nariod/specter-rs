// Test BOF: argument parsing (BeaconDataParse/Int/Short/Length/Extract/Ptr)
// plus the C-variadic BeaconPrintf conversion set (%s %d %u %x %X %c %p).
//
// Build (no toolchain beyond the beacon's own target):
//   rustc --target x86_64-pc-windows-gnu --emit=obj -C opt-level=z \
//       -C panic=abort args.rs -o args.o
//
// Call convention follows docs/WIRE.md (BOF contract): every Beacon API is
// an extern *static (refptr into the mapFuncs slot), never a direct extern
// fn â see tools/bof/hello.rs.

#![no_std]
# [crate_type = "cdylib"]
#![allow clippy::missing_safety_doc)]

use core::ffi::c_void;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Same layout as the loader's parser state (`specter_core::coff::Datum`).
#[repr(C)]
struct Datum {
    original: *mut u8,
    buffer: *mut u8,
    length: i32,
    size: i32,
}

extern "C" {
    #[link_name = "BeaconDataParse"]
    static B_PARSE: *const c_void;
    #[link_name = "BeaconDataInt"]
    static B_INT: *const c_void;
    #[link_name = "BeaconDataShort"]
    static B_SHORT: *const c_void;
    #[link_name = "BeaconDataLength"]
    static B_LENGTH: *const c_void;
    #[link_name = "BeaconDataExtract"]
    static B_EXTRACT: *const c_void;
    #[link_name = "BeaconDataPtr"]
    static B_PTR: *const c_void;
    #[link_name = "BeaconPrintf"]
    static B_PRINTF: *const c_void;
}

#[no_mangle]
pub unsafe extern "C" fn go(args: *mut u8, alen: i32) {
    let parse: unsafe extern "C" fn(*mut Datum, *mut u8, i32) =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_PARSE)));
    let int: unsafe extern "C" fn(*mut Datum) -> i32 =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_INT)));
    let short: unsafe extern "C" fn(*mut Datum) -> i16 =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_SHORT)));
    let length: unsafe extern "C" fn(*mut Datum) -> i32 =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_LENGTH)));
    let extract: unsafe extern "C" fn(*mut Datum, *mut i32) -> *mut u8 =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_EXTRACT)));
    let ptr: unsafe extern "C" fn(*mut Datum, i32) -> *mut u8 =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_PTR)));
    let printf: unsafe extern "C" fn(i32, *const u8, ...) =
        core::mem::transmute(core::ptr::read(core::ptr::addr_of!(B_PRINTF)));

    let mut d = Datum {
        original: core::ptr::null_mut(),
        buffer: core::ptr::null_mut(),
        length: 0,
        size: 0,
    };
    parse(&mut d, args, alen);
    let n = int(&mut d);
    let s = short(&mut d);
    let mut blen = 0i32;
    let blob = extract(&mut d, &mut blen);
    let rest = length(&mut d);
    let p = ptr(&mut d, 4);
    printf(
        0,
        b"args: n=%d s=%d blen=%d rest=%d ptr4=%p\n\0".as_ptr(),
        n,
        s as i32,
        blen,
        rest,
        p,
    );
    if !blob.is_null() && blen > 0 {
        printf(0, b"blob: %s\n\0".as_ptr(), blob);
    }
    printf(
        0,
        b"fmt: %s %d %u %x %X %c\n\0".as_ptr(),
        b"str\0".as_ptr(),
        -7,
        42u32,
        0xdead_beefu32,
        0xabcdeu32,
        b'A' as i32,
    );
}
