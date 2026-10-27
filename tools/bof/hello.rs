// Reference test BOF: the smallest possible COFF object exercising the
// loader's Beacon API surface (mapFuncs by hash, C-variadic BeaconPrintf).
// Validated end-to-end on the real Windows test VM (iteration 16):
// session -> execute bof -> "bof: exec"/"bof: done" -> operator console
// shows "hello from the specter-rs bof".
//
// Build (no toolchain beyond the beacon's own target):
//   rustc --target x86_64-pc-windows-gnu --emit=obj -C opt-level=z \
//       -C panic=abort hello.rs -o hello.o
//
// CONVENTION (docs/WIRE.md, BOF contract): a BOF never calls the Beacon
// API directly. The `jmp/call rel32` a plain extern fn would emit jumps
// INTO the 8-byte mapFuncs slot (the original's runner.c behaves the
// same). The reference must be indirect — the extern *static* below is
// the slot itself: LLVM emits a `.rdata$.refptr.BeaconPrintf` section
// holding the slot address (ADDR64 reloc), the code loads that address,
// dereferences the slot to fetch the function pointer, and calls through
// the register.

#![no_std]
#![crate_type = "cdylib"]
#![allow(clippy::missing_safety_doc)]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

extern "C" {
    /// The mapFuncs slot holding the resolved BeaconPrintf pointer.
    #[link_name = "BeaconPrintf"]
    static BEACON_PRINTF: *const core::ffi::c_void;
}

#[no_mangle]
pub unsafe extern "C" fn go(_args: *mut u8, _alen: i32) {
    const CALLBACK_OUTPUT: i32 = 0;
    static MSG: &[u8] = b"hello from the specter-rs bof\n\0";
    let slot = core::ptr::read(core::ptr::addr_of!(BEACON_PRINTF));
    let printf: unsafe extern "C" fn(i32, *const u8) = core::mem::transmute(slot);
    printf(CALLBACK_OUTPUT, MSG.as_ptr());
}
