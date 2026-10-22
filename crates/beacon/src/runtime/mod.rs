//! Runtime layer (port of `src_beacon/src/runtime/`): custom heap exposed as
//! a `GlobalAlloc`, TEB instance access, sleep obfuscation plumbing,
//! bootstrap. Pure logic (hashing, wire, structures) lives in the
//! `specter-core` crate so it is testable on the host.
//!
//! Phase 1 of the roadmap (docs/ETUDE-DE-FAISABILITE.md, section 8).

pub use specter_core::fnv;
