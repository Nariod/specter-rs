//! COFF object file loader (port of `src_beacon/src/coff/` and `Coff.h`):
//! BOF execution, sync and async thread-pool variants.
//!
//! Prime motivation of the rewrite: this is untrusted-input parsing that the
//! C version does by hand, in a process where a segfault costs the beacon.
//! Bounded slices and typed errors only.
//!
//! Phase 3 of the roadmap (docs/ETUDE-DE-FAISABILITE.md, section 8).
