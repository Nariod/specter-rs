//! xorshift64 PRNG (same family as the original project's per-build
//! encryption stream).
//!
//! Used for sleep jitter (seeded from `QueryPerformanceCounter` at
//! bootstrap) and later for gadget rotation and per-build encryption.
//! Not cryptographic — it only needs unpredictability-from-the-operator,
//! never secrecy.

/// xorshift64 state. Never seed with zero (the generator would stick).
#[derive(Clone, Copy)]
pub struct XorShift64 {
    pub state: u64,
}

impl XorShift64 {
    /// New generator; a zero seed is remapped to a fixed nonzero constant.
    #[inline]
    pub const fn new(seed: u64) -> Self {
        XorShift64 {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    /// Next raw 64-bit value.
    #[inline]
    pub const fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Next value as a u32 (lower bits of the raw value).
    #[inline]
    pub const fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference values computed independently (Python) — any change to the
    /// algorithm breaks gadget/encryption consumers, so it is pinned.
    #[test]
    fn xorshift64_vector_pinned() {
        let mut rng = XorShift64::new(0x9E37_79B9_7F4A_7C15);
        assert_eq!(rng.next_u64(), 0xDC1B_77AE_0BF3_4DAD);
        assert_eq!(rng.next_u64(), 0x64F0_EEB9_026E_6076);
        assert_eq!(rng.next_u64(), 0x7B07_CE91_E590_6136);
    }

    #[test]
    fn zero_seed_is_remapped() {
        let first = XorShift64::new(0).next_u64();
        assert_ne!(first, 0);
        // And equals the golden-ratio remap.
        assert_eq!(first, XorShift64::new(0x9E37_79B9_7F4A_7C15).next_u64());
    }

    #[test]
    fn never_sticks_at_zero() {
        let mut rng = XorShift64::new(1);
        let mut zeros = 0;
        for _ in 0..1000 {
            if rng.next_u64() == 0 {
                zeros += 1;
            }
        }
        assert_eq!(zeros, 0);
    }
}
