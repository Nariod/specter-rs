//! Sleep cycle computation (port of the sleep/jitter command of the
//! original project).
//!
//! The beacon sleeps `SLEEP_MS` with a symmetric `±JITTER_MS` random offset
//! drawn from the instance RNG. Assumption documented in docs/PARITE.md: the
//! exact jitter semantics of the original dialog will be reconciled when the
//! agent_specter plugin dialog is adapted (phase 4) — the computation here is
//! pure, so the change is a one-liner plus tests.

/// Effective sleep duration, in milliseconds: `base ± jitter` clamped to
/// `[0, u32::MAX]`. `r` is any random value from the instance RNG.
#[inline]
pub const fn sleep_with_jitter(base_ms: u32, jitter_ms: u32, r: u32) -> u32 {
    if jitter_ms == 0 {
        return base_ms;
    }
    // Symmetric offset in [-jitter, +jitter].
    let offset = (r % (2 * jitter_ms + 1)) as i64 - jitter_ms as i64;
    let v = base_ms as i64 + offset;
    if v <= 0 {
        0
    } else {
        let max = u32::MAX as i64;
        if v > max {
            u32::MAX
        } else {
            v as u32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::XorShift64;

    #[test]
    fn zero_jitter_returns_base() {
        assert_eq!(sleep_with_jitter(30_000, 0, 0), 30_000);
        assert_eq!(sleep_with_jitter(30_000, 0, 123_456), 30_000);
    }

    #[test]
    fn offset_stays_within_plus_minus_jitter() {
        for base in [0u32, 1, 1000, 30_000, u32::MAX] {
            for jitter in [1u32, 100, 5_000] {
                let mut rng = XorShift64::new(0x1234_5678);
                for _ in 0..500 {
                    let s = sleep_with_jitter(base, jitter, rng.next_u32());
                    // Saturating: clamp bounds to the representable range.
                    let lo = base.saturating_sub(jitter);
                    let hi = base.saturating_add(jitter);
                    assert!(s >= lo && s <= hi, "base={base} jitter={jitter} -> {s}");
                }
            }
        }
    }

    #[test]
    fn extremes_clamp_to_zero_or_max() {
        // base 0 with the lowest draw: offset -jitter, clamps at 0.
        assert_eq!(sleep_with_jitter(0, 1000, 0), 0);
        // base u32::MAX with a positive offset draw (r=2000 -> +1000): clamps at u32::MAX.
        assert_eq!(sleep_with_jitter(u32::MAX, 1000, 2000), u32::MAX);
    }

    #[test]
    fn deterministic_given_the_same_random_value() {
        assert_eq!(
            sleep_with_jitter(30_000, 2_000, 4242),
            sleep_with_jitter(30_000, 2_000, 4242)
        );
        // Offsets differ across draws.
        let vals: std::vec::Vec<u32> = (0..8)
            .map(|i| sleep_with_jitter(30_000, 2_000, i * 577))
            .collect();
        let distinct = vals.iter().filter(|v| **v != vals[0]).count();
        assert!(distinct > 0);
    }
}
