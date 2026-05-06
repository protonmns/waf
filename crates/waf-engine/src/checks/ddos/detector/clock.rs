//! Time abstraction for testable `DDoS` detectors.
//!
//! The `Clock` trait allows detectors to use real wall-clock time in production
//! while substituting mock clocks in tests for deterministic behavior.

use std::time::{SystemTime, UNIX_EPOCH};

/// Trait for obtaining current time in milliseconds since UNIX epoch.
///
/// Production code uses `SystemClock`; tests use mock implementations
/// to control time boundaries and window rollovers.
pub trait Clock: Send + Sync {
    /// Current time in milliseconds since UNIX epoch.
    fn now_ms(&self) -> i64;
}

/// Real wall-clock implementation of `Clock`.
///
/// Uses `SystemTime::now()` — suitable for production use.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};

    /// Mock clock with controllable time for testing.
    ///
    /// Call `set_ms()` or `advance_ms()` to control the returned time.
    pub struct MockClock {
        time_ms: AtomicI64,
    }

    impl MockClock {
        pub fn new(initial_ms: i64) -> Self {
            Self {
                time_ms: AtomicI64::new(initial_ms),
            }
        }

        pub fn set_ms(&self, ms: i64) {
            self.time_ms.store(ms, Ordering::Relaxed);
        }

        pub fn advance_ms(&self, delta: i64) {
            self.time_ms.fetch_add(delta, Ordering::Relaxed);
        }
    }

    impl Clock for MockClock {
        fn now_ms(&self) -> i64 {
            self.time_ms.load(Ordering::Relaxed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_positive_value() {
        let clock = SystemClock;
        let now = clock.now_ms();
        assert!(now > 0, "system clock should return positive epoch ms");
    }

    #[test]
    fn system_clock_advances() {
        let clock = SystemClock;
        let t1 = clock.now_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let t2 = clock.now_ms();
        assert!(t2 >= t1, "time should not go backwards");
    }

    #[test]
    fn mock_clock_controllable() {
        use test_utils::MockClock;

        let clock = MockClock::new(1000);
        assert_eq!(clock.now_ms(), 1000);

        clock.set_ms(5000);
        assert_eq!(clock.now_ms(), 5000);

        clock.advance_ms(100);
        assert_eq!(clock.now_ms(), 5100);
    }
}
