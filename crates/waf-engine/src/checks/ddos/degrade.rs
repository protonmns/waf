//! FR-005 Phase 6 — Degrade & Circuit Breaker.
//!
//! `resolve` maps (`Tier`, `FailMode`, `ErrorKind`) → `DegradeAction` per the fail-mode
//! matrix. `OverloadGuard` monitors runtime load via an in-flight call counter
//! (fallback since `tokio_unstable` metrics are not enabled).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use waf_common::tier::{FailMode, Tier};

/// Error kinds that trigger degradation logic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Counter store (Redis/memory) is unavailable.
    StoreUnavailable,
    /// Backend service is overloaded or timing out.
    BackendOverload,
    /// Configuration is stale or failed to reload.
    ConfigStale,
}

/// Action to take when the system is degraded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DegradeAction {
    /// Allow the request through without restriction.
    Allow,
    /// Allow but emit a warning metric/log for observability.
    AllowAndWarn,
    /// Block with HTTP status and Retry-After header.
    Block {
        /// HTTP status code (typically 503).
        status: u16,
        /// Retry-After header value in seconds.
        retry_after_s: u32,
    },
}

/// Resolve the degradation action based on tier, `fail_mode`, and error kind.
///
/// ## Matrix (FR-036/037/038)
///
/// | Tier       | `StoreUnavailable` | `BackendOverload` | `ConfigStale` |
/// |------------|------------------|-----------------|-------------|
/// | `Critical` | Block 503        | Block 503       | Block 503   |
/// | `High`     | Block 503        | Block 503       | Block 503   |
/// | `Medium`   | `AllowAndWarn`   | `AllowAndWarn`  | `AllowAndWarn`|
/// | `CatchAll` | Allow            | Allow           | Allow       |
///
/// **Override:** If `fail_mode == FailMode::Close`, always block regardless of tier.
///
/// This function is pure — no I/O, no panics.
#[must_use]
pub fn resolve(tier: Tier, fail_mode: FailMode, _err: ErrorKind) -> DegradeAction {
    // FailMode::Close overrides tier-based behavior — always block.
    if fail_mode == FailMode::Close {
        return DegradeAction::Block {
            status: 503,
            retry_after_s: 5,
        };
    }

    // Tier-based behavior when fail_mode == FailMode::Open.
    match tier {
        Tier::Critical | Tier::High => DegradeAction::Block {
            status: 503,
            retry_after_s: 5,
        },
        Tier::Medium => DegradeAction::AllowAndWarn,
        Tier::CatchAll => DegradeAction::Allow,
    }
}

/// Runtime load monitor using an in-flight call counter.
///
/// Since `tokio_unstable` is not enabled, we cannot use
/// `tokio::runtime::Handle::metrics().global_queue_depth()`. Instead, callers
/// increment/decrement a shared counter around blocking operations.
///
/// A background sampler checks the counter periodically and flips `overloaded`
/// when it exceeds the threshold. `is_overloaded()` is lock-free.
pub struct OverloadGuard {
    /// Current in-flight call count (incremented/decremented by callers).
    in_flight: AtomicUsize,
    /// Overload flag — set by sampler, read by `is_overloaded()`.
    overloaded: AtomicBool,
    /// Shutdown signal for the sampler task.
    shutdown: AtomicBool,
    /// Threshold above which we consider the system overloaded.
    threshold: usize,
}

impl OverloadGuard {
    /// Create a new `OverloadGuard` with the given threshold.
    ///
    /// # Arguments
    /// - `threshold`: Number of in-flight calls above which system is overloaded.
    #[must_use]
    pub const fn new(threshold: usize) -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            overloaded: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            threshold,
        }
    }

    /// Signal the sampler to shut down.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Check if shutdown has been requested.
    fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Increment in-flight counter. Call before a blocking operation.
    pub fn enter(&self) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement in-flight counter. Call after a blocking operation completes.
    pub fn exit(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    /// Current in-flight count. Useful for metrics/debugging.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Check if system is currently overloaded.
    ///
    /// This is a lock-free read of an `AtomicBool` — safe to call on hot path.
    #[inline]
    #[must_use]
    pub fn is_overloaded(&self) -> bool {
        self.overloaded.load(Ordering::Relaxed)
    }

    /// Spawn a background sampler task that periodically checks in-flight count.
    ///
    /// The sampler runs every `sample_interval` and updates the `overloaded` flag.
    /// Call `shutdown()` to signal the sampler to exit cleanly.
    ///
    /// # Arguments
    /// - `self`: Arc-wrapped self for shared access
    /// - `sample_interval`: How often to sample (e.g., 100ms)
    pub fn spawn_sampler(self: Arc<Self>, sample_interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(sample_interval).await;

                if self.is_shutdown() {
                    tracing::debug!("OverloadGuard sampler shutting down");
                    break;
                }

                let count = self.in_flight.load(Ordering::Relaxed);
                let was_overloaded = self.overloaded.load(Ordering::Relaxed);
                let now_overloaded = count > self.threshold;

                if was_overloaded != now_overloaded {
                    self.overloaded.store(now_overloaded, Ordering::Relaxed);
                    if now_overloaded {
                        tracing::warn!(in_flight = count, threshold = self.threshold, "system overloaded");
                    } else {
                        tracing::info!(
                            in_flight = count,
                            threshold = self.threshold,
                            "system recovered from overload"
                        );
                    }
                }
            }
        })
    }

    /// Manually sample and update overload state (for testing without spawning).
    pub fn sample(&self) {
        let count = self.in_flight.load(Ordering::Relaxed);
        self.overloaded.store(count > self.threshold, Ordering::Relaxed);
    }
}

impl Default for OverloadGuard {
    /// Default threshold of 1000 in-flight calls.
    fn default() -> Self {
        Self::new(1000)
    }
}

/// RAII guard for `enter`/`exit` — ensures exit is called even on panic.
pub struct InFlightGuard<'a> {
    guard: &'a OverloadGuard,
}

impl<'a> InFlightGuard<'a> {
    /// Create a new guard, incrementing the in-flight counter.
    #[must_use]
    pub fn new(guard: &'a OverloadGuard) -> Self {
        guard.enter();
        Self { guard }
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.guard.exit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Chaos table tests for resolve()
    // =========================================================================

    /// Table-driven test cases for the resolve matrix.
    /// Format: (tier, `fail_mode`, `error_kind`, `expected_action`)
    const RESOLVE_TABLE: &[(Tier, FailMode, ErrorKind, DegradeAction)] = &[
        // Critical tier — always blocks (fail-open or close)
        (
            Tier::Critical,
            FailMode::Open,
            ErrorKind::StoreUnavailable,
            DegradeAction::Block {
                status: 503,
                retry_after_s: 5,
            },
        ),
        (
            Tier::Critical,
            FailMode::Open,
            ErrorKind::BackendOverload,
            DegradeAction::Block {
                status: 503,
                retry_after_s: 5,
            },
        ),
        (
            Tier::Critical,
            FailMode::Open,
            ErrorKind::ConfigStale,
            DegradeAction::Block {
                status: 503,
                retry_after_s: 5,
            },
        ),
        (
            Tier::Critical,
            FailMode::Close,
            ErrorKind::StoreUnavailable,
            DegradeAction::Block {
                status: 503,
                retry_after_s: 5,
            },
        ),
        // High tier — always blocks (fail-open or close)
        (
            Tier::High,
            FailMode::Open,
            ErrorKind::StoreUnavailable,
            DegradeAction::Block {
                status: 503,
                retry_after_s: 5,
            },
        ),
        (
            Tier::High,
            FailMode::Open,
            ErrorKind::BackendOverload,
            DegradeAction::Block {
                status: 503,
                retry_after_s: 5,
            },
        ),
        (
            Tier::High,
            FailMode::Close,
            ErrorKind::StoreUnavailable,
            DegradeAction::Block {
                status: 503,
                retry_after_s: 5,
            },
        ),
        // Medium tier — AllowAndWarn when open, Block when close
        (
            Tier::Medium,
            FailMode::Open,
            ErrorKind::StoreUnavailable,
            DegradeAction::AllowAndWarn,
        ),
        (
            Tier::Medium,
            FailMode::Open,
            ErrorKind::BackendOverload,
            DegradeAction::AllowAndWarn,
        ),
        (
            Tier::Medium,
            FailMode::Open,
            ErrorKind::ConfigStale,
            DegradeAction::AllowAndWarn,
        ),
        (
            Tier::Medium,
            FailMode::Close,
            ErrorKind::StoreUnavailable,
            DegradeAction::Block {
                status: 503,
                retry_after_s: 5,
            },
        ),
        // CatchAll tier — Allow when open, Block when close
        (
            Tier::CatchAll,
            FailMode::Open,
            ErrorKind::StoreUnavailable,
            DegradeAction::Allow,
        ),
        (
            Tier::CatchAll,
            FailMode::Open,
            ErrorKind::BackendOverload,
            DegradeAction::Allow,
        ),
        (
            Tier::CatchAll,
            FailMode::Open,
            ErrorKind::ConfigStale,
            DegradeAction::Allow,
        ),
        (
            Tier::CatchAll,
            FailMode::Close,
            ErrorKind::BackendOverload,
            DegradeAction::Block {
                status: 503,
                retry_after_s: 5,
            },
        ),
    ];

    #[test]
    fn resolve_chaos_table() {
        for (i, (tier, fail_mode, err, expected)) in RESOLVE_TABLE.iter().enumerate() {
            let actual = resolve(*tier, *fail_mode, *err);
            assert_eq!(
                actual, *expected,
                "row {i}: resolve({tier:?}, {fail_mode:?}, {err:?}) = {actual:?}, expected {expected:?}"
            );
        }
    }

    // =========================================================================
    // OverloadGuard unit tests
    // =========================================================================

    #[test]
    fn overload_guard_enter_exit() {
        let guard = OverloadGuard::new(5);
        assert_eq!(guard.in_flight_count(), 0);

        guard.enter();
        assert_eq!(guard.in_flight_count(), 1);

        guard.enter();
        assert_eq!(guard.in_flight_count(), 2);

        guard.exit();
        assert_eq!(guard.in_flight_count(), 1);

        guard.exit();
        assert_eq!(guard.in_flight_count(), 0);
    }

    #[test]
    fn overload_guard_sample_flips_flag() {
        let guard = OverloadGuard::new(2);
        assert!(!guard.is_overloaded());

        // Below threshold
        guard.enter();
        guard.enter();
        guard.sample();
        assert!(!guard.is_overloaded()); // 2 == threshold, not >

        // Above threshold
        guard.enter();
        guard.sample();
        assert!(guard.is_overloaded()); // 3 > 2

        // Back below
        guard.exit();
        guard.exit();
        guard.sample();
        assert!(!guard.is_overloaded()); // 1 <= 2
    }

    #[test]
    fn in_flight_guard_raii() {
        let guard = OverloadGuard::new(10);
        assert_eq!(guard.in_flight_count(), 0);

        {
            let _g = InFlightGuard::new(&guard);
            assert_eq!(guard.in_flight_count(), 1);
        }
        // Guard dropped, counter decremented
        assert_eq!(guard.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn overload_guard_sampler_flips_within_200ms() {
        let guard = Arc::new(OverloadGuard::new(2));

        // Spawn sampler with 50ms interval
        let handle = Arc::clone(&guard).spawn_sampler(Duration::from_millis(50));

        // Push above threshold
        guard.enter();
        guard.enter();
        guard.enter();

        // Wait for sampler to detect (should flip within 100ms at 50ms interval)
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(guard.is_overloaded(), "should be overloaded after 150ms");

        // Drop below threshold
        guard.exit();
        guard.exit();

        // Wait for recovery
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!guard.is_overloaded(), "should recover after 150ms");

        // Clean shutdown
        guard.shutdown();
        let result = tokio::time::timeout(Duration::from_millis(200), handle).await;
        assert!(result.is_ok(), "sampler should exit within 200ms after shutdown");
    }

    // =========================================================================
    // Property tests
    // =========================================================================

    mod proptest_resolve {
        use proptest::prelude::*;

        use super::super::*;

        fn arb_tier() -> impl Strategy<Value = Tier> {
            prop_oneof![
                Just(Tier::Critical),
                Just(Tier::High),
                Just(Tier::Medium),
                Just(Tier::CatchAll),
            ]
        }

        fn arb_fail_mode() -> impl Strategy<Value = FailMode> {
            prop_oneof![Just(FailMode::Open), Just(FailMode::Close),]
        }

        fn arb_error_kind() -> impl Strategy<Value = ErrorKind> {
            prop_oneof![
                Just(ErrorKind::StoreUnavailable),
                Just(ErrorKind::BackendOverload),
                Just(ErrorKind::ConfigStale),
            ]
        }

        proptest! {
            /// Property: resolve always terminates and returns a valid action.
            #[test]
            fn resolve_terminates(
                tier in arb_tier(),
                fail_mode in arb_fail_mode(),
                err in arb_error_kind()
            ) {
                // Should not panic
                let action = resolve(tier, fail_mode, err);

                // Action should be one of the valid variants with correct values
                match action {
                    DegradeAction::Allow | DegradeAction::AllowAndWarn => {}
                    DegradeAction::Block { status, retry_after_s } => {
                        prop_assert_eq!(status, 503);
                        prop_assert_eq!(retry_after_s, 5);
                    }
                }
            }

            /// Property: FailMode::Close always produces Block.
            #[test]
            fn fail_close_always_blocks(
                tier in arb_tier(),
                err in arb_error_kind()
            ) {
                let action = resolve(tier, FailMode::Close, err);
                let is_block = matches!(action, DegradeAction::Block { .. });
                prop_assert!(is_block, "expected Block, got {:?}", action);
            }

            /// Property: Critical/High tiers always block regardless of error.
            #[test]
            fn critical_high_always_block(
                tier in prop_oneof![Just(Tier::Critical), Just(Tier::High)],
                fail_mode in arb_fail_mode(),
                err in arb_error_kind()
            ) {
                let action = resolve(tier, fail_mode, err);
                let is_block = matches!(action, DegradeAction::Block { .. });
                prop_assert!(is_block, "expected Block, got {:?}", action);
            }

            /// Property: CatchAll with Open never blocks.
            #[test]
            fn catchall_open_never_blocks(
                err in arb_error_kind()
            ) {
                let action = resolve(Tier::CatchAll, FailMode::Open, err);
                prop_assert_eq!(action, DegradeAction::Allow);
            }
        }
    }
}
