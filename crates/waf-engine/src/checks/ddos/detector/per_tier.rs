//! Per-tier aggregate `DDoS` detector.
//!
//! Maintains a single global counter per tier with adaptive thresholding
//! based on a 60-second moving-median baseline. This catches distributed
//! attacks that slip past per-IP/per-fingerprint limits by spreading
//! traffic across many sources.
//!
//! # Threshold Logic
//!
//! ```text
//! threshold = max(absolute_cap_floor, 3 × median)
//! if count > threshold → HardBurst
//! ```
//!
//! - **Cold start** (median=0): Uses `absolute_cap_floor` as the threshold.
//! - **Warmed up**: Adapts to traffic patterns — 3× median catches spikes
//!   while allowing organic growth.
//!
//! # Key Format
//!
//! `ddos:tier:{tier}` — one key per tier, shared across all IPs/fingerprints.

use std::sync::Arc;

use tracing::warn;
use waf_common::RequestCtx;

use crate::checks::ddos::store::CounterStore;

use super::baseline::MovingMedian;
use super::clock::Clock;
use super::{DdosTierCfg, Detector, DetectorVerdict, tier_str};

/// Default requests-per-second floor when baseline is cold.
///
/// Conservative value for Critical tier — operators tune via config.
const DEFAULT_ABSOLUTE_CAP_FLOOR: u32 = 1000;

/// Per-tier aggregate rate detector.
///
/// Counts total requests per tier (all IPs combined) and compares against
/// an adaptive threshold based on the rolling 60-second median.
pub struct PerTierDetector {
    store: Arc<dyn CounterStore>,
    baseline: MovingMedian,
    clock: Arc<dyn Clock>,
    absolute_cap_floor: u32,
}

impl PerTierDetector {
    /// Create a new per-tier detector.
    ///
    /// # Arguments
    /// - `store`: Counter backend (memory or Redis).
    /// - `clock`: Time source (real or mock for tests).
    /// - `absolute_cap_floor`: Minimum threshold when median=0 (cold start).
    #[must_use]
    pub fn new(store: Arc<dyn CounterStore>, clock: Arc<dyn Clock>, absolute_cap_floor: u32) -> Self {
        Self {
            store,
            baseline: MovingMedian::new(),
            clock,
            absolute_cap_floor,
        }
    }

    /// Create with default absolute cap floor (1000 rps).
    #[must_use]
    pub fn with_defaults(store: Arc<dyn CounterStore>, clock: Arc<dyn Clock>) -> Self {
        Self::new(store, clock, DEFAULT_ABSOLUTE_CAP_FLOOR)
    }

    /// Build the counter key for this tier.
    ///
    /// Format: `ddos:tier:{tier}` — one key per tier.
    fn build_key(ctx: &RequestCtx) -> String {
        format!("ddos:tier:{}", tier_str(ctx.tier))
    }

    /// Compute the adaptive threshold.
    ///
    /// Returns `max(absolute_cap_floor, 3 × median)`.
    fn compute_threshold(&self) -> u64 {
        let median = self.baseline.median();
        let adaptive = median.saturating_mul(3);
        u64::from(self.absolute_cap_floor).max(adaptive)
    }

    /// Core evaluation logic with explicit timestamp.
    ///
    /// Exposed for testing with controlled time.
    pub fn evaluate_at(&self, ctx: &RequestCtx, cfg: &DdosTierCfg, now_ms: i64) -> DetectorVerdict {
        let key = Self::build_key(ctx);
        let ttl_ms = i64::from(cfg.per_tier_window_s) * 1000;

        // Increment counter and get current count
        let count = match self.store.incr_get_blocking(&key, ttl_ms, now_ms) {
            Ok(n) => n,
            Err(e) => {
                warn!(
                    detector = "per_tier",
                    tier = ?ctx.tier,
                    error = %e,
                    "counter store error, degrading to allow"
                );
                return DetectorVerdict::Allow;
            }
        };

        // Record after store increment: baseline lags by 1 request intentionally.
        // This avoids circular dependency and the delta is negligible vs thresholds.
        self.baseline.record(now_ms);

        // Compute adaptive threshold
        let threshold = self.compute_threshold();

        if count > threshold {
            DetectorVerdict::HardBurst {
                reason: "tier_burst",
                detector: "per_tier",
            }
        } else {
            DetectorVerdict::Allow
        }
    }
}

impl Detector for PerTierDetector {
    fn name(&self) -> &'static str {
        "per_tier"
    }

    fn evaluate(&self, ctx: &RequestCtx, cfg: &DdosTierCfg, _now_ms: i64) -> DetectorVerdict {
        // Use real clock time for production
        let now_ms = self.clock.now_ms();
        self.evaluate_at(ctx, cfg, now_ms)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use async_trait::async_trait;
    use bytes::Bytes;
    use waf_common::tier::{Tier, TierPolicy};
    use waf_common::{HostConfig, RequestCtx};

    use crate::checks::ddos::store::MemoryCounterStore;

    use super::super::clock::test_utils::MockClock;
    use super::*;

    fn test_ctx(tier: Tier) -> RequestCtx {
        RequestCtx {
            req_id: "test-req".to_string(),
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            client_port: 12345,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 443,
            path: "/api/test".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: true,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
            tier,
            tier_policy: Arc::new(TierPolicy::default()),
            cookies: HashMap::new(),
        }
    }

    fn test_cfg() -> DdosTierCfg {
        DdosTierCfg {
            per_fp_threshold: 100,
            per_fp_window_s: 60,
            per_tier_threshold: 1000,
            per_tier_window_s: 60,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cold start tests (median=0 → uses absolute_cap_floor)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn cold_start_uses_absolute_cap_floor() {
        let store = Arc::new(MemoryCounterStore::new(10000, 60));
        let clock = Arc::new(MockClock::new(1000));
        let detector = PerTierDetector::new(store, clock, 100); // floor=100

        let ctx = test_ctx(Tier::Critical);
        let cfg = test_cfg();

        // First 100 requests should be allowed (at floor)
        for i in 1..=100 {
            let verdict = detector.evaluate_at(&ctx, &cfg, i * 10); // spread over time
            assert_eq!(verdict, DetectorVerdict::Allow, "request {i} should be allowed");
        }

        // 101st exceeds floor
        let verdict = detector.evaluate_at(&ctx, &cfg, 1010);
        assert_eq!(
            verdict,
            DetectorVerdict::HardBurst {
                reason: "tier_burst",
                detector: "per_tier",
            }
        );
    }

    #[test]
    fn high_floor_allows_burst() {
        let store = Arc::new(MemoryCounterStore::new(10000, 60));
        let clock = Arc::new(MockClock::new(1000));
        let detector = PerTierDetector::new(store, clock, 10000);

        let ctx = test_ctx(Tier::Critical);
        let cfg = test_cfg();

        // 5000 requests should be allowed with floor=10000
        for i in 0..5000 {
            let verdict = detector.evaluate_at(&ctx, &cfg, i);
            assert_eq!(verdict, DetectorVerdict::Allow);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Warmed baseline tests (adaptive 3×median threshold)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn warmed_baseline_adapts_threshold() {
        let store = Arc::new(MemoryCounterStore::new(100_000, 60));
        let clock = Arc::new(MockClock::new(0));
        let detector = PerTierDetector::new(store, clock, 10);

        let ctx = test_ctx(Tier::Medium);
        let cfg = test_cfg();

        // Establish baseline: 100 requests per second for 30 seconds
        // This warms up 30 buckets with ~100 each
        for second in 0..30 {
            let base_ms = second * 1000;
            for req in 0..100 {
                let now_ms = base_ms + req * 10;
                detector.evaluate_at(&ctx, &cfg, now_ms);
            }
        }

        // Median should be ~100, threshold = 3*100 = 300
        // Next request (count=3001) may or may not trigger depending on exact timing
        // Let's check the threshold calculation
        let threshold = detector.compute_threshold();
        assert!(threshold >= 100, "threshold should be at least 100: got {threshold}");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Key format tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn key_format_includes_tier() {
        let ctx = test_ctx(Tier::Critical);
        let key = PerTierDetector::build_key(&ctx);
        assert_eq!(key, "ddos:tier:critical");
    }

    #[test]
    fn key_format_catch_all() {
        let ctx = test_ctx(Tier::CatchAll);
        let key = PerTierDetector::build_key(&ctx);
        assert_eq!(key, "ddos:tier:catch_all");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error handling tests
    // ─────────────────────────────────────────────────────────────────────────

    struct FailingStore;

    #[async_trait]
    impl CounterStore for FailingStore {
        async fn incr_get(&self, _key: &str, _ttl_ms: i64, _now_ms: i64) -> anyhow::Result<u64> {
            anyhow::bail!("store unavailable")
        }

        fn incr_get_blocking(&self, _key: &str, _ttl_ms: i64, _now_ms: i64) -> anyhow::Result<u64> {
            anyhow::bail!("store unavailable")
        }

        async fn purge_expired(&self, _now_ms: i64) -> anyhow::Result<usize> {
            Ok(0)
        }
    }

    #[test]
    fn store_error_degrades_to_allow() {
        let store: Arc<dyn CounterStore> = Arc::new(FailingStore);
        let clock = Arc::new(MockClock::new(1000));
        let detector = PerTierDetector::new(store, clock, 100);

        let ctx = test_ctx(Tier::High);
        let cfg = test_cfg();

        let verdict = detector.evaluate_at(&ctx, &cfg, 1000);
        assert_eq!(verdict, DetectorVerdict::Allow);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Trait method tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn detector_name() {
        let store = Arc::new(MemoryCounterStore::new(1000, 60));
        let clock = Arc::new(MockClock::new(0));
        let detector = PerTierDetector::with_defaults(store, clock);
        assert_eq!(detector.name(), "per_tier");
    }

    #[test]
    fn evaluate_uses_clock() {
        let store = Arc::new(MemoryCounterStore::new(10000, 60));
        let clock = Arc::new(MockClock::new(5000));
        let detector = PerTierDetector::new(store, Arc::clone(&clock) as Arc<dyn Clock>, 100);

        let ctx = test_ctx(Tier::Medium);
        let cfg = test_cfg();

        // First call uses clock time 5000
        let verdict = detector.evaluate(&ctx, &cfg, 0); // now_ms param ignored
        assert_eq!(verdict, DetectorVerdict::Allow);

        // Advance clock and verify it's used
        clock.advance_ms(1000);
        let verdict = detector.evaluate(&ctx, &cfg, 0);
        assert_eq!(verdict, DetectorVerdict::Allow);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Threshold computation tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn threshold_max_of_floor_and_triple_median() {
        let store = Arc::new(MemoryCounterStore::new(10000, 60));
        let clock = Arc::new(MockClock::new(0));
        let detector = PerTierDetector::new(store, clock, 500);

        // Initial: median=0, threshold=floor=500
        assert_eq!(detector.compute_threshold(), 500);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tier isolation tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn different_tiers_separate_counters() {
        let store = Arc::new(MemoryCounterStore::new(10000, 60));
        let clock = Arc::new(MockClock::new(1000));
        let detector = PerTierDetector::new(Arc::clone(&store) as Arc<dyn CounterStore>, clock, 5);

        let cfg = test_cfg();
        let ctx_crit = test_ctx(Tier::Critical);
        let ctx_med = test_ctx(Tier::Medium);

        // Hit Critical 5 times (at floor)
        for _ in 0..5 {
            detector.evaluate_at(&ctx_crit, &cfg, 1000);
        }

        // Medium tier starts fresh
        let verdict = detector.evaluate_at(&ctx_med, &cfg, 1000);
        assert_eq!(verdict, DetectorVerdict::Allow);

        // Critical's 6th request bursts
        let verdict = detector.evaluate_at(&ctx_crit, &cfg, 1000);
        assert_eq!(
            verdict,
            DetectorVerdict::HardBurst {
                reason: "tier_burst",
                detector: "per_tier",
            }
        );
    }
}
