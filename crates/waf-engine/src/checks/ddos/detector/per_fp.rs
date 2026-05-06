//! Per-fingerprint `DDoS` detector.
//!
//! Keys a fixed-window counter on the device fingerprint hash. Catches
//! IP-rotating botnets that share the same TLS/HTTP fingerprint (JA3/JA4/H2).
//!
//! # Trade-off: Fixed Window vs Precise Sliding Window
//!
//! This detector uses a **fixed-window** counter (TTL-expiring key) rather than
//! the precise sliding-window from `rate_limit::algo`. The trade-off:
//!
//! - **Fixed-window** allows up to 2× threshold at window boundaries (request at
//!   T-1ms then T+1ms both count toward different windows). This is acceptable
//!   for rough `DDoS` detection where thresholds are 100-10k requests.
//!
//! - **Precise sliding-window** requires storing per-key timestamp vectors,
//!   which adds memory overhead proportional to (keys × `window_duration` / granularity).
//!   For 100k fingerprints × 60s window, this is significant.
//!
//! For FR-005 v1, the fixed-window approximation is sufficient. Upgrade to
//! precise sliding if edge-case exploitation becomes a real attack vector.
//!
//! # Current Limitation
//!
//! **GAP**: `RequestCtx` does not yet carry a `device_fp` field. Until phase 7
//! wires device fingerprinting into the request pipeline, this detector will
//! always return `Allow` for live traffic. The core logic is complete and
//! tested via `evaluate_with_fp()`.

use std::sync::Arc;

use tracing::warn;
use waf_common::RequestCtx;

use crate::checks::ddos::store::CounterStore;

use super::{DdosTierCfg, Detector, DetectorVerdict, tier_str};

/// Per-fingerprint rate detector using `CounterStore`.
///
/// Counts requests per fingerprint hash within a sliding window. When count
/// exceeds the per-fingerprint threshold, returns `HardBurst` to trigger
/// blocking.
pub struct PerFpDetector {
    store: Arc<dyn CounterStore>,
}

impl PerFpDetector {
    /// Create a new per-fingerprint detector backed by the given counter store.
    ///
    /// The store is typically `MemoryCounterStore` for standalone deployments
    /// or a Redis-backed store for clustered deployments (phase 4).
    #[must_use]
    pub fn new(store: Arc<dyn CounterStore>) -> Self {
        Self { store }
    }

    /// Build the counter key for this fingerprint + tier combination.
    ///
    /// Format: `ddos:fp:{tier}:{fp_hash}` — distinct from per-IP's `ddos:ip:{tier}:{ip}`.
    fn build_key(tier: waf_common::tier::Tier, fp_hash: &str) -> String {
        format!("ddos:fp:{}:{}", tier_str(tier), fp_hash)
    }

    /// Core evaluation logic with explicit fingerprint input.
    ///
    /// This method contains the actual detection logic. It's exposed separately
    /// from `Detector::evaluate` because `RequestCtx` doesn't yet carry device
    /// fingerprint data (that wiring happens in phase 7).
    ///
    /// # Arguments
    /// - `fp_hash`: Device fingerprint hash. `None` or empty string → `Allow` (no signal).
    /// - `ctx`: Request context (used for tier classification).
    /// - `cfg`: `DDoS` tier configuration (thresholds and windows).
    /// - `now_ms`: Current timestamp in milliseconds.
    pub fn evaluate_with_fp(
        &self,
        fp_hash: Option<&str>,
        ctx: &RequestCtx,
        cfg: &DdosTierCfg,
        now_ms: i64,
    ) -> DetectorVerdict {
        // Skip when fingerprint is absent or empty — no signal available.
        // This happens when FR-010 device fingerprinting didn't run (e.g.,
        // plain HTTP/1 without TLS extensions, or FR-010 disabled).
        let Some(fp) = fp_hash.filter(|s| !s.is_empty()) else {
            return DetectorVerdict::Allow;
        };

        let key = Self::build_key(ctx.tier, fp);
        let ttl_ms = i64::from(cfg.per_fp_window_s) * 1000;

        match self.store.incr_get_blocking(&key, ttl_ms, now_ms) {
            Ok(n) if n > u64::from(cfg.per_fp_threshold) => DetectorVerdict::HardBurst {
                reason: "fp_burst",
                detector: "per_fp",
            },
            Ok(_) => DetectorVerdict::Allow,
            Err(e) => {
                // Degrade decision owned by phase 6 — here we warn and allow.
                warn!(
                    detector = "per_fp",
                    fp = %fp,
                    tier = ?ctx.tier,
                    error = %e,
                    "counter store error, degrading to allow"
                );
                DetectorVerdict::Allow
            }
        }
    }
}

impl Detector for PerFpDetector {
    fn name(&self) -> &'static str {
        "per_fp"
    }

    /// Evaluate the request against per-fingerprint rate limits.
    ///
    /// # Current Behavior
    ///
    /// **Always returns `Allow`** because `RequestCtx` doesn't yet carry
    /// `device_fp`. This is a documented gap — phase 7 wires device
    /// fingerprinting into the request pipeline.
    ///
    /// Once phase 7 is complete, this will extract `ctx.device_fp.hash` and
    /// delegate to `evaluate_with_fp()`.
    fn evaluate(&self, _ctx: &RequestCtx, _cfg: &DdosTierCfg, _now_ms: i64) -> DetectorVerdict {
        // GAP: RequestCtx.device_fp does not exist yet.
        // Phase 7 will add it; then this becomes:
        //   let fp = ctx.device_fp.as_ref().and_then(|f| f.hash.as_ref());
        //   self.evaluate_with_fp(fp.map(String::as_str), ctx, cfg, now_ms)
        DetectorVerdict::Allow
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

    use crate::checks::ddos::store::CounterStore;

    use super::*;

    /// In-memory counter store for testing with controllable behavior.
    struct TestCounterStore {
        counts: parking_lot::Mutex<HashMap<String, u64>>,
    }

    impl TestCounterStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                counts: parking_lot::Mutex::new(HashMap::new()),
            })
        }
    }

    #[async_trait]
    #[allow(clippy::significant_drop_tightening)]
    impl CounterStore for TestCounterStore {
        async fn incr_get(&self, key: &str, _ttl_ms: i64, _now_ms: i64) -> anyhow::Result<u64> {
            let mut counts = self.counts.lock();
            let entry = counts.entry(key.to_string()).or_insert(0);
            *entry += 1;
            Ok(*entry)
        }

        fn incr_get_blocking(&self, key: &str, _ttl_ms: i64, _now_ms: i64) -> anyhow::Result<u64> {
            let mut counts = self.counts.lock();
            let entry = counts.entry(key.to_string()).or_insert(0);
            *entry += 1;
            Ok(*entry)
        }

        async fn purge_expired(&self, _now_ms: i64) -> anyhow::Result<usize> {
            Ok(0)
        }
    }

    /// Store that always returns an error.
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

    fn test_cfg(threshold: u32, window_s: u32) -> DdosTierCfg {
        DdosTierCfg {
            per_fp_threshold: threshold,
            per_fp_window_s: window_s,
            per_tier_threshold: 1000,
            per_tier_window_s: 60,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Missing/empty fingerprint tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn missing_fp_returns_allow() {
        let store = TestCounterStore::new();
        let detector = PerFpDetector::new(store);
        let ctx = test_ctx(Tier::Medium);
        let cfg = test_cfg(10, 60);

        let verdict = detector.evaluate_with_fp(None, &ctx, &cfg, 1000);
        assert_eq!(verdict, DetectorVerdict::Allow);
    }

    #[test]
    fn empty_fp_returns_allow() {
        let store = TestCounterStore::new();
        let detector = PerFpDetector::new(store);
        let ctx = test_ctx(Tier::Medium);
        let cfg = test_cfg(10, 60);

        let verdict = detector.evaluate_with_fp(Some(""), &ctx, &cfg, 1000);
        assert_eq!(verdict, DetectorVerdict::Allow);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Threshold boundary tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn count_below_threshold_returns_allow() {
        let store = TestCounterStore::new();
        let detector = PerFpDetector::new(store);
        let ctx = test_ctx(Tier::Medium);
        let cfg = test_cfg(10, 60);

        // 5 requests with threshold=10 should all be allowed
        for _ in 0..5 {
            let verdict = detector.evaluate_with_fp(Some("ja4-abc123"), &ctx, &cfg, 1000);
            assert_eq!(verdict, DetectorVerdict::Allow);
        }
    }

    #[test]
    fn count_at_threshold_returns_allow() {
        let store = TestCounterStore::new();
        let detector = PerFpDetector::new(store);
        let ctx = test_ctx(Tier::Medium);
        let cfg = test_cfg(10, 60);

        // First 10 requests should be allowed (threshold=10, >10 triggers)
        for i in 1..=10 {
            let verdict = detector.evaluate_with_fp(Some("ja4-abc123"), &ctx, &cfg, 1000);
            assert_eq!(verdict, DetectorVerdict::Allow, "request {i} should be allowed");
        }
    }

    #[test]
    fn count_exceeds_threshold_returns_hard_burst() {
        let store = TestCounterStore::new();
        let detector = PerFpDetector::new(store);
        let ctx = test_ctx(Tier::Critical);
        let cfg = test_cfg(10, 60);

        // First 10 are allowed
        for _ in 0..10 {
            detector.evaluate_with_fp(Some("ja4-abc123"), &ctx, &cfg, 1000);
        }

        // 11th request exceeds threshold
        let verdict = detector.evaluate_with_fp(Some("ja4-abc123"), &ctx, &cfg, 1000);
        assert_eq!(
            verdict,
            DetectorVerdict::HardBurst {
                reason: "fp_burst",
                detector: "per_fp",
            }
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Key namespace isolation tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn distinct_fps_have_separate_counters() {
        let store = TestCounterStore::new();
        let detector = PerFpDetector::new(store);
        let ctx = test_ctx(Tier::Medium);
        let cfg = test_cfg(5, 60);

        // Hit fp1 5 times (at threshold)
        for _ in 0..5 {
            detector.evaluate_with_fp(Some("fp1"), &ctx, &cfg, 1000);
        }

        // fp2 should start fresh at count=1
        let verdict = detector.evaluate_with_fp(Some("fp2"), &ctx, &cfg, 1000);
        assert_eq!(verdict, DetectorVerdict::Allow);

        // fp1's 6th request should burst
        let verdict = detector.evaluate_with_fp(Some("fp1"), &ctx, &cfg, 1000);
        assert_eq!(
            verdict,
            DetectorVerdict::HardBurst {
                reason: "fp_burst",
                detector: "per_fp",
            }
        );
    }

    #[test]
    fn distinct_tiers_have_separate_counters() {
        let store = TestCounterStore::new();
        let detector = PerFpDetector::new(store);
        let cfg = test_cfg(5, 60);

        let ctx_critical = test_ctx(Tier::Critical);
        let ctx_medium = test_ctx(Tier::Medium);

        // Hit same fingerprint 5 times on Critical tier
        for _ in 0..5 {
            detector.evaluate_with_fp(Some("shared-fp"), &ctx_critical, &cfg, 1000);
        }

        // Same fingerprint on Medium tier should start fresh
        let verdict = detector.evaluate_with_fp(Some("shared-fp"), &ctx_medium, &cfg, 1000);
        assert_eq!(verdict, DetectorVerdict::Allow);

        // Critical tier's 6th request should burst
        let verdict = detector.evaluate_with_fp(Some("shared-fp"), &ctx_critical, &cfg, 1000);
        assert_eq!(
            verdict,
            DetectorVerdict::HardBurst {
                reason: "fp_burst",
                detector: "per_fp",
            }
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Key format tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn key_format_includes_tier_and_fp() {
        let key = PerFpDetector::build_key(Tier::Critical, "ja4-abc123");
        assert_eq!(key, "ddos:fp:critical:ja4-abc123");
    }

    #[test]
    fn key_format_catch_all_tier() {
        let key = PerFpDetector::build_key(Tier::CatchAll, "h2-xyz789");
        assert_eq!(key, "ddos:fp:catch_all:h2-xyz789");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error handling tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn store_error_degrades_to_allow() {
        let store: Arc<dyn CounterStore> = Arc::new(FailingStore);
        let detector = PerFpDetector::new(store);
        let ctx = test_ctx(Tier::High);
        let cfg = test_cfg(10, 60);

        // Store error should degrade to Allow (fail-open)
        let verdict = detector.evaluate_with_fp(Some("ja4-abc123"), &ctx, &cfg, 1000);
        assert_eq!(verdict, DetectorVerdict::Allow);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Detector trait tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn detector_name_is_per_fp() {
        let store = TestCounterStore::new();
        let detector = PerFpDetector::new(store);
        assert_eq!(detector.name(), "per_fp");
    }

    #[test]
    fn detector_evaluate_returns_allow_gap_documented() {
        // This tests the current behavior where RequestCtx.device_fp doesn't exist.
        // The Detector::evaluate method always returns Allow until phase 7 wires it up.
        let store = TestCounterStore::new();
        let detector = PerFpDetector::new(store);
        let ctx = test_ctx(Tier::Medium);
        let cfg = test_cfg(1, 60); // Very low threshold to prove it's not being hit

        // Even with threshold=1, evaluate() returns Allow because it can't
        // extract fingerprint from RequestCtx yet.
        let verdict = detector.evaluate(&ctx, &cfg, 1000);
        assert_eq!(verdict, DetectorVerdict::Allow);
    }
}
