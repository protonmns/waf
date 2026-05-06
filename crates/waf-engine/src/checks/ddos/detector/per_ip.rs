//! Per-IP `DDoS` detector.
//!
//! Thin wrapper around `RateLimitStore` — delegates rate limiting math to FR-004,
//! only translates `Decision` → `DetectorVerdict`. No new counters or algorithms.

use std::sync::Arc;

use tracing::warn;
use waf_common::RequestCtx;

use crate::checks::rate_limit::store::{Decision, LimitCfg, RateLimitStore};

use super::{DdosTierCfg, Detector, DetectorVerdict, tier_str};

/// Per-IP rate detector using the existing `RateLimitStore`.
///
/// Reuses FR-004's token bucket + sliding window implementation to detect
/// per-IP burst violations. Key format: `ddos:ip:{tier}:{ip}` to avoid
/// collision with FR-004's `ip:{host}:{ip}` namespace.
pub struct PerIpDetector {
    store: Arc<dyn RateLimitStore>,
}

impl PerIpDetector {
    /// Create a new per-IP detector backed by the given store.
    #[must_use]
    pub fn new(store: Arc<dyn RateLimitStore>) -> Self {
        Self { store }
    }

    /// Build the rate limit key for this IP + tier combination.
    ///
    /// Format: `ddos:ip:{tier}:{ip}` — distinct from FR-004's `ip:{host}:{ip}`.
    fn build_key(ctx: &RequestCtx) -> String {
        format!("ddos:ip:{}:{}", tier_str(ctx.tier), ctx.client_ip)
    }

    /// Convert `DDoS` tier config to rate limit config.
    ///
    /// Maps per-fingerprint thresholds to the token bucket + sliding window:
    /// - `burst_capacity` = `per_fp_threshold` (max burst before throttle)
    /// - `burst_refill_per_s` = threshold / window (steady-state rate)
    /// - `window_secs` = `per_fp_window_s`
    /// - `window_limit` = `per_fp_threshold`
    ///
    /// # Precondition
    /// `cfg.per_fp_window_s > 0` — validated by `DdosFileConfig::validate()`.
    fn to_limit_cfg(cfg: &DdosTierCfg) -> LimitCfg {
        debug_assert!(cfg.per_fp_window_s > 0, "per_fp_window_s must be > 0");
        LimitCfg {
            burst_capacity: cfg.per_fp_threshold,
            // Refill rate = threshold / window to allow sustained rate at limit
            burst_refill_per_s: f64::from(cfg.per_fp_threshold) / f64::from(cfg.per_fp_window_s),
            window_secs: cfg.per_fp_window_s,
            window_limit: cfg.per_fp_threshold,
        }
    }
}

impl Detector for PerIpDetector {
    fn name(&self) -> &'static str {
        "per_ip"
    }

    fn evaluate(&self, ctx: &RequestCtx, cfg: &DdosTierCfg, now_ms: i64) -> DetectorVerdict {
        let key = Self::build_key(ctx);
        let limit_cfg = Self::to_limit_cfg(cfg);

        // Delegate to rate limit store — no new math here
        match self.store.check_and_consume_blocking(&key, &limit_cfg, now_ms) {
            Ok(Decision::Allow) => DetectorVerdict::Allow,
            Ok(Decision::BurstExceeded) => DetectorVerdict::HardBurst {
                reason: "burst",
                detector: "per_ip",
            },
            Ok(Decision::SustainedExceeded) => DetectorVerdict::HardBurst {
                reason: "sustained",
                detector: "per_ip",
            },
            Err(e) => {
                // Degrade decision owned by phase 6 — here we just warn and allow
                warn!(
                    detector = "per_ip",
                    ip = %ctx.client_ip,
                    tier = ?ctx.tier,
                    error = %e,
                    "rate limit store error, degrading to allow"
                );
                DetectorVerdict::Allow
            }
        }
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

    use crate::checks::rate_limit::store::{Decision, LimitCfg, RateLimitStore};

    use super::*;

    /// Mock store that returns a predetermined decision.
    struct MockStore {
        decision: Decision,
    }

    impl MockStore {
        fn new(decision: Decision) -> Arc<Self> {
            Arc::new(Self { decision })
        }

        fn failing() -> Arc<FailingStore> {
            Arc::new(FailingStore)
        }
    }

    #[async_trait]
    impl RateLimitStore for MockStore {
        async fn check_and_consume(&self, _key: &str, _cfg: &LimitCfg, _now_ms: i64) -> anyhow::Result<Decision> {
            Ok(self.decision)
        }

        fn check_and_consume_blocking(&self, _key: &str, _cfg: &LimitCfg, _now_ms: i64) -> anyhow::Result<Decision> {
            Ok(self.decision)
        }

        async fn purge_expired(&self) -> anyhow::Result<usize> {
            Ok(0)
        }
    }

    /// Mock store that always returns an error.
    struct FailingStore;

    #[async_trait]
    impl RateLimitStore for FailingStore {
        async fn check_and_consume(&self, _key: &str, _cfg: &LimitCfg, _now_ms: i64) -> anyhow::Result<Decision> {
            anyhow::bail!("store unavailable")
        }

        fn check_and_consume_blocking(&self, _key: &str, _cfg: &LimitCfg, _now_ms: i64) -> anyhow::Result<Decision> {
            anyhow::bail!("store unavailable")
        }

        async fn purge_expired(&self) -> anyhow::Result<usize> {
            Ok(0)
        }
    }

    fn test_ctx(ip: IpAddr, tier: Tier) -> RequestCtx {
        RequestCtx {
            req_id: "test-req".to_string(),
            client_ip: ip,
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

    #[test]
    fn decision_allow_maps_to_verdict_allow() {
        let store = MockStore::new(Decision::Allow);
        let detector = PerIpDetector::new(store);
        let ctx = test_ctx(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), Tier::Medium);
        let cfg = test_cfg();

        let verdict = detector.evaluate(&ctx, &cfg, 1000);
        assert_eq!(verdict, DetectorVerdict::Allow);
    }

    #[test]
    fn decision_burst_exceeded_maps_to_hard_burst() {
        let store = MockStore::new(Decision::BurstExceeded);
        let detector = PerIpDetector::new(store);
        let ctx = test_ctx(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), Tier::High);
        let cfg = test_cfg();

        let verdict = detector.evaluate(&ctx, &cfg, 1000);
        assert_eq!(
            verdict,
            DetectorVerdict::HardBurst {
                reason: "burst",
                detector: "per_ip",
            }
        );
    }

    #[test]
    fn decision_sustained_exceeded_maps_to_hard_burst() {
        let store = MockStore::new(Decision::SustainedExceeded);
        let detector = PerIpDetector::new(store);
        let ctx = test_ctx(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), Tier::Critical);
        let cfg = test_cfg();

        let verdict = detector.evaluate(&ctx, &cfg, 1000);
        assert_eq!(
            verdict,
            DetectorVerdict::HardBurst {
                reason: "sustained",
                detector: "per_ip",
            }
        );
    }

    #[test]
    fn store_error_degrades_to_allow() {
        let store = MockStore::failing();
        let detector = PerIpDetector::new(store);
        let ctx = test_ctx(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), Tier::CatchAll);
        let cfg = test_cfg();

        // Error should degrade to Allow (fail-open for now, phase 6 owns degrade)
        let verdict = detector.evaluate(&ctx, &cfg, 1000);
        assert_eq!(verdict, DetectorVerdict::Allow);
    }

    #[test]
    fn key_format_includes_tier_and_ip() {
        let ctx = test_ctx(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), Tier::Critical);
        let key = PerIpDetector::build_key(&ctx);
        assert_eq!(key, "ddos:ip:critical:1.2.3.4");
    }

    #[test]
    fn key_format_catch_all_tier() {
        let ctx = test_ctx(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), Tier::CatchAll);
        let key = PerIpDetector::build_key(&ctx);
        assert_eq!(key, "ddos:ip:catch_all:5.6.7.8");
    }

    #[test]
    fn detector_name_is_per_ip() {
        let store = MockStore::new(Decision::Allow);
        let detector = PerIpDetector::new(store);
        assert_eq!(detector.name(), "per_ip");
    }

    #[test]
    fn key_format_ipv6() {
        use std::net::Ipv6Addr;
        let ctx = test_ctx(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), Tier::Medium);
        let key = PerIpDetector::build_key(&ctx);
        assert_eq!(key, "ddos:ip:medium:2001:db8::1");
    }
}
