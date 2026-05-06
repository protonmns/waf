//! FR-005 Phase 7 — `DdosCheck` pipeline integration.
//!
//! Wires detectors (per-IP, per-FP, per-tier) into the WAF engine pipeline.
//! Runs after allowlist phases (1-4) and before rate-limit (Phase 11).
//!
//! ## Pipeline Behavior
//! - Runs detectors in cheap-first order: `per_ip` → `per_fp` → `per_tier`
//! - Short-circuits on first `HardBurst` verdict → immediate block
//! - `SoftAnomaly` bumps risk only, continues evaluation
//! - Store errors invoke degrade logic per tier's fail-mode

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use tracing::warn;

use waf_common::{DetectionResult, Phase, RequestCtx};

use super::action::{ActionExecutor, CombinedAction};
use super::degrade::{self, DegradeAction, ErrorKind, OverloadGuard};
use super::detector::{Detector, DetectorVerdict, tier_str};
use super::metrics::DdosMetrics;
use super::{DdosConfig, DynamicBanTable};
use crate::checks::Check;

/// `DDoS` detection check for the WAF pipeline.
///
/// Composes multiple detectors and executes actions (ban, risk bump) on
/// hard-burst verdicts. Integrates with the degrade circuit breaker for
/// graceful failure handling.
pub struct DdosCheck {
    /// Hot-reloadable config snapshot.
    cfg: Arc<ArcSwap<DdosConfig>>,
    /// Ordered list of detectors (cheap-first: `per_ip`, `per_fp`, `per_tier`).
    detectors: Vec<Box<dyn Detector>>,
    /// Combined action executor (ban + risk bump).
    action: Arc<CombinedAction>,
    /// Circuit breaker for overload protection.
    guard: Arc<OverloadGuard>,
    /// Dynamic ban table for checking already-banned IPs.
    ban_table: Arc<DynamicBanTable>,
    /// Metrics counters.
    metrics: Arc<DdosMetrics>,
}

impl DdosCheck {
    /// Create a new `DdosCheck` with the given components.
    #[must_use]
    pub fn new(
        cfg: Arc<ArcSwap<DdosConfig>>,
        detectors: Vec<Box<dyn Detector>>,
        action: Arc<CombinedAction>,
        guard: Arc<OverloadGuard>,
        ban_table: Arc<DynamicBanTable>,
        metrics: Arc<DdosMetrics>,
    ) -> Self {
        Self {
            cfg,
            detectors,
            action,
            guard,
            ban_table,
            metrics,
        }
    }

    /// Get reference to metrics for external access.
    #[must_use]
    pub const fn metrics(&self) -> &Arc<DdosMetrics> {
        &self.metrics
    }

    /// Get reference to ban table for external access (e.g., purge task).
    #[must_use]
    pub const fn ban_table(&self) -> &Arc<DynamicBanTable> {
        &self.ban_table
    }
}

impl Check for DdosCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        // Load config snapshot
        let snap = self.cfg.load();

        // Skip if tier unconfigured for DDoS protection
        let tier_cfg = snap.for_tier(ctx.tier)?;

        // Check circuit breaker state
        if self.guard.is_overloaded() {
            let action = degrade::resolve(ctx.tier, ctx.tier_policy.fail_mode, ErrorKind::BackendOverload);
            self.metrics.inc_degrade();

            return match action {
                DegradeAction::Block { status, retry_after_s } => {
                    warn!(
                        target: "ddos::audit",
                        request_id = %ctx.req_id,
                        ip = %ctx.client_ip,
                        tier = %tier_str(ctx.tier),
                        "DDoS check degraded: system overloaded"
                    );
                    Some(DetectionResult {
                        rule_id: Some("DDOS-DEGRADE".to_string()),
                        rule_name: "DDoS Protection (Degraded)".to_string(),
                        phase: Phase::Ddos,
                        detail: format!("system overloaded; retry after {retry_after_s}s; status {status}"),
                    })
                }
                DegradeAction::AllowAndWarn => {
                    warn!(
                        target: "ddos::audit",
                        request_id = %ctx.req_id,
                        ip = %ctx.client_ip,
                        tier = %tier_str(ctx.tier),
                        "DDoS check degraded: allowing with warning"
                    );
                    None
                }
                DegradeAction::Allow => None,
            };
        }

        // Check if IP is already banned
        let now_ms = now_epoch_ms();
        if self.ban_table.contains(ctx.client_ip, now_ms) {
            return Some(DetectionResult {
                rule_id: Some("DDOS-BAN".to_string()),
                rule_name: "DDoS Protection".to_string(),
                phase: Phase::Ddos,
                detail: format!("IP {} is currently banned", ctx.client_ip),
            });
        }

        // Run detectors in order (cheap-first)
        for detector in &self.detectors {
            let verdict = detector.evaluate(ctx, tier_cfg, now_ms);

            match verdict {
                DetectorVerdict::Allow => {}

                DetectorVerdict::SoftAnomaly(score) => {
                    // Bump risk only, continue evaluation
                    self.metrics.inc_burst(detector.name());
                    // Note: risk bump would go to a risk aggregator here
                    // For now, just record the event
                    tracing::debug!(
                        detector = detector.name(),
                        score = score,
                        ip = %ctx.client_ip,
                        "soft anomaly detected"
                    );
                }

                DetectorVerdict::HardBurst {
                    reason,
                    detector: det_name,
                } => {
                    // Execute action (ban + risk bump)
                    let result = self.action.execute(ctx.client_ip, &verdict, now_ms);

                    // Update metrics
                    self.metrics.inc_burst(det_name);
                    if result.banned {
                        self.metrics.inc_ban();
                    }

                    // Structured audit log per FR-032
                    warn!(
                        target: "ddos::audit",
                        request_id = %ctx.req_id,
                        ts_ms = now_ms,
                        ip = %ctx.client_ip,
                        device_fp = ?ctx.headers.get("x-device-fp"),
                        detector = det_name,
                        threshold = tier_cfg.per_fp_threshold,
                        action = "ban",
                        ttl_s = ?result.ban_ttl_s,
                        "DDoS action executed"
                    );

                    return Some(DetectionResult {
                        rule_id: Some(format!("DDOS-{}", det_name.to_uppercase())),
                        rule_name: "DDoS Protection".to_string(),
                        phase: Phase::Ddos,
                        detail: format!(
                            "ddos {} ({}); banned {}s",
                            det_name,
                            reason,
                            result.ban_ttl_s.unwrap_or(0)
                        ),
                    });
                }
            }
        }

        None
    }
}

/// Current wall-clock epoch milliseconds.
#[inline]
#[must_use]
fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use waf_common::tier::{FailMode, Tier, TierPolicy};

    use super::*;
    use crate::checks::ddos::action::BanAction;
    use crate::checks::ddos::store::{CounterStore, MemoryCounterStore};
    use crate::checks::ddos::{DdosConfig, DdosTierCfg};

    fn make_ctx(ip: &str) -> RequestCtx {
        use bytes::Bytes;
        use std::collections::HashMap;
        use waf_common::HostConfig;

        RequestCtx {
            req_id: "test-req".to_string(),
            client_ip: ip.parse().expect("valid IP"),
            client_port: 12345,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
            tier: Tier::Medium,
            tier_policy: Arc::new(TierPolicy {
                fail_mode: FailMode::Open,
                ..TierPolicy::default()
            }),
            cookies: HashMap::new(),
        }
    }

    fn make_check_no_detectors() -> DdosCheck {
        let mut tiers = std::collections::HashMap::new();
        tiers.insert(
            Tier::Medium,
            DdosTierCfg {
                per_fp_threshold: 100,
                per_fp_window_s: 60,
                per_tier_threshold: 10_000,
                per_tier_window_s: 60,
            },
        );
        let cfg = Arc::new(ArcSwap::from(Arc::new(DdosConfig {
            tiers,
            gc_interval_s: 60,
            max_keys: 1000,
        })));

        let store: Arc<dyn CounterStore> = Arc::new(MemoryCounterStore::new(1000, 60));
        let ban_table = Arc::new(DynamicBanTable::new());
        let ban_action = BanAction::with_defaults(Arc::clone(&ban_table), store);
        let action = Arc::new(CombinedAction::new(vec![Box::new(ban_action)]));

        DdosCheck::new(
            cfg,
            vec![], // No detectors
            action,
            Arc::new(OverloadGuard::default()),
            ban_table,
            Arc::new(DdosMetrics::new()),
        )
    }

    #[test]
    fn check_allows_when_no_detectors() {
        let check = make_check_no_detectors();
        let ctx = make_ctx("192.168.1.1");
        assert!(check.check(&ctx).is_none());
    }

    #[test]
    fn check_skips_unconfigured_tier() {
        let cfg = Arc::new(ArcSwap::from(Arc::new(DdosConfig::default())));
        let store: Arc<dyn CounterStore> = Arc::new(MemoryCounterStore::new(1000, 60));
        let ban_table = Arc::new(DynamicBanTable::new());
        let ban_action = BanAction::with_defaults(Arc::clone(&ban_table), store);
        let action = Arc::new(CombinedAction::new(vec![Box::new(ban_action)]));

        let check = DdosCheck::new(
            cfg, // Empty config = no tiers configured
            vec![],
            action,
            Arc::new(OverloadGuard::default()),
            ban_table,
            Arc::new(DdosMetrics::new()),
        );

        let ctx = make_ctx("192.168.1.1");
        assert!(check.check(&ctx).is_none());
    }

    #[test]
    fn check_blocks_banned_ip() {
        let check = make_check_no_detectors();
        let ip: IpAddr = "10.0.0.1".parse().expect("valid IP");

        // Ban the IP
        let now_ms = now_epoch_ms();
        check.ban_table.insert(ip, now_ms + 60_000);

        let ctx = make_ctx("10.0.0.1");
        let result = check.check(&ctx);

        assert!(result.is_some());
        let r = result.expect("should block");
        assert_eq!(r.rule_id.as_deref(), Some("DDOS-BAN"));
        assert_eq!(r.phase, Phase::Ddos);
    }

    #[test]
    fn metrics_accessible() {
        let check = make_check_no_detectors();
        assert_eq!(check.metrics().burst_total(), 0);
    }
}
