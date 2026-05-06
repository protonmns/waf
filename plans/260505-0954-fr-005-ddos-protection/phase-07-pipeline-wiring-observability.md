---
phase: 7
title: "Pipeline Wiring & Observability"
status: completed
priority: P0
effort: "1d"
dependencies: [1, 2, 3, 4, 5, 6]
---

# Phase 7: Pipeline Wiring & Observability

## Overview

Wire `DdosCheck` (impls `Check` trait) into `engine.rs` between Phase 4 (allowlist) and Phase 5 (rate_limit). Implements chain-of-responsibility over registered detectors. Adds Prom metrics + structured audit log feeding FR-032.

## Requirements

- Functional:
  - `DdosCheck::check(&self, ctx: &RequestCtx) -> Option<DetectionResult>`.
  - Runs detectors in cheap-first order: per_ip → per_fp → per_tier. Short-circuits on first `HardBurst`.
  - On `HardBurst`: invokes `CombinedAction` (ban + risk bump), returns `DetectionResult`.
  - On `SoftAnomaly(score)`: bumps risk only, returns `None` (let downstream challenge engine decide).
  - On store error: invokes `degrade::resolve` per ctx tier; returns `DetectionResult` if blocked.
  - Pipeline order verified: runs after `access::Evaluator` (allowlist short-circuits before us) and BEFORE `RateLimitCheck` (so banned IPs skip rate-limit work — but allowlist already short-circuited so this is purely an optimisation order).
- Non-functional:
  - Prom metrics: `ddos_burst_total{detector,tier}`, `ddos_ban_active`, `ddos_counter_keys`, `ddos_store_errors_total{kind}`.
  - One `tracing::warn!` structured log per ban event with: `request_id, ts_ms, ip, device_fp, detector, threshold, action, ttl_s`.

## Architecture

```rust
// check.rs
pub struct DdosCheck {
    cfg: Arc<ArcSwap<DdosConfig>>,
    detectors: Vec<Box<dyn Detector>>,
    action: Arc<CombinedAction>,
    guard: Arc<OverloadGuard>,
}

impl Check for DdosCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        let snap = self.cfg.load();
        let cfg = snap.for_tier(ctx.tier)?;     // skip if tier unconfigured
        let now_ms = now_epoch_ms();
        for d in &self.detectors {
            match d.evaluate(ctx, cfg, now_ms) {
                DetectorVerdict::Allow => continue,
                DetectorVerdict::SoftAnomaly(score) => {
                    self.action.bump_risk_only(ctx, score);
                    metrics::DDOS_BURST.with_label_values(&[d.name(), tier_str(ctx.tier)]).inc();
                    // continue evaluating — soft anomalies don't short-circuit
                }
                DetectorVerdict::HardBurst { reason, detector } => {
                    let res = self.action.execute(ctx, &verdict);
                    metrics::DDOS_BURST.with_label_values(&[detector, tier_str(ctx.tier)]).inc();
                    return Some(DetectionResult {
                        rule_id: Some(format!("DDOS-{}", detector.to_uppercase())),
                        rule_name: "DDoS Protection".into(),
                        phase: Phase::Ddos,            // new variant — see step 3
                        detail: format!("ddos {} ({}); banned {}s", detector, reason, res.ban_ttl_s.unwrap_or(0)),
                    });
                }
            }
        }
        None
    }
}
```

## Related Code Files

- Create:
  - `crates/waf-engine/src/checks/ddos/check.rs`
  - `crates/waf-engine/src/checks/ddos/metrics.rs` (Prom Lazy statics; mirrors patterns in `crates/waf-engine/src/checks/*` if existing — otherwise centralise via `waf-common::metrics` if that exists).
- Modify:
  - `crates/waf-engine/src/engine.rs` — register `DdosCheck` between allowlist (Phase 1-4) and `RateLimitCheck` (Phase 5-11). Pass through reload handle.
  - `crates/waf-engine/src/checks/mod.rs` — re-export `DdosCheck`, `DdosConfig`, `DdosFileConfig`, `DdosReloader`.
  - `crates/waf-common/src/lib.rs` (or wherever `Phase` enum lives) — add `Phase::Ddos` variant.
  - `waf-common::RequestCtx` — confirm `device_fp: Option<DeviceFp>` field exists; if absent, add it now (the central wiring phase is the right place).

## Implementation Steps

1. Read `engine.rs` end-to-end (lines 1-300+); locate the exact insertion point between allowlist evaluator and `checkers` vec push for `RateLimitCheck`.
2. Add `Phase::Ddos` variant to `waf-common::Phase`. Update any exhaustive matches (compiler will flag).
3. Implement `ddos/check.rs` per sketch above.
4. Implement `ddos/metrics.rs`:
   - `Lazy<IntCounterVec>` for `ddos_burst_total{detector,tier}`.
   - `Lazy<IntGauge>` for `ddos_ban_active` (track from `BanAction` increments + GC decrements).
   - `Lazy<IntGauge>` for `ddos_counter_keys` (sample from `MemoryCounterStore::len()` on GC tick).
   - `Lazy<IntCounterVec>` for `ddos_store_errors_total{kind}`.
5. Wire reloader: parallel to `RateLimitReloader`, instantiate `DdosReloader::start(path, cfg_swap, DEFAULT_DEBOUNCE_MS)` at engine boot; store handle on `WafEngine`.
6. Confirm pipeline ordering with a synthetic request: allowlisted IP never hits ddos detector (test); banned IP returns 403 from access evaluator on next request without entering rate_limit (test).
7. Audit log: `tracing::warn!(target: "ddos::audit", request_id, ts_ms, ip, device_fp, detector, threshold, action, ttl_s, "ddos action")`. Confirm subscriber routes `ddos::audit` target into FR-032 audit sink.
8. Run `cargo check / clippy / test`; integration test in phase 9 covers full flow.

## Success Criteria

- [x] `cargo check -p waf-engine` clean after pipeline insertion
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] Pipeline ordering test: allowlist → ddos → rate_limit (verified by ordered call counter on mocks) — deferred to phase 9
- [x] Banned IP, on next request, blocked by `DdosCheck` (ban_table.contains check in check.rs)
- [x] Atomic metrics exposed via `DdosMetrics` (4 counter types: burst, ban, store_error, degrade)
- [x] Structured audit log emitted on every ban (tracing::warn! target="ddos::audit")
- [x] No regression in existing `engine.rs` tests
- [x] No `.unwrap()` outside tests; reload errors fail-soft (existing pattern)

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Adding `Phase::Ddos` breaks downstream exhaustive matches | Compiler-enforced; fix all sites in same PR |
| `RequestCtx::device_fp` field addition ripples through tests | Default field to `None` via `#[serde(default)]` / `Default` impl; existing test fixtures unaffected |
| Metric label cardinality (per-IP labels) | We label only by `detector` + `tier` (4 tiers × 3 detectors = 12 series cap) — bounded |
| Audit log volume on flood | Logged AT ban time, not per request after ban — natural rate-limit |
| Pipeline order regression in future refactor | Comment block in `engine.rs` near insertion site documents required ordering; integration test in phase 9 enforces |
| Adding metrics without existing prom registry | If repo lacks one, follow `crates/waf-engine/src/checks/*` precedent or use `waf-common::metrics`; do NOT introduce new framework |
