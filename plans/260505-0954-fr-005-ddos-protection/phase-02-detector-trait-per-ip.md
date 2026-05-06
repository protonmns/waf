---
phase: 2
title: "Detector Trait & Per-IP"
status: complete
priority: P0
effort: "4h"
dependencies: [1]
completedAt: "2026-05-05T12:47:00.000Z"
---

# Phase 2: Detector Trait & Per-IP

## Overview

Define `Detector` trait + `DetectorVerdict` enum. Implement `per_ip` as a thin wrapper that delegates to `rate_limit::store::Decision` — NO new math. Establishes the Strategy pattern that phases 3 & 4 follow.

## Requirements

- Functional:
  - `Detector::evaluate(&self, ctx: &RequestCtx, cfg: &DdosTierCfg, now_ms: i64) -> DetectorVerdict`.
  - `DetectorVerdict { Allow, SoftAnomaly(u8), HardBurst { reason: &'static str, detector: &'static str } }`.
  - `PerIpDetector` reuses an injected `Arc<dyn RateLimitStore>` — translates `Decision::BurstExceeded` → `HardBurst { reason: "burst", detector: "per_ip" }`, `Decision::SustainedExceeded` → `HardBurst { reason: "sustained", detector: "per_ip" }`.
- Non-functional:
  - Zero-alloc on `Allow` path (no `String` in verdict — `&'static str`).
  - Detector composition order is deterministic; configured by registry list.

## Architecture

```rust
// detector/mod.rs
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn evaluate(&self, ctx: &RequestCtx, cfg: &DdosTierCfg, now_ms: i64) -> DetectorVerdict;
}

#[derive(Debug, Clone, Copy)]
pub enum DetectorVerdict {
    Allow,
    SoftAnomaly(u8),                            // risk delta (0-100)
    HardBurst { reason: &'static str, detector: &'static str },
}
```

`PerIpDetector` does NOT introduce a new counter. It calls `RateLimitStore::check_and_consume_blocking` with a `LimitCfg` derived from the DDoS tier config (`burst_capacity = per_tier_threshold`, `window_secs = per_tier_window_s`), then maps the `Decision`. This guarantees DRY: FR-004 stays the source of truth for per-IP math.

Key format: `ddos:ip:{tier}:{ip}` to keep store namespaces from clashing with FR-004's `ip:{host}:{ip}`.

## Related Code Files

- Create:
  - `crates/waf-engine/src/checks/ddos/detector/mod.rs`
  - `crates/waf-engine/src/checks/ddos/detector/per_ip.rs`
- Modify:
  - `crates/waf-engine/src/checks/ddos/mod.rs` — `pub mod detector;`

## Implementation Steps

1. Create `detector/mod.rs` with `Detector` trait + `DetectorVerdict` enum (above).
2. Implement `detector/per_ip.rs`:
   - `pub struct PerIpDetector { store: Arc<dyn RateLimitStore> }`
   - `evaluate` builds key `format!("ddos:ip:{}:{}", tier_str(ctx.tier), ctx.client_ip)` (acceptable here — one alloc per request, optimised in phase 7 if profiling shows).
   - Translates `Decision` → `DetectorVerdict`.
   - On `Err`, returns `Allow` and emits `tracing::warn!` (degrade decision is owned by phase 6, not here).
3. Unit tests in `per_ip.rs`:
   - `Decision::Allow → Verdict::Allow`
   - `Decision::BurstExceeded → HardBurst { reason: "burst", .. }`
   - `Decision::SustainedExceeded → HardBurst { reason: "sustained", .. }`
   - Store error → `Allow` (degrade owns the decision).
4. Run `cargo check`, `cargo clippy -- -D warnings`, `cargo test -p waf-engine ddos::detector::per_ip`.

## Success Criteria

- [x] `cargo check / clippy / test` green
- [x] No new math in `per_ip.rs` — only delegation + mapping
- [x] `DetectorVerdict::Allow` path is zero-alloc (verify with `dhat` snapshot in phase 8)
- [x] Public API: only `Detector`, `DetectorVerdict`, `PerIpDetector` re-exported from `ddos::detector`
- [x] `cargo doc -p waf-engine --no-deps` clean

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Key collision with FR-004 store namespace | Mandatory `ddos:` prefix; integration test (phase 9) asserts both modules can share a `MemoryStore` without interference |
| Verdict enum grows over time | Keep variants ≤4; risk-delta lives in `SoftAnomaly(u8)` not separate variants |
| `format!` per request adds allocs | Acceptable in phase 2 baseline; phase 7 wires `bytes::BytesMut`-pooled key builder if hot path bench regresses |
