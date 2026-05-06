---
phase: 3
title: "Per-Fingerprint Detector"
status: complete
priority: P0
effort: "6h"
dependencies: [1, 2]
---

# Phase 3: Per-Fingerprint Detector

## Overview

`PerFpDetector` keys a sliding-window counter on `ctx.device_fp.hash`. Catches IP-rotating botnets sharing a fingerprint. Skips silently when device-fp is absent (no panic).

## Requirements

- Functional:
  - Counter check: `count(window_s) > per_fp_threshold` ⇒ `HardBurst`.
  - Reuses `rate_limit::algo::sliding_window` where applicable — DRY.
  - Skip when `ctx.device_fp` absent (FR-010 may not run for plain HTTP/1 without TLS extensions).
  - Per-tier defaults: Critical 30/10s, Medium 200/10s (configured in YAML; phase 1 schema covers).
- Non-functional:
  - Detector p99 < 80µs per brainstorm §10 budget.
  - Counter uses `MemoryCounterStore` from phase 1 (separate key namespace).

## Architecture

```rust
pub struct PerFpDetector {
    store: Arc<dyn CounterStore>,
}

impl Detector for PerFpDetector {
    fn name(&self) -> &'static str { "per_fp" }
    fn evaluate(&self, ctx: &RequestCtx, cfg: &DdosTierCfg, now_ms: i64) -> DetectorVerdict {
        let Some(fp) = ctx.device_fp.as_ref().and_then(|f| f.hash.as_ref()) else {
            return DetectorVerdict::Allow; // FR-010 absent → no signal, no false positive
        };
        let key = format!("ddos:fp:{}:{}", tier_str(ctx.tier), fp);
        let ttl_ms = i64::from(cfg.per_fp_window_s) * 1000;
        match self.store.incr_get_blocking(&key, ttl_ms, now_ms) {
            Ok(n) if n > u64::from(cfg.per_fp_threshold) =>
                DetectorVerdict::HardBurst { reason: "fp_burst", detector: "per_fp" },
            Ok(_) => DetectorVerdict::Allow,
            Err(_) => DetectorVerdict::Allow, // degrade owns it
        }
    }
}
```

This is a fixed-window approximation. The precise sliding-window from `rate_limit::algo` requires per-key timestamp vec we don't want to store for fp. Document the trade-off in rustdoc.

## Related Code Files

- Create:
  - `crates/waf-engine/src/checks/ddos/detector/per_fp.rs`
- Read for context:
  - `crates/waf-engine/src/device_fp/types.rs` — `FpKey` / fp hash field shape
  - `crates/waf-engine/src/device_fp/mod.rs` — how `ctx.device_fp` gets attached
  - `waf-common::RequestCtx` — confirm `device_fp` field exists; if not, gap noted for phase 7

## Implementation Steps

1. Confirm `RequestCtx` carries an `Option<DeviceFp>` (or equivalent). If not, document the gap — actual wiring lives in phase 7. Do NOT mutate `RequestCtx` here.
2. Implement `detector/per_fp.rs` per sketch above.
3. Re-export `PerFpDetector` from `ddos::detector` mod.
4. Unit tests:
   - Missing fp → `Allow`.
   - Empty fp string → `Allow`.
   - n < threshold → `Allow`.
   - n == threshold → `Allow` (boundary: `>` not `>=`).
   - n == threshold + 1 → `HardBurst`.
   - Distinct fps don't share counter (key namespace test).
   - Distinct tiers don't share counter (key includes tier).
5. Run `cargo check / clippy / test`.

## Success Criteria

- [x] All unit tests green (12 tests pass)
- [x] `cargo clippy -p waf-engine --all-targets -- -D warnings` clean
- [x] No panic on missing/empty fp (tested: `missing_fp_returns_allow`, `empty_fp_returns_allow`)
- [x] Trade-off (fixed-window vs precise sliding) documented in rustdoc
- [ ] Detector p99 < 80µs in shared bench harness (deferred to phase 8)

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| FR-010 fp absent for HTTP/1 plain → false negatives | Documented; per-IP detector still fires |
| Fingerprint collision (legit devices sharing JA4) | Threshold tuned per-tier; baseline learning deferred to v2 (brainstorm §10) |
| Fixed-window edge effect (≤2× burst at boundary) | Acceptable for rough rate; precise sliding would require per-key vec — YAGNI |
| `RequestCtx` lacks `device_fp` field | Defer add to phase 7 wiring; keep phase 3 changes inside `ddos/` |
