---
phase: 5
title: "Action Ban & Risk Bump"
status: completed
priority: P0
effort: "1d"
dependencies: [1, 2]
completed: 2026-05-05
---

# Phase 5: Action Ban & Risk Bump

## Overview

`ActionExecutor` trait (Command pattern). `BanAction` writes TTL-escalating bans into `access::ip_table`; `RiskBumpAction` bumps risk via existing aggregator. Decouples detection (phase 2-4) from side-effects.

## Requirements

- Functional:
  - `ActionExecutor::execute(&self, ctx: &RequestCtx, verdict: &DetectorVerdict) -> ActionResult`.
  - `BanAction`: TTL escalation per offender (1st=60s/+30 risk, 2nd=5m/+50, 3rd+=1h/+max-clamp). Offense window: 1h.
  - Writes to `access::ip_table` block list with per-entry TTL.
  - `RiskBumpAction`: submits delta to FR-025 risk aggregator (FR-010 `RiskAggregator` trait). Clamp at 100.
  - Combined executor that runs ban + risk bump for `HardBurst` verdicts.
- Non-functional:
  - Offense counter shares `MemoryCounterStore` from phase 1 (separate namespace `ddos:offense:`).
  - Offense entries auto-GC after offense_window (1h).
  - Idempotent: repeated ban for same `(ip, ts)` does NOT double-escalate within 100 ms (debounce).

## Architecture

```rust
// action/mod.rs
pub trait ActionExecutor: Send + Sync {
    fn name(&self) -> &'static str;
    fn execute(&self, ctx: &RequestCtx, verdict: &DetectorVerdict) -> ActionResult;
}

pub struct ActionResult {
    pub banned: bool,
    pub ban_ttl_s: Option<u32>,
    pub risk_delta: u8,
}

// action/ban.rs
pub struct BanAction {
    ip_table: Arc<access::IpTable>,        // FR-008 write API
    offense_store: Arc<dyn CounterStore>,  // counts offenses per IP
    schedule: BanSchedule,                 // [(60, 30), (300, 50), (3600, 100)]
}

impl BanAction {
    fn ttl_for(offense_n: u64) -> (u32 /*ttl_s*/, u8 /*risk*/) {
        match offense_n {
            0 | 1 => (60, 30),
            2 => (300, 50),
            _ => (3600, 100), // clamped
        }
    }
}

// action/risk.rs
pub struct RiskBumpAction {
    aggregator: Arc<dyn RiskAggregator>, // FR-010 aggregator trait
}
```

`access::IpTable` exposes `insert_str`. We need a TTL-aware variant — confirm during phase 5 read pass; if missing, add `insert_with_ttl(cidr, expires_ms)` to `access::ip_table` (small, surgical) and a GC pass in `access` (already exists per FR-008 phase-02 — verify).

## Related Code Files

- Create:
  - `crates/waf-engine/src/checks/ddos/action/mod.rs`
  - `crates/waf-engine/src/checks/ddos/action/ban.rs`
  - `crates/waf-engine/src/checks/ddos/action/risk.rs`
- Read:
  - `crates/waf-engine/src/access/ip_table.rs` — insert API; confirm TTL support
  - `crates/waf-engine/src/access/reload.rs` — does block list survive reload? (must — bans persist across config reload)
  - `crates/waf-engine/src/device_fp/aggregator.rs` — `RiskAggregator` trait
- Modify (only if `IpTable::insert_with_ttl` missing):
  - `crates/waf-engine/src/access/ip_table.rs` — add TTL field + expiry-aware `contains`

## Implementation Steps

1. Read `access::ip_table` API. If `insert_with_ttl` missing, add it (small change, document in phase 5 PR description).
2. Implement `action/mod.rs` trait + `ActionResult`.
3. Implement `action/ban.rs`:
   - Offense lookup: `incr_get("ddos:offense:{ip}", 3600_000, now_ms)`.
   - Map count → `(ttl_s, risk)` via `BanSchedule::ttl_for`.
   - Call `ip_table.insert_with_ttl(format!("{}/32 or /128", ip), now_ms + ttl_s*1000)`.
   - Emit `tracing::warn!` with structured fields per brainstorm §9.
4. Implement `action/risk.rs`:
   - `aggregator.submit(&fp_key, &[Signal::DdosBurst { score: clamped }])`. (Reuse existing `Signal` enum if it has a generic risk variant; if not, document gap and use `Signal::Custom("ddos_burst", score)` per device_fp signal types.)
5. Implement `CombinedAction { ban: BanAction, risk: RiskBumpAction }` that composes both.
6. Unit tests via `rstest` parametric over offense # 1..=5:

   | Offense # | Expected TTL (s) | Expected risk delta |
   |-----------|------------------|---------------------|
   | 1 | 60 | 30 |
   | 2 | 300 | 50 |
   | 3 | 3600 | 100 |
   | 4 | 3600 | 100 |
   | 5 | 3600 | 100 |

7. Verify `risk_delta` clamps at 100 (proptest: any input → output ≤ 100).
8. Verify offense counter expires after 1h (use `MockClock`, advance 3700s, assert next ban resets to TTL=60).
9. Run `cargo check / clippy / test`.

## Success Criteria

- [x] All ban-schedule rstest rows green (20 tests pass)
- [x] Risk clamp at 100 (unit test: `action_result_merge_clamps_risk`)
- [x] Offense counter expiry restarts schedule after 1h (configured via `offense_window_ms`)
- [x] `DynamicBanTable` correctly contains banned IP within TTL; expires after
- [x] `cargo clippy --all-targets -- -D warnings` clean (lib)
- [x] No `.unwrap()` outside tests
- [x] Structured log emitted on ban (tracing::warn! with structured fields)

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| `IpTable` lacks TTL — needs surgical extension | Document scope creep in PR; small additive change, no behaviour drift for existing FR-008 callers |
| Race: same IP banned twice in 100ms doubles escalation | 100ms debounce key `ddos:offense_lock:{ip}` with TTL=100ms — second writer skips offense increment |
| Offense store GC starves under flood | Shares phase 1 `MemoryCounterStore` GC; `max_keys` cap protects |
| Ban survives config reload? | `access` reload swaps allow/block lists atomically (FR-008 design); bans live in the active list — verify behaviour with test |
| `RiskAggregator::submit` is async fire-and-forget | Aligns with FR-010 contract; use `block_in_place` bridge identical to `RateLimitStore` |
