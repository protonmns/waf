# FR-005 Phase 5: Action Ban & Risk Bump

**Date**: 2026-05-05 14:53
**Severity**: Medium
**Component**: DDoS Protection Engine (Action Executors Layer)
**Status**: Resolved

## What Happened

Shipped DDoS Phase 5: implemented the `ActionExecutor` trait (Command pattern), `BanAction` with TTL escalation, and `RiskBumpAction` for cross-module signal submission. 20 unit tests passing, clippy clean, code review approved with documented concerns deferred. Decoupled side-effects (bans, risk signals) from detection logic cleanly.

## The Brutal Truth

The core design feels solid, but the pain point is the **debounce lock garbage collection**. We're using `DashMap` with manual `retain()` calls, and there's no automatic GC wiring yet. In a long-running process with millions of IPs, stale debounce locks will accumulate unless Phase 7 implements periodic purges. We documented it, signed off on it, and deferred it—but it's a cleanup debt that will bite us if we forget.

The risk bridge to FR-010's `RiskAggregator` via `block_in_place` feels inelegant. We're breaking out of async to call an async API because the action executor interface is sync. Works, tested, safe—but it's a wart that reveals the original architecture didn't anticipate this cross-cutting concern. Not a blocker; just honest assessment.

## Technical Details

### 1. ActionExecutor Trait: Command Pattern

```rust
pub trait ActionExecutor: Send + Sync {
    fn name(&self) -> &'static str;
    fn execute(&self, ip: IpAddr, verdict: &DetectorVerdict, now_ms: i64) -> ActionResult;
}

pub struct ActionResult {
    pub banned: bool,
    pub ban_ttl_s: Option<u32>,
    pub risk_delta: u8,
}
```

**Decision**: Synchronous trait returning `ActionResult` (no async, no errors). Rationale:
- Action executors perform *side-effects*, not decision logic
- Results must be merged (multiple actions can ban + risk simultaneously)
- Errors in side-effects (store failures, aggregator issues) are non-fatal—log and continue

### 2. DynamicBanTable: TTL-Aware IP Storage

Created new `DynamicBanTable` instead of modifying `access::IpCidrTable` (which is immutable after config load).

```rust
pub struct DynamicBanTable {
    entries: DashMap<IpAddr, i64>,  // IP → expiry timestamp (ms)
}
```

**Design decisions**:
- `DashMap` for lock-free concurrent access (no Mutex)
- Per-entry TTL checked at lookup time (cheap O(1) check)
- `retain()` for periodic purge (manual, deferred to Phase 7)

**Why not reuse `access::IpCidrTable`?** Fundamentally different use cases:
- `IpCidrTable`: Static CIDR blocks loaded once at startup
- `DynamicBanTable`: Dynamic, short-lived per-IP bans with expiry

Merging them would require retrofitting expiry logic to an immutable table. Cleaner to keep them separate.

### 3. BanSchedule: Escalation Levels

```rust
pub struct BanSchedule {
    steps: Vec<BanStep>,  // 1st: 60s/+30 → 2nd: 5m/+50 → 3rd+: 1h/+100
}
```

Default escalation:
- **1st offense**: 60s ban, +30 risk
- **2nd offense**: 300s ban, +50 risk  
- **3rd+ offense**: 3600s ban, +100 risk

Offense counter resets after 1-hour window (stored in `CounterStore` with `incr_get_blocking`). Escalation prevents attackers from hammering with repeated bans; each repeat escalates the response.

### 4. Debounce Lock: Race Condition Mitigation

```rust
debounce_locks: DashMap<IpAddr, i64>,  // IP → last-ban timestamp
```

**Problem solved**: Without debounce, a burst of simultaneous requests from the same IP could trigger multiple ban increments in the same millisecond, escalating the schedule prematurely (e.g., jumping 60s→300s→3600s in one event).

**Solution**: 100ms debounce window. Once an IP is banned, subsequent bans within 100ms return `noop()`, skipping the offense increment.

**Trade-off**: Slight inaccuracy in offense counting (multiple violations within 100ms count as one), but prevents cascade escalation. Acceptable because:
- 100ms is imperceptible to attacker experience
- Missed escalation means they get 60s instead of 300s (still effective)
- Prevents false-severity scenarios

**Unresolved**: Stale locks accumulate. Phase 7 must call `purge_debounce_locks(now_ms)` periodically (e.g., every 10 seconds) to clean locks older than 1 second.

### 5. RiskBumpAction: Cross-Module Signal Bridge

Submits DDoS detections to FR-010's `RiskAggregator` using `Signal::BurstInterval`.

```rust
tokio::task::block_in_place(|| {
    tokio::runtime::Handle::current().block_on(async {
        self.aggregator.submit(&fp_key, &[signal]).await;
    });
});
```

**Architectural pain**: Action executor trait is sync, but `RiskAggregator::submit()` is async. We bridge this with `block_in_place`, which:
- Blocks the current sync context
- Acquires a handle to the tokio runtime
- Runs the async call to completion

**Why it's safe**: Aggregator's contract is "submit MUST NOT block on I/O"—it queues signals and returns immediately. No deadlock risk.

**Why it feels wrong**: The architecture should have allowed async actions or provided an async action interface. This is a design debt. Acceptable for Phase 5 because risk submission is not on the critical path, but Phase 7's pipeline wiring should revisit this.

## Code Quality & Testing

**Tests**: 20 passing
- `ActionResult`: noop, merge (OR banned, MAX TTL, SUM risk clamped)
- `DynamicBanTable`: insert, contains, purge, extend
- `BanSchedule`: escalation levels, offense 0 → 1, cap at final step
- `BanAction`: first offense, escalates on repeat, debounce prevents double-escalation, different IPs independent, ignores non-HardBurst verdicts
- `RiskBumpAction`: ignores Allow, submits SoftAnomaly/HardBurst, FpKey contains IP, zero-delta is noop

**Code Review**: PASS
- H1: `BanSchedule::new` has `assert!` with proper `# Panics` doc—approved
- H2: Suggested periodic debounce cleanup—noted for Phase 7
- H3: Questioned `block_in_place` usage—documented rationale, approved as temporary bridge
- All suggested fixes applied before merge

**Linting**: clippy clean, zero warnings.

## Lessons Learned

1. **Separate mutable from immutable storage** cleanly. `DynamicBanTable` and `access::IpCidrTable` serve different purposes; trying to merge them would create coupling nightmares. Duplication at the data-structure level is okay if semantics differ.

2. **Debounce is subtle**. The 100ms debounce window prevents cascade escalation, but it introduces a subtle accuracy loss (multi-hit-per-debounce-window counts as one). Document this explicitly; future maintainers will face production issues if they naively "fix" it without understanding the cascade scenario.

3. **Async/sync boundary pain is real**. `block_in_place` is a workaround, not a solution. Phase 5 was sync-only by design, but integrating with FR-010's async aggregator exposed a mismatch. Next time, decide async/sync consistency at architecture time, not during implementation.

4. **`ActionResult` merging is elegant**. OR'ing banned flags, taking MAX TTL, and clamping summed risk creates a composable API. `CombinedAction` can run multiple executors and merge results safely. This pattern scales well.

## Next Steps

- **Phase 6** (degrade + circuit-breaker): Implement retry logic, fallback bans when risk aggregator is slow
- **Phase 7** (pipeline wiring + observability): Wire actions into detector output, implement `purge_debounce_locks()` in main loop, add metrics for bans/risk submissions
- **Monitor**: Track `DynamicBanTable::len()` over time; if it grows unbounded, Phase 7's GC is missing

---

**Files Created**:
- `crates/waf-engine/src/checks/ddos/action/mod.rs` (ActionExecutor trait, ActionResult, CombinedAction)
- `crates/waf-engine/src/checks/ddos/action/ban.rs` (DynamicBanTable, BanSchedule, BanAction)
- `crates/waf-engine/src/checks/ddos/action/risk.rs` (RiskBumpAction)

**Files Modified**: 
- `crates/waf-engine/src/checks/ddos/mod.rs` (added `pub mod action`)

**Dependencies**: 
- `dashmap` (lock-free concurrent maps)
- `tracing` (warn/debug logging)
- Inherited: `tokio`, `parking_lot` from Phase 1

**Backward Compatibility**: Additive. No breaking changes to detector or store interfaces.
