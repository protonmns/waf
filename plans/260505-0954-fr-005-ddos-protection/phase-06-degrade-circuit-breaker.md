---
phase: 6
title: "Degrade & Circuit Breaker"
status: completed
priority: P0
effort: "6h"
dependencies: [1, 2]
completedDate: "2026-05-05"
---

# Phase 6: Degrade & Circuit Breaker

## Overview

`OverloadGuard` watches tokio runtime metrics; `degrade::resolve(tier_policy, error_kind) → Action` enforces the FR-036/037/038 fail-mode matrix. Production must not amplify overload — when the detector store is broken or the runtime is saturated, decisions are deterministic per tier.

## Requirements

- Functional:
  - `degrade::resolve(tier: Tier, fail_mode: FailMode, err: ErrorKind) -> DegradeAction`.
  - `ErrorKind { StoreUnavailable, BackendOverload, ConfigStale }`.
  - `DegradeAction { Allow, BlockWithStatus(503, "retry-after"), AllowAndWarn }`.
  - Matrix per brainstorm §7:

    | Tier | Detector overload (StoreUnavailable) | Backend overload |
    |------|--------------------------------------|------------------|
    | Critical | Block 503 | Block 503 |
    | High | Block 503 | Block 503 |
    | Medium | Allow + warn | Allow + warn |
    | CatchAll | Allow | Allow |

  - `OverloadGuard::is_overloaded()` — true if `tokio::runtime::Handle::metrics().global_queue_depth()` > threshold OR rolling p99 task wait > threshold.
- Non-functional:
  - `resolve` is pure; `OverloadGuard` thread-safe and lock-free for reads (`AtomicBool` flipped by background sampler).

## Architecture

```rust
// degrade.rs
pub enum ErrorKind { StoreUnavailable, BackendOverload, ConfigStale }
pub enum DegradeAction {
    Allow,
    AllowAndWarn,
    Block { status: u16, retry_after_s: u32 },
}

pub fn resolve(tier: Tier, fail_mode: FailMode, err: ErrorKind) -> DegradeAction {
    match (tier, fail_mode) {
        (Tier::Critical | Tier::High, _)
            | (_, FailMode::Close)        => DegradeAction::Block { status: 503, retry_after_s: 5 },
        (Tier::Medium, _)                 => DegradeAction::AllowAndWarn,
        (Tier::CatchAll, _)               => DegradeAction::Allow,
    }
}

pub struct OverloadGuard {
    overloaded: AtomicBool,
    queue_depth_threshold: usize,
}

impl OverloadGuard {
    pub fn spawn_sampler(self: Arc<Self>, handle: tokio::runtime::Handle) {
        // every 100ms, sample handle.metrics().global_queue_depth()
        // store overloaded.store(depth > threshold, Relaxed)
    }
    #[inline] pub fn is_overloaded(&self) -> bool { self.overloaded.load(Relaxed) }
}
```

`tokio::runtime::Handle::metrics()` is unstable; gate behind `tokio_unstable` cfg flag (CLAUDE.md does not currently set this — confirm in repo `.cargo/config.toml`). If unavailable, fall back to a manual queue-depth proxy: count of in-flight `block_in_place` calls via a shared `AtomicUsize`.

## Related Code Files

- Create:
  - `crates/waf-engine/src/checks/ddos/degrade.rs`
- Read:
  - `waf-common::tier::{Tier, FailMode, TierPolicy}` — confirm exhaustive enum match
  - `crates/waf-engine/src/checks/rate_limit/check.rs::handle_store_err` — current per-tier fail-mode handling for reference

## Implementation Steps

1. Confirm tokio runtime metrics availability. If `tokio_unstable` is on:
   - Build sampler around `Handle::metrics().global_queue_depth()`.
   Else:
   - Use a shared `Arc<AtomicUsize>` increment/decrement around every `incr_get_blocking` call as a coarser proxy. Document the substitution.
2. Implement `degrade.rs` with `ErrorKind`, `DegradeAction`, `resolve`, and `OverloadGuard`.
3. Chaos table tests via `rstest`:

   | Tier × FailMode × ErrorKind | Expected |
   |-----------------------------|----------|
   | (Critical, Open, StoreUnavailable) | Block 503 |
   | (Critical, Open, BackendOverload) | Block 503 |
   | (High, Open, StoreUnavailable) | Block 503 |
   | (Medium, Open, StoreUnavailable) | AllowAndWarn |
   | (Medium, Close, StoreUnavailable) | Block 503 |
   | (CatchAll, Open, StoreUnavailable) | Allow |
   | (CatchAll, Close, BackendOverload) | Block 503 |
   | (CatchAll, Open, ConfigStale) | Allow |

4. Property test: `forall (tier, fail_mode, err): resolve(...) terminates` (no panic).
5. `OverloadGuard` test: spawn sampler, push fake queue-depth via the shared counter, assert `is_overloaded()` flips within 200ms.

## Success Criteria

- [x] `cargo check / clippy / test` green
- [x] All chaos table rows green
- [x] Exhaustive match on `(Tier, FailMode, ErrorKind)` — no `_ => ...` fallthroughs (compiler enforces)
- [x] `OverloadGuard::is_overloaded()` is lock-free read (verified by in-flight counter + sampler test)
- [x] No `.unwrap()` outside tests

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| `tokio_unstable` not enabled in repo | Fall back to in-flight-call counter; document trade-off; revisit when team enables flag |
| Sampler thread leak on shutdown | Sampler honours `CancellationToken`; integration test asserts task exits cleanly |
| Matrix grows with new tiers | Exhaustive match makes new variants compile-fail until handled — feature, not bug |
| Action confusion: phase 6 owns degrade decisions, phase 5 owns ban decisions | Documented split; phase 7 wiring is single owner of "which one to call" |
