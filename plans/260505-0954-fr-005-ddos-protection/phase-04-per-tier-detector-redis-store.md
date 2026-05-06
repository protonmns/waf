---
phase: 4
title: "Per-Tier Detector & Redis Store"
status: complete
priority: P0
effort: "1.5d"
dependencies: [1, 2]
---

# Phase 4: Per-Tier Detector & Redis Store

## Overview

`PerTierDetector` maintains a single global counter per tier, plus a 60s moving-median baseline. Threshold = `count > 3 × median`, falling back to absolute cap on cold start. Adds Redis-backed `CounterStore` (cluster-coherent via Lua INCR+EXPIRE). Introduces `Clock` trait for testable time.

## Requirements

- Functional:
  - One global counter per tier (key: `ddos:tier:{tier_str}`).
  - Moving-median over rolling 60s window of per-second counts.
  - Threshold rule: `count > max(absolute_cap_floor, 3 × median)`. Cold start (median=0) ⇒ `count > absolute_cap_floor`.
  - Redis backend: atomic `EVAL` Lua script (INCR + PEXPIRE in one round-trip).
  - Feature-gated: `redis-store` cargo feature (mirrors `rate_limit/store/redis.rs`).
- Non-functional:
  - Detector p99 < 30µs in-process; Redis-mode p99 < 5ms (bounded by network).
  - `Clock` trait abstracts `SystemTime::now()` for testable time boundaries.
  - Redis call respects `op_timeout_ms` from config; on timeout/error returns `Err` (degrade owns reaction).

## Architecture

```rust
// detector/per_tier.rs
pub trait Clock: Send + Sync { fn now_ms(&self) -> i64; }
pub struct SystemClock;
impl Clock for SystemClock { fn now_ms(&self) -> i64 { /* SystemTime::UNIX_EPOCH */ } }

pub struct PerTierDetector {
    store: Arc<dyn CounterStore>,
    baseline: Arc<MovingMedian>, // 60-slot ring of per-second counts
    clock: Arc<dyn Clock>,
    absolute_cap_floor: u32,
}

struct MovingMedian {
    buckets: [AtomicU64; 60],   // ring indexed by epoch_s % 60
    last_tick_s: AtomicI64,
}

impl Detector for PerTierDetector {
    fn evaluate(&self, ctx, cfg, now_ms) -> DetectorVerdict {
        let key = format!("ddos:tier:{}", tier_str(ctx.tier));
        let n = self.store.incr_get_blocking(&key, 1000, now_ms)?;  // 1s window per slot
        self.baseline.record(n, now_ms);
        let median = self.baseline.median();
        let threshold = self.absolute_cap_floor.max(3 * median as u32);
        if n > u64::from(threshold) {
            HardBurst { reason: "tier_burst", detector: "per_tier" }
        } else { Allow }
    }
}
```

```lua
-- store/redis.rs Lua script (single EVAL):
-- KEYS[1]=key, ARGV[1]=ttl_ms
-- returns: incremented value
local v = redis.call('INCR', KEYS[1])
if v == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return v
```

## Related Code Files

- Create:
  - `crates/waf-engine/src/checks/ddos/detector/per_tier.rs`
  - `crates/waf-engine/src/checks/ddos/detector/baseline.rs` (MovingMedian)
  - `crates/waf-engine/src/checks/ddos/store/redis.rs` (feature-gated `redis-store`)
- Read for context:
  - `crates/waf-engine/src/checks/rate_limit/store/redis.rs` — Lua/connection pattern
  - `crates/waf-engine/src/checks/rate_limit/store/breaker.rs` — circuit breaker around Redis ops
- Modify:
  - `crates/waf-engine/src/checks/ddos/store/mod.rs` — `#[cfg(feature = "redis-store")] pub mod redis;`
  - `crates/waf-engine/Cargo.toml` — confirm `redis-store` feature already exists; if not, add (it does — see CLAUDE.md "Features (cargo)").

## Implementation Steps

1. Add `Clock` trait + `SystemClock` to `detector/per_tier.rs`. (Could live in `ddos/mod.rs` if reused — start local, hoist if needed.)
2. Implement `MovingMedian` in `detector/baseline.rs`:
   - `record(count, now_ms)`: bucket index = `(now_ms / 1000) % 60`. Reset bucket when `epoch_s` differs from `last_tick_s`.
   - `median()`: copy 60 buckets to local array, sort, return `arr[30]`.
   - Atomicity: `AtomicU64` per bucket, `AtomicI64` for `last_tick_s` with CAS on rollover.
3. Implement `PerTierDetector` per sketch.
4. Implement Redis store under `store/redis.rs`:
   - Connection from `redis::aio::ConnectionManager` (see `rate_limit/store/redis.rs`).
   - `incr_get` calls Lua via `redis::Script::new(...).key(k).arg(ttl_ms).invoke_async()`.
   - Wrap calls in `tokio::time::timeout(op_timeout)` per `RedisCfg::op_timeout`.
5. Unit tests:
   - `MovingMedian`: empty → 0; sorted/unsorted inputs → correct median; rollover at `epoch_s` boundary clears stale buckets.
   - `PerTierDetector` with `MockClock` + `MemoryCounterStore`: cold start uses `absolute_cap_floor`; sustained traffic raises median; spike > 3× median fires.
   - Redis store with `mockall::mock!` for `aio::ConnectionLike` (or use `redis-test` crate) — assert Lua invoked once with correct keys/args; timeout returns `Err`.
6. Add CI matrix entry (or document) for `cargo test --features redis-store`.

## Success Criteria

- [x] `cargo check / clippy / test` green for default + `--features redis-store`
- [x] `MovingMedian` proptest: monotonic count increase ⇒ non-decreasing median (10k cases)
- [x] Cold-start path covered (median=0 → uses `absolute_cap_floor`)
- [x] Redis store: timeout, connection-refused, Lua error all return `Err` (no panic)
- [x] Detector p99 < 30µs in-process bench
- [x] No `.unwrap()` outside tests

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Redis as hard cluster dep (open Q) | Memory backend always works; cluster mode is opt-in. Documented in phase 10 docs |
| Median sort cost on hot path | 60-element sort is O(60 log 60) ≈ ~2µs; recompute on every request acceptable. Cache last value if profiling demands |
| Bucket race at second-boundary | CAS on `last_tick_s`; readers tolerate stale slot values for ≤1ms during rollover |
| Cold-start false negative | `absolute_cap_floor` config knob (default e.g. 1000 rps for Critical, 10k for Medium); operators tune per traffic |
| Lua script not loaded on first call | Use `redis::Script` (auto-EVALSHA with EVAL fallback) — pattern matches `rate_limit/store/redis.rs` |
