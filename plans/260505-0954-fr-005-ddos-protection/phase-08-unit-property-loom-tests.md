---
phase: 8
title: "Unit Property Loom Tests"
status: complete
priority: P0
effort: "1.5d"
dependencies: [1, 2, 3, 4, 5, 6, 7]
---

# Phase 8: Unit Property Loom Tests

## Overview

Bring `checks/ddos/**` to ≥90% line+branch coverage target via unit tests, property tests, and `loom` concurrency tests. Backfills the matrix from brainstorm §8.2 + §8.3.

## Requirements

- Functional:
  - Unit coverage on every detector / store / action / degrade path.
  - Property tests on counter math + threshold logic + risk monotonicity.
  - `loom`-gated concurrency tests on memory store atomics + ArcSwap reload race.
  - Time injected via `Clock` trait — no `SystemTime::now()` direct calls in tests.
  - Mock Redis store via `mockall` — assert error branches.
- Non-functional:
  - `cargo-llvm-cov --branch -p waf-engine -- --include-pattern "checks/ddos/**"` reports ≥90% line + ≥90% branch.
  - Reported in CI artifact; NOT gated (per locked decision).
  - All tests deterministic; no `sleep_ms` longer than necessary.

## Test Inventory

### Unit (per file `#[cfg(test)] mod tests`)

| Module | Cases |
|--------|-------|
| `store/memory.rs` | empty store; single key incr; ttl expiry exact-tick; GC removes expired; max_keys LRU evict |
| `store/redis.rs` | mockall: success; timeout returns Err; conn-refused returns Err; Lua error returns Err |
| `detector/per_ip.rs` | Decision::Allow→Allow; Burst→HardBurst; Sustained→HardBurst; Err→Allow |
| `detector/per_fp.rs` | missing fp→Allow; empty fp→Allow; n=threshold-1→Allow; n=threshold→Allow; n=threshold+1→HardBurst; tier-segregated keys |
| `detector/per_tier.rs` | cold start uses cap_floor; sustained traffic raises median; spike >3× fires |
| `detector/baseline.rs` | empty median=0; bucket rollover at second boundary; sort correctness |
| `action/ban.rs` | rstest: offense # 1..=5 → expected (TTL,risk); offense expiry resets schedule |
| `action/risk.rs` | clamp at 100; submission goes to aggregator (LoggingAggregator) |
| `degrade.rs` | rstest matrix from phase 6; exhaustive; no panic |
| `check.rs` | detector chain order; HardBurst short-circuits; SoftAnomaly continues; allowlist runs before us (mock) |

### Property (`proptest` in dedicated `tests/ddos_proptest.rs`)

```rust
proptest! {
    #[test]
    fn allow_below_threshold(threshold in 1u32..10_000, n in 0u32..10_000) {
        prop_assume!(n < threshold);
        // build detector with mock store returning n
        prop_assert!(matches!(verdict, DetectorVerdict::Allow));
    }

    #[test]
    fn risk_clamped(delta in 0u8..=255) {
        let final_risk = clamp_risk(0, delta);
        prop_assert!(final_risk <= 100);
    }

    #[test]
    fn monotonic_count_monotonic_median(samples in proptest::collection::vec(0u64..1_000, 60)) {
        // sliding sum on monotonically non-decreasing inputs ⇒ non-decreasing median
    }
}
```

10k cases per property.

### Concurrency (`loom` in `#[cfg(loom)] mod loom_tests`)

```rust
#[cfg(loom)]
#[test]
fn concurrent_incr_no_lost_updates() {
    loom::model(|| {
        let store = Arc::new(MemoryCounterStore::new(1000));
        let s2 = Arc::clone(&store);
        let h = loom::thread::spawn(move || s2.incr_get_sync("k", 1000, 0));
        store.incr_get_sync("k", 1000, 0);
        h.join().unwrap();
        // final count must be exactly 2 — no torn reads
    });
}
```

Add `#[cfg(loom)]` gated module with:
- Concurrent `incr_get` from N=2 workers — final count == N.
- `ArcSwap<DdosConfig>` reload race: 2 readers + 1 swapper — readers see consistent (old or new) snapshot, never a torn config.

### Mocked Redis Failure Injection

```rust
#[cfg_attr(feature = "redis-store", test)]
fn redis_timeout_returns_err() {
    let mut mock = MockRedisConn::new();
    mock.expect_invoke().returning(|_| Err(RedisError::timeout()));
    let store = RedisCounterStore::with_conn(mock, RedisCfg::test());
    let r = store.incr_get_blocking("k", 1000, 0);
    assert!(r.is_err());
}
```

## Related Code Files

- Create:
  - `crates/waf-engine/tests/ddos_proptest.rs`
  - `crates/waf-engine/tests/ddos_loom.rs` (gated `#[cfg(loom)]` — only built with `RUSTFLAGS=--cfg loom`)
- Modify (add `#[cfg(test)] mod tests`):
  - All files in `checks/ddos/` per Test Inventory above.
- Update:
  - `crates/waf-engine/Cargo.toml` — `[dev-dependencies]` add `proptest`, `mockall`, `rstest`, `tracing-test`. `loom` gated `[target.'cfg(loom)'.dev-dependencies]`.
  - `.github/workflows/*.yml` — add coverage job:
    ```yaml
    - run: cargo install cargo-llvm-cov --locked
    - run: cargo llvm-cov --branch --html -p waf-engine --features redis-store -- --include-pattern "checks/ddos/**"
    - uses: actions/upload-artifact@v4
      with: { name: ddos-coverage, path: target/llvm-cov/html }
    ```
  - Add nightly job for `loom`:
    ```yaml
    - run: RUSTFLAGS="--cfg loom" cargo test --test ddos_loom --release
    ```

## Implementation Steps

1. Add dev-deps. Confirm `proptest`, `mockall`, `rstest` not already present (likely partial).
2. Backfill unit tests per inventory. Use `Clock` trait (phase 4) to inject time everywhere; no `SystemTime::now()` calls in test bodies.
3. Write `tests/ddos_proptest.rs` with the three properties above.
4. Write `tests/ddos_loom.rs` gated `#[cfg(loom)]`. Verify locally with `RUSTFLAGS="--cfg loom" cargo test --release`.
5. Run `cargo llvm-cov --branch -p waf-engine -- --include-pattern "checks/ddos/**"` locally; iterate on uncovered branches.
6. Add CI coverage artifact upload (NOT a gate).
7. Add nightly loom job (separate workflow file, scheduled).

## Success Criteria

- [ ] All unit + property + loom tests green
- [ ] `cargo llvm-cov` reports ≥90% line + ≥90% branch on `checks/ddos/**`
- [ ] No `sleep` >100 ms in any test; all use `MockClock`
- [ ] Loom test discovers no concurrency bugs after `LOOM_MAX_PREEMPTIONS=3`
- [ ] CI publishes coverage HTML as artifact on every PR
- [ ] No coverage theatre: zero tests on `Display`/`Debug`/`Default` derives
- [ ] `cargo clippy --all-targets -- -D warnings` clean

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| `loom` slow (combinatorial explosion) | Cap with `LOOM_MAX_PREEMPTIONS=3`; run in nightly only, not PR |
| Property tests flaky | `proptest!` is deterministic per seed; capture seed on failure with `proptest-derive` |
| Coverage tooling missing on CI runners | `cargo-llvm-cov` install step in workflow; falls back to `tarpaulin` if needed |
| Mocking async Redis is fiddly | Use `redis-test` crate's mock connection or hand-rolled `mockall::mock!` per pattern in `rate_limit/store/redis.rs` tests (read for reference) |
| Coverage drift over time | Nightly artifact + dashboard; team review when drops below 88% |
