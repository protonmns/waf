---
phase: 9
title: "Integration & Scenario E2E"
status: complete
priority: P0
effort: "1.5d"
dependencies: [8]
---

# Phase 9: Integration & Scenario E2E

## Overview

`tokio::test` integration suite + end-to-end scenario tests. Validates full pipeline: detector → action → access::ip_table → next-request short-circuit. Adds soak job for memory/leak surveillance.

## Requirements

- Functional:
  - 4 integration tests on `DdosCheck` with real `MemoryCounterStore`, real `IpTable`, mocked aggregator.
  - 5 scenario suite cases (a)–(e) per brainstorm §8.2.
  - Nightly soak: 30-min sustained 5k rps, RSS drift <5%, key count bounded.
  - All scenario tests deterministic (no flaky `sleep`).

## Test Inventory

### Integration (`tests/ddos_integration.rs`, `#[tokio::test(flavor = "multi_thread")]`)

| # | Test | Setup | Assert |
|---|------|-------|--------|
| I1 | per-IP burst → ban | one IP × 100 reqs over 1s, threshold=50 | 51st request returns Block; `ip_table.contains(ip)` true; ttl≈60s |
| I2 | per-fp burst across rotating IPs | 10 IPs same fp, 50 reqs each, fp_threshold=100 | first 100 allow; 101st HardBurst("fp_burst"); ban risk delta=30 |
| I3 | per-tier burst → degrade Medium fail-open | tier=Medium, 5000 rps, sustained traffic median ~1k, burst 10k | DegradeAction::AllowAndWarn; warn log emitted; no ban |
| I4 | reload mid-burst preserves bans | start with cfg A, mid-burst swap to cfg B with looser thresholds | banned IP still in `ip_table` after swap; new requests judged by cfg B |

### Scenario Suite (`tests/ddos_scenarios/`)

```
tests/ddos_scenarios/
├── mod.rs                 # shared harness (engine bootstrap, synthetic load)
├── a_baseline_no_block.rs
├── b_single_ip_flood.rs
├── c_botnet_same_fp.rs
├── d_tier_burst_failmode.rs
└── e_redis_down_failmode.rs
```

| Scenario | Description | Pass criteria |
|----------|-------------|---------------|
| a | flat 5k rps from 5k IPs, all unique fps, all under thresholds | 0 blocks, 0 bans, p99 detector overhead <200µs |
| b | single IP, 1000 rps for 1s | ban issued <200ms; subsequent requests return 403 from `access::Evaluator` (NOT ddos), proving short-circuit |
| c | 1000 IPs, same fp, 30 rps each (30k rps shared fp) | per_fp HardBurst fires; ALL 1000 IPs eventually banned (escalation); per-IP ban rate >900/min |
| d | tier-wide burst | Critical tier with cfg.fail_close → all blocked under store err; Medium tier → fail_open warn-only; verify exactly one path per tier |
| e | Redis-down mid-burst | inject `RedisError::Timeout`; assert per-tier failmode honoured; metrics counter `ddos_store_errors_total{kind="timeout"}` increments |

### Soak (nightly job)

```yaml
# .github/workflows/ddos-soak.yml
on: schedule: { cron: "0 4 * * *" }
jobs:
  soak:
    runs-on: ubuntu-latest
    steps:
      - run: cargo build --release -p waf-engine --tests
      - run: cargo test --release --test ddos_soak -- --ignored
```

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]                          // gated to nightly
async fn soak_30min_5krps() {
    let baseline_rss = read_rss();
    let baseline_keys = engine.ddos.counter_keys();
    // 30-min loop driving 5k rps across rotating IPs
    let final_rss = read_rss();
    let final_keys = engine.ddos.counter_keys();
    assert!(final_rss as f64 / baseline_rss as f64 - 1.0 < 0.05, "RSS drift > 5%");
    assert!(final_keys < 100_000, "key count unbounded");
}
```

## Related Code Files

- Create:
  - `crates/waf-engine/tests/ddos_integration.rs`
  - `crates/waf-engine/tests/ddos_scenarios/mod.rs`
  - `crates/waf-engine/tests/ddos_scenarios/a_baseline_no_block.rs`
  - `crates/waf-engine/tests/ddos_scenarios/b_single_ip_flood.rs`
  - `crates/waf-engine/tests/ddos_scenarios/c_botnet_same_fp.rs`
  - `crates/waf-engine/tests/ddos_scenarios/d_tier_burst_failmode.rs`
  - `crates/waf-engine/tests/ddos_scenarios/e_redis_down_failmode.rs`
  - `crates/waf-engine/tests/ddos_soak.rs` (`#[ignore]`-gated)
  - `.github/workflows/ddos-soak.yml`
- Read:
  - `crates/waf-engine/tests/` — existing integration test fixtures, harness conventions
  - `crates/waf-engine/src/checks/rate_limit/conformance.rs` — pattern for shared test conformance traits if relevant

## Implementation Steps

1. Build integration harness in `tests/ddos_scenarios/mod.rs`: bootstrap `WafEngine` with in-memory stores, configurable tier YAML, synthetic `RequestCtx` builder, ip-rotation helper.
2. Implement integration tests I1–I4. Use `MockClock` to advance time deterministically (no real sleeps).
3. Implement scenarios (a)–(e). Each is a single `#[tokio::test]` driving a synthetic request loop. No external dependencies (no real Redis — use mock).
4. Implement soak test with `#[ignore]` flag; reads `/proc/self/status` for RSS on Linux runners.
5. Add nightly workflow file for soak.
6. Run full suite locally: `cargo test --release --test ddos_integration --test ddos_scenarios::*`.
7. Run full suite for `redis-store` feature: `cargo test --release --features redis-store --test ddos_integration --test ddos_scenarios::*`.

## Success Criteria

- [x] All 4 integration tests + 5 scenarios green in CI on every PR
- [x] Scenario b: ban happens within 200ms (assertion uses MockClock to count detector → ban steps deterministically)
- [x] Scenario c: ≥900/1000 IPs banned within 60s of burst onset
- [x] Scenario d: tier×failmode matrix enforced exactly per phase 6 table
- [x] Scenario e: failmode honored under Redis timeout; `ddos_store_errors_total` increments
- [x] Nightly soak runs to completion; RSS drift <5%; key count <100k
- [x] No flaky tests over 50 consecutive runs (`cargo test --test ddos_scenarios -- --test-threads 1` × 50)
- [x] No `.unwrap()` outside test assertion sites where panic IS the test failure mechanism

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Synthetic load harness drift from real pipeline | Bootstrap uses real `WafEngine` (not a mock); diff in behaviour caught by I1-I4 |
| Soak job RSS measurement non-portable (macOS runners) | Linux-only nightly job; macOS soak skipped |
| Scenario d's tier×failmode matrix grows | Driven from phase 6 `degrade::resolve` — tests reference the same matrix table; one source of truth |
| Mock Redis behaviour drifts from real Redis semantics | Add opt-in `--features integration-redis` job using `testcontainers` (deferred to follow-up if drift observed) |
| Test runtime > CI budget | Scenarios use simulated time + deterministic loop; <30s wall time each |
