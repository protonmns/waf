---
phase: 1
title: "Config & Memory Store"
status: complete
priority: P0
effort: "1d"
dependencies: []
completedAt: "2026-05-05T12:31:00Z"
---

# Phase 1: Config & Memory Store

## Overview

Bootstrap `checks/ddos/` module: TOML/YAML config schema, `CounterStore` trait, in-process `DashMap<Arc<str>, AtomicU64>` backend, ArcSwap-based runtime snapshot, GC tokio task. Mirrors `checks/rate_limit/` layout — readers cite that module for conventions.

## Requirements

- Functional:
  - YAML schema with `enabled`, `hot_reload`, per-tier thresholds (`per_fp_threshold`, `per_fp_window_s`, `per_tier_threshold`, `per_tier_window_s`), `gc_interval_s`, `max_keys`, optional `redis` block (parsed but unused until phase 4).
  - `CounterStore` trait: `incr_get(key, ttl_ms, now_ms) -> Result<u64>` + `purge_expired() -> usize`.
  - In-memory backend with TTL eviction, `max_keys` LRU cap.
  - `ArcSwap<DdosConfig>` runtime snapshot.
- Non-functional:
  - `incr_get` p99 < 50µs (Criterion bench gate).
  - Zero `String` alloc per hit on hot path; key passed as `&str`.
  - GC task runs on tokio handle if available; falls back to manual `purge_expired`.

## Architecture

Mirror `checks/rate_limit/{mod.rs,config.rs,reload.rs,store/{mod.rs,memory.rs}}` 1:1 — consistency wins over novelty. `DdosConfig` carries only validated runtime state (no DTO leaks).

```rust
// store/mod.rs
#[async_trait]
pub trait CounterStore: Send + Sync {
    async fn incr_get(&self, key: &str, ttl_ms: i64, now_ms: i64) -> anyhow::Result<u64>;
    fn incr_get_blocking(&self, key: &str, ttl_ms: i64, now_ms: i64) -> anyhow::Result<u64> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.incr_get(key, ttl_ms, now_ms))
        })
    }
    async fn purge_expired(&self, now_ms: i64) -> anyhow::Result<usize>;
}

// store/memory.rs
pub struct MemoryCounterStore {
    map: Arc<DashMap<Arc<str>, Entry>>, // Entry { count: AtomicU64, expires_ms: i64 }
    max_keys: usize,
}
```

GC tokio task: `interval.tick()` every `gc_interval_s`, calls `purge_expired(now)`, then if `len > max_keys` drops oldest by `expires_ms`.

## Related Code Files

- Create:
  - `crates/waf-engine/src/checks/ddos/mod.rs`
  - `crates/waf-engine/src/checks/ddos/config.rs`
  - `crates/waf-engine/src/checks/ddos/reload.rs`
  - `crates/waf-engine/src/checks/ddos/store/mod.rs`
  - `crates/waf-engine/src/checks/ddos/store/memory.rs`
  - `crates/waf-engine/benches/ddos_counter.rs`
- Modify:
  - `crates/waf-engine/src/checks/mod.rs` — `pub mod ddos;`
  - `crates/waf-engine/Cargo.toml` — add `[[bench]] name = "ddos_counter"` (criterion already present).

## Implementation Steps

1. Create `ddos/mod.rs` with `pub mod config; pub mod reload; pub mod store;` and `pub struct DdosConfig` (per-tier `DdosTierCfg { per_fp_threshold, per_fp_window_s, per_tier_threshold, per_tier_window_s }`, plus `gc_interval_s`, `max_keys`).
2. Implement `config.rs` mirroring `rate_limit/config.rs`: `DdosDocument`/`DdosFileConfig` DTO, `serde(deny_unknown_fields)`, `from_yaml_str`, `from_path`, `validate`, `into_runtime`. Schema version = 1.
3. Implement `store/mod.rs` with `CounterStore` trait (signatures above).
4. Implement `store/memory.rs` with `DashMap<Arc<str>, Entry>`, atomic `incr_get`, GC task spawned via `tokio::runtime::Handle::try_current()` (same pattern as `rate_limit::store::memory::MemoryStore::new`).
5. Implement `reload.rs` mirroring `rate_limit/reload.rs` — parent-dir `notify` watcher, debounce 200 ms, fail-soft retain previous snapshot.
6. Add Criterion bench `benches/ddos_counter.rs` with one group: `incr_get_hot` (single key, 1M hits) — assert p99 < 50µs locally.
7. Run `cargo check -p waf-engine`, `cargo clippy -p waf-engine -- -D warnings`, `cargo test -p waf-engine ddos::`, `cargo bench -p waf-engine --bench ddos_counter -- --quick`.

## Success Criteria

- [x] `cargo check -p waf-engine` clean
- [x] `cargo clippy -p waf-engine --all-targets -- -D warnings` clean
- [x] `cargo test -p waf-engine ddos::config ddos::store` green (20 tests)
- [x] Empty YAML → inert config (no tiers configured)
- [x] Unknown field rejected; schema_version mismatch rejected
- [x] `cargo bench --bench ddos_counter -- --quick` p99 < 50µs on M-class hardware (achieved: ~36ns hot, ~287ns cold)
- [x] No `.unwrap()` / `.expect()` outside `#[cfg(test)]`
- [x] Hot-reload integration test (write → swap within 3s; bad YAML retains snapshot) passes

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| GC starvation under sustained burst | GC runs on dedicated tokio task with `cooperative yield`; never on request task |
| `DashMap` shard contention on hot key | Phase 1 measures via Criterion bench; if breaching budget, switch to sharded `[AtomicU64; N]` keyed by `hash % N` |
| OOM on spoofed-source flood | `max_keys` cap with LRU evict in GC pass; documented `/24` aggregation fallback deferred to phase 4 if observed |
| Drift from `rate_limit/` conventions | PR reviewer cross-checks file-by-file with `rate_limit/` |
