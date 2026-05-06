# Brainstorm — FR-005 DDoS Protection (Production-Ready)

**Date:** 2026-05-05
**Status:** Design approved (items 1, 2, 3, 5 confirmed; item 4 dropped — no hard CI coverage gate)
**Source FR:** `analysis/requirements.md` § FR-005
**Target crate:** `crates/waf-engine/src/checks/ddos/` (new)

---

## 1. Problem Statement

FR-005 mandates: **burst detection + auto-block + per-tier threshold + per-tier fail-mode**, on a Rust Pingora-based reverse proxy already serving FR-004 rate-limiting. Production-ready bar: deterministic under load, cluster-coherent, observable, hot-reloadable.

Gap vs FR-004: FR-004 is per-IP/per-session budget. FR-005 needs aggregation axes FR-004 cannot express (global per-tier, per-device-fingerprint) and produces side-effects (auto-ban, risk escalation), not just verdicts.

---

## 2. Decisions Locked (from Q&A)

| # | Decision | Rationale |
|---|----------|-----------|
| Q1 | **L7 only** | Pingora is L7; L4 belongs to kernel/upstream LB. Out-of-scope avoids false promises. |
| Q2 | **Per-device-fp + Per-tier global** (additive to FR-004 per-IP) | Catches botnet flood (per-tier) + IP-rotation evasion (per-fp). Skips per-ASN/per-route as YAGNI for now. |
| Q3 | **Ban + risk bump** | Hard ban for sustained burst (TTL-escalating); risk bump feeds challenge engine for borderline cases. |
| Q4 | **Line+branch ≥90% target + scenario suite** (not CI-gated) | Strong target without blocking PRs on flaky coverage drift. |

---

## 3. Module Layout

```
crates/waf-engine/src/checks/ddos/
├── mod.rs                  # public surface: DdosCheck, DdosConfig
├── config.rs               # TOML schema
├── reload.rs               # ArcSwap<DdosConfig> hot-reload
├── detector/
│   ├── mod.rs              # Detector trait + DetectorVerdict enum
│   ├── per_ip.rs           # delegates to existing rate_limit primitives
│   ├── per_fp.rs           # device-fp keyed counter
│   └── per_tier.rs         # global per-tier RPS counter
├── store/
│   ├── mod.rs              # CounterStore trait
│   ├── memory.rs           # DashMap<Arc<str>, AtomicU64>
│   └── redis.rs            # cluster-shared via Lua INCR+EXPIRE
├── action/
│   ├── mod.rs              # ActionExecutor trait
│   ├── ban.rs              # writes to access::ip_table with TTL escalation
│   └── risk.rs             # bumps cumulative risk via aggregator
├── degrade.rs              # FailMode enforcement on overload
└── check.rs                # Check trait impl — orchestrates detector → action
```

**Why separate from `rate_limit/`:** SRP — FR-004 is per-key budget; FR-005 is burst → side-effect. Mixing bloats FR-004 hot path.

---

## 4. Design Patterns

| Pattern | Where | Why |
|---------|-------|-----|
| **Strategy** | `Detector` trait (per_ip / per_fp / per_tier) | Independently swappable + testable; pipeline runs in declared order. |
| **Chain of Responsibility** | `DdosCheck::check()` short-circuits on first ≥Block verdict | Cheap detectors first; matches existing `Check` trait pattern. |
| **Command** | `ActionExecutor` (Ban, RiskBump, Both) | Decouples detection from side-effect. |
| **Observer** | Detector emits to `metrics::DDOS_BURST` + `tracing::warn!` | Telemetry decoupled from logic. |
| **Atomic Swap (ArcSwap)** | `DdosRegistry` for hot-reload | Same idiom as access/relay/device_fp. Zero-lock readers. |
| **Token-Bucket / Sliding-Window** (reused from FR-004) | `algo::*` shared via `pub(crate)` | DRY — burst = token bucket with `capacity = burst_threshold`. |
| **Circuit Breaker** | `degrade::OverloadGuard` | Production must not amplify overload. |

---

## 5. Detector Math

Each detector returns: `Allow | SoftAnomaly(score) | HardBurst(reason)`.

- **per_ip** — delegates to existing `rate_limit::store::Decision`. No new math.
- **per_fp** — sliding-window counter keyed on `device_fp_hash` from `ctx.device_fp`. Tier-configured threshold (e.g. Critical 30/10s, Medium 200/10s).
- **per_tier** — single global counter per tier. Threshold: `>3× moving-median of last 60s`, fallback to absolute cap on cold start (baseline=0).

**Auto-block escalation (per offender, 1h offense window):**

| Offense # | Ban TTL | Risk delta |
|-----------|---------|------------|
| 1 | 60s | +30 |
| 2 | 5m  | +50 |
| 3+ | 1h | clamp → max |

Tracked in `action::ban` via per-key offense counter (memory store, GC'd).

---

## 6. Concurrency & Hot-Path Discipline

- **Lock-free counter:** `DashMap<Arc<str>, AtomicU64>` — no `Mutex` in hot path.
- **GC task:** dedicated `tokio::task` every `gc_interval` (5s default), drops expired entries. `max_keys` cap + LRU on overflow.
- **Cluster mode:** Redis `EVAL` Lua for atomic INCR+EXPIRE (single round-trip).
- **Hot-reload:** `ArcSwap<DdosConfig>` — readers `Arc::clone` only.
- **Allocation:** keys built from pre-hashed IP/fp bytes + 4 interned tier strings — zero `String` per request.

---

## 7. Tier × FailMode Matrix (FR-036/037/038)

| Tier | Detector overload | Backend overload |
|------|-------------------|------------------|
| Critical | **Block** (fail-close) | **503 + retry-after** |
| High | **Block** | **503** |
| Medium | **Allow + warn** (fail-open) | Allow, drop logs if overloaded |
| CatchAll | **Allow** | Allow |

Implemented in `degrade::resolve(tier_policy, error_kind) -> Action`.

---

## 8. Test Strategy (≥90% line+branch target)

### 8.1 Tooling
- `cargo-llvm-cov --branch --html -p waf-engine -- --include-pattern "checks/ddos/**"`
- Coverage **reported** in CI artifact, **not gated** (per item-4 drop).

### 8.2 Test Pyramid

| Layer | Tool | Target | Examples |
|-------|------|--------|----------|
| **Unit** | `#[cfg(test)]` | every detector + store + action | window math at n−1 / n / n+1; offense-table escalation; TTL expiry; GC removal |
| **Property** | `proptest` | counter math + threshold logic | `forall threshold, requests: detector(n<threshold)==Allow` (10k cases); risk monotonicity |
| **Concurrency** | `loom` (`#[cfg(loom)]`) | memory store atomics | concurrent `incr_get` from N workers — no lost updates / torn reads |
| **Integration** | `tokio::test` + mock ctx | check.rs orchestration | per-IP burst → ban; per-fp burst across rotating IPs; per-tier burst → degrade; reload mid-burst preserves state |
| **Scenario** | `tests/ddos_scenarios/` | full proxy + synthetic load | (a) flat 5k rps no-block, (b) single-IP flood → ban <200ms, (c) 1000-IP botnet same fp → fp-ban, (d) tier-wide burst → fail-open Medium / fail-close Critical, (e) Redis-down → fail-mode honored |
| **Chaos** | tokio table tests | degrade.rs paths | inject `StoreUnavailable` / `BackendOverload` / `ConfigStale`, assert per-tier action |
| **Soak** (nightly) | k6 / goose | leak detection | 30-min sustained 5k rps; assert RSS stable, key count bounded |

### 8.3 Coverage Tactics — the 10% That Usually Leaks

1. **Error branches** — every `?` and `match err` in `store::redis` must have an injected-failure test (`mockall` for `RedisStore`).
2. **Time boundaries** — wrap `SystemTime::now()` behind `Clock` trait; inject fixed timestamps. Cover exact-tick rollover, negative skew.
3. **ArcSwap reload race** — 100 readers + concurrent swap, assert all complete with consistent (old or new) view.
4. **Default-impl fallthroughs** — `device_fp` absent ⇒ `per_fp` skipped, no panic.
5. **Risk saturation** — bump >100 must clamp.
6. **TTL escalation table** — `rstest` parametric over all 3 tiers.

### 8.4 Anti-Coverage-Theater
- No tests for `Display` / `Debug` derives.
- No literal log-message assertions.
- No `Default::default()` smoke tests.

### 8.5 Acceptance → Test Mapping

| FR-005 criterion | Verified by |
|------------------|-------------|
| Burst detection | unit + property; scenario (b)(c) |
| Auto-block | integration on `access::ip_table` mutation; scenario (b) |
| Configurable threshold per tier | TOML round-trip + reload test |
| Fail-close / fail-open per tier | chaos table tests on `degrade.rs` |

---

## 9. Observability

- Prom metrics: `ddos_burst_total{detector,tier}`, `ddos_ban_active`, `ddos_counter_keys`, `ddos_store_errors_total`.
- Structured log per action: `request_id, ts_ms, ip, device_fp, detector, threshold, action, ttl_s` → feeds FR-032 audit.
- Dashboard widget (FR-029/030): live ban list + top burst sources.

---

## 10. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| False-positive ban on legit spike (CDN cache miss storm) | FR-008 allowlist evaluated **before** ddos check; per-tier baseline learns from 60s moving window. |
| Memory blow-up under spoofed-source flood (millions of unique keys) | `max_keys` cap + LRU evict + `/24` aggregation fallback at >80% capacity. |
| Cluster counter divergence | Redis backend with Lua atomic; local-mode is per-node best-effort, documented. |
| Detector latency budget breach | Per-detector p99 budget: per_ip <50µs, per_fp <80µs, per_tier <30µs. Bench gate. |
| GC starvation under burst | Dedicated tokio task with cooperative yield; never blocks request task. |

---

## 11. Trade-offs (Brutal Honesty)

- **Skipped:** L4, per-ASN, per-route, ML-based anomaly. Each adds weeks; documented attack matrix is covered without them.
- **90% coverage is target, not theater.** Branch coverage matters more than line; scenario tests catch what coverage can't.
- **Biggest risk:** per-tier global counter requires Redis in cluster mode. Local-only mode = per-node slice. Document, don't hide.

---

## 12. Success Metrics

- All 4 FR-005 acceptance criteria pass automated tests.
- Coverage report: `ddos/**` ≥90% line, ≥90% branch (target, not gate).
- Scenario suite (a)–(e) green in CI.
- p99 detector overhead <200µs under 5k rps.
- Soak nightly: 30-min run, RSS drift <5%, key count bounded.

---

## 13. Next Steps

1. Run `/ck:plan` to decompose into phases (config + store, detectors, actions, degrade, tests, integration).
2. Open implementation worktree.
3. Phase 1 PR: skeleton + memory store + per_ip detector (reuses FR-004) — proves wiring.
4. Phase 2+ PRs: per_fp, per_tier, action::ban, degrade, scenario suite.

---

## 14. Unresolved Questions

1. **Redis as hard dep for cluster mode** — confirm with deploy team that Redis is acceptable infra (or do we need an alternative like in-cluster gossip via existing Raft-lite QUIC?).
2. **Baseline learning window** (60s moving median) — tune via real traffic post-deploy; default ok for v1.
3. **Whitelist override path** — confirm FR-008 allowlist runs before FR-005 in the 16-phase pipeline (likely yes, but verify with `engine.rs` ordering during `/ck:plan`).
