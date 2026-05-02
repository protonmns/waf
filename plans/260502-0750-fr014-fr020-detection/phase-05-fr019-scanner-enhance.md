---
phase: 05
title: "FR-019 — Scanner / Recon Enhance (response status + endpoint enum + OPTIONS)"
status: pending
priority: P1
effort: 1d
dependencies: [00]
branch: feat/fr-019-scanner-recon
fr: FR-019
---

## Overview

Existing `scanner.rs` (302 LOC, verified `crates/waf-engine/src/checks/scanner.rs:1-302`) detects scanners by User-Agent only. Add 3 new heuristics: rapid 4xx ratio per IP, endpoint-enumeration pattern (many distinct paths short window), and OPTIONS-method abuse. The 4xx-ratio heuristic requires response data, so reuse the `ResponseCheck` trait introduced in Phase 00 (Decision C).

## Acceptance Criteria (from analysis/requirements.md:59)

> Error Scanning / Recon — Rapid 4xx/5xx patterns, endpoint enumeration, OPTIONS method abuse

## Detection Rules (synthesis: existing UA + researcher-02-style stateful counters; OWASP CRS 913xxx)

1. **UA scanner detection** — already covered (32 patterns in `SCANNER_UA_SET`)
2. **NEW: 4xx response ratio** — sliding window per `client_ip`: track last 50 responses; if ≥30 are 4xx in last 60s → DETECT
3. **NEW: Endpoint enumeration** — sliding window per `client_ip`: track distinct paths in last 60s; if `distinct >= 30` → DETECT
4. **NEW: OPTIONS abuse** — count OPTIONS requests per `client_ip` in last 60s; threshold 20 → DETECT
5. **NEW: 5xx-induced recon** — 5xx ratio ≥ 50% over 50 responses → DETECT (less common but high signal)

## Files to Modify

- `crates/waf-engine/src/checks/scanner.rs` (302 → est. ~280 LOC after split; or split into:)

## Files to Create (REQUIRED — scanner.rs already 302 LOC will exceed 200 with new code)

- `crates/waf-engine/src/checks/scanner_state.rs` — `ScannerState` struct with `dashmap::DashMap<IpAddr, IpRecord>` where `IpRecord = parking_lot::Mutex<RingBuffer>` (≤120 LOC)

Keep `scanner.rs` itself slim by moving stateful logic to `scanner_state.rs`.

## DefenseConfig Fields Used

- `defense_config.scan` (existing — gate)
- New tunables (add in this phase, NOT Phase 00, since scoped to scanner): `scanner_4xx_window_secs: u64=60`, `scanner_4xx_threshold: usize=30`, `scanner_endpoint_enum_threshold: usize=30`, `scanner_options_threshold: usize=20`

(All `#[serde(default = "...")]`. Do not bunch into Phase 00 to keep stub PRs lean — but these MUST be added on this branch alongside the impl.)

## Implementation Steps

1. Create `scanner_state.rs`:
   - `pub struct ScannerState { per_ip: Arc<DashMap<IpAddr, parking_lot::Mutex<IpRecord>>> }`
   - `IpRecord` carries: `VecDeque<(Instant, u16 /*status*/)>`, `HashSet<String /*path*/>` w/ insertion-time eviction, `VecDeque<Instant>` for OPTIONS
   - Methods: `record_response(ip, status, path)`, `record_options(ip)`, `is_4xx_burst(ip, window, threshold) -> bool`, `is_endpoint_enum(ip, window, threshold) -> bool`, `is_options_abuse(ip, window, threshold) -> bool`, `prune_older_than(cutoff)`
2. Modify `scanner.rs`:
   - `ScannerCheck` gains `state: Arc<ScannerState>`
   - `Check::check` (request-phase): keep UA logic; ADD: count OPTIONS via `state.record_options`, check `is_options_abuse` → DETECT; check `is_endpoint_enum` (path already known at request time) → DETECT
   - Implement `ResponseCheck::on_response` (Phase 00 trait): `state.record_response(ctx.client_ip, status, ctx.path.clone())` then check `is_4xx_burst` / `is_5xx_burst`. If true, **the next** request from this IP triggers DETECT via state lookup in `Check::check`. (Or: emit decision via side channel — discuss in PR review.)
3. Spawn background pruner: `tokio::spawn` task in `ScannerCheck::new` that runs every 30s, calls `state.prune_older_than(Instant::now() - 5min)`. Use `tokio::sync::Notify` for graceful shutdown.
4. Add tests (≥25 — see matrix); use `tokio::time::pause()` + `advance` for deterministic time
5. `cargo fmt && cargo clippy -p waf-engine -- -D warnings && cargo test -p waf-engine scanner`
6. Update bench `crates/waf-engine/benches/scanner.rs` (extend existing or create)

## Test Matrix (target ≥25 tests)

| # | Vector | Expect |
|---|---|---|
| 1-3 | UA = "sqlmap/1.0", "Nikto/2.5", "Burp Suite Pro" | DETECT (existing) |
| 4 | UA = "Mozilla/5.0 ..." | None |
| 5 | record 30 × 4xx in 60s, then request → DETECT | DETECT (4xx burst) |
| 6 | record 30 × 4xx over 120s (slow) → None | None (window expires) |
| 7 | record 30 × 200 → next request | None |
| 8 | 30 distinct paths in 60s | DETECT (endpoint enum) |
| 9 | 30 distinct paths over 120s | None |
| 10 | same path 30 times in 60s | None (1 distinct) |
| 11 | 20 OPTIONS in 60s | DETECT |
| 12 | 19 OPTIONS in 60s | None |
| 13 | 25 5xx in 50 responses → 5xx burst | DETECT |
| 14 | `defense_config.scan=false` + scanner UA | None |
| 15 | pruner removes records older than 5min | state count == 0 after prune |
| 16-20 | per-IP isolation — state for IP A doesn't leak to IP B | None for B |
| 21 | concurrent record from 100 tokio tasks | no panic, state consistent |
| 22 | empty state (cold start) | None for any check |
| 23 | OPTIONS for `/`-only request | counted but not other-method-counted |
| 24 | OPTIONS abuse + UA scanner = 1 detection (first wins) | DETECT (early-return) |
| 25 | path includes query string — only path key counted in enum | dedup by path-without-query |

## Bench

`crates/waf-engine/benches/scanner.rs`:
- `scanner_clean_ua`: < 30µs p99
- `scanner_attack_ua`: < 50µs p99
- `scanner_state_record_response`: < 20µs p99 (DashMap insert + VecDeque push)
- `scanner_state_query_burst`: < 30µs p99
- **Aggregate budget per check: p99 < 200µs**

## False Positive Mitigation

- **Crawlers (Googlebot, Bingbot)**: legitimate enumeration. Mitigation: whitelist their UA OR raise endpoint_enum_threshold per `client_ip` if reverse-DNS matches `*.google.com` (deferred — out of scope v1; documented).
- **CORS preflight OPTIONS**: many legit requests send OPTIONS. Threshold 20/min per IP is high enough to not trip on normal SPA usage.
- **Health checkers / monitoring**: same path repeated → enum threshold uses *distinct* paths so health-check loops don't trigger.
- **High-traffic shared NAT**: many users behind one IP can hit thresholds. Mitigation: combine with FR-010 device fingerprint (out of scope here; future).

## Branch + PR

- Branch: `feat/fr-019-scanner-recon`
- Squash commit: `feat(detection): FR-019 scanner recon (4xx burst, endpoint enum, OPTIONS abuse)`
- `gh pr create --base main --head feat/fr-019-scanner-recon --title "feat(detection): FR-019 scanner recon" --reviewer lotus`

## Coverage Requirement

`crates/waf-engine/src/checks/scanner.rs` + `scanner_state.rs`: combined ≥90% in Docker.

## Definition of Done

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test -p waf-engine scanner` ≥25 tests passing
- [ ] Coverage gate passes
- [ ] Bench p99 < 200µs
- [ ] PR opened, CI green

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `ScannerState` memory growth unbounded if pruner fails | Medium | High | Hard cap `per_ip` map at 100k entries; LRU evict on overflow |
| `ResponseCheck` wiring to checker.rs incomplete (depends on Phase 07's pipeline) | High | High | Phase 05 ships request-side + state machine; response-hook actual call site lands in Phase 07 alongside FR-018 |
| Pruner task leaks if `ScannerCheck` dropped without explicit shutdown | Low | Low | Wrap in `Arc<Notify>`; Drop impl notifies |
| Test flakiness with real `Instant::now()` | High | Medium | Use `tokio::time::pause()` everywhere |

## Rollback

Single squash commit; `git revert` removes scanner_state.rs and reverts scanner.rs to UA-only. Phase 00 trait remains (no impls). No persistent state.

## Note on shared-file edit

This phase modifies `scanner.rs` (existing file). Since it's the ONLY phase touching that file, no conflicts arise with siblings 01-04, 06, 07. Ownership: this phase exclusively owns `scanner.rs` and `scanner_state.rs`.

## Red Team Fixes (applied 2026-05-02)

Findings #6, #14. See `plan.md ## Red Team Review`.

### Finding #6 — DashMap unbounded → IPv6-rotating attacker OOMs WAF
Plan mentions LRU only in Risks row, never actually implemented. An attacker rotating /64 IPv6 addresses can insert millions of unique keys.

- **Add** to `ScannerState` struct in step 1:
  > Wrap `per_ip` in a bounded LRU: replace `Arc<DashMap<IpAddr, ...>>` with `Arc<parking_lot::Mutex<lru::LruCache<IpAddr, IpRecord>>>` with `cap = 100_000` (configurable via `defense_config.scanner_max_ips`). NOTE: `lru` crate is NOT in workspace today — **either add it, OR implement a manual LRU using DashMap + atomic counter + size-trigger purge**. Recommend manual approach to avoid new dep:
  > ```rust
  > pub struct ScannerState {
  >     per_ip: Arc<DashMap<IpAddr, parking_lot::Mutex<IpRecord>>>,
  >     max_entries: usize, // default 100_000
  > }
  > // On record_*, after insert: if per_ip.len() > max_entries, drop oldest 10%
  > // (sample N random keys, evict the one with oldest last-touched timestamp)
  > ```
- **Add test**: `scanner_state_caps_at_max_entries` — insert 100_001 distinct IPs, assert `per_ip.len() <= max_entries`.

### Finding #14 — `tokio::spawn` from `Check::new` (sync) leaks JoinHandles
`WafEngine::new` is sync (verified `crates/waf-engine/src/engine.rs:52,96-102`). Calling `tokio::spawn` from inside `Check::new` requires a runtime context that may not exist (test fixtures, sync init). Worse: the JoinHandle is dropped → task is detached → no graceful shutdown.

- **Replace** Implementation Step 3:
  > **Do NOT spawn from `ScannerCheck::new`.** Add a free function `pub fn spawn_pruner(state: Arc<ScannerState>, shutdown: Arc<tokio::sync::Notify>) -> tokio::task::JoinHandle<()>`. The engine bootstrap (`crates/waf-engine/src/engine.rs::new` or its async counterpart) calls this AFTER constructing the check, holding the JoinHandle for graceful shutdown. If no async runtime is available (e.g. test), pruner is simply not spawned — state grows until process exit (acceptable for tests).
- **Add to Risks**: "Pruner-start coupling — engine bootstrap MUST call `spawn_pruner` for each stateful check; missed call = unbounded growth. Mitigated by Phase 08 e2e test that runs for 10min and asserts state stays bounded."

### Lower-severity (deferred)
- ~~`tokio::time::pause()` doesn't affect `std::time::Instant`~~ → **RESOLVED (Validation Q7)**: use injected `Clock` trait declared in Phase 00. `ScannerState` holds `Arc<dyn Clock>`; replace ALL `Instant::now()` calls with `self.clock.now()`. Tests use `MockClock` from Phase 00 `test_clock` module.

## Validation Updates (Session 1 — 2026-05-02)

### `Clock` trait wiring (Q7)
- **Modify** `ScannerState` struct (step 1):
  ```rust
  pub struct ScannerState {
      per_ip: Arc<DashMap<IpAddr, parking_lot::Mutex<IpRecord>>>,
      max_entries: usize,
      clock: Arc<dyn Clock>,
  }
  impl ScannerState {
      pub fn new(max_entries: usize, clock: Arc<dyn Clock>) -> Self { ... }
  }
  ```
- All `Instant::now()` → `self.clock.now()`.
- `IpRecord` timestamp fields stay `std::time::Instant` (returned by Clock).
- Tests construct `ScannerState::new(100_000, Arc::new(MockClock::new()))` and call `clock.advance(Duration::from_secs(60))` to simulate window passage — no real sleeps, no tokio runtime dependency.
