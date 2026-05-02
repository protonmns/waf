---
title: "P0 Detection Suite — FR-014..FR-020"
description: "7 production-grade WAF detection checks (XSS, PathTraversal, SSRF, HeaderInjection, BruteForce, Scanner, BodyAbuse) with >=90% per-crate coverage gate, parallel 7-worktree PR flow."
name: "fr014-fr020-detection"
status: active
priority: P1
effort: 9d
branch: main
date: 2026-05-02
blockedBy: []
blocks: []
tags: [waf, detection, security, p0, hackathon]
created: 2026-05-02
---

## Goal

Ship 7 production P0 detection checks (FR-014..FR-020) for prx-waf with extensible trait architecture, >=90% per-crate test coverage, no host-toolchain pollution (Docker-only), and one squash-merged PR per FR developed in parallel via git worktrees. Internal hackathon target — production-grade, not POC.

## Architectural Decisions

| # | Decision | Choice | Why |
|---|---|---|---|
| A | Conflict-prevention | **Phase-0 framework PR merged FIRST owns ALL 7 stub registrations** in `engine.rs::new()` `vec![]` literal (line 96-102), then 7 disjoint FR PRs swap stub → real impl in their own check file only | KISS over `inventory!` macro (R3§Sec2). Phase 00 absorbs the registration burden so FR PRs touch only `crates/waf-engine/src/checks/<check>*.rs`. **Red Team Finding #2 confirmed:** without this, `engine.rs::new()` would be a shared-file conflict point. |
| B | PR ordering | 1 framework + 7 parallel FR + 1 integration = **9 PRs** total | Explicit gate at Phase 0; siblings parallel; integration last to validate cross-checks. |
| C | FR-018 response phase | **Extend existing `Check` trait with default-impl `fn on_response(&self, _ctx: &RequestCtx, _status: u16) {}`** invoked from Pingora `response_filter` callback (`gateway/src/proxy.rs:429`, header+status only — NO body) | **REVISED post-Red-Team (Finding #7).** Avoids parallel pipeline + sync/async mismatch. Default no-op preserves backward compatibility with existing 11 checks. FR-018 + FR-019 override; others ignore. Body inspection (`response_body_filter`) deferred — FR-018 v1 uses status code only (Finding #8). |
| D | Coverage gate | `cargo-llvm-cov 0.8.5` + `awk` parsing fallback per R3§Sec1, gate **>=90% per crate** in CI job `coverage` | Upstream `--fail-under-lines` bug; awk parses TOTAL line. Run in Docker via `Dockerfile.coverage` — no host pollution. |
| E | FR-018 state store | `dashmap` + `parking_lot::Mutex<VecDeque<Instant>>` per `(username_hash, ip)` | Both deps already in workspace (verified `Cargo.toml:52,54`). Async-safe, lock-free reads. |

## Phases

| # | File | Branch | FR | Status | Owner |
|---|---|---|---|---|---|
| 00 | [phase-00-framework-and-coverage.md](phase-00-framework-and-coverage.md) | `feat/fr-frame-detection-framework` | — | code-complete (coverage-baseline deferred) | lotus |
| 01 | [phase-01-fr014-xss-enhance.md](phase-01-fr014-xss-enhance.md) | `feat/fr-014-xss-json-walk` | FR-014 | pending | TBD |
| 02 | [phase-02-fr015-path-traversal-enhance.md](phase-02-fr015-path-traversal-enhance.md) | `feat/fr-015-path-traversal-recursive` | FR-015 | pending | TBD |
| 03 | [phase-03-fr016-ssrf-new.md](phase-03-fr016-ssrf-new.md) | `feat/fr-016-ssrf-detection` | FR-016 | pending | TBD |
| 04 | [phase-04-fr017-header-injection-new.md](phase-04-fr017-header-injection-new.md) | `feat/fr-017-header-injection` | FR-017 | pending | TBD |
| 05 | [phase-05-fr019-scanner-enhance.md](phase-05-fr019-scanner-enhance.md) | `feat/fr-019-scanner-recon` | FR-019 | pending | TBD |
| 06 | [phase-06-fr020-body-abuse-new.md](phase-06-fr020-body-abuse-new.md) | `feat/fr-020-body-abuse` | FR-020 | pending | TBD |
| 07 | [phase-07-fr018-brute-force-new.md](phase-07-fr018-brute-force-new.md) | `feat/fr-018-brute-force` | FR-018 | code-complete (PR stacked on Phase 00) | lotus |
| 08 | [phase-08-integration-and-bench.md](phase-08-integration-and-bench.md) | `feat/fr-frame-integration-tests` | — | code-complete (integrates all 7 FR) | lotus |

Phases 01-07 run in parallel after Phase 00 merges. Phase 08 runs after all 01-07 merge.

## Cross-Cutting Non-Functional Requirements

- p99 < 200µs per check (verified by criterion bench under `crates/waf-engine/benches/<check>.rs`)
- Per-crate line coverage >= 90% (`cargo llvm-cov` in Docker)
- Zero `.unwrap()`/`.expect()` outside `#[cfg(test)]` (CLAUDE.md Iron Rule 1)
- Zero `cargo clippy --workspace --all-targets --all-features -- -D warnings` warnings
- All build/test in Docker only — host `target/` MUST stay untouched (named volume `prx-waf-cov-target`)
- Each new check file <= 200 LOC (CLAUDE.md modularization rule); split into `<check>.rs` + `<check>_patterns.rs` + `<check>_scanners.rs` if needed (mirrors `sql_injection*` triplet)
- All new code must compile with `cargo check`

## Dependencies

| Crate | Status | Used By |
|---|---|---|
| `dashmap = "6"` | Workspace dep (Cargo.toml:52) | FR-018 brute force state |
| `ipnet = "2"` (serde) | Workspace dep (Cargo.toml:54) | FR-016 SSRF CIDR matching, FR-017 X-F2 validation |
| `parking_lot` | Already used (sql_injection_scanners) | FR-018 sliding window mutex |
| `serde_json` | Already used | FR-014, FR-020 JSON walking |
| `regex` (RegexSet) | Already used | All checks |
| `arc_swap` | Already used | All hot-reload configs |

NO new external crates required. NO `inventory` crate added.

## Verify (Definition of Done)

- [ ] All 9 PRs merged to `main` via squash
- [ ] CI green on `main` HEAD: lint + test + build + coverage all pass
- [ ] `cargo llvm-cov --workspace` reports >=90% per crate (waf-engine, waf-common)
- [ ] `crates/waf-engine/tests/p0_detection_acceptance.rs` exercises all 7 attack types end-to-end through `WafEngine::inspect()` (verified at `crates/waf-engine/src/engine.rs:272`)
- [ ] `crates/waf-engine/benches/p0_detection.rs` aggregate p99 < 1ms (sum of all 7 checks)
- [ ] `docs/codebase-summary.md` and `docs/request-pipeline.md` updated
- [ ] CHANGELOG.md has entry per FR
- [ ] No host `~/.cargo/registry` or repo-root `target/` writes during build (Docker-only)

## Out of Scope (Explicit)

- IPv6 SSRF beyond `::ffff:` mapped IPv4 (deferred — researcher-02§FR-016 Bypass scope)
- Zip / Gzip / XML bombs (FR-020 — deferred per researcher-02§FR-020 Bypass1)
- Distributed brute force across N IPs (FR-018 — same-IP only for v1; deferred per researcher-02§FR-018 Bypass1)
- ML-based pattern detection (FR-046, P1 bonus)
- ModSecurity rule conversion for the new checks (FR-022 covers existing CRS only)
- DNS rebinding active mitigation (researcher-02§FR-016 Bypass2 — requires upstream resolver hook; deferred)

## Unresolved Questions

1. ~~FR-018 response hook~~ → **RESOLVED**: Pingora `response_filter` at `crates/gateway/src/proxy.rs:429` exposes status+headers only (NO body). FR-018 v1 uses status-code-only failure detection. Body-aware path via `response_body_filter` (`:472`) deferred.
2. ~~FR-017 Host-vs-SNI matching~~ → **RESOLVED**: SNI not in `RequestCtx`; Phase 04 ships whitelist-only validation against `host_config.host`. Test #7 (SNI mismatch) DROPPED.
3. Coverage scope: benchmarks dir excluded via gate script `--exclude-regex '/tests/|/benches/'`. Awk parser MUST be smoke-tested against real `cargo llvm-cov --lcov` output before Phase 00 merge (Red Team Finding #13).
4. ~~FR-020 `set_recursion_limit`~~ → **RESOLVED (Red Team Finding #3)**: API does NOT exist; only `disable_recursion_limit()` exists (does opposite). Phase 06 ships **iterative walker only** + cap `max_body_size = 64 KiB` to match upstream `BODY_PREVIEW_LIMIT` (`crates/gateway/src/context.rs:10`).
5. ~~Baseline coverage~~ → **RESOLVED (Validation Q5)**: STRICT 90% from Phase 00. Phase 00 first task: measure baseline; second task: raise any waf-engine file < 90% to ≥ 90% by writing tests BEFORE merging Phase 00. Effort 4h → 2d. No FR PR unblocks until Phase 00 hits 90%.

## Red Team Review

### Session — 2026-05-02
**Findings:** 15 (15 accepted, 0 rejected) — distilled from 41 raw findings across 4 reviewers (Security Adversary, Failure Mode Analyst, Assumption Destroyer, Scope & Complexity Critic). All findings backed by `file:line` codebase evidence (passed evidence filter).
**Severity breakdown:** 8 Critical, 7 High, 0 Medium (15 lower-severity findings deferred — see `reports/red-team-260502-0815-*.md`).

| # | Finding | Severity | Disposition | Applied To |
|---|---------|----------|-------------|------------|
| 1 | `WafEngine::evaluate()` does not exist; correct method is `inspect()` (`crates/waf-engine/src/engine.rs:272`) | Critical | Accept | plan.md, phase-08 |
| 2 | `engine.rs::new()` `vec![]` constructor (lines 96-102) is unaccounted; "zero shared-file edits" claim broken without Phase 00 owning all 7 stub registrations | Critical | Accept | Decision A revised; phase-00 |
| 3 | `serde_json::Deserializer::set_recursion_limit` does NOT exist (only `disable_recursion_limit`, opposite semantics — verified docs.rs/serde_json) | Critical | Accept | phase-06; iterative walker only |
| 4 | FR-014 plan reuses `walk_json` from `sql_injection_scanners.rs:58` with no depth cap → same stack-overflow class FR-020 detects | Critical | Accept | phase-01: hard cap depth=64 |
| 5 | `BODY_PREVIEW_LIMIT=64 KiB` (`crates/gateway/src/context.rs:10`) vs Phase 06 `max_body_size=1 MiB` default → oversize check is dead code | Critical | Accept | phase-06: lower default to 64 KiB |
| 6 | DashMap (FR-019) + DashMap+VecDeque (FR-018) unbounded → IPv6-rotating attacker OOMs WAF; Phase 05 LRU only in Risks row, never implemented; Phase 07 has no cap | Critical | Accept | phase-05, phase-07: LRU cap 100K + explicit eviction policy |
| 7 | `ResponseCheck` trait async/sync mismatch + parallel-pipeline over-engineering for 1.5 callers | Critical | Accept | Decision C revised: collapse into `Check` default-impl `on_response()` |
| 8 | FR-018 expects body via `response_filter` but Pingora `response_filter` (`proxy.rs:429`) exposes headers+status only; body needs `response_body_filter` (`proxy.rs:472`) which is unwired | Critical | Accept | phase-07: status-code-only v1; body-regex deferred |
| 9 | `RequestCtx.headers` is `HashMap<String,String>` — duplicate-Host detection (Phase 04 test #22) cannot work | High | Accept | phase-04: drop test #22 |
| 10 | SSRF userinfo bypass `http://google.com@169.254.169.254/` defeats substring extraction; need `url::Url::host_str()` | High | Accept | phase-03: spec `url::Url` parse |
| 11 | FR-018 failure-detection regex `(?i)(invalid\|failed\|incorrect\|denied)` weaponizable as victim-account-lockout primitive | High | Accept | phase-07: status-code-only by default; regex opt-in |
| 12 | `RequestCtx` has no `sni` field; Phase 04 test #7 (SNI mismatch) cannot pass | High | Accept | phase-04: drop test #7; whitelist-only |
| 13 | Coverage gate awk parser cannot match `cargo llvm-cov --lcov` output format → silent exit 0 regardless of coverage | High | Accept | phase-00: smoke-test parser before merge |
| 14 | `tokio::spawn` from `Check::new` (sync constructor) leaks JoinHandles + races on engine reload | High | Accept | phase-05, phase-07: move spawn to engine init |
| 15 | 14d estimate ignores serial sequencing (Phase 05 → 07); real critical path ≈ 5.5d + rebase tax | High | Accept | plan.md effort: 14d → 7d |

### Lower-severity findings deferred (recorded only)
See full reports for context; address opportunistically during implementation:
- `host_whitelist` semantic collision (FR-016 outbound vs FR-017 inbound) — rename one
- Plaintext password as `Option<String>` no `zeroize` — add zeroize wrapper
- 11 new `DefenseConfig` fields backward-compat trap — verify smoke test in phase-00 DoD
- `<check>_patterns.rs`+`_scanners.rs` triplet premature for some checks — split only if file exceeds 200 LOC
- cesc1802 has no Rust repos — citation acknowledged as architectural pattern reference, not direct style
- "Production-grade vs FR-018 same-IP only MVP" — same-IP is v1; distributed BF documented as out-of-scope
- `tokio::time::pause()` ineffective on `std::time::Instant` — phase-05/07 tests must use injectable Clock or `tokio::time::Instant`
- Hot-reload `bf_window_secs` mid-flight state-window mismatch — document; reset state on config-version change
- R3 worktree script branch slugs wrong (FR-014=SQLi placeholder) — phase-00 implementer overrides
- Phase 07 explicitly admits sequential dependency on Phase 05 — plan.md phase table caveat already notes this

### Reports
- `reports/red-team-260502-0815-security-adversary.md` (10 findings)
- `reports/red-team-260502-0815-failure-mode.md` (10 findings)
- `reports/red-team-260502-0815-assumption-destroyer.md` (11 findings)
- `reports/red-team-260502-0815-scope-critic.md` (10 findings)

## Validation Log

### Session 1 — 2026-05-02
**Trigger:** `/ck:plan validate` after Red Team Review applied.
**Questions asked:** 7 (Step 2.5 verification skipped per Guard — Red Team already provided codebase evidence)

#### Questions & Answers

1. **[Architecture]** `on_response` trait method signature: SYNC vs ASYNC vs side-channel state?
   - Options: Sync (Recommended) | Async | Side-channel state
   - **Answer:** Sync (Recommended)
   - **Rationale:** No body, no awaits in v1; gateway adapter calls sync from `response_filter` async block — `tokio::task::spawn_blocking` not needed because work is non-blocking (DashMap insert + atomic counter).

2. **[Scope]** FR-020 `max_body_size = 64 KiB` ship-as-is for "production"?
   - Options: Ship 64 KiB v1 (Recommended) | Bump gateway BODY_PREVIEW_LIMIT | Defer FR-020
   - **Answer:** Ship 64 KiB v1 (Recommended)
   - **Rationale:** Document in CHANGELOG + open follow-up issue to raise BODY_PREVIEW_LIMIT in gateway PR.

3. **[Scope]** FR-018 status-code-only acceptable for v1?
   - Options: Ship status-code-only (Recommended) | Hold for body-wired | Hybrid opt-in
   - **Answer:** Ship status-code-only v1 (Recommended)
   - **Rationale:** 401/403 covers standard REST/OAuth backends; document JSON-200-error-body limitation; follow-up when `response_body_filter` is wired.

4. **[Risks]** Coverage gate: strict 90% from Phase 00, or informational fallback?
   - Options: Phase 00 first-task informational (Recommended) | **Strict 90% from Phase 00** | Lower to 80%
   - **Answer:** Strict 90% from Phase 00 (NOT recommended; deliberate)
   - **Rationale:** Hard quality gate. Phase 00 absorbs the cost of writing tests for currently uncovered files BEFORE any FR PR is unblocked.

5. **[Scope]** With strict 90%, Phase 00 effort grows. Approach?
   - Options: Phase 00 absorbs ~1-3d test work | Spawn parallel cov-fix PR | `/ck:loop` auto-iterate
   - **Answer:** Phase 00 absorbs (~1-3d test write-up)
   - **Rationale:** Single coordinated PR; no cross-PR rebase risk. Phase 00 effort 4h → 2d; total plan effort 7d → 9d.

6. **[Architecture]** `host_whitelist` collision (FR-016 outbound vs FR-017 inbound) — rename now or defer?
   - Options: Rename now in Phase 00 (Recommended) | Defer | Defer to Phase 08
   - **Answer:** Rename now in Phase 00 (Recommended)
   - **Rationale:** Split into `defense_config.ssrf_outbound_host_allowlist` and `defense_config.host_inbound_whitelist`. ~10min add to Phase 00; eliminates semantic collision permanently.

7. **[Architecture]** Time-mock for stateful checks (Phase 05 + 07 sliding-window tests)?
   - Options: Inject `Clock` trait (Recommended) | `tokio::time::Instant` + `pause()` | Real time + `thread::sleep`
   - **Answer:** Inject `Clock` trait (Recommended)
   - **Rationale:** Production uses `SystemClock`; tests use `MockClock` with manual `advance()`. No tokio runtime coupling; works for sync state stores.

#### Confirmed Decisions
- `Check::on_response(&self, _ctx: &RequestCtx, _status: u16) {}` — sync default no-op, override in FR-018/019.
- `max_body_size = 64 * 1024` (Phase 00 default), document gateway-PR follow-up to raise.
- FR-018 status-code-only (`401`/`403`); body-regex deferred.
- **Strict 90% per-crate coverage gate from Phase 00 onward — Phase 00 must raise existing baseline if needed.**
- Rename: `host_whitelist` → `ssrf_outbound_host_allowlist` (FR-016) + `host_inbound_whitelist` (FR-017).
- Declare `pub trait Clock { fn now(&self) -> std::time::Instant; }` in `crates/waf-engine/src/checks/mod.rs` (Phase 00); FR-018 + FR-019 state stores hold `Arc<dyn Clock>`.

#### Action Items / Impact on Phases
- **Phase 00 (effort 4h → 2d):** add 4 sub-tasks: (a) measure baseline coverage in Docker, (b) list waf-engine files < 90%, (c) write tests to bring all to ≥ 90%, (d) declare `Clock` trait + `SystemClock` impl + `MockClock` test fixture; rename `host_whitelist` field into the two new fields in `DefenseConfig`.
- **Phase 03 (FR-016 SSRF):** use `defense_config.ssrf_outbound_host_allowlist` instead of `host_whitelist`.
- **Phase 04 (FR-017 Header Injection):** use `defense_config.host_inbound_whitelist` instead of `host_whitelist`.
- **Phase 05 (FR-019 Scanner):** `ScannerState` holds `Arc<dyn Clock>`; replace `Instant::now()` with `clock.now()`.
- **Phase 07 (FR-018 Brute Force):** `BfState` holds `Arc<dyn Clock>`; same replacement.
- **plan.md effort:** 7d → 9d (front-loaded into Phase 00).
