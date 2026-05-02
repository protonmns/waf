---
phase: 00
title: "Framework + Coverage Scaffold (Pre-req for FR PRs)"
status: code-complete (coverage-baseline deferred)
priority: P1
effort: 4h
dependencies: []
branch: feat/fr-frame-detection-framework
fr: framework
---

## Implementation Status (260502-0905)

Code path: ✓ all framework edits + scripts + CI landed on branch `main`
(working tree, pre-commit). Verified:

- `cargo check -p waf-common -p waf-engine --tests` rc=0 (Docker rust:1.91-slim-bookworm)
- `cargo clippy --workspace --all-targets -- -D warnings` rc=0 (Docker rust:1.95-slim-bookworm)
- `cargo fmt --all -- --check` rc=0
- `cargo test -p waf-common --lib` 20/20 ok
- `cargo test -p waf-engine --lib checks::` 108/108 ok (incl. 4 new stub tests)
- `bash scripts/coverage-gate.sh tests/fixtures/llvm-cov-summary-pass.txt 90` rc=0
- `bash scripts/coverage-gate.sh tests/fixtures/llvm-cov-summary-fail.txt 90` rc=1 (correct rejection)

Deferred to follow-up session before flipping CI gate to enforcing
(Validation V1 contract):
- Step 0 — measure baseline `cargo llvm-cov -p waf-engine --summary-only`
- Step 0b — list waf-engine src files <90%
- Step 0c — write tests to bring all to ≥90%
- Smoke `bash scripts/create-worktrees.sh` (needs sibling-dir state ready)
- Build `Dockerfile.coverage` end-to-end and run llvm-cov inside it

Pre-existing cross-version lint divergence noted: `relay/config_tests.rs:4`
allows `clippy::duration_suboptimal_units` (added in clippy >=1.92), which
is unknown under Rust 1.91. Out of Phase 00 scope; document as a known
issue for Dockerfile.coverage rust pinning (see Risks).

## Overview

Land all shared edits in ONE small PR so each downstream FR PR (01-07) only touches its own files — zero merge conflicts. Adds 4 enum variants, 4 stub `Check` impls, `DefenseConfig` toggles, Docker coverage gate, worktree creation script, and CI coverage job.

## Acceptance Criteria

- `Phase` enum gains 4 new variants: `Ssrf`, `HeaderInjection`, `BruteForce`, `RequestBodyAbuse`
- `DefenseConfig` gains 4 + tunable fields (see below) with serde defaults
- 4 stub modules compile and return `None` from `Check::check`
- `cargo build --workspace` + `cargo clippy -- -D warnings` green
- `Dockerfile.coverage` builds and produces `lcov.info` from inside container
- `scripts/coverage-gate.sh` exits 0 (informational on this PR; gate enforced from Phase 01 onward)
- `scripts/create-worktrees.sh` creates 7 worktrees from `origin/main`
- CI workflow `.github/workflows/ci.yml` has new `coverage` job (uncommented + adapted from existing skeleton lines 65-101)
- New `ResponseCheck` trait declared in `checker.rs` (no impls yet — used by Phase 07)

## Files to Create

| Path | Purpose |
|---|---|
| `crates/waf-engine/src/checks/ssrf.rs` | Stub `SsrfCheck` |
| `crates/waf-engine/src/checks/header_injection.rs` | Stub `HeaderInjectionCheck` |
| `crates/waf-engine/src/checks/brute_force.rs` | Stub `BruteForceCheck` (request-phase Check returns None; ResponseCheck added Phase 07) |
| `crates/waf-engine/src/checks/body_abuse.rs` | Stub `RequestBodyAbuseCheck` |
| `Dockerfile.coverage` | R3§Sec1 single-stage Rust 1.91 image, `cargo-llvm-cov 0.8.5` pre-installed |
| `scripts/coverage-gate.sh` | R3§Sec1 awk parser, gate >=90% per crate |
| `scripts/create-worktrees.sh` | R3§Sec2 Step1, but slugs match Phase 01-07 branch names |
| `scripts/setup-worktree-env.sh` | R3§Sec2 Step2, sets `CARGO_TARGET_DIR=<worktree>/target` |

## Files to Modify

| Path | Edit |
|---|---|
| `crates/waf-common/src/types.rs:131-157` | Add `Ssrf=19, HeaderInjection=20, BruteForce=21, RequestBodyAbuse=22` to `Phase`; matching `Display` arms |
| `crates/waf-common/src/types.rs:305-342` | Add to `DefenseConfig`: see field table below |
| `crates/waf-engine/src/checks/mod.rs:1-25` | Add `pub mod ssrf;` etc. and `pub use ssrf::SsrfCheck;` etc. |
| `crates/waf-engine/src/checker.rs` | Declare `pub trait ResponseCheck: Send + Sync { fn on_response(&self, ctx: &RequestCtx, status: u16, body: &[u8]); }` (no callers yet) |
| `.github/workflows/ci.yml:69-101` | Uncomment + replace gateway-specific gate with workspace per-crate gate (R3§Sec1) |
| `Cargo.toml` | No new deps (verify `dashmap`, `ipnet`, `parking_lot`, `serde_json`, `arc_swap` already workspace deps) |

## DefenseConfig fields to add

```rust
// FR-016 SSRF
#[serde(default = "bool_true")]      pub ssrf: bool,
#[serde(default = "default_ssrf_dns_timeout_ms")] pub ssrf_dns_timeout_ms: u64, // 50
// FR-017 Header injection
#[serde(default = "bool_true")]      pub header_injection: bool,
#[serde(default = "default_xf2_max_hops")] pub xf2_max_hops: usize, // 5
pub host_whitelist: Vec<String>,     // empty = no host validation
// FR-018 Brute force
#[serde(default = "bool_true")]      pub brute_force: bool,
#[serde(default = "default_bf_window_secs")] pub bf_window_secs: u64,           // 900 (15min)
#[serde(default = "default_bf_max_per_user")] pub bf_max_per_user: usize,       // 5
#[serde(default = "default_bf_spray_threshold")] pub bf_spray_threshold: usize, // 5
#[serde(default = "default_bf_login_routes")] pub bf_login_routes: Vec<String>, // ["/login","/api/auth/token"]
// FR-020 Body abuse
#[serde(default = "bool_true")]      pub body_abuse: bool,
#[serde(default = "default_max_body_size")] pub max_body_size: usize, // 1_048_576
#[serde(default = "default_max_json_depth")] pub max_json_depth: usize, // 100
#[serde(default = "default_max_json_keys")] pub max_json_keys: usize, // 10_000
```

## Implementation Steps

1. Add `Phase` variants + `Display` arms in `types.rs:131-182`
2. Add `DefenseConfig` fields + `const fn default_*` helpers (mirror existing `default_cc_rps` style at types.rs:350)
3. Update `DefenseConfig::default()` impl in same file to populate new fields
4. Create 4 stub files; each follows this skeleton:
   ```rust
   use waf_common::{DetectionResult, RequestCtx};
   use super::Check;

   pub struct SsrfCheck;
   impl SsrfCheck { pub const fn new() -> Self { Self } }
   impl Default for SsrfCheck { fn default() -> Self { Self::new() } }
   impl Check for SsrfCheck {
       fn check(&self, _ctx: &RequestCtx) -> Option<DetectionResult> { None }
   }
   ```
5. Wire stubs in `checks/mod.rs` (add 4 `pub mod` + 4 `pub use`)
6. Add `ResponseCheck` trait stub to `checker.rs` (only declaration; impls in Phase 07)
7. Author `Dockerfile.coverage`, `scripts/coverage-gate.sh`, `scripts/create-worktrees.sh`, `scripts/setup-worktree-env.sh` from R3§Sec1+2 verbatim, **substituting branch names to match this plan's table**
8. Uncomment + adapt CI coverage job; gate at info-level on this PR (set `continue-on-error: true` for one PR; flip to hard gate from Phase 01 merge onward via follow-up commit on first FR PR)
9. Smoke test: `cargo check -p waf-engine && cargo test -p waf-engine --lib checks::`
10. `gh pr create --title "feat(detection): framework + coverage scaffold" --body ...`

## Test Matrix

| Test | Target | Pass Criterion |
|---|---|---|
| `checks::ssrf::tests::stub_returns_none` | each stub | `SsrfCheck::new().check(&ctx).is_none()` |
| `defense_config_default_serializes` | `waf-common` | round-trip serde of `DefenseConfig::default()` includes 4 new toggles |
| `phase_display_new_variants` | `waf-common` | `Phase::Ssrf.to_string() == "SSRF"` etc. |
| `coverage_script_smoke` | shell | `bash scripts/coverage-gate.sh tests/fixtures/lcov-mock.txt 90` returns 0 |

## False Positive Mitigation

N/A (stubs return None).

## Branch + PR

- Branch: `feat/fr-frame-detection-framework`
- Squash commit: `feat(detection): framework scaffold (Phase enum, DefenseConfig, ResponseCheck trait, stubs, coverage gate)`
- Reviewer: `@lotus`

## Coverage Requirement

Informational only on this PR. Gate flips to enforcing on first FR PR (Phase 01).

## Definition of Done

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `docker build -f Dockerfile.coverage -t prx-waf:cov .` succeeds
- [ ] `docker run --rm prx-waf:cov cargo llvm-cov --workspace --summary-only` produces output
- [ ] `bash scripts/create-worktrees.sh` creates 7 worktrees in sibling dirs without error
- [ ] CI lint+test+build green on PR
- [ ] PR merged to `main`

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `DefenseConfig` field addition breaks downstream serde consumers | Medium | High | All new fields use `#[serde(default = "...")]`; existing TOML files load unchanged |
| `ResponseCheck` trait declared but unused → clippy `dead_code` warn | Low | Low | Add `#[allow(dead_code)]` on trait until Phase 07 wires it |
| Coverage Docker image first-build slow (~5min) | High | Low | Cached in CI via Swatinem/rust-cache; subsequent builds <60s |
| Worktree script collides with existing `../mini-waf-*` directories | Low | Medium | Script does `git worktree remove ... 2>/dev/null \|\| true` first |

## Rollback

Single squash commit; `git revert <sha>` removes 4 enum variants, 4 fields, 4 stubs cleanly. Downstream FR PRs not yet merged. Cov gate revert is no-op (was informational).

## Red Team Fixes (applied 2026-05-02)

Findings #2, #7, #13. See `plan.md ## Red Team Review`.

### Finding #2 — Phase 00 owns ALL 7 stub registrations in `engine.rs::new()`
- **Add** to "Files to Modify" table: `crates/waf-engine/src/engine.rs:96-102` — extend the `vec![]` literal in `WafEngine::new()` constructor with 7 stub registrations:
  ```rust
  Box::new(SsrfCheck::new()),
  Box::new(HeaderInjectionCheck::new()),
  Box::new(BruteForceCheck::new()),
  Box::new(RequestBodyAbuseCheck::new()),
  ```
  (Plus enhanced re-registrations for XSS/PathTraversal/Scanner if they keep their existing entries — verify by reading current `vec![]` first.)
- **Add** to DoD: `grep -A5 'Vec<Box<dyn Check>>' crates/waf-engine/src/engine.rs` shows all 7 new entries.

### Finding #7 — Collapse `ResponseCheck` into `Check` default-impl
- **Replace** step 6 + acceptance criteria mention of `ResponseCheck`. New trait declaration in `crates/waf-engine/src/checks/mod.rs` (NOT `checker.rs`):
  ```rust
  pub trait Check: Send + Sync {
      fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult>;
      /// Default no-op response hook. Override in checks that need upstream
      /// status (FR-018 brute force, FR-019 4xx-burst). Body NOT exposed in v1
      /// (Pingora `response_filter` gives headers+status only; body via
      /// `response_body_filter` deferred).
      fn on_response(&self, _ctx: &RequestCtx, _status: u16) {}
  }
  ```
- **Drop** the separate `pub trait ResponseCheck` declaration entirely.
- All 11 existing `Check` impls auto-inherit no-op `on_response` — zero changes elsewhere.

### Finding #13 — Smoke-test cov gate awk parser BEFORE merge
- **Add** to DoD: `bash scripts/coverage-gate.sh tests/fixtures/lcov-real.txt 90` MUST exit non-zero when fixture is 89.5% AND exit zero when fixture is 91.0%.
- **Add** to Files to Create: `tests/fixtures/lcov-real.txt` — captured from `docker run --rm prx-waf:cov cargo llvm-cov -p waf-engine --lcov` (real format, not mocked).
- **Add** to Implementation Steps step 7: validate awk regex against the captured fixture; if format doesn't match, fix parser BEFORE proceeding.

### Lower-severity (deferred, recorded)
- DefenseConfig serde-default smoke test: add to DoD `cargo test -p waf-common defense_config_default_loads_existing_toml_fixtures`.

## Validation Updates (Session 1 — 2026-05-02)

Per `plan.md ## Validation Log`, Phase 00 absorbs additional scope:

### V1 — Strict 90% coverage gate (Q4 + Q5)
- **NEW Step 0 (first task):** `docker run --rm prx-waf:cov cargo llvm-cov -p waf-engine --summary-only > baseline.txt`. Record current `waf-engine` line coverage.
- **NEW Step 0b:** `docker run --rm prx-waf:cov cargo llvm-cov -p waf-engine --html` → list every file < 90%.
- **NEW Step 0c:** Write tests for each under-covered file until ALL files in `crates/waf-engine/src/` are ≥ 90%. (No Phase 00 merge until this passes.)
- **Effort:** 4h → **2d** (front-loaded).
- **DoD:** `bash scripts/coverage-gate.sh /out/lcov.info 90` exits 0 against actual `cargo llvm-cov -p waf-engine` output. Gate is **enforcing** (not informational) on Phase 00 PR.

### V2 — `Clock` trait declaration (Q7)
- **Add to "Files to Modify"** `crates/waf-engine/src/checks/mod.rs`:
  ```rust
  pub trait Clock: Send + Sync {
      fn now(&self) -> std::time::Instant;
  }

  pub struct SystemClock;
  impl Clock for SystemClock {
      fn now(&self) -> std::time::Instant { std::time::Instant::now() }
  }

  #[cfg(test)]
  pub mod test_clock {
      use super::*;
      use std::sync::atomic::{AtomicU64, Ordering};
      pub struct MockClock { offset_nanos: AtomicU64, base: std::time::Instant }
      impl MockClock {
          pub fn new() -> Self { Self { offset_nanos: 0.into(), base: std::time::Instant::now() } }
          pub fn advance(&self, dur: std::time::Duration) {
              self.offset_nanos.fetch_add(dur.as_nanos() as u64, Ordering::SeqCst);
          }
      }
      impl Clock for MockClock {
          fn now(&self) -> std::time::Instant {
              self.base + std::time::Duration::from_nanos(self.offset_nanos.load(Ordering::SeqCst))
          }
      }
  }
  ```
- FR-018 + FR-019 state stores hold `Arc<dyn Clock>` (default `Arc::new(SystemClock)` in production; `Arc::new(MockClock::new())` in tests).

### V3 — `host_whitelist` field rename (Q6)
- **Replace** in DefenseConfig fields table:
  ```rust
  pub host_whitelist: Vec<String>,     // empty = no host validation
  ```
  With **two** fields:
  ```rust
  // FR-016 SSRF outbound allow-list (host_str values to permit despite RFC1918 match)
  #[serde(default)]
  pub ssrf_outbound_host_allowlist: Vec<String>,
  // FR-017 inbound Host header whitelist (validate request Host against this set)
  #[serde(default)]
  pub host_inbound_whitelist: Vec<String>,
  ```
- Update `DefenseConfig::default()` to populate both as `Vec::new()`.
- No collision; clear semantics.
