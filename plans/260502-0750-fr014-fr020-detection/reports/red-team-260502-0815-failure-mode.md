---
name: Red-team review — Failure Mode Analyst
date: 2026-05-02
reviewer: code-reviewer (hostile lens)
plan: 260502-0750-fr014-fr020-detection
---

# Red-Team Findings — Failure Mode Analyst

Hostile review of FR-014..FR-020 plan from Murphy's Law lens. Every finding grep-verified against codebase.

---

## Finding 1: Every new check needs `engine.rs:96-103` registration — phases 03/04/06/07 don't say so. Stubs ship to main and silently never run.

- **Severity:** Critical
- **Location:** plan.md "Decision A" + Phase 00 "Acceptance Criteria" + Phases 03, 04, 06, 07 ("Files to Modify")
- **Flaw:** Plan asserts "Zero shared-file edits in FR PRs" (plan.md:24). But every `Box<dyn Check>` must be appended to `WafEngine.checkers: Vec<Box<dyn Check>>` constructed at `crates/waf-engine/src/engine.rs:96-103`. None of phases 01-07 document modifying `engine.rs`. Phase 00 only declares stubs and a `ResponseCheck` trait — it does NOT add `Box::new(SsrfCheck::new())` etc. to the constructor. After Phase 00 merges, `SsrfCheck` exists but is never invoked. After Phase 03 merges with the real impl, it's still never invoked because nobody added it to the constructor list.
- **Failure scenario:** Phase 00 → main (stubs return None, engine.rs unchanged). Phase 03 SSRF → main (real impl, engine.rs unchanged). Phase 08 acceptance test runs `engine.inspect()` against an SSRF payload and FAILS — because `SsrfCheck` is never in the loop at engine.rs:370. Discovered at the very end of the 14d hackathon. Worse, if Phase 08 author then edits engine.rs to register all four, that single line creates 4-way merge conflicts with any later patch that touches the constructor.
- **Evidence:** `crates/waf-engine/src/engine.rs:96-103`:
  ```
  let checkers: Vec<Box<dyn Check>> = vec![
      Box::new(CcCheck::new()),
      Box::new(ScannerCheck::new()),
      Box::new(BotCheck::new()),
      Box::new(XssCheck::new()),
      Box::new(RceCheck::new()),
      Box::new(DirTraversalCheck::new()),
  ];
  ```
  Loop at `engine.rs:370` (`for checker in &self.checkers`) is the only call site. `grep -l engine.rs plans/.../phase-*.md` returns ONLY `phase-07-fr018-brute-force-new.md`, and that mentions `on_response`, not the request-side `checkers` Vec.
- **Suggested fix:** Move all 4 `Box::new(...)` insertions for the new checks into Phase 00 alongside the stubs (the stubs return None so adding them is harmless until impls land). That way each FR phase only changes its own files. OR: add a `register_check(&mut self, c: Box<dyn Check>)` API and call once per check from Phase 00.

---

## Finding 2: `WafEngine::evaluate()` does not exist — public entry point is `inspect()`. Plan's DoD checklist references a method that isn't there.

- **Severity:** High
- **Location:** plan.md:74 ("through `WafEngine::evaluate()`"); phase-08-integration-and-bench.md:14, 18, 42, 45 (4 references)
- **Flaw:** Plan repeatedly refers to `WafEngine::evaluate()` as the public API. The actual method is `pub async fn inspect(&self, ctx: &mut RequestCtx) -> WafDecision`. Phase 08's acceptance suite is specced against a non-existent function name.
- **Failure scenario:** Phase 08 author copies the spec verbatim, runs `cargo test`, hits `error[E0599]: no method named 'evaluate' found for struct WafEngine`. Wastes 30min on a name fix. Worse: a careless implementer creates a new `evaluate()` wrapper to satisfy the plan, doubling the public surface.
- **Evidence:** `grep -n "fn evaluate\|fn inspect" crates/waf-engine/src/engine.rs`:
  - `272: pub async fn inspect(&self, ctx: &mut RequestCtx) -> WafDecision`
  - No `fn evaluate` anywhere in the workspace.
- **Suggested fix:** Search-and-replace `evaluate` → `inspect` across plan.md and all phase files. Also: `engine.on_response()` (plan phase-08 step 1) doesn't exist either — that's what Phase 07 must add.

---

## Finding 3: `Check` trait is sync; `Pingora response_filter` is async. The plan's `ResponseCheck` trait declared in Phase 00 is unspecified about sync/async, and Phase 07 declares it as `async fn on_response` — but that breaks the symmetry and forces the dispatch loop in `checker.rs` to be async, which the existing `Check` orchestration is not.

- **Severity:** High
- **Location:** Phase 00 (line 48) declares `pub trait ResponseCheck { fn on_response(&self, ...) }` (sync); Phase 07 (lines 67, 73) calls `self.checker.on_response(ctx, status, body).await` and writes `pub async fn on_response`.
- **Flaw:** Two contradictory specs in the same plan. Phase 00 says non-async trait method (`fn on_response(...)` no `async`). Phase 07 awaits the result. If the trait method is sync, you cannot `await` it. If the trait method is async, then Phase 07 must use `async-trait` crate or `Box<dyn Future>` boxing (neither is mentioned). The existing `Check::check` (`crates/waf-engine/src/checks/mod.rs:34-36`) is intentionally sync — every existing check is sync — so a parallel async trait creates two divergent orchestration styles inside `checker.rs`.
- **Failure scenario:** Phase 00 ships sync trait declaration (line 48 verbatim). Phase 07 author tries to await it; compile error. They convert to `async fn` — but Phase 00 already merged. Now Phase 07 must change Phase 00's contract, which is exactly the "shared-file thrash" the plan was designed to avoid. Or they add `async-trait` as a new dep, contradicting plan.md:67 ("NO new external crates required").
- **Evidence:** `crates/waf-engine/src/checks/mod.rs:34`:
  ```
  pub trait Check: Send + Sync {
      fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult>;
  }
  ```
  Sync. Phase 00 acceptance criteria says: `pub trait ResponseCheck: Send + Sync { fn on_response(&self, ctx: &RequestCtx, status: u16, body: &[u8]); }` — sync. Phase 07 step 4: `pub async fn on_response(&self, ...)` and step 5 awaits it.
- **Suggested fix:** Pin the contract in Phase 00. Either (a) sync `on_response` (matches existing style; recording state in DashMap is sync anyway — no I/O), and the dispatch loop in `checker.rs` is sync; the gateway awaits at the call site without awaiting each check; or (b) `async fn` with `async_trait` (already in workspace deps `async-trait = "0.1"` per `Cargo.toml:56`) — note it is in workspace deps, contradicting plan.md "no new deps" reasoning. Pick one before either Phase merges.

---

## Finding 4: `cargo llvm-cov --workspace --lcov` produces LCOV format; awk script parses human-readable per-crate lines that LCOV doesn't contain. Coverage gate is silently broken on first CI run.

- **Severity:** High
- **Location:** Phase 00 acceptance ("`scripts/coverage-gate.sh` exits 0"); research/researcher-03 §Sec1; CI snippet in researcher-03 lines 161-170
- **Flaw:** The CI step pipes `cargo llvm-cov --workspace --lcov --output-path lcov.info ... | tee cov-summary.txt`. With `--lcov`, the stdout is empty (or just emit log), and `lcov.info` is in DA/BRDA records, not per-crate `waf-engine: 87.5 / 100` lines. The awk script in researcher-03 lines 78-90 (and Phase 00 references it) matches `^(prx-waf|gateway|...):` but LCOV has `SF:`, `DA:`, `LF:`, `LH:` records only. Result: awk matches zero lines → `FAILED=0` stays 0 → script exits 0 → gate silently passes regardless of coverage. (Plan.md:27 explicitly cites this as the upstream bug avoidance.)
- **Failure scenario:** Phase 00 lands. CI green (gate exits 0 because awk found nothing). Phase 01 lands with 12% coverage. Gate still green (still nothing matched). Discovered when somebody manually inspects `cov-summary.txt` weeks later. All 7 PRs merged with no real coverage enforcement. Plan's signature "≥90% per-crate" is fictional.
- **Evidence:** `cargo-llvm-cov --lcov` writes the LCOV tracefile, not the summary table. The summary lines (`waf-engine: ...`) come from `--summary-only` (no `--lcov`). The two flags are mutually exclusive for the human-format output. Verified: researcher-03 §Sec1 lines 53-56 use `cargo llvm-cov ... --lcov ... | tee /out/cov-summary.txt` — that tee captures llvm-cov's stderr/info, not the summary table. The awk pattern at lines 78-90 cannot match.
- **Suggested fix:** Two-pass: (1) `cargo llvm-cov report --summary-only` for awk parsing, (2) `cargo llvm-cov report --lcov --output-path lcov.info` for artifact upload. Or use `--json` and `jq`. Add a smoke test on Phase 00 PR: deliberately drop one crate's coverage to 50%, confirm gate fails. Without that smoke test, the gate is unverified.

---

## Finding 5: `RequestCtx` has no `sni` field, and Phase 04 plan says "VERIFY in Phase 00 PR review" — but Phase 00 doesn't add the field. Phase 04 ships with a degraded-mode comment and the spec rule (HDR-003) is half-implemented.

- **Severity:** High
- **Location:** Phase 04 (lines 50, 120) — "verify `RequestCtx` exposes `sni: Option<String>`. If absent, fall back to whitelist-only validation" + Risk row "SNI not exposed in `RequestCtx` → Host check degraded to whitelist-only"
- **Flaw:** `RequestCtx` definitively has no `sni` field today (`crates/waf-common/src/types.rs:21-54`). Phase 00 acceptance criteria does NOT add one. So Phase 04 will ship without SNI validation — but the plan's Test #7 (`Host: target.com` + SNI=`other.com` → DETECT) cannot be implemented without it. Either the test is fake or the rule is never wired correctly. The "fallback to whitelist-only" comment hides a real gap: TLS-with-Host-spoofing attacks are NOT caught.
- **Failure scenario:** Phase 04 ships, Test #7 is silently rewritten as `whitelist=["target.com"], host="other.com" → DETECT` which passes but doesn't actually exercise SNI. Production attacker sends `Host: admin.internal.example.com` over TLS to a public-facing domain; check passes because `host_whitelist` was empty (default). HDR-003 attack class FR-017 promised to catch is not caught.
- **Evidence:** `crates/waf-common/src/types.rs:21-54` — full `RequestCtx` definition. No `sni` field. `crates/gateway/src/ctx_builder/` exists but `grep -rn sni crates/gateway/src/ctx_builder/` returns empty (verified above).
- **Suggested fix:** Add `pub sni: Option<String>` to `RequestCtx` in Phase 00 alongside the other config fields, AND add a `ctx_builder` modification phase to populate it from Pingora's TLS handshake. If that's out of scope, drop Test #7 and explicitly mark Rule 3's TLS variant as deferred.

---

## Finding 6: FR-018 sliding-window VecDeque uses `parking_lot::Mutex` but the eviction is O(N) and runs INSIDE the request hot path during `record_failed`, plus the VecDeque is held while `now()` is computed — attacker can flood to amplify lock contention.

- **Severity:** High
- **Location:** Phase 07 step 1 ("`record_failed(&self, user_hash, ip, now)` — push timestamp, prune > window") + step 6 (background pruner every 60s)
- **Flaw:** `record_failed` does an inline prune of timestamps older than the 15-minute window (default `bf_window_secs=900`). For a single attacker who sends 1000 req/s against the same `(user, ip)`, after ~15min the VecDeque holds ~900_000 entries. Each new push then walks/pops the front while holding the parking_lot Mutex. While that mutex is held, every other tokio task contending for the same shard of `DashMap<(u64,IpAddr), Mutex<VecDeque<Instant>>>` blocks. Worse: parking_lot mutex blocks the OS thread (no async yielding), so a Pingora worker thread is fully consumed. Background pruner running every 60s is too slow — eviction is request-driven, so a sustained attacker keeps the Mutex hot. This is a self-inflicted DoS.
- **Failure scenario:** Attacker sends 1k req/s against `/login` with rotating usernames AND a single fixed `(victim_user, attacker_ip)` to inflate state. After 15min, VecDeque per shard exceeds 100k entries. p99 of `record_failed` jumps from 50µs (planned) to 2-5ms (front-of-VecDeque eviction under lock). Pingora workers stall. Other request paths (XSS, SQLi) miss SLO. The brute-force check that was supposed to BLOCK the attacker has DoS'd the WAF instead.
- **Evidence:** Phase 07 line 51-52 ("push timestamp, prune > window") indicates inline prune. Risk row "Cross-task synchronization on shared state under load" is acknowledged but mitigation is "Stress test: 1000 concurrent record_failed; verify VecDeque mutex doesn't deadlock" — that tests deadlock, not throughput degradation. No cap on VecDeque size. Compare with the existing `cc.rs:65-92` implementation which has both `MAX_ENTRIES` cap AND background-only cleanup.
- **Suggested fix:** Cap VecDeque to `bf_max_per_user * 4` entries (eviction is bounded by the threshold itself; you only need enough history to count over the window, never more than `max+1` entries). Drop oldest at push if over cap. Move all eviction to the background pruner.

---

## Finding 7: Hot-reload + DashMap state corruption — DefenseConfig changes (e.g. `bf_window_secs` 900 → 60) take effect mid-flight while VecDeque holds 15min of timestamps. Old timestamps suddenly look "fresh" relative to the new window, or "stale" relative to the new threshold, depending on direction of change.

- **Severity:** Medium
- **Location:** Phase 07 Test #11 ("hot-reload: change `bf_max_per_user` from 5 to 10 mid-flight | new threshold takes effect on next request") + Phase 06 lines 49 ("supports hot-reload natively"); plan.md Decision A ("Aligns with existing `Arc<ArcSwap>` pattern")
- **Flaw:** State stored in `BfState` is keyed by `(user_hash, ip)` and persists across config changes. If operator hot-reloads `bf_window_secs` from 900 → 60, the existing VecDeque entries with timestamps 5min ago suddenly flip from "in-window failed attempts" to "out-of-window expired". A user who legitimately had 4 historical failures at minute -5 (counted under old config) is now innocent under new config — but the operator who tightened the window expected stricter enforcement, not looser. Reverse direction (60 → 900) re-counts already-expired failures, falsely escalating toward block. There is no migration step.
- **Failure scenario:** Ops engineer loosens `bf_window_secs` to 60 to reduce false positives Friday afternoon. Attacker had been pacing attempts at 1/120s (under old config = 7 attempts in 15min, blocked at 5). After hot-reload, only 1 attempt visible in 60s window; attacker resumes. Discovered Monday post-incident.
- **Evidence:** Phase 07 Test #11 says "new threshold takes effect on next request" — but doesn't specify state migration. Phase 06 says "no internal state... reads thresholds from `ctx.host_config.defense_config` per request — supports hot-reload natively" — that's true ONLY for stateless checks. FR-018 has state. No `Arc<ArcSwap<BfState>>` mentioned anywhere.
- **Suggested fix:** Either (a) snapshot the config into the `BfState` itself at construction time and require engine restart to change windowing (document this clearly); or (b) version the state and discard on config change. (a) is simpler.

---

## Finding 8: 7-worktree script in researcher-03 §Sec2 uses different feature names (`fr014:sqli-scanner-v2`, `fr015:ssrf-detection`, ...) than the plan's branch names (`feat/fr-014-xss-json-walk`, `feat/fr-015-path-traversal-recursive`, `feat/fr-016-ssrf-detection`, ...). Phase 00 says "substituting branch names to match this plan's table" but worktree script source-of-truth is wrong by 1 (FR-numbers shifted).

- **Severity:** Medium
- **Location:** research/researcher-03 §Sec2 lines 295-302 (worktree array) vs plan.md Phases table (lines 34-42)
- **Flaw:** Researcher-03's worktree slugs assign FR-015 to SSRF, FR-016 to header-injection, FR-017 to brute-force, FR-018 to body-size-abuse — completely off-by-one from the plan, which assigns FR-014=XSS, FR-015=PathTraversal, FR-016=SSRF, FR-017=HeaderInjection, FR-018=BruteForce, FR-019=Scanner, FR-020=BodyAbuse. Even the *content* of FR slots is different (researcher-03 has "proto-smuggling" and "crypto-downgrade" not in the plan at all). Phase 00 says to "substitute branch names" but doesn't list the substitution table — implementer guesses.
- **Failure scenario:** Phase 00 author copies the worktree script verbatim, creates 7 worktrees with WRONG branch names. 7 implementers `cd ../mini-waf-fr014` (which actually contains a `feat/fr014-sqli-scanner-v2` branch when it should be `feat/fr-014-xss-json-walk`). They start work, push, open PRs with wrong titles. Caught at PR review; everyone deletes branches and re-creates worktrees. Loses ~2hr of context.
- **Evidence:** researcher-03 lines 295-302 vs plan.md:34-42. `grep "FR-" plans/.../research/researcher-03-llvm-cov-and-worktree.md` returns 0 occurrences of "ssrf-detection" matching FR-016. The two documents disagree.
- **Suggested fix:** Phase 00 must include the verbatim corrected script (not "substitute branch names" — list them). Or generate the array from the plan.md table programmatically.

---

## Finding 9: Phase 07 explicitly admits dependency on Phase 05 ("Phase 05 ResponseCheck impl will work once Phase 07 merges"), violating plan.md's claim that "Phases 01-07 run in parallel after Phase 00 merges". Recommended merge order at Phase 07 line 178 contradicts plan.md:44.

- **Severity:** Medium
- **Location:** Phase 07 lines 36, 124, 165, 178; plan.md line 44 ("Phases 01-07 run in parallel after Phase 00 merges. Phase 08 runs after all 01-07 merge.")
- **Flaw:** Phase 07 line 178 says "Recommended merge order: 01, 02, 03, 04, 06 → 05 → 07 → 08." Phase 07 line 124 (Risk row): "`ResponseCheck` wiring to checker.rs incomplete (depends on Phase 07's pipeline) | High | High | Phase 05 ships request-side + state machine; response-hook actual call site lands in Phase 07". Phase 05 will ship ResponseCheck IMPL with no dispatch loop wired. If Phase 05 merges before Phase 07, the impl is dead code that triggers `unused` warnings (and CI denies warnings — `Cargo.toml:113-115`). If Phase 07 merges before Phase 05, the dispatch loop iterates over an empty Vec — silently no-op, no error caught.
- **Failure scenario:** Phase 05 lands first with 4xx-burst ResponseCheck impl. CI fails: `unused method on_response`. Author adds `#[allow(dead_code)]`. Phase 07 lands later and forgets to remove the allow. Now the dispatch loop is wired but the allow lingers — code rot. Worse: if order is Phase 07 → Phase 05, then between merges the WAF has the dispatch loop running with 0 ResponseChecks; if a developer runs the Phase 08 acceptance test mid-window, FR-019 fails. Order-dependent CI flakiness.
- **Evidence:** Phase 07 line 178 (already quoted). Phase 05 line 124 risk row explicitly says response-hook lands in Phase 07. plan.md:44 is contradictory.
- **Suggested fix:** Promote the dispatch loop wiring (the `Vec<Arc<dyn ResponseCheck>>` field + its iteration) into Phase 00. Then phases 05 and 07 each only register their own impl. This is the same fix as Finding 1 — wire orchestration in Phase 00.

---

## Finding 10: Existing `DefenseConfig` fields `bot/sqli/xss/scan/rce/sensitive/dir_traversal/owasp_set` lack `#[serde(default)]` (`crates/waf-common/src/types.rs:306-313`). Risk row in Phase 00 says "All new fields use `#[serde(default = "...")]`; existing TOML files load unchanged". True for new fields, but reverse mitigation isn't tested: if any existing config fixture is missing `cc` field (added later), it already fails to load. Plan never inventories which TOML files exist or runs a load test against them.

- **Severity:** Medium
- **Location:** Phase 00 Risks table row 1 ("`DefenseConfig` field addition breaks downstream serde consumers")
- **Flaw:** Mitigation correctly notes new fields use `#[serde(default)]`, but existing fields are non-defaulted — meaning DefenseConfig deserialization is fragile to begin with. If Phase 00 author copies `default_*` helpers and accidentally drops one (or the helper is misnamed), the field becomes required, and `configs/*.toml` fail to load at engine start. No smoke test in Definition of Done loads a representative config.
- **Failure scenario:** Phase 00 ships with `pub ssrf: bool` missing the `#[serde(default = "bool_true")]` attribute (typo in copy-paste). Existing user config (`configs/example.toml`) loads → fails because `ssrf` is required. WAF refuses to start on upgrade. Discovered post-deploy.
- **Evidence:** `crates/waf-common/src/types.rs:306-313`:
  ```
  pub bot: bool,
  pub sqli: bool,
  pub xss: bool,
  pub scan: bool,
  pub rce: bool,
  pub sensitive: bool,
  pub dir_traversal: bool,
  pub owasp_set: bool,
  ```
  No `#[serde(default = ...)]` on any of them. Compare line 315 (`cc`) which DOES have it. Plan Phase 00 DoD has no "load existing TOML fixtures" step.
- **Suggested fix:** Add to Phase 00 DoD: `cargo test -p waf-common config_loads_existing_fixtures`. Provide a `configs/example.toml` round-trip test BEFORE merging Phase 00. Also: while there, add `#[serde(default = "bool_true")]` to the existing 8 fields too (out-of-scope but hygiene win).

---

## Summary

**Status:** DONE
**Total findings:** 10 (Critical: 1, High: 5, Medium: 4)

The plan has good architectural instincts (Phase 0 framework, no `inventory!`, mirror existing patterns) but three load-bearing assumptions are wrong:

1. **No shared edits** — plan claims phases are disjoint; in reality every new check needs `engine.rs:96-103` edit (Finding 1). Until that's centralized in Phase 00, parallelism is illusory.
2. **`evaluate()` is the API** — actual name is `inspect()` (Finding 2). Cosmetic but indicates the plan was not grep-verified before review.
3. **Coverage gate works** — the awk parser cannot match LCOV format (Finding 4). The 90% gate is theatre until a smoke test proves it fails on bad input.

Finding 3 (sync vs async ResponseCheck) is the most architecturally consequential — pin the contract before either Phase 00 or Phase 07 ships.

Findings 6 and 7 are the only operational/runtime risks (FR-018 state mgmt). Both are fixable inside Phase 07.

## Unresolved Questions

1. Does `RequestCtx` need a permanent `sni` field, or is `host_whitelist` sufficient v1? (Affects Phase 00 + Phase 04 scope.)
2. Should the `Vec<Arc<dyn ResponseCheck>>` registration list live in `WafEngine` or `Checker`? Plan is silent.
3. What is the production-acceptable max VecDeque length per `(user, ip)` pair? Defaults to "unbounded" in plan; suggest `bf_max_per_user * 4` but needs ops sign-off.
4. Is `async-trait` actually fine to use? It's already a workspace dep (`Cargo.toml:56`) so plan.md:67's "no new external crates" is already satisfied — but does the team prefer to avoid it for trait-object reasons?
