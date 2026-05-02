---
agent: red-team / assumption-destroyer
date: 2026-05-02
plan: 260502-0750-fr014-fr020-detection
verdict: REQUIRES REWORK before kicking off PR-flow
---

# Red Team — Assumption Destroyer

Hostile review of the FR-014..FR-020 detection plan. Every "X exists" / "Y is wired" / "Z works" claim grep-verified. Findings ranked by failure radius.

---

## Finding 1: `WafEngine::evaluate()` does not exist — entry point is `inspect()`

- **Severity:** Critical
- **Location:** plan.md "Verify (Definition of Done)" line 74; phase-08 §Acceptance Criteria, §Implementation Steps step 1, §Test Matrix
- **Flaw:** Plan's gate-of-done says "exercises all 7 attack types end-to-end through `WafEngine::evaluate()`", and Phase 08 directs implementers to "call `engine.evaluate()`". That method does not exist. The public entry is `pub async fn inspect(&self, ctx: &mut RequestCtx) -> WafDecision`.
- **Failure scenario:** Phase-08 implementer writes `engine.evaluate(...)`, code does not compile. They either (a) waste time guessing or (b) silently rename to `inspect`, but discover the signature requires `&mut RequestCtx` (not `&RequestCtx` as the test matrix suggests for stateless calls). Either way: the very acceptance API is fictional.
- **Evidence:**
  - `crates/waf-engine/src/engine.rs:272`: `pub async fn inspect(&self, ctx: &mut RequestCtx) -> WafDecision`
  - `grep -rn "fn evaluate\|engine.evaluate\|WafEngine::evaluate" /Users/admin/lab/mini-waf/crates/` returns hits only for unrelated `access::evaluator` and `relay::evaluate`. No `WafEngine::evaluate`.
  - Confirmed: `crates/gateway/src/proxy.rs:363` calls `self.engine.inspect(&mut request_ctx).await`.
- **Suggested fix:** Global search-and-replace `evaluate` → `inspect` across plan.md and phase-08; update test matrix to take `&mut RequestCtx`.

---

## Finding 2: `checker.rs` is the rule store, not the orchestrator — Phase 07's wiring target is wrong

- **Severity:** Critical
- **Location:** phase-00 "Files to Modify" row 4; phase-05 §Implementation step 2; phase-07 §Files to Modify; Decision C in plan.md
- **Flaw:** Plan repeatedly claims `checker.rs` will host the new `ResponseCheck` trait, the `Vec<Arc<dyn ResponseCheck>>`, and the `pub async fn on_response` dispatch. In reality `crates/waf-engine/src/checker.rs` is 278 LOC of `RuleStore` + IP/URL list helpers — it does NOT iterate any `Vec<dyn Check>`. The detection-check pipeline lives in `engine.rs::inspect` (the `for checker in &self.checkers` loop at engine.rs:370). The `checkers: Vec<Box<dyn Check>>` field is on `WafEngine`, declared at engine.rs:52 and constructed at engine.rs:96.
- **Failure scenario:** Phase 07 implementer adds the trait + Vec to `checker.rs` (RuleStore), where there is no callsite. They must then trace through `engine.rs::inspect` to wire dispatch — duplicating shared-file edits Phase 0 was supposed to absorb. Phase 00's "no shared edits" guarantee for downstream FR PRs collapses: `engine.rs` has to be edited for FR-018, FR-019, AND for the original Phase 00 trait declaration.
- **Evidence:**
  - `crates/waf-engine/src/checker.rs:1-30`: contains `pub struct RuleStore`, never `Vec<dyn Check>`.
  - `crates/waf-engine/src/engine.rs:52`: `checkers: Vec<Box<dyn Check>>,` — field is on `WafEngine`.
  - `crates/waf-engine/src/engine.rs:96-102`: `let checkers: Vec<Box<dyn Check>> = vec![ Box::new(BotCheck::new()), Box::new(XssCheck::new()), Box::new(RceCheck::new()), ... ]`.
  - `engine.rs:370`: `for checker in &self.checkers { if let Some(result) = checker.check(ctx) { ... } }`.
  - `grep "Vec.*dyn Check" checker.rs` → no hits.
- **Suggested fix:** Replace every "modify `checker.rs`" with "modify `engine.rs`". Recognize: every new check requires editing engine.rs (vec push). FR-018's `ResponseCheck` plumbing requires engine.rs (new field + new method) and proxy.rs (wire `response_filter` to call it). Phase 00 must own those edits or the parallelism premise (Decision A: "zero shared-file edits in FR PRs") is broken.

---

## Finding 3: `parking_lot — Already used (sql_injection_scanners)` is FALSE

- **Severity:** Medium
- **Location:** plan.md §Dependencies row "parking_lot"
- **Flaw:** Plan asserts `parking_lot` is "already used (sql_injection_scanners)" to justify FR-018's mutex choice. `sql_injection_scanners.rs` does NOT use `parking_lot`. It uses no Mutex at all.
- **Failure scenario:** Reviewer takes plan at face value, doesn't ask whether the MSRV / feature flags need updating. Low-severity because parking_lot IS used elsewhere in waf-engine, just not where the plan claims.
- **Evidence:**
  - `grep "parking_lot\|Mutex" crates/waf-engine/src/checks/sql_injection_scanners.rs` — no hits in source code (only test fixtures via std HashMap).
  - parking_lot IS used at `crates/waf-engine/src/crowdsec/cache.rs:5`, `rules/manager.rs:6`, `rules/hot_reload.rs:10`, `relay/intel/*.rs`. Plan should cite one of these.
- **Suggested fix:** Replace evidence anchor with `crates/waf-engine/src/crowdsec/cache.rs:5` or `relay/intel/asn_feed.rs:71`.

---

## Finding 4: serde_json `set_recursion_limit` API does not exist

- **Severity:** High
- **Location:** phase-06 §Risks row 1: "Use `serde_json::de::Deserializer::from_slice(...).set_recursion_limit(150)`"
- **Flaw:** Plan marks this `[UNVERIFIED]` but accepts it as the mitigation for the most critical FR-020 risk (serde_json stack-overflow on adversarial input). serde_json exposes only `disable_recursion_limit()` (gated behind opt-in `unbounded_depth` feature) — there is NO `set_recursion_limit(usize)` setter. Default depth is hard-coded at 128.
- **Failure scenario:** FR-020 implementer hits compile error on first attempt. Fallback options: (a) accept default 128 limit (≤ plan's `max_json_depth=100` — borderline; deeply-nested JSON 100 < input 130 will OOM/stack-crash before our walker runs); (b) pull in `serde-stacker` crate (new dep); (c) use `serde_json::Value` walker only after initial parse — but parse itself can stack-overflow. The risk row's "fallback: custom Value walker" misses this: `from_slice` to `Value` triggers the same recursion.
- **Evidence:**
  - serde_json upstream issue tracker: "Allow increasing recursion limit · Issue #334" — feature request, NOT shipped.
  - `Deserializer` docs.rs entry exposes `disable_recursion_limit` only.
  - serde-stacker (`dtolnay/serde-stacker`) is the canonical workaround — would be a NEW dep, contradicting plan's "NO new external crates required" claim (plan.md §Dependencies line 67).
- **Suggested fix:** Either (a) lower `max_json_depth` default to 64 to stay well below serde_json's hard 128 cap, document that depth ∈ (64,128] silently passes parse but is never walked, OR (b) add `serde-stacker` to deps and update §Dependencies, OR (c) parse incrementally with `StreamDeserializer` and depth-counting reader. Today's plan defers the issue to "first task of Phase 06 implementer" — that is too late, the mitigation must be picked before parallel PRs branch.

---

## Finding 5: Phase 00's "zero shared-file edits in FR PRs" guarantee is unattainable as scoped

- **Severity:** Critical
- **Location:** plan.md Decisions A + B; phase-00 §Files to Modify
- **Flaw:** Phase 00 promises shared edits land first → FR PRs touch only their own files → no merge conflicts → 7 truly parallel PRs. Verification reveals the plan ALREADY admits 3 violations:
  1. Phase 05 (FR-019) §"Note on shared-file edit" admits modifying scanner.rs (existing file). OK because exclusive.
  2. Phase 05 §Implementation step 2 says "ScannerCheck gains state" — but `ScannerCheck` is constructed inside engine.rs's `vec![Box::new(ScannerCheck::new())]`. Adding state means changing the constructor signature OR mutating engine.rs to pass shared state. Either way: engine.rs edit.
  3. Phase 07 §Files to Modify explicitly lists `engine.rs` AND `checker.rs` (latter is a Finding 2 confusion).
- Add to that: every FR PR that ships a new `Check` impl MUST register it in `engine.rs::new`'s `vec![]` literal — otherwise the check is dead code. Phase 00 stubs are not added to that vec (acceptance criteria omits it). So either Phase 00 also pre-registers stubs in engine.rs (file conflict!) or every FR PR edits engine.rs (parallelism violation!).
- **Failure scenario:** Phase 01 (XSS) and Phase 03 (SSRF) PRs both rebased after another lands → engine.rs:96-102 vec![] literal has merge conflicts on every PR. Manual resolve × 7 = the "permanent macro complexity" Decision A claims to avoid.
- **Evidence:**
  - `crates/waf-engine/src/engine.rs:96-102`: literal `vec![Box::new(BotCheck::new()), ...]` is the registration point.
  - phase-00 §"Files to Modify" mentions `checks/mod.rs:1-25` only ("Add `pub mod ssrf;` etc."), NOT `engine.rs`. The stubs are never wired into the running pipeline.
  - phase-01..06 do not list engine.rs in §Files to Modify.
- **Suggested fix:** Either (a) Phase 00 adds 4 NEW stub registrations to engine.rs `vec![]` AND fields like `scanner_state` for future Phase 05 — making Phase 00 fatter but FR PRs truly disjoint; or (b) accept that engine.rs is a shared file, sequence FR PRs serially on that line, drop the parallelism narrative.

---

## Finding 6: FR-018 ResponseCheck has no upstream-response hook in engine.rs to wire into

- **Severity:** Critical
- **Location:** plan.md §Unresolved Questions item 1 (claims RESOLVED), phase-07 §Implementation Steps step 5
- **Flaw:** Plan §Unresolved Q1 is marked RESOLVED with "Pingora `response_filter` exposed at `crates/gateway/src/proxy.rs:429`". Verified — that hook exists. BUT plan's actual wiring path is `engine.rs` → `checker.on_response`. There is no `on_response` callback on `WafEngine` today, and Pingora's `response_filter` in proxy.rs:429 only delegates to `self.response_chain.apply_all(upstream_response, &fctx)` — a HEADER-only filter chain. Phase 07 needs upstream **body** for body-regex match (`is_failed_login_response(status, body)`). The body is NOT available in `response_filter`; it streams chunk-by-chunk through `response_body_filter` (proxy.rs:472). That path does not pass through any waf-engine call today.
- **Failure scenario:** Phase 07 implementer wires `engine.on_response()` into proxy.rs `response_filter` → has status but no body → body-regex matching silently never fires → BF-001 detection only triggers on 401/403 status. The plan promises both. Realistic worst case: Phase 07 attempts to thread body bytes through existing `response_body_filter` chain → discovers proxy.rs CTX has no engine handle in that hook (verify) → escalation, schedule slip, or scope cut.
- **Evidence:**
  - `crates/gateway/src/proxy.rs:429-470`: response_filter takes `upstream_response: &mut pingora_http::ResponseHeader`, never the body.
  - `crates/gateway/src/proxy.rs:472-491`: response_body_filter handles chunks but only invokes `apply_body_mask_chunk` (regex masking), no waf-engine callout.
  - `grep "fn on_response\|response_check" engine.rs checker.rs` → no hits.
  - Phase 07 §Risks row 1 itself flags this as Likelihood=Medium / Impact=Critical — yet plan.md §Unresolved Q1 self-resolves. Contradiction.
- **Suggested fix:** Un-resolve §Unresolved Q1 in plan.md. Add a Phase 0.5 (or expand Phase 00) to: (a) thread `Arc<WafEngine>` into `ProxyHttp::CTX` (already done — proxy.rs:45 has `pub engine: Arc<WafEngine>`), (b) in `response_body_filter`, accumulate body up to `body_preview_limit`, (c) on `end_of_stream`, invoke `engine.on_response(ctx, status, body_preview).await`. Then Phase 07 has a place to plug in.

---

## Finding 7: Spawning `tokio::spawn` from `Check::new()` violates struct-only construction; pruners leak

- **Severity:** High
- **Location:** phase-05 §Implementation Steps step 3; phase-07 §Implementation Steps step 6
- **Flaw:** Plan says "Spawn background pruner: `tokio::spawn` task in `ScannerCheck::new`". But `engine.rs::new()` is NOT async — it's `pub fn new(db: Arc<Database>, config: WafEngineConfig) -> Self`. `tokio::spawn` requires a current Tokio runtime in scope; calling it from a sync constructor used at engine boot is fragile. Worse, `ScannerCheck` is stored as `Box<dyn Check>` inside `Vec<Box<dyn Check>>`. The spawned pruner holds an `Arc<ScannerState>`, but the Check itself doesn't own a JoinHandle, and Drop on the Vec will not abort the pruner. Result: pruner outlives engine on test teardown → test flakes; and on production reload (`reload_rules`) the old pruner keeps running indefinitely. The "Notify-driven shutdown" handwave is undermined by lacking a shutdown wiring strategy in the plan.
- **Failure scenario:** Tests using `tokio::time::pause()` see two pruners (old + new from engine reload) racing on the same DashMap → state oscillates → `is_4xx_burst` flakes intermittently.
- **Evidence:**
  - `crates/waf-engine/src/engine.rs:81`: `pub fn new(db: Arc<Database>, config: WafEngineConfig) -> Self` — sync.
  - `crates/waf-engine/src/checks/mod.rs:34`: `pub trait Check: Send + Sync { fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult>; }` — no async, no Drop, no shutdown method.
- **Suggested fix:** Move pruner spawning out of `Check::new`. Add a `Check::start_background(self: Arc<Self>, shutdown: CancellationToken) -> Option<JoinHandle<()>>` extension method, called from `WafEngine::new` after the Vec is built. Engine owns JoinHandles, aborts them on Drop. Update Phase 00 to introduce the trait method (shared edit — see Finding 5).

---

## Finding 8: Coverage gate >= 90% per crate is fictional given current baseline; plan never measures it

- **Severity:** High
- **Location:** plan.md §Cross-Cutting NFRs; phase-00 §Acceptance Criteria; every phase's "Coverage Requirement" row
- **Flaw:** Plan asserts ">=90% per-crate" gate. Adding 90%-covered new files cannot lift a crate that is currently below 90% — line-coverage % is `(lines_hit) / (lines_total)`, dominated by mass. The plan never establishes the baseline. `gateway/CLAUDE.md` shows the gateway crate uses a 95% gate but only against a heavily-filtered file set (`--ignore-filename-regex '(cache|lb|tunnel|ssl|http3|proxy|proxy_waf_response|context|router|lib|request_ctx_builder|protocol)\.rs$'`). For waf-engine (the crate this plan actually touches), no baseline exists in CI today — the workflow lines plan cites at `.github/workflows/ci.yml:65-101` are entirely COMMENTED OUT (verified).
- **Failure scenario:** Phase 01 PR opens with new XSS code at 95% coverage. CI runs `cargo llvm-cov --workspace --summary-only` per Phase 00 spec. Existing waf-engine subtree (engine.rs at 618 LOC, lots of crowdsec/community/relay code with light test coverage) drags total to 70%. Gate rejects. Implementer can't ship without backfilling tests for unrelated code OR re-engineering the gate to per-FILE not per-crate.
- **Evidence:**
  - `.github/workflows/ci.yml:69-101`: every coverage line is `#`-prefixed (commented).
  - waf-engine LOC sample: engine.rs 618, checker.rs 278, scanner.rs 302, sql_injection.rs 276 = >1.4k LOC of legacy code, never measured.
  - `gateway/CLAUDE.md` openly excludes ~10 files from its gate to hit 95% — proves the precedent that baseline-aware gating is required.
- **Suggested fix:** Phase 00 first task: measure current per-crate coverage (run `cargo llvm-cov` once, record numbers). Either (a) gate at `max(current_baseline, target_threshold)` per crate, OR (b) gate per NEW file added (use `--include-filename-regex 'checks/(ssrf|brute_force|header_injection|body_abuse).*\.rs$'`). Drop the per-crate >=90% claim until baseline is measured.

---

## Finding 9: `cesc1802 style` is post-hoc rationalization — not a Rust style source

- **Severity:** Medium
- **Location:** phase-03 §Files to Create note: "Triplet structure mirrors existing `sql_injection*` per cesc1802 style — `research/researcher-01-cesc1802-style.md§4`"
- **Flaw:** researcher-01 itself states cesc1802 has 119 public repos, primary language Go, no Rust repos (line 12-13 of researcher-01-cesc1802-style.md). The "style" being adopted is a Go developer's interface-and-DDD conventions, manually translated to Rust. The "triplet" (ssrf.rs / ssrf_patterns.rs / ssrf_scanners.rs) is not in cesc1802's repos at all — it mirrors the existing prx-waf `sql_injection*` triplet that predates this plan. Citing cesc1802 to justify it is a circular/false attribution.
- **Failure scenario:** New contributor reads phase-03, opens cesc1802's GitHub looking for the canonical "triplet" pattern, finds Go monoliths and is confused. Slows onboarding. Worse, future plan PRs use "follows cesc1802 style" as cargo-cult justification for unrelated decisions, weakening review rigor.
- **Evidence:**
  - `plans/.../research/researcher-01-cesc1802-style.md:11-13`: "119 public repos across Go, TypeScript, Python, Dart, JavaScript, HCL — Primary language: Go (15+ projects)" — no Rust mentioned.
  - `crates/waf-engine/src/checks/sql_injection*` already exists pre-plan (verified `ls`); the splitting decision was driven by CLAUDE.md's "200-LOC modularization" rule, not cesc1802.
- **Suggested fix:** Replace "per cesc1802 style" with "per CLAUDE.md modularization rule + existing sql_injection* precedent". Drop the cesc1802 citation throughout phase files. (Note: this is also a YAGNI violation — researcher-01 is solving a problem the codebase already solved.)

---

## Finding 10: 14-day estimate ignores branch order constraints + R3 worktree script bugs

- **Severity:** High
- **Location:** plan.md `effort: 14d`; phase-07 §"Note on Sequencing" mandates merge order `01,02,03,04,06 → 05 → 07 → 08`
- **Flaw:** Plan presents 7 FRs as parallel (~2 days each) for 14d total. But §Sequencing imposes: Phases 05 and 07 must merge AFTER 01-04+06 (because they share engine.rs / checker.rs touchpoints — see Finding 5). Phase 08 awaits all 7. Critical path = max(01..06) + 05 + 07 + 08 = 1.5d + 1d + 2d + 1d = 5.5d MINIMUM, assuming zero rebase cost. With 7 parallel PRs all rebasing onto each other's merges, expect 1-2 hr rebase × 7 PRs = +1-2 days. R3-claimed parallel speedup is only 2.5x, not 7x.
- Add: R3's `scripts/create-worktrees.sh` (researcher-03 line 294-301) names branches `feat/fr014-sqli-scanner-v2`, `feat/fr015-ssrf-detection`, etc. — but FR-014 in this plan is XSS not SQLi, FR-015 is path traversal not SSRF. Plan §Phases table has correct names. Implementer running R3's script verbatim creates 7 wrongly-named branches, then has to manually rename. Phase 00 step 7 tells the implementer to use R3 "verbatim, substituting branch names" — that's NOT verbatim.
- Add: 7 worktrees all sharing `target/` will collide. R3's `setup-worktree-env.sh` (line 332-350) sets `CARGO_TARGET_DIR=$WORKTREE_PATH/target` per-worktree — good — BUT registry locks (`~/.cargo/registry/index/.cargo-mutate-monitor`) and git index locks remain shared. 7 simultaneous `cargo build` first-time runs serialize on registry lock anyway.
- **Failure scenario:** Hackathon timeline slips. Plan owner promised 14d for "production grade, not POC" — actual realistic timeline 18-22d once rebases + serialization + the `evaluate→inspect` rename + serde_json fix + engine.rs vec! conflicts are accounted.
- **Evidence:**
  - phase-07 line 178: `Recommended merge order: 01, 02, 03, 04, 06 → 05 → 07 → 08`.
  - `plans/.../research/researcher-03-llvm-cov-and-worktree.md:294-301`: branch names mismatch FR meanings.
  - phase-00 line 94: "verbatim, substituting branch names to match this plan's table" — internally inconsistent ("verbatim" ≠ "substituting").
- **Suggested fix:** (a) Drop "14d" estimate → state "5.5d critical path + rebase margin". (b) Inline corrected `create-worktrees.sh` directly in phase-00 instead of pointing at R3. (c) Add a §"Concurrent build budget" note: at most 3 parallel `cargo` runs during hot phase (registry contention) — schedule worktree builds rather than fanning out 7.

---

## Finding 11: FR-018 `same-IP only` is explicitly MVP — contradicts "Production-grade, NOT MVP" claim

- **Severity:** Medium
- **Location:** plan.md "Goal" line 18 ("Production-grade, not POC"); plan.md §Out of Scope ("Distributed brute force across N IPs (FR-018 — same-IP only for v1)")
- **Flaw:** Plan opens by branding the deliverable "production-grade, NOT MVP", then immediately scopes FR-018 to single-IP detection — which means any attacker using a $5/mo proxy rotation bypasses the check 100%. That IS the MVP definition for credential-stuffing detection. Production-grade brute-force protection requires either (a) per-username sliding window across all IPs, OR (b) credential-pair caching (seen-before password+username detection).
- **Failure scenario:** Stakeholder reads "Production-grade FR-018 ships in 14d", deploys behind public login endpoint, attacker uses Bright Data residential proxies, every login attempt is from a new IP, BF-001 never fires, account takeover succeeds. Customer escalation: "I thought you said production-grade?"
- **Evidence:**
  - plan.md line 18: "Production-grade, not POC" applied to ALL 7 FRs.
  - plan.md line 84: "Distributed brute force across N IPs (FR-018 — same-IP only for v1)".
  - Same internal contradiction in phase-07 §Risks last row ("Distributed brute force unmitigated — Likelihood: High, Impact: Low") — labelling Impact:Low for the most common credential-stuffing pattern is mis-calibrated.
- **Suggested fix:** Either (a) add FR-018 v2 (per-user-across-IPs) to in-scope, raising effort estimate, or (b) downgrade FR-018 in plan to "MVP/v1" explicitly and drop the "production-grade" framing for FR-018 specifically.

---

## Verified vs Failed Claims Summary

| # | Plan claim | Verdict | Evidence |
|---|---|---|---|
| 1 | `dashmap = "6"` at Cargo.toml:52 | ✓ VERIFIED | Cargo.toml:52 |
| 2 | `ipnet = "2"` at Cargo.toml:54 | ✓ VERIFIED | Cargo.toml:54 |
| 3 | `parking_lot` "already used (sql_injection_scanners)" | ✗ FAILED | Finding 3 — used elsewhere, not there |
| 4 | Pingora response_filter at proxy.rs:429 | ✓ VERIFIED (signature only) | proxy.rs:429 — but headers-only, see Finding 6 |
| 5 | Phase enum at types.rs:131-157 | ✓ VERIFIED | types.rs:131-157 |
| 6 | DefenseConfig at types.rs:305-342 | ✓ VERIFIED | types.rs:305-342 |
| 7 | `request_targets()` provides recursive variants | ✓ VERIFIED | mod.rs:95-150 |
| 8 | Phase 02 mostly adopts existing helper | ✓ VERIFIED | dir_traversal.rs:64-94 still uses bespoke single-decode |
| 9 | "FR-013 SQLi DONE" | ✓ VERIFIED | sql_injection_acceptance.rs has 63 test fns |
| 10 | "Phase 00 zero shared edits in FR PRs" | ✗ FAILED | Finding 5 — engine.rs vec![] is unaddressed |
| 11 | `cargo-llvm-cov 0.8.5 --fail-under-lines bug` | PARTIAL | Real per existing CI comment, but only when combined with `--ignore-filename-regex` |
| 12 | `serde_json::Deserializer::set_recursion_limit` exists | ✗ FAILED | Finding 4 — only `disable_recursion_limit` exists |
| 13 | `WafEngine::evaluate()` exists | ✗ FAILED | Finding 1 — method is `inspect` |
| 14 | `host_config.host` whitelist available | ✓ VERIFIED | types.rs:198 |
| 15 | R3 `create-worktrees.sh` reusable verbatim | ✗ FAILED | Finding 10 — branch names misspelled |
| 16 | 14-day effort sane | ✗ FAILED | Finding 10 — sequencing forces 5.5d critical path + rebase tax |
| 17 | "Production-grade, NOT MVP" all 7 FRs | PARTIAL | Finding 11 — FR-018 is single-IP MVP |

**Total: 17 claims tested. Verified: 8. Failed: 8. Partial: 2.**

---

## Unresolved Questions

1. If engine.rs vec![] is the true shared file (Finding 5), should Phase 00 land all 4 stub registrations + scanner_state + bf_state together, OR should the plan abandon the parallel-PR narrative and switch to a sequential merge train?
2. For Finding 6 (response body access), is there appetite to add `Arc<WafEngine>::on_response()` into `response_body_filter` (proxy.rs:472) accumulating bytes up to `body_preview_limit`, or is FR-018 acceptable as status-only (drop body-regex matching from spec)?
3. For Finding 4 (serde_json), is adding `serde-stacker` acceptable, or do we lower `max_json_depth` to 64 and document the gap?
4. For Finding 8, what is the actual current waf-engine line coverage today? (No measurement exists in repo — first concrete measurement should precede gating.)
5. For Finding 11, is FR-018 v1 explicitly an MVP (acceptable for hackathon) or is "Production-grade" a hard contract (then scope must grow)?

---

**Status:** DONE
**Total findings:** 11 (Critical: 4, High: 4, Medium: 3)
**Verified claims:** 8 | **Failed:** 8 | **Unverified→Now Verified:** 1 (serde_json — confirmed FAILED)
