# Red Team — Scope & Complexity Critic
## fr014-fr020-detection plan

Lens: YAGNI / KISS / DRY enforcement. Verifier: Contract correctness across all consumers.
Date: 2026-05-02. Reviewer: code-reviewer (hostile).

---

## Finding 1: ResponseCheck trait is a parallel pipeline built for ONE-AND-A-HALF callers

- **Severity:** Critical
- **Location:** Phase 00 ("Acceptance Criteria" + "Files to Modify"), Phase 05 §"Detection Rules" + Steps, Phase 07 §"Implementation Steps" + Note on Sequencing
- **Flaw:** Plan introduces a brand-new `pub trait ResponseCheck: Send + Sync` (Phase 00 step 6), wires it into `checker.rs` as a parallel `Vec<Arc<dyn ResponseCheck>>` dispatch loop (Phase 07 step 4), and modifies `engine.rs` to invoke the new pipeline from a Pingora response hook (Phase 07 step 5). Total scope: a new trait, new collection, new method on checker, new Pingora hook integration — for **one full implementor (FR-018 BruteForceCheck)** plus **one partial piggyback (FR-019 ScannerCheck record_response)**. Phase 05 even admits the response-side wiring "depends on Phase 07's pipeline" (Phase 05 Risks row 2), creating a hard cross-PR coupling. Phase 07 own §"Note on Sequencing" sets recommended merge order to "01, 02, 03, 04, 06 → 05 → 07 → 08" — confirming the parallelism claim of the architecture is false.
- **Failure scenario:** Two checks adopt a callback shape that invents abstraction at the worst moment — when there is exactly one consumer pattern. Future "FR-033/034/035 outbound checks" cited in Decision C (plan.md:26) are not in the work; YAGNI violation. The day someone adds an outbound RESPONSE-PHASE feature with different needs (header rewrite, body scanning), the trait shape will be wrong and rewritten anyway. Meanwhile the cross-PR coupling guarantees rebase pain in 5/7 of the "parallel" PRs.
- **Evidence:**
  - `crates/waf-engine/src/checks/mod.rs:34-36` shows the existing `Check` trait is single-method `fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult>`. Adding an optional response field to `RequestCtx` (or extending `Check` with a default-impl method `fn on_response(&self, _ctx: &RequestCtx, _status: u16, _body: &[u8]) {}`) would let FR-018 + FR-019 piggyback with **zero new traits and zero parallel pipelines**.
  - `crates/waf-engine/src/engine.rs:52,96-102` shows the existing dispatch is one `Vec<Box<dyn Check>>`. Default-impl-on-Check requires zero changes to construction; only the engine-side response-hook plumbing is needed.
  - Phase 05 Risks row 2 already flags this as "High likelihood / High impact" — the plan author saw it and proceeded.
- **Suggested fix:** Delete the `ResponseCheck` trait entirely. Add a default-impl method to `Check`:
  ```rust
  pub trait Check: Send + Sync {
      fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult>;
      fn on_response(&self, _ctx: &RequestCtx, _status: u16, _body: &[u8]) {}
  }
  ```
  Phase 07 then iterates the existing `checkers: Vec<Box<dyn Check>>` and calls `.on_response`. No new collection. No new dispatch. Phase 05's coupling vanishes. The "Phase 0 framework PR" no longer needs to declare a trait that is then `#[allow(dead_code)]`-flagged for two PRs (Phase 00 Risks row 2).

---

## Finding 2: Phase 00 framework PR is a manufactured merge gate, not a feature

- **Severity:** Critical
- **Location:** plan.md "Architectural Decisions" row A; Phase 00 entire file
- **Flaw:** Phase 00 is a 4-hour PR whose only purpose is "land all shared edits in ONE small PR so each downstream FR PR (01-07) only touches its own files." Its content: 4 enum variants, 4 stub `Check` impls returning `None`, 11 new `DefenseConfig` fields, a `ResponseCheck` trait stub flagged `#[allow(dead_code)]`, a Dockerfile.coverage, two shell scripts, and a CI job. Then Phase 05 immediately violates the "no shared edits" rule by adding 4 MORE config fields to `DefenseConfig` on its own branch (Phase 05 §"DefenseConfig Fields Used" admits: "New tunables (add in this phase, NOT Phase 00, since scoped to scanner)"). So Phase 00's design constraint is broken on the very first FR phase.
- **Failure scenario:** The "9 PRs not 7" overhead exists to avoid `inventory!` macro complexity (plan.md row A), but the inventory! complexity was a one-time learning cost. The chosen approach trades it for: (a) one merge gate that blocks 7 parallel branches, (b) two branches (`feat/fr-frame-detection-framework`, `feat/fr-frame-integration-tests`) that contribute zero detection capability, (c) stub modules that exist only to be replaced, (d) a trait that's `dead_code` for two PR merges, (e) the constraint that motivates Phase 00 (no shared file edits) is violated by Phase 05 anyway. Net result: 2 PRs of pure scaffolding overhead with the same merge-conflict surface as the simpler approach.
- **Evidence:**
  - Phase 05 line 41: "New tunables (add in this phase, NOT Phase 00 ... but these MUST be added on this branch alongside the impl)" — Phase 05 modifies `DefenseConfig` outside Phase 00. The conflict-prevention rationale collapses.
  - Phase 07 line 36: "This is shared with Phase 05 (which also uses `ResponseCheck`). Coordination: Phase 05 ships request-side only; Phase 07 lands the actual `ResponseCheck` dispatch loop." — Phase 07 shares `checker.rs` with Phase 05. Conflict still exists.
  - `crates/waf-engine/src/engine.rs:96-102` — adding a single `Box::new(SsrfCheck::new())` etc. is a 1-line change; trivial 3-way merge for Git.
- **Suggested fix:** Cut Phase 00 entirely. Each FR phase adds its own enum variant, its own `DefenseConfig` fields (already what Phase 05 does), its own `mod` declaration, and registers itself in `engine.rs`. The merge conflict on `engine.rs:96` "checkers vec" insertion is exactly the kind of trivial 1-line conflict Git auto-resolves or any human resolves in 30 seconds. The trait-stub gymnastics are unjustified for a 7-PR set.

---

## Finding 3: 11 new `DefenseConfig` fields — a backward-compat trap dressed as configurability

- **Severity:** High
- **Location:** Phase 00 §"DefenseConfig fields to add" + Phase 05 (4 more fields)
- **Flaw:** Plan adds 7 new boolean toggles + 8 tunables (window seconds, max-per-user, spray threshold, login-route list, max body size, max JSON depth, max JSON keys, X-F2 max hops, DNS timeout, etc.) to `DefenseConfig` — a struct that today (`crates/waf-common/src/types.rs:305-342`) has 11 boolean fields and 5 numeric tunables for the existing 9 detection checks. Adding another 15 fields nearly doubles its surface in one go. None of these tunables are user-requested; all are speculative ("hot-reloadable" thresholds for checks that don't exist yet).
- **Failure scenario:** (a) Every consumer of `DefenseConfig` (admin UI form, TOML loader, REST API, audit log redaction, hot-reload differ) must learn 15 new fields — a real cost born by `crates/waf-common/src/types.rs` consumers grep'd above (gateway, waf-engine, waf-api, tests). (b) The thresholds will be wrong — researcher hand-picked defaults are guesses; once shipped they become permanent. (c) Hot-reload claim is false: the plan keeps mentioning "Arc<ArcSwap>" pattern (plan.md row A "Aligns with existing `Arc<ArcSwap>` pattern"), but only **one** existing check (`sql_injection.rs`) uses ArcSwap — every other check reads `ctx.host_config.defense_config` per-request as a snapshot. Plumbing 15 fields through a "hot-reload pattern" that doesn't actually exist for new checks is cargo culting.
- **Evidence:**
  - `grep -rln "ArcSwap" crates/waf-engine/src/checks/` returns ONLY `sql_injection.rs`. Every other check (xss, dir_traversal, scanner, bot, rce, etc.) takes the snapshot from `ctx.host_config.defense_config` at request time. Plan's "Arc<ArcSwap>" alignment claim is a misread.
  - `crates/waf-common/src/types.rs:305-342` — current `DefenseConfig` has 11 booleans + 5 tunables. Adding 11 more nearly doubles it.
  - Phase 06 §"Implementation Steps" line 49: "no internal state; reads thresholds from `ctx.host_config.defense_config` per request — supports hot-reload natively" — this is the snapshot pattern, NOT ArcSwap. Plan author knows this; the architectural decision text on plan.md is misleading.
- **Suggested fix:** Drop tunables to ONLY the on/off boolean per check (7 fields, not 15). Bake other thresholds in as `const` for v1 (e.g., `const BF_WINDOW_SECS: u64 = 900;`). When a real operator complains about a threshold, promote it to `DefenseConfig` with evidence. This is YAGNI 101 and matches the existing pattern: most checks have ONE bool field in `DefenseConfig`; only `cc` has tunables — and those exist because they were operationally tuned (plus comment at types.rs:332-341 explaining the tradeoff).

---

## Finding 4: `<check>_patterns.rs` + `<check>_scanners.rs` triplet — premature splitting

- **Severity:** High
- **Location:** plan.md §"Cross-Cutting NFRs" line 53 ("split into `<check>.rs` + `<check>_patterns.rs` + `<check>_scanners.rs` if needed"); Phase 03 §"Files to Create" (3 ssrf files), Phase 04 §"Files to Create" (2 header_injection files), Phase 06 §"Files to Create" (2 body_abuse files), Phase 07 §"Files to Create" (3 brute_force files)
- **Flaw:** The "triplet" pattern is cited as "mirrors `sql_injection*` triplet". But `sql_injection_*` files exist because `sql_injection.rs` is 276 LOC with `_patterns.rs` 154 LOC and `_scanners.rs` 235 LOC — a real concern of file growth at ~600 combined LOC AND a real reason (libinjection bindings + custom regex engine + JSON walker are 3 distinct concerns). The plan applies this triplet to checks that are ESTIMATED at 80-140 LOC each (Phase 03: 120+80+100=300 LOC; Phase 04: 140+40=180 LOC; Phase 06: 140+100=240 LOC; Phase 07: 140+120+80=340 LOC). At those sizes, ONE file would be under or barely over the 200-LOC modularization target — and the modularization rule (CLAUDE.md) says "consider modularizing", not "preemptively split into 3".
- **Failure scenario:** (a) Forced 3-file modules add navigation cost — every new check is `mod check; mod check_patterns; mod check_scanners` import dance. (b) Public API surface bloat: e.g., `extract_username` and `truncated_hash` get pulled into separate files for FR-018 even though they're 5-10 line helpers used in one place. (c) Future maintainers see the split and can't tell whether it was justified or cargo-culted from sql_injection. (d) Coverage becomes harder to reason about — a single 80-LOC `_patterns.rs` file with `LazyLock<RegexSet>` constants will have line coverage of 100% trivially or 50% trivially depending on whether tests exercise the patterns; small files distort the per-crate coverage average.
- **Evidence:**
  - `wc -l crates/waf-engine/src/checks/*.rs` shows existing checks span 154-878 LOC. Only `owasp.rs` (878), `scanner.rs` (302), `sql_injection.rs` (276), `anti_hotlink.rs` (263), `geo.rs` (256), `cc.rs` (257), `sensitive.rs` (243) exceed 200. Smaller checks (`bot.rs` 209, `rce.rs` 178, `dir_traversal.rs` 161, `xss.rs` 174) live in single files. The codebase pattern is "single file unless really large", not "always triplet".
  - The plan estimates for new checks (120-340 LOC combined) all fall in the "single file is fine" range based on existing precedent.
- **Suggested fix:** For Phases 03/04/06/07, default to ONE file per check. Split only after `cargo check` shows it crossed 200 LOC AND review finds two genuine concerns. Phase 04 already did this right ("No scanners.rs file — header iteration is straightforward, doesn't justify split." — line 33); apply same judgment to other phases.

---

## Finding 5: Phase 07 BruteForce — pre-resolved by spawning unsupervised tokio tasks in `Check::new`

- **Severity:** High
- **Location:** Phase 07 §"Implementation Steps" step 6, Phase 05 §"Implementation Steps" step 3
- **Flaw:** Both Phase 05 (ScannerCheck) and Phase 07 (BruteForceCheck) say: "Spawn background pruner: `tokio::spawn` task in `<X>Check::new` ... Notify-driven shutdown." But `Check::new` is called once during `WafEngine::with_sqli_config` (engine.rs:96-100) inside what is currently a synchronous-construction pattern. There is NO `Drop` notify wiring in the existing checks. The plan invents a lifecycle (background tasks tied to check construction with shutdown via `Notify`) that does not exist anywhere in the codebase today.
- **Failure scenario:** (a) Tests construct `XssCheck::new()` etc. dozens of times — if Phase 05/07 follow this pattern in tests, each test spawns leaked tokio tasks. (b) `Drop` impl on `BruteForceCheck` that triggers `Notify` requires an `Arc<Notify>` field; if the check is wrapped `Arc<dyn Check>` (which it is — `Vec<Box<dyn Check>>` per engine.rs:52), the Drop fires only when the engine drops — fine — but the construction-time spawn fires on EVERY test that builds a check. (c) The `tokio::spawn` requires a runtime; constructing a check outside `#[tokio::test]` (e.g. in benchmark setup) panics. None of the existing checks have this footgun.
- **Evidence:**
  - `crates/waf-engine/src/engine.rs:96-102` — Vec construction is synchronous; no current check does `tokio::spawn` in `new`.
  - `crates/waf-engine/src/checks/cc.rs` (existing rate limiter, cc.rs is 257 LOC) is the most analogous existing check — it uses interior mutability (`parking_lot` mutex on token bucket) and does NOT spawn a background pruner, instead pruning lazily on each request. Same pattern would work for FR-018 / FR-019.
- **Suggested fix:** Cut the background pruner. Prune-on-access: every `record_failed` and `record_response` call also evicts entries older than the window before inserting. Bound the dashmap size with an LRU cap (already mentioned in Phase 05 risk #1). Zero background tasks. Zero Drop gymnastics. Zero test-runtime hazards. Matches existing CC pattern.

---

## Finding 6: ≥20-25 tests per check, ≥90% coverage, p99 < 200µs — picking three numbers that each look reasonable but together over-constrain

- **Severity:** High
- **Location:** Phase 01-07 §"Test Matrix" headers ("target ≥20", "≥22", "≥25" tests); plan.md "Cross-Cutting NFRs" (90%, 200µs); Phase 00 §"Coverage Requirement"
- **Flaw:** Three quantitative gates are imposed on every new check. None has empirical justification:
  - **≥90% per crate** — hard target. Existing `waf-engine` crate has 14 check modules + checker.rs + engine.rs + rules subsystem + crowdsec + community + plugins + geoip — coverage today is unmeasured (no existing CI gate). Going from "no gate" to "90% per crate" in one sweep, on a crate with 3700+ LOC of unmeasured code (`wc -l crates/waf-engine/src/checks/*.rs` total: 3772), will fail on day 1 due to uncovered helper code outside the new checks. Plan ASSUMES the existing crate is already at 90% — there is zero verification.
  - **≥20-25 tests per check** — quantity is not quality. Plan dictates a count but not the equivalence-class coverage; reviewers cannot tell if 20 contrived inputs actually exercise the boundary. Test-count-as-quality is a known anti-pattern.
  - **p99 < 200µs per check, p99 < 1ms aggregate** — the only existing bench is `crates/waf-engine/benches/sql_injection.rs`. There is NO baseline p99 for the existing 14 checks. Setting 200µs without knowing what `xss.rs` or `dir_traversal.rs` measure today guarantees one of two outcomes: (a) the gate is loose and means nothing, or (b) the gate flaps in CI on whatever runner happens to be slow that hour.
- **Failure scenario:** (a) Phase 00 PR is supposed to be 4 hours; instead it spends a week tuning the coverage gate to not fail on the existing waf-engine crate. (b) Reviewers waste cycles arguing about whether test #21 in xss.rs is genuinely necessary. (c) CI flakes 1-2% of the time on the bench gate, the team adds `continue-on-error: true` (Phase 00 step 8 already does this!), the gate becomes informational, the gate is meaningless. (d) ≥90% per-crate is enforced but encourages tests-for-coverage (testing serde derives, testing `Default`) instead of attack-vector coverage.
- **Evidence:**
  - `ls /Users/admin/lab/mini-waf/crates/waf-engine/benches/` shows only `access_lookup.rs, relay_eval.rs, rule_eval.rs, sql_injection.rs` — 4 benches, none of them on the 14 detection checks. NO baseline.
  - Phase 00 step 8: "set `continue-on-error: true` for one PR; flip to hard gate from Phase 01 merge onward" — author already anticipates the gate isn't viable on day 1.
  - Phase 00 Risks row 3: "Coverage Docker image first-build slow (~5min)" — operational friction acknowledged.
- **Suggested fix:** (a) Replace per-crate 90% with per-NEW-FILE 80% (measured by `--include-files` against the new check files). Existing crate coverage is out of scope for this work. (b) Replace "≥20 tests" with a minimum equivalence-class checklist (one per attack vector, one boundary case, one false-positive avoider, one disable-toggle test) — 5-8 hand-picked tests > 20 contrived ones. (c) Drop the p99 gate to "no regression vs main" rather than absolute µs. Defer absolute targets to Phase 08 where we have the full pipeline measured.

---

## Finding 7: `Dockerfile.coverage` + 4 shell scripts + new CI job — toolchain bureaucracy for a 7-feature ship

- **Severity:** Medium
- **Location:** Phase 00 §"Files to Create" rows 5-8, plus `.github/workflows/ci.yml` modification
- **Flaw:** Plan adds:
  - `Dockerfile.coverage` (new, separate from existing `Dockerfile` and `Dockerfile.prebuilt`)
  - `scripts/coverage-gate.sh` (custom awk parser because `cargo-llvm-cov --fail-under-lines` has a bug per R3§Sec1)
  - `scripts/create-worktrees.sh` (creates 7 worktrees from origin/main)
  - `scripts/setup-worktree-env.sh` (sets `CARGO_TARGET_DIR`)
  - New `coverage` CI job
  
  Plus the cwd verifies only two existing Dockerfiles (`Dockerfile`, `Dockerfile.prebuilt`) and only 4 nginx/k6 config files in `scripts/`. The plan adds 4 new shell scripts to a directory that today contains zero shell scripts — these are one-off scripts that will rot.
- **Failure scenario:** (a) `Dockerfile.coverage` will diverge from `Dockerfile` over time (Rust version, deps, cache layer order); coverage runs that pass don't predict prod build success. (b) `scripts/create-worktrees.sh` is run ONCE at hackathon start by the team; after that it's dead code that no one removes. (c) `scripts/coverage-gate.sh` reimplements a stdlib coverage tool feature because of a bug — the simpler fix is to pin a working `cargo-llvm-cov` version OR run plain `cargo llvm-cov --summary-only` and grep the output in CI YAML, no script file. (d) Permanent maintenance cost on 4 files that exist to support 1 hackathon PR sequence.
- **Evidence:**
  - `ls /Users/admin/lab/mini-waf/Dockerfile*` returns `Dockerfile` and `Dockerfile.prebuilt` — adding `Dockerfile.coverage` is a third variant.
  - `ls /Users/admin/lab/mini-waf/scripts/` returns 4 nginx/k6 configs, NO existing shell scripts. Adding 4 new ones inverts the directory's purpose without precedent.
  - CLAUDE.md Section "Build & Test" lists `cargo fmt --all -- --check`, `cargo clippy --workspace ...`, `cargo test`, `cargo build --release` — coverage is not mentioned. Adding it as a hard gate in this plan elevates it without buy-in.
- **Suggested fix:** Add `cargo llvm-cov --workspace --summary-only --fail-under-lines 80` directly in the CI YAML if and only if the version-bug claim is verified. Drop `Dockerfile.coverage` — run coverage in the same Docker image as builds (extend with `cargo install cargo-llvm-cov`). Drop `create-worktrees.sh` — document the 4 git commands inline in plan.md (worktrees are a developer tool, not project infrastructure). Drop `coverage-gate.sh` — push the awk into the YAML step.

---

## Finding 8: Phase 08 integration PR is gold-plated with rule-pack YAML, ops docs, and Mermaid updates

- **Severity:** Medium
- **Location:** Phase 08 §"Files to Create" + §"Files to Modify"
- **Flaw:** Phase 08 ships:
  - `crates/waf-engine/tests/p0_detection_acceptance.rs` (e2e harness — JUSTIFIED)
  - `crates/waf-engine/benches/p0_detection.rs` (aggregate bench — JUSTIFIED)
  - `rules/p0-detection.yaml` (sample rule pack with `risk_score_delta` for each phase — NOT JUSTIFIED; speculative ops content)
  - `docs/p0-detection-rulepack.md` (operator-facing reference NEW — NOT JUSTIFIED; no operator has asked)
  - `docs/codebase-summary.md` update (justified)
  - `docs/request-pipeline.md` Mermaid extension (justified if request-pipeline.md exists; needs verification)
  - `CHANGELOG.md` update (justified)
  
  The yaml + the new docs file are scope creep for a "P0 detection suite" task. Each FR PR could ship its own one-line CHANGELOG entry; an aggregate doc page can wait for an operator request.
- **Failure scenario:** (a) `rules/p0-detection.yaml` introduces an opinionated default risk-score-delta per phase (e.g. SSRF=90, BF=60). These numbers are guesses. Once shipped they're frozen unless someone justifies changing them. (b) `docs/p0-detection-rulepack.md` is documentation written for users who don't exist yet; it will be wrong by the time someone reads it. (c) Phase 08 ships a `cargo test` assertion that bench p99 < 1ms (`benches/p0_detection.rs` step 2: "Assert (in test, not bench): p99 < 1ms via `criterion::Criterion::with_filter`") — criterion benches in CI are flaky at µs precision; this gate WILL flap.
- **Evidence:**
  - Phase 08 §"Implementation Steps" step 3 yaml block hard-codes phase=>risk_score with no source citation — "P0-SSRF-001 ... risk_score_delta: 90  # higher: SSRF often catastrophic (Capital One)" — this is a per-deployment policy decision masquerading as a code default.
  - `docs/codebase-summary.md` and `docs/request-pipeline.md` are listed in CLAUDE.md "Documentation Management" — those updates are appropriate. The NEW `docs/p0-detection-rulepack.md` is not listed in the documentation taxonomy.
- **Suggested fix:** Cut `rules/p0-detection.yaml` and `docs/p0-detection-rulepack.md` from Phase 08. Defer to operator-driven request. Cut the in-test p99 assertion — record the bench number, fail only on regression measured by a separate baseline file (or just skip in CI and run benches manually). Keep e2e harness, aggregate bench, codebase-summary update, request-pipeline Mermaid update, CHANGELOG entries.

---

## Finding 9: Multiple "[UNVERIFIED]" markers in shipping plan = "we'll figure it out at PR time"

- **Severity:** Medium
- **Location:** Phase 04 step 3 ("[VERIFY in Phase 00 PR review]"), Phase 06 Risks row 1 ("[UNVERIFIED API surface]"), Phase 07 §"Files to Modify" ("[UNVERIFIED — depends on current Pingora integration]"), plan.md Unresolved Questions #4 ("[UNVERIFIED]")
- **Flaw:** Four explicit `[UNVERIFIED]` / `[VERIFY]` markers across phases for foundational facts: (a) does `RequestCtx` expose SNI? (b) does `serde_json` support `set_recursion_limit` at the pinned version? (c) does `engine.rs` actually have a Pingora response hook? Plan proceeds to schedule estimates (1d, 1.5d, 2d) and PR shapes assuming the answers are favorable. If the SNI answer is "no", Phase 04 Rule 3 collapses to whitelist-only — half the FR-017 scope. If the recursion_limit answer is "no", Phase 06 builds a custom `Value` walker — different file, different bench, different LOC. If the engine response-hook answer is "no", Phase 07 cannot land — a 2-day estimate becomes an unscoped rabbit hole.
- **Failure scenario:** Hackathon mode + unverified foundations = phases that get re-planned during the PR. "Mid-flight" replanning of Phase 06 or Phase 07 dominoes Phase 08 (integration tests assume specific phase shapes per Phase 08 §"Test Matrix" rows 5-7).
- **Evidence:**
  - Phase 07 line 38: "VERIFY existing engine entry-points [UNVERIFIED — depends on current Pingora integration; trace before implementing]" — and Phase 07 §"Risks" row 1 admits this could require "additional Phase 0.5".
  - Phase 06 Risks row 1: "Verify API exists in current serde_json version. [UNVERIFIED API surface]"
  - `crates/gateway/src/proxy.rs:429` does have `async fn response_filter` — partial verification, but the path from there to invoking `WafEngine::on_response` is not the same as having that hook today. The UNVERIFIED is real.
- **Suggested fix:** A 30-minute investigation BEFORE the plan is "done" can resolve all 4. Specifically: (1) `grep -n "sni\|server_name" crates/waf-common/src/types.rs crates/gateway/src/` answers SNI. (2) `cargo doc -p serde_json --no-deps` and check `Deserializer::set_recursion_limit` answers serde_json. (3) Read `crates/gateway/src/proxy.rs:429-500` to confirm the response_filter signature and what's plumbed into WafEngine. Three greps, ten minutes — eliminates 3 risks worth 1+ phase-day of slip each. Plan should not be approved with these markers.

---

## Finding 10: 14d effort for what is effectively 7 single-purpose pattern-checkers — soft-budget concealing fat

- **Severity:** Medium
- **Location:** plan.md frontmatter `effort: 14d`; per-phase efforts (1d + 1d + 1.5d + 1d + 1d + 1.5d + 2d + 1d = 10d for FR work + 4h Phase 00 + 1d Phase 08 = ~11.5d total FR effort)
- **Flaw:** Plan declares 14 days. Sum of phase efforts is ~11.5d. The 2.5d gap is unexplained. More importantly, several of the FR phases are effectively `<200 LOC of pattern matching` against existing `request_targets()` infrastructure — Phase 02 (path traversal) admits this: "Replace bespoke decode loop with `super::request_targets(ctx)`" and add 6 regex patterns. That is hours, not days. Phase 01 (XSS) similarly: walk JSON leaves through XSS_SET. Phase 04 (header injection) is a single-file iterator over headers with two regex sets. The day-budget reflects the test-count and bench gates (Finding 6) more than the actual code.
- **Failure scenario:** When a hackathon team sees "1.5d for FR-016", they spend 1.5d. Parkinson's law. The plan's structural gates (≥25 tests, ≥90% coverage, p99 bench, triplet split, framework PR) consume the budget, leaving the actual detection logic shallow.
- **Evidence:**
  - Phase 02 step 1: "Replace bespoke decode loop with `super::request_targets(ctx)` (already gives raw + decoded + recursive-decoded for path/query/cookie/body)" + step 2: 6 new regex patterns added to existing `DIR_TRAVERSAL_SET`. Total code change: ~30 LOC.
  - `crates/waf-engine/src/checks/dir_traversal.rs` is 161 LOC; the proposed change keeps it under 200, no split, no new file. Yet 1d budget.
  - Phase 04 estimated 140 LOC main + 40 LOC patterns = 180 LOC for header injection across 22 tests + bench. Budget 1d. Reasonable IF tests dominate, but tests are usually 2-3x impl LOC; this implies 360-540 test LOC, on top of the existing crate test infrastructure.
- **Suggested fix:** Re-budget at 7d total: 0.5d × 7 FR phases for the actual logic + 1.5d for shared bench/integration + 2d slack = 7d. Reclaim the gap. If the team wants 14d, they should explicitly own that they are buying gold-plating (15 config fields, dockerfile.coverage, ResponseCheck trait, Phase 0 framework, Phase 8 ops docs). Make the trade explicit, don't hide it in the gate stack.

---

## Summary by severity

| Severity | Count | Findings |
|---|---|---|
| Critical | 2 | F1 (ResponseCheck trait), F2 (Phase 00 framework PR) |
| High | 4 | F3 (15 DefenseConfig fields), F4 (forced triplet split), F5 (background tokio tasks in `Check::new`), F6 (3 quantitative gates with no baseline) |
| Medium | 4 | F7 (Dockerfile.coverage + scripts), F8 (Phase 08 yaml + ops docs), F9 (4 UNVERIFIED markers), F10 (14d budget concealing fat) |

## Single largest cut
Eliminate Phase 00 + the `ResponseCheck` trait. Replace with: (a) default-impl method `on_response` on existing `Check` trait, (b) each FR PR adds its own `Phase` enum variant + `DefenseConfig` boolean + `mod` line + `engine.rs:96` registration — exactly the conflict surface the plan tried to engineer away, but trivially mergeable. Net: 2 fewer PRs, 1 fewer trait, ~15 fewer config fields, no parallel pipeline, no merge gate.

## Unresolved questions
1. Has anyone measured current `waf-engine` crate coverage? If <90%, the per-crate gate is a re-write project, not a feature gate.
2. Does the existing CI runner support `cargo bench` reliably enough to gate on µs-precision p99? If not, all bench gates flap.
3. Is "Capital One" CVE-driven SSRF (FR-016) actually a hackathon-scope priority, or speculative? Researcher cite suggests yes; product priority list doesn't appear in plan files reviewed.
4. The plan mentions FR-018 hot-reload (Phase 07 test #11) — which TOML/REST mechanism reloads `bf_max_per_user` mid-flight today? No evidence the plumbing exists; this test may not be implementable as written.

**Status:** DONE
**Total findings:** 10 (Critical: 2, High: 4, Medium: 4)
