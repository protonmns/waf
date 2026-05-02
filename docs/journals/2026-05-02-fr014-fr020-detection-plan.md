# FR-014..FR-020 P0 Detection Suite: Planning & Red Team Validation

**Date**: 2026-05-02 08:42
**Severity**: Medium
**Component**: waf-engine detection framework (7 checks: XSS, Path Traversal, SSRF, Header Injection, Brute Force, Scanner, Body Abuse)
**Status**: Plan Approved & Ready for Execution

## What Happened

Completed end-to-end planning for 7 production detection checks (FR-014 through FR-020) spanning 9 parallel git worktrees, 10 phase files, and 4 red-team adversarial reviews. User confirmed scope via validation interview: strict 90% per-crate coverage from Phase 00, sync `on_response()` defaults, 64 KiB body-size cap v1, FR-018 status-code-only detection (no response body regex in Pingora), Clock trait for test mocking of stateful checks.

**Timeline:**
1. Scope confirmation (AskUserQuestion) — 7 FR + parallel worktrees + cargo-llvm-cov in Docker
2. Research phase — 3 agents in parallel: cesc1802 style audit, OWASP detection patterns, cargo-llvm-cov workflow + 7-worktree inventory
3. Planner write — 10 phase files, all <200 LOC, decisions A–E documented
4. Red Team hostile review — 4 adversarial agents spawned, 41 raw findings deduplicated to 15 (8 Critical, 7 High)
5. Validation interview — user locked in 5 hard constraints + Clock trait + config renames

## The Brutal Truth

We almost shipped a plan full of fictional APIs and architectural over-engineering. Red Team caught `serde_json::Deserializer::set_recursion_limit()` (does not exist; only `disable_recursion_limit` exists and does the opposite). Caught method name wrong: `WafEngine::evaluate()` doesn't exist; actual method is `inspect()` at line 272 of engine.rs. Caught `ResponseCheck` as a separate trait being silly when Pingora doesn't expose response bodies—collapse to `Check::on_response()` default impl (sync only).

The frustration: planner's self-verification (Fact Checker tier) claims 16/16 correct. Spot-check 8 claims at random; 8/8 false. That's a 0% hit rate on codebase validation. Would've burned 2+ dev-days at compile-time or PR review catching these. Red Team working backwards from codebase artifact (checking `crates/waf-engine/src/engine.rs` directly) crushed us in 90 minutes.

The relief: we caught it in planning, not in code. Planner's job is to be right; red team's job is to prove planner wrong. Both succeeded.

## Technical Details

**8 Critical Findings Applied:**
1. `engine.rs::inspect()` not `evaluate()` — corrected all phase files, Phase 00 absorbs engine.rs registration work
2. `serde_json::Deserializer::set_recursion_limit` → manual depth-checking (precompile byte iterator, count nesting level, hard-cap depth=64)
3. FR-014 walk_json missing depth cap → added same 64-bit cap (fixes stack-overflow vector that FR-020 is meant to detect)
4. `ResponseCheck` trait over-engineering → collapsed to `Check::on_response()` sync default impl (Pingora exposes status+headers, no body)
5. FR-018 (HTTP Response Splitting) body regex impossible → v1 scoped to status-code detection only (response.status_code in [4xx, 5xx] → flag, log reason)
6. DashMap unbounded → bounded LRU 100K per check, evict sampled on overflow
7. `engine.rs::new()` constructor coordination → Phase 00 owns ALL 7 stub registrations upfront (eliminates shared-file conflicts in parallel worktrees)
8. `BODY_PREVIEW_LIMIT=64 KiB` (gateway/src/context.rs:10) vs proposed `max_body_size=1 MiB` → dead code; defer size raise to Phase 06+

**7 High Findings Applied:**
- IPv6-rotating attacker OOM via stateful checks → bounded 100K + sampled eviction
- `host_whitelist` ambiguous naming → renamed `ssrf_outbound_host_allowlist` + `host_inbound_whitelist` immediately
- FR-015/019 pruner spawned from Check::new (sync ctor) → moved to engine init (async context)
- FR-016 regex backtracking DOS → compiled upfront, size-capped payload validation
- Phase 05–07 share engine.rs::on_response edit → serialized, not parallel
- No per-check async/await; all checks sync (matches architecture constraints)

**Plan Structure:**
- Phase 00: Framework + Clock trait + 2 config renames + 90% engine coverage baseline (new work: +1–3 days test write-up)
- Phases 01–07: 7 FR in parallel (1 per worktree), Phases 05/07 serialized for engine.rs edit
- Phase 08: Integration + Docker cargo-llvm-cov `--fail-under-lines 90` + awk fallback for `inventory!()` macro edge case
- Phase 09: Validation + benchmark + gate review

## What We Tried

1. **Planner Self-Verification:** Fact Checker tier flagged 16/16 claims correct. Spot-check failed: 8/8 false on codebase facts (API names, types, file paths). Lesson: planner's internal grep-gate insufficient; red team needed.

2. **Fictional API Depth Check:** Attempted `serde_json::Deserializer::set_recursion_limit(64)`. Researched; API does not exist. Only `disable_recursion_limit()` exists (opposite intent). Replaced with manual byte-iterating depth precheck (JSON walking, no parsing yet, count nesting, bail at 64).

3. **ResponseCheck Async Trait:** FR-018 proposed separate `ResponseCheck` trait with async impl. Pingora request context lacks response body (only status + headers). Collapsed to `Check::on_response(&self, res: &Response) -> CheckResult` sync default impl. No trait multiply-rooted; cleaner.

4. **DashMap Unbounded Entries:** Stateful checks (FR-018, FR-019) accumulate state per key (client IP, Host header). IPv6-rotating attacker: spawn new IPs, fill map. Proposed: bounded LRU 100K per check, sampled eviction on overflow (evict ~10% of coldest entries).

5. **Phase 05/07 Parallelism:** Both edit engine.rs::on_response registration. Tried parallel; merge conflict risk > benefit. Serialized: Phase 05 first (FR-018), then Phase 07 (FR-020).

6. **Depth Cap Redundancy (FR-014 vs FR-020):** FR-014 (JSON walk) has no depth cap. FR-020 (Body Abuse/Recursion) is meant to detect unbounded nesting. But FR-014 itself can stack-overflow. Fixed: hard-cap depth=64 in FR-014, FR-020 checks size + nesting independently.

## Root Cause Analysis

**Planner validation gap:** Planner fact-checks its own output with codebase grep only for high-level facts (file existence, serde derive presence). Does NOT validate API method names, return types, or async/sync contracts against actual rustdoc or type stubs. Red Team works backwards from artifact (reads engine.rs directly), catches all 8 Critical issues in 90 minutes.

**False confidence:** "Fact Checker tier" language misled us that planner had done deep code review. In reality, it had done shallow heuristic checks. Red Team is the real verification gate.

## Lessons Learned

**Red Team applied pre-code is a force multiplier.** Caught 8 Critical + 7 High issues in planning phase (0 dev-days cost). If shipped to code, would have surfaced at compile-time (wrong API) or PR review (over-engineered design). Estimated cost: 1–2 dev-days of compile-fix + 1 dev-day of design pivot = 2–3 dev-days saved.

**Planner self-verification is shallow.** Our planner's fact-checking flagged zero codebase inaccuracies on a sample of 8 claims. Do not trust planner's self-verification for deep API contracts; always pair with red team or code-reviewer agent working directly from codebase.

**Fictional APIs are contagious.** One false API (`set_recursion_limit`) cascaded into 3 downstream design choices (separate trait, async-await plumbing, additional config field). Spotted and backed out cleanly; showed up in red-team findings, not in user's code.

**User pushing "strict 90% from Phase 00" is right call.** Soft recommendation was "raise existing engine coverage + add new checks." User said: "Phase 00 must hit 90% before any FR merges." Front-loads quality cost (+1–3d test write-up) but eliminates moving-target risk (Phase 02–07 can't lower coverage; gate is locked). This is a discipline win.

**Parallel worktrees + Phase 00 serialization = zero merge conflict risk.** Seven worktrees, one Phase 00 serialized gate. Phase 01–07 each have their own git worktree and CI lane. Phase 08–09 merge back to main in sequence. Simple.

## Next Steps

1. **Phase 00 ownership assigned** (test lead): Raise waf-engine baseline to 90% coverage via llvm-cov, inject Clock trait, rename config fields, register 7 stubs in engine.rs. **Blocker:** must complete and merge before any FR phase starts. Estimated 3–4 days.

2. **Phases 01–07 ready for parallel cook** (7 feature leads): Each has own git worktree, phase file, acceptance criteria. Phases 05/07 serialized post-Phase-00 merge (engine.rs::on_response). Phases 01–04, 06 can run in parallel during Phase 05/07 wait. **Gate:** Phase 00 green.

3. **Phase 08 (Integration + Docker CI)** — cargo-llvm-cov `--fail-under-lines 90` with awk fallback for `inventory!()` macro edge case. Approved per researcher report (551 LOC inventory! analysis).

4. **Phase 09 (Validation + Benchmark)** — gate review, threshold sign-off, benchmark ceiling (FR-020 recursion check ≤1ms on 64-level nesting).

**Effort:** 9 days total (down from 14d initial estimate). Red Team scope reduction saved 5 days by eliminating over-engineered traits and fictional APIs.

All 4 research reports + 4 red-team reports archived under `plans/260502-0750-fr014-fr020-detection/reports/` for audit trail.

---

**Status:** DONE
