---
phase: 08
title: "Integration: e2e acceptance suite + aggregate bench + docs"
status: pending
priority: P1
effort: 1d
dependencies: [00, 01, 02, 03, 04, 05, 06, 07]
branch: feat/fr-frame-integration-tests
fr: integration
---

## Overview

Final phase. Validates all 7 P0 detection checks fire correctly through the full `WafEngine::inspect()` pipeline, measures aggregate p99 budget (sum of all checks < 1ms), publishes a sample rules pack, and updates project documentation.

## Acceptance Criteria

- All 7 attack vectors caught end-to-end via public `WafEngine::inspect()` API
- Aggregate p99 latency (running all 7 checks back-to-back) < 1ms
- `rules/p0-detection.yaml` sample rule pack loads via existing rule engine
- `docs/codebase-summary.md` and `docs/request-pipeline.md` reflect 4 new Phase variants
- `CHANGELOG.md` has dated entries for FR-014..FR-020

## Files to Create

- `crates/waf-engine/tests/p0_detection_acceptance.rs` — end-to-end test harness (≤200 LOC, modularized via helper fn `attack_request(kind: AttackKind) -> RequestCtx`)
- `crates/waf-engine/benches/p0_detection.rs` — aggregate criterion bench (≤80 LOC)
- `rules/p0-detection.yaml` — sample rule pack with risk-score deltas for each new phase
- `docs/p0-detection-rulepack.md` — operator-facing reference (NEW; explains each rule_id, default thresholds, tuning guide)

## Files to Modify

- `docs/codebase-summary.md` — add row for new checks under "waf-engine"
- `docs/request-pipeline.md` — update pipeline diagram (Mermaid) to show 4 new Phase variants in execution order
- `CHANGELOG.md` — add `## [Unreleased]` block with one bullet per FR ID

## Implementation Steps

1. Author `tests/p0_detection_acceptance.rs`:
   - Build `WafEngine` with default `HostConfig` (all defenses on)
   - 7 test fns: `fr_014_xss_blocks_json_payload`, `fr_015_path_traversal_blocks_double_encoded`, `fr_016_ssrf_blocks_aws_metadata`, `fr_017_header_injection_blocks_crlf`, `fr_018_brute_force_blocks_after_5_failures`, `fr_019_scanner_blocks_options_abuse`, `fr_020_body_abuse_blocks_oversize`
   - Each: build `RequestCtx`, optionally trigger `engine.on_response` for stateful tests, call `engine.inspect()`, assert `WafDecision::action == WafAction::Block` and `result.phase == Phase::<expected>`
2. Author `benches/p0_detection.rs`:
   - Setup: 1 representative `RequestCtx` per attack vector
   - Criterion group `p0_aggregate`: bench full `inspect()` → records aggregate
   - Assert (in test, not bench): p99 < 1ms via `criterion::Criterion::with_filter`
3. Author `rules/p0-detection.yaml`:
   ```yaml
   rules:
     - id: P0-XSS-001
       phase: xss
       action: block
       risk_score_delta: 80
     - id: P0-SSRF-001
       phase: ssrf
       action: block
       risk_score_delta: 90  # higher: SSRF often catastrophic (Capital One)
     - id: P0-BF-001
       phase: brute_force
       action: challenge
       risk_score_delta: 60
     # ...etc, one per phase
   ```
4. Update `docs/codebase-summary.md`: append a "Detection Checks (FR-014..FR-020)" subsection listing all 7 with file paths
5. Update `docs/request-pipeline.md`: extend Mermaid diagram with new phase nodes
6. Update `CHANGELOG.md`:
   ```markdown
   ## [Unreleased]
   ### Added
   - feat(detection): FR-014 XSS JSON walker + form-urlencoded scanner
   - feat(detection): FR-015 path traversal recursive decode + OS-specific targets
   - feat(detection): FR-016 SSRF check (RFC1918, metadata, obfuscated IPs)
   - feat(detection): FR-017 header injection (CRLF, Host, X-F2)
   - feat(detection): FR-018 brute force + credential stuffing (ResponseCheck pipeline)
   - feat(detection): FR-019 scanner recon (4xx burst, endpoint enum, OPTIONS abuse)
   - feat(detection): FR-020 request body abuse (size, JSON depth/keys, CT mismatch)
   - feat(coverage): per-crate >=90% line coverage gate (Docker)
   ```
7. Smoke: `cargo test --workspace`, `cargo bench -p waf-engine --bench p0_detection`, `docker run --rm prx-waf:cov` for full coverage check
8. `gh pr create --title "feat(detection): P0 integration tests + benches + docs" --body ...`

## Test Matrix (target ≥7 e2e tests)

| # | FR | Attack | Decision | Phase |
|---|---|---|---|---|
| 1 | FR-014 | JSON body `{"comment":"<script>alert(1)</script>"}` | Block | Xss |
| 2 | FR-015 | path `/files/..%252fetc%252fpasswd` | Block | DirTraversal |
| 3 | FR-016 | body `{"webhook":"http://169.254.169.254/latest/meta-data"}` | Block | Ssrf |
| 4 | FR-017 | header `Referer: foo\r\nSet-Cookie: x=1` | Block | HeaderInjection |
| 5 | FR-018 | 5 prior 401s + 6th login attempt | Block | BruteForce |
| 6 | FR-019 | 20 OPTIONS requests + 21st arbitrary | Block | Scanner |
| 7 | FR-020 | declared json + 2MB body | Block | RequestBodyAbuse |

## Bench

`crates/waf-engine/benches/p0_detection.rs`:
- `evaluate_clean_request`: < 500µs p99 (all 7 checks see clean input)
- `evaluate_xss_attack`: < 200µs p99 (early-return on first match)
- `evaluate_no_attack_with_state_lookup`: < 600µs p99 (FR-018 + FR-019 do state lookups)
- **Aggregate budget: p99 < 1ms total**

## False Positive Mitigation

- Acceptance tests assert positive AND negative cases (clean request → Allow)
- Sample rules pack uses `action: challenge` (not block) for FR-018 by default — operators raise to block after observing FP rate

## Branch + PR

- Branch: `feat/fr-frame-integration-tests`
- Squash commit: `feat(detection): P0 integration tests + benches + docs`
- `gh pr create --base main --head feat/fr-frame-integration-tests --title "feat(detection): P0 integration + bench + docs" --reviewer lotus`

## Coverage Requirement

Workspace ≥90% per crate. Acceptance tests excluded from denominator (`--exclude-regex '/tests/|/benches/'` per R3§Sec1).

## Definition of Done

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace` all green (incl. e2e suite)
- [ ] `cargo bench -p waf-engine --bench p0_detection` aggregate p99 < 1ms
- [ ] `docker run --rm prx-waf:cov` reports per-crate ≥90%
- [ ] `docs/codebase-summary.md`, `docs/request-pipeline.md`, `CHANGELOG.md`, `docs/p0-detection-rulepack.md` updated
- [ ] `rules/p0-detection.yaml` loads via existing rule engine without error
- [ ] PR opened, CI green, reviewer approved

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| One of the 7 phases has subtle interaction (e.g. SSRF check fires before BodyAbuse on oversized JSON, masking the BodyAbuse signal) | High | Medium | Tests assert specific phase; pipeline ordering documented in `request-pipeline.md` |
| Aggregate bench exceeds 1ms | Medium | Medium | Profile via `cargo flamegraph`; rebudget per check if hot path identified |
| Mermaid v11 syntax mismatch with existing diagrams | Low | Low | Use `/ck:mermaidjs-v11` skill if needed |
| Acceptance test flakiness from FR-018/FR-019 time-dependent state | Medium | Medium | Use `tokio::time::pause()` in tests, deterministic `Instant` injection |

## Rollback

Single squash commit; `git revert` removes tests + bench + docs without affecting check implementations (they remain on main from earlier PRs). Operationally safe.

## Red Team Fixes (applied 2026-05-02)

Finding #1. See `plan.md ## Red Team Review`.

### Finding #1 — `WafEngine::evaluate()` does not exist; correct method is `inspect()`
Verified `crates/waf-engine/src/engine.rs:272` — public entry point is `pub fn inspect(&self, ctx: &RequestCtx) -> WafDecision`. All occurrences of `evaluate()` in this phase file have been renamed to `inspect()`. Implementer: re-verify before integration tests by `grep -n 'pub fn ' crates/waf-engine/src/engine.rs`.

- All test fns in `tests/p0_detection_acceptance.rs` call `engine.inspect(&ctx)` not `evaluate`.
- Bench fns also use `inspect`.
