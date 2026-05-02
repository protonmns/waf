---
phase: 01
title: "FR-014 — XSS Enhance (JSON walker + Content-Type aware)"
status: pending
priority: P1
effort: 1d
dependencies: [00]
branch: feat/fr-014-xss-json-walk
fr: FR-014
---

## Overview

Existing `xss.rs` (174 LOC) only scans the union of `request_targets()` (path + query + cookie + body bytes), missing structured JSON values nested under array/object trees. Add a JSON walker triggered by Content-Type, mirroring `sql_injection_scanners::scan_json_body` (`crates/waf-engine/src/checks/sql_injection_scanners.rs:1-235`).

## Acceptance Criteria (from analysis/requirements.md:54)

> XSS — Reflected & stored; script injection in query string, form data, JSON

## Detection Rules (from research/researcher-02-owasp-patterns.md is silent on FR-014; rules carried from existing xss.rs + OWASP CRS 941xxx)

1. `<script>` tag (raw + encoded) — already covered
2. Event handler attributes `onload=`, `onerror=`, `onclick=` — already covered
3. `javascript:` URI scheme in `href`/`src` — already covered
4. **NEW:** Walk JSON body recursively: extract every string leaf, run through XSS_SET; report `body.json.<json-pointer>` location
5. **NEW:** Form-urlencoded body (`application/x-www-form-urlencoded`): split on `&`, urldecode each `key=value`, scan value

## Files to Modify

- `crates/waf-engine/src/checks/xss.rs` (174 → est. 200 LOC; if exceeds, split into `xss_scanners.rs` per modularization rule)

## Files to Create (only if xss.rs exceeds 200 LOC after edit)

- `crates/waf-engine/src/checks/xss_scanners.rs` — `scan_json_body_xss`, `scan_form_urlencoded`

## DefenseConfig Fields Used

- `defense_config.xss` (existing)

## Implementation Steps

1. Read current `xss.rs` patterns + tests
2. Add `scan_json_body` adapted from sql_injection_scanners (re-use traversal, swap regex set arg to `XSS_SET`)
3. In `XssCheck::check`: branch on `content-type` header — if `application/json`, call new walker BEFORE the generic `request_targets()` loop (more precise location attribution)
4. If `application/x-www-form-urlencoded`, parse via `url::form_urlencoded::parse` and scan each value
5. Both scanners must respect `cfg.json_parse_cap` (mirror SqliScanConfig); if not present in `XssScanConfig`, add it with default `64 * 1024`
6. Add 12+ new tests covering: JSON-nested `<script>`, JSON array of strings, form-encoded `q=<img onerror=...>`, deeply-nested object, oversized JSON beyond cap (skipped, not flagged)
7. `cargo fmt && cargo clippy -p waf-engine -- -D warnings && cargo test -p waf-engine xss`
8. Add `criterion` bench `crates/waf-engine/benches/xss.rs`: 1KB JSON input, 4KB JSON input, plain query string baseline

## Test Matrix (target ≥20 tests in xss.rs)

| # | Vector | Location | Encoding | Expect |
|---|---|---|---|---|
| 1-6 | `<script>`, `<SCRIPT>`, `<sCrIpT>` | path/query/cookie/body | raw + %3C + %253C | DETECT |
| 7-9 | `onerror=`, `onload=` | query | raw | DETECT |
| 10 | `javascript:alert(1)` | query | raw | DETECT |
| 11-13 | nested JSON `{"a":{"b":"<script>"}}` | body | raw | DETECT, location `body.json.a.b` |
| 14 | JSON array `["<img onerror=x>"]` | body | raw | DETECT |
| 15-16 | form-urlencoded `q=%3Cscript%3E` | body | encoded | DETECT |
| 17 | clean JSON `{"name":"Alice"}` | body | raw | None |
| 18 | clean form `q=hello+world` | body | encoded | None |
| 19 | malformed JSON | body | — | None (Phase 06 catches BodyAbuse) |
| 20 | XSS in body but `defense_config.xss=false` | body | raw | None |

## Bench

`crates/waf-engine/benches/xss.rs` — criterion targets:
- `xss_clean_json_1kb`: < 50µs p99
- `xss_attack_json_1kb`: < 100µs p99
- `xss_clean_form_4kb`: < 80µs p99
- **Aggregate budget per check: p99 < 200µs**

## False Positive Mitigation

- Skip Content-Type=`text/markdown` — markdown legitimately contains `<script` snippets in code blocks. Mark in `XssScanConfig` as `markdown_aware: bool` (default true). Out of scope for v1: actual markdown parsing.
- Cap JSON parse at `cfg.json_parse_cap` bytes; oversized → skip not block (BodyAbuse phase handles oversized).

## Branch + PR

- Branch: `feat/fr-014-xss-json-walk`
- Squash commit: `feat(detection): FR-014 XSS JSON walker + form-urlencoded scanner`
- `gh pr create --base main --head feat/fr-014-xss-json-walk --title "feat(detection): FR-014 XSS enhance" --reviewer lotus`

## Coverage Requirement

`crates/waf-engine/src/checks/xss.rs` (and `xss_scanners.rs` if split): line coverage ≥90%, measured by `cargo llvm-cov -p waf-engine --tests` in Docker.

## Definition of Done

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test -p waf-engine xss` ≥20 tests passing
- [ ] `docker run --rm prx-waf:cov bash scripts/coverage-gate.sh /out/cov-summary.txt 90` passes
- [ ] `cargo bench -p waf-engine --bench xss` records p99 < 200µs per scenario
- [ ] PR opened via `gh pr create`, all CI checks green, reviewer approved

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| JSON walker recursion stack overflow on malicious deep nesting | Medium | High | Hard cap depth at 100 inside walker; matches Phase 06 BodyAbuse limit (defense in depth) |
| Regex slowdown on large bodies | Low | Medium | `cfg.json_parse_cap` cap before regex; benches enforce |
| False positive on `<script>` in markdown blog posts | Medium | Medium | `markdown_aware` config flag; default true |

## Rollback

Single squash commit; `git revert <sha>` restores prior `xss.rs`. No DB/state migrations.

## Red Team Fixes (applied 2026-05-02)

Finding #4. See `plan.md ## Red Team Review`.

### Finding #4 — Hard depth cap in `walk_json` adapter
The XSS plan reuses the JSON walker pattern from `crates/waf-engine/src/checks/sql_injection_scanners.rs:58` which does NOT cap recursion depth — the same stack-overflow vulnerability FR-020 (Phase 06) is meant to detect. XSS check runs BEFORE BodyAbuse in the pipeline, so an attacker with deep-nested JSON crashes the WAF before BodyAbuse fires.

- **Replace** step 2 of Implementation Steps:
  > Add `scan_json_body(value, max_depth=64) -> Option<(JsonPointer, &'static str)>` adapted from sql_injection_scanners. **Use iterative walker with explicit stack `Vec<(&Value, usize)>`** (matches Phase 06 pattern). Bail with `None` (skip, do not flag) on `depth > 64` — Phase 06 will catch the deep-nested attack itself; XSS just needs to not crash.
- **Add test**: `xss_deeply_nested_json_does_not_overflow` — input depth 10_000, expect `None` (skip), no panic.
- **Add test**: `xss_at_depth_64_still_detected` — `<script>` tag at depth exactly 64, expect DETECT.
