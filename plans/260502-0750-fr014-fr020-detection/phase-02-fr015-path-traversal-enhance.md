---
phase: 02
title: "FR-015 — Path Traversal Enhance (recursive-decode + OS targets)"
status: pending
priority: P1
effort: 1d
dependencies: [00]
branch: feat/fr-015-path-traversal-recursive
fr: FR-015
---

## Overview

Existing `dir_traversal.rs` (161 LOC) detects `../` but uses single URL-decode. Adopt `request_targets()` (which already includes recursive-decode variants — verified `checks/mod.rs:74-150`), and extend pattern set with Linux/Windows-specific OS file targets per OWASP CRS rules 930-100..930-130.

## Acceptance Criteria (from analysis/requirements.md:55)

> Path Traversal — `../` sequences, URL-encoded variants, in URL path & query params

## Detection Rules (from research/researcher-02 implicit + OWASP CRS 930xxx)

1. `../` and `..\\` (already covered) — extend to mixed `..%2f`, `..%5c`, `..%c0%af` (overlong UTF-8)
2. **NEW:** OS-sensitive paths — Linux: `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`, `/proc/version`; Windows: `c:\windows\system32`, `boot.ini`, `win.ini`
3. **NEW:** Null-byte truncation: `..%00`, `..\0`
4. Already covered: 16-bit Unicode `..%u002f`
5. **NEW:** Adopt `request_targets()` recursive-decoded variants (current code uses only `path_decoded`, missing `path_recursive`)

## Files to Modify

- `crates/waf-engine/src/checks/dir_traversal.rs` (161 → est. ~195 LOC)

## DefenseConfig Fields Used

- `defense_config.dir_traversal` (existing)

## Implementation Steps

1. Replace bespoke decode loop with `super::request_targets(ctx)` (already gives raw + decoded + recursive-decoded for path/query/cookie/body)
2. Extend `DIR_TRAVERSAL_DESCS` and `DIR_TRAVERSAL_SET` with new patterns:
   - `r"(?i)/etc/(passwd|shadow|hosts|group|fstab)"`
   - `r"(?i)/proc/(self|[0-9]+)/(environ|status|cmdline|version)"`
   - `r"(?i)c:\\windows\\system32"`
   - `r"(?i)\b(boot|win)\.ini\b"`
   - `r"\.\.[%/\\]"` (covers `../`, `..\`, `..%2f`)
   - `r"\.\.%00|\.\.\\0"` (null truncation)
3. Update existing tests; add 12+ new tests for OS targets + recursive-decode + null-byte
4. `cargo fmt && cargo clippy -p waf-engine -- -D warnings && cargo test -p waf-engine dir_traversal`
5. Add bench `crates/waf-engine/benches/dir_traversal.rs`

## Test Matrix (target ≥20 tests)

| # | Vector | Location | Encoding | Expect |
|---|---|---|---|---|
| 1-4 | `../../../etc/passwd` | path/query/cookie/body | raw | DETECT |
| 5-7 | `..%2f..%2f..%2fetc%2fpasswd` | path | single-decoded | DETECT |
| 8-10 | `..%252f..%252fetc%252fpasswd` | path | double-decoded (recursive) | DETECT |
| 11 | `c:\windows\system32\config\sam` | query | raw | DETECT |
| 12 | `/proc/self/environ` | query | raw | DETECT |
| 13 | `..%c0%af..%c0%afetc%c0%afpasswd` | path | overlong UTF-8 | DETECT |
| 14 | `..%00.png` | path | null-byte | DETECT |
| 15 | clean `/api/users/123` | path | raw | None |
| 16 | clean `/img/photo.jpg?w=100` | path+query | raw | None |
| 17 | filename containing literal `..` (e.g. `..hidden.txt`) without slash/backslash | path | raw | None |
| 18 | `defense_config.dir_traversal=false` + attack | — | — | None |
| 19 | empty path | — | — | None |
| 20 | path > 4KB cap | path | raw | None (perf safeguard) |

## Bench

`crates/waf-engine/benches/dir_traversal.rs`:
- `dir_clean_path_short`: < 20µs p99
- `dir_attack_path_short`: < 50µs p99
- `dir_attack_recursive_decoded`: < 100µs p99
- **Aggregate budget per check: p99 < 200µs**

## False Positive Mitigation

- Pattern `..` alone (without `/` `\` `%2f` `%5c`) MUST NOT match → all regexes anchor on path separator after `..`
- Filename `version.txt` ≠ `/proc/version`: regex requires `/proc/` prefix
- Long benign URL `?ref=https://example.com/blog/something` won't false-trigger because no `..` segment

## Branch + PR

- Branch: `feat/fr-015-path-traversal-recursive`
- Squash commit: `feat(detection): FR-015 path traversal recursive decode + OS-specific targets`
- `gh pr create --base main --head feat/fr-015-path-traversal-recursive --title "feat(detection): FR-015 path traversal enhance" --reviewer lotus`

## Coverage Requirement

`crates/waf-engine/src/checks/dir_traversal.rs`: ≥90% line coverage measured by `cargo llvm-cov -p waf-engine --tests` in Docker.

## Definition of Done

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test -p waf-engine dir_traversal` ≥20 tests passing
- [ ] Coverage gate passes in Docker
- [ ] Bench shows p99 < 200µs across scenarios
- [ ] PR opened via `gh pr create`, all CI green

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| OS-target regex over-broad → flags benign API paths containing `passwd` (e.g. `/api/passwd-reset`) | Medium | Medium | Anchor on `/etc/` prefix specifically; test FP coverage |
| Recursive decode loop CPU on adversarial input | Low | Low | `url_decode_recursive` already capped at 3 iterations (mod.rs:75) |
| Conflict with future RCE check that scans similar paths | Low | Low | Phases are independent; both can fire — `request_targets()` is idempotent |

## Rollback

Single squash commit; `git revert` restores prior dir_traversal.rs. No state.
