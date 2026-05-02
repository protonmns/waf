---
phase: 06
title: "FR-020 — Request Body Abuse (NEW)"
status: pending
priority: P1
effort: 1.5d
dependencies: [00]
branch: feat/fr-020-body-abuse
fr: FR-020
---

## Overview

NEW check. Validates request body for: malformed JSON when Content-Type=`application/json`, oversized payload vs. configured cap, deeply nested objects (CVE-2025-67221 class), key-count explosion, and Content-Type vs. magic-byte mismatch. Per `research/researcher-02-owasp-patterns.md#fr-020`.

## Acceptance Criteria (from analysis/requirements.md:60)

> Request Body Abuse — Malformed JSON, oversized payload, deeply nested objects, content-type mismatch

## Detection Rules (from researcher-02§FR-020)

1. **Oversized** — `ctx.body_preview.len() > defense_config.max_body_size` (default 1MB)
2. **Content-Type mismatch** — declared CT vs. magic-byte sniff (`{`/`[` → JSON, `<` → XML, `PK\x03\x04` → ZIP, `\x1f\x8b` → GZIP)
3. **Malformed JSON** — declared `application/json`, `serde_json::from_slice` fails
4. **Deep nesting** — JSON tree depth > `defense_config.max_json_depth` (default 100); use **iterative walker with explicit stack** (NOT recursive — recursive walk is itself the CVE class)
5. **Key explosion** — total key count > `defense_config.max_json_keys` (default 10_000); same iterative walker

Order matters: cheap checks first (size, magic byte), then JSON parse only if needed.

## Files to Create

- `crates/waf-engine/src/checks/body_abuse.rs` — main `RequestBodyAbuseCheck` (≤140 LOC)
- `crates/waf-engine/src/checks/body_abuse_walker.rs` — iterative JSON walker, magic-byte sniff (≤100 LOC)

## DefenseConfig Fields Used

- `defense_config.body_abuse` (Phase 00)
- `defense_config.max_body_size` (Phase 00)
- `defense_config.max_json_depth` (Phase 00)
- `defense_config.max_json_keys` (Phase 00)

## Implementation Steps

1. Create `body_abuse_walker.rs`:
   - `fn sniff_content_type(bytes: &[u8]) -> &'static str` — magic-byte switch
   - `fn walk_json_iterative(value: &serde_json::Value, max_depth: usize, max_keys: usize) -> Result<(), BodyAbuseViolation>` — uses `Vec<(&Value, depth)>` as explicit stack; counts keys; bails on first violation
   - `enum BodyAbuseViolation { TooDeep, TooManyKeys }`
2. Create `body_abuse.rs`:
   - `RequestBodyAbuseCheck` struct (no internal state; reads thresholds from `ctx.host_config.defense_config` per request — supports hot-reload natively)
   - `impl Check::check`:
     1. Gate on `body_abuse` toggle
     2. Empty body → None
     3. Rule 1: size check (cheapest) → BODY-002
     4. Rule 2: magic-byte sniff vs declared Content-Type → BODY-005
     5. If declared `application/json`: try `serde_json::from_slice`. Err → BODY-001. Ok(value) → walk → BODY-003 / BODY-004
3. Add tests (≥22 — see matrix)
4. `cargo fmt && cargo clippy -p waf-engine -- -D warnings && cargo test -p waf-engine body_abuse`
5. Add bench `crates/waf-engine/benches/body_abuse.rs`

## Test Matrix (target ≥22 tests)

| # | Vector | Body | CT | Expect |
|---|---|---|---|---|
| 1 | oversized 2MB | 2MB | application/json | DETECT (BODY-002) |
| 2 | exactly at 1MB cap | 1MB | application/json | None (boundary) |
| 3 | declared json, body=`<xml/>` | XML | application/json | DETECT (BODY-005) |
| 4 | declared json, body=`PK\x03\x04...` | ZIP | application/json | DETECT (BODY-005) |
| 5 | declared text/plain, body=`{}` | JSON | text/plain | DETECT (BODY-005) — actual is json |
| 6 | declared json, body=`{` (truncated) | malformed | application/json | DETECT (BODY-001) |
| 7 | declared json, body=valid JSON, depth 50 | JSON | application/json | None |
| 8 | declared json, body=depth 101 (just over cap) | JSON | application/json | DETECT (BODY-003) |
| 9 | declared json, body=10001 keys (just over cap) | JSON | application/json | DETECT (BODY-004) |
| 10 | declared json, body=10000 keys exactly | JSON | application/json | None |
| 11 | adversarial: depth=1000 deeply nested | JSON | application/json | DETECT — walker doesn't stack-overflow |
| 12 | adversarial: 100k keys flat array | JSON | application/json | DETECT (BODY-004) |
| 13 | empty body | empty | (any) | None |
| 14 | clean small JSON `{"name":"alice","age":30}` | JSON | application/json | None |
| 15 | `defense_config.body_abuse=false` + attack | 2MB | application/json | None |
| 16 | declared json with charset suffix `application/json; charset=utf-8` | JSON | (with charset) | None — must parse CT correctly |
| 17 | no Content-Type header, body=`{}` | JSON | (none) | None — skip CT mismatch check; parse JSON only if declared |
| 18 | declared text/html, body=`<html>...` | HTML | text/html | None |
| 19 | gzipped body declared `application/gzip` | GZIP | application/gzip | None — magic matches, no further inspection |
| 20 | mixed object+array nesting `{"a":[{"b":[...]}]}` depth 105 | JSON | application/json | DETECT (BODY-003) |
| 21 | huge string value (1MB string in JSON) | JSON | application/json | DETECT (BODY-002) — body size cap hits first |
| 22 | per-route override: max_body_size raised to 5MB for `/api/upload` | (deferred — config integration) | — | TODO Phase 08 |

## Bench

`crates/waf-engine/benches/body_abuse.rs`:
- `body_clean_json_1kb`: < 30µs p99
- `body_attack_oversize_check`: < 5µs p99 (fast path)
- `body_attack_deep_nest_walker`: < 100µs p99
- `body_attack_key_explosion_walker`: < 150µs p99
- **Aggregate budget per check: p99 < 200µs**

## False Positive Mitigation

- Per researcher-02§FR-020 Scenario A: legit bulk-data JSON > 1MB → per-route `max_body_size` override via `HostConfig`-level rule (deferred to Phase 08 if needed)
- Scenario B: deeply nested webhook payload → per-route `max_json_depth` override (deferred Phase 08)
- Scenario C: tree-based API (file system, org hierarchy) → same; document opt-in route override
- **Iterative walker not recursive** — eliminates the very class of bug we detect (defense in depth)

## Branch + PR

- Branch: `feat/fr-020-body-abuse`
- Squash commit: `feat(detection): FR-020 request body abuse (size, JSON depth/keys, CT mismatch)`
- `gh pr create --base main --head feat/fr-020-body-abuse --title "feat(detection): FR-020 body abuse" --reviewer lotus`

## Coverage Requirement

`crates/waf-engine/src/checks/body_abuse*.rs`: combined ≥90% in Docker.

## Definition of Done

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test -p waf-engine body_abuse` ≥22 tests passing
- [ ] Coverage gate passes
- [ ] Bench p99 < 200µs (incl. adversarial inputs)
- [ ] PR opened, CI green

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `serde_json::from_slice` itself recurses — could stack-overflow on malicious input before our walker runs | High | Critical | Use `serde_json::de::from_slice` with `recursion_limit` set via `serde_json::de::Deserializer::from_slice(...).set_recursion_limit(150)` (slightly above max_depth=100 to allow detection rather than crash). **Verify API exists in current serde_json version.** [UNVERIFIED API surface] |
| Magic-byte sniff false-positive on JSON-looking string `[1,2,3]` declared as text | Low | Low | Only flag mismatch if both sides have unambiguous magic |
| Body preview truncated upstream → false-negative for oversize | Medium | Medium | Document: relies on Pingora's `body_preview` capping at known limit; if cap < 1MB this check is moot for size > cap. Verify `RequestCtx.body_preview` semantics in Phase 08 integration. |
| Walker stack on `Vec<&Value>` may itself OOM on pathological input | Low | High | Cap stack size: bail with `TooDeep` if `stack.len() > max_depth` |

## Rollback

Single squash commit; `git revert` removes 2 files. Phase 00 stub regains control. No state.

## Red Team Fixes (applied 2026-05-02)

Findings #3, #5. See `plan.md ## Red Team Review`.

### Finding #3 — `serde_json::Deserializer::set_recursion_limit` is fictional
Verified docs.rs/serde_json: only `disable_recursion_limit()` exists (does the OPPOSITE — removes the default 128 cap). The Risks-row mitigation citing `set_recursion_limit(150)` will not compile.

- **Remove** Risk row #1 entirely.
- **Replace** Implementation Step 2 (`body_abuse.rs` step 5):
  > Do NOT call `serde_json::from_slice` on untrusted input — its default 128-depth cap is fine but the parser still allocates linearly. Instead, **iterate bytes manually** to count `{` / `[` / `}` / `]` and bail when nesting > `max_json_depth`:
  > ```rust
  > fn precheck_json_depth(bytes: &[u8], max_depth: usize) -> Result<(), BodyAbuseViolation> {
  >     let mut depth = 0usize;
  >     for &b in bytes {
  >         match b {
  >             b'{' | b'[' => { depth += 1; if depth > max_depth { return Err(TooDeep); } }
  >             b'}' | b']' => { depth = depth.saturating_sub(1); }
  >             _ => {}
  >         }
  >     }
  >     Ok(())
  > }
  > ```
  > Run this BEFORE `serde_json::from_slice`. If precheck passes, parse to `Value` for key-count walk (parsing a depth-≤100 doc is safe). If precheck fails, return DETECT (BODY-003) without ever invoking the parser.
- **Add test**: `body_precheck_rejects_depth_10000_without_panic` — input is 10000 nested `{`s, no closing braces. Expect DETECT in O(N), no allocation.
- **Add test**: `body_precheck_handles_strings_with_braces` — `{"a":"{{{"}` valid JSON with `{` inside string. NOTE: precheck is intentionally a fast over-approximation; if it false-positives on string literals containing many braces, that's acceptable (rare in practice and BODY-003 is a Block, the operator can investigate). Document this trade-off.

### Finding #5 — `BODY_PREVIEW_LIMIT=64 KiB` vs Phase 06 `max_body_size=1 MiB` → dead code
Verified `crates/gateway/src/context.rs:10`: `pub const BODY_PREVIEW_LIMIT: usize = 64 * 1024;`. `RequestCtx.body_preview` is upstream-truncated at 64 KiB, so any `max_body_size > 64 KiB` check on `body_preview.len()` can NEVER fire — bytes beyond 64 KiB are not present.

- **Change** Phase 00 default: `default_max_body_size = 64 * 1024` (was `1_048_576`).
- **Replace** Detection Rule 1:
  > **Oversized** — `ctx.content_length > defense_config.max_body_size` (use `content_length` from `RequestCtx`, NOT `body_preview.len()` — `content_length` is the declared header, available before body is read; matches what Pingora reports). For requests with no `Content-Length` (chunked), fall back to `body_preview.len()` and document that bodies > 64 KiB cannot be detected v1 (limitation: BodyAbuse depth/keys check still works on first 64 KiB).
- **Update** all tests #1, #2, #21 to use 64 KiB / 65 KiB boundaries (not 1 MiB / 2 MiB).
- **Add note** to Risks: "Raising `max_body_size > 64 KiB` requires gateway PR to extend `BODY_PREVIEW_LIMIT`. Out of scope for FR-020 v1."
