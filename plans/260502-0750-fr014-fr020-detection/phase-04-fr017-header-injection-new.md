---
phase: 04
title: "FR-017 — HTTP Header Injection (NEW)"
status: pending
priority: P1
effort: 1d
dependencies: [00]
branch: feat/fr-017-header-injection
fr: FR-017
---

## Overview

NEW check. Detects CRLF injection in any header (raw + URL-encoded), Host header tampering against config whitelist, and X-Forwarded-For chain anomalies. Per `research/researcher-02-owasp-patterns.md#fr-017`.

## Acceptance Criteria (from analysis/requirements.md:57)

> HTTP Header Injection — Host header injection, CRLF response splitting, X-Forwarded-For spoofing

## Detection Rules (from researcher-02§FR-017)

1. **Raw CRLF** — `\r\n` (`0x0d 0x0a`) bytes in any header value
2. **Encoded CRLF** — `%0[dD]%0[aA]` regex; double-encoded `%250d%250a` (already covered by `request_targets()` recursive decode but headers are not currently in that helper — verify)
3. **Host header validation** — must match SNI (TLS) OR be in `defense_config.host_inbound_whitelist`. Reject if contains `@`, space, multiple values
4. **X-Forwarded-For** — leftmost IP must not be private when `client_ip` is public; chain length ≤ `defense_config.xf2_max_hops` (default 5)
5. **Generic header-splitting** — newline in header NAME (not value) → always reject

## Files to Create

- `crates/waf-engine/src/checks/header_injection.rs` — main `HeaderInjectionCheck` (≤140 LOC)
- `crates/waf-engine/src/checks/header_injection_patterns.rs` — encoded-CRLF regex set (≤40 LOC)

(No scanners.rs file — header iteration is straightforward, doesn't justify split.)

## DefenseConfig Fields Used

- `defense_config.header_injection` (Phase 00)
- `defense_config.xf2_max_hops` (Phase 00)
- `defense_config.host_inbound_whitelist` (Phase 00)

## Implementation Steps

1. Create `header_injection_patterns.rs` with:
   - `HDR_DESCS: &[&str]` (mirror cesc1802 style)
   - `HDR_ENCODED_CRLF_SET: LazyLock<RegexSet>` matching `%0[dD]%0[aA]`, `%250d%250a`
2. Create `header_injection.rs`:
   - Helper fns (free, not methods): `check_header_for_crlf(&str) -> bool`, `validate_host_header(host, sni, &whitelist) -> bool`, `validate_x_forwarded_for(value, client_ip, max_hops) -> Option<&str>` (returns reason on failure)
   - `HeaderInjectionCheck` struct (no internal state — patterns static)
   - `impl Check::check`: gate on toggle; iterate `ctx.headers` once; per (name, value) run Rules 1-2-5; then specialized Host check; then specialized X-F2 check
3. **NOTE on RequestCtx fields:** header iteration uses existing `ctx.headers` map. SNI is needed for Rule 3 — verify `RequestCtx` exposes `sni: Option<String>`. If absent, fall back to whitelist-only validation (acceptable for HTTP-only). Doc comment cites this. **[VERIFY in Phase 00 PR review]**
4. Add tests (≥22 — see matrix)
5. `cargo fmt && cargo clippy -p waf-engine -- -D warnings && cargo test -p waf-engine header_injection`
6. Add bench `crates/waf-engine/benches/header_injection.rs`

## Test Matrix (target ≥22 tests)

| # | Vector | Expect |
|---|---|---|
| 1 | `Referer: foo\r\nSet-Cookie: admin=1` (raw CRLF) | DETECT (HDR-001) |
| 2 | `User-Agent: foo%0d%0aSet-Cookie: x` | DETECT (HDR-002) |
| 3 | `Cookie: a=b%250d%250a` (double-encoded) | DETECT (HDR-002) |
| 4 | header NAME contains `\n` | DETECT (HDR-005) |
| 5 | `Host: evil.com@target.com` (`@` injection) | DETECT (HDR-003) |
| 6 | `Host: target.com target2.com` (space) | DETECT (HDR-003) |
| 7 | `Host: target.com` + SNI=`other.com` | DETECT (HDR-003) |
| 8 | `Host: target.com` + SNI=`target.com` | None |
| 9 | `Host: legit.com`, no SNI, whitelist=["legit.com"] | None |
| 10 | `Host: evil.com`, no SNI, whitelist=["legit.com"] | DETECT (HDR-003) |
| 11 | `X-Forwarded-For: 10.0.0.1, 1.2.3.4`, client_ip=public | DETECT (HDR-004) — leftmost private |
| 12 | `X-Forwarded-For: 1.2.3.4, 5.6.7.8`, client_ip=public | None |
| 13 | `X-Forwarded-For: 1.1.1.1, 2.2.2.2, ..., 11 hops`, max_hops=5 | DETECT (HDR-004b) |
| 14 | clean `Authorization: Bearer eyJ...` (JWT contains `.`) | None |
| 15 | clean `User-Agent: Mozilla/5.0` | None |
| 16 | `defense_config.header_injection=false` + attack | None |
| 17 | empty headers | None |
| 18 | `Content-Length: 0\r\nTransfer-Encoding: chunked` (request smuggling — partial coverage) | DETECT raw CRLF |
| 19 | `Host: localhost:8080` whitelisted | None |
| 20 | UTF-8 multi-byte in header value (no CR/LF) | None |
| 21 | `X-Forwarded-For: ` (empty) | None |
| 22 | multi-value `Host: a, Host: b` | DETECT (HDR-003) — duplicate |

## Bench

`crates/waf-engine/benches/header_injection.rs`:
- `hdr_clean_5_headers`: < 30µs p99
- `hdr_clean_30_headers`: < 80µs p99
- `hdr_attack_crlf_encoded`: < 60µs p99
- **Aggregate budget per check: p99 < 200µs**

## False Positive Mitigation

- Per researcher-02§FR-017 Scenario A: User-Agent rich content → only flag `\r\n` not arbitrary special chars
- Scenario B: CDN headers (CF-Connecting-IP) → only inspect `host`, `x-forwarded-for`, generic CRLF (don't add new validations on CDN-specific headers)
- Scenario C: Long X-F2 chain → configurable `xf2_max_hops` (default 5, per researcher-02 recommendation)

## Branch + PR

- Branch: `feat/fr-017-header-injection`
- Squash commit: `feat(detection): FR-017 header injection (CRLF, Host, X-F2)`
- `gh pr create --base main --head feat/fr-017-header-injection --title "feat(detection): FR-017 header injection" --reviewer lotus`

## Coverage Requirement

`crates/waf-engine/src/checks/header_injection*.rs`: combined ≥90% line coverage in Docker.

## Definition of Done

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test -p waf-engine header_injection` ≥22 tests passing
- [ ] Coverage gate passes in Docker
- [ ] Bench p99 < 200µs
- [ ] PR opened, CI green

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Host validation breaks legitimate multi-domain hosts | High | High | Default whitelist empty = check disabled; opt-in per host |
| SNI not exposed in `RequestCtx` → Host check degraded to whitelist-only | Medium | Medium | Fallback documented; spec works for HTTP+HTTPS-with-whitelist |
| X-F2 false-positive on legit reverse proxy chains > 5 hops | Medium | Medium | Configurable `xf2_max_hops` |
| Hop-by-hop header smuggling (TE/CL desync) only partially detected | Medium | High | Document as known limitation; full mitigation requires Pingora-layer normalization (out of scope) |

## Rollback

Single squash commit; `git revert` removes 2 files. Phase 00 stub regains control (returns None). No state.

## Red Team Fixes (applied 2026-05-02)

Findings #9, #12. See `plan.md ## Red Team Review`.

### Finding #9 — `HashMap<String,String>` headers cannot detect duplicate Host
Verified: `crates/waf-common/src/types.rs:30` — `pub headers: HashMap<String, String>`. A second Host header overwrites the first; the duplicate is invisible by the time `RequestCtx` is built. Test #22 ("multi-value `Host: a, Host: b`") cannot pass against current `RequestCtx`.

- **DROP** test #22 from the matrix.
- **Replace** with new test #22: `Host: a` only — verify Pingora-layer normalization is documented as the duplicate-defense (out of scope for waf-engine v1).
- **Add note** to "False Positive Mitigation": "Duplicate-Host detection requires `Vec<String>` headers shape; deferred to a future `RequestCtx` refactor that touches both `gateway` and `waf-engine`. Out of scope for FR-017 v1."

### Finding #12 — `RequestCtx` has no `sni` field; test #7 cannot pass
Verified: `crates/waf-common/src/types.rs:21-54` defines no `sni` field. Test #7 (Host=target.com + SNI=other.com → DETECT) cannot be implemented.

- **DROP** test #7.
- **Replace** Implementation Step 3 entirely:
  > **Remove** the SNI-based path. `validate_host_header(host, &whitelist) -> bool` — whitelist-only validation. If `whitelist.is_empty()`, the check is skipped (no-op for hosts that haven't opted in). Future SNI integration deferred to a `RequestCtx` extension that requires gateway changes.
- **Add note** to Risks: "SNI mismatch detection deferred until `RequestCtx::sni: Option<String>` is added by a future PR (cross-crate change requiring gateway buy-in). v1 ships whitelist-only — operators MUST populate `host_inbound_whitelist` per host or the check is a no-op."
