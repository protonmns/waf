---
phase: 03
title: "FR-016 — SSRF Detection (NEW)"
status: pending
priority: P1
effort: 1.5d
dependencies: [00]
branch: feat/fr-016-ssrf-detection
fr: FR-016
---

## Overview

NEW check. Detects SSRF attempts where user-supplied URLs target internal infrastructure (RFC1918, link-local, loopback, cloud metadata endpoints). Handles obfuscated IP encodings (octal/hex/dword/IPv6-mapped) per Capital One 2019 (`research/researcher-02-owasp-patterns.md#fr-016-ssrf`).

## Acceptance Criteria (from analysis/requirements.md:56)

> SSRF — Requests to internal IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x), metadata endpoints

## Detection Rules (from research/researcher-02-owasp-patterns.md§FR-016)

1. **RFC1918 regex** — `10/8`, `172.16/12`, `192.168/16` in URL form
2. **Loopback + link-local** — `127.0.0.0/8`, `169.254.0.0/16`, `localhost`
3. **Cloud metadata hostnames** — `169.254.169.254`, `metadata.google.internal`, `100.100.100.200` (Alibaba), `metadata.amazonaws.com`, `metadata.service.consul`, IPv6-mapped form `[::ffff:169.254.169.254]`
4. **Obfuscated IP** — octal `017700000001`, hex `0x7f000001`, dword `2130706433` → normalize via `parse_obfuscated_ip()` then check against private ranges using `ipnet::Ipv4Net`
5. **IPv6-mapped IPv4** — `::ffff:10.0.0.1` → strip prefix, validate as Rule 1-3

## Files to Create

- `crates/waf-engine/src/checks/ssrf.rs` — main `SsrfCheck` (≤120 LOC)
- `crates/waf-engine/src/checks/ssrf_patterns.rs` — `SSRF_RFC1918_DESCS`, `SSRF_RFC1918_SET`, `SSRF_METADATA_DESCS`, `SSRF_METADATA_SET` (≤80 LOC)
- `crates/waf-engine/src/checks/ssrf_scanners.rs` — `extract_urls_from_request`, `parse_obfuscated_ip`, `is_private_ip(IpAddr)`, `scan_body_urls` (≤100 LOC)

(Triplet structure mirrors existing `sql_injection*` per cesc1802 style — `research/researcher-01-cesc1802-style.md§4`.)

## Files to Modify

- `crates/waf-engine/src/checks/mod.rs` — already declares `pub mod ssrf;` from Phase 00; verify

## DefenseConfig Fields Used

- `defense_config.ssrf` (Phase 00)
- `defense_config.ssrf_dns_timeout_ms` (Phase 00, default 50ms)

## Implementation Steps

1. Create `ssrf_patterns.rs` with 2 `LazyLock<RegexSet>` per researcher-02 Rules 1-3 (using existing `// SAFETY:` style from `scanner.rs:43`)
2. Create `ssrf_scanners.rs`:
   - `parse_obfuscated_ip(&str) -> Option<IpAddr>` — strip `0x`/`0o` prefix, parse as u32 (dword), fallback `IpAddr::from_str`
   - `is_private_ip(addr: &IpAddr) -> bool` — use `ipnet::Ipv4Net` against const list of CIDRs `["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16"]`
   - `extract_urls_from_request(ctx) -> Vec<(&'static str, String)>` — scan body JSON leaves + headers (`location`, `referer`, custom `webhook_url`-like) for `http(s)://...` substrings
3. Create `ssrf.rs`:
   - `SsrfCheck` struct (no config field needed — patterns are static, threshold via DefenseConfig)
   - `impl Check::check`: gate on `ctx.host_config.defense_config.ssrf`; iterate `extract_urls_from_request`; per URL try Rule 1 (regex set match), Rule 4 (obfuscated parse), Rule 5 (IPv6-mapped strip)
   - **No DNS resolution in v1** — researcher-02§FR-016 Bypass2 (DNS rebinding) deferred. Doc comment cites future hook.
4. Add tests (≥25 — see matrix)
5. `cargo fmt && cargo clippy -p waf-engine -- -D warnings && cargo test -p waf-engine ssrf`
6. Add bench `crates/waf-engine/benches/ssrf.rs`

## Test Matrix (target ≥25 tests)

| # | Vector | Location | Expect |
|---|---|---|---|
| 1 | `http://10.1.2.3/api` in JSON `webhook_url` | body | DETECT (RFC1918) |
| 2 | `http://172.16.0.1/` in query | query | DETECT |
| 3 | `http://192.168.1.1` in `Referer` header | header | DETECT |
| 4 | `http://127.0.0.1:8080` | body | DETECT (loopback) |
| 5 | `http://localhost/admin` | body | DETECT |
| 6 | `http://169.254.169.254/latest/meta-data/` (AWS) | body | DETECT (metadata) |
| 7 | `http://metadata.google.internal/` | body | DETECT |
| 8 | `http://100.100.100.200/` (Alibaba) | body | DETECT |
| 9 | `http://[::ffff:169.254.169.254]/` | body | DETECT (IPv6-mapped) |
| 10 | `http://0x7f000001/` (hex 127.0.0.1) | body | DETECT (obfuscated) |
| 11 | `http://2130706433/` (dword 127.0.0.1) | body | DETECT |
| 12 | `http://017700000001/` (octal 127.0.0.1) | body | DETECT |
| 13 | clean `https://example.com/api` | body | None |
| 14 | clean `https://api.stripe.com/v1` | body | None |
| 15 | `defense_config.ssrf=false` + attack | body | None |
| 16 | URL inside nested JSON object | body | DETECT, location includes pointer |
| 17 | URL inside JSON array | body | DETECT |
| 18 | multiple URLs in body — first malicious wins | body | DETECT (first) |
| 19 | empty body | — | None |
| 20 | non-JSON body (form-urlencoded `webhook=http%3A//10.0.0.1/`) | body | DETECT after decode |
| 21-25 | obfuscation: `0x7F.0.0.1` mixed dotted-hex, `::1`, `0:0:0:0:0:0:0:1` IPv6 loopback | body | DETECT |

## Bench

`crates/waf-engine/benches/ssrf.rs`:
- `ssrf_clean_json_1kb`: < 50µs p99
- `ssrf_attack_metadata`: < 80µs p99
- `ssrf_obfuscated_ip_parse`: < 100µs p99
- **Aggregate budget per check: p99 < 200µs**

## False Positive Mitigation

- Per researcher-02§FR-016 Scenario A/B/C: support `defense_config.ssrf_outbound_host_allowlist` (Phase 00 added) for legitimate internal callers — but SSRF check uses a separate `ssrf_internal_whitelist` Vec? **Decision:** v1 reuses `ssrf_outbound_host_allowlist`; if collision arises, add dedicated field in Phase 08.
- Pattern `100.100.100.200` is Alibaba metadata — but `100.x.x.x` shared address space (RFC6598) is also used by carrier-grade NAT. Restrict to exact `100.100.100.200` only.
- Don't false-positive on legitimate `https://api.cloudflare.com` — only `http://` + `https://` prefix counts when value is in user-supplied URL field.

## Branch + PR

- Branch: `feat/fr-016-ssrf-detection`
- Squash commit: `feat(detection): FR-016 SSRF check (RFC1918, metadata, obfuscated IPs)`
- `gh pr create --base main --head feat/fr-016-ssrf-detection --title "feat(detection): FR-016 SSRF detection" --reviewer lotus`

## Coverage Requirement

`crates/waf-engine/src/checks/ssrf*.rs` (3 files): combined ≥90% line coverage measured by `cargo llvm-cov -p waf-engine --tests` in Docker.

## Definition of Done

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test -p waf-engine ssrf` ≥25 tests passing
- [ ] Coverage gate passes in Docker
- [ ] Bench shows p99 < 200µs
- [ ] PR opened via `gh pr create`, CI green

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Capital One CVE replay (169.254.169.254 missed) | Low | Critical | Explicit test (#6, #9), regression test forever |
| FP on cloud webhooks legitimately calling internal endpoints | Medium | Medium | Per-host whitelist via DefenseConfig |
| URL extraction misses fields with non-standard names (e.g. custom `target_uri`) | Medium | Medium | Walk all JSON string leaves, not just known keys |
| Obfuscated IP parsing collides with legitimate numeric IDs in body | Low | Low | Only parse as IP if input shape matches IP-like (`\d+`, `0x[0-9a-f]+`); skip mixed-content strings |

## Rollback

Single squash commit; `git revert` removes 3 ssrf files + `mod.rs` lines (mod.rs lines were added by Phase 00, will linger as orphan stub if revert is partial — acceptable, harmless). No state.

## Red Team Fixes (applied 2026-05-02)

Finding #10. See `plan.md ## Red Team Review`.

### Finding #10 — SSRF userinfo bypass `http://google.com@169.254.169.254/`
Substring extraction defeated by URL userinfo `user[:pass]@host` syntax — `extract_urls_from_request` reading `http://...@169.254.169.254/` will see `google.com` as the host if it splits on the first `/` instead of parsing.

- **Replace** Implementation Step 2 second bullet:
  > `extract_urls_from_request(ctx) -> Vec<(&'static str, IpOrHost)>` — for each candidate URL substring, **parse via `url::Url::parse`** (already a workspace dep — verify `Cargo.toml`) then take **`url.host_str()`** for matching. URLs that fail to parse are skipped (not flagged — Phase 04 catches malformed-host header injection).
- **Add test #26**: `http://google.com@169.254.169.254/latest/meta-data/` → DETECT (host_str returns `169.254.169.254`)
- **Add test #27**: `http://169.254.169.254@google.com/` → None (host_str returns `google.com` — userinfo ≠ host)
- **Add test #28**: malformed `http://[::1` (unclosed bracket) → None (parse fails, skipped — covered by Phase 04)

### Lower-severity (deferred)
- `ssrf_outbound_host_allowlist` semantic collision with FR-017: rename SSRF allowlist to `defense_config.ssrf_outbound_host_allowlist` to avoid conflict.
