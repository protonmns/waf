# Red Team Review — Security Adversary Lens
**Plan:** `260502-0750-fr014-fr020-detection` (FR-014..FR-020 P0 detection suite)
**Reviewer:** code-reviewer (Security Adversary lens)
**Date:** 2026-05-02
**Method:** 15+ codebase grep verifications cross-referenced against plan claims and researcher-02 bypass scenarios.

---

## Finding 1: FR-020 oversize-body check is dead code (capped at 64 KiB upstream, plan ships 1 MiB default)
- **Severity:** Critical
- **Location:** Phase 06, "Detection Rules" Rule 1 + Phase 00 `default_max_body_size = 1_048_576`
- **Flaw:** `RequestCtx.body_preview` is hard-capped to **64 KiB** by the gateway (`crates/gateway/src/context.rs:10` → `pub const BODY_PREVIEW_LIMIT: usize = 64 * 1024;`). The engine receives at most 64 KiB regardless of true body size. Plan defaults `max_body_size = 1 MiB`. Therefore the size-check at Phase 06 step 5 (Rule 1, "BODY-002") **literally cannot fire** for the documented threat model — `body_preview.len() > 1_048_576` is never true. Attacker can ship 100 GiB body — WAF sees 64 KiB clean preview, decides "size OK".
- **Failure scenario:** Attacker POSTs `Content-Length: 999999999` of `{"x":"…"}`. Gateway streams up to 64 KiB into preview, calls engine. Phase 06 oversize check passes. Pingora forwards full body upstream → app OOM. The WAF advertised "FR-020 oversized payload" but does not detect oversize.
- **Evidence:**
  - `/Users/admin/lab/mini-waf/crates/gateway/src/context.rs:10` — `pub const BODY_PREVIEW_LIMIT: usize = 64 * 1024;`
  - `/Users/admin/lab/mini-waf/crates/gateway/src/proxy.rs:386` — `should_inspect = ctx.body_buf.len() >= BODY_PREVIEW_LIMIT || (end_of_stream && !ctx.body_buf.is_empty())` (preview only)
  - Phase 06 "Risks" row 3 mentions this hand-wavily ("Verify `RequestCtx.body_preview` semantics in Phase 08") but ships defaults that guarantee the check is broken.
- **Suggested fix:** Add `RequestCtx.content_length: u64` (already exists, line 32) — gate Rule 1 on `ctx.content_length > max_body_size`, not `body_preview.len()`. `Content-Length` is attacker-controlled but is the only signal we have at request-time without buffering the full body. Document that streamed/chunked bodies without `Content-Length` cannot be size-validated pre-forwarding (need response-side or WafEngine streaming hook).

---

## Finding 2: serde_json `set_recursion_limit` does NOT exist — Phase 06 mitigation is fictional
- **Severity:** Critical
- **Location:** Phase 06 Risks table, row 1; phase 06 §"Implementation Steps" §5 implicit assumption
- **Flaw:** Phase 06 Risks states: "Use `serde_json::de::Deserializer::from_slice(...).set_recursion_limit(150)`". This API **does not exist** on `serde_json::Deserializer` in any version, including the pinned `1.0.149` (`Cargo.lock`). Only `disable_recursion_limit()` exists, gated behind the optional `unbounded_depth` feature flag — and it does the opposite (removes the cap). The default 128-call recursion limit is built into `serde_json::from_slice` and cannot be raised or set externally.
- **Failure scenario:** A reviewer reading the Phase 06 risk register believes the stack-overflow vector is mitigated by an explicit recursion cap. It is not. In practice `serde_json::from_slice` with depth>128 returns `Err(...)` ("recursion limit exceeded"), which Phase 06 step 5 maps to BODY-001 (malformed) — so an attacker sending depth=200 JSON gets blocked, but for the wrong reason and via a fragile path. Worse, if Phase 06 implementer "fixes the unverified API" by enabling the `unbounded_depth` feature to "set 150", they will instead **disable** all recursion protection and immediately reintroduce the CVE class FR-020 was supposed to defend against.
- **Evidence:**
  - `Cargo.lock` confirms `serde_json = "1.0.149"`.
  - https://docs.rs/serde_json/1.0.149/serde_json/de/struct.Deserializer.html confirms only `disable_recursion_limit` exists (with feature gate); no setter method.
  - Phase 06 Risks row 1 verbatim: `set_recursion_limit(150)` (marked `[UNVERIFIED]`).
- **Suggested fix:** Delete the recursion-limit risk entry. Document the actual behavior: `serde_json` enforces 128 by default; bodies deeper than that fail parse → BODY-001 fires (correct outcome). Set `max_json_depth` default to 100 (below 128) so the iterative walker reports BODY-003 before parser exhaustion ambiguity. Never enable `unbounded_depth`.

---

## Finding 3: FR-014 XSS plan reuses recursive `walk_json` — same stack-overflow class it claims to defend against
- **Severity:** Critical
- **Location:** Phase 01 §"Implementation Steps" #2: "Add `scan_json_body` adapted from sql_injection_scanners (re-use traversal, swap regex set arg to `XSS_SET`)"
- **Flaw:** The function being copied (`crates/waf-engine/src/checks/sql_injection_scanners.rs:58`) is a **recursive** Rust function with **no depth cap** on `walk_json`. Phase 01 does not modify the recursion. Phase 01 Risks row 1 says "Hard cap depth at 100 inside walker; matches Phase 06 BodyAbuse limit (defense in depth)" but the implementation steps never wire that cap. Attackers send `{"a":{"a":...129 levels deep...}}` to **any host with XSS check enabled** (default-on) → process stack overflow → WAF dies → fail-open or restart loop. This is the same DoS-the-WAF vector listed in Phase 06.
- **Failure scenario:** `curl -X POST -H 'Content-Type: application/json' -d "$(python3 -c 'print("{\"a\":"*200 + "1" + "}"*200)')" https://target/anywhere` → reaches XSS check before BodyAbuse check → recursive `walk_json` → stack overflow → crash. Plan claims XSS runs **before** BodyAbuse for "more precise location attribution" (Phase 01 §step 3), so BodyAbuse defense-in-depth never executes.
- **Evidence:**
  - `crates/waf-engine/src/checks/sql_injection_scanners.rs:58-90` — `fn walk_json` is recursive, has no `depth` parameter or cap.
  - Phase 01 §step 2: "re-use traversal, swap regex set arg" — does not introduce a cap.
  - The existing SQLi check has the same latent bug (independently of this plan), but FR-020 will not save FR-014 due to phase ordering.
- **Suggested fix:** Phase 00 must include "Refactor `walk_json` to iterative `Vec<(&Value, depth)>` stack with `max_depth: usize` parameter" as a shared edit. Then both SQLi scanner and the new XSS scanner take a depth argument. Or, simpler: Phase 06's `body_abuse_walker` runs FIRST in pipeline ordering, rejecting deeply-nested bodies before XSS sees them. This requires changing pipeline ordering documented in Phase 08 — a cross-cutting change not currently planned.

---

## Finding 4: Per-IP DashMaps grow unbounded — IPv6-rotating attacker OOMs the WAF
- **Severity:** Critical
- **Location:** Phase 05 (`ScannerState.per_ip`) + Phase 07 (`BfState.failed`, `BfState.spray`)
- **Flaw:** Both phases use `DashMap<IpAddr, ...>` keyed by client IP (Phase 05) or `(user_hash, IpAddr)` (Phase 07). Phase 05 Risks row 1 *mentions* "Hard cap `per_ip` map at 100k entries; LRU evict on overflow" but the Implementation Steps never specify an LRU; no LRU library is added; `dashmap` does not provide LRU. Phase 07 has **no cap mentioned at all**. The pruner only removes entries older than the window — an attacker sending one request per second from a fresh IPv6 source per request keeps every entry "young". With `2^64 /64` realistic source-IP space, attacker easily creates 10M map entries (≈ 10M × 80 bytes ≈ 800 MB) before pruner can keep up. WAF process OOM-killed.
- **Failure scenario:** Attacker on a `/64` IPv6 prefix (free from any ISP) sends `GET /` from `2001:db8::1`, `2001:db8::2`, … Each hits Phase 05 `record_options` → DashMap insert. After a few minutes, kernel kills the WAF (OOM) → fail-open window. Same applies to Phase 07: send POST to `/login` from rotating IPv6 with random username — `BfState.failed` grows unbounded. This trades a P0 detection feature for a P0 availability hole.
- **Evidence:**
  - Phase 05 §"Implementation Steps" #1 — no cap parameter on `ScannerState`.
  - Phase 07 §"Implementation Steps" #1 — no cap on either DashMap.
  - Phase 05 Risks #1 — hand-wavy mitigation, never implemented.
  - `Cargo.toml` has no `lru` crate.
  - Existing `cc.rs` rate limiter is per-IP but has its own bounds (need separate audit, out of scope here).
- **Suggested fix:** Add explicit hard-cap with eviction policy to BOTH `ScannerState` and `BfState`. Recommend `dashmap` + manual LRU via a `parking_lot::Mutex<lru::LruCache<IpAddr, Arc<...>>>` for the eviction order, OR a simple "if `per_ip.len() > MAX, drop random 10%" panic-evict. Add bounded-memory test (1M unique IPs → memory < N MB).

---

## Finding 5: Header iteration uses `HashMap<String,String>` — multi-valued headers silently collapsed (HRS / Host duplicate bypass)
- **Severity:** High
- **Location:** Phase 04 Test #22 ("multi-value `Host: a, Host: b` → DETECT (HDR-003) — duplicate"), Phase 04 §step 2 ("iterate `ctx.headers` once")
- **Flaw:** `RequestCtx.headers: HashMap<String, String>` (`crates/waf-common/src/types.rs:30`) — a single string value per name. HTTP allows duplicate headers. The gateway necessarily folds duplicate `Host:` into one slot; the LAST or FIRST occurrence wins (depending on Pingora's parser). Phase 04's test #22 asserts that two `Host` headers will be detected as duplicate — but `HashMap` cannot represent duplicates. The test will pass only because the test author crafts a HashMap with a single key, not because production ever observes the second `Host` value. This is a textbook **request smuggling** / **Host-of-trouble** primitive: attacker sends `Host: legit.com\r\nHost: evil.com`, Pingora normalizes one (caches under "legit.com"), backend sees the other → cache poisoning / SSRF-via-Host. WAF cannot detect because it is structurally blind.
- **Failure scenario:** Attacker bypasses Host-whitelist check at FR-017 by sending duplicate Host headers. WAF sees `Host: legit.com` (in whitelist), allows. Backend (or downstream cache) acts on `Host: evil.com`. Plan's HDR-003 fires only in tests with crafted maps, never in production traffic.
- **Evidence:**
  - `/Users/admin/lab/mini-waf/crates/waf-common/src/types.rs:30` — `pub headers: HashMap<String, String>` (single value per key).
  - Phase 04 test matrix #22 cannot execute its claimed scenario through real Pingora ingestion.
  - `crates/gateway/src/router.rs:53` — `host_header.split(':').next()` shows there's no multi-value handling at the gateway either.
- **Suggested fix:** EITHER change `RequestCtx.headers` to `HashMap<String, Vec<String>>` (breaking change, large refactor) OR document that duplicate-header detection requires a dedicated upstream pass before HashMap collapse — a Pingora-layer filter. Alternatively, gateway's `request_ctx_builder` should detect `header_name appears more than once` at parse time and stash a `duplicate_headers: Vec<String>` field on `RequestCtx`. Phase 04 should then check that field, not iterate the collapsed `HashMap`. Without one of these changes, test #22 is theater.

---

## Finding 6: SSRF check decodes URL strings but skips IDN/Unicode-homograph hostnames
- **Severity:** High
- **Location:** Phase 03 §"Detection Rules" Rules 1-5 (regex on `http://...` substrings)
- **Flaw:** Phase 03 detects obfuscated IPs (octal/hex/dword) and IPv6-mapped form. It does not handle:
  1. **IDN punycode**: `http://xn--googl-fsa.com` resolves at DNS time to attacker-controlled host, which can return `169.254.169.254` (DNS rebind — out of scope, fine) OR a CNAME to internal infrastructure.
  2. **Unicode normalization**: `http://①⑦②.16.0.1/` (circled-digit) — `is_private_ip` regex won't match, but Rust's `Url::parse` will normalize and `IpAddr::from_str` may parse some Unicode digits depending on version.
  3. **`@`-userinfo trick**: `http://google.com@169.254.169.254/` — regex matches `google.com`, parser resolves to 169.254. The plan extracts URLs by regex then checks the host part via `parse_obfuscated_ip` and CIDR — but if extraction matches the **first** hostname-looking token, it gets `google.com` and silently passes.
  4. **DNS rebinding** is explicitly out-of-scope (Plan §"Out of Scope" line 87) — fine, but document that listed metadata IPs cover only 4 known cloud providers; **GCP shadow `metadata.google.internal` resolves to 169.254.169.254** which IS caught, but Hetzner/Linode/DigitalOcean/Oracle metadata endpoints are not in the list.
- **Failure scenario:** SSRF attempt `http://attacker.com@169.254.169.254/latest/meta-data/` — naive regex extracts host as `attacker.com` (matches `[^/@]+` pattern). `parse_obfuscated_ip("attacker.com")` returns None → not flagged → `is_private_ip("attacker.com")` returns false → check passes → Pingora's URL parser correctly resolves to `169.254.169.254` → AWS IMDS exposed. **Capital One CVE replay succeeds despite Phase 03 Risks row 1 claiming "regression test forever".**
- **Evidence:**
  - Phase 03 §step 2: `extract_urls_from_request(ctx) -> Vec<(&'static str, String)>` — no specified URL parsing semantics; "scan body JSON leaves + headers ... for `http(s)://...` substrings". A substring match without RFC 3986 parsing has the userinfo-bypass.
  - Phase 03 Test #6 only tests the bare `http://169.254.169.254/...` form, never the `user@host` form.
  - Researcher-02 §FR-016 documents the DNS-rebind class but not userinfo-trick.
- **Suggested fix:** Use `url::Url::parse` (the `url` crate is already a workspace dep — see `Cargo.toml:99`) to extract `.host_str()`. Run `parse_obfuscated_ip` and CIDR check on the **parsed host**, not on the raw substring. Add explicit test cases: `http://google.com@169.254.169.254/`, `http://169.254.169.254#@google.com/`, `http://[::1]:80/`. Add `metadata.platformequinix.com`, `metadata.tencentyun.com`, Hetzner/DO/Linode/Oracle endpoints to metadata pattern list.

---

## Finding 7: Brute-force "failure" detection regex is over-broad → DoS-the-detector via legit error replays
- **Severity:** High
- **Location:** Phase 07 §"Detection Rules" #3, Phase 07 §"Implementation Steps" #2
- **Flaw:** `is_failed_login_response` matches `(?i)(invalid|failed|incorrect|denied)` on the response body. Many legitimate non-auth pages contain those words: `"Invalid request format"`, `"Operation failed: please retry"`, `"Access denied to /resource"`, `"Incorrect format"`, error pages, NSFW filters, internationalization templates. Worse: the check **only fires on `bf_login_routes`**, but defaults `["/login","/api/auth/token"]` use **substring match** per test #25 (`"route prefix /api/auth/token/refresh matches /api/auth/token substring"`). A legitimate `POST /api/auth/token/refresh` returning 200 with `{"error":"Token expired, please re-login"}` is recorded as a failed login.
- **Failure scenario A (false positive → user lockout):** Legit user gets 5 token-refresh failures (genuine token expiry) → on 6th login attempt is BLOCKED with BF-001. Help desk gets called.
- **Failure scenario B (DoS the detector → hide real attack):** Attacker discovers any `bf_login_routes`-matching endpoint that legitimately returns body with the keyword. Sends 5 such requests as `username=victim` → fills `state.failed` for `(victim, attacker_ip)` → victim-account-lockout-via-third-party. Or: makes 5 distinct failed requests with same crafted password against 5 victim usernames → BF-002 spray DETECT against victim accounts → all 5 victim accounts now flagged.
- **Failure scenario C (state pollution):** Substring matching `/api/auth/token` matches `/api/auth/tokenfish` (a hypothetical user-content endpoint). Attacker can pump the bf state to OOM (compounds Finding 4).
- **Evidence:**
  - Phase 07 §"Detection Rules" #3: `body matches (?i)(invalid|failed|incorrect|denied)`.
  - Phase 07 §"Test Matrix" #25 explicitly endorses substring match for `bf_login_routes`.
  - Researcher-02 line 551 has the same regex with `unwrap()` — copy-pasted from research without analysis of FP rate.
- **Suggested fix:** (a) Use exact-equal route match (`==`) plus optional explicit prefix list (e.g. `bf_login_routes_prefix: Vec<String>`); never substring-match. (b) Drop body-regex heuristic entirely; rely on `401`/`403` status codes (which are the actual auth signal). If body-match must stay, anchor to known phrases like `^login failed`, `^invalid (username|password|credentials)$`, with case-sensitivity, AND require status >= 400.

---

## Finding 8: Plaintext password held in `Option<String>` heap allocation, no zeroization
- **Severity:** High
- **Location:** Phase 07 §"Files to Create" (`brute_force_extractors.rs`: `extract_password(ctx) -> Option<String>`), §"Implementation Steps" #2 + #3
- **Flaw:** `extract_password` returns `Option<String>` — plaintext password copied into a heap allocation, then hashed, then dropped. Without `zeroize`, the allocator may not zero the memory; another tenant in the process (plugin Wasm/Rhai) or a heap dump (panic, core file) can reveal it. Worse, the password flows through tracing: Phase 07 Risks row 4 says "`tracing::debug!` on extraction failure". A debug log line containing `body_preview` or extraction site is one Rust formatting mistake away from logging the password (e.g., `debug!(?body_preview)` would dump the entire JSON including password). Plan does not specify any `Zeroize` impl or "never log this field" guard.
- **Failure scenario:** Operator enables debug logs to investigate FR-018 false positives. Logs are scraped by Loki/Splunk. Passwords end up in long-term log retention. Compliance violation (PCI 8.2.1, GDPR Art 32).
- **Evidence:**
  - Phase 07 §"Files to Create" line: `extract_password(ctx) -> Option<String>`.
  - `Cargo.toml` has no `zeroize` crate.
  - Phase 07 §step 2 hashes via SHA-256 truncated `u64` — that's fine for the storage key, but the **input** `String` is the leak vector.
  - Phase 07 §"False Positive Mitigation" line 139: "store SHA-256 truncated u64 (not raw username); reduces memory + GDPR posture" — addresses username only, not password.
- **Suggested fix:** Add `zeroize = "1"` workspace dep. Wrap extraction in a closure that hashes immediately and drops the plaintext: `fn extract_and_hash_password(ctx) -> Option<u64>` returning the SHA-256 truncation directly; never expose `String`. Add `#[deny(clippy::useless_format)]`-style review gate that no `tracing` macro takes the body slice. Document in Phase 07: never log username, password, or body when this check is involved.

---

## Finding 9: `host_whitelist` overloaded between FR-016 (SSRF outbound allow) and FR-017 (Host-header inbound allow) — semantic collision creates bypass
- **Severity:** High
- **Location:** Phase 00 (`pub host_whitelist: Vec<String>`), Phase 03 §"False Positive Mitigation" line 96 ("v1 reuses `host_whitelist`"), Phase 04 §"Detection Rules" #3 ("must match SNI (TLS) OR be in `defense_config.host_whitelist`")
- **Flaw:** One `Vec<String>` field is wired into two opposite-polarity controls:
  - **FR-017 (HDR-003):** "Host header MUST be in `host_whitelist`" — *inbound restriction*; entries are domains the operator OWNS.
  - **FR-016 (SSRF):** "URLs to hosts in `host_whitelist` are LEGITIMATE internal callers" — *outbound permission*; entries are domains the operator allows their app to fetch from.
  These are different lists. Operators will populate one for one purpose, accidentally weakening the other:
  - Operator adds `api.internal.svc` to `host_whitelist` so the app can fetch from it (FR-016 use). Suddenly attacker can send `Host: api.internal.svc` from the public internet — passes FR-017 — proxy routes to internal API.
  - Operator adds `legit.example.com` to `host_whitelist` (FR-017 use). Attacker SSRFs to `http://legit.example.com/redirect?to=http://169.254.169.254` — Phase 03 sees `legit.example.com` in whitelist, allows the URL, server-side fetch happens; if `legit.example.com` open-redirects to IMDS → SSRF succeeds.
- **Failure scenario:** Both directions above are exploitable as documented; this is exactly the kind of "config-fiddly bypass" attackers grep for in WAF docs.
- **Evidence:**
  - Phase 00 line 61: single field.
  - Phase 03 line 96 explicitly chooses to reuse it.
  - Phase 04 line 39: same field.
- **Suggested fix:** Two distinct fields — `inbound_host_whitelist: Vec<String>` (FR-017) and `outbound_url_host_whitelist: Vec<String>` (FR-016). Plan says "if collision arises, add dedicated field in Phase 08" — that's deferred risk acceptance for a Critical-class config trap. Promote to Phase 00 split now.

---

## Finding 10: `tokio::time::pause()` does not affect `std::time::Instant` — Phase 05/07 tests are by-design flaky
- **Severity:** Medium
- **Location:** Phase 05 §"Implementation Steps" #4 ("use `tokio::time::pause()` + `advance` for deterministic time"), Phase 07 §"Implementation Steps" #7 ("use `tokio::time::pause()` for windowing"), Phase 08 Risks row 4
- **Flaw:** `tokio::time::pause()` only freezes tokio's internal timer wheel (drives `tokio::time::sleep`, `Interval`, `tokio::time::Instant`). It does **not** affect `std::time::Instant::now()`. Researcher-02 prototype code (line 470, 491) uses `Instant::now()` (the `std` import is implicit in `use std::time::Instant;` per existing `cc.rs:66`). Therefore the sliding-window state in Phase 05/07 will read real wall-clock and tests asserting "advance 16 minutes → window expired" will sleep for 16 real minutes — or the team will switch to `tokio::time::Instant`, which **does not implement `Ord` with `std::time::Instant`** and panics if confused with deadlines.
- **Failure scenario:** CI runs Phase 07 test #1 (5 × 401 within 15min). Test author writes `time::pause(); time::advance(Duration::from_secs(950));`. State module records via `std::time::Instant::now()` → all 5 timestamps are real wall-clock now. Window-expiry check `ts > cutoff` where cutoff = `Instant::now() - 900s` evaluates against real clock → pass on first run, race-fail later. Or the test author actually waits 15 minutes → CI suite blows past time limits.
- **Evidence:**
  - `crates/waf-engine/src/checks/cc.rs:66` — `use std::time::Instant;` `let now = Instant::now();` (existing pattern).
  - Researcher-02 line 470, 491 — uses `Instant::now()` (std).
  - Plan doesn't specify which `Instant` to use; just "use `tokio::time::pause()`".
- **Suggested fix:** Either (a) consistently use `tokio::time::Instant` in `BfState`/`ScannerState` (then `tokio::time::pause()` works) and document this; or (b) inject a `Clock` trait (`fn now(&self) -> Instant`) so tests can pass a `MockClock`. Pick one; document in Phase 00 alongside the trait declarations. Without this, the entire stateful test matrix for Phases 05 + 07 is wishful thinking.

---

## Summary

The plan delivers a credible structure (parallel worktrees, coverage gate, KISS over inventory!), but the **detection logic itself contains four Critical-severity bypasses** (Findings 1-4) and several High-severity weaknesses (5-9). The most worrying pattern: each phase confidently lists mitigations in Risks tables that the Implementation Steps never wire (Finding 4 LRU, Finding 6 IDN handling, Finding 8 zeroization). A reviewer scanning the Risks columns sees a tidy register; a reviewer reading the actual `## Implementation Steps` finds none of those mitigations. Recommend gating Phase 00 merge on resolving Findings 1, 2, 3 (they are cross-cutting) before any FR phase branches.

**Status:** DONE
**Total findings:** 10 (Critical: 4, High: 5, Medium: 1)
