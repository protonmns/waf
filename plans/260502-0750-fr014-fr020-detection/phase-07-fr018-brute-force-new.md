---
phase: 07
title: "FR-018 — Brute Force / Credential Stuffing (NEW + ResponseCheck pipeline wiring)"
status: pending
priority: P1
effort: 2d
dependencies: [00]
branch: feat/fr-018-brute-force
fr: FR-018
---

## Overview

NEW check requiring upstream-response inspection. Implements the `ResponseCheck` trait declared in Phase 00, wires it into `checker.rs` (parallel response pipeline), and uses `dashmap` + `parking_lot::Mutex<VecDeque<Instant>>` sliding-window state per `(username_hash, client_ip)`. Per `research/researcher-02-owasp-patterns.md#fr-018`. Same-IP only (distributed brute-force out of scope).

## Acceptance Criteria (from analysis/requirements.md:58)

> Brute Force / Credential Stuffing — Per-user failed login counter, password spraying pattern detection

## Detection Rules (from researcher-02§FR-018, Decisions C + E)

1. **Per-user failed-login counter** — sliding window 15min (configurable); ≥5 failures from same `(user_hash, ip)` → DETECT (BF-001) on NEXT request to login route from same IP+user
2. **Password spray** — same `password_hash_truncated` tried against ≥5 distinct usernames from same IP within 5min → DETECT (BF-002)
3. **Failed-login signal** — upstream response `401`/`403`, OR body matches `(?i)(invalid|failed|incorrect|denied)` (only for login routes); recorded via `ResponseCheck::on_response`
4. Login routes configured via `defense_config.bf_login_routes` (default `["/login","/api/auth/token"]`)
5. Username extraction: JSON `username`/`email`/`user` keys, OR form-urlencoded `username=` field

## Files to Create

- `crates/waf-engine/src/checks/brute_force.rs` — `BruteForceCheck` (Check + ResponseCheck impls) (≤140 LOC)
- `crates/waf-engine/src/checks/brute_force_state.rs` — `BfState` w/ DashMap<(u64,IpAddr), Mutex<VecDeque<Instant>>>, password-spray DashMap (≤120 LOC)
- `crates/waf-engine/src/checks/brute_force_extractors.rs` — `extract_username(ctx) -> Option<String>`, `extract_password(ctx) -> Option<String>`, `is_failed_login_response(status, body) -> bool` (≤80 LOC)

## Files to Modify (THIS IS THE COUPLED PHASE — see Risks)

- `crates/waf-engine/src/checker.rs` — wire `ResponseCheck` invocation. **This is shared with Phase 05** (which also uses `ResponseCheck`). Coordination: Phase 05 ships request-side only; Phase 07 lands the actual `ResponseCheck` dispatch loop. Phase 05 ResponseCheck impl will work once Phase 07 merges — sequencing in PR review.
- `crates/waf-engine/src/engine.rs` — call `checker.on_response(...)` from upstream-response callback (Pingora hook). **VERIFY existing engine entry-points** [UNVERIFIED — depends on current Pingora integration; trace before implementing].

## DefenseConfig Fields Used

- `defense_config.brute_force` (Phase 00)
- `defense_config.bf_window_secs` (Phase 00, default 900)
- `defense_config.bf_max_per_user` (Phase 00, default 5)
- `defense_config.bf_spray_threshold` (Phase 00, default 5)
- `defense_config.bf_login_routes` (Phase 00, default `["/login","/api/auth/token"]`)

## Implementation Steps

1. Create `brute_force_state.rs`:
   - `BfState { failed: Arc<DashMap<(u64,IpAddr), parking_lot::Mutex<VecDeque<Instant>>>>, spray: Arc<DashMap<(IpAddr,u64), parking_lot::Mutex<HashSet<String>>>> }`
   - `record_failed(&self, user_hash, ip, now)` — push timestamp, prune > window
   - `record_spray(&self, ip, pwd_hash, username, now)` — insert into HashSet, prune oldest if > 1000 entries per (ip,pwd_hash)
   - `is_over_threshold(&self, user_hash, ip, window, max) -> bool`
   - `is_spray(&self, ip, pwd_hash, threshold) -> bool`
   - `prune(&self, cutoff)` — for background task
2. Create `brute_force_extractors.rs`:
   - `truncated_hash(&str) -> u64` (SHA-256 first 8 bytes as u64)
   - `extract_username(ctx) -> Option<String>` — try JSON `username`/`email`/`user`, then `application/x-www-form-urlencoded`
   - `extract_password(ctx) -> Option<String>` — same shape
   - `is_failed_login_response(status, body_preview) -> bool` — `401`/`403` short-circuit; else regex on body
3. Create `brute_force.rs`:
   - `BruteForceCheck { state: Arc<BfState> }`
   - `impl Check::check`: gate; route match against `bf_login_routes`; if state shows over-threshold for `(user_hash, ip)` → DETECT (BF-001); if spray detected → DETECT (BF-002); else None
   - `impl ResponseCheck::on_response`: gate; route match; if `is_failed_login_response`, extract username + password, hash, call `state.record_failed` and `state.record_spray`
4. Wire into `checker.rs`:
   - Add `Vec<Arc<dyn ResponseCheck>>` to checker
   - New method `pub async fn on_response(&self, ctx: &RequestCtx, status: u16, body: &[u8])` iterates `response_checks`
5. Wire into `engine.rs`:
   - Locate Pingora upstream-response callback (likely `upstream_response_filter` or similar) — **trace this before code change**
   - Invoke `self.checker.on_response(ctx, status, body_preview).await`
6. Spawn pruner: `tokio::spawn` in `BruteForceCheck::new`, every 60s call `state.prune(Instant::now() - 30min)`. Notify-driven shutdown.
7. Add tests (≥25 — see matrix); use `tokio::time::pause()` for windowing
8. `cargo fmt && cargo clippy -p waf-engine -- -D warnings && cargo test -p waf-engine brute_force`
9. Add bench `crates/waf-engine/benches/brute_force.rs`

## State Machine

```
                 +----------------+
 request -----> | request-phase  |---> if state[(user,ip)] >= 5 → BLOCK (BF-001)
                |  Check::check  |---> if spray[(ip,pwd)] >= 5 → BLOCK (BF-002)
                +-------+--------+
                        |
                        v (None) — pass to upstream
                  upstream returns
                        |
                        v
                 +----------------+
 response ----> | resp-phase     |---> if status in {401,403} OR body~"failed":
                | ResponseCheck  |       extract username/pwd → hash → record
                | ::on_response  |       update state[(user,ip)] += 1, spray[(ip,pwd)] += {user}
                +----------------+
```

## Test Matrix (target ≥25 tests)

| # | Vector | Expect |
|---|---|---|
| 1 | 5 × 401 from same (alice, IP_X) within 15min, then 6th request | DETECT (BF-001) |
| 2 | 4 × 401, then 5th request | None (boundary) |
| 3 | 5 × 401 over 30min | None (window expired) |
| 4 | 5 × 401 (alice, IP_X) + 1 (alice, IP_Y) | None for IP_Y (per-IP isolation) |
| 5 | password "P@ss1" against 5 distinct usernames (charlie, diana, eve, frank, grace) from same IP | DETECT (BF-002) on 5th |
| 6 | password "P@ss1" against 4 users → 5th attempt | None |
| 7 | clean login success (200) | None, no state change |
| 8 | response 401, route NOT in `bf_login_routes` | None, no state change |
| 9 | request to `/login` but `defense_config.brute_force=false` | None |
| 10 | response 401 with body "Server error" not matching failure regex | not recorded (false positive avoidance) |
| 11 | hot-reload: change `bf_max_per_user` from 5 to 10 mid-flight | new threshold takes effect on next request |
| 12 | concurrent: 100 tasks recording same (user,ip) | state count consistent (mutex correctness) |
| 13 | username extraction: JSON `{"username":"x"}` | works |
| 14 | username extraction: JSON `{"email":"x@y.z"}` | works |
| 15 | username extraction: form `username=x&password=y` | works |
| 16 | username missing in body | record skipped silently |
| 17 | extract username with weird casing | hashed to same value |
| 18 | pruner: state cleared after 30min | dashmap len == 0 |
| 19 | empty body POST to /login | record skipped |
| 20 | request-phase BF-001 fires WITHOUT response (state pre-populated) | DETECT |
| 21 | response 200 success after 4 failures → state retained but no detection | None on next |
| 22 | response 403 (not 401) on login | recorded as failure |
| 23 | response body match `"login failed"` with status 200 | recorded |
| 24 | spray + per-user thresholds both exceeded → BF-001 wins (lower rule_id) | DETECT BF-001 |
| 25 | route prefix `/api/auth/token/refresh` matches `/api/auth/token` substring | recorded (substring match) |

## Bench

`crates/waf-engine/benches/brute_force.rs`:
- `bf_check_request_phase_clean`: < 30µs p99 (state lookup only)
- `bf_check_request_phase_blocked`: < 40µs p99
- `bf_response_record_failed`: < 50µs p99 (DashMap insert + Mutex<VecDeque> push)
- `bf_response_spray_record`: < 80µs p99 (HashSet insert)
- **Aggregate budget per check: p99 < 200µs**

## False Positive Mitigation

- Per researcher-02§FR-018 Scenario A (forgot password): default threshold 5 is conservative; real-world typo recovery is rare to exceed
- Scenario B (shared accounts): documented; opt-in to `defense_config.bf_shared_accounts: Vec<String>` (defer to Phase 08 if needed; v1 ships without this — accept FP)
- Scenario C (API client retry): only count `401`/`403`/regex-match; transient `503` ignored
- Privacy: store SHA-256 truncated `u64` (not raw username); reduces memory + GDPR posture

## Branch + PR

- Branch: `feat/fr-018-brute-force`
- Squash commit: `feat(detection): FR-018 brute force + credential stuffing (ResponseCheck pipeline wiring)`
- `gh pr create --base main --head feat/fr-018-brute-force --title "feat(detection): FR-018 brute force" --reviewer lotus`

## Coverage Requirement

`crates/waf-engine/src/checks/brute_force*.rs` (3 files): combined ≥90%; `checker.rs` and `engine.rs` deltas ≥90% (existing high coverage retained).

## Definition of Done

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test -p waf-engine brute_force` ≥25 tests passing
- [ ] Coverage gate passes (note: `checker.rs` + `engine.rs` modifications must keep waf-engine crate ≥90%)
- [ ] Bench p99 < 200µs across all scenarios
- [ ] Manual e2e: spin up `podman-compose up -d --build`, send 6 × invalid login → 6th gets blocked
- [ ] PR opened, CI green

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `engine.rs` Pingora callback for response not actually exposed → cannot wire `on_response` | Medium | Critical | **Phase 07 first task**: trace existing engine.rs response handling. If absent, escalate — may require Pingora upgrade or additional Phase 0.5 |
| `checker.rs` shared edit conflicts with Phase 05 | High | Medium | Phase 07 sequenced AFTER Phase 05 merges (see plan.md ordering); on rebase, manual merge of `Vec<Arc<dyn ResponseCheck>>` field |
| Cross-task synchronization on shared state under load | Medium | High | Stress test: 1000 concurrent record_failed; verify VecDeque mutex doesn't deadlock |
| `extract_username` failure mode silent — failures uncountable | Low | Medium | `tracing::debug!` on extraction failure; metric counter for "bf_extract_failed" |
| Pruner task lost on engine restart → state grows | Low | Medium | DashMap is in-memory only; restart resets — acceptable |
| Distributed brute force unmitigated | High | Low | Out-of-scope per plan.md; documented |

## Rollback

Multi-touch (3 new files + 2 modified). Squash commit; `git revert <sha>` reverses everything atomically. Worst case: `checker.rs` ResponseCheck dispatch reverts, Phase 05's response-side stub becomes dead code (warning only). Restart engine — state resets.

## Note on Sequencing

Because Phase 07 modifies `checker.rs` AND `engine.rs` (shared with Phase 05), it should merge AFTER Phase 05 lands to minimize cascading rebases. **Recommended merge order: 01, 02, 03, 04, 06 → 05 → 07 → 08.** Sibling rebase via R3§Sec2 Step6 script.

## Red Team Fixes (applied 2026-05-02)

Findings #6, #7, #8, #11, #14. See `plan.md ## Red Team Review`.

### Finding #7 — Collapse `ResponseCheck` into `Check::on_response` default-impl
The separate `ResponseCheck` trait + parallel pipeline is over-engineered for 1.5 callers (FR-018 + FR-019 piggyback) and creates async/sync mismatch (Pingora `response_filter` is `async fn`, existing `Check` is sync).

- **Replace** Implementation Steps 4 + 5 (`checker.rs` and `engine.rs` wiring):
  > 4. `checker.rs` — **No new method**. The orchestrator iterates `Vec<Box<dyn Check>>` and calls `check.on_response(ctx, status)` (default no-op for the 11 existing checks; FR-018 + FR-019 override).
  > 5. `engine.rs` — Add a single new method on `WafEngine`:
  >    ```rust
  >    pub fn on_response(&self, ctx: &RequestCtx, status: u16) {
  >        for check in &self.checkers {
  >            check.on_response(ctx, status);
  >        }
  >    }
  >    ```
  >    This is sync (no body, no awaits). Gateway calls it from the `response_filter` callback at `crates/gateway/src/proxy.rs:429` after extracting `status_code`.
- **Update** "Files to Modify" to drop `checker.rs`; only `engine.rs` adds the new method.

### Finding #8 — Pingora `response_filter` does NOT expose body
Verified `crates/gateway/src/proxy.rs:429`: `response_filter` signature exposes headers + status only. Body is in `response_body_filter` at line 472, which has no waf-engine call site. The plan's body-regex failure detection cannot work.

- **Drop** body-regex from Detection Rule 3:
  > 3. **Failed-login signal** — upstream response status `401` or `403` ONLY (status-code-only v1). Body-regex deferred to a future PR that wires `response_body_filter` into the engine (cross-crate change).
- **Drop** `bf_failure_body_regex_enabled` config field (not added; YAGNI).
- **Drop** test #23 (body match without 401/403). Update test #22 to only assert 403 case.

### Finding #11 — Failure regex is weaponizable
Even if body-regex were available, `(?i)(invalid|failed|incorrect|denied)` is broad enough to false-positive on legit responses ("Your password failed our complexity check"). An attacker could weaponize this as a victim-account-lockout primitive by crafting URLs that elicit such responses. Status-code-only avoids this entirely.

- Already addressed by Finding #8 fix (drop regex). No additional action.

### Finding #14 — `tokio::spawn` from `BruteForceCheck::new`
Same as Phase 05 Finding #14. Move to engine init.

- **Replace** Implementation Step 6:
  > Do NOT spawn from `BruteForceCheck::new`. Provide `pub fn spawn_pruner(state: Arc<BfState>, shutdown: Arc<tokio::sync::Notify>) -> tokio::task::JoinHandle<()>`. Engine bootstrap calls it.

### Finding #6 — DashMap + VecDeque unbounded
Same root cause as Phase 05 Finding #6.

- **Add** to `BfState` struct in step 1:
  > Cap both DashMaps:
  > ```rust
  > pub struct BfState {
  >     failed: Arc<DashMap<(u64, IpAddr), parking_lot::Mutex<VecDeque<Instant>>>>,
  >     spray: Arc<DashMap<(IpAddr, u64), parking_lot::Mutex<HashSet<String>>>>,
  >     max_entries: usize, // default 100_000 per map
  > }
  > // Inside record_failed/record_spray: if map.len() > max_entries, evict 10%
  > //   sampled-oldest-timestamp (same algorithm as Phase 05 ScannerState).
  > // Inside record_spray: cap HashSet at 1000 (already in plan); add cap on
  > //   VecDeque too: max length = bf_max_per_user * 4 (well above threshold).
  > ```
- **Add test**: `bf_state_caps_failed_at_max_entries` and `bf_state_caps_spray_at_max_entries`.

### Outstanding (acknowledged, not blocking)
- `parking_lot` "already used in sql_injection_scanners" claim is false — actually used in `crowdsec/cache.rs` and `relay/intel/*`. Citation in plan.md Dependencies table is wrong but `parking_lot` IS a workspace dep. Implementer just verifies via `cargo tree -p waf-engine | grep parking_lot`.

## Validation Updates (Session 1 — 2026-05-02)

### `Clock` trait wiring (Q7)
- **Modify** `BfState` struct (step 1):
  ```rust
  pub struct BfState {
      failed: Arc<DashMap<(u64, IpAddr), parking_lot::Mutex<VecDeque<Instant>>>>,
      spray: Arc<DashMap<(IpAddr, u64), parking_lot::Mutex<HashSet<String>>>>,
      max_entries: usize,
      clock: Arc<dyn Clock>,
  }
  impl BfState {
      pub fn new(max_entries: usize, clock: Arc<dyn Clock>) -> Self { ... }
  }
  ```
- All `Instant::now()` → `self.clock.now()`. Tests use `MockClock::advance()` to simulate sliding-window expiry.

### Status-code-only failure detection confirmed (Q3)
- Detection Rule 3 reads: "401 OR 403 ONLY". Body-regex code path NOT implemented; `bf_failure_body_regex_enabled` config field NOT added.
- Document in `False Positive Mitigation`: "Backends returning HTTP 200 with JSON error body (e.g., legacy GraphQL-style error envelope) WILL bypass FR-018 v1. Operator must wrap such backends in a 401-translating middleware OR wait for body-aware FR-018-v2 (deferred)."

### `host_whitelist` collision: this phase does NOT use that field — no propagation needed.
