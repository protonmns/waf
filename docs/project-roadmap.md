# Project Roadmap

## Release History & Status

### v0.1.0-rc.1 (2026-03-16) — Complete

**Cluster Foundation (P1–P5)**
- [x] QUIC mTLS transport (quinn + rustls + rcgen)
- [x] Raft-lite leader election with phi-accrual failure detection
- [x] Rule sync (incremental changelog + full snapshot)
- [x] Admin UI cluster dashboard (4 new pages)
- [x] docker-compose cluster setup (3-node, 1 main + 2 workers)
- [x] End-to-end integration tests (20+ cluster scenarios)

**Core WAF**
- [x] 16-phase detection pipeline
- [x] 51 built-in rules (OWASP CRS, CVE patches, advanced patterns)
- [x] WASM plugin system (wasmtime 23)
- [x] Rhai custom rule scripting
- [x] CrowdSec bouncer + AppSec integration
- [x] PostgreSQL persistence layer
- [x] Vue 3 admin UI (19 pages)

---

### v0.2.0 (2026-03-27) — Complete ✓

**Status**: Production-ready, all acceptance criteria met

**Security Hardening**
- [x] 8 panic-capable unwrapping → safe degradation (panic elimination)
- [x] SSRF protection (url_validator module, DNS rebinding guard)
- [x] Iterative URL decoding (up to 3 rounds, encoding bypass prevention)
- [x] Remote rule source hardening (30s timeout, 10MB size limit, no redirects)
- [x] Admin API security middleware (IP allowlist, rate limiting, security headers)
- [x] Login rate limiting (per-IP configurable)
- [x] WebSocket IP allowlist
- [x] Cluster peer fencing (stale peer eviction)
- [x] XFF trusted-proxy CIDR validation (config error, not runtime panic)
- [x] Rule deletion atomic swap (RuleRegistry in-memory sync)

**Rule Engine Enhancements**
- [x] libinjectionrs integration (detect_sqli, detect_xss operators)
- [x] OWASP CRS rule operators now fully evaluated (CRS-942100, CRS-941100)
- [x] Remote rule source async loading (background fetch post-startup)
- [x] Rule source URL validation (public IP only, no RFC-1918)

**Dependency Upgrades (Security + Compatibility)**
- [x] wasmtime: 23.0.3 → 43.0.0 (5 CVEs fixed)
- [x] axum: 0.7 → 0.8.8
- [x] tower: 0.4 → 0.5.3
- [x] jsonwebtoken: 9 → 10 (OpenSSL → rust_crypto)
- [x] reqwest: 0.12 → 0.13
- [x] tokio-tungstenite: 0.23 → 0.26
- [x] serde_yaml: 0.9 → serde_yaml_ng 0.10
- [x] sqlx: set default-features = false (drop rsa dep)

**Testing & Quality**
- [x] E2E test suite (1,812 LOC): 5 shell runners (rules-engine, gateway, api, cluster, report-renderer)
- [x] 63+ SQLi acceptance tests (19 patterns, encoding bypasses, false positives)
- [x] 116 new regression tests (suite total: 243)
- [x] SSRF validation tests
- [x] Encoding bypass prevention tests
- [x] SQLi/XSS detection tests
- [x] Cluster peer fencing tests
- [x] Dependency upgrade compatibility tests
- [x] Zero unaddressed high/critical CVEs

**Deliverables**
- [x] Release notes (CHANGELOG.md)
- [x] Security advisory (panic elimination, SSRF guard)
- [x] Build & test automation (CI passing)
- [x] Documentation (architecture, deployment, code standards)

**Metrics v0.2.0**
- Regression test coverage: 243 tests (↑116 from v0.1); E2E suite 1,812 LOC with 5 modular runners
- SQLi modularization: 19 patterns (SQLI-001..019), 3 scanner modules (classic/blind/error-based)
- SQLi benchmarks: p99 <500µs clean traffic, <1ms malicious payloads
- Security issues fixed: 10 (8 panics, SSRF, DNS rebinding, encoding bypass)
- Performance: <0.5ms per request (99th percentile, unchanged)
- Cluster stability: 3-node election <500ms (unchanged)

---

## Unreleased (In Progress — 2026-04-29)

### FR-004 — Rate Limiting (Complete ✓)

Tiered rate limiting with token-bucket (burst) and sliding-window (sustained) algorithms. Two-tier store architecture: MemoryStore (DashMap, idle-eviction 10min, 100K cap) for fast local checks, RedisStore (single Lua script roundtrip) for distributed state. BreakerStore circuit-breaker (default 5 failures) routes to memory fallback. Dual keys: `ip:<host>:<client_ip>` (flood short-circuit) and `sess:<host>:<session_id>` (fallback to device-fp). Both must Allow for request to pass. Rule IDs: RL-IP, RL-SESSION, RL-ERR. Hot-reload via `configs/rate-limit.yaml` (notify watcher, 200ms debounce, ArcSwap snapshot). Per-tier config: `burst_capacity`, `burst_refill_per_s`, `window_secs`, `window_limit`. Fail-mode honors tier policy (Close=block, Open=pass).

- [x] Token-bucket + sliding-window algorithms (pure logic, ~16B state per key)
- [x] MemoryStore (DashMap, idle-eviction, background cleanup)
- [x] RedisStore (Lua script, 50ms timeout)
- [x] BreakerStore (circuit-breaker with fallback)
- [x] Dual-key strategy (IP + session, both must Allow)
- [x] YAML hot-reload (`configs/rate-limit.yaml`, schema v1)
- [x] Per-tier policies via TierPolicyRegistry
- [x] Integration as Check trait, fail-mode dispatch
- [x] Rule IDs: RL-IP, RL-SESSION, RL-ERR
- [x] Plan: plans/260502-1957-fr004-rate-limiting/

**Deliverables**
- Module: `crates/waf-engine/src/checks/rate_limit/`
- Config: `configs/rate-limit.yaml` (example)
- Rules emitted: RL-IP (IP limit), RL-SESSION (session limit), RL-ERR (check error)

---

### FR-005 — DDoS Protection (Complete ✓)

Multi-layer DDoS detection with per-IP, per-fingerprint, and per-tier sliding-window detectors. Dynamic IP banning with TTL, graceful degradation on store failures (Redis down), and per-tier fail-mode policies (Close=block, Open=pass). Three detection layers: (1) **PerIpDetector** — incremental sliding-window counter per client IP; threshold: `ddos.per_ip.threshold_rps` (configurable, e.g., 1000 RPS). (2) **PerFingerPrintDetector** — groups requests by device fingerprint (FR-010 JA3/JA4 + HTTP/2 hash) to detect botnet attacks across rotating IPs; fallback to per-IP if fingerprint unavailable. (3) **PerTierDetector** — adaptive RPS threshold per tier (Critical/High/Medium/CatchAll), detects tier-wide bursts (e.g., all Critical endpoints hammered). Store backends: MemoryStore (100K cap, idle-eviction 10min) or RedisStore (single Lua script roundtrip, 50ms timeout). BreakerStore circuit-breaker (5 failure threshold) routes to memory fallback on Redis errors. Actions: **Ban** (add IP to ban table, TTL 60s, short-circuits to 403), **RiskBump** (emit `Signal::DdosSuspected` to FR-025 risk scorer), **Degrade** (fail-open/close per tier policy on store error). Nightly soak test (5+ min sustained 1K RPS) verifies memory growth <5%, ban table bounded <300K entries, no panics. Rule IDs: `DDOS-BAN`, `DDOS-RISK`, `DDOS-DEGRADE`.

- [x] Per-IP sliding-window detector (16-bit quantized buckets, per-tier threshold)
- [x] Per-fingerprint detector (FpKey from FR-010; fallback to per-IP)
- [x] Per-tier detector (adaptive threshold per Tier enum)
- [x] Ban table (in-memory hash map, TTL-based eviction)
- [x] MemoryStore (DashMap, idle-eviction, background cleanup)
- [x] RedisStore (Lua script, 50ms timeout, feature-gated)
- [x] BreakerStore (circuit-breaker, fallback to memory)
- [x] DdosAction executor (Ban, RiskBump, Degrade)
- [x] Per-tier fail-mode degradation (Close=block, Open=pass)
- [x] Metrics: detections, hard bursts, bans issued, store errors, degrade events, latency histogram
- [x] Integration tests (I1-I4): per-IP ban, per-FP fallback, per-tier detection, config reload
- [x] Scenario tests (a-e): baseline traffic, single IP flood, botnet pattern, tier fail-modes, Redis down
- [x] Soak test (nightly): 5+ min at 1K RPS, memory drift <5%, ban table <300K
- [x] GitHub workflow (`.github/workflows/ddos-soak.yml`): scheduled nightly + manual dispatch
- [x] Plan: `plans/260505-0954-fr-005-ddos-protection/` (10 phases, all complete)

**Deliverables**
- Module: `crates/waf-engine/src/checks/ddos/`
- Config: `configs/default.toml` `[ddos]` section + `[ddos.per_tier]`
- Tests: `crates/waf-engine/tests/{ddos_integration,ddos_scenarios,ddos_soak,ddos_loom,ddos_proptest}.rs`
- CI workflow: `.github/workflows/ddos-soak.yml` (nightly schedule + manual trigger)
- Operator guide: `docs/ddos-protection.md`
- Metrics: `ddos_detector_evaluations_total`, `ddos_hard_burst_total`, `ddos_bans_issued_total`, `ddos_ban_table_size`, `ddos_store_errors_total`, `ddos_degrade_events_total`, `ddos_detector_latency_us`

**Performance (verified in soak test):**
- Detector latency p99: <500µs per request
- Ban table lookup: <100µs
- Memory growth: <5% drift over 5+ min sustained load
- Ban table capacity: 100K entries (soft limit; hard cap enforced)

---

### FR-009 — Smart Caching (Complete ✓)

Response caching with tier-aware bypass logic and tag-based purge. CRITICAL tier never cached (non-overridable). Pipeline refactored to Chain-of-Responsibility: TierGate → MethodGate → AuthGate → RouteRuleGate → UpstreamCcGate → TierDefaultGate. YAML hot-reload of `rules/cache.yaml` (notify, 200ms debounce, ArcSwap, schema v1). Tag index (DashMap reverse-index, moka eviction listeners) with admin endpoints for purge-by-tag / purge-by-route and cache stats. Schema: defaults (max_body_bytes, cacheable_status_codes [200,203,301,410]), rules with id/match{host,path.regex,methods}/ttl_seconds/tags/allow_authenticated. Tier defaults: NoCache, ShortTtl{300}, Aggressive{600}, Default{60}.

- [x] Tier-aware bypass logic (CRITICAL never cached)
- [x] Chain-of-Responsibility pipeline (6-gate architecture)
- [x] YAML hot-reload (`rules/cache.yaml`, schema v1)
- [x] Tag-based purge index (DashMap + moka eviction listeners)
- [x] Admin endpoints: POST /api/cache/purge/tag, POST /api/cache/purge/route
- [x] Cache stats: GET /api/cache/stats (hit/miss/bypassed/tag_index_size)
- [x] Regex/ID validation on YAML parse; error-safe hot-reload
- [x] Per-tier TierDefault policies (NoCache, ShortTtl, Aggressive, Default)
- [x] Plan: plans/260502-2150-fr-009-smart-caching/

**Deliverables**
- Module: `crates/gateway/src/cache/`
- Config: `rules/cache.yaml` (example)
- Admin endpoints: cache purge + stats

---

### FR-002 — Tiered Protection (Complete ✓)

Implements a four-tier request classification and per-tier policy bus that all downstream feature-requests (FR-005, FR-006, FR-009, FR-027) consume. Every request is mapped to `Critical / High / Medium / CatchAll` by a priority-sorted classifier (path-exact, path-prefix, path-regex, host-suffix, method, header matchers); the matched tier's `TierPolicy` — carrying `fail_mode`, `ddos_threshold_rps`, `cache_policy`, and `risk_thresholds` — is attached to `RequestCtx` before Phase 1 runs. The policy registry is backed by `ArcSwap` for lock-free atomic hot-swaps: the `TierConfigWatcher` thread monitors `configs/default.toml`, debounces editor-burst events (200 ms window), and publishes validated snapshots without restarting the gateway. On parse or validation failure the previous config is retained and a `tracing::warn!` is emitted; the gateway never panics on bad config.

- [x] `waf-common::tier` — `Tier` enum, `TierPolicy`, `TierClassifierRule`, `TierConfig::validate()`, TOML schema
- [x] `gateway::tiered::TierClassifier` — compiled rules, priority sort, first-match-wins
- [x] `gateway::tiered::TierPolicyRegistry` — `ArcSwap<TierSnapshot>`, lock-free classify
- [x] `gateway::tiered::TierConfigWatcher` — `notify`-based hot-reload, debounce, atomic swap
- [x] `gateway::ctx_builder` — wires classifier into `RequestCtxBuilder`; `ctx.tier` set before checks
- [x] E2E integration tests (`crates/gateway/tests/tier_e2e.rs`) — 6 tests covering all 4 tiers, default fallback, TOML round-trip, and hot-reload
- [x] Criterion bench (`crates/gateway/benches/tier_classifier_bench.rs`) — 50-rule classify over 1000 paths
- [x] Consumer doc (`docs/tiered-protection.md`) — API reference for FR-005/006/009/027 implementers
- [x] Architecture diagram — Mermaid tier flow added to `docs/system-architecture.md`

### FR-003 — File-Based Custom Rule Loader (Complete ✓)

Scans `rules/custom/*.yaml` and auto-loads YAML documents marked with `kind: custom_rule_v1`. Per-file error isolation: bad files skip gracefully, previous versions retained, errors logged. Hot-reload via `notify` watcher (500ms debounce). Forward-compat: unknown `custom_rule_v*` versions rejected on parse.

- [x] `crates/waf-engine/src/rules/custom_file_loader.rs` — watcher loop, scan + load
- [x] `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs` — multi-doc YAML parser, `kind` discriminator
- [x] Rule registry integration: clear stale, `add_file_rule` per result
- [x] Tests: `custom_rule_file_load.rs`, `custom_rule_hot_reload.rs`
- [x] Updated `docs/custom-rules-syntax.md` (already current)

### FR-008 — Whitelist + Blacklist (Complete ✓)

Phase-0 access-control gate that runs before the 16-phase rule pipeline: per-tier IP whitelist (Patricia trie via `ip_network_table`), IP blacklist, per-tier Host (FQDN) whitelist, with `full_bypass` / `blacklist_only` per-tier dispatch (Strategy). Snapshot lives behind `Arc<ArcSwap<AccessLists>>`; the `notify`-driven reloader watches `rules/access-lists.yaml`, debounces editor save bursts (~250 ms), and atomically swaps validated snapshots — bad YAML keeps the previous snapshot live with a `tracing::warn!` (D8). Decision chain runs Host gate → IP blacklist → IP whitelist (deny wins over allow); audit fields `access_decision` / `access_reason` / `access_match` stamp every request. Soft-warn ≥50k entries, hard-reject ≥500k.

- [x] `crates/waf-engine/src/access/{config,ip_table,host_gate,evaluator,reload}.rs` — schema, trie adapter, host gate, chain evaluator, watcher
- [x] `crates/gateway/src/pipeline/access_phase.rs` — Phase-0 wiring
- [x] `crates/waf-engine/tests/access_hot_reload.rs`, `access_reload_under_load.rs` — hot-reload integration
- [x] `crates/waf-engine/benches/access_lookup.rs` — bench: v4 p99 ≤2µs @ 10k, v6 ≤4µs
- [x] Operator doc (`docs/access-lists.md`) + sample YAML (`rules/access-lists.yaml`)
- [x] Cross-links: `tiered-protection.md` §10, `codebase-summary.md`, `system-architecture.md`

Deferred follow-ups: Tor exit list (FR-042), ASN-aware rule predicates (FR-025/026 risk-scorer integration).

### FR-007 — Relay & Proxy Detection (Complete ✓)

Detects relay/proxy traffic via XFF validation, proxy-chain hop-depth analysis, and ASN classification (residential/datacenter/Tor exit). Multi-provider architecture with hot-reload support.

- [x] `crates/waf-engine/src/relay/` — XFF validator, proxy-chain analyzer, ASN classifier, Tor exit matcher
- [x] `crates/waf-engine/src/relay/intel/` — IP intel refresh (Tor feed, IPinfo Lite mmdb, iptoasn fallback)
- [x] `crates/gateway/src/proxy.rs` — relay detector integration, `ClientIdentity` attachment to request context
- [x] YAML hot-reload — `ArcSwap<RelayConfig>`, `ArcSwap<TorSet>`, `ArcSwap<AsnDb>` with `notify` watcher
- [x] Test suite (9 integration tests + 1 gateway test) — XFF edge cases, proptest fuzz (256 cases), ASN override precedence, Tor exit matching, intel feed scenarios (200/304/500/below-floor), hot-reload propagation ≤1s
- [x] Criterion bench (`relay_eval`) — 4-hop XFF + all 4 providers, p99 <50µs target
- [x] Adversarial test matrix (12 rows) — spoofed XFF, IPv6 zone-id, oversize headers/chains, unicode rejects, compromised feed scenarios
- [x] Wiremock intel feed tests — covers TorFeed, IpinfoLite, Iptoasn refresh with 200/304/500/below-floor outcomes
- [x] Dev-deps added: `proptest`, `wiremock`, `reqwest` (explicit for tests)

**Deferred to CI pipeline:** ≥90% coverage llvm-cov gate, `.unwrap()` grep gate, 1M-entry Tor oversize test, IptoasnFeed gz variant test, full Pingora e2e (substituted with wiring contract test).

### FR-010 — Device Fingerprinting (Complete ✓)

JA3 / JA4 TLS fingerprint, full Akamai HTTP/2 fingerprint, UA entropy / churn, and "same device switching IPs" detection. Trait-driven extension with YAML hot-reload; signal-only output via `RiskAggregator` (FR-025 plug-in point).

- [x] `crates/waf-engine/src/device_fp/` — capture, fingerprint, identity, providers, aggregator, registry, reload
- [x] `vendor/pingora/` — patched fork exposing L4 `ClientHelloInspector` + `H2FrameInspector`
- [x] `IdentityStore` trait + 2 impls — Memory (default) + Redis (feature `redis-store`); shared conformance suite
- [x] 5 signal providers — `ip_hopping`, `fp_conflict`, `ua_entropy`, `ua_blocklist`, `h2_anomaly`
- [x] YAML schema (`deny_unknown_fields`) + `ArcSwap<DeviceFpConfig>` hot reload
- [x] CI coverage gate ≥90% scoped to `device_fp/` (`device-fp-coverage` job)
- [x] Criterion benches (`device_fp_capture`, `device_fp_pipeline`); nightly bench job; p99 <300µs target
- [x] Operator guide: [`docs/device-fingerprinting.md`](device-fingerprinting.md)

**Deferred:** real-client capture fixtures (curl-impersonate harness), gateway listener wiring patch, JA4+ extended hashes (JA4S/JA4H/JA4X) — tracked in `plans/260501-2005-fr010-device-fingerprinting/plan.md`.

### FR-011 — Behavioral Anomaly Detection (Complete ✓)

Per-actor sliding-window behavior recorder with four classifiers detecting bot/automation patterns: burst inter-request intervals (<50 ms), robotic cadence (low coefficient of variation), zero-depth single-path sessions on CRITICAL tier, and missing-Referer navigational requests. All signals share one per-`FpKey` sliding-window state struct (16-slot ring, alloc-free, ≤1KB), emit through existing `RiskSignalProvider` pattern, feed FR-010 risk aggregator → FR-RS-048/049 risk deltas.

- [x] `crates/waf-engine/src/device_fp/behavior/` — state, recorder, config, path exempt matchers
- [x] Four classifiers: `burst_interval`, `regularity`, `zero_depth`, `missing_referer` (trait-driven providers)
- [x] Hot-reload of `configs/device-fp.yaml` `behavior:` block (ArcSwap, 200ms debounce, arc-swap pattern)
- [x] Criterion bench (`behavior_eval.rs`): `behavior_record_only` ~80 ns, `behavior_full_eval` ~840 ns (budget <5 µs ✓)
- [x] Proptest coverage (`behavior_property.rs`): classifiers_never_panic, window_size_bounded, evaluation_is_idempotent
- [x] Integration wiring: Pingora request_filter hook, per-request record + classify loop
- [x] `docs/codebase-summary.md` updated with FR-011 prose + behavior tree entry
- [x] Plan: `plans/260504-1129-fr-011-behavioral-anomaly-detection/` (6 phases, all completed)

**Deviations from plan:** Loom test SKIPPED (DashMap/parking_lot/Instant not loom-instrumented; concurrent_inserts_no_panic empirical test in recorder.rs covers concurrent inserts). 1000×1000 stress test SKIPPED (100×100 already in recorder.rs). CI `llvm-cov --fail-under-lines 90` step SKIPPED (matches existing project pattern — cache/gateway coverage gates already commented out).

**Node-local state only (open question):** v1 ships node-local per-node recorder; cluster behavioral state mirroring documented as post-v0.2 work.

### FR-012 — Transaction Velocity & Sequence Detection (Complete ✓)

Cross-endpoint behavioral fraud detection: rapid login→OTP→deposit sequences, withdrawal velocity bursts, and limit-change storms. Signal-only — emits to the shared `RiskAggregator` (FR-025 plug-in point), never blocks directly. Per-session state via `DashMap<SessionKey, ActorTx>` (lock-free shards) with 16-slot `ArrayVec` ring buffer (~256 B per session, alloc-free after first record). Identity priority: session cookie (configurable name) → device-fp `FpKey` fallback. Three classifiers run on every record under one `Arc<dyn Classifier>` registry: `SequenceTiming` (Login→OTP→Deposit < `min_human_ms`), `WithdrawalVelocity` (≥N withdrawals / window), `LimitChangeBurst` (analogous). Per-session cooldown (`signal_cooldown_ms`, default 5s) suppresses duplicate signal flooding. TTL janitor purges idle sessions (`session_ttl_secs`, default 600s). Hot-reload via `ArcSwap<TxVelocityConfig>` driven by `notify` watcher on `configs/tx-velocity.yaml` — bad YAML retains last-good snapshot with `tracing::warn!`. Engine integration: positioned after `RateLimitCheck`, before `ScannerCheck` (Phase 5.5) — flood traffic shed first, but tx-velocity records before pattern checks pollute state.

- [x] Module: `crates/waf-engine/src/checks/tx_velocity/` (config, role_tagger, recorder, classifier, classifiers/, session_key, check)
- [x] `Signal` enum extended with 3 variants: `TxSequenceTooFast`, `WithdrawalVelocity`, `LimitChangeBurst`
- [x] Engine wiring: `WafEngine::start_tx_velocity_watcher` + check registered in checker chain
- [x] YAML schema v1 + hot-reload (`configs/tx-velocity.yaml`)
- [x] Unit tests: 31 (role_tagger 4, recorder 12, classifiers 15)
- [x] Integration tests: 9 (`crates/waf-engine/tests/tx_velocity_integration.rs`)
- [x] Criterion benches: 6 (`crates/waf-engine/benches/tx_velocity_bench.rs`) — p99 < 100µs verified
- [x] Operator guide: [`docs/transaction-velocity.md`](./transaction-velocity.md)
- [x] Pipeline doc updated: Phase 5.5 in [`docs/request-pipeline.md`](./request-pipeline.md)
- [x] Plan: [`plans/260504-1632-fr-012-transaction-velocity/`](../plans/260504-1632-fr-012-transaction-velocity/) (5 phases, all complete)

**Performance:** ~94 ns hot path (record + 3 classifier evals); ~1.5 µs cold path (new session alloc); constant scaling 1k → 50k sessions. Bench results: [`bench-results.md`](../plans/260504-1632-fr-012-transaction-velocity/bench-results.md).

**Node-local state (open question):** Same per-node limitation as FR-011. Cluster session affinity assumed at the LB; Redis-backed `TxStore` deferred to post-v0.2.

**`ok=true` always (deferred):** Phase 3 records on request entry only. Failed-login detection requires a response-side hook — captured as follow-up work.

### Panel-Config API (Complete ✓)

Atomic read/write of `waf-panel.toml` (operational policy settings) via `GET/PUT /api/panel-config`. Config struct `WafPanelConfig` with nested sections: `ResponseFilteringPanel`, `TrustedBypassPanel`, `RateLimitsPanel`, `AutoBlockPanel`. Validates risk thresholds (allow < challenge < block), CIDR syntax, honeypot paths. Atomic write-through semantics.

- [x] `crates/waf-common/src/panel_config.rs` — TOML schema + validation
- [x] `crates/waf-api/src/panel_api.rs` — `GET/PUT /api/panel-config` handlers
- [x] Frontend: `web/admin-panel/src/pages/settings/index.tsx` — settings UI with i18n
- [x] i18n locales updated (all 11 locales)

---

## v0.3.0 (Proposed — Q3 2026)

**Theme**: Observability & Developer Experience

**Build on FR-004/FR-009**: v0.3.0 will add Prometheus metrics for rate-limit counters (RL-IP, RL-SESSION request/deny counts) and cache hit ratio tracking. These extend the core FR-004 rate limiting and FR-009 caching functionality shipped in v0.2.x.

### Metrics & Monitoring
- [ ] Prometheus `/metrics` endpoint (counter, gauge, histogram types)
- [ ] Metrics exported:
  - `prx_waf_requests_total` (counter, by host + rule_id)
  - `prx_waf_blocked_requests_total` (counter, by rule_id)
  - `prx_waf_request_duration_ms` (histogram, P50/P95/P99)
  - `prx_waf_rule_matches_total` (counter, per rule_id)
  - `prx_waf_backend_latency_ms` (histogram)
  - `prx_waf_rate_limit_hits_total` (counter, RL-IP/RL-SESSION)
  - `prx_waf_cache_hit_ratio` (gauge)
  - `prx_waf_cluster_election_time_ms` (histogram)
- [ ] Grafana dashboard templates (JSON)
- [ ] Alert examples (Prometheus rules)

### Distributed Tracing
- [ ] OpenTelemetry integration (optional, off by default)
- [ ] Trace propagation (W3C Trace Context)
- [ ] Spans: HTTP request, rule eval, database query
- [ ] Exporter: Jaeger, Zipkin, Datadog
- [ ] Admin UI: trace correlation with security events

### Admin UI Testing
- [ ] Vitest + Vue Test Utils (unit tests)
- [ ] Cypress (E2E tests)
- [ ] Target: >80% code coverage (views + components)
- [ ] Accessibility tests (axe-core)

### Documentation Enhancements
- [ ] API reference (70+ endpoints, all documented)
- [ ] Operator runbooks (troubleshooting, incident response)
- [ ] Performance tuning guide
- [ ] Security best practices
- [ ] Multi-language docs (at least: EN, ZH, RU)

### Performance Baseline
- Target: <3ms added latency (99th percentile, vs <5ms today)
- Target: >15,000 RPS per node (vs >10,000 today)
- Profiling: continuous benchmarks in CI

### Quality
- [ ] Code coverage: >85% (unit + integration)
- [ ] Zero panics in any code path
- [ ] Zero high/critical security issues
- [ ] Full audit of all dependencies (cargo-audit + cargo-deny)

**Effort Estimate**: 120–150 engineer-hours (or ~30 Claude-hours)

---

## v1.0.0 (Proposed — Q4 2026 or early 2027)

**Theme**: Advanced Features & Enterprise Scale

### WASM Plugin Sync
- [ ] Binary plugin distribution to worker nodes
- [ ] Plugin versioning (semantic)
- [ ] Plugin marketplace (community-curated list)
- [ ] Plugin update mechanism (no downtime)
- [ ] Sandboxing enhancements (memory limits, CPU time budgets)

### Multi-Region Clustering
- [ ] Cross-datacenter clustering (georeplicated)
- [ ] Region-aware traffic routing (failover to healthy region)
- [ ] Bandwidth-efficient sync (delta compression)
- [ ] Latency-optimized election (region-aware quorum)

### Machine Learning (Optional)
- [ ] Anomaly detection (request pattern, traffic baseline)
- [ ] Bot detection ML model (decision tree or shallow NN)
- [ ] False positive reduction (feedback loop)

### Kubernetes Native
- [ ] Operator CRDs (Helm-installable)
  - `WAFCluster` — cluster topology
  - `WAFHost` — vhost proxy config
  - `WAFRule` — custom rule definition
- [ ] Auto-scaling policy (HPA integration)
- [ ] Health probes (liveness, readiness, startup)
- [ ] NetworkPolicy templates

### Enterprise Features
- [ ] SAML/OIDC authentication (vs JWT-only)
- [ ] Multi-tenancy (per-customer namespace + RBAC)
- [ ] Customer-specific rule sets
- [ ] Compliance reporting (SOC2, PCI-DSS)
- [ ] Audit log retention policies

### API v2
- [ ] GraphQL endpoint (alternative to REST)
- [ ] Server-sent events (SSE) as WebSocket alternative
- [ ] gRPC interface (for high-performance integrations)

### Performance Target
- [ ] <2ms added latency (99th percentile)
- [ ] >20,000 RPS per node
- [ ] <100ms cluster consensus latency (multi-region)

**Effort Estimate**: 200+ engineer-hours (very large scope)

---

## Future Considerations (Post-v1)

### IPv6 Support
- Full IPv6 support (currently IPv4-only)
- Dual-stack proxy
- IPv6 geolocation

### Edge Computing
- CloudFlare Workers integration
- Fastly Compute integration
- Deploy WAF rules to CDN edge

### AI-Powered Rules
- Natural language rule authoring (GPT + semantic parsing)
- Auto-remediation (auto-tuning rule thresholds)
- Attack prediction (threat modeling)

### Advanced Integrations
- Splunk integration (log streaming)
- Datadog integration (metrics + traces)
- AWS WAF federation
- Azure WAF federation

### Hardware Accelerators
- GPU-accelerated regex matching
- FPGA-optimized rule evaluation
- Intel QuickAssist for encryption

### Developer Tools
- WAF rule testing framework (pytest-style)
- Local dev environment (docker-compose + tester)
- Browser extension for rule debugging
- VS Code extension for rule editing

---

## Priority Alignment

### P0 (Must-Have, Blocking Release)
- [x] v0.2.0: Security hardening (panics, SSRF, encoding bypass)
- [ ] v0.3.0: Observability (metrics, tracing)
- [ ] v1.0.0: Kubernetes operator (enterprise requirement)

### P1 (High Value, Quick ROI)
- [x] Clustering (v0.1)
- [ ] Admin UI testing (v0.3)
- [ ] Multi-region clustering (v1.0)
- [ ] WASM plugin sync (v1.0)

### P2 (Nice-to-Have, Lower Priority)
- [ ] IPv6 (post-v1)
- [ ] Edge computing (post-v1)
- [ ] AI rules (post-v1)
- [ ] Hardware accelerators (post-v1)

### P3 (Deferred, Community-Contributed)
- [ ] OIDC/SAML (v1.0, but can defer)
- [ ] Splunk integration (v1.0+)
- [ ] Developer tools (v1.0+)

---

## Known Limitations

### v0.2.0

| Limitation | Impact | Workaround | Target Fix |
|-----------|--------|-----------|-----------|
| WASM plugins not synced to workers | Workers lack plugin features | Run plugins on main only, or accept feature gap | v1.0 |
| IPv4-only | No IPv6 support | Use IPv4 upstream, add IPv6 reverse proxy | v0.3 or v1.0 |
| Single-region clustering | Can't cross-datacenter | Use separate clusters per region | v1.0 |
| Per-node rate limiting | No shared CC counters | Accept per-node limits | v1.0 |
| No distributed tracing | Hard to debug requests | Parse logs manually | v0.3 |
| No API v2 (GraphQL) | REST-only | Continue using REST | v1.0 |

---

## Dependency Upgrade Plan

### Q2 2026 (Monthly)
- [ ] Check cargo-audit for CVEs
- [ ] Review cargo-deny output
- [ ] Plan upgrades (minor + patch)
- [ ] Test upgrade compatibility

### Q3 2026 (Major Version Candidates)
- [ ] Tokio: 1.x → follow latest (1.40+)
- [ ] Pingora: 0.8 → 0.9+
- [ ] Axum: 0.8 → 0.9+ (if available)
- [ ] wasmtime: 43 → latest (stay current)

### Deprecation Policy
- **MSRV**: Rust 1.86 (2024 Edition)
- **Support**: Latest stable + 1 minor version back
- **Deprecation notice**: Minimum 1 release ahead

---

## Success Metrics (By Release)

### v0.2.0
- [x] 0 unaddressed high/critical CVEs
- [x] 243 regression tests passing
- [x] <0.5ms request latency (99th percentile)
- [x] <500ms cluster election
- [x] 100% uptime in staging (1-week burn-in)

### v0.3.0 (Proposed)
- [ ] Prometheus metrics exported successfully
- [ ] OpenTelemetry traces in Jaeger
- [ ] Admin UI unit test coverage >80%
- [ ] E2E test suite >50 scenarios
- [ ] Documentation: 100+ pages
- [ ] <3ms request latency (99th percentile)
- [ ] >15,000 RPS/node in production

### v1.0.0 (Proposed)
- [ ] Kubernetes operator deployable via Helm
- [ ] Multi-region cluster tested (DR failover <1min)
- [ ] WASM plugins synced to all workers
- [ ] Enterprise customer deployments (>3)
- [ ] <2ms request latency (99th percentile)
- [ ] >20,000 RPS/node in production

---

## Community Contribution Areas

**Welcome contributions from community:**
1. **Rule Pack**: Additional OWASP/vendor rule sets
2. **Integrations**: Splunk, Datadog, Prometheus exporters
3. **Localization**: Additional language translations (currently 11 locales)
4. **Documentation**: Guides, tutorials, troubleshooting
5. **WASM Plugins**: Community plugin marketplace
6. **Performance**: Benchmarking, optimization tips

**Not for community (core team only):**
1. Clustering protocol changes
2. Election algorithm
3. Core WAF engine phases
4. Security-critical paths

---

## Version Support Matrix

| Version | Released | Support Ends | Status |
|---------|----------|--------------|--------|
| **v0.1.0-rc.1** | 2026-03-16 | 2026-06-30 | Bug fixes only |
| **v0.2.0** | 2026-03-27 | 2026-09-30 | Active support |
| **v0.3.0** | TBD Q3 2026 | TBD Q4 2027 | Planned |
| **v1.0.0** | TBD Q4 2026 | TBD Q4 2028 | Planned |

---

## Milestones (Gantt-style)

```
Q1 2026 [===========]                                 (v0.2.0 released, security hardening complete)
         └─ Clustering P1–P5 ✓
         └─ SSRF/DNS guard ✓
         └─ 243 regression tests ✓

Q2 2026            [=================]                 (v0.3.0 planning & design)
         └─ Observability design
         └─ Metrics framework
         └─ Distributed tracing design
         └─ Admin UI test strategy

Q3 2026                         [=====================] (v0.3.0 implementation)
         └─ Prometheus metrics
         └─ OpenTelemetry integration
         └─ Admin UI tests (Vitest + Cypress)
         └─ Operator docs

Q4 2026                                      [=============================] (v0.3.0 RC + v1.0.0 start)
         └─ v0.3.0 RC testing
         └─ WASM plugin sync design
         └─ Multi-region clustering design
         └─ Kubernetes operator start

Q1 2027                                                          [===========] (v1.0.0 implementation)
         └─ Kubernetes operator (Helm)
         └─ Multi-region clustering
         └─ WASM plugin binary sync
         └─ Enterprise features (SAML/OIDC)

Q2 2027                                                                      [==========] (v1.0.0 RC)
         └─ Multi-region cluster testing
         └─ Operator testing in EKS/GKE
         └─ Performance optimization
         └─ Documentation

Q3+ 2027                                                                                [future releases]
```

---

## Feedback & Questions

**How to submit feedback:**
1. GitHub Issues (bugs, feature requests)
2. GitHub Discussions (ideas, feedback)
3. Security issues: security@openprx.dev

**Roadmap review cycle:** Quarterly (Q-end review + next-Q planning)
