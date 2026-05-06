# PRX-WAF Codebase Summary

## Overview

PRX-WAF is a 7-crate Rust workspace (~26K LOC) implementing a production-grade reverse proxy WAF with clustering, WASM plugins, and comprehensive observability.

---

## Crate Inventory

| Crate | LOC | Purpose | Key Dependencies |
|-------|-----|---------|------------------|
| **prx-waf** | 1,552 | CLI binary, server bootstrap | tokio, tracing, clap |
| **gateway** | 1,868 | Pingora reverse proxy, HTTP/3, SSL, response cache | pingora-core, quinn, rustls, moka |
| **waf-engine** | 11,154 | 16-phase detection pipeline, rule registry, WASM plugins | aho-corasick, rhai, libinjectionrs, wasmtime |
| **waf-storage** | 2,293 | PostgreSQL persistence layer (sqlx) | sqlx (postgres), chrono, uuid |
| **waf-api** | 4,040 | Axum REST API, JWT/TOTP auth, WebSocket, embedded UI | axum, jsonwebtoken, argon2, tokio-tungstenite |
| **waf-common** | 1,457 | Shared types, config, crypto, RequestCtx | serde, tokio, aes-gcm, instant-acme |
| **waf-cluster** | 3,804 | QUIC mTLS mesh, Raft-lite election, rule sync | quinn, rustls, rcgen, lz4_flex |
| **Total** | **26,168** | Production Rust WAF | 50+ workspace deps |

---

## Directory Map

```
prx-waf/
├── crates/
│   ├── prx-waf/src/
│   │   ├── main.rs           # Entry point: config, runtime bootstrap
│   │   ├── commands/          # CLI subcommands (run, migrate, rules, cluster, crowdsec)
│   │   └── server.rs          # Thread spawning (API, HTTP/3, cluster)
│   │
│   ├── gateway/src/
│   │   ├── proxy.rs           # Pingora ProxyHttp handler
│   │   ├── router.rs          # Vhost-based routing
│   │   ├── ssl_manager.rs     # ACME (Let's Encrypt) via instant-acme
│   │   ├── http3.rs           # HTTP/3 server (QUIC via quinn)
│   │   ├── cache/             # FR-009 Phase 3-4: per-route TTL via YAML + tag-based purge (ArcSwap, lock-free reads)
│   │   │   ├── config.rs      # YAML schema + Defaults struct
│   │   │   ├── gates/         # Cache verdict pipeline (TierGate, MethodGate, AuthGate, RouteRuleGate, UpstreamCcGate, TierDefaultGate)
│   │   │   ├── rule.rs        # Individual cache rule (path pattern, ttl_seconds, tags)
│   │   │   ├── rule_set.rs    # Compiled cache ruleset (hot-swappable via ArcSwap)
│   │   │   ├── policy.rs      # Caching policy logic
│   │   │   ├── store.rs       # moka LRU response cache backend + tag index integration
│   │   │   ├── tag_index.rs   # FR-009 Phase 4: tag→cache_keys reverse index (DashMap-based, auto-cleanup via eviction listener)
│   │   │   ├── stats.rs       # Cache statistics (hit/miss/bypassed/purges counters, tag_index_size)
│   │   │   ├── watcher.rs     # File watcher for rules/cache.yaml hot-reload (notify, 500ms debounce)
│   │   │   └── mod.rs         # Cache resolver facade
│   │   └── tunnel.rs          # Reverse tunnel (encrypted WebSocket)
│   │
│   ├── waf-engine/src/
│   │   ├── engine.rs          # Main WafEngine (16-phase checker)
│   │   ├── access/            # FR-008 Phase-0 gate: IP/host whitelist + blacklist (Patricia trie + ArcSwap hot-reload)
│   │   ├── checks/            # Individual detection modules
│   │   │   ├── ip_allow.rs    # IP whitelist (CIDR)
│   │   │   ├── ip_block.rs    # IP blocklist
│   │   │   ├── url_*.rs       # URL patterns
│   │   │   ├── rate_limit/    # FR-004 token-bucket + sliding-window (memory/Redis store, hot-reload YAML)
│   │   │   ├── scanner.rs     # Scanner detection (fingerprints)
│   │   │   ├── bot.rs         # Bot detection (UA, headless)
│   │   │   ├── sql_injection.rs          # SQL injection coordinator (libinjectionrs + pattern checks)
│   │   │   ├── sql_injection_patterns.rs # 19 regex patterns (SQLI-001..019, classic/blind/error-based)
│   │   │   ├── sql_injection_scanners.rs # Scanner helpers (3 modular scanners)
│   │   │   ├── xss.rs         # XSS (libinjectionrs + regex)
│   │   │   ├── rce.rs         # Command injection
│   │   │   ├── traversal.rs   # Directory traversal
│   │   │   ├── custom.rs      # Custom rules (Rhai + JSON DSL; FR-003 Composite/Strategy compiled tree — see docs/custom-rules-syntax.md)
│   │   │   ├── owasp.rs       # OWASP CRS rules
│   │   │   ├── sensitive.rs   # Sensitive data (Aho-Corasick)
│   │   │   ├── hotlink.rs     # Anti-hotlink (Referer)
│   │   │   ├── crowdsec.rs    # CrowdSec bouncer + AppSec
│   │   │   ├── ddos/          # FR-005 DDoS protection (multi-layer detection: per-IP, per-fingerprint, per-tier; dynamic banning + graceful degrade)
│   │   │   │   ├── check.rs       # DdosCheck orchestrator (invokes detector pipeline, aggregates verdicts, emits action)
│   │   │   │   ├── config.rs      # TOML schema ([ddos], [ddos.per_ip], [ddos.per_tier]) + validation
│   │   │   │   ├── reload.rs      # notify-based hot-reload with ArcSwap snapshot
│   │   │   │   ├── detector/      # Detector trait + 3 implementations
│   │   │   │   │   ├── mod.rs         # Detector trait (evaluate(ctx, cfg, now_ms) → DetectorVerdict::HardBurst)
│   │   │   │   │   ├── clock.rs       # SystemClock + MockClock for testing
│   │   │   │   │   ├── baseline.rs    # BaselineDetector (quantized buckets, per-IP window)
│   │   │   │   │   ├── per_ip.rs      # PerIpDetector (sliding-window, wraps CounterStore)
│   │   │   │   │   ├── per_fp.rs      # PerFingerPrintDetector (device_fp aggregation, fallback to per-IP)
│   │   │   │   │   └── per_tier.rs    # PerTierDetector (aggregate RPS per tier, adaptive threshold)
│   │   │   │   ├── action.rs      # DdosAction executor (Ban, RiskBump, Degrade); IpTable (dynamic ban table w/ TTL)
│   │   │   │   ├── degrade.rs     # OverloadGuard (store error handling, per-tier fail-mode dispatch)
│   │   │   │   ├── metrics.rs     # DdosMetrics (Prometheus: detections, bans, errors, latency)
│   │   │   │   └── store/         # Counter backends (CounterStore trait)
│   │   │   │       ├── mod.rs         # CounterStore trait (async incr, purge_expired)
│   │   │   │       ├── memory.rs      # MemoryCounterStore (DashMap + idle eviction, 100K cap)
│   │   │   │       └── redis.rs       # RedisCounterStore (Lua script, 50ms timeout; feature redis-store)
│   │   │   ├── tx_velocity/   # FR-012 transaction velocity anomaly detection (role-tagging, sequence timing, withdrawal burst)
│   │   │   │   ├── check.rs       # TxVelocityCheck (Check trait impl, signal-only)
│   │   │   │   ├── recorder.rs    # DashMap<SessionKey, ActorTx>, event recording, cooldown logic
│   │   │   │   ├── config.rs      # YAML schema + ArcSwap hot-reload
│   │   │   │   ├── session_key.rs # Extract session identity (cookie preferred, then FpKey)
│   │   │   │   ├── role_tagger.rs # Classify endpoint role from path (Login/OTP/Withdrawal/etc)
│   │   │   │   ├── classifier.rs  # Classifier trait + registry
│   │   │   │   └── classifiers/   # Individual risk detectors (sequence_timing, withdrawal_velocity, limit_change_burst)
│   │   │   └── mod.rs         # Check trait + registry
│   │   │
│   │   ├── rules/
│   │   │   ├── registry.rs    # RuleRegistry (in-memory + version tracking)
│   │   │   ├── manager.rs     # File watcher + YAML/ModSec/JSON parsing
│   │   │   ├── changelog.rs   # Incremental sync changelog (ring buffer)
│   │   │   └── remote.rs      # Remote rule source loading (async)
│   │   │
│   │   ├── plugins/
│   │   │   ├── wasm.rs        # WASM plugin manager (wasmtime)
│   │   │   └── rhai.rs        # Rhai script engine sandbox
│   │   │
│   │   ├── device_fp/         # FR-010 device fingerprinting (operator guide: docs/device-fingerprinting.md)
│   │   │   ├── capture/       # TLS ClientHello + H2 frame inspection (Pingora hooks)
│   │   │   │   ├── tls.rs / h2.rs / client_hello_inspector.rs / h2_frame_inspector.rs
│   │   │   │   ├── conn_ctx.rs   # ConnCtx, ConnRegistry (per-connection state)
│   │   │   │   └── parsed.rs     # RawCapture, H2Capture, PriorityFrame
│   │   │   ├── fingerprint/   # JA3, JA4, Akamai H2 hashers (FingerprintRegistry)
│   │   │   ├── identity/      # IdentityStore trait + Memory + Redis (feature `redis-store`)
│   │   │   ├── providers/     # SignalProvider impls: ip_hopping, fp_conflict, ua_entropy, ua_blocklist, h2_anomaly
│   │   │   ├── aggregator.rs  # RiskAggregator trait + Noop/Logging defaults (FR-025 plug-in point)
│   │   │   ├── config.rs      # YAML schema (deny_unknown_fields), ArcSwap snapshot
│   │   │   ├── reload.rs      # notify-based hot reload
│   │   │   ├── registry.rs    # ProviderRegistry (Strategy + Registry pattern)
│   │   │   ├── signal.rs      # Signal enum + H2AnomalyReason
│   │   │   ├── types.rs       # DeviceCtx, DeviceIdentity, FpKey, Observation
│   │   │   ├── behavior/      # FR-011 behavioral anomaly detection (per-actor sliding window)
│   │   │   │   ├── state.rs       # ActorBehavior (16-slot ring, alloc-free, ≤1KB)
│   │   │   │   ├── recorder.rs    # DashMap<FpKey, ActorBehavior>, monotonic ms, TTL janitor
│   │   │   │   ├── config.rs      # BehaviorConfig (validated, hot-reload via ArcSwap)
│   │   │   │   ├── path_classifier.rs  # entry/low-signal exempt-path matchers
│   │   │   │   └── providers/     # burst_interval, regularity, zero_depth, missing_referer
│   │   │   └── mod.rs         # DeviceFpDetector facade (process pipeline)
│   │   │
│   │   ├── security/
│   │   │   ├── geoip.rs       # GeoIP lookup (ip2region)
│   │   │   └── url_validator.rs # SSRF protection, DNS rebinding guard
│   │   │
│   │   └── lib.rs
│   │
│   ├── waf-storage/src/
│   │   ├── db.rs              # Database pool + broadcast events
│   │   ├── repository/        # Data access patterns
│   │   │   ├── user.rs
│   │   │   ├── rule.rs
│   │   │   ├── ip_list.rs
│   │   │   ├── url_list.rs
│   │   │   ├── security_event.rs
│   │   │   ├── attack_log.rs
│   │   │   ├── certificate.rs
│   │   │   ├── plugin.rs
│   │   │   └── notification.rs
│   │   │
│   │   ├── models/            # Database models (Serialize + Deserialize)
│   │   └── lib.rs
│   │
│   ├── waf-api/src/
│   │   ├── server.rs          # Axum router + middleware
│   │   ├── middleware/
│   │   │   ├── auth.rs        # JWT bearer token extraction
│   │   │   ├── security.rs    # CORS, security headers, rate limit
│   │   │   └── admin_ip.rs    # Admin IP allowlist
│   │   │
│   │   ├── handlers/
│   │   │   ├── auth.rs        # Login (JWT + TOTP), refresh, logout
│   │   │   ├── hosts.rs       # Vhost CRUD
│   │   │   ├── rules.rs       # Rule enable/disable/info
│   │   │   ├── ip_rules.rs    # IP allow/block CRUD
│   │   │   ├── url_rules.rs   # URL allow/block CRUD
│   │   │   ├── certificates.rs
│   │   │   ├── custom_rules.rs
│   │   │   ├── security_events.rs
│   │   │   ├── stats.rs
│   │   │   ├── notifications.rs
│   │   │   ├── plugins.rs
│   │   │   ├── cluster.rs
│   │   │   ├── crowdsec.rs
│   │   │   └── ws.rs          # WebSocket events + logs
│   │   │
│   │   ├── state.rs           # AppState (shared across handlers)
│   │   └── lib.rs
│   │
│   ├── waf-common/src/
│   │   ├── config.rs          # AppConfig (TOML structure + defaults)
│   │   ├── request.rs         # RequestCtx (per-request context)
│   │   ├── waf_decision.rs    # WafAction, WafDecision enums
│   │   ├── crypto.rs          # AES-GCM encryption helpers
│   │   └── lib.rs
│   │
│   └── waf-cluster/src/
│       ├── node.rs            # ClusterNode orchestrator, NodeState, StorageMode
│       ├── transport/
│       │   ├── server.rs      # QUIC mTLS listener
│       │   ├── client.rs      # QUIC peer dialer
│       │   └── frame.rs       # Length-prefixed JSON codec
│       │
│       ├── crypto/
│       │   ├── ca.rs          # CA generation (rcgen)
│       │   ├── node_cert.rs   # Node cert signing
│       │   ├── token.rs       # Join token HMAC
│       │   └── store.rs       # AES-GCM key storage
│       │
│       ├── discovery/
│       │   └── static.rs      # Static seed list
│       │
│       ├── sync/
│       │   ├── rules.rs       # RuleChangelog + sync logic
│       │   ├── config.rs      # Config sync (TOML)
│       │   └── events.rs      # Event batching + forwarding
│       │
│       ├── election/
│       │   └── manager.rs     # Raft-lite term/vote state machine
│       │
│       ├── health/
│       │   ├── heartbeat.rs   # Periodic heartbeat sender
│       │   └── detector.rs    # Phi-accrual failure detection
│       │
│       ├── protocol/
│       │   └── messages.rs    # All ClusterMessage types (serde_json)
│       │
│       └── lib.rs
│
├── migrations/          # sqlx migrations (0001–0008)
├── configs/             # Example TOML files (default, cluster-node-a/b/c)
├── rules/               # Built-in YAML rules (51 files)
│   ├── owasp-crs/       # 24 OWASP Core Rule Set
│   ├── cve-patches/     # 7 CVE-specific rules
│   ├── advanced/        # 6 advanced patterns
│   ├── owasp-api/       # 5 API security rules
│   ├── modsecurity/     # 4 ModSecurity patterns
│   ├── bot-detection/   # 3 bot detection rules
│   ├── geoip.yaml       # Geo-blocking template
│   ├── custom.yaml      # Custom rule template
│   └── custom/          # Site-specific rules (registry YAML + FR-003 file-loaded
│                        #   *.yaml carrying `kind: custom_rule_v1`; auto-loaded
│                        #   at startup with hot-reload — see custom-rules-syntax.md)
│
├── web/admin-ui/        # Vue 3 SPA
│   ├── src/
│   │   ├── views/       # 21 Vue pages (Dashboard, Hosts, Rules, Cluster, etc.)
│   │   ├── components/  # 5 reusable components (Layout, StatCard, Badge, etc.)
│   │   ├── stores/      # Pinia stores (auth.ts)
│   │   ├── api/         # 11 API modules (auth, hosts, rules, cluster, etc.)
│   │   ├── i18n/        # 11 locales (en, zh, ru, ka, ar, de, es, fr, ja, ko, et)
│   │   ├── router/      # Vue Router config (hash mode)
│   │   └── App.vue      # Root component
│   │
│   ├── package.json     # Vue 3.3.13 + Vite 5.1 + Tailwind 3.4 + axios + vue-i18n
│   └── vite.config.ts   # Vite dev server proxy
│
├── tests/               # Integration + E2E test suite (1,812 LOC)
│   ├── e2e-cluster.sh   # Main orchestrator (5 shell runners, multi-artifact output)
│   ├── runners/
│   │   ├── rules-engine.sh     # Validates YAML/ModSec/JSON rule parsing
│   │   ├── gateway.sh          # HTTP/1.1, HTTP/2, HTTP/3, load balancing
│   │   ├── api.sh              # REST API endpoints, auth, CRUD operations
│   │   ├── cluster.sh          # QUIC mesh, leader election, rule sync, failover
│   │   └── report-renderer.sh  # JUnit/JSON/Markdown/HTML artifact generation
│   └── *.rs             # Rust integration tests (63+ acceptance tests for SQLi)
│
├── build.rs             # Creates admin-panel/dist/ placeholder (prevents cargo failures in sandboxed CI)
├── Dockerfile           # 2-stage: builder + runtime
├── Dockerfile.prebuilt  # Pre-built binary only (admin UI embedded via build.rs)
├── docker-compose.yml   # Single-node: postgres + prx-waf
├── docker-compose.cluster.yml # 3-node cluster + postgres
│
└── docs/                # Documentation (this directory)
```

---

## Rule Inventory (51 Built-in Rules)

### OWASP CRS (24 rules)

- `xss-*.yaml` (4 rules) — XSS vectors (script tags, event handlers, etc.)
- `sqli-*.yaml` (4 rules) — SQL injection patterns
- `rce-*.yaml` (2 rules) — Remote code execution
- `rfi-lfi-*.yaml` (2 rules) — Remote/Local file inclusion
- `protocol-*.yaml` (2 rules) — HTTP protocol violations
- `data-leakage-*.yaml` (2 rules) — Response data leakage
- `multipart-*.yaml` (1 rule) — Multipart form validation
- `modsec-*.yaml` (5 rules) — ModSecurity compatibility patterns

### CVE Patches (7 rules)

- `cve-2021-44228.yaml` — Log4Shell
- `cve-2022-22965.yaml` — Spring4Shell
- `cve-2023-4761.yaml` — Text4Shell
- `cve-2023-34362.yaml` — MOVEit Transfer
- `cve-2024-3156.yaml` — XZ backdoor (CVE-2024-3156)
- `cve-2023-46604.yaml` — Apache OFBiz
- `cve-2024-1234.yaml` — Custom patch

### Advanced (6 rules)

- `deserialization.yaml` — Object deserialization attacks
- `prototype-pollution.yaml` — JavaScript prototype pollution
- `ssrf.yaml` — SSRF detection
- `ssti.yaml` — Server-side template injection
- `webshell-upload.yaml` — Malicious file uploads
- `xxe.yaml` — XML external entity attacks

### OWASP API Top 10 (5 rules)

- `api-broken-auth.yaml`
- `api-data-exposure.yaml`
- `api-injection.yaml`
- `api-mass-assignment.yaml`
- `api-rate-abuse.yaml`

### ModSecurity (4 rules)

- `data-leakage.yaml`
- `dos-protection.yaml`
- `ip-reputation.yaml`
- `response-validation.yaml`

### Bot Detection (3 rules)

- `crawlers.yaml` — Google, Bing, etc. (allow by default)
- `credential-stuffing.yaml` — Credential stuffing bots
- `scraping.yaml` — Web scraping tools

### Miscellaneous (2 rules)

- `geoip.yaml` — Geo-blocking template (example)
- `custom.yaml` — Custom rule template (example)

### Rule Schema

```yaml
- id: "OWASP-CRS-941100"
  name: "XSS Attack"
  category: "xss"
  source: "owasp-crs"
  severity: "high"
  paranoia: 2  # 1-4 (higher = more aggressive)
  enabled: true
  action: "block"  # block, log, challenge
  field: "all"  # headers, body, uri, all
  operator: "detect_xss"  # regex, detect_xss, detect_sqli, contains, rx, etc.
  pattern: "javascript:"
  tags:
    - "crs"
    - "xss"
  cve: ["CVE-2023-12345"]
  description: "Blocks inline JavaScript XSS vectors"
```

---

## Request Lifecycle (16-Phase Pipeline)

```
1. Client Connection (TCP/TLS/QUIC)
2. Parse HTTP request + extract headers/body
3. Resolve upstream backend (vhost routing)

4. Phase 1: IP Allowlist (CIDR)
5. Phase 2: IP Blocklist (CIDR)
6. Phase 3: URL Allowlist (regex/string)
7. Phase 4: URL Blocklist (regex/string)
8. Phase 5: Rate Limiting (FR-004: token-bucket + sliding-window, dual IP+session keys, tiered)
9. Phase 6: Scanner Detection (Nmap, Nikto, etc.)
10. Phase 7: Bot Detection (headless browser, crawlers)
11. Phase 8: SQL Injection (libinjectionrs + regex)
12. Phase 9: XSS (libinjectionrs + regex)
13. Phase 10: RCE / Command Injection
14. Phase 11: Directory Traversal (path normalization)
15. Phase 12: Custom Rules (Rhai scripts + JSON DSL)
16. Phase 13: OWASP CRS (24 compiled rules)
17. Phase 14: Sensitive Data Leakage (Aho-Corasick)
18. Phase 15: Anti-Hotlink (Referer-based)
19. Phase 16: CrowdSec Bouncer + AppSec

20. Decision: Allow / Block / Challenge / Log
21. If Allow: Route to backend via load balancer
22. If Block: Return 403 Forbidden
23. If Challenge: CAPTCHA or rate-limit token (429)
24. Log: Write security_events + attack_logs to PostgreSQL
25. Cache: If response eligible and tier permits (FR-009), store in moka LRU
26. Notify: Send alerts (Email, Webhook, Telegram)
27. Return response to client
```

---

## Data Storage (PostgreSQL Schema)

**Core Tables**
- `hosts` — Vhost proxy configuration (upstream, ports, SSL certs, LB config)
- `allow_ips`, `block_ips` — IP lists (CIDR ranges)
- `allow_urls`, `block_urls` — URL patterns (regex, string)
- `custom_rules` — User-created rules (Rhai/JSON)
- `sensitive_patterns` — PII/credential keywords (Aho-Corasick)
- `certificates` — TLS certs (Let's Encrypt + custom)
- `load_balance_backends` — Backend servers per host
- `admin_users` — Admin accounts (username, password hash, TOTP secret)
- `refresh_tokens` — JWT refresh tokens (expiry tracking)

**Observability Tables**
- `security_events` — Attack detections (rule_id, action, client_ip, timestamp)
- `attack_logs` — Detailed attack payloads + geo (geo_country JSONB)
- `request_stats` — Aggregated metrics (RPS, top rules, top IPs, geo)

**Cluster Tables**
- `cluster_nodes` — Peer metadata (role, last_heartbeat, rules_version)
- `cluster_sync_queue` — Pending event/config updates to workers
- `cluster_ca_key` — Encrypted cluster CA key (AES-GCM)

**Extension Tables**
- `plugins` — WASM plugin binaries (name, code, enabled, checksum)
- `tunnels` — Reverse tunnel configs (client_id, key, allowed_paths)
- `crowdsec_cache` — Bouncer decisions cache (IP, action, expiry)
- `notifications` — Alert channels (email, webhook, telegram)

---

## Key Patterns & Conventions

### Tiered Protection (FR-002)

See [Tiered Protection Consumer Guide](./tiered-protection.md) for request classification, policy bus, and per-tier semantics.

### Rate Limiting (FR-004)

Tiered rate limiting using token-bucket (burst) and sliding-window (sustained) algorithms. Two-store architecture: MemoryStore (DashMap-based, 100K entry cap, 10min idle eviction, background cleanup) for fast local checks; RedisStore (single Lua script roundtrip via `CHECK_AND_CONSUME_LUA`, 50ms op timeout) for distributed state. BreakerStore wraps both with circuit-breaker (default 5 consecutive failures) to fallback gracefully to memory. Dual-key strategy: `ip:<host>:<client_ip>` (IP-based, checked first for flood short-circuit) and `sess:<host>:<session_id>` (session/device-fingerprint, fallback if cookie present). Both keys must Allow for request to pass. Emitted rule IDs: RL-IP, RL-SESSION, RL-ERR. Hot-reload via `notify` watcher on `configs/rate-limit.yaml` (200ms debounce, ArcSwap snapshot, schema v1). Config per tier: `burst_capacity`, `burst_refill_per_s`, `window_secs`, `window_limit`. Fail-mode dispatch: tier policy Close (block) / Open (pass on failure). Module: `crates/waf-engine/src/checks/rate_limit/`, integrated as Check trait in phase 5. See scout findings and plans/260502-1957-fr004-rate-limiting/.

### Behavioral Anomaly Detection (FR-011)

Per-actor sliding-window cadence/path classifiers layered on top of FR-010 device fingerprinting. `Recorder` keys a `DashMap<FpKey, ActorBehavior>` (lock-free shards via `ahash::RandomState`); `ActorBehavior` is a 16-slot fixed-array ring (~600 B, alloc-free after first observation) plus an 8-slot distinct-paths set. Time is monotonic ms since the recorder's anchor `Instant` — wall-clock jumps cannot produce negative intervals. Four `SignalProvider` impls read snapshot clones (no shard-guard hold across eval): `burst_interval` (≥5 sub-50ms intervals → `Signal::BurstInterval`, +15), `regularity` (CV cadence ≤ 0.15, ≥6 samples → `Signal::Regularity`, +10), `zero_depth` (≥4 same-path hits with no Referer on Critical tier → `Signal::ZeroDepth`, +10), `missing_referer` (first-seen actor on non-exempt nav → `Signal::MissingReferer`, +5). Risk-delta cap aggregates to ≤ 40 across all four. Hot-reload via `ArcSwap<DeviceFpConfig>` (validated `BehaviorConfig` block in `configs/device-fp.yaml`, `deny_unknown_fields`). TTL janitor purges idle actors (default 600s). **v1 limitation: behavioral state is per-node**; a cluster-mode rotator dilutes the window — Redis-backed sharing is captured as follow-up (research §10 Q#2). Hot-path budget: < 5 µs (record + 4 evals); benched at ~840 ns p50 in release. Module: `crates/waf-engine/src/device_fp/behavior/`. Tests: `behavior_acceptance.rs` (4 ACs), `behavior_property.rs` (proptest invariants), `benches/behavior_eval.rs`.

### Transaction Velocity Anomaly Detection (FR-012)

Session-level transaction velocity and sequence anomalies for fintech fraud detection. `TxVelocityCheck` (signal-only, never blocks) records inbound requests keyed by session identity (cookie preferred, falls back to device fingerprint via FR-010 FpKey). Three classifiers run independently on the recorded event stream: (1) `SequenceTimingClassifier` detects suspicious gaps in multi-factor sequences (e.g., login → OTP in >1500ms, or OTP without prior login), (2) `WithdrawalVelocityClassifier` flags ≥3 withdrawal events within a 60s window, (3) `LimitChangeBurstClassifier` detects rapid limit-increase requests. Each classifier emits risk signals to the aggregator with severity deltas (+5 to +15 points). State machine: `DashMap<SessionKey, ActorTx>` (lock-free shards) where `ActorTx` is a 32-slot ring buffer (~1.5 KB, alloc-free after init) indexed by role-tagged path. TTL janitor purges idle sessions (default 3600s). Hot-path budget: ~94 ns (record + classifier eval, sub-microsecond); benched with Criterion at full scale (50k sessions, linear scaling). Hot-reload via `ArcSwap<TxVelocityConfig>` (YAML schema: `configs/tx-velocity.yaml`, thresholds configurable per classifier). Engine integration: positioned after `RateLimitCheck`, before `ScannerCheck` in the 16-phase pipeline to shed flood traffic first. Module: `crates/waf-engine/src/checks/tx_velocity/`. Tests: 9 integration + 15 unit (role_tagger, recorder, classifiers), 6 Criterion benchmarks in `crates/waf-engine/benches/tx_velocity_bench.rs`.

### Access Lists (FR-008)

Phase-0 gate ahead of the 16-phase rule pipeline: per-tier IP whitelist (Patricia trie via `ip_network_table`), IP blacklist, per-tier Host (FQDN) whitelist. Hot-reloaded from `rules/access-lists.yaml` via `ArcSwap`. Decisions: host gate → IP blacklist → IP whitelist; per-tier dispatch on `full_bypass` vs `blacklist_only` (Strategy). Soft-warn ≥50k entries, hard-reject ≥500k. See [Access Lists Operator Guide](./access-lists.md). Module: `crates/waf-engine/src/access/`.

### Custom Rule File Loader (FR-003)

File-based custom rule hot-reload: scans `rules/custom/*.yaml`, auto-loads YAML docs with `kind: custom_rule_v1` discriminator. Per-file error isolation; stale rules cleared on reload. `notify`-driven watcher (500ms debounce). Formats: `custom_rule_yaml.rs` multi-doc YAML, forward-compat rejects unknown `custom_rule_v*` versions. See [Custom Rules Syntax](./custom-rules-syntax.md). Module: `crates/waf-engine/src/rules/{custom_file_loader,formats/custom_rule_yaml}.rs`.

### Panel Config API (Control Plane)

Atomic read/write of `waf-panel.toml` (WAF policy settings) via `GET/PUT /api/panel-config`. Config struct `WafPanelConfig` (TOML) with nested sections: `ResponseFilteringPanel`, `TrustedBypassPanel`, `RateLimitsPanel`, `AutoBlockPanel`. Validates risk thresholds (allow < challenge < block), CIDR syntax, honeypot paths start with '/'. Atomic write semantics (write-through to file). Frontend: `web/admin-panel/src/pages/settings/index.tsx` binds to live config state. Module: `crates/waf-common/src/panel_config.rs`, `crates/waf-api/src/panel_api.rs`.

### Error Handling

- No `.unwrap()` or `.expect()` in production code (test-only)
- Use `?` operator with `.context()` for anyhow error chaining
- Silent errors logged with `tracing::warn!()` before `.ok()`
- Explicit `Err(e)` returns for validation failures

### Async Runtime

- Single shared Tokio multi-threaded runtime for initialization
- API server: own thread + dedicated runtime
- HTTP/3 server: own thread + dedicated runtime
- Cluster node: own thread + dedicated runtime
- Pingora: blocks main thread forever (no async wrapper)

### Concurrency

- Arc<RwLock<T>> for shared reader-writer state (rule registry, config)
- Arc<Mutex<T>> for exclusive state (rarely used; prefer lock-free)
- parking_lot::Mutex for sync code (no poison, faster)
- tokio::sync::Mutex for async code
- DashMap for concurrent hash maps (atomic updates)
- arc-swap for lock-free reads of immutable snapshots (NodeState)

### Configuration

- AppConfig struct (serde::Deserialize from TOML)
- All values copied into Arc<AppConfig> at startup
- No runtime config changes (reload requires restart)
- Sensible defaults (enable = false for optional features)

### Testing

- Unit tests in-line with modules (`#[cfg(test)] mod tests {}`)
- Integration tests in `tests/` directory
- Fixtures in `tests/common/` (database setup, test configs)
- Chaos tests: network simulation, kill -9 node, partition network
- Performance benchmarks: criterion crate (optional)

---

## Performance Characteristics

| Metric | Baseline (i7 6-core) | Target | Status |
|--------|----------------------|--------|--------|
| Rule eval latency | 0.5ms | <5ms | Achieved |
| Throughput | >12,000 RPS | >10,000 RPS | Achieved |
| Memory footprint | 150MB baseline | <500MB | Achieved |
| Cache hit ratio | >80% | >75% | Achieved |
| Cluster election | <500ms (LAN) | <500ms | Achieved |
| Full rule sync (1K rules) | <2s | <3s | Achieved |

---

## SQL Injection Detection Engine

**Architecture**: Modular 3-part system
- `sql_injection.rs` — Coordinator (libinjectionrs + pattern dispatch)
- `sql_injection_patterns.rs` — 19 regex patterns (SQLI-001..019)
- `sql_injection_scanners.rs` — Scanner modules (classic, blind, error-based)

**Pattern Categories (19 total)**
- **Classic SQLi** (SQLI-001..007): Union-based, OR-based, comment-based injection
- **Blind SQLi** (SQLI-008..014): Boolean-based, time-based, error-based inference
- **Error-Based** (SQLI-015..019): MSSQL, MySQL, PostgreSQL, Oracle error patterns

**Configuration** (SqliScanConfig)
- Header scan toggle (enable/disable scanning HTTP headers)
- Denylist/allowlist for specific parameters
- Scan caps: 4KB max header size, 256KB max JSON body
- Criterion benchmarks: p99 <500µs clean traffic, <1ms malicious payloads

**Testing**: 63+ acceptance tests covering all pattern types, encoding bypasses, false positives

---

## Security Boundaries

1. **Admin API** (127.0.0.1:9527) — IP allowlist + JWT + TOTP
2. **WebSocket** (/ws/events, /ws/logs) — JWT + IP allowlist
3. **Cluster QUIC** (0.0.0.0:16851) — mTLS (client cert verification)
4. **Rule Evaluation** — Rhai scripts sandboxed (no file I/O, limited stdlib)
5. **WASM Plugins** — wasmtime sandboxed (memory isolation, WASI disabled)
6. **Database Secrets** — AES-256-GCM encrypted (API keys, TOTP secrets)

---

## External Integrations

| Service | Protocol | Purpose | Status |
|---------|----------|---------|--------|
| PostgreSQL | TCP:5432 | Data storage | Required |
| Let's Encrypt | HTTPS | TLS automation | Optional |
| CrowdSec LAPI | HTTP | Threat intel, bouncer | Optional |
| CrowdSec AppSec | HTTP | Remote WAF inspection | Optional |
| SMTP | TCP:25/587 | Email alerts | Optional |
| Webhooks | HTTPS | Custom callbacks | Optional |
| Telegram Bot API | HTTPS | Telegram alerts | Optional |
