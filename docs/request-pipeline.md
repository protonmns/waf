# Request Pipeline

Detailed walkthrough of the per-request processing path: tier classification, the Phase-0 access gate, and the 16-phase WAF rule pipeline. Extracted from [system-architecture.md](./system-architecture.md) for focus.

## Pre-Phase: Tier Classification (FR-002)

```
Tier Classification:
├─ RequestCtx populated in gateway::ctx_builder
├─ TierPolicyRegistry::classify(&request_parts) runs
├─ Returns (Tier, Arc<TierPolicy>) from current snapshot
├─ ctx.tier and ctx.tier_policy set before Phase 1
└─ All downstream phases read tier for policy-aware decisions
   (e.g., rate-limit threshold, block action per tier)
```

**Default**: If no tier registry configured at boot, uses `Tier::CatchAll` + permissive policy (fallback mode).

**Wired in**: `prx-waf/src/main.rs::try_init_tier_registry()` loads config, spawns `TierConfigWatcher` for hot-reload, injects registry into gateway.

### Tier Flow Diagram

```mermaid
flowchart LR
    A([HTTP Request]) --> B[ctx_builder]
    B --> C{TierPolicyRegistry\n.classify}
    C -->|"(Tier, Arc&lt;TierPolicy&gt;)"| D[RequestCtx\ntier + tier_policy]
    D --> E[WAF Checks\nPhases 1–16]
    E -->|Allow| F([Upstream])
    E -->|Block| G([403 / 429])

    subgraph hot-reload ["Hot-Reload (background)"]
        H[configs/default.toml\nwatcher] -->|ArcSwap.store| C
    end

    subgraph consumers ["Downstream consumers"]
        D -.->|ddos_threshold_rps| FR005[FR-005 DDoS]
        D -.->|risk_thresholds| FR006[FR-006 Challenge]
        D -.->|cache_policy| FR009[FR-009 Cache]
    end
```

See [tiered-protection.md](./tiered-protection.md) for the consumer guide.

---

## Pre-Phase: Relay & Proxy Detection (FR-007)

Detects relay/proxy traffic by validating HTTP headers (`XFF`, `X-Real-IP`) and classifying the true client IP. Runs **before** Phase-0 to populate `ClientIdentity` for downstream decisions.

```
Relay Detection:
├─ XffValidator: parse chain, detect spoofing (private IPs in trusted section)
├─ ProxyChainAnalyzer: count hop depth, emit ExcessiveHopDepth if >32
├─ AsnClassifier: lookup BGP ASN (mmdb: IPinfo Lite / iptoasn fallback)
├─ TorExitMatcher: check IP against Tor exit node set
├─ Emits signals: XffSpoofPrivate, XffMalformed, XffTooLong, TorExit, ...
└─ Output: ClientIdentity { real_ip, asn_class, asn, signals }
   └─ real_ip: IpAddr (either from XFF chain with trusted-proxy CIDR strip, or fallback to peer IP)
   └─ asn_class: AsnClass (Datacenter / Residential / Tor / Unknown)
   └─ signals: Vec<Signal> (for rule predicates and risk scoring)
```

**Configuration**: `rules/relay.yaml` (YAML schema). Specifies:
- `trusted_proxy_cidrs` — CIDR list for XFF chain trust boundary
- `asn_db_path` — mmdb file path (IPinfo Lite, MaxMind GeoLite2-ASN)
- `asn_fallback_feed_url` — HTTP endpoint for iptoasn TSV (if mmdb missing)
- `tor_feed_url` — HTTP refresh source for Tor exit node list (ETag-aware)
- `datacenter_overrides` — operator-defined ASN ranges to classify as datacenter

**Hot-reload**: File watcher on `rules/relay.yaml` → parsed config → `ArcSwap<RelayConfig>` (lock-free atomic swap). Intel feeds (Tor, ASN mmdb) refresh via background HTTP tasks with retry and ETag caching. Propagation ≤1s.

**Signals emitted** (consumed by rule predicates and risk-scorer):
- `XffSpoofPrivate` — RFC1918 IP in trusted section of XFF chain
- `XffMalformed` — unparseable XFF (non-IP, truncated, unicode)
- `XffTooLong` — chain >32 entries or header >8KB
- `ExcessiveHopDepth(n)` — n hops detected (after trusted-proxy strip)
- `TorExit` — IP matched Tor exit node list
- `AsnDatacenter` — IP classified as datacenter (EC2, GCP, Fastly, etc.)
- `AsnResidential` — IP classified as residential ISP

See **[planned signal-predicate docs (FR-025/026)]** for risk-scorer integration examples.

---

## Phase-0: Access Gate (FR-008)

Phase-0 gate runs **before** the 16-phase rule pipeline: three stages in order: **(1)** Host gate (per-tier FQDN whitelist, deny-by-default if non-empty) → **(2)** IP blacklist (Patricia trie, longest-prefix v4/v6) → **(3)** IP whitelist (Patricia trie, per-tier `full_bypass` vs `blacklist_only` dispatch).

**Rationale**: Blacklist before whitelist prevents leaked whitelist IPs from bypassing explicit blocks.

**Configuration**: `rules/access-lists.yaml` (YAML v1). Hot-reload via `notify` (250ms debounce, SIGHUP forces immediate). Atomic `ArcSwap` swaps; on parse error, retains previous snapshot with `tracing::warn!`. Soft-warn ≥50k entries, hard-reject ≥500k.

**Audit Fields**: Every request stamped with `access_decision` (continue|bypass_all|host_gate|ip_blacklist), `access_reason`, `access_match` (host/IP or empty), `access_dry_run` (bool).

See [Access Lists Operator Guide](./access-lists.md) for full schema, worked examples, dry-run mode, troubleshooting.

---

## Phases 1-4: IP & URL Filtering

```
Phase 1: IP Allowlist (CIDR)
├─ Check if client IP in allow_ips table
├─ If match → allow this phase, continue to Phase 2
└─ If no match → continue (allowlist is permissive)

Phase 2: IP Blocklist (CIDR)
├─ Check if client IP in block_ips table
├─ If match → BLOCK (decision made)
└─ If no match → continue to Phase 3

Phase 3: URL Allowlist (regex + literal)
├─ Check if request path in allow_urls table
├─ If match → bypass all downstream phases, allow
└─ If no match → continue to Phase 4

Phase 4: URL Blocklist (regex + literal)
├─ Check if request path in block_urls table
├─ If match → BLOCK
└─ If no match → continue to Phase 5
```

## Phases 5-7: Rate Limiting & Behavior Analysis

### Phase 5: Rate Limiting (FR-004)

```
FR-004 Rate Limiting: Tiered token-bucket + sliding-window
├─ Key 1: ip:<host>:<client_ip> (checked first, IP-based limit)
│  ├─ Algorithm: token-bucket (burst) + sliding-window (sustained)
│  ├─ Config: per-tier burst_capacity, burst_refill_per_s, window_secs, window_limit
│  ├─ Store: MemoryStore (100K cap, 10min idle eviction) or RedisStore (Lua roundtrip)
│  └─ BreakerStore wraps both: circuit-breaker (default 5 failures) → fallback to memory
├─ If IP key fails → BLOCK with rule ID RL-IP (fail-mode: tier.Close=block, Open=pass)
├─ Else check Key 2: sess:<host>:<session_id> (session/device-fp, fallback if cookie present)
│  └─ If session key fails → BLOCK with rule ID RL-SESSION
├─ If both Allow → continue to Phase 6
└─ Rule ID RL-ERR on check error (fail-mode honored per tier policy)

Config: configs/rate-limit.yaml (hot-reload via notify, 200ms debounce, ArcSwap)
```

### Phase 5.1: DDoS Detection (FR-005)

```
FR-005 DDoS Protection: Multi-layer detection with dynamic banning
├─ Position: AFTER rate-limit (catch token-bucket exhaustion first)
├─ Three detectors run in parallel:
│  ├─ PerIpDetector: sliding-window counter per IP
│  │  └─ threshold: tier.policy.ddos_threshold_rps (requests/sec)
│  │  └─ window: 1 second
│  ├─ PerFingerPrintDetector: sliding-window per device fingerprint (if available)
│  │  └─ groups requests by FpKey across multiple IPs (botnet detection)
│  │  └─ fallback to PerIpDetector if FpKey unavailable
│  └─ PerTierDetector: adaptive threshold per tier (Critical/High/Medium/CatchAll)
│     └─ detects tier-wide bursts; config: ddos.per_tier.<tier>_threshold_rps
├─ On detector trigger (HardBurst event):
│  ├─ DdosAction::Ban → add IP to ban table (TTL: 60s default)
│  │  └─ subsequent requests from banned IP short-circuit → 403 DDOS-BAN
│  ├─ DdosAction::RiskBump → emit Signal::DdosSuspected (to FR-025 risk scorer)
│  └─ DdosAction::Degrade → on store error (Redis down):
│     ├─ tier.policy.fail_mode == Close → BLOCK (safe-default)
│     └─ tier.policy.fail_mode == Open → ALLOW (assume legitimate)
├─ Store backend: MemoryStore (100K cap, idle eviction) or RedisStore (Lua script)
├─ BreakerStore circuit-breaker: fallback to memory on >5 Redis failures
├─ Metrics: ddos_detector_evaluations_total, ddos_hard_burst_total, ddos_bans_issued_total
│  └─ Labels: {tier, detector_type, error_kind}
└─ If no burst → continue to Phase 6

Config: configs/default.toml [ddos] section
Operator guide: docs/ddos-protection.md
```

### Phase 5.5: Transaction Velocity & Sequence (FR-012)

```
FR-012 Transaction Velocity: Cross-endpoint behavioral fraud detection
├─ Position: AFTER rate-limit (shed flood traffic first), BEFORE scanner
├─ RoleTagger: regex match request path → EndpointRole
│  └─ {Login, Otp, Deposit, Withdrawal, LimitChange, None}
│  └─ None → skip tracking, continue to Phase 6
├─ SessionKey extract: cookie value (configurable name) ?? FpKey (FR-010 fallback)
│  └─ neither present → skip tracking, continue to Phase 6
├─ TxStore.record(key, Event {role, ts_ms, ok}):
│  └─ DashMap<SessionKey, ActorTx>; ArrayVec<Event, 16> ring buffer
│  └─ Drops oldest event on overflow
├─ Cooldown gate: if now_ms - last_signal_ms < signal_cooldown_ms → skip
├─ Run 3 classifiers (each <20µs):
│  ├─ SequenceTimingClassifier: Login→OTP→Deposit faster than min_human_ms
│  │  → Signal::TxSequenceTooFast { from, to, interval_ms }
│  ├─ WithdrawalVelocityClassifier: ≥N withdrawals / window_ms
│  │  → Signal::WithdrawalVelocity { count, window_sec }
│  └─ LimitChangeBurstClassifier: ≥M limit-changes / window_ms
│     → Signal::LimitChangeBurst { count, window_sec }
├─ Submit signals to RiskAggregator (fire-and-forget via tokio::spawn)
├─ Janitor (tokio interval): purges idle sessions (TTL session_ttl_secs)
└─ Returns None — SIGNAL-ONLY, never blocks. Continue to Phase 6.

Config: configs/tx-velocity.yaml (hot-reload via notify, ArcSwap, schema v1)
Operator guide: docs/transaction-velocity.md
```

### Phase 6: Scanner Detection (and beyond)

```
Phase 6: Scanner Detection
├─ Check User-Agent against scanner fingerprints (Nmap, Nikto, etc.)
├─ Check request patterns (unusual paths, SQL comments in URI, etc.)
├─ If scanner detected → log & continue (or block, configurable)
└─ else → continue to Phase 7

Phase 7: Bot Detection
├─ Check User-Agent against known bot list (headless browsers, etc.)
├─ Check for browser fingerprinting anomalies
├─ If malicious bot → BLOCK (or challenge)
└─ else → continue to Phase 8
```

## Phases 8-11: Payload Attack Detection

```
Phase 8: SQL Injection (SQLi)
├─ Parse request body + query string (up to 256KB JSON)
├─ Run libinjectionrs detect_sqli fingerprint engine
├─ Check 19 modular regex patterns (SQLI-001..019: classic, blind, error-based)
├─ Apply SqliScanConfig (header/JSON toggles, denylist/allowlist, 4KB header cap)
├─ If SQL injection payload detected → BLOCK
└─ else → continue to Phase 9

Phase 9: Cross-Site Scripting (XSS)
├─ Parse request body + headers
├─ Run libinjectionrs detect_xss fingerprint engine
├─ Check compiled XSS regex patterns (script tags, event handlers, etc.)
├─ If JavaScript/HTML injection detected → BLOCK
└─ else → continue to Phase 10

Phase 10: Remote Code Execution (RCE)
├─ Check for command injection patterns (shell metacharacters, etc.)
├─ Check for expression language injection (${}, #{}, etc.)
├─ Check for template injection (Jinja2, Freemarker, etc.)
├─ If RCE pattern detected → BLOCK
└─ else → continue to Phase 11

Phase 11: Directory Traversal
├─ Normalize path (decode, resolve ../)
├─ Check for attempts to escape web root
├─ Check for Windows alternate data streams (::$DATA)
├─ If traversal detected → BLOCK
└─ else → continue to Phase 12
```

## Phases 12-16: Advanced & Custom Rules

```
Phase 12: Custom Rules (User-Defined)
├─ Load from custom_rules table (Rhai scripts + JSON DSL)
├─ Execute Rhai scripts in sandboxed environment
├─ Evaluate JSON DSL conditions
├─ If rule matches → action (block/log/challenge)
└─ else → continue to Phase 13

Phase 13: OWASP CRS (Core Rule Set)
├─ 24 pre-compiled rule patterns
├─ Categories: XSS, SQLi, RCE, RFI, LFI, protocol violations, etc.
├─ If CRS rule matches → action (block/log)
└─ else → continue to Phase 14

Phase 14: Sensitive Data Leakage
├─ Aho-Corasick multi-pattern matching
├─ Patterns: credit card numbers, SSN, API keys, passwords, etc.
├─ If sensitive data in request → log & continue (or block)
└─ else → continue to Phase 15

Phase 15: Anti-Hotlink Protection
├─ Check Referer header
├─ If Referer not in allowed list → BLOCK (return 403)
└─ else → continue to Phase 16

Phase 16: CrowdSec Integration
├─ Query CrowdSec bouncer for active decisions on client IP
├─ If IP has active decision (ban, captcha, etc.) → apply action
├─ If IP is in local cache → use cached decision
├─ Push attack logs to CrowdSec Log Pusher
└─ FINAL DECISION: Allow / Block / Challenge
```

## Post-Decision

```
After Phase 16:
├─ Decision = Allow
│  ├─ Route to backend (vhost → load balancer → upstream)
│  ├─ Receive response from backend
│  ├─ FR-009 Smart Cache: Check tier gate (CRITICAL never cached)
│  │  → MethodGate, AuthGate, RouteRuleGate, UpstreamCcGate, TierDefaultGate
│  │  → If cacheable: store in moka LRU (tag index updated for purge)
│  └─ Return response to client
│
├─ Decision = Block
│  ├─ Return HTTP 403 Forbidden
│  ├─ Log to security_events + attack_logs
│  ├─ Send notifications (email, webhook, etc.)
│  └─ Increment blocked_requests counter
│
└─ Decision = Challenge (FR-004 rate limit)
   ├─ Return HTTP 429 Too Many Requests (or CAPTCHA page)
   ├─ Log to security_events
   └─ Wait for client to solve challenge before allowing
```

---

## Related Docs

- [system-architecture.md](./system-architecture.md) — Topology, components, storage, cluster.
- [tiered-protection.md](./tiered-protection.md) — Tier classifier consumer guide.
- [access-lists.md](./access-lists.md) — Phase-0 access gate operator guide.
- [custom-rules-syntax.md](./custom-rules-syntax.md) — Phase-12 custom rule schema.
- [transaction-velocity.md](./transaction-velocity.md) — FR-012 Phase-5.5 cross-endpoint fraud detection.
- [device-fingerprinting.md](./device-fingerprinting.md) — FR-010 device identity (SessionKey fallback for FR-012).
