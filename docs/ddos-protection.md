# DDoS Protection (FR-005)

Multi-layered DDoS detection and mitigation via per-IP, per-fingerprint, and per-tier detectors with adaptive thresholds, dynamic banning, and graceful degradation on store failures.

## Overview

FR-005 provides three detection layers evaluated in parallel:

1. **Per-IP Detector** — sliding-window rate counter; tracks requests per unique client IP
2. **Per-Fingerprint Detector** — device fingerprinting (TLS + HTTP/2); detects botnet/distributed attacks using same client profile
3. **Per-Tier Detector** — adaptive threshold scaled by request tier; prevents burst-mode DOS on high-value endpoints

When any detector triggers, `DdosAction` decides: **Ban** (add to IP table, block subsequent requests), **RiskBump** (increment risk score for FR-025), or **Degrade** (fail-open/close per tier policy on store errors).

---

## Configuration

### Primary Config: `configs/default.toml`

```toml
[ddos]
enabled = true
store = "memory"  # or "redis" if redis-store feature enabled

[ddos.per_ip]
threshold_rps = 1000      # requests per second per IP
window_secs = 1           # sliding window duration
ban_ttl_secs = 60         # how long to keep IP in ban table

[ddos.per_tier]
# Per-tier thresholds (requests/sec) — scale by tier criticality
critical_threshold_rps = 500
high_threshold_rps = 1000
medium_threshold_rps = 2000
catchall_threshold_rps = 5000

[ddos.action]
ban_enabled = true        # issue bans on detector trigger
risk_bump_delta = 30      # risk score delta for FR-025 integration
```

### Per-Tier Policy Integration

Tier policy (from `configs/default.toml` `[[tiers]]` section) controls fail-mode on store errors:

```toml
[[tiers]]
name = "critical"
fail_mode = "close"    # Close: block requests on store error; Open: allow

# DDoS thresholds inherited from [ddos] config above
# Detectors use tier.policy.ddos_threshold_rps for adaptive scaling
```

---

## How It Works

### Request Flow

```
Request arrives
    │
    ├─ Phase 5: Rate Limiting (FR-004)
    │   ├─ IP bucket limit (token-bucket)
    │   └─ Session limit (device fingerprint or cookie)
    │
    ├─ Phase 5.5: DDoS Detection (FR-005) ◄── NEW
    │   ├─ Per-IP sliding-window (threshold: tier.ddos_threshold_rps)
    │   ├─ Per-fingerprint sliding-window (fallback if FP available)
    │   ├─ Per-tier burst detector (adaptive RPS threshold)
    │   └─ On HardBurst → DdosAction (Ban | RiskBump | Degrade)
    │
    ├─ Phase 6–16: Payload/Rule checks
    │
    └─ Decisions emit: Block / Allow / Challenge
```

### Detection Logic

**Per-IP Detector:**
- Maintains sliding-window counter of requests from each IP
- Counter increments on every request; decrements as window slides
- If counter > threshold → `HardBurst` event emitted

**Per-Fingerprint Detector:**
- If `x-device-fp` header present (or computed from FR-010), groups requests by fingerprint
- Same detection logic as per-IP, but aggregates across multiple IPs (botnet scenario)
- Falls back to per-IP if fingerprint unavailable

**Per-Tier Detector:**
- Aggregates all requests hitting tier (Critical/High/Medium/CatchAll)
- Threshold per tier: `ddos.per_tier.<tier_name>_threshold_rps`
- Detects tier-wide bursts (e.g., all Critical endpoints hammered simultaneously)

### Action: Ban

When `DdosAction::Ban` fires:
1. IP added to `IpTable` (in-memory hash map)
2. Ban has TTL (configurable: default 60s)
3. Subsequent requests from banned IP immediately return **403 Forbidden**
4. Short-circuit: evaluated before any rule pipeline phase

**Rule ID:** `DDOS-BAN` (emitted to logs/metrics)

### Action: Risk Bump

When `DdosAction::RiskBump` fires (for non-critical tiers or soft-limit scenarios):
1. Signal `DdosSuspected` added to request's `risk_signals`
2. Risk score delta applied by FR-025 risk scorer (if enabled)
3. Request may challenge or block based on accumulated risk, not immediate ban

**Rule ID:** `DDOS-RISK` (emitted to logs/metrics)

### Degrade: Store Failures

If counter store (Redis) is unavailable or timeouts:

| Tier  | Fail-Mode | Behavior |
|-------|-----------|----------|
| Critical | Close | BLOCK request (safe-default) |
| High  | Open  | ALLOW request (assume legitimate) |
| Medium | Open  | ALLOW request |
| CatchAll | Open  | ALLOW request |

**Metric:** `ddos_degrade_events_total{tier,fail_mode}` incremented on each degradation.

---

## Store Backends

### Memory Store (Default)

```rust
// In-memory DashMap with idle eviction
// - Capacity: 100,000 IP keys
// - Idle TTL: 10 minutes (keys auto-expire)
// - No synchronization across nodes
```

**Use case:** Single-node deployments, lab testing.

**Limitations:**
- Does not persist across restarts
- Per-node state — cluster nodes have independent ban tables

### Redis Store (Optional)

Requires `cargo build --features redis-store`.

```toml
[ddos]
store = "redis"
redis_url = "redis://127.0.0.1:6379"
redis_timeout_ms = 50
```

**Use case:** Multi-node clusters; shared ban table.

**Behavior:**
- Single Lua script roundtrip per request
- 50ms default timeout (configurable)
- On timeout → `BreakerStore` circuit-breaker triggers, fallback to memory
- BreakerStore config: default 5 failures before opening circuit

---

## Metrics

Prometheus-compatible metrics emitted to `localhost:9527/metrics`:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ddos_detector_evaluations_total` | Counter | `tier`, `detector_type` (per_ip/per_fp/per_tier) | Number of times detector ran |
| `ddos_hard_burst_total` | Counter | `tier` | Number of HardBurst events (threshold exceeded) |
| `ddos_bans_issued_total` | Counter | `tier` | Number of IPs banned |
| `ddos_ban_table_size` | Gauge | | Current number of IPs in ban table |
| `ddos_store_errors_total` | Counter | `store_type`, `error_kind` (timeout/io/other) | Store failures |
| `ddos_degrade_events_total` | Counter | `tier`, `fail_mode` (close/open) | Degradations due to store error |
| `ddos_detector_latency_us` | Histogram | `detector_type` | Detector evaluation time (microseconds) |

**Query examples:**

```promql
# Current ban table size
ddos_ban_table_size

# Rate of new bans in past 5 minutes
rate(ddos_bans_issued_total[5m])

# Detector overhead (p99)
histogram_quantile(0.99, ddos_detector_latency_us)

# Store timeout rate
rate(ddos_store_errors_total{error_kind="timeout"}[5m])
```

---

## Operations Guide

### Monitoring

**Check ban table size:**

```bash
curl -s http://localhost:9527/metrics | grep ddos_ban_table_size
# Output: ddos_ban_table_size 42  (42 IPs currently banned)
```

**Watch ban rate (every 5 seconds):**

```bash
watch -n 5 'curl -s http://localhost:9527/metrics | grep ddos_bans_issued_total'
```

### Tuning Thresholds

Edit `configs/default.toml`:

```toml
[ddos.per_ip]
threshold_rps = 1000    # Lower = more sensitive; higher = fewer false positives
```

Hot-reload: Thresholds are **not** hot-reloaded currently. Restart required:

```bash
# Kill existing process
pkill -9 prx-waf

# Restart with new config
./target/release/prx-waf -c configs/default.toml run
```

### Manual IP Ban / Unban

IP bans are in-memory. To clear all bans:

```bash
# No direct CLI command yet (future: `prx-waf ddos ban-table clear`)
# Workaround: Restart WAF or wait for TTL expiry (default 60s)
```

### Alert Rules (Prometheus)

```yaml
groups:
  - name: ddos_alerts
    rules:
      - alert: DdosSuspectedHighBanRate
        expr: rate(ddos_bans_issued_total[5m]) > 10  # >10 bans/sec
        for: 1m
        annotations:
          summary: "High DDoS ban rate detected"

      - alert: DdosStoreFailure
        expr: rate(ddos_store_errors_total[5m]) > 1
        for: 5m
        annotations:
          summary: "DDoS store (Redis) is timing out"

      - alert: DdosBanTableFull
        expr: ddos_ban_table_size > 90000  # approaching 100k limit
        for: 1m
        annotations:
          summary: "Ban table nearly at capacity"
```

---

## Troubleshooting

### Issue: "All traffic blocked during burst"

**Symptom:** Legitimate requests blocked with `DDOS-BAN` rule.

**Cause:** Per-tier or per-IP threshold too low.

**Fix:**
1. Check current ban count: `curl -s http://localhost:9527/metrics | grep ddos_ban_table_size`
2. Increase threshold in `configs/default.toml`:
   ```toml
   [ddos.per_ip]
   threshold_rps = 2000  # was 1000
   ```
3. Restart WAF
4. Monitor: `rate(ddos_bans_issued_total[5m])`

### Issue: "Redis store timeouts, traffic degrading"

**Symptom:** Logs show `ddos_store_errors_total{error_kind="timeout"}` increasing.

**Cause:** Redis latency >50ms, or Redis pod down.

**Fix:**
1. Check Redis health: `redis-cli ping`
2. If down, restart Redis or increase availability
3. If slow, check network/CPU on Redis host
4. Increase timeout (if applicable):
   ```toml
   [ddos]
   redis_timeout_ms = 100  # was 50
   ```

### Issue: "Ban table grows unbounded"

**Symptom:** `ddos_ban_table_size` keeps increasing, never decreases.

**Cause:** Legitimate traffic from many IPs (e.g., corporate proxy, datacenter).

**Fix:**
1. Whitelist the proxy/datacenter IP in `rules/access-lists.yaml` (Phase-0 bypass)
2. Or lower `ban_ttl_secs` to recover entries faster:
   ```toml
   [ddos.action]
   ban_ttl_secs = 30  # was 60
   ```
3. Monitor: `ddos_ban_table_size` should stabilize

---

## Testing

### Unit Tests

```bash
# Per-IP detector logic
cargo test -p waf-engine detector::per_ip --lib

# Per-fingerprint fallback
cargo test -p waf-engine detector::per_fp --lib

# Per-tier detection
cargo test -p waf-engine detector::per_tier --lib

# Action & ban table
cargo test -p waf-engine ddos::action --lib
```

### Integration Tests

```bash
# Run all 4 integration tests (I1-I4)
cargo test -p waf-engine --test ddos_integration

# Output example:
# test i1_per_ip_burst_triggers_ban ... ok
# test i2_per_fp_burst_across_ips_fallback_to_per_ip ... ok
# test i3_per_tier_burst_triggers_detection ... ok
# test i4_reload_mid_burst_preserves_bans ... ok
```

### Scenario Tests

```bash
# Run all 5 scenario suites (a-e)
cargo test -p waf-engine --test ddos_scenarios

# Scenarios:
# a) Baseline traffic (no blocks)
# b) Single IP flood (triggers ban)
# c) Botnet same fingerprint (escalation)
# d) Per-tier burst + fail-mode matrix
# e) Redis down failmode

# Individual scenario:
cargo test -p waf-engine scenario_a_baseline_traffic_no_blocks
```

### Soak Test (Memory / Leak Surveillance)

```bash
# Quick 5-min soak (used in PR validation)
cargo test --release -p waf-engine --test ddos_soak soak_quick_5min

# Full 30-min soak (nightly CI only, runs automatically)
# Schedule: `.github/workflows/ddos-soak.yml` (daily 4 AM UTC)
# Manual trigger:
gh workflow run ddos-soak.yml --ref main
```

---

## Related Documentation

- **[System Architecture](./system-architecture.md)** — Phase 5 pipeline diagram, component integration
- **[Request Pipeline](./request-pipeline.md)** — Phase 5 (FR-004 rate limiting) vs Phase 5.5 (FR-005 DDoS)
- **[Tiered Protection](./tiered-protection.md)** — Tier policy integration with FR-005
- **[Test E2E Guideline](./test-e2e-guideline.md)** — Nightly soak job (`.github/workflows/ddos-soak.yml`)

---

## Implementation Notes

**Module:** `crates/waf-engine/src/checks/ddos/`

**Key files:**
- `detector/per_ip.rs` — Per-IP sliding-window logic
- `detector/per_fp.rs` — Per-fingerprint detector (device_fp fallback)
- `detector/per_tier.rs` — Per-tier burst detector
- `action.rs` — Ban table, action execution
- `degrade.rs` — Fail-mode degradation on store errors
- `metrics.rs` — Prometheus metric collectors
- `store.rs` — Memory and Redis counter backends

**Performance targets (p99):**
- Detector evaluation: <500µs per request
- Ban table lookup: <100µs
- Store roundtrip (Redis): <50ms (with 50ms timeout)

**Constraints:**
- Ban table capacity: 100,000 IPs (hard limit)
- Per-IP counter window: 1 second (sliding, non-overlapping)
- Per-tier aggregation: all 4 tiers monitored in parallel
- Fallback behavior: on store error, delegates to tier.fail_mode policy
