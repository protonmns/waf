---
title: "FR-005 DDoS Protection"
description: "Burst detection + auto-block + per-tier threshold/fail-mode. Adds per-fp + per-tier-global axes; reuses FR-004 per-IP. L7 only."
status: complete
priority: P0
branch: "main"
tags: ["security", "ddos", "fr-005", "production-ready"]
blockedBy: ["260502-1957-fr004-rate-limiting"]
blocks: []
created: "2026-05-05T03:06:30.095Z"
createdBy: "ck:plan"
source: skill
relatedReports:
  - plans/reports/brainstorm-260505-0954-fr-005-ddos-protection.md
---

# FR-005 DDoS Protection

**Spec:** `analysis/requirements.md` line 45 (FR-005, P0 mandatory)
**Brainstorm:** `plans/reports/brainstorm-260505-0954-fr-005-ddos-protection.md`
**Target module:** `crates/waf-engine/src/checks/ddos/`

## Overview

Production-ready L7 DDoS protection. Adds burst detection on two new axes (per-device-fp, per-tier-global) on top of FR-004 per-IP. Triggers TTL-escalating bans via FR-008 access::ip_table + cumulative risk bump. Honors FR-002 tier policies and FR-036/037/038 fail-mode contract. Hot-reloadable via ArcSwap. Cluster-coherent via Redis Lua scripts.

## Acceptance Criteria (from FR-005)

- [x] Burst detection (per-fp + per-tier global, in addition to FR-004 per-IP)
- [x] Auto-block (TTL-escalating ban: 60s → 5m → 1h)
- [x] Configurable threshold per tier
- [x] Fail-close (Critical/High) / fail-open (Medium/CatchAll) per tier

## Locked Decisions (do not redebate)

| # | Decision |
|---|----------|
| Scope | L7 only — L4 delegated to kernel/upstream LB |
| Detection axes | per-IP (delegate FR-004), per-device-fp, per-tier-global |
| Auto-block | TTL ban via `access::ip_table` + risk bump via existing aggregator |
| Module | New `checks/ddos/` (separate from `rate_limit/`, SRP) |
| Patterns | Strategy detectors + Command actions + ArcSwap reload + Circuit breaker |
| Cluster | Redis `EVAL` Lua INCR+EXPIRE for global counter; in-process for per-IP/per-fp |
| Coverage | ≥90% line+branch target (reported, NOT CI-gated) |

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Config & Memory Store](./phase-01-config-memory-store.md) | Complete |
| 2 | [Detector Trait & Per-IP](./phase-02-detector-trait-per-ip.md) | Complete |
| 3 | [Per-Fingerprint Detector](./phase-03-per-fingerprint-detector.md) | Complete |
| 4 | [Per-Tier Detector & Redis Store](./phase-04-per-tier-detector-redis-store.md) | Complete |
| 5 | [Action Ban & Risk Bump](./phase-05-action-ban-risk-bump.md) | Complete |
| 6 | [Degrade & Circuit Breaker](./phase-06-degrade-circuit-breaker.md) | Complete |
| 7 | [Pipeline Wiring & Observability](./phase-07-pipeline-wiring-observability.md) | Complete |
| 8 | [Unit Property Loom Tests](./phase-08-unit-property-loom-tests.md) | Complete |
| 9 | [Integration & Scenario E2E](./phase-09-integration-scenario-e2e.md) | Complete |
| 10 | [Docs & Roadmap Update](./phase-10-docs-roadmap-update.md) | Complete |

## Dependencies

**Upstream (must be available):**
- FR-002 Tiered Protection — `waf_common::tier::{Tier, TierPolicy, FailMode}` (complete)
- FR-004 Rate Limiting — `checks::rate_limit::algo::{sliding_window, token_bucket}` reused (in-progress, see `260502-1957-fr004-rate-limiting`)
- FR-008 Access Lists — `access::ip_table` write API for ban execution (complete)
- FR-010 Device Fingerprinting — `ctx.device_fp` for per-fp detector (complete)

**Pipeline ordering (verified `engine.rs`):**
1. Phase 1-4: IP/URL whitelist + blacklist (FR-008) — runs before FR-005, allowlist short-circuits
2. Phase 5-11: Attack detection (FR-005 ddos check inserted here, before rate_limit which it complements)
3. Phase 16: CrowdSec / community blocklist

## Unresolved Questions

1. **Redis as hard dep for cluster mode** — confirm with deploy team. Alternative: gossip per-tier counter via existing Raft-lite QUIC channel (would push to v0.4.0).
2. **Baseline learning window** (60s moving median) — tune via real traffic post-deploy. Default acceptable for v1.
3. **Pipeline insertion point** — confirm FR-005 runs after FR-008 allowlist (yes per `engine.rs` Phase 1-4 → Phase 5-11) and before FR-004 rate_limit (so ban short-circuits rate-limit work).

## Success Metrics

- All 4 FR-005 acceptance criteria pass automated tests
- `cargo-llvm-cov` reports ≥90% line + ≥90% branch on `checks/ddos/**` (CI artifact, not gated)
- Scenario suite (a)–(e) green in CI
- p99 detector overhead <200µs at 5k rps
- Nightly soak: 30-min run, RSS drift <5%, key count bounded
