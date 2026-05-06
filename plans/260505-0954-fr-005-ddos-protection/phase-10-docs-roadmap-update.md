---
phase: 10
title: "Docs & Roadmap Update"
status: complete
priority: P1
effort: "4h"
dependencies: [9]
---

# Phase 10: Docs & Roadmap Update

## Overview

Final phase: ship docs alongside code. Operator-facing config guide, request-pipeline diagram update, roadmap status flip, codebase summary entry, CHANGELOG.

## Requirements

- Functional:
  - New `docs/ddos-protection.md` — operator guide (config schema, defaults, tuning, fail-mode matrix, observability).
  - Update `docs/request-pipeline.md` — insert FR-005 between Phase 4 (allowlist) and Phase 5 (rate_limit).
  - Update `docs/project-roadmap.md` — flip FR-005 to Complete in current release section.
  - Update `docs/codebase-summary.md` — add `crates/waf-engine/src/checks/ddos/` module entry mirroring `rate_limit/` style.
  - Update `CHANGELOG.md` — versioned entry under "Added".
- Non-functional:
  - Doc style mirrors existing `docs/tiered-protection.md` and `docs/rate-limiting.md` (read both for tone + structure).
  - Cross-links accurate; YAML examples lint-clean.

## Doc Outlines

### `docs/ddos-protection.md`

```markdown
# DDoS Protection (FR-005)

## Scope
L7 only. Pingora reverse-proxy layer. L4 delegated to upstream LB / kernel.

## Detection Axes
- Per-IP — delegates to FR-004 rate-limit primitives (no new math).
- Per-device-fingerprint — counters keyed on JA3/JA4/H2 hash.
- Per-tier-global — single counter per tier with 60s moving-median baseline.

## Configuration
File: `configs/ddos.yaml`. Hot-reloaded.
[example yaml]

## Auto-Block
TTL-escalating ban via `access::ip_table`:

| Offense # | Ban TTL | Risk delta |
|-----------|---------|------------|
| 1 | 60s | +30 |
| 2 | 5m  | +50 |
| 3+ | 1h | clamp 100 |

## Tier × Fail-Mode Matrix
[from phase 6 table]

## Cluster Mode
Optional Redis backend for cluster-coherent per-tier counter. Memory-only mode = per-node best-effort (documented limitation).

## Observability
- Metrics: `ddos_burst_total`, `ddos_ban_active`, `ddos_counter_keys`, `ddos_store_errors_total`.
- Audit log: `target = "ddos::audit"`, structured fields per ban event.

## Tuning Guide
Cold-start absolute caps; baseline learning window; offense window.
```

### `docs/request-pipeline.md` change

Find the existing diagram listing Phase 1-4 (allowlist) → Phase 5-11 (detection). Insert "FR-005 DDoS check" between them. Update any line numbers / mermaid arrows. Note: this is an existing doc (mentioned in commit `c631c1e` as updated for FR-004/FR-009) — read first to confirm structure.

### `docs/project-roadmap.md` change

Find FR-005 row. Status `Pending` → `Complete`. Add release tag (current sprint).

### `docs/codebase-summary.md` change

In the `crates/waf-engine/src/checks/` section, add:

```
ddos/                # FR-005 DDoS protection
├── config.rs        # YAML schema + validation
├── reload.rs        # ArcSwap hot-reload watcher
├── detector/        # Strategy: per_ip, per_fp, per_tier
├── store/           # CounterStore trait: memory + redis (gated)
├── action/          # Command: ban + risk bump
├── degrade.rs       # Tier × fail-mode matrix
└── check.rs         # Pipeline integration
```

### `CHANGELOG.md` entry

```markdown
### Added
- **FR-005 DDoS Protection** — L7 burst detection with auto-block. Per-IP (delegates FR-004), per-device-fingerprint, and per-tier-global detectors. TTL-escalating bans (60s → 5m → 1h) via `access::ip_table` plus risk bump. Hot-reloadable, cluster-coherent (Redis), tier × fail-mode honoured per FR-036/037/038. See `docs/ddos-protection.md`.
```

## Related Code Files

- Create:
  - `docs/ddos-protection.md`
- Modify:
  - `docs/request-pipeline.md`
  - `docs/project-roadmap.md`
  - `docs/codebase-summary.md`
  - `CHANGELOG.md`

## Implementation Steps

1. Read existing `docs/tiered-protection.md` + `docs/rate-limiting.md` (if present) to match tone + structure exactly.
2. Read current `docs/request-pipeline.md` — locate FR-004 insertion from prior PR; place FR-005 immediately before it (per pipeline-ordering decision in phase 7).
3. Write `docs/ddos-protection.md` per outline above.
4. Update `docs/request-pipeline.md` — add ddos box to mermaid diagram + bullet list.
5. Update `docs/project-roadmap.md` FR-005 row → Complete.
6. Update `docs/codebase-summary.md` with `ddos/` tree entry.
7. Update `CHANGELOG.md`.
8. Render mermaid in `docs/request-pipeline.md` locally (mermaid CLI or `mermaidjs-v11` skill) to verify no syntax break.
9. Cross-check all internal links resolve.

## Success Criteria

- [x] `docs/ddos-protection.md` published; matches operator-guide tone of sibling docs
- [x] `docs/request-pipeline.md` diagram includes FR-005 box, ordered after FR-008 allowlist + before FR-004 rate_limit
- [x] `docs/project-roadmap.md` FR-005 row shows Complete + release tag
- [x] `docs/codebase-summary.md` lists `ddos/` module
- [x] `CHANGELOG.md` entry under correct version heading
- [x] No broken markdown links (run `mlc` or equivalent)
- [x] Mermaid renders without syntax error
- [x] Operator can configure DDoS protection from `docs/ddos-protection.md` alone (smoke-tested by team-member dry read)

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Doc drift from final code | Phase 10 runs LAST; references actual config field names from phase 1 schema |
| Mermaid v10 vs v11 syntax mismatch | Use `/ck:mermaidjs-v11` skill for v11 rules |
| Roadmap entry out of sync with PR merge | Update in same PR as code; CI doesn't block but PR review enforces |
| Operator confusion on Redis dep | "Cluster Mode" subsection states explicit fallback semantics |
