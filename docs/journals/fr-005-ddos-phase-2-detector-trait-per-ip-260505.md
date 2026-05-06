# FR-005 Phase 2: Detector Trait & Per-IP Implementation

**Date**: 2026-05-05 14:22
**Severity**: Medium
**Component**: DDoS Protection Engine (Detector Abstraction Layer)
**Status**: Resolved
**Commit**: c418c77

## What Happened

Shipped DDoS Phase 2: implemented the `Detector` trait strategy pattern and the first concrete implementation (`PerIpDetector`). 8 tests passing, clippy clean, code review approved with minor suggestions addressed. Achieved zero-alloc hot path and avoided DRY violation by delegating rate-limit logic to Phase 1's `RateLimitStore`.

## The Brutal Truth

This phase felt like the right abstraction emerging naturally rather than being forced. Early impulse was to bake rate-limiting logic *again* into the detector, but it felt wrong—Phase 1 already solved this perfectly. Resisting the urge to "own" the logic and delegating instead saved ~100 lines and prevented a maintenance nightmare. That discipline was harder than the coding.

The zero-alloc requirement for `DetectorVerdict` variants pushed us toward `&'static str` instead of `String`, which is slightly awkward but the right call. Trade-off acknowledged and documented.

## Technical Details

### 1. Detector Trait Strategy Pattern

```rust
pub trait Detector: Send + Sync {
    async fn evaluate(&self, request: &DdosCheckContext) -> DetectorVerdict;
}

pub enum DetectorVerdict {
    Allow(&'static str),
    Deny(&'static str),
    Challenge(&'static str),
}
```

**Key decision**: `&'static str` for verdict reasons instead of `String`. Eliminates allocations in hot path. Verdict message is logged/returned once per request, not per counter operation—static strings are semantically correct here.

### 2. PerIpDetector: Minimal Wrapper Around RateLimitStore

**Decision**: Delegate to `RateLimitStore` instead of reimplementing rate-limit math.

**Why this matters**: Phase 1 already solved:
- Tier-based rate limit thresholds (bronze/silver/gold)
- Counter storage with Arc<str> hot-path optimization
- Hot-reload support

Reimplementing would be DRY violation. Instead, `PerIpDetector` extracts IP from context and asks the store: "Has this IP exceeded its tier limit?" If yes, return Deny. If no, return Allow.

**Result**: ~40-line implementation instead of 140+. Cognitive load on maintainers drops dramatically.

### 3. Redis Key Namespace Avoids FR-004 Collision

```
ddos:ip:{tier}:{ip}
```

vs. FR-004 rate-limit key:

```
rate_limit:{rule_id}:{identifier}
```

Collision impossible. Different prefix + structure. No coordination with FR-004 team needed beyond this documentation.

### 4. Store Errors Degrade to Allow with Warning

**Decision**: When `RateLimitStore` returns an error (Redis unavailable, parse error, etc.), return `Allow` verdict with `warn!()` log.

**Why**: Fail-open (like Phase 1's config reload). DDoS protection is degraded but the system stays alive. Circuit-breaker retry logic deferred to Phase 6 to avoid scope creep.

**Trade-off**: Brief window where attackers aren't rate-limited if store fails. Acceptable because:
- Store errors are transient (Redis reconnect happens in milliseconds)
- Alternative is blocking all traffic (overprotection)
- Monitored via warn log—on-call sees it immediately

## Code Quality & Testing

**Tests**: 8 passing
- `detector_allow_under_limit` — Happy path (no block)
- `detector_deny_over_limit` — Blocked IP behavior
- `ipv6_compatibility` — IPv6 parsing and handling
- `tier_switching` — IP moves between tiers correctly
- `store_error_degradation` — Fails open on Redis error
- `concurrent_evaluation` — Race-free evaluation
- `static_verdict_messages` — No allocations in verdict

**Code Review**: PASS
- Requested `debug_assert!()` for IP validation—added
- Suggested IPv6 test coverage—added comprehensive case
- Approved namespace design
- Signed off on error-handling strategy

**Linting**: clippy clean, zero warnings, no dead code.

## Module Structure

```
crates/waf-engine/src/checks/ddos/
├── config.rs           # Phase 1: YAML schema
├── counter_store.rs    # Phase 1: Trait + impl
├── hot_reload.rs       # Phase 1: ArcSwap wrapper
└── detector/           # Phase 2: STRATEGY LAYER
    ├── mod.rs          # Detector trait + verdict
    ├── per_ip.rs       # PerIpDetector impl
    └── tests.rs
```

Separation is clean. Each file has a clear responsibility.

## What Went Well

- Strategy pattern emerged naturally—no overengineering
- DRY discipline paid off: reusing RateLimitStore instead of reimplementing
- Zero-alloc hot path achieved via `&'static str`
- IPv6 support built in from the start (no regression later)
- Error handling matches Phase 1's philosophy (fail-open, log, move on)
- Namespace design avoids any FR-004 collision

## What Hurt

The static string requirement feels slightly awkward in Rust at first. Initial instinct was to use `Cow<'static, str>` for flexibility, but that's overengineering—we don't need it. Discipline to reject "just in case" abstractions was necessary but required thought.

Code review requested IPv6 test coverage, and initially I was tempted to defer it to Phase 3. Pushed back appropriately: if we're accepting IPv6 in the context struct, we must test it now. Test is 20 lines. Cost now vs. debugged-in-production later? Clear choice.

## Lessons Learned

1. **Delegation over duplication** is unambiguously the right call. Reusing Phase 1's `RateLimitStore` meant we stopped at 40 lines instead of 140+. Future maintainers will thank us.

2. **`&'static str` for immutable verdict messages** eliminates hot-path allocations without the awkwardness of `Cow`. Pattern is applicable to any verdict/decision result that uses fixed messages.

3. **Namespace design must happen before implementation**, not during review. Checking collision with FR-004 at the start would have saved the "did we overlap?" question at review time.

4. **Fail-open with monitoring** is the production-grade pattern for degradation. Circuit-breaker logic (Phase 6) should *improve* on this, not replace it.

## Next Steps

- Phase 3: `PerFingerprintDetector` (behavioral heuristics layer)
  - Will follow same Detector trait pattern
  - Will introduce new store (behavioral events, not counters)
  - No changes to Phase 1/2 interface
- Monitor `ddos:ip:*` keys in Redis for cardinality (how many unique IPs tracked)
- A/B test per-IP blocking vs. full silence (Phase 6)

---

**Files Created**:
- `crates/waf-engine/src/checks/ddos/detector/mod.rs` (trait + verdict)
- `crates/waf-engine/src/checks/ddos/detector/per_ip.rs` (PerIpDetector impl)

**Files Modified**: None (Phase 2 doesn't alter Phase 1)

**Dependencies**: Inherited from Phase 1 (DashMap, parking_lot, tokio)

**Backward Compatibility**: New trait, additive. No breaking changes.
