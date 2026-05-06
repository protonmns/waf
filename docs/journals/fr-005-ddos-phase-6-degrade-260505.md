# FR-005 Phase 6: Degrade & Circuit Breaker Implementation

**Date**: 2026-05-05 11:38  
**Severity**: High  
**Component**: DDoS Protection / Degradation Logic  
**Status**: Resolved

## What Happened

Implemented graceful degradation and circuit breaker for FR-005 DDoS protection. Built the decision matrix that routes requests based on tier, failure mode, and error type—187 lines of pure logic with zero runtime dependencies added.

## The Brutal Truth

The hardest part wasn't the logic; it was fighting against constraints. `tokio_unstable` isn't enabled in this repo, so we couldn't use runtime metrics for in-flight tracking. We built around it with `AtomicUsize`. The fail-mode matrix is exhaustive—compiler won't let you forget a case—which is exactly what we needed after Phase 5's complexity.

## Technical Details

**ErrorKind enum**: Three variants (StoreUnavailable, BackendOverload, ConfigStale)  
**DegradeAction enum**: Four outcomes (Allow, AllowAndWarn, Block with 503 status and retry-after header)  

Fail-mode matrix (14 decision paths):
```
Critical/High + any error → Block 503
Medium + any error → AllowAndWarn  
CatchAll + any error → Allow
FailMode::Close override → always Block (circuit open)
```

**OverloadGuard**: Monitors in-flight requests via atomic counter. Sampler thread flips overload flag when threshold exceeded.  
**InFlightGuard**: RAII guard auto-decrements counter on scope exit (tokio::task::abort-safe).

## What We Tried

1. **tokio runtime metrics** – Not available without tokio_unstable feature. Rejected: too invasive to enable just for this.
2. **CancellationToken for shutdown** – Would add tokio_util dependency. Used internal `AtomicBool` instead. Simpler, fewer deps.
3. **Wildcard match in resolve()** – Compiler rejection saved us. Exhaustive matching forces handling new error kinds.

## Root Cause Analysis

The constraint wasn't a bug; it was architecture. Repo deliberately minimizes external deps. We adapted by:
- Using std atomics instead of runtime metrics
- Implementing our own shutdown pattern
- Leaning into Rust's exhaustive matching (feature, not limitation)

This forced us to write simpler, more testable code.

## Lessons Learned

**Exhaustive matching is a feature.** The `_ => unreachable!()` trap doesn't exist when the compiler won't compile. Add an ErrorKind? Compiler screams. Add a FailMode? Compiler screams. This catches bugs earlier than property tests.

**Atomic counters are fast enough.** We worried about contention. In-flight counter: single `fetch_add`/`fetch_sub` per request. No lock. Negligible cost. Simpler than waiting for tokio metrics to stabilize.

**Graceful degradation beats crash.** AllowAndWarn on Medium tier isn't "user might get bad data." It's "backend is struggling, but user can retry." Tier design matters.

## Next Steps

**Phase 7: Pipeline Wiring & Observability**
- Wire DegradeAction into request pipeline  
- Add metrics/tracing for degrade decisions  
- Integration test: simulate backend failure → verify retry-after headers sent  
- Verify all 715 tests still pass post-wiring

**Ownership**: Phase 7 implementation. **Timeline**: Next session.

---

**Test Status**: 715/715 pass. 14 chaos cases + 4 property tests confirm behavior.
