//! In-memory `RateLimitStore` backed by `DashMap`.
//!
//! Default backend for standalone deployments and Redis-fallback when the
//! breaker is open. Per-key entry packs `(TokenBucketState, SlidingWindowState)`
//! so a single shard write-lock covers both algorithm steps atomically.

#![allow(clippy::duration_suboptimal_units)] // prefer `from_secs` over MSRV‑gated `from_mins`

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use dashmap::DashMap;

use crate::checks::rate_limit::algo::{SlidingWindowState, TokenBucketState};
use crate::checks::rate_limit::store::{Decision, LimitCfg, RateLimitStore};

/// Maximum number of entries before forced eviction of oldest.
const MAX_ENTRIES: usize = 100_000;

/// Entries idle longer than this are eligible for eviction.
const ENTRY_TTL: Duration = Duration::from_secs(600);

/// How often the background cleanup task runs.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Packed per-key state. ~32B: TB (16) + SW (16) + `last_touch` (8) + alignment.
struct Entry {
    tb: TokenBucketState,
    sw: SlidingWindowState,
    last_touch_ms: i64,
}

/// `DashMap`-backed rate-limit store.
pub struct MemoryStore {
    map: Arc<DashMap<String, Entry>>,
}

impl MemoryStore {
    /// Construct a fresh store. Spawns a background cleanup task if a Tokio
    /// runtime is currently active; otherwise the store still works but
    /// relies on `purge_expired` being invoked manually.
    pub fn new() -> Self {
        let map = Arc::new(DashMap::new());

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let map_bg = Arc::clone(&map);
            handle.spawn(async move {
                let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
                loop {
                    interval.tick().await;
                    Self::cleanup(&map_bg, now_epoch_ms());
                }
            });
        }

        Self { map }
    }

    /// Evict entries idle past `ENTRY_TTL`, then enforce `MAX_ENTRIES` cap by
    /// removing the oldest-touched entries. Returns count removed.
    fn cleanup(map: &DashMap<String, Entry>, now_ms: i64) -> usize {
        let ttl_ms = i64::try_from(ENTRY_TTL.as_millis()).unwrap_or(i64::MAX);
        let before = map.len();

        map.retain(|_k, e| now_ms.saturating_sub(e.last_touch_ms) < ttl_ms);

        if map.len() > MAX_ENTRIES {
            let mut entries: Vec<(String, i64)> =
                map.iter().map(|e| (e.key().clone(), e.value().last_touch_ms)).collect();
            entries.sort_by_key(|(_k, t)| *t);
            let to_remove = map.len().saturating_sub(MAX_ENTRIES);
            for (key, _) in entries.into_iter().take(to_remove) {
                map.remove(&key);
            }
        }

        before.saturating_sub(map.len())
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// Pure-sync core. Both async and blocking entry points delegate here so
    /// they share identical semantics without round-tripping through the
    /// runtime.
    #[allow(clippy::significant_drop_tightening)] // lock must span both algo steps for atomic RMW
    fn check_and_consume_inner(&self, key: &str, cfg: &LimitCfg, now_ms: i64) -> Decision {
        // DashMap::entry holds the shard write-lock for the duration of this
        // closure, giving us atomic read-modify-write per key.
        let mut entry = self.map.entry(key.to_string()).or_insert_with(|| Entry {
            tb: TokenBucketState::new_full(cfg, now_ms),
            sw: SlidingWindowState::new(now_ms, cfg.window_secs),
            last_touch_ms: now_ms,
        });
        entry.last_touch_ms = now_ms;

        // TB checked first so a burst attacker sees `BurstExceeded` rather
        // than `SustainedExceeded` (more precise classification).
        if !entry.tb.try_consume(cfg, now_ms) {
            return Decision::BurstExceeded;
        }
        if !entry.sw.try_consume(cfg, now_ms) {
            return Decision::SustainedExceeded;
        }
        Decision::Allow
    }
}

#[async_trait]
impl RateLimitStore for MemoryStore {
    async fn check_and_consume(&self, key: &str, cfg: &LimitCfg, now_ms: i64) -> anyhow::Result<Decision> {
        Ok(self.check_and_consume_inner(key, cfg, now_ms))
    }

    fn check_and_consume_blocking(&self, key: &str, cfg: &LimitCfg, now_ms: i64) -> anyhow::Result<Decision> {
        Ok(self.check_and_consume_inner(key, cfg, now_ms))
    }

    async fn purge_expired(&self) -> anyhow::Result<usize> {
        Ok(Self::cleanup(&self.map, now_epoch_ms()))
    }
}

/// Current wall-clock epoch milliseconds, clamped to `i64`.
fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn cfg() -> LimitCfg {
        LimitCfg {
            burst_capacity: 5,
            burst_refill_per_s: 0.0,
            window_secs: 60,
            window_limit: 1_000,
        }
    }

    #[tokio::test]
    async fn allow_then_burst_exceeded() {
        let store = MemoryStore::new();
        let cfg = cfg();
        for _ in 0..5 {
            assert_eq!(store.check_and_consume("k", &cfg, 0).await.unwrap(), Decision::Allow,);
        }
        assert_eq!(
            store.check_and_consume("k", &cfg, 0).await.unwrap(),
            Decision::BurstExceeded,
        );
    }

    #[tokio::test]
    async fn sustained_exceeded_after_burst_refills() {
        // Burst large enough to never block; window is the constraint.
        let cfg = LimitCfg {
            burst_capacity: 1_000,
            burst_refill_per_s: 1_000.0,
            window_secs: 60,
            window_limit: 3,
        };
        let store = MemoryStore::new();
        for _ in 0..3 {
            assert_eq!(store.check_and_consume("k", &cfg, 0).await.unwrap(), Decision::Allow,);
        }
        assert_eq!(
            store.check_and_consume("k", &cfg, 0).await.unwrap(),
            Decision::SustainedExceeded,
        );
    }

    #[tokio::test]
    async fn keys_isolated() {
        let store = MemoryStore::new();
        let cfg = cfg();
        for _ in 0..5 {
            assert_eq!(store.check_and_consume("a", &cfg, 0).await.unwrap(), Decision::Allow,);
        }
        // Different key starts fresh.
        assert_eq!(store.check_and_consume("b", &cfg, 0).await.unwrap(), Decision::Allow,);
    }

    #[tokio::test]
    async fn concurrent_hammer_same_key_no_panic_and_bounded() {
        let store = Arc::new(MemoryStore::new());
        let cfg = LimitCfg {
            burst_capacity: 100,
            burst_refill_per_s: 0.0,
            window_secs: 60,
            window_limit: 100,
        };
        let mut handles = Vec::with_capacity(1_000);
        for _ in 0..1_000 {
            let s = Arc::clone(&store);
            let c = cfg.clone();
            handles.push(tokio::spawn(async move {
                matches!(s.check_and_consume("hot", &c, 0).await.unwrap(), Decision::Allow)
            }));
        }
        let mut allowed = 0_usize;
        for h in handles {
            if h.await.unwrap() {
                allowed += 1;
            }
        }
        // With burst=100 and no refill, exactly 100 should pass; rest blocked.
        assert_eq!(allowed, 100, "expected exactly burst_capacity allows");
    }

    #[tokio::test]
    async fn ttl_eviction_removes_idle_entry() {
        let store = MemoryStore::new();
        let cfg = cfg();
        store.check_and_consume("k", &cfg, 0).await.unwrap();
        assert_eq!(store.map.len(), 1);

        // Simulate "now" beyond TTL by touching cleanup directly with a
        // future epoch time exceeding ENTRY_TTL since last_touch (which is 0).
        let future_ms = i64::try_from(ENTRY_TTL.as_millis()).unwrap() + 1;
        let removed = MemoryStore::cleanup(&store.map, future_ms);
        assert_eq!(removed, 1);
        assert_eq!(store.map.len(), 0);
    }

    #[tokio::test]
    async fn max_entries_cap_evicts_oldest() {
        let store = MemoryStore::new();
        let cfg = cfg();
        // Insert MAX_ENTRIES + 1 with monotonically increasing timestamps so
        // the very first key is the oldest and gets evicted by the cap.
        for i in 0..=MAX_ENTRIES {
            let ts = i64::try_from(i).unwrap();
            store.check_and_consume(&format!("k{i}"), &cfg, ts).await.unwrap();
        }
        assert!(store.map.len() > MAX_ENTRIES);

        // Run cleanup with a `now` close enough that no entry is TTL-evicted
        // (so only the cap path runs).
        let now = i64::try_from(MAX_ENTRIES).unwrap();
        MemoryStore::cleanup(&store.map, now);
        assert_eq!(store.map.len(), MAX_ENTRIES);
        assert!(!store.map.contains_key("k0"), "oldest entry must be gone");
    }

    #[test]
    fn new_without_runtime_does_not_panic() {
        // No #[tokio::test] — intentionally outside any runtime.
        assert!(tokio::runtime::Handle::try_current().is_err());
        let _store = MemoryStore::new();
    }

    // Phase 05: full conformance suite, parameterized over `dyn RateLimitStore`.
    #[tokio::test]
    async fn conformance_suite() {
        use crate::checks::rate_limit::conformance::run_conformance;
        let store: Arc<dyn RateLimitStore> = Arc::new(MemoryStore::new());
        run_conformance(store).await;
    }
}
