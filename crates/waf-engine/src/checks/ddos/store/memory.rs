//! In-memory `CounterStore` backed by `DashMap`.
//!
//! Default backend for standalone deployments. Uses `Arc<str>` keys to avoid
//! per-hit String allocation on the hot path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use dashmap::DashMap;

use super::CounterStore;

/// Per-key counter entry with atomic count and expiry timestamp.
struct Entry {
    count: AtomicU64,
    expires_ms: i64,
}

/// `DashMap`-backed `DDoS` counter store.
pub struct MemoryCounterStore {
    map: Arc<DashMap<Arc<str>, Entry>>,
    max_keys: usize,
}

impl MemoryCounterStore {
    /// Construct a fresh store with the given limits.
    ///
    /// Spawns a background GC task if a Tokio runtime is currently active;
    /// otherwise relies on `purge_expired` being invoked manually.
    pub fn new(max_keys: usize, gc_interval_s: u32) -> Self {
        let map = Arc::new(DashMap::new());

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let map_bg = Arc::clone(&map);
            let interval = Duration::from_secs(u64::from(gc_interval_s));
            let max = max_keys;
            handle.spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                loop {
                    ticker.tick().await;
                    Self::gc(&map_bg, now_epoch_ms(), max);
                    tokio::task::yield_now().await;
                }
            });
        }

        Self { map, max_keys }
    }

    /// GC pass: purge expired entries, then enforce `max_keys` via LRU.
    fn gc(map: &DashMap<Arc<str>, Entry>, now_ms: i64, max_keys: usize) -> usize {
        let before = map.len();

        map.retain(|_k, e| e.expires_ms > now_ms);

        if map.len() > max_keys {
            let mut entries: Vec<(Arc<str>, i64)> = map
                .iter()
                .map(|e| (Arc::clone(e.key()), e.value().expires_ms))
                .collect();
            entries.sort_by_key(|(_k, exp)| *exp);
            let to_remove = map.len().saturating_sub(max_keys);
            for (key, _) in entries.into_iter().take(to_remove) {
                map.remove(&key);
            }
        }

        before.saturating_sub(map.len())
    }

    /// Pure-sync core. Both async and blocking entry points delegate here.
    ///
    /// NOTE: Cold-key insertion has a benign TOCTOU race where concurrent
    /// first-hits to the same key may both insert, losing one count. This is
    /// acceptable for `DDoS` thresholds (typically 100-10000) and avoids per-call
    /// String allocation that `entry()` would require.
    fn incr_get_inner(&self, key: &str, ttl_ms: i64, now_ms: i64) -> u64 {
        let expires_ms = now_ms.saturating_add(ttl_ms);

        if let Some(mut entry) = self.map.get_mut(key as &str) {
            if entry.expires_ms > now_ms {
                entry.expires_ms = expires_ms;
                return entry.count.fetch_add(1, Ordering::Relaxed) + 1;
            }
            entry.count.store(1, Ordering::Relaxed);
            entry.expires_ms = expires_ms;
            return 1;
        }

        let arc_key: Arc<str> = Arc::from(key);
        self.map.insert(
            arc_key,
            Entry {
                count: AtomicU64::new(1),
                expires_ms,
            },
        );
        1
    }
}

impl Default for MemoryCounterStore {
    fn default() -> Self {
        Self::new(100_000, 60)
    }
}

#[async_trait]
impl CounterStore for MemoryCounterStore {
    async fn incr_get(&self, key: &str, ttl_ms: i64, now_ms: i64) -> anyhow::Result<u64> {
        Ok(self.incr_get_inner(key, ttl_ms, now_ms))
    }

    fn incr_get_blocking(&self, key: &str, ttl_ms: i64, now_ms: i64) -> anyhow::Result<u64> {
        Ok(self.incr_get_inner(key, ttl_ms, now_ms))
    }

    async fn purge_expired(&self, now_ms: i64) -> anyhow::Result<usize> {
        Ok(Self::gc(&self.map, now_ms, self.max_keys))
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

    #[tokio::test]
    async fn incr_get_creates_new_key() {
        let store = MemoryCounterStore::new(1000, 60);
        let count = store.incr_get("k", 60_000, 0).await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn incr_get_increments_existing() {
        let store = MemoryCounterStore::new(1000, 60);
        for i in 1..=5 {
            let count = store.incr_get("k", 60_000, 0).await.unwrap();
            assert_eq!(count, i);
        }
    }

    #[tokio::test]
    async fn incr_get_resets_after_expiry() {
        let store = MemoryCounterStore::new(1000, 60);
        store.incr_get("k", 1000, 0).await.unwrap();
        store.incr_get("k", 1000, 0).await.unwrap();
        assert_eq!(store.incr_get("k", 1000, 0).await.unwrap(), 3);

        let count = store.incr_get("k", 1000, 2000).await.unwrap();
        assert_eq!(count, 1, "expired key should reset");
    }

    #[tokio::test]
    async fn keys_isolated() {
        let store = MemoryCounterStore::new(1000, 60);
        for _ in 0..5 {
            store.incr_get("a", 60_000, 0).await.unwrap();
        }
        let count = store.incr_get("b", 60_000, 0).await.unwrap();
        assert_eq!(count, 1, "different key starts fresh");
    }

    #[tokio::test]
    async fn purge_expired_removes_old_entries() {
        let store = MemoryCounterStore::new(1000, 60);
        store.incr_get("k1", 1000, 0).await.unwrap();
        store.incr_get("k2", 5000, 0).await.unwrap();
        assert_eq!(store.map.len(), 2);

        let removed = store.purge_expired(2000).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(store.map.len(), 1);
        assert!(!store.map.contains_key("k1" as &str));
        assert!(store.map.contains_key("k2" as &str));
    }

    #[tokio::test]
    async fn max_keys_cap_evicts_oldest() {
        let store = MemoryCounterStore::new(10, 60);
        for i in 0..15 {
            let ts = i64::from(i);
            store.incr_get(&format!("k{i}"), 60_000, ts).await.unwrap();
        }
        assert_eq!(store.map.len(), 15);

        let removed = store.purge_expired(100).await.unwrap();
        assert_eq!(removed, 5);
        assert_eq!(store.map.len(), 10);
        assert!(!store.map.contains_key("k0" as &str), "oldest entry must be gone");
    }

    #[tokio::test]
    async fn concurrent_hammer_same_key() {
        let store = Arc::new(MemoryCounterStore::new(1000, 60));
        let mut handles = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let s = Arc::clone(&store);
            handles.push(tokio::spawn(async move { s.incr_get("hot", 60_000, 0).await.unwrap() }));
        }
        let mut max_count = 0_u64;
        for h in handles {
            let c = h.await.unwrap();
            max_count = max_count.max(c);
        }
        assert_eq!(max_count, 1000, "should see 1000 increments");
    }

    #[test]
    fn new_without_runtime_does_not_panic() {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let _store = MemoryCounterStore::new(1000, 60);
    }

    #[tokio::test]
    async fn blocking_api_works() {
        let store = MemoryCounterStore::new(1000, 60);
        let count = store.incr_get_blocking("k", 60_000, 0).unwrap();
        assert_eq!(count, 1);
        let count = store.incr_get_blocking("k", 60_000, 0).unwrap();
        assert_eq!(count, 2);
    }
}
