//! `MokaStore` — in-process LRU cache backend backed by [`moka`].
//!
//! Implements [`CacheBackend`] for the `memory` backend mode. This is the
//! default and is always compiled in regardless of feature flags. All tag
//! management uses the local [`TagIndex`] (DashMap-based; no external process).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use moka::notification::RemovalCause;
use tracing::trace;

use super::backend::{BackendHealth, BackendInfo, CacheBackend, CachedResponse};
use super::tag_index::TagIndex;

/// In-process moka LRU response cache.
pub struct MokaStore {
    inner: Cache<String, Arc<CachedResponse>>,
    tag_index: Arc<TagIndex>,
}

impl MokaStore {
    /// Construct a new `MokaStore`.
    ///
    /// `max_size_mb` controls the entry capacity (approximated as
    /// `max_size_mb × 16` entries — same heuristic as the old `ResponseCache`).
    pub fn new(max_size_mb: u64, max_ttl_secs: u64) -> Self {
        let capacity = (max_size_mb * 16).max(64);
        let tag_index = Arc::new(TagIndex::new());
        let tag_index_for_evict = Arc::clone(&tag_index);

        let inner = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(Duration::from_secs(max_ttl_secs))
            .eviction_listener(move |k: Arc<String>, _v: Arc<CachedResponse>, cause: RemovalCause| {
                // Skip Replaced: the new `put` already re-registers tags for the new
                // value. Acting on Replaced would wipe the freshly registered index
                // entry and cause purge-by-tag misses.
                if matches!(cause, RemovalCause::Replaced) {
                    return;
                }
                tag_index_for_evict.unregister(&Arc::<str>::from(k.as_str()));
            })
            .build();

        Self { inner, tag_index }
    }
}

#[async_trait]
impl CacheBackend for MokaStore {
    async fn get(&self, key: &str) -> Option<Arc<CachedResponse>> {
        let result = self.inner.get(key).await;
        trace!(key = %key, hit = result.is_some(), "MokaStore::get");
        result
    }

    async fn put(&self, key: &str, value: CachedResponse, ttl_secs: u64, tags: &[Arc<str>]) -> bool {
        debug_assert_eq!(
            ttl_secs, value.max_age,
            "ttl_secs from gate pipeline must match CachedResponse.max_age"
        );
        let entry = Arc::new(CachedResponse {
            max_age: ttl_secs,
            ..value
        });
        let key_arc: Option<Arc<str>> = if tags.is_empty() {
            None
        } else {
            Some(Arc::<str>::from(key))
        };
        self.inner.insert(key.to_string(), entry).await;
        if let Some(k) = key_arc {
            self.tag_index.register(&k, tags);
        }
        true
    }

    async fn remove(&self, key: &str) {
        self.inner.remove(key).await;
    }

    async fn purge_by_tag(&self, tag: &str) -> usize {
        let keys = self.tag_index.keys_for_tag(tag);
        let count = keys.len();
        for k in keys {
            self.inner.remove(k.as_ref()).await;
            self.tag_index.unregister(&k);
        }
        count
    }

    async fn purge_by_route_id(&self, route_id: &str) -> usize {
        self.purge_by_tag(route_id).await
    }

    async fn purge_host(&self, host: &str) -> usize {
        let keys: Vec<String> = self
            .inner
            .iter()
            .filter(|(k, _)| {
                let mut parts = k.splitn(3, ':');
                parts.next(); // method
                parts.next() == Some(host)
            })
            .map(|(k, _)| k.to_string())
            .collect();
        let count = keys.len();
        for k in keys {
            self.inner.remove(&k).await;
        }
        count
    }

    async fn flush(&self) {
        self.inner.invalidate_all();
        self.inner.run_pending_tasks().await;
        self.tag_index.clear();
    }

    fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }

    fn tag_index_size(&self) -> usize {
        self.tag_index.key_count()
    }

    async fn ping(&self) -> BackendHealth {
        // In-process store is always healthy.
        BackendHealth::healthy(0)
    }

    async fn backend_info(&self) -> BackendInfo {
        BackendInfo {
            backend: "memory".to_string(),
            valkey_version: None,
            connected: true,
            nodes: vec![],
            memory_used_bytes: None,
            memory_max_bytes: None,
            memory_fragmentation_ratio: None,
            ops_per_sec: None,
            connected_clients: None,
            keyspace: std::collections::HashMap::new(),
            health: BackendHealth::healthy(0),
            circuit_breaker: "closed".to_string(),
        }
    }

    async fn tag_entry_counts(&self) -> Vec<(String, u64)> {
        self.tag_index.tag_entry_counts()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn make_response() -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: vec![],
            body: Bytes::from_static(b"hello"),
            max_age: 60,
        }
    }

    #[tokio::test]
    async fn put_and_get_roundtrip() {
        let store = MokaStore::new(8, 3600);
        assert!(store.put("k1", make_response(), 60, &[]).await);
        assert!(store.get("k1").await.is_some());
    }

    #[tokio::test]
    async fn miss_returns_none() {
        let store = MokaStore::new(8, 3600);
        assert!(store.get("missing").await.is_none());
    }

    #[tokio::test]
    async fn purge_by_tag_removes_tagged_keys() {
        let store = MokaStore::new(8, 3600);
        let tag: Arc<str> = Arc::from("catalog");
        store.put("k1", make_response(), 60, &[Arc::clone(&tag)]).await;
        store.put("k2", make_response(), 60, &[Arc::clone(&tag)]).await;
        assert_eq!(store.purge_by_tag("catalog").await, 2);
        assert!(store.get("k1").await.is_none());
    }

    #[tokio::test]
    async fn flush_clears_everything() {
        let store = MokaStore::new(8, 3600);
        store.put("k1", make_response(), 60, &[]).await;
        store.flush().await;
        assert_eq!(store.entry_count(), 0);
    }

    #[tokio::test]
    async fn purge_host_removes_only_matching() {
        let store = MokaStore::new(8, 3600);
        store.put("GET:host-a:/x", make_response(), 60, &[]).await;
        store.put("GET:host-a:/y", make_response(), 60, &[]).await;
        store.put("GET:host-b:/z", make_response(), 60, &[]).await;
        assert_eq!(store.purge_host("host-a").await, 2);
        assert!(store.get("GET:host-b:/z").await.is_some());
    }
}
