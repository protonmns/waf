//! `CounterStore` trait for `DDoS` counter backends.
//!
//! Backends (in-memory, Redis, …) implement this trait. The pipeline
//! consumes only the trait — no backend knowledge leaks upward.

use async_trait::async_trait;

pub mod memory;
pub use memory::MemoryCounterStore;

#[cfg(feature = "redis-store")]
pub mod redis;
#[cfg(feature = "redis-store")]
pub use redis::{RedisCounterConfig, RedisCounterStore};

/// Atomic `DDoS` counter operations on a keyed counter.
///
/// Each key represents a fingerprint (e.g., IP) or aggregate (e.g., tier).
/// Counters auto-expire after `ttl_ms` from last increment.
#[async_trait]
pub trait CounterStore: Send + Sync {
    /// Atomically increment the counter for `key` and return the new count.
    ///
    /// If the key doesn't exist or has expired, it's created with count=1.
    /// The TTL is reset on each increment.
    async fn incr_get(&self, key: &str, ttl_ms: i64, now_ms: i64) -> anyhow::Result<u64>;

    /// Synchronous entry point used by the sync `Check` pipeline.
    ///
    /// Default impl bridges to `incr_get` via `block_in_place` +
    /// `Handle::block_on`. Backends with a fully synchronous internal path
    /// (e.g. `MemoryCounterStore`) override this to skip the bridge.
    fn incr_get_blocking(&self, key: &str, ttl_ms: i64, now_ms: i64) -> anyhow::Result<u64> {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(self.incr_get(key, ttl_ms, now_ms)))
    }

    /// Sweep expired entries. Returns count purged.
    ///
    /// Called periodically by GC task. Implementations with native TTL
    /// (e.g., Redis `EXPIRE`) may no-op here.
    async fn purge_expired(&self, now_ms: i64) -> anyhow::Result<usize>;
}
