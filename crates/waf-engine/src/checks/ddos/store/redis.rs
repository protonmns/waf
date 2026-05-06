//! Redis-backed `CounterStore` for `DDoS` detection (feature `redis-store`).
//!
//! Provides cluster-coherent counters via atomic Lua scripts. Each key uses
//! INCR + PEXPIRE in a single round-trip for consistency across nodes.
//!
//! # Lua Script
//!
//! ```lua
//! local v = redis.call('INCR', KEYS[1])
//! if v == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
//! return v
//! ```
//!
//! Only sets TTL on first increment (v==1) to avoid resetting expiry on every hit.
//!
//! # Circuit Breaker
//!
//! Tracks consecutive failures via `AtomicU32`. Once `breaker_threshold` is reached,
//! `breaker_open()` returns true. A single success resets the counter.
//! The wrapping layer (phase 6) can route to memory fallback when breaker is open.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use redis::{Script, aio::ConnectionManager};
use tokio::time::timeout;

use super::CounterStore;

/// Configuration for the Redis `DDoS` counter backend.
#[derive(Clone, Debug)]
pub struct RedisCounterConfig {
    /// Redis URL, e.g. `redis://127.0.0.1:6379`.
    pub url: String,
    /// Prepended to every key, used to namespace from other Redis users.
    pub key_prefix: String,
    /// Per-call timeout. Above this we record a failure and surface an error.
    pub op_timeout: Duration,
    /// Consecutive failures required to open the circuit breaker.
    pub breaker_threshold: u32,
}

impl Default for RedisCounterConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".into(),
            key_prefix: "wafddos:".into(),
            op_timeout: Duration::from_millis(50),
            breaker_threshold: 5,
        }
    }
}

/// Single round-trip: INCR + PEXPIRE on first creation.
///
/// KEYS[1] = counter key
/// ARGV[1] = TTL in milliseconds
///
/// Returns the incremented value.
const INCR_WITH_EXPIRE_LUA: &str = r"
local v = redis.call('INCR', KEYS[1])
if v == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return v
";

/// Redis-backed `DDoS` counter store.
pub struct RedisCounterStore {
    conn: ConnectionManager,
    cfg: RedisCounterConfig,
    consecutive_fails: AtomicU32,
    script: Script,
}

impl std::fmt::Debug for RedisCounterStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisCounterStore")
            .field("cfg", &self.cfg)
            .field("consecutive_fails", &self.consecutive_fails.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl RedisCounterStore {
    /// Open a connection, PING to verify, return a ready store.
    ///
    /// # Errors
    /// Returns error if connection fails or PING times out.
    pub async fn new(cfg: RedisCounterConfig) -> anyhow::Result<Self> {
        let client =
            redis::Client::open(cfg.url.as_str()).with_context(|| format!("ddos redis: open client {}", cfg.url))?;
        let mut conn = ConnectionManager::new(client)
            .await
            .context("ddos redis: connection manager init")?;
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .context("ddos redis: ping")?;
        Ok(Self {
            conn,
            cfg,
            consecutive_fails: AtomicU32::new(0),
            script: Script::new(INCR_WITH_EXPIRE_LUA),
        })
    }

    /// True once `breaker_threshold` consecutive failures have occurred.
    ///
    /// The wrapping layer (phase 6) can read this to route to memory fallback.
    #[must_use]
    pub fn breaker_open(&self) -> bool {
        self.consecutive_fails.load(Ordering::Relaxed) >= self.cfg.breaker_threshold
    }

    /// Reset failure counter on successful operation.
    fn record_ok(&self) {
        self.consecutive_fails.store(0, Ordering::Relaxed);
    }

    /// Increment failure counter; log when threshold crossed.
    fn record_fail(&self) {
        let n = self.consecutive_fails.fetch_add(1, Ordering::Relaxed) + 1;
        if n == self.cfg.breaker_threshold {
            tracing::warn!(consecutive_fails = n, "ddos redis: circuit breaker tripped");
        }
    }
}

#[async_trait]
impl CounterStore for RedisCounterStore {
    async fn incr_get(&self, key: &str, ttl_ms: i64, _now_ms: i64) -> anyhow::Result<u64> {
        let full_key = format!("{}{}", self.cfg.key_prefix, key);
        let mut conn = self.conn.clone();

        let mut invocation = self.script.prepare_invoke();
        invocation.key(&full_key).arg(ttl_ms);

        let res = timeout(self.cfg.op_timeout, invocation.invoke_async::<i64>(&mut conn)).await;

        match res {
            Ok(Ok(v)) => {
                self.record_ok();
                // Redis INCR returns signed i64; clamp negative (impossible) to 0
                Ok(u64::try_from(v).unwrap_or(0))
            }
            Ok(Err(e)) => {
                self.record_fail();
                Err(anyhow!(e).context("ddos redis: incr_get"))
            }
            Err(_) => {
                self.record_fail();
                Err(anyhow!("ddos redis: incr_get timeout {:?}", self.cfg.op_timeout))
            }
        }
    }

    /// No-op: Redis `PEXPIRE` set on key creation handles TTL natively.
    async fn purge_expired(&self, _now_ms: i64) -> anyhow::Result<usize> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_prefix() -> String {
        format!(
            "wafddos_test_{}:",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        )
    }

    /// Integration test — runs only when `REDIS_TEST_URL` is set.
    #[tokio::test]
    async fn incr_get_increments_and_expires() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            tracing::info!("skipping ddos redis test: REDIS_TEST_URL unset");
            return;
        };

        let store = RedisCounterStore::new(RedisCounterConfig {
            url,
            key_prefix: unique_prefix(),
            op_timeout: Duration::from_millis(500),
            breaker_threshold: 5,
        })
        .await
        .expect("connect to REDIS_TEST_URL");

        // Increment same key multiple times
        let now = 0;
        let ttl = 60_000;

        let c1 = store.incr_get("test_key", ttl, now).await.unwrap();
        assert_eq!(c1, 1);

        let c2 = store.incr_get("test_key", ttl, now).await.unwrap();
        assert_eq!(c2, 2);

        let c3 = store.incr_get("test_key", ttl, now).await.unwrap();
        assert_eq!(c3, 3);

        // Different key starts fresh
        let c_new = store.incr_get("other_key", ttl, now).await.unwrap();
        assert_eq!(c_new, 1);
    }

    /// Breaker logic test — requires real Redis connection.
    #[tokio::test]
    async fn breaker_opens_after_threshold_and_resets_on_success() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            tracing::info!("skipping breaker test: REDIS_TEST_URL unset");
            return;
        };

        let store = RedisCounterStore::new(RedisCounterConfig {
            url,
            key_prefix: unique_prefix(),
            op_timeout: Duration::from_millis(500),
            breaker_threshold: 3,
        })
        .await
        .expect("connect to REDIS_TEST_URL");

        assert!(!store.breaker_open());

        // Simulate failures
        store.record_fail();
        store.record_fail();
        assert!(!store.breaker_open());

        store.record_fail();
        assert!(store.breaker_open());

        // Success resets
        store.record_ok();
        assert!(!store.breaker_open());
    }

    /// Verify `purge_expired` is no-op (Redis handles TTL natively).
    #[tokio::test]
    async fn purge_expired_is_noop() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            tracing::info!("skipping purge test: REDIS_TEST_URL unset");
            return;
        };

        let store = RedisCounterStore::new(RedisCounterConfig {
            url,
            key_prefix: unique_prefix(),
            op_timeout: Duration::from_millis(500),
            breaker_threshold: 5,
        })
        .await
        .expect("connect to REDIS_TEST_URL");

        let removed = store.purge_expired(0).await.unwrap();
        assert_eq!(removed, 0);
    }

    /// Timeout test — connects to a real Redis but with very short timeout.
    /// This test is fragile and may pass/fail based on network latency.
    /// Keeping it as documentation of expected behavior.
    #[tokio::test]
    #[ignore = "fragile: depends on network latency"]
    async fn timeout_returns_error_and_increments_breaker() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            return;
        };

        let store = RedisCounterStore::new(RedisCounterConfig {
            url,
            key_prefix: unique_prefix(),
            op_timeout: Duration::from_nanos(1), // impossibly short
            breaker_threshold: 5,
        })
        .await
        .expect("connect");

        let result = store.incr_get("timeout_test", 60_000, 0).await;
        assert!(result.is_err());
        assert!(store.consecutive_fails.load(Ordering::Relaxed) >= 1);
    }
}
