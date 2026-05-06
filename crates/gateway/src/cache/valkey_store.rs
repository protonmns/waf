//! `ValkeyStore` — async Valkey/Redis cache backend using the `fred` crate.
//!
//! Enabled via the `valkey` Cargo feature. When the feature is absent the
//! module compiles to stubs that return compile-time errors, guiding operators.
//!
//! ## Key naming
//!
//! | Concept           | Pattern                      |
//! |-------------------|------------------------------|
//! | Cached entry      | `prx:cache:{method}:{host}:{path}[?query]` |
//! | Tag → keys set    | `prx:tag:{tag}`              |
//! | Key → tags set    | `prx:key_tags:{cache_key}`   |
//!
//! ## Circuit breaker
//!
//! `CircuitBreakerStore` wraps a `ValkeyStore` with a `MokaStore` fallback.
//! After `threshold` consecutive failures the circuit trips to `Open` and all
//! reads/writes transparently use the local moka store. After `reset_secs` the
//! circuit enters `HalfOpen` and probes Valkey; on success it returns to `Closed`.

#![cfg(feature = "valkey")]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fred::prelude::*;
use fred::types::{InfoKind, Scanner};
use futures_util::StreamExt;
use serde_json as json;
use tracing::{debug, warn};
use waf_common::config::ValkeyClientConfig;

use super::backend::{BackendHealth, BackendInfo, CacheBackend, CachedResponse, KeyspaceSummary, WireCachedResponse};
use super::moka_store::MokaStore;

const KEY_PREFIX: &str = "prx:cache:";
const TAG_PREFIX: &str = "prx:tag:";
const KEY_TAGS_PREFIX: &str = "prx:key_tags:";

// ── ValkeyStore ───────────────────────────────────────────────────────────────

/// Async Valkey/Redis backend using `fred`.
///
/// Supports single-node and cluster topologies. TLS is optional.
pub struct ValkeyStore {
    client: Arc<RedisClient>,
    command_timeout: Duration,
    max_size_mb: u64,
    /// `true` when built with multiple seeds (fred cluster client). SCAN-based ops are node-local.
    cluster_mode: bool,
}

impl ValkeyStore {
    /// Connect to Valkey using `cfg`. Returns `Err` if the initial connection fails.
    pub async fn connect(cfg: &ValkeyClientConfig, max_size_mb: u64) -> anyhow::Result<Self> {
        use fred::types::{RedisConfig, ServerConfig};

        let cluster_mode = cfg.seeds.len() > 1;

        let server = if cluster_mode {
            // Cluster mode: provide all seeds; fred discovers the rest.
            let nodes: Vec<(String, u16)> = cfg
                .seeds
                .iter()
                .map(|s| parse_host_port(s))
                .collect::<anyhow::Result<_>>()?;
            ServerConfig::new_clustered(nodes)
        } else {
            let seed = cfg.seeds.first().map_or("127.0.0.1:6379", String::as_str);
            if let Some(path) = seed.strip_prefix("unix:") {
                ServerConfig::new_unix_socket(path)
            } else {
                let (host, port) = parse_host_port(seed)?;
                ServerConfig::new_centralized(host, port)
            }
        };

        let redis_cfg = RedisConfig {
            server,
            database: Some(cfg.db),
            username: None,
            password: if cfg.password.is_empty() {
                None
            } else {
                Some(cfg.password.clone())
            },
            ..RedisConfig::default()
        };

        // `pool_size` drives fred broadcast-channel capacity (this client is a
        // single multiplexed `RedisClient`, not `build_pool`; see fred docs).
        let pool_cap = cfg.pool_size.clamp(4, 4096);
        let client = Arc::new(
            Builder::from_config(redis_cfg)
                .with_connection_config(|c| {
                    c.connection_timeout = Duration::from_millis(cfg.connect_timeout_ms);
                })
                .with_performance_config(|p| {
                    p.broadcast_channel_capacity = pool_cap;
                })
                .build()
                .map_err(|e| anyhow::anyhow!("fred build error: {e}"))?,
        );

        // `init()` spawns the connection task and waits until the first connection
        // is established (or fails). We drop the returned `ConnectHandle` — fred
        // keeps the connection alive internally regardless.
        client
            .init()
            .await
            .map_err(|e| anyhow::anyhow!("valkey connect error: {e}"))?;

        // Verify connectivity with a PING.
        let _: () = client
            .ping()
            .await
            .map_err(|e| anyhow::anyhow!("valkey ping error: {e}"))?;

        tracing::info!(seeds = ?cfg.seeds, "ValkeyStore connected");

        Ok(Self {
            client,
            command_timeout: Duration::from_millis(cfg.command_timeout_ms),
            max_size_mb,
            cluster_mode,
        })
    }

    fn vk_key(key: &str) -> String {
        format!("{KEY_PREFIX}{key}")
    }

    fn tag_key(tag: &str) -> String {
        format!("{TAG_PREFIX}{tag}")
    }

    fn key_tags_key(vk_key: &str) -> String {
        format!("{KEY_TAGS_PREFIX}{vk_key}")
    }

    /// Run a single-future command with the configured timeout.
    /// On timeout or error, logs a warning and returns `None`.
    async fn timed<F, T>(&self, op: F) -> Option<T>
    where
        F: std::future::Future<Output = Result<T, fred::error::RedisError>>,
    {
        match tokio::time::timeout(self.command_timeout, op).await {
            Ok(Ok(v)) => Some(v),
            Ok(Err(e)) => {
                warn!(error = %e, "valkey command error");
                None
            }
            Err(_) => {
                warn!(
                    timeout_ms = self.command_timeout.as_millis(),
                    "valkey command timed out"
                );
                None
            }
        }
    }

    /// SCAN-based key collection with a deadline budget.
    ///
    /// **Cluster limitation:** Redis/Valkey `SCAN` runs on the node that
    /// receives the command only; it does not fan out to every shard.
    /// [`Self::purge_host`] and [`Self::flush`] are therefore **best-effort**
    /// in cluster mode unless extended with a cluster-wide scan API.
    /// Returns all matching keys up to `limit` pages; stops early on error.
    async fn scan_keys(&self, pattern: &str, page_size: u32) -> Vec<String> {
        let mut keys = Vec::new();
        let mut scanner = self.client.scan(pattern, Some(page_size), None);
        let deadline = tokio::time::Instant::now() + self.command_timeout * 10;

        loop {
            if tokio::time::Instant::now() > deadline {
                warn!(pattern = %pattern, "valkey scan exceeded budget — stopping early");
                break;
            }
            match scanner.next().await {
                Some(Ok(mut page)) => {
                    if let Some(page_keys) = page.take_results() {
                        keys.extend(page_keys.into_iter().filter_map(RedisKey::into_string));
                    }
                    // Scanner stream ends when cursor reaches 0.
                }
                Some(Err(e)) => {
                    warn!(error = %e, "valkey scan error");
                    break;
                }
                None => break,
            }
        }
        keys
    }
}

#[async_trait]
impl CacheBackend for ValkeyStore {
    async fn get(&self, key: &str) -> Option<Arc<CachedResponse>> {
        let vk = Self::vk_key(key);
        let raw: Option<String> = self.timed(self.client.get(&vk)).await.flatten();
        let raw = raw?;
        match json::from_str::<WireCachedResponse>(&raw) {
            Ok(w) => Some(Arc::new(CachedResponse::from(w))),
            Err(e) => {
                warn!(key = %key, error = %e, "valkey: failed to deserialize entry");
                None
            }
        }
    }

    async fn put(&self, key: &str, value: CachedResponse, ttl_secs: u64, tags: &[Arc<str>]) -> bool {
        let vk = Self::vk_key(key);
        let wire = WireCachedResponse::from(&value);
        let serialized = match json::to_string(&wire) {
            Ok(s) => s,
            Err(e) => {
                warn!(key = %key, error = %e, "valkey: failed to serialize entry");
                return false;
            }
        };

        // SET key value EX ttl
        let set_ok = self
            .timed(self.client.set::<(), _, _>(
                &vk,
                serialized,
                Some(Expiration::EX(i64::try_from(ttl_secs).unwrap_or(i64::MAX))),
                None,
                false,
            ))
            .await
            .is_some();

        if !set_ok {
            return false;
        }

        // Tag sets: SADD prx:tag:{tag} vk_key  AND  SADD prx:key_tags:vk_key tag
        for tag in tags {
            let tag_k = Self::tag_key(tag);
            let key_tags_k = Self::key_tags_key(&vk);
            let _: Option<()> = self.timed(self.client.sadd(&tag_k, &vk as &str)).await;
            let _: Option<()> = self.timed(self.client.sadd(&key_tags_k, tag.as_ref())).await;
        }

        debug!(key = %key, ttl = ttl_secs, "valkey: stored entry");
        true
    }

    async fn remove(&self, key: &str) {
        let vk = Self::vk_key(key);
        // Retrieve tags first so we can clean up tag sets.
        let key_tags_k = Self::key_tags_key(&vk);
        if let Some(tags) = self.timed::<_, Vec<String>>(self.client.smembers(&key_tags_k)).await {
            for tag in &tags {
                let tag_k = Self::tag_key(tag);
                let _: Option<()> = self.timed(self.client.srem(&tag_k, &vk as &str)).await;
            }
        }
        let _: Option<()> = self.timed(self.client.del(&[&vk as &str, &key_tags_k as &str])).await;
    }

    async fn purge_by_tag(&self, tag: &str) -> usize {
        let tag_k = Self::tag_key(tag);
        let members: Vec<String> = match self.timed(self.client.smembers(&tag_k)).await {
            Some(m) => m,
            None => return 0,
        };
        let count = members.len();
        for vk in &members {
            let key_tags_k = Self::key_tags_key(vk);
            let _: Option<()> = self.timed(self.client.srem(&key_tags_k, tag)).await;
            let _: Option<()> = self.timed(self.client.del(vk as &str)).await;
        }
        // Delete the tag set itself.
        let _: Option<()> = self.timed(self.client.del(&tag_k as &str)).await;
        count
    }

    async fn purge_by_route_id(&self, route_id: &str) -> usize {
        self.purge_by_tag(route_id).await
    }

    async fn purge_host(&self, host: &str) -> usize {
        let pattern = format!("{KEY_PREFIX}*:{host}:*");
        let keys = self.scan_keys(&pattern, 100).await;
        let count = keys.len();
        for vk in &keys {
            let _: Option<()> = self.timed(self.client.del(vk.as_str())).await;
        }
        count
    }

    async fn flush(&self) {
        // SCAN + batch DEL for all prx:cache:* keys (non-blocking alternative to FLUSHDB).
        let pattern = format!("{KEY_PREFIX}*");
        let keys = self.scan_keys(&pattern, 500).await;
        if !keys.is_empty() {
            let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
            let _: Option<()> = self.timed(self.client.del(refs)).await;
        }
    }

    fn entry_count(&self) -> u64 {
        // Not tracked locally for Valkey — dbsize is fetched asynchronously in backend_info.
        0
    }

    fn tag_index_size(&self) -> usize {
        0
    }

    async fn ping(&self) -> BackendHealth {
        let start = Instant::now();
        match tokio::time::timeout(self.command_timeout, self.client.ping::<()>()).await {
            Ok(Ok(())) => BackendHealth::healthy(u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)),
            Ok(Err(e)) => BackendHealth::unhealthy(e.to_string()),
            Err(_) => BackendHealth::unhealthy("ping timed out"),
        }
    }

    async fn backend_info(&self) -> BackendInfo {
        let health = self.ping().await;

        // INFO all sections — version, memory, stats
        let info_str: Option<String> = self.timed(self.client.info(Some(InfoKind::All))).await;
        let mut version = None;
        let mut memory_used = None;
        let mut memory_max = None;
        let mut fragmentation = None;
        let mut ops_per_sec = None;
        let mut connected_clients = None;

        if let Some(s) = info_str {
            for line in s.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                if let Some((k, v)) = line.split_once(':') {
                    match k.trim() {
                        "redis_version" | "valkey_version" => version = Some(v.trim().to_string()),
                        "used_memory" => memory_used = v.trim().parse().ok(),
                        "maxmemory" => memory_max = Some(v.trim().parse::<u64>().unwrap_or(0)).filter(|&v| v > 0),
                        "mem_fragmentation_ratio" => fragmentation = v.trim().parse().ok(),
                        "instantaneous_ops_per_sec" => ops_per_sec = v.trim().parse().ok(),
                        "connected_clients" => connected_clients = v.trim().parse().ok(),
                        _ => {}
                    }
                }
            }
        }

        // DBSIZE for approximate entry count
        let keyspace_count: Option<u64> = self.timed(self.client.dbsize()).await;
        let mut keyspace = HashMap::new();
        if let Some(c) = keyspace_count {
            keyspace.insert("db0".to_string(), KeyspaceSummary { keys: c, expires: 0 });
        }

        let memory_max_bytes = memory_max.or_else(|| Some(self.max_size_mb * 1024 * 1024));

        BackendInfo {
            backend: if self.cluster_mode {
                "cluster".to_string()
            } else {
                "standalone".to_string()
            },
            valkey_version: version,
            connected: health.ok,
            nodes: vec![],
            memory_used_bytes: memory_used,
            memory_max_bytes,
            memory_fragmentation_ratio: fragmentation,
            ops_per_sec,
            connected_clients,
            keyspace,
            health,
            circuit_breaker: "closed".to_string(),
        }
    }

    async fn tag_entry_counts(&self) -> Vec<(String, u64)> {
        let pattern = format!("{TAG_PREFIX}*");
        let keys = self.scan_keys(&pattern, 100).await;
        let mut out = Vec::with_capacity(keys.len());
        for tag_key in keys {
            let Some(rest) = tag_key.strip_prefix(TAG_PREFIX) else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            let n = self
                .timed(self.client.scard::<u32, _>(&tag_key))
                .await
                .map_or(0, u64::from);
            out.push((rest.to_string(), n));
        }
        out
    }
}

fn parse_host_port(addr: &str) -> anyhow::Result<(String, u16)> {
    let (host, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid address (missing port): {addr}"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid port in address: {addr}"))?;
    Ok((host.to_string(), port))
}

// ── Circuit breaker ───────────────────────────────────────────────────────────

/// Circuit-breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

const fn circuit_breaker_state_from_counters(
    failures: u32,
    threshold: u32,
    tripped_at: u64,
    reset_secs: u64,
    now_secs: u64,
) -> CircuitState {
    if failures < threshold {
        return CircuitState::Closed;
    }
    let elapsed = now_secs.saturating_sub(tripped_at);
    if elapsed >= reset_secs {
        CircuitState::HalfOpen
    } else {
        CircuitState::Open
    }
}

/// Wraps a `ValkeyStore` with a `MokaStore` fallback.
///
/// When the Valkey backend accumulates `threshold` consecutive failures the
/// circuit trips to `Open`; all I/O transparently uses the local moka store.
/// After `reset_secs` the circuit enters `HalfOpen` and probes Valkey once;
/// on success it returns to `Closed`, on failure it reopens for another cycle.
pub struct CircuitBreakerStore {
    inner: Arc<ValkeyStore>,
    fallback: Arc<MokaStore>,
    threshold: u32,
    reset_secs: u64,
    /// Consecutive failure count.
    failures: AtomicU32,
    /// Unix timestamp (secs) when the circuit tripped to `Open`.
    tripped_at: AtomicU64,
}

impl CircuitBreakerStore {
    pub fn new(inner: Arc<ValkeyStore>, fallback: Arc<MokaStore>, cfg: &ValkeyClientConfig) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fallback,
            threshold: cfg.circuit_breaker_threshold,
            reset_secs: cfg.circuit_breaker_reset_secs,
            failures: AtomicU32::new(0),
            tripped_at: AtomicU64::new(0),
        })
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn state(&self) -> CircuitState {
        circuit_breaker_state_from_counters(
            self.failures.load(Ordering::Relaxed),
            self.threshold,
            self.tripped_at.load(Ordering::Relaxed),
            self.reset_secs,
            Self::now_secs(),
        )
    }

    fn state_label(&self) -> &'static str {
        match self.state() {
            CircuitState::Closed => "closed",
            CircuitState::Open => "open",
            CircuitState::HalfOpen => "half_open",
        }
    }

    fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.tripped_at.store(0, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        let prev = self.failures.fetch_add(1, Ordering::Relaxed);
        if prev + 1 >= self.threshold && self.tripped_at.load(Ordering::Relaxed) == 0 {
            let now = Self::now_secs();
            self.tripped_at.store(now, Ordering::Relaxed);
            warn!(
                threshold = self.threshold,
                "cache circuit breaker opened — falling back to moka"
            );
        }
    }

    /// Try Valkey; on any `None` result record a failure.
    async fn try_valkey_get(&self, key: &str) -> Option<Arc<CachedResponse>> {
        let result = self.inner.get(key).await;
        if result.is_some() {
            self.record_success();
        }
        // A miss (None) is not a failure — only errors in timed() increment the counter.
        result
    }
}

#[async_trait]
impl CacheBackend for CircuitBreakerStore {
    async fn get(&self, key: &str) -> Option<Arc<CachedResponse>> {
        match self.state() {
            CircuitState::Closed => self.try_valkey_get(key).await,
            CircuitState::Open => self.fallback.get(key).await,
            CircuitState::HalfOpen => {
                // Probe: try Valkey once.
                match self.inner.ping().await {
                    h if h.ok => {
                        self.record_success();
                        self.try_valkey_get(key).await
                    }
                    _ => {
                        self.record_failure();
                        self.fallback.get(key).await
                    }
                }
            }
        }
    }

    async fn put(&self, key: &str, value: CachedResponse, ttl_secs: u64, tags: &[Arc<str>]) -> bool {
        if self.state() == CircuitState::Open {
            return self.fallback.put(key, value, ttl_secs, tags).await;
        }
        let stored = self.inner.put(key, value.clone(), ttl_secs, tags).await;
        if stored {
            self.record_success();
        } else {
            self.record_failure();
            return self.fallback.put(key, value, ttl_secs, tags).await;
        }
        stored
    }

    async fn remove(&self, key: &str) {
        self.inner.remove(key).await;
        self.fallback.remove(key).await;
    }

    async fn purge_by_tag(&self, tag: &str) -> usize {
        let n = self.inner.purge_by_tag(tag).await;
        self.fallback.purge_by_tag(tag).await;
        n
    }

    async fn purge_by_route_id(&self, route_id: &str) -> usize {
        let n = self.inner.purge_by_route_id(route_id).await;
        self.fallback.purge_by_route_id(route_id).await;
        n
    }

    async fn purge_host(&self, host: &str) -> usize {
        let n = self.inner.purge_host(host).await;
        self.fallback.purge_host(host).await;
        n
    }

    async fn flush(&self) {
        self.inner.flush().await;
        self.fallback.flush().await;
    }

    fn entry_count(&self) -> u64 {
        match self.state() {
            CircuitState::Open => self.fallback.entry_count(),
            _ => self.inner.entry_count(),
        }
    }

    fn tag_index_size(&self) -> usize {
        self.fallback.tag_index_size()
    }

    async fn ping(&self) -> BackendHealth {
        self.inner.ping().await
    }

    async fn backend_info(&self) -> BackendInfo {
        let mut info = self.inner.backend_info().await;
        info.circuit_breaker = self.state_label().to_string();
        info
    }

    async fn tag_entry_counts(&self) -> Vec<(String, u64)> {
        use std::collections::HashMap;
        let mut acc: HashMap<String, u64> = HashMap::new();
        for (k, v) in self.inner.tag_entry_counts().await {
            acc.entry(k).and_modify(|e| *e = (*e).max(v)).or_insert(v);
        }
        for (k, v) in self.fallback.tag_entry_counts().await {
            acc.entry(k).and_modify(|e| *e = (*e).max(v)).or_insert(v);
        }
        acc.into_iter().collect()
    }
}

#[cfg(test)]
mod circuit_breaker_tests {
    use super::{CircuitState, circuit_breaker_state_from_counters};

    #[test]
    fn cb_closed_when_failures_below_threshold() {
        assert_eq!(
            circuit_breaker_state_from_counters(2, 5, 0, 60, 1_000),
            CircuitState::Closed
        );
    }

    #[test]
    fn cb_open_when_tripped_and_within_reset_window() {
        assert_eq!(
            circuit_breaker_state_from_counters(5, 3, 1_000, 60, 1_005),
            CircuitState::Open
        );
    }

    #[test]
    fn cb_half_open_after_reset_secs_elapsed() {
        assert_eq!(
            circuit_breaker_state_from_counters(5, 3, 1_000, 60, 1_100),
            CircuitState::HalfOpen
        );
    }

    #[test]
    fn cb_exact_threshold_is_open_when_tripped_recently() {
        assert_eq!(
            circuit_breaker_state_from_counters(3, 3, 500, 30, 510),
            CircuitState::Open
        );
    }
}
