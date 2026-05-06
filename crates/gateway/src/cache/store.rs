//! `ResponseCache` — facade that wires the Chain-of-Responsibility resolver
//! pipeline to a pluggable [`CacheBackend`] storage implementation.
//!
//! ## Architecture
//!
//! ```text
//! ResponseCache (resolver + bypass stats)
//!     │
//!     └─ Arc<dyn CacheBackend>
//!            ├─ MokaStore     (backend = "memory", default)
//!            ├─ ValkeyStore   (backend = "standalone" / "cluster")
//!            ├─ EmbeddedValkey → ValkeyStore  (backend = "embedded")
//!            └─ CircuitBreakerStore  (wraps ValkeyStore, fallback to MokaStore)
//! ```
//!
//! The resolver pipeline (`TierGate → MethodGate → AuthGate → RouteRuleGate →
//! UpstreamCcGate → TierDefaultGate`) and all bypass counters live here.
//! Storage hits/misses are tracked at this layer too so the same counters work
//! regardless of which backend is active.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;
use tracing::{debug, trace};
use waf_common::tier::{CachePolicy, Tier};

use super::backend::{BackendHealth, BackendInfo, CacheBackend, CachedResponse};
use super::gates::{AuthGate, MethodGate, RouteRuleGate, TierDefaultGate, TierGate, UpstreamCcGate};
use super::moka_store::MokaStore;
use super::policy::{CacheCtx, CachePolicyResolver, Verdict};
use super::rule_set::{CompiledRuleSet, RuleSetHolder};
use super::stats::{CacheStats, CacheStatsSnapshot, RouteStats, TimeseriesBucket};

fn parse_cache_key(key: &str) -> Option<(&str, &str, &str)> {
    let main = key.split_once('?').map_or(key, |(a, _)| a);
    let mut parts = main.splitn(3, ':');
    let method = parts.next()?;
    let host = parts.next()?;
    let path = parts.next()?;
    Some((method, host, path))
}

/// Cache [`BackendInfo`] for the stats dashboard poll interval (avoids Valkey `INFO` on every request).
const STATS_BACKEND_INFO_TTL: Duration = Duration::from_secs(10);

/// Shared response cache.
///
/// Holds the resolver pipeline and bypass counters. All storage operations
/// delegate to the inner `backend` implementation.
pub struct ResponseCache {
    backend: Arc<dyn CacheBackend>,
    stats: Arc<CacheStats>,
    rules: Arc<RuleSetHolder>,
    default_ttl: Duration,
    max_ttl: Duration,
    resolver: CachePolicyResolver,
    stats_backend_info_cache: Mutex<Option<(BackendInfo, Instant)>>,
}

impl ResponseCache {
    /// Create a memory-backed cache (moka LRU, no external process).
    ///
    /// Shorthand for `with_rules` with an empty rule set — suitable for tests
    /// and deployments that do not need per-route TTL rules.
    pub fn new(max_size_mb: u64, default_ttl_secs: u64, max_ttl_secs: u64) -> Arc<Self> {
        Self::with_rules(
            max_size_mb,
            default_ttl_secs,
            max_ttl_secs,
            RuleSetHolder::new(CompiledRuleSet::empty()),
        )
    }

    /// Build a memory-backed cache with a hot-swappable rule set.
    ///
    /// Resolver order: `TierGate → MethodGate → AuthGate → RouteRule →
    /// UpstreamCcGate → TierDefaultGate`. FR-009 Phase 3.
    pub fn with_rules(
        max_size_mb: u64,
        default_ttl_secs: u64,
        max_ttl_secs: u64,
        rules: Arc<RuleSetHolder>,
    ) -> Arc<Self> {
        let backend = Arc::new(MokaStore::new(max_size_mb, max_ttl_secs));
        Self::with_backend(backend, max_size_mb, default_ttl_secs, max_ttl_secs, rules)
    }

    /// Build a cache with an explicit [`CacheBackend`] and a rule set.
    ///
    /// Used when the operator selects `embedded`, `standalone`, or `cluster`.
    pub fn with_backend(
        backend: Arc<dyn CacheBackend>,
        _max_size_mb: u64,
        default_ttl_secs: u64,
        max_ttl_secs: u64,
        rules: Arc<RuleSetHolder>,
    ) -> Arc<Self> {
        let resolver = CachePolicyResolver::new(vec![
            Box::new(TierGate),
            Box::new(MethodGate),
            Box::new(AuthGate),
            Box::new(RouteRuleGate::new(Arc::clone(&rules))),
            Box::new(UpstreamCcGate),
            Box::new(TierDefaultGate),
        ]);

        Arc::new(Self {
            backend,
            stats: Arc::new(CacheStats::default()),
            rules,
            default_ttl: Duration::from_secs(default_ttl_secs),
            max_ttl: Duration::from_secs(max_ttl_secs),
            resolver,
            stats_backend_info_cache: Mutex::new(None),
        })
    }

    // ── Public key helper ────────────────────────────────────────────────────

    /// Build the cache key for a request.
    pub fn make_key(method: &str, host: &str, path: &str, query: &str) -> String {
        if query.is_empty() {
            format!("{method}:{host}:{path}")
        } else {
            format!("{method}:{host}:{path}?{query}")
        }
    }

    // ── Read path ────────────────────────────────────────────────────────────

    /// Look up a cached response. Returns `None` on miss or on tier bypass.
    ///
    /// Symmetric tier gate (FR-009 AC-1): CRITICAL-tier requests are never
    /// served a cached entry even if one was stored before reclassification.
    pub async fn get(&self, key: &str, tier: Tier) -> Option<Arc<CachedResponse>> {
        let route_label = parse_cache_key(key).and_then(|(method, host, path)| {
            self.rules
                .load()
                .first_cacheable_rule_id(host, path, method)
                .map(|s| s.as_ref().to_string())
        });
        if matches!(tier, Tier::Critical) {
            self.stats.bypassed_critical.fetch_add(1, Ordering::Relaxed);
            trace!(key = %key, "cache bypass: CRITICAL tier");
            return None;
        }
        let result = self.backend.get(key).await;
        if let Some(ref label) = route_label {
            if result.is_some() {
                self.stats.record_route_hit(label);
            } else {
                self.stats.record_route_miss(label);
            }
        }
        if result.is_some() {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            trace!(key = %key, "cache hit");
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            trace!(key = %key, "cache miss");
        }
        result
    }

    // ── Write path ───────────────────────────────────────────────────────────

    /// Store a response. Decision is delegated to `CachePolicyResolver`.
    /// Returns `false` if any gate bypassed.
    #[allow(clippy::too_many_arguments)]
    pub async fn put(
        &self,
        key: String,
        host: &str,
        path: &str,
        status: u16,
        headers: Vec<(String, String)>,
        body: Bytes,
        cache_control: Option<&str>,
        tier: Tier,
        policy: &CachePolicy,
        has_authorization: bool,
        has_cookie: bool,
    ) -> bool {
        let method = key.split(':').next().unwrap_or("");
        let ctx = CacheCtx {
            tier,
            method,
            host,
            path,
            status,
            headers: &headers,
            cache_control,
            policy,
            max_ttl_secs: self.max_ttl.as_secs(),
            default_ttl_secs: self.default_ttl.as_secs(),
            has_authorization,
            has_cookie,
        };

        match self.resolver.resolve(&ctx) {
            Verdict::Bypass(reason) => {
                self.stats.record_bypass(reason);
                debug!(key = %key, ?reason, "cache bypass");
                false
            }
            Verdict::Cache { ttl, tags } => {
                let entry = CachedResponse {
                    status,
                    headers,
                    body,
                    max_age: ttl.as_secs(),
                };
                let stored = self.backend.put(&key, entry, ttl.as_secs(), &tags).await;
                if stored {
                    self.stats.stores.fetch_add(1, Ordering::Relaxed);
                }
                stored
            }
            Verdict::Continue => false,
        }
    }

    // ── Purge / invalidation ─────────────────────────────────────────────────

    /// Invalidate all entries for a given host.
    pub async fn purge_host(&self, host: &str) {
        let _ = self.backend.purge_host(host).await;
    }

    /// Invalidate a single cache key.
    pub async fn purge_key(&self, key: &str) {
        self.backend.remove(key).await;
    }

    /// Flush the entire cache.
    pub async fn flush(&self) {
        self.backend.flush().await;
    }

    /// FR-009 Phase 4: purge every entry tagged with `tag`. Returns count purged.
    pub async fn purge_by_tag(&self, tag: &str) -> usize {
        let n = self.backend.purge_by_tag(tag).await;
        self.stats.purges_tag.fetch_add(n as u64, Ordering::Relaxed);
        n
    }

    /// FR-009 Phase 4: purge every entry cached by the rule with this `id`.
    pub async fn purge_by_route_id(&self, route_id: &str) -> usize {
        let n = self.backend.purge_by_route_id(route_id).await;
        self.stats.purges_route.fetch_add(n as u64, Ordering::Relaxed);
        n
    }

    // ── Gauges / stats ───────────────────────────────────────────────────────

    /// FR-009 Phase 4: number of distinct keys currently tracked by the tag index.
    pub fn tag_index_size(&self) -> usize {
        self.backend.tag_index_size()
    }

    /// Return current request-level statistics.
    pub fn stats(&self) -> CacheStatsSnapshot {
        self.stats.snapshot()
    }

    /// Approximate entry count.
    pub fn entry_count(&self) -> u64 {
        self.backend.entry_count()
    }

    /// Return timeseries data points (up to `minutes`, capped at 60).
    pub fn timeseries(&self, minutes: usize) -> Vec<TimeseriesBucket> {
        self.stats.timeseries(minutes)
    }

    /// Tick the 1-minute timeseries bucket. Call from a background task.
    pub async fn tick_timeseries(&self) {
        let info = self.backend.backend_info().await;
        let mem = info.memory_used_bytes.unwrap_or(0);
        self.stats.tick_timeseries(mem);
    }

    /// Probe the backend and return a health snapshot.
    pub async fn ping(&self) -> BackendHealth {
        self.backend.ping().await
    }

    /// Return backend info for the `/api/cache/backend` endpoint.
    pub async fn backend_info(&self) -> BackendInfo {
        self.backend.backend_info().await
    }

    /// Freshness-trades-off copy of [`Self::backend_info`] for endpoints polled frequently (e.g. stats KPIs).
    pub async fn backend_info_for_stats_panel(&self) -> BackendInfo {
        let now = Instant::now();
        {
            let guard = self.stats_backend_info_cache.lock();
            #[allow(clippy::collapsible_if)] // nested form avoids depending on `let_chains`
            if let Some((info, at)) = guard.as_ref() {
                if now.duration_since(*at) < STATS_BACKEND_INFO_TTL {
                    return info.clone();
                }
            }
        }
        let info = self.backend.backend_info().await;
        *self.stats_backend_info_cache.lock() = Some((info.clone(), now));
        info
    }

    /// Per-tag entry counts from the active storage backend (memory tag index or Valkey `SCAN`).
    pub async fn tag_entry_counts(&self) -> Vec<(String, u64)> {
        self.backend.tag_entry_counts().await
    }

    /// Return top cached routes by hits. `limit` caps the result count.
    ///
    /// Merges per-tag entry counts from the active backend with in-process
    /// hit/miss counters keyed by rule id (or `"_default"`).
    pub async fn top_routes(&self, limit: usize) -> Vec<RouteStats> {
        let tag_map: HashMap<String, u64> = self.backend.tag_entry_counts().await.into_iter().collect();
        let traffic = self.stats.route_traffic_snapshot();
        let mut route_ids: HashSet<String> = tag_map.keys().cloned().collect();
        for k in traffic.keys() {
            route_ids.insert(k.clone());
        }
        let mut rows: Vec<RouteStats> = route_ids
            .into_iter()
            .map(|id| {
                let entry_count = *tag_map.get(&id).unwrap_or(&0);
                let (hits, misses) = traffic.get(&id).copied().unwrap_or((0, 0));
                RouteStats {
                    route_id: id,
                    hits,
                    misses,
                    entry_count,
                }
            })
            .collect();
        rows.sort_by(|a, b| {
            b.hits
                .cmp(&a.hits)
                .then_with(|| b.entry_count.cmp(&a.entry_count))
                .then_with(|| a.route_id.cmp(&b.route_id))
        });
        rows.truncate(limit);
        rows
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> Arc<ResponseCache> {
        ResponseCache::new(8, 60, 3600)
    }

    fn key() -> String {
        "GET:h:/p".to_string()
    }

    async fn put_basic(
        c: &ResponseCache,
        headers: Vec<(String, String)>,
        cc: Option<&str>,
        tier: Tier,
        policy: &CachePolicy,
    ) -> bool {
        c.put(
            key(),
            "h",
            "/p",
            200,
            headers,
            Bytes::from("ok"),
            cc,
            tier,
            policy,
            false,
            false,
        )
        .await
    }

    #[tokio::test]
    async fn critical_tier_bypasses_put_even_with_max_age() {
        let c = cache();
        let stored = put_basic(
            &c,
            vec![],
            Some("max-age=3600"),
            Tier::Critical,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
        )
        .await;
        assert!(!stored, "CRITICAL must never cache");
        assert_eq!(c.stats().bypassed_critical, 1);
        assert_eq!(c.stats().stores, 0);
    }

    #[tokio::test]
    async fn critical_tier_bypasses_get_even_for_existing_key() {
        let c = cache();
        let stored = put_basic(
            &c,
            vec![],
            Some("max-age=60"),
            Tier::Medium,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
        )
        .await;
        assert!(stored);
        let r = c.get(&key(), Tier::Critical).await;
        assert!(r.is_none());
        assert!(c.stats().bypassed_critical >= 1);
    }

    #[tokio::test]
    async fn no_cache_policy_bypasses_regardless_of_tier() {
        let c = cache();
        let stored = put_basic(&c, vec![], Some("max-age=600"), Tier::Medium, &CachePolicy::NoCache).await;
        assert!(!stored);
        assert_eq!(c.stats().bypassed_critical, 1);
    }

    #[tokio::test]
    async fn aggressive_caps_upstream_max_age_above_ceiling() {
        let c = cache();
        put_basic(
            &c,
            vec![],
            Some("max-age=10000"),
            Tier::Medium,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
        )
        .await;
        let entry = c.get(&key(), Tier::Medium).await.expect("present");
        assert_eq!(entry.max_age, 300, "must cap to policy ceiling");
    }

    #[tokio::test]
    async fn aggressive_uses_policy_default_when_upstream_silent() {
        let c = cache();
        put_basic(
            &c,
            vec![],
            None,
            Tier::Medium,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
        )
        .await;
        let entry = c.get(&key(), Tier::Medium).await.expect("present");
        assert_eq!(entry.max_age, 300);
    }

    #[tokio::test]
    async fn short_ttl_caps_upstream_below_ceiling_unchanged() {
        let c = cache();
        put_basic(
            &c,
            vec![],
            Some("max-age=30"),
            Tier::Medium,
            &CachePolicy::ShortTtl { ttl_seconds: 120 },
        )
        .await;
        let entry = c.get(&key(), Tier::Medium).await.expect("present");
        assert_eq!(entry.max_age, 30, "below ceiling stays as-is");
    }

    #[tokio::test]
    async fn set_cookie_response_bypasses_cache() {
        let c = cache();
        let stored = put_basic(
            &c,
            vec![("Set-Cookie".into(), "sid=abc".into())],
            Some("max-age=600"),
            Tier::Medium,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
        )
        .await;
        assert!(!stored);
        assert_eq!(c.stats().bypassed_critical, 0);
    }

    #[tokio::test]
    async fn auth_request_bypasses_via_authorization_header() {
        let c = cache();
        let stored = c
            .put(
                key(),
                "h",
                "/p",
                200,
                vec![],
                Bytes::from("ok"),
                Some("max-age=600"),
                Tier::Medium,
                &CachePolicy::Aggressive { ttl_seconds: 300 },
                true,
                false,
            )
            .await;
        assert!(!stored);
        assert_eq!(c.stats().bypassed_authenticated, 1);
        assert_eq!(c.stats().bypassed_critical, 0);
    }

    #[tokio::test]
    async fn auth_request_bypasses_via_cookie_header() {
        let c = cache();
        let stored = c
            .put(
                key(),
                "h",
                "/p",
                200,
                vec![],
                Bytes::from("ok"),
                Some("max-age=600"),
                Tier::Medium,
                &CachePolicy::Aggressive { ttl_seconds: 300 },
                false,
                true,
            )
            .await;
        assert!(!stored);
        assert_eq!(c.stats().bypassed_authenticated, 1);
    }

    fn cache_with_rule(rule_id: &str, prefix: &str, ttl_secs: u32, tags: Vec<String>) -> Arc<ResponseCache> {
        use crate::cache::config::{CacheConfigDoc, Defaults, MatchDoc, PathSpec, RuleDoc};
        let doc = CacheConfigDoc {
            version: 1,
            defaults: Defaults::default(),
            rules: vec![RuleDoc {
                id: rule_id.into(),
                match_: MatchDoc {
                    host: None,
                    path: PathSpec::Prefix { prefix: prefix.into() },
                    methods: None,
                },
                ttl_seconds: ttl_secs,
                tags,
                allow_authenticated: false,
            }],
        };
        let set = CompiledRuleSet::try_from_doc(doc).unwrap();
        ResponseCache::with_rules(8, 60, 3600, RuleSetHolder::new(set))
    }

    async fn put_under_rule(c: &ResponseCache, key: &str, host: &str, path: &str) -> bool {
        c.put(
            key.to_string(),
            host,
            path,
            200,
            vec![],
            Bytes::from("ok"),
            None,
            Tier::Medium,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
            false,
            false,
        )
        .await
    }

    #[tokio::test]
    async fn purge_by_tag_removes_only_matching_entries() {
        let c = cache_with_rule("static", "/p", 600, vec!["catalog".into()]);
        assert!(put_under_rule(&c, "GET:h:/p/a", "h", "/p/a").await);
        assert!(put_under_rule(&c, "GET:h:/p/b", "h", "/p/b").await);
        assert_eq!(c.tag_index_size(), 2);

        let purged = c.purge_by_tag("catalog").await;
        assert_eq!(purged, 2);
        assert_eq!(c.tag_index_size(), 0);
        assert!(c.get("GET:h:/p/a", Tier::Medium).await.is_none());
        assert!(c.get("GET:h:/p/b", Tier::Medium).await.is_none());
        assert_eq!(c.stats().purges_tag, 2);
    }

    #[tokio::test]
    async fn purge_by_unknown_tag_returns_zero() {
        let c = cache_with_rule("static", "/p", 600, vec!["catalog".into()]);
        assert!(put_under_rule(&c, "GET:h:/p/a", "h", "/p/a").await);
        let purged = c.purge_by_tag("nonexistent").await;
        assert_eq!(purged, 0);
        assert!(c.get("GET:h:/p/a", Tier::Medium).await.is_some());
    }

    #[tokio::test]
    async fn purge_by_route_id_uses_auto_prepended_tag() {
        let c = cache_with_rule("static", "/p", 600, vec!["catalog".into()]);
        assert!(put_under_rule(&c, "GET:h:/p/a", "h", "/p/a").await);
        let purged = c.purge_by_route_id("static").await;
        assert_eq!(purged, 1);
        assert_eq!(c.stats().purges_route, 1);
        assert_eq!(c.stats().purges_tag, 0);
    }

    #[tokio::test]
    async fn flush_clears_tag_index() {
        let c = cache_with_rule("static", "/p", 600, vec!["catalog".into()]);
        assert!(put_under_rule(&c, "GET:h:/p/a", "h", "/p/a").await);
        assert!(c.tag_index_size() >= 1);
        c.flush().await;
        assert_eq!(c.tag_index_size(), 0);
    }

    #[tokio::test]
    async fn untagged_entries_do_not_grow_tag_index() {
        let c = cache();
        assert!(
            put_basic(
                &c,
                vec![],
                Some("max-age=600"),
                Tier::Medium,
                &CachePolicy::Aggressive { ttl_seconds: 300 },
            )
            .await
        );
        assert_eq!(c.tag_index_size(), 0);
    }

    #[tokio::test]
    async fn purge_host_removes_only_matching_host_entries() {
        let c = cache();
        for (host, path) in [("a", "/x"), ("a", "/y"), ("b", "/z")] {
            c.put(
                ResponseCache::make_key("GET", host, path, ""),
                host,
                path,
                200,
                vec![],
                Bytes::from("ok"),
                Some("max-age=60"),
                Tier::Medium,
                &CachePolicy::Aggressive { ttl_seconds: 300 },
                false,
                false,
            )
            .await;
        }
        c.purge_host("a").await;
        assert!(c.get("GET:a:/x", Tier::Medium).await.is_none());
        assert!(c.get("GET:a:/y", Tier::Medium).await.is_none());
        assert!(c.get("GET:b:/z", Tier::Medium).await.is_some());
    }

    #[tokio::test]
    async fn purge_key_removes_single_entry() {
        let c = cache();
        let stored = put_basic(
            &c,
            vec![],
            Some("max-age=60"),
            Tier::Medium,
            &CachePolicy::Aggressive { ttl_seconds: 300 },
        )
        .await;
        assert!(stored);
        assert!(c.get(&key(), Tier::Medium).await.is_some());
        c.purge_key(&key()).await;
        assert!(c.get(&key(), Tier::Medium).await.is_none());
    }

    #[tokio::test]
    async fn route_rule_ttl_overrides_upstream_when_anonymous() {
        use crate::cache::config::{CacheConfigDoc, Defaults, MatchDoc, PathSpec, RuleDoc};
        let doc = CacheConfigDoc {
            version: 1,
            defaults: Defaults::default(),
            rules: vec![RuleDoc {
                id: "static".into(),
                match_: MatchDoc {
                    host: None,
                    path: PathSpec::Prefix { prefix: "/p".into() },
                    methods: None,
                },
                ttl_seconds: 1800,
                tags: vec!["static".into()],
                allow_authenticated: false,
            }],
        };
        let set = CompiledRuleSet::try_from_doc(doc).unwrap();
        let holder = RuleSetHolder::new(set);
        let c = ResponseCache::with_rules(8, 60, 3600, holder);

        let stored = c
            .put(
                key(),
                "h",
                "/p",
                200,
                vec![],
                Bytes::from("ok"),
                None,
                Tier::Medium,
                &CachePolicy::Aggressive { ttl_seconds: 300 },
                false,
                false,
            )
            .await;
        assert!(stored);
        let entry = c.get(&key(), Tier::Medium).await.expect("present");
        assert_eq!(entry.max_age, 1800, "route rule TTL must apply");
    }
}
