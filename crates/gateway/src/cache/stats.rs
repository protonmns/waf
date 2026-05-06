//! Response-cache statistics counters + timeseries ring buffer.
//!
//! `bypassed_critical` is the audit signal for FR-009 AC-1: it MUST tick on
//! every CRITICAL-tier or `NoCache`-policy bypass so operators can prove the
//! tier gate is firing.
//!
//! The 60-bucket timeseries ring buffer records 1-minute snapshots for the
//! `/api/cache/stats/timeseries` endpoint.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use parking_lot::Mutex;
use serde::Serialize;

use super::policy::BypassReason;

// ── Per-route hit/miss tracking ───────────────────────────────────────────────

/// Aggregated stats for a single cache route rule.
#[derive(Debug, Clone, Serialize)]
pub struct RouteStats {
    pub route_id: String,
    pub hits: u64,
    pub misses: u64,
    pub entry_count: u64,
}

// ── Timeseries bucket ─────────────────────────────────────────────────────────

/// One 1-minute data point in the timeseries ring buffer.
#[derive(Debug, Clone, Serialize)]
pub struct TimeseriesBucket {
    /// Unix timestamp (start of the minute, UTC) in seconds.
    pub ts: u64,
    pub hits: u64,
    pub misses: u64,
    pub hit_ratio: f64,
    pub stores: u64,
    /// Memory used by the backend in bytes (0 for moka).
    pub memory_used_bytes: u64,
}

impl TimeseriesBucket {
    fn new(ts: u64, hits: u64, misses: u64, stores: u64, memory_used_bytes: u64) -> Self {
        let total = hits + misses;
        let hit_ratio = if total == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            {
                hits as f64 / total as f64
            }
        };
        Self {
            ts,
            hits,
            misses,
            hit_ratio,
            stores,
            memory_used_bytes,
        }
    }
}

// ── Cache statistics counters ─────────────────────────────────────────────────

/// Cache statistics counters.
#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub stores: AtomicU64,
    /// Count of put/get calls bypassed by tier or `NoCache` policy.
    /// Audit signal for FR-009 AC-1.
    pub bypassed_critical: AtomicU64,
    /// FR-009 Phase 3: count of bypasses caused by `AuthGate`
    /// (request had `Authorization` or `Cookie`).
    pub bypassed_authenticated: AtomicU64,
    /// FR-009 Phase 3: count of bypasses caused by `RouteRuleGate` matching
    /// a rule with `ttl_seconds: 0` (operator opt-out).
    pub bypassed_explicit_deny: AtomicU64,
    /// FR-009 Phase 4: cumulative entries removed via `purge_by_tag`.
    pub purges_tag: AtomicU64,
    /// FR-009 Phase 4: cumulative entries removed via `purge_by_route_id`.
    pub purges_route: AtomicU64,

    /// Per-route cache hits (key = rule id or `"_default"`).
    route_hits: DashMap<String, AtomicU64>,
    /// Per-route cache misses on lookup.
    route_misses: DashMap<String, AtomicU64>,

    // ── Timeseries ring buffer (60 × 1-min buckets) ───────────────────────────
    // Guarded by a Mutex so the ticker thread can append without blocking
    // the hot request path (atomic counters are read lock-free).
    timeseries: Mutex<TimeseriesRing>,
    /// Snapshot of cumulative counters at the time the last bucket was recorded.
    last_snapshot: Mutex<BucketBaseline>,
}

/// Cumulative baseline captured at the start of each 1-minute window.
#[derive(Debug, Default, Clone)]
struct BucketBaseline {
    hits: u64,
    misses: u64,
    stores: u64,
}

/// Ring buffer of `TimeseriesBucket` (newest at back).
#[derive(Debug)]
struct TimeseriesRing {
    buckets: VecDeque<TimeseriesBucket>,
    /// Maximum number of 1-minute buckets to keep.
    max_buckets: usize,
}

impl Default for TimeseriesRing {
    fn default() -> Self {
        Self {
            buckets: VecDeque::new(),
            max_buckets: 60,
        }
    }
}

impl TimeseriesRing {
    fn push(&mut self, bucket: TimeseriesBucket) {
        if self.buckets.len() >= self.max_buckets {
            self.buckets.pop_front();
        }
        self.buckets.push_back(bucket);
    }

    /// Return the last `n` buckets, oldest first.
    fn last_n(&self, n: usize) -> Vec<TimeseriesBucket> {
        let skip = self.buckets.len().saturating_sub(n);
        self.buckets.iter().skip(skip).cloned().collect()
    }
}

impl CacheStats {
    pub fn snapshot(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            stores: self.stores.load(Ordering::Relaxed),
            bypassed_critical: self.bypassed_critical.load(Ordering::Relaxed),
            bypassed_authenticated: self.bypassed_authenticated.load(Ordering::Relaxed),
            bypassed_explicit_deny: self.bypassed_explicit_deny.load(Ordering::Relaxed),
            purges_tag: self.purges_tag.load(Ordering::Relaxed),
            purges_route: self.purges_route.load(Ordering::Relaxed),
        }
    }

    /// Bump the appropriate bypass counter for a `Verdict::Bypass(reason)`.
    pub fn record_bypass(&self, reason: BypassReason) {
        match reason {
            BypassReason::CriticalTier | BypassReason::NoCachePolicy => {
                self.bypassed_critical.fetch_add(1, Ordering::Relaxed);
            }
            BypassReason::Authenticated => {
                self.bypassed_authenticated.fetch_add(1, Ordering::Relaxed);
            }
            BypassReason::ExplicitDeny => {
                self.bypassed_explicit_deny.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Tick a timeseries bucket for the current minute. Call once per minute
    /// from a background task. `memory_used_bytes` should come from the backend.
    pub fn tick_timeseries(&self, memory_used_bytes: u64) {
        let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        // Align to minute boundary.
        let bucket_ts = (now_secs / 60) * 60;

        let hits_now = self.hits.load(Ordering::Relaxed);
        let misses_now = self.misses.load(Ordering::Relaxed);
        let stores_now = self.stores.load(Ordering::Relaxed);

        let mut baseline = self.last_snapshot.lock();
        let delta_hits = hits_now.saturating_sub(baseline.hits);
        let delta_misses = misses_now.saturating_sub(baseline.misses);
        let delta_stores = stores_now.saturating_sub(baseline.stores);
        *baseline = BucketBaseline {
            hits: hits_now,
            misses: misses_now,
            stores: stores_now,
        };
        drop(baseline);

        let bucket = TimeseriesBucket::new(bucket_ts, delta_hits, delta_misses, delta_stores, memory_used_bytes);
        self.timeseries.lock().push(bucket);
    }

    /// Return the last `minutes` data points, oldest first.
    /// Clamps to the ring buffer size (60).
    pub fn timeseries(&self, minutes: usize) -> Vec<TimeseriesBucket> {
        self.timeseries.lock().last_n(minutes.min(60))
    }

    pub fn record_route_hit(&self, route_key: &str) {
        self.route_hits
            .entry(route_key.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_route_miss(&self, route_key: &str) {
        self.route_misses
            .entry(route_key.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn route_traffic_snapshot(&self) -> HashMap<String, (u64, u64)> {
        let mut keys = HashSet::new();
        for r in &self.route_hits {
            keys.insert(r.key().clone());
        }
        for r in &self.route_misses {
            keys.insert(r.key().clone());
        }
        let mut out = HashMap::with_capacity(keys.len());
        for k in keys {
            let h = self.route_hits.get(&k).map_or(0, |v| v.load(Ordering::Relaxed));
            let m = self.route_misses.get(&k).map_or(0, |v| v.load(Ordering::Relaxed));
            out.insert(k, (h, m));
        }
        out
    }
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CacheStatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub stores: u64,
    pub bypassed_critical: u64,
    pub bypassed_authenticated: u64,
    pub bypassed_explicit_deny: u64,
    pub purges_tag: u64,
    pub purges_route: u64,
}

impl CacheStatsSnapshot {
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            {
                self.hits as f64 / total as f64
            }
        }
    }
}
