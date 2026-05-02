//! Sliding-window state for FR-018 brute force / credential stuffing.
//!
//! Two maps, keyed differently:
//! - `failed` keyed by `(user_hash, client_ip)` → deque of recent failure
//!   timestamps. A request into a login route is blocked when the in-window
//!   count exceeds `bf_max_per_user`.
//! - `spray` keyed by `(client_ip, password_hash)` → set of usernames tried.
//!   When one password hits `>= bf_spray_threshold` distinct users from one
//!   IP inside the window, any subsequent login from that IP is blocked.
//!
//! Both maps are bounded (Red Team Finding #6) — when they exceed
//! `max_entries` the oldest 10 percent are evicted by last-touched.
//!
//! Time comes from the Phase 00 `Clock` trait so tests advance the window
//! without sleeping (Validation Q7).
//
// `significant_drop_tightening` fires on the DashMap entry held across a
// Mutex lock — restructuring would cost an Arc<Mutex> per record for no
// throughput win. `option_if_let_else` rewrites add a closure per call site
// that is less readable than the match form we use.
#![allow(clippy::significant_drop_tightening, clippy::option_if_let_else)]

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

use super::Clock;

struct FailedRecord {
    hits: VecDeque<Instant>,
    last_touched: Instant,
}

struct SprayRecord {
    users: HashSet<u64>,
    last_touched: Instant,
}

pub struct BfState {
    failed: Arc<DashMap<(u64, IpAddr), Mutex<FailedRecord>>>,
    spray: Arc<DashMap<(IpAddr, u64), Mutex<SprayRecord>>>,
    /// Secondary index: count of `(ip, password_hash)` records that have
    /// currently reached `bf_spray_threshold`. Lets the request-phase
    /// dispatcher answer "any spray over threshold for this IP?" in O(1)
    /// instead of scanning the whole `spray` map (100k entries worst case).
    spray_hits_per_ip: Arc<DashMap<IpAddr, AtomicUsize>>,
    max_entries: usize,
    evict_ticker: AtomicUsize,
    clock: Arc<dyn Clock>,
}

/// Cap per (ip, password) spray set — well above any reasonable threshold,
/// prevents unbounded growth when someone hammers `P@ss1` across thousands
/// of usernames.
const SPRAY_USERS_CAP: usize = 1000;
/// Cap per (user, ip) failed-login deque — well above
/// `bf_max_per_user * 4` so boundary tests still have headroom but adversaries
/// can't grow this deque without bound.
const FAILED_HITS_CAP: usize = 64;
/// Amortize eviction: only every N-th call while over cap pays the sort.
const EVICT_INTERVAL: usize = 1024;

impl BfState {
    pub fn new(max_entries: usize, clock: Arc<dyn Clock>) -> Self {
        Self {
            failed: Arc::new(DashMap::new()),
            spray: Arc::new(DashMap::new()),
            spray_hits_per_ip: Arc::new(DashMap::new()),
            max_entries,
            evict_ticker: AtomicUsize::new(0),
            clock,
        }
    }

    pub fn record_failed(&self, user_hash: u64, ip: IpAddr, window: Duration) {
        self.evict_if_over_cap_failed();
        let now = self.clock.now();
        let entry = self.failed.entry((user_hash, ip)).or_insert_with(|| {
            Mutex::new(FailedRecord {
                hits: VecDeque::new(),
                last_touched: now,
            })
        });
        let mut rec = entry.lock();
        rec.last_touched = now;
        rec.hits.push_back(now);
        Self::prune_hits(&mut rec.hits, now, window);
        while rec.hits.len() > FAILED_HITS_CAP {
            rec.hits.pop_front();
        }
    }

    pub fn failed_count(&self, user_hash: u64, ip: IpAddr, window: Duration) -> usize {
        let now = self.clock.now();
        match self.failed.get(&(user_hash, ip)) {
            Some(entry) => {
                let mut rec = entry.lock();
                Self::prune_hits(&mut rec.hits, now, window);
                rec.hits.len()
            }
            None => 0,
        }
    }

    pub fn record_spray(
        &self,
        ip: IpAddr,
        password_hash: u64,
        user_hash: u64,
        window: Duration,
        threshold: usize,
    ) -> usize {
        self.evict_if_over_cap_spray();
        let now = self.clock.now();
        let (user_count, transitioned) = {
            // Scope the DashMap entry so its shard guard is dropped before
            // we touch a second DashMap (`spray_hits_per_ip`). Without this
            // scoping, a hash collision on the same shard deadlocks.
            let entry = self.spray.entry((ip, password_hash)).or_insert_with(|| {
                Mutex::new(SprayRecord {
                    users: HashSet::new(),
                    last_touched: now,
                })
            });
            let mut rec = entry.lock();
            let was_over_threshold = rec.last_touched + window >= now && rec.users.len() >= threshold;
            if rec.last_touched + window < now {
                // Whole window has passed since last touch — reset.
                rec.users.clear();
            }
            rec.last_touched = now;
            if rec.users.len() < SPRAY_USERS_CAP {
                rec.users.insert(user_hash);
            }
            let now_count = rec.users.len();
            let transitioned = !was_over_threshold && now_count >= threshold;
            (now_count, transitioned)
        };
        if transitioned {
            self.spray_hits_per_ip
                .entry(ip)
                .or_insert_with(|| AtomicUsize::new(0))
                .fetch_add(1, Ordering::Relaxed);
        }
        user_count
    }

    pub fn spray_count(&self, ip: IpAddr, password_hash: u64, window: Duration) -> usize {
        let now = self.clock.now();
        match self.spray.get(&(ip, password_hash)) {
            Some(entry) => {
                let rec = entry.lock();
                if rec.last_touched + window < now {
                    0
                } else {
                    rec.users.len()
                }
            }
            None => 0,
        }
    }

    /// Return true when at least one `(ip, password)` record has currently
    /// reached `threshold` distinct users inside `window`. O(1) fast path via
    /// the `spray_hits_per_ip` secondary index (an approximate counter),
    /// falling back to a scoped iteration only over this IP's own spray
    /// entries when the counter indicates a candidate — avoiding the full
    /// map scan that would otherwise make this O(N) on every login.
    pub fn any_spray_over_threshold(&self, ip: IpAddr, threshold: usize, window: Duration) -> bool {
        // Fast negative path — if the counter is 0, no record ever crossed
        // the threshold for this IP. Avoids the spray map scan entirely for
        // the vast majority of legitimate traffic.
        let candidate_count = self.spray_hits_per_ip.get(&ip).map_or(0, |e| e.load(Ordering::Relaxed));
        if candidate_count == 0 {
            return false;
        }
        // Slow path — re-verify against live state (counter may be stale
        // after window expiry). Scoped to keys with matching IP only.
        let now = self.clock.now();
        let hit = self.spray.iter().any(|kv| {
            let (entry_ip, _) = kv.key();
            if *entry_ip != ip {
                return false;
            }
            let rec = kv.value().lock();
            rec.last_touched + window >= now && rec.users.len() >= threshold
        });
        if !hit {
            // Counter was stale (all candidate records expired). Reset so
            // future queries take the fast negative path.
            if let Some(e) = self.spray_hits_per_ip.get(&ip) {
                e.store(0, Ordering::Relaxed);
            }
        }
        hit
    }

    fn prune_hits(hits: &mut VecDeque<Instant>, now: Instant, window: Duration) {
        let cutoff = now.checked_sub(window).unwrap_or(now);
        while hits.front().is_some_and(|t| *t < cutoff) {
            hits.pop_front();
        }
    }

    fn should_evict_now(&self) -> bool {
        let tick = self.evict_ticker.fetch_add(1, Ordering::Relaxed);
        tick.is_multiple_of(EVICT_INTERVAL)
    }

    fn evict_if_over_cap_failed(&self) {
        if self.failed.len() <= self.max_entries || !self.should_evict_now() {
            return;
        }
        let mut ages: Vec<((u64, IpAddr), Instant)> = self
            .failed
            .iter()
            .map(|kv| (*kv.key(), kv.value().lock().last_touched))
            .collect();
        ages.sort_by_key(|(_, t)| *t);
        let over = self.failed.len().saturating_sub(self.max_entries);
        let drop_n = over.max(ages.len() / 10);
        for (key, _) in ages.into_iter().take(drop_n) {
            self.failed.remove(&key);
        }
    }

    fn evict_if_over_cap_spray(&self) {
        if self.spray.len() <= self.max_entries || !self.should_evict_now() {
            return;
        }
        let mut ages: Vec<((IpAddr, u64), Instant)> = self
            .spray
            .iter()
            .map(|kv| (*kv.key(), kv.value().lock().last_touched))
            .collect();
        ages.sort_by_key(|(_, t)| *t);
        let over = self.spray.len().saturating_sub(self.max_entries);
        let drop_n = over.max(ages.len() / 10);
        for (key, _) in ages.into_iter().take(drop_n) {
            self.spray.remove(&key);
        }
    }

    pub fn prune_older_than(&self, cutoff: Instant) {
        self.failed.retain(|_, rec| rec.lock().last_touched >= cutoff);
        self.spray.retain(|_, rec| rec.lock().last_touched >= cutoff);
        // Secondary index is approximate; drop entries for IPs with no
        // remaining spray records to keep it bounded.
        self.spray_hits_per_ip
            .retain(|ip, _| self.spray.iter().any(|kv| kv.key().0 == *ip));
    }

    pub fn failed_len(&self) -> usize {
        self.failed.len()
    }

    pub fn spray_len(&self) -> usize {
        self.spray.len()
    }
}

#[cfg(test)]
#[allow(clippy::duration_suboptimal_units, clippy::redundant_clone)]
mod tests {
    use super::*;
    use crate::checks::test_clock::MockClock;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn failed_count_grows_and_window_expires() {
        let clock = Arc::new(MockClock::new());
        let s = BfState::new(1000, clock.clone());
        for _ in 0..5 {
            s.record_failed(42, ip("1.1.1.1"), Duration::from_secs(900));
        }
        assert_eq!(s.failed_count(42, ip("1.1.1.1"), Duration::from_secs(900)), 5);
        clock.advance(Duration::from_secs(1800));
        assert_eq!(s.failed_count(42, ip("1.1.1.1"), Duration::from_secs(900)), 0);
    }

    #[test]
    fn failed_isolation_by_user_and_ip() {
        let clock = Arc::new(MockClock::new());
        let s = BfState::new(1000, clock.clone());
        for _ in 0..5 {
            s.record_failed(42, ip("1.1.1.1"), Duration::from_secs(900));
        }
        assert_eq!(s.failed_count(42, ip("1.1.1.1"), Duration::from_secs(900)), 5);
        assert_eq!(s.failed_count(43, ip("1.1.1.1"), Duration::from_secs(900)), 0);
        assert_eq!(s.failed_count(42, ip("2.2.2.2"), Duration::from_secs(900)), 0);
    }

    const TH: usize = 5;

    #[test]
    fn spray_counts_distinct_users() {
        let clock = Arc::new(MockClock::new());
        let s = BfState::new(1000, clock.clone());
        for user in 0..5_u64 {
            s.record_spray(ip("9.9.9.9"), 0xdead_beef, user, Duration::from_secs(300), TH);
        }
        assert_eq!(s.spray_count(ip("9.9.9.9"), 0xdead_beef, Duration::from_secs(300)), 5);
    }

    #[test]
    fn spray_dedups_same_user() {
        let clock = Arc::new(MockClock::new());
        let s = BfState::new(1000, clock.clone());
        for _ in 0..10 {
            s.record_spray(ip("9.9.9.9"), 0xdead, 1, Duration::from_secs(300), TH);
        }
        assert_eq!(s.spray_count(ip("9.9.9.9"), 0xdead, Duration::from_secs(300)), 1);
    }

    #[test]
    fn spray_window_expires() {
        let clock = Arc::new(MockClock::new());
        let s = BfState::new(1000, clock.clone());
        for user in 0..5_u64 {
            s.record_spray(ip("9.9.9.9"), 0xbeef, user, Duration::from_secs(300), TH);
        }
        clock.advance(Duration::from_secs(600));
        assert_eq!(s.spray_count(ip("9.9.9.9"), 0xbeef, Duration::from_secs(300)), 0);
    }

    #[test]
    fn any_spray_over_threshold_detects_cross_password() {
        let clock = Arc::new(MockClock::new());
        let s = BfState::new(1000, clock.clone());
        for user in 0..5_u64 {
            s.record_spray(ip("9.9.9.9"), 0xdead, user, Duration::from_secs(300), TH);
        }
        assert!(s.any_spray_over_threshold(ip("9.9.9.9"), 5, Duration::from_secs(300)));
        assert!(!s.any_spray_over_threshold(ip("9.9.9.9"), 6, Duration::from_secs(300)));
        assert!(!s.any_spray_over_threshold(ip("8.8.8.8"), 5, Duration::from_secs(300)));
    }

    #[test]
    fn any_spray_over_threshold_clears_when_window_expires() {
        // Validates the approximate-counter reset path: after the window
        // expires, the secondary index is stale but a single query will
        // self-correct and subsequent queries return fast-path false.
        let clock = Arc::new(MockClock::new());
        let s = BfState::new(1000, clock.clone());
        for user in 0..5_u64 {
            s.record_spray(ip("9.9.9.9"), 0xcafe, user, Duration::from_secs(300), TH);
        }
        assert!(s.any_spray_over_threshold(ip("9.9.9.9"), TH, Duration::from_secs(300)));
        clock.advance(Duration::from_secs(600));
        assert!(!s.any_spray_over_threshold(ip("9.9.9.9"), TH, Duration::from_secs(300)));
        // Second query takes the fast-path negative because counter was reset.
        assert!(!s.any_spray_over_threshold(ip("9.9.9.9"), TH, Duration::from_secs(300)));
    }

    #[test]
    fn failed_caps_hits_deque() {
        let clock = Arc::new(MockClock::new());
        let s = BfState::new(1000, clock.clone());
        for _ in 0..(FAILED_HITS_CAP + 20) {
            s.record_failed(42, ip("1.1.1.1"), Duration::from_secs(900));
        }
        assert!(s.failed_count(42, ip("1.1.1.1"), Duration::from_secs(900)) <= FAILED_HITS_CAP);
    }

    #[test]
    fn failed_map_bounded_by_amortized_eviction() {
        // Eviction is amortized — every EVICT_INTERVAL calls while over cap.
        // Worst-case headroom above `max_entries` is one interval's worth.
        let clock = Arc::new(MockClock::new());
        let s = BfState::new(50, clock.clone());
        let total = 50 + EVICT_INTERVAL + 100;
        for i in 0..total {
            let i = i as u64;
            s.record_failed(
                i,
                ip(&format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff)),
                Duration::from_secs(900),
            );
        }
        assert!(s.failed_len() < total, "no sweep fired: len={}", s.failed_len());
        assert!(
            s.failed_len() <= 50 + EVICT_INTERVAL,
            "headroom exceeded: len={}",
            s.failed_len()
        );
    }

    #[test]
    fn spray_map_bounded_by_amortized_eviction() {
        let clock = Arc::new(MockClock::new());
        let s = BfState::new(50, clock.clone());
        let total = 50 + EVICT_INTERVAL + 100;
        for i in 0..total {
            let i = i as u64;
            s.record_spray(
                ip(&format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff)),
                0xaa,
                i,
                Duration::from_secs(300),
                TH,
            );
        }
        assert!(s.spray_len() < total, "no sweep fired: len={}", s.spray_len());
        assert!(
            s.spray_len() <= 50 + EVICT_INTERVAL,
            "headroom exceeded: len={}",
            s.spray_len()
        );
    }

    #[test]
    fn prune_older_than_drops_stale() {
        let clock = Arc::new(MockClock::new());
        let s = BfState::new(1000, clock.clone());
        s.record_failed(1, ip("1.1.1.1"), Duration::from_secs(900));
        clock.advance(Duration::from_secs(3600));
        s.record_failed(2, ip("2.2.2.2"), Duration::from_secs(900));
        let cutoff = clock.now().checked_sub(Duration::from_secs(1800)).unwrap();
        s.prune_older_than(cutoff);
        assert_eq!(s.failed_len(), 1);
    }
}
