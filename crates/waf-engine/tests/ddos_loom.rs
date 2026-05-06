//! Loom concurrency tests for FR-005 `DDoS` protection.
//!
//! These tests use the `loom` crate to exhaustively check for race conditions
//! and atomicity violations in concurrent code paths.
//!
//! # Running
//!
//! ```bash
//! RUSTFLAGS="--cfg loom" cargo test --test ddos_loom --release
//! ```
//!
//! Note: Only runs when compiled with `--cfg loom`. The `#[cfg(loom)]` gate
//! prevents compilation in normal builds since loom has significant overhead.

#![cfg(loom)]
// Loom test code uses casts that are safe within test ranges
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]

use loom::sync::Arc;
use loom::thread;

// ─────────────────────────────────────────────────────────────────────────────
// Test: Concurrent counter increments have no lost updates
// ─────────────────────────────────────────────────────────────────────────────

/// Loom-compatible in-memory counter using loom's atomic primitives.
mod loom_counter {
    use loom::sync::Mutex;
    use loom::sync::atomic::{AtomicU64, Ordering};
    use std::collections::HashMap;

    /// Simplified counter store for loom testing.
    pub struct LoomCounterStore {
        counts: Mutex<HashMap<String, AtomicU64>>,
    }

    impl LoomCounterStore {
        pub fn new() -> Self {
            Self {
                counts: Mutex::new(HashMap::new()),
            }
        }

        /// Increment and return new count — the operation under test.
        pub fn incr_get_sync(&self, key: &str) -> u64 {
            let mut map = self.counts.lock().unwrap();

            if let Some(counter) = map.get(key) {
                return counter.fetch_add(1, Ordering::SeqCst) + 1;
            }

            // Key doesn't exist — insert with initial value 1
            map.insert(key.to_string(), AtomicU64::new(1));
            1
        }

        /// Get current count without incrementing.
        pub fn get(&self, key: &str) -> u64 {
            let map = self.counts.lock().unwrap();
            map.get(key).map(|c| c.load(Ordering::SeqCst)).unwrap_or(0)
        }
    }
}

#[test]
fn concurrent_incr_no_lost_updates() {
    loom::model(|| {
        let store = Arc::new(loom_counter::LoomCounterStore::new());

        let s1 = Arc::clone(&store);
        let s2 = Arc::clone(&store);

        let h1 = thread::spawn(move || s1.incr_get_sync("k"));

        let h2 = thread::spawn(move || s2.incr_get_sync("k"));

        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();

        // Both increments must be visible — final count must be exactly 2
        let final_count = store.get("k");
        assert_eq!(final_count, 2, "expected 2, got {}", final_count);

        // The returned values must be 1 and 2 (in some order)
        let mut results = vec![r1, r2];
        results.sort();
        assert_eq!(results, vec![1, 2], "increments should return 1 and 2");
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: OverloadGuard atomic flag consistency
// ─────────────────────────────────────────────────────────────────────────────

mod loom_overload {
    use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Simplified OverloadGuard for loom testing.
    pub struct LoomOverloadGuard {
        in_flight: AtomicUsize,
        overloaded: AtomicBool,
        threshold: usize,
    }

    impl LoomOverloadGuard {
        pub fn new(threshold: usize) -> Self {
            Self {
                in_flight: AtomicUsize::new(0),
                overloaded: AtomicBool::new(false),
                threshold,
            }
        }

        pub fn enter(&self) {
            self.in_flight.fetch_add(1, Ordering::SeqCst);
        }

        pub fn exit(&self) {
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
        }

        pub fn sample(&self) {
            let count = self.in_flight.load(Ordering::SeqCst);
            self.overloaded.store(count > self.threshold, Ordering::SeqCst);
        }

        pub fn is_overloaded(&self) -> bool {
            self.overloaded.load(Ordering::SeqCst)
        }

        pub fn in_flight_count(&self) -> usize {
            self.in_flight.load(Ordering::SeqCst)
        }
    }
}

#[test]
fn overload_guard_concurrent_enter_exit() {
    loom::model(|| {
        let guard = Arc::new(loom_overload::LoomOverloadGuard::new(2));

        let g1 = Arc::clone(&guard);
        let g2 = Arc::clone(&guard);

        // Two threads enter concurrently
        let h1 = thread::spawn(move || {
            g1.enter();
        });

        let h2 = thread::spawn(move || {
            g2.enter();
        });

        h1.join().unwrap();
        h2.join().unwrap();

        // Both enters should be counted
        assert_eq!(guard.in_flight_count(), 2);
    });
}

#[test]
fn overload_guard_sample_sees_consistent_state() {
    loom::model(|| {
        let guard = Arc::new(loom_overload::LoomOverloadGuard::new(1));

        let g1 = Arc::clone(&guard);
        let g2 = Arc::clone(&guard);

        // Thread 1: enter twice (should trigger overload)
        let h1 = thread::spawn(move || {
            g1.enter();
            g1.enter();
        });

        // Thread 2: sample after some point
        let h2 = thread::spawn(move || {
            g2.sample();
            g2.is_overloaded()
        });

        h1.join().unwrap();
        let was_overloaded = h2.join().unwrap();

        // After h1 completes, in_flight = 2 > threshold = 1
        // If sample ran after both enters, overloaded should be true
        // If sample ran before, overloaded could be false
        // Either is valid — we're checking for no panics/UB
        let _ = was_overloaded; // Suppress unused warning
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: MovingMedian bucket update atomicity
// ─────────────────────────────────────────────────────────────────────────────

mod loom_baseline {
    use loom::sync::atomic::{AtomicU64, Ordering};

    const BUCKETS: usize = 4; // Small for loom tractability

    pub struct LoomMovingMedian {
        buckets: [AtomicU64; BUCKETS],
    }

    impl LoomMovingMedian {
        pub fn new() -> Self {
            Self {
                buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            }
        }

        pub fn record(&self, epoch_s: i64) -> u64 {
            let idx = (epoch_s as usize) % BUCKETS;
            self.buckets[idx].fetch_add(1, Ordering::SeqCst) + 1
        }

        pub fn total(&self) -> u64 {
            self.buckets.iter().map(|b| b.load(Ordering::SeqCst)).sum()
        }
    }
}

#[test]
fn baseline_concurrent_record_same_bucket() {
    loom::model(|| {
        let mm = Arc::new(loom_baseline::LoomMovingMedian::new());

        let m1 = Arc::clone(&mm);
        let m2 = Arc::clone(&mm);

        // Both threads record to same bucket (epoch_s = 0)
        let h1 = thread::spawn(move || m1.record(0));

        let h2 = thread::spawn(move || m2.record(0));

        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();

        // Total should be exactly 2
        assert_eq!(mm.total(), 2);

        // Returns should be 1 and 2 (in some order)
        let mut results = vec![r1, r2];
        results.sort();
        assert_eq!(results, vec![1, 2]);
    });
}

#[test]
fn baseline_concurrent_record_different_buckets() {
    loom::model(|| {
        let mm = Arc::new(loom_baseline::LoomMovingMedian::new());

        let m1 = Arc::clone(&mm);
        let m2 = Arc::clone(&mm);

        // Record to different buckets
        let h1 = thread::spawn(move || {
            m1.record(0) // bucket 0
        });

        let h2 = thread::spawn(move || {
            m2.record(1) // bucket 1
        });

        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();

        // Total should be exactly 2
        assert_eq!(mm.total(), 2);

        // Each bucket should have 1, so both returns should be 1
        assert_eq!(r1, 1);
        assert_eq!(r2, 1);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: DynamicBanTable concurrent insert/contains
// ─────────────────────────────────────────────────────────────────────────────

mod loom_ban_table {
    use loom::sync::Mutex;
    use std::collections::HashMap;
    use std::net::IpAddr;

    /// Simplified DynamicBanTable for loom testing.
    pub struct LoomBanTable {
        entries: Mutex<HashMap<IpAddr, i64>>,
    }

    impl LoomBanTable {
        pub fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
            }
        }

        pub fn insert(&self, ip: IpAddr, expires_ms: i64) {
            let mut map = self.entries.lock().unwrap();
            map.entry(ip)
                .and_modify(|exp| *exp = (*exp).max(expires_ms))
                .or_insert(expires_ms);
        }

        pub fn contains(&self, ip: IpAddr, now_ms: i64) -> bool {
            let map = self.entries.lock().unwrap();
            map.get(&ip).is_some_and(|exp| *exp > now_ms)
        }
    }
}

#[test]
fn ban_table_concurrent_insert_extends() {
    use std::net::{IpAddr, Ipv4Addr};

    loom::model(|| {
        let table = Arc::new(loom_ban_table::LoomBanTable::new());
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let t1 = Arc::clone(&table);
        let t2 = Arc::clone(&table);

        // Two threads insert same IP with different expiry
        let h1 = thread::spawn(move || {
            t1.insert(ip, 1000);
        });

        let h2 = thread::spawn(move || {
            t2.insert(ip, 2000);
        });

        h1.join().unwrap();
        h2.join().unwrap();

        // The larger expiry should win
        assert!(table.contains(ip, 1500), "should be banned at 1500 (exp=2000)");
        assert!(!table.contains(ip, 2500), "should NOT be banned at 2500");
    });
}

#[test]
fn ban_table_concurrent_insert_and_contains() {
    use std::net::{IpAddr, Ipv4Addr};

    loom::model(|| {
        let table = Arc::new(loom_ban_table::LoomBanTable::new());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let t1 = Arc::clone(&table);
        let t2 = Arc::clone(&table);

        // Thread 1: insert
        let h1 = thread::spawn(move || {
            t1.insert(ip, 5000);
        });

        // Thread 2: check contains (may or may not see the insert)
        let h2 = thread::spawn(move || t2.contains(ip, 1000));

        h1.join().unwrap();
        let found = h2.join().unwrap();

        // If h2 ran after h1, found should be true
        // If h2 ran before h1, found should be false
        // Either is valid — we're checking for no data races
        let _ = found;

        // After both complete, IP should definitely be banned
        assert!(table.contains(ip, 1000));
    });
}
