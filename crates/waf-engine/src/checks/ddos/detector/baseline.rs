//! Moving-median baseline for per-tier traffic normalization.
//!
//! Maintains a 60-slot ring buffer of per-second request counts. The median
//! of these counts serves as the baseline for adaptive threshold calculation:
//! `threshold = max(absolute_cap_floor, 3 × median)`.
//!
//! # Design Trade-offs
//!
//! - **60 buckets at 1s granularity**: Captures ~1 minute of traffic history.
//!   Fine enough for detecting bursts, coarse enough to smooth normal variance.
//!
//! - **Atomic operations per bucket**: Each bucket uses `AtomicU64` for lock-free
//!   concurrent updates. The `record()` path is fast (no sorting), while `median()`
//!   pays the O(60 log 60) sort cost — acceptable since it's only called once per
//!   request evaluation.
//!
//! - **Eventual consistency at second boundaries**: When the epoch-second changes,
//!   there's a brief race where readers may see stale bucket values. This is
//!   acceptable for baseline calculation (median is robust to outliers).

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

const BUCKETS: usize = 60;

/// Rolling 60-second window of per-second request counts.
///
/// Thread-safe via atomic operations on each bucket. The median provides
/// a noise-resistant baseline for adaptive threshold calculation.
pub struct MovingMedian {
    /// Ring buffer: index = `epoch_s % 60`.
    buckets: [AtomicU64; BUCKETS],
    /// Last recorded epoch-second (used to detect rollover).
    last_epoch_s: AtomicI64,
}

impl MovingMedian {
    /// Create a new median tracker with zeroed buckets.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            last_epoch_s: AtomicI64::new(-1),
        }
    }

    /// Record a request at the given timestamp and return the bucket's new count.
    ///
    /// If the epoch-second has advanced past the current bucket, stale buckets
    /// in between are cleared. This ensures old data doesn't pollute the median.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    pub fn record(&self, now_ms: i64) -> u64 {
        let epoch_s = now_ms / 1000;
        // Safe: BUCKETS=60, rem_euclid result is always 0..59, fits in usize on any platform.
        let idx = epoch_s.rem_euclid(BUCKETS as i64) as usize;

        // Check if we need to clear stale buckets
        let prev_s = self.last_epoch_s.load(Ordering::Acquire);
        if epoch_s > prev_s {
            // Try to claim the epoch advance
            if self
                .last_epoch_s
                .compare_exchange(prev_s, epoch_s, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // We won the CAS — clear stale buckets between prev and now
                self.clear_stale_buckets(prev_s, epoch_s);
            }
            // If CAS failed, another thread already advanced — they'll clear
        }

        // Increment current bucket (idx is guaranteed valid by rem_euclid)
        // SAFETY: idx is always in 0..BUCKETS due to rem_euclid above.
        self.buckets
            .get(idx)
            .map_or(0, |b| b.fetch_add(1, Ordering::Relaxed) + 1)
    }

    /// Clear buckets that have become stale between `prev_s` and `now_s`.
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    fn clear_stale_buckets(&self, prev_s: i64, now_s: i64) {
        let advance = now_s.saturating_sub(prev_s);
        // Safe: BUCKETS=60 fits in i64
        let buckets_i64 = BUCKETS as i64;

        if advance >= buckets_i64 {
            // All buckets are stale — reset everything
            for bucket in &self.buckets {
                bucket.store(0, Ordering::Relaxed);
            }
        } else if prev_s >= 0 {
            // Clear the specific buckets that rolled over
            for offset in 1..=advance {
                // Safe: rem_euclid result is always 0..59
                let stale_idx = (prev_s + offset).rem_euclid(buckets_i64) as usize;
                if let Some(bucket) = self.buckets.get(stale_idx) {
                    bucket.store(0, Ordering::Relaxed);
                }
            }
        }
    }

    /// Compute the median of all 60 bucket values.
    ///
    /// Returns 0 if the baseline is cold (all zeros). The O(60 log 60) sort
    /// cost is acceptable since this is called once per request evaluation.
    #[must_use]
    pub fn median(&self) -> u64 {
        let mut values: [u64; BUCKETS] =
            std::array::from_fn(|i| self.buckets.get(i).map_or(0, |b| b.load(Ordering::Relaxed)));
        values.sort_unstable();
        // BUCKETS/2 = 30, always valid index
        values.get(BUCKETS / 2).copied().unwrap_or(0)
    }

    /// Sum of all bucket counts (useful for debugging/metrics).
    #[must_use]
    pub fn total(&self) -> u64 {
        self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum()
    }
}

impl Default for MovingMedian {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_baseline_has_zero_median() {
        let mm = MovingMedian::new();
        assert_eq!(mm.median(), 0);
    }

    #[test]
    fn record_increments_correct_bucket() {
        let mm = MovingMedian::new();
        let count = mm.record(5000); // epoch_s=5, idx=5
        assert_eq!(count, 1);
        let count = mm.record(5500); // same second
        assert_eq!(count, 2);
    }

    #[test]
    fn record_in_different_seconds_uses_different_buckets() {
        let mm = MovingMedian::new();
        mm.record(1000); // idx=1
        mm.record(2000); // idx=2
        mm.record(3000); // idx=3
        assert_eq!(mm.total(), 3);
    }

    #[test]
    fn median_with_single_nonzero_bucket() {
        let mm = MovingMedian::new();
        for _ in 0..100 {
            mm.record(0); // all in bucket 0
        }
        // 59 buckets at 0, 1 bucket at 100 → median is 0
        assert_eq!(mm.median(), 0);
    }

    #[test]
    fn median_with_half_buckets_populated() {
        let mm = MovingMedian::new();
        // Populate 30 buckets with 10 each
        for i in 0..30 {
            for _ in 0..10 {
                mm.record(i * 1000);
            }
        }
        // 30 buckets at 10, 30 at 0 → sorted: [0×30, 10×30], median at idx 30 = 10
        assert_eq!(mm.median(), 10);
    }

    #[test]
    fn median_with_all_buckets_populated() {
        let mm = MovingMedian::new();
        // Populate all 60 buckets with 5 each
        for i in 0..60 {
            for _ in 0..5 {
                mm.record(i * 1000);
            }
        }
        assert_eq!(mm.median(), 5);
    }

    #[test]
    fn stale_buckets_cleared_on_rollover() {
        let mm = MovingMedian::new();
        // Record at t=0s
        mm.record(0);
        mm.record(0);
        assert_eq!(mm.total(), 2);

        // Jump to t=1s — bucket 0 should remain, bucket 1 cleared before use
        mm.record(1000);
        // bucket 0 has 2, bucket 1 has 1
        assert_eq!(mm.total(), 3);

        // Jump 60s ahead — all buckets should be cleared
        mm.record(61_000);
        assert_eq!(mm.total(), 1);
    }

    #[test]
    fn large_time_gap_clears_all() {
        let mm = MovingMedian::new();
        for i in 0..30 {
            mm.record(i * 1000);
        }
        assert!(mm.total() >= 30);

        // Jump 120 seconds ahead — all stale
        mm.record(150_000);
        assert_eq!(mm.total(), 1);
    }

    #[test]
    fn concurrent_records_same_bucket() {
        use std::sync::Arc;
        use std::thread;

        let mm = Arc::new(MovingMedian::new());
        let mut handles = vec![];

        for _ in 0..100 {
            let mm_clone = Arc::clone(&mm);
            handles.push(thread::spawn(move || {
                mm_clone.record(5000);
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        // Should have ~100 in bucket 5 (small race tolerance)
        let total = mm.total();
        assert!((99..=100).contains(&total), "got {total}, expected ~100");
    }

    #[test]
    fn proptest_monotonic_count_nondecreasing_median() {
        // Simplified property test: increasing traffic → non-decreasing median
        let mm = MovingMedian::new();
        let mut prev_median = 0;

        for round in 0..60 {
            let requests_this_second = (round + 1) * 2;
            for _ in 0..requests_this_second {
                mm.record(round * 1000);
            }
            let m = mm.median();
            assert!(m >= prev_median, "median should not decrease: {prev_median} → {m}");
            prev_median = m;
        }
    }
}
