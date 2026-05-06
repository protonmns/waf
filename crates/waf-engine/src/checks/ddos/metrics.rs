//! FR-005 Phase 7 — `DDoS` observability metrics.
//!
//! Provides atomic counters for `DDoS` detection events. Uses `AtomicU64` for
//! lock-free updates on the hot path. Counters are exposed via accessor methods
//! for external metrics exporters (Prometheus, `StatsD`, etc.).
//!
//! No external metrics framework dependency — integrates with existing
//! tracing-based observability.

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters for `DDoS` detection and action events.
///
/// All operations are `Ordering::Relaxed` — sufficient for monotonic counters
/// where we only care about eventual consistency, not happens-before ordering.
#[derive(Debug, Default)]
pub struct DdosMetrics {
    /// Total burst events detected (per-IP, per-FP, per-tier combined).
    burst_total: AtomicU64,
    /// Burst events by `per_ip` detector.
    burst_per_ip: AtomicU64,
    /// Burst events by `per_fp` detector.
    burst_per_fp: AtomicU64,
    /// Burst events by `per_tier` detector.
    burst_per_tier: AtomicU64,
    /// Total active bans (incremented on ban, decremented on expiry purge).
    bans_active: AtomicU64,
    /// Total ban events issued.
    bans_total: AtomicU64,
    /// Store errors (Redis/memory unavailable).
    store_errors: AtomicU64,
    /// Degrade events (circuit breaker triggered).
    degrade_events: AtomicU64,
}

impl DdosMetrics {
    /// Create a new metrics instance with all counters at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            burst_total: AtomicU64::new(0),
            burst_per_ip: AtomicU64::new(0),
            burst_per_fp: AtomicU64::new(0),
            burst_per_tier: AtomicU64::new(0),
            bans_active: AtomicU64::new(0),
            bans_total: AtomicU64::new(0),
            store_errors: AtomicU64::new(0),
            degrade_events: AtomicU64::new(0),
        }
    }

    /// Increment burst counter for the given detector.
    pub fn inc_burst(&self, detector: &str) {
        self.burst_total.fetch_add(1, Ordering::Relaxed);
        match detector {
            "per_ip" => self.burst_per_ip.fetch_add(1, Ordering::Relaxed),
            "per_fp" => self.burst_per_fp.fetch_add(1, Ordering::Relaxed),
            "per_tier" => self.burst_per_tier.fetch_add(1, Ordering::Relaxed),
            _ => 0, // Unknown detector, only increment total
        };
    }

    /// Increment ban counters (both total and active).
    pub fn inc_ban(&self) {
        self.bans_total.fetch_add(1, Ordering::Relaxed);
        self.bans_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active bans (called when bans expire via purge).
    pub fn dec_bans_active(&self, count: u64) {
        // Use saturating sub to prevent underflow
        let _ = self
            .bans_active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(count)));
    }

    /// Increment store error counter.
    pub fn inc_store_error(&self) {
        self.store_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment degrade event counter.
    pub fn inc_degrade(&self) {
        self.degrade_events.fetch_add(1, Ordering::Relaxed);
    }

    // ─── Accessors for metrics export ─────────────────────────────────────────

    #[must_use]
    pub fn burst_total(&self) -> u64 {
        self.burst_total.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn burst_per_ip(&self) -> u64 {
        self.burst_per_ip.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn burst_per_fp(&self) -> u64 {
        self.burst_per_fp.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn burst_per_tier(&self) -> u64 {
        self.burst_per_tier.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn bans_active(&self) -> u64 {
        self.bans_active.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn bans_total(&self) -> u64 {
        self.bans_total.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn store_errors(&self) -> u64 {
        self.store_errors.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn degrade_events(&self) -> u64 {
        self.degrade_events.load(Ordering::Relaxed)
    }

    /// Snapshot all metrics for logging/export.
    #[must_use]
    pub fn snapshot(&self) -> DdosMetricsSnapshot {
        DdosMetricsSnapshot {
            burst_total: self.burst_total(),
            burst_per_ip: self.burst_per_ip(),
            burst_per_fp: self.burst_per_fp(),
            burst_per_tier: self.burst_per_tier(),
            bans_active: self.bans_active(),
            bans_total: self.bans_total(),
            store_errors: self.store_errors(),
            degrade_events: self.degrade_events(),
        }
    }
}

/// Immutable snapshot of `DDoS` metrics for serialization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DdosMetricsSnapshot {
    pub burst_total: u64,
    pub burst_per_ip: u64,
    pub burst_per_fp: u64,
    pub burst_per_tier: u64,
    pub bans_active: u64,
    pub bans_total: u64,
    pub store_errors: u64,
    pub degrade_events: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_inc_burst_by_detector() {
        let m = DdosMetrics::new();

        m.inc_burst("per_ip");
        m.inc_burst("per_ip");
        m.inc_burst("per_fp");
        m.inc_burst("per_tier");
        m.inc_burst("unknown");

        assert_eq!(m.burst_total(), 5);
        assert_eq!(m.burst_per_ip(), 2);
        assert_eq!(m.burst_per_fp(), 1);
        assert_eq!(m.burst_per_tier(), 1);
    }

    #[test]
    fn metrics_ban_counters() {
        let m = DdosMetrics::new();

        m.inc_ban();
        m.inc_ban();
        m.inc_ban();
        assert_eq!(m.bans_total(), 3);
        assert_eq!(m.bans_active(), 3);

        m.dec_bans_active(2);
        assert_eq!(m.bans_active(), 1);

        // Saturating sub prevents underflow
        m.dec_bans_active(10);
        assert_eq!(m.bans_active(), 0);
    }

    #[test]
    fn metrics_snapshot() {
        let m = DdosMetrics::new();
        m.inc_burst("per_ip");
        m.inc_ban();
        m.inc_store_error();
        m.inc_degrade();

        let snap = m.snapshot();
        assert_eq!(snap.burst_total, 1);
        assert_eq!(snap.burst_per_ip, 1);
        assert_eq!(snap.bans_total, 1);
        assert_eq!(snap.bans_active, 1);
        assert_eq!(snap.store_errors, 1);
        assert_eq!(snap.degrade_events, 1);
    }
}
