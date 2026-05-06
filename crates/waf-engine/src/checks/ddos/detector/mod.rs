//! `DDoS` detector traits and verdict types.
//!
//! Detectors evaluate requests against `DDoS` thresholds and return a verdict.
//! The pipeline composes multiple detectors (per-IP, per-fingerprint, per-tier)
//! and aggregates their verdicts into a final decision.

use waf_common::{RequestCtx, tier::Tier};

use super::DdosTierCfg;

pub mod baseline;
pub mod clock;
pub mod per_fp;
pub mod per_ip;
pub mod per_tier;

pub use clock::{Clock, SystemClock};
pub use per_fp::PerFpDetector;
pub use per_ip::PerIpDetector;
pub use per_tier::PerTierDetector;

/// Outcome of a single detector evaluation.
///
/// Designed for zero-alloc on the Allow path — all strings are `&'static str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorVerdict {
    /// Request passes this detector's check.
    Allow,
    /// Soft anomaly detected — add risk delta (0-100) to the request's score.
    /// Does not block on its own; downstream aggregation decides.
    SoftAnomaly(u8),
    /// Hard burst limit exceeded — immediate block recommended.
    HardBurst {
        /// Why the burst was detected (e.g., "burst", "sustained").
        reason: &'static str,
        /// Which detector raised this verdict (e.g., `per_ip`).
        detector: &'static str,
    },
}

/// Trait for `DDoS` detectors.
///
/// Each detector evaluates a request against its specific criteria (per-IP rate,
/// fingerprint pattern, tier-wide aggregate, etc.) and returns a verdict.
///
/// Detectors are stateless per-call — they read from shared stores but don't
/// own mutable state beyond Arc references.
pub trait Detector: Send + Sync {
    /// Detector name for logging and metrics.
    fn name(&self) -> &'static str;

    /// Evaluate the request against this detector's criteria.
    ///
    /// # Arguments
    /// - `ctx`: Request context (IP, tier, headers, etc.)
    /// - `cfg`: `DDoS` tier config (thresholds, windows)
    /// - `now_ms`: Current time in milliseconds (for rate window calculations)
    fn evaluate(&self, ctx: &RequestCtx, cfg: &DdosTierCfg, now_ms: i64) -> DetectorVerdict;
}

/// Convert a `Tier` to its `snake_case` string representation for key building.
///
/// Returns a static string to avoid allocation in the hot path.
#[must_use]
pub const fn tier_str(tier: Tier) -> &'static str {
    match tier {
        Tier::Critical => "critical",
        Tier::High => "high",
        Tier::Medium => "medium",
        Tier::CatchAll => "catch_all",
    }
}
