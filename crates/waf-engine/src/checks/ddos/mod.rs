//! FR-005 `DDoS` protection module.
//!
//! Composed of:
//! - [`store`]    — async `CounterStore` trait + in-memory backend
//! - [`config`]   — YAML schema + parsing for `configs/ddos.yaml`
//! - [`reload`]   — hot-reload watcher with `ArcSwap` snapshot
//! - [`detector`] — `Detector` trait + per-IP detector (phase 2)
//! - [`action`]   — action executors for bans and risk bumps (phase 5)
//! - [`degrade`]  — circuit breaker & fail-mode resolution (phase 6)
//! - [`check`]    — `DdosCheck` pipeline integration (phase 7)
//! - [`metrics`]  — atomic counters for observability (phase 7)

use std::collections::HashMap;

use waf_common::tier::Tier;

pub mod action;
pub mod check;
pub mod config;
pub mod degrade;
pub mod detector;
pub mod metrics;
pub mod reload;
pub mod store;

pub use action::{
    ActionExecutor, ActionResult, BanAction, BanSchedule, CombinedAction, DynamicBanTable, RiskBumpAction,
};
pub use check::DdosCheck;
pub use config::DdosFileConfig;
pub use degrade::{DegradeAction, ErrorKind, InFlightGuard, OverloadGuard};
pub use detector::{Detector, DetectorVerdict, PerIpDetector};
pub use metrics::{DdosMetrics, DdosMetricsSnapshot};
pub use reload::DdosReloader;
pub use store::{CounterStore, MemoryCounterStore};

/// Per-tier `DDoS` threshold configuration.
#[derive(Clone, Debug)]
pub struct DdosTierCfg {
    /// Per-fingerprint request threshold (e.g., per-IP).
    pub per_fp_threshold: u32,
    /// Window in seconds for per-fingerprint threshold.
    pub per_fp_window_s: u32,
    /// Aggregate tier-wide request threshold.
    pub per_tier_threshold: u32,
    /// Window in seconds for tier-wide threshold.
    pub per_tier_window_s: u32,
}

/// Runtime `DDoS` configuration snapshot.
///
/// Validated and converted from `DdosFileConfig`. Maps each protection tier
/// to its thresholds. Tiers without an explicit entry are not `DDoS`-protected.
#[derive(Clone, Debug)]
pub struct DdosConfig {
    /// Per-tier `DDoS` configurations. Missing tiers ⇒ no `DDoS` check.
    pub tiers: HashMap<Tier, DdosTierCfg>,
    /// GC interval in seconds for counter cleanup.
    pub gc_interval_s: u32,
    /// Maximum keys before LRU eviction in GC pass.
    pub max_keys: usize,
}

impl DdosConfig {
    /// Look up the `DDoS` cfg for a given tier, if any.
    #[must_use]
    pub fn for_tier(&self, tier: Tier) -> Option<&DdosTierCfg> {
        self.tiers.get(&tier)
    }
}

impl Default for DdosConfig {
    /// Empty config — no tiers protected. Real config wired in later phases;
    /// this default keeps the check inert when registered into the pipeline.
    fn default() -> Self {
        Self {
            tiers: HashMap::new(),
            gc_interval_s: 60,
            max_keys: 100_000,
        }
    }
}
