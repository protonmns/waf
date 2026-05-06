//! Shared test harness for FR-005 `DDoS` scenario tests.
//!
//! Provides utilities to:
//! - Bootstrap `DdosCheck` with in-memory stores
//! - Build synthetic `RequestCtx` instances
//! - Control time via `MockClock`
//! - Rotate IPs for distributed attack simulation

// Test code uses casts that are safe within test ranges
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
// Test harness provides helpers that may not all be used in every scenario
#![allow(dead_code)]
#![allow(clippy::missing_const_for_fn)] // Test code doesn't benefit from const
#![allow(clippy::doc_markdown)] // Allow DDoS without backticks in docs

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use arc_swap::ArcSwap;
use bytes::Bytes;
use waf_common::tier::{FailMode, Tier, TierPolicy};
use waf_common::{HostConfig, RequestCtx};

use waf_engine::checks::Check;
use waf_engine::checks::ddos::action::{BanAction, CombinedAction, DynamicBanTable};
use waf_engine::checks::ddos::degrade::OverloadGuard;
use waf_engine::checks::ddos::detector::per_ip::PerIpDetector;
use waf_engine::checks::ddos::detector::per_tier::PerTierDetector;
use waf_engine::checks::ddos::metrics::DdosMetrics;
use waf_engine::checks::ddos::store::MemoryCounterStore;
use waf_engine::checks::ddos::{DdosCheck, DdosConfig, DdosTierCfg, Detector};
use waf_engine::checks::rate_limit::RateLimitStore;
use waf_engine::checks::rate_limit::store::MemoryStore as RateLimitMemoryStore;

// Re-export scenario test modules
pub mod a_baseline_no_block;
pub mod b_single_ip_flood;
pub mod c_botnet_same_fp;
pub mod d_tier_burst_failmode;
pub mod e_redis_down_failmode;

// ─────────────────────────────────────────────────────────────────────────────
// Mock Clock (thread-safe, test-only)
// ─────────────────────────────────────────────────────────────────────────────

/// Mock clock for deterministic time control in tests.
pub struct MockClock {
    time_ms: AtomicI64,
}

impl MockClock {
    pub fn new(initial_ms: i64) -> Self {
        Self {
            time_ms: AtomicI64::new(initial_ms),
        }
    }

    pub fn now_ms(&self) -> i64 {
        self.time_ms.load(Ordering::Relaxed)
    }

    pub fn set_ms(&self, ms: i64) {
        self.time_ms.store(ms, Ordering::Relaxed);
    }

    pub fn advance_ms(&self, delta: i64) {
        self.time_ms.fetch_add(delta, Ordering::Relaxed);
    }
}

impl waf_engine::checks::ddos::detector::clock::Clock for MockClock {
    fn now_ms(&self) -> i64 {
        self.time_ms.load(Ordering::Relaxed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test Harness
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the test harness.
pub struct HarnessConfig {
    /// Per-fingerprint threshold (default: 50)
    pub per_fp_threshold: u32,
    /// Per-fingerprint window in seconds (default: 60)
    pub per_fp_window_s: u32,
    /// Per-tier threshold (default: 1000)
    pub per_tier_threshold: u32,
    /// Per-tier window in seconds (default: 60)
    pub per_tier_window_s: u32,
    /// Overload guard threshold (default: 1000)
    pub overload_threshold: usize,
    /// Tier to configure (default: Medium)
    pub tier: Tier,
    /// Fail mode for tier policy (default: Open)
    pub fail_mode: FailMode,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            per_fp_threshold: 50,
            per_fp_window_s: 60,
            per_tier_threshold: 1000,
            per_tier_window_s: 60,
            overload_threshold: 1000,
            tier: Tier::Medium,
            fail_mode: FailMode::Open,
        }
    }
}

/// Test harness providing bootstrapped DDoS check with in-memory stores.
pub struct DdosTestHarness {
    pub check: DdosCheck,
    pub ban_table: Arc<DynamicBanTable>,
    pub metrics: Arc<DdosMetrics>,
    pub clock: Arc<MockClock>,
    pub config: HarnessConfig,
}

impl DdosTestHarness {
    /// Create a new harness with default configuration.
    pub fn new() -> Self {
        Self::with_config(HarnessConfig::default())
    }

    /// Create a new harness with custom configuration.
    pub fn with_config(config: HarnessConfig) -> Self {
        let clock = Arc::new(MockClock::new(0));

        // Build tier config
        let mut tiers = HashMap::new();
        tiers.insert(
            config.tier,
            DdosTierCfg {
                per_fp_threshold: config.per_fp_threshold,
                per_fp_window_s: config.per_fp_window_s,
                per_tier_threshold: config.per_tier_threshold,
                per_tier_window_s: config.per_tier_window_s,
            },
        );

        let ddos_cfg = Arc::new(ArcSwap::from(Arc::new(DdosConfig {
            tiers,
            gc_interval_s: 60,
            max_keys: 100_000,
        })));

        // Create stores
        let counter_store: Arc<dyn waf_engine::checks::ddos::CounterStore> =
            Arc::new(MemoryCounterStore::new(100_000, 60));
        let rate_limit_store: Arc<dyn RateLimitStore> = Arc::new(RateLimitMemoryStore::new());

        // Create detectors
        let per_ip_detector = PerIpDetector::new(Arc::clone(&rate_limit_store));
        let per_tier_detector = PerTierDetector::with_defaults(
            Arc::clone(&counter_store),
            Arc::clone(&clock) as Arc<dyn waf_engine::checks::ddos::detector::clock::Clock>,
        );

        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(per_ip_detector), Box::new(per_tier_detector)];

        // Create ban table and action
        let ban_table = Arc::new(DynamicBanTable::new());
        let ban_action = BanAction::with_defaults(Arc::clone(&ban_table), Arc::clone(&counter_store));
        let action = Arc::new(CombinedAction::new(vec![Box::new(ban_action)]));

        // Create guard and metrics
        let guard = Arc::new(OverloadGuard::new(config.overload_threshold));
        let metrics = Arc::new(DdosMetrics::new());

        let check = DdosCheck::new(
            ddos_cfg,
            detectors,
            action,
            guard,
            Arc::clone(&ban_table),
            Arc::clone(&metrics),
        );

        Self {
            check,
            ban_table,
            metrics,
            clock,
            config,
        }
    }

    /// Run a single request through the check.
    pub fn check(&self, ctx: &RequestCtx) -> Option<waf_common::DetectionResult> {
        self.check.check(ctx)
    }

    /// Check if an IP is currently banned.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.ban_table.contains(ip, self.clock.now_ms())
    }
}

impl Default for DdosTestHarness {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Request Context Builder
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for synthetic `RequestCtx` instances.
pub struct CtxBuilder {
    ip: IpAddr,
    tier: Tier,
    fail_mode: FailMode,
    method: String,
    path: String,
    headers: HashMap<String, String>,
}

impl CtxBuilder {
    pub fn new() -> Self {
        Self {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            tier: Tier::Medium,
            fail_mode: FailMode::Open,
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: HashMap::new(),
        }
    }

    pub fn ip(mut self, ip: &str) -> Self {
        self.ip = ip.parse().expect("valid IP");
        self
    }

    pub fn ip_addr(mut self, ip: IpAddr) -> Self {
        self.ip = ip;
        self
    }

    pub fn tier(mut self, tier: Tier) -> Self {
        self.tier = tier;
        self
    }

    pub fn fail_mode(mut self, mode: FailMode) -> Self {
        self.fail_mode = mode;
        self
    }

    pub fn method(mut self, method: &str) -> Self {
        self.method = method.to_string();
        self
    }

    pub fn path(mut self, path: &str) -> Self {
        self.path = path.to_string();
        self
    }

    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn build(self) -> RequestCtx {
        RequestCtx {
            req_id: format!("test-{}", uuid_lite()),
            client_ip: self.ip,
            client_port: 12345,
            method: self.method,
            host: "test.example.com".to_string(),
            port: 443,
            path: self.path,
            query: String::new(),
            headers: self.headers,
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: true,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
            tier: self.tier,
            tier_policy: Arc::new(TierPolicy {
                fail_mode: self.fail_mode,
                ..TierPolicy::default()
            }),
            cookies: HashMap::new(),
        }
    }
}

impl Default for CtxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IP Rotation Helper
// ─────────────────────────────────────────────────────────────────────────────

/// Generates sequential IPs for distributed attack simulation.
pub struct IpRotator {
    base: u32,
    count: u32,
    current: u32,
}

impl IpRotator {
    /// Create a rotator starting from base IP, cycling through `count` IPs.
    pub fn new(base_ip: &str, count: u32) -> Self {
        let ip: Ipv4Addr = base_ip.parse().expect("valid IPv4");
        Self {
            base: u32::from(ip),
            count,
            current: 0,
        }
    }

    /// Get next IP in rotation.
    pub fn next_ip(&mut self) -> IpAddr {
        let ip = Ipv4Addr::from(self.base + self.current);
        self.current = (self.current + 1) % self.count;
        IpAddr::V4(ip)
    }

    /// Reset rotation to start.
    pub fn reset(&mut self) {
        self.current = 0;
    }
}

impl Iterator for IpRotator {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_ip())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a simple unique ID (not cryptographically secure, just for test IDs).
fn uuid_lite() -> String {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{n:016x}")
}

/// Measure wall-clock execution time of a closure.
pub fn measure_time<F, T>(f: F) -> (T, std::time::Duration)
where
    F: FnOnce() -> T,
{
    let start = std::time::Instant::now();
    let result = f();
    (result, start.elapsed())
}
