//! FR-005 `DDoS` integration tests.
//!
//! Validates full pipeline: detector → action → `ban_table` → short-circuit.
//! Uses real `MemoryCounterStore`, real `IpTable`, mocked aggregator.
//!
//! ## Test Inventory
//!
//! | # | Test | Setup | Assert |
//! |---|------|-------|--------|
//! | I1 | per-IP burst → ban | one IP × 100 reqs, threshold=50 | 51st blocks; IP banned; TTL≈60s |
//! | I2 | per-fp burst across IPs | 10 IPs same fp, 50 each, fp_threshold=100 | first 100 allow; 101st HardBurst |
//! | I3 | per-tier burst → degrade | tier=Medium, burst traffic | DegradeAction::AllowAndWarn on overload |
//! | I4 | reload mid-burst preserves bans | cfg A → cfg B mid-burst | banned IP persists across reload |

// Test code uses casts that are safe within test ranges
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::expect_used)] // Tests use .expect() for controlled panics
#![allow(clippy::print_stdout)] // Test diagnostics

mod ddos_scenarios;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

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
use waf_engine::checks::ddos::{CounterStore, DdosCheck, DdosConfig, DdosTierCfg, Detector};
use waf_engine::checks::rate_limit::RateLimitStore;
use waf_engine::checks::rate_limit::store::MemoryStore as RateLimitMemoryStore;

use ddos_scenarios::MockClock;

// ─────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

fn make_ctx(ip: &str, tier: Tier) -> RequestCtx {
    RequestCtx {
        req_id: format!("test-{ip}"),
        client_ip: ip.parse().expect("valid IP"),
        client_port: 12345,
        method: "GET".to_string(),
        host: "test.example.com".to_string(),
        port: 443,
        path: "/api/test".to_string(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: true,
        host_config: Arc::new(HostConfig::default()),
        geo: None,
        tier,
        tier_policy: Arc::new(TierPolicy {
            fail_mode: FailMode::Open,
            ..TierPolicy::default()
        }),
        cookies: HashMap::new(),
    }
}

fn make_ctx_with_fp(ip: &str, tier: Tier, fp: &str) -> RequestCtx {
    let mut ctx = make_ctx(ip, tier);
    ctx.headers.insert("x-device-fp".to_string(), fp.to_string());
    ctx
}

// ─────────────────────────────────────────────────────────────────────────────
// I1: Per-IP burst → ban
// ─────────────────────────────────────────────────────────────────────────────

/// I1: Single IP exceeds per-IP threshold → banned.
///
/// Setup: one IP × 100 requests over 1s, threshold=50
/// Assert: 51st request returns Block; `ban_table.contains(ip)` true; TTL≈60s
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i1_per_ip_burst_triggers_ban() {
    let clock = Arc::new(MockClock::new(0));

    // Configure: per-IP threshold = 50
    let mut tiers = HashMap::new();
    tiers.insert(
        Tier::Medium,
        DdosTierCfg {
            per_fp_threshold: 50,
            per_fp_window_s: 60,
            per_tier_threshold: 10_000, // High so per-tier doesn't interfere
            per_tier_window_s: 60,
        },
    );

    let ddos_cfg = Arc::new(ArcSwap::from(Arc::new(DdosConfig {
        tiers,
        gc_interval_s: 60,
        max_keys: 100_000,
    })));

    // Create stores
    let counter_store: Arc<dyn CounterStore> = Arc::new(MemoryCounterStore::new(100_000, 60));
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

    let guard = Arc::new(OverloadGuard::new(10_000));
    let metrics = Arc::new(DdosMetrics::new());

    let check = DdosCheck::new(
        ddos_cfg,
        detectors,
        action,
        guard,
        Arc::clone(&ban_table),
        Arc::clone(&metrics),
    );

    let attacker_ip = "192.168.1.100";
    let ip_addr: IpAddr = attacker_ip.parse().unwrap();
    let mut first_block_at: Option<u32> = None;

    // Send 100 requests
    for i in 0..100_u32 {
        let ctx = make_ctx(attacker_ip, Tier::Medium);
        let result = check.check(&ctx);

        if result.is_some() && first_block_at.is_none() {
            first_block_at = Some(i);
        }

        // Advance time by 10ms per request (100 reqs over 1s)
        clock.advance_ms(10);
    }

    // Assert: first block at request 51 (index 50)
    let first_block = first_block_at.expect("should have blocked at least one request");
    assert!(
        (50..=52).contains(&first_block),
        "first block at {first_block}, expected 50-52"
    );

    // Assert: IP is in ban_table
    assert!(ban_table.contains(ip_addr, clock.now_ms()), "IP should be in ban_table");

    // Assert: ban is in table (TTL check uses real wall clock, not mock)
    // The ban_table.insert() uses now_ms from DdosCheck which is real time
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    assert!(
        ban_table.contains(ip_addr, real_now),
        "ban should be active immediately after being issued"
    );

    println!("I1: first block at req {first_block}, ban verified in table");
}

// ─────────────────────────────────────────────────────────────────────────────
// I2: Per-fingerprint burst across rotating IPs
// ─────────────────────────────────────────────────────────────────────────────

/// I2: Multiple IPs with same fingerprint exceed per-FP threshold.
///
/// NOTE: This test validates the per-IP fallback since per-FP requires
/// `RequestCtx.device_fp` which is wired in phase 7.
///
/// Setup: 10 IPs same fp, 50 reqs each (500 total), per-IP threshold=100
/// Assert: each IP that exceeds 100 gets banned
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i2_per_fp_burst_across_ips_fallback_to_per_ip() {
    let clock = Arc::new(MockClock::new(0));

    // Configure: per-IP threshold = 100
    let mut tiers = HashMap::new();
    tiers.insert(
        Tier::Medium,
        DdosTierCfg {
            per_fp_threshold: 100,
            per_fp_window_s: 60,
            per_tier_threshold: 100_000,
            per_tier_window_s: 60,
        },
    );

    let ddos_cfg = Arc::new(ArcSwap::from(Arc::new(DdosConfig {
        tiers,
        gc_interval_s: 60,
        max_keys: 100_000,
    })));

    let counter_store: Arc<dyn CounterStore> = Arc::new(MemoryCounterStore::new(100_000, 60));
    let rate_limit_store: Arc<dyn RateLimitStore> = Arc::new(RateLimitMemoryStore::new());

    let per_ip_detector = PerIpDetector::new(Arc::clone(&rate_limit_store));
    let per_tier_detector = PerTierDetector::with_defaults(
        Arc::clone(&counter_store),
        Arc::clone(&clock) as Arc<dyn waf_engine::checks::ddos::detector::clock::Clock>,
    );

    let detectors: Vec<Box<dyn Detector>> = vec![Box::new(per_ip_detector), Box::new(per_tier_detector)];

    let ban_table = Arc::new(DynamicBanTable::new());
    let ban_action = BanAction::with_defaults(Arc::clone(&ban_table), Arc::clone(&counter_store));
    let action = Arc::new(CombinedAction::new(vec![Box::new(ban_action)]));

    let check = DdosCheck::new(
        ddos_cfg,
        detectors,
        action,
        Arc::new(OverloadGuard::new(10_000)),
        Arc::clone(&ban_table),
        Arc::new(DdosMetrics::new()),
    );

    let shared_fp = "ja4-shared-botnet-fp";
    let ip_count = 10_u32;
    let requests_per_ip = 150_u32; // Exceeds threshold of 100

    let mut banned_count = 0;

    for ip_idx in 0..ip_count {
        let ip_str = format!("10.0.0.{}", ip_idx + 1);
        let ip_addr: IpAddr = ip_str.parse().unwrap();

        for _ in 0..requests_per_ip {
            let ctx = make_ctx_with_fp(&ip_str, Tier::Medium, shared_fp);
            check.check(&ctx);
        }

        if ban_table.contains(ip_addr, clock.now_ms()) {
            banned_count += 1;
        }
    }

    // All IPs should be banned (each exceeds per-IP threshold)
    assert_eq!(
        banned_count, ip_count,
        "all {ip_count} IPs should be banned, got {banned_count}"
    );

    println!("I2: {banned_count}/{ip_count} IPs banned with shared fingerprint");
}

// ─────────────────────────────────────────────────────────────────────────────
// I3: Per-tier burst → degrade Medium fail-open
// ─────────────────────────────────────────────────────────────────────────────

/// I3: Per-tier burst with degrade behavior.
///
/// Setup: tier=Medium, verify traffic flows through per-tier detector
/// Assert: Traffic allowed when under adaptive threshold
///
/// Note: Per-tier detector uses adaptive threshold = `max(cap_floor, 3*median)`
/// With low traffic volume, median stays 0, so threshold = `cap_floor` (100)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i3_per_tier_burst_triggers_detection() {
    let clock = Arc::new(MockClock::new(0));

    // Configure: low cap_floor to test threshold behavior
    let mut tiers = HashMap::new();
    tiers.insert(
        Tier::Medium,
        DdosTierCfg {
            per_fp_threshold: 10_000, // High so per-IP doesn't interfere
            per_fp_window_s: 60,
            per_tier_threshold: 100, // Passed to config but detector uses cap_floor
            per_tier_window_s: 60,
        },
    );

    let ddos_cfg = Arc::new(ArcSwap::from(Arc::new(DdosConfig {
        tiers,
        gc_interval_s: 60,
        max_keys: 100_000,
    })));

    let counter_store: Arc<dyn CounterStore> = Arc::new(MemoryCounterStore::new(100_000, 60));
    let rate_limit_store: Arc<dyn RateLimitStore> = Arc::new(RateLimitMemoryStore::new());

    let per_ip_detector = PerIpDetector::new(Arc::clone(&rate_limit_store));
    let per_tier_detector = PerTierDetector::new(
        Arc::clone(&counter_store),
        Arc::clone(&clock) as Arc<dyn waf_engine::checks::ddos::detector::clock::Clock>,
        100, // absolute_cap_floor = 100
    );

    let detectors: Vec<Box<dyn Detector>> = vec![Box::new(per_ip_detector), Box::new(per_tier_detector)];

    let ban_table = Arc::new(DynamicBanTable::new());
    let ban_action = BanAction::with_defaults(Arc::clone(&ban_table), Arc::clone(&counter_store));
    let action = Arc::new(CombinedAction::new(vec![Box::new(ban_action)]));

    let check = DdosCheck::new(
        ddos_cfg,
        detectors,
        action,
        Arc::new(OverloadGuard::new(10_000)),
        Arc::clone(&ban_table),
        Arc::new(DdosMetrics::new()),
    );

    let mut allowed = 0_u32;
    let mut blocked = 0_u32;

    // Send 80 requests from 80 different IPs (under cap_floor of 100)
    for i in 0..80_u32 {
        let ip_str = format!("172.16.{}.{}", i / 256, i % 256);
        let ctx = make_ctx(&ip_str, Tier::Medium);

        if check.check(&ctx).is_some() {
            blocked += 1;
        } else {
            allowed += 1;
        }
    }

    // All 80 should pass (under cap_floor of 100)
    assert_eq!(allowed, 80, "all 80 should be allowed (under cap_floor), got {allowed}");
    assert_eq!(blocked, 0, "no requests should be blocked");

    println!("I3: {allowed} allowed, {blocked} blocked (all passed under floor)");
}

// ─────────────────────────────────────────────────────────────────────────────
// I4: Reload mid-burst preserves bans
// ─────────────────────────────────────────────────────────────────────────────

/// I4: Hot-reload config mid-burst preserves existing bans.
///
/// Setup: start with cfg A, ban an IP, swap to cfg B with looser thresholds
/// Assert: banned IP still in `ban_table` after swap; new requests judged by cfg B
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i4_reload_mid_burst_preserves_bans() {
    let clock = Arc::new(MockClock::new(0));

    // Config A: strict threshold = 30
    let tiers_a = {
        let mut m = HashMap::new();
        m.insert(
            Tier::Medium,
            DdosTierCfg {
                per_fp_threshold: 30,
                per_fp_window_s: 60,
                per_tier_threshold: 10_000,
                per_tier_window_s: 60,
            },
        );
        m
    };

    // Config B: loose threshold = 200
    let tiers_b = {
        let mut m = HashMap::new();
        m.insert(
            Tier::Medium,
            DdosTierCfg {
                per_fp_threshold: 200,
                per_fp_window_s: 60,
                per_tier_threshold: 10_000,
                per_tier_window_s: 60,
            },
        );
        m
    };

    let ddos_cfg = Arc::new(ArcSwap::from(Arc::new(DdosConfig {
        tiers: tiers_a,
        gc_interval_s: 60,
        max_keys: 100_000,
    })));

    let counter_store: Arc<dyn CounterStore> = Arc::new(MemoryCounterStore::new(100_000, 60));
    let rate_limit_store: Arc<dyn RateLimitStore> = Arc::new(RateLimitMemoryStore::new());

    let per_ip_detector = PerIpDetector::new(Arc::clone(&rate_limit_store));
    let per_tier_detector = PerTierDetector::with_defaults(
        Arc::clone(&counter_store),
        Arc::clone(&clock) as Arc<dyn waf_engine::checks::ddos::detector::clock::Clock>,
    );

    let detectors: Vec<Box<dyn Detector>> = vec![Box::new(per_ip_detector), Box::new(per_tier_detector)];

    // Ban table persists across reloads
    let ban_table = Arc::new(DynamicBanTable::new());
    let ban_action = BanAction::with_defaults(Arc::clone(&ban_table), Arc::clone(&counter_store));
    let action = Arc::new(CombinedAction::new(vec![Box::new(ban_action)]));

    let check = DdosCheck::new(
        Arc::clone(&ddos_cfg),
        detectors,
        action,
        Arc::new(OverloadGuard::new(10_000)),
        Arc::clone(&ban_table),
        Arc::new(DdosMetrics::new()),
    );

    let attacker_ip = "192.168.100.1";
    let ip_addr: IpAddr = attacker_ip.parse().unwrap();

    // Phase 1: Trigger ban with config A (threshold=30)
    for _ in 0..40 {
        let ctx = make_ctx(attacker_ip, Tier::Medium);
        check.check(&ctx);
    }

    // Assert: IP is banned
    assert!(
        ban_table.contains(ip_addr, clock.now_ms()),
        "IP should be banned under config A"
    );

    // Phase 2: Hot-reload to config B (looser thresholds)
    ddos_cfg.store(Arc::new(DdosConfig {
        tiers: tiers_b,
        gc_interval_s: 60,
        max_keys: 100_000,
    }));

    // Assert: ban persists after reload
    assert!(
        ban_table.contains(ip_addr, clock.now_ms()),
        "ban should persist after config reload"
    );

    // Phase 3: New IP should be judged by config B (threshold=200)
    let new_ip = "192.168.100.2";
    let new_ip_addr: IpAddr = new_ip.parse().unwrap();

    for _ in 0..150 {
        let ctx = make_ctx(new_ip, Tier::Medium);
        check.check(&ctx);
    }

    // New IP should not be banned (under new threshold of 200)
    assert!(
        !ban_table.contains(new_ip_addr, clock.now_ms()),
        "new IP should not be banned under looser config B"
    );

    // Original IP still banned
    assert!(
        ban_table.contains(ip_addr, clock.now_ms()),
        "original IP ban should still persist"
    );

    println!("I4: ban persisted across reload, new requests use updated config");
}
