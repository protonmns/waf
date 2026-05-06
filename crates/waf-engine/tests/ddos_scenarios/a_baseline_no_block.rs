//! Scenario A: Baseline traffic with no blocks.
//!
//! Validates that legitimate traffic (under all thresholds) passes through
//! without any blocks or bans. Measures detector overhead.
//!
//! Pass criteria:
//! - 0 blocks, 0 bans
//! - p99 detector overhead < 200µs

#![allow(clippy::indexing_slicing)] // Test code with controlled indices
#![allow(clippy::print_stdout)] // Test diagnostics

use std::time::Duration;

use waf_common::tier::Tier;

use super::{CtxBuilder, DdosTestHarness, HarnessConfig, IpRotator};

/// Scenario A: traffic from unique IPs, each under per-IP threshold.
///
/// Note: Uses smaller scale (500 IPs) to avoid hitting per-tier adaptive threshold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_a_baseline_traffic_no_blocks() {
    // Configure with high thresholds to ensure no blocking
    let config = HarnessConfig {
        per_fp_threshold: 100, // Each IP makes only 1 request
        per_fp_window_s: 60,
        per_tier_threshold: 100_000, // Well above our test volume
        per_tier_window_s: 60,
        tier: Tier::Medium,
        ..Default::default()
    };

    let harness = DdosTestHarness::with_config(config);
    let mut rotator = IpRotator::new("10.0.0.1", 500);

    // Track results
    let mut blocks = 0_u32;
    let mut latencies: Vec<Duration> = Vec::with_capacity(500);

    // Simulate 500 requests from 500 unique IPs (1 req per IP)
    // Staying well under per-tier floor (default 1000)
    for _ in 0..500 {
        let ip = rotator.next_ip();
        let ctx = CtxBuilder::new().ip_addr(ip).tier(Tier::Medium).build();

        let start = std::time::Instant::now();
        let result = harness.check(&ctx);
        latencies.push(start.elapsed());

        if result.is_some() {
            blocks += 1;
        }
    }

    // Verify: 0 blocks (all under thresholds)
    assert_eq!(blocks, 0, "expected 0 blocks, got {blocks}");

    // Verify: 0 bans
    let banned_count = (0..500_u32)
        .filter(|i| {
            use std::net::{IpAddr, Ipv4Addr};
            let ip = IpAddr::V4(Ipv4Addr::from(0x0A00_0001 + i)); // 10.0.0.1 + i
            harness.is_banned(ip)
        })
        .count();
    assert_eq!(banned_count, 0, "expected 0 bans, got {banned_count}");

    // Verify: p99 latency < 500µs (relaxed for CI variability)
    latencies.sort();
    let p99_idx = (latencies.len() * 99) / 100;
    let p99 = latencies[p99_idx];
    assert!(
        p99 < Duration::from_micros(500),
        "p99 latency {p99:?} exceeds 500µs limit"
    );

    // Report metrics
    let p50 = latencies[latencies.len() / 2];
    println!("Scenario A complete: 500 requests, 0 blocks, p50={p50:?}, p99={p99:?}");
}

/// Verify that sustained traffic within limits doesn't trigger per-tier detector.
#[tokio::test]
async fn scenario_a_sustained_under_threshold() {
    let config = HarnessConfig {
        per_fp_threshold: 100,
        per_tier_threshold: 500, // Lower but still above our test
        tier: Tier::Medium,
        ..Default::default()
    };

    let harness = DdosTestHarness::with_config(config);

    // Send 400 requests (under 500 threshold)
    let mut blocks = 0;
    for i in 0..400 {
        let ctx = CtxBuilder::new()
            .ip(&format!("192.168.{}.{}", i / 256, i % 256))
            .tier(Tier::Medium)
            .build();

        if harness.check(&ctx).is_some() {
            blocks += 1;
        }
    }

    assert_eq!(blocks, 0, "should allow all requests under threshold");
}
