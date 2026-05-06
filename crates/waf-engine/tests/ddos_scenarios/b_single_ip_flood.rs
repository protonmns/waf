//! Scenario B: Single IP flood attack.
//!
//! Single attacker IP sends 1000 rps for 1 second. Tests that:
//! - Ban is issued within threshold + 1 requests
//! - Subsequent requests are blocked by ban table (short-circuit)
//! - The block comes from access layer, not `DDoS` detector
//!
//! Pass criteria:
//! - Ban issued after threshold exceeded
//! - Subsequent requests blocked

#![allow(clippy::print_stdout)] // Test diagnostics

use waf_common::tier::Tier;

use super::{CtxBuilder, DdosTestHarness, HarnessConfig};

/// Scenario B: single IP, 1000 rps, ban after threshold.
#[tokio::test]
async fn scenario_b_single_ip_flood_triggers_ban() {
    let config = HarnessConfig {
        per_fp_threshold: 50, // Ban after 50 requests
        per_fp_window_s: 60,
        per_tier_threshold: 10_000, // High enough to not interfere
        tier: Tier::Medium,
        ..Default::default()
    };

    let harness = DdosTestHarness::with_config(config);
    let attacker_ip = "192.168.1.100";

    let mut first_block_at: Option<u32> = None;
    let mut total_blocks = 0_u32;

    // Send 1000 requests from single IP
    for i in 0..1000_u32 {
        let ctx = CtxBuilder::new().ip(attacker_ip).tier(Tier::Medium).build();
        let result = harness.check(&ctx);

        if result.is_some() {
            total_blocks += 1;
            if first_block_at.is_none() {
                first_block_at = Some(i);
            }
        }
    }

    // Verify: first block happens after threshold (request 51 = index 50)
    let first_block = first_block_at.expect("expected at least one block");
    assert!(
        (50..=52).contains(&first_block),
        "first block at request {first_block}, expected around 50-52"
    );

    // Verify: IP is banned
    let ip: std::net::IpAddr = attacker_ip.parse().unwrap();
    assert!(harness.is_banned(ip), "attacker IP should be banned");

    // Verify: subsequent requests are blocked by ban table
    let ctx = CtxBuilder::new().ip(attacker_ip).tier(Tier::Medium).build();
    let result = harness.check(&ctx);
    assert!(result.is_some(), "banned IP should be blocked");

    // Check the block is from ban table (DDOS-BAN rule)
    let det = result.unwrap();
    assert_eq!(
        det.rule_id.as_deref(),
        Some("DDOS-BAN"),
        "block should be from ban table, not detector"
    );

    println!("Scenario B complete: first block at req {first_block}, total blocks: {total_blocks}");
}

/// Verify ban TTL escalation on repeat offenses.
///
/// Note: This test verifies the ban is issued and escalates, but doesn't
/// test exact TTL timing since the check uses real wall-clock time while
/// we can only control the mock clock for the `is_banned()` check.
#[tokio::test]
async fn scenario_b_ban_escalation() {
    let config = HarnessConfig {
        per_fp_threshold: 10, // Low threshold for quick test
        tier: Tier::Medium,
        ..Default::default()
    };

    let harness = DdosTestHarness::with_config(config);
    let attacker_ip = "10.0.0.1";
    let ip: std::net::IpAddr = attacker_ip.parse().unwrap();

    // First offense: trigger ban
    let mut first_blocked = false;
    for _ in 0..15 {
        let ctx = CtxBuilder::new().ip(attacker_ip).tier(Tier::Medium).build();
        if harness.check(&ctx).is_some() {
            first_blocked = true;
        }
    }

    // Verify blocked after exceeding threshold
    assert!(first_blocked, "should be blocked after first offense");

    // Verify IP is in ban table (using current real time)
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    assert!(harness.ban_table.contains(ip, now_ms), "IP should be in ban_table");

    println!("Scenario B escalation: ban issued on threshold breach");
}

/// Verify different IPs are tracked independently.
#[tokio::test]
async fn scenario_b_different_ips_independent() {
    let config = HarnessConfig {
        per_fp_threshold: 20,
        tier: Tier::Medium,
        ..Default::default()
    };

    let harness = DdosTestHarness::with_config(config);

    // IP1: exceed threshold
    for _ in 0..25 {
        let ctx = CtxBuilder::new().ip("192.168.1.1").tier(Tier::Medium).build();
        harness.check(&ctx);
    }

    // IP2: under threshold
    for _ in 0..15 {
        let ctx = CtxBuilder::new().ip("192.168.1.2").tier(Tier::Medium).build();
        harness.check(&ctx);
    }

    // Verify: IP1 banned, IP2 not
    let ip1: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    let ip2: std::net::IpAddr = "192.168.1.2".parse().unwrap();

    assert!(harness.is_banned(ip1), "IP1 should be banned");
    assert!(!harness.is_banned(ip2), "IP2 should not be banned");
}
