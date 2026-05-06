//! Scenario C: Botnet attack with same fingerprint.
//!
//! Simulates a botnet where 1000 IPs share the same device fingerprint
//! (common in credential stuffing attacks using the same automation tool).
//!
//! NOTE: Per-fingerprint detection requires `RequestCtx.device_fp` field,
//! which is wired in phase 7. This test validates the per-IP fallback
//! behavior when fingerprint detection is not available.
//!
//! Pass criteria:
//! - Per-IP bans triggered for each attacking IP
//! - High ban rate when attacks detected

#![allow(clippy::print_stdout)] // Test diagnostics

use waf_common::tier::Tier;

use super::{CtxBuilder, DdosTestHarness, HarnessConfig, IpRotator};

/// Scenario C: 1000 IPs, same fingerprint (simulated via header).
///
/// Since per-FP detection requires `device_fp` field not yet wired,
/// this test validates per-IP detection handles distributed attacks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scenario_c_botnet_same_fp_per_ip_fallback() {
    let config = HarnessConfig {
        per_fp_threshold: 30, // Each IP gets 30 requests before ban
        per_tier_threshold: 50_000,
        tier: Tier::Medium,
        ..Default::default()
    };

    let harness = DdosTestHarness::with_config(config);
    let botnet_fp = "ja4-botnet-abc123";

    // 100 IPs, 40 requests each (above per-IP threshold of 30)
    let ip_count = 100_u32;
    let requests_per_ip = 40_u32;
    let mut rotator = IpRotator::new("172.16.0.1", ip_count);

    let mut banned_ips = 0_u32;

    for _ in 0..ip_count {
        let ip = rotator.next_ip();

        // Send requests from this IP
        for _ in 0..requests_per_ip {
            let ctx = CtxBuilder::new()
                .ip_addr(ip)
                .tier(Tier::Medium)
                .header("x-device-fp", botnet_fp) // Shared fingerprint
                .build();

            harness.check(&ctx);
        }

        // Check if this IP got banned
        if harness.is_banned(ip) {
            banned_ips += 1;
        }
    }

    // Verify: majority of attacking IPs are banned
    let ban_rate = f64::from(banned_ips) / f64::from(ip_count);
    assert!(
        ban_rate > 0.90,
        "expected >90% of IPs banned, got {ban_rate:.2} ({banned_ips}/{ip_count})"
    );

    println!("Scenario C complete: {banned_ips}/{ip_count} IPs banned (rate: {ban_rate:.2})");
}

/// Verify that legitimate IPs aren't caught in botnet detection.
#[tokio::test]
async fn scenario_c_legitimate_traffic_not_affected() {
    let config = HarnessConfig {
        per_fp_threshold: 50,
        tier: Tier::Medium,
        ..Default::default()
    };

    let harness = DdosTestHarness::with_config(config);

    // Legitimate user: single IP, moderate traffic
    let legit_ip = "10.0.0.1";
    for _ in 0..30 {
        let ctx = CtxBuilder::new()
            .ip(legit_ip)
            .tier(Tier::Medium)
            .header("x-device-fp", "ja4-legitimate-user")
            .build();
        harness.check(&ctx);
    }

    // Verify: legitimate IP not banned
    let ip: std::net::IpAddr = legit_ip.parse().unwrap();
    assert!(!harness.is_banned(ip), "legitimate user should not be banned");

    // Attacker: exceed threshold
    let attacker_ip = "10.0.0.2";
    for _ in 0..60 {
        let ctx = CtxBuilder::new()
            .ip(attacker_ip)
            .tier(Tier::Medium)
            .header("x-device-fp", "ja4-attacker")
            .build();
        harness.check(&ctx);
    }

    // Verify: attacker banned, legitimate user still not banned
    let attacker: std::net::IpAddr = attacker_ip.parse().unwrap();
    assert!(harness.is_banned(attacker), "attacker should be banned");
    assert!(!harness.is_banned(ip), "legitimate user still should not be banned");
}

/// Test concurrent attack from multiple IPs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_c_concurrent_attack() {
    use std::sync::Arc;

    let config = HarnessConfig {
        per_fp_threshold: 20,
        per_tier_threshold: 100_000,
        tier: Tier::Medium,
        ..Default::default()
    };

    let harness = Arc::new(DdosTestHarness::with_config(config));

    // Spawn concurrent attackers
    let mut handles = Vec::with_capacity(10);
    for attacker_id in 0..10_u8 {
        let h = Arc::clone(&harness);
        handles.push(tokio::spawn(async move {
            let ip_str = format!("192.168.{attacker_id}.1");

            // Each attacker sends 30 requests (above threshold of 20)
            for _ in 0..30 {
                let ctx = CtxBuilder::new().ip(&ip_str).tier(Tier::Medium).build();
                h.check(&ctx);
            }

            ip_str
        }));
    }

    // Wait for all attackers to finish
    let mut ips = Vec::new();
    for h in handles {
        ips.push(h.await.unwrap());
    }

    // Verify: all attackers should be banned
    let banned = ips
        .iter()
        .filter(|ip| {
            let addr: std::net::IpAddr = ip.parse().unwrap();
            harness.is_banned(addr)
        })
        .count();

    assert_eq!(banned, 10, "all 10 concurrent attackers should be banned, got {banned}");
}
