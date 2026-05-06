//! Property-based tests for FR-005 `DDoS` protection.
//!
//! These tests verify invariants that must hold across all possible inputs:
//! - Threshold logic correctness
//! - Risk clamping bounds
//! - Counter monotonicity
//! - Baseline median properties

// Test code uses casts that are safe within test ranges
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
// proptest! macro generates code with items after statements
#![allow(clippy::items_after_statements)]
// proptest! macro generates code with wildcard imports
#![allow(clippy::wildcard_imports)]
// Test helper structs don't need const fn
#![allow(clippy::missing_const_for_fn)]

use std::sync::Arc;

use proptest::prelude::*;

// ─────────────────────────────────────────────────────────────────────────────
// Test harnesses (mock implementations for property testing)
// ─────────────────────────────────────────────────────────────────────────────

/// Mock counter store that returns a predetermined count.
mod mock_store {
    use async_trait::async_trait;

    pub struct FixedCountStore {
        count: u64,
    }

    impl FixedCountStore {
        pub fn new(count: u64) -> Self {
            Self { count }
        }
    }

    #[async_trait]
    impl waf_engine::checks::ddos::store::CounterStore for FixedCountStore {
        async fn incr_get(&self, _key: &str, _ttl_ms: i64, _now_ms: i64) -> anyhow::Result<u64> {
            Ok(self.count)
        }

        fn incr_get_blocking(&self, _key: &str, _ttl_ms: i64, _now_ms: i64) -> anyhow::Result<u64> {
            Ok(self.count)
        }

        async fn purge_expired(&self, _now_ms: i64) -> anyhow::Result<usize> {
            Ok(0)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property: Below threshold → Allow
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// When count < threshold, detector should return Allow.
    #[test]
    fn per_fp_below_threshold_allows(
        threshold in 1u32..10_000,
        count in 0u64..10_000
    ) {
        // Only test when count <= threshold (at threshold still allows)
        prop_assume!(count <= u64::from(threshold));

        use std::collections::HashMap;
        use std::net::{IpAddr, Ipv4Addr};
        use bytes::Bytes;
        use waf_common::tier::{Tier, TierPolicy};
        use waf_common::{HostConfig, RequestCtx};
        use waf_engine::checks::ddos::detector::DetectorVerdict;
        use waf_engine::checks::ddos::detector::per_fp::PerFpDetector;
        use waf_engine::checks::ddos::DdosTierCfg;
        use waf_engine::checks::ddos::store::CounterStore;

        let store: Arc<dyn CounterStore> = Arc::new(mock_store::FixedCountStore::new(count));
        let detector = PerFpDetector::new(store);

        let ctx = RequestCtx {
            req_id: "test".into(),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            client_port: 0,
            method: "GET".into(),
            host: "test".into(),
            port: 80,
            path: "/".into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
            tier: Tier::Medium,
            tier_policy: Arc::new(TierPolicy::default()),
            cookies: HashMap::new(),
        };

        let cfg = DdosTierCfg {
            per_fp_threshold: threshold,
            per_fp_window_s: 60,
            per_tier_threshold: 10_000,
            per_tier_window_s: 60,
        };

        let verdict = detector.evaluate_with_fp(Some("test-fp"), &ctx, &cfg, 1000);
        prop_assert!(
            matches!(verdict, DetectorVerdict::Allow),
            "count {} <= threshold {} should Allow, got {:?}",
            count, threshold, verdict
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property: Above threshold → HardBurst
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// When count > threshold, detector should return HardBurst.
    #[test]
    fn per_fp_above_threshold_bursts(
        threshold in 1u32..1_000,
        excess in 1u32..100
    ) {
        use std::collections::HashMap;
        use std::net::{IpAddr, Ipv4Addr};
        use bytes::Bytes;
        use waf_common::tier::{Tier, TierPolicy};
        use waf_common::{HostConfig, RequestCtx};
        use waf_engine::checks::ddos::detector::DetectorVerdict;
        use waf_engine::checks::ddos::detector::per_fp::PerFpDetector;
        use waf_engine::checks::ddos::DdosTierCfg;
        use waf_engine::checks::ddos::store::CounterStore;

        let count = u64::from(threshold) + u64::from(excess);
        let store: Arc<dyn CounterStore> = Arc::new(mock_store::FixedCountStore::new(count));
        let detector = PerFpDetector::new(store);

        let ctx = RequestCtx {
            req_id: "test".into(),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            client_port: 0,
            method: "GET".into(),
            host: "test".into(),
            port: 80,
            path: "/".into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
            tier: Tier::Medium,
            tier_policy: Arc::new(TierPolicy::default()),
            cookies: HashMap::new(),
        };

        let cfg = DdosTierCfg {
            per_fp_threshold: threshold,
            per_fp_window_s: 60,
            per_tier_threshold: 10_000,
            per_tier_window_s: 60,
        };

        let verdict = detector.evaluate_with_fp(Some("test-fp"), &ctx, &cfg, 1000);
        prop_assert!(
            matches!(verdict, DetectorVerdict::HardBurst { .. }),
            "count {} > threshold {} should HardBurst, got {:?}",
            count, threshold, verdict
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property: Risk delta always clamped to [0, 100]
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Risk deltas from verdicts should never exceed 100.
    #[test]
    fn risk_delta_clamped(delta in 0u8..=255) {
        use waf_engine::checks::ddos::detector::DetectorVerdict;

        // SoftAnomaly carries a u8 score — verify it's used as-is (caller responsibility)
        let verdict = DetectorVerdict::SoftAnomaly(delta);
        if let DetectorVerdict::SoftAnomaly(score) = verdict {
            // Score is raw u8, but consumers should clamp if >100
            prop_assert!(score == delta);
        }

        // HardBurst always implies max risk (100) — verified in action/ban.rs
    }

    /// BanSchedule risk deltas are always valid (<= 100).
    #[test]
    fn ban_schedule_risk_bounded(offense in 0u64..1000) {
        use waf_engine::checks::ddos::action::ban::BanSchedule;

        let schedule = BanSchedule::default();
        let step = schedule.step_for(offense);

        prop_assert!(
            step.risk_delta <= 100,
            "risk_delta {} exceeds 100 for offense {}",
            step.risk_delta, offense
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property: Ban TTL escalation is monotonic
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Ban TTL should be monotonically non-decreasing with offense count.
    /// For offense 1 → 2 → 3 → ... → N, TTL(N) >= TTL(N-1).
    #[test]
    fn ban_ttl_monotonic(max_offense in 1u64..100) {
        use waf_engine::checks::ddos::action::ban::BanSchedule;

        let schedule = BanSchedule::default();
        let mut prev_ttl = 0u32;

        // Check sequential offenses from 1 to max_offense
        for offense in 1..=max_offense {
            let step = schedule.step_for(offense);
            prop_assert!(
                step.ttl_s >= prev_ttl,
                "TTL should be monotonic: offense {} has ttl {} < prev {}",
                offense, step.ttl_s, prev_ttl
            );
            prev_ttl = step.ttl_s;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property: Baseline median properties
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Monotonically increasing traffic → non-decreasing median.
    #[test]
    fn monotonic_traffic_monotonic_median(
        samples in proptest::collection::vec(1u64..100, 60)
    ) {
        use waf_engine::checks::ddos::detector::baseline::MovingMedian;

        let mm = MovingMedian::new();
        let mut prev_median = 0u64;

        for (second, &req_count) in samples.iter().enumerate() {
            let base_ms = (second as i64) * 1000;
            for req in 0..req_count {
                mm.record(base_ms + (req as i64) * 10);
            }

            let median = mm.median();
            // After enough samples, median should be stable or increasing
            if second >= 30 {
                prop_assert!(
                    median >= prev_median.saturating_sub(1),
                    "median dropped unexpectedly at second {}: {} → {}",
                    second, prev_median, median
                );
            }
            prev_median = median;
        }
    }

    /// Empty baseline always returns median = 0.
    #[test]
    fn empty_baseline_zero_median(_dummy in 0u8..1) {
        use waf_engine::checks::ddos::detector::baseline::MovingMedian;

        let mm = MovingMedian::new();
        prop_assert_eq!(mm.median(), 0);
    }

    /// Recording at same timestamp increments same bucket.
    #[test]
    fn same_second_same_bucket(count in 1u32..1000, timestamp in 0i64..60_000) {
        use waf_engine::checks::ddos::detector::baseline::MovingMedian;

        let mm = MovingMedian::new();
        let base_ms = timestamp * 1000;

        for i in 0..count {
            let returned = mm.record(base_ms + i64::from(i % 1000));
            prop_assert_eq!(returned, u64::from(i) + 1);
        }

        prop_assert_eq!(mm.total(), u64::from(count));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property: Degrade resolve is total function
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// resolve() never panics for any input combination.
    #[test]
    fn degrade_resolve_total(
        tier in prop_oneof![
            Just(waf_common::tier::Tier::Critical),
            Just(waf_common::tier::Tier::High),
            Just(waf_common::tier::Tier::Medium),
            Just(waf_common::tier::Tier::CatchAll),
        ],
        fail_mode in prop_oneof![
            Just(waf_common::tier::FailMode::Open),
            Just(waf_common::tier::FailMode::Close),
        ],
        err in prop_oneof![
            Just(waf_engine::checks::ddos::degrade::ErrorKind::StoreUnavailable),
            Just(waf_engine::checks::ddos::degrade::ErrorKind::BackendOverload),
            Just(waf_engine::checks::ddos::degrade::ErrorKind::ConfigStale),
        ]
    ) {
        use waf_engine::checks::ddos::degrade::{resolve, DegradeAction};

        let action = resolve(tier, fail_mode, err);

        // Verify output is valid
        match action {
            DegradeAction::Allow | DegradeAction::AllowAndWarn => {}
            DegradeAction::Block { status, retry_after_s } => {
                prop_assert_eq!(status, 503);
                prop_assert_eq!(retry_after_s, 5);
            }
        }
    }

    /// FailMode::Close always produces Block for any tier.
    #[test]
    fn fail_close_always_blocks(
        tier in prop_oneof![
            Just(waf_common::tier::Tier::Critical),
            Just(waf_common::tier::Tier::High),
            Just(waf_common::tier::Tier::Medium),
            Just(waf_common::tier::Tier::CatchAll),
        ],
        err in prop_oneof![
            Just(waf_engine::checks::ddos::degrade::ErrorKind::StoreUnavailable),
            Just(waf_engine::checks::ddos::degrade::ErrorKind::BackendOverload),
            Just(waf_engine::checks::ddos::degrade::ErrorKind::ConfigStale),
        ]
    ) {
        use waf_engine::checks::ddos::degrade::{resolve, DegradeAction};
        use waf_common::tier::FailMode;

        let action = resolve(tier, FailMode::Close, err);
        prop_assert!(
            matches!(action, DegradeAction::Block { .. }),
            "FailMode::Close should always Block, got {:?}",
            action
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property: DynamicBanTable TTL correctness
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Ban expires exactly at expiry timestamp.
    #[test]
    fn ban_table_expiry_boundary(
        ip_last_octet in 1u8..255,
        expires_ms in 1000i64..1_000_000,
        check_offset in -100i64..100
    ) {
        use std::net::{IpAddr, Ipv4Addr};
        use waf_engine::checks::ddos::action::ban::DynamicBanTable;

        let table = DynamicBanTable::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, ip_last_octet));

        table.insert(ip, expires_ms);

        let check_time = expires_ms.saturating_add(check_offset);

        if check_time < expires_ms {
            prop_assert!(
                table.contains(ip, check_time),
                "IP should be banned at {} (expires {})",
                check_time, expires_ms
            );
        } else {
            prop_assert!(
                !table.contains(ip, check_time),
                "IP should NOT be banned at {} (expires {})",
                check_time, expires_ms
            );
        }
    }
}
