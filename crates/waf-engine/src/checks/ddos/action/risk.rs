//! FR-005 phase-05 — Risk bump action for `DDoS` verdicts.
//!
//! Submits risk signals to FR-010's [`RiskAggregator`] when `DDoS` violations
//! are detected. Fire-and-forget semantics — no blocking on scorer response.

use std::net::IpAddr;
use std::sync::Arc;

use tracing::debug;

use crate::checks::ddos::detector::DetectorVerdict;
use crate::device_fp::aggregator::RiskAggregator;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::FpKey;

use super::{ActionExecutor, ActionResult};

/// Risk bump action that submits `DDoS` signals to the risk aggregator.
///
/// Uses the [`BurstInterval`](Signal::BurstInterval) signal variant to report
/// `DDoS` burst detections. The aggregator handles scoring asynchronously.
pub struct RiskBumpAction {
    aggregator: Arc<dyn RiskAggregator>,
}

impl RiskBumpAction {
    #[must_use]
    pub fn new(aggregator: Arc<dyn RiskAggregator>) -> Self {
        Self { aggregator }
    }

    /// Build an [`FpKey`] from client IP for signal submission.
    ///
    /// `DDoS` detection operates on IPs, not TLS fingerprints. We create a
    /// minimal [`FpKey`] with the IP encoded in JA3 field for keying purposes.
    fn ip_to_fp_key(ip: IpAddr) -> FpKey {
        use crate::device_fp::types::FingerprintValue;
        FpKey {
            ja3: Some(FingerprintValue::new(format!("ddos:{ip}"))),
            ja4: None,
            h2_akamai: None,
        }
    }

    /// Build the signal for a `DDoS` burst detection.
    fn burst_signal(risk_delta: u8) -> Signal {
        // BurstInterval count field represents severity (clamped to u16)
        Signal::BurstInterval {
            count: u16::from(risk_delta),
        }
    }
}

impl ActionExecutor for RiskBumpAction {
    fn name(&self) -> &'static str {
        "risk_bump"
    }

    fn execute(&self, ip: IpAddr, verdict: &DetectorVerdict, _now_ms: i64) -> ActionResult {
        // Determine risk delta from verdict
        let risk_delta = match verdict {
            DetectorVerdict::Allow => return ActionResult::noop(),
            DetectorVerdict::SoftAnomaly(delta) => *delta,
            DetectorVerdict::HardBurst { .. } => 100, // max risk for hard bursts
        };

        if risk_delta == 0 {
            return ActionResult::noop();
        }

        let fp_key = Self::ip_to_fp_key(ip);
        let signal = Self::burst_signal(risk_delta);

        // Fire-and-forget submission via block_in_place bridge
        // The aggregator contract says submit MUST NOT block, so this is safe
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.aggregator.submit(&fp_key, &[signal]).await;
            });
        });

        debug!(
            action = "risk_bump",
            ip = %ip,
            risk_delta = risk_delta,
            "submitted DDoS risk signal"
        );

        ActionResult {
            banned: false,
            ban_ttl_s: None,
            risk_delta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::aggregator::LoggingAggregator;

    fn make_risk_action() -> (LoggingAggregator, RiskBumpAction) {
        let agg = LoggingAggregator::new(16);
        let action = RiskBumpAction::new(Arc::new(agg.clone()));
        (agg, action)
    }

    #[tokio::test]
    async fn ignores_allow_verdict() {
        let (agg, action) = make_risk_action();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let result = action.execute(ip, &DetectorVerdict::Allow, 1000);
        assert_eq!(result, ActionResult::noop());
        assert!(agg.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn submits_soft_anomaly() {
        let (agg, action) = make_risk_action();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result = action.execute(ip, &DetectorVerdict::SoftAnomaly(50), 1000);
        assert_eq!(result.risk_delta, 50);
        assert!(!result.banned);

        let snap = agg.snapshot();
        assert_eq!(snap.len(), 1);
        let first = snap.first().expect("expected one submission");
        assert!(matches!(
            first.signals.as_slice(),
            [Signal::BurstInterval { count: 50 }]
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn submits_hard_burst_max_risk() {
        let (agg, action) = make_risk_action();
        let ip: IpAddr = "172.16.0.1".parse().unwrap();

        let verdict = DetectorVerdict::HardBurst {
            reason: "burst",
            detector: "per_ip",
        };
        let result = action.execute(ip, &verdict, 1000);
        assert_eq!(result.risk_delta, 100);

        let snap = agg.snapshot();
        assert_eq!(snap.len(), 1);
        let first = snap.first().expect("expected one submission");
        assert!(matches!(
            first.signals.as_slice(),
            [Signal::BurstInterval { count: 100 }]
        ));
    }

    #[tokio::test]
    async fn fp_key_contains_ip() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let key = RiskBumpAction::ip_to_fp_key(ip);
        assert!(key.ja3.unwrap().as_str().contains("8.8.8.8"));
    }

    #[tokio::test]
    async fn zero_soft_anomaly_is_noop() {
        let (agg, action) = make_risk_action();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();

        let result = action.execute(ip, &DetectorVerdict::SoftAnomaly(0), 1000);
        assert_eq!(result, ActionResult::noop());
        assert!(agg.is_empty());
    }
}
