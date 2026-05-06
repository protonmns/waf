//! FR-005 phase-05 — `DDoS` action executors (Command pattern).
//!
//! Decouples detection (phases 2-4) from side-effects (bans, risk bumps).
//! Each action implements [`ActionExecutor`] and produces an [`ActionResult`].

use std::net::IpAddr;

use super::detector::DetectorVerdict;

pub mod ban;
pub mod risk;

pub use ban::{BanAction, BanSchedule, DynamicBanTable};
pub use risk::RiskBumpAction;

/// Outcome of executing a `DDoS` action.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActionResult {
    /// Whether the IP was banned.
    pub banned: bool,
    /// Ban TTL in seconds, if banned.
    pub ban_ttl_s: Option<u32>,
    /// Risk delta applied (0-100).
    pub risk_delta: u8,
}

impl ActionResult {
    /// No-op result — nothing happened.
    #[must_use]
    pub const fn noop() -> Self {
        Self {
            banned: false,
            ban_ttl_s: None,
            risk_delta: 0,
        }
    }

    /// Merge two results: OR banned flags, MAX TTL, SUM risk (clamped to 100).
    #[must_use]
    pub fn merge(self, other: Self) -> Self {
        Self {
            banned: self.banned || other.banned,
            ban_ttl_s: match (self.ban_ttl_s, other.ban_ttl_s) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            },
            risk_delta: self.risk_delta.saturating_add(other.risk_delta).min(100),
        }
    }
}

/// Trait for `DDoS` action executors.
///
/// Executors receive a request context and detector verdict, then perform
/// side-effects (bans, risk submissions) and return a result summary.
pub trait ActionExecutor: Send + Sync {
    /// Executor name for logging and metrics.
    fn name(&self) -> &'static str;

    /// Execute the action for the given request and verdict.
    ///
    /// # Arguments
    /// - `ip`: Client IP to act upon
    /// - `verdict`: Detector verdict that triggered this action
    /// - `now_ms`: Current timestamp in milliseconds
    fn execute(&self, ip: IpAddr, verdict: &DetectorVerdict, now_ms: i64) -> ActionResult;
}

/// Composite executor that runs multiple actions in sequence.
///
/// Results are merged: bans are OR'd, TTLs take max, risk deltas sum (capped).
pub struct CombinedAction {
    actions: Vec<Box<dyn ActionExecutor>>,
}

impl CombinedAction {
    /// Create a combined executor from a list of actions.
    #[must_use]
    pub fn new(actions: Vec<Box<dyn ActionExecutor>>) -> Self {
        Self { actions }
    }

    /// Convenience constructor for ban + risk bump combo.
    #[must_use]
    pub fn ban_and_risk(ban: BanAction, risk: RiskBumpAction) -> Self {
        Self::new(vec![Box::new(ban), Box::new(risk)])
    }
}

impl ActionExecutor for CombinedAction {
    fn name(&self) -> &'static str {
        "combined"
    }

    fn execute(&self, ip: IpAddr, verdict: &DetectorVerdict, now_ms: i64) -> ActionResult {
        self.actions
            .iter()
            .map(|a| a.execute(ip, verdict, now_ms))
            .fold(ActionResult::noop(), ActionResult::merge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_result_noop() {
        let r = ActionResult::noop();
        assert!(!r.banned);
        assert!(r.ban_ttl_s.is_none());
        assert_eq!(r.risk_delta, 0);
    }

    #[test]
    fn action_result_merge_or_banned() {
        let a = ActionResult {
            banned: true,
            ban_ttl_s: Some(60),
            risk_delta: 30,
        };
        let b = ActionResult {
            banned: false,
            ban_ttl_s: None,
            risk_delta: 20,
        };
        let merged = a.merge(b);
        assert!(merged.banned);
        assert_eq!(merged.ban_ttl_s, Some(60));
        assert_eq!(merged.risk_delta, 50);
    }

    #[test]
    fn action_result_merge_max_ttl() {
        let a = ActionResult {
            banned: true,
            ban_ttl_s: Some(60),
            risk_delta: 0,
        };
        let b = ActionResult {
            banned: true,
            ban_ttl_s: Some(300),
            risk_delta: 0,
        };
        let merged = a.merge(b);
        assert_eq!(merged.ban_ttl_s, Some(300));
    }

    #[test]
    fn action_result_merge_clamps_risk() {
        let a = ActionResult {
            banned: false,
            ban_ttl_s: None,
            risk_delta: 80,
        };
        let b = ActionResult {
            banned: false,
            ban_ttl_s: None,
            risk_delta: 50,
        };
        let merged = a.merge(b);
        assert_eq!(merged.risk_delta, 100);
    }
}
