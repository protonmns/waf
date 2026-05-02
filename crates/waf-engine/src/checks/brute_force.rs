//! Brute force / credential stuffing detection (FR-018).
//!
//! Request phase (`Check::check`):
//!   - If the request targets a configured login route AND the
//!     `(user_hash, ip)` failure counter is at or above
//!     `bf_max_per_user`, block with BF-001.
//!   - If any password has been sprayed against `>= bf_spray_threshold`
//!     distinct users from this IP inside the window, block with BF-002.
//!
//! Response phase (`Check::on_response`, status-code-only v1):
//!   - If status is 401 or 403 AND the original request targeted a login
//!     route, extract username + password from the body and record a
//!     failure.
//!
//! Body-regex failure detection is intentionally NOT implemented —
//! Pingora's `response_filter` exposes headers + status only (Finding #8),
//! and a generic failure regex is weaponizable as a victim-account
//! lockout primitive (Finding #11).

use std::sync::Arc;
use std::time::Duration;

use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;
use super::brute_force_extractors::{
    PASSWORD_KEYS, USERNAME_KEYS, extract_credential_field, extract_credentials, is_failed_login_status, truncated_hash,
};
use super::brute_force_state::BfState;
use super::{Clock, SystemClock};

pub struct BruteForceCheck {
    state: Arc<BfState>,
}

impl BruteForceCheck {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Arc::new(BfState::new(100_000, clock)),
        }
    }

    /// Expose the inner state so an engine bootstrap can drive periodic
    /// `prune_older_than` calls (background pruner lives in engine init per
    /// Red Team Finding #14).
    pub fn state(&self) -> Arc<BfState> {
        Arc::clone(&self.state)
    }
}

impl Default for BruteForceCheck {
    fn default() -> Self {
        Self::new()
    }
}

/// Does `ctx.path` target any configured login route?
fn is_login_route(ctx: &RequestCtx) -> bool {
    let routes = &ctx.host_config.defense_config.bf_login_routes;
    if routes.is_empty() {
        return false;
    }
    let path = ctx.path.split('?').next().unwrap_or(ctx.path.as_str());
    routes.iter().any(|r| path.starts_with(r.as_str()))
}

impl Check for BruteForceCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        let dc = &ctx.host_config.defense_config;
        if !dc.brute_force || !is_login_route(ctx) {
            return None;
        }

        let window = Duration::from_secs(dc.bf_window_secs);

        // BF-001 — per-user failure threshold.
        let content_type = ctx.headers.get("content-type").map_or("", String::as_str);
        if let Some(username) = extract_credential_field(&ctx.body_preview, content_type, USERNAME_KEYS) {
            let user_hash = truncated_hash(&normalize_username(&username));
            let count = self.state.failed_count(user_hash, ctx.client_ip, window);
            if count >= dc.bf_max_per_user {
                return Some(detection(
                    1,
                    format!(
                        "{count} failed logins for same user from {ip} in {secs}s",
                        ip = ctx.client_ip,
                        secs = dc.bf_window_secs,
                    ),
                ));
            }
        }

        // BF-002 — password-spray across distinct users from this IP.
        if self
            .state
            .any_spray_over_threshold(ctx.client_ip, dc.bf_spray_threshold, window)
        {
            return Some(detection(
                2,
                format!(
                    "password sprayed against >= {thr} users from {ip} in {secs}s",
                    thr = dc.bf_spray_threshold,
                    ip = ctx.client_ip,
                    secs = dc.bf_window_secs,
                ),
            ));
        }

        None
    }

    fn on_response(&self, ctx: &RequestCtx, status: u16) {
        let dc = &ctx.host_config.defense_config;
        if !dc.brute_force || !is_login_route(ctx) || !is_failed_login_status(status) {
            return;
        }

        let window = Duration::from_secs(dc.bf_window_secs);
        let content_type = ctx.headers.get("content-type").map_or("", String::as_str);

        // Single-parse extraction: pulls both username and (optional) password
        // from the same parse tree — avoids parsing a 4 KiB login body twice
        // on every failed-login response.
        let mut fields = extract_credentials(&ctx.body_preview, content_type, &[USERNAME_KEYS, PASSWORD_KEYS]);
        let Some(username) = fields.first_mut().and_then(Option::take) else {
            return;
        };
        let user_hash = truncated_hash(&normalize_username(&username));
        self.state.record_failed(user_hash, ctx.client_ip, window);

        // Password is optional — sprayer tracking works only when we also
        // know what was attempted. Legit failed logins without a body-visible
        // password simply skip the spray counter.
        if let Some(password) = fields.get_mut(1).and_then(Option::take) {
            let pwd_hash = truncated_hash(&password);
            self.state
                .record_spray(ctx.client_ip, pwd_hash, user_hash, window, dc.bf_spray_threshold);
        }
    }
}

/// Lower-case + trim so `"alice"`, `"ALICE"`, and `"alice "` all hash to the
/// same slot. Without this, an attacker can bypass BF-001 by appending a
/// trailing space to the username (Red Team Finding L2).
fn normalize_username(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn detection(rule_seq: usize, desc: String) -> DetectionResult {
    DetectionResult {
        rule_id: Some(format!("BF-{rule_seq:03}")),
        rule_name: "Brute Force".to_string(),
        phase: Phase::BruteForce,
        detail: desc,
    }
}

#[cfg(test)]
#[allow(clippy::duration_suboptimal_units)]
mod tests {
    use super::*;
    use crate::checks::test_clock::MockClock;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx(path: &str, body: &[u8], ct: &str, ip: &str) -> RequestCtx {
        make_ctx_dc(path, body, ct, ip, DefenseConfig::default())
    }

    fn make_ctx_dc(path: &str, body: &[u8], ct: &str, ip: &str, dc: DefenseConfig) -> RequestCtx {
        let mut headers = HashMap::new();
        if !ct.is_empty() {
            headers.insert("content-type".to_string(), ct.to_string());
        }
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: ip.parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "POST".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: path.to_string(),
            query: String::new(),
            headers,
            body_preview: Bytes::copy_from_slice(body),
            content_length: body.len() as u64,
            is_tls: false,
            host_config: Arc::new(HostConfig {
                defense_config: dc,
                ..HostConfig::default()
            }),
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: HashMap::new(),
        }
    }

    #[test]
    fn detects_per_user_threshold_on_sixth_attempt() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        let body = br#"{"username":"alice","password":"wrong"}"#;
        for _ in 0..5 {
            let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
            checker.on_response(&ctx, 401);
        }
        let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
        let det = checker.check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BF-001");
    }

    #[test]
    fn allows_fifth_attempt_boundary() {
        // 4 failures, 5th request hits the check — count is 4, threshold is 5,
        // so still allowed.
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        let body = br#"{"username":"alice","password":"wrong"}"#;
        for _ in 0..4 {
            let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
            checker.on_response(&ctx, 401);
        }
        let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn window_expiry_clears_failures() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock.clone());
        let body = br#"{"username":"alice","password":"wrong"}"#;
        for _ in 0..5 {
            let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
            checker.on_response(&ctx, 401);
        }
        // Default window is 900s; jump well past it.
        clock.advance(Duration::from_secs(1800));
        let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn per_ip_isolation() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        let body = br#"{"username":"alice","password":"wrong"}"#;
        for _ in 0..5 {
            let ctx = make_ctx("/login", body, "application/json", "1.1.1.1");
            checker.on_response(&ctx, 401);
        }
        // Different IP — no state.
        let ctx = make_ctx("/login", body, "application/json", "2.2.2.2");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn detects_password_spray() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        for user in ["charlie", "diana", "eve", "frank", "grace"] {
            let body = format!(r#"{{"username":"{user}","password":"P@ss1"}}"#);
            let ctx = make_ctx("/login", body.as_bytes(), "application/json", "9.9.9.9");
            checker.on_response(&ctx, 401);
        }
        // Next request from same IP — spray detected regardless of username.
        let ctx = make_ctx(
            "/login",
            br#"{"username":"zed","password":"anything"}"#,
            "application/json",
            "9.9.9.9",
        );
        let det = checker.check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BF-002");
    }

    #[test]
    fn spray_below_threshold_no_detection() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        for user in ["charlie", "diana", "eve", "frank"] {
            let body = format!(r#"{{"username":"{user}","password":"P@ss1"}}"#);
            let ctx = make_ctx("/login", body.as_bytes(), "application/json", "9.9.9.9");
            checker.on_response(&ctx, 401);
        }
        let ctx = make_ctx(
            "/login",
            br#"{"username":"x","password":"y"}"#,
            "application/json",
            "9.9.9.9",
        );
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn success_response_does_not_increment_failures() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        let body = br#"{"username":"alice","password":"correct"}"#;
        for _ in 0..10 {
            let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
            checker.on_response(&ctx, 200);
        }
        let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn status_500_does_not_increment_failures() {
        // Transient server errors must not count as login failures.
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        let body = br#"{"username":"alice","password":"x"}"#;
        for _ in 0..10 {
            let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
            checker.on_response(&ctx, 503);
        }
        let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn response_on_non_login_route_ignored() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        let body = br#"{"username":"alice","password":"x"}"#;
        for _ in 0..10 {
            let ctx = make_ctx("/api/health", body, "application/json", "5.5.5.5");
            checker.on_response(&ctx, 401);
        }
        let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn disabled_brute_force_kills_all_signals() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        let dc = DefenseConfig {
            brute_force: false,
            ..DefenseConfig::default()
        };
        let body = br#"{"username":"alice","password":"x"}"#;
        for _ in 0..20 {
            let ctx = make_ctx_dc("/login", body, "application/json", "5.5.5.5", dc.clone());
            checker.on_response(&ctx, 401);
        }
        let ctx = make_ctx_dc("/login", body, "application/json", "5.5.5.5", dc);
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn extraction_failure_silently_skips_recording() {
        // Body missing username — recording is skipped; no threshold hit.
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        let body = br#"{"token":"xyz"}"#;
        for _ in 0..20 {
            let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
            checker.on_response(&ctx, 401);
        }
        let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn whitespace_padded_username_hashes_to_same_slot() {
        // Red Team L2: attacker appends/prepends space to evade BF-001.
        // normalize_username trims before hashing.
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        for user in ["alice", " alice", "alice ", "  alice  "] {
            let body = format!(r#"{{"username":"{user}","password":"x"}}"#);
            let ctx = make_ctx("/login", body.as_bytes(), "application/json", "5.5.5.5");
            checker.on_response(&ctx, 401);
        }
        for _ in 0..1 {
            let ctx = make_ctx(
                "/login",
                br#"{"username":"alice","password":"x"}"#,
                "application/json",
                "5.5.5.5",
            );
            checker.on_response(&ctx, 401);
        }
        let ctx = make_ctx(
            "/login",
            br#"{"username":"alice","password":"x"}"#,
            "application/json",
            "5.5.5.5",
        );
        let det = checker
            .check(&ctx)
            .expect("5 padded failures must collapse to same slot");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BF-001");
    }

    #[test]
    fn case_insensitive_username_hashes_to_same_slot() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        // Three failures under mixed casing.
        for user in ["Alice", "ALICE", "alice"] {
            let body = format!(r#"{{"username":"{user}","password":"x"}}"#);
            let ctx = make_ctx("/login", body.as_bytes(), "application/json", "5.5.5.5");
            checker.on_response(&ctx, 401);
        }
        for _ in 0..2 {
            let ctx = make_ctx(
                "/login",
                br#"{"username":"alice","password":"x"}"#,
                "application/json",
                "5.5.5.5",
            );
            checker.on_response(&ctx, 401);
        }
        let ctx = make_ctx(
            "/login",
            br#"{"username":"alice","password":"x"}"#,
            "application/json",
            "5.5.5.5",
        );
        let det = checker.check(&ctx).expect("hit after combined 5 failures");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BF-001");
    }

    #[test]
    fn form_urlencoded_body_works() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        for _ in 0..5 {
            let ctx = make_ctx(
                "/login",
                b"username=alice&password=wrong",
                "application/x-www-form-urlencoded",
                "5.5.5.5",
            );
            checker.on_response(&ctx, 401);
        }
        let ctx = make_ctx(
            "/login",
            b"username=alice&password=wrong",
            "application/x-www-form-urlencoded",
            "5.5.5.5",
        );
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn route_prefix_match_covers_subpaths() {
        // `/api/auth/token/refresh` must count for the `/api/auth/token` route.
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        let body = br#"{"username":"alice","password":"x"}"#;
        for _ in 0..5 {
            let ctx = make_ctx("/api/auth/token/refresh", body, "application/json", "5.5.5.5");
            checker.on_response(&ctx, 401);
        }
        let ctx = make_ctx("/api/auth/token/refresh", body, "application/json", "5.5.5.5");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detection_carries_correct_phase_and_prefix() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        let body = br#"{"username":"alice","password":"x"}"#;
        for _ in 0..5 {
            let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
            checker.on_response(&ctx, 401);
        }
        let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
        let det = checker.check(&ctx).expect("hit");
        assert_eq!(det.phase, Phase::BruteForce);
        assert_eq!(det.rule_name, "Brute Force");
        assert!(det.rule_id.as_deref().unwrap_or("").starts_with("BF-"));
    }

    #[test]
    fn empty_login_routes_disables_check() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        let dc = DefenseConfig {
            bf_login_routes: Vec::new(),
            ..DefenseConfig::default()
        };
        let body = br#"{"username":"alice","password":"x"}"#;
        for _ in 0..10 {
            let ctx = make_ctx_dc("/login", body, "application/json", "5.5.5.5", dc.clone());
            checker.on_response(&ctx, 401);
        }
        let ctx = make_ctx_dc("/login", body, "application/json", "5.5.5.5", dc);
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn response_status_403_also_counted() {
        let clock = Arc::new(MockClock::new());
        let checker = BruteForceCheck::with_clock(clock);
        let body = br#"{"username":"alice","password":"x"}"#;
        for _ in 0..5 {
            let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
            checker.on_response(&ctx, 403);
        }
        let ctx = make_ctx("/login", body, "application/json", "5.5.5.5");
        assert!(checker.check(&ctx).is_some());
    }
}
