//! FR-014..FR-020 end-to-end acceptance suite.
//!
//! Exercises each of the 7 P0 detection checks through its public `Check`
//! trait (and `on_response` for FR-018) using a realistic request context.
//! Intentionally *does not* spin up the full `WafEngine` — that requires a
//! live `PostgreSQL` instance. Unit + module-level tests cover per-check
//! internals; this suite pins the contract that every FR fires the right
//! phase + rule-id prefix for a known-bad input, and allows a clean input.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use waf_common::{DefenseConfig, HostConfig, Phase, RequestCtx};
use waf_engine::checks::{
    BruteForceCheck, Check, DirTraversalCheck, HeaderInjectionCheck, RequestBodyAbuseCheck, ScannerCheck, SsrfCheck,
    XssCheck,
};

fn ctx(path: &str, method: &str, body: &[u8], ct: &str, headers: HashMap<String, String>) -> RequestCtx {
    let mut hdrs = headers;
    if !ct.is_empty() {
        hdrs.insert("content-type".to_string(), ct.to_string());
    }
    let content_length = body.len() as u64;
    RequestCtx {
        req_id: "p0-acc".to_string(),
        client_ip: "5.5.5.5".parse::<IpAddr>().unwrap(),
        client_port: 0,
        method: method.to_string(),
        host: "example.com".to_string(),
        port: 80,
        path: path.to_string(),
        query: String::new(),
        headers: hdrs,
        body_preview: Bytes::copy_from_slice(body),
        content_length,
        is_tls: false,
        host_config: Arc::new(HostConfig {
            defense_config: DefenseConfig::default(),
            ..HostConfig::default()
        }),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: waf_common::RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Positive — each attack vector fires the expected phase + rule-id prefix
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fr_014_xss_blocks_json_payload() {
    let c = XssCheck::new();
    let req = ctx(
        "/api/comment",
        "POST",
        br#"{"comment":"<script>alert(1)</script>"}"#,
        "application/json",
        HashMap::new(),
    );
    let d = c.check(&req).expect("FR-014 hit");
    assert_eq!(d.phase, Phase::Xss);
    assert!(d.rule_id.as_deref().unwrap_or("").starts_with("XSS-"));
}

#[test]
fn fr_015_path_traversal_blocks_double_encoded() {
    let c = DirTraversalCheck::new();
    let req = ctx("/files/%252e%252e%252fetc%252fpasswd", "GET", b"", "", HashMap::new());
    let d = c.check(&req).expect("FR-015 hit");
    assert_eq!(d.phase, Phase::DirTraversal);
    assert!(d.rule_id.as_deref().unwrap_or("").starts_with("TRAV-"));
}

#[test]
fn fr_016_ssrf_blocks_aws_metadata() {
    let c = SsrfCheck::new();
    let req = ctx(
        "/api/webhook",
        "POST",
        br#"{"u":"http://169.254.169.254/latest/meta-data/"}"#,
        "application/json",
        HashMap::new(),
    );
    let d = c.check(&req).expect("FR-016 hit");
    assert_eq!(d.phase, Phase::Ssrf);
    assert!(d.rule_id.as_deref().unwrap_or("").starts_with("SSRF-"));
}

#[test]
fn fr_017_header_injection_blocks_crlf_in_referer() {
    let c = HeaderInjectionCheck::new();
    let mut h = HashMap::new();
    h.insert("referer".to_string(), "foo\r\nSet-Cookie: pwned=1".to_string());
    let req = ctx("/", "GET", b"", "", h);
    let d = c.check(&req).expect("FR-017 hit");
    assert_eq!(d.phase, Phase::HeaderInjection);
    assert!(d.rule_id.as_deref().unwrap_or("").starts_with("HDR-"));
}

#[test]
fn fr_018_brute_force_blocks_after_five_failed_logins() {
    let c = BruteForceCheck::new();
    let body = br#"{"username":"alice","password":"wrong"}"#;
    for _ in 0..5 {
        let r = ctx("/login", "POST", body, "application/json", HashMap::new());
        c.on_response(&r, 401);
    }
    let req = ctx("/login", "POST", body, "application/json", HashMap::new());
    let d = c.check(&req).expect("FR-018 hit");
    assert_eq!(d.phase, Phase::BruteForce);
    assert!(d.rule_id.as_deref().unwrap_or("").starts_with("BF-"));
}

#[test]
fn fr_019_scanner_blocks_options_abuse() {
    let c = ScannerCheck::new();
    // Default threshold is 20 OPTIONS from same client_ip inside window.
    for _ in 0..19 {
        let r = ctx("/api/users", "OPTIONS", b"", "", HashMap::new());
        let _ = c.check(&r);
    }
    let req = ctx("/api/users", "OPTIONS", b"", "", HashMap::new());
    let d = c.check(&req).expect("FR-019 hit");
    assert_eq!(d.phase, Phase::Scanner);
    assert!(d.rule_id.as_deref().unwrap_or("").starts_with("SCAN-"));
}

#[test]
fn fr_020_body_abuse_blocks_oversized_declared_length() {
    let c = RequestBodyAbuseCheck::new();
    // Declared 128 KiB while preview body is small — matches production shape.
    let mut req = ctx("/api/upload", "POST", b"{}", "application/json", HashMap::new());
    req.content_length = 128 * 1024;
    let d = c.check(&req).expect("FR-020 hit");
    assert_eq!(d.phase, Phase::RequestBodyAbuse);
    assert!(d.rule_id.as_deref().unwrap_or("").starts_with("BODY-"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Negative — clean input sails through every check
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fr_clean_benign_request_triggers_no_detection() {
    let req = ctx("/api/v1/users/42", "GET", b"", "", HashMap::new());
    assert!(XssCheck::new().check(&req).is_none());
    assert!(DirTraversalCheck::new().check(&req).is_none());
    assert!(SsrfCheck::new().check(&req).is_none());
    assert!(HeaderInjectionCheck::new().check(&req).is_none());
    assert!(BruteForceCheck::new().check(&req).is_none());
    assert!(RequestBodyAbuseCheck::new().check(&req).is_none());
    // ScannerCheck's stateful OPTIONS/enum-path counters fire only under
    // threshold — a single clean GET must not trigger them.
    assert!(ScannerCheck::new().check(&req).is_none());
}

#[test]
fn fr_clean_json_webhook_passes_ssrf_and_body_abuse() {
    let req = ctx(
        "/api/webhook",
        "POST",
        br#"{"webhook":"https://api.stripe.com/v1/charges"}"#,
        "application/json",
        HashMap::new(),
    );
    assert!(SsrfCheck::new().check(&req).is_none());
    assert!(RequestBodyAbuseCheck::new().check(&req).is_none());
}
