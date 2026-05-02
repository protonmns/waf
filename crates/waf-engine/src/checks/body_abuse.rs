//! Request body abuse detection (FR-020).
//!
//! Five rules run in cheap-to-expensive order:
//!
//! 1. Oversized — declared `Content-Length` > `defense_config.max_body_size`.
//!    Uses the header (NOT `body_preview.len()`) because Pingora truncates
//!    `body_preview` at 64 KiB; a declared 1 MiB `content_length` must
//!    still be flagged (Red Team Finding #5).
//! 2. Content-Type mismatch — magic-byte sniff disagrees with declared
//!    type. Only fires when both sides land in a known category so a
//!    generic `text/plain` body does not false-flag.
//! 3. JSON depth pre-check — byte-scan counts `{` / `[` nesting and bails
//!    the moment it crosses `max_json_depth`, before any parse/allocation
//!    (Finding #3 — `serde_json` has no `set_recursion_limit` API).
//! 4. JSON parse — only after pre-check passes. Parse failure → block.
//! 5. JSON key explosion — iterative walker over the parsed `Value` bails
//!    when cumulative key count exceeds `max_json_keys`.

use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;
use super::body_abuse_walker::{
    BodyAbuseViolation, declared_body_kind, precheck_json_depth, sniff_body_kind, walk_count_keys,
};

pub struct RequestBodyAbuseCheck;

impl RequestBodyAbuseCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for RequestBodyAbuseCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for RequestBodyAbuseCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        let dc = &ctx.host_config.defense_config;
        if !dc.body_abuse {
            return None;
        }
        if ctx.body_preview.is_empty() && ctx.content_length == 0 {
            return None;
        }

        let max_body = dc.max_body_size as u64;

        // ── Rule 1: declared oversized (cheapest) ───────────────────────────
        if ctx.content_length > max_body {
            return Some(detection(
                2,
                format!(
                    "Content-Length {} exceeds max_body_size {}",
                    ctx.content_length, dc.max_body_size
                ),
            ));
        }
        // Fallback when content_length is missing (chunked) — use what we have.
        if ctx.content_length == 0 && (ctx.body_preview.len() as u64) > max_body {
            return Some(detection(
                2,
                format!(
                    "chunked body preview {} exceeds max_body_size {}",
                    ctx.body_preview.len(),
                    dc.max_body_size
                ),
            ));
        }

        // ── Rule 2: declared vs sniffed content-type ────────────────────────
        let declared_ct = ctx.headers.get("content-type").map_or("", String::as_str);
        let declared = declared_body_kind(declared_ct);
        let sniffed = sniff_body_kind(&ctx.body_preview);
        if declared != "unknown" && sniffed != "unknown" && declared != sniffed {
            return Some(detection(
                5,
                format!("Content-Type says {declared} but body magic-bytes look like {sniffed}"),
            ));
        }

        // ── Rule 3-5: JSON-specific (only when declared JSON) ───────────────
        if declared == "json" {
            if let Err(v) = precheck_json_depth(&ctx.body_preview, dc.max_json_depth) {
                return Some(violation_to_detection(&v, dc.max_json_depth, dc.max_json_keys));
            }
            match serde_json::from_slice::<serde_json::Value>(&ctx.body_preview) {
                Err(_) => {
                    return Some(detection(
                        1,
                        "declared application/json but body failed to parse".to_string(),
                    ));
                }
                Ok(value) => {
                    if let Err(v) = walk_count_keys(&value, dc.max_json_keys) {
                        return Some(violation_to_detection(&v, dc.max_json_depth, dc.max_json_keys));
                    }
                }
            }
        }

        None
    }
}

fn detection(rule_seq: usize, desc: String) -> DetectionResult {
    DetectionResult {
        rule_id: Some(format!("BODY-{rule_seq:03}")),
        rule_name: "Request Body Abuse".to_string(),
        phase: Phase::RequestBodyAbuse,
        detail: desc,
    }
}

fn violation_to_detection(v: &BodyAbuseViolation, max_depth: usize, max_keys: usize) -> DetectionResult {
    match v {
        BodyAbuseViolation::TooDeep => detection(3, format!("JSON nesting exceeds max_json_depth {max_depth}")),
        BodyAbuseViolation::TooManyKeys => detection(4, format!("JSON key count exceeds max_json_keys {max_keys}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::fmt::Write as _;
    use std::net::IpAddr;
    use std::sync::Arc;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx(body: &[u8], ct: &str, content_length: u64) -> RequestCtx {
        make_ctx_dc(body, ct, content_length, DefenseConfig::default())
    }

    fn make_ctx_dc(body: &[u8], ct: &str, content_length: u64, dc: DefenseConfig) -> RequestCtx {
        let mut headers = HashMap::new();
        if !ct.is_empty() {
            headers.insert("content-type".to_string(), ct.to_string());
        }
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "POST".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/api/upload".to_string(),
            query: String::new(),
            headers,
            body_preview: Bytes::copy_from_slice(body),
            content_length,
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
    fn detects_oversized_by_content_length() {
        // Default max_body_size = 64 KiB. Declare 128 KiB via content_length.
        let ctx = make_ctx(b"{}", "application/json", 128 * 1024);
        let det = RequestBodyAbuseCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BODY-002");
    }

    #[test]
    fn allows_exactly_at_body_size_cap() {
        // content_length == cap should pass (strictly greater-than).
        let ctx = make_ctx(b"{}", "application/json", 64 * 1024);
        assert!(RequestBodyAbuseCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn detects_ct_mismatch_json_declared_xml_body() {
        let ctx = make_ctx(b"<?xml version='1.0'?><root/>", "application/json", 28);
        let det = RequestBodyAbuseCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BODY-005");
    }

    #[test]
    fn detects_ct_mismatch_json_declared_zip_body() {
        let ctx = make_ctx(b"PK\x03\x04rest", "application/json", 9);
        let det = RequestBodyAbuseCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BODY-005");
    }

    #[test]
    fn detects_ct_mismatch_text_declared_json_body() {
        let ctx = make_ctx(b"{\"x\":1}", "text/html", 7);
        let det = RequestBodyAbuseCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BODY-005");
    }

    #[test]
    fn detects_malformed_json() {
        // Valid depth pre-check (`{` then EOF balances below cap) but parse
        // fails — we want BODY-001.
        let ctx = make_ctx(b"{\"a\":", "application/json", 5);
        let det = RequestBodyAbuseCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BODY-001");
    }

    #[test]
    fn allows_clean_small_json() {
        let ctx = make_ctx(br#"{"name":"alice","age":30}"#, "application/json", 25);
        assert!(RequestBodyAbuseCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn detects_deep_nesting() {
        // Build depth 101 JSON.
        let mut s = String::new();
        for _ in 0..101 {
            s.push_str("{\"x\":");
        }
        s.push_str("null");
        for _ in 0..101 {
            s.push('}');
        }
        let ctx = make_ctx(s.as_bytes(), "application/json", s.len() as u64);
        let det = RequestBodyAbuseCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BODY-003");
    }

    #[test]
    fn allows_depth_at_cap() {
        let mut s = String::new();
        for _ in 0..100 {
            s.push_str("{\"x\":");
        }
        s.push_str("null");
        for _ in 0..100 {
            s.push('}');
        }
        let ctx = make_ctx(s.as_bytes(), "application/json", s.len() as u64);
        assert!(RequestBodyAbuseCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn detects_adversarial_deep_nesting_does_not_panic() {
        // 10_000 unclosed `{` — depth precheck bails in O(N), no parser invoked.
        let s = "{".repeat(10_000);
        let ctx = make_ctx(s.as_bytes(), "application/json", s.len() as u64);
        let det = RequestBodyAbuseCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BODY-003");
    }

    #[test]
    fn detects_key_explosion() {
        // Generate object with 11 keys; set max_json_keys=10 to trigger.
        let mut s = String::from("{");
        for i in 0..11 {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(s, r#""k{i}":{i}"#);
        }
        s.push('}');
        let dc = DefenseConfig {
            max_json_keys: 10,
            ..DefenseConfig::default()
        };
        let ctx = make_ctx_dc(s.as_bytes(), "application/json", s.len() as u64, dc);
        let det = RequestBodyAbuseCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BODY-004");
    }

    #[test]
    fn allows_keys_at_cap() {
        let mut s = String::from("{");
        for i in 0..10 {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(s, r#""k{i}":{i}"#);
        }
        s.push('}');
        let dc = DefenseConfig {
            max_json_keys: 10,
            ..DefenseConfig::default()
        };
        let ctx = make_ctx_dc(s.as_bytes(), "application/json", s.len() as u64, dc);
        assert!(RequestBodyAbuseCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn empty_body_no_detection() {
        let ctx = make_ctx(b"", "application/json", 0);
        assert!(RequestBodyAbuseCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn skipped_when_body_abuse_disabled() {
        let dc = DefenseConfig {
            body_abuse: false,
            ..DefenseConfig::default()
        };
        let ctx = make_ctx_dc(b"<xml/>", "application/json", 6, dc);
        assert!(RequestBodyAbuseCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn json_with_charset_parameter_treated_as_json() {
        let ctx = make_ctx(br#"{"ok":true}"#, "application/json; charset=utf-8", 11);
        assert!(RequestBodyAbuseCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn no_content_type_skips_mismatch() {
        // Unknown declared → the mismatch rule is intentionally skipped.
        let ctx = make_ctx(br#"{"x":1}"#, "", 7);
        assert!(RequestBodyAbuseCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn html_declared_html_body_allowed() {
        let ctx = make_ctx(b"<!DOCTYPE html><html></html>", "text/html", 28);
        assert!(RequestBodyAbuseCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn gzip_declared_gzip_body_allowed() {
        let body: &[u8] = &[0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0];
        let ctx = make_ctx(body, "application/gzip", body.len() as u64);
        assert!(RequestBodyAbuseCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn detects_mixed_array_object_nesting() {
        // Alternate `[{[{...}]}]` to hit the precheck depth cap.
        let mut s = String::new();
        for i in 0..120 {
            s.push(if i % 2 == 0 { '[' } else { '{' });
        }
        let ctx = make_ctx(s.as_bytes(), "application/json", s.len() as u64);
        let det = RequestBodyAbuseCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BODY-003");
    }

    #[test]
    fn detection_carries_correct_phase_and_prefix() {
        let ctx = make_ctx(b"{}", "application/json", 128 * 1024);
        let det = RequestBodyAbuseCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.phase, Phase::RequestBodyAbuse);
        assert_eq!(det.rule_name, "Request Body Abuse");
        assert!(det.rule_id.as_deref().unwrap_or("").starts_with("BODY-"));
    }

    #[test]
    fn chunked_fallback_checks_body_preview_when_content_length_zero() {
        // content_length=0 with a 128 KiB body_preview → fall back to preview size.
        let body = vec![b'a'; 128 * 1024];
        let ctx = make_ctx(&body, "application/octet-stream", 0);
        let det = RequestBodyAbuseCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "BODY-002");
    }

    #[test]
    fn unknown_ct_and_unknown_magic_allowed() {
        // No mismatch can be established — rule is defensive, so allow.
        let ctx = make_ctx(b"plain raw bytes", "text/plain", 15);
        assert!(RequestBodyAbuseCheck::new().check(&ctx).is_none());
    }
}
