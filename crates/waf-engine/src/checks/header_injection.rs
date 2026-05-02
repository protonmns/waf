//! HTTP header injection detection (FR-017).
//!
//! Scans every request header for raw / percent-encoded CRLF (response-splitting
//! primitive), validates the `Host` header against a per-host whitelist, and
//! sanity-checks `X-Forwarded-For` for leftmost-private and excessive-hop-count
//! patterns.
//!
//! SNI-vs-Host comparison is intentionally NOT implemented in v1 — `RequestCtx`
//! has no `sni` field (Red Team Finding #12). Whitelist-only validation is the
//! ship target; operators must populate `defense_config.host_inbound_whitelist`
//! per host or the Host check is a no-op for that host.

use std::net::IpAddr;

use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;
use super::header_injection_patterns::{HDR_ENCODED_CRLF_DESCS, HDR_ENCODED_CRLF_SET};

/// HTTP header injection checker.
pub struct HeaderInjectionCheck;

impl HeaderInjectionCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for HeaderInjectionCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for HeaderInjectionCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.header_injection {
            return None;
        }

        // ── Rules 1, 2, 5: CRLF in any header (name or value) ──────────────
        for (name, value) in &ctx.headers {
            if has_raw_crlf_or_nul(name) {
                return Some(detection(
                    5,
                    "CRLF/NUL in header name (response splitting primitive)",
                    name,
                ));
            }
            if has_raw_crlf_or_nul(value) {
                return Some(detection(1, "raw CRLF/NUL in header value", name));
            }
            if let Some(idx) = HDR_ENCODED_CRLF_SET.matches(value).iter().next() {
                let desc = HDR_ENCODED_CRLF_DESCS.get(idx).copied().unwrap_or("encoded CRLF");
                return Some(detection(2, desc, name));
            }
        }

        // ── Rule 3: Host header validation ─────────────────────────────────
        if let Some(host_value) = ctx.headers.get("host") {
            if !is_valid_host_header(host_value) {
                return Some(detection(3, "malformed Host header", "host"));
            }
            let whitelist = &ctx.host_config.defense_config.host_inbound_whitelist;
            if !whitelist.is_empty() && !host_in_whitelist(host_value, whitelist) {
                return Some(detection(3, "Host not in inbound whitelist", "host"));
            }
        }

        // ── Rule 4: X-Forwarded-For chain checks ───────────────────────────
        if let Some(xff) = ctx.headers.get("x-forwarded-for") {
            let max_hops = ctx.host_config.defense_config.xf2_max_hops;
            if let Some(reason) = validate_x_forwarded_for(xff, ctx.client_ip, max_hops) {
                return Some(detection(4, reason, "x-forwarded-for"));
            }
        }

        None
    }
}

fn detection(rule_seq: usize, desc: &str, location: &str) -> DetectionResult {
    DetectionResult {
        rule_id: Some(format!("HDR-{rule_seq:03}")),
        rule_name: "Header Injection".to_string(),
        phase: Phase::HeaderInjection,
        detail: format!("{desc} in {location}"),
    }
}

/// Raw CR (`\r`), LF (`\n`), or NUL (`\0`) in the byte stream of a header
/// value or name. NUL is included because some proxies treat it as a
/// terminator the same way a CRLF splits the header section.
fn has_raw_crlf_or_nul(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
}

/// A Host header is considered well-formed when:
/// - it is non-empty,
/// - contains no whitespace, no `,`, no `@`, no CR/LF/NUL,
/// - has at most one `:` (the port separator) outside of an IPv6 literal.
///
/// IPv6 literals are wrapped in brackets `[…]:port`, which we recognise so we
/// don't false-flag them.
fn is_valid_host_header(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if has_raw_crlf_or_nul(host) {
        return false;
    }
    if host.bytes().any(|b| matches!(b, b' ' | b'\t' | b',' | b'@')) {
        return false;
    }
    // IPv6 literal form: must be `[...]` optionally followed by `:port`.
    if host.starts_with('[') {
        let Some(close) = host.find(']') else {
            return false;
        };
        // Body inside the brackets must contain at least one `:` (IPv6 has them).
        if close == 1 {
            return false;
        }
        // After `]`, allow nothing or `:digits`.
        match host.get(close + 1..) {
            Some("") | None => return true,
            Some(rest) if rest.starts_with(':') && rest[1..].bytes().all(|b| b.is_ascii_digit()) => return true,
            _ => return false,
        }
    }
    // Otherwise: at most one `:` (port separator).
    host.matches(':').count() <= 1
}

/// Case-insensitive whitelist match. Strips the `:port` suffix before comparison
/// so `Host: example.com:8080` matches `example.com` in the whitelist.
fn host_in_whitelist(host: &str, whitelist: &[String]) -> bool {
    let host_no_port = strip_port(host);
    whitelist.iter().any(|allowed| {
        let allowed_no_port = strip_port(allowed);
        host_no_port.eq_ignore_ascii_case(allowed_no_port)
    })
}

/// Strip `:port` from a host string, respecting IPv6 bracketed form.
fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            return &rest[..close];
        }
        return host;
    }
    match host.rsplit_once(':') {
        Some((head, tail)) if tail.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => host,
    }
}

/// Validate `X-Forwarded-For`. Returns `Some(reason)` when malformed or
/// suspicious; `None` for clean.
fn validate_x_forwarded_for<'a>(value: &str, client_ip: IpAddr, max_hops: usize) -> Option<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let hops: Vec<&str> = trimmed.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if hops.is_empty() {
        return None;
    }
    if max_hops > 0 && hops.len() > max_hops {
        return Some("X-Forwarded-For chain exceeds max_hops");
    }
    // Leftmost hop — the originating client. If our actual client_ip is public
    // and the leftmost claims to be private, the request is lying about its
    // origin (classic XFF spoofing primitive).
    if !is_private_or_loopback(client_ip)
        && let Some(first) = hops.first()
        && let Ok(addr) = first.parse::<IpAddr>()
        && is_private_or_loopback(addr)
    {
        return Some("X-Forwarded-For leftmost is private but client_ip is public");
    }
    None
}

const fn is_private_or_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback() || v4.is_private() || v4.is_link_local();
            }
            let segs = v6.segments();
            (segs[0] & 0xfe00 == 0xfc00) || (segs[0] & 0xffc0 == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Arc;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx(headers: HashMap<String, String>, client_ip: &str, dc: DefenseConfig) -> RequestCtx {
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: client_ip.parse().unwrap(),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers,
            body_preview: Bytes::new(),
            content_length: 0,
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

    fn mk(name: &str, value: &str) -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert(name.to_string(), value.to_string());
        h
    }

    // ─── Rule 1: raw CRLF in value ───────────────────────────────────────

    #[test]
    fn detects_raw_crlf_in_referer() {
        let ctx = make_ctx(
            mk("referer", "foo\r\nSet-Cookie: admin=1"),
            "8.8.8.8",
            DefenseConfig::default(),
        );
        let det = HeaderInjectionCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "HDR-001");
    }

    #[test]
    fn detects_raw_lf_only() {
        let ctx = make_ctx(mk("user-agent", "evil\nfoo"), "8.8.8.8", DefenseConfig::default());
        assert!(HeaderInjectionCheck::new().check(&ctx).is_some());
    }

    #[test]
    fn detects_nul_byte_in_value() {
        let ctx = make_ctx(mk("x-custom", "abc\0def"), "8.8.8.8", DefenseConfig::default());
        assert!(HeaderInjectionCheck::new().check(&ctx).is_some());
    }

    // ─── Rule 2: encoded CRLF ────────────────────────────────────────────

    #[test]
    fn detects_single_encoded_crlf() {
        let ctx = make_ctx(
            mk("user-agent", "foo%0d%0aSet-Cookie: x"),
            "8.8.8.8",
            DefenseConfig::default(),
        );
        let det = HeaderInjectionCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "HDR-002");
    }

    #[test]
    fn detects_double_encoded_crlf() {
        let ctx = make_ctx(
            mk("cookie", "a=b%250d%250aSet-Cookie:y"),
            "8.8.8.8",
            DefenseConfig::default(),
        );
        let det = HeaderInjectionCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "HDR-002");
    }

    // ─── Rule 5: CRLF in header NAME ─────────────────────────────────────

    #[test]
    fn detects_crlf_in_header_name() {
        let mut h = HashMap::new();
        h.insert("evil\nname".to_string(), "value".to_string());
        let ctx = make_ctx(h, "8.8.8.8", DefenseConfig::default());
        let det = HeaderInjectionCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "HDR-005");
    }

    // ─── Rule 3: Host header validation ──────────────────────────────────

    #[test]
    fn detects_host_with_at_sign() {
        let ctx = make_ctx(mk("host", "evil.com@target.com"), "8.8.8.8", DefenseConfig::default());
        let det = HeaderInjectionCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "HDR-003");
    }

    #[test]
    fn detects_host_with_space() {
        let ctx = make_ctx(
            mk("host", "target.com target2.com"),
            "8.8.8.8",
            DefenseConfig::default(),
        );
        let det = HeaderInjectionCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "HDR-003");
    }

    #[test]
    fn detects_host_with_comma() {
        let ctx = make_ctx(mk("host", "a.com,b.com"), "8.8.8.8", DefenseConfig::default());
        assert!(HeaderInjectionCheck::new().check(&ctx).is_some());
    }

    #[test]
    fn allows_clean_host_with_port() {
        let ctx = make_ctx(mk("host", "example.com:8080"), "8.8.8.8", DefenseConfig::default());
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn allows_clean_ipv6_host() {
        let ctx = make_ctx(mk("host", "[2606:4700::1111]:443"), "8.8.8.8", DefenseConfig::default());
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn detects_host_not_in_whitelist() {
        let dc = DefenseConfig {
            host_inbound_whitelist: vec!["legit.com".to_string()],
            ..DefenseConfig::default()
        };
        let ctx = make_ctx(mk("host", "evil.com"), "8.8.8.8", dc);
        let det = HeaderInjectionCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "HDR-003");
    }

    #[test]
    fn allows_host_in_whitelist() {
        let dc = DefenseConfig {
            host_inbound_whitelist: vec!["legit.com".to_string()],
            ..DefenseConfig::default()
        };
        let ctx = make_ctx(mk("host", "legit.com"), "8.8.8.8", dc);
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn whitelist_match_strips_port() {
        let dc = DefenseConfig {
            host_inbound_whitelist: vec!["legit.com".to_string()],
            ..DefenseConfig::default()
        };
        let ctx = make_ctx(mk("host", "legit.com:8443"), "8.8.8.8", dc);
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn empty_whitelist_skips_host_check() {
        // Default whitelist is empty — Host validation falls through to syntax
        // checks only. Operators must opt in per host.
        let ctx = make_ctx(mk("host", "anything.example"), "8.8.8.8", DefenseConfig::default());
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    // ─── Rule 4: X-Forwarded-For ─────────────────────────────────────────

    #[test]
    fn detects_xff_leftmost_private_with_public_client() {
        let ctx = make_ctx(
            mk("x-forwarded-for", "10.0.0.1, 1.2.3.4"),
            "1.2.3.4",
            DefenseConfig::default(),
        );
        let det = HeaderInjectionCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "HDR-004");
    }

    #[test]
    fn allows_xff_leftmost_public() {
        let ctx = make_ctx(
            mk("x-forwarded-for", "1.2.3.4, 5.6.7.8"),
            "5.6.7.8",
            DefenseConfig::default(),
        );
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn detects_xff_chain_exceeds_max_hops() {
        let chain = "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6";
        let dc = DefenseConfig {
            xf2_max_hops: 5,
            ..DefenseConfig::default()
        };
        let ctx = make_ctx(mk("x-forwarded-for", chain), "1.1.1.1", dc);
        let det = HeaderInjectionCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "HDR-004");
    }

    #[test]
    fn allows_xff_under_max_hops() {
        let dc = DefenseConfig {
            xf2_max_hops: 5,
            ..DefenseConfig::default()
        };
        let ctx = make_ctx(mk("x-forwarded-for", "1.1.1.1, 2.2.2.2, 3.3.3.3"), "3.3.3.3", dc);
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn allows_empty_xff() {
        let ctx = make_ctx(mk("x-forwarded-for", ""), "8.8.8.8", DefenseConfig::default());
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn allows_xff_when_client_ip_is_private() {
        // If our ingress is itself private (e.g. internal mesh request), a
        // private leftmost is plausible — don't false-flag.
        let ctx = make_ctx(
            mk("x-forwarded-for", "10.0.0.1, 192.168.1.5"),
            "10.0.0.1",
            DefenseConfig::default(),
        );
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    // ─── Cross-cutting ────────────────────────────────────────────────────

    #[test]
    fn allows_clean_authorization_jwt() {
        let ctx = make_ctx(
            mk("authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIx.foo"),
            "8.8.8.8",
            DefenseConfig::default(),
        );
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn allows_clean_user_agent() {
        let ctx = make_ctx(
            mk("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            "8.8.8.8",
            DefenseConfig::default(),
        );
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn skipped_when_check_disabled() {
        let dc = DefenseConfig {
            header_injection: false,
            ..DefenseConfig::default()
        };
        let ctx = make_ctx(mk("referer", "foo\r\nSet-Cookie: x"), "8.8.8.8", dc);
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn empty_headers_no_detection() {
        let ctx = make_ctx(HashMap::new(), "8.8.8.8", DefenseConfig::default());
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn allows_utf8_value_with_no_crlf() {
        let ctx = make_ctx(mk("x-custom", "héllo wörld 你好"), "8.8.8.8", DefenseConfig::default());
        assert!(HeaderInjectionCheck::new().check(&ctx).is_none());
    }

    #[test]
    fn detection_carries_correct_phase() {
        let ctx = make_ctx(mk("referer", "foo\r\n"), "8.8.8.8", DefenseConfig::default());
        let det = HeaderInjectionCheck::new().check(&ctx).expect("hit");
        assert_eq!(det.phase, Phase::HeaderInjection);
        assert_eq!(det.rule_name, "Header Injection");
    }

    // ─── strip_port unit tests ──────────────────────────────────────────

    #[test]
    fn strip_port_plain_host() {
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("example.com:8080"), "example.com");
    }

    #[test]
    fn strip_port_ipv6_bracketed() {
        assert_eq!(strip_port("[::1]"), "::1");
        assert_eq!(strip_port("[::1]:8080"), "::1");
    }
}
