//! SSRF helpers — URL extraction, obfuscated-IP normalisation, RFC1918 check.
//!
//! Kept in a sibling file so `ssrf.rs` stays under the modularization limit.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;

use regex::Regex;
use waf_common::RequestCtx;

use super::ssrf_patterns::PRIVATE_CIDRS;
use super::url_decode_recursive;

/// Headers that have historically been the SSRF foothold and are worth scanning
/// even if the body is empty. Lowercase — `RequestCtx.headers` keys arrive
/// lowercase from the gateway.
const URL_BEARING_HEADERS: &[&str] = &[
    "referer",
    "location",
    "x-original-url",
    "x-rewrite-url",
    "x-forwarded-host",
    "x-forwarded-server",
    "destination",
    "forwarded",
];

// SAFETY: compile-time literal — failure is a code bug.
static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    match Regex::new(r#"(?i)https?://[^\s\x00-\x20\x7f"'<>\\]+"#) {
        Ok(re) => re,
        Err(e) => {
            tracing::error!("BUG: SSRF URL extractor regex failed to compile: {e}");
            // Returning a regex that matches nothing keeps the check from
            // firing rather than panicking the engine.
            #[allow(clippy::expect_used)]
            Regex::new(r"$^").expect("trivial regex must compile")
        }
    }
});

/// Pull every `http(s)://…` substring from request body, query, cookie, and
/// the SSRF-prone headers. Each candidate is recursively url-decoded before
/// regex extraction so `webhook=http%3A//10.0.0.1/` is normalised first.
pub fn extract_urls(ctx: &RequestCtx) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    let mut push_from = |location: &str, text: &str| {
        if text.is_empty() {
            return;
        }
        let decoded = url_decode_recursive(text);
        for m in URL_RE.find_iter(&decoded) {
            out.push((location.to_string(), m.as_str().to_string()));
        }
    };

    push_from("query", &ctx.query);
    if !ctx.body_preview.is_empty() {
        let body_str = String::from_utf8_lossy(&ctx.body_preview);
        push_from("body", &body_str);
    }
    for header_name in URL_BEARING_HEADERS {
        if let Some(value) = ctx.headers.get(*header_name) {
            push_from(&format!("header.{header_name}"), value);
        }
    }
    if let Some(cookie) = ctx.headers.get("cookie") {
        push_from("cookie", cookie);
    }
    out
}

/// Parse a host string into an `IpAddr`, accepting the obfuscated forms that
/// classic SSRF payloads use to bypass naive substring filters.
///
/// Recognised:
/// - `127.0.0.1`, `::1` (canonical)
/// - `0x7f000001` / `0X7F000001` (hex dword)
/// - `017700000001` (leading-zero octal dword)
/// - `2130706433` (decimal dword)
///
/// Mixed-radix dotted forms like `0x7F.0.0.1` are normalised by `Url::parse`
/// before this function ever sees the `host_str`, so they reach this code as
/// `127.0.0.1` already.
pub fn parse_obfuscated_ip(s: &str) -> Option<IpAddr> {
    if let Ok(addr) = s.parse::<IpAddr>() {
        return Some(addr);
    }
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
        && let Ok(n) = u32::from_str_radix(rest, 16)
    {
        return Some(IpAddr::V4(Ipv4Addr::from(n)));
    }
    if s.starts_with('0')
        && s.len() > 1
        && !s.starts_with("0x")
        && !s.starts_with("0X")
        && s.bytes().all(|b| (b'0'..=b'7').contains(&b))
        && let Ok(n) = u32::from_str_radix(s, 8)
    {
        return Some(IpAddr::V4(Ipv4Addr::from(n)));
    }
    if s.bytes().all(|b| b.is_ascii_digit())
        && let Ok(n) = s.parse::<u32>()
    {
        return Some(IpAddr::V4(Ipv4Addr::from(n)));
    }
    None
}

/// Return `true` if the IP belongs to a private / loopback / link-local
/// range — i.e. should not be reachable from a user-supplied URL.
///
/// IPv6 addresses are first tested for loopback (`::1`) and IPv4-mapped form
/// (`::ffff:a.b.c.d`); the mapped IPv4 is then run through the same CIDR set
/// so `[::ffff:169.254.169.254]` is caught the same way `169.254.169.254` is.
pub fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => PRIVATE_CIDRS.iter().any(|net| net.contains(&v4)),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return PRIVATE_CIDRS.iter().any(|net| net.contains(&v4));
            }
            // Reject IPv6 unique-local + link-local prefixes; everything
            // else is treated as routable for v1.
            let segs = v6.segments();
            // fc00::/7 (unique-local)
            if segs[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            // fe80::/10 (link-local)
            if segs[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn parse_obfuscated_ip_canonical_v4() {
        let addr = parse_obfuscated_ip("127.0.0.1").expect("canonical");
        assert!(addr.is_loopback());
    }

    #[test]
    fn parse_obfuscated_ip_hex() {
        let addr = parse_obfuscated_ip("0x7f000001").expect("hex");
        assert_eq!(addr.to_string(), "127.0.0.1");
    }

    #[test]
    fn parse_obfuscated_ip_hex_uppercase() {
        let addr = parse_obfuscated_ip("0X7F000001").expect("HEX");
        assert_eq!(addr.to_string(), "127.0.0.1");
    }

    #[test]
    fn parse_obfuscated_ip_octal() {
        let addr = parse_obfuscated_ip("017700000001").expect("octal");
        assert_eq!(addr.to_string(), "127.0.0.1");
    }

    #[test]
    fn parse_obfuscated_ip_dword_decimal() {
        let addr = parse_obfuscated_ip("2130706433").expect("dword");
        assert_eq!(addr.to_string(), "127.0.0.1");
    }

    #[test]
    fn parse_obfuscated_ip_rejects_arbitrary_string() {
        assert!(parse_obfuscated_ip("example.com").is_none());
        assert!(parse_obfuscated_ip("notanip").is_none());
    }

    #[test]
    fn parse_obfuscated_ip_v6_loopback() {
        let addr = parse_obfuscated_ip("::1").expect("v6 loopback");
        assert!(addr.is_loopback());
    }

    #[test]
    fn is_private_ip_rfc1918() {
        for s in [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
        ] {
            let addr: IpAddr = s.parse().expect("test ip");
            assert!(is_private_ip(addr), "{s} should be private");
        }
    }

    #[test]
    fn is_private_ip_public_v4_returns_false() {
        for s in ["8.8.8.8", "1.1.1.1", "100.64.0.1", "100.100.100.1"] {
            let addr: IpAddr = s.parse().expect("test ip");
            assert!(!is_private_ip(addr), "{s} should not be private");
        }
    }

    #[test]
    fn is_private_ip_v6_mapped_v4() {
        // ::ffff:169.254.169.254 — must catch the mapped form.
        let v6: IpAddr = "::ffff:169.254.169.254".parse().expect("mapped");
        assert!(is_private_ip(v6));
    }

    #[test]
    fn is_private_ip_v6_unique_local() {
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1));
        assert!(is_private_ip(v6));
    }

    #[test]
    fn is_private_ip_v6_link_local() {
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert!(is_private_ip(v6));
    }

    #[test]
    fn is_private_ip_v6_public_returns_false() {
        let v6: IpAddr = "2606:4700:4700::1111".parse().expect("public v6");
        assert!(!is_private_ip(v6));
    }
}
