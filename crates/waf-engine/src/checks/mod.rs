pub mod anti_hotlink;
pub mod body_abuse;
pub(crate) mod body_abuse_walker;
pub mod bot;
pub mod brute_force;
pub(crate) mod brute_force_extractors;
pub(crate) mod brute_force_state;
pub mod cc;
pub mod dir_traversal;
pub mod geo;
pub mod header_injection;
pub(crate) mod header_injection_patterns;
pub mod owasp;
pub mod rce;
pub mod scanner;
pub(crate) mod scanner_state;
pub mod sensitive;
pub mod sql_injection;
pub(crate) mod sql_injection_patterns;
pub(crate) mod sql_injection_scanners;
pub mod ssrf;
pub(crate) mod ssrf_patterns;
pub(crate) mod ssrf_scanners;
pub mod xss;
pub(crate) mod xss_scanners;

pub use anti_hotlink::AntiHotlinkCheck;
pub use body_abuse::RequestBodyAbuseCheck;
pub use bot::BotCheck;
pub use brute_force::BruteForceCheck;
pub use cc::CcCheck;
pub use dir_traversal::DirTraversalCheck;
pub use geo::{GeoCheck, GeoRule, GeoRuleMode};
pub use header_injection::HeaderInjectionCheck;
pub use owasp::OWASPCheck;
pub use rce::RceCheck;
pub use scanner::ScannerCheck;
pub use sensitive::SensitiveCheck;
pub use sql_injection::SqlInjectionCheck;
pub use ssrf::SsrfCheck;
pub use xss::XssCheck;

use waf_common::{DetectionResult, RequestCtx};

/// Trait implemented by every WAF checker module.
///
/// Each checker is stateless (detection patterns) or uses interior mutability
/// (CC rate limiter). The pipeline calls `check()` in sequence and
/// short-circuits on the first `Some(result)`.
pub trait Check: Send + Sync {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult>;

    /// Default no-op response hook. Override in checks that need upstream
    /// status (FR-018 brute force, FR-019 4xx-burst). Body is NOT exposed in
    /// v1: Pingora `response_filter` gives headers + status only; the body
    /// path via `response_body_filter` is deferred.
    fn on_response(&self, _ctx: &RequestCtx, _status: u16) {}
}

/// Monotonic clock abstraction so stateful checks (FR-018 brute-force,
/// FR-019 scanner sliding-window) can be tested without sleeping.
///
/// Production wires `SystemClock`; tests inject `MockClock` and call
/// `advance()` to move time forward deterministically.
pub trait Clock: Send + Sync {
    fn now(&self) -> std::time::Instant;
}

/// Real-time `Clock` implementation backed by `Instant::now()`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
}

#[cfg(test)]
pub mod test_clock {
    use super::Clock;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Test fixture clock — advances only when `advance()` is called.
    pub struct MockClock {
        offset_nanos: AtomicU64,
        base: std::time::Instant,
    }

    impl MockClock {
        pub fn new() -> Self {
            Self {
                offset_nanos: AtomicU64::new(0),
                base: std::time::Instant::now(),
            }
        }

        pub fn advance(&self, dur: std::time::Duration) {
            let nanos = u64::try_from(dur.as_nanos()).unwrap_or(u64::MAX);
            self.offset_nanos.fetch_add(nanos, Ordering::SeqCst);
        }
    }

    impl Default for MockClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> std::time::Instant {
            self.base + std::time::Duration::from_nanos(self.offset_nanos.load(Ordering::SeqCst))
        }
    }
}

// ─── Shared utilities ─────────────────────────────────────────────────────────

/// Decode a percent-encoded string (URL decoding, ASCII only).
#[allow(clippy::indexing_slicing)] // bounds checked by loop guard: i < len, i+2 < len
pub(crate) fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = char::from(bytes[i + 1]).to_digit(16);
            let lo = char::from(bytes[i + 2]).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                #[allow(clippy::cast_possible_truncation)]
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Iteratively URL-decode until the result stabilises or the iteration cap is reached.
///
/// This catches double/triple-encoded evasion attempts such as:
///   `%253Cscript%253E` → (pass 1) `%3Cscript%3E` → (pass 2) `<script>`
///
/// `MAX_ITERATIONS` is capped at 3 to cover the most common multi-encoding
/// depths while preventing pathological inputs from causing excessive work.
pub(crate) fn url_decode_recursive(input: &str) -> String {
    const MAX_ITERATIONS: usize = 3;
    let mut current = url_decode(input);
    for _ in 1..MAX_ITERATIONS {
        let next = url_decode(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// Collect all strings to inspect from the request context.
///
/// Returns a list of `(location, value)` pairs so error messages can
/// indicate where the pattern was found.
///
/// Each field is included in three forms: raw, single-decoded, and
/// recursively-decoded (up to 3 passes) so that double/triple-encoded
/// evasion attempts are caught alongside the plain variants.
pub(crate) fn request_targets(ctx: &RequestCtx) -> Vec<(&'static str, String)> {
    let mut targets = Vec::new();

    // Raw, decoded, and recursively-decoded path
    targets.push(("path", ctx.path.clone()));
    let path_decoded = url_decode(&ctx.path);
    let path_recursive = url_decode_recursive(&ctx.path);
    if path_decoded != ctx.path {
        targets.push(("path(decoded)", path_decoded.clone()));
    }
    if path_recursive != path_decoded {
        targets.push(("path(decoded-recursive)", path_recursive));
    }

    // Raw, decoded, and recursively-decoded query string
    if !ctx.query.is_empty() {
        targets.push(("query", ctx.query.clone()));
        let query_decoded = url_decode(&ctx.query);
        let query_recursive = url_decode_recursive(&ctx.query);
        if query_decoded != ctx.query {
            targets.push(("query(decoded)", query_decoded.clone()));
        }
        if query_recursive != query_decoded {
            targets.push(("query(decoded-recursive)", query_recursive));
        }
    }

    // Cookie header
    if let Some(cookie) = ctx.headers.get("cookie") {
        targets.push(("cookie", cookie.clone()));
        let cookie_decoded = url_decode(cookie);
        let cookie_recursive = url_decode_recursive(cookie);
        if cookie_decoded != *cookie {
            targets.push(("cookie(decoded)", cookie_decoded.clone()));
        }
        if cookie_recursive != cookie_decoded {
            targets.push(("cookie(decoded-recursive)", cookie_recursive));
        }
    }

    // Request body preview (best-effort UTF-8)
    if !ctx.body_preview.is_empty() {
        let body_str = String::from_utf8_lossy(&ctx.body_preview).into_owned();
        targets.push(("body", body_str.clone()));
        let body_decoded = url_decode(&body_str);
        let body_recursive = url_decode_recursive(&body_str);
        if body_decoded != body_str {
            targets.push(("body(decoded)", body_decoded.clone()));
        }
        if body_recursive != body_decoded {
            targets.push(("body(decoded-recursive)", body_recursive));
        }
    }

    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode_recursive_double_encoded() {
        // %253C = %25 → %, 3C → <  (two passes needed)
        assert_eq!(url_decode_recursive("%253Cscript%253E"), "<script>");
    }

    #[test]
    fn test_url_decode_recursive_triple_encoded() {
        // %25253C → %253C → %3C → <  (three passes needed)
        assert_eq!(url_decode_recursive("%25253Cscript%25253E"), "<script>");
    }

    #[test]
    fn test_url_decode_recursive_normal_input() {
        // Plain text must pass through unchanged.
        assert_eq!(url_decode_recursive("hello world"), "hello world");
    }

    #[test]
    fn test_url_decode_recursive_single_encoded() {
        // Standard %3C → <  (one pass)
        assert_eq!(url_decode_recursive("%3Cscript%3E"), "<script>");
    }

    #[test]
    fn test_url_decode_recursive_max_iterations() {
        // Depth-4 encoding exceeds MAX_ITERATIONS=3; the loop stops after 3 passes.
        // %2525253C: pass1 → %25253C, pass2 → %253C, pass3 → %3C  (stops, result is %3C)
        assert_eq!(url_decode_recursive("%2525253C"), "%3C");
    }
}
