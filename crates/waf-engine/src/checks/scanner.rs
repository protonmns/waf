use std::sync::{Arc, LazyLock};
use std::time::Duration;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::scanner_state::ScannerState;
use super::{Check, Clock, SystemClock};

static SCANNER_UA_DESCS: &[&str] = &[
    "sqlmap (SQL injection scanner)",
    "Nmap (port scanner)",
    "Nikto (web scanner)",
    "Burp Suite (proxy/scanner)",
    "Acunetix (web scanner)",
    "Nessus (vulnerability scanner)",
    "Metasploit (exploitation framework)",
    "w3af (web application attack framework)",
    "DirBuster / dirbuster (directory brute-forcer)",
    "AppScan (IBM web scanner)",
    "WebInspect (HP web scanner)",
    "Paros Proxy",
    "OWASP ZAP",
    "gobuster (directory/DNS brute-forcer)",
    "ffuf (fast web fuzzer)",
    "wfuzz (web fuzzer)",
    "Nuclei (vulnerability scanner)",
    "dirb (web content scanner)",
    "Havij (automated SQL injection)",
    "Masscan (port scanner)",
    "zgrab (banner grabber)",
    "Netsparker (web scanner)",
    "Arachni (web scanner)",
    "OpenVAS (vulnerability scanner)",
    "Vega (web security scanner)",
    "Skipfish",
    "Wapiti (web app vulnerability scanner)",
    "Hydra (login brute-forcer)",
    "Medusa (login brute-forcer)",
    "headless Chrome / Puppeteer / Selenium",
    "PhantomJS",
    "Scrapy (web scraper)",
];

// SAFETY: All patterns are compile-time string literals. If any pattern fails
// to compile it is a code bug that must be caught in development, not at runtime.
static SCANNER_UA_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    match RegexSet::new([
        r"(?i)\bsqlmap\b",
        r"(?i)\bnmap\b",
        r"(?i)\bnikto\b",
        r"(?i)\bburp\b|\bburpsuite\b",
        r"(?i)\bacunetix\b",
        r"(?i)\bnessus\b",
        r"(?i)\bmetasploit\b",
        r"(?i)\bw3af\b",
        r"(?i)\bdirbuster\b",
        r"(?i)\bappscan\b",
        r"(?i)\bwebinspect\b",
        r"(?i)\bparos\b",
        r"(?i)\b(OWASP[\s_-]?)?ZAP\b",
        r"(?i)\bgobuster\b",
        r"(?i)\bffuf\b",
        r"(?i)\bwfuzz\b",
        r"(?i)\bnuclei\b",
        r"(?i)\bdirb\b",
        r"(?i)\bhavij\b",
        r"(?i)\bmasscan\b",
        r"(?i)\bzgrab\b",
        r"(?i)\bnetsparker\b",
        r"(?i)\barachni\b",
        r"(?i)\bopenvas\b",
        r"(?i)\bvega\b",
        r"(?i)\bskipfish\b",
        r"(?i)\bwapiti\b",
        r"(?i)\bhydra\b",
        r"(?i)\bmedusa\b",
        r"(?i)(headlesschrome|headless chrome|puppeteer|selenium|webdriver)",
        r"(?i)\bphantomjs\b",
        r"(?i)\bscrapy\b",
    ]) {
        Ok(set) => set,
        Err(e) => {
            tracing::error!("BUG: scanner UA regex set failed to compile: {e}");
            RegexSet::empty()
        }
    }
});

/// Description text aligned with `SCRIPTED_CLIENT_UA_SET` patterns by index.
static SCRIPTED_CLIENT_UA_DESCS: &[&str] = &[
    "curl (non-browser HTTP client)",
    "Python Requests library",
    "Go HTTP client",
    "libwww-perl (Perl HTTP lib)",
    "wget (non-browser HTTP client)",
    "Apache HttpClient (Java)",
    "Node.js HTTP client",
];

/// Generic scripted-HTTP-client UAs. These are gated behind
/// `DefenseConfig.block_scripted_clients` because they are extremely
/// common in legitimate traffic (health checks, internal services, CI,
/// automation). Operators who run a strictly browser-only public site
/// can opt in to block them.
static SCRIPTED_CLIENT_UA_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    match RegexSet::new([
        r"(?i)^curl/",
        r"(?i)^python-requests/",
        r"(?i)^go-http-client/",
        r"(?i)^libwww-perl/",
        r"(?i)^wget/",
        r"(?i)^apache-httpclient/",
        r"(?i)^node-fetch/|^axios/|^got\s|^undici",
    ]) {
        Ok(set) => set,
        Err(e) => {
            tracing::error!("BUG: scripted-client UA regex set failed to compile: {e}");
            RegexSet::empty()
        }
    }
});

/// Security scanner / automated tool detection checker.
///
/// Combines three signals:
/// 1. User-Agent regex match against known scanner / scripted-client UAs
///    (always on; the original behaviour, untouched).
/// 2. Endpoint enumeration — too many distinct paths from one `client_ip`
///    inside `defense_config.scanner_window_secs` (FR-019).
/// 3. OPTIONS preflight abuse — too many OPTIONS requests inside the same
///    window (FR-019).
///
/// 4xx / 5xx burst detection is deferred until the response-side hook is
/// wired in Phase 07; the state machine is already shape-compatible.
pub struct ScannerCheck {
    state: Arc<ScannerState>,
}

impl ScannerCheck {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        // 100k cap matches DefenseConfig::default().scanner_max_ips. Per-host
        // overrides take effect at request time via the threshold reads.
        Self {
            state: Arc::new(ScannerState::new(100_000, clock)),
        }
    }

    /// Expose the inner state so an engine bootstrap can drive periodic
    /// `prune_older_than` calls (Phase 07/08 wiring).
    pub fn state(&self) -> Arc<ScannerState> {
        Arc::clone(&self.state)
    }
}

impl Default for ScannerCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for ScannerCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.scan {
            return None;
        }

        let ua = ctx.headers.get("user-agent").map_or("", String::as_str);

        // Always check the real attack-tool list (sqlmap / nikto / nuclei /
        // headless browsers / etc.). These are unambiguously malicious so
        // they're never gated by config.
        let matches = SCANNER_UA_SET.matches(ua);
        if matches.matched_any() {
            let idx = matches.iter().next().unwrap_or(0);
            let desc = SCANNER_UA_DESCS.get(idx).copied().unwrap_or("scanner");
            return Some(DetectionResult {
                rule_id: Some(format!("SCAN-{:03}", idx + 1)),
                rule_name: "Scanner".to_string(),
                phase: Phase::Scanner,
                detail: format!("{desc} User-Agent detected"),
            });
        }

        // Optionally check generic scripted-client UAs (curl, python-requests,
        // go-http-client, …). Off by default — see DefenseConfig docs.
        if ctx.host_config.defense_config.block_scripted_clients {
            let matches = SCRIPTED_CLIENT_UA_SET.matches(ua);
            if matches.matched_any() {
                let idx = matches.iter().next().unwrap_or(0);
                let desc = SCRIPTED_CLIENT_UA_DESCS.get(idx).copied().unwrap_or("scripted-client");
                return Some(DetectionResult {
                    rule_id: Some(format!("SCRIPT-{:03}", idx + 1)),
                    rule_name: "Scripted Client".to_string(),
                    phase: Phase::Scanner,
                    detail: format!("{desc} User-Agent detected (block_scripted_clients=true)"),
                });
            }
        }

        // FR-019 sliding-window heuristics. Dedup the path by stripping query
        // so health-check-with-cachebuster traffic does not look like enum.
        let dc = &ctx.host_config.defense_config;
        let window = Duration::from_secs(dc.scanner_window_secs);

        if ctx.method.eq_ignore_ascii_case("OPTIONS") {
            let count = self.state.record_options(ctx.client_ip, window);
            if count >= dc.scanner_options_threshold {
                return Some(DetectionResult {
                    rule_id: Some("SCAN-OPT-001".to_string()),
                    rule_name: "Scanner".to_string(),
                    phase: Phase::Scanner,
                    detail: format!(
                        "OPTIONS preflight abuse: {count} requests from {ip} in {secs}s",
                        ip = ctx.client_ip,
                        secs = dc.scanner_window_secs,
                    ),
                });
            }
        }

        let path_key = ctx.path.split('?').next().unwrap_or(ctx.path.as_str());
        let distinct = self.state.record_path(ctx.client_ip, path_key, window);
        if distinct >= dc.scanner_endpoint_enum_threshold {
            return Some(DetectionResult {
                rule_id: Some("SCAN-ENUM-001".to_string()),
                rule_name: "Scanner".to_string(),
                phase: Phase::Scanner,
                detail: format!(
                    "endpoint enumeration: {distinct} distinct paths from {ip} in {secs}s",
                    ip = ctx.client_ip,
                    secs = dc.scanner_window_secs,
                ),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx_with(ua: &str, block_scripted: bool) -> RequestCtx {
        let mut headers = HashMap::new();
        if !ua.is_empty() {
            headers.insert("user-agent".to_string(), ua.to_string());
        }
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
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
                defense_config: DefenseConfig {
                    scan: true,
                    block_scripted_clients: block_scripted,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            }),
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: std::collections::HashMap::new(),
        }
    }

    fn make_ctx(ua: &str) -> RequestCtx {
        // Default: block_scripted_clients=false (production default).
        make_ctx_with(ua, false)
    }

    #[test]
    fn detects_sqlmap() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("sqlmap/1.7.6#stable (https://sqlmap.org)");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_nikto() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("Nikto/2.1.5");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn allows_regular_browser() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn allows_curl_by_default() {
        // curl is used for health checks, internal services, CI, etc. — never
        // block when block_scripted_clients is the default (false).
        let checker = ScannerCheck::new();
        let ctx = make_ctx("curl/8.5.0");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn allows_python_requests_by_default() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("python-requests/2.28.0");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn allows_go_http_client_by_default() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("Go-http-client/2.0");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn blocks_curl_when_strict_mode_enabled() {
        // Operator opts in via DefenseConfig.block_scripted_clients=true
        // (e.g. browser-only public site). curl is then flagged.
        let checker = ScannerCheck::new();
        let ctx = make_ctx_with("curl/8.5.0", true);
        let result = checker.check(&ctx).expect("strict mode should block curl");
        assert_eq!(result.rule_name, "Scripted Client");
        assert!(result.detail.contains("curl"));
    }

    #[test]
    fn blocks_python_requests_when_strict_mode_enabled() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx_with("python-requests/2.28.0", true);
        let result = checker.check(&ctx).expect("strict mode should block python-requests");
        assert_eq!(result.rule_name, "Scripted Client");
    }

    #[test]
    fn real_attack_tools_blocked_regardless_of_strict_mode() {
        // sqlmap is always blocked, never gated on block_scripted_clients.
        let checker = ScannerCheck::new();
        for strict in [false, true] {
            let ctx = make_ctx_with("sqlmap/1.7.6", strict);
            let result = checker.check(&ctx).unwrap_or_else(|| {
                panic!("sqlmap UA should always be blocked (strict={strict})");
            });
            assert_eq!(result.rule_name, "Scanner");
        }
    }

    // ─── FR-019 sliding-window heuristics ────────────────────────────────

    use crate::checks::test_clock::MockClock;
    use std::time::Duration;
    #[allow(clippy::duration_suboptimal_units)]
    const TEST_WINDOW_EXPIRED: Duration = Duration::from_secs(120);

    fn make_ctx_with_method_path(method: &str, path: &str, ip: &str) -> RequestCtx {
        let mut ctx = make_ctx_with("Mozilla/5.0", false);
        ctx.method = method.to_string();
        ctx.path = path.to_string();
        ctx.client_ip = ip.parse().unwrap();
        ctx
    }

    #[test]
    fn endpoint_enumeration_threshold_triggers_detection() {
        let clock = Arc::new(MockClock::new());
        let checker = ScannerCheck::with_clock(clock);
        // Default threshold is 30 distinct paths.
        for i in 0..29 {
            let ctx = make_ctx_with_method_path("GET", &format!("/p{i}"), "5.6.7.8");
            assert!(checker.check(&ctx).is_none(), "should not fire at {i} distinct paths");
        }
        let ctx = make_ctx_with_method_path("GET", "/p30", "5.6.7.8");
        let det = checker.check(&ctx).expect("hit at 30 distinct");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "SCAN-ENUM-001");
    }

    #[test]
    fn endpoint_enumeration_window_expires() {
        let clock = Arc::new(MockClock::new());
        let checker = ScannerCheck::with_clock(clock.clone());
        for i in 0..29 {
            let ctx = make_ctx_with_method_path("GET", &format!("/p{i}"), "5.6.7.8");
            checker.check(&ctx);
        }
        clock.advance(TEST_WINDOW_EXPIRED);
        // After window passage, the buffer is fresh — one new path = 1 distinct.
        let ctx = make_ctx_with_method_path("GET", "/p_new", "5.6.7.8");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn endpoint_enum_dedups_by_path_ignoring_query() {
        // /a?cb=1, /a?cb=2, /a?cb=3 should count as one distinct path.
        let clock = Arc::new(MockClock::new());
        let checker = ScannerCheck::with_clock(clock);
        for i in 0..50 {
            let ctx = make_ctx_with_method_path("GET", &format!("/api/health?cb={i}"), "5.6.7.8");
            assert!(checker.check(&ctx).is_none());
        }
    }

    #[test]
    fn options_threshold_triggers_detection() {
        let clock = Arc::new(MockClock::new());
        let checker = ScannerCheck::with_clock(clock);
        // Default threshold is 20.
        for _ in 0..19 {
            let ctx = make_ctx_with_method_path("OPTIONS", "/api/users", "5.6.7.8");
            assert!(checker.check(&ctx).is_none());
        }
        let ctx = make_ctx_with_method_path("OPTIONS", "/api/users", "5.6.7.8");
        let det = checker.check(&ctx).expect("hit at 20");
        assert_eq!(det.rule_id.as_deref().unwrap_or(""), "SCAN-OPT-001");
    }

    #[test]
    fn options_window_expires() {
        let clock = Arc::new(MockClock::new());
        let checker = ScannerCheck::with_clock(clock.clone());
        for _ in 0..19 {
            let ctx = make_ctx_with_method_path("OPTIONS", "/api/users", "5.6.7.8");
            checker.check(&ctx);
        }
        clock.advance(TEST_WINDOW_EXPIRED);
        let ctx = make_ctx_with_method_path("OPTIONS", "/api/users", "5.6.7.8");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn per_ip_isolation_does_not_leak() {
        let clock = Arc::new(MockClock::new());
        let checker = ScannerCheck::with_clock(clock);
        // IP A racks up 29 distinct paths.
        for i in 0..29 {
            let ctx = make_ctx_with_method_path("GET", &format!("/p{i}"), "1.1.1.1");
            checker.check(&ctx);
        }
        // IP B starts cold — single request, no detection.
        let ctx_b = make_ctx_with_method_path("GET", "/p0", "2.2.2.2");
        assert!(checker.check(&ctx_b).is_none());
    }

    #[test]
    fn ua_scanner_short_circuits_before_state_lookup() {
        let clock = Arc::new(MockClock::new());
        let checker = ScannerCheck::with_clock(clock);
        let mut ctx = make_ctx_with_method_path("OPTIONS", "/", "5.6.7.8");
        ctx.headers.insert("user-agent".to_string(), "sqlmap/1.7".to_string());
        let det = checker.check(&ctx).expect("hit");
        // UA hit gives SCAN-001..SCAN-032, never the state-machine SCAN-OPT-001.
        let id = det.rule_id.as_deref().unwrap_or("");
        assert!(id.starts_with("SCAN-") && !id.contains("OPT") && !id.contains("ENUM"));
    }

    #[test]
    fn skipped_when_scan_disabled_even_for_state_signals() {
        let clock = Arc::new(MockClock::new());
        let checker = ScannerCheck::with_clock(clock);
        let mut ctx = make_ctx_with_method_path("OPTIONS", "/", "5.6.7.8");
        // Disable scanner check entirely.
        ctx.host_config = Arc::new(waf_common::HostConfig {
            defense_config: DefenseConfig {
                scan: false,
                ..DefenseConfig::default()
            },
            ..waf_common::HostConfig::default()
        });
        for _ in 0..50 {
            assert!(checker.check(&ctx).is_none());
        }
    }
}
