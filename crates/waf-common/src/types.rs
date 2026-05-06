use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use crate::tier::{Tier, TierPolicy};

/// `GeoIP` information resolved from the client IP address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoIpInfo {
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
    pub iso_code: String,
}

/// Request context passed through the WAF pipeline
#[derive(Debug, Clone)]
pub struct RequestCtx {
    pub req_id: String,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body_preview: Bytes,
    pub content_length: u64,
    pub is_tls: bool,
    pub host_config: Arc<HostConfig>,
    /// `GeoIP` info populated by the WAF engine before checks run.
    ///
    /// `None` if `GeoIP` is disabled or the xdb file is missing.
    pub geo: Option<GeoIpInfo>,
    /// Protection tier classified for this request (FR-002).
    ///
    /// Populated by `gateway::ctx_builder` via `TierPolicyRegistry::classify`
    /// before any check consumes the value. Defaults to `Tier::CatchAll`
    /// when no tier registry is configured (boot fallback).
    pub tier: Tier,
    /// Tier policy referenced from the same snapshot the tier was classified
    /// against. Held as `Arc` so consumers can keep it across `.await` without
    /// cloning the policy struct.
    pub tier_policy: Arc<TierPolicy>,
    /// Cookies parsed once from the `Cookie` header at ctx build time. Empty
    /// when no `Cookie` header is present. Kept here (not lazy) so per-rule
    /// `Cookie(name)` lookups stay O(1) without re-splitting the header.
    /// Names are case-sensitive per RFC 6265.
    pub cookies: HashMap<String, String>,
}

/// Parse a `Cookie:` header value into a name → value map.
///
/// Splits on `;`, trims whitespace, splits the first `=`. Pairs missing a
/// name or `=` are silently dropped (defensive: malformed cookies are common
/// and must not panic). Names are case-sensitive per RFC 6265.
#[must_use]
pub fn parse_cookie_header(header: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in header.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        out.insert(name.to_string(), value.trim().to_string());
    }
    out
}

impl RequestCtx {
    /// Process-wide default tier policy used when no `TierPolicyRegistry` is
    /// wired into the gateway (e.g., test fixtures, boot fallback). Cached
    /// in a `OnceLock` so every fixture/fallback path shares the same `Arc`.
    #[must_use]
    pub fn default_tier_policy() -> Arc<TierPolicy> {
        static DEFAULT: OnceLock<Arc<TierPolicy>> = OnceLock::new();
        Arc::clone(DEFAULT.get_or_init(|| Arc::new(TierPolicy::default())))
    }
}

/// WAF action decision
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WafAction {
    Allow,
    Block { status: u16, body: Option<String> },
    LogOnly,
    Redirect { url: String },
}

/// WAF decision with context
#[derive(Debug, Clone)]
pub struct WafDecision {
    pub action: WafAction,
    pub result: Option<DetectionResult>,
}

impl WafDecision {
    pub const fn allow() -> Self {
        Self {
            action: WafAction::Allow,
            result: None,
        }
    }

    pub const fn block(status: u16, body: Option<String>, result: DetectionResult) -> Self {
        Self {
            action: WafAction::Block { status, body },
            result: Some(result),
        }
    }

    pub const fn is_allowed(&self) -> bool {
        matches!(self.action, WafAction::Allow | WafAction::LogOnly)
    }
}

/// Detection phase
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    IpWhitelist = 1,
    IpBlacklist = 2,
    UrlWhitelist = 3,
    UrlBlacklist = 4,
    SqlInjection = 5,
    Xss = 6,
    Rce = 7,
    Scanner = 8,
    DirTraversal = 9,
    Bot = 10,
    RateLimit = 11,
    /// Custom scripted rules engine
    CustomRule = 12,
    /// OWASP Core Rule Set checks
    Owasp = 13,
    /// Sensitive word / data-leak detection
    Sensitive = 14,
    /// Anti-hotlinking (Referer check)
    AntiHotlink = 15,
    /// `CrowdSec` bouncer / `AppSec` decision
    CrowdSec = 16,
    /// `GeoIP`-based access control
    GeoIp = 17,
    /// Community threat intelligence blocklist
    Community = 18,
    /// `DDoS` burst detection (FR-005)
    Ddos = 19,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpWhitelist => write!(f, "IP Whitelist"),
            Self::IpBlacklist => write!(f, "IP Blacklist"),
            Self::UrlWhitelist => write!(f, "URL Whitelist"),
            Self::UrlBlacklist => write!(f, "URL Blacklist"),
            Self::SqlInjection => write!(f, "SQL Injection"),
            Self::Xss => write!(f, "XSS"),
            Self::Rce => write!(f, "RCE"),
            Self::Scanner => write!(f, "Scanner"),
            Self::DirTraversal => write!(f, "Directory Traversal"),
            Self::Bot => write!(f, "Bot"),
            Self::RateLimit => write!(f, "Rate Limit"),
            Self::CustomRule => write!(f, "Custom Rule"),
            Self::Owasp => write!(f, "OWASP CRS"),
            Self::Sensitive => write!(f, "Sensitive Data"),
            Self::AntiHotlink => write!(f, "Anti-Hotlink"),
            Self::CrowdSec => write!(f, "CrowdSec"),
            Self::GeoIp => write!(f, "GeoIP"),
            Self::Community => write!(f, "Community"),
            Self::Ddos => write!(f, "DDoS"),
        }
    }
}

/// Detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub phase: Phase,
    pub detail: String,
}

/// Host configuration matching `SamWaf` Hosts model
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub code: String,
    pub host: String,
    pub port: u16,
    pub ssl: bool,
    pub guard_status: bool,
    pub remote_host: String,
    pub remote_port: u16,
    pub remote_ip: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub remarks: Option<String>,
    pub start_status: bool,
    pub exclude_url_log: Vec<String>,
    pub is_enable_load_balance: bool,
    pub load_balance_strategy: LoadBalanceStrategy,
    pub defense_config: DefenseConfig,
    pub log_only_mode: bool,
    /// Custom HTML block page template; placeholders: `{{req_id}}`, `{{rule_name}}`, `{{client_ip}}`
    pub block_page_template: Option<String>,
    /// Whether to preserve the client's `Host` header when proxying upstream.
    /// When `true` (default, transparent), the upstream sees the original `Host`.
    /// When `false`, `Host` is rewritten to `remote_host` (AC-25 rewrite mode).
    #[serde(default = "default_preserve_host")]
    pub preserve_host: bool,
    /// AC-16: when `true`, scrub the `Server` response header.
    /// Default `false` keeps backend `Server` byte-identical (preserves AC-04).
    #[serde(default)]
    pub strip_server_header: bool,
    /// AC-15: extra response headers to strip on the way out.
    /// Matched case-insensitively. `via` is always stripped via a dedicated filter.
    #[serde(default = "default_header_blocklist")]
    pub header_blocklist: Vec<String>,
    /// AC-17: regex patterns whose matches in identity-encoded response bodies
    /// are replaced with [`mask_token`]. Empty disables body masking. Patterns
    /// are validated at config load; invalid regexes are dropped (fail-open).
    #[serde(default)]
    pub internal_patterns: Vec<String>,
    /// AC-17: replacement token written in place of every matched substring.
    #[serde(default = "default_mask_token")]
    pub mask_token: String,
    /// AC-17: hard ceiling on bytes scanned per response. Beyond this, the
    /// remainder is forwarded untouched with a `tracing::warn!`.
    #[serde(default = "default_body_mask_max_bytes")]
    pub body_mask_max_bytes: u64,
}

const fn default_preserve_host() -> bool {
    true
}

fn default_header_blocklist() -> Vec<String> {
    vec!["x-powered-by-waf".to_string(), "x-waf-version".to_string()]
}

fn default_mask_token() -> String {
    "[redacted]".to_string()
}

const fn default_body_mask_max_bytes() -> u64 {
    1024 * 1024
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            code: String::new(),
            host: String::new(),
            port: 80,
            ssl: false,
            guard_status: true,
            remote_host: String::new(),
            remote_port: 8080,
            remote_ip: None,
            cert_file: None,
            key_file: None,
            remarks: None,
            start_status: true,
            exclude_url_log: Vec::new(),
            is_enable_load_balance: false,
            load_balance_strategy: LoadBalanceStrategy::RoundRobin,
            defense_config: DefenseConfig::default(),
            log_only_mode: false,
            block_page_template: None,
            preserve_host: true,
            strip_server_header: false,
            header_blocklist: default_header_blocklist(),
            internal_patterns: Vec::new(),
            mask_token: default_mask_token(),
            body_mask_max_bytes: default_body_mask_max_bytes(),
        }
    }
}

/// Load balancing strategy
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    #[default]
    RoundRobin,
    IpHash,
    WeightedRoundRobin,
    LeastConnections,
}

/// Defense configuration per host
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct DefenseConfig {
    pub bot: bool,
    pub sqli: bool,
    pub xss: bool,
    pub scan: bool,
    pub rce: bool,
    pub sensitive: bool,
    pub dir_traversal: bool,
    pub owasp_set: bool,
    /// CC / rate-limit protection enabled
    #[serde(default = "bool_true")]
    pub cc: bool,
    /// Token bucket refill rate (requests per second)
    #[serde(default = "default_cc_rps")]
    pub cc_rps: f64,
    /// Token bucket burst capacity
    #[serde(default = "default_cc_burst")]
    pub cc_burst: u32,
    /// Violations before auto-ban
    #[serde(default = "default_cc_ban_threshold")]
    pub cc_ban_threshold: u32,
    /// Auto-ban duration in seconds
    #[serde(default = "default_cc_ban_duration_secs")]
    pub cc_ban_duration_secs: u64,
    /// OWASP CRS paranoia level (1-4, default 1 = most permissive)
    #[serde(default = "default_owasp_paranoia")]
    pub owasp_paranoia: u8,
    /// Block scripted HTTP clients (curl, python-requests, go-http-client,
    /// libwww-perl) by their User-Agent. Default `false` because these are
    /// extremely common in legitimate traffic — health checks, internal
    /// service calls, automation scripts, container orchestrators, CI
    /// pipelines. Enable only on hosts that are guaranteed to be reached
    /// exclusively by browsers (e.g. a public-facing web app with no API
    /// surface). Real attack-tool detection (sqlmap, nikto, nuclei, …) is
    /// always on regardless of this flag.
    #[serde(default = "bool_false")]
    pub block_scripted_clients: bool,
}

const fn bool_true() -> bool {
    true
}
const fn bool_false() -> bool {
    false
}
const fn default_cc_rps() -> f64 {
    100.0
}
const fn default_cc_burst() -> u32 {
    200
}
const fn default_cc_ban_threshold() -> u32 {
    10
}
const fn default_cc_ban_duration_secs() -> u64 {
    300
}
const fn default_owasp_paranoia() -> u8 {
    1
}

impl Default for DefenseConfig {
    fn default() -> Self {
        Self {
            bot: true,
            sqli: true,
            xss: true,
            scan: true,
            rce: true,
            sensitive: true,
            dir_traversal: true,
            owasp_set: false,
            cc: true,
            cc_rps: default_cc_rps(),
            cc_burst: default_cc_burst(),
            cc_ban_threshold: default_cc_ban_threshold(),
            cc_ban_duration_secs: default_cc_ban_duration_secs(),
            block_scripted_clients: false,
            owasp_paranoia: default_owasp_paranoia(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_cookie_header;

    #[test]
    fn parse_cookie_header_basic() {
        let m = parse_cookie_header("a=1; b=2");
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("2"));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn parse_cookie_header_malformed_skipped() {
        // Pairs without `=` and pairs with empty name must be silently dropped.
        let m = parse_cookie_header("=v; k=; valid=ok; nocookie; ; another=fine");
        assert_eq!(m.get("k").map(String::as_str), Some(""));
        assert_eq!(m.get("valid").map(String::as_str), Some("ok"));
        assert_eq!(m.get("another").map(String::as_str), Some("fine"));
        assert!(!m.contains_key(""));
        assert!(!m.contains_key("nocookie"));
    }

    #[test]
    fn parse_cookie_header_empty() {
        assert!(parse_cookie_header("").is_empty());
    }

    #[test]
    fn parse_cookie_header_case_sensitive() {
        let m = parse_cookie_header("Session=abc; session=xyz");
        // RFC 6265: cookie names are case-sensitive.
        assert_eq!(m.get("Session").map(String::as_str), Some("abc"));
        assert_eq!(m.get("session").map(String::as_str), Some("xyz"));
    }
}
