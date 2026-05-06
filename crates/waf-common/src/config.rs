use serde::{Deserialize, Serialize};

/// Top-level application configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    pub proxy: ProxyConfig,
    pub api: ApiConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub hosts: Vec<HostEntry>,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub http3: Http3Config,
    #[serde(default)]
    pub security: SecurityConfig,
    /// Phase 6: `CrowdSec` integration
    #[serde(default)]
    pub crowdsec: CrowdSecConfig,
    /// Phase 7: Rule management
    #[serde(default)]
    pub rules: RulesConfig,
    /// `GeoIP` lookup configuration
    #[serde(default)]
    pub geoip: GeoIpConfig,
    /// Community threat intelligence sharing
    #[serde(default)]
    pub community: CommunityConfig,
    /// Cluster configuration — None means standalone mode (default)
    #[serde(default)]
    pub cluster: Option<ClusterConfig>,
    /// `SQLi` scanner configuration (header scanning, size limits)
    #[serde(default)]
    pub sqli_scan: SqliScanConfig,
    /// Admin panel runtime TOML path (`waf-panel.toml`)
    #[serde(default)]
    pub panel: crate::panel_config::PanelFileRef,
    /// FR-004 rate-limit subsystem reference. Points to a YAML config file
    /// (e.g. `configs/rate-limit.yaml`). Omit ⇒ subsystem inert.
    #[serde(default)]
    pub rate_limit: RateLimitFileRef,
    /// `VictoriaLogs` managed sidecar configuration (opt-in)
    #[serde(default)]
    pub victoria_logs: VictoriaLogsConfig,
}

/// Path reference for `configs/rate-limit.yaml`.
///
/// Lives in waf-common so the gateway/main can read it without pulling in
/// the full engine crate. The actual schema parsing happens engine-side.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RateLimitFileRef {
    /// Path to the YAML file. None ⇒ rate-limit subsystem stays inert.
    #[serde(default)]
    pub config_path: Option<String>,
}

/// Rule source entry from configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSourceEntry {
    pub name: String,
    /// Local directory path (for local sources)
    pub path: Option<String>,
    /// Remote URL (for remote sources)
    pub url: Option<String>,
    /// Rule format: yaml | modsec | json
    #[serde(default = "default_rule_format")]
    pub format: String,
    /// Update interval in seconds (for remote sources)
    #[serde(default = "default_update_interval")]
    pub update_interval: u64,
}

fn default_rule_format() -> String {
    "yaml".to_string()
}
const fn default_update_interval() -> u64 {
    86400
}

/// Phase 7: Rule management configuration
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    /// Directory to watch for rule files
    #[serde(default = "default_rules_dir")]
    pub dir: String,
    /// Enable file-system hot-reload
    #[serde(default = "default_hot_reload")]
    pub hot_reload: bool,
    /// Debounce ms after last file change before reload
    #[serde(default = "default_debounce_ms")]
    pub reload_debounce_ms: u64,
    /// Load built-in OWASP CRS rules
    #[serde(default = "default_true")]
    pub enable_builtin_owasp: bool,
    /// Load built-in bot detection rules
    #[serde(default = "default_true")]
    pub enable_builtin_bot: bool,
    /// Load built-in scanner detection rules
    #[serde(default = "default_true")]
    pub enable_builtin_scanner: bool,
    /// Configured rule sources
    #[serde(default)]
    pub sources: Vec<RuleSourceEntry>,
}

fn default_rules_dir() -> String {
    "rules/".to_string()
}
const fn default_hot_reload() -> bool {
    true
}
const fn default_debounce_ms() -> u64 {
    500
}
const fn default_true() -> bool {
    true
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            dir: default_rules_dir(),
            hot_reload: default_hot_reload(),
            reload_debounce_ms: default_debounce_ms(),
            enable_builtin_owasp: true,
            enable_builtin_bot: true,
            enable_builtin_scanner: true,
            sources: Vec::new(),
        }
    }
}

/// `CrowdSec` integration configuration.
///
/// Mirrors waf-engine `CrowdSecConfig` but lives in waf-common so it can be
/// loaded from the TOML without pulling in the full engine crate as a dep of
/// prx-waf's config loader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrowdSecConfig {
    pub enabled: bool,
    #[serde(default)]
    pub mode: String,
    pub lapi_url: String,
    pub api_key: String,
    #[serde(default = "default_cs_update_secs")]
    pub update_frequency_secs: u64,
    #[serde(default)]
    pub cache_ttl_secs: u64,
    #[serde(default = "default_cs_fallback")]
    pub fallback_action: String,
    #[serde(default)]
    pub scenarios_containing: Vec<String>,
    #[serde(default)]
    pub scenarios_not_containing: Vec<String>,
    pub appsec_endpoint: Option<String>,
    pub appsec_key: Option<String>,
    #[serde(default = "default_appsec_timeout")]
    pub appsec_timeout_ms: u64,
    pub pusher_login: Option<String>,
    pub pusher_password: Option<String>,
}

impl Default for CrowdSecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "bouncer".to_string(),
            lapi_url: "http://127.0.0.1:8080".to_string(),
            api_key: String::new(),
            update_frequency_secs: default_cs_update_secs(),
            cache_ttl_secs: 0,
            fallback_action: default_cs_fallback(),
            scenarios_containing: Vec::new(),
            scenarios_not_containing: Vec::new(),
            appsec_endpoint: None,
            appsec_key: None,
            appsec_timeout_ms: default_appsec_timeout(),
            pusher_login: None,
            pusher_password: None,
        }
    }
}

const fn default_cs_update_secs() -> u64 {
    10
}
fn default_cs_fallback() -> String {
    "allow".to_string()
}
const fn default_appsec_timeout() -> u64 {
    500
}

/// Proxy listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub listen_addr_tls: String,
    pub worker_threads: Option<usize>,
    /// Trust X-Forwarded-For / X-Real-IP headers from upstream proxies.
    /// When `false` (default), the client IP is always taken from the TCP
    /// connection peer address. Only enable this when running behind a
    /// trusted reverse proxy.
    #[serde(default)]
    pub trust_proxy_headers: bool,
    /// List of trusted proxy CIDRs. When `trust_proxy_headers` is true,
    /// only XFF headers from connections originating in these ranges are
    /// honoured. Empty list means trust XFF from any source (legacy
    /// behaviour, NOT recommended for production).
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:80".to_string(),
            listen_addr_tls: "0.0.0.0:443".to_string(),
            worker_threads: None,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
        }
    }
}

/// Management API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub listen_addr: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9527".to_string(),
        }
    }
}

/// Database storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub database_url: String,
    pub max_connections: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_url: "postgresql://prx_waf:prx_waf@127.0.0.1:5432/prx_waf".to_string(),
            max_connections: 20,
        }
    }
}

/// Static host entry from configuration file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    pub host: String,
    pub port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub ssl: Option<bool>,
    pub guard_status: Option<bool>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    /// OWASP CRS rule pipeline. Defaults to `true` for TOML-declared hosts
    /// (operators expect a sensible "WAF on" baseline) — the DB admin UI
    /// keeps its own opt-in toggle.
    #[serde(default)]
    pub owasp_set: Option<bool>,
    /// When `true`, also block generic scripted HTTP clients (curl,
    /// python-requests, go-http-client, libwww-perl, wget, …) by their
    /// User-Agent. Off by default — these are common in legitimate traffic
    /// (health checks, internal services, automation, CI). Enable only on
    /// hosts reached exclusively by browsers.
    #[serde(default)]
    pub block_scripted_clients: Option<bool>,
}

/// Storage backend selector for the response cache.
///
/// Values: `"memory"` (default, moka LRU in-process) | `"embedded"` (spawn
/// valkey-server child) | `"standalone"` (external single Valkey node) |
/// `"cluster"` (external Valkey/Redis cluster).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CacheBackendKind {
    #[default]
    Memory,
    Embedded,
    Standalone,
    Cluster,
}

/// Embedded Valkey child-process supervisor configuration.
///
/// Only read when `cache.backend = "embedded"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedValkeyConfig {
    /// Path to `valkey-server` binary. Empty → auto-detect from `PATH`,
    /// then try `redis-server` as fallback.
    #[serde(default)]
    pub binary_path: String,
    /// Working directory for Valkey data files (used when persistence enabled).
    #[serde(default = "default_valkey_data_dir")]
    pub data_dir: String,
    /// Extra CLI arguments forwarded verbatim to `valkey-server`.
    #[serde(default)]
    pub extra_args: Vec<String>,
}

fn default_valkey_data_dir() -> String {
    "/tmp/prx-valkey".to_string()
}

impl Default for EmbeddedValkeyConfig {
    fn default() -> Self {
        Self {
            binary_path: String::new(),
            data_dir: default_valkey_data_dir(),
            extra_args: Vec::new(),
        }
    }
}

/// Standalone or cluster Valkey/Redis client configuration.
///
/// Read when `cache.backend = "standalone"` or `"cluster"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValkeyClientConfig {
    /// Seed nodes. Standalone: only the first entry is used.
    /// Cluster: at least one required; `fred` discovers the rest automatically.
    #[serde(default = "default_valkey_seeds")]
    pub seeds: Vec<String>,
    /// AUTH password / `requirepass`. Empty = unauthenticated.
    #[serde(default)]
    pub password: String,
    /// Logical DB index. Ignored in cluster mode (always 0).
    #[serde(default)]
    pub db: u8,
    /// Enable TLS.
    #[serde(default)]
    pub tls: bool,
    /// Path to CA certificate PEM for peer verification (optional).
    #[serde(default)]
    pub tls_ca_cert: Option<String>,
    /// Capacity hint for the fred client (maps to `PerformanceConfig::broadcast_channel_capacity`;
    /// the bundled `RedisClient` is multiplexed, not per-key connection pools — see fred `build_pool`).
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    /// TCP connection timeout in milliseconds.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Per-command execution timeout in milliseconds.
    #[serde(default = "default_command_timeout_ms")]
    pub command_timeout_ms: u64,
    /// Consecutive failures before the circuit breaker trips.
    #[serde(default = "default_circuit_breaker_threshold")]
    pub circuit_breaker_threshold: u32,
    /// Seconds the circuit stays open before entering half-open probe.
    #[serde(default = "default_circuit_breaker_reset_secs")]
    pub circuit_breaker_reset_secs: u64,
    /// When the circuit is open, transparently fall back to the local moka store.
    #[serde(default = "default_true")]
    pub fallback_to_memory: bool,
}

fn default_valkey_seeds() -> Vec<String> {
    vec!["127.0.0.1:6379".to_string()]
}
const fn default_pool_size() -> usize {
    4
}
const fn default_connect_timeout_ms() -> u64 {
    2_000
}
const fn default_command_timeout_ms() -> u64 {
    500
}
const fn default_circuit_breaker_threshold() -> u32 {
    5
}
const fn default_circuit_breaker_reset_secs() -> u64 {
    30
}

impl Default for ValkeyClientConfig {
    fn default() -> Self {
        Self {
            seeds: default_valkey_seeds(),
            password: String::new(),
            db: 0,
            tls: false,
            tls_ca_cert: None,
            pool_size: default_pool_size(),
            connect_timeout_ms: default_connect_timeout_ms(),
            command_timeout_ms: default_command_timeout_ms(),
            circuit_breaker_threshold: default_circuit_breaker_threshold(),
            circuit_breaker_reset_secs: default_circuit_breaker_reset_secs(),
            fallback_to_memory: true,
        }
    }
}

/// Response caching configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable response caching
    pub enabled: bool,
    /// Maximum cache size in megabytes (moka cap or `maxmemory` for embedded Valkey)
    pub max_size_mb: u64,
    /// Default TTL in seconds (used when Cache-Control is absent)
    pub default_ttl_secs: u64,
    /// Maximum TTL in seconds (caps upstream Cache-Control max-age)
    pub max_ttl_secs: u64,
    /// FR-009 Phase 3: path to YAML file with per-route TTL rules.
    /// `None` (default) → no rules; only tier-default TTLs apply.
    /// Hot-reloaded at runtime; missing file is non-fatal at boot.
    #[serde(default)]
    pub rules_path: Option<std::path::PathBuf>,
    /// Cache storage backend. Default `"memory"` uses the moka LRU.
    #[serde(default)]
    pub backend: CacheBackendKind,
    /// Embedded Valkey process config (only used when `backend = "embedded"`).
    #[serde(default)]
    pub embedded: EmbeddedValkeyConfig,
    /// External Valkey/Redis client config (`backend = "standalone"` or `"cluster"`).
    #[serde(default)]
    pub valkey: ValkeyClientConfig,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size_mb: 256,
            default_ttl_secs: 60,
            max_ttl_secs: 3600,
            rules_path: None,
            backend: CacheBackendKind::Memory,
            embedded: EmbeddedValkeyConfig::default(),
            valkey: ValkeyClientConfig::default(),
        }
    }
}

/// HTTP/3 (QUIC) listener configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http3Config {
    /// Enable HTTP/3 listener
    pub enabled: bool,
    /// UDP listen address for QUIC
    pub listen_addr: String,
    /// Path to TLS certificate PEM (required when enabled)
    pub cert_pem: Option<String>,
    /// Path to TLS key PEM (required when enabled)
    pub key_pem: Option<String>,
    /// Verify upstream TLS certificates.
    /// When `true` (default), invalid/self-signed upstream certs are rejected.
    /// Set to `false` only for development/testing with self-signed upstreams.
    #[serde(default = "default_true")]
    pub upstream_tls_verify: bool,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "0.0.0.0:443".to_string(),
            cert_pem: None,
            key_pem: None,
            upstream_tls_verify: true,
        }
    }
}

/// Security hardening configuration for the management API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// IP allowlist for admin API (empty = allow all)
    #[serde(default)]
    pub admin_ip_allowlist: Vec<String>,
    /// Maximum request body size in bytes (default 10 MB)
    pub max_request_body_bytes: u64,
    /// API rate limit (requests per second per IP, 0 = disabled)
    pub api_rate_limit_rps: u32,
    /// Allowed CORS origins for admin API (empty = all)
    #[serde(default)]
    pub cors_origins: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            admin_ip_allowlist: Vec::new(),
            max_request_body_bytes: 10 * 1024 * 1024, // 10 MB
            api_rate_limit_rps: 0,
            cors_origins: Vec::new(),
        }
    }
}

/// Automatic ip2region xdb update configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpAutoUpdateConfig {
    /// Enable periodic automatic xdb updates.  Default: `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Update check interval.  Supports suffixes: `d` (days), `h` (hours),
    /// `m` (minutes), `s` (seconds).  Default: `"7d"`.
    #[serde(default = "default_geoip_update_interval")]
    pub interval: String,
    /// Base URL for downloading xdb files.
    /// Default: GitHub raw content URL for ip2region master.
    #[serde(default = "default_geoip_source_url")]
    pub source_url: String,
}

fn default_geoip_update_interval() -> String {
    "7d".to_string()
}
fn default_geoip_source_url() -> String {
    "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data".to_string()
}

impl Default for GeoIpAutoUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: default_geoip_update_interval(),
            source_url: default_geoip_source_url(),
        }
    }
}

/// `GeoIP` lookup configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpConfig {
    /// Enable `GeoIP` lookups on every request.
    pub enabled: bool,
    /// Path to the ip2region IPv4 xdb file (default: `data/ip2region_v4.xdb`).
    #[serde(default = "default_ipv4_xdb")]
    pub ipv4_xdb_path: String,
    /// Path to the ip2region IPv6 xdb file (default: `data/ip2region_v6.xdb`).
    #[serde(default = "default_ipv6_xdb")]
    pub ipv6_xdb_path: String,
    /// Cache policy: `full_memory` (fastest, ~20MB), `vector_index` (~2MB), `no_cache` (1-2MB).
    #[serde(default = "default_geoip_cache_policy")]
    pub cache_policy: String,
    /// Automatic xdb update settings.
    #[serde(default)]
    pub auto_update: GeoIpAutoUpdateConfig,
}

fn default_ipv4_xdb() -> String {
    "data/ip2region_v4.xdb".to_string()
}
fn default_ipv6_xdb() -> String {
    "data/ip2region_v6.xdb".to_string()
}
fn default_geoip_cache_policy() -> String {
    "full_memory".to_string()
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ipv4_xdb_path: default_ipv4_xdb(),
            ipv6_xdb_path: default_ipv6_xdb(),
            cache_policy: default_geoip_cache_policy(),
            auto_update: GeoIpAutoUpdateConfig::default(),
        }
    }
}

/// Community threat intelligence sharing configuration.
///
/// Mirrors `waf_engine::community::config::CommunityConfig` so the TOML
/// config can be loaded without pulling in the full engine crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityConfig {
    /// Enable community threat intelligence sharing.
    #[serde(default)]
    pub enabled: bool,
    /// Community server base URL.
    #[serde(default = "default_community_server_url")]
    pub server_url: String,
    /// API key obtained during machine enrollment.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Machine identifier obtained during enrollment.
    #[serde(default)]
    pub machine_id: Option<String>,
    /// Ed25519 public key (hex-encoded 32 bytes) for blocklist signature verification.
    /// When set, the WAF verifies signed snapshots from `/blocklist/full`.
    /// When absent, falls back to the unverified `/blocklist/decoded` endpoint.
    #[serde(default)]
    pub public_key: Option<String>,
    /// Maximum number of signals to batch before flushing.
    #[serde(default = "default_community_batch_size")]
    pub batch_size: usize,
    /// Flush interval in seconds.
    #[serde(default = "default_community_flush_interval")]
    pub flush_interval_secs: u64,
    /// Blocklist sync interval in seconds.
    #[serde(default = "default_community_sync_interval")]
    pub sync_interval_secs: u64,
}

fn default_community_server_url() -> String {
    "https://community.openprx.dev".to_string()
}
const fn default_community_batch_size() -> usize {
    50
}
const fn default_community_flush_interval() -> u64 {
    30
}
const fn default_community_sync_interval() -> u64 {
    300
}

impl Default for CommunityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: default_community_server_url(),
            api_key: None,
            machine_id: None,
            public_key: None,
            batch_size: default_community_batch_size(),
            flush_interval_secs: default_community_flush_interval(),
            sync_interval_secs: default_community_sync_interval(),
        }
    }
}

/// `SQLi` scanner configuration for header scanning and size limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliScanConfig {
    /// Enable scanning HTTP headers for `SQLi` patterns.
    #[serde(default = "default_true")]
    pub scan_headers: bool,
    /// Headers to skip (lowercase). Ignored if `header_allowlist` is non-empty.
    #[serde(default = "default_header_denylist")]
    pub header_denylist: Vec<String>,
    /// If non-empty, ONLY these headers are scanned (overrides denylist).
    #[serde(default)]
    pub header_allowlist: Vec<String>,
    /// Max bytes to scan per header value.
    #[serde(default = "default_header_scan_cap")]
    pub header_scan_cap: usize,
    /// Max bytes to parse for JSON body.
    #[serde(default = "default_json_parse_cap")]
    pub json_parse_cap: usize,
}

fn default_header_denylist() -> Vec<String> {
    vec![
        "content-length".to_string(),
        "content-type".to_string(),
        "host".to_string(),
        "connection".to_string(),
        "accept-encoding".to_string(),
        "cookie".to_string(),
    ]
}

const fn default_header_scan_cap() -> usize {
    4096
}

const fn default_json_parse_cap() -> usize {
    256 * 1024
}

impl Default for SqliScanConfig {
    fn default() -> Self {
        Self {
            scan_headers: true,
            header_denylist: default_header_denylist(),
            header_allowlist: Vec::new(),
            header_scan_cap: default_header_scan_cap(),
            json_parse_cap: default_json_parse_cap(),
        }
    }
}

// ── VictoriaLogs sidecar configuration ────────────────────────────────────────

/// `VictoriaLogs` managed sidecar configuration.
///
/// `prx-waf` runs `VictoriaLogs` as an in-process child when `enabled = true`.
/// The binary is installed on demand (see `auto_install`) and the listener is
/// constrained to loopback because `VictoriaLogs` itself has no built-in
/// authentication; all external access must go through the WAF management API.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VictoriaLogsConfig {
    /// Master switch — when `false`, the entire pipeline is a no-op.
    #[serde(default)]
    pub enabled: bool,
    /// Filesystem path to the `victoria-logs` binary.
    #[serde(default = "default_vlogs_binary_path")]
    pub binary_path: String,
    /// Directory where `VictoriaLogs` stores its data partitions.
    #[serde(default = "default_vlogs_storage_path")]
    pub storage_data_path: String,
    /// HTTP listen address. **Must be loopback** — validated at load time.
    #[serde(default = "default_vlogs_listen_addr")]
    pub listen_addr: String,
    /// Time-based retention period (e.g. `"30d"`, `"7d"`).
    #[serde(default = "default_vlogs_retention")]
    pub retention_period: String,
    /// Hard size cap on data directory; oldest partitions deleted on overflow.
    #[serde(default = "default_vlogs_max_disk")]
    pub max_disk_space_bytes: String,
    /// Safety stop — `VictoriaLogs` rejects writes when free disk drops below this.
    #[serde(default = "default_vlogs_min_free_disk")]
    pub min_free_disk_bytes: String,
    /// Release tag to download via `installer` (e.g. `"v1.50.0"`).
    #[serde(default = "default_vlogs_version")]
    pub version: String,
    /// Auto-download the binary when missing. When `false`, `enabled = true`
    /// requires the operator to provision the binary out-of-band.
    #[serde(default = "default_true")]
    pub auto_install: bool,
    /// Batch buffer flush threshold (entries).
    #[serde(default = "default_vlogs_batch_size")]
    pub batch_size: usize,
    /// Batch buffer max age before flush (milliseconds).
    #[serde(default = "default_vlogs_flush_interval_ms")]
    pub flush_interval_ms: u64,
    /// Pending-entries channel capacity. Older entries are dropped when full.
    #[serde(default = "default_vlogs_channel_capacity")]
    pub channel_capacity: usize,
}

fn default_vlogs_binary_path() -> String {
    "/var/lib/prx-waf/victoria-logs/victoria-logs".to_string()
}
fn default_vlogs_storage_path() -> String {
    "/var/lib/prx-waf/victoria-logs/data".to_string()
}
fn default_vlogs_listen_addr() -> String {
    "127.0.0.1:9428".to_string()
}
fn default_vlogs_retention() -> String {
    "30d".to_string()
}
fn default_vlogs_max_disk() -> String {
    "100GiB".to_string()
}
fn default_vlogs_min_free_disk() -> String {
    "1GiB".to_string()
}
fn default_vlogs_version() -> String {
    "v1.50.0".to_string()
}
const fn default_vlogs_batch_size() -> usize {
    100
}
const fn default_vlogs_flush_interval_ms() -> u64 {
    1000
}
const fn default_vlogs_channel_capacity() -> usize {
    10_000
}

impl Default for VictoriaLogsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            binary_path: default_vlogs_binary_path(),
            storage_data_path: default_vlogs_storage_path(),
            listen_addr: default_vlogs_listen_addr(),
            retention_period: default_vlogs_retention(),
            max_disk_space_bytes: default_vlogs_max_disk(),
            min_free_disk_bytes: default_vlogs_min_free_disk(),
            version: default_vlogs_version(),
            auto_install: true,
            batch_size: default_vlogs_batch_size(),
            flush_interval_ms: default_vlogs_flush_interval_ms(),
            channel_capacity: default_vlogs_channel_capacity(),
        }
    }
}

impl VictoriaLogsConfig {
    /// Validate the config. Only enforced when `enabled = true` so a default
    /// (disabled) `AppConfig` remains usable without any of the fields filled.
    ///
    /// Listener must be loopback because `VictoriaLogs` has no built-in auth —
    /// exposing it externally would let any reachable client read or delete
    /// audit logs without going through the WAF JWT/role checks.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.storage_data_path.trim().is_empty() {
            anyhow::bail!("victoria_logs.storage_data_path must not be empty");
        }
        if self.binary_path.trim().is_empty() {
            anyhow::bail!("victoria_logs.binary_path must not be empty");
        }
        let addr: std::net::SocketAddr = self.listen_addr.parse().map_err(|e| {
            anyhow::anyhow!(
                "victoria_logs.listen_addr is not a valid socket address ('{}'): {e}",
                self.listen_addr
            )
        })?;
        if !addr.ip().is_loopback() {
            anyhow::bail!(
                "victoria_logs.listen_addr must bind to a loopback address \
                 (got '{}'). VictoriaLogs has no built-in authentication; \
                 external access must go through the WAF /api/v1/logs proxy.",
                self.listen_addr
            );
        }
        Ok(())
    }

    /// JSON-Lines ingest URL used by the `tracing` layer and audit sender.
    pub fn ingest_url(&self) -> String {
        format!("http://{}/insert/jsonline", self.listen_addr)
    }

    /// `VictoriaLogs` HTTP base URL (no path component).
    ///
    /// The `waf-api` proxy appends per-endpoint paths (`/select/logsql/query`,
    /// `/select/logsql/stats_query`, `/select/logsql/field_values`, `/metrics`)
    /// onto this — so this function MUST return only the host root.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.listen_addr)
    }
}

/// Load configuration from a TOML file
pub fn load_config(path: &str) -> anyhow::Result<AppConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: AppConfig = toml::from_str(&content)?;
    config.victoria_logs.validate()?;
    Ok(config)
}

// --- Cluster Configuration ---

/// Node role in the cluster
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    Main,
    Worker,
    Candidate,
}

/// Cluster TLS/certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterCryptoConfig {
    /// Path to CA certificate PEM file
    #[serde(default = "default_ca_cert_path")]
    pub ca_cert: String,
    /// Path to CA private key PEM file.
    /// Required on the main node only; leave empty on worker nodes.
    /// Used when `auto_generate = false` to load a pre-generated CA key.
    #[serde(default)]
    pub ca_key: String,
    /// Path to node certificate PEM file
    #[serde(default = "default_node_cert_path")]
    pub node_cert: String,
    /// Path to node private key PEM file
    #[serde(default = "default_node_key_path")]
    pub node_key: String,
    /// Auto-generate CA and node certs on first startup
    #[serde(default = "default_true")]
    pub auto_generate: bool,
    /// CA certificate validity in days (default 10 years)
    #[serde(default = "default_ca_validity_days")]
    pub ca_validity_days: u32,
    /// Node certificate validity in days (default 1 year)
    #[serde(default = "default_node_validity_days")]
    pub node_validity_days: u32,
    /// Renew node cert this many days before expiry
    #[serde(default = "default_renewal_before_days")]
    pub renewal_before_days: u32,
    /// Passphrase used to encrypt the CA private key for replication to workers.
    /// If empty, CA key replication is disabled.
    #[serde(default)]
    pub ca_passphrase: String,
}

fn default_ca_cert_path() -> String {
    "/app/certs/cluster-ca.pem".to_string()
}
fn default_node_cert_path() -> String {
    "/app/certs/node.pem".to_string()
}
fn default_node_key_path() -> String {
    "/app/certs/node.key".to_string()
}
const fn default_ca_validity_days() -> u32 {
    3650
}
const fn default_node_validity_days() -> u32 {
    365
}
const fn default_renewal_before_days() -> u32 {
    7
}

impl Default for ClusterCryptoConfig {
    fn default() -> Self {
        Self {
            ca_cert: default_ca_cert_path(),
            ca_key: String::new(),
            node_cert: default_node_cert_path(),
            node_key: default_node_key_path(),
            auto_generate: true,
            ca_validity_days: default_ca_validity_days(),
            node_validity_days: default_node_validity_days(),
            renewal_before_days: default_renewal_before_days(),
            ca_passphrase: String::new(),
        }
    }
}

/// Cluster sync intervals and batch sizes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSyncConfig {
    /// Periodic rule version check interval in seconds
    #[serde(default = "default_rules_interval")]
    pub rules_interval_secs: u64,
    /// Config sync interval in seconds
    #[serde(default = "default_config_interval")]
    pub config_interval_secs: u64,
    /// Flush event batch after this many events
    #[serde(default = "default_events_batch_size")]
    pub events_batch_size: usize,
    /// Flush event batch after this many seconds even if not full
    #[serde(default = "default_events_flush_interval")]
    pub events_flush_interval_secs: u64,
    /// Stats push interval in seconds
    #[serde(default = "default_stats_interval")]
    pub stats_interval_secs: u64,
    /// Maximum events in the worker queue before dropping oldest
    #[serde(default = "default_events_queue_size")]
    pub events_queue_size: usize,
}

const fn default_rules_interval() -> u64 {
    10
}
const fn default_config_interval() -> u64 {
    30
}
const fn default_events_batch_size() -> usize {
    100
}
const fn default_events_flush_interval() -> u64 {
    5
}
const fn default_stats_interval() -> u64 {
    10
}
const fn default_events_queue_size() -> usize {
    10_000
}

impl Default for ClusterSyncConfig {
    fn default() -> Self {
        Self {
            rules_interval_secs: default_rules_interval(),
            config_interval_secs: default_config_interval(),
            events_batch_size: default_events_batch_size(),
            events_flush_interval_secs: default_events_flush_interval(),
            stats_interval_secs: default_stats_interval(),
            events_queue_size: default_events_queue_size(),
        }
    }
}

/// Raft-lite election configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterElectionConfig {
    /// Minimum election timeout in milliseconds
    #[serde(default = "default_timeout_min_ms")]
    pub timeout_min_ms: u64,
    /// Maximum election timeout in milliseconds
    #[serde(default = "default_timeout_max_ms")]
    pub timeout_max_ms: u64,
    /// Main→workers heartbeat interval in milliseconds
    #[serde(default = "default_heartbeat_interval_ms")]
    pub heartbeat_interval_ms: u64,
    /// Phi threshold to suspect a node is failing
    #[serde(default = "default_phi_suspect")]
    pub phi_suspect: f64,
    /// Phi threshold to declare a node dead and trigger election
    #[serde(default = "default_phi_dead")]
    pub phi_dead: f64,
}

const fn default_timeout_min_ms() -> u64 {
    150
}
const fn default_timeout_max_ms() -> u64 {
    300
}
const fn default_heartbeat_interval_ms() -> u64 {
    50
}
const fn default_phi_suspect() -> f64 {
    8.0
}
const fn default_phi_dead() -> f64 {
    12.0
}

impl Default for ClusterElectionConfig {
    fn default() -> Self {
        Self {
            timeout_min_ms: default_timeout_min_ms(),
            timeout_max_ms: default_timeout_max_ms(),
            heartbeat_interval_ms: default_heartbeat_interval_ms(),
            phi_suspect: default_phi_suspect(),
            phi_dead: default_phi_dead(),
        }
    }
}

/// Node health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterHealthConfig {
    /// Health check interval in seconds
    #[serde(default = "default_health_check_interval")]
    pub check_interval_secs: u64,
    /// Number of missed heartbeats before declaring node unhealthy
    #[serde(default = "default_max_missed_heartbeats")]
    pub max_missed_heartbeats: u32,
}

const fn default_health_check_interval() -> u64 {
    5
}
const fn default_max_missed_heartbeats() -> u32 {
    3
}

impl Default for ClusterHealthConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: default_health_check_interval(),
            max_missed_heartbeats: default_max_missed_heartbeats(),
        }
    }
}

/// Full cluster configuration — presence of this section enables clustering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Enable clustering. Must be true for any cluster behaviour.
    #[serde(default)]
    pub enabled: bool,
    /// Unique node identifier. Auto-generated from hostname+random suffix if empty.
    #[serde(default)]
    pub node_id: String,
    /// Role assignment: "auto" | "main" | "worker"
    #[serde(default = "default_cluster_role")]
    pub role: String,
    /// QUIC listen address for cluster communication
    #[serde(default = "default_cluster_addr")]
    pub listen_addr: String,
    /// Static seed nodes. At least one reachable seed required to join an existing cluster.
    #[serde(default)]
    pub seeds: Vec<String>,
    /// TLS/certificate settings
    #[serde(default)]
    pub crypto: ClusterCryptoConfig,
    /// Sync intervals and batch sizes
    #[serde(default)]
    pub sync: ClusterSyncConfig,
    /// Election protocol settings
    #[serde(default)]
    pub election: ClusterElectionConfig,
    /// Health check settings
    #[serde(default)]
    pub health: ClusterHealthConfig,
}

fn default_cluster_role() -> String {
    "auto".to_string()
}
fn default_cluster_addr() -> String {
    "0.0.0.0:16851".to_string()
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: String::new(),
            role: default_cluster_role(),
            listen_addr: default_cluster_addr(),
            seeds: Vec::new(),
            crypto: ClusterCryptoConfig::default(),
            sync: ClusterSyncConfig::default(),
            election: ClusterElectionConfig::default(),
            health: ClusterHealthConfig::default(),
        }
    }
}
