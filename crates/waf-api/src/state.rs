use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use gateway::{HostRouter, ResponseCache, TunnelRegistry};
use waf_engine::{CommunityReporter, CrowdSecClient, DecisionCache, PluginManager, WafEngine};
use waf_storage::Database;

use crate::notifications::NotifRateLimiter;

/// Shared application state for the API server.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub engine: Arc<WafEngine>,
    pub router: Arc<HostRouter>,
    /// Total request counter (incremented by the proxy layer)
    pub request_counter: Arc<AtomicU64>,
    /// Blocked request counter
    pub blocked_counter: Arc<AtomicU64>,
    /// Active WebSocket connection count (capped at 50)
    pub ws_connections: Arc<AtomicU32>,
    /// JWT signing/verifying secret (from env `JWT_SECRET`)
    pub jwt_secret: String,
    /// In-process rate limiter for notifications
    pub notif_rate_limiter: NotifRateLimiter,
    // ── Phase 5 ──────────────────────────────────────────────────────────────
    /// Response cache (moka-backed LRU)
    pub cache: Arc<ResponseCache>,
    /// WASM plugin manager
    pub plugin_manager: Arc<PluginManager>,
    /// Reverse tunnel registry
    pub tunnel_registry: Arc<TunnelRegistry>,
    // ── Phase 6: CrowdSec ────────────────────────────────────────────────────
    /// In-memory decision cache (None if `CrowdSec` not enabled)
    pub crowdsec_cache: Option<Arc<DecisionCache>>,
    /// LAPI client for delete/test operations (None if `CrowdSec` not enabled)
    pub crowdsec_client: Option<Arc<CrowdSecClient>>,
    /// LAPI base URL (for display in status endpoint)
    pub crowdsec_lapi_url: Option<String>,
    // ── Community threat intelligence ──────────────────────────────────────
    /// Community signal reporter (None if community sharing not enabled)
    pub community_reporter: Option<Arc<CommunityReporter>>,
    // ── Phase 7: Cluster ─────────────────────────────────────────────────────
    /// Shared cluster node state (None when running in standalone mode)
    pub cluster_state: Option<Arc<waf_cluster::NodeState>>,
    /// Allowed CORS origins for admin API (empty = allow all — insecure default)
    pub cors_origins: Vec<String>,
    /// Security config for IP allowlist and rate limiting
    pub security_config: waf_common::config::SecurityConfig,
    /// In-process API rate limiter (None if rate limiting disabled)
    pub rate_limiter: Option<Arc<crate::security::ApiRateLimiter>>,
    /// Dedicated rate limiter for login endpoint — stricter than general API
    /// to mitigate brute-force credential attacks (None if disabled)
    pub login_rate_limiter: Option<Arc<crate::security::ApiRateLimiter>>,
    /// Resolved absolute path to `waf-panel.toml` when `[panel]` is configured.
    pub panel_config_path: Option<PathBuf>,
    /// Path to the main WAF config file the server was started with (e.g. `configs/default.toml`).
    pub main_config_file: Option<String>,
    /// `VictoriaLogs` HTTP base URL (e.g. `http://127.0.0.1:9428`, no path
    /// component). `None` when `[victoria_logs] enabled = false` — log proxy
    /// endpoints then return 503.
    pub victoria_logs_base_url: Option<String>,
    /// Memoised response for `GET /api/v1/logs/streams`.  60-second TTL —
    /// distinct-value enumeration is expensive on `VictoriaLogs` and the FE
    /// only needs it to populate filter dropdowns.
    pub logs_streams_cache: Arc<crate::logs::StreamsCache>,
}

impl AppState {
    /// Create new application state.
    ///
    /// Returns an error if the `JWT_SECRET` environment variable is not set or empty.
    /// In production this ensures the operator explicitly configures a strong secret.
    pub fn new(
        db: Arc<Database>,
        engine: Arc<WafEngine>,
        router: Arc<HostRouter>,
        cache: Arc<ResponseCache>,
    ) -> anyhow::Result<Self> {
        let jwt_secret = std::env::var("JWT_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "JWT_SECRET environment variable is not set. \
                 Set a strong random secret (>= 32 chars) before starting the server."
                )
            })?;

        Ok(Self {
            db,
            engine,
            router,
            request_counter: Arc::new(AtomicU64::new(0)),
            blocked_counter: Arc::new(AtomicU64::new(0)),
            ws_connections: Arc::new(AtomicU32::new(0)),
            jwt_secret,
            notif_rate_limiter: crate::notifications::new_rate_limiter(),
            cache,
            plugin_manager: Arc::new(PluginManager::new()),
            tunnel_registry: TunnelRegistry::new(),
            crowdsec_cache: None,
            crowdsec_client: None,
            crowdsec_lapi_url: None,
            community_reporter: None,
            cluster_state: None,
            cors_origins: Vec::new(),
            security_config: waf_common::config::SecurityConfig::default(),
            rate_limiter: None,
            login_rate_limiter: None,
            panel_config_path: None,
            main_config_file: None,
            victoria_logs_base_url: None,
            logs_streams_cache: crate::logs::new_streams_cache(),
        })
    }

    pub fn increment_requests(&self) {
        self.request_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_blocked(&self) {
        self.blocked_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_requests(&self) -> u64 {
        self.request_counter.load(Ordering::Relaxed)
    }

    pub fn total_blocked(&self) -> u64 {
        self.blocked_counter.load(Ordering::Relaxed)
    }
}
