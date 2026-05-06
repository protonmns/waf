use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use tracing::{debug, info, warn};
use uuid::Uuid;

use waf_common::{RequestCtx, WafAction, WafDecision};
use waf_storage::{
    Database,
    models::{AttackLog, CreateSecurityEvent},
};

use crate::block_page::render_block_page;
use crate::checker::{RuleStore, check_ip_blacklist, check_ip_whitelist, check_url_blacklist, check_url_whitelist};
use waf_common::config::SqliScanConfig;

use crate::checks::ddos::action::{BanAction, CombinedAction};
use crate::checks::ddos::detector::PerIpDetector;
use crate::checks::ddos::reload::DEFAULT_DEBOUNCE_MS as DDOS_DEBOUNCE_MS;
use crate::checks::ddos::store::MemoryCounterStore as DdosMemoryStore;
use crate::checks::ddos::{
    DdosCheck, DdosConfig, DdosFileConfig, DdosMetrics, DdosReloader, DynamicBanTable, OverloadGuard,
};
use crate::checks::rate_limit::reload::{DEFAULT_DEBOUNCE_MS as RL_DEBOUNCE_MS, RateLimitReloader};
use crate::checks::rate_limit::store::MemoryStore as RlMemoryStore;
use crate::checks::rate_limit::{RateLimitFileConfig, store::RateLimitStore};
use crate::checks::tx_velocity::{
    TxStore, TxVelocityCheck, TxVelocityConfig, TxVelocityFileConfig, TxVelocityReloader,
};
use crate::checks::{
    AntiHotlinkCheck, BotCheck, Check, DirTraversalCheck, GeoCheck, OWASPCheck, RateLimitCheck, RateLimitConfig,
    RceCheck, ScannerCheck, SensitiveCheck, SqlInjectionCheck, XssCheck,
};
use crate::community::{CommunityChecker, CommunityReporter, RequestInfo};
use crate::crowdsec::{AppSecClient, AppSecResult, CrowdSecChecker, appsec_to_detection};
use crate::geoip::GeoIpService;
use crate::logging::{AuditEvent, AuditEventType, AuditSender};
use crate::rules::custom_file_loader::CustomRuleFileWatcher;
use crate::rules::engine::{CustomRulesEngine, from_db_rule};

/// WAF engine configuration
#[derive(Debug, Clone, Default)]
pub struct WafEngineConfig {
    /// Whether to log allowed requests that matched whitelist rules
    pub log_whitelist_hits: bool,
}

/// Main WAF engine — runs all detection phases.
///
/// Phase 1-4  : IP / URL whitelist + blacklist (fast-path)
/// Phase 16   : `CrowdSec` bouncer (cache lookup — runs early for efficiency)
/// Phase 5-11 : Attack detection (CC, scanner, bot, `SQLi`, XSS, RCE, traversal)
/// Phase 16b  : `CrowdSec` `AppSec` (async HTTP check — runs after local detectors)
/// Phase 12   : Custom rules engine (Rhai scripting)
/// Phase 13   : OWASP CRS subset
/// Phase 14   : Sensitive data detection
/// Phase 15   : Anti-hotlinking
pub struct WafEngine {
    pub store: Arc<RuleStore>,
    pub custom_rules: Arc<CustomRulesEngine>,
    pub sensitive: Arc<SensitiveCheck>,
    pub hotlink: Arc<AntiHotlinkCheck>,
    db: Arc<Database>,
    #[allow(dead_code)]
    config: WafEngineConfig,
    /// Dynamic checker pipeline (Phase 5-11 detectors).
    checkers: Vec<Box<dyn Check>>,
    owasp: Arc<OWASPCheck>,
    /// GeoIP-based access control check (Phase 17).
    geo_check: Arc<GeoCheck>,
    /// SQL injection checker (stored separately for config hot-reload)
    sqli_check: Arc<SqlInjectionCheck>,
    // ── Phase 6: `CrowdSec` ───────────────────────────────────────────────────
    /// Bouncer checker (set once after engine construction via `set_crowdsec`)
    crowdsec_checker: OnceLock<Arc<CrowdSecChecker>>,
    /// `AppSec` client (set once after engine construction via `set_crowdsec`)
    appsec_client: OnceLock<Arc<AppSecClient>>,
    // ── Community ──────────────────────────────────────────────────────────
    /// Community blocklist checker (set once after engine construction via `set_community`)
    community_checker: OnceLock<Arc<CommunityChecker>>,
    /// Community signal reporter for pushing detections (set once via `set_community_reporter`)
    community_reporter: OnceLock<Arc<CommunityReporter>>,
    // ── `GeoIP` ────────────────────────────────────────────────────────────────
    /// `GeoIP` lookup service (set once after engine construction via `set_geoip`)
    geoip: OnceLock<Arc<GeoIpService>>,
    // ── FR-003 file-based custom rules ────────────────────────────────────────
    /// Root rules directory; `<rules_dir>/custom/*.yaml` is scanned during
    /// `reload_rules`. Set once via `set_rules_dir`; falls back to `./rules`.
    rules_dir: OnceLock<PathBuf>,
    /// File watcher for `<rules_dir>/custom/*.yaml` (FR-003 hot-reload).
    /// Set lazily via `start_file_watcher`; held to keep the OS watch alive.
    file_watcher: OnceLock<CustomRuleFileWatcher>,
    // ── FR-004 rate-limit (phase-07) ─────────────────────────────────────────
    /// Hot-reloadable rate-limit config snapshot. Shared with the
    /// `RateLimitCheck` registered in `checkers`.
    rate_limit_cfg: Arc<ArcSwap<RateLimitConfig>>,
    /// File watcher for `configs/rate-limit.yaml`. Lazy via
    /// `start_rate_limit_watcher`; held to keep the OS watch alive.
    rate_limit_reloader: OnceLock<RateLimitReloader>,
    // ── FR-012 tx-velocity (phase-03) ────────────────────────────────────────
    /// Hot-reloadable tx-velocity config snapshot. Shared with the
    /// `TxVelocityCheck` and `TxStore` registered in `checkers`.
    tx_velocity_cfg: Arc<ArcSwap<TxVelocityConfig>>,
    /// In-memory transaction store for velocity tracking.
    /// Kept alive for `TxVelocityCheck`; not accessed directly after construction.
    #[allow(dead_code)]
    tx_velocity_store: Arc<TxStore>,
    /// File watcher for `configs/tx-velocity.yaml`. Lazy via
    /// `start_tx_velocity_watcher`; held to keep the OS watch alive.
    tx_velocity_reloader: OnceLock<TxVelocityReloader>,
    // ── FR-005 ddos-protection (phase-07) ────────────────────────────────────
    /// Hot-reloadable `DDoS` config snapshot.
    ddos_cfg: Arc<ArcSwap<DdosConfig>>,
    /// `DdosCheck` instance for pipeline integration.
    ddos_check: Arc<DdosCheck>,
    /// File watcher for `configs/ddos.yaml`. Lazy via
    /// `start_ddos_watcher`; held to keep the OS watch alive.
    ddos_reloader: OnceLock<DdosReloader>,
    // ── Phase 02: VictoriaLogs audit sender ───────────────────────────────────
    /// Structured audit-event sink. `None` until [`set_audit_sender`] is
    /// called by the binary boot path.  When set, every non-Allow decision
    /// from `inspect()` is mirrored into `VictoriaLogs` as an audit record.
    audit_sender: OnceLock<Arc<AuditSender>>,
}

impl WafEngine {
    pub fn new(db: Arc<Database>, config: WafEngineConfig) -> Self {
        Self::with_sqli_config(db, config, SqliScanConfig::default())
    }

    pub fn with_sqli_config(db: Arc<Database>, config: WafEngineConfig, sqli_cfg: SqliScanConfig) -> Self {
        let store = Arc::new(RuleStore::new(Arc::clone(&db)));
        let custom_rules = Arc::new(CustomRulesEngine::new());
        let sensitive = Arc::new(SensitiveCheck::new());
        let hotlink = Arc::new(AntiHotlinkCheck::new());
        let owasp = Arc::new(OWASPCheck::new());
        let geo_check = Arc::new(GeoCheck::new());
        let sqli_check = Arc::new(SqlInjectionCheck::with_config(sqli_cfg));

        // Build the Phase 5-11 checker pipeline (SQLi handled separately for hot-reload).
        // FR-004 RateLimitCheck runs first to shed flood traffic before expensive
        // pattern checks. Inert until `start_rate_limit_watcher` loads tier config.
        let rl_store: Arc<dyn RateLimitStore> = Arc::new(RlMemoryStore::new());
        let rate_limit_cfg = Arc::new(ArcSwap::from(Arc::new(RateLimitConfig::default())));

        // FR-012 TxVelocityCheck: signal-only, records events and emits risk signals.
        // Runs after rate-limit (shed flood traffic first), before pattern checks.
        // Inert until `start_tx_velocity_watcher` loads config.
        let tx_velocity_cfg = Arc::new(ArcSwap::from(Arc::new(TxVelocityConfig::default())));
        let tx_velocity_store = Arc::new(TxStore::new(Arc::clone(&tx_velocity_cfg)));

        // FR-005 DdosCheck: burst detection and banning.
        // Runs BEFORE rate-limit in the pipeline (separate from checkers vec).
        // Inert until `start_ddos_watcher` loads config.
        let ddos_cfg = Arc::new(ArcSwap::from(Arc::new(DdosConfig::default())));
        // Reuse rate-limit store for per-IP detection (same token bucket algorithm)
        let ddos_rl_store: Arc<dyn RateLimitStore> = Arc::new(RlMemoryStore::new());
        // Separate counter store for offense tracking (ban escalation)
        let ddos_counter_store: Arc<dyn crate::checks::ddos::store::CounterStore> =
            Arc::new(DdosMemoryStore::new(100_000, 60));
        let ddos_ban_table = Arc::new(DynamicBanTable::new());
        let ddos_guard = Arc::new(OverloadGuard::default());
        let ddos_metrics = Arc::new(DdosMetrics::new());

        // Build detectors (cheap-first order)
        let ddos_detectors: Vec<Box<dyn crate::checks::ddos::detector::Detector>> =
            vec![Box::new(PerIpDetector::new(ddos_rl_store))];

        // Build action executors (ban only — risk bump requires FR-010 aggregator)
        let ddos_ban_action = BanAction::with_defaults(Arc::clone(&ddos_ban_table), ddos_counter_store);
        let ddos_action = Arc::new(CombinedAction::new(vec![Box::new(ddos_ban_action)]));

        let ddos_check = Arc::new(DdosCheck::new(
            Arc::clone(&ddos_cfg),
            ddos_detectors,
            ddos_action,
            Arc::clone(&ddos_guard),
            Arc::clone(&ddos_ban_table),
            Arc::clone(&ddos_metrics),
        ));

        let checkers: Vec<Box<dyn Check>> = vec![
            Box::new(RateLimitCheck::new(rl_store, Arc::clone(&rate_limit_cfg))),
            Box::new(TxVelocityCheck::new(
                Arc::clone(&tx_velocity_cfg),
                Arc::clone(&tx_velocity_store),
            )),
            Box::new(ScannerCheck::new()),
            Box::new(BotCheck::new()),
            Box::new(XssCheck::new()),
            Box::new(RceCheck::new()),
            Box::new(DirTraversalCheck::new()),
        ];

        Self {
            store,
            custom_rules,
            sensitive,
            hotlink,
            db,
            config,
            checkers,
            owasp,
            geo_check,
            sqli_check,
            crowdsec_checker: OnceLock::new(),
            appsec_client: OnceLock::new(),
            community_checker: OnceLock::new(),
            community_reporter: OnceLock::new(),
            geoip: OnceLock::new(),
            rules_dir: OnceLock::new(),
            file_watcher: OnceLock::new(),
            rate_limit_cfg,
            rate_limit_reloader: OnceLock::new(),
            tx_velocity_cfg,
            tx_velocity_store,
            tx_velocity_reloader: OnceLock::new(),
            ddos_cfg,
            ddos_check,
            ddos_reloader: OnceLock::new(),
            audit_sender: OnceLock::new(),
        }
    }

    /// Load `configs/rate-limit.yaml` once and start the hot-reload watcher.
    ///
    /// Bad YAML or a missing file logs a warning and leaves the subsystem
    /// inert (default empty config) — the gateway never refuses to start
    /// because of a rate-limit config issue.
    pub fn start_rate_limit_watcher(&self, path: &Path) {
        if self.rate_limit_reloader.get().is_some() {
            return;
        }
        match RateLimitFileConfig::from_path(path) {
            Ok(cfg) => {
                self.rate_limit_cfg.store(cfg);
                info!(file = %path.display(), "rate_limit: initial config loaded");
            }
            Err(e) => {
                warn!(file = %path.display(), error = %e, "rate_limit: initial load failed; using empty config");
            }
        }
        match RateLimitReloader::start(path.to_path_buf(), Arc::clone(&self.rate_limit_cfg), RL_DEBOUNCE_MS) {
            Ok(r) => {
                let _ = self.rate_limit_reloader.set(r);
            }
            Err(e) => warn!(
                file = %path.display(),
                error = %e,
                "rate_limit: hot-reload watcher failed to start; running without hot-reload"
            ),
        }
    }

    /// Test/admin hook: replace the rate-limit config snapshot directly.
    /// Used by integration tests; production paths go through the file watcher.
    #[cfg(test)]
    pub fn replace_rate_limit_config(&self, cfg: Arc<RateLimitConfig>) {
        self.rate_limit_cfg.store(cfg);
    }

    /// Load `configs/tx-velocity.yaml` once and start the hot-reload watcher.
    ///
    /// Bad YAML or a missing file logs a warning and leaves the subsystem
    /// inert (default disabled config) — the gateway never refuses to start
    /// because of a tx-velocity config issue.
    pub fn start_tx_velocity_watcher(&self, path: &Path) {
        if self.tx_velocity_reloader.get().is_some() {
            return;
        }
        match TxVelocityFileConfig::from_path(path) {
            Ok(cfg) => {
                self.tx_velocity_cfg.store(cfg);
                info!(file = %path.display(), "tx_velocity: initial config loaded");
            }
            Err(e) => {
                warn!(file = %path.display(), error = %e, "tx_velocity: initial load failed; using disabled config");
            }
        }
        match TxVelocityReloader::start(path.to_path_buf(), Arc::clone(&self.tx_velocity_cfg), None) {
            Ok(r) => {
                let _ = self.tx_velocity_reloader.set(r);
            }
            Err(e) => warn!(
                file = %path.display(),
                error = %e,
                "tx_velocity: hot-reload watcher failed to start; running without hot-reload"
            ),
        }
    }

    /// Load `configs/ddos.yaml` once and start the hot-reload watcher.
    ///
    /// Bad YAML or a missing file logs a warning and leaves the subsystem
    /// inert (default empty config) — the gateway never refuses to start
    /// because of a `DDoS` config issue.
    pub fn start_ddos_watcher(&self, path: &Path) {
        if self.ddos_reloader.get().is_some() {
            return;
        }
        match DdosFileConfig::from_path(path) {
            Ok(cfg) => {
                self.ddos_cfg.store(cfg);
                info!(file = %path.display(), "ddos: initial config loaded");
            }
            Err(e) => {
                warn!(file = %path.display(), error = %e, "ddos: initial load failed; using empty config");
            }
        }
        match DdosReloader::start(path.to_path_buf(), Arc::clone(&self.ddos_cfg), DDOS_DEBOUNCE_MS) {
            Ok(r) => {
                let _ = self.ddos_reloader.set(r);
            }
            Err(e) => warn!(
                file = %path.display(),
                error = %e,
                "ddos: hot-reload watcher failed to start; running without hot-reload"
            ),
        }
    }

    /// Get reference to `DDoS` metrics for external access.
    #[must_use]
    pub fn ddos_metrics(&self) -> &Arc<DdosMetrics> {
        self.ddos_check.metrics()
    }

    /// Get reference to `DDoS` ban table for external access (e.g., purge task).
    #[must_use]
    pub fn ddos_ban_table(&self) -> &Arc<DynamicBanTable> {
        self.ddos_check.ban_table()
    }

    /// Set the root rules directory used by the file-based custom rule
    /// loader (FR-003). Call before `reload_rules` to take effect.
    pub fn set_rules_dir(&self, dir: PathBuf) {
        let _ = self.rules_dir.set(dir);
    }

    /// Start the FR-003 hot-reload watcher on `<rules_dir>/custom/`.
    ///
    /// Must be called after `set_rules_dir` + initial `reload_rules`. Creation
    /// failure (e.g. permission denied on the directory) is logged and the
    /// service continues without hot-reload — rules already loaded keep
    /// working, the operator just has to restart to pick up edits.
    pub fn start_file_watcher(&self) {
        if self.file_watcher.get().is_some() {
            return;
        }
        let rules_dir = self.rules_dir.get().cloned().unwrap_or_else(|| PathBuf::from("rules"));
        match CustomRuleFileWatcher::spawn(rules_dir, Arc::clone(&self.custom_rules)) {
            Ok(w) => {
                let _ = self.file_watcher.set(w);
            }
            Err(e) => warn!(error = %e, "Custom-rule file watcher failed to start; continuing without hot-reload"),
        }
    }

    /// Plug `CrowdSec` components into the engine (called once after init).
    pub fn set_crowdsec(&self, checker: Arc<CrowdSecChecker>, appsec: Option<Arc<AppSecClient>>) {
        let _ = self.crowdsec_checker.set(checker);
        if let Some(ac) = appsec {
            let _ = self.appsec_client.set(ac);
        }
    }

    /// Plug the community checker into the engine (called once after init).
    pub fn set_community(&self, checker: Arc<CommunityChecker>) {
        let _ = self.community_checker.set(checker);
    }

    /// Plug the community signal reporter into the engine (called once after init).
    ///
    /// When set, every WAF detection (block or `log_only`) is pushed to the
    /// community reporter buffer for eventual batch upload.
    pub fn set_community_reporter(&self, reporter: Arc<CommunityReporter>) {
        let _ = self.community_reporter.set(reporter);
    }

    /// Plug the `GeoIP` lookup service into the engine (called once after init).
    ///
    /// After this call every request will have its `ctx.geo` populated before
    /// the checker pipeline runs, enabling `GeoIP`-based rules.
    pub fn set_geoip(&self, service: Arc<GeoIpService>) {
        let _ = self.geoip.set(service);
    }

    /// Plug the `VictoriaLogs` audit sender into the engine (called once
    /// after init when `[victoria_logs] enabled = true`).
    pub fn set_audit_sender(&self, sender: Arc<AuditSender>) {
        let _ = self.audit_sender.set(sender);
    }

    /// Return a reference to the `GeoCheck` so callers can load rules.
    pub const fn geo_check(&self) -> &Arc<GeoCheck> {
        &self.geo_check
    }

    /// Hot-reload `SQLi` scan configuration without restarting.
    pub fn reload_sqli_scan_config(&self, cfg: SqliScanConfig) {
        self.sqli_check.reload_config(cfg);
    }

    /// Reload all rules from the database
    pub async fn reload_rules(&self) -> anyhow::Result<()> {
        // Reload IP/URL rules
        self.store.reload_all().await?;

        // Reload custom rules
        let custom_rules = self.db.list_custom_rules(None).await?;
        {
            let mut by_host: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
            for row in &custom_rules {
                match from_db_rule(row) {
                    Ok(rule) => {
                        by_host.entry(row.host_code.clone()).or_default().push(rule);
                    }
                    Err(e) => warn!("Failed to parse custom rule {}: {}", row.id, e),
                }
            }
            for (host_code, rules) in by_host {
                self.custom_rules.load_host(&host_code, rules);
            }
        }

        // ── FR-003: file-based custom rules ──────────────────────────────────
        // DB load above used `load_host` which replaces buckets — so any prior
        // file rules are already cleared. Append fresh file rules with `add_rule`;
        // they sort into the same priority-ordered bucket as DB rules.
        let rules_dir = self.rules_dir.get().cloned().unwrap_or_else(|| PathBuf::from("rules"));
        match crate::rules::custom_file_loader::load_dir(&rules_dir) {
            Ok(file_rules) => {
                let count = file_rules.len();
                for rule in file_rules {
                    self.custom_rules.add_file_rule(rule);
                }
                if count > 0 {
                    info!("Loaded {count} file-based custom rules from {rules_dir:?}");
                }
            }
            Err(e) => warn!("Custom rule file load failed: {e}"),
        }

        // Reload sensitive patterns
        let patterns = self.db.list_sensitive_patterns(None).await?;
        {
            let mut by_host: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
            for row in &patterns {
                if row.check_request {
                    by_host
                        .entry(row.host_code.clone())
                        .or_default()
                        .push(row.pattern.clone());
                }
            }
            for (host_code, pats) in by_host {
                self.sensitive.load_host(&host_code, &pats);
            }
        }

        // Reload hotlink configs
        let hotlink_configs = self.db.list_hotlink_configs().await?;
        for row in &hotlink_configs {
            let domains: Vec<String> = row
                .allowed_domains
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            let config = crate::checks::anti_hotlink::HotlinkConfig {
                enabled: row.enabled,
                allow_empty_referer: row.allow_empty_referer,
                allowed_domains: domains,
                redirect_url: row.redirect_url.clone(),
            };
            self.hotlink.set_config(&row.host_code, config);
        }

        Ok(())
    }

    /// Run the full WAF inspection pipeline.
    ///
    /// `ctx` is taken as `&mut` so the engine can enrich it with `GeoIP` data
    /// before the checker pipeline runs.  Callers should check
    /// `decision.is_allowed()`.
    pub async fn inspect(&self, ctx: &mut RequestCtx) -> WafDecision {
        // Skip WAF if guard is disabled for this host
        if !ctx.host_config.guard_status {
            return WafDecision::allow();
        }

        // ── GeoIP enrichment — populate ctx.geo before any checks ────────────
        if let Some(geoip) = self.geoip.get() {
            ctx.geo = Some(geoip.lookup(ctx.client_ip));
        }

        // ── Phase 1: IP Whitelist — allow immediately if matched ──────────────
        let ip_whitelist = check_ip_whitelist(ctx, &self.store);
        if let Some(ref result) = ip_whitelist.result
            && matches!(ip_whitelist.action, WafAction::Allow)
            && result.phase == waf_common::Phase::IpWhitelist
        {
            debug!("Request allowed by IP whitelist: {}", ctx.client_ip);
            return ip_whitelist;
        }

        // ── Phase 2: IP Blacklist — block if matched ───────────────────────────
        let ip_blacklist = check_ip_blacklist(ctx, &self.store);
        if !ip_blacklist.is_allowed() {
            self.log_attack(ctx, &ip_blacklist);
            self.report_community_signal(ctx, &ip_blacklist);
            self.send_audit_event(ctx, &ip_blacklist);
            return ip_blacklist;
        }

        // ── Phase 3: URL Whitelist — allow immediately if matched ──────────────
        if let Some(url_wl) = check_url_whitelist(ctx, &self.store) {
            debug!("Request allowed by URL whitelist: {}", ctx.path);
            return url_wl;
        }

        // ── Phase 4: URL Blacklist — block if matched ──────────────────────────
        let url_bl = check_url_blacklist(ctx, &self.store);
        if !url_bl.is_allowed() {
            self.log_attack(ctx, &url_bl);
            self.report_community_signal(ctx, &url_bl);
            self.send_audit_event(ctx, &url_bl);
            return url_bl;
        }

        // ── Phase 19: DDoS burst detection (FR-005) ───────────────────────────
        // Runs AFTER allowlist/blacklist (fast-path) and BEFORE rate-limit.
        // Banned IPs are blocked here; burst detection may trigger new bans.
        if let Some(result) = self.ddos_check.check(ctx) {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            return decision;
        }

        // ── Phase 16a: CrowdSec Bouncer — fast cache lookup ───────────────────
        if let Some(cs) = self.crowdsec_checker.get()
            && let Some(result) = cs.check(ctx)
        {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            self.send_audit_event(ctx, &decision);
            return decision;
        }

        // ── Phase 18: Community blocklist ─────────────────────────────────────
        if let Some(cc) = self.community_checker.get()
            && let Some(result) = cc.check(ctx)
        {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision);
            return decision;
        }

        // ── Phase 17: GeoIP access control ────────────────────────────────────
        if let Some(result) = self.geo_check.check(ctx) {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            self.send_audit_event(ctx, &decision);
            return decision;
        }

        // ── Phase 5-11: Attack detection pipeline ─────────────────────────────
        for checker in &self.checkers {
            if let Some(result) = checker.check(ctx) {
                let rule_name = result.rule_name.clone();

                let decision = if ctx.host_config.log_only_mode {
                    WafDecision {
                        action: WafAction::LogOnly,
                        result: Some(result),
                    }
                } else {
                    let body = render_block_page(ctx, &rule_name);
                    WafDecision::block(403, Some(body), result)
                };

                self.log_security_event(ctx, &decision);
                self.report_community_signal(ctx, &decision);
                self.send_audit_event(ctx, &decision);
                return decision;
            }
        }

        // ── SQLi check (separate for hot-reload support) ─────────────────────
        if let Some(result) = self.sqli_check.check(ctx) {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            self.send_audit_event(ctx, &decision);
            return decision;
        }

        // ── Phase 16b: CrowdSec AppSec — async per-request check ──────────────
        if let Some(appsec) = self.appsec_client.get() {
            match appsec.check_request(ctx).await {
                AppSecResult::Block { message } => {
                    let result = appsec_to_detection(message);
                    let rule_name = result.rule_name.clone();
                    let decision = if ctx.host_config.log_only_mode {
                        WafDecision {
                            action: WafAction::LogOnly,
                            result: Some(result),
                        }
                    } else {
                        let body = render_block_page(ctx, &rule_name);
                        WafDecision::block(403, Some(body), result)
                    };
                    self.log_security_event(ctx, &decision);
                    self.report_community_signal(ctx, &decision);
                    self.send_audit_event(ctx, &decision);
                    return decision;
                }
                AppSecResult::Allow | AppSecResult::Unavailable => {}
            }
        }

        // ── Phase 12: Custom rules engine ─────────────────────────────────────
        if let Some(result) = self.custom_rules.check(ctx) {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            self.send_audit_event(ctx, &decision);
            return decision;
        }

        // ── Phase 13: OWASP CRS ────────────────────────────────────────────────
        if let Some(result) = self.owasp.check(ctx) {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            self.send_audit_event(ctx, &decision);
            return decision;
        }

        // ── Phase 14: Sensitive data ───────────────────────────────────────────
        if let Some(result) = self.sensitive.check(ctx) {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            self.send_audit_event(ctx, &decision);
            return decision;
        }

        // ── Phase 15: Anti-hotlinking ──────────────────────────────────────────
        if let Some(result) = self.hotlink.check(ctx) {
            let rule_name = result.rule_name.clone();
            let decision = if ctx.host_config.log_only_mode {
                WafDecision {
                    action: WafAction::LogOnly,
                    result: Some(result),
                }
            } else {
                let body = render_block_page(ctx, &rule_name);
                WafDecision::block(403, Some(body), result)
            };
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            self.send_audit_event(ctx, &decision);
            return decision;
        }

        WafDecision::allow()
    }

    // ── Logging helpers ───────────────────────────────────────────────────────

    /// Log a Phase 1/2 event to the `attack_logs` table (fire-and-forget).
    fn log_attack(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let Some(result) = &decision.result else {
            return;
        };

        let action_str = match &decision.action {
            WafAction::Block { .. } => "block",
            WafAction::Allow => "allow",
            WafAction::LogOnly => "log_only",
            WafAction::Redirect { .. } => "redirect",
        };

        let log = AttackLog {
            id: Uuid::new_v4(),
            host_code: ctx.host_config.code.clone(),
            host: ctx.host.clone(),
            client_ip: ctx.client_ip.to_string(),
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            query: if ctx.query.is_empty() {
                None
            } else {
                Some(ctx.query.clone())
            },
            rule_id: result.rule_id.clone(),
            rule_name: result.rule_name.clone(),
            action: action_str.to_string(),
            phase: result.phase.to_string(),
            detail: Some(result.detail.clone()),
            request_headers: None,
            geo_info: ctx.geo.as_ref().map(|g| {
                serde_json::json!({
                    "country": g.country,
                    "province": g.province,
                    "city": g.city,
                    "isp": g.isp,
                    "iso_code": g.iso_code,
                })
            }),
            created_at: chrono::Utc::now(),
        };

        let db = Arc::clone(&self.db);
        tokio::spawn(async move {
            if let Err(e) = db.create_attack_log(log).await {
                warn!("Failed to log attack event: {}", e);
            }
        });
    }

    /// Log a Phase 2+ security event to the `security_events` table (fire-and-forget).
    fn log_security_event(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let Some(result) = &decision.result else {
            return;
        };

        let action_str = match &decision.action {
            WafAction::Block { .. } => "block",
            WafAction::Allow => "allow",
            WafAction::LogOnly => "log_only",
            WafAction::Redirect { .. } => "redirect",
        };

        let event = CreateSecurityEvent {
            host_code: ctx.host_config.code.clone(),
            client_ip: ctx.client_ip.to_string(),
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            rule_id: result.rule_id.clone(),
            rule_name: result.rule_name.clone(),
            action: action_str.to_string(),
            detail: Some(result.detail.clone()),
            geo_info: ctx.geo.as_ref().map(|g| {
                serde_json::json!({
                    "country": g.country,
                    "province": g.province,
                    "city": g.city,
                    "isp": g.isp,
                    "iso_code": g.iso_code,
                })
            }),
        };

        let db = Arc::clone(&self.db);
        tokio::spawn(async move {
            if let Err(e) = db.create_security_event(event).await {
                warn!("Failed to log security event: {}", e);
            }
        });
    }

    /// Mirror a non-Allow decision into the `VictoriaLogs` audit stream.
    ///
    /// Fire-and-forget: drops silently when the audit sender is unset
    /// (`[victoria_logs] enabled = false`) or its buffer is saturated.
    /// The hot path never blocks on observability.
    fn send_audit_event(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let Some(sender) = self.audit_sender.get() else {
            return;
        };
        let Some(result) = &decision.result else {
            return;
        };

        let event_type = match &decision.action {
            WafAction::Block { .. } => AuditEventType::Block,
            WafAction::Allow => AuditEventType::Allow,
            WafAction::LogOnly => AuditEventType::LogOnly,
            // Redirects in this codebase are used as challenge-style
            // responses (CAPTCHA, soft block). Map to the closest LogsQL
            // category so analysts can filter them out from hard blocks.
            WafAction::Redirect { .. } => AuditEventType::Challenge,
        };

        let event = AuditEvent {
            timestamp: chrono::Utc::now(),
            event_type,
            rule_name: result.rule_name.clone(),
            rule_id: result.rule_id.clone(),
            phase: Some(result.phase.to_string()),
            client_ip: ctx.client_ip.to_string(),
            host: ctx.host.clone(),
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            tier: Some(format!("{:?}", ctx.tier)),
            detail: Some(result.detail.clone()),
            req_id: Some(ctx.req_id.clone()),
        };
        sender.send(event);
    }

    /// Push a detection signal to the community reporter via bounded channel.
    ///
    /// This is a **synchronous** call on the hot path — no `tokio::spawn`,
    /// no async mutex, just a single `try_send` into an MPSC channel.
    /// When the channel is full (back-pressure from flood traffic), the signal is silently
    /// dropped and the reporter logs the drop count periodically.
    fn report_community_signal(&self, ctx: &RequestCtx, decision: &WafDecision) {
        let Some(reporter) = self.community_reporter.get() else {
            return;
        };
        let Some(result) = &decision.result else {
            return;
        };

        let req_info = RequestInfo {
            http_method: ctx.method.clone(),
            request_path: ctx.path.clone(),
            request_host: ctx.host.clone(),
            geo_country: ctx.geo.as_ref().map(|g| g.iso_code.clone()),
        };

        reporter.try_push_detection(ctx.client_ip, result, Some(&req_info));
    }
}
