use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
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

use crate::checks::{
    AntiHotlinkCheck, BotCheck, BruteForceCheck, CcCheck, Check, DirTraversalCheck, GeoCheck, HeaderInjectionCheck,
    OWASPCheck, RceCheck, RequestBodyAbuseCheck, ScannerCheck, SensitiveCheck, SqlInjectionCheck, SsrfCheck, XssCheck,
};
use crate::community::{CommunityChecker, CommunityReporter, RequestInfo};
use crate::crowdsec::{AppSecClient, AppSecResult, CrowdSecChecker, appsec_to_detection};
use crate::geoip::GeoIpService;
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
        // CC runs first to shed flood traffic before expensive pattern checks.
        // Stubs for FR-016/017/018/020 are registered here by Phase 00 so each
        // downstream FR PR only swaps its own check file (zero shared-edit conflicts).
        let checkers: Vec<Box<dyn Check>> = vec![
            Box::new(CcCheck::new()),
            Box::new(ScannerCheck::new()),
            Box::new(BotCheck::new()),
            Box::new(XssCheck::new()),
            Box::new(RceCheck::new()),
            Box::new(DirTraversalCheck::new()),
            Box::new(SsrfCheck::new()),
            Box::new(HeaderInjectionCheck::new()),
            Box::new(BruteForceCheck::new()),
            Box::new(RequestBodyAbuseCheck::new()),
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
        }
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
            return url_bl;
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
            return decision;
        }

        WafDecision::allow()
    }

    /// Dispatch an upstream response status to every registered `Check`.
    ///
    /// Gateway callers invoke this from Pingora's `response_filter` after
    /// extracting the status code. Most checks inherit the no-op default and
    /// ignore the call; FR-018 brute-force records 401/403 as login
    /// failures and FR-019 scanner (future) will count 4xx/5xx bursts.
    ///
    /// Sync on purpose — there's no body or await in v1. The work inside
    /// each `on_response` impl is a bounded state insert (`DashMap` +
    /// `Mutex` push).
    pub fn on_response(&self, ctx: &RequestCtx, status: u16) {
        for check in &self.checkers {
            check.on_response(ctx, status);
        }
        self.sqli_check.on_response(ctx, status);
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
