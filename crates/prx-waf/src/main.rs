#![allow(clippy::print_stdout, clippy::print_stderr)]

mod victoria_logs;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use gateway::{HostRouter, TunnelConfig, WafProxy};
use waf_api::{AppState, start_api_server};
use waf_common::config::{AppConfig, load_config};
use waf_engine::logging::{AuditSender, BatchConfig, LayerSlot, VictoriaLogsLayer, spawn_batch_flusher};
use waf_engine::{
    CrowdSecClient, CrowdSecConfig, ExportFormat, GeoIpService, RuleManager, WafEngine, WafEngineConfig, XdbUpdater,
    cache_policy_from_str, init_community, init_crowdsec, spawn_auto_updater,
};
use waf_storage::Database;

/// PRX-WAF — High-performance Pingora-based Web Application Firewall
#[derive(Parser, Debug)]
#[command(name = "prx-waf", version, about)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "configs/default.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the proxy and management API
    Run,
    /// Run database migrations only
    Migrate,
    /// Seed the default admin user (admin / admin) if none exist
    SeedAdmin,
    /// `CrowdSec` integration management
    #[command(subcommand)]
    Crowdsec(CrowdSecCommands),
    /// Rule management (list, validate, reload, import, export, …)
    #[command(subcommand)]
    Rules(RulesCommands),
    /// Rule source management (add, remove, sync, …)
    #[command(subcommand)]
    Sources(SourcesCommands),
    /// Bot detection management (list, add, remove, test)
    #[command(subcommand)]
    Bot(BotCommands),
    /// `GeoIP` database management (download, update, status)
    #[command(subcommand)]
    Geoip(GeoIpCommands),
    /// Community threat intelligence sharing management
    #[command(subcommand)]
    Community(CommunityCommands),
    /// Cluster management (status, nodes, token, promote/demote/remove)
    #[command(subcommand)]
    Cluster(ClusterCommands),
}

// ── Community sub-commands ────────────────────────────────────────────────────

/// Community threat intelligence sub-commands
#[derive(Subcommand, Debug)]
enum CommunityCommands {
    /// Show community integration status
    Status,
    /// Enroll this machine with the community server
    Enroll,
    /// Test connectivity to the community server
    Test,
}

// ── Cluster sub-commands ──────────────────────────────────────────────────────

/// Cluster management sub-commands
#[derive(Subcommand, Debug)]
enum ClusterCommands {
    /// Show cluster status (role, term, nodes, health)
    Status,
    /// List cluster nodes and their roles
    Nodes,
    /// Cluster join-token management
    #[command(subcommand)]
    Token(ClusterTokenCommands),
    /// Promote a node to Main
    Promote {
        /// Node ID to promote
        node_id: String,
    },
    /// Demote a node to Worker
    Demote {
        /// Node ID to demote
        node_id: String,
    },
    /// Remove a node from the cluster
    Remove {
        /// Node ID to remove
        node_id: String,
    },
    /// Generate cluster CA and per-node certificates for offline provisioning
    ///
    /// Run this once before starting a new cluster. The generated certificates
    /// are written to `OUTPUT_DIR` and then mounted into each node's container.
    CertInit {
        /// Comma-separated list of node names to generate certificates for
        #[arg(long, default_value = "node-a,node-b,node-c")]
        nodes: String,
        /// Output directory for certificate files
        #[arg(long, default_value = "/certs")]
        output_dir: String,
        /// CA certificate validity in days
        #[arg(long, default_value_t = 3650)]
        ca_validity_days: u32,
        /// Node certificate validity in days
        #[arg(long, default_value_t = 365)]
        node_validity_days: u32,
    },
}

/// Cluster token sub-commands
#[derive(Subcommand, Debug)]
enum ClusterTokenCommands {
    /// Generate a cluster join token
    Generate {
        /// Token validity duration (e.g. 24h, 7d)
        #[arg(long, default_value = "24h")]
        ttl: String,
    },
}

// ── CrowdSec sub-commands ─────────────────────────────────────────────────────

/// `CrowdSec` sub-commands
#[derive(Subcommand, Debug)]
enum CrowdSecCommands {
    /// Show `CrowdSec` connection status and cache statistics
    Status,
    /// List active decisions cached from LAPI
    Decisions,
    /// Test LAPI connectivity
    Test,
    /// Interactive setup wizard (detect platform, generate config snippet)
    Setup,
}

// ── Rules sub-commands ────────────────────────────────────────────────────────

/// Rule management sub-commands
#[derive(Subcommand, Debug)]
enum RulesCommands {
    /// List all loaded rules
    List {
        /// Filter by category (sqli, xss, rce, bot, scanner, …)
        #[arg(long)]
        category: Option<String>,
        /// Filter by source (owasp, builtin-bot, builtin-scanner, custom, …)
        #[arg(long)]
        source: Option<String>,
    },
    /// Show detailed information about a rule
    Info {
        /// Rule id
        rule_id: String,
    },
    /// Enable a rule
    Enable {
        /// Rule id
        rule_id: String,
    },
    /// Disable a rule
    Disable {
        /// Rule id
        rule_id: String,
    },
    /// Hot-reload all rules from disk
    Reload,
    /// Validate a rule file without loading it
    Validate {
        /// Path to the rule file
        path: PathBuf,
    },
    /// Import rules from a local file or remote URL
    Import {
        /// File path or HTTP(S) URL
        source: String,
    },
    /// Export current rules to stdout
    Export {
        /// Output format: yaml (default) or json
        #[arg(long, default_value = "yaml")]
        format: String,
    },
    /// Fetch latest rules from all configured remote sources
    Update,
    /// Search rules by name, id, or description
    Search {
        /// Search query
        query: String,
    },
    /// Show rule statistics
    Stats,
}

// ── Sources sub-commands ──────────────────────────────────────────────────────

/// Rule source sub-commands
#[derive(Subcommand, Debug)]
enum SourcesCommands {
    /// List configured rule sources
    List,
    /// Add a remote rule source
    Add {
        /// Source name
        name: String,
        /// Remote URL
        url: String,
        /// Format: yaml | modsec | json
        #[arg(long, default_value = "yaml")]
        format: String,
    },
    /// Remove a rule source by name
    Remove {
        /// Source name
        name: String,
    },
    /// Fetch latest rules from a source (or all sources)
    Update {
        /// Source name (optional — all sources if omitted)
        name: Option<String>,
    },
    /// Sync all configured sources
    Sync,
}

// ── Bot sub-commands ──────────────────────────────────────────────────────────

/// Bot detection sub-commands
#[derive(Subcommand, Debug)]
enum BotCommands {
    /// List known bot signatures
    List,
    /// Add a bot pattern
    Add {
        /// Regex pattern to match against User-Agent
        pattern: String,
        /// Action: block | log | captcha | allow
        #[arg(long, default_value = "block")]
        action: String,
    },
    /// Remove a bot pattern
    Remove {
        /// Pattern to remove
        pattern: String,
    },
    /// Test a User-Agent string against all bot rules
    Test {
        /// User-Agent string to test
        user_agent: String,
    },
}

// ── GeoIP sub-commands ────────────────────────────────────────────────────────

/// `GeoIP` database sub-commands
#[derive(Subcommand, Debug)]
enum GeoIpCommands {
    /// Download xdb files from upstream (first-time setup or forced refresh)
    Download,
    /// Check for updates and download if newer files are available
    Update,
    /// Show current xdb file info (path, size, modification date)
    Status,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    // Install the rustls process-wide `CryptoProvider`.
    //
    // rustls 0.23 panics on first use if both `ring` and `aws-lc-rs` are linked
    // (which happens here via transitive dependencies — Cargo.lock contains
    // both). Installing explicitly at startup picks `ring` deterministically
    // and avoids the worker-thread panic that disables the cluster QUIC
    // transport (and therefore /api/cluster/status). The cluster transport
    // ALSO uses `builder_with_provider(ring)` directly, so even if this call
    // races with another initialiser the cluster bring-up still works. We
    // emit a stderr breadcrumb here so the container log makes it obvious
    // whether this exact binary contains the fix.
    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) => eprintln!("rustls: installed ring as the process-default CryptoProvider"),
        Err(_) => eprintln!("rustls: another CryptoProvider was already installed (ignored)"),
    }

    // The VictoriaLogs tracing layer needs a `BatchSender` that can only be
    // built once the Tokio runtime is up.  We register the layer here with
    // an empty slot; `init_async` plugs the real sender in afterwards. Until
    // then the layer is inert (events drop on the floor), so CLI commands
    // that don't go through `run_server` are unaffected.
    let (vlogs_layer, vlogs_layer_slot) = VictoriaLogsLayer::new();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env()
                .add_directive(tracing_subscriber::filter::Directive::from(tracing::Level::INFO)),
        )
        .with(vlogs_layer)
        .init();

    let cli = Cli::parse();
    info!("PRX-WAF v{}", env!("CARGO_PKG_VERSION"));

    let config = load_config(&cli.config).unwrap_or_else(|e| {
        tracing::warn!("Failed to load config from {}: {}. Using defaults.", cli.config, e);
        AppConfig::default()
    });

    match cli.command {
        Commands::Migrate => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_migrate(&config))?;
        }
        Commands::SeedAdmin => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_seed_admin(&config))?;
        }
        Commands::Run => {
            run_server(&config, &cli.config, vlogs_layer_slot)?;
        }
        Commands::Crowdsec(sub) => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_crowdsec_cmd(sub, &config))?;
        }
        Commands::Rules(sub) => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_rules_cmd(sub, &config))?;
        }
        Commands::Sources(sub) => {
            run_sources_cmd(sub, &config)?;
        }
        Commands::Bot(sub) => {
            run_bot_cmd(sub, &config)?;
        }
        Commands::Geoip(sub) => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_geoip_cmd(sub, &config))?;
        }
        Commands::Community(sub) => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_community_cmd(sub, &config))?;
        }
        Commands::Cluster(sub) => {
            run_cluster_cmd(sub, &config)?;
        }
    }

    Ok(())
}

// ── GeoIP commands ────────────────────────────────────────────────────────────

async fn run_geoip_cmd(cmd: GeoIpCommands, config: &AppConfig) -> anyhow::Result<()> {
    use std::path::PathBuf;
    use waf_engine::geoip_updater::xdb_file_info;

    // Derive the data directory from the configured xdb path.
    let data_dir = PathBuf::from(&config.geoip.ipv4_xdb_path)
        .parent()
        .map_or_else(|| PathBuf::from("data"), std::path::Path::to_path_buf);

    let source_url = config.geoip.auto_update.source_url.clone();
    let updater = XdbUpdater::new(data_dir.clone(), source_url);

    match cmd {
        GeoIpCommands::Download => {
            println!("Downloading ip2region xdb files...");
            println!("  Source: {}", config.geoip.auto_update.source_url);
            println!("  Target: {}/", data_dir.display());
            println!();

            match updater.download().await {
                Ok(result) => {
                    if result.ipv4_updated {
                        println!("  IPv4 xdb: {} bytes", result.ipv4_size);
                    }
                    if result.ipv6_updated {
                        println!("  IPv6 xdb: {} bytes", result.ipv6_size);
                    }
                    println!();
                    println!("Download complete.");
                }
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            }
        }

        GeoIpCommands::Update => {
            println!("Checking for ip2region xdb updates...");

            let policy = cache_policy_from_str(&config.geoip.cache_policy);
            let geoip = GeoIpService::init(&config.geoip.ipv4_xdb_path, &config.geoip.ipv6_xdb_path, policy)?;

            match updater.update(&geoip).await {
                Ok(result) if result.ipv4_updated || result.ipv6_updated => {
                    println!("Updated successfully:");
                    if result.ipv4_updated {
                        println!("  IPv4 xdb: {} bytes", result.ipv4_size);
                    }
                    if result.ipv6_updated {
                        println!("  IPv6 xdb: {} bytes", result.ipv6_size);
                    }
                }
                Ok(_) => {
                    println!("Already up to date.");
                }
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            }
        }

        GeoIpCommands::Status => {
            println!("GeoIP xdb Status");
            println!("================");
            println!();

            let v4_path = std::path::Path::new(&config.geoip.ipv4_xdb_path);
            let v6_path = std::path::Path::new(&config.geoip.ipv6_xdb_path);

            println!("  IPv4:  {}", xdb_file_info(v4_path));
            println!("  IPv6:  {}", xdb_file_info(v6_path));
            println!();
            println!("  Config:");
            println!("    Enabled:        {}", config.geoip.enabled);
            println!("    Cache policy:   {}", config.geoip.cache_policy);
            println!("    Auto-update:    {}", config.geoip.auto_update.enabled);
            println!("    Interval:       {}", config.geoip.auto_update.interval);
            println!("    Source URL:     {}", config.geoip.auto_update.source_url);
        }
    }

    Ok(())
}

// ── Rules commands ────────────────────────────────────────────────────────────

#[allow(clippy::significant_drop_tightening)]
async fn run_rules_cmd(cmd: RulesCommands, config: &AppConfig) -> anyhow::Result<()> {
    match cmd {
        RulesCommands::List { category, source } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;

            let reg = manager.registry.read();
            let rules: Vec<_> = match (&category, &source) {
                (Some(cat), _) => reg.filter_by_category(cat),
                (_, Some(src)) => reg.filter_by_source(src),
                _ => reg.list(),
            };

            println!(
                "{:<20} {:<35} {:<12} {:<16} {:<8} Action",
                "ID", "Name", "Category", "Source", "Status"
            );
            println!("{}", "-".repeat(100));
            for rule in &rules {
                println!(
                    "{:<20} {:<35} {:<12} {:<16} {:<8} {}",
                    truncate(&rule.id, 19),
                    truncate(&rule.name, 34),
                    truncate(&rule.category, 11),
                    truncate(&rule.source, 15),
                    if rule.enabled { "enabled" } else { "disabled" },
                    rule.action,
                );
            }
            println!("\nTotal: {} rules", rules.len());
        }

        RulesCommands::Info { rule_id } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;

            let reg = manager.registry.read();
            match reg.get(&rule_id) {
                Some(rule) => {
                    println!("ID:          {}", rule.id);
                    println!("Name:        {}", rule.name);
                    println!("Category:    {}", rule.category);
                    println!("Source:      {}", rule.source);
                    println!("Status:      {}", if rule.enabled { "enabled" } else { "disabled" });
                    println!("Action:      {}", rule.action);
                    if let Some(sev) = &rule.severity {
                        println!("Severity:    {sev}");
                    }
                    if let Some(desc) = &rule.description {
                        println!("Description: {desc}");
                    }
                    if let Some(pattern) = &rule.pattern {
                        println!("Pattern:     {pattern}");
                    }
                    if !rule.tags.is_empty() {
                        println!("Tags:        {}", rule.tags.join(", "));
                    }
                }
                None => println!("Rule not found: {rule_id}"),
            }
        }

        RulesCommands::Enable { rule_id } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;
            manager.enable_rule(&rule_id)?;
            println!("Rule enabled: {rule_id}");
        }

        RulesCommands::Disable { rule_id } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;
            manager.disable_rule(&rule_id)?;
            println!("Rule disabled: {rule_id}");
        }

        RulesCommands::Reload => {
            let mut manager = RuleManager::new(&config.rules);
            let report = manager.reload()?;
            println!("{report}");
        }

        RulesCommands::Validate { path } => {
            let manager = RuleManager::new(&config.rules);
            let errors = manager.validate_file(&path)?;
            if errors.is_empty() {
                println!("OK: {} is valid", path.display());
            } else {
                println!("{} validation errors in {}:", errors.len(), path.display());
                for err in &errors {
                    println!("  - {err}");
                }
                std::process::exit(1);
            }
        }

        RulesCommands::Import { source } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;

            let count = if source.starts_with("http://") || source.starts_with("https://") {
                manager.import_from_url(&source).await?
            } else {
                manager.import_from_file(std::path::Path::new(&source))?
            };
            println!("Imported {count} rules from {source}");
        }

        RulesCommands::Export { format } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;
            let fmt = ExportFormat::parse_str(&format);
            let output = manager.export(fmt)?;
            print!("{output}");
        }

        RulesCommands::Update => {
            println!("Fetching remote rule sources...");
            let mut manager = RuleManager::new(&config.rules);
            let results = manager.load_remote_sources().await;
            if results.is_empty() {
                println!("No remote rule sources configured.");
            } else {
                let mut had_error = false;
                for (name, result) in &results {
                    match result {
                        Ok(n) => println!("  {name}: {n} rules loaded"),
                        Err(e) => {
                            eprintln!("  {name}: ERROR: {e}");
                            had_error = true;
                        }
                    }
                }
                if had_error {
                    anyhow::bail!("One or more remote sources failed to load");
                }
                println!("Done.");
            }
        }

        RulesCommands::Search { query } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;

            let results = manager.search(&query);
            if results.is_empty() {
                println!("No rules matched '{query}'");
            } else {
                println!("{} result(s) for '{query}':", results.len());
                for rule in &results {
                    println!("  {} — {} [{}]", rule.id, rule.name, rule.category);
                }
            }
        }

        RulesCommands::Stats => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;
            let stats = manager.stats();

            println!("Rule Statistics");
            println!("===============");
            println!("  Total:    {}", stats.total);
            println!("  Enabled:  {}", stats.enabled);
            println!("  Disabled: {}", stats.disabled);
            println!("  Version:  {}", stats.version);
            println!();
            println!("By Category:");
            let mut cats: Vec<_> = stats.by_category.iter().collect();
            cats.sort_by_key(|(k, _)| k.as_str());
            for (cat, count) in cats {
                println!("  {cat:<20} {count}");
            }
            println!();
            println!("By Source:");
            let mut srcs: Vec<_> = stats.by_source.iter().collect();
            srcs.sort_by_key(|(k, _)| k.as_str());
            for (src, count) in srcs {
                println!("  {src:<20} {count}");
            }
        }
    }

    Ok(())
}

// ── Sources commands ──────────────────────────────────────────────────────────

#[allow(clippy::unnecessary_wraps)]
fn run_sources_cmd(cmd: SourcesCommands, config: &AppConfig) -> anyhow::Result<()> {
    match cmd {
        SourcesCommands::List => {
            println!("{:<20} {:<12} URL/Path", "Name", "Type");
            println!("{}", "-".repeat(80));
            for src in &config.rules.sources {
                let type_str = if src.url.is_some() { "remote_url" } else { "local" };
                let location = src.url.as_deref().or(src.path.as_deref()).unwrap_or("-");
                println!("{:<20} {:<12} {}", src.name, type_str, location);
            }
            if config.rules.enable_builtin_owasp {
                println!("{:<20} {:<12} (compiled-in)", "builtin-owasp", "builtin");
            }
            if config.rules.enable_builtin_bot {
                println!("{:<20} {:<12} (compiled-in)", "builtin-bot", "builtin");
            }
            if config.rules.enable_builtin_scanner {
                println!("{:<20} {:<12} (compiled-in)", "builtin-scanner", "builtin");
            }
        }
        SourcesCommands::Add { name, url, format } => {
            println!("Add source '{name}' ({format}): {url}");
            println!("Note: add the following to your [rules.sources] config:");
            println!();
            println!("[[rules.sources]]");
            println!("name   = \"{name}\"");
            println!("url    = \"{url}\"");
            println!("format = \"{format}\"");
        }
        SourcesCommands::Remove { name } => {
            println!("Remove source '{name}': edit configs/default.toml and remove the [[rules.sources]] entry.");
        }
        SourcesCommands::Update { name } => {
            if let Some(name) = name {
                println!("Updating source '{name}'... (run `prx-waf rules update` to fetch)");
            } else {
                println!("Updating all sources... (run `prx-waf rules update` to fetch all)");
            }
        }
        SourcesCommands::Sync => {
            println!("Syncing all sources... run `prx-waf rules update` to fetch.");
        }
    }
    Ok(())
}

// ── Bot commands ──────────────────────────────────────────────────────────────

#[allow(clippy::significant_drop_tightening)]
fn run_bot_cmd(cmd: BotCommands, config: &AppConfig) -> anyhow::Result<()> {
    match cmd {
        BotCommands::List => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;
            let reg = manager.registry.read();
            let bot_rules = reg.filter_by_category("bot");

            println!("{:<20} {:<40} {:<8} Tags", "ID", "Name", "Action");
            println!("{}", "-".repeat(100));
            for rule in bot_rules {
                println!(
                    "{:<20} {:<40} {:<8} {}",
                    truncate(&rule.id, 19),
                    truncate(&rule.name, 39),
                    rule.action,
                    rule.tags.join(", "),
                );
            }
        }

        BotCommands::Add { pattern, action } => {
            println!("Bot pattern added: {pattern} → {action}");
            println!("Note: persistent storage requires database integration.");
            println!("To make permanent, add a YAML rule to your rules/ directory:");
            println!();
            println!("- id: \"BOT-CUSTOM-001\"");
            println!("  name: \"Custom bot pattern\"");
            println!("  category: \"bot\"");
            println!("  action: \"{action}\"");
            println!("  pattern: \"{pattern}\"");
        }

        BotCommands::Remove { pattern } => {
            println!("Remove bot pattern: {pattern}");
            println!("Note: remove the corresponding rule from your rules/ directory.");
        }

        BotCommands::Test { user_agent } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;
            let reg = manager.registry.read();
            let bot_rules = reg.filter_by_category("bot");

            let mut matched = false;
            for rule in bot_rules {
                if let Some(pattern) = &rule.pattern
                    && let Ok(re) = regex::Regex::new(pattern.as_str())
                    && re.is_match(user_agent.as_str())
                {
                    println!("MATCH: {} — {} (action: {})", rule.id, rule.name, rule.action);
                    matched = true;
                }
            }
            if !matched {
                println!("No bot rules matched: {user_agent}");
            }
        }
    }
    Ok(())
}

// ── Cluster commands ──────────────────────────────────────────────────────────

fn run_cluster_cmd(cmd: ClusterCommands, config: &AppConfig) -> anyhow::Result<()> {
    let cluster_addr = config
        .cluster
        .as_ref()
        .map_or("(not configured)", |c| c.listen_addr.as_str());

    match cmd {
        ClusterCommands::Status => {
            println!("Cluster Status");
            println!("==============");
            println!();
            if let Some(cluster) = &config.cluster {
                println!("  Enabled:    {}", cluster.enabled);
                println!("  Listen:     {}", cluster.listen_addr);
                println!("  Role:       {}", cluster.role);
                println!("  Node ID:    {}", cluster.node_id);
                println!("  Seeds:      {}", cluster.seeds.join(", "));
            } else {
                println!("  [INFO] Cluster is not configured. Add a [cluster] section to your config.");
            }
        }

        ClusterCommands::Nodes => {
            println!("Cluster Nodes");
            println!("=============");
            println!();
            if let Some(cluster) = &config.cluster {
                println!("  This node:  {} ({})", cluster.node_id, cluster.listen_addr);
                if cluster.seeds.is_empty() {
                    println!("  Peers:      (none configured)");
                } else {
                    println!("  Configured seeds:");
                    for seed in &cluster.seeds {
                        println!("    - {seed}");
                    }
                }
                println!();
                println!("  Note: live node list is only available through the running cluster API.");
            } else {
                println!("  [INFO] Cluster is not configured.");
            }
        }

        ClusterCommands::Token(ClusterTokenCommands::Generate { ttl }) => {
            println!("Cluster Join Token");
            println!("==================");
            println!();
            println!("  Listen addr: {cluster_addr}");
            println!("  TTL:         {ttl}");
            println!();
            println!("  Note: token generation requires a running cluster node.");
            println!("  Use the management API to generate tokens:");
            println!("    POST /api/v1/cluster/tokens  {{ \"ttl\": \"{ttl}\" }}");
        }

        ClusterCommands::Promote { node_id } => {
            println!("Promote node '{node_id}' to Main");
            println!("Note: use the management API: POST /api/v1/cluster/nodes/{node_id}/promote");
        }

        ClusterCommands::Demote { node_id } => {
            println!("Demote node '{node_id}' to Worker");
            println!("Note: use the management API: POST /api/v1/cluster/nodes/{node_id}/demote");
        }

        ClusterCommands::Remove { node_id } => {
            println!("Remove node '{node_id}' from cluster");
            println!("Note: use the management API: DELETE /api/v1/cluster/nodes/{node_id}");
        }

        ClusterCommands::CertInit {
            nodes,
            output_dir,
            ca_validity_days,
            node_validity_days,
        } => {
            run_cert_init(&nodes, &output_dir, ca_validity_days, node_validity_days)?;
        }
    }

    Ok(())
}

/// Generate cluster CA and per-node certificates and write them to `output_dir`.
fn run_cert_init(nodes: &str, output_dir: &str, ca_validity_days: u32, node_validity_days: u32) -> anyhow::Result<()> {
    use std::fs;
    use std::path::Path;

    use waf_cluster::crypto::ca::CertificateAuthority;
    use waf_cluster::crypto::node_cert::NodeCertificate;

    let output = Path::new(output_dir);
    fs::create_dir_all(output).map_err(|e| anyhow::anyhow!("failed to create output directory '{output_dir}': {e}"))?;

    // Generate cluster CA.
    let ca = CertificateAuthority::generate(ca_validity_days)
        .map_err(|e| anyhow::anyhow!("failed to generate cluster CA: {e}"))?;

    let ca_cert_path = output.join("cluster-ca.pem");
    let ca_key_path = output.join("cluster-ca.key");
    fs::write(&ca_cert_path, ca.cert_pem())
        .map_err(|e| anyhow::anyhow!("failed to write CA cert to '{}': {e}", ca_cert_path.display()))?;
    fs::write(&ca_key_path, ca.key_pem())
        .map_err(|e| anyhow::anyhow!("failed to write CA key to '{}': {e}", ca_key_path.display()))?;

    println!("Generated cluster CA:");
    println!("  Cert: {}", ca_cert_path.display());
    println!("  Key:  {} (keep this secret)", ca_key_path.display());
    println!();

    // Generate per-node certificates.
    let node_names: Vec<&str> = nodes.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if node_names.is_empty() {
        anyhow::bail!("--nodes must contain at least one node name");
    }

    for node_name in &node_names {
        let node_cert = NodeCertificate::generate(node_name, &ca, node_validity_days)
            .map_err(|e| anyhow::anyhow!("failed to generate certificate for node '{node_name}': {e}"))?;

        let cert_path = output.join(format!("{node_name}.pem"));
        let key_path = output.join(format!("{node_name}.key"));
        fs::write(&cert_path, &node_cert.cert_pem)
            .map_err(|e| anyhow::anyhow!("failed to write cert for '{node_name}': {e}"))?;
        fs::write(&key_path, &node_cert.key_pem)
            .map_err(|e| anyhow::anyhow!("failed to write key for '{node_name}': {e}"))?;

        println!("  Node '{node_name}':");
        println!("    Cert: {}", cert_path.display());
        println!("    Key:  {}", key_path.display());
    }

    println!();
    println!("Certificates generated for nodes: {}", node_names.join(", "));
    println!("Distribute 'cluster-ca.pem' to all nodes (read-only mount).");
    println!("Each node loads its own cert/key pair from the output directory.");
    println!("The CA key 'cluster-ca.key' is only needed on the main node.");

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len - 1])
    }
}

// ── Community commands ────────────────────────────────────────────────────────

async fn run_community_cmd(cmd: CommunityCommands, config: &AppConfig) -> anyhow::Result<()> {
    match cmd {
        CommunityCommands::Status => {
            println!("Community Threat Intelligence Status");
            println!("====================================");
            println!("  Enabled:    {}", config.community.enabled);
            println!("  Server URL: {}", config.community.server_url);
            println!(
                "  Machine ID: {}",
                config.community.machine_id.as_deref().unwrap_or("(not enrolled)")
            );
            println!(
                "  API Key:    {}",
                if config.community.api_key.is_some() {
                    "(configured)"
                } else {
                    "(not set)"
                }
            );
            println!("  Batch size: {}", config.community.batch_size);
            println!("  Flush interval: {}s", config.community.flush_interval_secs);
            println!("  Sync interval:  {}s", config.community.sync_interval_secs);
            if !config.community.enabled {
                println!();
                println!("  [INFO] Community sharing is disabled. Enable it in configs/default.toml.");
            }
        }

        CommunityCommands::Enroll => {
            println!(
                "Enrolling machine with community server: {}",
                config.community.server_url
            );
            let client = waf_engine::CommunityClient::new(&config.community.server_url)?;
            match waf_engine::community::enroll::enroll_machine(&client).await {
                Ok(resp) => {
                    println!();
                    println!("Enrollment successful!");
                    println!("  Machine ID: {}", resp.machine_id);
                    println!("  API Key:    {}", resp.api_key);
                    if let Some(cred) = resp.enrollment_credential {
                        println!("  Credential: {cred}");
                    }
                    println!();
                    println!("Add to your configs/default.toml:");
                    println!();
                    println!("[community]");
                    println!("enabled = true");
                    println!("server_url = \"{}\"", config.community.server_url);
                    println!("machine_id = \"{}\"", resp.machine_id);
                    println!("api_key = \"{}\"", resp.api_key);
                }
                Err(e) => {
                    eprintln!("Enrollment failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        CommunityCommands::Test => {
            println!("Testing connection to: {}", config.community.server_url);
            let client = waf_engine::CommunityClient::new(&config.community.server_url)?;
            let api_key_ref = config.community.api_key.as_deref();
            match client.test_connection(api_key_ref).await {
                Ok(msg) => println!("OK: {msg}"),
                Err(e) => println!("FAILED: {e}"),
            }
        }
    }

    Ok(())
}

// ── Existing implementations (unchanged) ─────────────────────────────────────

async fn run_migrate(config: &AppConfig) -> anyhow::Result<()> {
    info!("Running database migrations...");
    let db = Database::connect(&config.storage.database_url, config.storage.max_connections).await?;
    db.migrate().await?;
    info!("Migrations complete.");
    Ok(())
}

async fn run_seed_admin(config: &AppConfig) -> anyhow::Result<()> {
    info!("Connecting to database...");
    let db = Arc::new(Database::connect(&config.storage.database_url, config.storage.max_connections).await?);
    db.migrate().await?;

    let engine = Arc::new(WafEngine::new(Arc::clone(&db), WafEngineConfig::default()));
    let router = Arc::new(HostRouter::new());
    let state = Arc::new(AppState::new(
        Arc::clone(&db),
        engine,
        router,
        gateway::ResponseCache::new(256, 60, 3600),
    )?);

    waf_api::auth::ensure_default_admin(&state).await?;
    info!("Default admin user seeded (username=admin, password=admin). Change it immediately!");
    Ok(())
}

/// Handle `CrowdSec` CLI sub-commands
async fn run_crowdsec_cmd(cmd: CrowdSecCommands, config: &AppConfig) -> anyhow::Result<()> {
    let cs_config = app_config_to_crowdsec(config);

    match cmd {
        CrowdSecCommands::Status => {
            println!("CrowdSec Integration Status");
            println!("  Enabled : {}", cs_config.enabled);
            println!("  Mode    : {:?}", cs_config.mode);
            println!("  LAPI URL: {}", cs_config.lapi_url);
            if !cs_config.enabled {
                println!("\n  [INFO] CrowdSec is disabled. Enable it in configs/default.toml.");
            }
        }

        CrowdSecCommands::Decisions => {
            if !cs_config.enabled {
                println!("CrowdSec is not enabled.");
                return Ok(());
            }
            let client = CrowdSecClient::new(cs_config.lapi_url.clone(), cs_config.api_key.clone())?;
            let stream = client.get_decisions_stream(true).await?;
            let decisions = stream.new.unwrap_or_default();
            println!("Active decisions ({}):", decisions.len());
            println!(
                "{:<18} {:<12} {:<40} {:<12} Duration",
                "Value", "Type", "Scenario", "Origin"
            );
            println!("{}", "-".repeat(100));
            for d in &decisions {
                println!(
                    "{:<18} {:<12} {:<40} {:<12} {}",
                    d.value,
                    d.type_,
                    d.scenario,
                    d.origin,
                    d.duration.as_deref().unwrap_or("-"),
                );
            }
        }

        CrowdSecCommands::Test => {
            if cs_config.api_key.is_empty() {
                println!("ERROR: No API key configured. Check your config file.");
                return Ok(());
            }
            println!("Testing connection to: {}", cs_config.lapi_url);
            let client = CrowdSecClient::new(cs_config.lapi_url.clone(), cs_config.api_key.clone())?;
            match client.test_connection().await {
                Ok(msg) => println!("OK: {msg}"),
                Err(e) => println!("FAILED: {e}"),
            }
        }

        CrowdSecCommands::Setup => {
            println!("CrowdSec Setup Wizard");
            println!("=====================");
            println!();

            #[cfg(target_os = "linux")]
            {
                println!("Detected platform: Linux");
                let lapi_cfg = std::path::Path::new("/etc/crowdsec/local_api_credentials.yaml");
                if lapi_cfg.exists() {
                    println!("Found CrowdSec LAPI credentials at: {}", lapi_cfg.display());
                } else {
                    println!("CrowdSec config not found. Install CrowdSec first:");
                    println!("  curl -s https://install.crowdsec.net | sudo sh");
                }
                println!();
                println!("To create a bouncer API key:");
                println!("  sudo cscli bouncers add prx-waf-bouncer");
                println!();
            }
            #[cfg(target_os = "windows")]
            {
                println!("Detected platform: Windows");
                println!("CrowdSec for Windows: https://docs.crowdsec.net/docs/getting_started/install_windows/");
                println!();
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            {
                println!("Detected platform: Unix/macOS (Docker recommended)");
                println!("  docker run -d crowdsecurity/crowdsec");
                println!();
            }

            println!("Add to your configs/default.toml:");
            println!();
            println!("[crowdsec]");
            println!("enabled = true");
            println!("mode = \"bouncer\"          # bouncer | appsec | both");
            println!("lapi_url = \"http://127.0.0.1:8080\"");
            println!("api_key = \"<paste your bouncer key here>\"");
            println!("update_frequency_secs = 10");
            println!("fallback_action = \"allow\"  # allow | block | log");
        }
    }

    Ok(())
}

/// Convert the flat `AppConfig` `CrowdSecConfig` to the engine's `CrowdSecConfig` type.
fn app_config_to_crowdsec(config: &AppConfig) -> CrowdSecConfig {
    use waf_engine::crowdsec::config::{AppSecConfig, CrowdSecMode, FallbackAction, PusherConfig};

    let mode = match config.crowdsec.mode.as_str() {
        "appsec" => CrowdSecMode::Appsec,
        "both" => CrowdSecMode::Both,
        _ => CrowdSecMode::Bouncer,
    };

    let fallback = match config.crowdsec.fallback_action.as_str() {
        "block" => FallbackAction::Block,
        "log" => FallbackAction::Log,
        _ => FallbackAction::Allow,
    };

    let appsec = config.crowdsec.appsec_endpoint.as_ref().map(|endpoint| AppSecConfig {
        endpoint: endpoint.clone(),
        api_key: config.crowdsec.appsec_key.clone().unwrap_or_default(),
        timeout_ms: config.crowdsec.appsec_timeout_ms,
        failure_action: FallbackAction::Allow,
    });

    let pusher = config
        .crowdsec
        .pusher_login
        .as_ref()
        .zip(config.crowdsec.pusher_password.as_ref())
        .map(|(login, password)| PusherConfig {
            login: login.clone(),
            password: password.clone(),
        });

    CrowdSecConfig {
        enabled: config.crowdsec.enabled,
        mode,
        lapi_url: config.crowdsec.lapi_url.clone(),
        api_key: config.crowdsec.api_key.clone(),
        update_frequency_secs: config.crowdsec.update_frequency_secs,
        cache_ttl_secs: config.crowdsec.cache_ttl_secs,
        fallback_action: fallback,
        scenarios_containing: config.crowdsec.scenarios_containing.clone(),
        scenarios_not_containing: config.crowdsec.scenarios_not_containing.clone(),
        appsec,
        pusher,
    }
}

/// Start the full server: async init → API server thread → Pingora proxy
fn run_server(config: &AppConfig, config_file_path: &str, vlogs_layer_slot: LayerSlot) -> anyhow::Result<()> {
    use pingora_core::server::Server;

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    // Build the cluster node BEFORE init_async so its NodeState can be plugged
    // into AppState while we still own a mutable handle to it. The actual
    // cluster runtime is spawned later (after the API server is up).
    let cluster_node = if let Some(cluster_cfg) = config.cluster.clone() {
        if cluster_cfg.enabled {
            match waf_cluster::ClusterNode::new(cluster_cfg) {
                Ok(node) => Some(node),
                Err(e) => {
                    tracing::error!("Failed to create cluster node: {e}");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    let cluster_state_for_api = cluster_node.as_ref().map(waf_cluster::ClusterNode::state);

    let panel_config_path = resolve_panel_config_path(config_file_path, config.panel.config_path.as_deref());

    // `_shutdown_guards` holds the watch senders that signal background workers
    // to stop.  They are dropped automatically when `run_server` returns (after
    // `server.run_forever()` exits), which sends the shutdown signal.
    //
    // `vlogs_sidecar` is `Some` when `[victoria_logs] enabled = true`. It is
    // shut down explicitly after the proxy stops so the child gets SIGTERM
    // (with a 5 s grace period) while the runtime is still alive — Drop alone
    // can only fire SIGKILL.
    let (engine, router, api_state, _shutdown_guards, vlogs_sidecar) = rt.block_on(init_async(
        config,
        config_file_path,
        cluster_state_for_api,
        panel_config_path,
        vlogs_layer_slot,
    ))?;

    // Start the management API in a background thread
    let api_listen = config.api.listen_addr.clone();
    let api_state_bg = Arc::clone(&api_state);
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!("Failed to build API runtime: {e}");
                return;
            }
        };
        rt.block_on(async move {
            if let Err(e) = start_api_server(&api_listen, api_state_bg).await {
                tracing::error!("API server error: {}", e);
            }
        });
    });

    // Per-protocol counters (AC-22). Constructed once and shared across the
    // Pingora proxy (H1/H2/WS) and the QUIC listener (H3) so a single struct
    // accounts for every accepted request regardless of protocol.
    let proto_counters = gateway::ProtoCounters::new();

    // Optionally start HTTP/3 listener
    if config.http3.enabled {
        let h3_config = config.http3.clone();
        let h3_engine = Arc::clone(&engine);
        let h3_router = Arc::clone(&router);
        let h3_counters = Arc::clone(&proto_counters);
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("Failed to build HTTP/3 runtime: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                let cert_pem = if let Some(p) = h3_config.cert_pem.as_deref() {
                    match std::fs::read_to_string(p) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("HTTP/3 cert read error: {e}");
                            return;
                        }
                    }
                } else {
                    tracing::error!("HTTP/3 cert_pem not configured");
                    return;
                };
                let key_pem = if let Some(p) = h3_config.key_pem.as_deref() {
                    match std::fs::read_to_string(p) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("HTTP/3 key read error: {e}");
                            return;
                        }
                    }
                } else {
                    tracing::error!("HTTP/3 key_pem not configured");
                    return;
                };
                let addr: std::net::SocketAddr = match h3_config.listen_addr.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!("HTTP/3 listen_addr parse error: {e}");
                        return;
                    }
                };
                if let Err(e) = gateway::http3::start_http3_server(
                    addr,
                    cert_pem,
                    key_pem,
                    "http://127.0.0.1:8080".to_string(),
                    h3_config.upstream_tls_verify,
                    Arc::clone(&h3_engine),
                    Arc::clone(&h3_router),
                    Arc::clone(&h3_counters),
                )
                .await
                {
                    tracing::error!("HTTP/3 server error: {e}");
                }
            });
        });
    }

    // Spawn the cluster node we built earlier (its NodeState is already wired
    // into AppState above).
    if let Some(node) = cluster_node {
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("Failed to build cluster runtime: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                if let Err(e) = node.run().await {
                    tracing::error!("Cluster node error: {e}");
                }
            });
        });
    }

    // Build and run Pingora proxy (blocks forever)
    let mut server = Server::new(None)?;
    server.bootstrap();

    let mut proxy = WafProxy::new(router, engine);
    // Share counters with AppState so the /api/stats/overview endpoint reflects live traffic
    proxy.request_counter = Arc::clone(&api_state.request_counter);
    proxy.blocked_counter = Arc::clone(&api_state.blocked_counter);
    // AC-22: same per-protocol counter struct as the H3 listener.
    proxy.proto_counters = Arc::clone(&proto_counters);
    proxy.trust_proxy_headers = config.proxy.trust_proxy_headers;
    proxy.trusted_proxies = config
        .proxy
        .trusted_proxies
        .iter()
        .filter_map(|s| match s.parse::<ipnet::IpNet>() {
            Ok(net) => Some(net),
            Err(e) => {
                tracing::warn!("Ignoring invalid trusted_proxies entry '{}': {}", s, e);
                None
            }
        })
        .collect();

    proxy.response_cache = Some(Arc::clone(&api_state.cache));

    let cache_for_timeseries = Arc::clone(&api_state.cache);
    rt.spawn(async move {
        use tokio::time::MissedTickBehavior;
        #[allow(clippy::duration_suboptimal_units)] // `from_secs(60)` — stable MSRV parity
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            cache_for_timeseries.tick_timeseries().await;
        }
    });

    // Warn when XFF trust is enabled but no trusted proxy CIDRs are configured,
    // meaning XFF headers from ANY source will be honoured (fail-open).
    if proxy.trust_proxy_headers && proxy.trusted_proxies.is_empty() {
        tracing::warn!(
            "trust_proxy_headers is enabled but trusted_proxies is empty — \
             XFF headers from ANY source will be trusted. \
             Consider adding trusted proxy CIDRs for production use."
        );
    }

    let mut proxy_service = pingora_proxy::http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&config.proxy.listen_addr);
    server.add_service(proxy_service);

    info!("Proxy listening on {}", config.proxy.listen_addr);
    // AC-22 / phase-05: the Pingora HTTP service shares a single ALPN-aware
    // listener for H1+H2 when TLS is configured (`add_tls_with_settings`).
    // The `add_tcp` path used here is plaintext, so h2 is only reachable via
    // h2c prior-knowledge; h2-over-TLS depends on an upstream listener
    // wrapper that advertises `h2,http/1.1`. Logged here to make the
    // protocol surface visible at startup.
    info!("ALPN: H1/H2 served via shared Pingora listener (plaintext H1 + h2c)");
    info!("Management API listening on {}", config.api.listen_addr);
    if config.http3.enabled {
        info!("HTTP/3 (QUIC) listener on {}", config.http3.listen_addr);
    }
    info!("Press Ctrl+C to stop");

    // The VictoriaLogs supervisor listens for SIGTERM/SIGINT on its own and
    // performs graceful shutdown directly. Pingora's `run_forever` returns
    // `!` (calls `std::process::exit(0)`), so any cleanup we'd write here
    // would be unreachable. Hand the handle to a `Box::leak` so the
    // supervisor task can react to signals for the duration of the
    // process; pingora's exit terminates everything in lock-step at the
    // end. Using leak (rather than a `_` binding) sidesteps the
    // `no_effect_underscore_binding` clippy lint since the side effect is
    // intentional.
    if let Some(sidecar) = vlogs_sidecar {
        Box::leak(Box::new(sidecar));
    }

    server.run_forever();
}

/// Shutdown guards that keep background-task sender halves alive.
///
/// Each field is a `tokio::sync::watch::Sender<bool>`.  Dropping this struct
/// closes the watch channel, which signals background workers to exit via
/// `changed().is_err()`.
struct ShutdownGuards {
    /// Keeps the `CrowdSec` background worker alive while the server runs.
    _crowdsec: Option<tokio::sync::watch::Sender<bool>>,
    /// Keeps the Community background worker alive while the server runs.
    _community: Option<tokio::sync::watch::Sender<bool>>,
    /// FR-009: `CacheRuleWatcher` must not be dropped while serving.
    _cache_rules_watcher: Option<gateway::cache::CacheRuleWatcher>,
    /// FR-009: embedded `valkey-server` child handle (opaque).
    _embedded_valkey: Option<Box<dyn Send + Sync + 'static>>,
}

fn resolve_panel_config_path(main_config_file: &str, configured: Option<&str>) -> Option<std::path::PathBuf> {
    let s = configured?.trim();
    if s.is_empty() {
        return None;
    }
    let p = std::path::Path::new(s);
    Some(if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::path::Path::new(main_config_file)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(p)
    })
}

/// Async initialization: database, engine, rules, Phases 5 & 6
async fn init_async(
    config: &AppConfig,
    config_file_path: &str,
    cluster_state: Option<Arc<waf_cluster::NodeState>>,
    panel_config_path: Option<std::path::PathBuf>,
    vlogs_layer_slot: LayerSlot,
) -> anyhow::Result<(
    Arc<WafEngine>,
    Arc<HostRouter>,
    Arc<AppState>,
    ShutdownGuards,
    Option<victoria_logs::VictoriaLogsSidecar>,
)> {
    // ── VictoriaLogs sidecar (Phase 1) ───────────────────────────────────────
    // Install the binary (no-op when disabled or already present) and spawn
    // the child *before* anything else so log forwarding is in place by the
    // time the rest of init starts emitting `tracing` events. A spawn failure
    // is fail-fast: if the operator opted into VictoriaLogs we refuse to
    // start without it rather than silently degrade.
    victoria_logs::ensure_binary(&config.victoria_logs).await?;
    let vlogs_sidecar = victoria_logs::VictoriaLogsSidecar::spawn(&config.victoria_logs).await?;

    info!("Connecting to database...");
    let db = Arc::new(Database::connect(&config.storage.database_url, config.storage.max_connections).await?);

    info!("Running database migrations...");
    db.migrate().await?;

    if let Some(ref path) = panel_config_path
        && !path.exists()
    {
        use waf_common::panel_config::WafPanelConfig;
        let default = WafPanelConfig::default();
        let s = default
            .to_toml_string()
            .map_err(|e| anyhow::anyhow!("panel config serialize: {e}"))?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(path, s.as_bytes()).await?;
        info!("Created default panel config at {}", path.display());
    }

    // WAF engine
    let engine = Arc::new(WafEngine::new(Arc::clone(&db), WafEngineConfig::default()));
    engine.set_rules_dir(std::path::PathBuf::from(&config.rules.dir));
    engine.reload_rules().await?;
    engine.start_file_watcher();

    // FR-004 rate-limit subsystem: load YAML and start hot-reload watcher.
    // Absent path leaves the subsystem inert (default empty config).
    if let Some(rl_path) = config.rate_limit.config_path.as_deref() {
        engine.start_rate_limit_watcher(std::path::Path::new(rl_path));
    }

    // ── Phase 02: VictoriaLogs logging pipeline ──────────────────────────────
    // Two independent batch flushers (tracing + audit) sharing the same
    // ingest URL. The tracing slot is filled lazily here; the audit sender
    // is plugged into the engine. Both are no-ops when VictoriaLogs is
    // disabled, keeping the feature opt-in and zero-cost.
    if config.victoria_logs.enabled {
        let ingest_url = config.victoria_logs.ingest_url();

        let tracing_sender = spawn_batch_flusher(BatchConfig::for_tracing(
            ingest_url.clone(),
            config.victoria_logs.batch_size,
            config.victoria_logs.flush_interval_ms,
            config.victoria_logs.channel_capacity,
        ));
        // The tracing layer was registered at process start with an empty
        // slot; this fills it.  Subsequent `tracing::*!` calls (anywhere
        // in the workspace) flow into VictoriaLogs from now on.
        if vlogs_layer_slot.set(tracing_sender).is_err() {
            tracing::warn!("VictoriaLogs tracing slot already filled — ignoring duplicate init");
        }

        let audit_sender = spawn_batch_flusher(BatchConfig::for_audit(
            ingest_url,
            config.victoria_logs.batch_size,
            config.victoria_logs.flush_interval_ms,
            config.victoria_logs.channel_capacity,
        ));
        engine.set_audit_sender(Arc::new(AuditSender::new(audit_sender)));

        info!("VictoriaLogs logging pipeline active");
    } else {
        // Drop the slot so nothing holds the unused `Arc` longer than needed.
        drop(vlogs_layer_slot);
    }

    // GeoIP service
    if config.geoip.enabled {
        let policy = cache_policy_from_str(&config.geoip.cache_policy);
        match GeoIpService::init(&config.geoip.ipv4_xdb_path, &config.geoip.ipv6_xdb_path, policy) {
            Ok(service) => {
                info!("GeoIP service initialized");
                let service = Arc::new(service);
                engine.set_geoip(Arc::clone(&service));

                // Spawn background auto-updater if enabled.
                if config.geoip.auto_update.enabled {
                    let data_dir = std::path::PathBuf::from(&config.geoip.ipv4_xdb_path)
                        .parent()
                        .map_or_else(|| std::path::PathBuf::from("data"), std::path::Path::to_path_buf);

                    let handle = spawn_auto_updater(Arc::clone(&service), config.geoip.auto_update.clone(), data_dir);
                    // Keep the task alive for the process lifetime.
                    std::mem::forget(handle);

                    info!(
                        "GeoIP auto-updater spawned (interval: {})",
                        config.geoip.auto_update.interval
                    );
                }
            }
            Err(e) => {
                tracing::warn!("Failed to initialize GeoIP service: {}", e);
            }
        }
    }

    // Host router
    let router = Arc::new(HostRouter::new());

    // Load hosts from database
    let hosts = db.list_hosts().await?;
    info!("Loading {} hosts from database", hosts.len());
    for host in &hosts {
        use waf_common::HostConfig;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let cfg = Arc::new(HostConfig {
            code: host.code.clone(),
            host: host.host.clone(),
            port: host.port as u16,
            ssl: host.ssl,
            guard_status: host.guard_status,
            remote_host: host.remote_host.clone(),
            remote_port: host.remote_port as u16,
            remote_ip: host.remote_ip.clone(),
            cert_file: host.cert_file.clone(),
            key_file: host.key_file.clone(),
            start_status: host.start_status,
            ..HostConfig::default()
        });
        router.register(&cfg);
    }

    // Register hosts from config file
    for entry in &config.hosts {
        use waf_common::{DefenseConfig, HostConfig};
        let code = format!("cfg-{}", &uuid::Uuid::new_v4().to_string().replace('-', "")[..8]);
        // Per-host defense profile. Defaults to "WAF on" baseline for
        // TOML-declared hosts (OWASP CRS enabled, scripted-client blocking
        // off). Both flags are overridable per host via the [[hosts]] table.
        let defense_config = DefenseConfig {
            owasp_set: entry.owasp_set.unwrap_or(true),
            block_scripted_clients: entry.block_scripted_clients.unwrap_or(false),
            ..DefenseConfig::default()
        };
        let cfg = Arc::new(HostConfig {
            code,
            host: entry.host.clone(),
            port: entry.port,
            ssl: entry.ssl.unwrap_or(false),
            guard_status: entry.guard_status.unwrap_or(true),
            remote_host: entry.remote_host.clone(),
            remote_port: entry.remote_port,
            cert_file: entry.cert_file.clone(),
            key_file: entry.key_file.clone(),
            defense_config,
            ..HostConfig::default()
        });
        router.register(&cfg);
    }

    info!("Registered {} host routes", router.len());

    let gateway::cache::CacheInit {
        cache,
        rules_watcher,
        embedded_supervisor,
    } = gateway::cache::init_response_cache(&config.cache).await?;

    // Build app state
    let mut api_state = AppState::new(
        Arc::clone(&db),
        Arc::clone(&engine),
        Arc::clone(&router),
        Arc::clone(&cache),
    )?;

    // Plug the cluster's NodeState into AppState so /api/cluster/status,
    // /api/cluster/nodes etc. can read role / term / peers. Without this the
    // API's cluster_state stays None and every /api/cluster/* route returns
    // 404 "cluster not enabled" — the smoking gun we observed on the e2e run.
    api_state.cluster_state = cluster_state;

    // Apply security configuration
    api_state.cors_origins = config.security.cors_origins.clone();
    api_state.security_config = config.security.clone();
    if config.security.api_rate_limit_rps > 0 {
        api_state.rate_limiter = Some(waf_api::security::ApiRateLimiter::new(
            config.security.api_rate_limit_rps,
        ));
    }

    // Login rate limiter: always enabled with a strict 10 req/s burst
    // to mitigate brute-force credential attacks on /api/auth/login
    api_state.login_rate_limiter = Some(waf_api::security::ApiRateLimiter::new(10));
    api_state.panel_config_path = panel_config_path;
    api_state.main_config_file = Some(config_file_path.to_string());

    // Phase 03: expose the VictoriaLogs base URL to the API layer so the
    // logs proxy endpoints know where to forward.  Stays `None` when the
    // sidecar is disabled; the handlers then return 503 with a clear message.
    if config.victoria_logs.enabled {
        api_state.victoria_logs_base_url = Some(config.victoria_logs.base_url());
    }

    // Phase 4: create default admin user if none exist
    {
        let tmp_state = Arc::new(api_state.clone());
        if let Err(e) = waf_api::auth::ensure_default_admin(&tmp_state).await {
            tracing::warn!("Could not ensure default admin: {e}");
        }
    }

    // Phase 5: load WASM plugins from DB
    let plugins = db.list_wasm_plugins().await.unwrap_or_default();
    info!("Loading {} WASM plugins", plugins.len());
    for p in &plugins {
        if let Err(e) = api_state
            .plugin_manager
            .load(waf_engine::plugins::manager::LoadPluginParams {
                id: p.id,
                name: p.name.clone(),
                version: p.version.clone(),
                description: p.description.clone().unwrap_or_default(),
                author: p.author.clone().unwrap_or_default(),
                enabled: p.enabled,
                wasm_bytes: &p.wasm_binary,
            })
            .await
        {
            tracing::warn!(plugin = %p.name, "Failed to load plugin: {e}");
        }
    }

    // Phase 5: load tunnel configs from DB
    let tunnels = db.list_tunnels().await.unwrap_or_default();
    info!("Loaded {} tunnel configs", tunnels.len());
    for t in &tunnels {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let tunnel_cfg = TunnelConfig {
            id: t.id,
            name: t.name.clone(),
            token_hash: t.token_hash.clone(),
            target_host: t.target_host.clone(),
            target_port: t.target_port as u16,
            enabled: t.enabled,
        };
        api_state.tunnel_registry.register(tunnel_cfg).await;
    }

    // Phase 6: CrowdSec integration
    let cs_config = app_config_to_crowdsec(config);
    let crowdsec_shutdown_guard = if cs_config.enabled {
        // Create a channel for graceful shutdown signal.
        // The sender is returned to the caller so it lives until the server
        // exits; dropping it signals the background worker to shut down.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        if let Some(components) = init_crowdsec(cs_config.clone(), shutdown_rx).await {
            info!(
                lapi_url = %cs_config.lapi_url,
                "CrowdSec integration active"
            );

            // Plug bouncer checker and AppSec client into the WAF engine
            engine.set_crowdsec(Arc::clone(&components.checker), components.appsec_client.clone());

            // Share cache and client with the API layer
            api_state.crowdsec_cache = Some(Arc::clone(&components.cache));
            api_state.crowdsec_client = Some(Arc::clone(&components.lapi_client));
            api_state.crowdsec_lapi_url = Some(cs_config.lapi_url.clone());

            // Keep the background task alive by holding its join handle inside
            // the components struct.  The sender is passed back to the caller.
            std::mem::forget(components);
            Some(shutdown_tx)
        } else {
            tracing::warn!("CrowdSec enabled in config but failed to initialise");
            None
        }
    } else {
        None
    };

    // Phase 8: Community threat intelligence sharing
    let community_shutdown_guard = if config.community.enabled {
        let community_config = waf_engine::community::config::CommunityConfig {
            enabled: config.community.enabled,
            server_url: config.community.server_url.clone(),
            api_key: config.community.api_key.clone(),
            machine_id: config.community.machine_id.clone(),
            public_key: config.community.public_key.clone(),
            batch_size: config.community.batch_size,
            flush_interval_secs: config.community.flush_interval_secs,
            sync_interval_secs: config.community.sync_interval_secs,
        };

        // Create a shutdown channel for community tasks.
        // The sender is returned to the caller so it lives until the server
        // exits; dropping it signals the community worker to shut down.
        let (community_shutdown_tx, community_shutdown_rx) = tokio::sync::watch::channel(false);

        if let Some(components) = init_community(community_config, community_shutdown_rx).await {
            info!(
                server_url = %config.community.server_url,
                "Community threat intelligence active"
            );

            // Plug community checker into the WAF engine
            engine.set_community(Arc::clone(&components.checker));

            // Plug community reporter into the WAF engine so detections
            // are automatically pushed to the community platform
            engine.set_community_reporter(Arc::clone(&components.reporter));

            // Share reporter with the API state for potential future use
            api_state.community_reporter = Some(Arc::clone(&components.reporter));

            // Keep background task join handles alive; sender is passed back.
            std::mem::forget(components);
            Some(community_shutdown_tx)
        } else {
            tracing::warn!("Community sharing enabled in config but failed to initialise");
            None
        }
    } else {
        None
    };

    let guards = ShutdownGuards {
        _crowdsec: crowdsec_shutdown_guard,
        _community: community_shutdown_guard,
        _cache_rules_watcher: rules_watcher,
        _embedded_valkey: embedded_supervisor,
    };

    Ok((engine, router, Arc::new(api_state), guards, vlogs_sidecar))
}
