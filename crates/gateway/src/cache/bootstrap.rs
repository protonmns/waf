//! Wire [`ResponseCache`] from `[cache]` in `AppConfig` (memory / Valkey modes).

use std::sync::Arc;

use tracing::info;
use waf_common::config::{CacheBackendKind, CacheConfig};

use super::backend::CacheBackend;
use super::moka_store::MokaStore;
use super::rule_set::{CompiledRuleSet, RuleSetHolder};
use super::store::ResponseCache;
use super::watcher::{CacheRuleWatcher, DEFAULT_DEBOUNCE_MS, load_or_empty};

/// Result of [`init_response_cache`]: cache + handles that must stay alive.
pub struct CacheInit {
    pub cache: Arc<ResponseCache>,
    /// FR-009 Phase 3: hot-reload watcher for `rules_path`; `None` if unset.
    pub rules_watcher: Option<CacheRuleWatcher>,
    /// Keeps embedded `valkey-server` child alive when `backend = "embedded"`.
    pub embedded_supervisor: Option<Box<dyn Send + Sync + 'static>>,
}

/// Build [`ResponseCache`] from operator `[cache]` config.
pub async fn init_response_cache(cfg: &CacheConfig) -> anyhow::Result<CacheInit> {
    let rules = match &cfg.rules_path {
        Some(p) => load_or_empty(p.as_path())?,
        None => CompiledRuleSet::empty(),
    };
    let holder = Arc::new(RuleSetHolder::new(rules));
    let max = cfg.max_size_mb;
    let def = cfg.default_ttl_secs;
    let max_ttl = cfg.max_ttl_secs;

    let (backend, embedded_supervisor): (Arc<dyn CacheBackend>, Option<Box<dyn Send + Sync + 'static>>) = match cfg
        .backend
    {
        CacheBackendKind::Memory => {
            info!(backend = "memory", "response cache backend: in-process moka LRU");
            (Arc::new(MokaStore::new(max, max_ttl)), None)
        }
        #[cfg(feature = "valkey")]
        CacheBackendKind::Standalone | CacheBackendKind::Cluster => {
            let label = match cfg.backend {
                CacheBackendKind::Cluster => "cluster",
                _ => "standalone",
            };
            info!(backend = label, seeds = ?cfg.valkey.seeds, "response cache backend: Valkey");
            let fallback = Arc::new(MokaStore::new(max, max_ttl));
            let vk = Arc::new(super::valkey_store::ValkeyStore::connect(&cfg.valkey, max).await?);
            let b: Arc<dyn CacheBackend> = if cfg.valkey.fallback_to_memory {
                super::valkey_store::CircuitBreakerStore::new(vk, fallback, &cfg.valkey)
            } else {
                vk
            };
            (b, None)
        }
        #[cfg(feature = "valkey")]
        CacheBackendKind::Embedded => {
            info!(
                backend = "embedded",
                "response cache backend: valkey-server child process"
            );
            let supervisor = Arc::new(super::embedded_valkey::EmbeddedValkey::spawn(&cfg.embedded, max).await?);
            let mut vk_cfg = cfg.valkey.clone();
            vk_cfg.seeds = vec![supervisor.unix_socket_addr()];
            let fallback = Arc::new(MokaStore::new(max, max_ttl));
            let vk = Arc::new(super::valkey_store::ValkeyStore::connect(&vk_cfg, max).await?);
            let b: Arc<dyn CacheBackend> = if cfg.valkey.fallback_to_memory {
                super::valkey_store::CircuitBreakerStore::new(vk, fallback, &cfg.valkey)
            } else {
                vk
            };
            let hold: Option<Box<dyn Send + Sync + 'static>> = Some(Box::new(supervisor));
            (b, hold)
        }
        #[cfg(not(feature = "valkey"))]
        CacheBackendKind::Embedded | CacheBackendKind::Standalone | CacheBackendKind::Cluster => {
            anyhow::bail!(
                "cache backend {:?} requires building with `--features gateway/valkey` (or `valkey` on the prx-waf package)",
                cfg.backend
            );
        }
    };

    let cache = ResponseCache::with_backend(backend, max, def, max_ttl, Arc::clone(&holder));

    let rules_watcher = if let Some(path) = cfg.rules_path.as_ref() {
        info!(path = %path.display(), "watching cache rules YAML for hot reload");
        Some(CacheRuleWatcher::spawn(
            path.clone(),
            Arc::clone(&holder),
            DEFAULT_DEBOUNCE_MS,
        )?)
    } else {
        None
    };

    Ok(CacheInit {
        cache,
        rules_watcher,
        embedded_supervisor,
    })
}
