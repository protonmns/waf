//! Response-cache module.
//!
//! Public surface (re-exported by `crate::lib`):
//! - [`ResponseCache`] — facade (resolver pipeline + backend delegate)
//! - [`CachedResponse`] — stored HTTP response value
//! - [`CacheStatsSnapshot`] — read-only counter view
//! - [`CompiledRuleSet`] / [`RuleSetHolder`] — YAML-defined per-route rules
//! - [`CacheRuleWatcher`] — `rules/cache.yaml` hot-reloader
//! - [`BackendInfo`] / [`BackendHealth`] — backend status for dashboard
//!
//! Internal:
//! - [`backend`] — `CacheBackend` trait + shared types
//! - [`moka_store`] — in-process LRU backend (always compiled)
//! - [`valkey_store`] — Valkey/Redis backend (requires `valkey` feature)
//! - [`embedded_valkey`] — embedded Valkey child-process supervisor (`valkey` feature)
//! - [`policy`] — `Verdict`, `CacheGate` trait, `CachePolicyResolver`
//! - [`gates`] — concrete gate impls
//! - [`stats`] — atomic counters + timeseries ring buffer
//!
//! See [`policy`] for the Chain of Responsibility design rationale.

pub mod backend;
pub mod bootstrap;
pub mod config;
pub mod embedded_valkey;
pub mod gates;
pub mod moka_store;
pub mod policy;
pub mod rule;
pub mod rule_set;
pub mod stats;
pub mod store;
pub mod tag_index;
pub mod valkey_store;
pub mod watcher;

pub use backend::{BackendHealth, BackendInfo, CachedResponse};
pub use bootstrap::{CacheInit, init_response_cache};
pub use rule_set::{CompiledRuleSet, RuleSetError, RuleSetHolder};
pub use stats::{CacheStatsSnapshot, TimeseriesBucket};
pub use store::ResponseCache;
pub use watcher::{CacheRuleWatcher, CacheWatcherError, DEFAULT_DEBOUNCE_MS, load_or_empty, reload};
