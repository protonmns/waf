//! FR-005 phase-01 — YAML schema + parser for `configs/ddos.yaml`.
//!
//! Pure data + validation, returns an `Arc<DdosConfig>` runtime snapshot.
//! `deny_unknown_fields` everywhere — typos in operator YAML are loud, not
//! silent. Mirrors `rate_limit::config`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use serde::Deserialize;

use waf_common::tier::Tier;

use super::{DdosConfig, DdosTierCfg};

const SCHEMA_VERSION: u32 = 1;

/// Top-level YAML wrapper: `ddos:` is the single root key.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DdosDocument {
    #[serde(default)]
    pub ddos: DdosFileConfig,
}

/// Operator-facing YAML schema for `DDoS` configuration.
///
/// Empty file ⇒ inert (no tiers protected).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DdosFileConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_hot_reload")]
    pub hot_reload: bool,
    /// Per-tier threshold configurations. Tiers omitted from the map are not
    /// DDoS-protected (the check skips them).
    #[serde(default)]
    pub tiers: DdosTierMap,
    /// GC interval in seconds for counter cleanup.
    #[serde(default = "default_gc_interval_s")]
    pub gc_interval_s: u32,
    /// Maximum keys before LRU eviction in GC pass.
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,
    /// Optional Redis backend. Absence ⇒ memory-only standalone mode.
    /// Parsed but unused until phase 4.
    #[serde(default)]
    pub redis: Option<RedisCfg>,
}

impl Default for DdosFileConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            enabled: false,
            hot_reload: default_hot_reload(),
            tiers: DdosTierMap::default(),
            gc_interval_s: default_gc_interval_s(),
            max_keys: default_max_keys(),
            redis: None,
        }
    }
}

const fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}
const fn default_hot_reload() -> bool {
    true
}
const fn default_gc_interval_s() -> u32 {
    60
}
const fn default_max_keys() -> usize {
    100_000
}

/// Tier map keyed by `snake_case` names matching `Tier` variants.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DdosTierMap {
    #[serde(default)]
    pub critical: Option<TierThresholdCfg>,
    #[serde(default)]
    pub high: Option<TierThresholdCfg>,
    #[serde(default)]
    pub medium: Option<TierThresholdCfg>,
    #[serde(default)]
    pub catch_all: Option<TierThresholdCfg>,
}

/// One tier's `DDoS` threshold knobs.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierThresholdCfg {
    /// Per-fingerprint request threshold (e.g., per-IP).
    pub per_fp_threshold: u32,
    /// Window in seconds for per-fingerprint threshold.
    pub per_fp_window_s: u32,
    /// Aggregate tier-wide request threshold.
    pub per_tier_threshold: u32,
    /// Window in seconds for tier-wide threshold.
    pub per_tier_window_s: u32,
}

/// Optional Redis backend block (parsed but unused until phase 4).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisCfg {
    pub url: String,
    #[serde(default = "default_redis_prefix")]
    pub key_prefix: String,
    #[serde(default = "default_op_timeout_ms")]
    pub op_timeout_ms: u64,
}

fn default_redis_prefix() -> String {
    "wafddos:".to_string()
}
const fn default_op_timeout_ms() -> u64 {
    50
}

impl DdosFileConfig {
    /// Parse from raw YAML text → validated runtime snapshot.
    pub fn from_yaml_str(s: &str) -> anyhow::Result<Arc<DdosConfig>> {
        let doc: DdosDocument = serde_yaml::from_str(s).context("ddos: parse YAML")?;
        let cfg = doc.ddos;
        cfg.validate()?;
        Ok(Arc::new(cfg.into_runtime()))
    }

    /// Parse from a file path.
    pub fn from_path(path: &Path) -> anyhow::Result<Arc<DdosConfig>> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("ddos: read {}", path.display()))?;
        Self::from_yaml_str(&raw)
    }

    /// Schema version + range checks.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            bail!(
                "ddos: unsupported schema_version {} (this build expects {})",
                self.schema_version,
                SCHEMA_VERSION
            );
        }
        if self.gc_interval_s == 0 {
            bail!("ddos: gc_interval_s must be > 0");
        }
        if self.max_keys == 0 {
            bail!("ddos: max_keys must be > 0");
        }
        for (name, t) in self.iter_tiers() {
            if t.per_fp_threshold == 0 {
                bail!("ddos.tiers.{name}: per_fp_threshold must be > 0");
            }
            if t.per_fp_window_s == 0 {
                bail!("ddos.tiers.{name}: per_fp_window_s must be > 0");
            }
            if t.per_tier_threshold == 0 {
                bail!("ddos.tiers.{name}: per_tier_threshold must be > 0");
            }
            if t.per_tier_window_s == 0 {
                bail!("ddos.tiers.{name}: per_tier_window_s must be > 0");
            }
        }
        if let Some(r) = &self.redis
            && r.url.is_empty()
        {
            bail!("ddos.redis.url must not be empty when redis block is present");
        }
        Ok(())
    }

    fn iter_tiers(&self) -> impl Iterator<Item = (&'static str, &TierThresholdCfg)> {
        [
            ("critical", self.tiers.critical.as_ref()),
            ("high", self.tiers.high.as_ref()),
            ("medium", self.tiers.medium.as_ref()),
            ("catch_all", self.tiers.catch_all.as_ref()),
        ]
        .into_iter()
        .filter_map(|(n, t)| t.map(|tc| (n, tc)))
    }

    /// Convert validated DTO → runtime `DdosConfig`.
    /// Disabled subsystem ⇒ empty tier map (check is inert).
    fn into_runtime(self) -> DdosConfig {
        let mut tiers: HashMap<Tier, DdosTierCfg> = HashMap::new();
        if self.enabled {
            if let Some(t) = self.tiers.critical {
                tiers.insert(Tier::Critical, t.into());
            }
            if let Some(t) = self.tiers.high {
                tiers.insert(Tier::High, t.into());
            }
            if let Some(t) = self.tiers.medium {
                tiers.insert(Tier::Medium, t.into());
            }
            if let Some(t) = self.tiers.catch_all {
                tiers.insert(Tier::CatchAll, t.into());
            }
        }
        DdosConfig {
            tiers,
            gc_interval_s: self.gc_interval_s,
            max_keys: self.max_keys,
        }
    }
}

impl From<TierThresholdCfg> for DdosTierCfg {
    fn from(t: TierThresholdCfg) -> Self {
        Self {
            per_fp_threshold: t.per_fp_threshold,
            per_fp_window_s: t.per_fp_window_s,
            per_tier_threshold: t.per_tier_threshold,
            per_tier_window_s: t.per_tier_window_s,
        }
    }
}

impl RedisCfg {
    /// Convert to operation timeout duration.
    #[must_use]
    pub const fn op_timeout(&self) -> Duration {
        Duration::from_millis(self.op_timeout_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_yaml_parses_inert() {
        let cfg = DdosFileConfig::from_yaml_str("").expect("empty parses");
        assert!(cfg.tiers.is_empty());
        assert_eq!(cfg.gc_interval_s, 60);
        assert_eq!(cfg.max_keys, 100_000);
    }

    #[test]
    fn full_yaml_round_trip() {
        let yaml = r#"
ddos:
  schema_version: 1
  enabled: true
  hot_reload: true
  gc_interval_s: 30
  max_keys: 50000
  tiers:
    critical:
      per_fp_threshold: 10
      per_fp_window_s: 60
      per_tier_threshold: 1000
      per_tier_window_s: 60
    catch_all:
      per_fp_threshold: 100
      per_fp_window_s: 60
      per_tier_threshold: 10000
      per_tier_window_s: 60
  redis:
    url: "redis://127.0.0.1:6379"
    key_prefix: "wafddos:"
    op_timeout_ms: 75
"#;
        let cfg = DdosFileConfig::from_yaml_str(yaml).expect("parses");
        assert_eq!(cfg.gc_interval_s, 30);
        assert_eq!(cfg.max_keys, 50000);
        let crit = cfg.for_tier(Tier::Critical).expect("critical");
        assert_eq!(crit.per_fp_threshold, 10);
        let ca = cfg.for_tier(Tier::CatchAll).expect("catch_all");
        assert_eq!(ca.per_tier_threshold, 10000);
        assert!(cfg.for_tier(Tier::High).is_none(), "high unconfigured");
    }

    #[test]
    fn redis_omitted_means_standalone() {
        let yaml = r"
ddos:
  enabled: true
  tiers:
    catch_all:
      per_fp_threshold: 100
      per_fp_window_s: 60
      per_tier_threshold: 5000
      per_tier_window_s: 60
";
        let cfg = DdosFileConfig::from_yaml_str(yaml).expect("parses");
        assert_eq!(cfg.tiers.len(), 1);
    }

    #[test]
    fn disabled_yields_empty_tiers() {
        let yaml = r"
ddos:
  enabled: false
  tiers:
    critical:
      per_fp_threshold: 10
      per_fp_window_s: 60
      per_tier_threshold: 1000
      per_tier_window_s: 60
";
        let cfg = DdosFileConfig::from_yaml_str(yaml).expect("parses");
        assert!(cfg.tiers.is_empty(), "enabled=false ⇒ inert config");
    }

    #[test]
    fn unknown_field_rejected() {
        let yaml = r"
ddos:
  enabled: true
  bogus_field: 42
";
        assert!(DdosFileConfig::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn schema_mismatch_rejected() {
        let yaml = r"
ddos:
  schema_version: 999
";
        let err = DdosFileConfig::from_yaml_str(yaml).unwrap_err().to_string();
        assert!(err.contains("schema_version"), "got: {err}");
    }

    #[test]
    fn zero_window_rejected() {
        let yaml = r"
ddos:
  enabled: true
  tiers:
    critical:
      per_fp_threshold: 10
      per_fp_window_s: 0
      per_tier_threshold: 1000
      per_tier_window_s: 60
";
        assert!(DdosFileConfig::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn zero_gc_interval_rejected() {
        let yaml = r"
ddos:
  enabled: true
  gc_interval_s: 0
";
        assert!(DdosFileConfig::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn zero_max_keys_rejected() {
        let yaml = r"
ddos:
  enabled: true
  max_keys: 0
";
        assert!(DdosFileConfig::from_yaml_str(yaml).is_err());
    }
}
