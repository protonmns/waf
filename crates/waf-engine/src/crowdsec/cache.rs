#![allow(clippy::duration_suboptimal_units)] // prefer `from_secs` over MSRV‑gated `from_mins`/`from_hours`

/// When the operator sets `cache_ttl_secs = 0` and a decision has no usable
/// `duration` field, cached entries use this many seconds until expiry (4 hours).
pub const DEFAULT_DECISION_CACHE_FALLBACK_SECS: u64 = 4 * 3_600;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use dashmap::DashMap;
use ipnet::IpNet;

use super::config::CrowdSecConfig;
use super::models::{CacheStats, CachedDecision, Decision, DecisionStream};

/// In-memory decision cache with exact-IP and CIDR-range matching.
///
/// Thread-safe via `DashMap` (exact IPs), `RwLock<Vec>` (CIDR ranges), and
/// atomic counters for statistics.
pub struct DecisionCache {
    /// Exact IP address decisions
    ip_decisions: DashMap<IpAddr, CachedDecision>,
    /// CIDR range decisions
    range_decisions: RwLock<Vec<(IpNet, CachedDecision)>>,
    /// Other scope decisions (Country/AS keyed by value string)
    other_decisions: DashMap<String, CachedDecision>,
    /// Running total of cached decisions
    total_cached: AtomicU64,
    /// Cache hit counter
    pub hits: AtomicU64,
    /// Cache miss counter
    pub misses: AtomicU64,
    /// Optional override TTL in seconds (0 = use decision duration)
    cache_ttl_secs: u64,
}

impl DecisionCache {
    pub fn new(cache_ttl_secs: u64) -> Self {
        Self {
            ip_decisions: DashMap::new(),
            range_decisions: RwLock::new(Vec::new()),
            other_decisions: DashMap::new(),
            total_cached: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            cache_ttl_secs,
        }
    }

    /// Check if `ip` has an active decision. Returns the first match found.
    pub fn check_ip(&self, ip: &IpAddr) -> Option<CachedDecision> {
        // 1. Exact IP match
        if let Some(entry) = self.ip_decisions.get(ip)
            && !entry.is_expired()
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entry.clone());
        }

        // 2. CIDR range match
        {
            let ranges = self.range_decisions.read();
            for (net, cached) in ranges.iter() {
                if net.contains(ip) && !cached.is_expired() {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(cached.clone());
                }
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Apply a decision stream: insert new decisions and remove deleted ones.
    pub fn apply_stream(&self, stream: DecisionStream, config: &CrowdSecConfig) {
        if let Some(new_decisions) = stream.new {
            for decision in new_decisions {
                if !Self::should_cache(&decision, config) {
                    continue;
                }
                let expires_at = self.compute_expiry(&decision);
                let cached = CachedDecision {
                    decision: decision.clone(),
                    expires_at,
                };
                self.insert_decision(&decision, cached);
            }
        }

        if let Some(deleted) = stream.deleted {
            for decision in deleted {
                self.remove_decision(&decision);
            }
        }

        self.update_total();
    }

    /// Remove all expired entries from the cache.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.ip_decisions.retain(|_, v| v.expires_at > now);
        {
            let mut ranges = self.range_decisions.write();
            ranges.retain(|(_, v)| v.expires_at > now);
        }
        self.other_decisions.retain(|_, v| v.expires_at > now);
        self.update_total();
    }

    /// Return all non-expired decisions as a flat Vec (for API listing).
    pub fn list_decisions(&self) -> Vec<Decision> {
        let mut result = Vec::new();

        for entry in &self.ip_decisions {
            if !entry.is_expired() {
                result.push(entry.decision.clone());
            }
        }

        {
            let ranges = self.range_decisions.read();
            for (_, cached) in ranges.iter() {
                if !cached.is_expired() {
                    result.push(cached.decision.clone());
                }
            }
        }

        for entry in &self.other_decisions {
            if !entry.is_expired() {
                result.push(entry.decision.clone());
            }
        }

        result
    }

    /// Get cache hit/miss statistics.
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total_lookups = hits + misses;
        #[allow(clippy::cast_precision_loss)]
        let hit_rate_pct = if total_lookups > 0 {
            (hits as f64 / total_lookups as f64) * 100.0
        } else {
            0.0
        };
        CacheStats {
            total_cached: self.total_cached.load(Ordering::Relaxed),
            hits,
            misses,
            hit_rate_pct,
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn should_cache(decision: &Decision, config: &CrowdSecConfig) -> bool {
        if !config.scenarios_containing.is_empty() {
            let matches = config
                .scenarios_containing
                .iter()
                .any(|s| decision.scenario.contains(s.as_str()));
            if !matches {
                return false;
            }
        }
        for excluded in &config.scenarios_not_containing {
            if decision.scenario.contains(excluded.as_str()) {
                return false;
            }
        }
        true
    }

    fn compute_expiry(&self, decision: &Decision) -> Instant {
        if self.cache_ttl_secs > 0 {
            return Instant::now() + Duration::from_secs(self.cache_ttl_secs);
        }
        if let Some(ref dur_str) = decision.duration
            && let Some(secs) = parse_cs_duration(dur_str)
        {
            return Instant::now() + Duration::from_secs(secs);
        }
        // Default fallback: [`DEFAULT_DECISION_CACHE_FALLBACK_SECS`] (4 hours)
        Instant::now() + Duration::from_secs(DEFAULT_DECISION_CACHE_FALLBACK_SECS)
    }

    fn insert_decision(&self, decision: &Decision, cached: CachedDecision) {
        let scope = decision.scope.to_lowercase();
        match scope.as_str() {
            "ip" => {
                if let Ok(ip) = decision.value.parse::<IpAddr>() {
                    self.ip_decisions.insert(ip, cached);
                }
            }
            "range" => {
                if let Ok(net) = decision.value.parse::<IpNet>() {
                    let mut ranges = self.range_decisions.write();
                    ranges.retain(|(n, _)| *n != net);
                    ranges.push((net, cached));
                }
            }
            _ => {
                self.other_decisions.insert(decision.value.clone(), cached);
            }
        }
    }

    fn remove_decision(&self, decision: &Decision) {
        let scope = decision.scope.to_lowercase();
        match scope.as_str() {
            "ip" => {
                if let Ok(ip) = decision.value.parse::<IpAddr>() {
                    self.ip_decisions.remove(&ip);
                }
            }
            "range" => {
                if let Ok(net) = decision.value.parse::<IpNet>() {
                    let mut ranges = self.range_decisions.write();
                    ranges.retain(|(n, _)| *n != net);
                }
            }
            _ => {
                self.other_decisions.remove(&decision.value);
            }
        }
    }

    fn update_total(&self) {
        let n = self.ip_decisions.len() + self.range_decisions.read().len() + self.other_decisions.len();
        self.total_cached.store(n as u64, Ordering::Relaxed);
    }
}

/// Parse a `CrowdSec` duration string like "4h35m6.571762785s" into total seconds.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn parse_cs_duration(s: &str) -> Option<u64> {
    let mut total = 0u64;
    let mut current = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() || c == '.' {
            current.push(c);
        } else {
            let n: f64 = current.parse().ok()?;
            match c {
                'h' => total += (n * 3600.0) as u64,
                'm' => total += (n * 60.0) as u64,
                's' => total += n as u64,
                _ => {}
            }
            current.clear();
        }
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crowdsec::config::CrowdSecConfig;
    use crate::crowdsec::models::{Decision, DecisionStream};

    /// Stable margin around `Instant::now()` for past vs future in
    /// `cached_decision_is_expired_reflects_instant` (not tied to
    /// [`DEFAULT_DECISION_CACHE_FALLBACK_SECS`]).
    const EXPIRY_INSTANT_TEST_MARGIN_SECS: u64 = 60;

    fn decision(scope: &str, value: &str, scenario: &str) -> Decision {
        Decision {
            id: 1,
            origin: "crowdsec".to_string(),
            scope: scope.to_string(),
            value: value.to_string(),
            type_: "ban".to_string(),
            scenario: scenario.to_string(),
            duration: Some("1h".to_string()),
            created_at: None,
        }
    }

    #[test]
    fn parse_cs_duration_handles_compound_units() {
        assert_eq!(parse_cs_duration("1h"), Some(3600));
        assert_eq!(parse_cs_duration("2m"), Some(120));
        assert_eq!(parse_cs_duration("30s"), Some(30));
        assert_eq!(parse_cs_duration("1h30m15s"), Some(3600 + 30 * 60 + 15));
        // Empty string yields zero, garbage segments are ignored.
        assert_eq!(parse_cs_duration(""), Some(0));
    }

    #[test]
    fn cached_decision_is_expired_reflects_instant() {
        let past = CachedDecision {
            decision: decision("Ip", "1.2.3.4", "test"),
            expires_at: Instant::now()
                .checked_sub(Duration::from_secs(EXPIRY_INSTANT_TEST_MARGIN_SECS))
                .expect("clock"),
        };
        let future = CachedDecision {
            decision: decision("Ip", "1.2.3.4", "test"),
            expires_at: Instant::now() + Duration::from_secs(EXPIRY_INSTANT_TEST_MARGIN_SECS),
        };
        assert!(past.is_expired());
        assert!(!future.is_expired());
    }

    #[test]
    fn apply_stream_inserts_ip_range_and_other_then_check_ip_finds_them() {
        let cache = DecisionCache::new(60);
        let stream = DecisionStream {
            new: Some(vec![
                decision("Ip", "10.0.0.1", "scenario-a"),
                decision("Range", "10.1.0.0/16", "scenario-b"),
                decision("Country", "RU", "scenario-c"),
            ]),
            deleted: None,
        };
        cache.apply_stream(stream, &CrowdSecConfig::default());

        let stats = cache.stats();
        assert_eq!(stats.total_cached, 3);

        // Exact-IP hit
        let ip_match = cache.check_ip(&"10.0.0.1".parse().expect("ip"));
        assert!(ip_match.is_some());

        // CIDR-range hit (different IP within the range)
        let range_match = cache.check_ip(&"10.1.5.5".parse().expect("ip"));
        assert!(range_match.is_some());

        // Miss
        assert!(cache.check_ip(&"8.8.8.8".parse().expect("ip")).is_none());

        let stats = cache.stats();
        assert!(stats.hits >= 2);
        assert!(stats.misses >= 1);
        assert!(stats.hit_rate_pct > 0.0);
    }

    #[test]
    fn apply_stream_deletion_removes_entries() {
        let cache = DecisionCache::new(60);
        cache.apply_stream(
            DecisionStream {
                new: Some(vec![
                    decision("Ip", "1.2.3.4", "s"),
                    decision("Range", "10.0.0.0/24", "s"),
                    decision("Country", "RU", "s"),
                ]),
                deleted: None,
            },
            &CrowdSecConfig::default(),
        );
        assert_eq!(cache.stats().total_cached, 3);

        cache.apply_stream(
            DecisionStream {
                new: None,
                deleted: Some(vec![
                    decision("Ip", "1.2.3.4", "s"),
                    decision("Range", "10.0.0.0/24", "s"),
                    decision("Country", "RU", "s"),
                ]),
            },
            &CrowdSecConfig::default(),
        );
        assert_eq!(cache.stats().total_cached, 0);
    }

    #[test]
    fn should_cache_respects_scenarios_filters() {
        let cache = DecisionCache::new(60);
        let config = CrowdSecConfig {
            scenarios_containing: vec!["bruteforce".to_string()],
            scenarios_not_containing: vec!["whitelist".to_string()],
            ..CrowdSecConfig::default()
        };

        cache.apply_stream(
            DecisionStream {
                new: Some(vec![
                    decision("Ip", "1.0.0.1", "ssh-bruteforce"),       // included
                    decision("Ip", "1.0.0.2", "scan"),                 // excluded — no "bruteforce"
                    decision("Ip", "1.0.0.3", "bruteforce-whitelist"), // excluded — "whitelist"
                ]),
                deleted: None,
            },
            &config,
        );
        assert_eq!(cache.stats().total_cached, 1);
        assert!(cache.check_ip(&"1.0.0.1".parse().expect("ip")).is_some());
        assert!(cache.check_ip(&"1.0.0.2".parse().expect("ip")).is_none());
    }

    #[test]
    fn cleanup_expired_drops_stale_entries_in_all_scopes() {
        let cache = DecisionCache::new(0); // use decision duration
        // Insert decisions with an immediately-expired duration.
        let mut stale = decision("Ip", "1.2.3.4", "s");
        stale.duration = Some("0s".to_string());
        let mut stale_range = decision("Range", "10.0.0.0/24", "s");
        stale_range.duration = Some("0s".to_string());
        let mut stale_other = decision("Country", "ZZ", "s");
        stale_other.duration = Some("0s".to_string());

        cache.apply_stream(
            DecisionStream {
                new: Some(vec![stale, stale_range, stale_other]),
                deleted: None,
            },
            &CrowdSecConfig::default(),
        );
        // Sleep a hair to ensure expires_at is in the past.
        std::thread::sleep(Duration::from_millis(10));
        cache.cleanup_expired();
        assert_eq!(cache.stats().total_cached, 0);
    }

    #[test]
    fn list_decisions_returns_all_active() {
        let cache = DecisionCache::new(60);
        cache.apply_stream(
            DecisionStream {
                new: Some(vec![
                    decision("Ip", "1.1.1.1", "s"),
                    decision("Range", "10.0.0.0/8", "s"),
                    decision("Country", "AA", "s"),
                ]),
                deleted: None,
            },
            &CrowdSecConfig::default(),
        );
        assert_eq!(cache.list_decisions().len(), 3);
    }

    #[test]
    fn invalid_ip_or_cidr_values_are_silently_skipped() {
        let cache = DecisionCache::new(60);
        cache.apply_stream(
            DecisionStream {
                new: Some(vec![
                    decision("Ip", "not-an-ip", "s"),
                    decision("Range", "definitely-not-a-cidr", "s"),
                ]),
                deleted: None,
            },
            &CrowdSecConfig::default(),
        );
        assert_eq!(cache.stats().total_cached, 0);
    }

    #[test]
    fn checker_returns_detection_on_cache_hit_and_skips_in_appsec_mode() {
        use crate::checks::Check;
        use crate::crowdsec::checker::CrowdSecChecker;
        use crate::crowdsec::config::CrowdSecMode;
        use bytes::Bytes;
        use std::collections::HashMap;
        use std::sync::Arc;
        use waf_common::{HostConfig, RequestCtx};

        let cache = Arc::new(DecisionCache::new(60));
        cache.apply_stream(
            DecisionStream {
                new: Some(vec![decision("Ip", "9.9.9.9", "ssh-bf")]),
                deleted: None,
            },
            &CrowdSecConfig::default(),
        );

        let ctx = RequestCtx {
            req_id: "test".to_string(),
            client_ip: "9.9.9.9".parse().expect("ip"),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: RequestCtx::default_tier_policy(),
            cookies: HashMap::new(),
        };

        // Bouncer mode → cache hit
        let bouncer = CrowdSecChecker::new(Arc::clone(&cache), CrowdSecConfig::default());
        let det = bouncer.check(&ctx).expect("detection");
        assert!(det.rule_id.as_deref().unwrap_or("").contains("ssh-bf"));

        // AppSec-only mode → checker bails out
        let appsec_only = CrowdSecChecker::new(
            Arc::clone(&cache),
            CrowdSecConfig {
                mode: CrowdSecMode::Appsec,
                ..CrowdSecConfig::default()
            },
        );
        assert!(appsec_only.check(&ctx).is_none());
    }
}
