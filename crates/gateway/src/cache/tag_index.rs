//! Reverse index: tag → set of cache keys, for FR-009 Phase 4 tag-based purge.
//!
//! Two `DashMap`s kept in lockstep:
//! - `tag_to_keys`: tag → set of keys carrying that tag (purge lookup)
//! - `key_to_tags`: key → tags it was registered under (eviction cleanup)
//!
//! The reverse map is what makes O(1) eviction-listener cleanup possible. With
//! a single forward map you would have to scan every tag bucket on each
//! eviction — which leaks entries until the next purge sweep.
//!
//! Why `Arc<str>`: tags come from `CompiledRule::tags` already as `Arc<str>`,
//! and cache keys are reused across the index — `Arc` clones are refcount
//! bumps, not heap copies.

use std::sync::Arc;

use dashmap::{DashMap, DashSet};

#[derive(Debug, Default)]
pub struct TagIndex {
    tag_to_keys: DashMap<Arc<str>, DashSet<Arc<str>>>,
    key_to_tags: DashMap<Arc<str>, Vec<Arc<str>>>,
}

impl TagIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Associate `key` with each of `tags`. Idempotent — a re-register replaces
    /// the prior tag set for that key (rule reload may change tags for the
    /// same path; we must not leak the old ones).
    pub fn register(&self, key: &Arc<str>, tags: &[Arc<str>]) {
        if tags.is_empty() {
            return;
        }
        // Drop any prior registration first.
        self.unregister(key);
        for tag in tags {
            self.tag_to_keys
                .entry(Arc::clone(tag))
                .or_default()
                .insert(Arc::clone(key));
        }
        self.key_to_tags.insert(Arc::clone(key), tags.to_vec());
    }

    /// Forget `key` from all its tags. Called by moka eviction listener AND by
    /// explicit purges. Empty tag buckets are dropped so the index can shrink.
    pub fn unregister(&self, key: &Arc<str>) {
        let Some((_, tags)) = self.key_to_tags.remove(key) else {
            return;
        };
        for t in &tags {
            // Limit the get() lock scope before remove_if takes its own lock.
            let became_empty = self.tag_to_keys.get(t).is_some_and(|set| {
                set.remove(key);
                set.is_empty()
            });
            if became_empty {
                self.tag_to_keys.remove_if(t, |_, s| s.is_empty());
            }
        }
    }

    /// Snapshot of keys for a tag — releases shard locks before the caller
    /// does anything async with the result. Iterating-while-mutating the same
    /// shard would deadlock under concurrent put + purge.
    pub fn keys_for_tag(&self, tag: &str) -> Vec<Arc<str>> {
        self.tag_to_keys
            .get(tag)
            .map(|set| set.iter().map(|k| Arc::clone(&k)).collect())
            .unwrap_or_default()
    }

    /// Total keys tracked.
    pub fn key_count(&self) -> usize {
        self.key_to_tags.len()
    }

    /// Per-tag entry counts (cardinality of each tag bucket).
    pub fn tag_entry_counts(&self) -> Vec<(String, u64)> {
        self.tag_to_keys
            .iter()
            .map(|r| (r.key().as_ref().to_string(), r.value().len() as u64))
            .collect()
    }

    /// Total distinct tags tracked. Used by tests and by stats responses to
    /// observe whether the index shrinks correctly under purge/eviction.
    #[cfg(test)]
    pub fn tag_count(&self) -> usize {
        self.tag_to_keys.len()
    }

    /// Wipe everything (used on full cache flush).
    pub fn clear(&self) {
        self.tag_to_keys.clear();
        self.key_to_tags.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(s: &str) -> Arc<str> {
        Arc::from(s)
    }

    #[test]
    fn register_then_lookup_returns_all_keys() {
        let idx = TagIndex::new();
        let tag = k("catalog");
        idx.register(&k("k1"), &[Arc::clone(&tag)]);
        idx.register(&k("k2"), &[Arc::clone(&tag)]);
        let mut got: Vec<String> = idx
            .keys_for_tag("catalog")
            .into_iter()
            .map(|k| k.as_ref().to_owned())
            .collect();
        got.sort();
        assert_eq!(got, vec!["k1".to_string(), "k2".to_string()]);
    }

    #[test]
    fn unregister_removes_from_all_tags_and_shrinks_buckets() {
        let idx = TagIndex::new();
        idx.register(&k("k1"), &[k("catalog"), k("v1")]);
        assert_eq!(idx.tag_count(), 2);
        idx.unregister(&k("k1"));
        assert_eq!(idx.key_count(), 0);
        assert_eq!(idx.tag_count(), 0, "empty buckets must be dropped");
        assert!(idx.keys_for_tag("catalog").is_empty());
    }

    #[test]
    fn unregister_keeps_other_keys_in_same_tag() {
        let idx = TagIndex::new();
        let tag = k("t");
        idx.register(&k("k1"), &[Arc::clone(&tag)]);
        idx.register(&k("k2"), &[Arc::clone(&tag)]);
        idx.unregister(&k("k1"));
        let got = idx.keys_for_tag("t");
        assert_eq!(got.len(), 1);
        assert_eq!(got.first().map(AsRef::as_ref), Some("k2"));
    }

    #[test]
    fn re_register_replaces_prior_tags() {
        let idx = TagIndex::new();
        idx.register(&k("k1"), &[k("old")]);
        idx.register(&k("k1"), &[k("new")]);
        assert!(idx.keys_for_tag("old").is_empty());
        assert_eq!(idx.keys_for_tag("new").len(), 1);
    }

    #[test]
    fn empty_tags_is_noop() {
        let idx = TagIndex::new();
        idx.register(&k("k1"), &[]);
        assert_eq!(idx.key_count(), 0);
    }

    #[test]
    fn clear_wipes_both_maps() {
        let idx = TagIndex::new();
        idx.register(&k("k1"), &[k("t")]);
        idx.clear();
        assert_eq!(idx.key_count(), 0);
        assert_eq!(idx.tag_count(), 0);
    }
}
