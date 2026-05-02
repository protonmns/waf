//! SSRF pattern data — metadata hostnames and private-network CIDRs.
//!
//! Kept in a sibling file so `ssrf.rs` stays under the modularization limit.

use std::sync::LazyLock;

use ipnet::Ipv4Net;
use regex::RegexSet;

/// Cloud / orchestrator metadata hostnames that should never be reachable
/// from a user-supplied URL. Anchored with `^` so a request body containing
/// `metadata.google.internal.attacker.com` does not slip past as a substring.
pub static METADATA_HOST_DESCS: &[&str] = &[
    "AWS / OpenStack metadata IP (169.254.169.254)",
    "Google Cloud metadata host",
    "Alibaba Cloud metadata IP (100.100.100.200)",
    "Consul metadata service",
    "DigitalOcean / generic 'metadata' host",
];

// SAFETY: Compile-time string literals; failure is a code bug.
pub static METADATA_HOST_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    match RegexSet::new([
        r"^169\.254\.169\.254$",
        r"^metadata\.google\.internal$",
        r"^100\.100\.100\.200$",
        r"^metadata\.service\.consul$",
        r"^metadata(\.|$)",
    ]) {
        Ok(set) => set,
        Err(e) => {
            tracing::error!("BUG: SSRF metadata host regex set failed to compile: {e}");
            RegexSet::empty()
        }
    }
});

/// Private / loopback / link-local IPv4 ranges. Caller should also test the
/// IPv4 form of an IPv6-mapped address against this set.
///
/// 100.64.0.0/10 (RFC 6598 carrier-grade NAT) is intentionally NOT included
/// — only the exact metadata IP `100.100.100.200` is flagged via the regex
/// set above. Treating the whole CGNAT range as SSRF would false-flag
/// legitimate calls into ISP-shared address space.
pub static PRIVATE_CIDRS: LazyLock<Vec<Ipv4Net>> = LazyLock::new(|| {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",
    ]
    .iter()
    .filter_map(|s| s.parse::<Ipv4Net>().ok())
    .collect()
});
