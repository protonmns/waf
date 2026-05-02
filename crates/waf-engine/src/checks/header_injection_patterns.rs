//! Header-injection pattern data — encoded CRLF detection.
//!
//! Raw CRLF is bytewise-scanned in `header_injection.rs`; this file holds the
//! regex set that catches single- and double-percent-encoded forms.

use std::sync::LazyLock;

use regex::RegexSet;

/// Description text aligned with `HDR_ENCODED_CRLF_SET` patterns by index.
pub static HDR_ENCODED_CRLF_DESCS: &[&str] = &[
    "single-encoded CRLF (%0d%0a)",
    "double-encoded CRLF (%250d%250a)",
    "single-encoded LF only (%0a) — header smuggling primitive",
    "double-encoded LF only (%250a)",
];

// SAFETY: Compile-time string literals; failure is a code bug.
pub static HDR_ENCODED_CRLF_SET: LazyLock<RegexSet> =
    LazyLock::new(
        || match RegexSet::new([r"(?i)%0d%0a", r"(?i)%250d%250a", r"(?i)%0a", r"(?i)%250a"]) {
            Ok(set) => set,
            Err(e) => {
                tracing::error!("BUG: header-injection encoded-CRLF regex set failed to compile: {e}");
                RegexSet::empty()
            }
        },
    );
