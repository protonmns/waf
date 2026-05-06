//! FR-007 phase-04 — shared HTTP client for intel feed refresh.
//!
//! Single `reqwest::Client` per refresh task with conservative timeouts
//! and a stable User-Agent. Body streaming is enabled (workspace feature
//! `stream`); `gzip` is enabled for `.gz` TSV feeds.

#![allow(clippy::duration_suboptimal_units)] // prefer `from_secs` over MSRV‑gated `from_mins`

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(60);

const USER_AGENT: &str = concat!("mini-waf/", env!("CARGO_PKG_VERSION"), " relay-intel");

/// Build the shared client for a single intel feed.
///
/// `total_timeout` overrides the default (60s) when the operator configures
/// a slower feed (large mmdb pulls). `connect_timeout` stays at 5s — that
/// is purely TCP/TLS handshake.
pub fn build_client(total_timeout: Option<Duration>) -> Result<Client> {
    Client::builder()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .timeout(total_timeout.unwrap_or(DEFAULT_TOTAL_TIMEOUT))
        .user_agent(USER_AGENT)
        // Refresh URLs may redirect (e.g. CDN) — follow within reason.
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("building intel-refresh HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_client_succeeds_with_defaults() {
        assert!(build_client(None).is_ok());
    }

    #[test]
    fn build_client_accepts_custom_timeout() {
        assert!(build_client(Some(Duration::from_secs(10))).is_ok());
    }
}
