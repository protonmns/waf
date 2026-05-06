use std::sync::Arc;

use bytes::BytesMut;
use waf_common::tier::{CachePolicy, Tier};
use waf_common::{HostConfig, RequestCtx};
use waf_engine::device_fp::DeviceIdentity;
use waf_engine::relay::ClientIdentity;

use crate::protocol::Protocol;

/// Maximum request body bytes buffered for WAF inspection (64 KiB).
pub const BODY_PREVIEW_LIMIT: usize = 64 * 1024;

/// Maximum bytes buffered from upstream for response caching.
pub const RESPONSE_CACHE_BODY_LIMIT: usize = 2 * 1024 * 1024;

/// FR-009: state for deferred `ResponseCache::put` after the upstream body completes.
pub struct ResponseCachePending {
    pub key: String,
    pub host: String,
    pub path: String,
    pub tier: Tier,
    pub cache_policy: CachePolicy,
    pub has_authorization: bool,
    pub has_cookie: bool,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub cache_control: Option<String>,
    pub body: BytesMut,
    /// Set in `response_filter` once headers are snapshotted and buffering is allowed.
    pub capture_started: bool,
}

/// Per-request state stored in the Pingora session context
#[derive(Default)]
pub struct GatewayCtx {
    /// Built `RequestCtx` for WAF pipeline
    pub request_ctx: Option<RequestCtx>,
    /// Resolved upstream address (host:port)
    pub upstream_addr: Option<String>,
    /// Matched host config
    pub host_config: Option<Arc<HostConfig>>,
    /// Accumulates the first [`BODY_PREVIEW_LIMIT`] bytes of the request body
    /// for WAF body inspection in `request_body_filter`.
    pub body_buf: BytesMut,
    /// Set to `true` once the body WAF check has been performed so we only
    /// inspect once (on the first chunk that completes the preview or at EOS).
    pub body_inspected: bool,
    /// AC-17: streaming state for the response body internal-ref masker.
    pub body_mask: BodyMaskState,
    /// Phase-05: wire protocol detected at session start. Tagged once in
    /// `request_filter` and consumed for per-protocol observability.
    pub protocol: Protocol,
    /// FR-008 phase-05: set by the Phase-0 access gate when an IP whitelist hit
    /// resolves to `full_bypass` for the request's tier. When `true`, the WAF
    /// engine `inspect()` call is skipped (whitelist trust → fast path).
    pub access_bypass: bool,
    /// FR-007 phase-06: validated client identity from the relay/proxy detector.
    /// `None` when the detector is not configured (back-compat) or before the
    /// `request_filter` phase has run. Downstream phases prefer
    /// `client_identity.real_ip` over the raw TCP peer when present.
    pub client_identity: Option<ClientIdentity>,
    /// FR-010 phase-07: resolved device fingerprint identity. `None` when the
    /// detector is not configured or before `request_filter` has run.
    pub device_identity: Option<DeviceIdentity>,
    /// FR-009: buffer a cacheable upstream response for [`crate::cache::ResponseCache::put`].
    pub response_cache_store: Option<ResponseCachePending>,
}

/// Per-response state for the streaming body masker (AC-17).
///
/// `enabled` is decided in `response_filter` once the upstream `Content-Encoding`
/// is known. Compressed bodies bypass masking entirely (FR-001 scope).
#[derive(Default)]
pub struct BodyMaskState {
    /// Whether masking should run for this response (set in `response_filter`).
    pub enabled: bool,
    /// Tail bytes of the prior chunk preserved to handle pattern straddle.
    pub tail: BytesMut,
    /// Total bytes scanned so far. Beyond [`HostConfig::body_mask_max_bytes`]
    /// the rest of the response is forwarded unchanged.
    pub processed: u64,
    /// `true` once the byte ceiling was hit; used to log a single warning.
    pub ceiling_logged: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;
    use std::net::{IpAddr, Ipv4Addr};
    use waf_engine::relay::RelayDetector;

    #[test]
    fn default_client_identity_is_none() {
        let ctx = GatewayCtx::default();
        assert!(ctx.client_identity.is_none());
    }

    #[test]
    fn detector_eval_populates_identity_with_peer_as_real_ip() {
        // FR-007 phase-06: when no XFF and no providers (empty detector),
        // `real_ip` falls back to the TCP peer. Verifies the wiring contract
        // gateway relies on for FR-008 handover.
        let detector = RelayDetector::empty();
        let peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let id = detector.evaluate(peer, &HeaderMap::new());
        assert_eq!(id.real_ip, peer);

        let ctx = GatewayCtx {
            client_identity: Some(id),
            ..GatewayCtx::default()
        };
        assert_eq!(ctx.client_identity.as_ref().expect("set above").real_ip, peer);
    }
}
