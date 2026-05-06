//! Pingora [`ProxyHttp`] implementation that wires WAF inspection and filter
//! chains into the proxy lifecycle.
//!
//! All context construction is delegated to [`RequestCtxBuilder`].
//! All filter execution is delegated to [`RequestFilterChain`] /
//! [`ResponseFilterChain`] (populated by phases 02–04).
//! WAF response helpers live in [`super::proxy_waf_response`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tracing::{debug, info, warn};

use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::{FailToProxy, ProxyHttp, Session};

use waf_common::HostConfig;
use waf_common::tier::CachePolicy;
use waf_engine::WafEngine;
use waf_engine::access::AccessLists;
use waf_engine::device_fp::DeviceFpDetector;
use waf_engine::device_fp::behavior::Recorder as BehaviorRecorder;
use waf_engine::device_fp::capture::ConnCtx as DeviceFpConnCtx;
use waf_engine::relay::RelayDetector;

use crate::tiered::TierPolicyRegistry;

use crate::cache::ResponseCache;
use crate::context::{BODY_PREVIEW_LIMIT, GatewayCtx, ResponseCachePending};
use crate::ctx_builder::RequestCtxBuilder;
use crate::error_page::ErrorPageFactory;
use crate::filters::{
    CompiledMask, RequestForwardedHostFilter, RequestForwardedProtoFilter, RequestHopByHopFilter,
    RequestHostPolicyFilter, RequestRealIpFilter, RequestXffFilter, ResponseHeaderBlocklistFilter,
    ResponseLocationRewriter, ResponseServerPolicyFilter, ResponseViaStripFilter, apply_body_mask_chunk,
};
use crate::pipeline::{AccessGateOutcome, AccessPhaseGate, FilterCtx, RequestFilterChain, ResponseFilterChain};
use crate::protocol::{ProtoCounters, detect_from_session};
use crate::proxy_waf_response::{write_waf_body_decision, write_waf_decision};
use crate::router::HostRouter;

/// Pingora-based reverse proxy with WAF integration and filter chains.
pub struct WafProxy {
    pub router: Arc<HostRouter>,
    pub engine: Arc<WafEngine>,
    /// Whether to trust X-Forwarded-For headers for client IP extraction.
    pub trust_proxy_headers: bool,
    /// Parsed trusted proxy CIDR ranges.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Total request counter (cloned from `AppState`).
    pub request_counter: Arc<AtomicU64>,
    /// Blocked request counter (cloned from `AppState`).
    pub blocked_counter: Arc<AtomicU64>,
    /// Per-protocol counters (AC-22 transparency proof). Shared with the
    /// HTTP/3 listener so QUIC traffic increments the same struct.
    pub proto_counters: Arc<ProtoCounters>,
    /// Ordered chain of upstream request filters (populated by phases 02–04).
    pub request_chain: Arc<RequestFilterChain>,
    /// Ordered chain of response filters (populated by phases 02–03).
    pub response_chain: Arc<ResponseFilterChain>,
    /// AC-17: per-host compiled mask cache, keyed by `Arc<HostConfig>` pointer
    /// identity. Compiled lazily on first body chunk; survives until config reload.
    pub body_mask_cache: Arc<DashMap<usize, Arc<CompiledMask>>>,
    /// FR-002: tier policy registry. When `None`, every request defaults to
    /// `Tier::CatchAll` + permissive policy (boot-time safety).
    pub tier_registry: Option<Arc<TierPolicyRegistry>>,
    /// FR-008 phase-05: Phase-0 access-list gate. Optional — `None` = every
    /// request continues unconditionally (no whitelist/blacklist enforcement).
    pub access_lists: Option<Arc<AccessPhaseGate>>,
    /// FR-007 phase-06: relay/proxy detector. Optional — `None` = pipeline
    /// behaves exactly as pre-FR-007 (back-compat fast path).
    pub relay_detector: Option<Arc<RelayDetector>>,
    /// FR-010 phase-07: device fingerprint detector. Optional — `None` =
    /// no fingerprinting, no signal emission, no aggregator submit.
    pub device_fp_detector: Option<Arc<DeviceFpDetector>>,
    /// FR-011 phase-02: behavioral anomaly recorder. Optional — `None` =
    /// no per-actor sliding-window state, classifiers downstream see no data.
    pub behavior_recorder: Option<Arc<BehaviorRecorder>>,
    /// FR-009: same `Arc` as the management API — when set, GET responses may
    /// be served from cache and cacheable upstream bodies are stored.
    pub response_cache: Option<Arc<ResponseCache>>,
}

impl WafProxy {
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(router: Arc<HostRouter>, engine: Arc<WafEngine>) -> Self {
        Self {
            router,
            engine,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
            request_counter: Arc::new(AtomicU64::new(0)),
            blocked_counter: Arc::new(AtomicU64::new(0)),
            proto_counters: ProtoCounters::new(),
            request_chain: Arc::new(build_request_chain()),
            response_chain: Arc::new(build_response_chain()),
            body_mask_cache: Arc::new(DashMap::new()),
            tier_registry: None,
            access_lists: None,
            relay_detector: None,
            device_fp_detector: None,
            behavior_recorder: None,
            response_cache: None,
        }
    }

    /// Inject the FR-011 behavioral recorder. When set, every request with a
    /// non-empty `FpKey` records one `Sample` after device-fp resolution.
    /// When unset, the recording call is a no-op.
    pub fn with_behavior_recorder(&mut self, recorder: Arc<BehaviorRecorder>) {
        self.behavior_recorder = Some(recorder);
    }

    /// Inject the FR-010 device fingerprint detector. When set, every request
    /// runs `process()` after relay detection so resolved signals reach the
    /// risk aggregator. When unset, no fingerprinting work runs.
    pub fn with_device_fp_detector(&mut self, detector: Arc<DeviceFpDetector>) {
        self.device_fp_detector = Some(detector);
    }

    /// Inject the FR-007 relay/proxy detector. When set, every request runs
    /// detection in `request_filter` and the resolved `ClientIdentity` is
    /// stashed on the gateway context. When unset, the detector is skipped
    /// entirely (no overhead, identical to pre-FR-007 behaviour).
    pub fn with_relay_detector(&mut self, detector: Arc<RelayDetector>) {
        self.relay_detector = Some(detector);
    }

    /// Inject the tier policy registry (FR-002 phase-05). When set, every
    /// `RequestCtx` built by this proxy carries a classified tier instead of
    /// the boot-time `CatchAll` fallback.
    pub fn with_tier_registry(&mut self, registry: Arc<TierPolicyRegistry>) {
        self.tier_registry = Some(registry);
    }

    /// Inject the FR-008 Phase-0 access-list gate. The proxy stores a hot
    /// snapshot reference; phase-06 watcher will swap the `ArcSwap` content on
    /// file change without restart. When unset, no access-list enforcement runs.
    pub fn with_access_lists(&mut self, lists: Arc<ArcSwap<AccessLists>>) {
        self.access_lists = Some(Arc::new(AccessPhaseGate::new(lists)));
    }

    /// Resolve (and lazily compile) the mask config for a given host.
    /// Cache key is the `Arc<HostConfig>` pointer; identical configs across
    /// requests reuse the same compiled regex.
    fn resolve_mask(&self, hc: &Arc<HostConfig>) -> Arc<CompiledMask> {
        let key = Arc::as_ptr(hc) as usize;
        if let Some(existing) = self.body_mask_cache.get(&key) {
            return Arc::clone(&existing);
        }
        let compiled = Arc::new(CompiledMask::build(
            &hc.internal_patterns,
            &hc.mask_token,
            hc.body_mask_max_bytes,
        ));
        self.body_mask_cache.insert(key, Arc::clone(&compiled));
        compiled
    }
}

/// Map a Pingora error to the HTTP status used by [`ErrorPageFactory`].
///
/// Mirrors the default `fail_to_proxy` mapping but lives in gateway code so we
/// can render a neutral body. `0` means "downstream is already gone — do not
/// attempt to write a response."
fn error_to_status(e: &pingora_core::Error) -> u16 {
    use pingora_core::{ErrorSource, ErrorType};
    if let ErrorType::HTTPStatus(code) = e.etype() {
        return *code;
    }
    match e.esource() {
        ErrorSource::Upstream => 502,
        ErrorSource::Downstream => match e.etype() {
            ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
            _ => 400,
        },
        ErrorSource::Internal | ErrorSource::Unset => 500,
    }
}

/// Build the default response-side filter chain (AC-15, 16, 18).
///
/// Order:
/// 1. `via-strip` — unconditional removal.
/// 2. `server-policy` — passthrough (default) or strip.
/// 3. `location-rewrite` — rewrite internal-host redirects.
/// 4. `header-blocklist` — drop configured leak headers last so anything
///    a prior filter leaves behind still gets scrubbed.
fn build_response_chain() -> ResponseFilterChain {
    let mut chain = ResponseFilterChain::new();
    chain.register(Arc::new(ResponseViaStripFilter));
    chain.register(Arc::new(ResponseServerPolicyFilter));
    chain.register(Arc::new(ResponseLocationRewriter));
    chain.register(Arc::new(ResponseHeaderBlocklistFilter));
    chain
}

/// Build the default request-side filter chain.
///
/// Order is significant:
/// 1. `xff` / `real-ip` / `forwarded-proto` — populate forwarded metadata.
/// 2. `forwarded-host` — captures the ORIGINAL `Host` (must run before host-policy).
/// 3. `host-policy` — applies `Preserve` or `Rewrite(remote_host)` per host config.
/// 4. `hop-by-hop` — strips RFC 7230 hop headers + Connection-tokens last,
///    so any header *we* added (e.g. `Connection: upgrade` for WS) is preserved
///    by the WS-aware branch.
fn build_request_chain() -> RequestFilterChain {
    let mut chain = RequestFilterChain::new();
    chain.register(Arc::new(RequestXffFilter));
    chain.register(Arc::new(RequestRealIpFilter));
    chain.register(Arc::new(RequestForwardedProtoFilter));
    chain.register(Arc::new(RequestForwardedHostFilter));
    chain.register(Arc::new(RequestHostPolicyFilter));
    chain.register(Arc::new(RequestHopByHopFilter));
    chain
}

#[async_trait]
impl ProxyHttp for WafProxy {
    type CTX = GatewayCtx;

    fn new_ctx(&self) -> Self::CTX {
        GatewayCtx::default()
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<Box<HttpPeer>> {
        self.request_counter.fetch_add(1, Ordering::Relaxed);

        let host_header = session
            .get_header("host")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .unwrap_or("")
            .to_string();

        debug!("Routing request for host: {}", host_header);

        let host_config = self.router.resolve(&host_header).ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::ConnectProxyFailure,
                format!("No route found for host: {host_header}"),
            )
        })?;

        if !host_config.start_status {
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::ConnectProxyFailure,
                "Site is closed",
            ));
        }

        let upstream_addr = format!("{}:{}", host_config.remote_host, host_config.remote_port);
        let use_tls = host_config.ssl;

        ctx.upstream_addr = Some(upstream_addr.clone());
        if ctx.host_config.is_none() {
            ctx.host_config = Some(Arc::clone(&host_config));
        }
        if ctx.request_ctx.is_none() {
            let mut builder = RequestCtxBuilder::new(session, self.trust_proxy_headers, &self.trusted_proxies)
                .with_host_config(Arc::clone(&host_config));
            if let Some(reg) = &self.tier_registry {
                builder = builder.with_tier_registry(reg);
            }
            ctx.request_ctx = Some(builder.build());
        }

        info!("Proxying {} → {}", host_header, upstream_addr);
        Ok(Box::new(HttpPeer::new(
            &upstream_addr,
            use_tls,
            host_config.remote_host.clone(),
        )))
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<bool> {
        // AC-22: tag protocol once and bump the per-protocol counter so every
        // request through the Pingora listener (H1/H2/WS-upgrade) is accounted
        // for. H3 traffic increments the same struct from `http3.rs`.
        ctx.protocol = detect_from_session(session);
        self.proto_counters.record(ctx.protocol);

        // FR-007 phase-06: run relay/proxy detection BEFORE building the
        // request ctx so the resolved `real_ip` can override the raw peer/XFF
        // value used by FR-008 + downstream WAF checks. When the detector is
        // unset, this block is skipped and the pipeline behaves exactly as
        // pre-FR-007 (no-op fast path).
        if let Some(detector) = &self.relay_detector
            && ctx.client_identity.is_none()
        {
            let peer_ip = session.client_addr().and_then(|a| a.as_inet()).map_or_else(
                || std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                std::net::SocketAddr::ip,
            );
            ctx.client_identity = Some(detector.evaluate(peer_ip, &session.req_header().headers));
        }

        // FR-010 phase-07: device fingerprint pipeline. Runs after relay
        // detection so it can use the validated `real_ip`. L4 capture
        // wiring (TLS/h2 inspectors → ConnCtx) lands in a later phase;
        // until then `process()` operates on an empty `ConnCtx`, producing
        // an empty FpKey but still dispatching UA-only providers.
        if let Some(detector) = &self.device_fp_detector
            && ctx.device_identity.is_none()
        {
            let peer_ip = ctx.client_identity.as_ref().map_or_else(
                || {
                    session.client_addr().and_then(|a| a.as_inet()).map_or(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        std::net::SocketAddr::ip,
                    )
                },
                |id| id.real_ip,
            );
            let ua = session
                .get_header("user-agent")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                .unwrap_or("");
            let conn = DeviceFpConnCtx::new();
            ctx.device_identity = Some(detector.process(peer_ip, ua, &conn).await);
        }

        // Build request context early so WAF runs before upstream_peer.
        if ctx.request_ctx.is_none() {
            let host_header = session
                .get_header("host")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                .unwrap_or("")
                .to_string();
            if let Some(host_config) = self.router.resolve(&host_header) {
                ctx.host_config = Some(Arc::clone(&host_config));
                let mut builder = RequestCtxBuilder::new(session, self.trust_proxy_headers, &self.trusted_proxies)
                    .with_host_config(host_config);
                if let Some(reg) = &self.tier_registry {
                    builder = builder.with_tier_registry(reg);
                }
                let mut built = builder.build();
                // FR-007 → FR-008 handover: when the detector resolved a
                // validated `real_ip`, prefer it over the builder's XFF-based
                // extraction. Detector validates trusted-proxy chain + spoof
                // signals; raw XFF parsing in the builder does not.
                if let Some(id) = &ctx.client_identity {
                    built.client_ip = id.real_ip;
                }
                ctx.request_ctx = Some(built);
            }
        }

        let host_for_log = ctx
            .request_ctx
            .as_ref()
            .map_or_else(|| "<unknown>".to_string(), |c| c.host.clone());

        // FAIL-CLOSED: never bypass WAF when context is missing (AC-22).
        let mut request_ctx = if let Some(c) = &ctx.request_ctx {
            c.clone()
        } else {
            self.blocked_counter.fetch_add(1, Ordering::Relaxed);
            warn!(host = %host_for_log, "fail-closed: missing request context, returning 503");
            let accept = session
                .get_header("accept")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                .map(str::to_string);
            let (headers, body) = ErrorPageFactory::render(503, accept.as_deref())?;
            session.write_response_header(Box::new(headers), false).await?;
            session.write_response_body(Some(body), true).await?;
            return Ok(true);
        };

        if request_ctx.path == "/health" && request_ctx.method == "GET" {
            let _ = session.respond_error(200).await;
            return Ok(true);
        }

        // FR-011 phase-02 — record one behavioral sample per request. Skipped
        // when no fingerprint resolved (empty FpKey) or no recorder injected.
        // Phase 4 also forwards `Sec-Purpose: prefetch` so the
        // missing_referer classifier can exempt browser-prefetched navs.
        if let Some(device) = ctx.device_identity.as_ref() {
            let had_referer = session.get_header("referer").is_some();
            let had_prefetch_hint = session
                .get_header("sec-purpose")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("prefetch")));
            crate::behavior_record::record_sample(
                self.behavior_recorder.as_ref(),
                &device.key,
                &request_ctx.path,
                had_referer,
                had_prefetch_hint,
                request_ctx.tier,
            );
        }

        // FR-008 phase-05 — Phase-0 access-list gate runs *before* the WAF
        // engine. peer_ip is the immediate TCP peer (XFF/real-ip rewrites are
        // upstream-bound and run later in upstream_request_filter).
        if let Some(gate) = &self.access_lists {
            // FR-007 → FR-008 handover: prefer detector-validated `real_ip`
            // over raw TCP peer. Falls back to peer when the detector is
            // unset, preserving pre-FR-007 semantics.
            let access_ip = ctx.client_identity.as_ref().map_or_else(
                || {
                    session
                        .client_addr()
                        .and_then(|a| a.as_inet())
                        .map_or(request_ctx.client_ip, std::net::SocketAddr::ip)
                },
                |id| id.real_ip,
            );
            match gate.evaluate(&request_ctx.host, access_ip, request_ctx.tier) {
                AccessGateOutcome::Continue => {}
                AccessGateOutcome::Bypass => {
                    ctx.access_bypass = true;
                }
                AccessGateOutcome::Block(status) => {
                    self.blocked_counter.fetch_add(1, Ordering::Relaxed);
                    let accept = session
                        .get_header("accept")
                        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                        .map(str::to_string);
                    let (headers, body) = ErrorPageFactory::render(status, accept.as_deref())?;
                    session.write_response_header(Box::new(headers), false).await?;
                    session.write_response_body(Some(body), true).await?;
                    return Ok(true);
                }
            }
        }

        // Whitelist full-bypass skips the WAF engine entirely (D6 fast path).
        if ctx.access_bypass {
            return Ok(false);
        }

        let decision = self.engine.inspect(&mut request_ctx).await;
        if write_waf_decision(session, &decision, &request_ctx, &self.blocked_counter).await? {
            return Ok(true);
        }

        if let Some(cache) = &self.response_cache
            && request_ctx.method.eq_ignore_ascii_case("GET")
            && !matches!(request_ctx.tier_policy.cache_policy, CachePolicy::NoCache)
            && !request_ctx.headers.contains_key("authorization")
            && request_ctx.cookies.is_empty()
        {
            let key = ResponseCache::make_key(
                &request_ctx.method,
                &request_ctx.host,
                &request_ctx.path,
                &request_ctx.query,
            );
            if let Some(entry) = cache.get(&key, request_ctx.tier).await {
                crate::response_cache_integration::write_cached_entry(session, &entry).await?;
                return Ok(true);
            }
            ctx.response_cache_store = Some(ResponseCachePending {
                key,
                host: request_ctx.host.clone(),
                path: request_ctx.path.clone(),
                tier: request_ctx.tier,
                cache_policy: request_ctx.tier_policy.cache_policy.clone(),
                has_authorization: false,
                has_cookie: false,
                status: 0,
                headers: Vec::new(),
                cache_control: None,
                body: BytesMut::new(),
                capture_started: false,
            });
        }

        Ok(false)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut GatewayCtx,
    ) -> pingora_core::Result<()> {
        if ctx.body_inspected || ctx.access_bypass {
            return Ok(());
        }
        if let Some(chunk) = body {
            let remaining = BODY_PREVIEW_LIMIT.saturating_sub(ctx.body_buf.len());
            if remaining > 0 {
                let take = chunk.len().min(remaining);
                if let Some(slice) = chunk.get(..take) {
                    ctx.body_buf.extend_from_slice(slice);
                }
            }
        }
        let should_inspect = ctx.body_buf.len() >= BODY_PREVIEW_LIMIT || (end_of_stream && !ctx.body_buf.is_empty());
        if !should_inspect {
            return Ok(());
        }
        ctx.body_inspected = true;
        let mut request_ctx = match &ctx.request_ctx {
            Some(c) => c.clone(),
            None => return Ok(()),
        };
        request_ctx.body_preview = Bytes::copy_from_slice(&ctx.body_buf);
        let decision = self.engine.inspect(&mut request_ctx).await;
        write_waf_body_decision(session, &decision, &request_ctx, &self.blocked_counter).await
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let (Some(req_ctx), Some(hc)) = (&ctx.request_ctx, &ctx.host_config) {
            // peer_ip is the IMMEDIATE TCP peer (not the resolved client).
            // The two differ when trust_proxy_headers=true and the peer is
            // a trusted proxy: client_ip then comes from XFF, while peer_ip
            // remains the proxy's IP. XFF append-mode (AC-14) needs peer_ip.
            let peer_ip = session
                .client_addr()
                .and_then(|a| a.as_inet())
                .map_or(req_ctx.client_ip, std::net::SocketAddr::ip);
            let fctx = FilterCtx {
                request_ctx: req_ctx,
                host_config: hc,
                peer_ip,
                is_tls: req_ctx.is_tls,
            };
            self.request_chain.apply_all(upstream_request, &fctx)?;
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let (Some(req_ctx), Some(hc)) = (&ctx.request_ctx, &ctx.host_config) {
            let fctx = FilterCtx {
                request_ctx: req_ctx,
                host_config: hc,
                peer_ip: req_ctx.client_ip,
                is_tls: req_ctx.is_tls,
            };
            self.response_chain.apply_all(upstream_response, &fctx)?;

            // AC-17: decide whether body masking will run for this response.
            // Identity (or absent) Content-Encoding only — compressed bodies
            // are out of scope for FR-001 (FR-033 will add decompression).
            let identity = upstream_response
                .headers
                .get("content-encoding")
                .and_then(|v| v.to_str().ok())
                .is_none_or(|v| {
                    let v = v.trim();
                    v.is_empty() || v.eq_ignore_ascii_case("identity")
                });
            let compiled = self.resolve_mask(hc);
            if identity && !compiled.is_noop() {
                ctx.body_mask.enabled = true;
                // Replacement length differs from match length — body length is
                // no longer fixed. Drop Content-Length so Pingora switches to
                // chunked encoding.
                let _ = upstream_response.remove_header("content-length");
            } else if !compiled.is_noop() {
                debug!("body-mask: skipping non-identity content-encoding");
            }
        }

        // Cache capture reads `Content-Encoding` from the same header map Pingora will
        // stream (after response_chain above when host config exists), so misses without
        // host context still observe identity/absent CE correctly.
        if let Some(pending) = ctx.response_cache_store.as_mut()
            && !crate::response_cache_integration::begin_upstream_cache_capture(
                pending,
                upstream_response,
                ctx.body_mask.enabled,
            )
        {
            ctx.response_cache_store = None;
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        // Body mask runs first: when enabled, `begin_upstream_cache_capture` already
        // declined capture (`capture_started == false`), so the cache branch below is a no-op.
        if ctx.body_mask.enabled {
            let Some(hc) = &ctx.host_config else {
                return Ok(None);
            };
            let compiled = self.resolve_mask(hc);
            apply_body_mask_chunk(&mut ctx.body_mask, &compiled, body, end_of_stream);
            return Ok(None);
        }

        if let Some(cache) = &self.response_cache {
            crate::response_cache_integration::cache_store_on_body_chunk(
                cache,
                &mut ctx.response_cache_store,
                body,
                end_of_stream,
            );
        }

        Ok(None)
    }

    /// AC-19: render a neutral, content-negotiated error page (no Pingora fingerprint).
    ///
    /// Maps the error to an HTTP status using the same heuristics as the trait
    /// default, then writes our own headers+body so the response is free of any
    /// Pingora-default markers (`Server: pingora/...`, default HTML page, etc.).
    async fn fail_to_proxy(&self, session: &mut Session, e: &pingora_core::Error, _ctx: &mut Self::CTX) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let code = error_to_status(e);
        if code > 0 {
            let accept = session
                .get_header("accept")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                .map(str::to_string);
            match ErrorPageFactory::render(code, accept.as_deref()) {
                Ok((headers, body)) => {
                    if let Err(write_err) = session.write_response_header(Box::new(headers), false).await {
                        warn!("failed to write error header to downstream: {write_err}");
                    } else if let Err(write_err) = session.write_response_body(Some(body), true).await {
                        warn!("failed to write error body to downstream: {write_err}");
                    }
                }
                Err(render_err) => {
                    warn!("error-page render failed: {render_err}");
                }
            }
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    async fn logging(&self, _session: &mut Session, _error: Option<&pingora_core::Error>, ctx: &mut GatewayCtx) {
        if let Some(req_ctx) = &ctx.request_ctx {
            debug!(
                tier = ?req_ctx.tier,
                "Request completed: {} {} {} → upstream={}",
                req_ctx.method,
                req_ctx.host,
                req_ctx.path,
                ctx.upstream_addr.as_deref().unwrap_or("unknown"),
            );
        }
    }
}
