//! FR-009: serve cached responses from [`crate::cache::ResponseCache`] and
//! asynchronously store upstream bodies after the proxy path completes.

use std::sync::Arc;

use pingora_proxy::Session;

use crate::cache::{CachedResponse, ResponseCache};
use crate::context::{RESPONSE_CACHE_BODY_LIMIT, ResponseCachePending};

/// Write a cache hit to the downstream session and finish the exchange.
pub async fn write_cached_entry(session: &mut Session, entry: &Arc<CachedResponse>) -> pingora_core::Result<()> {
    let status = http::StatusCode::from_u16(entry.status).unwrap_or(http::StatusCode::OK);
    let mut resp = pingora_http::ResponseHeader::build(status, None)?;
    for (k, v) in &entry.headers {
        let _ = resp.insert_header(k.clone(), v.clone());
    }
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(bytes::Bytes::clone(&entry.body)), true)
        .await?;
    Ok(())
}

fn collect_response_headers(resp: &pingora_http::ResponseHeader) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in &resp.headers {
        let name_s = name.as_str();
        let Ok(val_s) = value.to_str() else {
            continue;
        };
        out.push((name_s.to_string(), val_s.to_string()));
    }
    out
}

/// `Content-Encoding` is cacheable when absent, empty, or `identity` (no gzip/br/etc.).
///
/// Uses the **current** response headers (after `response_chain` runs when host context exists).
fn response_content_encoding_allows_cache(resp: &pingora_http::ResponseHeader) -> bool {
    resp.headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| {
            let v = v.trim();
            v.is_empty() || v.eq_ignore_ascii_case("identity")
        })
}

/// Returns `false` when the upstream response must not be cached.
pub fn begin_upstream_cache_capture(
    pending: &mut ResponseCachePending,
    upstream_response: &pingora_http::ResponseHeader,
    body_mask_enabled: bool,
) -> bool {
    if body_mask_enabled || !response_content_encoding_allows_cache(upstream_response) {
        return false;
    }
    let status = upstream_response.status.as_u16();
    if !(200..300).contains(&status) {
        return false;
    }
    if upstream_response.headers.contains_key("vary") {
        tracing::debug!(
            cache_key = %pending.key,
            "response cache: skipping capture due to Vary header"
        );
        return false;
    }
    pending.status = status;
    pending.headers = collect_response_headers(upstream_response);
    pending.cache_control = upstream_response
        .headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);
    pending.capture_started = true;
    true
}

/// Append body bytes; on end-of-stream spawn async `put` into [`ResponseCache`].
pub fn cache_store_on_body_chunk(
    cache: &Arc<ResponseCache>,
    pending: &mut Option<ResponseCachePending>,
    body: &mut Option<bytes::Bytes>,
    end_of_stream: bool,
) {
    let Some(p) = pending.as_mut() else {
        return;
    };
    if !p.capture_started {
        return;
    }
    if let Some(chunk) = body {
        let room = RESPONSE_CACHE_BODY_LIMIT.saturating_sub(p.body.len());
        if room > 0 {
            let take = chunk.len().min(room);
            if let Some(s) = chunk.get(..take) {
                p.body.extend_from_slice(s);
            }
        }
    }
    if end_of_stream {
        let Some(done) = pending.take() else {
            return;
        };
        spawn_cache_store_task(Arc::clone(cache), done);
    }
}

fn spawn_cache_store_task(cache: Arc<ResponseCache>, pending: ResponseCachePending) {
    let body = pending.body.freeze();
    let key = pending.key;
    let host = pending.host;
    let path = pending.path;
    let status = pending.status;
    let headers = pending.headers;
    let cc = pending.cache_control;
    let tier = pending.tier;
    let policy = pending.cache_policy;
    let auth = pending.has_authorization;
    let cookie = pending.has_cookie;
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let _stored = cache
                .put(
                    key,
                    &host,
                    &path,
                    status,
                    headers,
                    body,
                    cc.as_deref(),
                    tier,
                    &policy,
                    auth,
                    cookie,
                )
                .await;
        });
    } else {
        tracing::warn!("response cache store skipped: no tokio runtime handle");
    }
}
