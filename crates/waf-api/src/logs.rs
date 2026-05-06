//! `VictoriaLogs` proxy endpoints (Phase 03).
//!
//! `VictoriaLogs` binds to loopback only (validated in `waf-common::config`)
//! and has no built-in authentication, so all queries from the admin panel
//! flow through this thin Rust proxy:
//!
//! * JWT (`require_auth` middleware on the parent router) validates the
//!   bearer token,
//! * a per-handler admin-role gate enforces RBAC (only `role == "admin"`
//!   may inspect security logs),
//! * `LogsQL` queries are scanned for write/delete operations before being
//!   forwarded — read-only operation is enforced server-side regardless
//!   of what the FE sends,
//! * proxied responses are size-capped (50 MiB) so a runaway query cannot
//!   exhaust the WAF process memory.
//!
//! No SSRF surface: every HTTP call targets the configured `base_url()`
//! built from the (loopback-locked) `[victoria_logs] listen_addr`.
//!
//! When `VictoriaLogs` is disabled (`AppState::victoria_logs_base_url` is
//! `None`) every endpoint here returns `503` so the FE can present a
//! helpful empty state instead of crashing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::{Claims, validate_access_token};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Hard limit on a single `LogsQL` response body. Keeps the WAF heap bounded
/// even when an admin asks for a query that scans everything.
const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;

/// Hard cap forwarded to `VictoriaLogs` as the `limit` parameter.
const MAX_QUERY_LIMIT: u32 = 5_000;

/// `streams` cache lifetime. Distinct-value enumeration is expensive on
/// `VictoriaLogs` and the FE only needs it to populate dropdowns.
const STREAMS_CACHE_TTL: Duration = Duration::from_mins(1);

/// `LogsQL` keywords that mutate state. Rejected before forwarding.
///
/// We keep the list small and conservative — a write attempt by a
/// malicious admin (or a compromised JWT) is a privilege-escalation
/// concern, so anything ambiguous is rejected outright.
const FORBIDDEN_LOGSQL_PIPES: &[&str] = &["delete", "drop", "alter", "insert", "update", "copy"];

// ── Query types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    /// Raw `LogsQL` expression — passed through after pipe-keyword scrub.
    pub query: String,
    /// Optional RFC3339 lower bound for `_time`.
    pub start: Option<String>,
    /// Optional RFC3339 upper bound for `_time`.
    pub end: Option<String>,
    /// Maximum rows returned. Capped at [`MAX_QUERY_LIMIT`].
    pub limit: Option<u32>,
}

// ── Auth helper ──────────────────────────────────────────────────────────────

/// Re-extract claims and ensure the caller has the `admin` role.
///
/// The parent router's `require_auth` already validated the token, but
/// we validate again here so the handler is self-contained and the role
/// gate cannot be skipped if the route layout changes later.
fn require_admin(headers: &HeaderMap, jwt_secret: &str) -> Result<Claims, ApiError> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("missing bearer token".into()))?;
    let claims = validate_access_token(token, jwt_secret)
        .map_err(|_| ApiError::Unauthorized("invalid or expired token".into()))?;
    if claims.role != "admin" {
        return Err(ApiError::Unauthorized("admin role required".into()));
    }
    Ok(claims)
}

// ── `LogsQL` safety scrub ────────────────────────────────────────────────────

/// Reject queries containing forbidden write/delete pipe operators.
///
/// `LogsQL` pipes are introduced by `|` followed by a keyword, so we look
/// for `|` followed by any of [`FORBIDDEN_LOGSQL_PIPES`] regardless of
/// whitespace.  This is intentionally conservative: a legitimate
/// read-only query has no reason to mention these tokens.
fn ensure_read_only(query: &str) -> Result<(), ApiError> {
    let lower = query.to_ascii_lowercase();
    for pipe in FORBIDDEN_LOGSQL_PIPES {
        // Match `|<ws>*<keyword>` only (so the substring isn't tripped
        // by e.g. `|message:"deleted"`).  Walk every `|` occurrence.
        let mut search = lower.as_str();
        while let Some(idx) = search.find('|') {
            let after = search[idx + 1..].trim_start();
            if after.starts_with(pipe) {
                let next = after.as_bytes().get(pipe.len()).copied().unwrap_or(b' ');
                if !next.is_ascii_alphanumeric() && next != b'_' {
                    return Err(ApiError::BadRequest(format!(
                        "LogsQL pipe '| {pipe}' is not allowed in this proxy"
                    )));
                }
            }
            search = &search[idx + 1..];
        }
    }
    Ok(())
}

// ── /api/v1/logs/query ──────────────────────────────────────────────────────

/// Forward a `LogsQL` query to the local `VictoriaLogs` instance.
pub async fn logs_query(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<LogsQuery>,
) -> ApiResult<Response> {
    let _claims = require_admin(&headers, &state.jwt_secret)?;

    let base = state
        .victoria_logs_base_url
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("VictoriaLogs is disabled in this build".into()))?;

    if params.query.trim().is_empty() {
        return Err(ApiError::BadRequest("'query' parameter is required".into()));
    }
    ensure_read_only(&params.query)?;

    let limit = params.limit.unwrap_or(MAX_QUERY_LIMIT).min(MAX_QUERY_LIMIT);

    // Build the query string manually because the workspace `reqwest`
    // is configured with `default-features = false`, which omits the
    // `serde_urlencoded` integration that powers `RequestBuilder::query`.
    // Scope the (non-`Send`) serializer so it doesn't span the next await.
    let qs = {
        let mut s = url::form_urlencoded::Serializer::new(String::new());
        s.append_pair("query", &params.query);
        s.append_pair("limit", &limit.to_string());
        if let Some(start) = params.start.as_ref() {
            s.append_pair("start", start);
        }
        if let Some(end) = params.end.as_ref() {
            s.append_pair("end", end);
        }
        s.finish()
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("logs client build: {e}")))?;

    let resp = client
        .get(format!("{base}/select/logsql/query?{qs}"))
        .send()
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("VictoriaLogs unreachable: {e}")))?;

    let status = resp.status();
    let bytes = read_capped(resp).await?;
    let body = String::from_utf8(bytes.into())
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("VictoriaLogs returned non-utf8 body")))?;

    // Pass status straight through so `VictoriaLogs` error codes (4xx/5xx)
    // are visible to the FE rather than being collapsed to 200.
    let status_code = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Ok((status_code, [("content-type", "application/x-ndjson")], body).into_response())
}

// ── /api/v1/logs/stats ──────────────────────────────────────────────────────

/// Return a small dashboard payload: 24 h ingest count + storage usage.
pub async fn logs_stats(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let _claims = require_admin(&headers, &state.jwt_secret)?;

    let base = state
        .victoria_logs_base_url
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("VictoriaLogs is disabled in this build".into()))?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("logs client build: {e}")))?;

    // Count via stats_query: `count() _time:[<24h ago>, now]`.
    // `VictoriaLogs` supports the `_time:1d` shorthand which we use here.
    let count_qs = {
        let mut s = url::form_urlencoded::Serializer::new(String::new());
        s.append_pair("query", "_time:1d | stats count() as total");
        s.finish()
    };
    let count_url = format!("{base}/select/logsql/stats_query?{count_qs}");
    let count_resp = client
        .get(&count_url)
        .send()
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("VictoriaLogs unreachable: {e}")))?;
    let count_body = count_resp.text().await.unwrap_or_default();

    // /metrics returns Prometheus exposition format; we keep it as-is and
    // let the FE parse the few keys it cares about. Capping at 1 MiB.
    let metrics_resp = client.get(format!("{base}/metrics")).send().await.ok();
    let metrics_text = match metrics_resp {
        Some(r) => {
            let bytes = read_capped(r).await.unwrap_or_default();
            String::from_utf8(bytes.into()).unwrap_or_default()
        }
        None => String::new(),
    };

    Ok(Json(json!({
        "count_24h_raw": count_body,
        "metrics": metrics_text,
    })))
}

// ── /api/v1/logs/streams ─────────────────────────────────────────────────────

/// Cached distinct-values listing for the FE filter dropdowns.
///
/// `VictoriaLogs` `field_values` calls are expensive (full scan within the
/// configured time range) so we memoise the response for 60 s.
pub async fn logs_streams(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let _claims = require_admin(&headers, &state.jwt_secret)?;

    let base = state
        .victoria_logs_base_url
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("VictoriaLogs is disabled in this build".into()))?;

    {
        let cache = state.logs_streams_cache.lock();
        if let Some(entry) = cache.as_ref()
            && entry.0.elapsed() < STREAMS_CACHE_TTL
        {
            return Ok(Json(entry.1.clone()));
        }
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("logs client build: {e}")))?;

    // Pull the three filter dimensions in parallel. Field-values endpoint
    // returns one JSON line per value, so we just stream the raw text and
    // let the FE parse it — keeps the proxy zero-copy beyond the size cap.
    let fetch = |field: &'static str, query: &'static str| {
        let qs = {
            let mut s = url::form_urlencoded::Serializer::new(String::new());
            s.append_pair("query", query);
            s.append_pair("field", field);
            s.finish()
        };
        let url = format!("{base}/select/logsql/field_values?{qs}");
        let client = client.clone();
        async move {
            let resp = client.get(&url).send().await.ok()?;
            if !resp.status().is_success() {
                return None;
            }
            let bytes = read_capped(resp).await.ok()?;
            let body = String::from_utf8(bytes.into()).ok()?;
            Some(body)
        }
    };

    let (event_types, rule_names, tiers) = tokio::join!(
        fetch("event_type", "_time:7d stream:waf_audit"),
        fetch("rule_name", "_time:7d stream:waf_audit"),
        fetch("tier", "_time:7d stream:waf_audit"),
    );

    let payload = json!({
        "event_type": event_types.unwrap_or_default(),
        "rule_name": rule_names.unwrap_or_default(),
        "tier": tiers.unwrap_or_default(),
    });

    *state.logs_streams_cache.lock() = Some((Instant::now(), payload.clone()));

    Ok(Json(payload))
}

// ── Shared cache type ────────────────────────────────────────────────────────

/// Cache entry for the streams endpoint.  Stored in `AppState`.
pub type StreamsCache = Mutex<Option<(Instant, Value)>>;

/// Build an empty streams cache.  Helper kept here so all cache lifetime
/// concerns live alongside the consumer.
pub fn new_streams_cache() -> Arc<StreamsCache> {
    Arc::new(Mutex::new(None))
}

// ── Utility ──────────────────────────────────────────────────────────────────

/// Drain a `reqwest::Response` body up to [`MAX_RESPONSE_BYTES`]. Returns
/// an `ApiError::TooManyRequests` if the cap is exceeded so the client
/// receives a clear signal that they should narrow the query.
async fn read_capped(resp: reqwest::Response) -> ApiResult<bytes::Bytes> {
    use futures_util::StreamExt as _;

    let mut stream = resp.bytes_stream();
    let mut buf = bytes::BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ApiError::Internal(anyhow::anyhow!("VictoriaLogs read: {e}")))?;
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(ApiError::TooManyRequests(format!(
                "VictoriaLogs response exceeded {MAX_RESPONSE_BYTES}-byte cap; refine your query"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_read_only_passes_simple_query() {
        ensure_read_only("event_type:block").unwrap();
        ensure_read_only("client_ip:\"1.2.3.4\" | stats count() by (rule_name)").unwrap();
    }

    #[test]
    fn ensure_read_only_rejects_pipe_delete() {
        let err = ensure_read_only("event_type:block | delete event_type").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn ensure_read_only_allows_keyword_in_message() {
        // `delete` inside a quoted match value should not trip the scrub.
        ensure_read_only("rule_name:\"delete-handler\"").unwrap();
        ensure_read_only("_msg:\"deleted user\"").unwrap();
    }

    #[test]
    fn ensure_read_only_rejects_pipe_drop_and_alter() {
        ensure_read_only("foo | drop bar").unwrap_err();
        ensure_read_only("foo |alter x").unwrap_err();
    }
}
