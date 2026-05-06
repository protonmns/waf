//! Cache management API handlers.
//!
//! Existing endpoints (unchanged semantics):
//! - `GET  /api/cache/stats`
//! - `POST /api/cache/purge/tag`
//! - `POST /api/cache/purge/route`
//! - `DELETE /api/cache`
//! - `DELETE /api/cache/host/:host`
//! - `DELETE /api/cache/key`
//!
//! New endpoints (FR-009 / Valkey dashboard):
//! - `GET /api/cache/backend`
//! - `GET /api/cache/stats/timeseries?minutes=60`
//! - `GET /api/cache/routes/top?limit=20`
//! - `GET /api/cache/tags`

use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use serde_json::{Map, Value};

use crate::state::AppState;

/// Admin API hint when destructive SCAN-based ops may not cover the whole cluster.
fn cluster_scan_purge_warning(info: &gateway::BackendInfo) -> Option<&'static str> {
    if info.backend == "cluster" {
        Some(
            "cluster mode: SCAN-based flush and purge_host are best-effort and node-local; keys on other shards may remain",
        )
    } else {
        None
    }
}

/// Max length for a tag or `route_id` received over the admin API.
const MAX_TAG_LEN: usize = 64;

fn validate_tag(raw: &str) -> Result<&str, &'static str> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("must not be empty");
    }
    if t.len() > MAX_TAG_LEN {
        return Err("must be 64 chars or fewer");
    }
    if !t
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':'))
    {
        return Err("only ASCII alnum and `_`, `-`, `:` allowed");
    }
    Ok(t)
}

// ── Request/response types ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PurgeTagBody {
    pub tag: String,
}

#[derive(Deserialize)]
pub struct PurgeRouteBody {
    pub route_id: String,
}

#[derive(Deserialize)]
pub struct TimeseriesQuery {
    #[serde(default = "default_minutes")]
    pub minutes: usize,
}

const fn default_minutes() -> usize {
    60
}

#[derive(Deserialize)]
pub struct TopRoutesQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

const fn default_limit() -> usize {
    20
}

// ── Existing endpoints ────────────────────────────────────────────────────────

/// GET /api/cache/stats — cache hit/miss/eviction counters (extended with
/// `hit_ratio`, backend name, and `last_updated_at` timestamp).
pub async fn cache_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let snap = state.cache.stats();
    let count = state.cache.entry_count();
    let tag_index = state.cache.tag_index_size();
    let hit_ratio = snap.hit_ratio();
    let backend_info = state.cache.backend_info_for_stats_panel().await;

    (
        StatusCode::OK,
        Json(json!({
            // Base counters
            "hits": snap.hits,
            "misses": snap.misses,
            "evictions": snap.evictions,
            "stores": snap.stores,
            "entry_count": count,
            // FR-009 Phase 3 audit signals
            "bypassed_critical": snap.bypassed_critical,
            "bypassed_authenticated": snap.bypassed_authenticated,
            "bypassed_explicit_deny": snap.bypassed_explicit_deny,
            // FR-009 Phase 4 purge counters + tag-index gauge
            "purges_tag": snap.purges_tag,
            "purges_route": snap.purges_route,
            "tag_index_size": tag_index,
            // New (Valkey dashboard)
            "hit_ratio": hit_ratio,
            "backend": backend_info.backend,
            "memory_used_bytes": backend_info.memory_used_bytes,
            "memory_max_bytes": backend_info.memory_max_bytes,
            "memory_fragmentation_ratio": backend_info.memory_fragmentation_ratio,
            "valkey_ops_per_sec": backend_info.ops_per_sec,
            "connected_clients": backend_info.connected_clients,
            "last_updated_at": chrono::Utc::now().to_rfc3339(),
        })),
    )
        .into_response()
}

/// POST /api/cache/purge/tag — purge every entry tagged with `tag`.
pub async fn cache_purge_tag(State(state): State<Arc<AppState>>, Json(body): Json<PurgeTagBody>) -> impl IntoResponse {
    let tag = match validate_tag(&body.tag) {
        Ok(t) => t.to_string(),
        Err(reason) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error": format!("invalid tag: {reason}") })),
            )
                .into_response();
        }
    };
    let started = Instant::now();
    let purged = state.cache.purge_by_tag(&tag).await;
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "purged": purged,
            "duration_ms": started.elapsed().as_millis(),
        })),
    )
        .into_response()
}

/// POST /api/cache/purge/route — purge every entry cached by the rule with
/// this `route_id`.
pub async fn cache_purge_route(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PurgeRouteBody>,
) -> impl IntoResponse {
    let route_id = match validate_tag(&body.route_id) {
        Ok(t) => t.to_string(),
        Err(reason) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error": format!("invalid route_id: {reason}") })),
            )
                .into_response();
        }
    };
    let started = Instant::now();
    let purged = state.cache.purge_by_route_id(&route_id).await;
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "purged": purged,
            "duration_ms": started.elapsed().as_millis(),
        })),
    )
        .into_response()
}

/// DELETE /api/cache — flush the entire cache.
pub async fn cache_flush(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let info = state.cache.backend_info().await;
    let warn = cluster_scan_purge_warning(&info);
    state.cache.flush().await;
    let mut body = Map::new();
    body.insert("flushed".to_string(), json!(true));
    if let Some(w) = warn {
        body.insert("warning".to_string(), json!(w));
    }
    (StatusCode::OK, Json(Value::Object(body))).into_response()
}

/// DELETE /api/cache/host/:host — flush all entries for a given host.
pub async fn cache_flush_host(State(state): State<Arc<AppState>>, Path(host): Path<String>) -> impl IntoResponse {
    let info = state.cache.backend_info().await;
    let warn = cluster_scan_purge_warning(&info);
    state.cache.purge_host(&host).await;
    let mut body = Map::new();
    body.insert("flushed_host".to_string(), json!(host.clone()));
    if let Some(w) = warn {
        body.insert("warning".to_string(), json!(w));
    }
    (StatusCode::OK, Json(Value::Object(body))).into_response()
}

/// DELETE /api/cache/key — flush a specific cache key (`?key=<encoded-key>`).
#[allow(clippy::implicit_hasher)]
pub async fn cache_flush_key(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let key = match params.get("key") {
        Some(k) => k.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "key query parameter required" })),
            )
                .into_response();
        }
    };
    state.cache.purge_key(&key).await;
    (StatusCode::OK, Json(json!({ "flushed_key": key }))).into_response()
}

// ── New dashboard endpoints ───────────────────────────────────────────────────

/// GET /api/cache/backend — backend identity, health, and memory stats.
pub async fn cache_backend_info(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let info = state.cache.backend_info().await;
    (StatusCode::OK, Json(info)).into_response()
}

/// GET /api/cache/stats/timeseries?minutes=60 — per-minute hit/miss timeseries.
pub async fn cache_stats_timeseries(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TimeseriesQuery>,
) -> impl IntoResponse {
    let minutes = q.minutes.clamp(1, 60);
    let buckets = state.cache.timeseries(minutes);

    // Convert bucket timestamps to RFC-3339 strings for the frontend.
    let payload: Vec<serde_json::Value> = buckets
        .into_iter()
        .map(|b| {
            let ts = chrono::DateTime::from_timestamp(i64::try_from(b.ts).unwrap_or(0), 0)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default();
            json!({
                "ts": ts,
                "hits": b.hits,
                "misses": b.misses,
                "hit_ratio": b.hit_ratio,
                "memory_used_bytes": b.memory_used_bytes,
                "stores": b.stores,
            })
        })
        .collect();

    (StatusCode::OK, Json(payload)).into_response()
}

/// GET /api/cache/routes/top?limit=20 — top cached routes by hit count.
pub async fn cache_top_routes(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TopRoutesQuery>,
) -> impl IntoResponse {
    let limit = q.limit.clamp(1, 100);
    let routes = state.cache.top_routes(limit).await;
    (StatusCode::OK, Json(routes)).into_response()
}

/// GET /api/cache/tags — list all tags with entry counts.
pub async fn cache_list_tags(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let tags_data: Vec<serde_json::Value> = state
        .cache
        .tag_entry_counts()
        .await
        .into_iter()
        .map(|(tag, entry_count)| json!({ "tag": tag, "entry_count": entry_count }))
        .collect();
    let total_tags = tags_data.len();
    (
        StatusCode::OK,
        Json(json!({ "total_tags": total_tags, "tags": tags_data })),
    )
        .into_response()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_tag_accepts_empty_after_trim_with_whitespace_only() {
        assert!(matches!(validate_tag("   "), Err("must not be empty")));
    }

    #[test]
    fn validate_tag_rejects_empty_string() {
        assert!(matches!(validate_tag(""), Err("must not be empty")));
    }

    #[test]
    fn validate_tag_accepts_basic_alphanumeric() {
        assert_eq!(validate_tag("catalog"), Ok("catalog"));
        assert_eq!(validate_tag("Cache123"), Ok("Cache123"));
    }

    #[test]
    fn validate_tag_accepts_underscore() {
        assert_eq!(validate_tag("catalog_v2"), Ok("catalog_v2"));
        assert_eq!(validate_tag("_private"), Ok("_private"));
    }

    #[test]
    fn validate_tag_accepts_hyphen() {
        assert_eq!(validate_tag("catalog-items"), Ok("catalog-items"));
        assert_eq!(validate_tag("api-routes-v1"), Ok("api-routes-v1"));
    }

    #[test]
    fn validate_tag_accepts_colon() {
        assert_eq!(validate_tag("app:cache:v1"), Ok("app:cache:v1"));
        assert_eq!(validate_tag("rule:123"), Ok("rule:123"));
    }

    #[test]
    fn validate_tag_trims_whitespace() {
        assert_eq!(validate_tag("  catalog  "), Ok("catalog"));
        assert_eq!(validate_tag("\tcatalog\n"), Ok("catalog"));
    }

    #[test]
    fn validate_tag_rejects_at_65_chars() {
        let invalid_65 = "a".repeat(65);
        assert!(matches!(validate_tag(&invalid_65), Err("must be 64 chars or fewer")));
    }

    #[test]
    fn validate_tag_rejects_semicolon() {
        assert!(matches!(
            validate_tag("catalog;drop"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }

    #[test]
    fn validate_tag_rejects_internal_space() {
        assert!(matches!(
            validate_tag("foo bar"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }

    #[test]
    fn validate_tag_rejects_newline_embedded() {
        assert!(matches!(
            validate_tag("foo\nbar"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }

    #[test]
    fn validate_tag_rejects_tab_embedded() {
        assert!(matches!(
            validate_tag("foo\tbar"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }

    #[test]
    fn validate_tag_rejects_slash() {
        assert!(matches!(
            validate_tag("a/b"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }
}
