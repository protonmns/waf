//! WAF security-event audit sender.
//!
//! Layer 2 of the `VictoriaLogs` pipeline (Layer 1 is `tracing`).  Whereas
//! the `tracing` Layer captures every log line emitted by the WAF process,
//! this sender only records **access decisions** — block / allow on a
//! whitelist hit / rate-limit / challenge.  Each event carries a fixed
//! schema so downstream `LogsQL` queries are deterministic and SIEM
//! ingestion is straightforward.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::batch_buffer::BatchSender;

/// High-level event category.  Mapped 1:1 to a string in the JSON payload
/// so `VictoriaLogs` filters can use `event_type:block` etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// WAF blocked the request.
    Block,
    /// WAF allowed the request via an explicit whitelist match.
    Allow,
    /// WAF requested a CAPTCHA / challenge.
    Challenge,
    /// WAF rate-limited the request.
    RateLimit,
    /// WAF logged-only mode — would have blocked in enforce mode.
    LogOnly,
}

impl AuditEventType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Allow => "allow",
            Self::Challenge => "challenge",
            Self::RateLimit => "rate_limit",
            Self::LogOnly => "log_only",
        }
    }
}

/// Path truncation cap.  Keeps individual log lines bounded so `VictoriaLogs`
/// indexing stays cheap even if an attacker crafts huge URIs.
const PATH_TRUNCATE_AT: usize = 500;

/// Structured WAF audit event.  Field names match the `LogsQL` queries used
/// by the admin panel — do not rename them without updating the FE.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: AuditEventType,
    pub rule_name: String,
    pub rule_id: Option<String>,
    pub phase: Option<String>,
    pub client_ip: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub tier: Option<String>,
    pub detail: Option<String>,
    pub req_id: Option<String>,
}

/// Fire-and-forget audit sink.  Cloning is cheap (`Arc` internally).
#[derive(Clone)]
pub struct AuditSender {
    inner: Arc<Inner>,
}

struct Inner {
    buffer: BatchSender,
}

impl AuditSender {
    /// Wrap a [`BatchSender`] dedicated to audit events.
    pub fn new(buffer: BatchSender) -> Self {
        Self {
            inner: Arc::new(Inner { buffer }),
        }
    }

    /// Send an event without blocking the caller. Drops silently when
    /// `VictoriaLogs` is unreachable so the WAF request path is never gated
    /// on observability availability.
    pub fn send(&self, event: AuditEvent) {
        if !self.inner.buffer.is_active() {
            return;
        }

        let path = if event.path.len() > PATH_TRUNCATE_AT {
            // Slice on a UTF-8 char boundary to stay safe for non-ASCII URIs.
            let mut end = PATH_TRUNCATE_AT;
            while end > 0 && !event.path.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}…", &event.path[..end])
        } else {
            event.path
        };

        let payload = json!({
            "_time": event.timestamp.to_rfc3339(),
            "_msg": format!(
                "{} {} {} → {} (rule={})",
                event.event_type.as_str(),
                event.method,
                path,
                event.client_ip,
                event.rule_name,
            ),
            "event_type": event.event_type.as_str(),
            "rule_name": event.rule_name,
            "rule_id": event.rule_id,
            "phase": event.phase,
            "client_ip": event.client_ip,
            "host": event.host,
            "method": event.method,
            "path": path,
            "tier": event.tier,
            "detail": event.detail,
            "req_id": event.req_id,
            "stream": "waf_audit",
        });
        self.inner.buffer.try_send(payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_string_round_trip() {
        assert_eq!(AuditEventType::Block.as_str(), "block");
        assert_eq!(AuditEventType::Allow.as_str(), "allow");
        assert_eq!(AuditEventType::Challenge.as_str(), "challenge");
        assert_eq!(AuditEventType::RateLimit.as_str(), "rate_limit");
        assert_eq!(AuditEventType::LogOnly.as_str(), "log_only");
    }

    #[test]
    fn path_truncation_respects_utf8_boundaries() {
        let mut p = String::new();
        // 'é' is 2 bytes in UTF-8; pushing > PATH_TRUNCATE_AT/2 chars
        // guarantees we cross the cap and exercise the boundary walk.
        for _ in 0..(PATH_TRUNCATE_AT) {
            p.push('é');
        }
        assert!(p.len() > PATH_TRUNCATE_AT);
        // Use the same logic as `send` for the boundary calculation.
        let mut end = PATH_TRUNCATE_AT;
        while end > 0 && !p.is_char_boundary(end) {
            end -= 1;
        }
        let truncated = &p[..end];
        assert!(truncated.is_char_boundary(0));
        assert!(truncated.len() <= PATH_TRUNCATE_AT);
    }
}
