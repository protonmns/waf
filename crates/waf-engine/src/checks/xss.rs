use std::sync::LazyLock;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::xss_scanners::{scan_form_urlencoded, scan_json_body_xss};
use super::{Check, request_targets};

pub(crate) static XSS_DESCS: &[&str] = &[
    "<script> tag",
    "event handler attribute (on*=)",
    "javascript: URI",
    "vbscript: URI",
    "CSS expression()",
    "data:text/html URI",
    "document.cookie / document.write access",
    "eval() call",
    ".innerHTML assignment",
    "String.fromCharCode() obfuscation",
    "HTML numeric character reference (&#...)",
    "<svg> with event handler",
    "<img> with javascript: src",
    "<iframe> injection",
    "<object>/<embed> injection",
    "<svg>/<math> inline vector",
];

// SAFETY: All patterns are compile-time string literals. If any pattern fails
// to compile it is a code bug that must be caught in development, not at runtime.
pub(crate) static XSS_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    match RegexSet::new([
        // <script...>
        r"(?i)<\s*/?\s*script[\s/>]",
        // Event handlers: on[event]=
        r"(?i)\bon(abort|blur|change|click|dblclick|drag|drop|error|focus|hashchange|input|keydown|keypress|keyup|load|message|mousedown|mousemove|mouseout|mouseover|mouseup|paste|popstate|reset|resize|scroll|select|submit|touchend|touchmove|touchstart|unload|wheel)\s*=",
        // javascript: (allow whitespace/encoding obfuscation)
        r"(?i)j[\s]*a[\s]*v[\s]*a[\s]*s[\s]*c[\s]*r[\s]*i[\s]*p[\s]*t[\s]*:",
        // vbscript:
        r"(?i)v[\s]*b[\s]*s[\s]*c[\s]*r[\s]*i[\s]*p[\s]*t[\s]*:",
        // CSS expression()
        r"(?i)expression\s*\(",
        // data: URIs with html content
        r"(?i)data:\s*text/html",
        // document.cookie / document.write / document.location
        r"(?i)document\s*\.\s*(cookie|write|writeln|body|location|domain|referrer)",
        // eval(
        r"(?i)\beval\s*\(",
        // .innerHTML =
        r"(?i)\.innerHTML\s*=",
        // fromCharCode
        r"(?i)\bfromCharCode\b",
        // HTML numeric entities &#x41; or &#65;
        r"&#\s*(x\s*[0-9a-fA-F]+|[0-9]+)\s*;",
        // <svg onload=...>
        r"(?i)<\s*svg[^>]*\bon\w+\s*=",
        // <img src=javascript:
        r"(?i)<\s*img[^>]*src\s*=\s*javascript:",
        // <iframe ...>
        r"(?i)<\s*iframe[\s/>]",
        // <object> / <embed>
        r"(?i)<\s*(object|embed)[\s/>]",
        // Inline SVG/MathML vectors
        r"(?i)<\s*(svg|math)[\s/>]",
    ]) {
        Ok(set) => set,
        Err(e) => {
            tracing::error!("BUG: XSS regex set failed to compile: {e}");
            RegexSet::empty()
        }
    }
});

/// XSS detection checker.
pub struct XssCheck;

impl XssCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for XssCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for XssCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.xss {
            return None;
        }

        // Content-Type-aware body inspection runs first so structured payloads
        // (JSON / form-urlencoded) get precise location attribution before the
        // raw-bytes fallback in `request_targets()`.
        let content_type = ctx
            .headers
            .get("content-type")
            .map_or("", String::as_str)
            .to_ascii_lowercase();
        let body_cap = ctx.host_config.defense_config.max_body_size;

        if !ctx.body_preview.is_empty() {
            if content_type.starts_with("application/json")
                && let Some((path, idx)) = scan_json_body_xss(&ctx.body_preview, &XSS_SET, body_cap)
            {
                return Some(detection_at(idx, &path));
            } else if content_type.starts_with("application/x-www-form-urlencoded")
                && let Some((loc, idx)) = scan_form_urlencoded(&ctx.body_preview, &XSS_SET)
            {
                return Some(detection_at(idx, &loc));
            }
        }

        // `text/markdown` legitimately contains `<script` snippets in code
        // blocks; skip the raw-body location to suppress false positives.
        // Non-body locations (path / query / cookie) still scan normally.
        let skip_body = content_type.starts_with("text/markdown");

        for (location, value) in request_targets(ctx) {
            if skip_body && location.starts_with("body") {
                continue;
            }
            let matches = XSS_SET.matches(&value);
            if matches.matched_any() {
                let idx = matches.iter().next().unwrap_or(0);
                return Some(detection_at(idx, location));
            }
        }
        None
    }
}

fn detection_at(idx: usize, location: &str) -> DetectionResult {
    let desc = XSS_DESCS.get(idx).copied().unwrap_or("XSS pattern");
    DetectionResult {
        rule_id: Some(format!("XSS-{:03}", idx + 1)),
        rule_name: "XSS".to_string(),
        phase: Phase::Xss,
        detail: format!("{desc} detected in {location}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx(query: &str, body: &str) -> RequestCtx {
        make_ctx_with(query, body, "", true)
    }

    fn make_ctx_with(query: &str, body: &str, content_type: &str, xss_enabled: bool) -> RequestCtx {
        let mut headers = HashMap::new();
        if !content_type.is_empty() {
            headers.insert("content-type".to_string(), content_type.to_string());
        }
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "POST".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: query.to_string(),
            headers,
            body_preview: Bytes::from(body.to_string()),
            content_length: body.len() as u64,
            is_tls: false,
            host_config: Arc::new(HostConfig {
                defense_config: DefenseConfig {
                    xss: xss_enabled,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            }),
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn detects_script_tag() {
        let checker = XssCheck::new();
        let ctx = make_ctx("q=<script>alert(1)</script>", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_event_handler() {
        let checker = XssCheck::new();
        let ctx = make_ctx("", "name=<img onerror=alert(1)>");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_javascript_uri() {
        let checker = XssCheck::new();
        let ctx = make_ctx("url=javascript:alert(1)", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn allows_clean_request() {
        let checker = XssCheck::new();
        let ctx = make_ctx("q=hello+world&page=1", "");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn detects_script_tag_double_encoded_in_query() {
        // %253Cscript%253E → %3Cscript%3E → <script> after recursive decode.
        let checker = XssCheck::new();
        let ctx = make_ctx("q=%253Cscript%253Ealert(1)%253C/script%253E", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_xss_in_json_body_with_path_attribution() {
        let checker = XssCheck::new();
        let ctx = make_ctx_with("", r#"{"a":{"b":"<script>"}}"#, "application/json", true);
        let det = checker.check(&ctx).expect("hit");
        assert!(det.detail.contains("body.json.a.b"));
    }

    #[test]
    fn detects_xss_in_json_array() {
        let checker = XssCheck::new();
        let ctx = make_ctx_with("", r#"["safe","<img onerror=x>"]"#, "application/json", true);
        let det = checker.check(&ctx).expect("hit");
        assert!(det.detail.contains("body.json[1]"));
    }

    #[test]
    fn detects_xss_in_form_urlencoded_body() {
        let checker = XssCheck::new();
        let ctx = make_ctx_with(
            "",
            "q=%3Cscript%3Ealert(1)%3C/script%3E",
            "application/x-www-form-urlencoded",
            true,
        );
        let det = checker.check(&ctx).expect("hit");
        assert!(det.detail.contains("body.form.q"));
    }

    #[test]
    fn allows_clean_json_body() {
        let checker = XssCheck::new();
        let ctx = make_ctx_with("", r#"{"name":"Alice"}"#, "application/json", true);
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn allows_clean_form_body() {
        let checker = XssCheck::new();
        let ctx = make_ctx_with("", "q=hello+world&page=1", "application/x-www-form-urlencoded", true);
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn malformed_json_falls_through_to_raw_scan() {
        // Walker bails None on bad JSON; raw `request_targets()` then scans
        // the bytes — `<script>` substring still gets caught.
        let checker = XssCheck::new();
        let ctx = make_ctx_with("", "not-json-but-<script>here", "application/json", true);
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn skipped_when_xss_disabled() {
        let checker = XssCheck::new();
        let ctx = make_ctx_with("", r#"{"x":"<script>"}"#, "application/json", false);
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn markdown_body_skipped_but_query_still_scanned() {
        // `<script>` in a markdown body is allowed (false-positive mitigation).
        let checker = XssCheck::new();
        let ctx = make_ctx_with("", "Here is some `<script>` in a code block", "text/markdown", true);
        assert!(checker.check(&ctx).is_none());

        // Query string still scans even with markdown content type.
        let ctx2 = make_ctx_with("q=<script>", "ignored", "text/markdown", true);
        assert!(checker.check(&ctx2).is_some());
    }

    #[test]
    fn detection_carries_correct_phase_and_rule_id_prefix() {
        let checker = XssCheck::new();
        let ctx = make_ctx("q=<script>", "");
        let det = checker.check(&ctx).expect("hit");
        assert_eq!(det.phase, waf_common::Phase::Xss);
        assert_eq!(det.rule_name, "XSS");
        assert!(det.rule_id.as_deref().unwrap_or("").starts_with("XSS-"));
    }

    #[test]
    fn deeply_nested_json_does_not_overflow_dispatcher() {
        // Echoes xss_scanners::tests but exercises the full dispatcher path
        // including content-type detection + body cap.
        let checker = XssCheck::new();
        let mut s = String::new();
        for _ in 0..200 {
            s.push_str("{\"x\":");
        }
        s.push_str("\"<script>\"");
        for _ in 0..200 {
            s.push('}');
        }
        let ctx = make_ctx_with("", &s, "application/json", true);
        // Should NOT panic. May or may not detect (walker bails past depth cap).
        let _ = checker.check(&ctx);
    }
}
