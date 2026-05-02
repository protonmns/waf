use std::sync::LazyLock;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::{Check, request_targets};

static TRAVERSAL_DESCS: &[&str] = &[
    "directory traversal (../)",
    "URL-encoded traversal (%2e%2e)",
    "double URL-encoded traversal (%252e%252e)",
    "Unicode / overlong UTF-8 traversal",
    "Windows backslash traversal (..\\)",
    "null byte injection (%00)",
    "absolute path to sensitive Unix directory",
    "Windows drive-letter path (C:\\)",
    "Linux sensitive file (/etc/passwd, /etc/shadow, …)",
    "Linux /proc inspection (/proc/self/environ, /proc/version, …)",
    "Windows system32 / config",
    "legacy Windows config file (boot.ini / win.ini)",
];

// SAFETY: All patterns are compile-time string literals. If any pattern fails
// to compile it is a code bug that must be caught in development, not at runtime.
static TRAVERSAL_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    match RegexSet::new([
        // Classic `../` and `..\`
        r"(\.\./|\.\.\\)",
        // URL single-encoded: `%2e%2e` followed by separator
        r"(?i)%2e%2e(%2f|%5c|/|\\)",
        // Double URL-encoded: `%252e%252e`
        r"(?i)%252e%252e",
        // Unicode / overlong UTF-8 encodings
        r"(?i)\.\.((%c0%af)|(%c1%9c)|(%e0%80%af)|(%c0%9v))",
        // Windows backslash traversal — kept for descriptor parity with the
        // Classic arm so the `..\\` hit attributes to the Windows-specific
        // descriptor rather than the generic one.
        r"\.\.\\",
        // Null byte
        r"%00",
        // Absolute path to broadly sensitive Unix directories
        r"(?i)/(etc|proc|var/log|usr/local|root|home|tmp|dev|sys)(/|$)",
        // Windows drive-letter path (e.g. `C:\`)
        r"(?i)[A-Za-z]:\\",
        // Linux sensitive file targets — anchored on `/etc/` so a benign
        // route like `/api/passwd-reset` cannot match.
        r"(?i)/etc/(passwd|shadow|hosts|group|fstab|sudoers)",
        // Linux /proc/<pid>/<file> probes — pid is `self` or numeric.
        r"(?i)/proc/(self|[0-9]+)/(environ|status|cmdline|version|maps|cwd)",
        // Windows system32 / config attempts (must include the literal
        // backslash before `system32` to avoid hitting random `system32`
        // mentions in user content).
        r"(?i)\\windows\\system32(\\|$)",
        // Legacy Windows boot/config files — word-boundary anchored so
        // benign paths like `version.txt` don't false-match.
        r"(?i)(^|[/\\])\b(boot|win)\.ini\b",
    ]) {
        Ok(set) => set,
        Err(e) => {
            tracing::error!("BUG: directory traversal regex set failed to compile: {e}");
            RegexSet::empty()
        }
    }
});

/// Directory traversal / path injection detection checker.
pub struct DirTraversalCheck;

impl DirTraversalCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DirTraversalCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for DirTraversalCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.dir_traversal {
            return None;
        }

        // Reuse `request_targets()` so we get raw + single-decoded + recursively-
        // decoded variants of path / query / cookie / body in one pass. This is
        // strictly more coverage than the previous bespoke `candidates` array
        // (which missed the recursive variant — i.e. `..%252f..%252fetc%252fpasswd`
        // double-encoded payloads weren't catching the `..` segment after the
        // first single-decode pass).
        for (location, value) in request_targets(ctx) {
            if value.is_empty() {
                continue;
            }
            let matches = TRAVERSAL_SET.matches(&value);
            if matches.matched_any() {
                let idx = matches.iter().next().unwrap_or(0);
                let desc = TRAVERSAL_DESCS.get(idx).copied().unwrap_or("path traversal");
                return Some(DetectionResult {
                    rule_id: Some(format!("TRAV-{:03}", idx + 1)),
                    rule_name: "Directory Traversal".to_string(),
                    phase: Phase::DirTraversal,
                    detail: format!("{desc} detected in {location}"),
                });
            }
        }
        None
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

    fn make_ctx(path: &str, query: &str) -> RequestCtx {
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: path.to_string(),
            query: query.to_string(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig {
                defense_config: DefenseConfig {
                    dir_traversal: true,
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
    fn detects_dot_dot_slash() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/images/../../../etc/passwd", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_encoded_traversal() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/", "file=%2e%2e%2fetc%2fpasswd");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_double_encoded() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/%252e%252e/etc/passwd", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn allows_clean_path() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/api/v1/users", "page=2");
        assert!(checker.check(&ctx).is_none());
    }

    // ─── FR-015 enhancements: OS targets + recursive decode + null byte ──────

    #[test]
    fn detects_etc_passwd_in_path() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/files/../../etc/passwd", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_proc_self_environ_in_query() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/", "file=/proc/self/environ");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_proc_version_in_query() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/", "file=/proc/123/cmdline");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_windows_system32_in_query() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/", "f=C:\\windows\\system32\\config\\sam");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_windows_boot_ini() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/files/boot.ini", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_windows_win_ini() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/files/win.ini", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_overlong_utf8_traversal() {
        // ..%c0%af is overlong UTF-8 for `/`.
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/static/..%c0%af..%c0%afetc%c0%afpasswd", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_null_byte_truncation() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/uploads/photo.jpg%00.php", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_recursive_double_encoded_in_path() {
        // %25 → %, then %2e%2e → .. — only catchable via the recursive pass.
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/files/%252e%252e%252fetc%252fpasswd", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_recursive_double_encoded_in_query() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/", "f=%252e%252e%252fetc%252fpasswd");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn allows_benign_passwd_route() {
        // `/api/passwd-reset` is a common UI route; must NOT trigger the
        // /etc/passwd matcher (it's anchored on `/etc/`).
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/api/passwd-reset", "user=alice");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn allows_filename_with_double_dot_no_separator() {
        // `..hidden.txt` (no `/` or `\` after `..`) must not trigger the
        // classic-traversal regex which requires the path separator.
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/files/..hidden.txt", "");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn allows_version_txt_filename() {
        // `version.txt` must not trigger the `/proc/<pid>/version` matcher.
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/docs/version.txt", "");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn skipped_when_dir_traversal_disabled() {
        let checker = DirTraversalCheck::new();
        let mut ctx = make_ctx("/files/../../etc/passwd", "");
        // Override config to disable.
        ctx.host_config = Arc::new(HostConfig {
            defense_config: DefenseConfig {
                dir_traversal: false,
                ..DefenseConfig::default()
            },
            ..HostConfig::default()
        });
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn detects_traversal_in_cookie() {
        let checker = DirTraversalCheck::new();
        let mut ctx = make_ctx("/", "");
        ctx.headers
            .insert("cookie".to_string(), "next=../../etc/passwd".to_string());
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_traversal_in_body() {
        let checker = DirTraversalCheck::new();
        let mut ctx = make_ctx("/", "");
        ctx.body_preview = Bytes::from("path=/etc/shadow");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detection_carries_correct_phase_and_rule_id() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/files/../../etc/passwd", "");
        let det = checker.check(&ctx).expect("hit");
        assert_eq!(det.phase, Phase::DirTraversal);
        assert_eq!(det.rule_name, "Directory Traversal");
        assert!(det.rule_id.as_deref().unwrap_or("").starts_with("TRAV-"));
    }
}
