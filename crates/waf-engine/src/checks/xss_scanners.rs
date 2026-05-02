//! XSS scanner helpers — JSON walker + form-urlencoded extractor.
//!
//! Both scanners produce `(location_string, pattern_index)` so the caller can
//! attribute the hit precisely (e.g. `body.json.user.name` vs `body.form.q`).
//! The JSON walker is **iterative** and bails on depth > [`MAX_JSON_DEPTH`] —
//! using the recursive pattern from `sql_injection_scanners` would re-introduce
//! the stack-overflow class FR-020 is meant to detect (Red Team Finding #4).

use regex::RegexSet;
use serde_json::Value;
use std::fmt::Write;

use super::url_decode_recursive;

/// Hard recursion cap for JSON walking. Anything deeper is skipped (not flagged)
/// so a malicious deep-nested body cannot crash the engine before FR-020
/// (Phase 06) gets a chance to flag it.
pub const MAX_JSON_DEPTH: usize = 64;

/// Scan a JSON body for XSS patterns, returning (`json_path`, `pattern_index`)
/// on the first hit. Bails out as `None` on parse error, oversize, or
/// depth-exceeded — the body-abuse check (FR-020) is responsible for
/// translating those cases into block decisions.
pub fn scan_json_body_xss(body: &[u8], patterns: &RegexSet, json_parse_cap: usize) -> Option<(String, usize)> {
    if body.len() > json_parse_cap {
        return None;
    }
    let v: Value = serde_json::from_slice(body).ok()?;
    walk_json_iter(&v, patterns)
}

/// Iterative depth-first walker. Each stack entry owns the full path string
/// for its node — costs O(depth × `path_len`) memory bounded by
/// [`MAX_JSON_DEPTH`] but avoids the truncate-on-pop bookkeeping that's
/// brittle when interleaved with branchy iteration order.
fn walk_json_iter(root: &Value, set: &RegexSet) -> Option<(String, usize)> {
    let mut stack: Vec<(&Value, String, usize)> = Vec::with_capacity(MAX_JSON_DEPTH);
    stack.push((root, String::from("body.json"), 0));

    while let Some((node, path, depth)) = stack.pop() {
        if depth > MAX_JSON_DEPTH {
            // Skip — FR-020 will flag the depth violation separately.
            continue;
        }
        match node {
            Value::String(s) => {
                let decoded = url_decode_recursive(s);
                if let Some(idx) = set.matches(&decoded).iter().next() {
                    return Some((path, idx));
                }
            }
            Value::Object(map) => {
                // Push reversed so LIFO pop yields original insertion order.
                for (k, child) in map.iter().rev() {
                    let mut child_path = path.clone();
                    child_path.push('.');
                    child_path.push_str(k);
                    stack.push((child, child_path, depth + 1));
                }
            }
            Value::Array(arr) => {
                for (i, child) in arr.iter().enumerate().rev() {
                    let mut child_path = path.clone();
                    let _ = write!(child_path, "[{i}]");
                    stack.push((child, child_path, depth + 1));
                }
            }
            _ => {} // null / bool / number — skip
        }
    }
    None
}

/// Scan a form-urlencoded body (`application/x-www-form-urlencoded`),
/// returning (`body.form.<key>`, `pattern_index`) on first hit. Each value is
/// percent-decoded recursively before regex match.
pub fn scan_form_urlencoded(body: &[u8], patterns: &RegexSet) -> Option<(String, usize)> {
    for (k, v) in url::form_urlencoded::parse(body) {
        let decoded = url_decode_recursive(&v);
        if let Some(idx) = patterns.matches(&decoded).iter().next() {
            return Some((format!("body.form.{k}"), idx));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::xss::XSS_SET;

    const TEST_CAP: usize = 64 * 1024;

    #[test]
    fn json_nested_object_hit() {
        let body = br#"{"a":{"b":"<script>alert(1)</script>"}}"#;
        let (path, _) = scan_json_body_xss(body, &XSS_SET, TEST_CAP).expect("hit");
        assert_eq!(path, "body.json.a.b");
    }

    #[test]
    fn json_array_hit() {
        let body = br#"["safe","<img onerror=x>"]"#;
        let (path, _) = scan_json_body_xss(body, &XSS_SET, TEST_CAP).expect("hit");
        assert_eq!(path, "body.json[1]");
    }

    #[test]
    fn json_clean() {
        let body = br#"{"name":"Alice","age":25}"#;
        assert!(scan_json_body_xss(body, &XSS_SET, TEST_CAP).is_none());
    }

    #[test]
    fn json_malformed_returns_none() {
        let body = b"not valid json";
        assert!(scan_json_body_xss(body, &XSS_SET, TEST_CAP).is_none());
    }

    #[test]
    fn json_oversize_returns_none() {
        let body = vec![b'{'; TEST_CAP + 1];
        assert!(scan_json_body_xss(&body, &XSS_SET, TEST_CAP).is_none());
    }

    #[test]
    fn xss_url_encoded_value_in_json() {
        // %3Cscript%3E decodes to <script>; recursive url-decode resolves.
        let body = br#"{"q":"%3Cscript%3Ealert(1)%3C/script%3E"}"#;
        assert!(scan_json_body_xss(body, &XSS_SET, TEST_CAP).is_some());
    }

    #[test]
    fn xss_deeply_nested_json_does_not_overflow() {
        // Synthesize depth = 200, well past MAX_JSON_DEPTH=64.
        let mut s = String::new();
        for _ in 0..200 {
            s.push_str("{\"x\":");
        }
        s.push_str("\"<script>\"");
        for _ in 0..200 {
            s.push('}');
        }
        // Iterative walker must NOT panic; bails as None per Finding #4.
        let _ = scan_json_body_xss(s.as_bytes(), &XSS_SET, TEST_CAP);
    }

    #[test]
    fn xss_at_max_depth_still_detected() {
        // Build object nested exactly MAX_JSON_DEPTH levels — leaf string
        // sits at that depth and must still match.
        let mut s = String::new();
        for _ in 0..MAX_JSON_DEPTH {
            s.push_str("{\"x\":");
        }
        s.push_str("\"<script>\"");
        for _ in 0..MAX_JSON_DEPTH {
            s.push('}');
        }
        assert!(scan_json_body_xss(s.as_bytes(), &XSS_SET, TEST_CAP).is_some());
    }

    #[test]
    fn form_simple_hit() {
        let body = b"q=%3Cscript%3Ealert(1)%3C/script%3E";
        let (loc, _) = scan_form_urlencoded(body, &XSS_SET).expect("hit");
        assert_eq!(loc, "body.form.q");
    }

    #[test]
    fn form_clean() {
        let body = b"q=hello+world&page=1";
        assert!(scan_form_urlencoded(body, &XSS_SET).is_none());
    }

    #[test]
    fn form_event_handler_value() {
        let body = b"comment=%3Cimg+onerror%3Dalert(1)%3E";
        let (loc, _) = scan_form_urlencoded(body, &XSS_SET).expect("hit");
        assert_eq!(loc, "body.form.comment");
    }
}
