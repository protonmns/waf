//! Request-body abuse helpers — magic-byte content-type sniff, iterative
//! byte-level depth pre-check, and key-count walker.
//!
//! The depth check is intentionally implemented as a byte scan (not a
//! `serde_json` recursion-limit hook). `serde_json::de::Deserializer` only
//! exposes `disable_recursion_limit()` — the opposite of what we need
//! (Red Team Finding #3). Walking bytes ourselves is O(N) and bails the
//! moment nesting crosses the cap, before any allocation.

use serde_json::Value;

/// Magic-byte classification of the request body. Returned as a short static
/// tag (`"json"`, `"xml"`, `"zip"`, `"gzip"`, `"html"`, `"unknown"`) so
/// callers can compare against the declared Content-Type category without
/// allocating.
pub fn sniff_body_kind(bytes: &[u8]) -> &'static str {
    let trimmed = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map_or(bytes, |i| bytes.get(i..).unwrap_or(bytes));
    let Some(&first) = trimmed.first() else {
        return "unknown";
    };
    match first {
        b'{' | b'[' => "json",
        b'<' => {
            // `<!DOCTYPE html` / `<html` → html; otherwise treat as xml.
            let lower: Vec<u8> = trimmed.iter().take(16).map(u8::to_ascii_lowercase).collect();
            if lower.starts_with(b"<!doctype html") || lower.starts_with(b"<html") {
                "html"
            } else {
                "xml"
            }
        }
        _ if trimmed.starts_with(b"PK\x03\x04") => "zip",
        _ if trimmed.starts_with(&[0x1f, 0x8b]) => "gzip",
        _ => "unknown",
    }
}

/// Extract the Content-Type category from the declared header value. Returns
/// the same tag alphabet as [`sniff_body_kind`] so a mismatch check is a
/// straight `!=`.
///
/// `application/json; charset=utf-8` → `"json"`, `text/html` → `"html"`, etc.
/// Unknown / missing → `"unknown"`, which the caller uses to mean
/// "skip mismatch check".
pub fn declared_body_kind(content_type: &str) -> &'static str {
    let primary = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if primary == "application/json" || primary.ends_with("+json") {
        "json"
    } else if primary == "application/xml" || primary == "text/xml" || primary.ends_with("+xml") {
        "xml"
    } else if primary == "application/zip" {
        "zip"
    } else if primary == "application/gzip" || primary == "application/x-gzip" {
        "gzip"
    } else if primary == "text/html" {
        "html"
    } else {
        "unknown"
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BodyAbuseViolation {
    TooDeep,
    TooManyKeys,
}

/// Fast pre-scan: walk the raw bytes and bail the moment `{`/`[` nesting
/// exceeds `max_depth`. Treats `{` inside a string literal as a nesting
/// token — this is an intentional over-approximation documented in the
/// plan (the alternative is to parse strings + escapes here, which defeats
/// the point of running before the parser).
pub fn precheck_json_depth(bytes: &[u8], max_depth: usize) -> Result<(), BodyAbuseViolation> {
    let mut depth: usize = 0;
    for &b in bytes {
        match b {
            b'{' | b'[' => {
                depth += 1;
                if depth > max_depth {
                    return Err(BodyAbuseViolation::TooDeep);
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Iteratively walk a parsed `serde_json::Value` counting object keys. Bails
/// as soon as the cumulative count exceeds `max_keys`. Uses an explicit
/// `Vec<&Value>` stack (never recursive) so we cannot trigger the very
/// class of bug we detect.
pub fn walk_count_keys(root: &Value, max_keys: usize) -> Result<(), BodyAbuseViolation> {
    let mut stack: Vec<&Value> = Vec::new();
    stack.push(root);
    let mut keys: usize = 0;
    while let Some(node) = stack.pop() {
        match node {
            Value::Object(map) => {
                keys += map.len();
                if keys > max_keys {
                    return Err(BodyAbuseViolation::TooManyKeys);
                }
                for child in map.values() {
                    stack.push(child);
                }
            }
            Value::Array(arr) => {
                for child in arr {
                    stack.push(child);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn sniff_json_object() {
        assert_eq!(sniff_body_kind(br#"{"a":1}"#), "json");
    }

    #[test]
    fn sniff_json_array() {
        assert_eq!(sniff_body_kind(b"[1,2,3]"), "json");
    }

    #[test]
    fn sniff_skips_leading_whitespace() {
        assert_eq!(sniff_body_kind(b"   \r\n{}"), "json");
    }

    #[test]
    fn sniff_xml() {
        assert_eq!(sniff_body_kind(b"<?xml version='1.0'?>"), "xml");
        assert_eq!(sniff_body_kind(b"<root/>"), "xml");
    }

    #[test]
    fn sniff_html() {
        assert_eq!(sniff_body_kind(b"<!DOCTYPE html>"), "html");
        assert_eq!(sniff_body_kind(b"<html>"), "html");
    }

    #[test]
    fn sniff_zip() {
        assert_eq!(sniff_body_kind(b"PK\x03\x04rest"), "zip");
    }

    #[test]
    fn sniff_gzip() {
        assert_eq!(sniff_body_kind(&[0x1f, 0x8b, 0x08]), "gzip");
    }

    #[test]
    fn sniff_unknown() {
        assert_eq!(sniff_body_kind(b"plain text body"), "unknown");
        assert_eq!(sniff_body_kind(b""), "unknown");
    }

    #[test]
    fn declared_json_variants() {
        assert_eq!(declared_body_kind("application/json"), "json");
        assert_eq!(declared_body_kind("application/json; charset=utf-8"), "json");
        assert_eq!(declared_body_kind("APPLICATION/JSON"), "json");
        assert_eq!(declared_body_kind("application/vnd.api+json"), "json");
    }

    #[test]
    fn declared_xml_variants() {
        assert_eq!(declared_body_kind("application/xml"), "xml");
        assert_eq!(declared_body_kind("text/xml"), "xml");
        assert_eq!(declared_body_kind("application/soap+xml"), "xml");
    }

    #[test]
    fn declared_other() {
        assert_eq!(declared_body_kind("text/html"), "html");
        assert_eq!(declared_body_kind("application/zip"), "zip");
        assert_eq!(declared_body_kind("application/gzip"), "gzip");
        assert_eq!(declared_body_kind("text/plain"), "unknown");
        assert_eq!(declared_body_kind(""), "unknown");
    }

    #[test]
    fn precheck_accepts_shallow() {
        assert!(precheck_json_depth(b"{\"a\":{\"b\":1}}", 100).is_ok());
    }

    #[test]
    fn precheck_rejects_over_depth() {
        let bytes = "{".repeat(200);
        assert_eq!(
            precheck_json_depth(bytes.as_bytes(), 100),
            Err(BodyAbuseViolation::TooDeep)
        );
    }

    #[test]
    fn precheck_handles_adversarial_no_close_braces() {
        // 10000 `{`s, no closes. Must finish in O(N) without panicking.
        let bytes = "{".repeat(10_000);
        assert_eq!(
            precheck_json_depth(bytes.as_bytes(), 100),
            Err(BodyAbuseViolation::TooDeep)
        );
    }

    #[test]
    fn precheck_saturating_sub_guards_against_extra_close() {
        // Extra `}` should not underflow; overall accept because depth stays ≤ 1.
        assert!(precheck_json_depth(b"}}}{}", 10).is_ok());
    }

    #[test]
    fn walk_count_keys_flat() {
        let v: Value = serde_json::from_str(r#"{"a":1,"b":2,"c":3}"#).unwrap();
        assert!(walk_count_keys(&v, 10).is_ok());
    }

    #[test]
    fn walk_count_keys_exceeds_cap() {
        // Build an object with 50 keys.
        let mut s = String::from("{");
        for i in 0..50 {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(s, r#""k{i}":{i}"#);
        }
        s.push('}');
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(walk_count_keys(&v, 10), Err(BodyAbuseViolation::TooManyKeys));
    }

    #[test]
    fn walk_count_keys_nested() {
        let v: Value = serde_json::from_str(r#"{"a":{"b":{"c":1}}}"#).unwrap();
        assert!(walk_count_keys(&v, 10).is_ok());
        assert_eq!(walk_count_keys(&v, 2), Err(BodyAbuseViolation::TooManyKeys));
    }

    #[test]
    fn walk_count_keys_array_of_objects() {
        let v: Value = serde_json::from_str(r#"[{"a":1},{"b":2},{"c":3}]"#).unwrap();
        assert!(walk_count_keys(&v, 10).is_ok());
        assert_eq!(walk_count_keys(&v, 2), Err(BodyAbuseViolation::TooManyKeys));
    }
}
