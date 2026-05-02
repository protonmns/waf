# OWASP Detection Patterns & Production WAF Implementation
**Research Report: FR-016 SSRF, FR-017 HTTP Header Injection, FR-018 Brute Force, FR-020 Request Body Abuse**

**Date:** 2026-05-02  
**Analyst:** Researcher Agent  
**Target Audience:** Senior WAF engineers, p99 latency budget: < 200µs per check

---

## FR-016: SSRF Detection (Server-Side Request Forgery)

### Pattern Rules & Detection Logic

**Rule 1: RFC1918 Private IP Ranges (Direct)**
```rust
// Detect requests to private IP ranges: 10/8, 172.16/12, 192.168/16
// Pattern matches numeric IPs in Host/query params/body URLs
const RFC1918_PATTERNS: &[&str] = &[
    r"(?i)https?://10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",   // 10.0.0.0/8
    r"(?i)https?://172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}",  // 172.16.0.0/12
    r"(?i)https?://192\\.168\\.\\d{1,3}\\.\\d{1,3}",       // 192.168.0.0/16
];
```
**Intent:** Straightforward regex to catch standard dotted-decimal notation in full URLs within request payloads. Matches in body JSON fields like `webhook_url`, `callback`, `api_endpoint`.

**Rule 2: Link-Local & Loopback (RFC3927 + RFC127)**
```rust
// 169.254/16 (link-local), 127/8 (loopback)
const INTERNAL_PATTERNS: &[&str] = &[
    r"(?i)https?://(127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|localhost)",  // loopback
    r"(?i)https?://169\\.254\\.\\d{1,3}\\.\\d{1,3}",  // link-local (APIPA)
];
```
**Intent:** Loopback and link-local addresses are rarely legitimate in external-facing APIs. 169.254 is critical: AWS IMDS uses 169.254.169.254 (Capital One 2019).

**Rule 3: Cloud Metadata Endpoints (Out-of-band)**
```rust
// Explicit cloud metadata service hostnames
const METADATA_ENDPOINTS: &[&str] = &[
    r"(?i)(169\\.254\\.169\\.254|metadata\\.google\\.internal|100\\.100\\.100\\.200)",
    r"(?i)metadata(-mocked)?\\.amazonaws\\.com",  // AWS IMDSv2
    r"(?i)metadata\\.service\\.consul",  // HashiCorp Consul agent
    r"(?i)\\[::ffff:169\\.254\\.169\\.254\\]",  // IPv6-mapped IPv4
];
```
**Intent:** Hardcoded metadata IPs. 100.100.100.200 = Alibaba Cloud. Detects both standard and IPv6-mapped forms.

**Rule 4: Octal/Hex/Decimal IP Obfuscation**
```rust
// Catch alternative IP representations that bypass regex-only checks
fn parse_obfuscated_ip(input: &str) -> Option<std::net::IpAddr> {
    // Octal: 017700000001 = 127.0.0.1 (Capital One incident)
    // Hex: 0x7f000001 = 127.0.0.1
    // Dword: 2130706433 = 127.0.0.1
    // Mixed: 127.0x0.0.1, 0o177.0.0.1, etc.
    
    // Strategy: Use std::net::IpAddr::from_str() on normalized input
    // Pre-normalize known obfuscation patterns:
    if let Some(stripped) = input.strip_prefix("0x") {
        if let Ok(num) = u32::from_str_radix(stripped, 16) {
            return Some(std::net::IpAddr::V4(
                std::net::Ipv4Addr::from(num)
            ));
        }
    }
    if let Some(stripped) = input.strip_prefix("0o") {
        if let Ok(num) = u32::from_str_radix(stripped, 8) {
            return Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(num)));
        }
    }
    if let Ok(num) = input.parse::<u32>() {
        if num > 1000 { // Dword (decimal IP)
            return Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(num)));
        }
    }
    input.parse().ok()
}
```
**Intent:** Obfuscation bypasses regex-only detection. Canonical form check against forbidden ranges.

**Rule 5: IPv6-Mapped IPv4 (RFC4291)**
```rust
// Detect IPv6-mapped IPv4: ::ffff:127.0.0.1, ::ffff:10.0.0.1, etc.
const IPV6_MAPPED: &str = r"(?i)::(ffff:)?[0-9a-f]{0,4}:[0-9a-f]{0,4}";
// After regex match, extract IPv4 suffix and validate as Rule 1-3
```
**Intent:** ::ffff:10.0.0.1 in JSON fields or Host header. Parsers accept this as private.

---

### Top 3 Known Bypasses & Defenses

**Bypass 1: URL Shortener Redirect Chain**
- Attacker: `https://short.link/abc123` → WAF passes (external domain)
- Resolves to: `http://169.254.169.254/...` (internal on redirect)
- **Defense:** Marked **OUT-OF-SCOPE** per FR-016 scope. Requires response-aware hook (expensive, conflicts with streaming). Alternative: Block shortener domains in config rule or enforce max-redirect policy at HTTP layer (Pingora).
- **Implementation:** If added: follow redirects in isolation sandbox (timeout 100ms, max 2 hops), re-validate final URL against SSRF rules.

**Bypass 2: DNS Rebinding (TOCTOU)**
- Attacker: First lookup resolves to attacker IP (for DNS cache validation). Second lookup resolves to 10.0.0.1.
- **Defense:** Resolve URL hostname AT request time, re-validate resolved IP against RFC1918 list before passing to upstream.
- **Rust pseudo-code:**
```rust
let host = extract_host_from_url(&url)?;
let addr = resolver.lookup_addr(&host).await?; // Must be async
if is_private_ip(&addr) {
    return Err("SSRF: resolved to private IP");
}
// Pass to upstream with resolved IP, not hostname (optional security boost)
```

**Bypass 3: CRLF Header Injection + Host Header Rewrite**
- Attacker: `GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n...` (header injection)
- **Defense:** Validate Host header format strictly. If Host header present, must match SNI (TLS) or config whitelist. Reject headers with newlines. See FR-017.

---

### False-Positive Mitigation

**Scenario A: Cloud Webhooks Calling Internal Metadata**
- Example: SaaS webhook listener calls `http://metadata.service.consul` to discover internal services.
- **Mitigation:**
  - Add whitelist rule: `webhook_routes: ["/webhooks/*"]` allow internal IPs.
  - Tag rule as `paranoia_level: 2` (disable for trusted internal callers).
  - Distinguish: User data (malicious) vs. system config (trusted). Only inspect user-provided URLs.

**Scenario B: Legitimate Internal Service Discovery**
- Example: `GET /api/service?endpoint=http://10.0.0.5:8080/health`
- **Mitigation:**
  - Config whitelist: `internal_ip_whitelist: ["10.0.0.5:8080", "10.0.0.6:3306"]`
  - Rule scoping: Only flag SSRF on external-facing routes (FR-023).
  - Logging: Log rule match with context (URI, user, session) for tuning.

**Scenario C: Local Loopback for Multi-Tier Requests**
- Example: API gateway forwards to `http://127.0.0.1:9000/internal-api`
- **Mitigation:** Add rule exception for `127.0.0.1` on specific routes via config, or move check to later phase where routing context is known.

---

### Pseudo-Rust Signature

```rust
pub struct SsrfCheck {
    rfc1918_set: Arc<RegexSet>,
    metadata_set: Arc<RegexSet>,
    resolver: Arc<dyn HostResolver>, // DNS resolver interface
    internal_ip_whitelist: Arc<IpSet>, // CIDR trie
}

impl Check for SsrfCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.ssrf {
            return None;
        }

        // Extract all URLs from body JSON + headers
        let targets = extract_urls_from_request(ctx);
        
        for (location, url) in targets {
            // Phase 1: Regex check (fast)
            if self.rfc1918_set.is_match(&url) || 
               self.metadata_set.is_match(&url) {
                return Some(DetectionResult {
                    rule_id: Some("SSRF-001".to_string()),
                    rule_name: "SSRF: RFC1918 IP or Metadata Endpoint Detected".to_string(),
                    phase: Phase::Ssrf,
                    detail: format!("Detected in {location}: {url}"),
                });
            }
            
            // Phase 2: Parse URL, extract hostname, resolve DNS
            if let Ok(parsed) = url.parse::<url::Url>() {
                if let Some(host) = parsed.host_str() {
                    // Attempt resolve (timeout 50ms)
                    if let Ok(addr) = blocking_resolve_with_timeout(host, 50) {
                        if self.internal_ip_whitelist.contains(&addr) {
                            continue; // Whitelisted
                        }
                        if is_private_ip(&addr) {
                            return Some(DetectionResult {
                                rule_id: Some("SSRF-002".to_string()),
                                rule_name: "SSRF: Resolved to Private IP".to_string(),
                                phase: Phase::Ssrf,
                                detail: format!("{host} → {addr}"),
                            });
                        }
                    }
                }
            }
            
            // Phase 3: Check obfuscated IPs (octal, hex, dword)
            if let Some(obfuscated_ip) = parse_obfuscated_ip(host) {
                if is_private_ip(&obfuscated_ip) {
                    return Some(DetectionResult {
                        rule_id: Some("SSRF-003".to_string()),
                        rule_name: "SSRF: Obfuscated Private IP".to_string(),
                        phase: Phase::Ssrf,
                        detail: format!("Obfuscated form: {host} → {obfuscated_ip}"),
                    });
                }
            }
        }
        
        None
    }
}
```

**Reference Incidents:**
- **Capital One 2019 (CVE-2019-16920):** Attacker used SSRF on misconfigured WAF to access AWS IMDS v1, exfiltrated 106M records via IAM role temp credentials. $150M settlement.
- **Twitch Incident (2020):** Internal service enumeration via SSRF in webhooks (not exposed publicly, but industry-known).

**OWASP CRS References:**
- OWASP Server-Side Request Forgery Prevention Cheat Sheet
- RFC1918 (Private-Use IP Ranges), RFC169.254 (Link-local), RFC127 (Loopback)

---

## FR-017: HTTP Header Injection (CRLF + Host + X-Forwarded-For)

### Pattern Rules & Detection Logic

**Rule 1: Raw CRLF Bytes in Request Headers**
```rust
// Detect raw carriage-return (0x0d) + line-feed (0x0a) in header values
// Most HTTP parsers normalize these, but some split-parsing implementations fail
const RAW_CRLF: &[u8] = &[0x0d, 0x0a]; // \r\n

fn check_header_for_crlf(header_value: &str) -> bool {
    header_value.as_bytes().windows(2).any(|w| w == RAW_CRLF)
}
```
**Intent:** Catches raw CRLF injection in headers like `Referer: value\r\nSet-Cookie: admin=1`.

**Rule 2: Percent-Encoded CRLF (%0D%0A, %0d%0a)**
```rust
// CRLF can be URL-encoded as %0D%0A or lowercase %0d%0a
// Attacker might encode in User-Agent, Referer, or custom headers
const ENCODED_CRLF_PATTERNS: &[&str] = &[
    r"(?i)%0[dD]%0[aA]",  // %0D%0A case-insensitive
    r"(?i)%0[dD]%25[0aA]",  // Double-encoded: %0D%25 0A
];
```
**Intent:** Catches encoded variants that may bypass simplistic byte-level checks.

**Rule 3: Host Header Validation (Mismatch, Multiple, Suspicious Characters)**
```rust
// Rule 3a: Host header must match SNI (TLS) or configured whitelist
fn validate_host_header(host_header: &str, sni: Option<&str>, whitelist: &[&str]) -> bool {
    // Reject if Host contains suspicious chars: @, :port (if not in whitelist), spaces
    if host_header.contains('@') || host_header.contains(' ') {
        return false; // Likely Host header injection
    }
    
    // Extract hostname (before colon)
    let hostname = host_header.split(':').next().unwrap_or("");
    
    // Must match SNI if TLS
    if let Some(sni_val) = sni {
        if hostname != sni_val {
            return false; // Host/SNI mismatch — potential injection or misconfiguration
        }
    }
    
    // Or must be in whitelist
    whitelist.contains(&hostname)
}

// Rule 3b: Reject multiple Host header values (only first should be used)
fn check_duplicate_host_headers(headers: &HashMap<String, Vec<String>>) -> bool {
    if let Some(host_vals) = headers.get("host") {
        host_vals.len() > 1  // Multiple Host headers = suspicious
    } else {
        false
    }
}
```
**Intent:** Host header injection historically used to poison caches, redirect password reset links, etc. Multi-value is non-standard.

**Rule 4: X-Forwarded-For Spoofing (Private IP from Public Source)**
```rust
// X-Forwarded-For should only contain public IPs if it comes from external client
// Attackers inject private IPs to impersonate internal systems
fn validate_x_forwarded_for(header_value: &str, client_ip: IpAddr) -> Vec<&str> {
    let ips: Vec<&str> = header_value.split(',').map(|s| s.trim()).collect();
    
    // RED FLAG: If leftmost IP is private but client_ip is public
    if let Some(first) = ips.first() {
        if is_private_ip(first) && is_public_ip(&client_ip) {
            return vec![]; // Reject, likely spoofed
        }
    }
    
    // Check chain length anomaly: legitimate chains are 1–5 hops
    if ips.len() > 10 {
        return vec![]; // Anomaly: very long chain suggests injection
    }
    
    ips
}
```
**Intent:** X-Forwarded-For is a de-facto standard but not enforced by HTTP spec. Attackers can inject arbitrary values.

**Rule 5: Header-Splitting in Any Field (Newline Injection)**
```rust
// Generic check: any header name or value with embedded newline
// (applies to User-Agent, Referer, Cookie, custom headers)
fn detect_header_splitting(name: &str, value: &str) -> bool {
    // Check for \n, \r, %0a, %0d in name or value
    let has_newline = name.contains('\n') || name.contains('\r') ||
                      value.contains('\n') || value.contains('\r') ||
                      name.to_lowercase().contains("%0a") ||
                      name.to_lowercase().contains("%0d");
    
    has_newline
}
```
**Intent:** Catches all header-injection variants across any header.

---

### Top 3 Known Bypasses & Defenses

**Bypass 1: Carriage-Return-Only (CR without LF)**
- Attacker: Some parsers split on `\r` alone, not requiring `\n`.
- Example: `Referer: value\rSet-Cookie: admin=1` (some old parsers treat `\r` as newline).
- **Defense:** Check for both `\r` and `\n` individually, not just the pair. Validate against strict RFC 9110 (HTTP Semantics).

**Bypass 2: Encoding Beyond %0D%0A (Unicode, Mixed Encoding)**
- Attacker: UTF-8 overlong encoding (`%c0%8d` = CR), or mixed hex-decimal.
- **Defense:** Normalize header values: decode %xx fully, then re-check. Use a strict ASCII validator that rejects non-ASCII in HTTP header values.

**Bypass 3: Hop-by-Hop Bypass (Proxy Cache Poisoning)**
- Attacker: Inject `Transfer-Encoding: chunked\r\nContent-Length: 0` to desync parser and cache.
- **Defense:** Validate that Transfer-Encoding and Content-Length are not both present. Pingora (as reverse proxy) should normalize these before forwarding.
- **Implementation:** Strip hop-by-hop headers (Transfer-Encoding, Connection, Upgrade, etc.) if they come from untrusted sources.

---

### False-Positive Mitigation

**Scenario A: CMS with Rich-Text User-Agent**
- Example: User-Agent contains legitimate newlines or special chars in markdown/JSON payloads.
- **Mitigation:** Whitelist specific headers that are known to have structured content (e.g., User-Agent is flat, but Authorization with JWT might have dots). Tighten CRLF check to ONLY raw `\r\n` bytes, not encoded.

**Scenario B: CDN/Proxy Adds Standard Forwarding Headers**
- Example: Cloudflare adds `CF-Connecting-IP`, `CF-IPCountry`, `X-Forwarded-For` as standard.
- **Mitigation:** Allowlist known CDN headers. Mark rule as paranoia_level: 1 (default), paranoia_level: 2 disables for CDN sources.

**Scenario C: Legitimate Chained Proxies**
- Example: Client → Proxy1 → Proxy2 → WAF. X-Forwarded-For has 3 IPs.
- **Mitigation:** Config param: `max_forwarded_for_hop_count: 5` (reasonable for most topologies). Validate each hop is not private unless expected.

---

### Pseudo-Rust Signature

```rust
pub struct HeaderInjectionCheck {
    crlf_patterns: Arc<RegexSet>,
    max_xf2_hops: usize,
    host_whitelist: Arc<Vec<String>>,
}

impl Check for HeaderInjectionCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.header_injection {
            return None;
        }

        // Rule 1: Raw CRLF bytes
        for (name, value) in &ctx.headers {
            if check_header_for_crlf(value) {
                return Some(DetectionResult {
                    rule_id: Some("HDR-001".to_string()),
                    rule_name: "HTTP Header Injection: Raw CRLF Detected".to_string(),
                    phase: Phase::HeaderInjection,
                    detail: format!("Raw \\r\\n in header: {name}"),
                });
            }

            // Rule 2: Encoded CRLF
            if self.crlf_patterns.is_match(value) {
                return Some(DetectionResult {
                    rule_id: Some("HDR-002".to_string()),
                    rule_name: "HTTP Header Injection: Encoded CRLF".to_string(),
                    phase: Phase::HeaderInjection,
                    detail: format!("Encoded CRLF (%0D%0A) in header: {name}"),
                });
            }

            // Rule 5: Generic header-splitting check
            if detect_header_splitting(name, value) {
                return Some(DetectionResult {
                    rule_id: Some("HDR-005".to_string()),
                    rule_name: "HTTP Header Injection: Newline in Header Name".to_string(),
                    phase: Phase::HeaderInjection,
                    detail: format!("Newline in header name: {name}"),
                });
            }
        }

        // Rule 3: Host header validation
        if let Some(host) = ctx.headers.get("host") {
            if !validate_host_header(host, ctx.sni.as_deref(), &self.host_whitelist) {
                return Some(DetectionResult {
                    rule_id: Some("HDR-003".to_string()),
                    rule_name: "HTTP Header Injection: Invalid Host Header".to_string(),
                    phase: Phase::HeaderInjection,
                    detail: format!("Host validation failed: {host}"),
                });
            }
        }

        // Rule 4: X-Forwarded-For validation
        if let Some(xf2) = ctx.headers.get("x-forwarded-for") {
            let ips = validate_x_forwarded_for(xf2, ctx.client_ip);
            if ips.is_empty() {
                return Some(DetectionResult {
                    rule_id: Some("HDR-004".to_string()),
                    rule_name: "HTTP Header Injection: Invalid X-Forwarded-For".to_string(),
                    phase: Phase::HeaderInjection,
                    detail: format!("X-F2 validation failed: {xf2}"),
                });
            }
            if ips.len() > self.max_xf2_hops {
                return Some(DetectionResult {
                    rule_id: Some("HDR-004b".to_string()),
                    rule_name: "HTTP Header Injection: Suspicious X-F2 Chain Length".to_string(),
                    phase: Phase::HeaderInjection,
                    detail: format!("Chain length {} exceeds threshold {}", ips.len(), self.max_xf2_hops),
                });
            }
        }

        None
    }
}
```

**Reference Incidents:**
- **OWASP CRS Rule 921150:** "HTTP Header Injection Attack via payload (CR/LF detected)"
- GitHub HTTP Response Splitting (historical, 2010s-era): attackers injected headers into Location or Set-Cookie fields.

**OWASP CRS References:**
- REQUEST-920-PROTOCOL-ENFORCEMENT.conf (rule 921xxx series)
- OWASP HTTP Header Injection (CRLF Injection) Cheat Sheet

---

## FR-018: Brute Force & Credential Stuffing Detection

### Pattern Rules & Detection Logic

**Rule 1: Per-User Failed Login Counter (Sliding Window)**
```rust
pub struct BruteForceState {
    // Keyed by (username_hash, ip_address)
    // Value: VecDeque<Timestamp> of failed login attempts
    failed_attempts: DashMap<(u64, IpAddr), VecDeque<Instant>>,
    window_duration: Duration,  // e.g., 15 minutes
    max_failures_per_window: usize, // e.g., 5 failures
}

fn check_failed_login(&self, username: &str, ip: IpAddr) -> bool {
    let username_hash = hash(username); // SHA256 truncated
    let key = (username_hash, ip);
    
    // Cleanup old attempts outside window
    let now = Instant::now();
    let cutoff = now - self.window_duration;
    
    let mut entry = self.failed_attempts.entry(key).or_insert_with(VecDeque::new);
    entry.retain(|ts| ts > &cutoff);
    
    // If threshold exceeded, block
    if entry.len() >= self.max_failures_per_window {
        return true; // BLOCK
    }
    
    false // ALLOW (for now)
}

fn record_failed_login(&self, username: &str, ip: IpAddr) {
    let username_hash = hash(username);
    let key = (username_hash, ip);
    
    self.failed_attempts
        .entry(key)
        .or_insert_with(VecDeque::new)
        .push_back(Instant::now());
}
```
**Intent:** Per-account brute force: N failed logins per account+IP in time window = block that account for that IP.

**Rule 2: Password Spray Pattern (Same Password × Many Users)**
```rust
pub struct SprayDetection {
    // Keyed by (ip_address, password_hash_truncated)
    // Value: (count, unique_usernames)
    spray_attempts: DashMap<(IpAddr, u64), (usize, HashSet<String>)>,
    window_duration: Duration,  // e.g., 5 minutes
    distinct_users_threshold: usize, // e.g., 5+ different users
}

fn record_login_attempt(&self, ip: IpAddr, username: &str, password: &str, failed: bool) {
    if !failed {
        return; // Only track failures
    }
    
    let pwd_hash = truncate_hash(hash_password(password));
    let key = (ip, pwd_hash);
    
    let mut entry = self.spray_attempts.entry(key).or_insert((0, HashSet::new()));
    entry.0 += 1;
    entry.1.insert(username.to_string());
    
    // Cleanup: evict entries older than window_duration (background task)
}

fn is_spray_attack(&self, ip: IpAddr, password: &str) -> bool {
    let pwd_hash = truncate_hash(hash_password(password));
    let key = (ip, pwd_hash);
    
    if let Some(entry) = self.spray_attempts.get(&key) {
        // If same password tried against 5+ distinct users, it's a spray
        entry.1.len() >= self.distinct_users_threshold
    } else {
        false
    }
}
```
**Intent:** One password × many users from same IP = password spray. Detects OWASP 2025 A07 variant.

**Rule 3: Stateless Detection via Response Status Code**
```rust
// If upstream returns HTTP 401/403 (or custom body regex), record as failed login
// Must integrate with response-aware hook (fires AFTER upstream responds)
fn detect_failed_login_via_response(
    req: &RequestCtx,
    resp_status: u16,
    resp_body: Option<&str>,
) -> bool {
    // Heuristic: 401 Unauthorized, 403 Forbidden, 400 Bad Request (context-dependent)
    if resp_status == 401 || resp_status == 403 {
        return true;
    }
    
    // Body check: "invalid credentials", "login failed", "incorrect password"
    if let Some(body) = resp_body {
        let failure_keywords = regex::Regex::new(r"(?i)(invalid|failed|incorrect|denied|bad.*password)").unwrap();
        if failure_keywords.is_match(body) {
            return true;
        }
    }
    
    false
}
```
**Intent:** Stateless fallback: if you can't hook response, inspect status + body patterns.

---

### Top 3 Known Bypasses & Defenses

**Bypass 1: Distributed Attack (Multiple IPs, Same Username)**
- Attacker: Uses botnet, each IP attempts password once against same account.
- Example: 100 different IPs, 1 attempt each against username "admin".
- **Defense:** Cross-IP pattern detection (complex). Add secondary check: per-username failure count (ignoring IP). If username "admin" sees 50 failures in 5min across any IPs, block temporarily. Trade-off: higher false-positive risk.

**Bypass 2: Low-and-Slow (1 attempt/hour per IP, spread across many days)**
- Attacker: Avoids triggering per-IP thresholds by slowing down.
- **Defense:** Add long-term model: if username has >20 failures in 30 days, increase scrutiny (challenge, MFA, account lock). Use FR-025 cumulative risk scoring.

**Bypass 3: Valid User Enumeration + Targeted Spray**
- Attacker: First phase: enumerate valid usernames (different error messages).
- Second phase: password spray on confirmed users only.
- **Defense:** Ensure login endpoint returns **same error message** for invalid username and invalid password. Rate-limit /login endpoint globally (FR-004). Integrate with FR-025 cumulative risk: first phase (enum) raises risk, second phase (spray) triggers challenge/block.

---

### False-Positive Mitigation

**Scenario A: Legitimate User Forgets Password, Multiple Failed Logins**
- Example: User tries password 4 times, then clicks "Forgot Password" link. Expected behavior.
- **Mitigation:**
  - Config: Set threshold high (e.g., 10 failures) for non-critical tiers.
  - Soft block: Challenge (JS/CAPTCHA) instead of hard block for first few hits.
  - Monitor: Track if user clicks "Forgot Password" after N failures — whitelist, don't block.

**Scenario B: Shared Account (Multiple Users, Legitimate)**
- Example: Shared test account used by QA team from different IPs.
- **Mitigation:**
  - Whitelist high-entropy usernames that are known to be shared.
  - Config param: `shared_accounts: ["test.user", "demo", "qa"]` → raise thresholds for these.
  - Alternative: Use service accounts instead of shared user accounts.

**Scenario C: Business Logic: API Client Retries After Transient Error**
- Example: API client fails auth, auto-retries 3 times. Looks like brute force.
- **Mitigation:**
  - Distinguish: 401 (auth failure) vs. 503 (server error). Retrying after 503 is legitimate.
  - Reduce window: If retry interval is < 100ms, likely a legitimate client retry (not human).
  - Whitelist by User-Agent or API key prefix (e.g., `X-API-Key` header indicates service account).

---

### Pseudo-Rust Signature

```rust
pub struct BruteForceCheck {
    failed_logins: Arc<DashMap<(u64, IpAddr), VecDeque<Instant>>>,
    password_spray: Arc<DashMap<(IpAddr, u64), (usize, HashSet<String>)>>,
    window: Duration,
    max_per_user: usize,
    spray_threshold: usize,
    login_routes: Arc<Vec<String>>, // ["/login", "/api/auth/token"]
}

impl Check for BruteForceCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.brute_force {
            return None;
        }

        // Only check on login routes
        if !self.login_routes.iter().any(|r| ctx.path.contains(r)) {
            return None;
        }

        // This is a REQUEST-PHASE check: we don't know if login succeeded yet.
        // We'll hook RESPONSE phase to record actual failures.
        // For now, return None; response hook will populate state.
        None
    }
}

// Separate response-phase handler (must be registered in pipeline)
pub async fn brute_force_response_hook(
    ctx: &RequestCtx,
    resp_status: u16,
    resp_body: &[u8],
    check: &Arc<BruteForceCheck>,
) {
    if !check.login_routes.iter().any(|r| ctx.path.contains(r)) {
        return;
    }

    let failed = detect_failed_login_via_response(ctx, resp_status, resp_body);
    if !failed {
        return;
    }

    // Extract username from request (JSON body, form data, or query param)
    if let Some(username) = extract_username_from_request(ctx) {
        check.record_failed_login(&username, ctx.client_ip);

        // Check if exceeded threshold
        if check.check_failed_login(&username, ctx.client_ip) {
            // LOG or trigger action: block this IP+user combo
            tracing::warn!("BRUTE_FORCE: {} from {} exceeded failure threshold",
                           username, ctx.client_ip);
        }
    }

    // Password spray detection
    if let Some(password) = extract_password_from_request(ctx) {
        check.record_login_attempt(ctx.client_ip, &username, &password, true);
        
        if check.is_spray_attack(ctx.client_ip, &password) {
            tracing::warn!("PASSWORD_SPRAY: {} has been tried against 5+ users", password);
        }
    }
}
```

**Reference Sources:**
- **OWASP ASVS V2.2.1:** Account recovery and registration requirements, brute force mitigation.
- **NIST SP 800-63B-3:** Authentication and Lifecycle Management. Recommends: account lockout (5–15min), per-account rate limiting, monitoring for anomalies.
- **OWASP Top 10 2025 A07:** Authentication Failures, explicitly calls out password spray with seasonal/incremental variations.

---

## FR-020: Request Body Abuse Detection

### Pattern Rules & Detection Logic

**Rule 1: Malformed JSON (Parse Failure)**
```rust
fn detect_malformed_json(body: &[u8]) -> Option<DetectionResult> {
    // Only check if Content-Type is application/json
    if !content_type_is_json(content_type_header) {
        return None;
    }

    // Try parse with serde_json
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(_) => None, // Valid JSON
        Err(e) => {
            // Invalid JSON
            Some(DetectionResult {
                rule_id: Some("BODY-001".to_string()),
                rule_name: "Malformed JSON: Parse Failure".to_string(),
                phase: Phase::RequestBodyAbuse,
                detail: format!("JSON parse error: {e}"),
            })
        }
    }
}
```
**Intent:** Malformed JSON with Content-Type mismatch is often fuzz attacks or intentional DoS payloads.

**Rule 2: Oversized Payload (vs. Content-Length or Actual Bytes)**
```rust
fn detect_oversized_payload(ctx: &RequestCtx, max_body_size: usize) -> bool {
    // Check 1: Content-Length header vs. size limit
    if let Some(cl_header) = ctx.headers.get("content-length") {
        if let Ok(cl) = cl_header.parse::<usize>() {
            if cl > max_body_size {
                return true; // Oversized
            }
        }
    }

    // Check 2: Actual body preview size
    if ctx.body_preview.len() > max_body_size {
        return true;
    }

    false
}
```
**Intent:** Content-Length = 10MB but max_body_size = 1MB. Per-route config in FR-023.

**Rule 3: Deeply Nested Objects (Recursion Depth > N)**
```rust
fn detect_deep_nesting(value: &serde_json::Value, max_depth: usize) -> bool {
    fn walk(v: &serde_json::Value, depth: usize, max: usize) -> bool {
        if depth > max {
            return true; // Too deep
        }
        match v {
            serde_json::Value::Object(obj) => {
                obj.values().any(|child| walk(child, depth + 1, max))
            }
            serde_json::Value::Array(arr) => {
                arr.iter().any(|child| walk(child, depth + 1, max))
            }
            _ => false,
        }
    }
    walk(value, 0, max_depth)
}
```
**Intent:** `{ "a": { "b": { "c": ... }}} ` with 500+ levels causes stack exhaustion (CVE-2025-67221, CVE-2025-53864).

**Rule 4: Key-Count Anomaly (Payload Size Explosion)**
```rust
fn detect_key_explosion(value: &serde_json::Value, max_keys: usize) -> bool {
    fn count_keys(v: &serde_json::Value) -> usize {
        match v {
            serde_json::Value::Object(obj) => {
                obj.len() + obj.values().map(count_keys).sum::<usize>()
            }
            serde_json::Value::Array(arr) => {
                arr.iter().map(count_keys).sum()
            }
            _ => 0,
        }
    }
    count_keys(value) > max_keys
}
```
**Intent:** Payload with 1M keys (small per-key, large total) can exhaust memory.

**Rule 5: Content-Type Mismatch (Declared vs. Sniffed Magic Byte)**
```rust
fn detect_content_type_mismatch(
    content_type_header: &str,
    body_bytes: &[u8],
) -> Option<&'static str> {
    let declared = content_type_header.split(';').next().unwrap_or("").trim();
    
    // Sniff magic bytes
    let actual = if body_bytes.starts_with(b"{") || body_bytes.starts_with(b"[") {
        "application/json"
    } else if body_bytes.starts_with(b"<") {
        "text/xml" // or application/xml
    } else if body_bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        "application/zip"
    } else if body_bytes.starts_with(&[0x1F, 0x8B]) {
        "application/gzip"
    } else {
        "text/plain"
    };
    
    if declared != actual {
        return Some(actual);
    }
    
    None
}
```
**Intent:** Attacker declares `application/json` but sends ZIP bomb or XML. Mismatch = reject.

---

### Top 3 Known Bypasses & Defenses

**Bypass 1: Zip/Gzip Bombs (Deferred)**
- Attacker: Sends ZIP with 1MB of repetitive data, inflates to 1GB.
- **Defense:** Marked **DEFERRED** in FR-020 scope. Implementation:
  - Sniff magic bytes (0x504B = PK = ZIP).
  - If found in request body, log but don't decompress. Let upstream handle.
  - Optional (expensive): Decompress with size limit (max 100MB), timeout 500ms. Reject if exceeds.

**Bypass 2: XML Bomb (Billion Laughs Attack)**
- Attacker: XML with nested entity references expands exponentially.
- **Defense:** Deferred. If XML processing required: disable external entity processing (XXE protection). Use libxml2 with `XML_PARSE_NOENT` disabled.

**Bypass 3: Application-Specific Parsing Bomb**
- Attacker: Payload valid per JSON spec but triggers O(n²) parsing in app (e.g., repeated key collisions).
- **Defense:** Heuristic limits: max 10K keys, max 100 depth. Accept that some bombs slip through; rely on app-level timeouts.

---

### False-Positive Mitigation

**Scenario A: Legitimate CSV-in-JSON (Newline-Heavy)**
- Example: `{ "data": "col1,col2\nval1,val2\nval3,val4\n..." }` — large but valid JSON.
- **Mitigation:**
  - Increase max_body_size for non-critical routes.
  - Whitelist: If route is known to accept bulk data, add exception rule.

**Scenario B: Deeply Nested API Response Embedded in Request**
- Example: Webhook forwards upstream response (which has 50-level nesting) as-is in request body.
- **Mitigation:**
  - Reduce max_depth threshold only for specific routes (per FR-023).
  - Log with context; don't hard-block. Let app decide.

**Scenario C: Legitimate Recursive Data Structure**
- Example: Tree-based API (file system, org hierarchy) naturally has deep nesting.
- **Mitigation:**
  - Route-level config: `max_json_depth: 200` for routes like `/api/tree/upload`.
  - Use soft block: challenge + log, don't reject.

---

### Pseudo-Rust Signature

```rust
pub struct RequestBodyAbuseCheck {
    max_body_size: usize,  // e.g., 1MB = 1_048_576
    max_json_depth: usize, // e.g., 100
    max_json_keys: usize,  // e.g., 10_000
}

impl Check for RequestBodyAbuseCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.body_abuse {
            return None;
        }

        // Rule 2: Oversized payload
        if ctx.body_preview.len() > self.max_body_size {
            return Some(DetectionResult {
                rule_id: Some("BODY-002".to_string()),
                rule_name: "Oversized Payload".to_string(),
                phase: Phase::RequestBodyAbuse,
                detail: format!("Body size {} exceeds limit {}", ctx.body_preview.len(), self.max_body_size),
            });
        }

        // Rule 5: Content-Type mismatch
        if let Some(ct) = ctx.headers.get("content-type") {
            if let Some(actual) = detect_content_type_mismatch(ct, &ctx.body_preview) {
                return Some(DetectionResult {
                    rule_id: Some("BODY-005".to_string()),
                    rule_name: "Content-Type Mismatch".to_string(),
                    phase: Phase::RequestBodyAbuse,
                    detail: format!("Declared: {}, Actual: {}", ct, actual),
                });
            }
        }

        // Rules 1, 3, 4: JSON parsing + structure validation
        if let Some(ct) = ctx.headers.get("content-type") {
            if ct.contains("application/json") {
                match serde_json::from_slice::<serde_json::Value>(&ctx.body_preview) {
                    Err(e) => {
                        // Rule 1: Malformed JSON
                        return Some(DetectionResult {
                            rule_id: Some("BODY-001".to_string()),
                            rule_name: "Malformed JSON".to_string(),
                            phase: Phase::RequestBodyAbuse,
                            detail: format!("Parse error: {e}"),
                        });
                    }
                    Ok(json_value) => {
                        // Rule 3: Deep nesting
                        if detect_deep_nesting(&json_value, self.max_json_depth) {
                            return Some(DetectionResult {
                                rule_id: Some("BODY-003".to_string()),
                                rule_name: "Deeply Nested JSON".to_string(),
                                phase: Phase::RequestBodyAbuse,
                                detail: format!("Nesting depth exceeds {}", self.max_json_depth),
                            });
                        }

                        // Rule 4: Key explosion
                        if detect_key_explosion(&json_value, self.max_json_keys) {
                            return Some(DetectionResult {
                                rule_id: Some("BODY-004".to_string()),
                                rule_name: "JSON Key Explosion".to_string(),
                                phase: Phase::RequestBodyAbuse,
                                detail: format!("Key count exceeds {}", self.max_json_keys),
                            });
                        }
                    }
                }
            }
        }

        None
    }
}
```

**Reference Incidents:**
- **CVE-2025-67221 (orjson):** Unbounded recursion for deeply nested JSON; DoS via stack exhaustion.
- **CVE-2025-53864 (Nimbus JOSE+JWT):** Deeply nested JSON in JWT claims causes stack overflow.
- **CVE-2026-32141 (flatted):** Unbounded recursion in parse() during revive phase.

**OWASP References:**
- OWASP Input Validation Cheat Sheet (size limits, type validation).
- API4: Unrestricted Resource Consumption (JSON bomb detection as part of rate limiting and resource accounting).

---

## Cross-Cutting Concerns

### Performance Budget Enforcement
- Each check (SSRF, HeaderInjection, BruteForce-request-phase, BodyAbuse) must complete **< 200µs on p99**.
- Strategies:
  - SSRF: LazyLock RegexSet (compiled once, reused). DNS resolution optional + timeout 50ms (async).
  - HeaderInjection: Fast regex + string operations, no I/O.
  - BodyAbuse: JSON parse is O(n); limit to 1MB payload (default), reject oversized before parse.
  - BruteForce: DashMap lookup O(1) expected; no I/O.

### Configuration & Scoping (FR-023)
- Each check must respect host-level `DefenseConfig` toggle.
- Per-route thresholds: config file or API can override defaults.
  - Example: `/api/admin/*` has stricter SSRF rules; `/api/public/webhook/*` allows internal IPs.

### State Management & Cleanup
- BruteForce state (DashMap + VecDeque) must evict old entries (background task, 15min default window).
- Use `tokio::spawn_blocking()` for cleanup to avoid blocking async runtime.

### Logging & Observability
- Each detection result includes: rule_id, rule_name, phase, detail, timestamp.
- Log structured JSON for SIEM integration (FR-032).
- Example: `{"rule_id":"SSRF-001","phase":"ssrf","client_ip":"1.2.3.4","req_id":"abc123","detail":"RFC1918: 10.0.0.1"}`

---

## Unresolved Questions

1. **FR-018 Response Hook Timing:** When exactly is the response hook fired relative to the upstream response? Can it fire BEFORE the response body is sent to the client (so we can inject a Challenge header)?
   
2. **FR-016 DNS Resolution Blocking:** If DNS resolution during SSRF check blocks (even for 50ms), will this violate the p99 < 200µs latency budget under load? Should resolution be async-only with a fallback to reject on timeout?

3. **FR-020 JSON Parsing Limits:** serde_json doesn't natively limit depth or key count; must manually walk the tree. Will this add 50-100µs latency for moderate payloads? Should we use a custom deserializer?

4. **FR-017 Host Header SNI Matching:** If the request is HTTP (not TLS), there's no SNI. Should Host header validation be lenient for HTTP traffic, or still enforce whitelist?

5. **Distributed Brute Force (FR-018):** The per-user-per-IP model doesn't catch coordinated attacks across 100 IPs. Should we add a secondary per-username global counter, and at what cost (global state contention)?

6. **False-Positive Tuning:** Is there an automated mechanism to tune thresholds (max_failures, spray_threshold, etc.) based on observed traffic patterns, or is this manual config?

---

## Summary

**FR-016 (SSRF):** Regex RFC1918 + metadata endpoints, handle obfuscation (octal/hex/IPv6-mapped), optional DNS rebinding check. Capital One (2019) proof: must catch 169.254.169.254.

**FR-017 (Header Injection):** CRLF detection (raw + encoded), Host header validation (SNI match or whitelist), X-Forwarded-For sanity check. OWASP CRS rule 921150 as baseline.

**FR-018 (Brute Force):** Stateful per-user-per-IP counter + password spray (same pwd × many users). Response-aware hook required. Tradeoff: distributed attacks bypass per-IP model; mitigate with per-username global counter.

**FR-020 (Body Abuse):** JSON malformed + oversized + depth + key-explosion + type mismatch. Zip/XML bombs deferred. serde_json walk for depth/key limits, custom deserializer if latency issues.

---

**Sources:**
- [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Capital One Breach Analysis: AWS IMDS SSRF](https://www.zscaler.com/resources/white-papers/capital-one-data-breach.pdf)
- [OWASP CRLF Injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)
- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 2025 A07: Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- [GitHub: SSRF Bypass Techniques and IP Obfuscation](https://dominicbreuker.com/post/filters_bypasses_rare_ipv4_formats_for_ssrf/)
- [MITRE ATT&CK: Password Spraying Detection Strategy](https://attack.mitre.org/detectionstrategies/DET0487/)
- [CVE-2025-67221: orjson Recursion Limit Bypass](https://advisories.gitlab.com/pkg/pypi/orjson/CVE-2025-67221/)
- [CVE-2025-53864: Nimbus JOSE+JWT DoS via Deeply Nested JSON](https://vulert.com/vuln-db/CVE-2025-53864/)
- [OWASP CRS Core Rule Set GitHub](https://github.com/coreruleset/coreruleset)
