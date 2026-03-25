---
title: Synapse Feature Reference
---

# Synapse Feature Reference

Complete feature inventory for the Synapse WAF engine.

## Feature Matrix

| Feature | Module | Default | Performance |
| --- | --- | --- | --- |
| WAF Detection | `waf/` | Enabled | ~10–25 μs |
| Entity Tracking | `entity/` | Enabled | 45 ns lookup |
| Actor Fingerprinting | `actor/` | Enabled | — |
| Session Management | `session/` | Enabled | 304 ns |
| DLP Scanning | `dlp/` | Disabled | ~34 μs (4 KB) |
| Rate Limiting | `ratelimit/` | Enabled | 61 ns |
| Bot/Crawler Detection | `crawler/` | Enabled | — |
| Behavioral Profiling | `profiler/` | Enabled | — |
| Campaign Correlation | `correlation/` | Enabled | — |
| Geo/Impossible Travel | `geo/` | Enabled | — |
| Shadow Mirroring | `shadow/` | Disabled | — |
| Tarpit | `tarpit/` | Enabled | — |
| TLS/SNI | `tls/` | Disabled | — |
| CAPTCHA/JS Challenge | `interrogator/` | Enabled | — |
| Honeypot Traps | `trap/` | Enabled | 33 ns |
| Telemetry to Horizon | `telemetry/` | Disabled | — |
| Config Hot-Reload | `reload/` | Enabled | ~240 μs |
| Access Lists | `access/` | Enabled | 156 ns (100 rules) |

## Detection Engine

### WAF Rules

237 production rules with 99.8% OWASP CRS coverage (4,122/4,131 tests) and 0% false positives (GoTestWAF validated).

**Rule categories:**

| Category | Coverage |
| --- | --- |
| SQL Injection (SQLi) | UNION, boolean, tautology, stacked, blind, time-based |
| Cross-Site Scripting (XSS) | Script injection, event handlers, SVG, DOM manipulation |
| Path Traversal | Literal, URL-encoded, double-encoded, null byte variants |
| Command Injection | Shell commands, pipe, backtick, semicolon chaining |
| LDAP Injection | Directory service attack patterns |
| XML External Entity (XXE) | XML parser exploitation |

Each rule has a risk score (0–100). Scores accumulate per-request; the request is blocked when the total exceeds `waf_threshold` (default: 70).

**Detection actions:** `block` (HTTP 403), `log` (forward + log), `challenge` (CAPTCHA/JS).

**Evasion resistance:** All payloads pass through a multi-stage decoder (URL decode → HTML entity → Unicode normalization → case folding) before rule evaluation. Regex timeout at `waf_regex_timeout_ms` (default: 100 ms) prevents ReDoS. All evasion techniques detected under 34 μs.

### Detection Pipeline (8 Phases)

Every request goes through the complete detection cycle in ~75 μs:

| Phase | What It Does | Cost |
| --- | --- | --- |
| 1. Context Building | Parse method, URI, query params, headers. Compute feature flags. | ~30 ns |
| 2. Actor Store | Lookup/create actor by IP. Update last-seen. Record UA fingerprint. | ~15 ns |
| 3. Credential Stuffing | Check if auth endpoint. Record attempt if yes. | ~3 ns (non-auth) |
| 4. Profile Anomaly | Lookup endpoint baseline. Check for unusual params, payload, method. | ~40 ns |
| 5. Candidate Selection | Rule index filters 237 rules → ~35 candidates via bitmask. Cache lookup. | ~15 ns |
| 6. Rule Evaluation | Evaluate ~35 candidate rules at ~5.7 ns each. Short-circuit on first false. | ~200 ns |
| 7. Entity Tracking | Update entity risk. Apply decay. Record rule contributions. | ~30 ns |
| 8. Verdict | Aggregate risk. Determine action (Allow/Challenge/Block). | ~15 ns |

### DLP Scanning

Data Loss Prevention scans request bodies for sensitive data.

**Supported pattern types (22):**

| Type | Detection Method |
| --- | --- |
| Credit card numbers | Regex + Luhn checksum validation |
| Social Security Numbers | Format validation |
| IBAN numbers | Mod-97 checksum |
| Phone numbers | US area code validation |
| API keys / tokens | JWT, Bearer tokens, common key patterns |
| Private keys | RSA, SSH key detection |
| Crypto addresses | BTC, ETH wallet patterns |
| Database strings | Connection string detection |
| Custom patterns | User-defined regex |

**DLP actions:** `mask` (redact in-place), `hash` (replace with hash), `block` (reject request), `log` (forward + log).

**Performance optimizations:**
- Aho-Corasick prefilter for multi-pattern detection (30–50% faster than sequential regex)
- Content-type short circuit — binary types automatically skipped
- Inspection depth cap — truncate body scan at `max_body_inspection_bytes` (default: 8 KB)

## Entity & Actor Tracking

### Entity Tracking

Track IP addresses and fingerprints across requests with cumulative risk scoring.

- **Risk accumulation** — entity risk grows with each detected threat
- **Automatic blocking** — entities exceeding the block threshold are rejected on sight
- **Decay** — risk scores decay over time to handle transient spikes

### Actor Correlation

The ActorManager (1,450 LOC) correlates requests across multiple IPs into unified actor identities using composite signals:

| Signal | Weight | Purpose |
| --- | --- | --- |
| JA4 TLS Fingerprint | High | Stable across IP rotation |
| JA4H HTTP Fingerprint | High | Browser/client behavior |
| Auth Token | Definitive | Links authenticated sessions |
| User-Agent Hash | Medium | Client identification |
| Header Order | Low | Implementation fingerprint |

- **100K actor LRU cache** with O(1) DashMap lookup
- **Probabilistic eviction** — ~20x faster than linear scan
- **Persistence** — snapshots to disk on interval, survives restarts

### Session Intelligence

The SessionManager (1,562 LOC) provides stateful session tracking with hijack detection.

- **Session binding** — JA4 fingerprint + auth token + IP composite key
- **50K active sessions** with LRU eviction
- **Token extraction** — JWT parsing, Bearer tokens, Cookie session IDs
- **304 ns** per-request validation

**Hijack detection signals:**

| Detection | Signal | Risk |
| --- | --- | --- |
| Fingerprint Mutation | JA4/JA4H change within session | +40 points |
| Impossible Travel | Geo-location change faster than possible | +60 points |
| Token Reuse | Same token from different fingerprints | +50 points |
| Concurrent Sessions | Same user, different locations simultaneously | +35 points |

## Network Security

### Rate Limiting

Per-client-IP rate limiting with configurable RPS threshold.

- **Pre-TLS** — rate limiting runs in `early_request_filter` before TLS handshake
- **Per-site** — hostname-aware rate limits when using virtual hosts
- **Performance** — 61 ns per check

### Access Lists

IP-based allow/deny lists per site.

- **CIDR support** — allow or deny ranges
- **Per-site** — different ACLs per virtual host
- **Performance** — 156 ns for 100 rules

### Tarpit

Progressive delays against malicious actors using non-blocking async delays (Tokio).

- **Formula:** `delay = base_delay × 1.5^(level-1)`, max 30 s
- **10 levels** of increasing delays
- **Per-IP state** with automatic decay
- **LRU eviction** — max 10K states

## Bot Detection

### Crawler Verification

500+ crawler signatures with multi-layer detection.

**Detection layers:**

| Layer | Method |
| --- | --- |
| Signature-Based | User-Agent pattern matching against 500+ known crawlers |
| DNS Verification | Reverse DNS + forward validation for claimed identities (Googlebot, Bingbot, etc.) |
| Client Integrity | TLS fingerprint vs. User-Agent consistency (catches spoofed browser identities) |
| Behavioral | Request patterns, timing, coverage analysis for headless browsers |

**Bot categories:** SearchEngine, SocialMedia, Monitoring, Security, DataMining, Automation, Malicious, AI (GPTBot, ClaudeBot), Unknown.

**Bot policy** is configurable per category — allow verified search engines, challenge unverified bots, block malicious bots, set AI crawler policy.

### Headless Browser Detection

The InjectionTracker (1,078 LOC) detects headless browsers that bypass JS challenges:

| Signal | Indicator |
| --- | --- |
| Timing Variance | JS execution time too consistent |
| Fingerprint Stability | Canvas/WebGL identical across sessions |
| Navigator Anomalies | `navigator.webdriver`, mismatched plugins |
| Request Rate | Faster than human possible |

Detects Puppeteer, Playwright, Selenium, curl/wget, and Python requests through behavioral signals and challenge feedback loops.

## Advanced Features

### Schema Learning

The SchemaLearner (2,297 LOC) automatically learns and enforces API schemas at ~5 μs validation latency — 100x faster than the TypeScript implementation.

**Type detection:** UUID, email, ISO dates, credit cards, API keys, JWT — all auto-detected with format validation.

**Enforcement signals:**

| Check | Signal |
| --- | --- |
| Missing required field | `SCHEMA_VIOLATION` (Medium) |
| Type mismatch | `SCHEMA_VIOLATION` (Medium) |
| Unknown field (strict mode) | `SCHEMA_VIOLATION` (Low) |
| Array size anomaly | `PAYLOAD_ANOMALY` (Low) |

### Response Profiling

Analyzes upstream server responses to detect exfiltration and application-layer attacks.

| Anomaly | Detection | Indicates |
| --- | --- | --- |
| Unusual response size | > 3σ from baseline | Data exfiltration, IDOR |
| Error rate spike | > 2x baseline | Fuzzing, enumeration |
| Latency anomaly | > 3σ from baseline | Blind injection, DoS |
| Content-type mismatch | Unexpected MIME type | Content injection |
| Status code anomaly | Unusual distribution | Application errors |

Baselines are learned per-endpoint. Minimum 100 observations before triggering anomalies.

### Header Profiling

Per-endpoint header baselining and anomaly detection.

- **Profiled headers:** Authorization, X-API-Key, Cookie, User-Agent, Accept-Language, Origin, Referer, Content-Type
- **Anomaly types:** missing expected header, unexpected new header, value outside distribution, header order change

### Credential Stuffing Detection

Detects automated login attacks using leaked credentials.

| Signal | Threshold | Indicates |
| --- | --- | --- |
| High failure rate | > 90% failures over 10+ attempts | Credential list attack |
| Username enumeration | > 20 unique usernames per IP in 5 min | Account enumeration |
| Distributed attack | Same username from 5+ IPs in 1 hour | Distributed stuffing |
| Velocity anomaly | > 10 attempts per minute per IP | Automated tool |
| Fingerprint rotation | 3+ fingerprints per IP in 10 min | Evasion attempt |

::: info Privacy
Synapse hashes usernames before storage. Actual credentials are never stored — only statistical patterns.
:::

### Campaign Correlation

8 weighted detectors identify coordinated attack campaigns:

| Detector | Weight | Signal |
| --- | --- | --- |
| Graph Correlation | 55 | Multi-hop IP ↔ JA4 ↔ Token ↔ ASN relationships |
| Attack Sequence | 50 | Sequential attack patterns (probe → exploit → post-exploit) |
| Auth Token | 45 | Shared authentication tokens across IPs |
| HTTP Fingerprint | 40 | JA4H header fingerprint sharing |
| TLS Fingerprint | 35 | JA4 TLS fingerprint sharing across IPs |
| Behavioral Similarity | 30 | Anomaly behavior matching |
| Timing Correlation | 25 | Request timing pattern analysis |
| Network Proximity | 15 | IP geolocation clustering |

Fingerprint indexing provides O(1) lookup. Heavy detection cycles run in background workers, not blocking requests.

### Graph Correlation

Models attack infrastructure as a connected graph for multi-hop discovery.

**Node types:** IP, JA4, JA4H, AuthToken, ASN, UserAgent.

**Edge types with weights:**

| Edge | Relationship | Weight |
| --- | --- | --- |
| UsedFingerprint | IP → JA4/JA4H | 0.7 |
| UsedToken | IP → AuthToken | 0.9 |
| SharedFingerprint | IP ↔ IP (via JA4) | 0.8 |
| SharedToken | IP ↔ IP (via Token) | 0.95 |
| SameAsn | IP → ASN | 0.3 |
| SameUserAgent | IP → UA Hash | 0.5 |

**2nd-degree discovery:** traverse from a known-bad IP through shared fingerprints and tokens to discover related attackers that share no direct attributes.

### Shadow Mirroring

Test rules safely against production traffic.

- **Mirror mode** — duplicate traffic to a shadow detection pipeline
- **Comparison reports** — see what would be blocked by new rules
- **Zero impact** — shadow results don't affect production responses

### Impossible Travel Detection

GeoIP-based detection of physically impossible session movements.

- **Speed calculation** — compare geographic distance vs. time between requests
- **Configurable thresholds** — adjust for your user base's travel patterns

### Challenge Escalation (Interrogator)

5-level progressive challenge system that separates legitimate users from automated attacks:

1. **Tarpit delays** — progressive slowdown (100 ms → 30 s)
2. **Cookie challenge** — inject tracking cookie with HMAC signing, verify acceptance
3. **JS proof-of-work** — SHA-256 computational challenge
4. **CAPTCHA** — human verification for persistent threats
5. **Block** — full block after repeated failures

Includes automatic **de-escalation** — challenge level reduces after successful passes.

### Honeypot Traps

Hidden endpoints that catch automated scanners.

- **Trap endpoints** — configure fake paths that only automated tools would visit
- **Instant flagging** — any request to a trap immediately escalates the actor's risk
- **Performance** — 33 ns trap matching

### Auto-Mitigation

Risk-based automated defensive actions without human intervention.

| Action | Trigger | Effect |
| --- | --- | --- |
| AutoBlock | Entity risk ≥ threshold (default: 80) | Block all requests from IP for configured duration |
| Challenge Escalation | Repeated challenge failures | Escalate Cookie → JS → CAPTCHA |
| Tarpit | Suspicious bot behavior | Progressive delay injection |
| Rate Limit | High request velocity | Temporary per-IP rate limit |
| Campaign Block | Campaign membership detected | Block all IPs in coordinated campaign |

Auto-blocks expire after configured duration. Risk decay and de-escalation prevent false positive lock-out. Admin API provides manual override.

### Multi-Site Support

Single binary, multiple sites with independent WAF policies.

- **Exact hostname matching** — O(1) lookup via ahash HashMap
- **Wildcard patterns** — `*.example.com` with specificity ordering
- **Default site** — `_` or `default` as catch-all
- **Per-site config** — independent WAF threshold, rate limits, access lists, rule overrides, upstreams
- **Multi-upstream load balancing** — weighted round-robin per site

### Configuration Hot-Reload

Update configuration without downtime.

- **Atomic swap** — new config replaces old via `RwLock` swap in ~240 μs
- **No dropped requests** — in-flight requests continue on the old config
- **Validation** — new config is parsed and validated before swapping
- **Admin API** — `POST /reload` with admin key authentication

## Memory Budget

| Component | Limit | Memory |
| --- | --- | --- |
| ActorManager | 100K actors | ~50 MB |
| SessionManager | 50K sessions | ~25–40 MB |
| ProfilerManager | 10K templates | ~30 MB |
| InterrogatorManager | 10K tarpit + 50K cookies + 10K challenges | ~40 MB |
| InjectionTracker | 50K records | ~25 MB |
| **Total** | — | **~170 MB** |

All state is in-memory with LRU eviction. Persistence snapshots to disk on interval — WAF retains intelligence across restarts with no cold-start learning period.
