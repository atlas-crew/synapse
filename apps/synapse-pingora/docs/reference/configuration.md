# Synapse Sensor Configuration Reference

Complete YAML configuration reference for the Synapse Sensor (synapse-pingora).

## Configuration File

The sensor loads configuration from a YAML file specified at startup:

```bash
synapse-pingora --config /etc/synapse/config.yaml
```

**Security limits:**
- Maximum file size: 10MB
- Path traversal detection on all file paths
- TLS certificate/key paths validated at load time

---

## Server Settings

Global proxy and admin server configuration.

```yaml
server:
  http_addr: "0.0.0.0:80"
  https_addr: "0.0.0.0:443"
  workers: 0
  shutdown_timeout_secs: 30
  waf_threshold: 70
  waf_enabled: true
  log_level: "info"
  admin_api_key: ""
  waf_regex_timeout_ms: 100
  trap_config:
    enabled: true
    paths: [...]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `http_addr` | string | `"0.0.0.0:80"` | HTTP listen address |
| `https_addr` | string | `"0.0.0.0:443"` | HTTPS listen address |
| `workers` | integer | `0` | Worker threads (0 = auto-detect CPU cores) |
| `shutdown_timeout_secs` | integer | `30` | Graceful shutdown timeout in seconds |
| `waf_threshold` | integer | `70` | Global WAF risk score threshold (1-100) |
| `waf_enabled` | boolean | `true` | Enable WAF protection globally |
| `log_level` | string | `"info"` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `admin_api_key` | string | auto-generated | Static admin API key (secure random if empty) |
| `waf_regex_timeout_ms` | integer | `100` | WAF regex timeout for ReDoS protection (max 500ms) |
| `trap_config` | object | see below | Honeypot trap endpoint configuration |

### Trap Configuration

Honeypot trap endpoints detect reconnaissance by triggering on paths legitimate users never access.

```yaml
trap_config:
  enabled: true
  paths:
    - "/.git/*"
    - "/.env"
    - "/.env.*"
    - "/admin/backup*"
    - "/wp-admin/*"
    - "/phpmyadmin/*"
    - "/.svn/*"
    - "/.htaccess"
    - "/web.config"
    - "/config.php"
  apply_max_risk: true
  extended_tarpit_ms: 5000
  alert_telemetry: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable trap detection |
| `paths` | string[] | see above | Glob patterns for trap paths |
| `apply_max_risk` | boolean | `true` | Apply maximum risk score (100) on trap hit |
| `extended_tarpit_ms` | integer | `5000` | Additional tarpit delay for trap hits (ms) |
| `alert_telemetry` | boolean | `true` | Send telemetry alerts on trap hits |

**Glob syntax:**
- `*` matches any characters except `/`
- `**` matches any characters including `/`
- `?` matches exactly one character

---

## Rate Limiting

Global rate limiting configuration. Can be overridden per-site.

```yaml
rate_limit:
  rps: 10000
  enabled: true
  burst: 20000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rps` | integer | `10000` | Requests per second limit |
| `enabled` | boolean | `true` | Enable rate limiting |
| `burst` | integer | `2 × rps` | Burst capacity (allows temporary spikes) |

---

## Profiler

Endpoint behavior learning for anomaly detection.

```yaml
profiler:
  enabled: true
  max_profiles: 1000
  max_schemas: 500
  min_samples_for_validation: 100
  payload_z_threshold: 3.0
  param_z_threshold: 4.0
  response_z_threshold: 4.0
  min_stddev: 0.01
  type_ratio_threshold: 0.9
  max_type_counts: 10
  redact_pii: true
  freeze_after_samples: 0
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable endpoint profiling |
| `max_profiles` | integer | `1000` | Maximum endpoint profiles to maintain |
| `max_schemas` | integer | `500` | Maximum learned JSON schemas |
| `min_samples_for_validation` | integer | `100` | Samples required before enforcing profiles |
| `payload_z_threshold` | float | `3.0` | Z-score threshold for payload size anomalies |
| `param_z_threshold` | float | `4.0` | Z-score threshold for parameter value anomalies |
| `response_z_threshold` | float | `4.0` | Z-score threshold for response size anomalies |
| `min_stddev` | float | `0.01` | Minimum standard deviation (prevents div/0) |
| `type_ratio_threshold` | float | `0.9` | Ratio threshold for type-based anomaly detection |
| `max_type_counts` | integer | `10` | Maximum type categories per parameter |
| `redact_pii` | boolean | `true` | Redact sensitive values in anomaly logs |
| `freeze_after_samples` | integer | `0` | Lock baseline after N samples (0 = continuous learning) |

---

## Tarpit

Progressive response delays for suspicious actors.

```yaml
tarpit:
  enabled: true
  base_delay_ms: 1000
  max_delay_ms: 30000
  progressive_multiplier: 1.5
  max_states: 10000
  decay_threshold_ms: 300000
  cleanup_threshold_ms: 1800000
  max_concurrent_tarpits: 1000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable tarpitting |
| `base_delay_ms` | integer | `1000` | Base delay in milliseconds (1 second) |
| `max_delay_ms` | integer | `30000` | Maximum delay in milliseconds (30 seconds) |
| `progressive_multiplier` | float | `1.5` | Delay multiplier per level |
| `max_states` | integer | `10000` | Maximum tracked IPs (LRU eviction) |
| `decay_threshold_ms` | integer | `300000` | Decay level after idle time (5 min) |
| `cleanup_threshold_ms` | integer | `1800000` | Remove state after idle time (30 min) |
| `max_concurrent_tarpits` | integer | `1000` | Maximum concurrent delays (prevents exhaustion) |

**Delay calculation:** `delay = base × multiplier^(level-1)`, capped at `max_delay_ms`

---

## DLP (Data Loss Prevention)

Scans response bodies for PII and sensitive data.

```yaml
dlp:
  enabled: true
  max_scan_size: 5242880
  max_matches: 10
  scan_text_only: true
  max_body_inspection_bytes: 8192
  fast_mode: false
  custom_keywords:
    - "project-codename"
  redaction:
    credit_card: "mask"
    ssn: "hash"
    api_key: "full"
  hash_salt: "random-32-byte-string"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable DLP scanning |
| `max_scan_size` | integer | `5242880` | Maximum body size to accept (5MB, reject if larger) |
| `max_matches` | integer | `10` | Stop scanning after N matches |
| `scan_text_only` | boolean | `true` | Only scan text/* content types |
| `max_body_inspection_bytes` | integer | `8192` | Truncate scan at this size (8KB) |
| `fast_mode` | boolean | `false` | Skip low-priority patterns for performance |
| `custom_keywords` | string[] | `[]` | Custom keywords to detect |
| `redaction` | map | `{}` | Per-type redaction mode |
| `hash_salt` | string | required for hash | Salt for hash-based redaction (min 32 bytes) |

**Redaction modes:**
- `mask` - Replace with asterisks (e.g., `****-****-****-1234`)
- `hash` - Replace with SHA-256 hash (requires `hash_salt`)
- `full` - Remove entirely

**Detected data types:** `credit_card`, `ssn`, `email`, `phone`, `api_key`, `password`, `iban`, `ip_address`, `aws_key`, `private_key`, `jwt`, `medical_record`, `custom`

---

## Crawler Detection

Bot detection and verification.

```yaml
crawler:
  enabled: true
  verify_legitimate_crawlers: true
  block_bad_bots: true
  dns_cache_ttl_secs: 300
  verification_cache_ttl_secs: 3600
  max_cache_entries: 50000
  dns_timeout_ms: 2000
  max_concurrent_dns_lookups: 100
  dns_failure_policy: "apply_risk_penalty"
  dns_failure_risk_penalty: 50
  max_stats_entries: 1000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable crawler detection |
| `verify_legitimate_crawlers` | boolean | `true` | DNS verification for Googlebot, Bingbot, etc. |
| `block_bad_bots` | boolean | `true` | Block known malicious bots |
| `dns_cache_ttl_secs` | integer | `300` | DNS cache TTL (5 minutes) |
| `verification_cache_ttl_secs` | integer | `3600` | Verification result cache (1 hour) |
| `max_cache_entries` | integer | `50000` | Maximum cache entries |
| `dns_timeout_ms` | integer | `2000` | DNS lookup timeout |
| `max_concurrent_dns_lookups` | integer | `100` | Concurrent DNS limit (prevents exhaustion) |
| `dns_failure_policy` | string | `"apply_risk_penalty"` | Policy on DNS failure |
| `dns_failure_risk_penalty` | integer | `50` | Risk penalty when DNS fails |
| `max_stats_entries` | integer | `1000` | Maximum stats entries per bot type |

**DNS failure policies:**
- `allow` - Allow request through (fail-open, not recommended)
- `apply_risk_penalty` - Continue with elevated risk score (default)
- `block` - Block request entirely (fail-secure)

---

## Telemetry

Event reporting to external collectors.

```yaml
telemetry:
  enabled: false
  endpoint: "http://localhost:8080/telemetry"
  api_key: ""
  batch_size: 100
  flush_interval_secs: 10
  max_retries: 3
  max_buffer_size: 10000
  circuit_breaker_threshold: 5
  circuit_breaker_timeout_secs: 60
  instance_id: ""
  dry_run: false
  enabled_events: []
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable telemetry |
| `endpoint` | string | `"http://localhost:8080/telemetry"` | Telemetry endpoint URL |
| `api_key` | string | `""` | API key for authentication |
| `batch_size` | integer | `100` | Events per batch |
| `flush_interval_secs` | integer | `10` | Flush interval in seconds |
| `max_retries` | integer | `3` | Maximum retry attempts |
| `max_buffer_size` | integer | `10000` | Maximum buffered events |
| `circuit_breaker_threshold` | integer | `5` | Failures before circuit opens |
| `circuit_breaker_timeout_secs` | integer | `60` | Circuit breaker reset timeout |
| `instance_id` | string | `""` | Sensor instance identifier |
| `dry_run` | boolean | `false` | Skip HTTP sending (for testing) |
| `enabled_events` | string[] | `[]` | Event types to send (empty = all) |

**Event types:** `request_processed`, `waf_block`, `rate_limit_hit`, `config_reload`, `service_health`, `sensor_report`, `campaign_report`

---

## Horizon (Fleet Intelligence)

WebSocket connection to Signal Horizon Hub for fleet-wide threat sharing.

```yaml
horizon:
  enabled: false
  hub_url: "wss://horizon.example.com/ws"
  api_key: ""
  sensor_id: ""
  sensor_name: ""
  reconnect_delay_ms: 5000
  max_reconnect_attempts: 0
  circuit_breaker_threshold: 5
  circuit_breaker_cooldown_ms: 300000
  signal_batch_size: 100
  signal_batch_delay_ms: 1000
  heartbeat_interval_ms: 30000
  max_queued_signals: 1000
  blocklist_cache_ttl_secs: 3600
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable Horizon integration |
| `hub_url` | string | `""` | WebSocket URL for Hub |
| `api_key` | string | `""` | API key (required when enabled) |
| `sensor_id` | string | `""` | Unique sensor ID (required when enabled) |
| `sensor_name` | string | `""` | Human-readable sensor name |
| `reconnect_delay_ms` | integer | `5000` | Reconnection delay |
| `max_reconnect_attempts` | integer | `0` | Max reconnections (0 = unlimited) |
| `circuit_breaker_threshold` | integer | `5` | Failures before circuit opens |
| `circuit_breaker_cooldown_ms` | integer | `300000` | Circuit breaker cooldown (5 min) |
| `signal_batch_size` | integer | `100` | Signals per batch |
| `signal_batch_delay_ms` | integer | `1000` | Batch delay |
| `heartbeat_interval_ms` | integer | `30000` | Heartbeat interval |
| `max_queued_signals` | integer | `1000` | Maximum queued signals when disconnected |
| `blocklist_cache_ttl_secs` | integer | `3600` | Blocklist cache TTL |

---

## Payload Profiling

Bandwidth and payload size anomaly detection.

```yaml
payload:
  enabled: true
  window_duration_ms: 60000
  max_windows: 60
  max_endpoints: 5000
  max_entities: 10000
  oversize_threshold: 3.0
  bandwidth_spike_threshold: 5.0
  warmup_requests: 100
  exfiltration_ratio_threshold: 100.0
  upload_ratio_threshold: 100.0
  min_large_payload_bytes: 100000
  timeline_max_buckets: 1440
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable payload profiling |
| `window_duration_ms` | integer | `60000` | Window duration (1 minute) |
| `max_windows` | integer | `60` | Windows to retain (1 hour) |
| `max_endpoints` | integer | `5000` | Maximum tracked endpoints |
| `max_entities` | integer | `10000` | Maximum tracked entities |
| `oversize_threshold` | float | `3.0` | Multiplier of p99 for oversized detection |
| `bandwidth_spike_threshold` | float | `5.0` | Multiplier of average for spike detection |
| `warmup_requests` | integer | `100` | Requests before detection activates |
| `exfiltration_ratio_threshold` | float | `100.0` | Response/request byte ratio for exfiltration |
| `upload_ratio_threshold` | float | `100.0` | Request/response byte ratio for upload pattern |
| `min_large_payload_bytes` | integer | `100000` | Minimum size to flag as large (100KB) |
| `timeline_max_buckets` | integer | `1440` | Maximum bandwidth history buckets |

---

## Trends

Time-series anomaly detection for authentication and behavioral patterns.

```yaml
trends:
  enabled: true
  bucket_size_ms: 60000
  retention_hours: 24
  max_signals_per_bucket: 10000
  anomaly_check_interval_ms: 60000
  max_entities: 10000
  max_recent_signals: 100
  max_anomalies: 1000
  anomaly_risk:
    fingerprint_change: 30
    session_sharing: 50
    token_reuse: 40
    velocity_spike: 15
    rotation_pattern: 35
    timing_anomaly: 10
    impossible_travel: 25
    ja4_rotation_pattern: 45
    ja4_ip_cluster: 35
    ja4_browser_spoofing: 60
    ja4h_change: 25
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable trends tracking |
| `bucket_size_ms` | integer | `60000` | Time bucket size (1 minute) |
| `retention_hours` | integer | `24` | Data retention (24 hours) |
| `max_signals_per_bucket` | integer | `10000` | Maximum signals per bucket |
| `anomaly_check_interval_ms` | integer | `60000` | Anomaly check interval |
| `max_entities` | integer | `10000` | Maximum tracked entities |
| `max_recent_signals` | integer | `100` | Recent signals cached per entity |
| `max_anomalies` | integer | `1000` | Maximum retained anomalies |
| `anomaly_risk` | map | see above | Risk scores per anomaly type |

**Anomaly types:**
- `fingerprint_change` - TLS/HTTP fingerprint changed
- `session_sharing` - Session used from multiple IPs
- `token_reuse` - Token reused after expiry
- `velocity_spike` - Sudden request rate increase
- `rotation_pattern` - Credential rotation detected
- `timing_anomaly` - Unusual request timing
- `impossible_travel` - Geographic impossibility
- `ja4_rotation_pattern` - JA4 fingerprint rotation
- `ja4_ip_cluster` - Multiple IPs with same JA4
- `ja4_browser_spoofing` - JA4 doesn't match claimed browser
- `ja4h_change` - JA4H fingerprint changed

---

## Sites

Virtual host configurations with hostname-based routing.

```yaml
sites:
  - hostname: "example.com"
    upstreams:
      - host: "127.0.0.1"
        port: 8080
        weight: 1
    tls:
      cert_path: "/etc/certs/example.pem"
      key_path: "/etc/certs/example.key"
      min_version: "1.2"
    waf:
      enabled: true
      threshold: 60
      rule_overrides:
        "sqli-001": "log"
    rate_limit:
      rps: 5000
      enabled: true
      burst: 10000
    access_control:
      allow:
        - "10.0.0.0/8"
      deny:
        - "0.0.0.0/0"
      default_action: "deny"
    headers:
      request:
        add: { X-Forwarded-Proto: "https" }
        set: { Host: "backend.internal" }
        remove: ["X-Debug"]
      response:
        set: { X-Frame-Options: "DENY" }
        remove: ["Server"]
    shadow_mirror:
      enabled: true
      honeypot_urls: ["http://honeypot:8080/mirror"]
```

### Site Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | yes | Hostname or wildcard pattern |
| `upstreams` | array | yes | Backend servers (at least one) |
| `tls` | object | no | TLS configuration |
| `waf` | object | no | WAF override |
| `rate_limit` | object | no | Rate limit override |
| `access_control` | object | no | IP-based access control |
| `headers` | object | no | Header manipulation |
| `shadow_mirror` | object | no | Traffic mirroring to honeypot |

### Hostname Patterns

```yaml
# Exact match
hostname: "example.com"

# Wildcard subdomain
hostname: "*.example.com"

# More specific wildcard (higher priority)
hostname: "*.api.example.com"

# Multi-segment wildcard
hostname: "api-*.prod.example.com"

# Catch-all default
hostname: "_"
# or
hostname: "default"
```

**Wildcard rules:**
- `*` matches alphanumeric characters and hyphens (`[a-z0-9-]*`)
- Maximum 3 wildcards per pattern (ReDoS protection)
- Maximum 253 characters per hostname (RFC 1035)
- More specific patterns (more segments) match first
- `_` or `default` serves as catch-all

### Upstream Configuration

```yaml
upstreams:
  - host: "127.0.0.1"      # Hostname or IP
    port: 8080              # Port number
    weight: 1               # Load balancing weight (default: 1)
```

Higher weight = more traffic. Upstreams are load-balanced using weighted round-robin.

### TLS Configuration

```yaml
tls:
  cert_path: "/etc/certs/server.pem"    # PEM certificate path
  key_path: "/etc/certs/server.key"     # PEM private key path
  min_version: "1.2"                    # "1.2" or "1.3"
```

Paths are validated at config load time. Path traversal (`..`) is blocked.

### WAF Override

```yaml
waf:
  enabled: true
  threshold: 60                          # Override global threshold
  rule_overrides:
    "sqli-001": "log"                   # Log instead of block
    "xss-002": "block"                  # Explicitly block
    "scanner-001": "pass"               # Allow through
```

**Rule actions:** `block`, `log`, `pass`

### Access Control

```yaml
access_control:
  allow:
    - "10.0.0.0/8"
    - "192.168.1.0/24"
    - "203.0.113.50/32"
  deny:
    - "0.0.0.0/0"
  default_action: "deny"               # "allow" or "deny"
```

Rules are evaluated in order: first matching `allow` or `deny` wins, then `default_action`.

### Header Manipulation

```yaml
headers:
  request:
    add:
      X-Request-ID: "{{uuid}}"          # Add header (append if exists)
    set:
      Host: "backend.internal"          # Set header (replace if exists)
    remove:
      - "X-Debug"                       # Remove header
  response:
    set:
      X-Frame-Options: "DENY"
      Strict-Transport-Security: "max-age=31536000"
    remove:
      - "Server"
      - "X-Powered-By"
```

### Shadow Mirroring

Mirror suspicious traffic to honeypot for analysis.

```yaml
shadow_mirror:
  enabled: true
  min_risk_score: 40.0                  # Mirror if risk >= 40
  max_risk_score: 70.0                  # Don't mirror if >= 70 (blocked)
  honeypot_urls:
    - "http://honeypot:8080/mirror"
    - "http://honeypot2:8080/mirror"    # Load balanced
  sampling_rate: 1.0                    # 0.0-1.0 (1.0 = 100%)
  per_ip_rate_limit: 10                 # Per-IP requests/minute
  timeout_secs: 5                       # Delivery timeout
  hmac_secret: ""                       # Payload signing secret
  include_body: true                    # Include request body
  max_body_size: 1048576                # Max body size (1MB)
  include_headers:
    - "User-Agent"
    - "Referer"
    - "Origin"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable shadow mirroring |
| `min_risk_score` | float | `40.0` | Minimum risk to trigger mirror |
| `max_risk_score` | float | `70.0` | Maximum risk (above = blocked, no mirror) |
| `honeypot_urls` | string[] | `[]` | Honeypot endpoint URLs |
| `sampling_rate` | float | `1.0` | Sampling rate (0.0-1.0) |
| `per_ip_rate_limit` | integer | `10` | Per-IP rate limit (requests/minute) |
| `timeout_secs` | integer | `5` | Delivery timeout |
| `hmac_secret` | string | `""` | HMAC secret for payload signing |
| `include_body` | boolean | `true` | Include request body in mirror |
| `max_body_size` | integer | `1048576` | Maximum body size to mirror |
| `include_headers` | string[] | see above | Headers to include in mirror |

---

## Example Configuration

Minimal production configuration:

```yaml
server:
  http_addr: "0.0.0.0:80"
  https_addr: "0.0.0.0:443"
  waf_threshold: 70
  waf_enabled: true
  log_level: "info"

rate_limit:
  rps: 10000
  enabled: true

profiler:
  enabled: true

sites:
  - hostname: "api.example.com"
    upstreams:
      - host: "api-backend.internal"
        port: 8080
    tls:
      cert_path: "/etc/certs/api.pem"
      key_path: "/etc/certs/api.key"
    waf:
      enabled: true
      threshold: 60

  - hostname: "*.example.com"
    upstreams:
      - host: "web-backend.internal"
        port: 8080

  - hostname: "_"
    upstreams:
      - host: "default-backend.internal"
        port: 8080
```

---

## Environment Variables

Some fields can be set via environment variables for secrets management:

| Config Path | Environment Variable |
|-------------|---------------------|
| `server.admin_api_key` | `SYNAPSE_ADMIN_API_KEY` |
| `telemetry.api_key` | `SYNAPSE_TELEMETRY_API_KEY` |
| `horizon.api_key` | `SYNAPSE_HORIZON_API_KEY` |
| `dlp.hash_salt` | `SYNAPSE_DLP_HASH_SALT` |

Environment variables take precedence over config file values.

---

## Validation Errors

Common validation errors and solutions:

| Error | Solution |
|-------|----------|
| `site 'X' has no upstreams configured` | Add at least one upstream to the site |
| `duplicate hostname: X` | Each hostname must be unique |
| `WAF threshold 0 effectively disables protection` | Use `waf.enabled: false` or set threshold 1-100 |
| `path traversal detected` | Remove `..` from file paths |
| `TLS certificate not found` | Verify cert_path exists and is readable |
| `pattern 'X' has N wildcards, max is 3` | Reduce wildcards in hostname pattern |
| `invalid risk score range` | Ensure min_risk_score < max_risk_score |
