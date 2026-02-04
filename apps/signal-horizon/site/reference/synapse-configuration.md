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

| Field | Type | Default | Constraints | Description |
|-------|------|---------|-------------|-------------|
| `http_addr` | string | `"0.0.0.0:80"` | `host:port` format | HTTP listen address |
| `https_addr` | string | `"0.0.0.0:443"` | `host:port` format | HTTPS listen address |
| `workers` | integer | `0` | 0-1024 | Worker threads (0 = auto-detect CPU cores) |
| `shutdown_timeout_secs` | integer | `30` | 1-300 | Graceful shutdown timeout in seconds |
| `waf_threshold` | integer | `70` | 1-100 | Global WAF risk score threshold |
| `waf_enabled` | boolean | `true` | — | Enable WAF protection globally |
| `log_level` | string | `"info"` | enum | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `admin_api_key` | string | auto-generated | min 16 chars if set | Static admin API key (secure random if empty) |
| `waf_regex_timeout_ms` | integer | `100` | 1-500 | WAF regex timeout for ReDoS protection |
| `trap_config` | object | see below | — | Honeypot trap endpoint configuration |

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

| Field | Type | Default | Constraints | Description |
|-------|------|---------|-------------|-------------|
| `enabled` | boolean | `true` | — | Enable trap detection |
| `paths` | string[] | see above | max 100 patterns | Glob patterns for trap paths |
| `apply_max_risk` | boolean | `true` | — | Apply maximum risk score (100) on trap hit |
| `extended_tarpit_ms` | integer | `5000` | 0-60000 | Additional tarpit delay for trap hits (ms) |
| `alert_telemetry` | boolean | `true` | — | Send telemetry alerts on trap hits |

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

| Field | Type | Default | Constraints | Description |
|-------|------|---------|-------------|-------------|
| `rps` | integer | `10000` | 1-1000000 | Requests per second limit |
| `enabled` | boolean | `true` | — | Enable rate limiting |
| `burst` | integer | `2 × rps` | ≥ rps | Burst capacity (allows temporary spikes) |

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

| Field | Type | Default | Constraints | Description |
|-------|------|---------|-------------|-------------|
| `enabled` | boolean | `true` | — | Enable endpoint profiling |
| `max_profiles` | integer | `1000` | 1-100000 | Maximum endpoint profiles to maintain |
| `max_schemas` | integer | `500` | 1-50000 | Maximum learned JSON schemas |
| `min_samples_for_validation` | integer | `100` | 10-10000 | Samples required before enforcing profiles |
| `payload_z_threshold` | float | `3.0` | 1.0-10.0 | Z-score threshold for payload size anomalies |
| `param_z_threshold` | float | `4.0` | 1.0-10.0 | Z-score threshold for parameter value anomalies |
| `response_z_threshold` | float | `4.0` | 1.0-10.0 | Z-score threshold for response size anomalies |
| `min_stddev` | float | `0.01` | 0.001-1.0 | Minimum standard deviation (prevents div/0) |
| `type_ratio_threshold` | float | `0.9` | 0.5-1.0 | Ratio threshold for type-based anomaly detection |
| `max_type_counts` | integer | `10` | 1-100 | Maximum type categories per parameter |
| `redact_pii` | boolean | `true` | — | Redact sensitive values in anomaly logs |
| `freeze_after_samples` | integer | `0` | 0-1000000 | Lock baseline after N samples (0 = continuous learning) |

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

| Field | Type | Default | Constraints | Description |
|-------|------|---------|-------------|-------------|
| `enabled` | boolean | `true` | — | Enable tarpitting |
| `base_delay_ms` | integer | `1000` | 100-60000 | Base delay in milliseconds |
| `max_delay_ms` | integer | `30000` | ≥ base_delay_ms | Maximum delay in milliseconds |
| `progressive_multiplier` | float | `1.5` | 1.0-5.0 | Delay multiplier per level |
| `max_states` | integer | `10000` | 100-1000000 | Maximum tracked IPs (LRU eviction) |
| `decay_threshold_ms` | integer | `300000` | 1000-3600000 | Decay level after idle time |
| `cleanup_threshold_ms` | integer | `1800000` | > decay_threshold_ms | Remove state after idle time |
| `max_concurrent_tarpits` | integer | `1000` | 10-100000 | Maximum concurrent delays (prevents exhaustion) |

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

| Field | Type | Default | Constraints | Description |
|-------|------|---------|-------------|-------------|
| `enabled` | boolean | `true` | — | Enable DLP scanning |
| `max_scan_size` | integer | `5242880` | 1024-104857600 | Maximum body size to accept (reject if larger) |
| `max_matches` | integer | `10` | 1-1000 | Stop scanning after N matches |
| `scan_text_only` | boolean | `true` | — | Only scan text/* content types |
| `max_body_inspection_bytes` | integer | `8192` | 1024-10485760 | Truncate scan at this size |
| `fast_mode` | boolean | `false` | — | Skip low-priority patterns for performance |
| `custom_keywords` | string[] | `[]` | max 1000 keywords | Custom keywords to detect |
| `redaction` | map | `{}` | valid keys only | Per-type redaction mode |
| `hash_salt` | string | required for hash | min 32 bytes | Salt for hash-based redaction |

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

| Field | Type | Default | Constraints | Description |
|-------|------|---------|-------------|-------------|
| `enabled` | boolean | `true` | — | Enable crawler detection |
| `verify_legitimate_crawlers` | boolean | `true` | — | DNS verification for Googlebot, Bingbot, etc. |
| `block_bad_bots` | boolean | `true` | — | Block known malicious bots |
| `dns_cache_ttl_secs` | integer | `300` | 60-86400 | DNS cache TTL |
| `verification_cache_ttl_secs` | integer | `3600` | 300-86400 | Verification result cache |
| `max_cache_entries` | integer | `50000` | 1000-1000000 | Maximum cache entries |
| `dns_timeout_ms` | integer | `2000` | 100-30000 | DNS lookup timeout |
| `max_concurrent_dns_lookups` | integer | `100` | 1-1000 | Concurrent DNS limit (prevents exhaustion) |
| `dns_failure_policy` | string | `"apply_risk_penalty"` | enum | Policy on DNS failure |
| `dns_failure_risk_penalty` | integer | `50` | 0-100 | Risk penalty when DNS fails |
| `max_stats_entries` | integer | `1000` | 100-100000 | Maximum stats entries per bot type |

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
  endpoint: "http://localhost:3100/telemetry"
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

| Field | Type | Default | Constraints | Description |
|-------|------|---------|-------------|-------------|
| `enabled` | boolean | `false` | — | Enable telemetry |
| `endpoint` | string | `"http://localhost:3100/telemetry"` | valid URL | Telemetry endpoint URL |
| `api_key` | string | `""` | — | API key for authentication |
| `batch_size` | integer | `100` | 1-10000 | Events per batch |
| `flush_interval_secs` | integer | `10` | 1-300 | Flush interval in seconds |
| `max_retries` | integer | `3` | 0-10 | Maximum retry attempts |
| `max_buffer_size` | integer | `10000` | 100-1000000 | Maximum buffered events |
| `circuit_breaker_threshold` | integer | `5` | 1-100 | Failures before circuit opens |
| `circuit_breaker_timeout_secs` | integer | `60` | 10-3600 | Circuit breaker reset timeout |
| `instance_id` | string | `""` | max 64 chars | Sensor instance identifier |
| `dry_run` | boolean | `false` | — | Skip HTTP sending (for testing) |
| `enabled_events` | string[] | `[]` | valid event types | Event types to send (empty = all) |

**Event types:** `request_processed`, `waf_block`, `rate_limit_hit`, `config_reload`, `service_health`, `sensor_report`, `campaign_report`

Signal Horizon also accepts legacy `/_sensor/report` endpoints for backward compatibility.

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

| Field | Type | Default | Constraints | Description |
|-------|------|---------|-------------|-------------|
| `enabled` | boolean | `false` | — | Enable Horizon integration |
| `hub_url` | string | `""` | wss:// URL, required if enabled | WebSocket URL for Hub |
| `api_key` | string | `""` | required if enabled | API key for authentication |
| `sensor_id` | string | `""` | required if enabled, UUID format | Unique sensor ID |
| `sensor_name` | string | `""` | max 128 chars | Human-readable sensor name |
| `reconnect_delay_ms` | integer | `5000` | 1000-300000 | Reconnection delay |
| `max_reconnect_attempts` | integer | `0` | 0-1000 (0 = unlimited) | Max reconnections |
| `circuit_breaker_threshold` | integer | `5` | 1-100 | Failures before circuit opens |
| `circuit_breaker_cooldown_ms` | integer | `300000` | 10000-3600000 | Circuit breaker cooldown |
| `signal_batch_size` | integer | `100` | 1-10000 | Signals per batch |
| `signal_batch_delay_ms` | integer | `1000` | 100-60000 | Batch delay |
| `heartbeat_interval_ms` | integer | `30000` | 5000-300000 | Heartbeat interval |
| `max_queued_signals` | integer | `1000` | 100-100000 | Maximum queued signals when disconnected |
| `blocklist_cache_ttl_secs` | integer | `3600` | 60-86400 | Blocklist cache TTL |

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

| Field | Type | Default | Constraints | Description |
|-------|------|---------|-------------|-------------|
| `enabled` | boolean | `true` | — | Enable payload profiling |
| `window_duration_ms` | integer | `60000` | 1000-3600000 | Window duration |
| `max_windows` | integer | `60` | 1-1440 | Windows to retain |
| `max_endpoints` | integer | `5000` | 100-100000 | Maximum tracked endpoints |
| `max_entities` | integer | `10000` | 100-1000000 | Maximum tracked entities |
| `oversize_threshold` | float | `3.0` | 1.5-100.0 | Multiplier of p99 for oversized detection |
| `bandwidth_spike_threshold` | float | `5.0` | 2.0-100.0 | Multiplier of average for spike detection |
| `warmup_requests` | integer | `100` | 10-10000 | Requests before detection activates |
| `exfiltration_ratio_threshold` | float | `100.0` | 10.0-10000.0 | Response/request byte ratio for exfiltration |
| `upload_ratio_threshold` | float | `100.0` | 10.0-10000.0 | Request/response byte ratio for upload pattern |
| `min_large_payload_bytes` | integer | `100000` | 1024-104857600 | Minimum size to flag as large |
| `timeline_max_buckets` | integer | `1440` | 60-10080 | Maximum bandwidth history buckets |

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

| Field | Type | Default | Constraints | Description |
|-------|------|---------|-------------|-------------|
| `enabled` | boolean | `true` | — | Enable trends tracking |
| `bucket_size_ms` | integer | `60000` | 1000-3600000 | Time bucket size |
| `retention_hours` | integer | `24` | 1-168 | Data retention |
| `max_signals_per_bucket` | integer | `10000` | 100-1000000 | Maximum signals per bucket |
| `anomaly_check_interval_ms` | integer | `60000` | 1000-3600000 | Anomaly check interval |
| `max_entities` | integer | `10000` | 100-1000000 | Maximum tracked entities |
| `max_recent_signals` | integer | `100` | 10-10000 | Recent signals cached per entity |
| `max_anomalies` | integer | `1000` | 100-100000 | Maximum retained anomalies |
| `anomaly_risk` | map | see above | values 0-100 | Risk scores per anomaly type |

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

| Field | Type | Default | Constraints | Description |
|-------|------|---------|-------------|-------------|
| `enabled` | boolean | `false` | — | Enable shadow mirroring |
| `min_risk_score` | float | `40.0` | 0.0-100.0, < max_risk_score | Minimum risk to trigger mirror |
| `max_risk_score` | float | `70.0` | 0.0-100.0, > min_risk_score | Maximum risk (above = blocked, no mirror) |
| `honeypot_urls` | string[] | `[]` | valid URLs, required if enabled | Honeypot endpoint URLs |
| `sampling_rate` | float | `1.0` | 0.0-1.0 | Sampling rate (100% = 1.0) |
| `per_ip_rate_limit` | integer | `10` | 1-10000 | Per-IP rate limit (requests/minute) |
| `timeout_secs` | integer | `5` | 1-60 | Delivery timeout |
| `hmac_secret` | string | `""` | min 32 bytes if set | HMAC secret for payload signing |
| `include_body` | boolean | `true` | — | Include request body in mirror |
| `max_body_size` | integer | `1048576` | 1024-104857600 | Maximum body size to mirror |
| `include_headers` | string[] | see above | max 100 headers | Headers to include in mirror |

---

## Example Configurations

### Minimal Configuration

Basic setup with sensible defaults:

```yaml
server:
  http_addr: "0.0.0.0:80"
  https_addr: "0.0.0.0:443"
  waf_enabled: true
  log_level: "info"

sites:
  - hostname: "api.example.com"
    upstreams:
      - host: "backend.internal"
        port: 8080
    tls:
      cert_path: "/etc/certs/api.pem"
      key_path: "/etc/certs/api.key"
```

### Complete Production Configuration

Enterprise-grade configuration with all major features enabled:

```yaml
# =============================================================================
# Synapse Sensor - Production Configuration
# =============================================================================

server:
  http_addr: "0.0.0.0:80"
  https_addr: "0.0.0.0:443"
  workers: 0                           # Auto-detect CPU cores
  shutdown_timeout_secs: 30
  waf_threshold: 70                    # Global threshold (can override per-site)
  waf_enabled: true
  log_level: "info"
  waf_regex_timeout_ms: 100            # ReDoS protection
  trap_config:
    enabled: true
    paths:
      - "/.git/*"
      - "/.env"
      - "/.env.*"
      - "/admin/backup*"
      - "/wp-admin/*"
      - "/phpmyadmin/*"
      - "/.aws/*"
      - "/config.php"
    apply_max_risk: true
    extended_tarpit_ms: 5000
    alert_telemetry: true

# -----------------------------------------------------------------------------
# Rate Limiting - Global defaults (override per-site as needed)
# -----------------------------------------------------------------------------
rate_limit:
  rps: 10000
  enabled: true
  burst: 20000

# -----------------------------------------------------------------------------
# Endpoint Profiling - Behavioral baseline learning
# -----------------------------------------------------------------------------
profiler:
  enabled: true
  max_profiles: 5000
  max_schemas: 2000
  min_samples_for_validation: 100
  payload_z_threshold: 3.0
  param_z_threshold: 4.0
  response_z_threshold: 4.0
  redact_pii: true
  freeze_after_samples: 0              # Continuous learning

# -----------------------------------------------------------------------------
# Tarpit - Progressive delays for bad actors
# -----------------------------------------------------------------------------
tarpit:
  enabled: true
  base_delay_ms: 1000
  max_delay_ms: 30000
  progressive_multiplier: 1.5
  max_states: 50000
  max_concurrent_tarpits: 5000

# -----------------------------------------------------------------------------
# DLP - Response body scanning for sensitive data
# -----------------------------------------------------------------------------
dlp:
  enabled: true
  max_scan_size: 5242880               # 5MB max body
  max_matches: 10
  scan_text_only: true
  max_body_inspection_bytes: 8192      # Scan first 8KB
  redaction:
    credit_card: "mask"
    ssn: "hash"
    api_key: "full"
  # hash_salt set via SYNAPSE_DLP_HASH_SALT env var

# -----------------------------------------------------------------------------
# Crawler Detection - Bot verification and blocking
# -----------------------------------------------------------------------------
crawler:
  enabled: true
  verify_legitimate_crawlers: true     # DNS verification for Googlebot, etc.
  block_bad_bots: true
  dns_cache_ttl_secs: 300
  verification_cache_ttl_secs: 3600
  dns_timeout_ms: 2000
  dns_failure_policy: "apply_risk_penalty"
  dns_failure_risk_penalty: 50

# -----------------------------------------------------------------------------
# Telemetry - Event reporting to external collector
# -----------------------------------------------------------------------------
telemetry:
  enabled: true
  endpoint: "https://collector.example.com/api/v1/events"
  batch_size: 100
  flush_interval_secs: 10
  max_retries: 3
  max_buffer_size: 10000
  circuit_breaker_threshold: 5
  circuit_breaker_timeout_secs: 60
  instance_id: "prod-sensor-01"
  # api_key set via SYNAPSE_TELEMETRY_API_KEY env var

# -----------------------------------------------------------------------------
# Horizon - Fleet intelligence and threat sharing
# -----------------------------------------------------------------------------
horizon:
  enabled: true
  hub_url: "wss://horizon.example.com/ws"
  sensor_name: "prod-edge-01"
  reconnect_delay_ms: 5000
  max_reconnect_attempts: 0            # Unlimited retries
  circuit_breaker_threshold: 5
  circuit_breaker_cooldown_ms: 300000
  signal_batch_size: 100
  heartbeat_interval_ms: 30000
  max_queued_signals: 10000
  blocklist_cache_ttl_secs: 3600
  # sensor_id and api_key set via env vars

# -----------------------------------------------------------------------------
# Payload Profiling - Bandwidth and size anomaly detection
# -----------------------------------------------------------------------------
payload:
  enabled: true
  window_duration_ms: 60000
  max_windows: 60
  max_endpoints: 10000
  oversize_threshold: 3.0
  bandwidth_spike_threshold: 5.0
  warmup_requests: 100
  exfiltration_ratio_threshold: 100.0
  upload_ratio_threshold: 100.0
  min_large_payload_bytes: 100000

# -----------------------------------------------------------------------------
# Trends - Time-series anomaly detection
# -----------------------------------------------------------------------------
trends:
  enabled: true
  bucket_size_ms: 60000
  retention_hours: 24
  max_entities: 50000
  anomaly_risk:
    fingerprint_change: 30
    session_sharing: 50
    token_reuse: 40
    velocity_spike: 15
    impossible_travel: 25
    ja4_browser_spoofing: 60

# -----------------------------------------------------------------------------
# Sites - Virtual host configurations
# -----------------------------------------------------------------------------
sites:
  # API backend - strict WAF, lower threshold
  - hostname: "api.example.com"
    upstreams:
      - host: "api-backend-1.internal"
        port: 8080
        weight: 2
      - host: "api-backend-2.internal"
        port: 8080
        weight: 1
    tls:
      cert_path: "/etc/certs/api.pem"
      key_path: "/etc/certs/api.key"
      min_version: "1.2"
    waf:
      enabled: true
      threshold: 60                    # Stricter than global
      rule_overrides:
        "scanner-001": "log"           # Log scanner detection, don't block
    rate_limit:
      rps: 5000
      burst: 10000
    headers:
      request:
        set:
          X-Real-IP: "{{client_ip}}"
      response:
        set:
          X-Frame-Options: "DENY"
          X-Content-Type-Options: "nosniff"
          Strict-Transport-Security: "max-age=31536000; includeSubDomains"
        remove:
          - "Server"
          - "X-Powered-By"

  # Web app - moderate protection with shadow mirroring
  - hostname: "www.example.com"
    upstreams:
      - host: "web-backend.internal"
        port: 8080
    tls:
      cert_path: "/etc/certs/www.pem"
      key_path: "/etc/certs/www.key"
      min_version: "1.2"
    waf:
      enabled: true
      threshold: 70
    rate_limit:
      rps: 10000
    access_control:
      deny:
        - "192.0.2.0/24"               # Block known bad range
      default_action: "allow"
    shadow_mirror:
      enabled: true
      min_risk_score: 40.0
      max_risk_score: 70.0
      honeypot_urls:
        - "http://honeypot.internal:8080/mirror"
      sampling_rate: 1.0
      per_ip_rate_limit: 10
      include_body: true
      max_body_size: 1048576

  # Internal admin - IP-restricted
  - hostname: "admin.example.com"
    upstreams:
      - host: "admin-backend.internal"
        port: 8080
    tls:
      cert_path: "/etc/certs/admin.pem"
      key_path: "/etc/certs/admin.key"
      min_version: "1.3"               # TLS 1.3 only for admin
    access_control:
      allow:
        - "10.0.0.0/8"
        - "192.168.0.0/16"
      default_action: "deny"
    waf:
      enabled: true
      threshold: 50                    # Very strict

  # Wildcard subdomain catch-all
  - hostname: "*.example.com"
    upstreams:
      - host: "default-backend.internal"
        port: 8080
    waf:
      enabled: true
      threshold: 70

  # Default fallback
  - hostname: "_"
    upstreams:
      - host: "fallback-backend.internal"
        port: 8080
    waf:
      enabled: true
      threshold: 80                    # Lenient for unknown hosts
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

### Configuration Structure Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid YAML syntax` | Malformed YAML | Check indentation, quotes, and special characters |
| `unknown field 'X'` | Typo or deprecated field | Check field name spelling against this reference |
| `expected type T, got U` | Wrong value type | Use correct type (e.g., integer not string for ports) |
| `config file exceeds 10MB limit` | File too large | Split into includes or reduce comments |

### Server Settings Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid address format` | Malformed listen address | Use `host:port` format (e.g., `0.0.0.0:80`) |
| `workers must be 0-1024` | Invalid worker count | Use 0 for auto-detect or 1-1024 |
| `WAF threshold must be 1-100` | Threshold out of range | Set threshold between 1 and 100 |
| `WAF threshold 0 effectively disables protection` | Zero threshold | Use `waf.enabled: false` or set threshold 1-100 |
| `waf_regex_timeout_ms exceeds 500ms limit` | Timeout too high | Reduce to 500ms or less (ReDoS protection) |
| `admin_api_key too short (min 16 chars)` | Weak API key | Use at least 16 characters or leave empty for auto-generation |

### Site Configuration Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `site 'X' has no upstreams configured` | Missing upstreams | Add at least one upstream to the site |
| `duplicate hostname: X` | Repeated hostname | Each hostname must be unique across all sites |
| `hostname exceeds 253 characters` | Hostname too long | Use shorter hostname (RFC 1035 limit) |
| `pattern 'X' has N wildcards, max is 3` | Too many wildcards | Reduce wildcards in hostname pattern (ReDoS protection) |
| `invalid upstream port` | Port out of range | Use port 1-65535 |
| `upstream weight must be positive` | Zero or negative weight | Use weight >= 1 |

### TLS Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `TLS certificate not found` | Missing file | Verify cert_path exists and is readable |
| `TLS key not found` | Missing file | Verify key_path exists and is readable |
| `path traversal detected` | Suspicious path | Remove `..` from file paths |
| `invalid TLS version` | Unknown version | Use `"1.2"` or `"1.3"` |
| `certificate and key mismatch` | Mismatched pair | Ensure cert and key belong together |

### Rate Limiting Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `rps must be 1-1000000` | RPS out of range | Set RPS between 1 and 1,000,000 |
| `burst must be >= rps` | Burst too small | Set burst equal to or greater than RPS |

### DLP Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `hash_salt required when using hash redaction` | Missing salt | Set `hash_salt` (min 32 bytes) or use env var |
| `hash_salt too short (min 32 bytes)` | Weak salt | Use at least 32 bytes for cryptographic security |
| `invalid redaction mode` | Unknown mode | Use `mask`, `hash`, or `full` |
| `unknown data type for redaction` | Invalid key | See detected data types list |

### Shadow Mirror Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid risk score range` | Inverted range | Ensure min_risk_score < max_risk_score |
| `honeypot_urls required when shadow_mirror enabled` | Missing URLs | Add at least one honeypot URL |
| `invalid honeypot URL` | Malformed URL | Use valid HTTP/HTTPS URLs |
| `sampling_rate must be 0.0-1.0` | Invalid rate | Use decimal between 0.0 and 1.0 |

### Horizon (Fleet) Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `hub_url required when horizon enabled` | Missing URL | Set WebSocket URL (wss://) |
| `api_key required when horizon enabled` | Missing auth | Set API key via config or SYNAPSE_HORIZON_API_KEY |
| `sensor_id required when horizon enabled` | Missing ID | Set unique sensor ID (UUID format) |
| `invalid WebSocket URL` | Wrong protocol | Use `wss://` protocol for hub_url |

### Access Control Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid CIDR notation` | Malformed IP range | Use valid CIDR (e.g., `10.0.0.0/8`) |
| `invalid default_action` | Unknown action | Use `allow` or `deny` |

### Telemetry Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid telemetry endpoint URL` | Malformed URL | Use valid HTTP/HTTPS URL |
| `unknown event type` | Invalid event | See event types list |

---

## Troubleshooting

### Configuration Not Loading

1. **Check file permissions**: Sensor needs read access to config file
2. **Validate YAML syntax**: Use `yq` or online YAML validator
3. **Check file encoding**: Must be UTF-8 without BOM

```bash
# Validate YAML syntax
yq eval '.' /etc/synapse/config.yaml

# Check file permissions
ls -la /etc/synapse/config.yaml
```

### TLS Certificate Issues

1. **Verify certificate chain**: Full chain required in cert file
2. **Check file paths**: Must be absolute paths
3. **Verify permissions**: Sensor user needs read access

```bash
# Verify certificate
openssl x509 -in /etc/certs/server.pem -text -noout

# Verify key matches certificate
openssl x509 -noout -modulus -in /etc/certs/server.pem | openssl md5
openssl rsa -noout -modulus -in /etc/certs/server.key | openssl md5
```

### High Memory Usage

1. **Reduce cache sizes**: Lower `max_cache_entries`, `max_states`, `max_profiles`
2. **Reduce retention**: Lower `retention_hours`, `max_windows`
3. **Enable fast mode**: Set `dlp.fast_mode: true`

### Performance Tuning

1. **Adjust workers**: Match CPU cores or set to 0 for auto-detect
2. **Tune batch sizes**: Balance latency vs throughput
3. **Enable sampling**: Use `sampling_rate` < 1.0 for shadow mirroring
