# Synapse Sensor Configuration Reference

Complete YAML configuration reference for the Synapse Sensor (synapse-pingora). The sensor loads configuration from a YAML file at startup:

```bash
synapse-pingora --config /etc/synapse/config.yaml
```

Configuration file maximum size is 10 MB. All file paths are validated against path traversal at load time.

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
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `http_addr` | string | `0.0.0.0:80` | HTTP listen address (`host:port`) |
| `https_addr` | string | `0.0.0.0:443` | HTTPS listen address (`host:port`) |
| `workers` | integer | `0` | Worker threads (0 = auto-detect CPU cores, max 1024) |
| `shutdown_timeout_secs` | integer | `30` | Graceful shutdown timeout (1-300 seconds) |
| `waf_threshold` | integer | `70` | Global WAF risk score threshold (1-100) |
| `waf_enabled` | boolean | `true` | Enable WAF protection globally |
| `log_level` | string | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `admin_api_key` | string | auto-generated | Admin API key (min 16 chars if set, or leave empty for auto) |
| `waf_regex_timeout_ms` | integer | `100` | WAF regex timeout for ReDoS protection (1-500 ms) |

### Trap Configuration

Honeypot trap endpoints that detect reconnaissance by triggering on paths legitimate users never access.

```yaml
server:
  trap_config:
    enabled: true
    paths:
      - "/.git/*"
      - "/.env"
      - "/wp-admin/*"
      - "/phpmyadmin/*"
    apply_max_risk: true
    extended_tarpit_ms: 5000
    alert_telemetry: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable trap detection |
| `paths` | string[] | (see example) | Glob patterns for trap paths (max 100) |
| `apply_max_risk` | boolean | `true` | Apply maximum risk score (100) on trap hit |
| `extended_tarpit_ms` | integer | `5000` | Additional tarpit delay for trap hits (0-60000 ms) |
| `alert_telemetry` | boolean | `true` | Send telemetry alerts on trap hits |

---

## Rate Limiting

Global rate limiting. Can be overridden per site.

```yaml
rate_limit:
  rps: 10000
  enabled: true
  burst: 20000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rps` | integer | `10000` | Requests per second limit (1-1000000) |
| `enabled` | boolean | `true` | Enable rate limiting |
| `burst` | integer | 2 x rps | Burst capacity for temporary spikes (must be >= rps) |

---

## Profiler

Endpoint behavior learning for anomaly detection.

```yaml
profiler:
  enabled: true
  max_profiles: 1000
  min_samples_for_validation: 100
  payload_z_threshold: 3.0
  param_z_threshold: 4.0
  redact_pii: true
  freeze_after_samples: 0
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable endpoint profiling |
| `max_profiles` | integer | `1000` | Maximum endpoint profiles to maintain (1-100000) |
| `max_schemas` | integer | `500` | Maximum learned JSON schemas (1-50000) |
| `min_samples_for_validation` | integer | `100` | Samples required before enforcement (10-10000) |
| `payload_z_threshold` | float | `3.0` | Z-score threshold for payload size anomalies (1.0-10.0) |
| `param_z_threshold` | float | `4.0` | Z-score threshold for parameter anomalies (1.0-10.0) |
| `response_z_threshold` | float | `4.0` | Z-score threshold for response size anomalies (1.0-10.0) |
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
  max_concurrent_tarpits: 1000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable tarpitting |
| `base_delay_ms` | integer | `1000` | Base delay in milliseconds (100-60000) |
| `max_delay_ms` | integer | `30000` | Maximum delay in milliseconds |
| `progressive_multiplier` | float | `1.5` | Delay multiplier per level (1.0-5.0) |
| `max_states` | integer | `10000` | Maximum tracked IPs with LRU eviction (100-1000000) |
| `decay_threshold_ms` | integer | `300000` | Decay tarpit level after this idle time |
| `cleanup_threshold_ms` | integer | `1800000` | Remove state after this idle time |
| `max_concurrent_tarpits` | integer | `1000` | Maximum concurrent delays (10-100000) |

Delay formula: `delay = base_delay_ms * progressive_multiplier ^ (level - 1)`, capped at `max_delay_ms`.

---

## DLP (Data Loss Prevention)

Scans response bodies for PII and sensitive data.

```yaml
dlp:
  enabled: true
  max_scan_size: 5242880
  max_matches: 10
  scan_text_only: true
  redaction:
    credit_card: "mask"
    ssn: "hash"
    api_key: "full"
  hash_salt: "your-32-byte-minimum-salt"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable DLP scanning |
| `max_scan_size` | integer | `5242880` | Maximum body size to accept (bytes) |
| `max_matches` | integer | `10` | Stop scanning after N matches |
| `scan_text_only` | boolean | `true` | Only scan `text/*` content types |
| `max_body_inspection_bytes` | integer | `8192` | Truncate scan at this size |
| `fast_mode` | boolean | `false` | Skip low-priority patterns for performance |
| `custom_keywords` | string[] | `[]` | Custom keywords to detect (max 1000) |
| `redaction` | map | `{}` | Per-type redaction mode |
| `hash_salt` | string | (required for hash) | Salt for hash-based redaction (min 32 bytes) |

**Redaction modes:** `mask` (replace with asterisks), `hash` (SHA-256 hash, requires salt), `full` (remove entirely).

**Detected data types:** `credit_card`, `ssn`, `email`, `phone`, `api_key`, `password`, `iban`, `ip_address`, `aws_key`, `private_key`, `jwt`, `medical_record`, `custom`.

---

## Crawler Detection

Bot detection and verification.

```yaml
crawler:
  enabled: true
  verify_legitimate_crawlers: true
  block_bad_bots: true
  dns_cache_ttl_secs: 300
  dns_failure_policy: "apply_risk_penalty"
  dns_failure_risk_penalty: 50
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable crawler detection |
| `verify_legitimate_crawlers` | boolean | `true` | DNS verification for Googlebot, Bingbot, etc. |
| `block_bad_bots` | boolean | `true` | Block known malicious bots |
| `dns_cache_ttl_secs` | integer | `300` | DNS cache TTL (60-86400) |
| `dns_timeout_ms` | integer | `2000` | DNS lookup timeout (100-30000) |
| `max_concurrent_dns_lookups` | integer | `100` | Concurrent DNS limit (1-1000) |
| `dns_failure_policy` | string | `apply_risk_penalty` | Policy on DNS failure: `allow`, `apply_risk_penalty`, `block` |
| `dns_failure_risk_penalty` | integer | `50` | Risk score penalty when DNS fails (0-100) |

---

## Telemetry

Event reporting to Signal Horizon or external collectors.

```yaml
telemetry:
  enabled: true
  endpoint: "https://collector.example.com/api/v1/events"
  batch_size: 100
  flush_interval_secs: 10
  max_retries: 3
  circuit_breaker_threshold: 5
  instance_id: "prod-sensor-01"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable telemetry |
| `endpoint` | string | `http://localhost:3100/telemetry` | Telemetry endpoint URL |
| `api_key` | string | `""` | API key for authentication |
| `batch_size` | integer | `100` | Events per batch (1-10000) |
| `flush_interval_secs` | integer | `10` | Flush interval in seconds (1-300) |
| `max_retries` | integer | `3` | Maximum retry attempts (0-10) |
| `max_buffer_size` | integer | `10000` | Maximum buffered events (100-1000000) |
| `circuit_breaker_threshold` | integer | `5` | Failures before circuit opens (1-100) |
| `circuit_breaker_timeout_secs` | integer | `60` | Circuit breaker reset timeout (10-3600) |
| `instance_id` | string | `""` | Sensor instance identifier (max 64 chars) |
| `dry_run` | boolean | `false` | Skip HTTP sending (for testing) |
| `enabled_events` | string[] | `[]` | Event types to send (empty = all) |

**Event types:** `request_processed`, `waf_block`, `rate_limit_hit`, `config_reload`, `service_health`, `sensor_report`, `campaign_report`.

---

## Horizon (Fleet Intelligence)

WebSocket connection to Signal Horizon Hub for fleet-wide threat sharing.

```yaml
horizon:
  enabled: true
  hub_url: "wss://horizon.example.com/ws"
  api_key: "your-api-key"
  sensor_id: "sensor-uuid"
  sensor_name: "prod-edge-01"
  heartbeat_interval_ms: 30000
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable Horizon integration |
| `hub_url` | string | `""` | WebSocket URL for Hub (required if enabled) |
| `api_key` | string | `""` | API key for authentication (required if enabled) |
| `sensor_id` | string | `""` | Unique sensor ID, UUID format (required if enabled) |
| `sensor_name` | string | `""` | Human-readable sensor name (max 128 chars) |
| `reconnect_delay_ms` | integer | `5000` | Reconnection delay (1000-300000) |
| `max_reconnect_attempts` | integer | `0` | Max reconnections (0 = unlimited) |
| `signal_batch_size` | integer | `100` | Signals per batch (1-10000) |
| `signal_batch_delay_ms` | integer | `1000` | Batch delay (100-60000) |
| `heartbeat_interval_ms` | integer | `30000` | Heartbeat interval (5000-300000) |
| `max_queued_signals` | integer | `1000` | Maximum queued signals when disconnected (100-100000) |
| `blocklist_cache_ttl_secs` | integer | `3600` | Blocklist cache TTL (60-86400) |

---

## Payload Profiling

Bandwidth and payload size anomaly detection.

```yaml
payload:
  enabled: true
  oversize_threshold: 3.0
  bandwidth_spike_threshold: 5.0
  warmup_requests: 100
  exfiltration_ratio_threshold: 100.0
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable payload profiling |
| `window_duration_ms` | integer | `60000` | Window duration (1000-3600000) |
| `max_windows` | integer | `60` | Windows to retain (1-1440) |
| `oversize_threshold` | float | `3.0` | Multiplier of p99 for oversized detection (1.5-100.0) |
| `bandwidth_spike_threshold` | float | `5.0` | Multiplier of average for spike detection (2.0-100.0) |
| `warmup_requests` | integer | `100` | Requests before detection activates (10-10000) |
| `exfiltration_ratio_threshold` | float | `100.0` | Response/request ratio for exfiltration alert (10.0-10000.0) |

---

## Trends

Time-series anomaly detection for authentication and behavioral patterns.

```yaml
trends:
  enabled: true
  bucket_size_ms: 60000
  retention_hours: 24
  anomaly_risk:
    fingerprint_change: 30
    session_sharing: 50
    impossible_travel: 25
    ja4_browser_spoofing: 60
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable trends tracking |
| `bucket_size_ms` | integer | `60000` | Time bucket size (1000-3600000) |
| `retention_hours` | integer | `24` | Data retention (1-168 hours) |
| `max_entities` | integer | `10000` | Maximum tracked entities (100-1000000) |
| `anomaly_risk` | map | (see below) | Risk scores per anomaly type (0-100 each) |

**Anomaly types and defaults:** `fingerprint_change` (30), `session_sharing` (50), `token_reuse` (40), `velocity_spike` (15), `rotation_pattern` (35), `timing_anomaly` (10), `impossible_travel` (25), `ja4_rotation_pattern` (45), `ja4_ip_cluster` (35), `ja4_browser_spoofing` (60), `ja4h_change` (25).

---

## Sites

Virtual host configurations with hostname-based routing.

```yaml
sites:
  - hostname: "api.example.com"
    upstreams:
      - host: "backend.internal"
        port: 8080
        weight: 1
    tls:
      cert_path: "/etc/certs/api.pem"
      key_path: "/etc/certs/api.key"
      min_version: "1.2"
    waf:
      enabled: true
      threshold: 60
    rate_limit:
      rps: 5000
```

### Site Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | yes | Hostname or wildcard pattern |
| `upstreams` | array | yes | Backend servers (at least one) |
| `tls` | object | no | TLS configuration |
| `waf` | object | no | WAF override for this site |
| `rate_limit` | object | no | Rate limit override for this site |
| `access_control` | object | no | IP-based access control |
| `headers` | object | no | Request/response header manipulation |
| `shadow_mirror` | object | no | Traffic mirroring to honeypot |

### Hostname Patterns

- Exact match: `example.com`
- Wildcard subdomain: `*.example.com`
- Catch-all: `_` or `default`
- Max 3 wildcards per pattern, 253 characters per hostname

### Access Control

```yaml
access_control:
  allow:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
  deny:
    - "0.0.0.0/0"
  default_action: "deny"
```

Rules are evaluated in order: first matching `allow` or `deny` wins, then `default_action`.

### WAF Rule Overrides

```yaml
waf:
  enabled: true
  threshold: 60
  rule_overrides:
    "sqli-001": "log"
    "xss-002": "block"
    "scanner-001": "pass"
```

**Rule actions:** `block`, `log`, `pass`.

### Shadow Mirroring

Mirror suspicious traffic to a honeypot for analysis.

```yaml
shadow_mirror:
  enabled: true
  min_risk_score: 40.0
  max_risk_score: 70.0
  honeypot_urls:
    - "http://honeypot:8080/mirror"
  sampling_rate: 1.0
```

---

## Environment Variables

Secrets can be set via environment variables, which take precedence over config file values.

| Config Path | Environment Variable |
|-------------|---------------------|
| `server.admin_api_key` | `SYNAPSE_ADMIN_API_KEY` |
| `telemetry.api_key` | `SYNAPSE_TELEMETRY_API_KEY` |
| `horizon.api_key` | `SYNAPSE_HORIZON_API_KEY` |
| `dlp.hash_salt` | `SYNAPSE_DLP_HASH_SALT` |

---

## Example: Minimal Configuration

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

## Example: Production with Fleet Intelligence

```yaml
server:
  http_addr: "0.0.0.0:80"
  https_addr: "0.0.0.0:443"
  workers: 0
  waf_threshold: 70
  waf_enabled: true
  trap_config:
    enabled: true
    paths: ["/.git/*", "/.env", "/wp-admin/*", "/phpmyadmin/*"]

rate_limit:
  rps: 10000
  burst: 20000

tarpit:
  enabled: true
  base_delay_ms: 1000
  max_delay_ms: 30000

dlp:
  enabled: true
  redaction:
    credit_card: "mask"
    ssn: "hash"
    api_key: "full"

horizon:
  enabled: true
  hub_url: "wss://horizon.example.com/ws"
  sensor_name: "prod-edge-01"
  heartbeat_interval_ms: 30000

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
    rate_limit:
      rps: 5000

  - hostname: "*.example.com"
    upstreams:
      - host: "default-backend.internal"
        port: 8080
```

## Troubleshooting

### Configuration Not Loading

1. Verify YAML syntax: `yq eval '.' /etc/synapse/config.yaml`
2. Check file permissions (sensor needs read access)
3. Ensure UTF-8 encoding without BOM

### High Memory Usage

1. Reduce cache sizes: `max_cache_entries`, `max_states`, `max_profiles`
2. Reduce retention: `retention_hours`, `max_windows`
3. Enable fast mode: `dlp.fast_mode: true`

### Performance Tuning

1. Set `workers: 0` for auto-detection or match to CPU cores
2. Tune batch sizes for latency vs throughput tradeoff
3. Use `sampling_rate < 1.0` for shadow mirroring on high-traffic sites
