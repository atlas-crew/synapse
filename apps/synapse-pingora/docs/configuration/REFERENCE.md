# Synapse-Pingora Configuration Reference

Complete reference for all configuration parameters, types, and default values.

## Configuration formats and precedence

Synapse-Pingora supports two YAML formats:

- **Single-site (legacy):** `config.yaml` or `config.yml`
- **Multi-site (recommended):** `config.sites.yaml` (or `config.yaml` containing a `sites` list)

At startup, Synapse-Pingora loads the single-site config for shared subsystem settings,
then attempts to load multi-site config for vhost routing. If a multi-site file with
`sites` exists, site routing uses that configuration.

## Single-site configuration (legacy `config.yaml`)

### Top-level structure

```yaml
server:
upstreams:
rate_limit:
logging:
detection:
tls:
telemetry:
tarpit:
dlp:
crawler:
horizon:
payload:
trends:
```

### Server settings (`server`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `listen` | string | `"0.0.0.0:6190"` | Proxy listen address |
| `admin_listen` | string | `"0.0.0.0:6191"` | Admin API listen address |
| `workers` | integer | `0` | Worker threads (0 = auto-detect) |
| `admin_api_key` | string | `null` (auto-generated at startup) | Admin API key (X-Admin-Key) |
| `trusted_proxies` | array[string] | `[]` | Trusted proxy CIDR ranges for X-Forwarded-For validation (empty = ignore XFF). In production, set explicit proxy IPs and avoid broad private ranges. |

### Upstreams (`upstreams[]`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | string | `"127.0.0.1"` | Backend host |
| `port` | integer | `8080` | Backend port |

### Rate limiting (`rate_limit`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `rps` | integer | `10000` | Requests per second limit |
| `per_ip_rps` | integer | `100` | Per-IP requests per second limit |
| `enabled` | boolean | `true` | Enable rate limiting |

### Logging (`logging`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `level` | string | `"info"` | Log level: trace, debug, info, warn, error |
| `format` | string | `"text"` | Log format: text, json |
| `access_log` | boolean | `true` | Enable access logs |

### Detection (`detection`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sqli` | boolean | `true` | Enable SQL injection detection |
| `xss` | boolean | `true` | Enable XSS detection |
| `path_traversal` | boolean | `true` | Enable path traversal detection |
| `command_injection` | boolean | `true` | Enable command injection detection |
| `action` | string | `"block"` | Action on detection (block, log, challenge) |
| `block_status` | integer | `403` | HTTP status for blocked requests |
| `rules_path` | string | `"data/rules.json"` | Rules file path |
| `anomaly_blocking` | object | (see below) | Anomaly blocking settings |
| `risk_server_url` | string | `null` | Deprecated (use `telemetry.endpoint`) |

#### Anomaly blocking (`detection.anomaly_blocking`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable anomaly blocking |
| `threshold` | float | `10.0` | Risk threshold for anomaly blocking |

### TLS (`tls`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable TLS |
| `cert_path` | string | `""` | Default cert path (PEM) |
| `key_path` | string | `""` | Default key path (PEM) |
| `per_domain_certs` | array[object] | `[]` | Per-domain certificates |
| `min_version` | string | `"1.2"` | Minimum TLS version (1.2 or 1.3) |

#### Per-domain certificates (`tls.per_domain_certs[]`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domain` | string | (required) | Domain or wildcard (e.g., `*.example.com`) |
| `cert_path` | string | (required) | Certificate path |
| `key_path` | string | (required) | Private key path |

### Telemetry (`telemetry`)

Telemetry durations are serialized as `{ secs: <int>, nanos: <int> }`.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable telemetry |
| `endpoint` | string | `"http://localhost:3100/telemetry"` | Telemetry endpoint |
| `api_key` | string | `null` | API key for telemetry |
| `batch_size` | integer | `100` | Events per batch |
| `flush_interval` | duration | `10s` | Flush interval |
| `max_retries` | integer | `3` | Retry attempts |
| `initial_backoff` | duration | `100ms` | Initial backoff |
| `max_backoff` | duration | `30s` | Max backoff |
| `max_buffer_size` | integer | `10000` | Max buffered events |
| `circuit_breaker_threshold` | integer | `5` | Failures before opening circuit |
| `circuit_breaker_timeout` | duration | `60s` | Circuit breaker reset timeout |
| `enabled_events` | array[string] | `[]` (all events) | Event allowlist |
| `instance_id` | string | `null` | Optional instance identifier |
| `dry_run` | boolean | `false` | Skip HTTP sends (testing) |

**`enabled_events` values:** `request_processed`, `waf_block`, `rate_limit_hit`, `config_reload`,
`service_health`, `sensor_report`, `campaign_report`, `auth_coverage`, `log_entry`

### Tarpit (`tarpit`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `base_delay_ms` | integer | `1000` | Base tarpit delay (ms) |
| `max_delay_ms` | integer | `30000` | Max tarpit delay (ms) |
| `progressive_multiplier` | float | `1.5` | Delay multiplier per level |
| `enabled` | boolean | `true` | Enable tarpit |
| `max_states` | integer | `10000` | Max tracked IP states |
| `decay_threshold_ms` | integer | `300000` | Idle time before decay (ms) |
| `cleanup_threshold_ms` | integer | `1800000` | Idle time before cleanup (ms) |
| `max_concurrent_tarpits` | integer | `1000` | Max concurrent tarpits |

### DLP (`dlp`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable DLP scanning |
| `max_scan_size` | integer | `5242880` | Reject scans larger than this (bytes) |
| `max_matches` | integer | `100` | Stop after this many matches |
| `scan_text_only` | boolean | `true` | Scan only text-based content types |
| `max_body_inspection_bytes` | integer | `8192` | Max bytes to inspect (bytes) |
| `fast_mode` | boolean | `false` | Skip low-priority patterns |
| `custom_keywords` | array[string] | `null` | Custom keywords to detect |
| `redaction` | map[string,string] | `{}` | Per-type redaction mode |
| `hash_salt` | string | `null` | Required if any redaction mode is `hash` |

**`redaction` keys:** `credit_card`, `ssn`, `email`, `phone`, `api_key`, `password`, `iban`,
`ip_address`, `aws_key`, `private_key`, `jwt`, `medical_record`, `custom`

**Redaction modes:** `full`, `partial`, `hash`, `none`

### Crawler detection (`crawler`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable crawler detection |
| `dns_cache_ttl_secs` | integer | `300` | DNS cache TTL (s) |
| `verification_cache_ttl_secs` | integer | `3600` | Verification cache TTL (s) |
| `max_cache_entries` | integer | `50000` | Max DNS cache entries |
| `dns_timeout_ms` | integer | `2000` | DNS lookup timeout (ms) |
| `max_concurrent_dns_lookups` | integer | `100` | Max concurrent DNS lookups |
| `verify_legitimate_crawlers` | boolean | `true` | Verify known crawlers via DNS |
| `block_bad_bots` | boolean | `true` | Block detected bad bots |
| `dns_failure_policy` | string | `apply_risk_penalty` | DNS failure policy |
| `dns_failure_risk_penalty` | integer | `50` | Risk penalty on DNS failure |
| `max_stats_entries` | integer | `1000` | Max entries in stats maps |

**`dns_failure_policy` values:** `allow`, `apply_risk_penalty`, `block`

### Signal Horizon (`horizon`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable Horizon integration |
| `hub_url` | string | `""` | WebSocket URL for the hub |
| `api_key` | string | `""` | API key for authentication |
| `sensor_id` | string | `""` | Unique sensor identifier |
| `sensor_name` | string | `null` | Human-readable name |
| `version` | string | (package version) | Sensor version string |
| `reconnect_delay_ms` | integer | `5000` | Reconnect delay (ms) |
| `max_reconnect_attempts` | integer | `0` | Max reconnect attempts (0 = unlimited) |
| `circuit_breaker_threshold` | integer | `5` | Failures before circuit break |
| `circuit_breaker_cooldown_ms` | integer | `300000` | Circuit breaker cooldown (ms) |
| `signal_batch_size` | integer | `100` | Signals per batch |
| `signal_batch_delay_ms` | integer | `1000` | Batch delay (ms) |
| `heartbeat_interval_ms` | integer | `30000` | Heartbeat interval (ms) |
| `max_queued_signals` | integer | `1000` | Max queued signals |
| `blocklist_cache_ttl_secs` | integer | `3600` | Blocklist cache TTL (s) |

### Payload profiling (`payload`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable payload profiling |
| `window_duration_ms` | integer | `60000` | Window duration (ms) |
| `max_windows` | integer | `60` | Max windows to keep |
| `max_endpoints` | integer | `5000` | Max endpoints tracked |
| `max_entities` | integer | `10000` | Max entities tracked |
| `oversize_threshold` | float | `3.0` | Oversize multiplier (p99) |
| `bandwidth_spike_threshold` | float | `5.0` | Spike multiplier (avg) |
| `warmup_requests` | integer | `100` | Requests before detection |
| `exfiltration_ratio_threshold` | float | `100.0` | Response/request ratio threshold |
| `upload_ratio_threshold` | float | `100.0` | Request/response ratio threshold |
| `min_large_payload_bytes` | integer | `100000` | Minimum large payload (bytes) |
| `timeline_max_buckets` | integer | `1440` | Max timeline buckets |
| `anomaly_risk` | map[string,float] | (see below) | Risk score per anomaly type |

**Default `payload.anomaly_risk`:**

| Anomaly type | Default risk |
|-------------|--------------|
| `oversized_request` | `20.0` |
| `oversized_response` | `15.0` |
| `bandwidth_spike` | `25.0` |
| `exfiltration_pattern` | `40.0` |
| `upload_pattern` | `35.0` |

### Trends (`trends`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable trends tracking |
| `bucket_size_ms` | integer | `60000` | Bucket size (ms) |
| `retention_hours` | integer | `24` | Retention in hours |
| `max_signals_per_bucket` | integer | `10000` | Max signals per bucket |
| `anomaly_check_interval_ms` | integer | `60000` | Anomaly check interval (ms) |
| `anomaly_risk` | map[string,int] | (see below) | Risk score per anomaly type |
| `max_entities` | integer | `10000` | Max entities tracked |
| `max_recent_signals` | integer | `100` | Max recent signals per entity |
| `max_anomalies` | integer | `1000` | Max anomalies retained |

**Default `trends.anomaly_risk`:**

| Anomaly type | Default risk |
|-------------|--------------|
| `fingerprint_change` | `30` |
| `session_sharing` | `50` |
| `token_reuse` | `40` |
| `velocity_spike` | `15` |
| `rotation_pattern` | `35` |
| `timing_anomaly` | `10` |
| `impossible_travel` | `25` |
| `ja4_rotation_pattern` | `45` |
| `ja4_ip_cluster` | `35` |
| `ja4_browser_spoofing` | `60` |
| `ja4h_change` | `25` |
| `oversized_request` | `20` |
| `oversized_response` | `15` |
| `bandwidth_spike` | `25` |
| `exfiltration_pattern` | `40` |
| `upload_pattern` | `35` |

## Multi-site configuration (`config.sites.yaml`)

### Top-level structure

```yaml
server:
sites:
rate_limit:
profiler:
```

### Global server settings (`server`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `http_addr` | string | `"0.0.0.0:80"` | HTTP listen address |
| `https_addr` | string | `"0.0.0.0:443"` | HTTPS listen address |
| `workers` | integer | `0` | Number of worker threads (0 = auto-detect) |
| `shutdown_timeout_secs` | integer | `30` | Graceful shutdown timeout (s) |
| `waf_threshold` | integer | `70` | Global WAF risk threshold (1-100) |
| `waf_enabled` | boolean | `true` | Global WAF enable/disable |
| `log_level` | string | `"info"` | Log level: trace, debug, info, warn, error |
| `admin_api_key` | string | `null` (auto-generated at startup) | Admin API key (X-Admin-Key) |
| `trap_config` | object | `null` | Honeypot trap configuration |

### Trap configuration (`server.trap_config`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable trap endpoint detection |
| `paths` | array[string] | (see below) | Trap path globs |
| `apply_max_risk` | boolean | `true` | Apply max risk score on trap hit |
| `extended_tarpit_ms` | integer | `5000` | Optional extended tarpit delay (ms) |
| `alert_telemetry` | boolean | `true` | Send telemetry alerts on trap hits |

**Default trap paths:**
- `/.git/*`, `/.env`, `/.env.*`
- `/admin/backup*`, `/wp-admin/*`, `/phpmyadmin/*`
- `/.svn/*`, `/.htaccess`, `/web.config`, `/config.php`

### Rate limiting (`rate_limit`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `rps` | integer | `10000` | Requests per second limit |
| `enabled` | boolean | `true` | Enable rate limiting |
| `burst` | integer | `rps * 2` | Burst capacity (2x RPS when unset) |

### Profiler configuration (`profiler`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable behavior profiling |
| `max_profiles` | integer | `1000` | Maximum endpoint profiles |
| `max_schemas` | integer | `500` | Maximum learned schemas |
| `min_samples_for_validation` | integer | `100` | Samples required before validation |
| `payload_z_threshold` | float | `3.0` | Z-score threshold for payload size |
| `param_z_threshold` | float | `4.0` | Z-score threshold for parameter values |
| `response_z_threshold` | float | `4.0` | Z-score threshold for response size |
| `min_stddev` | float | `0.01` | Minimum stddev for z-score |
| `type_ratio_threshold` | float | `0.9` | Type-based anomaly threshold |
| `max_type_counts` | integer | `10` | Max type categories per parameter |
| `redact_pii` | boolean | `true` | Redact PII in anomalies |
| `freeze_after_samples` | integer | `0` | Freeze baseline after N samples (0 = disabled) |

### Site configuration (`sites[]`)

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `hostname` | string | Yes | Hostname or wildcard (e.g., `*.example.com`) |
| `upstreams` | array[object] | Yes | Backend servers |
| `tls` | object | No | TLS configuration |
| `waf` | object | No | Site-specific WAF settings |
| `rate_limit` | object | No | Site-specific rate limiting |
| `access_control` | object | No | IP-based access control |
| `headers` | object | No | Header manipulation rules |
| `shadow_mirror` | object | No | Shadow mirroring to honeypots |

#### Upstream configuration (`sites[].upstreams[]`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | string | (required) | Backend host |
| `port` | integer | (required) | Backend port |
| `weight` | integer | `1` | Load balancing weight |

#### TLS configuration (`sites[].tls`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cert_path` | string | (required) | Certificate path (PEM) |
| `key_path` | string | (required) | Private key path (PEM) |
| `min_version` | string | `"1.2"` | Minimum TLS version (1.2 or 1.3) |

#### Site WAF configuration (`sites[].waf`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable WAF for this site |
| `threshold` | integer | (global) | Site-specific threshold override |
| `rule_overrides` | map[string,string] | `{}` | Rule ID to action overrides |

#### Access control (`sites[].access_control`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `allow` | array[string] | `[]` | CIDR ranges to allow |
| `deny` | array[string] | `[]` | CIDR ranges to deny |
| `default_action` | string | `""` | Default action if no rule matches |

#### Header configuration (`sites[].headers`)

```yaml
headers:
  request:
    add: { "X-Custom": "value" }
    set: { "X-Override": "value" }
    remove: ["X-Internal"]
  response:
    add: { "X-Frame-Options": "DENY" }
    set: {}
    remove: []
```

#### Shadow mirroring (`sites[].shadow_mirror`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable shadow mirroring |
| `min_risk_score` | float | `40.0` | Minimum risk to trigger mirroring |
| `max_risk_score` | float | `70.0` | Maximum risk (above this, block) |
| `honeypot_urls` | array[string] | `[]` | Honeypot endpoint URLs |
| `sampling_rate` | float | `1.0` | Sampling rate 0.0-1.0 |
| `per_ip_rate_limit` | integer | `10` | Per-IP requests per minute |
| `timeout_secs` | integer | `5` | Honeypot delivery timeout (s) |
| `hmac_secret` | string | `null` | HMAC secret for payload signing |
| `include_body` | boolean | `true` | Include request body |
| `max_body_size` | integer | `1048576` | Max body size to mirror (bytes) |
| `include_headers` | array[string] | (see below) | Headers to include |

**Default included headers:** User-Agent, Referer, Origin, Accept, Accept-Language, Accept-Encoding

## Environment variable overrides

| Environment Variable | Configuration Path | Description |
|---------------------|-------------------|-------------|
| `SYNAPSE_ADMIN_API_KEY` | `server.admin_api_key` | Admin API authentication key |
| `SYNAPSE_HORIZON_API_KEY` | `horizon.api_key` | Signal Horizon API key |
| `SYNAPSE_HMAC_SECRET` | `sites[].shadow_mirror.hmac_secret` | Honeypot payload signing |

## Validation rules (selected)

- **Config size:** max 10MB.
- **TLS:** certificate/key paths must exist and min_version is 1.2 or 1.3.
- **Hostnames:** no duplicate hostnames in multi-site config.
- **Path traversal:** TLS paths must not contain path traversal sequences.
- **Shadow mirror:** `min_risk_score` < `max_risk_score`; sampling rate 0.0-1.0; URLs must start with http:// or https://.
- **DLP:** `hash_salt` required if any redaction mode is `hash`; custom keywords <= 1000 and each <= 1024 chars.
- **Crawler:** `dns_timeout_ms` > 0 and <= 30000; `max_concurrent_dns_lookups` > 0; `dns_failure_risk_penalty` <= 100.

## Security considerations

- Store API keys and secrets in environment variables, not config files.
- Keep `redact_pii: true` in profiler to avoid sensitive data in logs.
- Leave `waf_enabled: true` unless you intentionally bypass protection.
- Review trap paths to match your application attack surface.
- Use HMAC signing for shadow mirroring to prevent honeypot spoofing.
