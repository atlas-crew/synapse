# Tuning WAF Rules and Thresholds (Synapse-Pingora)

This tutorial shows how to tune WAF behavior using configuration thresholds and
rule overrides. You will adjust global and per-site thresholds, override rule
actions, and safely reload configuration.

## Objectives

- Adjust the global WAF threshold for the sensor.
- Apply per-site WAF thresholds.
- Override specific rules to allow, log, challenge, or block.
- Reload configuration without restarting the proxy.

## Prerequisites

- Access to the sensor configuration file (typically `config.sites.yaml`).
- Admin API key (for `POST /reload`).
- A test endpoint or staging environment to validate changes.

## Step 1: Review Current WAF Settings

Open your configuration and locate the global settings:

```yaml
server:
  waf_enabled: true
  waf_threshold: 70
```

Notes:
- `waf_threshold` is a 1-100 risk score threshold.
- Lower values increase sensitivity (more blocks).
- Higher values reduce sensitivity (fewer blocks).

## Step 2: Set a Per-Site Threshold

Override thresholds for a specific hostname:

```yaml
sites:
  - hostname: "api.example.com"
    upstreams:
      - host: "10.0.0.10"
        port: 8080
    waf:
      enabled: true
      threshold: 85
```

Checkpoint:
- This site now requires higher risk scores before blocking.

## Step 3: Override Individual Rules

Rule overrides map a `rule_id` to an action. Common actions:

- `block`
- `allow`
- `log`
- `challenge`

Example:

```yaml
sites:
  - hostname: "api.example.com"
    upstreams:
      - host: "10.0.0.10"
        port: 8080
    waf:
      enabled: true
      threshold: 75
      rule_overrides:
        sql-injection-001: "block"
        noisy-header-019: "log"
        legacy-partner-003: "allow"
```

Tip:
- Use rule IDs from WAF telemetry, dashboards, or rule catalogs.

## Step 4: Validate Changes

Before applying changes in production:

1. Apply the config in a staging environment.
2. Send a known test request (e.g., a benign SQLi pattern).
3. Confirm the decision outcome matches your override.

## Step 5: Reload Configuration

Trigger a hot reload via the Admin API:

```bash
curl -X POST "http://<sensor-admin-host>:<port>/reload" \
  -H "X-Admin-Key: $SENSOR_ADMIN_KEY"
```

Checkpoint:
- Response indicates reload success and updated site count.

## Troubleshooting

- **Unexpected blocks**: Lower the per-site threshold or override a noisy rule to `log`.
- **No blocks at all**: Ensure `waf_enabled` is `true` and threshold is not too high.
- **Reload fails**: Check the configuration file for YAML errors and verify `X-Admin-Key`.

## Next Steps

- Review full configuration reference in `docs/reference/configuration.md`.
- Pair WAF tuning with rate limits and access controls for layered protection.
