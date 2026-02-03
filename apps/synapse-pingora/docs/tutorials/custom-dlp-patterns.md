# Implementing Custom DLP Patterns (Synapse-Pingora)

This tutorial shows how to define custom Data Loss Prevention (DLP) patterns,
apply redaction, and validate detections safely.

## Objectives

- Enable DLP scanning with safe defaults.
- Add custom keywords for organization-specific data.
- Configure redaction modes for sensitive types.
- Validate DLP matches without disrupting traffic.

## Prerequisites

- Access to `config.sites.yaml` (or your active sensor config).
- Admin API key to reload configuration.
- A staging endpoint to send test payloads.

## Step 1: Enable DLP and Set Safe Limits

Start with conservative limits to avoid large payload scans:

```yaml
dlp:
  enabled: true
  max_body_inspection_bytes: 8192
  max_scan_size: 5242880
  max_matches: 100
  scan_text_only: true
```

Checkpoint:
- DLP is enabled and only inspects the first 8KB of text payloads.

## Step 2: Add Custom Keywords

Use `custom_keywords` for organization-specific identifiers:

```yaml
dlp:
  enabled: true
  custom_keywords:
    - "acct_id="
    - "employee_ssn"
    - "customer_internal_token"
```

Guidance:
- Keep keyword lists under 1000 items.
- Keep each keyword under 1024 characters.

## Step 3: Configure Redaction

Redaction controls how sensitive data is masked in logs and signals:

```yaml
dlp:
  enabled: true
  redaction:
    credit_card: "partial"
    ssn: "hash"
    api_key: "full"
    custom: "partial"
  hash_salt: "replace-with-secure-random-salt"
```

Notes:
- `hash_salt` is required when any redaction mode is `hash`.
- Redaction modes: `full`, `partial`, `hash`, `none`.

## Step 4: Validate with Test Payloads

Send a test request in staging:

```bash
curl -X POST "https://api.example.com/checkout" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","acct_id=12345","card":"4111 1111 1111 1111"}'
```

Checkpoint:
- DLP matches should appear in logs or Signal Horizon telemetry,
  with redaction applied according to your configuration.

## Step 5: Tune Performance vs Coverage

For large uploads, consider enabling `fast_mode`:

```yaml
dlp:
  enabled: true
  fast_mode: true
```

Tips:
- Increase `max_body_inspection_bytes` only after load testing.
- Keep `scan_text_only: true` unless you specifically need binary scanning.

## Reload Configuration

Apply changes without restarting the proxy:

```bash
curl -X POST "http://<sensor-admin-host>:<port>/reload" \
  -H "X-Admin-Key: $SENSOR_ADMIN_KEY"
```

## Troubleshooting

- **No matches**: Confirm payload is within `max_body_inspection_bytes`.
- **Too many matches**: Lower `max_matches` or refine keywords.
- **Reload fails**: Validate YAML syntax and confirm `X-Admin-Key`.

## Next Steps

- Review `docs/configuration/REFERENCE.md` for all DLP settings.
- Pair DLP with WAF rule overrides for layered enforcement.
