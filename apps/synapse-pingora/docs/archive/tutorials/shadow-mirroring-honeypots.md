# Shadow Mirroring for Honeypot Analysis (Synapse-Pingora)

Shadow mirroring lets you copy suspicious traffic to one or more honeypot
targets without impacting the primary request path. This tutorial covers setup,
safe defaults, and validation steps.

## Objectives

- Configure shadow mirroring on a site.
- Route suspicious traffic to honeypot URLs safely.
- Use HMAC signing to prevent spoofed mirror payloads.
- Validate mirrored traffic without affecting production.

## Prerequisites

- Honeypot endpoint(s) reachable from the sensor.
- Access to `config.sites.yaml`.
- Admin API key to reload configuration.

## Step 1: Define Honeypot Targets

Pick one or more destinations. Example:

```yaml
sites:
  - hostname: "api.example.com"
    upstreams:
      - host: "10.0.0.10"
        port: 8080
    shadow_mirror:
      enabled: true
      honeypot_urls:
        - "https://honeypot.example.net/ingest"
```

## Step 2: Set Risk Thresholds and Sampling

Shadow mirroring operates on a risk window:

- `min_risk_score`: lowest score to mirror
- `max_risk_score`: above this, the WAF blocks instead of mirroring

```yaml
shadow_mirror:
  enabled: true
  min_risk_score: 40.0
  max_risk_score: 70.0
  sampling_rate: 0.25
  per_ip_rate_limit: 5
  timeout_secs: 5
```

Checkpoint:
- Only 25% of traffic in the risk window is mirrored.

## Step 3: Enable HMAC Signing

HMAC signatures prevent attackers from spoofing mirrored payloads:

```yaml
shadow_mirror:
  enabled: true
  hmac_secret: "${SYNAPSE_HMAC_SECRET}"
```

Export the secret at runtime:

```bash
export SYNAPSE_HMAC_SECRET="replace-with-secure-random-secret"
```

## Step 4: Control Payload Size

Limit what gets mirrored to protect the honeypot:

```yaml
shadow_mirror:
  enabled: true
  include_body: true
  max_body_size: 1048576
  include_headers:
    - "User-Agent"
    - "Referer"
    - "Origin"
```

## Step 5: Reload Configuration

Apply changes without restarting the proxy:

```bash
curl -X POST "http://<sensor-admin-host>:<port>/reload" \
  -H "X-Admin-Key: $SENSOR_ADMIN_KEY"
```

## Validation Checklist

- Send a known low-risk request: it should not mirror.
- Send a mid-risk request (within thresholds): it should mirror.
- Send a high-risk request (above max): it should block and not mirror.

## Troubleshooting

- **No mirrored traffic**: check `sampling_rate` and risk thresholds.
- **Honeypot not receiving**: verify `honeypot_urls` and `timeout_secs`.
- **Invalid signature**: confirm `SYNAPSE_HMAC_SECRET` matches the honeypot verifier.

## Next Steps

- Review `docs/reference/configuration.md` for all shadow mirror settings.
- Pair shadow mirroring with DLP and WAF tuning for layered analysis.
