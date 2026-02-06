# Shadow Mirroring

Shadow mirroring copies suspicious traffic from your Synapse sensors to analysis endpoints without affecting the primary request path. Use it for threat research, machine learning training, compliance auditing, or honeypot analysis.

## What Is Shadow Mirroring?

When shadow mirroring is enabled on a site, the sensor evaluates each request's risk score. Requests that fall within a configurable risk window are copied asynchronously to one or more destination URLs. The original request continues to its upstream unmodified and undelayed.

Key properties:

- **Non-blocking**: Mirroring happens after the response is sent to the client.
- **Risk-scoped**: Only requests within a defined risk range are mirrored. Requests above the range are blocked by the WAF; requests below are clean traffic.
- **Sampled**: A sampling rate controls what percentage of eligible traffic is actually mirrored.
- **Signed**: HMAC signatures prevent spoofed payloads from polluting your analysis pipeline.

## Setting Up Mirror Destinations

Define one or more honeypot or analysis endpoints in the site configuration:

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
        - "https://ml-pipeline.internal/collect"
```

Each URL receives a POST with the mirrored request data. Ensure these endpoints are reachable from the sensor and can handle the expected volume.

## Configuring Risk Thresholds and Sampling

Shadow mirroring operates on a **risk window** defined by minimum and maximum scores:

```yaml
shadow_mirror:
  enabled: true
  min_risk_score: 40.0
  max_risk_score: 70.0
  sampling_rate: 0.25
  per_ip_rate_limit: 5
  timeout_secs: 5
```

| Setting | Description | Default |
|---------|-------------|---------|
| `min_risk_score` | Lowest risk score eligible for mirroring | 0.0 |
| `max_risk_score` | Highest risk score eligible (above this, WAF blocks) | 100.0 |
| `sampling_rate` | Fraction of eligible requests to mirror (0.0 - 1.0) | 1.0 |
| `per_ip_rate_limit` | Max mirrored requests per source IP per minute | 10 |
| `timeout_secs` | HTTP timeout for sending mirrored payloads | 5 |

With the example above, 25% of requests scoring between 40 and 70 are mirrored.

## HMAC Signing

HMAC signatures protect your analysis endpoints from spoofed data. When configured, the sensor signs every mirrored payload with a shared secret. Your receiving endpoint verifies the signature before processing.

Enable HMAC in the configuration:

```yaml
shadow_mirror:
  enabled: true
  hmac_secret: "${SYNAPSE_HMAC_SECRET}"
```

Set the secret as an environment variable on the sensor host:

```bash
export SYNAPSE_HMAC_SECRET="replace-with-secure-random-secret"
```

The sensor includes the signature in the `X-Mirror-Signature` header of each mirrored request. Your endpoint should:

1. Extract the `X-Mirror-Signature` header.
2. Compute the HMAC-SHA256 of the request body using the shared secret.
3. Compare the computed signature with the header value.
4. Reject the request if they do not match.

## Controlling Payload Size

Limit what data is included in mirrored payloads to protect bandwidth and your analysis endpoints:

```yaml
shadow_mirror:
  enabled: true
  include_body: true
  max_body_size: 1048576
  include_headers:
    - "User-Agent"
    - "Referer"
    - "Origin"
    - "Content-Type"
    - "X-Forwarded-For"
```

- `include_body`: Set to `false` to mirror only metadata (headers, URL, method).
- `max_body_size`: Maximum body size in bytes (default: 1 MB). Larger bodies are truncated.
- `include_headers`: Allowlist of headers to include. All other headers are stripped.

## Use Cases

### Threat Research
Mirror suspicious-but-not-blocked traffic to a honeypot that emulates vulnerable responses. Attackers interact with the honeypot while real users are unaffected.

### ML Training
Feed mirrored traffic into a machine learning pipeline to train anomaly detection models on real attack patterns without exposing production systems.

### Compliance Auditing
Capture a sample of flagged traffic for compliance review. Use a low sampling rate (e.g., `0.05`) and store payloads in an immutable audit log.

### Incident Response
During an active investigation, temporarily increase the sampling rate and widen the risk window to capture more context around suspicious activity.

## Applying Changes

Reload the sensor configuration after making changes:

```bash
curl -X POST "http://<sensor-admin>:6191/reload" \
  -H "X-Admin-Key: $SENSOR_ADMIN_KEY"
```

You can also push configuration changes from Signal Horizon via **Fleet > Sensors > [Sensor] > Push Config**.

## Validation Checklist

After enabling shadow mirroring, verify the setup:

1. Send a request with a known low risk score (below `min_risk_score`). It should **not** be mirrored.
2. Send a request within the risk window. It should appear at your honeypot endpoint (subject to sampling).
3. Send a request above `max_risk_score`. It should be **blocked** by the WAF and not mirrored.
4. If HMAC is enabled, verify the signature on a received payload.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| No mirrored traffic arriving | Sampling rate too low or risk window too narrow | Increase `sampling_rate` or widen the risk range |
| Honeypot not receiving data | Endpoint unreachable or DNS failure | Check `honeypot_urls` and network connectivity |
| Invalid HMAC signatures | Secret mismatch between sensor and endpoint | Confirm `SYNAPSE_HMAC_SECRET` matches on both sides |
| High latency on primary requests | Mirror timeout too long | Reduce `timeout_secs`; mirroring is async but the timeout applies to the background send |
| Payload too large | Body exceeding `max_body_size` | Increase the limit or set `include_body: false` |
