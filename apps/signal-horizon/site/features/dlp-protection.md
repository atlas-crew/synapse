# Feature: DLP Protection

Synapse sensors include built-in Data Loss Prevention (DLP) that scans HTTP responses for sensitive data before it leaves your network. If a backend application accidentally exposes credit card numbers, API keys, or social security numbers in an API response, DLP catches it and either redacts the data or blocks the response entirely.

## Why DLP at the WAF Layer

Application bugs, misconfigurations, and verbose error messages can leak sensitive information in HTTP responses. Traditional DLP solutions operate at the network perimeter or endpoint level, but Synapse's response-layer DLP catches leaks at the exact point where data leaves your application -- before it reaches the client.

Common scenarios DLP protects against:

- A debug endpoint accidentally left enabled in production returns raw database rows containing customer SSNs.
- An API error response includes the full stack trace with embedded database credentials.
- A logging endpoint echoes back request bodies that contain credit card numbers.
- A misconfigured search API returns fields containing API keys or JWTs.

## Built-in Pattern Types

Synapse ships with detection patterns for the following sensitive data categories:

| Pattern Type | What It Detects |
|-------------|-----------------|
| `credit_card` | Visa, MasterCard, Amex, Discover, and other major card formats |
| `ssn` | US Social Security Numbers (XXX-XX-XXXX and variants) |
| `email` | Email addresses |
| `phone` | Phone numbers in common formats |
| `api_key` | API keys and tokens (common prefix patterns) |
| `password` | Password fields and credential patterns |
| `iban` | International Bank Account Numbers |
| `ip_address` | IPv4 addresses |
| `aws_key` | AWS Access Key IDs and Secret Access Keys |
| `private_key` | PEM-encoded private keys (RSA, EC, etc.) |
| `jwt` | JSON Web Tokens |
| `medical_record` | Medical record numbers and health identifiers |

All patterns are evaluated against HTTP response bodies before the response is forwarded to the client.

## Enabling DLP

DLP is enabled by default in Synapse. The basic configuration in your Synapse YAML config:

```yaml
dlp:
  enabled: true
  max_scan_size: 5242880        # Skip responses larger than 5MB
  max_body_inspection_bytes: 8192  # Inspect first 8KB of response body
  max_matches: 100              # Stop scanning after 100 matches
  scan_text_only: true          # Only scan text-based content types
```

### Key Settings

- **`max_scan_size`**: Responses larger than this (in bytes) are skipped entirely. Prevents performance impact from scanning large file downloads.
- **`max_body_inspection_bytes`**: How many bytes of the response body to inspect. Increase this if your responses are large and may contain sensitive data beyond the first 8KB.
- **`scan_text_only`**: When enabled, only responses with text-based content types (JSON, HTML, XML, plain text) are scanned. Binary content types like images and downloads are skipped.
- **`fast_mode`**: When enabled, skips lower-priority patterns for faster scanning at the cost of reduced coverage.

## Redaction Modes

When DLP detects sensitive data, you control what happens through per-type redaction modes. Configure each pattern type independently:

```yaml
dlp:
  enabled: true
  redaction:
    credit_card: "partial"
    ssn: "full"
    api_key: "full"
    email: "hash"
    jwt: "full"
    aws_key: "full"
    private_key: "full"
  hash_salt: "your-secret-salt-here"
```

### Available Modes

| Mode | Behavior | Example Output |
|------|----------|---------------|
| `full` | Replaces the entire match with `[REDACTED]` | `[REDACTED]` |
| `partial` | Masks most of the value, preserving a few characters for identification | `****-****-****-4242` |
| `hash` | Replaces with a salted hash (requires `hash_salt`) | `[HASH:a1b2c3d4]` |
| `none` | Logs the detection but does not modify the response | Original value unchanged |

### When to Use Each Mode

- **`full`** -- Best for high-sensitivity data like API keys, private keys, and AWS credentials. No part of the value is exposed.
- **`partial`** -- Useful for credit cards and phone numbers where operators need to identify which record was exposed without seeing the full value.
- **`hash`** -- Enables correlation (same value produces same hash) without exposing the data. Useful for incident investigation.
- **`none`** -- Use for monitoring and alerting only. The response passes through unmodified, but detections are logged and reported to Signal Horizon.

## Custom Keywords

In addition to built-in patterns, you can define custom keywords to detect application-specific sensitive data:

```yaml
dlp:
  enabled: true
  custom_keywords:
    - "INTERNAL_SECRET"
    - "X-Internal-Token"
    - "company-confidential"
```

Custom keywords are matched as literal strings in response bodies. You can define up to 1,000 keywords, each up to 1,024 characters long.

## Blocking vs. Redaction

DLP operates in **redaction mode** by default -- it modifies the response to remove or mask sensitive data, then forwards the sanitized response to the client. The original request is not blocked.

If you need to **block** responses containing sensitive data entirely (returning a 403 instead of the redacted response), combine DLP with Synapse's anomaly risk scoring. DLP detections contribute to the entity's risk score, and if the cumulative risk exceeds the WAF threshold, subsequent requests from that client are blocked.

## Monitoring DLP Activity

All DLP detections are reported to Signal Horizon as telemetry events. From the Signal Horizon dashboard you can:

- View DLP detection counts by pattern type and sensor.
- Identify which endpoints are leaking sensitive data most frequently.
- Track redaction activity over time to measure remediation progress.
- Set up alerts for specific pattern types (e.g., alert immediately on any private key detection).

## Performance Considerations

DLP scanning adds minimal latency to response processing:

- Only text-based content types are scanned by default.
- The `max_body_inspection_bytes` setting bounds how much data is inspected per response.
- Responses exceeding `max_scan_size` are passed through without scanning.
- Enable `fast_mode` in high-throughput environments where scanning latency is a concern.
