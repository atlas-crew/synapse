# Feature: Advanced Threat Detection

Synapse sensors go beyond traditional signature-based WAF rules with a layered threat detection system that identifies attackers through behavioral analysis, session tracking, and TLS fingerprinting. These features work together to catch sophisticated adversaries that evade conventional defenses.

## Trap Endpoints (Honeypot URLs)

Trap endpoints are decoy paths that legitimate users would never access. When an attacker or automated scanner hits one of these paths, Synapse immediately flags the entire session as malicious.

### Why This Matters

Attackers and scanners routinely probe for sensitive files like `/.git/config`, `/.env`, or `/wp-admin/` before launching targeted attacks. By monitoring these paths, Synapse catches reconnaissance activity before any real damage occurs -- with virtually zero false positives.

### Default Trap Paths

Synapse monitors the following paths out of the box:

| Pattern | What It Catches |
|---------|-----------------|
| `/.git/*` | Source code theft attempts |
| `/.env`, `/.env.*` | Credential harvesting |
| `/admin/backup*` | Data exfiltration probes |
| `/wp-admin/*` | CMS exploitation scanners |
| `/phpmyadmin/*` | Database access attempts |
| `/.svn/*` | Version control exposure |
| `/.htaccess`, `/web.config` | Configuration leaks |
| `/config.php` | PHP credential theft |

### Adding Custom Traps

You can add application-specific trap paths in your Synapse configuration:

```yaml
server:
  trap_config:
    enabled: true
    paths:
      - "/api/internal/**"
      - "/debug/*"
      - "/.aws/credentials"
      - "/id_rsa*"
    apply_max_risk: true
    extended_tarpit_ms: 5000
    alert_telemetry: true
```

Glob patterns are supported: `*` matches within a path segment, `**` matches recursively, and `?` matches a single character.

### What Happens on a Trap Hit

1. The client receives an immediate maximum risk score (100.0).
2. The request is blocked with a 403 response.
3. An optional tarpit delay (default 5 seconds) slows the scanner down.
4. A telemetry alert is sent to Signal Horizon for fleet-wide visibility.

## Session-Based Threat Scoring

Synapse tracks every client as an "entity" using IP address, cookies, and fingerprints. Rather than evaluating each request in isolation, the sensor builds a cumulative risk profile across the entire session.

### How Risk Accumulates

Each suspicious behavior adds to the client's risk score. When the total crosses a configurable threshold (default: 70.0), all subsequent requests from that client are blocked.

| Behavior | Risk Added |
|----------|------------|
| Trap endpoint hit | 100.0 (instant block) |
| Rapid TLS fingerprint changes | 40.0 |
| TLS fingerprint changed | 30.0 |
| Multiple IPs for same session | 20.0 |
| User-Agent changed mid-session | 15.0 |
| WAF rule match | Varies by rule severity |

### Repeat Offender Escalation

Clients that repeatedly trigger the same WAF rule receive progressively higher risk scores:

| Triggers | Multiplier |
|----------|------------|
| 1 | 1.0x (base) |
| 2-5 | 1.25x |
| 6-10 | 1.5x |
| 11+ | 2.0x |

### Risk Decay

Risk scores decay over time (default: 10 points per minute), so legitimate users who trigger a single false positive will recover automatically. If risk drops below the block threshold, the client is unblocked without operator intervention.

### Configuration

```yaml
entity:
  enabled: true
  max_entities: 100000
  risk_decay_per_minute: 10.0
  block_threshold: 70.0
```

## JA4 TLS Fingerprinting

JA4+ fingerprints identify clients by analyzing their TLS handshake and HTTP header patterns. Unlike IP addresses, these fingerprints remain stable even when attackers rotate IPs or use proxy chains.

### What Gets Fingerprinted

- **JA4 (TLS)**: Built from the TLS ClientHello -- cipher suites, extensions, ALPN protocol, and TLS version.
- **JA4H (HTTP)**: Built from HTTP request headers -- method, version, cookie presence, header ordering.

### Why Fingerprints Matter for Security

- **Bot detection**: Automated tools have distinctive TLS signatures that differ from real browsers.
- **Persistence**: Fingerprints survive IP rotation, VPN switching, and proxy chains.
- **Evasion detection**: Rapidly changing fingerprints indicate tooling or attack frameworks.
- **Correlation**: Links requests from the same client across different sessions and IPs.

### Rapid Change Detection

If a client's TLS fingerprint changes 3 or more times within 60 seconds, Synapse applies a 40.0 risk score. This catches automated tools that cycle through TLS configurations to evade detection.

### Suspicious Fingerprint Indicators

Synapse also flags fingerprints with characteristics uncommon in legitimate browsers:

| Indicator | Why It Is Suspicious |
|-----------|---------------------|
| TLS version below 1.2 | Deprecated, rarely used by modern browsers |
| Very few cipher suites (< 5) | Likely a script or bot |
| Very few extensions (< 5) | Likely a script or bot |
| No Accept-Language header | Bots and raw HTTP clients |
| HTTP/1.0 | Extremely rare in browser traffic |
| TLS 1.3 with HTTP/1.0 | Protocol mismatch indicating a tool |

## Credential Stuffing Detection

The session tracking system detects credential stuffing by correlating multiple signals: IPs sharing a session token (botnet replay), fingerprint changes on a single session (cookie hijacking), and high request rates to authentication endpoints (brute force). These signals feed into the cumulative risk score, meaning a credential stuffing campaign quickly exceeds the block threshold even if individual requests look benign.

## Campaign Correlation

When signals from multiple sensors are reported to Signal Horizon, the hub's Correlator detects coordinated attacks using eight detection methods:

| Detector | What It Finds |
|----------|---------------|
| **Payload Clustering** | Similar attack signatures appearing across sensors |
| **Temporal Clustering** | Coordinated attacks within the same time window |
| **Actor Correlation** | Same actor (fingerprint/session) appearing across sensors |
| **Fingerprint Matching** | JA4/JA4H fingerprint correlation across the fleet |
| **Geo Clustering** | Attacks originating from the same geographic region |
| **Graph Correlation** | Multi-hop relationships between IPs, fingerprints, and tokens |
| **ASN Correlation** | Attack traffic concentrated in a single autonomous system |
| **Behavioral Clustering** | Similar request patterns (paths, methods, timing) across actors |

When a campaign is detected, Signal Horizon creates a Campaign object that groups all related signals. Analysts can investigate campaigns in the [Campaign Map](soc-tooling.md#campaign-map) or escalate to a [War Room](warroom.md).

## Behavioral Analysis

All detection features feed into a unified behavioral model. Rather than relying on any single indicator, Synapse correlates path access patterns, session continuity, request velocity, WAF rule history, and TLS fingerprint characteristics. Sophisticated attackers who evade one detection method are still caught by the combination of others.

The request processing pipeline evaluates these layers in sequence: trap detection, session tracking, JA4 reputation, WAF rules, and finally the risk decision. Each layer contributes independently to the cumulative score, and the final decision reflects the full picture of client behavior across the session.
