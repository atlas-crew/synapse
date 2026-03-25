# Feature: SOC Analyst Tooling

Signal Horizon provides purpose-built tools for SOC analysts to investigate, hunt, and respond to threats across the fleet.

## Live Threat Map

Real-time global visualization of attack traffic.

- **Geo-IP visualization** of attack origins plotted on a world map
- **Attack type breakdown** by region (SQLi, XSS, bot traffic, etc.)
- **Live counters** and rate indicators showing fleet-wide attack velocity
- **Sensor health overlay** showing sensor status by location
- **Drill-down** to individual attacks from any region marker

## Campaign Map

Interactive graph visualization of attack infrastructure relationships.

- **Node types**: IPs, JA4 fingerprints, session tokens, ASNs
- **Edge relationships** showing connections between nodes with confidence scores
- **2nd-degree attacker discovery** — follow relationships to find related infrastructure
- **Interactive expand/collapse** — start from a single IP and expand the graph
- **One-click campaign blocking** — block all IPs in a cluster directly from the map

## Sigma Rules

Industry-standard detection rule format for proactive threat hunting.

- **Native Sigma rule parsing** — write rules in the standard Sigma YAML format
- **Import from SigmaHQ** — pull rules from the community repository
- **Custom rule editor** with syntax highlighting and validation
- **Hunt workflows** — execute Sigma rules against historical signal data
- **Scheduled detection jobs** — run rules on a recurring schedule for continuous monitoring

### Example Sigma Rule

```yaml
title: Multiple Failed Logins from Same IP
status: experimental
logsource:
  category: authentication
detection:
  selection:
    signal_type: CREDENTIAL_STUFFING
  condition: selection | count(source_ip) > 10
  timeframe: 5m
level: high
```

## CyberChef Integration

Data transformation and analysis toolkit for investigating payloads and indicators.

| Operation | Description |
|-----------|-------------|
| **Base64/URL/HTML decode** | Decode obfuscated payloads |
| **Hex and binary conversion** | Analyze raw data |
| **Hash computation** | MD5, SHA-1, SHA-256 for IOC matching |
| **Regex extraction** | Extract patterns from payloads |
| **Recipe chaining** | Combine multiple operations for complex transforms |

Access CyberChef from the SOC Toolkit section in the Synapse navigation module. Paste any payload, URL, or encoded string and apply transformations to reveal the underlying content.

## Remote Sensor Access

SOC analysts can interact with individual sensors remotely through Signal Horizon.

| Capability | Description |
|-----------|-------------|
| **Live Traffic View** | Stream real-time requests from any sensor with filtering |
| **Config Inspection** | View active configuration and rule sets on a sensor |
| **Debug Mode** | Enable verbose logging for specific IPs or paths |
| **Profile Export** | Export learned API profiles and schemas from a sensor |
| **Emergency Block** | Push immediate block rules to one or more sensors |

## Getting Started

1. Navigate to the **Synapse** module in the sidebar
2. SOC tools are available under the **Global Intel** and **Threat Hunting** sections
3. The Campaign Map is accessible from any active campaign's detail page
4. CyberChef is in the **SOC Toolkit** section
