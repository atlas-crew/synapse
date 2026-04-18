---
title: Synapse Fleet Feature Reference
---

# Synapse Fleet Feature Reference

Complete feature inventory for the Synapse Fleet intelligence hub (formerly Signal Horizon).

## Feature Matrix

| Feature | Status | Category |
| --- | --- | --- |
| Fleet Management | Production | Core |
| Advanced Threat Detection | Production | Intelligence |
| DLP Protection | Production | Security |
| Impossible Travel | Production | Intelligence |
| Signal Array | Production | Intelligence |
| TestBed | Production | Operations |
| War Room | Production | Collaboration |
| API Intelligence | Production | Operations |
| Blue-Green Deployments | Production | Operations |
| Shadow Mirroring | Production | Operations |
| Capacity Planning | Production | Operations |
| Drift Management | Production | Operations |
| Firmware Updates | Production | Operations |
| Remote Shell | Production | Operations |
| Rule Authoring | Production | Core |
| Tunnel Monitoring | Production | Monitoring |

## Core Features

### Fleet Management

Manage the lifecycle of Synapse sensors across the fleet.

- **Sensor registration** — register new sensors via REST API, issue authentication tokens
- **Health monitoring** — heartbeat tracking with configurable stale thresholds (`WS_HEARTBEAT_INTERVAL_MS`)
- **Grouping** — organize sensors by region, tenant, or custom labels
- **Metrics** — per-sensor traffic volume, detection rates, latency
- **Config templates** — create reusable configuration bundles and push to sensor groups
- **Command queue** — send commands to sensors with delivery tracking and acknowledgment

### Rule Authoring

Create, test, and distribute WAF rules.

- **Rule creation** — author rules via REST API with regex patterns and risk scores
- **Rule strategies** — deploy rules with `immediate`, `canary`, or `scheduled` strategies
- **Sync tracking** — per-sensor sync state in `rule_sync_state` table
- **Rollback** — remove or deactivate rules across the fleet

## Intelligence Features

### Advanced Threat Detection

ML-driven threat scoring and multi-signal correlation.

- **Signal scoring** — combine multiple signal types into composite threat scores
- **Campaign detection** — cross-tenant correlation using anonymized SHA-256 fingerprints
- **Escalation** — automatic severity escalation when campaigns cross thresholds
- **Blocklist automation** — auto-create blocklist entries for high-severity threats

### Impossible Travel

Geographic anomaly detection for sessions and actors.

- **Location tracking** — GeoIP-based session location analysis
- **Travel speed** — detect physically impossible movements between requests
- **Signal creation** — generates `IMPOSSIBLE_TRAVEL` signals from credential stuffing events with location metadata

### Signal Array

Multi-signal aggregation and composite alerting.

- **Signal types** — aggregate across WAF, DLP, bot, session, and behavioral signals
- **Composite scoring** — combine individual signal risk scores into an overall threat assessment
- **Alerting rules** — trigger alerts when composite scores exceed configurable thresholds

## Security Features

### DLP Protection

Data Loss Prevention at the edge.

- **Pattern matching** — credit cards, SSN, IBAN, API keys, and custom regex patterns
- **Actions** — mask, hash, block, or log detected PII
- **Edge enforcement** — DLP scanning happens in Synapse before traffic reaches your backend

## Operations Features

### TestBed

Integrated security testing environment.

- **Scenario execution** — run predefined attack scenarios against a sensor
- **Validation** — verify detection rules work as expected before production deployment

### War Room

Collaborative incident response.

- **Real-time collaboration** — shared workspace for investigating active campaigns
- **Activity log** — timestamped record of all investigation actions
- **Bot automation** — `@horizon-bot` auto-creates war rooms for high-severity campaigns

### API Intelligence

Schema learning and violation detection.

- **Endpoint profiling** — learn expected request/response schemas from live traffic
- **Anomaly detection** — flag requests that deviate from learned schemas
- **Documentation** — auto-generate API documentation from observed traffic patterns

### Blue-Green Deployments

Zero-downtime sensor deployment.

- **Traffic shifting** — gradually shift traffic between sensor versions
- **Health gating** — automatic rollback if the new version reports unhealthy metrics

### Shadow Mirroring

Safe rule testing against live traffic.

- **Mirror mode** — copy live traffic to a shadow Synapse instance
- **Comparison** — compare detection results between production and shadow rules
- **Zero risk** — shadow results don't affect production traffic

### Capacity Planning

Fleet sizing and resource forecasting.

- **Traffic analysis** — historical traffic patterns and growth trends
- **Resource projection** — estimate CPU, memory, and bandwidth needs for fleet expansion

### Drift Management

Detect and resolve configuration drift across the fleet.

- **Drift detection** — compare actual sensor config against templates
- **Remediation** — push corrected configuration to drifted sensors

### Remote Shell

Secure remote access to sensor instances.

- **Authenticated access** — API key-scoped remote shell sessions
- **Audit logging** — all remote shell commands logged for compliance

### Firmware Updates

Sensor firmware lifecycle management.

- **Version management** — track firmware versions across the fleet
- **Staged rollout** — deploy firmware updates using canary strategies

### Tunnel Monitoring

Monitor WebSocket tunnel connections between sensors and the hub.

- **Connection status** — real-time view of tunnel health
- **Latency tracking** — round-trip latency measurements
- **Reconnection** — automatic reconnection with configurable backoff
