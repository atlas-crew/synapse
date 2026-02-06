# Platform Features Reference

This reference provides a comprehensive overview of all Signal Horizon platform capabilities, organized by functional area.

---

## Fleet Management

| Feature | Description |
|---------|-------------|
| Sensor Inventory | View all sensors with status, version, region, and resource usage |
| Real-Time Monitoring | Live health metrics via WebSocket (CPU, memory, RPS, latency) |
| Fleet Overview | Aggregated fleet health score with regional breakdown |
| Version Distribution | Track sensor versions across the fleet |
| Sensor Detail Pages | Per-sensor system info, performance, network, processes, and logs |
| Alerts Dashboard | Sensors requiring attention (offline, high resource usage, failed commands) |

## Configuration Management

| Feature | Description |
|---------|-------------|
| Config Templates | Create, version, and manage reusable configuration templates |
| Config Push | Deploy templates to one or more sensors with a single action |
| Sync Status | Track which sensors are in sync with the latest configuration |
| Audit Trail | Full audit log of configuration changes (who, what, when) |
| Environment Scoping | Tag templates by environment (production, staging, dev) |
| Pingora Config Editor | Edit and push Synapse WAF configuration from the console |

## Rule Distribution

| Feature | Description |
|---------|-------------|
| Immediate Deployment | Push rules to all target sensors at once |
| Canary Rollout | Deploy to a percentage of sensors first, expand on success |
| Rolling Deployment | Deploy in batches with health checks between each batch |
| Blue/Green Deployment | Stage rules to all sensors, then perform an atomic switch |
| Scheduled Deployment | Deploy rules at a specified future time |
| Rule Sync Status | Track per-sensor rule deployment status |
| Failed Rule Retry | Retry failed rule deployments per sensor |

## Remote Sensor Management

| Feature | Description |
|---------|-------------|
| Remote Shell | Interactive WebSocket terminal sessions to sensors |
| File Browser | Browse, inspect, and download files from remote sensors |
| Diagnostics Collection | On-demand health, memory, connection, and cache diagnostics |
| Live Diagnostics Stream | Real-time SSE stream of sensor diagnostics |
| Service Control | Reload, restart, drain, resume, and shutdown sensor services |
| Batch Control | Execute control commands across multiple sensors simultaneously |

## Threat Detection and Intelligence

| Feature | Description |
|---------|-------------|
| Signal Ingestion | Real-time WebSocket signal pipeline from sensors |
| Signal Types | IP threats, fingerprint threats, bot signatures, credential stuffing, rate anomalies, impossible travel, campaign indicators |
| Cross-Tenant Correlation | Detect coordinated attacks across tenants using anonymized fingerprints |
| Campaign Detection | Automatically correlate signals into attack campaigns |
| Threat Scoring | Risk scoring with configurable thresholds and confidence levels |
| Fleet-Wide Threats | Identify threats that span multiple tenants |

## Blocklist Management

| Feature | Description |
|---------|-------------|
| Automatic Blocking | Auto-generate blocklist entries from high-severity threats |
| Manual Blocking | Add/remove IP, CIDR, fingerprint, ASN, or User-Agent blocks |
| Fleet-Wide Blocks | Propagate blocks across all tenants (admin only) |
| Blocklist Sync | Sensors request and receive blocklist snapshots over WebSocket |
| Expiring Blocks | Set TTL on blocklist entries for automatic removal |
| Propagation Tracking | Monitor block propagation status across the sensor fleet |

## Threat Hunting

| Feature | Description |
|---------|-------------|
| Timeline Search | Query signal history with filters for type, severity, IP, and confidence |
| Automatic Query Routing | Queries route to PostgreSQL or ClickHouse based on time range |
| Campaign Timelines | View the event history of specific campaigns |
| Hourly Aggregations | Time-series statistics for trend analysis |
| IP Activity Lookup | Cross-tenant IP activity investigation (admin only) |
| Saved Queries | Store and re-execute hunt queries |

## War Rooms

| Feature | Description |
|---------|-------------|
| Incident Collaboration | Create war rooms to coordinate response to active threats |
| Activity Timeline | Threaded activity log with messages, blocks, and status changes |
| Campaign Linking | Associate campaigns with war rooms for context |
| Block Management | Create and remove blocklist entries directly from war rooms |
| Priority and Status | Track war room priority (LOW-CRITICAL) and status (ACTIVE-ARCHIVED) |
| Automated Triggers | System-generated war rooms for high-severity campaigns |

## Analytics and Reporting

| Feature | Description |
|---------|-------------|
| IOC Export | Export indicators of compromise in JSON, CSV, or STIX format |
| Attack Trends | Time-series analysis of attack volume and patterns |
| Fleet Intelligence Summary | Cross-tenant threat landscape overview |
| Top Threats Dashboard | Top IPs, fingerprints, and campaigns by activity |
| Signal Breakdown | Signal distribution by type and severity |
| Volume Charts | Time-series visualizations of signal volume |
| Sensor Logs | Access, error, system, and WAF logs from ClickHouse |

## Security and Access Control

| Feature | Description |
|---------|-------------|
| API Key Authentication | SHA-256 hashed keys with scope-based access control |
| Role-Based Access | Viewer, operator, and admin roles with escalating privileges |
| Multi-Tenant Isolation | Strict tenant data isolation with controlled sharing |
| Audit Logging | Comprehensive audit trail for security-sensitive operations |
| Confirmation Tokens | Required for destructive operations (restart, shutdown) |

## Integration

| Feature | Description |
|---------|-------------|
| REST API | Full management API at `/api/v1` |
| WebSocket Sensor Protocol | Real-time bidirectional sensor communication |
| WebSocket Dashboard Protocol | Real-time push notifications for UI dashboards |
| Server-Sent Events | Live diagnostics streaming |
| ClickHouse Integration | Optional historical analytics backend |
| Synapse Pingora WAF | Native integration with the Synapse WAF sensor |
