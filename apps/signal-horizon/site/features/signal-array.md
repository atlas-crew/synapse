# Feature: Signal Array

Signal Array is Signal Horizon's fleet-wide intelligence layer. It connects your distributed Synapse sensors into a unified security mesh, enabling real-time correlation, centralized visibility, and coordinated response across every edge location in your deployment.

## What Signal Array Does

In a multi-site deployment, individual Synapse sensors each see only their local traffic. Signal Array bridges this gap by collecting threat signals from every sensor and correlating them at the hub level. This means an attacker probing one site can be identified and blocked across your entire fleet before they reach a second target.

### Key Capabilities

- **Centralized signal collection**: Every sensor streams threat signals, health metrics, and detection events to the hub in real time.
- **Fleet-wide correlation**: The hub aggregates signals across sensors to detect coordinated attacks, distributed scans, and campaign-level activity.
- **Coordinated response**: Block decisions, rule updates, and configuration changes propagate to the entire fleet from a single control plane.
- **Historical analysis**: All signals are stored and indexed for retrospective investigation and trend analysis.

## How Sensors Report to the Hub

Synapse sensors connect to Signal Horizon using outbound WebSocket tunnels. This design means sensors work behind firewalls, NATs, and corporate proxies without requiring any inbound port changes at edge sites.

### Connection Flow

1. The sensor authenticates with its API key and sensor ID.
2. A persistent WebSocket tunnel is established to Signal Horizon.
3. The sensor begins streaming telemetry: heartbeats (every 30 seconds), threat signals, WAF events, and health metrics.
4. Signal Horizon sends commands back through the same tunnel: configuration updates, rule deployments, and operational directives.

### Signal Batching

To minimize overhead, sensors batch signals before transmission:

```yaml
horizon:
  enabled: true
  hub_url: "wss://horizon.example.com/ws"
  api_key: "${SYNAPSE_HORIZON_API_KEY}"
  sensor_id: "edge-us-west-01"
  signal_batch_size: 100
  signal_batch_delay_ms: 1000
  heartbeat_interval_ms: 30000
```

Signals are queued locally and flushed in batches (default: up to 100 signals every 1 second). If the connection to the hub is temporarily lost, signals are buffered locally (up to 1,000 by default) and delivered when connectivity is restored.

### Resilience

The sensor-to-hub connection includes built-in fault tolerance:

- **Automatic reconnection** with configurable delay (default: 5 seconds).
- **Circuit breaker** that pauses reconnection attempts after repeated failures (default: 5 failures, 5-minute cooldown).
- **Local buffering** so no signals are lost during brief outages.

## Real-Time Correlation Across the Fleet

Signal Array's value becomes clear in multi-sensor deployments. The hub processes incoming signals from all sensors simultaneously and can identify patterns that no single sensor could detect alone.

### What Gets Correlated

| Signal Type | What the Hub Detects |
|-------------|---------------------|
| WAF blocks | Same attacker IP blocked at multiple sites |
| Trap hits | Coordinated reconnaissance scanning across locations |
| JA4 fingerprints | Same bot fingerprint appearing fleet-wide |
| Rate limit events | Distributed attacks spread across sensors to stay under per-site limits |
| Session anomalies | Credential stuffing campaigns targeting multiple endpoints |

### Fleet-Wide Blocklists

When Signal Horizon identifies a threat actor across multiple sensors, it can push a fleet-wide blocklist update. Sensors cache these blocklists locally (default TTL: 1 hour) so blocking decisions are enforced even during temporary hub disconnections.

## Benefits for Multi-Site Deployments

### Single Pane of Glass

The Signal Horizon dashboard provides a unified view of your entire fleet:

- **Fleet health**: Aggregated RPS, latency, and resource utilization across all sensors.
- **Threat map**: Geographic visualization of attacks across your edge locations.
- **Signal timeline**: Correlated event stream showing activity across the fleet.

### Operational Efficiency

- **One-click rule deployment**: Push WAF rules, rate limits, and custom policies to the entire fleet or targeted sensor groups.
- **Config drift detection**: The hub tracks the expected vs. actual configuration for every sensor and alerts when they diverge.
- **Remote diagnostics**: Access sensor logs, metrics, and even a remote shell through the hub without direct network access to edge sites.

### Regional Awareness

Group sensors by region, environment, or function to:

- Identify localized outages or attack bursts.
- Apply region-specific policies (stricter rules for public-facing sites, relaxed rules for internal services).
- Compare traffic patterns across data centers.

## Caching and Performance

Signal Array uses a three-tier caching strategy to keep the dashboard responsive without overloading sensors:

1. **In-memory LRU cache** (30-second TTL, 1,000 entries) for frequently accessed sensor data.
2. **Redis cache** (5-minute TTL) for fleet aggregations and status summaries.
3. **PostgreSQL** for persistent storage of all signals and configuration state.

Cache invalidation happens automatically when sensors disconnect or when operators manually clear cached data from the dashboard.

## Getting Started

To connect a Synapse sensor to Signal Array, add the `horizon` block to your sensor configuration:

```yaml
horizon:
  enabled: true
  hub_url: "wss://your-horizon-instance.example.com/ws"
  api_key: "${SYNAPSE_HORIZON_API_KEY}"
  sensor_id: "unique-sensor-id"
  sensor_name: "US-West Production Edge"
```

The sensor will appear in the Signal Horizon fleet dashboard within seconds of establishing the connection.
