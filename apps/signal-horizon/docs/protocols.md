# Communication Protocols

Signal Horizon uses WebSockets for real-time bidirectional communication with both sensors and dashboards.

---

## Sensor Gateway (`/ws/sensors`)

The sensor gateway handles ingestion of threat signals and distribution of commands/configurations.

### 1. Authentication
Sensors must send an `auth` message within 10 seconds of connection.

**Client -> Hub:**
```json
{
  "type": "auth",
  "payload": {
    "apiKey": "...",
    "sensorId": "...",
    "sensorName": "...",
    "version": "1.2.3"
  }
}
```

### 2. Signal Ingestion
Sensors can send individual signals or batches.

**Client -> Hub:**
```json
{
  "type": "signal",
  "payload": {
    "signalType": "IP_THREAT",
    "sourceIp": "1.2.3.4",
    "severity": "HIGH",
    "confidence": 0.92,
    "eventCount": 1
  }
}
```

### 3. Heartbeat & Metrics
Sent every 30-60 seconds to report sensor health and traffic stats.

**Client -> Hub:**
```json
{
  "type": "heartbeat",
  "payload": {
    "status": "healthy",
    "cpu": 42,
    "memory": 65,
    "disk": 30,
    "requestsLastMinute": 1200,
    "avgLatencyMs": 18,
    "configHash": "...",
    "rulesHash": "..."
  }
}
```

### 4. Commands (Hub-Initiated)
The hub sends commands to sensors for orchestration.

**Hub -> Client:**
```json
{
  "type": "push_config",
  "commandId": "cmd_123",
  "payload": { "config": { "...": "..." } }
}
```

**Client -> Hub (Ack):**
```json
{
  "type": "command-ack",
  "payload": {
    "commandId": "cmd_123",
    "success": true,
    "result": { "...": "..." }
  }
}
```

---

## Dashboard Gateway (`/ws/dashboard`)

The dashboard gateway pushes real-time alerts and fleet updates to UI clients.

### 1. Authentication
Uses standard API keys with `dashboard:read` scope.

### 2. Subscriptions
Clients can subscribe to specific topics.

**Client -> Hub:**
```json
{
  "type": "subscribe",
  "payload": { "topic": "campaigns" }
}
```

**Available Topics:**
- `campaigns`: Real-time campaign detection/updates.
- `threats`: Real-time threat detection (high-risk IPs, etc.).
- `blocklist`: Real-time propagation of new blocklist entries.
- `metrics`: (Future) Real-time fleet metrics stream.

### 3. Alerts
Real-time messages pushed to subscribers.

**Hub -> Client:**
```json
{
  "type": "campaign-alert",
  "data": {
    "type": "campaign-detected",
    "campaign": { "id": "...", "name": "...", "severity": "HIGH" }
  }
}
```

---

## Reliability Features

- **Backpressure**: The Hub's `Aggregator` service monitors its queue depth and will slow down processing if overloaded.
- **Heartbeats**: Both gateways use a ping/pong mechanism to detect stale connections. Sensors that miss 3 heartbeats are marked `OFFLINE`.
- **Batching**: The `Aggregator` flushes signals to storage in batches (default: 100 signals or 5 seconds) for optimal database performance.
