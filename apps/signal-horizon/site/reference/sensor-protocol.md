# Sensor Protocol Reference

This reference documents the WebSocket protocol used by Synapse sensors to communicate with the Signal Horizon hub. It covers connection setup, authentication, signal reporting, blocklist synchronization, heartbeats, and command handling.

## Connection

### WebSocket Endpoint

```
ws://signal-horizon:3100/ws/sensors
wss://signal-horizon:3100/ws/sensors   (with TLS)
```

The path is configurable on the hub. The default is `/ws/sensors`.

### Protocol Flow

1. Sensor opens a WebSocket connection to the hub.
2. Sensor sends an `auth` message within 10 seconds.
3. Hub validates the API key and responds with `auth-success` or `auth-failed`.
4. On success, the sensor begins sending signals and responding to commands.
5. Hub sends periodic `ping` messages; sensor responds with `pong`.

---

## Authentication

Sensors must authenticate within 10 seconds of connecting or the connection is closed.

**Sensor to Hub:**

```json
{
  "type": "auth",
  "payload": {
    "apiKey": "your-api-key",
    "sensorId": "sensor-prod-1",
    "sensorName": "Edge Sensor US-East",
    "version": "1.2.3"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `apiKey` | string | yes | API key with `signal:write` scope |
| `sensorId` | string | yes | Unique sensor identifier |
| `sensorName` | string | yes | Human-readable name |
| `version` | string | yes | Sensor version (semver format) |

**Success Response:**

```json
{
  "type": "auth-success",
  "sensorId": "sensor-prod-1",
  "tenantId": "tenant-abc",
  "capabilities": ["signal", "blocklist-sync"]
}
```

**Failure Response:**

```json
{
  "type": "auth-failed",
  "error": "Invalid API key"
}
```

---

## Sending Signals

### Single Signal

```json
{
  "type": "signal",
  "payload": {
    "signalType": "IP_THREAT",
    "sourceIp": "192.168.1.100",
    "severity": "HIGH",
    "confidence": 0.92,
    "eventCount": 1,
    "metadata": {
      "route": "/admin",
      "pattern": "admin_probe"
    }
  }
}
```

**Acknowledgment:**

```json
{
  "type": "signal-ack",
  "sequenceId": 1
}
```

### Batch Signals

For high-volume reporting, send multiple signals in a single message. Maximum batch size is 1000 signals.

```json
{
  "type": "signal-batch",
  "payload": [
    {
      "signalType": "IP_THREAT",
      "sourceIp": "192.168.1.100",
      "severity": "HIGH",
      "confidence": 0.92,
      "eventCount": 5
    },
    {
      "signalType": "BOT_SIGNATURE",
      "sourceIp": "10.0.0.50",
      "severity": "MEDIUM",
      "confidence": 0.85,
      "eventCount": 12
    }
  ]
}
```

**Acknowledgment:**

```json
{
  "type": "batch-ack",
  "count": 2,
  "sequenceId": 2
}
```

### Signal Types

| Signal Type | Description |
|-------------|-------------|
| `IP_THREAT` | IP-based threat detection (probes, attacks) |
| `FINGERPRINT_THREAT` | Browser/TLS fingerprint anomaly |
| `CAMPAIGN_INDICATOR` | Part of a correlated attack campaign |
| `CREDENTIAL_STUFFING` | Credential abuse attempt |
| `RATE_ANOMALY` | Unusual request rate pattern |
| `BOT_SIGNATURE` | Automated bot behavior |
| `IMPOSSIBLE_TRAVEL` | Geographically impossible access |

### Severity Levels

| Severity | Confidence Range | Typical Action |
|----------|-----------------|----------------|
| `LOW` | 0.0 - 0.3 | Log and monitor |
| `MEDIUM` | 0.3 - 0.6 | Alert, consider blocking |
| `HIGH` | 0.6 - 0.8 | Alert, likely block |
| `CRITICAL` | 0.8 - 1.0 | Immediate block and alert |

---

## Blocklist Synchronization

Sensors can request the current blocklist snapshot from the hub.

**Request:**

```json
{
  "type": "blocklist-sync"
}
```

**Response:**

```json
{
  "type": "blocklist-snapshot",
  "entries": [
    {
      "blockType": "IP",
      "indicator": "192.168.1.100",
      "expiresAt": null,
      "source": "AUTOMATIC"
    },
    {
      "blockType": "FINGERPRINT",
      "indicator": "abc123hash",
      "expiresAt": "2026-02-01T00:00:00Z",
      "source": "WAR_ROOM"
    }
  ],
  "sequenceId": 3
}
```

**Block Types:**

| Type | Description |
|------|-------------|
| `IP` | Single IP address |
| `IP_RANGE` | CIDR range |
| `FINGERPRINT` | Browser/device fingerprint |
| `ASN` | Autonomous System Number |
| `USER_AGENT` | User-Agent string |

---

## Heartbeat and Health

### Ping/Pong

The hub sends periodic `ping` messages to verify the connection. Sensors must respond with `pong`.

**Hub to Sensor:**

```json
{
  "type": "ping",
  "timestamp": 1735689600000
}
```

**Sensor to Hub:**

```json
{
  "type": "pong"
}
```

### Rich Heartbeat

Sensors can optionally send detailed health data for fleet monitoring:

```json
{
  "type": "heartbeat",
  "payload": {
    "timestamp": 1735689600000,
    "status": "healthy",
    "cpu": 40,
    "memory": 60,
    "disk": 30,
    "requestsLastMinute": 1200,
    "avgLatencyMs": 18,
    "configHash": "abc123",
    "rulesHash": "def456"
  }
}
```

---

## Receiving Commands

The hub can push commands to sensors over the WebSocket connection.

**Hub to Sensor:**

```json
{
  "type": "push_config",
  "commandId": "cmd-123",
  "payload": {
    "threshold": 70,
    "decayRate": 10,
    "blockMode": "block"
  }
}
```

**Sensor Acknowledgment:**

```json
{
  "type": "command-ack",
  "payload": {
    "commandId": "cmd-123",
    "success": true,
    "message": "Configuration applied",
    "result": {}
  }
}
```

**Command Types:**

| Command | Description |
|---------|-------------|
| `push_config` | Update sensor configuration |
| `push_rules` | Deploy WAF rules |
| `restart` | Request sensor restart |
| `collect_diagnostics` | Request diagnostic data |

---

## Reconnection Behavior

When the WebSocket connection drops, sensors should implement automatic reconnection with the following behavior:

1. Wait for the configured reconnection delay (default: 5 seconds).
2. Attempt to reconnect and re-authenticate.
3. On success, request a fresh blocklist snapshot.
4. Resume signal reporting.

Sensors using the Synapse Horizon client have built-in reconnection with configurable parameters:

| Setting | Default | Description |
|---------|---------|-------------|
| `reconnect_delay_ms` | 5000 | Base delay between reconnection attempts |
| `max_reconnect_attempts` | 0 (unlimited) | Maximum number of retries |
| `circuit_breaker_threshold` | 5 | Consecutive failures before circuit opens |
| `circuit_breaker_cooldown_ms` | 300000 | Wait time when circuit breaker is open |

---

## Rate Limits

| Constraint | Value |
|------------|-------|
| Messages per second | 100 (sliding window) |
| Maximum batch size | 1000 signals |
| Authentication timeout | 10 seconds |

Exceeding these limits results in an error message and potential disconnection.

## Error Messages

```json
{
  "type": "error",
  "error": "Rate limit exceeded"
}
```

| Error | Description |
|-------|-------------|
| `Invalid message` | Malformed JSON or unknown message type |
| `Rate limit exceeded` | Too many messages per second |
| `Auth timeout` | Did not authenticate within 10 seconds |
| `Invalid API key` | API key not found or invalid |
