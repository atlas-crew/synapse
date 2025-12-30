# Sensor Protocol Guide

This guide documents how sensors (like Cutlass/Echo Pro) connect to and communicate with Signal Horizon Hub.

## Overview

Sensors connect to Signal Horizon via WebSocket to stream threat signals in real-time. The hub aggregates, correlates, and distributes threat intelligence across the sensor fleet.

```
┌─────────────────┐        WebSocket        ┌──────────────────┐
│     Sensor      │ ────────────────────>   │  Signal Horizon  │
│  (Tracer, etc)  │ <──── Commands ──────   │  Hub             │
└─────────────────┘        Blocklist        └──────────────────┘
                                                     │
                                                     ▼
                                            ┌──────────────────┐
                                            │   Dashboards     │
                                            │   War Rooms      │
                                            │   Alerting       │
                                            └──────────────────┘
```

## Connection Setup

### WebSocket Endpoint

```
ws://signal-horizon:3000/ws/sensors
wss://signal-horizon:3000/ws/sensors  (with TLS)
```

### Authentication

Sensors must authenticate within 10 seconds of connecting:

```json
{
  "type": "auth",
  "payload": {
    "apiKey": "sensor-api-key-here",
    "sensorId": "tracer-prod-1",
    "sensorName": "Edge Sensor US-East",
    "version": "1.2.3"
  }
}
```

**Required scope:** `signal:write`

**Success Response:**
```json
{
  "type": "auth-success",
  "sensorId": "tracer-prod-1",
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

### Batch Signals (Recommended for High Volume)

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

**Batch Acknowledgment:**
```json
{
  "type": "batch-ack",
  "count": 2,
  "sequenceId": 2
}
```

**Note:** Maximum batch size is 1000 signals.

## Signal Types

| Signal Type | Description | Example Trigger |
|-------------|-------------|-----------------|
| `IP_THREAT` | IP-based threat detection | Repeated attack patterns from same IP |
| `FINGERPRINT_THREAT` | Browser fingerprint threat | Same fingerprint across multiple IPs |
| `CAMPAIGN_INDICATOR` | Part of a larger campaign | Correlated attack patterns |
| `CREDENTIAL_STUFFING` | Credential abuse attempt | Multiple failed logins |
| `RATE_ANOMALY` | Unusual request rates | Traffic spike from single source |
| `BOT_SIGNATURE` | Automated bot behavior | Non-human traffic patterns |
| `IMPOSSIBLE_TRAVEL` | Geographically impossible access | Same user from distant locations |

## Severity Levels

| Severity | Confidence Range | Action |
|----------|-----------------|--------|
| `LOW` | 0.0 - 0.3 | Log, monitor |
| `MEDIUM` | 0.3 - 0.6 | Alert, consider blocking |
| `HIGH` | 0.6 - 0.8 | Alert, likely block |
| `CRITICAL` | 0.8 - 1.0 | Immediate block + alert |

## Blocklist Synchronization

Sensors can request the current blocklist snapshot:

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
      "expiresAt": "2024-01-16T00:00:00Z",
      "source": "WAR_ROOM"
    }
  ],
  "sequenceId": 3
}
```

**Block Types:**
- `IP` - Single IP address
- `IP_RANGE` - CIDR range
- `FINGERPRINT` - Browser/device fingerprint
- `ASN` - Autonomous System Number
- `USER_AGENT` - User agent string

## Heartbeat & Health

Sensors should respond to ping messages to maintain connection:

**Hub → Sensor:**
```json
{
  "type": "ping",
  "timestamp": 1735689600000
}
```

**Sensor → Hub:**
```json
{
  "type": "pong"
}
```

### Rich Heartbeat (Optional)

Sensors can send rich heartbeat data for fleet monitoring:

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

## Receiving Commands

The hub can push commands to sensors:

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
- `push_config` - Update sensor configuration
- `push_rules` - Deploy WAF rules
- `restart` - Request sensor restart
- `collect_diagnostics` - Request diagnostic data

## Complete Integration Example

```typescript
import WebSocket from 'ws';

const HORIZON_URL = 'ws://signal-horizon:3000/ws/sensors';
const API_KEY = process.env.SIGNAL_HORIZON_API_KEY;
const SENSOR_ID = process.env.SENSOR_ID || 'tracer-1';

class SignalHorizonClient {
  private ws: WebSocket | null = null;
  private sequenceId = 0;
  private signalBuffer: any[] = [];

  connect() {
    this.ws = new WebSocket(HORIZON_URL);

    this.ws.on('open', () => this.authenticate());
    this.ws.on('message', (data) => this.handleMessage(JSON.parse(data.toString())));
    this.ws.on('close', () => setTimeout(() => this.connect(), 5000));
    this.ws.on('error', (err) => console.error('WebSocket error:', err));
  }

  private authenticate() {
    this.send({
      type: 'auth',
      payload: {
        apiKey: API_KEY,
        sensorId: SENSOR_ID,
        sensorName: 'Tracer Edge Sensor',
        version: '1.0.0'
      }
    });
  }

  private handleMessage(msg: any) {
    switch (msg.type) {
      case 'auth-success':
        console.log('Authenticated:', msg.sensorId);
        this.requestBlocklist();
        break;

      case 'ping':
        this.send({ type: 'pong' });
        break;

      case 'blocklist-snapshot':
        this.updateBlocklist(msg.entries);
        break;

      case 'push_config':
        this.applyConfig(msg.payload);
        this.send({
          type: 'command-ack',
          payload: { commandId: msg.commandId, success: true }
        });
        break;
    }
  }

  // Report a threat signal
  reportThreat(ip: string, signalType: string, severity: string, metadata?: object) {
    this.signalBuffer.push({
      signalType,
      sourceIp: ip,
      severity,
      confidence: this.calculateConfidence(severity),
      eventCount: 1,
      metadata
    });

    // Flush when buffer reaches 100 signals
    if (this.signalBuffer.length >= 100) {
      this.flushSignals();
    }
  }

  private flushSignals() {
    if (this.signalBuffer.length === 0) return;

    this.send({
      type: 'signal-batch',
      payload: this.signalBuffer.splice(0, 100)
    });
  }

  private requestBlocklist() {
    this.send({ type: 'blocklist-sync' });
  }

  private send(msg: object) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }

  private calculateConfidence(severity: string): number {
    return { LOW: 0.3, MEDIUM: 0.5, HIGH: 0.75, CRITICAL: 0.95 }[severity] || 0.5;
  }

  private updateBlocklist(entries: any[]) {
    // Implement local blocklist update
  }

  private applyConfig(config: any) {
    // Implement config application
  }
}

// Usage
const client = new SignalHorizonClient();
client.connect();

// Report threats as they're detected
client.reportThreat('192.168.1.100', 'IP_THREAT', 'HIGH', { route: '/admin' });
```

## Rate Limiting

- **Messages per second:** 100 (sliding window)
- **Batch size:** 1000 signals max
- **Authentication timeout:** 10 seconds

Exceeding rate limits will result in an error message and potential disconnection.

## Error Handling

```json
{
  "type": "error",
  "error": "Rate limit exceeded"
}
```

Common errors:
- `"Invalid message"` - Malformed JSON or unknown message type
- `"Rate limit exceeded"` - Too many messages per second
- `"Auth timeout"` - Did not authenticate within 10 seconds
- `"Invalid API key"` - API key not found or invalid

## Mapping from Cutlass Signal Types

If you're integrating Cutlass/Echo Pro sensors, here's how to map their signal types:

| Cutlass Signal | Signal Horizon Type | Notes |
|---------------|---------------------|-------|
| `honeypot_hit` | `IP_THREAT` | High severity, probe behavior |
| `trap_trigger` | `IP_THREAT` | Critical severity, immediate action |
| `protocol_probe` | `IP_THREAT` | Medium-high severity |
| `dlp_match` | `IP_THREAT` | High severity, data exfil concern |

## Related Documentation

- [Architecture Overview](./architecture.md)
- [Fleet Management API](./fleet-api.md)
- [API Reference](./api.md)
