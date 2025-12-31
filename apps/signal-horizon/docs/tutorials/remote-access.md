# Remote Access Guide

This guide explains how to access your distributed edge sensors through Signal Horizon's browser-based shell sessions and embedded dashboards.

## Overview

Signal Array provides secure remote access to sensors without requiring inbound firewall ports. Sensors establish outbound WebSocket tunnels to Signal Horizon, enabling:

- **Shell Access**: Browser-based terminal sessions (SSH-over-WebSocket)
- **Dashboard Proxy**: Access sensor web dashboards through the tunnel

## Architecture

```
┌─────────────┐         ┌──────────────────┐         ┌─────────────┐
│   Browser   │◀───────▶│  Signal Horizon  │◀───────▶│   Sensor    │
│             │  HTTPS  │   Tunnel Broker  │  WSS    │   Agent     │
│  xterm.js   │         │                  │         │             │
└─────────────┘         └──────────────────┘         └─────────────┘
     User                     Cloud                      Edge
```

**Key Benefits**:
- No inbound ports required on sensors (outbound-only connections)
- TLS encryption for all traffic
- JWT authentication and session isolation
- Audit logging of all tunnel activities

## Shell Access

### Starting a Shell Session

#### Via Web UI

1. Navigate to **Fleet → Sensors**
2. Click on the sensor you want to access
3. Click **Open Shell** in the sensor detail panel
4. A new terminal window opens with an interactive shell

#### Via API

```bash
# Establish WebSocket connection
wscat -c "wss://your-signal-horizon.com/ws/shell?sensorId=sen_xxx" \
  -H "Authorization: Bearer $JWT_TOKEN"
```

### Terminal Features

The web terminal provides:

- **Full terminal emulation**: xterm.js with 256-color support
- **Copy/paste**: Ctrl+Shift+C / Ctrl+Shift+V
- **Resize handling**: Terminal adapts to window size
- **Session persistence**: Reconnects automatically on network interruption

### Shell Session Architecture

```
Browser                Signal Horizon              Sensor
   │                        │                        │
   │──WebSocket Connect────▶│                        │
   │                        │──shell-data(start)────▶│
   │                        │                        │──spawn PTY
   │◀─────────────────────────────────────────────────│
   │  stdin  ──────────────▶│──shell-data(data)─────▶│
   │                        │                        │
   │◀──shell-data(data)─────│◀──────────────────────│  stdout/stderr
   │                        │                        │
```

### Example Session

```typescript
// Terminal component connection flow
const ws = new WebSocket(`wss://signal-horizon.com/ws/shell?sensorId=${sensorId}`);

ws.onopen = () => {
  // Send terminal dimensions
  ws.send(JSON.stringify({
    type: 'shell-resize',
    payload: { cols: 80, rows: 24 }
  }));
};

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.type === 'shell-data') {
    terminal.write(msg.payload.data);
  }
};

// Send user input
terminal.onData((data) => {
  ws.send(JSON.stringify({
    type: 'shell-data',
    payload: { data }
  }));
});
```

## Dashboard Proxy

### Accessing Sensor Dashboards

Many sensors run local web dashboards (Synapse UI, monitoring tools, etc.). Signal Array proxies these through the WebSocket tunnel.

#### Via Web UI

1. Navigate to **Fleet → Sensors**
2. Click on the sensor
3. Click **Open Dashboard** in the sensor detail panel
4. The sensor's dashboard loads in an embedded iframe

#### Via Direct URL

```
https://your-signal-horizon.com/proxy/sen_xxx/dashboard/
```

### Dashboard Proxy Architecture

```
Browser                Signal Horizon              Sensor
   │                        │                        │
   │──HTTP GET /proxy/...──▶│                        │
   │                        │──dashboard-request────▶│
   │                        │                        │──HTTP GET localhost:3000
   │◀──dashboard-response───│◀──────────────────────│
   │                        │                        │
```

### Supported Dashboard Features

- **Static assets**: HTML, CSS, JavaScript, images
- **API calls**: XHR/fetch requests proxied through tunnel
- **WebSocket**: Sub-tunnels for real-time dashboard features
- **Authentication**: JWT token passed for authorization

## Tunnel Capabilities

Sensors declare capabilities when connecting:

```typescript
interface TunnelSession {
  sensorId: string;
  tenantId: string;
  capabilities: ('shell' | 'dashboard')[];
  connectedAt: Date;
  lastHeartbeat: Date;
  metadata?: {
    hostname?: string;
    version?: string;
    platform?: string;
  };
}
```

Check sensor capabilities before attempting access:

```bash
curl https://your-signal-horizon.com/api/v1/fleet/sensors/sen_xxx \
  -H "Authorization: Bearer $API_KEY"
```

```json
{
  "id": "sen_xxx",
  "name": "edge-us-east-1-prod-01",
  "capabilities": ["shell", "dashboard"],
  "tunnelStatus": "connected",
  "lastHeartbeat": "2025-01-15T10:30:00Z"
}
```

## Security Model

### Authentication Flow

```
1. User logs into Signal Horizon
2. UI requests JWT with appropriate scopes
3. JWT includes tenantId and allowed sensors
4. WebSocket connection validates JWT
5. TunnelBroker verifies sensor belongs to tenant
6. Session established with audit logging
```

### Required Permissions

| Action | Required Scope |
|--------|---------------|
| View sensors | `fleet:read` |
| Shell access | `fleet:write` |
| Dashboard access | `fleet:read` |
| Modify sensor | `fleet:write` |

### Session Isolation

- Each user session gets a unique `sessionId`
- Sessions are isolated at the TunnelBroker level
- One user cannot intercept another's session
- Sessions automatically terminate when:
  - User disconnects
  - Sensor disconnects
  - JWT expires
  - Inactivity timeout (configurable)

### Audit Logging

All tunnel activities are logged:

```json
{
  "event": "session:started",
  "sessionId": "uuid",
  "userId": "user_xxx",
  "sensorId": "sen_xxx",
  "type": "shell",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## Troubleshooting

### Tunnel Disconnected

```
Error: Sensor tunnel not found
```

**Causes**:
- Sensor is offline
- Network connectivity issue
- Heartbeat timeout

**Solutions**:
1. Check sensor status in Fleet Overview
2. Verify sensor logs: `journalctl -u signal-horizon-sensor`
3. Test network connectivity from sensor

### Session Timeout

```
Error: Session terminated due to inactivity
```

**Solution**: Increase activity or reconnect. Sessions timeout after 30 minutes of inactivity by default.

### Permission Denied

```
Error: Forbidden - tenant mismatch
```

**Cause**: Attempting to access a sensor that doesn't belong to your tenant.

**Solution**: Verify you're logged into the correct tenant/organization.

### Dashboard Not Loading

```
Error: Dashboard capability not available
```

**Causes**:
- Sensor doesn't have dashboard capability enabled
- Local dashboard service not running on sensor

**Solutions**:
1. Check sensor capabilities in detail view
2. Verify dashboard service on sensor: `curl localhost:3000/health`
3. Enable dashboard in sensor configuration

### Latency Issues

High latency in shell or dashboard:

**Causes**:
- Geographic distance between user and Signal Horizon
- Network congestion
- Large payloads

**Solutions**:
1. Use a Signal Horizon region closer to your sensors
2. Check network path: `mtr your-signal-horizon.com`
3. For dashboards, optimize asset sizes

## Best Practices

### For Shell Access

- Use `tmux` or `screen` for persistent sessions
- Set appropriate terminal dimensions on connect
- Implement reconnection logic with exponential backoff
- Log session activities for compliance

### For Dashboard Proxy

- Optimize dashboard assets for tunnel transfer
- Use WebSocket for real-time features (already tunneled)
- Cache static assets when possible
- Consider data compression for large payloads

### For Security

- Rotate JWT tokens regularly
- Use short session timeouts for sensitive environments
- Enable MFA for users with fleet access
- Review audit logs periodically

## API Reference

### Shell Sessions

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ws/shell` | WebSocket | Start shell session |

**Query Parameters**:
- `sensorId`: Target sensor ID

**Message Types**:
- `shell-data`: Terminal I/O
- `shell-resize`: Terminal dimension change

### Dashboard Proxy

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ws/dashboard` | WebSocket | Start dashboard session |
| `/proxy/:sensorId/*` | GET/POST | HTTP proxy to sensor |

### Tunnel Status

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/tunnel/status/:sensorId` | GET | Check tunnel status |
| `/api/v1/tunnel/sessions` | GET | List active sessions |

## Next Steps

- **[Synapse Rules Guide](./synapse-rules.md)**: Configure security rules via the tunnel
- **[API Key Management](./api-key-management.md)**: Manage access credentials
- **[Sensor Onboarding](./sensor-onboarding.md)**: Add more sensors to your fleet
