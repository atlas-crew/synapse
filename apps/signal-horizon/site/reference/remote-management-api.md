# Remote Management API Reference

The Remote Management API enables operators to interact with Synapse sensors through a secure tunnel. It provides file browsing, diagnostics collection, service control, and session management capabilities.

## Overview

Remote management operations are relayed through the Signal Horizon hub to sensors via an encrypted WebSocket tunnel. The sensor must be online and have an active tunnel connection for these operations to succeed.

---

## File Browser API

Browse and download files from remote sensors. File access is restricted to paths allowed by the sensor's file access policy.

**Base Path:** `/api/v1/fleet/:sensorId/files`

**Required Scope:** `sensor:files`

### GET /api/v1/fleet/:sensorId/files

List files in a directory on the sensor.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | string | `/var/log/synapse` | Directory path to list |
| `timeout` | integer | 30000 | Request timeout in milliseconds (1000-60000) |

**Response:**

```json
{
  "sensorId": "sensor-123",
  "sensorName": "Edge US-East",
  "path": "/var/log/synapse",
  "entries": [
    {
      "path": "/var/log/synapse/access.log",
      "name": "access.log",
      "size": 1048576,
      "modified": "2026-01-15T10:30:00Z",
      "isDir": false
    }
  ],
  "total": 12,
  "truncated": false
}
```

### GET /api/v1/fleet/:sensorId/files/stat

Get metadata for a specific file.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | string | (required) | File path to inspect |
| `includeChecksum` | boolean | false | Include SHA-256 checksum |
| `timeout` | integer | 30000 | Request timeout in ms |

### GET /api/v1/fleet/:sensorId/files/download

Download a file from the sensor. Files under 10 MB are returned directly. Larger files are streamed in chunks.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | string | (required) | File path to download |
| `timeout` | integer | 30000 | Request timeout in ms |

**Response Headers:**

| Header | Description |
|--------|-------------|
| `Content-Disposition` | Attachment with filename |
| `Content-Type` | `application/octet-stream` |
| `X-File-Size` | Original file size in bytes |
| `X-Checksum` | SHA-256 checksum (when available) |

### GET /api/v1/fleet/:sensorId/files/download-chunk

Download a single chunk from a file. Useful for resumable downloads or random access.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | string | (required) | File path |
| `offset` | integer | 0 | Byte offset to start reading |
| `timeout` | integer | 30000 | Request timeout in ms |

### GET /api/v1/fleet/:sensorId/files/progress/:transferId

Get the progress of an active file transfer.

**Response:**

```json
{
  "transferId": "uuid",
  "sensorId": "sensor-123",
  "path": "/var/log/synapse/access.log",
  "totalSize": 52428800,
  "transferred": 10485760,
  "percentage": 20,
  "bytesPerSecond": 2097152,
  "estimatedSecondsRemaining": 20,
  "elapsedMs": 5000
}
```

---

## Diagnostics API

Collect diagnostic data from sensors, including health checks, resource usage, and performance metrics.

**Base Path:** `/api/v1/fleet/:sensorId/diagnostics`

**Required Scope:** `sensor:diag`

### Diagnostic Sections

| Section | Description |
|---------|-------------|
| `health` | Overall sensor health status and component checks |
| `memory` | Heap usage, RSS, GC statistics |
| `connections` | Active connection counts and recent connections |
| `rules` | WAF rule counts, categories, and trigger statistics |
| `actors` | Tracked and blocked actor counts |
| `config` | Current configuration hash and settings (secrets redacted) |
| `metrics` | Request rates, latency percentiles, error rates |
| `threads` | Worker thread states and task queues |
| `cache` | Cache hit rates, sizes, and eviction counts |

### GET /api/v1/fleet/:sensorId/diagnostics

Collect diagnostics on demand.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sections` | string | `health,memory,connections` | Comma-separated list of sections |
| `timeout` | integer | 30000 | Request timeout in ms (1000-60000) |

**Response:**

```json
{
  "sensorId": "sensor-123",
  "collectedAt": "2026-01-15T12:00:00Z",
  "collectionTimeMs": 35,
  "sections": ["health", "memory"],
  "data": {
    "health": {
      "status": "healthy",
      "uptime": 86400,
      "version": "1.2.3",
      "components": [
        { "name": "memory", "status": "healthy", "message": null },
        { "name": "tunnel", "status": "healthy", "message": null }
      ]
    },
    "memory": {
      "heapUsed": 157286400,
      "heapTotal": 500000000,
      "rss": 350000000
    }
  }
}
```

### GET /api/v1/fleet/:sensorId/diagnostics/live

Stream live diagnostics via Server-Sent Events (SSE).

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sections` | string | `health,metrics` | Comma-separated list of sections |
| `interval` | integer | 1000 | Update interval in ms (500-30000) |

**SSE Events:**

| Event | Description |
|-------|-------------|
| `connected` | Initial connection confirmation |
| `diagnostics` | Periodic diagnostics data |
| `status` | Sensor status changes (e.g., offline) |
| `error` | Error notifications |

### POST /api/v1/fleet/:sensorId/diagnostics/run

Run a targeted diagnostic check with specific parameters.

**Request Body:**

```json
{
  "sections": ["health", "memory", "rules"],
  "params": {
    "verbose": true
  }
}
```

### GET /api/v1/fleet/:sensorId/diagnostics/history

Retrieve historical diagnostics data for trend analysis. Returns time-series data with metrics like RPS, latency, memory, and CPU.

---

## Service Control API

Control sensor services remotely (reload, restart, shutdown, drain, resume).

**Base Path:** `/api/v1/fleet-control`

### Required Scopes

| Scope | Commands |
|-------|----------|
| `sensor:control` | `reload`, `drain`, `resume` |
| `sensor:admin` | `restart`, `shutdown` |

### POST /api/v1/fleet-control/:sensorId/control/:command

Execute a control command on a sensor.

**Valid Commands:**

| Command | Description | Scope | Confirmation |
|---------|-------------|-------|-------------|
| `reload` | Hot-reload configuration | `sensor:control` | No |
| `restart` | Graceful restart (drain first) | `sensor:admin` | Yes |
| `shutdown` | Graceful shutdown (drain first) | `sensor:admin` | Yes |
| `drain` | Stop accepting new connections | `sensor:control` | No |
| `resume` | Resume accepting connections | `sensor:control` | No |

**Confirmation:** Destructive commands (`restart`, `shutdown`) require the `X-Confirm-Token` header. Without it, the API returns HTTP 428 (Precondition Required).

```bash
curl -X POST /api/v1/fleet-control/sensor-123/control/restart \
  -H "Authorization: Bearer <api-key>" \
  -H "X-Confirm-Token: unique-token-123"
```

### GET /api/v1/fleet-control/:sensorId/state

Get the current service state for a sensor.

**Scope:** `sensor:control`

**Response:**

```json
{
  "sensorId": "sensor-123",
  "sensorName": "Edge US-East",
  "state": "running",
  "activeConnections": 342,
  "isAccepting": true,
  "isOnline": true,
  "uptime": 604800,
  "lastHeartbeat": "2026-01-15T12:00:00Z",
  "lastReload": "2026-01-14T08:00:00Z"
}
```

### GET /api/v1/fleet-control/:sensorId/audit

Get the control command audit log for a sensor.

**Scope:** `sensor:admin`

### POST /api/v1/fleet-control/batch/control/:command

Execute a control command on multiple sensors simultaneously.

**Request Body:**

```json
{
  "sensorIds": ["sensor-1", "sensor-2", "sensor-3"],
  "reason": "Scheduled maintenance reload"
}
```

Maximum 50 sensors per batch request.

---

## Session Management API

Search and manage sessions across your sensor fleet.

**Base Path:** `/api/v1/fleet`

### GET /api/v1/fleet/sessions/search

Search sessions across all online sensors in parallel.

**Scope:** `fleet:read`

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `sessionId` | string | Specific session ID |
| `actorId` | string | Actor identifier |
| `clientIp` | string | Client IP address |
| `ja4Fingerprint` | string | JA4 TLS fingerprint |
| `userAgent` | string | User-Agent substring |
| `timeRangeStart` | ISO 8601 | Start of time range |
| `timeRangeEnd` | ISO 8601 | End of time range |
| `riskScoreMin` | number | Minimum risk score (0-100) |
| `blockedOnly` | boolean | Only blocked sessions |
| `limitPerSensor` | integer | Max results per sensor (default: 50, max: 500) |

### POST /api/v1/fleet/sessions/:sessionId/revoke

Revoke a session globally across all or specified sensors.

**Scope:** `fleet:write`

### POST /api/v1/fleet/actors/:actorId/ban

Ban an actor globally across the fleet.

**Scope:** `fleet:write`

**Request Body:**

```json
{
  "reason": "Credential stuffing campaign",
  "durationSeconds": 86400,
  "sensorIds": ["sensor-1", "sensor-2"]
}
```

---

## Security Considerations

- All remote operations are relayed through the hub's authenticated tunnel. Direct sensor access is not exposed.
- File browsing is restricted to paths defined in the sensor's allowlist. Path traversal attempts are blocked at the sensor level.
- All file access operations are logged for audit purposes, including the operator identity, path accessed, and operation result.
- Destructive service control commands require explicit confirmation tokens to prevent accidental execution.
- Session and actor management operations affect the live traffic handling on sensors. Use with caution in production.

## Common Error Codes

| HTTP Status | Description |
|-------------|-------------|
| 400 | Invalid parameters or cannot download directory |
| 404 | Sensor not found or offline |
| 428 | Confirmation token required for destructive commands |
| 502 | Tunnel communication error |
| 503 | Sensor offline or tunnel not connected |
| 504 | Operation timed out |
