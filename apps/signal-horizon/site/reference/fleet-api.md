# Fleet Management API Reference

The Fleet Management API provides endpoints for managing your Synapse sensor fleet, including sensor monitoring, configuration templates, command dispatch, and rule distribution.

## Base URL

```
/api/v1/fleet
```

## Authentication

All fleet endpoints require a Bearer token in the `Authorization` header:

```
Authorization: Bearer <api-key>
```

### Required Scopes

| Scope | Access Level |
|-------|-------------|
| `fleet:read` | List sensors, view metrics, command history, rule status |
| `fleet:write` | Send commands, push rules, cancel commands |
| `config:read` | View configuration templates |
| `config:write` | Create, update, delete, and push configuration templates |

Write operations additionally require the `operator` role. Template deletion requires the `admin` role.

## Rate Limiting

Fleet command endpoints are rate-limited. When limits are exceeded, the API returns HTTP 429 with a `Retry-After` header.

---

## Fleet Overview

### GET /api/v1/fleet

Returns fleet-wide aggregated metrics.

**Scope:** `fleet:read`

**Response:**

```json
{
  "totalSensors": 10,
  "onlineSensors": 9,
  "offlineSensors": 1,
  "totalRps": 12500,
  "avgLatency": 18.4,
  "healthScore": 90.0,
  "avgCpu": 44.1,
  "avgMemory": 62.3,
  "avgDisk": 41.8,
  "timestamp": "2026-01-15T12:00:00Z"
}
```

### GET /api/v1/fleet/overview

Returns a comprehensive fleet overview with regional breakdown, version distribution, and recent alerts.

**Scope:** `fleet:read`

### GET /api/v1/fleet/alerts

Returns sensors requiring attention and recent failed commands from the last 24 hours.

**Scope:** `fleet:read`

---

## Sensor Management

### GET /api/v1/fleet/sensors

List all sensors with filtering, sorting, and pagination.

**Scope:** `fleet:read`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | - | Filter by status: `online`, `warning`, `offline`, `CONNECTED`, `DISCONNECTED`, `RECONNECTING` |
| `region` | string | - | Filter by region |
| `version` | string | - | Filter by sensor version |
| `search` | string | - | Search by sensor name (case-insensitive) |
| `sort` | string | `lastHeartbeat` | Sort field: `name`, `status`, `cpu`, `memory`, `rps`, `latency`, `version`, `region`, `lastHeartbeat` |
| `sortDir` | string | `asc` | Sort direction: `asc` or `desc` |
| `limit` | integer | 50 | Results per page (1-100) |
| `offset` | integer | 0 | Pagination offset |

**Response:**

```json
{
  "sensors": [
    {
      "id": "sensor-123",
      "name": "Edge Sensor US-East",
      "connectionState": "CONNECTED",
      "version": "1.2.3",
      "region": "us-east-1",
      "lastHeartbeat": "2026-01-15T12:00:00Z"
    }
  ],
  "pagination": { "total": 10, "limit": 50, "offset": 0 }
}
```

### GET /api/v1/fleet/sensors/:sensorId

Returns detailed information about a specific sensor, including its 10 most recent commands.

**Scope:** `fleet:read`

### GET /api/v1/fleet/sensors/:sensorId/system

Returns system information for a sensor (OS, kernel, IP addresses, architecture, uptime).

**Scope:** `fleet:read`

### GET /api/v1/fleet/sensors/:sensorId/performance

Returns live performance metrics reported by the sensor. Metric fields may be `null` until the sensor emits them, and historical collections stay empty until a time-series telemetry source is wired into the fleet API.

**Scope:** `fleet:read`

### GET /api/v1/fleet/sensors/:sensorId/network

Returns network information (traffic rates, interfaces, active connections, DNS).

**Scope:** `fleet:read`

### GET /api/v1/fleet/sensors/:sensorId/logs

Returns log entries from ClickHouse for a sensor.

**Scope:** `fleet:read`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `type` | string | `access` | Log type: `access`, `error`, `system`, `waf` |
| `limit` | integer | 100 | Maximum entries (1-500) |

### POST /api/v1/fleet/sensors/:sensorId/actions/restart

Send a restart command to a sensor.

**Scope:** `fleet:write` | **Role:** `operator`

---

## Configuration Templates

### GET /api/v1/fleet/config/templates

List all configuration templates for your tenant.

**Scope:** `config:read`

### POST /api/v1/fleet/config/templates

Create a new configuration template.

**Scope:** `config:write` | **Role:** `operator`

**Request Body:**

```json
{
  "name": "Production WAF Config",
  "description": "Standard production configuration",
  "environment": "production",
  "config": {
    "waf_threshold": 70,
    "rate_limit_rps": 10000,
    "block_mode": "block"
  }
}
```

### PUT /api/v1/fleet/config/templates/:id

Update an existing template. Accepts partial updates.

**Scope:** `config:write` | **Role:** `operator`

### DELETE /api/v1/fleet/config/templates/:id

Delete a configuration template.

**Scope:** `config:write` | **Role:** `admin`

### POST /api/v1/fleet/config/push

Push a configuration template to one or more sensors.

**Scope:** `config:write` | **Role:** `operator`

**Request Body:**

```json
{
  "templateId": "template-uuid",
  "sensorIds": ["sensor-1", "sensor-2"]
}
```

**Response (202 Accepted):**

```json
{
  "message": "Configuration push initiated",
  "commands": [{ "id": "cmd-1", "sensorId": "sensor-1", "status": "pending" }]
}
```

### GET /api/v1/fleet/config/sync-status

Returns configuration sync status across all sensors.

**Scope:** `config:read`

### GET /api/v1/fleet/config/audit

Returns recent configuration audit events (create, update, delete actions).

**Scope:** `config:read`

---

## Command Management

### GET /api/v1/fleet/commands

List command history with optional status filtering.

**Scope:** `fleet:read`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | - | Filter by status: `pending`, `sent`, `success`, `failed`, `timeout` |
| `limit` | integer | 50 | Results per page (max 100) |
| `offset` | integer | 0 | Pagination offset |

### POST /api/v1/fleet/commands

Send a command to one or more sensors.

**Scope:** `fleet:write` | **Role:** `operator`

**Request Body:**

```json
{
  "commandType": "push_config",
  "sensorIds": ["sensor-uuid-1", "sensor-uuid-2"],
  "payload": {
    "templateId": "template-uuid",
    "config": { "waf_threshold": 60 }
  }
}
```

**Valid Command Types:**

| Type | Description |
|------|-------------|
| `push_config` | Push configuration to sensors |
| `push_rules` | Deploy WAF rules |
| `update` | Firmware/software update |
| `restart` | Restart sensor services |
| `sync_blocklist` | Synchronize blocklists |

### GET /api/v1/fleet/commands/:commandId

Get the status of a specific command.

**Scope:** `fleet:read`

### POST /api/v1/fleet/commands/:commandId/cancel

Cancel a pending command. Only commands with `pending` status can be cancelled.

**Scope:** `fleet:write` | **Role:** `operator`

---

## Rule Distribution

### GET /api/v1/fleet/rules/status

Returns rule sync status for all sensors in your tenant.

**Scope:** `fleet:read`

### POST /api/v1/fleet/rules/push

Push rules to sensors with a deployment strategy.

**Scope:** `fleet:write` | **Role:** `operator`

**Request Body:**

```json
{
  "ruleIds": ["rule-uuid-1", "rule-uuid-2"],
  "sensorIds": ["sensor-uuid-1"],
  "strategy": "rolling",
  "rollingBatchSize": 2,
  "healthCheckTimeout": 30000,
  "maxFailuresBeforeAbort": 3,
  "rollbackOnFailure": true
}
```

**Deployment Strategies:**

| Strategy | Description |
|----------|-------------|
| `immediate` | Push to all sensors at once (default) |
| `canary` | Gradual rollout by percentage |
| `scheduled` | Deploy at a specific future time |
| `rolling` | Deploy in batches with health checks |
| `blue_green` | Stage to all sensors, then atomic switch |

### POST /api/v1/fleet/rules/retry/:sensorId

Retry failed rule deployments for a specific sensor.

**Scope:** `fleet:write`

---

## Common Error Codes

| HTTP Status | Error | Description |
|-------------|-------|-------------|
| 400 | Invalid request | Malformed request body or parameters |
| 401 | Unauthorized | Missing or invalid API key |
| 403 | Forbidden | Insufficient scopes or role |
| 404 | Not found | Sensor, command, or template not found |
| 409 | Conflict | Command type disabled |
| 429 | Too many requests | Rate limit exceeded |
| 500 | Internal error | Server-side failure |
| 503 | Service unavailable | Required service (aggregator, config manager) not available |
