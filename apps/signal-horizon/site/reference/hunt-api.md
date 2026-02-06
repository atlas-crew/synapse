# Hunt API Reference

The Hunt API provides endpoints for time-based threat hunting across your signal data. Queries are automatically routed between PostgreSQL (recent data) and ClickHouse (historical data) based on the time range.

## Base URL

```
/api/v1/hunt
```

## Authentication

All hunt endpoints require a Bearer token:

```
Authorization: Bearer <api-key>
```

### Required Scopes

| Scope | Access Level |
|-------|-------------|
| `hunt:read` | Check hunt status, view saved queries |
| `hunt:write` | Create and delete saved queries |
| `hunt:execute` | Execute saved queries |
| `admin` (role) | Cross-tenant IP activity lookups |

## Rate Limits

| Endpoint Category | Limit |
|-------------------|-------|
| Hunt queries | 100 requests/minute |
| Saved queries | 30 requests/minute |
| Heavy aggregations (hourly stats, IP activity) | 10 requests/minute |

Rate limit headers are included in responses:

- `X-RateLimit-Limit` -- Maximum requests allowed
- `X-RateLimit-Remaining` -- Requests remaining in window
- `X-RateLimit-Reset` -- Window reset timestamp
- `Retry-After` -- Seconds to wait (on 429 responses)

---

## Endpoints

### GET /api/v1/hunt/status

Check whether historical hunting (ClickHouse) is available.

**Response:**

```json
{
  "historical": true,
  "routingThreshold": "24h",
  "description": "Historical queries via ClickHouse enabled"
}
```

When ClickHouse is disabled, `historical` is `false` and queries are limited to PostgreSQL.

---

### POST /api/v1/hunt/query

Query the signal timeline with automatic time-based routing.

- Queries within the last 24 hours route to PostgreSQL.
- Queries older than 24 hours route to ClickHouse.
- Mixed ranges are split and merged automatically.

**Request Body:**

```json
{
  "startTime": "2026-01-14T00:00:00Z",
  "endTime": "2026-01-15T00:00:00Z",
  "signalTypes": ["IP_THREAT", "BOT_SIGNATURE"],
  "sourceIps": ["192.168.1.100"],
  "severities": ["HIGH", "CRITICAL"],
  "minConfidence": 0.8,
  "limit": 1000,
  "offset": 0
}
```

**Query Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `startTime` | ISO 8601 | yes | Start of time range |
| `endTime` | ISO 8601 | yes | End of time range |
| `signalTypes` | string[] | no | Filter by signal type |
| `sourceIps` | string[] | no | Filter by source IP |
| `severities` | string[] | no | Filter by severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `minConfidence` | number | no | Minimum confidence score (0.0-1.0) |
| `anonFingerprint` | string | no | 64-character anonymized fingerprint hash |
| `limit` | integer | no | Max results (1-10000, default: 1000) |
| `offset` | integer | no | Pagination offset (default: 0) |

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "id": "sig-123",
      "timestamp": "2026-01-14T12:30:00Z",
      "tenantId": "tenant-abc",
      "sensorId": "sensor-123",
      "signalType": "IP_THREAT",
      "sourceIp": "192.168.1.100",
      "severity": "HIGH",
      "confidence": 0.92,
      "eventCount": 15
    }
  ],
  "meta": {
    "total": 1200,
    "source": "postgres",
    "queryTimeMs": 42,
    "limit": 1000,
    "offset": 0
  }
}
```

The `source` field indicates which backend served the query: `postgres`, `clickhouse`, or `hybrid`.

---

### GET /api/v1/hunt/timeline/:campaignId

Retrieve the event timeline for a specific campaign. Requires ClickHouse.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `startTime` | ISO 8601 | no | Start of time range |
| `endTime` | ISO 8601 | no | End of time range |

Returns HTTP 503 if ClickHouse is disabled.

---

### GET /api/v1/hunt/stats/hourly

Get hourly aggregated statistics. Requires ClickHouse.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `startTime` | ISO 8601 | no | Start of time range |
| `endTime` | ISO 8601 | no | End of time range |
| `signalTypes` | string[] | no | Filter by signal types |

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "hour": "2026-01-14T12:00:00Z",
      "tenantId": "tenant-abc",
      "signalType": "IP_THREAT",
      "severity": "HIGH",
      "signalCount": 100,
      "totalEvents": 120,
      "uniqueIps": 20,
      "uniqueFingerprints": 5
    }
  ],
  "meta": { "count": 24 }
}
```

---

### POST /api/v1/hunt/ip-activity

Get activity summary for a specific IP address across all tenants. Restricted to administrators.

**Role required:** `admin`

**Request Body:**

```json
{
  "sourceIp": "203.0.113.50",
  "days": 30
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sourceIp` | string (IP) | yes | IP address to investigate |
| `days` | integer | no | Lookback period in days (1-365, default: 30) |

---

## Saved Queries

Saved queries allow you to store and re-execute hunt queries. Saved queries are currently stored in memory and reset on service restart.

### GET /api/v1/hunt/saved-queries

List all saved queries. Optionally filter by `createdBy` query parameter.

**Scope:** `hunt:read`

### POST /api/v1/hunt/saved-queries

Create a new saved query.

**Scope:** `hunt:write`

**Request Body:**

```json
{
  "name": "High-severity IP threats last 24h",
  "description": "Finds critical IP-based threats from the last day",
  "query": {
    "startTime": "2026-01-14T00:00:00Z",
    "endTime": "2026-01-15T00:00:00Z",
    "signalTypes": ["IP_THREAT"],
    "severities": ["HIGH", "CRITICAL"],
    "minConfidence": 0.8
  }
}
```

### GET /api/v1/hunt/saved-queries/:id

Retrieve a specific saved query by ID.

**Scope:** `hunt:read`

### POST /api/v1/hunt/saved-queries/:id/run

Execute a saved query. The query runs in the context of your authenticated tenant, regardless of any tenant ID stored in the query.

**Scope:** `hunt:execute`

### DELETE /api/v1/hunt/saved-queries/:id

Delete a saved query.

**Scope:** `hunt:write` | **Role:** `operator`

---

## Signal Types

| Signal Type | Description |
|-------------|-------------|
| `IP_THREAT` | IP-based threat detection |
| `FINGERPRINT_THREAT` | Browser/TLS fingerprint threat |
| `CAMPAIGN_INDICATOR` | Part of a correlated attack campaign |
| `CREDENTIAL_STUFFING` | Credential abuse attempt |
| `RATE_ANOMALY` | Unusual request rate pattern |
| `BOT_SIGNATURE` | Automated bot behavior |
| `IMPOSSIBLE_TRAVEL` | Geographically impossible access |

## Common Error Codes

| HTTP Status | Description |
|-------------|-------------|
| 400 | Invalid query parameters |
| 401 | Authentication required |
| 403 | Insufficient permissions |
| 404 | Saved query not found |
| 429 | Rate limit exceeded |
| 500 | Query execution failed |
| 503 | ClickHouse not available (for historical endpoints) |
