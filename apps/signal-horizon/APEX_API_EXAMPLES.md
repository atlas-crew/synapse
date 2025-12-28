# Apex API Examples

This document provides example API requests and responses for the Apex Customer Protection Console endpoints.

## Authentication

All requests require a valid API key in the `Authorization` header:

```bash
Authorization: Bearer <your-api-key>
```

The API key determines the tenant context for all operations.

---

## Dashboard

### Get Dashboard Summary

```bash
GET /api/v1/apex/dashboard
```

**Response:**
```json
{
  "status": "protected",
  "summary": {
    "totalEndpoints": 47,
    "totalRules": 12,
    "activeRules": 8,
    "blocks24h": 156
  }
}
```

---

## Endpoints

### List Discovered Endpoints

```bash
GET /api/v1/apex/endpoints
```

**Response:**
```json
{
  "endpoints": [
    {
      "id": "clx123abc",
      "tenantId": "clx456def",
      "sensorId": "clx789ghi",
      "method": "POST",
      "path": "/api/v2/users/login",
      "pathTemplate": "/api/v2/users/login",
      "service": "auth-service",
      "firstSeenAt": "2025-12-20T10:00:00Z",
      "lastSeenAt": "2025-12-22T20:45:00Z",
      "requestCount": 1247,
      "hasSchema": true,
      "schemaVersion": "v1.0",
      "schemaHash": "sha256:abc123...",
      "avgLatencyMs": 45.2,
      "p95LatencyMs": 89.1,
      "p99LatencyMs": 142.3,
      "errorRate": 0.02,
      "riskLevel": "medium",
      "authRequired": true,
      "sensitiveData": true,
      "sensor": {
        "id": "clx789ghi",
        "name": "prod-sensor-01"
      },
      "_count": {
        "schemaChanges": 3,
        "ruleBindings": 2
      }
    }
  ]
}
```

### Get Endpoint Details

```bash
GET /api/v1/apex/endpoints/:id
```

**Response:**
```json
{
  "endpoint": {
    "id": "clx123abc",
    "tenantId": "clx456def",
    "sensorId": "clx789ghi",
    "method": "POST",
    "path": "/api/v2/users/login",
    "pathTemplate": "/api/v2/users/login",
    "service": "auth-service",
    "firstSeenAt": "2025-12-20T10:00:00Z",
    "lastSeenAt": "2025-12-22T20:45:00Z",
    "requestCount": 1247,
    "hasSchema": true,
    "schemaVersion": "v1.0",
    "schemaHash": "sha256:abc123...",
    "requestSchema": {
      "type": "object",
      "properties": {
        "username": { "type": "string" },
        "password": { "type": "string" }
      },
      "required": ["username", "password"]
    },
    "responseSchema": {
      "type": "object",
      "properties": {
        "token": { "type": "string" },
        "userId": { "type": "string" }
      }
    },
    "avgLatencyMs": 45.2,
    "p95LatencyMs": 89.1,
    "p99LatencyMs": 142.3,
    "errorRate": 0.02,
    "riskLevel": "medium",
    "authRequired": true,
    "sensitiveData": true,
    "sensor": {
      "id": "clx789ghi",
      "name": "prod-sensor-01",
      "version": "2.1.0"
    },
    "schemaChanges": [
      {
        "id": "clx999zzz",
        "endpointId": "clx123abc",
        "tenantId": "clx456def",
        "changeType": "field_added",
        "field": "mfaToken",
        "oldValue": null,
        "newValue": "string",
        "riskLevel": "low",
        "previousHash": "sha256:old123...",
        "currentHash": "sha256:new456...",
        "detectedAt": "2025-12-21T14:30:00Z"
      }
    ],
    "ruleBindings": [
      {
        "id": "clx888yyy",
        "ruleId": "clx777xxx",
        "endpointId": "clx123abc",
        "tenantId": "clx456def",
        "bindingType": "include",
        "createdAt": "2025-12-20T12:00:00Z",
        "rule": {
          "id": "clx777xxx",
          "name": "Rate Limit Login Attempts",
          "enabled": true
        }
      }
    ]
  }
}
```

---

## Rules

### List Customer Rules

```bash
GET /api/v1/apex/rules
```

**Response:**
```json
{
  "rules": [
    {
      "id": "clx777xxx",
      "tenantId": "clx456def",
      "name": "Rate Limit Login Attempts",
      "description": "Block IPs with >10 failed login attempts in 5 minutes",
      "category": "rate_limiting",
      "severity": "high",
      "action": "block",
      "patterns": {
        "type": "rate_limit",
        "path_pattern": "/api/*/login",
        "max_requests": 10,
        "window_seconds": 300,
        "response_code": 401
      },
      "sensitivity": 75,
      "enabled": true,
      "status": "deployed",
      "rolloutStrategy": "immediate",
      "totalSensors": 5,
      "deployedSensors": 5,
      "failedSensors": 0,
      "triggers24h": 23,
      "lastTriggered": "2025-12-22T19:30:00Z",
      "createdAt": "2025-12-20T08:00:00Z",
      "updatedAt": "2025-12-22T20:00:00Z",
      "deployedAt": "2025-12-20T08:05:00Z",
      "createdBy": "admin@example.com",
      "_count": {
        "deployments": 5,
        "endpointBindings": 3
      }
    }
  ]
}
```

### Get Rule Details

```bash
GET /api/v1/apex/rules/:id
```

**Response:**
```json
{
  "rule": {
    "id": "clx777xxx",
    "tenantId": "clx456def",
    "name": "Rate Limit Login Attempts",
    "description": "Block IPs with >10 failed login attempts in 5 minutes",
    "category": "rate_limiting",
    "severity": "high",
    "action": "block",
    "patterns": {
      "type": "rate_limit",
      "path_pattern": "/api/*/login",
      "max_requests": 10,
      "window_seconds": 300,
      "response_code": 401
    },
    "sensitivity": 75,
    "enabled": true,
    "status": "deployed",
    "rolloutStrategy": "immediate",
    "totalSensors": 5,
    "deployedSensors": 5,
    "failedSensors": 0,
    "triggers24h": 23,
    "lastTriggered": "2025-12-22T19:30:00Z",
    "createdAt": "2025-12-20T08:00:00Z",
    "updatedAt": "2025-12-22T20:00:00Z",
    "deployedAt": "2025-12-20T08:05:00Z",
    "createdBy": "admin@example.com",
    "deployments": [
      {
        "id": "clx111aaa",
        "ruleId": "clx777xxx",
        "sensorId": "clx789ghi",
        "tenantId": "clx456def",
        "status": "synced",
        "error": null,
        "attempts": 1,
        "queuedAt": "2025-12-20T08:05:00Z",
        "startedAt": "2025-12-20T08:05:10Z",
        "completedAt": "2025-12-20T08:05:15Z",
        "sensor": {
          "id": "clx789ghi",
          "name": "prod-sensor-01",
          "connectionState": "CONNECTED"
        }
      }
    ],
    "endpointBindings": [
      {
        "id": "clx888yyy",
        "ruleId": "clx777xxx",
        "endpointId": "clx123abc",
        "tenantId": "clx456def",
        "bindingType": "include",
        "createdAt": "2025-12-20T12:00:00Z",
        "endpoint": {
          "id": "clx123abc",
          "method": "POST",
          "pathTemplate": "/api/v2/users/login",
          "service": "auth-service"
        }
      }
    ]
  }
}
```

### Create Custom Rule

```bash
POST /api/v1/apex/rules
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "Block SQL Injection Attempts",
  "description": "Detect and block SQL injection patterns in query parameters",
  "category": "injection",
  "severity": "critical",
  "action": "block",
  "patterns": {
    "type": "regex",
    "param_patterns": [
      "(?i)(union.*select|select.*from|insert.*into|drop.*table|delete.*from)",
      "(?i)(exec\\s*\\(|execute\\s*\\(|script\\s*\\>)"
    ],
    "locations": ["query", "body", "headers"]
  },
  "sensitivity": 90
}
```

**Response:**
```json
{
  "rule": {
    "id": "clx222bbb",
    "tenantId": "clx456def",
    "name": "Block SQL Injection Attempts",
    "description": "Detect and block SQL injection patterns in query parameters",
    "category": "injection",
    "severity": "critical",
    "action": "block",
    "patterns": {
      "type": "regex",
      "param_patterns": [
        "(?i)(union.*select|select.*from|insert.*into|drop.*table|delete.*from)",
        "(?i)(exec\\s*\\(|execute\\s*\\(|script\\s*\\>)"
      ],
      "locations": ["query", "body", "headers"]
    },
    "exclusions": null,
    "sensitivity": 90,
    "enabled": true,
    "status": "draft",
    "rolloutStrategy": "immediate",
    "rolloutConfig": null,
    "totalSensors": 0,
    "deployedSensors": 0,
    "failedSensors": 0,
    "triggers24h": 0,
    "lastTriggered": null,
    "createdAt": "2025-12-22T20:50:00Z",
    "updatedAt": "2025-12-22T20:50:00Z",
    "deployedAt": null,
    "createdBy": null
  }
}
```

---

## Threats

### List Block Decisions

```bash
GET /api/v1/apex/threats?limit=20&offset=0
```

**Response:**
```json
{
  "blocks": [
    {
      "id": "clx333ccc",
      "tenantId": "clx456def",
      "sensorId": "clx789ghi",
      "blockId": "block-20251222-001",
      "entityId": "entity-192.168.1.100",
      "sourceIp": "192.168.1.100",
      "mode": "block",
      "ruleId": "clx777xxx",
      "ruleName": "Rate Limit Login Attempts",
      "reason": "Exceeded rate limit: 15 requests in 300 seconds",
      "riskScore": 85,
      "requestMethod": "POST",
      "requestPath": "/api/v2/users/login",
      "requestHeaders": {
        "user-agent": "Mozilla/5.0...",
        "content-type": "application/json"
      },
      "entityState": {
        "request_count": 15,
        "window_start": "2025-12-22T20:30:00Z",
        "failed_attempts": 15,
        "success_attempts": 0
      },
      "matchedRules": [
        {
          "ruleId": "clx777xxx",
          "ruleName": "Rate Limit Login Attempts",
          "confidence": 1.0
        }
      ],
      "decidedAt": "2025-12-22T20:35:00Z",
      "createdAt": "2025-12-22T20:35:01Z",
      "sensor": {
        "id": "clx789ghi",
        "name": "prod-sensor-01"
      }
    }
  ],
  "pagination": {
    "total": 156,
    "limit": 20,
    "offset": 0,
    "hasMore": true
  }
}
```

### Get Block Decision Details

```bash
GET /api/v1/apex/threats/:id
```

**Response:**
```json
{
  "block": {
    "id": "clx333ccc",
    "tenantId": "clx456def",
    "sensorId": "clx789ghi",
    "blockId": "block-20251222-001",
    "entityId": "entity-192.168.1.100",
    "sourceIp": "192.168.1.100",
    "mode": "block",
    "ruleId": "clx777xxx",
    "ruleName": "Rate Limit Login Attempts",
    "reason": "Exceeded rate limit: 15 requests in 300 seconds",
    "riskScore": 85,
    "requestMethod": "POST",
    "requestPath": "/api/v2/users/login",
    "requestHeaders": {
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "content-type": "application/json",
      "accept": "application/json",
      "origin": "https://example.com"
    },
    "entityState": {
      "request_count": 15,
      "window_start": "2025-12-22T20:30:00Z",
      "window_end": "2025-12-22T20:35:00Z",
      "failed_attempts": 15,
      "success_attempts": 0,
      "unique_usernames": ["admin", "root", "administrator", "user"],
      "credential_stuffing_score": 0.92
    },
    "matchedRules": [
      {
        "ruleId": "clx777xxx",
        "ruleName": "Rate Limit Login Attempts",
        "severity": "high",
        "confidence": 1.0,
        "matched_at": "2025-12-22T20:35:00Z"
      }
    ],
    "decidedAt": "2025-12-22T20:35:00Z",
    "createdAt": "2025-12-22T20:35:01Z",
    "sensor": {
      "id": "clx789ghi",
      "name": "prod-sensor-01",
      "version": "2.1.0"
    }
  }
}
```

---

## Error Responses

### Unauthorized (401)

```json
{
  "error": "Unauthorized"
}
```

### Not Found (404)

```json
{
  "error": "Endpoint not found"
}
```

### Bad Request (400)

```json
{
  "error": "Missing required fields: name, patterns"
}
```

### Internal Server Error (500)

```json
{
  "error": "Internal server error"
}
```

---

## Notes

1. All timestamps are in ISO 8601 format (UTC)
2. All IDs are CUID format (e.g., `clx123abc`)
3. The `patterns` field in rules is flexible JSON - structure depends on rule category
4. Block decisions include full request context for forensic analysis
5. Pagination is available on list endpoints via `limit` and `offset` query parameters
6. All responses include appropriate HTTP status codes
