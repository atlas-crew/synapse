# Synapse Rules Guide

This guide explains how to write and manage Synapse rules in Signal Horizon's Signal Array feature. The Synapse Proxy Service enables fleet operators to remotely manage security and monitoring rules on individual edge sensors.

## Overview

Synapse is the local decision engine running on each sensor. Through the Signal Array Synapse Proxy, you can:

- **List and manage entities**: Track IPs, fingerprints, sessions, and users
- **Create and manage blocks**: Block malicious actors
- **Define custom rules**: Create conditions and actions for traffic handling
- **Monitor actors**: Track behavior patterns and risk scores
- **Evaluate requests**: Test rule behavior before deployment

## Rule Structure

Each rule consists of:

```typescript
interface Rule {
  id: string;              // Auto-generated
  name: string;            // Human-readable name
  type: RuleType;          // BLOCK | CHALLENGE | RATE_LIMIT | MONITOR
  enabled: boolean;        // Active status
  priority: number;        // 0-1000, higher = evaluated first
  conditions: Condition[]; // Match criteria
  actions: Action[];       // What to do when matched
  hitCount: number;        // Number of matches
  createdAt: Date;
  updatedAt: Date;
}
```

## Conditions

Conditions define when a rule matches. Each condition has:

```typescript
interface Condition {
  field: string;           // What to check
  operator: Operator;      // How to compare
  value: unknown;          // What to compare against
}

type Operator = 'eq' | 'ne' | 'gt' | 'lt' | 'contains' | 'matches' | 'in';
```

### Available Fields

| Field | Type | Description |
|-------|------|-------------|
| `request.method` | string | HTTP method (GET, POST, etc.) |
| `request.path` | string | Request URL path |
| `request.query` | object | Query parameters |
| `request.headers` | object | Request headers |
| `request.body` | string | Request body |
| `client.ip` | string | Client IP address |
| `client.geo.country` | string | GeoIP country code |
| `client.geo.city` | string | GeoIP city |
| `client.fingerprint` | string | Browser fingerprint hash |
| `client.userAgent` | string | User-Agent header |
| `actor.type` | string | Actor classification |
| `actor.riskScore` | number | Risk score (0-100) |
| `session.id` | string | Session identifier |

### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Exact match | `{"field": "client.ip", "operator": "eq", "value": "192.168.1.1"}` |
| `ne` | Not equal | `{"field": "request.method", "operator": "ne", "value": "GET"}` |
| `gt` | Greater than | `{"field": "actor.riskScore", "operator": "gt", "value": 80}` |
| `lt` | Less than | `{"field": "actor.riskScore", "operator": "lt", "value": 20}` |
| `contains` | Substring match | `{"field": "request.path", "operator": "contains", "value": "/api"}` |
| `matches` | Regex match | `{"field": "client.userAgent", "operator": "matches", "value": "bot|crawler"}` |
| `in` | In list | `{"field": "client.geo.country", "operator": "in", "value": ["CN", "RU"]}` |

## Actions

Actions define what happens when conditions match:

```typescript
interface Action {
  type: ActionType;
  params?: Record<string, unknown>;
}

type ActionType = 'block' | 'challenge' | 'rate_limit' | 'tag' | 'log';
```

### Action Types

| Type | Description | Parameters |
|------|-------------|------------|
| `block` | Block the request | `reason`: string |
| `challenge` | Show CAPTCHA/JS challenge | `type`: 'captcha' \| 'js' |
| `rate_limit` | Apply rate limiting | `requests`, `period`, `action` |
| `tag` | Add a tag to the entity | `tag`: string |
| `log` | Log for monitoring | `level`: 'info' \| 'warn' \| 'alert' |

## Creating Rules

### Via API

```bash
curl -X POST https://your-signal-horizon.com/api/v1/synapse/sen_xxx/rules \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block High-Risk IPs",
    "type": "BLOCK",
    "enabled": true,
    "priority": 100,
    "conditions": [
      {
        "field": "actor.riskScore",
        "operator": "gt",
        "value": 90
      }
    ],
    "actions": [
      {
        "type": "block",
        "params": { "reason": "High risk score" }
      }
    ]
  }'
```

### Response

```json
{
  "id": "rule_abc123",
  "name": "Block High-Risk IPs",
  "type": "BLOCK",
  "enabled": true,
  "priority": 100,
  "conditions": [...],
  "actions": [...],
  "hitCount": 0,
  "createdAt": "2025-01-15T10:30:00Z",
  "updatedAt": "2025-01-15T10:30:00Z"
}
```

## Common Rule Patterns

### Geographic Blocking

Block traffic from specific countries:

```json
{
  "name": "Block Restricted Countries",
  "type": "BLOCK",
  "enabled": true,
  "priority": 200,
  "conditions": [
    {
      "field": "client.geo.country",
      "operator": "in",
      "value": ["KP", "IR", "SY"]
    }
  ],
  "actions": [
    {
      "type": "block",
      "params": { "reason": "Geographic restriction" }
    },
    {
      "type": "log",
      "params": { "level": "warn" }
    }
  ]
}
```

### Rate Limiting by Path

Apply rate limits to API endpoints:

```json
{
  "name": "API Rate Limit",
  "type": "RATE_LIMIT",
  "enabled": true,
  "priority": 150,
  "conditions": [
    {
      "field": "request.path",
      "operator": "contains",
      "value": "/api/"
    }
  ],
  "actions": [
    {
      "type": "rate_limit",
      "params": {
        "requests": 100,
        "period": 60,
        "action": "block"
      }
    }
  ]
}
```

### Challenge Suspicious Actors

Show CAPTCHA to suspicious traffic:

```json
{
  "name": "Challenge Suspicious Traffic",
  "type": "CHALLENGE",
  "enabled": true,
  "priority": 100,
  "conditions": [
    {
      "field": "actor.type",
      "operator": "eq",
      "value": "suspicious"
    }
  ],
  "actions": [
    {
      "type": "challenge",
      "params": { "type": "captcha" }
    }
  ]
}
```

### Bot Monitoring

Log and tag crawler traffic:

```json
{
  "name": "Monitor Crawlers",
  "type": "MONITOR",
  "enabled": true,
  "priority": 50,
  "conditions": [
    {
      "field": "client.userAgent",
      "operator": "matches",
      "value": "bot|crawler|spider|scraper"
    }
  ],
  "actions": [
    {
      "type": "tag",
      "params": { "tag": "crawler" }
    },
    {
      "type": "log",
      "params": { "level": "info" }
    }
  ]
}
```

### Fingerprint-Based Challenge

Challenge repeated fingerprints without session:

```json
{
  "name": "Challenge Fingerprint Abuse",
  "type": "CHALLENGE",
  "enabled": true,
  "priority": 120,
  "conditions": [
    {
      "field": "client.fingerprint",
      "operator": "ne",
      "value": null
    },
    {
      "field": "session.id",
      "operator": "eq",
      "value": null
    }
  ],
  "actions": [
    {
      "type": "challenge",
      "params": { "type": "js" }
    }
  ]
}
```

## Testing Rules

Before deploying rules, test them using the evaluate endpoint:

```bash
curl -X POST https://your-signal-horizon.com/api/v1/synapse/sen_xxx/evaluate \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "path": "/api/users",
    "headers": {
      "user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"
    },
    "clientIp": "66.249.66.1",
    "fingerprint": "abc123"
  }'
```

### Evaluation Response

```json
{
  "decision": "challenge",
  "matchedRules": [
    {
      "id": "rule_abc123",
      "name": "Challenge Suspicious Traffic",
      "actions": [
        { "type": "challenge", "params": { "type": "captcha" } }
      ]
    }
  ],
  "actor": {
    "type": "crawler",
    "riskScore": 45
  },
  "evaluationTime": 12
}
```

## Managing Rules

### List Rules

```bash
curl https://your-signal-horizon.com/api/v1/synapse/sen_xxx/rules \
  -H "Authorization: Bearer $API_KEY"
```

### Update a Rule

```bash
curl -X PUT https://your-signal-horizon.com/api/v1/synapse/sen_xxx/rules/rule_abc123 \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": false
  }'
```

### Delete a Rule

```bash
curl -X DELETE https://your-signal-horizon.com/api/v1/synapse/sen_xxx/rules/rule_abc123 \
  -H "Authorization: Bearer $API_KEY"
```

## Rule Priority

Rules are evaluated in priority order (highest first). When multiple rules match:

1. All matching rules' actions are collected
2. Actions are deduplicated by type
3. Most restrictive action wins (block > challenge > rate_limit > tag > log)

### Priority Guidelines

| Priority Range | Use Case |
|---------------|----------|
| 900-1000 | Emergency blocks, critical security |
| 700-899 | Compliance requirements |
| 400-699 | Standard security rules |
| 200-399 | Rate limiting, monitoring |
| 0-199 | Logging, tagging, analytics |

## Rule TTL (Time-To-Live)

Create temporary rules that auto-expire:

```bash
curl -X POST https://your-signal-horizon.com/api/v1/synapse/sen_xxx/rules \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Temporary Attack Block",
    "type": "BLOCK",
    "enabled": true,
    "priority": 950,
    "ttl": 3600,
    "conditions": [
      {
        "field": "client.ip",
        "operator": "eq",
        "value": "192.168.1.100"
      }
    ],
    "actions": [
      {
        "type": "block",
        "params": { "reason": "Active attack - temporary block" }
      }
    ]
  }'
```

The rule will automatically delete after `ttl` seconds.

## Fleet-Wide Rule Distribution

To apply rules across multiple sensors, iterate over your fleet:

```bash
# Get all sensor IDs
SENSORS=$(curl -s .../fleet/sensors | jq -r '.sensors[].id')

# Apply rule to each
for SENSOR_ID in $SENSORS; do
  curl -X POST ".../synapse/$SENSOR_ID/rules" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d @rule.json
done
```

Or use the Rule Distributor service for synchronized fleet-wide deployment.

## Best Practices

### Naming Conventions

- Use descriptive names: `"Block SQL Injection Patterns"`
- Include purpose: `"Rate Limit - Public API"`
- Add version if iterating: `"Geo Block v2"`

### Rule Organization

- Group related rules by priority bands
- Use consistent condition ordering
- Document complex regex patterns
- Test rules in staging before production

### Performance Considerations

- Put most selective conditions first
- Avoid overly complex regex patterns
- Use `eq` over `matches` when possible
- Monitor `hitCount` to identify hot rules

### Security Guidelines

- Start with monitoring (`MONITOR`) before blocking
- Review blocked requests before expanding rules
- Keep audit trail of rule changes
- Use TTL for incident response rules

## API Reference

### Rules Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/synapse/:sensorId/rules` | GET | List rules |
| `/api/v1/synapse/:sensorId/rules` | POST | Create rule |
| `/api/v1/synapse/:sensorId/rules/:ruleId` | PUT | Update rule |
| `/api/v1/synapse/:sensorId/rules/:ruleId` | DELETE | Delete rule |

### Evaluation Endpoint

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/synapse/:sensorId/evaluate` | POST | Test request against rules |

### Query Parameters

- `limit`: Max results (default 25, max 100)
- `offset`: Pagination offset
- `type`: Filter by rule type
- `enabled`: Filter by enabled status

## Next Steps

- **[API Key Management](./api-key-management.md)**: Secure your Synapse API access
- **[Sensor Onboarding](./sensor-onboarding.md)**: Add sensors to manage
- **[Remote Access](./remote-access.md)**: Access sensor dashboards for rule monitoring
