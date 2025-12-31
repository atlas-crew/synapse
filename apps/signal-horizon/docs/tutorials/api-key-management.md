# API Key Management Guide

This guide covers the complete lifecycle of sensor API keys in Signal Horizon's Signal Array fleet management system. Proper key management is critical for securing your fleet operations.

## Overview

Signal Array uses API keys for:

- **Sensor Authentication**: Sensors authenticate to Signal Horizon using API keys
- **API Access**: External systems integrate via API keys
- **Service-to-Service**: Internal services communicate securely

## Key Anatomy

API keys follow a structured format:

```
sk_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
│  │    └─────────────────────────────────┴ Random 32 bytes (base64url)
│  └─────────────────────────────────────── Environment (live/test)
└──────────────────────────────────────────  Key type (sk = secret key)
```

### Key Properties

| Property | Description |
|----------|-------------|
| `id` | Unique key identifier |
| `name` | Human-readable name |
| `keyPrefix` | First 8 characters (for identification) |
| `scopes` | Permissions granted |
| `sensorId` | Associated sensor (if sensor key) |
| `expiresAt` | Optional expiration date |
| `lastUsedAt` | Last activity timestamp |
| `createdAt` | Creation timestamp |
| `createdBy` | User who created the key |

## Generating Keys

### Via Dashboard

1. Navigate to **Management → API Keys**
2. Click **Generate New Key**
3. Enter key details:
   - **Name**: Descriptive identifier
   - **Scopes**: Select required permissions
   - **Expiration**: Optional expiry date
   - **Sensor**: Associate with specific sensor (optional)
4. Click **Generate**
5. **Copy the key immediately** - it won't be shown again

### Via API

```bash
curl -X POST https://your-signal-horizon.com/api/v1/management/keys \
  -H "Authorization: Bearer $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Sensor Key",
    "scopes": ["sensor:read", "sensor:write"],
    "sensorId": "sen_xxx",
    "expiresAt": "2026-01-01T00:00:00Z"
  }'
```

Response:
```json
{
  "id": "key_abc123",
  "key": "sk_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "name": "Production Sensor Key",
  "keyPrefix": "sk_live_",
  "scopes": ["sensor:read", "sensor:write"],
  "sensorId": "sen_xxx",
  "expiresAt": "2026-01-01T00:00:00Z",
  "createdAt": "2025-01-15T10:30:00Z",
  "message": "Save this key securely. It will not be shown again."
}
```

## Available Scopes

### Sensor Scopes

| Scope | Description |
|-------|-------------|
| `sensor:read` | Read sensor status and metrics |
| `sensor:write` | Update sensor configuration |
| `sensor:register` | Register new sensors |
| `sensor:delete` | Remove sensors |

### Fleet Scopes

| Scope | Description |
|-------|-------------|
| `fleet:read` | Read fleet overview and aggregations |
| `fleet:write` | Manage fleet-wide configurations |
| `fleet:admin` | Full fleet administrative access |

### Synapse Scopes

| Scope | Description |
|-------|-------------|
| `synapse:read` | Read entities, rules, actors |
| `synapse:write` | Create/update rules and blocks |

### Admin Scopes

| Scope | Description |
|-------|-------------|
| `admin` | Full administrative access |
| `keys:manage` | Create/revoke API keys |

### Principle of Least Privilege

Always grant the minimum scopes needed:

```bash
# ❌ Bad: Overly permissive
{
  "scopes": ["admin"]
}

# ✅ Good: Minimal permissions
{
  "scopes": ["sensor:read", "fleet:read"]
}
```

## Key Rotation

Regular key rotation is essential for security. Signal Array supports zero-downtime rotation.

### Rotation Workflow

```
1. Generate new key  ──▶  2. Deploy new key to sensor  ──▶  3. Verify connectivity
         │                         │                               │
         ▼                         ▼                               ▼
   Keep old key active      Both keys work              Old key can be revoked
```

### Step-by-Step Rotation

#### Step 1: Generate New Key

```bash
curl -X POST .../management/keys \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{
    "name": "Production Sensor Key (Jan 2025)",
    "scopes": ["sensor:read", "sensor:write"],
    "sensorId": "sen_xxx"
  }'
```

#### Step 2: Update Sensor Configuration

```bash
# On the sensor
sudo tee /etc/signal-horizon/sensor.conf > /dev/null << EOF
SENSOR_ID=sen_xxx
API_KEY=sk_live_NEW_KEY_HERE
SIGNAL_HORIZON_URL=wss://your-signal-horizon.com/ws/tunnel
EOF

sudo systemctl restart signal-horizon-sensor
```

#### Step 3: Verify Connectivity

```bash
# Check sensor status
curl https://your-signal-horizon.com/api/v1/fleet/sensors/sen_xxx \
  -H "Authorization: Bearer $API_KEY" | jq '.status'

# Should return "connected"
```

#### Step 4: Revoke Old Key

```bash
curl -X DELETE https://your-signal-horizon.com/api/v1/management/keys/key_OLD_ID \
  -H "Authorization: Bearer $ADMIN_KEY"
```

### Automated Rotation

For large fleets, automate key rotation:

```bash
#!/bin/bash
# rotate-keys.sh

SENSORS=$(curl -s .../fleet/sensors | jq -r '.sensors[].id')

for SENSOR_ID in $SENSORS; do
  # Generate new key
  NEW_KEY=$(curl -s -X POST .../management/keys \
    -d "{\"sensorId\": \"$SENSOR_ID\", \"name\": \"Auto-rotated $(date)\"}" \
    | jq -r '.key')

  # Deploy via configuration management (Ansible, etc.)
  ansible-playbook deploy-key.yml -e "sensor_id=$SENSOR_ID api_key=$NEW_KEY"

  # Verify and revoke old key after grace period
  sleep 60
  verify_sensor $SENSOR_ID && revoke_old_key $SENSOR_ID
done
```

## Bulk Key Operations

### List All Keys

```bash
curl https://your-signal-horizon.com/api/v1/management/keys \
  -H "Authorization: Bearer $ADMIN_KEY"
```

### Filter Keys

```bash
# Keys expiring soon
curl ".../management/keys?expiresBefore=2025-02-01"

# Keys for specific sensor
curl ".../management/keys?sensorId=sen_xxx"

# Inactive keys
curl ".../management/keys?lastUsedBefore=2024-12-01"
```

### Bulk Revocation

For incident response, revoke multiple keys:

```bash
# Revoke all keys for a compromised sensor
KEYS=$(curl -s ".../management/keys?sensorId=sen_xxx" | jq -r '.keys[].id')

for KEY_ID in $KEYS; do
  curl -X DELETE ".../management/keys/$KEY_ID" \
    -H "Authorization: Bearer $ADMIN_KEY"
done
```

## Incident Response

### Compromised Key Detection

Signs of a compromised key:

- Unusual API activity patterns
- Requests from unexpected IPs
- Failed authentication spikes
- Access outside normal hours

### Immediate Revocation

```bash
# Identify the compromised key
curl ".../management/keys?keyPrefix=sk_live_abc" \
  -H "Authorization: Bearer $ADMIN_KEY"

# Revoke immediately
curl -X DELETE ".../management/keys/key_xxx" \
  -H "Authorization: Bearer $ADMIN_KEY"
```

### Post-Incident Steps

1. **Revoke** the compromised key
2. **Audit** recent activity with that key
3. **Generate** new key with same scopes
4. **Deploy** new key to affected systems
5. **Monitor** for continued suspicious activity
6. **Document** the incident

### Audit Key Usage

```bash
# Get key activity
curl ".../management/keys/key_xxx/activity" \
  -H "Authorization: Bearer $ADMIN_KEY"
```

```json
{
  "keyId": "key_xxx",
  "recentActivity": [
    {
      "timestamp": "2025-01-15T10:30:00Z",
      "action": "sensor:heartbeat",
      "ip": "203.0.113.45",
      "userAgent": "signal-horizon-sensor/1.2.0"
    }
  ],
  "stats": {
    "requestsLast24h": 1440,
    "uniqueIps": 1,
    "failedAttempts": 0
  }
}
```

## Monitoring Key Health

### Expiration Alerts

Set up monitoring for expiring keys:

```bash
# Keys expiring in next 30 days
curl ".../management/keys?expiresBefore=$(date -d '+30 days' -Iseconds)" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  | jq '.keys[] | {name, expiresAt}'
```

### Usage Analytics

Track key usage patterns:

```bash
# Most active keys
curl ".../management/keys/analytics?sort=requestCount&order=desc" \
  -H "Authorization: Bearer $ADMIN_KEY"

# Unused keys (candidates for cleanup)
curl ".../management/keys?lastUsedBefore=$(date -d '-90 days' -Iseconds)" \
  -H "Authorization: Bearer $ADMIN_KEY"
```

### Anomaly Detection

Set thresholds for unusual activity:

```yaml
# alerting-rules.yml
- alert: APIKeyHighUsage
  expr: api_key_requests_per_minute > 100
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Unusual API key activity detected"

- alert: APIKeyFailedAuth
  expr: api_key_failed_auth_total > 10
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "Multiple failed authentication attempts"
```

## Storage Best Practices

### DO

- Store keys in secrets managers (HashiCorp Vault, AWS Secrets Manager)
- Use environment variables for configuration
- Set file permissions to `600` for config files
- Encrypt keys at rest

### DON'T

- Commit keys to version control
- Log key values (log key IDs instead)
- Share keys across environments
- Store keys in plaintext databases

### Environment Variables

```bash
# On sensor
export SIGNAL_HORIZON_API_KEY="sk_live_xxx"

# Or in systemd service
# /etc/systemd/system/signal-horizon-sensor.service
[Service]
EnvironmentFile=/etc/signal-horizon/sensor.env
```

### Secrets Manager Integration

```bash
# AWS Secrets Manager
aws secretsmanager get-secret-value \
  --secret-id signal-horizon/sensor-key \
  --query SecretString --output text

# HashiCorp Vault
vault kv get -field=api_key secret/signal-horizon/sensor
```

## API Reference

### Key Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/management/keys` | GET | List all keys |
| `/api/v1/management/keys` | POST | Generate new key |
| `/api/v1/management/keys/:id` | GET | Get key details |
| `/api/v1/management/keys/:id` | DELETE | Revoke key |
| `/api/v1/management/keys/:id/activity` | GET | Key usage activity |

### Query Parameters

| Parameter | Description |
|-----------|-------------|
| `sensorId` | Filter by associated sensor |
| `expiresBefore` | Keys expiring before date |
| `lastUsedBefore` | Keys unused since date |
| `scope` | Filter by scope |

## Security Checklist

- [ ] Keys have minimal required scopes
- [ ] Keys have appropriate expiration dates
- [ ] Keys are stored in secrets manager
- [ ] Rotation schedule is defined
- [ ] Monitoring alerts are configured
- [ ] Revocation procedures are documented
- [ ] Audit logging is enabled

## Next Steps

- **[Sensor Onboarding](./sensor-onboarding.md)**: Use keys to register sensors
- **[Remote Access](./remote-access.md)**: Authenticate tunnel connections
- **[Synapse Rules](./synapse-rules.md)**: Secure API access with rules
