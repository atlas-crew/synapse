# Sensor Onboarding Guide

This guide walks you through connecting your first sensor to Signal Horizon's Signal Array fleet management system.

## Overview

Signal Array supports three onboarding methods, each suited for different deployment scenarios:

| Method | Best For | Security | Setup Speed |
|--------|----------|----------|-------------|
| Agent Script | Quick deployments | Good | Fast |
| Manual Registration | Maximum control | Excellent | Moderate |
| Auto-Discovery | Zero-touch deployments | Good | Fast |

## Prerequisites

Before onboarding a sensor, ensure you have:

- A Signal Horizon account with `fleet:write` permissions
- Network connectivity from the sensor to Signal Horizon (outbound HTTPS on port 443)
- The sensor software installed on your edge device

## Method 1: Agent Script (Recommended)

The agent script method provides fast, automated deployment using one-liner commands.

### Step 1: Generate a Registration Token

```bash
# Via API
curl -X POST https://your-signal-horizon.com/api/v1/onboarding/tokens \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Fleet Token",
    "maxUses": 50,
    "expiresIn": 30,
    "region": "us-east-1"
  }'
```

Response:
```json
{
  "token": "sh_reg_xxxxxxxxxxxxxxxxxxxxx",
  "id": "tok_abc123",
  "name": "Production Fleet Token",
  "maxUses": 50,
  "expiresAt": "2025-01-30T00:00:00Z",
  "message": "Save this token securely. It will not be shown again."
}
```

### Step 2: Run on Your Sensor

```bash
# One-liner installation
curl -sSL https://your-signal-horizon.com/api/v1/fleet/onboarding/script | \
  REGISTRATION_TOKEN="sh_reg_xxxxxxxxxxxxxxxxxxxxx" bash
```

The script will:
1. Validate the registration token
2. Generate sensor credentials
3. Configure the sensor agent
4. Establish the WebSocket tunnel to Signal Horizon
5. Report success/failure

### Step 3: Verify Connection

Check the Fleet Overview page or use the API:

```bash
curl https://your-signal-horizon.com/api/v1/fleet/sensors \
  -H "Authorization: Bearer $API_KEY"
```

## Method 2: Manual Registration

Manual registration provides maximum security with explicit control over each step.

### Step 1: Create Sensor in Dashboard

1. Navigate to **Fleet → Add Sensor**
2. Fill in sensor details:
   - **Name**: Descriptive name (e.g., "edge-us-east-1-prod-01")
   - **Region**: Deployment region
   - **Tags**: Optional metadata tags
3. Click **Create Sensor**
4. Copy the generated credentials

### Step 2: Configure Sensor

Create the configuration file on your sensor:

```bash
sudo mkdir -p /etc/signal-horizon
sudo chmod 700 /etc/signal-horizon

sudo tee /etc/signal-horizon/sensor.conf > /dev/null << EOF
SENSOR_ID=sen_xxxxxxxxxxxxx
API_KEY=sk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SIGNAL_HORIZON_URL=wss://your-signal-horizon.com/ws/tunnel
CAPABILITIES=shell,dashboard
EOF

sudo chmod 600 /etc/signal-horizon/sensor.conf
```

### Step 3: Start the Sensor Agent

```bash
sudo systemctl enable signal-horizon-sensor
sudo systemctl start signal-horizon-sensor

# Verify status
sudo systemctl status signal-horizon-sensor
journalctl -u signal-horizon-sensor -f
```

## Method 3: Auto-Discovery

Auto-discovery enables zero-touch deployments where sensors announce themselves for approval.

### Step 1: Enable Auto-Discovery Mode

Configure sensors to start in discovery mode:

```bash
# /etc/signal-horizon/sensor.conf
DISCOVERY_MODE=true
DISCOVERY_TOKEN=sh_disc_xxxxxxxxxxxxxxxxxxxxx
SIGNAL_HORIZON_URL=wss://your-signal-horizon.com/ws/tunnel
```

### Step 2: Approve Pending Sensors

Sensors in discovery mode appear in the pending approvals queue:

```bash
# List pending sensors
curl https://your-signal-horizon.com/api/v1/onboarding/pending \
  -H "Authorization: Bearer $API_KEY"
```

```json
{
  "sensors": [
    {
      "id": "sen_pending_abc123",
      "hostname": "edge-server-01",
      "publicIp": "203.0.113.45",
      "region": "us-east-1",
      "version": "1.2.0",
      "createdAt": "2025-01-15T10:30:00Z"
    }
  ],
  "total": 1
}
```

### Step 3: Approve or Reject

```bash
# Approve with custom name
curl -X POST https://your-signal-horizon.com/api/v1/onboarding/pending/sen_pending_abc123 \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "approve",
    "assignedName": "edge-us-east-1-prod-01"
  }'

# Or reject
curl -X POST https://your-signal-horizon.com/api/v1/onboarding/pending/sen_pending_abc123 \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "reject",
    "reason": "Unrecognized device"
  }'
```

## Decision Flowchart

```
┌─────────────────────────────────────────────────────────────┐
│                  How many sensors?                          │
└─────────────────────────────────────────────────────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
         1-5 sensors   6-50 sensors   50+ sensors
              │            │            │
              ▼            ▼            ▼
         ┌────────┐   ┌─────────┐   ┌──────────────┐
         │ Manual │   │ Agent   │   │ Auto-        │
         │ Regis- │   │ Script  │   │ Discovery    │
         │ tration│   │         │   │              │
         └────────┘   └─────────┘   └──────────────┘
```

## Troubleshooting

### Token Expired or Invalid

```
Error: Registration token invalid or expired
```

**Solution**: Generate a new token with adequate expiration time:
```bash
curl -X POST .../onboarding/tokens \
  -d '{"name": "New Token", "expiresIn": 90}'
```

### Connection Timeout

```
Error: Connection to Signal Horizon timed out
```

**Solutions**:
1. Verify outbound HTTPS (443) is allowed in firewall
2. Check DNS resolution: `nslookup your-signal-horizon.com`
3. Test connectivity: `curl -v https://your-signal-horizon.com/health`

### Authentication Failed

```
Error: Invalid sensor credentials
```

**Solutions**:
1. Verify sensor ID and API key are correct
2. Check file permissions: `ls -la /etc/signal-horizon/`
3. Ensure no trailing whitespace in config values

### Certificate Errors

```
Error: SSL certificate verification failed
```

**Solutions**:
1. Update CA certificates: `sudo apt update && sudo apt install ca-certificates`
2. For self-signed certs (dev only): Set `SKIP_TLS_VERIFY=true`

## Security Best Practices

### Token Management

- **Use minimal scopes**: Registration tokens should only have `sensor:register` permission
- **Set expiration**: Always set `expiresIn` to limit token lifetime
- **Limit uses**: Set `maxUses` to prevent token abuse
- **Revoke unused tokens**: Delete tokens that are no longer needed

### Credential Storage

- Store credentials in `/etc/signal-horizon/` with `600` permissions
- Never commit credentials to version control
- Use secrets managers (HashiCorp Vault, AWS Secrets Manager) in production
- Rotate API keys periodically

### Network Security

- Sensors connect outbound only (no inbound ports required)
- All communication is encrypted via TLS 1.3
- WebSocket tunnels use secure protocols

## Next Steps

After onboarding your first sensor:

1. **[Remote Access Guide](./remote-access.md)**: Access your sensor's shell and dashboard
2. **[Synapse Rules Guide](./synapse-rules.md)**: Configure security rules on your sensors
3. **[API Key Management](./api-key-management.md)**: Manage sensor credentials

## API Reference

### Registration Tokens

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/onboarding/tokens` | GET | List all tokens |
| `/api/v1/onboarding/tokens` | POST | Create new token |
| `/api/v1/onboarding/tokens/:id` | DELETE | Revoke token |

### Pending Sensors

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/onboarding/pending` | GET | List pending sensors |
| `/api/v1/onboarding/pending/:id` | POST | Approve/reject sensor |
| `/api/v1/onboarding/pending/:id` | DELETE | Delete pending sensor |

### Statistics

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/onboarding/stats` | GET | Onboarding statistics |
