# Setup Guide

Get Signal Horizon running and connect your first Synapse sensor. This guide covers a Docker Compose deployment suitable for evaluation, staging, or small production environments. For advanced deployment options, see the [Deployment Guide](deployment.md).

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Docker | v24 or later with Docker Compose v2 |
| Browser | Chrome, Firefox, or Edge (latest two versions) |
| Network | Outbound HTTPS for container image pulls; inbound access on ports 3003 (API) and 5180 (UI) |
| Resources | Minimum 4 GB RAM, 2 CPU cores, 20 GB disk |

## Step 1: Deploy Signal Horizon

Pull and start the full stack with Docker Compose:

```bash
curl -fsSL https://get.signal-horizon.io/compose.yml -o compose.yml
docker compose up -d
```

This starts four containers:

| Container | Purpose | Port |
|-----------|---------|------|
| signal-horizon | API server and WebSocket gateway | 3003 |
| postgres | Configuration state and fleet data | 5432 |
| redis | Session cache and real-time pub/sub | 6379 |
| clickhouse | Historical analytics (optional) | 8123 |

Wait for all containers to report healthy:

```bash
docker compose ps
```

All services should show a status of `Up` or `healthy`.

## Step 2: Access the Web Console

Open your browser and navigate to:

```
http://localhost:5180
```

Log in with the default administrator credentials:

- **Username**: `admin@signal-horizon.local`
- **Password**: `changeme`

Change the default password immediately after first login under **Settings > Account**.

## Step 3: Register Your First Sensor

1. In the web console, navigate to **Fleet > Sensors**.
2. Click **Register Sensor**.
3. Enter a name and region for the sensor (e.g., `us-east-primary`).
4. Click **Create**. The console displays the sensor ID and authentication token.
5. Copy the provided sensor configuration block and add it to your Synapse sensor's config file:

   ```yaml
   signal_horizon:
     enabled: true
     endpoint: ws://YOUR_HUB_HOST:3003/ws/sensor
     sensor_id: <provided-sensor-id>
     token: <provided-token>
     heartbeat_interval: 60s
   ```

6. Restart the Synapse sensor. Within 60 seconds, the sensor should appear as **Online** in the Fleet dashboard.

## Step 4: Generate API Keys

API keys allow external tools and scripts to interact with Signal Horizon programmatically.

1. Navigate to **Settings > API Keys**.
2. Click **Generate Key**.
3. Assign a descriptive name and select the appropriate permission scope.
4. Copy the key immediately -- it will not be shown again.

Use the key in API requests via the `Authorization` header:

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:3003/api/fleet/sensors
```

## Step 5: Verify Connectivity

Confirm that all components are communicating correctly:

1. **API health**: Visit `http://localhost:3003/api/health` -- should return `{"status":"ok"}`.
2. **Sensor connection**: Navigate to **Fleet > Sensors** and verify your sensor shows **Online** with a recent heartbeat timestamp.
3. **Data flow**: If a Synapse sensor is processing traffic, navigate to **Threats > Live Feed** to confirm signals are arriving.

## Changing Default Ports

If ports 3003 or 5180 conflict with other services, edit `compose.yml` before starting:

```yaml
services:
  signal-horizon:
    ports:
      - "CUSTOM_PORT:3003"
```

Update browser bookmarks and sensor endpoint URLs accordingly.

## Next Steps

- [Deployment Guide](deployment.md) -- Production hardening, Kubernetes, and high availability
- [Sensor Onboarding](tutorials/sensor-onboarding.md) -- Detailed walkthrough for onboarding multiple sensors
- [Fleet Configuration Management](tutorials/fleet-configuration-management.md) -- Push configuration templates across your fleet
- [API Key Management](tutorials/api-key-management.md) -- Key rotation and permission scopes
- [Tuning WAF Rules](guides/tuning-waf-rules.md) -- Optimize detection accuracy for your environment
