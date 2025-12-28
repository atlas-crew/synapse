# Feature: Fleet Management

Signal Horizon serves as the central command plane for your distributed fleet of Synapse sensors.

## Core Capabilities

### 1. Fleet Aggregation
The `FleetAggregator` service provides a real-time, unified view of all connected sensors.
- **Aggregated Metrics**: Sum of RPS, average latency, and resource utilization (CPU/Mem) across the fleet.
- **Health Scoring**: A fleet-wide health score (0-100) based on sensor status and resource pressure.
- **Regional Views**: Group sensors by region to identify localized outages or attack bursts.

### 2. Command & Control
The `FleetCommander` allows operators to send remote commands to one or many sensors.
- **Direct Commands**: Restart services, collect diagnostics, or rotate keys.
- **Broadcasts**: Send commands to the entire fleet simultaneously.
- **Execution Tracking**: Track the status of every command from `pending` -> `sent` -> `success/failed`.

### 3. Configuration Management
The `ConfigManager` ensures that your sensors are running the correct security policies.
- **Templates**: Manage versioned configuration templates for different environments (Prod, Staging, Dev).
- **Sync Tracking**: Real-time detection of "Config Drift". The Hub tracks the expected vs. actual configuration hash for every sensor.
- **One-Click Push**: Update the configuration across a set of sensors from the central dashboard.

### 4. Rule Distribution
Deploy security rules (WAF rules, rate limits, custom logic) across the fleet with the `RuleDistributor`.
- **Rollout Strategies**:
  - **Immediate**: Push to all targets at once.
  - **Canary**: Incremental rollout (e.g., 10% -> 50% -> 100%) to mitigate risk.
  - **Scheduled**: Deploy during maintenance windows.

## Operational Workflow

1. **Onboarding**: A sensor connects to the Hub using an API key and performs an `auth` handshake.
2. **Registration**: The Hub registers the sensor and initializes its `SensorSyncState`.
3. **Synchronization**: The Hub detects that the new sensor has an empty config and automatically triggers a `push_config` command with the default template.
4. **Monitoring**: The sensor sends periodic `heartbeat` messages with health metrics and its current config hash.
5. **Updates**: An operator modifies a Config Template in the dashboard and clicks "Push to Fleet", initiating a fleet-wide synchronization.

## Dashboard Pages

- **Fleet Overview**: High-level metrics and health map.
- **Sensor List**: Detailed table of all sensors with status and version info.
- **Sensor Detail**: Deep-dive into a single sensor's metrics (Netdata-style) and command history.
- **Config Manager**: Template editor and fleet sync status.
- **Rule Distribution**: Deploy and track security rules.
- **Updates**: Manage firmware/version updates across the fleet.
