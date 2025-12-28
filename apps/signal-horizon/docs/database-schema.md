# Database Schema

Signal Horizon uses a dual-database architecture:
1. **PostgreSQL** (via Prisma): The source of truth for all metadata, configuration, real-time signals, and fleet state.
2. **ClickHouse**: Optimized time-series storage for historical hunting and deep analytics.

---

## PostgreSQL Schema (Prisma)

The PostgreSQL schema is partitioned logically into core modules.

### Multi-Tenant Core

- **Tenant**: Represents an organization using Signal Horizon.
  - `id`, `name`, `tier` (FREE, STANDARD, ENTERPRISE, PLATINUM), `sharingPreference`.
- **ApiKey**: Scoped authentication keys for sensors and dashboards.
  - `tenantId`, `keyHash` (SHA-256), `scopes` (array), `isRevoked`.

### Sensors & Fleet

- **Sensor**: Represents a connected Synapse sensor.
  - `tenantId`, `name`, `region`, `version`, `connectionState`, `lastHeartbeat`.
- **ConfigTemplate**: Configuration templates for fleet-wide distribution.
  - `environment`, `config` (JSON), `hash` (SHA-256), `version`.
- **SensorSyncState**: Tracks if a sensor's config/rules match the hub's expected state.
- **FleetCommand**: History and status of commands sent to sensors.
- **RuleSyncState**: Sync status per rule per sensor.

### Threat Intelligence

- **Signal**: Individual threat events ingested from sensors.
  - `signalType` (IP_THREAT, BOT_SIGNATURE, etc.), `sourceIp`, `anonFingerprint`, `severity`, `confidence`.
- **Threat**: Aggregated indicators (IPs, Fingerprints) tracked over time.
  - `riskScore`, `fleetRiskScore`, `isFleetThreat` (flag for 2+ tenants affected).
- **Campaign**: Correlated groups of threats forming a single attack pattern.
  - `status`, `severity`, `isCrossTenant`, `tenantsAffected`.
- **BlocklistEntry**: Indicators actively blocked by the fleet.
  - `blockType`, `indicator`, `source` (AUTOMATIC, MANUAL, etc.), `propagationStatus`.

### War Room

- **WarRoom**: Collaboration space for an incident.
  - `status`, `priority`, `leaderId`.
- **WarRoomActivity**: Timeline of messages, blocks created, and links to campaigns.

---

## ClickHouse Schema

ClickHouse is used for high-volume, historical data.

### signal_events
The primary time-series table for all threat signals.
- **Partitioning**: Monthly by `timestamp`.
- **Ordering**: `tenant_id`, `timestamp`, `signal_type`.
- **Indexes**: Bloom filters on `source_ip` and `anon_fingerprint` for fast lookups.
- **TTL**: 90 days (hot storage).

### campaign_history
Snapshots of campaign state changes for attack chain reconstruction.
- **Ordering**: `campaign_id`, `timestamp`.
- **TTL**: 180 days.

### blocklist_history
Audit log of all blocklist changes (added, removed, expired).
- **TTL**: 365 days.

### Materialized Views

- **signal_hourly_mv**: Pre-aggregates signals by hour/tenant/type for fast dashboard charts.
- **ip_daily_mv**: Pre-aggregates IP activity by day for long-term dwell time detection.

---

## Data Flow: Postgres vs ClickHouse

1. **Ingestion**: The `Aggregator` service writes every incoming signal to **PostgreSQL** immediately.
2. **Dual-Write**: If ClickHouse is enabled, the `Aggregator` also sends the signal to **ClickHouse** asynchronously.
3. **Query Routing**:
   - Recent data (< 24h) is queried from **PostgreSQL**.
   - Historical data (> 24h) is queried from **ClickHouse**.
   - Large ranges are handled by the `HuntService` via hybrid queries.
