# Database Schema Reference

High-level overview of the polyglot data layer for Signal Horizon.

## PostgreSQL (Relational)
Managed via Prisma in `apps/signal-horizon/api/prisma/schema.prisma`.

### Core Models

- **Tenant**: Multi-tenant isolation unit. All data belongs to a tenant.
- **User**: Authentication and RBAC (VIEWER, OPERATOR, ADMIN, SUPER_ADMIN).
- **Sensor**: Metadata for Synapse WAF instances (ID, name, status, config).
- **Signal**: Normalized threat indicators aggregated from sensors.
- **Campaign**: Clusters of related signals forming an attack chain.
- **Actor**: Identified threat entities (IPs, fingerprints) with risk scores.
- **WarRoom**: Collaboration space for incident response.

### Conventions
- Primary Keys: `String` (CUID) via `@default(cuid())`.
- Foreign Keys: Mandatory `tenantId` for isolation.
- Dates: `createdAt`, `updatedAt` on all major models.

## ClickHouse (Time-Series)
Managed via SQL in `apps/signal-horizon/clickhouse/schema.sql`.

### Primary Tables

- **signal_events**: High-volume ingestion of raw threat signals (90-day retention).
- **http_transactions**: Metadata for every request/response (30-day retention).
- **actor_events**: Fine-grained risk changes and rule matches for entities.
- **blocks**: Denormalized log of every WAF block event.
- **sensor_logs**: Raw logs from sensors (kernel, access, WAF).

### Materialized Views
Used for sub-second dashboard performance:
- **signal_hourly_mv**: Pre-aggregated hourly signal counts.
- **top_actors_hourly**: Tracks the most active threat actors per hour.
- **geo_distribution_daily**: Country-level block summaries.
- **fingerprint_spread_daily**: Tracks botnet-like behavior across sensors.

## Data Lifecycle

| Step | Data Flow | Storage |
|------|-----------|---------|
| **Ingest** | Sensor push via WebSocket | ClickHouse (Raw) |
| **Aggregate**| Hub Aggregator Service | Postgres (Relational) |
| **Correlate**| Hub Correlator Service | Postgres (Campaigns) |
| **Observe** | UI Dashboard Query | ClickHouse (MV) + Postgres |
| **Archive** | Retention Cleanup Job | Both (TTL based) |
