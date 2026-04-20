# Data Conventions

Strict rules for modeling, naming, and relationships in the Edge Protection ecosystem.

## Relational (Postgres / Prisma)

### 1. Multi-Tenant Isolation
- **Mandatory `tenantId`**: Every row (with rare exceptions like `Tenant` and `User`) must have a `tenantId`.
- **Foreign Key**: `tenantId String`.
- **Prisma Relation**: `tenant Tenant @relation(fields: [tenantId], references: [id], onDelete: Cascade)`.

### 2. Primary Keys
- **Default**: Use `String` with `cuid()` for primary keys.
- **Exceptions**: Use `uuid()` only when external parity is required (e.g., `TunnelSession`).

### 3. Naming
- **Models**: PascalCase (e.g., `SensorIntelActor`).
- **Fields**: camelCase (e.g., `lastSeenAt`).
- **Database Mapping**: Use `@@map("table_name")` to use snake_case for the actual Postgres table names.
- **Enums**: UPPERCASE for values (e.g., `CONNECTED`, `DISCONNECTED`).

### 4. Indexing Strategy
- **Covering Indexes**: Always index `tenantId` on every table.
- **Time-Range Queries**: Use compound indexes like `[tenantId, createdAt(sort: Desc)]`.
- **Searchable Fields**: Use `@@index([indicator])` or `@@index([keyHash])` for high-frequency lookups.

## Telemetry (ClickHouse)

### 1. Ingestion Keys
- **Tenant ID**: Use `tenant_id LowCardinality(String)` for efficient storage and filtering.
- **Sensor ID**: Use `sensor_id LowCardinality(String)`.
- **Request ID**: Use `request_id Nullable(String) CODEC(ZSTD)` for correlation across services.

### 2. Storage Optimization
- **Codecs**: Use `ZSTD` for large string fields and `Delta, ZSTD` for timestamps/monotonically increasing IDs.
- **Bloom Filters**: Use `INDEX ... TYPE bloom_filter` for fields with high cardinality that are frequently searched (e.g., `source_ip`, `fingerprint`).

### 3. Lifecycle
- **TTL**: Define a TTL on every large table (typically 30-90 days).
- **Partitioning**: Partition by `toYYYYMM(timestamp)` or `toYYYYMMDD(timestamp)` depending on volume.
