-- Signal Horizon Hub - ClickHouse Schema
-- Time-series storage for historical threat hunting
--
-- Tables:
--   signal_events      - Time-series signal data with bloom filters
--   campaign_history   - Campaign state change snapshots
--   blocklist_history  - Blocklist entry change log
--
-- Materialized Views:
--   signal_hourly_mv   - Hourly rollups by tenant/type
--   ip_daily_mv        - Daily IP summary for dwell time detection
--
-- Retention:
--   signal_events: 90 days (hot)
--   campaign_history: 180 days
--   blocklist_history: 365 days

-- =============================================================================
-- Signal Events (time-series with bloom filters)
-- =============================================================================
-- Primary table for all threat signals from sensors.
-- Optimized for:
--   - High-volume ingestion (10K signals/sec)
--   - Time-range queries
--   - IP/fingerprint lookups via bloom filters
--   - Compression (~100 bytes/signal with ZSTD)

CREATE TABLE IF NOT EXISTS signal_events (
    -- Time & Identity
    timestamp DateTime64(3) CODEC(Delta, ZSTD),
    tenant_id LowCardinality(String),
    sensor_id LowCardinality(String),

    -- Signal Data
    signal_type LowCardinality(String),  -- IP_THREAT, FINGERPRINT_THREAT, etc.
    source_ip IPv4 CODEC(ZSTD),
    fingerprint String CODEC(ZSTD),
    anon_fingerprint FixedString(64),     -- SHA-256 for cross-tenant correlation

    -- Context
    severity LowCardinality(String),      -- LOW, MEDIUM, HIGH, CRITICAL
    confidence Float32,
    event_count UInt32 DEFAULT 1,
    metadata String,                       -- JSON blob for signal-specific data

    -- Bloom filter indexes for fast IP/fingerprint lookups
    INDEX idx_anon_fp (anon_fingerprint) TYPE bloom_filter GRANULARITY 1,
    INDEX idx_source_ip (source_ip) TYPE bloom_filter GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
-- ORDER BY optimized for time-range queries within tenant
-- tenant_id first (multi-tenant isolation)
-- timestamp second (time-range filtering is most common)
-- signal_type third (secondary filter)
ORDER BY (tenant_id, timestamp, signal_type)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;


-- =============================================================================
-- Campaign History (state snapshots)
-- =============================================================================
-- Stores campaign state changes for attack chain reconstruction.
-- Every significant campaign event creates a snapshot.

CREATE TABLE IF NOT EXISTS campaign_history (
    timestamp DateTime64(3) CODEC(Delta, ZSTD),
    campaign_id String,
    tenant_id LowCardinality(String),     -- 'fleet' for cross-tenant campaigns

    -- Event that triggered this snapshot
    event_type LowCardinality(String),    -- created, updated, escalated, resolved

    -- Campaign state at this timestamp
    name String,
    status LowCardinality(String),        -- ACTIVE, MONITORING, RESOLVED, FALSE_POSITIVE
    severity LowCardinality(String),
    is_cross_tenant UInt8,
    tenants_affected UInt16,
    confidence Float32,
    metadata String                        -- JSON snapshot of full campaign state
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (campaign_id, timestamp)
TTL timestamp + INTERVAL 180 DAY
SETTINGS index_granularity = 4096;


-- =============================================================================
-- Blocklist History (change log)
-- =============================================================================
-- Tracks all blocklist changes for auditing and forensics.
-- Enables "when was this IP blocked?" and "what changed?" queries.

CREATE TABLE IF NOT EXISTS blocklist_history (
    timestamp DateTime64(3) CODEC(Delta, ZSTD),
    tenant_id LowCardinality(String),     -- 'fleet' for fleet-wide blocks

    -- Action taken
    action LowCardinality(String),        -- added, removed, expired

    -- Entry details
    block_type LowCardinality(String),    -- IP, IP_RANGE, FINGERPRINT, ASN, USER_AGENT
    indicator String,
    source LowCardinality(String),        -- AUTOMATIC, MANUAL, FLEET_INTEL, EXTERNAL_FEED
    reason String,
    campaign_id String,
    expires_at Nullable(DateTime64(3))
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, block_type, timestamp)
TTL timestamp + INTERVAL 365 DAY
SETTINGS index_granularity = 4096;


-- =============================================================================
-- Hourly Rollup Materialized View
-- =============================================================================
-- Pre-aggregates signals by hour for fast dashboard queries.
-- Uses SummingMergeTree for automatic aggregation on merge.

CREATE MATERIALIZED VIEW IF NOT EXISTS signal_hourly_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, signal_type, severity, hour)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    tenant_id,
    signal_type,
    severity,
    count() AS signal_count,
    sum(event_count) AS total_events,
    uniq(source_ip) AS unique_ips,
    uniq(anon_fingerprint) AS unique_fingerprints,
    avg(confidence) AS avg_confidence
FROM signal_events
GROUP BY hour, tenant_id, signal_type, severity;


-- =============================================================================
-- Daily IP Summary Materialized View
-- =============================================================================
-- Pre-aggregates IP activity by day for dwell time detection.
-- "This IP hit us 6 months ago, went quiet, now back"

CREATE MATERIALIZED VIEW IF NOT EXISTS ip_daily_mv
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (source_ip, day)
AS SELECT
    toDate(timestamp) AS day,
    source_ip,
    uniqState(tenant_id) AS tenants_hit_state,
    countState() AS signal_count_state,
    maxState(confidence) AS max_confidence_state,
    groupArrayState(signal_type) AS signal_types_state
FROM signal_events
WHERE source_ip != toIPv4('0.0.0.0')
GROUP BY day, source_ip;


-- =============================================================================
-- SOC Session Surfacing Tables
-- =============================================================================

-- Actor events (high velocity)
CREATE TABLE IF NOT EXISTS actor_events (
    timestamp DateTime64(3),
    sensor_id String,
    actor_id String,
    event_type Enum('rule_match', 'risk_change', 'block', 'unblock', 'session_bind'),
    risk_score UInt16,
    risk_delta Int16,
    rule_id Nullable(String),
    rule_category Nullable(String),
    ip String,
    fingerprint Nullable(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (sensor_id, actor_id, timestamp);

-- Session events
CREATE TABLE IF NOT EXISTS session_events (
    timestamp DateTime64(3),
    sensor_id String,
    session_id String,
    actor_id String,
    event_type Enum('created', 'request', 'suspicious', 'hijack_alert', 'expired'),
    request_count UInt32,
    ja4_hash Nullable(String),
    bound_ip Nullable(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (sensor_id, session_id, timestamp);

-- Campaign events
CREATE TABLE IF NOT EXISTS campaign_events (
    timestamp DateTime64(3),
    campaign_id String,
    sensor_id String,
    actor_id String,
    event_type Enum('actor_added', 'correlation_signal', 'status_change'),
    correlation_type Nullable(String),
    confidence Nullable(Float32)
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (campaign_id, timestamp);

-- Blocks (denormalized for fast queries)
CREATE TABLE IF NOT EXISTS blocks (
    timestamp DateTime64(3),
    sensor_id String,
    actor_id String,
    session_id Nullable(String),
    reason String,
    rule_id Nullable(String),
    ip String,
    country Nullable(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (sensor_id, timestamp);

-- =============================================================================
-- Materialized Views for SOC Widgets
-- =============================================================================

-- Top actors by hour
CREATE MATERIALIZED VIEW IF NOT EXISTS top_actors_hourly
ENGINE = SummingMergeTree()
ORDER BY (sensor_id, hour, actor_id)
AS SELECT
    sensor_id,
    toStartOfHour(timestamp) AS hour,
    actor_id,
    max(risk_score) AS risk_score,
    count() AS event_count
FROM actor_events
GROUP BY sensor_id, hour, actor_id;

-- Attack trends by day
CREATE MATERIALIZED VIEW IF NOT EXISTS attack_trends_daily
ENGINE = SummingMergeTree()
ORDER BY (sensor_id, day, rule_category)
AS SELECT
    sensor_id,
    toDate(timestamp) AS day,
    rule_category,
    count() AS hit_count
FROM actor_events
WHERE rule_category IS NOT NULL
GROUP BY sensor_id, day, rule_category;

-- Blocks by sensor (fleet health)
CREATE MATERIALIZED VIEW IF NOT EXISTS blocks_by_sensor_hourly
ENGINE = SummingMergeTree()
ORDER BY (sensor_id, hour)
AS SELECT
    sensor_id,
    toStartOfHour(timestamp) AS hour,
    count() AS block_count,
    max(timestamp) AS last_block
FROM blocks
GROUP BY sensor_id, hour;

-- Campaign velocity
CREATE MATERIALIZED VIEW IF NOT EXISTS campaign_velocity_hourly
ENGINE = SummingMergeTree()
ORDER BY (campaign_id, hour)
AS SELECT
    campaign_id,
    toStartOfHour(timestamp) AS hour,
    uniqExact(actor_id) AS new_actors,
    count() AS event_count
FROM campaign_events
GROUP BY campaign_id, hour;

-- Geo distribution
CREATE MATERIALIZED VIEW IF NOT EXISTS geo_distribution_daily
ENGINE = SummingMergeTree()
ORDER BY (day, country)
AS SELECT
    toDate(timestamp) AS day,
    country,
    count() AS block_count
FROM blocks
WHERE country IS NOT NULL
GROUP BY day, country;

-- =============================================================================
-- Cross-sensor correlation
-- =============================================================================

-- Actor seen across multiple sensors
CREATE MATERIALIZED VIEW IF NOT EXISTS actor_sensor_matrix
ENGINE = AggregatingMergeTree()
ORDER BY (actor_id)
AS SELECT
    actor_id,
    groupArrayState(DISTINCT sensor_id) AS sensors,
    minState(timestamp) AS first_seen
FROM actor_events
GROUP BY actor_id;

-- Fingerprint spread (botnet detection)
CREATE MATERIALIZED VIEW IF NOT EXISTS fingerprint_spread_daily
ENGINE = SummingMergeTree()
ORDER BY (day, fingerprint)
AS SELECT
    toDate(timestamp) AS day,
    fingerprint,
    uniqExact(actor_id) AS actor_count,
    uniqExact(sensor_id) AS sensor_count
FROM actor_events
WHERE fingerprint IS NOT NULL
GROUP BY day, fingerprint;

-- =============================================================================
-- Reporting / compliance
-- =============================================================================

-- Daily summary
CREATE MATERIALIZED VIEW IF NOT EXISTS daily_summary
ENGINE = SummingMergeTree()
ORDER BY (sensor_id, day)
AS SELECT
    sensor_id,
    toDate(timestamp) AS day,
    count() AS total_events,
    uniqExact(actor_id) AS unique_actors,
    countIf(event_type = 'block') AS blocks
FROM actor_events
GROUP BY sensor_id, day;
