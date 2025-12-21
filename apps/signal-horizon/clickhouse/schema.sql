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
