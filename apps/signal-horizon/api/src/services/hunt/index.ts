/**
 * Hunt Service
 * Time-based threat hunting with intelligent query routing
 *
 * Query Routing Strategy:
 * - PostgreSQL (<24h): Real-time queries for recent data
 * - ClickHouse (>24h): Historical queries for archived data
 */

import type { PrismaClient, Signal, Prisma, SignalType } from '@prisma/client';
import type { Logger } from 'pino';
import type { ClickHouseService } from '../../storage/clickhouse/index.js';
import type { Severity } from '../../types/protocol.js';

// =============================================================================
// Query Types
// =============================================================================

export interface HuntQuery {
  tenantId?: string;
  startTime: Date;
  endTime: Date;
  signalTypes?: string[];
  sourceIps?: string[];
  severities?: Severity[];
  minConfidence?: number;
  anonFingerprint?: string;
  limit?: number;
  offset?: number;
}

export interface HuntResult {
  signals: SignalResult[];
  total: number;
  source: 'postgres' | 'clickhouse' | 'hybrid';
  queryTimeMs: number;
}

export interface SignalResult {
  id: string;
  timestamp: Date;
  tenantId: string;
  sensorId: string;
  signalType: string;
  sourceIp: string | null;
  anonFingerprint: string | null;
  severity: Severity;
  confidence: number;
  eventCount: number;
  metadata?: any;
}

export interface CampaignTimelineEvent {
  timestamp: Date;
  campaignId: string;
  eventType: 'created' | 'updated' | 'escalated' | 'resolved';
  name: string;
  status: string;
  severity: string;
  isCrossTenant: boolean;
  tenantsAffected: number;
  confidence: number;
}

export interface HourlyStats {
  hour: Date;
  tenantId: string;
  signalType: string;
  severity: string;
  signalCount: number;
  totalEvents: number;
  uniqueIps: number;
  uniqueFingerprints: number;
}

export interface SavedQuery {
  id: string;
  name: string;
  description?: string;
  query: HuntQuery;
  createdBy: string;
  createdAt: Date;
  lastRunAt?: Date;
}

// =============================================================================
// Hunt Service
// =============================================================================

/**
 * Hunt Service for time-based threat hunting.
 * Routes queries to PostgreSQL or ClickHouse based on time range.
 */
export class HuntService {
  private prisma: PrismaClient;
  private clickhouse: ClickHouseService | null;
  private logger: Logger;

  // Time threshold for routing (24 hours in ms)
  private readonly ROUTING_THRESHOLD_MS = 24 * 60 * 60 * 1000;

  constructor(
    prisma: PrismaClient,
    logger: Logger,
    clickhouse?: ClickHouseService
  ) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'hunt' });
    this.clickhouse = clickhouse ?? null;
  }

  /**
   * Check if ClickHouse is available for historical queries
   */
  isHistoricalEnabled(): boolean {
    return this.clickhouse?.isEnabled() ?? false;
  }

  /**
   * Query signal timeline with intelligent routing
   * - <24h old: PostgreSQL (source of truth)
   * - >24h old: ClickHouse (historical analytics)
   */
  async queryTimeline(query: HuntQuery): Promise<HuntResult> {
    const startTime = Date.now();
    const now = new Date();
    const threshold = new Date(now.getTime() - this.ROUTING_THRESHOLD_MS);

    // Determine routing strategy
    const useClickHouse = this.clickhouse?.isEnabled() && query.startTime < threshold;
    const usePostgres = query.endTime >= threshold;

    if (useClickHouse && usePostgres) {
      // Hybrid query: Split at threshold
      return this.queryHybrid(query, threshold, startTime);
    } else if (useClickHouse) {
      // Pure historical query
      return this.queryClickHouse(query, startTime);
    } else {
      // Pure real-time query
      return this.queryPostgres(query, startTime);
    }
  }

  /**
   * Query PostgreSQL for recent signals
   */
  private async queryPostgres(query: HuntQuery, startTime: number): Promise<HuntResult> {
    const where = this.buildPrismaWhere(query);
    const limit = query.limit ?? 1000;
    const offset = query.offset ?? 0;

    const [signals, total] = await Promise.all([
      this.prisma.signal.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
      }),
      this.prisma.signal.count({ where }),
    ]);

    return {
      signals: signals.map(this.mapSignalToResult),
      total,
      source: 'postgres',
      queryTimeMs: Date.now() - startTime,
    };
  }

  /**
   * Query ClickHouse for historical signals
   */
  private async queryClickHouse(query: HuntQuery, startTime: number): Promise<HuntResult> {
    if (!this.clickhouse) {
      throw new Error('ClickHouse is not enabled');
    }

    const { sql, countSql, params } = this.buildClickHouseQuery(query);

    const [signals, countResult] = await Promise.all([
      this.clickhouse.queryWithParams<ClickHouseSignalRow>(sql, params),
      this.clickhouse.queryOneWithParams<{ count: string }>(countSql, params),
    ]);

    return {
      signals: signals.map(this.mapClickHouseToResult),
      total: parseInt(countResult?.count ?? '0', 10),
      source: 'clickhouse',
      queryTimeMs: Date.now() - startTime,
    };
  }

  /**
   * Hybrid query: Split between PostgreSQL and ClickHouse
   */
  private async queryHybrid(
    query: HuntQuery,
    threshold: Date,
    startTime: number
  ): Promise<HuntResult> {
    // Split query at threshold
    const historicalQuery = { ...query, endTime: threshold };
    const recentQuery = { ...query, startTime: threshold };

    // Run both queries in parallel
    const [historical, recent] = await Promise.all([
      this.queryClickHouse(historicalQuery, startTime),
      this.queryPostgres(recentQuery, startTime),
    ]);

    // Merge results (recent first, then historical)
    const signals = [...recent.signals, ...historical.signals];
    const limit = query.limit ?? 1000;

    return {
      signals: signals.slice(0, limit),
      total: historical.total + recent.total,
      source: 'hybrid',
      queryTimeMs: Date.now() - startTime,
    };
  }

  /**
   * Get campaign timeline from ClickHouse
   */
  async getCampaignTimeline(
    campaignId: string,
    startTime?: Date,
    endTime?: Date
  ): Promise<CampaignTimelineEvent[]> {
    if (!this.clickhouse?.isEnabled()) {
      this.logger.warn('ClickHouse not enabled, campaign timeline unavailable');
      return [];
    }

    // Validate inputs
    this.validateIdentifier(campaignId, 'campaignId');

    const start = startTime?.toISOString().replace('T', ' ').replace('Z', '') ?? '1970-01-01 00:00:00';
    const end = endTime?.toISOString().replace('T', ' ').replace('Z', '') ?? new Date().toISOString().replace('T', ' ').replace('Z', '');

    const sql = `
      SELECT
        timestamp,
        campaign_id,
        event_type,
        name,
        status,
        severity,
        is_cross_tenant,
        tenants_affected,
        confidence
      FROM campaign_history
      WHERE campaign_id = {campaignId:String}
        AND timestamp >= toDateTime64({startTime:String}, 3)
        AND timestamp <= toDateTime64({endTime:String}, 3)
      ORDER BY timestamp ASC
    `;

    const params = { campaignId, startTime: start, endTime: end };
    const rows = await this.clickhouse.queryWithParams<ClickHouseCampaignRow>(sql, params);

    return rows.map((row) => ({
      timestamp: new Date(row.timestamp),
      campaignId: row.campaign_id,
      eventType: row.event_type as CampaignTimelineEvent['eventType'],
      name: row.name,
      status: row.status,
      severity: row.severity,
      isCrossTenant: row.is_cross_tenant === 1,
      tenantsAffected: row.tenants_affected,
      confidence: row.confidence,
    }));
  }

  /**
   * Get hourly aggregated statistics from materialized view
   */
  async getHourlyStats(
    tenantId?: string,
    startTime?: Date,
    endTime?: Date,
    signalTypes?: string[]
  ): Promise<HourlyStats[]> {
    if (!this.clickhouse?.isEnabled()) {
      this.logger.warn('ClickHouse not enabled, hourly stats unavailable');
      return [];
    }

    // Validate inputs
    if (tenantId) {
      this.validateIdentifier(tenantId, 'tenantId');
    }
    if (signalTypes) {
      signalTypes.forEach((t, i) => this.validateIdentifier(t, `signalTypes[${i}]`));
    }

    const start = startTime?.toISOString().replace('T', ' ').replace('Z', '')
      ?? new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().replace('T', ' ').replace('Z', '');
    const end = endTime?.toISOString().replace('T', ' ').replace('Z', '')
      ?? new Date().toISOString().replace('T', ' ').replace('Z', '');

    const params: Record<string, unknown> = { startTime: start, endTime: end };
    const whereClauses: string[] = [
      'hour >= toStartOfHour(toDateTime64({startTime:String}, 3))',
      'hour <= toStartOfHour(toDateTime64({endTime:String}, 3))',
    ];

    if (tenantId) {
      whereClauses.push('tenant_id = {tenantId:String}');
      params.tenantId = tenantId;
    }

    if (signalTypes && signalTypes.length > 0) {
      whereClauses.push('signal_type IN {signalTypes:Array(String)}');
      params.signalTypes = signalTypes;
    }

    const sql = `
      SELECT
        hour,
        tenant_id,
        signal_type,
        severity,
        signal_count,
        total_events,
        unique_ips,
        unique_fingerprints
      FROM signal_hourly_mv
      WHERE ${whereClauses.join(' AND ')}
      ORDER BY hour DESC
      LIMIT 1000
    `;

    const rows = await this.clickhouse.queryWithParams<ClickHouseHourlyRow>(sql, params);

    return rows.map((row) => ({
      hour: new Date(row.hour),
      tenantId: row.tenant_id,
      signalType: row.signal_type,
      severity: row.severity,
      signalCount: row.signal_count,
      totalEvents: row.total_events,
      uniqueIps: row.unique_ips,
      uniqueFingerprints: row.unique_fingerprints,
    }));
  }

  /**
   * Get IP activity across tenants (for threat hunting)
   */
  async getIpActivity(
    sourceIp: string,
    days: number = 30
  ): Promise<{
    totalHits: number;
    tenantsHit: number;
    firstSeen: Date | null;
    lastSeen: Date | null;
    signalTypes: string[];
  }> {
    // Validate inputs
    this.validateIpAddress(sourceIp, 'sourceIp');
    const validDays = this.validatePositiveInt(days, 1, 365);

    if (!this.clickhouse?.isEnabled()) {
      // Fall back to PostgreSQL for recent data
      const signals = await this.prisma.signal.findMany({
        where: {
          sourceIp,
          createdAt: { gte: new Date(Date.now() - validDays * 24 * 60 * 60 * 1000) },
        },
        select: { tenantId: true, signalType: true, createdAt: true },
      });

      const tenants = new Set(signals.map((s) => s.tenantId));
      const types = new Set(signals.map((s) => s.signalType));
      const times = signals.map((s) => s.createdAt);

      return {
        totalHits: signals.length,
        tenantsHit: tenants.size,
        firstSeen: times.length > 0 ? new Date(Math.min(...times.map((t) => t.getTime()))) : null,
        lastSeen: times.length > 0 ? new Date(Math.max(...times.map((t) => t.getTime()))) : null,
        signalTypes: Array.from(types),
      };
    }

    const sql = `
      SELECT
        count() AS total_hits,
        uniq(tenant_id) AS tenants_hit,
        min(timestamp) AS first_seen,
        max(timestamp) AS last_seen,
        groupUniqArray(signal_type) AS signal_types
      FROM signal_events
      WHERE source_ip = toIPv4({sourceIp:String})
        AND timestamp >= now() - INTERVAL {days:UInt32} DAY
    `;

    const params = { sourceIp, days: validDays };
    const result = await this.clickhouse.queryOneWithParams<{
      total_hits: string;
      tenants_hit: string;
      first_seen: string;
      last_seen: string;
      signal_types: string[];
    }>(sql, params);

    if (!result) {
      return {
        totalHits: 0,
        tenantsHit: 0,
        firstSeen: null,
        lastSeen: null,
        signalTypes: [],
      };
    }

    return {
      totalHits: parseInt(result.total_hits, 10),
      tenantsHit: parseInt(result.tenants_hit, 10),
      firstSeen: result.first_seen ? new Date(result.first_seen) : null,
      lastSeen: result.last_seen ? new Date(result.last_seen) : null,
      signalTypes: result.signal_types,
    };
  }

  // =============================================================================
  // Saved Queries (In-Memory for Demo, Prisma for Production)
  // =============================================================================

  private savedQueries: Map<string, SavedQuery> = new Map();

  async saveQuery(
    name: string,
    query: HuntQuery,
    createdBy: string,
    description?: string
  ): Promise<SavedQuery> {
    const saved: SavedQuery = {
      id: crypto.randomUUID(),
      name,
      description,
      query,
      createdBy,
      createdAt: new Date(),
    };

    this.savedQueries.set(saved.id, saved);
    this.logger.info({ queryId: saved.id, name }, 'Saved hunt query');

    return saved;
  }

  async getSavedQueries(createdBy?: string): Promise<SavedQuery[]> {
    const queries = Array.from(this.savedQueries.values());
    return createdBy
      ? queries.filter((q) => q.createdBy === createdBy)
      : queries;
  }

  async getSavedQuery(id: string): Promise<SavedQuery | null> {
    return this.savedQueries.get(id) ?? null;
  }

  async deleteSavedQuery(id: string): Promise<boolean> {
    return this.savedQueries.delete(id);
  }

  async runSavedQuery(id: string): Promise<HuntResult | null> {
    const saved = this.savedQueries.get(id);
    if (!saved) return null;

    saved.lastRunAt = new Date();
    return this.queryTimeline(saved.query);
  }

  // =============================================================================
  // Private Helpers
  // =============================================================================

  private buildPrismaWhere(query: HuntQuery): Prisma.SignalWhereInput {
    const where: Prisma.SignalWhereInput = {
      createdAt: {
        gte: query.startTime,
        lte: query.endTime,
      },
    };

    if (query.tenantId) {
      where.tenantId = query.tenantId;
    }

    if (query.signalTypes && query.signalTypes.length > 0) {
      where.signalType = { in: query.signalTypes as SignalType[] };
    }

    if (query.sourceIps && query.sourceIps.length > 0) {
      where.sourceIp = { in: query.sourceIps };
    }

    if (query.severities && query.severities.length > 0) {
      where.severity = { in: query.severities };
    }

    if (query.minConfidence !== undefined) {
      where.confidence = { gte: query.minConfidence };
    }

    if (query.anonFingerprint) {
      where.anonFingerprint = query.anonFingerprint;
    }

    return where;
  }

  private buildClickHouseQuery(query: HuntQuery): { sql: string; countSql: string; params: Record<string, unknown> } {
    // Validate and sanitize numeric inputs
    const limit = this.validatePositiveInt(query.limit ?? 1000, 1, 10000);
    const offset = this.validatePositiveInt(query.offset ?? 0, 0, 1000000);
    const minConfidence = query.minConfidence !== undefined
      ? this.validateFloat(query.minConfidence, 0, 1)
      : undefined;

    // Build parameterized query
    const params: Record<string, unknown> = {
      startTime: query.startTime.toISOString().replace('T', ' ').replace('Z', ''),
      endTime: query.endTime.toISOString().replace('T', ' ').replace('Z', ''),
      limit,
      offset,
    };

    const whereClauses: string[] = [
      'timestamp >= toDateTime64({startTime:String}, 3)',
      'timestamp <= toDateTime64({endTime:String}, 3)',
    ];

    if (query.tenantId) {
      this.validateIdentifier(query.tenantId, 'tenantId');
      whereClauses.push('tenant_id = {tenantId:String}');
      params.tenantId = query.tenantId;
    }

    if (query.signalTypes && query.signalTypes.length > 0) {
      query.signalTypes.forEach((t, i) => this.validateIdentifier(t, `signalTypes[${i}]`));
      whereClauses.push('signal_type IN {signalTypes:Array(String)}');
      params.signalTypes = query.signalTypes;
    }

    if (query.sourceIps && query.sourceIps.length > 0) {
      query.sourceIps.forEach((ip, i) => this.validateIpAddress(ip, `sourceIps[${i}]`));
      whereClauses.push('source_ip IN {sourceIps:Array(IPv4)}');
      params.sourceIps = query.sourceIps;
    }

    if (query.severities && query.severities.length > 0) {
      query.severities.forEach((s, i) => this.validateIdentifier(s, `severities[${i}]`));
      whereClauses.push('severity IN {severities:Array(String)}');
      params.severities = query.severities;
    }

    if (minConfidence !== undefined) {
      whereClauses.push('confidence >= {minConfidence:Float64}');
      params.minConfidence = minConfidence;
    }

    if (query.anonFingerprint) {
      this.validateIdentifier(query.anonFingerprint, 'anonFingerprint');
      whereClauses.push('anon_fingerprint = {anonFingerprint:String}');
      params.anonFingerprint = query.anonFingerprint;
    }

    const whereClause = whereClauses.join(' AND ');

    const sql = `
      SELECT
        generateUUIDv4() AS id,
        timestamp,
        tenant_id,
        sensor_id,
        signal_type,
        IPv4NumToString(source_ip) AS source_ip,
        anon_fingerprint,
        severity,
        confidence,
        event_count,
        metadata
      FROM signal_events
      WHERE ${whereClause}
      ORDER BY timestamp DESC
      LIMIT {limit:UInt32} OFFSET {offset:UInt32}
    `;

    const countSql = `
      SELECT count() AS count
      FROM signal_events
      WHERE ${whereClause}
    `;

    return { sql, countSql, params };
  }

  private mapSignalToResult(signal: Signal): SignalResult {
    return {
      id: signal.id,
      timestamp: signal.createdAt,
      tenantId: signal.tenantId,
      sensorId: signal.sensorId,
      signalType: signal.signalType,
      sourceIp: signal.sourceIp,
      anonFingerprint: signal.anonFingerprint,
      severity: signal.severity as Severity,
      confidence: signal.confidence,
      eventCount: signal.eventCount,
      metadata: signal.metadata,
    };
  }

  private mapClickHouseToResult(row: ClickHouseSignalRow): SignalResult {
    let parsedMetadata = {};
    try {
      if (row.metadata) {
        parsedMetadata = typeof row.metadata === 'string' ? JSON.parse(row.metadata) : row.metadata;
      }
    } catch (e) {
      // Ignore parse errors
    }

    return {
      id: row.id,
      timestamp: new Date(row.timestamp),
      tenantId: row.tenant_id,
      sensorId: row.sensor_id,
      signalType: row.signal_type,
      sourceIp: row.source_ip || null,
      anonFingerprint: row.anon_fingerprint || null,
      severity: row.severity as Severity,
      confidence: row.confidence,
      eventCount: row.event_count,
      metadata: parsedMetadata,
    };
  }

  // =============================================================================
  // Input Validation Helpers (SQL Injection Prevention)
  // =============================================================================

  /**
   * Validate a positive integer within bounds
   * @throws Error if value is not a valid integer within bounds
   */
  private validatePositiveInt(value: number, min: number, max: number): number {
    if (!Number.isInteger(value) || !Number.isFinite(value)) {
      throw new Error(`Invalid integer value: ${value}`);
    }
    if (value < min || value > max) {
      throw new Error(`Value ${value} out of range [${min}, ${max}]`);
    }
    return value;
  }

  /**
   * Validate a floating point number within bounds
   * @throws Error if value is not a valid number within bounds
   */
  private validateFloat(value: number, min: number, max: number): number {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new Error(`Invalid float value: ${value}`);
    }
    if (value < min || value > max) {
      throw new Error(`Value ${value} out of range [${min}, ${max}]`);
    }
    return value;
  }

  /**
   * Validate an identifier (tenant ID, signal type, fingerprint, etc.)
   * Allows alphanumeric, hyphens, underscores, and periods (for UUIDs and domains)
   * @throws Error if identifier contains invalid characters
   */
  private validateIdentifier(value: string, fieldName: string): void {
    if (typeof value !== 'string' || value.length === 0 || value.length > 256) {
      throw new Error(`Invalid ${fieldName}: must be a non-empty string <= 256 chars`);
    }
    // Allow alphanumeric, hyphen, underscore, period, colon (for namespaced types)
    const validPattern = /^[a-zA-Z0-9_\-.:]+$/;
    if (!validPattern.test(value)) {
      throw new Error(`Invalid ${fieldName}: contains disallowed characters`);
    }
  }

  /**
   * Validate an IP address (IPv4 or IPv6)
   * @throws Error if not a valid IP address
   */
  private validateIpAddress(value: string, fieldName: string): void {
    if (typeof value !== 'string') {
      throw new Error(`Invalid ${fieldName}: must be a string`);
    }
    // Basic IPv4 pattern
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    // Basic IPv6 pattern (simplified)
    const ipv6Pattern = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;

    if (!ipv4Pattern.test(value) && !ipv6Pattern.test(value)) {
      throw new Error(`Invalid ${fieldName}: not a valid IP address`);
    }

    // Additional IPv4 validation - each octet must be 0-255
    if (ipv4Pattern.test(value)) {
      const octets = value.split('.').map(Number);
      if (octets.some((o) => o < 0 || o > 255)) {
        throw new Error(`Invalid ${fieldName}: IP address octets must be 0-255`);
      }
    }
  }

}

// =============================================================================
// ClickHouse Row Types
// =============================================================================

interface ClickHouseSignalRow {
  id: string;
  timestamp: string;
  tenant_id: string;
  sensor_id: string;
  signal_type: string;
  source_ip: string;
  anon_fingerprint: string;
  severity: string;
  confidence: number;
  event_count: number;
  metadata?: string | Record<string, unknown> | null;
}

interface ClickHouseCampaignRow {
  timestamp: string;
  campaign_id: string;
  event_type: string;
  name: string;
  status: string;
  severity: string;
  is_cross_tenant: 0 | 1;
  tenants_affected: number;
  confidence: number;
}

interface ClickHouseHourlyRow {
  hour: string;
  tenant_id: string;
  signal_type: string;
  severity: string;
  signal_count: number;
  total_events: number;
  unique_ips: number;
  unique_fingerprints: number;
}
