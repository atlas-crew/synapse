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

    const { sql, countSql } = this.buildClickHouseQuery(query);

    const [signals, countResult] = await Promise.all([
      this.clickhouse.query<ClickHouseSignalRow>(sql),
      this.clickhouse.queryOne<{ count: string }>(countSql),
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

    const start = startTime?.toISOString() ?? '1970-01-01 00:00:00';
    const end = endTime?.toISOString() ?? new Date().toISOString();

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
      WHERE campaign_id = '${this.escapeString(campaignId)}'
        AND timestamp >= toDateTime64('${start}', 3)
        AND timestamp <= toDateTime64('${end}', 3)
      ORDER BY timestamp ASC
    `;

    const rows = await this.clickhouse.query<ClickHouseCampaignRow>(sql);

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

    const start = startTime?.toISOString() ?? new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const end = endTime?.toISOString() ?? new Date().toISOString();

    let sql = `
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
      WHERE hour >= toStartOfHour(toDateTime64('${start}', 3))
        AND hour <= toStartOfHour(toDateTime64('${end}', 3))
    `;

    if (tenantId) {
      sql += ` AND tenant_id = '${this.escapeString(tenantId)}'`;
    }

    if (signalTypes && signalTypes.length > 0) {
      const types = signalTypes.map((t) => `'${this.escapeString(t)}'`).join(',');
      sql += ` AND signal_type IN (${types})`;
    }

    sql += ' ORDER BY hour DESC LIMIT 1000';

    const rows = await this.clickhouse.query<ClickHouseHourlyRow>(sql);

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
    if (!this.clickhouse?.isEnabled()) {
      // Fall back to PostgreSQL for recent data
      const signals = await this.prisma.signal.findMany({
        where: {
          sourceIp,
          createdAt: { gte: new Date(Date.now() - days * 24 * 60 * 60 * 1000) },
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
      WHERE source_ip = toIPv4('${this.escapeString(sourceIp)}')
        AND timestamp >= now() - INTERVAL ${days} DAY
    `;

    const result = await this.clickhouse.queryOne<{
      total_hits: string;
      tenants_hit: string;
      first_seen: string;
      last_seen: string;
      signal_types: string[];
    }>(sql);

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

  private buildClickHouseQuery(query: HuntQuery): { sql: string; countSql: string } {
    const limit = query.limit ?? 1000;
    const offset = query.offset ?? 0;

    let whereClause = `
      timestamp >= toDateTime64('${query.startTime.toISOString()}', 3)
      AND timestamp <= toDateTime64('${query.endTime.toISOString()}', 3)
    `;

    if (query.tenantId) {
      whereClause += ` AND tenant_id = '${this.escapeString(query.tenantId)}'`;
    }

    if (query.signalTypes && query.signalTypes.length > 0) {
      const types = query.signalTypes.map((t) => `'${this.escapeString(t)}'`).join(',');
      whereClause += ` AND signal_type IN (${types})`;
    }

    if (query.sourceIps && query.sourceIps.length > 0) {
      const ips = query.sourceIps.map((ip) => `toIPv4('${this.escapeString(ip)}')`).join(',');
      whereClause += ` AND source_ip IN (${ips})`;
    }

    if (query.severities && query.severities.length > 0) {
      const sevs = query.severities.map((s) => `'${this.escapeString(s)}'`).join(',');
      whereClause += ` AND severity IN (${sevs})`;
    }

    if (query.minConfidence !== undefined) {
      whereClause += ` AND confidence >= ${query.minConfidence}`;
    }

    if (query.anonFingerprint) {
      whereClause += ` AND anon_fingerprint = '${this.escapeString(query.anonFingerprint)}'`;
    }

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
        event_count
      FROM signal_events
      WHERE ${whereClause}
      ORDER BY timestamp DESC
      LIMIT ${limit} OFFSET ${offset}
    `;

    const countSql = `
      SELECT count() AS count
      FROM signal_events
      WHERE ${whereClause}
    `;

    return { sql, countSql };
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
    };
  }

  private mapClickHouseToResult(row: ClickHouseSignalRow): SignalResult {
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
    };
  }

  /**
   * Escape string for ClickHouse SQL injection prevention.
   * CRITICAL: Backslash must be escaped FIRST, then quotes.
   * Otherwise: "test'" → "test\'" → "test\\'" (broken)
   * Correct:  "test'" → "test'" → "test\'" (safe)
   */
  private escapeString(str: string): string {
    return str
      .replace(/\\/g, '\\\\')   // Backslash FIRST
      .replace(/'/g, "\\'")     // Then single quotes
      .replace(/\n/g, '\\n')    // Newlines
      .replace(/\r/g, '\\r')    // Carriage returns
      .replace(/\0/g, '');      // Null bytes (remove completely)
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
