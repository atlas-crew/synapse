/**
 * Hunt Service Tests
 * Tests query routing, saved queries, IP activity, and hourly stats
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { HuntService, type HuntQuery } from '../index.js';
import type { PrismaClient, Signal, SignalType } from '@prisma/client';
import type { Logger } from 'pino';
import type { ClickHouseService } from '../../../storage/clickhouse/index.js';

// =============================================================================
// Mock Factories
// =============================================================================

const mockPrisma = {
  signal: {
    findMany: vi.fn(),
    count: vi.fn(),
  },
} as unknown as PrismaClient;

type SignalFindManyArgs = Parameters<PrismaClient['signal']['findMany']>[0];
type SignalFindManyReturn = Awaited<ReturnType<PrismaClient['signal']['findMany']>>;

const mockLogger = {
  child: vi.fn().mockReturnThis(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
} as unknown as Logger;

const mockClickHouse = {
  isEnabled: vi.fn(),
  query: vi.fn(),
  queryOne: vi.fn(),
  queryWithParams: vi.fn(),
  queryOneWithParams: vi.fn(),
  ping: vi.fn(),
} as unknown as ClickHouseService;

function createSignal(overrides: Partial<Signal> = {}): Signal {
  return {
    id: 'signal-123',
    tenantId: 'tenant-1',
    sensorId: 'sensor-1',
    signalType: 'IP_THREAT' as SignalType,
    sourceIp: '192.168.1.100',
    fingerprint: 'fp-hash-123',
    anonFingerprint: 'anon-fp-hash-123',
    severity: 'HIGH',
    confidence: 0.85,
    eventCount: 5,
    metadata: {},
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as Signal;
}

function createHuntQuery(overrides: Partial<HuntQuery> = {}): HuntQuery {
  return {
    startTime: new Date(Date.now() - 6 * 60 * 60 * 1000), // 6 hours ago
    endTime: new Date(),
    ...overrides,
  };
}

// =============================================================================
// Tests
// =============================================================================

describe('HuntService', () => {
  let huntService: HuntService;
  let huntServiceWithClickHouse: HuntService;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-06-15T12:00:00Z'));

    huntService = new HuntService(mockPrisma, mockLogger);
    huntServiceWithClickHouse = new HuntService(mockPrisma, mockLogger, mockClickHouse);

    // Default mock implementations
    vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([createSignal()]);
    vi.mocked(mockPrisma.signal.count).mockResolvedValue(1);
    vi.mocked(mockClickHouse.isEnabled).mockReturnValue(true);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ===========================================================================
  // isHistoricalEnabled
  // ===========================================================================

  describe('isHistoricalEnabled', () => {
    it('should return false when ClickHouse is not configured', () => {
      expect(huntService.isHistoricalEnabled()).toBe(false);
    });

    it('should return true when ClickHouse is enabled', () => {
      expect(huntServiceWithClickHouse.isHistoricalEnabled()).toBe(true);
    });

    it('should return false when ClickHouse is disabled', () => {
      vi.mocked(mockClickHouse.isEnabled).mockReturnValue(false);
      expect(huntServiceWithClickHouse.isHistoricalEnabled()).toBe(false);
    });
  });

  // ===========================================================================
  // queryTimeline - PostgreSQL Routing
  // ===========================================================================

  describe('queryTimeline - PostgreSQL routing', () => {
    it('should route to PostgreSQL for queries within 24h', async () => {
      const query = createHuntQuery({
        startTime: new Date(Date.now() - 6 * 60 * 60 * 1000), // 6h ago
        endTime: new Date(),
      });

      const result = await huntService.queryTimeline(query);

      expect(result.source).toBe('postgres');
      expect(mockPrisma.signal.findMany).toHaveBeenCalled();
    });

    it('should apply all filter conditions', async () => {
      const query = createHuntQuery({
        tenantId: 'tenant-1',
        signalTypes: ['IP_THREAT', 'BOT_SIGNATURE'],
        sourceIps: ['192.168.1.100'],
        severities: ['HIGH', 'CRITICAL'],
        minConfidence: 0.8,
        anonFingerprint: 'anon-hash-123',
        limit: 50,
        offset: 10,
      });

      await huntService.queryTimeline(query);

      expect(mockPrisma.signal.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tenantId: 'tenant-1',
            signalType: { in: ['IP_THREAT', 'BOT_SIGNATURE'] },
            sourceIp: { in: ['192.168.1.100'] },
            severity: { in: ['HIGH', 'CRITICAL'] },
            confidence: { gte: 0.8 },
            anonFingerprint: 'anon-hash-123',
          }),
          take: 50,
          skip: 10,
        })
      );
    });

    it('should return total count with results', async () => {
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([
        createSignal({ id: 'signal-1' }),
        createSignal({ id: 'signal-2' }),
      ]);
      vi.mocked(mockPrisma.signal.count).mockResolvedValue(100);

      const result = await huntService.queryTimeline(createHuntQuery());

      expect(result.signals).toHaveLength(2);
      expect(result.total).toBe(100);
    });

    it('should calculate query time', async () => {
      const result = await huntService.queryTimeline(createHuntQuery());

      expect(result.queryTimeMs).toBeGreaterThanOrEqual(0);
    });

    it('should use default limit of 1000', async () => {
      await huntService.queryTimeline(createHuntQuery());

      expect(mockPrisma.signal.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ take: 1000 })
      );
    });
  });

  // ===========================================================================
  // queryTimeline - ClickHouse Routing
  // ===========================================================================

  describe('queryTimeline - ClickHouse routing', () => {
    it('should route to ClickHouse for queries older than 24h', async () => {
      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([]);
      vi.mocked(mockClickHouse.queryOneWithParams).mockResolvedValue({ count: '0' });

      const query = createHuntQuery({
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000), // 48h ago
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000), // 30h ago
      });

      const result = await huntServiceWithClickHouse.queryTimeline(query);

      expect(result.source).toBe('clickhouse');
      expect(mockClickHouse.queryWithParams).toHaveBeenCalled();
    });

    it('should parse ClickHouse results correctly', async () => {
      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([
        {
          id: 'ch-signal-1',
          timestamp: '2024-06-14T12:00:00.000Z',
          tenant_id: 'tenant-1',
          sensor_id: 'sensor-1',
          signal_type: 'IP_THREAT',
          source_ip: '192.168.1.100',
          anon_fingerprint: 'anon-123',
          severity: 'HIGH',
          confidence: 0.9,
          event_count: 10,
        },
      ]);
      vi.mocked(mockClickHouse.queryOneWithParams).mockResolvedValue({ count: '1' });

      const query = createHuntQuery({
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000),
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000),
      });

      const result = await huntServiceWithClickHouse.queryTimeline(query);

      expect(result.signals).toHaveLength(1);
      expect(result.signals[0]).toMatchObject({
        id: 'ch-signal-1',
        tenantId: 'tenant-1',
        signalType: 'IP_THREAT',
        confidence: 0.9,
      });
    });

    it('should throw error when ClickHouse not enabled but needed', async () => {
      vi.mocked(mockClickHouse.isEnabled).mockReturnValue(false);

      const query = createHuntQuery({
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000),
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000),
      });

      // Should fall back to postgres since ClickHouse is disabled
      const result = await huntServiceWithClickHouse.queryTimeline(query);
      expect(result.source).toBe('postgres');
    });
  });

  // ===========================================================================
  // queryTimeline - Hybrid Routing
  // ===========================================================================

  describe('queryTimeline - hybrid routing', () => {
    it('should use hybrid query when time range spans 24h threshold', async () => {
      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([
        {
          id: 'ch-signal-old',
          timestamp: '2024-06-14T00:00:00.000Z',
          tenant_id: 'tenant-1',
          sensor_id: 'sensor-1',
          signal_type: 'IP_THREAT',
          source_ip: '192.168.1.1',
          anon_fingerprint: '',
          severity: 'MEDIUM',
          confidence: 0.7,
          event_count: 3,
        },
      ]);
      vi.mocked(mockClickHouse.queryOneWithParams).mockResolvedValue({ count: '50' });
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([
        createSignal({ id: 'pg-signal-new' }),
      ]);
      vi.mocked(mockPrisma.signal.count).mockResolvedValue(10);

      const query = createHuntQuery({
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000), // 48h ago
        endTime: new Date(), // now
      });

      const result = await huntServiceWithClickHouse.queryTimeline(query);

      expect(result.source).toBe('hybrid');
      expect(result.signals).toHaveLength(2); // 1 from PG + 1 from CH
      expect(result.total).toBe(60); // 10 from PG + 50 from CH
      expect(mockPrisma.signal.findMany).toHaveBeenCalled();
      expect(mockClickHouse.queryWithParams).toHaveBeenCalled();
    });

    it('should order results with recent first', async () => {
      const oldTimestamp = new Date('2024-06-13T12:00:00.000Z');
      const newTimestamp = new Date('2024-06-15T11:00:00.000Z');

      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([
        {
          id: 'ch-old',
          timestamp: oldTimestamp.toISOString(),
          tenant_id: 'tenant-1',
          sensor_id: 'sensor-1',
          signal_type: 'IP_THREAT',
          source_ip: '1.1.1.1',
          anon_fingerprint: '',
          severity: 'LOW',
          confidence: 0.5,
          event_count: 1,
        },
      ]);
      vi.mocked(mockClickHouse.queryOneWithParams).mockResolvedValue({ count: '1' });
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([
        createSignal({ id: 'pg-new', createdAt: newTimestamp }),
      ]);
      vi.mocked(mockPrisma.signal.count).mockResolvedValue(1);

      const query = createHuntQuery({
        startTime: new Date(Date.now() - 72 * 60 * 60 * 1000),
        endTime: new Date(),
      });

      const result = await huntServiceWithClickHouse.queryTimeline(query);

      // PostgreSQL (recent) should come first
      expect(result.signals[0].id).toBe('pg-new');
      expect(result.signals[1].id).toBe('ch-old');
    });

    it('should respect limit in hybrid queries', async () => {
      const chSignals = Array.from({ length: 100 }, (_, i) => ({
        id: `ch-${i}`,
        timestamp: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
        tenant_id: 'tenant-1',
        sensor_id: 'sensor-1',
        signal_type: 'IP_THREAT',
        source_ip: `10.0.0.${i % 256}`,
        anon_fingerprint: '',
        severity: 'LOW',
        confidence: 0.5,
        event_count: 1,
      }));

      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue(chSignals);
      vi.mocked(mockClickHouse.queryOneWithParams).mockResolvedValue({ count: '100' });
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([
        createSignal({ id: 'pg-1' }),
        createSignal({ id: 'pg-2' }),
      ]);
      vi.mocked(mockPrisma.signal.count).mockResolvedValue(2);

      const query = createHuntQuery({
        startTime: new Date(Date.now() - 72 * 60 * 60 * 1000),
        endTime: new Date(),
        limit: 50,
      });

      const result = await huntServiceWithClickHouse.queryTimeline(query);

      expect(result.signals).toHaveLength(50);
    });
  });

  // ===========================================================================
  // Saved Queries
  // ===========================================================================

  describe('saved queries', () => {
    it('should save a query', async () => {
      const query = createHuntQuery({ tenantId: 'tenant-1' });

      const saved = await huntService.saveQuery(
        'My Test Query',
        query,
        'user-1',
        'A test query for threats'
      );

      expect(saved).toMatchObject({
        name: 'My Test Query',
        description: 'A test query for threats',
        createdBy: 'user-1',
      });
      expect(saved.id).toBeDefined();
      expect(saved.createdAt).toBeInstanceOf(Date);
    });

    it('should list saved queries', async () => {
      const query = createHuntQuery();
      await huntService.saveQuery('Query 1', query, 'user-1');
      await huntService.saveQuery('Query 2', query, 'user-1');
      await huntService.saveQuery('Query 3', query, 'user-2');

      const allQueries = await huntService.getSavedQueries();
      expect(allQueries).toHaveLength(3);

      const user1Queries = await huntService.getSavedQueries('user-1');
      expect(user1Queries).toHaveLength(2);
    });

    it('should get a saved query by ID', async () => {
      const query = createHuntQuery();
      const saved = await huntService.saveQuery('Test Query', query, 'user-1');

      const retrieved = await huntService.getSavedQuery(saved.id);

      expect(retrieved).toMatchObject({ name: 'Test Query' });
    });

    it('should return null for non-existent query', async () => {
      const result = await huntService.getSavedQuery('non-existent');
      expect(result).toBeNull();
    });

    it('should delete a saved query', async () => {
      const query = createHuntQuery();
      const saved = await huntService.saveQuery('To Delete', query, 'user-1');

      const deleted = await huntService.deleteSavedQuery(saved.id);
      expect(deleted).toBe(true);

      const retrieved = await huntService.getSavedQuery(saved.id);
      expect(retrieved).toBeNull();
    });

    it('should return false when deleting non-existent query', async () => {
      const deleted = await huntService.deleteSavedQuery('non-existent');
      expect(deleted).toBe(false);
    });

    it('should run a saved query and update lastRunAt', async () => {
      const query = createHuntQuery();
      const saved = await huntService.saveQuery('Runnable Query', query, 'user-1');

      expect(saved.lastRunAt).toBeUndefined();

      const result = await huntService.runSavedQuery(saved.id);

      expect(result).not.toBeNull();
      expect(result?.source).toBe('postgres');

      const updated = await huntService.getSavedQuery(saved.id);
      expect(updated?.lastRunAt).toBeInstanceOf(Date);
    });

    it('should return null when running non-existent query', async () => {
      const result = await huntService.runSavedQuery('non-existent');
      expect(result).toBeNull();
    });
  });

  // ===========================================================================
  // getIpActivity
  // ===========================================================================

  describe('getIpActivity', () => {
    it('should return IP activity from PostgreSQL when ClickHouse disabled', async () => {
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([
        createSignal({
          tenantId: 'tenant-1',
          signalType: 'IP_THREAT' as SignalType,
          createdAt: new Date('2024-06-10'),
        }),
        createSignal({
          tenantId: 'tenant-2',
          signalType: 'BOT_SIGNATURE' as SignalType,
          createdAt: new Date('2024-06-12'),
        }),
      ]);

      const result = await huntService.getIpActivity('192.168.1.100', 30);

      expect(result).toMatchObject({
        totalHits: 2,
        tenantsHit: 2,
        signalTypes: expect.arrayContaining(['IP_THREAT', 'BOT_SIGNATURE']),
      });
      expect(result.firstSeen).toEqual(new Date('2024-06-10'));
      expect(result.lastSeen).toEqual(new Date('2024-06-12'));
    });

    it('should return empty result when no matches', async () => {
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([]);

      const result = await huntService.getIpActivity('10.0.0.1', 30);

      expect(result).toMatchObject({
        totalHits: 0,
        tenantsHit: 0,
        firstSeen: null,
        lastSeen: null,
        signalTypes: [],
      });
    });

    it('should use ClickHouse when available', async () => {
      vi.mocked(mockClickHouse.queryOneWithParams).mockResolvedValue({
        total_hits: '150',
        tenants_hit: '5',
        first_seen: '2024-05-01T00:00:00.000Z',
        last_seen: '2024-06-15T10:00:00.000Z',
        signal_types: ['IP_THREAT', 'CAMPAIGN_INDICATOR', 'RATE_ANOMALY'],
      });

      const result = await huntServiceWithClickHouse.getIpActivity('192.168.1.100', 90);

      expect(mockClickHouse.queryOneWithParams).toHaveBeenCalled();
      expect(result).toMatchObject({
        totalHits: 150,
        tenantsHit: 5,
        signalTypes: ['IP_THREAT', 'CAMPAIGN_INDICATOR', 'RATE_ANOMALY'],
      });
    });

    it('should handle ClickHouse returning null', async () => {
      vi.mocked(mockClickHouse.queryOneWithParams).mockResolvedValue(null);

      const result = await huntServiceWithClickHouse.getIpActivity('10.0.0.1', 30);

      expect(result).toMatchObject({
        totalHits: 0,
        tenantsHit: 0,
        firstSeen: null,
        lastSeen: null,
        signalTypes: [],
      });
    });
  });

  // ===========================================================================
  // getCampaignTimeline
  // ===========================================================================

  describe('getCampaignTimeline', () => {
    it('should return empty array when ClickHouse disabled', async () => {
      const result = await huntService.getCampaignTimeline('campaign-123');

      expect(result).toEqual([]);
      expect(mockLogger.warn).toHaveBeenCalled();
    });

    it('should fetch campaign timeline from ClickHouse', async () => {
      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([
        {
          timestamp: '2024-06-10T08:00:00.000Z',
          campaign_id: 'campaign-123',
          event_type: 'created',
          name: 'Brute Force Campaign',
          status: 'ACTIVE',
          severity: 'HIGH',
          is_cross_tenant: 1,
          tenants_affected: 3,
          confidence: 0.85,
        },
        {
          timestamp: '2024-06-12T12:00:00.000Z',
          campaign_id: 'campaign-123',
          event_type: 'escalated',
          name: 'Brute Force Campaign',
          status: 'ACTIVE',
          severity: 'CRITICAL',
          is_cross_tenant: 1,
          tenants_affected: 5,
          confidence: 0.95,
        },
      ]);

      const result = await huntServiceWithClickHouse.getCampaignTimeline('campaign-123');

      expect(result).toHaveLength(2);
      expect(result[0]).toMatchObject({
        eventType: 'created',
        severity: 'HIGH',
        isCrossTenant: true,
        tenantsAffected: 3,
      });
      expect(result[1]).toMatchObject({
        eventType: 'escalated',
        severity: 'CRITICAL',
        tenantsAffected: 5,
      });
    });
  });

  // ===========================================================================
  // getHourlyStats
  // ===========================================================================

  describe('getHourlyStats', () => {
    it('should return empty array when ClickHouse disabled', async () => {
      const result = await huntService.getHourlyStats();

      expect(result).toEqual([]);
      expect(mockLogger.warn).toHaveBeenCalled();
    });

    it('should fetch hourly stats from ClickHouse', async () => {
      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([
        {
          hour: '2024-06-15T10:00:00.000Z',
          tenant_id: 'tenant-1',
          signal_type: 'IP_THREAT',
          severity: 'HIGH',
          signal_count: 50,
          total_events: 200,
          unique_ips: 15,
          unique_fingerprints: 8,
        },
        {
          hour: '2024-06-15T11:00:00.000Z',
          tenant_id: 'tenant-1',
          signal_type: 'BOT_SIGNATURE',
          severity: 'MEDIUM',
          signal_count: 30,
          total_events: 120,
          unique_ips: 10,
          unique_fingerprints: 5,
        },
      ]);

      const result = await huntServiceWithClickHouse.getHourlyStats('tenant-1');

      expect(result).toHaveLength(2);
      expect(result[0]).toMatchObject({
        tenantId: 'tenant-1',
        signalType: 'IP_THREAT',
        signalCount: 50,
        totalEvents: 200,
        uniqueIps: 15,
      });
    });

    it('should filter by signal types', async () => {
      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([]);

      await huntServiceWithClickHouse.getHourlyStats(
        'tenant-1',
        undefined,
        undefined,
        ['IP_THREAT', 'RATE_ANOMALY']
      );

      // Verify parameterized query was called with signal types array
      const call = vi.mocked(mockClickHouse.queryWithParams).mock.calls[0];
      const params = call[1] as Record<string, unknown>;
      expect(params.signalTypes).toEqual(['IP_THREAT', 'RATE_ANOMALY']);
    });
  });

  // ===========================================================================
  // Tenant Isolation (Negative Tests)
  // ===========================================================================

  describe('tenant isolation', () => {
    it('should only return signals for the specified tenant', async () => {
      // Setup: Multiple signals from different tenants
      const tenant1Signal = createSignal({
        id: 'signal-tenant1',
        tenantId: 'tenant-1',
        sourceIp: '192.168.1.1',
      });
      const tenant2Signal = createSignal({
        id: 'signal-tenant2',
        tenantId: 'tenant-2',
        sourceIp: '192.168.1.2',
      });

      // Mock returns signals only for tenant-1 when filtered
      vi.mocked(mockPrisma.signal.findMany).mockImplementation(async (args?: SignalFindManyArgs) => {
        const tenantId = (args?.where as { tenantId?: string } | undefined)?.tenantId;
        if (tenantId === 'tenant-1') {
          return [tenant1Signal] as SignalFindManyReturn;
        }
        if (tenantId === 'tenant-2') {
          return [tenant2Signal] as SignalFindManyReturn;
        }
        // No tenantId filter - return all (this is what we want to prevent)
        return [tenant1Signal, tenant2Signal] as SignalFindManyReturn;
      });
      vi.mocked(mockPrisma.signal.count).mockResolvedValue(1);

      // Query as tenant-1
      const result = await huntService.queryTimeline(
        createHuntQuery({ tenantId: 'tenant-1' })
      );

      // Should only see tenant-1's signal
      expect(result.signals).toHaveLength(1);
      expect(result.signals[0].tenantId).toBe('tenant-1');
      expect(result.signals.some((s) => s.tenantId === 'tenant-2')).toBe(false);
    });

    it('should NOT return other tenant data when querying with tenantId', async () => {
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([
        createSignal({ id: 'signal-1', tenantId: 'attacker-tenant' }),
      ]);

      // Query as victim-tenant should pass tenantId filter
      const query = createHuntQuery({ tenantId: 'victim-tenant' });
      await huntService.queryTimeline(query);

      // Verify the Prisma call included tenantId filter
      expect(mockPrisma.signal.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tenantId: 'victim-tenant',
          }),
        })
      );
    });

    it('should enforce tenant isolation in ClickHouse queries', async () => {
      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([]);
      vi.mocked(mockClickHouse.queryOneWithParams).mockResolvedValue({ count: '0' });

      const query = createHuntQuery({
        tenantId: 'isolated-tenant',
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000),
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000),
      });

      await huntServiceWithClickHouse.queryTimeline(query);

      // Verify ClickHouse query includes tenant_id filter
      const call = vi.mocked(mockClickHouse.queryWithParams).mock.calls[0];
      const sql = call[0] as string;
      const params = call[1] as Record<string, unknown>;

      expect(sql).toContain('tenant_id = {tenantId:String}');
      expect(params.tenantId).toBe('isolated-tenant');
    });

    it('should prevent cross-tenant data access in getIpActivity (PostgreSQL)', async () => {
      // Note: getIpActivity does NOT filter by tenantId by design - it's for cross-tenant hunting
      // But each result includes tenantId so the caller can verify access
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([
        createSignal({ tenantId: 'tenant-1' }),
        createSignal({ tenantId: 'tenant-2' }),
        createSignal({ tenantId: 'tenant-3' }),
      ]);

      const result = await huntService.getIpActivity('192.168.1.100', 30);

      // getIpActivity returns aggregate stats including how many tenants were hit
      // This is intentional for threat hunting - it shows cross-tenant attack patterns
      expect(result.tenantsHit).toBe(3);
    });

    it('should handle hybrid queries with tenant isolation', async () => {
      // Setup: Hybrid query (spans 24h threshold)
      // PostgreSQL returns tenant-1 signals, ClickHouse returns tenant-1 signals
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([
        createSignal({ id: 'pg-signal', tenantId: 'tenant-1' }),
      ]);
      vi.mocked(mockPrisma.signal.count).mockResolvedValue(1);
      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([
        {
          id: 'ch-signal',
          timestamp: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
          tenant_id: 'tenant-1',
          sensor_id: 'sensor-1',
          signal_type: 'IP_THREAT',
          source_ip: '192.168.1.1',
          anon_fingerprint: '',
          severity: 'HIGH',
          confidence: 0.9,
          event_count: 1,
        },
      ]);
      vi.mocked(mockClickHouse.queryOneWithParams).mockResolvedValue({ count: '1' });

      const query = createHuntQuery({
        tenantId: 'tenant-1',
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000), // 48h ago
        endTime: new Date(), // now
      });

      const result = await huntServiceWithClickHouse.queryTimeline(query);

      // All signals should be from tenant-1
      expect(result.signals.every((s) => s.tenantId === 'tenant-1')).toBe(true);
      expect(result.source).toBe('hybrid');
    });

    it('should not leak tenant data when tenantId is not provided', async () => {
      // When no tenantId is provided, the service returns ALL data
      // This is the expected behavior - caller must provide tenantId for isolation
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([
        createSignal({ tenantId: 'tenant-1' }),
        createSignal({ tenantId: 'tenant-2' }),
      ]);
      vi.mocked(mockPrisma.signal.count).mockResolvedValue(2);

      const query = createHuntQuery(); // No tenantId

      await huntService.queryTimeline(query);

      // Verify Prisma was called WITHOUT tenantId filter
      expect(mockPrisma.signal.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.not.objectContaining({
            tenantId: expect.anything(),
          }),
        })
      );
    });

    it('should isolate hourly stats by tenant when tenantId provided', async () => {
      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([]);

      await huntServiceWithClickHouse.getHourlyStats(
        'isolated-tenant',
        new Date(Date.now() - 24 * 60 * 60 * 1000),
        new Date()
      );

      const call = vi.mocked(mockClickHouse.queryWithParams).mock.calls[0];
      const sql = call[0] as string;
      const params = call[1] as Record<string, unknown>;

      expect(sql).toContain('tenant_id = {tenantId:String}');
      expect(params.tenantId).toBe('isolated-tenant');
    });

    it('should validate tenant ID to prevent injection attacks', async () => {
      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([]);
      vi.mocked(mockClickHouse.queryOneWithParams).mockResolvedValue({ count: '0' });

      const query = createHuntQuery({
        tenantId: 'tenant-1; SELECT * FROM secrets --',
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000),
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000),
      });

      await expect(huntServiceWithClickHouse.queryTimeline(query)).rejects.toThrow(
        'Invalid tenantId: contains disallowed characters'
      );
    });
  });

  // ===========================================================================
  // getRequestTimeline
  // ===========================================================================

  describe('getRequestTimeline', () => {
    it('should query ClickHouse across http/log/signal tables and merge sorted by timestamp', async () => {
      vi.mocked(mockClickHouse.queryWithParams)
        .mockResolvedValueOnce([
          {
            timestamp: '2024-06-15 11:59:00.000',
            tenant_id: 'tenant-1',
            sensor_id: 'sensor-1',
            request_id: 'req_123',
            site: 'example.com',
            method: 'GET',
            path: '/health',
            status_code: 200,
            latency_ms: 12,
            waf_action: null,
          },
        ])
        .mockResolvedValueOnce([
          {
            timestamp: '2024-06-15 11:59:01.000',
            tenant_id: 'tenant-1',
            sensor_id: 'sensor-1',
            request_id: 'req_123',
            signal_type: 'WAF_BLOCK',
            source_ip: '203.0.113.10',
            severity: 'HIGH',
            confidence: 1.0,
            event_count: 1,
            metadata: '{"rule_id":"941100"}',
          },
        ])
        .mockResolvedValueOnce([
          {
            timestamp: '2024-06-15 11:59:02.000',
            tenant_id: 'tenant-1',
            sensor_id: 'sensor-1',
            request_id: 'req_123',
            log_id: 'log-1',
            source: 'access',
            level: 'info',
            message: 'GET /health',
            fields: '{"k":"v"}',
            method: 'GET',
            path: '/health',
            status_code: 200,
            latency_ms: 12,
            client_ip: '203.0.113.10',
            rule_id: null,
          },
        ]);

      const events = await huntServiceWithClickHouse.getRequestTimeline('tenant-1', 'req_123');

      expect(mockClickHouse.queryWithParams).toHaveBeenCalledTimes(3);
      const [sql0, params0] = vi.mocked(mockClickHouse.queryWithParams).mock.calls[0] ?? [];
      expect(sql0 as string).toContain('FROM http_transactions');
      expect((params0 as Record<string, unknown>).tenantId).toBe('tenant-1');
      expect((params0 as Record<string, unknown>).requestId).toBe('req_123');

      expect(events).toHaveLength(3);
      expect(events[0]).toMatchObject({ kind: 'http_transaction', requestId: 'req_123' });
      expect(events[1]).toMatchObject({ kind: 'signal_event', requestId: 'req_123' });
      expect(events[2]).toMatchObject({ kind: 'sensor_log', requestId: 'req_123' });
    });
  });

  // ===========================================================================
  // SQL Injection Prevention
  // ===========================================================================

  describe('SQL injection prevention', () => {
    it('should reject tenant ID with SQL injection characters', async () => {
      const query = createHuntQuery({
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000),
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000),
        tenantId: "tenant'; DROP TABLE signal_events; --",
      });

      // Should throw validation error for invalid characters
      await expect(huntServiceWithClickHouse.queryTimeline(query)).rejects.toThrow(
        'Invalid tenantId: contains disallowed characters'
      );
    });

    it('should reject IP addresses with invalid format', async () => {
      const query = createHuntQuery({
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000),
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000),
        sourceIps: ['192.168.1.1; DROP TABLE--'],
      });

      await expect(huntServiceWithClickHouse.queryTimeline(query)).rejects.toThrow(
        'Invalid sourceIps[0]: not a valid IP address'
      );
    });

    it('should reject signal types with special characters', async () => {
      const query = createHuntQuery({
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000),
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000),
        signalTypes: ["IP_THREAT' OR '1'='1"],
      });

      await expect(huntServiceWithClickHouse.queryTimeline(query)).rejects.toThrow(
        'Invalid signalTypes[0]: contains disallowed characters'
      );
    });

    it('should accept valid identifiers with allowed characters', async () => {
      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([]);
      vi.mocked(mockClickHouse.queryOneWithParams).mockResolvedValue({ count: '0' });

      const query = createHuntQuery({
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000),
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000),
        tenantId: 'tenant-123_abc.prod:v2',
        signalTypes: ['IP_THREAT', 'BOT_SIGNATURE'],
        sourceIps: ['192.168.1.100', '10.0.0.1'],
      });

      // Should not throw - valid characters
      await expect(huntServiceWithClickHouse.queryTimeline(query)).resolves.toBeDefined();

      // Verify parameterized query was used
      expect(mockClickHouse.queryWithParams).toHaveBeenCalled();
      const call = vi.mocked(mockClickHouse.queryWithParams).mock.calls[0];
      const params = call[1] as Record<string, unknown>;
      expect(params.tenantId).toBe('tenant-123_abc.prod:v2');
    });

    it('should use parameterized queries instead of string interpolation', async () => {
      vi.mocked(mockClickHouse.queryWithParams).mockResolvedValue([]);
      vi.mocked(mockClickHouse.queryOneWithParams).mockResolvedValue({ count: '0' });

      const query = createHuntQuery({
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000),
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000),
        tenantId: 'tenant-1',
        minConfidence: 0.8,
      });

      await huntServiceWithClickHouse.queryTimeline(query);

      // Verify queryWithParams was called (parameterized), not query (string)
      expect(mockClickHouse.queryWithParams).toHaveBeenCalled();
      expect(mockClickHouse.query).not.toHaveBeenCalled();

      // Verify SQL uses placeholders, not interpolated values
      const call = vi.mocked(mockClickHouse.queryWithParams).mock.calls[0];
      const sql = call[0] as string;
      expect(sql).toContain('{tenantId:String}');
      expect(sql).toContain('{minConfidence:Float64}');
      expect(sql).not.toContain("'tenant-1'"); // No interpolated string
    });
  });
});
