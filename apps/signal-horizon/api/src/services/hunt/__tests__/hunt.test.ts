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
      vi.mocked(mockClickHouse.query).mockResolvedValue([]);
      vi.mocked(mockClickHouse.queryOne).mockResolvedValue({ count: '0' });

      const query = createHuntQuery({
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000), // 48h ago
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000), // 30h ago
      });

      const result = await huntServiceWithClickHouse.queryTimeline(query);

      expect(result.source).toBe('clickhouse');
      expect(mockClickHouse.query).toHaveBeenCalled();
    });

    it('should parse ClickHouse results correctly', async () => {
      vi.mocked(mockClickHouse.query).mockResolvedValue([
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
      vi.mocked(mockClickHouse.queryOne).mockResolvedValue({ count: '1' });

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
      vi.mocked(mockClickHouse.query).mockResolvedValue([
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
      vi.mocked(mockClickHouse.queryOne).mockResolvedValue({ count: '50' });
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
      expect(mockClickHouse.query).toHaveBeenCalled();
    });

    it('should order results with recent first', async () => {
      const oldTimestamp = new Date('2024-06-13T12:00:00.000Z');
      const newTimestamp = new Date('2024-06-15T11:00:00.000Z');

      vi.mocked(mockClickHouse.query).mockResolvedValue([
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
      vi.mocked(mockClickHouse.queryOne).mockResolvedValue({ count: '1' });
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
        source_ip: `10.0.0.${i}`,
        anon_fingerprint: '',
        severity: 'LOW',
        confidence: 0.5,
        event_count: 1,
      }));

      vi.mocked(mockClickHouse.query).mockResolvedValue(chSignals);
      vi.mocked(mockClickHouse.queryOne).mockResolvedValue({ count: '100' });
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
      vi.mocked(mockClickHouse.queryOne).mockResolvedValue({
        total_hits: '150',
        tenants_hit: '5',
        first_seen: '2024-05-01T00:00:00.000Z',
        last_seen: '2024-06-15T10:00:00.000Z',
        signal_types: ['IP_THREAT', 'CAMPAIGN_INDICATOR', 'RATE_ANOMALY'],
      });

      const result = await huntServiceWithClickHouse.getIpActivity('192.168.1.100', 90);

      expect(mockClickHouse.queryOne).toHaveBeenCalled();
      expect(result).toMatchObject({
        totalHits: 150,
        tenantsHit: 5,
        signalTypes: ['IP_THREAT', 'CAMPAIGN_INDICATOR', 'RATE_ANOMALY'],
      });
    });

    it('should handle ClickHouse returning null', async () => {
      vi.mocked(mockClickHouse.queryOne).mockResolvedValue(null);

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
      vi.mocked(mockClickHouse.query).mockResolvedValue([
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
      vi.mocked(mockClickHouse.query).mockResolvedValue([
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
      vi.mocked(mockClickHouse.query).mockResolvedValue([]);

      await huntServiceWithClickHouse.getHourlyStats(
        'tenant-1',
        undefined,
        undefined,
        ['IP_THREAT', 'RATE_ANOMALY']
      );

      const queryCall = vi.mocked(mockClickHouse.query).mock.calls[0][0];
      expect(queryCall).toContain("signal_type IN ('IP_THREAT','RATE_ANOMALY')");
    });
  });

  // ===========================================================================
  // SQL Injection Prevention
  // ===========================================================================

  describe('SQL injection prevention', () => {
    it('should escape single quotes in tenant ID', async () => {
      vi.mocked(mockClickHouse.query).mockResolvedValue([]);
      vi.mocked(mockClickHouse.queryOne).mockResolvedValue({ count: '0' });

      const query = createHuntQuery({
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000),
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000),
        tenantId: "tenant'; DROP TABLE signal_events; --",
      });

      await huntServiceWithClickHouse.queryTimeline(query);

      const queryCall = vi.mocked(mockClickHouse.query).mock.calls[0][0];
      // The single quote should be escaped to neutralize injection
      // Input: tenant'; DROP... → Output: tenant\'; DROP...
      // The backslash-quote (\') breaks the SQL injection attempt
      expect(queryCall).toContain("tenant\\'");
      // Verify the injection payload is neutralized (inside escaped string)
      expect(queryCall).not.toMatch(/tenant_id\s*=\s*'tenant';/);
    });
  });
});
