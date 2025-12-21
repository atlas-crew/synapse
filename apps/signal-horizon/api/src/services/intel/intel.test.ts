/**
 * Intel Service Tests
 * Tests IOC export, attack trends, and fleet intelligence summary
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IntelService, type IntelConfig } from './index.js';
import type { PrismaClient, Threat } from '@prisma/client';
import type { Logger } from 'pino';

// Mock Prisma client
const mockPrisma = {
  threat: {
    findMany: vi.fn(),
    count: vi.fn(),
  },
  signal: {
    count: vi.fn(),
    findMany: vi.fn(),
    groupBy: vi.fn(),
  },
  blocklistEntry: {
    count: vi.fn(),
    findMany: vi.fn(),
  },
  campaign: {
    count: vi.fn(),
    findMany: vi.fn(),
  },
  sensor: {
    count: vi.fn(),
  },
} as unknown as PrismaClient;

// Mock Logger
const mockLogger = {
  child: vi.fn().mockReturnThis(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
} as unknown as Logger;

const defaultConfig: IntelConfig = {
  maxExportLimit: 1000,
  defaultTrendWindowHours: 24,
  minRiskScoreForExport: 50,
};

function createThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    id: 'threat-123',
    tenantId: 'tenant-1',
    threatType: 'IP',
    indicator: '192.168.1.100',
    riskScore: 85,
    fleetRiskScore: 90,
    hitCount: 25,
    tenantsAffected: 3,
    isFleetThreat: true,
    firstSeenAt: new Date('2024-01-01'),
    lastSeenAt: new Date('2024-01-15'),
    metadata: {},
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as Threat;
}

describe('IntelService', () => {
  let intelService: IntelService;

  beforeEach(() => {
    vi.clearAllMocks();
    intelService = new IntelService(mockPrisma, mockLogger, defaultConfig);
  });

  describe('exportIOCs', () => {
    it('should export IOCs as JSON', async () => {
      vi.mocked(mockPrisma.threat.findMany).mockResolvedValue([
        createThreat({ indicator: '10.0.0.1', riskScore: 90 }),
        createThreat({ indicator: '10.0.0.2', riskScore: 85 }),
      ]);

      const result = await intelService.exportIOCs({ format: 'json' });
      const parsed = JSON.parse(result);

      expect(parsed.count).toBe(2);
      expect(parsed.iocs).toHaveLength(2);
      expect(parsed.iocs[0].indicator).toBe('10.0.0.1');
      expect(parsed.iocs[0].risk_score).toBe(90);
      expect(parsed.exported_at).toBeDefined();
    });

    it('should export IOCs as CSV', async () => {
      vi.mocked(mockPrisma.threat.findMany).mockResolvedValue([
        createThreat({ indicator: '10.0.0.1', riskScore: 90 }),
      ]);

      const result = await intelService.exportIOCs({ format: 'csv' });
      const lines = result.split('\n');

      expect(lines[0]).toContain('indicator');
      expect(lines[0]).toContain('type');
      expect(lines[0]).toContain('risk_score');
      expect(lines[1]).toContain('10.0.0.1');
    });

    it('should export IOCs as STIX 2.1 bundle', async () => {
      vi.mocked(mockPrisma.threat.findMany).mockResolvedValue([
        createThreat({ indicator: '10.0.0.1', threatType: 'IP' }),
      ]);

      const result = await intelService.exportIOCs({ format: 'stix' });
      const parsed = JSON.parse(result);

      expect(parsed.type).toBe('bundle');
      expect(parsed.id).toMatch(/^bundle--/);
      expect(parsed.objects).toHaveLength(1);
      expect(parsed.objects[0].type).toBe('indicator');
      expect(parsed.objects[0].spec_version).toBe('2.1');
      expect(parsed.objects[0].pattern).toContain('ipv4-addr');
    });

    it('should filter by minimum risk score', async () => {
      vi.mocked(mockPrisma.threat.findMany).mockResolvedValue([]);

      await intelService.exportIOCs({ format: 'json', minRiskScore: 80 });

      expect(mockPrisma.threat.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            riskScore: { gte: 80 },
          }),
        })
      );
    });

    it('should filter by threat types', async () => {
      vi.mocked(mockPrisma.threat.findMany).mockResolvedValue([]);

      await intelService.exportIOCs({
        format: 'json',
        threatTypes: ['IP', 'FINGERPRINT'],
      });

      expect(mockPrisma.threat.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            threatType: { in: ['IP', 'FINGERPRINT'] },
          }),
        })
      );
    });

    it('should filter fleet-only threats', async () => {
      vi.mocked(mockPrisma.threat.findMany).mockResolvedValue([]);

      await intelService.exportIOCs({ format: 'json', fleetOnly: true });

      expect(mockPrisma.threat.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            isFleetThreat: true,
          }),
        })
      );
    });

    it('should respect export limit', async () => {
      vi.mocked(mockPrisma.threat.findMany).mockResolvedValue([]);

      await intelService.exportIOCs({ format: 'json', limit: 50 });

      expect(mockPrisma.threat.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          take: 50,
        })
      );
    });

    it('should cap limit to maxExportLimit', async () => {
      vi.mocked(mockPrisma.threat.findMany).mockResolvedValue([]);

      await intelService.exportIOCs({ format: 'json', limit: 5000 });

      expect(mockPrisma.threat.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          take: defaultConfig.maxExportLimit,
        })
      );
    });

    it('should generate correct tags for IOCs', async () => {
      vi.mocked(mockPrisma.threat.findMany).mockResolvedValue([
        createThreat({
          isFleetThreat: true,
          tenantsAffected: 5,
          riskScore: 95,
          hitCount: 150,
        }),
      ]);

      const result = await intelService.exportIOCs({ format: 'json' });
      const parsed = JSON.parse(result);

      expect(parsed.iocs[0].tags).toContain('fleet-threat');
      expect(parsed.iocs[0].tags).toContain('cross-tenant');
      expect(parsed.iocs[0].tags).toContain('high-risk');
      expect(parsed.iocs[0].tags).toContain('high-volume');
    });
  });

  describe('getAttackTrends', () => {
    beforeEach(() => {
      // Setup default mock returns
      vi.mocked(mockPrisma.signal.count).mockResolvedValue(100);
      vi.mocked(mockPrisma.threat.count).mockResolvedValue(50);
      vi.mocked(mockPrisma.blocklistEntry.count).mockResolvedValue(25);
      vi.mocked(mockPrisma.signal.groupBy).mockResolvedValue([
        { signalType: 'CREDENTIAL_STUFFING', _count: { _all: 40 } },
        { signalType: 'BRUTE_FORCE', _count: { _all: 30 } },
      ] as never);
      vi.mocked(mockPrisma.threat.findMany).mockResolvedValue([]);
      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([]);
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([]);
    });

    it('should return attack trends with totals', async () => {
      const result = await intelService.getAttackTrends(null, 24);

      expect(result.totalSignals).toBe(100);
      expect(result.totalThreats).toBe(50);
      expect(result.totalBlocks).toBe(25);
      expect(result.timeRange.from).toBeInstanceOf(Date);
      expect(result.timeRange.to).toBeInstanceOf(Date);
    });

    it('should group signals by type', async () => {
      const result = await intelService.getAttackTrends(null, 24);

      expect(result.signalsByType).toEqual({
        CREDENTIAL_STUFFING: 40,
        BRUTE_FORCE: 30,
      });
    });

    it('should filter by tenant when provided', async () => {
      await intelService.getAttackTrends('tenant-123', 24);

      expect(mockPrisma.signal.count).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tenantId: 'tenant-123',
          }),
        })
      );
    });

    it('should return top IPs', async () => {
      vi.mocked(mockPrisma.threat.findMany).mockResolvedValue([
        createThreat({ indicator: '10.0.0.1', hitCount: 100, riskScore: 90 }),
        createThreat({ indicator: '10.0.0.2', hitCount: 50, riskScore: 75 }),
      ]);

      const result = await intelService.getAttackTrends(null, 24);

      expect(result.topIPs).toHaveLength(2);
      expect(result.topIPs[0].ip).toBe('10.0.0.1');
      expect(result.topIPs[0].count).toBe(100);
    });
  });

  describe('getFleetSummary', () => {
    beforeEach(() => {
      vi.mocked(mockPrisma.sensor.count).mockResolvedValue(10);
      vi.mocked(mockPrisma.threat.count)
        .mockResolvedValueOnce(500) // total threats
        .mockResolvedValueOnce(50); // fleet threats
      vi.mocked(mockPrisma.campaign.count).mockResolvedValue(5);
      vi.mocked(mockPrisma.blocklistEntry.count).mockResolvedValue(1000);
      vi.mocked(mockPrisma.signal.count).mockResolvedValue(2500);
      vi.mocked(mockPrisma.signal.groupBy).mockResolvedValue([
        { signalType: 'CREDENTIAL_STUFFING', _count: { _all: 1000 } },
        { signalType: 'BRUTE_FORCE', _count: { _all: 800 } },
        { signalType: 'SQL_INJECTION', _count: { _all: 500 } },
      ] as never);
    });

    it('should return fleet summary with correct counts', async () => {
      const result = await intelService.getFleetSummary();

      expect(result.activeSensors).toBe(10);
      expect(result.totalThreats).toBe(500);
      expect(result.fleetThreats).toBe(50);
      expect(result.crossTenantCampaigns).toBe(5);
      expect(result.blockedIndicators).toBe(1000);
      expect(result.signalsLast24h).toBe(2500);
    });

    it('should calculate top attack types with percentages', async () => {
      const result = await intelService.getFleetSummary();

      expect(result.topAttackTypes).toHaveLength(3);
      expect(result.topAttackTypes[0].type).toBe('CREDENTIAL_STUFFING');
      expect(result.topAttackTypes[0].count).toBe(1000);
      expect(result.topAttackTypes[0].percentage).toBeCloseTo(43.5, 0);
    });
  });

  describe('exportBlocklist', () => {
    const mockEntries = [
      {
        id: 'block-1',
        tenantId: 'tenant-1',
        blockType: 'IP',
        indicator: '10.0.0.1',
        source: 'FLEET_INTEL',
        reason: 'Campaign detection',
        createdAt: new Date('2024-01-01'),
        expiresAt: new Date('2024-02-01'),
        propagationStatus: 'ACTIVE',
        updatedAt: new Date(),
      },
    ];

    beforeEach(() => {
      vi.mocked(mockPrisma.blocklistEntry.findMany).mockResolvedValue(mockEntries as never);
    });

    it('should export blocklist as JSON', async () => {
      const result = await intelService.exportBlocklist('tenant-1', 'json');
      const parsed = JSON.parse(result);

      expect(parsed.count).toBe(1);
      expect(parsed.entries[0].indicator).toBe('10.0.0.1');
      expect(parsed.entries[0].type).toBe('IP');
    });

    it('should export blocklist as CSV', async () => {
      const result = await intelService.exportBlocklist('tenant-1', 'csv');
      const lines = result.split('\n');

      expect(lines[0]).toContain('type');
      expect(lines[0]).toContain('indicator');
      expect(lines[1]).toContain('10.0.0.1');
    });

    it('should export blocklist as plain text', async () => {
      const result = await intelService.exportBlocklist('tenant-1', 'plain');

      expect(result).toBe('10.0.0.1');
    });

    it('should include tenant-specific and fleet-wide blocks', async () => {
      await intelService.exportBlocklist('tenant-1', 'json');

      expect(mockPrisma.blocklistEntry.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            OR: [{ tenantId: 'tenant-1' }, { tenantId: null }],
          },
        })
      );
    });
  });
});
