/**
 * Broadcaster Service Tests
 * Tests blocklist management, campaign notifications, and dashboard broadcasting
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Broadcaster, type BroadcasterConfig } from './index.js';
import type { PrismaClient, Campaign } from '@prisma/client';
import type { Logger } from 'pino';
import type { EnrichedSignal } from '../../types/protocol.js';

// Mock Prisma client - use explicit type
const mockPrisma = {
  blocklistEntry: {
    upsert: vi.fn(),
  },
} as unknown as PrismaClient;

// Mock Logger - use explicit type
const mockLogger = {
  child: vi.fn().mockReturnThis(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
} as unknown as Logger;

// Mock Dashboard Gateway
const mockDashboardGateway = {
  broadcastCampaignAlert: vi.fn(),
  broadcastBlocklistUpdate: vi.fn(),
  broadcastThreatAlert: vi.fn(),
};

const defaultConfig: BroadcasterConfig = {
  pushDelayMs: 50,
  cacheSize: 100000,
};

function createCampaign(overrides: Partial<Campaign> = {}): Campaign {
  return {
    id: 'campaign-123',
    name: 'Test Campaign',
    description: 'Cross-tenant attack campaign',
    status: 'ACTIVE',
    severity: 'HIGH',
    isCrossTenant: true,
    tenantsAffected: 3,
    confidence: 0.92,
    correlationSignals: {},
    firstSeenAt: new Date(),
    lastActivityAt: new Date(),
    metadata: {},
    tenantId: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as Campaign;
}

function createEnrichedSignal(overrides: Partial<EnrichedSignal> = {}): EnrichedSignal {
  // CREDENTIAL_STUFFING requires GeoMetadata with latitude/longitude
  const base = {
    tenantId: 'tenant-1',
    sensorId: 'sensor-1',
    signalType: 'CREDENTIAL_STUFFING' as const,
    metadata: { latitude: 37.7749, longitude: -122.4194 },
    sourceIp: '192.168.1.100',
    fingerprint: 'raw-fingerprint',
    anonFingerprint: 'anon-fingerprint-abc123',
    severity: 'HIGH' as const,
    confidence: 0.9,
    eventCount: 1,
    id: 'signal-id-123',
  };
  return { ...base, ...overrides } as EnrichedSignal;
}

describe('Broadcaster', () => {
  let broadcaster: Broadcaster;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(mockPrisma.blocklistEntry.upsert).mockResolvedValue({} as never);

    broadcaster = new Broadcaster(mockPrisma, mockLogger, defaultConfig);
    broadcaster.setDashboardGateway(mockDashboardGateway as never);
  });

  describe('onCampaignDetected', () => {
    it('should broadcast campaign alert to dashboards', async () => {
      const campaign = createCampaign();
      const signals = [createEnrichedSignal()];

      await broadcaster.onCampaignDetected(campaign, signals);

      expect(mockDashboardGateway.broadcastCampaignAlert).toHaveBeenCalledWith({
        type: 'campaign-detected',
        campaign: expect.objectContaining({
          id: 'campaign-123',
          name: 'Test Campaign',
          severity: 'HIGH',
          isCrossTenant: true,
          tenantsAffected: 3,
        }),
        timestamp: expect.any(Number),
      });
    });

    it('should create blocklist entries for high-confidence campaigns', async () => {
      const campaign = createCampaign({ confidence: 0.92 });
      const signals = [
        createEnrichedSignal({ sourceIp: '10.0.0.1', anonFingerprint: 'fp-1' }),
        createEnrichedSignal({ sourceIp: '10.0.0.2', anonFingerprint: 'fp-2' }),
      ];

      await broadcaster.onCampaignDetected(campaign, signals);

      // Should create blocks for both IPs and fingerprints
      expect(mockPrisma.blocklistEntry.upsert).toHaveBeenCalledTimes(4);
    });

    it('should not create blocklist entries for low-confidence campaigns', async () => {
      const campaign = createCampaign({ confidence: 0.7 });
      const signals = [createEnrichedSignal()];

      await broadcaster.onCampaignDetected(campaign, signals);

      expect(mockDashboardGateway.broadcastCampaignAlert).toHaveBeenCalled();
      expect(mockPrisma.blocklistEntry.upsert).not.toHaveBeenCalled();
    });

    it('should broadcast blocklist updates after creating blocks', async () => {
      const campaign = createCampaign({ confidence: 0.9 });
      const signals = [createEnrichedSignal()];

      await broadcaster.onCampaignDetected(campaign, signals);

      expect(mockDashboardGateway.broadcastBlocklistUpdate).toHaveBeenCalledWith({
        updates: expect.arrayContaining([
          expect.objectContaining({
            type: 'add',
            blockType: 'IP',
            source: 'FLEET_INTEL',
          }),
        ]),
        campaign: 'campaign-123',
      });
    });

    it('should update blocklist cache', async () => {
      const campaign = createCampaign({ confidence: 0.9 });
      const signals = [createEnrichedSignal({ sourceIp: '10.0.0.50' })];

      await broadcaster.onCampaignDetected(campaign, signals);

      expect(broadcaster.isBlocked('IP', '10.0.0.50')).toBe(true);
      expect(broadcaster.getCacheSize()).toBeGreaterThan(0);
    });

    it('should handle signals without IP or fingerprint', async () => {
      const campaign = createCampaign({ confidence: 0.9 });
      const signals = [createEnrichedSignal({ sourceIp: undefined, anonFingerprint: undefined })];

      await broadcaster.onCampaignDetected(campaign, signals);

      // Should not error, just skip creating blocks
      expect(mockPrisma.blocklistEntry.upsert).not.toHaveBeenCalled();
    });

    it('should work without dashboard gateway set', async () => {
      const noDashboardBroadcaster = new Broadcaster(mockPrisma, mockLogger, defaultConfig);
      const campaign = createCampaign({ confidence: 0.9 });
      const signals = [createEnrichedSignal()];

      // Should not throw
      await expect(noDashboardBroadcaster.onCampaignDetected(campaign, signals)).resolves.not.toThrow();
    });
  });

  describe('broadcastThreatAlert', () => {
    it('should broadcast threat to dashboards', () => {
      const threat = {
        id: 'threat-123',
        threatType: 'BRUTE_FORCE' as const,
        indicator: '192.168.1.100',
        riskScore: 85,
        isFleetThreat: true,
      };

      broadcaster.broadcastThreatAlert(threat as never);

      expect(mockDashboardGateway.broadcastThreatAlert).toHaveBeenCalledWith({
        threat: expect.objectContaining({
          id: 'threat-123',
          threatType: 'BRUTE_FORCE',
          riskScore: 85,
          isFleetThreat: true,
        }),
        timestamp: expect.any(Number),
      });
    });
  });

  describe('blocklist cache', () => {
    it('should return empty blocklist initially', () => {
      expect(broadcaster.getBlocklist()).toEqual([]);
      expect(broadcaster.getCacheSize()).toBe(0);
    });

    it('should correctly check if indicator is blocked', async () => {
      const campaign = createCampaign({ confidence: 0.9 });
      const signals = [createEnrichedSignal({ sourceIp: '10.0.0.99' })];

      await broadcaster.onCampaignDetected(campaign, signals);

      expect(broadcaster.isBlocked('IP', '10.0.0.99')).toBe(true);
      expect(broadcaster.isBlocked('IP', '10.0.0.100')).toBe(false);
    });

    it('should return all cached blocklist entries', async () => {
      const campaign = createCampaign({ confidence: 0.9 });
      const signals = [
        createEnrichedSignal({ sourceIp: '10.0.0.1', anonFingerprint: 'fp-1' }),
        createEnrichedSignal({ sourceIp: '10.0.0.2', anonFingerprint: 'fp-2' }),
      ];

      await broadcaster.onCampaignDetected(campaign, signals);

      const blocklist = broadcaster.getBlocklist();
      expect(blocklist.length).toBe(4); // 2 IPs + 2 fingerprints
    });
  });

  describe('getConfig', () => {
    it('should return the broadcaster config', () => {
      const config = broadcaster.getConfig();
      expect(config).toEqual(defaultConfig);
    });
  });

  describe('stop', () => {
    it('should clear cache and gateway reference', async () => {
      const campaign = createCampaign({ confidence: 0.9 });
      const signals = [createEnrichedSignal()];

      await broadcaster.onCampaignDetected(campaign, signals);
      expect(broadcaster.getCacheSize()).toBeGreaterThan(0);

      broadcaster.stop();

      expect(broadcaster.getCacheSize()).toBe(0);
      expect(broadcaster.getBlocklist()).toEqual([]);
    });
  });

  describe('upsert behavior', () => {
    it('should upsert with fleet-wide tenantId (null)', async () => {
      const campaign = createCampaign({ confidence: 0.9 });
      const signals = [createEnrichedSignal({ sourceIp: '10.0.0.1' })];

      await broadcaster.onCampaignDetected(campaign, signals);

      // Verify the first call is for IP block
      const calls = vi.mocked(mockPrisma.blocklistEntry.upsert).mock.calls;
      const ipCall = calls.find((call) => call[0]?.where?.blockType_indicator_tenantId?.blockType === 'IP');

      expect(ipCall).toBeDefined();
      expect(ipCall![0]).toMatchObject({
        where: {
          blockType_indicator_tenantId: {
            blockType: 'IP',
            indicator: '10.0.0.1',
            tenantId: null, // Fleet-wide block uses null tenantId
          },
        },
        create: {
          blockType: 'IP',
          indicator: '10.0.0.1',
          source: 'FLEET_INTEL',
          propagationStatus: 'PENDING',
          reason: expect.stringContaining('Campaign'),
        },
      });
    });
  });
});
