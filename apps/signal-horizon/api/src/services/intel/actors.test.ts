/**
 * Actor Service Tests
 * Tests threat actor profile aggregation from campaigns and threats
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ActorService } from './actors.js';
import type { PrismaClient, Campaign, Threat, CampaignThreat } from '@prisma/client';
import type { Logger } from 'pino';

// =============================================================================
// Mock Setup
// =============================================================================

const mockPrisma = {
  campaign: {
    findMany: vi.fn(),
    findFirst: vi.fn(),
    findUnique: vi.fn(),
  },
  signal: {
    findMany: vi.fn(),
  },
  blocklistEntry: {
    findMany: vi.fn(),
  },
} as unknown as PrismaClient;

const mockLogger = {
  child: vi.fn().mockReturnThis(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
} as unknown as Logger;

// =============================================================================
// Factory Helpers
// =============================================================================

function createThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    id: 'threat-123',
    tenantId: 'tenant-1',
    threatType: 'IP',
    indicator: '192.168.1.100',
    anonIndicator: null,
    riskScore: 85,
    fleetRiskScore: 90,
    hitCount: 25,
    tenantsAffected: 3,
    isFleetThreat: true,
    firstSeenAt: new Date('2024-01-01'),
    lastSeenAt: new Date('2024-01-15'),
    ttl: null,
    metadata: {},
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as Threat;
}

function createCampaign(overrides: Partial<Campaign> = {}): Campaign {
  return {
    id: 'campaign-123',
    tenantId: 'tenant-1',
    name: 'APT-29 Campaign',
    description: 'Coordinated attack campaign',
    status: 'ACTIVE',
    severity: 'HIGH',
    isCrossTenant: false,
    tenantsAffected: 1,
    confidence: 0.85,
    correlationSignals: null,
    firstSeenAt: new Date('2024-01-01'),
    lastActivityAt: new Date(), // Recent activity for 'burst' pattern
    resolvedAt: null,
    resolvedBy: null,
    metadata: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as Campaign;
}

function createCampaignThreat(
  campaignId: string,
  threat: Threat,
  role: string
): CampaignThreat & { threat: Threat } {
  return {
    id: `link-${campaignId}-${threat.id}`,
    campaignId,
    threatId: threat.id,
    role,
    createdAt: new Date(),
    threat,
  } as CampaignThreat & { threat: Threat };
}

// =============================================================================
// Tests
// =============================================================================

describe('ActorService', () => {
  let actorService: ActorService;

  beforeEach(() => {
    vi.clearAllMocks();
    actorService = new ActorService(mockPrisma, mockLogger);
  });

  describe('listActors', () => {
    it('should return aggregated actor profiles from campaigns', async () => {
      const primaryThreat = createThreat({ id: 'threat-1', indicator: 'actor-fingerprint-123' });
      const ipThreat = createThreat({ id: 'threat-2', threatType: 'IP', indicator: '10.0.0.1' });
      const asnThreat = createThreat({ id: 'threat-3', threatType: 'ASN', indicator: 'AS12345' });

      const campaign = createCampaign();
      const campaignWithLinks = {
        ...campaign,
        threatLinks: [
          createCampaignThreat(campaign.id, primaryThreat, 'primary_actor'),
          createCampaignThreat(campaign.id, ipThreat, 'infrastructure'),
          createCampaignThreat(campaign.id, asnThreat, 'infrastructure'),
        ],
      };

      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([campaignWithLinks]);

      const result = await actorService.listActors({});

      expect(result).toHaveLength(1);
      expect(result[0].id).toBe(campaign.id);
      expect(result[0].name).toBe('APT-29 Campaign');
      expect(result[0].infrastructure.topIPs).toHaveLength(1);
      expect(result[0].infrastructure.topASNs).toHaveLength(1);
    });

    it('should filter actors by minRiskScore', async () => {
      const lowRiskThreat = createThreat({ riskScore: 30 });
      const campaign = createCampaign();
      const campaignWithLinks = {
        ...campaign,
        threatLinks: [createCampaignThreat(campaign.id, lowRiskThreat, 'primary_actor')],
      };

      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([campaignWithLinks]);

      const result = await actorService.listActors({ minRiskScore: 50 });

      // Actor should be filtered out due to low risk score
      expect(result).toHaveLength(0);
    });

    it('should filter actors with hasActiveCampaigns', async () => {
      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([]);

      await actorService.listActors({ hasActiveCampaigns: true });

      expect(mockPrisma.campaign.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            status: 'ACTIVE',
          }),
        })
      );
    });

    it('should respect pagination with limit and offset', async () => {
      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([]);

      await actorService.listActors({ limit: 10, offset: 20 });

      expect(mockPrisma.campaign.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          take: 10,
          skip: 20,
        })
      );
    });

    it('should apply tenant isolation when tenantId is provided', async () => {
      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([]);

      await actorService.listActors({ tenantId: 'tenant-123' });

      expect(mockPrisma.campaign.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tenantId: 'tenant-123',
          }),
        })
      );
    });

    it('should determine activity pattern correctly', async () => {
      // Test burst pattern (recent activity)
      const recentCampaign = createCampaign({ lastActivityAt: new Date() });
      const threat = createThreat();
      const recentCampaignWithLinks = {
        ...recentCampaign,
        threatLinks: [createCampaignThreat(recentCampaign.id, threat, 'primary_actor')],
      };

      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([recentCampaignWithLinks]);

      const result = await actorService.listActors({});
      expect(result[0].timeline.activityPattern).toBe('burst');
    });

    it('should return empty array when no campaigns have primary actors', async () => {
      const campaign = createCampaign();
      const threat = createThreat();
      // Only infrastructure, no primary_actor
      const campaignWithLinks = {
        ...campaign,
        threatLinks: [createCampaignThreat(campaign.id, threat, 'infrastructure')],
      };

      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([campaignWithLinks]);

      const result = await actorService.listActors({});

      expect(result).toHaveLength(0);
    });
  });

  describe('getActor', () => {
    it('should return full actor profile by ID', async () => {
      const primaryThreat = createThreat({ id: 'threat-1' });
      const ipThreat = createThreat({ id: 'threat-2', threatType: 'IP', indicator: '10.0.0.1' });

      const campaign = createCampaign({ id: 'actor-123' });
      const campaignWithLinks = {
        ...campaign,
        threatLinks: [
          createCampaignThreat(campaign.id, primaryThreat, 'primary_actor'),
          createCampaignThreat(campaign.id, ipThreat, 'infrastructure'),
        ],
      };

      vi.mocked(mockPrisma.campaign.findFirst).mockResolvedValue(campaignWithLinks);

      const result = await actorService.getActor('actor-123');

      expect(result).not.toBeNull();
      expect(result?.id).toBe('actor-123');
      expect(result?.name).toBe('APT-29 Campaign');
      expect(result?.infrastructure.topIPs).toHaveLength(1);
    });

    it('should return null for non-existent actor', async () => {
      vi.mocked(mockPrisma.campaign.findFirst).mockResolvedValue(null);

      const result = await actorService.getActor('non-existent');

      expect(result).toBeNull();
    });

    it('should apply tenant filter when tenantId is provided', async () => {
      vi.mocked(mockPrisma.campaign.findFirst).mockResolvedValue(null);

      await actorService.getActor('actor-123', 'tenant-456');

      expect(mockPrisma.campaign.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            id: 'actor-123',
            tenantId: 'tenant-456',
          }),
        })
      );
    });

    it('should calculate risk score from all linked threats', async () => {
      const threat1 = createThreat({ id: 'threat-1', riskScore: 80 });
      const threat2 = createThreat({ id: 'threat-2', riskScore: 60 });

      const campaign = createCampaign();
      const campaignWithLinks = {
        ...campaign,
        threatLinks: [
          createCampaignThreat(campaign.id, threat1, 'primary_actor'),
          createCampaignThreat(campaign.id, threat2, 'infrastructure'),
        ],
      };

      vi.mocked(mockPrisma.campaign.findFirst).mockResolvedValue(campaignWithLinks);

      const result = await actorService.getActor('actor-123');

      expect(result?.riskScore).toBe(70); // (80 + 60) / 2
    });
  });

  describe('getActorInfrastructure', () => {
    it('should group infrastructure by threat type', async () => {
      const ipThreat1 = createThreat({
        id: 'ip-1',
        threatType: 'IP',
        indicator: '10.0.0.1',
        hitCount: 100,
      });
      const ipThreat2 = createThreat({
        id: 'ip-2',
        threatType: 'IP',
        indicator: '10.0.0.2',
        hitCount: 50,
      });
      const asnThreat = createThreat({
        id: 'asn-1',
        threatType: 'ASN',
        indicator: 'AS12345',
        hitCount: 200,
      });
      const fingerprintThreat = createThreat({
        id: 'fp-1',
        threatType: 'FINGERPRINT',
        indicator: 'fp-hash-123',
        hitCount: 75,
      });
      const userAgentThreat = createThreat({
        id: 'ua-1',
        threatType: 'USER_AGENT',
        indicator: 'Mozilla/5.0 Bot',
        hitCount: 30,
      });

      const campaign = createCampaign();
      const campaignWithLinks = {
        ...campaign,
        threatLinks: [
          createCampaignThreat(campaign.id, ipThreat1, 'infrastructure'),
          createCampaignThreat(campaign.id, ipThreat2, 'infrastructure'),
          createCampaignThreat(campaign.id, asnThreat, 'infrastructure'),
          createCampaignThreat(campaign.id, fingerprintThreat, 'infrastructure'),
          createCampaignThreat(campaign.id, userAgentThreat, 'infrastructure'),
        ],
      };

      vi.mocked(mockPrisma.campaign.findUnique).mockResolvedValue(campaignWithLinks);

      const result = await actorService.getActorInfrastructure('actor-123');

      expect(result).not.toBeNull();
      expect(result?.ips).toHaveLength(2);
      expect(result?.asns).toHaveLength(1);
      expect(result?.fingerprints).toHaveLength(1);
      expect(result?.userAgents).toHaveLength(1);
    });

    it('should sort infrastructure by hit count descending', async () => {
      const ipThreat1 = createThreat({
        id: 'ip-1',
        threatType: 'IP',
        indicator: '10.0.0.1',
        hitCount: 50,
      });
      const ipThreat2 = createThreat({
        id: 'ip-2',
        threatType: 'IP',
        indicator: '10.0.0.2',
        hitCount: 100,
      });

      const campaign = createCampaign();
      const campaignWithLinks = {
        ...campaign,
        threatLinks: [
          createCampaignThreat(campaign.id, ipThreat1, 'infrastructure'),
          createCampaignThreat(campaign.id, ipThreat2, 'infrastructure'),
        ],
      };

      vi.mocked(mockPrisma.campaign.findUnique).mockResolvedValue(campaignWithLinks);

      const result = await actorService.getActorInfrastructure('actor-123');

      expect(result?.ips[0].indicator).toBe('10.0.0.2'); // Higher hit count first
      expect(result?.ips[0].hitCount).toBe(100);
    });

    it('should return null for non-existent actor', async () => {
      vi.mocked(mockPrisma.campaign.findUnique).mockResolvedValue(null);

      const result = await actorService.getActorInfrastructure('non-existent');

      expect(result).toBeNull();
    });
  });

  describe('getActorTimeline', () => {
    it('should return hourly buckets for the specified window', async () => {
      const threat = createThreat({ indicator: '10.0.0.1' });
      const campaign = createCampaign();
      const campaignWithLinks = {
        ...campaign,
        threatLinks: [createCampaignThreat(campaign.id, threat, 'infrastructure')],
      };

      vi.mocked(mockPrisma.campaign.findUnique).mockResolvedValue(campaignWithLinks);
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([]);
      vi.mocked(mockPrisma.blocklistEntry.findMany).mockResolvedValue([]);

      const result = await actorService.getActorTimeline('actor-123', 24);

      // Should have 24 hourly buckets
      expect(result).toHaveLength(24);
      expect(result[0]).toHaveProperty('timestamp');
      expect(result[0]).toHaveProperty('signalCount');
      expect(result[0]).toHaveProperty('blockCount');
    });

    it('should count signals and blocks in correct buckets', async () => {
      const threat = createThreat({ indicator: '10.0.0.1' });
      const campaign = createCampaign();
      const campaignWithLinks = {
        ...campaign,
        threatLinks: [createCampaignThreat(campaign.id, threat, 'infrastructure')],
      };

      // Create signals 2 hours ago (well within the 24-hour window)
      const hourMs = 60 * 60 * 1000;
      const twoHoursAgo = Date.now() - 2 * hourMs;
      const targetBucketStart = Math.floor(twoHoursAgo / hourMs) * hourMs;

      const signals = [
        { createdAt: new Date(targetBucketStart + 10 * 60 * 1000) }, // 10 mins into bucket
        { createdAt: new Date(targetBucketStart + 20 * 60 * 1000) }, // 20 mins into bucket
      ];
      const blocks = [
        { createdAt: new Date(targetBucketStart + 15 * 60 * 1000) }, // 15 mins into bucket
      ];

      vi.mocked(mockPrisma.campaign.findUnique).mockResolvedValue(campaignWithLinks);
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue(signals as never);
      vi.mocked(mockPrisma.blocklistEntry.findMany).mockResolvedValue(blocks as never);

      const result = await actorService.getActorTimeline('actor-123', 24);

      // Calculate total signals and blocks across all buckets
      const totalSignals = result.reduce((sum, entry) => sum + entry.signalCount, 0);
      const totalBlocks = result.reduce((sum, entry) => sum + entry.blockCount, 0);

      expect(totalSignals).toBe(2);
      expect(totalBlocks).toBe(1);
    });

    it('should return empty array for non-existent actor', async () => {
      vi.mocked(mockPrisma.campaign.findUnique).mockResolvedValue(null);

      const result = await actorService.getActorTimeline('non-existent');

      expect(result).toHaveLength(0);
    });

    it('should handle actors with no threat indicators', async () => {
      const campaign = createCampaign();
      const campaignWithLinks = {
        ...campaign,
        threatLinks: [],
      };

      vi.mocked(mockPrisma.campaign.findUnique).mockResolvedValue(campaignWithLinks);

      const result = await actorService.getActorTimeline('actor-123', 24);

      // Should return empty timeline with zero counts
      expect(result).toHaveLength(24);
      result.forEach((entry) => {
        expect(entry.signalCount).toBe(0);
        expect(entry.blockCount).toBe(0);
      });
    });

    it('should use default window of 168 hours (7 days)', async () => {
      const threat = createThreat({ indicator: '10.0.0.1' });
      const campaign = createCampaign();
      const campaignWithLinks = {
        ...campaign,
        threatLinks: [createCampaignThreat(campaign.id, threat, 'infrastructure')],
      };

      vi.mocked(mockPrisma.campaign.findUnique).mockResolvedValue(campaignWithLinks);
      vi.mocked(mockPrisma.signal.findMany).mockResolvedValue([]);
      vi.mocked(mockPrisma.blocklistEntry.findMany).mockResolvedValue([]);

      const result = await actorService.getActorTimeline('actor-123');

      expect(result).toHaveLength(168);
    });
  });
});
