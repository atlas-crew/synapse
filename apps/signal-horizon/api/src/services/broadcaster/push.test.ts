/**
 * Broadcaster Push Tests
 * Verifies that blocklist updates are pushed to sensors and dashboards correctly
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Broadcaster, type BroadcasterConfig } from './index.js';
import type { PrismaClient, Campaign } from '@prisma/client';
import type { Logger } from 'pino';
import type { EnrichedSignal } from '../../types/protocol.js';

// Mock Prisma client
const mockPrisma = {
  blocklistEntry: {
    upsert: vi.fn(),
  },
} as unknown as PrismaClient;

// Mock Logger
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

// Mock Sensor Gateway
const mockSensorGateway = {
  broadcastBlocklistPush: vi.fn(),
};

const defaultConfig: BroadcasterConfig = {
  pushDelayMs: 50,
  cacheSize: 100000,
};

function createCampaign(overrides: Partial<Campaign> = {}): Campaign {
  return {
    id: 'campaign-123',
    name: 'Test Campaign',
    status: 'ACTIVE',
    severity: 'HIGH',
    isCrossTenant: true,
    tenantsAffected: 3,
    confidence: 0.95,
    firstSeenAt: new Date(),
    lastActivityAt: new Date(),
    metadata: {},
    tenantId: null,
    ...overrides,
  } as Campaign;
}

function createEnrichedSignal(overrides: Partial<EnrichedSignal> = {}): EnrichedSignal {
  return {
    tenantId: 'tenant-1',
    sensorId: 'sensor-1',
    signalType: 'IP_THREAT' as const,
    sourceIp: '1.2.3.4',
    fingerprint: 'test-fingerprint',
    anonFingerprint: 'anon-fp-123',
    severity: 'HIGH' as const,
    confidence: 0.9,
    eventCount: 1,
    id: 'signal-123',
    ...overrides,
  } as EnrichedSignal;
}

describe('Broadcaster Push', () => {
  let broadcaster: Broadcaster;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(mockPrisma.blocklistEntry.upsert).mockResolvedValue({} as never);

    broadcaster = new Broadcaster(mockPrisma, mockLogger, defaultConfig);
    broadcaster.setDashboardGateway(mockDashboardGateway as never);
    broadcaster.setSensorGateway(mockSensorGateway as never);
  });

  it('should push blocklist updates to both dashboards and sensors', async () => {
    const campaign = createCampaign();
    const signals = [createEnrichedSignal({ sourceIp: '10.0.0.1' })];

    await broadcaster.onCampaignDetected(campaign, signals);

    // Verify dashboard broadcast
    expect(mockDashboardGateway.broadcastBlocklistUpdate).toHaveBeenCalledWith(
      expect.objectContaining({
        updates: expect.arrayContaining([
          expect.objectContaining({ indicator: '10.0.0.1' }),
        ]),
      })
    );

    // Verify sensor push
    expect(mockSensorGateway.broadcastBlocklistPush).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ indicator: '10.0.0.1' }),
      ])
    );
  });

  it('should honor tenantId in alerts', async () => {
    const campaign = createCampaign({ isCrossTenant: false, tenantId: 'tenant-abc' });
    const signals = [createEnrichedSignal({ tenantId: 'tenant-abc' })];

    await broadcaster.onCampaignDetected(campaign, signals);

    expect(mockDashboardGateway.broadcastCampaignAlert).toHaveBeenCalledWith(
      expect.objectContaining({
        campaign: expect.objectContaining({
          tenantId: 'tenant-abc',
          isCrossTenant: false,
        }),
      })
    );
  });
});
