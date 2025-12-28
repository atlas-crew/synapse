/**
 * Correlator Service Tests
 * Tests cross-tenant campaign detection and correlation logic
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Correlator } from './index.js';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { Broadcaster } from '../broadcaster/index.js';
import type { EnrichedSignal } from '../../types/protocol.js';

// Mock Prisma client - use explicit type
const mockPrisma = {
  campaign: {
    findMany: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
  },
} as unknown as PrismaClient;

// Mock Logger - use explicit type
const mockLogger = {
  child: vi.fn().mockReturnThis(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
} as unknown as Logger;

// Mock Broadcaster - use explicit type
const mockBroadcaster = {
  onCampaignDetected: vi.fn().mockResolvedValue(undefined),
} as unknown as Broadcaster;

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

describe('Correlator', () => {
  let correlator: Correlator;

  beforeEach(() => {
    vi.clearAllMocks();

    // Default: no existing campaigns
    vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([]);
    vi.mocked(mockPrisma.campaign.create).mockResolvedValue({
      id: 'campaign-id-123',
      name: 'Test Campaign',
      status: 'ACTIVE',
      severity: 'HIGH',
      isCrossTenant: true,
      tenantsAffected: 2,
      confidence: 0.9,
    } as never);

    correlator = new Correlator(mockPrisma, mockLogger, mockBroadcaster);
  });

  describe('analyzeSignals', () => {
    it('should return empty array for null/empty input', async () => {
      expect(await correlator.analyzeSignals([])).toEqual([]);
      expect(await correlator.analyzeSignals(null as unknown as EnrichedSignal[])).toEqual([]);
    });

    it('should not detect campaign for single-tenant signals', async () => {
      const signals = [
        createEnrichedSignal({ tenantId: 'tenant-1', anonFingerprint: 'fp1' }),
        createEnrichedSignal({ tenantId: 'tenant-1', anonFingerprint: 'fp1' }),
      ];

      const results = await correlator.analyzeSignals(signals);

      expect(results).toHaveLength(0);
      expect(mockBroadcaster.onCampaignDetected).not.toHaveBeenCalled();
    });

    it('should detect campaign when same fingerprint spans 2+ tenants', async () => {
      const signals = [
        createEnrichedSignal({ tenantId: 'tenant-1', anonFingerprint: 'shared-fp' }),
        createEnrichedSignal({ tenantId: 'tenant-2', anonFingerprint: 'shared-fp' }),
        createEnrichedSignal({ tenantId: 'tenant-3', anonFingerprint: 'shared-fp' }),
      ];

      const results = await correlator.analyzeSignals(signals);

      expect(results).toHaveLength(1);
      expect(results[0].isCampaign).toBe(true);
      expect(results[0].campaignId).toBe('campaign-id-123');
      expect(mockBroadcaster.onCampaignDetected).toHaveBeenCalled();
    });

    it('should create new campaign when none exists', async () => {
      const signals = [
        createEnrichedSignal({ tenantId: 'tenant-1', anonFingerprint: 'new-fp' }),
        createEnrichedSignal({ tenantId: 'tenant-2', anonFingerprint: 'new-fp' }),
      ];

      await correlator.analyzeSignals(signals);

      expect(mockPrisma.campaign.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          name: expect.stringContaining('Fleet Campaign'),
          isCrossTenant: true,
          tenantsAffected: 2,
          status: 'ACTIVE',
        }),
      });
    });

    it('should update existing campaign instead of creating new one', async () => {
      const existingCampaign = {
        id: 'existing-campaign-id',
        name: 'Existing Campaign',
        status: 'ACTIVE',
        isCrossTenant: true,
        metadata: { anonFingerprint: 'existing-fp' },
      };

      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([existingCampaign] as never);

      const signals = [
        createEnrichedSignal({ tenantId: 'tenant-1', anonFingerprint: 'existing-fp' }),
        createEnrichedSignal({ tenantId: 'tenant-2', anonFingerprint: 'existing-fp' }),
      ];

      await correlator.analyzeSignals(signals);

      expect(mockPrisma.campaign.create).not.toHaveBeenCalled();
      expect(mockPrisma.campaign.update).toHaveBeenCalledWith({
        where: { id: 'existing-campaign-id' },
        data: expect.objectContaining({
          tenantsAffected: 2,
          lastActivityAt: expect.any(Date),
        }),
      });
    });

    it('should handle signals without anonFingerprint', async () => {
      const signals = [
        createEnrichedSignal({ anonFingerprint: undefined }),
        createEnrichedSignal({ anonFingerprint: undefined }),
      ];

      const results = await correlator.analyzeSignals(signals);

      expect(results).toHaveLength(0);
    });

    it('should detect multiple campaigns from different fingerprints', async () => {
      vi.mocked(mockPrisma.campaign.create)
        .mockResolvedValueOnce({ id: 'campaign-1', name: 'Campaign 1' } as never)
        .mockResolvedValueOnce({ id: 'campaign-2', name: 'Campaign 2' } as never);

      const signals = [
        // Campaign 1
        createEnrichedSignal({ tenantId: 'tenant-1', anonFingerprint: 'fp-1' }),
        createEnrichedSignal({ tenantId: 'tenant-2', anonFingerprint: 'fp-1' }),
        // Campaign 2
        createEnrichedSignal({ tenantId: 'tenant-3', anonFingerprint: 'fp-2' }),
        createEnrichedSignal({ tenantId: 'tenant-4', anonFingerprint: 'fp-2' }),
      ];

      const results = await correlator.analyzeSignals(signals);

      expect(results).toHaveLength(2);
      expect(mockBroadcaster.onCampaignDetected).toHaveBeenCalledTimes(2);
    });

    it('should calculate correct severity from signals', async () => {
      const signals = [
        createEnrichedSignal({ tenantId: 'tenant-1', anonFingerprint: 'fp', severity: 'LOW' }),
        createEnrichedSignal({ tenantId: 'tenant-2', anonFingerprint: 'fp', severity: 'CRITICAL' }),
        createEnrichedSignal({ tenantId: 'tenant-3', anonFingerprint: 'fp', severity: 'MEDIUM' }),
      ];

      await correlator.analyzeSignals(signals);

      expect(mockPrisma.campaign.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          severity: 'CRITICAL',
        }),
      });
    });
  });

  describe('batch lookup optimization', () => {
    it('should query campaigns only once for multiple fingerprints', async () => {
      const signals = [
        createEnrichedSignal({ tenantId: 'tenant-1', anonFingerprint: 'fp-1' }),
        createEnrichedSignal({ tenantId: 'tenant-2', anonFingerprint: 'fp-1' }),
        createEnrichedSignal({ tenantId: 'tenant-3', anonFingerprint: 'fp-2' }),
        createEnrichedSignal({ tenantId: 'tenant-4', anonFingerprint: 'fp-2' }),
      ];

      await correlator.analyzeSignals(signals);

      // Should only call findMany once (batch lookup)
      expect(mockPrisma.campaign.findMany).toHaveBeenCalledTimes(1);
    });
  });

  describe('error handling', () => {
    it('should continue processing other fingerprints on individual error', async () => {
      vi.mocked(mockPrisma.campaign.create)
        .mockRejectedValueOnce(new Error('DB error'))
        .mockResolvedValueOnce({ id: 'campaign-2', name: 'Campaign 2' } as never);

      const signals = [
        createEnrichedSignal({ tenantId: 'tenant-1', anonFingerprint: 'fp-1' }),
        createEnrichedSignal({ tenantId: 'tenant-2', anonFingerprint: 'fp-1' }),
        createEnrichedSignal({ tenantId: 'tenant-3', anonFingerprint: 'fp-2' }),
        createEnrichedSignal({ tenantId: 'tenant-4', anonFingerprint: 'fp-2' }),
      ];

      const results = await correlator.analyzeSignals(signals);

      // First campaign failed, second succeeded
      expect(results).toHaveLength(1);
      expect(mockLogger.error).toHaveBeenCalled();
    });
  });

  describe('confidence calculation', () => {
    it('should calculate confidence based on signal count and individual confidences', async () => {
      const signals = [
        createEnrichedSignal({ tenantId: 'tenant-1', anonFingerprint: 'fp', confidence: 0.8 }),
        createEnrichedSignal({ tenantId: 'tenant-2', anonFingerprint: 'fp', confidence: 0.9 }),
        createEnrichedSignal({ tenantId: 'tenant-3', anonFingerprint: 'fp', confidence: 0.7 }),
      ];

      const results = await correlator.analyzeSignals(signals);

      expect(results[0].confidence).toBeGreaterThanOrEqual(0.75);
      expect(results[0].confidence).toBeLessThanOrEqual(0.95);
    });
  });
});
