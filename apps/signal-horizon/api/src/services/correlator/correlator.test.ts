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

    it('should escalate confidence and severity based on sequential pattern (RECON -> EXPLOIT)', async () => {
      // 1. Initial RECON signals
      const reconSignals = [
        createEnrichedSignal({ 
          tenantId: 'tenant-1', 
          anonFingerprint: 'seq-fp', 
          signalType: 'TEMPLATE_DISCOVERY',
          confidence: 0.5 
        }),
        createEnrichedSignal({ 
          tenantId: 'tenant-2', 
          anonFingerprint: 'seq-fp', 
          signalType: 'TEMPLATE_DISCOVERY',
          confidence: 0.5 
        }),
      ];

      vi.mocked(mockPrisma.campaign.create).mockResolvedValue({
        id: 'camp-1',
        confidence: 0.6,
        metadata: { anonFingerprint: 'seq-fp', sequenceState: { currentStage: 'reconnaissance', history: [] } }
      } as never);

      await correlator.analyzeSignals(reconSignals);

      expect(mockPrisma.campaign.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          confidence: expect.any(Number),
          correlationSignals: expect.objectContaining({
            currentStage: 'reconnaissance'
          }),
        }),
      });

      // 2. Subsequent EXPLOIT signals
      const exploitSignals = [
        createEnrichedSignal({ 
          tenantId: 'tenant-1', 
          anonFingerprint: 'seq-fp', 
          signalType: 'SCHEMA_VIOLATION',
          confidence: 0.8 
        }),
        createEnrichedSignal({ 
          tenantId: 'tenant-3', 
          anonFingerprint: 'seq-fp', 
          signalType: 'SCHEMA_VIOLATION',
          confidence: 0.8 
        }),
      ];

      const existingCampaign = {
        id: 'camp-1',
        confidence: 0.6,
        severity: 'MEDIUM',
        metadata: { anonFingerprint: 'seq-fp', sequenceState: { currentStage: 'reconnaissance', history: [] } }
      };

      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([existingCampaign] as never);

      await correlator.analyzeSignals(exploitSignals);

      expect(mockPrisma.campaign.update).toHaveBeenCalledWith({
        where: { id: 'camp-1' },
        data: expect.objectContaining({
          confidence: expect.any(Number), // Confidence should boost on progression
        }),
      });

      const updateCall = vi.mocked(mockPrisma.campaign.update).mock.calls[0][0];
      const updatedConfidence = (updateCall.data as any).confidence;
      expect(updatedConfidence).toBeGreaterThan(0.6);
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

  describe('metadata resilience', () => {
    it('should handle malformed campaign metadata gracefully', async () => {
      const existingCampaign = {
        id: 'bad-meta-campaign',
        name: 'Bad Meta',
        status: 'ACTIVE',
        severity: 'MEDIUM',
        isCrossTenant: true,
        confidence: 0.6,
        tenantsAffected: 2,
        metadata: 'this-is-a-string-not-an-object',
      };

      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([existingCampaign] as never);
      vi.mocked(mockPrisma.campaign.update).mockResolvedValue(existingCampaign as never);

      const signals = [
        createEnrichedSignal({ tenantId: 'tenant-1', anonFingerprint: 'bad-meta-fp' }),
        createEnrichedSignal({ tenantId: 'tenant-2', anonFingerprint: 'bad-meta-fp' }),
      ];

      // Should not throw — falls back to safe defaults
      const results = await correlator.analyzeSignals(signals);

      // String metadata fails isCampaignMetadata, so no match found — creates new campaign
      expect(mockPrisma.campaign.create).toHaveBeenCalled();
    });

    it('should handle numeric campaign metadata gracefully', async () => {
      const existingCampaign = {
        id: 'num-meta-campaign',
        name: 'Num Meta',
        status: 'ACTIVE',
        severity: 'LOW',
        isCrossTenant: true,
        confidence: 0.5,
        tenantsAffected: 2,
        metadata: 42,
      };

      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([existingCampaign] as never);

      const signals = [
        createEnrichedSignal({ tenantId: 'tenant-1', anonFingerprint: 'num-fp' }),
        createEnrichedSignal({ tenantId: 'tenant-2', anonFingerprint: 'num-fp' }),
      ];

      // Should not throw — numeric metadata fails type guard
      const results = await correlator.analyzeSignals(signals);
      expect(mockPrisma.campaign.create).toHaveBeenCalled();
    });
  });

  describe('severity escalation via sequence', () => {
    it('should escalate to CRITICAL when exfiltration follows exploitation', async () => {
      const existingCampaign = {
        id: 'escalate-campaign',
        name: 'Escalate',
        status: 'ACTIVE',
        severity: 'HIGH',
        isCrossTenant: true,
        confidence: 0.7,
        tenantsAffected: 3,
        metadata: {
          anonFingerprint: 'esc-fp',
          signalCount: 5,
          sequenceState: {
            currentStage: 'exploitation',
            highestStage: 'exploitation',
            history: [{ stage: 'exploitation', signalId: 'prev', timestamp: '2026-01-01', confidence: 0.8 }],
          },
        },
      };

      vi.mocked(mockPrisma.campaign.findMany).mockResolvedValue([existingCampaign] as never);
      vi.mocked(mockPrisma.campaign.update).mockResolvedValue(existingCampaign as never);

      // Send DLP exfiltration signals
      const signals = [
        createEnrichedSignal({
          tenantId: 'tenant-1',
          anonFingerprint: 'esc-fp',
          signalType: 'SCHEMA_VIOLATION',
          metadata: { dlp_match_count: 3 },
          confidence: 0.9,
        }),
        createEnrichedSignal({
          tenantId: 'tenant-2',
          anonFingerprint: 'esc-fp',
          signalType: 'SCHEMA_VIOLATION',
          metadata: { dlp_match_count: 1 },
          confidence: 0.85,
        }),
      ];

      await correlator.analyzeSignals(signals);

      expect(mockPrisma.campaign.update).toHaveBeenCalledWith({
        where: { id: 'escalate-campaign' },
        data: expect.objectContaining({
          severity: 'CRITICAL',
          confidence: expect.any(Number),
        }),
      });

      // Verify confidence increased
      const updateCall = vi.mocked(mockPrisma.campaign.update).mock.calls[0][0];
      const updatedConfidence = (updateCall.data as any).confidence;
      expect(updatedConfidence).toBeGreaterThan(0.7);
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
