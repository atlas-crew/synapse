/**
 * Aggregator Privacy Enforcement Tests
 * Verifies that SharingPreference is honored during signal ingestion
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Aggregator, type AggregatorConfig, type IncomingSignal } from './index.js';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { Correlator } from '../correlator/index.js';

// Mock Prisma client
const mockPrisma = {
  signal: {
    create: vi.fn(),
  },
  tenant: {
    findUnique: vi.fn(),
  },
} as unknown as PrismaClient;

// Mock Logger
const mockLogger = {
  child: vi.fn().mockReturnThis(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
} as unknown as Logger;

// Mock Correlator
const mockCorrelator = {
  analyzeSignals: vi.fn().mockResolvedValue([]),
} as unknown as Correlator;

const defaultConfig: AggregatorConfig = {
  batchSize: 1,
  batchTimeoutMs: 100,
};

function createTestSignal(overrides: Partial<IncomingSignal> = {}): IncomingSignal {
  return {
    tenantId: 'tenant-1',
    sensorId: 'sensor-1',
    signalType: 'IP_THREAT' as const,
    sourceIp: '1.2.3.4',
    fingerprint: 'test-fingerprint',
    severity: 'MEDIUM' as const,
    confidence: 0.85,
    eventCount: 1,
    ...overrides,
  } as IncomingSignal;
}

describe('Aggregator Privacy Enforcement', () => {
  let aggregator: Aggregator;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();

    // Mock crypto.subtle.digest for anonymization
    vi.stubGlobal('crypto', {
      subtle: {
        digest: vi.fn().mockResolvedValue(new Uint8Array(32).buffer),
      },
    });

    vi.mocked(mockPrisma.signal.create).mockResolvedValue({
      id: 'signal-123',
      createdAt: new Date(),
    } as never);

    aggregator = new Aggregator(mockPrisma, mockLogger, mockCorrelator, defaultConfig);
  });

  afterEach(async () => {
    await aggregator.stop();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('should generate anonFingerprint for CONTRIBUTE_AND_RECEIVE', async () => {
    vi.mocked(mockPrisma.tenant.findUnique).mockResolvedValue({
      id: 'tenant-1',
      sharingPreference: 'CONTRIBUTE_AND_RECEIVE',
    } as never);

    aggregator.queueSignal(createTestSignal());
    await vi.advanceTimersByTimeAsync(200);

    expect(mockCorrelator.analyzeSignals).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({
          sharingPreference: 'CONTRIBUTE_AND_RECEIVE',
          anonFingerprint: expect.any(String),
        }),
      ])
    );
  });

  it('should generate anonFingerprint for CONTRIBUTE_ONLY', async () => {
    vi.mocked(mockPrisma.tenant.findUnique).mockResolvedValue({
      id: 'tenant-1',
      sharingPreference: 'CONTRIBUTE_ONLY',
    } as never);

    aggregator.queueSignal(createTestSignal());
    await vi.advanceTimersByTimeAsync(200);

    expect(mockCorrelator.analyzeSignals).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({
          sharingPreference: 'CONTRIBUTE_ONLY',
          anonFingerprint: expect.any(String),
        }),
      ])
    );
  });

  it('should NOT generate anonFingerprint for RECEIVE_ONLY', async () => {
    vi.mocked(mockPrisma.tenant.findUnique).mockResolvedValue({
      id: 'tenant-1',
      sharingPreference: 'RECEIVE_ONLY',
    } as never);

    aggregator.queueSignal(createTestSignal());
    await vi.advanceTimersByTimeAsync(200);

    expect(mockCorrelator.analyzeSignals).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({
          sharingPreference: 'RECEIVE_ONLY',
          anonFingerprint: undefined,
        }),
      ])
    );
  });

  it('should NOT generate anonFingerprint for ISOLATED', async () => {
    vi.mocked(mockPrisma.tenant.findUnique).mockResolvedValue({
      id: 'tenant-1',
      sharingPreference: 'ISOLATED',
    } as never);

    aggregator.queueSignal(createTestSignal());
    await vi.advanceTimersByTimeAsync(200);

    expect(mockCorrelator.analyzeSignals).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({
          sharingPreference: 'ISOLATED',
          anonFingerprint: undefined,
        }),
      ])
    );
  });

  it('should default to CONTRIBUTE_AND_RECEIVE if tenant not found', async () => {
    vi.mocked(mockPrisma.tenant.findUnique).mockResolvedValue(null as never);

    aggregator.queueSignal(createTestSignal());
    await vi.advanceTimersByTimeAsync(200);

    expect(mockCorrelator.analyzeSignals).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({
          sharingPreference: 'CONTRIBUTE_AND_RECEIVE',
          anonFingerprint: expect.any(String),
        }),
      ])
    );
  });
});
