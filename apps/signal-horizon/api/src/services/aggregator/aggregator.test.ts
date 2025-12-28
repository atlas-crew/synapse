/**
 * Aggregator Service Tests
 * Tests signal batching, deduplication, backpressure, and error handling
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Aggregator, type AggregatorConfig, type IncomingSignal } from './index.js';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { Correlator } from '../correlator/index.js';

// Mock Prisma client - use explicit type
const mockPrisma = {
  signal: {
    create: vi.fn(),
  },
} as unknown as PrismaClient;

// Mock Logger - use explicit type
const mockLogger = {
  child: vi.fn().mockReturnThis(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
} as unknown as Logger;

// Mock Correlator - use explicit type
const mockCorrelator = {
  analyzeSignals: vi.fn().mockResolvedValue([]),
} as unknown as Correlator;

const defaultConfig: AggregatorConfig = {
  batchSize: 5,
  batchTimeoutMs: 1000,
  maxQueueSize: 100,
  maxRetries: 3,
};

function createTestSignal(overrides: Partial<IncomingSignal> = {}): IncomingSignal {
  // Base signal with IP_THREAT type (doesn't require metadata)
  const base = {
    tenantId: 'tenant-1',
    sensorId: 'sensor-1',
    signalType: 'IP_THREAT' as const,
    sourceIp: '192.168.1.100',
    fingerprint: 'test-fingerprint',
    severity: 'MEDIUM' as const,
    confidence: 0.85,
    eventCount: 1,
  };
  return { ...base, ...overrides } as IncomingSignal;
}

describe('Aggregator', () => {
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

    // Mock Prisma create to return an object with id
    vi.mocked(mockPrisma.signal.create).mockResolvedValue({
      id: 'signal-id-123',
    } as never);

    aggregator = new Aggregator(mockPrisma, mockLogger, mockCorrelator, defaultConfig);
  });

  afterEach(async () => {
    await aggregator.stop();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  describe('queueSignal', () => {
    it('should accept signals when queue is not full', () => {
      const signal = createTestSignal();
      const result = aggregator.queueSignal(signal);

      expect(result.accepted).toBe(true);
      expect(result.reason).toBe('queued');
      expect(result.queueSize).toBe(1);
    });

    it('should reject signals when queue is full (backpressure)', () => {
      // Fill the queue
      const smallConfig = { ...defaultConfig, maxQueueSize: 3 };
      aggregator = new Aggregator(mockPrisma, mockLogger, mockCorrelator, smallConfig);

      for (let i = 0; i < 3; i++) {
        aggregator.queueSignal(createTestSignal({ sourceIp: `192.168.1.${i}` }));
      }

      // Try to add one more
      const result = aggregator.queueSignal(createTestSignal());

      expect(result.accepted).toBe(false);
      expect(result.reason).toBe('queue_full');
    });

    it('should trigger batch flush when batch size reached', async () => {
      for (let i = 0; i < 5; i++) {
        aggregator.queueSignal(createTestSignal({ sourceIp: `192.168.1.${i}` }));
      }

      // Allow flush to complete - use advanceTimersByTime to avoid infinite loop
      await vi.advanceTimersByTimeAsync(100);

      expect(mockPrisma.signal.create).toHaveBeenCalledTimes(5);
      expect(mockCorrelator.analyzeSignals).toHaveBeenCalled();
    });
  });

  describe('deduplication', () => {
    it('should deduplicate signals with same type and IP', async () => {
      // Queue 3 signals with same IP
      for (let i = 0; i < 3; i++) {
        aggregator.queueSignal(createTestSignal({ eventCount: 1 }));
      }

      // Trigger flush
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      // Should only create 1 signal (deduped)
      expect(mockPrisma.signal.create).toHaveBeenCalledTimes(1);

      // Event count should be merged
      const createCall = vi.mocked(mockPrisma.signal.create).mock.calls[0][0];
      expect(createCall.data.eventCount).toBe(3);
    });

    it('should keep highest severity when deduplicating', async () => {
      aggregator.queueSignal(createTestSignal({ severity: 'LOW' }));
      aggregator.queueSignal(createTestSignal({ severity: 'CRITICAL' }));
      aggregator.queueSignal(createTestSignal({ severity: 'MEDIUM' }));

      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      const createCall = vi.mocked(mockPrisma.signal.create).mock.calls[0][0];
      expect(createCall.data.severity).toBe('CRITICAL');
    });

    it('should not deduplicate signals with different IPs', async () => {
      aggregator.queueSignal(createTestSignal({ sourceIp: '192.168.1.1' }));
      aggregator.queueSignal(createTestSignal({ sourceIp: '192.168.1.2' }));
      aggregator.queueSignal(createTestSignal({ sourceIp: '192.168.1.3' }));

      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockPrisma.signal.create).toHaveBeenCalledTimes(3);
    });
  });

  describe('batch timer', () => {
    it('should flush on timer even if batch size not reached', async () => {
      aggregator.queueSignal(createTestSignal());
      aggregator.queueSignal(createTestSignal({ sourceIp: '192.168.1.2' }));

      // Wait for timer
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockPrisma.signal.create).toHaveBeenCalledTimes(2);
    });

    it('should not flush empty batch', async () => {
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockPrisma.signal.create).not.toHaveBeenCalled();
    });
  });

  describe('error handling', () => {
    it('should retry on failure', async () => {
      vi.mocked(mockPrisma.signal.create)
        .mockRejectedValueOnce(new Error('DB error'))
        .mockResolvedValue({ id: 'signal-id-123' } as never);

      aggregator.queueSignal(createTestSignal());

      // First flush fails
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);
      expect(mockLogger.error).toHaveBeenCalled();

      // Second flush succeeds
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);
      expect(mockPrisma.signal.create).toHaveBeenCalledTimes(2);
    });

    it('should drop batch after max retries', async () => {
      vi.mocked(mockPrisma.signal.create).mockRejectedValue(new Error('DB error'));

      aggregator.queueSignal(createTestSignal());

      // Exhaust retries
      for (let i = 0; i < 4; i++) {
        await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);
      }

      // Queue should be cleared
      const stats = aggregator.getStats();
      expect(stats.queueSize).toBe(0);
      expect(stats.retryCount).toBe(0);
    });
  });

  describe('getStats', () => {
    it('should return current queue statistics', () => {
      aggregator.queueSignal(createTestSignal());
      aggregator.queueSignal(createTestSignal({ sourceIp: '192.168.1.2' }));

      const stats = aggregator.getStats();

      expect(stats.queueSize).toBe(2);
      expect(stats.retryQueueSize).toBe(0);
      expect(stats.isFlushing).toBe(false);
      expect(stats.retryCount).toBe(0);
    });
  });

  describe('stop', () => {
    it('should flush remaining signals on stop', async () => {
      aggregator.queueSignal(createTestSignal());

      await aggregator.stop();

      expect(mockPrisma.signal.create).toHaveBeenCalled();
    });

    it('should clear batch timer on stop', async () => {
      await aggregator.stop();

      // Advance time - no flush should happen
      vi.clearAllMocks();
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs * 2);

      expect(mockPrisma.signal.create).not.toHaveBeenCalled();
    });
  });
});
