/**
 * Aggregator Service Tests
 * Tests signal batching, deduplication, backpressure, error handling,
 * and APIIntelligenceService integration
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Aggregator, type AggregatorConfig, type IncomingSignal } from './index.js';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { Correlator } from '../correlator/index.js';
import type { APIIntelligenceService } from '../api-intelligence/index.js';

// Mock Prisma client - use explicit type
const mockPrisma = {
  signal: {
    create: vi.fn(),
  },
  tenant: {
    findUnique: vi.fn().mockResolvedValue({ sharingPreference: 'CONTRIBUTE_AND_RECEIVE', anonymizationSalt: 'test-salt' }),
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

// Mock APIIntelligenceService - use explicit type
const createMockAPIIntelligence = (): APIIntelligenceService => ({
  processDiscoverySignal: vi.fn().mockResolvedValue(undefined),
  getEndpointsByPattern: vi.fn().mockResolvedValue([]),
  getEndpointByPath: vi.fn().mockResolvedValue(null),
  getEndpointHistory: vi.fn().mockResolvedValue({ changes: [], totalChanges: 0 }),
  getAllEndpoints: vi.fn().mockResolvedValue({ endpoints: [], total: 0 }),
  getStats: vi.fn().mockReturnValue({
    totalEndpoints: 0,
    totalChanges: 0,
    avgChangesPerEndpoint: 0,
    endpointsByMethod: {},
  }),
} as unknown as APIIntelligenceService);

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

  describe('idempotency store', () => {
    let mockIdempotencyStore: { checkAndAdd: ReturnType<typeof vi.fn> };
    let aggregatorWithIdempotency: Aggregator;

    beforeEach(() => {
      mockIdempotencyStore = {
        checkAndAdd: vi.fn().mockResolvedValue(true),
      };

      // Need findFirst for the duplicate-signal lookup fallback
      (mockPrisma as any).signal.findFirst = vi.fn().mockResolvedValue(null);

      aggregatorWithIdempotency = new Aggregator(
        mockPrisma,
        mockLogger,
        mockCorrelator,
        defaultConfig,
        undefined, // clickhouse
        undefined, // impossibleTravel
        undefined, // apiIntelligence
        undefined, // threatService
        undefined, // playbookTrigger
        mockIdempotencyStore as any
      );
    });

    afterEach(async () => {
      await aggregatorWithIdempotency.stop();
    });

    it('should store signal when checkAndAdd returns true (new signal)', async () => {
      mockIdempotencyStore.checkAndAdd.mockResolvedValue(true);

      aggregatorWithIdempotency.queueSignal(createTestSignal());
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockIdempotencyStore.checkAndAdd).toHaveBeenCalledTimes(1);
      expect(mockPrisma.signal.create).toHaveBeenCalledTimes(1);
    });

    it('should skip signal when checkAndAdd returns false (duplicate)', async () => {
      mockIdempotencyStore.checkAndAdd.mockResolvedValue(false);

      aggregatorWithIdempotency.queueSignal(createTestSignal());
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockIdempotencyStore.checkAndAdd).toHaveBeenCalledTimes(1);
      expect(mockPrisma.signal.create).not.toHaveBeenCalled();
    });

    it('should pass custom idempotencyKey to checkAndAdd when present', async () => {
      mockIdempotencyStore.checkAndAdd.mockResolvedValue(true);

      const signal = createTestSignal({ idempotencyKey: 'custom-key-abc' });
      aggregatorWithIdempotency.queueSignal(signal);
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockIdempotencyStore.checkAndAdd).toHaveBeenCalledWith(
        'custom-key-abc',
        expect.any(Number),
        expect.objectContaining({ tenantId: 'tenant-1' })
      );
    });
  });

  describe('backpressure warning', () => {
    it('should log warning when queue reaches 80% capacity', () => {
      // BUFFER_PRESSURE_THRESHOLD = 0.8. The check is: currentSize / maxQueueSize >= 0.8
      // currentSize is checked BEFORE the signal is pushed, so when queueing the 9th
      // signal into a maxQueueSize=10 queue, currentSize is 8, utilization = 8/10 = 0.8.
      const smallConfig = { ...defaultConfig, maxQueueSize: 10, batchSize: 100 };
      aggregator = new Aggregator(mockPrisma, mockLogger, mockCorrelator, smallConfig);

      // Queue 9 signals - at the 9th, currentSize is 8 (80%), triggering warning
      for (let i = 0; i < 9; i++) {
        aggregator.queueSignal(createTestSignal({ sourceIp: `192.168.1.${i}` }));
      }

      // The logger.child() returns mockReturnThis, so warn is on the child logger
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          utilization: expect.any(Number),
          queueSize: expect.any(Number),
          maxSize: 10,
        }),
        'Signal queue approaching capacity'
      );
    });

    it('should not log warning when queue is below 80% capacity', () => {
      const smallConfig = { ...defaultConfig, maxQueueSize: 20, batchSize: 100 };
      aggregator = new Aggregator(mockPrisma, mockLogger, mockCorrelator, smallConfig);

      // Queue 10 signals (50% of 20) - should not trigger warning
      for (let i = 0; i < 10; i++) {
        aggregator.queueSignal(createTestSignal({ sourceIp: `192.168.1.${i}` }));
      }

      // Check that warn was NOT called with the capacity message
      const warnCalls = vi.mocked(mockLogger.warn).mock.calls;
      const capacityCalls = warnCalls.filter(
        (args) => typeof args[1] === 'string' && args[1].includes('approaching capacity')
      );
      expect(capacityCalls).toHaveLength(0);
    });
  });

  describe('retryQueue', () => {
    it('should accept signals into retry queue during active flush', async () => {
      // Create a slow-resolving mock that gives us time to queue during flush
      let resolveFlush: () => void;
      const flushPromise = new Promise<void>((resolve) => {
        resolveFlush = resolve;
      });

      vi.mocked(mockPrisma.signal.create).mockImplementation(() => {
        return flushPromise.then(() => ({ id: 'signal-id-123' })) as any;
      });

      // Queue enough signals to trigger a flush
      for (let i = 0; i < 5; i++) {
        aggregator.queueSignal(createTestSignal({ sourceIp: `192.168.1.${i}` }));
      }

      // The batch flush is now in progress. Queue a signal during flush.
      // Need to give the flush a tick to start
      await vi.advanceTimersByTimeAsync(0);

      const result = aggregator.queueSignal(createTestSignal({ sourceIp: '10.0.0.1' }));
      expect(result.accepted).toBe(true);
      expect(result.reason).toBe('flushing');

      const stats = aggregator.getStats();
      expect(stats.retryQueueSize).toBe(1);

      // Now resolve the flush so cleanup works properly
      resolveFlush!();
      await vi.advanceTimersByTimeAsync(100);
    });
  });

  describe('ClickHouse write', () => {
    let mockClickhouse: { isEnabled: ReturnType<typeof vi.fn>; insertSignalEvents: ReturnType<typeof vi.fn> };
    let aggregatorWithCH: Aggregator;

    beforeEach(() => {
      mockClickhouse = {
        isEnabled: vi.fn().mockReturnValue(true),
        insertSignalEvents: vi.fn().mockResolvedValue(undefined),
      };

      // Ensure prisma.signal.create returns createdAt so writeToClickHouse doesn't fail
      vi.mocked(mockPrisma.signal.create).mockResolvedValue({
        id: 'signal-id-ch',
        createdAt: new Date('2025-01-01T00:00:00Z'),
      } as never);

      aggregatorWithCH = new Aggregator(
        mockPrisma,
        mockLogger,
        mockCorrelator,
        defaultConfig,
        mockClickhouse as any
      );
    });

    afterEach(async () => {
      await aggregatorWithCH.stop();
    });

    it('should store signals in Prisma with correct shape when ClickHouse is enabled', async () => {
      const signal = createTestSignal({
        sourceIp: '10.0.0.1',
        fingerprint: 'fp-test',
        severity: 'HIGH',
        confidence: 0.9,
        eventCount: 3,
      });

      aggregatorWithCH.queueSignal(signal);
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      // The signal should have been stored in Prisma with correct fields
      expect(mockPrisma.signal.create).toHaveBeenCalledTimes(1);
      const createCall = vi.mocked(mockPrisma.signal.create).mock.calls[0][0];
      expect(createCall.data).toMatchObject({
        tenantId: 'tenant-1',
        sensorId: 'sensor-1',
        signalType: 'IP_THREAT',
        sourceIp: '10.0.0.1',
        fingerprint: 'fp-test',
        severity: 'HIGH',
        confidence: 0.9,
        eventCount: 3,
      });

      // The ClickHouse retry buffer is initialized internally; verify insertSignalEvents
      // was called on the underlying clickhouse client (via the retry buffer)
      expect(mockClickhouse.insertSignalEvents).toHaveBeenCalledTimes(1);
      const rows = mockClickhouse.insertSignalEvents.mock.calls[0][0];
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        tenant_id: 'tenant-1',
        sensor_id: 'sensor-1',
        signal_type: 'IP_THREAT',
        source_ip: '10.0.0.1',
        fingerprint: 'fp-test',
        severity: 'HIGH',
        confidence: 0.9,
        event_count: 3,
      });
      expect(rows[0].timestamp).toBe('2025-01-01T00:00:00.000Z');
      expect(typeof rows[0].metadata).toBe('string');
    });
  });

  describe('impossible travel integration', () => {
    let mockImpossibleTravel: { processLogin: ReturnType<typeof vi.fn> };
    let aggregatorWithTravel: Aggregator;

    beforeEach(() => {
      mockImpossibleTravel = {
        processLogin: vi.fn().mockResolvedValue(undefined),
      };

      aggregatorWithTravel = new Aggregator(
        mockPrisma,
        mockLogger,
        mockCorrelator,
        defaultConfig,
        undefined, // clickhouse
        mockImpossibleTravel as any
      );
    });

    afterEach(async () => {
      await aggregatorWithTravel.stop();
    });

    it('should call processLogin when signal has geolocation metadata', async () => {
      const signal = createTestSignal({
        sourceIp: '10.0.0.1',
        fingerprint: 'user-fp-1',
        metadata: {
          latitude: 40.7128,
          longitude: -74.006,
          city: 'New York',
          countryCode: 'US',
        },
      });

      aggregatorWithTravel.queueSignal(signal);
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockImpossibleTravel.processLogin).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-fp-1',
          tenantId: 'tenant-1',
          ip: '10.0.0.1',
          location: expect.objectContaining({
            latitude: 40.7128,
            longitude: -74.006,
            city: 'New York',
            countryCode: 'US',
          }),
        })
      );
    });

    it('should NOT call processLogin when signal lacks geolocation metadata', async () => {
      const signal = createTestSignal({
        sourceIp: '10.0.0.1',
        metadata: { someField: 'value' },
      });

      aggregatorWithTravel.queueSignal(signal);
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockImpossibleTravel.processLogin).not.toHaveBeenCalled();
    });
  });

  describe('APIIntelligenceService integration', () => {
    let mockAPIIntelligence: APIIntelligenceService;
    let aggregatorWithAPIIntel: Aggregator;

    beforeEach(() => {
      mockAPIIntelligence = createMockAPIIntelligence();
      aggregatorWithAPIIntel = new Aggregator(
        mockPrisma,
        mockLogger,
        mockCorrelator,
        defaultConfig,
        undefined, // clickhouse
        undefined, // impossibleTravel
        mockAPIIntelligence
      );
    });

    afterEach(async () => {
      await aggregatorWithAPIIntel.stop();
    });

    it('should call APIIntelligenceService for TEMPLATE_DISCOVERY signals', async () => {
      const signal = createTestSignal({
        signalType: 'TEMPLATE_DISCOVERY',
        metadata: {
          template: '/api/users/{id}',
          method: 'GET',
          statusCode: 200,
        },
      });

      aggregatorWithAPIIntel.queueSignal(signal);
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockAPIIntelligence.processDiscoverySignal).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          sensorId: 'sensor-1',
          signalType: 'TEMPLATE_DISCOVERY',
          metadata: expect.objectContaining({
            template: '/api/users/{id}',
          }),
        }),
        expect.objectContaining({
          signalId: 'signal-id-123',
          swallowErrors: true,
          emitEvents: true,
        })
      );
    });

    it('should call APIIntelligenceService for SCHEMA_VIOLATION signals', async () => {
      const signal = createTestSignal({
        signalType: 'SCHEMA_VIOLATION',
        metadata: {
          endpoint: '/api/orders',
          violation: 'unexpected_field',
          field: 'extra_field',
        },
      });

      aggregatorWithAPIIntel.queueSignal(signal);
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockAPIIntelligence.processDiscoverySignal).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-1',
          sensorId: 'sensor-1',
          signalType: 'SCHEMA_VIOLATION',
          metadata: expect.objectContaining({
            endpoint: '/api/orders',
            violation: 'unexpected_field',
          }),
        }),
        expect.objectContaining({
          signalId: 'signal-id-123',
          swallowErrors: true,
        })
      );
    });

    it('should NOT call APIIntelligenceService for IP_THREAT signals', async () => {
      const signal = createTestSignal({
        signalType: 'IP_THREAT',
        sourceIp: '10.0.0.1',
      });

      aggregatorWithAPIIntel.queueSignal(signal);
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockAPIIntelligence.processDiscoverySignal).not.toHaveBeenCalled();
    });

    it('should NOT call APIIntelligenceService for BOT signals', async () => {
      const signal = createTestSignal({
        signalType: 'BOT',
        fingerprint: 'bot-fingerprint-123',
      });

      aggregatorWithAPIIntel.queueSignal(signal);
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockAPIIntelligence.processDiscoverySignal).not.toHaveBeenCalled();
    });

    it('should handle APIIntelligenceService errors gracefully', async () => {
      // Make APIIntelligenceService throw an error
      vi.mocked(mockAPIIntelligence.processDiscoverySignal).mockRejectedValueOnce(
        new Error('API Intelligence error')
      );

      const signal = createTestSignal({
        signalType: 'TEMPLATE_DISCOVERY',
        metadata: { template: '/api/error' },
      });

      aggregatorWithAPIIntel.queueSignal(signal);
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      // Signal should still be stored in Prisma (main flow not affected)
      expect(mockPrisma.signal.create).toHaveBeenCalled();
      // Correlator should still be called
      expect(mockCorrelator.analyzeSignals).toHaveBeenCalled();
    });

    it('should process multiple discovery signals in same batch', async () => {
      const signals = [
        createTestSignal({
          signalType: 'TEMPLATE_DISCOVERY',
          sourceIp: '192.168.1.1',
          metadata: { template: '/api/users' },
        }),
        createTestSignal({
          signalType: 'SCHEMA_VIOLATION',
          sourceIp: '192.168.1.2',
          metadata: { endpoint: '/api/orders' },
        }),
        createTestSignal({
          signalType: 'IP_THREAT', // Should not trigger API Intelligence
          sourceIp: '192.168.1.3',
        }),
      ];

      for (const signal of signals) {
        aggregatorWithAPIIntel.queueSignal(signal);
      }
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      // Should be called twice (TEMPLATE_DISCOVERY and SCHEMA_VIOLATION only)
      expect(mockAPIIntelligence.processDiscoverySignal).toHaveBeenCalledTimes(2);
    });

    it('should pass empty metadata when signal has no metadata', async () => {
      const signal = createTestSignal({
        signalType: 'TEMPLATE_DISCOVERY',
        metadata: undefined,
      });

      aggregatorWithAPIIntel.queueSignal(signal);
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      expect(mockAPIIntelligence.processDiscoverySignal).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: {},
        }),
        expect.any(Object)
      );
    });

    it('should work when APIIntelligenceService is not provided', async () => {
      // Create aggregator without API Intelligence service
      const aggregatorNoAPIIntel = new Aggregator(
        mockPrisma,
        mockLogger,
        mockCorrelator,
        defaultConfig
      );

      const signal = createTestSignal({
        signalType: 'TEMPLATE_DISCOVERY',
        metadata: { template: '/api/test' },
      });

      aggregatorNoAPIIntel.queueSignal(signal);
      await vi.advanceTimersByTimeAsync(defaultConfig.batchTimeoutMs + 100);

      // Should not throw, signal should still be stored
      expect(mockPrisma.signal.create).toHaveBeenCalled();

      await aggregatorNoAPIIntel.stop();
    });
  });
});
