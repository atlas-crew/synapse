/**
 * Rollout Orchestrator Service Tests
 *
 * P1 reliability tests for firmware rollout orchestration:
 * - 20% failure threshold enforcement
 * - Batch strategy correctness (canary, rolling, immediate)
 * - Concurrency cap respected
 * - Finalize sets correct status on completion
 * - Rollout abort on threshold breach
 * - Partial rollout status tracking
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { RolloutOrchestrator } from '../rollout-orchestrator.js';

// Prevent actual Redis/BullMQ connections
vi.mock('../../../jobs/queue.js', () => ({
  createQueue: vi.fn().mockReturnValue({
    add: vi.fn().mockResolvedValue({ id: 'mock-job-id' }),
    getJob: vi.fn().mockResolvedValue(null),
    close: vi.fn().mockResolvedValue(undefined),
    on: vi.fn(),
  }),
  QUEUE_NAMES: { ROLLOUT: 'rollout-jobs' },
}));

function createMockLogger(): Logger {
  return {
    child: vi.fn().mockReturnThis(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  } as unknown as Logger;
}

interface SensorInfo {
  id: string;
  name: string;
  version: string | null;
}

const RELEASE = {
  id: 'release-1',
  version: '2.0.0',
  binaryUrl: 'https://releases.example.com/v2.0.0',
  sha256: 'abc123',
  size: 50_000_000,
  changelog: 'Bug fixes',
};

function makeSensors(count: number): SensorInfo[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `sensor-${i + 1}`,
    name: `Sensor ${i + 1}`,
    version: '1.0.0',
  }));
}

/**
 * Creates a mock PrismaClient that tracks rollout progress records in memory.
 */
function createMockPrisma() {
  const progressRecords = new Map<string, { rolloutId: string; sensorId: string; status: string; error?: string }>();

  const mock = {
    rollout: {
      findUnique: vi.fn().mockImplementation(({ where }) => {
        return Promise.resolve({ id: where.id, status: 'in_progress' });
      }),
      update: vi.fn().mockResolvedValue({}),
    },
    rolloutProgress: {
      findMany: vi.fn().mockImplementation(({ where }) => {
        const records = Array.from(progressRecords.values()).filter(
          (r) => r.rolloutId === where.rolloutId
        );
        return Promise.resolve(records);
      }),
      updateMany: vi.fn().mockImplementation(({ where, data }) => {
        const sensorIds: string[] = where.sensorId?.in
          ? where.sensorId.in
          : where.sensorId
            ? [where.sensorId]
            : [];

        let count = 0;
        for (const sensorId of sensorIds) {
          const key = `${where.rolloutId}:${sensorId}`;
          const existing = progressRecords.get(key);
          if (existing) {
            if (data.status) existing.status = data.status;
            if (data.error !== undefined) existing.error = data.error;
            count++;
          }
        }
        return Promise.resolve({ count });
      }),
    },
    sensor: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    _progressRecords: progressRecords,
    _seedProgress(rolloutId: string, sensors: SensorInfo[]) {
      for (const sensor of sensors) {
        progressRecords.set(`${rolloutId}:${sensor.id}`, {
          rolloutId,
          sensorId: sensor.id,
          status: 'pending',
        });
      }
    },
  };

  return mock as unknown as PrismaClient & {
    _progressRecords: Map<string, { rolloutId: string; sensorId: string; status: string; error?: string }>;
    _seedProgress: (rolloutId: string, sensors: SensorInfo[]) => void;
  };
}

describe('RolloutOrchestrator', () => {
  let prisma: ReturnType<typeof createMockPrisma>;
  let logger: Logger;
  let orchestrator: RolloutOrchestrator;

  beforeEach(() => {
    prisma = createMockPrisma();
    logger = createMockLogger();
    // No fleetCommander => test mode (instant success path)
    orchestrator = new RolloutOrchestrator(prisma as unknown as PrismaClient, logger);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('20% failure threshold', () => {
    it('should continue when failures are below 20% threshold', async () => {
      // 10 sensors, MAX_TOTAL_FAILURES = max(1, floor(10 * 0.2)) = 2
      // In test mode (no fleetCommander), all succeed => 0 failures < 2 threshold
      const sensors = makeSensors(10);
      const rolloutId = 'rollout-threshold-under';
      prisma._seedProgress(rolloutId, sensors);

      await orchestrator.executeRollout('tenant-1', rolloutId, RELEASE, sensors, {
        strategy: 'immediate',
        batchSize: 100,
        batchDelay: 0,
      });

      // finalizeRollout should mark 'completed' because all are 'activated'
      const finalizeCalls = vi.mocked(prisma.rollout.update).mock.calls;
      const finalizeCall = finalizeCalls.find(
        (call) => (call[0] as any).data.completedAt !== undefined
      );
      expect(finalizeCall).toBeDefined();
      expect((finalizeCall![0] as any).data.status).toBe('completed');
    });

    it('should abort when failures reach 20% threshold', async () => {
      vi.useFakeTimers();

      // 5 sensors, MAX_TOTAL_FAILURES = max(1, floor(5 * 0.2)) = 1
      // Commander that fails on every send -> markSensorFailed for each
      // After processBatch, totalFailures (5) >= MAX_TOTAL_FAILURES (1) -> abort
      const sensors = makeSensors(5);
      const rolloutId = 'rollout-threshold-breach';
      prisma._seedProgress(rolloutId, sensors);

      const mockCommander = {
        sendCommand: vi.fn().mockRejectedValue(new Error('Connection refused')),
      };

      const failOrchestrator = new RolloutOrchestrator(
        prisma as unknown as PrismaClient,
        logger,
        mockCommander as any
      );

      // monitorBatchHealth needs sensor data; return old-version sensors
      vi.mocked(prisma.sensor.findMany).mockResolvedValue(
        sensors.map((s) => ({
          id: s.id,
          version: '1.0.0',
          connectionState: 'DISCONNECTED',
          lastHeartbeat: null,
        })) as any
      );

      // Run executeRollout but don't await yet - we need to advance timers
      const rolloutPromise = failOrchestrator.executeRollout(
        'tenant-1', rolloutId, RELEASE, sensors,
        { strategy: 'immediate', batchSize: 100, batchDelay: 0 }
      );

      // Advance timers past the monitoring timeout (60 seconds default buffer)
      // The loop polls every 5s, so advance enough for timeout expiry
      for (let i = 0; i < 15; i++) {
        await vi.advanceTimersByTimeAsync(5000);
      }

      await rolloutPromise;

      // All 5 sendCommand calls fail -> markSensorFailed called 5 times
      // totalFailures (5) >= MAX_TOTAL_FAILURES (1) -> abort logged
      expect(logger.error).toHaveBeenCalledWith(
        expect.objectContaining({ rolloutId }),
        expect.stringContaining('Failure threshold exceeded')
      );

      vi.useRealTimers();
    });
  });

  describe('Batch strategies', () => {
    it('should split canary batch as 10% first then remaining', async () => {
      const sensors = makeSensors(20);
      const rolloutId = 'rollout-canary';
      prisma._seedProgress(rolloutId, sensors);

      await orchestrator.executeRollout('tenant-1', rolloutId, RELEASE, sensors, {
        strategy: 'canary',
        batchSize: 5,
        batchDelay: 0,
      });

      // In test mode, each sensor gets two updateMany calls: downloading + activated.
      // Extract all 'downloading' calls to count how sensors were batched.
      const updateCalls = vi.mocked(prisma.rolloutProgress.updateMany).mock.calls;
      const downloadingSensorIds = updateCalls
        .filter((call) => (call[0] as any).data.status === 'downloading')
        .map((call) => (call[0] as any).where.sensorId)
        .filter(Boolean);

      // Canary for 20 sensors: first 2 (10%), then remaining 18
      // Total sensors that got 'downloading' = 20
      expect(downloadingSensorIds).toHaveLength(20);

      // First 2 should be canary sensors (sensor-1, sensor-2)
      expect(downloadingSensorIds.slice(0, 2)).toEqual(['sensor-1', 'sensor-2']);
      // Next 18 should be the remainder
      expect(downloadingSensorIds.slice(2)).toHaveLength(18);
    });

    it('should respect rolling batch size', async () => {
      const sensors = makeSensors(10);
      const rolloutId = 'rollout-rolling';
      prisma._seedProgress(rolloutId, sensors);

      await orchestrator.executeRollout('tenant-1', rolloutId, RELEASE, sensors, {
        strategy: 'rolling',
        batchSize: 3,
        batchDelay: 0,
      });

      // Extract 'downloading' calls to verify batching
      const updateCalls = vi.mocked(prisma.rolloutProgress.updateMany).mock.calls;
      const downloadingSensorIds = updateCalls
        .filter((call) => (call[0] as any).data.status === 'downloading')
        .map((call) => (call[0] as any).where.sensorId)
        .filter(Boolean);

      // 10 sensors with batchSize=3 => 4 batches (3+3+3+1) => all 10 get 'downloading'
      expect(downloadingSensorIds).toHaveLength(10);

      // Verify the isCancelled checks happened (one per batch iteration)
      // 4 batches => at least 4 isCancelled checks
      expect(vi.mocked(prisma.rollout.findUnique)).toHaveBeenCalledTimes(4);
    });
  });

  describe('Concurrency cap', () => {
    it('should not send more than 50 concurrent operations per batch chunk', async () => {
      const sensors = makeSensors(120);
      const rolloutId = 'rollout-concurrency';
      prisma._seedProgress(rolloutId, sensors);

      const concurrentCalls: number[] = [];
      let currentConcurrent = 0;

      const mockCommander = {
        sendCommand: vi.fn().mockImplementation(async () => {
          currentConcurrent++;
          concurrentCalls.push(currentConcurrent);
          await new Promise((resolve) => setTimeout(resolve, 1));
          currentConcurrent--;
          return 'cmd-id';
        }),
      };

      // Quickly cancel to avoid long monitoring waits
      vi.mocked(prisma.rollout.findUnique).mockResolvedValue({
        id: rolloutId,
        status: 'cancelled',
      } as any);

      const concurrentOrchestrator = new RolloutOrchestrator(
        prisma as unknown as PrismaClient,
        logger,
        mockCommander as any
      );

      await concurrentOrchestrator.executeRollout('tenant-1', rolloutId, RELEASE, sensors, {
        strategy: 'immediate',
        batchSize: 200,
        batchDelay: 0,
      });

      // The max concurrent calls should not exceed 50 (CONCURRENCY constant)
      const maxConcurrent = Math.max(...concurrentCalls);
      expect(maxConcurrent).toBeLessThanOrEqual(50);
    });
  });

  describe('Finalize sets correct status', () => {
    it('should set status to completed when all sensors are activated', async () => {
      const sensors = makeSensors(3);
      const rolloutId = 'rollout-finalize-ok';
      prisma._seedProgress(rolloutId, sensors);

      await orchestrator.executeRollout('tenant-1', rolloutId, RELEASE, sensors, {
        strategy: 'immediate',
        batchSize: 10,
        batchDelay: 0,
      });

      const finalizeCalls = vi.mocked(prisma.rollout.update).mock.calls;
      const finalizeCall = finalizeCalls.find(
        (call) => (call[0] as any).data.completedAt !== undefined
      );
      expect(finalizeCall).toBeDefined();
      expect((finalizeCall![0] as any).data.status).toBe('completed');
    });

    it('should set status to failed when all sensors failed', async () => {
      const sensors = makeSensors(3);
      const rolloutId = 'rollout-all-failed';
      prisma._seedProgress(rolloutId, sensors);

      // Override findMany to return all-failed for finalizeRollout
      vi.mocked(prisma.rolloutProgress.findMany).mockResolvedValue(
        sensors.map((s) => ({ rolloutId, sensorId: s.id, status: 'failed' })) as any
      );

      await orchestrator.executeRollout('tenant-1', rolloutId, RELEASE, sensors, {
        strategy: 'immediate',
        batchSize: 10,
        batchDelay: 0,
      });

      const finalizeCalls = vi.mocked(prisma.rollout.update).mock.calls;
      const finalizeCall = finalizeCalls.find(
        (call) => (call[0] as any).data.completedAt !== undefined
      );
      expect(finalizeCall).toBeDefined();
      expect((finalizeCall![0] as any).data.status).toBe('failed');
    });
  });

  describe('Partial rollout status tracking', () => {
    it('should set status to failed when incomplete sensors remain (aborted mid-way)', async () => {
      const sensors = makeSensors(4);
      const rolloutId = 'rollout-partial';
      prisma._seedProgress(rolloutId, sensors);

      // Simulate a mix: 2 activated, 1 failed, 1 still pending (aborted)
      vi.mocked(prisma.rolloutProgress.findMany).mockResolvedValue([
        { rolloutId, sensorId: 'sensor-1', status: 'activated' },
        { rolloutId, sensorId: 'sensor-2', status: 'activated' },
        { rolloutId, sensorId: 'sensor-3', status: 'failed' },
        { rolloutId, sensorId: 'sensor-4', status: 'pending' },
      ] as any);

      await orchestrator.executeRollout('tenant-1', rolloutId, RELEASE, sensors, {
        strategy: 'rolling',
        batchSize: 2,
        batchDelay: 0,
      });

      // incompleteCount > 0 (sensor-4 is 'pending'), so status should be 'failed'
      const finalizeCalls = vi.mocked(prisma.rollout.update).mock.calls;
      const finalizeCall = finalizeCalls.find(
        (call) => (call[0] as any).data.completedAt !== undefined
      );
      expect(finalizeCall).toBeDefined();
      expect((finalizeCall![0] as any).data.status).toBe('failed');
    });
  });
});
