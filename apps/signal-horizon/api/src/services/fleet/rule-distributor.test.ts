/**
 * Rule Distributor Service Tests
 * Tests rolling rollout strategy with health checks and rollback capabilities
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { RuleDistributor } from './rule-distributor.js';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { FleetCommander } from './fleet-commander.js';
import type { Rule, RolloutConfig } from './types.js';

// Mock Prisma client
const createMockPrisma = () =>
  ({
    sensor: {
      findMany: vi.fn().mockResolvedValue([]),
      findUnique: vi.fn().mockResolvedValue(null),
    },
    ruleSyncState: {
      findMany: vi.fn().mockResolvedValue([]),
      findFirst: vi.fn().mockResolvedValue(null),
      upsert: vi.fn().mockResolvedValue({}),
      update: vi.fn().mockResolvedValue({}),
    },
    sensorSyncState: {
      findUnique: vi.fn().mockResolvedValue(null),
      upsert: vi.fn().mockResolvedValue({}),
    },
  }) as unknown as PrismaClient;

// Mock Logger
const createMockLogger = () =>
  ({
    child: vi.fn().mockReturnThis(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }) as unknown as Logger;

// Mock FleetCommander
const createMockFleetCommander = () =>
  ({
    sendCommand: vi.fn().mockResolvedValue('cmd-123'),
    sendCommandToMultiple: vi.fn().mockImplementation((sensorIds: string[]) =>
      Promise.resolve(sensorIds.map((_, i) => `cmd-${i}`))
    ),
    broadcastCommand: vi.fn().mockResolvedValue(['cmd-broadcast-1', 'cmd-broadcast-2']),
  }) as unknown as FleetCommander;

function createTestRule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: `rule-${Math.random().toString(36).substr(2, 9)}`,
    name: 'Test Rule',
    conditions: {},
    actions: {},
    enabled: true,
    priority: 1,
    ...overrides,
  };
}

describe('RuleDistributor', () => {
  let distributor: RuleDistributor;
  let mockPrisma: ReturnType<typeof createMockPrisma>;
  let mockLogger: ReturnType<typeof createMockLogger>;
  let mockFleetCommander: ReturnType<typeof createMockFleetCommander>;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();

    mockPrisma = createMockPrisma();
    mockLogger = createMockLogger();
    mockFleetCommander = createMockFleetCommander();

    distributor = new RuleDistributor(mockPrisma, mockLogger);
    distributor.setFleetCommander(mockFleetCommander);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Rolling Rollout Strategy', () => {
    const createHealthySensor = (id: string) => ({
      id,
      lastHeartbeat: new Date(),
      connectionState: 'CONNECTED',
    });

    const createSyncState = (sensorId: string) => ({
      sensorId,
      ruleId: 'rule-1',
      status: 'synced',
    });

    it('should deploy to sensors one at a time by default', async () => {
      const sensorIds = ['sensor-1', 'sensor-2', 'sensor-3'];
      const rules = [createTestRule()];

      // Mock healthy sensors and sync states
      vi.mocked(mockPrisma.sensor.findUnique).mockImplementation(
        () => Promise.resolve(createHealthySensor('sensor-1')) as unknown as ReturnType<typeof mockPrisma.sensor.findUnique>
      );
      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue(
        createSyncState('sensor-1') as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findFirst>>
      );

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Advance timers sufficiently for all batches and health checks
      await vi.advanceTimersByTimeAsync(5000);

      const result = await resultPromise;

      expect(result.success).toBe(true);
      expect(result.totalTargets).toBe(3);
      expect(mockFleetCommander.sendCommand).toHaveBeenCalledTimes(3);
    });

    it('should wait for health confirmation between sensors', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];

      // First sensor healthy, second needs time
      let healthCheckCalls = 0;
      vi.mocked(mockPrisma.sensor.findUnique).mockImplementation(() => {
        healthCheckCalls++;
        return Promise.resolve(
          createHealthySensor(healthCheckCalls <= 2 ? 'sensor-1' : 'sensor-2')
        ) as unknown as ReturnType<typeof mockPrisma.sensor.findUnique>;
      });
      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue(
        createSyncState('sensor-1') as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findFirst>>
      );

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 500,
        healthCheckIntervalMs: 50,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Advance timers incrementally
      await vi.advanceTimersByTimeAsync(1000);

      const result = await resultPromise;

      expect(result.success).toBe(true);
      // Health checks should have been performed
      expect(mockPrisma.sensor.findUnique).toHaveBeenCalled();
    });

    it('should rollback on consecutive failures when enabled', async () => {
      const sensorIds = ['sensor-1', 'sensor-2', 'sensor-3', 'sensor-4'];
      const rules = [createTestRule()];

      // Mock deployment success but health check failures (stale heartbeat)
      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue(
        createSyncState('sensor-1') as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findFirst>>
      );
      vi.mocked(mockPrisma.sensor.findUnique).mockResolvedValue({
        id: 'sensor-1',
        lastHeartbeat: new Date(Date.now() - 120000), // Stale heartbeat - degraded
        connectionState: 'CONNECTED',
      } as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findUnique>>);

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 3,
        rollbackOnFailure: true,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Advance timers sufficiently for health checks and deployment
      await vi.advanceTimersByTimeAsync(5000);

      const result = await resultPromise;

      expect(result.success).toBe(false);
      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.objectContaining({ deploymentId: expect.any(String) }),
        'Rolling deployment aborted - initiating rollback'
      );
    });

    it('should continue despite failures when rollback disabled', async () => {
      const sensorIds = ['sensor-1', 'sensor-2', 'sensor-3'];
      const rules = [createTestRule()];

      // All sensors unhealthy (stale heartbeat)
      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue(
        createSyncState('sensor-1') as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findFirst>>
      );
      vi.mocked(mockPrisma.sensor.findUnique).mockResolvedValue({
        id: 'sensor-1',
        lastHeartbeat: new Date(Date.now() - 120000), // Stale
        connectionState: 'CONNECTED',
      } as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findUnique>>);

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 10,
        rollbackOnFailure: false,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Advance timers sufficiently
      await vi.advanceTimersByTimeAsync(5000);

      const result = await resultPromise;

      // Should complete (not abort) even with failures
      expect(result.totalTargets).toBe(3);
      // All sensors were deployed to
      expect(mockFleetCommander.sendCommand).toHaveBeenCalledTimes(3);
    });

    it('should respect configurable batch size', async () => {
      const sensorIds = ['sensor-1', 'sensor-2', 'sensor-3', 'sensor-4', 'sensor-5', 'sensor-6'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensor.findUnique).mockImplementation(
        () => Promise.resolve(createHealthySensor('sensor-1')) as unknown as ReturnType<typeof mockPrisma.sensor.findUnique>
      );
      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue(
        createSyncState('sensor-1') as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findFirst>>
      );

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 3,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      await vi.advanceTimersByTimeAsync(2000);

      const result = await resultPromise;

      expect(result.success).toBe(true);
      expect(result.totalTargets).toBe(6);
      // Should have deployed to all 6 sensors
      expect(mockFleetCommander.sendCommand).toHaveBeenCalledTimes(6);

      // Verify logging shows batch deployment
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({ batch: expect.any(Array) }),
        'Deploying to batch'
      );
    });

    it('should handle sensor offline during rollout', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];

      // Both sensors return disconnected status (unhealthy)
      vi.mocked(mockPrisma.sensor.findUnique).mockImplementation(
        () => Promise.resolve({
          id: 'sensor-1',
          lastHeartbeat: new Date(),
          connectionState: 'DISCONNECTED',
        }) as unknown as ReturnType<typeof mockPrisma.sensor.findUnique>
      );
      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue(
        createSyncState('sensor-1') as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findFirst>>
      );

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      await vi.advanceTimersByTimeAsync(5000);

      const result = await resultPromise;

      // Should complete but with failures due to DISCONNECTED sensors
      expect(result.failureCount).toBeGreaterThan(0);
    });

    it('should handle deployment command failures', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];

      // Make deployment fail for sensor-2
      vi.mocked(mockFleetCommander.sendCommand)
        .mockResolvedValueOnce('cmd-1')
        .mockRejectedValueOnce(new Error('Connection refused'));

      vi.mocked(mockPrisma.sensor.findUnique).mockImplementation(
        () => Promise.resolve(createHealthySensor('sensor-1')) as unknown as ReturnType<typeof mockPrisma.sensor.findUnique>
      );
      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue(
        createSyncState('sensor-1') as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findFirst>>
      );

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      await vi.advanceTimersByTimeAsync(2000);

      const result = await resultPromise;

      expect(result.failureCount).toBeGreaterThanOrEqual(1);
      expect(result.results.some((r) => !r.success && r.error?.includes('Connection refused'))).toBe(
        true
      );
    });

    it('should emit proper logging for monitoring', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensor.findUnique).mockResolvedValue(
        createHealthySensor('sensor-1') as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findUnique>>
      );
      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue(
        createSyncState('sensor-1') as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findFirst>>
      );

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      await vi.advanceTimersByTimeAsync(500);

      await resultPromise;

      // Verify logging calls
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          deploymentId: expect.any(String),
          totalSensors: 1,
          batchSize: 1,
        }),
        'Starting rolling deployment'
      );

      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          deploymentId: expect.any(String),
          totalDeployed: expect.any(Number),
        }),
        'Rolling deployment completed'
      );
    });

    it('should handle health check timeout', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      // Sync state exists but sensor never becomes healthy
      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue(
        createSyncState('sensor-1') as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findFirst>>
      );
      vi.mocked(mockPrisma.sensor.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 20,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      await vi.advanceTimersByTimeAsync(500);

      const result = await resultPromise;

      // Should have recorded health check failure
      expect(result.failureCount).toBeGreaterThan(0);
    });

    it('should handle no sync state found', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      // No sync state found
      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue(null);
      vi.mocked(mockPrisma.sensor.findUnique).mockResolvedValue(
        createHealthySensor('sensor-1') as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findUnique>>
      );

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 20,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      await vi.advanceTimersByTimeAsync(500);

      const result = await resultPromise;

      // Health check should fail due to no sync state
      expect(result.failureCount).toBeGreaterThan(0);
    });
  });

  describe('pushRulesWithStrategy - strategy selection', () => {
    it('should throw error for unknown strategy', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      const config = {
        strategy: 'unknown_strategy' as RolloutConfig['strategy'],
      };

      await expect(
        distributor.pushRulesWithStrategy(sensorIds, rules, config)
      ).rejects.toThrow('Unknown rollout strategy: unknown_strategy');
    });

    it('should handle rolling strategy via pushRulesWithStrategy', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensor.findUnique).mockResolvedValue({
        id: 'sensor-1',
        lastHeartbeat: new Date(),
        connectionState: 'CONNECTED',
      } as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findUnique>>);
      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue({
        sensorId: 'sensor-1',
        ruleId: 'rule-1',
        status: 'synced',
      } as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findFirst>>);

      const config: RolloutConfig = {
        strategy: 'rolling',
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      await vi.advanceTimersByTimeAsync(500);

      const result = await resultPromise;

      expect(result.totalTargets).toBe(1);
    });
  });

  describe('FleetCommander integration', () => {
    it('should throw error if FleetCommander not set', async () => {
      const distributorWithoutCommander = new RuleDistributor(mockPrisma, mockLogger);

      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      await expect(
        distributorWithoutCommander.pushRulesWithStrategy(sensorIds, rules, {
          strategy: 'immediate',
        })
      ).rejects.toThrow('FleetCommander not initialized');
    });

    it('should throw error for rolling strategy without FleetCommander', async () => {
      const distributorWithoutCommander = new RuleDistributor(mockPrisma, mockLogger);

      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      const config: RolloutConfig = {
        strategy: 'rolling',
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
      };

      // The check for FleetCommander happens at the start of pushRulesWithStrategy
      // so it should throw immediately
      await expect(
        distributorWithoutCommander.pushRulesWithStrategy(sensorIds, rules, config)
      ).rejects.toThrow('FleetCommander not initialized');
    });
  });

  describe('Blue/Green Rollout Strategy', () => {
    it('should stage green deployment without affecting active traffic', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: 5000,
        switchTimeout: 3000,
        requireAllSensorsStaged: false,
        minStagedPercentage: 0,
      };

      // Start deployment - don't await, we need to advance timers manually
      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Advance time in small increments to allow async operations to run
      // This is needed because the deployment runs async and we need to give
      // the event loop a chance to process the staging commands
      for (let i = 0; i < 10; i++) {
        await vi.advanceTimersByTimeAsync(10);
        await Promise.resolve(); // Yield to event loop
      }

      // Verify staging command was sent with activate: false
      expect(mockFleetCommander.sendCommand).toHaveBeenCalled();
      const stagingCall = vi.mocked(mockFleetCommander.sendCommand).mock.calls[0];
      expect(stagingCall[1].payload).toHaveProperty('activate', false);

      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({ deploymentId: expect.any(String) }),
        'Starting blue/green deployment'
      );

      // Simulate staging complete and let deployment finish to avoid hanging promise
      const deployments = distributor.listActiveDeployments();
      if (deployments.length > 0) {
        const deploymentId = deployments[0].deploymentId;
        for (const sensorId of sensorIds) {
          distributor.updateSensorStagingStatus(deploymentId, sensorId, true);
          distributor.updateSensorActivationStatus(deploymentId, sensorId, true);
        }
      }

      // Advance through the remaining poll loops
      for (let i = 0; i < 10; i++) {
        await vi.advanceTimersByTimeAsync(500);
        await Promise.resolve();
      }

      await resultPromise;
    }, 15000);

    it('should execute atomic switchover', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: 5000,  // Must be > 2000ms (sleep interval in staging loop)
        switchTimeout: 3000,   // Must be > 1000ms (sleep interval in switch loop)
        requireAllSensorsStaged: false,
        minStagedPercentage: 0,
      };

      // Start deployment (don't await - we need to control timing)
      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Advance time to allow staging commands to be sent
      for (let i = 0; i < 10; i++) {
        await vi.advanceTimersByTimeAsync(10);
        await Promise.resolve();
      }

      // Simulate staging complete by marking sensors as staged
      const deployments = distributor.listActiveDeployments();
      expect(deployments.length).toBe(1);
      const deploymentId = deployments[0].deploymentId;
      for (const sensorId of sensorIds) {
        distributor.updateSensorStagingStatus(deploymentId, sensorId, true);
      }

      // Advance through staging poll loop (2000ms interval) to detect staged sensors
      for (let i = 0; i < 6; i++) {
        await vi.advanceTimersByTimeAsync(500);
        await Promise.resolve();
      }

      // Now simulate activation acknowledgment so switch completes
      for (const sensorId of sensorIds) {
        distributor.updateSensorActivationStatus(deploymentId, sensorId, true);
      }

      // Advance through switch poll loop (1000ms interval)
      for (let i = 0; i < 4; i++) {
        await vi.advanceTimersByTimeAsync(500);
        await Promise.resolve();
      }

      await resultPromise;

      // Verify broadcast command was called for switch
      expect(mockFleetCommander.broadcastCommand).toHaveBeenCalled();
      const broadcastCall = vi.mocked(mockFleetCommander.broadcastCommand).mock.calls[0];
      expect(broadcastCall[0].payload).toHaveProperty('activate', true);
    }, 15000);

    it('should rollback if staging fails', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];

      // Staging never completes - no stagedDeploymentId set
      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: 4000, // Must be > 2000ms (sleep interval)
        switchTimeout: 4000,
        requireAllSensorsStaged: true,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Advance timers in increments - need > stagingTimeout to trigger failure
      for (let i = 0; i < 30; i++) {
        await vi.advanceTimersByTimeAsync(500);
      }

      const result = await resultPromise;

      expect(result.success).toBe(false);
      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          deploymentId: expect.any(String),
          error: expect.stringContaining('Staging incomplete'),
        }),
        'Blue/green deployment failed'
      );

      // Verify abort was called
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({ deploymentId: expect.any(String) }),
        'Aborting green deployment'
      );
    }, 15000);

    it('should cleanup retired blue deployment', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: 5000,  // Must be > 2000ms (sleep interval in staging loop)
        switchTimeout: 3000,   // Must be > 1000ms (sleep interval in switch loop)
        cleanupDelayMs: 500,   // Short cleanup delay for testing
        requireAllSensorsStaged: false,
        minStagedPercentage: 0,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Advance time to allow staging commands to be sent
      for (let i = 0; i < 10; i++) {
        await vi.advanceTimersByTimeAsync(10);
        await Promise.resolve();
      }

      const activeDeployments = distributor.listActiveDeployments();
      expect(activeDeployments.length).toBe(1);
      const deploymentId = activeDeployments[0].deploymentId;

      for (const sensorId of sensorIds) {
        distributor.updateSensorStagingStatus(deploymentId, sensorId, true);
      }

      // Advance through staging poll loop
      for (let i = 0; i < 6; i++) {
        await vi.advanceTimersByTimeAsync(500);
        await Promise.resolve();
      }

      for (const sensorId of sensorIds) {
        distributor.updateSensorActivationStatus(deploymentId, sensorId, true);
      }

      // Advance through switch poll loop
      for (let i = 0; i < 4; i++) {
        await vi.advanceTimersByTimeAsync(500);
        await Promise.resolve();
      }

      const result = await resultPromise;
      expect(result.success).toBe(true);

      // Advance past cleanup delay (500ms + margin)
      for (let i = 0; i < 4; i++) {
        await vi.advanceTimersByTimeAsync(300);
        await Promise.resolve();
      }

      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({ deploymentId: expect.any(String) }),
        'Cleaning up retired blue deployment'
      );
    }, 15000);

    it('should track deployment status', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: 5000,    // Must be > 2000ms (sleep interval in staging loop)
        switchTimeout: 3000,    // Must be > 1000ms (sleep interval in switch loop)
        cleanupDelayMs: 500000, // Long cleanup delay so deployment stays in memory
        requireAllSensorsStaged: false,
        minStagedPercentage: 0,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Advance time to allow staging commands to be sent
      for (let i = 0; i < 10; i++) {
        await vi.advanceTimersByTimeAsync(10);
        await Promise.resolve();
      }

      const deployments = distributor.listActiveDeployments();
      expect(deployments.length).toBe(1);
      const deploymentId = deployments[0].deploymentId;

      for (const sensorId of sensorIds) {
        distributor.updateSensorStagingStatus(deploymentId, sensorId, true);
      }

      // Advance through staging poll loop
      for (let i = 0; i < 6; i++) {
        await vi.advanceTimersByTimeAsync(500);
        await Promise.resolve();
      }

      for (const sensorId of sensorIds) {
        distributor.updateSensorActivationStatus(deploymentId, sensorId, true);
      }

      // Advance through switch poll loop
      for (let i = 0; i < 4; i++) {
        await vi.advanceTimersByTimeAsync(500);
        await Promise.resolve();
      }

      await resultPromise;

      // Check listActiveDeployments
      const activeDeployments = distributor.listActiveDeployments();
      expect(activeDeployments.length).toBe(1);
      expect(activeDeployments[0].status).toBe('active');

      // Check getDeploymentStatus
      const deploymentStatus = distributor.getDeploymentStatus(activeDeployments[0].deploymentId);
      expect(deploymentStatus).toBeDefined();
      expect(deploymentStatus?.status).toBe('active');
      expect(deploymentStatus?.activatedAt).toBeDefined();
    }, 15000);

    it('should timeout if staging takes too long', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      // Never return a staged deployment
      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: 4000, // Must be > 2000ms (sleep interval)
        switchTimeout: 4000,
        requireAllSensorsStaged: true,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Advance timers in increments - need > stagingTimeout to trigger failure
      for (let i = 0; i < 30; i++) {
        await vi.advanceTimersByTimeAsync(500);
      }

      const result = await resultPromise;

      expect(result.success).toBe(false);
      expect(result.results[0].error).toContain('Staging incomplete');
    }, 15000);

    it('should timeout if switch takes too long', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      // Mock sensor status updates - sensors never report activation
      // The switch will timeout because activeStatus never becomes 'green'
      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: 4000, // Must be > 2000ms (sleep interval)
        switchTimeout: 1500,  // Must be > 1000ms (sleep interval in switch)
        requireAllSensorsStaged: false, // Allow staging to pass even though sensors never confirm
        minStagedPercentage: 0, // Allow 0% staged to proceed to switch phase
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Advance timers enough for staging + switch timeouts
      for (let i = 0; i < 30; i++) {
        await vi.advanceTimersByTimeAsync(500);
      }

      const result = await resultPromise;

      expect(result.success).toBe(false);
      expect(result.results[0].error).toContain('Switch timeout');
    }, 20000);

    it('should handle FleetCommander not being set', async () => {
      const distributorWithoutCommander = new RuleDistributor(mockPrisma, mockLogger);

      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: 100,
        switchTimeout: 100,
      };

      await expect(
        distributorWithoutCommander.pushRulesWithStrategy(sensorIds, rules, config)
      ).rejects.toThrow('FleetCommander not initialized');
    });

    it('should handle sendCommand failures during staging', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];

      // First sensor succeeds, second fails
      vi.mocked(mockFleetCommander.sendCommand)
        .mockResolvedValueOnce('cmd-1')
        .mockRejectedValueOnce(new Error('Connection refused'));

      // Only first sensor appears staged, but since second failed to stage, deployment fails
      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: 4000, // Must be > 2000ms (sleep interval)
        switchTimeout: 4000,
        requireAllSensorsStaged: true,
      };

      const resultPromise = distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Advance timers in increments - need > stagingTimeout to trigger failure
      for (let i = 0; i < 30; i++) {
        await vi.advanceTimersByTimeAsync(500);
      }

      const result = await resultPromise;

      // Should fail because not all sensors staged
      expect(result.success).toBe(false);
    }, 15000);

    it('should use default config values when not provided', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        // No other config - use defaults
      };

      // Start deployment - it will start with default timeouts
      distributor.pushRulesWithStrategy(sensorIds, rules, config);

      // Just verify the default values are being used in the logging
      // Don't wait for completion since default timeouts are very long
      await vi.advanceTimersByTimeAsync(100);

      // The test should still work with defaults
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          stagingTimeout: 60000, // Default staging timeout
        }),
        'Starting blue/green deployment'
      );
    });
  });
});
