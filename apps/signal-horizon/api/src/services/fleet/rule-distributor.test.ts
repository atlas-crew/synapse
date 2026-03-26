/**
 * Rule Distributor Service Tests
 * Tests rolling rollout strategy with health checks and rollback capabilities
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import { createHash } from 'node:crypto';
import { RuleDistributor, TenantIsolationError } from './rule-distributor.js';
import type { DeploymentStateStore } from './deployment-state-store.js';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { FleetCommander } from './fleet-commander.js';
import type { Rule, RolloutConfig } from './types.js';

// Test tenant ID for all tests
const TEST_TENANT_ID = 'test-tenant-123';

// Timer constants for tests (labs-pg4p)
/** Time allowed for async initialization (DB queries, microtask flush) before checking side effects */
const ASYNC_INIT_DELAY_MS = 10;
/** Default interval for polling async status in test loops */
const TEST_POLL_INTERVAL_MS = 500;
/** Timeout for staging phase in blue/green tests */
const TEST_STAGING_TIMEOUT_MS = 5000;
/** Timeout for switch phase in blue/green tests */
const TEST_SWITCH_TIMEOUT_MS = 3000;
/** Short delay for fast canary tests */
const SHORT_CANARY_DELAY_MS = 1;

// Helper to create sensor ownership records for validation
const createSensorOwnership = (sensorIds: string[], tenantId: string = TEST_TENANT_ID) =>
  sensorIds.map((id) => ({ id, tenantId }));

// Mock Prisma client with tenant-aware sensor lookup
const createMockPrisma = (ownedSensorIds: string[] = []) => {
  const mock = {
    sensor: {
      // Default implementation handles both ownership checks and health polling
      findMany: vi.fn().mockImplementation(({ where, select }: { where?: any, select?: any } = {}) => {
        // If select includes tenantId, it's an ownership validation call
        if (select?.tenantId && where?.id?.in) {
          return Promise.resolve(
            where.id.in.map((id: string) => ({
              id,
              tenantId: TEST_TENANT_ID,
            }))
          );
        }

        // Otherwise treat as a health/status check
        if (where?.id?.in) {
          const ids = where.id.in;
          return Promise.resolve(
            ids
              .filter((id: string) => ownedSensorIds.length === 0 || ownedSensorIds.includes(id))
              .map((id: string) => ({ 
                id, 
                tenantId: TEST_TENANT_ID,
                connectionState: 'CONNECTED',
                lastHeartbeat: new Date(),
              }))
          );
        }
        
        // Handle tenant-based lookup (e.g. getRuleSyncStatus)
        if (where?.tenantId === TEST_TENANT_ID) {
          const ids = ownedSensorIds.length > 0 ? ownedSensorIds : ['sensor-1'];
          return Promise.resolve(ids.map(id => ({
            id,
            tenantId: TEST_TENANT_ID,
            connectionState: 'CONNECTED',
            lastHeartbeat: new Date(),
            ruleSyncState: [],
          })));
        }

        return Promise.resolve([]);
      }),
      findUnique: vi.fn().mockResolvedValue(null),
      findFirst: vi.fn().mockImplementation(({ where }: { where?: any } = {}) => {
        return Promise.resolve({
          id: where?.id || 'sensor-1',
          tenantId: TEST_TENANT_ID,
          connectionState: 'CONNECTED',
          lastHeartbeat: new Date(),
        });
      }),
    },
    ruleSyncState: {
      findMany: vi.fn().mockImplementation(({ where }: { where?: any } = {}) => {
        // Handle where: { sensorId: { in: [...] } }
        if (where?.sensorId?.in) {
          const ids = where.sensorId.in;
          return Promise.resolve(ids.map((id: string) => ({
            sensorId: id,
            ruleId: 'rule-1',
            status: 'synced',
          })));
        }
        return Promise.resolve([]);
      }),
      findFirst: vi.fn().mockResolvedValue({
        sensorId: 'sensor-1',
        ruleId: 'rule-1',
        status: 'synced',
      }),
      upsert: vi.fn().mockResolvedValue({}),
      update: vi.fn().mockResolvedValue({}),
    },
    sensorSyncState: {
      findUnique: vi.fn().mockResolvedValue(null),
      upsert: vi.fn().mockResolvedValue({}),
    },
    fleetCommand: {
      findMany: vi.fn().mockResolvedValue([]),
      findFirst: vi.fn().mockResolvedValue(null),
      create: vi.fn().mockResolvedValue({ id: 'cmd-123' }),
    },
    scheduledDeployment: {
      create: vi.fn().mockResolvedValue({
        id: 'scheduled-123',
        tenantId: TEST_TENANT_ID,
        sensorIds: [],
        rules: [],
        scheduledAt: new Date(),
        status: 'PENDING',
      }),
      update: vi.fn().mockResolvedValue({}),
      findMany: vi.fn().mockResolvedValue([]),
    },
    $transaction: vi.fn(async (ops: any) => {
      if (Array.isArray(ops)) return Promise.all(ops);
      return ops;
    }),
  };
  return mock as unknown as PrismaClient;
};

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
  Object.assign(new EventEmitter(), {
    sendCommand: vi.fn().mockResolvedValue('cmd-123'),
    sendCommandToMultiple: vi.fn().mockImplementation((_tenantId: string, sensorIds: string[]) =>
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

async function advanceUntil<T>(
  condition: () => T | undefined,
  {
    stepMs = 100,
    maxSteps = 50,
    description = 'condition',
  }: { stepMs?: number; maxSteps?: number; description?: string } = {}
): Promise<T> {
  for (let i = 0; i < maxSteps; i += 1) {
    const result = condition();
    if (result) {
      return result;
    }
    await vi.advanceTimersByTimeAsync(stepMs);
    await Promise.resolve();
  }
  throw new Error(`Timeout waiting for ${description}`);
}

async function advanceUntilMicrotasks<T>(
  condition: () => T | undefined,
  {
    maxSteps = 50,
    description = 'condition',
  }: { maxSteps?: number; description?: string } = {}
): Promise<T> {
  // Use this when the code under test is promise-driven and advancing fake timers would
  // trigger unrelated timeout paths that are not part of the behavior being asserted.
  // Each step flushes a single microtask tick, so callers may need a larger maxSteps value
  // for promise chains that span multiple .then() hops.
  for (let i = 0; i < maxSteps; i += 1) {
    const result = condition();
    if (result) {
      return result;
    }
    await Promise.resolve();
  }
  throw new Error(`Timeout waiting for ${description}`);
}

async function advanceUntilSettled<T>(
  promise: Promise<T>,
  options?: { stepMs?: number; maxSteps?: number; description?: string }
): Promise<T> {
  let done = false;
  let value: T | undefined;
  let error: unknown;

  promise
    .then((result) => {
      done = true;
      value = result;
    })
    .catch((err) => {
      done = true;
      error = err;
    });

  await advanceUntil(
    () => (done ? true : undefined),
    options
  );

  if (error) {
    throw error;
  }

  return value as T;
}

async function settleResult<T>(
  promise: Promise<T>,
  description: string,
  options?: { stepMs?: number; maxSteps?: number }
): Promise<T> {
  return advanceUntilSettled(promise, { description, ...options });
}

async function waitForBlueGreenDeploymentInitialized(
  distributor: RuleDistributor,
  tenantId: string,
  expectedSensorCount: number
): Promise<string> {
  return advanceUntil(
    () => {
      const deployment = distributor.listActiveDeployments(tenantId)[0];
      return deployment && deployment.sensorStatus.size === expectedSensorCount
        ? deployment.deploymentId
        : undefined;
    },
    {
      stepMs: ASYNC_INIT_DELAY_MS,
      // Generous headroom for CI fake-timer scheduling; local init is typically much faster.
      maxSteps: 50,
      description: 'blue/green deployment initialization',
    }
  );
}

async function waitForBlueGreenDeploymentStatus(
  distributor: RuleDistributor,
  tenantId: string,
  deploymentId: string,
  expectedStatus: 'staging' | 'staged' | 'switching' | 'active' | 'failed' | 'retired'
): Promise<void> {
  await advanceUntil(
    () => {
      const deployment = distributor.getDeploymentStatus(tenantId, deploymentId);
      return deployment?.status === expectedStatus ? true : undefined;
    },
    {
      stepMs: TEST_POLL_INTERVAL_MS,
      maxSteps: 20,
      description: `blue/green deployment status ${expectedStatus}`,
    }
  );
}

describe('RuleDistributor', () => {
  let distributor: RuleDistributor;
  let mockPrisma: ReturnType<typeof createMockPrisma>;
  let mockLogger: ReturnType<typeof createMockLogger>;
  let mockFleetCommander: ReturnType<typeof createMockFleetCommander>;
  let digestSpy: ReturnType<typeof vi.spyOn<typeof globalThis.crypto.subtle, 'digest'>>;

  const getSendCommandMock = () => vi.mocked(mockFleetCommander.sendCommand);
  const getSendCommandToMultipleMock = () => vi.mocked(mockFleetCommander.sendCommandToMultiple);
  const getLoggerInfoMock = () => vi.mocked(mockLogger.info);
  const mapDigestAlgorithm = (algorithm: AlgorithmIdentifier): 'sha256' | 'sha384' | 'sha512' => {
    const normalized = typeof algorithm === 'string' ? algorithm : algorithm.name;
    switch (normalized) {
      case 'SHA-256':
        return 'sha256';
      case 'SHA-384':
        return 'sha384';
      case 'SHA-512':
        return 'sha512';
      default:
        throw new Error(`Unexpected digest algorithm in tests: ${normalized}`);
    }
  };

  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();

    // Keep hashing deterministic and independent from host WebCrypto scheduling while fake
    // timers are active. Several deployment paths hash rules before sending commands.
    digestSpy = vi.spyOn(globalThis.crypto.subtle, 'digest').mockImplementation(async (algorithm, data) => {
      const bytes = data instanceof ArrayBuffer
        ? new Uint8Array(data)
        : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      const hash = createHash(mapDigestAlgorithm(algorithm)).update(bytes).digest();
      return hash.buffer.slice(hash.byteOffset, hash.byteOffset + hash.byteLength);
    });

    // Default: all sensors from tests are owned by TEST_TENANT_ID
    mockPrisma = createMockPrisma();
    mockLogger = createMockLogger();
    mockFleetCommander = createMockFleetCommander();

    distributor = new RuleDistributor(mockPrisma, mockLogger);
    distributor.setFleetCommander(mockFleetCommander);
  });

  afterEach(() => {
    digestSpy.mockRestore();
    vi.useRealTimers();
  });

  /**
   * Override sensor.findMany to preserve ownership validation
   * while customizing health check responses.
   *
   * The production code calls findMany twice with different `select` shapes:
   *   1. Ownership: select { id, tenantId }
   *   2. Health:    select { id, lastHeartbeat, connectionState }
   *
   * This helper routes ownership calls to the default behaviour and
   * delegates health-check calls to the provided override function.
   */
  const mockSensorFindManyForHealth = (
    healthOverride: (ids: string[]) => Promise<any[]>
  ) => {
    vi.mocked(mockPrisma.sensor.findMany).mockImplementation(({ where, select }: any = {}) => {
      // Ownership validation (select includes tenantId)
      if (select?.tenantId && where?.id?.in) {
        return Promise.resolve(
          where.id.in.map((id: string) => ({ id, tenantId: TEST_TENANT_ID }))
        );
      }
      // Health check delegation
      if (where?.id?.in) {
        return healthOverride(where.id.in);
      }
      return Promise.resolve([]);
    });
  };

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

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'rolling deployment (single batch)');

      expect(result.success).toBe(true);
      expect(result.totalTargets).toBe(3);
      expect(mockFleetCommander.sendCommand).toHaveBeenCalledTimes(3);
    });

    it('should wait for health confirmation between sensors', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];

      // First sensor healthy, second needs time
      let healthCheckCalls = 0;
      vi.mocked(mockPrisma.sensor.findMany).mockImplementation(({ where }: any) => {
        // Ownership check returns both
        if (where?.id?.in?.length > 1) {
          return Promise.resolve(sensorIds.map(id => ({
            id, tenantId: TEST_TENANT_ID, connectionState: 'CONNECTED', lastHeartbeat: new Date()
          })));
        }
        
        healthCheckCalls++;
        return Promise.resolve([
          {
            id: healthCheckCalls <= 2 ? 'sensor-1' : 'sensor-2',
            lastHeartbeat: new Date(),
            connectionState: 'CONNECTED',
            tenantId: TEST_TENANT_ID,
          }
        ]) as unknown as ReturnType<typeof mockPrisma.sensor.findMany>;
      });

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 500,
        healthCheckIntervalMs: 50,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'rolling deployment (health gating)', {
        stepMs: 100,
        maxSteps: 100,
      });

      expect(result.success).toBe(true);
      // Health checks should have been performed via findMany
      expect(mockPrisma.sensor.findMany).toHaveBeenCalled();
    });

    it('should rollback on consecutive failures when enabled', async () => {
      const sensorIds = ['sensor-1', 'sensor-2', 'sensor-3', 'sensor-4'];
      const rules = [createTestRule()];

      // Mock previous rules for rollback
      vi.mocked(mockPrisma.fleetCommand.findMany).mockResolvedValue([
        {
          id: 'cmd-current',
          payload: { rules: [{ id: 'current-rule' }] },
          completedAt: new Date(),
        },
        {
          id: 'cmd-previous',
          payload: { rules: [{ id: 'previous-rule' }] },
          completedAt: new Date(Date.now() - 60000),
        },
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.fleetCommand.findMany>>);

      // Mock deployment success but health check failures (stale heartbeat)
      vi.mocked(mockPrisma.sensor.findMany).mockImplementation(({ where }: any) => {
        if (where?.id?.in?.length > 1) {
          return Promise.resolve(sensorIds.map(id => ({
            id, tenantId: TEST_TENANT_ID, connectionState: 'CONNECTED', lastHeartbeat: new Date()
          })));
        }
        return Promise.resolve([
          {
            id: 'sensor-1',
            lastHeartbeat: new Date(Date.now() - 120000), // Stale heartbeat - degraded
            connectionState: 'CONNECTED',
            tenantId: TEST_TENANT_ID,
          }
        ]) as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findMany>>;
      });

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 3,
        rollbackOnFailure: true,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'rolling deployment (rollback)');

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

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'rolling deployment (no rollback)');

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

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'rolling deployment (batch size)');

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
      vi.mocked(mockPrisma.sensor.findMany).mockImplementation(({ where }: any) => {
        if (where?.id?.in?.length > 1) {
          return Promise.resolve(sensorIds.map(id => ({
            id, tenantId: TEST_TENANT_ID, connectionState: 'CONNECTED', lastHeartbeat: new Date()
          })));
        }
        return Promise.resolve([
          {
            id: 'sensor-1',
            lastHeartbeat: new Date(),
            connectionState: 'DISCONNECTED',
            tenantId: TEST_TENANT_ID,
          }
        ]) as unknown as ReturnType<typeof mockPrisma.sensor.findMany>;
      });

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'rolling deployment (offline)');

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

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'rolling deployment (command failure)');

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

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      await settleResult(resultPromise, 'rolling deployment (logging)');

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

      // Sensor never found during health check (ownership still works)
      mockSensorFindManyForHealth(() => Promise.resolve([]));

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 20,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'rolling deployment (health timeout)');

      // Should have recorded health check failure
      expect(result.failureCount).toBeGreaterThan(0);
    });

    it('should handle no sync state found', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      // No sync state found
      vi.mocked(mockPrisma.ruleSyncState.findMany).mockResolvedValue([]);

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 20,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'rolling deployment (no sync state)');

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
        distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config)
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

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'strategy selection (rolling)');

      expect(result.totalTargets).toBe(1);
    });
  });

  describe('FleetCommander integration', () => {
    it('should throw error if FleetCommander not set', async () => {
      const distributorWithoutCommander = new RuleDistributor(mockPrisma, mockLogger);

      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      await expect(
        distributorWithoutCommander.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, {
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
        distributorWithoutCommander.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config)
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
        stagingTimeout: TEST_STAGING_TIMEOUT_MS,
        switchTimeout: TEST_SWITCH_TIMEOUT_MS,
        requireAllSensorsStaged: false,
        minStagedPercentage: 0,
      };

      // Start deployment - don't await, we need to advance timers manually
      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      // Advance time to allow async initialization and sendCommand calls
      // Using advanceUntil is more robust than a fixed loop (labs-t1xj)
      await advanceUntil(
        () => (getSendCommandMock().mock.calls.length > 0 ? true : undefined),
        { stepMs: ASYNC_INIT_DELAY_MS, maxSteps: 20, description: 'sendCommand initialization' }
      );

      // Verify staging command was sent with activate: false
      expect(mockFleetCommander.sendCommand).toHaveBeenCalled();
      const stagingCall = vi.mocked(mockFleetCommander.sendCommand).mock.calls[0];
      expect(stagingCall[2].payload).toHaveProperty('activate', false);

      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({ deploymentId: expect.any(String) }),
        'Starting blue/green deployment'
      );

      // Simulate staging complete and let deployment finish to avoid hanging promise
      const deployments = distributor.listActiveDeployments(TEST_TENANT_ID);
      if (deployments.length > 0) {
        const deploymentId = deployments[0].deploymentId;
        for (const sensorId of sensorIds) {
          distributor.updateSensorStagingStatus(deploymentId, sensorId, true);
          distributor.updateSensorActivationStatus(deploymentId, sensorId, true);
        }
      }

      // Advance through the remaining poll loops
      for (let i = 0; i < 10; i++) {
        await vi.advanceTimersByTimeAsync(TEST_POLL_INTERVAL_MS);
        await Promise.resolve();
      }

      await advanceUntilSettled(resultPromise, {
        stepMs: TEST_POLL_INTERVAL_MS,
        maxSteps: 10,
        description: 'blue/green staging completion',
      });
    }, 15000);

    it('should execute atomic switchover', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: TEST_STAGING_TIMEOUT_MS,
        switchTimeout: TEST_SWITCH_TIMEOUT_MS,
        requireAllSensorsStaged: false,
        minStagedPercentage: 0,
      };

      // Start deployment (don't await - we need to control timing)
      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      // Advance time to allow staging commands to be sent
      const deploymentId = await waitForBlueGreenDeploymentInitialized(
        distributor,
        TEST_TENANT_ID,
        sensorIds.length
      );

      // Simulate staging complete by marking sensors as staged
      for (const sensorId of sensorIds) {
        distributor.updateSensorStagingStatus(deploymentId, sensorId, true);
      }

      // Advance through staging poll loop (2000ms interval in implementation)
      for (let i = 0; i < 6; i++) {
        await vi.advanceTimersByTimeAsync(TEST_POLL_INTERVAL_MS);
        await Promise.resolve();
      }

      // Now simulate activation acknowledgment so switch completes
      for (const sensorId of sensorIds) {
        distributor.updateSensorActivationStatus(deploymentId, sensorId, true);
      }

      // Advance through switch poll loop (1000ms interval in implementation)
      for (let i = 0; i < 4; i++) {
        await vi.advanceTimersByTimeAsync(TEST_POLL_INTERVAL_MS);
        await Promise.resolve();
      }

      await advanceUntilSettled(resultPromise, {
        stepMs: TEST_POLL_INTERVAL_MS,
        maxSteps: 10,
        description: 'blue/green atomic switchover',
      });

      // Verify broadcast command was called for switch
      expect(mockFleetCommander.broadcastCommand).toHaveBeenCalled();
      const broadcastCall = vi.mocked(mockFleetCommander.broadcastCommand).mock.calls[0];
      expect(broadcastCall[1].payload).toHaveProperty('activate', true);
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

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      // Advance timers in increments - need > stagingTimeout to trigger failure
      for (let i = 0; i < 30; i++) {
        await vi.advanceTimersByTimeAsync(500);
      }

      const result = await advanceUntilSettled(resultPromise, {
        stepMs: 500,
        maxSteps: 30,
        description: 'blue/green staging failure',
      });

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

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const deploymentId = await waitForBlueGreenDeploymentInitialized(
        distributor,
        TEST_TENANT_ID,
        sensorIds.length
      );

      for (const sensorId of sensorIds) {
        distributor.updateSensorStagingStatus(deploymentId, sensorId, true);
      }

      await waitForBlueGreenDeploymentStatus(
        distributor,
        TEST_TENANT_ID,
        deploymentId,
        'switching'
      );

      for (const sensorId of sensorIds) {
        distributor.updateSensorActivationStatus(deploymentId, sensorId, true);
      }

      await waitForBlueGreenDeploymentStatus(
        distributor,
        TEST_TENANT_ID,
        deploymentId,
        'active'
      );

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

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const deploymentId = await waitForBlueGreenDeploymentInitialized(
        distributor,
        TEST_TENANT_ID,
        sensorIds.length
      );

      for (const sensorId of sensorIds) {
        distributor.updateSensorStagingStatus(deploymentId, sensorId, true);
      }

      // Advance through staging poll loop (enough to cover 1s poll interval)
      for (let i = 0; i < 3; i++) {
        await vi.advanceTimersByTimeAsync(500);
        await Promise.resolve();
      }

      for (const sensorId of sensorIds) {
        distributor.updateSensorActivationStatus(deploymentId, sensorId, true);
      }

      // Advance through switch poll loop (enough to cover 1s poll interval)
      for (let i = 0; i < 3; i++) {
        await vi.advanceTimersByTimeAsync(500);
        await Promise.resolve();
      }

      await advanceUntilSettled(resultPromise, {
        stepMs: TEST_POLL_INTERVAL_MS,
        maxSteps: 10,
        description: 'blue/green status tracking completion',
      });

      // Check listActiveDeployments
      const activeDeployments = distributor.listActiveDeployments(TEST_TENANT_ID);
      expect(activeDeployments.length).toBe(1);
      expect(activeDeployments[0].status).toBe('active');

      // Check getDeploymentStatus
      const deploymentStatus = distributor.getDeploymentStatus(TEST_TENANT_ID, activeDeployments[0].deploymentId);
      expect(deploymentStatus).toBeDefined();
      expect(deploymentStatus?.status).toBe('active');
      expect(deploymentStatus?.activatedAt).toBeDefined();
    }, 15000);

    it('should handle concurrent deployments to the same sensor (labs-2j5u.13)', async () => {
      const sensorIds = ['sensor-1'];
      const rules1 = [createTestRule({ id: 'rule-1' })];
      const rules2 = [createTestRule({ id: 'rule-2' })];

      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: TEST_STAGING_TIMEOUT_MS,
        switchTimeout: TEST_SWITCH_TIMEOUT_MS,
        requireAllSensorsStaged: false,
        minStagedPercentage: 0,
      };

      // Start two deployments concurrently
      const promise1 = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules1, config);
      const promise2 = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules2, config);

      const activeDeployments = await advanceUntilMicrotasks(
        () => {
          const deployments = distributor.listActiveDeployments(TEST_TENANT_ID);
          return deployments.length === 2 &&
            deployments.every((deployment) => deployment.sensorStatus.size === sensorIds.length)
            ? deployments
            : undefined;
        },
        { maxSteps: 100, description: 'concurrent blue/green deployment initialization' }
      );

      // Complete staging for both deployments, then wait for the switch phase to begin.
      for (const deployment of activeDeployments) {
        distributor.updateSensorStagingStatus(deployment.deploymentId, sensorIds[0], true);
      }

      for (const deployment of activeDeployments) {
        await waitForBlueGreenDeploymentStatus(
          distributor,
          TEST_TENANT_ID,
          deployment.deploymentId,
          'switching'
        );
      }

      for (const deployment of activeDeployments) {
        distributor.updateSensorActivationStatus(deployment.deploymentId, sensorIds[0], true);
      }

      const [result1, result2] = await advanceUntilSettled(Promise.all([promise1, promise2]), {
        stepMs: TEST_POLL_INTERVAL_MS,
        maxSteps: 20,
        description: 'concurrent blue/green deployment completion',
      });

      // Verify both completed
      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      expect(mockFleetCommander.sendCommand).toHaveBeenCalledTimes(2);
      expect(
        distributor.getDeploymentStatus(TEST_TENANT_ID, activeDeployments[0].deploymentId)?.status
      ).toBe('active');
      expect(
        distributor.getDeploymentStatus(TEST_TENANT_ID, activeDeployments[1].deploymentId)?.status
      ).toBe('active');
    });

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

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      // Advance timers in increments - need > stagingTimeout to trigger failure
      for (let i = 0; i < 30; i++) {
        await vi.advanceTimersByTimeAsync(500);
      }

      const result = await advanceUntilSettled(resultPromise, {
        stepMs: 500,
        maxSteps: 30,
        description: 'blue/green sendCommand failure handling',
      });

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
        stagingTimeout: 100,   // Very short staging timeout
        switchTimeout: 100,    // Very short switch timeout
        requireAllSensorsStaged: false, // Allow staging to pass even though sensors never confirm
        minStagedPercentage: 0, // Allow 0% staged to proceed to switch phase
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      // Let deployment initialize so we can mark staging complete
      await vi.advanceTimersByTimeAsync(10);
      await Promise.resolve();

      const deployments = distributor.listActiveDeployments(TEST_TENANT_ID);
      expect(deployments.length).toBe(1);
      const deploymentId = deployments[0].deploymentId;

      // Wait for sensor status to initialize before marking staging complete
      await advanceUntil(
        () => distributor.getDeploymentStatus(TEST_TENANT_ID, deploymentId)?.sensorStatus.get(sensorIds[0]),
        { stepMs: 10, maxSteps: 50, description: 'sensor status initialization' }
      );

      // Mark staging complete but never activate - should timeout during switch
      for (const sensorId of sensorIds) {
        distributor.updateSensorStagingStatus(deploymentId, sensorId, true);
      }

      const result = await advanceUntilSettled(resultPromise, {
        stepMs: 1000,
        maxSteps: 10,
        description: 'blue/green switch timeout',
      });

      expect(result.success).toBe(false);
      expect(result.results[0].error).toContain('Switch timeout');
    }, 10000);

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
        distributorWithoutCommander.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config)
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

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      // Advance timers in increments - need > stagingTimeout to trigger failure
      for (let i = 0; i < 30; i++) {
        await vi.advanceTimersByTimeAsync(500);
      }

      const result = await advanceUntilSettled(resultPromise, {
        stepMs: 500,
        maxSteps: 30,
        description: 'blue/green sendCommand failure handling',
      });

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
      distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

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

  describe('Tenant Isolation', () => {
    const DIFFERENT_TENANT = 'different-tenant-456';

    // Type-safe mock return value for sensor ownership
    type SensorOwnershipResult = Awaited<ReturnType<typeof mockPrisma.sensor.findMany>>;

    it('should reject requests for sensors not owned by tenant', async () => {
      // Setup: Prisma returns sensors owned by a DIFFERENT tenant
      const sensorIds = ['sensor-1', 'sensor-2'];
      vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue(
        createSensorOwnership(sensorIds, DIFFERENT_TENANT) as SensorOwnershipResult
      );

      const rules = [createTestRule()];

      await expect(
        distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, {
          strategy: 'immediate',
        })
      ).rejects.toThrow(TenantIsolationError);
    });

    it('should reject requests when some sensors belong to different tenant', async () => {
      const sensorIds = ['sensor-1', 'sensor-2', 'sensor-3'];

      // Only sensor-1 belongs to our tenant, others belong to different tenant
      vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
        { id: 'sensor-1', tenantId: TEST_TENANT_ID },
        { id: 'sensor-2', tenantId: DIFFERENT_TENANT },
        { id: 'sensor-3', tenantId: DIFFERENT_TENANT },
      ] as SensorOwnershipResult);

      const rules = [createTestRule()];

      await expect(
        distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, {
          strategy: 'rolling',
        })
      ).rejects.toThrow(TenantIsolationError);
    });

    it('should reject requests for non-existent sensors', async () => {
      const sensorIds = ['sensor-1', 'non-existent'];

      // Only sensor-1 exists
      vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
        { id: 'sensor-1', tenantId: TEST_TENANT_ID },
      ] as SensorOwnershipResult);

      const rules = [createTestRule()];

      await expect(
        distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, {
          strategy: 'immediate',
        })
      ).rejects.toThrow(TenantIsolationError);
    });

    it('should allow requests when all sensors belong to tenant', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];

      // All sensors belong to TEST_TENANT_ID
      vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue(
        createSensorOwnership(sensorIds, TEST_TENANT_ID) as SensorOwnershipResult
      );

      // Mock healthy sensors
      vi.mocked(mockPrisma.sensor.findUnique).mockResolvedValue({
        id: 'sensor-1',
        lastHeartbeat: new Date(),
        connectionState: 'CONNECTED',
      } as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findUnique>>);

      const rules = [createTestRule()];

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, {
        strategy: 'immediate',
      });

      const result = await settleResult(resultPromise, 'tenant isolation (all sensors owned)');

      expect(result.success).toBe(true);
      expect(result.totalTargets).toBe(2);
    });

    it('should log tenant isolation violations', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];

      // Sensors belong to different tenant
      vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue(
        createSensorOwnership(sensorIds, DIFFERENT_TENANT) as SensorOwnershipResult
      );

      const rules = [createTestRule()];

      await expect(
        distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, {
          strategy: 'immediate',
        })
      ).rejects.toThrow(TenantIsolationError);

      // Verify security event was logged
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: TEST_TENANT_ID,
          unauthorizedSensorIds: sensorIds,
        }),
        'Tenant isolation violation attempted'
      );
    });

    it('should pass validation when sensorIds array is empty', async () => {
      const sensorIds: string[] = [];
      const rules = [createTestRule()];

      // Empty array should not throw
      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, {
        strategy: 'immediate',
      });

      const result = await resultPromise;

      expect(result.success).toBe(true);
      expect(result.totalTargets).toBe(0);
    });
  });

  // =============================================================================
  // Immediate Deployment Strategy Tests
  // =============================================================================

  describe('Immediate Deployment Strategy', () => {
    it('should deploy rules to all sensors at once', async () => {
      const sensorIds = ['sensor-1', 'sensor-2', 'sensor-3'];
      const rules = [createTestRule(), createTestRule()];

      const config: RolloutConfig = {
        strategy: 'immediate',
      };

      // Immediate strategy resolves without timer-driven polling, so a direct await is stable here.
      const result = await distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      expect(result.success).toBe(true);
      expect(result.totalTargets).toBe(3);
      expect(result.pendingCount).toBe(3);
      expect(mockFleetCommander.sendCommandToMultiple).toHaveBeenCalledWith(
        TEST_TENANT_ID,
        sensorIds,
        expect.objectContaining({
          type: 'push_rules',
          payload: expect.objectContaining({
            rules,
            hash: expect.any(String),
          }),
        })
      );
    });

    it('should create pending sync state for all sensors and rules', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule({ id: 'rule-1' }), createTestRule({ id: 'rule-2' })];

      const config: RolloutConfig = {
        strategy: 'immediate',
      };

      await distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      // Should have called upsert for each sensor-rule combination
      expect(mockPrisma.ruleSyncState.upsert).toHaveBeenCalledTimes(4);

      // Verify first call structure
      expect(mockPrisma.ruleSyncState.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            sensorId_ruleId: expect.any(Object),
          }),
          create: expect.objectContaining({
            status: 'pending',
          }),
          update: expect.objectContaining({
            status: 'pending',
          }),
        })
      );
    });

    it('should compute consistent rules hash', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [
        createTestRule({ id: 'rule-b', name: 'Rule B' }),
        createTestRule({ id: 'rule-a', name: 'Rule A' }),
      ];

      const config: RolloutConfig = {
        strategy: 'immediate',
      };

      await distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const sentPayload = vi.mocked(mockFleetCommander.sendCommandToMultiple).mock.calls[0][2]
        .payload as { hash: string };
      expect(sentPayload.hash).toBeDefined();
      expect(sentPayload.hash.length).toBe(64); // SHA-256 hex string
    });

    it('should return command IDs for tracking', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];

      vi.mocked(mockFleetCommander.sendCommandToMultiple).mockResolvedValue([
        'cmd-001',
        'cmd-002',
      ]);

      const config: RolloutConfig = {
        strategy: 'immediate',
      };

      const result = await distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      expect(result.results).toHaveLength(2);
      expect(result.results[0].commandId).toBe('cmd-001');
      expect(result.results[1].commandId).toBe('cmd-002');
    });
  });

  // =============================================================================
  // Canary Deployment Strategy Tests
  // =============================================================================

  describe('Canary Deployment Strategy', () => {
    it('should deploy to percentage-based batches', async () => {
      const sensorIds = ['s1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10'];
      const rules = [createTestRule()];

      const config: RolloutConfig = {
        strategy: 'canary',
        canaryPercentages: [10, 50, 100],
        delayBetweenStages: SHORT_CANARY_DELAY_MS, // Very short delay for testing
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      // Wait for all stages - advance incrementally to ensure timers fire
      for (let i = 0; i < 50; i++) {
        await vi.advanceTimersByTimeAsync(ASYNC_INIT_DELAY_MS);
        await Promise.resolve(); // Allow microtasks to complete
      }
      const result = await resultPromise;

      expect(result.success).toBe(true);
      expect(result.totalTargets).toBe(10);

      // Verify logging for canary stages
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          percentages: [10, 50, 100],
        }),
        'Starting canary deployment'
      );
    });

    it('should use default percentages when not specified', async () => {
      const sensorIds = ['s1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10'];
      const rules = [createTestRule()];

      const config: RolloutConfig = {
        strategy: 'canary',
        delayBetweenStages: SHORT_CANARY_DELAY_MS, // Very short delay
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      for (let i = 0; i < 50; i++) {
        await vi.advanceTimersByTimeAsync(ASYNC_INIT_DELAY_MS);
        await Promise.resolve();
      }
      const result = await resultPromise;

      expect(result.success).toBe(true);

      // Default percentages are [10, 50, 100]
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          percentages: [10, 50, 100],
        }),
        'Starting canary deployment'
      );
    });

    it('should wait between canary stages', async () => {
      const sensorIds = ['s1', 's2', 's3', 's4', 's5'];
      const rules = [createTestRule()];

      const config: RolloutConfig = {
        strategy: 'canary',
        canaryPercentages: [20, 100], // Two stages
        delayBetweenStages: 100, // Short delay for testing
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      // Wait for canary stages to complete - advance incrementally
      for (let i = 0; i < 30; i++) {
        await vi.advanceTimersByTimeAsync(ASYNC_INIT_DELAY_MS);
        await Promise.resolve();
      }
      await resultPromise;

      // Verify delay logging occurred between stages
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({ delayMs: 100 }),
        'Waiting before next canary stage'
      );
    });

    it('should log deployment progress for each stage', async () => {
      const sensorIds = ['s1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10'];
      const rules = [createTestRule()];

      const config: RolloutConfig = {
        strategy: 'canary',
        canaryPercentages: [10, 50, 100],
        delayBetweenStages: SHORT_CANARY_DELAY_MS, // Very short delay
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      for (let i = 0; i < 50; i++) {
        await vi.advanceTimersByTimeAsync(ASYNC_INIT_DELAY_MS);
        await Promise.resolve();
      }
      await resultPromise;

      // Verify stage logging
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({ stage: 10 }),
        'Deploying canary batch'
      );
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({ stage: 50 }),
        'Deploying canary batch'
      );
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({ stage: 100 }),
        'Deploying canary batch'
      );
    });

    it('should handle single-sensor canary deployment', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      const config: RolloutConfig = {
        strategy: 'canary',
        canaryPercentages: [50, 100],
        delayBetweenStages: SHORT_CANARY_DELAY_MS, // Very short delay
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      for (let i = 0; i < 20; i++) {
        await vi.advanceTimersByTimeAsync(ASYNC_INIT_DELAY_MS);
        await Promise.resolve();
      }
      const result = await resultPromise;

      expect(result.success).toBe(true);
      expect(result.totalTargets).toBe(1);
    });

    it('should skip empty batches in canary progression', async () => {
      const sensorIds = ['s1', 's2'];
      const rules = [createTestRule()];

      // With 2 sensors and [50, 50, 100] percentages:
      // 50% of 2 = ceil(1) = 1 sensor
      // 50% of 2 = ceil(1) = 1 sensor (but already deployed 1, so 0 new - SKIPPED)
      // 100% of 2 = ceil(2) = 2 sensors (1 more to deploy)
      // This tests the batchSize <= 0 continue logic
      const config: RolloutConfig = {
        strategy: 'canary',
        canaryPercentages: [50, 50, 100], // Second 50% would be skipped
        delayBetweenStages: 50,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await advanceUntilSettled(resultPromise, {
        stepMs: 100,
        maxSteps: 20,
        description: 'canary progression',
      });

      expect(result.success).toBe(true);
      expect(result.totalTargets).toBe(2);
    });
  });

  // =============================================================================
  // Scheduled Deployment Strategy Tests
  // =============================================================================

  describe('Scheduled Deployment Strategy', () => {
    it('should schedule deployment for future time', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];
      const futureTime = new Date(Date.now() + 500); // 0.5 seconds in future

      const config: RolloutConfig = {
        strategy: 'scheduled',
        scheduledTime: futureTime,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'scheduled deployment (future)');

      // Should return pending immediately
      expect(result.success).toBe(true);
      expect(result.pendingCount).toBe(2);

      // Verify scheduling log (log message was updated to reflect persistence)
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          scheduledTime: futureTime,
          delayMs: expect.any(Number),
        }),
        'Scheduling rule deployment (persisted)'
      );

      // Commands should NOT be sent yet
      expect(mockFleetCommander.sendCommandToMultiple).not.toHaveBeenCalled();

      // Advance timers until scheduled execution fires
      await advanceUntil(
        () => (getSendCommandToMultipleMock().mock.calls.length > 0 ? true : undefined),
        { stepMs: 100, maxSteps: 20, description: 'scheduled deployment execution' }
      );
    });

    it('should deploy immediately if scheduled time is in the past', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];
      const pastTime = new Date(Date.now() - 1000); // 1 second in past

      const config: RolloutConfig = {
        strategy: 'scheduled',
        scheduledTime: pastTime,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'scheduled deployment (past)');

      expect(result.success).toBe(true);
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Scheduled time is in the past, deploying immediately'
      );
      expect(mockFleetCommander.sendCommandToMultiple).toHaveBeenCalled();
    });

    it('should throw error if scheduledTime not provided', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      const config: RolloutConfig = {
        strategy: 'scheduled',
        // Missing scheduledTime
      };

      await expect(
        distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config)
      ).rejects.toThrow('Scheduled deployment requires scheduledTime');
    });

    it('should handle scheduled deployment with correct delay calculation', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];
      const delay = 500; // 0.5 seconds
      const futureTime = new Date(Date.now() + delay);

      const config: RolloutConfig = {
        strategy: 'scheduled',
        scheduledTime: futureTime,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      await settleResult(resultPromise, 'scheduled deployment (delay calc)');

      // Verify logged delay is approximately correct (log message was updated to reflect persistence)
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          delayMs: expect.any(Number),
        }),
        'Scheduling rule deployment (persisted)'
      );

      // Advance partway - should not deploy yet
      await vi.advanceTimersByTimeAsync(200);
      expect(mockFleetCommander.sendCommandToMultiple).not.toHaveBeenCalled();

      // Advance timers until scheduled execution fires
      await advanceUntil(
        () => (getSendCommandToMultipleMock().mock.calls.length > 0 ? true : undefined),
        { stepMs: 100, maxSteps: 20, description: 'scheduled deployment execution' }
      );
    });
  });

  // =============================================================================
  // Rollback Functionality Tests
  // =============================================================================

  describe('Rollback Functionality', () => {
    const createUnhealthySensor = () => ({
      id: 'sensor-1',
      lastHeartbeat: new Date(Date.now() - 120000), // Stale heartbeat
      connectionState: 'CONNECTED',
    });

    // Helper to mock previous rule version for rollback
    const mockPreviousRuleVersion = () => {
      vi.mocked(mockPrisma.fleetCommand.findMany).mockResolvedValue([
        {
          id: 'cmd-current',
          payload: { rules: [{ id: 'current-rule' }] },
          completedAt: new Date(),
        },
        {
          id: 'cmd-previous',
          payload: { rules: [{ id: 'previous-rule' }] },
          completedAt: new Date(Date.now() - 60000),
        },
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.fleetCommand.findMany>>);
    };

    it('should trigger rollback when failure threshold exceeded', async () => {
      const sensorIds = ['sensor-1', 'sensor-2', 'sensor-3', 'sensor-4', 'sensor-5'];
      const rules = [createTestRule()];

      // Mock previous rules for rollback
      mockPreviousRuleVersion();

      // All sensors unhealthy via findMany (stale heartbeat triggers degraded status)
      mockSensorFindManyForHealth((ids) =>
        Promise.resolve(ids.map(id => ({
          id,
          tenantId: TEST_TENANT_ID,
          connectionState: 'CONNECTED',
          lastHeartbeat: new Date(Date.now() - 120000), // Stale heartbeat - degraded
        })))
      );

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 3,
        rollbackOnFailure: true,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'rollback (failure threshold)');

      expect(result.success).toBe(false);
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          sensorCount: expect.any(Number),
        }),
        'Initiating rollback'
      );
    });

    it('should deploy previous rule version during rollback', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];

      // Mock previous rules for rollback
      mockPreviousRuleVersion();

      // All sensors unhealthy via findMany (stale heartbeat triggers degraded status)
      mockSensorFindManyForHealth((ids) =>
        Promise.resolve(ids.map(id => ({
          id,
          tenantId: TEST_TENANT_ID,
          connectionState: 'CONNECTED',
          lastHeartbeat: new Date(Date.now() - 120000), // Stale heartbeat
        })))
      );

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 1, // Abort after 1 failure
        rollbackOnFailure: true,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      await settleResult(resultPromise, 'rollback (previous version)');

      // Rollback should trigger deployment of previous rules
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.objectContaining({
          sensorCount: expect.any(Number),
        }),
        'Initiating rollback'
      );
    });

    it('should log rollback success for each sensor', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];

      // Mock previous rules for rollback
      mockPreviousRuleVersion();

      // All sensors unhealthy via findMany (stale heartbeat triggers degraded status)
      mockSensorFindManyForHealth((ids) =>
        Promise.resolve(ids.map(id => ({
          id,
          tenantId: TEST_TENANT_ID,
          connectionState: 'CONNECTED',
          lastHeartbeat: new Date(Date.now() - 120000),
        })))
      );

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 1,
        rollbackOnFailure: true,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      await settleResult(resultPromise, 'rollback (per-sensor success)');

      expect(mockLogger.debug).toHaveBeenCalledWith(
        expect.objectContaining({ sensorId: expect.any(String) }),
        'Rollback successful'
      );
    });

    it('should log rollback failures without stopping', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      // Mock previous rules for rollback
      mockPreviousRuleVersion();

      // Unhealthy sensor via findMany triggers rollback (stale heartbeat)
      mockSensorFindManyForHealth((ids) =>
        Promise.resolve(ids.map(id => ({
          id,
          tenantId: TEST_TENANT_ID,
          connectionState: 'CONNECTED',
          lastHeartbeat: new Date(Date.now() - 120000),
        })))
      );

      // Rollback deployment fails
      vi.mocked(mockFleetCommander.sendCommand)
        .mockResolvedValueOnce('cmd-1') // Initial deployment
        .mockRejectedValueOnce(new Error('Rollback failed')); // Rollback fails

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 1,
        rollbackOnFailure: true,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      await settleResult(resultPromise, 'rollback (failure logging)');

      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.objectContaining({
          sensorId: expect.any(String),
          error: expect.stringContaining('Rollback failed'),
        }),
        'Rollback failed for sensor'
      );
    });
  });

  // =============================================================================
  // Health Check Logic Tests
  // =============================================================================

  describe('Health Check Logic', () => {
    it('should mark sensor healthy with fresh heartbeat and connected state', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensor.findUnique).mockResolvedValue({
        id: 'sensor-1',
        lastHeartbeat: new Date(), // Fresh
        connectionState: 'CONNECTED',
      } as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findUnique>>);

      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue({
        sensorId: 'sensor-1',
        ruleId: 'rule-1',
        status: 'synced',
      } as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findFirst>>);

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'health check (healthy sensor)');

      expect(result.success).toBe(true);
      expect(result.failureCount).toBe(0);
    });

    it('should mark sensor degraded with stale heartbeat', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
        {
          id: 'sensor-1',
          lastHeartbeat: new Date(Date.now() - 90000), // 90 seconds old
          connectionState: 'CONNECTED',
          tenantId: TEST_TENANT_ID,
        }
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findMany>>);

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'health check (stale heartbeat)');

      // Degraded sensors count as failures
      expect(result.failureCount).toBeGreaterThan(0);
    });

    it('should mark sensor unhealthy when disconnected', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
        {
          id: 'sensor-1',
          lastHeartbeat: new Date(),
          connectionState: 'DISCONNECTED',
          tenantId: TEST_TENANT_ID,
        }
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findMany>>);

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'health check (disconnected sensor)');

      expect(result.failureCount).toBeGreaterThan(0);
    });

    it('should mark sensor unhealthy when not found', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      // Health check returns empty (sensor not found) while ownership still works
      mockSensorFindManyForHealth(() => Promise.resolve([]));

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'health check (sensor missing)');

      expect(result.failureCount).toBeGreaterThan(0);
    });

    it('should handle health check database errors', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      // Health check rejects with DB error while ownership still works
      mockSensorFindManyForHealth(() =>
        Promise.reject(new Error('Database connection failed'))
      );

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'health check (db error)');

      expect(result.failureCount).toBeGreaterThan(0);
    });

    it('should respect health check timeout', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      // Sensor never found during health check (ownership still works)
      mockSensorFindManyForHealth(() => Promise.resolve([]));

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 50,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'health check (timeout)');

      // Should complete with health check timeout failure
      expect(result.failureCount).toBeGreaterThan(0);
    });

    it('should poll at configured interval during health check', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      let pollCount = 0;
      mockSensorFindManyForHealth(() => {
        pollCount++;
        if (pollCount < 3) {
          return Promise.resolve([]);
        }
        return Promise.resolve([{
          id: 'sensor-1',
          lastHeartbeat: new Date(),
          connectionState: 'CONNECTED',
          tenantId: TEST_TENANT_ID,
        }]);
      });

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 500,
        healthCheckIntervalMs: 20,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'health check (poll interval)', {
        stepMs: 50,
        maxSteps: 50,
      });

      expect(result.success).toBe(true);
      expect(pollCount).toBeGreaterThanOrEqual(3);
    });
  });

  // =============================================================================
  // Rule Sync State Management Tests
  // =============================================================================

  describe('Rule Sync State Management', () => {
    it('should mark rule as synced', async () => {
      await distributor.markRuleSynced('sensor-1', 'rule-1');

      expect(mockPrisma.ruleSyncState.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            sensorId_ruleId: {
              sensorId: 'sensor-1',
              ruleId: 'rule-1',
            },
          },
          create: expect.objectContaining({
            sensorId: 'sensor-1',
            ruleId: 'rule-1',
            status: 'synced',
            syncedAt: expect.any(Date),
          }),
          update: expect.objectContaining({
            status: 'synced',
            syncedAt: expect.any(Date),
            error: null,
          }),
        })
      );

      expect(mockLogger.info).toHaveBeenCalledWith(
        { sensorId: 'sensor-1', ruleId: 'rule-1' },
        'Rule synced'
      );
    });

    it('should mark rule as failed with error message', async () => {
      await distributor.markRuleFailed('sensor-1', 'rule-1', 'Validation error');

      expect(mockPrisma.ruleSyncState.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            sensorId_ruleId: {
              sensorId: 'sensor-1',
              ruleId: 'rule-1',
            },
          },
          create: expect.objectContaining({
            sensorId: 'sensor-1',
            ruleId: 'rule-1',
            status: 'failed',
            error: 'Validation error',
          }),
          update: expect.objectContaining({
            status: 'failed',
            error: 'Validation error',
          }),
        })
      );

      expect(mockLogger.warn).toHaveBeenCalledWith(
        { sensorId: 'sensor-1', ruleId: 'rule-1', error: 'Validation error' },
        'Rule sync failed'
      );
    });

    it('should bulk update rule sync states', async () => {
      const updates = [
        { ruleId: 'rule-1', status: 'synced' as const },
        { ruleId: 'rule-2', status: 'failed' as const, error: 'Parse error' },
        { ruleId: 'rule-3', status: 'synced' as const },
      ];

      await distributor.bulkUpdateRuleSync('sensor-1', updates);

      // Should call upsert for each update
      expect(mockPrisma.ruleSyncState.upsert).toHaveBeenCalledTimes(3);
    });

    it('should use Unknown error for failed status without error message', async () => {
      const updates = [
        { ruleId: 'rule-1', status: 'failed' as const }, // No error message
      ];

      await distributor.bulkUpdateRuleSync('sensor-1', updates);

      expect(mockPrisma.ruleSyncState.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          update: expect.objectContaining({
            error: 'Unknown error',
          }),
        })
      );
    });
  });

  // =============================================================================
  // Rule Sync Status Queries Tests
  // =============================================================================

  describe('Rule Sync Status Queries', () => {
    it('should get rule sync status across fleet', async () => {
      vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
        {
          id: 'sensor-1',
          ruleSyncState: [
            { status: 'synced', syncedAt: new Date(), error: null },
            { status: 'synced', syncedAt: new Date(), error: null },
          ],
        },
        {
          id: 'sensor-2',
          ruleSyncState: [
            { status: 'pending', syncedAt: null, error: null },
            { status: 'failed', syncedAt: null, error: 'Timeout' },
          ],
        },
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findMany>>);

      const status = await distributor.getRuleSyncStatus();

      expect(status).toHaveLength(2);
      expect(status[0]).toEqual(
        expect.objectContaining({
          sensorId: 'sensor-1',
          totalRules: 2,
          syncedRules: 2,
          pendingRules: 0,
          failedRules: 0,
        })
      );
      expect(status[1]).toEqual(
        expect.objectContaining({
          sensorId: 'sensor-2',
          totalRules: 2,
          syncedRules: 0,
          pendingRules: 1,
          failedRules: 1,
          errors: ['Timeout'],
        })
      );
    });

    it('should get sensor rule status', async () => {
      vi.mocked(mockPrisma.ruleSyncState.findMany).mockResolvedValue([
        {
          ruleId: 'rule-1',
          status: 'synced',
          syncedAt: new Date('2024-01-01'),
          error: null,
        },
        {
          ruleId: 'rule-2',
          status: 'failed',
          syncedAt: null,
          error: 'Invalid format',
        },
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findMany>>);

      const status = await distributor.getSensorRuleStatus('sensor-1');

      expect(status.sensorId).toBe('sensor-1');
      expect(status.rules).toHaveLength(2);
      expect(status.rules[0]).toEqual(
        expect.objectContaining({
          ruleId: 'rule-1',
          status: 'synced',
        })
      );
      expect(status.rules[1]).toEqual(
        expect.objectContaining({
          ruleId: 'rule-2',
          status: 'failed',
          error: 'Invalid format',
        })
      );
    });

    it('should get sensors with failed rules', async () => {
      vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
        {
          id: 'sensor-1',
          ruleSyncState: [{ ruleId: 'rule-1' }, { ruleId: 'rule-2' }],
        },
        {
          id: 'sensor-2',
          ruleSyncState: [],
        },
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findMany>>);

      const sensors = await distributor.getSensorsWithFailedRules();

      expect(sensors).toHaveLength(1);
      expect(sensors[0]).toEqual({
        sensorId: 'sensor-1',
        failedRules: ['rule-1', 'rule-2'],
      });
    });
  });

  // =============================================================================
  // Retry Failed Rules Tests
  // =============================================================================

  describe('Retry Failed Rules', () => {
    it('should retry failed rules for a sensor', async () => {
      vi.mocked(mockPrisma.ruleSyncState.findMany).mockResolvedValue([
        { id: 'state-1', ruleId: 'rule-1', status: 'failed' },
        { id: 'state-2', ruleId: 'rule-2', status: 'failed' },
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findMany>>);

      const result = await distributor.retryFailedRules(TEST_TENANT_ID, 'sensor-1');

      expect(result.success).toBe(true);
      expect(result.pendingCount).toBe(1);
      expect(mockPrisma.ruleSyncState.update).toHaveBeenCalledTimes(2);
      expect(mockFleetCommander.sendCommand).toHaveBeenCalledWith(
        TEST_TENANT_ID,
        'sensor-1',
        expect.objectContaining({
          type: 'push_rules',
          payload: expect.objectContaining({
            ruleIds: ['rule-1', 'rule-2'],
            retry: true,
          }),
        })
      );
    });

    it('should return empty result when no failed rules', async () => {
      vi.mocked(mockPrisma.ruleSyncState.findMany).mockResolvedValue([]);

      const result = await distributor.retryFailedRules(TEST_TENANT_ID, 'sensor-1');

      expect(result.success).toBe(true);
      expect(result.totalTargets).toBe(0);
      expect(result.results).toHaveLength(0);
      expect(mockFleetCommander.sendCommand).not.toHaveBeenCalled();
    });

    it('should throw error when FleetCommander not set', async () => {
      const distributorWithoutCommander = new RuleDistributor(mockPrisma, mockLogger);

      vi.mocked(mockPrisma.ruleSyncState.findMany).mockResolvedValue([
        { id: 'state-1', ruleId: 'rule-1', status: 'failed' },
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findMany>>);

      await expect(
        distributorWithoutCommander.retryFailedRules(TEST_TENANT_ID, 'sensor-1')
      ).rejects.toThrow('FleetCommander not initialized');
    });

    it('should validate tenant ownership before retry', async () => {
      const DIFFERENT_TENANT = 'different-tenant';

      vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
        { id: 'sensor-1', tenantId: DIFFERENT_TENANT },
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findMany>>);

      await expect(
        distributor.retryFailedRules(TEST_TENANT_ID, 'sensor-1')
      ).rejects.toThrow(TenantIsolationError);
    });

    it('should log retry attempt', async () => {
      vi.mocked(mockPrisma.ruleSyncState.findMany).mockResolvedValue([
        { id: 'state-1', ruleId: 'rule-1', status: 'failed' },
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findMany>>);

      await distributor.retryFailedRules(TEST_TENANT_ID, 'sensor-1');

      expect(mockLogger.info).toHaveBeenCalledWith(
        { sensorId: 'sensor-1', failedCount: 1 },
        'Retrying failed rule syncs'
      );
    });

    it('should reset status to pending before retry', async () => {
      vi.mocked(mockPrisma.ruleSyncState.findMany).mockResolvedValue([
        { id: 'state-1', ruleId: 'rule-1', status: 'failed' },
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findMany>>);

      await distributor.retryFailedRules(TEST_TENANT_ID, 'sensor-1');

      expect(mockPrisma.ruleSyncState.update).toHaveBeenCalledWith({
        where: { id: 'state-1' },
        data: {
          status: 'pending',
          error: null,
        },
      });
    });
  });

  // =============================================================================
  // distributeRules Tests
  // =============================================================================

  describe('distributeRules', () => {
    it('should fetch rules and deploy with specified strategy', async () => {
      const ruleIds = ['rule-1', 'rule-2'];
      const sensorIds = ['sensor-1', 'sensor-2'];

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

      const resultPromise = distributor.distributeRules(TEST_TENANT_ID, ruleIds, sensorIds, {
        strategy: 'immediate',
      });

      const result = await settleResult(resultPromise, 'distribute rules (immediate)');

      expect(result.success).toBe(true);
      expect(result.totalTargets).toBe(2);
    });

    it('should validate tenant ownership before distribution', async () => {
      const DIFFERENT_TENANT = 'different-tenant';
      const ruleIds = ['rule-1'];
      const sensorIds = ['sensor-1'];

      vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
        { id: 'sensor-1', tenantId: DIFFERENT_TENANT },
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findMany>>);

      await expect(
        distributor.distributeRules(TEST_TENANT_ID, ruleIds, sensorIds, {
          strategy: 'immediate',
        })
      ).rejects.toThrow(TenantIsolationError);
    });

	    it('should use canary percentage in config', async () => {
	      const ruleIds = ['rule-1'];
	      const sensorIds = ['s1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10'];

	      // Focus this test on config plumbing (not timer-based rollout execution).
	      const deployCanarySpy = vi
	        // eslint-disable-next-line @typescript-eslint/no-explicit-any
	        .spyOn(distributor as any, 'deployCanary')
	        .mockResolvedValue({
	          success: true,
	          totalTargets: sensorIds.length,
	          successCount: 0,
	          failureCount: 0,
	          pendingCount: sensorIds.length,
	          results: sensorIds.map((sensorId, i) => ({ sensorId, success: true, commandId: `cmd-${i}` })),
	        });

	      await distributor.distributeRules(TEST_TENANT_ID, ruleIds, sensorIds, {
	        strategy: 'canary',
	        canaryPercentage: 25,
	      });

	      expect(deployCanarySpy).toHaveBeenCalledWith(
	        TEST_TENANT_ID,
	        sensorIds,
	        expect.any(Array),
	        expect.objectContaining({ canaryPercentages: [25, 50, 100] })
	      );
	    });
	  });

  // =============================================================================
  // pushRules (Simple API) Tests
  // =============================================================================

  describe('pushRules (Simple API)', () => {
    it('should deploy rules immediately', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];

      const resultPromise = distributor.pushRules(TEST_TENANT_ID, sensorIds, rules);

      const result = await settleResult(resultPromise, 'push rules (simple)');

      expect(result.success).toBe(true);
      expect(result.totalTargets).toBe(2);
      expect(mockFleetCommander.sendCommandToMultiple).toHaveBeenCalled();
    });

    it('should validate tenant ownership', async () => {
      const DIFFERENT_TENANT = 'different-tenant';
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensor.findMany).mockResolvedValue([
        { id: 'sensor-1', tenantId: DIFFERENT_TENANT },
      ] as unknown as Awaited<ReturnType<typeof mockPrisma.sensor.findMany>>);

      await expect(
        distributor.pushRules(TEST_TENANT_ID, sensorIds, rules)
      ).rejects.toThrow(TenantIsolationError);
    });
  });

  // =============================================================================
  // Blue/Green Status Updates Tests
  // =============================================================================

  describe('Blue/Green Status Updates', () => {
    it('should update sensor staging status', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: 5000,
        switchTimeout: 3000,
        requireAllSensorsStaged: false,
        minStagedPercentage: 0,
      };

      // Start deployment
      distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      // Advance to allow staging commands to be sent
      await advanceUntil(
        () => (getSendCommandMock().mock.calls.length > 0 ? true : undefined),
        { stepMs: ASYNC_INIT_DELAY_MS, maxSteps: 20, description: 'sendCommand initialization' }
      );

      const deployments = distributor.listActiveDeployments(TEST_TENANT_ID);
      expect(deployments.length).toBe(1);
      const deploymentId = deployments[0].deploymentId;

      // Update staging status
      distributor.updateSensorStagingStatus(deploymentId, 'sensor-1', true);

      const status = distributor.getDeploymentStatus(TEST_TENANT_ID, deploymentId);
      expect(status?.sensorStatus.get('sensor-1')?.stagingStatus).toBe('staged');
    });

    it('should update sensor staging status with error', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: 5000,
        switchTimeout: 3000,
        requireAllSensorsStaged: false,
        minStagedPercentage: 0,
      };

      // Start deployment
      distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      for (let i = 0; i < 10; i++) {
        await vi.advanceTimersByTimeAsync(ASYNC_INIT_DELAY_MS);
        await Promise.resolve();
      }

      const deployments = distributor.listActiveDeployments(TEST_TENANT_ID);
      const deploymentId = deployments[0].deploymentId;

      // Update staging status with failure
      distributor.updateSensorStagingStatus(deploymentId, 'sensor-1', false, 'Disk full');

      const status = distributor.getDeploymentStatus(TEST_TENANT_ID, deploymentId);
      expect(status?.sensorStatus.get('sensor-1')?.stagingStatus).toBe('failed');
      expect(status?.sensorStatus.get('sensor-1')?.error).toBe('Disk full');
    });

    it('should update sensor activation status', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.sensorSyncState.findUnique).mockResolvedValue(null);

      const config: RolloutConfig = {
        strategy: 'blue_green',
        stagingTimeout: 5000,
        switchTimeout: 3000,
        requireAllSensorsStaged: false,
        minStagedPercentage: 0,
      };

      // Start deployment
      distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      for (let i = 0; i < 10; i++) {
        await vi.advanceTimersByTimeAsync(ASYNC_INIT_DELAY_MS);
        await Promise.resolve();
      }

      const deployments = distributor.listActiveDeployments(TEST_TENANT_ID);
      const deploymentId = deployments[0].deploymentId;

      // Mark as staged first
      distributor.updateSensorStagingStatus(deploymentId, 'sensor-1', true);

      // Then activate
      distributor.updateSensorActivationStatus(deploymentId, 'sensor-1', true);

      const status = distributor.getDeploymentStatus(TEST_TENANT_ID, deploymentId);
      expect(status?.sensorStatus.get('sensor-1')?.activeStatus).toBe('green');
    });

    it('should hydrate + persist status update when deployment not in memory', async () => {
      const deploymentId = 'dep-1';
      const state = {
        deploymentId,
        tenantId: TEST_TENANT_ID,
        status: 'staging',
        rules: [],
        sensorStatus: new Map([
          [
            'sensor-1',
            {
              sensorId: 'sensor-1',
              stagingStatus: 'pending',
              activeStatus: 'unknown',
              lastUpdated: new Date(0),
            },
          ],
        ]),
      } as any;

      const store: DeploymentStateStore = {
        loadAll: vi.fn(async () => []),
        getByDeploymentId: vi.fn(async (id: string) => (id === deploymentId ? state : null)),
        upsert: vi.fn(async () => {}),
        delete: vi.fn(async () => {}),
      };

      const dist = new RuleDistributor(createMockPrisma(['sensor-1']), createMockLogger(), store);

      dist.updateSensorStagingStatus(deploymentId, 'sensor-1', true);

      await vi.advanceTimersByTimeAsync(ASYNC_INIT_DELAY_MS);
      await Promise.resolve();

      expect(vi.mocked(store.getByDeploymentId)).toHaveBeenCalledWith(deploymentId);
      expect(vi.mocked(store.upsert)).toHaveBeenCalled();
      const persisted = vi.mocked(store.upsert).mock.calls[0]?.[0] as any;
      expect(persisted.sensorStatus.get('sensor-1')?.stagingStatus).toBe('staged');
    });

    it('should handle status update for non-existent deployment', () => {
      // Should not throw, just no-op
      expect(() => {
        distributor.updateSensorStagingStatus('non-existent-id', 'sensor-1', true);
      }).not.toThrow();

      expect(() => {
        distributor.updateSensorActivationStatus('non-existent-id', 'sensor-1', true);
      }).not.toThrow();
    });
  });

  // =============================================================================
  // Error Handling Tests
  // =============================================================================

  describe('Error Handling', () => {
    it('should handle sensor offline during immediate deployment', async () => {
      const sensorIds = ['sensor-1', 'sensor-2'];
      const rules = [createTestRule()];

      // Simulate command send failure for one sensor
      vi.mocked(mockFleetCommander.sendCommandToMultiple).mockResolvedValue([
        'cmd-1',
        'cmd-2', // Both return IDs but actual delivery may fail
      ]);

      const config: RolloutConfig = {
        strategy: 'immediate',
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'error handling (offline immediate)');

      // Returns success because commands were queued (delivery is async)
      expect(result.success).toBe(true);
      expect(result.pendingCount).toBe(2);
    });

    it('should handle partial failures in multi-sensor deployment', async () => {
      const sensorIds = ['sensor-1', 'sensor-2', 'sensor-3'];
      const rules = [createTestRule()];

      // First two succeed, third fails to deploy
      vi.mocked(mockFleetCommander.sendCommand)
        .mockResolvedValueOnce('cmd-1')
        .mockResolvedValueOnce('cmd-2')
        .mockRejectedValueOnce(new Error('Network timeout'));

      // Mix of healthy and unhealthy sensors for health checks
      let healthCheckCount = 0;
      vi.mocked(mockPrisma.sensor.findUnique).mockImplementation(() => {
        healthCheckCount++;
        return Promise.resolve({
          id: `sensor-${healthCheckCount}`,
          lastHeartbeat: new Date(),
          connectionState: 'CONNECTED',
        }) as unknown as ReturnType<typeof mockPrisma.sensor.findUnique>;
      });

      vi.mocked(mockPrisma.ruleSyncState.findFirst).mockResolvedValue({
        sensorId: 'sensor-1',
        ruleId: 'rule-1',
        status: 'synced',
      } as unknown as Awaited<ReturnType<typeof mockPrisma.ruleSyncState.findFirst>>);

      const config: RolloutConfig = {
        strategy: 'rolling',
        rollingBatchSize: 1,
        healthCheckTimeout: 100,
        healthCheckIntervalMs: 10,
        maxFailuresBeforeAbort: 5,
      };

      const resultPromise = distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config);

      const result = await settleResult(resultPromise, 'error handling (partial failures)');

      expect(result.failureCount).toBeGreaterThanOrEqual(1);
      expect(result.results.some((r) => r.error?.includes('Network timeout'))).toBe(true);
    });

    it('should handle database errors during sync state creation', async () => {
      const sensorIds = ['sensor-1'];
      const rules = [createTestRule()];

      vi.mocked(mockPrisma.ruleSyncState.upsert).mockRejectedValueOnce(
        new Error('Database connection lost')
      );

      const config: RolloutConfig = {
        strategy: 'immediate',
      };

      await expect(
        distributor.pushRulesWithStrategy(TEST_TENANT_ID, sensorIds, rules, config)
      ).rejects.toThrow('Database connection lost');
    });
  });
});
