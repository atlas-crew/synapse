/**
 * Fleet Routes Strategy Tests
 *
 * Tests for PushRulesBodySchema validation covering:
 * - Rolling and blue_green strategy acceptance
 * - Strategy-specific option validation
 * - Invalid strategy options rejection
 * - Strategy options passed to RuleDistributor
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import request from '../../__tests__/test-request.js';
import { createFleetRoutes } from './fleet.js';
import type { PrismaClient, Sensor } from '@prisma/client';
import type { Logger } from 'pino';
import type { RuleDistributor } from '../../services/fleet/rule-distributor.js';

// Mock the auth middleware module
vi.mock('../middleware/auth.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../middleware/auth.js')>();
  return {
    ...actual,
    requireScope: (scope: string) => (req: Request, _res: Response, next: NextFunction) => {
      if (req.auth?.scopes?.includes(scope)) {
        return next();
      }
      if (scope === 'fleet:read' && req.auth?.scopes?.some((s: string) => s.startsWith('fleet:'))) {
        return next();
      }
      _res.status(403).json({ error: 'Forbidden' });
    },
    requireRole: () => (_req: Request, _res: Response, next: NextFunction) => next(),
  };
});

vi.mock('../../middleware/rate-limiter.js', () => ({
  rateLimiters: {
    fleetCommand: (_req: Request, _res: Response, next: NextFunction) => next(),
    configMutation: (_req: Request, _res: Response, next: NextFunction) => next(),
  },
}));

// Mock logger
const mockLogger: Logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

// Auth middleware to inject auth object
const injectAuth = (tenantId: string, scopes: string[] = ['fleet:read', 'fleet:write']) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    req.auth = { tenantId, scopes } as unknown as typeof req.auth;
    next();
  };
};

// Factory to create mock sensor
const createMockSensor = (overrides: Partial<Sensor> = {}): Sensor => ({
  id: 'sensor-1',
  name: 'Test Sensor',
  hostname: 'sensor-1.local',
  tenantId: 'tenant-1',
  connectionState: 'CONNECTED',
  lastHeartbeat: new Date(),
  createdAt: new Date(),
  updatedAt: new Date(),
  region: 'us-east-1',
  version: '1.0.0',
  lastSignalAt: null,
  signalsReported: 0,
  blocksApplied: 0,
  ipAddress: null,
  publicIp: null,
  privateIp: null,
  os: null,
  kernel: null,
  architecture: null,
  instanceType: null,
  lastBoot: null,
  uptime: null,
  tunnelActive: false,
  tunnelSessionId: null,
  metadata: null,
  registrationMethod: 'MANUAL',
  registrationToken: null,
  approvalStatus: 'APPROVED',
  approvedAt: null,
  approvedBy: null,
  registrationTokenId: null,
  fingerprint: null,
  ...overrides,
});

type SensorFindManyArgs = Parameters<PrismaClient['sensor']['findMany']>[0];

const extractRequestedSensorIds = (args?: SensorFindManyArgs): string[] => {
  const where = (args?.where ?? {}) as { id?: { in?: string[] } };
  const ids = where.id?.in ?? [];
  return Array.isArray(ids) ? ids : [];
};

describe('Fleet Routes - Strategy Validation', () => {
  let app: Express;
  let mockPrisma: Partial<PrismaClient>;
  let mockRuleDistributor: Partial<RuleDistributor>;

  beforeEach(() => {
    mockPrisma = {
      sensor: {
        findMany: vi.fn(),
        findUnique: vi.fn(),
        count: vi.fn(),
      } as unknown as PrismaClient['sensor'],
      fleetCommand: {
        findMany: vi.fn(),
      } as unknown as PrismaClient['fleetCommand'],
      ruleSyncState: {
        findMany: vi.fn(),
      } as unknown as PrismaClient['ruleSyncState'],
    };

    mockRuleDistributor = {
      distributeRules: vi.fn().mockResolvedValue({
        success: true,
        totalTargets: 2,
        successCount: 0,
        failureCount: 0,
        pendingCount: 2,
        results: [
          { sensorId: 'sensor-1', success: true },
          { sensorId: 'sensor-2', success: true },
        ],
      }),
    };

    app = express();
    app.use(express.json());
    app.use(injectAuth('tenant-1', ['fleet:read', 'fleet:write']));
    app.use(
      '/fleet',
      createFleetRoutes(mockPrisma as PrismaClient, mockLogger, {
        ruleDistributor: mockRuleDistributor as RuleDistributor,
      })
    );
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('POST /fleet/rules/push - Schema Validation', () => {
    beforeEach(() => {
      // Mock sensor lookup for tenant validation
      // Returns sensors that match the requested IDs
      const findMany = vi.mocked(
        mockPrisma.sensor!.findMany as unknown as PrismaClient['sensor']['findMany']
      );
      findMany.mockImplementation(async (args?: SensorFindManyArgs) => {
        const requestedIds = extractRequestedSensorIds(args);
        const allSensors = [
          createMockSensor({ id: 'sensor-1' }),
          createMockSensor({ id: 'sensor-2' }),
        ];
        return allSensors.filter((s) => requestedIds.includes(s.id));
      });
    });

    it('should accept rolling strategy', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1', 'rule-2'],
          sensorIds: ['sensor-1', 'sensor-2'],
          strategy: 'rolling',
        })
        .expect(202);

      expect(res.body).toHaveProperty('message', 'Rule distribution initiated');
      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1', 'rule-2'],
        ['sensor-1', 'sensor-2'],
        expect.objectContaining({
          strategy: 'rolling',
        })
      );
    });

    it('should accept blue_green strategy', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1', 'rule-2'],
          sensorIds: ['sensor-1', 'sensor-2'],
          strategy: 'blue_green',
        })
        .expect(202);

      expect(res.body).toHaveProperty('message', 'Rule distribution initiated');
      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1', 'rule-2'],
        ['sensor-1', 'sensor-2'],
        expect.objectContaining({
          strategy: 'blue_green',
        })
      );
    });

    it('should accept immediate strategy', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'immediate',
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          strategy: 'immediate',
        })
      );
    });

    it('should accept canary strategy', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'canary',
          canaryPercentage: 10,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          strategy: 'canary',
          canaryPercentage: 10,
        })
      );
    });

    it('should accept scheduled strategy with scheduledTime', async () => {
      const futureTime = new Date(Date.now() + 3600000).toISOString();
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'scheduled',
          scheduledTime: futureTime,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          strategy: 'scheduled',
          scheduledTime: expect.any(Date),
        })
      );
    });

    it('should use immediate as default strategy when not specified', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          strategy: 'immediate',
        })
      );
    });
  });

  describe('Rolling Strategy Options Validation', () => {
    beforeEach(() => {
      const findMany = vi.mocked(
        mockPrisma.sensor!.findMany as unknown as PrismaClient['sensor']['findMany']
      );
      findMany.mockImplementation(async (args?: SensorFindManyArgs) => {
        const requestedIds = extractRequestedSensorIds(args);
        const allSensors = [createMockSensor({ id: 'sensor-1' })];
        return allSensors.filter((s) => requestedIds.includes(s.id));
      });
    });

    it('should validate rollingBatchSize within bounds (1-100)', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
          rollingBatchSize: 5,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          strategy: 'rolling',
          rollingBatchSize: 5,
        })
      );
    });

    it('should validate healthCheckTimeout within bounds (5000-300000)', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
          healthCheckTimeout: 60000,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          healthCheckTimeout: 60000,
        })
      );
    });

    it('should validate maxFailuresBeforeAbort within bounds (1-100)', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
          maxFailuresBeforeAbort: 5,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          maxFailuresBeforeAbort: 5,
        })
      );
    });

    it('should accept rollbackOnFailure boolean option', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
          rollbackOnFailure: false,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          rollbackOnFailure: false,
        })
      );
    });

    it('should validate healthCheckIntervalMs within bounds (1000-60000)', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
          healthCheckIntervalMs: 10000,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          healthCheckIntervalMs: 10000,
        })
      );
    });

    it('should pass all rolling options together', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
          rollingBatchSize: 3,
          healthCheckTimeout: 45000,
          maxFailuresBeforeAbort: 2,
          rollbackOnFailure: true,
          healthCheckIntervalMs: 5000,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          strategy: 'rolling',
          rollingBatchSize: 3,
          healthCheckTimeout: 45000,
          maxFailuresBeforeAbort: 2,
          rollbackOnFailure: true,
          healthCheckIntervalMs: 5000,
        })
      );
    });
  });

  describe('Blue/Green Strategy Options Validation', () => {
    beforeEach(() => {
      const findMany = vi.mocked(
        mockPrisma.sensor!.findMany as unknown as PrismaClient['sensor']['findMany']
      );
      findMany.mockImplementation(async (args?: SensorFindManyArgs) => {
        const requestedIds = extractRequestedSensorIds(args);
        const allSensors = [createMockSensor({ id: 'sensor-1' })];
        return allSensors.filter((s) => requestedIds.includes(s.id));
      });
    });

    it('should validate stagingTimeout within bounds (10000-600000)', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'blue_green',
          stagingTimeout: 120000,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          stagingTimeout: 120000,
        })
      );
    });

    it('should validate switchTimeout within bounds (5000-300000)', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'blue_green',
          switchTimeout: 60000,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          switchTimeout: 60000,
        })
      );
    });

    it('should accept requireAllSensorsStaged boolean option', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'blue_green',
          requireAllSensorsStaged: false,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          requireAllSensorsStaged: false,
        })
      );
    });

    it('should validate minStagedPercentage within bounds (1-100)', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'blue_green',
          minStagedPercentage: 90,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          minStagedPercentage: 90,
        })
      );
    });

    it('should validate cleanupDelayMs within bounds (60000-3600000)', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'blue_green',
          cleanupDelayMs: 600000,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          cleanupDelayMs: 600000,
        })
      );
    });

    it('should pass all blue_green options together', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'blue_green',
          stagingTimeout: 90000,
          switchTimeout: 45000,
          requireAllSensorsStaged: true,
          minStagedPercentage: 95,
          cleanupDelayMs: 300000,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          strategy: 'blue_green',
          stagingTimeout: 90000,
          switchTimeout: 45000,
          requireAllSensorsStaged: true,
          minStagedPercentage: 95,
          cleanupDelayMs: 300000,
        })
      );
    });
  });

  describe('Invalid Strategy Options Rejection', () => {
    beforeEach(() => {
      const findMany = vi.mocked(
        mockPrisma.sensor!.findMany as unknown as PrismaClient['sensor']['findMany']
      );
      findMany.mockImplementation(async (args?: SensorFindManyArgs) => {
        const requestedIds = extractRequestedSensorIds(args);
        const allSensors = [createMockSensor({ id: 'sensor-1' })];
        return allSensors.filter((s) => requestedIds.includes(s.id));
      });
    });

    it('should reject invalid strategy value', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'invalid_strategy',
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject rollingBatchSize below minimum (1)', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
          rollingBatchSize: 0,
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject rollingBatchSize above maximum (100)', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
          rollingBatchSize: 101,
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject healthCheckTimeout below minimum (5000)', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
          healthCheckTimeout: 1000,
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject healthCheckTimeout above maximum (300000)', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
          healthCheckTimeout: 400000,
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject stagingTimeout below minimum (10000)', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'blue_green',
          stagingTimeout: 5000,
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject stagingTimeout above maximum (600000)', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'blue_green',
          stagingTimeout: 700000,
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject cleanupDelayMs below minimum (60000)', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'blue_green',
          cleanupDelayMs: 30000,
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject cleanupDelayMs above maximum (3600000)', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'blue_green',
          cleanupDelayMs: 4000000,
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject minStagedPercentage below minimum (1)', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'blue_green',
          minStagedPercentage: 0,
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject minStagedPercentage above maximum (100)', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'blue_green',
          minStagedPercentage: 101,
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject empty ruleIds array', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: [],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject empty sensorIds array', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: [],
          strategy: 'rolling',
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject invalid scheduledTime format', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'scheduled',
          scheduledTime: 'not-a-date',
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject canaryPercentage below minimum (1)', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'canary',
          canaryPercentage: 0,
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });

    it('should reject canaryPercentage above maximum (100)', async () => {
      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'canary',
          canaryPercentage: 150,
        })
        .expect(400);

      expect(res.body).toHaveProperty('detail');
    });
  });

  describe('Strategy Options Passed to RuleDistributor', () => {
    beforeEach(() => {
      const findMany = vi.mocked(
        mockPrisma.sensor!.findMany as unknown as PrismaClient['sensor']['findMany']
      );
      findMany.mockImplementation(async (args?: SensorFindManyArgs) => {
        const requestedIds = extractRequestedSensorIds(args);
        const allSensors = [
          createMockSensor({ id: 'sensor-1' }),
          createMockSensor({ id: 'sensor-2' }),
        ];
        return allSensors.filter((s) => requestedIds.includes(s.id));
      });
    });

    it('should pass all strategy options to distributeRules for rolling strategy', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1', 'rule-2'],
          sensorIds: ['sensor-1', 'sensor-2'],
          strategy: 'rolling',
          rollingBatchSize: 10,
          healthCheckTimeout: 60000,
          maxFailuresBeforeAbort: 5,
          rollbackOnFailure: false,
          healthCheckIntervalMs: 10000,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledTimes(1);
      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1', 'rule-2'],
        ['sensor-1', 'sensor-2'],
        {
          strategy: 'rolling',
          canaryPercentage: undefined,
          scheduledTime: undefined,
          rollingBatchSize: 10,
          healthCheckTimeout: 60000,
          maxFailuresBeforeAbort: 5,
          rollbackOnFailure: false,
          healthCheckIntervalMs: 10000,
          stagingTimeout: undefined,
          switchTimeout: undefined,
          requireAllSensorsStaged: undefined,
          minStagedPercentage: undefined,
          cleanupDelayMs: undefined,
        }
      );
    });

    it('should pass all strategy options to distributeRules for blue_green strategy', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1', 'rule-2'],
          sensorIds: ['sensor-1', 'sensor-2'],
          strategy: 'blue_green',
          stagingTimeout: 120000,
          switchTimeout: 60000,
          requireAllSensorsStaged: true,
          minStagedPercentage: 95,
          cleanupDelayMs: 600000,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledTimes(1);
      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1', 'rule-2'],
        ['sensor-1', 'sensor-2'],
        {
          strategy: 'blue_green',
          canaryPercentage: undefined,
          scheduledTime: undefined,
          rollingBatchSize: undefined,
          healthCheckTimeout: undefined,
          maxFailuresBeforeAbort: undefined,
          rollbackOnFailure: undefined,
          healthCheckIntervalMs: undefined,
          stagingTimeout: 120000,
          switchTimeout: 60000,
          requireAllSensorsStaged: true,
          minStagedPercentage: 95,
          cleanupDelayMs: 600000,
        }
      );
    });

    it('should handle missing optional options with undefined', async () => {
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          strategy: 'rolling',
          rollingBatchSize: undefined,
          healthCheckTimeout: undefined,
          maxFailuresBeforeAbort: undefined,
          rollbackOnFailure: undefined,
          healthCheckIntervalMs: undefined,
        })
      );
    });

    it('should convert scheduledTime string to Date before passing to distributeRules', async () => {
      const futureTime = '2025-12-31T23:59:59.000Z';
      await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'scheduled',
          scheduledTime: futureTime,
        })
        .expect(202);

      expect(mockRuleDistributor.distributeRules).toHaveBeenCalledWith(
        'tenant-1',
        ['rule-1'],
        ['sensor-1'],
        expect.objectContaining({
          strategy: 'scheduled',
          scheduledTime: new Date(futureTime),
        })
      );
    });
  });

  describe('Error Handling', () => {
    it('should return 503 when ruleDistributor is not available', async () => {
      const appWithoutDistributor = express();
      appWithoutDistributor.use(express.json());
      appWithoutDistributor.use(injectAuth('tenant-1', ['fleet:read', 'fleet:write']));
      appWithoutDistributor.use(
        '/fleet',
        createFleetRoutes(mockPrisma as PrismaClient, mockLogger, {})
      );

      const res = await request(appWithoutDistributor)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1'],
          strategy: 'rolling',
        })
        .expect(503);

      expect(res.body).toHaveProperty('error', 'Rule distributor service not available');
    });

    it('should return 400 when some sensors do not belong to tenant', async () => {
      vi.mocked(
        mockPrisma.sensor!.findMany as unknown as PrismaClient['sensor']['findMany']
      ).mockResolvedValue([
        createMockSensor({ id: 'sensor-1' }),
        // sensor-2 missing - simulates not belonging to tenant
      ]);

      const res = await request(app)
        .post('/fleet/rules/push')
        .send({
          ruleIds: ['rule-1'],
          sensorIds: ['sensor-1', 'sensor-2'],
          strategy: 'rolling',
        })
        .expect(400);

      expect(res.body).toHaveProperty('error');
      expect(res.body.error).toMatch(/sensor/i);
    });
  });
});
