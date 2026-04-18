/**
 * Fleet Routes Test Suite
 *
 * Tests for fleet management API endpoints including
 * sensor overview, metrics, configuration, and commands.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import request from '../../__tests__/test-request.js';
import { createFleetRoutes } from './fleet.js';
import type { PrismaClient, Sensor } from '@prisma/client';
import type { ConfigManager } from '../../services/fleet/config-manager.js';
import type { FleetCommander } from '../../services/fleet/fleet-commander.js';
import type { ConfigTemplate } from '../../services/fleet/types.js';
import type { Logger } from 'pino';
import type { SecurityAuditService } from '../../services/audit/security-audit.js';

// Mock the auth middleware module
vi.mock('../middleware/auth.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../middleware/auth.js')>();
  return {
    ...actual,
    requireScope: (scope: string) => (req: Request, _res: Response, next: NextFunction) => {
      // Check if auth has the required scope
      if (req.auth?.scopes?.includes(scope)) {
        return next();
      }
      // For read scopes, allow if any fleet:* scope exists
      if (scope === 'fleet:read' && req.auth?.scopes?.some((s: string) => s.startsWith('fleet:'))) {
        return next();
      }
      _res.status(403).json({ error: 'Forbidden' });
    },
    requireRole: () => (_req: Request, _res: Response, next: NextFunction) => next(),
  };
});

// Mock validation middleware
vi.mock('../middleware/validation.js', () => ({
  validateParams: () => (_req: Request, _res: Response, next: NextFunction) => next(),
  validateQuery: () => (_req: Request, _res: Response, next: NextFunction) => next(),
  validateBody: () => (_req: Request, _res: Response, next: NextFunction) => next(),
  IdParamSchema: {},
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

// Factory to create mock sensor (matches Prisma Sensor model)
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

describe('Fleet Routes', () => {
  let app: Express;
  let mockPrisma: Partial<PrismaClient>;
  let mockFleetCommander: Partial<FleetCommander>;
  let mockAuditService: Partial<SecurityAuditService>;

  beforeEach(() => {
    mockFleetCommander = {
      sendCommand: vi.fn().mockResolvedValue('cmd-1'),
    };
    mockAuditService = {
      logConfigCreated: vi.fn(),
      logConfigUpdated: vi.fn(),
      logConfigDeleted: vi.fn(),
    } as any;

    mockPrisma = {
      sensor: {
        findMany: vi.fn(),
        findFirst: vi.fn(),
        findUnique: vi.fn(),
        count: vi.fn(),
      } as unknown as PrismaClient['sensor'],
      sensorPayloadSnapshot: {
        findMany: vi.fn(),
      } as unknown as PrismaClient['sensorPayloadSnapshot'],
      signal: {
        findMany: vi.fn(),
      } as unknown as PrismaClient['signal'],
      sensorPingoraConfig: {
        findUnique: vi.fn(),
        upsert: vi.fn(),
      } as unknown as PrismaClient['sensorPingoraConfig'],
      fleetCommand: {
        findMany: vi.fn(),
        findFirst: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
      } as unknown as PrismaClient['fleetCommand'],
      synapseRule: {
        findMany: vi.fn().mockResolvedValue([]),
        findFirst: vi.fn().mockResolvedValue(null),
        count: vi.fn().mockResolvedValue(0),
      } as unknown as PrismaClient['synapseRule'],
      tenantRuleOverride: {
        findMany: vi.fn().mockResolvedValue([]),
      } as unknown as PrismaClient['tenantRuleOverride'],
      customerRule: {
        findMany: vi.fn().mockResolvedValue([]),
        count: vi.fn().mockResolvedValue(0),
      } as unknown as PrismaClient['customerRule'],
      $queryRaw: vi.fn(),
    };

    app = express();
    app.use(express.json());
    app.use(injectAuth('tenant-1', ['fleet:read', 'fleet:write']));
    app.use(
      '/fleet',
      createFleetRoutes(mockPrisma as PrismaClient, mockLogger, {
        fleetCommander: mockFleetCommander as FleetCommander,
        securityAuditService: mockAuditService as SecurityAuditService,
      })
    );

    vi.mocked(mockPrisma.sensorPayloadSnapshot!.findMany).mockResolvedValue([]);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('GET /fleet/overview', () => {
    it('should return fleet overview with sensor counts', async () => {
      const sensors = [
        createMockSensor({ connectionState: 'CONNECTED', lastHeartbeat: new Date() }),
        createMockSensor({ id: 'sensor-2', connectionState: 'DISCONNECTED', lastHeartbeat: new Date(Date.now() - 600000) }),
      ];
      vi.mocked(mockPrisma.sensor!.findMany).mockResolvedValue(sensors);
      vi.mocked(mockPrisma.fleetCommand!.findMany).mockResolvedValue([]);

      const res = await request(app)
        .get('/fleet/overview')
        .expect(200);

      expect(res.body).toHaveProperty('summary');
      expect(res.body.summary).toHaveProperty('totalSensors');
      expect(res.body.summary).toHaveProperty('onlineCount');
      expect(res.body.summary).toHaveProperty('offlineCount');
    });

    it('should return region distribution', async () => {
      const sensors = [
        createMockSensor({ region: 'us-east-1' }),
        createMockSensor({ id: 'sensor-2', region: 'eu-west-1' }),
      ];
      vi.mocked(mockPrisma.sensor!.findMany).mockResolvedValue(sensors);
      vi.mocked(mockPrisma.fleetCommand!.findMany).mockResolvedValue([]);

      const res = await request(app)
        .get('/fleet/overview')
        .expect(200);

      expect(res.body).toHaveProperty('regionDistribution');
      expect(Array.isArray(res.body.regionDistribution)).toBe(true);
    });
  });

  describe('GET /fleet/metrics', () => {
    it('should fall back to DB-derived metrics when aggregator is unavailable', async () => {
      const sensors = [
        createMockSensor({ id: 'sensor-1', connectionState: 'CONNECTED', lastHeartbeat: new Date() }),
        createMockSensor({ id: 'sensor-2', connectionState: 'DISCONNECTED', lastHeartbeat: new Date(Date.now() - 600000) }),
      ];
      vi.mocked(mockPrisma.sensor!.findMany).mockResolvedValue(sensors);
      vi.mocked(mockPrisma.sensorPayloadSnapshot!.findMany).mockResolvedValue([
        { sensorId: 'sensor-1', capturedAt: new Date(), stats: { rps: 120, latencyMs: 18 } },
        { sensorId: 'sensor-2', capturedAt: new Date(), stats: { rps: 0, latencyMs: 0 } },
      ] as any);

      const res = await request(app)
        .get('/fleet/metrics')
        .expect(200);

      expect(res.body).toMatchObject({
        totalSensors: 2,
        totalRps: 120,
      });
      expect(res.body).toHaveProperty('onlineCount');
      expect(res.body).toHaveProperty('warningCount');
      expect(res.body).toHaveProperty('offlineCount');
      expect(res.body).toHaveProperty('avgLatencyMs');
    });
  });

  describe('GET /fleet/sensors', () => {
    it('should return list of sensors for tenant', async () => {
      const sensors = [
        createMockSensor(),
        createMockSensor({ id: 'sensor-2', name: 'Sensor Two' }),
      ];
      vi.mocked(mockPrisma.sensor!.findMany).mockResolvedValue(sensors);
      vi.mocked(mockPrisma.sensor!.count).mockResolvedValue(2);

      const res = await request(app)
        .get('/fleet/sensors')
        .expect(200);

      expect(res.body.sensors).toHaveLength(2);
      expect(res.body.sensors[0]).toMatchObject({
        id: 'sensor-1',
        name: 'Test Sensor',
        status: expect.any(String),
        cpu: expect.any(Number),
        memory: expect.any(Number),
        rps: expect.any(Number),
        latencyMs: expect.any(Number),
        version: expect.any(String),
        region: expect.any(String),
      });
      expect(res.body.pagination).toHaveProperty('total', 2);
    });

    it('should support pagination with limit and offset', async () => {
      vi.mocked(mockPrisma.sensor!.findMany).mockResolvedValue([]);
      vi.mocked(mockPrisma.sensor!.count).mockResolvedValue(100);

      const res = await request(app)
        .get('/fleet/sensors?limit=10&offset=20')
        .expect(200);

      expect(res.body).toHaveProperty('pagination');
      expect(res.body.pagination).toHaveProperty('limit');
      expect(res.body.pagination).toHaveProperty('offset');
    });

    it('should filter by status', async () => {
      vi.mocked(mockPrisma.sensor!.findMany).mockResolvedValue([
        createMockSensor({ connectionState: 'CONNECTED' }),
      ]);
      vi.mocked(mockPrisma.sensor!.count).mockResolvedValue(1);

      const res = await request(app)
        .get('/fleet/sensors?status=CONNECTED')
        .expect(200);

      expect(res.body.sensors).toHaveLength(1);
    });
  });

  describe('GET /fleet/sensors/:sensorId', () => {
    it('should return sensor details', async () => {
      const sensor = createMockSensor();
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue({
        ...sensor,
        commands: [],
      } as unknown as Sensor);

      const res = await request(app)
        .get('/fleet/sensors/sensor-1')
        .expect(200);

      expect(res.body.id).toBe('sensor-1');
      expect(res.body.name).toBe('Test Sensor');
    });

    it('should return 403 for non-existent sensor', async () => {
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(null);

      await request(app)
        .get('/fleet/sensors/non-existent')
        .expect(403);
    });

    it('should enforce tenant isolation', async () => {
      // Sensor belongs to different tenant
      const otherTenantSensor = createMockSensor({ tenantId: 'other-tenant' });
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue({
        ...otherTenantSensor,
        commands: [],
      } as unknown as Sensor);

      await request(app)
        .get('/fleet/sensors/sensor-1')
        .expect(403);
    });
  });

  describe('GET /fleet/sensors/:sensorId/signals', () => {
    it('should return recent signals for a sensor', async () => {
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(createMockSensor());
      vi.mocked(mockPrisma.signal!.findMany).mockResolvedValue([
        {
          id: 'sig-1',
          createdAt: new Date(),
          sensorId: 'sensor-1',
          signalType: 'threat',
          sourceIp: '1.2.3.4',
          anonFingerprint: 'fp-1',
          severity: 'high',
          confidence: 0.9,
          eventCount: 1,
          metadata: { test: true },
        } as any,
      ]);

      const res = await request(app)
        .get('/fleet/sensors/sensor-1/signals?limit=1')
        .expect(200);

      expect(res.body.signals).toHaveLength(1);
      expect(vi.mocked(mockPrisma.signal!.findMany)).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ tenantId: 'tenant-1', sensorId: 'sensor-1' }),
        })
      );
    });

    it('should enforce tenant isolation via requireTenant', async () => {
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(createMockSensor({ tenantId: 'other-tenant' }));

      await request(app)
        .get('/fleet/sensors/sensor-1/signals')
        .expect(403);

      expect(vi.mocked(mockPrisma.signal!.findMany)).not.toHaveBeenCalled();
    });
  });

  describe('GET /fleet/sensors/:sensorId/system', () => {
    it('should return sensor system information', async () => {
      const sensor = createMockSensor({
        os: 'Ubuntu 22.04',
        kernel: '5.15.0',
        architecture: 'x86_64',
      });
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(sensor);

      const res = await request(app)
        .get('/fleet/sensors/sensor-1/system')
        .expect(200);

      expect(res.body).toHaveProperty('hostname');
      expect(res.body).toHaveProperty('os');
      expect(res.body).toHaveProperty('kernel');
      expect(res.body).toHaveProperty('connection');
    });

    it('should return 403 if sensor not found', async () => {
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(null);

      await request(app)
        .get('/fleet/sensors/non-existent/system')
        .expect(403);
    });
  });

  describe('GET /fleet/sensors/:sensorId/performance', () => {
    it('should return sensor performance metrics', async () => {
      const sensor = createMockSensor({ metadata: { cpu: 25, memory: 50 } });
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(sensor);

      const res = await request(app)
        .get('/fleet/sensors/sensor-1/performance')
        .expect(200);

      expect(res.body).toHaveProperty('current');
      expect(res.body.current).toHaveProperty('cpu');
      expect(res.body.current).toHaveProperty('memory');
      expect(res.body).toHaveProperty('history');
    });

    it('should return 403 if sensor not found', async () => {
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(null);

      await request(app)
        .get('/fleet/sensors/non-existent/performance')
        .expect(403);
    });

    it('should enforce tenant isolation on performance endpoint', async () => {
      const otherTenantSensor = createMockSensor({ tenantId: 'other-tenant' });
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(otherTenantSensor);

      await request(app)
        .get('/fleet/sensors/sensor-1/performance')
        .expect(403);
    });
  });

  describe('Sensor Config Tenant Isolation', () => {
    const buildSensorConfigApp = () => {
      const fleetCommander = {
        sendCommand: vi.fn(),
      } as unknown as FleetCommander;

      const configApp = express();
      configApp.use(express.json());
      configApp.use(injectAuth('tenant-1', ['fleet:read', 'fleet:write']));
      configApp.use(
        '/fleet',
        createFleetRoutes(mockPrisma as PrismaClient, mockLogger, {
          fleetCommander,
        })
      );

      return { configApp };
    };

    it('should enforce tenant isolation on GET config endpoint', async () => {
      const { configApp } = buildSensorConfigApp();
      const otherTenantSensor = createMockSensor({ tenantId: 'other-tenant' });
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(otherTenantSensor);

      await request(configApp)
        .get('/fleet/sensors/sensor-1/config/pingora')
        .expect(403);
    });

    it('should enforce tenant isolation on POST config endpoint', async () => {
      const { configApp } = buildSensorConfigApp();
      const otherTenantSensor = createMockSensor({ tenantId: 'other-tenant' });
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(otherTenantSensor);

      await request(configApp)
        .post('/fleet/sensors/sensor-1/config/pingora')
        .send({ config: { sample: true } })
        .expect(403);
    });
  });

  describe('POST /fleet/config/push', () => {
    const buildConfigApp = () => {
      const configManager = {
        getTemplate: vi.fn(),
      } as unknown as ConfigManager;
      const fleetCommander = {
        sendCommand: vi.fn(),
      } as unknown as FleetCommander;

      const configApp = express();
      configApp.use(express.json());
      configApp.use(injectAuth('tenant-1', ['config:write', 'fleet:write']));
      configApp.use(
        '/fleet',
        createFleetRoutes(mockPrisma as PrismaClient, mockLogger, {
          configManager,
          fleetCommander,
        })
      );

      return { configApp, configManager, fleetCommander };
    };

    it('should 404 when sensorIds include other-tenant sensors', async () => {
      const { configApp, configManager, fleetCommander } = buildConfigApp();
      const template: ConfigTemplate = {
        id: 'template-1',
        name: 'Template',
        environment: 'production',
        config: {},
        hash: 'hash',
        version: '1',
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      vi.mocked(configManager.getTemplate).mockResolvedValue(template);
      vi.mocked(mockPrisma.sensor!.findMany).mockResolvedValue([
        createMockSensor({ id: 'sensor-1', tenantId: 'tenant-1' }),
      ]);

      await request(configApp)
        .post('/fleet/config/push')
        .send({ templateId: 'template-1', sensorIds: ['sensor-1', 'sensor-2'] })
        .expect(404);

      expect(fleetCommander.sendCommand).not.toHaveBeenCalled();
    });
  });

  describe('POST /fleet/commands', () => {
    const buildCommandApp = () => {
      const fleetCommander = {
        sendCommand: vi.fn(),
      } as unknown as FleetCommander;

      const commandApp = express();
      commandApp.use(express.json());
      commandApp.use(injectAuth('tenant-1', ['fleet:write']));
      commandApp.use(
        '/fleet',
        createFleetRoutes(mockPrisma as PrismaClient, mockLogger, {
          fleetCommander,
        })
      );

      return { commandApp, fleetCommander };
    };

    it('should 404 when sensorIds include other-tenant sensors', async () => {
      const { commandApp, fleetCommander } = buildCommandApp();

      vi.mocked(mockPrisma.sensor!.findMany).mockResolvedValue([
        createMockSensor({ id: 'sensor-1', tenantId: 'tenant-1' }),
      ]);

      await request(commandApp)
        .post('/fleet/commands')
        .send({
          commandType: 'restart',
          sensorIds: ['sensor-1', 'sensor-2'],
          payload: {},
        })
        .expect(404);

      expect(fleetCommander.sendCommand).not.toHaveBeenCalled();
    });
  });

  describe('Authorization', () => {
    it('should require fleet:read scope for overview', async () => {
      // Create app without fleet scopes
      const noScopeApp = express();
      noScopeApp.use(express.json());
      noScopeApp.use(injectAuth('tenant-1', []));
      noScopeApp.use('/fleet', createFleetRoutes(mockPrisma as PrismaClient, mockLogger, {}));

      await request(noScopeApp)
        .get('/fleet/overview')
        .expect(403);
    });

    it('should require fleet:read scope for sensors list', async () => {
      const noScopeApp = express();
      noScopeApp.use(express.json());
      noScopeApp.use(injectAuth('tenant-1', []));
      noScopeApp.use('/fleet', createFleetRoutes(mockPrisma as PrismaClient, mockLogger, {}));

      await request(noScopeApp)
        .get('/fleet/sensors')
        .expect(403);
    });
  });

  describe('Error Handling', () => {
    it('should handle database errors gracefully on overview', async () => {
      vi.mocked(mockPrisma.sensor!.findMany).mockRejectedValue(new Error('DB connection failed'));

      const res = await request(app)
        .get('/fleet/overview')
        .expect(500);

      expect(res.body).toHaveProperty('error');
    });

    it('should handle database errors gracefully on sensors list', async () => {
      vi.mocked(mockPrisma.sensor!.findMany).mockRejectedValue(new Error('DB connection failed'));

      const res = await request(app)
        .get('/fleet/sensors')
        .expect(500);

      expect(res.body).toHaveProperty('error');
    });
  });

  describe('POST /fleet/pingora/presets/apparatus-echo', () => {
    it('should apply upstream preset and push config for sensors', async () => {
      vi.mocked(mockPrisma.sensor!.findMany).mockResolvedValue([
        { id: 'sensor-1' } as any,
        { id: 'sensor-2' } as any,
      ]);

      // getConfig ownership check: select tenantId
      vi.mocked(mockPrisma.sensor!.findUnique).mockImplementation(async (args: any) => {
        if (args?.where?.id === 'sensor-1' || args?.where?.id === 'sensor-2') {
          if (args.select?.tenantId) return { tenantId: 'tenant-1' } as any;
          if (args.include?.pingoraConfig) {
            return { tenantId: 'tenant-1', pingoraConfig: { version: 1, fullConfig: {} } } as any;
          }
        }
        return null as any;
      });

      vi.mocked(mockPrisma.sensorPingoraConfig!.findUnique).mockResolvedValue({
        sensorId: 'sensor-1',
        version: 1,
        fullConfig: {
          server: { http_addr: '0.0.0.0:8080', https_addr: '0.0.0.0:8443' },
          sites: [{ hostname: 'example.com', upstreams: [{ host: 'old', port: 80, weight: 1 }] }],
          rate_limit: { enabled: false, rps: 100 },
        },
      } as any);

      vi.mocked(mockPrisma.sensorPingoraConfig!.upsert).mockResolvedValue({} as any);

      const res = await request(app)
        .post('/fleet/pingora/presets/apparatus-echo')
        .send({ sensorIds: ['sensor-1', 'sensor-2'], host: 'demo.site', port: 80 })
        .expect(202);

      expect(res.body).toHaveProperty('results');
      expect(res.body.results).toHaveLength(2);
      expect(vi.mocked(mockFleetCommander.sendCommand as any)).toHaveBeenCalledTimes(2);
    });

    it('should return 404 when sensorIds are not all owned by tenant', async () => {
      vi.mocked(mockPrisma.sensor!.findMany).mockResolvedValue([{ id: 'sensor-1' } as any]);

      await request(app)
        .post('/fleet/pingora/presets/apparatus-echo')
        .send({ sensorIds: ['sensor-1', 'sensor-2'], host: 'demo.site', port: 80 })
        .expect(404);

      expect(vi.mocked(mockFleetCommander.sendCommand as any)).not.toHaveBeenCalled();
    });
  });

  describe('GET /fleet/rules/catalog/version', () => {
    it('returns null/zero envelope when catalog is empty', async () => {
      vi.mocked(mockPrisma.synapseRule!.findFirst).mockResolvedValue(null as any);
      vi.mocked(mockPrisma.synapseRule!.count).mockResolvedValue(0);

      const res = await request(app)
        .get('/fleet/rules/catalog/version')
        .expect(200);

      expect(res.body).toEqual({
        catalogVersion: null,
        catalogHash: null,
        ruleCount: 0,
        lastImportedAt: null,
      });
    });

    it('returns version metadata when catalog is populated', async () => {
      const importedAt = new Date('2026-04-17T00:00:00Z');
      vi.mocked(mockPrisma.synapseRule!.findFirst).mockResolvedValue({
        catalogVersion: 'ef83a85a3616',
        catalogHash: 'ef83a85a3616828a' + 'f'.repeat(48),
        importedAt,
        updatedAt: importedAt,
      } as any);
      vi.mocked(mockPrisma.synapseRule!.count).mockResolvedValue(248);

      const res = await request(app)
        .get('/fleet/rules/catalog/version')
        .expect(200);

      expect(res.body).toMatchObject({
        catalogVersion: 'ef83a85a3616',
        ruleCount: 248,
      });
      expect(res.body.lastImportedAt).toBe(importedAt.toISOString());
    });
  });

  describe('GET /fleet/rules', () => {
    it('returns merged catalog + custom rules with override metadata', async () => {
      vi.mocked(mockPrisma.synapseRule!.findMany).mockResolvedValue([
        {
          ruleId: 200002,
          name: null,
          description: 'Possible hex encoding v2',
          classification: 'Evasion',
          state: 'WebMapping',
          risk: 20,
          blocking: null,
          updatedAt: new Date('2026-04-17T00:00:00Z'),
          catalogVersion: 'v1',
        } as any,
      ]);
      vi.mocked(mockPrisma.tenantRuleOverride!.findMany).mockResolvedValue([
        { synapseRuleId: 200002, enabled: false, blockingOverride: true, riskOverride: null } as any,
      ]);
      vi.mocked(mockPrisma.customerRule!.findMany).mockResolvedValue([
        {
          id: 'cust-1',
          name: 'My rule',
          description: 'custom',
          category: 'custom',
          severity: 'high',
          action: 'block',
          enabled: true,
          status: 'draft',
        } as any,
      ]);

      const res = await request(app).get('/fleet/rules').expect(200);

      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body).toHaveLength(2);
      const catalog = res.body.find((r: any) => r.source === 'catalog');
      expect(catalog).toMatchObject({
        id: 200002,
        enabled: false,
        hasOverride: true,
        blocking: true,
      });
      const custom = res.body.find((r: any) => r.source === 'custom');
      expect(custom).toMatchObject({ id: 'cust-1', severity: 'high' });
    });

    it('filters catalog overrides by tenant', async () => {
      vi.mocked(mockPrisma.synapseRule!.findMany).mockResolvedValue([]);
      vi.mocked(mockPrisma.tenantRuleOverride!.findMany).mockResolvedValue([]);
      vi.mocked(mockPrisma.customerRule!.findMany).mockResolvedValue([]);

      await request(app).get('/fleet/rules').expect(200);

      expect(vi.mocked(mockPrisma.tenantRuleOverride!.findMany)).toHaveBeenCalledWith(
        expect.objectContaining({ where: { tenantId: 'tenant-1' } })
      );
      expect(vi.mocked(mockPrisma.customerRule!.findMany)).toHaveBeenCalledWith(
        expect.objectContaining({ where: expect.objectContaining({ tenantId: 'tenant-1' }) })
      );
    });
  });

  describe('GET /fleet/rules/drift', () => {
    it('returns drift summary classifying each sensor as in-sync or drifted', async () => {
      vi.mocked(mockPrisma.sensor!.findMany).mockResolvedValue([
        createMockSensor({ id: 'sensor-1' }),
        createMockSensor({ id: 'sensor-2' }),
      ]);
      const mockRuleDistributor = {
        getRuleDrift: vi.fn().mockResolvedValue({
          expectedHash: 'abc123',
          inSyncCount: 1,
          driftedCount: 1,
          sensors: [
            { sensorId: 'sensor-1', reportedHash: 'abc123', inSync: true, lastHeartbeat: new Date() },
            { sensorId: 'sensor-2', reportedHash: 'stale', inSync: false, lastHeartbeat: new Date() },
          ],
        }),
      };
      const mockFleetAggregator = {
        getAllSensorMetrics: vi.fn().mockResolvedValue([
          { sensorId: 'sensor-1', rulesHash: 'abc123', lastHeartbeat: new Date() },
          { sensorId: 'sensor-2', rulesHash: 'stale', lastHeartbeat: new Date() },
        ]),
      };

      const driftApp = express();
      driftApp.use(express.json());
      driftApp.use(injectAuth('tenant-1', ['fleet:read']));
      driftApp.use(
        '/fleet',
        createFleetRoutes(mockPrisma as PrismaClient, mockLogger, {
          ruleDistributor: mockRuleDistributor as any,
          fleetAggregator: mockFleetAggregator as any,
          securityAuditService: mockAuditService as SecurityAuditService,
        })
      );

      const res = await request(driftApp).get('/fleet/rules/drift').expect(200);

      expect(res.body.expectedHash).toBe('abc123');
      expect(res.body.inSyncCount).toBe(1);
      expect(res.body.driftedCount).toBe(1);
      expect(mockRuleDistributor.getRuleDrift).toHaveBeenCalledWith(
        'tenant-1',
        expect.arrayContaining([
          expect.objectContaining({ sensorId: 'sensor-1', reportedHash: 'abc123' }),
          expect.objectContaining({ sensorId: 'sensor-2', reportedHash: 'stale' }),
        ])
      );
    });

    it('returns 503 when rule distributor is unavailable', async () => {
      await request(app).get('/fleet/rules/drift').expect(503);
    });
  });

  describe('GET /fleet/rules/available', () => {
    it('returns paginated envelope with items + pagination block', async () => {
      vi.mocked(mockPrisma.synapseRule!.count).mockResolvedValue(1);
      vi.mocked(mockPrisma.synapseRule!.findMany).mockResolvedValue([
        {
          ruleId: 200008,
          name: null,
          description: 'Injection string',
          classification: 'CommandInjection',
          state: 'Exploitation',
          risk: 40,
          blocking: null,
          updatedAt: new Date('2026-04-17T00:00:00Z'),
          catalogVersion: 'v1',
        } as any,
      ]);
      vi.mocked(mockPrisma.tenantRuleOverride!.findMany).mockResolvedValue([]);
      vi.mocked(mockPrisma.customerRule!.count).mockResolvedValue(0);
      vi.mocked(mockPrisma.customerRule!.findMany).mockResolvedValue([]);

      const res = await request(app)
        .get('/fleet/rules/available?source=all&limit=100&offset=0')
        .expect(200);

      expect(res.body).toHaveProperty('items');
      expect(res.body).toHaveProperty('pagination');
      expect(res.body.pagination.total).toBe(1);
      expect(res.body.items[0]).toMatchObject({
        source: 'catalog',
        id: 200008,
        classification: 'CommandInjection',
      });
    });
  });
});
