/**
 * Fleet Routes Test Suite
 *
 * Tests for fleet management API endpoints including
 * sensor overview, metrics, configuration, and commands.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import request from 'supertest';
import { createFleetRoutes } from './fleet.js';
import type { PrismaClient, Sensor } from '@prisma/client';
import type { Logger } from 'pino';

// Mock the auth middleware module
vi.mock('../middleware/auth.js', () => ({
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
}));

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
  deploymentName: null,
  description: null,
  environment: null,
  location: null,
  region: 'us-east-1',
  version: '1.0.0',
  signalCount: 0,
  uniqueSignals: 0,
  lastSignalAt: null,
  osInfo: null,
  capabilities: null,
  publicIp: null,
  privateIp: null,
  os: null,
  kernel: null,
  architecture: null,
  instanceType: null,
  lastBoot: null,
  uptime: null,
  tunnelActive: false,
  metadata: null,
  ...overrides,
});

describe('Fleet Routes', () => {
  let app: Express;
  let mockPrisma: Partial<PrismaClient>;

  beforeEach(() => {
    mockPrisma = {
      sensor: {
        findMany: vi.fn(),
        findFirst: vi.fn(),
        findUnique: vi.fn(),
        count: vi.fn(),
      } as unknown as PrismaClient['sensor'],
      fleetCommand: {
        findMany: vi.fn(),
        findFirst: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
      } as unknown as PrismaClient['fleetCommand'],
      $queryRaw: vi.fn(),
    };

    app = express();
    app.use(express.json());
    app.use(injectAuth('tenant-1', ['fleet:read', 'fleet:write']));
    app.use('/fleet', createFleetRoutes(mockPrisma as PrismaClient, mockLogger, {}));
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

    it('should return 404 for non-existent sensor', async () => {
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(null);

      await request(app)
        .get('/fleet/sensors/non-existent')
        .expect(404);
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
        .expect(404);
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

    it('should return 404 if sensor not found', async () => {
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(null);

      await request(app)
        .get('/fleet/sensors/non-existent/system')
        .expect(404);
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

    it('should return 404 if sensor not found', async () => {
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(null);

      await request(app)
        .get('/fleet/sensors/non-existent/performance')
        .expect(404);
    });

    it('should enforce tenant isolation on performance endpoint', async () => {
      const otherTenantSensor = createMockSensor({ tenantId: 'other-tenant' });
      vi.mocked(mockPrisma.sensor!.findUnique).mockResolvedValue(otherTenantSensor);

      await request(app)
        .get('/fleet/sensors/sensor-1/performance')
        .expect(404);
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
});
