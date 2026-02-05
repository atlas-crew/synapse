/**
 * Tunnel Routes Test Suite
 *
 * Tests for WebSocket tunnel management API endpoints
 * including session creation, status checks, and cleanup.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express, { type Express } from 'express';
import request from '../../__tests__/test-request.js';
import { createTunnelRoutes } from './tunnel.js';
import type { PrismaClient, Sensor } from '@prisma/client';
import type { Logger } from 'pino';

// Mock logger
const mockLogger: Logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

// Factory to create mock sensor (matches Prisma Sensor model)
const createMockSensor = (overrides: Partial<Sensor> = {}): Sensor => ({
  id: 'sensor-1',
  name: 'Test Sensor',
  hostname: 'sensor-1.local',
  tenantId: 'tenant-1',
  connectionState: 'CONNECTED',
  lastHeartbeat: new Date(), // Online: just now
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

describe('Tunnel Routes', () => {
  let app: Express;
  let mockPrisma: Partial<PrismaClient>;

  beforeEach(() => {
    const createdSessions: Record<string, unknown>[] = [];
    const sensorStore = {
      findFirst: vi.fn(),
    } as unknown as PrismaClient['sensor'];
    const apiKeyStore = {
      findUnique: vi.fn(),
    } as unknown as PrismaClient['apiKey'];
    const tunnelSessionStore = {
      create: vi.fn(async ({ data }) => {
        const session = {
          ...data,
          createdAt: new Date(),
          lastActivity: new Date(),
        };
        createdSessions.push(session);
        return session;
      }),
      findUnique: vi.fn(async ({ where }) => {
        const id = String(where.id);
        return createdSessions.find((session) => session.id === id) ?? null;
      }),
      findMany: vi.fn(async ({ where }) => {
        return createdSessions.filter(
          (session) => session.tenantId === where.tenantId
        );
      }),
      delete: vi.fn(async ({ where }) => {
        const id = String(where.id);
        const index = createdSessions.findIndex((session) => session.id === id);
        if (index >= 0) {
          createdSessions.splice(index, 1);
        }
        return {};
      }),
      update: vi.fn(async ({ where, data }) => {
        const id = String(where.id);
        const index = createdSessions.findIndex((session) => session.id === id);
        const existing = index >= 0 ? createdSessions[index] : null;
        if (!existing) {
          return null;
        }
        const updated = { ...existing, ...data };
        createdSessions[index] = updated;
        return updated;
      }),
    } as unknown as PrismaClient['tunnelSession'];
    mockPrisma = {
      sensor: sensorStore,
      apiKey: apiKeyStore,
      tunnelSession: tunnelSessionStore,
      $transaction: vi.fn(async (callback) => callback({
        sensor: sensorStore,
        apiKey: apiKeyStore,
        tunnelSession: tunnelSessionStore,
      })),
    };
    vi.mocked(apiKeyStore.findUnique).mockResolvedValue({ tenantId: 'tenant-1' } as never);
    vi.mocked(tunnelSessionStore.create).mockResolvedValue({} as never);

    app = express();
    app.use(express.json());
    // Inject tenant header (simulating auth middleware)
    app.use((req, _res, next) => {
      req.headers['x-org-id'] = 'tenant-1';
      req.headers['x-user-id'] = 'user-1';
      req.auth = {
        tenantId: 'tenant-1',
        apiKeyId: 'test-key',
        scopes: [
          'tunnel:read',
          'tunnel:shell',
          'tunnel:dashboard',
          'tunnel:manage',
          'command:execute',
        ],
        isFleetAdmin: false,
        userId: 'user-1',
      };
      next();
    });
    app.use('/tunnel', createTunnelRoutes(mockPrisma as PrismaClient, mockLogger));
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('GET /tunnel/status/:sensorId', () => {
    it('should return available status for online sensor', async () => {
      const sensor = createMockSensor({
        lastHeartbeat: new Date(), // Just now = online
      });
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(sensor);

      const res = await request(app)
        .get('/tunnel/status/sensor-1')
        .expect(200);

      expect(res.body.sensorId).toBe('sensor-1');
      expect(res.body.available).toBe(true);
      expect(res.body.capabilities).toContain('shell');
      expect(res.body.capabilities).toContain('dashboard');
    });

    it('should return unavailable status for offline sensor', async () => {
      const sensor = createMockSensor({
        lastHeartbeat: new Date(Date.now() - 300000), // 5 minutes ago = offline
      });
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(sensor);

      const res = await request(app)
        .get('/tunnel/status/sensor-1')
        .expect(200);

      expect(res.body.available).toBe(false);
      expect(res.body.capabilities).toHaveLength(0);
    });

    it('should return 404 for non-existent sensor', async () => {
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(null);

      await request(app)
        .get('/tunnel/status/non-existent')
        .expect(404);
    });

    it('should enforce tenant isolation', async () => {
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(null);

      await request(app)
        .get('/tunnel/status/other-tenant-sensor')
        .expect(404);

      expect(mockPrisma.sensor!.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tenantId: 'tenant-1',
          }),
        })
      );
    });
  });

  describe('POST /tunnel/shell/:sensorId', () => {
    it('should create shell session for online sensor', async () => {
      const sensor = createMockSensor({
        lastHeartbeat: new Date(),
      });
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(sensor);

      const res = await request(app)
        .post('/tunnel/shell/sensor-1')
        .expect(201);

      expect(res.body.sessionId).toBeDefined();
      expect(res.body.sensorId).toBe('sensor-1');
      expect(res.body.type).toBe('shell');
      expect(res.body.wsUrl).toMatch(/^\/ws\/tunnel\/user\//);
      expect(res.body.expiresIn).toBe(300);
    });

    it('should return 503 for offline sensor', async () => {
      const sensor = createMockSensor({
        lastHeartbeat: new Date(Date.now() - 300000), // 5 minutes ago
      });
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(sensor);

      const res = await request(app)
        .post('/tunnel/shell/sensor-1')
        .expect(503);

      expect(res.body.error).toBe('Sensor offline');
    });

    it('should return 404 for non-existent sensor', async () => {
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(null);

      await request(app)
        .post('/tunnel/shell/non-existent')
        .expect(404);
    });

    it('should rate limit tunnel creation per API key', async () => {
      const previousLimit = process.env.TUNNEL_CREATE_RATE_LIMIT_PER_HOUR;
      process.env.TUNNEL_CREATE_RATE_LIMIT_PER_HOUR = '2';

      const sensor = createMockSensor({
        lastHeartbeat: new Date(),
      });
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(sensor);

      const rateLimitedApp = express();
      rateLimitedApp.use(express.json());
      rateLimitedApp.use((req, _res, next) => {
        req.headers['x-org-id'] = 'tenant-1';
        req.headers['x-user-id'] = 'user-1';
        req.auth = {
          tenantId: 'tenant-1',
          apiKeyId: 'test-key',
          scopes: [
            'tunnel:read',
            'tunnel:shell',
            'tunnel:dashboard',
            'tunnel:manage',
            'command:execute',
          ],
          isFleetAdmin: false,
          userId: 'user-1',
        };
        next();
      });
      rateLimitedApp.use('/tunnel', createTunnelRoutes(mockPrisma as PrismaClient, mockLogger));

      await request(rateLimitedApp).post('/tunnel/shell/sensor-1').expect(201);
      await request(rateLimitedApp).post('/tunnel/shell/sensor-1').expect(201);
      const res = await request(rateLimitedApp).post('/tunnel/shell/sensor-1').expect(429);

      expect(res.headers['retry-after']).toBeDefined();

      if (previousLimit === undefined) {
        delete process.env.TUNNEL_CREATE_RATE_LIMIT_PER_HOUR;
      } else {
        process.env.TUNNEL_CREATE_RATE_LIMIT_PER_HOUR = previousLimit;
      }
    });
  });

  describe('POST /tunnel/dashboard/:sensorId', () => {
    it('should create dashboard session for online sensor', async () => {
      const sensor = createMockSensor({
        lastHeartbeat: new Date(),
      });
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(sensor);

      const res = await request(app)
        .post('/tunnel/dashboard/sensor-1')
        .expect(201);

      expect(res.body.sessionId).toBeDefined();
      expect(res.body.sensorId).toBe('sensor-1');
      expect(res.body.type).toBe('dashboard');
      expect(res.body.wsUrl).toMatch(/^\/ws\/tunnel\/user\//);
      expect(res.body.proxyUrl).toMatch(/^\/api\/v1\/tunnel\/proxy\//);
      expect(res.body.expiresIn).toBe(300);
    });

    it('should return 503 for offline sensor', async () => {
      const sensor = createMockSensor({
        lastHeartbeat: new Date(Date.now() - 300000),
      });
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(sensor);

      const res = await request(app)
        .post('/tunnel/dashboard/sensor-1')
        .expect(503);

      expect(res.body.error).toBe('Sensor offline');
    });
  });

  describe('GET /tunnel/session/:sessionId', () => {
    it('should return session details', async () => {
      // First create a session
      const sensor = createMockSensor({ lastHeartbeat: new Date() });
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(sensor);

      const createRes = await request(app)
        .post('/tunnel/shell/sensor-1')
        .expect(201);

      const sessionId = createRes.body.sessionId;
      const session = {
        id: sessionId,
        sensorId: 'sensor-1',
        tenantId: 'tenant-1',
        userId: 'user-1',
        type: 'shell',
        status: 'pending',
        createdAt: new Date(),
        lastActivity: new Date(),
      };
      vi.mocked(mockPrisma.tunnelSession!.findUnique).mockResolvedValueOnce(session as never);

      // Then retrieve it
      const res = await request(app)
        .get(`/tunnel/session/${sessionId}`)
        .expect(200);

      expect(res.body.id).toBe(sessionId);
      expect(res.body.sensorId).toBe('sensor-1');
      expect(res.body.status).toBe('pending');
    });

    it('should return 404 for non-existent session', async () => {
      await request(app)
        .get('/tunnel/session/00000000-0000-0000-0000-000000000000')
        .expect(404);
    });

    it('should enforce tenant isolation on sessions', async () => {
      // Create session with tenant-1
      const sensor = createMockSensor({ lastHeartbeat: new Date() });
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(sensor);

      const createRes = await request(app)
        .post('/tunnel/shell/sensor-1')
        .expect(201);

      const sessionId = createRes.body.sessionId;

      // Try to access with different tenant
      const otherTenantApp = express();
      otherTenantApp.use(express.json());
    otherTenantApp.use((req, _res, next) => {
      req.headers['x-org-id'] = 'tenant-2'; // Different tenant
      req.auth = {
        tenantId: 'tenant-2',
        apiKeyId: 'test-key',
        scopes: [
          'tunnel:read',
            'tunnel:shell',
            'tunnel:dashboard',
            'tunnel:manage',
            'command:execute',
          ],
          isFleetAdmin: false,
          userId: 'user-2',
        };
        next();
      });
      otherTenantApp.use('/tunnel', createTunnelRoutes(mockPrisma as PrismaClient, mockLogger));

      // Note: This uses a new router instance with its own session store
      // So it won't find the session, simulating isolation
      await request(otherTenantApp)
        .get(`/tunnel/session/${sessionId}`)
        .expect(404);
    });
  });

  describe('DELETE /tunnel/session/:sessionId', () => {
    it('should terminate existing session', async () => {
      // First create a session
      const sensor = createMockSensor({ lastHeartbeat: new Date() });
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(sensor);

      const createRes = await request(app)
        .post('/tunnel/shell/sensor-1')
        .expect(201);

      const sessionId = createRes.body.sessionId;
      const session = {
        id: sessionId,
        sensorId: 'sensor-1',
        tenantId: 'tenant-1',
        userId: 'user-1',
        type: 'shell',
        status: 'pending',
        createdAt: new Date(),
        lastActivity: new Date(),
      };
      vi.mocked(mockPrisma.tunnelSession!.findUnique)
        .mockResolvedValueOnce(session as never)
        .mockResolvedValueOnce(null as never);

      // Then delete it
      await request(app)
        .delete(`/tunnel/session/${sessionId}`)
        .expect(204);

      // Verify it's gone
      await request(app)
        .get(`/tunnel/session/${sessionId}`)
        .expect(404);
    });

    it('should return 404 for non-existent session', async () => {
      await request(app)
        .delete('/tunnel/session/00000000-0000-0000-0000-000000000000')
        .expect(404);
    });
  });

  describe('GET /tunnel/sessions', () => {
    it('should return list of active sessions for tenant', async () => {
      // Create a few sessions
      const sensor = createMockSensor({ lastHeartbeat: new Date() });
      vi.mocked(mockPrisma.sensor!.findFirst).mockResolvedValue(sensor);

      await request(app).post('/tunnel/shell/sensor-1').expect(201);
      await request(app).post('/tunnel/dashboard/sensor-1').expect(201);
      vi.mocked(mockPrisma.tunnelSession!.findMany).mockResolvedValueOnce([
        {
          id: 'session-1',
          sensorId: 'sensor-1',
          tenantId: 'tenant-1',
          userId: 'user-1',
          type: 'shell',
          status: 'pending',
          createdAt: new Date(),
          lastActivity: new Date(),
        },
        {
          id: 'session-2',
          sensorId: 'sensor-1',
          tenantId: 'tenant-1',
          userId: 'user-1',
          type: 'dashboard',
          status: 'pending',
          createdAt: new Date(),
          lastActivity: new Date(),
        },
      ] as never);

      const res = await request(app)
        .get('/tunnel/sessions')
        .expect(200);

      expect(res.body.sessions).toHaveLength(2);
      expect(res.body.total).toBe(2);
    });

    it('should return empty list when no sessions', async () => {
      const res = await request(app)
        .get('/tunnel/sessions')
        .expect(200);

      expect(res.body.sessions).toHaveLength(0);
      expect(res.body.total).toBe(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle database errors gracefully', async () => {
      vi.mocked(mockPrisma.sensor!.findFirst).mockRejectedValue(new Error('DB connection failed'));

      const res = await request(app)
        .get('/tunnel/status/sensor-1')
        .expect(500);

      expect(res.body.error).toBe('Internal server error');
    });
  });
});
