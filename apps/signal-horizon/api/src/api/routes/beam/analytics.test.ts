/**
 * Beam Analytics Route Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import express, { Express } from 'express';
import request from '../../../__tests__/test-request.js';
import { createAnalyticsRouter } from './analytics.js';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';

// Mock Prisma client
const mockPrisma = {
  blockDecision: {
    findMany: vi.fn(),
  },
  endpoint: {
    count: vi.fn(),
  },
} as unknown as PrismaClient;

// Mock logger
const mockLogger = {
  info: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

describe('Beam Analytics Route', () => {
  let app: Express;

  beforeEach(() => {
    vi.clearAllMocks();
    app = express();
    app.use(express.json());
  });

  describe('GET /analytics', () => {
    describe('Authentication', () => {
      it('should return 401 when not authenticated', async () => {
        app.use('/analytics', createAnalyticsRouter(mockPrisma, mockLogger));

        const response = await request(app).get('/analytics');

        expect(response.status).toBe(401);
        expect(response.body).toMatchObject({
          status: 401,
          detail: 'Not authenticated',
          code: 'AUTH_REQUIRED',
        });
      });

      it('should return 401 with proper error message', async () => {
        app.use('/analytics', createAnalyticsRouter(mockPrisma, mockLogger));

        const response = await request(app).get('/analytics');

        expect(response.body).toMatchObject({
          status: 401,
          detail: 'Not authenticated',
          code: 'AUTH_REQUIRED',
        });
      });
    });

    describe('Successful Response', () => {
      beforeEach(() => {
        // Simulate authenticated request
        app.use((req, _res, next) => {
          req.auth = { tenantId: 'test-tenant-123', scopes: ['dashboard:read'] };
          next();
        });
        app.use('/analytics', createAnalyticsRouter(mockPrisma, mockLogger));

        // Mock empty data
        vi.mocked(mockPrisma.blockDecision.findMany).mockResolvedValue([]);
        vi.mocked(mockPrisma.endpoint.count).mockResolvedValue(0);
      });

      it('should return 200 with analytics data when authenticated', async () => {
        const response = await request(app).get('/analytics');

        expect(response.status).toBe(200);
        expect(response.body).toBeDefined();
      });

      it('should include traffic metrics', async () => {
        const response = await request(app).get('/analytics');

        expect(response.body).toHaveProperty('traffic');
        expect(response.body.traffic).toHaveProperty('totalRequests');
        expect(response.body.traffic).toHaveProperty('totalBlocked');
        expect(response.body.traffic).toHaveProperty('totalBandwidthIn');
        expect(response.body.traffic).toHaveProperty('totalBandwidthOut');
        expect(response.body.traffic).toHaveProperty('blockRate');
        expect(response.body.traffic).toHaveProperty('timeline');
        expect(Array.isArray(response.body.traffic.timeline)).toBe(true);
        expect(response.body.traffic.timeline).toHaveLength(24);
      });

      it('should include bandwidth metrics', async () => {
        const response = await request(app).get('/analytics');

        expect(response.body).toHaveProperty('bandwidth');
        expect(response.body.bandwidth).toHaveProperty('timeline');
        expect(response.body.bandwidth).toHaveProperty('totalBytesIn');
        expect(response.body.bandwidth).toHaveProperty('totalBytesOut');
        expect(response.body.bandwidth).toHaveProperty('avgBytesPerRequest');
      });

      it('should include threat statistics', async () => {
        const response = await request(app).get('/analytics');

        expect(response.body).toHaveProperty('threats');
        expect(response.body.threats).toHaveProperty('total');
        expect(response.body.threats).toHaveProperty('bySeverity');
        expect(response.body.threats).toHaveProperty('byType');
        expect(response.body.threats).toHaveProperty('recentEvents');
      });

      it('should include sensor metrics', async () => {
        const response = await request(app).get('/analytics');

        expect(response.body).toHaveProperty('sensor');
        expect(response.body.sensor).toHaveProperty('requestsTotal');
        expect(response.body.sensor).toHaveProperty('blocksTotal');
        expect(response.body.sensor).toHaveProperty('entitiesTracked');
        expect(response.body.sensor).toHaveProperty('uptime');
        expect(response.body.sensor).toHaveProperty('rps');
        expect(response.body.sensor).toHaveProperty('latencyP50');
        expect(response.body.sensor).toHaveProperty('latencyP95');
        expect(response.body.sensor).toHaveProperty('latencyP99');
      });

      it('should include fetchedAt timestamp', async () => {
        const response = await request(app).get('/analytics');

        expect(response.body).toHaveProperty('fetchedAt');
        expect(typeof response.body.fetchedAt).toBe('string');
        // Verify ISO 8601 format
        expect(new Date(response.body.fetchedAt).toISOString()).toBe(response.body.fetchedAt);
      });

      it('should include dataSource field', async () => {
        const response = await request(app).get('/analytics');

        expect(response.body).toHaveProperty('dataSource');
        expect(['live', 'synapse-direct']).toContain(response.body.dataSource);
      });
    });

    describe('With Block Decisions', () => {
      beforeEach(() => {
        app.use((req, _res, next) => {
          req.auth = { tenantId: 'test-tenant-123', scopes: ['dashboard:read'] };
          next();
        });
        app.use('/analytics', createAnalyticsRouter(mockPrisma, mockLogger));
      });

      it('should aggregate block decisions by severity', async () => {
        const mockBlocks = [
          { id: '1', riskScore: 90, threatType: 'SQLI', sourceIp: '1.1.1.1', path: '/api', action: 'BLOCK', decidedAt: new Date() },
          { id: '2', riskScore: 70, threatType: 'XSS', sourceIp: '2.2.2.2', path: '/login', action: 'BLOCK', decidedAt: new Date() },
          { id: '3', riskScore: 30, threatType: 'BOT', sourceIp: '3.3.3.3', path: '/home', action: 'BLOCK', decidedAt: new Date() },
        ];
        vi.mocked(mockPrisma.blockDecision.findMany).mockResolvedValue(mockBlocks);
        vi.mocked(mockPrisma.endpoint.count).mockResolvedValue(50);

        const response = await request(app).get('/analytics');

        expect(response.body.threats.bySeverity).toEqual({
          critical: 1,
          high: 1,
          medium: 0,
          low: 1,
        });
      });

      it('should aggregate block decisions by type', async () => {
        const mockBlocks = [
          { id: '1', riskScore: 90, threatType: 'SQLI', sourceIp: '1.1.1.1', path: '/api', action: 'BLOCK', decidedAt: new Date() },
          { id: '2', riskScore: 70, threatType: 'SQLI', sourceIp: '2.2.2.2', path: '/login', action: 'BLOCK', decidedAt: new Date() },
          { id: '3', riskScore: 30, threatType: 'XSS', sourceIp: '3.3.3.3', path: '/home', action: 'BLOCK', decidedAt: new Date() },
        ];
        vi.mocked(mockPrisma.blockDecision.findMany).mockResolvedValue(mockBlocks);
        vi.mocked(mockPrisma.endpoint.count).mockResolvedValue(50);

        const response = await request(app).get('/analytics');

        expect(response.body.threats.byType).toEqual({
          SQLI: 2,
          XSS: 1,
        });
      });

      it('should return live dataSource when blocks exist', async () => {
        const mockBlocks = [
          { id: '1', riskScore: 90, threatType: 'SQLI', sourceIp: '1.1.1.1', path: '/api', action: 'BLOCK', decidedAt: new Date() },
        ];
        vi.mocked(mockPrisma.blockDecision.findMany).mockResolvedValue(mockBlocks);
        vi.mocked(mockPrisma.endpoint.count).mockResolvedValue(50);

        const response = await request(app).get('/analytics');

        expect(response.body.dataSource).toBe('live');
      });

      it('should return live dataSource when no blocks exist', async () => {
        vi.mocked(mockPrisma.blockDecision.findMany).mockResolvedValue([]);
        vi.mocked(mockPrisma.endpoint.count).mockResolvedValue(0);

        const response = await request(app).get('/analytics');

        expect(response.body.dataSource).toBe('live');
      });
    });

    describe('Response Content-Type', () => {
      beforeEach(() => {
        app.use((req, _res, next) => {
          req.auth = { tenantId: 'test-tenant', scopes: ['dashboard:read'] };
          next();
        });
        app.use('/analytics', createAnalyticsRouter(mockPrisma, mockLogger));
        vi.mocked(mockPrisma.blockDecision.findMany).mockResolvedValue([]);
        vi.mocked(mockPrisma.endpoint.count).mockResolvedValue(0);
      });

      it('should return JSON content type', async () => {
        const response = await request(app).get('/analytics');

        expect(response.headers['content-type']).toMatch(/application\/json/);
      });
    });
  });
});
