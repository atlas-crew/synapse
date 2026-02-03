/**
 * Hunt Routes Integration Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import request from '../../__tests__/test-request.js';
import { createHuntRoutes } from './hunt.js';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { HuntQuery, HuntResult, HuntService, SavedQuery, HourlyStats } from '../../services/hunt/index.js';

vi.mock('../../middleware/index.js', () => ({
  rateLimiters: {
    hunt: (_req: Request, _res: Response, next: NextFunction) => next(),
    aggregations: (_req: Request, _res: Response, next: NextFunction) => next(),
    savedQueries: (_req: Request, _res: Response, next: NextFunction) => next(),
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

const injectAuth = (tenantId: string) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    req.auth = { tenantId, scopes: ['hunt:read'] } as unknown as typeof req.auth;
    next();
  };
};

describe('Hunt Routes', () => {
  let app: Express;
  let huntService: HuntService;

  beforeEach(() => {
    huntService = {
      isHistoricalEnabled: vi.fn().mockReturnValue(true),
      queryTimeline: vi.fn(),
      getCampaignTimeline: vi.fn(),
      getHourlyStats: vi.fn(),
      getIpActivity: vi.fn(),
      getSavedQueries: vi.fn(),
      saveQuery: vi.fn(),
      getSavedQuery: vi.fn(),
      deleteSavedQuery: vi.fn(),
    } as unknown as HuntService;

    app = express();
    app.use(express.json());
    app.use(injectAuth('tenant-1'));
    app.use('/api/v1/hunt', createHuntRoutes({} as PrismaClient, mockLogger, huntService));
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('POST /api/v1/hunt/query enforces tenant isolation', async () => {
    const result: HuntResult = {
      signals: [],
      total: 0,
      source: 'postgres',
      queryTimeMs: 12,
    };

    vi.mocked(huntService.queryTimeline).mockResolvedValue(result);

    const startTime = new Date(Date.now() - 60_000).toISOString();
    const endTime = new Date().toISOString();

    const response = await request(app)
      .post('/api/v1/hunt/query')
      .send({
        tenantId: 'tenant-2',
        startTime,
        endTime,
        limit: 5,
        offset: 0,
      })
      .expect(200);

    const calledWith = vi.mocked(huntService.queryTimeline).mock.calls[0][0] as HuntQuery;
    expect(calledWith.tenantId).toBe('tenant-1');
    expect(response.body).toMatchObject({
      success: true,
      data: [],
      meta: {
        total: 0,
        source: 'postgres',
        limit: 5,
        offset: 0,
      },
    });
  });

  it('GET /api/v1/hunt/stats/hourly uses authenticated tenant', async () => {
    const stats: HourlyStats[] = [
      {
        hour: new Date(),
        tenantId: 'tenant-1',
        signalType: 'IP_THREAT',
        severity: 'HIGH',
        signalCount: 3,
        totalEvents: 3,
        uniqueIps: 2,
        uniqueFingerprints: 1,
      },
    ];

    vi.mocked(huntService.getHourlyStats).mockResolvedValue(stats);

    const startTime = new Date(Date.now() - 3600_000).toISOString();
    const endTime = new Date().toISOString();

    const query = new URLSearchParams({
      tenantId: 'tenant-2',
      startTime,
      endTime,
    }).toString();

    const response = await request(app)
      .get(`/api/v1/hunt/stats/hourly?${query}`)
      .expect(200);

    expect(vi.mocked(huntService.getHourlyStats)).toHaveBeenCalledWith(
      'tenant-1',
      expect.any(Date),
      expect.any(Date),
      undefined
    );
    expect(response.body).toMatchObject({
      success: true,
      data: expect.any(Array),
      meta: { count: 1 },
    });
  });

  it('POST /api/v1/hunt/saved-queries/:id/run overrides saved tenant', async () => {
    const savedQuery: SavedQuery = {
      id: 'query-1',
      name: 'Test Query',
      createdBy: 'user-1',
      createdAt: new Date(),
      query: {
        tenantId: 'tenant-2',
        startTime: new Date(Date.now() - 60_000),
        endTime: new Date(),
        limit: 10,
        offset: 0,
      },
    };

    const result: HuntResult = {
      signals: [],
      total: 0,
      source: 'postgres',
      queryTimeMs: 9,
    };

    vi.mocked(huntService.getSavedQuery).mockResolvedValue(savedQuery);
    vi.mocked(huntService.queryTimeline).mockResolvedValue(result);

    await request(app)
      .post('/api/v1/hunt/saved-queries/query-1/run')
      .expect(200);

    const calledWith = vi.mocked(huntService.queryTimeline).mock.calls[0][0] as HuntQuery;
    expect(calledWith.tenantId).toBe('tenant-1');
  });

  describe('Hunt query validation', () => {
    const buildBaseQuery = () => {
      const startTime = new Date(Date.now() - 60_000).toISOString();
      const endTime = new Date().toISOString();

      return { startTime, endTime, limit: 5, offset: 0 };
    };

    it('rejects SQL injection attempts in time parameters', async () => {
      const baseQuery = buildBaseQuery();

      const response = await request(app)
        .post('/api/v1/hunt/query')
        .send({
          ...baseQuery,
          startTime: `${baseQuery.startTime}' OR 1=1 --`,
        })
        .expect(400);

      expect(response.body).toMatchObject({ error: 'Invalid query parameters' });
      expect(huntService.queryTimeline).not.toHaveBeenCalled();
    });

    it('rejects time-based blind injection payloads', async () => {
      const baseQuery = buildBaseQuery();

      const response = await request(app)
        .post('/api/v1/hunt/query')
        .send({
          ...baseQuery,
          endTime: `${baseQuery.endTime}; SELECT pg_sleep(5)`,
        })
        .expect(400);

      expect(response.body).toMatchObject({ error: 'Invalid query parameters' });
      expect(huntService.queryTimeline).not.toHaveBeenCalled();
    });

    it('rejects NoSQL injection in filter parameters', async () => {
      const baseQuery = buildBaseQuery();

      const response = await request(app)
        .post('/api/v1/hunt/query')
        .send({
          ...baseQuery,
          sourceIps: [{ $ne: '198.51.100.10' }],
        })
        .expect(400);

      expect(response.body).toMatchObject({ error: 'Invalid query parameters' });
      expect(huntService.queryTimeline).not.toHaveBeenCalled();
    });

    it('enforces pagination limit bounds', async () => {
      const baseQuery = buildBaseQuery();

      const response = await request(app)
        .post('/api/v1/hunt/query')
        .send({
          ...baseQuery,
          limit: 10001,
        })
        .expect(400);

      expect(response.body).toMatchObject({ error: 'Invalid query parameters' });
      expect(huntService.queryTimeline).not.toHaveBeenCalled();
    });

    it('rejects invalid input shapes', async () => {
      const baseQuery = buildBaseQuery();

      const response = await request(app)
        .post('/api/v1/hunt/query')
        .send({
          ...baseQuery,
          anonFingerprint: 'abc123',
        })
        .expect(400);

      expect(response.body).toMatchObject({ error: 'Invalid query parameters' });
      expect(huntService.queryTimeline).not.toHaveBeenCalled();
    });
  });
});
