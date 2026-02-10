import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import request from '../../../__tests__/test-request.js';
import { createOpsRoutes } from '../ops.js';

describe('Ops Routes', () => {
  let app: Express;
  let prisma: PrismaClient;
  let logger: Logger;

  beforeEach(() => {
    prisma = {} as unknown as PrismaClient;
    logger = {
      child: vi.fn().mockReturnThis(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    } as unknown as Logger;

    app = express();
    app.use(express.json());
  });

  it('rejects non-fleet-admin callers', async () => {
    const authMiddleware = (req: any, _res: any, next: any) => {
      req.auth = { tenantId: 't1', scopes: ['hunt:read'], isFleetAdmin: false };
      next();
    };

    app.use(
      '/api/v1/ops',
      createOpsRoutes(prisma, logger, {
        authMiddleware,
        clickhouse: null,
        clickhouseConfig: {
          enabled: true,
          host: 'localhost',
          port: 8123,
          database: 'signal_horizon',
          username: 'default',
          maxOpenConnections: 25,
          maxInFlightQueries: 25,
          maxInFlightStreamQueries: 2,
          queryTimeoutSec: 30,
          queueTimeoutSec: 30,
          maxRowsLimit: 100000,
        },
        metrics: {
          clickhouseInsertSuccess: { get: vi.fn().mockResolvedValue({}) },
          clickhouseInsertFailed: { get: vi.fn().mockResolvedValue({}) },
          clickhouseRetryBufferCount: { get: vi.fn().mockResolvedValue({}) },
          clickhouseQueryQueueDepth: { get: vi.fn().mockResolvedValue({}) },
          clickhouseQueryWaitDuration: { get: vi.fn().mockResolvedValue({}) },
          clickhouseQueryDuration: { get: vi.fn().mockResolvedValue({}) },
          clickhouseQueryErrors: { get: vi.fn().mockResolvedValue({}) },
          clickhouseQueriesInFlight: { get: vi.fn().mockResolvedValue({}) },
          clickhouseRawQueriesTotal: { get: vi.fn().mockResolvedValue({}) },
        },
      })
    );

    await request(app).get('/api/v1/ops/clickhouse').expect(403);
  });

  it('returns snapshot for fleet-admin callers', async () => {
    const authMiddleware = (req: any, _res: any, next: any) => {
      req.auth = { tenantId: 't1', scopes: ['fleet:admin'], isFleetAdmin: true };
      next();
    };

    const metrics = {
      clickhouseInsertSuccess: { get: vi.fn().mockResolvedValue({ name: 'a' }) },
      clickhouseInsertFailed: { get: vi.fn().mockResolvedValue({ name: 'b' }) },
      clickhouseRetryBufferCount: { get: vi.fn().mockResolvedValue({ name: 'c' }) },
      clickhouseQueryQueueDepth: { get: vi.fn().mockResolvedValue({ name: 'd' }) },
      clickhouseQueryWaitDuration: { get: vi.fn().mockResolvedValue({ name: 'e' }) },
      clickhouseQueryDuration: { get: vi.fn().mockResolvedValue({ name: 'f' }) },
      clickhouseQueryErrors: { get: vi.fn().mockResolvedValue({ name: 'g' }) },
      clickhouseQueriesInFlight: { get: vi.fn().mockResolvedValue({ name: 'h' }) },
      clickhouseRawQueriesTotal: { get: vi.fn().mockResolvedValue({ name: 'i' }) },
    };

    const clickhouse = {
      isEnabled: () => true,
      ping: vi.fn().mockResolvedValue(true),
    };

    app.use(
      '/api/v1/ops',
      createOpsRoutes(prisma, logger, {
        authMiddleware,
        clickhouse: clickhouse as any,
        clickhouseConfig: {
          enabled: true,
          host: 'localhost',
          port: 8123,
          database: 'signal_horizon',
          username: 'default',
          maxOpenConnections: 25,
          maxInFlightQueries: 25,
          maxInFlightStreamQueries: 2,
          queryTimeoutSec: 30,
          queueTimeoutSec: 30,
          maxRowsLimit: 100000,
        },
        metrics,
      })
    );

    const res = await request(app).get('/api/v1/ops/clickhouse').expect(200);
    expect(res.body.sampledAt).toBeDefined();
    expect(res.body.clickhouse).toMatchObject({ enabled: true, connected: true });
    expect(res.body.clickhouse.config).toMatchObject({ maxOpenConnections: 25, maxInFlightQueries: 25 });
    expect(res.body.clickhouse.config).not.toHaveProperty('host');
    expect(res.body.clickhouse.config).not.toHaveProperty('port');
    expect(res.body.clickhouse.config).not.toHaveProperty('database');
    expect(res.body.clickhouse.config).not.toHaveProperty('username');
    expect(res.body.metrics).toMatchObject({
      clickhouseInsertSuccess: { name: 'a' },
      clickhouseQueryErrors: { name: 'g' },
    });
    expect(clickhouse.ping).toHaveBeenCalled();
  });

  it('returns a generic 500 when metrics collection fails', async () => {
    const authMiddleware = (req: any, _res: any, next: any) => {
      req.auth = { tenantId: 't1', scopes: ['fleet:admin'], isFleetAdmin: true };
      next();
    };

    app.use(
      '/api/v1/ops',
      createOpsRoutes(prisma, logger, {
        authMiddleware,
        clickhouse: { isEnabled: () => true, ping: vi.fn().mockResolvedValue(true) } as any,
        clickhouseConfig: {
          enabled: true,
          host: 'localhost',
          port: 8123,
          database: 'signal_horizon',
          username: 'default',
          maxOpenConnections: 25,
          maxInFlightQueries: 25,
          maxInFlightStreamQueries: 2,
          queryTimeoutSec: 30,
          queueTimeoutSec: 30,
          maxRowsLimit: 100000,
        },
        metrics: {
          clickhouseInsertSuccess: { get: vi.fn().mockRejectedValue(new Error('boom')) },
          clickhouseInsertFailed: { get: vi.fn().mockResolvedValue({}) },
          clickhouseRetryBufferCount: { get: vi.fn().mockResolvedValue({}) },
          clickhouseQueryQueueDepth: { get: vi.fn().mockResolvedValue({}) },
          clickhouseQueryWaitDuration: { get: vi.fn().mockResolvedValue({}) },
          clickhouseQueryDuration: { get: vi.fn().mockResolvedValue({}) },
          clickhouseQueryErrors: { get: vi.fn().mockResolvedValue({}) },
          clickhouseQueriesInFlight: { get: vi.fn().mockResolvedValue({}) },
          clickhouseRawQueriesTotal: { get: vi.fn().mockResolvedValue({}) },
        },
      })
    );

    const res = await request(app).get('/api/v1/ops/clickhouse').expect(500);
    expect(res.body).toMatchObject({
      error: 'ops_snapshot_failed',
      message: 'Failed to collect ClickHouse ops snapshot',
    });
  });
});
