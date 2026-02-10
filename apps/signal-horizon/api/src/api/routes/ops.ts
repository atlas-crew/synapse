/**
 * Ops Routes
 * Fleet-admin visibility into infrastructure metrics and runtime config.
 */

import { Router, type Request, type Response } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { ClickHouseService } from '../../storage/clickhouse/index.js';
import type { RedisKv } from '../../storage/redis/kv.js';
import { createAuthMiddleware, authorize } from '../middleware/auth.js';
import { metrics as defaultMetrics } from '../../services/metrics.js';

type PromMetric = {
  get: () => Promise<unknown> | unknown;
};

export interface OpsRoutesOptions {
  clickhouse?: ClickHouseService | null;
  clickhouseConfig?: {
    enabled: boolean;
    host: string;
    port: number;
    database: string;
    username: string;
    maxOpenConnections: number;
    maxInFlightQueries: number;
    maxInFlightStreamQueries: number;
    queryTimeoutSec: number;
    queueTimeoutSec: number;
    maxRowsLimit: number;
  };
  kv?: RedisKv | null;
  authMiddleware?: ReturnType<typeof createAuthMiddleware>;
  metrics?: {
    clickhouseInsertSuccess: PromMetric;
    clickhouseInsertFailed: PromMetric;
    clickhouseRetryBufferCount: PromMetric;
    clickhouseQueryQueueDepth: PromMetric;
    clickhouseQueryWaitDuration: PromMetric;
    clickhouseQueryDuration: PromMetric;
    clickhouseQueryErrors: PromMetric;
    clickhouseQueriesInFlight: PromMetric;
    clickhouseRawQueriesTotal: PromMetric;
  };
}

export function createOpsRoutes(prisma: PrismaClient, logger: Logger, options: OpsRoutesOptions = {}): Router {
  const router = Router();
  const routeLogger = logger.child({ route: 'ops' });

  const authMiddleware = options.authMiddleware ?? createAuthMiddleware(prisma, options.kv ?? null);
  const metrics = options.metrics ?? defaultMetrics;

  // All ops routes require auth.
  router.use(authMiddleware);

  /**
   * GET /api/v1/ops/clickhouse
   * Fleet-admin snapshot of ClickHouse config + query health metrics.
   */
  router.get(
    '/clickhouse',
    authorize(prisma, { scopes: 'fleet:admin' }),
    async (req: Request, res: Response) => {
      const clickhouse = options.clickhouse ?? null;
      const cfg = options.clickhouseConfig;

      try {
        const enabled = Boolean(clickhouse?.isEnabled?.() ?? cfg?.enabled ?? false);
        let connected = false;
        if (enabled && typeof clickhouse?.ping === 'function') {
          connected = await clickhouse.ping().then(Boolean).catch(() => false);
        }

        const [
          clickhouseInsertSuccess,
          clickhouseInsertFailed,
          clickhouseRetryBufferCount,
          clickhouseQueryQueueDepth,
          clickhouseQueryWaitDuration,
          clickhouseQueryDuration,
          clickhouseQueryErrors,
          clickhouseQueriesInFlight,
          clickhouseRawQueriesTotal,
        ] = await Promise.all([
          Promise.resolve(metrics.clickhouseInsertSuccess.get()),
          Promise.resolve(metrics.clickhouseInsertFailed.get()),
          Promise.resolve(metrics.clickhouseRetryBufferCount.get()),
          Promise.resolve(metrics.clickhouseQueryQueueDepth.get()),
          Promise.resolve(metrics.clickhouseQueryWaitDuration.get()),
          Promise.resolve(metrics.clickhouseQueryDuration.get()),
          Promise.resolve(metrics.clickhouseQueryErrors.get()),
          Promise.resolve(metrics.clickhouseQueriesInFlight.get()),
          Promise.resolve(metrics.clickhouseRawQueriesTotal.get()),
        ]);

        const safeConfig = cfg
          ? {
              enabled: cfg.enabled,
              maxOpenConnections: cfg.maxOpenConnections,
              maxInFlightQueries: cfg.maxInFlightQueries,
              maxInFlightStreamQueries: cfg.maxInFlightStreamQueries,
              queryTimeoutSec: cfg.queryTimeoutSec,
              queueTimeoutSec: cfg.queueTimeoutSec,
              maxRowsLimit: cfg.maxRowsLimit,
            }
          : null;

        res.json({
          sampledAt: new Date().toISOString(),
          clickhouse: {
            enabled,
            connected,
            config: safeConfig,
          },
          metrics: {
            clickhouseInsertSuccess,
            clickhouseInsertFailed,
            clickhouseRetryBufferCount,
            clickhouseQueryQueueDepth,
            clickhouseQueryWaitDuration,
            clickhouseQueryDuration,
            clickhouseQueryErrors,
            clickhouseQueriesInFlight,
            clickhouseRawQueriesTotal,
          },
        });
      } catch (error) {
        routeLogger.error({ error, tenantId: req.auth?.tenantId }, 'Failed to render ClickHouse ops snapshot');
        res.status(500).json({
          error: 'ops_snapshot_failed',
          message: 'Failed to collect ClickHouse ops snapshot',
        });
      }
    }
  );

  return router;
}
