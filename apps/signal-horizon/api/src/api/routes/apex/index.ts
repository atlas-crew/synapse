import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { createDashboardRouter } from './dashboard.js';
import { createEndpointsRouter } from './endpoints.js';
import { createRulesRouter } from './rules.js';
import { createThreatsRouter } from './threats.js';

export function createApexRouter(
  prisma: PrismaClient,
  logger: Logger
): Router {
  const router = Router();
  const apexLogger = logger.child({ module: 'apex' });

  router.use('/dashboard', createDashboardRouter(prisma, apexLogger));
  router.use('/endpoints', createEndpointsRouter(prisma, apexLogger));
  router.use('/rules', createRulesRouter(prisma, apexLogger));
  router.use('/threats', createThreatsRouter(prisma, apexLogger));

  apexLogger.info('Apex routes initialized');

  return router;
}
