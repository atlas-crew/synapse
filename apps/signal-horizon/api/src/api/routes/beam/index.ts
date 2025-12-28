import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { createDashboardRouter } from './dashboard.js';
import { createEndpointsRouter } from './endpoints.js';
import { createRulesRouter } from './rules.js';
import { createThreatsRouter } from './threats.js';

export function createBeamRouter(
  prisma: PrismaClient,
  logger: Logger
): Router {
  const router = Router();
  const beamLogger = logger.child({ module: 'beam' });

  router.use('/dashboard', createDashboardRouter(prisma, beamLogger));
  router.use('/endpoints', createEndpointsRouter(prisma, beamLogger));
  router.use('/rules', createRulesRouter(prisma, beamLogger));
  router.use('/threats', createThreatsRouter(prisma, beamLogger));

  beamLogger.info('Beam routes initialized');

  return router;
}
