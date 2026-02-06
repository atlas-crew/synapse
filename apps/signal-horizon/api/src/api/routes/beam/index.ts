import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { requireScope } from '../../middleware/auth.js';
import { createDashboardRouter } from './dashboard.js';
import { createEndpointsRouter } from './endpoints.js';
import { createRulesRouter } from './rules.js';
import { createThreatsRouter } from './threats.js';
import { createAnalyticsRouter } from './analytics.js';
import { getSynapseDirectAdapter } from '../../../services/synapse-direct.js';
import { config } from '../../../config.js';
import { buildTraceHeaders } from '../../../lib/trace-headers.js';

export function createBeamRouter(
  prisma: PrismaClient,
  logger: Logger
): Router {
  const router = Router();
  const beamLogger = logger.child({ module: 'beam' });

  // Health check for synapse connectivity
  router.get('/health', requireScope('dashboard:read'), async (req, res) => {
    const synapseAdapter = getSynapseDirectAdapter();

    if (synapseAdapter) {
      const health = await synapseAdapter.healthCheck(buildTraceHeaders(req));
      return res.json({
        synapseDirect: {
          url: config.synapseDirect.url,
          connected: health.connected,
          status: health.status,
          uptime: health.uptime,
          checkedAt: new Date().toISOString(),
        },
      });
    }

    return res.json({
      synapseDirect: {
        enabled: false,
        note: 'SYNAPSE_DIRECT_URL not configured',
      },
    });
  });

  router.use('/dashboard', createDashboardRouter(prisma, beamLogger));
  router.use('/endpoints', createEndpointsRouter(prisma, beamLogger));
  router.use('/rules', createRulesRouter(prisma, beamLogger));
  router.use('/threats', createThreatsRouter(prisma, beamLogger));
  router.use('/analytics', createAnalyticsRouter(prisma, beamLogger));

  beamLogger.info('Beam routes initialized');

  return router;
}
