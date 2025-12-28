import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';

export function createDashboardRouter(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();

  router.get('/', async (req, res) => {
    try {
      const tenantId = (req as any).auth?.tenantId;
      if (!tenantId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const [endpointCount, ruleCount, activeRuleCount, blockCount] = await Promise.all([
        prisma.endpoint.count({ where: { tenantId } }),
        prisma.customerRule.count({ where: { tenantId } }),
        prisma.customerRule.count({ where: { tenantId, enabled: true } }),
        prisma.blockDecision.count({
          where: {
            tenantId,
            decidedAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
          }
        }),
      ]);

      return res.json({
        status: 'protected',
        summary: {
          totalEndpoints: endpointCount,
          totalRules: ruleCount,
          activeRules: activeRuleCount,
          blocks24h: blockCount,
        },
      });
    } catch (error) {
      logger.error({ error }, 'Failed to fetch dashboard');
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}
