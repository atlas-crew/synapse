import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { asyncHandler } from '../../../lib/errors.js';

export function createDashboardRouter(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();

  router.get('/', asyncHandler(async (req, res) => {
    const tenantId = (req as any).auth?.tenantId;
    if (!tenantId) {
      return res.status(401).json({
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
      });
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

    logger.info({ tenantId }, 'Dashboard data fetched successfully');

    return res.json({
      status: 'protected',
      summary: {
        totalEndpoints: endpointCount,
        totalRules: ruleCount,
        activeRules: activeRuleCount,
        blocks24h: blockCount,
      },
    });
  }));

  return router;
}
