import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';

export function createThreatsRouter(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();

  // GET /api/v1/apex/threats - List recent block decisions
  router.get('/', async (req, res) => {
    try {
      const tenantId = (req as any).auth?.tenantId;
      if (!tenantId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const limit = parseInt(req.query.limit as string) || 50;
      const offset = parseInt(req.query.offset as string) || 0;

      const [blocks, total] = await Promise.all([
        prisma.blockDecision.findMany({
          where: { tenantId },
          include: {
            sensor: {
              select: { id: true, name: true }
            }
          },
          orderBy: { decidedAt: 'desc' },
          take: limit,
          skip: offset,
        }),
        prisma.blockDecision.count({ where: { tenantId } }),
      ]);

      return res.json({
        blocks,
        pagination: {
          total,
          limit,
          offset,
          hasMore: offset + limit < total
        }
      });
    } catch (error) {
      logger.error({ error }, 'Failed to fetch block decisions');
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // GET /api/v1/apex/threats/:id - Get block decision details
  router.get('/:id', async (req, res) => {
    try {
      const tenantId = (req as any).auth?.tenantId;
      if (!tenantId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const block = await prisma.blockDecision.findFirst({
        where: { id: req.params.id, tenantId },
        include: {
          sensor: {
            select: { id: true, name: true, version: true }
          }
        }
      });

      if (!block) {
        return res.status(404).json({ error: 'Block decision not found' });
      }

      return res.json({ block });
    } catch (error) {
      logger.error({ error }, 'Failed to fetch block decision');
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}
