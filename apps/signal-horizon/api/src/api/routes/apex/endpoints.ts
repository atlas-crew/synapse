import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';

export function createEndpointsRouter(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();

  // GET /api/v1/apex/endpoints - List all endpoints
  router.get('/', async (req, res) => {
    try {
      const tenantId = (req as any).auth?.tenantId;
      if (!tenantId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const endpoints = await prisma.endpoint.findMany({
        where: { tenantId },
        include: {
          sensor: {
            select: { id: true, name: true }
          },
          _count: {
            select: { schemaChanges: true, ruleBindings: true }
          }
        },
        orderBy: { lastSeenAt: 'desc' },
        take: 100,
      });

      return res.json({ endpoints });
    } catch (error) {
      logger.error({ error }, 'Failed to fetch endpoints');
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // GET /api/v1/apex/endpoints/:id - Get endpoint details
  router.get('/:id', async (req, res) => {
    try {
      const tenantId = (req as any).auth?.tenantId;
      if (!tenantId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const endpoint = await prisma.endpoint.findFirst({
        where: { id: req.params.id, tenantId },
        include: {
          sensor: {
            select: { id: true, name: true, version: true }
          },
          schemaChanges: {
            orderBy: { detectedAt: 'desc' },
            take: 10,
          },
          ruleBindings: {
            include: {
              rule: {
                select: { id: true, name: true, enabled: true }
              }
            }
          }
        }
      });

      if (!endpoint) {
        return res.status(404).json({ error: 'Endpoint not found' });
      }

      return res.json({ endpoint });
    } catch (error) {
      logger.error({ error }, 'Failed to fetch endpoint');
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}
