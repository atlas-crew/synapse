import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';

export function createRulesRouter(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();

  // GET /api/v1/apex/rules - List all customer rules
  router.get('/', async (req, res) => {
    try {
      const tenantId = (req as any).auth?.tenantId;
      if (!tenantId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const rules = await prisma.customerRule.findMany({
        where: { tenantId },
        include: {
          _count: {
            select: { deployments: true, endpointBindings: true }
          }
        },
        orderBy: { updatedAt: 'desc' },
      });

      return res.json({ rules });
    } catch (error) {
      logger.error({ error }, 'Failed to fetch rules');
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // GET /api/v1/apex/rules/:id - Get rule details
  router.get('/:id', async (req, res) => {
    try {
      const tenantId = (req as any).auth?.tenantId;
      if (!tenantId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const rule = await prisma.customerRule.findFirst({
        where: { id: req.params.id, tenantId },
        include: {
          deployments: {
            include: {
              sensor: {
                select: { id: true, name: true, connectionState: true }
              }
            }
          },
          endpointBindings: {
            include: {
              endpoint: {
                select: {
                  id: true,
                  method: true,
                  pathTemplate: true,
                  service: true
                }
              }
            }
          }
        }
      });

      if (!rule) {
        return res.status(404).json({ error: 'Rule not found' });
      }

      return res.json({ rule });
    } catch (error) {
      logger.error({ error }, 'Failed to fetch rule');
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  // POST /api/v1/apex/rules - Create a new rule
  router.post('/', async (req, res) => {
    try {
      const tenantId = (req as any).auth?.tenantId;
      if (!tenantId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const { name, description, category, severity, action, patterns, exclusions, sensitivity } = req.body;

      if (!name || !patterns) {
        return res.status(400).json({ error: 'Missing required fields: name, patterns' });
      }

      const rule = await prisma.customerRule.create({
        data: {
          tenantId,
          name,
          description,
          category: category || 'custom',
          severity: severity || 'medium',
          action: action || 'block',
          patterns,
          exclusions,
          sensitivity: sensitivity || 50,
        }
      });

      return res.status(201).json({ rule });
    } catch (error) {
      logger.error({ error }, 'Failed to create rule');
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}
