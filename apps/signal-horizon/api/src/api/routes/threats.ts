/**
 * Threat API Routes
 * Query and search threat intelligence
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { requireScope } from '../middleware/auth.js';
import { validateParams, validateQuery, IdParamSchema } from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';

// Validation schemas
const ListThreatsQuerySchema = z.object({
  threatType: z.string().optional(),
  isFleetThreat: z.enum(['true', 'false']).optional().transform((v) => v === 'true'),
  minRiskScore: z.coerce.number().min(0).max(100).optional(),
  maxRiskScore: z.coerce.number().min(0).max(100).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

const SearchThreatsQuerySchema = z.object({
  q: z.string().min(2, 'Query must be at least 2 characters'),
  type: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(50).default(20),
});

export function createThreatRoutes(prisma: PrismaClient): Router {
  const router = Router();

  /**
   * GET /api/v1/threats
   * List threats with filtering
   */
  router.get(
    '/',
    requireScope('dashboard:read'),
    validateQuery(ListThreatsQuerySchema),
    async (req, res) => {
      try {
        const { threatType, isFleetThreat, minRiskScore, maxRiskScore, limit, offset } =
          req.query as unknown as z.infer<typeof ListThreatsQuerySchema>;
        const auth = req.auth!;

        // Build where clause
        const where: Record<string, unknown> = {};

        if (!auth.isFleetAdmin) {
          where.OR = [{ isFleetThreat: true }, { tenantId: auth.tenantId }];
        }

        if (threatType) {
          where.threatType = threatType;
        }

        if (isFleetThreat !== undefined) {
          where.isFleetThreat = isFleetThreat;
        }

        if (minRiskScore !== undefined || maxRiskScore !== undefined) {
          where.riskScore = {
            ...(minRiskScore !== undefined && { gte: minRiskScore }),
            ...(maxRiskScore !== undefined && { lte: maxRiskScore }),
          };
        }

        const [threats, total] = await Promise.all([
          prisma.threat.findMany({
            where,
            take: limit,
            skip: offset,
            orderBy: { lastSeenAt: 'desc' },
          }),
          prisma.threat.count({ where }),
        ]);

        res.json({ threats, pagination: { total, limit, offset } });
      } catch (error) {
        console.error('Failed to list threats:', error);
        res.status(500).json({ error: 'Failed to list threats', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/threats/search
   * Search threats by indicator
   */
  router.get(
    '/search',
    requireScope('dashboard:read'),
    validateQuery(SearchThreatsQuerySchema),
    async (req, res) => {
      try {
        const { q, type, limit } = req.query as unknown as z.infer<typeof SearchThreatsQuerySchema>;
        const auth = req.auth!;

        const where: Record<string, unknown> = {
          indicator: { contains: q, mode: 'insensitive' },
        };

        if (!auth.isFleetAdmin) {
          where.OR = [{ isFleetThreat: true }, { tenantId: auth.tenantId }];
        }

        if (type) {
          where.threatType = type;
        }

        const threats = await prisma.threat.findMany({
          where,
          take: limit,
          orderBy: { riskScore: 'desc' },
          select: {
            id: true,
            threatType: true,
            indicator: true,
            riskScore: true,
            hitCount: true,
            isFleetThreat: true,
            lastSeenAt: true,
          },
        });

        res.json({ threats, query: q });
      } catch (error) {
        console.error('Failed to search threats:', error);
        res.status(500).json({ error: 'Failed to search threats', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/threats/:id
   * Get single threat details
   */
  router.get(
    '/:id',
    requireScope('dashboard:read'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const auth = req.auth!;

        const threat = await prisma.threat.findUnique({ where: { id } });

        if (threat === undefined || threat === null) {
          res.status(404).json({ error: 'Threat not found' });
          return;
        }

        if (!auth.isFleetAdmin && !threat.isFleetThreat && threat.tenantId !== auth.tenantId) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }

        res.json(threat);
      } catch (error) {
        console.error('Failed to get threat:', error);
        res.status(500).json({ error: 'Failed to get threat', message: getErrorMessage(error) });
      }
    }
  );

  return router;
}
