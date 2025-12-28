import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { asyncHandler, handleValidationError } from '../../../lib/errors.js';
import { ThreatQuerySchema, UUIDParamSchema } from './validation.js';

export function createThreatsRouter(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();

  // GET /api/v1/beam/threats - List recent block decisions
  router.get('/', asyncHandler(async (req, res) => {
    const tenantId = (req as any).auth?.tenantId;
    if (!tenantId) {
      return res.status(401).json({
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
      });
    }

    // Validate query parameters
    const queryValidation = ThreatQuerySchema.safeParse(req.query);
    if (!queryValidation.success) {
      return handleValidationError(res, queryValidation.error);
    }

    const { severity, status, timeRange, limit, offset } = queryValidation.data;

    // Build where clause with filters
    const where: any = { tenantId };

    if (severity) {
      where.severity = severity;
    }

    if (status) {
      where.action = status;
    }

    if (timeRange) {
      const now = Date.now();
      const timeRangeMs: Record<string, number> = {
        '1h': 60 * 60 * 1000,
        '24h': 24 * 60 * 60 * 1000,
        '7d': 7 * 24 * 60 * 60 * 1000,
        '30d': 30 * 24 * 60 * 60 * 1000,
      };
      where.decidedAt = {
        gte: new Date(now - timeRangeMs[timeRange]),
      };
    }

    const [blocks, total] = await Promise.all([
      prisma.blockDecision.findMany({
        where,
        include: {
          sensor: {
            select: { id: true, name: true }
          }
        },
        orderBy: { decidedAt: 'desc' },
        take: limit,
        skip: offset,
      }),
      prisma.blockDecision.count({ where }),
    ]);

    logger.info({ tenantId, count: blocks.length, total }, 'Threats fetched successfully');

    return res.json({
      blocks,
      pagination: {
        total,
        limit,
        offset,
        hasMore: offset + limit < total
      }
    });
  }));

  // GET /api/v1/beam/threats/:id - Get block decision details
  router.get('/:id', asyncHandler(async (req, res) => {
    const tenantId = (req as any).auth?.tenantId;
    if (!tenantId) {
      return res.status(401).json({
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
      });
    }

    // Validate UUID parameter
    const paramValidation = UUIDParamSchema.safeParse(req.params);
    if (!paramValidation.success) {
      return handleValidationError(res, paramValidation.error);
    }

    const { id } = paramValidation.data;

    const block = await prisma.blockDecision.findFirst({
      where: { id, tenantId },
      include: {
        sensor: {
          select: { id: true, name: true, version: true }
        }
      }
    });

    if (!block) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Block decision not found',
      });
    }

    logger.info({ tenantId, blockId: id }, 'Threat details fetched successfully');

    return res.json({ block });
  }));

  return router;
}
