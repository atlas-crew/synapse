import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { requireScope } from '../../middleware/auth.js';
import { asyncHandler, handleValidationError } from '../../../lib/errors.js';
import { sendProblem } from '../../../lib/problem-details.js';
import { EndpointQuerySchema, UUIDParamSchema } from './validation.js';

export function createEndpointsRouter(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();

  // GET /api/v1/beam/endpoints - List all endpoints
  router.get('/', requireScope('dashboard:read'), asyncHandler(async (req, res) => {
    const tenantId = req.auth!.tenantId;

    // Validate query parameters
    const queryValidation = EndpointQuerySchema.safeParse(req.query);
    if (!queryValidation.success) {
      return handleValidationError(res, queryValidation.error);
    }

    const { service, method, limit } = queryValidation.data;

    const endpoints = await prisma.endpoint.findMany({
      where: {
        tenantId,
        ...(service && { service }),
        ...(method && { method }),
      },
      include: {
        sensor: {
          select: { id: true, name: true }
        },
        _count: {
          select: { schemaChanges: true, ruleBindings: true }
        }
      },
      orderBy: { lastSeenAt: 'desc' },
      take: limit,
    });

    logger.info({ tenantId, count: endpoints.length }, 'Endpoints fetched successfully');

    return res.json({ endpoints });
  }));

  // GET /api/v1/beam/endpoints/:id - Get endpoint details
  router.get('/:id', requireScope('dashboard:read'), asyncHandler(async (req, res) => {
    const tenantId = req.auth!.tenantId;

    // Validate UUID parameter
    const paramValidation = UUIDParamSchema.safeParse(req.params);
    if (!paramValidation.success) {
      return handleValidationError(res, paramValidation.error);
    }

    const { id } = paramValidation.data;

    const endpoint = await prisma.endpoint.findFirst({
      where: { id, tenantId },
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
      return sendProblem(res, 404, 'Endpoint not found', {
        code: 'NOT_FOUND',
        instance: req.originalUrl,
      });
    }

    logger.info({ tenantId, endpointId: id }, 'Endpoint details fetched successfully');

    return res.json({ endpoint });
  }));

  return router;
}
