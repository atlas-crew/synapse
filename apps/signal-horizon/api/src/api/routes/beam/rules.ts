import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { asyncHandler, handleValidationError } from '../../../lib/errors.js';
import { CreateRuleSchema, UUIDParamSchema } from './validation.js';

export function createRulesRouter(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();

  // GET /api/v1/beam/rules - List all customer rules
  router.get('/', asyncHandler(async (req, res) => {
    const tenantId = (req as any).auth?.tenantId;
    if (!tenantId) {
      return res.status(401).json({
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
      });
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

    logger.info({ tenantId, count: rules.length }, 'Rules fetched successfully');

    return res.json({ rules });
  }));

  // GET /api/v1/beam/rules/:id - Get rule details
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

    const rule = await prisma.customerRule.findFirst({
      where: { id, tenantId },
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
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Rule not found',
      });
    }

    logger.info({ tenantId, ruleId: id }, 'Rule details fetched successfully');

    return res.json({ rule });
  }));

  // POST /api/v1/beam/rules - Create a new rule
  router.post('/', asyncHandler(async (req, res) => {
    const tenantId = (req as any).auth?.tenantId;
    if (!tenantId) {
      return res.status(401).json({
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
      });
    }

    // Validate request body
    const bodyValidation = CreateRuleSchema.safeParse(req.body);
    if (!bodyValidation.success) {
      return handleValidationError(res, bodyValidation.error);
    }

    const { name, description, category, severity, action, patterns, exclusions, sensitivity } = bodyValidation.data;

    const rule = await prisma.customerRule.create({
      data: {
        tenantId,
        name,
        description,
        category,
        severity,
        action,
        patterns,
        exclusions,
        sensitivity,
      }
    });

    logger.info({ tenantId, ruleId: rule.id }, 'Rule created successfully');

    return res.status(201).json({ rule });
  }));

  return router;
}
