/**
 * Campaign API Routes
 * CRUD operations for cross-tenant campaigns
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { requireScope } from '../middleware/auth.js';
import { validateParams, validateQuery, validateBody, IdParamSchema } from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';

// Validation schemas
const ListCampaignsQuerySchema = z.object({
  status: z.enum(['ACTIVE', 'MONITORING', 'RESOLVED', 'FALSE_POSITIVE']).optional(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

const UpdateCampaignBodySchema = z.object({
  status: z.enum(['ACTIVE', 'MONITORING', 'RESOLVED', 'FALSE_POSITIVE']).optional(),
});

export function createCampaignRoutes(prisma: PrismaClient): Router {
  const router = Router();

  /**
   * GET /api/v1/campaigns
   * List campaigns (filtered by tenant unless fleet admin)
   */
  router.get(
    '/',
    requireScope('dashboard:read'),
    validateQuery(ListCampaignsQuerySchema),
    async (req, res) => {
      try {
        const { status, severity, limit, offset } = req.query as unknown as z.infer<typeof ListCampaignsQuerySchema>;
        const auth = req.auth!;

      // Build where clause based on permissions
      const where: Record<string, unknown> = {};

      if (!auth.isFleetAdmin) {
        // Non-fleet-admin can only see cross-tenant campaigns OR their own tenant's campaigns
        where.OR = [
          { isCrossTenant: true },
          { tenantId: auth.tenantId },
        ];
      }

        if (status) {
          where.status = status;
        }

        if (severity) {
          where.severity = severity;
        }

        const [campaigns, total] = await Promise.all([
          prisma.campaign.findMany({
            where,
            take: limit,
            skip: offset,
            orderBy: { lastActivityAt: 'desc' },
          }),
          prisma.campaign.count({ where }),
        ]);

        res.json({
          campaigns,
          pagination: { total, limit, offset },
        });
      } catch (error) {
        console.error('Failed to list campaigns:', error);
        res.status(500).json({ error: 'Failed to list campaigns', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/campaigns/:id
   * Get single campaign details
   */
  router.get(
    '/:id',
    requireScope('dashboard:read'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const auth = req.auth!;

        const campaign = await prisma.campaign.findUnique({
          where: { id },
        });

        if (campaign === undefined || campaign === null) {
          res.status(404).json({ error: 'Campaign not found' });
          return;
        }

        // Check access (fleet admin can see all, others only cross-tenant or own)
        if (!auth.isFleetAdmin && !campaign.isCrossTenant && campaign.tenantId !== auth.tenantId) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }

        res.json(campaign);
      } catch (error) {
        console.error('Failed to get campaign:', error);
        res.status(500).json({ error: 'Failed to get campaign', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * PATCH /api/v1/campaigns/:id
   * Update campaign status (requires write permission)
   */
  router.patch(
    '/:id',
    requireScope('dashboard:write', 'fleet:admin'),
    validateParams(IdParamSchema),
    validateBody(UpdateCampaignBodySchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const { status } = req.body as z.infer<typeof UpdateCampaignBodySchema>;
        const auth = req.auth!;

        // Verify campaign exists
        const existing = await prisma.campaign.findUnique({ where: { id } });

        if (existing === undefined || existing === null) {
          res.status(404).json({ error: 'Campaign not found' });
          return;
        }

        // Only fleet admin can update cross-tenant campaigns
        if (existing.isCrossTenant && !auth.isFleetAdmin) {
          res.status(403).json({ error: 'Only fleet admins can update cross-tenant campaigns' });
          return;
        }

        const campaign = await prisma.campaign.update({
          where: { id },
          data: { status },
        });

        res.json(campaign);
      } catch (error) {
        console.error('Failed to update campaign:', error);
        res.status(500).json({ error: 'Failed to update campaign', message: getErrorMessage(error) });
      }
    }
  );

  return router;
}
