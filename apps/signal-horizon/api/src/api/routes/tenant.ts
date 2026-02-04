/**
 * Tenant Settings API Routes
 *
 * Handles tenant-level configurations, specifically collective defense
 * and privacy settings (SharingPreference).
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { requireScope } from '../middleware/auth.js';

// Validation schemas
const updateSettingsSchema = z.object({
  sharingPreference: z.enum([
    'CONTRIBUTE_AND_RECEIVE',
    'RECEIVE_ONLY',
    'CONTRIBUTE_ONLY',
    'ISOLATED',
  ]).optional(),
});

/**
 * Create tenant routes for settings management
 */
export function createTenantRoutes(
  prisma: PrismaClient,
  logger: Logger
): Router {
  const router = Router();

  /**
   * GET /settings - Get current tenant settings
   */
  router.get('/settings', requireScope('fleet:read'), async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.auth!.tenantId;

      const tenant = await prisma.tenant.findUnique({
        where: { id: tenantId },
        select: {
          id: true,
          name: true,
          tier: true,
          sharingPreference: true,
          createdAt: true,
          updatedAt: true,
        },
      });

      if (!tenant) {
        res.status(404).json({ error: 'Tenant not found' });
        return;
      }

      res.json(tenant);
    } catch (error) {
      logger.error({ error }, 'Error fetching tenant settings');
      res.status(500).json({ error: 'Failed to fetch settings' });
    }
  });

  /**
   * PATCH /settings - Update tenant settings
   */
  router.patch('/settings', requireScope('fleet:write'), async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.auth!.tenantId;

      const parsed = updateSettingsSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Validation failed',
          details: parsed.error.issues,
        });
        return;
      }

      const { sharingPreference } = parsed.data;

      const updated = await prisma.tenant.update({
        where: { id: tenantId },
        data: {
          ...(sharingPreference && { sharingPreference }),
        },
        select: {
          id: true,
          name: true,
          tier: true,
          sharingPreference: true,
          updatedAt: true,
        },
      });

      logger.info(
        { tenantId, sharingPreference, userId: req.auth!.userId },
        'Tenant settings updated'
      );

      res.json(updated);
    } catch (error) {
      logger.error({ error }, 'Error updating tenant settings');
      res.status(500).json({ error: 'Failed to update settings' });
    }
  });

  return router;
}
