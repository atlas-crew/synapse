/**
 * Fleet Intelligence Routes
 * Fleet-wide intel endpoints backed by stored snapshots.
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { z } from 'zod';
import { requireScope } from '../middleware/auth.js';
import { validateQuery } from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';
import type { FleetIntelService } from '../../services/fleet/fleet-intel.js';

// =============================================================================
// Validation Schemas
// =============================================================================

const PaginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

const ActorsQuerySchema = PaginationSchema.extend({
  minRisk: z.coerce.number().min(0).max(100).optional(),
});

const SessionsQuerySchema = PaginationSchema.extend({
  actorId: z.string().optional(),
  suspicious: z.preprocess(
    (val) => val === 'true' || val === '1',
    z.boolean().optional()
  ),
});

const CampaignsQuerySchema = PaginationSchema.extend({
  status: z.string().optional(),
});

const ProfilesQuerySchema = PaginationSchema.extend({
  template: z.string().optional(),
});

// =============================================================================
// Route Factory
// =============================================================================

export interface FleetIntelRoutesOptions {
  fleetIntelService?: FleetIntelService;
}

export function createFleetIntelRoutes(
  _prisma: PrismaClient,
  logger: Logger,
  options: FleetIntelRoutesOptions = {}
): Router {
  const router = Router();
  const { fleetIntelService } = options;

  // =============================================================================
  // Actors
  // =============================================================================

  /**
   * GET /api/v1/fleet/intel/actors
   */
  router.get(
    '/actors',
    requireScope('fleet:read'),
    validateQuery(ActorsQuerySchema),
    async (req, res) => {
      try {
        if (!fleetIntelService) {
          res.status(503).json({ error: 'Fleet intel service not available' });
          return;
        }

        const auth = req.auth!;
        const query = req.query as unknown as z.infer<typeof ActorsQuerySchema>;
        const result = await fleetIntelService.getActors(auth.tenantId, query);
        res.json(result);
      } catch (error) {
        logger.error({ error }, 'Failed to fetch fleet actors');
        res.status(500).json({
          error: 'Failed to fetch fleet actors',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // =============================================================================
  // Sessions
  // =============================================================================

  /**
   * GET /api/v1/fleet/intel/sessions
   */
  router.get(
    '/sessions',
    requireScope('fleet:read'),
    validateQuery(SessionsQuerySchema),
    async (req, res) => {
      try {
        if (!fleetIntelService) {
          res.status(503).json({ error: 'Fleet intel service not available' });
          return;
        }

        const auth = req.auth!;
        const query = req.query as unknown as z.infer<typeof SessionsQuerySchema>;
        const result = await fleetIntelService.getSessions(auth.tenantId, query);
        res.json(result);
      } catch (error) {
        logger.error({ error }, 'Failed to fetch fleet sessions');
        res.status(500).json({
          error: 'Failed to fetch fleet sessions',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // =============================================================================
  // Campaigns
  // =============================================================================

  /**
   * GET /api/v1/fleet/intel/campaigns
   */
  router.get(
    '/campaigns',
    requireScope('fleet:read'),
    validateQuery(CampaignsQuerySchema),
    async (req, res) => {
      try {
        if (!fleetIntelService) {
          res.status(503).json({ error: 'Fleet intel service not available' });
          return;
        }

        const auth = req.auth!;
        const query = req.query as unknown as z.infer<typeof CampaignsQuerySchema>;
        const result = await fleetIntelService.getCampaigns(auth.tenantId, query);
        res.json(result);
      } catch (error) {
        logger.error({ error }, 'Failed to fetch fleet campaigns');
        res.status(500).json({
          error: 'Failed to fetch fleet campaigns',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // =============================================================================
  // Profiles
  // =============================================================================

  /**
   * GET /api/v1/fleet/intel/profiles
   */
  router.get(
    '/profiles',
    requireScope('fleet:read'),
    validateQuery(ProfilesQuerySchema),
    async (req, res) => {
      try {
        if (!fleetIntelService) {
          res.status(503).json({ error: 'Fleet intel service not available' });
          return;
        }

        const auth = req.auth!;
        const query = req.query as unknown as z.infer<typeof ProfilesQuerySchema>;
        const result = await fleetIntelService.getProfiles(auth.tenantId, query);
        res.json(result);
      } catch (error) {
        logger.error({ error }, 'Failed to fetch fleet profiles');
        res.status(500).json({
          error: 'Failed to fetch fleet profiles',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // =============================================================================
  // Payload Stats
  // =============================================================================

  /**
   * GET /api/v1/fleet/intel/payload/stats
   */
  router.get(
    '/payload/stats',
    requireScope('fleet:read'),
    async (req, res) => {
      try {
        if (!fleetIntelService) {
          res.status(503).json({ error: 'Fleet intel service not available' });
          return;
        }

        const auth = req.auth!;
        const result = await fleetIntelService.getPayloadStats(auth.tenantId);
        res.json(result);
      } catch (error) {
        logger.error({ error }, 'Failed to fetch fleet payload stats');
        res.status(500).json({
          error: 'Failed to fetch fleet payload stats',
          message: getErrorMessage(error),
        });
      }
    }
  );

  return router;
}
