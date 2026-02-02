/**
 * Actor API Routes
 * Threat actor profile endpoints
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { requireScope } from '../../middleware/auth.js';
import { validateParams, validateQuery, IdParamSchema } from '../../middleware/validation.js';
import { getErrorMessage } from '../../../utils/errors.js';
import { ActorService } from '../../../services/intel/actors.js';

// =============================================================================
// Validation Schemas
// =============================================================================

const ListActorsQuerySchema = z.object({
  minRiskScore: z.coerce.number().min(0).max(100).optional(),
  hasActiveCampaigns: z.coerce.boolean().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

const TimelineQuerySchema = z.object({
  windowHours: z.coerce.number().int().min(1).max(720).default(168), // 7 days default
});

const ActorGraphQuerySchema = z.object({
  fingerprint: z.string().min(1),
  windowHours: z.coerce.number().int().min(1).max(720).default(168),
});

// =============================================================================
// Route Factory
// =============================================================================

export function createActorRoutes(
  prisma: PrismaClient,
  logger: import('pino').Logger
): Router {
  const router = Router();
  const actorService = new ActorService(prisma, logger);

  /**
   * GET /api/v1/intel/actors
   * List threat actor profiles
   */
  router.get(
    '/',
    requireScope('dashboard:read'),
    validateQuery(ListActorsQuerySchema),
    async (req, res) => {
      try {
        const query = req.query as unknown as z.infer<typeof ListActorsQuerySchema>;
        const auth = req.auth!;

        const tenantId = auth.isFleetAdmin ? null : auth.tenantId;

        const actors = await actorService.listActors({
          ...query,
          tenantId,
        });

        res.json({
          actors,
          pagination: {
            limit: query.limit,
            offset: query.offset,
            total: actors.length,
          },
        });
      } catch (error) {
        console.error('Failed to list actors:', error);
        res.status(500).json({ error: 'Failed to list actors', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/intel/actors/graph
   * Get actor-to-infrastructure graph for a fingerprint
   */
  router.get(
    '/graph',
    requireScope('dashboard:read'),
    validateQuery(ActorGraphQuerySchema),
    async (req, res) => {
      try {
        const { fingerprint, windowHours } = req.query as unknown as z.infer<typeof ActorGraphQuerySchema>;
        const auth = req.auth!;

        const tenantId = auth.isFleetAdmin ? null : auth.tenantId;
        const graph = await actorService.getActorInfrastructureGraph(fingerprint, {
          tenantId,
          windowHours,
        });

        if (!graph) {
          res.status(404).json({ error: 'Actor not found' });
          return;
        }

        res.json(graph);
      } catch (error) {
        console.error('Failed to build actor graph:', error);
        res.status(500).json({ error: 'Failed to build actor graph', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/intel/actors/:id
   * Get specific actor profile
   */
  router.get(
    '/:id',
    requireScope('dashboard:read'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const auth = req.auth!;

        const tenantId = auth.isFleetAdmin ? undefined : auth.tenantId;
        const actor = await actorService.getActor(id, tenantId);

        if (!actor) {
          res.status(404).json({ error: 'Actor not found' });
          return;
        }

        res.json(actor);
      } catch (error) {
        console.error('Failed to get actor:', error);
        res.status(500).json({ error: 'Failed to get actor', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/intel/actors/:id/infrastructure
   * Get actor infrastructure details
   */
  router.get(
    '/:id/infrastructure',
    requireScope('dashboard:read'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const { id } = req.params;

        const infrastructure = await actorService.getActorInfrastructure(id);

        if (!infrastructure) {
          res.status(404).json({ error: 'Actor not found' });
          return;
        }

        res.json(infrastructure);
      } catch (error) {
        console.error('Failed to get actor infrastructure:', error);
        res
          .status(500)
          .json({ error: 'Failed to get actor infrastructure', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/intel/actors/:id/timeline
   * Get actor activity timeline
   */
  router.get(
    '/:id/timeline',
    requireScope('dashboard:read'),
    validateParams(IdParamSchema),
    validateQuery(TimelineQuerySchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const { windowHours } = req.query as unknown as z.infer<typeof TimelineQuerySchema>;

        const timeline = await actorService.getActorTimeline(id, windowHours);

        if (timeline.length === 0) {
          // Check if actor exists
          const actor = await actorService.getActor(id);
          if (!actor) {
            res.status(404).json({ error: 'Actor not found' });
            return;
          }
        }

        res.json({
          actorId: id,
          windowHours,
          timeline,
        });
      } catch (error) {
        console.error('Failed to get actor timeline:', error);
        res
          .status(500)
          .json({ error: 'Failed to get actor timeline', message: getErrorMessage(error) });
      }
    }
  );

  return router;
}
