/**
 * War Room API Routes
 * Real-time collaboration endpoints for incident response
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { requireScope } from '../middleware/auth.js';
import { validateParams, validateQuery, validateBody, IdParamSchema } from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';
import { WarRoomService, type WarRoomConfig } from '../../services/warroom/index.js';

// Validation schemas
const ListWarRoomsQuerySchema = z.object({
  status: z.enum(['ACTIVE', 'PAUSED', 'CLOSED', 'ARCHIVED']).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

const CreateWarRoomBodySchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(2000).optional(),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  campaignIds: z.array(z.string()).optional(),
});

const UpdateWarRoomBodySchema = z.object({
  status: z.enum(['ACTIVE', 'PAUSED', 'CLOSED', 'ARCHIVED']).optional(),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
});

const AddMessageBodySchema = z.object({
  message: z.string().min(1).max(5000),
});

const CreateBlockBodySchema = z.object({
  blockType: z.enum(['IP', 'IP_RANGE', 'FINGERPRINT', 'ASN', 'USER_AGENT']),
  indicator: z.string().min(1),
  reason: z.string().max(500).optional(),
  expiresAt: z.coerce.date().optional(),
});

const RemoveBlockBodySchema = z.object({
  blockType: z.enum(['IP', 'IP_RANGE', 'FINGERPRINT', 'ASN', 'USER_AGENT']),
  indicator: z.string().min(1),
});

const LinkCampaignsBodySchema = z.object({
  campaignIds: z.array(z.string()).min(1),
});

const ActivitiesQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().optional(),
});

// Default config
const DEFAULT_CONFIG: WarRoomConfig = {
  autoCreateForCrossTenant: true,
  autoCreateForCritical: true,
  maxActivityLimit: 200,
};

export function createWarRoomRoutes(prisma: PrismaClient, logger: import('pino').Logger): Router {
  const router = Router();
  const warRoomService = new WarRoomService(prisma, logger, DEFAULT_CONFIG);

  /**
   * GET /api/v1/warrooms
   * List war rooms for tenant
   */
  router.get(
    '/',
    requireScope('dashboard:read'),
    validateQuery(ListWarRoomsQuerySchema),
    async (req, res) => {
      try {
        const { status, limit, offset } = req.query as unknown as z.infer<typeof ListWarRoomsQuerySchema>;
        const auth = req.auth!;

        const where: Record<string, unknown> = { tenantId: auth.tenantId };
        if (status) where.status = status;

        const [warRooms, total] = await Promise.all([
          prisma.warRoom.findMany({
            where,
            take: limit,
            skip: offset,
            orderBy: [{ priority: 'desc' }, { createdAt: 'desc' }],
            include: {
              _count: { select: { activities: true, campaignLinks: true } },
            },
          }),
          prisma.warRoom.count({ where }),
        ]);

        res.json({
          warRooms,
          pagination: { total, limit, offset },
        });
      } catch (error) {
        console.error('Failed to list war rooms:', error);
        res.status(500).json({ error: 'Failed to list war rooms', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * POST /api/v1/warrooms
   * Create a new war room
   */
  router.post(
    '/',
    requireScope('dashboard:write'),
    validateBody(CreateWarRoomBodySchema),
    async (req, res) => {
      try {
        const body = req.body as z.infer<typeof CreateWarRoomBodySchema>;
        const auth = req.auth!;

        const warRoom = await warRoomService.createWarRoom({
          tenantId: auth.tenantId,
          name: body.name,
          description: body.description,
          priority: body.priority,
          leaderId: auth.userId,
          campaignIds: body.campaignIds,
        });

        res.status(201).json(warRoom);
      } catch (error) {
        console.error('Failed to create war room:', error);
        res.status(500).json({ error: 'Failed to create war room', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/warrooms/:id
   * Get war room details with recent activities
   */
  router.get(
    '/:id',
    requireScope('dashboard:read'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const auth = req.auth!;

        const warRoom = await warRoomService.getWarRoom(id);

        if (!warRoom) {
          res.status(404).json({ error: 'War room not found' });
          return;
        }

        // Check access
        if (warRoom.tenantId !== auth.tenantId && !auth.isFleetAdmin) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }

        res.json(warRoom);
      } catch (error) {
        console.error('Failed to get war room:', error);
        res.status(500).json({ error: 'Failed to get war room', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * PATCH /api/v1/warrooms/:id
   * Update war room status or priority
   */
  router.patch(
    '/:id',
    requireScope('dashboard:write'),
    validateParams(IdParamSchema),
    validateBody(UpdateWarRoomBodySchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const body = req.body as z.infer<typeof UpdateWarRoomBodySchema>;
        const auth = req.auth!;

        // Verify access
        const existing = await prisma.warRoom.findUnique({ where: { id } });
        if (!existing) {
          res.status(404).json({ error: 'War room not found' });
          return;
        }
        if (existing.tenantId !== auth.tenantId && !auth.isFleetAdmin) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }

        let warRoom = existing;

        if (body.status) {
          warRoom = await warRoomService.updateStatus(id, body.status, auth.userId ?? 'unknown', auth.userName ?? 'Unknown');
        }

        if (body.priority) {
          warRoom = await warRoomService.updatePriority(id, body.priority, auth.userId ?? 'unknown', auth.userName ?? 'Unknown');
        }

        res.json(warRoom);
      } catch (error) {
        console.error('Failed to update war room:', error);
        res.status(500).json({ error: 'Failed to update war room', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/warrooms/:id/activities
   * Get paginated activities for a war room
   */
  router.get(
    '/:id/activities',
    requireScope('dashboard:read'),
    validateParams(IdParamSchema),
    validateQuery(ActivitiesQuerySchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const { limit, cursor } = req.query as unknown as z.infer<typeof ActivitiesQuerySchema>;
        const auth = req.auth!;

        // Verify access
        const warRoom = await prisma.warRoom.findUnique({ where: { id } });
        if (!warRoom) {
          res.status(404).json({ error: 'War room not found' });
          return;
        }
        if (warRoom.tenantId !== auth.tenantId && !auth.isFleetAdmin) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }

        const result = await warRoomService.getActivities(id, limit, cursor);
        res.json(result);
      } catch (error) {
        console.error('Failed to get activities:', error);
        res.status(500).json({ error: 'Failed to get activities', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * POST /api/v1/warrooms/:id/messages
   * Add a message to the war room
   */
  router.post(
    '/:id/messages',
    requireScope('dashboard:write'),
    validateParams(IdParamSchema),
    validateBody(AddMessageBodySchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const { message } = req.body as z.infer<typeof AddMessageBodySchema>;
        const auth = req.auth!;

        // Verify access
        const warRoom = await prisma.warRoom.findUnique({ where: { id } });
        if (!warRoom) {
          res.status(404).json({ error: 'War room not found' });
          return;
        }
        if (warRoom.tenantId !== auth.tenantId && !auth.isFleetAdmin) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }

        const activity = await warRoomService.addMessage(
          id,
          auth.tenantId,
          auth.userId ?? 'unknown',
          auth.userName ?? 'Unknown',
          message
        );

        res.status(201).json(activity);
      } catch (error) {
        console.error('Failed to add message:', error);
        res.status(500).json({ error: 'Failed to add message', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * POST /api/v1/warrooms/:id/blocks
   * Create a block from the war room (quick action)
   */
  router.post(
    '/:id/blocks',
    requireScope('dashboard:write'),
    validateParams(IdParamSchema),
    validateBody(CreateBlockBodySchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const body = req.body as z.infer<typeof CreateBlockBodySchema>;
        const auth = req.auth!;

        // Verify access
        const warRoom = await prisma.warRoom.findUnique({ where: { id } });
        if (!warRoom) {
          res.status(404).json({ error: 'War room not found' });
          return;
        }
        if (warRoom.tenantId !== auth.tenantId && !auth.isFleetAdmin) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }

        await warRoomService.createBlock(
          id,
          auth.tenantId,
          {
            type: 'add',
            blockType: body.blockType,
            indicator: body.indicator,
            reason: body.reason,
            expiresAt: body.expiresAt,
            source: 'WAR_ROOM',
          },
          auth.userId ?? 'unknown',
          auth.userName ?? 'Unknown'
        );

        res.status(201).json({ success: true });
      } catch (error) {
        console.error('Failed to create block:', error);
        res.status(500).json({ error: 'Failed to create block', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * DELETE /api/v1/warrooms/:id/blocks
   * Remove a block from the war room (quick action)
   */
  router.delete(
    '/:id/blocks',
    requireScope('dashboard:write'),
    validateParams(IdParamSchema),
    validateBody(RemoveBlockBodySchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const body = req.body as z.infer<typeof RemoveBlockBodySchema>;
        const auth = req.auth!;

        // Verify access
        const warRoom = await prisma.warRoom.findUnique({ where: { id } });
        if (!warRoom) {
          res.status(404).json({ error: 'War room not found' });
          return;
        }
        if (warRoom.tenantId !== auth.tenantId && !auth.isFleetAdmin) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }

        await warRoomService.removeBlock(
          id,
          auth.tenantId,
          body.blockType,
          body.indicator,
          auth.userId ?? 'unknown',
          auth.userName ?? 'Unknown'
        );

        res.json({ success: true });
      } catch (error) {
        console.error('Failed to remove block:', error);
        res.status(500).json({ error: 'Failed to remove block', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * POST /api/v1/warrooms/:id/campaigns
   * Link campaigns to the war room
   */
  router.post(
    '/:id/campaigns',
    requireScope('dashboard:write'),
    validateParams(IdParamSchema),
    validateBody(LinkCampaignsBodySchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const { campaignIds } = req.body as z.infer<typeof LinkCampaignsBodySchema>;
        const auth = req.auth!;

        // Verify access
        const warRoom = await prisma.warRoom.findUnique({ where: { id } });
        if (!warRoom) {
          res.status(404).json({ error: 'War room not found' });
          return;
        }
        if (warRoom.tenantId !== auth.tenantId && !auth.isFleetAdmin) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }

        await warRoomService.linkCampaigns(id, auth.tenantId, campaignIds, auth.userId ?? 'unknown');

        res.status(201).json({ success: true });
      } catch (error) {
        console.error('Failed to link campaigns:', error);
        res.status(500).json({ error: 'Failed to link campaigns', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/warrooms/:id/campaigns
   * Get linked campaigns for a war room
   */
  router.get(
    '/:id/campaigns',
    requireScope('dashboard:read'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const auth = req.auth!;

        // Verify access
        const warRoom = await prisma.warRoom.findUnique({ where: { id } });
        if (!warRoom) {
          res.status(404).json({ error: 'War room not found' });
          return;
        }
        if (warRoom.tenantId !== auth.tenantId && !auth.isFleetAdmin) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }

        const campaigns = await warRoomService.getLinkedCampaigns(id);
        res.json({ campaigns });
      } catch (error) {
        console.error('Failed to get linked campaigns:', error);
        res.status(500).json({ error: 'Failed to get linked campaigns', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/warrooms/stats
   * Get war room statistics for tenant
   */
  router.get(
    '/stats',
    requireScope('dashboard:read'),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const stats = await warRoomService.getStats(auth.tenantId);
        res.json(stats);
      } catch (error) {
        console.error('Failed to get war room stats:', error);
        res.status(500).json({ error: 'Failed to get war room stats', message: getErrorMessage(error) });
      }
    }
  );

  return router;
}
