/**
 * Blocklist API Routes
 * Manage blocked indicators (IPs, fingerprints)
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { requireScope } from '../middleware/auth.js';
import { validateParams, validateQuery, validateBody, IdParamSchema } from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';

// Validation schemas - aligned with Prisma BlockType and BlockSource enums
const BlockTypeEnum = z.enum(['IP', 'IP_RANGE', 'FINGERPRINT', 'ASN', 'USER_AGENT']);
const BlockSourceEnum = z.enum(['AUTOMATIC', 'MANUAL', 'FLEET_INTEL', 'EXTERNAL_FEED', 'WAR_ROOM']);

const ListBlocklistQuerySchema = z.object({
  blockType: BlockTypeEnum.optional(),
  source: BlockSourceEnum.optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
  offset: z.coerce.number().int().min(0).default(0),
});

const CreateBlocklistBodySchema = z.object({
  blockType: BlockTypeEnum,
  indicator: z.string().min(1, 'Indicator is required').max(500),
  reason: z.string().max(1000).optional(),
  expiresAt: z.string().datetime().optional(),
  fleetWide: z.boolean().optional().default(false),
});

const CheckBlocklistQuerySchema = z.object({
  indicator: z.string().min(1, 'Indicator is required'),
  blockType: BlockTypeEnum.optional(),
});

export function createBlocklistRoutes(prisma: PrismaClient): Router {
  const router = Router();

  /**
   * GET /api/v1/blocklist
   * List blocklist entries
   */
  router.get(
    '/',
    requireScope('dashboard:read'),
    validateQuery(ListBlocklistQuerySchema),
    async (req, res) => {
      try {
        const { blockType, source, limit, offset } = req.query as unknown as z.infer<typeof ListBlocklistQuerySchema>;
        const auth = req.auth!;

        // Build where clause
        const where: Record<string, unknown> = {};

        if (!auth.isFleetAdmin) {
          // Non-fleet-admin sees fleet-wide blocks (null tenantId) + own tenant's blocks
          where.OR = [{ tenantId: null }, { tenantId: auth.tenantId }];
        }

        if (blockType) {
          where.blockType = blockType;
        }

        if (source) {
          where.source = source;
        }

        const [entries, total] = await Promise.all([
          prisma.blocklistEntry.findMany({
            where,
            take: limit,
            skip: offset,
            orderBy: { createdAt: 'desc' },
          }),
          prisma.blocklistEntry.count({ where }),
        ]);

        res.json({
          entries,
          pagination: { total, limit, offset },
        });
      } catch (error) {
        console.error('Failed to list blocklist:', error);
        res.status(500).json({ error: 'Failed to list blocklist', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * POST /api/v1/blocklist
   * Add indicator to blocklist
   */
  router.post(
    '/',
    requireScope('blocklist:write', 'fleet:admin'),
    validateBody(CreateBlocklistBodySchema),
    async (req, res) => {
      try {
        const { blockType, indicator, reason, expiresAt, fleetWide } = req.body as z.infer<
          typeof CreateBlocklistBodySchema
        >;
        const auth = req.auth!;

        // Only fleet admin can create fleet-wide blocks
        if (fleetWide && !auth.isFleetAdmin) {
          res.status(403).json({ error: 'Only fleet admins can create fleet-wide blocks' });
          return;
        }

        // Determine tenantId (null for fleet-wide)
        const tenantId = fleetWide ? null : auth.tenantId;

        // Upsert the blocklist entry
        const entry = await prisma.blocklistEntry.upsert({
          where: {
            blockType_indicator_tenantId: {
              blockType,
              indicator,
              tenantId: tenantId as string, // Prisma quirk with nullable unique
            },
          },
          create: {
            blockType,
            indicator,
            tenantId,
            source: 'MANUAL',
            reason: reason ?? 'Manually added',
            expiresAt: expiresAt ? new Date(expiresAt) : undefined,
            propagationStatus: 'PENDING',
          },
          update: {
            reason: reason ?? 'Manually updated',
            expiresAt: expiresAt ? new Date(expiresAt) : undefined,
            propagationStatus: 'PENDING',
          },
        });

        res.status(201).json(entry);
      } catch (error) {
        console.error('Failed to add blocklist entry:', error);
        res.status(500).json({ error: 'Failed to add blocklist entry', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * DELETE /api/v1/blocklist/:id
   * Remove indicator from blocklist
   */
  router.delete(
    '/:id',
    requireScope('blocklist:write', 'fleet:admin'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const auth = req.auth!;

        // Find the entry first
        const entry = await prisma.blocklistEntry.findUnique({ where: { id } });

        if (entry === undefined || entry === null) {
          res.status(404).json({ error: 'Blocklist entry not found' });
          return;
        }

        // Only fleet admin can delete fleet-wide blocks
        if (entry.tenantId === null && !auth.isFleetAdmin) {
          res.status(403).json({ error: 'Only fleet admins can delete fleet-wide blocks' });
          return;
        }

        // Only allow deleting own tenant's blocks (unless fleet admin)
        if (entry.tenantId !== null && entry.tenantId !== auth.tenantId && !auth.isFleetAdmin) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }

        await prisma.blocklistEntry.delete({ where: { id } });

        res.status(204).send();
      } catch (error) {
        console.error('Failed to delete blocklist entry:', error);
        res.status(500).json({ error: 'Failed to delete blocklist entry', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/blocklist/check
   * Check if an indicator is blocked
   */
  router.get(
    '/check',
    requireScope('dashboard:read', 'signal:write'),
    validateQuery(CheckBlocklistQuerySchema),
    async (req, res) => {
      try {
        const { indicator, blockType } = req.query as unknown as z.infer<typeof CheckBlocklistQuerySchema>;
        const auth = req.auth!;

        // Build where clause
        const where: Record<string, unknown> = {
          indicator,
          OR: [
            { tenantId: null }, // Fleet-wide blocks always apply
            { tenantId: auth.tenantId },
          ],
        };

        if (blockType) {
          where.blockType = blockType;
        }

        const entry = await prisma.blocklistEntry.findFirst({
          where,
          orderBy: { createdAt: 'desc' },
        });

        res.json({
          blocked: entry !== null,
          entry: entry ?? undefined,
        });
      } catch (error) {
        console.error('Failed to check blocklist:', error);
        res.status(500).json({ error: 'Failed to check blocklist', message: getErrorMessage(error) });
      }
    }
  );

  return router;
}
