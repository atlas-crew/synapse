/**
 * User Management API Routes
 *
 * REST endpoints for managing tenant members and their roles.
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { authorize } from '../middleware/auth.js';
import { validateParams, validateBody } from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';

// =============================================================================
// Validation Schemas
// =============================================================================

const UpdateRoleSchema = z.object({
  role: z.enum(['VIEWER', 'OPERATOR', 'ADMIN', 'SUPER_ADMIN']),
});

const InviteUserSchema = z.object({
  email: z.string().email(),
  name: z.string().optional(),
  role: z.enum(['VIEWER', 'OPERATOR', 'ADMIN']).default('VIEWER'),
});

const UserIdParamSchema = z.object({
  id: z.string().cuid(),
});

// =============================================================================
// Route Factory
// =============================================================================

export function createUserRoutes(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();
  const log = logger.child({ module: 'users' });

  /**
   * GET /api/v1/users
   * List all members of the current tenant.
   *
   * Security: Requires users:manage scope.
   */
  router.get('/', authorize(prisma, { scopes: 'users:manage' }), async (req: Request, res: Response) => {
    try {
      const auth = req.auth!;
      const members = await prisma.tenantMember.findMany({
        where: { tenantId: auth.tenantId },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true,
              createdAt: true,
              updatedAt: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
      });

      res.json(members.map(m => ({
        id: m.userId,
        email: m.user.email,
        name: m.user.name,
        role: m.role,
        joinedAt: m.createdAt,
      })));
    } catch (error) {
      log.error({ error }, 'Failed to list users');
      res.status(500).json({ error: 'Failed to list users', message: getErrorMessage(error) });
    }
  });

  /**
   * POST /api/v1/users/invite
   * Invite a new user to the tenant.
   *
   * Security: Requires users:manage scope.
   */
  router.post(
    '/invite',
    authorize(prisma, { scopes: 'users:manage', role: 'admin' }),
    validateBody(InviteUserSchema),
    async (req: Request, res: Response) => {
      try {
        const { email, name, role } = req.body;
        const auth = req.auth!;

        // 1. Find or create user
        let user = await prisma.user.findUnique({ where: { email } });
        
        if (!user) {
          // In a real system, we'd send an invitation email here.
          // For the lab, we'll create a user with a placeholder password.
          user = await prisma.user.create({
            data: {
              email,
              name,
              passwordHash: 'INVITED_USER_PENDING_SETUP', // Should be handled by setup flow
            },
          });
        }

        // 2. Check if already a member
        const existingMember = await prisma.tenantMember.findUnique({
          where: { tenantId_userId: { tenantId: auth.tenantId, userId: user.id } },
        });

        if (existingMember) {
          res.status(409).json({ error: 'User is already a member of this tenant' });
          return;
        }

        // 3. Create membership
        const member = await prisma.tenantMember.create({
          data: {
            tenantId: auth.tenantId,
            userId: user.id,
            role,
          },
        });

        res.status(201).json({
          id: user.id,
          email: user.email,
          role: member.role,
          message: 'User invited successfully',
        });
      } catch (error) {
        log.error({ error }, 'Failed to invite user');
        res.status(500).json({ error: 'Failed to invite user', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * PATCH /api/v1/users/:id/role
   * Update a user's role in the current tenant.
   *
   * Security: Requires users:manage scope.
   */
  router.patch(
    '/:id/role',
    authorize(prisma, { scopes: 'users:manage', role: 'admin' }),
    validateParams(UserIdParamSchema),
    validateBody(UpdateRoleSchema),
    async (req: Request, res: Response) => {
      try {
        const { id: userId } = req.params;
        const { role } = req.body;
        const auth = req.auth!;

        // Cannot change own role (prevent accidental lockout)
        if (userId === auth.userId) {
          res.status(400).json({ error: 'Cannot update your own role' });
          return;
        }

        const member = await prisma.tenantMember.update({
          where: { tenantId_userId: { tenantId: auth.tenantId, userId } },
          data: { role },
        });

        res.json({ id: userId, role: member.role });
      } catch (error) {
        log.error({ error, userId: req.params.id }, 'Failed to update user role');
        res.status(500).json({ error: 'Failed to update role', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * DELETE /api/v1/users/:id
   * Remove a user from the current tenant.
   *
   * Security: Requires users:manage scope.
   */
  router.delete(
    '/:id',
    authorize(prisma, { scopes: 'users:manage', role: 'admin' }),
    validateParams(UserIdParamSchema),
    async (req: Request, res: Response) => {
      try {
        const { id: userId } = req.params;
        const auth = req.auth!;

        if (userId === auth.userId) {
          res.status(400).json({ error: 'Cannot remove yourself from the tenant' });
          return;
        }

        await prisma.tenantMember.delete({
          where: { tenantId_userId: { tenantId: auth.tenantId, userId } },
        });

        res.status(204).send();
      } catch (error) {
        log.error({ error, userId: req.params.id }, 'Failed to remove user');
        res.status(500).json({ error: 'Failed to remove user', message: getErrorMessage(error) });
      }
    }
  );

  return router;
}
