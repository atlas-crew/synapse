/**
 * Authentication API Routes
 *
 * Handles user login, session management, and token revocation.
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import { Prisma, type PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { config } from '../../config.js';
import { parseJwt } from '../../lib/jwt.js';
import { authorize, requireScope } from '../middleware/auth.js';
import { rateLimiters } from '../../middleware/rate-limiter.js';
import { validateBody } from '../middleware/validation.js';
import { UserAuthService } from '../../services/user-auth.js';
import { getErrorMessage } from '../../utils/errors.js';

// =============================================================================
// Validation Schemas
// =============================================================================

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const RefreshSchema = z.object({
  refreshToken: z.string().min(1),
});

const SwitchTenantSchema = z.object({
  tenantId: z.string().min(1),
});

const RevokeTokenSchema = z.object({
  jti: z.string().min(1),
  token: z.string().min(1).optional(),
  reason: z.string().optional(),
  expiresInSeconds: z.number().int().min(60).max(31536000).optional(),
}).superRefine((data, ctx) => {
  if (!data.token && !data.expiresInSeconds) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Either expiresInSeconds or token must be provided',
      path: ['expiresInSeconds'],
    });
  }
  if (data.token && data.expiresInSeconds) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'token and expiresInSeconds are mutually exclusive',
      path: ['expiresInSeconds'],
    });
  }
});

// =============================================================================
// Route Factory
// =============================================================================

export function createAuthRoutes(
  prisma: PrismaClient,
  logger: Logger,
  userAuthService: UserAuthService,
  authMiddleware: any // Using any to avoid complex type issues for now
): Router {
  const router = Router();
  const log = logger.child({ module: 'auth' });

  /**
   * POST /api/v1/auth/login
   * Authenticate user and return tokens.
   */
  router.post('/login', rateLimiters.userAuth, validateBody(LoginSchema), async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;
      const result = await userAuthService.login(email, password, {
        ip: req.ip ?? req.headers['x-forwarded-for']?.toString(),
        ua: req.headers['user-agent'],
      });

      res.json(result);
    } catch (error) {
      log.warn({ email: req.body.email, error: getErrorMessage(error) }, 'Login failed');
      res.status(401).json({ error: 'Invalid email or password' });
    }
  });

  /**
   * POST /api/v1/auth/refresh
   * Refresh access token using refresh token.
   */
  router.post('/refresh', rateLimiters.userAuth, validateBody(RefreshSchema), async (req: Request, res: Response) => {
    try {
      const { refreshToken } = req.body;
      const result = await userAuthService.refreshSession(refreshToken, {
        ip: req.ip ?? req.headers['x-forwarded-for']?.toString(),
        ua: req.headers['user-agent'],
      });

      res.json(result);
    } catch (error) {
      res.status(401).json({ error: 'Invalid or expired refresh token' });
    }
  });

  // =========================================================================
  // Protected Routes - Require Authentication
  // =========================================================================
  router.use(authMiddleware);

  /**
   * POST /api/v1/auth/logout
   * Revoke current session.
   */
  router.post('/logout', async (req: Request, res: Response) => {
    try {
      if (!req.auth?.userId) {
        res.status(401).json({ error: 'Not authenticated as user' });
        return;
      }

      await userAuthService.logout(req.auth.authId, req.auth.tenantId);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ error: 'Logout failed' });
    }
  });

  /**
   * GET /api/v1/auth/me
   * Get current authenticated user details.
   */
  router.get('/me', async (req: Request, res: Response) => {
    if (!req.auth?.userId) {
      res.status(401).json({ error: 'Not authenticated as user' });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: req.auth.userId },
      select: { id: true, email: true, name: true, createdAt: true },
    });

    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    res.json({
      ...user,
      tenantId: req.auth.tenantId,
      scopes: req.auth.scopes,
    });
  });

  /**
   * GET /api/v1/auth/tenants
   * Get all tenants the user belongs to.
   */
  router.get('/tenants', async (req: Request, res: Response) => {
    if (!req.auth?.userId) {
      res.status(401).json({ error: 'Not authenticated as user' });
      return;
    }

    const memberships = await userAuthService.getUserTenants(req.auth.userId);
    res.json(memberships.map(m => ({
      id: m.tenantId,
      name: m.tenant.name,
      shortId: m.tenant.shortId,
      role: m.role,
    })));
  });

  /**
   * POST /api/v1/auth/switch-tenant
   * Switch active tenant context.
   */
  router.post('/switch-tenant', validateBody(SwitchTenantSchema), async (req: Request, res: Response) => {
    try {
      if (!req.auth?.userId) {
        res.status(401).json({ error: 'Not authenticated as user' });
        return;
      }

      const { tenantId } = req.body;
      const result = await userAuthService.switchTenant(req.auth.userId, tenantId, {
        ip: req.ip ?? req.headers['x-forwarded-for']?.toString(),
        ua: req.headers['user-agent'],
      });

      res.json(result);
    } catch (error) {
      res.status(403).json({ error: getErrorMessage(error) });
    }
  });

  /**
   * POST /api/v1/auth/revoke (Legacy logic)
   * Revoke a token by JTI.
   */
  router.post('/revoke', authorize(prisma, { role: 'admin' }), async (req: Request, res: Response) => {
    const result = RevokeTokenSchema.safeParse(req.body);
    if (!result.success) {
      res.status(400).json({ error: 'Validation failed', details: result.error.issues });
      return;
    }

    const { jti, reason, expiresInSeconds, token } = result.data;
    const auth = req.auth!;
    let expiresAt: Date;
    let targetTenantId: string;

    if (token) {
      const secret = config.telemetry.jwtSecret;
      if (!secret) {
        res.status(503).json({ error: 'jwt_secret_missing' });
        return;
      }

      const jwtPayload = parseJwt(token, secret);
      if (!jwtPayload || !jwtPayload.exp || !jwtPayload.jti) {
        res.status(400).json({ error: 'invalid_token' });
        return;
      }

      if (jwtPayload.jti !== jti) {
        res.status(400).json({ error: 'jti_mismatch' });
        return;
      }

      targetTenantId = (jwtPayload.tenantId ?? jwtPayload.tenant_id)!;

      if (targetTenantId !== auth.tenantId && !auth.isFleetAdmin) {
        res.status(403).json({ error: 'Access denied' });
        return;
      }

      expiresAt = new Date(jwtPayload.exp * 1000);
    } else {
      targetTenantId = auth.tenantId;
      expiresAt = new Date(Date.now() + (expiresInSeconds ?? 0) * 1000);
    }

    try {
      await prisma.tokenBlacklist.create({
        data: {
          jti,
          tenantId: targetTenantId,
          reason,
          expiresAt,
        },
      });

      res.status(204).send();
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        res.status(204).send();
        return;
      }
      res.status(500).json({ error: 'Failed to revoke token' });
    }
  });

  return router;
}
