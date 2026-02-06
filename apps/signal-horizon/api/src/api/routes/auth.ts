/**
 * Authentication API Routes
 *
 * Handles user login, session management, and token revocation.
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
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
// WebSocket Ticket Store (labs-n6nf)
// Short-lived, one-time-use tickets for authenticating WebSocket connections.
// Stored in-memory; automatically expired after WS_TICKET_TTL_MS.
// =============================================================================

const WS_TICKET_TTL_MS = 30_000; // 30 seconds

interface WsTicket {
  token: string;
  userId: string;
  tenantId: string;
  scopes: string[];
  expiresAt: number;
}

const wsTicketStore = new Map<string, WsTicket>();

// Periodic cleanup every 60s to remove expired tickets
setInterval(() => {
  const now = Date.now();
  for (const [key, ticket] of wsTicketStore) {
    if (ticket.expiresAt <= now) {
      wsTicketStore.delete(key);
    }
  }
}, 60_000).unref();

/**
 * Validate and consume a WebSocket ticket (one-time use).
 * Returns the ticket payload if valid, null otherwise.
 */
export function consumeWsTicket(token: string): Omit<WsTicket, 'token' | 'expiresAt'> | null {
  const ticket = wsTicketStore.get(token);
  if (!ticket) return null;

  // Always delete (one-time use)
  wsTicketStore.delete(token);

  // Check expiry
  if (Date.now() > ticket.expiresAt) return null;

  return {
    userId: ticket.userId,
    tenantId: ticket.tenantId,
    scopes: ticket.scopes,
  };
}

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
   * Sets accessToken as httpOnly cookie; returns refreshToken in body (labs-n6nf).
   */
  router.post('/login', rateLimiters.userAuth, validateBody(LoginSchema), async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;
      const result = await userAuthService.login(email, password, {
        ip: req.ip ?? req.headers['x-forwarded-for']?.toString(),
        ua: req.headers['user-agent'],
      });

      // Set access token as httpOnly cookie (labs-n6nf)
      res.cookie('access_token', result.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
        maxAge: (config.telemetry.jwtExpirationSeconds || 3600) * 1000,
      });

      // Return everything except the accessToken in the body.
      // Clients should rely on the cookie for session auth.
      const { accessToken: _at, ...body } = result;
      res.json(body);
    } catch (error) {
      log.warn({ email: req.body.email, error: getErrorMessage(error) }, 'Login failed');
      res.status(401).json({ error: 'Invalid email or password' });
    }
  });

  /**
   * POST /api/v1/auth/refresh
   * Refresh access token using refresh token.
   * Sets new accessToken as httpOnly cookie; returns new refreshToken in body (labs-n6nf).
   */
  router.post('/refresh', rateLimiters.userAuth, validateBody(RefreshSchema), async (req: Request, res: Response) => {
    try {
      const { refreshToken } = req.body;
      const result = await userAuthService.refreshSession(refreshToken, {
        ip: req.ip ?? req.headers['x-forwarded-for']?.toString(),
        ua: req.headers['user-agent'],
      });

      // Set access token as httpOnly cookie (labs-n6nf)
      res.cookie('access_token', result.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
        maxAge: (config.telemetry.jwtExpirationSeconds || 3600) * 1000,
      });

      // Return only the refresh token in the body
      res.json({ refreshToken: result.refreshToken });
    } catch (error) {
      res.status(401).json({ error: 'Invalid or expired refresh token' });
    }
  });

  // =========================================================================
  // Protected Routes - Require Authentication
  // =========================================================================
  router.use(authMiddleware);

  /**
   * GET /api/v1/auth/ws-ticket
   * Issue a short-lived, one-time-use ticket for authenticating WebSocket connections (labs-n6nf).
   *
   * Because httpOnly cookies cannot be sent during WebSocket handshake,
   * the UI first fetches a ticket (cookie-authenticated) and then passes
   * it as a query parameter on the WS URL. The WS server consumes and
   * immediately invalidates the ticket.
   */
  router.get('/ws-ticket', async (req: Request, res: Response) => {
    if (!req.auth) {
      res.status(401).json({ error: 'Not authenticated' });
      return;
    }

    const token = randomUUID();

    wsTicketStore.set(token, {
      token,
      userId: req.auth.userId ?? req.auth.authId,
      tenantId: req.auth.tenantId,
      scopes: req.auth.scopes,
      expiresAt: Date.now() + WS_TICKET_TTL_MS,
    });

    res.json({ ticket: token, expiresIn: WS_TICKET_TTL_MS });
  });

  /**
   * POST /api/v1/auth/logout
   * Revoke current session and clear httpOnly cookie (labs-n6nf).
   */
  router.post('/logout', async (req: Request, res: Response) => {
    try {
      if (!req.auth?.userId) {
        res.status(401).json({ error: 'Not authenticated as user' });
        return;
      }

      await userAuthService.logout(req.auth.authId, req.auth.tenantId);

      // Clear httpOnly access token cookie (labs-n6nf)
      res.clearCookie('access_token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
      });

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
   * Sets new accessToken as httpOnly cookie (labs-n6nf).
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

      // Set access token as httpOnly cookie (labs-n6nf)
      res.cookie('access_token', result.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/',
        maxAge: (config.telemetry.jwtExpirationSeconds || 3600) * 1000,
      });

      // Return only refresh token in body
      res.json({ refreshToken: result.refreshToken });
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
