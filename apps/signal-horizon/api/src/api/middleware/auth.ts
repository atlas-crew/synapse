/**
 * API Authentication Middleware
 * Validates API keys and extracts tenant context
 *
 * Security: Includes rate limiting for failed auth attempts (ADMIN-01)
 */

import type { Request, Response, NextFunction } from 'express';
import type { PrismaClient } from '@prisma/client';
import { createHash } from 'node:crypto';
import { config } from '../../config.js';
import { sendProblem } from '../../lib/problem-details.js';
import { verifyAndDecodeToken, type JwtPayload } from '../../lib/jwt.js';
import { getEpochForTenant, EpochLookupError } from '../../lib/epoch.js';
import type { RedisKv } from '../../storage/redis/kv.js';
import {
  checkAuthLockout,
  recordFailedAuth,
  clearFailedAuth,
  getClientIpForAuth,
} from '../../middleware/rate-limiter.js';
import { hasScope } from './scopes.js';

export interface AuthContext {
  tenantId: string;
  /** API Key ID or User Session JTI */
  authId: string;
  /** @deprecated use authId */
  apiKeyId: string;
  scopes: string[];
  isFleetAdmin: boolean;
  /** User ID if authenticated via user session (optional for API keys) */
  userId?: string;
  /** User display name (optional) */
  userName?: string;
}

// Extend Express Request with auth context
declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

export function createAuthMiddleware(prisma: PrismaClient, kv?: RedisKv | null) {
  return async function authMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    const clientIp = getClientIpForAuth(req);

    // ADMIN-01: Check for auth lockout before processing
    const lockoutCheck = checkAuthLockout(clientIp);
    if (lockoutCheck.locked) {
      res.setHeader('Retry-After', lockoutCheck.retryAfterSeconds.toString());
      sendProblem(res, 429, 'Too many authentication attempts', {
        code: 'AUTH_RATE_LIMITED',
        instance: req.originalUrl,
        retryAfterSeconds: lockoutCheck.retryAfterSeconds,
      });
      return;
    }

    const authHeader = req.headers.authorization;

    // labs-n6nf: Extract token from Authorization header (Bearer) or httpOnly cookie fallback.
    // API keys and programmatic clients use the Authorization header.
    // Browser sessions use the httpOnly access_token cookie set on login/refresh.
    let token: string | undefined;

    if (authHeader?.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } else if (req.cookies?.access_token) {
      token = req.cookies.access_token;
    } else if (req.cookies?.horizon_api_key) {
      token = req.cookies.horizon_api_key;
    } else if (req.cookies?.api_key) {
      token = req.cookies.api_key;
    }

    if (!token) {
      recordFailedAuth(clientIp);
      sendProblem(res, 401, 'Authorization required', {
        code: 'AUTH_REQUIRED',
        instance: req.originalUrl,
      });
      return;
    }

    try {
      const jwtSecret = config.telemetry.jwtSecret;
      const jwtResult = jwtSecret
        ? await verifyAndDecodeToken(token, jwtSecret, prisma, { audience: 'signal-horizon', source: 'api' })
        : null;

      if (jwtResult?.ok) {
        const jwtPayload: JwtPayload = jwtResult.payload;
        const tenantId = jwtResult.tenantId;

        // Epoch-based bulk revocation check (labs-wqy1)
        // If Redis is available and the JWT carries an epoch claim, verify it
        // against the current tenant epoch. Fail-closed (503) when Redis is
        // unavailable to prevent bypassing revocation.
        if (kv && typeof jwtPayload.epoch === 'number') {
          try {
            const currentEpoch = await getEpochForTenant(tenantId, kv);
            if (jwtPayload.epoch < currentEpoch) {
              recordFailedAuth(clientIp);
              sendProblem(res, 401, 'Token epoch has expired — all sessions were revoked', {
                code: 'TOKEN_EPOCH_EXPIRED',
                instance: req.originalUrl,
              });
              return;
            }
          } catch (error) {
            // labs-2rf9.11: Handle all errors within the epoch check to prevent 
            // unexpected bubbles and ensure consistent failure responses.
            if (error instanceof EpochLookupError) {
              console.error('Epoch lookup failed, denying request:', error);
              sendProblem(res, 503, 'Authentication service temporarily unavailable', {
                code: 'EPOCH_SERVICE_UNAVAILABLE',
                instance: req.originalUrl,
              });
            } else {
              console.error('Unexpected error during epoch check:', error);
              sendProblem(res, 500, 'Authentication check failed', {
                code: 'AUTH_CHECK_ERROR',
                instance: req.originalUrl,
              });
            }
            return;
          }
        }

        const scopes = 'scopes' in jwtPayload && Array.isArray(jwtPayload.scopes) ? jwtPayload.scopes : [];
        const userId = 'userId' in jwtPayload ? jwtPayload.userId : jwtPayload.user_id;

        clearFailedAuth(clientIp);

        req.auth = {
          tenantId,
          authId: jwtResult.jti,
          apiKeyId: jwtResult.jti, // Backward compatibility
          scopes,
          isFleetAdmin: scopes.includes('fleet:admin') || scopes.includes('*'),
          userId,
        };

        next();
        return;
      }

      if (jwtResult && !jwtResult.ok && jwtResult.error === 'invalid_payload') {
        recordFailedAuth(clientIp);
        sendProblem(res, 401, 'Invalid token payload', {
          code: 'INVALID_TOKEN',
          instance: req.originalUrl,
        });
        return;
      }

      if (jwtResult && !jwtResult.ok && jwtResult.error === 'revoked') {
        recordFailedAuth(clientIp);
        sendProblem(res, 401, 'Token has been revoked', {
          code: 'TOKEN_REVOKED',
          instance: req.originalUrl,
        });
        return;
      }

      // Hash the API key for lookup
      const keyHash = createHash('sha256').update(token).digest('hex');

      const apiKeyRecord = await prisma.apiKey.findUnique({
        where: { keyHash },
        include: { tenant: true },
      });

      if (!apiKeyRecord) {
        recordFailedAuth(clientIp);
        sendProblem(res, 401, 'Invalid API key', {
          code: 'INVALID_API_KEY',
          instance: req.originalUrl,
        });
        return;
      }

      if (apiKeyRecord.isRevoked) {
        recordFailedAuth(clientIp);
        sendProblem(res, 401, 'API key has been revoked', {
          code: 'API_KEY_REVOKED',
          instance: req.originalUrl,
        });
        return;
      }

      if (apiKeyRecord.expiresAt && apiKeyRecord.expiresAt < new Date()) {
        recordFailedAuth(clientIp);
        sendProblem(res, 401, 'API key has expired', {
          code: 'API_KEY_EXPIRED',
          instance: req.originalUrl,
        });
        return;
      }

      // Validate tenant association exists (defensive check)
      if (!apiKeyRecord.tenant) {
        console.error(`API key ${apiKeyRecord.id} has invalid tenant association`);
        sendProblem(res, 401, 'Invalid API key configuration', {
          code: 'INVALID_TENANT_ASSOCIATION',
          instance: req.originalUrl,
        });
        return;
      }

      // Successful authentication - clear any failed attempt tracking
      clearFailedAuth(clientIp);

      // Update last used timestamp (fire and forget)
      prisma.apiKey.update({
        where: { id: apiKeyRecord.id },
        data: { lastUsedAt: new Date() },
      }).catch(() => {
        // Ignore update errors - don't block the request
      });

      // Set auth context on request
      req.auth = {
        tenantId: apiKeyRecord.tenantId,
        authId: apiKeyRecord.id,
        apiKeyId: apiKeyRecord.id, // Backward compatibility
        scopes: apiKeyRecord.scopes,
        isFleetAdmin: apiKeyRecord.scopes.includes('fleet:admin') || apiKeyRecord.scopes.includes('*'),
      };

      next();
    } catch (error) {
      console.error('Auth middleware error:', error);
      sendProblem(res, 500, 'Authentication error', {
        code: 'AUTH_ERROR',
        instance: req.originalUrl,
      });
    }
  };
}

/**
 * Require specific scope(s) for a route.
 *
 * Checks both direct scope matches AND alias expansions. For example,
 * an API key with 'dashboard:read' will satisfy 'analytics:read'.
 *
 * @param requiredScopes - One or more scopes; user needs at least ONE
 */
export function requireScope(...requiredScopes: string[]) {
  return function scopeMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    if (!req.auth) {
      sendProblem(res, 401, 'Not authenticated', {
        code: 'AUTH_REQUIRED',
        instance: req.originalUrl,
      });
      return;
    }

    // Check if any required scope is satisfied (directly or via aliases)
    const hasScopeMatch = requiredScopes.some((scope) =>
      hasScope(req.auth!.scopes, scope)
    );

    if (!hasScopeMatch) {
      sendProblem(res, 403, 'Insufficient permissions', {
        code: 'INSUFFICIENT_SCOPE',
        instance: req.originalUrl,
        details: {
          required: requiredScopes,
          granted: req.auth.scopes,
        },
      });
      return;
    }

    next();
  };
}

/**
 * Validate that the requested resource belongs to the authenticated tenant. (labs-bp7t)
 * 
 * Returns 404 if the resource is not found or belongs to another tenant to prevent
 * information disclosure via timing side-channels or existence enumeration.
 * 
 * @param prisma - Prisma client instance
 * @param resource - The type of resource to check
 * @param paramName - The name of the request parameter containing the resource ID
 */
export function requireTenant(
  prisma: PrismaClient,
  resource: 'sensor' | 'policy' | 'template' | 'command',
  paramName: string
) {
  return async function tenantMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    const tenantId = req.auth?.tenantId;
    const isFleetAdmin = req.auth?.isFleetAdmin || false;
    const resourceId = req.params[paramName];

    if (!tenantId) {
      sendProblem(res, 401, 'Authentication required', { code: 'AUTH_REQUIRED' });
      return;
    }

    // labs-cbyq: Fleet admins bypass isolation checks
    if (isFleetAdmin) {
      return next();
    }

    if (!resourceId) {
      return next();
    }

    try {
      let ownerId: string | null = null;

      switch (resource) {
        case 'sensor': {
          const s = await prisma.sensor.findUnique({
            where: { id: resourceId },
            select: { tenantId: true },
          });
          ownerId = s?.tenantId || null;
          break;
        }
        case 'policy': {
          const p = await prisma.policyTemplate.findUnique({
            where: { id: resourceId },
            select: { tenantId: true },
          });
          ownerId = p?.tenantId || null;
          break;
        }
        case 'template': {
          const t = await prisma.configTemplate.findUnique({
            where: { id: resourceId },
            select: { tenantId: true },
          });
          ownerId = t?.tenantId || null;
          break;
        }
        case 'command': {
          const c = await prisma.fleetCommand.findUnique({
            where: { id: resourceId },
            include: { sensor: { select: { tenantId: true } } },
          });
          ownerId = c?.sensor?.tenantId || null;
          break;
        }
      }

      if (ownerId && ownerId !== tenantId) {
        // labs-cbyq & labs-kcts: Return generic 403 for both not found and forbidden 
        // to prevent tenant enumeration and information disclosure.
        sendProblem(res, 403, 'Access denied', {
          code: 'ACCESS_DENIED',
          instance: req.originalUrl,
        });
        return;
      }

      if (!ownerId) {
        // labs-cbyq: Return 403 even if resource doesn't exist to prevent enumeration
        sendProblem(res, 403, 'Access denied', {
          code: 'ACCESS_DENIED',
          instance: req.originalUrl,
        });
        return;
      }

      next();
    } catch (error) {
      console.error(`Tenant validation error for ${resource}:`, error);
      sendProblem(res, 500, 'Internal server error during tenant validation', {
        code: 'TENANT_VALIDATION_ERROR',
        instance: req.originalUrl,
      });
    }
  };
}

/**
 * Composite authorization middleware (labs-cwgv)
 *
 * Combines scope checks, role requirements, and tenant isolation into a single call.
 * This is the canonical pattern for protecting routes.
 *
 * @example
 * // Pattern A: Scope only
 * authorize(prisma, { scopes: 'sensor:read' })
 *
 * // Pattern B: Role + Scope
 * authorize(prisma, { scopes: 'config:write', role: 'operator' })
 *
 * // Pattern C: With Tenant Isolation
 * authorize(prisma, {
 *   scopes: 'sensor:read',
 *   tenant: { resource: 'sensor', param: 'sensorId' }
 * })
 */
export function authorize(
  prisma: PrismaClient,
  options: {
    scopes?: string | string[];
    role?: Role;
    tenant?: {
      resource: 'sensor' | 'policy' | 'template' | 'command';
      param: string;
    };
  }
) {
  return async function combinedMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    // 1. Basic Auth Check
    if (!req.auth) {
      sendProblem(res, 401, 'Not authenticated', {
        code: 'AUTH_REQUIRED',
        instance: req.originalUrl,
      });
      return;
    }

    // 2. Scope Check (at least one must match)
    if (options.scopes) {
      const required = Array.isArray(options.scopes) ? options.scopes : [options.scopes];
      const hasScopeMatch = required.some((s) => hasScope(req.auth!.scopes, s));

      if (!hasScopeMatch) {
        sendProblem(res, 403, 'Insufficient permissions', {
          code: 'INSUFFICIENT_SCOPE',
          instance: req.originalUrl,
          details: {
            required,
            granted: req.auth.scopes,
          },
        });
        return;
      }
    }

    // 3. Role Check
    if (options.role) {
      const userRole = deriveRole(req.auth.scopes);
      const userLevel = ROLE_HIERARCHY[userRole];
      const requiredLevel = ROLE_HIERARCHY[options.role];

      if (userLevel < requiredLevel) {
        sendProblem(res, 403, `Requires ${options.role} role`, {
          code: 'INSUFFICIENT_ROLE',
          instance: req.originalUrl,
          details: {
            currentRole: userRole,
            requiredRole: options.role,
          },
        });
        return;
      }
    }

    // 4. Tenant Check (Isolation)
    if (options.tenant) {
      const tenantId = req.auth.tenantId;
      const isFleetAdmin = req.auth.isFleetAdmin;
      const resourceId = req.params[options.tenant.param];

      // Fleet admins bypass isolation checks
      if (!isFleetAdmin && resourceId) {
        try {
          let ownerId: string | null = null;

          switch (options.tenant.resource) {
            case 'sensor': {
              const s = await prisma.sensor.findUnique({
                where: { id: resourceId },
                select: { tenantId: true },
              });
              ownerId = s?.tenantId || null;
              break;
            }
            case 'policy': {
              const p = await prisma.policyTemplate.findUnique({
                where: { id: resourceId },
                select: { tenantId: true },
              });
              ownerId = p?.tenantId || null;
              break;
            }
            case 'template': {
              const t = await prisma.configTemplate.findUnique({
                where: { id: resourceId },
                select: { tenantId: true },
              });
              ownerId = t?.tenantId || null;
              break;
            }
            case 'command': {
              const c = await prisma.fleetCommand.findUnique({
                where: { id: resourceId },
                include: { sensor: { select: { tenantId: true } } },
              });
              ownerId = c?.sensor?.tenantId || null;
              break;
            }
          }

          if (!ownerId || ownerId !== tenantId) {
            sendProblem(res, 403, 'Access denied', {
              code: 'ACCESS_DENIED',
              instance: req.originalUrl,
            });
            return;
          }
        } catch (error) {
          console.error(`Tenant validation error for ${options.tenant.resource}:`, error);
          sendProblem(res, 500, 'Internal server error during tenant validation', {
            code: 'TENANT_VALIDATION_ERROR',
            instance: req.originalUrl,
          });
          return;
        }
      }
    }

    next();
  };
}

/**
 * Role definitions with scope mappings (WS2-009)
 *
 * Role hierarchy: viewer < operator < admin
 * Each role includes all permissions of lower roles.
 */
export type Role = 'viewer' | 'operator' | 'admin';

const ROLE_HIERARCHY: Record<Role, number> = {
  viewer: 0,
  operator: 1,
  admin: 2,
};

/**
 * Map scopes to effective role
 * Admin: fleet:admin or *:admin scope
 * Operator: fleet:write, config:write, command:execute
 * Viewer: any valid authentication (default)
 */
function deriveRole(scopes: string[]): Role {
  // Check for admin
  if (scopes.some((s) => s === 'fleet:admin' || s.endsWith(':admin'))) {
    return 'admin';
  }

  // Check for operator
  const operatorScopes = ['fleet:write', 'config:write', 'command:execute', 'rules:write'];
  if (scopes.some((s) => operatorScopes.includes(s))) {
    return 'operator';
  }

  // Default to viewer
  return 'viewer';
}

/**
 * Require a minimum role level for a route (WS2-009)
 *
 * Role hierarchy:
 * - viewer: Can read data
 * - operator: Can modify operational settings (config, commands)
 * - admin: Full access including security-sensitive operations
 *
 * @example
 * router.get('/sensors', requireRole('viewer'), listSensors);
 * router.post('/commands', requireRole('operator'), sendCommand);
 * router.delete('/templates/:id', requireRole('admin'), deleteTemplate);
 */
export function requireRole(minRole: Role) {
  return function roleMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    if (!req.auth) {
      sendProblem(res, 401, 'Not authenticated', {
        code: 'AUTH_REQUIRED',
        instance: req.originalUrl,
      });
      return;
    }

    const userRole = deriveRole(req.auth.scopes);
    const userLevel = ROLE_HIERARCHY[userRole];
    const requiredLevel = ROLE_HIERARCHY[minRole];

    if (userLevel < requiredLevel) {
      sendProblem(res, 403, `Requires ${minRole} role`, {
        code: 'INSUFFICIENT_ROLE',
        instance: req.originalUrl,
        details: {
          currentRole: userRole,
          requiredRole: minRole,
        },
      });
      return;
    }

    next();
  };
}
