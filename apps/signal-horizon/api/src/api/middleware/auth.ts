/**
 * API Authentication Middleware
 * Validates API keys and extracts tenant context
 */

import type { Request, Response, NextFunction } from 'express';
import type { PrismaClient } from '@prisma/client';
import { createHash } from 'node:crypto';

export interface AuthContext {
  tenantId: string;
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

export function createAuthMiddleware(prisma: PrismaClient) {
  return async function authMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      res.status(401).json({ error: 'Authorization header required' });
      return;
    }

    const [scheme, token] = authHeader.split(' ');

    if (scheme !== 'Bearer' || !token) {
      res.status(401).json({ error: 'Invalid authorization format. Use: Bearer <api-key>' });
      return;
    }

    try {
      // Hash the API key for lookup
      const keyHash = createHash('sha256').update(token).digest('hex');

      const apiKeyRecord = await prisma.apiKey.findUnique({
        where: { keyHash },
        include: { tenant: true },
      });

      if (!apiKeyRecord) {
        res.status(401).json({ error: 'Invalid API key' });
        return;
      }

      if (apiKeyRecord.isRevoked) {
        res.status(401).json({ error: 'API key has been revoked' });
        return;
      }

      if (apiKeyRecord.expiresAt && apiKeyRecord.expiresAt < new Date()) {
        res.status(401).json({ error: 'API key has expired' });
        return;
      }

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
        apiKeyId: apiKeyRecord.id,
        scopes: apiKeyRecord.scopes,
        isFleetAdmin: apiKeyRecord.scopes.includes('fleet:admin'),
      };

      next();
    } catch (error) {
      console.error('Auth middleware error:', error);
      res.status(500).json({ error: 'Authentication error' });
    }
  };
}

/**
 * Require specific scope(s) for a route
 */
export function requireScope(...requiredScopes: string[]) {
  return function scopeMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    if (!req.auth) {
      res.status(401).json({ error: 'Not authenticated' });
      return;
    }

    const hasScope = requiredScopes.some((scope) => req.auth!.scopes.includes(scope));

    if (!hasScope) {
      res.status(403).json({
        error: 'Insufficient permissions',
        required: requiredScopes,
        granted: req.auth.scopes,
      });
      return;
    }

    next();
  };
}
