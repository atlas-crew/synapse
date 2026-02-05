/**
 * Rate Limiting Middleware
 * Provides tenant-scoped rate limiting for API endpoints
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { createHash } from 'node:crypto';
import rateLimit, { type RateLimitRequestHandler } from 'express-rate-limit';
import type { Logger } from 'pino';
import { getClientIpForAuth } from '../../middleware/rate-limiter.js';

/**
 * Rate limit configuration for different endpoint types
 */
export interface RateLimitConfig {
  /** Window size in milliseconds */
  windowMs: number;
  /** Maximum requests per window */
  maxRequests: number;
  /** Optional custom message */
  message?: string;
}

interface KeyedRateLimitConfig extends RateLimitConfig {
  keyGenerator: (req: Request) => string;
  skipSuccessfulRequests?: boolean;
}

const AUTH_RATE_LIMIT_DEFAULTS = {
  ipPerSecond: 10,
  ipFailuresPerMinute: 5,
  keyFailuresPerHour: 100,
} as const;

const TUNNEL_RATE_LIMIT_DEFAULTS = {
  keyCreatesPerHour: 50,
} as const;

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function retryAfterSeconds(windowMs: number): number {
  return Math.ceil(windowMs / 1000);
}

function createKeyedRateLimiter(
  config: KeyedRateLimitConfig,
  logger?: Logger,
  keyLabel?: (req: Request) => string
): RateLimitRequestHandler {
  return rateLimit({
    windowMs: config.windowMs,
    max: config.maxRequests,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: config.keyGenerator,
    skipSuccessfulRequests: config.skipSuccessfulRequests,
    handler: (req: Request, res: Response) => {
      const retryAfter = retryAfterSeconds(config.windowMs);

      if (logger) {
        logger.warn(
          {
            key: keyLabel ? keyLabel(req) : config.keyGenerator(req),
            path: req.path,
            method: req.method,
            limit: config.maxRequests,
            windowMs: config.windowMs,
          },
          'Rate limit exceeded'
        );
      }

      res.setHeader('Retry-After', retryAfter.toString());
      res.status(429).json({
        error: config.message || 'Too many requests. Please try again later.',
        retryAfter,
      });
    },
    skip: (req: Request) => req.method === 'OPTIONS',
  });
}

/**
 * Default rate limit configurations for playbook endpoints
 */
export const PlaybookRateLimits = {
  /** Playbook creation: 10 per minute per tenant */
  create: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 10,
    message: 'Too many playbook creation requests. Please try again later.',
  },
  /** Playbook execution: 30 per minute per tenant */
  execute: {
    windowMs: 60 * 1000,
    maxRequests: 30,
    message: 'Too many playbook execution requests. Please try again later.',
  },
  /** Step completions: 100 per minute per tenant */
  stepComplete: {
    windowMs: 60 * 1000,
    maxRequests: 100,
    message: 'Too many step completion requests. Please try again later.',
  },
} as const;

/**
 * Extract tenant ID from authenticated request for rate limit keying
 */
const TENANT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/i;

function normalizeTenantId(value?: string): string | null {
  if (!value) {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const normalized = trimmed.toLowerCase();
  if (!TENANT_ID_PATTERN.test(normalized)) {
    return null;
  }
  return normalized;
}

function getTenantKey(req: Request): string {
  // Use tenant ID from auth context if available
  const tenantId = normalizeTenantId(req.auth?.tenantId);
  if (tenantId) {
    return tenantId;
  }
  // Fall back to IP if not authenticated (shouldn't happen with proper middleware ordering)
  return req.ip || req.socket.remoteAddress || 'unknown';
}

/**
 * Create a tenant-scoped rate limiter
 *
 * @param config - Rate limit configuration
 * @param logger - Optional logger for rate limit events
 * @returns Express middleware for rate limiting
 */
export function createTenantRateLimiter(
  config: RateLimitConfig,
  logger?: Logger
): RateLimitRequestHandler {
  return createKeyedRateLimiter(
    {
      ...config,
      keyGenerator: getTenantKey,
    },
    logger,
    (req) => getTenantKey(req)
  );
}

/**
 * Pre-configured rate limiters for playbook endpoints
 */
export function createPlaybookRateLimiters(logger?: Logger) {
  return {
    /** Rate limiter for POST /playbooks (create) */
    create: createTenantRateLimiter(PlaybookRateLimits.create, logger),
    /** Rate limiter for POST /playbooks/:id/run (execute) */
    execute: createTenantRateLimiter(PlaybookRateLimits.execute, logger),
    /** Rate limiter for POST /playbooks/runs/:id/step (step completion) */
    stepComplete: createTenantRateLimiter(PlaybookRateLimits.stepComplete, logger),
  };
}

function extractBearerToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return null;
  }
  const [scheme, token] = authHeader.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return null;
  }
  return token;
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function authKeyGenerator(req: Request): string {
  const token = extractBearerToken(req);
  if (token) {
    return `key:${hashToken(token)}`;
  }
  return `ip:${getClientIpForAuth(req)}`;
}

/**
 * Create rate limiters for authentication endpoints.
 *
 * - Per-IP burst: 10 requests/second
 * - Per-IP failed auth: 5 failures/minute
 * - Per-API-key failed auth: 100 failures/hour
 */
export function createAuthRateLimiters(logger?: Logger) {
  const ipPerSecond = parsePositiveInt(
    process.env.AUTH_RATE_LIMIT_IP_PER_SEC,
    AUTH_RATE_LIMIT_DEFAULTS.ipPerSecond
  );
  const ipFailuresPerMinute = parsePositiveInt(
    process.env.AUTH_RATE_LIMIT_FAILURES_PER_MIN,
    AUTH_RATE_LIMIT_DEFAULTS.ipFailuresPerMinute
  );
  const keyFailuresPerHour = parsePositiveInt(
    process.env.AUTH_RATE_LIMIT_KEY_PER_HOUR,
    AUTH_RATE_LIMIT_DEFAULTS.keyFailuresPerHour
  );

  const ipBurst = createKeyedRateLimiter(
    {
      windowMs: 1000,
      maxRequests: ipPerSecond,
      message: 'Too many authentication requests. Please slow down.',
      keyGenerator: getClientIpForAuth,
    },
    logger
  );

  const ipFailures = createKeyedRateLimiter(
    {
      windowMs: 60 * 1000,
      maxRequests: ipFailuresPerMinute,
      message: 'Too many failed authentication attempts. Please wait before retrying.',
      keyGenerator: getClientIpForAuth,
      skipSuccessfulRequests: true,
    },
    logger
  );

  const keyFailures = createKeyedRateLimiter(
    {
      windowMs: 60 * 60 * 1000,
      maxRequests: keyFailuresPerHour,
      message: 'Too many failed authentication attempts for this API key.',
      keyGenerator: authKeyGenerator,
      skipSuccessfulRequests: true,
    },
    logger
  );

  return { ipBurst, ipFailures, keyFailures };
}

/**
 * Create rate limiter for tunnel session creation.
 * Default: 50 creations per hour per API key.
 */
export function createTunnelCreationRateLimiter(logger?: Logger): RateLimitRequestHandler {
  const maxCreates = parsePositiveInt(
    process.env.TUNNEL_CREATE_RATE_LIMIT_PER_HOUR,
    TUNNEL_RATE_LIMIT_DEFAULTS.keyCreatesPerHour
  );
  return createKeyedRateLimiter(
    {
      windowMs: 60 * 60 * 1000,
      maxRequests: maxCreates,
      message: 'Too many tunnel session creations. Please wait before retrying.',
      keyGenerator: (req) =>
        req.auth?.apiKeyId ?? req.auth?.userId ?? getClientIpForAuth(req),
    },
    logger
  );
}

/**
 * Combined rate limiter that applies multiple limits
 * Useful for endpoints that count against multiple quotas
 */
export function combineRateLimiters(
  ...limiters: RateLimitRequestHandler[]
): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    for (const limiter of limiters) {
      await new Promise<void>((resolve, reject) => {
        limiter(req, res, (err?: unknown) => {
          if (err) {
            reject(err);
          } else if (res.headersSent) {
            // Rate limit was triggered, don't continue
            reject(new Error('Rate limit exceeded'));
          } else {
            resolve();
          }
        });
      }).catch(() => {
        // Response already sent by limiter handler
        return;
      });

      // If response was sent (rate limited), stop processing
      if (res.headersSent) {
        return;
      }
    }
    next();
  };
}
