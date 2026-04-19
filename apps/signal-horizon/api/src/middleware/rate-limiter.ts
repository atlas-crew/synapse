/**
 * Rate Limiter Middleware (PEN-003 Fixed)
 * Simple sliding window rate limiter for API endpoints with trusted proxy support.
 *
 * For production, consider using Redis-backed rate limiting
 * to support horizontal scaling.
 *
 * Security: Validates X-Forwarded-For comes from trusted proxies only.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';

// =============================================================================
// Failed Authentication Rate Limiter (ADMIN-01)
// =============================================================================

interface FailedAuthEntry {
  count: number;
  resetAt: number;
}

const failedAuthStore = new Map<string, FailedAuthEntry>();

/** Max failed auth attempts before lockout */
const MAX_FAILED_AUTH_ATTEMPTS = 5;
/** Lockout window: 15 minutes */
const FAILED_AUTH_WINDOW_MS = 15 * 60 * 1000;

// Cleanup old failed auth entries periodically
const failedAuthCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of failedAuthStore.entries()) {
    if (entry.resetAt < now) {
      failedAuthStore.delete(key);
    }
  }
}, FAILED_AUTH_WINDOW_MS);
failedAuthCleanupInterval.unref();

/**
 * Check if auth lockout is disabled (dev mode or explicit bypass)
 */
function isAuthLockoutDisabled(): boolean {
  return process.env.NODE_ENV === 'development' || process.env.DISABLE_AUTH_LOCKOUT === 'true';
}

/**
 * Check if an IP is currently locked out due to too many failed auth attempts.
 * Call this BEFORE checking credentials.
 *
 * Note: Auth lockout is disabled in development mode to prevent blocking
 * during local testing when auth might fail frequently.
 *
 * @returns { locked: true, retryAfter } if locked out, { locked: false } otherwise
 */
export function checkAuthLockout(
  clientIp: string
): { locked: true; retryAfterSeconds: number } | { locked: false } {
  // Skip lockout in dev mode
  if (isAuthLockoutDisabled()) {
    return { locked: false };
  }

  const now = Date.now();
  const entry = failedAuthStore.get(clientIp);

  // No entry or window expired
  if (!entry || entry.resetAt < now) {
    return { locked: false };
  }

  // Check if locked out
  if (entry.count >= MAX_FAILED_AUTH_ATTEMPTS) {
    const retryAfterSeconds = Math.ceil((entry.resetAt - now) / 1000);
    return { locked: true, retryAfterSeconds };
  }

  return { locked: false };
}

/**
 * Record a failed authentication attempt for an IP.
 * Call this AFTER authentication fails.
 *
 * Note: Skipped in dev mode to prevent lockout during testing.
 */
export function recordFailedAuth(clientIp: string): void {
  // Skip recording in dev mode
  if (isAuthLockoutDisabled()) {
    return;
  }

  const now = Date.now();
  let entry = failedAuthStore.get(clientIp);

  // Reset if window expired
  if (!entry || entry.resetAt < now) {
    entry = {
      count: 0,
      resetAt: now + FAILED_AUTH_WINDOW_MS,
    };
  }

  entry.count++;
  failedAuthStore.set(clientIp, entry);
}

/**
 * Clear failed auth attempts for an IP on successful authentication.
 * Optional but helps prevent lockout after recovery.
 */
export function clearFailedAuth(clientIp: string): void {
  failedAuthStore.delete(clientIp);
}

/**
 * Get client IP from request, with proxy awareness.
 * Exported for use by auth middleware.
 */
export function getClientIpForAuth(req: Request): string {
  const trustedProxies = getTrustedProxies();
  const socketIp = req.socket.remoteAddress;

  // Only use forwarded headers if connection is from trusted proxy
  if (isTrustedProxy(socketIp, trustedProxies)) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      const clientIp = forwarded.split(',')[0].trim();
      if (clientIp) {
        return clientIp;
      }
    }
  }

  // Normalize IPv6-mapped IPv4 addresses
  if (socketIp?.startsWith('::ffff:')) {
    return socketIp.substring(7);
  }

  return socketIp ?? 'unknown';
}

// =============================================================================
// General Rate Limiter
// =============================================================================

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

interface RateLimiterOptions {
  /** Maximum requests per window */
  maxRequests: number;
  /** Window size in milliseconds */
  windowMs: number;
  /** Custom key extractor (default: IP address) */
  keyGenerator?: (req: Request) => string;
  /** Custom error message */
  message?: string;
  /**
   * Trusted proxy configuration.
   * - true: Trust all proxies (NOT RECOMMENDED for production)
   * - false: Don't trust any proxy, use socket IP only
   * - string[]: List of trusted proxy IPs/CIDRs
   * @default false
   */
  trustProxy?: boolean | string[];
}

/**
 * Create a rate limiter middleware with sliding window algorithm.
 *
 * @example
 * ```ts
 * // Limit to 100 requests per minute with trusted proxies
 * router.use('/query', createRateLimiter({
 *   maxRequests: 100,
 *   windowMs: 60 * 1000,
 *   trustProxy: ['10.0.0.0/8', '172.16.0.0/12'],  // Internal proxies
 * }));
 * ```
 */
export function createRateLimiter(options: RateLimiterOptions): RequestHandler {
  const {
    maxRequests,
    windowMs,
    keyGenerator = (req: Request) => getClientIp(req, options.trustProxy),
    message = 'Too many requests, please try again later',
  } = options;

  // In-memory store (for single instance)
  // For production, use Redis with MULTI/EXEC
  const store = new Map<string, RateLimitEntry>();

  // Cleanup old entries periodically
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of store.entries()) {
      if (entry.resetAt < now) {
        store.delete(key);
      }
    }
  }, windowMs);

  // Don't prevent process from exiting
  cleanupInterval.unref();

  return (req: Request, res: Response, next: NextFunction): void => {
    const key = keyGenerator(req);
    const now = Date.now();

    let entry = store.get(key);

    // Reset if window expired
    if (!entry || entry.resetAt < now) {
      entry = {
        count: 0,
        resetAt: now + windowMs,
      };
    }

    entry.count++;
    store.set(key, entry);

    // Set rate limit headers
    const remaining = Math.max(0, maxRequests - entry.count);
    const resetSeconds = Math.ceil((entry.resetAt - now) / 1000);

    res.setHeader('X-RateLimit-Limit', maxRequests);
    res.setHeader('X-RateLimit-Remaining', remaining);
    res.setHeader('X-RateLimit-Reset', resetSeconds);

    if (entry.count > maxRequests) {
      res.setHeader('Retry-After', resetSeconds);
      res.status(429).json({
        error: 'Rate limit exceeded',
        message,
        retryAfter: resetSeconds,
      });
      return;
    }

    next();
  };
}

/**
 * Check if an IP matches a CIDR range or exact IP.
 */
function ipMatchesCIDR(ip: string, cidr: string): boolean {
  // Normalize IPv6-mapped IPv4
  const normalizedIp = ip.replace(/^::ffff:/, '');

  // Exact match
  if (normalizedIp === cidr || ip === cidr) {
    return true;
  }

  // CIDR match (simplified - supports /8, /16, /24 for IPv4)
  if (cidr.includes('/')) {
    const [network, prefixStr] = cidr.split('/');
    const prefix = parseInt(prefixStr, 10);

    // Simple IPv4 CIDR matching
    const ipParts = normalizedIp.split('.').map(Number);
    const networkParts = network.split('.').map(Number);

    if (ipParts.length !== 4 || networkParts.length !== 4) {
      return false;
    }

    const octetsToCheck = Math.floor(prefix / 8);
    for (let i = 0; i < octetsToCheck; i++) {
      if (ipParts[i] !== networkParts[i]) {
        return false;
      }
    }

    // Partial octet matching
    const remainingBits = prefix % 8;
    if (remainingBits > 0 && octetsToCheck < 4) {
      const mask = 0xff << (8 - remainingBits);
      if ((ipParts[octetsToCheck] & mask) !== (networkParts[octetsToCheck] & mask)) {
        return false;
      }
    }

    return true;
  }

  return false;
}

/**
 * Check if the direct connection IP is from a trusted proxy.
 */
function isTrustedProxy(
  socketIp: string | undefined,
  trustProxy: boolean | string[] | undefined
): boolean {
  if (trustProxy === true) {
    return true;
  }
  if (trustProxy === false || trustProxy === undefined) {
    return false;
  }
  if (!socketIp) {
    return false;
  }

  // Check against trusted proxy list (trustProxy is string[] at this point)
  return trustProxy.some((trusted) => ipMatchesCIDR(socketIp, trusted));
}

/**
 * Extract client IP from request, handling proxies securely.
 *
 * PEN-003: Only trust X-Forwarded-For when the direct connection
 * comes from a trusted proxy. This prevents IP spoofing attacks.
 */
function getClientIp(
  req: Request,
  trustProxy?: boolean | string[]
): string {
  const socketIp = req.socket.remoteAddress;

  // Only use forwarded headers if connection is from trusted proxy
  if (isTrustedProxy(socketIp, trustProxy)) {
    // X-Forwarded-For: client, proxy1, proxy2
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      // Take the leftmost IP (original client)
      const clientIp = forwarded.split(',')[0].trim();
      if (clientIp) {
        return clientIp;
      }
    }

    // Try other common headers
    const realIp = req.headers['x-real-ip'];
    if (typeof realIp === 'string' && realIp.trim()) {
      return realIp.trim();
    }

    // CF-Connecting-IP for Cloudflare
    const cfIp = req.headers['cf-connecting-ip'];
    if (typeof cfIp === 'string' && cfIp.trim()) {
      return cfIp.trim();
    }
  }

  // Normalize IPv6-mapped IPv4 addresses
  if (socketIp?.startsWith('::ffff:')) {
    return socketIp.substring(7);
  }

  return socketIp ?? 'unknown';
}

/**
 * Get trusted proxy configuration from environment.
 * PEN-003: Configure trusted proxies via environment variable.
 *
 * Set TRUSTED_PROXIES to comma-separated list of IPs/CIDRs:
 * TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
 */
function getTrustedProxies(): string[] | false {
  const envValue = process.env.TRUSTED_PROXIES;
  if (!envValue) {
    return false; // Don't trust any proxy by default
  }
  return envValue.split(',').map((p) => p.trim()).filter(Boolean);
}

/**
 * Pre-configured rate limiters for common use cases.
 *
 * PEN-003: These use trusted proxy configuration from environment
 * to prevent IP spoofing via X-Forwarded-For headers.
 */
export const rateLimiters: Record<string, RequestHandler> = {
  /** Hunt queries: 100 requests per minute */
  hunt: createRateLimiter({
    maxRequests: 100,
    windowMs: 60 * 1000,
    message: 'Hunt query rate limit exceeded. Please wait before trying again.',
    trustProxy: getTrustedProxies(),
  }),

  /** Saved queries: 30 requests per minute */
  savedQueries: createRateLimiter({
    maxRequests: 30,
    windowMs: 60 * 1000,
    message: 'Saved query rate limit exceeded. Please wait before trying again.',
    trustProxy: getTrustedProxies(),
  }),

  /** Heavy aggregations: 10 requests per minute */
  aggregations: createRateLimiter({
    maxRequests: 10,
    windowMs: 60 * 1000,
    message: 'Aggregation rate limit exceeded. These queries are resource-intensive.',
    trustProxy: getTrustedProxies(),
  }),

  /** Connectivity tests: 10 requests per minute (expensive network operations) */
  connectivityTest: createRateLimiter({
    maxRequests: 10,
    windowMs: 60 * 1000,
    message: 'Connectivity test rate limit exceeded. These operations are resource-intensive.',
    trustProxy: getTrustedProxies(),
  }),

  /**
   * Authentication rate limiter: 5 failed attempts per 15 minutes (ADMIN-01)
   * Protects against brute-force API key guessing attacks.
   * Note: This tracks ALL auth attempts, not just failures - the auth middleware
   * should only increment this counter on failure.
   */
  authAttempt: createRateLimiter({
    maxRequests: 5,
    windowMs: 15 * 60 * 1000, // 15 minutes
    message: 'Too many authentication attempts. Please wait 15 minutes before trying again.',
    trustProxy: getTrustedProxies(),
  }),

  /**
   * Configuration mutation rate limiter: 10 requests per minute (labs-ddh)
   * Protects against configuration flooding attacks where attackers try to
   * overwhelm the system with excessive config updates.
   * Applied to: config templates, sensor config, rule distribution endpoints.
   */
  configMutation: createRateLimiter({
    maxRequests: 10,
    windowMs: 60 * 1000,
    message: 'Configuration update rate limit exceeded. Please wait before making more changes.',
    trustProxy: getTrustedProxies(),
  }),

  /**
   * Fleet command rate limiter: 20 commands per minute (labs-ddh)
   * Protects against command flooding attacks against the fleet.
   * Applied to: command dispatch, sensor actions, rule push endpoints.
   */
  fleetCommand: createRateLimiter({
    maxRequests: 20,
    windowMs: 60 * 1000,
    message: 'Fleet command rate limit exceeded. Please wait before issuing more commands.',
    trustProxy: getTrustedProxies(),
  }),

  /**
   * Onboarding rate limiter: 5 tokens per minute (labs-0f8)
   * Protects against registration token abuse and sensor registration flooding.
   */
  onboarding: createRateLimiter({
    maxRequests: 5,
    windowMs: 60 * 1000,
    message: 'Onboarding rate limit exceeded. Please wait before creating more tokens.',
    trustProxy: getTrustedProxies(),
  }),

  /**
   * Batch onboarding limiter: 2 requests per minute (m-7 task-77 hardening)
   * Protects high-impact batch approval/rejection endpoints from amplifying key
   * issuance and fleet handoff operations inside a single request.
   */
  onboardingBatch: createRateLimiter({
    maxRequests: 2,
    windowMs: 60 * 1000,
    message: 'Batch onboarding rate limit exceeded. Please wait before processing more sensors.',
    trustProxy: getTrustedProxies(),
  }),

  /**
   * User authentication limiter: 5 requests per minute (labs-k3vx)
   * Stricter limits for login endpoints to prevent credential stuffing.
   * Applied to: /auth/login, /auth/refresh, etc.
   */
  userAuth: createRateLimiter({
    maxRequests: 5,
    windowMs: 60 * 1000,
    message: 'Too many login attempts. Please wait 1 minute before trying again.',
    trustProxy: getTrustedProxies(),
  }),

  /**
   * Global API rate limit: 1000 requests per minute (labs-mmft.7)
   * Provides baseline protection against DoS and resource exhaustion.
   */
  global: createRateLimiter({
    // Dev UX: the UI + websocket reconnect loops can easily exceed 1000/min on localhost.
    // Keep a sane production default, but uncap local development enough to avoid flakiness.
    maxRequests: process.env.NODE_ENV === 'production' ? 1000 : 50_000,
    windowMs: 60 * 1000,
    message: 'Global API rate limit exceeded. Please reduce request frequency.',
    trustProxy: getTrustedProxies(),
  }),
};
