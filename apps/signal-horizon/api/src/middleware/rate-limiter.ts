/**
 * Rate Limiter Middleware
 * Simple sliding window rate limiter for API endpoints.
 *
 * For production, consider using Redis-backed rate limiting
 * to support horizontal scaling.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';

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
}

/**
 * Create a rate limiter middleware with sliding window algorithm.
 *
 * @example
 * ```ts
 * // Limit to 100 requests per minute
 * router.use('/query', createRateLimiter({
 *   maxRequests: 100,
 *   windowMs: 60 * 1000,
 * }));
 * ```
 */
export function createRateLimiter(options: RateLimiterOptions): RequestHandler {
  const {
    maxRequests,
    windowMs,
    keyGenerator = (req: Request) => getClientIp(req),
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
 * Extract client IP from request, handling proxies.
 */
function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress ?? 'unknown';
}

/**
 * Pre-configured rate limiters for common use cases
 */
export const rateLimiters: Record<string, RequestHandler> = {
  /** Hunt queries: 100 requests per minute */
  hunt: createRateLimiter({
    maxRequests: 100,
    windowMs: 60 * 1000,
    message: 'Hunt query rate limit exceeded. Please wait before trying again.',
  }),

  /** Saved queries: 30 requests per minute */
  savedQueries: createRateLimiter({
    maxRequests: 30,
    windowMs: 60 * 1000,
    message: 'Saved query rate limit exceeded. Please wait before trying again.',
  }),

  /** Heavy aggregations: 10 requests per minute */
  aggregations: createRateLimiter({
    maxRequests: 10,
    windowMs: 60 * 1000,
    message: 'Aggregation rate limit exceeded. These queries are resource-intensive.',
  }),
};
