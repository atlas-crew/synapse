/**
 * Security Middlewares
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';

/**
 * Enforce HTTPS middleware for production. (labs-mmft.4)
 * Rejects non-HTTPS requests when running in production mode.
 * Assumes the app is behind a proxy that sets X-Forwarded-Proto.
 */
export function enforceHttps(req: Request, res: Response, next: NextFunction): void {
  // Skip check in dev/test or if already HTTPS
  if (process.env.NODE_ENV !== 'production') {
    return next();
  }

  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
  
  if (!isHttps) {
    res.status(403).json({
      error: 'Forbidden',
      code: 'HTTPS_REQUIRED',
      message: 'HTTPS is required for all API requests in production',
    });
    return;
  }

  next();
}

/**
 * Strict Transport Security (HSTS) middleware.
 * Handled by Helmet usually, but added here for completeness if needed.
 */
export function hsts(maxAge: number = 31536000): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Strict-Transport-Security', `max-age=${maxAge}; includeSubDomains; preload`);
    next();
  };
}
