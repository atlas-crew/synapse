/**
 * Request ID Middleware
 *
 * Generates or accepts unique request IDs for tracing and audit purposes.
 * - Accepts existing X-Request-ID header if valid UUID
 * - Generates new UUID v4 if not provided
 * - Adds request ID to response headers
 * - Attaches to request object for logging
 */

import type { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'node:crypto';

// UUID v4 regex pattern for validation
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Validates if a string is a valid UUID v4
 */
function isValidUUID(value: string): boolean {
  return UUID_PATTERN.test(value);
}

/**
 * Express middleware that ensures every request has a unique ID.
 *
 * The ID is:
 * 1. Taken from the incoming X-Request-ID header if it's a valid UUID
 * 2. Generated as a new UUID v4 otherwise
 *
 * The ID is:
 * - Set on req.id for use in application code
 * - Added to response headers as X-Request-ID
 * - Passed to pino logger via req.id (pinoHttp will pick this up)
 */
export function requestId() {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Check for existing request ID header
    const existingId = req.get('X-Request-ID');

    // Use existing ID if valid UUID, otherwise generate new one
    const id = existingId && isValidUUID(existingId) ? existingId : randomUUID();

    // Attach to request object
    // Note: We use a custom property that Express types don't know about
    // TypeScript declaration merging handles this in a global.d.ts
    (req as Request & { id: string }).id = id;

    // Set response header before any handlers can send response
    res.setHeader('X-Request-ID', id);

    next();
  };
}

// TypeScript declaration merging for Express Request
declare global {
  namespace Express {
    interface Request {
      id?: string;
    }
  }
}
