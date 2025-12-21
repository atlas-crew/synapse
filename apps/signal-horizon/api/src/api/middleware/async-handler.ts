/**
 * Async Error Handler Middleware
 * Wraps async route handlers to catch errors and pass to error middleware
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import type { Logger } from 'pino';

/**
 * Wraps an async route handler to catch promise rejections
 * and pass them to Express error middleware
 */
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Error response structure
 */
export interface ApiError {
  error: string;
  message?: string;
  code?: string;
  details?: unknown;
}

/**
 * Custom error class with status code
 */
export class HttpError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public code?: string,
    public details?: unknown
  ) {
    super(message);
    this.name = 'HttpError';
  }

  static badRequest(message: string, details?: unknown): HttpError {
    return new HttpError(400, message, 'BAD_REQUEST', details);
  }

  static unauthorized(message = 'Unauthorized'): HttpError {
    return new HttpError(401, message, 'UNAUTHORIZED');
  }

  static forbidden(message = 'Access denied'): HttpError {
    return new HttpError(403, message, 'FORBIDDEN');
  }

  static notFound(resource = 'Resource'): HttpError {
    return new HttpError(404, `${resource} not found`, 'NOT_FOUND');
  }

  static conflict(message: string): HttpError {
    return new HttpError(409, message, 'CONFLICT');
  }

  static internal(message = 'Internal server error'): HttpError {
    return new HttpError(500, message, 'INTERNAL_ERROR');
  }
}

/**
 * Global error handling middleware
 * Must be registered after all routes
 */
export function createErrorHandler(logger: Logger) {
  return function errorHandler(
    err: Error | HttpError,
    _req: Request,
    res: Response,
    _next: NextFunction
  ): void {
    // Log error
    logger.error({ err, stack: err.stack }, 'Request error');

    // Handle HttpError
    if (err instanceof HttpError) {
      const response: ApiError = {
        error: err.message,
        code: err.code,
      };
      if (err.details) {
        response.details = err.details;
      }
      res.status(err.statusCode).json(response);
      return;
    }

    // Handle Prisma errors
    if (err.name === 'PrismaClientKnownRequestError') {
      const prismaError = err as Error & { code: string };
      if (prismaError.code === 'P2025') {
        res.status(404).json({ error: 'Record not found', code: 'NOT_FOUND' });
        return;
      }
      if (prismaError.code === 'P2002') {
        res.status(409).json({ error: 'Record already exists', code: 'CONFLICT' });
        return;
      }
    }

    // Handle validation errors
    if (err.name === 'ZodError') {
      res.status(400).json({
        error: 'Validation error',
        code: 'VALIDATION_ERROR',
        details: (err as Error & { errors: unknown[] }).errors,
      });
      return;
    }

    // Default error response
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
      message: process.env.NODE_ENV === 'development' ? err.message : undefined,
    });
  };
}
