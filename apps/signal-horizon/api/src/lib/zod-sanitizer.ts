/**
 * Zod Error Sanitization Utilities (WS5-004)
 *
 * Prevents schema disclosure in production by sanitizing Zod validation errors.
 *
 * OWASP Reference: CWE-209 - Generation of Error Message Containing Sensitive Information
 */

import { ZodError, type ZodSchema } from 'zod';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { sendProblem } from './problem-details.js';
import { ErrorCatalog } from './errors.js';

export interface SanitizeOptions {
  /** Run in production mode (hide field names and messages) */
  production?: boolean;
  /** Generic message to return in production */
  genericMessage?: string;
}

export type ValidationSource = 'body' | 'query' | 'params';

export interface ValidationMiddlewareOptions extends SanitizeOptions {
  /** HTTP status code for validation failures */
  statusCode?: number;
}

export type SafeParseResult<T> =
  | { success: true; data: T }
  | { success: false; error: string };

const isProduction = (): boolean => process.env.NODE_ENV === 'production';

/**
 * Sanitize a Zod error for safe exposure to clients.
 * In production, returns only a generic message.
 * In development, returns detailed field-level errors.
 */
export function sanitizeZodError(
  error: ZodError,
  options: SanitizeOptions = {}
): string {
  const production = options.production ?? isProduction();
  const genericMessage = options.genericMessage ?? 'Validation failed';

  // Always log full details server-side (without received values)
  const sanitizedIssues = error.issues.map((issue) => ({
    path: issue.path.join('.'),
    code: issue.code,
    message: issue.message,
    // Intentionally omit 'received' to prevent PII leakage in logs
  }));

  // Log for debugging (this would use your actual logger)
  if (typeof console !== 'undefined') {
    console.debug('Zod validation error', {
      issues: sanitizedIssues,
      issueCount: error.issues.length,
    });
  }

  // In production, return only generic message
  if (production) {
    return genericMessage;
  }

  // In development, return detailed errors
  const details = error.issues.map((issue) => {
    const path = issue.path.join('.');
    return `${path}: ${issue.message}`;
  });

  return details.join('; ');
}

/**
 * Safe parse wrapper with discriminated union result.
 * Returns either success with data or failure with sanitized error.
 */
export function safeParse<T>(
  schema: ZodSchema<T>,
  data: unknown,
  context?: string
): SafeParseResult<T> {
  const result = schema.safeParse(data);

  if (result.success) {
    return { success: true, data: result.data };
  }

  if (context && typeof console !== 'undefined') {
    console.debug(`Validation failed for ${context}`, { context });
  }

  return {
    success: false,
    error: sanitizeZodError(result.error),
  };
}

/**
 * Express middleware for validating a single request source (body, query, or params).
 * Replaces the source with parsed/coerced data on success.
 */
export function createValidationMiddleware<T>(
  schema: ZodSchema<T>,
  source: ValidationSource,
  options: ValidationMiddlewareOptions = {}
): RequestHandler {
  const statusCode = options.statusCode ?? 400;
  const production = options.production ?? isProduction();
  const genericMessage = options.genericMessage ?? 'Validation failed';

  return (req: Request, res: Response, next: NextFunction): void => {
    const data = req[source];
    const result = schema.safeParse(data);

    if (result.success) {
      // Replace with parsed/coerced data
      (req as unknown as Record<string, unknown>)[source] = result.data;
      next();
      return;
    }

    // Log validation failure with request context
    const requestId = (req as unknown as Record<string, unknown>).id as string | undefined;
    if (typeof console !== 'undefined') {
      console.warn('Validation failed for ' + source, {
        requestId,
        source,
        path: req.path,
        method: req.method,
      });
    }

    if (production) {
      const entry = ErrorCatalog.VALIDATION_ERROR;
      sendProblem(res, statusCode, genericMessage, {
        code: entry.code,
        hint: entry.hint,
        instance: req.originalUrl,
        context: { source },
      });
      return;
    }

    const entry = ErrorCatalog.VALIDATION_ERROR;
    sendProblem(res, statusCode, sanitizeZodError(result.error, { production: false }), {
      code: entry.code,
      hint: entry.hint,
      instance: req.originalUrl,
      details: { source },
      context: { source },
    });
  };
}

/**
 * Express middleware for validating multiple sources at once.
 * Validates body, query, and/or params in a single pass.
 */
export function createCombinedValidation(
  schemas: Partial<Record<ValidationSource, ZodSchema>>,
  options: ValidationMiddlewareOptions = {}
): RequestHandler {
  const statusCode = options.statusCode ?? 400;
  const production = options.production ?? isProduction();
  const genericMessage = options.genericMessage ?? 'Validation failed';

  return (req: Request, res: Response, next: NextFunction): void => {
    const errors: Array<{ source: ValidationSource; error: string }> = [];
    const parsed: Partial<Record<ValidationSource, unknown>> = {};

    for (const source of ['body', 'query', 'params'] as ValidationSource[]) {
      const schema = schemas[source];
      if (!schema) continue;

      const result = schema.safeParse(req[source]);
      if (result.success) {
        parsed[source] = result.data;
      } else {
        errors.push({
          source,
          error: sanitizeZodError(result.error, { production: false }),
        });
      }
    }

    if (errors.length > 0) {
      const requestId = (req as unknown as Record<string, unknown>).id as string | undefined;
      if (typeof console !== 'undefined') {
        console.warn('Combined validation failed', {
          requestId,
          errors,
        });
      }

      if (production) {
        const entry = ErrorCatalog.VALIDATION_ERROR;
        sendProblem(res, statusCode, genericMessage, {
          code: entry.code,
          hint: entry.hint,
          instance: req.originalUrl,
          context: { sources: errors.map((err) => err.source) },
        });
        return;
      }

      const entry = ErrorCatalog.VALIDATION_ERROR;
      sendProblem(res, statusCode, genericMessage, {
        code: entry.code,
        hint: entry.hint,
        instance: req.originalUrl,
        details: errors,
        context: { sources: errors.map((err) => err.source) },
      });
      return;
    }

    // Replace with parsed data
    for (const source of ['body', 'query', 'params'] as ValidationSource[]) {
      if (parsed[source] !== undefined) {
        (req as unknown as Record<string, unknown>)[source] = parsed[source];
      }
    }

    next();
  };
}

export default {
  sanitizeZodError,
  safeParse,
  createValidationMiddleware,
  createCombinedValidation,
};
