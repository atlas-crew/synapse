/**
 * Error handling utilities for sanitized error responses
 *
 * Security: Handles Prisma, Zod, and generic errors safely to prevent
 * database schema and internal structure disclosure (WS5-004, PEN-005).
 *
 * Signal Horizon Error Code Catalog (E***):
 * E001 unknown_param
 * E002 permission_denied
 * E003 unauthorized
 * E004 validation_failed
 * E005 not_found
 * E006 conflict
 * E007 service_unavailable
 * E008 database_error
 * E009 external_service_error
 * E999 internal_error
 */
import type { Response } from 'express';
import type { Logger } from 'pino';
import { ZodError } from 'zod';
import { Prisma } from '@prisma/client';
import { sendProblem } from './problem-details.js';

export interface ErrorCatalogEntry {
  code: string;
  message: string;
  status: number;
  hint?: string;
}

export const ErrorCatalog = {
  UNKNOWN_PARAM: {
    code: 'E001',
    message: 'Unknown parameter',
    status: 400,
    hint: 'Remove unsupported parameters and retry.',
  },
  PERMISSION_DENIED: {
    code: 'E002',
    message: 'Permission denied',
    status: 403,
    hint: 'Ensure your role allows this action.',
  },
  UNAUTHORIZED: {
    code: 'E003',
    message: 'Unauthorized',
    status: 401,
    hint: 'Provide a valid API key or token.',
  },
  VALIDATION_ERROR: {
    code: 'E004',
    message: 'Validation failed',
    status: 400,
    hint: 'Check required fields and formats.',
  },
  NOT_FOUND: {
    code: 'E005',
    message: 'Resource not found',
    status: 404,
    hint: 'Verify the resource identifier.',
  },
  CONFLICT: {
    code: 'E006',
    message: 'Resource conflict',
    status: 409,
    hint: 'Resolve the conflict and retry.',
  },
  SERVICE_UNAVAILABLE: {
    code: 'E007',
    message: 'Service unavailable',
    status: 503,
    hint: 'Retry later or contact support.',
  },
  DATABASE_ERROR: {
    code: 'E008',
    message: 'Database error',
    status: 500,
    hint: 'Retry later or contact support.',
  },
  EXTERNAL_SERVICE_ERROR: {
    code: 'E009',
    message: 'External service error',
    status: 502,
    hint: 'Retry later or contact support.',
  },
  INTERNAL_ERROR: {
    code: 'E999',
    message: 'Internal error',
    status: 500,
    hint: 'Retry later or contact support.',
  },
} as const;

export type ErrorCatalogKey = keyof typeof ErrorCatalog;

/**
 * Structured error response format
 */
export interface ErrorResponse {
  code: string;
  message: string;
  hint?: string;
  context?: Record<string, unknown>;
  details?: unknown;
  status?: number;
}

/**
 * Error codes for common scenarios
 */
export const ErrorCodes = {
  UNKNOWN_PARAM: ErrorCatalog.UNKNOWN_PARAM.code,
  PERMISSION_DENIED: ErrorCatalog.PERMISSION_DENIED.code,
  UNAUTHORIZED: ErrorCatalog.UNAUTHORIZED.code,
  VALIDATION_ERROR: ErrorCatalog.VALIDATION_ERROR.code,
  NOT_FOUND: ErrorCatalog.NOT_FOUND.code,
  CONFLICT: ErrorCatalog.CONFLICT.code,
  SERVICE_UNAVAILABLE: ErrorCatalog.SERVICE_UNAVAILABLE.code,
  DATABASE_ERROR: ErrorCatalog.DATABASE_ERROR.code,
  EXTERNAL_SERVICE_ERROR: ErrorCatalog.EXTERNAL_SERVICE_ERROR.code,
  INTERNAL_ERROR: ErrorCatalog.INTERNAL_ERROR.code,
} as const;

const LegacyCodeMap: Record<string, ErrorCatalogEntry> = {
  VALIDATION_ERROR: ErrorCatalog.VALIDATION_ERROR,
  UNAUTHORIZED: ErrorCatalog.UNAUTHORIZED,
  FORBIDDEN: ErrorCatalog.PERMISSION_DENIED,
  ACCESS_DENIED: ErrorCatalog.PERMISSION_DENIED,
  NOT_FOUND: ErrorCatalog.NOT_FOUND,
  CONFLICT: ErrorCatalog.CONFLICT,
  INTERNAL_ERROR: ErrorCatalog.INTERNAL_ERROR,
  DATABASE_ERROR: ErrorCatalog.DATABASE_ERROR,
  EXTERNAL_SERVICE_ERROR: ErrorCatalog.EXTERNAL_SERVICE_ERROR,
};

function resolveErrorEntry(code?: string): ErrorCatalogEntry | undefined {
  if (!code) return undefined;
  const direct = Object.values(ErrorCatalog).find((entry) => entry.code === code);
  if (direct) return direct;
  return LegacyCodeMap[code];
}

export class ApiError extends Error {
  public readonly code: string;
  public readonly status?: number;
  public readonly details?: unknown;
  public readonly hint?: string;
  public readonly context?: Record<string, unknown>;

  constructor(
    message: string,
    options: {
      code: string;
      status?: number;
      details?: unknown;
      hint?: string;
      context?: Record<string, unknown>;
    }
  ) {
    super(message);
    this.code = options.code;
    this.status = options.status;
    this.details = options.details;
    this.hint = options.hint;
    this.context = options.context;
  }
}

export function createApiError(
  key: ErrorCatalogKey,
  options: {
    message?: string;
    details?: unknown;
    hint?: string;
    context?: Record<string, unknown>;
    status?: number;
  } = {}
): ApiError {
  const entry = ErrorCatalog[key];
  return new ApiError(options.message ?? entry.message, {
    code: entry.code,
    status: options.status ?? entry.status,
    details: options.details,
    hint: options.hint ?? entry.hint,
    context: options.context,
  });
}

/**
 * PEN-005: Fail-safe development mode detection.
 * Only expose details when explicitly in development mode.
 */
function isDevelopmentMode(): boolean {
  const env = process.env.NODE_ENV?.toLowerCase();
  return env === 'development';
}

/**
 * Sanitize error for client response
 * Never exposes stack traces in production
 *
 * PEN-005: Uses fail-safe approach - if NODE_ENV is undefined
 * or misconfigured, defaults to production-safe behavior.
 */
export function sanitizeError(error: unknown): ErrorResponse {
  const isDevelopment = isDevelopmentMode();

  // Handle Zod validation errors
  if (error instanceof ZodError) {
    const entry = ErrorCatalog.VALIDATION_ERROR;
    return {
      code: entry.code,
      message: entry.message,
      hint: entry.hint,
      details: isDevelopment ? error.flatten() : undefined,
      status: entry.status,
    };
  }

  // Handle Prisma errors - never expose schema details or query structure
  // PEN-005: Prisma errors contain sensitive database schema information
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    // Map Prisma error codes to user-friendly messages
    const prismaErrorMap: Record<string, ErrorCatalogEntry> = {
      'P2002': ErrorCatalog.CONFLICT,
      'P2025': ErrorCatalog.NOT_FOUND,
      'P2003': ErrorCatalog.VALIDATION_ERROR,
      'P2014': ErrorCatalog.VALIDATION_ERROR,
    };

    const mapped = prismaErrorMap[error.code];
    if (mapped) {
      return {
        code: mapped.code,
        message: mapped.message,
        hint: mapped.hint,
        // Only include error code (not target/meta) in development
        details: isDevelopment ? { prismaCode: error.code } : undefined,
        status: mapped.status,
      };
    }

    // Unknown Prisma code - return generic database error
    const entry = ErrorCatalog.DATABASE_ERROR;
    return {
      code: entry.code,
      message: entry.message,
      hint: entry.hint,
      details: isDevelopment ? { prismaCode: error.code } : undefined,
      status: entry.status,
    };
  }

  // Handle Prisma validation errors (malformed queries)
  if (error instanceof Prisma.PrismaClientValidationError) {
    // Never expose the validation message as it contains schema info
    const entry = ErrorCatalog.VALIDATION_ERROR;
    return {
      code: entry.code,
      message: entry.message,
      hint: entry.hint,
      status: entry.status,
    };
  }

  // Handle Prisma initialization errors
  if (error instanceof Prisma.PrismaClientInitializationError) {
    const entry = ErrorCatalog.DATABASE_ERROR;
    return {
      code: entry.code,
      message: entry.message,
      hint: entry.hint,
      status: entry.status,
    };
  }

  if (error instanceof ApiError) {
    const entry = resolveErrorEntry(error.code);
    return {
      code: entry?.code ?? error.code,
      message: error.message,
      hint: error.hint ?? entry?.hint,
      context: error.context,
      details: isDevelopment ? error.details : undefined,
      status: error.status ?? entry?.status,
    };
  }

  const codedError = error as { code?: string; message?: string; status?: number; details?: unknown; hint?: string; context?: Record<string, unknown> };
  if (codedError && typeof codedError.code === 'string') {
    const entry = resolveErrorEntry(codedError.code) ?? ErrorCatalog.INTERNAL_ERROR;
    return {
      code: entry.code,
      message: codedError.message ?? entry.message,
      hint: codedError.hint ?? entry.hint,
      context: codedError.context,
      details: isDevelopment ? codedError.details : undefined,
      status: codedError.status ?? entry.status,
    };
  }

  // Handle known error types
  if (error instanceof Error) {
    // In production, never expose internal error messages
    if (!isDevelopment) {
      const entry = ErrorCatalog.INTERNAL_ERROR;
      return {
        code: entry.code,
        message: entry.message,
        hint: entry.hint,
        status: entry.status,
      };
    }

    // In development, include error details
    const entry = ErrorCatalog.INTERNAL_ERROR;
    return {
      code: entry.code,
      message: error.message,
      hint: entry.hint,
      details: {
        name: error.name,
        stack: error.stack,
      },
      status: entry.status,
    };
  }

  // Unknown error type
  const entry = ErrorCatalog.INTERNAL_ERROR;
  return {
    code: entry.code,
    message: isDevelopment ? String(error) : entry.message,
    hint: entry.hint,
    status: entry.status,
  };
}

/**
 * Handle validation error from Zod
 * PEN-005: Uses fail-safe development mode detection.
 */
export function handleValidationError(
  res: Response,
  error: ZodError,
  options: { instance?: string; context?: Record<string, unknown> } = {}
): Response {
  const isDevelopment = isDevelopmentMode();
  const entry = ErrorCatalog.VALIDATION_ERROR;

  return sendProblem(res, entry.status, entry.message, {
    code: entry.code,
    hint: entry.hint,
    details: isDevelopment ? error.flatten() : undefined,
    instance: options.instance,
    context: options.context,
  });
}

/**
 * Generic error handler for route handlers
 * Logs error and returns sanitized response
 */
export function handleRouteError(
  res: Response,
  error: unknown,
  logger: Logger,
  context?: Record<string, unknown>
): Response {
  // Log the full error with context
  logger.error({ error, ...context }, 'Route handler error');

  // Return sanitized error to client
  const sanitized = sanitizeError(error);

  // Determine status code
  let statusCode = sanitized.status ?? ErrorCatalog.INTERNAL_ERROR.status;
  if (!sanitized.status) {
    const entry = resolveErrorEntry(sanitized.code);
    if (entry) statusCode = entry.status;
  }

  const instance =
    typeof context?.instance === 'string' ? context.instance : undefined;
  const responseContext = {
    ...(context ?? {}),
    ...(sanitized.context ?? {}),
  };
  if ('instance' in responseContext) {
    delete (responseContext as Record<string, unknown>).instance;
  }
  const entry = resolveErrorEntry(sanitized.code);

  return sendProblem(res, statusCode, sanitized.message, {
    code: sanitized.code,
    hint: sanitized.hint ?? entry?.hint,
    details: sanitized.details,
    instance,
    context: Object.keys(responseContext).length > 0 ? responseContext : undefined,
  });
}

/**
 * Async error wrapper for Express route handlers
 * Catches async errors and forwards to error handler
 */
export function asyncHandler(
  fn: (req: any, res: Response, next?: any) => Promise<any>
) {
  return (req: any, res: Response, next: any) => {
    Promise.resolve(fn(req, res, next)).catch((error) => {
      handleRouteError(res, error, req.logger || console, {
        route: req.route?.path,
        method: req.method,
        instance: req.originalUrl,
      });
    });
  };
}
