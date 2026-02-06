/**
 * Request Timeout Middleware (WS4-008)
 *
 * Enforces request timeouts to prevent resource exhaustion from
 * slow or hanging requests (Slowloris-style attacks).
 *
 * OWASP Reference: A05:2021 - Security Misconfiguration
 * CWE-400: Uncontrolled Resource Consumption
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';

declare global {
  /** 
   * Extending Express Request interface to include timeout metadata.
   * This allows downstream middleware and logging to access timeout context.
   * 
   */
  namespace Express {
    interface Request {
      timeoutInfo?: {
        timeout: number;
        startTime: number;
      };
    }
  }
}

export interface TimeoutOptions {
  /**
   * Default timeout in milliseconds
   * @default 30000 (30 seconds)
   */
  timeout?: number;

  /**
   * Routes to skip timeout (e.g., WebSocket, SSE endpoints)
   */
  skipRoutes?: (string | RegExp)[];

  /**
   * Routes with custom timeouts (e.g., longer for complex queries)
   */
  customTimeouts?: Map<string | RegExp, number>;

  /**
   * Header name for timeout info
   * @default 'X-Request-Timeout'
   */
  headerName?: string;

  /**
   * Custom timeout handler
   */
  onTimeout?: (req: Request, res: Response) => void;
}

const DEFAULT_OPTIONS: Required<Omit<TimeoutOptions, 'onTimeout' | 'customTimeouts'>> & {
  customTimeouts: Map<string | RegExp, number>;
} = {
  timeout: 30000,
  skipRoutes: [],
  customTimeouts: new Map(),
  headerName: 'X-Request-Timeout',
};

/**
 * Checks if a path matches any pattern in the list
 */
function matchesRoute(path: string, patterns: (string | RegExp)[]): boolean {
  return patterns.some((pattern) => {
    if (typeof pattern === 'string') {
      return path === pattern || path.startsWith(pattern + '/');
    }
    return pattern.test(path);
  });
}

/**
 * Gets custom timeout for a route, if defined
 */
function getCustomTimeout(
  path: string,
  customTimeouts: Map<string | RegExp, number>
): number | null {
  for (const [pattern, timeout] of customTimeouts) {
    if (typeof pattern === 'string') {
      if (path === pattern || path.startsWith(pattern + '/')) {
        return timeout;
      }
    } else if (pattern.test(path)) {
      return timeout;
    }
  }
  return null;
}

/**
 * Creates request timeout middleware
 *
 * @example
 * ```typescript
 * app.use(requestTimeout({
 *   timeout: 30000,
 *   customTimeouts: new Map([
 *     ['/api/v1/hunt', 60000],
 *     [/^\/api\/v1\/reports/, 120000],
 *   ]),
 *   skipRoutes: ['/api/v1/ws', '/api/v1/events'],
 * }));
 * ```
 */
export function requestTimeout(options: TimeoutOptions = {}): RequestHandler {
  const config = {
    ...DEFAULT_OPTIONS,
    ...options,
    customTimeouts: options.customTimeouts ?? DEFAULT_OPTIONS.customTimeouts,
  };

  return (req: Request, res: Response, next: NextFunction): void => {
    // Skip timeout for excluded routes (WebSocket, SSE, etc.)
    if (matchesRoute(req.path, config.skipRoutes)) {
      next();
      return;
    }

    // Get effective timeout (custom if available, otherwise default)
    const customTimeout = getCustomTimeout(req.path, config.customTimeouts);
    const effectiveTimeout = customTimeout ?? config.timeout;

    // Attach timeout info to request for debugging
    req.timeoutInfo = {
      timeout: effectiveTimeout,
      startTime: Date.now(),
    };

    // Set timeout header
    res.setHeader(config.headerName, effectiveTimeout.toString());

    // Track if response has been sent
    let responseSent = false;

    // Set up timeout
    const timeoutId = setTimeout(() => {
      if (responseSent) return;
      responseSent = true;

      if (config.onTimeout) {
        config.onTimeout(req, res);
        return;
      }

      res.status(408).json({
        error: 'Request Timeout',
        message: `Request exceeded ${effectiveTimeout}ms timeout`,
        code: 'REQUEST_TIMEOUT',
        timeout: effectiveTimeout,
      });
    }, effectiveTimeout);

    // Clean up timeout on response completion
    const cleanup = () => {
      responseSent = true;
      clearTimeout(timeoutId);
    };

    res.on('finish', cleanup);
    res.on('close', cleanup);
    res.on('error', cleanup);

    next();
  };
}

/**
 * Pre-configured timeout presets for common use cases
 */
export const TimeoutPresets: Record<string, () => RequestHandler> = {
  /**
   * Standard 30-second timeout
   */
  standard: () => requestTimeout({ timeout: 30000 }),

  /**
   * Extended 60-second timeout for complex operations
   */
  extended: () => requestTimeout({ timeout: 60000 }),

  /**
   * Health check timeout (5 seconds)
   */
  health: () => requestTimeout({ timeout: 5000 }),

  /**
   * Signal Horizon-specific configuration
   */
  signalHorizon: () =>
    requestTimeout({
      timeout: 30000,
      skipRoutes: [
        '/api/v1/ws',
        '/api/v1/events',
        '/health',
        '/ready',
        /^\/api\/v1\/stream/,
      ],
      customTimeouts: new Map<string | RegExp, number>([
        ['/api/v1/hunt', 60000],
        [/^\/api\/v1\/synapse\/evaluate/, 60000],
        [/^\/api\/v1\/reports/, 120000],
        [/^\/api\/v1\/export/, 180000],
        [/^\/api\/v1\/fleet\/.*\/firmware/, 120000],
      ]),
    }),
};

export default requestTimeout;
