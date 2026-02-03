/**
 * Structured logging with pino
 */
import pino from 'pino';

/**
 * Create base logger instance with appropriate configuration
 */
export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  // Note: messageFormat functions can't be serialized in Node.js 25+ worker threads
  // Using simple pino-pretty config instead
  transport: process.env.NODE_ENV !== 'production' ? {
    target: 'pino-pretty',
    options: {
      colorize: true,
      levelFirst: true,
      translateTime: 'HH:MM:ss Z',
      ignore: 'pid,hostname',
    },
  } : undefined,
  formatters: {
    level: (label) => {
      return { level: label };
    },
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

/**
 * Create a child logger with additional context
 */
export function createLogger(context: Record<string, unknown>) {
  return logger.child(context);
}

/**
 * Express middleware to add request ID and logger to request context
 */
export function requestLoggerMiddleware(req: any, res: any, next: any) {
  const requestId = req.headers['x-request-id'] ||
                    req.headers['x-correlation-id'] ||
                    crypto.randomUUID();

  req.requestId = requestId;
  req.logger = logger.child({ requestId });

  res.setHeader('x-request-id', requestId);

  next();
}
