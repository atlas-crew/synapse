/**
 * Signal Horizon Hub - Configuration
 * Environment-based configuration with validation
 */

import { z } from 'zod';

/**
 * Helper to parse string to positive integer with range validation
 */
const positiveIntString = (min: number, max: number) =>
  z.string()
    .transform((val) => parseInt(val, 10))
    .refine((val) => !isNaN(val) && val >= min && val <= max, {
      message: `Must be an integer between ${min} and ${max}`,
    });

/**
 * Helper to parse port number
 */
const portString = z.string()
  .transform((val) => parseInt(val, 10))
  .refine((val) => !isNaN(val) && val >= 1 && val <= 65535, {
    message: 'Port must be between 1 and 65535',
  });

const envSchema = z.object({
  // Server
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: portString.catch(3100),
  HOST: z.string().default('0.0.0.0'),

  // Database
  DATABASE_URL: z.string().url({ message: 'DATABASE_URL must be a valid URL' }),

  // WebSocket
  WS_SENSOR_PATH: z.string().startsWith('/').default('/ws/sensors'),
  WS_DASHBOARD_PATH: z.string().startsWith('/').default('/ws/dashboard'),
  WS_HEARTBEAT_INTERVAL_MS: positiveIntString(1000, 300000).catch(30000), // 1s - 5min
  WS_MAX_SENSOR_CONNECTIONS: positiveIntString(1, 10000).catch(1000),
  WS_MAX_DASHBOARD_CONNECTIONS: positiveIntString(1, 1000).catch(100),

  // Aggregator
  SIGNAL_BATCH_SIZE: positiveIntString(1, 10000).catch(100),
  SIGNAL_BATCH_TIMEOUT_MS: positiveIntString(100, 60000).catch(5000), // 100ms - 60s

  // Broadcaster
  BLOCKLIST_PUSH_DELAY_MS: positiveIntString(0, 5000).catch(50), // 0 - 5s
  BLOCKLIST_CACHE_SIZE: positiveIntString(1000, 1000000).catch(100000), // 1K - 1M

  // Security
  API_KEY_HEADER: z.string().min(1).default('X-API-Key'),
  CORS_ORIGINS: z.string().default('*'),

  // Logging
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
});

function loadConfig() {
  const parsed = envSchema.safeParse(process.env);

  if (!parsed.success) {
    console.error('❌ Invalid environment configuration:');
    const formatted = parsed.error.format();
    // Log each error clearly
    for (const [key, value] of Object.entries(formatted)) {
      if (key !== '_errors' && value && typeof value === 'object' && '_errors' in value) {
        const errors = (value as { _errors: string[] })._errors;
        if (errors.length > 0) {
          console.error(`  ${key}: ${errors.join(', ')}`);
        }
      }
    }
    process.exit(1);
  }

  const env = parsed.data;

  // Build validated config object
  const config = {
    env: env.NODE_ENV,
    isDev: env.NODE_ENV === 'development',
    isProd: env.NODE_ENV === 'production',
    isTest: env.NODE_ENV === 'test',

    server: {
      port: env.PORT, // Already parsed to number by Zod
      host: env.HOST,
    },

    database: {
      url: env.DATABASE_URL,
    },

    websocket: {
      sensorPath: env.WS_SENSOR_PATH,
      dashboardPath: env.WS_DASHBOARD_PATH,
      heartbeatIntervalMs: env.WS_HEARTBEAT_INTERVAL_MS, // Already parsed
      maxSensorConnections: env.WS_MAX_SENSOR_CONNECTIONS, // Already parsed
      maxDashboardConnections: env.WS_MAX_DASHBOARD_CONNECTIONS, // Already parsed
    },

    aggregator: {
      batchSize: env.SIGNAL_BATCH_SIZE, // Already parsed
      batchTimeoutMs: env.SIGNAL_BATCH_TIMEOUT_MS, // Already parsed
    },

    broadcaster: {
      pushDelayMs: env.BLOCKLIST_PUSH_DELAY_MS, // Already parsed
      cacheSize: env.BLOCKLIST_CACHE_SIZE, // Already parsed
    },

    security: {
      apiKeyHeader: env.API_KEY_HEADER,
      corsOrigins: env.CORS_ORIGINS === '*' ? '*' : env.CORS_ORIGINS.split(','),
    },

    logging: {
      level: env.LOG_LEVEL,
    },
  } as const;

  // Log config summary in development
  if (config.isDev) {
    console.log('✅ Configuration loaded:');
    console.log(`   Environment: ${config.env}`);
    console.log(`   Server: ${config.server.host}:${config.server.port}`);
    console.log(`   WebSocket paths: ${config.websocket.sensorPath}, ${config.websocket.dashboardPath}`);
    console.log(`   Log level: ${config.logging.level}`);
  }

  return config;
}

export const config = loadConfig();
export type Config = typeof config;
