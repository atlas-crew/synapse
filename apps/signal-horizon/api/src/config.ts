/**
 * Signal Horizon Hub - Configuration
 * Environment-based configuration with validation
 */

import { z } from 'zod';

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Normalizes environment variables to lowercase for case-insensitive matching.
 * Used for enums like NODE_ENV, LOG_LEVEL, and boolean flags.
 */
const normalize = (val: unknown) => (typeof val === 'string' ? val.toLowerCase() : val);

/**
 * Parses a string value as a boolean (case-insensitive).
 * Accepts: true, 1, yes, y, on
 */
const booleanString = (defaultValue: 'true' | 'false' = 'false') =>
  z.preprocess(normalize, z.string())
    .transform((val) => ['true', '1', 'yes', 'y', 'on'].includes(val))
    .catch(defaultValue === 'true');

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
 * Helper to parse an optional string to positive integer with range validation
 */
const optionalPositiveIntString = (min: number, max: number) =>
  z
    .string()
    .optional()
    .transform((val) => (val === undefined ? undefined : parseInt(val, 10)))
    .refine((val) => val === undefined || (!isNaN(val) && val >= min && val <= max), {
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
  NODE_ENV: z.preprocess(normalize, z.enum(['development', 'production', 'test'])).default('development'),
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

  // Sensor compatibility (optional)
  SENSOR_MIN_VERSION: z.string().regex(/^\d+\.\d+\.\d+/, 'Version must be semver format').optional(),
  SENSOR_MAX_VERSION: z.string().regex(/^\d+\.\d+\.\d+/, 'Version must be semver format').optional(),

  // Aggregator
  SIGNAL_BATCH_SIZE: positiveIntString(1, 10000).catch(100),
  SIGNAL_BATCH_TIMEOUT_MS: positiveIntString(100, 60000).catch(5000), // 100ms - 60s

  // Broadcaster
  BLOCKLIST_PUSH_DELAY_MS: positiveIntString(0, 5000).catch(50), // 0 - 5s
  BLOCKLIST_CACHE_SIZE: positiveIntString(1000, 1000000).catch(100000), // 1K - 1M

  // Security
  API_KEY_HEADER: z.string().min(1).default('X-API-Key'),
  TELEMETRY_JWT_SECRET: z.string().min(16).optional(),
  JWT_SECRET: z.string().min(16).optional(),
  JWT_EXPIRATION_SECONDS: positiveIntString(60, 86400).catch(3600), // 1m - 24h
  REFRESH_TOKEN_EXPIRATION_SECONDS: positiveIntString(3600, 2592000).catch(604800), // 1h - 30d
  CORS_ORIGINS: z
    .string()
    .default('http://localhost:5173,http://localhost:4200,http://localhost:5180,http://127.0.0.1:5180'),

  // Logging
  LOG_LEVEL: z.preprocess(normalize, z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace'])).default('info'),

  // Risk Server (upstream Synapse proxy)
  RISK_SERVER_URL: z.string().url().default('http://localhost:3000'),

  // Direct Synapse WAF connection (optional)
  // When set, beam routes will fetch directly from synapse-waf admin API
  // instead of going through risk-server
  SYNAPSE_DIRECT_URL: z.string().url().optional(),

  // Sensor Bridge (bridges synapse-waf to fleet management)
  // Requires SYNAPSE_DIRECT_URL to be set
  SENSOR_BRIDGE_ENABLED: booleanString('false'),
  SENSOR_BRIDGE_API_KEY: z.string().optional(),
  SENSOR_BRIDGE_SENSOR_ID: z.string().default('synapse-waf-1'),
  SENSOR_BRIDGE_SENSOR_NAME: z.string().default('Synapse WAF'),
  SENSOR_BRIDGE_HEARTBEAT_MS: positiveIntString(5000, 120000).catch(15000), // 5s - 2min

  // Fleet command feature flags
  FLEET_COMMAND_TOGGLE_CHAOS_ENABLED: booleanString('false'),
  FLEET_COMMAND_TOGGLE_MTD_ENABLED: booleanString('false'),

  // ClickHouse (optional - for historical data)
  CLICKHOUSE_ENABLED: booleanString('false'),
  CLICKHOUSE_HOST: z.string().default('localhost'),
  CLICKHOUSE_HTTP_PORT: portString.catch(8123),
  CLICKHOUSE_DB: z.string().default('signal_horizon'),
  CLICKHOUSE_USER: z.string().default('default'),
  CLICKHOUSE_PASSWORD: z.string().default('clickhouse'),
  CLICKHOUSE_COMPRESSION: booleanString('true'),
  CLICKHOUSE_MAX_CONNECTIONS: positiveIntString(1, 200).catch(25),
  CLICKHOUSE_QUERY_TIMEOUT_SECONDS: positiveIntString(1, 600).catch(30),
  CLICKHOUSE_QUERY_QUEUE_TIMEOUT_SECONDS: optionalPositiveIntString(1, 600),
  CLICKHOUSE_MAX_RESULT_ROWS: positiveIntString(1, 1000000).catch(100000),
  CLICKHOUSE_MAX_INFLIGHT_QUERIES: optionalPositiveIntString(1, 500),
  CLICKHOUSE_MAX_INFLIGHT_STREAM_QUERIES: optionalPositiveIntString(1, 200),
}).refine((data) => {
  // Production-only security checks (labs-mmft.6, labs-msll)
  if (data.NODE_ENV === 'production') {
    if (!data.JWT_SECRET) return false;
    if (!data.TELEMETRY_JWT_SECRET) return false;
  }
  return true;
}, {
  message: 'JWT_SECRET and TELEMETRY_JWT_SECRET are required in production mode',
  path: ['JWT_SECRET'],
}).refine((data) => {
  if (data.NODE_ENV === 'production' && data.CLICKHOUSE_ENABLED) {
    // Insecure defaults are strictly forbidden in production
    return data.CLICKHOUSE_PASSWORD !== 'clickhouse' && data.CLICKHOUSE_PASSWORD.length >= 12;
  }
  return true;
}, {
  message: 'Insecure or weak CLICKHOUSE_PASSWORD is not allowed in production (min 12 chars)',
  path: ['CLICKHOUSE_PASSWORD'],
}).refine((data) => {
  if (data.NODE_ENV === 'production') {
    // Ensure DATABASE_URL doesn't point to localhost in production
    const dbUrl = data.DATABASE_URL.toLowerCase();
    return !dbUrl.includes('localhost') && !dbUrl.includes('127.0.0.1');
  }
  return true;
}, {
  message: 'DATABASE_URL should not point to localhost in production',
  path: ['DATABASE_URL'],
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
  const corsOriginsRaw = env.CORS_ORIGINS
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  const hasCorsWildcard = corsOriginsRaw.includes('*');
  const corsOrigins = corsOriginsRaw.filter((origin) => origin !== '*');

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
      protocol: {
        supportedVersions: ['1.0'],
        legacyVersion: '0.9',
      },
    },

    sensorCompatibility: {
      minVersion: env.SENSOR_MIN_VERSION,
      maxVersion: env.SENSOR_MAX_VERSION,
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
      corsOrigins,
    },

    telemetry: {
      jwtSecret: env.TELEMETRY_JWT_SECRET ?? env.JWT_SECRET,
      jwtExpirationSeconds: env.JWT_EXPIRATION_SECONDS,
      refreshTokenExpirationSeconds: env.REFRESH_TOKEN_EXPIRATION_SECONDS,
    },

    logging: {
      level: env.LOG_LEVEL,
    },

    // Risk Server (upstream Synapse)
    riskServer: {
      url: env.RISK_SERVER_URL,
    },

    // Direct Synapse WAF connection (optional)
    synapseDirect: {
      url: env.SYNAPSE_DIRECT_URL,
      enabled: !!env.SYNAPSE_DIRECT_URL,
    },

    // Sensor Bridge (bridges synapse-waf to fleet management)
    sensorBridge: {
      enabled: env.SENSOR_BRIDGE_ENABLED && !!env.SYNAPSE_DIRECT_URL,
      apiKey: env.SENSOR_BRIDGE_API_KEY,
      sensorId: env.SENSOR_BRIDGE_SENSOR_ID,
      sensorName: env.SENSOR_BRIDGE_SENSOR_NAME,
      heartbeatIntervalMs: env.SENSOR_BRIDGE_HEARTBEAT_MS,
    },

    fleetCommands: {
      enableToggleChaos: env.FLEET_COMMAND_TOGGLE_CHAOS_ENABLED,
      enableToggleMtd: env.FLEET_COMMAND_TOGGLE_MTD_ENABLED,
    },

    // ClickHouse for historical data (optional)
    clickhouse: {
      enabled: env.CLICKHOUSE_ENABLED,
      host: env.CLICKHOUSE_HOST,
      port: env.CLICKHOUSE_HTTP_PORT, // Already parsed
      database: env.CLICKHOUSE_DB,
      username: env.CLICKHOUSE_USER,
      password: env.CLICKHOUSE_PASSWORD,
      compression: env.CLICKHOUSE_COMPRESSION,
      maxOpenConnections: env.CLICKHOUSE_MAX_CONNECTIONS, // Already parsed
      queryTimeoutSec: env.CLICKHOUSE_QUERY_TIMEOUT_SECONDS, // Already parsed
      queueTimeoutSec: env.CLICKHOUSE_QUERY_QUEUE_TIMEOUT_SECONDS ?? env.CLICKHOUSE_QUERY_TIMEOUT_SECONDS,
      maxRowsLimit: env.CLICKHOUSE_MAX_RESULT_ROWS, // Already parsed
      maxInFlightQueries: env.CLICKHOUSE_MAX_INFLIGHT_QUERIES ?? env.CLICKHOUSE_MAX_CONNECTIONS,
      maxInFlightStreamQueries:
        env.CLICKHOUSE_MAX_INFLIGHT_STREAM_QUERIES ??
        Math.min(2, env.CLICKHOUSE_MAX_INFLIGHT_QUERIES ?? env.CLICKHOUSE_MAX_CONNECTIONS),
    },
  } as const;

  // Log config summary in development
  if (config.isDev) {
    console.log('✅ Configuration loaded:');
    console.log(`   Environment: ${config.env}`);
    console.log(`   Server: ${config.server.host}:${config.server.port}`);
    console.log(`   WebSocket paths: ${config.websocket.sensorPath}, ${config.websocket.dashboardPath}`);
    console.log(`   Log level: ${config.logging.level}`);
    console.log(`   Risk Server: ${config.riskServer.url}`);
    console.log(`   Synapse Direct: ${config.synapseDirect.enabled ? config.synapseDirect.url : 'disabled'}`);
    console.log(`   Sensor Bridge: ${config.sensorBridge.enabled ? `${config.sensorBridge.sensorId} (${config.sensorBridge.sensorName})` : 'disabled'}`);
    console.log(`   ClickHouse: ${config.clickhouse.enabled ? `${config.clickhouse.host}:${config.clickhouse.port}` : 'disabled'}`);
  }

  if (hasCorsWildcard) {
    console.warn(
      '⚠️  CORS_ORIGINS contains "*" which is not allowed. Provide explicit trusted origins.'
    );
  }

  return config;
}

export const config = loadConfig();
export type Config = typeof config;
