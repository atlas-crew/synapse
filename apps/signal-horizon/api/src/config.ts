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
  TELEMETRY_JWT_SECRET: z.string().min(16).optional(),
  JWT_SECRET: z.string().min(16).optional(),
  CORS_ORIGINS: z
    .string()
    .default('http://localhost:5173,http://localhost:4200,http://localhost:5180,http://127.0.0.1:5180'),

  // Logging
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  // Risk Server (upstream Synapse proxy)
  RISK_SERVER_URL: z.string().url().default('http://localhost:3000'),

  // Direct Synapse-Pingora connection (optional)
  // When set, beam routes will fetch directly from synapse-pingora admin API
  // instead of going through risk-server
  SYNAPSE_DIRECT_URL: z.string().url().optional(),

  // Sensor Bridge (bridges synapse-pingora to fleet management)
  // Requires SYNAPSE_DIRECT_URL to be set
  SENSOR_BRIDGE_ENABLED: z.enum(['true', 'false']).default('false'),
  SENSOR_BRIDGE_API_KEY: z.string().optional(),
  SENSOR_BRIDGE_SENSOR_ID: z.string().default('synapse-pingora-1'),
  SENSOR_BRIDGE_SENSOR_NAME: z.string().default('Synapse Pingora WAF'),
  SENSOR_BRIDGE_HEARTBEAT_MS: positiveIntString(5000, 120000).catch(15000), // 5s - 2min

  // ClickHouse (optional - for historical data)
  CLICKHOUSE_ENABLED: z.enum(['true', 'false']).default('false'),
  CLICKHOUSE_HOST: z.string().default('localhost'),
  CLICKHOUSE_HTTP_PORT: portString.catch(8123),
  CLICKHOUSE_DB: z.string().default('signal_horizon'),
  CLICKHOUSE_USER: z.string().default('default'),
  CLICKHOUSE_PASSWORD: z.string().default('clickhouse'),
  CLICKHOUSE_COMPRESSION: z.enum(['true', 'false']).default('true'),
  CLICKHOUSE_MAX_CONNECTIONS: positiveIntString(1, 100).catch(10),
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
    },

    logging: {
      level: env.LOG_LEVEL,
    },

    // Risk Server (upstream Synapse)
    riskServer: {
      url: env.RISK_SERVER_URL,
    },

    // Direct Synapse-Pingora connection (optional)
    synapseDirect: {
      url: env.SYNAPSE_DIRECT_URL,
      enabled: !!env.SYNAPSE_DIRECT_URL,
    },

    // Sensor Bridge (bridges synapse-pingora to fleet management)
    sensorBridge: {
      enabled: env.SENSOR_BRIDGE_ENABLED === 'true' && !!env.SYNAPSE_DIRECT_URL,
      apiKey: env.SENSOR_BRIDGE_API_KEY,
      sensorId: env.SENSOR_BRIDGE_SENSOR_ID,
      sensorName: env.SENSOR_BRIDGE_SENSOR_NAME,
      heartbeatIntervalMs: env.SENSOR_BRIDGE_HEARTBEAT_MS,
    },

    // ClickHouse for historical data (optional)
    clickhouse: {
      enabled: env.CLICKHOUSE_ENABLED === 'true',
      host: env.CLICKHOUSE_HOST,
      port: env.CLICKHOUSE_HTTP_PORT, // Already parsed
      database: env.CLICKHOUSE_DB,
      username: env.CLICKHOUSE_USER,
      password: env.CLICKHOUSE_PASSWORD,
      compression: env.CLICKHOUSE_COMPRESSION === 'true',
      maxOpenConnections: env.CLICKHOUSE_MAX_CONNECTIONS, // Already parsed
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
