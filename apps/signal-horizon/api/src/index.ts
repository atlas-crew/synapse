/**
 * Signal Horizon Hub - Entry Point
 * Fleet intelligence for collective defense across Synapse sensors
 */

import './bootstrap-env.js';
import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'node:http';
import type { Socket } from 'node:net';
import { pino } from 'pino';
import { pinoHttp } from 'pino-http';
import { PrismaClient } from '@prisma/client';

import { config } from './config.js';
import { SensorGateway } from './websocket/sensor-gateway.js';
import { DashboardGateway } from './websocket/dashboard-gateway.js';
import { Aggregator } from './services/aggregator/index.js';
import { Correlator } from './services/correlator/index.js';
import { Broadcaster } from './services/broadcaster/index.js';
import { HuntService } from './services/hunt/index.js';
import { APIIntelligenceService } from './services/api-intelligence/index.js';
import { createApiRouter } from './api/routes/index.js';
import { createOpsRoutes } from './api/routes/ops.js';
import { ClickHouseService, ClickHouseRetryBuffer } from './storage/clickhouse/index.js';
import { FileRetryStore } from './storage/clickhouse/persistent-store.js';
import path from 'node:path';
// Fleet management services
import { WarRoomService, type WarRoomConfig } from './services/warroom/index.js';
import {
  AutomatedPlaybookTrigger,
  InMemoryTriggerCooldownStore,
  RedisTriggerCooldownStore,
  ResilientTriggerCooldownStore,
} from './services/warroom/automated-trigger.js';
import { PlaybookService } from './services/warroom/playbook-service.js';
import { FleetAggregator } from './services/fleet/fleet-aggregator.js';
import { PreferenceService } from './services/fleet/preference-service.js';
import { fleetCommandFeatures } from './services/fleet/command-features.js';
import { ConfigManager } from './services/fleet/config-manager.js';
import { FleetCommander } from './services/fleet/fleet-commander.js';
import { RuleDistributor } from './services/fleet/rule-distributor.js';
import { RedisDeploymentStateStore } from './services/fleet/deployment-state-store.js';
import { FleetIntelService } from './services/fleet/fleet-intel.js';
import { FleetSessionQueryService } from './services/fleet/session-query.js';
import {
  ImpossibleTravelService,
  InMemoryUserHistoryStore,
  RedisUserHistoryStore,
  ResilientUserHistoryStore,
} from './services/impossible-travel.js';
import { SecurityAuditService } from './services/audit/security-audit.js';
import { DataRetentionService } from './jobs/data-retention.js';
import { createRetentionQueue, createRetentionWorker, type RetentionJobData } from './jobs/retention-queue.js';
import { createSigmaHuntQueue, createSigmaHuntWorker, type SigmaHuntJobData } from './jobs/sigma-hunt-queue.js';
import { createBlocklistQueue, createBlocklistWorker, type BlocklistJobData } from './jobs/blocklist-queue.js';
import { metrics } from './services/metrics.js';
import {
  ThreatService,
  InMemoryRecentSignalsStore,
  RedisRecentSignalsStore,
  ResilientRecentSignalsStore,
} from './services/threat-service.js';
// Protocol handlers
import { CommandSender } from './protocols/command-sender.js';
// Job queue and workers
import { createRolloutWorker, stopRolloutWorker, recoverStalledRollouts, closeQueue, closeWorker } from './jobs/index.js';
import type { Queue, Worker } from 'bullmq';
import type { RolloutJobData } from './jobs/queue.js';
import type { SharingPreference } from './types/protocol.js';
import { SigmaHuntService } from './services/sigma-hunt/index.js';
// Tunnel broker for remote access
import { TunnelBroker, type TunnelCapability } from './websocket/tunnel-broker.js';
import { SynapseProxyService } from './services/synapse-proxy.js';
import { FleetIntelIngestionService } from './services/fleet-intel/ingestion-service.js';
import { initSynapseDirectAdapter } from './services/synapse-direct.js';
import { initSensorBridge, getSensorBridge } from './services/sensor-bridge.js';
import { matchUpgradePath } from './websocket/upgrade-path.js';
import {
  TunnelSessionStore,
} from './websocket/tunnel-session-store.js';
import { WebSocketServer, WebSocket } from 'ws';
import { createHash, randomUUID } from 'node:crypto';
import { computeHmac } from './lib/safe-compare.js';
// Security middleware
import { jsonDepthLimit } from './middleware/json-depth.js';
import { requestId } from './middleware/request-id.js';
import { enforceHttps } from './middleware/security.js';
import { createTelemetryRouter } from './api/telemetry.js';
import { PrismaNonceStore } from './middleware/replay-protection.js';
import { AuthCoverageAggregator } from './services/auth-coverage-aggregator.js';
import { createAuthCoverageRoutes } from './api/routes/auth-coverage.js';
import { getSharedRedisKv, type SharedRedisKv } from './storage/redis/shared-kv.js';
import {
  InMemoryBlocklistStore,
  RedisBlocklistStore,
  ResilientBlocklistStore,
} from './services/broadcaster/blocklist-store.js';
import {
  InMemorySavedQueryStore,
  RedisSavedQueryStore,
  ResilientSavedQueryStore,
} from './services/hunt/saved-query-store.js';
import {
  InMemorySensorMetricsStore,
  RedisSensorMetricsStore,
  ResilientSensorMetricsStore,
} from './services/fleet/sensor-metrics-store.js';

// Initialize logger with sensitive header redaction (WS3-004, WS5-006)
const logger = pino({
  level: config.logging.level,
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'req.headers["x-api-key"]',
      'req.headers["x-auth-token"]',
      'req.headers["x-admin-key"]',
      // Redact sensitive body fields
      'req.body.apiKey',
      'req.body.password',
      'req.body.token',
      'req.body.secret',
      'req.body.clientSecret',
      'req.body.signature',
      // Also redact in response context
      'res.headers["set-cookie"]',
    ],
    censor: '[REDACTED]',
  },
  // Note: messageFormat functions can't be serialized in Node.js 25+ worker threads
  transport: config.isDev
    ? {
        target: 'pino-pretty',
        options: {
          colorize: true,
          levelFirst: true,
          translateTime: 'HH:MM:ss.l',
          ignore: 'pid,hostname',
        },
      }
    : undefined,
});

// Initialize Prisma
const prisma = new PrismaClient({
  log: config.isDev ? ['query', 'info', 'warn', 'error'] : ['error'],
});

// Initialize Express
const app = express();
const httpServer = createServer(app);

// Request ID middleware - must be first for tracing
// Accepts X-Request-ID header or generates UUID v4
app.use(requestId());

// Trust the first proxy level (e.g. Nginx, ALB) to ensure req.ip and req.secure are accurate (labs-mmft.4)
app.set('trust proxy', 1);

// Enforce HTTPS in production (labs-mmft.4)
app.use(enforceHttps);

// Middleware - Security headers with comprehensive protection
app.use(helmet({
  // Content Security Policy - restrict resource loading
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for error messages
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", 'wss:', 'ws:'], // Allow WebSocket connections
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'none'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  // Strict Transport Security - force HTTPS (1 year)
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  // Prevent clickjacking (X-Frame-Options: DENY)
  frameguard: { action: 'deny' },
  // Control referrer information
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  // Prevent DNS prefetching
  dnsPrefetchControl: { allow: false },
  // X-Content-Type-Options: nosniff (enabled by default)
  // X-Powered-By: removed by default
}));
app.use(cors({
  origin: config.security.corsOrigins,
  credentials: true,
}));
// Parse cookies before auth middleware so req.cookies is available (labs-n6nf)
app.use(cookieParser());
// SH-004: Reduced from 10mb — most API payloads are well under 1MB.
// File upload routes use multipart (not JSON) and have their own limits.
app.use(express.json({ limit: '2mb' }));
// JSON depth limiting to prevent stack overflow attacks (WS4-003)
app.use(jsonDepthLimit(20));
app.use(pinoHttp({
  logger,
  // Include request ID in all log entries for tracing
  genReqId: (req) => (req as Express.Request).id ?? 'unknown',
  customProps: (req) => ({
    requestId: (req as Express.Request).id,
  }),
}));

// Health check
app.get('/health', (_req, res) => {
  res.json({
    status: 'healthy',
    service: 'signal-horizon-hub',
    version: '0.1.0',
    timestamp: new Date().toISOString(),
  });
});

// Ready check (includes database connectivity)
app.get('/ready', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;

    // Check ClickHouse if enabled
    let clickhouseStatus: 'connected' | 'disabled' | 'disconnected' = 'disabled';
    if (clickhouse) {
      try {
        await clickhouse.ping();
        clickhouseStatus = 'connected';
      } catch {
        clickhouseStatus = 'disconnected';
      }
    }

    // Check Redis connectivity
    let redisStatus: 'connected' | 'disabled' | 'disconnected' = 'disabled';
    if (sharedRedis) {
      try {
        await sharedRedis.client.ping();
        redisStatus = 'connected';
      } catch {
        redisStatus = 'disconnected';
      }
    }

    res.json({
      status: 'ready',
      database: 'connected',
      clickhouse: clickhouseStatus,
      redis: redisStatus,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(503).json({
      status: 'not_ready',
      database: 'disconnected',
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// API routes placeholder
app.get('/api/v1/status', (_req, res) => {
  res.json({
    hub: 'signal-horizon',
    version: '0.1.0',
    uptime: process.uptime(),
    connections: {
      sensors: sensorGateway?.getConnectionCount() ?? 0,
      dashboards: dashboardGateway?.getConnectionCount() ?? 0,
    },
  });
});

// Initialize services
let clickhouse: ClickHouseService | null = null;
let telemetryRetryBuffer: ClickHouseRetryBuffer | null = null;
let huntService: HuntService;
let aggregator: Aggregator;
let correlator: Correlator;
let broadcaster: Broadcaster;
let apiIntelligenceService: APIIntelligenceService;
let threatService: ThreatService | null = null;
let sensorGateway: SensorGateway;
let dashboardGateway: DashboardGateway;
// Fleet management services
let commandSender: CommandSender;
let fleetAggregator: FleetAggregator;
let configManager: ConfigManager;
let fleetCommander: FleetCommander;
let ruleDistributor: RuleDistributor;
let preferenceService: PreferenceService;
let impossibleTravelService: ImpossibleTravelService;
let tunnelBroker: TunnelBroker;
let tunnelSessionStore: TunnelSessionStore;
let synapseProxy: SynapseProxyService;
let fleetIntelIngestion: FleetIntelIngestionService;
let sessionQueryService: FleetSessionQueryService;
let fleetIntelService: FleetIntelService;
let warRoomService: WarRoomService;
let securityAuditService: SecurityAuditService;
let playbookService: PlaybookService;
let playbookTrigger: AutomatedPlaybookTrigger;
let tunnelWss: WebSocketServer;
let rolloutWorker: Worker<RolloutJobData, void>;
let blocklistQueue: Queue<BlocklistJobData> | null = null;
let blocklistWorker: Worker<BlocklistJobData, void> | null = null;
let retentionQueue: Queue<RetentionJobData> | null = null;
let retentionWorker: Worker<RetentionJobData, Record<string, number>> | null = null;
let sigmaHuntQueue: Queue<SigmaHuntJobData> | null = null;
let sigmaHuntWorker: Worker<SigmaHuntJobData, { tenants: number; rules: number; matches: number; leadsUpserted: number }> | null = null;
let retentionInterval: NodeJS.Timeout | null = null;
let retentionTimeout: NodeJS.Timeout | null = null;
let sharedRedis: SharedRedisKv | null = null;

// ============================================================================
// Tunnel Authentication Handler
// ============================================================================

interface TunnelAuthPayload {
  sensorId: string;
  apiKey: string;
  capabilities?: TunnelCapability[];
  metadata?: {
    hostname?: string;
    version?: string;
    platform?: string;
  };
}

interface TunnelMessage {
  type: string;
  payload: unknown;
  timestamp: string;
}

interface TunnelAuthSuccessPayload {
  sensorId: string;
  sensorName?: string;
  tenantId: string;
  capabilities: TunnelCapability[];
}

function buildTunnelAuthSignaturePayload(params: {
  payload: TunnelAuthSuccessPayload;
  sessionId: string;
  timestamp: string;
}): string {
  const capabilities = [...params.payload.capabilities].sort().join(',');
  const sensorName = params.payload.sensorName ?? '';
  return [
    'type=auth-success',
    `sensorId=${params.payload.sensorId}`,
    `tenantId=${params.payload.tenantId}`,
    `sessionId=${params.sessionId}`,
    `timestamp=${params.timestamp}`,
    `capabilities=${capabilities}`,
    `sensorName=${sensorName}`,
  ].join('\n');
}

/**
 * Handle incoming sensor tunnel connection with authentication
 */
function handleTunnelSensorConnection(
  ws: WebSocket,
  db: PrismaClient,
  log: typeof logger
): void {
  const AUTH_TIMEOUT_MS = 10000;
  let authenticated = false;

  // Set auth timeout
  const authTimeout = setTimeout(() => {
    if (!authenticated) {
      log.warn('Tunnel connection auth timeout');
      ws.close(4001, 'Authentication timeout');
    }
  }, AUTH_TIMEOUT_MS);

  ws.once('message', async (data: Buffer | string) => {
    try {
      const str = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);
      const message: TunnelMessage = JSON.parse(str);

      if (message.type !== 'auth') {
        log.warn({ type: message.type }, 'Expected auth message');
        ws.close(4002, 'Expected auth message');
        clearTimeout(authTimeout);
        return;
      }

      const payload = message.payload as TunnelAuthPayload;
      const { sensorId, apiKey, capabilities = ['dashboard'], metadata } = payload;

      if (!sensorId || !apiKey) {
        log.warn('Missing sensorId or apiKey in auth');
        ws.close(4003, 'Missing credentials');
        clearTimeout(authTimeout);
        return;
      }

      // Hash the API key for lookup
      const keyHash = createHash('sha256').update(apiKey).digest('hex');

      // Validate sensor API key against database (must be scoped to this sensor)
      const sensorKeyRecord = await db.sensorApiKey.findFirst({
        where: {
          keyHash,
          status: 'ACTIVE',
          sensorId,
          OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } },
          ],
        },
        select: {
          id: true,
          name: true,
          sensor: {
            select: {
              id: true,
              name: true,
              tenantId: true,
            },
          },
        },
      });

      if (!sensorKeyRecord || !sensorKeyRecord.sensor) {
        log.warn({ sensorId }, 'Invalid or expired sensor API key for tunnel');
        ws.send(JSON.stringify({
          type: 'auth-error',
          payload: { error: 'Invalid or expired sensor API key' },
          timestamp: new Date().toISOString(),
        }));
        ws.close(4004, 'Invalid sensor API key');
        clearTimeout(authTimeout);
        return;
      }

      const sensor = sensorKeyRecord.sensor;
      const tenantId = sensor.tenantId;

      // Authentication successful
      authenticated = true;
      clearTimeout(authTimeout);

      const sessionId = randomUUID();
      const timestamp = new Date().toISOString();
      const authPayload: TunnelAuthSuccessPayload = {
        sensorId: sensor.id,
        sensorName: sensor.name,
        tenantId,
        capabilities,
      };
      const signaturePayload = buildTunnelAuthSignaturePayload({
        payload: authPayload,
        sessionId,
        timestamp,
      });
      const signature = computeHmac('sha256', apiKey, signaturePayload);

      // Send success response
      ws.send(JSON.stringify({
        type: 'auth-success',
        payload: authPayload,
        sessionId,
        timestamp,
        signature,
      }));

      // Hand off to TunnelBroker for connection management
      tunnelBroker.handleSensorConnect(
        ws,
        sensor.id,
        tenantId,
        capabilities,
        metadata
      );

      // Update sensor key last used
      await db.sensorApiKey.update({
        where: { id: sensorKeyRecord.id },
        data: { lastUsedAt: new Date() },
      });

      log.info(
        { sensorId: sensor.id, tenantId, capabilities },
        'Sensor tunnel authenticated and connected'
      );
    } catch (error) {
      log.error({ error }, 'Error processing tunnel auth');
      ws.close(4000, 'Auth error');
      clearTimeout(authTimeout);
    }
  });

  ws.on('error', (error) => {
    log.error({ error: error.message }, 'Tunnel WebSocket error during auth');
    clearTimeout(authTimeout);
  });

  ws.on('close', () => {
    clearTimeout(authTimeout);
  });
}

/**
 * Handle incoming user tunnel connections using first-message auth (labs-c4hh).
 *
 * The sessionId is no longer extracted from the URL path. Instead, the client
 * must send `{ type: 'auth', sessionId: '<id>' }` as its first WebSocket message.
 * This prevents the session token from being logged by proxies, stored in browser
 * history, or leaked via Referer headers.
 */
function handleTunnelUserConnection(
  ws: WebSocket,
  log: typeof logger
): void {
  if (!tunnelBroker) {
    log.error('Tunnel broker not initialized');
    ws.close(1011, 'Tunnel broker unavailable');
    return;
  }

  tunnelBroker.handleUserConnection(ws, async (sessionId: string) => {
    const session = await tunnelSessionStore.get(sessionId);
    if (!session) {
      return null;
    }

    if (session.expiresAt && Date.now() > session.expiresAt.getTime()) {
      await tunnelSessionStore.update(sessionId, { status: 'error', lastActivity: new Date() });
      return null;
    }

    if (session.status !== 'pending') {
      return null;
    }

    // Mark session as connected and track close
    await tunnelSessionStore.update(sessionId, { status: 'connected', lastActivity: new Date() });
    ws.on('close', async () => {
      await tunnelSessionStore.update(sessionId, { status: 'disconnected', lastActivity: new Date() });
    });

    return {
      sessionId: session.id,
      sensorId: session.sensorId,
      tenantId: session.tenantId,
      userId: session.userId,
      type: session.type as 'shell' | 'dashboard' | 'logs',
    };
  });
}

async function start() {
  logger.info('Starting Signal Horizon Hub...');

  // Connect to database
  await prisma.$connect();
  logger.info('Connected to database');

  // Initialize ClickHouse for historical data (if enabled)
  if (config.clickhouse.enabled) {
    clickhouse = new ClickHouseService(config.clickhouse, logger);
    try {
      const isHealthy = await clickhouse.ping();
      if (isHealthy) {
        logger.info('Connected to ClickHouse for historical analytics');
      } else {
        logger.warn('ClickHouse connection failed at startup - service will retry in background');
      }
    } catch (error) {
      logger.warn(
        { error },
        'ClickHouse connection failed - historical queries will be unavailable until reachable'
      );
      // We keep the instance so health checks report 'disconnected' instead of 'disabled' (labs-mmft.25)
    }
  } else {
    logger.info('ClickHouse disabled - using PostgreSQL only (demo mode)');
  }

  // Initialize telemetry ingestion routes (requires ClickHouse)
  if (clickhouse?.isEnabled()) {
    const storePath = path.resolve(process.cwd(), 'data/telemetry-retry.json');
    const persistentStore = new FileRetryStore(storePath, logger);
    telemetryRetryBuffer = new ClickHouseRetryBuffer(clickhouse, logger, {}, persistentStore);
    await telemetryRetryBuffer.start();
  }

  // PEN-006: Use Prisma-backed distributed nonce store for telemetry idempotency (labs-yb6m)
  const idempotencyStore = new PrismaNonceStore(prisma, {
    windowMs: 24 * 60 * 60 * 1000, // 24h window for batch idempotency
  });

  const telemetryRouter = createTelemetryRouter(logger, {
    clickhouse,
    retryBuffer: telemetryRetryBuffer,
    idempotencyStore,
    prisma,
  });
  app.use(telemetryRouter);
  logger.info('Telemetry routes mounted at /telemetry and /_sensor/report');

  /**
   * Prometheus Metrics Endpoint (P1-OBSERVABILITY-002)
   * Protected by bearer token or localhost-only access (labs-igrw).
   */
  app.get('/metrics', async (req, res) => {
    // Allow localhost access for Prometheus scraping without auth
    const clientIp = req.ip ?? req.socket.remoteAddress ?? '';
    const isLocalhost = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1';

    if (!isLocalhost) {
      const authHeader = req.headers.authorization;
      const metricsToken = process.env.METRICS_AUTH_TOKEN;

      if (metricsToken && (!authHeader || authHeader !== `Bearer ${metricsToken}`)) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
    }

    try {
      res.setHeader('Content-Type', metrics.getContentType());
      res.send(await metrics.getMetrics());
    } catch (error) {
      logger.error({ error }, 'Error rendering metrics');
      res.status(500).send('Error rendering metrics');
    }
  });

  // Initialize Synapse Direct adapter for synapse-pingora connection (if configured)
  if (config.synapseDirect.enabled && config.synapseDirect.url) {
    initSynapseDirectAdapter(config.synapseDirect.url, logger);
    logger.info({ url: config.synapseDirect.url }, 'Synapse Direct adapter initialized');
  }

  // Initialize Sensor Bridge (bridges synapse-pingora to fleet management via WebSocket)
  if (config.sensorBridge.enabled && config.synapseDirect.url && config.sensorBridge.apiKey) {
    const bridge = initSensorBridge({
      hubWsUrl: `ws://localhost:${config.server.port}${config.websocket.sensorPath}`,
      pingoraAdminUrl: config.synapseDirect.url,
      apiKey: config.sensorBridge.apiKey,
      sensorId: config.sensorBridge.sensorId,
      sensorName: config.sensorBridge.sensorName,
      heartbeatIntervalMs: config.sensorBridge.heartbeatIntervalMs,
    }, logger);
    // Delay start to ensure WebSocket gateway is ready
    setTimeout(() => {
      bridge.start().catch((err) => {
        logger.error({ err }, 'Failed to start sensor bridge');
      });
    }, 2000);
    logger.info(
      { sensorId: config.sensorBridge.sensorId, sensorName: config.sensorBridge.sensorName },
      'Sensor bridge initialized (will connect after gateway is ready)'
    );
  } else if (config.sensorBridge.enabled) {
    logger.warn(
      'Sensor bridge enabled but missing SYNAPSE_DIRECT_URL or SENSOR_BRIDGE_API_KEY'
    );
  }

  apiIntelligenceService = new APIIntelligenceService(prisma, logger);

  // Initialize protocol handlers for fleet management
  commandSender = new CommandSender();
  logger.info('Protocol handlers initialized');

  // Shared Redis (BullMQ-managed ioredis) for distributed state.
  try {
    sharedRedis = await getSharedRedisKv(logger);
    logger.info('Shared Redis state KV ready');
  } catch (error) {
    sharedRedis = null;
    logger.warn({ error }, 'Shared Redis services unavailable; falling back to in-memory state stores');
  }

  // Initialize Hunt service AFTER Redis (labs-2rf9.2: savedQueryStore needs sharedRedis)
  const savedQueryStore = sharedRedis
    ? new ResilientSavedQueryStore(
        logger,
        new RedisSavedQueryStore(sharedRedis.kv),
        new InMemorySavedQueryStore()
      )
    : undefined;
  huntService = new HuntService(prisma, logger, clickhouse ?? undefined, savedQueryStore);

  // Simple permission cache (10s TTL)
  const permissionCache = new Map<string, { allowed: boolean; expires: number }>();

  // Initialize fleet management services with resilient sensor metrics store
  const sensorMetricsStore = sharedRedis
    ? new ResilientSensorMetricsStore(
        logger,
        new RedisSensorMetricsStore(sharedRedis.kv),
        new InMemorySensorMetricsStore()
      )
    : undefined;
  fleetAggregator = new FleetAggregator(logger, {
    metricsRetentionMs: 5 * 60 * 1000, // 5 minutes
    heartbeatTimeoutMs: 90000, // 90 seconds
    cpuAlertThreshold: 80,
    memoryAlertThreshold: 85,
    diskAlertThreshold: 90,
  }, sensorMetricsStore);
  configManager = new ConfigManager(prisma, logger);
  fleetCommander = new FleetCommander(prisma, logger, {
    defaultTimeoutMs: 30000,
    maxRetries: 3,
    timeoutCheckIntervalMs: 5000,
    // Runtime (in-memory) feature flags; can be toggled via management config endpoint.
    commandFeatures: fleetCommandFeatures,
  });

  // Distributed stores (optional)
  const deploymentStateStore = sharedRedis ? new RedisDeploymentStateStore(sharedRedis.kv, logger) : undefined;
  ruleDistributor = new RuleDistributor(prisma, logger, deploymentStateStore);

  const userHistoryStore = sharedRedis
    ? new ResilientUserHistoryStore(
        logger,
        new RedisUserHistoryStore(sharedRedis.kv, logger),
        new InMemoryUserHistoryStore()
      )
    : undefined;
  impossibleTravelService = new ImpossibleTravelService(prisma, logger, userHistoryStore);

  const recentSignalsStore = sharedRedis
    ? new ResilientRecentSignalsStore(
        logger,
        new RedisRecentSignalsStore(sharedRedis.kv, logger),
        new InMemoryRecentSignalsStore()
      )
    : undefined;
  threatService = new ThreatService(logger, undefined, recentSignalsStore);

  preferenceService = new PreferenceService(prisma, logger, clickhouse ?? undefined);
  
  // Initialize TunnelBroker with permission checker (labs-zbjy)
  tunnelBroker = new TunnelBroker(logger, {
    permissionChecker: async (userId: string, tenantId: string) => {
      const cacheKey = `${userId}:${tenantId}`;
      const now = Date.now();
      const cached = permissionCache.get(cacheKey);
      
      if (cached && cached.expires > now) {
        return cached.allowed;
      }

      // If userId is actually an apiKeyId (service account)
      const apiKey = await prisma.apiKey.findUnique({
        where: { id: userId },
        select: { tenantId: true, isRevoked: true },
      });

      let allowed = false;
      if (apiKey) {
        allowed = !apiKey.isRevoked && apiKey.tenantId === tenantId;
      } else {
        // Assume user ID? We don't have a user table in schema.
        // For now, assume if it's not an API key, it might be a future user ID or system.
        // If "system", allow.
        if (userId === 'system') allowed = true;
      }

      permissionCache.set(cacheKey, { allowed, expires: now + 10000 }); // 10s cache
      return allowed;
    }
  });
  
  tunnelSessionStore = new TunnelSessionStore(prisma);
  synapseProxy = new SynapseProxyService(tunnelBroker, logger);

  // Start fleet intel ingestion (polls connected sensors)
  fleetIntelIngestion = new FleetIntelIngestionService(prisma, synapseProxy, logger);
  fleetIntelIngestion.start();
  sessionQueryService = new FleetSessionQueryService({ prisma, logger, tunnelBroker });
  fleetIntelService = new FleetIntelService(prisma, logger, synapseProxy);
  fleetIntelService.start();
  
  // Default War Room config
  const warRoomConfig: WarRoomConfig = {
    autoCreateForCrossTenant: true,
    autoCreateForCritical: true,
    maxActivityLimit: 200,
  };
  warRoomService = new WarRoomService(prisma, logger, warRoomConfig);
  securityAuditService = new SecurityAuditService(prisma, logger);
  playbookService = new PlaybookService(
    prisma,
    logger,
    fleetCommander,
    warRoomService,
    securityAuditService
  );
	  const triggerCooldownStore = sharedRedis
	    ? new ResilientTriggerCooldownStore(
	        logger,
	        new RedisTriggerCooldownStore(sharedRedis.kv),
	        new InMemoryTriggerCooldownStore()
	      )
	    : undefined;
	  playbookTrigger = new AutomatedPlaybookTrigger(
	    prisma,
	    logger,
	    playbookService,
	    undefined,
	    triggerCooldownStore
	  );

  // labs-ohgy: Initialize Data Retention Service
  const retentionService = new DataRetentionService(
    prisma,
    logger,
    {},
    securityAuditService,
    clickhouse
  );
  const startRetentionFallback = () => {
    if (retentionInterval || retentionTimeout) {
      return;
    }

    // Run daily (86400000 ms)
    retentionInterval = setInterval(async () => {
      // PEN-006: Use distributed lock for fallback (labs-y0t2)
      const lockKey = `retention-purge-daily-${new Date().getUTCFullYear()}-${new Date().getUTCMonth()}-${new Date().getUTCDate()}`;
      try {
        const acquired = await idempotencyStore.checkAndAdd(lockKey, Date.now(), {
          tenantId: 'system',
          path: 'jobs:retention:fallback',
        });

        if (acquired) {
          logger.info({ lockKey }, 'Acquired distributed lock for data retention fallback');
          await retentionService.runPurge();
        } else {
          logger.debug({ lockKey }, 'Data retention fallback lock already held by another instance');
        }
      } catch (err) {
        logger.error({ err }, 'Periodic data retention purge failed');
      }
    }, 86400000);

    // Also run once on startup (after a short delay to let DB settle)
    retentionTimeout = setTimeout(async () => {
      const lockKey = `retention-purge-startup-${Date.now() - (Date.now() % 3600000)}`; // 1 hour bucket
      try {
        const acquired = await idempotencyStore.checkAndAdd(lockKey, Date.now(), {
          tenantId: 'system',
          path: 'jobs:retention:startup',
        });

        if (acquired) {
          logger.info({ lockKey }, 'Acquired distributed lock for data retention startup');
          await retentionService.runPurge();
        }
      } catch (err) {
        logger.error({ err }, 'Startup data retention purge failed');
      }
    }, 60000);
  };

  // Create WebSocket server for tunnel connections (noServer mode - we handle upgrades manually)
  tunnelWss = new WebSocketServer({ noServer: true });
  logger.info('Fleet management services initialized');

  // Resolve circular dependencies: services that need each other
  configManager.setFleetCommander(fleetCommander);
  ruleDistributor.setFleetCommander(fleetCommander);
  fleetCommander.setCommandSender(commandSender);
  logger.info('Fleet service dependencies wired');

  // Mount API routes (including hunt routes, fleet routes, and synapse proxy)
  const sigmaHuntService = sharedRedis
    ? new SigmaHuntService(sharedRedis.kv, logger, clickhouse ?? null)
    : null;

  const apiRouter = createApiRouter(prisma, logger, {
    huntService,
    sigmaHuntService: sigmaHuntService ?? undefined,
    fleetAggregator,
    configManager,
    fleetCommander,
    ruleDistributor,
    clickhouse,
    synapseProxy,
    tunnelBroker,
    sessionQueryService,
    fleetIntelService,
    warRoomService,
    apiIntelligenceService,
    playbookService,
    securityAuditService,
  });
  app.use('/api/v1', apiRouter);
  logger.info('API routes mounted at /api/v1 (includes fleet and synapse routes)');

  // Ops routes (fleet-admin infra visibility). Kept outside createApiRouter so we can
  // safely iterate without touching the central routes index.
  app.use(
    '/api/v1/ops',
    createOpsRoutes(prisma, logger, {
      clickhouse,
      clickhouseConfig: config.clickhouse,
      kv: sharedRedis?.kv ?? null,
    })
  );
  logger.info('Ops routes mounted at /api/v1/ops');

  const authCoverageAggregator = new AuthCoverageAggregator();
  app.use('/api/v1/auth-coverage', createAuthCoverageRoutes(authCoverageAggregator));
  logger.info('Auth coverage routes mounted at /api/v1/auth-coverage');

  // Initialize core services (pass ClickHouse for dual-write)
  const blocklistStore = sharedRedis
    ? new ResilientBlocklistStore(
        logger,
        new RedisBlocklistStore(sharedRedis.kv),
        new InMemoryBlocklistStore()
      )
    : undefined;
  broadcaster = new Broadcaster(prisma, logger, config.broadcaster, clickhouse ?? undefined, blocklistStore);
  correlator = new Correlator(prisma, logger, broadcaster, clickhouse ?? undefined);
  aggregator = new Aggregator(
    prisma,
    logger,
    correlator,
    config.aggregator,
    clickhouse ?? undefined,
    impossibleTravelService,
    apiIntelligenceService,
    threatService ?? undefined,
    playbookTrigger,
    idempotencyStore
  );

  // Initialize WebSocket gateways
  sensorGateway = new SensorGateway(prisma, logger, aggregator, fleetAggregator, {
    path: config.websocket.sensorPath,
    heartbeatIntervalMs: config.websocket.heartbeatIntervalMs,
    maxConnections: config.websocket.maxSensorConnections,
    compatibility: config.sensorCompatibility,
  }, authCoverageAggregator);

  dashboardGateway = new DashboardGateway(prisma, logger, {
    path: config.websocket.dashboardPath,
    heartbeatIntervalMs: config.websocket.heartbeatIntervalMs,
    maxConnections: config.websocket.maxDashboardConnections,
  });

  // Wire up broadcaster to dashboard gateway and war room service
  broadcaster.setDashboardGateway(dashboardGateway);
  broadcaster.setSensorGateway(sensorGateway);
  broadcaster.setWarRoomService(warRoomService);
  warRoomService.setDashboardGateway(dashboardGateway);

  // labs-aoyv: Initialize Blocklist Queue & Worker
  blocklistQueue = createBlocklistQueue(logger);
  blocklistWorker = createBlocklistWorker(sensorGateway, logger);
  broadcaster.setBlocklistQueue(blocklistQueue);

  // labs-9yin: Wire up preference transition consensus
  preferenceService.on('preference-change-requested', (tenantId: string, preference: SharingPreference) => {
    return [
      sensorGateway.acknowledgePreferenceChange(tenantId, preference),
    ];
  });

  // Start protocol handlers for fleet management
  commandSender.start();
  logger.info('Protocol handlers started');

  // Initialize job queue workers for background processing (requires Redis)
  const enableJobQueue = process.env.ENABLE_JOB_QUEUE !== 'false';
  if (enableJobQueue) {
    try {
      // Check for stalled rollouts from previous server restarts
      await recoverStalledRollouts(prisma, logger);

      // Start the rollout worker (processes rollout jobs from the queue)
      rolloutWorker = createRolloutWorker(prisma, logger, fleetCommander);
      logger.info('Rollout worker started - background job processing enabled');

      retentionQueue = createRetentionQueue(logger);
      retentionWorker = createRetentionWorker(retentionService, logger);

      if (sigmaHuntService) {
        sigmaHuntQueue = createSigmaHuntQueue(logger);
        sigmaHuntWorker = createSigmaHuntWorker(sigmaHuntService, logger);

        try {
          await sigmaHuntQueue.add(
            'sigma-hunt-startup',
            { trigger: 'startup' },
            { jobId: 'sigma-hunt-startup', delay: 60000 }
          );
        } catch (error) {
          logger.warn({ error }, 'Sigma hunt startup job already scheduled or failed');
        }

        try {
          await sigmaHuntQueue.add(
            'sigma-hunt-hourly',
            { trigger: 'schedule' },
            { jobId: 'sigma-hunt-hourly', repeat: { every: 60 * 60 * 1000 } }
          );
        } catch (error) {
          logger.warn({ error }, 'Sigma hunt repeat job already scheduled or failed');
        }
      }

      try {
        await retentionQueue.add(
          'data-retention-startup',
          { trigger: 'startup' },
          { jobId: 'data-retention-startup', delay: 60000 }
        );
      } catch (error) {
        logger.warn({ error }, 'Retention startup job already scheduled or failed');
      }

      try {
        await retentionQueue.add(
          'data-retention-daily',
          { trigger: 'schedule' },
          { jobId: 'data-retention-daily', repeat: { every: 86400000 } }
        );
      } catch (error) {
        logger.warn({ error }, 'Retention repeat job already scheduled or failed');
      }
    } catch (error) {
      logger.warn(
        { error: error instanceof Error ? error.message : String(error) },
        'Failed to start job queue - Redis may not be available. Set ENABLE_JOB_QUEUE=false to suppress this warning.'
      );
      startRetentionFallback();
    }
  } else {
    logger.info('Job queue disabled (ENABLE_JOB_QUEUE=false) - rollout processing will not be available');
    startRetentionFallback();
  }

  // Wire up protocol handlers to sensor gateway for fleet operations
  sensorGateway.setProtocolHandlers(commandSender);

  // Route WebSocket upgrades to the correct gateway
  httpServer.on('upgrade', (req, socket, head) => {
    const match = matchUpgradePath(req.url, {
      sensorPath: config.websocket.sensorPath,
      dashboardPath: config.websocket.dashboardPath,
    });
    // Cast socket to Socket - the upgrade event provides a net.Socket typed as Duplex for compatibility
    const netSocket = socket as Socket;

    if (!match) {
      socket.destroy();
      return;
    }

    if (match.type === 'sensor') {
      sensorGateway.handleUpgrade(req, netSocket, head);
      return;
    }

    if (match.type === 'dashboard') {
      dashboardGateway.handleUpgrade(req, netSocket, head);
      return;
    }

    // Tunnel WebSocket paths: /ws/tunnel/sensor/:sensorId and /ws/tunnel/user/:sessionId
    if (match.type === 'tunnel-sensor') {
      tunnelWss.handleUpgrade(req, netSocket, head, (ws) => {
        handleTunnelSensorConnection(ws, prisma, logger);
      });
      return;
    }

    if (match.type === 'tunnel-user') {
      // labs-c4hh: Session ID is no longer in the URL path.
      // The client sends it as the first WebSocket message (first-message auth).
      tunnelWss.handleUpgrade(req, netSocket, head, (ws) => {
        handleTunnelUserConnection(ws, logger);
      });
      return;
    }

    if (match.type === 'tunnel-unknown') {
      logger.warn({ path: match.path }, 'Rejected unknown tunnel WebSocket path');
      socket.destroy();
      return;
    }

    socket.destroy();
  });

  // Start WebSocket gateways
  sensorGateway.start();
  dashboardGateway.start();

  // Start HTTP server
  httpServer.listen(config.server.port, config.server.host, () => {
    logger.info(
      { host: config.server.host, port: config.server.port },
      'Signal Horizon Hub listening'
    );
    logger.info(
      { path: config.websocket.sensorPath },
      'Sensor WebSocket gateway ready'
    );
    logger.info(
      { path: config.websocket.dashboardPath },
      'Dashboard WebSocket gateway ready'
    );
    logger.info(
      { path: '/ws/tunnel/sensor' },
      'Tunnel WebSocket gateway ready'
    );
  });
}

async function shutdown(signal: string) {
  logger.info({ signal }, 'Shutting down Signal Horizon Hub...');

  // Stop accepting new connections
  httpServer.close();

  // Stop gateways
  sensorGateway?.stop();
  dashboardGateway?.stop();

  // Stop protocol handlers
  commandSender?.stop();
  logger.info('Protocol handlers stopped');

  // Stop services
  aggregator?.stop();
  broadcaster?.stop();
  fleetAggregator?.stop?.();
  fleetIntelService?.shutdown();
  fleetIntelIngestion?.stop();
  await synapseProxy?.shutdown?.();
  await tunnelBroker?.shutdown?.();
  tunnelWss?.close();
  const sensorBridge = getSensorBridge();
  if (sensorBridge) {
    await sensorBridge.stop();
    logger.info('Sensor bridge stopped');
  }

  if (retentionInterval) {
    clearInterval(retentionInterval);
    retentionInterval = null;
  }
  if (retentionTimeout) {
    clearTimeout(retentionTimeout);
    retentionTimeout = null;
  }

  // Stop job queue workers
  if (rolloutWorker) {
    await stopRolloutWorker(rolloutWorker, logger);
    logger.info('Rollout worker stopped');
  }
  if (blocklistWorker) {
    await closeWorker(blocklistWorker, logger);
    logger.info('Blocklist worker stopped');
  }
  if (blocklistQueue) {
    await closeQueue(blocklistQueue, logger);
    logger.info('Blocklist queue closed');
  }
  if (retentionWorker) {
    await closeWorker(retentionWorker, logger);
    logger.info('Retention worker stopped');
  }
  if (retentionQueue) {
    await closeQueue(retentionQueue, logger);
    logger.info('Retention queue closed');
  }
  if (sigmaHuntWorker) {
    await closeWorker(sigmaHuntWorker, logger);
    logger.info('Sigma hunt worker stopped');
  }
  if (sigmaHuntQueue) {
    await closeQueue(sigmaHuntQueue, logger);
    logger.info('Sigma hunt queue closed');
  }
  logger.info('Fleet services stopped');

  // Flush ClickHouse retry buffer with timeout to prevent hanging on shutdown (labs-ykn9)
  if (telemetryRetryBuffer) {
    logger.info('Flushing ClickHouse retry buffer...');
    const flushResult = await telemetryRetryBuffer.flush(5000);
    logger.info(
      { succeeded: flushResult.succeeded, failed: flushResult.failed },
      'ClickHouse retry buffer flushed'
    );
  }
  if (clickhouse) {
    await clickhouse.close();
    logger.info('ClickHouse connection closed');
  }

  if (sharedRedis) {
    await sharedRedis.close();
    sharedRedis = null;
    logger.info('Shared Redis connection closed');
  }

  // Disconnect database
  await prisma.$disconnect();

  logger.info('Signal Horizon Hub shutdown complete');
  process.exit(0);
}

// Graceful shutdown
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Unhandled errors
process.on('unhandledRejection', (reason) => {
  logger.error({ reason }, 'Unhandled Promise rejection');
});

process.on('uncaughtException', (error) => {
  logger.fatal({ error }, 'Uncaught exception');
  process.exit(1);
});

// Start the server
start().catch((error) => {
  logger.fatal({ error }, 'Failed to start Signal Horizon Hub');
  process.exit(1);
});
