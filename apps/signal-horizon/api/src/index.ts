/**
 * Signal Horizon Hub - Entry Point
 * Fleet intelligence for collective defense across Synapse sensors
 */

import 'dotenv/config';
import express from 'express';
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
import { ClickHouseService } from './storage/clickhouse/index.js';
// Fleet management services
import { WarRoomService, type WarRoomConfig } from './services/warroom/index.js';
import { FleetAggregator } from './services/fleet/fleet-aggregator.js';
import { ConfigManager } from './services/fleet/config-manager.js';
import { FleetCommander } from './services/fleet/fleet-commander.js';
import { RuleDistributor } from './services/fleet/rule-distributor.js';
import { ImpossibleTravelService } from './services/impossible-travel.js';
// Protocol handlers
import { CommandSender } from './protocols/command-sender.js';
// Job queue and workers
import { createRolloutWorker, stopRolloutWorker, recoverStalledRollouts } from './jobs/index.js';
import type { Worker } from 'bullmq';
import type { RolloutJobData } from './jobs/queue.js';
// Tunnel broker for remote access
import { TunnelBroker, type TunnelCapability } from './websocket/tunnel-broker.js';
import { SynapseProxyService } from './services/synapse-proxy.js';
import { initSynapseDirectAdapter } from './services/synapse-direct.js';
import { initSensorBridge, getSensorBridge } from './services/sensor-bridge.js';
import { WebSocketServer, WebSocket } from 'ws';
import { createHash } from 'node:crypto';
// Security middleware
import { jsonDepthLimit } from './middleware/json-depth.js';

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
      // Also redact in response context
      'res.headers["set-cookie"]',
    ],
    censor: '[REDACTED]',
  },
  transport: config.isDev
    ? { target: 'pino-pretty', options: { colorize: true } }
    : undefined,
});

// Initialize Prisma
const prisma = new PrismaClient({
  log: config.isDev ? ['query', 'info', 'warn', 'error'] : ['error'],
});

// Initialize Express
const app = express();
const httpServer = createServer(app);

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
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  // Prevent MIME type sniffing
  xContentTypeOptions: true,
  // Prevent clickjacking
  xFrameOptions: { action: 'deny' },
  // Control referrer information
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  // Disable browser features we don't need
  permissionsPolicy: {
    features: {
      accelerometer: [],
      camera: [],
      geolocation: [],
      gyroscope: [],
      magnetometer: [],
      microphone: [],
      payment: [],
      usb: [],
    },
  },
  // Remove X-Powered-By header (Express default)
  xPoweredBy: false,
  // Prevent DNS prefetching
  xDnsPrefetchControl: { allow: false },
  // Don't cache sensitive responses
  noSniff: true,
}));
app.use(cors({
  origin: config.security.corsOrigins,
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));
// JSON depth limiting to prevent stack overflow attacks (WS4-003)
app.use(jsonDepthLimit(20));
app.use(pinoHttp({ logger }));

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

    res.json({
      status: 'ready',
      database: 'connected',
      clickhouse: clickhouseStatus,
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
let huntService: HuntService;
let aggregator: Aggregator;
let correlator: Correlator;
let broadcaster: Broadcaster;
let apiIntelligenceService: APIIntelligenceService;
let sensorGateway: SensorGateway;
let dashboardGateway: DashboardGateway;
// Fleet management services
let commandSender: CommandSender;
let fleetAggregator: FleetAggregator;
let configManager: ConfigManager;
let fleetCommander: FleetCommander;
let ruleDistributor: RuleDistributor;
let impossibleTravelService: ImpossibleTravelService;
let tunnelBroker: TunnelBroker;
let synapseProxy: SynapseProxyService;
let warRoomService: WarRoomService;
let tunnelWss: WebSocketServer;
let rolloutWorker: Worker<RolloutJobData, void>;

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

      // Validate API key against database
      const apiKeyRecord = await db.apiKey.findFirst({
        where: {
          keyHash,
          isRevoked: false,
          OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } },
          ],
        },
        select: {
          id: true,
          tenantId: true,
          name: true,
          scopes: true,
        },
      });

      if (!apiKeyRecord) {
        log.warn({ sensorId }, 'Invalid or expired API key for tunnel');
        ws.send(JSON.stringify({
          type: 'auth-error',
          payload: { error: 'Invalid or expired API key' },
          timestamp: new Date().toISOString(),
        }));
        ws.close(4004, 'Invalid API key');
        clearTimeout(authTimeout);
        return;
      }

      // Verify sensor belongs to this tenant
      const sensor = await db.sensor.findFirst({
        where: {
          id: sensorId,
          tenantId: apiKeyRecord.tenantId,
        },
        select: { id: true, name: true },
      });

      if (!sensor) {
        log.warn({ sensorId, tenantId: apiKeyRecord.tenantId }, 'Sensor not found or tenant mismatch');
        ws.send(JSON.stringify({
          type: 'auth-error',
          payload: { error: 'Sensor not found' },
          timestamp: new Date().toISOString(),
        }));
        ws.close(4005, 'Sensor not found');
        clearTimeout(authTimeout);
        return;
      }

      // Authentication successful
      authenticated = true;
      clearTimeout(authTimeout);

      // Send success response
      ws.send(JSON.stringify({
        type: 'auth-success',
        payload: {
          sensorId: sensor.id,
          sensorName: sensor.name,
          tenantId: apiKeyRecord.tenantId,
        },
        timestamp: new Date().toISOString(),
      }));

      // Hand off to TunnelBroker for connection management
      tunnelBroker.handleSensorConnect(
        ws,
        sensorId,
        apiKeyRecord.tenantId,
        capabilities,
        metadata
      );

      log.info(
        { sensorId, tenantId: apiKeyRecord.tenantId, capabilities },
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

async function start() {
  logger.info('Starting Signal Horizon Hub...');

  // Connect to database
  await prisma.$connect();
  logger.info('Connected to database');

  // Initialize ClickHouse for historical data (if enabled)
  if (config.clickhouse.enabled) {
    clickhouse = new ClickHouseService(config.clickhouse, logger);
    try {
      await clickhouse.ping();
      logger.info('Connected to ClickHouse for historical analytics');
    } catch (error) {
      logger.warn(
        { error },
        'ClickHouse connection failed - historical queries will be unavailable'
      );
      clickhouse = null;
    }
  } else {
    logger.info('ClickHouse disabled - using PostgreSQL only (demo mode)');
  }

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

  // Initialize Hunt service (always available, routes to ClickHouse when enabled)
  huntService = new HuntService(prisma, logger, clickhouse ?? undefined);
  apiIntelligenceService = new APIIntelligenceService(prisma, logger);

  // Initialize protocol handlers for fleet management
  commandSender = new CommandSender();
  logger.info('Protocol handlers initialized');

  // Initialize fleet management services
  fleetAggregator = new FleetAggregator(logger, {
    metricsRetentionMs: 5 * 60 * 1000, // 5 minutes
    heartbeatTimeoutMs: 90000, // 90 seconds
    cpuAlertThreshold: 80,
    memoryAlertThreshold: 85,
    diskAlertThreshold: 90,
  });
  configManager = new ConfigManager(prisma, logger);
  fleetCommander = new FleetCommander(prisma, logger, {
    defaultTimeoutMs: 30000,
    maxRetries: 3,
    timeoutCheckIntervalMs: 5000,
  });
  ruleDistributor = new RuleDistributor(prisma, logger);
  impossibleTravelService = new ImpossibleTravelService(prisma, logger);
  tunnelBroker = new TunnelBroker(logger);
  synapseProxy = new SynapseProxyService(tunnelBroker, logger);
  
  // Default War Room config
  const warRoomConfig: WarRoomConfig = {
    autoCreateForCrossTenant: true,
    autoCreateForCritical: true,
    maxActivityLimit: 200,
  };
  warRoomService = new WarRoomService(prisma, logger, warRoomConfig);

  // Create WebSocket server for tunnel connections (noServer mode - we handle upgrades manually)
  tunnelWss = new WebSocketServer({ noServer: true });
  logger.info('Fleet management services initialized');

  // Resolve circular dependencies: services that need each other
  configManager.setFleetCommander(fleetCommander);
  ruleDistributor.setFleetCommander(fleetCommander);
  fleetCommander.setCommandSender(commandSender);
  logger.info('Fleet service dependencies wired');

  // Mount API routes (including hunt routes, fleet routes, and synapse proxy)
  const apiRouter = createApiRouter(prisma, logger, {
    huntService,
    fleetAggregator,
    configManager,
    fleetCommander,
    ruleDistributor,
    synapseProxy,
    tunnelBroker,
    warRoomService,
    apiIntelligenceService,
  });
  app.use('/api/v1', apiRouter);
  logger.info('API routes mounted at /api/v1 (includes fleet and synapse routes)');

  // Initialize core services (pass ClickHouse for dual-write)
  broadcaster = new Broadcaster(prisma, logger, config.broadcaster, clickhouse ?? undefined);
  correlator = new Correlator(prisma, logger, broadcaster, clickhouse ?? undefined);
  aggregator = new Aggregator(
    prisma,
    logger,
    correlator,
    config.aggregator,
    clickhouse ?? undefined,
    impossibleTravelService,
    apiIntelligenceService
  );

  // Initialize WebSocket gateways
  sensorGateway = new SensorGateway(prisma, logger, aggregator, fleetAggregator, {
    path: config.websocket.sensorPath,
    heartbeatIntervalMs: config.websocket.heartbeatIntervalMs,
    maxConnections: config.websocket.maxSensorConnections,
  });

  dashboardGateway = new DashboardGateway(prisma, logger, {
    path: config.websocket.dashboardPath,
    heartbeatIntervalMs: config.websocket.heartbeatIntervalMs,
    maxConnections: config.websocket.maxDashboardConnections,
  });

  // Wire up broadcaster to dashboard gateway and war room service
  broadcaster.setDashboardGateway(dashboardGateway);
  broadcaster.setWarRoomService(warRoomService);
  warRoomService.setDashboardGateway(dashboardGateway);

  // Start protocol handlers for fleet management
  commandSender.start();
  logger.info('Protocol handlers started');

  // Initialize job queue workers for background processing
  // Check for stalled rollouts from previous server restarts
  await recoverStalledRollouts(prisma, logger);

  // Start the rollout worker (processes rollout jobs from the queue)
  rolloutWorker = createRolloutWorker(prisma, logger, fleetCommander);
  logger.info('Rollout worker started - background job processing enabled');

  // Wire up protocol handlers to sensor gateway for fleet operations
  sensorGateway.setProtocolHandlers(commandSender);

  // Route WebSocket upgrades to the correct gateway
  httpServer.on('upgrade', (req, socket, head) => {
    const url = req.url ? new URL(req.url, 'http://localhost') : null;
    const pathname = url?.pathname ?? '';
    const normalize = (path: string) =>
      path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;

    const normalizedPath = normalize(pathname);
    // Cast socket to Socket - the upgrade event provides a net.Socket typed as Duplex for compatibility
    const netSocket = socket as Socket;

    if (normalizedPath === normalize(config.websocket.sensorPath)) {
      sensorGateway.handleUpgrade(req, netSocket, head);
      return;
    }

    if (normalizedPath === normalize(config.websocket.dashboardPath)) {
      dashboardGateway.handleUpgrade(req, netSocket, head);
      return;
    }

    // Tunnel WebSocket paths: /ws/tunnel/sensor/:sensorId and /ws/tunnel/user/:sessionId
    if (normalizedPath.startsWith('/ws/tunnel/')) {
      // Handle sensor tunnel connections
      if (normalizedPath.startsWith('/ws/tunnel/sensor')) {
        tunnelWss.handleUpgrade(req, netSocket, head, (ws) => {
          handleTunnelSensorConnection(ws, prisma, logger);
        });
        return;
      }

      // User dashboard proxy connections (future)
      logger.info({ path: normalizedPath }, 'User tunnel WebSocket not yet implemented');
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
  await synapseProxy?.shutdown?.();
  await tunnelBroker?.shutdown?.();
  tunnelWss?.close();
  const sensorBridge = getSensorBridge();
  if (sensorBridge) {
    await sensorBridge.stop();
    logger.info('Sensor bridge stopped');
  }

  // Stop job queue workers
  if (rolloutWorker) {
    await stopRolloutWorker(rolloutWorker, logger);
    logger.info('Rollout worker stopped');
  }
  logger.info('Fleet services stopped');

  // Close ClickHouse connection
  if (clickhouse) {
    await clickhouse.close();
    logger.info('ClickHouse connection closed');
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
