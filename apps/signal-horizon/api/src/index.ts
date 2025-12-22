/**
 * Signal Horizon Hub - Entry Point
 * Fleet intelligence for collective defense across Synapse sensors
 */

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'node:http';
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
import { createApiRouter } from './api/routes/index.js';
import { ClickHouseService } from './storage/clickhouse/index.js';
// Fleet management services
import { FleetAggregator } from './services/fleet/fleet-aggregator.js';
import { ConfigManager } from './services/fleet/config-manager.js';
import { FleetCommander } from './services/fleet/fleet-commander.js';
import { RuleDistributor } from './services/fleet/rule-distributor.js';
// Protocol handlers
import { HeartbeatHandler } from './protocols/heartbeat-handler.js';
import { CommandSender } from './protocols/command-sender.js';

// Initialize logger
const logger = pino({
  level: config.logging.level,
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

// Middleware
app.use(helmet());
app.use(cors({
  origin: config.security.corsOrigins,
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));
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
let sensorGateway: SensorGateway;
let dashboardGateway: DashboardGateway;
// Fleet management services
let heartbeatHandler: HeartbeatHandler;
let commandSender: CommandSender;
let fleetAggregator: FleetAggregator;
let configManager: ConfigManager;
let fleetCommander: FleetCommander;
let ruleDistributor: RuleDistributor;

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

  // Initialize Hunt service (always available, routes to ClickHouse when enabled)
  huntService = new HuntService(prisma, logger, clickhouse ?? undefined);

  // Initialize protocol handlers for fleet management
  heartbeatHandler = new HeartbeatHandler();
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
  logger.info('Fleet management services initialized');

  // Resolve circular dependencies: services that need each other
  configManager.setFleetCommander(fleetCommander);
  ruleDistributor.setFleetCommander(fleetCommander);
  logger.info('Fleet service dependencies wired');

  // Mount API routes (including hunt routes and fleet routes)
  const apiRouter = createApiRouter(prisma, logger, {
    huntService,
    fleetAggregator,
    configManager,
    fleetCommander,
    ruleDistributor,
  });
  app.use('/api/v1', apiRouter);
  logger.info('API routes mounted at /api/v1 (includes fleet routes)');

  // Initialize core services (pass ClickHouse for dual-write)
  broadcaster = new Broadcaster(prisma, logger, config.broadcaster, clickhouse ?? undefined);
  correlator = new Correlator(prisma, logger, broadcaster, clickhouse ?? undefined);
  aggregator = new Aggregator(prisma, logger, correlator, config.aggregator, clickhouse ?? undefined);

  // Initialize WebSocket gateways
  sensorGateway = new SensorGateway(httpServer, prisma, logger, aggregator, {
    path: config.websocket.sensorPath,
    heartbeatIntervalMs: config.websocket.heartbeatIntervalMs,
    maxConnections: config.websocket.maxSensorConnections,
  });

  dashboardGateway = new DashboardGateway(httpServer, prisma, logger, {
    path: config.websocket.dashboardPath,
    heartbeatIntervalMs: config.websocket.heartbeatIntervalMs,
    maxConnections: config.websocket.maxDashboardConnections,
  });

  // Wire up broadcaster to dashboard gateway
  broadcaster.setDashboardGateway(dashboardGateway);

  // Start protocol handlers for fleet management
  heartbeatHandler.start();
  commandSender.start();
  logger.info('Protocol handlers started');

  // Wire up protocol handlers to sensor gateway for fleet operations
  // TODO: Phase 3 - Wire protocol handlers after implementing setProtocolHandlers() method
  // sensorGateway.setProtocolHandlers(heartbeatHandler, commandSender);

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
  heartbeatHandler?.stop();
  commandSender?.stop();
  logger.info('Protocol handlers stopped');

  // Stop services
  aggregator?.stop();
  broadcaster?.stop();
  fleetAggregator?.stop?.();
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
