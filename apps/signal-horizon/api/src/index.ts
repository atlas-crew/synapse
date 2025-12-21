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
import { createApiRouter } from './api/routes/index.js';

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
    res.json({
      status: 'ready',
      database: 'connected',
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
let aggregator: Aggregator;
let correlator: Correlator;
let broadcaster: Broadcaster;
let sensorGateway: SensorGateway;
let dashboardGateway: DashboardGateway;

async function start() {
  logger.info('Starting Signal Horizon Hub...');

  // Connect to database
  await prisma.$connect();
  logger.info('Connected to database');

  // Mount API routes
  const apiRouter = createApiRouter(prisma, logger);
  app.use('/api/v1', apiRouter);
  logger.info('API routes mounted at /api/v1');

  // Initialize core services
  broadcaster = new Broadcaster(prisma, logger, config.broadcaster);
  correlator = new Correlator(prisma, logger, broadcaster);
  aggregator = new Aggregator(prisma, logger, correlator, config.aggregator);

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

  // Stop services
  aggregator?.stop();

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
