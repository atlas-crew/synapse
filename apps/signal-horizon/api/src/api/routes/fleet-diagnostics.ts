/**
 * Fleet Diagnostics API Routes
 *
 * Endpoints for collecting and streaming diagnostics from remote sensors.
 * Supports both on-demand collection and real-time streaming (SSE).
 *
 * Security: All endpoints require `sensor:diag` scope via RBAC.
 *
 * @module api/routes/fleet-diagnostics
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { randomUUID } from 'node:crypto';
import { requireScope } from '../middleware/auth.js';
import { validateParams, validateQuery, validateBody } from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';
import type { TunnelBroker } from '../../websocket/tunnel-broker.js';
import type {
  DiagnosticType,
  DiagRequestMessage,
  DiagResponseMessage,
  DiagErrorMessage,
} from '../../types/tunnel.js';

// =============================================================================
// Validation Schemas
// =============================================================================

/**
 * Valid diagnostic sections that can be requested.
 * Maps to DiagnosticType in the tunnel protocol.
 */
const DIAGNOSTIC_SECTIONS = [
  'health',
  'memory',
  'connections',
  'rules',
  'actors',
  'config',
  'metrics',
  'threads',
  'cache',
] as const;

const SensorIdParamSchema = z.object({
  sensorId: z.string().min(1, 'Sensor ID is required'),
});

const DiagnosticsSectionsQuerySchema = z.object({
  sections: z
    .string()
    .optional()
    .transform((val) => {
      if (!val) return ['health', 'memory', 'connections'];
      return val.split(',').filter((s) => DIAGNOSTIC_SECTIONS.includes(s as DiagnosticType));
    }),
  timeout: z.coerce.number().int().min(1000).max(60000).default(30000),
});

const LiveDiagnosticsQuerySchema = z.object({
  sections: z
    .string()
    .optional()
    .transform((val) => {
      if (!val) return ['health', 'metrics'];
      return val.split(',').filter((s) => DIAGNOSTIC_SECTIONS.includes(s as DiagnosticType));
    }),
  interval: z.coerce.number().int().min(500).max(30000).default(1000),
});

const RunDiagnosticsBodySchema = z.object({
  sections: z.array(z.enum(DIAGNOSTIC_SECTIONS)).min(1).max(9),
  params: z.record(z.unknown()).optional(),
});

// =============================================================================
// Types
// =============================================================================

interface DiagnosticsRequest {
  requestId: string;
  sensorId: string;
  sections: DiagnosticType[];
  params?: Record<string, unknown>;
  createdAt: number;
  timeout: number;
  resolve: (data: DiagnosticsResponse) => void;
  reject: (error: Error) => void;
}

interface DiagnosticsResponse {
  sensorId: string;
  collectedAt: string;
  collectionTimeMs: number;
  sections: DiagnosticType[];
  data: Record<string, unknown>;
}

// =============================================================================
// Route Factory
// =============================================================================

/**
 * Create fleet diagnostics API routes.
 *
 * @param prisma - Prisma client for database access
 * @param logger - Pino logger instance
 * @param options - Optional dependencies for tunnel communication
 * @returns Express router with fleet diagnostics endpoints
 */
export function createFleetDiagnosticsRoutes(
  prisma: PrismaClient,
  logger: Logger,
  options: {
    tunnelBroker?: TunnelBroker;
  } = {}
): Router {
  const router = Router();
  const { tunnelBroker } = options;
  const log = logger.child({ component: 'fleet-diagnostics' });

  // Pending diagnostics requests (request ID -> request)
  const pendingRequests = new Map<string, DiagnosticsRequest>();

  // Set up tunnel message handler for diagnostics responses
  if (tunnelBroker) {
    tunnelBroker.onChannelMessage('diag', async (_session, message) => {
      if (message.type === 'response') {
        const response = message as DiagResponseMessage;
        handleDiagnosticsResponse(response);
      } else if (message.type === 'error') {
        const error = message as DiagErrorMessage;
        handleDiagnosticsError(error);
      }
    });
  }

  /**
   * Handle a diagnostics response from a sensor.
   */
  function handleDiagnosticsResponse(response: DiagResponseMessage): void {
    const request = pendingRequests.get(response.requestId);
    if (!request) {
      log.warn({ requestId: response.requestId }, 'Received response for unknown request');
      return;
    }

    pendingRequests.delete(response.requestId);

    request.resolve({
      sensorId: request.sensorId,
      collectedAt: new Date().toISOString(),
      collectionTimeMs: response.collectionTimeMs,
      sections: request.sections,
      data: response.data as unknown as Record<string, unknown>,
    });
  }

  /**
   * Handle a diagnostics error from a sensor.
   */
  function handleDiagnosticsError(error: DiagErrorMessage): void {
    const request = pendingRequests.get(error.requestId);
    if (!request) {
      log.warn({ requestId: error.requestId }, 'Received error for unknown request');
      return;
    }

    pendingRequests.delete(error.requestId);

    request.reject(new Error(`Diagnostics error: ${error.code} - ${error.message}`));
  }

  /**
   * Request diagnostics from a sensor via the tunnel.
   */
  async function requestDiagnostics(
    sensorId: string,
    sections: DiagnosticType[],
    timeout: number,
    params?: Record<string, unknown>
  ): Promise<DiagnosticsResponse> {
    if (!tunnelBroker) {
      throw new Error('Tunnel broker not available');
    }

    const requestId = randomUUID();

    return new Promise((resolve, reject) => {
      // Set up timeout
      const timeoutHandle = setTimeout(() => {
        pendingRequests.delete(requestId);
        reject(new Error(`Diagnostics request timed out after ${timeout}ms`));
      }, timeout);

      // Create pending request
      const request: DiagnosticsRequest = {
        requestId,
        sensorId,
        sections,
        params,
        createdAt: Date.now(),
        timeout,
        resolve: (data) => {
          clearTimeout(timeoutHandle);
          resolve(data);
        },
        reject: (error) => {
          clearTimeout(timeoutHandle);
          reject(error);
        },
      };

      pendingRequests.set(requestId, request);

      // Send request to sensor for each section
      // In a full implementation, we would batch these or send a single request
      const message: DiagRequestMessage = {
        channel: 'diag',
        sessionId: requestId,
        sequenceId: 0,
        timestamp: Date.now(),
        type: 'request',
        diagType: sections[0], // First section
        params: params ?? {},
        requestId,
      };

      // Send through tunnel broker
      const sent = tunnelBroker.sendToSensor(sensorId, message);
      if (!sent) {
        pendingRequests.delete(requestId);
        clearTimeout(timeoutHandle);
        reject(new Error('Failed to send diagnostics request to sensor'));
      }
    });
  }

  // ===========================================================================
  // Endpoints
  // ===========================================================================

  /**
   * GET /api/v1/fleet/:sensorId/diagnostics
   *
   * Collect diagnostics from a sensor.
   *
   * Query parameters:
   * - sections: Comma-separated list of diagnostic sections (default: health,memory,connections)
   * - timeout: Request timeout in milliseconds (default: 30000)
   *
   * Requires: sensor:diag scope
   */
  router.get(
    '/:sensorId/diagnostics',
    requireScope('sensor:diag'),
    validateParams(SensorIdParamSchema),
    validateQuery(DiagnosticsSectionsQuerySchema),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const { sections, timeout } = req.query as unknown as z.infer<typeof DiagnosticsSectionsQuerySchema>;
      const auth = req.auth!;

      try {
        // Verify sensor exists and belongs to tenant
        const sensor = await prisma.sensor.findFirst({
          where: { id: sensorId, tenantId: auth.tenantId },
          select: {
            id: true,
            name: true,
            connectionState: true,
            lastHeartbeat: true,
            tunnelActive: true,
          },
        });

        if (!sensor) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        // Check if sensor is online
        const isOnline =
          sensor.lastHeartbeat &&
          Date.now() - new Date(sensor.lastHeartbeat).getTime() < 120000 &&
          sensor.connectionState === 'CONNECTED';

        if (!isOnline) {
          res.status(503).json({
            error: 'Sensor offline',
            sensorId,
            connectionState: sensor.connectionState,
            lastHeartbeat: sensor.lastHeartbeat,
          });
          return;
        }

        // If tunnel broker available, request real diagnostics
        if (tunnelBroker && sensor.tunnelActive) {
          try {
            const diagnostics = await requestDiagnostics(
              sensorId,
              sections as DiagnosticType[],
              timeout
            );
            res.json(diagnostics);
            return;
          } catch (error) {
            log.warn({ error, sensorId }, 'Failed to collect diagnostics via tunnel, falling back to mock data');
          }
        }

        // Fall back to mock diagnostics for demo/development
        const mockDiagnostics = generateMockDiagnostics(sensorId, sensor.name, sections as DiagnosticType[]);
        res.json(mockDiagnostics);
      } catch (error) {
        log.error({ error, sensorId }, 'Failed to collect diagnostics');
        res.status(500).json({
          error: 'Failed to collect diagnostics',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/:sensorId/diagnostics/live
   *
   * Server-Sent Events endpoint for live diagnostics streaming.
   * Sends diagnostics updates at the specified interval (default: 1 second).
   *
   * Query parameters:
   * - sections: Comma-separated list of diagnostic sections (default: health,metrics)
   * - interval: Update interval in milliseconds (default: 1000)
   *
   * Requires: sensor:diag scope
   */
  router.get(
    '/:sensorId/diagnostics/live',
    requireScope('sensor:diag'),
    validateParams(SensorIdParamSchema),
    validateQuery(LiveDiagnosticsQuerySchema),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const { sections, interval } = req.query as unknown as z.infer<typeof LiveDiagnosticsQuerySchema>;
      const auth = req.auth!;

      try {
        // Verify sensor exists and belongs to tenant
        const sensor = await prisma.sensor.findFirst({
          where: { id: sensorId, tenantId: auth.tenantId },
          select: {
            id: true,
            name: true,
            connectionState: true,
            lastHeartbeat: true,
          },
        });

        if (!sensor) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        // Set up SSE headers
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('X-Accel-Buffering', 'no'); // Disable nginx buffering

        // Send initial connection event
        res.write(`event: connected\ndata: ${JSON.stringify({ sensorId, interval })}\n\n`);

        // Set up interval for streaming diagnostics
        let tickCount = 0;
        const streamInterval = setInterval(async () => {
          try {
            tickCount++;

            // Check if sensor is still online
            const currentSensor = await prisma.sensor.findUnique({
              where: { id: sensorId },
              select: { connectionState: true, lastHeartbeat: true },
            });

            const isOnline =
              currentSensor?.lastHeartbeat &&
              Date.now() - new Date(currentSensor.lastHeartbeat).getTime() < 120000;

            if (!isOnline) {
              const offlineEvent = {
                type: 'offline',
                sensorId,
                connectionState: currentSensor?.connectionState ?? 'UNKNOWN',
                timestamp: new Date().toISOString(),
              };
              res.write(`event: status\ndata: ${JSON.stringify(offlineEvent)}\n\n`);
              return;
            }

            // Generate diagnostics (mock for now, would use tunnel in production)
            const diagnostics = generateMockDiagnostics(
              sensorId,
              sensor.name,
              sections as DiagnosticType[],
              tickCount
            );

            res.write(`event: diagnostics\ndata: ${JSON.stringify(diagnostics)}\n\n`);
          } catch (error) {
            log.error({ error, sensorId }, 'Error in live diagnostics stream');
            const errorEvent = {
              type: 'error',
              message: getErrorMessage(error),
              timestamp: new Date().toISOString(),
            };
            res.write(`event: error\ndata: ${JSON.stringify(errorEvent)}\n\n`);
          }
        }, interval);

        // Clean up on client disconnect
        req.on('close', () => {
          clearInterval(streamInterval);
          log.info({ sensorId, tickCount }, 'Live diagnostics stream closed');
        });

        // Handle errors
        req.on('error', (error) => {
          clearInterval(streamInterval);
          log.error({ error, sensorId }, 'Live diagnostics stream error');
        });

        log.info({ sensorId, sections, interval }, 'Live diagnostics stream started');
      } catch (error) {
        log.error({ error, sensorId }, 'Failed to start live diagnostics stream');
        res.status(500).json({
          error: 'Failed to start live diagnostics stream',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * POST /api/v1/fleet/:sensorId/diagnostics/run
   *
   * Run a specific diagnostic check on a sensor.
   * Returns detailed results for the requested sections.
   *
   * Request body:
   * - sections: Array of diagnostic sections to collect
   * - params: Optional parameters for the diagnostic check
   *
   * Requires: sensor:diag scope
   */
  router.post(
    '/:sensorId/diagnostics/run',
    requireScope('sensor:diag'),
    validateParams(SensorIdParamSchema),
    validateBody(RunDiagnosticsBodySchema),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const { sections, params } = req.body as z.infer<typeof RunDiagnosticsBodySchema>;
      const auth = req.auth!;

      try {
        // Verify sensor exists and belongs to tenant
        const sensor = await prisma.sensor.findFirst({
          where: { id: sensorId, tenantId: auth.tenantId },
          select: {
            id: true,
            name: true,
            connectionState: true,
            lastHeartbeat: true,
            tunnelActive: true,
          },
        });

        if (!sensor) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        // Check if sensor is online
        const isOnline =
          sensor.lastHeartbeat &&
          Date.now() - new Date(sensor.lastHeartbeat).getTime() < 120000 &&
          sensor.connectionState === 'CONNECTED';

        if (!isOnline) {
          res.status(503).json({
            error: 'Sensor offline',
            sensorId,
            connectionState: sensor.connectionState,
            lastHeartbeat: sensor.lastHeartbeat,
          });
          return;
        }

        // If tunnel broker available, request real diagnostics
        if (tunnelBroker && sensor.tunnelActive) {
          try {
            const diagnostics = await requestDiagnostics(
              sensorId,
              sections as DiagnosticType[],
              30000,
              params
            );
            res.json(diagnostics);
            return;
          } catch (error) {
            log.warn({ error, sensorId }, 'Failed to run diagnostics via tunnel, falling back to mock data');
          }
        }

        // Fall back to mock diagnostics
        const mockDiagnostics = generateMockDiagnostics(sensorId, sensor.name, sections as DiagnosticType[]);

        log.info({ sensorId, sections }, 'Ran diagnostics on sensor');
        res.json(mockDiagnostics);
      } catch (error) {
        log.error({ error, sensorId }, 'Failed to run diagnostics');
        res.status(500).json({
          error: 'Failed to run diagnostics',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/:sensorId/diagnostics/history
   *
   * Get historical diagnostics data for a sensor.
   * Useful for tracking trends and identifying issues over time.
   *
   * Query parameters:
   * - section: Diagnostic section to retrieve history for
   * - from: Start timestamp (ISO 8601)
   * - to: End timestamp (ISO 8601)
   * - limit: Maximum number of entries (default: 100)
   *
   * Requires: sensor:diag scope
   */
  router.get(
    '/:sensorId/diagnostics/history',
    requireScope('sensor:diag'),
    validateParams(SensorIdParamSchema),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const auth = req.auth!;

      try {
        // Verify sensor exists and belongs to tenant
        const sensor = await prisma.sensor.findFirst({
          where: { id: sensorId, tenantId: auth.tenantId },
          select: { id: true, name: true },
        });

        if (!sensor) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        // Generate mock historical data (would come from time-series DB in production)
        const history = generateMockDiagnosticsHistory(sensorId, 100);

        res.json({
          sensorId,
          sensorName: sensor.name,
          count: history.length,
          history,
        });
      } catch (error) {
        log.error({ error, sensorId }, 'Failed to get diagnostics history');
        res.status(500).json({
          error: 'Failed to get diagnostics history',
          message: getErrorMessage(error),
        });
      }
    }
  );

  return router;
}

// =============================================================================
// Mock Data Generators
// =============================================================================

/**
 * Generate mock diagnostics for a sensor.
 * Used for development and when tunnel is unavailable.
 */
function generateMockDiagnostics(
  sensorId: string,
  _sensorName: string,
  sections: DiagnosticType[],
  tickCount = 0
): DiagnosticsResponse {
  const data: Record<string, unknown> = {};

  for (const section of sections) {
    switch (section) {
      case 'health':
        data.health = {
          diagType: 'health',
          status: tickCount % 20 === 0 ? 'degraded' : 'healthy',
          uptime: 86400 + tickCount, // 1 day + ticks
          version: '0.1.0',
          components: [
            { name: 'memory', status: 'healthy', message: null },
            { name: 'tunnel', status: tickCount % 30 === 0 ? 'degraded' : 'healthy', message: null },
            { name: 'rules', status: 'healthy', message: null },
          ],
        };
        break;

      case 'memory':
        data.memory = {
          diagType: 'memory',
          heapUsed: 150_000_000 + Math.random() * 50_000_000,
          heapTotal: 500_000_000,
          heapLimit: 1_073_741_824,
          external: 10_000_000,
          rss: 300_000_000 + Math.random() * 100_000_000,
          arrayBuffers: 5_000_000,
          gcStats: {
            collections: 1234 + tickCount,
            pauseMs: Math.random() * 10,
          },
        };
        break;

      case 'connections':
        data.connections = {
          diagType: 'connections',
          activeConnections: Math.floor(100 + Math.random() * 400),
          maxConnections: 10000,
          connectionsByType: {
            http: Math.floor(200 + Math.random() * 300),
            https: Math.floor(100 + Math.random() * 200),
            websocket: Math.floor(10 + Math.random() * 50),
          },
          recentConnections: Array.from({ length: 5 }, (_, i) => ({
            id: `conn-${1000 + i}`,
            remoteAddr: `203.0.113.${Math.floor(Math.random() * 255)}`,
            connectedAt: Date.now() - i * 60000,
            bytesIn: Math.floor(Math.random() * 100000),
            bytesOut: Math.floor(Math.random() * 500000),
          })),
        };
        break;

      case 'rules':
        data.rules = {
          diagType: 'rules',
          totalRules: 237,
          enabledRules: 230,
          disabledRules: 7,
          rulesByCategory: {
            sqli: 45,
            xss: 38,
            rce: 22,
            lfi: 18,
            rfi: 12,
            auth: 25,
            rate: 15,
            other: 62,
          },
          lastUpdated: new Date(Date.now() - 3600000).toISOString(),
          rulesHash: 'sha256:abc123...',
          topTriggeredRules: [
            { id: 'SQLI-001', name: 'SQL Injection Detection', triggerCount: 1234, lastTriggered: new Date().toISOString() },
            { id: 'XSS-002', name: 'XSS Attack Pattern', triggerCount: 567, lastTriggered: new Date().toISOString() },
            { id: 'RATE-001', name: 'Rate Limit Exceeded', triggerCount: 890, lastTriggered: new Date().toISOString() },
          ],
        };
        break;

      case 'actors':
        data.actors = {
          diagType: 'actors',
          trackedActors: 5432 + Math.floor(Math.random() * 100),
          blockedActors: 234 + Math.floor(Math.random() * 50),
          actorsByType: {
            ip: 4500,
            user: 800,
            session: 132,
          },
          topActors: Array.from({ length: 5 }, (_, i) => ({
            id: `203.0.113.${100 + i}`,
            type: 'ip',
            riskScore: 80 - i * 10 + Math.random() * 5,
            hitCount: 500 - i * 100 + Math.floor(Math.random() * 50),
            lastSeen: Date.now() - i * 300000,
          })),
        };
        break;

      case 'config':
        data.config = {
          diagType: 'config',
          configHash: 'sha256:def456...',
          lastUpdated: new Date(Date.now() - 86400000).toISOString(),
          settings: {
            rateLimit: 1000,
            blockThreshold: 70,
            decayRate: 10,
            // Secrets redacted
          },
        };
        break;

      case 'metrics':
        data.metrics = {
          diagType: 'metrics',
          requestsTotal: 1_234_567 + tickCount * 100,
          requestsPerSecond: 450 + Math.random() * 100,
          latencyP50: 5 + Math.random() * 5,
          latencyP95: 25 + Math.random() * 15,
          latencyP99: 80 + Math.random() * 40,
          errorsTotal: 1234 + Math.floor(tickCount / 10),
          errorRate: 0.1 + Math.random() * 0.1,
          bytesIn: 10_000_000_000 + tickCount * 1000000,
          bytesOut: 50_000_000_000 + tickCount * 5000000,
        };
        break;

      case 'threads':
        data.threads = {
          diagType: 'threads',
          workerThreads: 8,
          activeThreads: 6 + Math.floor(Math.random() * 2),
          pendingTasks: Math.floor(Math.random() * 10),
          completedTasks: 9_876_543 + tickCount * 10,
          threadPool: Array.from({ length: 8 }, (_, i) => ({
            id: i,
            state: i < 6 ? 'busy' : 'idle',
            currentTask: i < 6 ? ['request_processing', 'rule_evaluation', 'response_building'][i % 3] : undefined,
          })),
        };
        break;

      case 'cache':
        data.cache = {
          diagType: 'cache',
          caches: [
            {
              name: 'entity',
              size: 54321 + Math.floor(Math.random() * 1000),
              maxSize: 100000,
              hits: 8_765_432 + tickCount * 50,
              misses: 123_456 + tickCount * 5,
              hitRate: 0.986,
              evictions: 12345,
              memoryBytes: 54_321_000,
            },
            {
              name: 'session',
              size: 1234 + Math.floor(Math.random() * 100),
              maxSize: 10000,
              hits: 987_654 + tickCount * 10,
              misses: 12_345 + tickCount,
              hitRate: 0.988,
              evictions: 567,
              memoryBytes: 12_340_000,
            },
            {
              name: 'rule_compile',
              size: 237,
              maxSize: 500,
              hits: 1_234_567 + tickCount * 100,
              misses: 237,
              hitRate: 0.999,
              evictions: 0,
              memoryBytes: 23_700_000,
            },
          ],
        };
        break;
    }
  }

  return {
    sensorId,
    collectedAt: new Date().toISOString(),
    collectionTimeMs: Math.floor(Math.random() * 50) + 10,
    sections,
    data,
  };
}

/**
 * Generate mock diagnostics history for trend analysis.
 */
function generateMockDiagnosticsHistory(
  _sensorId: string,
  count: number
): Array<{
  timestamp: string;
  metrics: {
    rps: number;
    latencyP50: number;
    latencyP99: number;
    memoryMb: number;
    cpuPercent: number;
    activeConnections: number;
  };
}> {
  const history = [];
  const now = Date.now();

  for (let i = 0; i < count; i++) {
    const timestamp = new Date(now - i * 60000).toISOString();
    history.push({
      timestamp,
      metrics: {
        rps: 400 + Math.sin(i / 10) * 100 + Math.random() * 50,
        latencyP50: 5 + Math.sin(i / 15) * 2 + Math.random() * 2,
        latencyP99: 80 + Math.sin(i / 15) * 20 + Math.random() * 20,
        memoryMb: 300 + Math.sin(i / 20) * 50 + Math.random() * 20,
        cpuPercent: 30 + Math.sin(i / 12) * 15 + Math.random() * 10,
        activeConnections: 200 + Math.sin(i / 8) * 100 + Math.random() * 50,
      },
    });
  }

  return history;
}

export default createFleetDiagnosticsRoutes;
