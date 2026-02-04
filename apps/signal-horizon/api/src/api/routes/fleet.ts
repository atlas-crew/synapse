/**
 * Fleet Management API Routes
 * Endpoints for fleet-wide operations, sensor management, configuration, and rule distribution
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { z } from 'zod';
import { requireScope, requireRole } from '../middleware/auth.js';
import {
  validateParams,
  validateQuery,
  validateBody,
  IdParamSchema,
} from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';
import { rateLimiters } from '../../middleware/rate-limiter.js';
import type { FleetAggregator } from '../../services/fleet/fleet-aggregator.js';
import type { ConfigManager } from '../../services/fleet/config-manager.js';
import type { FleetCommander } from '../../services/fleet/fleet-commander.js';
import { CommandFeatureDisabledError } from '../../services/fleet/fleet-commander.js';
import type { RuleDistributor } from '../../services/fleet/rule-distributor.js';
import { SensorConfigService } from '../../services/sensorConfigService.js';
import { SensorConfigController } from '../../controllers/sensorConfigController.js';
import type { ClickHouseService } from '../../storage/clickhouse/index.js';
import { SecurityAuditService } from '../../services/audit/security-audit.js';
import type { ConfigTemplate } from '../../services/fleet/types.js';
import { ErrorCatalog } from '../../lib/errors.js';
import { sendProblem } from '../../lib/problem-details.js';

// ======================== Validation Schemas ========================

const ListSensorsQuerySchema = z.object({
  status: z.enum(['online', 'warning', 'offline', 'CONNECTED', 'DISCONNECTED', 'RECONNECTING']).optional(),
  region: z.string().optional(),
  version: z.string().optional(),
  search: z.string().optional(),
  sort: z.enum(['name', 'status', 'cpu', 'memory', 'rps', 'latency', 'version', 'region', 'lastHeartbeat']).optional(),
  sortDir: z.enum(['asc', 'desc']).default('asc'),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

/**
 * Safe config value schema - prevents dangerous nested structures and control characters.
 */
const SafeConfigValueSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z.string().max(10000).refine(
      (val) => !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(val),
      { message: 'String contains invalid control characters' }
    ),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(SafeConfigValueSchema).max(1000),
    z.record(SafeConfigValueSchema).refine(
      (obj) => Object.keys(obj).length <= 100,
      { message: 'Object has too many keys (max 100)' }
    ),
  ])
);

const CreateConfigTemplateBodySchema = z.object({
  name: z.string().min(1).max(255).refine(
    (val) => !/[\x00-\x1f\x7f]/.test(val.replace(/[\n\r\t]/g, '')),
    { message: 'Name contains invalid control characters' }
  ),
  description: z.string().max(5000).optional(),
  environment: z.enum(['production', 'staging', 'dev']).default('production'),
  config: z.record(SafeConfigValueSchema).refine(
    (obj) => Object.keys(obj).length <= 500,
    { message: 'Config has too many top-level keys (max 500)' }
  ),
});

const UpdateConfigTemplateBodySchema = CreateConfigTemplateBodySchema.partial();

const PushConfigBodySchema = z.object({
  templateId: z.string(),
  sensorIds: z.string().array().min(1),
});

const ConfigAuditQuerySchema = z.object({
  resourceId: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

/** Valid command types for fleet operations */
const VALID_COMMAND_TYPES = [
  'push_config',
  'push_rules',
  'update',
  'restart',
  'sync_blocklist',
  'toggle_chaos',
  'toggle_mtd'
] as const;

/**
 * Safe string validator function - prevents control characters.
 * Used to sanitize all user-provided string values in command payloads.
 */
function isSafeString(val: string): boolean {
  // Allow newlines/tabs but block other control characters
  return !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(val);
}

/**
 * Creates a safe string schema with the specified max length.
 */
function safeString(maxLength: number = 10000): z.ZodString {
  return z.string().max(maxLength);
}

/**
 * Safe string refinement - use after length validation.
 */
const SafeStringRefine = {
  check: isSafeString,
  message: 'String contains invalid control characters',
};

/**
 * Safe URL schema - validates URL format and blocks dangerous schemes.
 */
const SafeUrlSchema = z.string()
  .max(2048)
  .url()
  .refine(
    (val) => {
      try {
        const url = new URL(val);
        // Only allow http/https schemes for security
        return ['http:', 'https:'].includes(url.protocol);
      } catch {
        return false;
      }
    },
    { message: 'URL must use http or https protocol' }
  );

const CONFIG_AUDIT_ACTIONS = ['CONFIG_CREATED', 'CONFIG_UPDATED', 'CONFIG_DELETED'] as const;

function toConfigTemplateAuditValues(template: ConfigTemplate): Record<string, unknown> {
  return {
    name: template.name,
    description: template.description ?? null,
    environment: template.environment,
    config: template.config,
    hash: template.hash,
    version: template.version,
    isActive: template.isActive,
  };
}

/**
 * Type-specific payload schemas for fleet commands.
 * Each command type has a strictly defined payload structure to prevent injection attacks.
 */

/** push_config: Push configuration to sensors */
const PushConfigPayloadSchema = z.object({
  templateId: z.string().uuid().optional(),
  policyTemplateId: z.string().uuid().optional(),
  policyName: safeString(255).refine(SafeStringRefine.check, SafeStringRefine.message).optional(),
  policySeverity: z.enum(['strict', 'standard', 'permissive', 'dev']).optional(),
  config: z.record(z.union([
    z.string().max(10000).refine(SafeStringRefine.check, SafeStringRefine.message),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(z.union([z.string().max(1000), z.number(), z.boolean()])).max(1000),
  ])).optional(),
  version: z.string().max(50).regex(/^[\d.]+(-[\w.]+)?$/).optional(), // Semver-like format
  rolloutStrategy: z.enum(['immediate', 'canary', 'scheduled', 'rolling', 'blue_green']).optional(),
  component: z.enum(['pingora', 'waf', 'agent', 'collector']).optional(),
  action: z.enum(['test', 'reload']).optional(),
}).strict();

/** push_rules: Push security rules to sensors */
const PushRulesPayloadSchema = z.object({
  rules: z.array(z.object({
    id: z.string().uuid(),
    name: safeString(255).refine(SafeStringRefine.check, SafeStringRefine.message),
    enabled: z.boolean(),
    conditions: z.record(z.unknown()).optional(),
    actions: z.record(z.unknown()).optional(),
    priority: z.number().int().min(0).max(10000),
  })).max(1000).optional(),
  ruleIds: z.array(z.string().uuid()).max(1000).optional(),
  hash: z.string().max(128).regex(/^[a-f0-9]+$/i).optional(), // Hex hash
  activate: z.boolean().optional(),
  deploymentId: z.string().max(100).regex(/^[\w-]+$/).optional(),
  abort: z.boolean().optional(),
  retry: z.boolean().optional(),
}).strict();

/** update: Firmware/software update command */
const UpdatePayloadSchema = z.object({
  version: z.string().max(50).regex(/^[\d.]+(-[\w.]+)?$/), // Required semver-like format
  changelog: safeString(50000).refine(SafeStringRefine.check, SafeStringRefine.message).optional(),
  binary_url: SafeUrlSchema,
  sha256: z.string().length(64).regex(/^[a-f0-9]+$/i), // 64 hex chars
  size: z.number().int().min(0).max(1073741824), // Max 1GB
  released_at: z.string().datetime().optional(),
}).strict();

/** restart: Restart sensor services (minimal payload) */
const RestartPayloadSchema = z.object({
  component: z.enum(['all', 'pingora', 'waf', 'agent', 'collector']).optional(),
  graceful: z.boolean().optional(),
  delay_seconds: z.number().int().min(0).max(300).optional(),
}).strict();

/** sync_blocklist: Synchronize IP/domain blocklists */
const SyncBlocklistPayloadSchema = z.object({
  blocklist_id: z.string().uuid().optional(),
  blocklist_url: SafeUrlSchema.optional(),
  force_refresh: z.boolean().optional(),
  entries: z.array(z.object({
    type: z.enum(['ip', 'cidr', 'domain', 'url_pattern']),
    value: safeString(500).refine(SafeStringRefine.check, SafeStringRefine.message),
    ttl_seconds: z.number().int().min(0).max(86400 * 365).optional(),
  })).max(100000).optional(),
}).strict();

/** toggle_chaos: Trigger chaos spikes on sensors */
const ToggleChaosPayloadSchema = z.object({
  command: z.literal('toggle_chaos'),
  durationMs: z.number().int().min(1000).max(60000).optional(),
}).strict();

/** toggle_mtd: Set Moving Target Defense prefix */
const ToggleMtdPayloadSchema = z.object({
  command: z.literal('toggle_mtd'),
  prefix: z.string().max(32).optional(),
}).strict();

/**
 * Map of command types to their payload schemas.
 */
const COMMAND_PAYLOAD_SCHEMAS: Record<typeof VALID_COMMAND_TYPES[number], z.ZodSchema> = {
  push_config: PushConfigPayloadSchema,
  push_rules: PushRulesPayloadSchema,
  update: UpdatePayloadSchema,
  restart: RestartPayloadSchema,
  sync_blocklist: SyncBlocklistPayloadSchema,
  toggle_chaos: ToggleChaosPayloadSchema,
  toggle_mtd: ToggleMtdPayloadSchema,
};

/**
 * Base schema for send command requests.
 * Payload is validated separately based on commandType.
 */
const SendCommandBodySchema = z.object({
  commandType: z.enum(VALID_COMMAND_TYPES),
  sensorIds: z.array(z.string().uuid()).min(1).max(1000),
  payload: z.record(z.unknown()), // Validated below based on commandType
}).superRefine((data, ctx) => {
  // Validate payload against the command-specific schema
  const payloadSchema = COMMAND_PAYLOAD_SCHEMAS[data.commandType];
  const result = payloadSchema.safeParse(data.payload);

  if (!result.success) {
    for (const issue of result.error.issues) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['payload', ...issue.path],
        message: issue.message,
      });
    }
  }
});

/**
 * Schema for rule push requests with deployment strategy options.
 *
 * @property ruleIds - Array of rule IDs to deploy (required, at least one)
 * @property sensorIds - Array of target sensor IDs (required, at least one)
 * @property strategy - Deployment strategy (default: 'immediate')
 *   - 'immediate': Push to all sensors at once
 *   - 'canary': Gradual rollout (e.g., 10% → 50% → 100%)
 *   - 'scheduled': Deploy at a specific future time
 *   - 'rolling': Deploy in batches with health checks between each
 *   - 'blue_green': Stage to all sensors, then atomic switch
 *
 * Canary Strategy Options:
 * @property canaryPercentage - Initial percentage of sensors for canary (1-100)
 *
 * Scheduled Strategy Options:
 * @property scheduledTime - ISO 8601 datetime for scheduled deployment
 *
 * Rolling Strategy Options:
 * @property rollingBatchSize - Number of sensors to deploy per batch (1-100, default: 1)
 * @property healthCheckTimeout - Max time (ms) to wait for health confirmation (5000-300000, default: 30000)
 * @property maxFailuresBeforeAbort - Max failures before aborting deployment (1-100, default: 3)
 * @property rollbackOnFailure - Whether to rollback deployed sensors on abort (default: true)
 * @property healthCheckIntervalMs - Interval (ms) between health checks (1000-60000, default: 5000)
 *
 * Blue/Green Strategy Options:
 * @property stagingTimeout - Max time (ms) to wait for all sensors to stage (10000-600000, default: 60000)
 * @property switchTimeout - Max time (ms) to wait for atomic switch completion (5000-300000, default: 30000)
 * @property requireAllSensorsStaged - Require 100% of sensors to stage before switch (default: true)
 * @property minStagedPercentage - Minimum percentage of sensors that must stage (1-100, default: 100)
 * @property cleanupDelayMs - Delay (ms) before cleaning up old deployment (60000-3600000, default: 300000)
 */
const PushRulesBodySchema = z.object({
  ruleIds: z.string().array().min(1),
  sensorIds: z.string().array().min(1),
  strategy: z.enum(['immediate', 'canary', 'scheduled', 'rolling', 'blue_green']).default('immediate'),
  // Canary strategy options
  canaryPercentage: z.number().min(1).max(100).optional(),
  // Scheduled strategy options
  scheduledTime: z.string().datetime().optional(),
  // Rolling strategy options
  rollingBatchSize: z.number().min(1).max(100).optional(),
  healthCheckTimeout: z.number().min(5000).max(300000).optional(),
  maxFailuresBeforeAbort: z.number().min(1).max(100).optional(),
  rollbackOnFailure: z.boolean().optional(),
  healthCheckIntervalMs: z.number().min(1000).max(60000).optional(),
  // Blue/Green strategy options
  stagingTimeout: z.number().min(10000).max(600000).optional(),
  switchTimeout: z.number().min(5000).max(300000).optional(),
  requireAllSensorsStaged: z.boolean().optional(),
  minStagedPercentage: z.number().min(1).max(100).optional(),
  cleanupDelayMs: z.number().min(60000).max(3600000).optional(),
});

const SensorIdParamSchema = z.object({
  sensorId: z.string(),
});

const CommandIdParamSchema = z.object({
  commandId: z.string(),
});

const PingoraActionBodySchema = z.object({
  action: z.enum(['test', 'reload', 'restart']),
});

// ======================== Route Handler ========================

export function createFleetRoutes(
  prisma: PrismaClient,
  logger: Logger,
  options: {
    fleetAggregator?: FleetAggregator;
    configManager?: ConfigManager;
    fleetCommander?: FleetCommander;
    ruleDistributor?: RuleDistributor;
    clickhouse?: ClickHouseService | null;
    securityAuditService?: SecurityAuditService;
  }
): Router {
  const router = Router();
  const { fleetAggregator, configManager, fleetCommander, ruleDistributor, clickhouse } =
    options;

  const auditService = options.securityAuditService ?? new SecurityAuditService(prisma, logger);

  // Initialize Sensor Config Controller
  // We assume fleetCommander is available for sensor config operations
  // If not, the controller will fail gracefully or we can guard routes
  const sensorConfigService = fleetCommander 
    ? new SensorConfigService(prisma, logger, fleetCommander, auditService) 
    : null;
  const sensorConfigController = sensorConfigService 
    ? new SensorConfigController(sensorConfigService) 
    : null;

  // ======================== Fleet Metrics ========================

  /**
   * GET /api/v1/fleet/metrics
   * Get fleet-wide aggregated metrics
   */
  router.get('/', requireScope('fleet:read'), async (_req, res) => {
    try {
      if (!fleetAggregator) {
        res
          .status(503)
          .json({ error: 'Fleet aggregator service not available' });
        return;
      }

      const metrics = fleetAggregator.getFleetMetrics();
      res.json(metrics);
    } catch (error) {
      logger.error({ error }, 'Failed to get fleet metrics');
      res.status(500).json({
        error: 'Failed to get fleet metrics',
        message: getErrorMessage(error),
      });
    }
  });

  /**
   * GET /api/v1/fleet/overview
   * Get comprehensive fleet overview with regional breakdown
   */
  router.get('/overview', requireScope('fleet:read'), async (req, res) => {
    try {
      const auth = req.auth!;

      // Get all sensors for this tenant
      const sensors = await prisma.sensor.findMany({
        where: { tenantId: auth.tenantId },
        select: {
          id: true,
          name: true,
          region: true,
          version: true,
          connectionState: true,
          lastHeartbeat: true,
          metadata: true,
        },
      });

      // Calculate status counts
      const now = Date.now();
      const warningThreshold = 2 * 60 * 1000; // 2 minutes
      const offlineThreshold = 5 * 60 * 1000; // 5 minutes

      let onlineCount = 0;
      let warningCount = 0;
      let offlineCount = 0;

      const regionStats: Record<string, { online: number; warning: number; offline: number }> = {};

      for (const sensor of sensors) {
        const lastHeartbeat = sensor.lastHeartbeat ? new Date(sensor.lastHeartbeat).getTime() : 0;
        const timeSinceHeartbeat = now - lastHeartbeat;

        let status: 'online' | 'warning' | 'offline';
        if (sensor.connectionState === 'DISCONNECTED' || timeSinceHeartbeat > offlineThreshold) {
          status = 'offline';
          offlineCount++;
        } else if (timeSinceHeartbeat > warningThreshold) {
          status = 'warning';
          warningCount++;
        } else {
          status = 'online';
          onlineCount++;
        }

        // Aggregate by region
        const region = sensor.region || 'unknown';
        if (!regionStats[region]) {
          regionStats[region] = { online: 0, warning: 0, offline: 0 };
        }
        regionStats[region][status]++;
      }

      // Get fleet metrics from aggregator if available
      let fleetMetrics = null;
      if (fleetAggregator) {
        fleetMetrics = fleetAggregator.getFleetMetrics();
      }

      // Get recent alerts
      const recentAlerts = await prisma.fleetCommand.findMany({
        where: {
          sensor: { tenantId: auth.tenantId },
          status: 'failed',
          createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
        },
        take: 5,
        orderBy: { createdAt: 'desc' },
        include: { sensor: { select: { name: true } } },
      });

      // Get version distribution
      const versionCounts: Record<string, number> = {};
      for (const sensor of sensors) {
        const version = sensor.version || 'unknown';
        versionCounts[version] = (versionCounts[version] || 0) + 1;
      }

      res.json({
        summary: {
          totalSensors: sensors.length,
          onlineCount,
          warningCount,
          offlineCount,
          healthScore: sensors.length > 0 ? Math.round((onlineCount / sensors.length) * 100) : 100,
        },
        fleetMetrics: fleetMetrics || {
          totalRps: 0,
          avgLatency: 0,
          avgCpu: 0,
          avgMemory: 0,
        },
        regionDistribution: Object.entries(regionStats).map(([region, stats]) => ({
          region,
          ...stats,
          total: stats.online + stats.warning + stats.offline,
        })),
        versionDistribution: Object.entries(versionCounts).map(([version, count]) => ({
          version,
          count,
        })),
        recentAlerts: recentAlerts.map((cmd) => ({
          id: cmd.id,
          sensorName: cmd.sensor.name,
          type: cmd.commandType,
          error: cmd.error,
          createdAt: cmd.createdAt,
        })),
      });
    } catch (error) {
      logger.error({ error }, 'Failed to get fleet overview');
      res.status(500).json({
        error: 'Failed to get fleet overview',
        message: getErrorMessage(error),
      });
    }
  });

  // ======================== Sensor Management ========================

  /**
   * GET /api/v1/fleet/sensors
   * List all sensors with filtering and pagination
   */
  router.get(
    '/sensors',
    requireScope('fleet:read'),
    validateQuery(ListSensorsQuerySchema),
    async (req, res) => {
      try {
        const { status, region, version, search, sort, sortDir, limit, offset } = req.query as unknown as z.infer<
          typeof ListSensorsQuerySchema
        >;
        const auth = req.auth!;

        const where: Record<string, unknown> = {
          tenantId: auth.tenantId,
        };

        // Handle connection state status filter
        if (status && ['CONNECTED', 'DISCONNECTED', 'RECONNECTING'].includes(status)) {
          where.connectionState = status;
        }

        // Handle region filter
        if (region) {
          where.region = region;
        }

        // Handle version filter
        if (version) {
          where.version = version;
        }

        // Handle search filter (search by name)
        if (search) {
          where.name = { contains: search, mode: 'insensitive' };
        }

        // Determine sort order
        const orderBy: Record<string, string> = {};
        if (sort) {
          orderBy[sort] = sortDir;
        } else {
          orderBy.lastHeartbeat = 'desc';
        }

        const [sensors, total] = await Promise.all([
          prisma.sensor.findMany({
            where,
            take: limit,
            skip: offset,
            orderBy,
          }),
          prisma.sensor.count({ where }),
        ]);

        // If filtering by computed status (online/warning/offline), we need to post-process
        let filteredSensors = sensors;
        if (status && ['online', 'warning', 'offline'].includes(status)) {
          const now = Date.now();
          const warningThreshold = 2 * 60 * 1000; // 2 minutes
          const offlineThreshold = 5 * 60 * 1000; // 5 minutes

          filteredSensors = sensors.filter((sensor) => {
            const lastHeartbeat = sensor.lastHeartbeat ? new Date(sensor.lastHeartbeat).getTime() : 0;
            const timeSinceHeartbeat = now - lastHeartbeat;

            let computedStatus: 'online' | 'warning' | 'offline';
            if (sensor.connectionState === 'DISCONNECTED' || timeSinceHeartbeat > offlineThreshold) {
              computedStatus = 'offline';
            } else if (timeSinceHeartbeat > warningThreshold) {
              computedStatus = 'warning';
            } else {
              computedStatus = 'online';
            }

            return computedStatus === status;
          });
        }

        res.json({
          sensors: filteredSensors,
          pagination: { total, limit, offset },
        });
      } catch (error) {
        logger.error({ error }, 'Failed to list sensors');
        res.status(500).json({
          error: 'Failed to list sensors',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/sensors/:sensorId
   * Get detailed information about a specific sensor
   */
  router.get(
    '/sensors/:sensorId',
    requireScope('fleet:read'),
    validateParams(SensorIdParamSchema),
    async (req, res) => {
      try {
        const { sensorId } = req.params;
        const auth = req.auth!;

        const sensor = await prisma.sensor.findUnique({
          where: { id: sensorId },
          include: {
            commands: {
              take: 10,
              orderBy: { createdAt: 'desc' },
            },
          },
        });

        if (!sensor || sensor.tenantId !== auth.tenantId) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        res.json(sensor);
      } catch (error) {
        logger.error({ error }, 'Failed to get sensor details');
        res.status(500).json({
          error: 'Failed to get sensor details',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/sensors/:sensorId/system
   * Get system information for a sensor (OS, kernel, IPs, etc.)
   */
  router.get(
    '/sensors/:sensorId/system',
    requireScope('fleet:read'),
    validateParams(SensorIdParamSchema),
    async (req, res) => {
      try {
        const { sensorId } = req.params;
        const auth = req.auth!;

        const sensor = await prisma.sensor.findUnique({
          where: { id: sensorId },
          select: {
            id: true,
            name: true,
            tenantId: true,
            publicIp: true,
            privateIp: true,
            os: true,
            kernel: true,
            architecture: true,
            instanceType: true,
            lastBoot: true,
            uptime: true,
            version: true,
            region: true,
            connectionState: true,
            lastHeartbeat: true,
            tunnelActive: true,
            metadata: true,
          },
        });

        if (!sensor || sensor.tenantId !== auth.tenantId) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        // Calculate connection stats
        const now = Date.now();
        const lastHeartbeat = sensor.lastHeartbeat ? new Date(sensor.lastHeartbeat).getTime() : 0;
        const connectionLatency = lastHeartbeat > 0 ? now - lastHeartbeat : null;

        res.json({
          hostname: sensor.name,
          sensorId: sensor.id,
          version: sensor.version,
          os: sensor.os || 'Unknown',
          kernel: sensor.kernel || 'Unknown',
          architecture: sensor.architecture || 'x86_64',
          publicIp: sensor.publicIp || 'N/A',
          privateIp: sensor.privateIp || 'N/A',
          region: sensor.region,
          instanceType: sensor.instanceType || 'Unknown',
          lastBoot: sensor.lastBoot,
          uptime: sensor.uptime || 0,
          connection: {
            state: sensor.connectionState,
            lastHeartbeat: sensor.lastHeartbeat,
            latencyMs: connectionLatency,
            tunnelActive: sensor.tunnelActive,
          },
          metadata: sensor.metadata,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to get sensor system info');
        res.status(500).json({
          error: 'Failed to get sensor system info',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/sensors/:sensorId/performance
   * Get performance metrics for a sensor
   */
  router.get(
    '/sensors/:sensorId/performance',
    requireScope('fleet:read'),
    validateParams(SensorIdParamSchema),
    async (req, res) => {
      try {
        const { sensorId } = req.params;
        const auth = req.auth!;

        const sensor = await prisma.sensor.findUnique({
          where: { id: sensorId },
          select: {
            id: true,
            tenantId: true,
            metadata: true,
          },
        });

        if (!sensor || sensor.tenantId !== auth.tenantId) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        // Extract performance metrics from metadata or generate mock data
        // Safe extraction with null coalescing for untyped JSON metadata
        const meta: Record<string, unknown> =
          sensor.metadata && typeof sensor.metadata === 'object' && !Array.isArray(sensor.metadata)
            ? (sensor.metadata as Record<string, unknown>)
            : {};

        res.json({
          current: {
            cpu: meta.cpu ?? Math.random() * 40 + 10,
            memory: meta.memory ?? Math.random() * 30 + 20,
            disk: meta.disk ?? Math.random() * 20 + 30,
            loadAverage: [meta.load1 ?? 0.5, meta.load5 ?? 0.4, meta.load15 ?? 0.3],
            rps: meta.rps ?? Math.floor(Math.random() * 1000),
            latencyP50: meta.latencyP50 ?? Math.random() * 10 + 5,
            latencyP99: meta.latencyP99 ?? Math.random() * 50 + 20,
          },
          history: Array.from({ length: 60 }, (_, i) => ({
            timestamp: new Date(Date.now() - (59 - i) * 60000).toISOString(),
            cpu: Math.random() * 40 + 10,
            memory: Math.random() * 30 + 20,
            rps: Math.floor(Math.random() * 1000),
            latencyMs: Math.random() * 30 + 10,
          })),
          diskIO: {
            readBytesPerSec: Math.floor(Math.random() * 10000000),
            writeBytesPerSec: Math.floor(Math.random() * 5000000),
            iops: Math.floor(Math.random() * 500),
            ioWait: Math.random() * 5,
          },
          benchmarks: [
            { name: 'Request Processing', value: 2.1, unit: 'ms', status: 'good' },
            { name: 'Rule Evaluation', value: 0.8, unit: 'ms', status: 'good' },
            { name: 'SSL Handshake', value: 12.5, unit: 'ms', status: 'warning' },
            { name: 'Backend Response', value: 45.2, unit: 'ms', status: 'good' },
          ],
        });
      } catch (error) {
        logger.error({ error }, 'Failed to get sensor performance');
        res.status(500).json({
          error: 'Failed to get sensor performance',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/sensors/:sensorId/network
   * Get network information for a sensor
   */
  router.get(
    '/sensors/:sensorId/network',
    requireScope('fleet:read'),
    validateParams(SensorIdParamSchema),
    async (req, res) => {
      try {
        const { sensorId } = req.params;
        const auth = req.auth!;

        const sensor = await prisma.sensor.findUnique({
          where: { id: sensorId },
          select: {
            id: true,
            tenantId: true,
            publicIp: true,
            privateIp: true,
            metadata: true,
          },
        });

        if (!sensor || sensor.tenantId !== auth.tenantId) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        res.json({
          traffic: {
            inboundMbps: Math.random() * 100 + 50,
            outboundMbps: Math.random() * 50 + 20,
            packetsPerSec: Math.floor(Math.random() * 10000),
            activeConnections: Math.floor(Math.random() * 500 + 100),
          },
          interfaces: [
            { name: 'eth0', ip: sensor.privateIp || '10.0.1.100', rxMbps: 45.2, txMbps: 12.8, status: 'up' },
            { name: 'eth1', ip: sensor.publicIp || '203.0.113.50', rxMbps: 78.5, txMbps: 35.2, status: 'up' },
            { name: 'lo', ip: '127.0.0.1', rxMbps: 0.1, txMbps: 0.1, status: 'up' },
          ],
          connections: Array.from({ length: 10 }, (_, i) => ({
            protocol: i % 2 === 0 ? 'TCP' : 'UDP',
            localAddress: `10.0.1.100:${8080 + i}`,
            remoteAddress: `203.0.113.${i + 1}:${443 + i * 100}`,
            state: ['ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT'][i % 3],
            pid: 1000 + i,
            program: ['synapse-pingora', 'atlascrew-agent', 'node'][i % 3],
            duration: Math.floor(Math.random() * 3600),
          })),
          dns: {
            primary: '8.8.8.8',
            secondary: '8.8.4.4',
            latencyMs: Math.random() * 20 + 5,
          },
          history: Array.from({ length: 60 }, (_, i) => ({
            timestamp: new Date(Date.now() - (59 - i) * 60000).toISOString(),
            inboundMbps: Math.random() * 100 + 50,
            outboundMbps: Math.random() * 50 + 20,
          })),
        });
      } catch (error) {
        logger.error({ error }, 'Failed to get sensor network info');
        res.status(500).json({
          error: 'Failed to get sensor network info',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/sensors/:sensorId/processes
   * Get running processes for a sensor
   */
  router.get(
    '/sensors/:sensorId/processes',
    requireScope('fleet:read'),
    validateParams(SensorIdParamSchema),
    async (req, res) => {
      try {
        const { sensorId } = req.params;
        const auth = req.auth!;

        const sensor = await prisma.sensor.findUnique({
          where: { id: sensorId },
          select: { id: true, tenantId: true },
        });

        if (!sensor || sensor.tenantId !== auth.tenantId) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        const processes = [
          { pid: 1, name: 'systemd', user: 'root', cpu: 0.1, memory: 0.2, status: 'running', threads: 1 },
          { pid: 1234, name: 'synapse-pingora', user: 'atlascrew', cpu: 2.5, memory: 1.8, status: 'running', threads: 4 },
          { pid: 1235, name: 'synapse-pingora', user: 'atlascrew', cpu: 2.3, memory: 1.7, status: 'running', threads: 4 },
          { pid: 2001, name: 'atlascrew-agent', user: 'atlascrew', cpu: 5.2, memory: 3.4, status: 'running', threads: 8 },
          { pid: 2002, name: 'atlascrew-collector', user: 'atlascrew', cpu: 3.1, memory: 2.1, status: 'running', threads: 4 },
          { pid: 2003, name: 'atlascrew-waf', user: 'atlascrew', cpu: 8.5, memory: 6.2, status: 'running', threads: 16 },
          { pid: 3001, name: 'postgresql', user: 'postgres', cpu: 1.2, memory: 4.5, status: 'running', threads: 6 },
          { pid: 3002, name: 'redis-server', user: 'redis', cpu: 0.8, memory: 1.2, status: 'running', threads: 4 },
          { pid: 4001, name: 'unbound', user: 'unbound', cpu: 0.3, memory: 0.5, status: 'running', threads: 2 },
          { pid: 5001, name: 'sshd', user: 'root', cpu: 0.0, memory: 0.1, status: 'sleeping', threads: 1 },
        ];

        const services = [
          { name: 'atlascrew-waf', status: 'active', pid: 2003, uptime: 86400 * 7, health: 'healthy' },
          { name: 'atlascrew-agent', status: 'active', pid: 2001, uptime: 86400 * 7, health: 'healthy' },
          { name: 'atlascrew-collector', status: 'active', pid: 2002, uptime: 86400 * 7, health: 'healthy' },
          { name: 'synapse-pingora', status: 'active', pid: 1234, uptime: 86400 * 14, health: 'healthy' },
          { name: 'postgresql', status: 'active', pid: 3001, uptime: 86400 * 30, health: 'healthy' },
          { name: 'redis', status: 'active', pid: 3002, uptime: 86400 * 30, health: 'healthy' },
        ];

        res.json({
          summary: {
            totalProcesses: processes.length,
            totalThreads: processes.reduce((acc, p) => acc + p.threads, 0),
            systemServicesHealthy: services.filter((s) => s.health === 'healthy').length,
            openFiles: Math.floor(Math.random() * 1000 + 500),
          },
          processes,
          services,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to get sensor processes');
        res.status(500).json({
          error: 'Failed to get sensor processes',
          message: getErrorMessage(error),
        });
      }
    }
  );

const SensorLogsQuerySchema = z.object({
  type: z.enum(['access', 'error', 'system', 'waf']).default('access'),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});

  /**
   * GET /api/v1/fleet/sensors/:sensorId/logs
   * Get log entries for a sensor
   */
  router.get(
    '/sensors/:sensorId/logs',
    requireScope('fleet:read'),
    validateParams(SensorIdParamSchema),
    validateQuery(SensorLogsQuerySchema),
    async (req, res) => {
      try {
        const { sensorId } = req.params;
        const validatedQuery = req.query as unknown as z.infer<typeof SensorLogsQuerySchema>;
        const { type, limit } = validatedQuery;
        const auth = req.auth!;

        const sensor = await prisma.sensor.findUnique({
          where: { id: sensorId },
          select: { id: true, tenantId: true },
        });

        if (!sensor || sensor.tenantId !== auth.tenantId) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        if (!clickhouse || !clickhouse.isEnabled()) {
          res.status(503).json({ error: 'clickhouse_disabled' });
          return;
        }

        type LogRow = {
          timestamp: string;
          log_id: string;
          source: string;
          level: string;
          message: string;
          fields: string | null;
          method: string | null;
          path: string | null;
          status_code: number | null;
          latency_ms: number | null;
          client_ip: string | null;
          rule_id: string | null;
        };

        const whereClauses: string[] = [
          'tenant_id = {tenantId:String}',
          'sensor_id = {sensorId:String}',
        ];
        const params: Record<string, unknown> = {
          tenantId: auth.tenantId,
          sensorId,
          limit,
        };

        if (type === 'error') {
          whereClauses.push('level IN {levels:Array(String)}');
          params.levels = ['error', 'fatal'];
        } else {
          whereClauses.push('source IN {sources:Array(String)}');
          params.sources = [type];
        }

        const sql = `
          SELECT timestamp, log_id, source, level, message, fields, method, path,
            status_code, latency_ms, client_ip, rule_id
          FROM sensor_logs
          WHERE ${whereClauses.join(' AND ')}
          ORDER BY timestamp DESC
          LIMIT {limit:UInt32}
        `;

        const rows = await clickhouse.queryWithParams<LogRow>(sql, params);
        const logs = rows.map((row) => {
          let parsedFields: Record<string, unknown> | undefined;
          if (row.fields) {
            try {
              parsedFields = JSON.parse(row.fields) as Record<string, unknown>;
            } catch {
              parsedFields = undefined;
            }
          }

          return {
            id: row.log_id,
            timestamp: row.timestamp,
            source: row.source,
            level: row.level,
            message: row.message,
            fields: parsedFields,
            method: row.method ?? undefined,
            path: row.path ?? undefined,
            statusCode: row.status_code ?? undefined,
            latencyMs: row.latency_ms ?? undefined,
            clientIp: row.client_ip ?? undefined,
            ruleId: row.rule_id ?? undefined,
          };
        });

        res.json({
          type,
          logs,
          total: logs.length,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to get sensor logs');
        res.status(500).json({
          error: 'Failed to get sensor logs',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * POST /api/v1/fleet/sensors/:sensorId/actions/restart
   * Restart a sensor
   */
  router.post(
    '/sensors/:sensorId/actions/restart',
    rateLimiters.fleetCommand,
    requireScope('fleet:write'),
    requireRole('operator'),
    validateParams(SensorIdParamSchema),
    async (req, res) => {
      try {
        const { sensorId } = req.params;
        const auth = req.auth!;

        const sensor = await prisma.sensor.findUnique({
          where: { id: sensorId },
          select: { id: true, tenantId: true },
        });

        if (!sensor || sensor.tenantId !== auth.tenantId) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        // Create restart command
        if (fleetCommander) {
          await fleetCommander.sendCommand(auth.tenantId, sensorId, {
            type: 'restart',
            payload: {},
          });
        }

        res.json({ message: 'Restart command sent', sensorId });
      } catch (error) {
        logger.error({ error }, 'Failed to restart sensor');
        res.status(500).json({
          error: 'Failed to restart sensor',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * POST /api/v1/fleet/sensors/:sensorId/diagnostics/run
   * Run diagnostic checks on a sensor
   */
  router.post(
    '/sensors/:sensorId/diagnostics/run',
    rateLimiters.fleetCommand,
    requireScope('fleet:write'),
    requireRole('operator'),
    validateParams(SensorIdParamSchema),
    async (req, res) => {
      try {
        const { sensorId } = req.params;
        const auth = req.auth!;

        const sensor = await prisma.sensor.findUnique({
          where: { id: sensorId },
          select: { id: true, tenantId: true },
        });

        if (!sensor || sensor.tenantId !== auth.tenantId) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        // Return mock diagnostic results
        res.json({
          sensorId,
          runAt: new Date().toISOString(),
          checks: [
            { name: 'Network Connectivity', status: 'passed', message: 'All endpoints reachable' },
            { name: 'Disk Space', status: 'passed', message: '68% free (34GB/50GB)' },
            { name: 'Memory Usage', status: 'passed', message: '45% used (3.6GB/8GB)' },
            { name: 'CPU Load', status: 'passed', message: 'Load average: 0.5, 0.4, 0.3' },
            { name: 'Atlas Crew Services', status: 'passed', message: 'All 3 services running' },
            { name: 'SSL Certificates', status: 'warning', message: 'Certificate expires in 30 days' },
            { name: 'Log Rotation', status: 'passed', message: 'Logs rotated successfully' },
            { name: 'Time Sync', status: 'passed', message: 'NTP synced, offset < 1ms' },
          ],
        });
      } catch (error) {
        logger.error({ error }, 'Failed to run diagnostics');
        res.status(500).json({
          error: 'Failed to run diagnostics',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/sensors/:sensorId/config/pingora
   * Get Pingora configuration for a sensor
   */
  router.get(
    '/sensors/:sensorId/config/pingora',
    requireScope('fleet:read'),
    validateParams(SensorIdParamSchema),
    async (req, res) => {
      if (!sensorConfigController) {
        const entry = ErrorCatalog.SERVICE_UNAVAILABLE;
        return sendProblem(res, entry.status, 'Sensor config service not available', {
          code: entry.code,
          hint: entry.hint,
          instance: req.originalUrl,
          context: { operation: 'getConfig' },
        });
      }
      return sensorConfigController.getConfig(req, res);
    }
  );

  /**
   * POST /api/v1/fleet/sensors/:sensorId/config/pingora
   * Update Pingora configuration and push to sensor
   */
  router.post(
    '/sensors/:sensorId/config/pingora',
    rateLimiters.configMutation,
    requireScope('fleet:write'),
    requireRole('operator'),
    validateParams(SensorIdParamSchema),
    async (req, res) => {
      if (!sensorConfigController) {
        const entry = ErrorCatalog.SERVICE_UNAVAILABLE;
        return sendProblem(res, entry.status, 'Sensor config service not available', {
          code: entry.code,
          hint: entry.hint,
          instance: req.originalUrl,
          context: { operation: 'updateConfig' },
        });
      }
      return sensorConfigController.updateConfig(req, res);
    }
  );

  /**
   * POST /api/v1/fleet/sensors/:sensorId/actions/pingora
   * Trigger Pingora service actions (test, reload, restart)
   */
  router.post(
    '/sensors/:sensorId/actions/pingora',
    rateLimiters.fleetCommand,
    requireScope('fleet:write'),
    requireRole('operator'),
    validateParams(SensorIdParamSchema),
    validateBody(PingoraActionBodySchema),
    async (req, res) => {
      try {
        const { sensorId } = req.params;
        const { action } = req.body as z.infer<typeof PingoraActionBodySchema>;
        const auth = req.auth!;

        if (fleetCommander) {
          await fleetCommander.sendCommand(auth.tenantId, sensorId, {
            type: action === 'restart' ? 'restart' : 'push_config',
            payload: {
              component: 'pingora',
              action, // 'test' or 'reload'
            },
          });
        }

        res.json({ message: `Pingora ${action} command sent`, sensorId });
      } catch (error) {
        logger.error({ error }, 'Failed to trigger Pingora action');
        res.status(500).json({
          error: 'Failed to trigger Pingora action',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/alerts
   * Get list of sensors requiring attention (offline, high resource usage, etc.)
   */
  router.get('/alerts', requireScope('fleet:read'), async (req, res) => {
    try {
      const auth = req.auth!;

      // Find sensors with issues
      const problematicSensors = await prisma.sensor.findMany({
        where: {
          tenantId: auth.tenantId,
          OR: [
            {
              connectionState: {
                in: ['DISCONNECTED', 'RECONNECTING'],
              },
            },
            {
              lastHeartbeat: {
                lt: new Date(Date.now() - 5 * 60 * 1000), // Last heartbeat > 5 min ago
              },
            },
          ],
        },
        select: {
          id: true,
          name: true,
          connectionState: true,
          lastHeartbeat: true,
          metadata: true,
        },
      });

      // Find commands with failures
      const failedCommands = await prisma.fleetCommand.findMany({
        where: {
          sensor: { tenantId: auth.tenantId },
          status: 'failed',
          createdAt: {
            gte: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
          },
        },
        take: 10,
        orderBy: { createdAt: 'desc' },
      });

      res.json({
        offlineSensors: problematicSensors,
        recentFailures: failedCommands,
      });
    } catch (error) {
      logger.error({ error }, 'Failed to get fleet alerts');
      res.status(500).json({
        error: 'Failed to get fleet alerts',
        message: getErrorMessage(error),
      });
    }
  });

  // ======================== Configuration Management ========================

  /**
   * GET /api/v1/fleet/config/templates
   * List configuration templates
   */
  router.get(
    '/config/templates',
    requireScope('config:read'),
    async (_req, res) => {
      try {
        if (!configManager) {
          res
            .status(503)
            .json({ error: 'Config manager service not available' });
          return;
        }

        const templates = await configManager.listTemplates();
        res.json({ templates });
      } catch (error) {
        logger.error({ error }, 'Failed to list config templates');
        res.status(500).json({
          error: 'Failed to list config templates',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * POST /api/v1/fleet/config/templates
   * Create a new configuration template
   */
  router.post(
    '/config/templates',
    rateLimiters.configMutation,
    requireScope('config:write'),
    requireRole('operator'),
    validateBody(CreateConfigTemplateBodySchema),
    async (req, res) => {
      try {
        if (!configManager) {
          res
            .status(503)
            .json({ error: 'Config manager service not available' });
          return;
        }

        const { name, description, environment, config } = req.body as z.infer<
          typeof CreateConfigTemplateBodySchema
        >;

        // Generate config hash
        const hash = await configManager.computeConfigHash(config);

        const template = await configManager.createTemplate({
          name,
          description,
          environment,
          config,
          hash,
          version: '1.0.0',
          isActive: true,
        });

        await auditService.logConfigCreated(
          req,
          'config_template',
          template.id,
          toConfigTemplateAuditValues(template)
        );

        res.status(201).json(template);
      } catch (error) {
        logger.error({ error }, 'Failed to create config template');
        res.status(500).json({
          error: 'Failed to create config template',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/config/templates/:id
   * Get a specific configuration template
   */
  router.get(
    '/config/templates/:id',
    requireScope('config:read'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        if (!configManager) {
          res
            .status(503)
            .json({ error: 'Config manager service not available' });
          return;
        }

        const { id } = req.params;
        const template = await configManager.getTemplate(id);

        if (!template) {
          res.status(404).json({ error: 'Template not found' });
          return;
        }

        res.json(template);
      } catch (error) {
        logger.error({ error }, 'Failed to get config template');
        res.status(500).json({
          error: 'Failed to get config template',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * PUT /api/v1/fleet/config/templates/:id
   * Update a configuration template
   */
  router.put(
    '/config/templates/:id',
    rateLimiters.configMutation,
    requireScope('config:write'),
    requireRole('operator'),
    validateParams(IdParamSchema),
    validateBody(UpdateConfigTemplateBodySchema),
    async (req, res) => {
      try {
        if (!configManager) {
          res
            .status(503)
            .json({ error: 'Config manager service not available' });
          return;
        }

        const { id } = req.params;
        const updates = req.body as z.infer<
          typeof UpdateConfigTemplateBodySchema
        >;

        const previous = await configManager.getTemplate(id);
        if (!previous) {
          res.status(404).json({ error: 'Template not found' });
          return;
        }

        const template = await configManager.updateTemplate(id, updates);

        await auditService.logConfigUpdated(
          req,
          'config_template',
          id,
          toConfigTemplateAuditValues(previous),
          toConfigTemplateAuditValues(template)
        );

        res.json(template);
      } catch (error) {
        logger.error({ error }, 'Failed to update config template');
        res.status(500).json({
          error: 'Failed to update config template',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * DELETE /api/v1/fleet/config/templates/:id
   * Delete a configuration template
   */
  router.delete(
    '/config/templates/:id',
    rateLimiters.configMutation,
    requireScope('config:write'),
    requireRole('admin'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        if (!configManager) {
          res
            .status(503)
            .json({ error: 'Config manager service not available' });
          return;
        }

        const { id } = req.params;
        const previous = await configManager.getTemplate(id);
        if (!previous) {
          res.status(404).json({ error: 'Template not found' });
          return;
        }

        await configManager.deleteTemplate(id);
        await auditService.logConfigDeleted(
          req,
          'config_template',
          id,
          toConfigTemplateAuditValues(previous)
        );
        res.status(204).send();
      } catch (error) {
        logger.error({ error }, 'Failed to delete config template');
        res.status(500).json({
          error: 'Failed to delete config template',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/config/audit
   * List recent configuration audit events
   */
  router.get(
    '/config/audit',
    requireScope('config:read'),
    validateQuery(ConfigAuditQuerySchema),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const { resourceId, limit, offset } = req.query as z.infer<
          typeof ConfigAuditQuerySchema
        >;

        const where = {
          tenantId: auth.tenantId,
          action: { in: [...CONFIG_AUDIT_ACTIONS] },
          ...(resourceId ? { resourceId } : {}),
        };

        const [logs, total] = await Promise.all([
          prisma.auditLog.findMany({
            where,
            orderBy: { createdAt: 'desc' },
            take: limit,
            skip: offset,
          }),
          prisma.auditLog.count({ where }),
        ]);

        res.json({
          logs: logs.map((log) => ({
            id: log.id,
            action: log.action,
            resource: log.resource,
            resourceId: log.resourceId,
            userId: log.userId,
            createdAt: log.createdAt,
            details: log.details,
          })),
          total,
          limit,
          offset,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to list config audit logs');
        res.status(500).json({
          error: 'Failed to list config audit logs',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * POST /api/v1/fleet/config/push
   * Push configuration to sensors
   */
  router.post(
    '/config/push',
    rateLimiters.configMutation,
    requireScope('config:write'),
    requireRole('operator'),
    validateBody(PushConfigBodySchema),
    async (req, res) => {
      try {
        if (!configManager || !fleetCommander) {
          res
            .status(503)
            .json({ error: 'Fleet services not available' });
          return;
        }

        const { templateId, sensorIds } = req.body as z.infer<
          typeof PushConfigBodySchema
        >;
        const auth = req.auth!;

        const template = await configManager.getTemplate(templateId);
        if (!template) {
          res.status(404).json({ error: 'Template not found' });
          return;
        }

        // Send push_config command to each sensor
        const commands = await Promise.all(
          sensorIds.map((sensorId) =>
            fleetCommander!.sendCommand(auth.tenantId, sensorId, {
              type: 'push_config',
              payload: {
                templateId,
                config: template.config,
              },
            })
          )
        );

        res.status(202).json({
          message: 'Configuration push initiated',
          commands,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to push configuration');
        res.status(500).json({
          error: 'Failed to push configuration',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/config/sync-status
   * Get configuration sync status across all sensors
   */
  router.get('/config/sync-status', requireScope('config:read'), async (req, res) => {
    try {
      const auth = req.auth!;

      // Get all sensors for the tenant with their sync state
      const sensors = await prisma.sensor.findMany({
        where: auth.tenantId ? { tenantId: auth.tenantId } : undefined,
        select: {
          id: true,
          connectionState: true,
          syncState: true,
        },
      });

      const totalSensors = sensors.length;
      const syncedSensors = sensors.filter(
        (s) => s.connectionState === 'CONNECTED' && s.syncState?.lastSyncSuccess
      ).length;
      const outOfSyncSensors = sensors.filter(
        (s) => s.connectionState === 'CONNECTED' && !s.syncState?.lastSyncSuccess
      ).length;
      const errorSensors = sensors.filter(
        (s) => s.connectionState === 'ERROR'
      ).length;

      res.json({
        totalSensors,
        syncedSensors,
        outOfSyncSensors,
        errorSensors,
        syncPercentage: totalSensors > 0 ? Math.round((syncedSensors / totalSensors) * 100) : 0,
      });
    } catch (error) {
      logger.error({ error }, 'Failed to get config sync status');
      res.status(500).json({
        error: 'Failed to get config sync status',
        message: getErrorMessage(error),
      });
    }
  });

  // ======================== Command Management ========================

  /**
   * GET /api/v1/fleet/commands
   * Get command history with filtering
   */
  router.get('/commands', requireScope('fleet:read'), async (req, res) => {
    try {
      const auth = req.auth!;
      const { status, limit = '50', offset = '0' } = req.query;

      const where: Record<string, unknown> = {
        sensor: { tenantId: auth.tenantId },
      };

      if (status) {
        where.status = status;
      }

      const [commands, total] = await Promise.all([
        prisma.fleetCommand.findMany({
          where,
          take: Math.min(parseInt(limit as string, 10), 100),
          skip: parseInt(offset as string, 10),
          orderBy: { createdAt: 'desc' },
        }),
        prisma.fleetCommand.count({ where }),
      ]);

      res.json({
        commands,
        pagination: {
          total,
          limit: parseInt(limit as string, 10),
          offset: parseInt(offset as string, 10),
        },
      });
    } catch (error) {
      logger.error({ error }, 'Failed to list commands');
      res.status(500).json({
        error: 'Failed to list commands',
        message: getErrorMessage(error),
      });
    }
  });

  /**
   * POST /api/v1/fleet/commands
   * Send a command to multiple sensors
   */
  router.post(
    '/commands',
    rateLimiters.fleetCommand,
    requireScope('fleet:write'),
    requireRole('operator'),
    validateBody(SendCommandBodySchema),
    async (req, res) => {
      try {
        if (!fleetCommander) {
          res
            .status(503)
            .json({ error: 'Fleet commander service not available' });
          return;
        }

        const { commandType, sensorIds, payload } = req.body as z.infer<
          typeof SendCommandBodySchema
        >;
        const auth = req.auth!;

        const commands = await Promise.all(
          sensorIds.map((sensorId) =>
            fleetCommander!.sendCommand(auth.tenantId, sensorId, {
              type: commandType,
              payload,
            })
          )
        );

        res.status(202).json({
          message: 'Commands queued for delivery',
          commands,
        });
      } catch (error) {
        if (error instanceof CommandFeatureDisabledError) {
          res.status(409).json({
            error: 'Command type disabled',
            message: error.message,
          });
          return;
        }
        logger.error({ error }, 'Failed to send commands');
        res.status(500).json({
          error: 'Failed to send commands',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/commands/:commandId
   * Get status of a specific command
   */
  router.get(
    '/commands/:commandId',
    requireScope('fleet:read'),
    validateParams(CommandIdParamSchema),
    async (req, res) => {
      try {
        const { commandId } = req.params;
        const auth = req.auth!;

        const command = await prisma.fleetCommand.findUnique({
          where: { id: commandId },
          include: { sensor: true },
        });

        if (!command || command.sensor.tenantId !== auth.tenantId) {
          res.status(404).json({ error: 'Command not found' });
          return;
        }

        res.json(command);
      } catch (error) {
        logger.error({ error }, 'Failed to get command status');
        res.status(500).json({
          error: 'Failed to get command status',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * POST /api/v1/fleet/commands/:commandId/cancel
   * Cancel a pending command
   */
  router.post(
    '/commands/:commandId/cancel',
    rateLimiters.fleetCommand,
    requireScope('fleet:write'),
    requireRole('operator'),
    validateParams(CommandIdParamSchema),
    async (req, res) => {
      try {
        if (!fleetCommander) {
          res
            .status(503)
            .json({ error: 'Fleet commander service not available' });
          return;
        }

        const { commandId } = req.params;
        const auth = req.auth!;

        const command = await prisma.fleetCommand.findUnique({
          where: { id: commandId },
          include: { sensor: true },
        });

        if (!command || command.sensor.tenantId !== auth.tenantId) {
          res.status(404).json({ error: 'Command not found' });
          return;
        }

        if (command.status !== 'pending') {
          res.status(400).json({
            error: 'Can only cancel pending commands',
          });
          return;
        }

        await fleetCommander.cancelCommand(commandId);
        res.json({ message: 'Command cancelled' });
      } catch (error) {
        logger.error({ error }, 'Failed to cancel command');
        res.status(500).json({
          error: 'Failed to cancel command',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // ======================== Rule Distribution ========================

  /**
   * GET /api/v1/fleet/rules/status
   * Get rule sync status for all sensors
   */
  router.get('/rules/status', requireScope('fleet:read'), async (req, res) => {
    try {
      if (!ruleDistributor) {
        res
          .status(503)
          .json({ error: 'Rule distributor service not available' });
        return;
      }

      const auth = req.auth!;

      const sensors = await prisma.sensor.findMany({
        where: { tenantId: auth.tenantId },
        include: {
          ruleSyncState: true,
        },
      });

      const status = sensors.map((sensor) => {
        const ruleSyncStates = sensor.ruleSyncState ?? [];
        return {
          sensorId: sensor.id,
          sensorName: sensor.name,
          syncedRules: ruleSyncStates.length,
          syncStatus: ruleSyncStates.map((r) => ({
            ruleId: r.ruleId,
            status: r.status,
          })),
        };
      });

      res.json({ status });
    } catch (error) {
      logger.error({ error }, 'Failed to get rule sync status');
      res.status(500).json({
        error: 'Failed to get rule sync status',
        message: getErrorMessage(error),
      });
    }
  });

  /**
   * POST /api/v1/fleet/rules/push
   * Push rules to sensors with optional rollout strategy.
   *
   * Supports five deployment strategies:
   * - immediate: Push to all sensors at once (default)
   * - canary: Gradual rollout with configurable percentage stages
   * - scheduled: Deploy at a specific future time
   * - rolling: Deploy in batches with health checks between each batch
   * - blue_green: Stage rules to all sensors, then perform atomic switch
   */
  router.post(
    '/rules/push',
    rateLimiters.fleetCommand,
    requireScope('fleet:write'),
    requireRole('operator'),
    validateBody(PushRulesBodySchema),
    async (req, res) => {
      try {
        if (!ruleDistributor) {
          res
            .status(503)
            .json({ error: 'Rule distributor service not available' });
          return;
        }

        const {
          ruleIds,
          sensorIds,
          strategy,
          // Canary options
          canaryPercentage,
          // Scheduled options
          scheduledTime,
          // Rolling strategy options
          rollingBatchSize,
          healthCheckTimeout,
          maxFailuresBeforeAbort,
          rollbackOnFailure,
          healthCheckIntervalMs,
          // Blue/Green strategy options
          stagingTimeout,
          switchTimeout,
          requireAllSensorsStaged,
          minStagedPercentage,
          cleanupDelayMs,
        } = req.body as z.infer<typeof PushRulesBodySchema>;
        const auth = req.auth!;

        // Validate sensors belong to tenant
        const sensors = await prisma.sensor.findMany({
          where: {
            id: { in: sensorIds },
            tenantId: auth.tenantId,
          },
        });

        if (sensors.length !== sensorIds.length) {
          res.status(400).json({
            error: 'Some sensors not found or do not belong to your tenant',
          });
          return;
        }

        // Build strategy-specific options
        const strategyOptions: Parameters<typeof ruleDistributor.distributeRules>[3] = {
          strategy: strategy as 'immediate' | 'canary' | 'scheduled' | 'rolling' | 'blue_green',
          // Canary options
          canaryPercentage,
          // Scheduled options (convert ISO string to Date if provided)
          scheduledTime: scheduledTime ? new Date(scheduledTime) : undefined,
          // Rolling strategy options
          rollingBatchSize,
          healthCheckTimeout,
          maxFailuresBeforeAbort,
          rollbackOnFailure,
          healthCheckIntervalMs,
          // Blue/Green strategy options
          stagingTimeout,
          switchTimeout,
          requireAllSensorsStaged,
          minStagedPercentage,
          cleanupDelayMs,
        };

        // Distribute rules based on strategy (tenant validated by service)
        const deployment = await ruleDistributor.distributeRules(
          auth.tenantId,
          ruleIds,
          sensorIds,
          strategyOptions
        );

        res.status(202).json({
          message: 'Rule distribution initiated',
          deployment,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to push rules');
        res.status(500).json({
          error: 'Failed to push rules',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * POST /api/v1/fleet/rules/retry/:sensorId
   * Retry failed rule deployments for a specific sensor
   */
  router.post(
    '/rules/retry/:sensorId',
    rateLimiters.fleetCommand,
    requireScope('fleet:write'),
    validateParams(SensorIdParamSchema),
    async (req, res) => {
      try {
        if (!ruleDistributor) {
          res
            .status(503)
            .json({ error: 'Rule distributor service not available' });
          return;
        }

        const { sensorId } = req.params;
        const auth = req.auth!;

        const sensor = await prisma.sensor.findUnique({
          where: { id: sensorId },
        });

        if (!sensor || sensor.tenantId !== auth.tenantId) {
          res.status(404).json({ error: 'Sensor not found' });
          return;
        }

        // Get failed rule sync states and retry
        const failedRules = await prisma.ruleSyncState.findMany({
          where: {
            sensorId,
            status: 'failed',
          },
        });

        if (failedRules.length === 0) {
          res.status(200).json({
            message: 'No failed rules to retry',
          });
          return;
        }

        // Retry distribution (tenant validated by service)
        const result = await ruleDistributor.retryFailedRules(auth.tenantId, sensorId);

        res.json({
          message: 'Rule retry initiated',
          retriedRules: result,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to retry rules');
        res.status(500).json({
          error: 'Failed to retry rules',
          message: getErrorMessage(error),
        });
      }
    }
  );

  return router;
}
