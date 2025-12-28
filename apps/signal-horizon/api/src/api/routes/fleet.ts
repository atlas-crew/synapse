/**
 * Fleet Management API Routes
 * Endpoints for fleet-wide operations, sensor management, configuration, and rule distribution
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { z } from 'zod';
import { requireScope } from '../middleware/auth.js';
import {
  validateParams,
  validateQuery,
  validateBody,
  IdParamSchema,
} from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';
import type { FleetAggregator } from '../../services/fleet/fleet-aggregator.js';
import type { ConfigManager } from '../../services/fleet/config-manager.js';
import type { FleetCommander } from '../../services/fleet/fleet-commander.js';
import type { RuleDistributor } from '../../services/fleet/rule-distributor.js';

// ======================== Validation Schemas ========================

const ListSensorsQuerySchema = z.object({
  status: z.enum(['CONNECTED', 'DISCONNECTED', 'RECONNECTING']).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

const CreateConfigTemplateBodySchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  environment: z.enum(['production', 'staging', 'dev']).default('production'),
  config: z.record(z.unknown()),
});

const UpdateConfigTemplateBodySchema = CreateConfigTemplateBodySchema.partial();

const PushConfigBodySchema = z.object({
  templateId: z.string(),
  sensorIds: z.string().array().min(1),
});

const SendCommandBodySchema = z.object({
  commandType: z.string().min(1),
  sensorIds: z.string().array().min(1),
  payload: z.record(z.unknown()),
});

const PushRulesBodySchema = z.object({
  ruleIds: z.string().array().min(1),
  sensorIds: z.string().array().min(1),
  strategy: z.enum(['immediate', 'canary', 'scheduled']).default('immediate'),
  canaryPercentage: z.number().min(1).max(100).optional(),
  scheduledTime: z.string().datetime().optional(),
});

const SensorIdParamSchema = z.object({
  sensorId: z.string(),
});

const CommandIdParamSchema = z.object({
  commandId: z.string(),
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
  }
): Router {
  const router = Router();
  const { fleetAggregator, configManager, fleetCommander, ruleDistributor } =
    options;

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
        const { status, limit, offset } = req.query as unknown as z.infer<
          typeof ListSensorsQuerySchema
        >;
        const auth = req.auth!;

        const where: Record<string, unknown> = {
          tenantId: auth.tenantId,
        };

        if (status) {
          where.connectionState = status;
        }

        const [sensors, total] = await Promise.all([
          prisma.sensor.findMany({
            where,
            take: limit,
            skip: offset,
            orderBy: { lastHeartbeat: 'desc' },
          }),
          prisma.sensor.count({ where }),
        ]);

        res.json({
          sensors,
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
    requireScope('config:write'),
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
    requireScope('config:write'),
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

        const template = await configManager.updateTemplate(id, updates);

        if (!template) {
          res.status(404).json({ error: 'Template not found' });
          return;
        }

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
    requireScope('config:write'),
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
        await configManager.deleteTemplate(id);
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
   * POST /api/v1/fleet/config/push
   * Push configuration to sensors
   */
  router.post(
    '/config/push',
    requireScope('config:write'),
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

        const template = await configManager.getTemplate(templateId);
        if (!template) {
          res.status(404).json({ error: 'Template not found' });
          return;
        }

        // Send push_config command to each sensor
        const commands = await Promise.all(
          sensorIds.map((sensorId) =>
            fleetCommander!.sendCommand(sensorId, {
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
    requireScope('fleet:write'),
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

        const commands = await Promise.all(
          sensorIds.map((sensorId) =>
            fleetCommander!.sendCommand(sensorId, {
              type: commandType as 'push_config' | 'push_rules' | 'update' | 'restart' | 'sync_blocklist',
              payload,
            })
          )
        );

        res.status(202).json({
          message: 'Commands queued for delivery',
          commands,
        });
      } catch (error) {
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
    requireScope('fleet:write'),
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

      const status = sensors.map((sensor) => ({
        sensorId: sensor.id,
        sensorName: sensor.name,
        syncedRules: sensor.ruleSyncState?.length ?? 0,
        syncStatus: sensor.ruleSyncState?.map((r: { status: string; ruleId: string; }) => ({
          ruleId: r.ruleId,
          status: r.status,
        })) ?? [],
      }));

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
   * Push rules to sensors with optional rollout strategy
   */
  router.post(
    '/rules/push',
    requireScope('fleet:write'),
    validateBody(PushRulesBodySchema),
    async (req, res) => {
      try {
        if (!ruleDistributor) {
          res
            .status(503)
            .json({ error: 'Rule distributor service not available' });
          return;
        }

        const { ruleIds, sensorIds, strategy, canaryPercentage } =
          req.body as z.infer<typeof PushRulesBodySchema>;
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

        // Distribute rules based on strategy
        const deployment = await ruleDistributor.distributeRules(
          ruleIds,
          sensorIds,
          {
            strategy: strategy as 'immediate' | 'canary' | 'scheduled',
            canaryPercentage,
          }
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

        // Retry distribution (implementation deferred to ruleDistributor)
        const result = await ruleDistributor.retryFailedRules(sensorId);

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
