/**
 * Synapse Proxy API Routes
 *
 * REST endpoints for interacting with sensor's local Synapse API
 * through the WebSocket tunnel.
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import type { Logger } from 'pino';
import { requireScope } from '../middleware/auth.js';
import {
  SynapseProxyService,
  SynapseProxyError,
  type Block,
  type Rule,
  type EvalRequest,
  type SensorConfigSection,
} from '../../services/synapse-proxy.js';

// ============================================================================
// Validation Schemas
// ============================================================================

const PaginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  offset: z.coerce.number().int().min(0).default(0),
});

const EntityFilterSchema = PaginationSchema.extend({
  type: z.enum(['IP', 'FINGERPRINT', 'SESSION', 'USER']).optional(),
});

const BlockFilterSchema = PaginationSchema.extend({
  type: z.enum(['IP', 'FINGERPRINT', 'CIDR', 'USER_AGENT']).optional(),
});

const RuleFilterSchema = PaginationSchema.extend({
  type: z.enum(['BLOCK', 'CHALLENGE', 'RATE_LIMIT', 'MONITOR']).optional(),
  enabled: z.coerce.boolean().optional(),
});

const ActorFilterSchema = PaginationSchema.extend({
  type: z.enum(['human', 'bot', 'crawler', 'suspicious', 'attacker']).optional(),
  minScore: z.coerce.number().min(0).max(100).optional(),
  minRisk: z.coerce.number().min(0).max(100).optional(),
  min_risk: z.coerce.number().min(0).max(100).optional(),
  ip: z.string().optional(),
  fingerprint: z.string().optional(),
});

const TimelineQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).optional(),
});

const SessionFilterSchema = PaginationSchema.extend({
  actorId: z.string().optional(),
  actor_id: z.string().optional(),
  suspicious: z.preprocess(
    (val) => val === 'true' || val === '1',
    z.boolean().optional()
  ),
});

const CampaignFilterSchema = PaginationSchema.extend({
  status: z.string().optional(),
});

const AddBlockSchema = z.object({
  type: z.enum(['IP', 'FINGERPRINT', 'CIDR', 'USER_AGENT']),
  value: z.string().min(1),
  source: z.enum(['MANUAL', 'AUTO', 'FLEET_INTEL', 'RULE']).default('MANUAL'),
  reason: z.string().max(500),
  expiresAt: z.string().datetime().optional(),
  ruleId: z.string().optional(),
});

const RuleConditionSchema = z.object({
  field: z.string(),
  operator: z.enum(['eq', 'ne', 'gt', 'lt', 'contains', 'matches', 'in']),
  value: z.unknown().transform((v) => v ?? null),
});

const RuleActionSchema = z.object({
  type: z.enum(['block', 'challenge', 'rate_limit', 'tag', 'log']),
  params: z.record(z.unknown()).optional(),
});

const AddRuleSchema = z.object({
  name: z.string().min(1).max(100),
  type: z.enum(['BLOCK', 'CHALLENGE', 'RATE_LIMIT', 'MONITOR']),
  enabled: z.boolean().default(true),
  priority: z.number().int().min(0).max(1000).default(100),
  conditions: z.array(RuleConditionSchema).min(1),
  actions: z.array(RuleActionSchema).min(1),
  ttl: z.number().int().positive().optional(),
});

const UpdateRuleSchema = AddRuleSchema.partial();

const EvalRequestSchema = z.object({
  method: z.string(),
  path: z.string(),
  headers: z.record(z.string()),
  body: z.string().optional(),
  clientIp: z.string(),
  fingerprint: z.string().optional(),
});

const ConfigSectionSchema = z.enum([
  'dlp',
  'block-page',
  'crawler',
  'tarpit',
  'travel',
  'entity',
]);

const ConfigQuerySchema = z.object({
  section: ConfigSectionSchema.optional(),
});

const ConfigUpdateSchema = z.object({
  section: ConfigSectionSchema,
  config: z.record(z.unknown()),
});

const GlobalConfigUpdateSchema = ConfigUpdateSchema.extend({
  sensorIds: z.array(z.string().min(1)).optional(),
});

// ============================================================================
// Route Factory
// ============================================================================

export function createSynapseRoutes(
  synapseProxy: SynapseProxyService,
  logger: Logger
): Router {
  const router = Router();

  /**
   * Helper to handle synapse proxy errors consistently
   * Uses the enhanced SynapseProxyError.toJSON() for structured responses
   */
  function handleError(res: Response, error: unknown, context: string): void {
    if (error instanceof SynapseProxyError) {
      const statusMap: Record<string, number> = {
        TUNNEL_NOT_FOUND: 503,
        FORBIDDEN: 403,
        TIMEOUT: 504,
        SEND_FAILED: 503,
        SENSOR_ERROR: 502,
        HTTP_ERROR: error.status || 502,
        SHUTDOWN: 503,
        INVALID_SENSOR_ID: 400,
        INVALID_ENDPOINT: 400,
        ENDPOINT_NOT_ALLOWED: 403,
        STALE_REQUEST: 504,
      };

      const status = statusMap[error.code] || 500;
      // Use enhanced toJSON() for structured response with suggestions
      res.status(status).json(error.toJSON());
    } else {
      logger.error({ error, context }, 'Synapse proxy error');
      res.status(500).json({
        error: 'Internal server error',
        code: 'INTERNAL_ERROR',
        retryable: false,
      });
    }
  }

  function normalizeConfidence(value?: number | null): number {
    if (!value) return 0;
    return value > 1 ? Math.min(1, value / 100) : value;
  }

  function normalizeStatus(value?: string | null): 'ACTIVE' | 'DETECTED' | 'DORMANT' | 'RESOLVED' {
    switch ((value || '').toLowerCase()) {
      case 'active':
        return 'ACTIVE';
      case 'resolved':
        return 'RESOLVED';
      case 'dormant':
        return 'DORMANT';
      case 'detected':
      default:
        return 'DETECTED';
    }
  }

  function normalizeSeverity(score?: number | null): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const risk = score ?? 0;
    if (risk >= 85) return 'CRITICAL';
    if (risk >= 70) return 'HIGH';
    if (risk >= 50) return 'MEDIUM';
    return 'LOW';
  }

  function parseTimestamp(value?: string | null): number {
    if (!value) return Date.now();
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? Date.now() : parsed;
  }

  function formatCampaignName(id: string, attackTypes?: string[] | null): string {
    const primary = attackTypes?.[0];
    if (!primary) return `Campaign ${id}`;
    const title = primary
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
    return `${title} Campaign`;
  }

  // ==========================================================================
  // Status Endpoint
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/status
   * Get sensor's current status and health metrics
   */
  router.get(
    '/:sensorId/status',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const status = await synapseProxy.getSensorStatus(sensorId, tenantId);
        res.json(status);
      } catch (error) {
        handleError(res, error, 'getSensorStatus');
      }
    }
  );

  // ==========================================================================
  // Configuration Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/config
   * Fetch sensor configuration (system config view or specific section)
   */
  router.get(
    '/:sensorId/config',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = ConfigQuerySchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const section = parsed.data.section as SensorConfigSection | undefined;
        const config = section
          ? await synapseProxy.getSensorConfigSection(sensorId, tenantId, section)
          : await synapseProxy.getSensorConfig(sensorId, tenantId);
        res.json(config);
      } catch (error) {
        handleError(res, error, 'getSensorConfig');
      }
    }
  );

  /**
   * PUT /synapse/:sensorId/config
   * Update a specific sensor configuration section
   */
  router.put(
    '/:sensorId/config',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = ConfigUpdateSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid request body',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const { section, config } = parsed.data;
        const result = await synapseProxy.updateSensorConfig(
          sensorId,
          tenantId,
          section as SensorConfigSection,
          config
        );
        res.json(result);
      } catch (error) {
        handleError(res, error, 'updateSensorConfig');
      }
    }
  );

  /**
   * PUT /synapse/config
   * Push a configuration update across all connected sensors for a tenant
   */
  router.put(
    '/config',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const tenantId = req.auth!.tenantId;

      const parsed = GlobalConfigUpdateSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid request body',
          details: parsed.error.issues,
        });
        return;
      }

      const { section, config, sensorIds } = parsed.data;
      const targets = sensorIds?.length
        ? sensorIds
        : synapseProxy.listActiveSensors(tenantId);

      if (targets.length === 0) {
        res.status(404).json({
          error: 'No connected sensors found for tenant',
          code: 'NO_CONNECTED_SENSORS',
        });
        return;
      }

      const results = await Promise.all(targets.map(async (targetSensorId) => {
        try {
          await synapseProxy.updateSensorConfig(
            targetSensorId,
            tenantId,
            section as SensorConfigSection,
            config
          );
          return { sensorId: targetSensorId, success: true };
        } catch (error) {
          if (error instanceof SynapseProxyError) {
            return {
              sensorId: targetSensorId,
              success: false,
              error: error.message,
              code: error.code,
            };
          }
          return {
            sensorId: targetSensorId,
            success: false,
            error: 'Config update failed',
            code: 'INTERNAL_ERROR',
          };
        }
      }));

      const successCount = results.filter((r) => r.success).length;
      const failed = results.filter((r) => !r.success);

      res.json({
        success: failed.length === 0,
        summary: {
          total: results.length,
          updated: successCount,
          failed: failed.length,
        },
        results,
      });
    }
  );

  // ==========================================================================
  // Entities Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/entities
   * List tracked entities
   */
  router.get(
    '/:sensorId/entities',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = EntityFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.listEntities(sensorId, tenantId, parsed.data);
        res.json(result);
      } catch (error) {
        handleError(res, error, 'listEntities');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/entities/:entityId
   * Get a specific entity
   */
  router.get(
    '/:sensorId/entities/:entityId',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, entityId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const entity = await synapseProxy.getEntity(sensorId, tenantId, entityId);
        res.json(entity);
      } catch (error) {
        handleError(res, error, 'getEntity');
      }
    }
  );

  /**
   * DELETE /synapse/:sensorId/entities/:entityId
   * Release an entity (clear tracking data)
   */
  router.delete(
    '/:sensorId/entities/:entityId',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, entityId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        await synapseProxy.releaseEntity(sensorId, tenantId, entityId);
        logger.info({ sensorId, entityId, tenantId }, 'Entity released');
        res.status(204).send();
      } catch (error) {
        handleError(res, error, 'releaseEntity');
      }
    }
  );

  // ==========================================================================
  // Blocks Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/blocks
   * List active blocks
   */
  router.get(
    '/:sensorId/blocks',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = BlockFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.listBlocks(sensorId, tenantId, parsed.data);
        res.json(result);
      } catch (error) {
        handleError(res, error, 'listBlocks');
      }
    }
  );

  /**
   * POST /synapse/:sensorId/blocks
   * Add a new block
   */
  router.post(
    '/:sensorId/blocks',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = AddBlockSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid block data',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const block = await synapseProxy.addBlock(
          sensorId,
          tenantId,
          parsed.data as Omit<Block, 'id' | 'createdAt'>
        );
        logger.info({ sensorId, blockId: block.id, tenantId }, 'Block added');
        res.status(201).json(block);
      } catch (error) {
        handleError(res, error, 'addBlock');
      }
    }
  );

  /**
   * DELETE /synapse/:sensorId/blocks/:blockId
   * Remove a block
   */
  router.delete(
    '/:sensorId/blocks/:blockId',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, blockId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        await synapseProxy.removeBlock(sensorId, tenantId, blockId);
        logger.info({ sensorId, blockId, tenantId }, 'Block removed');
        res.status(204).send();
      } catch (error) {
        handleError(res, error, 'removeBlock');
      }
    }
  );

  // ==========================================================================
  // Rules Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/rules
   * List active rules
   */
  router.get(
    '/:sensorId/rules',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = RuleFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.listRules(sensorId, tenantId, parsed.data);
        res.json(result);
      } catch (error) {
        handleError(res, error, 'listRules');
      }
    }
  );

  /**
   * POST /synapse/:sensorId/rules
   * Add a new rule
   */
  router.post(
    '/:sensorId/rules',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = AddRuleSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid rule data',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const { ttl, ...ruleData } = parsed.data;
        const rule = await synapseProxy.addRule(
          sensorId,
          tenantId,
          ruleData as Omit<Rule, 'id' | 'hitCount' | 'createdAt' | 'updatedAt'>,
          ttl
        );
        logger.info({ sensorId, ruleId: rule.id, tenantId }, 'Rule added');
        res.status(201).json(rule);
      } catch (error) {
        handleError(res, error, 'addRule');
      }
    }
  );

  /**
   * PUT /synapse/:sensorId/rules/:ruleId
   * Update an existing rule
   */
  router.put(
    '/:sensorId/rules/:ruleId',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, ruleId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = UpdateRuleSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid rule update data',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const rule = await synapseProxy.updateRule(sensorId, tenantId, ruleId, parsed.data);
        logger.info({ sensorId, ruleId, tenantId }, 'Rule updated');
        res.json(rule);
      } catch (error) {
        handleError(res, error, 'updateRule');
      }
    }
  );

  /**
   * DELETE /synapse/:sensorId/rules/:ruleId
   * Delete a rule
   */
  router.delete(
    '/:sensorId/rules/:ruleId',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, ruleId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        await synapseProxy.deleteRule(sensorId, tenantId, ruleId);
        logger.info({ sensorId, ruleId, tenantId }, 'Rule deleted');
        res.status(204).send();
      } catch (error) {
        handleError(res, error, 'deleteRule');
      }
    }
  );

  // ==========================================================================
  // Actors Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/actors
   * List tracked actors
   */
  router.get(
    '/:sensorId/actors',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = ActorFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.listActors(sensorId, tenantId, {
          ip: parsed.data.ip,
          fingerprint: parsed.data.fingerprint,
          minRisk: parsed.data.minRisk ?? parsed.data.min_risk ?? parsed.data.minScore,
          minScore: parsed.data.minScore,
          type: parsed.data.type,
          limit: parsed.data.limit,
          offset: parsed.data.offset,
        });
        res.json(result);
      } catch (error) {
        handleError(res, error, 'listActors');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/actors/:actorId
   * Get a specific actor
   */
  router.get(
    '/:sensorId/actors/:actorId',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, actorId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const actor = await synapseProxy.getActor(sensorId, tenantId, actorId);
        res.json(actor);
      } catch (error) {
        handleError(res, error, 'getActor');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/actors/:actorId/timeline
   * Get actor timeline events
   */
  router.get(
    '/:sensorId/actors/:actorId/timeline',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, actorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = TimelineQuerySchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const timeline = await synapseProxy.getActorTimeline(
          sensorId,
          tenantId,
          actorId,
          parsed.data
        );
        res.json(timeline);
      } catch (error) {
        handleError(res, error, 'getActorTimeline');
      }
    }
  );

  // ==========================================================================
  // Sessions Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/sessions
   * List tracked sessions
   */
  router.get(
    '/:sensorId/sessions',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = SessionFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const actorId = parsed.data.actorId ?? parsed.data.actor_id;
        const result = await synapseProxy.listSessions(sensorId, tenantId, {
          actorId,
          suspicious: parsed.data.suspicious,
          limit: parsed.data.limit,
          offset: parsed.data.offset,
        });
        res.json(result);
      } catch (error) {
        handleError(res, error, 'listSessions');
      }
    }
  );

  // ==========================================================================
  // Campaigns Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/campaigns
   * List campaigns
   */
  router.get(
    '/:sensorId/campaigns',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = CampaignFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.listCampaigns(sensorId, tenantId, {
          status: parsed.data.status,
          limit: parsed.data.limit,
          offset: parsed.data.offset,
        });

        const campaigns = (result.data || []).map((campaign) => ({
          campaignId: campaign.id,
          name: formatCampaignName(campaign.id, campaign.attackTypes),
          status: normalizeStatus(campaign.status),
          severity: normalizeSeverity(campaign.riskScore),
          confidence: normalizeConfidence(campaign.confidence),
          actorCount: campaign.actorCount ?? 0,
          firstSeen: parseTimestamp(campaign.firstSeen),
          lastSeen: parseTimestamp(campaign.lastActivity),
          summary: campaign.attackTypes?.length
            ? `Attack types: ${campaign.attackTypes.join(', ')}`
            : null,
          correlationTypes: campaign.attackTypes ?? [],
        }));

        const filtered = parsed.data.status
          ? campaigns.filter((c) => c.status === normalizeStatus(parsed.data.status))
          : campaigns;

        const offset = parsed.data.offset ?? 0;
        const limit = parsed.data.limit ?? filtered.length;

        res.json({ campaigns: filtered.slice(offset, offset + limit) });
      } catch (error) {
        handleError(res, error, 'listCampaigns');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/campaigns/:campaignId
   * Get campaign detail
   */
  router.get(
    '/:sensorId/campaigns/:campaignId',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, campaignId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const result = await synapseProxy.getCampaign(sensorId, tenantId, campaignId);
        const campaign = result.data;

        res.json({
          campaign: {
            campaignId: campaign.id,
            name: formatCampaignName(campaign.id, campaign.attackTypes),
            status: normalizeStatus(campaign.status),
            severity: normalizeSeverity(campaign.riskScore),
            confidence: normalizeConfidence(campaign.confidence),
            actorCount: campaign.actorCount ?? 0,
            firstSeen: parseTimestamp(campaign.firstSeen),
            lastSeen: parseTimestamp(campaign.lastActivity),
            summary: campaign.attackTypes?.length
              ? `Attack types: ${campaign.attackTypes.join(', ')}`
              : null,
            correlationTypes: campaign.attackTypes ?? [],
          },
          signals: campaign.correlationReasons?.map((reason) => ({
            type: reason.type,
            confidence: normalizeConfidence(reason.confidence),
            reason: reason.description ?? null,
          })) ?? [],
        });
      } catch (error) {
        handleError(res, error, 'getCampaign');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/campaigns/:campaignId/actors
   * Get campaign actors
   */
  router.get(
    '/:sensorId/campaigns/:campaignId/actors',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, campaignId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const result = await synapseProxy.listCampaignActors(sensorId, tenantId, campaignId);
        const actors = (result.actors || []).map((actor) => ({
          actorId: actor.ip,
          riskScore: actor.risk ?? 0,
          lastSeen: parseTimestamp(actor.lastActivity ?? null),
          ips: [actor.ip],
        }));
        res.json({ campaignId, actors });
      } catch (error) {
        handleError(res, error, 'listCampaignActors');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/campaigns/:campaignId/graph
   * Get campaign correlation graph
   */
  router.get(
    '/:sensorId/campaigns/:campaignId/graph',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, campaignId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const result = await synapseProxy.getCampaignGraph(sensorId, tenantId, campaignId);
        res.json(result);
      } catch (error) {
        handleError(res, error, 'getCampaignGraph');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/sessions/:sessionId
   * Get session detail
   */
  router.get(
    '/:sensorId/sessions/:sessionId',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, sessionId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const session = await synapseProxy.getSession(sensorId, tenantId, sessionId);
        res.json(session);
      } catch (error) {
        handleError(res, error, 'getSession');
      }
    }
  );

  // ==========================================================================
  // Evaluation Endpoint
  // ==========================================================================

  /**
   * POST /synapse/:sensorId/evaluate
   * Evaluate a request against the sensor's rules
   */
  router.post(
    '/:sensorId/evaluate',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = EvalRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid evaluation request',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.evaluateRequest(
          sensorId,
          tenantId,
          parsed.data as EvalRequest
        );
        res.json(result);
      } catch (error) {
        handleError(res, error, 'evaluateRequest');
      }
    }
  );

  // ==========================================================================
  // Cache Management Endpoint
  // ==========================================================================

  /**
   * POST /synapse/:sensorId/cache/clear
   * Clear cached data for a sensor
   */
  router.post(
    '/:sensorId/cache/clear',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      // Verify the sensor tunnel exists and belongs to tenant
      try {
        await synapseProxy.getSensorStatus(sensorId, tenantId);
        synapseProxy.clearSensorCache(sensorId);
        logger.info({ sensorId, tenantId }, 'Sensor cache cleared');
        res.json({ message: 'Cache cleared' });
      } catch (error) {
        handleError(res, error, 'clearCache');
      }
    }
  );

  // ==========================================================================
  // Proxy Stats Endpoint
  // ==========================================================================

  /**
   * GET /synapse/stats
   * Get synapse proxy statistics (admin only)
   */
  router.get(
    '/stats',
    requireScope('admin'),
    (_req: Request, res: Response): void => {
      const stats = synapseProxy.getStats();
      res.json(stats);
    }
  );

  return router;
}
