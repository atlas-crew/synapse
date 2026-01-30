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
