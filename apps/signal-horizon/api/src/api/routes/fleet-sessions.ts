/**
 * Fleet Sessions API Routes
 * Endpoints for global session search, revocation, and actor banning across all sensors
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { z } from 'zod';
import { requireScope } from '../middleware/auth.js';
import { validateBody, validateParams, validateQuery } from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';
import type { FleetSessionQueryService } from '../../services/fleet/session-query.js';
import {
  SessionRevokeRequestSchema,
  GlobalSessionRevokeRequestSchema,
  ActorBanRequestSchema,
} from '../../services/fleet/session-query-types.js';

// =============================================================================
// Validation Schemas
// =============================================================================

const SessionIdParamSchema = z.object({
  sessionId: z.string().min(1),
});

const ActorIdParamSchema = z.object({
  actorId: z.string().min(1),
});

const SensorSessionRevokeParamSchema = z.object({
  sensorId: z.string().min(1),
  sessionId: z.string().min(1),
});

// Query schema for GET requests (all fields are strings from query params)
const SessionSearchQueryParamsSchema = z.object({
  sessionId: z.string().optional(),
  actorId: z.string().optional(),
  clientIp: z.string().optional(),
  ja4Fingerprint: z.string().optional(),
  userAgent: z.string().optional(),
  timeRangeStart: z.string().datetime().optional(),
  timeRangeEnd: z.string().datetime().optional(),
  riskScoreMin: z.coerce.number().min(0).max(100).optional(),
  blockedOnly: z.preprocess(
    (val) => val === 'true' || val === '1',
    z.boolean().optional()
  ),
  limitPerSensor: z.coerce.number().min(1).max(500).default(50),
});

// =============================================================================
// Route Factory
// =============================================================================

export interface FleetSessionsRoutesOptions {
  sessionQueryService?: FleetSessionQueryService;
}

/**
 * Create fleet sessions routes
 */
export function createFleetSessionsRoutes(
  _prisma: PrismaClient,
  logger: Logger,
  options: FleetSessionsRoutesOptions = {}
): Router {
  const router = Router();
  const { sessionQueryService } = options;

  // =============================================================================
  // Session Search
  // =============================================================================

  /**
   * GET /api/v1/fleet/sessions/search
   * Search sessions across all online sensors in parallel
   *
   * Query Parameters:
   * - sessionId: Specific session ID to find
   * - actorId: Search by actor identifier
   * - clientIp: Search by client IP address
   * - ja4Fingerprint: Search by JA4 TLS fingerprint
   * - userAgent: Search by User-Agent substring
   * - timeRangeStart: Start of time range (ISO 8601)
   * - timeRangeEnd: End of time range (ISO 8601)
   * - riskScoreMin: Minimum risk score (0-100)
   * - blockedOnly: Only return blocked sessions
   * - limitPerSensor: Max results per sensor (default: 50, max: 500)
   */
  router.get(
    '/sessions/search',
    requireScope('fleet:read'),
    validateQuery(SessionSearchQueryParamsSchema),
    async (req, res) => {
      try {
        if (!sessionQueryService) {
          res.status(503).json({
            error: 'Session query service not available',
          });
          return;
        }

        const auth = req.auth!;
        const queryParams = req.query as unknown as z.infer<typeof SessionSearchQueryParamsSchema>;

        // Convert query params to SessionSearchQuery
        const query = {
          sessionId: queryParams.sessionId,
          actorId: queryParams.actorId,
          clientIp: queryParams.clientIp,
          ja4Fingerprint: queryParams.ja4Fingerprint,
          userAgent: queryParams.userAgent,
          timeRange: queryParams.timeRangeStart
            ? {
                start: new Date(queryParams.timeRangeStart),
                end: queryParams.timeRangeEnd ? new Date(queryParams.timeRangeEnd) : undefined,
              }
            : undefined,
          riskScoreMin: queryParams.riskScoreMin,
          blockedOnly: queryParams.blockedOnly,
          limitPerSensor: queryParams.limitPerSensor,
        };

        const result = await sessionQueryService.searchSessions(auth.tenantId, query);
        res.json(result);
      } catch (error) {
        logger.error({ error }, 'Failed to search sessions');
        res.status(500).json({
          error: 'Failed to search sessions',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // =============================================================================
  // Session Statistics
  // =============================================================================

  /**
   * GET /api/v1/fleet/sessions/stats
   * Get fleet-wide session statistics
   */
  router.get(
    '/sessions/stats',
    requireScope('fleet:read'),
    async (req, res) => {
      try {
        if (!sessionQueryService) {
          res.status(503).json({
            error: 'Session query service not available',
          });
          return;
        }

        const auth = req.auth!;
        const stats = await sessionQueryService.getFleetSessionStats(auth.tenantId);
        res.json(stats);
      } catch (error) {
        logger.error({ error }, 'Failed to get session statistics');
        res.status(500).json({
          error: 'Failed to get session statistics',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // =============================================================================
  // Session Revocation
  // =============================================================================

  /**
   * POST /api/v1/fleet/sessions/:sessionId/revoke
   * Revoke a session globally across all sensors (or specified subset)
   */
  router.post(
    '/sessions/:sessionId/revoke',
    requireScope('fleet:write'),
    validateParams(SessionIdParamSchema),
    validateBody(GlobalSessionRevokeRequestSchema),
    async (req, res) => {
      try {
        if (!sessionQueryService) {
          res.status(503).json({
            error: 'Session query service not available',
          });
          return;
        }

        const auth = req.auth!;
        const { sessionId } = req.params;
        const body = req.body as z.infer<typeof GlobalSessionRevokeRequestSchema>;

        const result = await sessionQueryService.globalRevokeSession(
          auth.tenantId,
          sessionId,
          body.reason,
          body.sensorIds
        );

        res.json({
          message: 'Session revocation initiated',
          ...result,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to revoke session globally');
        res.status(500).json({
          error: 'Failed to revoke session globally',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * POST /api/v1/fleet/sensors/:sensorId/sessions/:sessionId/revoke
   * Revoke a session on a specific sensor
   */
  router.post(
    '/sensors/:sensorId/sessions/:sessionId/revoke',
    requireScope('fleet:write'),
    validateParams(SensorSessionRevokeParamSchema),
    validateBody(SessionRevokeRequestSchema),
    async (req, res) => {
      try {
        if (!sessionQueryService) {
          res.status(503).json({
            error: 'Session query service not available',
          });
          return;
        }

        const auth = req.auth!;
        const { sensorId, sessionId } = req.params;
        const body = req.body as z.infer<typeof SessionRevokeRequestSchema>;

        const result = await sessionQueryService.revokeSession(
          auth.tenantId,
          sensorId,
          sessionId,
          body.reason
        );

        if (!result.success) {
          res.status(result.error?.includes('not found') ? 404 : 500).json({
            error: 'Failed to revoke session',
            message: result.error,
          });
          return;
        }

        res.json({
          message: 'Session revoked successfully',
          ...result,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to revoke session on sensor');
        res.status(500).json({
          error: 'Failed to revoke session on sensor',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // =============================================================================
  // Actor Banning
  // =============================================================================

  /**
   * POST /api/v1/fleet/actors/:actorId/ban
   * Ban an actor globally across all sensors (or specified subset)
   */
  router.post(
    '/actors/:actorId/ban',
    requireScope('fleet:write'),
    validateParams(ActorIdParamSchema),
    validateBody(ActorBanRequestSchema),
    async (req, res) => {
      try {
        if (!sessionQueryService) {
          res.status(503).json({
            error: 'Session query service not available',
          });
          return;
        }

        const auth = req.auth!;
        const { actorId } = req.params;
        const body = req.body as z.infer<typeof ActorBanRequestSchema>;

        const result = await sessionQueryService.globalBanActor(
          auth.tenantId,
          actorId,
          body.reason,
          body.durationSeconds,
          body.sensorIds
        );

        res.json({
          message: 'Actor ban initiated',
          ...result,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to ban actor globally');
        res.status(500).json({
          error: 'Failed to ban actor globally',
          message: getErrorMessage(error),
        });
      }
    }
  );

  return router;
}
