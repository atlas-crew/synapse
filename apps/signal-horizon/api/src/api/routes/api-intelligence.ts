/**
 * API Intelligence Routes
 * REST endpoints for TEMPLATE_DISCOVERY and SCHEMA_VIOLATION signal aggregation
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { APIIntelligenceService } from '../../services/api-intelligence/index.js';
import { z } from 'zod';
import {
  APIIntelligenceSignalSchema,
  SignalBatchSchema,
  ListEndpointsQuerySchema,
  ListSignalsQuerySchema,
  ViolationTrendsQuerySchema,
} from '../../schemas/api-intelligence.js';
import { requireScope } from '../middleware/auth.js';
import { validateQuery, validateBody } from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';

export function createAPIIntelligenceRoutes(
  prisma: PrismaClient,
  logger: Logger
): Router {
  const router = Router();
  const service = new APIIntelligenceService(prisma, logger);

  // ===========================================================================
  // Signal Ingestion Endpoints
  // ===========================================================================

  /**
   * POST /api/v1/api-intelligence/signals
   * Ingest a single API intelligence signal
   */
  router.post(
    '/signals',
    requireScope('signal:write'),
    validateBody(APIIntelligenceSignalSchema),
    async (req, res) => {
      try {
        const signal = req.body;
        const tenantId = req.auth?.tenantId ?? 'default';

        await service.ingestSignal(signal, tenantId);

        res.status(202).json({
          accepted: true,
          message: 'Signal accepted for processing',
        });
      } catch (error) {
        logger.error({ error }, 'Failed to ingest signal');
        res.status(500).json({
          error: 'Failed to ingest signal',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * POST /api/v1/api-intelligence/signals/batch
   * Ingest a batch of API intelligence signals
   */
  router.post(
    '/signals/batch',
    requireScope('signal:write'),
    validateBody(SignalBatchSchema),
    async (req, res) => {
      try {
        const batch = req.body;
        const tenantId = req.auth?.tenantId ?? 'default';

        const result = await service.ingestBatch(batch, tenantId);

        res.status(202).json(result);
      } catch (error) {
        logger.error({ error }, 'Failed to ingest batch');
        res.status(500).json({
          error: 'Failed to ingest batch',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // ===========================================================================
  // Statistics & Analytics Endpoints
  // ===========================================================================

  /**
   * GET /api/v1/api-intelligence/stats
   * Get discovery and violation statistics for the tenant
   */
  router.get(
    '/stats',
    requireScope('dashboard:read'),
    async (req, res) => {
      try {
        const tenantId = req.auth?.tenantId ?? 'default';
        const stats = await service.getDiscoveryStats(tenantId);
        res.json(stats);
      } catch (error) {
        logger.error({ error }, 'Failed to get discovery stats');
        res.status(500).json({
          error: 'Failed to get discovery statistics',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/api-intelligence/violations/trends
   * Get violation trends over time
   */
  router.get(
    '/violations/trends',
    requireScope('dashboard:read'),
    validateQuery(ViolationTrendsQuerySchema),
    async (req, res) => {
      try {
        const tenantId = req.auth?.tenantId ?? 'default';
        const { days } = req.query as unknown as z.infer<typeof ViolationTrendsQuerySchema>;

        const trends = await service.getViolationTrends(tenantId, days);
        res.json(trends);
      } catch (error) {
        logger.error({ error }, 'Failed to get violation trends');
        res.status(500).json({
          error: 'Failed to get violation trends',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // ===========================================================================
  // Endpoint Listing & Details
  // ===========================================================================

  /**
   * GET /api/v1/api-intelligence/endpoints
   * List discovered API endpoints with pagination and filtering
   */
  router.get(
    '/endpoints',
    requireScope('dashboard:read'),
    validateQuery(ListEndpointsQuerySchema),
    async (req, res) => {
      try {
        const tenantId = req.auth?.tenantId ?? 'default';
        const { limit, offset, method } = req.query as unknown as z.infer<typeof ListEndpointsQuerySchema>;

        const result = await service.listEndpoints(tenantId, { limit, offset, method });

        res.json({
          endpoints: result.endpoints,
          pagination: {
            total: result.total,
            limit,
            offset,
          },
        });
      } catch (error) {
        logger.error({ error }, 'Failed to list endpoints');
        res.status(500).json({
          error: 'Failed to list endpoints',
          message: getErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/api-intelligence/endpoints/:id
   * Get a specific endpoint by ID
   */
  router.get(
    '/endpoints/:id',
    requireScope('dashboard:read'),
    async (req, res) => {
      try {
        const { id } = req.params;
        const tenantId = req.auth?.tenantId ?? 'default';

        const endpoint = await service.getEndpoint(id, tenantId);

        if (!endpoint) {
          res.status(404).json({ error: 'Endpoint not found' });
          return;
        }

        res.json(endpoint);
      } catch (error) {
        logger.error({ error }, 'Failed to get endpoint');
        res.status(500).json({
          error: 'Failed to get endpoint',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // ===========================================================================
  // Signal History Endpoints
  // ===========================================================================

  /**
   * GET /api/v1/api-intelligence/signals
   * List recent API intelligence signals with pagination and filtering
   */
  router.get(
    '/signals',
    requireScope('dashboard:read'),
    validateQuery(ListSignalsQuerySchema),
    async (req, res) => {
      try {
        const tenantId = req.auth?.tenantId ?? 'default';
        const { limit, offset, type, sensorId } = req.query as unknown as z.infer<typeof ListSignalsQuerySchema>;

        const result = await service.listSignals(tenantId, { limit, offset, type, sensorId });

        res.json({
          signals: result.signals,
          pagination: {
            total: result.total,
            limit,
            offset,
          },
        });
      } catch (error) {
        logger.error({ error }, 'Failed to list signals');
        res.status(500).json({
          error: 'Failed to list signals',
          message: getErrorMessage(error),
        });
      }
    }
  );

  return router;
}
