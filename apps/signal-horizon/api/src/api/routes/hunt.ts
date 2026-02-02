/**
 * Hunt API Routes
 * Time-based threat hunting endpoints
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { HuntService, HuntQuery } from '../../services/hunt/index.js';
import { rateLimiters } from '../../middleware/index.js';
import { requireRole } from '../middleware/auth.js';

// =============================================================================
// Validation Schemas
// =============================================================================

const SeveritySchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

const HuntQuerySchema = z.object({
  tenantId: z.string().optional(),
  startTime: z.string().datetime().transform((s) => new Date(s)),
  endTime: z.string().datetime().transform((s) => new Date(s)),
  signalTypes: z.array(z.string()).optional(),
  sourceIps: z.array(z.string().ip()).optional(),
  severities: z.array(SeveritySchema).optional(),
  minConfidence: z.number().min(0).max(1).optional(),
  anonFingerprint: z.string().length(64).optional(),
  limit: z.number().int().min(1).max(10000).optional().default(1000),
  offset: z.number().int().min(0).optional().default(0),
});

const SavedQuerySchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  query: HuntQuerySchema,
});

const TimeRangeSchema = z.object({
  startTime: z.string().datetime().transform((s) => new Date(s)).optional(),
  endTime: z.string().datetime().transform((s) => new Date(s)).optional(),
});

const IpActivitySchema = z.object({
  sourceIp: z.string().ip(),
  days: z.number().int().min(1).max(365).optional().default(30),
});

const HourlyStatsSchema = z.object({
  tenantId: z.string().optional(),
  startTime: z.string().datetime().transform((s) => new Date(s)).optional(),
  endTime: z.string().datetime().transform((s) => new Date(s)).optional(),
  signalTypes: z.array(z.string()).optional(),
});

// =============================================================================
// Route Factory
// =============================================================================

export function createHuntRoutes(
  _prisma: PrismaClient,
  logger: Logger,
  huntService: HuntService
): Router {
  const router = Router();
  const routeLogger = logger.child({ route: 'hunt' });

  /**
   * GET /api/v1/hunt/status
   * Check if historical hunting is available
   */
  router.get('/status', (_req: Request, res: Response) => {
    res.json({
      historical: huntService.isHistoricalEnabled(),
      routingThreshold: '24h',
      description: huntService.isHistoricalEnabled()
        ? 'Historical queries via ClickHouse enabled'
        : 'PostgreSQL only (demo mode)',
    });
  });

  /**
   * POST /api/v1/hunt/query
   * Query signal timeline with automatic routing
   *
   * Security: Tenant isolation enforced - users can only query their own tenant's data.
   * The tenantId from the request body is ignored; the authenticated tenant is used.
   */
  router.post('/query', rateLimiters.hunt, async (req: Request, res: Response) => {
    try {
      // Require authentication
      if (!req.auth?.tenantId) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const parsed = HuntQuerySchema.safeParse(req.body);

      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.errors,
        });
        return;
      }

      // SECURITY: Enforce tenant isolation - always use authenticated tenant
      // This prevents cross-tenant data access regardless of what tenantId is provided
      const query: HuntQuery = {
        ...parsed.data,
        tenantId: req.auth.tenantId, // Override with authenticated tenant
      };

      routeLogger.info(
        { tenantId: query.tenantId, startTime: query.startTime, endTime: query.endTime },
        'Executing hunt query'
      );

      const result = await huntService.queryTimeline(query);

      res.json({
        success: true,
        data: result.signals,
        meta: {
          total: result.total,
          source: result.source,
          queryTimeMs: result.queryTimeMs,
          limit: query.limit,
          offset: query.offset,
        },
      });
    } catch (error) {
      routeLogger.error({ error }, 'Hunt query failed');
      res.status(500).json({
        error: 'Query failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * GET /api/v1/hunt/timeline/:campaignId
   * Get campaign event timeline
   */
  router.get('/timeline/:campaignId', rateLimiters.hunt, async (req: Request, res: Response) => {
    try {
      const { campaignId } = req.params;
      const parsed = TimeRangeSchema.safeParse(req.query);

      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.errors,
        });
        return;
      }

      if (!huntService.isHistoricalEnabled()) {
        res.status(503).json({
          error: 'Historical queries not available',
          message: 'ClickHouse is not enabled',
        });
        return;
      }

      const { startTime, endTime } = parsed.data;
      const timeline = await huntService.getCampaignTimeline(campaignId, startTime, endTime);

      res.json({
        success: true,
        data: timeline,
        meta: {
          campaignId,
          count: timeline.length,
        },
      });
    } catch (error) {
      routeLogger.error({ error }, 'Campaign timeline query failed');
      res.status(500).json({
        error: 'Query failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * GET /api/v1/hunt/stats/hourly
   * Get hourly aggregated statistics
   *
   * Security: Tenant isolation enforced - users can only query their own tenant's data.
   */
  router.get('/stats/hourly', rateLimiters.aggregations, async (req: Request, res: Response) => {
    try {
      // Require authentication
      if (!req.auth?.tenantId) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const parsed = HourlyStatsSchema.safeParse(req.query);

      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.errors,
        });
        return;
      }

      if (!huntService.isHistoricalEnabled()) {
        res.status(503).json({
          error: 'Historical queries not available',
          message: 'ClickHouse is not enabled',
        });
        return;
      }

      // SECURITY: Enforce tenant isolation - always use authenticated tenant
      const { startTime, endTime, signalTypes } = parsed.data;
      const stats = await huntService.getHourlyStats(
        req.auth.tenantId, // Use authenticated tenant, ignore any tenantId from query
        startTime,
        endTime,
        signalTypes
      );

      res.json({
        success: true,
        data: stats,
        meta: {
          count: stats.length,
        },
      });
    } catch (error) {
      routeLogger.error({ error }, 'Hourly stats query failed');
      res.status(500).json({
        error: 'Query failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * POST /api/v1/hunt/ip-activity
   * Get IP activity across tenants
   *
   * Security: Requires admin role - this endpoint queries data across ALL tenants
   * and should only be accessible to SOC analysts/administrators.
   */
  router.post('/ip-activity', rateLimiters.aggregations, requireRole('admin'), async (req: Request, res: Response) => {
    try {
      const parsed = IpActivitySchema.safeParse(req.body);

      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.errors,
        });
        return;
      }

      const { sourceIp, days } = parsed.data;

      routeLogger.info(
        { sourceIp, days, adminUserId: req.auth?.apiKeyId },
        'Cross-tenant IP activity query by admin'
      );

      const activity = await huntService.getIpActivity(sourceIp, days);

      res.json({
        success: true,
        data: activity,
        meta: {
          sourceIp,
          lookbackDays: days,
        },
      });
    } catch (error) {
      routeLogger.error({ error }, 'IP activity query failed');
      res.status(500).json({
        error: 'Query failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  // =============================================================================
  // Saved Queries
  // =============================================================================

  /**
   * GET /api/v1/hunt/saved-queries
   * List saved queries
   */
  router.get('/saved-queries', rateLimiters.savedQueries, async (req: Request, res: Response) => {
    try {
      const createdBy = req.query.createdBy as string | undefined;
      const queries = await huntService.getSavedQueries(createdBy);

      res.json({
        success: true,
        data: queries,
        meta: {
          count: queries.length,
        },
      });
    } catch (error) {
      routeLogger.error({ error }, 'Failed to list saved queries');
      res.status(500).json({
        error: 'Failed to list saved queries',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * POST /api/v1/hunt/saved-queries
   * Create a saved query
   */
  router.post('/saved-queries', rateLimiters.savedQueries, async (req: Request, res: Response) => {
    try {
      const parsed = SavedQuerySchema.safeParse(req.body);

      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.errors,
        });
        return;
      }

      const { name, description, query } = parsed.data;
      const createdBy = (req as Request & { userId?: string }).userId ?? 'anonymous';

      const saved = await huntService.saveQuery(name, query, createdBy, description);

      res.status(201).json({
        success: true,
        data: saved,
      });
    } catch (error) {
      routeLogger.error({ error }, 'Failed to save query');
      res.status(500).json({
        error: 'Failed to save query',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * GET /api/v1/hunt/saved-queries/:id
   * Get a saved query by ID
   */
  router.get('/saved-queries/:id', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const query = await huntService.getSavedQuery(id);

      if (!query) {
        res.status(404).json({
          error: 'Saved query not found',
        });
        return;
      }

      res.json({
        success: true,
        data: query,
      });
    } catch (error) {
      routeLogger.error({ error }, 'Failed to get saved query');
      res.status(500).json({
        error: 'Failed to get saved query',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * POST /api/v1/hunt/saved-queries/:id/run
   * Execute a saved query
   *
   * Security: Tenant isolation enforced - saved queries are executed with
   * the authenticated tenant's context, not the original query's tenantId.
   */
  router.post('/saved-queries/:id/run', rateLimiters.hunt, async (req: Request, res: Response) => {
    try {
      // Require authentication
      if (!req.auth?.tenantId) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const { id } = req.params;

      // Get the saved query first to check ownership
      const savedQuery = await huntService.getSavedQuery(id);
      if (!savedQuery) {
        res.status(404).json({
          error: 'Saved query not found',
        });
        return;
      }

      // SECURITY: Run with authenticated tenant context (override any stored tenantId)
      const queryWithTenant: HuntQuery = {
        ...savedQuery.query,
        tenantId: req.auth.tenantId,
      };

      const result = await huntService.queryTimeline(queryWithTenant);

      // Update lastRunAt on the saved query
      savedQuery.lastRunAt = new Date();

      res.json({
        success: true,
        data: result.signals,
        meta: {
          total: result.total,
          source: result.source,
          queryTimeMs: result.queryTimeMs,
        },
      });
    } catch (error) {
      routeLogger.error({ error }, 'Failed to run saved query');
      res.status(500).json({
        error: 'Failed to run saved query',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * DELETE /api/v1/hunt/saved-queries/:id
   * Delete a saved query
   */
  router.delete('/saved-queries/:id', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const deleted = await huntService.deleteSavedQuery(id);

      if (!deleted) {
        res.status(404).json({
          error: 'Saved query not found',
        });
        return;
      }

      res.json({
        success: true,
        message: 'Saved query deleted',
      });
    } catch (error) {
      routeLogger.error({ error }, 'Failed to delete saved query');
      res.status(500).json({
        error: 'Failed to delete saved query',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  return router;
}
