/**
 * Fleet Bandwidth API Routes
 * Endpoints for bandwidth metrics aggregation and billing calculations
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { z } from 'zod';
import { requireScope } from '../middleware/auth.js';
import { validateParams, validateQuery } from '../middleware/validation.js';
import { BandwidthAggregatorService } from '../../services/fleet/bandwidth-aggregator.js';
import type { TunnelBroker } from '../../websocket/tunnel-broker.js';

/**
 * Sanitize error messages for client responses
 * Prevents leaking internal implementation details
 */
function sanitizeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    // Only expose safe, generic error messages
    const safeMessages = [
      'Sensor not found',
      'Not authorized',
      'Invalid request',
      'Service unavailable',
    ];
    if (safeMessages.some((msg) => error.message.includes(msg))) {
      return error.message;
    }
  }
  return 'An unexpected error occurred';
}

// ======================== Validation Schemas ========================

const SensorIdParamSchema = z.object({
  sensorId: z.string().min(1),
});

const TimelineQuerySchema = z.object({
  granularity: z.enum(['1m', '5m', '1h']).default('5m'),
  duration: z.coerce.number().int().min(5).max(1440).default(60), // 5 min to 24 hours
});

const BillingQuerySchema = z.object({
  start: z.string().datetime(),
  end: z.string().datetime(),
  costPerGb: z.coerce.number().min(0).max(1).optional(),
});

// ======================== Route Handler ========================

export interface FleetBandwidthRoutesOptions {
  tunnelBroker?: TunnelBroker;
  bandwidthService?: BandwidthAggregatorService;
}

export function createFleetBandwidthRoutes(
  prisma: PrismaClient,
  logger: Logger,
  options: FleetBandwidthRoutesOptions = {}
): Router {
  const router = Router();
  // Use shared service if provided, otherwise create local instance
  const bandwidthService = options.bandwidthService ?? new BandwidthAggregatorService(
    prisma,
    logger,
    { demoMode: true },
    options.tunnelBroker
  );

  // ======================== Fleet Bandwidth ========================

  /**
   * GET /api/v1/fleet/bandwidth
   * Get fleet-wide bandwidth statistics
   *
   * Returns aggregated bandwidth metrics across all sensors in the fleet.
   */
  router.get('/', requireScope('fleet:read'), async (req, res) => {
    try {
      const auth = req.auth!;
      const stats = await bandwidthService.getFleetBandwidth(auth.tenantId);

      res.json({
        success: true,
        data: stats,
      });
    } catch (error) {
      logger.error({ error }, 'Failed to get fleet bandwidth stats');
      res.status(500).json({
        success: false,
        error: 'Failed to get fleet bandwidth statistics',
        message: sanitizeErrorMessage(error),
      });
    }
  });

  /**
   * GET /api/v1/fleet/bandwidth/timeline
   * Get bandwidth timeline for visualization
   *
   * Returns time-series bandwidth data at specified granularity.
   */
  router.get(
    '/timeline',
    requireScope('fleet:read'),
    validateQuery(TimelineQuerySchema),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const { granularity, duration } = req.query as unknown as z.infer<typeof TimelineQuerySchema>;

        const timeline = await bandwidthService.getBandwidthTimeline({
          tenantId: auth.tenantId,
          granularity: granularity as '1m' | '5m' | '1h',
          durationMinutes: duration,
        });

        res.json({
          success: true,
          data: timeline,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to get bandwidth timeline');
        res.status(500).json({
          success: false,
          error: 'Failed to get bandwidth timeline',
          message: sanitizeErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/bandwidth/endpoints
   * Get per-endpoint bandwidth breakdown
   *
   * Returns bandwidth statistics aggregated by endpoint across the fleet.
   */
  router.get('/endpoints', requireScope('fleet:read'), async (req, res) => {
    try {
      const auth = req.auth!;
      const endpoints = await bandwidthService.getEndpointBandwidth(auth.tenantId);

      res.json({
        success: true,
        data: endpoints,
        count: endpoints.length,
      });
    } catch (error) {
      logger.error({ error }, 'Failed to get endpoint bandwidth stats');
      res.status(500).json({
        success: false,
        error: 'Failed to get endpoint bandwidth statistics',
        message: sanitizeErrorMessage(error),
      });
    }
  });

  /**
   * GET /api/v1/fleet/bandwidth/billing
   * Get billing metrics for a period
   *
   * Calculates billing metrics including estimated costs for the specified period.
   */
  router.get(
    '/billing',
    requireScope('fleet:read'),
    validateQuery(BillingQuerySchema),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const { start, end, costPerGb } = req.query as unknown as z.infer<typeof BillingQuerySchema>;

        const billing = await bandwidthService.getBillingMetrics({
          tenantId: auth.tenantId,
          start: new Date(start),
          end: new Date(end),
          costPerGb,
        });

        res.json({
          success: true,
          data: billing,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to get billing metrics');
        res.status(500).json({
          success: false,
          error: 'Failed to get billing metrics',
          message: sanitizeErrorMessage(error),
        });
      }
    }
  );

  /**
   * GET /api/v1/fleet/sensors/:sensorId/bandwidth
   * Get bandwidth statistics for a specific sensor
   *
   * Returns detailed bandwidth metrics for a single sensor.
   */
  router.get(
    '/sensors/:sensorId',
    requireScope('fleet:read'),
    validateParams(SensorIdParamSchema),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const { sensorId } = req.params;

        const stats = await bandwidthService.getSensorBandwidth(auth.tenantId, sensorId);

        res.json({
          success: true,
          data: stats,
        });
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : '';
        if (errorMsg.includes('not found')) {
          res.status(404).json({
            success: false,
            error: 'Sensor not found',
          });
          return;
        }

        logger.error({ error }, 'Failed to get sensor bandwidth stats');
        res.status(500).json({
          success: false,
          error: 'Failed to get sensor bandwidth statistics',
          message: sanitizeErrorMessage(error),
        });
      }
    }
  );

  return router;
}
