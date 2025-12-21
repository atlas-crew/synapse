/**
 * Intel API Routes
 * IOC export and attack trend endpoints
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { requireScope } from '../middleware/auth.js';
import { validateQuery } from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';
import { IntelService, type IntelConfig } from '../../services/intel/index.js';

// Validation schemas
const ExportIOCsQuerySchema = z.object({
  format: z.enum(['json', 'csv', 'stix']).default('json'),
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
  threatTypes: z.string().transform((s) => s.split(',')).optional(),
  minRiskScore: z.coerce.number().min(0).max(100).optional(),
  fleetOnly: z.coerce.boolean().optional(),
  limit: z.coerce.number().int().min(1).max(10000).default(1000),
});

const TrendsQuerySchema = z.object({
  windowHours: z.coerce.number().int().min(1).max(720).default(24), // Max 30 days
});

const ExportBlocklistQuerySchema = z.object({
  format: z.enum(['json', 'csv', 'plain']).default('json'),
  fleetOnly: z.coerce.boolean().optional(),
});

// Default config
const DEFAULT_CONFIG: IntelConfig = {
  maxExportLimit: 10000,
  defaultTrendWindowHours: 24,
  minRiskScoreForExport: 0,
};

export function createIntelRoutes(prisma: PrismaClient, logger: import('pino').Logger): Router {
  const router = Router();
  const intelService = new IntelService(prisma, logger, DEFAULT_CONFIG);

  /**
   * GET /api/v1/intel/iocs
   * Export IOCs in various formats
   */
  router.get(
    '/iocs',
    requireScope('dashboard:read'),
    validateQuery(ExportIOCsQuerySchema),
    async (req, res) => {
      try {
        const query = req.query as unknown as z.infer<typeof ExportIOCsQuerySchema>;

        const result = await intelService.exportIOCs({
          format: query.format,
          from: query.from,
          to: query.to,
          threatTypes: query.threatTypes as import('../../types/protocol.js').ThreatType[] | undefined,
          minRiskScore: query.minRiskScore,
          fleetOnly: query.fleetOnly,
          limit: query.limit,
        });

        // Set appropriate content type
        switch (query.format) {
          case 'json':
          case 'stix':
            res.setHeader('Content-Type', 'application/json');
            break;
          case 'csv':
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="iocs-${Date.now()}.csv"`);
            break;
        }

        res.send(result);
      } catch (error) {
        console.error('Failed to export IOCs:', error);
        res.status(500).json({ error: 'Failed to export IOCs', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/intel/trends
   * Get attack volume trends
   */
  router.get(
    '/trends',
    requireScope('dashboard:read'),
    validateQuery(TrendsQuerySchema),
    async (req, res) => {
      try {
        const { windowHours } = req.query as unknown as z.infer<typeof TrendsQuerySchema>;
        const auth = req.auth!;

        // Tenant-specific trends unless fleet admin
        const tenantId = auth.isFleetAdmin ? null : auth.tenantId;

        const trends = await intelService.getAttackTrends(tenantId, windowHours);
        res.json(trends);
      } catch (error) {
        console.error('Failed to get attack trends:', error);
        res.status(500).json({ error: 'Failed to get attack trends', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/intel/fleet-summary
   * Get fleet-wide intelligence summary (fleet admin only)
   */
  router.get(
    '/fleet-summary',
    requireScope('fleet:admin'),
    async (_req, res) => {
      try {
        const summary = await intelService.getFleetSummary();
        res.json(summary);
      } catch (error) {
        console.error('Failed to get fleet summary:', error);
        res.status(500).json({ error: 'Failed to get fleet summary', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/intel/blocklist
   * Export blocklist entries
   */
  router.get(
    '/blocklist',
    requireScope('dashboard:read'),
    validateQuery(ExportBlocklistQuerySchema),
    async (req, res) => {
      try {
        const { format, fleetOnly } = req.query as unknown as z.infer<typeof ExportBlocklistQuerySchema>;
        const auth = req.auth!;

        // Tenant-specific blocklist unless fleet admin or fleetOnly requested
        const tenantId = auth.isFleetAdmin && fleetOnly ? null : auth.tenantId;

        const result = await intelService.exportBlocklist(tenantId, format);

        // Set appropriate content type
        switch (format) {
          case 'json':
            res.setHeader('Content-Type', 'application/json');
            break;
          case 'csv':
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="blocklist-${Date.now()}.csv"`);
            break;
          case 'plain':
            res.setHeader('Content-Type', 'text/plain');
            break;
        }

        res.send(result);
      } catch (error) {
        console.error('Failed to export blocklist:', error);
        res.status(500).json({ error: 'Failed to export blocklist', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/intel/top-threats
   * Get top threats by various dimensions
   */
  router.get(
    '/top-threats',
    requireScope('dashboard:read'),
    validateQuery(TrendsQuerySchema),
    async (req, res) => {
      try {
        const { windowHours } = req.query as unknown as z.infer<typeof TrendsQuerySchema>;
        const auth = req.auth!;

        const tenantId = auth.isFleetAdmin ? null : auth.tenantId;
        const trends = await intelService.getAttackTrends(tenantId, windowHours);

        res.json({
          timeRange: trends.timeRange,
          topIPs: trends.topIPs,
          topFingerprints: trends.topFingerprints,
          topCampaigns: trends.topCampaigns,
        });
      } catch (error) {
        console.error('Failed to get top threats:', error);
        res.status(500).json({ error: 'Failed to get top threats', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/intel/signals-by-type
   * Get signal breakdown by type
   */
  router.get(
    '/signals-by-type',
    requireScope('dashboard:read'),
    validateQuery(TrendsQuerySchema),
    async (req, res) => {
      try {
        const { windowHours } = req.query as unknown as z.infer<typeof TrendsQuerySchema>;
        const auth = req.auth!;

        const tenantId = auth.isFleetAdmin ? null : auth.tenantId;
        const trends = await intelService.getAttackTrends(tenantId, windowHours);

        res.json({
          timeRange: trends.timeRange,
          signalsByType: trends.signalsByType,
          signalsBySeverity: trends.signalsBySeverity,
          total: trends.totalSignals,
        });
      } catch (error) {
        console.error('Failed to get signals by type:', error);
        res.status(500).json({ error: 'Failed to get signals by type', message: getErrorMessage(error) });
      }
    }
  );

  /**
   * GET /api/v1/intel/volume-chart
   * Get time-series data for volume charts
   */
  router.get(
    '/volume-chart',
    requireScope('dashboard:read'),
    validateQuery(TrendsQuerySchema),
    async (req, res) => {
      try {
        const { windowHours } = req.query as unknown as z.infer<typeof TrendsQuerySchema>;
        const auth = req.auth!;

        const tenantId = auth.isFleetAdmin ? null : auth.tenantId;
        const trends = await intelService.getAttackTrends(tenantId, windowHours);

        res.json({
          timeRange: trends.timeRange,
          dataPoints: trends.volumeOverTime,
        });
      } catch (error) {
        console.error('Failed to get volume chart:', error);
        res.status(500).json({ error: 'Failed to get volume chart', message: getErrorMessage(error) });
      }
    }
  );

  return router;
}
