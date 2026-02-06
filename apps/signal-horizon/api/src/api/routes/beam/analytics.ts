import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { requireScope } from '../../middleware/auth.js';
import { asyncHandler } from '../../../lib/errors.js';
import { getSynapseDirectAdapter } from '../../../services/synapse-direct.js';
import type { ResponseTimeBucket, SensorMetrics, StatusCodeDistribution } from '../../../types/beam.js';

const EMPTY_RESPONSE_TIME_DISTRIBUTION: ResponseTimeBucket[] = [
  { range: '<25ms', count: 0, percentage: 0 },
  { range: '25-50ms', count: 0, percentage: 0 },
  { range: '50-100ms', count: 0, percentage: 0 },
  { range: '100-250ms', count: 0, percentage: 0 },
  { range: '250-500ms', count: 0, percentage: 0 },
  { range: '>500ms', count: 0, percentage: 0 },
];

const EMPTY_STATUS_CODES: StatusCodeDistribution = {
  code2xx: 0,
  code3xx: 0,
  code4xx: 0,
  code5xx: 0,
};

function buildStatusCodesFromSensor(sensorMetrics: SensorMetrics | null): StatusCodeDistribution | null {
  if (!sensorMetrics?.statusCounts) {
    return null;
  }

  return {
    code2xx: sensorMetrics.statusCounts['2xx'] ?? 0,
    code3xx: sensorMetrics.statusCounts['3xx'] ?? 0,
    code4xx: sensorMetrics.statusCounts['4xx'] ?? 0,
    code5xx: sensorMetrics.statusCounts['5xx'] ?? 0,
  };
}

function buildFallbackStatusCodes(totalRequests: number, totalBlocked: number): StatusCodeDistribution {
  if (totalRequests <= 0) {
    return { ...EMPTY_STATUS_CODES };
  }

  return {
    code2xx: Math.max(totalRequests - totalBlocked, 0),
    code3xx: 0,
    code4xx: totalBlocked,
    code5xx: 0,
  };
}

export function createAnalyticsRouter(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();

  // GET /api/v1/beam/analytics - Traffic analytics data
  router.get('/', requireScope('dashboard:read'), asyncHandler(async (req, res) => {
    const tenantId = req.auth!.tenantId;

    // Type for block decisions from database
    interface BlockDecision {
      id: string;
      tenantId: string;
      sensorId?: string;
      action: string;
      severity?: string;
      threatType?: string;
      sourceIp: string;
      path: string;
      method: string;
      ruleId?: string;
      riskScore: number;
      decidedAt: Date;
    }

    const beamPrisma = prisma as unknown as {
      blockDecision: {
        findMany: (args: {
          where: { tenantId: string; decidedAt: { gte: Date } };
          orderBy: { decidedAt: 'desc' };
          take: number;
        }) => Promise<BlockDecision[]>;
      };
      endpoint: {
        count: (args: { where: { tenantId: string } }) => Promise<number>;
      };
    };

    const now = new Date();
    const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    // Fetch data in parallel
    const [
      blockDecisions,
      totalEndpoints,
    ] = await Promise.all([
      beamPrisma.blockDecision.findMany({
        where: {
          tenantId,
          decidedAt: { gte: dayAgo },
        },
        orderBy: { decidedAt: 'desc' },
        take: 1000,
      }),
      beamPrisma.endpoint.count({ where: { tenantId } }),
    ]);

    // Check for synapse-direct adapter for live sensor metrics
    const synapseAdapter = getSynapseDirectAdapter();
    let sensorMetrics: SensorMetrics | null = null;
    let responseTimeDistribution = EMPTY_RESPONSE_TIME_DISTRIBUTION;
    let statusCodes: StatusCodeDistribution = { ...EMPTY_STATUS_CODES };
    let dataSource: 'synapse-direct' | 'live' = 'live';

    if (synapseAdapter) {
      try {
        const [sensorData, prometheusAnalytics] = await Promise.all([
          synapseAdapter.getSensorStatus(),
          synapseAdapter.getPrometheusAnalytics(),
        ]);
        sensorMetrics = sensorData;
        if (prometheusAnalytics) {
          responseTimeDistribution = prometheusAnalytics.responseTimeDistribution;
          statusCodes = prometheusAnalytics.statusCodes;
        }
        if (sensorMetrics) {
          dataSource = 'synapse-direct';
          logger.info({ tenantId, source: 'synapse-direct' }, 'Using synapse-pingora sensor metrics');
        }
      } catch (err) {
        logger.warn({ err }, 'Failed to fetch synapse-direct metrics, using fallback');
      }
    }

    // Generate timeline buckets (24 hours, 1 hour each) using observed blocks and sensor totals
    const timelineBuckets = Array.from({ length: 24 }, (_, i) => {
      const bucketStart = new Date(now.getTime() - (23 - i) * 3600000);
      const bucketEnd = new Date(bucketStart.getTime() + 3600000);

      const bucketBlocks = (blockDecisions as BlockDecision[]).filter((b: BlockDecision) => {
        const decidedAt = new Date(b.decidedAt);
        return decidedAt >= bucketStart && decidedAt < bucketEnd;
      });

      return {
        timestamp: bucketStart.toISOString(),
        blocked: bucketBlocks.length,
      };
    });

    const blockedFromTimeline = timelineBuckets.reduce((sum, bucket) => sum + bucket.blocked, 0);
    const baselineRequests = sensorMetrics?.requestsTotal && sensorMetrics.requestsTotal > 0
      ? sensorMetrics.requestsTotal
      : blockedFromTimeline;
    const requestScale = blockedFromTimeline > 0 ? baselineRequests / blockedFromTimeline : 0;
    const defaultRequests = baselineRequests > 0 ? Math.round(baselineRequests / 24) : 0;

    const timeline = timelineBuckets.map(bucket => {
      const requests = blockedFromTimeline > 0
        ? Math.round(bucket.blocked * requestScale)
        : defaultRequests;
      return {
        timestamp: bucket.timestamp,
        requests,
        blocked: bucket.blocked,
        bytesIn: requests * 1500,
        bytesOut: requests * 4500,
      };
    });

    // Aggregate threat types
    const threatTypeCounts: Record<string, number> = {};
    (blockDecisions as BlockDecision[]).forEach((block: BlockDecision) => {
      const type = block.threatType || 'UNKNOWN';
      threatTypeCounts[type] = (threatTypeCounts[type] || 0) + 1;
    });

    // Severity distribution
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    (blockDecisions as BlockDecision[]).forEach((block: BlockDecision) => {
      const score = block.riskScore || 0;
      if (score >= 80) severityCounts.critical++;
      else if (score >= 60) severityCounts.high++;
      else if (score >= 40) severityCounts.medium++;
      else severityCounts.low++;
    });

    const totalRequests = timeline.reduce((sum, t) => sum + t.requests, 0);
    const totalBlocked = (blockDecisions as BlockDecision[]).length;
    const effectiveRequestsTotal = sensorMetrics?.requestsTotal ?? totalRequests;
    const effectiveBlocksTotal = sensorMetrics?.blocksTotal ?? totalBlocked;

    const statusCodesFromSensor = buildStatusCodesFromSensor(sensorMetrics);
    if (statusCodesFromSensor) {
      statusCodes = statusCodesFromSensor;
    } else if (statusCodes.code2xx === 0 && statusCodes.code3xx === 0 && statusCodes.code4xx === 0 && statusCodes.code5xx === 0) {
      statusCodes = buildFallbackStatusCodes(effectiveRequestsTotal, effectiveBlocksTotal);
    }

    logger.info({ tenantId, blockCount: totalBlocked, dataSource }, 'Analytics data fetched');

    return res.json({
      traffic: {
        totalRequests: effectiveRequestsTotal,
        totalBlocked: effectiveBlocksTotal,
        totalBandwidthIn: timeline.reduce((sum, t) => sum + t.bytesIn, 0),
        totalBandwidthOut: timeline.reduce((sum, t) => sum + t.bytesOut, 0),
        blockRate: effectiveRequestsTotal > 0 ? (effectiveBlocksTotal / effectiveRequestsTotal) * 100 : 0,
        timeline,
      },
      bandwidth: {
        timeline: timeline.map(t => ({
          timestamp: t.timestamp,
          bytesIn: t.bytesIn,
          bytesOut: t.bytesOut,
          requestCount: t.requests,
        })),
        topEndpoints: [],
        totalBytesIn: timeline.reduce((sum, t) => sum + t.bytesIn, 0),
        totalBytesOut: timeline.reduce((sum, t) => sum + t.bytesOut, 0),
        avgBytesPerRequest: 6000,
      },
      threats: {
        total: sensorMetrics?.blocksTotal ?? totalBlocked,
        bySeverity: severityCounts,
        byType: threatTypeCounts,
        recentEvents: (blockDecisions as BlockDecision[]).slice(0, 10).map((block: BlockDecision) => ({
          id: block.id,
          timestamp: block.decidedAt.toISOString(),
          severity: block.riskScore >= 80 ? 'CRITICAL' :
                   block.riskScore >= 60 ? 'HIGH' :
                   block.riskScore >= 40 ? 'MEDIUM' : 'LOW',
          type: block.threatType || 'UNKNOWN',
          description: `${block.action} request from ${block.sourceIp} to ${block.path}`,
          sourceIp: block.sourceIp,
          blocked: block.action === 'BLOCK',
        })),
      },
      sensor: sensorMetrics
        ? {
            ...sensorMetrics,
            entitiesTracked: sensorMetrics.entitiesTracked || totalEndpoints,
          }
        : {
            requestsTotal: effectiveRequestsTotal,
            blocksTotal: effectiveBlocksTotal,
            entitiesTracked: totalEndpoints,
            activeCampaigns: 0,
            uptime: 0,
            rps: effectiveRequestsTotal > 0 ? Math.round((effectiveRequestsTotal / (24 * 3600)) * 10) / 10 : 0,
            latencyP50: 0,
            latencyP95: 0,
            latencyP99: 0,
          },
      topEndpoints: [],
      responseTimeDistribution,
      regionTraffic: [],
      statusCodes,
      fetchedAt: now.toISOString(),
      dataSource,
    });
  }));

  return router;
}
