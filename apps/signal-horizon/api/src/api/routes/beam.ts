/**
 * Beam Analytics Routes
 * Proxies and aggregates data from risk-server or synapse-pingora for the Beam analytics dashboard
 *
 * Data sources (in priority order):
 * 1. Synapse Direct (SYNAPSE_DIRECT_URL) - Direct connection to synapse-pingora admin API
 * 2. Risk Server (RISK_SERVER_URL) - Upstream Synapse proxy with full analytics
 * 3. Derived Data - Fallback when metrics are unavailable
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import type { Logger } from 'pino';
import { config } from '../../config.js';
import { getSynapseDirectAdapter } from '../../services/synapse-direct.js';
import { requireScope } from '../middleware/auth.js';
import type {
  BeamAnalyticsResponse,
  BandwidthAnalytics,
  ThreatSummary,
  SensorMetrics,
  TopEndpoint,
  TrafficOverview,
  ResponseTimeBucket,
  RegionTraffic,
  StatusCodeDistribution,
} from '../../types/beam.js';

/**
 * Fetch JSON from risk-server with error handling
 */
async function fetchFromRiskServer<T>(path: string, logger: Logger): Promise<T | null> {
  const url = `${config.riskServer.url}${path}`;
  try {
    const response = await fetch(url, {
      headers: {
        'Accept': 'application/json',
      },
      signal: AbortSignal.timeout(5000), // 5s timeout
    });

    if (!response.ok) {
      logger.warn({ url, status: response.status }, 'Risk server request failed');
      return null;
    }

    return await response.json() as T;
  } catch (error) {
    logger.warn({ url, error: (error as Error).message }, 'Risk server fetch error');
    return null;
  }
}

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

/**
 * Transform risk-server bandwidth data to our format
 */
function transformBandwidthData(data: unknown): BandwidthAnalytics {
  // Default fallback
  const fallback: BandwidthAnalytics = {
    timeline: [],
    topEndpoints: [],
    totalBytesIn: 0,
    totalBytesOut: 0,
    avgBytesPerRequest: 0,
  };

  if (!data || typeof data !== 'object') return fallback;

  const rsData = data as Record<string, unknown>;

  // Extract timeline if available
  const timeline = Array.isArray(rsData.timeline)
    ? rsData.timeline.map((bucket: Record<string, unknown>) => ({
        timestamp: String(bucket.timestamp || new Date().toISOString()),
        bytesIn: Number(bucket.bytesIn || bucket.bytes_in || 0),
        bytesOut: Number(bucket.bytesOut || bucket.bytes_out || 0),
        requestCount: Number(bucket.requestCount || bucket.request_count || 0),
      }))
    : [];

  // Extract top endpoints if available
  const endpointsList = Array.isArray(rsData.topEndpoints)
    ? rsData.topEndpoints
    : Array.isArray(rsData.endpoints)
      ? rsData.endpoints
      : [];

  const topEndpoints = endpointsList.map((ep: Record<string, unknown>) => ({
    template: String(ep.template || ep.path || ''),
    method: String(ep.method || 'GET'),
    requests: Number(ep.requests || ep.count || 0),
    avgRequestSize: Number(ep.avgRequestSize || ep.avg_request_size || 0),
    avgResponseSize: Number(ep.avgResponseSize || ep.avg_response_size || 0),
    totalBytes: Number(ep.totalBytes || ep.total_bytes || 0),
  }));

  return {
    timeline,
    topEndpoints,
    totalBytesIn: Number(rsData.totalBytesIn || rsData.total_bytes_in || 0),
    totalBytesOut: Number(rsData.totalBytesOut || rsData.total_bytes_out || 0),
    avgBytesPerRequest: Number(rsData.avgBytesPerRequest || rsData.avg_bytes_per_request || 0),
  };
}

/**
 * Transform risk-server sensor status to our format
 */
function transformSensorMetrics(data: unknown): SensorMetrics {
  const fallback: SensorMetrics = {
    requestsTotal: 0,
    blocksTotal: 0,
    entitiesTracked: 0,
    activeCampaigns: 0,
    uptime: 0,
    rps: 0,
    latencyP50: 0,
    latencyP95: 0,
    latencyP99: 0,
  };

  if (!data || typeof data !== 'object') return fallback;

  const rsData = data as Record<string, unknown>;
  const metrics = (rsData.metrics || rsData) as Record<string, unknown>;
  const rawStatusCounts = (metrics.status_counts || metrics.statusCounts) as Record<string, unknown> | undefined;
  const statusCounts = rawStatusCounts && typeof rawStatusCounts === 'object'
    ? {
        '2xx': Number(rawStatusCounts['2xx'] ?? rawStatusCounts.code2xx ?? 0),
        '3xx': Number(rawStatusCounts['3xx'] ?? rawStatusCounts.code3xx ?? 0),
        '4xx': Number(rawStatusCounts['4xx'] ?? rawStatusCounts.code4xx ?? 0),
        '5xx': Number(rawStatusCounts['5xx'] ?? rawStatusCounts.code5xx ?? 0),
      }
    : undefined;

  return {
    requestsTotal: Number(metrics.requests_total || metrics.requestsTotal || 0),
    blocksTotal: Number(metrics.blocks_total || metrics.blocksTotal || 0),
    entitiesTracked: Number(metrics.entities_tracked || metrics.entitiesTracked || 0),
    activeCampaigns: Number(metrics.active_campaigns || metrics.activeCampaigns || 0),
    uptime: Number(metrics.uptime || 0),
    rps: Number(metrics.rps || metrics.requests_per_second || 0),
    latencyP50: Number(metrics.latency_p50 || metrics.latencyP50 || 0),
    latencyP95: Number(metrics.latency_p95 || metrics.latencyP95 || 0),
    latencyP99: Number(metrics.latency_p99 || metrics.latencyP99 || 0),
    statusCounts,
  };
}

/**
 * Transform risk-server anomalies to threat summary
 */
function transformThreats(data: unknown): ThreatSummary {
  const fallback: ThreatSummary = {
    total: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
    byType: {},
    recentEvents: [],
  };

  if (!data || typeof data !== 'object') return fallback;

  const rsData = data as Record<string, unknown>;
  const anomalies = Array.isArray(rsData.anomalies) ? rsData.anomalies :
                    Array.isArray(rsData) ? rsData : [];

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byType: Record<string, number> = {};

  for (const anomaly of anomalies as Record<string, unknown>[]) {
    const severity = String(anomaly.severity || 'LOW').toUpperCase();
    if (severity in bySeverity) {
      bySeverity[severity.toLowerCase() as keyof typeof bySeverity]++;
    }

    const type = String(anomaly.type || anomaly.anomaly_type || 'UNKNOWN');
    byType[type] = (byType[type] || 0) + 1;
  }

  const recentEvents = (anomalies as Record<string, unknown>[]).slice(0, 10).map((a, i) => ({
    id: String(a.id || `anomaly-${i}`),
    timestamp: String(a.timestamp || new Date().toISOString()),
    severity: String(a.severity || 'LOW').toUpperCase() as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    type: String(a.type || a.anomaly_type || 'UNKNOWN'),
    description: String(a.description || a.message || 'Anomaly detected'),
    entityId: a.entity_id ? String(a.entity_id) : undefined,
    sourceIp: a.source_ip ? String(a.source_ip) : undefined,
    blocked: Boolean(a.blocked),
  }));

  return {
    total: anomalies.length,
    bySeverity,
    byType,
    recentEvents,
  };
}

/**
 * Build traffic overview from sensor metrics and bandwidth data
 */
function buildTrafficOverview(sensor: SensorMetrics, bandwidth: BandwidthAnalytics): TrafficOverview {
  const blockRate = sensor.requestsTotal > 0
    ? sensor.blocksTotal / sensor.requestsTotal
    : 0;

  return {
    totalRequests: sensor.requestsTotal,
    totalBlocked: sensor.blocksTotal,
    totalBandwidthIn: bandwidth.totalBytesIn,
    totalBandwidthOut: bandwidth.totalBytesOut,
    blockRate: blockRate * 100,
    timeline: bandwidth.timeline.map(b => ({
      timestamp: b.timestamp,
      requests: b.requestCount,
      blocked: Math.round(b.requestCount * blockRate),
      bytesIn: b.bytesIn,
      bytesOut: b.bytesOut,
    })),
  };
}

/**
 * Transform bandwidth endpoints to top endpoints format
 */
function transformTopEndpoints(
  bandwidth: BandwidthAnalytics,
  sensor: SensorMetrics,
  statusCodes: StatusCodeDistribution
): TopEndpoint[] {
  const totalStatus = statusCodes.code2xx + statusCodes.code3xx + statusCodes.code4xx + statusCodes.code5xx;
  const errorRate = totalStatus > 0
    ? ((statusCodes.code4xx + statusCodes.code5xx) / totalStatus) * 100
    : 0;
  const avgLatency = sensor.latencyP50 || sensor.latencyP95 || 0;

  return bandwidth.topEndpoints.slice(0, 10).map(ep => ({
    method: ep.method.toUpperCase() as TopEndpoint['method'],
    path: ep.template,
    requests: ep.requests,
    avgLatency,
    errorRate,
    bandwidthIn: ep.avgRequestSize * ep.requests,
    bandwidthOut: ep.avgResponseSize * ep.requests,
  }));
}

function buildStatusCodes(sensor: SensorMetrics): StatusCodeDistribution {
  if (!sensor.statusCounts) {
    return { ...EMPTY_STATUS_CODES };
  }

  return {
    code2xx: sensor.statusCounts['2xx'] ?? 0,
    code3xx: sensor.statusCounts['3xx'] ?? 0,
    code4xx: sensor.statusCounts['4xx'] ?? 0,
    code5xx: sensor.statusCounts['5xx'] ?? 0,
  };
}

function buildRegionTraffic(sensor: SensorMetrics): RegionTraffic[] {
  if (sensor.requestsTotal <= 0) {
    return [];
  }

  return [
    {
      countryCode: 'ZZ',
      countryName: 'Unknown',
      requests: sensor.requestsTotal,
      percentage: 100,
      blocked: sensor.blocksTotal,
    },
  ];
}

export function createBeamRoutes(logger: Logger): Router {
  const router = Router();
  const log = logger.child({ module: 'beam-routes' });

  /**
   * GET /api/v1/beam/analytics
   * Returns combined analytics data from synapse-pingora or risk-server with derived fallbacks
   *
   * Security: Requires analytics:read scope (or dashboard:read via alias)
   */
  router.get('/analytics', requireScope('analytics:read'), async (_req: Request, res: Response, _next: NextFunction) => {
    log.debug('Fetching beam analytics data');

    // Check for synapse direct adapter first
    const synapseAdapter = getSynapseDirectAdapter();

    let sensor: SensorMetrics;
    let bandwidth: BandwidthAnalytics;
    let threats: ThreatSummary;
    let dataSource: 'synapse-direct' | 'risk-server' | 'mixed';
    let responseTimeDistribution = EMPTY_RESPONSE_TIME_DISTRIBUTION;
    let statusCodes = EMPTY_STATUS_CODES;

    if (synapseAdapter) {
      // Use direct synapse-pingora connection
      log.debug('Using synapse-direct adapter');

      const [sensorData, bandwidthData, threatData, prometheusAnalytics] = await Promise.all([
        synapseAdapter.getSensorStatus(),
        synapseAdapter.getBandwidthAnalytics(),
        synapseAdapter.getThreatSummary(),
        synapseAdapter.getPrometheusAnalytics(),
      ]);

      sensor = sensorData || transformSensorMetrics(null);
      bandwidth = bandwidthData || transformBandwidthData(null);
      threats = threatData || transformThreats(null);
      responseTimeDistribution = prometheusAnalytics?.responseTimeDistribution ?? EMPTY_RESPONSE_TIME_DISTRIBUTION;
      statusCodes = prometheusAnalytics?.statusCodes ?? buildStatusCodes(sensor);
      dataSource = 'synapse-direct';
    } else {
      // Fetch data from risk-server in parallel
      const [sensorData, bandwidthData, anomalyData] = await Promise.all([
        fetchFromRiskServer('/_sensor/status', log),
        fetchFromRiskServer('/_sensor/payload/bandwidth', log),
        fetchFromRiskServer('/_sensor/anomalies', log),
      ]);

      // Transform risk-server data
      sensor = transformSensorMetrics(sensorData);
      bandwidth = transformBandwidthData(bandwidthData);
      threats = transformThreats(anomalyData);
      statusCodes = buildStatusCodes(sensor);
      responseTimeDistribution = EMPTY_RESPONSE_TIME_DISTRIBUTION;

      // Determine data source
      dataSource = 'risk-server';
    }

    const traffic = buildTrafficOverview(sensor, bandwidth);
    const topEndpoints = transformTopEndpoints(bandwidth, sensor, statusCodes);
    const regionTraffic = buildRegionTraffic(sensor);

    const response: BeamAnalyticsResponse = {
      // Real data from risk-server (or transformed)
      traffic,
      bandwidth,
      threats,
      sensor,
      topEndpoints,

      // Derived metrics (may be empty if unavailable)
      responseTimeDistribution,
      regionTraffic,
      statusCodes,

      // Metadata
      fetchedAt: new Date().toISOString(),
      dataSource,
    };

    res.json(response);
  });

  /**
   * GET /api/v1/beam/traffic
   * Returns just traffic overview data
   *
   * Security: Requires analytics:read scope (or dashboard:read via alias)
   */
  router.get('/traffic', requireScope('analytics:read'), async (_req: Request, res: Response, _next: NextFunction) => {
    const synapseAdapter = getSynapseDirectAdapter();

    let sensor: SensorMetrics;
    let bandwidth: BandwidthAnalytics;

    if (synapseAdapter) {
      const [sensorData, bandwidthData] = await Promise.all([
        synapseAdapter.getSensorStatus(),
        synapseAdapter.getBandwidthAnalytics(),
      ]);
      sensor = sensorData || transformSensorMetrics(null);
      bandwidth = bandwidthData || transformBandwidthData(null);
    } else {
      const [sensorData, bandwidthData] = await Promise.all([
        fetchFromRiskServer('/_sensor/status', log),
        fetchFromRiskServer('/_sensor/payload/bandwidth', log),
      ]);
      sensor = transformSensorMetrics(sensorData);
      bandwidth = transformBandwidthData(bandwidthData);
    }

    const traffic = buildTrafficOverview(sensor, bandwidth);

    res.json({
      traffic,
      fetchedAt: new Date().toISOString(),
    });
  });

  /**
   * GET /api/v1/beam/threats
   * Returns threat/anomaly summary
   *
   * Security: Requires analytics:read scope (or dashboard:read via alias)
   */
  router.get('/threats', requireScope('analytics:read'), async (_req: Request, res: Response, _next: NextFunction) => {
    const synapseAdapter = getSynapseDirectAdapter();

    let threats: ThreatSummary;

    if (synapseAdapter) {
      const threatData = await synapseAdapter.getThreatSummary();
      threats = threatData || transformThreats(null);
    } else {
      const anomalyData = await fetchFromRiskServer('/_sensor/anomalies', log);
      threats = transformThreats(anomalyData);
    }

    res.json({
      threats,
      fetchedAt: new Date().toISOString(),
    });
  });

  /**
   * GET /api/v1/beam/endpoints
   * Returns top endpoints by traffic
   *
   * Security: Requires analytics:read scope (or dashboard:read via alias)
   */
  router.get('/endpoints', requireScope('analytics:read'), async (_req: Request, res: Response, _next: NextFunction) => {
    const bandwidthData = await fetchFromRiskServer('/_sensor/payload/bandwidth', log);
    const bandwidth = transformBandwidthData(bandwidthData);
    const sensor = transformSensorMetrics(null);
    const statusCodes = buildStatusCodes(sensor);
    const topEndpoints = transformTopEndpoints(bandwidth, sensor, statusCodes);

    res.json({
      endpoints: topEndpoints,
      fetchedAt: new Date().toISOString(),
    });
  });

  /**
   * GET /api/v1/beam/health
   * Check synapse-pingora or risk-server connectivity
   *
   * Security: Requires analytics:health scope (or dashboard:read via alias)
   */
  router.get('/health', requireScope('analytics:health'), async (_req: Request, res: Response, _next: NextFunction) => {
    const synapseAdapter = getSynapseDirectAdapter();

    if (synapseAdapter) {
      const health = await synapseAdapter.healthCheck();

      res.json({
        synapseDirect: {
          url: config.synapseDirect.url,
          connected: health.connected,
          status: health.status,
          uptime: health.uptime,
          checkedAt: new Date().toISOString(),
        },
        riskServer: {
          url: config.riskServer.url,
          connected: false,
          note: 'Bypassed - using synapse-direct',
        },
      });
    } else {
      const sensorData = await fetchFromRiskServer('/_sensor/status', log);
      const connected = sensorData !== null;

      res.json({
        synapseDirect: {
          enabled: false,
        },
        riskServer: {
          url: config.riskServer.url,
          connected,
          checkedAt: new Date().toISOString(),
        },
      });
    }
  });

  log.info('Beam analytics routes initialized');
  return router;
}
