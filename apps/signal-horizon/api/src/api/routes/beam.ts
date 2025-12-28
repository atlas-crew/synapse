/**
 * Beam Analytics Routes
 * Proxies and aggregates data from risk-server for the Beam analytics dashboard
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import type { Logger } from 'pino';
import { config } from '../../config.js';
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

/**
 * Generate demo response time distribution data
 * (Not available from risk-server yet)
 */
function generateDemoResponseTimeData(): ResponseTimeBucket[] {
  return [
    { range: '<25ms', count: 45230, percentage: 38.2 },
    { range: '25-50ms', count: 32100, percentage: 27.1 },
    { range: '50-100ms', count: 21500, percentage: 18.2 },
    { range: '100-250ms', count: 12300, percentage: 10.4 },
    { range: '250-500ms', count: 5200, percentage: 4.4 },
    { range: '>500ms', count: 2100, percentage: 1.8 },
  ];
}

/**
 * Generate demo region traffic data
 * (Not available from risk-server yet - no geo-IP resolution)
 */
function generateDemoRegionData(): RegionTraffic[] {
  return [
    { countryCode: 'US', countryName: 'United States', requests: 892000, percentage: 37.2, blocked: 18400 },
    { countryCode: 'GB', countryName: 'United Kingdom', requests: 412000, percentage: 17.2, blocked: 8200 },
    { countryCode: 'DE', countryName: 'Germany', requests: 298000, percentage: 12.4, blocked: 5900 },
    { countryCode: 'FR', countryName: 'France', requests: 245000, percentage: 10.2, blocked: 4900 },
    { countryCode: 'JP', countryName: 'Japan', requests: 187000, percentage: 7.8, blocked: 3700 },
    { countryCode: 'CA', countryName: 'Canada', requests: 156000, percentage: 6.5, blocked: 3100 },
    { countryCode: 'AU', countryName: 'Australia', requests: 98000, percentage: 4.1, blocked: 1900 },
    { countryCode: 'NL', countryName: 'Netherlands', requests: 112000, percentage: 4.7, blocked: 2200 },
  ];
}

/**
 * Generate demo status code distribution
 * (Not available from risk-server yet)
 */
function generateDemoStatusCodes(): StatusCodeDistribution {
  return {
    code2xx: 2145000,
    code3xx: 156000,
    code4xx: 89000,
    code5xx: 12000,
  };
}

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

  return {
    requestsTotal: Number(metrics.requests_total || metrics.requestsTotal || 0),
    blocksTotal: Number(metrics.blocks_total || metrics.blocksTotal || 0),
    entitiesTracked: Number(metrics.entities_tracked || metrics.entitiesTracked || 0),
    activeCampaigns: Number(metrics.active_campaigns || metrics.activeCampaigns || 0),
    uptime: Number(metrics.uptime || 0),
    rps: Number(metrics.rps || metrics.requests_per_second || 0),
    latencyP50: Number(metrics.latency_p50 || metrics.latencyP50 || 45),
    latencyP95: Number(metrics.latency_p95 || metrics.latencyP95 || 120),
    latencyP99: Number(metrics.latency_p99 || metrics.latencyP99 || 250),
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
  return {
    totalRequests: sensor.requestsTotal,
    totalBlocked: sensor.blocksTotal,
    totalBandwidthIn: bandwidth.totalBytesIn,
    totalBandwidthOut: bandwidth.totalBytesOut,
    blockRate: sensor.requestsTotal > 0
      ? (sensor.blocksTotal / sensor.requestsTotal) * 100
      : 0,
    timeline: bandwidth.timeline.map(b => ({
      timestamp: b.timestamp,
      requests: b.requestCount,
      blocked: Math.round(b.requestCount * 0.02), // Estimate ~2% block rate
      bytesIn: b.bytesIn,
      bytesOut: b.bytesOut,
    })),
  };
}

/**
 * Transform bandwidth endpoints to top endpoints format
 */
function transformTopEndpoints(bandwidth: BandwidthAnalytics): TopEndpoint[] {
  return bandwidth.topEndpoints.slice(0, 10).map(ep => ({
    method: ep.method.toUpperCase() as TopEndpoint['method'],
    path: ep.template,
    requests: ep.requests,
    avgLatency: 45 + Math.random() * 100, // Demo: not available from risk-server
    errorRate: Math.random() * 2,          // Demo: not available from risk-server
    bandwidthIn: ep.avgRequestSize * ep.requests,
    bandwidthOut: ep.avgResponseSize * ep.requests,
  }));
}

export function createBeamRoutes(logger: Logger): Router {
  const router = Router();
  const log = logger.child({ module: 'beam-routes' });

  /**
   * GET /api/v1/beam/analytics
   * Returns combined analytics data from risk-server with demo fallbacks
   */
  router.get('/analytics', async (_req: Request, res: Response, _next: NextFunction) => {
    log.debug('Fetching beam analytics data');

    // Fetch data from risk-server in parallel
    const [sensorData, bandwidthData, anomalyData] = await Promise.all([
      fetchFromRiskServer('/_sensor/status', log),
      fetchFromRiskServer('/_sensor/payload/bandwidth', log),
      fetchFromRiskServer('/_sensor/anomalies', log),
    ]);

    // Transform risk-server data
    const sensor = transformSensorMetrics(sensorData);
    const bandwidth = transformBandwidthData(bandwidthData);
    const threats = transformThreats(anomalyData);
    const traffic = buildTrafficOverview(sensor, bandwidth);
    const topEndpoints = transformTopEndpoints(bandwidth);

    // Determine data source
    const hasLiveData = sensorData !== null || bandwidthData !== null || anomalyData !== null;
    const dataSource = hasLiveData ? 'mixed' : 'demo';

    const response: BeamAnalyticsResponse = {
      // Real data from risk-server (or transformed)
      traffic,
      bandwidth,
      threats,
      sensor,
      topEndpoints,

      // Demo data (not available from risk-server yet)
      responseTimeDistribution: generateDemoResponseTimeData(),
      regionTraffic: generateDemoRegionData(),
      statusCodes: generateDemoStatusCodes(),

      // Metadata
      fetchedAt: new Date().toISOString(),
      dataSource,
    };

    res.json(response);
  });

  /**
   * GET /api/v1/beam/traffic
   * Returns just traffic overview data
   */
  router.get('/traffic', async (_req: Request, res: Response, _next: NextFunction) => {
    const [sensorData, bandwidthData] = await Promise.all([
      fetchFromRiskServer('/_sensor/status', log),
      fetchFromRiskServer('/_sensor/payload/bandwidth', log),
    ]);

    const sensor = transformSensorMetrics(sensorData);
    const bandwidth = transformBandwidthData(bandwidthData);
    const traffic = buildTrafficOverview(sensor, bandwidth);

    res.json({
      traffic,
      fetchedAt: new Date().toISOString(),
    });
  });

  /**
   * GET /api/v1/beam/threats
   * Returns threat/anomaly summary
   */
  router.get('/threats', async (_req: Request, res: Response, _next: NextFunction) => {
    const anomalyData = await fetchFromRiskServer('/_sensor/anomalies', log);
    const threats = transformThreats(anomalyData);

    res.json({
      threats,
      fetchedAt: new Date().toISOString(),
    });
  });

  /**
   * GET /api/v1/beam/endpoints
   * Returns top endpoints by traffic
   */
  router.get('/endpoints', async (_req: Request, res: Response, _next: NextFunction) => {
    const bandwidthData = await fetchFromRiskServer('/_sensor/payload/bandwidth', log);
    const bandwidth = transformBandwidthData(bandwidthData);
    const topEndpoints = transformTopEndpoints(bandwidth);

    res.json({
      endpoints: topEndpoints,
      fetchedAt: new Date().toISOString(),
    });
  });

  /**
   * GET /api/v1/beam/health
   * Check risk-server connectivity
   */
  router.get('/health', async (_req: Request, res: Response, _next: NextFunction) => {
    const sensorData = await fetchFromRiskServer('/_sensor/status', log);
    const connected = sensorData !== null;

    res.json({
      riskServer: {
        url: config.riskServer.url,
        connected,
        checkedAt: new Date().toISOString(),
      },
    });
  });

  log.info('Beam analytics routes initialized');
  return router;
}
