/**
 * Synapse Direct Adapter Service
 *
 * Provides direct integration with synapse-pingora admin API.
 * Transforms synapse-pingora's response format to match what beam routes expect,
 * allowing Signal Horizon to work with synapse-pingora without risk-server.
 *
 * Endpoints mapped:
 * - /health      → /_sensor/status equivalent
 * - /stats       → runtime statistics
 * - /waf/stats   → WAF-specific metrics
 * - /sites       → site configuration
 */

import type { Logger } from 'pino';
import type {
  SensorMetrics,
  BandwidthAnalytics,
  ThreatSummary,
  TopEndpoint,
  ResponseTimeBucket,
  StatusCodeDistribution,
} from '../types/beam.js';

// ============================================================================
// Synapse-Pingora Response Types
// ============================================================================

interface PingoraHealthResponse {
  success: boolean;
  data: {
    status: 'healthy' | 'degraded' | 'unhealthy';
    uptime_secs: number;
    backends: {
      healthy: number;
      unhealthy: number;
      total: number;
    };
    waf: {
      enabled: boolean;
      analyzed: number;
      blocked: number;
      block_rate_percent: number;
      avg_detection_us: number;
    };
  };
}

interface PingoraStatsResponse {
  success: boolean;
  data: {
    uptime_secs: number;
    rate_limit: {
      site_count: number;
      total_tracked_keys: number;
      global_enabled: boolean;
    };
    access_list_sites: number;
  };
}

interface PingoraWafStatsResponse {
  success: boolean;
  data: {
    enabled: boolean;
    analyzed: number;
    blocked: number;
    block_rate_percent: number;
    avg_detection_us: number;
  };
}

/**
 * Parsed Prometheus metrics from /metrics endpoint
 */
interface PrometheusMetrics {
  requestsTotal: number;
  requestsBlocked: number;
  wafAnalyzed: number;
  statusCounts: {
    '2xx': number;
    '3xx': number;
    '4xx': number;
    '5xx': number;
  };
  requestDuration?: {
    buckets: Record<string, number>;
    sum: number;
    count: number;
  };
}

// ============================================================================
// Adapter Service
// ============================================================================

export class SynapseDirectAdapter {
  private readonly baseUrl: string;
  private readonly timeout = 5000; // 5s timeout

  private normalizeTraceHeaders(traceHeaders?: Record<string, string>): Record<string, string> {
    if (!traceHeaders) return {};
    const out: Record<string, string> = {};
    for (const [key, value] of Object.entries(traceHeaders)) {
      const k = key.toLowerCase();
      if (k !== 'x-request-id' && k !== 'traceparent' && k !== 'tracestate') continue;
      if (typeof value !== 'string') continue;
      const v = value.trim();
      if (v.length === 0) continue;
      out[k] = v;
    }
    return out;
  }

  constructor(
    baseUrl: string,
    private logger: Logger
  ) {
    // Ensure no trailing slash
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.logger.info({ baseUrl: this.baseUrl }, 'SynapseDirectAdapter initialized');
  }

  /**
   * Fetch JSON from synapse-pingora with error handling
   */
  private async fetch<T>(path: string, traceHeaders?: Record<string, string>): Promise<T | null> {
    const url = `${this.baseUrl}${path}`;
    try {
      const headers = this.normalizeTraceHeaders(traceHeaders);
      const response = await fetch(url, {
        headers: { ...headers, Accept: 'application/json' },
        signal: AbortSignal.timeout(this.timeout),
      });

      if (!response.ok) {
        this.logger.warn({ url, status: response.status }, 'Synapse request failed');
        return null;
      }

      return (await response.json()) as T;
    } catch (error) {
      this.logger.warn({ url, error: (error as Error).message }, 'Synapse fetch error');
      return null;
    }
  }

  /**
   * Fetch and parse Prometheus metrics from /metrics endpoint
   */
  private async fetchPrometheusMetrics(traceHeaders?: Record<string, string>): Promise<PrometheusMetrics | null> {
    const url = `${this.baseUrl}/metrics`;
    try {
      const headers = this.normalizeTraceHeaders(traceHeaders);
      const response = await fetch(url, {
        headers,
        signal: AbortSignal.timeout(this.timeout),
      });

      if (!response.ok) {
        return null;
      }

      const text = await response.text();

      // Parse Prometheus format
      const getMetricValue = (name: string): number => {
        const match = text.match(new RegExp(`^${name}\\s+(\\d+(?:\\.\\d+)?)`, 'm'));
        return match ? parseFloat(match[1]) : 0;
      };

      const getStatusCount = (status: string): number => {
        const match = text.match(new RegExp(`synapse_requests_by_status\\{status="${status}"\\}\\s+(\\d+)`, 'm'));
        return match ? parseInt(match[1], 10) : 0;
      };

      const parseHistogram = (metric: string): { buckets: Record<string, number>; sum: number; count: number } | null => {
        const bucketRegex = new RegExp(`^${metric}_bucket\\{le="([^"]+)"\\}\\s+(\\d+(?:\\.\\d+)?)`, 'gm');
        const buckets: Record<string, number> = {};
        let match: RegExpExecArray | null;
        while ((match = bucketRegex.exec(text)) !== null) {
          buckets[match[1]] = parseFloat(match[2]);
        }

        const sum = getMetricValue(`${metric}_sum`);
        const count = getMetricValue(`${metric}_count`);

        if (Object.keys(buckets).length === 0 && sum === 0 && count === 0) {
          return null;
        }

        return { buckets, sum, count };
      };

      return {
        requestsTotal: getMetricValue('synapse_requests_total'),
        requestsBlocked: getMetricValue('synapse_requests_blocked'),
        wafAnalyzed: getMetricValue('synapse_waf_analyzed'),
        statusCounts: {
          '2xx': getStatusCount('2xx'),
          '3xx': getStatusCount('3xx'),
          '4xx': getStatusCount('4xx'),
          '5xx': getStatusCount('5xx'),
        },
        requestDuration: parseHistogram('synapse_request_duration_us') ?? undefined,
      };
    } catch (error) {
      this.logger.warn({ url, error: (error as Error).message }, 'Prometheus metrics fetch error');
      return null;
    }
  }

  /**
   * Get sensor status - transforms /health and /metrics to SensorMetrics format
   */
  async getSensorStatus(traceHeaders?: Record<string, string>): Promise<SensorMetrics | null> {
    const [health, stats, prometheus] = await Promise.all([
      this.fetch<PingoraHealthResponse>('/health', traceHeaders),
      this.fetch<PingoraStatsResponse>('/stats', traceHeaders),
      this.fetchPrometheusMetrics(traceHeaders),
    ]);

    if (!health?.success) {
      return null;
    }

    const waf = health.data.waf;
    const uptimeSecs = health.data.uptime_secs || stats?.data.uptime_secs || 0;

    // Use Prometheus metrics for accurate request counts, fallback to WAF stats
    const requestsTotal = prometheus?.requestsTotal ?? waf?.analyzed ?? 0;
    const blocksTotal = prometheus?.requestsBlocked ?? waf?.blocked ?? 0;

    // Calculate RPS based on uptime and total requests
    const rps = uptimeSecs > 0 ? Math.round((requestsTotal / uptimeSecs) * 10) / 10 : 0;

    // Convert avg_detection_us (microseconds) to latency estimates
    const avgDetectionUs = waf?.avg_detection_us || 0;
    const avgLatencyMs = avgDetectionUs / 1000;

    return {
      requestsTotal,
      blocksTotal,
      entitiesTracked: stats?.data.rate_limit?.total_tracked_keys || 0,
      activeCampaigns: 0, // Not available from synapse-pingora
      uptime: uptimeSecs,
      rps,
      latencyP50: avgLatencyMs > 0 ? avgLatencyMs * 0.8 : 0,
      latencyP95: avgLatencyMs > 0 ? avgLatencyMs * 1.5 : 0,
      latencyP99: avgLatencyMs > 0 ? avgLatencyMs * 2.5 : 0,
      // Include status code breakdown if available
      statusCounts: prometheus?.statusCounts,
    };
  }

  /**
   * Get bandwidth analytics - synthesized from available data
   * Note: synapse-pingora doesn't expose detailed bandwidth metrics,
   * so we provide estimates based on request counts
   */
  async getBandwidthAnalytics(traceHeaders?: Record<string, string>): Promise<BandwidthAnalytics | null> {
    const health = await this.fetch<PingoraHealthResponse>('/health', traceHeaders);

    if (!health?.success) {
      return null;
    }

    const analyzed = health.data.waf?.analyzed || 0;

    // Estimate average request/response sizes
    const avgRequestSize = 1024; // 1KB average request
    const avgResponseSize = 4096; // 4KB average response

    return {
      timeline: [], // Real-time timeline not available from synapse-pingora
      topEndpoints: [], // Endpoint-level data not available
      totalBytesIn: analyzed * avgRequestSize,
      totalBytesOut: analyzed * avgResponseSize,
      avgBytesPerRequest: avgRequestSize + avgResponseSize,
    };
  }

  /**
   * Get threat summary - synthesized from WAF stats
   * Note: synapse-pingora doesn't expose detailed threat breakdown,
   * so we provide summary based on block counts
   */
  async getThreatSummary(traceHeaders?: Record<string, string>): Promise<ThreatSummary | null> {
    const [health, wafStats] = await Promise.all([
      this.fetch<PingoraHealthResponse>('/health', traceHeaders),
      this.fetch<PingoraWafStatsResponse>('/waf/stats', traceHeaders),
    ]);

    if (!health?.success) {
      return null;
    }

    const waf = health.data.waf || wafStats?.data;
    const blocked = waf?.blocked || 0;

    // Estimate severity distribution based on block count
    // In reality, synapse-pingora would need to expose this data
    const critical = Math.floor(blocked * 0.1);
    const high = Math.floor(blocked * 0.3);
    const medium = Math.floor(blocked * 0.4);
    const low = blocked - critical - high - medium;

    return {
      total: blocked,
      bySeverity: { critical, high, medium, low },
      byType: blocked > 0 ? { WAF_BLOCK: blocked } : {},
      recentEvents: [], // Detailed events not available from synapse-pingora
    };
  }

  /**
   * Get top endpoints - not available from synapse-pingora
   * Returns empty array, beam routes will use demo data as fallback
   */
  async getTopEndpoints(): Promise<TopEndpoint[]> {
    return [];
  }

  /**
   * Get response time and status code analytics from Prometheus metrics.
   */
  async getPrometheusAnalytics(traceHeaders?: Record<string, string>): Promise<{
    responseTimeDistribution: ResponseTimeBucket[];
    statusCodes: StatusCodeDistribution;
  } | null> {
    const prometheus = await this.fetchPrometheusMetrics(traceHeaders);
    if (!prometheus) {
      return null;
    }

    const statusCodes: StatusCodeDistribution = {
      code2xx: prometheus.statusCounts['2xx'] || 0,
      code3xx: prometheus.statusCounts['3xx'] || 0,
      code4xx: prometheus.statusCounts['4xx'] || 0,
      code5xx: prometheus.statusCounts['5xx'] || 0,
    };

    const responseTimeDistribution = buildResponseTimeDistribution(prometheus.requestDuration);

    return { responseTimeDistribution, statusCodes };
  }

  /**
   * Health check - verify connection to synapse-pingora
   */
  async healthCheck(traceHeaders?: Record<string, string>): Promise<{ connected: boolean; status?: string; uptime?: number }> {
    const health = await this.fetch<PingoraHealthResponse>('/health', traceHeaders);

    if (!health?.success) {
      return { connected: false };
    }

    return {
      connected: true,
      status: health.data.status,
      uptime: health.data.uptime_secs,
    };
  }

  /**
   * Get raw WAF stats for debugging/monitoring
   */
  async getWafStats(traceHeaders?: Record<string, string>): Promise<PingoraWafStatsResponse['data'] | null> {
    const response = await this.fetch<PingoraWafStatsResponse>('/waf/stats', traceHeaders);
    return response?.success ? response.data : null;
  }
}

// ============================================================================
// Prometheus Analytics Helpers
// ============================================================================

const RESPONSE_TIME_BUCKETS = [
  { label: '<25ms', upperBoundUs: 25_000 },
  { label: '25-50ms', upperBoundUs: 50_000 },
  { label: '50-100ms', upperBoundUs: 100_000 },
  { label: '100-250ms', upperBoundUs: 250_000 },
  { label: '250-500ms', upperBoundUs: 500_000 },
] as const;

function buildResponseTimeDistribution(
  histogram?: { buckets: Record<string, number>; count: number }
): ResponseTimeBucket[] {
  if (!histogram) {
    return RESPONSE_TIME_BUCKETS.map(bucket => ({
      range: bucket.label,
      count: 0,
      percentage: 0,
    })).concat({ range: '>500ms', count: 0, percentage: 0 });
  }

  const total = histogram.count || histogram.buckets['+Inf'] || 0;
  const getCumulative = (upperBoundUs: number): number =>
    histogram.buckets[String(upperBoundUs)] ?? 0;

  const buckets: ResponseTimeBucket[] = [];
  let previousCumulative = 0;

  for (const bucket of RESPONSE_TIME_BUCKETS) {
    const cumulative = getCumulative(bucket.upperBoundUs);
    const count = Math.max(cumulative - previousCumulative, 0);
    previousCumulative = cumulative;
    buckets.push({
      range: bucket.label,
      count,
      percentage: total > 0 ? Math.round((count / total) * 1000) / 10 : 0,
    });
  }

  const overCount = Math.max(total - previousCumulative, 0);
  buckets.push({
    range: '>500ms',
    count: overCount,
    percentage: total > 0 ? Math.round((overCount / total) * 1000) / 10 : 0,
  });

  return buckets;
}

// ============================================================================
// Singleton Instance Management
// ============================================================================

let instance: SynapseDirectAdapter | null = null;

/**
 * Initialize the synapse direct adapter
 * Call this once at startup if SYNAPSE_DIRECT_URL is configured
 */
export function initSynapseDirectAdapter(baseUrl: string, logger: Logger): SynapseDirectAdapter {
  instance = new SynapseDirectAdapter(baseUrl, logger);
  return instance;
}

/**
 * Get the synapse direct adapter instance
 * Returns null if not initialized
 */
export function getSynapseDirectAdapter(): SynapseDirectAdapter | null {
  return instance;
}
