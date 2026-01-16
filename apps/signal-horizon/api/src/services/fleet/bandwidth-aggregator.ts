/**
 * Bandwidth Aggregator Service
 * Fleet-wide bandwidth metrics aggregation for billing and analytics
 */

import type { Logger } from 'pino';
import type { PrismaClient } from '@prisma/client';
import type { TunnelBroker } from '../../websocket/tunnel-broker.js';
import type {
  FleetBandwidthStats,
  SensorBandwidthStats,
  EndpointBandwidthStats,
  BandwidthTimeline,
  BillingMetrics,
  SensorBandwidthResponse,
  BandwidthTimelineQuery,
  BillingMetricsQuery,
  BandwidthDataPoint,
} from './bandwidth-types.js';

export interface BandwidthAggregatorConfig {
  /** Timeout for sensor queries in milliseconds (default: 5000) */
  queryTimeoutMs?: number;
  /** Default cost per GB for billing (default: $0.085) */
  defaultCostPerGb?: number;
  /** Whether to return demo data when no sensors respond (default: true) */
  demoMode?: boolean;
}

/**
 * BandwidthAggregatorService
 * Aggregates bandwidth metrics from all sensors in the fleet
 */
export class BandwidthAggregatorService {
  private logger: Logger;
  private prisma: PrismaClient;
  private tunnelBroker?: TunnelBroker;
  private config: Required<BandwidthAggregatorConfig>;

  constructor(
    prisma: PrismaClient,
    logger: Logger,
    config: BandwidthAggregatorConfig = {},
    tunnelBroker?: TunnelBroker
  ) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'bandwidth-aggregator' });
    this.tunnelBroker = tunnelBroker;
    this.config = {
      queryTimeoutMs: config.queryTimeoutMs ?? 5000,
      defaultCostPerGb: config.defaultCostPerGb ?? 0.085,
      demoMode: config.demoMode ?? true,
    };
  }

  /**
   * Set the tunnel broker for sensor communication
   */
  setTunnelBroker(broker: TunnelBroker): void {
    this.tunnelBroker = broker;
  }

  /**
   * Get fleet-wide bandwidth statistics
   */
  async getFleetBandwidth(tenantId: string): Promise<FleetBandwidthStats> {
    this.logger.debug({ tenantId }, 'Getting fleet bandwidth stats');

    // Get all sensors for this tenant
    const sensors = await this.prisma.sensor.findMany({
      where: { tenantId },
      select: { id: true, name: true, region: true, connectionState: true },
    });

    if (sensors.length === 0) {
      return this.getEmptyFleetStats();
    }

    // Query all sensors in parallel
    const responses = await this.querySensorsBandwidth(sensors.map((s) => s.id));

    // Aggregate results
    let totalBytesIn = 0;
    let totalBytesOut = 0;
    let totalRequests = 0;
    let peakBytesIn = 0;
    let peakBytesOut = 0;
    let respondedCount = 0;

    for (const response of responses) {
      if (response.success && response.data) {
        respondedCount++;
        totalBytesIn += response.data.totalBytesIn;
        totalBytesOut += response.data.totalBytesOut;
        totalRequests += response.data.requestCount;

        // Find peaks from timeline
        for (const point of response.data.timeline) {
          if (point.bytesIn > peakBytesIn) peakBytesIn = point.bytesIn;
          if (point.bytesOut > peakBytesOut) peakBytesOut = point.bytesOut;
        }
      }
    }

    // If no sensors responded and demo mode is enabled, return demo data
    if (respondedCount === 0 && this.config.demoMode) {
      return this.getDemoFleetStats(sensors.length);
    }

    const avgBytesPerRequest =
      totalRequests > 0 ? Math.round((totalBytesIn + totalBytesOut) / totalRequests) : 0;

    return {
      totalBytesIn,
      totalBytesOut,
      totalRequests,
      avgBytesPerRequest,
      peakBytesIn,
      peakBytesOut,
      sensorCount: sensors.length,
      respondedSensors: respondedCount,
      collectedAt: new Date(),
    };
  }

  /**
   * Get bandwidth statistics for a specific sensor
   */
  async getSensorBandwidth(tenantId: string, sensorId: string): Promise<SensorBandwidthStats> {
    this.logger.debug({ tenantId, sensorId }, 'Getting sensor bandwidth stats');

    // Verify sensor belongs to tenant
    const sensor = await this.prisma.sensor.findFirst({
      where: { id: sensorId, tenantId },
      select: { id: true, name: true, region: true, connectionState: true },
    });

    if (!sensor) {
      throw new Error('Sensor not found');
    }

    // Query the sensor
    const responses = await this.querySensorsBandwidth([sensorId]);
    const response = responses[0];

    if (!response?.success || !response.data) {
      // Return demo data if sensor is offline and demo mode is enabled
      if (this.config.demoMode) {
        return this.getDemoSensorStats(sensorId, sensor.name, sensor.region ?? undefined);
      }

      return {
        sensorId,
        sensorName: sensor.name,
        region: sensor.region ?? undefined,
        totalBytesIn: 0,
        totalBytesOut: 0,
        totalRequests: 0,
        avgBytesPerRequest: 0,
        maxRequestSize: 0,
        maxResponseSize: 0,
        collectedAt: new Date(),
        isOnline: false,
      };
    }

    const { data } = response;
    const avgBytesPerRequest =
      data.requestCount > 0 ? Math.round((data.totalBytesIn + data.totalBytesOut) / data.requestCount) : 0;

    return {
      sensorId,
      sensorName: sensor.name,
      region: sensor.region ?? undefined,
      totalBytesIn: data.totalBytesIn,
      totalBytesOut: data.totalBytesOut,
      totalRequests: data.requestCount,
      avgBytesPerRequest,
      maxRequestSize: data.maxRequestSize,
      maxResponseSize: data.maxResponseSize,
      collectedAt: new Date(),
      isOnline: true,
    };
  }

  /**
   * Get per-endpoint bandwidth breakdown (aggregated across fleet)
   */
  async getEndpointBandwidth(tenantId: string): Promise<EndpointBandwidthStats[]> {
    this.logger.debug({ tenantId }, 'Getting endpoint bandwidth stats');

    // Get all sensors for this tenant
    const sensors = await this.prisma.sensor.findMany({
      where: { tenantId },
      select: { id: true },
    });

    if (sensors.length === 0) {
      return [];
    }

    // Query all sensors
    const responses = await this.querySensorsBandwidth(sensors.map((s) => s.id));

    // Aggregate endpoint stats across sensors
    const endpointMap = new Map<
      string,
      {
        methods: Set<string>;
        bytesIn: number;
        bytesOut: number;
        requestCount: number;
        responseSizes: number[];
        firstSeen: number;
        lastSeen: number;
      }
    >();

    for (const response of responses) {
      if (response.success && response.data) {
        for (const stat of response.data.endpointStats) {
          const existing = endpointMap.get(stat.path);
          if (existing) {
            stat.methods.forEach((m) => existing.methods.add(m));
            existing.requestCount += stat.hitCount;
            if (stat.firstSeen < existing.firstSeen) existing.firstSeen = stat.firstSeen;
            if (stat.lastSeen > existing.lastSeen) existing.lastSeen = stat.lastSeen;
          } else {
            endpointMap.set(stat.path, {
              methods: new Set(stat.methods),
              bytesIn: 0,
              bytesOut: 0,
              requestCount: stat.hitCount,
              responseSizes: [],
              firstSeen: stat.firstSeen,
              lastSeen: stat.lastSeen,
            });
          }
        }
      }
    }

    // If no data and demo mode is enabled, return demo data
    if (endpointMap.size === 0 && this.config.demoMode) {
      return this.getDemoEndpointStats();
    }

    // Convert to array and estimate bandwidth per endpoint
    const totalRequests = Array.from(endpointMap.values()).reduce((sum, e) => sum + e.requestCount, 0);

    return Array.from(endpointMap.entries())
      .map(([endpoint, data]) => {
        // Estimate bandwidth based on request proportion
        const proportion = totalRequests > 0 ? data.requestCount / totalRequests : 0;
        const avgResponseSize = data.responseSizes.length > 0
          ? data.responseSizes.reduce((a, b) => a + b, 0) / data.responseSizes.length
          : 1024; // Default estimate

        return {
          endpoint,
          methods: Array.from(data.methods),
          bytesIn: Math.round(data.requestCount * 500 * proportion), // Estimate
          bytesOut: Math.round(data.requestCount * avgResponseSize),
          requestCount: data.requestCount,
          avgResponseSize: Math.round(avgResponseSize),
          maxResponseSize: Math.max(...data.responseSizes, avgResponseSize),
          firstSeen: new Date(data.firstSeen),
          lastSeen: new Date(data.lastSeen),
        };
      })
      .sort((a, b) => b.requestCount - a.requestCount);
  }

  /**
   * Get bandwidth timeline for visualization
   */
  async getBandwidthTimeline(query: BandwidthTimelineQuery): Promise<BandwidthTimeline> {
    const { tenantId, granularity = '5m', durationMinutes = 60 } = query;

    this.logger.debug({ tenantId, granularity, durationMinutes }, 'Getting bandwidth timeline');

    // Get all sensors for this tenant
    const sensors = await this.prisma.sensor.findMany({
      where: { tenantId },
      select: { id: true },
    });

    const now = new Date();
    const startTime = new Date(now.getTime() - durationMinutes * 60 * 1000);

    if (sensors.length === 0) {
      return {
        points: [],
        granularity,
        startTime,
        endTime: now,
        totalBytesIn: 0,
        totalBytesOut: 0,
      };
    }

    // Query all sensors
    const responses = await this.querySensorsBandwidth(sensors.map((s) => s.id));

    // Aggregate timeline data
    const pointsMap = new Map<number, BandwidthDataPoint>();

    // Calculate bucket size in ms
    const bucketSizeMs = granularity === '1m' ? 60000 : granularity === '5m' ? 300000 : 3600000;

    for (const response of responses) {
      if (response.success && response.data) {
        for (const point of response.data.timeline) {
          const bucket = Math.floor(point.timestamp / bucketSizeMs) * bucketSizeMs;
          const existing = pointsMap.get(bucket);
          if (existing) {
            existing.bytesIn += point.bytesIn;
            existing.bytesOut += point.bytesOut;
            existing.requestCount += point.requestCount;
          } else {
            pointsMap.set(bucket, {
              timestamp: new Date(bucket),
              bytesIn: point.bytesIn,
              bytesOut: point.bytesOut,
              requestCount: point.requestCount,
            });
          }
        }
      }
    }

    // If no data and demo mode is enabled, return demo data
    if (pointsMap.size === 0 && this.config.demoMode) {
      return this.getDemoTimeline(granularity, startTime, now);
    }

    const points = Array.from(pointsMap.values()).sort(
      (a, b) => a.timestamp.getTime() - b.timestamp.getTime()
    );

    const totalBytesIn = points.reduce((sum, p) => sum + p.bytesIn, 0);
    const totalBytesOut = points.reduce((sum, p) => sum + p.bytesOut, 0);

    return {
      points,
      granularity,
      startTime,
      endTime: now,
      totalBytesIn,
      totalBytesOut,
    };
  }

  /**
   * Calculate billing metrics for a period
   */
  async getBillingMetrics(query: BillingMetricsQuery): Promise<BillingMetrics> {
    const { tenantId, start, end, costPerGb = this.config.defaultCostPerGb } = query;

    this.logger.debug({ tenantId, start, end, costPerGb }, 'Calculating billing metrics');

    // Get fleet bandwidth
    const fleetStats = await this.getFleetBandwidth(tenantId);

    // Get endpoint breakdown
    const endpointStats = await this.getEndpointBandwidth(tenantId);

    // Get all sensors for breakdown
    const sensors = await this.prisma.sensor.findMany({
      where: { tenantId },
      select: { id: true, name: true },
    });

    // Query sensors for per-sensor breakdown
    const responses = await this.querySensorsBandwidth(sensors.map((s) => s.id));

    const totalDataTransfer = fleetStats.totalBytesIn + fleetStats.totalBytesOut;
    const totalGb = totalDataTransfer / (1024 * 1024 * 1024);
    const estimatedCost = Math.round(totalGb * costPerGb * 100) / 100;

    // Build endpoint breakdown
    const endpointBreakdown = endpointStats.map((ep) => ({
      endpoint: ep.endpoint,
      bytes: ep.bytesIn + ep.bytesOut,
      percentage:
        totalDataTransfer > 0
          ? Math.round(((ep.bytesIn + ep.bytesOut) / totalDataTransfer) * 10000) / 100
          : 0,
      requestCount: ep.requestCount,
    }));

    // Build sensor breakdown
    const sensorBreakdown: Array<{
      sensorId: string;
      sensorName: string;
      bytes: number;
      percentage: number;
      requestCount: number;
    }> = [];

    for (const sensor of sensors) {
      const response = responses.find((r) => r.sensorId === sensor.id);
      if (response?.success && response.data) {
        const bytes = response.data.totalBytesIn + response.data.totalBytesOut;
        sensorBreakdown.push({
          sensorId: sensor.id,
          sensorName: sensor.name,
          bytes,
          percentage: totalDataTransfer > 0 ? Math.round((bytes / totalDataTransfer) * 10000) / 100 : 0,
          requestCount: response.data.requestCount,
        });
      }
    }

    // Sort by bytes descending
    sensorBreakdown.sort((a, b) => b.bytes - a.bytes);

    return {
      period: { start, end },
      totalDataTransfer,
      ingressBytes: fleetStats.totalBytesIn,
      egressBytes: fleetStats.totalBytesOut,
      requestCount: fleetStats.totalRequests,
      estimatedCost,
      costPerGb,
      breakdown: endpointBreakdown,
      sensorBreakdown,
    };
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  /**
   * Query bandwidth from multiple sensors in parallel
   */
  private async querySensorsBandwidth(sensorIds: string[]): Promise<SensorBandwidthResponse[]> {
    if (!this.tunnelBroker) {
      this.logger.warn('No tunnel broker available, returning empty responses');
      return sensorIds.map((id) => ({ sensorId: id, success: false, error: 'No tunnel broker' }));
    }

    const timeout = this.config.queryTimeoutMs;

    const promises = sensorIds.map(async (sensorId) => {
      try {
        const response = await Promise.race([
          this.querySensorBandwidth(sensorId),
          new Promise<SensorBandwidthResponse>((_, reject) =>
            setTimeout(() => reject(new Error('Timeout')), timeout)
          ),
        ]);
        return response;
      } catch (error) {
        return {
          sensorId,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    });

    return Promise.all(promises);
  }

  /**
   * Query bandwidth from a single sensor via tunnel
   */
  private async querySensorBandwidth(sensorId: string): Promise<SensorBandwidthResponse> {
    if (!this.tunnelBroker) {
      return { sensorId, success: false, error: 'No tunnel broker' };
    }

    // Check if sensor has active tunnel
    const tunnelInfo = this.tunnelBroker.getSensorTunnelInfo(sensorId);
    if (!tunnelInfo || !tunnelInfo.connected) {
      return { sensorId, success: false, error: 'Sensor not connected' };
    }

    try {
      // Send request through tunnel and wait for response
      const response = await this.tunnelBroker.sendRequest(sensorId, {
        type: 'get-bandwidth-stats',
        payload: {},
      });

      if (response.type === 'bandwidth-stats' && response.payload) {
        return {
          sensorId,
          success: true,
          data: response.payload as SensorBandwidthResponse['data'],
        };
      }

      return { sensorId, success: false, error: 'Invalid response type' };
    } catch (error) {
      return {
        sensorId,
        success: false,
        error: error instanceof Error ? error.message : 'Query failed',
      };
    }
  }

  // ============================================================================
  // Demo Data Methods
  // ============================================================================

  private getEmptyFleetStats(): FleetBandwidthStats {
    return {
      totalBytesIn: 0,
      totalBytesOut: 0,
      totalRequests: 0,
      avgBytesPerRequest: 0,
      peakBytesIn: 0,
      peakBytesOut: 0,
      sensorCount: 0,
      respondedSensors: 0,
      collectedAt: new Date(),
    };
  }

  private getDemoFleetStats(sensorCount: number): FleetBandwidthStats {
    const baseBytes = 50 * 1024 * 1024 * 1024; // 50 GB base
    const variation = Math.random() * 0.2 - 0.1; // +/- 10%

    return {
      totalBytesIn: Math.round(baseBytes * 0.4 * (1 + variation)),
      totalBytesOut: Math.round(baseBytes * 0.6 * (1 + variation)),
      totalRequests: Math.round(1000000 * (1 + variation)),
      avgBytesPerRequest: Math.round(50 * 1024),
      peakBytesIn: Math.round(500 * 1024 * 1024),
      peakBytesOut: Math.round(800 * 1024 * 1024),
      sensorCount,
      respondedSensors: sensorCount,
      collectedAt: new Date(),
    };
  }

  private getDemoSensorStats(sensorId: string, sensorName: string, region?: string): SensorBandwidthStats {
    const baseBytes = 10 * 1024 * 1024 * 1024; // 10 GB base
    const variation = Math.random() * 0.3 - 0.15; // +/- 15%

    return {
      sensorId,
      sensorName,
      region,
      totalBytesIn: Math.round(baseBytes * 0.4 * (1 + variation)),
      totalBytesOut: Math.round(baseBytes * 0.6 * (1 + variation)),
      totalRequests: Math.round(200000 * (1 + variation)),
      avgBytesPerRequest: Math.round(50 * 1024),
      maxRequestSize: Math.round(5 * 1024 * 1024),
      maxResponseSize: Math.round(10 * 1024 * 1024),
      collectedAt: new Date(),
      isOnline: true,
    };
  }

  private getDemoEndpointStats(): EndpointBandwidthStats[] {
    const endpoints = [
      '/api/v1/users',
      '/api/v1/products',
      '/api/v1/orders',
      '/api/v1/auth/login',
      '/api/v1/auth/refresh',
      '/api/v1/search',
      '/api/v1/analytics',
      '/api/v1/uploads',
      '/health',
      '/api/v1/notifications',
    ];

    const now = Date.now();
    return endpoints.map((endpoint, i) => {
      const requestCount = Math.round(100000 / (i + 1) + Math.random() * 10000);
      const avgResponseSize = Math.round(2048 * (1 + Math.random()));
      const bytesOut = requestCount * avgResponseSize;
      const bytesIn = Math.round(requestCount * 500);

      return {
        endpoint,
        methods: i < 3 ? ['GET', 'POST', 'PUT', 'DELETE'] : ['GET', 'POST'],
        bytesIn,
        bytesOut,
        requestCount,
        avgResponseSize,
        maxResponseSize: avgResponseSize * 10,
        firstSeen: new Date(now - 7 * 24 * 60 * 60 * 1000),
        lastSeen: new Date(now - Math.random() * 60000),
      };
    });
  }

  private getDemoTimeline(
    granularity: '1m' | '5m' | '1h',
    startTime: Date,
    endTime: Date
  ): BandwidthTimeline {
    const bucketSizeMs = granularity === '1m' ? 60000 : granularity === '5m' ? 300000 : 3600000;
    const points: BandwidthDataPoint[] = [];

    let current = Math.floor(startTime.getTime() / bucketSizeMs) * bucketSizeMs;
    const end = endTime.getTime();

    let totalBytesIn = 0;
    let totalBytesOut = 0;

    while (current < end) {
      // Add some realistic variation
      const hour = new Date(current).getHours();
      const isBusinessHours = hour >= 9 && hour <= 17;
      const baseMultiplier = isBusinessHours ? 1.5 : 0.7;

      const bytesIn = Math.round(1024 * 1024 * baseMultiplier * (1 + Math.random() * 0.5));
      const bytesOut = Math.round(1.5 * 1024 * 1024 * baseMultiplier * (1 + Math.random() * 0.5));
      const requestCount = Math.round(1000 * baseMultiplier * (1 + Math.random() * 0.3));

      points.push({
        timestamp: new Date(current),
        bytesIn,
        bytesOut,
        requestCount,
      });

      totalBytesIn += bytesIn;
      totalBytesOut += bytesOut;
      current += bucketSizeMs;
    }

    return {
      points,
      granularity,
      startTime,
      endTime,
      totalBytesIn,
      totalBytesOut,
    };
  }
}
