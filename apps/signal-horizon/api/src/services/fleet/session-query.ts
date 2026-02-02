/**
 * Fleet Session Query Service
 * Service for searching and managing sessions across all connected sensors in a fleet
 */

import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { TunnelBroker } from '../../websocket/tunnel-broker.js';
import type {
  SessionSearchQuery,
  SensorSession,
  SessionSearchResult,
  GlobalSessionSearchResult,
  SensorRevokeResult,
  GlobalRevokeResult,
  SensorBanResult,
  GlobalBanResult,
  FleetSessionStats,
} from './session-query-types.js';

/** Timeout for sensor queries in milliseconds */
const SENSOR_QUERY_TIMEOUT_MS = 10000;

/** Maximum concurrent sensor queries */
const MAX_CONCURRENT_QUERIES = 50;

/**
 * Result from a sensor RPC call
 */
interface SensorRpcResult<T> {
  sensorId: string;
  sensorName: string;
  success: boolean;
  data?: T;
  error?: string;
  durationMs: number;
  online: boolean;
}

/**
 * Options for the FleetSessionQueryService
 */
export interface FleetSessionQueryServiceOptions {
  /** PrismaClient for database access */
  prisma: PrismaClient;
  /** Pino logger instance */
  logger: Logger;
  /** Optional tunnel broker for sensor communication */
  tunnelBroker?: TunnelBroker;
}

/**
 * Service for querying and managing sessions across all sensors in a fleet
 */
export class FleetSessionQueryService {
  private readonly prisma: PrismaClient;
  private readonly logger: Logger;
  private readonly tunnelBroker?: TunnelBroker;

  constructor(options: FleetSessionQueryServiceOptions) {
    this.prisma = options.prisma;
    this.logger = options.logger.child({ service: 'FleetSessionQueryService' });
    this.tunnelBroker = options.tunnelBroker;
  }

  /**
   * Get all online sensors for a tenant
   */
  private async getOnlineSensors(tenantId: string): Promise<Array<{ id: string; name: string }>> {
    const sensors = await this.prisma.sensor.findMany({
      where: {
        tenantId,
        connectionState: 'CONNECTED',
      },
      select: {
        id: true,
        name: true,
      },
    });
    return sensors;
  }

  /**
   * Map RPC method and parameters to a web request payload
   */
  private mapRpcToWebRequest(
    method: string,
    params: Record<string, unknown>
  ): { method: 'GET' | 'POST' | 'PUT' | 'DELETE'; endpoint: string; body?: unknown } {
    switch (method) {
      case 'sessions.search': {
        const query = new URLSearchParams();
        if (params.sessionId) query.set('session_id', params.sessionId as string);
        if (params.actorId) query.set('actor_id', params.actorId as string);
        if (params.clientIp) query.set('client_ip', params.clientIp as string);
        if (params.ja4Fingerprint) query.set('ja4', params.ja4Fingerprint as string);
        if (params.userAgent) query.set('ua', params.userAgent as string);
        if (params.timeRangeStart) query.set('start', params.timeRangeStart as string);
        if (params.timeRangeEnd) query.set('end', params.timeRangeEnd as string);
        if (params.riskScoreMin !== undefined) query.set('min_risk', String(params.riskScoreMin));
        if (params.blockedOnly !== undefined) query.set('blocked', String(params.blockedOnly));
        if (params.limit !== undefined) query.set('limit', String(params.limit));

        return { method: 'GET', endpoint: `/_sensor/sessions?${query.toString()}` };
      }

      case 'sessions.revoke': {
        return {
          method: 'DELETE',
          endpoint: `/_sensor/sessions/${params.sessionId}`,
          body: { reason: params.reason },
        };
      }

      case 'actors.ban': {
        // Map actor ban to creating a block record on the sensor
        return {
          method: 'POST',
          endpoint: '/_sensor/blocks',
          body: {
            type: 'IP',
            value: params.actorId,
            reason: params.reason,
            source: 'FLEET_COMMAND',
            expiresAt: params.durationSeconds
              ? new Date(Date.now() + (params.durationSeconds as number) * 1000).toISOString()
              : undefined,
          },
        };
      }

      case 'sessions.stats':
        return { method: 'GET', endpoint: '/_sensor/sessions/stats' };

      default:
        throw new Error(`Unknown RPC method: ${method}`);
    }
  }

  /**
   * Execute an RPC call to a sensor with timeout
   */
  private async callSensorWithTimeout<T>(
    sensorId: string,
    sensorName: string,
    method: string,
    params: Record<string, unknown>,
    timeoutMs: number = SENSOR_QUERY_TIMEOUT_MS
  ): Promise<SensorRpcResult<T>> {
    const startTime = Date.now();

    try {
      if (!this.tunnelBroker) {
        throw new Error('Tunnel broker not available');
      }

      // Check if sensor is connected
      const tunnelInfo = this.tunnelBroker.getSensorTunnelInfo(sensorId);
      if (!tunnelInfo?.connected) {
        return {
          sensorId,
          sensorName,
          success: false,
          error: 'Sensor not connected',
          durationMs: Date.now() - startTime,
          online: false,
        };
      }

      // Map RPC method to web request
      const webReq = this.mapRpcToWebRequest(method, params);
      const requestId = randomUUID();

      // Use TunnelBroker's sendRequest for correlation
      const response = await this.tunnelBroker.sendRequest(
        sensorId,
        {
          type: 'dashboard-request',
          payload: {
            requestId,
            ...webReq,
          },
        },
        timeoutMs
      );

      // Check for errors in sensor response payload
      const payload = response.payload as {
        status: number;
        data?: T;
        error?: string;
      };

      if (payload.error) {
        throw new Error(payload.error);
      }

      if (payload.status >= 400) {
        throw new Error(`Sensor returned status ${payload.status}`);
      }

      return {
        sensorId,
        sensorName,
        success: true,
        data: payload.data,
        durationMs: Date.now() - startTime,
        online: true,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.warn({ sensorId, method, error: errorMessage }, 'Sensor RPC call failed');

      return {
        sensorId,
        sensorName,
        success: false,
        error: errorMessage,
        durationMs: Date.now() - startTime,
        online: errorMessage !== 'Sensor not connected',
      };
    }
  }

  /**
   * Search sessions across all online sensors in parallel
   */
  async searchSessions(tenantId: string, query: SessionSearchQuery): Promise<GlobalSessionSearchResult> {
    const startTime = Date.now();
    this.logger.info({ tenantId, query }, 'Starting global session search');

    // Get all online sensors for this tenant
    const sensors = await this.getOnlineSensors(tenantId);

    if (sensors.length === 0) {
      return {
        results: [],
        totalSessions: 0,
        totalSensors: 0,
        successfulSensors: 0,
        failedSensors: 0,
        searchDurationMs: Date.now() - startTime,
        query,
      };
    }

    // Prepare query parameters for sensors
    const rpcParams = {
      sessionId: query.sessionId,
      actorId: query.actorId,
      clientIp: query.clientIp,
      ja4Fingerprint: query.ja4Fingerprint,
      userAgent: query.userAgent,
      timeRangeStart: query.timeRange?.start?.toISOString(),
      timeRangeEnd: query.timeRange?.end?.toISOString(),
      riskScoreMin: query.riskScoreMin,
      blockedOnly: query.blockedOnly,
      limit: query.limitPerSensor ?? 50,
    };

    // Query all sensors in parallel using Promise.allSettled
    const results = await this.batchQuerySensors<{ sessions: SensorSession[]; totalMatches: number }>(
      sensors,
      'sessions.search',
      rpcParams
    );

    // Aggregate results
    const searchResults: SessionSearchResult[] = results.map((result) => ({
      sensorId: result.sensorId,
      sensorName: result.sensorName,
      sessions: result.success && result.data ? result.data.sessions : [],
      searchDurationMs: result.durationMs,
      error: result.error,
      online: result.online,
      totalMatches: result.data?.totalMatches,
    }));

    const totalSessions = searchResults.reduce((sum, r) => sum + r.sessions.length, 0);
    const successfulSensors = results.filter((r) => r.success).length;
    const failedSensors = results.filter((r) => !r.success).length;

    this.logger.info(
      { tenantId, totalSessions, successfulSensors, failedSensors, durationMs: Date.now() - startTime },
      'Global session search completed'
    );

    return {
      results: searchResults,
      totalSessions,
      totalSensors: sensors.length,
      successfulSensors,
      failedSensors,
      searchDurationMs: Date.now() - startTime,
      query,
    };
  }

  /**
   * Revoke a session on a specific sensor
   */
  async revokeSession(
    tenantId: string,
    sensorId: string,
    sessionId: string,
    reason?: string
  ): Promise<SensorRevokeResult> {
    this.logger.info({ tenantId, sensorId, sessionId }, 'Revoking session on sensor');

    // Verify sensor belongs to tenant
    const sensor = await this.prisma.sensor.findFirst({
      where: { id: sensorId, tenantId },
      select: { id: true, name: true },
    });

    if (!sensor) {
      return {
        sensorId,
        success: false,
        sessionId,
        error: 'Sensor not found or not authorized',
      };
    }

    const result = await this.callSensorWithTimeout<{ success: boolean }>(
      sensorId,
      sensor.name,
      'sessions.revoke',
      { sessionId, reason }
    );

    return {
      sensorId,
      success: result.success && result.data?.success === true,
      sessionId,
      error: result.error,
    };
  }

  /**
   * Revoke a session across all sensors (or specified subset)
   */
  async globalRevokeSession(
    tenantId: string,
    sessionId: string,
    reason?: string,
    sensorIds?: string[]
  ): Promise<GlobalRevokeResult> {
    this.logger.info({ tenantId, sessionId, sensorIds }, 'Starting global session revoke');

    // Get target sensors
    let sensors: Array<{ id: string; name: string }>;
    if (sensorIds && sensorIds.length > 0) {
      sensors = await this.prisma.sensor.findMany({
        where: {
          tenantId,
          id: { in: sensorIds },
          connectionState: 'CONNECTED',
        },
        select: { id: true, name: true },
      });
    } else {
      sensors = await this.getOnlineSensors(tenantId);
    }

    if (sensors.length === 0) {
      return {
        sessionId,
        results: [],
        totalSensors: 0,
        successCount: 0,
        failureCount: 0,
      };
    }

    // Revoke on all sensors in parallel
    const results = await this.batchQuerySensors<{ success: boolean }>(
      sensors,
      'sessions.revoke',
      { sessionId, reason }
    );

    const revokeResults: SensorRevokeResult[] = results.map((result) => ({
      sensorId: result.sensorId,
      success: result.success && result.data?.success === true,
      sessionId,
      error: result.error,
    }));

    const successCount = revokeResults.filter((r) => r.success).length;
    const failureCount = revokeResults.filter((r) => !r.success).length;

    this.logger.info(
      { tenantId, sessionId, successCount, failureCount },
      'Global session revoke completed'
    );

    return {
      sessionId,
      results: revokeResults,
      totalSensors: sensors.length,
      successCount,
      failureCount,
    };
  }

  /**
   * Ban an actor across all sensors (or specified subset)
   */
  async globalBanActor(
    tenantId: string,
    actorId: string,
    reason: string,
    durationSeconds?: number,
    sensorIds?: string[]
  ): Promise<GlobalBanResult> {
    this.logger.info({ tenantId, actorId, reason, durationSeconds, sensorIds }, 'Starting global actor ban');

    // Get target sensors
    let sensors: Array<{ id: string; name: string }>;
    if (sensorIds && sensorIds.length > 0) {
      sensors = await this.prisma.sensor.findMany({
        where: {
          tenantId,
          id: { in: sensorIds },
          connectionState: 'CONNECTED',
        },
        select: { id: true, name: true },
      });
    } else {
      sensors = await this.getOnlineSensors(tenantId);
    }

    if (sensors.length === 0) {
      return {
        actorId,
        reason,
        durationSeconds,
        results: [],
        totalSensors: 0,
        successCount: 0,
        failureCount: 0,
        totalSessionsTerminated: 0,
      };
    }

    // Ban actor on all sensors in parallel
    const results = await this.batchQuerySensors<{ success: boolean; sessionsTerminated: number }>(
      sensors,
      'actors.ban',
      { actorId, reason, durationSeconds }
    );

    const banResults: SensorBanResult[] = results.map((result) => ({
      sensorId: result.sensorId,
      success: result.success && result.data?.success === true,
      actorId,
      sessionsTerminated: result.data?.sessionsTerminated,
      error: result.error,
    }));

    const successCount = banResults.filter((r) => r.success).length;
    const failureCount = banResults.filter((r) => !r.success).length;
    const totalSessionsTerminated = banResults.reduce(
      (sum, r) => sum + (r.sessionsTerminated ?? 0),
      0
    );

    this.logger.info(
      { tenantId, actorId, successCount, failureCount, totalSessionsTerminated },
      'Global actor ban completed'
    );

    return {
      actorId,
      reason,
      durationSeconds,
      results: banResults,
      totalSensors: sensors.length,
      successCount,
      failureCount,
      totalSessionsTerminated,
    };
  }

  /**
   * Get fleet-wide session statistics
   */
  async getFleetSessionStats(tenantId: string): Promise<FleetSessionStats> {
    const startTime = Date.now();
    this.logger.info({ tenantId }, 'Fetching fleet session statistics');

    const sensors = await this.getOnlineSensors(tenantId);

    if (sensors.length === 0) {
      return {
        totalActiveSessions: 0,
        totalBlockedSessions: 0,
        uniqueActors: 0,
        averageRiskScore: 0,
        sessionsByRiskTier: { low: 0, medium: 0, high: 0, critical: 0 },
        topThreatCategories: [],
        sensorStats: [],
        timestamp: new Date(),
      };
    }

    // Query all sensors for stats
    const results = await this.batchQuerySensors<{
      activeSessions: number;
      blockedSessions: number;
      uniqueActors: number;
      avgRiskScore: number;
      riskTiers: { low: number; medium: number; high: number; critical: number };
      threatCategories: Array<{ category: string; count: number }>;
    }>(sensors, 'sessions.stats', {});

    // Aggregate statistics
    let totalActiveSessions = 0;
    let totalBlockedSessions = 0;
    let totalRiskScoreSum = 0;
    let riskScoreCount = 0;
    const riskTiers = { low: 0, medium: 0, high: 0, critical: 0 };
    const categoryCountMap = new Map<string, number>();
    const actorSet = new Set<string>();

    const sensorStats: FleetSessionStats['sensorStats'] = [];

    for (const result of results) {
      const online = result.success && result.online;
      const data = result.data;

      sensorStats.push({
        sensorId: result.sensorId,
        sensorName: result.sensorName,
        activeSessions: data?.activeSessions ?? 0,
        blockedSessions: data?.blockedSessions ?? 0,
        online,
      });

      if (data) {
        totalActiveSessions += data.activeSessions;
        totalBlockedSessions += data.blockedSessions;

        if (data.avgRiskScore > 0 && data.activeSessions > 0) {
          totalRiskScoreSum += data.avgRiskScore * data.activeSessions;
          riskScoreCount += data.activeSessions;
        }

        if (data.riskTiers) {
          riskTiers.low += data.riskTiers.low;
          riskTiers.medium += data.riskTiers.medium;
          riskTiers.high += data.riskTiers.high;
          riskTiers.critical += data.riskTiers.critical;
        }

        if (data.threatCategories) {
          for (const cat of data.threatCategories) {
            categoryCountMap.set(cat.category, (categoryCountMap.get(cat.category) ?? 0) + cat.count);
          }
        }
      }
    }

    // Sort threat categories by count
    const topThreatCategories = Array.from(categoryCountMap.entries())
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const averageRiskScore = riskScoreCount > 0 ? totalRiskScoreSum / riskScoreCount : 0;

    this.logger.info(
      { tenantId, totalActiveSessions, totalBlockedSessions, durationMs: Date.now() - startTime },
      'Fleet session statistics fetched'
    );

    return {
      totalActiveSessions,
      totalBlockedSessions,
      uniqueActors: actorSet.size,
      averageRiskScore: Math.round(averageRiskScore * 100) / 100,
      sessionsByRiskTier: riskTiers,
      topThreatCategories,
      sensorStats,
      timestamp: new Date(),
    };
  }

  /**
   * Helper method to batch query multiple sensors in parallel with concurrency limit
   */
  private async batchQuerySensors<T>(
    sensors: Array<{ id: string; name: string }>,
    method: string,
    params: Record<string, unknown>
  ): Promise<SensorRpcResult<T>[]> {
    // Process in batches to avoid overwhelming resources
    const results: SensorRpcResult<T>[] = [];
    const batchSize = MAX_CONCURRENT_QUERIES;

    for (let i = 0; i < sensors.length; i += batchSize) {
      const batch = sensors.slice(i, i + batchSize);
      const batchPromises = batch.map((sensor) =>
        this.callSensorWithTimeout<T>(sensor.id, sensor.name, method, params)
      );

      const batchResults = await Promise.allSettled(batchPromises);

      for (let j = 0; j < batchResults.length; j++) {
        const result = batchResults[j];
        if (result.status === 'fulfilled') {
          results.push(result.value);
        } else {
          // This shouldn't happen since callSensorWithTimeout handles errors internally
          results.push({
            sensorId: batch[j].id,
            sensorName: batch[j].name,
            success: false,
            error: result.reason instanceof Error ? result.reason.message : String(result.reason),
            durationMs: 0,
            online: false,
          });
        }
      }
    }

    return results;
  }
}

/**
 * Create a new FleetSessionQueryService instance
 */
export function createFleetSessionQueryService(
  options: FleetSessionQueryServiceOptions
): FleetSessionQueryService {
  return new FleetSessionQueryService(options);
}
