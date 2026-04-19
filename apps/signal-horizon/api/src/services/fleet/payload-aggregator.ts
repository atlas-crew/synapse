import type { PrismaClient } from '@prisma/client';
import type {
  EndpointPayloadSummary,
  PayloadAnomalyResponse,
  PayloadBandwidthPoint,
  PayloadBandwidthStats,
  PayloadSummaryResponse,
} from '../synapse-proxy.js';
import {
  createFleetPartialAggregateResult,
  type FleetPartialAggregateResult,
  type FleetPartialResultEntry,
} from '../../types/fleet-partial-result.js';

export interface DlpStatsResponse {
  totalScans: number;
  totalMatches: number;
  patternCount: number;
}

export interface DlpViolation {
  timestamp: number;
  pattern_name: string;
  data_type: string;
  severity: string;
  masked_value: string;
  client_ip?: string;
  path: string;
  sensorId: string;
  sensorName: string;
}

interface SensorSnapshotRecord {
  sensorId: string;
  sensorName: string;
  snapshot: {
    capturedAt: Date;
    stats: unknown;
    bandwidth: unknown;
    endpoints: unknown;
    anomalies: unknown;
  } | null;
}

export class PayloadAggregatorService {
  constructor(private readonly prisma: PrismaClient) {}

  async getPayloadStats(
    tenantId: string
  ): Promise<FleetPartialAggregateResult<PayloadSummaryResponse, PayloadSummaryResponse>> {
    const snapshots = await this.listLatestSnapshots(tenantId);
    const results = snapshots.map<FleetPartialResultEntry<PayloadSummaryResponse>>((entry) => {
      if (!entry.snapshot) {
        return this.errorResult(entry.sensorId, 'No payload snapshot available');
      }

      const stats = this.parsePayloadStats(entry.snapshot.stats);
      if (!stats) {
        return this.errorResult(entry.sensorId, 'Payload stats snapshot is malformed');
      }

      return {
        sensorId: entry.sensorId,
        status: 'ok',
        data: stats,
      };
    });

    const aggregate = results.reduce<PayloadSummaryResponse>(
      (acc, result) => {
        if (result.status !== 'ok' || !result.data) return acc;
        return {
          total_endpoints: acc.total_endpoints + result.data.total_endpoints,
          total_entities: acc.total_entities + result.data.total_entities,
          total_requests: acc.total_requests + result.data.total_requests,
          total_request_bytes: acc.total_request_bytes + result.data.total_request_bytes,
          total_response_bytes: acc.total_response_bytes + result.data.total_response_bytes,
          avg_request_size: 0,
          avg_response_size: 0,
          active_anomalies: acc.active_anomalies + result.data.active_anomalies,
        };
      },
      {
        total_endpoints: 0,
        total_entities: 0,
        total_requests: 0,
        total_request_bytes: 0,
        total_response_bytes: 0,
        avg_request_size: 0,
        avg_response_size: 0,
        active_anomalies: 0,
      }
    );

    aggregate.avg_request_size =
      aggregate.total_requests > 0 ? aggregate.total_request_bytes / aggregate.total_requests : 0;
    aggregate.avg_response_size =
      aggregate.total_requests > 0 ? aggregate.total_response_bytes / aggregate.total_requests : 0;

    return createFleetPartialAggregateResult(results, aggregate);
  }

  async getPayloadEndpoints(
    tenantId: string,
    limit?: number
  ): Promise<FleetPartialAggregateResult<EndpointPayloadSummary[], EndpointPayloadSummary[]>> {
    const snapshots = await this.listLatestSnapshots(tenantId);
    const results = snapshots.map<FleetPartialResultEntry<EndpointPayloadSummary[]>>((entry) => {
      if (!entry.snapshot) {
        return this.errorResult(entry.sensorId, 'No payload snapshot available');
      }

      const endpoints = this.parsePayloadEndpoints(entry.snapshot.endpoints);
      if (!endpoints) {
        return this.errorResult(entry.sensorId, 'Payload endpoint snapshot is unavailable');
      }

      return {
        sensorId: entry.sensorId,
        status: 'ok',
        data: endpoints,
      };
    });

    const merged = new Map<string, EndpointPayloadSummary>();
    for (const result of results) {
      if (result.status !== 'ok' || !result.data) continue;
      for (const endpoint of result.data) {
        const key = endpoint.template;
        const existing = merged.get(key);
        if (!existing) {
          merged.set(key, { ...endpoint });
          continue;
        }

        const requestCount = existing.request_count + endpoint.request_count;
        merged.set(key, {
          template: endpoint.template,
          request_count: requestCount,
          avg_request_size: weightedAverage(
            existing.avg_request_size,
            existing.request_count,
            endpoint.avg_request_size,
            endpoint.request_count
          ),
          avg_response_size: weightedAverage(
            existing.avg_response_size,
            existing.request_count,
            endpoint.avg_response_size,
            endpoint.request_count
          ),
        });
      }
    }

    const aggregate = applyOptionalLimit(
      Array.from(merged.values()).sort((a, b) => b.request_count - a.request_count),
      limit
    );

    return createFleetPartialAggregateResult(results, aggregate);
  }

  async getPayloadAnomalies(
    tenantId: string,
    limit?: number
  ): Promise<FleetPartialAggregateResult<PayloadAnomalyResponse[], PayloadAnomalyResponse[]>> {
    const snapshots = await this.listLatestSnapshots(tenantId);
    const results = snapshots.map<FleetPartialResultEntry<PayloadAnomalyResponse[]>>((entry) => {
      if (!entry.snapshot) {
        return this.errorResult(entry.sensorId, 'No payload snapshot available');
      }

      const snapshot = entry.snapshot;
      const anomalies = this.parsePayloadAnomalies(
        snapshot.anomalies,
        snapshot.capturedAt.getTime()
      );
      if (!anomalies) {
        return this.errorResult(entry.sensorId, 'Payload anomaly snapshot is unavailable');
      }

      return {
        sensorId: entry.sensorId,
        status: 'ok',
        data: anomalies,
      };
    });

    const aggregate = applyOptionalLimit(
      results
        .flatMap((result) => (result.status === 'ok' && result.data ? result.data : []))
        .sort((a, b) => b.detected_at_ms - a.detected_at_ms),
      limit
    );

    return createFleetPartialAggregateResult(results, aggregate);
  }

  async getPayloadBandwidth(
    tenantId: string
  ): Promise<FleetPartialAggregateResult<PayloadBandwidthStats, PayloadBandwidthStats>> {
    const snapshots = await this.listLatestSnapshots(tenantId);
    const results = snapshots.map<FleetPartialResultEntry<PayloadBandwidthStats>>((entry) => {
      if (!entry.snapshot) {
        return this.errorResult(entry.sensorId, 'No payload snapshot available');
      }

      const snapshot = entry.snapshot;
      const bandwidth = this.parsePayloadBandwidth(
        snapshot.bandwidth,
        snapshot.capturedAt.getTime()
      );
      if (!bandwidth) {
        return this.errorResult(entry.sensorId, 'Payload bandwidth snapshot is unavailable');
      }

      return {
        sensorId: entry.sensorId,
        status: 'ok',
        data: bandwidth,
      };
    });

    const timeline = new Map<number, PayloadBandwidthPoint>();
    const aggregate = results.reduce<PayloadBandwidthStats>(
      (acc, result) => {
        if (result.status !== 'ok' || !result.data) return acc;

        acc.totalBytes += result.data.totalBytes;
        acc.totalBytesIn += result.data.totalBytesIn;
        acc.totalBytesOut += result.data.totalBytesOut;
        acc.requestCount += result.data.requestCount;
        acc.maxRequestSize = Math.max(acc.maxRequestSize, result.data.maxRequestSize);
        acc.maxResponseSize = Math.max(acc.maxResponseSize, result.data.maxResponseSize);

        for (const point of result.data.timeline) {
          const existing = timeline.get(point.timestamp);
          if (!existing) {
            timeline.set(point.timestamp, { ...point });
            continue;
          }

          timeline.set(point.timestamp, {
            timestamp: point.timestamp,
            bytesIn: existing.bytesIn + point.bytesIn,
            bytesOut: existing.bytesOut + point.bytesOut,
            requestCount: existing.requestCount + point.requestCount,
          });
        }

        return acc;
      },
      {
        totalBytes: 0,
        totalBytesIn: 0,
        totalBytesOut: 0,
        avgBytesPerRequest: 0,
        maxRequestSize: 0,
        maxResponseSize: 0,
        requestCount: 0,
        timeline: [],
      }
    );

    aggregate.avgBytesPerRequest =
      aggregate.requestCount > 0 ? aggregate.totalBytes / aggregate.requestCount : 0;
    aggregate.timeline = Array.from(timeline.values()).sort((a, b) => a.timestamp - b.timestamp);

    return createFleetPartialAggregateResult(results, aggregate);
  }

  async getDlpStats(
    tenantId: string
  ): Promise<FleetPartialAggregateResult<DlpStatsResponse, DlpStatsResponse>> {
    const snapshots = await this.listLatestSnapshots(tenantId);
    const results = snapshots.map<FleetPartialResultEntry<DlpStatsResponse>>((entry) => {
      if (!entry.snapshot) {
        return this.errorResult(entry.sensorId, 'No payload snapshot available');
      }

      const dlp = this.parseDlp(entry.snapshot.stats);
      if (!dlp) {
        return this.errorResult(entry.sensorId, 'No DLP data in payload snapshot');
      }

      return {
        sensorId: entry.sensorId,
        status: 'ok',
        data: {
          totalScans: dlp.totalScans,
          totalMatches: dlp.totalMatches,
          patternCount: dlp.patternCount,
        },
      };
    });

    const aggregate = results.reduce<DlpStatsResponse>(
      (acc, result) => {
        if (result.status !== 'ok' || !result.data) return acc;
        return {
          totalScans: acc.totalScans + safeNumber(result.data.totalScans),
          totalMatches: acc.totalMatches + safeNumber(result.data.totalMatches),
          patternCount: Math.max(acc.patternCount, safeNumber(result.data.patternCount)),
        };
      },
      { totalScans: 0, totalMatches: 0, patternCount: 0 }
    );

    return createFleetPartialAggregateResult(results, aggregate);
  }

  async getDlpViolations(
    tenantId: string,
    limit?: number
  ): Promise<FleetPartialAggregateResult<DlpViolation[], DlpViolation[]>> {
    const snapshots = await this.listLatestSnapshots(tenantId);
    const results = snapshots.map<FleetPartialResultEntry<DlpViolation[]>>((entry) => {
      if (!entry.snapshot) {
        return this.errorResult(entry.sensorId, 'No payload snapshot available');
      }

      const snapshot = entry.snapshot;
      const dlp = this.parseDlp(snapshot.stats);
      if (!dlp) {
        return this.errorResult(entry.sensorId, 'No DLP data in payload snapshot');
      }

      const rawViolations = Array.isArray(dlp?.violations) ? dlp.violations : [];
      const violations = rawViolations
        .map((value) =>
          this.parseDlpViolation(
            value,
            entry.sensorId,
            entry.sensorName,
            snapshot.capturedAt.getTime()
          )
        )
        .filter((value): value is DlpViolation => value !== null);

      return {
        sensorId: entry.sensorId,
        status: 'ok',
        data: violations,
      };
    });

    const aggregate = applyOptionalLimit(
      results
        .flatMap((result) => (result.status === 'ok' && result.data ? result.data : []))
        .sort((a, b) => b.timestamp - a.timestamp),
      limit
    );

    return createFleetPartialAggregateResult(results, aggregate);
  }

  private async listLatestSnapshots(tenantId: string): Promise<SensorSnapshotRecord[]> {
    const [sensors, snapshots] = await Promise.all([
      this.prisma.sensor.findMany({
        where: { tenantId },
        select: { id: true, name: true },
      }),
      this.prisma.sensorPayloadSnapshot.findMany({
        where: { tenantId },
        distinct: ['sensorId'],
        orderBy: [{ sensorId: 'asc' }, { capturedAt: 'desc' }],
        select: {
          sensorId: true,
          capturedAt: true,
          stats: true,
          bandwidth: true,
          endpoints: true,
          anomalies: true,
        },
      }),
    ]);

    const snapshotBySensor = new Map(snapshots.map((snapshot) => [snapshot.sensorId, snapshot]));
    return sensors.map((sensor) => ({
      sensorId: sensor.id,
      sensorName: sensor.name ?? sensor.id,
      snapshot: snapshotBySensor.get(sensor.id) ?? null,
    }));
  }

  private parsePayloadStats(value: unknown): PayloadSummaryResponse | null {
    const stats = asRecord(value);
    if (!stats) return null;

    const totalEndpoints = requiredNumber(stats.total_endpoints);
    const totalEntities = requiredNumber(stats.total_entities);
    const totalRequests = requiredNumber(stats.total_requests);
    const totalRequestBytes = requiredNumber(stats.total_request_bytes);
    const totalResponseBytes = requiredNumber(stats.total_response_bytes);
    const avgRequestSize = requiredNumber(stats.avg_request_size);
    const avgResponseSize = requiredNumber(stats.avg_response_size);
    const activeAnomalies = requiredNumber(stats.active_anomalies);

    if (
      totalEndpoints === null ||
      totalEntities === null ||
      totalRequests === null ||
      totalRequestBytes === null ||
      totalResponseBytes === null ||
      avgRequestSize === null ||
      avgResponseSize === null ||
      activeAnomalies === null
    ) {
      return null;
    }

    return {
      total_endpoints: totalEndpoints,
      total_entities: totalEntities,
      total_requests: totalRequests,
      total_request_bytes: totalRequestBytes,
      total_response_bytes: totalResponseBytes,
      avg_request_size: avgRequestSize,
      avg_response_size: avgResponseSize,
      active_anomalies: activeAnomalies,
    };
  }

  private parsePayloadEndpoints(value: unknown): EndpointPayloadSummary[] | null {
    if (!Array.isArray(value)) return null;

    const parsed = value.map((entry) => {
      const record = asRecord(entry);
      if (!record) return null;

      const template = typeof record.template === 'string' ? record.template : '';
      const requestCount = requiredNumber(record.request_count);
      const avgRequestSize = requiredNumber(record.avg_request_size);
      const avgResponseSize = requiredNumber(record.avg_response_size);

      if (!template || requestCount === null || avgRequestSize === null || avgResponseSize === null) {
        return null;
      }

      return {
        template,
        request_count: requestCount,
        avg_request_size: avgRequestSize,
        avg_response_size: avgResponseSize,
      };
    });

    const valid = parsed.filter(
      (entry): entry is EndpointPayloadSummary => entry !== null
    );
    return valid.length > 0 ? valid : null;
  }

  private parsePayloadAnomalies(
    value: unknown,
    fallbackTimestamp: number
  ): PayloadAnomalyResponse[] | null {
    if (!Array.isArray(value)) return null;

    return value
      .map((entry) => asRecord(entry))
      .filter((entry): entry is Record<string, unknown> => entry !== null)
      .map((entry) => ({
        anomaly_type: String(entry.anomaly_type ?? 'unknown'),
        severity: String(entry.severity ?? 'low'),
        risk_applied:
          entry.risk_applied === undefined || entry.risk_applied === null
            ? null
            : safeNumber(entry.risk_applied),
        template: String(entry.template ?? ''),
        entity_id: String(entry.entity_id ?? ''),
        detected_at_ms: safeNumber(entry.detected_at_ms, fallbackTimestamp),
        description: String(entry.description ?? ''),
      }));
  }

  private parsePayloadBandwidth(
    value: unknown,
    fallbackTimestamp: number
  ): PayloadBandwidthStats | null {
    const bandwidth = asRecord(value);
    if (!bandwidth) return null;

    const timeline = Array.isArray(bandwidth.timeline)
      ? bandwidth.timeline
          .map((entry) => asRecord(entry))
          .filter((entry): entry is Record<string, unknown> => entry !== null)
          .map((entry) => ({
            timestamp: safeNumber(entry.timestamp, fallbackTimestamp),
            bytesIn: safeNumber(entry.bytesIn),
            bytesOut: safeNumber(entry.bytesOut),
            requestCount: safeNumber(entry.requestCount),
          }))
      : [];

    return {
      totalBytes: safeNumber(bandwidth.totalBytes),
      totalBytesIn: safeNumber(bandwidth.totalBytesIn),
      totalBytesOut: safeNumber(bandwidth.totalBytesOut),
      avgBytesPerRequest: safeNumber(bandwidth.avgBytesPerRequest),
      maxRequestSize: safeNumber(bandwidth.maxRequestSize),
      maxResponseSize: safeNumber(bandwidth.maxResponseSize),
      requestCount: safeNumber(bandwidth.requestCount),
      timeline,
    };
  }

  private parseDlp(
    value: unknown
  ): ({ totalScans: number; totalMatches: number; patternCount: number; violations: unknown[] }) | null {
    const stats = asRecord(value);
    if (!stats) return null;

    const dlp = asRecord(stats.dlp);
    if (!dlp) return null;

    const totalScans = requiredNumber(dlp.totalScans);
    const totalMatches = requiredNumber(dlp.totalMatches);
    const patternCount = requiredNumber(dlp.patternCount);
    if (totalScans === null || totalMatches === null || patternCount === null) {
      return null;
    }

    return {
      totalScans,
      totalMatches,
      patternCount,
      violations: Array.isArray(dlp.violations) ? dlp.violations : [],
    };
  }

  private parseDlpViolation(
    value: unknown,
    sensorId: string,
    sensorName: string,
    fallbackTimestamp: number
  ): DlpViolation | null {
    const violation = asRecord(value);
    if (!violation) return null;

    return {
      timestamp: safeNumber(violation.timestamp, fallbackTimestamp),
      pattern_name: String(violation.pattern_name ?? 'Unknown'),
      data_type: String(violation.data_type ?? 'unknown'),
      severity: String(violation.severity ?? 'low'),
      masked_value: String(violation.masked_value ?? '********'),
      client_ip:
        violation.client_ip === undefined || violation.client_ip === null
          ? undefined
          : String(violation.client_ip),
      path: String(violation.path ?? '/'),
      sensorId,
      sensorName,
    };
  }

  private errorResult<T>(sensorId: string, error: string): FleetPartialResultEntry<T> {
    return {
      sensorId,
      status: 'error',
      error,
    };
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function safeNumber(value: unknown, fallback = 0): number {
  const parsed = parseNumericValue(value);
  return parsed ?? fallback;
}

function requiredNumber(value: unknown): number | null {
  return parseNumericValue(value);
}

function parseNumericValue(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const number = Number(trimmed);
    return Number.isFinite(number) ? number : null;
  }

  return null;
}

function weightedAverage(
  leftValue: number,
  leftWeight: number,
  rightValue: number,
  rightWeight: number
): number {
  const totalWeight = leftWeight + rightWeight;
  if (totalWeight <= 0) return 0;
  return (leftValue * leftWeight + rightValue * rightWeight) / totalWeight;
}

function applyOptionalLimit<T>(values: T[], limit?: number): T[] {
  return limit !== undefined ? values.slice(0, limit) : values;
}
