/**
 * Hunt API Hook
 * Provides methods for querying historical threat data
 */

import { useState, useCallback, useRef } from 'react';
import { z } from 'zod';
import { apiFetch } from '../lib/api';

// =============================================================================
// Types
// =============================================================================

export interface HuntQuery {
  tenantId?: string;
  startTime: string;
  endTime: string;
  signalTypes?: string[];
  sourceIps?: string[];
  severities?: Array<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>;
  minConfidence?: number;
  anonFingerprint?: string;
  limit?: number;
  offset?: number;
}

export interface SignalResult {
  id: string;
  timestamp: string;
  tenantId: string;
  sensorId: string;
  signalType: string;
  sourceIp: string | null;
  anonFingerprint: string | null;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  eventCount: number;
  metadata?: any;
}

export interface HuntResult {
  signals: SignalResult[];
  total: number;
  source: 'postgres' | 'clickhouse' | 'hybrid';
  queryTimeMs: number;
}

export interface HuntStatus {
  historical: boolean;
  isFleetAdmin: boolean;
  routingThreshold: string;
  description: string;
}

export interface SavedQuery {
  id: string;
  name: string;
  description?: string;
  query: HuntQuery;
  createdBy: string;
  createdAt: string;
  lastRunAt?: string;
}

export interface HourlyStats {
  hour: string;
  tenantId: string;
  signalType: string;
  severity: string;
  signalCount: number;
  totalEvents: number;
  uniqueIps: number;
  uniqueFingerprints: number;
}

export interface TenantBaseline {
  signalType: string;
  avgHourlyCount: number;
  stddevHourlyCount: number;
  maxHourlyCount: number;
  observationCount: number;
}

export interface TenantAnomaly {
  signalType: string;
  currentCount: number;
  expectedAvg: number;
  deviation: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface LowAndSlowIpCandidate {
  sourceIp: string;
  daysSeen: number;
  maxDailySignals: number;
  totalSignals: number;
  tenantsHit: number;
}

export interface FleetFingerprintCandidate {
  anonFingerprint: string;
  tenantsHit: number;
  sensorsHit: number;
  totalSignals: number;
  firstSeen: string;
  lastSeen: string;
  signalTypes: string[];
  tenantIds: string[];
  sensorIds: string[];
}

export interface SigmaRule {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  enabled: boolean;
  sqlTemplate: string;
  whereClause: string;
  createdAt: string;
  updatedAt: string;
}

export interface SigmaLead {
  id: string;
  tenantId: string;
  ruleId: string;
  ruleName: string;
  status: 'OPEN' | 'ACKED';
  acknowledgedAt: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  matchCount: number;
  pivot: {
    requestId: string | null;
    anonFingerprint: string | null;
    sourceIp: string | null;
  };
  sample: {
    timestamp: string;
    sensorId: string;
    signalType: string;
    severity: string;
    confidence: number;
  };
}

export interface IpActivity {
  totalHits: number;
  tenantsHit: number;
  firstSeen: string | null;
  lastSeen: string | null;
  signalTypes: string[];
}

export interface CampaignTimelineEvent {
  timestamp: string;
  campaignId: string;
  eventType: 'created' | 'updated' | 'escalated' | 'resolved';
  name: string;
  status: string;
  severity: string;
  isCrossTenant: boolean;
  tenantsAffected: number;
  confidence: number;
}

export type RequestTimelineEvent =
  | {
      kind: 'http_transaction';
      timestamp: string;
      tenantId: string;
      sensorId: string;
      requestId: string;
      site: string;
      method: string;
      path: string;
      statusCode: number;
      latencyMs: number;
      wafAction: string | null;
    }
  | {
      kind: 'signal_event';
      timestamp: string;
      tenantId: string;
      sensorId: string;
      requestId: string;
      signalType: string;
      sourceIp: string;
      severity: string;
      confidence: number;
      eventCount: number;
      metadata: Record<string, unknown> | null;
    }
  | {
      kind: 'sensor_log';
      timestamp: string;
      tenantId: string;
      sensorId: string;
      requestId: string;
      logId: string;
      source: string;
      level: string;
      message: string;
      fields: Record<string, unknown> | string | null;
      method: string | null;
      path: string | null;
      statusCode: number | null;
      latencyMs: number | null;
      clientIp: string | null;
      ruleId: string | null;
    }
  | {
      kind: 'actor_event';
      timestamp: string;
      sensorId: string;
      actorId: string;
      requestId: string;
      eventType: string;
      riskScore: number;
      riskDelta: number;
      ruleId: string | null;
      ruleCategory: string | null;
      ip: string;
    }
  | {
      kind: 'session_event';
      timestamp: string;
      sensorId: string;
      sessionId: string;
      actorId: string;
      requestId: string;
      eventType: string;
      requestCount: number;
    };

export interface RecentRequest {
  requestId: string;
  lastSeenAt: string;
  sensorId: string;
  path: string;
  statusCode: number;
  wafAction: string | null;
}

// =============================================================================
// Zod Schemas for Validation
// =============================================================================

const SignalResultSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  tenantId: z.string(),
  sensorId: z.string(),
  signalType: z.string(),
  sourceIp: z.string().nullable(),
  anonFingerprint: z.string().nullable(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  confidence: z.number(),
  eventCount: z.number(),
  metadata: z.any().optional(),
});

const HuntResultSchema = z.object({
  success: z.boolean(),
  data: z.array(SignalResultSchema),
  meta: z.object({
    total: z.number(),
    source: z.enum(['postgres', 'clickhouse', 'hybrid']),
    queryTimeMs: z.number(),
    limit: z.number().optional(),
    offset: z.number().optional(),
  }),
});

const HuntStatusSchema = z.object({
  historical: z.boolean(),
  isFleetAdmin: z.boolean().optional().default(false),
  routingThreshold: z.string(),
  description: z.string(),
});

const SavedQuerySchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional(),
  query: z.object({
    startTime: z.string(),
    endTime: z.string(),
    tenantId: z.string().optional(),
    signalTypes: z.array(z.string()).optional(),
    sourceIps: z.array(z.string()).optional(),
    severities: z.array(z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])).optional(),
    minConfidence: z.number().optional(),
    limit: z.number().optional(),
    offset: z.number().optional(),
  }),
  createdBy: z.string(),
  createdAt: z.string(),
  lastRunAt: z.string().optional(),
});

const SavedQueriesResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(SavedQuerySchema),
  meta: z.object({
    count: z.number(),
  }),
});

const HourlyStatsSchema = z.object({
  hour: z.string(),
  tenantId: z.string(),
  signalType: z.string(),
  severity: z.string(),
  signalCount: z.number(),
  totalEvents: z.number(),
  uniqueIps: z.number(),
  uniqueFingerprints: z.number(),
});

const HourlyStatsResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(HourlyStatsSchema),
  meta: z.object({
    count: z.number(),
  }),
});

const IpActivityResponseSchema = z.object({
  success: z.boolean(),
  data: z.object({
    totalHits: z.number(),
    tenantsHit: z.number(),
    firstSeen: z.string().nullable(),
    lastSeen: z.string().nullable(),
    signalTypes: z.array(z.string()),
  }),
  meta: z.object({
    sourceIp: z.string(),
    lookbackDays: z.number(),
  }),
});

const CampaignTimelineEventSchema = z.object({
  timestamp: z.string(),
  campaignId: z.string(),
  eventType: z.enum(['created', 'updated', 'escalated', 'resolved']),
  name: z.string(),
  status: z.string(),
  severity: z.string(),
  isCrossTenant: z.boolean(),
  tenantsAffected: z.number(),
  confidence: z.number(),
});

const CampaignTimelineResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(CampaignTimelineEventSchema),
  meta: z.object({
    campaignId: z.string(),
    count: z.number(),
  }),
});

const SingleSavedQueryResponseSchema = z.object({
  success: z.boolean(),
  data: SavedQuerySchema,
});

const RequestTimelineEventSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('http_transaction'),
    timestamp: z.string().datetime(),
    tenantId: z.string(),
    sensorId: z.string(),
    requestId: z.string(),
    site: z.string(),
    method: z.string(),
    path: z.string(),
    statusCode: z.number(),
    latencyMs: z.number(),
    wafAction: z.string().nullable(),
  }),
  z.object({
    kind: z.literal('signal_event'),
    timestamp: z.string().datetime(),
    tenantId: z.string(),
    sensorId: z.string(),
    requestId: z.string(),
    signalType: z.string(),
    sourceIp: z.string(),
    severity: z.string(),
    confidence: z.number(),
    eventCount: z.number(),
    metadata: z.record(z.string(), z.unknown()).nullable(),
  }),
  z.object({
    kind: z.literal('sensor_log'),
    timestamp: z.string().datetime(),
    tenantId: z.string(),
    sensorId: z.string(),
    requestId: z.string(),
    logId: z.string(),
    source: z.string(),
    level: z.string(),
    message: z.string(),
    fields: z.union([z.record(z.string(), z.unknown()), z.string(), z.null()]),
    method: z.string().nullable(),
    path: z.string().nullable(),
    statusCode: z.number().nullable(),
    latencyMs: z.number().nullable(),
    clientIp: z.string().nullable(),
    ruleId: z.string().nullable(),
  }),
  z.object({
    kind: z.literal('actor_event'),
    timestamp: z.string().datetime(),
    sensorId: z.string(),
    actorId: z.string(),
    requestId: z.string(),
    eventType: z.string(),
    riskScore: z.number(),
    riskDelta: z.number(),
    ruleId: z.string().nullable(),
    ruleCategory: z.string().nullable(),
    ip: z.string(),
  }),
  z.object({
    kind: z.literal('session_event'),
    timestamp: z.string().datetime(),
    sensorId: z.string(),
    sessionId: z.string(),
    actorId: z.string(),
    requestId: z.string(),
    eventType: z.string(),
    requestCount: z.number(),
  }),
]);

const RequestTimelineResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(RequestTimelineEventSchema),
  meta: z.object({
    requestId: z.string(),
    tenantId: z.string(),
    count: z.number(),
  }),
});

const RecentRequestSchema = z.object({
  requestId: z.string(),
  lastSeenAt: z.string(),
  sensorId: z.string(),
  path: z.string(),
  statusCode: z.number(),
  wafAction: z.string().nullable(),
});

const RecentRequestsResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(RecentRequestSchema),
  meta: z.object({
    tenantId: z.string(),
    count: z.number(),
    limit: z.number(),
  }),
});

const TenantBaselineSchema = z.object({
  signalType: z.string(),
  avgHourlyCount: z.number(),
  stddevHourlyCount: z.number(),
  maxHourlyCount: z.number(),
  observationCount: z.number(),
});

const TenantBaselinesResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(TenantBaselineSchema),
  meta: z.object({
    tenantId: z.string(),
    lookbackDays: z.number(),
    count: z.number(),
    historical: z.boolean(),
  }),
});

const TenantAnomalySchema = z.object({
  signalType: z.string(),
  currentCount: z.number(),
  expectedAvg: z.number(),
  deviation: z.number(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH']),
});

const TenantAnomaliesResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(TenantAnomalySchema),
  meta: z.object({
    tenantId: z.string(),
    zScoreThreshold: z.number(),
    count: z.number(),
    historical: z.boolean(),
  }),
});

const LowAndSlowIpSchema = z.object({
  sourceIp: z.string(),
  daysSeen: z.number(),
  maxDailySignals: z.number(),
  totalSignals: z.number(),
  tenantsHit: z.number(),
});

const LowAndSlowResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(LowAndSlowIpSchema),
  meta: z.object({
    days: z.number(),
    minDistinctDays: z.number(),
    maxSignalsPerDay: z.number(),
    limit: z.number(),
    count: z.number(),
    historical: z.boolean(),
  }),
});

const FleetFingerprintCandidateSchema = z.object({
  anonFingerprint: z.string().length(64),
  tenantsHit: z.number(),
  sensorsHit: z.number(),
  totalSignals: z.number(),
  firstSeen: z.string(),
  lastSeen: z.string(),
  signalTypes: z.array(z.string()),
  tenantIds: z.array(z.string()),
  sensorIds: z.array(z.string()),
});

const FleetFingerprintIntelResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(FleetFingerprintCandidateSchema),
  meta: z.object({
    days: z.number(),
    minTenants: z.number(),
    minSensors: z.number(),
    limit: z.number(),
    count: z.number(),
    historical: z.boolean(),
  }),
});

const SigmaRuleSchema = z.object({
  id: z.string(),
  tenantId: z.string(),
  name: z.string(),
  description: z.string().optional(),
  enabled: z.boolean(),
  sqlTemplate: z.string(),
  whereClause: z.string(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

const SigmaRulesResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(SigmaRuleSchema),
  meta: z.object({
    count: z.number(),
  }),
});

const SigmaLeadSchema = z.object({
  id: z.string(),
  tenantId: z.string(),
  ruleId: z.string(),
  ruleName: z.string(),
  status: z.enum(['OPEN', 'ACKED']),
  acknowledgedAt: z.string().nullable(),
  firstSeenAt: z.string(),
  lastSeenAt: z.string(),
  matchCount: z.number(),
  pivot: z.object({
    requestId: z.string().nullable(),
    anonFingerprint: z.string().nullable(),
    sourceIp: z.string().nullable(),
  }),
  sample: z.object({
    timestamp: z.string(),
    sensorId: z.string(),
    signalType: z.string(),
    severity: z.string(),
    confidence: z.number(),
  }),
});

const SigmaLeadsResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(SigmaLeadSchema),
  meta: z.object({
    count: z.number(),
    limit: z.number(),
  }),
});

// =============================================================================
// Hook
// =============================================================================

export function useHunt() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<HuntStatus | null>(null);
  const clearError = useCallback(() => setError(null), []);
  const devAuthBootstrappedRef = useRef(false);

  // Helper for API calls
  const fetchApi = useCallback(async <T>(
    endpoint: string,
    options: { method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'; body?: unknown } = {}
  ): Promise<T> => {
    try {
      return await apiFetch<T>(endpoint, options);
    } catch (err) {
      // Dev QoL: if the UI has no API key env configured, bootstrap a cookie-based
      // api key once and retry (localhost + dev-only server route).
      if (err instanceof Error && /401/.test(err.message) && !devAuthBootstrappedRef.current) {
        devAuthBootstrappedRef.current = true;
        // This endpoint is dev-only; body is ignored.
        await apiFetch('/auth/dev/bootstrap', { method: 'POST', body: {} }).catch(() => null);
        return apiFetch<T>(endpoint, options);
      }
      throw err;
    }
  }, []);

  // Get hunt status (historical availability)
  const getStatus = useCallback(async (): Promise<HuntStatus> => {
    try {
      const data = await fetchApi<unknown>('/hunt/status');
      const result = HuntStatusSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid status response');
      }
      setStatus(result.data);
      return result.data;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get status';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  // Execute hunt query
  const queryTimeline = useCallback(async (query: HuntQuery): Promise<HuntResult> => {
    setIsLoading(true);
    setError(null);

    try {
      const data = await fetchApi<unknown>('/hunt/query', {
        method: 'POST',
        body: query,
      });

      const result = HuntResultSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid query response');
      }

      return {
        signals: result.data.data,
        total: result.data.meta.total,
        source: result.data.meta.source,
        queryTimeMs: result.data.meta.queryTimeMs,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Query failed';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [fetchApi]);

  // Get hourly statistics
  const getHourlyStats = useCallback(async (params: {
    tenantId?: string;
    startTime?: string;
    endTime?: string;
    signalTypes?: string[];
  } = {}): Promise<HourlyStats[]> => {
    setIsLoading(true);
    setError(null);

    try {
      const queryParams = new URLSearchParams();
      if (params.tenantId) queryParams.set('tenantId', params.tenantId);
      if (params.startTime) queryParams.set('startTime', params.startTime);
      if (params.endTime) queryParams.set('endTime', params.endTime);
      if (params.signalTypes) {
        params.signalTypes.forEach(t => queryParams.append('signalTypes', t));
      }

      const url = `/hunt/stats/hourly${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
      const data = await fetchApi<unknown>(url);

      const result = HourlyStatsResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid hourly stats response');
      }

      return result.data.data;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get hourly stats';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [fetchApi]);

  // Get IP activity
  const getIpActivity = useCallback(async (sourceIp: string, days: number = 30): Promise<IpActivity> => {
    setIsLoading(true);
    setError(null);

    try {
      const data = await fetchApi<unknown>('/hunt/ip-activity', {
        method: 'POST',
        body: { sourceIp, days },
      });

      const result = IpActivityResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid IP activity response');
      }

      return result.data.data;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get IP activity';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [fetchApi]);

  // Get saved queries
  const getSavedQueries = useCallback(async (): Promise<SavedQuery[]> => {
    try {
      const data = await fetchApi<unknown>('/hunt/saved-queries');
      const result = SavedQueriesResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid saved queries response');
      }
      return result.data.data;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get saved queries';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  // Save a query
  const saveQuery = useCallback(async (
    name: string,
    query: HuntQuery,
    description?: string
  ): Promise<SavedQuery> => {
    try {
      const data = await fetchApi<unknown>('/hunt/saved-queries', {
        method: 'POST',
        body: { name, query, description },
      });

      const result = z.object({
        success: z.boolean(),
        data: SavedQuerySchema,
      }).safeParse(data);

      if (!result.success) {
        throw new Error('Invalid save query response');
      }

      return result.data.data;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save query';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  // Run a saved query
  const runSavedQuery = useCallback(async (id: string): Promise<HuntResult> => {
    setIsLoading(true);
    setError(null);

    try {
      const data = await fetchApi<unknown>(`/hunt/saved-queries/${id}/run`, {
        method: 'POST',
      });

      const result = HuntResultSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid query response');
      }

      return {
        signals: result.data.data,
        total: result.data.meta.total,
        source: result.data.meta.source,
        queryTimeMs: result.data.meta.queryTimeMs,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to run saved query';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [fetchApi]);

  // Delete a saved query
  const deleteSavedQuery = useCallback(async (id: string): Promise<void> => {
    try {
      await fetchApi(`/hunt/saved-queries/${id}`, {
        method: 'DELETE',
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to delete saved query';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  // Get a single saved query by ID
  const getSavedQuery = useCallback(async (id: string): Promise<SavedQuery> => {
    try {
      const data = await fetchApi<unknown>(`/hunt/saved-queries/${encodeURIComponent(id)}`);
      const result = SingleSavedQueryResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid saved query response');
      }
      return result.data.data;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get saved query';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  // Get campaign event timeline
  const getCampaignTimeline = useCallback(async (
    campaignId: string,
    params: { startTime?: string; endTime?: string } = {}
  ): Promise<{ events: CampaignTimelineEvent[]; meta: { campaignId: string; count: number } }> => {
    setIsLoading(true);
    setError(null);

    try {
      const queryParams = new URLSearchParams();
      if (params.startTime) queryParams.set('startTime', params.startTime);
      if (params.endTime) queryParams.set('endTime', params.endTime);

      const url = `/hunt/timeline/${encodeURIComponent(campaignId)}${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
      const data = await fetchApi<unknown>(url);

      const result = CampaignTimelineResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid campaign timeline response');
      }

      return {
        events: result.data.data,
        meta: result.data.meta,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get campaign timeline';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [fetchApi]);

  const getRequestTimeline = useCallback(async (
    requestId: string,
    params: { startTime?: string; endTime?: string; limit?: number } = {}
  ): Promise<{ events: RequestTimelineEvent[]; meta: { requestId: string; tenantId: string; count: number } }> => {
    setIsLoading(true);
    setError(null);

    try {
      const queryParams = new URLSearchParams();
      if (params.startTime) queryParams.set('startTime', params.startTime);
      if (params.endTime) queryParams.set('endTime', params.endTime);
      if (params.limit !== undefined) queryParams.set('limit', String(params.limit));

      const url = `/hunt/request/${encodeURIComponent(requestId)}${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
      const data = await fetchApi<unknown>(url);

      const result = RequestTimelineResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid request timeline response');
      }

      return {
        events: result.data.data as RequestTimelineEvent[],
        meta: result.data.meta,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get request timeline';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [fetchApi]);

  const getTenantBaselines = useCallback(async (
    days: number = 30
  ): Promise<{ baselines: TenantBaseline[]; meta: { tenantId: string; lookbackDays: number; count: number; historical: boolean } }> => {
    try {
      const queryParams = new URLSearchParams();
      queryParams.set('days', String(days));
      const data = await fetchApi<unknown>(`/hunt/baselines?${queryParams.toString()}`);

      const result = TenantBaselinesResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid baselines response');
      }

      return { baselines: result.data.data, meta: result.data.meta };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get baselines';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  const getAnomalies = useCallback(async (
    zScore: number = 2.0
  ): Promise<{ anomalies: TenantAnomaly[]; meta: { tenantId: string; zScoreThreshold: number; count: number; historical: boolean } }> => {
    try {
      const queryParams = new URLSearchParams();
      queryParams.set('zScore', String(zScore));
      const data = await fetchApi<unknown>(`/hunt/anomalies?${queryParams.toString()}`);

      const result = TenantAnomaliesResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid anomalies response');
      }

      return { anomalies: result.data.data, meta: result.data.meta };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get anomalies';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  const getLowAndSlowIps = useCallback(async (params: {
    days?: number;
    minDistinctDays?: number;
    maxSignalsPerDay?: number;
    limit?: number;
  } = {}): Promise<{ candidates: LowAndSlowIpCandidate[]; meta: { days: number; minDistinctDays: number; maxSignalsPerDay: number; limit: number; count: number; historical: boolean } }> => {
    try {
      const queryParams = new URLSearchParams();
      if (params.days !== undefined) queryParams.set('days', String(params.days));
      if (params.minDistinctDays !== undefined) queryParams.set('minDistinctDays', String(params.minDistinctDays));
      if (params.maxSignalsPerDay !== undefined) queryParams.set('maxSignalsPerDay', String(params.maxSignalsPerDay));
      if (params.limit !== undefined) queryParams.set('limit', String(params.limit));

      const data = await fetchApi<unknown>(`/hunt/low-and-slow${queryParams.toString() ? '?' + queryParams.toString() : ''}`);
      const result = LowAndSlowResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid low-and-slow response');
      }

      return { candidates: result.data.data, meta: result.data.meta };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get low-and-slow candidates';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  const getFleetFingerprintIntelligence = useCallback(async (params: {
    days?: number;
    minTenants?: number;
    minSensors?: number;
    limit?: number;
  } = {}): Promise<{ candidates: FleetFingerprintCandidate[]; meta: { days: number; minTenants: number; minSensors: number; limit: number; count: number; historical: boolean } }> => {
    try {
      const queryParams = new URLSearchParams();
      if (params.days !== undefined) queryParams.set('days', String(params.days));
      if (params.minTenants !== undefined) queryParams.set('minTenants', String(params.minTenants));
      if (params.minSensors !== undefined) queryParams.set('minSensors', String(params.minSensors));
      if (params.limit !== undefined) queryParams.set('limit', String(params.limit));

      const data = await fetchApi<unknown>(`/hunt/fleet-intel/fingerprints${queryParams.toString() ? '?' + queryParams.toString() : ''}`);
      const result = FleetFingerprintIntelResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid fleet fingerprint intel response');
      }

      return { candidates: result.data.data, meta: result.data.meta };
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get fleet fingerprint intel';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  const getSigmaRules = useCallback(async (): Promise<SigmaRule[]> => {
    try {
      const data = await fetchApi<unknown>('/hunt/sigma/rules');
      const result = SigmaRulesResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid sigma rules response');
      }
      return result.data.data;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get sigma rules';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  const createSigmaRule = useCallback(async (params: {
    name: string;
    description?: string;
    sqlTemplate: string;
    enabled?: boolean;
  }): Promise<SigmaRule> => {
    try {
      const data = await fetchApi<unknown>('/hunt/sigma/rules', {
        method: 'POST',
        body: params,
      });

      const result = z.object({
        success: z.boolean(),
        data: SigmaRuleSchema,
      }).safeParse(data);

      if (!result.success) {
        throw new Error('Invalid create sigma rule response');
      }

      return result.data.data;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to create sigma rule';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  const getSigmaLeads = useCallback(async (limit: number = 200): Promise<SigmaLead[]> => {
    try {
      const queryParams = new URLSearchParams();
      queryParams.set('limit', String(limit));
      const data = await fetchApi<unknown>(`/hunt/sigma/leads?${queryParams.toString()}`);
      const result = SigmaLeadsResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid sigma leads response');
      }
      return result.data.data;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get sigma leads';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  const ackSigmaLead = useCallback(async (id: string): Promise<SigmaLead> => {
    try {
      const data = await fetchApi<unknown>(`/hunt/sigma/leads/${encodeURIComponent(id)}/ack`, {
        method: 'POST',
      });
      const result = z.object({
        success: z.boolean(),
        data: SigmaLeadSchema,
      }).safeParse(data);
      if (!result.success) {
        throw new Error('Invalid ack sigma lead response');
      }
      return result.data.data;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to ack sigma lead';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  const getRecentRequests = useCallback(async (limit: number = 25): Promise<RecentRequest[]> => {
    try {
      const queryParams = new URLSearchParams();
      queryParams.set('limit', String(limit));
      const url = `/hunt/requests/recent?${queryParams.toString()}`;
      const data = await fetchApi<unknown>(url);

      const result = RecentRequestsResponseSchema.safeParse(data);
      if (!result.success) {
        throw new Error('Invalid recent requests response');
      }

      return result.data.data as RecentRequest[];
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to get recent requests';
      setError(message);
      throw err;
    }
  }, [fetchApi]);

  return {
    // State
    isLoading,
    error,
    status,

    // Methods
    getStatus,
    queryTimeline,
    getHourlyStats,
    getIpActivity,
    getSavedQueries,
    getSavedQuery,
    saveQuery,
    runSavedQuery,
    deleteSavedQuery,
    getCampaignTimeline,
    getRequestTimeline,
    getRecentRequests,
    getTenantBaselines,
    getAnomalies,
    getLowAndSlowIps,
    getFleetFingerprintIntelligence,
    getSigmaRules,
    createSigmaRule,
    getSigmaLeads,
    ackSigmaLead,

    // Helpers
    clearError,
  };
}
