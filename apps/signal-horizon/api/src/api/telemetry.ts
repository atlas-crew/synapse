/**
 * Telemetry ingestion routes
 * Accepts batched and single-event payloads from synapse-pingora.
 */

import { Router, type Request, type Response } from 'express';
import type { Logger } from 'pino';
import type { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { requireTelemetryJwt } from './middleware/telemetry-jwt.js';
import type { INonceStore } from '../middleware/replay-protection.js';
import type {
  ClickHouseRetryBuffer,
  ClickHouseService,
  HttpTransactionRow,
  LogEntryRow,
  SignalEventRow,
} from '../storage/clickhouse/index.js';

// ======================== Validation Schemas (P0-SEC-002) ========================

const TelemetryEventSchema = z.object({
  event_type: z.string().max(100).optional(),
  timestamp_ms: z.number().optional(),
  instance_id: z.string().max(255).optional(),
  data: z.record(z.unknown()).optional(),
  event: z.record(z.unknown()).optional(),
  // Apparatus fields
  sensorId: z.string().max(255).optional(),
  timestamp: z.union([z.string().max(100), z.number()]).optional(),
  actor: z.object({
    ip: z.string().max(50),
    fingerprint: z.string().max(255).optional(),
  }).optional(),
  signal: z.object({
    type: z.string().max(100),
    severity: z.string().max(20),
    details: z.record(z.unknown()).optional(),
  }).optional(),
  request: z.record(z.unknown()).optional(),
  version: z.string().max(50).optional(),
}).passthrough();

const TelemetryBatchSchema = z.object({
  batch_id: z.string().max(255).optional(),
  batchId: z.string().max(255).optional(),
  timestamp_ms: z.number().optional(),
  created_at_ms: z.number().optional(),
  events: z.array(TelemetryEventSchema).max(5000), // Max 5000 events per batch
});

const TelemetrySingleSchema = TelemetryEventSchema.superRefine((value, ctx) => {
  if (Object.prototype.hasOwnProperty.call(value, 'events')) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'events not allowed in single event payload',
      path: ['events'],
    });
  }
});

const TelemetryPayloadSchema = z.union([TelemetryBatchSchema, TelemetrySingleSchema]);

export interface TelemetryRouterOptions {
  clickhouse?: ClickHouseService | null;
  retryBuffer?: ClickHouseRetryBuffer | null;
  idempotencyStore?: INonceStore | null;
  prisma?: PrismaClient;
}

type TelemetryEventEntry = z.infer<typeof TelemetryEventSchema>;

interface ParsedTelemetry {
  rows: HttpTransactionRow[];
  logRows: LogEntryRow[];
  signalRows: SignalEventRow[];
  received: number;
  ignored: number;
}

const DEFAULT_SITE = '_default';

function normalizeEventType(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const raw = value.trim();
  if (raw.length === 0) return undefined;

  // Support both snake_case (`request_processed`) and legacy-ish CamelCase (`RequestProcessed`).
  const snake = raw.includes('_')
    ? raw
    : raw
        .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
        .replace(/([A-Z])([A-Z][a-z])/g, '$1_$2');

  return snake.toLowerCase();
}

/**
 * Normalizes a value to a finite number.
 * Handles both numeric and string inputs from various sensor versions. (labs-mmft.26)
 * 
 * @param value - The value to normalize
 * @param fallback - Fallback value if normalization fails
 */
function normalizeNumber(value: unknown, fallback: number): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}

/**
 * Normalizes a value to a string, ensuring it is non-empty and within length limits.
 */
function normalizeString(value: unknown, fallback: string, maxLength: number = 2048): string {
  if (typeof value === 'string' && value.trim().length > 0) {
    return value.trim().slice(0, maxLength);
  }
  return fallback;
}

/**
 * Normalizes an optional string value with length limits.
 */
function normalizeOptionalString(value: unknown, maxLength: number = 2048): string | null {
  if (typeof value === 'string' && value.trim().length > 0) {
    return value.trim().slice(0, maxLength);
  }
  return null;
}

const REQUEST_ID_MAX_LEN = 128;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9._-]+$/;

function normalizeOptionalRequestId(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > REQUEST_ID_MAX_LEN) return null;
  if (trimmed.includes('\r') || trimmed.includes('\n')) return null;
  if (!REQUEST_ID_PATTERN.test(trimmed)) return null;
  return trimmed;
}

function safeJsonStringify(value: unknown, maxLen: number): string | null {
  try {
    const str = JSON.stringify(value);
    if (typeof str !== 'string') return null;
    if (str.length <= maxLen) return str;
    return str.slice(0, maxLen);
  } catch {
    return null;
  }
}

/**
 * Normalizes an optional numeric value.
 * Useful for fields that can be null in the database.
 */
function normalizeOptionalNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

  function normalizeEventPayload(entry: TelemetryEventEntry): Record<string, unknown> | null {
    if (entry && typeof entry === 'object') {
      if (entry.event && typeof entry.event === 'object') {
        return entry.event as Record<string, unknown>;
      }
      return entry as Record<string, unknown>;
    }
    return null;
  }
function extractTelemetryEntries(payload: unknown): TelemetryEventEntry[] {
  if (!payload || typeof payload !== 'object') return [];

  const body = payload as Record<string, unknown>;

  if (Array.isArray(body.events)) {
    return body.events.filter((event): event is TelemetryEventEntry => typeof event === 'object' && event !== null);
  }

  if ('event_type' in body || 'event' in body) {
    return [body as TelemetryEventEntry];
  }

  if ('sensorId' in body || 'sensor_id' in body) {
    return [body as TelemetryEventEntry];
  }

  return [];
}

function parseTelemetryPayload(
  payload: unknown,
  tenantId: string,
  defaultSensorId: string,
  log: Logger,
  requestId: string | null = null
): ParsedTelemetry {
  const entries = extractTelemetryEntries(payload);
  const rows: HttpTransactionRow[] = [];
  const logRows: LogEntryRow[] = [];
  const signalRows: SignalEventRow[] = [];

  for (const entry of entries) {
    const eventPayload = normalizeEventPayload(entry);
    if (!eventPayload) continue;

    const eventType = normalizeEventType(eventPayload.event_type);

    const data = (eventPayload.data && typeof eventPayload.data === 'object')
      ? (eventPayload.data as Record<string, unknown>)
      : eventPayload;

    const eventRequestId = normalizeOptionalRequestId(
      (data.request_id ?? data.requestId) as unknown
    );
    const effectiveRequestId = eventRequestId ?? requestId ?? null;

    if (eventType === 'request_processed') {
      const timestampMs = normalizeNumber(
        entry.timestamp_ms ?? data.timestamp_ms,
        Date.now()
      );

      const providedInstanceId = normalizeOptionalString(entry.instance_id ?? data.instance_id);
      if (providedInstanceId && providedInstanceId !== defaultSensorId) {
        log.warn(
          { providedInstanceId, sensorId: defaultSensorId },
          'Telemetry instance_id does not match token sensorId'
        );
      }
      const instanceId = defaultSensorId;

      rows.push({
        timestamp: new Date(timestampMs).toISOString(),
        tenant_id: tenantId,
        sensor_id: instanceId,
        request_id: effectiveRequestId, // Pass correlation ID (prefer per-event request_id)
        site: normalizeString(data.site, DEFAULT_SITE),
        method: normalizeString(data.method, 'UNKNOWN'),
        path: normalizeString(data.path, '/'),
        status_code: Math.max(0, Math.floor(normalizeNumber(data.status_code ?? data.status, 0))),
        latency_ms: Math.max(0, Math.floor(normalizeNumber(data.latency_ms, 0))),
        waf_action: normalizeOptionalString(data.waf_action),
      });
      continue;
    }

    if (eventType === 'waf_block') {
      const timestampMs = normalizeNumber(
        entry.timestamp_ms ?? data.timestamp_ms,
        Date.now()
      );

      const providedInstanceId = normalizeOptionalString(entry.instance_id ?? data.instance_id);
      if (providedInstanceId && providedInstanceId !== defaultSensorId) {
        log.warn(
          { providedInstanceId, sensorId: defaultSensorId },
          'Telemetry instance_id does not match token sensorId'
        );
      }
      const instanceId = defaultSensorId;

      const severityRaw = normalizeString(data.severity, 'LOW', 32);
      const severity = severityRaw.toUpperCase();

      signalRows.push({
        timestamp: new Date(timestampMs).toISOString(),
        tenant_id: tenantId,
        sensor_id: instanceId,
        request_id: effectiveRequestId,
        signal_type: 'WAF_BLOCK',
        source_ip: normalizeString(data.client_ip ?? data.clientIp, '0.0.0.0', 50),
        fingerprint: '',
        anon_fingerprint: '',
        severity,
        confidence: 1.0,
        event_count: 1,
        metadata: JSON.stringify({
          rule_id: normalizeOptionalString(data.rule_id ?? data.ruleId, 256),
          site: normalizeOptionalString(data.site, 255),
          path: normalizeOptionalString(data.path, 2048),
          waf_action: 'block',
        }),
      });
      continue;
    }

    if (eventType === 'rate_limit_hit') {
      const timestampMs = normalizeNumber(
        entry.timestamp_ms ?? data.timestamp_ms,
        Date.now()
      );

      const providedInstanceId = normalizeOptionalString(entry.instance_id ?? data.instance_id);
      if (providedInstanceId && providedInstanceId !== defaultSensorId) {
        log.warn(
          { providedInstanceId, sensorId: defaultSensorId },
          'Telemetry instance_id does not match token sensorId'
        );
      }
      const instanceId = defaultSensorId;

      signalRows.push({
        timestamp: new Date(timestampMs).toISOString(),
        tenant_id: tenantId,
        sensor_id: instanceId,
        request_id: effectiveRequestId,
        signal_type: 'RATE_LIMIT_HIT',
        source_ip: normalizeString(data.client_ip ?? data.clientIp, '0.0.0.0', 50),
        fingerprint: '',
        anon_fingerprint: '',
        severity: 'MEDIUM',
        confidence: 1.0,
        event_count: 1,
        metadata: JSON.stringify({
          site: normalizeOptionalString(data.site, 255),
          limit: normalizeOptionalNumber(data.limit),
          window_secs: normalizeOptionalNumber(data.window_secs ?? data.windowSecs),
        }),
      });
      continue;
    }

    if (eventType === 'config_reload') {
      const timestampMs = normalizeNumber(
        entry.timestamp_ms ?? data.timestamp_ms,
        Date.now()
      );

      const providedInstanceId = normalizeOptionalString(entry.instance_id ?? data.instance_id);
      if (providedInstanceId && providedInstanceId !== defaultSensorId) {
        log.warn(
          { providedInstanceId, sensorId: defaultSensorId },
          'Telemetry instance_id does not match token sensorId'
        );
      }
      const instanceId = defaultSensorId;

      const logId = normalizeString(
        data.id ?? data.log_id,
        `config-reload-${instanceId}-${timestampMs}`
      );
      const success = Boolean(data.success);

      logRows.push({
        timestamp: new Date(timestampMs).toISOString(),
        tenant_id: tenantId,
        sensor_id: instanceId,
        request_id: effectiveRequestId,
        log_id: logId,
        source: 'system',
        level: success ? 'info' : 'error',
        message: 'config_reload',
        fields: JSON.stringify({
          sites_loaded: normalizeOptionalNumber(data.sites_loaded ?? data.sitesLoaded),
          duration_ms: normalizeOptionalNumber(data.duration_ms ?? data.durationMs),
          success,
          error: normalizeOptionalString(data.error, 2048),
          site: normalizeOptionalString(data.site, 255),
        }),
        method: null,
        path: null,
        status_code: null,
        latency_ms: null,
        client_ip: null,
        rule_id: null,
      });
      continue;
    }

    if (eventType === 'service_health') {
      const timestampMs = normalizeNumber(
        entry.timestamp_ms ?? data.timestamp_ms,
        Date.now()
      );

      const providedInstanceId = normalizeOptionalString(entry.instance_id ?? data.instance_id);
      if (providedInstanceId && providedInstanceId !== defaultSensorId) {
        log.warn(
          { providedInstanceId, sensorId: defaultSensorId },
          'Telemetry instance_id does not match token sensorId'
        );
      }
      const instanceId = defaultSensorId;

      const logId = normalizeString(
        data.id ?? data.log_id,
        `service-health-${instanceId}-${timestampMs}`
      );

      logRows.push({
        timestamp: new Date(timestampMs).toISOString(),
        tenant_id: tenantId,
        sensor_id: instanceId,
        request_id: effectiveRequestId,
        log_id: logId,
        source: 'system',
        level: 'info',
        message: 'service_health',
        fields: JSON.stringify({
          uptime_secs: normalizeOptionalNumber(data.uptime_secs ?? data.uptimeSecs),
          memory_mb: normalizeOptionalNumber(data.memory_mb ?? data.memoryMb),
          active_connections: normalizeOptionalNumber(data.active_connections ?? data.activeConnections),
          requests_per_sec: normalizeOptionalNumber(data.requests_per_sec ?? data.requestsPerSec),
        }),
        method: null,
        path: null,
        status_code: null,
        latency_ms: null,
        client_ip: null,
        rule_id: null,
      });
      continue;
    }

    if (eventType === 'auth_coverage' || eventType === 'campaign_report') {
      const timestampMs = normalizeNumber(
        entry.timestamp_ms ?? data.timestamp_ms,
        Date.now()
      );

      const providedInstanceId = normalizeOptionalString(entry.instance_id ?? data.instance_id);
      if (providedInstanceId && providedInstanceId !== defaultSensorId) {
        log.warn(
          { providedInstanceId, sensorId: defaultSensorId },
          'Telemetry instance_id does not match token sensorId'
        );
      }
      const instanceId = defaultSensorId;

      const logId = normalizeString(
        data.id ?? data.log_id,
        `${eventType}-${instanceId}-${timestampMs}`
      );

      logRows.push({
        timestamp: new Date(timestampMs).toISOString(),
        tenant_id: tenantId,
        sensor_id: instanceId,
        request_id: effectiveRequestId,
        log_id: logId,
        source: 'system',
        level: 'info',
        message: eventType,
        fields: safeJsonStringify(data, 10000),
        method: null,
        path: null,
        status_code: null,
        latency_ms: null,
        client_ip: null,
        rule_id: null,
      });
      continue;
    }

    if (eventType === 'log_entry') {
      const timestampMs = normalizeNumber(
        data.log_timestamp_ms ?? entry.timestamp_ms ?? data.timestamp_ms,
        Date.now()
      );

      const providedInstanceId = normalizeOptionalString(entry.instance_id ?? data.instance_id);
      if (providedInstanceId && providedInstanceId !== defaultSensorId) {
        log.warn(
          { providedInstanceId, sensorId: defaultSensorId },
          'Telemetry instance_id does not match token sensorId'
        );
      }
      const instanceId = defaultSensorId;

      const fieldsValue = data.fields;
      let fields: string | null = null;
      if (typeof fieldsValue === 'string') {
        fields = fieldsValue;
      } else if (fieldsValue && typeof fieldsValue === 'object') {
        try {
          fields = JSON.stringify(fieldsValue);
        } catch {
          fields = null;
        }
      }

      const statusCode = normalizeOptionalNumber(data.status_code ?? data.statusCode);
      const latencyMs = normalizeOptionalNumber(data.latency_ms ?? data.latencyMs);

      const logId = normalizeString(
        data.id ?? data.log_id,
        `log-${instanceId}-${timestampMs}`
      );

      logRows.push({
        timestamp: new Date(timestampMs).toISOString(),
        tenant_id: tenantId,
        sensor_id: instanceId,
        request_id: effectiveRequestId, // Pass correlation ID (prefer per-event request_id)
        log_id: logId,
        source: normalizeString(data.source, 'system'),
        level: normalizeString(data.level, 'info'),
        message: normalizeString(data.message, ''),
        fields,
        method: normalizeOptionalString(data.method),
        path: normalizeOptionalString(data.path),
        status_code: statusCode === null ? null : Math.max(0, Math.floor(statusCode)),
        latency_ms: latencyMs === null ? null : Math.max(0, latencyMs),
        client_ip: normalizeOptionalString(data.client_ip ?? data.clientIp),
        rule_id: normalizeOptionalString(data.rule_id ?? data.ruleId),
      });
      continue;
    }

    // Handle external threat signals (Apparatus/Cutlass format) (labs-gxge)
    if (!eventType && entry.signal && typeof entry.signal === 'object') {
      const signal = entry.signal;
      const timestampMs = normalizeNumber(
        entry.timestamp_ms ?? (typeof entry.timestamp === 'number' ? entry.timestamp : (typeof entry.timestamp === 'string' ? Date.parse(entry.timestamp) : Date.now())),
        Date.now()
      );

      const providedSensorId = normalizeOptionalString(entry.sensorId ?? entry.sensor_id);
      if (providedSensorId && providedSensorId !== defaultSensorId) {
        log.warn(
          { providedSensorId, sensorId: defaultSensorId },
          'Telemetry sensorId does not match token sensorId'
        );
      }
      const instanceId = defaultSensorId;

      const signalType = normalizeString(signal.type, 'UNKNOWN');
      const severity = normalizeString(signal.severity, 'LOW');

      // 1. AUDIT LOGGING (Required for compliance)
      log.info({
        audit: true,
        timestamp: new Date(timestampMs).toISOString(),
        tenant_id: tenantId,
        sensor_id: instanceId,
        signal_type: signalType,
        severity,
        result: 'received'
      }, 'External signal submission received');

      // 2. ClickHouse persistence
      signalRows.push({
        timestamp: new Date(timestampMs).toISOString(),
        tenant_id: tenantId,
        sensor_id: instanceId,
        request_id: effectiveRequestId, // Pass correlation ID (prefer per-event request_id)
        signal_type: signalType,
        source_ip: normalizeString(entry.actor?.ip, '0.0.0.0'),
        fingerprint: normalizeString(entry.actor?.fingerprint, ''),
        anon_fingerprint: '',
        severity: severity.toUpperCase(),
        confidence: 1.0,
        event_count: 1,
        metadata: JSON.stringify({
          details: signal.details || {},
          request: entry.request || undefined,
          version: entry.version || '1.0.0'
        })
      });
    }
  }

  const processed = rows.length + logRows.length + signalRows.length;
  return {
    rows,
    logRows,
    signalRows,
    received: entries.length,
    ignored: Math.max(0, entries.length - processed),
  };
}

export function createTelemetryRouter(
  logger: Logger,
  options: TelemetryRouterOptions = {}
): Router {
  const router = Router();
  const log = logger.child({ route: 'telemetry' });

      const handleTelemetry = async (req: Request, res: Response): Promise<void> => {
        if (!req.is('application/json')) {
          res.status(415).json({ error: 'content_type_required' });
          return;
        }
  
        if (!options.clickhouse || !options.clickhouse.isEnabled()) {
          res.status(503).json({ error: 'clickhouse_disabled' });
          return;
        }
  
        const authContext = await requireTelemetryJwt(req, res, options.prisma);
        if (!authContext) {
          return;
        }
      // Validate payload schema (P0-SEC-002)
    const result = TelemetryPayloadSchema.safeParse(req.body);
          if (!result.success) {
            log.warn({ errors: result.error.issues, tenantId: authContext.tenantId }, 'Telemetry payload validation failed');
            res.status(400).json({ 
              error: 'validation_failed', 
              details: result.error.issues.map(i => ({ path: i.path, message: i.message }))
            });
            return;
          }
      const { tenantId, sensorId } = authContext;
    const requestId = typeof req.id === 'string' ? req.id : null; // Use requestId from middleware (P1-OBSERVABILITY-001)

    // Check for idempotency if batch_id is present (labs-mmft.14)
    const body = result.data as Record<string, unknown>;
    const batchId = normalizeOptionalString(body.batch_id || body.batchId);
    if (batchId && options.idempotencyStore) {
      const timestamp = normalizeNumber(body.timestamp_ms || body.created_at_ms, Date.now());
      const isNew = await options.idempotencyStore.checkAndAdd(batchId, timestamp, {
        clientIp: req.ip,
        path: req.path,
        tenantId, // Ensure tenant-scoped deduplication
      });

              if (!isNew) {

                log.info({ batchId, tenantId, sensorId }, 'Ignoring duplicate telemetry batch');

                res.status(202).json({

                  received: 0,

                  inserted: 0,

                  ignored: 0,

                  duplicate: true,

                });

                return;

              }

      
    }

          const { rows, logRows, signalRows, received, ignored } = parseTelemetryPayload(
            req.body, 
            tenantId, 
            sensorId, 
            log,
            requestId
          );
    
          if (rows.length === 0 && logRows.length === 0 && signalRows.length === 0) {
            res.status(202).json({ received, inserted: 0, ignored });
            return;
          }
        try {
      let buffered = 0;
      if (options.retryBuffer) {
        if (rows.length > 0) {
          const success = await options.retryBuffer.insertHttpTransactions(rows);
          buffered += success ? 0 : rows.length;
        }
        if (logRows.length > 0) {
          const success = await options.retryBuffer.insertLogEntries(logRows);
          buffered += success ? 0 : logRows.length;
        }
        if (signalRows.length > 0) {
          const success = await options.retryBuffer.insertSignalEvents(signalRows);
          buffered += success ? 0 : signalRows.length;
        }
      } else {
        if (rows.length > 0) {
          await options.clickhouse.insertHttpTransactions(rows);
        }
        if (logRows.length > 0) {
          await options.clickhouse.insertLogEntries(logRows);
        }
        if (signalRows.length > 0) {
          await options.clickhouse.insertSignalEvents(signalRows);
        }
      }

      res.status(202).json({
        received,
        inserted: rows.length + logRows.length + signalRows.length - buffered,
        buffered,
        ignored,
      });
    } catch (error) {
      log.warn({ error, count: rows.length + logRows.length + signalRows.length }, 'Telemetry ingest failed');
      res.status(503).json({ error: 'ingest_failed' });
    }
  };

  router.post('/telemetry', handleTelemetry);
  router.post('/api/v1/telemetry', handleTelemetry);
  router.post('/_sensor/report', handleTelemetry);

  return router;
}
