/**
 * Telemetry ingestion routes
 * Accepts batched and single-event payloads from synapse-pingora.
 */

import { Router, type Request, type Response } from 'express';
import type { Logger } from 'pino';
import { requireTelemetryJwt } from './middleware/telemetry-jwt.js';
import type {
  ClickHouseRetryBuffer,
  ClickHouseService,
  HttpTransactionRow,
  LogEntryRow,
  SignalEventRow,
} from '../storage/clickhouse/index.js';

export interface TelemetryRouterOptions {
  clickhouse?: ClickHouseService | null;
  retryBuffer?: ClickHouseRetryBuffer | null;
}

type TelemetryEventPayload = Record<string, unknown>;

type TelemetryEventEntry = {
  timestamp_ms?: number;
  instance_id?: string | null;
  event?: TelemetryEventPayload;
  // External report fields (Apparatus format)
  sensorId?: string;
  timestamp?: string | number;
  actor?: {
    ip: string;
    fingerprint?: string;
  };
  signal?: {
    type: string;
    severity: string;
    details?: Record<string, unknown>;
  };
} & TelemetryEventPayload;

interface ParsedTelemetry {
  rows: HttpTransactionRow[];
  logRows: LogEntryRow[];
  signalRows: SignalEventRow[];
  received: number;
  ignored: number;
}

const DEFAULT_SITE = '_default';

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

function normalizeString(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.trim().length > 0 ? value : fallback;
}

function normalizeOptionalString(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value : null;
}

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

function normalizeEventPayload(entry: TelemetryEventEntry): TelemetryEventPayload | null {
  if (entry && typeof entry === 'object') {
    if (entry.event && typeof entry.event === 'object') {
      return entry.event as TelemetryEventPayload;
    }
    return entry as TelemetryEventPayload;
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
  log: Logger
): ParsedTelemetry {
  const entries = extractTelemetryEntries(payload);
  const rows: HttpTransactionRow[] = [];
  const logRows: LogEntryRow[] = [];
  const signalRows: SignalEventRow[] = [];

  for (const entry of entries) {
    const eventPayload = normalizeEventPayload(entry);
    if (!eventPayload) continue;

    const eventType = typeof eventPayload.event_type === 'string'
      ? eventPayload.event_type.toLowerCase()
      : undefined;

    const data = (eventPayload.data && typeof eventPayload.data === 'object')
      ? (eventPayload.data as Record<string, unknown>)
      : eventPayload;

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
        site: normalizeString(data.site, DEFAULT_SITE),
        method: normalizeString(data.method, 'UNKNOWN'),
        path: normalizeString(data.path, '/'),
        status_code: Math.max(0, Math.floor(normalizeNumber(data.status_code ?? data.status, 0))),
        latency_ms: Math.max(0, Math.floor(normalizeNumber(data.latency_ms, 0))),
        waf_action: normalizeOptionalString(data.waf_action),
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

  const handleTelemetry = async (req: Request, res: Response) => {
    if (!req.is('application/json')) {
      return res.status(415).json({ error: 'content_type_required' });
    }

    if (!options.clickhouse || !options.clickhouse.isEnabled()) {
      return res.status(503).json({ error: 'clickhouse_disabled' });
    }

    const authContext = requireTelemetryJwt(req, res);
    if (!authContext) {
      return;
    }

    const { tenantId, sensorId } = authContext;

    const { rows, logRows, signalRows, received, ignored } = parseTelemetryPayload(req.body, tenantId, sensorId, log);

    if (rows.length === 0 && logRows.length === 0 && signalRows.length === 0) {
      return res.status(202).json({ received, inserted: 0, ignored });
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
      log.warn({ error, count: rows.length + signalRows.length }, 'Telemetry ingest failed');
      res.status(503).json({ error: 'ingest_failed' });
    }
  };

  router.post('/telemetry', handleTelemetry);
  router.post('/api/v1/telemetry', handleTelemetry);
  router.post('/_sensor/report', handleTelemetry);

  return router;
}
