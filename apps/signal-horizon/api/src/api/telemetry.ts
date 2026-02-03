/**
 * Telemetry ingestion routes
 * Accepts batched and single-event payloads from synapse-pingora.
 */

import { Router, type Request, type Response } from 'express';
import type { Logger } from 'pino';
import { config } from '../config.js';
import { safeCompare } from '../lib/safe-compare.js';
import type { ClickHouseRetryBuffer, ClickHouseService, HttpTransactionRow } from '../storage/clickhouse/index.js';

export interface TelemetryRouterOptions {
  clickhouse?: ClickHouseService | null;
  retryBuffer?: ClickHouseRetryBuffer | null;
}

type TelemetryEventPayload = Record<string, unknown>;

type TelemetryEventEntry = {
  timestamp_ms?: number;
  instance_id?: string | null;
  event?: TelemetryEventPayload;
} & TelemetryEventPayload;

interface ParsedTelemetry {
  rows: HttpTransactionRow[];
  received: number;
  ignored: number;
}

const DEFAULT_TENANT_ID = 'default';
const DEFAULT_SITE = '_default';

function getHeader(req: { header: (name: string) => string | undefined }, name: string): string | undefined {
  const value = req.header(name);
  return value && value.trim().length > 0 ? value.trim() : undefined;
}

function getApiKey(
  req: { header: (name: string) => string | undefined },
  apiKeyHeader: string
): string | undefined {
  const headers = [apiKeyHeader, 'X-Admin-Key'];
  for (const header of headers) {
    const headerKey = getHeader(req, header);
    if (headerKey) return headerKey;
  }

  const auth = getHeader(req, 'authorization');
  if (auth && auth.toLowerCase().startsWith('bearer ')) {
    return auth.slice(7).trim();
  }

  return undefined;
}

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
  defaultSensorId: string
): ParsedTelemetry {
  const entries = extractTelemetryEntries(payload);
  const rows: HttpTransactionRow[] = [];

  for (const entry of entries) {
    const eventPayload = normalizeEventPayload(entry);
    if (!eventPayload) continue;

    const eventType = typeof eventPayload.event_type === 'string'
      ? eventPayload.event_type.toLowerCase()
      : undefined;

    if (eventType !== 'request_processed') {
      continue;
    }

    const data = (eventPayload.data && typeof eventPayload.data === 'object')
      ? (eventPayload.data as Record<string, unknown>)
      : eventPayload;

    const timestampMs = normalizeNumber(
      entry.timestamp_ms ?? data.timestamp_ms,
      Date.now()
    );

    const instanceId = normalizeString(
      entry.instance_id ?? data.instance_id,
      defaultSensorId
    );

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
  }

  return {
    rows,
    received: entries.length,
    ignored: Math.max(0, entries.length - rows.length),
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

    if (!config.telemetry.apiKey) {
      log.error('Telemetry API key not configured; rejecting /_sensor/report');
      return res.status(503).json({ error: 'telemetry_key_missing' });
    }

    const providedKey = getApiKey(req, config.security.apiKeyHeader);
    if (!providedKey || !safeCompare(providedKey, config.telemetry.apiKey)) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    const tenantId = getHeader(req, 'x-tenant-id') ?? getHeader(req, 'x-tenant') ?? DEFAULT_TENANT_ID;
    const sensorId = getHeader(req, 'x-sensor-id') ?? 'unknown';

    const { rows, received, ignored } = parseTelemetryPayload(req.body, tenantId, sensorId);

    if (rows.length === 0) {
      return res.status(202).json({ received, inserted: 0, ignored });
    }

    try {
      let buffered = 0;
      if (options.retryBuffer) {
        const success = await options.retryBuffer.insertHttpTransactions(rows);
        buffered = success ? 0 : rows.length;
      } else {
        await options.clickhouse.insertHttpTransactions(rows);
      }

      res.status(202).json({
        received,
        inserted: rows.length - buffered,
        buffered,
        ignored,
      });
    } catch (error) {
      log.warn({ error, count: rows.length }, 'Telemetry ingest failed');
      res.status(503).json({ error: 'ingest_failed' });
    }
  };

  router.post('/telemetry', handleTelemetry);
  router.post('/_sensor/report', handleTelemetry);

  return router;
}
