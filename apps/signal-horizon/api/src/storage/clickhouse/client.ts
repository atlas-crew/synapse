/**
 * ClickHouse Client Service
 * Time-series storage for historical threat hunting
 */

import { createClient, ClickHouseClient } from '@clickhouse/client';
import type { Logger } from 'pino';
import { AsyncSemaphore } from '../../lib/async-semaphore.js';
import { metrics } from '../../services/metrics.js';

// =============================================================================
// Configuration Types
// =============================================================================

export interface ClickHouseConfig {
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  compression: boolean;
  maxOpenConnections: number;
  /** Maximum number of in-flight queries (defaults to maxOpenConnections). */
  maxInFlightQueries?: number;
  /** Maximum number of in-flight streaming queries (defaults to min(2, maxInFlightQueries)). */
  maxInFlightStreamQueries?: number;
  /** Query timeout in seconds (default: 30) */
  queryTimeoutSec?: number;
  /** Max time to wait for a query permit before failing (default: queryTimeoutSec). */
  queueTimeoutSec?: number;
  /** Maximum rows to return from a single query (default: 100000) */
  maxRowsLimit?: number;
}

// =============================================================================
// Row Types (match ClickHouse schema)
// =============================================================================

/**
 * Signal event row for signal_events table
 */
export interface SignalEventRow {
  timestamp: string; // ISO 8601
  tenant_id: string;
  sensor_id: string;
  request_id: string | null; // Correlation ID (P1-OBSERVABILITY-001)
  signal_type: string;
  source_ip: string;
  fingerprint: string;
  anon_fingerprint: string;
  severity: string;
  confidence: number;
  event_count: number;
  metadata: string; // JSON string
}

/**
 * Campaign history row for campaign_history table
 */
export interface CampaignHistoryRow {
  timestamp: string;
  campaign_id: string;
  tenant_id: string;
  request_id: string | null; // Correlation ID (P1-OBSERVABILITY-001)
  event_type: 'created' | 'updated' | 'escalated' | 'resolved';
  name: string;
  status: string;
  severity: string;
  is_cross_tenant: 0 | 1;
  tenants_affected: number;
  confidence: number;
  metadata: string; // JSON string
}

/**
 * Blocklist history row for blocklist_history table
 */
export interface BlocklistHistoryRow {
  timestamp: string;
  tenant_id: string;
  request_id: string | null; // Correlation ID (P1-OBSERVABILITY-001)
  action: 'added' | 'removed' | 'expired';
  block_type: string;
  indicator: string;
  source: string;
  reason: string;
  campaign_id: string;
  expires_at: string | null;
}

/**
 * HTTP transaction row for http_transactions table
 */
export interface HttpTransactionRow {
  timestamp: string; // ISO 8601
  tenant_id: string;
  sensor_id: string;
  request_id: string | null; // Correlation ID (P1-OBSERVABILITY-001)
  site: string;
  method: string;
  path: string;
  status_code: number;
  latency_ms: number;
  waf_action: string | null;
}

/**
 * Sensor log entry row for sensor_logs table
 */
export interface LogEntryRow {
  timestamp: string; // ISO 8601
  tenant_id: string;
  sensor_id: string;
  request_id: string | null; // Correlation ID (P1-OBSERVABILITY-001)
  log_id: string;
  source: string;
  level: string;
  message: string;
  fields: string | null;
  method: string | null;
  path: string | null;
  status_code: number | null;
  latency_ms: number | null;
  client_ip: string | null;
  rule_id: string | null;
}

// =============================================================================
// ClickHouse Service
// =============================================================================

/**
 * ClickHouse client wrapper for Signal Horizon historical data.
 * Provides typed insert methods and connection management.
 *
 * Usage:
 * ```typescript
 * const clickhouse = new ClickHouseService(config, logger);
 * await clickhouse.insertSignalEvents([...signals]);
 * await clickhouse.close();
 * ```
 */
export class ClickHouseService {
  private client: ClickHouseClient | null = null;
  private logger: Logger;
  private enabled: boolean;
  private queryTimeoutSec: number;
  private queueTimeoutMs: number;
  private maxRowsLimit: number;
  private queryLimiter: AsyncSemaphore | null = null;
  private streamLimiter: AsyncSemaphore | null = null;

  constructor(config: ClickHouseConfig, logger: Logger, enabled = true) {
    this.logger = logger.child({ service: 'clickhouse' });
    this.enabled = enabled;
    this.queryTimeoutSec = config.queryTimeoutSec ?? 30;
    this.queueTimeoutMs = ((config.queueTimeoutSec ?? this.queryTimeoutSec) * 1000);
    this.maxRowsLimit = config.maxRowsLimit ?? 100000;
    const maxInFlightQueries = config.maxInFlightQueries ?? config.maxOpenConnections;
    const maxInFlightStreamQueries = Math.max(
      1,
      Math.min(
        config.maxInFlightStreamQueries ?? Math.min(2, maxInFlightQueries),
        maxInFlightQueries
      )
    );

    if (enabled) {
      this.queryLimiter = new AsyncSemaphore(Math.max(1, maxInFlightQueries));
      this.streamLimiter = new AsyncSemaphore(maxInFlightStreamQueries);
      this.client = createClient({
        url: `http://${config.host}:${config.port}`,
        database: config.database,
        username: config.username,
        password: config.password,
        compression: {
          request: config.compression,
          response: config.compression,
        },
        max_open_connections: config.maxOpenConnections,
        request_timeout: (this.queryTimeoutSec + 5) * 1000, // HTTP timeout > query timeout
        clickhouse_settings: {
          // Async inserts for high throughput
          async_insert: 1,
          // In dev/test we want insert errors surfaced immediately (prevents silent drops).
          wait_for_async_insert: process.env.NODE_ENV === 'production' ? 0 : 1,
          // Query execution limits (prevents runaway queries)
          max_execution_time: this.queryTimeoutSec,
          max_result_rows: String(this.maxRowsLimit), // UInt64 requires string
          result_overflow_mode: 'throw',
        },
      });
      this.logger.info(
        {
          host: config.host,
          port: config.port,
          database: config.database,
          queryTimeoutSec: this.queryTimeoutSec,
          queueTimeoutMs: this.queueTimeoutMs,
          maxRowsLimit: this.maxRowsLimit,
          maxOpenConnections: config.maxOpenConnections,
          maxInFlightQueries,
          maxInFlightStreamQueries,
        },
        'ClickHouse client created'
      );
    } else {
      this.logger.info('ClickHouse disabled (demo mode)');
    }
  }

  private async acquirePermit(options: {
    limiter: AsyncSemaphore | null;
    op: string;
    queue: 'query' | 'stream';
    timeoutError: string;
    onAcquire?: () => void;
    onRelease?: () => void;
  }): Promise<(() => void) | null> {
    const { limiter, op, queue, timeoutError, onAcquire, onRelease } = options;
    if (!limiter) return null;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.queueTimeoutMs);
    const willQueue = limiter.getAvailable() <= 0;

    if (willQueue) {
      metrics.clickhouseQueryQueueDepth.inc({ op, queue });
    }

    try {
      const release = await limiter.acquire({ signal: controller.signal });
      if (willQueue) {
        metrics.clickhouseQueryQueueDepth.dec({ op, queue });
      }
      onAcquire?.();

      return () => {
        onRelease?.();
        release();
      };
    } catch (error) {
      if (willQueue) {
        metrics.clickhouseQueryQueueDepth.dec({ op, queue });
      }
      if (controller.signal.aborted) {
        throw new Error(timeoutError);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async acquireQueryPermit(op: string): Promise<(() => void) | null> {
    return this.acquirePermit({
      limiter: this.queryLimiter,
      op,
      queue: 'query',
      timeoutError: `ClickHouse query permit wait timed out after ${this.queueTimeoutMs}ms`,
      onAcquire: () => metrics.clickhouseQueriesInFlight.inc({ op }),
      onRelease: () => metrics.clickhouseQueriesInFlight.dec({ op }),
    });
  }

  private async acquireStreamPermit(op: string): Promise<(() => void) | null> {
    return this.acquirePermit({
      limiter: this.streamLimiter,
      op,
      queue: 'stream',
      timeoutError: `ClickHouse stream permit wait timed out after ${this.queueTimeoutMs}ms`,
    });
  }

  private async withQueryTelemetry<T>(
    op: string,
    fn: () => Promise<T>,
    options?: { acquireExtraPermit?: () => Promise<(() => void) | null> }
  ): Promise<T> {
    const endWaitTimer = metrics.clickhouseQueryWaitDuration.startTimer({ op });
    const releases: Array<() => void> = [];

    try {
      const release = await this.acquireQueryPermit(op);
      if (release) releases.push(release);

      if (options?.acquireExtraPermit) {
        // Deadlock avoidance: stream limiter is clamped to <= query limiter, so at least one
        // stream query holding a query permit can always acquire a stream permit and make progress.
        const extraRelease = await options.acquireExtraPermit();
        if (extraRelease) releases.push(extraRelease);
      }
    } catch (error) {
      metrics.clickhouseQueryErrors.inc({ op });
      for (const release of releases.reverse()) {
        release();
      }
      throw error;
    } finally {
      endWaitTimer();
    }

    const endExecTimer = metrics.clickhouseQueryDuration.startTimer({ op });
    try {
      return await fn();
    } catch (error) {
      metrics.clickhouseQueryErrors.inc({ op });
      throw error;
    } finally {
      for (const release of releases.reverse()) {
        release();
      }
      endExecTimer();
    }
  }

  /**
   * Check if ClickHouse is enabled
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Health check - verifies connection to ClickHouse
   */
  async ping(): Promise<boolean> {
    if (!this.enabled || !this.client) return false;

    try {
      await this.client.ping();
      this.logger.debug('ClickHouse ping successful');
      return true;
    } catch (error) {
      this.logger.error({ error }, 'ClickHouse ping failed');
      return false;
    }
  }

  /**
   * Insert signal events into signal_events table
   * Uses async insert for high throughput (fire-and-forget)
   */
  async insertSignalEvents(signals: SignalEventRow[]): Promise<void> {
    if (!this.enabled || !this.client || signals.length === 0) return;

    try {
      await this.client.insert({
        table: 'signal_events',
        values: signals,
        format: 'JSONEachRow',
      });
      this.logger.debug({ count: signals.length }, 'Inserted signal events');
      metrics.clickhouseInsertSuccess.inc({ table: 'signal_events' });
    } catch (error) {
      this.logger.error({ error, count: signals.length }, 'Failed to insert signal events');
      metrics.clickhouseInsertFailed.inc({ table: 'signal_events' });
      throw error;
    }
  }

  /**
   * Insert campaign history event
   * Called on campaign creation, updates, and resolution
   */
  async insertCampaignEvent(event: CampaignHistoryRow): Promise<void> {
    if (!this.enabled || !this.client) return;

    try {
      await this.client.insert({
        table: 'campaign_history',
        values: [event],
        format: 'JSONEachRow',
      });
      this.logger.debug(
        { campaignId: event.campaign_id, eventType: event.event_type },
        'Inserted campaign history event'
      );
      metrics.clickhouseInsertSuccess.inc({ table: 'campaign_history' });
    } catch (error) {
      this.logger.error(
        { error, campaignId: event.campaign_id },
        'Failed to insert campaign event'
      );
      metrics.clickhouseInsertFailed.inc({ table: 'campaign_history' });
      throw error;
    }
  }

  /**
   * Insert blocklist history event
   * Called when blocklist entries are added, removed, or expire
   */
  async insertBlocklistEvent(event: BlocklistHistoryRow): Promise<void> {
    if (!this.enabled || !this.client) return;

    try {
      await this.client.insert({
        table: 'blocklist_history',
        values: [event],
        format: 'JSONEachRow',
      });
      this.logger.debug(
        { action: event.action, indicator: event.indicator },
        'Inserted blocklist history event'
      );
      metrics.clickhouseInsertSuccess.inc({ table: 'blocklist_history' });
    } catch (error) {
      this.logger.error({ error }, 'Failed to insert blocklist event');
      metrics.clickhouseInsertFailed.inc({ table: 'blocklist_history' });
      throw error;
    }
  }

  /**
   * Batch insert blocklist events
   */
  async insertBlocklistEvents(events: BlocklistHistoryRow[]): Promise<void> {
    if (!this.enabled || !this.client || events.length === 0) return;

    try {
      await this.client.insert({
        table: 'blocklist_history',
        values: events,
        format: 'JSONEachRow',
      });
      this.logger.debug({ count: events.length }, 'Inserted blocklist history events');
      metrics.clickhouseInsertSuccess.inc({ table: 'blocklist_history' });
    } catch (error) {
      this.logger.error({ error, count: events.length }, 'Failed to insert blocklist events');
      metrics.clickhouseInsertFailed.inc({ table: 'blocklist_history' });
      throw error;
    }
  }

  /**
   * Insert HTTP transaction events
   * High-volume telemetry for request/response metadata
   */
  async insertHttpTransactions(events: HttpTransactionRow[]): Promise<void> {
    if (!this.enabled || !this.client || events.length === 0) return;

    try {
      await this.client.insert({
        table: 'http_transactions',
        values: events,
        format: 'JSONEachRow',
      });
      this.logger.debug({ count: events.length }, 'Inserted HTTP transaction events');
      metrics.clickhouseInsertSuccess.inc({ table: 'http_transactions' });
    } catch (error) {
      this.logger.error({ error, count: events.length }, 'Failed to insert HTTP transaction events');
      metrics.clickhouseInsertFailed.inc({ table: 'http_transactions' });
      throw error;
    }
  }

  /**
   * Insert sensor log entries
   */
  async insertLogEntries(events: LogEntryRow[]): Promise<void> {
    if (!this.enabled || !this.client || events.length === 0) return;

    try {
      await this.client.insert({
        table: 'sensor_logs',
        values: events,
        format: 'JSONEachRow',
      });
      this.logger.debug({ count: events.length }, 'Inserted sensor log entries');
      metrics.clickhouseInsertSuccess.inc({ table: 'sensor_logs' });
    } catch (error) {
      this.logger.error({ error, count: events.length }, 'Failed to insert sensor log entries');
      metrics.clickhouseInsertFailed.inc({ table: 'sensor_logs' });
      throw error;
    }
  }

  /**
   * Execute a raw query (for Hunt service)
   * For large result sets, consider using queryStream() instead.
   *
   * @deprecated Use queryWithParams() for user-controlled inputs to prevent SQL injection
   */
  async query<T>(sql: string): Promise<T[]> {
    if (!this.enabled) {
      throw new Error('ClickHouse is not enabled');
    }
    if (!this.client) {
      throw new Error('ClickHouse client is not available (closed)');
    }

    // Breadcrumb: raw SQL queries are allowed for legacy/internal use but are not safe for untrusted input.
    metrics.clickhouseRawQueriesTotal.inc();

    return this.withQueryTelemetry('query', async () => {
      const client = this.client;
      if (!client) {
        throw new Error('ClickHouse client is not available (closed)');
      }

      try {
        const resultSet = await client.query({
          query: sql,
          format: 'JSONEachRow',
          clickhouse_settings: {
            max_execution_time: this.queryTimeoutSec,
            max_result_rows: String(this.maxRowsLimit),
            result_overflow_mode: 'throw',
          },
        });
        const rows = await resultSet.json<T>();
        return rows;
      } catch (error) {
        this.logger.error({ error, sql: sql.substring(0, 100) }, 'Query failed');
        throw error;
      }
    });
  }

  /**
   * Execute a parameterized query (SQL injection safe)
   *
   * Uses ClickHouse's native parameter binding with typed placeholders:
   * - {name:String} for string parameters
   * - {name:UInt32} for unsigned integers
   * - {name:Float64} for floating point numbers
   * - {name:DateTime64(3)} for timestamps
   * - {name:Array(String)} for string arrays
   *
   * Example:
   * ```typescript
   * const sql = `SELECT * FROM events WHERE tenant_id = {tenantId:String} AND confidence >= {minConfidence:Float64}`;
   * const rows = await clickhouse.queryWithParams<EventRow>(sql, {
   *   tenantId: 'tenant-123',
   *   minConfidence: 0.8,
   * });
   * ```
   */
  async queryWithParams<T>(sql: string, params: Record<string, unknown>): Promise<T[]> {
    if (!this.enabled) {
      throw new Error('ClickHouse is not enabled');
    }
    if (!this.client) {
      throw new Error('ClickHouse client is not available (closed)');
    }

    return this.withQueryTelemetry('queryWithParams', async () => {
      const client = this.client;
      if (!client) {
        throw new Error('ClickHouse client is not available (closed)');
      }

      try {
        const resultSet = await client.query({
          query: sql,
          query_params: params,
          format: 'JSONEachRow',
          clickhouse_settings: {
            max_execution_time: this.queryTimeoutSec,
            max_result_rows: String(this.maxRowsLimit),
            result_overflow_mode: 'throw',
          },
        });
        const rows = await resultSet.json<T>();
        return rows;
      } catch (error) {
        this.logger.error({ error, sql: sql.substring(0, 100) }, 'Parameterized query failed');
        throw error;
      }
    });
  }

  /**
   * Execute a parameterized query and return a single value
   */
  async queryOneWithParams<T>(sql: string, params: Record<string, unknown>): Promise<T | null> {
    const rows = await this.queryWithParams<T>(sql, params);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Execute a raw query and return a single value
   */
  async queryOne<T>(sql: string): Promise<T | null> {
    const rows = await this.query<T>(sql);
    return rows.length > 0 ? rows[0] : null;
  }

  /**
   * Execute a query with streaming for large result sets.
   * Processes rows in batches to avoid OOM for huge result sets.
   *
   * @param sql - The SQL query to execute
   * @param batchSize - Number of rows to process at once (default: 1000)
   * @param onBatch - Callback invoked for each batch of rows
   * @returns Total number of rows processed
   */
  async queryStream<T>(
    sql: string,
    batchSize: number,
    onBatch: (rows: T[]) => Promise<void>
  ): Promise<number> {
    if (!this.enabled) {
      throw new Error('ClickHouse is not enabled');
    }
    if (!this.client) {
      throw new Error('ClickHouse client is not available (closed)');
    }

    return this.withQueryTelemetry(
      'queryStream',
      async () => {
      // NOTE: We intentionally hold a query permit for the full streaming + onBatch duration,
      // since the underlying HTTP stream keeps a ClickHouse connection open.
      // Keep onBatch fast; for heavy processing, enqueue work and return quickly.
      const client = this.client;
      if (!client) {
        throw new Error('ClickHouse client is not available (closed)');
      }

      try {
        const resultSet = await client.query({
          query: sql,
          format: 'JSONEachRow',
          clickhouse_settings: {
            max_execution_time: this.queryTimeoutSec,
            max_result_rows: String(this.maxRowsLimit),
            result_overflow_mode: 'throw',
          },
        });

        let batch: T[] = [];
        let totalRows = 0;

        // Stream rows and process in batches
        for await (const rows of resultSet.stream()) {
          // Parse each row from the stream
          for (const row of rows) {
            const parsed = row.json<T>();
            batch.push(parsed);

            if (batch.length >= batchSize) {
              await onBatch(batch);
              totalRows += batch.length;
              batch = [];
            }
          }
        }

        // Process remaining rows
        if (batch.length > 0) {
          await onBatch(batch);
          totalRows += batch.length;
        }

        this.logger.debug({ totalRows, sql: sql.substring(0, 100) }, 'Stream query completed');
        return totalRows;
      } catch (error) {
        this.logger.error({ error, sql: sql.substring(0, 100) }, 'Stream query failed');
        throw error;
      }
      },
      { acquireExtraPermit: () => this.acquireStreamPermit('queryStream') }
    );
  }

  /**
   * Get the underlying ClickHouse client for advanced operations
   */
  getClient(): ClickHouseClient | null {
    return this.client;
  }

  /**
   * Close the connection
   */
  async close(): Promise<void> {
    if (this.enabled && this.client) {
      await this.client.close();
      this.client = null;
      this.logger.info('ClickHouse client closed');
    }
  }
}
