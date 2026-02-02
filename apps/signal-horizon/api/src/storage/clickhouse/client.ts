/**
 * ClickHouse Client Service
 * Time-series storage for historical threat hunting
 */

import { createClient, ClickHouseClient } from '@clickhouse/client';
import type { Logger } from 'pino';

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
  /** Query timeout in seconds (default: 30) */
  queryTimeoutSec?: number;
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
  action: 'added' | 'removed' | 'expired';
  block_type: string;
  indicator: string;
  source: string;
  reason: string;
  campaign_id: string;
  expires_at: string | null;
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
  private maxRowsLimit: number;

  constructor(config: ClickHouseConfig, logger: Logger, enabled = true) {
    this.logger = logger.child({ service: 'clickhouse' });
    this.enabled = enabled;
    this.queryTimeoutSec = config.queryTimeoutSec ?? 30;
    this.maxRowsLimit = config.maxRowsLimit ?? 100000;

    if (enabled) {
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
          wait_for_async_insert: 0,
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
          maxRowsLimit: this.maxRowsLimit,
        },
        'ClickHouse client created'
      );
    } else {
      this.logger.info('ClickHouse disabled (demo mode)');
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
    } catch (error) {
      this.logger.error({ error, count: signals.length }, 'Failed to insert signal events');
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
    } catch (error) {
      this.logger.error(
        { error, campaignId: event.campaign_id },
        'Failed to insert campaign event'
      );
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
    } catch (error) {
      this.logger.error({ error }, 'Failed to insert blocklist event');
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
    } catch (error) {
      this.logger.error({ error, count: events.length }, 'Failed to insert blocklist events');
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
    if (!this.enabled || !this.client) {
      throw new Error('ClickHouse is not enabled');
    }

    try {
      const resultSet = await this.client.query({
        query: sql,
        format: 'JSONEachRow',
      });
      const rows = await resultSet.json<T>();
      return rows;
    } catch (error) {
      this.logger.error({ error, sql: sql.substring(0, 100) }, 'Query failed');
      throw error;
    }
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
    if (!this.enabled || !this.client) {
      throw new Error('ClickHouse is not enabled');
    }

    try {
      const resultSet = await this.client.query({
        query: sql,
        query_params: params,
        format: 'JSONEachRow',
      });
      const rows = await resultSet.json<T>();
      return rows;
    } catch (error) {
      this.logger.error({ error, sql: sql.substring(0, 100) }, 'Parameterized query failed');
      throw error;
    }
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
    if (!this.enabled || !this.client) {
      throw new Error('ClickHouse is not enabled');
    }

    try {
      const resultSet = await this.client.query({
        query: sql,
        format: 'JSONEachRow',
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
