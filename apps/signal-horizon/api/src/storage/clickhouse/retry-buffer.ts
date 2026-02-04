/**
 * ClickHouse Retry Buffer
 *
 * Provides reliable ingestion with automatic retries and exponential backoff.
 * Buffers failed writes and retries them in the background.
 */

import type { Logger } from 'pino';
import type {
  ClickHouseService,
  SignalEventRow,
  CampaignHistoryRow,
  BlocklistHistoryRow,
  HttpTransactionRow,
  LogEntryRow,
} from './client.js';

/** Configuration for the retry buffer */
export interface RetryBufferConfig {
  /** Maximum items to buffer (default: 10000) */
  maxBufferSize: number;
  /** Maximum retry attempts per item (default: 5) */
  maxRetries: number;
  /** Initial retry delay in ms (default: 1000) */
  initialDelayMs: number;
  /** Maximum retry delay in ms (default: 60000) */
  maxDelayMs: number;
  /** Retry interval check in ms (default: 5000) */
  retryIntervalMs: number;
  /** Batch size for retry writes (default: 100) */
  retryBatchSize: number;
}

export const DEFAULT_RETRY_CONFIG: RetryBufferConfig = {
  maxBufferSize: 10000,
  maxRetries: 5,
  initialDelayMs: 1000,
  maxDelayMs: 60000,
  retryIntervalMs: 5000,
  retryBatchSize: 100,
};

/** Types of buffered items */
type BufferItemType = 'signal' | 'campaign' | 'blocklist' | 'transaction' | 'log';

/** Buffered item with retry metadata - uses discriminated union for type safety (labs-mmft.22) */
type BufferedItem =
  | { type: 'signal'; data: SignalEventRow[]; attempts: number; nextRetryAt: number; addedAt: number }
  | { type: 'campaign'; data: CampaignHistoryRow; attempts: number; nextRetryAt: number; addedAt: number }
  | { type: 'blocklist'; data: BlocklistHistoryRow[]; attempts: number; nextRetryAt: number; addedAt: number }
  | { type: 'transaction'; data: HttpTransactionRow[]; attempts: number; nextRetryAt: number; addedAt: number }
  | { type: 'log'; data: LogEntryRow[]; attempts: number; nextRetryAt: number; addedAt: number };

/** Statistics for the retry buffer */
export interface RetryBufferStats {
  bufferedCount: number;
  totalAttempts: number;
  successfulRetries: number;
  failedRetries: number;
  droppedItems: number;
  oldestItemAge: number | null;
  isProcessing: boolean;
  bufferUtilization: number;
}

/** Interface for optional persistent storage of retry buffer (labs-mmft.8) */
export interface IRetryPersistentStore {
  save(items: BufferedItem[]): Promise<void>;
  load(): Promise<BufferedItem[]>;
}

/**
 * Reliable ClickHouse ingestion with automatic retries.
 *
 * Wraps ClickHouseService to provide:
 * - Automatic buffering of failed writes
 * - Exponential backoff retry logic
 * - Memory-bounded queue with drop-oldest eviction
 * - Statistics for monitoring
 * - Persistent storage support (labs-mmft.8)
 */
export class ClickHouseRetryBuffer {
  private clickhouse: ClickHouseService;
  private logger: Logger;
  private config: RetryBufferConfig;
  private persistentStore: IRetryPersistentStore | null = null;

  /** 
   * Internal buffer of items awaiting retry.
   * Uses discriminated union to maintain type safety across different event types.
   */
  private buffer: BufferedItem[] = [];
  private retryTimer: ReturnType<typeof setInterval> | null = null;
  private isProcessing = false;

  // Statistics
  private totalAttempts = 0;
  private successfulRetries = 0;
  private failedRetries = 0;
  private droppedItems = 0;

  constructor(
    clickhouse: ClickHouseService,
    logger: Logger,
    config: Partial<RetryBufferConfig> = {},
    persistentStore: IRetryPersistentStore | null = null
  ) {
    this.clickhouse = clickhouse;
    this.logger = logger.child({ component: 'clickhouse-retry-buffer' });
    this.config = { ...DEFAULT_RETRY_CONFIG, ...config };
    this.persistentStore = persistentStore;
  }

  /**
   * Start the background retry processor
   */
  async start(): Promise<void> {
    if (this.retryTimer) return;

    // Load from persistent store if available (labs-mmft.8)
    if (this.persistentStore) {
      try {
        const loadedItems = await this.persistentStore.load();
        if (loadedItems.length > 0) {
          this.logger.info({ count: loadedItems.length }, 'Loaded telemetry items from persistent store');
          this.buffer = [...loadedItems, ...this.buffer].slice(0, this.config.maxBufferSize);
        }
      } catch (error) {
        this.logger.error({ error }, 'Failed to load telemetry items from persistent store');
      }
    }

    this.retryTimer = setInterval(() => {
      void this.processRetries();
    }, this.config.retryIntervalMs);

    this.logger.info(
      { config: this.config, persistent: !!this.persistentStore },
      'ClickHouse retry buffer started'
    );
  }

  /**
   * Stop the background retry processor
   */
  async stop(): Promise<void> {
    if (this.retryTimer) {
      clearInterval(this.retryTimer);
      this.retryTimer = null;
    }

    // Save to persistent store if available (labs-mmft.8)
    if (this.persistentStore && this.buffer.length > 0) {
      try {
        await this.persistentStore.save(this.buffer);
        this.logger.info({ count: this.buffer.length }, 'Saved telemetry items to persistent store');
      } catch (error) {
        this.logger.error({ error }, 'Failed to save telemetry items to persistent store');
      }
    }
  }

  /**
   * Insert signal events with automatic retry on failure.
   * Returns true if the write succeeded immediately, false if buffered for retry.
   */
  async insertSignalEvents(signals: SignalEventRow[]): Promise<boolean> {
    if (signals.length === 0) return true;

    try {
      await this.clickhouse.insertSignalEvents(signals);
      return true;
    } catch (error) {
      this.logger.warn(
        { error, count: signals.length },
        'Signal events write failed, buffering for retry'
      );
      this.bufferForRetry({ type: 'signal', data: signals });
      return false;
    }
  }

  /**
   * Insert campaign event with automatic retry on failure.
   */
  async insertCampaignEvent(event: CampaignHistoryRow): Promise<boolean> {
    try {
      await this.clickhouse.insertCampaignEvent(event);
      return true;
    } catch (error) {
      this.logger.warn(
        { error, campaignId: event.campaign_id },
        'Campaign event write failed, buffering for retry'
      );
      this.bufferForRetry({ type: 'campaign', data: event });
      return false;
    }
  }

  /**
   * Insert blocklist events with automatic retry on failure.
   */
  async insertBlocklistEvents(events: BlocklistHistoryRow[]): Promise<boolean> {
    if (events.length === 0) return true;

    try {
      await this.clickhouse.insertBlocklistEvents(events);
      return true;
    } catch (error) {
      this.logger.warn(
        { error, count: events.length },
        'Blocklist events write failed, buffering for retry'
      );
      this.bufferForRetry({ type: 'blocklist', data: events });
      return false;
    }
  }

  /**
   * Insert HTTP transaction events with automatic retry on failure.
   */
  async insertHttpTransactions(events: HttpTransactionRow[]): Promise<boolean> {
    if (events.length === 0) return true;

    try {
      await this.clickhouse.insertHttpTransactions(events);
      return true;
    } catch (error) {
      this.logger.warn(
        { error, count: events.length },
        'HTTP transaction write failed, buffering for retry'
      );
      this.bufferForRetry({ type: 'transaction', data: events });
      return false;
    }
  }

  /**
   * Insert sensor log entries with automatic retry on failure.
   */
  async insertLogEntries(events: LogEntryRow[]): Promise<boolean> {
    if (events.length === 0) return true;

    try {
      await this.clickhouse.insertLogEntries(events);
      return true;
    } catch (error) {
      this.logger.warn(
        { error, count: events.length },
        'Sensor log write failed, buffering for retry'
      );
      this.bufferForRetry({ type: 'log', data: events });
      return false;
    }
  }

  /**
   * Buffer an item for retry
   */
  private bufferForRetry(item: Pick<BufferedItem, 'type' | 'data'>): void {
    const now = Date.now();

    // Check buffer capacity
    if (this.buffer.length >= this.config.maxBufferSize) {
      // Evict oldest item
      const evicted = this.buffer.shift();
      if (evicted) {
        this.droppedItems++;
        this.logToDeadLetterQueue(evicted, 'buffer_overflow');
      }
    }

    this.buffer.push({
      ...item,
      attempts: 1, // Already tried once
      nextRetryAt: now + this.config.initialDelayMs,
      addedAt: now,
    } as BufferedItem);
  }

  /**
   * Log an item to the "Dead Letter Queue" (currently a high-priority log entry)
   * to prevent silent data loss.
   */
  private logToDeadLetterQueue(item: BufferedItem, reason: string, error?: unknown): void {
    this.logger.error({
      dlq: true,
      reason,
      itemType: item.type,
      attempts: item.attempts,
      addedAt: new Date(item.addedAt).toISOString(),
      error: error instanceof Error ? error.message : error,
      // Include data for potential manual recovery, but limit size
      dataCount: Array.isArray(item.data) ? item.data.length : 1,
      // Only include full data in debug mode or for small payloads to avoid log flooding
      payload: this.config.maxBufferSize < 1000 ? item.data : undefined
    }, 'Telemetry item moved to Dead Letter Queue');
  }

  /**
   * Process items that are ready for retry
   */
  private async processRetries(): Promise<void> {
    if (this.isProcessing || this.buffer.length === 0) return;

    this.isProcessing = true;
    const now = Date.now();

    try {
      // Find items ready for retry (sorted by next retry time)
      const readyItems = this.buffer
        .filter(item => item.nextRetryAt <= now)
        .slice(0, this.config.retryBatchSize);

      if (readyItems.length === 0) return;

      this.logger.debug(
        { count: readyItems.length, bufferSize: this.buffer.length },
        'Processing retry batch'
      );

      for (const item of readyItems) {
        this.totalAttempts++;

        let timerId: NodeJS.Timeout | undefined;
        try {
          // Add timeout to individual retry to prevent stalling the background process
          const retryTimeoutMs = 10000; // 10s timeout
          const timeoutPromise = new Promise((_, reject) => {
            timerId = setTimeout(() => reject(new Error(`Retry timed out after ${retryTimeoutMs}ms`)), retryTimeoutMs);
          });

          await Promise.race([
            this.retryItem(item),
            timeoutPromise
          ]);

          // Success - remove from buffer
          const index = this.buffer.indexOf(item);
          if (index > -1) {
            this.buffer.splice(index, 1);
          }
          this.successfulRetries++;
        } catch (error) {
          item.attempts++;
          this.failedRetries++;

          if (item.attempts >= this.config.maxRetries) {
            // Max retries exceeded - drop the item
            const index = this.buffer.indexOf(item);
            if (index > -1) {
              this.buffer.splice(index, 1);
            }
            this.droppedItems++;
            this.logToDeadLetterQueue(item, 'max_retries_exceeded', error);
          } else {
            // Schedule next retry with exponential backoff
            const delay = Math.min(
              this.config.initialDelayMs * Math.pow(2, item.attempts - 1),
              this.config.maxDelayMs
            );
            item.nextRetryAt = now + delay;
            this.logger.debug(
              { type: item.type, attempts: item.attempts, nextDelayMs: delay, error },
              'Scheduled retry with backoff'
            );
          }
        } finally {
          if (timerId) {
            clearTimeout(timerId);
          }
        }
      }
    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Retry a single buffered item.
   * Dispatches to the appropriate ClickHouse service method based on item type.
   * Type narrowing is automatic due to discriminated union (labs-mmft.22).
   */
  private async retryItem(item: BufferedItem): Promise<void> {
    switch (item.type) {
      case 'signal':
        await this.clickhouse.insertSignalEvents(item.data);
        break;
      case 'campaign':
        await this.clickhouse.insertCampaignEvent(item.data);
        break;
      case 'blocklist':
        await this.clickhouse.insertBlocklistEvents(item.data);
        break;
      case 'transaction':
        await this.clickhouse.insertHttpTransactions(item.data);
        break;
      case 'log':
        await this.clickhouse.insertLogEntries(item.data);
        break;
    }
  }

  /**
   * Get current statistics
   */
  getStats(): RetryBufferStats {
    const now = Date.now();
    const oldestItem = this.buffer.length > 0
      ? this.buffer.reduce((min, item) => item.addedAt < min.addedAt ? item : min)
      : null;

    return {
      bufferedCount: this.buffer.length,
      totalAttempts: this.totalAttempts,
      successfulRetries: this.successfulRetries,
      failedRetries: this.failedRetries,
      droppedItems: this.droppedItems,
      oldestItemAge: oldestItem ? now - oldestItem.addedAt : null,
      isProcessing: this.isProcessing,
      bufferUtilization: this.buffer.length / this.config.maxBufferSize,
    };
  }

  /**
   * Get current buffer size
   */
  getBufferSize(): number {
    return this.buffer.length;
  }

  /**
   * Check if ClickHouse is enabled (delegates to underlying service)
   */
  isEnabled(): boolean {
    return this.clickhouse.isEnabled();
  }

  /**
   * Flush all pending retries (best-effort, for graceful shutdown)
   */
  async flush(): Promise<{ succeeded: number; failed: number }> {
    this.stop(); // Stop background processing

    let succeeded = 0;
    let failed = 0;

    for (const item of [...this.buffer]) {
      try {
        await this.retryItem(item);
        succeeded++;
      } catch {
        failed++;
      }
    }

    this.buffer = [];
    this.logger.info({ succeeded, failed }, 'Flushed retry buffer');

    return { succeeded, failed };
  }

  /**
   * Reset statistics (for testing)
   */
  resetStats(): void {
    this.totalAttempts = 0;
    this.successfulRetries = 0;
    this.failedRetries = 0;
    this.droppedItems = 0;
  }

  /**
   * Clear the buffer (for testing)
   */
  clear(): void {
    this.buffer = [];
  }
}
