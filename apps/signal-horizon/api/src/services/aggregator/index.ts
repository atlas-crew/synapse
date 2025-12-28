/**
 * Signal Aggregator Service
 * Batches, deduplicates, and anonymizes incoming threat signals
 */

import type { PrismaClient, Prisma } from '@prisma/client';
import type { Logger } from 'pino';
import type { Correlator } from '../correlator/index.js';
import type { ImpossibleTravelService } from '../impossible-travel.js';
import type { ThreatSignal, EnrichedSignal, Severity } from '../../types/protocol.js';
import type { ClickHouseService, SignalEventRow } from '../../storage/clickhouse/index.js';

/**
 * Signal with tenant/sensor context from sensor gateway
 * This is what queueSignal receives before enrichment
 * Note: Using type intersection instead of interface extends because
 * ThreatSignal is a discriminated union (interfaces can't extend unions)
 */
export type IncomingSignal = ThreatSignal & {
  tenantId: string;
  sensorId: string;
};

export interface AggregatorConfig {
  batchSize: number;
  batchTimeoutMs: number;
  /** Maximum signals to hold in memory before applying backpressure */
  maxQueueSize?: number;
  /** Maximum retry attempts for failed batches */
  maxRetries?: number;
}

/** Result of queueSignal - indicates if signal was accepted */
export interface QueueResult {
  accepted: boolean;
  reason?: 'queued' | 'queue_full' | 'flushing';
  queueSize: number;
}

// Default limits to prevent unbounded memory growth
const DEFAULT_MAX_QUEUE_SIZE = 10000;
const DEFAULT_MAX_RETRIES = 3;

export class Aggregator {
  private prisma: PrismaClient;
  private logger: Logger;
  private correlator: Correlator;
  private impossibleTravel: ImpossibleTravelService | null;
  private clickhouse: ClickHouseService | null;
  private config: Required<AggregatorConfig>;
  private batchTimer: ReturnType<typeof setInterval> | null = null;
  private signalBatch: IncomingSignal[] = [];
  private isFlushing = false;
  private retryQueue: IncomingSignal[] = [];
  private retryCount = 0;

  constructor(
    prisma: PrismaClient,
    logger: Logger,
    correlator: Correlator,
    config: AggregatorConfig,
    clickhouse?: ClickHouseService,
    impossibleTravel?: ImpossibleTravelService
  ) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'aggregator' });
    this.correlator = correlator;
    this.clickhouse = clickhouse ?? null;
    this.impossibleTravel = impossibleTravel ?? null;
    this.config = {
      maxQueueSize: DEFAULT_MAX_QUEUE_SIZE,
      maxRetries: DEFAULT_MAX_RETRIES,
      ...config,
    };
    this.startBatchTimer();

    if (this.clickhouse?.isEnabled()) {
      this.logger.info('ClickHouse dual-write enabled for historical data');
    }
  }

  private startBatchTimer(): void {
    this.batchTimer = setInterval(() => {
      void this.flushBatch();
    }, this.config.batchTimeoutMs);
  }

  /**
   * Queue a signal for batch processing
   * Returns result indicating if signal was accepted (backpressure support)
   */
  queueSignal(signal: IncomingSignal): QueueResult {
    const currentSize = this.signalBatch.length + this.retryQueue.length;

    // Check memory bounds - apply backpressure if queue is full
    if (currentSize >= this.config.maxQueueSize) {
      this.logger.warn(
        { queueSize: currentSize, maxSize: this.config.maxQueueSize },
        'Signal queue full, rejecting signal (backpressure)'
      );
      return {
        accepted: false,
        reason: 'queue_full',
        queueSize: currentSize,
      };
    }

    // Don't accept new signals while flushing to prevent interleaving
    if (this.isFlushing) {
      // Add to retry queue instead - will be processed next flush
      this.retryQueue.push(signal);
      return {
        accepted: true,
        reason: 'flushing',
        queueSize: currentSize + 1,
      };
    }

    this.signalBatch.push(signal);

    // Trigger immediate flush if batch size reached
    if (this.signalBatch.length >= this.config.batchSize) {
      void this.flushBatch();
    }

    return {
      accepted: true,
      reason: 'queued',
      queueSize: this.signalBatch.length,
    };
  }

  /**
   * Process accumulated signals
   * Uses transaction-like pattern: only clears batch after successful processing
   */
  private async flushBatch(): Promise<void> {
    if (this.signalBatch.length === 0 && this.retryQueue.length === 0) return;
    if (this.isFlushing) return; // Prevent concurrent flushes

    this.isFlushing = true;

    // Take ownership of current batch (don't clear yet - that's the fix!)
    const batch = [...this.signalBatch, ...this.retryQueue];
    const batchSize = batch.length;

    try {
      this.logger.info({ count: batchSize }, 'Processing signal batch');

      // Deduplicate signals
      const dedupedSignals = this.deduplicateSignals(batch);

      // Store signals and collect enriched versions with anonFingerprint
      const enrichedSignals: EnrichedSignal[] = [];
      for (const signal of dedupedSignals) {
        const enriched = await this.storeSignal(signal);
        enrichedSignals.push(enriched);
      }

      // Forward enriched signals to correlator for campaign detection
      await this.correlator.analyzeSignals(enrichedSignals);

      // SUCCESS: Now safe to clear the batch
      this.signalBatch = [];
      this.retryQueue = [];
      this.retryCount = 0;

      this.logger.info(
        { original: batchSize, deduped: dedupedSignals.length },
        'Batch processed successfully'
      );
    } catch (error) {
      this.retryCount++;
      this.logger.error(
        { error, retryCount: this.retryCount, batchSize },
        'Failed to process signal batch'
      );

      // Keep signals for retry, but limit retry attempts
      if (this.retryCount >= this.config.maxRetries) {
        this.logger.error(
          { droppedCount: batchSize, maxRetries: this.config.maxRetries },
          'Max retries exceeded, dropping batch to prevent memory exhaustion'
        );
        // Clear to prevent infinite loop, but log the loss
        this.signalBatch = [];
        this.retryQueue = [];
        this.retryCount = 0;
      }
      // Otherwise, signals remain in batch for next flush attempt
    } finally {
      this.isFlushing = false;
    }
  }

  /**
   * Deduplicate signals by fingerprint + time window
   */
  private deduplicateSignals(signals: IncomingSignal[]): IncomingSignal[] {
    const seen = new Map<string, IncomingSignal>();

    for (const signal of signals) {
      const key = `${signal.signalType}:${signal.sourceIp ?? signal.fingerprint}`;
      const existing = seen.get(key);

      if (existing) {
        // Merge: increment event count, keep highest severity
        existing.eventCount = (existing.eventCount ?? 1) + (signal.eventCount ?? 1);
        if (this.severityRank(signal.severity) > this.severityRank(existing.severity)) {
          existing.severity = signal.severity;
        }
      } else {
        seen.set(key, { ...signal, eventCount: signal.eventCount ?? 1 });
      }
    }

    return Array.from(seen.values());
  }

  private severityRank(severity: Severity): number {
    const ranks: Record<Severity, number> = {
      LOW: 1,
      MEDIUM: 2,
      HIGH: 3,
      CRITICAL: 4,
    };
    return ranks[severity];
  }

  /**
   * Store signal with anonymized fingerprint for cross-tenant sharing
   * Returns the enriched signal with anonFingerprint for correlation
   *
   * Dual-write pattern:
   * 1. Store in PostgreSQL (source of truth, real-time queries)
   * 2. Async write to ClickHouse (historical analytics, non-blocking)
   */
  private async storeSignal(signal: IncomingSignal): Promise<EnrichedSignal> {
    // Generate anonymized fingerprint for cross-tenant intelligence
    const anonFingerprint = signal.fingerprint
      ? await this.anonymizeFingerprint(signal.fingerprint)
      : undefined;

    // 1. Store in PostgreSQL (source of truth)
    const stored = await this.prisma.signal.create({
      data: {
        tenantId: signal.tenantId,
        sensorId: signal.sensorId,
        signalType: signal.signalType,
        sourceIp: signal.sourceIp,
        fingerprint: signal.fingerprint,
        anonFingerprint: anonFingerprint ?? null,
        severity: signal.severity,
        confidence: signal.confidence,
        eventCount: signal.eventCount ?? 1,
        metadata: (signal.metadata ?? {}) as Prisma.InputJsonValue,
      },
    });

    // 2. Async write to ClickHouse (non-blocking, for historical analytics)
    if (this.clickhouse?.isEnabled()) {
      void this.writeToClickHouse(signal, anonFingerprint, stored.createdAt);
    }

    // 3. Optional: Trigger impossible travel check for authentication-related signals
    if (this.impossibleTravel && signal.signalType === 'CREDENTIAL_STUFFING') {
      const { metadata } = signal;
      void this.impossibleTravel.processLogin({
        userId: metadata.userId ?? 'unknown',
        tenantId: signal.tenantId,
        timestamp: stored.createdAt,
        ip: signal.sourceIp || '0.0.0.0',
        location: {
          latitude: metadata.latitude,
          longitude: metadata.longitude,
          city: metadata.city,
          countryCode: metadata.countryCode || 'XX',
        },
        fingerprint: signal.fingerprint,
      });
    }

    return {
      ...signal,
      anonFingerprint,
      id: stored.id,
    };
  }

  /**
   * Write signal to ClickHouse for historical analytics
   * Non-blocking: logs warning on failure, doesn't affect main request
   */
  private async writeToClickHouse(
    signal: IncomingSignal,
    anonFingerprint: string | undefined,
    timestamp: Date
  ): Promise<void> {
    if (!this.clickhouse) return;

    try {
      const row: SignalEventRow = {
        timestamp: timestamp.toISOString(),
        tenant_id: signal.tenantId,
        sensor_id: signal.sensorId,
        signal_type: signal.signalType,
        source_ip: signal.sourceIp ?? '0.0.0.0',
        fingerprint: signal.fingerprint ?? '',
        anon_fingerprint: anonFingerprint ?? ''.padEnd(64, '0'),
        severity: signal.severity,
        confidence: signal.confidence,
        event_count: signal.eventCount ?? 1,
        metadata: JSON.stringify(signal.metadata ?? {}),
      };

      await this.clickhouse.insertSignalEvents([row]);
    } catch (error) {
      // Log warning but don't fail - PostgreSQL is source of truth
      this.logger.warn(
        { error, signalType: signal.signalType },
        'ClickHouse write failed (non-critical)'
      );
    }
  }

  /**
   * SHA-256 hash for cross-tenant anonymization
   */
  private async anonymizeFingerprint(fingerprint: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(fingerprint);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Get current queue statistics
   */
  getStats(): { queueSize: number; retryQueueSize: number; isFlushing: boolean; retryCount: number } {
    return {
      queueSize: this.signalBatch.length,
      retryQueueSize: this.retryQueue.length,
      isFlushing: this.isFlushing,
      retryCount: this.retryCount,
    };
  }

  async stop(): Promise<void> {
    if (this.batchTimer) {
      clearInterval(this.batchTimer);
      this.batchTimer = null;
    }
    // Flush any remaining signals
    await this.flushBatch();
  }
}
