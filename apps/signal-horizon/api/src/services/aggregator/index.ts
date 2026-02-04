/**
 * Signal Aggregator Service
 * Batches, deduplicates, and anonymizes incoming threat signals
 */

import type { PrismaClient, Prisma } from '@prisma/client';
import type { Logger } from 'pino';
import type { Correlator } from '../correlator/index.js';
import type { ImpossibleTravelService, LoginEvent } from '../impossible-travel.js';
import type { APIIntelligenceService } from '../api-intelligence/index.js';
import type { ThreatService } from '../threat-service.js';
import type { AutomatedPlaybookTrigger } from '../warroom/automated-trigger.js';
import type { ThreatSignal, EnrichedSignal, Severity } from '../../types/protocol.js';
import type { ClickHouseService, SignalEventRow } from '../../storage/clickhouse/index.js';
import { ClickHouseRetryBuffer, type RetryBufferConfig } from '../../storage/clickhouse/index.js';

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
  /** ClickHouse retry buffer configuration */
  clickhouseRetry?: Partial<RetryBufferConfig>;
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
  private clickhouseRetryBuffer: ClickHouseRetryBuffer | null;
  private apiIntelligence: APIIntelligenceService | null;
  private threatService: ThreatService | null;
  private playbookTrigger: AutomatedPlaybookTrigger | null;
  private config: Required<Omit<AggregatorConfig, 'clickhouseRetry'>> & { clickhouseRetry?: Partial<RetryBufferConfig> };
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
    impossibleTravel?: ImpossibleTravelService,
    apiIntelligenceService?: APIIntelligenceService,
    threatService?: ThreatService,
    playbookTrigger?: AutomatedPlaybookTrigger
  ) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'aggregator' });
    this.correlator = correlator;
    this.clickhouse = clickhouse ?? null;
    this.impossibleTravel = impossibleTravel ?? null;
    this.apiIntelligence = apiIntelligenceService ?? null;
    this.threatService = threatService ?? null;
    this.playbookTrigger = playbookTrigger ?? null;
    this.config = {
      maxQueueSize: DEFAULT_MAX_QUEUE_SIZE,
      maxRetries: DEFAULT_MAX_RETRIES,
      ...config,
    };
    this.startBatchTimer();

    // Initialize ClickHouse retry buffer for reliable ingestion
    if (this.clickhouse?.isEnabled()) {
      this.clickhouseRetryBuffer = new ClickHouseRetryBuffer(
        this.clickhouse,
        this.logger,
        config.clickhouseRetry
      );
      this.clickhouseRetryBuffer.start();
      this.logger.info('ClickHouse dual-write enabled with reliable retry buffer');
    } else {
      this.clickhouseRetryBuffer = null;
    }
    if (this.playbookTrigger) {
      this.logger.info('Automated playbook triggers enabled');
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
   *
   * CRITICAL: Signals can arrive via queueSignal() during async processing.
   * We snapshot the queues and swap retryQueue to a fresh array so new arrivals
   * don't get nuked when we clear after success.
   */
  private async flushBatch(): Promise<void> {
    if (this.signalBatch.length === 0 && this.retryQueue.length === 0) return;
    if (this.isFlushing) return; // Prevent concurrent flushes

    this.isFlushing = true;

    // Snapshot current queues - swap retryQueue so new arrivals during processing
    // go to a fresh array instead of being lost when we clear on success
    const batchSnapshot = this.signalBatch;
    const retrySnapshot = this.retryQueue;
    this.signalBatch = [];
    this.retryQueue = []; // New arrivals during flush go here
    
    const batch = [...batchSnapshot, ...retrySnapshot];
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

      // Evaluate signals for automated playbook triggers (non-blocking)
      if (this.playbookTrigger) {
        void this.playbookTrigger.evaluateSignals(enrichedSignals).catch((err) => {
          this.logger.warn({ error: err }, 'Automated playbook trigger evaluation failed');
        });
      }

      // SUCCESS: Batch processed, snapshots can be discarded
      // signalBatch and retryQueue were already swapped to fresh arrays above,
      // so any signals that arrived during processing are preserved
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

      // Restore failed batch for retry, prepending to any signals that arrived during flush
      if (this.retryCount >= this.config.maxRetries) {
        this.logger.error(
          { droppedCount: batchSize, maxRetries: this.config.maxRetries },
          'Max retries exceeded, dropping batch to prevent memory exhaustion'
        );
        // Don't restore snapshots - let them be garbage collected
        // retryQueue already has only signals that arrived during this flush
        this.retryCount = 0;
      } else {
        // Prepend failed batch to current queues for retry
        // Signals that arrived during flush are already in this.signalBatch/retryQueue
        const combined = [...batchSnapshot, ...retrySnapshot, ...this.retryQueue];
        
        // Enforce memory bounds during restoration
        if (combined.length > this.config.maxQueueSize) {
          const dropCount = combined.length - this.config.maxQueueSize;
          this.logger.warn(
            { dropCount, maxSize: this.config.maxQueueSize },
            'Max queue size exceeded during batch restoration, dropping oldest signals'
          );
          this.retryQueue = combined.slice(dropCount);
        } else {
          this.retryQueue = combined;
        }
      }
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
      const key = this.buildDedupeKey(signal);
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

  private buildDedupeKey(signal: IncomingSignal): string {
    const base = `${signal.signalType}:`;

    if (signal.sourceIp) {
      return `${base}${signal.sourceIp}`;
    }

    if (signal.fingerprint) {
      return `${base}${signal.fingerprint}`;
    }

    if (signal.signalType === 'TEMPLATE_DISCOVERY' || signal.signalType === 'SCHEMA_VIOLATION') {
      const template =
        (signal.metadata as Record<string, unknown> | undefined)?.template;
      if (typeof template === 'string' && template.length > 0) {
        return `${base}template:${template}`;
      }
    }

    return `${base}unknown`;
  }

  private severityRank(severity: Severity): number {
    // Use ThreatService for scoring when available
    if (this.threatService) {
      return this.threatService.severityRank(severity);
    }
    // Fallback to basic ranking
    const ranks: Record<Severity, number> = {
      LOW: 25,
      MEDIUM: 50,
      HIGH: 75,
      CRITICAL: 100,
    };
    return ranks[severity];
  }

  /**
   * Calculate threat score for a signal using ThreatService
   * Returns null if ThreatService is not available
   */
  private calculateThreatScore(signal: IncomingSignal): number | null {
    if (!this.threatService) return null;

    const result = this.threatService.calculateThreatScore({
      signalType: signal.signalType,
      severity: signal.severity,
      confidence: signal.confidence,
      sourceIp: signal.sourceIp,
      fingerprint: signal.fingerprint,
      eventCount: signal.eventCount,
      metadata: signal.metadata as Record<string, unknown> | undefined,
    });

    this.logger.debug(
      { signalType: signal.signalType, score: result.score, action: result.recommendedAction },
      'Calculated threat score'
    );

    return result.score;
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
    // Fetch tenant to get sharing preference for policy enforcement
    const tenant = await this.prisma.tenant.findUnique({
      where: { id: signal.tenantId },
      select: { sharingPreference: true },
    });

    const sharingPreference = tenant?.sharingPreference ?? 'CONTRIBUTE_AND_RECEIVE';

    // Generate anonymized fingerprint for cross-tenant intelligence
    // Skip anonymization if tenant is ISOLATED or RECEIVE_ONLY (privacy-first)
    const canContribute =
      sharingPreference === 'CONTRIBUTE_AND_RECEIVE' ||
      sharingPreference === 'CONTRIBUTE_ONLY';

    const anonFingerprint = signal.fingerprint && canContribute
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

    // 3. Optional: Trigger impossible travel check for any signal with geolocation metadata
    if (this.impossibleTravel) {
      const geoEvent = this.extractGeoEvent(signal, stored.createdAt);
      if (geoEvent) {
        void this.impossibleTravel.processLogin(geoEvent);
      }
    }

    // 4. Persist API Discovery signals to Endpoint model
    if (signal.signalType === 'TEMPLATE_DISCOVERY' || signal.signalType === 'SCHEMA_VIOLATION') {
      void this.apiIntelligence?.processDiscoverySignal(
        {
          tenantId: signal.tenantId,
          sensorId: signal.sensorId,
          signalType: signal.signalType,
          metadata: signal.metadata ?? {},
        },
        { signalId: stored.id, swallowErrors: true, emitEvents: true }
      );
    }

    // 5. Calculate threat score using ThreatService
    const threatScore = this.calculateThreatScore(signal) ?? undefined;

    return {
      ...signal,
      anonFingerprint,
      id: stored.id,
      threatScore,
      sharingPreference,
    };
  }

  /**
   * Write signal to ClickHouse for historical analytics.
   * Uses retry buffer for reliable ingestion - failed writes are automatically
   * retried with exponential backoff.
   */
  private async writeToClickHouse(
    signal: IncomingSignal,
    anonFingerprint: string | undefined,
    timestamp: Date
  ): Promise<void> {
    if (!this.clickhouseRetryBuffer) return;

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

    // Use retry buffer - it handles failures automatically
    await this.clickhouseRetryBuffer.insertSignalEvents([row]);
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
   * Extract geolocation event from any signal with lat/long metadata.
   * Used for impossible travel detection across all signal types.
   */
  private extractGeoEvent(signal: IncomingSignal, timestamp: Date): LoginEvent | null {
    const metadata = signal.metadata as Record<string, unknown> | undefined;
    if (!metadata) return null;

    // Check for valid geolocation data
    const latitude = metadata.latitude;
    const longitude = metadata.longitude;
    if (typeof latitude !== 'number' || typeof longitude !== 'number') {
      return null;
    }

    // Extract userId - prefer explicit userId, fall back to fingerprint or sourceIp
    const userId = String(
      metadata.userId ?? signal.fingerprint ?? signal.sourceIp ?? 'unknown'
    );

    return {
      userId,
      tenantId: signal.tenantId,
      timestamp,
      ip: signal.sourceIp || '0.0.0.0',
      location: {
        latitude,
        longitude,
        city: typeof metadata.city === 'string' ? metadata.city : undefined,
        countryCode: typeof metadata.countryCode === 'string' ? metadata.countryCode : 'XX',
      },
      fingerprint: signal.fingerprint,
    };
  }

  /**
   * Get current queue statistics
   */
  getStats(): {
    queueSize: number;
    retryQueueSize: number;
    isFlushing: boolean;
    retryCount: number;
    clickhouseRetryBuffer?: {
      bufferedCount: number;
      droppedItems: number;
      successfulRetries: number;
      bufferUtilization: number;
    };
  } {
    const stats: ReturnType<typeof this.getStats> = {
      queueSize: this.signalBatch.length,
      retryQueueSize: this.retryQueue.length,
      isFlushing: this.isFlushing,
      retryCount: this.retryCount,
    };

    if (this.clickhouseRetryBuffer) {
      const chStats = this.clickhouseRetryBuffer.getStats();
      stats.clickhouseRetryBuffer = {
        bufferedCount: chStats.bufferedCount,
        droppedItems: chStats.droppedItems,
        successfulRetries: chStats.successfulRetries,
        bufferUtilization: chStats.bufferUtilization,
      };
    }

    return stats;
  }

  async stop(): Promise<void> {
    if (this.batchTimer) {
      clearInterval(this.batchTimer);
      this.batchTimer = null;
    }
    // Flush any remaining signals
    await this.flushBatch();
    // Flush ClickHouse retry buffer on shutdown
    if (this.clickhouseRetryBuffer) {
      const { succeeded, failed } = await this.clickhouseRetryBuffer.flush();
      this.logger.info(
        { succeeded, failed },
        'Flushed ClickHouse retry buffer on shutdown'
      );
    }
    // Stop playbook trigger service
    this.playbookTrigger?.stop();
  }
}
