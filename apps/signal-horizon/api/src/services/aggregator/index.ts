import { createHmac, createHash } from 'node:crypto';
import type { PrismaClient, Prisma } from '@prisma/client';
import type { Logger } from 'pino';
import type { Correlator } from '../correlator/index.js';
import type { ImpossibleTravelService, LoginEvent } from '../impossible-travel.js';
import type { APIIntelligenceService } from '../api-intelligence/index.js';
import type { ThreatService } from '../threat-service.js';
import type { AutomatedPlaybookTrigger } from '../warroom/automated-trigger.js';
import type { INonceStore } from '../../middleware/replay-protection.js';
import type { ThreatSignal, EnrichedSignal, Severity, SharingPreference } from '../../types/protocol.js';
import type { ClickHouseService, SignalEventRow } from '../../storage/clickhouse/index.js';
import { ClickHouseRetryBuffer, type RetryBufferConfig } from '../../storage/clickhouse/index.js';
import { metrics } from '../metrics.js';

/**
 * Signal with tenant/sensor context from sensor gateway
 * This is what queueSignal receives before enrichment
 * Note: Using type intersection instead of interface extends because
 * ThreatSignal is a discriminated union (interfaces can't extend unions)
 */
export type IncomingSignal = ThreatSignal & {
  tenantId: string;
  sensorId: string;
  requestId?: string; // Correlation ID (P1-OBSERVABILITY-001)
  /** Optional client-provided idempotency key (labs-yb6m) */
  idempotencyKey?: string;
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
/** Warn when buffer reaches this fraction of capacity */
const BUFFER_PRESSURE_THRESHOLD = 0.8;

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
  private idempotencyStore: INonceStore | null;
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
    playbookTrigger?: AutomatedPlaybookTrigger,
    idempotencyStore?: INonceStore
  ) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'aggregator' });
    this.correlator = correlator;
    this.clickhouse = clickhouse ?? null;
    this.impossibleTravel = impossibleTravel ?? null;
    this.apiIntelligence = apiIntelligenceService ?? null;
    this.threatService = threatService ?? null;
    this.playbookTrigger = playbookTrigger ?? null;
    this.idempotencyStore = idempotencyStore ?? null;
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
    if (this.idempotencyStore) {
      this.logger.info('Aggregator cross-instance idempotency enabled');
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
      metrics.signalsDroppedTotal.inc({ reason: 'queue_full' });
      return {
        accepted: false,
        reason: 'queue_full',
        queueSize: currentSize,
      };
    }

    // Warn when approaching capacity to give operators time to react
    const utilization = currentSize / this.config.maxQueueSize;
    if (utilization >= BUFFER_PRESSURE_THRESHOLD) {
      this.logger.warn(
        {
          queueSize: currentSize,
          maxSize: this.config.maxQueueSize,
          utilization: Math.round(utilization * 100),
        },
        'Signal queue approaching capacity'
      );
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

    // Snapshot current queues
    const batchSnapshot = this.signalBatch;
    const retrySnapshot = this.retryQueue;
    this.signalBatch = [];
    this.retryQueue = []; // New arrivals during flush go here
    
    const batch = [...batchSnapshot, ...retrySnapshot];
    const batchSize = batch.length;
    const startTime = Date.now();

    // Track successfully stored signals to avoid duplicates on retry (P1-ERROR-001)
    const storedSignals: EnrichedSignal[] = [];
    const processedIndices = new Set<number>();

    try {
      this.logger.info({ count: batchSize }, 'Processing signal batch');

      // Deduplicate signals (only those not yet processed)
      const dedupedSignals = this.deduplicateSignals(batch);

      // Store signals with individual retry protection
      for (let i = 0; i < dedupedSignals.length; i++) {
        const signal = dedupedSignals[i];
        try {
          const enriched = await this.storeSignal(signal);
          storedSignals.push(enriched);
          processedIndices.add(i);

          // Increment metrics (P1-OBSERVABILITY-002)
          metrics.signalsIngestedTotal.inc({ 
            type: signal.signalType, 
            tenant_id: signal.tenantId,
            severity: signal.severity
          });
        } catch (err) {
          this.logger.error({ err, signalType: signal.signalType, tenantId: signal.tenantId }, 'Failed to store individual signal - will retry batch');
          throw err; // Rethrow to trigger batch-level retry logic
        }
      }

      // Forward enriched signals to correlator for campaign detection
      if (storedSignals.length > 0) {
        await this.correlator.analyzeSignals(storedSignals);

        // Evaluate signals for automated playbook triggers (non-blocking)
        if (this.playbookTrigger) {
          void this.playbookTrigger.evaluateSignals(storedSignals).catch((err) => {
            this.logger.warn({ error: err }, 'Automated playbook trigger evaluation failed');
          });
        }
      }

      this.retryCount = 0;
      
      // Track duration
      const duration = (Date.now() - startTime) / 1000;
      metrics.signalIngestionDuration.observe(duration);

      this.logger.info(
        { original: batchSize, deduped: dedupedSignals.length, stored: storedSignals.length },
        'Batch processed successfully'
      );
    } catch (error) {
      this.retryCount++;
      this.logger.error(
        { error, retryCount: this.retryCount, batchSize },
        'Failed to process signal batch'
      );

      // Restore failed batch for retry, but only signals that weren't successfully stored
      // This is a simplified approach - in a full implementation we'd use idempotency keys
      if (this.retryCount >= this.config.maxRetries) {
        const droppedCount = batchSize - storedSignals.length;
        this.logger.error(
          { droppedCount, maxRetries: this.config.maxRetries },
          'Max retries exceeded, dropping remaining signals in batch'
        );
        metrics.signalsDroppedTotal.inc({ reason: 'max_retries' }, droppedCount);
        this.retryCount = 0;
      } else {
        // Find signals that weren't processed
        const deduped = this.deduplicateSignals(batch);
        const remaining = deduped.filter((_, idx) => !processedIndices.has(idx));
        
        const combined = [...remaining, ...this.retryQueue];
        
        // Enforce memory bounds - drop oldest when over capacity
        if (combined.length > this.config.maxQueueSize) {
          const dropCount = combined.length - this.config.maxQueueSize;
          this.logger.warn(
            { dropCount, combinedSize: combined.length, maxSize: this.config.maxQueueSize },
            'Retry queue overflow, dropping oldest signals'
          );
          metrics.signalsDroppedTotal.inc({ reason: 'retry_overflow' }, dropCount);
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
  private async calculateThreatScore(signal: IncomingSignal): Promise<number | null> {
    if (!this.threatService) return null;

    const result = await this.threatService.calculateThreatScore({
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
    // 0. Cross-instance idempotency check (labs-yb6m)
    if (this.idempotencyStore) {
      const idempotencyKey = signal.idempotencyKey || this.generateSignalIdempotencyKey(signal);
      const isNew = await this.idempotencyStore.checkAndAdd(idempotencyKey, Date.now(), {
        tenantId: signal.tenantId,
        path: 'aggregator:storeSignal',
      });

      if (!isNew) {
        this.logger.debug({ signalType: signal.signalType, tenantId: signal.tenantId }, 'Skipping duplicate signal (idempotency hit)');
        // Retrieve existing signal ID if possible, or return a mock ID
        // For correlation, we need an ID. 
        // We'll return the existing one if we can find it, otherwise throw to be safe
        const existing = await this.prisma.signal.findFirst({
          where: {
            tenantId: signal.tenantId,
            signalType: signal.signalType,
            sourceIp: signal.sourceIp,
            fingerprint: signal.fingerprint,
            createdAt: { gte: new Date(Date.now() - 60000) } // Look back 1 minute
          },
          select: { id: true }
        });

        if (existing) {
          // Wrap in a mock enriched signal so correlator can still see it if needed
          // Or just return it.
          return {
            ...signal,
            id: existing.id,
          };
        }
        
        // If we can't find it but idempotency store said it's a duplicate, 
        // it might have been deleted or we are in a race.
        // We'll proceed with a fake ID to avoid breaking the correlator chain
        return {
          ...signal,
          id: `dup-${idempotencyKey.slice(0, 8)}`,
        };
      }
    }

    // Fetch tenant to get sharing preference and salt for policy enforcement
    const tenant = await this.prisma.tenant.findUnique({
      where: { id: signal.tenantId },
      select: { sharingPreference: true, anonymizationSalt: true },
    });

    const sharingPreference = (tenant?.sharingPreference ?? 'CONTRIBUTE_AND_RECEIVE') as SharingPreference;
    const salt = tenant?.anonymizationSalt ?? 'default-salt';

    // Generate anonymized fingerprint for cross-tenant intelligence
    // Skip anonymization if tenant is ISOLATED or RECEIVE_ONLY (privacy-first)
    const canContribute =
      sharingPreference === 'CONTRIBUTE_AND_RECEIVE' ||
      sharingPreference === 'CONTRIBUTE_ONLY';

    const anonFingerprint = signal.fingerprint && canContribute
      ? await this.anonymizeFingerprint(signal.fingerprint, salt)
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
    const threatScore = (await this.calculateThreatScore(signal)) ?? undefined;

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
      request_id: signal.requestId ?? null,
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
   * HMAC-SHA256 for cross-tenant anonymization with tenant-specific salt. (labs-6wkk)
   */
  private async anonymizeFingerprint(fingerprint: string, salt: string): Promise<string> {
    return createHmac('sha256', salt).update(fingerprint).digest('hex');
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
   * Generate a stable idempotency key for a signal based on its content. (labs-yb6m)
   */
  private generateSignalIdempotencyKey(signal: IncomingSignal): string {
    const data = JSON.stringify({
      tenantId: signal.tenantId,
      sensorId: signal.sensorId,
      type: signal.signalType,
      ip: signal.sourceIp,
      fp: signal.fingerprint,
      meta: signal.metadata,
    });
    return createHash('sha256').update(data).digest('hex');
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
