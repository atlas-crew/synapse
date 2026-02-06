/**
 * Automated Playbook Trigger Service
 * Monitors incoming signals and automatically triggers matching playbooks
 * based on SIGNAL_SEVERITY and SIGNAL_TYPE trigger conditions.
 */

import type { PrismaClient, Playbook, WarRoom } from '@prisma/client';
import type { Logger } from 'pino';
import type { EnrichedSignal, Severity } from '../../types/protocol.js';
import { PlaybookService, PlaybookConcurrencyError, type UserInfo } from './playbook-service.js';
import { buildRedisKey, type RedisKv } from '../../storage/redis/index.js';
import {
  type TriggerRateLimitStore,
  InMemoryTriggerRateLimitStore,
  type TriggerCountRecord,
} from './trigger-rate-limit-store.js';

/**
 * Configuration for the automated trigger service
 */
export interface AutomatedTriggerConfig {
  /** Enable/disable automated triggering */
  enabled: boolean;
  /** Cooldown period (ms) before re-triggering the same playbook for the same tenant */
  cooldownMs: number;
  /** Maximum auto-triggered runs per tenant per minute */
  maxAutoTriggersPerMinute: number;
  /** System user info for automated executions */
  systemUser: UserInfo;
}

const DEFAULT_CONFIG: AutomatedTriggerConfig = {
  enabled: true,
  cooldownMs: 60_000, // 1 minute cooldown
  maxAutoTriggersPerMinute: 10,
  systemUser: {
    userId: 'system-automated-trigger',
    userName: 'Automated Response System',
  },
};

/**
 * Store interface for distributed cooldown tracking.
 */
export interface TriggerCooldownStore {
  tryAcquire(tenantId: string, playbookId: string, cooldownMs: number): Promise<boolean>;
  release(tenantId: string, playbookId: string): Promise<void>;
  stop(): void;
}

export class InMemoryTriggerCooldownStore implements TriggerCooldownStore {
  private triggers = new Map<string, number>();

  async tryAcquire(tenantId: string, playbookId: string, cooldownMs: number): Promise<boolean> {
    const key = `${tenantId}:${playbookId}`;
    const now = Date.now();
    const last = this.triggers.get(key);

    if (last !== undefined && now - last < cooldownMs) return false;

    this.triggers.set(key, now);
    return true;
  }

  async release(tenantId: string, playbookId: string): Promise<void> {
    this.triggers.delete(`${tenantId}:${playbookId}`);
  }

  stop(): void {
    this.triggers.clear();
  }
}

export class RedisTriggerCooldownStore implements TriggerCooldownStore {
  private kv: RedisKv;
  private namespace: string;
  private version: number;
  private dataType: string;

  constructor(
    kv: RedisKv,
    options: { namespace?: string; version?: number; dataType?: string } = {}
  ) {
    this.kv = kv;
    this.namespace = options.namespace ?? 'horizon';
    this.version = options.version ?? 1;
    this.dataType = options.dataType ?? 'warroom-playbook-cooldown';
  }

  private key(tenantId: string, playbookId: string): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId,
      dataType: this.dataType,
      id: playbookId,
    });
  }

  async tryAcquire(tenantId: string, playbookId: string, cooldownMs: number): Promise<boolean> {
    const ttlSeconds = Math.max(1, Math.ceil(cooldownMs / 1000));
    return this.kv.set(this.key(tenantId, playbookId), String(Date.now()), {
      ttlSeconds,
      ifNotExists: true,
    });
  }

  async release(tenantId: string, playbookId: string): Promise<void> {
    await this.kv.del(this.key(tenantId, playbookId));
  }

  stop(): void {
    // no-op
  }
}

/**
 * Best-effort wrapper: if the primary store errors (Redis outage), fall back to
 * in-memory cooldown tracking to keep automated triggering functional.
 */
export class ResilientTriggerCooldownStore implements TriggerCooldownStore {
  private logger: Logger;
  private primary: TriggerCooldownStore;
  private fallback: TriggerCooldownStore;
  private lastWarnAtMs = 0;

  constructor(logger: Logger, primary: TriggerCooldownStore, fallback: TriggerCooldownStore) {
    this.logger = logger.child({ component: 'resilient-trigger-cooldown-store' });
    this.primary = primary;
    this.fallback = fallback;
  }

  private warn(op: string, error: unknown): void {
    const now = Date.now();
    if (now - this.lastWarnAtMs < 30_000) return;
    this.lastWarnAtMs = now;
    this.logger.warn({ error, op }, 'TriggerCooldownStore primary failed; using fallback');
  }

  async tryAcquire(tenantId: string, playbookId: string, cooldownMs: number): Promise<boolean> {
    const fallbackAcquired = await this.fallback.tryAcquire(tenantId, playbookId, cooldownMs);
    try {
      return await this.primary.tryAcquire(tenantId, playbookId, cooldownMs);
    } catch (error) {
      this.warn('tryAcquire', error);
      return fallbackAcquired;
    }
  }

  async release(tenantId: string, playbookId: string): Promise<void> {
    await this.fallback.release(tenantId, playbookId);
    try {
      await this.primary.release(tenantId, playbookId);
    } catch (error) {
      this.warn('release', error);
    }
  }

  stop(): void {
    try {
      this.fallback.stop();
    } catch {}
    try {
      this.primary.stop();
    } catch (error) {
      this.warn('stop', error);
    }
  }
}

/**
 * Result of evaluating signals against playbook triggers
 */
interface TriggerEvaluation {
  playbook: Playbook;
  matchedSignals: EnrichedSignal[];
  matchReason: string;
}

export class AutomatedPlaybookTrigger {
  private prisma: PrismaClient;
  private logger: Logger;
  private playbookService: PlaybookService;
  private config: AutomatedTriggerConfig;

  private cooldownStore: TriggerCooldownStore;
  /** Rate limit tracking per tenant (distributed support) */
  private triggerCounts: TriggerRateLimitStore;

  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(
    prisma: PrismaClient,
    logger: Logger,
    playbookService: PlaybookService,
    config?: Partial<AutomatedTriggerConfig>,
    cooldownStore?: TriggerCooldownStore,
    rateLimitStore?: TriggerRateLimitStore
  ) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'automated-playbook-trigger' });
    this.playbookService = playbookService;
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.cooldownStore = cooldownStore ?? new InMemoryTriggerCooldownStore();
    this.triggerCounts = rateLimitStore ?? new InMemoryTriggerRateLimitStore();

    if (this.config.enabled) {
      this.startCleanupInterval();
      this.logger.info('Automated playbook trigger service started');
    }
  }

  /**
   * Evaluate signals and trigger matching playbooks
   * Called by Aggregator after signal processing
   */
  async evaluateSignals(signals: EnrichedSignal[]): Promise<void> {
    if (!this.config.enabled || signals.length === 0) {
      return;
    }

    // Group signals by tenant
    const signalsByTenant = this.groupSignalsByTenant(signals);

    for (const [tenantId, tenantSignals] of signalsByTenant) {
      try {
        await this.evaluateTenantSignals(tenantId, tenantSignals);
      } catch (error) {
        this.logger.error(
          { error, tenantId, signalCount: tenantSignals.length },
          'Failed to evaluate signals for tenant'
        );
      }
    }
  }

  /**
   * Evaluate signals for a single tenant
   */
  private async evaluateTenantSignals(
    tenantId: string,
    signals: EnrichedSignal[]
  ): Promise<void> {
    // Fetch active playbooks with automated triggers for this tenant
    const playbooks = await this.prisma.playbook.findMany({
      where: {
        tenantId,
        isActive: true,
        triggerType: { in: ['SIGNAL_SEVERITY', 'SIGNAL_TYPE'] },
      },
    });

    if (playbooks.length === 0) {
      return;
    }

    // Evaluate each playbook against the signals
    const triggeredPlaybooks: TriggerEvaluation[] = [];

    for (const playbook of playbooks) {
      const evaluation = this.evaluatePlaybook(playbook, signals);
      if (evaluation) {
        triggeredPlaybooks.push(evaluation);
      }
    }

    // Execute triggered playbooks
    for (const { playbook, matchedSignals, matchReason } of triggeredPlaybooks) {
      await this.triggerPlaybook(tenantId, playbook, matchedSignals, matchReason);
    }
  }

  /**
   * Evaluate a single playbook against signals
   */
  private evaluatePlaybook(
    playbook: Playbook,
    signals: EnrichedSignal[]
  ): TriggerEvaluation | null {
    if (playbook.triggerType === 'SIGNAL_SEVERITY') {
      return this.evaluateSeverityTrigger(playbook, signals);
    }

    if (playbook.triggerType === 'SIGNAL_TYPE') {
      return this.evaluateTypeTrigger(playbook, signals);
    }

    return null;
  }

  /**
   * Evaluate SIGNAL_SEVERITY trigger
   * triggerValue should be a severity level (e.g., "HIGH", "CRITICAL")
   */
  private evaluateSeverityTrigger(
    playbook: Playbook,
    signals: EnrichedSignal[]
  ): TriggerEvaluation | null {
    const targetSeverity = playbook.triggerValue as Severity | null;
    if (!targetSeverity) {
      return null;
    }

    const severityRank: Record<Severity, number> = {
      LOW: 1,
      MEDIUM: 2,
      HIGH: 3,
      CRITICAL: 4,
    };

    const targetRank = severityRank[targetSeverity];
    if (targetRank === undefined) {
      return null;
    }

    // Match signals at or above the target severity
    const matchedSignals = signals.filter(
      (s) => severityRank[s.severity] >= targetRank
    );

    if (matchedSignals.length === 0) {
      return null;
    }

    return {
      playbook,
      matchedSignals,
      matchReason: `${matchedSignals.length} signal(s) at or above ${targetSeverity} severity`,
    };
  }

  /**
   * Evaluate SIGNAL_TYPE trigger
   * triggerValue should be a signal type (e.g., "CREDENTIAL_STUFFING")
   */
  private evaluateTypeTrigger(
    playbook: Playbook,
    signals: EnrichedSignal[]
  ): TriggerEvaluation | null {
    const targetType = playbook.triggerValue;
    if (!targetType) {
      return null;
    }

    // Match signals of the target type
    const matchedSignals = signals.filter((s) => s.signalType === targetType);

    if (matchedSignals.length === 0) {
      return null;
    }

    return {
      playbook,
      matchedSignals,
      matchReason: `${matchedSignals.length} ${targetType} signal(s) detected`,
    };
  }

  /**
   * Trigger a playbook execution
   */
  private async triggerPlaybook(
    tenantId: string,
    playbook: Playbook,
    matchedSignals: EnrichedSignal[],
    matchReason: string
  ): Promise<void> {
    // Check rate limit before each trigger
    if (!(await this.checkRateLimit(tenantId))) {
      this.logger.warn(
        { tenantId, playbookId: playbook.id },
        'Rate limit exceeded for automated playbook triggers'
      );
      return;
    }

    // Acquire cooldown (distributed)
    const cooldownAcquired = await this.cooldownStore.tryAcquire(
      tenantId,
      playbook.id,
      this.config.cooldownMs
    );
    if (!cooldownAcquired) {
      this.logger.debug(
        { playbookId: playbook.id, tenantId },
        'Playbook trigger skipped (cooldown active)'
      );
      return;
    }

    // Find or create a war room for this automated response
    const warRoom = await this.findOrCreateWarRoom(tenantId, playbook, matchedSignals);
    if (!warRoom) {
      await this.cooldownStore.release(tenantId, playbook.id);
      return;
    }

    try {
      // Execute the playbook
      const run = await this.playbookService.runPlaybook(
        playbook.id,
        warRoom.id,
        tenantId,
        this.config.systemUser
      );

      await this.incrementRateCount(tenantId);

      this.logger.info(
        {
          playbookId: playbook.id,
          playbookName: playbook.name,
          warRoomId: warRoom.id,
          runId: run.id,
          matchReason,
          signalCount: matchedSignals.length,
        },
        'Automated playbook triggered'
      );
    } catch (error) {
      if (error instanceof PlaybookConcurrencyError) {
        // Playbook already running - this is fine for automated triggers
        this.logger.debug(
          { playbookId: playbook.id, warRoomId: warRoom.id },
          'Playbook already running in war room'
        );
        await this.cooldownStore.release(tenantId, playbook.id);
        return;
      }

      await this.cooldownStore.release(tenantId, playbook.id);
      throw error;
    }
  }

  /**
   * Find an existing war room for the signal context or create a new one
   */
  private async findOrCreateWarRoom(
    tenantId: string,
    playbook: Playbook,
    signals: EnrichedSignal[]
  ): Promise<WarRoom | null> {
    // Look for an active war room for this tenant with recent activity
    const existingWarRoom = await this.prisma.warRoom.findFirst({
      where: {
        tenantId,
        status: 'ACTIVE',
        // Prefer war rooms updated recently (within last hour)
        updatedAt: {
          gte: new Date(Date.now() - 60 * 60 * 1000),
        },
      },
      orderBy: { updatedAt: 'desc' },
    });

    if (existingWarRoom) {
      return existingWarRoom;
    }

    // Create a new war room for this automated response
    try {
      const highestSeverity = this.getHighestSeverity(signals);
      const signalTypes = [...new Set(signals.map((s) => s.signalType))];

      return await this.prisma.warRoom.create({
        data: {
          tenantId,
          name: `Auto Response: ${playbook.name}`,
          description: `Automated war room created for playbook "${playbook.name}" in response to ${signals.length} ${highestSeverity} severity signal(s). Signal types: ${signalTypes.join(', ')}`,
          status: 'ACTIVE',
          priority: this.severityToPriority(highestSeverity),
        },
      });
    } catch (error) {
      this.logger.error(
        { error, tenantId, playbookId: playbook.id },
        'Failed to create war room for automated response'
      );
      return null;
    }
  }

  /**
   * Get the highest severity from a list of signals
   */
  private getHighestSeverity(signals: EnrichedSignal[]): Severity {
    const severityRank: Record<Severity, number> = {
      LOW: 1,
      MEDIUM: 2,
      HIGH: 3,
      CRITICAL: 4,
    };

    let maxRank = 1;
    let maxSeverity: Severity = 'LOW';

    for (const signal of signals) {
      const rank = severityRank[signal.severity];
      if (rank > maxRank) {
        maxRank = rank;
        maxSeverity = signal.severity;
      }
    }

    return maxSeverity;
  }

  /**
   * Convert severity to war room priority
   */
  private severityToPriority(severity: Severity): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    return severity;
  }

  /**
   * Group signals by tenant ID
   */
  private groupSignalsByTenant(signals: EnrichedSignal[]): Map<string, EnrichedSignal[]> {
    const groups = new Map<string, EnrichedSignal[]>();

    for (const signal of signals) {
      const tenantId = signal.tenantId;
      if (!tenantId) continue;

      const existing = groups.get(tenantId) || [];
      existing.push(signal);
      groups.set(tenantId, existing);
    }

    return groups;
  }

  /**
   * Check rate limit for tenant
   */
  private async checkRateLimit(tenantId: string): Promise<boolean> {
    const now = Date.now();
    const windowMs = 60_000; // 1 minute window

    const record = await this.triggerCounts.get(tenantId);
    if (!record || now - record.windowStart > windowMs) {
      // New window
      await this.triggerCounts.set(tenantId, { count: 0, windowStart: now });
      return true;
    }

    return record.count < this.config.maxAutoTriggersPerMinute;
  }

  /**
   * Increment rate count for tenant
   */
  private async incrementRateCount(tenantId: string): Promise<void> {
    const record = await this.triggerCounts.get(tenantId);
    if (record) {
      record.count++;
      await this.triggerCounts.set(tenantId, record);
    }
  }

  /**
   * Start cleanup interval for stale trigger records
   */
  private startCleanupInterval(): void {
    this.cleanupInterval = setInterval(() => {
      // Clean up old rate limit windows
      const windowCutoff = Date.now() - 60_000;
      void this.triggerCounts.entries().then((entries) => {
        for (const [tenantId, record] of entries) {
          if (record.windowStart < windowCutoff) {
            void this.triggerCounts.delete(tenantId);
          }
        }
      });
    }, 60_000);
  }

  /**
   * Stop the service
   */
  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.cooldownStore.stop();
    void this.triggerCounts.clear();
    this.logger.info('Automated playbook trigger service stopped');
  }
}
