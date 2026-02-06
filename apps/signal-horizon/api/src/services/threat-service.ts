/**
 * Threat Service
 * Provides centralized threat scoring and risk assessment for signals.
 * Replaces basic severity ranking with multi-factor threat scoring.
 */

import type { Logger } from 'pino';
import type { Severity } from '../types/protocol.js';

/**
 * Signal context for threat scoring
 */
export interface SignalContext {
  signalType: string;
  severity: Severity;
  confidence: number;
  sourceIp?: string;
  fingerprint?: string;
  eventCount?: number;
  metadata?: Record<string, unknown>;
}

/**
 * Threat score result
 */
export interface ThreatScore {
  /** Overall threat score (0-100) */
  score: number;
  /** Score breakdown by factor */
  factors: ThreatFactor[];
  /** Suggested action based on score */
  recommendedAction: 'allow' | 'monitor' | 'alert' | 'block';
}

/**
 * Individual scoring factor
 */
export interface ThreatFactor {
  name: string;
  weight: number;
  contribution: number;
  reason: string;
}

/**
 * Configuration for threat scoring weights
 */
export interface ThreatScoringConfig {
  /** Weight for severity factor (0-1) */
  severityWeight: number;
  /** Weight for signal type factor (0-1) */
  signalTypeWeight: number;
  /** Weight for confidence factor (0-1) */
  confidenceWeight: number;
  /** Weight for volume/frequency factor (0-1) */
  volumeWeight: number;
  /** Thresholds for recommended actions */
  thresholds: {
    monitor: number;
    alert: number;
    block: number;
  };
}

const DEFAULT_CONFIG: ThreatScoringConfig = {
  severityWeight: 0.35,
  signalTypeWeight: 0.25,
  confidenceWeight: 0.20,
  volumeWeight: 0.20,
  thresholds: {
    monitor: 30,
    alert: 60,
    block: 85,
  },
};

/**
 * Signal type base scores (0-100)
 * Higher = more threatening
 */
const SIGNAL_TYPE_SCORES: Record<string, number> = {
  CREDENTIAL_STUFFING: 80,
  IMPOSSIBLE_TRAVEL: 90,
  IP_THREAT: 60,
  FINGERPRINT_THREAT: 55,
  CAMPAIGN_INDICATOR: 75,
  RATE_ANOMALY: 50,
  BOT_SIGNATURE: 65,
  TEMPLATE_DISCOVERY: 25,
  SCHEMA_VIOLATION: 40,
};

/**
 * Severity multipliers
 */
const SEVERITY_SCORES: Record<Severity, number> = {
  LOW: 25,
  MEDIUM: 50,
  HIGH: 75,
  CRITICAL: 100,
};

/**
 * Store interface for recent signal tracking data.
 * Allows swapping between in-memory and Redis-backed implementations.
 */
export interface RecentSignalsStore {
  get(key: string): Promise<{ count: number; lastSeen: number } | undefined>;
  set(key: string, value: { count: number; lastSeen: number }): Promise<void>;
  delete(key: string): Promise<void>;
  entries(): Promise<[string, { count: number; lastSeen: number }][]>;
}

/**
 * In-memory implementation of RecentSignalsStore (default).
 * Suitable for single-instance deployments.
 */
export class InMemoryRecentSignalsStore implements RecentSignalsStore {
  private map = new Map<string, { count: number; lastSeen: number }>();

  async get(key: string): Promise<{ count: number; lastSeen: number } | undefined> {
    return this.map.get(key);
  }

  async set(key: string, value: { count: number; lastSeen: number }): Promise<void> {
    this.map.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.map.delete(key);
  }

  async entries(): Promise<[string, { count: number; lastSeen: number }][]> {
    return Array.from(this.map.entries());
  }
}

export class ThreatService {
  private logger: Logger;
  private config: ThreatScoringConfig;

  /** Track recent signals for volume-based scoring */
  private recentSignals: RecentSignalsStore;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;
  private readonly WINDOW_MS = 5 * 60 * 1000; // 5 minute window

  constructor(logger: Logger, config?: Partial<ThreatScoringConfig>, recentSignalsStore?: RecentSignalsStore) {
    this.logger = logger.child({ service: 'threat-service' });
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.recentSignals = recentSignalsStore ?? new InMemoryRecentSignalsStore();
    this.startCleanup();
  }

  /**
   * Calculate threat score for a signal
   */
  async calculateThreatScore(signal: SignalContext): Promise<ThreatScore> {
    const factors: ThreatFactor[] = [];

    // 1. Severity factor
    const severityScore = SEVERITY_SCORES[signal.severity] ?? 50;
    factors.push({
      name: 'severity',
      weight: this.config.severityWeight,
      contribution: severityScore * this.config.severityWeight,
      reason: `Severity ${signal.severity} = ${severityScore}`,
    });

    // 2. Signal type factor
    const typeScore = SIGNAL_TYPE_SCORES[signal.signalType] ?? 40;
    factors.push({
      name: 'signalType',
      weight: this.config.signalTypeWeight,
      contribution: typeScore * this.config.signalTypeWeight,
      reason: `Signal type ${signal.signalType} = ${typeScore}`,
    });

    // 3. Confidence factor (signal's own confidence scaled)
    const confidenceScore = signal.confidence * 100;
    factors.push({
      name: 'confidence',
      weight: this.config.confidenceWeight,
      contribution: confidenceScore * this.config.confidenceWeight,
      reason: `Confidence ${(signal.confidence * 100).toFixed(0)}%`,
    });

    // 4. Volume factor (repeat offenders score higher)
    const volumeKey = this.buildVolumeKey(signal);
    const volumeScore = await this.updateVolumeTracking(volumeKey, signal.eventCount ?? 1);
    factors.push({
      name: 'volume',
      weight: this.config.volumeWeight,
      contribution: volumeScore * this.config.volumeWeight,
      reason: `Volume score = ${volumeScore}`,
    });

    // Calculate total score
    const totalScore = Math.min(
      100,
      Math.round(factors.reduce((sum, f) => sum + f.contribution, 0))
    );

    // Determine recommended action
    const recommendedAction = this.determineAction(totalScore);

    return {
      score: totalScore,
      factors,
      recommendedAction,
    };
  }

  /**
   * Get severity rank for comparison (for backward compatibility)
   */
  severityRank(severity: Severity): number {
    return SEVERITY_SCORES[severity] ?? 0;
  }

  /**
   * Compare two severities, returning the higher one
   */
  higherSeverity(a: Severity, b: Severity): Severity {
    return this.severityRank(a) >= this.severityRank(b) ? a : b;
  }

  private buildVolumeKey(signal: SignalContext): string {
    // Key by fingerprint, sourceIp, or signal type
    if (signal.fingerprint) return `fp:${signal.fingerprint}`;
    if (signal.sourceIp) return `ip:${signal.sourceIp}`;
    return `type:${signal.signalType}`;
  }

  private async updateVolumeTracking(key: string, eventCount: number): Promise<number> {
    const now = Date.now();
    const existing = await this.recentSignals.get(key);

    if (existing) {
      existing.count += eventCount;
      existing.lastSeen = now;
      await this.recentSignals.set(key, existing);
    } else {
      await this.recentSignals.set(key, { count: eventCount, lastSeen: now });
    }

    // Calculate volume score: logarithmic scaling for repeat offenders
    const totalCount = existing?.count ?? eventCount;
    // 1 signal = 0, 10 signals = 50, 100 signals = 100
    return Math.min(100, Math.round(Math.log10(totalCount + 1) * 50));
  }

  private determineAction(score: number): ThreatScore['recommendedAction'] {
    if (score >= this.config.thresholds.block) return 'block';
    if (score >= this.config.thresholds.alert) return 'alert';
    if (score >= this.config.thresholds.monitor) return 'monitor';
    return 'allow';
  }

  private startCleanup(): void {
    // Clean up old entries every minute
    this.cleanupInterval = setInterval(() => {
      const cutoff = Date.now() - this.WINDOW_MS;
      void this.recentSignals.entries().then((entries) => {
        for (const [key, value] of entries) {
          if (value.lastSeen < cutoff) {
            void this.recentSignals.delete(key);
          }
        }
      });
    }, 60_000);
  }

  /**
   * Get current volume statistics
   */
  async getVolumeStats(): Promise<{ trackedEntities: number; totalSignals: number }> {
    const allEntries = await this.recentSignals.entries();
    let totalSignals = 0;
    for (const [, value] of allEntries) {
      totalSignals += value.count;
    }
    return {
      trackedEntities: allEntries.length,
      totalSignals,
    };
  }

  /**
   * Stop the service and clean up
   */
  async stop(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    const entries = await this.recentSignals.entries();
    for (const [key] of entries) {
      await this.recentSignals.delete(key);
    }
  }
}
