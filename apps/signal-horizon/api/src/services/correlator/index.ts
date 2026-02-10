/**
 * Campaign Correlator Service
 * Detects cross-tenant campaigns and threat patterns
 */

import type { Prisma, PrismaClient, Campaign } from '@prisma/client';
import type { Logger } from 'pino';
import type { Broadcaster } from '../broadcaster/index.js';
import type { EnrichedSignal, Severity } from '../../types/protocol.js';
import type { ClickHouseService, CampaignHistoryRow } from '../../storage/clickhouse/index.js';
import { SequenceMatcher, type CampaignSequenceState } from './sequence-matcher.js';

interface CorrelationResult {
  isCampaign: boolean;
  campaignId?: string;
  confidence: number;
  signals: string[];
}

/**
 * Type guard for campaign metadata with anonFingerprint
 * Validates the structure at runtime instead of using type assertions
 */
interface CampaignMetadata {
  anonFingerprint?: string;
  signalCount?: number;
  sequenceState?: CampaignSequenceState;
}

function isCampaignMetadata(value: unknown): value is CampaignMetadata {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value !== 'object') {
    return false;
  }
  const obj = value as Record<string, unknown>;
  // anonFingerprint must be string or undefined
  if ('anonFingerprint' in obj && typeof obj.anonFingerprint !== 'string') {
    return false;
  }
  return true;
}

export class Correlator {
  private prisma: PrismaClient;
  private logger: Logger;
  private broadcaster: Broadcaster;
  private clickhouse: ClickHouseService | null;
  private sequenceMatcher: SequenceMatcher;

  // Correlation thresholds
  private readonly CROSS_TENANT_THRESHOLD = 2; // 2+ tenants = fleet campaign
  private readonly FINGERPRINT_CONFIDENCE = 0.98;
  private readonly TIMING_CONFIDENCE = 0.89;
  private readonly MIN_CAMPAIGN_CONFIDENCE = 0.75;

  constructor(
    prisma: PrismaClient,
    logger: Logger,
    broadcaster: Broadcaster,
    clickhouse?: ClickHouseService
  ) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'correlator' });
    this.broadcaster = broadcaster;
    this.clickhouse = clickhouse ?? null;
    this.sequenceMatcher = new SequenceMatcher();
  }

  private toJson(value: unknown): Prisma.InputJsonValue {
    if (value === undefined || value === null) {
      return {} as Prisma.InputJsonValue;
    }
    return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
  }

  /**
   * Analyze signals for campaign correlation
   * Handles empty or invalid input gracefully
   * Optimized: Batches campaign lookups to avoid N+1 queries
   */
  async analyzeSignals(signals: EnrichedSignal[]): Promise<CorrelationResult[]> {
    // Defensive: handle null/undefined/empty input
    if (!signals || signals.length === 0) {
      return [];
    }

    const results: CorrelationResult[] = [];

    // Group by anonymized fingerprint for cross-tenant analysis
    const byFingerprint = this.groupByAnonFingerprint(signals);

    // Filter to fingerprints that meet cross-tenant threshold
    const crossTenantFingerprints: Array<{
      anonFingerprint: string;
      signals: EnrichedSignal[];
      tenantCount: number;
    }> = [];

    for (const [anonFingerprint, fingerprintSignals] of byFingerprint) {
      if (!anonFingerprint || fingerprintSignals.length === 0) {
        continue;
      }
      const tenants = new Set(fingerprintSignals.map((s) => s.tenantId));
      if (tenants.size >= this.CROSS_TENANT_THRESHOLD) {
        crossTenantFingerprints.push({
          anonFingerprint,
          signals: fingerprintSignals,
          tenantCount: tenants.size,
        });
      }
    }

    if (crossTenantFingerprints.length === 0) {
      return [];
    }

    // OPTIMIZATION: Batch fetch all existing campaigns in one query
    const existingCampaigns = await this.findExistingCampaignsBatch(
      crossTenantFingerprints.map((f) => f.anonFingerprint)
    );

    // Process each cross-tenant fingerprint
    for (const { anonFingerprint, signals: fingerprintSignals, tenantCount } of crossTenantFingerprints) {
      try {
        const result = await this.correlateFingerprint(
          anonFingerprint,
          fingerprintSignals,
          tenantCount,
          existingCampaigns.get(anonFingerprint) // O(1) lookup from batch result
        );
        if (result.isCampaign) {
          results.push(result);
        }
      } catch (error) {
        // Log but don't fail the entire batch for one correlation error
        this.logger.error(
          { error, anonFingerprint, signalCount: fingerprintSignals.length },
          'Failed to correlate fingerprint signals'
        );
      }
    }

    return results;
  }

  private groupByAnonFingerprint(signals: EnrichedSignal[]): Map<string, EnrichedSignal[]> {
    const groups = new Map<string, EnrichedSignal[]>();

    for (const signal of signals) {
      if (signal.anonFingerprint) {
        const existing = groups.get(signal.anonFingerprint) || [];
        existing.push(signal);
        groups.set(signal.anonFingerprint, existing);
      }
    }

    return groups;
  }

  /**
   * Correlate signals sharing an anonymized fingerprint
   * @param existingCampaign - Pre-fetched campaign from batch lookup (avoids N+1)
   */
  private async correlateFingerprint(
    anonFingerprint: string,
    signals: EnrichedSignal[],
    tenantCount: number,
    existingCampaign: Campaign | undefined
  ): Promise<CorrelationResult> {
    // Cross-tenant attack detected!
    this.logger.info(
      { anonFingerprint, tenantCount },
      'Cross-tenant campaign detected'
    );

    let campaign: Campaign;

    if (!existingCampaign) {
      // Create new campaign
      campaign = await this.createCampaign(anonFingerprint, signals, tenantCount);
    } else {
      // Update existing campaign
      await this.updateCampaign(existingCampaign.id, signals, tenantCount, existingCampaign);
      campaign = existingCampaign;
    }

    // Notify broadcaster for real-time push
    await this.broadcaster.onCampaignDetected(campaign, signals);

    return {
      isCampaign: true,
      campaignId: campaign.id,
      confidence: this.calculateConfidence(signals),
      signals: signals.filter((s) => s.id).map((s) => s.id as string),
    };
  }

  /**
   * Batch fetch existing campaigns for multiple fingerprints
   * OPTIMIZATION: Single query instead of N queries
   * Uses Set for O(1) fingerprint lookups instead of O(n) includes()
   */
  private async findExistingCampaignsBatch(
    anonFingerprints: string[]
  ): Promise<Map<string, Campaign>> {
    if (anonFingerprints.length === 0) {
      return new Map();
    }

    // Query all active cross-tenant campaigns
    const campaigns = await this.prisma.campaign.findMany({
      where: {
        status: 'ACTIVE',
        isCrossTenant: true,
      },
    });

    // Use Set for O(1) lookups instead of O(n) includes()
    const fingerprintSet = new Set(anonFingerprints);

    // Build map keyed by anonFingerprint from metadata
    // Use type guard for runtime validation instead of type assertion
    const campaignMap = new Map<string, Campaign>();
    for (const campaign of campaigns) {
      if (isCampaignMetadata(campaign.metadata)) {
        const fingerprint = campaign.metadata.anonFingerprint;
        if (fingerprint && fingerprintSet.has(fingerprint)) {
          campaignMap.set(fingerprint, campaign);
        }
      }
    }

    return campaignMap;
  }

  private async createCampaign(
    anonFingerprint: string,
    signals: EnrichedSignal[],
    tenantCount: number
  ): Promise<Campaign> {
    const now = new Date();

    // Process initial signals through sequence matcher
    const baseConfidence = this.calculateConfidence(signals);
    const baseSeverity = this.calculateSeverity(signals);

    const { newState: sequenceState, confidence, severity } = this.sequenceMatcher.processSignalBatch(
      { history: [] },
      signals,
      baseConfidence,
      baseSeverity
    );

    const campaign = await this.prisma.campaign.create({
      data: {
        name: `Fleet Campaign ${anonFingerprint.substring(0, 8)}`,
        description: `Cross-tenant attack detected affecting ${tenantCount} tenants`,
        status: 'ACTIVE',
        severity,
        isCrossTenant: true,
        tenantsAffected: tenantCount,
        confidence,
        correlationSignals: {
          fingerprintMatch: this.FINGERPRINT_CONFIDENCE,
          timingMatch: this.TIMING_CONFIDENCE,
          tenantCount,
          currentStage: sequenceState.currentStage,
        },
        firstSeenAt: now,
        lastActivityAt: now,
        metadata: this.toJson({ anonFingerprint, signalCount: signals.length, sequenceState }),
      },
    });

    // Log to ClickHouse for historical tracking
    void this.logCampaignEvent(campaign, 'created');

    return campaign;
  }

  private async updateCampaign(
    campaignId: string,
    signals: EnrichedSignal[],
    tenantCount: number,
    existingCampaign: Campaign
  ): Promise<void> {
    // FIX P1.2: Consistently use type guard for metadata
    const metadata = isCampaignMetadata(existingCampaign.metadata)
      ? existingCampaign.metadata
      : { anonFingerprint: undefined, signalCount: 0 };

    const initialSequenceState: CampaignSequenceState = metadata.sequenceState || { history: [] };

    // FIX P2.7: Use extracted processSignalBatch
    const { newState: sequenceState, confidence, severity } = this.sequenceMatcher.processSignalBatch(
      initialSequenceState,
      signals,
      existingCampaign.confidence,
      existingCampaign.severity
    );

    const campaign = await this.prisma.campaign.update({
      where: { id: campaignId },
      data: {
        lastActivityAt: new Date(),
        tenantsAffected: tenantCount,
        confidence,
        severity,
        metadata: this.toJson({
          anonFingerprint: metadata.anonFingerprint,
          signalCount: (metadata.signalCount || 0) + signals.length,
          sequenceState,
        }),
      },
    });

    // Log to ClickHouse for historical tracking
    void this.logCampaignEvent(campaign, 'updated');
  }

  /**
   * Log campaign event to ClickHouse for historical tracking
   * Non-blocking: logs warning on failure
   */
  private async logCampaignEvent(
    campaign: Campaign,
    eventType: 'created' | 'updated' | 'escalated' | 'resolved'
  ): Promise<void> {
    if (!this.clickhouse?.isEnabled()) return;

    try {
      const metadata = campaign.metadata as Record<string, unknown> | null;

      const row: CampaignHistoryRow = {
        timestamp: new Date().toISOString(),
        campaign_id: campaign.id,
        tenant_id: campaign.tenantId ?? 'fleet',
        request_id: null,
        event_type: eventType,
        name: campaign.name,
        status: campaign.status,
        severity: campaign.severity,
        is_cross_tenant: campaign.isCrossTenant ? 1 : 0,
        tenants_affected: campaign.tenantsAffected,
        confidence: campaign.confidence,
        metadata: JSON.stringify({
          ...metadata,
          correlationSignals: campaign.correlationSignals,
        }),
      };

      await this.clickhouse.insertCampaignEvent(row);
    } catch (error) {
      this.logger.warn(
        { error, campaignId: campaign.id },
        'ClickHouse campaign log failed (non-critical)'
      );
    }
  }

  private calculateConfidence(signals: EnrichedSignal[]): number {
    // Base confidence on signal count and consistency
    const baseConfidence = Math.min(0.5 + signals.length * 0.05, 0.95);

    // Boost if signals have high individual confidence
    const avgSignalConfidence =
      signals.reduce((sum, s) => sum + s.confidence, 0) / signals.length;

    const confidence = (baseConfidence + avgSignalConfidence) / 2;

    // Ensure minimum campaign confidence threshold
    return Math.max(confidence, this.MIN_CAMPAIGN_CONFIDENCE);
  }

  private calculateSeverity(signals: EnrichedSignal[]): Severity {
    const severityScores: Record<Severity, number> = {
      LOW: 1,
      MEDIUM: 2,
      HIGH: 3,
      CRITICAL: 4,
    };

    const maxScore = Math.max(...signals.map((s) => severityScores[s.severity]));

    if (maxScore >= 4) return 'CRITICAL';
    if (maxScore >= 3) return 'HIGH';
    if (maxScore >= 2) return 'MEDIUM';
    return 'LOW';
  }
}
