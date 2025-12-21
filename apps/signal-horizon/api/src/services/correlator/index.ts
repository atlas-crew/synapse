/**
 * Campaign Correlator Service
 * Detects cross-tenant campaigns and threat patterns
 */

import type { PrismaClient, Campaign } from '@prisma/client';
import type { Logger } from 'pino';
import type { Broadcaster } from '../broadcaster/index.js';
import type { EnrichedSignal, Severity } from '../../types/protocol.js';

interface CorrelationResult {
  isCampaign: boolean;
  campaignId?: string;
  confidence: number;
  signals: string[];
}

export class Correlator {
  private prisma: PrismaClient;
  private logger: Logger;
  private broadcaster: Broadcaster;

  // Correlation thresholds
  private readonly CROSS_TENANT_THRESHOLD = 2; // 2+ tenants = fleet campaign
  private readonly FINGERPRINT_CONFIDENCE = 0.98;
  private readonly TIMING_CONFIDENCE = 0.89;
  private readonly MIN_CAMPAIGN_CONFIDENCE = 0.75;

  constructor(prisma: PrismaClient, logger: Logger, broadcaster: Broadcaster) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'correlator' });
    this.broadcaster = broadcaster;
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
      await this.updateCampaign(existingCampaign.id, signals, tenantCount);
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

    // Build map keyed by anonFingerprint from metadata
    const campaignMap = new Map<string, Campaign>();
    for (const campaign of campaigns) {
      const metadata = campaign.metadata as { anonFingerprint?: string } | null;
      const fingerprint = metadata?.anonFingerprint;
      if (fingerprint && anonFingerprints.includes(fingerprint)) {
        campaignMap.set(fingerprint, campaign);
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

    return this.prisma.campaign.create({
      data: {
        name: `Fleet Campaign ${anonFingerprint.substring(0, 8)}`,
        description: `Cross-tenant attack detected affecting ${tenantCount} tenants`,
        status: 'ACTIVE',
        severity: this.calculateSeverity(signals),
        isCrossTenant: true,
        tenantsAffected: tenantCount,
        confidence: this.calculateConfidence(signals),
        correlationSignals: {
          fingerprintMatch: this.FINGERPRINT_CONFIDENCE,
          timingMatch: this.TIMING_CONFIDENCE,
          tenantCount,
        },
        firstSeenAt: now,
        lastActivityAt: now,
        metadata: {
          anonFingerprint,
          signalCount: signals.length,
        },
      },
    });
  }

  private async updateCampaign(
    campaignId: string,
    signals: EnrichedSignal[],
    tenantCount: number
  ): Promise<void> {
    await this.prisma.campaign.update({
      where: { id: campaignId },
      data: {
        lastActivityAt: new Date(),
        tenantsAffected: tenantCount,
        confidence: this.calculateConfidence(signals),
      },
    });
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
