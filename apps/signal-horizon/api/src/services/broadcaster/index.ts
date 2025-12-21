/**
 * Broadcaster Service
 * Real-time blocklist push to sensors and dashboard notifications
 */

import type { PrismaClient, Campaign } from '@prisma/client';
import type { Logger } from 'pino';
import type { DashboardGateway } from '../../websocket/dashboard-gateway.js';
import type {
  EnrichedSignal,
  BlocklistUpdate,
  Threat,
} from '../../types/protocol.js';

export interface BroadcasterConfig {
  pushDelayMs: number;
  cacheSize: number;
}

export class Broadcaster {
  private prisma: PrismaClient;
  private logger: Logger;
  // Config will be used for push delay and cache eviction in future phases
  private _config: BroadcasterConfig;
  private dashboardGateway: DashboardGateway | null = null;

  // In-memory blocklist cache for fast lookup
  private blocklistCache: Map<string, BlocklistUpdate> = new Map();

  constructor(prisma: PrismaClient, logger: Logger, config: BroadcasterConfig) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'broadcaster' });
    this._config = config;
  }

  setDashboardGateway(gateway: DashboardGateway): void {
    this.dashboardGateway = gateway;
  }

  /**
   * Handle campaign detection - broadcast to dashboards and create blocks
   */
  async onCampaignDetected(campaign: Campaign, signals: EnrichedSignal[]): Promise<void> {
    this.logger.info(
      { campaignId: campaign.id, signalCount: signals.length },
      'Broadcasting campaign detection'
    );

    // Notify dashboards
    this.dashboardGateway?.broadcastCampaignAlert({
      type: 'campaign-detected',
      campaign: {
        id: campaign.id,
        name: campaign.name,
        severity: campaign.severity as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
        isCrossTenant: campaign.isCrossTenant,
        tenantsAffected: campaign.tenantsAffected,
        confidence: campaign.confidence,
      },
      timestamp: Date.now(),
    });

    // Auto-create blocklist entries for high-confidence threats
    if (campaign.confidence >= 0.85) {
      await this.createCampaignBlocks(campaign, signals);
    }
  }

  /**
   * Create blocklist entries from campaign signals
   */
  private async createCampaignBlocks(campaign: Campaign, signals: EnrichedSignal[]): Promise<void> {
    const blocks: BlocklistUpdate[] = [];

    for (const signal of signals) {
      if (signal.sourceIp) {
        const block: BlocklistUpdate = {
          type: 'add',
          blockType: 'IP',
          indicator: signal.sourceIp,
          reason: `Campaign: ${campaign.name}`,
          source: 'FLEET_INTEL',
        };

        blocks.push(block);

        // Store in database - upsert fleet-wide block (null tenantId)
        // Note: Prisma compound unique with nullable field requires type assertion
        await this.prisma.blocklistEntry.upsert({
          where: {
            blockType_indicator_tenantId: {
              blockType: 'IP',
              indicator: signal.sourceIp,
              tenantId: null as unknown as string, // Fleet-wide block
            },
          },
          create: {
            blockType: 'IP',
            indicator: signal.sourceIp,
            source: 'FLEET_INTEL',
            reason: `Campaign: ${campaign.name}`,
            propagationStatus: 'PENDING',
          },
          update: {
            reason: `Campaign: ${campaign.name}`,
            propagationStatus: 'PENDING',
          },
        });
      }

      if (signal.anonFingerprint) {
        const block: BlocklistUpdate = {
          type: 'add',
          blockType: 'FINGERPRINT',
          indicator: signal.anonFingerprint,
          reason: `Campaign: ${campaign.name}`,
          source: 'FLEET_INTEL',
        };

        blocks.push(block);

        await this.prisma.blocklistEntry.upsert({
          where: {
            blockType_indicator_tenantId: {
              blockType: 'FINGERPRINT',
              indicator: signal.anonFingerprint,
              tenantId: null as unknown as string, // Fleet-wide block
            },
          },
          create: {
            blockType: 'FINGERPRINT',
            indicator: signal.anonFingerprint,
            source: 'FLEET_INTEL',
            reason: `Campaign: ${campaign.name}`,
            propagationStatus: 'PENDING',
          },
          update: {
            reason: `Campaign: ${campaign.name}`,
            propagationStatus: 'PENDING',
          },
        });
      }
    }

    // Broadcast blocklist updates to dashboards
    if (blocks.length > 0) {
      this.dashboardGateway?.broadcastBlocklistUpdate({
        updates: blocks,
        campaign: campaign.id,
      });

      // Update cache
      for (const block of blocks) {
        this.blocklistCache.set(`${block.blockType}:${block.indicator}`, block);
      }

      this.logger.info(
        { campaignId: campaign.id, blockCount: blocks.length },
        'Created blocklist entries from campaign'
      );
    }
  }

  /**
   * Broadcast threat alert to dashboards
   */
  broadcastThreatAlert(threat: Threat): void {
    this.dashboardGateway?.broadcastThreatAlert({
      threat: {
        id: threat.id,
        threatType: threat.threatType,
        indicator: threat.indicator,
        riskScore: threat.riskScore,
        isFleetThreat: threat.isFleetThreat,
      },
      timestamp: Date.now(),
    });
  }

  /**
   * Get current blocklist for sensor sync
   */
  getBlocklist(): BlocklistUpdate[] {
    return Array.from(this.blocklistCache.values());
  }

  /**
   * Check if indicator is blocked
   */
  isBlocked(blockType: string, indicator: string): boolean {
    return this.blocklistCache.has(`${blockType}:${indicator}`);
  }

  /**
   * Get blocklist cache size
   */
  getCacheSize(): number {
    return this.blocklistCache.size;
  }

  getConfig(): BroadcasterConfig {
    return this._config;
  }

  /**
   * Cleanup resources and stop the broadcaster
   * Clears in-memory cache
   */
  stop(): void {
    this.blocklistCache.clear();
    this.dashboardGateway = null;
    this.logger.info('Broadcaster stopped');
  }
}
