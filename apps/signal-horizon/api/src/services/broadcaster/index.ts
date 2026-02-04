/**
 * Broadcaster Service
 * Real-time blocklist push to sensors and dashboard notifications
 */

import type { PrismaClient, Campaign } from '@prisma/client';
import type { Logger } from 'pino';
import type { DashboardGateway } from '../../websocket/dashboard-gateway.js';
import type { SensorGateway } from '../../websocket/sensor-gateway.js';
import type { WarRoomService } from '../warroom/index.js';
import type {
  EnrichedSignal,
  BlocklistUpdate,
  Threat,
} from '../../types/protocol.js';
import type { ClickHouseService, BlocklistHistoryRow } from '../../storage/clickhouse/index.js';

export interface BroadcasterConfig {
  pushDelayMs: number;
  cacheSize: number;
}

export class Broadcaster {
  private prisma: PrismaClient;
  private logger: Logger;
  private clickhouse: ClickHouseService | null;
  // Config will be used for push delay and cache eviction in future phases
  private _config: BroadcasterConfig;
  private dashboardGateway: DashboardGateway | null = null;
  private sensorGateway: SensorGateway | null = null;

  // In-memory blocklist cache for fast lookup
  private blocklistCache: Map<string, BlocklistUpdate> = new Map();

  // War room service for automatic incident creation
  private warRoomService: WarRoomService | null = null;

  constructor(
    prisma: PrismaClient,
    logger: Logger,
    config: BroadcasterConfig,
    clickhouse?: ClickHouseService
  ) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'broadcaster' });
    this._config = config;
    this.clickhouse = clickhouse ?? null;
  }

  setDashboardGateway(gateway: DashboardGateway): void {
    this.dashboardGateway = gateway;
  }

  setSensorGateway(gateway: SensorGateway): void {
    this.sensorGateway = gateway;
  }

  setWarRoomService(service: WarRoomService): void {
    this.warRoomService = service;
  }

  /**
   * Handle campaign detection - broadcast to dashboards, create blocks, and trigger war room automation
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
        tenantId: campaign.tenantId ?? undefined,
      },
      timestamp: Date.now(),
    });

    // Trigger war room automation (auto-creates war room for cross-tenant or CRITICAL campaigns)
    if (this.warRoomService) {
      try {
        await this.warRoomService.onCampaignDetected({
          ...campaign,
          severity: campaign.severity,
        });
      } catch (error) {
        this.logger.warn(
          { campaignId: campaign.id, error },
          'Failed to trigger war room automation (non-critical)'
        );
      }
    }

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

        // Log to ClickHouse for historical tracking
        void this.logBlocklistChange({
          action: 'added',
          block_type: 'IP',
          indicator: signal.sourceIp,
          source: 'FLEET_INTEL',
          reason: `Campaign: ${campaign.name}`,
          campaign_id: campaign.id,
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

        // Log to ClickHouse for historical tracking
        void this.logBlocklistChange({
          action: 'added',
          block_type: 'FINGERPRINT',
          indicator: signal.anonFingerprint,
          source: 'FLEET_INTEL',
          reason: `Campaign: ${campaign.name}`,
          campaign_id: campaign.id,
        });
      }
    }

    // Broadcast blocklist updates to dashboards and sensors
    if (blocks.length > 0) {
      this.dashboardGateway?.broadcastBlocklistUpdate({
        updates: blocks,
        campaign: campaign.id,
      });

      this.sensorGateway?.broadcastBlocklistPush(blocks);

      // Update cache
      for (const block of blocks) {
        this.blocklistCache.set(`${block.blockType}:${block.indicator}`, block);
      }

      this.logger.info(
        { campaignId: campaign.id, blockCount: blocks.length },
        'Created and pushed blocklist entries from campaign'
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
        tenantId: threat.tenantId ?? undefined,
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
   * Log blocklist change to ClickHouse for historical tracking
   * Non-blocking: logs warning on failure
   */
  private async logBlocklistChange(params: {
    action: 'added' | 'removed' | 'expired';
    block_type: string;
    indicator: string;
    source: string;
    reason: string;
    campaign_id?: string;
    tenant_id?: string;
    expires_at?: Date;
  }): Promise<void> {
    if (!this.clickhouse?.isEnabled()) return;

    try {
      const row: BlocklistHistoryRow = {
        timestamp: new Date().toISOString(),
        tenant_id: params.tenant_id ?? 'fleet',
        action: params.action,
        block_type: params.block_type,
        indicator: params.indicator,
        source: params.source,
        reason: params.reason,
        campaign_id: params.campaign_id ?? '',
        expires_at: params.expires_at?.toISOString() ?? null,
      };

      await this.clickhouse.insertBlocklistEvent(row);
    } catch (error) {
      this.logger.warn(
        { error, indicator: params.indicator },
        'ClickHouse blocklist log failed (non-critical)'
      );
    }
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
