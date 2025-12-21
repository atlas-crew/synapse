/**
 * War Room Service
 * Real-time incident response collaboration with @horizon-bot automation
 *
 * Features:
 * - War room lifecycle management (create, close, archive)
 * - Activity logging with @horizon-bot automation
 * - Real-time activity broadcasting to dashboards
 * - Campaign linking for unified incident view
 * - Quick actions (block, unblock, escalate)
 */

import type { PrismaClient, WarRoom, WarRoomActivity, Campaign } from '@prisma/client';
import type { Logger } from 'pino';
import type { DashboardGateway } from '../../websocket/dashboard-gateway.js';
import type { BlocklistUpdate } from '../../types/protocol.js';
import type { Prisma } from '@prisma/client';

// =============================================================================
// Types
// =============================================================================

export interface WarRoomConfig {
  /** Auto-create war room for cross-tenant campaigns */
  autoCreateForCrossTenant: boolean;
  /** Auto-create war room for CRITICAL severity campaigns */
  autoCreateForCritical: boolean;
  /** Maximum activities to return in a single query */
  maxActivityLimit: number;
}

export type Priority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type WarRoomStatus = 'ACTIVE' | 'PAUSED' | 'CLOSED' | 'ARCHIVED';
export type ActivityActorType = 'USER' | 'HORIZON_BOT' | 'SYSTEM';
export type ActivityActionType =
  | 'MESSAGE'
  | 'BLOCK_CREATED'
  | 'BLOCK_REMOVED'
  | 'CAMPAIGN_LINKED'
  | 'STATUS_CHANGED'
  | 'PRIORITY_CHANGED'
  | 'MEMBER_JOINED'
  | 'MEMBER_LEFT'
  | 'ALERT_TRIGGERED';

export interface CreateWarRoomInput {
  tenantId: string;
  name: string;
  description?: string;
  priority?: Priority;
  leaderId?: string;
  campaignIds?: string[];
}

export interface WarRoomActivityInput {
  warRoomId: string;
  tenantId: string;
  actorType: ActivityActorType;
  actorId?: string;
  actorName: string;
  actionType: ActivityActionType;
  description: string;
  metadata?: Record<string, unknown>;
}

export interface WarRoomWithActivities extends WarRoom {
  activities: WarRoomActivity[];
  _count: {
    activities: number;
    campaignLinks: number;
  };
}

// Dashboard message types for war room updates
export interface WarRoomActivityMessage {
  type: 'war-room-activity';
  warRoomId: string;
  activity: {
    id: string;
    actorType: ActivityActorType;
    actorName: string;
    actionType: ActivityActionType;
    description: string;
    metadata?: Record<string, unknown>;
    createdAt: Date;
  };
  timestamp: number;
  [key: string]: unknown; // Index signature for Record<string, unknown> compatibility
}

export interface WarRoomStatusMessage {
  type: 'war-room-status';
  warRoomId: string;
  status: WarRoomStatus;
  timestamp: number;
  [key: string]: unknown; // Index signature for Record<string, unknown> compatibility
}

// =============================================================================
// War Room Service
// =============================================================================

export class WarRoomService {
  private prisma: PrismaClient;
  private logger: Logger;
  private config: WarRoomConfig;
  private dashboardGateway: DashboardGateway | null = null;

  constructor(prisma: PrismaClient, logger: Logger, config: WarRoomConfig) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'warroom' });
    this.config = config;
  }

  setDashboardGateway(gateway: DashboardGateway): void {
    this.dashboardGateway = gateway;
  }

  // ===========================================================================
  // War Room Lifecycle
  // ===========================================================================

  /**
   * Create a new war room
   * Uses a transaction to ensure atomicity of creation + activity log
   */
  async createWarRoom(input: CreateWarRoomInput): Promise<WarRoom> {
    return this.prisma.$transaction(async (tx) => {
      const warRoom = await tx.warRoom.create({
        data: {
          tenantId: input.tenantId,
          name: input.name,
          description: input.description,
          priority: input.priority ?? 'MEDIUM',
          leaderId: input.leaderId,
          status: 'ACTIVE',
        },
      });

      this.logger.info(
        { warRoomId: warRoom.id, name: warRoom.name, tenantId: input.tenantId },
        'Created war room'
      );

      // Log creation as system activity (within transaction)
      await tx.warRoomActivity.create({
        data: {
          warRoomId: warRoom.id,
          tenantId: input.tenantId,
          actorType: 'SYSTEM',
          actorName: 'System',
          actionType: 'STATUS_CHANGED',
          description: `War room "${warRoom.name}" created`,
          metadata: { status: 'ACTIVE', priority: input.priority ?? 'MEDIUM' } as Prisma.InputJsonValue,
        },
      });

      // Link campaigns if provided (within transaction)
      if (input.campaignIds?.length) {
        await tx.warRoomCampaign.createMany({
          data: input.campaignIds.map((campaignId) => ({
            warRoomId: warRoom.id,
            campaignId,
            linkedBy: 'SYSTEM',
          })),
          skipDuplicates: true,
        });

        // Log campaign links within transaction
        for (const campaignId of input.campaignIds) {
          await tx.warRoomActivity.create({
            data: {
              warRoomId: warRoom.id,
              tenantId: input.tenantId,
              actorType: 'SYSTEM',
              actorName: 'System',
              actionType: 'CAMPAIGN_LINKED',
              description: `Campaign ${campaignId} linked`,
              metadata: { campaignId } as Prisma.InputJsonValue,
            },
          });
        }
      }

      return warRoom;
    });
  }

  /**
   * Get war room by ID with recent activities
   */
  async getWarRoom(warRoomId: string, activityLimit = 50): Promise<WarRoomWithActivities | null> {
    return this.prisma.warRoom.findUnique({
      where: { id: warRoomId },
      include: {
        activities: {
          orderBy: { createdAt: 'desc' },
          take: Math.min(activityLimit, this.config.maxActivityLimit),
        },
        _count: {
          select: {
            activities: true,
            campaignLinks: true,
          },
        },
      },
    });
  }

  /**
   * List active war rooms for a tenant
   */
  async listActiveWarRooms(tenantId: string): Promise<WarRoom[]> {
    return this.prisma.warRoom.findMany({
      where: {
        tenantId,
        status: { in: ['ACTIVE', 'PAUSED'] },
      },
      orderBy: [{ priority: 'desc' }, { createdAt: 'desc' }],
    });
  }

  /**
   * Update war room status
   */
  async updateStatus(
    warRoomId: string,
    status: WarRoomStatus,
    actorId: string,
    actorName: string
  ): Promise<WarRoom> {
    const warRoom = await this.prisma.warRoom.update({
      where: { id: warRoomId },
      data: {
        status,
        closedAt: status === 'CLOSED' || status === 'ARCHIVED' ? new Date() : null,
      },
    });

    await this.addActivity({
      warRoomId,
      tenantId: warRoom.tenantId,
      actorType: 'USER',
      actorId,
      actorName,
      actionType: 'STATUS_CHANGED',
      description: `Status changed to ${status}`,
      metadata: { status },
    });

    // Broadcast status change
    this.broadcastStatusChange(warRoomId, status);

    this.logger.info({ warRoomId, status, actorId }, 'War room status updated');

    return warRoom;
  }

  /**
   * Update war room priority
   */
  async updatePriority(
    warRoomId: string,
    priority: Priority,
    actorId: string,
    actorName: string
  ): Promise<WarRoom> {
    const warRoom = await this.prisma.warRoom.update({
      where: { id: warRoomId },
      data: { priority },
    });

    await this.addActivity({
      warRoomId,
      tenantId: warRoom.tenantId,
      actorType: 'USER',
      actorId,
      actorName,
      actionType: 'PRIORITY_CHANGED',
      description: `Priority changed to ${priority}`,
      metadata: { priority },
    });

    this.logger.info({ warRoomId, priority, actorId }, 'War room priority updated');

    return warRoom;
  }

  // ===========================================================================
  // Activity Management
  // ===========================================================================

  /**
   * Add activity to war room
   */
  async addActivity(input: WarRoomActivityInput): Promise<WarRoomActivity> {
    const activity = await this.prisma.warRoomActivity.create({
      data: {
        warRoomId: input.warRoomId,
        tenantId: input.tenantId,
        actorType: input.actorType,
        actorId: input.actorId,
        actorName: input.actorName,
        actionType: input.actionType,
        description: input.description,
        metadata: (input.metadata ?? {}) as Prisma.InputJsonValue,
      },
    });

    // Broadcast activity to dashboards
    this.broadcastActivity(input.warRoomId, activity);

    return activity;
  }

  /**
   * Add user message to war room
   */
  async addMessage(
    warRoomId: string,
    tenantId: string,
    userId: string,
    userName: string,
    message: string
  ): Promise<WarRoomActivity> {
    return this.addActivity({
      warRoomId,
      tenantId,
      actorType: 'USER',
      actorId: userId,
      actorName: userName,
      actionType: 'MESSAGE',
      description: message,
    });
  }

  /**
   * Get activities for a war room with pagination
   */
  async getActivities(
    warRoomId: string,
    limit = 50,
    cursor?: string
  ): Promise<{ activities: WarRoomActivity[]; nextCursor?: string }> {
    const activities = await this.prisma.warRoomActivity.findMany({
      where: { warRoomId },
      orderBy: { createdAt: 'desc' },
      take: Math.min(limit, this.config.maxActivityLimit) + 1,
      cursor: cursor ? { id: cursor } : undefined,
      skip: cursor ? 1 : 0,
    });

    const hasMore = activities.length > limit;
    const results = hasMore ? activities.slice(0, -1) : activities;

    return {
      activities: results,
      nextCursor: hasMore ? results[results.length - 1]?.id : undefined,
    };
  }

  // ===========================================================================
  // Campaign Linking
  // ===========================================================================

  /**
   * Link campaigns to a war room
   * Uses a transaction to ensure atomicity of links + activity logs
   */
  async linkCampaigns(
    warRoomId: string,
    tenantId: string,
    campaignIds: string[],
    linkedBy: string
  ): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      const warRoom = await tx.warRoom.findUnique({
        where: { id: warRoomId },
      });

      if (!warRoom) {
        throw new Error(`War room ${warRoomId} not found`);
      }

      // Create links (ignore duplicates)
      await tx.warRoomCampaign.createMany({
        data: campaignIds.map((campaignId) => ({
          warRoomId,
          campaignId,
          linkedBy,
        })),
        skipDuplicates: true,
      });

      // Log each campaign link within transaction
      for (const campaignId of campaignIds) {
        await tx.warRoomActivity.create({
          data: {
            warRoomId,
            tenantId,
            actorType: linkedBy === 'SYSTEM' ? 'SYSTEM' : 'USER',
            actorId: linkedBy === 'SYSTEM' ? undefined : linkedBy,
            actorName: linkedBy === 'SYSTEM' ? 'System' : linkedBy,
            actionType: 'CAMPAIGN_LINKED',
            description: `Campaign ${campaignId} linked`,
            metadata: { campaignId } as Prisma.InputJsonValue,
          },
        });
      }
    });

    this.logger.info({ warRoomId, campaignIds }, 'Campaigns linked to war room');
  }

  /**
   * Get linked campaigns for a war room
   */
  async getLinkedCampaigns(warRoomId: string): Promise<Campaign[]> {
    const links = await this.prisma.warRoomCampaign.findMany({
      where: { warRoomId },
      include: { campaign: true },
    });

    return links.map((link) => link.campaign);
  }

  // ===========================================================================
  // Quick Actions
  // ===========================================================================

  /**
   * Create block from war room (quick action)
   * Uses a transaction to ensure atomicity of block + activity log
   */
  async createBlock(
    warRoomId: string,
    tenantId: string,
    block: BlocklistUpdate,
    actorId: string,
    actorName: string
  ): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      // Create the block in database
      await tx.blocklistEntry.create({
        data: {
          tenantId,
          blockType: block.blockType,
          indicator: block.indicator,
          source: 'WAR_ROOM',
          reason: block.reason ?? `Created from war room`,
          expiresAt: block.expiresAt,
          propagationStatus: 'PENDING',
        },
      });

      // Log activity within transaction
      await tx.warRoomActivity.create({
        data: {
          warRoomId,
          tenantId,
          actorType: 'USER',
          actorId,
          actorName,
          actionType: 'BLOCK_CREATED',
          description: `Blocked ${block.blockType}: ${block.indicator}`,
          metadata: {
            blockType: block.blockType,
            indicator: block.indicator,
            reason: block.reason,
          } as Prisma.InputJsonValue,
        },
      });
    });

    this.logger.info(
      { warRoomId, blockType: block.blockType, indicator: block.indicator, actorId },
      'Block created from war room'
    );
  }

  /**
   * Remove block from war room (quick action)
   */
  async removeBlock(
    warRoomId: string,
    tenantId: string,
    blockType: string,
    indicator: string,
    actorId: string,
    actorName: string
  ): Promise<void> {
    // Delete the block
    await this.prisma.blocklistEntry.deleteMany({
      where: {
        tenantId,
        blockType: blockType as 'IP' | 'IP_RANGE' | 'FINGERPRINT' | 'ASN' | 'USER_AGENT',
        indicator,
      },
    });

    // Log activity
    await this.addActivity({
      warRoomId,
      tenantId,
      actorType: 'USER',
      actorId,
      actorName,
      actionType: 'BLOCK_REMOVED',
      description: `Unblocked ${blockType}: ${indicator}`,
      metadata: { blockType, indicator },
    });

    this.logger.info(
      { warRoomId, blockType, indicator, actorId },
      'Block removed from war room'
    );
  }

  // ===========================================================================
  // @horizon-bot Automation
  // ===========================================================================

  /**
   * Auto-handle campaign detection (called by Broadcaster/Correlator)
   *
   * @horizon-bot will:
   * - Create war room for cross-tenant or CRITICAL campaigns
   * - Add alerts to existing war rooms
   */
  async onCampaignDetected(campaign: Campaign & { severity: string }): Promise<void> {
    const shouldAutoCreate =
      (this.config.autoCreateForCrossTenant && campaign.isCrossTenant) ||
      (this.config.autoCreateForCritical && campaign.severity === 'CRITICAL');

    if (shouldAutoCreate && campaign.tenantId) {
      // Check if war room already exists for this campaign
      const existing = await this.prisma.warRoomCampaign.findFirst({
        where: { campaignId: campaign.id },
        include: { warRoom: true },
      });

      if (!existing) {
        // Create war room
        const warRoom = await this.createWarRoom({
          tenantId: campaign.tenantId,
          name: `Incident: ${campaign.name}`,
          description: campaign.description ?? undefined,
          priority: campaign.severity as Priority,
          campaignIds: [campaign.id],
        });

        // @horizon-bot alert
        await this.addActivity({
          warRoomId: warRoom.id,
          tenantId: campaign.tenantId,
          actorType: 'HORIZON_BOT',
          actorName: '@horizon-bot',
          actionType: 'ALERT_TRIGGERED',
          description: campaign.isCrossTenant
            ? `Cross-tenant campaign detected! ${campaign.tenantsAffected} tenants affected.`
            : `CRITICAL campaign detected: ${campaign.name}`,
          metadata: {
            campaignId: campaign.id,
            severity: campaign.severity,
            isCrossTenant: campaign.isCrossTenant,
            tenantsAffected: campaign.tenantsAffected,
          },
        });

        this.logger.info(
          { warRoomId: warRoom.id, campaignId: campaign.id },
          '@horizon-bot created war room for campaign'
        );
      }
    }
  }

  /**
   * @horizon-bot notification for blocklist changes
   */
  async onBlockCreated(
    tenantId: string,
    blockType: string,
    indicator: string,
    source: string,
    reason?: string
  ): Promise<void> {
    // Find active war rooms for this tenant
    const activeWarRooms = await this.listActiveWarRooms(tenantId);

    for (const warRoom of activeWarRooms) {
      await this.addActivity({
        warRoomId: warRoom.id,
        tenantId,
        actorType: 'HORIZON_BOT',
        actorName: '@horizon-bot',
        actionType: 'BLOCK_CREATED',
        description: `Fleet intelligence blocked ${blockType}: ${indicator.substring(0, 20)}...`,
        metadata: { blockType, indicator, source, reason },
      });
    }
  }

  // ===========================================================================
  // Dashboard Broadcasting
  // ===========================================================================

  private broadcastActivity(warRoomId: string, activity: WarRoomActivity): void {
    if (!this.dashboardGateway) return;

    const message: WarRoomActivityMessage = {
      type: 'war-room-activity',
      warRoomId,
      activity: {
        id: activity.id,
        actorType: activity.actorType as ActivityActorType,
        actorName: activity.actorName,
        actionType: activity.actionType as ActivityActionType,
        description: activity.description,
        metadata: activity.metadata as Record<string, unknown> | undefined,
        createdAt: activity.createdAt,
      },
      timestamp: Date.now(),
    };

    this.dashboardGateway.broadcastToTenant(activity.tenantId, message);
  }

  private broadcastStatusChange(warRoomId: string, status: WarRoomStatus): void {
    if (!this.dashboardGateway) return;

    // Note: Would need to fetch tenantId from warRoom for proper tenant isolation
    // For now, broadcast to all dashboards via broadcastAll
    const _message: WarRoomStatusMessage = {
      type: 'war-room-status',
      warRoomId,
      status,
      timestamp: Date.now(),
    };

    // This would need tenantId for proper isolation
    // For now, we broadcast to all authenticated connections
    this.dashboardGateway.broadcastAll(_message);
  }

  // ===========================================================================
  // Stats
  // ===========================================================================

  async getStats(tenantId: string): Promise<{
    activeWarRooms: number;
    activitiesLast24h: number;
    blocksCreatedLast24h: number;
  }> {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const [activeWarRooms, activitiesLast24h, blocksCreatedLast24h] = await Promise.all([
      this.prisma.warRoom.count({
        where: { tenantId, status: 'ACTIVE' },
      }),
      this.prisma.warRoomActivity.count({
        where: { tenantId, createdAt: { gte: oneDayAgo } },
      }),
      this.prisma.warRoomActivity.count({
        where: {
          tenantId,
          actionType: 'BLOCK_CREATED',
          createdAt: { gte: oneDayAgo },
        },
      }),
    ]);

    return {
      activeWarRooms,
      activitiesLast24h,
      blocksCreatedLast24h,
    };
  }
}
