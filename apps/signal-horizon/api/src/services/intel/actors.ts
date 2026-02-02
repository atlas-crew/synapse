/**
 * Actor Service
 * Aggregates threat actor profiles from campaigns and threats
 */

import type { PrismaClient, Severity } from '@prisma/client';
import type { Logger } from 'pino';

// =============================================================================
// Types
// =============================================================================

export interface ActorListOptions {
  minRiskScore?: number;
  hasActiveCampaigns?: boolean;
  limit?: number;
  offset?: number;
  tenantId?: string | null; // null = fleet-wide
}

export interface ActorProfile {
  id: string;
  name: string;
  infrastructure: {
    topIPs: Array<{ ip: string; hitCount: number; riskScore: number }>;
    topASNs: Array<{ asn: string; hitCount: number }>;
    topFingerprints: Array<{ fingerprint: string; hitCount: number }>;
  };
  campaigns: Array<{
    id: string;
    name: string;
    severity: Severity;
    confidence: number;
    role: string;
  }>;
  timeline: {
    firstSeen: Date;
    lastSeen: Date;
    activityPattern: 'sporadic' | 'sustained' | 'burst';
  };
  riskScore: number;
  tenantsAffected: number;
}

export interface ActorInfrastructure {
  ips: Array<{ indicator: string; hitCount: number; riskScore: number; lastSeen: Date }>;
  asns: Array<{ indicator: string; hitCount: number; riskScore: number }>;
  fingerprints: Array<{ indicator: string; hitCount: number; riskScore: number }>;
  userAgents: Array<{ indicator: string; hitCount: number }>;
}

export interface ActorTimelineEntry {
  timestamp: Date;
  signalCount: number;
  blockCount: number;
}

export interface ActorGraphNode {
  data: {
    id: string;
    label: string;
    type: string;
    details?: Record<string, string | number>;
  };
}

export interface ActorGraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
    label: string;
    weight?: number;
  };
}

export interface ActorInfrastructureGraph {
  fingerprint: string;
  windowHours: number;
  nodes: ActorGraphNode[];
  edges: ActorGraphEdge[];
}

// =============================================================================
// Actor Service
// =============================================================================

export class ActorService {
  private prisma: PrismaClient;
  private logger: Logger;

  constructor(prisma: PrismaClient, logger: Logger) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'actor' });
  }

  /**
   * List aggregated actor profiles
   * Aggregates from campaigns that have threats with primary_actor role
   */
  async listActors(options: ActorListOptions): Promise<ActorProfile[]> {
    this.logger.debug({ options }, 'Listing actors');

    // Query campaigns that have threats with primary_actor role
    const campaignsWithActors = await this.prisma.campaign.findMany({
      where: {
        ...(options.tenantId ? { tenantId: options.tenantId } : {}),
        ...(options.hasActiveCampaigns ? { status: 'ACTIVE' } : {}),
        threatLinks: {
          some: {
            role: 'primary_actor',
          },
        },
      },
      include: {
        threatLinks: {
          where: { role: { in: ['primary_actor', 'infrastructure'] } },
          include: { threat: true },
        },
      },
      take: options.limit ?? 50,
      skip: options.offset ?? 0,
      orderBy: { lastActivityAt: 'desc' },
    });

    // Build actor profiles
    const actors: ActorProfile[] = [];

    for (const campaign of campaignsWithActors) {
      const primaryActor = campaign.threatLinks.find((l) => l.role === 'primary_actor');
      if (!primaryActor) continue;

      const infrastructureThreats = campaign.threatLinks.filter((l) => l.role === 'infrastructure');

      // Calculate aggregate risk score
      const allThreats = campaign.threatLinks.map((l) => l.threat);
      const avgRiskScore =
        allThreats.length > 0
          ? allThreats.reduce((sum, t) => sum + t.riskScore, 0) / allThreats.length
          : 0;

      if (options.minRiskScore && avgRiskScore < options.minRiskScore) continue;

      // Aggregate infrastructure by type
      const ips = infrastructureThreats
        .filter((t) => t.threat.threatType === 'IP')
        .map((t) => ({
          ip: t.threat.indicator,
          hitCount: t.threat.hitCount,
          riskScore: t.threat.riskScore,
        }));

      const asns = infrastructureThreats
        .filter((t) => t.threat.threatType === 'ASN')
        .map((t) => ({
          asn: t.threat.indicator,
          hitCount: t.threat.hitCount,
        }));

      const fingerprints = infrastructureThreats
        .filter((t) => t.threat.threatType === 'FINGERPRINT')
        .map((t) => ({
          fingerprint: t.threat.indicator,
          hitCount: t.threat.hitCount,
        }));

      // Determine activity pattern based on recency
      const activityPattern = this.determineActivityPattern(campaign.lastActivityAt);

      actors.push({
        id: campaign.id, // Use campaign ID as actor ID
        name: campaign.name,
        infrastructure: {
          topIPs: ips.slice(0, 10),
          topASNs: asns.slice(0, 5),
          topFingerprints: fingerprints.slice(0, 5),
        },
        campaigns: [
          {
            id: campaign.id,
            name: campaign.name,
            severity: campaign.severity as Severity,
            confidence: campaign.confidence,
            role: 'primary',
          },
        ],
        timeline: {
          firstSeen: campaign.firstSeenAt,
          lastSeen: campaign.lastActivityAt,
          activityPattern,
        },
        riskScore: avgRiskScore,
        tenantsAffected: campaign.tenantsAffected,
      });
    }

    return actors;
  }

  /**
   * Get a specific actor profile by ID
   */
  async getActor(actorId: string, tenantId?: string): Promise<ActorProfile | null> {
    this.logger.debug({ actorId, tenantId }, 'Getting actor');

    const campaign = await this.prisma.campaign.findFirst({
      where: {
        id: actorId,
        ...(tenantId ? { tenantId } : {}),
      },
      include: {
        threatLinks: {
          include: { threat: true },
        },
      },
    });

    if (!campaign) return null;

    const infrastructureThreats = campaign.threatLinks.filter((l) => l.role === 'infrastructure');
    const allThreats = campaign.threatLinks.map((l) => l.threat);
    const avgRiskScore =
      allThreats.length > 0
        ? allThreats.reduce((sum, t) => sum + t.riskScore, 0) / allThreats.length
        : 0;

    const ips = infrastructureThreats
      .filter((t) => t.threat.threatType === 'IP')
      .map((t) => ({
        ip: t.threat.indicator,
        hitCount: t.threat.hitCount,
        riskScore: t.threat.riskScore,
      }));

    const asns = infrastructureThreats
      .filter((t) => t.threat.threatType === 'ASN')
      .map((t) => ({
        asn: t.threat.indicator,
        hitCount: t.threat.hitCount,
      }));

    const fingerprints = infrastructureThreats
      .filter((t) => t.threat.threatType === 'FINGERPRINT')
      .map((t) => ({
        fingerprint: t.threat.indicator,
        hitCount: t.threat.hitCount,
      }));

    const activityPattern = this.determineActivityPattern(campaign.lastActivityAt);

    return {
      id: campaign.id,
      name: campaign.name,
      infrastructure: {
        topIPs: ips.slice(0, 10),
        topASNs: asns.slice(0, 5),
        topFingerprints: fingerprints.slice(0, 5),
      },
      campaigns: [
        {
          id: campaign.id,
          name: campaign.name,
          severity: campaign.severity as Severity,
          confidence: campaign.confidence,
          role: 'primary',
        },
      ],
      timeline: {
        firstSeen: campaign.firstSeenAt,
        lastSeen: campaign.lastActivityAt,
        activityPattern,
      },
      riskScore: avgRiskScore,
      tenantsAffected: campaign.tenantsAffected,
    };
  }

  /**
   * Get detailed infrastructure for an actor
   */
  async getActorInfrastructure(actorId: string): Promise<ActorInfrastructure | null> {
    this.logger.debug({ actorId }, 'Getting actor infrastructure');

    const campaign = await this.prisma.campaign.findUnique({
      where: { id: actorId },
      include: {
        threatLinks: {
          include: { threat: true },
        },
      },
    });

    if (!campaign) return null;

    const threats = campaign.threatLinks.map((l) => l.threat);

    return {
      ips: threats
        .filter((t) => t.threatType === 'IP')
        .map((t) => ({
          indicator: t.indicator,
          hitCount: t.hitCount,
          riskScore: t.riskScore,
          lastSeen: t.lastSeenAt,
        }))
        .sort((a, b) => b.hitCount - a.hitCount),
      asns: threats
        .filter((t) => t.threatType === 'ASN')
        .map((t) => ({
          indicator: t.indicator,
          hitCount: t.hitCount,
          riskScore: t.riskScore,
        }))
        .sort((a, b) => b.hitCount - a.hitCount),
      fingerprints: threats
        .filter((t) => t.threatType === 'FINGERPRINT')
        .map((t) => ({
          indicator: t.indicator,
          hitCount: t.hitCount,
          riskScore: t.riskScore,
        }))
        .sort((a, b) => b.hitCount - a.hitCount),
      userAgents: threats
        .filter((t) => t.threatType === 'USER_AGENT')
        .map((t) => ({
          indicator: t.indicator,
          hitCount: t.hitCount,
        }))
        .sort((a, b) => b.hitCount - a.hitCount),
    };
  }

  /**
   * Get timeline data for an actor
   */
  async getActorTimeline(
    actorId: string,
    windowHours = 168 // 7 days default
  ): Promise<ActorTimelineEntry[]> {
    this.logger.debug({ actorId, windowHours }, 'Getting actor timeline');

    const campaign = await this.prisma.campaign.findUnique({
      where: { id: actorId },
      include: {
        threatLinks: {
          include: { threat: true },
        },
      },
    });

    if (!campaign) return [];

    const threats = campaign.threatLinks.map((l) => l.threat);
    const threatIndicators = threats.map((t) => t.indicator);

    if (threatIndicators.length === 0) {
      return this.generateEmptyTimeline(windowHours);
    }

    const since = new Date(Date.now() - windowHours * 60 * 60 * 1000);

    // Get signals related to these threats
    const signals = await this.prisma.signal.findMany({
      where: {
        createdAt: { gte: since },
        OR: [{ sourceIp: { in: threatIndicators } }, { fingerprint: { in: threatIndicators } }],
      },
      select: { createdAt: true },
      orderBy: { createdAt: 'asc' },
    });

    // Get blocks
    const blocks = await this.prisma.blocklistEntry.findMany({
      where: {
        createdAt: { gte: since },
        indicator: { in: threatIndicators },
      },
      select: { createdAt: true },
    });

    // Group into hourly buckets
    const hourMs = 60 * 60 * 1000;
    const timeline = new Map<number, { signalCount: number; blockCount: number }>();

    // Initialize buckets
    for (let i = 0; i < windowHours; i++) {
      const bucketTime = Math.floor((Date.now() - (windowHours - i) * hourMs) / hourMs) * hourMs;
      timeline.set(bucketTime, { signalCount: 0, blockCount: 0 });
    }

    // Count signals
    for (const signal of signals) {
      const bucketTime = Math.floor(signal.createdAt.getTime() / hourMs) * hourMs;
      const bucket = timeline.get(bucketTime);
      if (bucket) bucket.signalCount++;
    }

    // Count blocks
    for (const block of blocks) {
      const bucketTime = Math.floor(block.createdAt.getTime() / hourMs) * hourMs;
      const bucket = timeline.get(bucketTime);
      if (bucket) bucket.blockCount++;
    }

    return Array.from(timeline.entries()).map(([timestamp, data]) => ({
      timestamp: new Date(timestamp),
      ...data,
    }));
  }

  /**
   * Build a graph linking a fingerprint to IPs and sensors across the fleet.
   */
  async getActorInfrastructureGraph(
    fingerprint: string,
    options: { tenantId?: string | null; windowHours?: number } = {}
  ): Promise<ActorInfrastructureGraph | null> {
    if (!fingerprint) return null;

    const windowHours = options.windowHours ?? 168;
    const since = new Date(Date.now() - windowHours * 60 * 60 * 1000);

    const where = {
      fingerprint,
      createdAt: { gte: since },
      ...(options.tenantId ? { tenantId: options.tenantId } : {}),
    };

    const signals = await this.prisma.signal.findMany({
      where,
      select: {
        sourceIp: true,
        sensorId: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'asc' },
    });

    if (signals.length === 0) return null;

    const ipMap = new Map<
      string,
      {
        count: number;
        lastSeen: Date;
        sensors: Map<string, number>;
      }
    >();
    const sensorTotals = new Map<string, number>();

    for (const signal of signals) {
      if (!signal.sourceIp) continue;
      const sensorId = signal.sensorId ?? 'unknown';
      const entry = ipMap.get(signal.sourceIp) ?? {
        count: 0,
        lastSeen: signal.createdAt,
        sensors: new Map<string, number>(),
      };

      entry.count += 1;
      entry.lastSeen = signal.createdAt > entry.lastSeen ? signal.createdAt : entry.lastSeen;
      entry.sensors.set(sensorId, (entry.sensors.get(sensorId) ?? 0) + 1);
      ipMap.set(signal.sourceIp, entry);

      sensorTotals.set(sensorId, (sensorTotals.get(sensorId) ?? 0) + 1);
    }

    const nodes: ActorGraphNode[] = [];
    const edges: ActorGraphEdge[] = [];
    const actorNodeId = `actor:${fingerprint}`;
    let edgeIndex = 0;

    nodes.push({
      data: {
        id: actorNodeId,
        label: this.formatFingerprintLabel(fingerprint),
        type: 'actor',
        details: {
          fingerprint,
        },
      },
    });

    const sensorNodeIds = new Map<string, string>();

    for (const [ip, data] of ipMap.entries()) {
      const ipNodeId = `ip:${ip}`;
      nodes.push({
        data: {
          id: ipNodeId,
          label: ip,
          type: 'ip',
          details: {
            hitCount: data.count,
            lastSeen: data.lastSeen.toISOString(),
          },
        },
      });

      edges.push({
        data: {
          id: `edge-${edgeIndex++}`,
          source: actorNodeId,
          target: ipNodeId,
          label: 'uses',
          weight: data.count,
        },
      });

      for (const [sensorId, count] of data.sensors.entries()) {
        let sensorNodeId = sensorNodeIds.get(sensorId);
        if (!sensorNodeId) {
          sensorNodeId = `sensor:${sensorId}`;
          sensorNodeIds.set(sensorId, sensorNodeId);

          nodes.push({
            data: {
              id: sensorNodeId,
              label: sensorId,
              type: 'sensor',
              details: {
                hitCount: sensorTotals.get(sensorId) ?? count,
              },
            },
          });
        }

        edges.push({
          data: {
            id: `edge-${edgeIndex++}`,
            source: ipNodeId,
            target: sensorNodeId,
            label: 'observed_on',
            weight: count,
          },
        });
      }
    }

    return {
      fingerprint,
      windowHours,
      nodes,
      edges,
    };
  }

  // ===========================================================================
  // Private Helpers
  // ===========================================================================

  /**
   * Determine activity pattern based on last activity timestamp
   */
  private determineActivityPattern(lastActivityAt: Date): 'sporadic' | 'sustained' | 'burst' {
    const now = new Date();
    const daysSinceActivity =
      (now.getTime() - lastActivityAt.getTime()) / (1000 * 60 * 60 * 24);

    if (daysSinceActivity < 1) return 'burst';
    if (daysSinceActivity < 7) return 'sustained';
    return 'sporadic';
  }

  /**
   * Generate empty timeline with zero counts
   */
  private generateEmptyTimeline(windowHours: number): ActorTimelineEntry[] {
    const hourMs = 60 * 60 * 1000;
    const result: ActorTimelineEntry[] = [];

    for (let i = 0; i < windowHours; i++) {
      const bucketTime = Math.floor((Date.now() - (windowHours - i) * hourMs) / hourMs) * hourMs;
      result.push({
        timestamp: new Date(bucketTime),
        signalCount: 0,
        blockCount: 0,
      });
    }

    return result;
  }

  private formatFingerprintLabel(fingerprint: string): string {
    const trimmed = fingerprint.trim();
    if (trimmed.length <= 10) return trimmed;
    return `FP-${trimmed.slice(0, 8)}`;
  }
}
