/**
 * Intel Service
 * IOC export and attack trend analysis for threat intelligence
 *
 * Features:
 * - IOC export in multiple formats (JSON, CSV, STIX 2.1)
 * - Attack volume trends and analytics
 * - Top threats by various dimensions
 * - Fleet-wide intelligence aggregation
 */

import type { PrismaClient, Threat } from '@prisma/client';
import type { Logger } from 'pino';
import type { Severity, ThreatType } from '../../types/protocol.js';

// =============================================================================
// Types
// =============================================================================

/** Supported export formats for IOCs and blocklists */
export type ExportFormat = 'json' | 'csv' | 'stix';

/** Supported blocklist export formats */
export type BlocklistExportFormat = 'json' | 'csv' | 'plain';

export interface IntelConfig {
  /** Maximum IOCs to export in a single request */
  maxExportLimit: number;
  /** Default time window for trends (hours) */
  defaultTrendWindowHours: number;
  /** Minimum risk score for IOC inclusion */
  minRiskScoreForExport: number;
}

export interface IOCExportOptions {
  /** Time range start */
  from?: Date;
  /** Time range end */
  to?: Date;
  /** Filter by threat types */
  threatTypes?: ThreatType[];
  /** Filter by minimum risk score */
  minRiskScore?: number;
  /** Include fleet threats only */
  fleetOnly?: boolean;
  /** Maximum records */
  limit?: number;
  /** Export format */
  format: 'json' | 'csv' | 'stix';
}

export interface IOC {
  indicator: string;
  type: ThreatType;
  riskScore: number;
  confidence: number;
  firstSeen: Date;
  lastSeen: Date;
  hitCount: number;
  tenantsAffected: number;
  isFleetThreat: boolean;
  tags: string[];
  metadata?: Record<string, unknown>;
}

export interface TrendDataPoint {
  timestamp: Date;
  value: number;
}

export interface AttackTrends {
  timeRange: { from: Date; to: Date };
  totalSignals: number;
  totalThreats: number;
  totalBlocks: number;
  signalsByType: Record<string, number>;
  signalsBySeverity: Record<string, number>;
  volumeOverTime: TrendDataPoint[];
  topIPs: Array<{ ip: string; count: number; riskScore: number }>;
  topFingerprints: Array<{ ip: string; count: number; riskScore: number }>;
  topCampaigns: Array<{ id: string; name: string; severity: Severity; hitCount: number }>;
}

export interface FleetIntelSummary {
  activeSensors: number;
  totalThreats: number;
  fleetThreats: number;
  crossTenantCampaigns: number;
  blockedIndicators: number;
  signalsLast24h: number;
  topAttackTypes: Array<{ type: string; count: number; percentage: number }>;
}

// STIX 2.1 Types (simplified)
interface STIXBundle {
  type: 'bundle';
  id: string;
  objects: STIXObject[];
}

interface STIXObject {
  type: string;
  spec_version: '2.1';
  id: string;
  created: string;
  modified: string;
  [key: string]: unknown;
}

// =============================================================================
// Intel Service
// =============================================================================

export class IntelService {
  private prisma: PrismaClient;
  private logger: Logger;
  private config: IntelConfig;

  constructor(prisma: PrismaClient, logger: Logger, config: IntelConfig) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'intel' });
    this.config = config;
  }

  // ===========================================================================
  // IOC Export
  // ===========================================================================

  /**
   * Export IOCs in specified format
   */
  async exportIOCs(options: IOCExportOptions): Promise<string> {
    this.logger.info({ format: options.format, limit: options.limit }, 'Exporting IOCs');
    const iocs = await this.getIOCs(options);

    switch (options.format) {
      case 'json':
        return this.formatAsJSON(iocs);
      case 'csv':
        return this.formatAsCSV(iocs);
      case 'stix':
        return this.formatAsSTIX(iocs);
      default: {
        // Exhaustive check - TypeScript will error if a format is not handled
        const _exhaustive: never = options.format;
        throw new Error(`Unsupported format: ${_exhaustive}`);
      }
    }
  }

  /**
   * Get IOCs from threats and blocklist
   */
  private async getIOCs(options: IOCExportOptions): Promise<IOC[]> {
    const limit = Math.min(options.limit ?? 1000, this.config.maxExportLimit);
    const minRiskScore = options.minRiskScore ?? this.config.minRiskScoreForExport;

    // Build where clause
    const where: Record<string, unknown> = {
      riskScore: { gte: minRiskScore },
    };

    if (options.from || options.to) {
      where.lastSeenAt = {};
      if (options.from) (where.lastSeenAt as Record<string, Date>).gte = options.from;
      if (options.to) (where.lastSeenAt as Record<string, Date>).lte = options.to;
    }

    if (options.threatTypes?.length) {
      where.threatType = { in: options.threatTypes };
    }

    if (options.fleetOnly) {
      where.isFleetThreat = true;
    }

    const threats = await this.prisma.threat.findMany({
      where,
      orderBy: { riskScore: 'desc' },
      take: limit,
    });

    return threats.map((threat) => this.threatToIOC(threat));
  }

  /**
   * Convert Threat to IOC format
   */
  private threatToIOC(threat: Threat): IOC {
    const metadata = threat.metadata as Record<string, unknown> | null;
    const tags: string[] = [];

    // Generate tags based on threat properties
    if (threat.isFleetThreat) tags.push('fleet-threat');
    if (threat.tenantsAffected > 1) tags.push('cross-tenant');
    if (threat.riskScore >= 80) tags.push('high-risk');
    if (threat.hitCount >= 100) tags.push('high-volume');

    // Calculate confidence from risk score, clamped to [0, 1]
    const rawConfidence = (threat.fleetRiskScore ?? threat.riskScore) / 100;
    const confidence = Math.max(0, Math.min(1, rawConfidence));

    return {
      indicator: threat.indicator,
      type: threat.threatType as ThreatType,
      riskScore: threat.riskScore,
      confidence,
      firstSeen: threat.firstSeenAt,
      lastSeen: threat.lastSeenAt,
      hitCount: threat.hitCount,
      tenantsAffected: threat.tenantsAffected,
      isFleetThreat: threat.isFleetThreat,
      tags,
      metadata: metadata ?? undefined,
    };
  }

  /**
   * Format IOCs as JSON
   */
  private formatAsJSON(iocs: IOC[]): string {
    return JSON.stringify(
      {
        exported_at: new Date().toISOString(),
        count: iocs.length,
        iocs: iocs.map((ioc) => ({
          indicator: ioc.indicator,
          type: ioc.type,
          risk_score: ioc.riskScore,
          confidence: ioc.confidence,
          first_seen: ioc.firstSeen.toISOString(),
          last_seen: ioc.lastSeen.toISOString(),
          hit_count: ioc.hitCount,
          tenants_affected: ioc.tenantsAffected,
          is_fleet_threat: ioc.isFleetThreat,
          tags: ioc.tags,
        })),
      },
      null,
      2
    );
  }

  /**
   * Format IOCs as CSV
   */
  private formatAsCSV(iocs: IOC[]): string {
    const headers = [
      'indicator',
      'type',
      'risk_score',
      'confidence',
      'first_seen',
      'last_seen',
      'hit_count',
      'tenants_affected',
      'is_fleet_threat',
      'tags',
    ];

    const rows = iocs.map((ioc) => [
      this.escapeCSV(ioc.indicator),
      ioc.type,
      ioc.riskScore.toString(),
      ioc.confidence.toFixed(2),
      ioc.firstSeen.toISOString(),
      ioc.lastSeen.toISOString(),
      ioc.hitCount.toString(),
      ioc.tenantsAffected.toString(),
      ioc.isFleetThreat.toString(),
      this.escapeCSV(ioc.tags.join(';')),
    ]);

    return [headers.join(','), ...rows.map((row) => row.join(','))].join('\n');
  }

  /**
   * Escape CSV field
   */
  private escapeCSV(value: string): string {
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
  }

  /**
   * Format IOCs as STIX 2.1 bundle
   */
  private formatAsSTIX(iocs: IOC[]): string {
    const bundle: STIXBundle = {
      type: 'bundle',
      id: `bundle--${this.generateUUID()}`,
      objects: iocs.map((ioc) => this.iocToSTIX(ioc)),
    };

    return JSON.stringify(bundle, null, 2);
  }

  /**
   * Convert IOC to STIX 2.1 Indicator
   */
  private iocToSTIX(ioc: IOC): STIXObject {
    const now = new Date().toISOString();
    const pattern = this.getSTIXPattern(ioc);

    return {
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${this.generateUUID()}`,
      created: ioc.firstSeen.toISOString(),
      modified: now,
      name: `${ioc.type}: ${ioc.indicator}`,
      description: `Threat indicator detected by Signal Horizon fleet intelligence`,
      indicator_types: this.getSTIXIndicatorTypes(ioc),
      pattern,
      pattern_type: 'stix',
      valid_from: ioc.firstSeen.toISOString(),
      valid_until: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days
      confidence: Math.round(ioc.confidence * 100),
      labels: ioc.tags,
      external_references: [
        {
          source_name: 'Signal Horizon',
          description: 'Fleet intelligence threat detection',
        },
      ],
      custom_properties: {
        x_signal_horizon_risk_score: ioc.riskScore,
        x_signal_horizon_hit_count: ioc.hitCount,
        x_signal_horizon_tenants_affected: ioc.tenantsAffected,
        x_signal_horizon_is_fleet_threat: ioc.isFleetThreat,
      },
    };
  }

  /**
   * Generate STIX pattern from IOC
   */
  private getSTIXPattern(ioc: IOC): string {
    switch (ioc.type) {
      case 'IP':
        return `[ipv4-addr:value = '${ioc.indicator}']`;
      case 'FINGERPRINT':
        return `[x-signal-horizon-fingerprint:value = '${ioc.indicator}']`;
      case 'ASN':
        return `[autonomous-system:number = ${ioc.indicator}]`;
      case 'USER_AGENT':
        return `[http-request-ext:request_header.'User-Agent' = '${ioc.indicator}']`;
      case 'TLS_FINGERPRINT':
        return `[x-signal-horizon-tls-fingerprint:value = '${ioc.indicator}']`;
      default:
        return `[x-signal-horizon-indicator:value = '${ioc.indicator}']`;
    }
  }

  /**
   * Get STIX indicator types
   */
  private getSTIXIndicatorTypes(ioc: IOC): string[] {
    const types: string[] = ['malicious-activity'];

    if (ioc.type === 'IP') types.push('anomalous-activity');
    if (ioc.isFleetThreat) types.push('attribution');

    return types;
  }

  /**
   * Generate UUID v4
   */
  private generateUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }

  // ===========================================================================
  // Attack Trends
  // ===========================================================================

  /**
   * Get attack trends for a time window
   */
  async getAttackTrends(
    tenantId: string | null,
    windowHours = this.config.defaultTrendWindowHours
  ): Promise<AttackTrends> {
    const to = new Date();
    const from = new Date(to.getTime() - windowHours * 60 * 60 * 1000);

    const tenantFilter = tenantId ? { tenantId } : {};

    // Parallel queries for efficiency
    const [
      totalSignals,
      totalThreats,
      totalBlocks,
      signalsByType,
      signalsBySeverity,
      topIPs,
      topFingerprints,
      topCampaigns,
    ] = await Promise.all([
      // Total signals
      this.prisma.signal.count({
        where: { ...tenantFilter, createdAt: { gte: from, lte: to } },
      }),

      // Total threats
      this.prisma.threat.count({
        where: { ...tenantFilter, lastSeenAt: { gte: from, lte: to } },
      }),

      // Total blocks
      this.prisma.blocklistEntry.count({
        where: { ...tenantFilter, createdAt: { gte: from, lte: to } },
      }),

      // Signals by type
      this.prisma.signal.groupBy({
        by: ['signalType'],
        where: { ...tenantFilter, createdAt: { gte: from, lte: to } },
        _count: { _all: true },
      }),

      // Signals by severity
      this.prisma.signal.groupBy({
        by: ['severity'],
        where: { ...tenantFilter, createdAt: { gte: from, lte: to } },
        _count: { _all: true },
      }),

      // Top IPs
      this.getTopIndicators(tenantId, 'IP', from, to, 10),

      // Top fingerprints
      this.getTopIndicators(tenantId, 'FINGERPRINT', from, to, 10),

      // Top campaigns
      this.getTopCampaigns(tenantId, from, to, 10),
    ]);

    // Calculate volume over time (hourly buckets)
    const volumeOverTime = await this.getVolumeOverTime(tenantId, from, to);

    return {
      timeRange: { from, to },
      totalSignals,
      totalThreats,
      totalBlocks,
      signalsByType: Object.fromEntries(
        signalsByType.map((s) => [s.signalType, s._count._all])
      ),
      signalsBySeverity: Object.fromEntries(
        signalsBySeverity.map((s) => [s.severity, s._count._all])
      ),
      volumeOverTime,
      topIPs,
      topFingerprints,
      topCampaigns,
    };
  }

  /**
   * Get top indicators by hit count
   */
  private async getTopIndicators(
    tenantId: string | null,
    threatType: string,
    from: Date,
    to: Date,
    limit: number
  ): Promise<Array<{ ip: string; count: number; riskScore: number }>> {
    const tenantFilter = tenantId ? { tenantId } : {};

    const threats = await this.prisma.threat.findMany({
      where: {
        ...tenantFilter,
        threatType: threatType as ThreatType,
        lastSeenAt: { gte: from, lte: to },
      },
      orderBy: { hitCount: 'desc' },
      take: limit,
      select: {
        indicator: true,
        hitCount: true,
        riskScore: true,
      },
    });

    return threats.map((t) => ({
      ip: t.indicator,
      count: t.hitCount,
      riskScore: t.riskScore,
    }));
  }

  /**
   * Get top campaigns
   */
  private async getTopCampaigns(
    tenantId: string | null,
    from: Date,
    to: Date,
    limit: number
  ): Promise<Array<{ id: string; name: string; severity: Severity; hitCount: number }>> {
    const tenantFilter = tenantId ? { tenantId } : {};

    const campaigns = await this.prisma.campaign.findMany({
      where: {
        ...tenantFilter,
        lastActivityAt: { gte: from, lte: to },
        status: 'ACTIVE',
      },
      orderBy: { tenantsAffected: 'desc' },
      take: limit,
      select: {
        id: true,
        name: true,
        severity: true,
        tenantsAffected: true,
      },
    });

    return campaigns.map((c) => ({
      id: c.id,
      name: c.name,
      severity: c.severity as Severity,
      hitCount: c.tenantsAffected,
    }));
  }

  /**
   * Get signal volume over time (hourly buckets)
   */
  private async getVolumeOverTime(
    tenantId: string | null,
    from: Date,
    to: Date
  ): Promise<TrendDataPoint[]> {
    // Note: This is a simplified implementation. In production, you'd use
    // a proper time-series query with date_trunc or similar.
    const tenantFilter = tenantId ? { tenantId } : {};

    const signals = await this.prisma.signal.findMany({
      where: { ...tenantFilter, createdAt: { gte: from, lte: to } },
      select: { createdAt: true },
      orderBy: { createdAt: 'asc' },
    });

    // Group into hourly buckets
    const buckets = new Map<number, number>();
    const hourMs = 60 * 60 * 1000;

    for (const signal of signals) {
      const bucketTime = Math.floor(signal.createdAt.getTime() / hourMs) * hourMs;
      buckets.set(bucketTime, (buckets.get(bucketTime) ?? 0) + 1);
    }

    // Fill in missing hours with zeros
    const result: TrendDataPoint[] = [];
    let currentTime = Math.floor(from.getTime() / hourMs) * hourMs;
    const endTime = to.getTime();

    while (currentTime <= endTime) {
      result.push({
        timestamp: new Date(currentTime),
        value: buckets.get(currentTime) ?? 0,
      });
      currentTime += hourMs;
    }

    return result;
  }

  // ===========================================================================
  // Fleet Intelligence Summary
  // ===========================================================================

  /**
   * Get fleet-wide intelligence summary
   */
  async getFleetSummary(): Promise<FleetIntelSummary> {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const [
      activeSensors,
      totalThreats,
      fleetThreats,
      crossTenantCampaigns,
      blockedIndicators,
      signalsLast24h,
      signalsByType,
    ] = await Promise.all([
      // Active sensors (connected in last hour)
      this.prisma.sensor.count({
        where: { lastHeartbeat: { gte: new Date(Date.now() - 60 * 60 * 1000) } },
      }),

      // Total threats
      this.prisma.threat.count(),

      // Fleet threats
      this.prisma.threat.count({ where: { isFleetThreat: true } }),

      // Cross-tenant campaigns
      this.prisma.campaign.count({
        where: { isCrossTenant: true, status: 'ACTIVE' },
      }),

      // Blocked indicators
      this.prisma.blocklistEntry.count(),

      // Signals last 24h
      this.prisma.signal.count({
        where: { createdAt: { gte: oneDayAgo } },
      }),

      // Signals by type (last 24h)
      this.prisma.signal.groupBy({
        by: ['signalType'],
        where: { createdAt: { gte: oneDayAgo } },
        _count: { _all: true },
      }),
    ]);

    // Calculate percentages for top attack types
    const totalByType = signalsByType.reduce((sum, s) => sum + s._count._all, 0);
    const topAttackTypes = signalsByType
      .sort((a, b) => b._count._all - a._count._all)
      .slice(0, 5)
      .map((s) => ({
        type: s.signalType,
        count: s._count._all,
        percentage: totalByType > 0 ? (s._count._all / totalByType) * 100 : 0,
      }));

    return {
      activeSensors,
      totalThreats,
      fleetThreats,
      crossTenantCampaigns,
      blockedIndicators,
      signalsLast24h,
      topAttackTypes,
    };
  }

  // ===========================================================================
  // Blocklist Export
  // ===========================================================================

  /**
   * Export blocklist entries
   */
  async exportBlocklist(
    tenantId: string | null,
    format: 'json' | 'csv' | 'plain'
  ): Promise<string> {
    const where = tenantId
      ? { OR: [{ tenantId }, { tenantId: null }] } // Tenant-specific + fleet-wide
      : { tenantId: null }; // Fleet-wide only

    const entries = await this.prisma.blocklistEntry.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: this.config.maxExportLimit,
    });

    switch (format) {
      case 'json':
        return JSON.stringify(
          {
            exported_at: new Date().toISOString(),
            count: entries.length,
            entries: entries.map((e) => ({
              type: e.blockType,
              indicator: e.indicator,
              source: e.source,
              reason: e.reason,
              created_at: e.createdAt.toISOString(),
              expires_at: e.expiresAt?.toISOString() ?? null,
            })),
          },
          null,
          2
        );

      case 'csv':
        const headers = ['type', 'indicator', 'source', 'reason', 'created_at', 'expires_at'];
        const rows = entries.map((e) => [
          e.blockType,
          this.escapeCSV(e.indicator),
          e.source,
          this.escapeCSV(e.reason ?? ''),
          e.createdAt.toISOString(),
          e.expiresAt?.toISOString() ?? '',
        ]);
        return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');

      case 'plain':
        // Simple line-separated list of indicators
        return entries.map((e) => e.indicator).join('\n');

      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }
}
