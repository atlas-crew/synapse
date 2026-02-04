/**
 * Fleet Intelligence Service
 * Periodically ingests per-sensor intel snapshots and serves fleet-wide queries.
 */

import type { Prisma, PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type {
  SynapseProxyService,
  ActorListResponse,
  SessionListResponse,
  CampaignsRawResponse,
  ProfilesListResponse,
  PayloadStatsResponse,
  PayloadEndpointsResponse,
  PayloadAnomaliesResponse,
  PayloadBandwidthStats,
} from '../synapse-proxy.js';

export interface FleetIntelConfig {
  pollIntervalMs?: number;
  maxConcurrentSensors?: number;
  actorLimit?: number;
  sessionLimit?: number;
  campaignLimit?: number;
  payloadEndpointLimit?: number;
  payloadAnomalyLimit?: number;
}

export interface FleetIntelIngestSummary {
  sensorsProcessed: number;
  sensorsSucceeded: number;
  sensorsFailed: number;
  errors: Array<{ sensorId: string; error: string }>;
}

export class FleetIntelService {
  private logger: Logger;
  private pollTimer: NodeJS.Timeout | null = null;
  private pollInFlight = false;
  private config: Required<FleetIntelConfig>;

  constructor(
    private prisma: PrismaClient,
    logger: Logger,
    private synapseProxy: SynapseProxyService,
    config: FleetIntelConfig = {}
  ) {
    this.logger = logger.child({ service: 'fleet-intel' });
    this.config = {
      pollIntervalMs: config.pollIntervalMs ?? 60000,
      maxConcurrentSensors: config.maxConcurrentSensors ?? 5,
      actorLimit: config.actorLimit ?? 200,
      sessionLimit: config.sessionLimit ?? 200,
      campaignLimit: config.campaignLimit ?? 200,
      payloadEndpointLimit: config.payloadEndpointLimit ?? 100,
      payloadAnomalyLimit: config.payloadAnomalyLimit ?? 100,
    };
  }

  start(): void {
    if (this.pollTimer) return;
    this.pollTimer = setInterval(() => {
      void this.poll();
    }, this.config.pollIntervalMs);
    this.pollTimer.unref?.();
    this.logger.info({ pollIntervalMs: this.config.pollIntervalMs }, 'Fleet intel polling started');
  }

  shutdown(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  async poll(): Promise<void> {
    if (this.pollInFlight) {
      this.logger.debug('Fleet intel poll skipped - already in flight');
      return;
    }

    this.pollInFlight = true;
    try {
      await this.ingestConnectedSensors();
    } catch (error) {
      this.logger.warn(
        { error: error instanceof Error ? error.message : String(error) },
        'Fleet intel poll failed'
      );
    } finally {
      this.pollInFlight = false;
    }
  }

  async ingestConnectedSensors(): Promise<FleetIntelIngestSummary> {
    const sensors = await this.prisma.sensor.findMany({
      where: { connectionState: 'CONNECTED' },
      select: { id: true, tenantId: true },
    });

    if (sensors.length === 0) {
      return { sensorsProcessed: 0, sensorsSucceeded: 0, sensorsFailed: 0, errors: [] };
    }

    const sensorsByTenant = new Map<string, string[]>();
    for (const sensor of sensors) {
      const list = sensorsByTenant.get(sensor.tenantId) ?? [];
      list.push(sensor.id);
      sensorsByTenant.set(sensor.tenantId, list);
    }

    let sensorsProcessed = 0;
    let sensorsSucceeded = 0;
    let sensorsFailed = 0;
    const errors: Array<{ sensorId: string; error: string }> = [];

    for (const [tenantId, sensorIds] of sensorsByTenant) {
      const activeSensors = new Set(this.synapseProxy.listActiveSensors(tenantId));
      const targets = sensorIds.filter((id) => activeSensors.has(id));

      for (let i = 0; i < targets.length; i += this.config.maxConcurrentSensors) {
        const batch = targets.slice(i, i + this.config.maxConcurrentSensors);
        const results = await Promise.allSettled(
          batch.map((sensorId) => this.ingestSensorIntel(tenantId, sensorId))
        );

        results.forEach((result, index) => {
          const sensorId = batch[index];
          sensorsProcessed += 1;
          if (result.status === 'fulfilled') {
            sensorsSucceeded += 1;
          } else {
            sensorsFailed += 1;
            errors.push({
              sensorId,
              error: result.reason instanceof Error ? result.reason.message : String(result.reason),
            });
          }
        });
      }
    }

    if (errors.length > 0) {
      this.logger.debug({ errors: errors.slice(0, 5) }, 'Fleet intel ingest errors');
    }

    return { sensorsProcessed, sensorsSucceeded, sensorsFailed, errors };
  }

  async ingestSensorIntel(tenantId: string, sensorId: string): Promise<void> {
    const [actorsResult, sessionsResult, campaignsResult, profilesResult] = await Promise.allSettled([
      this.synapseProxy.listActors(sensorId, tenantId, { limit: this.config.actorLimit }),
      this.synapseProxy.listSessions(sensorId, tenantId, { limit: this.config.sessionLimit }),
      this.synapseProxy.listCampaigns(sensorId, tenantId, { limit: this.config.campaignLimit }),
      this.synapseProxy.listProfiles(sensorId, tenantId),
    ]);

    const payloadResults = await Promise.allSettled([
      this.synapseProxy.getPayloadStats(sensorId, tenantId),
      this.synapseProxy.listPayloadEndpoints(sensorId, tenantId, { limit: this.config.payloadEndpointLimit }),
      this.synapseProxy.listPayloadAnomalies(sensorId, tenantId, { limit: this.config.payloadAnomalyLimit }),
      this.synapseProxy.getPayloadBandwidth(sensorId, tenantId),
    ]);

    if (actorsResult.status === 'fulfilled') {
      await this.upsertActors(tenantId, sensorId, actorsResult.value);
    }

    if (sessionsResult.status === 'fulfilled') {
      await this.upsertSessions(tenantId, sensorId, sessionsResult.value);
    }

    if (campaignsResult.status === 'fulfilled') {
      await this.upsertCampaigns(tenantId, sensorId, campaignsResult.value);
    }

    if (profilesResult.status === 'fulfilled') {
      await this.upsertProfiles(tenantId, sensorId, profilesResult.value);
    }

    await this.capturePayloadSnapshot(
      tenantId,
      sensorId,
      payloadResults[0],
      payloadResults[1],
      payloadResults[2],
      payloadResults[3]
    );
  }

  async getActors(tenantId: string, options: { minRisk?: number; limit: number; offset: number }) {
    const where: Prisma.SensorIntelActorWhereInput = {
      tenantId,
      ...(options.minRisk !== undefined ? { riskScore: { gte: options.minRisk } } : {}),
    };

    const [items, total] = await Promise.all([
      this.prisma.sensorIntelActor.findMany({
        where,
        orderBy: { lastSeenAt: 'desc' },
        skip: options.offset,
        take: options.limit,
      }),
      this.prisma.sensorIntelActor.count({ where }),
    ]);

    return { actors: items, total };
  }

  async getSessions(
    tenantId: string,
    options: { actorId?: string; suspicious?: boolean; limit: number; offset: number }
  ) {
    const where: Prisma.SensorIntelSessionWhereInput = {
      tenantId,
      ...(options.actorId ? { actorId: options.actorId } : {}),
      ...(options.suspicious !== undefined ? { isSuspicious: options.suspicious } : {}),
    };

    const [items, total] = await Promise.all([
      this.prisma.sensorIntelSession.findMany({
        where,
        orderBy: { lastActivityAt: 'desc' },
        skip: options.offset,
        take: options.limit,
      }),
      this.prisma.sensorIntelSession.count({ where }),
    ]);

    return { sessions: items, total };
  }

  async getCampaigns(
    tenantId: string,
    options: { status?: string; limit: number; offset: number }
  ) {
    const where: Prisma.SensorIntelCampaignWhereInput = {
      tenantId,
      ...(options.status ? { status: options.status } : {}),
    };

    const [items, total] = await Promise.all([
      this.prisma.sensorIntelCampaign.findMany({
        where,
        orderBy: { lastActivityAt: 'desc' },
        skip: options.offset,
        take: options.limit,
      }),
      this.prisma.sensorIntelCampaign.count({ where }),
    ]);

    return { campaigns: items, total };
  }

  async getProfiles(
    tenantId: string,
    options: { template?: string; limit: number; offset: number }
  ) {
    const where: Prisma.SensorIntelProfileWhereInput = {
      tenantId,
      ...(options.template ? { template: { contains: options.template } } : {}),
    };

    const [items, total] = await Promise.all([
      this.prisma.sensorIntelProfile.findMany({
        where,
        orderBy: { updatedAt: 'desc' },
        skip: options.offset,
        take: options.limit,
      }),
      this.prisma.sensorIntelProfile.count({ where }),
    ]);

    return { profiles: items, total };
  }

  async getPayloadStats(tenantId: string) {
    const snapshots = await this.prisma.sensorPayloadSnapshot.findMany({
      where: { tenantId },
      orderBy: { capturedAt: 'desc' },
    });

    const latestBySensor = new Map<string, typeof snapshots[number]>();
    for (const snapshot of snapshots) {
      if (!latestBySensor.has(snapshot.sensorId)) {
        latestBySensor.set(snapshot.sensorId, snapshot);
      }
    }

    let totalEndpoints = 0;
    let totalEntities = 0;
    let totalRequests = 0;
    let totalRequestBytes = 0;
    let totalResponseBytes = 0;
    let activeAnomalies = 0;
    let latestCapturedAt: Date | null = null;

    for (const snapshot of latestBySensor.values()) {
      const stats = snapshot.stats as Record<string, unknown>;
      totalEndpoints += Number(stats.total_endpoints ?? 0);
      totalEntities += Number(stats.total_entities ?? 0);
      totalRequests += Number(stats.total_requests ?? 0);
      totalRequestBytes += Number(stats.total_request_bytes ?? 0);
      totalResponseBytes += Number(stats.total_response_bytes ?? 0);
      activeAnomalies += Number(stats.active_anomalies ?? 0);
      if (!latestCapturedAt || snapshot.capturedAt > latestCapturedAt) {
        latestCapturedAt = snapshot.capturedAt;
      }
    }

    const avgRequestSize = totalRequests > 0 ? totalRequestBytes / totalRequests : 0;
    const avgResponseSize = totalRequests > 0 ? totalResponseBytes / totalRequests : 0;

    return {
      totalEndpoints,
      totalEntities,
      totalRequests,
      totalRequestBytes,
      totalResponseBytes,
      avgRequestSize,
      avgResponseSize,
      activeAnomalies,
      sensorCount: latestBySensor.size,
      capturedAt: latestCapturedAt,
    };
  }

  private async upsertActors(
    tenantId: string,
    sensorId: string,
    response: ActorListResponse
  ): Promise<void> {
    if (!response.actors?.length) return;

    for (const actor of response.actors) {
      await this.prisma.sensorIntelActor.upsert({
        where: {
          tenantId_sensorId_actorId: {
            tenantId,
            sensorId,
            actorId: actor.actorId,
          },
        },
        create: {
          tenantId,
          sensorId,
          actorId: actor.actorId,
          riskScore: actor.riskScore,
          isBlocked: actor.isBlocked,
          firstSeenAt: new Date(actor.firstSeen || 0),
          lastSeenAt: new Date(actor.lastSeen || 0),
          ips: actor.ips as Prisma.InputJsonValue,
          fingerprints: actor.fingerprints as Prisma.InputJsonValue,
          sessionIds: actor.sessionIds as Prisma.InputJsonValue,
          raw: actor as unknown as Prisma.InputJsonValue,
        },
        update: {
          riskScore: actor.riskScore,
          isBlocked: actor.isBlocked,
          firstSeenAt: new Date(actor.firstSeen || 0),
          lastSeenAt: new Date(actor.lastSeen || 0),
          ips: actor.ips as Prisma.InputJsonValue,
          fingerprints: actor.fingerprints as Prisma.InputJsonValue,
          sessionIds: actor.sessionIds as Prisma.InputJsonValue,
          raw: actor as unknown as Prisma.InputJsonValue,
        },
      });
    }
  }

  private async upsertSessions(
    tenantId: string,
    sensorId: string,
    response: SessionListResponse
  ): Promise<void> {
    if (!response.sessions?.length) return;

    for (const session of response.sessions) {
      await this.prisma.sensorIntelSession.upsert({
        where: {
          tenantId_sensorId_sessionId: {
            tenantId,
            sensorId,
            sessionId: session.sessionId,
          },
        },
        create: {
          tenantId,
          sensorId,
          sessionId: session.sessionId,
          actorId: session.actorId ?? null,
          requestCount: session.requestCount,
          isSuspicious: session.isSuspicious,
          lastActivityAt: new Date(session.lastActivity || 0),
          boundIp: session.boundIp ?? null,
          boundJa4: session.boundJa4 ?? null,
          hijackAlerts: session.hijackAlerts as Prisma.InputJsonValue,
          raw: session as unknown as Prisma.InputJsonValue,
        },
        update: {
          actorId: session.actorId ?? null,
          requestCount: session.requestCount,
          isSuspicious: session.isSuspicious,
          lastActivityAt: new Date(session.lastActivity || 0),
          boundIp: session.boundIp ?? null,
          boundJa4: session.boundJa4 ?? null,
          hijackAlerts: session.hijackAlerts as Prisma.InputJsonValue,
          raw: session as unknown as Prisma.InputJsonValue,
        },
      });
    }
  }

  private async upsertCampaigns(
    tenantId: string,
    sensorId: string,
    response: CampaignsRawResponse
  ): Promise<void> {
    const campaigns = response.data ?? [];
    if (!campaigns.length) return;

    for (const campaign of campaigns) {
      const firstSeenAt = this.parseDate(campaign.firstSeen);
      const lastActivityAt = this.parseDate(campaign.lastActivity);

      await this.prisma.sensorIntelCampaign.upsert({
        where: {
          tenantId_sensorId_campaignId: {
            tenantId,
            sensorId,
            campaignId: campaign.id,
          },
        },
        create: {
          tenantId,
          sensorId,
          campaignId: campaign.id,
          status: campaign.status,
          riskScore: campaign.riskScore,
          confidence: campaign.confidence,
          actorCount: campaign.actorCount,
          attackTypes: campaign.attackTypes as Prisma.InputJsonValue,
          firstSeenAt,
          lastActivityAt,
          raw: campaign as unknown as Prisma.InputJsonValue,
        },
        update: {
          status: campaign.status,
          riskScore: campaign.riskScore,
          confidence: campaign.confidence,
          actorCount: campaign.actorCount,
          attackTypes: campaign.attackTypes as Prisma.InputJsonValue,
          firstSeenAt,
          lastActivityAt,
          raw: campaign as unknown as Prisma.InputJsonValue,
        },
      });
    }
  }

  private async upsertProfiles(
    tenantId: string,
    sensorId: string,
    response: ProfilesListResponse
  ): Promise<void> {
    const profiles = response.data?.profiles ?? [];
    if (!profiles.length) return;

    for (const profile of profiles) {
      const method = '';
      await this.prisma.sensorIntelProfile.upsert({
        where: {
          tenantId_sensorId_template_method: {
            tenantId,
            sensorId,
            template: profile.template,
            method,
          },
        },
        create: {
          tenantId,
          sensorId,
          template: profile.template,
          method,
          profile: profile as unknown as Prisma.InputJsonValue,
          updatedAt: new Date(profile.lastUpdatedMs || Date.now()),
        },
        update: {
          profile: profile as unknown as Prisma.InputJsonValue,
          updatedAt: new Date(profile.lastUpdatedMs || Date.now()),
        },
      });
    }
  }

  private async capturePayloadSnapshot(
    tenantId: string,
    sensorId: string,
    statsResult: PromiseSettledResult<PayloadStatsResponse>,
    endpointsResult: PromiseSettledResult<PayloadEndpointsResponse>,
    anomaliesResult: PromiseSettledResult<PayloadAnomaliesResponse>,
    bandwidthResult: PromiseSettledResult<PayloadBandwidthStats>
  ): Promise<void> {
    if (statsResult.status !== 'fulfilled' || !statsResult.value?.success || !statsResult.value.data) {
      return;
    }

    const stats = statsResult.value.data as unknown as Prisma.InputJsonValue;
    const endpoints = this.extractPayloadData(endpointsResult);
    const anomalies = this.extractPayloadData(anomaliesResult);
    const bandwidth = bandwidthResult.status === 'fulfilled'
      ? (bandwidthResult.value as unknown as Prisma.InputJsonValue)
      : null;

    await this.prisma.sensorPayloadSnapshot.create({
      data: {
        tenantId,
        sensorId,
        capturedAt: new Date(),
        stats,
        endpoints,
        anomalies,
        bandwidth,
      },
    });
  }

  private extractPayloadData(
    result: PromiseSettledResult<PayloadEndpointsResponse | PayloadAnomaliesResponse>
  ): Prisma.InputJsonValue | null {
    if (result.status !== 'fulfilled') return null;
    if (!result.value?.success || !result.value.data) return null;
    return result.value.data as unknown as Prisma.InputJsonValue;
  }

  private parseDate(value?: string | null): Date {
    if (!value) return new Date(0);
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? new Date(0) : new Date(parsed);
  }
}
