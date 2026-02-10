/**
 * Fleet Intel Ingestion Service
 * Polls connected sensors via Synapse proxy and stores aggregated snapshots.
 */

import type { Prisma, PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type {
  Actor,
  ActorStats,
  ActorListResponse,
  CampaignSummaryRaw,
  CampaignsRawResponse,
  ProfilesResponse,
  ProfileRecord,
  Session,
  SessionStats,
  SessionListResponse,
  SynapseProxyService,
} from '../synapse-proxy.js';

interface FleetIntelIngestionConfig {
  intervalMs?: number;
  pageSize?: number;
  maxPages?: number;
}

interface SensorRef {
  id: string;
  tenantId: string;
}

export class FleetIntelIngestionService {
  private timer: NodeJS.Timeout | null = null;
  private inFlight = false;
  private readonly config: Required<FleetIntelIngestionConfig>;
  private readonly logger: Logger;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly synapseProxy: SynapseProxyService,
    logger: Logger,
    config: FleetIntelIngestionConfig = {}
  ) {
    this.logger = logger.child({ service: 'fleet-intel-ingestion' });
    this.config = {
      intervalMs: config.intervalMs ?? 60000,
      pageSize: config.pageSize ?? 100,
      maxPages: config.maxPages ?? 10,
    };
  }

  start(): void {
    if (this.timer) {
      clearInterval(this.timer);
    }

    this.timer = setInterval(() => {
      void this.ingestFleet();
    }, this.config.intervalMs);

    void this.ingestFleet();
    this.logger.info({ intervalMs: this.config.intervalMs }, 'Fleet intel ingestion started');
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.logger.info('Fleet intel ingestion stopped');
  }

  async ingestFleet(): Promise<void> {
    if (this.inFlight) {
      this.logger.warn('Skipping fleet intel ingestion - previous run still in flight');
      return;
    }

    this.inFlight = true;

    try {
      const sensors = await this.prisma.sensor.findMany({
        where: { connectionState: 'CONNECTED' },
        select: { id: true, tenantId: true },
      });

      if (!sensors.length) {
        this.logger.debug('No connected sensors for fleet intel ingestion');
        return;
      }

      for (const sensor of sensors) {
        await this.ingestSensor(sensor);
      }
    } catch (error) {
      this.logger.error({ error }, 'Fleet intel ingestion failed');
    } finally {
      this.inFlight = false;
    }
  }

  private async ingestSensor(sensor: SensorRef): Promise<void> {
    const { id: sensorId, tenantId } = sensor;

    const actors = await this.safeFetch(
      sensorId,
      'actors',
      () => this.fetchActors(sensorId, tenantId)
    );
    if (actors) {
      await this.upsertActors(sensorId, tenantId, actors);
    }

    const sessions = await this.safeFetch(
      sensorId,
      'sessions',
      () => this.fetchSessions(sensorId, tenantId)
    );
    if (sessions) {
      await this.upsertSessions(sensorId, tenantId, sessions);
    }

    const campaigns = await this.safeFetch(
      sensorId,
      'campaigns',
      () => this.fetchCampaigns(sensorId, tenantId)
    );
    if (campaigns) {
      await this.upsertCampaigns(sensorId, tenantId, campaigns);
    }

    const profiles = await this.safeFetch(
      sensorId,
      'profiles',
      () => this.synapseProxy.listProfiles(sensorId, tenantId)
    );
    if (profiles) {
      await this.upsertProfiles(sensorId, tenantId, profiles);
    }

    const payloadStats = await this.safeFetch(
      sensorId,
      'payload stats',
      () => this.synapseProxy.getPayloadStats(sensorId, tenantId)
    );
    const payloadEndpoints = await this.safeFetch(
      sensorId,
      'payload endpoints',
      () => this.synapseProxy.getPayloadEndpoints(sensorId, tenantId)
    );
    const payloadAnomalies = await this.safeFetch(
      sensorId,
      'payload anomalies',
      () => this.synapseProxy.getPayloadAnomalies(sensorId, tenantId)
    );
    const payloadBandwidth = await this.safeFetch(
      sensorId,
      'payload bandwidth',
      () => this.synapseProxy.getPayloadBandwidth(sensorId, tenantId)
    );

    if (payloadStats) {
      await this.createPayloadSnapshot(
        sensorId,
        tenantId,
        payloadStats,
        payloadEndpoints,
        payloadAnomalies,
        payloadBandwidth
      );
    }
  }

  private async fetchActors(
    sensorId: string,
    tenantId: string
  ): Promise<ActorListResponse> {
    const actors: Actor[] = [];
    let stats: ActorStats | null | undefined;

    for (let page = 0; page < this.config.maxPages; page++) {
      const offset = page * this.config.pageSize;
      const result = await this.synapseProxy.listActors(sensorId, tenantId, {
        limit: this.config.pageSize,
        offset,
      });

      if (stats === undefined) {
        stats = result.stats ?? null;
      }

      const batch = result.actors ?? [];
      actors.push(...batch);

      if (batch.length < this.config.pageSize) {
        break;
      }
    }

    return { actors, stats };
  }

  private async fetchSessions(
    sensorId: string,
    tenantId: string
  ): Promise<SessionListResponse> {
    const sessions: Session[] = [];
    let stats: SessionStats | null | undefined;

    for (let page = 0; page < this.config.maxPages; page++) {
      const offset = page * this.config.pageSize;
      const result = await this.synapseProxy.listSessions(sensorId, tenantId, {
        limit: this.config.pageSize,
        offset,
      });

      if (stats === undefined) {
        stats = result.stats ?? null;
      }

      const batch = result.sessions ?? [];
      sessions.push(...batch);

      if (batch.length < this.config.pageSize) {
        break;
      }
    }

    return { sessions, stats };
  }

  private async fetchCampaigns(
    sensorId: string,
    tenantId: string
  ): Promise<CampaignsRawResponse> {
    const campaigns: CampaignSummaryRaw[] = [];

    for (let page = 0; page < this.config.maxPages; page++) {
      const offset = page * this.config.pageSize;
      const result = await this.synapseProxy.listCampaigns(sensorId, tenantId, {
        limit: this.config.pageSize,
        offset,
      });

      const batch = result.data ?? [];
      campaigns.push(...batch);

      if (batch.length < this.config.pageSize) {
        break;
      }
    }

    return { data: campaigns };
  }

  private async upsertActors(
    sensorId: string,
    tenantId: string,
    response: ActorListResponse
  ): Promise<void> {
    const actors = response.actors ?? [];
    if (!actors.length) return;

    await Promise.all(
      actors.map((actor) => {
        const data = {
          tenantId,
          sensorId,
          actorId: actor.actorId,
          riskScore: Number(actor.riskScore ?? 0),
          isBlocked: Boolean(actor.isBlocked),
          firstSeenAt: this.toDate(actor.firstSeen),
          lastSeenAt: this.toDate(actor.lastSeen),
          ips: this.toJson(actor.ips ?? []),
          fingerprints: this.toJson(actor.fingerprints ?? []),
          sessionIds: this.toJson(actor.sessionIds ?? []),
          raw: this.toJson(actor),
        };

        return this.prisma.sensorIntelActor.upsert({
          where: {
            tenantId_sensorId_actorId: {
              tenantId,
              sensorId,
              actorId: actor.actorId,
            },
          },
          create: data,
          update: data,
        });
      })
    );
  }

  private async upsertSessions(
    sensorId: string,
    tenantId: string,
    response: SessionListResponse
  ): Promise<void> {
    const sessions = response.sessions ?? [];
    if (!sessions.length) return;

    await Promise.all(
      sessions.map((session) => {
        const data = {
          tenantId,
          sensorId,
          sessionId: session.sessionId,
          actorId: session.actorId ?? null,
          requestCount: Number(session.requestCount ?? 0),
          isSuspicious: Boolean(session.isSuspicious),
          lastActivityAt: this.toDate(session.lastActivity),
          boundIp: session.boundIp ?? null,
          boundJa4: session.boundJa4 ?? null,
          hijackAlerts: this.toJson(session.hijackAlerts ?? []),
          raw: this.toJson(session),
        };

        return this.prisma.sensorIntelSession.upsert({
          where: {
            tenantId_sensorId_sessionId: {
              tenantId,
              sensorId,
              sessionId: session.sessionId,
            },
          },
          create: data,
          update: data,
        });
      })
    );
  }

  private async upsertCampaigns(
    sensorId: string,
    tenantId: string,
    response: CampaignsRawResponse
  ): Promise<void> {
    const campaigns = response.data ?? [];
    if (!campaigns.length) return;

    await Promise.all(
      campaigns.map((campaign) => {
        const data = {
          tenantId,
          sensorId,
          campaignId: campaign.id,
          status: campaign.status,
          riskScore: Number(campaign.riskScore ?? 0),
          confidence: Number(campaign.confidence ?? 0),
          actorCount: Number(campaign.actorCount ?? 0),
          attackTypes: this.toJson(campaign.attackTypes ?? []),
          firstSeenAt: this.toDate(campaign.firstSeen),
          lastActivityAt: this.toDate(campaign.lastActivity),
          raw: this.toJson(campaign),
        };

        return this.prisma.sensorIntelCampaign.upsert({
          where: {
            tenantId_sensorId_campaignId: {
              tenantId,
              sensorId,
              campaignId: campaign.id,
            },
          },
          create: data,
          update: data,
        });
      })
    );
  }

  private async upsertProfiles(
    sensorId: string,
    tenantId: string,
    response: ProfilesResponse
  ): Promise<void> {
    const profiles = this.normalizeProfiles(response);
    if (!profiles.length) return;

    await Promise.all(
      profiles.map((record) => {
        const template = this.extractTemplate(record);
        if (!template) {
          this.logger.warn({ sensorId, record }, 'Skipping profile without template');
          return null;
        }

        const method = this.extractMethod(record);
        const updatedAt = this.extractUpdatedAt(record);
        const profilePayload = record.profile ?? record;

        const data = {
          tenantId,
          sensorId,
          template,
          method,
          profile: this.toJson(profilePayload),
          updatedAt,
        };

        return this.prisma.sensorIntelProfile.upsert({
          where: {
            tenantId_sensorId_template_method: {
              tenantId,
              sensorId,
              template,
              method,
            },
          },
          create: data,
          update: data,
        });
      })
    );
  }

  private async createPayloadSnapshot(
    sensorId: string,
    tenantId: string,
    stats: Record<string, unknown>,
    endpoints: Record<string, unknown> | null,
    anomalies: Record<string, unknown> | null,
    bandwidth: Record<string, unknown> | null
  ): Promise<void> {
    const capturedAt = this.extractCapturedAt(stats);

    await this.prisma.sensorPayloadSnapshot.create({
      data: {
        tenantId,
        sensorId,
        capturedAt,
        stats: this.toJson(stats),
        endpoints: endpoints ? this.toJson(endpoints) : null,
        anomalies: anomalies ? this.toJson(anomalies) : null,
        bandwidth: bandwidth ? this.toJson(bandwidth) : null,
      },
    });
  }

  private normalizeProfiles(response: ProfilesResponse): ProfileRecord[] {
    if (Array.isArray(response)) {
      return response as ProfileRecord[];
    }

    if (response && typeof response === 'object') {
      const record = response as { profiles?: ProfileRecord[]; data?: ProfileRecord[] };
      if (Array.isArray(record.profiles)) return record.profiles;
      if (Array.isArray(record.data)) return record.data;
    }

    return [];
  }

  private extractTemplate(record: ProfileRecord): string | null {
    const template =
      (typeof record.template === 'string' && record.template) ||
      (typeof record.path === 'string' && record.path) ||
      (typeof record.endpoint === 'string' && record.endpoint) ||
      (typeof record.route === 'string' && record.route);

    return template ?? null;
  }

  private extractMethod(record: ProfileRecord): string {
    const method =
      (typeof record.method === 'string' && record.method) ||
      (typeof record.httpMethod === 'string' && record.httpMethod) ||
      (typeof record.http_method === 'string' && record.http_method);

    return (method ?? 'ANY').toUpperCase();
  }

  private extractUpdatedAt(record: ProfileRecord): Date {
    const value =
      record.updatedAt ??
      record.updated_at ??
      record.lastUpdated ??
      record.updated;

    return this.toDate(value ?? null);
  }

  private extractCapturedAt(stats: Record<string, unknown>): Date {
    const value =
      stats.capturedAt ??
      stats.captured_at ??
      stats.timestamp ??
      stats.time;

    return this.toDate(value ?? null);
  }

  private toDate(value?: string | number | null): Date {
    if (!value) return new Date();
    if (typeof value === 'number') {
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? new Date() : date;
    }
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? new Date() : date;
  }

  private toJson(value: unknown): Prisma.InputJsonValue {
    if (value === undefined) {
      return null;
    }
    return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
  }

  private async safeFetch<T>(
    sensorId: string,
    label: string,
    task: () => Promise<T>
  ): Promise<T | null> {
    try {
      return await task();
    } catch (error) {
      this.logger.warn({ error, sensorId, label }, 'Fleet intel ingest failed');
      return null;
    }
  }
}
