import { apiFetch } from '../../lib/api';
import type {
  SocActorDetailResponse,
  SocActorListResponse,
  SocActorTimelineResponse,
  SocCampaignActorsResponse,
  SocCampaignDetailResponse,
  SocCampaignListResponse,
  SocFleetActorDetailResponse,
  SocFleetActorListResponse,
  SocFleetActorTimelineResponse,
  SocSessionDetailResponse,
  SocSessionListResponse,
} from '../../types/soc';

export interface ActorQueryParams {
  ip?: string;
  fingerprint?: string;
  minRisk?: number;
  limit?: number;
  offset?: number;
}

export interface SessionQueryParams {
  actorId?: string;
  suspicious?: boolean;
  limit?: number;
  offset?: number;
}

export interface CampaignQueryParams {
  status?: string;
  limit?: number;
  offset?: number;
}

function buildQuery(params: Record<string, string | number | boolean | undefined>): string {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === '') return;
    query.set(key, String(value));
  });
  const queryString = query.toString();
  return queryString ? `?${queryString}` : '';
}

export async function fetchActors(sensorId: string, params: ActorQueryParams = {}) {
  const query = buildQuery({
    ip: params.ip,
    fingerprint: params.fingerprint,
    min_risk: params.minRisk,
    limit: params.limit,
    offset: params.offset,
  });
  return apiFetch<SocActorListResponse>(`/synapse/${sensorId}/actors${query}`);
}

export async function fetchActorDetail(sensorId: string, actorId: string) {
  return apiFetch<SocActorDetailResponse>(`/synapse/${sensorId}/actors/${actorId}`);
}

export async function fetchActorTimeline(sensorId: string, actorId: string, limit: number = 100) {
  const query = buildQuery({ limit });
  return apiFetch<SocActorTimelineResponse>(`/synapse/${sensorId}/actors/${actorId}/timeline${query}`);
}

// ============================================================================
// Fleet-view fetchers (ADR-0002). Use these for SOC dashboards that span the
// fleet; the sensor-prefixed fetchers above remain for the sensor-detail
// drawer.
// ============================================================================

export async function fetchFleetActors(params: ActorQueryParams = {}) {
  const query = buildQuery({
    ip: params.ip,
    fingerprint: params.fingerprint,
    min_risk: params.minRisk,
    limit: params.limit,
    offset: params.offset,
  });
  return apiFetch<SocFleetActorListResponse>(`/synapse/actors${query}`);
}

export async function fetchFleetActorDetail(actorId: string) {
  return apiFetch<SocFleetActorDetailResponse>(`/synapse/actors/${actorId}`);
}

export async function fetchFleetActorTimeline(actorId: string, limit: number = 100) {
  const query = buildQuery({ limit });
  return apiFetch<SocFleetActorTimelineResponse>(`/synapse/actors/${actorId}/timeline${query}`);
}

export async function fetchSessions(sensorId: string, params: SessionQueryParams = {}) {
  const query = buildQuery({
    actor_id: params.actorId,
    suspicious: params.suspicious,
    limit: params.limit,
    offset: params.offset,
  });
  return apiFetch<SocSessionListResponse>(`/synapse/${sensorId}/sessions${query}`);
}

export async function fetchSessionDetail(sensorId: string, sessionId: string) {
  return apiFetch<SocSessionDetailResponse>(`/synapse/${sensorId}/sessions/${sessionId}`);
}

export async function fetchCampaigns(params: CampaignQueryParams = {}) {
  const query = buildQuery({
    status: params.status,
    limit: params.limit,
    offset: params.offset,
  });
  return apiFetch<SocCampaignListResponse>(`/synapse/campaigns${query}`);
}

export async function fetchCampaignDetail(campaignId: string) {
  return apiFetch<SocCampaignDetailResponse>(`/synapse/campaigns/${campaignId}`);
}

export async function fetchCampaignActors(campaignId: string) {
  return apiFetch<SocCampaignActorsResponse>(`/synapse/campaigns/${campaignId}/actors`);
}
