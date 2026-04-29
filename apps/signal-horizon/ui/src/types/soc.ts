export interface SocActorRuleMatch {
  ruleId: string;
  timestamp: number;
  riskContribution: number;
  category: string;
}

export interface SocActor {
  actorId: string;
  riskScore: number;
  ruleMatches: SocActorRuleMatch[];
  anomalyCount: number;
  sessionIds: string[];
  firstSeen: number;
  lastSeen: number;
  ips: string[];
  fingerprints: string[];
  isBlocked: boolean;
  blockReason?: string | null;
  blockedSince?: number | null;
}

export interface SocActorStats {
  totalActors: number;
  blockedActors: number;
  correlationsMade: number;
  evictions: number;
  totalCreated: number;
  totalRuleMatches: number;
}

export interface SocActorListResponse {
  actors: SocActor[];
  stats?: SocActorStats | null;
}

export interface SocActorDetailResponse {
  actor: SocActor;
}

// =============================================================================
// Fleet-view types (ADR-0002 §Decision: Actors via SensorIntelActor dedup)
// Mirrors the API's FleetPartialResult envelope. Per-sensor entries report
// freshness as 'ok' | 'stale' | 'error' so dashboards can flag stale data
// without dropping it.
// =============================================================================

export type SocFleetEntryStatus = 'ok' | 'stale' | 'error';

export interface SocFleetResultEntry<T = unknown> {
  sensorId: string;
  status: SocFleetEntryStatus;
  data?: T;
  error?: string;
  lastUpdatedAt?: string;
}

export interface SocFleetSummary {
  succeeded: number;
  stale: number;
  failed: number;
}

export interface SocFleetActor extends SocActor {
  seenOnSensors: string[];
}

export interface SocFleetActorListResponse {
  results: SocFleetResultEntry<{ rowCount: number }>[];
  summary: SocFleetSummary;
  aggregate: SocFleetActor[];
  total: number;
}

export interface SocFleetActorDetailResponse {
  results: SocFleetResultEntry<{ rowCount: number }>[];
  summary: SocFleetSummary;
  aggregate: SocFleetActor;
}

export interface SocFleetTimelineEvent extends SocActorTimelineEvent {
  sensorId: string;
}

export interface SocFleetActorTimelineResponse {
  results: SocFleetResultEntry<{ count: number }>[];
  summary: SocFleetSummary;
  aggregate: {
    actorId: string;
    events: SocFleetTimelineEvent[];
  };
}

export interface SocActorTimelineEvent {
  timestamp: number;
  eventType: string;
  ruleId?: string;
  category?: string;
  riskDelta?: number;
  riskScore?: number;
  sessionId?: string;
  actorId?: string | null;
  boundJa4?: string | null;
  boundIp?: string | null;
  clientIp?: string;
  method?: string;
  path?: string;
  matchedRules?: number[];
  blockReason?: string;
  fingerprint?: string | null;
  alertType?: string;
  confidence?: number;
  reason?: string | null;
}

export interface SocActorTimelineResponse {
  actorId: string;
  events: SocActorTimelineEvent[];
}

export interface SocHijackAlert {
  sessionId: string;
  alertType: string;
  originalValue: string;
  newValue: string;
  timestamp: number;
  confidence: number;
}

export interface SocSession {
  sessionId: string;
  tokenHash: string;
  actorId?: string | null;
  creationTime: number;
  lastActivity: number;
  requestCount: number;
  boundJa4?: string | null;
  boundIp?: string | null;
  isSuspicious: boolean;
  hijackAlerts: SocHijackAlert[];
}

export interface SocSessionStats {
  totalSessions: number;
  activeSessions: number;
  suspiciousSessions: number;
  expiredSessions: number;
  hijackAlerts: number;
  evictions: number;
  totalCreated: number;
  totalInvalidated: number;
}

export interface SocSessionListResponse {
  sessions: SocSession[];
  stats?: SocSessionStats | null;
}

export interface SocSessionDetailResponse {
  session: SocSession;
}

export interface SocCampaignSignal {
  type: string;
  confidence: number;
  reason?: string | null;
}

export interface SocCampaign {
  campaignId: string;
  name: string;
  status: 'ACTIVE' | 'DETECTED' | 'DORMANT' | 'RESOLVED';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  actorCount: number;
  firstSeen: number;
  lastSeen: number;
  summary?: string | null;
  correlationTypes?: string[];
}

export interface SocCampaignActor {
  actorId: string;
  riskScore: number;
  lastSeen: number;
  ips: string[];
}

export interface SocCampaignListResponse {
  campaigns: SocCampaign[];
}

export interface SocCampaignDetailResponse {
  campaign: SocCampaign;
  signals?: SocCampaignSignal[];
}

export interface SocCampaignActorsResponse {
  campaignId: string;
  actors: SocCampaignActor[];
}
