/**
 * Signal Horizon Protocol Types
 * WebSocket message types for sensor and dashboard communication
 */

// =============================================================================
// Sensor Protocol (Inbound)
// =============================================================================

export type SensorMessageType =
  | 'auth'
  | 'signal'
  | 'signal-batch'
  | 'pong'
  | 'blocklist-sync'
  | 'heartbeat'
  | 'command-ack';

export interface SensorAuthMessage {
  type: 'auth';
  payload: {
    apiKey: string;
    sensorId: string;
    sensorName?: string;
    version: string;
  };
}

export interface SensorSignalMessage {
  type: 'signal';
  payload: ThreatSignal;
}

export interface SensorSignalBatchMessage {
  type: 'signal-batch';
  payload: ThreatSignal[];
}

export interface SensorPongMessage {
  type: 'pong';
}

export interface SensorBlocklistSyncMessage {
  type: 'blocklist-sync';
}

export interface SensorHeartbeatMessage {
  type: 'heartbeat';
  payload: {
    timestamp: number;
    status: 'healthy' | 'degraded' | 'unhealthy';
    cpu: number;
    memory: number;
    disk: number;
    requestsLastMinute: number;
    avgLatencyMs: number;
    configHash: string;
    rulesHash: string;
  };
}

export interface SensorCommandAckMessage {
  type: 'command-ack';
  payload: {
    commandId: string;
    success: boolean;
    message?: string;
    result?: Record<string, unknown>;
  };
}

export type SensorMessage =
  | SensorAuthMessage
  | SensorSignalMessage
  | SensorSignalBatchMessage
  | SensorPongMessage
  | SensorBlocklistSyncMessage
  | SensorHeartbeatMessage
  | SensorCommandAckMessage;

// =============================================================================
// Hub to Sensor Messages (Outbound)
// =============================================================================

export interface HubAuthSuccessMessage {
  type: 'auth-success';
  sensorId: string;
  tenantId: string;
  capabilities: string[];
}

export interface HubAuthFailedMessage {
  type: 'auth-failed';
  error: string;
}

export interface HubSignalAckMessage {
  type: 'signal-ack';
  sequenceId: number;
}

export interface HubBatchAckMessage {
  type: 'batch-ack';
  count: number;
  sequenceId: number;
}

export interface HubBlocklistSnapshotMessage {
  type: 'blocklist-snapshot';
  entries: BlocklistEntry[];
  sequenceId: number;
}

export interface HubBlocklistPushMessage {
  type: 'blocklist-push';
  updates: BlocklistUpdate[];
  sequenceId: number;
}

export interface HubPingMessage {
  type: 'ping';
  timestamp: number;
}

export interface HubErrorMessage {
  type: 'error';
  error: string;
}

export type HubToSensorMessage =
  | HubAuthSuccessMessage
  | HubAuthFailedMessage
  | HubSignalAckMessage
  | HubBatchAckMessage
  | HubBlocklistSnapshotMessage
  | HubBlocklistPushMessage
  | HubPingMessage
  | HubErrorMessage;

// =============================================================================
// Dashboard Protocol (Outbound Push)
// =============================================================================

export interface DashboardConnectedMessage {
  type: 'connected';
  sessionId: string;
  subscriptions: string[];
  timestamp: number;
}

export interface DashboardSnapshotMessage {
  type: 'snapshot';
  data: {
    activeCampaigns: Campaign[];
    recentThreats: Threat[];
    sensorStats: Record<string, number>;
  };
  timestamp: number;
  sequenceId: number;
}

export interface DashboardCampaignAlertMessage {
  type: 'campaign-alert';
  data: CampaignAlert;
  timestamp: number;
  sequenceId: number;
}

export interface DashboardThreatAlertMessage {
  type: 'threat-alert';
  data: ThreatAlert;
  timestamp: number;
  sequenceId: number;
}

export interface DashboardBlocklistUpdateMessage {
  type: 'blocklist-update';
  data: {
    updates: BlocklistUpdate[];
    campaign?: string;
  };
  timestamp: number;
  sequenceId: number;
}

export interface DashboardPingMessage {
  type: 'ping';
  timestamp: number;
}

export type DashboardPushMessage =
  | DashboardConnectedMessage
  | DashboardSnapshotMessage
  | DashboardCampaignAlertMessage
  | DashboardThreatAlertMessage
  | DashboardBlocklistUpdateMessage
  | DashboardPingMessage;

// =============================================================================
// Core Domain Types
// =============================================================================

export type SignalType =
  | 'IP_THREAT'
  | 'FINGERPRINT_THREAT'
  | 'CAMPAIGN_INDICATOR'
  | 'CREDENTIAL_STUFFING'
  | 'RATE_ANOMALY'
  | 'BOT_SIGNATURE'
  | 'IMPOSSIBLE_TRAVEL';

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ThreatSignal {
  signalType: SignalType;
  sourceIp?: string;
  fingerprint?: string;
  severity: Severity;
  confidence: number; // 0.0 - 1.0
  eventCount?: number;
  metadata?: Record<string, unknown>;
}

/**
 * ThreatSignal enriched with tenant/sensor context after ingestion
 * Used internally by aggregator, correlator, and broadcaster
 */
export interface EnrichedSignal extends ThreatSignal {
  tenantId: string;
  sensorId: string;
  anonFingerprint?: string; // Added by aggregator after SHA-256 anonymization
  id?: string; // Database ID after storage
}

export type BlockType = 'IP' | 'IP_RANGE' | 'FINGERPRINT' | 'ASN' | 'USER_AGENT';

export type BlockSource =
  | 'AUTOMATIC'
  | 'MANUAL'
  | 'FLEET_INTEL'
  | 'EXTERNAL_FEED'
  | 'WAR_ROOM';

export interface BlocklistEntry {
  blockType: BlockType;
  indicator: string;
  expiresAt?: Date | null;
  source: BlockSource;
}

export interface BlocklistUpdate {
  type: 'add' | 'remove';
  blockType: BlockType;
  indicator: string;
  reason?: string;
  expiresAt?: Date;
  source: BlockSource;
}

export type CampaignStatus = 'ACTIVE' | 'MONITORING' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface Campaign {
  id: string;
  name: string;
  description?: string;
  status: CampaignStatus;
  severity: Severity;
  isCrossTenant: boolean;
  tenantsAffected: number;
  confidence: number;
  firstSeenAt: Date;
  lastActivityAt: Date;
}

export interface CampaignAlert {
  type: 'campaign-detected' | 'campaign-updated' | 'campaign-resolved';
  campaign: {
    id: string;
    name: string;
    severity: Severity;
    isCrossTenant: boolean;
    tenantsAffected: number;
    confidence: number;
  };
  timestamp: number;
}

export type ThreatType =
  | 'IP'
  | 'FINGERPRINT'
  | 'ASN'
  | 'USER_AGENT'
  | 'TLS_FINGERPRINT'
  | 'CREDENTIAL_PATTERN';

export interface Threat {
  id: string;
  threatType: ThreatType;
  indicator: string;
  riskScore: number; // 0.0 - 100.0
  fleetRiskScore?: number;
  hitCount: number;
  tenantsAffected: number;
  isFleetThreat: boolean;
  firstSeenAt: Date;
  lastSeenAt: Date;
}

export interface ThreatAlert {
  threat: {
    id: string;
    threatType: ThreatType;
    indicator: string;
    riskScore: number;
    isFleetThreat: boolean;
  };
  timestamp: number;
}

// =============================================================================
// API Response Types
// =============================================================================

export interface HubStatusResponse {
  hub: 'signal-horizon';
  version: string;
  uptime: number;
  connections: {
    sensors: number;
    dashboards: number;
  };
}

export interface HealthResponse {
  status: 'healthy' | 'unhealthy';
  service: string;
  version: string;
  timestamp: string;
}

export interface ReadyResponse {
  status: 'ready' | 'not_ready';
  database: 'connected' | 'disconnected';
  timestamp: string;
  error?: string;
}
