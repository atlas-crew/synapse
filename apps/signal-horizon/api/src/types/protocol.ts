/**
 * Signal Horizon Protocol Types
 *
 * WebSocket message types for sensor and dashboard communication in the
 * Signal Horizon threat intelligence platform. This module defines the
 * complete protocol for:
 *
 * - **Sensor → Hub**: Authentication, threat signals, heartbeats, command acknowledgments
 * - **Hub → Sensor**: Auth responses, signal acks, blocklist updates, pings
 * - **Hub → Dashboard**: Real-time threat alerts, campaign updates, snapshots
 *
 * @module protocol
 */

// =============================================================================
// Sensor Protocol (Inbound)
// =============================================================================

/**
 * Discriminator values for sensor-to-hub messages.
 * Used for type narrowing in message handlers.
 */
export type SensorMessageType =
  | 'auth'
  | 'signal'
  | 'signal-batch'
  | 'pong'
  | 'blocklist-sync'
  | 'heartbeat'
  | 'command-ack';

/**
 * Authentication message sent by sensors upon WebSocket connection.
 * The hub validates the API key and registers the sensor for the tenant.
 *
 * @example
 * ```typescript
 * const authMsg: SensorAuthMessage = {
 *   type: 'auth',
 *   payload: {
 *     apiKey: 'sk_live_xxx',
 *     sensorId: 'sensor-prod-01',
 *     sensorName: 'Production Edge',
 *     version: '1.2.0'
 *   }
 * };
 * ```
 */
export interface SensorAuthMessage {
  type: 'auth';
  payload: {
    /** API key for tenant authentication (hashed for lookup) */
    apiKey: string;
    /** Unique sensor identifier */
    sensorId: string;
    /** Human-readable sensor name for dashboard display */
    sensorName?: string;
    /** Sensor software version for compatibility checks */
    version: string;
  };
}

/**
 * Single threat signal from a sensor.
 * Used for real-time, low-latency threat reporting.
 */
export interface SensorSignalMessage {
  type: 'signal';
  /** The threat signal data */
  payload: ThreatSignal;
}

/**
 * Batch of threat signals for high-throughput scenarios.
 * More efficient than individual messages when processing many signals.
 */
export interface SensorSignalBatchMessage {
  type: 'signal-batch';
  /** Array of threat signals (typically 10-100 per batch) */
  payload: ThreatSignal[];
}

/**
 * Response to hub ping messages for connection health monitoring.
 */
export interface SensorPongMessage {
  type: 'pong';
}

/**
 * Request for the current blocklist snapshot.
 * Hub responds with HubBlocklistSnapshotMessage.
 */
export interface SensorBlocklistSyncMessage {
  type: 'blocklist-sync';
}

/**
 * Periodic health status from sensors.
 * Used for fleet monitoring and anomaly detection.
 *
 * @example
 * ```typescript
 * const heartbeat: SensorHeartbeatMessage = {
 *   type: 'heartbeat',
 *   payload: {
 *     timestamp: Date.now(),
 *     status: 'healthy',
 *     cpu: 45.2,
 *     memory: 62.1,
 *     disk: 23.5,
 *     requestsLastMinute: 15420,
 *     avgLatencyMs: 2.3,
 *     configHash: 'abc123',
 *     rulesHash: 'def456'
 *   }
 * };
 * ```
 */
export interface SensorHeartbeatMessage {
  type: 'heartbeat';
  payload: {
    /** Unix timestamp in milliseconds */
    timestamp: number;
    /** Overall sensor health status */
    status: 'healthy' | 'degraded' | 'unhealthy';
    /** CPU utilization percentage (0-100) */
    cpu: number;
    /** Memory utilization percentage (0-100) */
    memory: number;
    /** Disk utilization percentage (0-100) */
    disk: number;
    /** Request count in the last 60 seconds */
    requestsLastMinute: number;
    /** Average request processing latency in milliseconds */
    avgLatencyMs: number;
    /** Hash of current configuration for drift detection */
    configHash: string;
    /** Hash of current rules for sync verification */
    rulesHash: string;
  };
}

/**
 * Acknowledgment of a fleet command execution.
 * Sent after processing push_config, push_rules, restart, or collect_diagnostics.
 */
export interface SensorCommandAckMessage {
  type: 'command-ack';
  payload: {
    /** ID of the command being acknowledged */
    commandId: string;
    /** Whether the command executed successfully */
    success: boolean;
    /** Human-readable status or error message */
    message?: string;
    /** Command-specific result data */
    result?: Record<string, unknown>;
  };
}

/**
 * Union of all valid sensor-to-hub message types.
 * Use the `type` field as a discriminator for type narrowing.
 *
 * @example
 * ```typescript
 * function handleMessage(msg: SensorMessage) {
 *   switch (msg.type) {
 *     case 'signal':
 *       processSignal(msg.payload);
 *       break;
 *     case 'heartbeat':
 *       updateSensorStatus(msg.payload);
 *       break;
 *   }
 * }
 * ```
 */
export type SensorMessage =
  | SensorAuthMessage
  | SensorSignalMessage
  | SensorSignalBatchMessage
  | SensorPongMessage
  | SensorBlocklistSyncMessage
  | SensorHeartbeatMessage
  | SensorCommandAckMessage;

/**
 * Extracted heartbeat payload type for handler convenience.
 * @see SensorHeartbeatMessage
 */
export type SensorHeartbeat = SensorHeartbeatMessage['payload'];

/**
 * Extracted command acknowledgment payload type.
 * @see SensorCommandAckMessage
 */
export type SensorCommandAck = SensorCommandAckMessage['payload'];

/**
 * Fleet management command sent to sensors.
 * Used for configuration pushes, rule updates, and diagnostics collection.
 */
export interface FleetCommand {
  /** Unique command identifier for tracking and acknowledgment */
  commandId: string;
  /** Command type determining the action sensors should take */
  type: 'push_config' | 'push_rules' | 'restart' | 'collect_diagnostics';
  /** Command-specific payload data */
  payload: Record<string, unknown>;
  /** ISO 8601 timestamp when command was issued */
  timestamp: string;
}

// =============================================================================
// Hub to Sensor Messages (Outbound)
// =============================================================================

/**
 * Successful authentication response sent to sensors.
 * Confirms the sensor is registered and provides tenant context.
 */
export interface HubAuthSuccessMessage {
  type: 'auth-success';
  /** Confirmed sensor ID */
  sensorId: string;
  /** Tenant ID the sensor belongs to */
  tenantId: string;
  /** List of enabled capabilities (e.g., 'blocklist-sync', 'fleet-commands') */
  capabilities: string[];
}

/**
 * Authentication failure response.
 * Sensor should disconnect and retry with valid credentials.
 */
export interface HubAuthFailedMessage {
  type: 'auth-failed';
  /** Reason for authentication failure */
  error: string;
}

/**
 * Acknowledgment of a single signal receipt.
 * Used for delivery confirmation and backpressure.
 */
export interface HubSignalAckMessage {
  type: 'signal-ack';
  /** Sequence ID for ordering and duplicate detection */
  sequenceId: number;
}

/**
 * Acknowledgment of a signal batch receipt.
 */
export interface HubBatchAckMessage {
  type: 'batch-ack';
  /** Number of signals processed in the batch */
  count: number;
  /** Sequence ID for ordering */
  sequenceId: number;
}

/**
 * Full blocklist snapshot sent in response to blocklist-sync requests.
 * Contains all active block entries for the tenant.
 */
export interface HubBlocklistSnapshotMessage {
  type: 'blocklist-snapshot';
  /** Complete list of active blocklist entries */
  entries: BlocklistEntry[];
  /** Sequence ID for cache invalidation */
  sequenceId: number;
}

/**
 * Incremental blocklist update pushed to sensors.
 * More efficient than full snapshots for small changes.
 */
export interface HubBlocklistPushMessage {
  type: 'blocklist-push';
  /** List of add/remove operations */
  updates: BlocklistUpdate[];
  /** Sequence ID for ordering */
  sequenceId: number;
}

/**
 * Heartbeat ping sent to sensors.
 * Sensors should respond with SensorPongMessage.
 */
export interface HubPingMessage {
  type: 'ping';
  /** Unix timestamp in milliseconds */
  timestamp: number;
}

/**
 * Error message for protocol or processing errors.
 */
export interface HubErrorMessage {
  type: 'error';
  /** Error description */
  error: string;
}

/**
 * Fleet command message sent to sensors.
 * Mirrors CommandSender payload shape for hub→sensor commands.
 */
export type HubCommandType =
  | 'push_config'
  | 'push_rules'
  | 'restart'
  | 'collect_diagnostics'
  | 'update'
  | 'sync_blocklist';

export interface HubCommandMessage {
  type: HubCommandType;
  /** Unique command identifier for tracking and acknowledgment */
  commandId: string;
  /** Command payload */
  payload: Record<string, unknown>;
}

/**
 * Union of all valid hub-to-sensor message types.
 */
export type HubToSensorMessage =
  | HubAuthSuccessMessage
  | HubAuthFailedMessage
  | HubSignalAckMessage
  | HubBatchAckMessage
  | HubBlocklistSnapshotMessage
  | HubBlocklistPushMessage
  | HubPingMessage
  | HubErrorMessage
  | HubCommandMessage;

// =============================================================================
// Dashboard Protocol (Outbound Push)
// =============================================================================

/**
 * Connection confirmation sent to dashboard clients.
 * Establishes the session and confirms active subscriptions.
 */
export interface DashboardConnectedMessage {
  type: 'connected';
  /** Unique session identifier for this connection */
  sessionId: string;
  /** Active subscription topics (e.g., 'threats', 'campaigns', 'blocklist') */
  subscriptions: string[];
  /** Connection timestamp in milliseconds */
  timestamp: number;
}

/**
 * Initial state snapshot sent upon dashboard connection.
 * Provides current threat landscape for immediate rendering.
 */
export interface DashboardSnapshotMessage {
  type: 'snapshot';
  data: {
    /** Currently active attack campaigns */
    activeCampaigns: Campaign[];
    /** Recent threat detections */
    recentThreats: Threat[];
    /** Sensor statistics by sensor ID */
    sensorStats: Record<string, number>;
    /** API security statistics */
    apiStats: {
      discoveryEvents: number;
      schemaViolations: number;
    };
  };
  /** Snapshot generation timestamp */
  timestamp: number;
  /** Sequence ID for ordering */
  sequenceId: number;
}

/**
 * Real-time campaign alert pushed to dashboards.
 * Triggered when campaigns are detected, updated, or resolved.
 */
export interface DashboardCampaignAlertMessage {
  type: 'campaign-alert';
  /** Campaign alert details */
  data: CampaignAlert;
  /** Alert timestamp */
  timestamp: number;
  /** Sequence ID for ordering */
  sequenceId: number;
}

/**
 * Real-time threat alert pushed to dashboards.
 * Triggered for new high-severity threats or fleet-wide indicators.
 */
export interface DashboardThreatAlertMessage {
  type: 'threat-alert';
  /** Threat alert details */
  data: ThreatAlert;
  /** Alert timestamp */
  timestamp: number;
  /** Sequence ID for ordering */
  sequenceId: number;
}

/**
 * Blocklist change notification pushed to dashboards.
 * Allows UI to reflect blocking actions in real-time.
 */
export interface DashboardBlocklistUpdateMessage {
  type: 'blocklist-update';
  data: {
    /** Blocklist add/remove operations */
    updates: BlocklistUpdate[];
    /** Associated campaign ID if applicable */
    campaign?: string;
  };
  /** Update timestamp */
  timestamp: number;
  /** Sequence ID for ordering */
  sequenceId: number;
}

/**
 * Heartbeat ping sent to dashboard clients.
 * Used for connection health monitoring.
 */
export interface DashboardPingMessage {
  type: 'ping';
  /** Unix timestamp in milliseconds */
  timestamp: number;
}

/**
 * Union of all valid hub-to-dashboard push message types.
 */
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

/**
 * Classification of threat signal types.
 * Determines processing logic and required metadata.
 */
export type SignalType =
  | 'IP_THREAT'
  | 'FINGERPRINT_THREAT'
  | 'CAMPAIGN_INDICATOR'
  | 'CREDENTIAL_STUFFING'
  | 'RATE_ANOMALY'
  | 'BOT_SIGNATURE'
  | 'IMPOSSIBLE_TRAVEL'
  | 'TEMPLATE_DISCOVERY'
  | 'SCHEMA_VIOLATION';

/**
 * Threat severity levels for prioritization and alerting.
 * - LOW: Informational, no immediate action required
 * - MEDIUM: Suspicious activity, monitor closely
 * - HIGH: Confirmed threat, action recommended
 * - CRITICAL: Active attack, immediate response required
 */
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * Geographic metadata attached to signals requiring location context.
 * Used for credential stuffing detection and impossible travel analysis.
 */
export interface GeoMetadata {
  /** Latitude coordinate */
  latitude: number;
  /** Longitude coordinate */
  longitude: number;
  /** City name if available */
  city?: string;
  /** ISO 3166-1 alpha-2 country code */
  countryCode?: string;
  /** User identifier for travel analysis */
  userId?: string;
}

/**
 * Extended geo metadata for impossible travel detection.
 * Requires userId to correlate location changes for the same user.
 */
export interface ImpossibleTravelMetadata extends GeoMetadata {
  /** Required user identifier for travel correlation */
  userId: string;
}

/**
 * Discriminated union of metadata types based on signal type.
 * Ensures type safety when accessing signal-specific metadata.
 */
export type SignalMetadata =
  | ({ signalType: 'CREDENTIAL_STUFFING' } & GeoMetadata)
  | ({ signalType: 'IMPOSSIBLE_TRAVEL' } & ImpossibleTravelMetadata)
  | ({ signalType: 'IP_THREAT' | 'FINGERPRINT_THREAT' | 'CAMPAIGN_INDICATOR' | 'RATE_ANOMALY' | 'BOT_SIGNATURE' | 'TEMPLATE_DISCOVERY' | 'SCHEMA_VIOLATION' } & Record<string, unknown>);

/**
 * Core threat signal structure sent by sensors.
 * Uses discriminated union pattern for type-safe metadata access.
 *
 * @example
 * ```typescript
 * // Credential stuffing signal with geo data
 * const signal: ThreatSignal = {
 *   signalType: 'CREDENTIAL_STUFFING',
 *   sourceIp: '192.168.1.1',
 *   severity: 'HIGH',
 *   confidence: 0.95,
 *   metadata: { latitude: 40.7128, longitude: -74.0060, city: 'New York' }
 * };
 *
 * // Type-safe access based on signalType
 * if (signal.signalType === 'CREDENTIAL_STUFFING') {
 *   console.log(signal.metadata.latitude); // Type-safe access
 * }
 * ```
 */
export type ThreatSignal = {
  /** Source IP address if available */
  sourceIp?: string;
  /** Browser/device fingerprint if available */
  fingerprint?: string;
  /** Threat severity level */
  severity: Severity;
  /** Detection confidence score (0.0 - 1.0) */
  confidence: number;
  /** Number of events contributing to this signal */
  eventCount?: number;
} & (
  | { signalType: 'CREDENTIAL_STUFFING'; metadata: GeoMetadata }
  | { signalType: 'IMPOSSIBLE_TRAVEL'; metadata: ImpossibleTravelMetadata }
  | { signalType: 'IP_THREAT'; metadata?: Record<string, unknown> }
  | { signalType: 'FINGERPRINT_THREAT'; metadata?: Record<string, unknown> }
  | { signalType: 'CAMPAIGN_INDICATOR'; metadata?: Record<string, unknown> }
  | { signalType: 'RATE_ANOMALY'; metadata?: Record<string, unknown> }
  | { signalType: 'BOT_SIGNATURE'; metadata?: Record<string, unknown> }
  | { signalType: 'TEMPLATE_DISCOVERY'; metadata?: Record<string, unknown> }
  | { signalType: 'SCHEMA_VIOLATION'; metadata?: Record<string, unknown> }
);

/**
 * ThreatSignal enriched with tenant/sensor context after ingestion.
 * Used internally by aggregator, correlator, and broadcaster.
 *
 * The enrichment process adds:
 * - tenantId: For multi-tenant isolation
 * - sensorId: For attribution and diagnostics
 * - anonFingerprint: SHA-256 anonymized fingerprint for cross-tenant correlation
 * - id: Database ID after persistence
 */
export type EnrichedSignal = ThreatSignal & {
  /** Tenant ID owning this signal */
  tenantId: string;
  /** Sensor ID that reported this signal */
  sensorId: string;
  /** SHA-256 anonymized fingerprint for fleet correlation */
  anonFingerprint?: string;
  /** Database primary key after storage */
  id?: string;
  /** Threat score from ThreatService (0-100) */
  threatScore?: number;
};

/**
 * Types of indicators that can be blocked.
 */
export type BlockType = 'IP' | 'IP_RANGE' | 'FINGERPRINT' | 'ASN' | 'USER_AGENT';

/**
 * Origin of a blocklist entry.
 * - AUTOMATIC: System-generated based on threat detection
 * - MANUAL: Operator-created through dashboard
 * - FLEET_INTEL: Cross-tenant intelligence sharing
 * - EXTERNAL_FEED: Third-party threat feed integration
 * - WAR_ROOM: Created during incident response
 */
export type BlockSource =
  | 'AUTOMATIC'
  | 'MANUAL'
  | 'FLEET_INTEL'
  | 'EXTERNAL_FEED'
  | 'WAR_ROOM';

/**
 * Individual blocklist entry enforced by sensors.
 */
export interface BlocklistEntry {
  /** Type of indicator being blocked */
  blockType: BlockType;
  /** The blocked indicator value (IP, fingerprint, etc.) */
  indicator: string;
  /** Optional expiration for temporary blocks */
  expiresAt?: Date | null;
  /** Origin of this block entry */
  source: BlockSource;
}

/**
 * Incremental blocklist change operation.
 */
export interface BlocklistUpdate {
  /** Whether to add or remove the block */
  type: 'add' | 'remove';
  /** Type of indicator */
  blockType: BlockType;
  /** Indicator value */
  indicator: string;
  /** Human-readable reason for the change */
  reason?: string;
  /** Expiration for add operations */
  expiresAt?: Date;
  /** Source of this update */
  source: BlockSource;
}

/**
 * Campaign lifecycle states.
 * - ACTIVE: Ongoing attack, blocking in effect
 * - MONITORING: Attack paused, still watching
 * - RESOLVED: Attack mitigated, case closed
 * - FALSE_POSITIVE: Incorrectly identified, removed
 */
export type CampaignStatus = 'ACTIVE' | 'MONITORING' | 'RESOLVED' | 'FALSE_POSITIVE';

/**
 * Correlated attack campaign spanning multiple signals.
 * Campaigns group related threat activity for coordinated response.
 */
export interface Campaign {
  /** Unique campaign identifier */
  id: string;
  /** Human-readable campaign name */
  name: string;
  /** Detailed campaign description */
  description?: string;
  /** Current campaign state */
  status: CampaignStatus;
  /** Overall severity assessment */
  severity: Severity;
  /** Whether campaign affects multiple tenants */
  isCrossTenant: boolean;
  /** Number of tenants impacted */
  tenantsAffected: number;
  /** Correlation confidence (0.0 - 1.0) */
  confidence: number;
  /** First detection timestamp */
  firstSeenAt: Date;
  /** Most recent activity timestamp */
  lastActivityAt: Date;
}

/**
 * Real-time campaign status change notification.
 */
export interface CampaignAlert {
  /** Alert type indicating the change */
  type: 'campaign-detected' | 'campaign-updated' | 'campaign-resolved';
  /** Campaign summary data */
  campaign: {
    id: string;
    name: string;
    severity: Severity;
    isCrossTenant: boolean;
    tenantsAffected: number;
    confidence: number;
  };
  /** Alert timestamp in milliseconds */
  timestamp: number;
}

/**
 * Types of threat indicators tracked.
 */
export type ThreatType =
  | 'IP'
  | 'FINGERPRINT'
  | 'ASN'
  | 'USER_AGENT'
  | 'TLS_FINGERPRINT'
  | 'CREDENTIAL_PATTERN';

/**
 * Aggregated threat entity tracked across time.
 * Represents a persistent threat indicator with risk scoring.
 */
export interface Threat {
  /** Unique threat identifier */
  id: string;
  /** Type of threat indicator */
  threatType: ThreatType;
  /** The actual indicator value */
  indicator: string;
  /** Tenant-specific risk score (0.0 - 100.0) */
  riskScore: number;
  /** Fleet-wide risk score if cross-tenant */
  fleetRiskScore?: number;
  /** Number of times this threat was detected */
  hitCount: number;
  /** Number of tenants affected by this threat */
  tenantsAffected: number;
  /** Whether this is a fleet-wide threat */
  isFleetThreat: boolean;
  /** First detection timestamp */
  firstSeenAt: Date;
  /** Most recent detection timestamp */
  lastSeenAt: Date;
}

/**
 * Real-time threat detection notification.
 */
export interface ThreatAlert {
  /** Threat summary data */
  threat: {
    id: string;
    threatType: ThreatType;
    indicator: string;
    riskScore: number;
    isFleetThreat: boolean;
  };
  /** Alert timestamp in milliseconds */
  timestamp: number;
}

// =============================================================================
// API Response Types
// =============================================================================

/**
 * Hub status response for the `/status` endpoint.
 * Provides operational metrics for monitoring.
 */
export interface HubStatusResponse {
  /** Service identifier */
  hub: 'signal-horizon';
  /** Software version */
  version: string;
  /** Uptime in seconds */
  uptime: number;
  /** Active connection counts */
  connections: {
    /** Connected sensor count */
    sensors: number;
    /** Connected dashboard count */
    dashboards: number;
  };
}

/**
 * Health check response for the `/health` endpoint.
 * Used by load balancers and orchestrators.
 */
export interface HealthResponse {
  /** Health status */
  status: 'healthy' | 'unhealthy';
  /** Service name */
  service: string;
  /** Software version */
  version: string;
  /** ISO 8601 timestamp */
  timestamp: string;
}

/**
 * Readiness check response for the `/ready` endpoint.
 * Indicates whether the service is ready to receive traffic.
 */
export interface ReadyResponse {
  /** Readiness status */
  status: 'ready' | 'not_ready';
  /** Database connection status */
  database: 'connected' | 'disconnected';
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Error message if not ready */
  error?: string;
}
