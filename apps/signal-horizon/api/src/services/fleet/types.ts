/**
 * Fleet Management Types
 * Shared types for fleet services
 */

export interface SensorMetricsSnapshot {
  sensorId: string;
  tenantId: string;
  hostname?: string;
  region?: string;
  rps: number;
  latency: number; // milliseconds
  cpu: number; // percentage 0-100
  memory: number; // percentage 0-100
  disk: number; // percentage 0-100
  health: 'healthy' | 'degraded' | 'critical';
  lastHeartbeat: Date;
  requestsTotal: number;
  configHash?: string;
  rulesHash?: string;
}

export interface FleetMetrics {
  totalSensors: number;
  onlineSensors: number;
  offlineSensors: number;
  totalRps: number;
  avgLatency: number;
  healthScore: number; // 0-100
  avgCpu: number;
  avgMemory: number;
  avgDisk: number;
  timestamp: Date;
}

export interface RegionMetrics {
  region: string;
  sensors: number;
  onlineSensors: number;
  totalRps: number;
  avgLatency: number;
  healthScore: number;
}

export interface SensorAlert {
  sensorId: string;
  tenantId: string;
  alertType: 'degraded' | 'high_cpu' | 'high_memory' | 'high_disk' | 'offline';
  severity: 'warning' | 'critical';
  message: string;
  value?: number;
  threshold?: number;
}

export interface ConfigTemplate {
  id: string;
  name: string;
  description?: string;
  environment: 'production' | 'staging' | 'dev';
  config: Record<string, unknown>;
  hash: string;
  version: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface ConfigSyncState {
  sensorId: string;
  configInSync: boolean;
  rulesInSync: boolean;
  blocklistInSync: boolean;
  lastSyncAttempt?: Date;
  lastSyncSuccess?: Date;
  syncErrors: string[];
}

export interface FleetSyncStatus {
  totalSensors: number;
  syncedSensors: number;
  outOfSyncSensors: number;
  errorSensors: number;
  syncPercentage: number;
}

export interface ConfigDiff {
  sensorId: string;
  currentConfig: Record<string, unknown> | null;
  targetConfig: Record<string, unknown>;
  differences: Array<{
    path: string;
    current: unknown;
    target: unknown;
    action: 'add' | 'modify' | 'remove';
  }>;
}

export interface DeploymentResult {
  success: boolean;
  totalTargets: number;
  successCount: number;
  failureCount: number;
  pendingCount: number;
  results: Array<{
    sensorId: string;
    success: boolean;
    error?: string;
    commandId?: string;
  }>;
  /** ID of the persisted scheduled deployment (only for scheduled strategy) */
  scheduledDeploymentId?: string;
}

export interface SensorCommand {
  type: 'push_config' | 'push_rules' | 'update' | 'restart' | 'sync_blocklist' | 'toggle_chaos' | 'toggle_mtd';
  payload: Record<string, unknown>;
  timeout?: number; // milliseconds, default 30000
}

export interface CommandStatus {
  commandId: string;
  sensorId: string;
  status: 'pending' | 'sent' | 'success' | 'failed' | 'timeout';
  result?: Record<string, unknown>;
  error?: string;
  queuedAt: Date;
  sentAt?: Date;
  completedAt?: Date;
  attempts: number;
}

export interface Command {
  id: string;
  sensorId: string;
  commandType: string;
  payload: Record<string, unknown>;
  status: string;
  result?: Record<string, unknown>;
  error?: string;
  queuedAt: Date;
  sentAt?: Date;
  completedAt?: Date;
  attempts: number;
  timeoutAt: Date;
}

export interface RuleSyncStatus {
  sensorId: string;
  totalRules: number;
  syncedRules: number;
  pendingRules: number;
  failedRules: number;
  lastSync?: Date;
  errors: string[];
}

export interface SensorRuleStatus {
  sensorId: string;
  rules: Array<{
    ruleId: string;
    status: 'pending' | 'synced' | 'failed';
    syncedAt?: Date;
    error?: string;
  }>;
}

export interface Rule {
  id: string;
  name: string;
  conditions: Record<string, unknown>;
  actions: Record<string, unknown>;
  enabled: boolean;
  priority: number;
}

export type RolloutStrategy = 'immediate' | 'canary' | 'scheduled' | 'rolling' | 'blue_green';

export interface RolloutConfig {
  strategy: RolloutStrategy;
  canaryPercentages?: number[]; // e.g., [10, 50, 100]
  delayBetweenStages?: number; // milliseconds
  scheduledTime?: Date;
  // Rolling strategy options
  rollingBatchSize?: number; // Default: 1
  healthCheckTimeout?: number; // Default: 30000ms
  rollbackOnFailure?: boolean; // Default: true
  maxFailuresBeforeAbort?: number; // Default: 3
  healthCheckIntervalMs?: number; // Default: 5000ms
  // Blue/Green strategy options
  stagingTimeout?: number; // Default: 60000ms
  switchTimeout?: number; // Default: 30000ms
  requireAllSensorsStaged?: boolean; // Default: true
  minStagedPercentage?: number; // Default: 100
  cleanupDelayMs?: number; // Default: 300000 (5 min)
}

/**
 * Result of a health check on a sensor
 */
export interface HealthCheckResult {
  healthy: boolean;
  sensorId: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'timeout';
  latencyMs?: number;
  errorMessage?: string;
}

/**
 * State of a rolling deployment in progress
 */
export interface RollingDeploymentState {
  deploymentId: string;
  totalSensors: number;
  completedSensors: number;
  failedSensors: number;
  currentBatch: string[];
  status: 'in_progress' | 'completed' | 'aborted' | 'rolling_back';
  startTime: Date;
  lastUpdateTime: Date;
}

/**
 * Result of a sensor deployment attempt
 */
export interface SensorDeployResult {
  sensorId: string;
  status: 'success' | 'failed';
  error?: string;
}

/**
 * Sensor Heartbeat (from protocol types, extended for fleet management)
 */
export interface SensorHeartbeat {
  sensorId: string;
  tenantId: string;
  timestamp: Date;
  metrics: {
    rps: number;
    latency: number;
    cpu: number;
    memory: number;
    disk: number;
  };
  health: 'healthy' | 'degraded' | 'critical';
  requestsTotal: number;
  configHash?: string;
  rulesHash?: string;
  region?: string;
  metadata?: Record<string, unknown>;
}

// =============================================================================
// Blue/Green Deployment Types
// =============================================================================

/**
 * State of a Blue/Green deployment
 */
export interface BlueGreenDeploymentState {
  deploymentId: string;
  status: 'staging' | 'staged' | 'switching' | 'active' | 'retired' | 'failed';
  rules: Rule[];
  stagedAt?: Date;
  activatedAt?: Date;
  retiredAt?: Date;
  sensorStatus: Map<string, BlueGreenSensorStatus>;
}

/**
 * Status of a single sensor in a Blue/Green deployment
 */
export interface BlueGreenSensorStatus {
  sensorId: string;
  stagingStatus: 'pending' | 'staged' | 'failed';
  activeStatus: 'blue' | 'green' | 'unknown';
  lastUpdated: Date;
  error?: string;
}

/**
 * Configuration options for Blue/Green deployments
 */
export interface BlueGreenConfig {
  /** Timeout for staging phase in milliseconds. Default: 60000ms */
  stagingTimeout?: number;
  /** Timeout for switch phase in milliseconds. Default: 30000ms */
  switchTimeout?: number;
  /** Whether all sensors must be staged before switch. Default: true */
  requireAllSensorsStaged?: boolean;
  /** Minimum percentage of sensors that must be staged (when requireAllSensorsStaged is false). Default: 100 */
  minStagedPercentage?: number;
  /** Delay before cleaning up old blue deployment in milliseconds. Default: 300000 (5 min) */
  cleanupDelayMs?: number;
}

/**
 * Extended deployment result for Blue/Green strategy
 */
export interface BlueGreenDeploymentResult {
  strategy: 'blue_green';
  deploymentId: string;
  sensors: Array<{
    sensorId: string;
    status: 'success' | 'failed';
    error?: string;
  }>;
  status: 'completed' | 'failed';
  error?: string;
  metadata?: {
    stagedAt?: Date;
    activatedAt?: Date;
  };
}
