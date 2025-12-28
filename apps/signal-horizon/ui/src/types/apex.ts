// ============================================
// APEX PROTECTION CONSOLE - TYPE DEFINITIONS
// ============================================

// Dashboard Types
export interface ApexDashboard {
  status: 'protected' | 'degraded' | 'critical';
  siteCount: number;
  endpointCount: number;
  activeRuleCount: number;
  lastUpdated: string;
  summary: {
    requests: MetricWithTrend;
    blocked: MetricWithTrend;
    threats: MetricWithTrend;
    coverage: MetricWithTrend;
  };
  trafficTimeline: TrafficDataPoint[];
  attackTypes: AttackTypeData[];
  recentThreats: ThreatEvent[];
  topEndpoints: EndpointThreatCount[];
  alerts: ProtectionAlert[];
}

export interface MetricWithTrend {
  value: number;
  trend: number;
  period: string;
}

export interface TrafficDataPoint {
  timestamp: string;
  requests: number;
  blocked: number;
}

export interface AttackTypeData {
  type: string;
  count: number;
  percentage: number;
}

export interface EndpointThreatCount {
  endpoint: string;
  threatCount: number;
}

export interface ProtectionAlert {
  id: string;
  type: 'endpoint_discovered' | 'schema_change' | 'rule_triggered' | 'deployment_complete';
  title: string;
  description: string;
  timestamp: string;
  severity: RuleSeverity;
}

// API Catalog Types
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface Endpoint {
  id: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  path: string;
  pathTemplate: string;
  service: string;
  riskLevel: RiskLevel;
  sensitiveFields: string[];
  protectionStatus: 'protected' | 'unprotected' | 'partial';
  activeRules: string[];
  requestCount24h: number;
  lastSeen: string;
  firstSeen: string;
  detectedSchema?: EndpointSchema;
}

export interface EndpointSchema {
  request: SchemaField[];
  response: SchemaField[];
}

export interface SchemaField {
  name: string;
  type: string;
  format?: string;
  sensitive: boolean;
  optional: boolean;
}

export interface SchemaChange {
  id: string;
  endpointId: string;
  endpoint: string;
  timestamp: string;
  changeType: 'field_added' | 'field_removed' | 'type_changed';
  field: string;
  oldValue?: string;
  newValue?: string;
  riskLevel: RiskLevel;
}

export interface Service {
  id: string;
  name: string;
  endpointCount: number;
  protectedCount: number;
  coveragePercent: number;
}

// Rules Types
export type RuleCategory = 'injection' | 'bot' | 'auth' | 'rate-limit' | 'custom';
export type RuleAction = 'log' | 'challenge' | 'block';
export type RuleSeverity = 'low' | 'medium' | 'high' | 'critical';
export type RolloutStrategy = 'immediate' | 'canary' | 'scheduled';
export type DeploymentStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'rolled_back';

export interface Rule {
  id: string;
  name: string;
  description: string;
  category: RuleCategory;
  severity: RuleSeverity;
  action: RuleAction;
  patterns: DetectionPattern[];
  exclusions: RuleExclusion[];
  sensitivity: number;
  enabled: boolean;
  deployedSensors: number;
  totalSensors: number;
  triggers24h: number;
  lastTriggered?: string;
  rolloutStrategy: RolloutStrategy;
  rolloutStatus?: RolloutStatus;
}

export interface DetectionPattern {
  type: string;
  value: string;
  locations: string[];
}

export interface RuleExclusion {
  type: 'endpoint' | 'ip' | 'path';
  value: string;
  reason?: string;
}

export interface RolloutStatus {
  currentStage: number;
  totalStages: number;
  progress: number;
}

export interface RuleDeployment {
  id: string;
  ruleId: string;
  strategy: RolloutStrategy;
  stages: DeploymentStage[];
  currentStage: number;
  status: DeploymentStatus;
}

export interface DeploymentStage {
  stage: number;
  percentage: number;
  sensorCount: number;
  successCount: number;
  failureCount: number;
  startedAt?: string;
  completedAt?: string;
}

export interface RuleTemplate {
  id: string;
  name: string;
  description: string;
  category: RuleCategory;
  severity: RuleSeverity;
  previewMatches: string[];
}

// Threats Types
export interface BlockedRequest {
  id: string;
  timestamp: string;
  action: 'blocked' | 'challenged' | 'throttled' | 'logged';
  threatType: string;
  sourceIp: string;
  endpoint: string;
  method: string;
  ruleId?: string;
  ruleName?: string;
  riskScore: number;
}

export interface DecisionTrace {
  requestId: string;
  timestamp: string;
  request: {
    method: string;
    path: string;
    sourceIp: string;
    headers: Record<string, string>;
  };
  verdict: 'allow' | 'challenge' | 'block' | 'throttle';
  riskScore: number;
  matchedRule?: string;
  factors: RiskFactor[];
  detectionDetails?: DetectionDetails;
  entity: EntityContext;
}

export interface RiskFactor {
  name: string;
  contribution: number;
  description: string;
}

export interface DetectionDetails {
  pattern: string;
  location: string;
  value: string;
  signatures: string[];
}

export interface EntityContext {
  ip: string;
  country: string;
  asn: string;
  firstSeen: string;
  requests24h: number;
  blocked24h: number;
  fingerprint?: string;
  status: 'clean' | 'suspicious' | 'blocklisted';
  campaigns?: string[];
}

export interface AttackPattern {
  type: string;
  count: number;
  percentage: number;
  trend: number;
}

export interface ThreatEvent {
  id: string;
  timestamp: string;
  type: string;
  sourceIp: string;
  action: string;
  rule?: string;
}

// Analytics Types
export interface ResponseTimeMetrics {
  p50: number;
  p75: number;
  p95: number;
  p99: number;
  trend: {
    p50: number;
    p95: number;
    p99: number;
  };
}

export interface ErrorAnalysis {
  total: number;
  rate: number;
  breakdown: {
    status4xx: number;
    status5xx: number;
  };
  byType: ErrorTypeCount[];
}

export interface ErrorTypeCount {
  statusCode: number;
  count: number;
  percentage: number;
}
