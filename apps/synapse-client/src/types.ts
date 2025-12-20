/**
 * Synapse API Client Types
 * TypeScript interfaces for the Synapse (risk-server) API
 */

// ============================================================================
// Client Options
// ============================================================================

export interface SynapseClientOptions {
  /** Base URL of the Synapse server (e.g., "http://localhost:3000") */
  baseUrl: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Enable verbose debug logging */
  debug?: boolean;
}

// ============================================================================
// Sensor Status & Metrics
// ============================================================================

export interface SensorStatus {
  totalRequests: number;
  blockedRequests: number;
  requestRate: number;
  blockRate: number;
  fallbackRate: number;
  rulesCount: number;
  autoblockThreshold: number;
  riskDecayPerMinute: number;
  riskBasedBlockingEnabled: boolean;
  requestBlockingEnabled: boolean;
  allowIpSpoofing: boolean;
  mode: 'demo' | 'production' | 'atlascrew';
}

export interface HealthResponse {
  status: string;
  service: string;
  uptime?: number;
  version?: string;
}

// ============================================================================
// Entity Management
// ============================================================================

export interface Entity {
  id: string;
  ip?: string;
  risk: number;
  requestCount: number;
  blocked: boolean;
  blockedReason?: string;
  firstSeen: string;
  lastSeen: string;
  matches?: EntityRuleMatch[];
}

export interface EntityRuleMatch {
  ruleId: number;
  count: number;
  firstMatchedAt: string;
  lastMatchedAt: string;
  reasons?: string[];
}

export interface Block {
  id: string;
  entityId: string;
  ip: string;
  mode: 'risk' | 'rule';
  ruleId?: number;
  reason: string;
  blockedAt: string;
  risk?: number;
}

export interface EntitiesResponse {
  entities: Entity[];
  count?: number;
}

export interface BlocksResponse {
  blocks: Block[];
  count?: number;
}

export interface ReleaseResponse {
  released: boolean;
  entityId?: string;
  ip?: string;
}

export interface ReleaseAllResponse {
  released: number;
}

// ============================================================================
// Configuration
// ============================================================================

export interface WafConfig {
  riskBasedBlockingEnabled: boolean;
  requestBlockingEnabled: boolean;
  autoblockThreshold: number;
  riskDecayPerMinute: number;
  allowIpSpoofing: boolean;
  trustedIpHeaders: string[];
  trustPrivateProxyRanges: boolean;
  trustedProxyCidrs: string[];
}

export interface SystemConfig extends WafConfig {
  targetOrigin: string;
  port: number;
  wafRulesPath: string;
  advancedRuleSupport: boolean;
  maxIpsTracked?: number;
  maxKeysPerIp?: number;
  maxValuesPerKey?: number;
}

export interface ConfigResponse {
  config: SystemConfig;
}

export interface ConfigUpdateResponse {
  config: WafConfig;
  updated: string[];
}

// ============================================================================
// WAF Rules
// ============================================================================

export interface MatchCondition {
  type: string;
  match?: unknown;
  op?: string;
  field?: string;
  direction?: 'c2s' | 's2c';
}

export interface Rule {
  id: number;
  name?: string | null;
  description: string;
  classification?: string | null;
  state?: string | null;
  contributing_score?: number | null;
  risk?: number | null;
  blocking?: boolean | null;
  tarpit?: boolean | null;
  interogate?: boolean | null;
  beta?: boolean | null;
  matches: MatchCondition[];
  /** For runtime rules: TTL in seconds */
  ttl?: number;
  /** For runtime rules: expiration timestamp */
  expiresAt?: string;
  /** Runtime rule hit count */
  hitCount?: number;
}

export interface RuleStats {
  total: number;
  blocking: number;
  riskBased: number;
  runtime: number;
}

export interface RulesResponse {
  rules: Rule[];
  stats: RuleStats;
}

export interface RuleDefinition {
  name?: string;
  description: string;
  classification?: string;
  risk?: number;
  blocking?: boolean;
  tarpit?: boolean;
  matches: MatchCondition[];
}

export interface AddRuleResponse {
  success: boolean;
  rule: Rule;
  stats: RuleStats;
}

export interface RemoveRuleResponse {
  removed: boolean;
  stats: RuleStats;
}

export interface ClearRulesResponse {
  cleared: number;
  stats: RuleStats;
}

export interface ReloadRulesResponse {
  success: boolean;
  message: string;
  stats: {
    total: number;
    blocking: number;
    riskBased: number;
  };
}

// ============================================================================
// Rule Evaluation
// ============================================================================

export interface EvaluateRequest {
  method?: string;
  url?: string;
  path?: string;
  headers?: Record<string, string>;
  body?: string;
  ip?: string;
  /** Optional: filter to specific rule IDs */
  ruleIds?: number[];
}

export interface EvaluateResult {
  matched: boolean;
  totalRisk: number;
  wouldBlock: boolean;
  blockReason?: string;
  matchedRules: {
    id: number;
    name?: string;
    risk: number;
    blocking: boolean;
    reasons: string[];
  }[];
}

// ============================================================================
// Actor Tracking
// ============================================================================

export interface Actor {
  ip: string;
  risk: number;
  sessionCount: number;
  fingerprintCount: number;
  jsExecuted: boolean;
  suspicious: boolean;
  userAgents: string[];
  fingerprint?: string;
  firstActivity: string;
  lastActivity: string;
}

export interface ActorsResponse {
  actors: Actor[];
  count: number;
}

export interface ActorStats {
  totalActors: number;
  suspiciousActors: number;
  jsExecutedCount: number;
  fingerprintChanges: number;
  averageSessionCount: number;
}

export interface SetFingerprintResponse {
  success: boolean;
  actor: Actor;
}

// ============================================================================
// Error Types
// ============================================================================

export class SynapseError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
    public readonly response?: string
  ) {
    super(message);
    this.name = 'SynapseError';
  }
}
