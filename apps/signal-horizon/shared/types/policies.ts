/**
 * Shared policy types for Signal Horizon.
 *
 * These types define the contract between the API and UI for security policy templates.
 */

/**
 * Security policy severity levels
 */
export type PolicySeverity = 'strict' | 'standard' | 'dev';

/**
 * Policy enforcement mode
 */
export type EnforcementMode = 'block' | 'log' | 'challenge';

/**
 * Rate limiting configuration
 */
export interface RateLimitConfig {
  enabled: boolean;
  requestsPerSecond: number;
  burstSize: number;
  windowSeconds: number;
}

/**
 * WAF protection settings
 */
export interface WAFProtectionSettings {
  sqlInjection: {
    enabled: boolean;
    mode: EnforcementMode;
    sensitivity: 'low' | 'medium' | 'high';
  };
  xss: {
    enabled: boolean;
    mode: EnforcementMode;
    sensitivity: 'low' | 'medium' | 'high';
  };
  commandInjection: {
    enabled: boolean;
    mode: EnforcementMode;
    sensitivity: 'low' | 'medium' | 'high';
  };
  pathTraversal: {
    enabled: boolean;
    mode: EnforcementMode;
    sensitivity: 'low' | 'medium' | 'high';
  };
  fileUpload: {
    enabled: boolean;
    mode: EnforcementMode;
    maxSizeBytes: number;
    allowedExtensions: string[];
  };
}

/**
 * Bot protection settings
 */
export interface BotProtectionSettings {
  enabled: boolean;
  mode: EnforcementMode;
  blockKnownBadBots: boolean;
  challengeSuspiciousBots: boolean;
  allowVerifiedBots: boolean;
  customBotRules: Array<{
    userAgentPattern: string;
    action: EnforcementMode;
  }>;
}

/**
 * Geo-blocking settings
 */
export interface GeoBlockingSettings {
  enabled: boolean;
  mode: 'allowlist' | 'blocklist';
  countries: string[];
}

/**
 * IP reputation settings
 */
export interface IPReputationSettings {
  enabled: boolean;
  blockThreshold: number; // 0-100, lower = more strict
  challengeThreshold: number;
}

/**
 * Complete policy configuration
 */
export interface PolicyConfig {
  /** Overall threat blocking threshold (0-100) */
  blockThreshold: number;
  /** Log all requests for analysis */
  logAllRequests: boolean;
  /** Rate limiting configuration */
  rateLimit: RateLimitConfig;
  /** WAF protection settings */
  wafProtection: WAFProtectionSettings;
  /** Bot protection settings */
  botProtection: BotProtectionSettings;
  /** Geo-blocking settings */
  geoBlocking: GeoBlockingSettings;
  /** IP reputation settings */
  ipReputation: IPReputationSettings;
  /** Custom headers to inject */
  customHeaders: Record<string, string>;
  /** Request body size limit in bytes */
  maxBodySizeBytes: number;
  /** Request timeout in milliseconds */
  requestTimeoutMs: number;
  /** Enable detailed logging for debugging */
  debugMode: boolean;
}

/**
 * Policy template metadata
 */
export interface PolicyTemplateMetadata {
  /** Template category */
  category: 'default' | 'custom' | 'industry';
  /** Industry vertical (e.g., 'fintech', 'healthcare', 'ecommerce') */
  industry?: string;
  /** Compliance standards this template helps with */
  compliance?: string[];
  /** Template author */
  author?: string;
  /** Tags for searchability */
  tags?: string[];
}

/**
 * Security policy template
 */
export interface PolicyTemplate {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  severity: PolicySeverity;
  config: PolicyConfig;
  metadata: PolicyTemplateMetadata;
  isDefault: boolean;
  isActive: boolean;
  version: string;
  createdAt: Date;
  updatedAt: Date;
}
