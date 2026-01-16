/**
 * Default Policy Templates
 * Pre-built security policy templates for Strict, Standard, and Dev environments
 */

import type { PolicyConfig, PolicyTemplate, PolicySeverity } from './policy-template-types.js';

// =============================================================================
// STRICT Policy - Maximum Protection
// =============================================================================

/**
 * Strict policy configuration
 * Maximum protection for production environments handling sensitive data
 * - Block threshold: 50 (aggressive blocking)
 * - All WAF protections enabled at high sensitivity
 * - Aggressive rate limiting
 * - Bot and geo protection enabled
 */
export const STRICT_POLICY_CONFIG: PolicyConfig = {
  blockThreshold: 50,
  logAllRequests: true,
  rateLimit: {
    enabled: true,
    requestsPerSecond: 100,
    burstSize: 50,
    windowSeconds: 60,
  },
  wafProtection: {
    sqlInjection: {
      enabled: true,
      mode: 'block',
      sensitivity: 'high',
    },
    xss: {
      enabled: true,
      mode: 'block',
      sensitivity: 'high',
    },
    commandInjection: {
      enabled: true,
      mode: 'block',
      sensitivity: 'high',
    },
    pathTraversal: {
      enabled: true,
      mode: 'block',
      sensitivity: 'high',
    },
    fileUpload: {
      enabled: true,
      mode: 'block',
      maxSizeBytes: 10485760, // 10MB
      allowedExtensions: ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg', '.jpeg', '.gif'],
    },
  },
  botProtection: {
    enabled: true,
    mode: 'block',
    blockKnownBadBots: true,
    challengeSuspiciousBots: true,
    allowVerifiedBots: true,
    customBotRules: [],
  },
  geoBlocking: {
    enabled: true,
    mode: 'blocklist',
    countries: [], // Configure per-tenant
  },
  ipReputation: {
    enabled: true,
    blockThreshold: 30,
    challengeThreshold: 50,
  },
  customHeaders: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'",
  },
  maxBodySizeBytes: 10485760, // 10MB
  requestTimeoutMs: 30000, // 30 seconds
  debugMode: false,
};

// =============================================================================
// STANDARD Policy - Balanced Protection
// =============================================================================

/**
 * Standard policy configuration
 * Balanced protection for typical production environments
 * - Block threshold: 70 (balanced blocking)
 * - WAF protections at medium sensitivity
 * - Moderate rate limiting
 * - Bot protection enabled with challenge mode
 */
export const STANDARD_POLICY_CONFIG: PolicyConfig = {
  blockThreshold: 70,
  logAllRequests: true,
  rateLimit: {
    enabled: true,
    requestsPerSecond: 500,
    burstSize: 200,
    windowSeconds: 60,
  },
  wafProtection: {
    sqlInjection: {
      enabled: true,
      mode: 'block',
      sensitivity: 'medium',
    },
    xss: {
      enabled: true,
      mode: 'block',
      sensitivity: 'medium',
    },
    commandInjection: {
      enabled: true,
      mode: 'block',
      sensitivity: 'medium',
    },
    pathTraversal: {
      enabled: true,
      mode: 'block',
      sensitivity: 'medium',
    },
    fileUpload: {
      enabled: true,
      mode: 'block',
      maxSizeBytes: 52428800, // 50MB
      allowedExtensions: ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg', '.jpeg', '.gif', '.zip', '.tar', '.gz'],
    },
  },
  botProtection: {
    enabled: true,
    mode: 'challenge',
    blockKnownBadBots: true,
    challengeSuspiciousBots: true,
    allowVerifiedBots: true,
    customBotRules: [],
  },
  geoBlocking: {
    enabled: false,
    mode: 'blocklist',
    countries: [],
  },
  ipReputation: {
    enabled: true,
    blockThreshold: 20,
    challengeThreshold: 40,
  },
  customHeaders: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
  },
  maxBodySizeBytes: 52428800, // 50MB
  requestTimeoutMs: 60000, // 60 seconds
  debugMode: false,
};

// =============================================================================
// DEV Policy - Minimal Blocking
// =============================================================================

/**
 * Dev policy configuration
 * Minimal blocking for development and testing environments
 * - Block threshold: 90 (minimal blocking)
 * - WAF protections in log mode
 * - Relaxed rate limiting
 * - Debug mode enabled
 */
export const DEV_POLICY_CONFIG: PolicyConfig = {
  blockThreshold: 90,
  logAllRequests: true,
  rateLimit: {
    enabled: true,
    requestsPerSecond: 10000,
    burstSize: 5000,
    windowSeconds: 60,
  },
  wafProtection: {
    sqlInjection: {
      enabled: true,
      mode: 'log',
      sensitivity: 'low',
    },
    xss: {
      enabled: true,
      mode: 'log',
      sensitivity: 'low',
    },
    commandInjection: {
      enabled: true,
      mode: 'log',
      sensitivity: 'low',
    },
    pathTraversal: {
      enabled: true,
      mode: 'log',
      sensitivity: 'low',
    },
    fileUpload: {
      enabled: true,
      mode: 'log',
      maxSizeBytes: 104857600, // 100MB
      allowedExtensions: [], // Allow all
    },
  },
  botProtection: {
    enabled: false,
    mode: 'log',
    blockKnownBadBots: false,
    challengeSuspiciousBots: false,
    allowVerifiedBots: true,
    customBotRules: [],
  },
  geoBlocking: {
    enabled: false,
    mode: 'blocklist',
    countries: [],
  },
  ipReputation: {
    enabled: false,
    blockThreshold: 10,
    challengeThreshold: 20,
  },
  customHeaders: {},
  maxBodySizeBytes: 104857600, // 100MB
  requestTimeoutMs: 120000, // 120 seconds
  debugMode: true,
};

// =============================================================================
// Default Template Generators
// =============================================================================

/**
 * Create default policy templates for a tenant
 */
export function createDefaultTemplates(tenantId: string): Omit<PolicyTemplate, 'id' | 'createdAt' | 'updatedAt'>[] {
  return [
    {
      tenantId,
      name: 'Strict Security Policy',
      description: 'Maximum protection for production environments handling sensitive data. Aggressive blocking with all WAF features enabled at high sensitivity.',
      severity: 'strict' as PolicySeverity,
      config: STRICT_POLICY_CONFIG,
      metadata: {
        category: 'default',
        compliance: ['PCI-DSS', 'HIPAA', 'SOC2'],
        tags: ['production', 'high-security', 'sensitive-data'],
      },
      isDefault: true,
      isActive: true,
      version: '1.0.0',
    },
    {
      tenantId,
      name: 'Standard Security Policy',
      description: 'Balanced protection for typical production environments. Good balance between security and usability.',
      severity: 'standard' as PolicySeverity,
      config: STANDARD_POLICY_CONFIG,
      metadata: {
        category: 'default',
        compliance: ['SOC2'],
        tags: ['production', 'balanced', 'general-purpose'],
      },
      isDefault: true,
      isActive: true,
      version: '1.0.0',
    },
    {
      tenantId,
      name: 'Development Policy',
      description: 'Minimal blocking for development and testing environments. WAF rules in log mode for visibility without blocking.',
      severity: 'dev' as PolicySeverity,
      config: DEV_POLICY_CONFIG,
      metadata: {
        category: 'default',
        tags: ['development', 'testing', 'debugging'],
      },
      isDefault: true,
      isActive: true,
      version: '1.0.0',
    },
  ];
}

/**
 * Get default policy config by severity level
 */
export function getDefaultPolicyConfig(severity: PolicySeverity): PolicyConfig {
  switch (severity) {
    case 'strict':
      return { ...STRICT_POLICY_CONFIG };
    case 'standard':
      return { ...STANDARD_POLICY_CONFIG };
    case 'dev':
      return { ...DEV_POLICY_CONFIG };
    default:
      return { ...STANDARD_POLICY_CONFIG };
  }
}

/**
 * Default template IDs (for reference when seeding)
 */
export const DEFAULT_TEMPLATE_NAMES = {
  STRICT: 'Strict Security Policy',
  STANDARD: 'Standard Security Policy',
  DEV: 'Development Policy',
} as const;
