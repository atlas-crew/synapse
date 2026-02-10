/**
 * Rules Demo Data Generator
 *
 * Generates Rule[] and RuleTemplate[] for demo scenarios.
 */

import type { DemoScenario } from '../../../stores/demoModeStore';
import type {
  Rule,
  RuleTemplate,
  RuleCategory,
  RuleSeverity,
  RuleAction,
  RolloutStrategy,
  DetectionPattern,
  RuleExclusion,
} from '../../../types/beam';
import { getScenarioProfile } from '../scenarios';

// Rule definitions with realistic names and patterns
const RULE_DEFINITIONS: Array<{
  name: string;
  description: string;
  category: RuleCategory;
  baseSeverity: RuleSeverity;
  baseAction: RuleAction;
  patterns: DetectionPattern[];
}> = [
  {
    name: 'SQL Injection Protection',
    description: 'Detects and blocks SQL injection attempts in request parameters',
    category: 'injection',
    baseSeverity: 'critical',
    baseAction: 'block',
    patterns: [
      { type: 'regex', value: "('|\")?\\s*(OR|AND)\\s+\\d+\\s*=\\s*\\d+", locations: ['query', 'body'] },
      { type: 'regex', value: 'UNION\\s+SELECT', locations: ['query', 'body'] },
      { type: 'keyword', value: 'DROP TABLE', locations: ['query', 'body'] },
    ],
  },
  {
    name: 'XSS Attack Prevention',
    description: 'Blocks cross-site scripting attacks in input fields',
    category: 'injection',
    baseSeverity: 'high',
    baseAction: 'block',
    patterns: [
      { type: 'regex', value: '<script[^>]*>.*</script>', locations: ['body', 'query'] },
      { type: 'regex', value: 'javascript:\\s*', locations: ['body', 'query'] },
      { type: 'keyword', value: 'onerror=', locations: ['body', 'query'] },
    ],
  },
  {
    name: 'Bot Detection - Automated Tools',
    description: 'Identifies and challenges requests from known automated tools',
    category: 'bot',
    baseSeverity: 'medium',
    baseAction: 'challenge',
    patterns: [
      { type: 'header', value: 'User-Agent: curl/*', locations: ['headers'] },
      { type: 'header', value: 'User-Agent: python-requests/*', locations: ['headers'] },
      { type: 'header', value: 'User-Agent: Go-http-client/*', locations: ['headers'] },
    ],
  },
  {
    name: 'Credential Stuffing Prevention',
    description: 'Detects credential stuffing attacks on authentication endpoints',
    category: 'auth',
    baseSeverity: 'critical',
    baseAction: 'block',
    patterns: [
      { type: 'behavior', value: 'high_login_rate', locations: ['endpoint'] },
      { type: 'behavior', value: 'credential_rotation', locations: ['body'] },
    ],
  },
  {
    name: 'API Rate Limiting',
    description: 'Enforces rate limits to prevent API abuse',
    category: 'rate-limit',
    baseSeverity: 'low',
    baseAction: 'challenge',
    patterns: [
      { type: 'rate', value: '100/minute', locations: ['ip'] },
      { type: 'rate', value: '1000/hour', locations: ['ip'] },
    ],
  },
  {
    name: 'Path Traversal Protection',
    description: 'Blocks directory traversal attempts',
    category: 'injection',
    baseSeverity: 'high',
    baseAction: 'block',
    patterns: [
      { type: 'regex', value: '\\.\\./|\\.\\.\\\\', locations: ['path', 'query'] },
      { type: 'keyword', value: '/etc/passwd', locations: ['path', 'query'] },
    ],
  },
  {
    name: 'Bot Detection - Headless Browsers',
    description: 'Identifies headless browser automation',
    category: 'bot',
    baseSeverity: 'medium',
    baseAction: 'challenge',
    patterns: [
      { type: 'fingerprint', value: 'headless_chrome', locations: ['headers'] },
      { type: 'fingerprint', value: 'phantom_js', locations: ['headers'] },
    ],
  },
  {
    name: 'Authentication Brute Force',
    description: 'Detects brute force attempts on login endpoints',
    category: 'auth',
    baseSeverity: 'high',
    baseAction: 'block',
    patterns: [
      { type: 'behavior', value: 'failed_login_rate', locations: ['endpoint'] },
      { type: 'threshold', value: '5_failures_in_1_minute', locations: ['ip'] },
    ],
  },
  {
    name: 'Sensitive Data Exposure',
    description: 'Monitors for sensitive data in API responses',
    category: 'custom',
    baseSeverity: 'high',
    baseAction: 'log',
    patterns: [
      { type: 'regex', value: '\\b\\d{3}-\\d{2}-\\d{4}\\b', locations: ['response'] },
      { type: 'regex', value: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', locations: ['response'] },
    ],
  },
  {
    name: 'API Endpoint Rate Limit',
    description: 'Per-endpoint rate limiting for high-value APIs',
    category: 'rate-limit',
    baseSeverity: 'medium',
    baseAction: 'challenge',
    patterns: [
      { type: 'rate', value: '10/second', locations: ['endpoint'] },
    ],
  },
  {
    name: 'Command Injection Protection',
    description: 'Blocks OS command injection attempts',
    category: 'injection',
    baseSeverity: 'critical',
    baseAction: 'block',
    patterns: [
      { type: 'regex', value: ';\\s*(cat|ls|rm|wget|curl)\\s', locations: ['body', 'query'] },
      { type: 'keyword', value: '| /bin/', locations: ['body', 'query'] },
    ],
  },
  {
    name: 'Scanner Detection',
    description: 'Identifies vulnerability scanner traffic',
    category: 'bot',
    baseSeverity: 'medium',
    baseAction: 'block',
    patterns: [
      { type: 'header', value: 'User-Agent: Nikto/*', locations: ['headers'] },
      { type: 'header', value: 'User-Agent: sqlmap/*', locations: ['headers'] },
      { type: 'behavior', value: 'sequential_path_probing', locations: ['request'] },
    ],
  },
  {
    name: 'JWT Token Validation',
    description: 'Validates JWT tokens and detects tampering',
    category: 'auth',
    baseSeverity: 'high',
    baseAction: 'block',
    patterns: [
      { type: 'signature', value: 'invalid_jwt_signature', locations: ['headers'] },
      { type: 'expiry', value: 'expired_token', locations: ['headers'] },
    ],
  },
  {
    name: 'GraphQL Depth Limit',
    description: 'Prevents deeply nested GraphQL queries',
    category: 'rate-limit',
    baseSeverity: 'medium',
    baseAction: 'block',
    patterns: [
      { type: 'depth', value: 'max_depth_10', locations: ['body'] },
    ],
  },
  {
    name: 'Custom Business Logic',
    description: 'Custom rule for application-specific threats',
    category: 'custom',
    baseSeverity: 'medium',
    baseAction: 'log',
    patterns: [
      { type: 'custom', value: 'business_rule_violation', locations: ['request'] },
    ],
  },
];

// Template definitions for suggested rules
const TEMPLATE_DEFINITIONS: Array<{
  name: string;
  description: string;
  category: RuleCategory;
  severity: RuleSeverity;
  previewMatches: string[];
}> = [
  {
    name: 'LDAP Injection Protection',
    description: 'Detect and block LDAP injection attempts',
    category: 'injection',
    severity: 'critical',
    previewMatches: ['*(|(objectClass=*))', '*)(&', '*)(uid=*))(|(uid=*'],
  },
  {
    name: 'XML External Entity (XXE)',
    description: 'Prevent XXE attacks in XML payloads',
    category: 'injection',
    severity: 'critical',
    previewMatches: ['<!DOCTYPE foo [<!ENTITY xxe', '<!ENTITY % dtd SYSTEM'],
  },
  {
    name: 'Server-Side Request Forgery',
    description: 'Block SSRF attempts targeting internal services',
    category: 'injection',
    severity: 'high',
    previewMatches: ['http://169.254.169.254', 'http://localhost', 'http://127.0.0.1'],
  },
  {
    name: 'API Key Rotation Alert',
    description: 'Alert when API keys are rotated frequently',
    category: 'auth',
    severity: 'medium',
    previewMatches: ['3+ key rotations in 24h', 'Unusual key generation pattern'],
  },
  {
    name: 'DDoS Layer 7 Protection',
    description: 'Mitigate application-layer DDoS attacks',
    category: 'rate-limit',
    severity: 'high',
    previewMatches: ['1000+ requests/second from single IP', 'Distributed attack pattern'],
  },
  {
    name: 'Web Scraping Detection',
    description: 'Identify and challenge web scraping bots',
    category: 'bot',
    severity: 'low',
    previewMatches: ['Sequential page access', 'Missing browser fingerprint', 'High page-to-session ratio'],
  },
  {
    name: 'Account Takeover Prevention',
    description: 'Detect account takeover attempts',
    category: 'auth',
    severity: 'critical',
    previewMatches: ['Impossible travel', 'New device + password change', 'Bulk account access'],
  },
  {
    name: 'GraphQL Introspection Block',
    description: 'Block GraphQL schema introspection in production',
    category: 'custom',
    severity: 'medium',
    previewMatches: ['__schema', '__type', 'introspectionQuery'],
  },
];

// Helper to generate random exclusions
function generateExclusions(scenario: DemoScenario): RuleExclusion[] {
  const exclusions: RuleExclusion[] = [];

  if (scenario === 'normal' || scenario === 'quiet') {
    // Add some exclusions for trusted endpoints
    if (Math.random() > 0.7) {
      exclusions.push({
        type: 'endpoint',
        value: '/api/v1/health',
        reason: 'Health check endpoint',
      });
    }
    if (Math.random() > 0.8) {
      exclusions.push({
        type: 'ip',
        value: '10.0.0.0/8',
        reason: 'Internal network',
      });
    }
  }

  return exclusions;
}

// Helper to calculate triggers based on scenario
function calculateTriggers(
  baseTriggers: number,
  category: RuleCategory,
  severity: RuleSeverity,
  profile: ReturnType<typeof getScenarioProfile>
): number {
  let triggers = Math.round(baseTriggers * profile.traffic.blockedMultiplier);

  // Adjust based on category and threat types
  const isRelevantThreat = profile.threats.primaryTypes.some(
    (type) =>
      (category === 'injection' && type.toLowerCase().includes('injection')) ||
      (category === 'bot' && type.toLowerCase().includes('bot')) ||
      (category === 'auth' && type.toLowerCase().includes('credential')) ||
      (category === 'rate-limit' && type.toLowerCase().includes('ddos'))
  );

  if (isRelevantThreat) {
    triggers = Math.round(triggers * 2.5);
  }

  // Severity multiplier
  const severityMultipliers: Record<RuleSeverity, number> = {
    critical: 1.5,
    high: 1.2,
    medium: 1.0,
    low: 0.8,
  };
  triggers = Math.round(triggers * severityMultipliers[severity]);

  return Math.max(0, triggers);
}

// Generate rules for a scenario
function generateRules(scenario: DemoScenario): Rule[] {
  const profile = getScenarioProfile(scenario);
  const totalSensors = 50;

  return RULE_DEFINITIONS.map((def, index) => {
    const triggers = calculateTriggers(
      50 + Math.random() * 150, // Base triggers between 50-200
      def.category,
      def.baseSeverity,
      profile
    );

    // More sensors deployed in high-threat scenarios
    const deploymentRatio = scenario === 'high-threat' ? 0.95 : scenario === 'normal' ? 0.9 : 0.85;
    const deployedSensors = Math.round(totalSensors * (deploymentRatio + Math.random() * 0.05));

    // Determine if rule has active rollout
    const hasRollout = scenario === 'high-threat' && index < 3;
    const rolloutStrategy: RolloutStrategy = hasRollout ? 'canary' : 'immediate';

    // Generate last triggered time
    const hoursAgo = scenario === 'high-threat' ? Math.random() * 0.5 : scenario === 'normal' ? Math.random() * 2 : Math.random() * 24;
    const lastTriggered = triggers > 0 ? new Date(Date.now() - hoursAgo * 60 * 60 * 1000).toISOString() : undefined;

    const rule: Rule = {
      id: `rule-${index + 1}`,
      name: def.name,
      description: def.description,
      category: def.category,
      severity: def.baseSeverity,
      action: def.baseAction,
      patterns: def.patterns,
      exclusions: generateExclusions(scenario),
      sensitivity: 0.7 + Math.random() * 0.25, // 70-95% sensitivity
      enabled: true,
      status: 'active',
      deployedSensors,
      totalSensors,
      triggers24h: triggers,
      lastTriggered,
      createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      rolloutStrategy,
      rolloutStatus: hasRollout
        ? {
            currentStage: Math.ceil(Math.random() * 3),
            totalStages: 4,
            progress: Math.round(Math.random() * 75),
          }
        : undefined,
    };

    return rule;
  });
}

// Generate rule templates
function generateTemplates(scenario: DemoScenario): RuleTemplate[] {
  // Filter templates based on scenario - high-threat shows more critical templates
  let templates = [...TEMPLATE_DEFINITIONS];

  if (scenario === 'high-threat') {
    // Prioritize critical and auth-related templates
    templates = templates.sort((a, b) => {
      const severityOrder: Record<RuleSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
  } else if (scenario === 'quiet') {
    // Show fewer templates in quiet period
    templates = templates.slice(0, 4);
  }

  return templates.map((def, index) => ({
    id: `template-${index + 1}`,
    name: def.name,
    description: def.description,
    category: def.category,
    severity: def.severity,
    previewMatches: def.previewMatches,
  }));
}

// Main generator function
export function generateRulesData(scenario: DemoScenario): {
  rules: Rule[];
  templates: RuleTemplate[];
} {
  return {
    rules: generateRules(scenario),
    templates: generateTemplates(scenario),
  };
}

export default generateRulesData;
