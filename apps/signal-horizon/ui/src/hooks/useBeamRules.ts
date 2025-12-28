/**
 * useBeamRules Hook
 * Fetches and manages protection rules from Signal Horizon API
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import type { Rule, RuleDeployment, RuleTemplate, RuleCategory, RuleSeverity, RuleAction } from '../types/beam';

// ============================================================================
// API Response/Request Types
// ============================================================================

interface RulesApiResponse {
  rules: ApiRule[];
}

interface ApiRule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  action: string;
  patterns: any;
  exclusions: any;
  sensitivity: number;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  _count?: { deployments: number; endpointBindings: number };
}

interface RuleDetailResponse {
  rule: ApiRule & {
    deployments: { id: string; sensor: { id: string; name: string; connectionState: string } }[];
    endpointBindings: { endpoint: { id: string; method: string; pathTemplate: string; service: string } }[];
  };
}

export interface CreateRulePayload {
  name: string;
  description?: string;
  category: RuleCategory;
  severity: RuleSeverity;
  action: RuleAction;
  patterns?: unknown[];
  exclusions?: unknown[];
  sensitivity?: number;
}

// ============================================================================
// Hook Configuration
// ============================================================================

export interface UseBeamRulesOptions {
  /** Polling interval in milliseconds (default: 60000 = 60s) */
  pollingInterval?: number;
  /** Whether to start fetching immediately (default: true) */
  autoFetch?: boolean;
  /** API base URL (default: /api/v1) */
  apiBaseUrl?: string;
}

export interface UseBeamRulesResult {
  rules: Rule[];
  deployments: RuleDeployment[];
  templates: RuleTemplate[];
  isLoading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
  fetchRuleById: (id: string) => Promise<Rule | null>;
  createRule: (payload: CreateRulePayload) => Promise<Rule | null>;
  isConnected: boolean;
  lastUpdated: Date | null;
  // Computed helpers
  activeRules: Rule[];
  rulesByCategory: Map<RuleCategory, Rule[]>;
}

// ============================================================================
// Demo Data Generator
// ============================================================================

function generateDemoRules(): Rule[] {
  return [
    {
      id: 'rule-1',
      name: 'SQL Injection Protection',
      description: 'Detects and blocks SQL injection attempts in request parameters',
      category: 'injection',
      severity: 'critical',
      action: 'block',
      patterns: [{ type: 'regex', value: '(\\/\\*|\\*\\/|;|--|\\bunion\\b)', locations: ['query', 'body'] }],
      exclusions: [],
      sensitivity: 8,
      enabled: true,
      deployedSensors: 12,
      totalSensors: 12,
      triggers24h: 847,
      lastTriggered: new Date(Date.now() - 1800000).toISOString(),
      rolloutStrategy: 'immediate',
    },
    {
      id: 'rule-2',
      name: 'Bot Traffic Detection',
      description: 'Identifies automated bot traffic based on behavior patterns',
      category: 'bot',
      severity: 'high',
      action: 'challenge',
      patterns: [{ type: 'behavior', value: 'high_request_rate', locations: ['request'] }],
      exclusions: [{ type: 'path', value: '/api/health', reason: 'Health check endpoint' }],
      sensitivity: 6,
      enabled: true,
      deployedSensors: 10,
      totalSensors: 12,
      triggers24h: 721,
      lastTriggered: new Date(Date.now() - 3600000).toISOString(),
      rolloutStrategy: 'canary',
      rolloutStatus: { currentStage: 2, totalStages: 3, progress: 67 },
    },
    {
      id: 'rule-3',
      name: 'Brute Force Protection',
      description: 'Rate limits login attempts to prevent credential stuffing',
      category: 'auth',
      severity: 'high',
      action: 'block',
      patterns: [{ type: 'threshold', value: '5_per_minute', locations: ['auth'] }],
      exclusions: [],
      sensitivity: 7,
      enabled: true,
      deployedSensors: 12,
      totalSensors: 12,
      triggers24h: 398,
      rolloutStrategy: 'immediate',
    },
    {
      id: 'rule-4',
      name: 'XSS Prevention',
      description: 'Blocks cross-site scripting attempts in input fields',
      category: 'injection',
      severity: 'high',
      action: 'block',
      patterns: [{ type: 'regex', value: '<script|javascript:|on\\w+=', locations: ['body', 'query'] }],
      exclusions: [],
      sensitivity: 8,
      enabled: true,
      deployedSensors: 12,
      totalSensors: 12,
      triggers24h: 534,
      lastTriggered: new Date(Date.now() - 7200000).toISOString(),
      rolloutStrategy: 'immediate',
    },
    {
      id: 'rule-5',
      name: 'API Rate Limiting',
      description: 'Enforces rate limits on API endpoints',
      category: 'rate-limit',
      severity: 'medium',
      action: 'challenge',
      patterns: [{ type: 'threshold', value: '100_per_minute', locations: ['api'] }],
      exclusions: [{ type: 'ip', value: '10.0.0.0/8', reason: 'Internal traffic' }],
      sensitivity: 5,
      enabled: false,
      deployedSensors: 0,
      totalSensors: 12,
      triggers24h: 0,
      rolloutStrategy: 'scheduled',
    },
  ];
}

function generateDemoTemplates(): RuleTemplate[] {
  return [
    {
      id: 'tmpl-1',
      name: 'OWASP SQL Injection',
      description: 'Standard OWASP-based SQL injection detection patterns',
      category: 'injection',
      severity: 'critical',
      previewMatches: ['UNION SELECT', "' OR 1=1", '; DROP TABLE'],
    },
    {
      id: 'tmpl-2',
      name: 'Credential Stuffing',
      description: 'Detects automated credential testing attacks',
      category: 'auth',
      severity: 'high',
      previewMatches: ['Multiple failed logins', 'Rapid auth attempts', 'Known bad IPs'],
    },
    {
      id: 'tmpl-3',
      name: 'Aggressive Bot',
      description: 'Identifies aggressive bot behavior patterns',
      category: 'bot',
      severity: 'medium',
      previewMatches: ['High RPS', 'No JS execution', 'Known bot UA'],
    },
  ];
}

// ============================================================================
// Hook Implementation
// ============================================================================

export function useBeamRules(options: UseBeamRulesOptions = {}): UseBeamRulesResult {
  const {
    pollingInterval = 60000,
    autoFetch = true,
    apiBaseUrl = '/api/v1',
  } = options;

  const [rules, setRules] = useState<Rule[]>([]);
  const [deployments] = useState<RuleDeployment[]>([]);
  const [templates] = useState<RuleTemplate[]>(generateDemoTemplates());
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const intervalRef = useRef<number | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // Transform API rule to UI Rule
  const transformRule = useCallback((apiRule: ApiRule): Rule => ({
    id: apiRule.id,
    name: apiRule.name,
    description: apiRule.description || '',
    category: apiRule.category as RuleCategory,
    severity: apiRule.severity as RuleSeverity,
    action: apiRule.action as RuleAction,
    patterns: Array.isArray(apiRule.patterns) ? apiRule.patterns : [],
    exclusions: Array.isArray(apiRule.exclusions) ? apiRule.exclusions : [],
    sensitivity: apiRule.sensitivity || 5,
    enabled: apiRule.enabled,
    deployedSensors: apiRule._count?.deployments ?? 0,
    totalSensors: 12, // Will come from fleet info
    triggers24h: 0, // Not provided by current API
    rolloutStrategy: 'immediate',
  }), []);

  const fetchData = useCallback(async () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setIsLoading(true);

    try {
      const response = await fetch(`${apiBaseUrl}/beam/rules`, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' },
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as RulesApiResponse;
      const transformedRules = data.rules.map(transformRule);

      setRules(transformedRules);
      setIsConnected(true);
      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      if ((err as Error).name === 'AbortError') return;

      console.warn('Failed to fetch beam rules, using demo data:', err);
      setError(err as Error);
      setIsConnected(false);

      if (rules.length === 0) {
        setRules(generateDemoRules());
      }
    } finally {
      setIsLoading(false);
    }
  }, [apiBaseUrl, transformRule, rules.length]);

  const fetchRuleById = useCallback(async (id: string): Promise<Rule | null> => {
    try {
      const response = await fetch(`${apiBaseUrl}/beam/rules/${id}`, {
        headers: { 'Accept': 'application/json' },
      });

      if (!response.ok) {
        if (response.status === 404) return null;
        throw new Error(`API error: ${response.status}`);
      }

      const data = await response.json() as RuleDetailResponse;
      return {
        ...transformRule(data.rule),
        deployedSensors: data.rule.deployments.length,
      };
    } catch (err) {
      console.warn('Failed to fetch rule details:', err);
      return null;
    }
  }, [apiBaseUrl, transformRule]);

  const createRule = useCallback(async (payload: CreateRulePayload): Promise<Rule | null> => {
    try {
      const response = await fetch(`${apiBaseUrl}/beam/rules`, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || `API error: ${response.status}`);
      }

      const data = await response.json() as { rule: ApiRule };
      const newRule = transformRule(data.rule);

      // Add to local state
      setRules(prev => [newRule, ...prev]);

      return newRule;
    } catch (err) {
      console.error('Failed to create rule:', err);
      throw err;
    }
  }, [apiBaseUrl, transformRule]);

  // Computed: active rules
  const activeRules = rules.filter(r => r.enabled);

  // Computed: rules by category
  const rulesByCategory = new Map<RuleCategory, Rule[]>();
  rules.forEach(rule => {
    const existing = rulesByCategory.get(rule.category) || [];
    rulesByCategory.set(rule.category, [...existing, rule]);
  });

  useEffect(() => {
    if (autoFetch) fetchData();
    return () => { abortControllerRef.current?.abort(); };
  }, [autoFetch, fetchData]);

  useEffect(() => {
    if (pollingInterval > 0) {
      intervalRef.current = window.setInterval(fetchData, pollingInterval);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [pollingInterval, fetchData]);

  return {
    rules,
    deployments,
    templates,
    isLoading,
    error,
    refetch: fetchData,
    fetchRuleById,
    createRule,
    isConnected,
    lastUpdated,
    activeRules,
    rulesByCategory,
  };
}

export default useBeamRules;
