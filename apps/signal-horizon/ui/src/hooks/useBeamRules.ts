/**
 * useBeamRules Hook
 * Fetches and manages protection rules from Signal Horizon API
 * with CRUD operations and real-time polling.
 */

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { apiFetch } from '../lib/api';
import { useDemoMode } from '../stores/demoModeStore';
import { getDemoData } from '../lib/demoData';
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
  patterns: unknown;
  exclusions: unknown;
  sensitivity: number;
  enabled: boolean;
  status: string;
  totalSensors: number;
  deployedSensors: number;
  failedSensors: number;
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
}

export interface UseBeamRulesResult {
  rules: Rule[];
  deployments: RuleDeployment[];
  templates: RuleTemplate[];
  isLoading: boolean;
  error: string | null;
  isDemo: boolean;
  /** @deprecated Use `!isDemo` instead */
  isConnected: boolean;
  refetch: () => Promise<void>;
  fetchRuleById: (id: string) => Promise<Rule | null>;
  createRule: (payload: CreateRulePayload) => Promise<Rule | null>;
  updateRule: (id: string, updates: Partial<Rule>) => Promise<Rule | null>;
  lastUpdated: Date | null;
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
      status: 'active',
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
      status: 'active',
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
      status: 'active',
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
      status: 'active',
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
      status: 'paused',
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

// Generate demo data once
const DEMO_RULES = generateDemoRules();
const DEMO_TEMPLATES = generateDemoTemplates();

// ============================================================================
// Hook Implementation
// ============================================================================

export function useBeamRules(options: UseBeamRulesOptions = {}): UseBeamRulesResult {
  const { pollingInterval = 60000, autoFetch = true } = options;

  // Check demo mode state - early return with static demo data
  const { isEnabled: isDemoEnabled, scenario } = useDemoMode();

  if (isDemoEnabled) {
    const demoData = getDemoData(scenario);
    const demoActiveRules = demoData.rules.filter(r => r.enabled);
    const demoRulesByCategory = new Map<RuleCategory, Rule[]>();
    demoData.rules.forEach(rule => {
      const existing = demoRulesByCategory.get(rule.category) || [];
      demoRulesByCategory.set(rule.category, [...existing, rule]);
    });

    return {
      rules: demoData.rules,
      deployments: [],
      templates: demoData.ruleTemplates,
      isLoading: false,
      error: null,
      isDemo: true,
      isConnected: false,
      refetch: async () => {},
      fetchRuleById: async () => null,
      createRule: async () => null,
      updateRule: async () => null,
      lastUpdated: new Date(demoData.generatedAt),
      activeRules: demoActiveRules,
      rulesByCategory: demoRulesByCategory,
    };
  }

  const [rules, setRules] = useState<Rule[]>(DEMO_RULES);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isDemo, setIsDemo] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const intervalRef = useRef<number | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const isFetchingRef = useRef(false);

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
    status: apiRule.status || 'active',
    deployedSensors: apiRule.deployedSensors ?? apiRule._count?.deployments ?? 0,
    totalSensors: apiRule.totalSensors ?? 0,
    triggers24h: 0,
    createdAt: apiRule.createdAt,
    rolloutStrategy: 'immediate',
  }), []);

  const fetchData = useCallback(async () => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;

    abortControllerRef.current?.abort();
    abortControllerRef.current = new AbortController();

    setIsLoading(true);

    try {
      const data = await apiFetch<RulesApiResponse>('/beam/rules', {
        signal: abortControllerRef.current.signal,
      });

      const transformedRules = data.rules.map(transformRule);
      setRules(transformedRules);
      setIsDemo(false);
      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') return;

      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      console.warn('[useBeamRules] API failed, using demo data:', errorMessage);
      setError(errorMessage);
      setIsDemo(true);
    } finally {
      isFetchingRef.current = false;
      setIsLoading(false);
    }
  }, [transformRule]);

  const fetchRuleById = useCallback(async (id: string): Promise<Rule | null> => {
    try {
      const data = await apiFetch<RuleDetailResponse>(`/beam/rules/${id}`);
      return {
        ...transformRule(data.rule),
        deployedSensors: data.rule.deployments.length,
      };
    } catch (err) {
      console.warn('[useBeamRules] Failed to fetch rule details:', err);
      return null;
    }
  }, [transformRule]);

  const createRule = useCallback(async (payload: CreateRulePayload): Promise<Rule | null> => {
    try {
      const data = await apiFetch<{ rule: ApiRule }>('/beam/rules', {
        method: 'POST',
        body: payload,
      });

      const newRule = transformRule(data.rule);
      setRules(prev => [newRule, ...prev]);
      return newRule;
    } catch (err) {
      console.error('[useBeamRules] Failed to create rule:', err);
      throw err;
    }
  }, [transformRule]);

  const updateRule = useCallback(async (id: string, updates: Partial<Rule>): Promise<Rule | null> => {
    try {
      // Map UI fields back to API fields if necessary
      const payload = {
        enabled: updates.enabled,
        severity: updates.severity,
        action: updates.action,
        sensitivity: updates.sensitivity,
      };

      const data = await apiFetch<{ rule: ApiRule }>(`/beam/rules/${id}`, {
        method: 'PATCH',
        body: payload,
      });

      const updatedRule = transformRule(data.rule);
      setRules(prev => prev.map(r => r.id === id ? updatedRule : r));
      return updatedRule;
    } catch (err) {
      console.error('[useBeamRules] Failed to update rule:', err);
      throw err;
    }
  }, [transformRule]);

  // Computed: active rules
  const activeRules = useMemo(() => rules.filter(r => r.enabled), [rules]);

  // Computed: rules by category
  const rulesByCategory = useMemo(() => {
    const map = new Map<RuleCategory, Rule[]>();
    rules.forEach(rule => {
      const existing = map.get(rule.category) || [];
      map.set(rule.category, [...existing, rule]);
    });
    return map;
  }, [rules]);

  // Initial fetch
  useEffect(() => {
    if (autoFetch) fetchData();
    return () => { abortControllerRef.current?.abort(); };
  }, [autoFetch, fetchData]);

  // Polling
  useEffect(() => {
    if (pollingInterval > 0) {
      intervalRef.current = window.setInterval(fetchData, pollingInterval);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [pollingInterval, fetchData]);

  return {
    rules,
    deployments: [],
    templates: DEMO_TEMPLATES,
    isLoading,
    error,
    isDemo,
    isConnected: !isDemo,
    refetch: fetchData,
    fetchRuleById,
    createRule,
    updateRule,
    lastUpdated,
    activeRules,
    rulesByCategory,
  };
}

export default useBeamRules;
