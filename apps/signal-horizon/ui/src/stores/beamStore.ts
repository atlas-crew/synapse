import { create } from 'zustand';
import { useShallow } from 'zustand/shallow';
import type {
  BeamDashboard,
  Endpoint,
  Service,
  SchemaChange,
  Rule,
  RuleTemplate,
  RuleDeployment,
  BlockedRequest,
  DecisionTrace,
  AttackPattern,
  ProtectionAlert,
  TrafficDataPoint,
} from '../types/beam';

// Memory bounds
const MAX_ENDPOINTS = 500;
const MAX_BLOCKED_REQUESTS = 1000;
const MAX_SCHEMA_CHANGES = 200;
const MAX_ALERTS = 50;
const MAX_RULES = 100;

interface BeamStats {
  totalEndpoints: number;
  protectedEndpoints: number;
  activeRules: number;
  blockedRequests24h: number;
  schemaChanges24h: number;
}

interface BeamState {
  // Loading state
  isLoading: boolean;
  hasReceivedSnapshot: boolean;

  // Dashboard
  dashboard: BeamDashboard | null;

  // Data arrays
  endpoints: Endpoint[];
  services: Service[];
  schemaChanges: SchemaChange[];
  rules: Rule[];
  ruleTemplates: RuleTemplate[];
  deployments: RuleDeployment[];
  blockedRequests: BlockedRequest[];
  decisionTraces: DecisionTrace[];
  attackPatterns: AttackPattern[];
  alerts: ProtectionAlert[];
  trafficTimeline: TrafficDataPoint[];

  // Computed stats
  stats: BeamStats;

  // Actions
  setLoading: (loading: boolean) => void;
  setHasReceivedSnapshot: (received: boolean) => void;
  setDashboard: (dashboard: BeamDashboard) => void;

  // Endpoint actions
  setEndpoints: (endpoints: Endpoint[]) => void;
  addEndpoint: (endpoint: Endpoint) => void;
  updateEndpoint: (id: string, updates: Partial<Endpoint>) => void;

  // Service actions
  setServices: (services: Service[]) => void;

  // Schema change actions
  addSchemaChange: (change: SchemaChange) => void;

  // Rule actions
  setRules: (rules: Rule[]) => void;
  addRule: (rule: Rule) => void;
  updateRule: (id: string, updates: Partial<Rule>) => void;
  removeRule: (id: string) => void;

  // Deployment actions
  setDeployments: (deployments: RuleDeployment[]) => void;
  updateDeployment: (id: string, updates: Partial<RuleDeployment>) => void;

  // Blocked request actions
  addBlockedRequest: (request: BlockedRequest) => void;
  setBlockedRequests: (requests: BlockedRequest[]) => void;

  // Alert actions
  addAlert: (alert: ProtectionAlert) => void;
  clearAlerts: () => void;

  // Traffic timeline
  setTrafficTimeline: (timeline: TrafficDataPoint[]) => void;

  // Stats
  updateStats: (stats: Partial<BeamStats>) => void;

  // Reset
  reset: () => void;
}

const initialStats: BeamStats = {
  totalEndpoints: 0,
  protectedEndpoints: 0,
  activeRules: 0,
  blockedRequests24h: 0,
  schemaChanges24h: 0,
};

export const useBeamStore = create<BeamState>((set, get) => ({
  // Initial state
  isLoading: false,
  hasReceivedSnapshot: false,
  dashboard: null,
  endpoints: [],
  services: [],
  schemaChanges: [],
  rules: [],
  ruleTemplates: [],
  deployments: [],
  blockedRequests: [],
  decisionTraces: [],
  attackPatterns: [],
  alerts: [],
  trafficTimeline: [],
  stats: initialStats,

  // Actions
  setLoading: (loading) => set({ isLoading: loading }),
  setHasReceivedSnapshot: (received) => set({ hasReceivedSnapshot: received }),
  setDashboard: (dashboard) => set({ dashboard }),

  // Endpoint actions
  setEndpoints: (endpoints) =>
    set({
      endpoints: endpoints.slice(0, MAX_ENDPOINTS),
      stats: { ...get().stats, totalEndpoints: endpoints.length },
    }),

  addEndpoint: (endpoint) =>
    set((state) => {
      const filtered = state.endpoints.filter((e) => e.id !== endpoint.id);
      const newEndpoints = [endpoint, ...filtered].slice(0, MAX_ENDPOINTS);
      return {
        endpoints: newEndpoints,
        stats: { ...state.stats, totalEndpoints: newEndpoints.length },
      };
    }),

  updateEndpoint: (id, updates) =>
    set((state) => ({
      endpoints: state.endpoints.map((e) => (e.id === id ? { ...e, ...updates } : e)),
    })),

  // Service actions
  setServices: (services) => set({ services }),

  // Schema change actions
  addSchemaChange: (change) =>
    set((state) => {
      const filtered = state.schemaChanges.filter((c) => c.id !== change.id);
      return {
        schemaChanges: [change, ...filtered].slice(0, MAX_SCHEMA_CHANGES),
      };
    }),

  // Rule actions
  setRules: (rules) =>
    set({
      rules: rules.slice(0, MAX_RULES),
      stats: { ...get().stats, activeRules: rules.filter((r) => r.enabled).length },
    }),

  addRule: (rule) =>
    set((state) => {
      const filtered = state.rules.filter((r) => r.id !== rule.id);
      const newRules = [rule, ...filtered].slice(0, MAX_RULES);
      return {
        rules: newRules,
        stats: { ...state.stats, activeRules: newRules.filter((r) => r.enabled).length },
      };
    }),

  updateRule: (id, updates) =>
    set((state) => ({
      rules: state.rules.map((r) => (r.id === id ? { ...r, ...updates } : r)),
    })),

  removeRule: (id) =>
    set((state) => ({
      rules: state.rules.filter((r) => r.id !== id),
    })),

  // Deployment actions
  setDeployments: (deployments) => set({ deployments }),

  updateDeployment: (id, updates) =>
    set((state) => ({
      deployments: state.deployments.map((d) => (d.id === id ? { ...d, ...updates } : d)),
    })),

  // Blocked request actions
  addBlockedRequest: (request) =>
    set((state) => {
      const filtered = state.blockedRequests.filter((r) => r.id !== request.id);
      return {
        blockedRequests: [request, ...filtered].slice(0, MAX_BLOCKED_REQUESTS),
      };
    }),

  setBlockedRequests: (requests) =>
    set({
      blockedRequests: requests.slice(0, MAX_BLOCKED_REQUESTS),
    }),

  // Alert actions
  addAlert: (alert) =>
    set((state) => {
      const filtered = state.alerts.filter((a) => a.id !== alert.id);
      return {
        alerts: [alert, ...filtered].slice(0, MAX_ALERTS),
      };
    }),

  clearAlerts: () => set({ alerts: [] }),

  // Traffic timeline
  setTrafficTimeline: (timeline) => set({ trafficTimeline: timeline }),

  // Stats
  updateStats: (stats) =>
    set((state) => ({
      stats: { ...state.stats, ...stats },
    })),

  // Reset
  reset: () =>
    set({
      isLoading: false,
      hasReceivedSnapshot: false,
      dashboard: null,
      endpoints: [],
      services: [],
      schemaChanges: [],
      rules: [],
      ruleTemplates: [],
      deployments: [],
      blockedRequests: [],
      decisionTraces: [],
      attackPatterns: [],
      alerts: [],
      trafficTimeline: [],
      stats: initialStats,
    }),
}));

// Memoized selectors
export const useBeamLoading = () => useBeamStore((state) => state.isLoading);
export const useBeamDashboard = () => useBeamStore((state) => state.dashboard);
export const useBeamStats = () => useBeamStore(useShallow((state) => state.stats));

export const useBeamEndpoints = () => useBeamStore(useShallow((state) => state.endpoints));
export const useProtectedEndpoints = () =>
  useBeamStore(useShallow((state) => state.endpoints.filter((e) => e.protectionStatus === 'protected')));
export const useHighRiskEndpoints = () =>
  useBeamStore(useShallow((state) => state.endpoints.filter((e) => e.riskLevel === 'high' || e.riskLevel === 'critical')));

export const useBeamServices = () => useBeamStore(useShallow((state) => state.services));
export const useSchemaChanges = () => useBeamStore(useShallow((state) => state.schemaChanges));

export const useBeamRules = () => useBeamStore(useShallow((state) => state.rules));
export const useActiveRules = () => useBeamStore(useShallow((state) => state.rules.filter((r) => r.enabled)));
export const useBeamDeployments = () => useBeamStore(useShallow((state) => state.deployments));

export const useBlockedRequests = () => useBeamStore(useShallow((state) => state.blockedRequests));
export const useRecentBlockedRequests = () => useBeamStore(useShallow((state) => state.blockedRequests.slice(0, 100)));

export const useBeamAlerts = () => useBeamStore(useShallow((state) => state.alerts));
export const useCriticalAlerts = () => useBeamStore(useShallow((state) => state.alerts.filter((a) => a.severity === 'critical')));

export const useTrafficTimeline = () => useBeamStore(useShallow((state) => state.trafficTimeline));
