/**
 * Beam Hooks Index
 * Centralized exports for all Beam API hooks
 */

// Dashboard hook
export { useBeamDashboard } from '../useBeamDashboard';
export type { UseBeamDashboardOptions, UseBeamDashboardResult } from '../useBeamDashboard';

// Analytics hook (existing)
export { useBeamAnalytics } from '../useBeamAnalytics';
export type {
  UseBeamAnalyticsOptions,
  UseBeamAnalyticsResult,
  BeamAnalyticsData,
  TrafficOverview,
  BandwidthAnalytics,
  ThreatSummary,
  SensorMetrics,
} from '../useBeamAnalytics';

// Endpoints hook
export { useBeamEndpoints } from '../useBeamEndpoints';
export type {
  UseBeamEndpointsOptions,
  UseBeamEndpointsResult,
  EndpointQueryParams,
} from '../useBeamEndpoints';

// Rules hook
export { useBeamRules } from '../useBeamRules';
export type {
  UseBeamRulesOptions,
  UseBeamRulesResult,
  CreateRulePayload,
} from '../useBeamRules';

// Threats hook
export { useBeamThreats } from '../useBeamThreats';
export type {
  UseBeamThreatsOptions,
  UseBeamThreatsResult,
  ThreatQueryParams,
  ThreatTimeRange,
  ThreatSeverity,
  ThreatStatus,
} from '../useBeamThreats';
