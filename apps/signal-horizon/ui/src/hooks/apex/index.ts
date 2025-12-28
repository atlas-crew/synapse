/**
 * Apex Hooks Index
 * Centralized exports for all Apex API hooks
 */

// Dashboard hook
export { useApexDashboard } from '../useApexDashboard';
export type { UseApexDashboardOptions, UseApexDashboardResult } from '../useApexDashboard';

// Analytics hook (existing)
export { useApexAnalytics } from '../useApexAnalytics';
export type {
  UseApexAnalyticsOptions,
  UseApexAnalyticsResult,
  ApexAnalyticsData,
  TrafficOverview,
  BandwidthAnalytics,
  ThreatSummary,
  SensorMetrics,
} from '../useApexAnalytics';

// Endpoints hook
export { useApexEndpoints } from '../useApexEndpoints';
export type {
  UseApexEndpointsOptions,
  UseApexEndpointsResult,
  EndpointQueryParams,
} from '../useApexEndpoints';

// Rules hook
export { useApexRules } from '../useApexRules';
export type {
  UseApexRulesOptions,
  UseApexRulesResult,
  CreateRulePayload,
} from '../useApexRules';

// Threats hook
export { useApexThreats } from '../useApexThreats';
export type {
  UseApexThreatsOptions,
  UseApexThreatsResult,
  ThreatQueryParams,
  ThreatTimeRange,
  ThreatSeverity,
  ThreatStatus,
} from '../useApexThreats';
