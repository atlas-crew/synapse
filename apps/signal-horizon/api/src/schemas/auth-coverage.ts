import { z } from 'zod';

// === Incoming from Synapse ===

export const EndpointCountsSchema = z.object({
  total: z.number(),
  success: z.number(),
  unauthorized: z.number(),
  forbidden: z.number(),
  other_error: z.number(),
  with_auth: z.number(),
  without_auth: z.number(),
});

export type EndpointCounts = z.infer<typeof EndpointCountsSchema>;

export const EndpointSummarySchema = z.object({
  endpoint: z.string(),
  counts: EndpointCountsSchema,
});

export type EndpointSummary = z.infer<typeof EndpointSummarySchema>;

export const AuthCoverageSummarySchema = z.object({
  timestamp: z.number(),
  sensor_id: z.string(),
  tenant_id: z.string().optional(),
  endpoints: z.array(EndpointSummarySchema),
});

export type AuthCoverageSummary = z.infer<typeof AuthCoverageSummarySchema>;

// === Internal/API types ===

export const AuthPatternSchema = z.enum([
  'enforced',
  'none_observed',
  'public',
  'insufficient_data',
]);

export type AuthPattern = z.infer<typeof AuthPatternSchema>;

export const RiskLevelSchema = z.enum(['low', 'medium', 'high', 'unknown']);

export type RiskLevel = z.infer<typeof RiskLevelSchema>;

// Aggregated stats per endpoint (API response)
export interface EndpointAuthStats {
  endpoint: string;
  method: string;
  tenantId?: string;

  // Counts
  totalRequests: number;
  successCount: number;
  unauthorizedCount: number;
  forbiddenCount: number;
  otherErrorCount: number;

  // Auth header tracking
  requestsWithAuth: number;
  requestsWithoutAuth: number;

  // Unique actors (if tracked)
  uniqueActors: number;

  // Timing
  firstSeen: Date;
  lastSeen: Date;

  // Computed
  denialRate: number;
  authPattern: AuthPattern;
  riskLevel: RiskLevel;
}

export interface CoverageMapSummary {
  totalEndpoints: number;
  highRiskCount: number;
  mediumRiskCount: number;
  lowRiskCount: number;
  unknownCount: number;
  lastUpdated: Date;
}

// API response wrappers
export interface AuthCoverageResponse {
  endpoints: EndpointAuthStats[];
  total: number;
}

export interface AuthGapsResponse {
  gaps: EndpointAuthStats[];
  total: number;
  highRiskCount: number;
  mediumRiskCount: number;
}
