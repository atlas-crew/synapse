/**
 * API Intelligence Schemas
 * Zod validation schemas for TEMPLATE_DISCOVERY and SCHEMA_VIOLATION signals
 */

import { z } from 'zod';

// =============================================================================
// Signal Schemas
// =============================================================================

/**
 * HTTP methods supported by API Intelligence
 */
export const HttpMethodSchema = z.enum([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
]);

export type HttpMethod = z.infer<typeof HttpMethodSchema>;

/**
 * Schema violation types
 */
export const ViolationTypeSchema = z.enum([
  'type_mismatch',
  'missing_required_field',
  'extra_field',
  'format_error',
  'constraint_violation',
  'invalid_enum_value',
]);

export type ViolationType = z.infer<typeof ViolationTypeSchema>;

/**
 * API Intelligence Signal Schema
 * Validates incoming signals from sensors
 */
export const APIIntelligenceSignalSchema = z.object({
  type: z.enum(['TEMPLATE_DISCOVERY', 'SCHEMA_VIOLATION']),
  sensorId: z.string().min(1, 'sensorId is required'),
  timestamp: z.string().datetime({ message: 'timestamp must be ISO 8601 format' }),
  endpoint: z.string().min(1, 'endpoint is required'),
  method: HttpMethodSchema,

  // TEMPLATE_DISCOVERY specific fields
  templatePattern: z.string().optional(), // e.g., "/api/users/{id}"
  discoveryConfidence: z.number().min(0).max(1).optional(),
  parameterTypes: z.record(z.string()).optional(), // e.g., {"id": "uuid", "name": "string"}

  // SCHEMA_VIOLATION specific fields
  expectedSchema: z.any().optional(),
  actualPayload: z.any().optional(),
  violationType: ViolationTypeSchema.optional(),
  violationPath: z.string().optional(), // JSON path to violation
  violationMessage: z.string().optional(),
}).refine(
  (data) => {
    // TEMPLATE_DISCOVERY requires templatePattern
    if (data.type === 'TEMPLATE_DISCOVERY' && !data.templatePattern) {
      return false;
    }
    // SCHEMA_VIOLATION requires violationType
    if (data.type === 'SCHEMA_VIOLATION' && !data.violationType) {
      return false;
    }
    return true;
  },
  {
    message: 'TEMPLATE_DISCOVERY requires templatePattern; SCHEMA_VIOLATION requires violationType',
  }
);

export type APIIntelligenceSignal = z.infer<typeof APIIntelligenceSignalSchema>;

// =============================================================================
// Batch Schemas
// =============================================================================

/**
 * Signal Batch Schema for bulk ingestion
 */
export const SignalBatchSchema = z.object({
  signals: z.array(APIIntelligenceSignalSchema).min(1, 'At least one signal required'),
  batchId: z.string().min(1, 'batchId is required'),
  sensorId: z.string().min(1, 'sensorId is required'),
  timestamp: z.string().datetime({ message: 'timestamp must be ISO 8601 format' }),
});

export type SignalBatch = z.infer<typeof SignalBatchSchema>;

// =============================================================================
// Endpoint Schemas
// =============================================================================

/**
 * API Endpoint Schema
 * Represents a discovered API endpoint
 */
export const APIEndpointSchema = z.object({
  id: z.string(),
  tenantId: z.string(),
  templatePattern: z.string(),
  method: z.string(),
  firstSeen: z.date(),
  lastSeen: z.date(),
  requestCount: z.number(),
  violationCount: z.number().optional(),
  discoveredBySensors: z.array(z.string()).optional(),
  parameterTypes: z.record(z.string()).optional(),
  schemaVersion: z.number().optional(),
});

export type APIEndpoint = z.infer<typeof APIEndpointSchema>;

// =============================================================================
// Stats & Analytics Schemas
// =============================================================================

/**
 * Discovery Statistics Interface
 */
export interface DiscoveryStats {
  totalEndpoints: number;
  newThisWeek: number;
  newToday: number;
  schemaViolations24h: number;
  schemaViolations7d: number;
  coveragePercent: number;
  topViolatingEndpoints: Array<{
    endpoint: string;
    method: string;
    violationCount: number;
  }>;
  endpointsByMethod: Record<string, number>;
  discoveryTrend: Array<{
    date: string;
    count: number;
  }>;
}

/**
 * Violation Trend Interface
 */
export interface ViolationTrend {
  date: string;
  type: string;
  count: number;
}

export interface InventoryEndpoint {
  id: string;
  path: string;
  pathTemplate: string;
  method: string;
  service: string;
  sensorId: string;
  requestCount: number;
  riskLevel: string;
  riskScore: number;
  lastSeenAt: string;
}

export interface InventoryService {
  service: string;
  endpointCount: number;
  totalRequests: number;
  avgRiskScore: number;
  endpoints: InventoryEndpoint[];
}

export interface FleetInventory {
  totalEndpoints: number;
  totalRequests: number;
  services: InventoryService[];
}

export interface SchemaChangeSummary {
  id: string;
  endpoint: string;
  method: string;
  service: string;
  changeType: string;
  field: string;
  oldValue: string | null;
  newValue: string | null;
  riskLevel: string;
  detectedAt: string;
  breaking: boolean;
}

export interface SchemaChangeList {
  changes: SchemaChangeSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface EndpointDriftTrend {
  endpoint: string;
  method: string;
  service: string;
  total: number;
  series: Array<{
    date: string;
    count: number;
  }>;
}

// =============================================================================
// Query Schemas
// =============================================================================

/**
 * List Endpoints Query Schema
 */
export const ListEndpointsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
  method: HttpMethodSchema.optional(),
});

export type ListEndpointsQuery = z.infer<typeof ListEndpointsQuerySchema>;

/**
 * List Signals Query Schema
 */
export const ListSignalsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
  type: z.enum(['TEMPLATE_DISCOVERY', 'SCHEMA_VIOLATION']).optional(),
  sensorId: z.string().optional(),
});

export type ListSignalsQuery = z.infer<typeof ListSignalsQuerySchema>;

/**
 * Violation Trends Query Schema
 */
export const ViolationTrendsQuerySchema = z.object({
  days: z.coerce.number().int().min(1).max(90).default(30),
});

export type ViolationTrendsQuery = z.infer<typeof ViolationTrendsQuerySchema>;

export const InventoryQuerySchema = z.object({
  maxServices: z.coerce.number().int().min(1).max(200).default(20),
  maxEndpoints: z.coerce.number().int().min(1).max(500).default(50),
});

export type InventoryQuery = z.infer<typeof InventoryQuerySchema>;

export const SchemaChangesQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).default(0),
  service: z.string().min(1).optional(),
  method: HttpMethodSchema.optional(),
  changeType: z.string().min(1).optional(),
  days: z.coerce.number().int().min(1).max(365).optional(),
});

export type SchemaChangesQuery = z.infer<typeof SchemaChangesQuerySchema>;

export const SchemaDriftTrendsQuerySchema = z.object({
  days: z.coerce.number().int().min(1).max(90).default(30),
  limit: z.coerce.number().int().min(1).max(50).default(10),
});

export type SchemaDriftTrendsQuery = z.infer<typeof SchemaDriftTrendsQuerySchema>;

// =============================================================================
// Response Types
// =============================================================================

/**
 * Batch ingestion result
 */
export interface BatchIngestionResult {
  accepted: number;
  rejected: number;
  batchId: string;
}

/**
 * Paginated list response
 */
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}
