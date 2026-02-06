/**
 * API Contracts
 * Centralized schema definitions for the Signal Horizon API.
 * Ensures consistent request/response formats and prevents breaking changes.
 * 
 * PEN-004: All mutation endpoints must follow these contracts.
 */

import { z } from 'zod';
import { SeveritySchema } from '../schemas/signal.js';

// =============================================================================
// Common Components
// =============================================================================

export const ErrorResponseSchema = z.object({
  error: z.string(),
  code: z.string().optional(),
  message: z.string().optional(),
  details: z.any().optional(),
});

export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;

export const PaginationParamsSchema = z.object({
  limit: z.number().int().min(1).max(1000).default(100),
  offset: z.number().int().min(0).default(0),
});

// =============================================================================
// Telemetry Contracts
// =============================================================================

export const TelemetryIngestResponseSchema = z.object({
  received: z.number(),
  inserted: z.number(),
  ignored: z.number(),
  buffered: z.number().optional(),
  duplicate: z.boolean().optional(),
});

export type TelemetryIngestResponse = z.infer<typeof TelemetryIngestResponseSchema>;

// =============================================================================
// Fleet Management Contracts
// =============================================================================

export const SensorStatusSchema = z.enum(['CONNECTED', 'DISCONNECTED', 'RECONNECTING']);

export const SensorSchema = z.object({
  id: z.string(),
  name: z.string(),
  version: z.string(),
  status: SensorStatusSchema,
  lastHeartbeat: z.string().datetime().nullable(),
});

// =============================================================================
// Intelligence Contracts
// =============================================================================

export const CampaignSchema = z.object({
  id: z.string(),
  name: z.string(),
  status: z.enum(['ACTIVE', 'MONITORING', 'RESOLVED', 'FALSE_POSITIVE']),
  severity: SeveritySchema,
  isCrossTenant: z.boolean(),
  tenantsAffected: z.number(),
  confidence: z.number(),
  firstSeenAt: z.string().datetime(),
  lastActivityAt: z.string().datetime(),
});

/**
 * Registry of all API routes and their contracts.
 * Useful for documentation generation and automated testing.
 */
export const ApiContract = {
  telemetry: {
    ingest: {
      path: '/telemetry',
      method: 'POST',
      response: TelemetryIngestResponseSchema,
    },
  },
  campaigns: {
    list: {
      path: '/campaigns',
      method: 'GET',
      query: PaginationParamsSchema,
      response: z.object({
        campaigns: z.array(CampaignSchema),
        total: z.number(),
      }),
    },
  },
} as const;
