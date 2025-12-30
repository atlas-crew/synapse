/**
 * Zod schemas for WebSocket message validation
 * Provides runtime validation for incoming sensor messages
 */

import { z } from 'zod';

// =============================================================================
// Signal Types & Metadata
// =============================================================================

export const SignalTypeSchema = z.enum([
  'IP_THREAT',
  'FINGERPRINT_THREAT',
  'CAMPAIGN_INDICATOR',
  'CREDENTIAL_STUFFING',
  'RATE_ANOMALY',
  'BOT_SIGNATURE',
  'IMPOSSIBLE_TRAVEL',
]);

export const SeveritySchema = z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

// Specific Metadata Schemas
const GeoMetadataSchema = z.object({
  latitude: z.number().min(-90).max(90),
  longitude: z.number().min(-180).max(180),
  city: z.string().optional(),
  countryCode: z.string().length(2).optional(),
  userId: z.string().optional(),
});

const ImpossibleTravelMetadataSchema = GeoMetadataSchema.extend({
  userId: z.string().min(1, 'userId is required for travel anomalies'),
});

const DefaultMetadataSchema = z.record(z.unknown()).optional();

// =============================================================================
// Threat Signal Schema (Discriminated Union)
// =============================================================================

export const BaseThreatSignalSchema = z.object({
  sourceIp: z.string().ip().optional(),
  fingerprint: z.string().max(256).optional(),
  severity: SeveritySchema,
  confidence: z.number().min(0).max(1),
  eventCount: z.number().int().positive().optional(),
});

export const ThreatSignalSchema = z.discriminatedUnion('signalType', [
  BaseThreatSignalSchema.extend({
    signalType: z.literal('CREDENTIAL_STUFFING'),
    metadata: GeoMetadataSchema,
  }),
  BaseThreatSignalSchema.extend({
    signalType: z.literal('IMPOSSIBLE_TRAVEL'),
    metadata: ImpossibleTravelMetadataSchema,
  }),
  BaseThreatSignalSchema.extend({
    signalType: z.literal('IP_THREAT'),
    metadata: DefaultMetadataSchema,
  }),
  BaseThreatSignalSchema.extend({
    signalType: z.literal('FINGERPRINT_THREAT'),
    metadata: DefaultMetadataSchema,
  }),
  BaseThreatSignalSchema.extend({
    signalType: z.literal('CAMPAIGN_INDICATOR'),
    metadata: DefaultMetadataSchema,
  }),
  BaseThreatSignalSchema.extend({
    signalType: z.literal('RATE_ANOMALY'),
    metadata: DefaultMetadataSchema,
  }),
  BaseThreatSignalSchema.extend({
    signalType: z.literal('BOT_SIGNATURE'),
    metadata: DefaultMetadataSchema,
  }),
]);

export type ValidatedThreatSignal = z.infer<typeof ThreatSignalSchema>;

// =============================================================================
// Sensor Message Schemas
// =============================================================================

export const SensorAuthPayloadSchema = z.object({
  apiKey: z.string().min(1, 'API key is required'),
  sensorId: z.string().min(1, 'Sensor ID is required'),
  sensorName: z.string().max(255).optional(),
  version: z.string().regex(/^\d+\.\d+\.\d+/, 'Version must be semver format'),
});

export const SensorHeartbeatPayloadSchema = z.object({
  timestamp: z.number(),
  status: z.enum(['healthy', 'degraded', 'unhealthy']),
  cpu: z.number().min(0).max(100),
  memory: z.number().min(0).max(100),
  disk: z.number().min(0).max(100),
  requestsLastMinute: z.number().nonnegative(),
  avgLatencyMs: z.number().nonnegative(),
  configHash: z.string(),
  rulesHash: z.string(),
});

export const SensorCommandAckPayloadSchema = z.object({
  commandId: z.string().min(1),
  success: z.boolean(),
  message: z.string().optional(),
  result: z.record(z.unknown()).optional(),
});

export type ValidatedSensorAuthPayload = z.infer<typeof SensorAuthPayloadSchema>;
export type ValidatedSensorHeartbeatPayload = z.infer<typeof SensorHeartbeatPayloadSchema>;
export type ValidatedSensorCommandAckPayload = z.infer<typeof SensorCommandAckPayloadSchema>;

// Discriminated union for all sensor messages
export const SensorMessageSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('auth'),
    payload: SensorAuthPayloadSchema,
  }),
  z.object({
    type: z.literal('signal'),
    payload: ThreatSignalSchema,
  }),
  z.object({
    type: z.literal('signal-batch'),
    payload: z.array(ThreatSignalSchema).max(1000, 'Batch size exceeds maximum of 1000'),
  }),
  z.object({
    type: z.literal('heartbeat'),
    payload: SensorHeartbeatPayloadSchema,
  }),
  z.object({
    type: z.literal('command-ack'),
    payload: SensorCommandAckPayloadSchema,
  }),
  z.object({
    type: z.literal('pong'),
  }),
  z.object({
    type: z.literal('blocklist-sync'),
  }),
]);

export type ValidatedSensorMessage = z.infer<typeof SensorMessageSchema>;

// =============================================================================
// Dashboard Message Schemas
// =============================================================================

export const DashboardAuthPayloadSchema = z.object({
  apiKey: z.string().min(1, 'API key is required'),
});

export const DashboardClientMessageSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('auth'),
    payload: DashboardAuthPayloadSchema.optional(),
  }),
  z.object({
    type: z.literal('pong'),
  }),
  z.object({
    type: z.literal('subscribe'),
    payload: z.object({
      topic: z.enum(['campaigns', 'threats', 'blocklist', 'metrics']),
    }).optional(),
  }),
  z.object({
    type: z.literal('unsubscribe'),
    payload: z.object({
      topic: z.enum(['campaigns', 'threats', 'blocklist', 'metrics']),
    }).optional(),
  }),
  z.object({
    type: z.literal('request-snapshot'),
  }),
]);

export type ValidatedDashboardMessage = z.infer<typeof DashboardClientMessageSchema>;

// =============================================================================
// Validation Helpers
// =============================================================================

/**
 * Validates and parses a sensor message with detailed error reporting
 */
export function validateSensorMessage(data: unknown):
  | { success: true; data: ValidatedSensorMessage }
  | { success: false; errors: string[] } {
  const result = SensorMessageSchema.safeParse(data);

  if (result.success) {
    return { success: true, data: result.data };
  }

  const errors = result.error.issues.map(issue =>
    `${issue.path.join('.')}: ${issue.message}`
  );

  return { success: false, errors };
}

/**
 * Validates and parses a dashboard message with detailed error reporting
 */
export function validateDashboardMessage(data: unknown):
  | { success: true; data: ValidatedDashboardMessage }
  | { success: false; errors: string[] } {
  const result = DashboardClientMessageSchema.safeParse(data);

  if (result.success) {
    return { success: true, data: result.data };
  }

  const errors = result.error.issues.map(issue =>
    `${issue.path.join('.')}: ${issue.message}`
  );

  return { success: false, errors };
}
