/**
 * Zod schemas for WebSocket message validation
 * Provides runtime validation for incoming sensor messages
 */

import { z } from 'zod';

// =============================================================================
// Fingerprint Validation (labs-764)
// =============================================================================

/**
 * Minimum fingerprint length to ensure sufficient entropy.
 * Browser fingerprints typically have 32+ characters.
 */
const MIN_FINGERPRINT_LENGTH = 16;

/**
 * Maximum fingerprint length to prevent memory exhaustion.
 */
const MAX_FINGERPRINT_LENGTH = 256;

/**
 * Valid characters for fingerprint strings.
 * Allows alphanumeric, hyphens, underscores, colons, and periods.
 * This covers common fingerprint formats:
 * - JA4: t13d1517h2_8daaf6152771_b0da82dd1658
 * - Canvas: a1b2c3d4e5f6...
 * - WebGL: vendor_renderer_extensions
 */
const FINGERPRINT_CHAR_PATTERN = /^[a-zA-Z0-9_\-.:]+$/;

/**
 * Patterns that indicate low entropy/spoofed fingerprints.
 * These patterns are commonly used in spoofing attempts.
 */
const SUSPICIOUS_FINGERPRINT_PATTERNS = [
  /^(.)\1{7,}$/,           // 8+ repeated chars (aaaaaaaa)
  /^(012345|123456|abcdef)/i, // Sequential patterns
  /^(test|fake|spoof|null|undefined|none)/i, // Obviously fake values
  /^0+$/,                  // All zeros
];

/**
 * Validates a fingerprint string for format and entropy.
 * Returns { valid: true } or { valid: false, reason: string }
 */
function validateFingerprintFormat(fp: string): { valid: true } | { valid: false; reason: string } {
  // Check length
  if (fp.length < MIN_FINGERPRINT_LENGTH) {
    return { valid: false, reason: `Fingerprint too short (min ${MIN_FINGERPRINT_LENGTH} chars)` };
  }

  // Check character set
  if (!FINGERPRINT_CHAR_PATTERN.test(fp)) {
    return { valid: false, reason: 'Fingerprint contains invalid characters' };
  }

  // Check for suspicious patterns
  for (const pattern of SUSPICIOUS_FINGERPRINT_PATTERNS) {
    if (pattern.test(fp)) {
      return { valid: false, reason: 'Fingerprint appears to be spoofed or invalid' };
    }
  }

  // Check entropy - require at least 4 unique characters
  const uniqueChars = new Set(fp.toLowerCase()).size;
  if (uniqueChars < 4) {
    return { valid: false, reason: 'Fingerprint has insufficient entropy' };
  }

  return { valid: true };
}

/**
 * Zod schema for validated fingerprint strings.
 * Applies format, length, character set, and entropy validation.
 *
 * Accepted formats:
 * - JA4 fingerprints: t13d1517h2_8daaf6152771_b0da82dd1658
 * - Canvas fingerprints: a1b2c3d4e5f6g7h8i9j0...
 * - Browser fingerprints: 3a7bd2f9e1c4...
 */
export const FingerprintSchema = z
  .string()
  .min(MIN_FINGERPRINT_LENGTH, `Fingerprint must be at least ${MIN_FINGERPRINT_LENGTH} characters`)
  .max(MAX_FINGERPRINT_LENGTH, `Fingerprint must be at most ${MAX_FINGERPRINT_LENGTH} characters`)
  .superRefine((fp, ctx) => {
    const result = validateFingerprintFormat(fp);
    if (!result.valid) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: result.reason,
      });
    }
  });

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
  /**
   * Browser/device fingerprint with validation for format, entropy, and anti-spoofing.
   * If provided, must meet minimum entropy requirements (labs-764).
   */
  fingerprint: FingerprintSchema.optional(),
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
  BaseThreatSignalSchema.extend({
    signalType: z.literal('TEMPLATE_DISCOVERY'),
    metadata: DefaultMetadataSchema,
  }),
  BaseThreatSignalSchema.extend({
    signalType: z.literal('SCHEMA_VIOLATION'),
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
