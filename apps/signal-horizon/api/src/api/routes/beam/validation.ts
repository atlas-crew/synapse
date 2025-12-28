/**
 * Zod validation schemas for Beam API routes
 */
import { z } from 'zod';

/**
 * Time range options for analytics queries
 */
export const TimeRangeSchema = z.enum(['1h', '24h', '7d', '30d']);

/**
 * Pagination parameters
 */
export const PaginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

/**
 * Sensor configuration schema
 */
export const SensorConfigSchema = z.object({
  sensorId: z.string().uuid(),
  rules: z.array(z.object({
    id: z.string().uuid(),
    enabled: z.boolean(),
    sensitivity: z.number().min(0).max(100).optional(),
  })),
  thresholds: z.object({
    cpuWarning: z.number().min(0).max(100).optional(),
    cpuCritical: z.number().min(0).max(100).optional(),
    memoryWarning: z.number().min(0).max(100).optional(),
    memoryCritical: z.number().min(0).max(100).optional(),
  }).optional(),
});

/**
 * Threat query parameters
 */
export const ThreatQuerySchema = z.object({
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  status: z.enum(['blocked', 'allowed', 'monitored']).optional(),
  timeRange: TimeRangeSchema.optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

/**
 * Rule creation schema
 */
export const CreateRuleSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(1000).optional(),
  category: z.string().min(1).max(100).default('custom'),
  severity: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
  action: z.enum(['block', 'allow', 'monitor']).default('block'),
  patterns: z.array(z.object({
    type: z.string(),
    value: z.string(),
  })).min(1),
  exclusions: z.array(z.object({
    type: z.string(),
    value: z.string(),
  })).optional(),
  sensitivity: z.number().min(0).max(100).default(50),
});

/**
 * Rule update schema (all fields optional)
 */
export const UpdateRuleSchema = CreateRuleSchema.partial();

/**
 * Endpoint query parameters
 */
export const EndpointQuerySchema = z.object({
  service: z.string().optional(),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']).optional(),
  limit: z.coerce.number().int().min(1).max(100).default(100),
});

/**
 * UUID parameter validation
 */
export const UUIDParamSchema = z.object({
  id: z.string().uuid(),
});
