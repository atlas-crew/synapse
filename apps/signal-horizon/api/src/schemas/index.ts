/**
 * Schema Exports
 *
 * Centralized exports for all Zod validation schemas.
 *
 * Security Controls:
 * - OWASP API3: Excessive Data Exposure - Hunt schemas with field filtering
 * - OWASP API4: Mass Assignment - Sensor update schemas with strict mode
 * - OWASP API10: Unsafe API Consumption - Synapse external API validation
 */

// -----------------------------------------------------------------------------
// Signal Schemas (WebSocket Messages)
// -----------------------------------------------------------------------------

export {
  // Fingerprint validation (labs-764 - Anti-spoofing)
  FingerprintSchema,
  // Signal schemas
  SignalTypeSchema,
  SeveritySchema,
  BaseThreatSignalSchema,
  ThreatSignalSchema,
  SensorAuthPayloadSchema,
  SensorHeartbeatPayloadSchema,
  SensorCommandAckPayloadSchema,
  SensorMessageSchema,
  DashboardAuthPayloadSchema,
  DashboardClientMessageSchema,
  validateSensorMessage,
  validateDashboardMessage,
  type ValidatedThreatSignal,
  type ValidatedSensorAuthPayload,
  type ValidatedSensorHeartbeatPayload,
  type ValidatedSensorCommandAckPayload,
  type ValidatedSensorMessage,
  type ValidatedDashboardMessage,
} from './signal.js';

// -----------------------------------------------------------------------------
// Sensor Schemas (OWASP API4 - Mass Assignment Prevention)
// -----------------------------------------------------------------------------

export {
  SensorUpdateSchema,
  SensorConfigSchema,
  SensorStatusReportSchema,
  SensorRegistrationSchema,
  SensorQuerySchema,
  SensorBulkActionSchema,
  validateSensorUpdate,
  validateSensorQuery,
  type SensorUpdate,
  type SensorConfig,
  type SensorStatusReport,
  type SensorRegistration,
  type SensorQuery,
  type SensorBulkAction,
} from './sensor.js';

// -----------------------------------------------------------------------------
// Hunt Schemas (OWASP API3 - Excessive Data Exposure Prevention)
// -----------------------------------------------------------------------------

export {
  HUNT_ALLOWED_FIELDS,
  EXCLUDED_INTERNAL_FIELDS,
  HuntQuerySchema,
  HuntResultSchema,
  HuntResponseSchema,
  HuntExportSchema,
  stripInternalFields,
  filterToAllowedFields,
  validateHuntQuery,
  type HuntAllowedField,
  type HuntQuery,
  type HuntResult,
  type HuntResponse,
  type HuntExport,
} from './hunt.js';

// -----------------------------------------------------------------------------
// Synapse Schemas (OWASP API10 - Unsafe API Consumption Prevention)
// -----------------------------------------------------------------------------

export {
  SafeUrlSchema,
  SanitizedStringSchema,
  SynapseRuleSchema,
  SynapseRuleResponseSchema,
  SynapseCampaignSchema,
  SynapseActorSchema,
  SynapseSessionSchema,
  validateExternalResponse,
  fetchAndValidateExternal,
  type SynapseRule,
  type SynapseRuleResponse,
  type SynapseCampaign,
  type SynapseActor,
  type SynapseSession,
} from './synapse.js';

// -----------------------------------------------------------------------------
// Auth Coverage Schemas
// -----------------------------------------------------------------------------

export {
  EndpointCountsSchema,
  EndpointSummarySchema,
  AuthCoverageSummarySchema,
  AuthPatternSchema,
  RiskLevelSchema,
  type EndpointCounts,
  type EndpointSummary,
  type AuthCoverageSummary,
  type AuthPattern,
  type RiskLevel,
  type EndpointAuthStats,
  type CoverageMapSummary,
  type AuthCoverageResponse,
  type AuthGapsResponse,
} from './auth-coverage.js';

// -----------------------------------------------------------------------------
// Tunnel Schemas
// -----------------------------------------------------------------------------

export * from './tunnel.js';

// -----------------------------------------------------------------------------
// API Intelligence Schemas
// -----------------------------------------------------------------------------

export * from './api-intelligence.js';
