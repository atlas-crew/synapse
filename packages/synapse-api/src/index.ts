/**
 * synapse-api
 *
 * TypeScript API client for Synapse (risk-server)
 * Provides typed access to WAF sensor, entity management, and rule evaluation APIs
 *
 * @example
 * ```typescript
 * import { SynapseClient } from 'synapse-api';
 *
 * const client = new SynapseClient({ baseUrl: 'http://localhost:3000' });
 * const status = await client.getStatus();
 * ```
 *
 * @packageDocumentation
 */

// Client
export { SynapseClient } from './client.js';

// Errors
export { SynapseError } from './errors.js';

// Types - Client Options
export type { SynapseClientOptions } from './types.js';

// Types - Health & Status
export type { HealthResponse, SensorStatus } from './types.js';

// Types - Entity Management
export type {
  Entity,
  EntityRuleMatch,
  Block,
  EntitiesResponse,
  BlocksResponse,
  ReleaseResponse,
  ReleaseAllResponse,
} from './types.js';

// Types - Configuration
export type {
  WafConfig,
  SystemConfig,
  ConfigResponse,
  ConfigUpdateResponse,
} from './types.js';

// Types - WAF Rules
export type {
  MatchCondition,
  Rule,
  RuleStats,
  RulesResponse,
  RuleDefinition,
  AddRuleResponse,
  RemoveRuleResponse,
  ClearRulesResponse,
  ReloadRulesResponse,
} from './types.js';

// Types - Rule Evaluation
export type { EvaluateRequest, EvaluateResult } from './types.js';

// Types - Actor Tracking
export type {
  Actor,
  ActorsResponse,
  ActorStats,
  SetFingerprintResponse,
} from './types.js';
