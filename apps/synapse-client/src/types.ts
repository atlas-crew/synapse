/**
 * Re-export types from synapse-api
 * This file exists for backward compatibility
 *
 * @deprecated Import directly from 'synapse-api' instead
 */

export type {
  SynapseClientOptions,
  HealthResponse,
  SensorStatus,
  Entity,
  EntityRuleMatch,
  Block,
  EntitiesResponse,
  BlocksResponse,
  ReleaseResponse,
  ReleaseAllResponse,
  WafConfig,
  SystemConfig,
  ConfigResponse,
  ConfigUpdateResponse,
  MatchCondition,
  Rule,
  RuleStats,
  RulesResponse,
  RuleDefinition,
  AddRuleResponse,
  RemoveRuleResponse,
  ClearRulesResponse,
  ReloadRulesResponse,
  EvaluateRequest,
  EvaluateResult,
  Actor,
  ActorsResponse,
  ActorStats,
  SetFingerprintResponse,
} from 'synapse-api';

export { SynapseError } from 'synapse-api';
