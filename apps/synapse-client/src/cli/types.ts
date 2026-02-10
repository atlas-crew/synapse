import type {
  SynapseClientOptions,
  EvaluateRequest,
  RuleDefinition,
  HealthResponse,
  SensorStatus,
  EntitiesResponse,
  BlocksResponse,
  ReleaseResponse,
  ReleaseAllResponse,
  ConfigResponse,
  ConfigUpdateResponse,
  WafConfig,
  RulesResponse,
  AddRuleResponse,
  RemoveRuleResponse,
  ClearRulesResponse,
  ReloadRulesResponse,
  EvaluateResult,
  ActorsResponse,
  ActorStats,
  SetFingerprintResponse,
} from 'synapse-api';

export const VERSION = '0.1.0';

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export interface GlobalOpts {
  url: string;
  json: boolean;
  debug: boolean;
  timeout: number;
}

export interface Parsed {
  command?: string;
  args: string[];
  globals: GlobalOpts;
  help?: boolean;
  version?: boolean;
}

export interface IO {
  log: (msg?: string) => void;
  error: (msg?: string) => void;
}

export const defaultIO: IO = {
  log: (msg = '') => console.log(msg),
  error: (msg = '') => console.error(msg),
};

export type SynapseClientLike = {
  health(): Promise<HealthResponse>;
  getStatus(): Promise<SensorStatus>;
  getMetrics(): Promise<string>;
  listEntities(): Promise<EntitiesResponse>;
  listBlocks(): Promise<BlocksResponse>;
  releaseEntity(entityIdOrIp: string): Promise<ReleaseResponse>;
  releaseAll(): Promise<ReleaseAllResponse>;
  getConfig(): Promise<ConfigResponse>;
  updateConfig(updates: Partial<WafConfig>): Promise<ConfigUpdateResponse>;
  listRules(): Promise<RulesResponse>;
  addRule(rule: RuleDefinition, ttl?: number): Promise<AddRuleResponse>;
  removeRule(ruleId: number): Promise<RemoveRuleResponse>;
  clearRules(): Promise<ClearRulesResponse>;
  reloadRules(): Promise<ReloadRulesResponse>;
  evaluate(request: EvaluateRequest): Promise<EvaluateResult>;
  listActors(): Promise<ActorsResponse>;
  getActorStats(): Promise<ActorStats>;
  setActorFingerprint(ip: string, fingerprint: string): Promise<SetFingerprintResponse>;
};

export type ClientFactory = (opts: SynapseClientOptions) => SynapseClientLike;

