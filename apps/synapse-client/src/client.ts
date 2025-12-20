/**
 * Synapse API Client
 * TypeScript client for the Synapse (risk-server) API
 */

import type {
  SynapseClientOptions,
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
  RuleDefinition,
  AddRuleResponse,
  RemoveRuleResponse,
  ClearRulesResponse,
  ReloadRulesResponse,
  EvaluateRequest,
  EvaluateResult,
  ActorsResponse,
  ActorStats,
  SetFingerprintResponse,
} from './types.js';
import { SynapseError } from './types.js';

/**
 * Synapse API Client
 *
 * @example
 * ```typescript
 * const client = new SynapseClient({ baseUrl: 'http://localhost:3000' });
 * const status = await client.getStatus();
 * console.log(status.totalRequests);
 * ```
 */
export class SynapseClient {
  private opts: Required<SynapseClientOptions>;

  constructor(opts: SynapseClientOptions) {
    this.opts = {
      baseUrl: opts.baseUrl.replace(/\/$/, ''), // Remove trailing slash
      timeout: opts.timeout ?? 30000,
      debug: opts.debug ?? false,
    };
  }

  // ==========================================================================
  // Health & Status
  // ==========================================================================

  /**
   * Check server health
   */
  async health(): Promise<HealthResponse> {
    return this.get<HealthResponse>('/health');
  }

  /**
   * Get sensor status and metrics
   */
  async getStatus(): Promise<SensorStatus> {
    return this.get<SensorStatus>('/_sensor/status');
  }

  /**
   * Get Prometheus-formatted metrics
   */
  async getMetrics(): Promise<string> {
    return this.getText('/_sensor/metrics');
  }

  // ==========================================================================
  // Entity Management
  // ==========================================================================

  /**
   * List all tracked entities
   */
  async listEntities(): Promise<EntitiesResponse> {
    return this.get<EntitiesResponse>('/_sensor/entities');
  }

  /**
   * List all block records
   */
  async listBlocks(): Promise<BlocksResponse> {
    return this.get<BlocksResponse>('/_sensor/blocks');
  }

  /**
   * Release a blocked entity by ID or IP address
   */
  async releaseEntity(entityIdOrIp: string): Promise<ReleaseResponse> {
    const isIp = /^[\d.:]+$/.test(entityIdOrIp);
    return this.post<ReleaseResponse>('/_sensor/release', {
      [isIp ? 'ip' : 'entityId']: entityIdOrIp,
    });
  }

  /**
   * Release all blocked entities
   */
  async releaseAll(): Promise<ReleaseAllResponse> {
    return this.post<ReleaseAllResponse>('/_sensor/release-all', {});
  }

  // ==========================================================================
  // Configuration
  // ==========================================================================

  /**
   * Get full system configuration
   */
  async getConfig(): Promise<ConfigResponse> {
    return this.get<ConfigResponse>('/_sensor/system/config');
  }

  /**
   * Update WAF configuration
   */
  async updateConfig(updates: Partial<WafConfig>): Promise<ConfigUpdateResponse> {
    return this.post<ConfigUpdateResponse>('/_sensor/config', updates);
  }

  // ==========================================================================
  // WAF Rules
  // ==========================================================================

  /**
   * List all WAF rules (static + runtime)
   */
  async listRules(): Promise<RulesResponse> {
    return this.get<RulesResponse>('/_sensor/rules');
  }

  /**
   * Add a runtime rule
   * @param rule - Rule definition
   * @param ttl - Optional TTL in seconds
   */
  async addRule(rule: RuleDefinition, ttl?: number): Promise<AddRuleResponse> {
    return this.post<AddRuleResponse>('/_sensor/rules', { rule, ttl });
  }

  /**
   * Remove a runtime rule by ID
   */
  async removeRule(ruleId: number): Promise<RemoveRuleResponse> {
    return this.delete<RemoveRuleResponse>(`/_sensor/rules/${ruleId}`);
  }

  /**
   * Clear all runtime rules
   */
  async clearRules(): Promise<ClearRulesResponse> {
    return this.delete<ClearRulesResponse>('/_sensor/rules');
  }

  /**
   * Reload WAF rules from file
   */
  async reloadRules(): Promise<ReloadRulesResponse> {
    return this.post<ReloadRulesResponse>('/_sensor/reload', {});
  }

  /**
   * Evaluate a request against WAF rules (dry run)
   */
  async evaluate(request: EvaluateRequest): Promise<EvaluateResult> {
    return this.post<EvaluateResult>('/_sensor/evaluate', request);
  }

  // ==========================================================================
  // Actor Tracking
  // ==========================================================================

  /**
   * List all tracked actors
   */
  async listActors(): Promise<ActorsResponse> {
    return this.get<ActorsResponse>('/_sensor/actors');
  }

  /**
   * Get actor tracking statistics
   */
  async getActorStats(): Promise<ActorStats> {
    return this.get<ActorStats>('/_sensor/actors/stats');
  }

  /**
   * Set fingerprint for an actor
   */
  async setActorFingerprint(ip: string, fingerprint: string): Promise<SetFingerprintResponse> {
    return this.post<SetFingerprintResponse>(
      `/_sensor/actors/${encodeURIComponent(ip)}/fingerprint`,
      { fingerprint }
    );
  }

  // ==========================================================================
  // HTTP Helpers
  // ==========================================================================

  private async get<T>(path: string): Promise<T> {
    return this.request<T>(path, { method: 'GET' });
  }

  private async post<T>(path: string, body: object): Promise<T> {
    return this.request<T>(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  private async delete<T>(path: string): Promise<T> {
    return this.request<T>(path, { method: 'DELETE' });
  }

  private async getText(path: string): Promise<string> {
    const url = `${this.opts.baseUrl}${path}`;

    if (this.opts.debug) {
      console.error(`[synapse] GET ${url}`);
    }

    const response = await fetch(url, {
      method: 'GET',
      signal: AbortSignal.timeout(this.opts.timeout),
    });

    if (this.opts.debug) {
      console.error(`[synapse] response: ${response.status}`);
    }

    if (!response.ok) {
      const text = await response.text();
      throw new SynapseError(
        `HTTP ${response.status}: ${text}`,
        response.status,
        text
      );
    }

    return response.text();
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const url = `${this.opts.baseUrl}${path}`;

    if (this.opts.debug) {
      console.error(`[synapse] ${init.method} ${url}`);
      if (init.body) {
        console.error(`[synapse] body: ${init.body}`);
      }
    }

    const response = await fetch(url, {
      ...init,
      signal: AbortSignal.timeout(this.opts.timeout),
    });

    if (this.opts.debug) {
      console.error(`[synapse] response: ${response.status}`);
    }

    if (!response.ok) {
      const text = await response.text();
      throw new SynapseError(
        `HTTP ${response.status}: ${text}`,
        response.status,
        text
      );
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return undefined as unknown as T;
    }

    const json = await response.json();

    if (this.opts.debug) {
      console.error(`[synapse] result: ${JSON.stringify(json).slice(0, 200)}...`);
    }

    return json as T;
  }
}
