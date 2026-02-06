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
import { SynapseError } from './errors.js';

/**
 * Internal client options with defaults applied
 */
interface ResolvedOptions {
  baseUrl: string;
  timeout: number;
  debug: boolean;
}

/**
 * Synapse API Client
 *
 * Provides typed access to all Synapse (risk-server) API endpoints for:
 * - Health monitoring and metrics
 * - Entity management (tracked IPs, blocks)
 * - WAF configuration
 * - Rule management (static + runtime)
 * - Request evaluation (dry-run)
 * - Actor tracking (fingerprinting)
 *
 * @example
 * ```typescript
 * import { SynapseClient } from 'synapse-api';
 *
 * const client = new SynapseClient({ baseUrl: 'http://localhost:3000' });
 *
 * // Get sensor status
 * const status = await client.getStatus();
 * console.log(`Total requests: ${status.totalRequests}`);
 *
 * // List blocked entities
 * const blocks = await client.listBlocks();
 * console.log(`Blocked: ${blocks.blocks.length}`);
 *
 * // Evaluate a request (dry-run)
 * const result = await client.evaluate({
 *   method: 'GET',
 *   path: '/api/admin',
 *   ip: '192.168.1.100'
 * });
 * console.log(`Would block: ${result.wouldBlock}`);
 * ```
 */
export class SynapseClient {
  private readonly opts: ResolvedOptions;

  constructor(opts: SynapseClientOptions) {
    this.opts = {
      baseUrl: opts.baseUrl.replace(/\/$/, ''), // Remove trailing slash
      timeout: opts.timeout ?? 30000,
      debug: opts.debug ?? false,
    };
  }

  /**
   * Get the configured base URL
   */
  get baseUrl(): string {
    return this.opts.baseUrl;
  }

  // ==========================================================================
  // Health & Status
  // ==========================================================================

  /**
   * Check server health
   * @returns Health status including service name and uptime
   */
  async health(): Promise<HealthResponse> {
    return this.get<HealthResponse>('/health');
  }

  /**
   * Get sensor status and metrics
   * @returns Current sensor state including request counts and configuration
   */
  async getStatus(): Promise<SensorStatus> {
    return this.get<SensorStatus>('/_sensor/status');
  }

  /**
   * Get Prometheus-formatted metrics
   * @returns Raw Prometheus metrics text
   */
  async getMetrics(): Promise<string> {
    return this.getText('/_sensor/metrics');
  }

  // ==========================================================================
  // Entity Management
  // ==========================================================================

  /**
   * List all tracked entities
   * @returns Array of entities with risk scores and block status
   */
  async listEntities(): Promise<EntitiesResponse> {
    return this.get<EntitiesResponse>('/_sensor/entities');
  }

  /**
   * List all block records
   * @returns Array of active blocks with reasons
   */
  async listBlocks(): Promise<BlocksResponse> {
    return this.get<BlocksResponse>('/_sensor/blocks');
  }

  /**
   * Release a blocked entity by ID or IP address
   * @param entityIdOrIp - Entity ID or IP address to release
   * @returns Release confirmation
   */
  async releaseEntity(entityIdOrIp: string): Promise<ReleaseResponse> {
    const isIp = /^[\d.:]+$/.test(entityIdOrIp);
    return this.post<ReleaseResponse>('/_sensor/release', {
      [isIp ? 'ip' : 'entityId']: entityIdOrIp,
    });
  }

  /**
   * Release all blocked entities
   * @returns Count of released entities
   */
  async releaseAll(): Promise<ReleaseAllResponse> {
    return this.post<ReleaseAllResponse>('/_sensor/release-all', {});
  }

  // ==========================================================================
  // Configuration
  // ==========================================================================

  /**
   * Get full system configuration
   * @returns Complete WAF and system configuration
   */
  async getConfig(): Promise<ConfigResponse> {
    return this.get<ConfigResponse>('/_sensor/system/config');
  }

  /**
   * Update WAF configuration
   * @param updates - Partial configuration to update
   * @returns Updated configuration with list of changed fields
   */
  async updateConfig(updates: Partial<WafConfig>): Promise<ConfigUpdateResponse> {
    return this.post<ConfigUpdateResponse>('/_sensor/config', updates);
  }

  // ==========================================================================
  // WAF Rules
  // ==========================================================================

  /**
   * List all WAF rules (static + runtime)
   * @returns Rules array with statistics
   */
  async listRules(): Promise<RulesResponse> {
    return this.get<RulesResponse>('/_sensor/rules');
  }

  /**
   * Add a runtime rule
   * @param rule - Rule definition
   * @param ttl - Optional TTL in seconds (rule expires after this time)
   * @returns Created rule with updated statistics
   */
  async addRule(rule: RuleDefinition, ttl?: number): Promise<AddRuleResponse> {
    return this.post<AddRuleResponse>('/_sensor/rules', { rule, ttl });
  }

  /**
   * Remove a runtime rule by ID
   * @param ruleId - ID of the rule to remove
   * @returns Removal confirmation with updated statistics
   */
  async removeRule(ruleId: number): Promise<RemoveRuleResponse> {
    return this.delete<RemoveRuleResponse>(`/_sensor/rules/${ruleId}`);
  }

  /**
   * Clear all runtime rules
   * @returns Count of cleared rules with updated statistics
   */
  async clearRules(): Promise<ClearRulesResponse> {
    return this.delete<ClearRulesResponse>('/_sensor/rules');
  }

  /**
   * Reload WAF rules from file
   * @returns Reload confirmation with rule statistics
   */
  async reloadRules(): Promise<ReloadRulesResponse> {
    return this.post<ReloadRulesResponse>('/_sensor/reload', {});
  }

  /**
   * Evaluate a request against WAF rules (dry run)
   * @param request - Request to evaluate
   * @returns Evaluation result including matched rules and block decision
   */
  async evaluate(request: EvaluateRequest): Promise<EvaluateResult> {
    return this.post<EvaluateResult>('/_sensor/evaluate', request);
  }

  // ==========================================================================
  // Actor Tracking
  // ==========================================================================

  /**
   * List all tracked actors
   * @returns Array of actors with fingerprint and session data
   */
  async listActors(): Promise<ActorsResponse> {
    return this.get<ActorsResponse>('/_sensor/actors');
  }

  /**
   * Get actor tracking statistics
   * @returns Aggregate statistics for actor tracking
   */
  async getActorStats(): Promise<ActorStats> {
    return this.get<ActorStats>('/_sensor/actors/stats');
  }

  /**
   * Set fingerprint for an actor
   * @param ip - Actor IP address
   * @param fingerprint - Fingerprint value to set
   * @returns Updated actor data
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
      console.error(`[synapse-api] GET ${url}`);
    }

    try {
      const response = await fetch(url, {
        method: 'GET',
        signal: AbortSignal.timeout(this.opts.timeout),
      });

      if (this.opts.debug) {
        console.error(`[synapse-api] response: ${response.status}`);
      }

      if (!response.ok) {
        const text = await response.text();
        throw SynapseError.fromResponse(response.status, text);
      }

      return response.text();
    } catch (error) {
      if (error instanceof SynapseError) throw error;
      throw SynapseError.fromNetworkError(error as Error);
    }
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const url = `${this.opts.baseUrl}${path}`;

    if (this.opts.debug) {
      console.error(`[synapse-api] ${init.method} ${url}`);
      if (init.body) {
        console.error(`[synapse-api] body: ${init.body}`);
      }
    }

    try {
      const response = await fetch(url, {
        ...init,
        signal: AbortSignal.timeout(this.opts.timeout),
      });

      if (this.opts.debug) {
        console.error(`[synapse-api] response: ${response.status}`);
      }

      if (!response.ok) {
        const text = await response.text();
        throw SynapseError.fromResponse(response.status, text);
      }

      // Handle 204 No Content
      if (response.status === 204) {
        return undefined as unknown as T;
      }

      const json = await response.json();

      if (this.opts.debug) {
        console.error(`[synapse-api] result: ${JSON.stringify(json).slice(0, 200)}...`);
      }

      return json as T;
    } catch (error) {
      if (error instanceof SynapseError) throw error;
      throw SynapseError.fromNetworkError(error as Error);
    }
  }
}
