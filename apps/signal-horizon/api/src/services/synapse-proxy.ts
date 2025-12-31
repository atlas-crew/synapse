/**
 * Synapse Proxy Service
 *
 * Routes requests through WebSocket tunnel to sensor's local Synapse API.
 * Provides high-level methods for common operations with response caching.
 */

import type { Logger } from 'pino';
import type { TunnelBroker, TunnelMessage } from '../websocket/tunnel-broker.js';
import { EventEmitter } from 'events';

// ============================================================================
// Types
// ============================================================================

export interface SynapseStatus {
  version: string;
  uptime: number;
  status: 'healthy' | 'degraded' | 'unhealthy';
  cpu: number;
  memory: number;
  disk: number;
  requestsPerSecond: number;
  blockedRequests: number;
  rulesLoaded: number;
  entitiesTracked: number;
  actorsActive: number;
}

export interface Entity {
  id: string;
  type: 'IP' | 'FINGERPRINT' | 'SESSION' | 'USER';
  value: string;
  score: number;
  firstSeen: string;
  lastSeen: string;
  requestCount: number;
  blockCount: number;
  tags: string[];
  metadata?: Record<string, unknown>;
}

export interface Block {
  id: string;
  type: 'IP' | 'FINGERPRINT' | 'CIDR' | 'USER_AGENT';
  value: string;
  source: 'MANUAL' | 'AUTO' | 'FLEET_INTEL' | 'RULE';
  reason: string;
  createdAt: string;
  expiresAt?: string;
  ruleId?: string;
}

export interface Rule {
  id: string;
  name: string;
  type: 'BLOCK' | 'CHALLENGE' | 'RATE_LIMIT' | 'MONITOR';
  enabled: boolean;
  priority: number;
  conditions: RuleCondition[];
  actions: RuleAction[];
  ttl?: number;
  hitCount: number;
  lastHit?: string;
  createdAt: string;
  updatedAt: string;
}

export interface RuleCondition {
  field: string;
  operator: 'eq' | 'ne' | 'gt' | 'lt' | 'contains' | 'matches' | 'in';
  value: unknown;
}

export interface RuleAction {
  type: 'block' | 'challenge' | 'rate_limit' | 'tag' | 'log';
  params?: Record<string, unknown>;
}

export interface Actor {
  id: string;
  identifier: string;
  type: 'human' | 'bot' | 'crawler' | 'suspicious' | 'attacker';
  score: number;
  requestCount: number;
  blockedCount: number;
  challengesPassed: number;
  challengesFailed: number;
  lastRequest: string;
  geoLocation?: {
    country: string;
    region: string;
    city: string;
  };
  fingerprints: string[];
  tags: string[];
}

export interface EvalRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body?: string;
  clientIp: string;
  fingerprint?: string;
}

export interface EvalResult {
  decision: 'allow' | 'block' | 'challenge' | 'rate_limit';
  score: number;
  matchedRules: string[];
  processingTimeMs: number;
  reasoning?: string;
}

export interface SynapseProxyRequest {
  requestId: string;
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
}

export interface SynapseProxyResponse {
  requestId: string;
  status: number;
  data?: unknown;
  error?: string;
}

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
}

// ============================================================================
// SynapseProxyService Class
// ============================================================================

export class SynapseProxyService extends EventEmitter {
  private cache = new Map<string, CacheEntry<unknown>>();
  private pendingRequests = new Map<string, {
    resolve: (value: unknown) => void;
    reject: (error: Error) => void;
    timeout: NodeJS.Timeout;
  }>();
  private requestCounter = 0;

  // Cache TTLs in milliseconds
  private readonly STATUS_CACHE_TTL = 5000;     // 5 seconds
  private readonly LIST_CACHE_TTL = 10000;      // 10 seconds
  private readonly REQUEST_TIMEOUT = 30000;     // 30 seconds

  constructor(
    private tunnelBroker: TunnelBroker,
    private logger: Logger
  ) {
    super();
    this.setupTunnelListener();
    this.startCacheCleanup();
    this.logger.info('SynapseProxyService initialized');
  }

  // ==========================================================================
  // Core Proxy Method
  // ==========================================================================

  /**
   * Route a request through the tunnel to sensor's Synapse API
   */
  async proxyRequest<T = unknown>(
    sensorId: string,
    tenantId: string,
    endpoint: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET',
    body?: unknown
  ): Promise<T> {
    // Verify tunnel exists and belongs to tenant
    const tunnel = this.tunnelBroker.getTunnelStatus(sensorId);
    if (!tunnel) {
      throw new SynapseProxyError('Sensor tunnel not connected', 'TUNNEL_NOT_FOUND');
    }

    if (tunnel.tenantId !== tenantId) {
      throw new SynapseProxyError('Tenant mismatch', 'FORBIDDEN');
    }

    const requestId = this.generateRequestId();

    return new Promise<T>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        reject(new SynapseProxyError('Request timeout', 'TIMEOUT'));
      }, this.REQUEST_TIMEOUT);

      this.pendingRequests.set(requestId, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timeout,
      });

      const message: TunnelMessage = {
        type: 'dashboard-request',
        sessionId: requestId,
        payload: {
          requestId,
          endpoint,
          method,
          body,
        } as SynapseProxyRequest,
        timestamp: new Date().toISOString(),
      };

      const sent = this.tunnelBroker.sendToSensor(sensorId, message);
      if (!sent) {
        this.pendingRequests.delete(requestId);
        clearTimeout(timeout);
        reject(new SynapseProxyError('Failed to send request', 'SEND_FAILED'));
      }
    });
  }

  // ==========================================================================
  // High-Level Methods
  // ==========================================================================

  /**
   * Get sensor's current status and health metrics
   */
  async getSensorStatus(sensorId: string, tenantId: string): Promise<SynapseStatus> {
    const cacheKey = `status:${sensorId}`;
    const cached = this.getFromCache<SynapseStatus>(cacheKey);
    if (cached) return cached;

    const status = await this.proxyRequest<SynapseStatus>(
      sensorId,
      tenantId,
      '/api/v1/status',
      'GET'
    );

    this.setCache(cacheKey, status, this.STATUS_CACHE_TTL);
    return status;
  }

  /**
   * List tracked entities (IPs, fingerprints, sessions)
   */
  async listEntities(
    sensorId: string,
    tenantId: string,
    options?: { type?: Entity['type']; limit?: number; offset?: number }
  ): Promise<{ entities: Entity[]; total: number }> {
    const cacheKey = `entities:${sensorId}:${JSON.stringify(options ?? {})}`;
    const cached = this.getFromCache<{ entities: Entity[]; total: number }>(cacheKey);
    if (cached) return cached;

    const query = new URLSearchParams();
    if (options?.type) query.set('type', options.type);
    if (options?.limit) query.set('limit', String(options.limit));
    if (options?.offset) query.set('offset', String(options.offset));

    const result = await this.proxyRequest<{ entities: Entity[]; total: number }>(
      sensorId,
      tenantId,
      `/api/v1/entities?${query.toString()}`,
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
  }

  /**
   * Get details for a specific entity
   */
  async getEntity(sensorId: string, tenantId: string, entityId: string): Promise<Entity> {
    return this.proxyRequest<Entity>(
      sensorId,
      tenantId,
      `/api/v1/entities/${entityId}`,
      'GET'
    );
  }

  /**
   * List active blocks
   */
  async listBlocks(
    sensorId: string,
    tenantId: string,
    options?: { type?: Block['type']; limit?: number; offset?: number }
  ): Promise<{ blocks: Block[]; total: number }> {
    const cacheKey = `blocks:${sensorId}:${JSON.stringify(options ?? {})}`;
    const cached = this.getFromCache<{ blocks: Block[]; total: number }>(cacheKey);
    if (cached) return cached;

    const query = new URLSearchParams();
    if (options?.type) query.set('type', options.type);
    if (options?.limit) query.set('limit', String(options.limit));
    if (options?.offset) query.set('offset', String(options.offset));

    const result = await this.proxyRequest<{ blocks: Block[]; total: number }>(
      sensorId,
      tenantId,
      `/api/v1/blocks?${query.toString()}`,
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
  }

  /**
   * Add a new block
   */
  async addBlock(
    sensorId: string,
    tenantId: string,
    block: Omit<Block, 'id' | 'createdAt'>
  ): Promise<Block> {
    this.invalidateCache(`blocks:${sensorId}`);

    return this.proxyRequest<Block>(
      sensorId,
      tenantId,
      '/api/v1/blocks',
      'POST',
      block
    );
  }

  /**
   * Remove a block
   */
  async removeBlock(sensorId: string, tenantId: string, blockId: string): Promise<void> {
    this.invalidateCache(`blocks:${sensorId}`);

    await this.proxyRequest<void>(
      sensorId,
      tenantId,
      `/api/v1/blocks/${blockId}`,
      'DELETE'
    );
  }

  /**
   * Release an entity (clear its tracking data)
   */
  async releaseEntity(sensorId: string, tenantId: string, entityId: string): Promise<void> {
    this.invalidateCache(`entities:${sensorId}`);

    await this.proxyRequest<void>(
      sensorId,
      tenantId,
      `/api/v1/entities/${entityId}`,
      'DELETE'
    );
  }

  /**
   * List active rules
   */
  async listRules(
    sensorId: string,
    tenantId: string,
    options?: { enabled?: boolean; type?: Rule['type']; limit?: number; offset?: number }
  ): Promise<{ rules: Rule[]; total: number }> {
    const cacheKey = `rules:${sensorId}:${JSON.stringify(options ?? {})}`;
    const cached = this.getFromCache<{ rules: Rule[]; total: number }>(cacheKey);
    if (cached) return cached;

    const query = new URLSearchParams();
    if (options?.enabled !== undefined) query.set('enabled', String(options.enabled));
    if (options?.type) query.set('type', options.type);
    if (options?.limit) query.set('limit', String(options.limit));
    if (options?.offset) query.set('offset', String(options.offset));

    const result = await this.proxyRequest<{ rules: Rule[]; total: number }>(
      sensorId,
      tenantId,
      `/api/v1/rules?${query.toString()}`,
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
  }

  /**
   * Add a new rule
   */
  async addRule(
    sensorId: string,
    tenantId: string,
    rule: Omit<Rule, 'id' | 'hitCount' | 'createdAt' | 'updatedAt'>,
    ttl?: number
  ): Promise<Rule> {
    this.invalidateCache(`rules:${sensorId}`);

    const body = ttl ? { ...rule, ttl } : rule;
    return this.proxyRequest<Rule>(
      sensorId,
      tenantId,
      '/api/v1/rules',
      'POST',
      body
    );
  }

  /**
   * Update an existing rule
   */
  async updateRule(
    sensorId: string,
    tenantId: string,
    ruleId: string,
    updates: Partial<Omit<Rule, 'id' | 'hitCount' | 'createdAt' | 'updatedAt'>>
  ): Promise<Rule> {
    this.invalidateCache(`rules:${sensorId}`);

    return this.proxyRequest<Rule>(
      sensorId,
      tenantId,
      `/api/v1/rules/${ruleId}`,
      'PUT',
      updates
    );
  }

  /**
   * Delete a rule
   */
  async deleteRule(sensorId: string, tenantId: string, ruleId: string): Promise<void> {
    this.invalidateCache(`rules:${sensorId}`);

    await this.proxyRequest<void>(
      sensorId,
      tenantId,
      `/api/v1/rules/${ruleId}`,
      'DELETE'
    );
  }

  /**
   * List tracked actors
   */
  async listActors(
    sensorId: string,
    tenantId: string,
    options?: { type?: Actor['type']; minScore?: number; limit?: number; offset?: number }
  ): Promise<{ actors: Actor[]; total: number }> {
    const cacheKey = `actors:${sensorId}:${JSON.stringify(options ?? {})}`;
    const cached = this.getFromCache<{ actors: Actor[]; total: number }>(cacheKey);
    if (cached) return cached;

    const query = new URLSearchParams();
    if (options?.type) query.set('type', options.type);
    if (options?.minScore !== undefined) query.set('minScore', String(options.minScore));
    if (options?.limit) query.set('limit', String(options.limit));
    if (options?.offset) query.set('offset', String(options.offset));

    const result = await this.proxyRequest<{ actors: Actor[]; total: number }>(
      sensorId,
      tenantId,
      `/api/v1/actors?${query.toString()}`,
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
  }

  /**
   * Get details for a specific actor
   */
  async getActor(sensorId: string, tenantId: string, actorId: string): Promise<Actor> {
    return this.proxyRequest<Actor>(
      sensorId,
      tenantId,
      `/api/v1/actors/${actorId}`,
      'GET'
    );
  }

  /**
   * Evaluate a request against the sensor's rules
   */
  async evaluateRequest(
    sensorId: string,
    tenantId: string,
    request: EvalRequest
  ): Promise<EvalResult> {
    // Evaluation requests are never cached
    return this.proxyRequest<EvalResult>(
      sensorId,
      tenantId,
      '/api/v1/evaluate',
      'POST',
      request
    );
  }

  // ==========================================================================
  // Tunnel Response Handler
  // ==========================================================================

  private setupTunnelListener(): void {
    // Listen for dashboard-response messages from sensors
    this.tunnelBroker.on('tunnel:message', (_sensorId: string, message: TunnelMessage) => {
      if (message.type === 'dashboard-response' && message.sessionId) {
        this.handleResponse(message.sessionId, message.payload as SynapseProxyResponse);
      }
    });
  }

  private handleResponse(requestId: string, response: SynapseProxyResponse): void {
    const pending = this.pendingRequests.get(requestId);
    if (!pending) {
      this.logger.warn({ requestId }, 'Received response for unknown request');
      return;
    }

    clearTimeout(pending.timeout);
    this.pendingRequests.delete(requestId);

    if (response.error) {
      pending.reject(new SynapseProxyError(response.error, 'SENSOR_ERROR'));
    } else if (response.status >= 400) {
      pending.reject(new SynapseProxyError(
        `Sensor returned status ${response.status}`,
        'HTTP_ERROR',
        response.status
      ));
    } else {
      pending.resolve(response.data);
    }
  }

  // ==========================================================================
  // Cache Management
  // ==========================================================================

  private getFromCache<T>(key: string): T | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    return entry.data as T;
  }

  private setCache(key: string, data: unknown, ttlMs: number): void {
    this.cache.set(key, {
      data,
      expiresAt: Date.now() + ttlMs,
    });
  }

  private invalidateCache(prefix: string): void {
    for (const key of this.cache.keys()) {
      if (key.startsWith(prefix)) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Clear all cache entries for a sensor
   */
  clearSensorCache(sensorId: string): void {
    const prefixes = ['status', 'entities', 'blocks', 'rules', 'actors'];
    for (const prefix of prefixes) {
      this.invalidateCache(`${prefix}:${sensorId}`);
    }
  }

  private startCacheCleanup(): void {
    setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.cache) {
        if (now > entry.expiresAt) {
          this.cache.delete(key);
        }
      }
    }, 60000); // Clean up every minute
  }

  // ==========================================================================
  // Utilities
  // ==========================================================================

  private generateRequestId(): string {
    this.requestCounter++;
    return `synapse-${Date.now()}-${this.requestCounter}`;
  }

  /**
   * Get proxy statistics
   */
  getStats(): { pendingRequests: number; cacheSize: number; cacheHitRate: number } {
    return {
      pendingRequests: this.pendingRequests.size,
      cacheSize: this.cache.size,
      cacheHitRate: 0, // TODO: Track cache hits/misses
    };
  }

  /**
   * Shutdown the service
   */
  async shutdown(): Promise<void> {
    // Cancel all pending requests
    for (const [requestId, pending] of this.pendingRequests) {
      clearTimeout(pending.timeout);
      pending.reject(new SynapseProxyError('Service shutting down', 'SHUTDOWN'));
      this.pendingRequests.delete(requestId);
    }

    this.cache.clear();
    this.logger.info('SynapseProxyService shutdown complete');
  }
}

// ============================================================================
// Error Class
// ============================================================================

export class SynapseProxyError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly status?: number
  ) {
    super(message);
    this.name = 'SynapseProxyError';
  }
}
