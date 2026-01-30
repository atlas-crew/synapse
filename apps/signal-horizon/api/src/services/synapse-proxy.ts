/**
 * Synapse Proxy Service
 *
 * Routes requests through WebSocket tunnel to sensor's local Synapse API.
 * Provides high-level methods for common operations with response caching.
 *
 * Security features:
 * - Tenant isolation via tunnel validation
 * - Path allowlist to prevent SSRF
 * - Bounded cache with LRU eviction
 * - Concurrency limits to prevent upstream overload
 * - Request timeout handling
 */

import type { Logger } from 'pino';
import type { TunnelBroker, LegacyTunnelMessage } from '../websocket/tunnel-broker.js';

// Alias for backward compatibility
type TunnelMessage = LegacyTunnelMessage;
import { EventEmitter } from 'events';
import { randomUUID } from 'crypto';

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

export interface ActorRuleMatch {
  ruleId: string;
  timestamp: number;
  riskContribution: number;
  category: string;
}

export interface Actor {
  actorId: string;
  riskScore: number;
  ruleMatches: ActorRuleMatch[];
  anomalyCount: number;
  sessionIds: string[];
  firstSeen: number;
  lastSeen: number;
  ips: string[];
  fingerprints: string[];
  isBlocked: boolean;
  blockReason?: string | null;
  blockedSince?: number | null;
}

export interface ActorStats {
  totalActors: number;
  blockedActors: number;
  correlationsMade: number;
  evictions: number;
  totalCreated: number;
  totalRuleMatches: number;
}

export interface ActorListResponse {
  actors: Actor[];
  stats?: ActorStats | null;
}

export interface ActorDetailResponse {
  actor: Actor;
}

export interface ActorTimelineEvent {
  timestamp: number;
  eventType: string;
  ruleId?: string;
  category?: string;
  riskDelta?: number;
  riskScore?: number;
  sessionId?: string;
  actorId?: string | null;
  boundJa4?: string | null;
  boundIp?: string | null;
  clientIp?: string;
  method?: string;
  path?: string;
  matchedRules?: number[];
  blockReason?: string;
  fingerprint?: string | null;
  alertType?: string;
  confidence?: number;
  reason?: string | null;
}

export interface ActorTimelineResponse {
  actorId: string;
  events: ActorTimelineEvent[];
}

export interface HijackAlert {
  sessionId: string;
  alertType: string;
  originalValue: string;
  newValue: string;
  timestamp: number;
  confidence: number;
}

export interface Session {
  sessionId: string;
  tokenHash: string;
  actorId?: string | null;
  creationTime: number;
  lastActivity: number;
  requestCount: number;
  boundJa4?: string | null;
  boundIp?: string | null;
  isSuspicious: boolean;
  hijackAlerts: HijackAlert[];
}

export interface SessionStats {
  totalSessions: number;
  activeSessions: number;
  suspiciousSessions: number;
  expiredSessions: number;
  hijackAlerts: number;
  evictions: number;
  totalCreated: number;
  totalInvalidated: number;
}

export interface SessionListResponse {
  sessions: Session[];
  stats?: SessionStats | null;
}

export interface SessionDetailResponse {
  session: Session;
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
  accessedAt: number;
}

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
  createdAt: number;
}

// ============================================================================
// Security Constants
// ============================================================================

/** Allowed API path prefixes to prevent SSRF */
const ALLOWED_PATH_PREFIXES = [
  '/_sensor/status',
  '/_sensor/entities',
  '/_sensor/blocks',
  '/_sensor/rules',
  '/_sensor/actors',
  '/_sensor/sessions',
  '/_sensor/evaluate',
  '/_sensor/profiling',
  '/_sensor/payload',
] as const;

/** Sensor ID format validation */
const SENSOR_ID_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;

// ============================================================================
// LRU Cache Implementation
// ============================================================================

class LRUCache<K, V> {
  private cache = new Map<K, { value: V; accessedAt: number }>();
  private readonly maxSize: number;

  constructor(maxSize: number) {
    this.maxSize = maxSize;
  }

  get(key: K): V | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined;

    // Move to end (most recently used)
    this.cache.delete(key);
    entry.accessedAt = Date.now();
    this.cache.set(key, entry);
    return entry.value;
  }

  set(key: K, value: V): void {
    // If key exists, delete it first to update position
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxSize) {
      // Evict oldest (first) entry
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }
    this.cache.set(key, { value, accessedAt: Date.now() });
  }

  delete(key: K): boolean {
    return this.cache.delete(key);
  }

  has(key: K): boolean {
    return this.cache.has(key);
  }

  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }

  keys(): IterableIterator<K> {
    return this.cache.keys();
  }

  /** Delete entries matching a prefix */
  deleteByPrefix(prefix: string): void {
    for (const key of this.cache.keys()) {
      if (typeof key === 'string' && key.startsWith(prefix)) {
        this.cache.delete(key);
      }
    }
  }
}

// ============================================================================
// Concurrency Control
// ============================================================================

class Semaphore {
  private permits: number;
  private waiting: Array<() => void> = [];

  constructor(permits: number) {
    this.permits = permits;
  }

  async acquire(): Promise<void> {
    if (this.permits > 0) {
      this.permits--;
      return;
    }

    return new Promise<void>((resolve) => {
      this.waiting.push(resolve);
    });
  }

  release(): void {
    const next = this.waiting.shift();
    if (next) {
      next();
    } else {
      this.permits++;
    }
  }

  get available(): number {
    return this.permits;
  }

  get queueLength(): number {
    return this.waiting.length;
  }
}

// ============================================================================
// SynapseProxyService Class
// ============================================================================

export class SynapseProxyService extends EventEmitter {
  private cache: LRUCache<string, CacheEntry<unknown>>;
  private pendingRequests = new Map<string, PendingRequest>();
  private concurrencyLimit: Semaphore;

  // Metrics
  private cacheHits = 0;
  private cacheMisses = 0;
  private totalRequests = 0;

  // Configuration
  private readonly MAX_CACHE_SIZE = 1000;
  private readonly MAX_CONCURRENT_REQUESTS = 20;
  private readonly STATUS_CACHE_TTL = 5000;     // 5 seconds
  private readonly LIST_CACHE_TTL = 10000;      // 10 seconds
  private readonly REQUEST_TIMEOUT = 30000;     // 30 seconds
  private readonly STALE_REQUEST_THRESHOLD = 60000; // 1 minute for GC

  constructor(
    private tunnelBroker: TunnelBroker,
    private logger: Logger
  ) {
    super();
    this.cache = new LRUCache(this.MAX_CACHE_SIZE);
    this.concurrencyLimit = new Semaphore(this.MAX_CONCURRENT_REQUESTS);
    this.setupTunnelListener();
    this.startCacheCleanup();
    this.startStaleRequestCleanup();
    this.logger.info({
      maxCacheSize: this.MAX_CACHE_SIZE,
      maxConcurrentRequests: this.MAX_CONCURRENT_REQUESTS,
    }, 'SynapseProxyService initialized');
  }

  // ==========================================================================
  // Core Proxy Method
  // ==========================================================================

  /**
   * Route a request through the tunnel to sensor's Synapse API
   *
   * Security checks:
   * - Validates sensor ID format
   * - Validates endpoint against allowlist (SSRF protection)
   * - Verifies tunnel exists and belongs to tenant
   * - Applies concurrency limits
   */
  async proxyRequest<T = unknown>(
    sensorId: string,
    tenantId: string,
    endpoint: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET',
    body?: unknown
  ): Promise<T> {
    this.totalRequests++;

    // Validate sensor ID format
    if (!SENSOR_ID_PATTERN.test(sensorId)) {
      throw new SynapseProxyError(
        'Invalid sensor ID format',
        'INVALID_SENSOR_ID'
      );
    }

    // SSRF protection: validate endpoint against allowlist
    this.validateEndpoint(endpoint);

    // Verify tunnel exists and belongs to tenant
    const tunnel = this.tunnelBroker.getTunnelStatus(sensorId);
    if (!tunnel) {
      throw new SynapseProxyError('Sensor tunnel not connected', 'TUNNEL_NOT_FOUND');
    }

    if (tunnel.tenantId !== tenantId) {
      throw new SynapseProxyError('Tenant mismatch', 'FORBIDDEN');
    }

    // Apply concurrency limit
    await this.concurrencyLimit.acquire();

    try {
      return await this.executeRequest<T>(sensorId, endpoint, method, body);
    } finally {
      this.concurrencyLimit.release();
    }
  }

  /**
   * Validate endpoint against allowlist to prevent SSRF
   */
  private validateEndpoint(endpoint: string): void {
    // Reject path traversal attempts
    if (endpoint.includes('..') || endpoint.includes('//')) {
      throw new SynapseProxyError(
        'Invalid endpoint: path traversal detected',
        'INVALID_ENDPOINT'
      );
    }

    // Check against allowlist
    const pathWithoutQuery = endpoint.split('?')[0];
    const isAllowed = ALLOWED_PATH_PREFIXES.some(prefix =>
      pathWithoutQuery.startsWith(prefix)
    );

    if (!isAllowed) {
      this.logger.warn({ endpoint }, 'Blocked request to non-allowlisted endpoint');
      throw new SynapseProxyError(
        'Endpoint not allowed',
        'ENDPOINT_NOT_ALLOWED'
      );
    }
  }

  /**
   * Execute the actual request through the tunnel
   */
  private async executeRequest<T>(
    sensorId: string,
    endpoint: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    body?: unknown
  ): Promise<T> {
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
        createdAt: Date.now(),
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
      '/_sensor/status',
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
      `/_sensor/entities?${query.toString()}`,
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
      `/_sensor/entities/${entityId}`,
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
      `/_sensor/blocks?${query.toString()}`,
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
      '/_sensor/blocks',
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
      `/_sensor/blocks/${blockId}`,
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
      `/_sensor/entities/${entityId}`,
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
      `/_sensor/rules?${query.toString()}`,
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
      '/_sensor/rules',
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
      `/_sensor/rules/${ruleId}`,
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
      `/_sensor/rules/${ruleId}`,
      'DELETE'
    );
  }

  /**
   * List tracked actors
   */
  async listActors(
    sensorId: string,
    tenantId: string,
    options?: {
      ip?: string;
      fingerprint?: string;
      minRisk?: number;
      minScore?: number;
      type?: string;
      limit?: number;
      offset?: number;
    }
  ): Promise<ActorListResponse> {
    const cacheKey = `actors:${sensorId}:${JSON.stringify(options ?? {})}`;
    const cached = this.getFromCache<ActorListResponse>(cacheKey);
    if (cached) return cached;

    const query = new URLSearchParams();
    if (options?.ip) query.set('ip', options.ip);
    if (options?.fingerprint) query.set('fingerprint', options.fingerprint);
    if (options?.minRisk !== undefined) {
      query.set('min_risk', String(options.minRisk));
    } else if (options?.minScore !== undefined) {
      query.set('min_risk', String(options.minScore));
    }
    if (options?.limit) query.set('limit', String(options.limit));
    if (options?.offset) query.set('offset', String(options.offset));

    const result = await this.proxyRequest<ActorListResponse>(
      sensorId,
      tenantId,
      `/_sensor/actors?${query.toString()}`,
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
  }

  /**
   * Get details for a specific actor
   */
  async getActor(sensorId: string, tenantId: string, actorId: string): Promise<ActorDetailResponse> {
    return this.proxyRequest<ActorDetailResponse>(
      sensorId,
      tenantId,
      `/_sensor/actors/${actorId}`,
      'GET'
    );
  }

  /**
   * Get actor timeline events
   */
  async getActorTimeline(
    sensorId: string,
    tenantId: string,
    actorId: string,
    options?: { limit?: number }
  ): Promise<ActorTimelineResponse> {
    const query = new URLSearchParams();
    if (options?.limit) query.set('limit', String(options.limit));
    const suffix = query.toString() ? `?${query.toString()}` : '';

    return this.proxyRequest<ActorTimelineResponse>(
      sensorId,
      tenantId,
      `/_sensor/actors/${actorId}/timeline${suffix}`,
      'GET'
    );
  }

  /**
   * List tracked sessions
   */
  async listSessions(
    sensorId: string,
    tenantId: string,
    options?: { actorId?: string; suspicious?: boolean; limit?: number; offset?: number }
  ): Promise<SessionListResponse> {
    const cacheKey = `sessions:${sensorId}:${JSON.stringify(options ?? {})}`;
    const cached = this.getFromCache<SessionListResponse>(cacheKey);
    if (cached) return cached;

    const query = new URLSearchParams();
    if (options?.actorId) query.set('actor_id', options.actorId);
    if (options?.suspicious !== undefined) query.set('suspicious', String(options.suspicious));
    if (options?.limit) query.set('limit', String(options.limit));
    if (options?.offset) query.set('offset', String(options.offset));

    const result = await this.proxyRequest<SessionListResponse>(
      sensorId,
      tenantId,
      `/_sensor/sessions?${query.toString()}`,
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
  }

  /**
   * Get session detail by ID
   */
  async getSession(
    sensorId: string,
    tenantId: string,
    sessionId: string
  ): Promise<SessionDetailResponse> {
    return this.proxyRequest<SessionDetailResponse>(
      sensorId,
      tenantId,
      `/_sensor/sessions/${sessionId}`,
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
      '/_sensor/evaluate',
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
    if (!entry) {
      this.cacheMisses++;
      return null;
    }

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      this.cacheMisses++;
      return null;
    }

    this.cacheHits++;
    return entry.data as T;
  }

  private setCache(key: string, data: unknown, ttlMs: number): void {
    const now = Date.now();
    this.cache.set(key, {
      data,
      expiresAt: now + ttlMs,
      accessedAt: now,
    });
  }

  private invalidateCache(prefix: string): void {
    this.cache.deleteByPrefix(prefix);
  }

  /**
   * Clear all cache entries for a sensor
   */
  clearSensorCache(sensorId: string): void {
    const sanitizedSensorId = sensorId.replace(/[^a-zA-Z0-9_-]/g, '');
    const prefixes = ['status', 'entities', 'blocks', 'rules', 'actors', 'sessions'];
    for (const prefix of prefixes) {
      this.invalidateCache(`${prefix}:${sanitizedSensorId}`);
    }
  }

  private startCacheCleanup(): void {
    setInterval(() => {
      const now = Date.now();
      for (const key of this.cache.keys()) {
        const entry = this.cache.get(key);
        if (entry && now > entry.expiresAt) {
          this.cache.delete(key);
        }
      }
    }, 60000); // Clean up every minute
  }

  /**
   * Garbage collect stale pending requests
   * This catches requests that weren't properly cleaned up due to:
   * - Tunnel disconnection without error emission
   * - Network partitions
   * - Unhandled edge cases
   */
  private startStaleRequestCleanup(): void {
    setInterval(() => {
      const now = Date.now();
      let cleanedCount = 0;

      for (const [requestId, pending] of this.pendingRequests) {
        if (now - pending.createdAt > this.STALE_REQUEST_THRESHOLD) {
          clearTimeout(pending.timeout);
          pending.reject(new SynapseProxyError(
            'Request stale - garbage collected',
            'STALE_REQUEST'
          ));
          this.pendingRequests.delete(requestId);
          cleanedCount++;
        }
      }

      if (cleanedCount > 0) {
        this.logger.warn({ cleanedCount }, 'Garbage collected stale pending requests');
      }
    }, 30000); // Check every 30 seconds
  }

  // ==========================================================================
  // Utilities
  // ==========================================================================

  /**
   * Generate a unique request ID using crypto.randomUUID
   * This is collision-safe even under high concurrency
   */
  private generateRequestId(): string {
    return `synapse-${randomUUID()}`;
  }

  /**
   * Get proxy statistics including cache hit rate and concurrency metrics
   */
  getStats(): {
    pendingRequests: number;
    cacheSize: number;
    maxCacheSize: number;
    cacheHitRate: number;
    cacheHits: number;
    cacheMisses: number;
    totalRequests: number;
    concurrentRequestsAvailable: number;
    concurrentRequestsQueued: number;
  } {
    const totalCacheRequests = this.cacheHits + this.cacheMisses;
    const hitRate = totalCacheRequests > 0
      ? Math.round((this.cacheHits / totalCacheRequests) * 100) / 100
      : 0;

    return {
      pendingRequests: this.pendingRequests.size,
      cacheSize: this.cache.size,
      maxCacheSize: this.MAX_CACHE_SIZE,
      cacheHitRate: hitRate,
      cacheHits: this.cacheHits,
      cacheMisses: this.cacheMisses,
      totalRequests: this.totalRequests,
      concurrentRequestsAvailable: this.concurrencyLimit.available,
      concurrentRequestsQueued: this.concurrencyLimit.queueLength,
    };
  }

  /**
   * Shutdown the service gracefully
   */
  async shutdown(): Promise<void> {
    this.logger.info('SynapseProxyService shutting down...');

    // Cancel all pending requests
    for (const [requestId, pending] of this.pendingRequests) {
      clearTimeout(pending.timeout);
      pending.reject(new SynapseProxyError('Service shutting down', 'SHUTDOWN'));
      this.pendingRequests.delete(requestId);
    }

    this.cache.clear();
    this.logger.info({
      totalRequests: this.totalRequests,
      cacheHits: this.cacheHits,
      cacheMisses: this.cacheMisses,
    }, 'SynapseProxyService shutdown complete');
  }
}

// ============================================================================
// Error Class
// ============================================================================

export type SynapseErrorCode =
  | 'TUNNEL_NOT_FOUND'
  | 'FORBIDDEN'
  | 'TIMEOUT'
  | 'SEND_FAILED'
  | 'SENSOR_ERROR'
  | 'HTTP_ERROR'
  | 'SHUTDOWN'
  | 'INVALID_SENSOR_ID'
  | 'INVALID_ENDPOINT'
  | 'ENDPOINT_NOT_ALLOWED'
  | 'STALE_REQUEST';

export class SynapseProxyError extends Error {
  readonly code: SynapseErrorCode;
  readonly status: number | undefined;
  readonly retryable: boolean;

  constructor(
    message: string,
    code: SynapseErrorCode,
    status?: number,
    options?: { cause?: Error }
  ) {
    super(message, options);
    this.name = 'SynapseProxyError';
    this.code = code;
    this.status = status;

    // Determine if error is retryable based on code
    this.retryable = [
      'TUNNEL_NOT_FOUND',
      'TIMEOUT',
      'SEND_FAILED',
      'STALE_REQUEST',
    ].includes(code);
  }

  /**
   * Create a structured error response for API consumers
   */
  toJSON(): {
    error: string;
    code: SynapseErrorCode;
    status?: number;
    retryable: boolean;
    suggestion?: string;
  } {
    const suggestions: Partial<Record<SynapseErrorCode, string>> = {
      TUNNEL_NOT_FOUND: 'Verify sensor is online and connected',
      TIMEOUT: 'Retry the request or check sensor connectivity',
      SEND_FAILED: 'Check tunnel connection and retry',
      FORBIDDEN: 'Verify you have access to this sensor',
      INVALID_SENSOR_ID: 'Sensor ID must be alphanumeric with hyphens/underscores, max 64 chars',
      ENDPOINT_NOT_ALLOWED: 'The requested endpoint is not available through the proxy',
    };

    return {
      error: this.message,
      code: this.code,
      status: this.status,
      retryable: this.retryable,
      suggestion: suggestions[this.code],
    };
  }
}
