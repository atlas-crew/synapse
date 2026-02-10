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
import type { ProblemDetails } from '../lib/problem-details.js';

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

export interface CampaignSummaryRaw {
  id: string;
  status: string;
  actorCount: number;
  confidence: number;
  attackTypes: string[];
  firstSeen: string;
  lastActivity: string;
  totalRequests: number;
  blockedRequests: number;
  rulesTriggered: number;
  riskScore: number;
}

export interface CampaignsRawResponse {
  data: CampaignSummaryRaw[];
}

export interface CampaignCorrelationReasonRaw {
  type: string;
  confidence: number;
  description?: string | null;
}

export interface CampaignDetailRaw {
  id: string;
  status: string;
  actorCount: number;
  confidence: number;
  attackTypes: string[];
  firstSeen: string;
  lastActivity: string;
  totalRequests: number;
  blockedRequests: number;
  rulesTriggered: number;
  riskScore: number;
  correlationReasons?: CampaignCorrelationReasonRaw[];
  resolvedAt?: string;
  resolvedReason?: string;
}

export interface CampaignDetailRawResponse {
  data: CampaignDetailRaw;
}

export interface CampaignActorRaw {
  ip: string;
  risk?: number;
  lastActivity?: string;
}

export interface CampaignActorsRawResponse {
  actors: CampaignActorRaw[];
}

export interface SynapseApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface PayloadSummaryResponse {
  total_endpoints: number;
  total_entities: number;
  total_requests: number;
  total_request_bytes: number;
  total_response_bytes: number;
  avg_request_size: number;
  avg_response_size: number;
  active_anomalies: number;
}

export interface EndpointPayloadSummary {
  template: string;
  request_count: number;
  avg_request_size: number;
  avg_response_size: number;
}

export interface PayloadAnomalyResponse {
  anomaly_type: string;
  severity: string;
  risk_applied?: number | null;
  template: string;
  entity_id: string;
  detected_at_ms: number;
  description: string;
}

export interface PayloadBandwidthPoint {
  timestamp: number;
  bytesIn: number;
  bytesOut: number;
  requestCount: number;
}

export interface PayloadBandwidthStats {
  totalBytes: number;
  totalBytesIn: number;
  totalBytesOut: number;
  avgBytesPerRequest: number;
  maxRequestSize: number;
  maxResponseSize: number;
  requestCount: number;
  timeline: PayloadBandwidthPoint[];
}

export type PayloadStatsResponse = SynapseApiResponse<PayloadSummaryResponse>;
export type PayloadEndpointsResponse = SynapseApiResponse<EndpointPayloadSummary[]>;
export type PayloadAnomaliesResponse = SynapseApiResponse<PayloadAnomalyResponse[]>;

export interface ProfilePayloadSizeStats {
  mean: number;
  variance: number;
  stdDev: number;
  count: number;
}

export interface ProfileSummary {
  template: string;
  sampleCount: number;
  firstSeenMs: number;
  lastUpdatedMs: number;
  payloadSize: ProfilePayloadSizeStats;
  expectedParams: unknown;
  contentTypes: unknown;
  statusCodes: unknown;
  endpointRisk: number;
  currentRps: number;
}

export interface ProfileDetail {
  template: string;
  sampleCount: number;
  firstSeenMs: number;
  lastUpdatedMs: number;
  payloadSize: ProfilePayloadSizeStats;
  expectedParams: unknown;
  contentTypes: unknown;
  statusCodes: unknown;
  endpointRisk: number;
  requestRate: {
    currentRps: number;
    windowMs: number;
  };
}

export type ProfilesListResponse = SynapseApiResponse<{ profiles: ProfileSummary[]; count: number }>;
export type ProfileDetailResponse = SynapseApiResponse<ProfileDetail>;

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

export type SensorConfigSection =
  | 'dlp'
  | 'block-page'
  | 'crawler'
  | 'tarpit'
  | 'travel'
  | 'entity'
  | 'kernel';

export interface SensorConfigResponse {
  success?: boolean;
  data?: unknown;
  message?: string;
}

export interface SynapseProxyRequest {
  requestId: string;
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
  headers?: Record<string, string>;
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
  sensorId: string;
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
  '/_sensor/campaigns',
  '/_sensor/evaluate',
  '/_sensor/profiling',
  '/_sensor/payload',
  '/_sensor/config',
  '/_sensor/system',
  '/_sensor/signals',
  '/_sensor/trends',
  '/api/profiles',
  '/api/profiles/',
] as const;

/** Sensor ID format validation */
const SENSOR_ID_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;

/**
 * Private/reserved IP ranges that must be blocked to prevent SSRF.
 * Covers loopback, link-local, private RFC1918, and metadata endpoints.
 */
const BLOCKED_IP_PATTERNS = [
  /^127\./,                          // 127.0.0.0/8 loopback
  /^10\./,                           // 10.0.0.0/8 private
  /^172\.(1[6-9]|2\d|3[01])\./,     // 172.16.0.0/12 private
  /^192\.168\./,                     // 192.168.0.0/16 private
  /^169\.254\./,                     // 169.254.0.0/16 link-local (AWS metadata)
  /^0\./,                            // 0.0.0.0/8
  /^::1$/,                           // IPv6 loopback
  /^fc00:/i,                         // IPv6 ULA
  /^fe80:/i,                         // IPv6 link-local
] as const;

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  '0.0.0.0',
  '[::1]',
  'metadata.google.internal',
  'metadata.google',
  '169.254.169.254',
]);

/** Valid admin port range for sensors */
const VALID_SENSOR_PORT_MIN = 1024;
const VALID_SENSOR_PORT_MAX = 65535;

/**
 * Validate a URL is safe (not targeting internal/private services).
 * Used to prevent SSRF when sensor admin URLs are registered.
 */
export function validateSensorUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new SynapseProxyError(
      'Invalid sensor URL',
      'INVALID_ENDPOINT'
    );
  }

  // Validate scheme
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new SynapseProxyError(
      'Invalid URL scheme: only http and https are allowed',
      'INVALID_ENDPOINT'
    );
  }

  const hostname = parsed.hostname.toLowerCase();

  // Block known dangerous hostnames
  if (BLOCKED_HOSTNAMES.has(hostname)) {
    throw new SynapseProxyError(
      'URL targets a blocked host',
      'INVALID_ENDPOINT'
    );
  }

  // Block private/reserved IP ranges
  for (const pattern of BLOCKED_IP_PATTERNS) {
    if (pattern.test(hostname)) {
      throw new SynapseProxyError(
        'URL targets a private or reserved IP range',
        'INVALID_ENDPOINT'
      );
    }
  }

  // Validate port range if specified
  if (parsed.port) {
    const port = parseInt(parsed.port, 10);
    if (isNaN(port) || port < VALID_SENSOR_PORT_MIN || port > VALID_SENSOR_PORT_MAX) {
      throw new SynapseProxyError(
        `Invalid sensor port: must be between ${VALID_SENSOR_PORT_MIN} and ${VALID_SENSOR_PORT_MAX}`,
        'INVALID_ENDPOINT'
      );
    }
  }

  // Block credentials in URL
  if (parsed.username || parsed.password) {
    throw new SynapseProxyError(
      'URL must not contain credentials',
      'INVALID_ENDPOINT'
    );
  }
}

// ============================================================================
// Retry Utilities
// ============================================================================

/** Maximum number of retry attempts for failed requests */
const MAX_RETRIES = 3;

/**
 * Calculate exponential backoff delay with jitter.
 * Uses decorrelated jitter to prevent thundering herd.
 */
export function backoffDelay(attempt: number): number {
  const base = 1000;  // 1 second
  const max = 30000;  // 30 seconds
  const delay = Math.min(base * Math.pow(2, attempt), max);
  const jitter = Math.random() * delay * 0.25;
  return delay + jitter;
}

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
    body?: unknown,
    headers?: Record<string, string>
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
      return await this.executeWithRetry<T>(sensorId, endpoint, method, body, headers);
    } finally {
      this.concurrencyLimit.release();
    }
  }

  /**
   * Execute a request with exponential backoff retry for retryable failures.
   * Only retries on TIMEOUT, SEND_FAILED, and SENSOR_DISCONNECTED errors.
   */
  private async executeWithRetry<T>(
    sensorId: string,
    endpoint: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    body?: unknown,
    headers?: Record<string, string>
  ): Promise<T> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        return await this.executeRequest<T>(sensorId, endpoint, method, body, headers);
      } catch (error) {
        lastError = error as Error;

        // Only retry on retryable errors
        const isRetryable =
          error instanceof SynapseProxyError && error.retryable;

        if (!isRetryable || attempt >= MAX_RETRIES) {
          throw error;
        }

        const delay = backoffDelay(attempt);
        this.logger.warn(
          { sensorId, endpoint, attempt: attempt + 1, maxRetries: MAX_RETRIES, delayMs: Math.round(delay) },
          'Retrying failed proxy request'
        );

        await this.sleep(delay);
      }
    }

    // Should not reach here, but satisfy TypeScript
    throw lastError ?? new SynapseProxyError('Retry exhausted', 'SEND_FAILED');
  }

  /**
   * Promise-based sleep for retry delays.
   * Uses setTimeout so it works with both real and fake timers.
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Validate endpoint against allowlist to prevent SSRF.
   *
   * Checks performed:
   * 1. Reject null bytes
   * 2. Reject encoded path traversal (percent-encoded dots/slashes)
   * 3. Reject path traversal via .. or //
   * 4. Reject absolute URLs (must be a relative path)
   * 5. Normalize and check against allowlist
   */
  private validateEndpoint(endpoint: string): void {
    // Reject null bytes
    if (endpoint.includes('\0')) {
      throw new SynapseProxyError(
        'Invalid endpoint: null byte detected',
        'INVALID_ENDPOINT'
      );
    }

    // Reject encoded path traversal attempts (%2e = '.', %2f = '/')
    const lower = endpoint.toLowerCase();
    if (lower.includes('%2e') || lower.includes('%2f') || lower.includes('%5c')) {
      throw new SynapseProxyError(
        'Invalid endpoint: encoded traversal detected',
        'INVALID_ENDPOINT'
      );
    }

    // Reject path traversal attempts
    if (endpoint.includes('..') || endpoint.includes('//')) {
      throw new SynapseProxyError(
        'Invalid endpoint: path traversal detected',
        'INVALID_ENDPOINT'
      );
    }

    // Reject absolute URLs (endpoint must be a relative path)
    if (/^https?:\/\//i.test(endpoint)) {
      throw new SynapseProxyError(
        'Invalid endpoint: absolute URLs are not allowed',
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
    body?: unknown,
    headers?: Record<string, string>
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
        sensorId,
      });

      const message: TunnelMessage = {
        type: 'dashboard-request',
        sessionId: requestId,
        payload: {
          requestId,
          endpoint,
          method,
          body,
          headers,
        } as SynapseProxyRequest,
        timestamp: new Date().toISOString(),
      };

      let sent = false;
      try {
        sent = this.tunnelBroker.sendToSensor(sensorId, message);
      } catch {
        this.pendingRequests.delete(requestId);
        clearTimeout(timeout);
        reject(new SynapseProxyError('Failed to send request', 'SEND_FAILED'));
        return;
      }
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
   * Get sensor configuration (system config view)
   */
  async getSensorConfig(
    sensorId: string,
    tenantId: string
  ): Promise<SensorConfigResponse> {
    const cacheKey = `config:${sensorId}:system`;
    const cached = this.getFromCache<SensorConfigResponse>(cacheKey);
    if (cached) return cached;

    const config = await this.proxyRequest<SensorConfigResponse>(
      sensorId,
      tenantId,
      '/_sensor/system/config',
      'GET'
    );

    this.setCache(cacheKey, config, this.LIST_CACHE_TTL);
    return config;
  }

  /**
   * Get a specific configuration section
   */
  async getSensorConfigSection(
    sensorId: string,
    tenantId: string,
    section: SensorConfigSection
  ): Promise<SensorConfigResponse> {
    const cacheKey = `config:${sensorId}:${section}`;
    const cached = this.getFromCache<SensorConfigResponse>(cacheKey);
    if (cached) return cached;

    const config = await this.proxyRequest<SensorConfigResponse>(
      sensorId,
      tenantId,
      `/_sensor/config/${section}`,
      'GET'
    );

    this.setCache(cacheKey, config, this.LIST_CACHE_TTL);
    return config;
  }

  /**
   * Update a specific configuration section
   */
  async updateSensorConfig(
    sensorId: string,
    tenantId: string,
    section: SensorConfigSection,
    config: Record<string, unknown>
  ): Promise<SensorConfigResponse> {
    this.invalidateCache(`config:${sensorId}`);

    return this.proxyRequest<SensorConfigResponse>(
      sensorId,
      tenantId,
      `/_sensor/config/${section}`,
      'PUT',
      config
    );
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
   * List threat campaigns
   */
  async listCampaigns(
    sensorId: string,
    tenantId: string,
    options?: { status?: string; limit?: number; offset?: number }
  ): Promise<CampaignsRawResponse> {
    const cacheKey = `campaigns:${sensorId}:${JSON.stringify(options ?? {})}`;
    const cached = this.getFromCache<CampaignsRawResponse>(cacheKey);
    if (cached) return cached;

    const query = new URLSearchParams();
    if (options?.status) query.set('status', options.status);
    if (options?.limit) query.set('limit', String(options.limit));
    if (options?.offset) query.set('offset', String(options.offset));

    const suffix = query.toString() ? `?${query.toString()}` : '';
    const result = await this.proxyRequest<CampaignsRawResponse>(
      sensorId,
      tenantId,
      `/_sensor/campaigns${suffix}`,
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
  }

  /**
   * Get campaign detail
   */
  async getCampaign(
    sensorId: string,
    tenantId: string,
    campaignId: string
  ): Promise<CampaignDetailRawResponse> {
    return this.proxyRequest<CampaignDetailRawResponse>(
      sensorId,
      tenantId,
      `/_sensor/campaigns/${campaignId}`,
      'GET'
    );
  }

  /**
   * List campaign actors
   */
  async listCampaignActors(
    sensorId: string,
    tenantId: string,
    campaignId: string
  ): Promise<CampaignActorsRawResponse> {
    return this.proxyRequest<CampaignActorsRawResponse>(
      sensorId,
      tenantId,
      `/_sensor/campaigns/${campaignId}/actors`,
      'GET'
    );
  }

  /**
   * Get campaign correlation graph
   */
  async getCampaignGraph(
    sensorId: string,
    tenantId: string,
    campaignId: string
  ): Promise<unknown> {
    return this.proxyRequest<unknown>(
      sensorId,
      tenantId,
      `/_sensor/campaigns/${campaignId}/graph`,
      'GET'
    );
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
   * Get payload profiling summary stats
   */
  async getPayloadStats(sensorId: string, tenantId: string): Promise<PayloadStatsResponse> {
    const cacheKey = `payload:stats:${sensorId}`;
    const cached = this.getFromCache<PayloadStatsResponse>(cacheKey);
    if (cached) return cached;

    const result = await this.proxyRequest<PayloadStatsResponse>(
      sensorId,
      tenantId,
      '/_sensor/payload/stats',
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
  }

  /**
   * List payload endpoint summaries
   */
  async listPayloadEndpoints(
    sensorId: string,
    tenantId: string,
    options?: { limit?: number }
  ): Promise<PayloadEndpointsResponse> {
    const cacheKey = `payload:endpoints:${sensorId}:${JSON.stringify(options ?? {})}`;
    const cached = this.getFromCache<PayloadEndpointsResponse>(cacheKey);
    if (cached) return cached;

    const query = new URLSearchParams();
    if (options?.limit) query.set('limit', String(options.limit));
    const suffix = query.toString() ? `?${query.toString()}` : '';

    const result = await this.proxyRequest<PayloadEndpointsResponse>(
      sensorId,
      tenantId,
      `/_sensor/payload/endpoints${suffix}`,
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
  }

  /**
   * List recent payload anomalies
   */
  async listPayloadAnomalies(
    sensorId: string,
    tenantId: string,
    options?: { limit?: number }
  ): Promise<PayloadAnomaliesResponse> {
    const cacheKey = `payload:anomalies:${sensorId}:${JSON.stringify(options ?? {})}`;
    const cached = this.getFromCache<PayloadAnomaliesResponse>(cacheKey);
    if (cached) return cached;

    const query = new URLSearchParams();
    if (options?.limit) query.set('limit', String(options.limit));
    const suffix = query.toString() ? `?${query.toString()}` : '';

    const result = await this.proxyRequest<PayloadAnomaliesResponse>(
      sensorId,
      tenantId,
      `/_sensor/payload/anomalies${suffix}`,
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
  }

  /**
   * Get payload bandwidth statistics
   */
  async getPayloadBandwidth(
    sensorId: string,
    tenantId: string
  ): Promise<PayloadBandwidthStats> {
    const cacheKey = `payload:bandwidth:${sensorId}`;
    const cached = this.getFromCache<PayloadBandwidthStats>(cacheKey);
    if (cached) return cached;

    const result = await this.proxyRequest<PayloadBandwidthStats>(
      sensorId,
      tenantId,
      '/_sensor/payload/bandwidth',
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
  }

  /**
   * List all endpoint profiles
   */
  async listProfiles(sensorId: string, tenantId: string): Promise<ProfilesListResponse> {
    const cacheKey = `profiles:${sensorId}`;
    const cached = this.getFromCache<ProfilesListResponse>(cacheKey);
    if (cached) return cached;

    const result = await this.proxyRequest<ProfilesListResponse>(
      sensorId,
      tenantId,
      '/api/profiles',
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
  }

  /**
   * Get profile detail by template
   */
  async getProfile(
    sensorId: string,
    tenantId: string,
    template: string
  ): Promise<ProfileDetailResponse> {
    const encodedTemplate = encodeURIComponent(template);
    const cacheKey = `profiles:${sensorId}:${encodedTemplate}`;
    const cached = this.getFromCache<ProfileDetailResponse>(cacheKey);
    if (cached) return cached;

    const result = await this.proxyRequest<ProfileDetailResponse>(
      sensorId,
      tenantId,
      `/api/profiles/${encodedTemplate}`,
      'GET'
    );

    this.setCache(cacheKey, result, this.LIST_CACHE_TTL);
    return result;
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

  /**
   * List connected sensors for a tenant (legacy tunnel protocol).
   */
  listActiveSensors(tenantId: string): string[] {
    return this.tunnelBroker
      .getActiveTunnels(tenantId)
      .map((tunnel) => tunnel.sensorId);
  }

  // ==========================================================================
  // Tunnel Response Handler
  // ==========================================================================

  private setupTunnelListener(): void {
    // Listen for dashboard-response messages from sensors
    this.tunnelBroker.on('tunnel:message', (sensorId: string, message: TunnelMessage) => {
      if (message.type === 'dashboard-response' && message.sessionId) {
        this.handleResponse(sensorId, message.sessionId, message.payload as SynapseProxyResponse);
      }
    });

    // Fail fast when a sensor tunnel disconnects
    this.tunnelBroker.on('tunnel:disconnected', (sensorId: string) => {
      this.rejectPendingForSensor(sensorId, 'Sensor disconnected');
    });
  }

  private handleResponse(sensorId: string, requestId: string, response: SynapseProxyResponse): void {
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
      if (isProblemDetails(response.data)) {
        pending.reject(new SensorError(response.data, sensorId));
      } else {
        pending.reject(new SynapseProxyError(
          `Sensor returned status ${response.status}`,
          'HTTP_ERROR',
          response.status
        ));
      }
    } else {
      pending.resolve(response.data);
    }
  }

  private rejectPendingForSensor(sensorId: string, reason: string): void {
    for (const [requestId, pending] of this.pendingRequests) {
      if (pending.sensorId !== sensorId) {
        continue;
      }
      clearTimeout(pending.timeout);
      pending.reject(new SynapseProxyError(reason, 'SENSOR_DISCONNECTED'));
      this.pendingRequests.delete(requestId);
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
    const prefixes = [
      'status',
      'entities',
      'blocks',
      'rules',
      'actors',
      'sessions',
      'campaigns',
      'config',
      'payload',
      'profiles',
    ];
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
  | 'SENSOR_DISCONNECTED'
  | 'HTTP_ERROR'
  | 'SHUTDOWN'
  | 'INVALID_SENSOR_ID'
  | 'INVALID_ENDPOINT'
  | 'ENDPOINT_NOT_ALLOWED'
  | 'STALE_REQUEST';

export class SensorError extends Error {
  constructor(
    public readonly sensorProblem: ProblemDetails,
    public readonly sensorId: string
  ) {
    super(`Sensor ${sensorId}: ${sensorProblem.title}`);
    this.name = 'SensorError';
  }

  toProblemDetails(): ProblemDetails {
    return {
      type: 'tag:signal-horizon.atlascrew.io,2025:error/sensor-error',
      title: 'Sensor Error',
      status: this.sensorProblem.status,
      detail: this.sensorProblem.detail,
      instance: `/sensors/${this.sensorId}`,
      cause: this.sensorProblem,
    };
  }
}

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
      'SENSOR_DISCONNECTED',
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
      SENSOR_DISCONNECTED: 'Wait for sensor to reconnect and retry',
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

function isProblemDetails(data: unknown): data is ProblemDetails {
  if (!data || typeof data !== 'object') return false;
  const record = data as Record<string, unknown>;
  return typeof record.type === 'string'
    && typeof record.title === 'string'
    && typeof record.status === 'number'
    && typeof record.detail === 'string';
}
