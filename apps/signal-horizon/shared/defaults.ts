/**
 * Shared default configuration values for Signal Horizon.
 *
 * These defaults are used by both the API (Zod schemas) and UI (form components).
 * Import from here to ensure consistency across packages.
 *
 * @example
 * import { DEFAULT_DLP_ENABLED, DEFAULT_TARPIT_BASE_DELAY_MS } from '@signal-horizon/shared/defaults';
 */

// =============================================================================
// Server Defaults
// =============================================================================
export const DEFAULT_SERVER_HTTP_ADDR = '0.0.0.0:80';
export const DEFAULT_SERVER_HTTPS_ADDR = '0.0.0.0:443';
export const DEFAULT_SERVER_WORKERS = 0; // Auto-detect CPU count
export const DEFAULT_SERVER_SHUTDOWN_TIMEOUT_SECS = 30;
export const DEFAULT_SERVER_WAF_THRESHOLD = 70;
export const DEFAULT_SERVER_WAF_ENABLED = true;
export const DEFAULT_SERVER_LOG_LEVEL = 'info';

// =============================================================================
// Upstream Defaults
// =============================================================================
export const DEFAULT_UPSTREAM_WEIGHT = 1;

// =============================================================================
// TLS Defaults
// =============================================================================
export const DEFAULT_TLS_MIN_VERSION = '1.2';

// =============================================================================
// Access Control Defaults
// =============================================================================
export const DEFAULT_ACCESS_CONTROL_ACTION = 'allow' as const;

// =============================================================================
// Site WAF Defaults
// =============================================================================
export const DEFAULT_SITE_WAF_ENABLED = true;

// =============================================================================
// Rate Limit Defaults
// =============================================================================
export const DEFAULT_RATE_LIMIT_RPS = 10000;
export const DEFAULT_RATE_LIMIT_ENABLED = true;
export const DEFAULT_RATE_LIMIT_BURST = 20000;

// =============================================================================
// Profiler Defaults
// =============================================================================
export const DEFAULT_PROFILER_ENABLED = true;
export const DEFAULT_PROFILER_MAX_PROFILES = 1000;
export const DEFAULT_PROFILER_MAX_SCHEMAS = 500;
export const DEFAULT_PROFILER_MIN_SAMPLES = 100;
export const DEFAULT_PROFILER_PAYLOAD_Z = 3.0;
export const DEFAULT_PROFILER_PARAM_Z = 4.0;
export const DEFAULT_PROFILER_RESPONSE_Z = 4.0;
export const DEFAULT_PROFILER_MIN_STDDEV = 0.01;
export const DEFAULT_PROFILER_TYPE_RATIO = 0.9;
export const DEFAULT_PROFILER_MAX_TYPE_COUNTS = 10;
export const DEFAULT_PROFILER_REDACT_PII = true;
export const DEFAULT_PROFILER_FREEZE_AFTER_SAMPLES = 0;

// =============================================================================
// DLP (Data Loss Prevention) Defaults
// =============================================================================
export const DEFAULT_DLP_ENABLED = true;
export const DEFAULT_DLP_FAST_MODE = false;
export const DEFAULT_DLP_SCAN_TEXT_ONLY = true;
export const DEFAULT_DLP_MAX_SCAN_SIZE_BYTES = 5 * 1024 * 1024; // 5MB
export const DEFAULT_DLP_MAX_BODY_INSPECTION_BYTES = 8 * 1024; // 8KB
export const DEFAULT_DLP_MAX_MATCHES = 100;

// =============================================================================
// Block Page Defaults
// =============================================================================
export const DEFAULT_BLOCK_PAGE_SHOW_REQUEST_ID = true;
export const DEFAULT_BLOCK_PAGE_SHOW_TIMESTAMP = true;
export const DEFAULT_BLOCK_PAGE_SHOW_CLIENT_IP = false;
export const DEFAULT_BLOCK_PAGE_SHOW_RULE_ID = false;

// =============================================================================
// Crawler/Bot Detection Defaults
// =============================================================================
export const DEFAULT_CRAWLER_ENABLED = true;
export const DEFAULT_CRAWLER_VERIFY_LEGIT = true;
export const DEFAULT_CRAWLER_BLOCK_BAD_BOTS = true;
export const DEFAULT_CRAWLER_DNS_FAILURE_POLICY = 'apply_risk_penalty' as const;
export const DEFAULT_CRAWLER_DNS_CACHE_TTL_SECS = 300;
export const DEFAULT_CRAWLER_VERIFICATION_CACHE_TTL_SECS = 3600;
export const DEFAULT_CRAWLER_MAX_CACHE_ENTRIES = 50000;
export const DEFAULT_CRAWLER_DNS_TIMEOUT_MS = 2000;
export const DEFAULT_CRAWLER_MAX_CONCURRENT_DNS_LOOKUPS = 100;
export const DEFAULT_CRAWLER_DNS_FAILURE_RISK_PENALTY = 20;

// =============================================================================
// Tarpit Defaults
// =============================================================================
export const DEFAULT_TARPIT_ENABLED = true;
export const DEFAULT_TARPIT_BASE_DELAY_MS = 1000;
export const DEFAULT_TARPIT_MAX_DELAY_MS = 30000;
export const DEFAULT_TARPIT_PROGRESSIVE_MULTIPLIER = 1.5;
export const DEFAULT_TARPIT_MAX_STATES = 10000;
export const DEFAULT_TARPIT_DECAY_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes
export const DEFAULT_TARPIT_CLEANUP_THRESHOLD_MS = 30 * 60 * 1000; // 30 minutes
export const DEFAULT_TARPIT_MAX_CONCURRENT = 1000;

// =============================================================================
// Impossible Travel Defaults
// =============================================================================
export const DEFAULT_TRAVEL_MAX_SPEED_KMH = 800;
export const DEFAULT_TRAVEL_MIN_DISTANCE_KM = 100;
export const DEFAULT_TRAVEL_HISTORY_WINDOW_MS = 24 * 60 * 60 * 1000; // 24 hours
export const DEFAULT_TRAVEL_MAX_HISTORY_PER_USER = 100;

// =============================================================================
// Entity Store Defaults
// =============================================================================
export const DEFAULT_ENTITY_ENABLED = true;
export const DEFAULT_ENTITY_MAX_ENTITIES = 100000;
export const DEFAULT_ENTITY_RISK_DECAY_PER_MINUTE = 10;
export const DEFAULT_ENTITY_BLOCK_THRESHOLD = 70;
export const DEFAULT_ENTITY_MAX_RULES_PER_ENTITY = 50;
export const DEFAULT_ENTITY_MAX_RISK = 100;
export const DEFAULT_ENTITY_MAX_ANOMALIES = 100;
