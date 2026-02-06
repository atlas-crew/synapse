import { z } from 'zod';
import {
  DEFAULT_ACCESS_CONTROL_ACTION,
  DEFAULT_BLOCK_PAGE_SHOW_CLIENT_IP,
  DEFAULT_BLOCK_PAGE_SHOW_REQUEST_ID,
  DEFAULT_BLOCK_PAGE_SHOW_RULE_ID,
  DEFAULT_BLOCK_PAGE_SHOW_TIMESTAMP,
  DEFAULT_CRAWLER_BLOCK_BAD_BOTS,
  DEFAULT_CRAWLER_DNS_CACHE_TTL_SECS,
  DEFAULT_CRAWLER_DNS_FAILURE_POLICY,
  DEFAULT_CRAWLER_DNS_FAILURE_RISK_PENALTY,
  DEFAULT_CRAWLER_DNS_TIMEOUT_MS,
  DEFAULT_CRAWLER_ENABLED,
  DEFAULT_CRAWLER_MAX_CACHE_ENTRIES,
  DEFAULT_CRAWLER_MAX_CONCURRENT_DNS_LOOKUPS,
  DEFAULT_CRAWLER_VERIFY_LEGIT,
  DEFAULT_CRAWLER_VERIFICATION_CACHE_TTL_SECS,
  DEFAULT_DLP_ENABLED,
  DEFAULT_DLP_FAST_MODE,
  DEFAULT_DLP_MAX_BODY_INSPECTION_BYTES,
  DEFAULT_DLP_MAX_MATCHES,
  DEFAULT_DLP_MAX_SCAN_SIZE_BYTES,
  DEFAULT_DLP_SCAN_TEXT_ONLY,
  DEFAULT_ENTITY_BLOCK_THRESHOLD,
  DEFAULT_ENTITY_ENABLED,
  DEFAULT_ENTITY_MAX_ANOMALIES,
  DEFAULT_ENTITY_MAX_ENTITIES,
  DEFAULT_ENTITY_MAX_RISK,
  DEFAULT_ENTITY_MAX_RULES_PER_ENTITY,
  DEFAULT_ENTITY_RISK_DECAY_PER_MINUTE,
  DEFAULT_PROFILER_ENABLED,
  DEFAULT_PROFILER_FREEZE_AFTER_SAMPLES,
  DEFAULT_PROFILER_MAX_PROFILES,
  DEFAULT_PROFILER_MAX_SCHEMAS,
  DEFAULT_PROFILER_MAX_TYPE_COUNTS,
  DEFAULT_PROFILER_MIN_SAMPLES,
  DEFAULT_PROFILER_MIN_STDDEV,
  DEFAULT_PROFILER_PARAM_Z,
  DEFAULT_PROFILER_PAYLOAD_Z,
  DEFAULT_PROFILER_REDACT_PII,
  DEFAULT_PROFILER_RESPONSE_Z,
  DEFAULT_PROFILER_TYPE_RATIO,
  DEFAULT_RATE_LIMIT_ENABLED,
  DEFAULT_RATE_LIMIT_RPS,
  DEFAULT_SERVER_HTTP_ADDR,
  DEFAULT_SERVER_HTTPS_ADDR,
  DEFAULT_SERVER_LOG_LEVEL,
  DEFAULT_SERVER_SHUTDOWN_TIMEOUT_SECS,
  DEFAULT_SERVER_WAF_ENABLED,
  DEFAULT_SERVER_WAF_THRESHOLD,
  DEFAULT_SERVER_WORKERS,
  DEFAULT_SITE_WAF_ENABLED,
  DEFAULT_TARPIT_BASE_DELAY_MS,
  DEFAULT_TARPIT_CLEANUP_THRESHOLD_MS,
  DEFAULT_TARPIT_DECAY_THRESHOLD_MS,
  DEFAULT_TARPIT_ENABLED,
  DEFAULT_TARPIT_MAX_CONCURRENT,
  DEFAULT_TARPIT_MAX_DELAY_MS,
  DEFAULT_TARPIT_MAX_STATES,
  DEFAULT_TARPIT_PROGRESSIVE_MULTIPLIER,
  DEFAULT_TLS_MIN_VERSION,
  DEFAULT_TRAVEL_HISTORY_WINDOW_MS,
  DEFAULT_TRAVEL_MAX_HISTORY_PER_USER,
  DEFAULT_TRAVEL_MAX_SPEED_KMH,
  DEFAULT_TRAVEL_MIN_DISTANCE_KM,
  DEFAULT_UPSTREAM_WEIGHT,
} from './sensorConfigDefaults';

export const ServerConfigSchema = z.object({
  http_addr: z.string().max(255).regex(/^([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])?:\d+$/).default(DEFAULT_SERVER_HTTP_ADDR),
  https_addr: z.string().max(255).regex(/^([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])?:\d+$/).default(DEFAULT_SERVER_HTTPS_ADDR),
  workers: z.number().int().min(0).max(1024).default(DEFAULT_SERVER_WORKERS),
  shutdown_timeout_secs: z.number().int().min(1).max(3600).default(DEFAULT_SERVER_SHUTDOWN_TIMEOUT_SECS),
  waf_threshold: z.number().min(0).max(100).default(DEFAULT_SERVER_WAF_THRESHOLD),
  waf_enabled: z.boolean().default(DEFAULT_SERVER_WAF_ENABLED),
  log_level: z.enum(["trace", "debug", "info", "warn", "error", "fatal"]).default(DEFAULT_SERVER_LOG_LEVEL),
});

export const UpstreamConfigSchema = z.object({
  host: z.string().max(255),
  port: z.number().int().min(1).max(65535),
  weight: z.number().int().min(1).max(1000).default(DEFAULT_UPSTREAM_WEIGHT),
});

export const TlsConfigSchema = z.object({
  cert_path: z.string().max(1024).refine(p => !p.includes('..'), "Path traversal detected"),
  key_path: z.string().max(1024).refine(p => !p.includes('..'), "Path traversal detected"),
  min_version: z.enum(["1.2", "1.3"]).default(DEFAULT_TLS_MIN_VERSION),
});

export const AccessControlConfigSchema = z.object({
  allow: z.array(z.string().max(255)).max(1000).default([]),
  deny: z.array(z.string().max(255)).max(1000).default([]),
  default_action: z.enum(["allow", "deny"]).default(DEFAULT_ACCESS_CONTROL_ACTION),
});

export const SiteWafConfigSchema = z.object({
  enabled: z.boolean().default(DEFAULT_SITE_WAF_ENABLED),
  threshold: z.number().min(0).max(100).optional(),
  rule_overrides: z.record(z.string().max(100), z.string().max(50)).default({}),
});

export const RateLimitConfigSchema = z.object({
  rps: z.number().int().min(1).max(1000000).default(DEFAULT_RATE_LIMIT_RPS),
  enabled: z.boolean().default(DEFAULT_RATE_LIMIT_ENABLED),
  burst: z.number().int().min(1).max(2000000).optional(),
});

export const SiteConfigSchema = z.object({
  hostname: z.string().max(255),
  upstreams: z.array(UpstreamConfigSchema).min(1).max(100),
  tls: TlsConfigSchema.optional(),
  waf: SiteWafConfigSchema.optional(),
  rate_limit: RateLimitConfigSchema.optional(),
  access_control: AccessControlConfigSchema.optional(),
});

export const ProfilerConfigSchema = z.object({
  enabled: z.boolean().default(DEFAULT_PROFILER_ENABLED),
  max_profiles: z.number().int().min(1).max(100000).default(DEFAULT_PROFILER_MAX_PROFILES),
  max_schemas: z.number().int().min(1).max(10000).default(DEFAULT_PROFILER_MAX_SCHEMAS),
  min_samples_for_validation: z.number().int().min(1).max(10000).default(DEFAULT_PROFILER_MIN_SAMPLES),
  payload_z_threshold: z.number().min(0.1).max(20.0).default(DEFAULT_PROFILER_PAYLOAD_Z),
  param_z_threshold: z.number().min(0.1).max(20.0).default(DEFAULT_PROFILER_PARAM_Z),
  response_z_threshold: z.number().min(0.1).max(20.0).default(DEFAULT_PROFILER_RESPONSE_Z),
  min_stddev: z.number().min(0.0001).max(1.0).default(DEFAULT_PROFILER_MIN_STDDEV),
  type_ratio_threshold: z.number().min(0.1).max(1.0).default(DEFAULT_PROFILER_TYPE_RATIO),
  max_type_counts: z.number().int().min(1).max(1000).default(DEFAULT_PROFILER_MAX_TYPE_COUNTS),
  redact_pii: z.boolean().default(DEFAULT_PROFILER_REDACT_PII),
  freeze_after_samples: z.number().int().min(0).max(1000000).default(DEFAULT_PROFILER_FREEZE_AFTER_SAMPLES),
});

// =============================================================================
// DLP (Data Loss Prevention) Configuration
// =============================================================================
export const DlpConfigSchema = z.object({
  enabled: z.boolean().default(DEFAULT_DLP_ENABLED),
  fast_mode: z.boolean().default(DEFAULT_DLP_FAST_MODE),
  scan_text_only: z.boolean().default(DEFAULT_DLP_SCAN_TEXT_ONLY),
  max_scan_size: z.number().int().min(1).max(100 * 1024 * 1024).default(DEFAULT_DLP_MAX_SCAN_SIZE_BYTES),
  max_body_inspection_bytes: z.number().int().min(1).max(10 * 1024 * 1024).default(DEFAULT_DLP_MAX_BODY_INSPECTION_BYTES),
  max_matches: z.number().int().min(1).max(10000).default(DEFAULT_DLP_MAX_MATCHES),
  custom_keywords: z.array(z.string().max(255)).max(1000).default([]),
  redaction: z.record(z.string().max(100), z.enum(["mask", "hash", "full"])).default({}),
});

// =============================================================================
// Block Page Configuration
// =============================================================================
export const BlockPageConfigSchema = z.object({
  company_name: z.string().max(255).optional(),
  support_email: z.string().max(255).email().optional(),
  logo_url: z.string().max(2048).url().optional(),
  custom_template: z.string().max(100000).optional(),
  custom_css: z.string().max(100000).optional(),
  show_request_id: z.boolean().default(DEFAULT_BLOCK_PAGE_SHOW_REQUEST_ID),
  show_timestamp: z.boolean().default(DEFAULT_BLOCK_PAGE_SHOW_TIMESTAMP),
  show_client_ip: z.boolean().default(DEFAULT_BLOCK_PAGE_SHOW_CLIENT_IP),
  show_rule_id: z.boolean().default(DEFAULT_BLOCK_PAGE_SHOW_RULE_ID),
});

// =============================================================================
// Crawler/Bot Detection Configuration
// =============================================================================
export const CrawlerConfigSchema = z.object({
  enabled: z.boolean().default(DEFAULT_CRAWLER_ENABLED),
  verify_legitimate_crawlers: z.boolean().default(DEFAULT_CRAWLER_VERIFY_LEGIT),
  block_bad_bots: z.boolean().default(DEFAULT_CRAWLER_BLOCK_BAD_BOTS),
  dns_failure_policy: z.enum(["allow", "apply_risk_penalty", "block"]).default(DEFAULT_CRAWLER_DNS_FAILURE_POLICY),
  dns_cache_ttl_secs: z.number().int().min(1).max(86400).default(DEFAULT_CRAWLER_DNS_CACHE_TTL_SECS),
  verification_cache_ttl_secs: z.number().int().min(1).max(604800).default(DEFAULT_CRAWLER_VERIFICATION_CACHE_TTL_SECS),
  max_cache_entries: z.number().int().min(1).max(1000000).default(DEFAULT_CRAWLER_MAX_CACHE_ENTRIES),
  dns_timeout_ms: z.number().int().min(1).max(30000).default(DEFAULT_CRAWLER_DNS_TIMEOUT_MS),
  max_concurrent_dns_lookups: z.number().int().min(1).max(10000).default(DEFAULT_CRAWLER_MAX_CONCURRENT_DNS_LOOKUPS),
  dns_failure_risk_penalty: z.number().int().min(0).max(100).default(DEFAULT_CRAWLER_DNS_FAILURE_RISK_PENALTY),
});

// =============================================================================
// Tarpit Configuration
// =============================================================================
export const TarpitConfigSchema = z.object({
  enabled: z.boolean().default(DEFAULT_TARPIT_ENABLED),
  base_delay_ms: z.number().int().min(0).max(60000).default(DEFAULT_TARPIT_BASE_DELAY_MS),
  max_delay_ms: z.number().int().min(0).max(300000).default(DEFAULT_TARPIT_MAX_DELAY_MS),
  progressive_multiplier: z.number().min(1.0).max(10.0).default(DEFAULT_TARPIT_PROGRESSIVE_MULTIPLIER),
  max_states: z.number().int().min(1).max(1000000).default(DEFAULT_TARPIT_MAX_STATES),
  decay_threshold_ms: z.number().int().min(1000).max(3600000).default(DEFAULT_TARPIT_DECAY_THRESHOLD_MS),
  cleanup_threshold_ms: z.number().int().min(1000).max(86400000).default(DEFAULT_TARPIT_CLEANUP_THRESHOLD_MS),
  max_concurrent_tarpits: z.number().int().min(1).max(100000).default(DEFAULT_TARPIT_MAX_CONCURRENT),
});

// =============================================================================
// Impossible Travel Configuration
// =============================================================================
export const TravelConfigSchema = z.object({
  max_speed_kmh: z.number().min(1).max(40000).default(DEFAULT_TRAVEL_MAX_SPEED_KMH),
  min_distance_km: z.number().min(0).max(20000).default(DEFAULT_TRAVEL_MIN_DISTANCE_KM),
  history_window_ms: z.number().int().min(1000).max(30 * 24 * 60 * 60 * 1000).default(DEFAULT_TRAVEL_HISTORY_WINDOW_MS),
  max_history_per_user: z.number().int().min(1).max(10000).default(DEFAULT_TRAVEL_MAX_HISTORY_PER_USER),
});

// =============================================================================
// Entity Store Configuration
// =============================================================================
export const EntityConfigSchema = z.object({
  enabled: z.boolean().default(DEFAULT_ENTITY_ENABLED),
  max_entities: z.number().int().min(1).max(10000000).default(DEFAULT_ENTITY_MAX_ENTITIES),
  risk_decay_per_minute: z.number().min(0).max(100).default(DEFAULT_ENTITY_RISK_DECAY_PER_MINUTE),
  block_threshold: z.number().min(0).max(100).default(DEFAULT_ENTITY_BLOCK_THRESHOLD),
  max_rules_per_entity: z.number().int().min(1).max(1000).default(DEFAULT_ENTITY_MAX_RULES_PER_ENTITY),
  max_risk: z.number().min(0).max(1000).default(DEFAULT_ENTITY_MAX_RISK),
  max_anomalies_per_entity: z.number().int().min(1).max(1000).default(DEFAULT_ENTITY_MAX_ANOMALIES),
});

export const SensorConfigSchema = z.object({
  server: ServerConfigSchema.default({}),
  sites: z.array(SiteConfigSchema).default([]),
  rate_limit: RateLimitConfigSchema.default({ rps: DEFAULT_RATE_LIMIT_RPS, enabled: DEFAULT_RATE_LIMIT_ENABLED }),
  profiler: ProfilerConfigSchema.default({}),
  // Advanced features
  dlp: DlpConfigSchema.default({}),
  block_page: BlockPageConfigSchema.default({}),
  crawler: CrawlerConfigSchema.default({}),
  tarpit: TarpitConfigSchema.default({}),
  travel: TravelConfigSchema.default({}),
  entity: EntityConfigSchema.default({}),
});

export type SensorConfig = z.infer<typeof SensorConfigSchema>;
export type DlpConfig = z.infer<typeof DlpConfigSchema>;
export type BlockPageConfig = z.infer<typeof BlockPageConfigSchema>;
export type CrawlerConfig = z.infer<typeof CrawlerConfigSchema>;
export type TarpitConfig = z.infer<typeof TarpitConfigSchema>;
export type TravelConfig = z.infer<typeof TravelConfigSchema>;
export type EntityConfig = z.infer<typeof EntityConfigSchema>;
