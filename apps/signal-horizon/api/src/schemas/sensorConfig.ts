import { z } from 'zod';

export const ServerConfigSchema = z.object({
  http_addr: z.string().default("0.0.0.0:80"),
  https_addr: z.string().default("0.0.0.0:443"),
  workers: z.number().default(0),
  shutdown_timeout_secs: z.number().default(30),
  waf_threshold: z.number().min(0).max(100).default(70),
  waf_enabled: z.boolean().default(true),
  log_level: z.string().default("info"),
});

export const UpstreamConfigSchema = z.object({
  host: z.string(),
  port: z.number(),
  weight: z.number().default(1),
});

export const TlsConfigSchema = z.object({
  cert_path: z.string(),
  key_path: z.string(),
  min_version: z.string().default("1.2"),
});

export const AccessControlConfigSchema = z.object({
  allow: z.array(z.string()).default([]),
  deny: z.array(z.string()).default([]),
  default_action: z.enum(["allow", "deny"]).default("allow"),
});

export const SiteWafConfigSchema = z.object({
  enabled: z.boolean().default(true),
  threshold: z.number().min(0).max(100).optional(),
  rule_overrides: z.record(z.string()).default({}),
});

export const RateLimitConfigSchema = z.object({
  rps: z.number(),
  enabled: z.boolean().default(true),
  burst: z.number().optional(),
});

export const SiteConfigSchema = z.object({
  hostname: z.string(),
  upstreams: z.array(UpstreamConfigSchema),
  tls: TlsConfigSchema.optional(),
  waf: SiteWafConfigSchema.optional(),
  rate_limit: RateLimitConfigSchema.optional(),
  access_control: AccessControlConfigSchema.optional(),
});

export const ProfilerConfigSchema = z.object({
  enabled: z.boolean().default(true),
  max_profiles: z.number().default(1000),
  max_schemas: z.number().default(500),
  min_samples_for_validation: z.number().default(100),
  payload_z_threshold: z.number().default(3.0),
  param_z_threshold: z.number().default(4.0),
  response_z_threshold: z.number().default(4.0),
  min_stddev: z.number().default(0.01),
  type_ratio_threshold: z.number().default(0.9),
  max_type_counts: z.number().default(10),
  redact_pii: z.boolean().default(true),
  freeze_after_samples: z.number().default(0),
});

// =============================================================================
// DLP (Data Loss Prevention) Configuration
// =============================================================================
export const DlpConfigSchema = z.object({
  enabled: z.boolean().default(true),
  fast_mode: z.boolean().default(false),
  scan_text_only: z.boolean().default(true),
  max_scan_size: z.number().default(5 * 1024 * 1024), // 5MB
  max_body_inspection_bytes: z.number().default(8 * 1024), // 8KB
  max_matches: z.number().default(100),
  custom_keywords: z.array(z.string()).default([]),
  redaction: z.record(z.enum(["mask", "hash", "full"])).default({}),
});

// =============================================================================
// Block Page Configuration
// =============================================================================
export const BlockPageConfigSchema = z.object({
  company_name: z.string().optional(),
  support_email: z.string().email().optional(),
  logo_url: z.string().url().optional(),
  custom_template: z.string().optional(),
  custom_css: z.string().optional(),
  show_request_id: z.boolean().default(true),
  show_timestamp: z.boolean().default(true),
  show_client_ip: z.boolean().default(false),
  show_rule_id: z.boolean().default(false),
});

// =============================================================================
// Crawler/Bot Detection Configuration
// =============================================================================
export const CrawlerConfigSchema = z.object({
  enabled: z.boolean().default(true),
  verify_legitimate_crawlers: z.boolean().default(true),
  block_bad_bots: z.boolean().default(true),
  dns_failure_policy: z.enum(["allow", "apply_risk_penalty", "block"]).default("apply_risk_penalty"),
  dns_cache_ttl_secs: z.number().default(300),
  verification_cache_ttl_secs: z.number().default(3600),
  max_cache_entries: z.number().default(50000),
  dns_timeout_ms: z.number().default(2000),
  max_concurrent_dns_lookups: z.number().default(100),
  dns_failure_risk_penalty: z.number().default(20),
});

// =============================================================================
// Tarpit Configuration
// =============================================================================
export const TarpitConfigSchema = z.object({
  enabled: z.boolean().default(true),
  base_delay_ms: z.number().default(1000),
  max_delay_ms: z.number().default(30000),
  progressive_multiplier: z.number().default(1.5),
  max_states: z.number().default(10000),
  decay_threshold_ms: z.number().default(5 * 60 * 1000), // 5 minutes
  cleanup_threshold_ms: z.number().default(30 * 60 * 1000), // 30 minutes
  max_concurrent_tarpits: z.number().default(1000),
});

// =============================================================================
// Impossible Travel Configuration
// =============================================================================
export const TravelConfigSchema = z.object({
  max_speed_kmh: z.number().default(800),
  min_distance_km: z.number().default(100),
  history_window_ms: z.number().default(24 * 60 * 60 * 1000), // 24 hours
  max_history_per_user: z.number().default(100),
});

// =============================================================================
// Entity Store Configuration
// =============================================================================
export const EntityConfigSchema = z.object({
  enabled: z.boolean().default(true),
  max_entities: z.number().default(100000),
  risk_decay_per_minute: z.number().default(10),
  block_threshold: z.number().default(70),
  max_rules_per_entity: z.number().default(50),
  max_risk: z.number().default(100),
  max_anomalies_per_entity: z.number().default(100),
});

export const SensorConfigSchema = z.object({
  server: ServerConfigSchema.default({}),
  sites: z.array(SiteConfigSchema).default([]),
  rate_limit: RateLimitConfigSchema.default({ rps: 10000, enabled: true }),
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
