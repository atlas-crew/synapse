/**
 * Shared configuration types for Signal Horizon.
 *
 * These types define the contract between the API and UI for sensor configuration.
 * Both packages should import from this file to ensure type consistency.
 *
 * Note: The API uses Zod schemas that mirror these types for runtime validation.
 * The UI uses these types directly for type-safe form handling.
 */

// =============================================================================
// DLP (Data Loss Prevention) Configuration
// =============================================================================
export interface DlpConfig {
  enabled: boolean;
  fast_mode: boolean;
  scan_text_only: boolean;
  max_scan_size: number;
  max_body_inspection_bytes: number;
  max_matches: number;
  custom_keywords: string[];
  /** Optional redaction settings - API only, not exposed in UI */
  redaction?: Record<string, 'mask' | 'hash' | 'full'>;
}

// =============================================================================
// Block Page Configuration
// =============================================================================
export interface BlockPageConfig {
  company_name?: string;
  support_email?: string;
  logo_url?: string;
  custom_template?: string;
  custom_css?: string;
  show_request_id: boolean;
  show_timestamp: boolean;
  show_client_ip: boolean;
  show_rule_id: boolean;
}

// =============================================================================
// Crawler/Bot Detection Configuration
// =============================================================================
export type DnsFailurePolicy = 'allow' | 'apply_risk_penalty' | 'block';

export interface CrawlerConfig {
  enabled: boolean;
  verify_legitimate_crawlers: boolean;
  block_bad_bots: boolean;
  dns_failure_policy: DnsFailurePolicy;
  dns_cache_ttl_secs: number;
  verification_cache_ttl_secs?: number;
  max_cache_entries?: number;
  dns_timeout_ms: number;
  max_concurrent_dns_lookups: number;
  dns_failure_risk_penalty: number;
}

// =============================================================================
// Tarpit Configuration
// =============================================================================
export interface TarpitConfig {
  enabled: boolean;
  base_delay_ms: number;
  max_delay_ms: number;
  progressive_multiplier: number;
  max_states?: number;
  decay_threshold_ms: number;
  cleanup_threshold_ms?: number;
  max_concurrent_tarpits: number;
}

// =============================================================================
// Entity Store Configuration
// =============================================================================
export interface EntityConfig {
  enabled: boolean;
  max_entities: number;
  risk_decay_per_minute: number;
  block_threshold: number;
  max_rules_per_entity: number;
  max_risk: number;
  max_anomalies_per_entity?: number;
}

// =============================================================================
// Impossible Travel Configuration
// =============================================================================
export interface TravelConfig {
  max_speed_kmh: number;
  min_distance_km: number;
  history_window_ms: number;
  max_history_per_user: number;
}

// =============================================================================
// Rate Limit Configuration
// =============================================================================
export interface RateLimitConfig {
  enabled: boolean;
  /** Requests per second. UI uses 'requests_per_second', API uses 'rps' */
  rps?: number;
  requests_per_second?: number;
  burst?: number;
}

// =============================================================================
// WAF Configuration
// =============================================================================
export interface WafConfig {
  enabled: boolean;
  threshold?: number;
  rule_overrides?: Record<string, string>;
}

// =============================================================================
// Access Control Configuration
// =============================================================================
export type AccessControlAction = 'allow' | 'deny';

export interface AccessControlConfig {
  allow: string[];
  deny: string[];
  default_action: AccessControlAction;
}

// =============================================================================
// Server Configuration
// =============================================================================
export interface ServerConfig {
  http_addr: string;
  https_addr: string;
  workers: number;
  shutdown_timeout_secs: number;
  waf_threshold: number;
  waf_enabled: boolean;
  log_level: string;
}

// =============================================================================
// Upstream Configuration
// =============================================================================
export interface UpstreamConfig {
  host: string;
  port: number;
  weight: number;
}

// =============================================================================
// TLS Configuration
// =============================================================================
export interface TlsConfig {
  cert_path: string;
  key_path: string;
  min_version: string;
}

// =============================================================================
// Site Configuration
// =============================================================================
export interface SiteConfig {
  hostname: string;
  upstreams: UpstreamConfig[];
  tls?: TlsConfig;
  waf?: WafConfig;
  rate_limit?: RateLimitConfig;
  access_control?: AccessControlConfig;
}

// =============================================================================
// Profiler Configuration
// =============================================================================
export interface ProfilerConfig {
  enabled: boolean;
  max_profiles: number;
  max_schemas: number;
  min_samples_for_validation: number;
  payload_z_threshold: number;
  param_z_threshold: number;
  response_z_threshold: number;
  min_stddev: number;
  type_ratio_threshold: number;
  max_type_counts: number;
  redact_pii: boolean;
  freeze_after_samples: number;
}

// =============================================================================
// Complete Sensor Configuration
// =============================================================================
export interface SensorConfig {
  server: ServerConfig;
  sites: SiteConfig[];
  rate_limit: RateLimitConfig;
  profiler: ProfilerConfig;
  dlp: DlpConfig;
  block_page: BlockPageConfig;
  crawler: CrawlerConfig;
  tarpit: TarpitConfig;
  travel: TravelConfig;
  entity: EntityConfig;
}

// =============================================================================
// Partial types for form updates (UI convenience)
// =============================================================================
export type PartialDlpConfig = Partial<DlpConfig>;
export type PartialTarpitConfig = Partial<TarpitConfig>;
export type PartialEntityConfig = Partial<EntityConfig>;
export type PartialTravelConfig = Partial<TravelConfig>;
export type PartialCrawlerConfig = Partial<CrawlerConfig>;
export type PartialRateLimitConfig = Partial<RateLimitConfig>;
export type PartialBlockPageConfig = Partial<BlockPageConfig>;
