/**
 * Shared types for Signal Horizon.
 *
 * Import from this file to ensure consistent types between API and UI.
 *
 * @example
 * import { DlpConfig, TarpitConfig } from '@signal-horizon/shared/types';
 */

export type {
  // Config types
  DlpConfig,
  BlockPageConfig,
  CrawlerConfig,
  TarpitConfig,
  EntityConfig,
  TravelConfig,
  RateLimitConfig,
  WafConfig,
  AccessControlConfig,
  ServerConfig,
  UpstreamConfig,
  TlsConfig,
  SiteConfig,
  ProfilerConfig,
  SensorConfig,
  // Enum types
  DnsFailurePolicy,
  AccessControlAction,
  // Partial types for forms
  PartialDlpConfig,
  PartialTarpitConfig,
  PartialEntityConfig,
  PartialTravelConfig,
  PartialCrawlerConfig,
  PartialRateLimitConfig,
  PartialBlockPageConfig,
} from './config';
