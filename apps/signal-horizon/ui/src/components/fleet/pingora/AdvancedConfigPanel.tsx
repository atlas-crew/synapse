import { useState, useCallback } from 'react';
import { Settings, Eye, Bot, Hourglass, Users, FileWarning } from 'lucide-react';
import { DlpConfig, type DlpConfigData } from './DlpConfig';
import { BlockPageConfig, type BlockPageConfigData } from './BlockPageConfig';
import { CrawlerConfig, type CrawlerConfigData } from './CrawlerConfig';
import { TarpitConfig, type TarpitConfigData } from './TarpitConfig';
import { EntityConfig, type EntityConfigData, type TravelConfigData } from './EntityConfig';
import {
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
  DEFAULT_CRAWLER_MAX_CONCURRENT_DNS_LOOKUPS,
  DEFAULT_CRAWLER_VERIFY_LEGIT,
  DEFAULT_DLP_ENABLED,
  DEFAULT_DLP_FAST_MODE,
  DEFAULT_DLP_MAX_BODY_INSPECTION_BYTES,
  DEFAULT_DLP_MAX_MATCHES,
  DEFAULT_DLP_MAX_SCAN_SIZE_BYTES,
  DEFAULT_DLP_SCAN_TEXT_ONLY,
  DEFAULT_ENTITY_BLOCK_THRESHOLD,
  DEFAULT_ENTITY_ENABLED,
  DEFAULT_ENTITY_MAX_ENTITIES,
  DEFAULT_ENTITY_MAX_RISK,
  DEFAULT_ENTITY_MAX_RULES_PER_ENTITY,
  DEFAULT_ENTITY_RISK_DECAY_PER_MINUTE,
  DEFAULT_TARPIT_BASE_DELAY_MS,
  DEFAULT_TARPIT_DECAY_THRESHOLD_MS,
  DEFAULT_TARPIT_ENABLED,
  DEFAULT_TARPIT_MAX_CONCURRENT,
  DEFAULT_TARPIT_MAX_DELAY_MS,
  DEFAULT_TARPIT_PROGRESSIVE_MULTIPLIER,
  DEFAULT_TRAVEL_HISTORY_WINDOW_MS,
  DEFAULT_TRAVEL_MAX_HISTORY_PER_USER,
  DEFAULT_TRAVEL_MAX_SPEED_KMH,
  DEFAULT_TRAVEL_MIN_DISTANCE_KM,
} from './configDefaults';

export interface AdvancedConfigData {
  dlp: DlpConfigData;
  block_page: BlockPageConfigData;
  crawler: CrawlerConfigData;
  tarpit: TarpitConfigData;
  entity: EntityConfigData;
  travel: TravelConfigData;
}

interface AdvancedConfigPanelProps {
  config: AdvancedConfigData;
  onChange: (config: AdvancedConfigData) => void;
}

type TabId = 'dlp' | 'block_page' | 'crawler' | 'tarpit' | 'entity';

const tabs: { id: TabId; label: string; icon: React.ElementType; description: string }[] = [
  { id: 'dlp', label: 'DLP', icon: Eye, description: 'Data Loss Prevention' },
  { id: 'block_page', label: 'Block Page', icon: FileWarning, description: 'Branding & Display' },
  { id: 'crawler', label: 'Crawler/Bots', icon: Bot, description: 'Bot Detection' },
  { id: 'tarpit', label: 'Tarpit', icon: Hourglass, description: 'Slow-Drip Defense' },
  { id: 'entity', label: 'Entity & Travel', icon: Users, description: 'Risk Tracking' },
];

export function AdvancedConfigPanel({ config, onChange }: AdvancedConfigPanelProps) {
  const [activeTab, setActiveTab] = useState<TabId>('dlp');

  const handleDlpChange = useCallback((dlp: DlpConfigData) => onChange({ ...config, dlp }), [config, onChange]);
  const handleBlockPageChange = useCallback((block_page: BlockPageConfigData) => onChange({ ...config, block_page }), [config, onChange]);
  const handleCrawlerChange = useCallback((crawler: CrawlerConfigData) => onChange({ ...config, crawler }), [config, onChange]);
  const handleTarpitChange = useCallback((tarpit: TarpitConfigData) => onChange({ ...config, tarpit }), [config, onChange]);
  const handleEntityChange = useCallback((entity: EntityConfigData) => onChange({ ...config, entity }), [config, onChange]);
  const handleTravelChange = useCallback((travel: TravelConfigData) => onChange({ ...config, travel }), [config, onChange]);

  return (
    <div className="flex h-full">
      {/* Sidebar */}
      <div className="w-56 border-r border-border-subtle bg-surface-subtle/50 flex-shrink-0">
        <div className="p-4 border-b border-border-subtle">
          <div className="flex items-center gap-2">
            <Settings className="w-4 h-4 text-ac-blue" />
            <h2 className="text-sm font-semibold text-ink-primary">Advanced Config</h2>
          </div>
        </div>
        <nav className="p-2">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-colors ${
                  isActive
                    ? 'bg-ac-blue/10 text-ac-blue'
                    : 'text-ink-secondary hover:bg-surface-subtle hover:text-ink-primary'
                }`}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                <div className="min-w-0">
                  <div className="text-sm font-medium truncate">{tab.label}</div>
                  <div className="text-xs opacity-70 truncate">{tab.description}</div>
                </div>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-2xl">
          {activeTab === 'dlp' && (
            <DlpConfig config={config.dlp} onChange={handleDlpChange} />
          )}
          {activeTab === 'block_page' && (
            <BlockPageConfig config={config.block_page} onChange={handleBlockPageChange} />
          )}
          {activeTab === 'crawler' && (
            <CrawlerConfig config={config.crawler} onChange={handleCrawlerChange} />
          )}
          {activeTab === 'tarpit' && (
            <TarpitConfig config={config.tarpit} onChange={handleTarpitChange} />
          )}
          {activeTab === 'entity' && (
            <EntityConfig
              entityConfig={config.entity}
              travelConfig={config.travel}
              onEntityChange={handleEntityChange}
              onTravelChange={handleTravelChange}
            />
          )}
        </div>
      </div>
    </div>
  );
}

// Default config values
export const defaultAdvancedConfig: AdvancedConfigData = {
  dlp: {
    enabled: DEFAULT_DLP_ENABLED,
    fast_mode: DEFAULT_DLP_FAST_MODE,
    scan_text_only: DEFAULT_DLP_SCAN_TEXT_ONLY,
    max_scan_size: DEFAULT_DLP_MAX_SCAN_SIZE_BYTES,
    max_body_inspection_bytes: DEFAULT_DLP_MAX_BODY_INSPECTION_BYTES,
    max_matches: DEFAULT_DLP_MAX_MATCHES,
    custom_keywords: [],
  },
  block_page: {
    show_request_id: DEFAULT_BLOCK_PAGE_SHOW_REQUEST_ID,
    show_timestamp: DEFAULT_BLOCK_PAGE_SHOW_TIMESTAMP,
    show_client_ip: DEFAULT_BLOCK_PAGE_SHOW_CLIENT_IP,
    show_rule_id: DEFAULT_BLOCK_PAGE_SHOW_RULE_ID,
  },
  crawler: {
    enabled: DEFAULT_CRAWLER_ENABLED,
    verify_legitimate_crawlers: DEFAULT_CRAWLER_VERIFY_LEGIT,
    block_bad_bots: DEFAULT_CRAWLER_BLOCK_BAD_BOTS,
    dns_failure_policy: DEFAULT_CRAWLER_DNS_FAILURE_POLICY,
    dns_cache_ttl_secs: DEFAULT_CRAWLER_DNS_CACHE_TTL_SECS,
    dns_timeout_ms: DEFAULT_CRAWLER_DNS_TIMEOUT_MS,
    max_concurrent_dns_lookups: DEFAULT_CRAWLER_MAX_CONCURRENT_DNS_LOOKUPS,
    dns_failure_risk_penalty: DEFAULT_CRAWLER_DNS_FAILURE_RISK_PENALTY,
  },
  tarpit: {
    enabled: DEFAULT_TARPIT_ENABLED,
    base_delay_ms: DEFAULT_TARPIT_BASE_DELAY_MS,
    max_delay_ms: DEFAULT_TARPIT_MAX_DELAY_MS,
    progressive_multiplier: DEFAULT_TARPIT_PROGRESSIVE_MULTIPLIER,
    max_concurrent_tarpits: DEFAULT_TARPIT_MAX_CONCURRENT,
    decay_threshold_ms: DEFAULT_TARPIT_DECAY_THRESHOLD_MS,
  },
  entity: {
    enabled: DEFAULT_ENTITY_ENABLED,
    max_entities: DEFAULT_ENTITY_MAX_ENTITIES,
    risk_decay_per_minute: DEFAULT_ENTITY_RISK_DECAY_PER_MINUTE,
    block_threshold: DEFAULT_ENTITY_BLOCK_THRESHOLD,
    max_risk: DEFAULT_ENTITY_MAX_RISK,
    max_rules_per_entity: DEFAULT_ENTITY_MAX_RULES_PER_ENTITY,
  },
  travel: {
    max_speed_kmh: DEFAULT_TRAVEL_MAX_SPEED_KMH,
    min_distance_km: DEFAULT_TRAVEL_MIN_DISTANCE_KM,
    history_window_ms: DEFAULT_TRAVEL_HISTORY_WINDOW_MS,
    max_history_per_user: DEFAULT_TRAVEL_MAX_HISTORY_PER_USER,
  },
};
