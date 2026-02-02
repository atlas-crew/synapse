import { useState } from 'react';
import { Settings, Eye, Bot, Hourglass, Users, FileWarning } from 'lucide-react';
import { DlpConfig, type DlpConfigData } from './DlpConfig';
import { BlockPageConfig, type BlockPageConfigData } from './BlockPageConfig';
import { CrawlerConfig, type CrawlerConfigData } from './CrawlerConfig';
import { TarpitConfig, type TarpitConfigData } from './TarpitConfig';
import { EntityConfig, type EntityConfigData, type TravelConfigData } from './EntityConfig';

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

  const handleDlpChange = (dlp: DlpConfigData) => onChange({ ...config, dlp });
  const handleBlockPageChange = (block_page: BlockPageConfigData) => onChange({ ...config, block_page });
  const handleCrawlerChange = (crawler: CrawlerConfigData) => onChange({ ...config, crawler });
  const handleTarpitChange = (tarpit: TarpitConfigData) => onChange({ ...config, tarpit });
  const handleEntityChange = (entity: EntityConfigData) => onChange({ ...config, entity });
  const handleTravelChange = (travel: TravelConfigData) => onChange({ ...config, travel });

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
    enabled: true,
    fast_mode: false,
    scan_text_only: true,
    max_scan_size: 5 * 1024 * 1024,
    max_body_inspection_bytes: 8 * 1024,
    max_matches: 100,
    custom_keywords: [],
  },
  block_page: {
    show_request_id: true,
    show_timestamp: true,
    show_client_ip: false,
    show_rule_id: false,
  },
  crawler: {
    enabled: true,
    verify_legitimate_crawlers: true,
    block_bad_bots: true,
    dns_failure_policy: 'apply_risk_penalty',
    dns_cache_ttl_secs: 300,
    dns_timeout_ms: 2000,
    max_concurrent_dns_lookups: 100,
    dns_failure_risk_penalty: 20,
  },
  tarpit: {
    enabled: true,
    base_delay_ms: 1000,
    max_delay_ms: 30000,
    progressive_multiplier: 1.5,
    max_concurrent_tarpits: 1000,
    decay_threshold_ms: 5 * 60 * 1000,
  },
  entity: {
    enabled: true,
    max_entities: 100000,
    risk_decay_per_minute: 10,
    block_threshold: 70,
    max_risk: 100,
    max_rules_per_entity: 50,
  },
  travel: {
    max_speed_kmh: 800,
    min_distance_km: 100,
    history_window_ms: 24 * 60 * 60 * 1000,
    max_history_per_user: 100,
  },
};
