/**
 * SynapseConfigEditor - Visual and YAML editor for Synapse sensor configuration
 *
 * Covers all synapse-pingora configuration options from docs/configuration/REFERENCE.md
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Code, Settings, Plus, Trash2, ChevronDown, ChevronRight } from 'lucide-react';
import { CodeEditor } from '../ctrlx/CodeEditor';
import YAML from 'yaml';

// Complete config structure matching synapse-pingora
export interface SynapseConfig {
  server: {
    listen: string;
    admin_listen: string;
    workers: number;
    admin_api_key?: string;
    trusted_proxies?: string[];
  };
  upstreams: Array<{ host: string; port: number; weight?: number }>;
  rate_limit: {
    enabled: boolean;
    rps: number;
    per_ip_rps: number;
    burst?: number;
  };
  logging: {
    level: string;
    format: string;
    access_log: boolean;
  };
  detection: {
    sqli: boolean;
    xss: boolean;
    path_traversal: boolean;
    command_injection: boolean;
    action: string;
    block_status: number;
    rules_path?: string;
    risk_server_url?: string;
    anomaly_blocking?: {
      enabled: boolean;
      threshold: number;
    };
  };
  tls: {
    enabled: boolean;
    min_version: string;
    cert_path?: string;
    key_path?: string;
    per_domain_certs?: Array<{ domain: string; cert_path: string; key_path: string }>;
  };
  telemetry: {
    enabled: boolean;
    endpoint?: string;
    api_key?: string;
    batch_size?: number;
    flush_interval_secs?: number;
    max_retries?: number;
    instance_id?: string;
    dry_run?: boolean;
  };
  tarpit: {
    enabled: boolean;
    base_delay_ms: number;
    max_delay_ms: number;
    progressive_multiplier?: number;
    max_states?: number;
    max_concurrent_tarpits?: number;
  };
  dlp: {
    enabled: boolean;
    max_scan_size: number;
    max_matches?: number;
    scan_text_only?: boolean;
    fast_mode?: boolean;
    custom_keywords?: string[];
  };
  crawler: {
    enabled: boolean;
    verify_legitimate_crawlers?: boolean;
    block_bad_bots?: boolean;
    dns_cache_ttl_secs?: number;
    dns_timeout_ms?: number;
  };
  horizon: {
    enabled: boolean;
    hub_url?: string;
    api_key?: string;
    sensor_id?: string;
    sensor_name?: string;
    heartbeat_interval_ms?: number;
    signal_batch_size?: number;
  };
  payload?: {
    enabled: boolean;
    max_endpoints?: number;
    oversize_threshold?: number;
  };
  trends?: {
    enabled: boolean;
    bucket_size_ms?: number;
    retention_hours?: number;
  };
}

const defaultConfig: SynapseConfig = {
  server: {
    listen: '0.0.0.0:6190',
    admin_listen: '0.0.0.0:6191',
    workers: 0,
  },
  upstreams: [{ host: '127.0.0.1', port: 8080 }],
  rate_limit: {
    enabled: true,
    rps: 10000,
    per_ip_rps: 100,
  },
  logging: {
    level: 'info',
    format: 'json',
    access_log: true,
  },
  detection: {
    sqli: true,
    xss: true,
    path_traversal: true,
    command_injection: true,
    action: 'block',
    block_status: 403,
  },
  tls: {
    enabled: false,
    min_version: '1.2',
  },
  telemetry: {
    enabled: false,
  },
  tarpit: {
    enabled: true,
    base_delay_ms: 1000,
    max_delay_ms: 30000,
  },
  dlp: {
    enabled: true,
    max_scan_size: 5242880,
  },
  crawler: {
    enabled: true,
    verify_legitimate_crawlers: true,
    block_bad_bots: true,
  },
  horizon: {
    enabled: false,
  },
};

interface Props {
  value: string;
  onChange: (yaml: string) => void;
}

interface SectionProps {
  title: string;
  description?: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}

function Section({ title, description, children, defaultOpen = true }: SectionProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  return (
    <div className="border border-border-subtle rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-3 bg-surface-subtle hover:bg-surface-elevated transition-colors"
      >
        <div className="text-left">
          <span className="font-medium text-ink-primary">{title}</span>
          {description && <p className="text-xs text-ink-muted mt-0.5">{description}</p>}
        </div>
        {isOpen ? (
          <ChevronDown className="w-4 h-4 text-ink-muted flex-shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 text-ink-muted flex-shrink-0" />
        )}
      </button>
      {isOpen && <div className="p-4 space-y-4 bg-surface-base">{children}</div>}
    </div>
  );
}

function Toggle({ label, description, checked, onChange }: {
  label: string;
  description?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-start gap-3 cursor-pointer">
      <div
        className={`relative w-10 h-6 rounded-full transition-colors flex-shrink-0 mt-0.5 ${
          checked ? 'bg-ac-blue' : 'bg-surface-elevated'
        }`}
        onClick={() => onChange(!checked)}
      >
        <div
          className={`absolute top-1 w-4 h-4 rounded-full bg-white shadow transition-transform ${
            checked ? 'translate-x-5' : 'translate-x-1'
          }`}
        />
      </div>
      <div>
        <span className="text-sm text-ink-primary">{label}</span>
        {description && <p className="text-xs text-ink-muted mt-0.5">{description}</p>}
      </div>
    </label>
  );
}

function Input({ label, description, value, onChange, type = 'text', placeholder }: {
  label: string;
  description?: string;
  value: string | number;
  onChange: (v: string) => void;
  type?: string;
  placeholder?: string;
}) {
  return (
    <div>
      <label className="block text-sm text-ink-secondary mb-1">{label}</label>
      {description && <p className="text-xs text-ink-muted mb-1">{description}</p>}
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full px-3 py-2 bg-surface-elevated border border-border-subtle rounded text-ink-primary text-sm focus:outline-none focus:ring-1 focus:ring-ac-blue"
      />
    </div>
  );
}

function Select({ label, description, value, onChange, options }: {
  label: string;
  description?: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <div>
      <label className="block text-sm text-ink-secondary mb-1">{label}</label>
      {description && <p className="text-xs text-ink-muted mb-1">{description}</p>}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-3 py-2 bg-surface-elevated border border-border-subtle rounded text-ink-primary text-sm focus:outline-none focus:ring-1 focus:ring-ac-blue"
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>{opt.label}</option>
        ))}
      </select>
    </div>
  );
}

export function SynapseConfigEditor({ value, onChange }: Props) {
  const [mode, setMode] = useState<'visual' | 'yaml'>('visual');
  const [config, setConfig] = useState<SynapseConfig>(defaultConfig);
  const [yamlError, setYamlError] = useState<string | null>(null);

  // Parse YAML to config on mount
  useEffect(() => {
    try {
      const parsed = YAML.parse(value);
      if (parsed && typeof parsed === 'object') {
        setConfig(deepMerge(defaultConfig, parsed));
        setYamlError(null);
      }
    } catch {
      // Keep current config if YAML is invalid
    }
  }, []);

  // Deep merge helper
  function deepMerge<T extends Record<string, unknown>>(target: T, source: Partial<T>): T {
    const result = { ...target };
    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = deepMerge(
          (target[key] || {}) as Record<string, unknown>,
          source[key] as Record<string, unknown>
        ) as T[Extract<keyof T, string>];
      } else if (source[key] !== undefined) {
        result[key] = source[key] as T[Extract<keyof T, string>];
      }
    }
    return result;
  }

  // Update YAML when config changes in visual mode
  const updateConfigAndYaml = useCallback((newConfig: SynapseConfig) => {
    setConfig(newConfig);
    // Clean up undefined/empty optional values for cleaner YAML
    const cleanConfig = JSON.parse(JSON.stringify(newConfig, (_, v) => v === undefined ? undefined : v));
    const yaml = YAML.stringify(cleanConfig, { indent: 2 });
    onChange(yaml);
  }, [onChange]);

  // Handle YAML text changes
  const handleYamlChange = useCallback((yaml: string) => {
    onChange(yaml);
    try {
      const parsed = YAML.parse(yaml);
      if (parsed && typeof parsed === 'object') {
        setConfig(deepMerge(defaultConfig, parsed));
        setYamlError(null);
      }
    } catch (e) {
      setYamlError(e instanceof Error ? e.message : 'Invalid YAML');
    }
  }, [onChange]);

  // Helper to update nested config
  const updateSection = <K extends keyof SynapseConfig>(
    section: K,
    updates: Partial<SynapseConfig[K]>
  ) => {
    const newConfig = {
      ...config,
      [section]: {
        ...config[section],
        ...updates,
      },
    };
    updateConfigAndYaml(newConfig);
  };

  return (
    <div className="flex flex-col h-full">
      {/* Mode Toggle */}
      <div className="flex items-center gap-2 mb-4">
        <button
          type="button"
          onClick={() => setMode('visual')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            mode === 'visual'
              ? 'bg-ac-blue text-white'
              : 'bg-surface-elevated text-ink-secondary hover:text-ink-primary'
          }`}
        >
          <Settings className="w-4 h-4" />
          Visual Editor
        </button>
        <button
          type="button"
          onClick={() => setMode('yaml')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            mode === 'yaml'
              ? 'bg-ac-blue text-white'
              : 'bg-surface-elevated text-ink-secondary hover:text-ink-primary'
          }`}
        >
          <Code className="w-4 h-4" />
          YAML Editor
        </button>
      </div>

      {mode === 'yaml' ? (
        <div className="flex-1 flex flex-col min-h-0">
          {yamlError && (
            <div className="mb-2 p-2 bg-ac-red/10 border border-ac-red/30 rounded text-sm text-ac-red">
              {yamlError}
            </div>
          )}
          <div className="flex-1 border border-border-subtle rounded-lg overflow-hidden">
            <CodeEditor
              value={value}
              onChange={handleYamlChange}
              language="yaml"
              height="100%"
            />
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto space-y-4 pr-2">
          {/* Server Section */}
          <Section title="Server" description="Proxy and admin server settings">
            <div className="grid grid-cols-2 gap-4">
              <Input
                label="Listen Address"
                description="Proxy listen address"
                value={config.server.listen}
                onChange={(v) => updateSection('server', { listen: v })}
                placeholder="0.0.0.0:6190"
              />
              <Input
                label="Admin Listen Address"
                description="Admin API listen address"
                value={config.server.admin_listen}
                onChange={(v) => updateSection('server', { admin_listen: v })}
                placeholder="0.0.0.0:6191"
              />
              <Input
                label="Workers"
                description="Worker threads (0 = auto-detect)"
                value={config.server.workers}
                onChange={(v) => updateSection('server', { workers: parseInt(v) || 0 })}
                type="number"
              />
              <Input
                label="Admin API Key"
                description="Optional static API key (auto-generated if empty)"
                value={config.server.admin_api_key || ''}
                onChange={(v) => updateSection('server', { admin_api_key: v || undefined })}
                placeholder="Leave empty for auto-generated"
              />
            </div>
          </Section>

          {/* Upstreams Section */}
          <Section title="Upstreams" description="Backend servers for load balancing">
            <div className="space-y-3">
              {config.upstreams.map((upstream, idx) => (
                <div key={idx} className="flex items-end gap-3">
                  <div className="flex-1">
                    <Input
                      label={idx === 0 ? 'Host' : ''}
                      value={upstream.host}
                      onChange={(v) => {
                        const newUpstreams = [...config.upstreams];
                        newUpstreams[idx] = { ...newUpstreams[idx], host: v };
                        updateConfigAndYaml({ ...config, upstreams: newUpstreams });
                      }}
                      placeholder="127.0.0.1"
                    />
                  </div>
                  <div className="w-24">
                    <Input
                      label={idx === 0 ? 'Port' : ''}
                      value={upstream.port}
                      onChange={(v) => {
                        const newUpstreams = [...config.upstreams];
                        newUpstreams[idx] = { ...newUpstreams[idx], port: parseInt(v) || 8080 };
                        updateConfigAndYaml({ ...config, upstreams: newUpstreams });
                      }}
                      type="number"
                    />
                  </div>
                  <div className="w-20">
                    <Input
                      label={idx === 0 ? 'Weight' : ''}
                      value={upstream.weight || 1}
                      onChange={(v) => {
                        const newUpstreams = [...config.upstreams];
                        newUpstreams[idx] = { ...newUpstreams[idx], weight: parseInt(v) || 1 };
                        updateConfigAndYaml({ ...config, upstreams: newUpstreams });
                      }}
                      type="number"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      const newUpstreams = config.upstreams.filter((_, i) => i !== idx);
                      if (newUpstreams.length === 0) newUpstreams.push({ host: '127.0.0.1', port: 8080 });
                      updateConfigAndYaml({ ...config, upstreams: newUpstreams });
                    }}
                    className="p-2 text-ink-muted hover:text-ac-red transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
              <button
                type="button"
                onClick={() => {
                  updateConfigAndYaml({
                    ...config,
                    upstreams: [...config.upstreams, { host: '127.0.0.1', port: 8080 }],
                  });
                }}
                className="flex items-center gap-2 text-sm text-ac-blue hover:text-ac-blue/80 transition-colors"
              >
                <Plus className="w-4 h-4" />
                Add Upstream
              </button>
            </div>
          </Section>

          {/* Rate Limiting Section */}
          <Section title="Rate Limiting" description="Request rate limits">
            <Toggle
              label="Enable Rate Limiting"
              checked={config.rate_limit.enabled}
              onChange={(v) => updateSection('rate_limit', { enabled: v })}
            />
            {config.rate_limit.enabled && (
              <div className="grid grid-cols-3 gap-4 mt-3">
                <Input
                  label="Global RPS"
                  description="Requests per second limit"
                  value={config.rate_limit.rps}
                  onChange={(v) => updateSection('rate_limit', { rps: parseInt(v) || 10000 })}
                  type="number"
                />
                <Input
                  label="Per-IP RPS"
                  description="Per-IP limit"
                  value={config.rate_limit.per_ip_rps}
                  onChange={(v) => updateSection('rate_limit', { per_ip_rps: parseInt(v) || 100 })}
                  type="number"
                />
                <Input
                  label="Burst"
                  description="Burst allowance"
                  value={config.rate_limit.burst || ''}
                  onChange={(v) => updateSection('rate_limit', { burst: v ? parseInt(v) : undefined })}
                  type="number"
                  placeholder="Optional"
                />
              </div>
            )}
          </Section>

          {/* Logging Section */}
          <Section title="Logging" description="Log output settings">
            <div className="grid grid-cols-2 gap-4">
              <Select
                label="Log Level"
                value={config.logging.level}
                onChange={(v) => updateSection('logging', { level: v })}
                options={[
                  { value: 'trace', label: 'Trace' },
                  { value: 'debug', label: 'Debug' },
                  { value: 'info', label: 'Info' },
                  { value: 'warn', label: 'Warn' },
                  { value: 'error', label: 'Error' },
                ]}
              />
              <Select
                label="Log Format"
                value={config.logging.format}
                onChange={(v) => updateSection('logging', { format: v })}
                options={[
                  { value: 'json', label: 'JSON' },
                  { value: 'text', label: 'Text' },
                ]}
              />
            </div>
            <Toggle
              label="Access Logs"
              description="Log each request"
              checked={config.logging.access_log}
              onChange={(v) => updateSection('logging', { access_log: v })}
            />
          </Section>

          {/* WAF Detection Section */}
          <Section title="WAF Detection" description="Attack detection rules">
            <div className="grid grid-cols-2 gap-4">
              <Toggle
                label="SQL Injection"
                checked={config.detection.sqli}
                onChange={(v) => updateSection('detection', { sqli: v })}
              />
              <Toggle
                label="XSS"
                checked={config.detection.xss}
                onChange={(v) => updateSection('detection', { xss: v })}
              />
              <Toggle
                label="Path Traversal"
                checked={config.detection.path_traversal}
                onChange={(v) => updateSection('detection', { path_traversal: v })}
              />
              <Toggle
                label="Command Injection"
                checked={config.detection.command_injection}
                onChange={(v) => updateSection('detection', { command_injection: v })}
              />
            </div>
            <div className="grid grid-cols-2 gap-4 mt-3">
              <Select
                label="Action"
                description="Action on detection"
                value={config.detection.action}
                onChange={(v) => updateSection('detection', { action: v })}
                options={[
                  { value: 'block', label: 'Block' },
                  { value: 'log', label: 'Log Only' },
                  { value: 'challenge', label: 'Challenge' },
                ]}
              />
              <Input
                label="Block Status"
                description="HTTP status for blocked requests"
                value={config.detection.block_status}
                onChange={(v) => updateSection('detection', { block_status: parseInt(v) || 403 })}
                type="number"
              />
            </div>
            <div className="grid grid-cols-2 gap-4 mt-3">
              <Input
                label="Rules Path"
                description="Path to rules file"
                value={config.detection.rules_path || ''}
                onChange={(v) => updateSection('detection', { rules_path: v || undefined })}
                placeholder="data/rules.json"
              />
              <Input
                label="Risk Server URL"
                description="External risk assessment service"
                value={config.detection.risk_server_url || ''}
                onChange={(v) => updateSection('detection', { risk_server_url: v || undefined })}
                placeholder="Optional"
              />
            </div>
          </Section>

          {/* TLS Section */}
          <Section title="TLS" description="HTTPS/TLS settings" defaultOpen={false}>
            <Toggle
              label="Enable TLS"
              description="Enable HTTPS on the proxy listener"
              checked={config.tls.enabled}
              onChange={(v) => updateSection('tls', { enabled: v })}
            />
            {config.tls.enabled && (
              <div className="grid grid-cols-2 gap-4 mt-3">
                <Select
                  label="Minimum TLS Version"
                  value={config.tls.min_version}
                  onChange={(v) => updateSection('tls', { min_version: v })}
                  options={[
                    { value: '1.2', label: 'TLS 1.2' },
                    { value: '1.3', label: 'TLS 1.3' },
                  ]}
                />
                <div />
                <Input
                  label="Certificate Path"
                  value={config.tls.cert_path || ''}
                  onChange={(v) => updateSection('tls', { cert_path: v || undefined })}
                  placeholder="/etc/certs/server.pem"
                />
                <Input
                  label="Key Path"
                  value={config.tls.key_path || ''}
                  onChange={(v) => updateSection('tls', { key_path: v || undefined })}
                  placeholder="/etc/certs/server.key"
                />
              </div>
            )}
          </Section>

          {/* Telemetry Section */}
          <Section title="Telemetry" description="Metrics and event reporting" defaultOpen={false}>
            <Toggle
              label="Enable Telemetry"
              description="Send telemetry data to external endpoint"
              checked={config.telemetry.enabled}
              onChange={(v) => updateSection('telemetry', { enabled: v })}
            />
            {config.telemetry.enabled && (
              <div className="grid grid-cols-2 gap-4 mt-3">
                <Input
                  label="Endpoint"
                  description="Telemetry receiver URL"
                  value={config.telemetry.endpoint || ''}
                  onChange={(v) => updateSection('telemetry', { endpoint: v || undefined })}
                  placeholder="http://localhost:8080/telemetry"
                />
                <Input
                  label="API Key"
                  description="Authentication key"
                  value={config.telemetry.api_key || ''}
                  onChange={(v) => updateSection('telemetry', { api_key: v || undefined })}
                  placeholder="Optional"
                />
                <Input
                  label="Batch Size"
                  description="Events per batch"
                  value={config.telemetry.batch_size || 100}
                  onChange={(v) => updateSection('telemetry', { batch_size: parseInt(v) || 100 })}
                  type="number"
                />
                <Input
                  label="Instance ID"
                  description="Unique instance identifier"
                  value={config.telemetry.instance_id || ''}
                  onChange={(v) => updateSection('telemetry', { instance_id: v || undefined })}
                  placeholder="Optional"
                />
              </div>
            )}
          </Section>

          {/* Tarpit Section */}
          <Section title="Tarpit" description="Slow down malicious actors" defaultOpen={false}>
            <Toggle
              label="Enable Tarpit"
              description="Apply delays to suspicious requests"
              checked={config.tarpit.enabled}
              onChange={(v) => updateSection('tarpit', { enabled: v })}
            />
            {config.tarpit.enabled && (
              <div className="grid grid-cols-2 gap-4 mt-3">
                <Input
                  label="Base Delay (ms)"
                  description="Initial delay"
                  value={config.tarpit.base_delay_ms}
                  onChange={(v) => updateSection('tarpit', { base_delay_ms: parseInt(v) || 1000 })}
                  type="number"
                />
                <Input
                  label="Max Delay (ms)"
                  description="Maximum delay"
                  value={config.tarpit.max_delay_ms}
                  onChange={(v) => updateSection('tarpit', { max_delay_ms: parseInt(v) || 30000 })}
                  type="number"
                />
                <Input
                  label="Multiplier"
                  description="Progressive delay multiplier"
                  value={config.tarpit.progressive_multiplier || 1.5}
                  onChange={(v) => updateSection('tarpit', { progressive_multiplier: parseFloat(v) || 1.5 })}
                  type="number"
                />
                <Input
                  label="Max Concurrent"
                  description="Max concurrent tarpits"
                  value={config.tarpit.max_concurrent_tarpits || 1000}
                  onChange={(v) => updateSection('tarpit', { max_concurrent_tarpits: parseInt(v) || 1000 })}
                  type="number"
                />
              </div>
            )}
          </Section>

          {/* DLP Section */}
          <Section title="Data Loss Prevention" description="Sensitive data detection" defaultOpen={false}>
            <Toggle
              label="Enable DLP"
              description="Scan requests/responses for sensitive data"
              checked={config.dlp.enabled}
              onChange={(v) => updateSection('dlp', { enabled: v })}
            />
            {config.dlp.enabled && (
              <div className="grid grid-cols-2 gap-4 mt-3">
                <Input
                  label="Max Scan Size (bytes)"
                  description="Skip scanning larger payloads"
                  value={config.dlp.max_scan_size}
                  onChange={(v) => updateSection('dlp', { max_scan_size: parseInt(v) || 5242880 })}
                  type="number"
                />
                <Input
                  label="Max Matches"
                  description="Stop after this many matches"
                  value={config.dlp.max_matches || 100}
                  onChange={(v) => updateSection('dlp', { max_matches: parseInt(v) || 100 })}
                  type="number"
                />
                <Toggle
                  label="Text Only"
                  description="Only scan text content types"
                  checked={config.dlp.scan_text_only ?? true}
                  onChange={(v) => updateSection('dlp', { scan_text_only: v })}
                />
                <Toggle
                  label="Fast Mode"
                  description="Skip low-priority patterns"
                  checked={config.dlp.fast_mode ?? false}
                  onChange={(v) => updateSection('dlp', { fast_mode: v })}
                />
              </div>
            )}
          </Section>

          {/* Crawler Detection Section */}
          <Section title="Crawler Detection" description="Bot and crawler identification" defaultOpen={false}>
            <Toggle
              label="Enable Crawler Detection"
              description="Detect and classify web crawlers"
              checked={config.crawler.enabled}
              onChange={(v) => updateSection('crawler', { enabled: v })}
            />
            {config.crawler.enabled && (
              <div className="grid grid-cols-2 gap-4 mt-3">
                <Toggle
                  label="Verify Legitimate Crawlers"
                  description="DNS verification for known bots"
                  checked={config.crawler.verify_legitimate_crawlers ?? true}
                  onChange={(v) => updateSection('crawler', { verify_legitimate_crawlers: v })}
                />
                <Toggle
                  label="Block Bad Bots"
                  description="Block detected malicious crawlers"
                  checked={config.crawler.block_bad_bots ?? true}
                  onChange={(v) => updateSection('crawler', { block_bad_bots: v })}
                />
                <Input
                  label="DNS Cache TTL (s)"
                  value={config.crawler.dns_cache_ttl_secs || 300}
                  onChange={(v) => updateSection('crawler', { dns_cache_ttl_secs: parseInt(v) || 300 })}
                  type="number"
                />
                <Input
                  label="DNS Timeout (ms)"
                  value={config.crawler.dns_timeout_ms || 2000}
                  onChange={(v) => updateSection('crawler', { dns_timeout_ms: parseInt(v) || 2000 })}
                  type="number"
                />
              </div>
            )}
          </Section>

          {/* Signal Horizon Section */}
          <Section title="Signal Horizon" description="Hub integration for fleet management" defaultOpen={false}>
            <Toggle
              label="Enable Horizon Integration"
              description="Connect to Signal Horizon hub"
              checked={config.horizon.enabled}
              onChange={(v) => updateSection('horizon', { enabled: v })}
            />
            {config.horizon.enabled && (
              <div className="grid grid-cols-2 gap-4 mt-3">
                <Input
                  label="Hub URL"
                  description="WebSocket URL for the hub"
                  value={config.horizon.hub_url || ''}
                  onChange={(v) => updateSection('horizon', { hub_url: v || undefined })}
                  placeholder="wss://horizon.example.com/ws/sensor"
                />
                <Input
                  label="API Key"
                  description="Authentication key"
                  value={config.horizon.api_key || ''}
                  onChange={(v) => updateSection('horizon', { api_key: v || undefined })}
                  placeholder="sk-..."
                />
                <Input
                  label="Sensor ID"
                  description="Unique sensor identifier"
                  value={config.horizon.sensor_id || ''}
                  onChange={(v) => updateSection('horizon', { sensor_id: v || undefined })}
                  placeholder="sensor-001"
                />
                <Input
                  label="Sensor Name"
                  description="Human-readable name"
                  value={config.horizon.sensor_name || ''}
                  onChange={(v) => updateSection('horizon', { sensor_name: v || undefined })}
                  placeholder="Production WAF"
                />
                <Input
                  label="Heartbeat Interval (ms)"
                  value={config.horizon.heartbeat_interval_ms || 30000}
                  onChange={(v) => updateSection('horizon', { heartbeat_interval_ms: parseInt(v) || 30000 })}
                  type="number"
                />
                <Input
                  label="Signal Batch Size"
                  value={config.horizon.signal_batch_size || 100}
                  onChange={(v) => updateSection('horizon', { signal_batch_size: parseInt(v) || 100 })}
                  type="number"
                />
              </div>
            )}
          </Section>

          {/* Payload Profiling Section */}
          <Section title="Payload Profiling" description="Request/response size analysis" defaultOpen={false}>
            <Toggle
              label="Enable Payload Profiling"
              description="Track payload sizes for anomaly detection"
              checked={config.payload?.enabled ?? true}
              onChange={(v) => updateConfigAndYaml({ ...config, payload: { ...config.payload, enabled: v } })}
            />
            {config.payload?.enabled && (
              <div className="grid grid-cols-2 gap-4 mt-3">
                <Input
                  label="Max Endpoints"
                  description="Maximum endpoints to track"
                  value={config.payload?.max_endpoints || 5000}
                  onChange={(v) => updateConfigAndYaml({
                    ...config,
                    payload: { ...config.payload, enabled: true, max_endpoints: parseInt(v) || 5000 }
                  })}
                  type="number"
                />
                <Input
                  label="Oversize Threshold"
                  description="Multiplier for oversize detection"
                  value={config.payload?.oversize_threshold || 3.0}
                  onChange={(v) => updateConfigAndYaml({
                    ...config,
                    payload: { ...config.payload, enabled: true, oversize_threshold: parseFloat(v) || 3.0 }
                  })}
                  type="number"
                />
              </div>
            )}
          </Section>

          {/* Trends Section */}
          <Section title="Trends" description="Historical pattern tracking" defaultOpen={false}>
            <Toggle
              label="Enable Trends"
              description="Track traffic patterns over time"
              checked={config.trends?.enabled ?? true}
              onChange={(v) => updateConfigAndYaml({ ...config, trends: { ...config.trends, enabled: v } })}
            />
            {config.trends?.enabled && (
              <div className="grid grid-cols-2 gap-4 mt-3">
                <Input
                  label="Bucket Size (ms)"
                  description="Time bucket duration"
                  value={config.trends?.bucket_size_ms || 60000}
                  onChange={(v) => updateConfigAndYaml({
                    ...config,
                    trends: { ...config.trends, enabled: true, bucket_size_ms: parseInt(v) || 60000 }
                  })}
                  type="number"
                />
                <Input
                  label="Retention (hours)"
                  description="How long to keep data"
                  value={config.trends?.retention_hours || 24}
                  onChange={(v) => updateConfigAndYaml({
                    ...config,
                    trends: { ...config.trends, enabled: true, retention_hours: parseInt(v) || 24 }
                  })}
                  type="number"
                />
              </div>
            )}
          </Section>
        </div>
      )}
    </div>
  );
}

export function getDefaultConfigYaml(): string {
  return YAML.stringify(defaultConfig, { indent: 2 });
}
