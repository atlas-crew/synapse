/**
 * SynapseConfigEditor - Visual and YAML editor for Synapse sensor configuration
 *
 * Matches the actual synapse-pingora ConfigFile structure from config.rs
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Code, Settings, Plus, Trash2, ChevronDown, ChevronRight, Globe } from 'lucide-react';
import { CodeEditor } from '../ctrlx/CodeEditor';
import YAML from 'yaml';

// Upstream backend configuration
interface UpstreamConfig {
  host: string;
  port: number;
  weight?: number;
}

// TLS configuration for a site
interface TlsConfig {
  cert_path: string;
  key_path: string;
  min_version?: string;
}

// Site-specific WAF configuration
interface SiteWafConfig {
  enabled: boolean;
  threshold?: number;
  rule_overrides?: Record<string, string>;
}

// Rate limiting configuration
interface RateLimitConfig {
  rps: number;
  enabled: boolean;
  burst?: number;
}

// Access control configuration
interface AccessControlConfig {
  allow?: string[];
  deny?: string[];
  default_action?: string;
}

// Header manipulation
interface HeaderOps {
  add?: Record<string, string>;
  set?: Record<string, string>;
  remove?: string[];
}

interface HeaderConfig {
  request?: HeaderOps;
  response?: HeaderOps;
}

// Shadow mirroring configuration
interface ShadowMirrorConfig {
  enabled: boolean;
  target_url?: string;
  sample_rate?: number;
}

// Site configuration - supports wildcard hostnames
interface SiteYamlConfig {
  hostname: string; // Supports wildcards like *.example.com
  upstreams: UpstreamConfig[];
  tls?: TlsConfig;
  waf?: SiteWafConfig;
  rate_limit?: RateLimitConfig;
  access_control?: AccessControlConfig;
  headers?: HeaderConfig;
  shadow_mirror?: ShadowMirrorConfig;
}

// Profiler configuration
interface ProfilerConfig {
  enabled: boolean;
  max_profiles?: number;
  max_schemas?: number;
  min_samples_for_validation?: number;
  payload_z_threshold?: number;
  param_z_threshold?: number;
  response_z_threshold?: number;
  redact_pii?: boolean;
  freeze_after_samples?: number;
}

// Global server configuration
interface GlobalConfig {
  http_addr: string;
  https_addr: string;
  workers: number;
  shutdown_timeout_secs?: number;
  waf_threshold: number;
  waf_enabled: boolean;
  log_level: string;
  admin_api_key?: string;
  waf_regex_timeout_ms?: number;
}

// Complete config structure matching synapse-pingora ConfigFile
export interface SynapseConfig {
  server: GlobalConfig;
  sites: SiteYamlConfig[];
  rate_limit: RateLimitConfig;
  profiler: ProfilerConfig;
}

const defaultSite: SiteYamlConfig = {
  hostname: 'example.com',
  upstreams: [{ host: '127.0.0.1', port: 8080, weight: 1 }],
  waf: { enabled: true, threshold: 70 },
};

const defaultConfig: SynapseConfig = {
  server: {
    http_addr: '0.0.0.0:80',
    https_addr: '0.0.0.0:443',
    workers: 0,
    shutdown_timeout_secs: 30,
    waf_threshold: 70,
    waf_enabled: true,
    log_level: 'info',
    waf_regex_timeout_ms: 100,
  },
  sites: [{ ...defaultSite }],
  rate_limit: {
    rps: 10000,
    enabled: true,
  },
  profiler: {
    enabled: true,
    max_profiles: 1000,
    max_schemas: 500,
    min_samples_for_validation: 100,
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
    <div className="border border-border-subtle overflow-hidden">
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
        className={`relative w-10 h-6  transition-colors flex-shrink-0 mt-0.5 ${
          checked ? 'bg-ac-blue' : 'bg-surface-elevated'
        }`}
        onClick={() => onChange(!checked)}
      >
        <div
          className={`absolute top-1 w-4 h-4  bg-white shadow transition-transform ${
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

function Input({ label, description, value, onChange, type = 'text', placeholder, required, min, max, pattern }: {
  label: string;
  description?: string;
  value: string | number;
  onChange: (v: string) => void;
  type?: string;
  placeholder?: string;
  required?: boolean;
  min?: number;
  max?: number;
  pattern?: string;
}) {
  return (
    <div>
      <label className="block text-sm text-ink-secondary mb-1">
        {label}
        {required && <span className="text-ac-red ml-0.5" aria-hidden="true">*</span>}
      </label>
      {description && <p className="text-xs text-ink-muted mb-1">{description}</p>}
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        required={required}
        min={min}
        max={max}
        pattern={pattern}
        className="w-full px-3 py-2 bg-surface-elevated border border-border-subtle text-ink-primary text-sm focus:outline-none focus:ring-1 focus:ring-ac-blue invalid:border-ac-red invalid:ring-ac-red/30"
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
        className="w-full px-3 py-2 bg-surface-elevated border border-border-subtle text-ink-primary text-sm focus:outline-none focus:ring-1 focus:ring-ac-blue"
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
  const [activeSiteIndex, setActiveSiteIndex] = useState(0);

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

  // Helper to update server config
  const updateServer = (updates: Partial<GlobalConfig>) => {
    updateConfigAndYaml({
      ...config,
      server: { ...config.server, ...updates },
    });
  };

  // Helper to update a site
  const updateSite = (index: number, updates: Partial<SiteYamlConfig>) => {
    const newSites = [...config.sites];
    newSites[index] = { ...newSites[index], ...updates };
    updateConfigAndYaml({ ...config, sites: newSites });
  };

  // Add new site
  const addSite = () => {
    const newSites = [...config.sites, { ...defaultSite, hostname: `site${config.sites.length + 1}.example.com` }];
    updateConfigAndYaml({ ...config, sites: newSites });
    setActiveSiteIndex(newSites.length - 1);
  };

  // Remove site
  const removeSite = (index: number) => {
    if (config.sites.length <= 1) return;
    const newSites = config.sites.filter((_, i) => i !== index);
    updateConfigAndYaml({ ...config, sites: newSites });
    if (activeSiteIndex >= newSites.length) {
      setActiveSiteIndex(newSites.length - 1);
    }
  };

  const activeSite = config.sites[activeSiteIndex] || config.sites[0];

  return (
    <div className="flex flex-col h-full">
      {/* Mode Toggle */}
      <div className="flex items-center gap-2 mb-4">
        <button
          type="button"
          onClick={() => setMode('visual')}
          className={`flex items-center gap-2 px-4 py-2  text-sm font-medium transition-colors ${
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
          className={`flex items-center gap-2 px-4 py-2  text-sm font-medium transition-colors ${
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
        <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
          {yamlError && (
            <div className="mb-2 p-2 bg-ac-red/10 border border-ac-red/30 text-sm text-ac-red flex-shrink-0">
              {yamlError}
            </div>
          )}
          <div className="flex-1 min-h-0 [&_.cm-editor]:h-full [&_.cm-scroller]:overflow-auto">
            <CodeEditor
              value={value}
              onChange={handleYamlChange}
              language="yaml"
              height="100%"
              className="h-full"
            />
          </div>
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto space-y-4 pr-2">
          {/* Server Section */}
          <Section title="Server" description="Global proxy and admin server settings">
            <div className="grid grid-cols-2 gap-4">
              <Input
                label="HTTP Listen Address"
                description="Proxy HTTP listen address"
                value={config.server.http_addr}
                onChange={(v) => updateServer({ http_addr: v })}
                placeholder="0.0.0.0:80"
                required
                pattern="[^\s]+"
              />
              <Input
                label="HTTPS Listen Address"
                description="Proxy HTTPS listen address"
                value={config.server.https_addr}
                onChange={(v) => updateServer({ https_addr: v })}
                placeholder="0.0.0.0:443"
                required
                pattern="[^\s]+"
              />
              <Input
                label="Workers"
                description="Worker threads (0 = auto-detect)"
                value={config.server.workers}
                onChange={(v) => updateServer({ workers: parseInt(v) || 0 })}
                type="number"
                min={0}
                max={256}
              />
              <Input
                label="Shutdown Timeout (s)"
                description="Graceful shutdown timeout"
                value={config.server.shutdown_timeout_secs || 30}
                onChange={(v) => updateServer({ shutdown_timeout_secs: parseInt(v) || 30 })}
                type="number"
                min={1}
                max={300}
              />
              <Select
                label="Log Level"
                value={config.server.log_level}
                onChange={(v) => updateServer({ log_level: v })}
                options={[
                  { value: 'trace', label: 'Trace' },
                  { value: 'debug', label: 'Debug' },
                  { value: 'info', label: 'Info' },
                  { value: 'warn', label: 'Warn' },
                  { value: 'error', label: 'Error' },
                ]}
              />
              <Input
                label="Admin API Key"
                description="Static API key (auto-generated if empty)"
                value={config.server.admin_api_key || ''}
                onChange={(v) => updateServer({ admin_api_key: v || undefined })}
                placeholder="Leave empty for auto-generated"
              />
            </div>
          </Section>

          {/* Global WAF Section */}
          <Section title="Global WAF Settings" description="Default WAF settings for all sites">
            <Toggle
              label="Enable WAF Globally"
              description="Enable WAF protection by default"
              checked={config.server.waf_enabled}
              onChange={(v) => updateServer({ waf_enabled: v })}
            />
            <div className="grid grid-cols-2 gap-4 mt-3">
              <Input
                label="WAF Threshold"
                description="Risk score threshold (1-100)"
                value={config.server.waf_threshold}
                onChange={(v) => updateServer({ waf_threshold: Math.min(100, Math.max(1, parseInt(v) || 70)) })}
                type="number"
                min={1}
                max={100}
                required
              />
              <Input
                label="Regex Timeout (ms)"
                description="WAF regex timeout (max 500ms)"
                value={config.server.waf_regex_timeout_ms || 100}
                onChange={(v) => updateServer({ waf_regex_timeout_ms: Math.min(500, parseInt(v) || 100) })}
                type="number"
                min={1}
                max={500}
              />
            </div>
          </Section>

          {/* Global Rate Limiting */}
          <Section title="Global Rate Limiting" description="Default rate limits">
            <Toggle
              label="Enable Rate Limiting"
              checked={config.rate_limit.enabled}
              onChange={(v) => updateConfigAndYaml({ ...config, rate_limit: { ...config.rate_limit, enabled: v } })}
            />
            {config.rate_limit.enabled && (
              <div className="grid grid-cols-2 gap-4 mt-3">
                <Input
                  label="Requests Per Second"
                  value={config.rate_limit.rps}
                  onChange={(v) => updateConfigAndYaml({ ...config, rate_limit: { ...config.rate_limit, rps: parseInt(v) || 10000 } })}
                  type="number"
                  min={1}
                  required
                />
                <Input
                  label="Burst Allowance"
                  description="Optional burst capacity"
                  value={config.rate_limit.burst || ''}
                  onChange={(v) => updateConfigAndYaml({ ...config, rate_limit: { ...config.rate_limit, burst: v ? parseInt(v) : undefined } })}
                  type="number"
                  placeholder="Default: 2x RPS"
                />
              </div>
            )}
          </Section>

          {/* Sites Section */}
          <Section title="Sites" description="Virtual host configurations with hostname routing">
            {/* Site Tabs */}
            <div className="flex flex-wrap gap-2 mb-4">
              {config.sites.map((site, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => setActiveSiteIndex(idx)}
                  className={`flex items-center gap-2 px-3 py-1.5  text-sm transition-colors ${
                    idx === activeSiteIndex
                      ? 'bg-ac-blue text-white'
                      : 'bg-surface-elevated text-ink-secondary hover:text-ink-primary'
                  }`}
                >
                  <Globe className="w-3 h-3" />
                  {site.hostname.length > 20 ? site.hostname.slice(0, 20) + '...' : site.hostname}
                </button>
              ))}
              <button
                type="button"
                onClick={addSite}
                className="flex items-center gap-1 px-3 py-1.5 text-sm text-ac-blue hover:bg-surface-elevated transition-colors"
              >
                <Plus className="w-3 h-3" />
                Add Site
              </button>
            </div>

            {/* Active Site Config */}
            {activeSite && (
              <div className="space-y-4 p-4 bg-surface-subtle">
                <div className="flex items-center justify-between">
                  <h4 className="font-medium text-ink-primary">Site Configuration</h4>
                  {config.sites.length > 1 && (
                    <button
                      type="button"
                      onClick={() => removeSite(activeSiteIndex)}
                      className="text-sm text-ac-red hover:text-ac-red/80 transition-colors"
                    >
                      Remove Site
                    </button>
                  )}
                </div>

                {/* Hostname */}
                <Input
                  label="Hostname"
                  description="Exact hostname or wildcard pattern (e.g., *.example.com, api.*.example.com)"
                  value={activeSite.hostname}
                  onChange={(v) => updateSite(activeSiteIndex, { hostname: v })}
                  placeholder="example.com or *.example.com"
                  required
                />
                <p className="text-xs text-ink-muted -mt-2">
                  Wildcards: Use * for subdomain matching. Examples: *.example.com, *.api.example.com, api-*.prod.example.com
                </p>

                {/* Upstreams */}
                <div>
                  <label className="block text-sm text-ink-secondary mb-2">Upstream Backends</label>
                  <div className="space-y-2">
                    {activeSite.upstreams.map((upstream, idx) => (
                      <div key={idx} className="flex items-center gap-2">
                        <input
                          type="text"
                          value={upstream.host}
                          onChange={(e) => {
                            const newUpstreams = [...activeSite.upstreams];
                            newUpstreams[idx] = { ...newUpstreams[idx], host: e.target.value };
                            updateSite(activeSiteIndex, { upstreams: newUpstreams });
                          }}
                          placeholder="hostname or IP"
                          required
                          className="flex-1 px-3 py-2 bg-surface-elevated border border-border-subtle text-ink-primary text-sm invalid:border-ac-red"
                        />
                        <input
                          type="number"
                          value={upstream.port}
                          onChange={(e) => {
                            const newUpstreams = [...activeSite.upstreams];
                            newUpstreams[idx] = { ...newUpstreams[idx], port: parseInt(e.target.value) || 8080 };
                            updateSite(activeSiteIndex, { upstreams: newUpstreams });
                          }}
                          placeholder="port"
                          required
                          min={1}
                          max={65535}
                          className="w-24 px-3 py-2 bg-surface-elevated border border-border-subtle text-ink-primary text-sm invalid:border-ac-red"
                        />
                        <input
                          type="number"
                          value={upstream.weight || 1}
                          onChange={(e) => {
                            const newUpstreams = [...activeSite.upstreams];
                            newUpstreams[idx] = { ...newUpstreams[idx], weight: parseInt(e.target.value) || 1 };
                            updateSite(activeSiteIndex, { upstreams: newUpstreams });
                          }}
                          placeholder="weight"
                          min={1}
                          max={100}
                          className="w-20 px-3 py-2 bg-surface-elevated border border-border-subtle text-ink-primary text-sm invalid:border-ac-red"
                          title="Load balancing weight"
                        />
                        <button
                          type="button"
                          onClick={() => {
                            const newUpstreams = activeSite.upstreams.filter((_, i) => i !== idx);
                            if (newUpstreams.length === 0) newUpstreams.push({ host: '127.0.0.1', port: 8080 });
                            updateSite(activeSiteIndex, { upstreams: newUpstreams });
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
                        updateSite(activeSiteIndex, {
                          upstreams: [...activeSite.upstreams, { host: '127.0.0.1', port: 8080 }],
                        });
                      }}
                      className="flex items-center gap-2 text-sm text-ac-blue hover:text-ac-blue/80 transition-colors"
                    >
                      <Plus className="w-4 h-4" />
                      Add Upstream
                    </button>
                  </div>
                </div>

                {/* Site WAF Override */}
                <div className="pt-3 border-t border-border-subtle">
                  <Toggle
                    label="Enable WAF for this site"
                    description="Override global WAF setting"
                    checked={activeSite.waf?.enabled ?? true}
                    onChange={(v) => updateSite(activeSiteIndex, { waf: { ...activeSite.waf, enabled: v } })}
                  />
                  {(activeSite.waf?.enabled ?? true) && (
                    <div className="mt-3">
                      <Input
                        label="WAF Threshold Override"
                        description="Site-specific threshold (leave empty for global default)"
                        value={activeSite.waf?.threshold || ''}
                        onChange={(v) => updateSite(activeSiteIndex, {
                          waf: { ...activeSite.waf, enabled: true, threshold: v ? parseInt(v) : undefined }
                        })}
                        type="number"
                        placeholder="Use global default"
                      />
                    </div>
                  )}
                </div>

                {/* Site Rate Limit Override */}
                <div className="pt-3 border-t border-border-subtle">
                  <Toggle
                    label="Site-specific Rate Limit"
                    description="Override global rate limit for this site"
                    checked={!!activeSite.rate_limit}
                    onChange={(v) => updateSite(activeSiteIndex, {
                      rate_limit: v ? { rps: 10000, enabled: true } : undefined
                    })}
                  />
                  {activeSite.rate_limit && (
                    <div className="grid grid-cols-2 gap-4 mt-3">
                      <Input
                        label="RPS Limit"
                        value={activeSite.rate_limit.rps}
                        onChange={(v) => updateSite(activeSiteIndex, {
                          rate_limit: { ...activeSite.rate_limit!, rps: parseInt(v) || 10000 }
                        })}
                        type="number"
                      />
                      <Input
                        label="Burst"
                        value={activeSite.rate_limit.burst || ''}
                        onChange={(v) => updateSite(activeSiteIndex, {
                          rate_limit: { ...activeSite.rate_limit!, burst: v ? parseInt(v) : undefined }
                        })}
                        type="number"
                        placeholder="Optional"
                      />
                    </div>
                  )}
                </div>

                {/* Site TLS */}
                <div className="pt-3 border-t border-border-subtle">
                  <Toggle
                    label="Enable TLS for this site"
                    checked={!!activeSite.tls}
                    onChange={(v) => updateSite(activeSiteIndex, {
                      tls: v ? { cert_path: '', key_path: '', min_version: '1.2' } : undefined
                    })}
                  />
                  {activeSite.tls && (
                    <div className="grid grid-cols-2 gap-4 mt-3">
                      <Input
                        label="Certificate Path"
                        value={activeSite.tls.cert_path}
                        onChange={(v) => updateSite(activeSiteIndex, {
                          tls: { ...activeSite.tls!, cert_path: v }
                        })}
                        placeholder="/etc/certs/server.pem"
                      />
                      <Input
                        label="Key Path"
                        value={activeSite.tls.key_path}
                        onChange={(v) => updateSite(activeSiteIndex, {
                          tls: { ...activeSite.tls!, key_path: v }
                        })}
                        placeholder="/etc/certs/server.key"
                      />
                      <Select
                        label="Minimum TLS Version"
                        value={activeSite.tls.min_version || '1.2'}
                        onChange={(v) => updateSite(activeSiteIndex, {
                          tls: { ...activeSite.tls!, min_version: v }
                        })}
                        options={[
                          { value: '1.2', label: 'TLS 1.2' },
                          { value: '1.3', label: 'TLS 1.3' },
                        ]}
                      />
                    </div>
                  )}
                </div>

                {/* Shadow Mirroring */}
                <div className="pt-3 border-t border-border-subtle">
                  <Toggle
                    label="Shadow Mirroring"
                    description="Mirror traffic to honeypot for analysis"
                    checked={!!activeSite.shadow_mirror?.enabled}
                    onChange={(v) => updateSite(activeSiteIndex, {
                      shadow_mirror: v ? { enabled: true, sample_rate: 100 } : undefined
                    })}
                  />
                  {activeSite.shadow_mirror?.enabled && (
                    <div className="grid grid-cols-2 gap-4 mt-3">
                      <Input
                        label="Target URL"
                        description="Honeypot endpoint"
                        value={activeSite.shadow_mirror.target_url || ''}
                        onChange={(v) => updateSite(activeSiteIndex, {
                          shadow_mirror: { ...activeSite.shadow_mirror!, target_url: v }
                        })}
                        placeholder="http://honeypot:8080"
                      />
                      <Input
                        label="Sample Rate (%)"
                        description="Percentage of traffic to mirror"
                        value={activeSite.shadow_mirror.sample_rate || 100}
                        onChange={(v) => updateSite(activeSiteIndex, {
                          shadow_mirror: { ...activeSite.shadow_mirror!, sample_rate: Math.min(100, parseInt(v) || 100) }
                        })}
                        type="number"
                        min={1}
                        max={100}
                      />
                    </div>
                  )}
                </div>
              </div>
            )}
          </Section>

          {/* Profiler Section */}
          <Section title="Profiler" description="Endpoint behavior learning and anomaly detection" defaultOpen={false}>
            <Toggle
              label="Enable Profiling"
              description="Learn endpoint behavior patterns"
              checked={config.profiler.enabled}
              onChange={(v) => updateConfigAndYaml({ ...config, profiler: { ...config.profiler, enabled: v } })}
            />
            {config.profiler.enabled && (
              <div className="grid grid-cols-2 gap-4 mt-3">
                <Input
                  label="Max Profiles"
                  description="Maximum endpoint profiles"
                  value={config.profiler.max_profiles || 1000}
                  onChange={(v) => updateConfigAndYaml({ ...config, profiler: { ...config.profiler, max_profiles: parseInt(v) || 1000 } })}
                  type="number"
                  min={1}
                  max={100000}
                />
                <Input
                  label="Max Schemas"
                  description="Maximum learned schemas"
                  value={config.profiler.max_schemas || 500}
                  onChange={(v) => updateConfigAndYaml({ ...config, profiler: { ...config.profiler, max_schemas: parseInt(v) || 500 } })}
                  type="number"
                  min={1}
                  max={100000}
                />
                <Input
                  label="Min Samples"
                  description="Samples before validation"
                  value={config.profiler.min_samples_for_validation || 100}
                  onChange={(v) => updateConfigAndYaml({ ...config, profiler: { ...config.profiler, min_samples_for_validation: parseInt(v) || 100 } })}
                  type="number"
                  min={1}
                  max={10000}
                />
                <Input
                  label="Payload Z-Score Threshold"
                  description="Anomaly detection threshold"
                  value={config.profiler.payload_z_threshold || 3.0}
                  onChange={(v) => updateConfigAndYaml({ ...config, profiler: { ...config.profiler, payload_z_threshold: parseFloat(v) || 3.0 } })}
                  type="number"
                />
                <Toggle
                  label="Redact PII"
                  description="Redact sensitive values in logs"
                  checked={config.profiler.redact_pii ?? true}
                  onChange={(v) => updateConfigAndYaml({ ...config, profiler: { ...config.profiler, redact_pii: v } })}
                />
                <Input
                  label="Freeze After Samples"
                  description="Lock baseline (0 = continuous)"
                  value={config.profiler.freeze_after_samples || 0}
                  onChange={(v) => updateConfigAndYaml({ ...config, profiler: { ...config.profiler, freeze_after_samples: parseInt(v) || 0 } })}
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
