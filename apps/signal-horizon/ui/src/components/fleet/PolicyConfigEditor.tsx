import React, { useState, useCallback, memo } from 'react';
import { 
  Shield, 
  Zap, 
  Bot, 
  Globe, 
  UserCheck, 
  Settings, 
  Layout, 
  ChevronDown, 
  ChevronRight,
  Info,
  AlertTriangle,
  Layers,
  FileCode
} from 'lucide-react';
import { clsx } from 'clsx';
import { CodeEditor } from '../ctrlx/CodeEditor';
import type { PolicyConfig, EnforcementMode } from '@signal-horizon/shared/types';
import { Button, Stack } from '@/ui';

export interface PolicyConfigEditorProps {
  value: PolicyConfig;
  onChange: (config: PolicyConfig) => void;
}

// =============================================================================
// Helper Components
// =============================================================================

const Section = memo(function Section({ 
  title, 
  icon: Icon, 
  description, 
  children, 
  defaultOpen = true 
}: { 
  title: string; 
  icon: React.ElementType; 
  description?: string; 
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  return (
    <div className="bg-surface-card border border-border-subtle overflow-hidden">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-3 bg-surface-subtle hover:bg-surface-elevated transition-colors"
      >
        <Stack direction="row" align="center" gap="md">
          <Icon className="w-4 h-4 text-ac-blue" />
          <div className="text-left">
            <span className="text-sm font-bold text-ink-primary uppercase tracking-widest">{title}</span>
            {description && <p className="text-[10px] text-ink-muted uppercase tracking-tighter mt-0.5">{description}</p>}
          </div>
        </Stack>
        {isOpen ? (
          <ChevronDown className="w-4 h-4 text-ink-muted" />
        ) : (
          <ChevronRight className="w-4 h-4 text-ink-muted" />
        )}
      </button>
      {isOpen && <div className="p-6 space-y-6">{children}</div>}
    </div>
  );
});

const Toggle = memo(function Toggle({ 
  label, 
  description, 
  checked, 
  onChange 
}: { 
  label: string; 
  description?: string; 
  checked: boolean; 
  onChange: (v: boolean) => void; 
}) {
  return (
    <label className="flex items-start gap-4 cursor-pointer group">
      <div
        className={clsx(
          "relative w-10 h-6 transition-colors flex-shrink-0 mt-0.5",
          checked ? 'bg-status-success' : 'bg-surface-elevated border border-border-subtle'
        )}
        onClick={() => onChange(!checked)}
      >
        <div
          className={clsx(
            "absolute top-1 w-4 h-4 bg-white shadow transition-transform",
            checked ? 'translate-x-5' : 'translate-x-1'
          )}
        />
      </div>
      <div>
        <span className="text-sm font-bold text-ink-primary group-hover:text-ac-blue transition-colors">{label}</span>
        {description && <p className="text-xs text-ink-muted mt-0.5">{description}</p>}
      </div>
    </label>
  );
});

const InputField = memo(function InputField({ 
  label, 
  value, 
  onChange, 
  type = 'text', 
  min, 
  max, 
  step, 
  suffix 
}: { 
  label: string; 
  value: string | number; 
  onChange: (v: string) => void; 
  type?: string; 
  min?: number; 
  max?: number; 
  step?: number;
  suffix?: string;
}) {
  return (
    <div className="space-y-1.5">
      <label className="text-[10px] font-bold text-ink-muted uppercase tracking-widest block">{label}</label>
      <div className="relative">
        <input
          type={type}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          min={min}
          max={max}
          step={step}
          className="w-full bg-surface-subtle border border-border-subtle p-2 text-sm font-mono focus:outline-none focus:border-ac-blue transition-colors"
        />
        {suffix && (
          <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] font-bold text-ink-muted uppercase">
            {suffix}
          </span>
        )}
      </div>
    </div>
  );
});

const ModeSelect = memo(function ModeSelect({ 
  label, 
  value, 
  onChange 
}: { 
  label: string; 
  value: EnforcementMode; 
  onChange: (v: EnforcementMode) => void; 
}) {
  return (
    <div className="space-y-1.5">
      <label className="text-[10px] font-bold text-ink-muted uppercase tracking-widest block">{label}</label>
      <div className="flex gap-1 bg-surface-subtle p-1 border border-border-subtle">
        {(['block', 'log', 'challenge'] as EnforcementMode[]).map((mode) => (
          <button
            key={mode}
            type="button"
            onClick={() => onChange(mode)}
            className={clsx(
              "flex-1 py-1.5 text-[10px] font-bold uppercase tracking-widest transition-all",
              value === mode 
                ? "bg-ac-navy text-white shadow-sm" 
                : "text-ink-muted hover:text-ink-primary hover:bg-surface-elevated"
            )}
          >
            {mode}
          </button>
        ))}
      </div>
    </div>
  );
});

// =============================================================================
// Main Component
// =============================================================================

export function PolicyConfigEditor({ value, onChange }: PolicyConfigEditorProps) {
  const [editorMode, setMode] = useState<'visual' | 'json'>('visual');
  const [jsonValue, setJsonValue] = useState(() => JSON.stringify(value, null, 2));
  const [jsonError, setJsonError] = useState<string | null>(null);

  const updateConfig = useCallback((updates: Partial<PolicyConfig>) => {
    const newConfig = { ...value, ...updates };
    onChange(newConfig);
    setJsonValue(JSON.stringify(newConfig, null, 2));
  }, [value, onChange]);

  const handleJsonChange = useCallback((val: string) => {
    setJsonValue(val);
    try {
      const parsed = JSON.parse(val);
      onChange(parsed);
      setJsonError(null);
    } catch (e) {
      setJsonError(e instanceof Error ? e.message : 'Invalid JSON');
    }
  }, [onChange]);

  const syncJsonToVisual = () => {
    setJsonValue(JSON.stringify(value, null, 2));
    setJsonError(null);
  };

  return (
    <div className="space-y-6">
      {/* Mode Switcher */}
      <div className="flex justify-between items-center bg-ac-card-dark p-4 border-l-4 border-ac-magenta shadow-lg">
        <Stack direction="row" align="center" gap="md">
          <Layers className="w-5 h-5 text-ac-sky-blue" />
          <div>
            <h3 className="text-white text-sm font-bold uppercase tracking-widest">Policy Engine Interface</h3>
            <p className="text-white/40 text-[10px] uppercase tracking-tighter">Configuration Mode: {editorMode === 'visual' ? 'GRAPHICAL_OVERRIDE' : 'RAW_SOURCE_JSON'}</p>
          </div>
        </Stack>
        <div className="flex gap-1 bg-white/5 p-1 border border-white/10">
          <button
            onClick={() => { setMode('visual'); syncJsonToVisual(); }}
            className={clsx(
              "px-4 py-2 text-[10px] font-bold uppercase tracking-widest transition-all",
              editorMode === 'visual' ? "bg-ac-sky-blue text-ac-navy" : "text-white/60 hover:text-white hover:bg-white/5"
            )}
          >
            <Stack direction="row" align="center" gap="sm">
              <Layout className="w-3.5 h-3.5" />
              <span>Visual</span>
            </Stack>
          </button>
          <button
            onClick={() => setMode('json')}
            className={clsx(
              "px-4 py-2 text-[10px] font-bold uppercase tracking-widest transition-all",
              editorMode === 'json' ? "bg-ac-sky-blue text-ac-navy" : "text-white/60 hover:text-white hover:bg-white/5"
            )}
          >
            <Stack direction="row" align="center" gap="sm">
              <FileCode className="w-3.5 h-3.5" />
              <span>JSON</span>
            </Stack>
          </button>
        </div>
      </div>

      {editorMode === 'json' ? (
        <div className="space-y-2 animate-in fade-in slide-in-from-top-2 duration-300">
          {jsonError && (
            <Stack direction="row" align="center" gap="md" className="p-3 bg-status-error/10 border-l-4 border-status-error">
              <AlertTriangle className="w-4 h-4 text-status-error" />
              <span className="text-xs font-mono text-status-error">LINT_FAILURE: {jsonError}</span>
            </Stack>
          )}
          <CodeEditor
            value={jsonValue}
            onChange={handleJsonChange}
            language="json"
            height="600px"
            className="font-mono text-xs"
          />
          <Stack direction="row" align="center" gap="sm" className="text-[10px] text-ink-muted uppercase tracking-widest font-bold px-2">
            <Info className="w-3 h-3" />
            Direct JSON manipulation bypasses UI validation. Use with caution.
          </Stack>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
          {/* General Thresholds */}
          <Section title="Fleet Defense Thresholds" icon={Shield} description="Primary blocking and observability controls">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="space-y-4">
                <InputField
                  label="Global Block Threshold"
                  type="number"
                  min={0}
                  max={100}
                  value={value.blockThreshold}
                  suffix="RISK_SCORE"
                  onChange={(v) => updateConfig({ blockThreshold: parseInt(v) || 0 })}
                />
                <p className="text-[10px] text-ink-muted leading-relaxed">
                  Requests with a cumulative risk score higher than this value will be subject to the default enforcement action.
                </p>
              </div>
              <div className="space-y-6 bg-surface-subtle p-4 border border-border-subtle">
                <Toggle
                  label="Global Observability"
                  description="Force telemetry logging for all processed requests regardless of score."
                  checked={value.logAllRequests}
                  onChange={(v) => updateConfig({ logAllRequests: v })}
                />
                <Toggle
                  label="Extended Diagnostics"
                  description="Enable verbose header and payload logging for policy troubleshooting."
                  checked={value.debugMode}
                  onChange={(v) => updateConfig({ debugMode: v })}
                />
              </div>
            </div>
          </Section>

          {/* Rate Limiting */}
          <Section title="Traffic Metering" icon={Zap} description="Anti-DDoS and consumption management">
            <div className="space-y-6">
              <Toggle
                label="Enforce Rate Limits"
                description="Apply token-bucket rate limiting based on client IP identity."
                checked={value.rateLimit.enabled}
                onChange={(v) => updateConfig({ rateLimit: { ...value.rateLimit, enabled: v } })}
              />
              
              {value.rateLimit.enabled && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-4 border-t border-border-subtle animate-in zoom-in-95 duration-200">
                  <InputField
                    label="Requests Per Second"
                    type="number"
                    value={value.rateLimit.requestsPerSecond}
                    suffix="RPS"
                    onChange={(v) => updateConfig({ rateLimit: { ...value.rateLimit, requestsPerSecond: parseInt(v) || 1 } })}
                  />
                  <InputField
                    label="Burst Capacity"
                    type="number"
                    value={value.rateLimit.burstSize}
                    suffix="TOKENS"
                    onChange={(v) => updateConfig({ rateLimit: { ...value.rateLimit, burstSize: parseInt(v) || 1 } })}
                  />
                  <InputField
                    label="Analysis Window"
                    type="number"
                    value={value.rateLimit.windowSeconds}
                    suffix="SECONDS"
                    onChange={(v) => updateConfig({ rateLimit: { ...value.rateLimit, windowSeconds: parseInt(v) || 1 } })}
                  />
                </div>
              )}
            </div>
          </Section>

          {/* WAF Protection */}
          <Section title="WAF Payload Inspection" icon={Shield} description="Deep packet inspection for common exploit vectors">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {[
                { id: 'sqlInjection' as const, label: 'SQL Injection' },
                { id: 'xss' as const, label: 'Cross-Site Scripting' },
                { id: 'commandInjection' as const, label: 'OS Command Injection' },
                { id: 'pathTraversal' as const, label: 'Directory Traversal' },
              ].map((vector) => (
                <div key={vector.id} className="p-4 border border-border-subtle bg-surface-subtle space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-ink-primary uppercase tracking-widest">{vector.label}</span>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={value.wafProtection[vector.id].enabled}
                        onChange={(e) => updateConfig({
                          wafProtection: {
                            ...value.wafProtection,
                            [vector.id]: { ...value.wafProtection[vector.id], enabled: e.target.checked }
                          }
                        })}
                        className="sr-only peer"
                      />
                      <div className="w-8 h-4 bg-surface-elevated border border-border-subtle peer-checked:bg-ac-blue transition-colors after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:h-3 after:w-3 after:transition-all peer-checked:after:translate-x-4"></div>
                    </label>
                  </div>
                  
                  {value.wafProtection[vector.id].enabled && (
                    <div className="grid grid-cols-2 gap-4 animate-in fade-in duration-200">
                      <ModeSelect
                        label="Action"
                        value={value.wafProtection[vector.id].mode}
                        onChange={(v) => updateConfig({
                          wafProtection: {
                            ...value.wafProtection,
                            [vector.id]: { ...value.wafProtection[vector.id], mode: v }
                          }
                        })}
                      />
                      <div className="space-y-1.5">
                        <label className="text-[10px] font-bold text-ink-muted uppercase tracking-widest block">Sensitivity</label>
                        <select
                          value={value.wafProtection[vector.id].sensitivity}
                          onChange={(e) => updateConfig({
                            wafProtection: {
                              ...value.wafProtection,
                              [vector.id]: { ...value.wafProtection[vector.id], sensitivity: e.target.value as any }
                            }
                          })}
                          className="w-full bg-surface-card border border-border-subtle p-1.5 text-[10px] font-bold uppercase tracking-widest focus:outline-none"
                        >
                          <option value="low">Low</option>
                          <option value="medium">Medium</option>
                          <option value="high">High</option>
                        </select>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </Section>

          {/* Bot Protection */}
          <Section title="Automated Actor Defense" icon={Bot} description="Bot management and fingerprint verification">
            <div className="space-y-6">
              <Toggle
                label="Enable Bot Detection"
                description="Activate behavioral and signature-based bot identification."
                checked={value.botProtection.enabled}
                onChange={(v) => updateConfig({ botProtection: { ...value.botProtection, enabled: v } })}
              />

              {value.botProtection.enabled && (
                <div className="space-y-6 pt-4 border-t border-border-subtle animate-in fade-in duration-200">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <ModeSelect
                        label="Default Bot Action"
                        value={value.botProtection.mode}
                        onChange={(v) => updateConfig({ botProtection: { ...value.botProtection, mode: v } })}
                      />
                      <div className="space-y-3 p-4 bg-surface-subtle border border-border-subtle">
                        <Toggle
                          label="Block Malicious Crawlers"
                          checked={value.botProtection.blockKnownBadBots}
                          onChange={(v) => updateConfig({ botProtection: { ...value.botProtection, blockKnownBadBots: v } })}
                        />
                        <Toggle
                          label="Challenge Suspicious UA"
                          checked={value.botProtection.challengeSuspiciousBots}
                          onChange={(v) => updateConfig({ botProtection: { ...value.botProtection, challengeSuspiciousBots: v } })}
                        />
                        <Toggle
                          label="Allow Verified Search"
                          checked={value.botProtection.allowVerifiedBots}
                          onChange={(v) => updateConfig({ botProtection: { ...value.botProtection, allowVerifiedBots: v } })}
                        />
                      </div>
                    </div>
                    <div className="space-y-4">
                      <label className="text-[10px] font-bold text-ink-muted uppercase tracking-widest block">Custom UA Patterns</label>
                      <div className="space-y-2 border border-border-subtle p-3 bg-surface-subtle max-h-40 overflow-y-auto font-mono text-[10px]">
                        {value.botProtection.customBotRules.length === 0 ? (
                          <span className="text-ink-muted italic">No custom rules defined.</span>
                        ) : (
                          value.botProtection.customBotRules.map((rule: { userAgentPattern: string; action: string }, idx: number) => (
                            <div key={idx} className="flex justify-between items-center py-1 border-b border-border-subtle last:border-0">
                              <span>{rule.userAgentPattern}</span>
                              <span className="text-ac-blue">{rule.action.toUpperCase()}</span>
                            </div>
                          ))
                        )}
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        style={{
                          height: '24px',
                          padding: 0,
                          fontSize: '10px',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          letterSpacing: '0.08em',
                          color: '#0057B7',
                        }}
                      >
                        + Define Pattern
                      </Button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </Section>

          {/* Geo-Blocking */}
          <Section title="Geographic Control" icon={Globe} description="Regional access policies and constraints">
            <div className="space-y-6">
              <Toggle
                label="Enable Geo-Location Policies"
                description="Restrict traffic based on originating country metadata."
                checked={value.geoBlocking.enabled}
                onChange={(v) => updateConfig({ geoBlocking: { ...value.geoBlocking, enabled: v } })}
              />

              {value.geoBlocking.enabled && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-4 border-t border-border-subtle animate-in fade-in duration-200">
                  <div className="space-y-4">
                    <label className="text-[10px] font-bold text-ink-muted uppercase tracking-widest block">Policy Mode</label>
                    <div className="flex gap-1 bg-surface-subtle p-1 border border-border-subtle">
                      {['allowlist', 'blocklist'].map((mode) => (
                        <button
                          key={mode}
                          type="button"
                          onClick={() => updateConfig({ geoBlocking: { ...value.geoBlocking, mode: mode as any } })}
                          className={clsx(
                            "flex-1 py-1.5 text-[10px] font-bold uppercase tracking-widest transition-all",
                            value.geoBlocking.mode === mode 
                              ? "bg-ac-navy text-white shadow-sm" 
                              : "text-ink-muted hover:text-ink-primary hover:bg-surface-elevated"
                          )}
                        >
                          {mode}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-4">
                    <label className="text-[10px] font-bold text-ink-muted uppercase tracking-widest block">Target Countries (ISO)</label>
                    <div className="flex flex-wrap gap-2">
                      {value.geoBlocking.countries.map((c: string) => (
                        <span key={c} className="px-2 py-1 bg-ac-blue/10 border border-ac-blue/30 text-ac-blue text-[10px] font-bold font-mono">
                          {c}
                        </span>
                      ))}
                      <Button
                        variant="outlined"
                        size="sm"
                        style={{
                          height: '24px',
                          padding: '0 8px',
                          fontSize: '10px',
                          fontWeight: 700,
                          color: '#7F7F7F',
                        }}
                      >
                        + ADD
                      </Button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </Section>

          {/* Reputation */}
          <Section title="IP Reputation Intel" icon={UserCheck} description="Crowd-sourced and behavioral threat intelligence">
            <div className="space-y-6">
              <Toggle
                label="Leverage Global Blocklists"
                description="Automatically sync with Signal Horizon's aggregated threat feed."
                checked={value.ipReputation.enabled}
                onChange={(v) => updateConfig({ ipReputation: { ...value.ipReputation, enabled: v } })}
              />

              {value.ipReputation.enabled && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-4 border-t border-border-subtle animate-in fade-in duration-200">
                  <InputField
                    label="Automatic Block Threshold"
                    type="number"
                    min={0}
                    max={100}
                    value={value.ipReputation.blockThreshold}
                    suffix="REP_SCORE"
                    onChange={(v) => updateConfig({ ipReputation: { ...value.ipReputation, blockThreshold: parseInt(v) || 0 } })}
                  />
                  <InputField
                    label="Challenge Threshold"
                    type="number"
                    min={0}
                    max={100}
                    value={value.ipReputation.challengeThreshold}
                    suffix="REP_SCORE"
                    onChange={(v) => updateConfig({ ipReputation: { ...value.ipReputation, challengeThreshold: parseInt(v) || 0 } })}
                  />
                </div>
              )}
            </div>
          </Section>

          {/* Resource Constraints */}
          <Section title="Resource Constraints" icon={Settings} description="Lower-level system and memory safeguards">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <InputField
                label="Max Request Body"
                type="number"
                value={value.maxBodySizeBytes}
                suffix="BYTES"
                onChange={(v) => updateConfig({ maxBodySizeBytes: parseInt(v) || 0 })}
              />
              <InputField
                label="Request Timeout"
                type="number"
                value={value.requestTimeoutMs}
                suffix="MS"
                onChange={(v) => updateConfig({ requestTimeoutMs: parseInt(v) || 1000 })}
              />
              <div className="space-y-1.5">
                <label className="text-[10px] font-bold text-ink-muted uppercase tracking-widest block">Header Injections</label>
                <div className="bg-surface-subtle border border-border-subtle p-2 text-[10px] font-mono h-9 overflow-hidden flex items-center justify-between">
                  <span className="text-ink-muted">{Object.keys(value.customHeaders).length} Keys defined</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    style={{ height: '20px', padding: 0, color: '#0057B7', fontWeight: 700 }}
                  >
                    MANAGE
                  </Button>
                </div>
              </div>
            </div>
          </Section>
        </div>
      )}
    </div>
  );
}
