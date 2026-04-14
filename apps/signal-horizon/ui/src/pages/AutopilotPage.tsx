/**
 * Autopilot Page — AI Red Team control panel
 *
 * Config viewer, launch form, live session status, stop/kill controls,
 * and completed session reports.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { Bot, Cpu, Play, Square, OctagonX, FileText, Clock, Shield, AlertTriangle, Loader2 } from 'lucide-react';
import { clsx } from 'clsx';
import { apiFetch } from '../lib/api';
import { useApparatusStatus } from '../hooks/useApparatusStatus';
import { useDemoMode } from '../stores/demoModeStore';
import { Stack, SectionHeader, Button, PAGE_TITLE_STYLE } from '@/ui';

// =============================================================================
// Types
// =============================================================================

interface AutopilotTool { id: string; name: string; description: string; category: string }
interface AutopilotConfig { tools: AutopilotTool[]; maxIterationsDefault: number; timeoutSeconds: number; safetyMode: boolean }

// Apparatus returns a flatter shape than this UI was written against:
//   { availableTools: string[], defaultAllowedTools: string[], personas: [...],
//     maxIterationsDefault?: number, ... }
// Adapt it to the AutopilotTool shape the UI renders. Each tool id like
// "chaos.cpu" becomes { id, name: 'Chaos Cpu', category: 'chaos', description: '' }
// so the page renders something meaningful without a round-trip redesign.
interface ApparatusAutopilotConfigResponse {
  availableTools?: string[];
  defaultAllowedTools?: string[];
  maxIterationsDefault?: number;
  timeoutSeconds?: number;
  safetyMode?: boolean;
}

function adaptApparatusConfig(raw: ApparatusAutopilotConfigResponse): AutopilotConfig {
  const toolIds = raw.availableTools ?? [];
  const tools: AutopilotTool[] = toolIds.map((id) => {
    const [category, rawName] = id.includes('.') ? id.split('.', 2) : [id, id];
    const name = (rawName ?? id)
      .replace(/[_-]/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());
    return { id, name, description: '', category: category ?? '' };
  });
  return {
    tools,
    maxIterationsDefault: raw.maxIterationsDefault ?? 50,
    timeoutSeconds: raw.timeoutSeconds ?? 3600,
    safetyMode: raw.safetyMode ?? true,
  };
}
type SessionState = 'idle' | 'running' | 'stopping' | 'completed' | 'failed';
interface SessionStatus { active: boolean; session?: { state: SessionState; objective?: string; iteration?: number; maxIterations?: number; startedAt?: string } }
interface SessionReport { id: string; objective: string; state: string; iterations: number; findings: number; startedAt: string; durationSeconds: number }

// =============================================================================
// Demo Data
// =============================================================================

const DEMO_CONFIG: AutopilotConfig = {
  tools: [
    { id: 'sqli-probe', name: 'SQL Injection Probe', description: 'Automated SQLi payload generation and testing', category: 'injection' },
    { id: 'xss-scanner', name: 'XSS Scanner', description: 'Reflected and stored XSS vector discovery', category: 'injection' },
    { id: 'auth-bypass', name: 'Auth Bypass Engine', description: 'JWT manipulation, session fixation, privilege escalation', category: 'authentication' },
    { id: 'ssrf-mapper', name: 'SSRF Mapper', description: 'Internal network discovery via SSRF chaining', category: 'network' },
    { id: 'rate-hammer', name: 'Rate Limit Hammer', description: 'Brute-force rate limit boundary detection', category: 'availability' },
  ],
  maxIterationsDefault: 50,
  timeoutSeconds: 3600,
  safetyMode: true,
};

const DEMO_REPORTS: SessionReport[] = [
  { id: 'rpt-001', objective: 'Identify auth bypass vectors in /api/v2/admin', state: 'completed', iterations: 34, findings: 7, startedAt: '2026-04-04T14:22:00Z', durationSeconds: 1152 },
];

// =============================================================================
// Helpers
// =============================================================================

const formatTime = (sec: number) => `${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')}`;

const stateColor = (s: SessionState) =>
  s === 'running' ? 'text-ac-cyan' : s === 'stopping' ? 'text-ac-orange' : s === 'completed' ? 'text-ac-green' : s === 'failed' ? 'text-ac-red' : 'text-ink-muted';

// =============================================================================
// Component
// =============================================================================

export default function AutopilotPage() {
  const { isEnabled: isDemo } = useDemoMode();
  const { status: apparatusStatus } = useApparatusStatus();
  const isConnected = isDemo || apparatusStatus.state === 'connected';

  const [config, setConfig] = useState<AutopilotConfig | null>(null);
  const [sessionState, setSessionState] = useState<SessionState>('idle');
  const [objective, setObjective] = useState('');
  const [maxIter, setMaxIter] = useState(50);
  const [iteration, setIteration] = useState(0);
  const [elapsedSec, setElapsedSec] = useState(0);
  const [reports, setReports] = useState<SessionReport[]>([]);
  const [launching, setLaunching] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const isActive = sessionState === 'running' || sessionState === 'stopping';

  // Fetch config + reports
  useEffect(() => {
    if (isDemo) { setConfig(DEMO_CONFIG); setMaxIter(50); setReports(DEMO_REPORTS); return; }
    apiFetch<ApparatusAutopilotConfigResponse>('/apparatus/autopilot/config')
      .then((raw) => {
        const adapted = adaptApparatusConfig(raw);
        setConfig(adapted);
        setMaxIter(adapted.maxIterationsDefault);
      })
      .catch(() => {});
    apiFetch<{ reports: SessionReport[] }>('/apparatus/autopilot/reports').then((r) => setReports(r.reports ?? [])).catch(() => {});
  }, [isDemo]);

  // Elapsed timer
  useEffect(() => {
    if (!isActive) { if (timerRef.current) clearInterval(timerRef.current); return; }
    timerRef.current = setInterval(() => setElapsedSec((s) => s + 1), 1000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [isActive]);

  const handleLaunch = useCallback(async () => {
    if (!objective.trim()) return;
    setLaunching(true);
    try {
      if (!isDemo) {
        await apiFetch('/apparatus/autopilot/start', { method: 'POST', body: JSON.stringify({ objective: objective.trim(), maxIterations: maxIter }) });
      }
      setSessionState('running');
      setIteration(0);
      setElapsedSec(0);
      setObjective('');
      if (!isDemo) {
        pollRef.current = setInterval(async () => {
          try {
            const s = await apiFetch<SessionStatus>('/apparatus/autopilot/status');
            if (s.session) {
              setSessionState(s.session.state);
              setIteration(s.session.iteration ?? 0);
            }
            if (!s.active && pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
          } catch { /* continue */ }
        }, 3000);
      }
    } finally { setLaunching(false); }
  }, [objective, maxIter, isDemo]);

  const handleStop = useCallback(async () => {
    if (!isDemo) await apiFetch('/apparatus/autopilot/stop', { method: 'POST' }).catch(() => {});
    setSessionState('stopping');
  }, [isDemo]);

  const handleKill = useCallback(async () => {
    if (!isDemo) await apiFetch('/apparatus/autopilot/kill', { method: 'POST' }).catch(() => {});
    setSessionState('idle');
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, [isDemo]);

  // Cleanup
  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  return (
    <div className="p-6 space-y-6 max-w-5xl">
      <SectionHeader
        title="AI Red Team Autopilot"
        icon={<Bot className="w-5 h-5 text-ac-cyan" />}
        size="h1"
        titleStyle={PAGE_TITLE_STYLE}
      />
      <p className="text-sm text-ink-muted max-w-2xl">
        Autonomous red team agent powered by Apparatus. Define an objective and the autopilot
        will iteratively probe, test, and report vulnerabilities.
      </p>

      {!isConnected && (
        <div className="px-4 py-3 border border-ac-orange/30 bg-ac-orange/10 text-sm text-ac-orange">
          <Stack direction="row" align="center" gap="sm">
            <AlertTriangle className="w-4 h-4" />
            <span>Apparatus is not connected. Autopilot is unavailable.</span>
          </Stack>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Config + Launch + Reports */}
        <div className="lg:col-span-2 space-y-6">
          {/* Available Tools */}
          <section className="bg-surface-card border border-border-subtle">
            <div className="px-4 py-3 border-b border-border-subtle">
              <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted font-medium">Available Tools</p>
            </div>
            <div className="p-4 space-y-2">
              {config?.tools?.map((tool) => (
                <div key={tool.id} className="flex items-start gap-3 px-3 py-2 bg-surface-subtle border border-border-subtle">
                  <Cpu className="w-4 h-4 mt-0.5 text-ac-cyan flex-shrink-0" />
                  <div>
                    <Stack direction="row" align="center" gap="sm">
                      <span className="text-sm font-medium text-ink-primary">{tool.name}</span>
                      <span className="text-[9px] uppercase tracking-wider text-ink-muted">{tool.category}</span>
                    </Stack>
                    <p className="text-xs text-ink-muted">{tool.description}</p>
                  </div>
                </div>
              )) ?? <p className="text-sm text-ink-muted">Loading...</p>}
            </div>
          </section>

          {/* Launch Form */}
          <section className="bg-surface-card border border-border-subtle p-4 space-y-4">
            <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted font-medium">Launch Session</p>
            <input
              type="text"
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              placeholder="e.g. Identify OWASP Top 10 vulnerabilities in /api/v2"
              disabled={isActive || !isConnected}
              className="w-full bg-surface-base border border-border-subtle px-3 py-2 text-sm text-ink-primary font-mono placeholder:text-ink-muted focus:outline-none focus:border-ac-cyan disabled:opacity-50"
            />
            <Stack direction="row" align="end" gap="md">
              <div>
                <label className="block text-[10px] uppercase tracking-[0.2em] text-ink-muted mb-1">Max Iterations</label>
                <input
                  type="number"
                  value={maxIter}
                  onChange={(e) => setMaxIter(Math.max(1, parseInt(e.target.value, 10) || 1))}
                  min={1} max={500}
                  disabled={isActive || !isConnected}
                  className="w-24 bg-surface-base border border-border-subtle px-3 py-2 text-sm text-ink-primary font-mono focus:outline-none focus:border-ac-cyan disabled:opacity-50"
                />
              </div>
              <Button variant="primary" disabled={!objective.trim() || isActive || !isConnected} onClick={handleLaunch}>
                <Stack direction="row" align="center" gap="sm">
                  {launching ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                  <span>Launch</span>
                </Stack>
              </Button>
            </Stack>
          </section>

          {/* Reports */}
          <section className="bg-surface-card border border-border-subtle">
            <div className="px-4 py-3 border-b border-border-subtle">
              <Stack direction="row" align="center" gap="sm">
                <FileText className="w-4 h-4 text-ink-muted" />
                <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted font-medium">Session Reports</p>
              </Stack>
            </div>
            <div className="p-4">
              {reports.length === 0 ? (
                <p className="text-sm text-ink-muted">No completed sessions yet.</p>
              ) : (
                <div className="space-y-3">
                  {reports.map((r) => (
                    <div key={r.id} className="border border-border-subtle p-4 bg-surface-subtle">
                      <p className="text-sm font-medium text-ink-primary mb-1">{r.objective}</p>
                      <Stack direction="row" align="center" gap="md" className="text-xs text-ink-muted font-mono">
                        <span className={r.state === 'completed' ? 'text-ac-green' : 'text-ac-red'}>{r.state}</span>
                        <span>{r.iterations} iterations</span>
                        <span>{r.findings} findings</span>
                        <span>{formatTime(r.durationSeconds)}</span>
                      </Stack>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>
        </div>

        {/* Right: Status Panel */}
        <div className="space-y-6">
          <section className="bg-surface-card border border-border-subtle">
            <div className="px-4 py-3 border-b border-border-subtle">
              <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted font-medium">Session Status</p>
            </div>
            <div className="p-4 space-y-4">
              <div className="flex justify-between">
                <span className="text-[10px] uppercase tracking-[0.2em] text-ink-muted">State</span>
                <span className={clsx('text-sm font-mono uppercase font-semibold', stateColor(sessionState))}>
                  {sessionState === 'running' && <Loader2 className="inline w-3 h-3 mr-1 animate-spin" />}
                  {sessionState}
                </span>
              </div>

              {isActive && (
                <>
                  <div className="flex justify-between">
                    <span className="text-[10px] uppercase tracking-[0.2em] text-ink-muted">Iteration</span>
                    <span className="text-sm font-mono text-ink-primary">{iteration} / {maxIter}</span>
                  </div>
                  <div className="h-1 bg-surface-subtle">
                    <div className="h-full bg-ac-cyan transition-all" style={{ width: `${maxIter > 0 ? (iteration / maxIter) * 100 : 0}%` }} />
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[10px] uppercase tracking-[0.2em] text-ink-muted">Elapsed</span>
                    <Stack direction="row" align="center" gap="sm" className="text-sm font-mono text-ink-primary">
                      <Clock className="w-3 h-3" />
                      <span>{formatTime(elapsedSec)}</span>
                    </Stack>
                  </div>
                  <div className="flex gap-2 pt-2 border-t border-border-subtle">
                    <Button variant="secondary" onClick={handleStop} disabled={sessionState === 'stopping'}>
                      <Stack direction="row" align="center" gap="sm"><Square className="w-3 h-3" /><span>Stop</span></Stack>
                    </Button>
                    <Button variant="magenta" onClick={handleKill}>
                      <Stack direction="row" align="center" gap="sm"><OctagonX className="w-3 h-3" /><span>Kill</span></Stack>
                    </Button>
                  </div>
                </>
              )}
            </div>
          </section>

          <section className="bg-surface-card border border-border-subtle p-4 space-y-2">
            <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted font-medium mb-2">Safety Defaults</p>
            <div className="flex justify-between text-xs font-mono">
              <span className="text-ink-muted">Safety mode</span>
              <span className="text-ink-primary"><Shield className="inline w-3 h-3 mr-1" />{config?.safetyMode ? 'ON' : 'OFF'}</span>
            </div>
            <div className="flex justify-between text-xs font-mono">
              <span className="text-ink-muted">Timeout</span>
              <span className="text-ink-primary">{config?.timeoutSeconds ?? '—'}s</span>
            </div>
            <div className="flex justify-between text-xs font-mono">
              <span className="text-ink-muted">Tools loaded</span>
              <span className="text-ink-primary">{config?.tools.length ?? 0}</span>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
