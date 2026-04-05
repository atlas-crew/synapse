/**
 * Scenarios Page — Multi-step scenario orchestration
 *
 * Scenario library, step-by-step execution monitor, and run controls.
 */

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { Route, Play, Clock, AlertTriangle, Loader2, CheckCircle, XCircle, Layers } from 'lucide-react';
import { clsx } from 'clsx';
import { apiFetch } from '../lib/api';
import { useApparatusStatus } from '../hooks/useApparatusStatus';
import { useDemoMode } from '../stores/demoModeStore';
import { Stack, SectionHeader, Button, PAGE_TITLE_STYLE } from '@/ui';

// =============================================================================
// Types
// =============================================================================

interface ScenarioStep { id: string; action: string; params?: Record<string, unknown>; delayMs?: number }
interface Scenario { id: string; name: string; description: string; steps: ScenarioStep[]; createdAt?: string }
type ExecState = 'running' | 'completed' | 'failed';
interface ScenarioExecution { executionId: string; scenarioId: string; scenarioName: string; status: ExecState; startedAt: string; finishedAt?: string; currentStepId?: string; error?: string }

// =============================================================================
// Demo Data
// =============================================================================

const DEMO_SCENARIOS: Scenario[] = [
  {
    id: 'sc-ddos',
    name: 'DDoS Simulation',
    description: 'Volumetric and application-layer flood targeting edge WAF rate limiting and circuit breaker thresholds.',
    steps: [
      { id: 's1', action: 'Baseline capture — record normal traffic patterns' },
      { id: 's2', action: 'Volumetric ramp — increase to 10x baseline', delayMs: 5000 },
      { id: 's3', action: 'Layer 7 flood — targeted POST flood against auth endpoints', delayMs: 10000 },
      { id: 's4', action: 'Recovery validation — verify service recovery', delayMs: 5000 },
    ],
    createdAt: '2026-03-28T10:00:00Z',
  },
  {
    id: 'sc-auth',
    name: 'Auth Bypass Chain',
    description: 'Multi-stage authentication bypass: JWT manipulation, session fixation, and privilege escalation.',
    steps: [
      { id: 's1', action: 'Token enumeration — discover JWT signing algorithm' },
      { id: 's2', action: 'Algorithm confusion — attempt none/HS256 substitution', delayMs: 3000 },
      { id: 's3', action: 'Session fixation — force pre-auth session ID reuse', delayMs: 5000 },
      { id: 's4', action: 'Privilege escalation — modify role claims', delayMs: 3000 },
      { id: 's5', action: 'Report generation — compile attack path graph', delayMs: 2000 },
    ],
    createdAt: '2026-03-30T14:15:00Z',
  },
  {
    id: 'sc-exfil',
    name: 'Data Exfil Pipeline',
    description: 'Simulate data exfiltration through DNS tunneling and covert channels to test DLP controls.',
    steps: [
      { id: 's1', action: 'Recon — identify available exfiltration channels' },
      { id: 's2', action: 'DNS tunneling — encode data in DNS queries', delayMs: 8000 },
      { id: 's3', action: 'Covert HTTP — embed payloads in headers and image metadata', delayMs: 6000 },
      { id: 's4', action: 'DLP validation — verify detection and blocking', delayMs: 3000 },
    ],
    createdAt: '2026-04-01T09:30:00Z',
  },
];

// =============================================================================
// Component
// =============================================================================

export default function ScenariosPage() {
  const { isEnabled: isDemo } = useDemoMode();
  const { status: apparatusStatus } = useApparatusStatus();
  const isConnected = isDemo || apparatusStatus.state === 'connected';

  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [execution, setExecution] = useState<ScenarioExecution | null>(null);
  const [launching, setLaunching] = useState(false);
  const [elapsedSec, setElapsedSec] = useState(0);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const selected = useMemo(() => scenarios.find((s) => s.id === selectedId) ?? null, [scenarios, selectedId]);
  const isRunning = execution?.status === 'running';

  // Fetch scenarios
  useEffect(() => {
    if (isDemo) { setScenarios(DEMO_SCENARIOS); return; }
    apiFetch<Scenario[]>('/apparatus/scenarios').then(setScenarios).catch(() => {});
  }, [isDemo]);

  // Elapsed timer
  useEffect(() => {
    if (!isRunning) { if (timerRef.current) clearInterval(timerRef.current); return; }
    timerRef.current = setInterval(() => setElapsedSec((s) => s + 1), 1000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [isRunning]);

  // Cleanup
  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const handleRun = useCallback(async (scenarioId: string) => {
    setLaunching(true);
    setElapsedSec(0);
    try {
      if (isDemo) {
        setExecution({
          executionId: 'demo-exec-1',
          scenarioId,
          scenarioName: scenarios.find((s) => s.id === scenarioId)?.name ?? scenarioId,
          status: 'completed',
          startedAt: new Date().toISOString(),
          finishedAt: new Date().toISOString(),
        });
        return;
      }
      const result = await apiFetch<{ executionId: string; status: string }>(`/apparatus/scenarios/${scenarioId}/run`, { method: 'POST' });
      setExecution({
        executionId: result.executionId,
        scenarioId,
        scenarioName: scenarios.find((s) => s.id === scenarioId)?.name ?? scenarioId,
        status: 'running',
        startedAt: new Date().toISOString(),
      });
      // Poll
      pollRef.current = setInterval(async () => {
        try {
          const s = await apiFetch<ScenarioExecution>(`/apparatus/scenarios/${scenarioId}/status?executionId=${result.executionId}`);
          setExecution(s);
          if (s.status !== 'running' && pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
        } catch { /* continue */ }
      }, 2000);
    } finally { setLaunching(false); }
  }, [isDemo, scenarios]);

  const formatTime = (sec: number) => `${Math.floor(sec / 60)}:${String(sec % 60).padStart(2, '0')}`;

  return (
    <div className="p-6 space-y-6 max-w-5xl">
      <SectionHeader
        title="Scenario Orchestration"
        icon={<Route className="w-5 h-5 text-ac-cyan" />}
        size="h1"
        titleStyle={PAGE_TITLE_STYLE}
      />
      <p className="text-sm text-ink-muted max-w-2xl">
        Multi-step attack scenario engine powered by Apparatus. Select a scenario,
        review the steps, and launch coordinated simulations.
      </p>

      {!isConnected && (
        <div className="px-4 py-3 border border-ac-orange/30 bg-ac-orange/10 text-sm text-ac-orange">
          <Stack direction="row" align="center" gap="sm">
            <AlertTriangle className="w-4 h-4" />
            <span>Apparatus is not connected. Scenario execution is unavailable.</span>
          </Stack>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Library */}
        <div>
          <section className="bg-surface-card border border-border-subtle">
            <div className="px-4 py-3 border-b border-border-subtle">
              <Stack direction="row" align="center" gap="sm">
                <Layers className="w-4 h-4 text-ink-muted" />
                <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted font-medium">Scenario Library</p>
              </Stack>
            </div>
            <div className="p-2 space-y-1">
              {scenarios.length === 0 ? (
                <p className="text-sm text-ink-muted p-2">No scenarios available.</p>
              ) : scenarios.map((s) => (
                <button
                  key={s.id}
                  onClick={() => { setSelectedId(s.id); setExecution(null); }}
                  className={clsx(
                    'w-full text-left px-3 py-3 border transition-colors',
                    selectedId === s.id
                      ? 'border-ac-cyan/40 bg-ac-cyan/5'
                      : 'border-transparent hover:bg-surface-subtle',
                  )}
                >
                  <p className="text-sm font-medium text-ink-primary">{s.name}</p>
                  <p className="text-xs text-ink-muted mt-0.5 line-clamp-2">{s.description}</p>
                  <span className="text-[10px] font-mono text-ink-muted mt-1 inline-block">{s.steps.length} steps</span>
                </button>
              ))}
            </div>
          </section>
        </div>

        {/* Right: Detail + Execution */}
        <div className="lg:col-span-2 space-y-6">
          {selected ? (
            <>
              <section className="bg-surface-card border border-border-subtle">
                <div className="px-4 py-3 border-b border-border-subtle">
                  <p className="text-sm font-bold text-ink-primary">{selected.name}</p>
                </div>
                <div className="p-4 space-y-4">
                  <p className="text-sm text-ink-secondary">{selected.description}</p>

                  <div>
                    <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted font-medium mb-2">Steps</p>
                    <div className="space-y-1">
                      {selected.steps.map((step, idx) => {
                        const isCurrent = execution?.status === 'running' && execution.currentStepId === step.id;
                        return (
                          <div
                            key={step.id}
                            className={clsx(
                              'flex items-start gap-3 px-3 py-2 border',
                              isCurrent ? 'border-ac-cyan/40 bg-ac-cyan/5' : 'border-border-subtle bg-surface-subtle',
                            )}
                          >
                            <span className="flex items-center justify-center w-5 h-5 text-[10px] font-mono text-ink-muted border border-border-subtle flex-shrink-0 mt-0.5">
                              {execution?.status === 'completed' ? (
                                <CheckCircle className="w-4 h-4 text-ac-green" />
                              ) : execution?.status === 'failed' && idx === selected.steps.length - 1 ? (
                                <XCircle className="w-4 h-4 text-ac-red" />
                              ) : isCurrent ? (
                                <Loader2 className="w-4 h-4 text-ac-cyan animate-spin" />
                              ) : (
                                idx + 1
                              )}
                            </span>
                            <div>
                              <p className="text-sm text-ink-primary">{step.action}</p>
                              {step.delayMs && <p className="text-[10px] text-ink-muted font-mono">delay: {step.delayMs}ms</p>}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <Stack direction="row" align="center" gap="md" className="pt-2 border-t border-border-subtle">
                    <Button
                      variant="primary"
                      disabled={isRunning || launching || !isConnected}
                      onClick={() => handleRun(selected.id)}
                    >
                      <Stack direction="row" align="center" gap="sm">
                        {launching ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
                        <span>{isRunning ? 'Running...' : 'Run Scenario'}</span>
                      </Stack>
                    </Button>
                    {selected.createdAt && (
                      <span className="text-[10px] font-mono text-ink-muted">Created {new Date(selected.createdAt).toLocaleDateString()}</span>
                    )}
                  </Stack>
                </div>
              </section>

              {/* Execution Monitor */}
              {execution && (
                <section className="bg-surface-card border border-border-subtle">
                  <div className="px-4 py-3 border-b border-border-subtle">
                    <Stack direction="row" align="center" justify="space-between">
                      <Stack direction="row" align="center" gap="sm">
                        <Clock className="w-4 h-4 text-ink-muted" />
                        <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted font-medium">Execution</p>
                      </Stack>
                      <Stack direction="row" align="center" gap="sm">
                        <span className={clsx(
                          'text-xs font-mono uppercase font-semibold',
                          execution.status === 'completed' ? 'text-ac-green' : execution.status === 'failed' ? 'text-ac-red' : 'text-ac-cyan',
                        )}>
                          {execution.status === 'running' && <Loader2 className="inline w-3 h-3 mr-1 animate-spin" />}
                          {execution.status}
                        </span>
                        {isRunning && (
                          <span className="text-xs font-mono text-ink-muted">{formatTime(elapsedSec)}</span>
                        )}
                      </Stack>
                    </Stack>
                  </div>
                  <div className="p-4">
                    {/* Step progress bar */}
                    <div className="flex gap-1 mb-3">
                      {selected.steps.map((_, i) => (
                        <div
                          key={i}
                          className={clsx('h-1.5 flex-1',
                            execution.status === 'completed' ? 'bg-ac-green' :
                            execution.status === 'failed' && i === selected.steps.length - 1 ? 'bg-ac-red' :
                            'bg-surface-subtle',
                          )}
                        />
                      ))}
                    </div>
                    <div className="flex gap-4 text-xs font-mono text-ink-muted">
                      <span>ID: {execution.executionId}</span>
                      <span>Started: {new Date(execution.startedAt).toLocaleTimeString()}</span>
                      {execution.finishedAt && <span>Finished: {new Date(execution.finishedAt).toLocaleTimeString()}</span>}
                    </div>
                    {execution.error && (
                      <div className="mt-3 px-3 py-2 border border-ac-red/30 bg-ac-red/10 text-sm text-ac-red font-mono">
                        {execution.error}
                      </div>
                    )}
                  </div>
                </section>
              )}
            </>
          ) : (
            <section className="bg-surface-card border border-border-subtle">
              <div className="p-12 text-center">
                <Route className="w-10 h-10 text-ink-muted mx-auto mb-3 opacity-30" />
                <p className="text-sm text-ink-muted">Select a scenario from the library to view details and launch execution.</p>
              </div>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
