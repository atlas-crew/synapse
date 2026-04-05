/**
 * Breach Drills Page
 *
 * Launch, monitor, and debrief Apparatus breach protocol drills
 * from the Horizon dashboard. Three views:
 *   1. Library — browse available drills
 *   2. Active — real-time timeline during a running drill
 *   3. Debrief — score breakdown after drill completes
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Shield,
  Play,
  Square,
  Eye,
  Trophy,
  Clock,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ChevronRight,
  RefreshCw,
} from 'lucide-react';
import { clsx } from 'clsx';
import { apiFetch } from '../lib/api';
import { useApparatusStatus } from '../hooks/useApparatusStatus';
import { useDemoMode } from '../stores/demoModeStore';
import { Stack, SectionHeader, Button, PAGE_TITLE_STYLE } from '@/ui';

// =============================================================================
// Types (mirror apparatus-lib)
// =============================================================================

interface DrillDefinition {
  id: string;
  name: string;
  description: string;
  difficulty: 'junior' | 'senior' | 'principal';
  tags: string[];
  briefing: string;
  maxDurationSec: number;
  createdAt?: string;
}

interface DrillTimelineEvent {
  at: string;
  type: 'system' | 'metric' | 'hint' | 'user_action' | 'status_change';
  message: string;
  data?: Record<string, unknown>;
}

interface DrillScore {
  total: number;
  ttdSec?: number;
  ttmSec?: number;
  ttrSec?: number;
  penalties: number;
  bonuses: number;
}

interface DrillRun {
  runId: string;
  drillId: string;
  drillName: string;
  status: 'pending' | 'arming' | 'active' | 'stabilizing' | 'won' | 'failed' | 'cancelled';
  startedAt: string;
  finishedAt?: string;
  detectedAt?: string;
  mitigatedAt?: string;
  failureReason?: string;
  timeline: DrillTimelineEvent[];
  lastSnapshot?: Record<string, unknown>;
  score?: DrillScore;
  elapsedSec?: number;
}

interface DrillDebrief {
  runId: string;
  drillId: string;
  status: string;
  score: DrillScore;
  detectedAt?: string;
  mitigatedAt?: string;
  startedAt: string;
  finishedAt?: string;
  timeline: DrillTimelineEvent[];
}

// =============================================================================
// Constants
// =============================================================================

const DIFFICULTY_COLORS: Record<string, string> = {
  junior: 'text-ac-green border-ac-green/30 bg-ac-green/10',
  senior: 'text-ac-orange border-ac-orange/30 bg-ac-orange/10',
  principal: 'text-ac-red border-ac-red/30 bg-ac-red/10',
};

const STATUS_ICONS: Record<string, typeof Shield> = {
  pending: Clock,
  arming: AlertTriangle,
  active: AlertTriangle,
  stabilizing: RefreshCw,
  won: Trophy,
  failed: XCircle,
  cancelled: Square,
};

const TERMINAL_STATES = new Set(['won', 'failed', 'cancelled']);

const EVENT_TYPE_COLORS: Record<string, string> = {
  system: 'text-ink-muted',
  metric: 'text-ac-cyan',
  hint: 'text-ac-orange',
  user_action: 'text-ac-magenta',
  status_change: 'text-ac-blue',
};

// =============================================================================
// Demo data
// =============================================================================

const DEMO_DRILLS: DrillDefinition[] = [
  {
    id: 'cpu-spike-drill',
    name: 'CPU Spike Detection',
    description: 'Detect and respond to a sudden CPU spike caused by a cryptomining payload injection.',
    difficulty: 'junior',
    tags: ['chaos', 'detection', 'resource'],
    briefing: 'An attacker has compromised a container and deployed a crypto miner. Detect the anomaly and mitigate before service degrades.',
    maxDurationSec: 300,
  },
  {
    id: 'sqli-campaign-drill',
    name: 'SQLi Campaign Blitz',
    description: 'Identify and block a coordinated SQL injection campaign targeting multiple endpoints.',
    difficulty: 'senior',
    tags: ['sqli', 'campaign', 'blocking'],
    briefing: 'A distributed SQLi campaign is probing your API endpoints. Detect the pattern, correlate the actors, and deploy blocking rules.',
    maxDurationSec: 600,
  },
  {
    id: 'supply-chain-drill',
    name: 'Supply Chain Compromise',
    description: 'Detect a compromised dependency injecting exfiltration payloads into API responses.',
    difficulty: 'principal',
    tags: ['supply-chain', 'exfiltration', 'forensics'],
    briefing: 'A third-party library update contains a backdoor that exfiltrates session tokens. Trace the anomaly to its source and contain the blast radius.',
    maxDurationSec: 900,
  },
];

// =============================================================================
// Component
// =============================================================================

type View = 'library' | 'active' | 'debrief';

export default function BreachDrillsPage() {
  const { isEnabled: isDemo } = useDemoMode();
  const { status: apparatusStatus } = useApparatusStatus();
  const isConnected = isDemo || apparatusStatus.state === 'connected';

  const [view, setView] = useState<View>('library');
  const [drills, setDrills] = useState<DrillDefinition[]>([]);
  const [isLoadingDrills, setIsLoadingDrills] = useState(true);
  const [activeDrill, setActiveDrill] = useState<DrillRun | null>(null);
  const [debrief, setDebrief] = useState<DrillDebrief | null>(null);
  const [elapsedSec, setElapsedSec] = useState(0);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Fetch drill definitions
  useEffect(() => {
    if (isDemo) {
      setDrills(DEMO_DRILLS);
      setIsLoadingDrills(false);
      return;
    }

    apiFetch<DrillDefinition[]>('/apparatus/drills')
      .then(setDrills)
      .catch(() => setDrills([]))
      .finally(() => setIsLoadingDrills(false));
  }, [isDemo]);

  // Poll active drill status
  useEffect(() => {
    if (!activeDrill || TERMINAL_STATES.has(activeDrill.status)) {
      if (pollRef.current) clearInterval(pollRef.current);
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    if (isDemo) return; // Demo doesn't poll

    pollRef.current = setInterval(async () => {
      try {
        const status = await apiFetch<DrillRun>(
          `/apparatus/drills/${activeDrill.drillId}/status?runId=${activeDrill.runId}`,
        );
        setActiveDrill(status);

        if (TERMINAL_STATES.has(status.status)) {
          // Fetch debrief
          const d = await apiFetch<DrillDebrief>(
            `/apparatus/drills/${activeDrill.drillId}/debrief?runId=${activeDrill.runId}`,
          );
          setDebrief(d);
          setView('debrief');
        }
      } catch {
        // Continue polling
      }
    }, 2000);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [activeDrill?.drillId, activeDrill?.runId, activeDrill?.status, isDemo]);

  // Elapsed timer
  useEffect(() => {
    if (!activeDrill || TERMINAL_STATES.has(activeDrill.status)) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    timerRef.current = setInterval(() => {
      setElapsedSec((s) => s + 1);
    }, 1000);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [activeDrill?.drillId, activeDrill?.status]);

  const launchDrill = useCallback(async (drillId: string) => {
    if (isDemo) {
      // Simulate a drill run in demo mode
      const drill = DEMO_DRILLS.find((d) => d.id === drillId)!;
      setActiveDrill({
        runId: 'demo-run-1',
        drillId,
        drillName: drill.name,
        status: 'active',
        startedAt: new Date().toISOString(),
        timeline: [
          { at: new Date().toISOString(), type: 'system', message: 'Drill armed — incident injected' },
          { at: new Date().toISOString(), type: 'metric', message: 'CPU usage spiking: 12% → 78%' },
          { at: new Date().toISOString(), type: 'hint', message: 'Check resource utilization dashboards' },
        ],
      });
      setElapsedSec(0);
      setView('active');
      return;
    }

    try {
      const result = await apiFetch<{ status: string; runId: string; drillId: string; message: string }>(
        `/apparatus/drills/${drillId}/run`,
        { method: 'POST' },
      );
      setActiveDrill({
        runId: result.runId,
        drillId: result.drillId,
        drillName: drills.find((d) => d.id === drillId)?.name ?? drillId,
        status: 'arming',
        startedAt: new Date().toISOString(),
        timeline: [],
      });
      setElapsedSec(0);
      setView('active');
    } catch {
      // Error handling via toast would be nice here
    }
  }, [isDemo, drills]);

  const markDetected = useCallback(async () => {
    if (!activeDrill) return;

    if (isDemo) {
      setActiveDrill((prev) => prev ? {
        ...prev,
        detectedAt: new Date().toISOString(),
        timeline: [
          ...prev.timeline,
          { at: new Date().toISOString(), type: 'user_action', message: 'Operator marked threat as detected' },
        ],
      } : null);
      return;
    }

    try {
      await apiFetch(`/apparatus/drills/${activeDrill.drillId}/detect`, {
        method: 'POST',
        body: JSON.stringify({ runId: activeDrill.runId }),
      });
    } catch {
      // Continue
    }
  }, [activeDrill, isDemo]);

  const cancelDrill = useCallback(async () => {
    if (!activeDrill) return;

    if (isDemo) {
      setActiveDrill((prev) => prev ? { ...prev, status: 'cancelled' } : null);
      setView('library');
      return;
    }

    try {
      await apiFetch(`/apparatus/drills/${activeDrill.drillId}/cancel`, {
        method: 'POST',
        body: JSON.stringify({ runId: activeDrill.runId }),
      });
    } catch {
      // Continue
    }
  }, [activeDrill, isDemo]);

  const formatTime = (sec: number) => {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${m}:${String(s).padStart(2, '0')}`;
  };

  // ===========================================================================
  // Library View
  // ===========================================================================

  if (view === 'library') {
    return (
      <div className="p-6 space-y-6 max-w-5xl">
        <SectionHeader
          title="Breach Drills"
          icon={<Shield className="w-5 h-5 text-ac-magenta" />}
          size="h1"
          titleStyle={PAGE_TITLE_STYLE}
        />
        <p className="text-sm text-ink-muted max-w-2xl">
          Controlled breach simulations powered by Apparatus. Launch a drill, detect the incident,
          and get scored on time-to-detect, time-to-mitigate, and time-to-recover.
        </p>

        {!isConnected && (
          <div className="px-4 py-3 border border-ac-orange/30 bg-ac-orange/10 text-sm text-ac-orange">
            Apparatus is not connected. Drills are unavailable until the connection is restored.
          </div>
        )}

        {isLoadingDrills ? (
          <div className="py-12 text-center text-ink-muted">Loading drills...</div>
        ) : drills.length === 0 ? (
          <div className="py-12 text-center text-ink-muted">No drills available.</div>
        ) : (
          <div className="space-y-3">
            {drills.map((drill) => (
              <div
                key={drill.id}
                className="bg-surface-card border border-border-subtle p-5 hover:border-ac-magenta/30 transition-colors"
              >
                <Stack direction="row" align="start" justify="space-between">
                  <div className="flex-1 min-w-0">
                    <Stack direction="row" align="center" gap="sm" className="mb-1">
                      <h3 className="text-sm font-bold text-ink-primary">{drill.name}</h3>
                      <span className={clsx(
                        'text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 border',
                        DIFFICULTY_COLORS[drill.difficulty],
                      )}>
                        {drill.difficulty}
                      </span>
                    </Stack>
                    <p className="text-xs text-ink-muted mb-2">{drill.description}</p>
                    <Stack direction="row" align="center" gap="sm">
                      <Clock className="w-3 h-3 text-ink-muted" />
                      <span className="text-xs text-ink-muted">
                        Max {Math.floor(drill.maxDurationSec / 60)} min
                      </span>
                      {drill.tags.map((tag) => (
                        <span
                          key={tag}
                          className="text-[10px] px-1.5 py-0.5 bg-surface-subtle text-ink-muted border border-border-subtle"
                        >
                          {tag}
                        </span>
                      ))}
                    </Stack>
                  </div>
                  <Button
                    variant="outlined"
                    size="sm"
                    disabled={!isConnected}
                    onClick={() => launchDrill(drill.id)}
                    style={{ borderColor: 'var(--color-ac-magenta)', color: 'var(--color-ac-magenta)' }}
                  >
                    <Stack direction="row" align="center" gap="sm">
                      <Play className="w-3 h-3" />
                      <span>Launch</span>
                    </Stack>
                  </Button>
                </Stack>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  // ===========================================================================
  // Active View
  // ===========================================================================

  if (view === 'active' && activeDrill) {
    const StatusIcon = STATUS_ICONS[activeDrill.status] ?? Shield;

    return (
      <div className="p-6 space-y-6 max-w-5xl">
        <Stack direction="row" align="center" justify="space-between">
          <div>
            <Stack direction="row" align="center" gap="sm" className="mb-1">
              <StatusIcon className={clsx('w-5 h-5', activeDrill.status === 'active' ? 'text-ac-red animate-pulse' : 'text-ac-orange')} />
              <h1 className="text-lg font-light tracking-wide text-ink-primary">{activeDrill.drillName}</h1>
            </Stack>
            <p className="text-xs text-ink-muted font-mono uppercase tracking-wider">
              {activeDrill.status} &middot; {formatTime(elapsedSec)} elapsed
            </p>
          </div>
          <Stack direction="row" align="center" gap="sm">
            {!activeDrill.detectedAt && (
              <Button
                variant="magenta"
                size="sm"
                onClick={markDetected}
                style={{ backgroundColor: 'var(--color-ac-magenta)' }}
              >
                <Stack direction="row" align="center" gap="sm">
                  <Eye className="w-3 h-3" />
                  <span>Mark Detected</span>
                </Stack>
              </Button>
            )}
            {activeDrill.detectedAt && !TERMINAL_STATES.has(activeDrill.status) && (
              <span className="text-xs text-ac-green font-mono">
                <CheckCircle className="w-3 h-3 inline mr-1" />
                Detected
              </span>
            )}
            <Button
              variant="outlined"
              size="sm"
              onClick={cancelDrill}
              style={{ borderColor: 'var(--color-ink-muted)', color: 'var(--color-ink-muted)' }}
            >
              <Stack direction="row" align="center" gap="sm">
                <Square className="w-3 h-3" />
                <span>Cancel</span>
              </Stack>
            </Button>
          </Stack>
        </Stack>

        {/* Snapshot Metrics */}
        {activeDrill.lastSnapshot && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(activeDrill.lastSnapshot).map(([key, value]) => (
              <div key={key} className="bg-surface-card border border-border-subtle p-3">
                <p className="text-[10px] text-ink-muted uppercase tracking-wider">{key.replace(/([A-Z])/g, ' $1')}</p>
                <p className="text-lg font-mono text-ink-primary">{typeof value === 'number' ? value.toFixed(1) : String(value)}</p>
              </div>
            ))}
          </div>
        )}

        {/* Timeline */}
        <div className="bg-surface-card border border-border-subtle">
          <div className="px-4 py-3 border-b border-border-subtle">
            <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted font-medium">Timeline</p>
          </div>
          <div className="max-h-96 overflow-y-auto">
            {activeDrill.timeline.length === 0 ? (
              <div className="px-4 py-8 text-center text-ink-muted text-sm">Waiting for events...</div>
            ) : (
              <div className="divide-y divide-border-subtle">
                {[...activeDrill.timeline].reverse().map((event, i) => (
                  <div key={i} className="px-4 py-2.5 flex items-start gap-3">
                    <ChevronRight className={clsx('w-3 h-3 mt-0.5 flex-shrink-0', EVENT_TYPE_COLORS[event.type])} />
                    <div className="flex-1 min-w-0">
                      <p className={clsx('text-sm', EVENT_TYPE_COLORS[event.type])}>{event.message}</p>
                    </div>
                    <span className="text-[10px] text-ink-muted font-mono flex-shrink-0">
                      {new Date(event.at).toLocaleTimeString()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // ===========================================================================
  // Debrief View
  // ===========================================================================

  if (view === 'debrief' && (debrief || (isDemo && activeDrill))) {
    const score = debrief?.score ?? { total: 82, ttdSec: 34, ttmSec: 120, ttrSec: 180, penalties: 5, bonuses: 12 };
    const timeline = debrief?.timeline ?? activeDrill?.timeline ?? [];
    const status = debrief?.status ?? activeDrill?.status ?? 'won';

    return (
      <div className="p-6 space-y-6 max-w-5xl">
        <Stack direction="row" align="center" justify="space-between">
          <Stack direction="row" align="center" gap="sm">
            <Trophy className={clsx('w-6 h-6', status === 'won' ? 'text-ac-green' : 'text-ac-red')} />
            <h1 className="text-lg font-light tracking-wide text-ink-primary">
              Drill Debrief
            </h1>
            <span className={clsx(
              'text-xs font-bold uppercase tracking-wider px-2 py-0.5 border',
              status === 'won' ? 'text-ac-green border-ac-green/30 bg-ac-green/10' : 'text-ac-red border-ac-red/30 bg-ac-red/10',
            )}>
              {status}
            </span>
          </Stack>
          <Button
            variant="outlined"
            size="sm"
            onClick={() => { setView('library'); setActiveDrill(null); setDebrief(null); }}
          >
            Back to Library
          </Button>
        </Stack>

        {/* Score Breakdown */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="bg-surface-card border-t-4 border-ac-magenta p-4">
            <p className="text-[10px] text-ink-muted uppercase tracking-wider">Total Score</p>
            <p className="text-2xl font-mono font-bold text-ac-magenta">{score.total}</p>
          </div>
          <div className="bg-surface-card border border-border-subtle p-4">
            <p className="text-[10px] text-ink-muted uppercase tracking-wider">Time to Detect</p>
            <p className="text-lg font-mono text-ink-primary">{score.ttdSec != null ? `${score.ttdSec}s` : '—'}</p>
          </div>
          <div className="bg-surface-card border border-border-subtle p-4">
            <p className="text-[10px] text-ink-muted uppercase tracking-wider">Time to Mitigate</p>
            <p className="text-lg font-mono text-ink-primary">{score.ttmSec != null ? `${score.ttmSec}s` : '—'}</p>
          </div>
          <div className="bg-surface-card border border-border-subtle p-4">
            <p className="text-[10px] text-ink-muted uppercase tracking-wider">Time to Recover</p>
            <p className="text-lg font-mono text-ink-primary">{score.ttrSec != null ? `${score.ttrSec}s` : '—'}</p>
          </div>
          <div className="bg-surface-card border border-border-subtle p-4">
            <p className="text-[10px] text-ink-muted uppercase tracking-wider">Penalties</p>
            <p className="text-lg font-mono text-ac-red">-{score.penalties}</p>
          </div>
          <div className="bg-surface-card border border-border-subtle p-4">
            <p className="text-[10px] text-ink-muted uppercase tracking-wider">Bonuses</p>
            <p className="text-lg font-mono text-ac-green">+{score.bonuses}</p>
          </div>
        </div>

        {/* Full Timeline */}
        <div className="bg-surface-card border border-border-subtle">
          <div className="px-4 py-3 border-b border-border-subtle">
            <p className="text-[10px] uppercase tracking-[0.2em] text-ink-muted font-medium">
              Full Timeline ({timeline.length} events)
            </p>
          </div>
          <div className="max-h-96 overflow-y-auto divide-y divide-border-subtle">
            {timeline.map((event, i) => (
              <div key={i} className="px-4 py-2.5 flex items-start gap-3">
                <span className={clsx(
                  'text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 border flex-shrink-0 mt-0.5',
                  EVENT_TYPE_COLORS[event.type],
                  'border-current/20',
                )}>
                  {event.type}
                </span>
                <p className="text-sm text-ink-primary flex-1">{event.message}</p>
                <span className="text-[10px] text-ink-muted font-mono flex-shrink-0">
                  {new Date(event.at).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Fallback
  return null;
}
