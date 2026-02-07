import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { clsx } from 'clsx';
import type { Threat, ThreatAlert } from '../../stores/horizonStore';

interface ThreatTrajectoryFeedProps {
  threats: Threat[];
  alerts: ThreatAlert[];
}

type TimelineEntry =
  | { kind: 'threat'; ts: number; data: Threat }
  | { kind: 'alert'; ts: number; data: ThreatAlert };

const MAX_ITEMS = 15;

function getRiskBadgeClass(score: number): string {
  if (score >= 80) return 'text-ac-red';
  if (score >= 60) return 'text-ac-orange';
  if (score >= 40) return 'text-ac-blue';
  return 'text-ac-green';
}

function getDotColor(entry: TimelineEntry): string {
  if (entry.kind === 'alert') {
    const sev = entry.data.severity;
    if (sev === 'CRITICAL' || sev === 'HIGH') return 'bg-ac-red';
    if (sev === 'MEDIUM') return 'bg-ac-orange';
    return 'bg-ac-blue';
  }
  const score = entry.data.riskScore;
  if (score >= 80) return 'bg-ac-red';
  if (score >= 60) return 'bg-ac-orange';
  return 'bg-ac-blue';
}

function formatTimestamp(ts: number): { display: string; iso: string } {
  const d = new Date(ts);
  return {
    iso: d.toISOString(),
    display: d.toLocaleString('en-US', {
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }),
  };
}

function ThreatEntry({ threat, ts }: { threat: Threat; ts: number }) {
  const { display, iso } = formatTimestamp(ts);
  return (
    <div className="py-2 space-y-0.5">
      <time dateTime={iso} className="text-[10px] text-[#529EEC]/60">
        {display}
      </time>
      <div className="text-sm text-white/90">{threat.indicator}</div>
      <div className="flex items-center gap-2 text-xs">
        <span className={getRiskBadgeClass(threat.riskScore)}>
          Risk: {Math.round(threat.riskScore)}
        </span>
        <span className="text-white/40">{threat.hitCount.toLocaleString()} hits</span>
        {threat.isFleetThreat && <span className="text-ac-magenta">FLEET</span>}
      </div>
    </div>
  );
}

function AlertEntry({ alert, ts }: { alert: ThreatAlert; ts: number }) {
  const { display, iso } = formatTimestamp(ts);
  return (
    <div className="py-2 space-y-0.5">
      <time dateTime={iso} className="text-[10px] text-[#529EEC]/60">
        {display}
      </time>
      <div className="text-sm text-white/90">{alert.title}</div>
      <div className="text-xs text-white/50">{alert.description}</div>
    </div>
  );
}

export function ThreatTrajectoryFeed({ threats, alerts }: ThreatTrajectoryFeedProps) {
  const timeline = useMemo<TimelineEntry[]>(() => {
    const items: TimelineEntry[] = [];

    for (const t of threats) {
      items.push({ kind: 'threat', ts: new Date(t.lastSeenAt).getTime(), data: t });
    }
    for (const a of alerts) {
      items.push({ kind: 'alert', ts: a.timestamp, data: a });
    }

    items.sort((a, b) => b.ts - a.ts);
    return items.slice(0, MAX_ITEMS);
  }, [threats, alerts]);

  return (
    <div
      className="bg-[#0A1A3A] border border-[#001E62]/60 p-0 overflow-hidden"
      role="log"
      aria-live="polite"
      aria-label="Threat trajectory feed"
    >
      {/* Header */}
      <div className="px-4 py-3 border-b border-[#001E62]/40 flex items-center justify-between">
        <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-[#529EEC]">
          THREAT TRAJECTORY
        </h3>
        <span className="status-blink">
          <span className="inline-block w-2 h-2 bg-ac-magenta" />
        </span>
      </div>

      {/* Feed body */}
      <div className="max-h-96 overflow-y-auto px-4 py-3 font-mono">
        {timeline.length === 0 ? (
          <div className="text-center text-[#529EEC]/40 py-8 font-mono text-sm">
            No threat activity detected
          </div>
        ) : (
          timeline.map((entry, index) => {
            const key =
              entry.kind === 'threat'
                ? `threat-${entry.data.id}`
                : `alert-${entry.data.id}`;

            return (
              <motion.div
                key={key}
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.03 }}
              >
                <div className="relative pl-4 border-l-2 border-ac-blue/30">
                  <div className={clsx('absolute left-[-5px] top-2 w-2 h-2', getDotColor(entry))} />
                  {entry.kind === 'threat' ? (
                    <ThreatEntry threat={entry.data} ts={entry.ts} />
                  ) : (
                    <AlertEntry alert={entry.data} ts={entry.ts} />
                  )}
                </div>
              </motion.div>
            );
          })
        )}
      </div>
    </div>
  );
}

export default ThreatTrajectoryFeed;
