import { useMemo, useState } from 'react';
import { clsx } from 'clsx';
import type { RequestTimelineEvent } from '../../hooks/useHunt';
import { Stack } from '@/ui';

type EventKind = RequestTimelineEvent['kind'];

type Lane = {
  kind: EventKind;
  label: string;
  colorClass: string; // applied as text color; svg uses currentColor
};

const LANES: Lane[] = [
  { kind: 'http_transaction', label: 'HTTP', colorClass: 'text-ac-blue' },
  { kind: 'sensor_log', label: 'Logs', colorClass: 'text-ac-navy' },
  { kind: 'signal_event', label: 'Signals', colorClass: 'text-ac-magenta' },
  { kind: 'actor_event', label: 'Actor', colorClass: 'text-ac-orange' },
  { kind: 'session_event', label: 'Session', colorClass: 'text-ac-sky-blue' },
];

const DEFAULT_MAX_GRAPH_EVENTS = 1500;

function getEventLabel(e: RequestTimelineEvent): string {
  switch (e.kind) {
    case 'http_transaction':
      return `${e.method} ${e.path} (${e.statusCode})`;
    case 'signal_event':
      return e.signalType;
    case 'sensor_log':
      return `${e.source}:${e.level}`;
    case 'actor_event':
      return `${e.eventType} ${e.riskDelta >= 0 ? '+' : ''}${e.riskDelta}`;
    case 'session_event':
      return e.eventType;
  }
}

function formatDeltaMs(t0: number, t: number): string {
  const d = Math.max(0, t - t0);
  if (d < 1_000) return `+${d}ms`;
  if (d < 60_000) return `+${(d / 1_000).toFixed(2)}s`;
  return `+${(d / 60_000).toFixed(2)}m`;
}

function eventKey(e: RequestTimelineEvent, idx: number): string {
  // stable enough for a single render; avoids leaking huge metadata into key
  return `${e.kind}:${e.timestamp}:${'requestId' in e ? e.requestId : 'na'}:${idx}`;
}

export function RequestTimelineGraph({ events }: { events: RequestTimelineEvent[] }) {
  const [selectedIdx, setSelectedIdx] = useState<number>(0);

  if (events.length > DEFAULT_MAX_GRAPH_EVENTS) {
    return (
      <div className="border border-border-subtle bg-surface-subtle/40 p-4">
        <div className="text-sm text-ink-primary font-medium">Graph disabled for large timelines</div>
        <div className="text-xs text-ink-secondary mt-1">
          {events.length} events exceeds the graph render cap ({DEFAULT_MAX_GRAPH_EVENTS}). Use Table view, reduce
          the limit, or narrow the time window.
        </div>
      </div>
    );
  }

  const model = useMemo(() => {
    const parsed = events
      .map((e) => ({ e, t: new Date(e.timestamp).getTime() }))
      .filter((x) => Number.isFinite(x.t))
      .sort((a, b) => a.t - b.t);

    const start = parsed[0]?.t ?? 0;
    const end = parsed[parsed.length - 1]?.t ?? start;
    const duration = Math.max(1, end - start);

    const laneIndexByKind = new Map<EventKind, number>();
    for (let i = 0; i < LANES.length; i += 1) laneIndexByKind.set(LANES[i]!.kind, i);

    const laneHeight = 20;
    const height = LANES.length * laneHeight;

    const nodes = parsed.map(({ e, t }, idx) => {
      const laneIdx = laneIndexByKind.get(e.kind) ?? 0;
      const x = ((t - start) / duration) * 100;
      const y = laneIdx * laneHeight + laneHeight / 2;
      return { idx, e, t, x, y, laneIdx };
    });

    const edges = nodes
      .slice(0, -1)
      .map((a, i) => {
        const b = nodes[i + 1]!;
        return { a, b };
      });

    return { nodes, edges, start, end, duration, height, laneHeight };
  }, [events]);

  const safeSelectedIdx = Math.min(Math.max(0, selectedIdx), Math.max(0, model.nodes.length - 1));
  const selected = model.nodes[safeSelectedIdx]?.e;

  if (events.length === 0) {
    return (
      <div className="text-sm text-ink-secondary">
        No events.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <Stack direction="row" align="center" justify="space-between" style={{ gap: '12px' }}>
        <Stack direction="row" align="center" gap="sm" className="flex-wrap text-[10px] font-mono text-ink-muted">
          {LANES.map((lane) => (
            <Stack
              key={lane.kind}
              direction="row"
              align="center"
              gap="sm"
              className={clsx('border border-border-subtle bg-surface-inset px-2 py-1', lane.colorClass)}
            >
              <span className="inline-block w-2 h-2 bg-current" aria-hidden="true" />
              <span>{lane.label}</span>
            </Stack>
          ))}
        </Stack>
        <div className="text-[10px] font-mono text-ink-muted whitespace-nowrap">
          {model.duration < 1_000 ? `${model.duration}ms` : `${(model.duration / 1_000).toFixed(2)}s`}
        </div>
      </Stack>

      <div className="overflow-x-auto">
        <div className="min-w-[900px]">
          <svg
            viewBox={`0 0 100 ${model.height}`}
            className="w-full h-[220px] bg-surface-inset border border-border-subtle"
            role="img"
            aria-label="Request timeline graph"
            preserveAspectRatio="none"
          >
            {/* Lane separators + labels */}
            {LANES.map((lane, i) => {
              const y = i * model.laneHeight;
              return (
                <g key={lane.kind}>
                  <line x1="0" y1={y} x2="100" y2={y} className="stroke-border-subtle" strokeWidth="0.35" />
                  <text
                    x="0.8"
                    y={y + model.laneHeight / 2}
                    className={clsx('fill-current text-[2.3px]', lane.colorClass)}
                    dominantBaseline="middle"
                  >
                    {lane.label}
                  </text>
                </g>
              );
            })}

            {/* Time rails */}
            {([0, 25, 50, 75, 100] as const).map((x) => (
              <line
                key={x}
                x1={x}
                y1="0"
                x2={x}
                y2={model.height}
                className="stroke-border-subtle"
                strokeWidth="0.25"
                opacity={x === 0 || x === 100 ? 0.75 : 0.35}
              />
            ))}

            {/* Edges */}
            {model.edges.map(({ a, b }, i) => {
              const mid = (a.x + b.x) / 2;
              const d = `M ${a.x} ${a.y} C ${mid} ${a.y}, ${mid} ${b.y}, ${b.x} ${b.y}`;
              const lane = LANES[b.laneIdx] ?? LANES[0]!;
              return (
                <path
                  key={`edge-${i}`}
                  d={d}
                  className={clsx('fill-none stroke-current', lane.colorClass)}
                  strokeWidth="0.55"
                  opacity={0.5}
                />
              );
            })}

            {/* Nodes */}
            {model.nodes.map((n) => {
              const lane = LANES[n.laneIdx] ?? LANES[0]!;
              const isSelected = n.idx === safeSelectedIdx;
              const label = getEventLabel(n.e);
              const title = `${label} ${formatDeltaMs(model.start, n.t)}`;

              return (
                <g
                  key={eventKey(n.e, n.idx)}
                  className={clsx('cursor-pointer', lane.colorClass)}
                  onClick={() => setSelectedIdx(n.idx)}
                >
                  <title>{title}</title>
                  <rect
                    x={Math.max(0, Math.min(100, n.x)) - 0.8}
                    y={n.y - 3.2}
                    width="1.6"
                    height="6.4"
                    className="fill-current"
                    opacity={isSelected ? 1 : 0.75}
                  />
                  {isSelected && (
                    <rect
                      x={Math.max(0, Math.min(100, n.x)) - 1.1}
                      y={n.y - 3.6}
                      width="2.2"
                      height="7.2"
                      className="fill-none stroke-current"
                      strokeWidth="0.35"
                      opacity={0.9}
                    />
                  )}
                </g>
              );
            })}
          </svg>
        </div>
      </div>

      {selected && (
        <div className="border border-border-subtle bg-surface-subtle/40 p-3">
          <Stack direction="row" align="flex-start" justify="space-between" style={{ gap: '12px' }}>
            <div className="min-w-0">
              <div className="text-xs font-mono text-ink-primary truncate">
                {getEventLabel(selected)}
              </div>
              <div className="text-[10px] font-mono text-ink-muted mt-1">
                {new Date(selected.timestamp).toLocaleString()} ({formatDeltaMs(model.start, new Date(selected.timestamp).getTime())})
              </div>
            </div>
            <span className="px-2 py-1 border border-border-subtle bg-surface-inset text-[10px] font-mono text-ink-secondary whitespace-nowrap">
              {selected.kind}
            </span>
          </Stack>

          <pre className="mt-3 text-[10px] font-mono text-ink-secondary whitespace-pre-wrap bg-surface-inset border border-border-subtle p-3 overflow-auto">
            {JSON.stringify(selected, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export default RequestTimelineGraph;
