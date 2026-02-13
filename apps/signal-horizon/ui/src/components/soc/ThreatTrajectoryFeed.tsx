import React, { useMemo } from 'react';
import { clsx } from 'clsx';
import type { Threat, ThreatAlert } from '../../stores/horizonStore';
import { useRelativeTime } from '../../hooks/useRelativeTime';
import { Button, SectionHeader, Stack, colors } from '@/ui';

interface ThreatTrajectoryFeedProps {
  threats: Threat[];
  alerts: ThreatAlert[];
}

type FeedItem = 
  | { type: 'threat'; data: Threat; timestamp: number }
  | { type: 'alert'; data: ThreatAlert; timestamp: number };

export const ThreatTrajectoryFeed: React.FC<ThreatTrajectoryFeedProps> = ({ threats, alerts }) => {
  const mergedFeed = useMemo(() => {
    const items: FeedItem[] = [
      ...threats.map(t => ({ 
        type: 'threat' as const, 
        data: t, 
        timestamp: new Date(t.lastSeenAt).getTime() 
      })),
      ...alerts.map(a => ({ 
        type: 'alert' as const, 
        data: a, 
        timestamp: a.timestamp 
      }))
    ];

    return items
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, 15);
  }, [threats, alerts]);

  return (
    <section 
      className="bg-surface-card border border-border-subtle flex flex-col h-full font-mono"
      aria-labelledby="feed-heading"
    >
      <div className="px-4 py-3 border-b border-border-subtle flex items-center justify-between">
        <SectionHeader
          titleId="feed-heading"
          title="Threat Trajectory"
          icon={<span className="w-2 h-2 bg-ac-blue dark:bg-ac-sky-blue status-blink" />}
          size="h4"
          mb="xs"
          style={{ marginBottom: 0 }}
          titleStyle={{
            fontSize: '12px',
            lineHeight: '16px',
            fontWeight: 700,
            letterSpacing: '0.2em',
            textTransform: 'uppercase',
            color: colors.blue,
          }}
        />
        <span className="text-[10px] text-ink-muted uppercase tracking-tighter">Diagnostic Feed</span>
      </div>

      <div 
        className="flex-1 overflow-y-auto max-h-[240px] p-4 space-y-6 scrollbar-thin scrollbar-thumb-ac-blue/30"
        role="log"
        aria-live="polite"
      >
        {mergedFeed.length === 0 ? (
          <div className="py-12 text-center text-ink-muted text-xs">
            Awaiting signal correlation...
          </div>
        ) : (
          mergedFeed.map((item, index) => (
            <div key={`${item.type}-${item.timestamp}-${index}`} className="relative pl-6 border-l-2 border-ac-blue/20 pb-2">
              {/* Timeline Dot */}
              <div 
                className={clsx(
                  'absolute -left-[7px] top-0 w-3 h-3 border-2 border-surface-card',
                  item.type === 'alert' ? (
                    item.data.severity === 'CRITICAL' ? 'bg-ac-magenta' : 
                    item.data.severity === 'HIGH' ? 'bg-ac-orange' : 'bg-ac-blue'
                  ) : 'bg-ac-blue'
                )} 
                aria-hidden="true"
              />

              <div className="flex justify-between items-start mb-1.5">
                <span className="text-[10px] text-ink-secondary font-medium">
                  <ItemTime timestamp={item.timestamp} />
                </span>
                <span 
                  className={clsx(
                    'text-[9px] px-1.5 py-0.5 border font-bold uppercase tracking-tighter',
                    item.type === 'alert' ? (
                      item.data.severity === 'CRITICAL' ? 'text-ac-magenta border-ac-magenta/30 bg-ac-magenta/10' : 
                      'text-ac-sky-blue border-ac-sky-blue/30 bg-ac-sky-blue/10'
                    ) : 'text-ac-blue-light border-ac-blue-light/30 bg-ac-blue-light/10'
                  )}
                  aria-label={`Type: ${item.type === 'alert' ? item.data.type : 'threat'}`}
                >
                  {item.type === 'alert' ? item.data.type : 'threat'}
                </span>
              </div>

              <div className="space-y-1.5">
                <p className="text-sm text-ink-primary font-medium leading-tight">
                  {item.type === 'alert' ? item.data.title : item.data.threatType}
                </p>
                <p className="text-xs text-ink-primary leading-relaxed truncate font-medium">
                  {item.type === 'alert' ? item.data.description : `Indicator: ${item.data.indicator}`}
                </p>
              </div>

              {item.type === 'threat' && (
                <Stack direction="row" align="center" style={{ gap: '12px' }} className="mt-2">
                  <div className="text-[9px] text-ink-secondary font-bold uppercase">
                    Risk: <span className="text-ink-primary font-bold">{item.data.riskScore}%</span>
                  </div>
                  <div className="text-[9px] text-ink-secondary font-bold uppercase">
                    Hits: <span className="text-ink-primary font-bold">{item.data.hitCount}</span>
                  </div>
                </Stack>
              )}
            </div>
          ))
        )}
      </div>

      <div className="px-4 py-2 bg-surface-subtle/50 border-t border-border-subtle">
        <Button
          variant="ghost"
          size="sm"
          fill
          style={{
            fontSize: '9px',
            letterSpacing: '0.2em',
            textTransform: 'uppercase',
            color: colors.blue,
            height: '32px',
          }}
        >
          Access Full Terminal Feed &gt;
        </Button>
      </div>
    </section>
  );
};

const ItemTime: React.FC<{ timestamp: number }> = ({ timestamp }) => {
  const time = useRelativeTime(timestamp);
  return <span>{time || 'Just now'}</span>;
};

export default ThreatTrajectoryFeed;
