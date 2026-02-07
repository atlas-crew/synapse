import React, { useMemo } from 'react';
import { Activity, Shield, AlertTriangle } from 'lucide-react';
import { clsx } from 'clsx';
import type { Threat, ThreatAlert } from '../../stores/horizonStore';
import { useRelativeTime } from '../../hooks/useRelativeTime';

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
      className="bg-[#0A1A3A] border border-[#001E62]/60 flex flex-col h-full font-mono"
      aria-labelledby="feed-heading"
    >
      <div className="px-4 py-3 border-b border-[#001E62]/60 flex items-center justify-between">
        <h2 id="feed-heading" className="text-xs font-bold tracking-[0.2em] text-[#529EEC] uppercase flex items-center gap-2">
          <span className="w-2 h-2 bg-[#529EEC] status-blink" />
          Threat Trajectory
        </h2>
        <span className="text-[10px] text-white/40 uppercase tracking-tighter">Diagnostic Feed</span>
      </div>

      <div 
        className="flex-1 overflow-y-auto max-h-[240px] p-4 space-y-6 scrollbar-thin scrollbar-thumb-ac-blue/30"
        role="log"
        aria-live="polite"
      >
        {mergedFeed.length === 0 ? (
          <div className="py-12 text-center text-white/30 text-xs">
            Awaiting signal correlation...
          </div>
        ) : (
          mergedFeed.map((item, index) => (
            <div key={`${item.type}-${item.timestamp}-${index}`} className="relative pl-6 border-l-2 border-ac-blue/20 pb-2">
              {/* Timeline Dot */}
              <div 
                className={clsx(
                  'absolute -left-[7px] top-0 w-3 h-3 border-2 border-[#0A1A3A]',
                  item.type === 'alert' ? (
                    item.data.severity === 'CRITICAL' ? 'bg-ac-magenta' : 
                    item.data.severity === 'HIGH' ? 'bg-ac-orange' : 'bg-ac-blue'
                  ) : 'bg-ac-blue'
                )} 
                aria-hidden="true"
              />

              <div className="flex justify-between items-start mb-1.5">
                <span className="text-[10px] text-white/40">
                  <ItemTime timestamp={item.timestamp} />
                </span>
                <span 
                  className={clsx(
                    'text-[9px] px-1.5 py-0.5 border font-bold uppercase tracking-tighter',
                    item.type === 'alert' ? (
                      item.data.severity === 'CRITICAL' ? 'text-ac-magenta border-ac-magenta/30 bg-ac-magenta/10' : 
                      'text-[#529EEC] border-[#529EEC]/30 bg-[#529EEC]/10'
                    ) : 'text-ac-blue-tint border-ac-blue-tint/30 bg-ac-blue-tint/10'
                  )}
                  aria-label={`Type: ${item.type === 'alert' ? item.data.type : 'threat'}`}
                >
                  {item.type === 'alert' ? item.data.type : 'threat'}
                </span>
              </div>

              <div className="space-y-1.5">
                <p className="text-sm text-white/90 font-medium leading-tight">
                  {item.type === 'alert' ? item.data.title : item.data.threatType}
                </p>
                <p className="text-xs text-white/50 leading-relaxed truncate">
                  {item.type === 'alert' ? item.data.description : `Indicator: ${item.data.indicator}`}
                </p>
              </div>

              {item.type === 'threat' && (
                <div className="mt-2 flex items-center gap-3">
                  <div className="text-[9px] text-white/40 uppercase">
                    Risk: <span className="text-white font-bold">{item.data.riskScore}%</span>
                  </div>
                  <div className="text-[9px] text-white/40 uppercase">
                    Hits: <span className="text-white font-bold">{item.data.hitCount}</span>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      <div className="px-4 py-2 bg-[#001E62]/20 border-t border-[#001E62]/40">
        <button className="w-full py-2 text-[9px] font-bold text-[#529EEC] uppercase tracking-[0.2em] hover:text-white transition-colors">
          Access Full Terminal Feed &gt;
        </button>
      </div>
    </section>
  );
};

const ItemTime: React.FC<{ timestamp: number }> = ({ timestamp }) => {
  const time = useRelativeTime(timestamp);
  return <span>{time || 'Just now'}</span>;
};

export default ThreatTrajectoryFeed;