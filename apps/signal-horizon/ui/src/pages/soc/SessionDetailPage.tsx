import { useMemo } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Shield, Activity, Fingerprint } from 'lucide-react';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { Breadcrumb, Button, EmptyState, SectionHeader, alpha, colors, spacing } from '@/ui';
import { useDemoMode } from '../../stores/demoModeStore';
import { fetchSessionDetail } from '../../hooks/soc/api';
import { useSocSensor } from '../../hooks/soc/useSocSensor';
import type { SocSession } from '../../types/soc';

const demoSession: SocSession = {
  sessionId: 'sess-demo-42',
  tokenHash: 'tok_demo_42',
  actorId: 'actor-demo-7',
  creationTime: Date.now() - 4 * 3600 * 1000,
  lastActivity: Date.now() - 12 * 60 * 1000,
  requestCount: 482,
  boundJa4: 'ja4-demo-9',
  boundIp: '203.0.113.88',
  isSuspicious: true,
  hijackAlerts: [
    {
      sessionId: 'sess-demo-42',
      alertType: 'fingerprint_change',
      originalValue: 'ja4-legacy',
      newValue: 'ja4-demo-9',
      timestamp: Date.now() - 42 * 60 * 1000,
      confidence: 0.84,
    },
    {
      sessionId: 'sess-demo-42',
      alertType: 'ip_drift',
      originalValue: '203.0.113.12',
      newValue: '203.0.113.88',
      timestamp: Date.now() - 22 * 60 * 1000,
      confidence: 0.73,
    },
  ],
};

export default function SessionDetailPage() {
  useDocumentTitle('SOC - Session Detail');
  const { id } = useParams();
  const { sensorId } = useSocSensor();
  const { isEnabled: isDemoMode } = useDemoMode();

  const { data, isLoading } = useQuery({
    queryKey: ['soc', 'session', sensorId, id, isDemoMode],
    queryFn: async () => {
      if (isDemoMode) return { session: demoSession };
      if (!id) throw new Error('Missing session ID');
      return fetchSessionDetail(sensorId, id);
    },
    enabled: !!id,
  });

  const session = data?.session;

  const summaryStats = useMemo(() => {
    if (!session) return [];
    return [
      { label: 'Requests', value: session.requestCount },
      { label: 'Hijack Alerts', value: session.hijackAlerts?.length ?? 0 },
      { label: 'Last Activity', value: new Date(session.lastActivity).toLocaleTimeString() },
      { label: 'Status', value: session.isSuspicious ? 'Suspicious' : 'Active' },
    ];
  }, [session]);

  if (isLoading && !session) {
    return <div className="p-6 text-ink-muted">Loading session...</div>;
  }

  if (!session) {
    return (
      <EmptyState
        icon={<AlertTriangle aria-hidden="true" />}
        title="Session Not Found"
        description="The requested session could not be found."
      />
    );
  }

  const sessionStateStyle = session.isSuspicious
    ? {
        background: alpha(colors.orange, 0.15),
        color: colors.orange,
        borderColor: alpha(colors.orange, 0.4),
      }
    : {
        background: alpha(colors.green, 0.1),
        color: colors.green,
        borderColor: alpha(colors.green, 0.4),
      };

  return (
    <div className="p-6 space-y-6">
      <Breadcrumb items={[{ label: 'Sessions', to: '/sessions' }, { label: session.sessionId }]} />
      <header className="space-y-2">
        <Link to="/sessions" className="text-sm text-link hover:text-link-hover">
          Back to Sessions
        </Link>
        <SectionHeader
          title={session.sessionId}
          description={`Created ${new Date(session.creationTime).toLocaleString()}`}
          size="h3"
          actions={
            <div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>
              <Button variant="outlined" size="sm">
                Revoke Session
              </Button>
              <span className="px-2 py-1 text-xs border" style={sessionStateStyle}>
                {session.isSuspicious ? 'Suspicious' : 'Active'}
              </span>
            </div>
          }
        />
        {session.actorId && (
          <Link
            to={`/actors/${session.actorId}`}
            className="text-sm text-link hover:text-link-hover inline-block"
          >
            View actor {session.actorId}
          </Link>
        )}
      </header>

      <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {summaryStats.map((stat) => (
          <div key={stat.label} className="card p-4">
            <p className="text-xs tracking-[0.2em] uppercase text-ink-muted">{stat.label}</p>
            <p className="text-2xl font-light text-ink-primary mt-2">{stat.value}</p>
          </div>
        ))}
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="card p-4">
          <div className="flex items-center gap-2 text-sm text-ink-muted uppercase tracking-[0.2em]">
            <Fingerprint aria-hidden="true" className="w-4 h-4" /> Identity Binding
          </div>
          <div className="mt-3 space-y-2 text-sm text-ink-secondary">
            <div>
              <span className="text-ink-muted">Token:</span>{' '}
              <span className="font-mono">{session.tokenHash}</span>
            </div>
            <div>
              <span className="text-ink-muted">JA4:</span>{' '}
              <span className="font-mono">{session.boundJa4 ?? 'Unbound'}</span>
            </div>
            <div>
              <span className="text-ink-muted">IP:</span>{' '}
              <span className="font-mono">{session.boundIp ?? 'Unbound'}</span>
            </div>
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-sm text-ink-muted uppercase tracking-[0.2em]">
            <Activity aria-hidden="true" className="w-4 h-4" /> Session Pulse
          </div>
          <div className="mt-3 text-ink-secondary text-sm">
            Last activity {new Date(session.lastActivity).toLocaleString()}. Request volume trending{' '}
            {session.requestCount > 400 ? 'elevated' : 'stable'}.
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-sm text-ink-muted uppercase tracking-[0.2em]">
            <Shield aria-hidden="true" className="w-4 h-4" /> Response Notes
          </div>
          <div className="mt-3 text-ink-secondary text-sm">
            {session.isSuspicious
              ? 'Investigate for potential hijack or token replay.'
              : 'Session remains within normal bounds.'}
          </div>
        </div>
      </section>

      <section className="card">
        <div className="card-header flex items-center justify-between">
          <div className="text-sm uppercase tracking-[0.2em] text-ink-muted">Hijack Alerts</div>
          <div className="text-xs text-ink-muted">{session.hijackAlerts?.length ?? 0} alerts</div>
        </div>
        <div className="card-body space-y-3">
          {(session.hijackAlerts?.length ?? 0) === 0 && (
            <div className="text-ink-muted">No hijack alerts for this session.</div>
          )}
          {(session.hijackAlerts ?? []).map((alert, index) => (
            <div key={`${alert.alertType}-${index}`} className="flex flex-wrap items-center gap-3">
              <div
                className="px-2 py-1 text-xs border"
                style={
                  alert.confidence > 0.8
                    ? {
                        background: alpha(colors.red, 0.15),
                        color: colors.red,
                        borderColor: alpha(colors.red, 0.4),
                      }
                    : {
                        background: alpha(colors.orange, 0.15),
                        color: colors.orange,
                        borderColor: alpha(colors.orange, 0.4),
                      }
                }
              >
                {alert.alertType.replace('_', ' ')}
              </div>
              <div className="flex-1 text-sm text-ink-secondary">
                {alert.originalValue} → {alert.newValue}
              </div>
              <div className="text-xs text-ink-muted">
                {new Date(alert.timestamp).toLocaleString()}
              </div>
              <div className="text-xs text-ink-muted">{Math.round(alert.confidence * 100)}%</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
