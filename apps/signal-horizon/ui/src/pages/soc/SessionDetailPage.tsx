import { useMemo } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Shield, Activity, Fingerprint } from 'lucide-react';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { 
  Breadcrumb, 
  Button, 
  EmptyState, 
  SectionHeader, 
  Stack, 
  alpha, 
  colors,
  Box,
  Text,
  PAGE_TITLE_STYLE,
} from '@/ui';
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
    return (
      <Box p="xl" style={{ textAlign: 'center' }}>
        <Text variant="body" color="secondary">Loading session...</Text>
      </Box>
    );
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

  return (
    <Box p="xl">
      <Stack gap="xl">
        <Breadcrumb items={[{ label: 'Sessions', to: '/sessions' }, { label: session.sessionId }]} />
        
        {/* Header */}
        <Box bg="card" border="top" borderColor="var(--ac-blue)" p="lg">
          <Stack gap="md">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => window.history.back()}
              icon={<span aria-hidden="true">←</span>}
              style={{ width: 'fit-content' }}
            >
              Back to Sessions
            </Button>
            <SectionHeader
              title={session.sessionId}
              description={`Created ${new Date(session.creationTime).toLocaleString()}`}
              size="h2"
              titleStyle={PAGE_TITLE_STYLE}
              actions={
                <Stack direction="row" align="center" gap="md">
                  <Button variant="outlined" size="sm">
                    Revoke Session
                  </Button>
                  <Box
                    px="sm"
                    py="xs"
                    style={{
                      border: '1px solid',
                      background: session.isSuspicious ? 'var(--ac-orange-dim)' : 'var(--ac-green-dim)',
                      color: session.isSuspicious ? 'var(--ac-orange)' : 'var(--ac-green)',
                      borderColor: session.isSuspicious ? alpha(colors.orange, 0.3) : alpha(colors.green, 0.3),
                    }}
                  >
                    <Text variant="tag" noMargin>{session.isSuspicious ? 'Suspicious' : 'Active'}</Text>
                  </Box>
                </Stack>
              }
            />
            {session.actorId && (
              <Link
                to={`/actors/${session.actorId}`}
                className="text-link hover:opacity-80 transition-opacity"
                style={{ fontSize: '13px', width: 'fit-content' }}
              >
                View actor {session.actorId}
              </Link>
            )}
          </Stack>
        </Box>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {summaryStats.map((stat) => (
            <Box key={stat.label} bg="card" border="subtle" p="lg">
              <Text variant="label" color="secondary" noMargin>{stat.label}</Text>
              <Text variant="h2" weight="light" noMargin style={{ marginTop: '8px' }}>
                {stat.value}
              </Text>
            </Box>
          ))}
        </div>

        {/* Details Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Box bg="card" border="subtle" p="lg">
            <Stack direction="row" align="center" gap="md" style={{ marginBottom: '16px' }}>
              <Fingerprint size={18} className="text-ink-muted" />
              <Text variant="label" color="secondary" noMargin>Identity Binding</Text>
            </Stack>
            <Stack gap="sm">
              <Box>
                <Text variant="caption" color="secondary">Token</Text>
                <Text variant="code" noMargin>{session.tokenHash}</Text>
              </Box>
              <Box>
                <Text variant="caption" color="secondary">JA4</Text>
                <Text variant="code" noMargin>{session.boundJa4 ?? 'Unbound'}</Text>
              </Box>
              <Box>
                <Text variant="caption" color="secondary">IP</Text>
                <Text variant="code" noMargin>{session.boundIp ?? 'Unbound'}</Text>
              </Box>
            </Stack>
          </Box>
          
          <Box bg="card" border="subtle" p="lg">
            <Stack direction="row" align="center" gap="md" style={{ marginBottom: '16px' }}>
              <Activity size={18} className="text-ink-muted" />
              <Text variant="label" color="secondary" noMargin>Session Pulse</Text>
            </Stack>
            <Text variant="body" color="secondary">
              Last activity {new Date(session.lastActivity).toLocaleString()}. Request volume trending{' '}
              <Text as="span" weight="medium" color={session.requestCount > 400 ? 'error' : 'success'}>
                {session.requestCount > 400 ? 'elevated' : 'stable'}
              </Text>.
            </Text>
          </Box>

          <Box bg="card" border="subtle" p="lg">
            <Stack direction="row" align="center" gap="md" style={{ marginBottom: '16px' }}>
              <Shield size={18} className="text-ink-muted" />
              <Text variant="label" color="secondary" noMargin>Response Notes</Text>
            </Stack>
            <Text variant="body" color="secondary">
              {session.isSuspicious
                ? 'Investigate for potential hijack or token replay.'
                : 'Session remains within normal bounds.'}
            </Text>
          </Box>
        </div>

        {/* Hijack Alerts */}
        <Box bg="card" border="subtle">
          <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
            <Stack direction="row" align="center" justify="space-between">
              <Text variant="label" color="secondary" noMargin>Hijack Alerts</Text>
              <Text variant="caption" color="secondary" noMargin>{session.hijackAlerts?.length ?? 0} alerts</Text>
            </Stack>
          </Box>
          <Box p="lg">
            <Stack gap="lg">
              {(session.hijackAlerts?.length ?? 0) === 0 && (
                <Text variant="body" color="secondary" align="center">No hijack alerts for this session.</Text>
              )}
              {(session.hijackAlerts ?? []).map((alert, index) => (
                <Stack
                  key={`${alert.alertType}-${index}`}
                  direction="row"
                  align="center"
                  gap="lg"
                  wrap
                >
                  <Box
                    px="sm"
                    py="xs"
                    style={{
                      width: 'fit-content',
                      border: '1px solid',
                      background: alert.confidence > 0.8 ? 'var(--ac-red-dim)' : 'var(--ac-orange-dim)',
                      color: alert.confidence > 0.8 ? 'var(--ac-red)' : 'var(--ac-orange)',
                      borderColor: alert.confidence > 0.8 ? alpha(colors.red, 0.3) : alpha(colors.orange, 0.3),
                      flexShrink: 0,
                    }}
                  >
                    <Text variant="tag" noMargin>{alert.alertType.replace('_', ' ')}</Text>
                  </Box>
                  <Text variant="body" color="secondary" style={{ flex: 1 }}>
                    {alert.originalValue} → {alert.newValue}
                  </Text>
                  <Text variant="caption" color="secondary" noMargin>
                    {new Date(alert.timestamp).toLocaleString()}
                  </Text>
                  <Text variant="caption" color="secondary" noMargin>
                    {Math.round(alert.confidence * 100)}%
                  </Text>
                </Stack>
              ))}
            </Stack>
          </Box>
        </Box>
      </Stack>
    </Box>
  );
}
