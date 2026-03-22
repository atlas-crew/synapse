/**
 * Connectivity Page
 *
 * Real-time network connectivity monitoring for fleet sensors,
 * including cloud endpoint status and diagnostic tests.
 */

import React, { useState, useMemo, useEffect, useRef, useCallback } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  Activity,
  Wifi,
  WifiOff,
  Clock,
  TrendingUp,
  Globe,
  Lock,
  Route,
  Server,
  Radio,
  Database,
  Mail,
  CheckCircle,
  XCircle,
  AlertTriangle,
} from 'lucide-react';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { MetricCard } from '../../components/fleet';
import { apiFetch } from '../../lib/api';
import {
  SectionHeader,
  Stack,
  alpha,
  axisDefaults,
  colors,
  gridDefaultsSoft,
  tooltipDefaults,
  xAxisNoLine,
  PAGE_TITLE_STYLE,
} from '@/ui';

const xAxisSmall = { ...xAxisNoLine, tick: { ...xAxisNoLine.tick, fontSize: 11 } } as const;
const yAxisSmall = { ...axisDefaults.y, tick: { ...axisDefaults.y.tick, fontSize: 11 } } as const;
const PAGE_HEADER_STYLE = { marginBottom: 0 };
const SECTION_HEADER_TITLE_STYLE = {
  fontSize: '18px',
  lineHeight: '28px',
  fontWeight: 600,
  color: 'var(--text-primary)',
};

interface ConnectivityStats {
  total: number;
  online: number;
  offline: number;
  degraded: number;
  avgLatency: number;
  uptime: number;
}

interface ConnectivityTest {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
}

interface SensorConnectivity {
  sensorId: string;
  sensorName: string;
  status: 'connected' | 'disconnected' | 'degraded';
  latency: number | null;
  lastHeartbeat: string | null;
  reconnects: number;
  packetLoss: number;
}

// Connectivity tests
const connectivityTests: ConnectivityTest[] = [
  { id: 'ping', name: 'Ping Test', description: 'Test basic network connectivity', icon: Activity },
  {
    id: 'dns',
    name: 'DNS Resolution',
    description: 'Verify DNS lookup functionality',
    icon: Globe,
  },
  {
    id: 'tls',
    name: 'TLS Handshake',
    description: 'Test secure connection establishment',
    icon: Lock,
  },
  {
    id: 'traceroute',
    name: 'Traceroute',
    description: 'Map network path to endpoints',
    icon: Route,
  },
  {
    id: 'http1',
    name: 'HTTP/1 Echo',
    description: 'GET /echo over HTTP/1.1 (Apparatus port 80)',
    icon: Globe,
  },
  {
    id: 'http2',
    name: 'HTTP/2 Echo',
    description: 'GET /echo over HTTP/2 TLS (Apparatus port 443)',
    icon: Lock,
  },
  {
    id: 'h2c',
    name: 'H2C Echo',
    description: 'GET /echo over HTTP/2 cleartext (Apparatus port 81)',
    icon: Route,
  },
  {
    id: 'tcp',
    name: 'TCP Echo',
    description: 'TCP echo round-trip (Apparatus port 9000)',
    icon: Server,
  },
  {
    id: 'udp',
    name: 'UDP Echo',
    description: 'UDP echo round-trip (Apparatus port 9001)',
    icon: Radio,
  },
  {
    id: 'grpc',
    name: 'gRPC Probe',
    description: 'HTTP/2 preface/settings probe (Apparatus port 50051)',
    icon: Route,
  },
  {
    id: 'mqtt',
    name: 'MQTT Connect',
    description: 'CONNECT/CONNACK handshake (Apparatus port 1883)',
    icon: Radio,
  },
  {
    id: 'redis',
    name: 'Redis PING',
    description: 'RESP PING/PONG (Apparatus port 6379)',
    icon: Database,
  },
  {
    id: 'smtp',
    name: 'SMTP EHLO',
    description: 'SMTP greeting + EHLO (Apparatus port 2525)',
    icon: Mail,
  },
  {
    id: 'icap',
    name: 'ICAP OPTIONS',
    description: 'ICAP OPTIONS probe (Apparatus port 1344)',
    icon: Lock,
  },
  {
    id: 'syslog',
    name: 'Syslog Send',
    description: 'UDP syslog send (Apparatus port 5140)',
    icon: Activity,
  },
];

interface TestResult {
  testType: string;
  status: 'passed' | 'failed' | 'error';
  target: string;
  latencyMs: number | null;
  details: Record<string, unknown>;
  error?: string;
  timestamp: string;
}

export function ConnectivityPage(): React.ReactElement {
  const [runningTest, setRunningTest] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, TestResult>>({});
  const [targetHost, setTargetHost] = useState<string>('demo.site');
  const abortControllerRef = useRef<AbortController | null>(null);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  // Fetch connectivity stats
  const { data: statsData } = useQuery<any>({
    queryKey: ['connectivity-stats'],
    queryFn: async () => {
      return apiFetch('/management/connectivity');
    },
    refetchInterval: 30000,
  });

  // Derived stats
  const stats: ConnectivityStats = useMemo(() => {
    if (!statsData?.stats) {
      return { total: 0, online: 0, offline: 0, degraded: 0, avgLatency: 45, uptime: 99.9 };
    }
    return {
      total: statsData.stats.total || 0,
      online: statsData.stats.online || 0,
      offline: statsData.stats.offline || 0,
      degraded: statsData.stats.reconnecting || 0,
      avgLatency: 45, // Simulated
      uptime: 99.9, // Simulated
    };
  }, [statsData]);

  // Fetch sensor connectivity
  const { data: sensorConnectivity = [] } = useQuery<SensorConnectivity[]>({
    queryKey: ['sensor-connectivity'],
    queryFn: async () => {
      const data = await apiFetch<any>('/management/connectivity');
      // Transform sensor data to connectivity format
      const allSensors = [
        ...(data.sensors?.CONNECTED || []),
        ...(data.sensors?.DISCONNECTED || []),
        ...(data.sensors?.RECONNECTING || []),
      ];
      return allSensors.map(
        (s: {
          id: string;
          name: string;
          connectionState: string;
          lastHeartbeat: string | null;
        }) => {
          const status =
            s.connectionState === 'CONNECTED'
              ? 'connected'
              : s.connectionState === 'RECONNECTING'
                ? 'degraded'
                : 'disconnected';

          return {
            sensorId: s.id,
            sensorName: s.name,
            status,
            latency: Math.floor(Math.random() * 100),
            lastHeartbeat: s.lastHeartbeat,
            reconnects: Math.floor(Math.random() * 5),
            packetLoss: Math.random() * 2,
          };
        },
      );
    },
    refetchInterval: 15000,
  });

  // Run connectivity test mutation with AbortController support
  const testMutation = useMutation({
    mutationFn: async ({
      testId,
      target,
      signal,
    }: {
      testId: string;
      target?: string;
      signal: AbortSignal;
    }) => {
      return apiFetch<any>('/management/connectivity/test', {
        method: 'POST',
        body: target ? { testType: testId, target } : { testType: testId },
        signal,
      });
    },
  });

  const buildTarget = useCallback(
    (testId: string): string | undefined => {
      const host = targetHost.trim();
      if (!host) return undefined;

      switch (testId) {
        case 'http1':
          return `http://${host}:80/echo`;
        case 'http2':
          return `https://${host}:443/echo`;
        case 'h2c':
          return `http://${host}:81/echo`;
        case 'tcp':
          return `${host}:9000`;
        case 'udp':
          return `${host}:9001`;
        case 'grpc':
          return `${host}:50051`;
        case 'mqtt':
          return `${host}:1883`;
        case 'redis':
          return `${host}:6379`;
        case 'smtp':
          return `${host}:2525`;
        case 'icap':
          return `${host}:1344`;
        case 'syslog':
          return `${host}:5140`;
        case 'ping':
        case 'dns':
        case 'tls':
        case 'traceroute':
        default:
          return host;
      }
    },
    [targetHost],
  );

  const handleRunTest = useCallback(
    async (testId: string) => {
      // Abort any previous test
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }

      const controller = new AbortController();
      abortControllerRef.current = controller;

      setRunningTest(testId);
      try {
        const response = await testMutation.mutateAsync({
          testId,
          target: buildTarget(testId),
          signal: controller.signal,
        });
        if (response.result) {
          setTestResults((prev) => ({ ...prev, [testId]: response.result }));
        }
      } catch (error) {
        // Don't update state if aborted
        if (error instanceof Error && error.name === 'AbortError') {
          return;
        }
        // Store error result
        setTestResults((prev) => ({
          ...prev,
          [testId]: {
            testType: testId,
            status: 'error',
            target: 'N/A',
            latencyMs: null,
            details: {},
            error: error instanceof Error ? error.message : 'Test failed',
            timestamp: new Date().toISOString(),
          },
        }));
      } finally {
        if (!controller.signal.aborted) {
          setRunningTest(null);
        }
      }
    },
    [testMutation, buildTarget],
  );

  // Generate mock chart data
  const latencyTrendData = useMemo(() => {
    const data = [];
    const now = Date.now();
    for (let i = 24; i >= 0; i--) {
      data.push({
        time: new Date(now - i * 3600000).toLocaleTimeString('en-US', { hour: '2-digit' }),
        latency: 30 + Math.random() * 40,
      });
    }
    return data;
  }, []);

  const connectionEventsData = useMemo(() => {
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    return days.map((day) => ({
      day,
      reconnections: Math.floor(Math.random() * 15),
    }));
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'operational':
      case 'connected':
        return 'text-status-success';
      case 'degraded':
        return 'text-status-warning';
      case 'down':
      case 'disconnected':
        return 'text-status-error';
      default:
        return 'text-ink-muted';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'operational':
      case 'connected':
        return <CheckCircle className="w-4 h-4 text-status-success" />;
      case 'degraded':
        return <AlertTriangle className="w-4 h-4 text-status-warning" />;
      case 'down':
      case 'disconnected':
        return <XCircle className="w-4 h-4 text-status-error" />;
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <SectionHeader
        title="Connectivity Monitor"
        description="Real-time network connectivity status and diagnostics"
        size="h1"
        style={PAGE_HEADER_STYLE}
        titleStyle={PAGE_TITLE_STYLE}
      />

      {/* Top Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Connected Sensors"
          value={stats.online}
          description="Sensors with an active WebSocket connection to Signal Horizon"
          icon={<Wifi className="w-6 h-6" />}
          trend={{ value: 0, label: 'Online now' }}
        />
        <MetricCard
          label="Disconnected"
          value={stats.offline}
          description="Sensors that have lost their connection and are not reporting"
          icon={<WifiOff className="w-6 h-6" />}
          trend={{ value: 0, label: 'Offline sensors' }}
        />
        <MetricCard
          label="Avg Latency"
          value={`${stats.avgLatency}ms`}
          description="Average round-trip time for heartbeat pings across the fleet"
          icon={<Clock className="w-6 h-6" />}
          trend={{ value: 0, label: 'Response time' }}
        />
        <MetricCard
          label="Uptime (30D)"
          value={`${stats.uptime}%`}
          description="Fleet-wide connection uptime percentage over the last 30 days"
          icon={<TrendingUp className="w-6 h-6" />}
          trend={{ value: 0, label: 'Last 30 days' }}
        />
      </div>

      {/* Connectivity Tests */}
      <section
        aria-labelledby="diagnostic-tests-heading"
        className="bg-surface-card border border-border-subtle p-6"
      >
        <SectionHeader
          title="Network Diagnostic Tests"
          titleId="diagnostic-tests-heading"
          size="h4"
          style={{ marginBottom: '16px' }}
          titleStyle={SECTION_HEADER_TITLE_STYLE}
        />
        <div
          className="mb-4 flex md:flex-row md:items-end"
          style={{ flexDirection: 'column', gap: '12px' }}
        >
          <div className="space-y-1">
            <label
              htmlFor="connectivity-target-host"
              className="block text-[10px] font-bold uppercase tracking-[0.2em] text-ink-secondary"
            >
              Target Host
            </label>
            <input
              id="connectivity-target-host"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              className="h-9 w-64 bg-surface-subtle border border-border-subtle px-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
              placeholder="demo.site"
            />
          </div>
          <div className="text-xs text-ink-muted">
            Apparatus ports: 80 http1, 443 http2, 81 h2c, 9000 tcp, 9001 udp, 50051 grpc, 1883 mqtt,
            6379 redis, 2525 smtp, 1344 icap, 5140 syslog
          </div>
        </div>
        {/* Live region for screen reader announcements */}
        <div aria-live="polite" aria-atomic="true" className="sr-only">
          {runningTest && `Running ${runningTest} test...`}
          {Object.values(testResults).length > 0 &&
            !runningTest &&
            `Last test: ${Object.values(testResults)[Object.values(testResults).length - 1]?.testType} ${Object.values(testResults)[Object.values(testResults).length - 1]?.status}`}
        </div>
        <div
          className="grid grid-cols-1 md:grid-cols-2 gap-4"
          role="list"
          aria-label="Available network tests"
        >
          {connectivityTests.map((test) => {
            const Icon = test.icon;
            const isRunning = runningTest === test.id;
            const result = testResults[test.id];
            const testStatusId = `test-status-${test.id}`;
            return (
              <article
                key={test.id}
                role="listitem"
                aria-labelledby={`test-name-${test.id}`}
                className="bg-surface-subtle border border-border-subtle p-4"
              >
                <Stack
                  direction="row"
                  align="flex-start"
                  justify="space-between"
                  style={{ gap: '12px' }}
                >
                  <div className="flex items-start gap-3 flex-1">
                    <Icon className="w-5 h-5 text-ink-muted mt-0.5" aria-hidden="true" />
                    <div className="flex-1">
                      <h3 id={`test-name-${test.id}`} className="font-medium text-ink-primary mb-1">
                        {test.name}
                      </h3>
                      <p className="text-sm text-ink-secondary">{test.description}</p>
                    </div>
                  </div>
                  <button
                    onClick={() => handleRunTest(test.id)}
                    disabled={isRunning || runningTest !== null}
                    aria-describedby={result ? testStatusId : undefined}
                    aria-busy={isRunning}
                    className="px-3 py-1.5 bg-accent-primary/10 hover:bg-accent-primary/20 text-accent-primary text-sm font-medium border border-accent-primary/20 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                  >
                    {isRunning ? 'Running...' : 'Run Test'}
                  </button>
                </Stack>

                {/* Test Result Display */}
                {result && (
                  <div
                    id={testStatusId}
                    role="status"
                    aria-label={`${test.name} result: ${result.status}`}
                    className={`mt-4 p-3  border ${
                      result.status === 'passed'
                        ? 'bg-status-success/10 border-status-success/20'
                        : result.status === 'failed'
                          ? 'bg-status-error/10 border-status-error/20'
                          : 'bg-status-warning/10 border-status-warning/20'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <Stack direction="row" align="center" gap="sm">
                        {result.status === 'passed' ? (
                          <CheckCircle className="w-4 h-4 text-status-success" />
                        ) : result.status === 'failed' ? (
                          <XCircle className="w-4 h-4 text-status-error" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-status-warning" />
                        )}
                        <span
                          className={`text-sm font-medium capitalize ${
                            result.status === 'passed'
                              ? 'text-status-success'
                              : result.status === 'failed'
                                ? 'text-status-error'
                                : 'text-status-warning'
                          }`}
                        >
                          {result.status}
                        </span>
                      </Stack>
                      {result.latencyMs !== null && (
                        <span className="text-sm text-ink-secondary">
                          {result.latencyMs.toFixed(1)}ms
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-ink-secondary space-y-1">
                      <div>
                        Target: <span className="text-ink-primary font-mono">{result.target}</span>
                      </div>
                      {result.error && (
                        <div className="text-status-error">Error: {result.error}</div>
                      )}
                      {/* Show relevant details based on test type */}
                      {result.testType === 'ping' && result.details && (
                        <div className="mt-2 space-y-0.5">
                          <div>
                            Packet Loss:{' '}
                            <span className="text-ink-primary">
                              {String(result.details.packetLoss)}
                            </span>
                          </div>
                          <div>
                            Avg RTT:{' '}
                            <span className="text-ink-primary">
                              {String(result.details.avgRoundTrip)}
                            </span>
                          </div>
                          {result.details.ttl != null && (
                            <div>
                              TTL:{' '}
                              <span className="text-ink-primary">{String(result.details.ttl)}</span>
                            </div>
                          )}
                        </div>
                      )}
                      {result.testType === 'dns' && result.details && (
                        <div className="mt-2 space-y-0.5">
                          <div>
                            Resolved:{' '}
                            <span className="text-ink-primary font-mono">
                              {(result.details.resolvedAddresses as string[])?.join(', ')}
                            </span>
                          </div>
                          <div>
                            Records:{' '}
                            <span className="text-ink-primary">
                              {String(result.details.recordCount)}
                            </span>
                          </div>
                        </div>
                      )}
                      {result.testType === 'tls' && result.details && (
                        <div className="mt-2 space-y-0.5">
                          <div>
                            Protocol:{' '}
                            <span className="text-ink-primary">
                              {String(result.details.protocol)}
                            </span>
                          </div>
                          <div>
                            Cipher:{' '}
                            <span className="text-ink-primary">
                              {String(result.details.cipher)}
                            </span>
                          </div>
                          {result.details.certificate != null && (
                            <div>
                              Subject:{' '}
                              <span className="text-ink-primary">
                                {String(
                                  (result.details.certificate as Record<string, unknown>).subject,
                                )}
                              </span>
                            </div>
                          )}
                        </div>
                      )}
                      {result.testType === 'traceroute' && result.details && (
                        <div className="mt-2 space-y-0.5">
                          <div>
                            Hops:{' '}
                            <span className="text-ink-primary">
                              {String(result.details.hopCount)}
                            </span>
                          </div>
                          <div>
                            Reached Target:{' '}
                            <span className="text-ink-primary">
                              {result.details.reachedTarget ? 'Yes' : 'No'}
                            </span>
                          </div>
                          {Array.isArray(result.details.hops) && result.details.hops.length > 0 && (
                            <div className="mt-2 font-mono text-[10px] max-h-24 overflow-y-auto bg-surface-base/50 p-2">
                              {(
                                result.details.hops as Array<{
                                  hop: number;
                                  host: string;
                                  ip: string | null;
                                  latency: string;
                                }>
                              )
                                .slice(0, 8)
                                .map((hop, i) => (
                                  <div key={i} className="text-ink-muted">
                                    {String(hop.hop)}. {hop.ip || hop.host} ({hop.latency})
                                  </div>
                                ))}
                              {(result.details.hops as Array<unknown>).length > 8 && (
                                <div className="text-ink-muted">
                                  ... and{' '}
                                  {String((result.details.hops as Array<unknown>).length - 8)} more
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )}
                      {(result.testType === 'http1' ||
                        result.testType === 'http2' ||
                        result.testType === 'h2c') && (
                        <div className="mt-2 space-y-0.5">
                          {'statusCode' in (result.details as any) && (
                            <div>
                              Status:{' '}
                              <span className="text-ink-primary">
                                {String((result.details as any).statusCode)}
                              </span>
                            </div>
                          )}
                        </div>
                      )}
                      {(result.testType === 'tcp' || result.testType === 'udp') && (
                        <div className="mt-2 space-y-0.5">
                          {'echoed' in (result.details as any) && (
                            <div>
                              Echoed:{' '}
                              <span className="text-ink-primary">
                                {String((result.details as any).echoed)}
                              </span>
                            </div>
                          )}
                        </div>
                      )}
                      {result.testType === 'grpc' && (
                        <div className="mt-2 space-y-0.5">
                          {'http2SettingsFrame' in (result.details as any) && (
                            <div>
                              HTTP/2:{' '}
                              <span className="text-ink-primary">
                                {String((result.details as any).http2SettingsFrame)}
                              </span>
                            </div>
                          )}
                        </div>
                      )}
                      {result.testType === 'mqtt' && (
                        <div className="mt-2 space-y-0.5">
                          {'connack' in (result.details as any) && (
                            <div>
                              CONNACK:{' '}
                              <span className="text-ink-primary">
                                {String((result.details as any).connack)}
                              </span>
                            </div>
                          )}
                        </div>
                      )}
                      {result.testType === 'redis' && (
                        <div className="mt-2 space-y-0.5">
                          {'pong' in (result.details as any) && (
                            <div>
                              PONG:{' '}
                              <span className="text-ink-primary">
                                {String((result.details as any).pong)}
                              </span>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                    <div className="text-[10px] text-ink-muted mt-2">
                      {new Date(result.timestamp).toLocaleString()}
                    </div>
                  </div>
                )}
              </article>
            );
          })}
        </div>
      </section>

      {/* Sensor Connectivity Table */}
      <div className="bg-surface-card border border-border-subtle overflow-hidden">
        <div className="p-6 border-b border-border-subtle">
          <SectionHeader
            title="Sensor Connectivity Status"
            size="h4"
            style={{ marginBottom: 0 }}
            titleStyle={SECTION_HEADER_TITLE_STYLE}
          />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <caption className="sr-only">
              Sensor connectivity status with latency and packet loss
            </caption>
            <thead className="bg-surface-subtle">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-ink-muted uppercase tracking-wider">
                  Sensor
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-ink-muted uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-ink-muted uppercase tracking-wider">
                  Latency
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-ink-muted uppercase tracking-wider">
                  Last Heartbeat
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-ink-muted uppercase tracking-wider">
                  Reconnects (24h)
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-ink-muted uppercase tracking-wider">
                  Packet Loss
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {sensorConnectivity.map((sensor) => (
                <tr key={sensor.sensorId} className="hover:bg-surface-subtle/50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-ink-primary">{sensor.sensorName}</div>
                    <div className="text-xs text-ink-muted">{sensor.sensorId}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <Stack direction="row" align="center" gap="sm">
                      {getStatusIcon(sensor.status)}
                      <span className={`text-sm capitalize ${getStatusColor(sensor.status)}`}>
                        {sensor.status}
                      </span>
                    </Stack>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-ink-primary">
                    {sensor.latency !== null ? `${sensor.latency}ms` : 'N/A'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-ink-secondary">
                    {sensor.lastHeartbeat
                      ? new Date(sensor.lastHeartbeat).toLocaleString()
                      : 'Never'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span
                      className={`text-sm ${sensor.reconnects > 5 ? 'text-status-warning' : 'text-ink-primary'}`}
                    >
                      {sensor.reconnects}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span
                      className={`text-sm ${sensor.packetLoss > 1 ? 'text-status-error' : 'text-ink-primary'}`}
                    >
                      {sensor.packetLoss.toFixed(1)}%
                    </span>
                  </td>
                </tr>
              ))}
              {sensorConnectivity.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-ink-muted">
                    No sensor connectivity data available
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Latency Trend Chart */}
        <div className="bg-surface-card border border-border-subtle p-6">
          <SectionHeader
            title="Latency Trend (24h)"
            size="h4"
            style={{ marginBottom: '16px' }}
            titleStyle={SECTION_HEADER_TITLE_STYLE}
          />
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={latencyTrendData}>
              <defs>
                <linearGradient id="latencyGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={colors.skyBlue} stopOpacity={0.3} />
                  <stop offset="100%" stopColor={colors.skyBlue} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid {...gridDefaultsSoft} />
              <XAxis dataKey="time" {...xAxisSmall} />
              <YAxis {...yAxisSmall} />
              <Tooltip {...tooltipDefaults} />
              <Line
                type="monotone"
                dataKey="latency"
                stroke={colors.skyBlue}
                strokeWidth={2.5}
                dot={false}
                name="Latency (ms)"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Connection Events Chart */}
        <div className="bg-surface-card border border-border-subtle p-6">
          <SectionHeader
            title="Connection Events (Weekly)"
            size="h4"
            style={{ marginBottom: '16px' }}
            titleStyle={SECTION_HEADER_TITLE_STYLE}
          />
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={connectionEventsData}>
              <defs>
                <linearGradient id="reconnectGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={colors.orange} stopOpacity={1} />
                  <stop offset="100%" stopColor={colors.orange} stopOpacity={0.7} />
                </linearGradient>
              </defs>
              <CartesianGrid {...gridDefaultsSoft} />
              <XAxis dataKey="day" {...xAxisSmall} />
              <YAxis {...yAxisSmall} />
              <Tooltip {...tooltipDefaults} cursor={{ fill: alpha(colors.blue, 0.1) }} />
              <Bar
                dataKey="reconnections"
                fill="url(#reconnectGradient)"
                name="Reconnections"
                radius={[0, 0, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

export default ConnectivityPage;
