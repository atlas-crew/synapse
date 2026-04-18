import { useState, useCallback, useEffect } from 'react';
import {
  AlertTriangle,
  ArrowUpCircle,
  CheckCircle2,
  Globe2,
  Plug,
  RotateCcw,
  Trash2,
  XCircle,
} from 'lucide-react';
import { useToast } from '../../../components/ui/Toast';
import { ConfirmDialog } from '../../../components/ui/ConfirmDialog';
import { MetricCard, Panel, Stack } from '@/ui';
import { InfoRow, ActionButton, formatUptime } from './shared';
import { apiFetch } from '../../../lib/api';

interface OverviewTabProps {
  sensor: any;
  systemInfo: any;
  performance?: {
    current?: {
      cpu?: number;
      memory?: number;
      disk?: number;
      rps?: number;
      latencyP99?: number;
    };
  };
  diagnostics: any;
  onRestartSensor: () => void;
}

function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function formatPercent(value: unknown, digits = 1): string {
  const numeric = asNumber(value);
  return numeric === null ? '—' : `${numeric.toFixed(digits)}%`;
}

function formatCount(value: unknown): string {
  const numeric = asNumber(value);
  if (numeric === null) return '—';
  return numeric < 10 ? numeric.toFixed(1) : Math.round(numeric).toLocaleString();
}

function formatMilliseconds(value: unknown): string {
  const numeric = asNumber(value);
  return numeric === null ? '—' : `${numeric.toFixed(0)}ms`;
}

export function OverviewTab({ sensor, systemInfo, performance, diagnostics, onRestartSensor }: OverviewTabProps) {
  const currentPerf = performance?.current || {};
  const { toast } = useToast();

  const [recentSignals, setRecentSignals] = useState<any[]>([]);
  const [signalsLoading, setSignalsLoading] = useState<boolean>(false);
  const [confirmAction, setConfirmAction] = useState<{
    title: string;
    description: string;
    confirmLabel: string;
    action: () => void;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    if (!sensor?.id) return;

    setSignalsLoading(true);
    apiFetch(`/fleet/sensors/${sensor.id}/signals?limit=25`, { method: 'GET' })
      .then((res: any) => {
        if (cancelled) return;
        setRecentSignals(Array.isArray(res?.signals) ? res.signals : []);
      })
      .catch(() => {
        if (cancelled) return;
        setRecentSignals([]);
      })
      .finally(() => {
        if (cancelled) return;
        setSignalsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [sensor?.id]);

  const requestAction = useCallback(async (endpoint: string, successMsg: string) => {
    try {
      await apiFetch(`/fleet/sensors/${sensor.id}/actions/${endpoint}`, { method: 'POST' });
      toast.success(successMsg);
    } catch (err) {
      toast.error((err as Error).message);
    }
  }, [sensor.id, toast]);

  const handleRestartServices = () => {
    setConfirmAction({
      title: 'Restart Services',
      description: 'This will restart all WAF services on this sensor. Active connections will be dropped and the sensor will be briefly unavailable. Are you sure?',
      confirmLabel: 'Restart Services',
      action: () => requestAction('restart-services', 'Services restart initiated'),
    });
  };

  const handleClearLogs = () => {
    setConfirmAction({
      title: 'Clear Logs',
      description: 'This will permanently delete all local log files on this sensor. This action cannot be undone. Are you sure?',
      confirmLabel: 'Clear Logs',
      action: () => requestAction('clear-logs', 'Log clearing initiated'),
    });
  };

  const handleRestartSensor = () => {
    setConfirmAction({
      title: 'Restart Sensor',
      description: 'This will fully restart the sensor process. The sensor will be offline during restart and all active connections will be terminated. Are you sure?',
      confirmLabel: 'Restart Sensor',
      action: onRestartSensor,
    });
  };

  return (
    <div className="space-y-6">
      <ConfirmDialog
        open={confirmAction !== null}
        title={confirmAction?.title ?? ''}
        description={confirmAction?.description ?? ''}
        confirmLabel={confirmAction?.confirmLabel}
        variant="danger"
        onConfirm={() => {
          confirmAction?.action();
          setConfirmAction(null);
        }}
        onCancel={() => setConfirmAction(null)}
      />

      {/* Resource Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <MetricCard label="CPU" value={formatPercent(currentPerf.cpu)} description="Current CPU utilization for this sensor" className="border-l-2 border-l-ac-navy" labelClassName="text-ac-navy dark:text-ac-sky-light" valueClassName="text-ac-navy dark:text-ac-sky-light" />
        <MetricCard label="Memory" value={formatPercent(currentPerf.memory)} description="Current memory usage as a percentage of total available" className="border-l-2 border-l-ac-blue" labelClassName="text-ac-blue dark:text-ac-sky-light" valueClassName="text-ac-blue dark:text-ac-sky-light" />
        <MetricCard label="Disk" value={formatPercent(currentPerf.disk, 0)} description="Disk space used on the primary partition" className="border-l-2 border-l-ac-orange" labelClassName="text-ac-orange dark:text-ac-orange" valueClassName="text-ac-orange dark:text-ac-orange" />
        <MetricCard label="REQ/SEC" value={formatCount(currentPerf.rps)} description="Requests per second currently being processed by this sensor" className="border-l-2 border-l-ac-green" labelClassName="text-ac-green dark:text-ac-green" valueClassName="text-ac-green dark:text-ac-green" />
        <MetricCard label="Latency P99" value={formatMilliseconds(currentPerf.latencyP99)} description="99th percentile response latency — 99% of requests are faster than this" className="border-l-2 border-l-ac-red" labelClassName="text-ac-red dark:text-ac-red" valueClassName="text-ac-red dark:text-ac-red" />
        <MetricCard label="Uptime" value={formatUptime(sensor.uptime || systemInfo?.uptime || 0)} description="Time since the sensor process was last restarted" className="border-l-2 border-l-ac-purple" labelClassName="text-ac-purple dark:text-ac-purple" valueClassName="text-ac-purple dark:text-ac-purple" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* System Information */}
        <Panel tone="info" padding="md">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">System Information</h3>
          <dl className="space-y-3 text-sm">
            <InfoRow label="Hostname" value={systemInfo?.hostname || sensor.name} />
            <InfoRow label="Sensor ID" value={sensor.id} />
            <InfoRow label="Version" value={sensor.version} />
            <InfoRow label="OS" value={systemInfo?.os || 'Unknown'} />
            <InfoRow label="Kernel" value={systemInfo?.kernel || 'Unknown'} />
            <InfoRow label="Architecture" value={systemInfo?.architecture || 'x86_64'} />
            <InfoRow label="Public IP" value={systemInfo?.publicIp || 'N/A'} />
            <InfoRow label="Private IP" value={systemInfo?.privateIp || 'N/A'} />
            <InfoRow label="Region" value={sensor.region} />
            <InfoRow label="Instance Type" value={systemInfo?.instanceType || 'Unknown'} />
            <InfoRow label="Last Boot" value={systemInfo?.lastBoot ? new Date(systemInfo.lastBoot).toLocaleString() : 'Unknown'} />
            <InfoRow label="Last Check-in" value={sensor.lastHeartbeat ? new Date(sensor.lastHeartbeat).toLocaleString() : 'Never'} />
          </dl>
        </Panel>

        {/* Connection Status */}
        <Panel tone="info" padding="md">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Connection Status</h3>
          <dl className="space-y-3 text-sm">
            <InfoRow label="Cloud Connection" value={sensor.connectionState} />
            <InfoRow label="Tunnel Active" value={systemInfo?.connection?.tunnelActive ? 'Yes' : 'No'} />
            <InfoRow label="Connection Latency" value={systemInfo?.connection?.latencyMs ? `${systemInfo.connection.latencyMs}ms` : 'N/A'} />
          </dl>

          {/* Key Processes */}
          <h4 className="text-md font-semibold text-ink-primary mt-6 mb-3">Key Processes</h4>
          <div className="space-y-2">
            {['atlascrew-waf', 'atlascrew-agent', 'atlascrew-collector', 'synapse-waf'].map((proc) => (
              <div key={proc} className="flex items-center justify-between">
                <span className="text-ink-secondary">{proc}</span>
                <span className="inline-flex items-center gap-2 text-xs text-ink-primary">
                  <span className="inline-block w-2 h-2 bg-status-success" />
                  Running
                </span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* Quick Actions */}
      <Panel tone="advanced" padding="md">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">Quick Actions</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <ActionButton icon={RotateCcw} label="Restart Services" onClick={handleRestartServices} />
          <ActionButton icon={Trash2} label="Clear Logs" onClick={handleClearLogs} />
          <ActionButton icon={ArrowUpCircle} label="Update Sensor" />
          <ActionButton icon={Globe2} label="Test Connectivity" />
          <ActionButton icon={Plug} label="Restart Sensor" onClick={handleRestartSensor} />
        </div>
      </Panel>

      {/* Recent Signals */}
      <Panel tone="advanced" padding="md">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-ink-primary">Recent Signals</h3>
          <div className="text-xs text-ink-muted font-mono">
            {signalsLoading ? 'loading…' : `${recentSignals.length} shown`}
          </div>
        </div>

        {recentSignals.length === 0 ? (
          <div className="text-sm text-ink-secondary">
            {signalsLoading ? 'Loading signals…' : 'No signals yet for this sensor.'}
          </div>
        ) : (
          <div className="space-y-2">
            {recentSignals.slice(0, 25).map((sig: any) => {
              const sev = String(sig.severity || '').toUpperCase();
              const sevClass =
                sev === 'CRITICAL' || sev === 'HIGH'
                  ? 'text-status-error'
                  : sev === 'MEDIUM'
                    ? 'text-status-warning'
                    : 'text-status-success';
              const ts = sig.createdAt || sig.timestamp || sig.time;
              const apparatusType = sig?.metadata?.apparatusType || sig?.metadata?.type;
              const srcIp = sig.sourceIp || sig.source_ip || sig.ip;

              return (
                <Stack
                  key={sig.id}
                  direction="row"
                  align="center"
                  justify="space-between"
                  gap="md"
                  className="border border-border-subtle bg-surface-card px-3 py-2"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-3">
                      <span className={`text-xs font-bold uppercase tracking-widest ${sevClass}`}>
                        {sev || 'UNKNOWN'}
                      </span>
                      <span className="text-xs font-mono text-ink-secondary">
                        {sig.signalType}
                      </span>
                      {apparatusType && (
                        <span className="text-[10px] font-bold uppercase tracking-widest text-ac-magenta">
                          {String(apparatusType)}
                        </span>
                      )}
                    </div>
                    {srcIp && (
                      <div className="text-xs text-ink-muted font-mono truncate">
                        {srcIp}
                      </div>
                    )}
                  </div>
                  <div className="text-xs text-ink-muted font-mono whitespace-nowrap">
                    {ts ? new Date(ts).toLocaleString() : ''}
                  </div>
                </Stack>
              );
            })}
          </div>
        )}
      </Panel>

      {/* Diagnostic Results */}
      {diagnostics && (
        <Panel tone="info" padding="md">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">
            Diagnostic Results <span className="text-sm text-ink-secondary font-normal">({new Date(diagnostics.runAt).toLocaleTimeString()})</span>
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {diagnostics.checks.map((check: any) => (
              <div key={check.name} className="flex items-start gap-2">
                <span className={check.status === 'passed' ? 'text-status-success' : check.status === 'warning' ? 'text-status-warning' : 'text-status-error'}>
                  {check.status === 'passed' ? (
                    <CheckCircle2 className="w-4 h-4" />
                  ) : check.status === 'warning' ? (
                    <AlertTriangle className="w-4 h-4" />
                  ) : (
                    <XCircle className="w-4 h-4" />
                  )}
                </span>
                <div>
                  <div className="text-sm font-medium text-ink-primary">{check.name}</div>
                  <div className="text-xs text-ink-secondary">{check.message}</div>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}
