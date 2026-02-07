import { useState, useCallback } from 'react';
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
import { MetricCard } from '../../../components/fleet';
import { InfoRow, ActionButton, formatUptime } from './shared';

interface OverviewTabProps {
  sensor: any;
  systemInfo: any;
  diagnostics: any;
  onRestartSensor: () => void;
}

export function OverviewTab({ sensor, systemInfo, diagnostics, onRestartSensor }: OverviewTabProps) {
  const meta = sensor.metadata || {};
  const { toast, Toasts } = useToast();
  const [confirmAction, setConfirmAction] = useState<{
    title: string;
    description: string;
    confirmLabel: string;
    action: () => void;
  } | null>(null);

  const API_BASE_LOCAL = import.meta.env.VITE_API_URL || '';
  const API_KEY_LOCAL = import.meta.env.VITE_API_KEY || 'demo-key';
  const headers = {
    Authorization: `Bearer ${API_KEY_LOCAL}`,
    'Content-Type': 'application/json',
  };

  const requestAction = useCallback(async (endpoint: string, successMsg: string) => {
    try {
      const response = await fetch(`${API_BASE_LOCAL}/api/v1/fleet/sensors/${sensor.id}/actions/${endpoint}`, {
        method: 'POST',
        headers,
      });
      if (!response.ok) throw new Error(`Failed to ${endpoint}`);
      toast.success(successMsg);
    } catch (err) {
      toast.error((err as Error).message);
    }
  }, [sensor.id, toast, API_BASE_LOCAL, headers]);

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
      {Toasts}
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
        <MetricCard label="CPU" value={`${(meta.cpu ?? 0).toFixed(1)}%`} description="Current CPU utilization for this sensor" className="border-l-2 border-l-ac-navy" labelClassName="text-ac-navy dark:text-ac-sky-light" valueClassName="text-ac-navy dark:text-ac-sky-light" />
        <MetricCard label="Memory" value={`${(meta.memory ?? 0).toFixed(1)}%`} description="Current memory usage as a percentage of total available" className="border-l-2 border-l-ac-blue" labelClassName="text-ac-blue dark:text-ac-sky-light" valueClassName="text-ac-blue dark:text-ac-sky-light" />
        <MetricCard label="Disk" value={`${(meta.disk ?? 50).toFixed(0)}%`} description="Disk space used on the primary partition" className="border-l-2 border-l-ac-orange" labelClassName="text-ac-orange dark:text-ac-orange" valueClassName="text-ac-orange dark:text-ac-orange" />
        <MetricCard label="REQ/SEC" value={(meta.rps ?? 0).toLocaleString()} description="Requests per second currently being processed by this sensor" className="border-l-2 border-l-ac-green" labelClassName="text-ac-green dark:text-ac-green" valueClassName="text-ac-green dark:text-ac-green" />
        <MetricCard label="Latency P99" value={`${(meta.latency ?? 0).toFixed(0)}ms`} description="99th percentile response latency — 99% of requests are faster than this" className="border-l-2 border-l-ac-red" labelClassName="text-ac-red dark:text-ac-red" valueClassName="text-ac-red dark:text-ac-red" />
        <MetricCard label="Uptime" value={formatUptime(sensor.uptime || systemInfo?.uptime || 0)} description="Time since the sensor process was last restarted" className="border-l-2 border-l-ac-purple" labelClassName="text-ac-purple dark:text-ac-purple" valueClassName="text-ac-purple dark:text-ac-purple" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* System Information */}
        <div className="card border border-border-subtle border-t-2 border-t-ac-navy p-6">
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
        </div>

        {/* Connection Status */}
        <div className="card border border-border-subtle border-t-2 border-t-ac-blue p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Connection Status</h3>
          <dl className="space-y-3 text-sm">
            <InfoRow label="Cloud Connection" value={sensor.connectionState} />
            <InfoRow label="Tunnel Active" value={systemInfo?.connection?.tunnelActive ? 'Yes' : 'No'} />
            <InfoRow label="Connection Latency" value={systemInfo?.connection?.latencyMs ? `${systemInfo.connection.latencyMs}ms` : 'N/A'} />
          </dl>

          {/* Key Processes */}
          <h4 className="text-md font-semibold text-ink-primary mt-6 mb-3">Key Processes</h4>
          <div className="space-y-2">
            {['atlascrew-waf', 'atlascrew-agent', 'atlascrew-collector', 'synapse-pingora'].map((proc) => (
              <div key={proc} className="flex items-center justify-between">
                <span className="text-ink-secondary">{proc}</span>
                <span className="inline-flex items-center gap-2 text-xs text-ink-primary">
                  <span className="inline-block w-2 h-2 bg-status-success" />
                  Running
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="card border border-border-subtle border-t-2 border-t-ac-magenta p-6">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">Quick Actions</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <ActionButton icon={RotateCcw} label="Restart Services" onClick={handleRestartServices} />
          <ActionButton icon={Trash2} label="Clear Logs" onClick={handleClearLogs} />
          <ActionButton icon={ArrowUpCircle} label="Update Sensor" />
          <ActionButton icon={Globe2} label="Test Connectivity" />
          <ActionButton icon={Plug} label="Restart Sensor" onClick={handleRestartSensor} />
        </div>
      </div>

      {/* Diagnostic Results */}
      {diagnostics && (
        <div className="card border border-border-subtle border-t-2 border-t-info p-6">
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
        </div>
      )}
    </div>
  );
}
