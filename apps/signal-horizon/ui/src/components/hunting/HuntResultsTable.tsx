/**
 * Hunt Results Table Component
 * Results table with severity badges, timestamp formatting
 */

import { Download, ChevronDown, Database, Clock } from 'lucide-react';
import { clsx } from 'clsx';
import type { SignalResult, HuntResult } from '../../hooks/useHunt';

interface HuntResultsTableProps {
  result: HuntResult | null;
  isLoading?: boolean;
}

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'HIGH':
      return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'MEDIUM':
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'LOW':
      return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    default:
      return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
}

function getSourceLabel(source: 'postgres' | 'clickhouse' | 'hybrid'): string {
  switch (source) {
    case 'postgres':
      return 'Real-time (PostgreSQL)';
    case 'clickhouse':
      return 'Historical (ClickHouse)';
    case 'hybrid':
      return 'Hybrid Query';
    default:
      return source;
  }
}

function getSignalTypeLabel(type: string): string {
  const labels: Record<string, string> = {
    IP_THREAT: 'IP Threat',
    FINGERPRINT_THREAT: 'Fingerprint',
    CAMPAIGN_INDICATOR: 'Campaign',
    CREDENTIAL_STUFFING: 'Cred Stuffing',
    RATE_ANOMALY: 'Rate Anomaly',
    BOT_SIGNATURE: 'Bot',
    IMPOSSIBLE_TRAVEL: 'Impossible Travel',
  };
  return labels[type] || type;
}

function exportToCsv(signals: SignalResult[]) {
  const headers = [
    'ID',
    'Timestamp',
    'Tenant ID',
    'Sensor ID',
    'Signal Type',
    'Source IP',
    'Severity',
    'Confidence',
    'Event Count',
  ];

  const rows = signals.map((s) => [
    s.id,
    s.timestamp,
    s.tenantId,
    s.sensorId,
    s.signalType,
    s.sourceIp || '',
    s.severity,
    s.confidence.toFixed(2),
    s.eventCount.toString(),
  ]);

  const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `hunt-results-${new Date().toISOString().split('T')[0]}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export function HuntResultsTable({ result, isLoading }: HuntResultsTableProps) {
  if (!result && !isLoading) {
    return (
      <div className="card">
        <div className="p-8 text-center text-gray-500">
          <Database className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>Run a query to see results</p>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="card">
        <div className="p-8 text-center text-gray-500">
          <div className="animate-spin w-8 h-8 border-2 border-horizon-500 border-t-transparent rounded-full mx-auto mb-3" />
          <p>Searching...</p>
        </div>
      </div>
    );
  }

  const signals = result?.signals || [];

  return (
    <div className="card">
      <div className="card-header flex items-center justify-between">
        <div className="flex items-center gap-4">
          <h2 className="font-semibold text-white">Results</h2>
          <div className="flex items-center gap-3 text-sm text-gray-500">
            <span>{result?.total.toLocaleString()} total</span>
            <span className="text-gray-700">|</span>
            <span className="flex items-center gap-1">
              <Database className="w-3.5 h-3.5" />
              {result ? getSourceLabel(result.source) : ''}
            </span>
            <span className="text-gray-700">|</span>
            <span className="flex items-center gap-1">
              <Clock className="w-3.5 h-3.5" />
              {result?.queryTimeMs}ms
            </span>
          </div>
        </div>
        <button
          onClick={() => signals.length > 0 && exportToCsv(signals)}
          disabled={signals.length === 0}
          className="btn-ghost text-sm py-1"
        >
          <Download className="w-4 h-4 mr-1" />
          Export CSV
        </button>
      </div>

      {signals.length === 0 ? (
        <div className="p-8 text-center text-gray-500">
          <p>No signals found matching your query</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>
                  <button className="flex items-center gap-1">
                    Timestamp
                    <ChevronDown className="w-3 h-3" />
                  </button>
                </th>
                <th>Signal Type</th>
                <th>Source IP</th>
                <th>Tenant</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Events</th>
              </tr>
            </thead>
            <tbody>
              {signals.map((signal) => (
                <tr key={signal.id}>
                  <td className="text-sm text-gray-400 whitespace-nowrap">
                    {formatTimestamp(signal.timestamp)}
                  </td>
                  <td>
                    <span className="px-2 py-0.5 text-xs bg-gray-700 rounded font-mono">
                      {getSignalTypeLabel(signal.signalType)}
                    </span>
                  </td>
                  <td className="font-mono text-sm text-white">
                    {signal.sourceIp || '-'}
                  </td>
                  <td className="text-sm text-gray-400 font-mono">
                    {signal.tenantId.substring(0, 8)}...
                  </td>
                  <td>
                    <span
                      className={clsx(
                        'px-2 py-0.5 text-xs rounded border',
                        getSeverityColor(signal.severity)
                      )}
                    >
                      {signal.severity}
                    </span>
                  </td>
                  <td>
                    <div className="flex items-center gap-2">
                      <div className="w-12 h-1.5 rounded-full overflow-hidden bg-gray-700">
                        <div
                          className="h-full rounded-full bg-horizon-500"
                          style={{ width: `${signal.confidence * 100}%` }}
                        />
                      </div>
                      <span className="text-sm text-gray-400">
                        {(signal.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                  </td>
                  <td className="text-sm">{signal.eventCount.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
