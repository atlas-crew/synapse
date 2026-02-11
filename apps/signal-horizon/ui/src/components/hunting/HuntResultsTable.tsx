/**
 * Hunt Results Table Component
 * Results table with severity badges, timestamp formatting
 */

import React, { useState } from 'react';
import { Download, ChevronDown, ChevronRight, Database, Clock, ExternalLink, Terminal } from 'lucide-react';
import { clsx } from 'clsx';
import type { SignalResult, HuntResult } from '../../hooks/useHunt';
import { getCyberChefUrl, CyberChefRecipes } from '../../utils/cyberchef';
import { SectionHeader, Spinner } from '@/ui';

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
      return 'bg-ac-red/15 text-ac-red border border-ac-red/40';
    case 'HIGH':
      return 'bg-ac-orange/20 text-ac-orange border border-ac-orange/40';
    case 'MEDIUM':
      return 'bg-ac-orange/10 text-ac-orange border border-ac-orange/30';
    case 'LOW':
      return 'bg-ac-blue/10 text-ac-blue border border-ac-blue/30';
    default:
      return 'bg-surface-subtle text-ink-muted border border-border-subtle';
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
    TEMPLATE_DISCOVERY: 'API Discovery',
    SCHEMA_VIOLATION: 'Schema Change',
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
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (!result && !isLoading) {
    return (
      <div className="card">
        <div className="p-8 text-center text-ink-muted">
          <Database className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>Run a query to see results</p>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="card">
        <div className="p-8 text-center text-ink-muted">
          <div className="mx-auto mb-3 w-fit">
            <Spinner size={32} color="#0057B7" />
          </div>
          <p>Searching...</p>
        </div>
      </div>
    );
  }

  const signals = result?.signals || [];

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  return (
    <div className="card">
      <div className="card-header flex items-center justify-between">
        <div className="flex items-center gap-4">
          <SectionHeader
            title="Results"
            size="h4"
            mb="xs"
            style={{ marginBottom: 0 }}
            titleStyle={{ fontSize: '16px', lineHeight: '24px', fontWeight: 500 }}
            actions={(
              <div className="flex items-center gap-3 text-sm text-ink-muted">
                <span>{result?.total.toLocaleString()} total</span>
                <span className="text-ink-muted">|</span>
                <span className="flex items-center gap-1">
                  <Database className="w-3.5 h-3.5" />
                  {result ? getSourceLabel(result.source) : ''}
                </span>
                <span className="text-ink-muted">|</span>
                <span className="flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5" />
                  {result?.queryTimeMs}ms
                </span>
              </div>
            )}
          />
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
        <div className="p-8 text-center text-ink-muted">
          <p>No signals found matching your query</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="data-table">
            <caption className="sr-only">Threat hunting query results with severity and metadata</caption>
            <thead>
              <tr>
                <th className="w-10"></th>
                <th>
                  <button className="flex items-center gap-1">
                    Timestamp
                    <ChevronDown className="w-3 h-3" />
                  </button>
                </th>
                <th>Signal Type</th>
                <th>Source IP</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Events</th>
              </tr>
            </thead>
            <tbody>
              {signals.map((signal) => (
                <React.Fragment key={signal.id}>
                  <tr 
                    className={clsx(
                      "cursor-pointer hover:bg-surface-subtle transition-colors focus:outline-none focus:bg-surface-subtle focus:ring-1 focus:ring-inset focus:ring-ac-blue",
                      expandedId === signal.id && "bg-surface-subtle"
                    )}
                    onClick={() => toggleExpand(signal.id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        toggleExpand(signal.id);
                      }
                    }}
                    tabIndex={0}
                    role="button"
                    aria-expanded={expandedId === signal.id}
                    aria-label={`${getSignalTypeLabel(signal.signalType)} from ${signal.sourceIp || 'unknown IP'} at ${formatTimestamp(signal.timestamp)}`}
                  >
                    <td className="text-center">
                      {expandedId === signal.id ? (
                        <ChevronDown className="w-4 h-4 text-ink-muted" aria-hidden="true" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-ink-muted" aria-hidden="true" />
                      )}
                    </td>
                    <td className="text-sm text-ink-muted whitespace-nowrap">
                      {formatTimestamp(signal.timestamp)}
                    </td>
                    <td>
                      <span className="px-2 py-0.5 text-xs bg-surface-subtle border border-border-subtle font-mono">
                        {getSignalTypeLabel(signal.signalType)}
                      </span>
                    </td>
                    <td className="font-mono text-sm text-ink-primary">
                      {signal.sourceIp || '-'}
                    </td>
                    <td>
                      <span
                        className={clsx(
                          'px-2 py-0.5 text-xs',
                          getSeverityColor(signal.severity)
                        )}
                      >
                        {signal.severity}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="w-12 h-1.5 overflow-hidden bg-surface-subtle">
                          <div
                            className="h-full bg-ac-blue"
                            style={{ width: `${signal.confidence * 100}%` }}
                          />
                        </div>
                        <span className="text-sm text-ink-muted">
                          {(signal.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                    </td>
                    <td className="text-sm">{signal.eventCount.toLocaleString()}</td>
                  </tr>
                  {expandedId === signal.id && (
                    <tr className="bg-surface-inset">
                      <td colSpan={7} className="p-0">
                        <div className="p-4 border-t border-border-subtle space-y-4">
                          <div className="grid grid-cols-2 gap-8">
                            <div className="space-y-3">
                              <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
                                Signal Metadata
                              </h3>
                              <div className="bg-surface-base border border-border-subtle p-3">
                                <pre className="text-xs font-mono text-ink-secondary overflow-auto max-h-48">
                                  {JSON.stringify(signal.metadata || {}, null, 2)}
                                </pre>
                              </div>
                            </div>
                            <div className="space-y-3">
                              <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
                                SOC Actions
                              </h3>
                              <div className="flex flex-wrap gap-3">
                                <a
                                  href={getCyberChefUrl(
                                    JSON.stringify(signal.metadata || {}),
                                    CyberChefRecipes.MAGIC
                                  )}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="flex items-center gap-2 px-3 py-2 bg-surface-base border border-border-subtle hover:border-ac-blue text-sm transition-colors group"
                                >
                                  <Terminal className="w-4 h-4 text-ac-blue" />
                                  <span>Analyze Metadata in CyberChef</span>
                                  <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                                </a>
                                
                                {signal.anonFingerprint && (
                                  <a
                                    href={getCyberChefUrl(
                                      signal.anonFingerprint,
                                      CyberChefRecipes.MAGIC
                                    )}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="flex items-center gap-2 px-3 py-2 bg-surface-base border border-border-subtle hover:border-ac-blue text-sm transition-colors group"
                                  >
                                    <Terminal className="w-4 h-4 text-ac-blue" />
                                    <span>Analyze Fingerprint</span>
                                    <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                                  </a>
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
