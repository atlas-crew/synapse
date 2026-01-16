/**
 * SessionSearchResults Component
 *
 * Displays session search results across all sensors in a tabular format.
 * Supports session revocation and actor banning actions.
 */

import { useState, useMemo, useCallback } from 'react';
import type {
  GlobalSessionSearchResult,
  SensorSession,
} from '../../hooks/fleet/useSessionSearch';

// =============================================================================
// Type Definitions
// =============================================================================

export interface SessionSearchResultsProps {
  /** Search results to display */
  results: GlobalSessionSearchResult;
  /** Callback when revoke button is clicked */
  onRevokeSession?: (sessionId: string, sensorId: string) => void;
  /** Callback when ban button is clicked */
  onBanActor?: (actorId: string) => void;
  /** Callback when session row is clicked */
  onSessionClick?: (session: SensorSession, sensorId: string) => void;
  /** Whether actions are currently in progress */
  isActionPending?: boolean;
  /** Class name for the container */
  className?: string;
}

interface FlattenedSession extends SensorSession {
  sensorId: string;
  sensorName: string;
}

type SortField = 'riskScore' | 'lastSeen' | 'requestCount' | 'sensorName' | 'clientIp';
type SortDirection = 'asc' | 'desc';

// =============================================================================
// Helper Components
// =============================================================================

function RiskBadge({ score }: { score: number }) {
  let colorClass = 'bg-ac-green/20 text-ac-green';
  let label = 'Low';

  if (score >= 76) {
    colorClass = 'bg-ac-red/20 text-ac-red';
    label = 'Critical';
  } else if (score >= 51) {
    colorClass = 'bg-ac-orange/20 text-ac-orange';
    label = 'High';
  } else if (score >= 26) {
    colorClass = 'bg-ac-yellow/20 text-ac-yellow';
    label = 'Medium';
  }

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium ${colorClass}`}>
      <span className="font-mono">{score}</span>
      <span className="text-[10px]">{label}</span>
    </span>
  );
}

function BlockedBadge({ reason }: { reason?: string }) {
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium bg-ac-red/20 text-ac-red"
      title={reason}
    >
      BLOCKED
    </span>
  );
}

function formatTimeAgo(dateStr: string): string {
  const date = new Date(dateStr);
  const now = Date.now();
  const diffMs = now - date.getTime();

  const seconds = Math.floor(diffMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return `${seconds}s ago`;
}

// =============================================================================
// Main Component
// =============================================================================

export function SessionSearchResults({
  results,
  onRevokeSession,
  onBanActor,
  onSessionClick,
  isActionPending = false,
  className = '',
}: SessionSearchResultsProps) {
  const [sortField, setSortField] = useState<SortField>('riskScore');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [expandedSensors, setExpandedSensors] = useState<Set<string>>(new Set());
  const [viewMode, setViewMode] = useState<'grouped' | 'flat'>('flat');
  const [selectedSession, setSelectedSession] = useState<string | null>(null);

  // Flatten sessions for flat view
  const flattenedSessions = useMemo((): FlattenedSession[] => {
    const sessions: FlattenedSession[] = [];
    for (const result of results.results) {
      for (const session of result.sessions) {
        sessions.push({
          ...session,
          sensorId: result.sensorId,
          sensorName: result.sensorName,
        });
      }
    }
    return sessions;
  }, [results.results]);

  // Sort flattened sessions
  const sortedSessions = useMemo(() => {
    const sorted = [...flattenedSessions];
    sorted.sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case 'riskScore':
          comparison = a.riskScore - b.riskScore;
          break;
        case 'lastSeen':
          comparison = new Date(a.lastSeen).getTime() - new Date(b.lastSeen).getTime();
          break;
        case 'requestCount':
          comparison = a.requestCount - b.requestCount;
          break;
        case 'sensorName':
          comparison = a.sensorName.localeCompare(b.sensorName);
          break;
        case 'clientIp':
          comparison = a.clientIp.localeCompare(b.clientIp);
          break;
      }
      return sortDirection === 'desc' ? -comparison : comparison;
    });
    return sorted;
  }, [flattenedSessions, sortField, sortDirection]);

  const handleSort = useCallback((field: SortField) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  }, [sortField]);

  const toggleSensorExpanded = useCallback((sensorId: string) => {
    setExpandedSensors((prev) => {
      const next = new Set(prev);
      if (next.has(sensorId)) {
        next.delete(sensorId);
      } else {
        next.add(sensorId);
      }
      return next;
    });
  }, []);

  const handleSessionClick = useCallback((session: FlattenedSession) => {
    setSelectedSession(session.id);
    onSessionClick?.(session, session.sensorId);
  }, [onSessionClick]);

  const SortHeader = ({ field, label }: { field: SortField; label: string }) => (
    <th
      className="px-4 py-3 text-left text-xs font-medium text-ink-secondary uppercase tracking-wider cursor-pointer hover:bg-surface-raised/50"
      onClick={() => handleSort(field)}
    >
      <div className="flex items-center gap-1">
        {label}
        {sortField === field && (
          <span className="text-ac-blue">{sortDirection === 'asc' ? '\u2191' : '\u2193'}</span>
        )}
      </div>
    </th>
  );

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Summary Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-6 text-sm">
          <span className="text-ink-secondary">
            <span className="font-medium text-ink-primary">{results.totalSessions}</span> sessions found
          </span>
          <span className="text-ink-secondary">
            across <span className="font-medium text-ink-primary">{results.successfulSensors}</span> sensors
          </span>
          {results.failedSensors > 0 && (
            <span className="text-ac-orange">
              {results.failedSensors} sensor{results.failedSensors > 1 ? 's' : ''} failed
            </span>
          )}
          <span className="text-ink-tertiary">
            ({results.searchDurationMs}ms)
          </span>
        </div>

        {/* View Mode Toggle */}
        <div className="flex items-center gap-2">
          <button
            className={`px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === 'flat'
                ? 'bg-ac-blue text-white'
                : 'bg-surface-raised text-ink-secondary hover:text-ink-primary'
            }`}
            onClick={() => setViewMode('flat')}
          >
            Flat View
          </button>
          <button
            className={`px-3 py-1.5 text-xs font-medium transition-colors ${
              viewMode === 'grouped'
                ? 'bg-ac-blue text-white'
                : 'bg-surface-raised text-ink-secondary hover:text-ink-primary'
            }`}
            onClick={() => setViewMode('grouped')}
          >
            By Sensor
          </button>
        </div>
      </div>

      {/* Results Table */}
      {viewMode === 'flat' ? (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-border-default">
              <thead className="bg-surface-raised">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-secondary uppercase tracking-wider">
                    Session
                  </th>
                  <SortHeader field="sensorName" label="Sensor" />
                  <SortHeader field="clientIp" label="Client IP" />
                  <SortHeader field="riskScore" label="Risk" />
                  <SortHeader field="requestCount" label="Requests" />
                  <SortHeader field="lastSeen" label="Last Seen" />
                  <th className="px-4 py-3 text-left text-xs font-medium text-ink-secondary uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-ink-secondary uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-default">
                {sortedSessions.map((session) => (
                  <tr
                    key={`${session.sensorId}-${session.id}`}
                    className={`hover:bg-surface-raised/50 cursor-pointer transition-colors ${
                      selectedSession === session.id ? 'bg-ac-blue/10' : ''
                    }`}
                    onClick={() => handleSessionClick(session)}
                  >
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="text-sm font-mono text-ink-primary truncate max-w-[200px]" title={session.id}>
                        {session.id.substring(0, 20)}...
                      </div>
                      <div className="text-xs text-ink-tertiary font-mono truncate max-w-[200px]" title={session.actorId}>
                        {session.actorId}
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="text-sm text-ink-primary">{session.sensorName}</div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="text-sm font-mono text-ink-primary">{session.clientIp}</div>
                      {session.countryCode && (
                        <div className="text-xs text-ink-tertiary">{session.countryCode}</div>
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <RiskBadge score={session.riskScore} />
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-ink-primary">
                      {session.requestCount.toLocaleString()}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-ink-secondary">
                      {formatTimeAgo(session.lastSeen)}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {session.isBlocked ? (
                        <BlockedBadge reason={session.blockReason} />
                      ) : (
                        <span className="text-xs text-ink-tertiary">Active</span>
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-right">
                      <div className="flex items-center justify-end gap-2">
                        {!session.isBlocked && onRevokeSession && (
                          <button
                            className="px-2 py-1 text-xs font-medium text-ac-orange hover:bg-ac-orange/10 disabled:opacity-50"
                            onClick={(e) => {
                              e.stopPropagation();
                              onRevokeSession(session.id, session.sensorId);
                            }}
                            disabled={isActionPending}
                          >
                            Revoke
                          </button>
                        )}
                        {onBanActor && (
                          <button
                            className="px-2 py-1 text-xs font-medium text-ac-red hover:bg-ac-red/10 disabled:opacity-50"
                            onClick={(e) => {
                              e.stopPropagation();
                              onBanActor(session.actorId);
                            }}
                            disabled={isActionPending}
                          >
                            Ban Actor
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {sortedSessions.length === 0 && (
            <div className="px-4 py-12 text-center text-ink-secondary">
              No sessions found matching your criteria
            </div>
          )}
        </div>
      ) : (
        /* Grouped View */
        <div className="space-y-4">
          {results.results.map((sensorResult) => (
            <div key={sensorResult.sensorId} className="card overflow-hidden">
              {/* Sensor Header */}
              <button
                className="w-full px-4 py-3 flex items-center justify-between bg-surface-raised hover:bg-surface-raised/80 transition-colors"
                onClick={() => toggleSensorExpanded(sensorResult.sensorId)}
              >
                <div className="flex items-center gap-4">
                  <span className={`w-2 h-2 rounded-full ${sensorResult.online ? 'bg-ac-green' : 'bg-ac-gray-mid'}`} />
                  <span className="font-medium text-ink-primary">{sensorResult.sensorName}</span>
                  <span className="text-sm text-ink-secondary">
                    {sensorResult.sessions.length} session{sensorResult.sessions.length !== 1 ? 's' : ''}
                  </span>
                  {sensorResult.error && (
                    <span className="text-xs text-ac-red">{sensorResult.error}</span>
                  )}
                </div>
                <div className="flex items-center gap-4">
                  <span className="text-xs text-ink-tertiary">{sensorResult.searchDurationMs}ms</span>
                  <span className="text-ink-secondary">
                    {expandedSensors.has(sensorResult.sensorId) ? '\u25B2' : '\u25BC'}
                  </span>
                </div>
              </button>

              {/* Expanded Sessions */}
              {expandedSensors.has(sensorResult.sensorId) && (
                <div className="divide-y divide-border-default">
                  {sensorResult.sessions.map((session) => (
                    <div
                      key={session.id}
                      className={`px-4 py-3 hover:bg-surface-raised/30 cursor-pointer transition-colors ${
                        selectedSession === session.id ? 'bg-ac-blue/10' : ''
                      }`}
                      onClick={() => handleSessionClick({ ...session, sensorId: sensorResult.sensorId, sensorName: sensorResult.sensorName })}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-6">
                          <div>
                            <div className="text-sm font-mono text-ink-primary truncate max-w-[200px]">{session.id}</div>
                            <div className="text-xs text-ink-tertiary">{session.actorId}</div>
                          </div>
                          <div className="text-sm font-mono text-ink-primary">{session.clientIp}</div>
                          <RiskBadge score={session.riskScore} />
                          {session.isBlocked && <BlockedBadge reason={session.blockReason} />}
                        </div>
                        <div className="flex items-center gap-4">
                          <span className="text-sm text-ink-secondary">{session.requestCount.toLocaleString()} reqs</span>
                          <span className="text-sm text-ink-tertiary">{formatTimeAgo(session.lastSeen)}</span>
                          <div className="flex items-center gap-2">
                            {!session.isBlocked && onRevokeSession && (
                              <button
                                className="px-2 py-1 text-xs font-medium text-ac-orange hover:bg-ac-orange/10 disabled:opacity-50"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onRevokeSession(session.id, sensorResult.sensorId);
                                }}
                                disabled={isActionPending}
                              >
                                Revoke
                              </button>
                            )}
                            {onBanActor && (
                              <button
                                className="px-2 py-1 text-xs font-medium text-ac-red hover:bg-ac-red/10 disabled:opacity-50"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onBanActor(session.actorId);
                                }}
                                disabled={isActionPending}
                              >
                                Ban
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                  {sensorResult.sessions.length === 0 && (
                    <div className="px-4 py-6 text-center text-ink-tertiary text-sm">
                      No sessions found on this sensor
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default SessionSearchResults;
