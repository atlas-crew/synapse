/**
 * GlobalSessionSearchPage
 *
 * Page for searching and managing sessions across all sensors in the fleet.
 * Provides search form, results display, and action buttons for session
 * revocation and actor banning.
 */

import { useState, useCallback, useMemo } from 'react';
import { useSessionSearch, type SessionSearchQuery } from '../../hooks/fleet/useSessionSearch';
import { SessionSearchResults } from '../../components/fleet/SessionSearchResults';
import { MetricCard } from '../../components/fleet';

// =============================================================================
// Type Definitions
// =============================================================================

interface SearchFormState {
  sessionId: string;
  actorId: string;
  clientIp: string;
  ja4Fingerprint: string;
  userAgent: string;
  riskScoreMin: string;
  blockedOnly: boolean;
  timeRangeEnabled: boolean;
  timeRangeStart: string;
  timeRangeEnd: string;
  limitPerSensor: string;
}

interface BanModalState {
  isOpen: boolean;
  actorId: string;
  reason: string;
  durationHours: string;
}

interface RevokeModalState {
  isOpen: boolean;
  sessionId: string;
  sensorId: string;
  reason: string;
  global: boolean;
}

// =============================================================================
// Initial State
// =============================================================================

const initialFormState: SearchFormState = {
  sessionId: '',
  actorId: '',
  clientIp: '',
  ja4Fingerprint: '',
  userAgent: '',
  riskScoreMin: '',
  blockedOnly: false,
  timeRangeEnabled: false,
  timeRangeStart: '',
  timeRangeEnd: '',
  limitPerSensor: '50',
};

const initialBanModalState: BanModalState = {
  isOpen: false,
  actorId: '',
  reason: '',
  durationHours: '',
};

const initialRevokeModalState: RevokeModalState = {
  isOpen: false,
  sessionId: '',
  sensorId: '',
  reason: '',
  global: true,
};

// =============================================================================
// Main Component
// =============================================================================

export function GlobalSessionSearchPage() {
  const {
    searchResults,
    stats,
    isSearching,
    isLoadingStats,
    searchError,
    search,
    revokeSession,
    banActor,
    refreshStats,
    clearResults,
  } = useSessionSearch({ autoFetchStats: true, statsRefreshInterval: 30000 });

  const [formState, setFormState] = useState<SearchFormState>(initialFormState);
  const [banModal, setBanModal] = useState<BanModalState>(initialBanModalState);
  const [revokeModal, setRevokeModal] = useState<RevokeModalState>(initialRevokeModalState);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [isActionPending, setIsActionPending] = useState(false);

  // Build query from form state
  const buildQuery = useCallback((): SessionSearchQuery => {
    const query: SessionSearchQuery = {};

    if (formState.sessionId.trim()) query.sessionId = formState.sessionId.trim();
    if (formState.actorId.trim()) query.actorId = formState.actorId.trim();
    if (formState.clientIp.trim()) query.clientIp = formState.clientIp.trim();
    if (formState.ja4Fingerprint.trim()) query.ja4Fingerprint = formState.ja4Fingerprint.trim();
    if (formState.userAgent.trim()) query.userAgent = formState.userAgent.trim();
    if (formState.riskScoreMin.trim()) query.riskScoreMin = parseInt(formState.riskScoreMin, 10);
    if (formState.blockedOnly) query.blockedOnly = true;
    if (formState.limitPerSensor.trim()) query.limitPerSensor = parseInt(formState.limitPerSensor, 10);

    if (formState.timeRangeEnabled && formState.timeRangeStart) {
      query.timeRange = {
        start: new Date(formState.timeRangeStart),
        end: formState.timeRangeEnd ? new Date(formState.timeRangeEnd) : undefined,
      };
    }

    return query;
  }, [formState]);

  // Handle search
  const handleSearch = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setActionError(null);
    setActionSuccess(null);

    try {
      await search(buildQuery());
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Search failed');
    }
  }, [search, buildQuery]);

  // Handle clear
  const handleClear = useCallback(() => {
    setFormState(initialFormState);
    clearResults();
    setActionError(null);
    setActionSuccess(null);
  }, [clearResults]);

  // Handle revoke action
  const handleRevokeSession = useCallback(async () => {
    if (!revokeModal.sessionId) return;

    setIsActionPending(true);
    setActionError(null);

    try {
      const result = await revokeSession(
        revokeModal.sessionId,
        revokeModal.reason || undefined,
        revokeModal.global ? undefined : [revokeModal.sensorId]
      );

      setActionSuccess(
        `Session revoked on ${result.successCount} of ${result.totalSensors} sensors`
      );
      setRevokeModal(initialRevokeModalState);

      // Refresh results
      await search(buildQuery());
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Revoke failed');
    } finally {
      setIsActionPending(false);
    }
  }, [revokeModal, revokeSession, search, buildQuery]);

  // Handle ban action
  const handleBanActor = useCallback(async () => {
    if (!banModal.actorId || !banModal.reason) return;

    setIsActionPending(true);
    setActionError(null);

    try {
      const durationSeconds = banModal.durationHours
        ? parseInt(banModal.durationHours, 10) * 3600
        : undefined;

      const result = await banActor(banModal.actorId, banModal.reason, durationSeconds);

      setActionSuccess(
        `Actor banned on ${result.successCount} of ${result.totalSensors} sensors. ${result.totalSessionsTerminated} sessions terminated.`
      );
      setBanModal(initialBanModalState);

      // Refresh results
      await search(buildQuery());
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Ban failed');
    } finally {
      setIsActionPending(false);
    }
  }, [banModal, banActor, search, buildQuery]);

  // Open revoke modal
  const openRevokeModal = useCallback((sessionId: string, sensorId: string) => {
    setRevokeModal({
      isOpen: true,
      sessionId,
      sensorId,
      reason: '',
      global: true,
    });
  }, []);

  // Open ban modal
  const openBanModal = useCallback((actorId: string) => {
    setBanModal({
      isOpen: true,
      actorId,
      reason: '',
      durationHours: '',
    });
  }, []);

  // Risk tier chart data
  const riskTierData = useMemo(() => {
    if (!stats) return [];
    const { sessionsByRiskTier } = stats;
    const total = sessionsByRiskTier.low + sessionsByRiskTier.medium + sessionsByRiskTier.high + sessionsByRiskTier.critical;
    if (total === 0) return [];

    return [
      { label: 'Low', value: sessionsByRiskTier.low, color: 'bg-ac-green', pct: (sessionsByRiskTier.low / total * 100).toFixed(1) },
      { label: 'Medium', value: sessionsByRiskTier.medium, color: 'bg-ac-yellow', pct: (sessionsByRiskTier.medium / total * 100).toFixed(1) },
      { label: 'High', value: sessionsByRiskTier.high, color: 'bg-ac-orange', pct: (sessionsByRiskTier.high / total * 100).toFixed(1) },
      { label: 'Critical', value: sessionsByRiskTier.critical, color: 'bg-ac-red', pct: (sessionsByRiskTier.critical / total * 100).toFixed(1) },
    ];
  }, [stats]);

  return (
    <div className="space-y-6 p-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-light text-ink-primary">Global Session Search</h1>
          <p className="mt-1 text-sm text-ink-secondary">
            Search and manage sessions across all sensors in your fleet
          </p>
        </div>
        <button
          className="px-4 py-2 bg-surface-raised text-ink-primary text-sm font-medium hover:bg-surface-raised/80 transition-colors"
          onClick={refreshStats}
          disabled={isLoadingStats}
        >
          Refresh Stats
        </button>
      </div>

      {/* Alerts */}
      {actionError && (
        <div className="p-4 bg-ac-red/10 border border-ac-red/30 text-ac-red text-sm">
          {actionError}
          <button className="ml-4 underline" onClick={() => setActionError(null)}>
            Dismiss
          </button>
        </div>
      )}
      {actionSuccess && (
        <div className="p-4 bg-ac-green/10 border border-ac-green/30 text-ac-green text-sm">
          {actionSuccess}
          <button className="ml-4 underline" onClick={() => setActionSuccess(null)}>
            Dismiss
          </button>
        </div>
      )}

      {/* Stats Overview */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Active Sessions"
          value={stats?.totalActiveSessions ?? 0}
          className={isLoadingStats ? 'opacity-50' : ''}
        />
        <MetricCard
          label="Blocked Sessions"
          value={stats?.totalBlockedSessions ?? 0}
          className={stats?.totalBlockedSessions && stats.totalBlockedSessions > 0 ? 'border-ac-orange/40' : ''}
        />
        <MetricCard
          label="Unique Actors"
          value={stats?.uniqueActors ?? 0}
        />
        <MetricCard
          label="Avg Risk Score"
          value={stats?.averageRiskScore?.toFixed(1) ?? '0'}
        />
      </div>

      {/* Risk Distribution */}
      {riskTierData.length > 0 && (
        <div className="card p-4">
          <h3 className="text-sm font-medium text-ink-secondary mb-3">Sessions by Risk Tier</h3>
          <div className="flex items-center gap-1 h-4">
            {riskTierData.map((tier) => (
              <div
                key={tier.label}
                className={`h-full ${tier.color} transition-all`}
                style={{ width: `${tier.pct}%` }}
                title={`${tier.label}: ${tier.value.toLocaleString()} (${tier.pct}%)`}
              />
            ))}
          </div>
          <div className="flex items-center justify-between mt-2 text-xs text-ink-tertiary">
            {riskTierData.map((tier) => (
              <span key={tier.label}>
                {tier.label}: {tier.value.toLocaleString()}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Search Form */}
      <form onSubmit={handleSearch} className="card p-6">
        <h2 className="text-lg font-medium text-ink-primary mb-4">Search Sessions</h2>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {/* Session ID */}
          <div>
            <label className="block text-sm font-medium text-ink-secondary mb-1">Session ID</label>
            <input
              type="text"
              className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary placeholder-ink-tertiary focus:outline-none focus:border-ac-blue"
              placeholder="sess-..."
              value={formState.sessionId}
              onChange={(e) => setFormState((s) => ({ ...s, sessionId: e.target.value }))}
            />
          </div>

          {/* Actor ID */}
          <div>
            <label className="block text-sm font-medium text-ink-secondary mb-1">Actor ID</label>
            <input
              type="text"
              className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary placeholder-ink-tertiary focus:outline-none focus:border-ac-blue"
              placeholder="actor-..."
              value={formState.actorId}
              onChange={(e) => setFormState((s) => ({ ...s, actorId: e.target.value }))}
            />
          </div>

          {/* Client IP */}
          <div>
            <label className="block text-sm font-medium text-ink-secondary mb-1">Client IP</label>
            <input
              type="text"
              className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary placeholder-ink-tertiary focus:outline-none focus:border-ac-blue"
              placeholder="192.168.1.100"
              value={formState.clientIp}
              onChange={(e) => setFormState((s) => ({ ...s, clientIp: e.target.value }))}
            />
          </div>

          {/* JA4 Fingerprint */}
          <div>
            <label className="block text-sm font-medium text-ink-secondary mb-1">JA4 Fingerprint</label>
            <input
              type="text"
              className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary placeholder-ink-tertiary focus:outline-none focus:border-ac-blue"
              placeholder="t13d..."
              value={formState.ja4Fingerprint}
              onChange={(e) => setFormState((s) => ({ ...s, ja4Fingerprint: e.target.value }))}
            />
          </div>

          {/* User Agent */}
          <div>
            <label className="block text-sm font-medium text-ink-secondary mb-1">User Agent (contains)</label>
            <input
              type="text"
              className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary placeholder-ink-tertiary focus:outline-none focus:border-ac-blue"
              placeholder="Mozilla..."
              value={formState.userAgent}
              onChange={(e) => setFormState((s) => ({ ...s, userAgent: e.target.value }))}
            />
          </div>

          {/* Min Risk Score */}
          <div>
            <label className="block text-sm font-medium text-ink-secondary mb-1">Min Risk Score</label>
            <input
              type="number"
              min="0"
              max="100"
              className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary placeholder-ink-tertiary focus:outline-none focus:border-ac-blue"
              placeholder="0-100"
              value={formState.riskScoreMin}
              onChange={(e) => setFormState((s) => ({ ...s, riskScoreMin: e.target.value }))}
            />
          </div>

          {/* Limit Per Sensor */}
          <div>
            <label className="block text-sm font-medium text-ink-secondary mb-1">Limit Per Sensor</label>
            <input
              type="number"
              min="1"
              max="500"
              className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary placeholder-ink-tertiary focus:outline-none focus:border-ac-blue"
              placeholder="50"
              value={formState.limitPerSensor}
              onChange={(e) => setFormState((s) => ({ ...s, limitPerSensor: e.target.value }))}
            />
          </div>

          {/* Blocked Only */}
          <div className="flex items-center">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                className="w-4 h-4 text-ac-blue bg-surface-raised border border-border-default focus:ring-ac-blue"
                checked={formState.blockedOnly}
                onChange={(e) => setFormState((s) => ({ ...s, blockedOnly: e.target.checked }))}
              />
              <span className="text-sm text-ink-primary">Blocked sessions only</span>
            </label>
          </div>

          {/* Time Range Toggle */}
          <div className="flex items-center">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                className="w-4 h-4 text-ac-blue bg-surface-raised border border-border-default focus:ring-ac-blue"
                checked={formState.timeRangeEnabled}
                onChange={(e) => setFormState((s) => ({ ...s, timeRangeEnabled: e.target.checked }))}
              />
              <span className="text-sm text-ink-primary">Filter by time range</span>
            </label>
          </div>
        </div>

        {/* Time Range Inputs */}
        {formState.timeRangeEnabled && (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 mt-4">
            <div>
              <label className="block text-sm font-medium text-ink-secondary mb-1">Start Time</label>
              <input
                type="datetime-local"
                className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary focus:outline-none focus:border-ac-blue"
                value={formState.timeRangeStart}
                onChange={(e) => setFormState((s) => ({ ...s, timeRangeStart: e.target.value }))}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink-secondary mb-1">End Time (optional)</label>
              <input
                type="datetime-local"
                className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary focus:outline-none focus:border-ac-blue"
                value={formState.timeRangeEnd}
                onChange={(e) => setFormState((s) => ({ ...s, timeRangeEnd: e.target.value }))}
              />
            </div>
          </div>
        )}

        {/* Form Actions */}
        <div className="flex items-center gap-4 mt-6">
          <button
            type="submit"
            className="px-6 py-2 bg-ac-blue text-white font-medium hover:bg-ac-blue/90 transition-colors disabled:opacity-50"
            disabled={isSearching}
          >
            {isSearching ? 'Searching...' : 'Search'}
          </button>
          <button
            type="button"
            className="px-6 py-2 bg-surface-raised text-ink-primary font-medium hover:bg-surface-raised/80 transition-colors"
            onClick={handleClear}
          >
            Clear
          </button>
        </div>

        {searchError && (
          <p className="mt-4 text-sm text-ac-red">{searchError.message}</p>
        )}
      </form>

      {/* Search Results */}
      {searchResults && (
        <SessionSearchResults
          results={searchResults}
          onRevokeSession={openRevokeModal}
          onBanActor={openBanModal}
          isActionPending={isActionPending}
        />
      )}

      {/* Revoke Modal */}
      {revokeModal.isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="card w-full max-w-md p-6">
            <h3 className="text-lg font-medium text-ink-primary mb-4">Revoke Session</h3>
            <p className="text-sm text-ink-secondary mb-4">
              This will terminate the session and force the client to re-authenticate.
            </p>

            <div className="mb-4">
              <label className="block text-sm font-medium text-ink-secondary mb-1">Session ID</label>
              <input
                type="text"
                className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary"
                value={revokeModal.sessionId}
                disabled
              />
            </div>

            <div className="mb-4">
              <label className="block text-sm font-medium text-ink-secondary mb-1">Reason (optional)</label>
              <input
                type="text"
                className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary placeholder-ink-tertiary focus:outline-none focus:border-ac-blue"
                placeholder="Suspicious activity detected"
                value={revokeModal.reason}
                onChange={(e) => setRevokeModal((s) => ({ ...s, reason: e.target.value }))}
              />
            </div>

            <div className="mb-6">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  className="w-4 h-4 text-ac-blue bg-surface-raised border border-border-default focus:ring-ac-blue"
                  checked={revokeModal.global}
                  onChange={(e) => setRevokeModal((s) => ({ ...s, global: e.target.checked }))}
                />
                <span className="text-sm text-ink-primary">Revoke globally (all sensors)</span>
              </label>
            </div>

            <div className="flex items-center gap-4">
              <button
                className="flex-1 px-4 py-2 bg-ac-orange text-white font-medium hover:bg-ac-orange/90 transition-colors disabled:opacity-50"
                onClick={handleRevokeSession}
                disabled={isActionPending}
              >
                {isActionPending ? 'Revoking...' : 'Revoke Session'}
              </button>
              <button
                className="flex-1 px-4 py-2 bg-surface-raised text-ink-primary font-medium hover:bg-surface-raised/80 transition-colors"
                onClick={() => setRevokeModal(initialRevokeModalState)}
                disabled={isActionPending}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Ban Modal */}
      {banModal.isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="card w-full max-w-md p-6">
            <h3 className="text-lg font-medium text-ink-primary mb-4">Ban Actor</h3>
            <p className="text-sm text-ink-secondary mb-4">
              This will block all current and future sessions from this actor across all sensors.
            </p>

            <div className="mb-4">
              <label className="block text-sm font-medium text-ink-secondary mb-1">Actor ID</label>
              <input
                type="text"
                className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary"
                value={banModal.actorId}
                disabled
              />
            </div>

            <div className="mb-4">
              <label className="block text-sm font-medium text-ink-secondary mb-1">
                Reason <span className="text-ac-red">*</span>
              </label>
              <input
                type="text"
                className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary placeholder-ink-tertiary focus:outline-none focus:border-ac-blue"
                placeholder="Malicious activity detected"
                value={banModal.reason}
                onChange={(e) => setBanModal((s) => ({ ...s, reason: e.target.value }))}
                required
              />
            </div>

            <div className="mb-6">
              <label className="block text-sm font-medium text-ink-secondary mb-1">
                Duration (hours, leave empty for permanent)
              </label>
              <input
                type="number"
                min="1"
                max="8760"
                className="w-full px-3 py-2 bg-surface-raised border border-border-default text-ink-primary placeholder-ink-tertiary focus:outline-none focus:border-ac-blue"
                placeholder="24"
                value={banModal.durationHours}
                onChange={(e) => setBanModal((s) => ({ ...s, durationHours: e.target.value }))}
              />
            </div>

            <div className="flex items-center gap-4">
              <button
                className="flex-1 px-4 py-2 bg-ac-red text-white font-medium hover:bg-ac-red/90 transition-colors disabled:opacity-50"
                onClick={handleBanActor}
                disabled={isActionPending || !banModal.reason}
              >
                {isActionPending ? 'Banning...' : 'Ban Actor'}
              </button>
              <button
                className="flex-1 px-4 py-2 bg-surface-raised text-ink-primary font-medium hover:bg-surface-raised/80 transition-colors"
                onClick={() => setBanModal(initialBanModalState)}
                disabled={isActionPending}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default GlobalSessionSearchPage;
