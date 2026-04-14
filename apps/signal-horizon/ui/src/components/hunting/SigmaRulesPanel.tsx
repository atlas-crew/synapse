import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ListChecks, RefreshCw, Trash2 } from 'lucide-react';
import type { SigmaRule } from '../../hooks/useHunt';
import { formatIsoOrInvalid } from '../../utils';
import { LoadingSpinner } from '../LoadingStates';
import { Panel, SectionHeader, Stack } from '@/ui';

interface SigmaRulesPanelProps {
  historicalEnabled: boolean;
  getSigmaRules: () => Promise<SigmaRule[]>;
  updateSigmaRule: (id: string, params: { name?: string; description?: string; enabled?: boolean }) => Promise<SigmaRule>;
  deleteSigmaRule: (id: string) => Promise<void>;
  refreshNonce?: number;
}

export function SigmaRulesPanel({
  historicalEnabled,
  getSigmaRules,
  updateSigmaRule,
  deleteSigmaRule,
  refreshNonce = 0,
}: SigmaRulesPanelProps) {
  const [rows, setRows] = useState<SigmaRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busyRuleId, setBusyRuleId] = useState<string | null>(null);
  const loadedOnceRef = useRef(false);

  const sorted = useMemo(() => {
    return [...rows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }, [rows]);

  const refresh = useCallback(async () => {
    if (!historicalEnabled) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getSigmaRules();
      setRows(data);
    } catch (err) {
      setRows([]);
      setError(err instanceof Error ? err.message : 'Failed to load sigma rules');
    } finally {
      setLoading(false);
    }
  }, [getSigmaRules, historicalEnabled]);

  useEffect(() => {
    if (!historicalEnabled) {
      setRows([]);
      setError(null);
      loadedOnceRef.current = false;
      return;
    }
    if (loadedOnceRef.current) return;
    loadedOnceRef.current = true;
    void refresh();
  }, [historicalEnabled, refresh]);

  useEffect(() => {
    if (!historicalEnabled) return;
    if (refreshNonce === 0) return;
    void refresh();
  }, [historicalEnabled, refresh, refreshNonce]);

  const handleToggleEnabled = async (rule: SigmaRule) => {
    if (loading) return;
    if (busyRuleId === rule.id) return;
    setBusyRuleId(rule.id);
    setError(null);
    try {
      const updated = await updateSigmaRule(rule.id, { enabled: !rule.enabled });
      setRows((prev) => prev.map((r) => (r.id === rule.id ? updated : r)));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update sigma rule');
    } finally {
      setBusyRuleId(null);
    }
  };

  const handleDelete = async (rule: SigmaRule) => {
    if (loading) return;
    if (busyRuleId === rule.id) return;
    const ok = window.confirm(`Delete Sigma rule "${rule.name}"?`);
    if (!ok) return;

    setBusyRuleId(rule.id);
    setError(null);
    try {
      await deleteSigmaRule(rule.id);
      setRows((prev) => prev.filter((r) => r.id !== rule.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete sigma rule');
    } finally {
      setBusyRuleId(null);
    }
  };

  return (
    <Panel tone="default" padding="none" spacing="none" as="div">
      <Stack
        direction="row"
        align="flex-start"
        justify="space-between"
        gap="md"
        className="p-4 border-b border-border-subtle"
      >
        <div className="min-w-0">
          <SectionHeader
            title="Sigma Rules"
            description='Manage background hunts. Create new rules via "Import Sigma Rule" then "Save Background Hunt".'
            icon={<ListChecks className="w-4 h-4 text-ac-blue" />}
            size="h4"
            mb="xs"
            style={{ marginBottom: 0 }}
            titleStyle={{ fontSize: '18px', lineHeight: '24px' }}
          />
        </div>

        <button
          type="button"
          onClick={() => void refresh()}
          disabled={!historicalEnabled || loading}
          className="px-3 py-2 border border-border-subtle bg-surface-base text-sm text-ink-secondary hover:text-ink-primary disabled:opacity-50 disabled:cursor-not-allowed"
          title="Refresh"
        >
          <Stack direction="row" align="center" gap="sm">
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </Stack>
        </button>
      </Stack>

      {!historicalEnabled && (
        <div className="p-4 text-sm text-ink-secondary">
          Historical analytics unavailable (ClickHouse disabled).
        </div>
      )}

      {historicalEnabled && (
        <div className="p-4 space-y-4">
          <Stack direction="row" align="center" gap="sm">
            {loading && <LoadingSpinner />}
            <div className="text-xs text-ink-muted font-mono">count={sorted.length}</div>
          </Stack>

          {error && (
            <div className="p-3 bg-ac-red/10 border border-ac-red/30 text-ac-red text-sm">
              {error}
            </div>
          )}

          {!loading && !error && sorted.length === 0 && (
            <div className="text-sm text-ink-secondary">
              No rules yet.
            </div>
          )}

          {sorted.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-ink-muted border-b border-border-subtle">
                  <tr>
                    <th className="text-left font-medium py-2 pr-3">Name</th>
                    <th className="text-left font-medium py-2 pr-3">Updated</th>
                    <th className="text-left font-medium py-2 pr-3">Enabled</th>
                    <th className="text-right font-medium py-2">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((r) => {
                    const busy = busyRuleId === r.id;
                    return (
                      <tr key={r.id} className="border-b border-border-subtle align-top">
                        <td className="py-2 pr-3">
                          <div className="text-ink-primary">{r.name}</div>
                          {r.description && (
                            <div className="text-xs text-ink-muted mt-1">{r.description}</div>
                          )}
                          <details className="text-xs mt-2">
                            <summary className="cursor-pointer text-link hover:text-link-hover font-mono">
                              whereClause
                            </summary>
                            <pre className="mt-2 whitespace-pre-wrap bg-surface-inset border border-border-subtle p-3 overflow-auto text-ink-secondary">
                              {r.whereClause}
                            </pre>
                          </details>
                        </td>
                        <td className="py-2 pr-3 font-mono text-ink-secondary whitespace-nowrap">
                          {formatIsoOrInvalid(r.updatedAt)}
                        </td>
                        <td className="py-2 pr-3 font-mono text-xs whitespace-nowrap">
                          {r.enabled ? 'true' : 'false'}
                        </td>
                        <td className="py-2 text-right whitespace-nowrap">
                          <button
                            type="button"
                            onClick={() => void handleToggleEnabled(r)}
                            disabled={busy}
                            className="px-2 py-1 border border-border-subtle bg-surface-base text-xs text-ink-secondary hover:text-ink-primary disabled:opacity-50 disabled:cursor-not-allowed font-mono mr-2"
                            title={r.enabled ? 'Disable' : 'Enable'}
                          >
                            {r.enabled ? 'Disable' : 'Enable'}
                          </button>
                          <button
                            type="button"
                            onClick={() => void handleDelete(r)}
                            disabled={busy}
                            className="px-2 py-1 border border-border-subtle bg-surface-base text-xs text-ac-red hover:text-ac-red/80 disabled:opacity-50 disabled:cursor-not-allowed font-mono"
                            title="Delete rule"
                          >
                            <Stack direction="row" align="center" gap="sm">
                              <Trash2 className="w-3 h-3" />
                              <span>Delete</span>
                            </Stack>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
