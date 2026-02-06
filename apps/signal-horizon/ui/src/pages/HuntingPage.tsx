/**
 * Threat Hunting Page
 * Query builder, filters, results table, saved queries
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import { Database, AlertCircle } from 'lucide-react';
import { HuntQueryBuilder, HuntResultsTable, SavedQueries } from '../components/hunting';
import { useHunt, type HuntQuery, type HuntResult, type SavedQuery } from '../hooks/useHunt';
import { useFocusTrap } from '../hooks/useFocusTrap';
import { useDocumentTitle } from '../hooks/useDocumentTitle';

export default function HuntingPage() {
  useDocumentTitle('Threat Hunting');
  const {
    isLoading,
    error,
    status,
    getStatus,
    queryTimeline,
    getSavedQueries,
    saveQuery,
    runSavedQuery,
    deleteSavedQuery,
    clearError,
  } = useHunt();

  const [result, setResult] = useState<HuntResult | null>(null);
  const [savedQueries, setSavedQueries] = useState<SavedQuery[]>([]);
  const [saveModalOpen, setSaveModalOpen] = useState(false);
  const [queryToSave, setQueryToSave] = useState<HuntQuery | null>(null);
  const [activeExampleQuery, setActiveExampleQuery] = useState<HuntQuery | null>(null);

  // Fetch status and saved queries on mount
  useEffect(() => {
    getStatus().catch(() => {});
    loadSavedQueries();
  }, [getStatus]);

  const loadSavedQueries = useCallback(async () => {
    try {
      const queries = await getSavedQueries();
      setSavedQueries(queries);
    } catch {
      // Ignore error - saved queries are optional
    }
  }, [getSavedQueries]);

  const handleQuery = async (query: HuntQuery) => {
    clearError();
    try {
      const huntResult = await queryTimeline(query);
      setResult(huntResult);
    } catch {
      setResult(null);
    }
  };

  const handleSaveQuery = (query: HuntQuery) => {
    setQueryToSave(query);
    setSaveModalOpen(true);
  };

  const confirmSaveQuery = async (name: string, description?: string) => {
    if (!queryToSave) return;

    try {
      await saveQuery(name, queryToSave, description);
      setSaveModalOpen(false);
      setQueryToSave(null);
      await loadSavedQueries();
    } catch {
      // Error is displayed via the error state
    }
  };

  const handleRunSavedQuery = async (id: string) => {
    clearError();
    try {
      const huntResult = await runSavedQuery(id);
      setResult(huntResult);
      await loadSavedQueries(); // Refresh to update lastRunAt
    } catch {
      setResult(null);
    }
  };

  const handleDeleteSavedQuery = async (id: string) => {
    try {
      await deleteSavedQuery(id);
      await loadSavedQueries();
    } catch {
      // Error is displayed via the error state
    }
  };

  const handleRunExample = async (queryString: string) => {
    // Simple parser for demo purposes: key:value AND key:value
    const query: HuntQuery = {
      startTime: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      endTime: new Date().toISOString(),
      limit: 100,
    };

    // Split by AND
    const parts = queryString.split(' AND ');
    
    parts.forEach(part => {
      const [key, value] = part.split(':').map(s => s.trim());
      if (!key || !value) return;

      const cleanValue = value.replace(/"/g, ''); // Remove quotes

      switch (key) {
        case 'ip':
          query.sourceIps = [cleanValue.replace('*', '')]; // Simple wildcard handling
          break;
        case 'fingerprint':
          query.anonFingerprint = cleanValue;
          break;
        case 'customer':
        case 'tenant':
          query.tenantId = cleanValue;
          break;
        case 'severity':
          if (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(cleanValue.toUpperCase())) {
            query.severities = [cleanValue.toUpperCase() as any];
          }
          break;
        case 'campaign':
          // In a real implementation, we'd add campaignId to HuntQuery
          break;
      }
    });

    setActiveExampleQuery(query);
    handleQuery(query);
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-light text-ink-primary">Threat Hunting</h1>
          <p className="text-ink-secondary mt-1">
            Search and analyze threats across the fleet
          </p>
          <div className="mt-2 text-xs text-ink-muted">
            <Link className="text-link hover:text-link-hover font-mono" to="/hunting/request">
              Pivot by request_id →
            </Link>
          </div>
        </div>

        {/* Status Badge */}
        <div className="flex items-center gap-2 px-3 py-2 border border-border-subtle bg-surface-card">
          <Database className="w-4 h-4 text-ink-muted" />
          <span className="text-sm text-ink-secondary">
            {status?.historical ? 'Historical queries enabled' : 'Real-time only'}
          </span>
          <span
            className={`w-2 h-2  ${
              status?.historical ? 'bg-ac-green' : 'bg-ac-orange'
            }`}
          />
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-ac-red/10 border border-ac-red/30">
          <AlertCircle className="w-5 h-5 text-ac-red" />
          <span className="text-ac-red">{error}</span>
          <button
            onClick={clearError}
            className="ml-auto text-sm text-ac-red hover:text-ac-red/80"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Query Builder */}
      <HuntQueryBuilder
        onQuery={handleQuery}
        onSave={handleSaveQuery}
        isLoading={isLoading}
        historicalEnabled={status?.historical ?? false}
        externalQuery={activeExampleQuery}
      />

      <HuntResultsTable result={result} isLoading={isLoading} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SavedQueries
          queries={savedQueries}
          onRun={handleRunSavedQuery}
          onDelete={handleDeleteSavedQuery}
          isLoading={isLoading}
        />
        <QueryExamples onRun={handleRunExample} />
      </div>

      {/* Save Query Modal */}
      {saveModalOpen && (
        <SaveQueryModal
          onSave={confirmSaveQuery}
          onCancel={() => {
            setSaveModalOpen(false);
            setQueryToSave(null);
          }}
        />
      )}
    </div>
  );
}

// =============================================================================
// Save Query Modal
// =============================================================================

interface SaveQueryModalProps {
  onSave: (name: string, description?: string) => void;
  onCancel: () => void;
}

function SaveQueryModal({ onSave, onCancel }: SaveQueryModalProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const modalRef = useRef<HTMLDivElement>(null);
  const stableOnCancel = useCallback(() => onCancel(), [onCancel]);
  useFocusTrap(modalRef, true, stableOnCancel);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    onSave(name.trim(), description.trim() || undefined);
  };

  return (
    <div className="fixed inset-0 bg-ac-black/50 flex items-center justify-center z-50">
      <div ref={modalRef} role="dialog" aria-modal="true" aria-labelledby="save-query-title" className="bg-surface-base border border-border-subtle p-6 w-full max-w-md">
        <h2 id="save-query-title" className="text-lg font-medium text-ink-primary mb-4">Save Query</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="save-query-name" className="block text-sm font-medium text-ink-secondary mb-1">
              Name *
            </label>
            <input
              id="save-query-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My saved query"
              autoFocus
              className="w-full bg-surface-inset border border-border-subtle px-3 py-2 text-ink-primary placeholder-ink-muted focus:outline-none focus:border-ac-blue"
            />
          </div>
          <div>
            <label htmlFor="save-query-description" className="block text-sm font-medium text-ink-secondary mb-1">
              Description
            </label>
            <textarea
              id="save-query-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description..."
              rows={2}
              className="w-full bg-surface-inset border border-border-subtle px-3 py-2 text-ink-primary placeholder-ink-muted focus:outline-none focus:border-ac-blue resize-none"
            />
          </div>
          <div className="flex gap-3 justify-end">
            <button
              type="button"
              onClick={onCancel}
              className="btn-outline h-10 px-4 text-sm"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!name.trim()}
              className="btn-primary h-10 px-4 text-sm"
            >
              Save Query
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function QueryExamples({ onRun }: { onRun: (query: string) => void }) {
  const examples = [
    'ip:185.228.*',
    'fingerprint:"curl" AND blocked:true',
    'customer:Healthcare-A',
    'campaign:#4421',
    'asn:12345',
    'severity:critical',
    'endpoint:/api/auth/* AND action:blocked',
  ];

  return (
    <div className="card">
      <div className="card-header flex items-center justify-between">
        <h2 className="font-medium text-ink-primary">Query Examples</h2>
        <span className="text-xs text-ink-muted">20 links</span>
      </div>
      <div className="card-body space-y-2">
        {examples.map((example) => (
          <div
            key={example}
            className="flex items-center justify-between px-3 py-2 border border-border-subtle bg-surface-inset text-sm text-ink-secondary"
          >
            <span className="font-mono">{example}</span>
            <button
              onClick={() => onRun(example)}
              className="text-link text-xs font-semibold tracking-[0.14em] uppercase hover:text-link-hover"
            >
              Run →
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
