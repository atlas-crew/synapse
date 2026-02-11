/**
 * Threat Hunting Page
 * Query builder, filters, results table, saved queries
 */

import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { Database } from 'lucide-react';
import {
  BehavioralAnomaliesPanel,
  ClickHouseOpsPanel,
  FleetIntelligencePanel,
  HuntQueryBuilder,
  HuntResultsTable,
  LowAndSlowPanel,
  RecentRequestsPanel,
  SavedQueries,
  SigmaLeadsPanel,
  SigmaRulesPanel,
} from '../components/hunting';
import { useHunt, type HuntQuery, type HuntResult, type SavedQuery } from '../hooks/useHunt';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import {
  Alert,
  Box,
  Button,
  CARD_HEADER_TITLE_STYLE,
  Input,
  Modal,
  SectionHeader,
  colors,
  spacing,
} from '@/ui';

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
    getTenantBaselines,
    getAnomalies,
    getLowAndSlowIps,
    getFleetFingerprintIntelligence,
    createSigmaRule,
    getSigmaRules,
    updateSigmaRule,
    deleteSigmaRule,
    getSigmaLeads,
    ackSigmaLead,
    getRecentRequests,
    getClickHouseOpsSnapshot,
    clearError,
  } = useHunt();

  const [result, setResult] = useState<HuntResult | null>(null);
  const [savedQueries, setSavedQueries] = useState<SavedQuery[]>([]);
  const [saveModalOpen, setSaveModalOpen] = useState(false);
  const [queryToSave, setQueryToSave] = useState<HuntQuery | null>(null);
  const [activeExampleQuery, setActiveExampleQuery] = useState<HuntQuery | null>(null);
  const [sigmaRulesRefreshNonce, setSigmaRulesRefreshNonce] = useState(0);

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

    parts.forEach((part) => {
      const [key, value] = part.split(':').map((s) => s.trim());
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
      <SectionHeader
        title="Threat Hunting"
        description="Search and analyze threats across the fleet"
        actions={
          <Box
            bg="card"
            border="subtle"
            flex
            direction="row"
            align="center"
            gap="sm"
            style={{ padding: `${spacing.sm} ${spacing.md}` }}
          >
            <Database aria-hidden="true" className="w-4 h-4" style={{ color: colors.gray.mid }} />
            <span className="text-sm text-ink-secondary">
              {status?.historical ? 'Historical queries enabled' : 'Real-time only'}
            </span>
            <span
              aria-hidden="true"
              style={{
                width: 8,
                height: 8,
                background: status?.historical ? colors.green : colors.orange,
                display: 'inline-block',
              }}
            />
          </Box>
        }
      />
      <div className="text-xs text-ink-muted">
        <Link className="text-link hover:text-link-hover font-mono" to="/hunting/request">
          Pivot by request_id →
        </Link>
        <span className="mx-2 text-ink-muted/50">|</span>
        <Link className="text-link hover:text-link-hover font-mono" to="/hunting/campaign">
          Campaign timeline →
        </Link>
      </div>

      {/* Error Banner */}
      {error && (
        <Alert status="error" dismissible onDismiss={clearError}>
          {error}
        </Alert>
      )}

      {/* Query Builder */}
      <HuntQueryBuilder
        onQuery={handleQuery}
        onSave={handleSaveQuery}
        onSaveSigmaBackgroundHunt={async (input) => {
          await createSigmaRule(input);
          setSigmaRulesRefreshNonce((n) => n + 1);
        }}
        isLoading={isLoading}
        historicalEnabled={status?.historical ?? false}
        externalQuery={activeExampleQuery}
      />

      {status?.isFleetAdmin && (
        <ClickHouseOpsPanel
          historicalEnabled={status?.historical ?? false}
          getClickHouseOpsSnapshot={getClickHouseOpsSnapshot}
        />
      )}

      <RecentRequestsPanel
        historicalEnabled={status?.historical ?? false}
        getRecentRequests={getRecentRequests}
      />

      <BehavioralAnomaliesPanel
        historicalEnabled={status?.historical ?? false}
        getTenantBaselines={getTenantBaselines}
        getAnomalies={getAnomalies}
      />

      <SigmaLeadsPanel
        historicalEnabled={status?.historical ?? false}
        getSigmaLeads={getSigmaLeads}
        ackSigmaLead={ackSigmaLead}
        onPivotExample={handleRunExample}
      />

      <SigmaRulesPanel
        historicalEnabled={status?.historical ?? false}
        getSigmaRules={getSigmaRules}
        updateSigmaRule={updateSigmaRule}
        deleteSigmaRule={deleteSigmaRule}
        refreshNonce={sigmaRulesRefreshNonce}
      />

      {status?.isFleetAdmin ? (
        <>
          <LowAndSlowPanel
            historicalEnabled={status?.historical ?? false}
            getLowAndSlowIps={getLowAndSlowIps}
          />
          <FleetIntelligencePanel
            historicalEnabled={status?.historical ?? false}
            getFleetFingerprintIntelligence={getFleetFingerprintIntelligence}
            onPivotFingerprint={(fp) => handleRunExample(`fingerprint:\"${fp}\"`)}
          />
        </>
      ) : (
        <div className="border border-border-subtle bg-surface-card p-4">
          <div className="text-sm text-ink-secondary">
            Fleet intelligence panels are admin-only.
          </div>
        </div>
      )}

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

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    onSave(name.trim(), description.trim() || undefined);
  };

  return (
    <Modal open onClose={onCancel} size="520px" title="Save Query">
      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Name *"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="My saved query"
          autoFocus
          size="md"
        />
        <Input
          label="Description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Optional description..."
          multiline
          rows={2}
          size="md"
        />
        <div className="flex gap-3 justify-end">
          <Button variant="outlined" type="button" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="submit" disabled={!name.trim()}>
            Save Query
          </Button>
        </div>
      </form>
    </Modal>
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
        <SectionHeader
          title="Query Examples"
          size="h4"
          style={{ marginBottom: 0 }}
          titleStyle={CARD_HEADER_TITLE_STYLE}
          actions={<span className="text-xs text-ink-muted">20 links</span>}
        />
      </div>
      <div className="card-body space-y-2">
        {examples.map((example) => (
          <div
            key={example}
            className="flex items-center justify-between px-3 py-2 border border-border-subtle bg-surface-inset text-sm text-ink-secondary"
          >
            <span className="font-mono">{example}</span>
            <Button variant="ghost" size="sm" onClick={() => onRun(example)}>
              Run →
            </Button>
          </div>
        ))}
      </div>
    </div>
  );
}
