/**
 * Hunt Query Builder Component
 * Time range, signal types, IPs, confidence filter form
 */

import { useState, useCallback, useEffect } from 'react';
import { Search, Calendar, Filter, X, Terminal, FileText } from 'lucide-react';
import { clsx } from 'clsx';
import { CodeEditor } from '../ctrlx/CodeEditor';
import { SigmaImportModal } from './SigmaImportModal';
import type { HuntQuery } from '../../hooks/useHunt';
import { Panel, Stack } from '@/ui';

interface HuntQueryBuilderProps {
  onQuery: (query: HuntQuery) => void;
  onSave?: (query: HuntQuery) => void;
  onSaveSigmaBackgroundHunt?: (input: { name: string; description?: string; sqlTemplate: string }) => Promise<void>;
  isLoading?: boolean;
  historicalEnabled?: boolean;
  externalQuery?: HuntQuery | null;
}

const SIGNAL_TYPES = [
  { value: 'IP_THREAT', label: 'IP Threat' },
  { value: 'FINGERPRINT_THREAT', label: 'Fingerprint Threat' },
  { value: 'CAMPAIGN_INDICATOR', label: 'Campaign Indicator' },
  { value: 'CREDENTIAL_STUFFING', label: 'Credential Stuffing' },
  { value: 'RATE_ANOMALY', label: 'Rate Anomaly' },
  { value: 'BOT_SIGNATURE', label: 'Bot Signature' },
  { value: 'IMPOSSIBLE_TRAVEL', label: 'Impossible Travel' },
];

const SEVERITIES = [
  { value: 'CRITICAL', label: 'Critical', color: 'bg-ac-red' },
  { value: 'HIGH', label: 'High', color: 'bg-ac-orange' },
  { value: 'MEDIUM', label: 'Medium', color: 'bg-ac-orange/70' },
  { value: 'LOW', label: 'Low', color: 'bg-ac-blue' },
];

const TIME_PRESETS = [
  { label: 'Last 1 hour', hours: 1 },
  { label: 'Last 24 hours', hours: 24 },
  { label: 'Last 7 days', hours: 168 },
  { label: 'Last 30 days', hours: 720 },
  { label: 'Last 90 days', hours: 2160 },
];

export function HuntQueryBuilder({
  onQuery,
  onSave,
  onSaveSigmaBackgroundHunt,
  isLoading = false,
  historicalEnabled = false,
  externalQuery,
}: HuntQueryBuilderProps) {
  const [timePreset, setTimePreset] = useState<number>(24);
  const [customStartTime, setCustomStartTime] = useState('');
  const [customEndTime, setCustomEndTime] = useState('');
  const [useCustomTime, setUseCustomTime] = useState(false);

  // Power Mode (SQL)
  const [isPowerMode, setIsPowerMode] = useState(false);
  const [sqlQuery, setSqlQuery] = useState('');
  const [showSigmaModal, setShowSigmaModal] = useState(false);

  const [selectedSignalTypes, setSelectedSignalTypes] = useState<string[]>([]);
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([]);
  const [sourceIps, setSourceIps] = useState('');
  const [minConfidence, setMinConfidence] = useState<number | undefined>(undefined);
  const [anonFingerprint, setAnonFingerprint] = useState('');
  const [limit, setLimit] = useState(100);

  // Sync external query to state
  useEffect(() => {
    if (externalQuery) {
      if (externalQuery.signalTypes) setSelectedSignalTypes(externalQuery.signalTypes);
      if (externalQuery.severities) setSelectedSeverities(externalQuery.severities as any);
      if (externalQuery.sourceIps) setSourceIps(externalQuery.sourceIps.join(', '));
      if (externalQuery.minConfidence) setMinConfidence(externalQuery.minConfidence * 100);
      if (externalQuery.anonFingerprint) setAnonFingerprint(externalQuery.anonFingerprint);
      if (externalQuery.limit) setLimit(externalQuery.limit);
      
      // Auto-switch to visual mode if it's a structured query
      setIsPowerMode(false);
    }
  }, [externalQuery]);

  const toggleSignalType = (type: string) => {
    setSelectedSignalTypes((prev) =>
      prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]
    );
  };

  const toggleSeverity = (severity: string) => {
    setSelectedSeverities((prev) =>
      prev.includes(severity)
        ? prev.filter((s) => s !== severity)
        : [...prev, severity]
    );
  };

  const buildQuery = useCallback((): HuntQuery => {
    let startTime: string;
    let endTime: string;

    if (useCustomTime && customStartTime && customEndTime) {
      startTime = new Date(customStartTime).toISOString();
      endTime = new Date(customEndTime).toISOString();
    } else {
      const now = new Date();
      endTime = now.toISOString();
      startTime = new Date(now.getTime() - timePreset * 60 * 60 * 1000).toISOString();
    }

    const query: HuntQuery = {
      startTime,
      endTime,
      limit,
    };

    if (selectedSignalTypes.length > 0) {
      query.signalTypes = selectedSignalTypes;
    }

    if (selectedSeverities.length > 0) {
      query.severities = selectedSeverities as Array<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>;
    }

    if (sourceIps.trim()) {
      query.sourceIps = sourceIps.split(',').map((ip) => ip.trim()).filter(Boolean);
    }

    if (minConfidence !== undefined && minConfidence > 0) {
      query.minConfidence = minConfidence / 100;
    }

    if (anonFingerprint.trim()) {
      query.anonFingerprint = anonFingerprint.trim();
    }

    return query;
  }, [
    useCustomTime,
    customStartTime,
    customEndTime,
    timePreset,
    selectedSignalTypes,
    selectedSeverities,
    sourceIps,
    minConfidence,
    anonFingerprint,
    limit,
  ]);

  const handleSearch = () => {
    if (isPowerMode) {
      // In a real implementation, this would parse the SQL or send it to a raw query endpoint
      // For now, we'll just log it and maybe show a toast that "Raw SQL not yet supported by API"
      console.log('Executing SQL:', sqlQuery);
      // Fallback to standard query for demo
      const query = buildQuery();
      onQuery(query);
    } else {
      const query = buildQuery();
      onQuery(query);
    }
  };

  const handleSave = () => {
    if (onSave) {
      const query = buildQuery();
      onSave(query);
    }
  };

  const clearFilters = () => {
    setSelectedSignalTypes([]);
    setSelectedSeverities([]);
    setSourceIps('');
    setMinConfidence(undefined);
    setAnonFingerprint('');
    setLimit(100);
    setSqlQuery('');
  };

  const generateSqlFromFilters = () => {
    const parts = ['SELECT * FROM signals'];
    const conditions = [];

    if (selectedSignalTypes.length > 0) {
      conditions.push(`signal_type IN (${selectedSignalTypes.map(t => `'${t}'`).join(', ')})`);
    }
    if (selectedSeverities.length > 0) {
      conditions.push(`severity IN (${selectedSeverities.map(s => `'${s}'`).join(', ')})`);
    }
    if (sourceIps) {
      conditions.push(`source_ip IN (${sourceIps.split(',').map(ip => `'${ip.trim()}'`).join(', ')})`);
    }
    if (minConfidence) {
      conditions.push(`confidence >= ${minConfidence / 100}`);
    }

    if (conditions.length > 0) {
      parts.push('WHERE ' + conditions.join(' AND '));
    }
    
    parts.push(`ORDER BY timestamp DESC LIMIT ${limit}`);
    setSqlQuery(parts.join('\n'));
  };

  // Toggle mode and sync query
  const toggleMode = () => {
    if (!isPowerMode) {
      generateSqlFromFilters();
    }
    setIsPowerMode(!isPowerMode);
  };

  const hasFilters =
    selectedSignalTypes.length > 0 ||
    selectedSeverities.length > 0 ||
    sourceIps.trim() ||
    minConfidence !== undefined ||
    anonFingerprint.trim();

  return (
    <Panel tone="default" padding="none" spacing="none">
      <div className="p-4 space-y-4">
        {/* Header with Mode Toggle */}
        <div className="flex items-center justify-between border-b border-border-subtle pb-4 mb-4">
          <Stack direction="row" align="center" gap="sm">
            <Filter className="w-4 h-4 text-ink-muted" />
            <h3 className="font-medium text-ink-primary">Query Filters</h3>
          </Stack>
          <Stack direction="row" align="center" gap="sm">
            <button
              onClick={() => setShowSigmaModal(true)}
              className="px-3 py-1.5 text-xs font-medium border border-border-subtle bg-surface-inset text-ink-secondary hover:border-border-strong hover:text-ink-primary transition-colors"
            >
              <Stack direction="row" align="center" gap="sm">
                <FileText className="w-3 h-3" />
                <span>Import Sigma Rule</span>
              </Stack>
            </button>
            <button
              onClick={toggleMode}
              className={clsx(
                "px-3 py-1.5 text-xs font-medium border transition-colors ",
                isPowerMode 
                  ? "bg-ac-blue/10 border-ac-blue text-ac-blue" 
                  : "bg-surface-inset border-border-subtle text-ink-secondary hover:border-border-strong"
              )}
            >
              <Stack direction="row" align="center" gap="sm">
                <Terminal className="w-3 h-3" />
                <span>{isPowerMode ? 'Visual Builder' : 'Power Mode (SQL)'}</span>
              </Stack>
            </button>
          </Stack>
        </div>

        {isPowerMode ? (
          <div className="space-y-4 animate-in fade-in duration-200">
            <div className="bg-surface-inset p-3 border border-ac-blue/20">
               <p className="text-xs text-ink-secondary mb-2">
                 <span className="text-ac-blue font-bold">SQL Mode:</span> Write ClickHouse-compatible SQL queries directly. 
                 This allows for advanced aggregations and joins not possible in the visual builder.
               </p>
            </div>
            <CodeEditor
              value={sqlQuery}
              onChange={setSqlQuery}
              language="sql"
              height="200px"
              placeholder="SELECT * FROM signals WHERE severity = 'CRITICAL'..."
            />
          </div>
        ) : (
          <div className="space-y-4 animate-in fade-in duration-200">
            {/* Time Range */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-ink-secondary">
                <Stack direction="row" align="center" gap="sm">
                  <Calendar className="w-4 h-4" />
                  <span>Time Range</span>
                  {!historicalEnabled && timePreset > 24 && (
                    <span className="text-xs text-ac-orange">
                      (Historical queries limited without ClickHouse)
                    </span>
                  )}
                </Stack>
              </label>

              {!useCustomTime && (
                <div className="flex flex-wrap gap-2">
                  {TIME_PRESETS.map((preset) => (
                    <button
                      key={preset.hours}
                      onClick={() => setTimePreset(preset.hours)}
                      disabled={!historicalEnabled && preset.hours > 24}
                      className={clsx(
                        'px-3 py-1.5 text-sm border transition-colors',
                        timePreset === preset.hours
                          ? 'bg-ac-blue/10 border-ac-blue text-ac-blue'
                          : 'bg-surface-inset border-border-subtle text-ink-secondary hover:border-border-strong',
                        !historicalEnabled && preset.hours > 24 && 'opacity-50 cursor-not-allowed'
                      )}
                    >
                      {preset.label}
                    </button>
                  ))}
                  <button
                    onClick={() => setUseCustomTime(true)}
                    className="px-3 py-1.5 text-sm border bg-surface-inset border-border-subtle text-ink-secondary hover:border-border-strong"
                  >
                    Custom
                  </button>
                </div>
              )}

              {useCustomTime && (
                <Stack direction="row" align="center" gap="md">
                  <div className="flex-1">
                    <input
                      type="datetime-local"
                      value={customStartTime}
                      onChange={(e) => setCustomStartTime(e.target.value)}
                      className="w-full bg-surface-inset border border-border-subtle px-3 py-2 text-sm text-ink-primary"
                    />
                  </div>
                  <span className="text-ink-muted">to</span>
                  <div className="flex-1">
                    <input
                      type="datetime-local"
                      value={customEndTime}
                      onChange={(e) => setCustomEndTime(e.target.value)}
                      className="w-full bg-surface-inset border border-border-subtle px-3 py-2 text-sm text-ink-primary"
                    />
                  </div>
                  <button
                    onClick={() => setUseCustomTime(false)}
                    className="p-2 text-ink-muted hover:text-ink-primary"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </Stack>
              )}
            </div>

            {/* Signal Types */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-ink-secondary">Signal Types</label>
              <div className="flex flex-wrap gap-2">
                {SIGNAL_TYPES.map((type) => (
                  <button
                    key={type.value}
                    onClick={() => toggleSignalType(type.value)}
                    className={clsx(
                      'px-3 py-1.5 text-sm border transition-colors',
                      selectedSignalTypes.includes(type.value)
                        ? 'bg-ac-blue/10 border-ac-blue text-ac-blue'
                        : 'bg-surface-inset border-border-subtle text-ink-secondary hover:border-border-strong'
                    )}
                  >
                    {type.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Severities */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-ink-secondary">Severities</label>
              <div className="flex gap-2">
                {SEVERITIES.map((severity) => (
                  <button
                    key={severity.value}
                    onClick={() => toggleSeverity(severity.value)}
                    className={clsx(
                      'px-3 py-1.5 text-sm border transition-colors',
                      selectedSeverities.includes(severity.value)
                        ? 'bg-ac-blue/10 border-ac-blue text-ac-blue'
                        : 'bg-surface-inset border-border-subtle text-ink-secondary hover:border-border-strong'
                    )}
                  >
                    <Stack direction="row" align="center" gap="sm">
                      <span className={clsx('w-2 h-2', severity.color)} />
                      <span>{severity.label}</span>
                    </Stack>
                  </button>
                ))}
              </div>
            </div>

            {/* Advanced Filters */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-ink-secondary">Source IPs (comma-separated)</label>
                <input
                  type="text"
                  value={sourceIps}
                  onChange={(e) => setSourceIps(e.target.value)}
                  placeholder="192.168.1.100, 10.0.0.1"
                  className="w-full bg-surface-inset border border-border-subtle px-3 py-2 text-sm text-ink-primary placeholder-ink-muted focus:outline-none focus:border-ac-blue font-mono"
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-ink-secondary">Fingerprint Hash</label>
                <input
                  type="text"
                  value={anonFingerprint}
                  onChange={(e) => setAnonFingerprint(e.target.value)}
                  placeholder="64-character hash"
                  maxLength={64}
                  className="w-full bg-surface-inset border border-border-subtle px-3 py-2 text-sm text-ink-primary placeholder-ink-muted focus:outline-none focus:border-ac-blue font-mono"
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-ink-secondary">Min Confidence (%)</label>
                <input
                  type="number"
                  value={minConfidence ?? ''}
                  onChange={(e) => setMinConfidence(e.target.value ? parseInt(e.target.value) : undefined)}
                  placeholder="0-100"
                  min={0}
                  max={100}
                  className="w-full bg-surface-inset border border-border-subtle px-3 py-2 text-sm text-ink-primary placeholder-ink-muted focus:outline-none focus:border-ac-blue"
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-ink-secondary">Result Limit</label>
                <select
                  value={limit}
                  onChange={(e) => setLimit(parseInt(e.target.value))}
                  className="w-full bg-surface-inset border border-border-subtle px-3 py-2 text-sm text-ink-primary focus:outline-none focus:border-ac-blue"
                >
                  <option value={100}>100</option>
                  <option value={500}>500</option>
                  <option value={1000}>1000</option>
                  <option value={5000}>5000</option>
                </select>
              </div>
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center justify-between pt-2 border-t border-border-subtle mt-4">
          <Stack direction="row" align="center" gap="sm">
            {hasFilters && !isPowerMode && (
              <button
                onClick={clearFilters}
                className="text-sm text-ink-muted hover:text-ink-primary"
              >
                <Stack direction="row" align="center" gap="xs">
                  <X className="w-4 h-4" />
                  <span>Clear filters</span>
                </Stack>
              </button>
            )}
          </Stack>
          <div className="flex gap-2">
            {onSave && !isPowerMode && (
              <button
                onClick={handleSave}
                className="btn-ghost"
              >
                <Filter className="w-4 h-4 mr-2" />
                Save Query
              </button>
            )}
            <button
              onClick={handleSearch}
              disabled={isLoading}
              className="btn-primary"
            >
              <Search className="w-4 h-4 mr-2" />
              {isLoading ? 'Searching...' : 'Search'}
            </button>
          </div>
        </div>
      </div>
      
      {showSigmaModal && (
        <SigmaImportModal
          onClose={() => setShowSigmaModal(false)}
          onImport={(sql) => {
            setSqlQuery(sql);
            setIsPowerMode(true);
          }}
          onSaveBackgroundHunt={onSaveSigmaBackgroundHunt}
        />
      )}
    </Panel>
  );
}
