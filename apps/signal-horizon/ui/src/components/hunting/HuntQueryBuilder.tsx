/**
 * Hunt Query Builder Component
 * Time range, signal types, IPs, confidence filter form
 */

import { useState, useCallback } from 'react';
import { Search, Calendar, Filter, X } from 'lucide-react';
import { clsx } from 'clsx';
import type { HuntQuery } from '../../hooks/useHunt';

interface HuntQueryBuilderProps {
  onQuery: (query: HuntQuery) => void;
  onSave?: (query: HuntQuery) => void;
  isLoading?: boolean;
  historicalEnabled?: boolean;
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
  { value: 'CRITICAL', label: 'Critical', color: 'bg-red-500' },
  { value: 'HIGH', label: 'High', color: 'bg-orange-500' },
  { value: 'MEDIUM', label: 'Medium', color: 'bg-yellow-500' },
  { value: 'LOW', label: 'Low', color: 'bg-blue-500' },
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
  isLoading = false,
  historicalEnabled = false,
}: HuntQueryBuilderProps) {
  const [timePreset, setTimePreset] = useState<number>(24);
  const [customStartTime, setCustomStartTime] = useState('');
  const [customEndTime, setCustomEndTime] = useState('');
  const [useCustomTime, setUseCustomTime] = useState(false);

  const [selectedSignalTypes, setSelectedSignalTypes] = useState<string[]>([]);
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([]);
  const [sourceIps, setSourceIps] = useState('');
  const [minConfidence, setMinConfidence] = useState<number | undefined>(undefined);
  const [anonFingerprint, setAnonFingerprint] = useState('');
  const [limit, setLimit] = useState(100);

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
    const query = buildQuery();
    onQuery(query);
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
  };

  const hasFilters =
    selectedSignalTypes.length > 0 ||
    selectedSeverities.length > 0 ||
    sourceIps.trim() ||
    minConfidence !== undefined ||
    anonFingerprint.trim();

  return (
    <div className="card">
      <div className="p-4 space-y-4">
        {/* Time Range */}
        <div className="space-y-2">
          <label className="text-sm font-medium text-gray-400 flex items-center gap-2">
            <Calendar className="w-4 h-4" />
            Time Range
            {!historicalEnabled && timePreset > 24 && (
              <span className="text-xs text-yellow-500">
                (Historical queries limited without ClickHouse)
              </span>
            )}
          </label>

          {!useCustomTime && (
            <div className="flex flex-wrap gap-2">
              {TIME_PRESETS.map((preset) => (
                <button
                  key={preset.hours}
                  onClick={() => setTimePreset(preset.hours)}
                  disabled={!historicalEnabled && preset.hours > 24}
                  className={clsx(
                    'px-3 py-1.5 text-sm rounded-lg border transition-colors',
                    timePreset === preset.hours
                      ? 'bg-horizon-600/20 border-horizon-500 text-horizon-400'
                      : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600',
                    !historicalEnabled && preset.hours > 24 && 'opacity-50 cursor-not-allowed'
                  )}
                >
                  {preset.label}
                </button>
              ))}
              <button
                onClick={() => setUseCustomTime(true)}
                className="px-3 py-1.5 text-sm rounded-lg border bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600"
              >
                Custom
              </button>
            </div>
          )}

          {useCustomTime && (
            <div className="flex items-center gap-4">
              <div className="flex-1">
                <input
                  type="datetime-local"
                  value={customStartTime}
                  onChange={(e) => setCustomStartTime(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white"
                />
              </div>
              <span className="text-gray-500">to</span>
              <div className="flex-1">
                <input
                  type="datetime-local"
                  value={customEndTime}
                  onChange={(e) => setCustomEndTime(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white"
                />
              </div>
              <button
                onClick={() => setUseCustomTime(false)}
                className="p-2 text-gray-500 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>

        {/* Signal Types */}
        <div className="space-y-2">
          <label className="text-sm font-medium text-gray-400">Signal Types</label>
          <div className="flex flex-wrap gap-2">
            {SIGNAL_TYPES.map((type) => (
              <button
                key={type.value}
                onClick={() => toggleSignalType(type.value)}
                className={clsx(
                  'px-3 py-1.5 text-sm rounded-lg border transition-colors',
                  selectedSignalTypes.includes(type.value)
                    ? 'bg-horizon-600/20 border-horizon-500 text-horizon-400'
                    : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600'
                )}
              >
                {type.label}
              </button>
            ))}
          </div>
        </div>

        {/* Severities */}
        <div className="space-y-2">
          <label className="text-sm font-medium text-gray-400">Severities</label>
          <div className="flex gap-2">
            {SEVERITIES.map((severity) => (
              <button
                key={severity.value}
                onClick={() => toggleSeverity(severity.value)}
                className={clsx(
                  'flex items-center gap-2 px-3 py-1.5 text-sm rounded-lg border transition-colors',
                  selectedSeverities.includes(severity.value)
                    ? 'bg-horizon-600/20 border-horizon-500 text-horizon-400'
                    : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600'
                )}
              >
                <span className={clsx('w-2 h-2 rounded-full', severity.color)} />
                {severity.label}
              </button>
            ))}
          </div>
        </div>

        {/* Advanced Filters */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-sm font-medium text-gray-400">Source IPs (comma-separated)</label>
            <input
              type="text"
              value={sourceIps}
              onChange={(e) => setSourceIps(e.target.value)}
              placeholder="192.168.1.100, 10.0.0.1"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-horizon-500 font-mono"
            />
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium text-gray-400">Fingerprint Hash</label>
            <input
              type="text"
              value={anonFingerprint}
              onChange={(e) => setAnonFingerprint(e.target.value)}
              placeholder="64-character hash"
              maxLength={64}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-horizon-500 font-mono"
            />
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium text-gray-400">Min Confidence (%)</label>
            <input
              type="number"
              value={minConfidence ?? ''}
              onChange={(e) => setMinConfidence(e.target.value ? parseInt(e.target.value) : undefined)}
              placeholder="0-100"
              min={0}
              max={100}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-horizon-500"
            />
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium text-gray-400">Result Limit</label>
            <select
              value={limit}
              onChange={(e) => setLimit(parseInt(e.target.value))}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-horizon-500"
            >
              <option value={100}>100</option>
              <option value={500}>500</option>
              <option value={1000}>1000</option>
              <option value={5000}>5000</option>
            </select>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-between pt-2">
          <div className="flex items-center gap-2">
            {hasFilters && (
              <button
                onClick={clearFilters}
                className="flex items-center gap-1 text-sm text-gray-400 hover:text-white"
              >
                <X className="w-4 h-4" />
                Clear filters
              </button>
            )}
          </div>
          <div className="flex gap-2">
            {onSave && (
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
    </div>
  );
}
