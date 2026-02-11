/**
 * LogViewer Component
 *
 * Virtualized log display with real-time streaming, filtering,
 * and export capabilities for sensor log monitoring.
 */

import { useEffect, useRef, useState, useCallback, memo, type CSSProperties } from 'react';
import { VariableSizeList as List } from 'react-window';
import {
  Activity,
  WifiOff,
  Pause,
  Play,
  Trash2,
  Download,
  ChevronDown,
  X,
  Search,
  Globe,
  AlertCircle,
  Shield,
  FileText,
  Settings,
  Filter,
  ArrowDown,
} from 'lucide-react';
import { useLogStream } from '../../hooks/fleet/useLogStream';
import { Box } from '@/ui';
import type {
  LogEntry,
  LogFilter,
  LogSource,
  LogLevel,
  LogLevelPreset,
} from '../../types/logs';
import {
  LOG_LEVEL_COLORS,
  LOG_SOURCE_LABELS,
  ALL_LOG_SOURCES,
  LOG_LEVEL_PRESETS,
} from '../../types/logs';

// =============================================================================
// Type Definitions
// =============================================================================

export interface LogViewerProps {
  /** Sensor ID to stream logs from */
  sensorId: string;
  /** Display name for the sensor */
  sensorName: string;
  /** Initial filter configuration */
  initialFilter?: LogFilter;
  /** Height of the log list (number in pixels or CSS string) */
  height?: number | string;
  /** Callback when close button is clicked */
  onClose?: () => void;
}

interface LogRowProps {
  entry: LogEntry;
  style: CSSProperties;
  isExpanded: boolean;
  onToggle: () => void;
}

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Format timestamp for display
 */
function formatTime(date: Date): string {
  return date.toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }) + '.' + date.getMilliseconds().toString().padStart(3, '0');
}

/**
 * Get icon component for log source
 */
function SourceIcon({ source, className = '' }: { source: LogSource; className?: string }) {
  const iconProps = { className: `w-3.5 h-3.5 ${className}` };

  switch (source) {
    case 'access':
      return <Globe {...iconProps} />;
    case 'error':
      return <AlertCircle {...iconProps} />;
    case 'waf':
      return <Shield {...iconProps} />;
    case 'audit':
      return <FileText {...iconProps} />;
    case 'system':
      return <Settings {...iconProps} />;
    default:
      return <Globe {...iconProps} />;
  }
}

/**
 * Format JSON fields for display
 */
function formatFields(fields: Record<string, unknown>): string {
  return JSON.stringify(fields, null, 2);
}

// =============================================================================
// LogRow Component
// =============================================================================

const LogRow = memo(function LogRow({ entry, style, isExpanded, onToggle }: LogRowProps) {
  const levelColors = LOG_LEVEL_COLORS[entry.level];

  return (
    <Box style={style} className="group">
      {/* Main row */}
      <div
        className={`
          flex items-center gap-2 px-3 h-6
          hover:bg-surface-subtle cursor-pointer transition-colors
          ${isExpanded ? 'bg-surface-subtle' : ''}
        `}
        onClick={onToggle}
      >
        {/* Timestamp */}
        <span className="text-ink-muted text-xs w-24 flex-shrink-0 font-mono">
          {formatTime(entry.timestamp)}
        </span>

        {/* Source icon */}
        <span className="flex-shrink-0" title={LOG_SOURCE_LABELS[entry.source]}>
          <SourceIcon source={entry.source} className="text-ink-secondary" />
        </span>

        {/* Level badge */}
        <span
          className={`
            px-1.5 py-0.5  text-[10px] font-mono font-medium uppercase tracking-wide
            ${levelColors.bg} ${levelColors.text}
            min-w-[3.5rem] text-center
          `}
        >
          {entry.level}
        </span>

        {/* Message */}
        <span className="text-sm text-ink-primary truncate flex-1 font-mono">
          {entry.message}
        </span>

        {/* Expand indicator */}
        {entry.fields && Object.keys(entry.fields).length > 0 && (
          <ChevronDown
            className={`w-4 h-4 text-ink-muted transition-transform ${isExpanded ? 'rotate-180' : ''}`}
          />
        )}
      </div>

      {/* Expanded details */}
      {isExpanded && (
        <div className="px-3 py-2 bg-surface-raised border-t border-border-subtle">
          {/* Structured fields */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs mb-2">
            {entry.method && (
              <div>
                <span className="text-ink-muted">Method:</span>{' '}
                <span className="text-ink-primary font-medium">{entry.method}</span>
              </div>
            )}
            {entry.path && (
              <div>
                <span className="text-ink-muted">Path:</span>{' '}
                <span className="text-ink-primary font-mono">{entry.path}</span>
              </div>
            )}
            {entry.statusCode !== undefined && (
              <div>
                <span className="text-ink-muted">Status:</span>{' '}
                <span
                  className={`font-medium ${
                    entry.statusCode >= 500
                      ? 'text-red-600'
                      : entry.statusCode >= 400
                      ? 'text-yellow-600'
                      : 'text-green-600'
                  }`}
                >
                  {entry.statusCode}
                </span>
              </div>
            )}
            {entry.latencyMs !== undefined && (
              <div>
                <span className="text-ink-muted">Latency:</span>{' '}
                <span className="text-ink-primary">{entry.latencyMs.toFixed(2)}ms</span>
              </div>
            )}
            {entry.clientIp && (
              <div>
                <span className="text-ink-muted">Client IP:</span>{' '}
                <span className="text-ink-primary font-mono">{entry.clientIp}</span>
              </div>
            )}
            {entry.ruleId && (
              <div>
                <span className="text-ink-muted">Rule ID:</span>{' '}
                <span className="text-ink-primary font-mono">{entry.ruleId}</span>
              </div>
            )}
          </div>

          {/* Additional fields */}
          {entry.fields && Object.keys(entry.fields).length > 0 && (
            <div className="mt-2">
              <span className="text-ink-muted text-xs">Fields:</span>
              <pre className="mt-1 p-2 bg-surface-base text-xs font-mono text-ink-secondary overflow-x-auto">
                {formatFields(entry.fields)}
              </pre>
            </div>
          )}
        </div>
      )}
    </Box>
  );
});

// =============================================================================
// LogViewer Component
// =============================================================================

export function LogViewer({
  sensorId,
  sensorName,
  initialFilter,
  height = 600,
  onClose,
}: LogViewerProps) {
  const listRef = useRef<List>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [searchInput, setSearchInput] = useState(initialFilter?.search || '');
  const [selectedSources, setSelectedSources] = useState<Set<LogSource>>(
    new Set(initialFilter?.sources || ALL_LOG_SOURCES)
  );
  const [levelPreset, setLevelPreset] = useState<LogLevelPreset>('all');
  const [showFilters, setShowFilters] = useState(false);
  const [containerHeight, setContainerHeight] = useState(typeof height === 'number' ? height : 600);

  const { state, connect, disconnect, setFilter, togglePause, clear, exportLogs } = useLogStream({
    sensorId,
    maxEntries: 5000,
    initialFilter,
  });

  // Connect on mount
  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  // Auto-scroll when new entries arrive
  useEffect(() => {
    if (autoScroll && listRef.current && state.entries.length > 0) {
      listRef.current.scrollToItem(0);
    }
  }, [state.entries.length, autoScroll]);

  // Calculate container height on resize
  useEffect(() => {
    if (typeof height === 'number') {
      setContainerHeight(height);
      return;
    }

    const updateHeight = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        // Subtract header height (~140px) from available space
        setContainerHeight(Math.max(200, rect.height - 140));
      }
    };

    updateHeight();
    window.addEventListener('resize', updateHeight);
    return () => window.removeEventListener('resize', updateHeight);
  }, [height]);

  // Handle filter changes with debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      const newFilter: LogFilter = {
        sources: selectedSources.size < ALL_LOG_SOURCES.length ? Array.from(selectedSources) : undefined,
        levels: LOG_LEVEL_PRESETS[levelPreset].length > 0 ? LOG_LEVEL_PRESETS[levelPreset] as LogLevel[] : undefined,
        search: searchInput.trim() || undefined,
      };
      setFilter(newFilter);
    }, 300);

    return () => clearTimeout(timer);
  }, [searchInput, selectedSources, levelPreset, setFilter]);

  // Toggle row expansion
  const toggleRow = useCallback((id: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
    // Reset list cache when expansion changes
    listRef.current?.resetAfterIndex(0);
  }, []);

  // Toggle source filter
  const toggleSource = useCallback((source: LogSource) => {
    setSelectedSources((prev) => {
      const next = new Set(prev);
      if (next.has(source)) {
        next.delete(source);
      } else {
        next.add(source);
      }
      return next;
    });
  }, []);

  // Handle scroll to detect auto-scroll state
  const handleScroll = useCallback(
    ({ scrollOffset }: { scrollOffset: number }) => {
      // If user scrolls away from top, disable auto-scroll
      if (scrollOffset > 50 && autoScroll) {
        setAutoScroll(false);
      }
      // If user scrolls back to top, re-enable auto-scroll
      if (scrollOffset < 10 && !autoScroll) {
        setAutoScroll(true);
      }
    },
    [autoScroll]
  );

  // Clear filters
  const clearFilters = useCallback(() => {
    setSearchInput('');
    setSelectedSources(new Set(ALL_LOG_SOURCES));
    setLevelPreset('all');
  }, []);

  // Calculate row height (base 24px, expanded varies)
  const getItemSize = useCallback(
    (index: number) => {
      const entry = state.entries[index];
      if (!entry) return 24;

      if (expandedRows.has(entry.id)) {
        // Base expanded height + fields if present
        let height = 24 + 60; // Base row + basic fields
        if (entry.fields && Object.keys(entry.fields).length > 0) {
          height += 80; // Additional space for JSON fields
        }
        return height;
      }
      return 24;
    },
    [state.entries, expandedRows]
  );

  // Calculate actual list height
  const listHeight = typeof height === 'number' ? height - 140 : containerHeight;

  return (
    <div
      ref={containerRef}
      className="flex flex-col bg-surface-base border border-border-subtle overflow-hidden"
      style={{ height: typeof height === 'string' ? height : `${height}px` }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-border-subtle bg-surface-raised">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-semibold text-ink-primary">{sensorName}</h3>
          <span className="text-xs text-ink-secondary">Logs</span>

          {/* Connection status */}
          <div className="flex items-center gap-1.5">
            {state.connected ? (
              <>
                <Activity className="w-3.5 h-3.5 text-status-success" />
                <span className="text-xs text-status-success">Connected</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5 text-status-warning" />
                <span className="text-xs text-status-warning">Disconnected</span>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Entry count */}
          <span className="text-xs text-ink-muted">
            {state.entries.length.toLocaleString()} entries
            {state.dropped > 0 && (
              <span className="text-status-warning ml-1">
                ({state.dropped.toLocaleString()} dropped)
              </span>
            )}
          </span>

          {/* Close button */}
          {onClose && (
            <button
              onClick={onClose}
              className="p-1 hover:bg-surface-subtle transition-colors"
              title="Close"
            >
              <X className="w-4 h-4 text-ink-muted" />
            </button>
          )}
        </div>
      </div>

      {/* Filter bar */}
      <div className="px-4 py-2 border-b border-border-subtle bg-surface-subtle">
        <div className="flex items-center gap-3">
          {/* Search input */}
          <div className="flex-1 relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-muted" />
            <input
              type="text"
              placeholder="Search logs..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              aria-label="Search logs"
              className="w-full pl-9 pr-3 py-1.5 text-sm bg-surface-base border border-border-subtle focus:outline-none focus:ring-2 focus:ring-accent-primary/20 focus:border-accent-primary"
            />
          </div>

          {/* Level preset dropdown */}
          <select
            value={levelPreset}
            onChange={(e) => setLevelPreset(e.target.value as LogLevelPreset)}
            className="px-3 py-1.5 text-sm bg-surface-base border border-border-subtle focus:outline-none focus:ring-2 focus:ring-accent-primary/20 focus:border-accent-primary"
          >
            <option value="all">All Levels</option>
            <option value="debug+">Debug+</option>
            <option value="info+">Info+</option>
            <option value="warn+">Warn+</option>
            <option value="error+">Error+</option>
          </select>

          {/* Filter toggle */}
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`
              flex items-center gap-1.5 px-3 py-1.5 text-sm  transition-colors
              ${showFilters ? 'bg-accent-primary text-white' : 'bg-surface-base border border-border-subtle hover:bg-surface-card'}
            `}
          >
            <Filter className="w-4 h-4" />
            Sources
          </button>

          {/* Clear filters */}
          <button
            onClick={clearFilters}
            className="px-3 py-1.5 text-sm text-ink-secondary hover:text-ink-primary bg-surface-base border border-border-subtle hover:bg-surface-card transition-colors"
          >
            Clear
          </button>
        </div>

        {/* Source checkboxes (expandable) */}
        {showFilters && (
          <div className="flex items-center gap-4 mt-2 pt-2 border-t border-border-subtle">
            {ALL_LOG_SOURCES.map((source) => (
              <label
                key={source}
                className="flex items-center gap-1.5 cursor-pointer select-none"
              >
                <input
                  type="checkbox"
                  checked={selectedSources.has(source)}
                  onChange={() => toggleSource(source)}
                  className="w-4 h-4 border-border-subtle text-accent-primary focus:ring-accent-primary/20"
                />
                <SourceIcon source={source} className="text-ink-secondary" />
                <span className="text-sm text-ink-primary">{LOG_SOURCE_LABELS[source]}</span>
              </label>
            ))}
          </div>
        )}
      </div>

      {/* Control bar */}
      <div className="flex items-center justify-between px-4 py-1.5 border-b border-border-subtle bg-surface-base">
        <div className="flex items-center gap-2">
          {/* Play/Pause */}
          <button
            onClick={togglePause}
            className={`
              flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium  transition-colors
              ${state.paused ? 'bg-status-warning/10 text-status-warning' : 'bg-surface-subtle hover:bg-surface-card text-ink-secondary'}
            `}
            title={state.paused ? 'Resume' : 'Pause'}
          >
            {state.paused ? (
              <>
                <Play className="w-3.5 h-3.5" />
                Paused
              </>
            ) : (
              <>
                <Pause className="w-3.5 h-3.5" />
                Live
              </>
            )}
          </button>

          {/* Clear */}
          <button
            onClick={clear}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-ink-secondary bg-surface-subtle hover:bg-surface-card transition-colors"
            title="Clear logs"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear
          </button>

          {/* Export */}
          <button
            onClick={exportLogs}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-ink-secondary bg-surface-subtle hover:bg-surface-card transition-colors"
            title="Export as JSON"
            disabled={state.entries.length === 0}
          >
            <Download className="w-3.5 h-3.5" />
            Export
          </button>
        </div>

        {/* Auto-scroll indicator */}
        <button
          onClick={() => {
            setAutoScroll(true);
            listRef.current?.scrollToItem(0);
          }}
          className={`
            flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium  transition-colors
            ${autoScroll ? 'text-status-success' : 'text-ink-muted hover:text-ink-primary bg-surface-subtle'}
          `}
          title={autoScroll ? 'Auto-scroll enabled' : 'Click to scroll to latest'}
        >
          <ArrowDown className={`w-3.5 h-3.5 ${autoScroll ? 'animate-bounce' : ''}`} />
          {autoScroll ? 'Following' : 'Scroll to latest'}
        </button>
      </div>

      {/* Virtualized log list */}
      <div className="flex-1 min-h-0">
        {state.entries.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-ink-muted">
            <FileText className="w-12 h-12 mb-3 opacity-50" />
            <p className="text-sm font-medium">No logs to display</p>
            <p className="text-xs mt-1">
              {state.connected
                ? 'Waiting for log entries...'
                : 'Connect to start receiving logs'}
            </p>
          </div>
        ) : (
          <List
            ref={listRef}
            height={listHeight}
            itemCount={state.entries.length}
            itemSize={getItemSize}
            width="100%"
            onScroll={handleScroll}
            overscanCount={10}
          >
            {({ index, style }) => (
              <LogRow
                entry={state.entries[index]}
                style={style as CSSProperties}
                isExpanded={expandedRows.has(state.entries[index].id)}
                onToggle={() => toggleRow(state.entries[index].id)}
              />
            )}
          </List>
        )}
      </div>

      {/* Footer status */}
      <div className="px-4 py-1.5 border-t border-border-subtle bg-surface-raised">
        <div className="flex items-center justify-between text-xs text-ink-muted">
          <span>
            Sensor: <span className="font-mono">{sensorId}</span>
          </span>
          <span>
            Buffer: {state.entries.length.toLocaleString()} / 5,000
          </span>
        </div>
      </div>
    </div>
  );
}

export default LogViewer;
