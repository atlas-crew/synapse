/**
 * Log Viewer Type Definitions
 *
 * Types for the virtualized log viewer component including
 * log entries, filters, and streaming state.
 */

export type LogSource = 'access' | 'error' | 'waf' | 'audit' | 'system';
export type LogLevel = 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';

/**
 * Individual log entry from a sensor
 */
export interface LogEntry {
  /** Unique identifier for the log entry */
  id: string;
  /** Timestamp when the log was generated */
  timestamp: Date;
  /** Source category of the log */
  source: LogSource;
  /** Severity level */
  level: LogLevel;
  /** Log message content */
  message: string;
  /** Additional structured fields */
  fields?: Record<string, unknown>;
  // Structured access log fields
  /** HTTP method (for access logs) */
  method?: string;
  /** Request path (for access logs) */
  path?: string;
  /** HTTP status code (for access logs) */
  statusCode?: number;
  /** Request latency in milliseconds */
  latencyMs?: number;
  /** Client IP address */
  clientIp?: string;
  /** WAF rule ID that triggered (for waf logs) */
  ruleId?: string;
}

/**
 * Filter criteria for log entries
 */
export interface LogFilter {
  /** Filter by log sources */
  sources?: LogSource[];
  /** Filter by minimum log level */
  levels?: LogLevel[];
  /** Text search in message content */
  search?: string;
  /** Only show logs after this timestamp */
  since?: Date;
}

/**
 * State for the log stream connection and buffer
 */
export interface LogStreamState {
  /** Whether the WebSocket is connected */
  connected: boolean;
  /** Buffered log entries (newest first) */
  entries: LogEntry[];
  /** Current active filter */
  filter: LogFilter;
  /** Whether new entries are paused from display */
  paused: boolean;
  /** Count of entries dropped due to buffer limits */
  dropped: number;
}

/**
 * Color configuration for log levels
 */
export const LOG_LEVEL_COLORS: Record<LogLevel, { bg: string; text: string; border: string }> = {
  trace: { bg: 'bg-gray-100', text: 'text-gray-500', border: 'border-gray-300' },
  debug: { bg: 'bg-blue-100', text: 'text-blue-700', border: 'border-blue-300' },
  info: { bg: 'bg-green-100', text: 'text-green-700', border: 'border-green-300' },
  warn: { bg: 'bg-yellow-100', text: 'text-yellow-700', border: 'border-yellow-300' },
  error: { bg: 'bg-red-100', text: 'text-red-700', border: 'border-red-300' },
  fatal: { bg: 'bg-red-200', text: 'text-red-900', border: 'border-red-500' },
};

/**
 * Icon mapping for log sources
 */
export const LOG_SOURCE_ICONS: Record<LogSource, string> = {
  access: 'globe',
  error: 'alert-circle',
  waf: 'shield',
  audit: 'file-text',
  system: 'settings',
};

/**
 * Display labels for log sources
 */
export const LOG_SOURCE_LABELS: Record<LogSource, string> = {
  access: 'Access',
  error: 'Error',
  waf: 'WAF',
  audit: 'Audit',
  system: 'System',
};

/**
 * All available log sources
 */
export const ALL_LOG_SOURCES: LogSource[] = ['access', 'error', 'waf', 'audit', 'system'];

/**
 * All available log levels in order of severity
 */
export const ALL_LOG_LEVELS: LogLevel[] = ['trace', 'debug', 'info', 'warn', 'error', 'fatal'];

/**
 * Level filter presets for quick selection
 */
export const LOG_LEVEL_PRESETS = {
  all: [] as LogLevel[],
  'debug+': ['debug', 'info', 'warn', 'error', 'fatal'] as LogLevel[],
  'info+': ['info', 'warn', 'error', 'fatal'] as LogLevel[],
  'warn+': ['warn', 'error', 'fatal'] as LogLevel[],
  'error+': ['error', 'fatal'] as LogLevel[],
} as const;

export type LogLevelPreset = keyof typeof LOG_LEVEL_PRESETS;

/**
 * WebSocket message types for log streaming
 */
export interface LogSubscribeMessage {
  type: 'subscribe';
  channel: 'logs';
  sensorId: string;
  filter?: LogFilter;
}

export interface LogUnsubscribeMessage {
  type: 'unsubscribe';
  channel: 'logs';
  sensorId: string;
}

export interface LogEntryMessage {
  type: 'log';
  entry: {
    id: string;
    timestamp: string;
    source: LogSource;
    level: LogLevel;
    message: string;
    logTimestamp?: number;
    fields?: Record<string, unknown>;
    method?: string;
    path?: string;
    statusCode?: number;
    latencyMs?: number;
    clientIp?: string;
    ruleId?: string;
  };
}

export interface LogBatchMessage {
  type: 'log-batch';
  entries: LogEntryMessage['entry'][];
}

export interface TunnelLogEntryMessage {
  type: 'entry';
  channel: 'logs';
  sessionId?: string;
  source: LogSource;
  level: LogLevel;
  message: string;
  fields?: Record<string, unknown>;
  method?: string;
  path?: string;
  statusCode?: number;
  latencyMs?: number;
  clientIp?: string;
  ruleId?: string;
  logTimestamp?: number;
}

export interface LogBackfillCompleteMessage {
  type: 'backfill-complete';
  channel: 'logs';
  sessionId?: string;
  count?: number;
  sources?: LogSource[];
}

export type LogStreamMessage =
  | LogEntryMessage
  | LogBatchMessage
  | TunnelLogEntryMessage
  | LogBackfillCompleteMessage;
