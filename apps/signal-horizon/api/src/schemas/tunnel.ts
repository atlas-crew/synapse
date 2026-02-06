/**
 * Zod Validation Schemas for Tunnel Protocol Messages
 *
 * Provides comprehensive runtime validation for all tunnel protocol messages
 * with strict type checking, size limits, and detailed error reporting.
 *
 * @module tunnel-schemas
 */

import { z } from 'zod';
import { zodRegexSafeSuperRefine } from '../lib/regex-validator.js';

// =============================================================================
// Constants
// =============================================================================

/** Maximum size for shell data payload (64KB before base64 encoding) */
const MAX_SHELL_DATA_SIZE = 87381; // ~64KB after base64 (65536 * 4/3)

/** Maximum lines for log backfill */
const MAX_BACKFILL_LINES = 1000;

/** Maximum file entries in directory listing */
const MAX_FILE_ENTRIES = 1000;

/** Maximum chunk size for file transfer (64KB before base64 encoding) */
const MAX_CHUNK_SIZE = 87381;

// =============================================================================
// Base Schemas
// =============================================================================

/**
 * Tunnel channel types.
 */
export const TunnelChannelSchema = z.enum([
  'shell',
  'logs',
  'diag',
  'control',
  'files',
]);

/**
 * Session state schema.
 */
export const TunnelSessionStateSchema = z.enum([
  'starting',
  'active',
  'closing',
  'closed',
  'error',
]);

/**
 * Base tunnel message fields present in all channel messages.
 */
export const TunnelMessageBaseSchema = z.object({
  channel: TunnelChannelSchema,
  sessionId: z.string().min(1).max(64),
  sequenceId: z.number().int().nonnegative(),
  timestamp: z.number().int().positive(),
});

// =============================================================================
// Shell Channel Schemas
// =============================================================================

export const ShellDataMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('shell'),
  type: z.literal('data'),
  data: z.string().max(MAX_SHELL_DATA_SIZE, `Shell data exceeds ${MAX_SHELL_DATA_SIZE} bytes`),
});

export const ShellResizeMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('shell'),
  type: z.literal('resize'),
  cols: z.number().int().min(1).max(1000),
  rows: z.number().int().min(1).max(1000),
});

export const ShellExitMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('shell'),
  type: z.literal('exit'),
  code: z.number().int(),
  signal: z.string().max(32).optional(),
});

export const ShellStartMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('shell'),
  type: z.literal('start'),
  cols: z.number().int().min(1).max(1000),
  rows: z.number().int().min(1).max(1000),
  shell: z.string().max(256).optional(),
  env: z.record(z.string().max(4096)).optional(),
});

export const ShellStartedMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('shell'),
  type: z.literal('started'),
  pid: z.number().int().positive(),
  shell: z.string().max(256),
});

export const ShellErrorMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('shell'),
  type: z.literal('error'),
  code: z.string().max(64),
  message: z.string().max(1024),
});

/**
 * Union of all shell message schemas.
 */
export const ShellMessageSchema = z.discriminatedUnion('type', [
  ShellDataMessageSchema,
  ShellResizeMessageSchema,
  ShellExitMessageSchema,
  ShellStartMessageSchema,
  ShellStartedMessageSchema,
  ShellErrorMessageSchema,
]);

export type ValidatedShellMessage = z.infer<typeof ShellMessageSchema>;

// =============================================================================
// Logs Channel Schemas
// =============================================================================

export const LogSourceSchema = z.enum([
  'system',
  'sensor',
  'access',
  'error',
  'audit',
  'security',
  'waf',
]);

export const LogLevelSchema = z.enum([
  'trace',
  'debug',
  'info',
  'warn',
  'error',
  'fatal',
]);

export const LogFilterSchema = z.object({
  minLevel: LogLevelSchema.optional(),
  pattern: z.string().max(256).optional(),
  regex: z.string().max(500).superRefine(zodRegexSafeSuperRefine).optional(),
  components: z.array(z.string().max(128)).max(50).optional(),
  since: z.number().int().positive().optional(),
  until: z.number().int().positive().optional(),
}).strict();

export const LogSubscribeMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('logs'),
  type: z.literal('subscribe'),
  sources: z.array(LogSourceSchema).min(1).max(10),
  filter: LogFilterSchema.optional(),
  backfill: z.boolean().optional(),
  backfillLines: z.number().int().min(1).max(MAX_BACKFILL_LINES).optional(),
});

export const LogUnsubscribeMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('logs'),
  type: z.literal('unsubscribe'),
  sources: z.array(LogSourceSchema).max(10).optional(),
});

export const LogEntryMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('logs'),
  type: z.literal('entry'),
  source: LogSourceSchema,
  level: LogLevelSchema,
  message: z.string().max(16384),
  fields: z.record(z.unknown()).optional(),
  logTimestamp: z.number().int().positive(),
  component: z.string().max(128).optional(),
});

export const LogBackfillMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('logs'),
  type: z.literal('backfill-complete'),
  count: z.number().int().nonnegative(),
  sources: z.array(LogSourceSchema),
});

export const LogErrorMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('logs'),
  type: z.literal('error'),
  code: z.string().max(64),
  message: z.string().max(1024),
});

/**
 * Union of all logs message schemas.
 */
export const LogsMessageSchema = z.discriminatedUnion('type', [
  LogSubscribeMessageSchema,
  LogUnsubscribeMessageSchema,
  LogEntryMessageSchema,
  LogBackfillMessageSchema,
  LogErrorMessageSchema,
]);

export type ValidatedLogsMessage = z.infer<typeof LogsMessageSchema>;

// =============================================================================
// Diagnostics Channel Schemas
// =============================================================================

export const DiagnosticTypeSchema = z.enum([
  'health',
  'memory',
  'connections',
  'rules',
  'actors',
  'config',
  'metrics',
  'threads',
  'cache',
]);

export const DiagRequestMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('diag'),
  type: z.literal('request'),
  diagType: DiagnosticTypeSchema,
  params: z.record(z.unknown()).optional(),
  requestId: z.string().min(1).max(64),
});

// Diagnostic payload schemas
export const HealthDiagnosticSchema = z.object({
  diagType: z.literal('health'),
  status: z.enum(['healthy', 'degraded', 'unhealthy']),
  uptime: z.number().nonnegative(),
  version: z.string().max(64),
  components: z.array(z.object({
    name: z.string().max(128),
    status: z.enum(['healthy', 'degraded', 'unhealthy']),
    message: z.string().max(512).optional(),
  })),
});

export const MemoryDiagnosticSchema = z.object({
  diagType: z.literal('memory'),
  heapUsed: z.number().nonnegative(),
  heapTotal: z.number().nonnegative(),
  heapLimit: z.number().nonnegative(),
  external: z.number().nonnegative(),
  rss: z.number().nonnegative(),
  arrayBuffers: z.number().nonnegative(),
  gcStats: z.object({
    collections: z.number().nonnegative(),
    pauseMs: z.number().nonnegative(),
  }).optional(),
});

export const ConnectionsDiagnosticSchema = z.object({
  diagType: z.literal('connections'),
  activeConnections: z.number().int().nonnegative(),
  maxConnections: z.number().int().nonnegative(),
  connectionsByType: z.record(z.number().int().nonnegative()),
  recentConnections: z.array(z.object({
    id: z.string().max(64),
    remoteAddr: z.string().max(64),
    connectedAt: z.number().int().positive(),
    bytesIn: z.number().nonnegative(),
    bytesOut: z.number().nonnegative(),
  })),
});

export const RulesDiagnosticSchema = z.object({
  diagType: z.literal('rules'),
  totalRules: z.number().int().nonnegative(),
  enabledRules: z.number().int().nonnegative(),
  disabledRules: z.number().int().nonnegative(),
  rulesByCategory: z.record(z.number().int().nonnegative()),
  lastUpdated: z.number().int().nonnegative(),
  rulesHash: z.string().max(128),
  topTriggeredRules: z.array(z.object({
    id: z.string().max(64),
    name: z.string().max(256),
    triggerCount: z.number().int().nonnegative(),
    lastTriggered: z.number().int().nonnegative(),
  })),
});

export const ActorsDiagnosticSchema = z.object({
  diagType: z.literal('actors'),
  trackedActors: z.number().int().nonnegative(),
  blockedActors: z.number().int().nonnegative(),
  actorsByType: z.record(z.number().int().nonnegative()),
  topActors: z.array(z.object({
    id: z.string().max(64),
    type: z.string().max(64),
    riskScore: z.number().min(0).max(100),
    hitCount: z.number().int().nonnegative(),
    lastSeen: z.number().int().nonnegative(),
  })),
});

export const ConfigDiagnosticSchema = z.object({
  diagType: z.literal('config'),
  configHash: z.string().max(128),
  lastUpdated: z.number().int().nonnegative(),
  settings: z.record(z.unknown()),
});

export const MetricsDiagnosticSchema = z.object({
  diagType: z.literal('metrics'),
  requestsTotal: z.number().nonnegative(),
  requestsPerSecond: z.number().nonnegative(),
  latencyP50: z.number().nonnegative(),
  latencyP95: z.number().nonnegative(),
  latencyP99: z.number().nonnegative(),
  errorsTotal: z.number().nonnegative(),
  errorRate: z.number().min(0).max(1),
  bytesIn: z.number().nonnegative(),
  bytesOut: z.number().nonnegative(),
});

export const ThreadsDiagnosticSchema = z.object({
  diagType: z.literal('threads'),
  workerThreads: z.number().int().nonnegative(),
  activeThreads: z.number().int().nonnegative(),
  pendingTasks: z.number().int().nonnegative(),
  completedTasks: z.number().int().nonnegative(),
  threadPool: z.array(z.object({
    id: z.number().int(),
    state: z.enum(['idle', 'busy', 'blocked']),
    currentTask: z.string().max(256).optional(),
  })),
});

export const CacheDiagnosticSchema = z.object({
  diagType: z.literal('cache'),
  caches: z.array(z.object({
    name: z.string().max(128),
    size: z.number().int().nonnegative(),
    maxSize: z.number().int().nonnegative(),
    hits: z.number().int().nonnegative(),
    misses: z.number().int().nonnegative(),
    hitRate: z.number().min(0).max(1),
    evictions: z.number().int().nonnegative(),
  })),
});

export const DiagnosticPayloadSchema = z.discriminatedUnion('diagType', [
  HealthDiagnosticSchema,
  MemoryDiagnosticSchema,
  ConnectionsDiagnosticSchema,
  RulesDiagnosticSchema,
  ActorsDiagnosticSchema,
  ConfigDiagnosticSchema,
  MetricsDiagnosticSchema,
  ThreadsDiagnosticSchema,
  CacheDiagnosticSchema,
]);

export const DiagResponseMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('diag'),
  type: z.literal('response'),
  requestId: z.string().min(1).max(64),
  data: DiagnosticPayloadSchema,
  collectionTimeMs: z.number().nonnegative(),
});

export const DiagErrorMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('diag'),
  type: z.literal('error'),
  requestId: z.string().min(1).max(64),
  code: z.string().max(64),
  message: z.string().max(1024),
});

/**
 * Union of all diagnostics message schemas.
 */
export const DiagMessageSchema = z.discriminatedUnion('type', [
  DiagRequestMessageSchema,
  DiagResponseMessageSchema,
  DiagErrorMessageSchema,
]);

export type ValidatedDiagMessage = z.infer<typeof DiagMessageSchema>;

// =============================================================================
// Control Channel Schemas
// =============================================================================

export const ControlOperationSchema = z.enum([
  'reload',
  'restart',
  'shutdown',
  'drain',
  'resume',
]);

export const ControlRequestMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('control'),
  type: z.literal('request'),
  operation: ControlOperationSchema,
  requestId: z.string().min(1).max(64),
  params: z.object({
    timeoutMs: z.number().int().positive().max(600000).optional(),
    force: z.boolean().optional(),
    gracePeriodMs: z.number().int().positive().max(300000).optional(),
  }).optional(),
});

export const ControlAckMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('control'),
  type: z.literal('ack'),
  requestId: z.string().min(1).max(64),
  accepted: z.boolean(),
  reason: z.string().max(512).optional(),
});

export const ControlProgressMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('control'),
  type: z.literal('progress'),
  requestId: z.string().min(1).max(64),
  phase: z.string().max(128),
  progress: z.number().min(0).max(100),
  message: z.string().max(512).optional(),
});

export const ControlCompleteMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('control'),
  type: z.literal('complete'),
  requestId: z.string().min(1).max(64),
  success: z.boolean(),
  message: z.string().max(512).optional(),
  result: z.record(z.unknown()).optional(),
});

export const ControlErrorMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('control'),
  type: z.literal('error'),
  requestId: z.string().min(1).max(64),
  code: z.string().max(64),
  message: z.string().max(1024),
});

/**
 * Union of all control message schemas.
 */
export const ControlMessageSchema = z.discriminatedUnion('type', [
  ControlRequestMessageSchema,
  ControlAckMessageSchema,
  ControlProgressMessageSchema,
  ControlCompleteMessageSchema,
  ControlErrorMessageSchema,
]);

export type ValidatedControlMessage = z.infer<typeof ControlMessageSchema>;

// =============================================================================
// Files Channel Schemas
// =============================================================================

export const FileTypeSchema = z.enum(['file', 'directory', 'symlink', 'unknown']);

export const FileEntrySchema = z.object({
  name: z.string().min(1).max(256),
  type: FileTypeSchema,
  size: z.number().int().nonnegative(),
  modifiedAt: z.number().int().nonnegative(),
  permissions: z.string().regex(/^[0-7]{3,4}$/),
  owner: z.string().max(64).optional(),
  group: z.string().max(64).optional(),
  linkTarget: z.string().max(4096).optional(),
});

export const FileListMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('files'),
  type: z.literal('list'),
  path: z.string().min(1).max(4096),
  requestId: z.string().min(1).max(64),
  includeHidden: z.boolean().optional(),
});

export const FileListResponseMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('files'),
  type: z.literal('list-response'),
  requestId: z.string().min(1).max(64),
  path: z.string().min(1).max(4096),
  entries: z.array(FileEntrySchema).max(MAX_FILE_ENTRIES),
  totalCount: z.number().int().nonnegative(),
  truncated: z.boolean(),
});

export const FileReadMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('files'),
  type: z.literal('read'),
  path: z.string().min(1).max(4096),
  requestId: z.string().min(1).max(64),
  offset: z.number().int().nonnegative().optional(),
  length: z.number().int().positive().optional(),
});

export const FileReadChunkMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('files'),
  type: z.literal('read-chunk'),
  requestId: z.string().min(1).max(64),
  chunkIndex: z.number().int().nonnegative(),
  data: z.string().max(MAX_CHUNK_SIZE),
  offset: z.number().int().nonnegative(),
});

export const FileReadCompleteMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('files'),
  type: z.literal('read-complete'),
  requestId: z.string().min(1).max(64),
  totalBytes: z.number().int().nonnegative(),
  totalChunks: z.number().int().nonnegative(),
  checksum: z.string().regex(/^[a-f0-9]{64}$/, 'Must be SHA-256 hex string'),
});

export const FileWriteMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('files'),
  type: z.literal('write'),
  path: z.string().min(1).max(4096),
  requestId: z.string().min(1).max(64),
  totalSize: z.number().int().nonnegative(),
  checksum: z.string().regex(/^[a-f0-9]{64}$/, 'Must be SHA-256 hex string'),
  overwrite: z.boolean().optional(),
});

export const FileWriteChunkMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('files'),
  type: z.literal('write-chunk'),
  requestId: z.string().min(1).max(64),
  chunkIndex: z.number().int().nonnegative(),
  data: z.string().max(MAX_CHUNK_SIZE),
  final: z.boolean(),
});

export const FileWriteAckMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('files'),
  type: z.literal('write-ack'),
  requestId: z.string().min(1).max(64),
  chunkIndex: z.number().int().nonnegative(),
  bytesWritten: z.number().int().nonnegative(),
});

export const FileWriteCompleteMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('files'),
  type: z.literal('write-complete'),
  requestId: z.string().min(1).max(64),
  totalBytes: z.number().int().nonnegative(),
  path: z.string().min(1).max(4096),
});

export const FileStatMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('files'),
  type: z.literal('stat'),
  path: z.string().min(1).max(4096),
  requestId: z.string().min(1).max(64),
});

export const FileStatResponseMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('files'),
  type: z.literal('stat-response'),
  requestId: z.string().min(1).max(64),
  path: z.string().min(1).max(4096),
  entry: FileEntrySchema,
});

export const FileErrorMessageSchema = TunnelMessageBaseSchema.extend({
  channel: z.literal('files'),
  type: z.literal('error'),
  requestId: z.string().max(64).optional(),
  code: z.string().max(64),
  message: z.string().max(1024),
});

/**
 * Union of all files message schemas.
 */
export const FilesMessageSchema = z.discriminatedUnion('type', [
  FileListMessageSchema,
  FileListResponseMessageSchema,
  FileReadMessageSchema,
  FileReadChunkMessageSchema,
  FileReadCompleteMessageSchema,
  FileWriteMessageSchema,
  FileWriteChunkMessageSchema,
  FileWriteAckMessageSchema,
  FileWriteCompleteMessageSchema,
  FileStatMessageSchema,
  FileStatResponseMessageSchema,
  FileErrorMessageSchema,
]);

export type ValidatedFilesMessage = z.infer<typeof FilesMessageSchema>;

// =============================================================================
// Legacy Protocol Schemas (P1-TYPE-001)
// =============================================================================

/**
 * Schema for legacy tunnel messages (backward compatibility).
 */
export const LegacyTunnelMessageSchema = z.object({
  type: z.string().max(64),
  sessionId: z.string().max(64).optional(),
  requestId: z.string().max(64).optional(),
  payload: z.unknown(),
  timestamp: z.string().max(64),
});

export type ValidatedLegacyTunnelMessage = z.infer<typeof LegacyTunnelMessageSchema>;

// =============================================================================
// Session Management Schemas
// =============================================================================

export const SessionOpenMessageSchema = z.object({
  type: z.literal('session-open'),
  channel: TunnelChannelSchema,
  sessionId: z.string().min(1).max(64).optional(),
  authToken: z.string().min(1).max(512),
  timestamp: z.number().int().positive(),
});

export const SessionOpenedMessageSchema = z.object({
  type: z.literal('session-opened'),
  channel: TunnelChannelSchema,
  sessionId: z.string().min(1).max(64),
  capabilities: z.array(z.string().max(64)),
  timestamp: z.number().int().positive(),
});

export const SessionCloseMessageSchema = z.object({
  type: z.literal('session-close'),
  channel: TunnelChannelSchema,
  sessionId: z.string().min(1).max(64),
  reason: z.string().max(512).optional(),
  timestamp: z.number().int().positive(),
});

export const SessionClosedMessageSchema = z.object({
  type: z.literal('session-closed'),
  channel: TunnelChannelSchema,
  sessionId: z.string().min(1).max(64),
  status: z.enum(['normal', 'timeout', 'error', 'forced']),
  reason: z.string().max(512).optional(),
  timestamp: z.number().int().positive(),
});

export const SessionErrorMessageSchema = z.object({
  type: z.literal('session-error'),
  channel: TunnelChannelSchema.optional(),
  sessionId: z.string().min(1).max(64).optional(),
  code: z.string().max(64),
  message: z.string().max(1024),
  timestamp: z.number().int().positive(),
});

/**
 * Union of all session management message schemas.
 */
export const SessionMessageSchema = z.discriminatedUnion('type', [
  SessionOpenMessageSchema,
  SessionOpenedMessageSchema,
  SessionCloseMessageSchema,
  SessionClosedMessageSchema,
  SessionErrorMessageSchema,
]);

export type ValidatedSessionMessage = z.infer<typeof SessionMessageSchema>;

// =============================================================================
// Channel-Specific Message Schema by Channel
// =============================================================================

/**
 * Map channel to its message schema for dynamic validation.
 */
export const ChannelMessageSchemas = {
  shell: ShellMessageSchema,
  logs: LogsMessageSchema,
  diag: DiagMessageSchema,
  control: ControlMessageSchema,
  files: FilesMessageSchema,
} as const;

// =============================================================================
// Master Tunnel Message Schema
// =============================================================================

/**
 * Validates a tunnel channel message (not session management).
 * Uses channel discriminator then type discriminator for proper narrowing.
 */
export const TunnelMessageSchema = z.union([
  // Shell channel
  ShellDataMessageSchema,
  ShellResizeMessageSchema,
  ShellExitMessageSchema,
  ShellStartMessageSchema,
  ShellStartedMessageSchema,
  ShellErrorMessageSchema,
  // Logs channel
  LogSubscribeMessageSchema,
  LogUnsubscribeMessageSchema,
  LogEntryMessageSchema,
  LogBackfillMessageSchema,
  LogErrorMessageSchema,
  // Diag channel
  DiagRequestMessageSchema,
  DiagResponseMessageSchema,
  DiagErrorMessageSchema,
  // Control channel
  ControlRequestMessageSchema,
  ControlAckMessageSchema,
  ControlProgressMessageSchema,
  ControlCompleteMessageSchema,
  ControlErrorMessageSchema,
  // Files channel
  FileListMessageSchema,
  FileListResponseMessageSchema,
  FileReadMessageSchema,
  FileReadChunkMessageSchema,
  FileReadCompleteMessageSchema,
  FileWriteMessageSchema,
  FileWriteChunkMessageSchema,
  FileWriteAckMessageSchema,
  FileWriteCompleteMessageSchema,
  FileStatMessageSchema,
  FileStatResponseMessageSchema,
  FileErrorMessageSchema,
]);

export type ValidatedTunnelMessage = z.infer<typeof TunnelMessageSchema>;

/**
 * Full tunnel protocol message including session management.
 */
export const TunnelProtocolMessageSchema = z.union([
  TunnelMessageSchema,
  SessionMessageSchema,
]);

export type ValidatedTunnelProtocolMessage = z.infer<typeof TunnelProtocolMessageSchema>;

// =============================================================================
// Validation Helpers
// =============================================================================

/**
 * Result type for validation operations.
 */
export type ValidationResult<T> =
  | { success: true; data: T }
  | { success: false; errors: string[] };

/**
 * Validates and parses a tunnel message with detailed error reporting.
 *
 * @param data - Unknown data to validate
 * @returns Validation result with typed data or error messages
 *
 * @example
 * ```typescript
 * const result = validateTunnelMessage(incomingData);
 * if (result.success) {
 *   handleMessage(result.data); // TypeScript knows the type
 * } else {
 *   logger.warn({ errors: result.errors }, 'Invalid tunnel message');
 * }
 * ```
 */
export function validateTunnelMessage(
  data: unknown
): ValidationResult<ValidatedTunnelMessage> {
  const result = TunnelMessageSchema.safeParse(data);

  if (result.success) {
    return { success: true, data: result.data };
  }

  const errors = result.error.issues.map(
    (issue) => `${issue.path.join('.')}: ${issue.message}`
  );

  return { success: false, errors };
}

/**
 * Validates and parses a tunnel protocol message (including session management).
 *
 * @param data - Unknown data to validate
 * @returns Validation result with typed data or error messages
 */
export function validateTunnelProtocolMessage(
  data: unknown
): ValidationResult<ValidatedTunnelProtocolMessage> {
  const result = TunnelProtocolMessageSchema.safeParse(data);

  if (result.success) {
    return { success: true, data: result.data };
  }

  const errors = result.error.issues.map(
    (issue) => `${issue.path.join('.')}: ${issue.message}`
  );

  return { success: false, errors };
}

/**
 * Validates and parses a session message.
 *
 * @param data - Unknown data to validate
 * @returns Validation result with typed data or error messages
 */
export function validateSessionMessage(
  data: unknown
): ValidationResult<ValidatedSessionMessage> {
  const result = SessionMessageSchema.safeParse(data);

  if (result.success) {
    return { success: true, data: result.data };
  }

  const errors = result.error.issues.map(
    (issue) => `${issue.path.join('.')}: ${issue.message}`
  );

  return { success: false, errors };
}

/**
 * Validates a message for a specific channel.
 * More efficient than full validation when channel is known.
 *
 * @param channel - The channel type
 * @param data - Unknown data to validate
 * @returns Validation result with typed data or error messages
 */
export function validateChannelMessage(
  channel: keyof typeof ChannelMessageSchemas,
  data: unknown
): ValidationResult<
  | ValidatedShellMessage
  | ValidatedLogsMessage
  | ValidatedDiagMessage
  | ValidatedControlMessage
  | ValidatedFilesMessage
> {
  const schema = ChannelMessageSchemas[channel];
  const result = schema.safeParse(data);

  if (result.success) {
    return { success: true, data: result.data };
  }

  const errors = result.error.issues.map(
    (issue) => `${issue.path.join('.')}: ${issue.message}`
  );

  return { success: false, errors };
}

/**
 * Checks if a message has a valid structure without full validation.
 * Useful for quick routing decisions before full validation.
 *
 * @param data - Data to check
 * @returns True if data has valid channel and type fields
 */
export function hasValidTunnelStructure(data: unknown): boolean {
  if (typeof data !== 'object' || data === null) {
    return false;
  }

  const obj = data as Record<string, unknown>;

  // Check for session message
  if ('type' in obj && typeof obj.type === 'string') {
    const sessionTypes = [
      'session-open',
      'session-opened',
      'session-close',
      'session-closed',
      'session-error',
    ];
    if (sessionTypes.includes(obj.type)) {
      return true;
    }
  }

  // Check for channel message
  if (
    'channel' in obj &&
    'type' in obj &&
    'sessionId' in obj &&
    'sequenceId' in obj &&
    'timestamp' in obj
  ) {
    const validChannels = ['shell', 'logs', 'diag', 'control', 'files'];
    return (
      typeof obj.channel === 'string' &&
      validChannels.includes(obj.channel) &&
      typeof obj.type === 'string' &&
      typeof obj.sessionId === 'string' &&
      typeof obj.sequenceId === 'number' &&
      typeof obj.timestamp === 'number'
    );
  }

  return false;
}

/**
 * Extracts channel from a tunnel message without full validation.
 * Returns undefined if channel cannot be determined.
 *
 * @param data - Data to extract channel from
 * @returns Channel type or undefined
 */
export function extractChannel(
  data: unknown
): keyof typeof ChannelMessageSchemas | undefined {
  if (typeof data !== 'object' || data === null) {
    return undefined;
  }

  const obj = data as Record<string, unknown>;

  if ('channel' in obj && typeof obj.channel === 'string') {
    const channel = obj.channel;
    if (channel in ChannelMessageSchemas) {
      return channel as keyof typeof ChannelMessageSchemas;
    }
  }

  return undefined;
}
