import { useEffect, useId, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  EmptyState,
  Input,
  Select,
  Spinner,
  Stack,
  Tabs,
  Text,
  colors,
  spacing,
} from '@atlascrew/signal-ui';

type ApiEnvelope<T> = {
  success: boolean;
  data?: T;
  error?: string;
};

type ApiReadResult<T> = {
  data: T;
  etag: string | null;
};

type HealthResponse = {
  status?: string;
  healthy?: boolean;
  [key: string]: unknown;
};

type StatusResponse = {
  running?: boolean;
  mode?: string;
  active_connections?: number;
  blocked_requests?: number;
  requests_seen?: number;
  [key: string]: unknown;
};

type SensorSiteInfo = {
  hostname?: string;
  upstreams?: string[];
  tls_enabled?: boolean;
  waf_enabled?: boolean;
  [key: string]: unknown;
};

type SensorConfigResponse = {
  success?: boolean;
  data?: {
    sites?: SensorSiteInfo[];
    [key: string]: unknown;
  };
  [key: string]: unknown;
};

type TrapConfig = {
  enabled?: boolean;
  paths?: string[];
  apply_max_risk?: boolean;
  extended_tarpit_ms?: number | null;
  alert_telemetry?: boolean;
  [key: string]: unknown;
};

type GlobalConfig = {
  http_addr?: string;
  https_addr?: string;
  workers?: number;
  shutdown_timeout_secs?: number;
  waf_threshold?: number;
  waf_enabled?: boolean;
  log_level?: string;
  admin_api_key?: string | null;
  trap_config?: TrapConfig | null;
  waf_regex_timeout_ms?: number;
  [key: string]: unknown;
};

type SiteWafConfig = {
  enabled?: boolean;
  threshold?: number | null;
  rule_overrides?: Record<string, string>;
  [key: string]: unknown;
};

type HeaderOpsConfig = {
  add?: Record<string, string>;
  set?: Record<string, string>;
  remove?: string[];
  [key: string]: unknown;
};

type HeaderConfig = {
  request?: HeaderOpsConfig;
  response?: HeaderOpsConfig;
  [key: string]: unknown;
};

type SiteConfig = {
  hostname?: string;
  upstreams?: Array<{ host?: string; port?: number; [key: string]: unknown }>;
  waf?: SiteWafConfig;
  headers?: HeaderConfig;
  shadow_mirror?: unknown;
  tls?: unknown;
  [key: string]: unknown;
};

type RateLimitConfig = {
  rps?: number;
  enabled?: boolean;
  burst?: number | null;
  [key: string]: unknown;
};

type ProfilerConfig = {
  enabled?: boolean;
  max_profiles?: number;
  max_schemas?: number;
  min_samples_for_validation?: number;
  payload_z_threshold?: number;
  param_z_threshold?: number;
  response_z_threshold?: number;
  min_stddev?: number;
  type_ratio_threshold?: number;
  max_type_counts?: number;
  redact_pii?: boolean;
  freeze_after_samples?: number;
  [key: string]: unknown;
};

type ConfigFile = {
  server: GlobalConfig;
  sites: SiteConfig[];
  rate_limit: RateLimitConfig;
  profiler: ProfilerConfig;
  [key: string]: unknown;
};

type MutationResult = {
  applied: boolean;
  persisted: boolean;
  rebuild_required: boolean;
  warnings?: string[];
  [key: string]: unknown;
};

type ServerFormState = {
  http_addr: string;
  https_addr: string;
  workers: string;
  shutdown_timeout_secs: string;
  waf_threshold: string;
  waf_enabled: boolean;
  log_level: string;
  admin_api_key: string;
  replace_admin_api_key: boolean;
  clear_admin_api_key: boolean;
  waf_regex_timeout_ms: string;
  trap_present: boolean;
  trap_enabled: boolean;
  trap_paths: string;
  trap_apply_max_risk: boolean;
  trap_extended_tarpit_ms: string;
  trap_alert_telemetry: boolean;
};

type SaveState =
  | { kind: 'idle' }
  | { kind: 'saving' }
  | { kind: 'success'; message: string; sticky?: boolean; warning?: string }
  | { kind: 'error'; message: string };

type RateLimitFormState = {
  enabled: boolean;
  rps: string;
  burst: string;
};

type ProfilerFormState = {
  enabled: boolean;
  max_profiles: string;
  max_schemas: string;
  min_samples_for_validation: string;
  payload_z_threshold: string;
  param_z_threshold: string;
  response_z_threshold: string;
  min_stddev: string;
  type_ratio_threshold: string;
  max_type_counts: string;
  redact_pii: boolean;
  freeze_after_samples: string;
};

type UpstreamFormRow = {
  id: string;
  baseUpstream: NonNullable<SiteConfig['upstreams']>[number] | null;
  host: string;
  port: string;
};

type KeyValueFormRow = {
  id: string;
  key: string;
  value: string;
};

type StringFormRow = {
  id: string;
  value: string;
};

type SiteWafFormState = {
  enabled: boolean;
  threshold: string;
  rule_overrides: KeyValueFormRow[];
};

type HeaderOpsFormState = {
  add: KeyValueFormRow[];
  set: KeyValueFormRow[];
  remove: StringFormRow[];
};

type SiteHeadersFormState = {
  request: HeaderOpsFormState;
  response: HeaderOpsFormState;
};

type SiteFormState = {
  hostname: string;
  upstreams: UpstreamFormRow[];
  waf: SiteWafFormState;
  headers: SiteHeadersFormState;
};

type SiteEditorState =
  | { mode: 'idle' }
  | { mode: 'add'; form: SiteFormState }
  | { mode: 'edit'; index: number; form: SiteFormState; baseSite: SiteConfig }
  | { mode: 'delete-confirm'; index: number };

type LoadState =
  | { kind: 'loading' }
  | {
      kind: 'ready';
      health?: HealthResponse;
      status?: StatusResponse;
      fullConfig?: ConfigFile;
      configEtag?: string | null;
      sensorConfig?: SensorConfigResponse;
      loadedAt: string;
      warnings: string[];
    };

const tabs = [
  { key: 'overview', label: 'Overview' },
  { key: 'server', label: 'Server' },
  { key: 'sites', label: 'Sites' },
  { key: 'rate-limit', label: 'Rate Limit' },
  { key: 'profiler', label: 'Profiler' },
  { key: 'roadmap', label: 'Roadmap' },
] as const;

const logLevelOptions = [
  { value: 'trace', label: 'trace' },
  { value: 'debug', label: 'debug' },
  { value: 'info', label: 'info' },
  { value: 'warn', label: 'warn' },
  { value: 'error', label: 'error' },
];

const defaultTrapPaths = [
  '/.git/*',
  '/.env',
  '/.env.*',
  '/admin/backup*',
  '/wp-admin/*',
  '/phpmyadmin/*',
  '/.svn/*',
  '/.htaccess',
  '/web.config',
  '/config.php',
];

type TabKey = (typeof tabs)[number]['key'];

function nextUpstreamRowId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `upstream-row-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function nextFormRowId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `form-row-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function buildKeyValueRows(source: Record<string, unknown> | undefined): KeyValueFormRow[] {
  if (!source) return [];
  return Object.entries(source).flatMap(([key, value]) =>
    typeof value === 'string'
      ? [
          {
            id: nextFormRowId(),
            key,
            value,
          },
        ]
      : [],
  );
}

function buildStringRows(source: unknown): StringFormRow[] {
  if (!Array.isArray(source)) return [];
  return source
    .filter((value): value is string => typeof value === 'string')
    .map((value) => ({
      id: nextFormRowId(),
      value,
    }));
}

function normalizeStringRecord(source: Record<string, unknown> | undefined): Record<string, string> {
  if (!source) return {};
  const next: Record<string, string> = {};
  Object.entries(source).forEach(([key, value]) => {
    if (typeof value === 'string') {
      next[key] = value;
    }
  });
  return next;
}

function recordsEqual(
  left: Record<string, string>,
  right: Record<string, string>,
): boolean {
  const leftEntries = Object.entries(left);
  const rightEntries = Object.entries(right);
  if (leftEntries.length !== rightEntries.length) return false;
  return leftEntries.every(([key, value]) => right[key] === value);
}

function arraysEqual(left: string[], right: string[]): boolean {
  if (left.length !== right.length) return false;
  return left.every((value, index) => value === right[index]);
}

function buildRuleOverrideRecord(rows: KeyValueFormRow[]): Record<string, string> {
  const next: Record<string, string> = {};
  rows.forEach((row, index) => {
    const key = row.key.trim();
    const value = row.value.trim();
    if (key === '' && value === '') return;
    if (key === '') {
      throw new Error(`Rule override #${index + 1}: rule ID is required.`);
    }
    if (value === '') {
      throw new Error(`Rule override #${index + 1}: action is required.`);
    }
    next[key] = value;
  });
  return next;
}

function buildHeaderRecord(rows: KeyValueFormRow[], label: string): Record<string, string> {
  const next: Record<string, string> = {};
  rows.forEach((row, index) => {
    const key = row.key.trim();
    const value = row.value.trim();
    if (key === '' && value === '') return;
    if (key === '') {
      throw new Error(`${label} #${index + 1}: header name is required.`);
    }
    if (value === '') {
      throw new Error(`${label} #${index + 1}: header value is required.`);
    }
    next[key] = value;
  });
  return next;
}

function buildRemoveList(rows: StringFormRow[]): string[] {
  return rows
    .map((row) => row.value.trim())
    .filter((value) => value !== '');
}

function buildHeaderOpsForm(source?: HeaderOpsConfig): HeaderOpsFormState {
  return {
    add: buildKeyValueRows(normalizeStringRecord(source?.add)),
    set: buildKeyValueRows(normalizeStringRecord(source?.set)),
    remove: buildStringRows(source?.remove),
  };
}

function buildHeadersForm(source?: HeaderConfig): SiteHeadersFormState {
  return {
    request: buildHeaderOpsForm(source?.request),
    response: buildHeaderOpsForm(source?.response),
  };
}

function buildWafForm(source?: SiteWafConfig): SiteWafFormState {
  return {
    enabled: source?.enabled ?? true,
    threshold:
      typeof source?.threshold === 'number' && Number.isFinite(source.threshold)
        ? String(source.threshold)
        : '',
    rule_overrides: buildKeyValueRows(normalizeStringRecord(source?.rule_overrides)),
  };
}

function normalizeHeaderOps(source?: HeaderOpsConfig): {
  add: Record<string, string>;
  set: Record<string, string>;
  remove: string[];
} {
  return {
    add: normalizeStringRecord(source?.add),
    set: normalizeStringRecord(source?.set),
    remove: Array.isArray(source?.remove)
      ? source.remove.filter((value): value is string => typeof value === 'string')
      : [],
  };
}

function buildHeaderOpsConfig(
  nextOps: { add: Record<string, string>; set: Record<string, string>; remove: string[] },
  base?: HeaderOpsConfig,
): HeaderOpsConfig {
  const baseRecord = isRecord(base) ? (base as HeaderOpsConfig) : {};
  const { add: _baseAdd, set: _baseSet, remove: _baseRemove, ...rest } = baseRecord;
  const next: HeaderOpsConfig = { ...rest };
  if (Object.keys(nextOps.add).length > 0) {
    next.add = nextOps.add;
  }
  if (Object.keys(nextOps.set).length > 0) {
    next.set = nextOps.set;
  }
  if (nextOps.remove.length > 0) {
    next.remove = nextOps.remove;
  }
  return next;
}

function extractMessage(data: unknown, fallback: string): string {
  if (typeof data === 'string') return data;
  if (data && typeof data === 'object') {
    if ('error' in data && typeof data.error === 'string') return data.error;
    if ('message' in data && typeof data.message === 'string') return data.message;
    if ('detail' in data && typeof data.detail === 'string') return data.detail;
  }
  return fallback;
}

async function requestJsonWithMeta<T>(
  path: string,
  init?: RequestInit,
): Promise<{ data: T; headers: Headers }> {
  const response = await fetch(path, init);
  const contentType = response.headers.get('content-type') ?? '';
  const text = await response.text();
  let data: unknown = text;

  if (contentType.includes('json')) {
    try {
      data = JSON.parse(text);
    } catch (error) {
      throw new Error(
        response.ok
          ? `Received malformed JSON from ${path}: ${error instanceof Error ? error.message : 'parse failure'}`
          : text,
      );
    }
  }

  if (!response.ok) {
    const fallbackMessage =
      response.status === 401
        ? 'Authentication expired or missing. Re-authenticate and retry.'
        : response.status === 403
          ? 'This session does not have permission for that action.'
          : response.status === 409 || response.status === 412
            ? 'Config changed elsewhere. Refresh to load the latest version and retry.'
          : `Request to ${path} failed with status ${response.status}.`;
    throw new Error(extractMessage(data, fallbackMessage));
  }

  return { data: data as T, headers: response.headers };
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const result = await requestJsonWithMeta<T>(path, init);
  return result.data;
}

async function readApiWithMeta<T>(path: string): Promise<ApiReadResult<T>> {
  const { data: envelope, headers } = await requestJsonWithMeta<ApiEnvelope<T>>(path);
  if (!envelope.success || envelope.data === undefined) {
    throw new Error(envelope.error ?? `Request to ${path} did not return data.`);
  }
  return {
    data: envelope.data,
    etag: headers.get('etag'),
  };
}

async function writeApi<T>(
  path: string,
  method: 'POST' | 'PUT',
  body: unknown,
  extraHeaders: Record<string, string> = {},
): Promise<T> {
  const envelope = await requestJson<ApiEnvelope<T>>(path, {
    method,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    body: JSON.stringify(body),
  });

  if (!envelope.success || envelope.data === undefined) {
    throw new Error(envelope.error ?? `${method} ${path} failed.`);
  }

  return envelope.data;
}

function formatBoolean(value: boolean | undefined): string {
  if (value === true) return 'Enabled';
  if (value === false) return 'Disabled';
  return 'Unknown';
}

function formatUpstreams(upstreams: SiteConfig['upstreams'] | undefined): string {
  if (!upstreams || upstreams.length === 0) {
    return 'Not configured';
  }

  return upstreams
    .map((upstream) => {
      if (!upstream.host) return 'Unknown upstream';
      return upstream.port ? `${upstream.host}:${upstream.port}` : upstream.host;
    })
    .join(', ');
}

function normalizeHostname(hostname: string | undefined): string {
  return (hostname ?? '').trim().toLowerCase().replace(/\.+$/, '');
}

function getRefreshWarning(nextState: LoadState): string {
  if (nextState.kind !== 'ready' || !nextState.fullConfig || !nextState.configEtag) {
    return 'Refresh failed. Reload the page before editing again.';
  }
  if (nextState.warnings.length > 0) {
    return `Refresh reported: ${nextState.warnings.join(' ')}`;
  }
  return '';
}

function getSaveButtonLabel(
  saveState: SaveState,
  isAnySaveInFlight: boolean,
  idleLabel: string,
): string {
  if (saveState.kind === 'saving') {
    return 'Saving…';
  }
  if (isAnySaveInFlight) {
    return 'Another save in progress…';
  }
  return idleLabel;
}

function updateUpstreamRow(
  row: UpstreamFormRow,
  field: 'host' | 'port',
  value: string,
): UpstreamFormRow {
  const nextRow = { ...row, [field]: value };
  if (!row.baseUpstream) {
    return nextRow;
  }

  const baseValue =
    field === 'host'
      ? typeof row.baseUpstream.host === 'string'
        ? row.baseUpstream.host
        : ''
      : row.baseUpstream.port === undefined || row.baseUpstream.port === null
        ? ''
        : String(row.baseUpstream.port);

  // Once host or port changes, stop carrying opaque extension keys from the original
  // upstream row so edits cannot accidentally inherit stale metadata.
  return value === baseValue ? nextRow : { ...nextRow, baseUpstream: null };
}

function buildRateLimitForm(rateLimit?: RateLimitConfig): RateLimitFormState {
  return {
    enabled: rateLimit?.enabled ?? true,
    rps: String(rateLimit?.rps ?? 10000),
    burst:
      rateLimit?.burst === undefined || rateLimit?.burst === null
        ? ''
        : String(rateLimit.burst),
  };
}

function buildProfilerForm(profiler?: ProfilerConfig): ProfilerFormState {
  return {
    enabled: profiler?.enabled ?? true,
    max_profiles: String(profiler?.max_profiles ?? 1000),
    max_schemas: String(profiler?.max_schemas ?? 500),
    min_samples_for_validation: String(profiler?.min_samples_for_validation ?? 100),
    payload_z_threshold: String(profiler?.payload_z_threshold ?? 3),
    param_z_threshold: String(profiler?.param_z_threshold ?? 4),
    response_z_threshold: String(profiler?.response_z_threshold ?? 4),
    min_stddev: String(profiler?.min_stddev ?? 0.01),
    type_ratio_threshold: String(profiler?.type_ratio_threshold ?? 0.9),
    max_type_counts: String(profiler?.max_type_counts ?? 10),
    redact_pii: profiler?.redact_pii ?? true,
    freeze_after_samples: String(profiler?.freeze_after_samples ?? 0),
  };
}

function buildSiteForm(site?: SiteConfig): SiteFormState {
  const upstreamSource = site?.upstreams && site.upstreams.length > 0 ? site.upstreams : [{}];
  return {
    hostname: site?.hostname ?? '',
    upstreams: upstreamSource.map((upstream, index) => ({
      id: nextUpstreamRowId(),
      baseUpstream: site?.upstreams ? structuredClone(site.upstreams[index]) : null,
      host: typeof upstream.host === 'string' ? upstream.host : '',
      port:
        upstream.port === undefined || upstream.port === null
          ? ''
          : String(upstream.port),
    })),
    waf: buildWafForm(site?.waf),
    headers: buildHeadersForm(site?.headers),
  };
}

function siteFromForm(form: SiteFormState, base?: SiteConfig): SiteConfig {
  const hostname = form.hostname.trim();
  if (normalizeHostname(hostname) === '') {
    throw new Error('Hostname is required.');
  }

  const upstreams = form.upstreams
    .map((row, index) => {
      const host = row.host.trim();
      const portRaw = row.port.trim();
      if (host === '' && portRaw === '') return null;
      if (host === '') {
        throw new Error(`Upstream #${index + 1}: host is required.`);
      }
      const baseUpstream = row.baseUpstream ?? {};
      if (portRaw === '') {
        const { port: _droppedPort, ...rest } = baseUpstream;
        return { ...rest, host };
      }
      const port = parseIntegerField(portRaw, `Upstream #${index + 1} port`, {
        min: 1,
        max: 65535,
      });
      return { ...baseUpstream, host, port };
    })
    .filter((row): row is NonNullable<typeof row> => row !== null);

  if (upstreams.length === 0) {
    throw new Error('At least one upstream with a hostname is required.');
  }

  const nextSite: SiteConfig = {
    ...(base ?? {}),
    hostname,
    upstreams,
  };

  const nextRuleOverrides = buildRuleOverrideRecord(form.waf.rule_overrides);
  const nextThreshold =
    form.waf.threshold.trim() === ''
      ? null
      : parseIntegerField(form.waf.threshold, 'Site WAF threshold', { min: 0, max: 100 });
  const baseWaf = base?.waf;
  const baseWafEnabled = baseWaf?.enabled ?? true;
  const baseWafThreshold =
    typeof baseWaf?.threshold === 'number' && Number.isFinite(baseWaf.threshold)
      ? baseWaf.threshold
      : null;
  const baseRuleOverrides = normalizeStringRecord(baseWaf?.rule_overrides);
  const wafMatchesBase =
    !!baseWaf &&
    form.waf.enabled === baseWafEnabled &&
    nextThreshold === baseWafThreshold &&
    recordsEqual(nextRuleOverrides, baseRuleOverrides);
  const wafIsMeaningful =
    form.waf.enabled !== true ||
    nextThreshold !== null ||
    Object.keys(nextRuleOverrides).length > 0;

  if (wafMatchesBase) {
    nextSite.waf = baseWaf;
  } else if (!baseWaf && !wafIsMeaningful) {
    delete nextSite.waf;
  } else {
    const baseWafRecord = isRecord(baseWaf) ? baseWaf : {};
    const {
      enabled: _baseEnabled,
      threshold: _baseThreshold,
      rule_overrides: _baseRuleOverrides,
      ...restWaf
    } = baseWafRecord;
    const nextWaf: SiteWafConfig = {
      ...restWaf,
      enabled: form.waf.enabled,
    };
    if (nextThreshold !== null) {
      nextWaf.threshold = nextThreshold;
    }
    if (Object.keys(nextRuleOverrides).length > 0) {
      nextWaf.rule_overrides = nextRuleOverrides;
    }
    if (Object.keys(nextWaf).length === 1 && nextWaf.enabled === true) {
      delete nextSite.waf;
    } else {
      nextSite.waf = nextWaf;
    }
  }

  const nextRequestOps = {
    add: buildHeaderRecord(form.headers.request.add, 'Request add header'),
    set: buildHeaderRecord(form.headers.request.set, 'Request set header'),
    remove: buildRemoveList(form.headers.request.remove),
  };
  const nextResponseOps = {
    add: buildHeaderRecord(form.headers.response.add, 'Response add header'),
    set: buildHeaderRecord(form.headers.response.set, 'Response set header'),
    remove: buildRemoveList(form.headers.response.remove),
  };
  const baseHeaders = base?.headers;
  const baseRequestOps = normalizeHeaderOps(baseHeaders?.request);
  const baseResponseOps = normalizeHeaderOps(baseHeaders?.response);
  const requestMatchesBase =
    recordsEqual(nextRequestOps.add, baseRequestOps.add) &&
    recordsEqual(nextRequestOps.set, baseRequestOps.set) &&
    arraysEqual(nextRequestOps.remove, baseRequestOps.remove);
  const responseMatchesBase =
    recordsEqual(nextResponseOps.add, baseResponseOps.add) &&
    recordsEqual(nextResponseOps.set, baseResponseOps.set) &&
    arraysEqual(nextResponseOps.remove, baseResponseOps.remove);
  const headersMatchBase = !!baseHeaders && requestMatchesBase && responseMatchesBase;
  const headersAreMeaningful =
    Object.keys(nextRequestOps.add).length > 0 ||
    Object.keys(nextRequestOps.set).length > 0 ||
    nextRequestOps.remove.length > 0 ||
    Object.keys(nextResponseOps.add).length > 0 ||
    Object.keys(nextResponseOps.set).length > 0 ||
    nextResponseOps.remove.length > 0;

  if (headersMatchBase) {
    nextSite.headers = baseHeaders;
  } else if (!baseHeaders && !headersAreMeaningful) {
    delete nextSite.headers;
  } else {
    const baseHeaderRecord = isRecord(baseHeaders) ? baseHeaders : {};
    const { request: _baseRequest, response: _baseResponse, ...restHeaders } = baseHeaderRecord;
    const nextRequestConfig = buildHeaderOpsConfig(nextRequestOps, baseHeaders?.request);
    const nextResponseConfig = buildHeaderOpsConfig(nextResponseOps, baseHeaders?.response);
    const nextHeaders: HeaderConfig = { ...restHeaders };
    if (Object.keys(nextRequestConfig).length > 0) {
      nextHeaders.request = nextRequestConfig;
    }
    if (Object.keys(nextResponseConfig).length > 0) {
      nextHeaders.response = nextResponseConfig;
    }
    if (Object.keys(nextHeaders).length === 0) {
      delete nextSite.headers;
    } else {
      nextSite.headers = nextHeaders;
    }
  }

  return nextSite;
}

function buildServerForm(server?: GlobalConfig): ServerFormState {
  const trap = server?.trap_config ?? null;

  return {
    http_addr: server?.http_addr ?? '0.0.0.0:80',
    https_addr: server?.https_addr ?? '0.0.0.0:443',
    workers: String(server?.workers ?? 0),
    shutdown_timeout_secs: String(server?.shutdown_timeout_secs ?? 30),
    waf_threshold: String(server?.waf_threshold ?? 70),
    waf_enabled: server?.waf_enabled ?? true,
    log_level: server?.log_level ?? 'info',
    admin_api_key: '',
    replace_admin_api_key: false,
    clear_admin_api_key: false,
    waf_regex_timeout_ms: String(server?.waf_regex_timeout_ms ?? 100),
    trap_present: trap !== null,
    trap_enabled: trap?.enabled ?? true,
    trap_paths: (trap?.paths ?? defaultTrapPaths).join('\n'),
    trap_apply_max_risk: trap?.apply_max_risk ?? true,
    trap_extended_tarpit_ms:
      trap?.extended_tarpit_ms === null || trap?.extended_tarpit_ms === undefined
        ? ''
        : String(trap.extended_tarpit_ms),
    trap_alert_telemetry: trap?.alert_telemetry ?? true,
  };
}

function parseIntegerField(
  value: string,
  label: string,
  options: { min?: number; max?: number } = {},
): number {
  const normalized = value.trim();
  if (normalized === '') {
    throw new Error(`${label} is required.`);
  }
  if (!/^-?\d+$/.test(normalized)) {
    throw new Error(`${label} must be a whole number.`);
  }
  const parsed = Number(normalized);
  if (options.min !== undefined && parsed < options.min) {
    throw new Error(`${label} must be at least ${options.min}.`);
  }
  if (options.max !== undefined && parsed > options.max) {
    throw new Error(`${label} must be at most ${options.max}.`);
  }
  return parsed;
}

function parseFloatField(
  value: string,
  label: string,
  options: { min?: number; max?: number } = {},
): number {
  const normalized = value.trim();
  if (normalized === '') {
    throw new Error(`${label} is required.`);
  }
  const parsed = Number(normalized);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${label} must be a number.`);
  }
  if (options.min !== undefined && parsed < options.min) {
    throw new Error(`${label} must be at least ${options.min}.`);
  }
  if (options.max !== undefined && parsed > options.max) {
    throw new Error(`${label} must be at most ${options.max}.`);
  }
  return parsed;
}

function MetricTile({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: string;
}) {
  return (
    <Box
      bg="card"
      p="lg"
      border="top"
      borderColor={tone ?? colors.border.strong}
      style={{ minWidth: 0 }}
    >
      <Stack gap="xs">
        <Text variant="label" color={colors.textSecondary}>
          {label}
        </Text>
        <Text variant="metric" color={colors.text}>
          {value}
        </Text>
      </Stack>
    </Box>
  );
}

function PropertyList({
  entries,
}: {
  entries: Array<{ label: string; value: string }>;
}) {
  return (
    <Stack gap="sm">
      {entries.map((entry) => (
        <Box
          key={entry.label}
          bg="card"
          p="md"
          border="subtle"
          style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(120px, 180px) 1fr',
            gap: spacing.md,
          }}
        >
          <Text variant="label" color={colors.textSecondary}>
            {entry.label}
          </Text>
          <Text variant="data">{entry.value}</Text>
        </Box>
      ))}
    </Stack>
  );
}

function ToggleField({
  label,
  helper,
  checked,
  onChange,
}: {
  label: string;
  helper?: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  const inputId = useId();
  const helperId = helper ? `${inputId}-help` : undefined;
  return (
    <div className="console-next-toggle">
      <input
        id={inputId}
        type="checkbox"
        checked={checked}
        aria-describedby={helperId}
        onChange={(event) => onChange(event.currentTarget.checked)}
      />
      <div>
        <label htmlFor={inputId}>
          <Text variant="label">{label}</Text>
        </label>
        {helper ? (
          <span id={helperId}>
            <Text variant="body" color={colors.textSecondary}>
              {helper}
            </Text>
          </span>
        ) : null}
      </div>
    </div>
  );
}

function KeyValueListEditor({
  title,
  description,
  rows,
  saving,
  nameLabelPrefix,
  valueLabelPrefix,
  addButtonLabel,
  emptyState,
  onChange,
}: {
  title: string;
  description: string;
  rows: KeyValueFormRow[];
  saving: boolean;
  nameLabelPrefix: string;
  valueLabelPrefix: string;
  addButtonLabel: string;
  emptyState: string;
  onChange: (rows: KeyValueFormRow[]) => void;
}) {
  return (
    <Stack gap="sm">
      <div>
        <Text variant="label">{title}</Text>
        <Text variant="body" color={colors.textSecondary}>
          {description}
        </Text>
      </div>
      {rows.length === 0 ? (
        <Text variant="body" color={colors.textSecondary}>
          {emptyState}
        </Text>
      ) : null}
      {rows.map((row, index) => (
        <div key={row.id} className="console-next-form-grid">
          <Input
            fill
            label={`${nameLabelPrefix} #${index + 1}`}
            value={row.key}
            onChange={(event) => {
              const value = event.currentTarget.value;
              onChange(rows.map((item, rowIndex) => (rowIndex === index ? { ...item, key: value } : item)));
            }}
          />
          <Input
            fill
            label={`${valueLabelPrefix} #${index + 1}`}
            value={row.value}
            onChange={(event) => {
              const value = event.currentTarget.value;
              onChange(
                rows.map((item, rowIndex) => (rowIndex === index ? { ...item, value } : item)),
              );
            }}
          />
          <div className="console-next-button-row">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={saving}
              onClick={() => onChange(rows.filter((_, rowIndex) => rowIndex !== index))}
            >
              Remove row
            </Button>
          </div>
        </div>
      ))}
      <div className="console-next-button-row">
        <Button
          type="button"
          variant="outlined"
          size="sm"
          disabled={saving}
          onClick={() => onChange([...rows, { id: nextFormRowId(), key: '', value: '' }])}
        >
          {addButtonLabel}
        </Button>
      </div>
    </Stack>
  );
}

function StringListEditor({
  title,
  description,
  rows,
  saving,
  labelPrefix,
  addButtonLabel,
  emptyState,
  onChange,
}: {
  title: string;
  description: string;
  rows: StringFormRow[];
  saving: boolean;
  labelPrefix: string;
  addButtonLabel: string;
  emptyState: string;
  onChange: (rows: StringFormRow[]) => void;
}) {
  return (
    <Stack gap="sm">
      <div>
        <Text variant="label">{title}</Text>
        <Text variant="body" color={colors.textSecondary}>
          {description}
        </Text>
      </div>
      {rows.length === 0 ? (
        <Text variant="body" color={colors.textSecondary}>
          {emptyState}
        </Text>
      ) : null}
      {rows.map((row, index) => (
        <div key={row.id} className="console-next-form-grid">
          <Input
            fill
            label={`${labelPrefix} #${index + 1}`}
            value={row.value}
            onChange={(event) => {
              const value = event.currentTarget.value;
              onChange(
                rows.map((item, rowIndex) => (rowIndex === index ? { ...item, value } : item)),
              );
            }}
          />
          <div className="console-next-button-row">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={saving}
              onClick={() => onChange(rows.filter((_, rowIndex) => rowIndex !== index))}
            >
              Remove row
            </Button>
          </div>
        </div>
      ))}
      <div className="console-next-button-row">
        <Button
          type="button"
          variant="outlined"
          size="sm"
          disabled={saving}
          onClick={() => onChange([...rows, { id: nextFormRowId(), value: '' }])}
        >
          {addButtonLabel}
        </Button>
      </div>
    </Stack>
  );
}

function SiteEditor({
  title,
  form,
  saving,
  submitButtonLabel,
  onChange,
  onSubmit,
  onCancel,
}: {
  title: string;
  form: SiteFormState;
  saving: boolean;
  submitButtonLabel: string;
  onChange: (updater: (form: SiteFormState) => SiteFormState) => void;
  onSubmit: () => void;
  onCancel: () => void;
}) {
  return (
    <Box bg="card" p="lg" border="top" borderColor={colors.skyBlue}>
      <form
        className="console-next-form"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit();
        }}
      >
        <Stack gap="md">
          <Text variant="heading">{title}</Text>
          <Input
            fill
            label="Hostname"
            value={form.hostname}
            onChange={(event) => {
              const value = event.currentTarget.value;
              onChange((current) => ({ ...current, hostname: value }));
            }}
            helper="Example: example.com"
          />

          <Stack gap="sm">
            <Text variant="label" color={colors.textSecondary}>
              Upstreams
            </Text>
            {form.upstreams.map((row, rowIndex) => (
              <div
                key={row.id}
                className="console-next-form-grid"
                data-testid={`upstream-row-${rowIndex}`}
              >
                <Input
                  fill
                  label={`Host #${rowIndex + 1}`}
                  value={row.host}
                  onChange={(event) => {
                    const value = event.currentTarget.value;
                    onChange((current) => ({
                      ...current,
                      upstreams: current.upstreams.map((item, idx) =>
                        idx === rowIndex ? updateUpstreamRow(item, 'host', value) : item,
                      ),
                    }));
                  }}
                  helper="Example: origin.internal"
                />
                <Input
                  fill
                  label={`Port #${rowIndex + 1}`}
                  type="number"
                  min={1}
                  max={65535}
                  step={1}
                  value={row.port}
                  onChange={(event) => {
                    const value = event.currentTarget.value;
                    onChange((current) => ({
                      ...current,
                      upstreams: current.upstreams.map((item, idx) =>
                        idx === rowIndex ? updateUpstreamRow(item, 'port', value) : item,
                      ),
                    }));
                  }}
                  helper="1-65535; leave blank to omit"
                />
                <div className="console-next-button-row">
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    disabled={saving || form.upstreams.length <= 1}
                    onClick={() =>
                      onChange((current) => ({
                        ...current,
                        upstreams: current.upstreams.filter((_, idx) => idx !== rowIndex),
                      }))
                    }
                  >
                    Remove upstream
                  </Button>
                </div>
              </div>
            ))}
            <div className="console-next-button-row">
              <Button
                type="button"
                variant="outlined"
                size="sm"
                disabled={saving}
                onClick={() =>
                  onChange((current) => ({
                    ...current,
                    upstreams: [
                      ...current.upstreams,
                      { id: nextUpstreamRowId(), baseUpstream: null, host: '', port: '' },
                    ],
                  }))
                }
              >
                Add upstream
              </Button>
            </div>
          </Stack>

          <Box bg="canvas" p="md" border="top" borderColor={colors.magenta}>
            <Stack gap="md">
              <Text variant="heading">WAF</Text>
              <ToggleField
                label="Site WAF enabled"
                helper="Override the global WAF enablement state for this site."
                checked={form.waf.enabled}
                onChange={(checked) =>
                  onChange((current) => ({
                    ...current,
                    waf: { ...current.waf, enabled: checked },
                  }))
                }
              />
              <Input
                fill
                label="Site WAF threshold"
                type="number"
                min={0}
                max={100}
                step={1}
                value={form.waf.threshold}
                onChange={(event) => {
                  const value = event.currentTarget.value;
                  onChange((current) => ({
                    ...current,
                    waf: { ...current.waf, threshold: value },
                  }));
                }}
                helper="Leave blank to inherit the global threshold."
              />
              <KeyValueListEditor
                title="Rule overrides"
                description="Override individual rule actions for this site."
                rows={form.waf.rule_overrides}
                saving={saving}
                nameLabelPrefix="Rule ID"
                valueLabelPrefix="Rule action"
                addButtonLabel="Add rule override"
                emptyState="No rule overrides configured."
                onChange={(rows) =>
                  onChange((current) => ({
                    ...current,
                    waf: { ...current.waf, rule_overrides: rows },
                  }))
                }
              />
            </Stack>
          </Box>

          <Box bg="canvas" p="md" border="top" borderColor={colors.blue}>
            <Stack gap="md">
              <Text variant="heading">Request headers</Text>
              <KeyValueListEditor
                title="Add headers"
                description="Append request headers without replacing existing values."
                rows={form.headers.request.add}
                saving={saving}
                nameLabelPrefix="Request add header name"
                valueLabelPrefix="Request add header value"
                addButtonLabel="Add request add header"
                emptyState="No request add headers configured."
                onChange={(rows) =>
                  onChange((current) => ({
                    ...current,
                    headers: {
                      ...current.headers,
                      request: { ...current.headers.request, add: rows },
                    },
                  }))
                }
              />
              <KeyValueListEditor
                title="Set headers"
                description="Replace request header values before proxying upstream."
                rows={form.headers.request.set}
                saving={saving}
                nameLabelPrefix="Request set header name"
                valueLabelPrefix="Request set header value"
                addButtonLabel="Add request set header"
                emptyState="No request set headers configured."
                onChange={(rows) =>
                  onChange((current) => ({
                    ...current,
                    headers: {
                      ...current.headers,
                      request: { ...current.headers.request, set: rows },
                    },
                  }))
                }
              />
              <StringListEditor
                title="Remove headers"
                description="Strip request headers before they reach the upstream."
                rows={form.headers.request.remove}
                saving={saving}
                labelPrefix="Request remove header"
                addButtonLabel="Add request remove header"
                emptyState="No request remove headers configured."
                onChange={(rows) =>
                  onChange((current) => ({
                    ...current,
                    headers: {
                      ...current.headers,
                      request: { ...current.headers.request, remove: rows },
                    },
                  }))
                }
              />
            </Stack>
          </Box>

          <Box bg="canvas" p="md" border="top" borderColor={colors.orange}>
            <Stack gap="md">
              <Text variant="heading">Response headers</Text>
              <KeyValueListEditor
                title="Add headers"
                description="Append response headers before replies leave the proxy."
                rows={form.headers.response.add}
                saving={saving}
                nameLabelPrefix="Response add header name"
                valueLabelPrefix="Response add header value"
                addButtonLabel="Add response add header"
                emptyState="No response add headers configured."
                onChange={(rows) =>
                  onChange((current) => ({
                    ...current,
                    headers: {
                      ...current.headers,
                      response: { ...current.headers.response, add: rows },
                    },
                  }))
                }
              />
              <KeyValueListEditor
                title="Set headers"
                description="Replace response header values before they return to clients."
                rows={form.headers.response.set}
                saving={saving}
                nameLabelPrefix="Response set header name"
                valueLabelPrefix="Response set header value"
                addButtonLabel="Add response set header"
                emptyState="No response set headers configured."
                onChange={(rows) =>
                  onChange((current) => ({
                    ...current,
                    headers: {
                      ...current.headers,
                      response: { ...current.headers.response, set: rows },
                    },
                  }))
                }
              />
              <StringListEditor
                title="Remove headers"
                description="Strip response headers before returning traffic to clients."
                rows={form.headers.response.remove}
                saving={saving}
                labelPrefix="Response remove header"
                addButtonLabel="Add response remove header"
                emptyState="No response remove headers configured."
                onChange={(rows) =>
                  onChange((current) => ({
                    ...current,
                    headers: {
                      ...current.headers,
                      response: { ...current.headers.response, remove: rows },
                    },
                  }))
                }
              />
            </Stack>
          </Box>

          <div className="console-next-button-row">
            <Button type="submit" disabled={saving}>
              {submitButtonLabel}
            </Button>
            <Button type="button" variant="outlined" disabled={saving} onClick={onCancel}>
              Cancel
            </Button>
          </div>
        </Stack>
      </form>
    </Box>
  );
}

export function App() {
  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [saveState, setSaveState] = useState<SaveState>({ kind: 'idle' });
  const [serverForm, setServerForm] = useState<ServerFormState>(() => buildServerForm());
  const [siteEditor, setSiteEditor] = useState<SiteEditorState>({ mode: 'idle' });
  const [siteSaveState, setSiteSaveState] = useState<SaveState>({ kind: 'idle' });
  const [rateLimitForm, setRateLimitForm] = useState<RateLimitFormState>(() =>
    buildRateLimitForm(),
  );
  const [rateLimitSaveState, setRateLimitSaveState] = useState<SaveState>({ kind: 'idle' });
  const [profilerForm, setProfilerForm] = useState<ProfilerFormState>(() => buildProfilerForm());
  const [profilerSaveState, setProfilerSaveState] = useState<SaveState>({ kind: 'idle' });
  const isAnySaveInFlight =
    saveState.kind === 'saving' ||
    siteSaveState.kind === 'saving' ||
    rateLimitSaveState.kind === 'saving' ||
    profilerSaveState.kind === 'saving';

  async function load(): Promise<LoadState> {
    setState({ kind: 'loading' });

    const results = await Promise.allSettled([
      requestJson<HealthResponse>('/health'),
      requestJson<StatusResponse>('/_sensor/status'),
      readApiWithMeta<ConfigFile>('/config'),
      requestJson<SensorConfigResponse>('/_sensor/config'),
    ]);

    const labels = ['Health', 'Status', 'Full config', 'Sensor config'] as const;
    const warnings = results.flatMap((result, index) => {
      if (result.status === 'fulfilled') return [];
      const message =
        result.reason instanceof Error ? result.reason.message : 'Request failed.';
      return [`${labels[index]} failed: ${message}`];
    });

    const health = results[0].status === 'fulfilled' ? results[0].value : undefined;
    const status = results[1].status === 'fulfilled' ? results[1].value : undefined;
    const fullConfigResult = results[2].status === 'fulfilled' ? results[2].value : undefined;
    const fullConfig = fullConfigResult?.data;
    const configEtag = fullConfigResult?.etag ?? null;
    const sensorConfig = results[3].status === 'fulfilled' ? results[3].value : undefined;

    if (fullConfig) {
      setServerForm(buildServerForm(fullConfig.server));
      setRateLimitForm(buildRateLimitForm(fullConfig.rate_limit));
      setProfilerForm(buildProfilerForm(fullConfig.profiler));
    }

    const nextState: LoadState = {
      kind: 'ready',
      health,
      status,
      fullConfig,
      configEtag,
      sensorConfig,
      loadedAt: new Date().toLocaleString(),
      warnings,
    };

    setState(nextState);
    return nextState;
  }

  function assertValidMutationResult(mutation: MutationResult): MutationResult {
    if (
      typeof mutation.applied !== 'boolean' ||
      typeof mutation.persisted !== 'boolean' ||
      typeof mutation.rebuild_required !== 'boolean'
    ) {
      throw new Error('Invalid config mutation response. Reload and retry.');
    }
    return {
      ...mutation,
      applied: mutation.applied,
      persisted: mutation.persisted,
      rebuild_required: mutation.rebuild_required,
      warnings: Array.isArray(mutation.warnings)
        ? mutation.warnings.filter((warning): warning is string => typeof warning === 'string')
        : [],
    };
  }

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    if (saveState.kind !== 'success' || saveState.sticky === true) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setSaveState({ kind: 'idle' });
    }, 8000);

    return () => window.clearTimeout(timeoutId);
  }, [saveState]);

  useEffect(() => {
    if (siteSaveState.kind !== 'success' || siteSaveState.sticky === true) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setSiteSaveState({ kind: 'idle' });
    }, 8000);

    return () => window.clearTimeout(timeoutId);
  }, [siteSaveState]);

  useEffect(() => {
    if (rateLimitSaveState.kind !== 'success' || rateLimitSaveState.sticky === true) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setRateLimitSaveState({ kind: 'idle' });
    }, 8000);

    return () => window.clearTimeout(timeoutId);
  }, [rateLimitSaveState]);

  useEffect(() => {
    if (profilerSaveState.kind !== 'success' || profilerSaveState.sticky === true) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setProfilerSaveState({ kind: 'idle' });
    }, 8000);

    return () => window.clearTimeout(timeoutId);
  }, [profilerSaveState]);

  const overview = useMemo(() => {
    if (state.kind !== 'ready') return null;

    const siteCount =
      state.fullConfig?.sites.length ?? state.sensorConfig?.data?.sites?.length ?? 0;
    const blocked = state.status?.blocked_requests ?? 0;
    const mode = state.status?.mode ?? state.health?.status ?? 'unknown';
    const workers = state.fullConfig?.server?.workers ?? 0;

    return { siteCount, blocked, mode, workers };
  }, [state]);

  function updateServerForm<K extends keyof ServerFormState>(
    key: K,
    value: ServerFormState[K],
  ) {
    setServerForm((current) => ({ ...current, [key]: value }));
  }

  async function saveServerConfig() {
    if (saveState.kind === 'saving' || isAnySaveInFlight) {
      return;
    }

    if (state.kind !== 'ready' || !state.fullConfig) {
      setSaveState({
        kind: 'error',
        message:
          'Full config is unavailable. This editor needs both config:write and admin:write scope.',
      });
      return;
    }

    setSaveState({ kind: 'saving' });

    try {
      if (!state.configEtag) {
        throw new Error('Config version is unavailable. Refresh the page and try again.');
      }

      if (serverForm.replace_admin_api_key && serverForm.admin_api_key.trim() === '') {
        throw new Error('Admin API key is required when replacement is enabled.');
      }

      const trapPaths = serverForm.trap_paths
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);

      if (serverForm.trap_present && trapPaths.length === 0) {
        throw new Error('Trap paths cannot be empty when trap configuration is enabled.');
      }

      const { admin_api_key: _currentAdminApiKey, ...serverWithoutAdminApiKey } =
        state.fullConfig.server;
      const nextServer: GlobalConfig = {
        ...serverWithoutAdminApiKey,
        http_addr: serverForm.http_addr.trim(),
        https_addr: serverForm.https_addr.trim(),
        workers: parseIntegerField(serverForm.workers, 'Workers', { min: 0 }),
        shutdown_timeout_secs: parseIntegerField(
          serverForm.shutdown_timeout_secs,
          'Shutdown timeout',
          { min: 1 },
        ),
        waf_threshold: parseIntegerField(serverForm.waf_threshold, 'WAF threshold', {
          min: 0,
          max: 100,
        }),
        waf_enabled: serverForm.waf_enabled,
        log_level: serverForm.log_level,
        waf_regex_timeout_ms: parseIntegerField(
          serverForm.waf_regex_timeout_ms,
          'WAF regex timeout',
          { min: 1, max: 500 },
        ),
        trap_config: serverForm.trap_present
          ? {
              enabled: serverForm.trap_enabled,
              paths: trapPaths,
              apply_max_risk: serverForm.trap_apply_max_risk,
              extended_tarpit_ms: serverForm.trap_extended_tarpit_ms.trim()
                ? parseIntegerField(
                    serverForm.trap_extended_tarpit_ms,
                    'Extended tarpit delay',
                    { min: 0 },
                  )
                : null,
              alert_telemetry: serverForm.trap_alert_telemetry,
            }
          : null,
      };

      if (serverForm.clear_admin_api_key) {
        nextServer.admin_api_key = null;
      } else if (serverForm.replace_admin_api_key) {
        nextServer.admin_api_key = serverForm.admin_api_key.trim();
      } else {
        // The admin server preserves the stored key when this field is omitted from POST /config.
        // That contract is covered by test_config_post_preserves_existing_admin_key_when_omitted.
      }

      const nextConfig: ConfigFile = {
        ...state.fullConfig,
        server: {
          ...nextServer,
        },
      };

      const mutation = assertValidMutationResult(
        await writeApi<MutationResult>('/config', 'POST', nextConfig, {
        'If-Match': state.configEtag,
        ...(serverForm.clear_admin_api_key ? { 'X-Clear-Admin-Api-Key': 'true' } : {}),
        }),
      );
      const refreshedState = await load();
      const refreshWarning = getRefreshWarning(refreshedState);

      const warningSuffix =
        mutation.warnings && mutation.warnings.length > 0
          ? ` Warnings: ${mutation.warnings.join(' ')}`
          : '';

      setSaveState({
        kind: 'success',
        message:
          `Server config saved. Applied=${String(mutation.applied)} persisted=${String(
            mutation.persisted,
          )} rebuild_required=${String(mutation.rebuild_required)}.` + warningSuffix,
        warning: refreshWarning || undefined,
        sticky:
          mutation.rebuild_required === true ||
          Boolean(mutation.warnings?.length) ||
          refreshWarning.length > 0,
      });
    } catch (error) {
      setSaveState({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Failed to save server config.',
      });
    }
  }

  async function saveSiteMutation(
    action: 'add' | 'edit' | 'delete',
    options: { index?: number; form?: SiteFormState; baseSite?: SiteConfig },
  ) {
    if (siteSaveState.kind === 'saving' || isAnySaveInFlight) {
      return;
    }

    if (state.kind !== 'ready' || !state.fullConfig) {
      setSiteSaveState({
        kind: 'error',
        message:
          'Full config is unavailable. This editor needs both config:write and admin:write scope.',
      });
      return;
    }

    if (!state.configEtag) {
      setSiteSaveState({
        kind: 'error',
        message: 'Config version is unavailable. Refresh the page and try again.',
      });
      return;
    }

    setSiteSaveState({ kind: 'saving' });

    try {
      const existingSites = state.fullConfig.sites ?? [];
      let nextSites: SiteConfig[];
      let actionLabel: string;

      if (action === 'delete') {
        if (options.index === undefined || !existingSites[options.index]) {
          throw new Error('Cannot delete: site was already removed. Refresh and try again.');
        }
        nextSites = existingSites.filter((_, idx) => idx !== options.index);
        actionLabel = `Site removed (${existingSites[options.index].hostname ?? 'unnamed'})`;
      } else if (action === 'add') {
        if (!options.form) {
          throw new Error('Cannot add: form state is missing.');
        }
        const nextSite = siteFromForm(options.form);
        if (
          existingSites.some(
            (s) => normalizeHostname(s.hostname) === normalizeHostname(nextSite.hostname),
          )
        ) {
          throw new Error(`A site with hostname "${nextSite.hostname}" already exists.`);
        }
        nextSites = [...existingSites, nextSite];
        actionLabel = `Site added (${nextSite.hostname})`;
      } else {
        if (options.index === undefined || !options.form || !options.baseSite) {
          throw new Error('Cannot update: site no longer exists. Refresh and try again.');
        }
        const nextSite = siteFromForm(options.form, options.baseSite);
        const duplicate = existingSites.some(
          (s, idx) =>
            idx !== options.index &&
            normalizeHostname(s.hostname) === normalizeHostname(nextSite.hostname),
        );
        if (duplicate) {
          throw new Error(`Another site already uses hostname "${nextSite.hostname}".`);
        }
        nextSites = existingSites.map((site, idx) =>
          idx === options.index ? nextSite : site,
        );
        actionLabel = `Site updated (${nextSite.hostname})`;
      }

      const nextConfig: ConfigFile = {
        ...state.fullConfig,
        sites: nextSites,
      };

      const mutation = assertValidMutationResult(
        await writeApi<MutationResult>('/config', 'POST', nextConfig, {
        'If-Match': state.configEtag,
        }),
      );
      const refreshedState = await load();
      setSiteEditor({ mode: 'idle' });
      const refreshWarning = getRefreshWarning(refreshedState);

      const warningSuffix =
        mutation.warnings && mutation.warnings.length > 0
          ? ` Warnings: ${mutation.warnings.join(' ')}`
          : '';

      setSiteSaveState({
        kind: 'success',
        message:
          `${actionLabel}. Applied=${String(mutation.applied)} persisted=${String(
            mutation.persisted,
          )} rebuild_required=${String(mutation.rebuild_required)}.` + warningSuffix,
        warning: refreshWarning || undefined,
        sticky:
          mutation.rebuild_required === true ||
          Boolean(mutation.warnings?.length) ||
          refreshWarning.length > 0,
      });
    } catch (error) {
      setSiteSaveState({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Failed to save site changes.',
      });
    }
  }

  async function saveRateLimitConfig() {
    if (rateLimitSaveState.kind === 'saving' || isAnySaveInFlight) {
      return;
    }

    if (state.kind !== 'ready' || !state.fullConfig) {
      setRateLimitSaveState({
        kind: 'error',
        message:
          'Full config is unavailable. This editor needs both config:write and admin:write scope.',
      });
      return;
    }

    if (!state.configEtag) {
      setRateLimitSaveState({
        kind: 'error',
        message: 'Config version is unavailable. Refresh the page and try again.',
      });
      return;
    }

    setRateLimitSaveState({ kind: 'saving' });

    try {
      const rps = parseIntegerField(rateLimitForm.rps, 'Requests per second', { min: 1 });
      const burstRaw = rateLimitForm.burst.trim();
      const burst = burstRaw === ''
        ? undefined
        : parseIntegerField(rateLimitForm.burst, 'Burst capacity', { min: 0 });

      const nextRateLimit: RateLimitConfig = {
        ...state.fullConfig.rate_limit,
        enabled: rateLimitForm.enabled,
        rps,
        ...(burst === undefined ? {} : { burst }),
      };

      const nextConfig: ConfigFile = {
        ...state.fullConfig,
        rate_limit: nextRateLimit,
      };

      const mutation = assertValidMutationResult(
        await writeApi<MutationResult>('/config', 'POST', nextConfig, {
        'If-Match': state.configEtag,
        }),
      );
      const refreshedState = await load();
      const refreshWarning = getRefreshWarning(refreshedState);

      const warningSuffix =
        mutation.warnings && mutation.warnings.length > 0
          ? ` Warnings: ${mutation.warnings.join(' ')}`
          : '';

      setRateLimitSaveState({
        kind: 'success',
        message:
          `Rate-limit config saved. Applied=${String(mutation.applied)} persisted=${String(
            mutation.persisted,
          )} rebuild_required=${String(mutation.rebuild_required)}.` + warningSuffix,
        warning: refreshWarning || undefined,
        sticky:
          mutation.rebuild_required === true ||
          Boolean(mutation.warnings?.length) ||
          refreshWarning.length > 0,
      });
    } catch (error) {
      setRateLimitSaveState({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Failed to save rate-limit config.',
      });
    }
  }

  async function saveProfilerConfig() {
    if (profilerSaveState.kind === 'saving' || isAnySaveInFlight) {
      return;
    }

    if (state.kind !== 'ready' || !state.fullConfig) {
      setProfilerSaveState({
        kind: 'error',
        message:
          'Full config is unavailable. This editor needs both config:write and admin:write scope.',
      });
      return;
    }

    if (!state.configEtag) {
      setProfilerSaveState({
        kind: 'error',
        message: 'Config version is unavailable. Refresh the page and try again.',
      });
      return;
    }

    setProfilerSaveState({ kind: 'saving' });

    try {
      const nextProfiler: ProfilerConfig = {
        ...state.fullConfig.profiler,
        enabled: profilerForm.enabled,
        max_profiles: parseIntegerField(profilerForm.max_profiles, 'Max profiles', { min: 1 }),
        max_schemas: parseIntegerField(profilerForm.max_schemas, 'Max schemas', { min: 1 }),
        min_samples_for_validation: parseIntegerField(
          profilerForm.min_samples_for_validation,
          'Min samples for validation',
          { min: 1 },
        ),
        payload_z_threshold: parseFloatField(
          profilerForm.payload_z_threshold,
          'Payload z-threshold',
          { min: 0, max: 20 },
        ),
        param_z_threshold: parseFloatField(
          profilerForm.param_z_threshold,
          'Parameter z-threshold',
          { min: 0, max: 20 },
        ),
        response_z_threshold: parseFloatField(
          profilerForm.response_z_threshold,
          'Response z-threshold',
          { min: 0, max: 20 },
        ),
        min_stddev: parseFloatField(profilerForm.min_stddev, 'Minimum stddev', {
          min: 0,
          max: 100,
        }),
        type_ratio_threshold: parseFloatField(
          profilerForm.type_ratio_threshold,
          'Type-ratio threshold',
          { min: 0, max: 1 },
        ),
        max_type_counts: parseIntegerField(
          profilerForm.max_type_counts,
          'Max type counts',
          { min: 1 },
        ),
        redact_pii: profilerForm.redact_pii,
        freeze_after_samples: parseIntegerField(
          profilerForm.freeze_after_samples,
          'Freeze after samples',
          { min: 0 },
        ),
      };

      const nextConfig: ConfigFile = {
        ...state.fullConfig,
        profiler: nextProfiler,
      };

      const mutation = assertValidMutationResult(
        await writeApi<MutationResult>('/config', 'POST', nextConfig, {
        'If-Match': state.configEtag,
        }),
      );
      const refreshedState = await load();
      const refreshWarning = getRefreshWarning(refreshedState);

      const warningSuffix =
        mutation.warnings && mutation.warnings.length > 0
          ? ` Warnings: ${mutation.warnings.join(' ')}`
          : '';

      setProfilerSaveState({
        kind: 'success',
        message:
          `Profiler config saved. Applied=${String(mutation.applied)} persisted=${String(
            mutation.persisted,
          )} rebuild_required=${String(mutation.rebuild_required)}.` + warningSuffix,
        warning: refreshWarning || undefined,
        sticky:
          mutation.rebuild_required === true ||
          Boolean(mutation.warnings?.length) ||
          refreshWarning.length > 0,
      });
    } catch (error) {
      setProfilerSaveState({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Failed to save profiler config.',
      });
    }
  }

  function updateRateLimitForm<K extends keyof RateLimitFormState>(
    key: K,
    value: RateLimitFormState[K],
  ) {
    setRateLimitForm((current) => ({ ...current, [key]: value }));
  }

  function updateProfilerForm<K extends keyof ProfilerFormState>(
    key: K,
    value: ProfilerFormState[K],
  ) {
    setProfilerForm((current) => ({ ...current, [key]: value }));
  }

  function updateSiteFormField(updater: (form: SiteFormState) => SiteFormState) {
    setSiteEditor((current) => {
      if (current.mode === 'add') {
        return { ...current, form: updater(current.form) };
      }
      if (current.mode === 'edit') {
        return { ...current, form: updater(current.form) };
      }
      return current;
    });
  }

  const fullConfigSites = state.kind === 'ready' ? state.fullConfig?.sites ?? [] : [];
  const sensorFallbackSites =
    state.kind === 'ready' && !state.fullConfig ? state.sensorConfig?.data?.sites ?? [] : [];

  return (
    <main className="console-next-shell">
      <header className="console-next-header">
        <div className="console-next-brand">
          <img src="/console-next/assets/sidebar-lockup.svg" alt="Synapse Fleet" />
          <div>
            <Text variant="subhead" color={colors.textSecondary}>
              Console Next
            </Text>
            <Text as="h1" variant="heading">
              Synapse Operator UI
            </Text>
          </div>
        </div>
        <div className="console-next-actions">
          <a className="console-next-link" href="/console">
            Open legacy console
          </a>
          <Button
            variant="outlined"
            onClick={() => {
              setSaveState({ kind: 'idle' });
              void load();
            }}
          >
            Refresh
          </Button>
        </div>
      </header>

      <Alert status="info" title="Operator surface is live">
        Server, site CRUD, and per-site WAF/header overrides now run through the real
        full-config API. TLS, shadow-mirror, and access-control editors are the next gaps.
      </Alert>

      <div className="console-next-tabs">
        <Tabs
          tabs={tabs.map((tab) => ({ key: tab.key, label: tab.label }))}
          active={activeTab}
          onChange={(key) => setActiveTab(key as TabKey)}
          ariaLabel="Console Next sections"
          idPrefix="tab-"
          panelIdPrefix="panel-"
        />
      </div>

      {state.kind === 'loading' ? (
        <div className="console-next-center">
          <Spinner size={28} />
          <Text variant="body" muted>
            Loading current sensor state…
          </Text>
        </div>
      ) : null}

      {state.kind === 'ready' && state.warnings.length > 0 ? (
        <Alert status="warning" title="Partial data available">
          {state.warnings.join(' ')}
        </Alert>
      ) : null}

      {state.kind === 'ready' && activeTab === 'overview' ? (
        <section role="tabpanel" id="panel-overview" aria-labelledby="tab-overview">
          <Stack gap="lg">
            <div className="console-next-grid">
              <MetricTile
                label="Mode"
                value={overview?.mode ?? 'unknown'}
                tone={colors.blue}
              />
              <MetricTile
                label="Sites"
                value={String(overview?.siteCount ?? 0)}
                tone={colors.green}
              />
              <MetricTile
                label="Workers"
                value={String(overview?.workers ?? 0)}
                tone={colors.magenta}
              />
              <MetricTile
                label="Blocked Requests"
                value={String(overview?.blocked ?? 0)}
                tone={colors.orange}
              />
            </div>
            <PropertyList
              entries={[
                {
                  label: 'Health',
                  value: String(state.health?.status ?? formatBoolean(state.health?.healthy)),
                },
                {
                  label: 'HTTP Bind',
                  value: state.fullConfig?.server?.http_addr ?? 'Unavailable',
                },
                {
                  label: 'HTTPS Bind',
                  value: state.fullConfig?.server?.https_addr ?? 'Unavailable',
                },
                {
                  label: 'Last Loaded',
                  value: state.loadedAt,
                },
              ]}
            />
          </Stack>
        </section>
      ) : null}

      {state.kind === 'ready' && activeTab === 'server' ? (
        <section role="tabpanel" id="panel-server" aria-labelledby="tab-server">
          <Stack gap="lg">
            <Box bg="card" p="lg" border="top" borderColor={colors.skyBlue}>
              <Stack gap="sm">
                <Text variant="heading">Server configuration</Text>
                <Text variant="body" color={colors.textSecondary}>
                  This editor reads from `GET /config` and writes via `POST /config`, preserving
                  sites, profiler, and rate-limit blocks while only updating `server.*`.
                </Text>
              </Stack>
            </Box>

            {saveState.kind === 'success' ? (
              <>
                <Alert status="success" title="Saved">
                  {saveState.message}
                </Alert>
                {saveState.warning ? (
                  <Alert status="warning" title="Reload required">
                    {saveState.warning}
                  </Alert>
                ) : null}
              </>
            ) : null}

            {saveState.kind === 'error' ? (
              <Alert status="error" title="Save failed">
                {saveState.message}
              </Alert>
            ) : null}

            {!state.fullConfig ? (
              <Alert status="warning" title="Full config unavailable">
                This tab needs `config:write` to load `GET /config` and `admin:write` to save
                `POST /config`. The current session only has read-only dashboard data.
              </Alert>
            ) : (
              <form
                className="console-next-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void saveServerConfig();
                }}
              >
                <Stack gap="lg">
                  <div className="console-next-form-grid">
                    <Input
                      fill
                      label="HTTP bind"
                      value={serverForm.http_addr}
                      onChange={(event) => updateServerForm('http_addr', event.currentTarget.value)}
                      helper="Example: 0.0.0.0:80"
                    />
                    <Input
                      fill
                      label="HTTPS bind"
                      value={serverForm.https_addr}
                      onChange={(event) => updateServerForm('https_addr', event.currentTarget.value)}
                      helper="Example: 0.0.0.0:443"
                    />
                    <Input
                      fill
                      label="Workers"
                      type="number"
                      min={0}
                      step={1}
                      value={serverForm.workers}
                      onChange={(event) => updateServerForm('workers', event.currentTarget.value)}
                      helper="0 means auto-detect"
                    />
                    <Input
                      fill
                      label="Shutdown timeout (seconds)"
                      type="number"
                      min={1}
                      step={1}
                      value={serverForm.shutdown_timeout_secs}
                      onChange={(event) =>
                        updateServerForm('shutdown_timeout_secs', event.currentTarget.value)
                      }
                    />
                    <Input
                      fill
                      label="WAF threshold"
                      type="number"
                      min={0}
                      max={100}
                      step={1}
                      value={serverForm.waf_threshold}
                      onChange={(event) =>
                        updateServerForm('waf_threshold', event.currentTarget.value)
                      }
                      helper="Backend validates the final range"
                    />
                    <Input
                      fill
                      label="WAF regex timeout (ms)"
                      type="number"
                      min={1}
                      max={500}
                      step={1}
                      value={serverForm.waf_regex_timeout_ms}
                      onChange={(event) =>
                        updateServerForm('waf_regex_timeout_ms', event.currentTarget.value)
                      }
                    />
                    <Select
                      fill
                      label="Log level"
                      options={logLevelOptions}
                      value={serverForm.log_level}
                      onChange={(event) => updateServerForm('log_level', event.currentTarget.value)}
                    />
                    <Input
                      fill
                      label="Admin API key"
                      type="password"
                      value={serverForm.admin_api_key}
                      disabled={!serverForm.replace_admin_api_key || serverForm.clear_admin_api_key}
                      onChange={(event) =>
                        updateServerForm('admin_api_key', event.currentTarget.value)
                      }
                      helper="The current key is never returned to the browser. Enable replacement to set a new one."
                    />
                  </div>

                  <div className="console-next-toggle-grid">
                    <ToggleField
                      label="WAF enabled"
                      helper="Master enable for global WAF enforcement."
                      checked={serverForm.waf_enabled}
                      onChange={(checked) => updateServerForm('waf_enabled', checked)}
                    />
                    <ToggleField
                      label="Trap configuration present"
                      helper="Remove the trap block entirely when unchecked."
                      checked={serverForm.trap_present}
                      onChange={(checked) => {
                        updateServerForm('trap_present', checked);
                        if (checked && serverForm.trap_paths.trim() === '') {
                          updateServerForm('trap_paths', defaultTrapPaths.join('\n'));
                        }
                      }}
                    />
                    <ToggleField
                      label="Replace admin API key"
                      helper="Only when checked will a newly typed key be submitted."
                      checked={serverForm.replace_admin_api_key}
                      onChange={(checked) => {
                        updateServerForm('replace_admin_api_key', checked);
                        if (!checked) {
                          updateServerForm('admin_api_key', '');
                        }
                      }}
                    />
                    <ToggleField
                      label="Clear stored admin API key"
                      helper="Use this only if you want startup-generated rotation instead of preserving the existing key."
                      checked={serverForm.clear_admin_api_key}
                      onChange={(checked) => {
                        updateServerForm('clear_admin_api_key', checked);
                        if (checked) {
                          updateServerForm('replace_admin_api_key', false);
                          updateServerForm('admin_api_key', '');
                        }
                      }}
                    />
                  </div>

                  {serverForm.trap_present ? (
                    <Box bg="card" p="lg" border="top" borderColor={colors.magenta}>
                      <Stack gap="md">
                        <Text variant="heading">Trap configuration</Text>
                        <div className="console-next-toggle-grid">
                          <ToggleField
                            label="Trap matching enabled"
                            checked={serverForm.trap_enabled}
                            onChange={(checked) => updateServerForm('trap_enabled', checked)}
                          />
                          <ToggleField
                            label="Apply max risk"
                            checked={serverForm.trap_apply_max_risk}
                            onChange={(checked) =>
                              updateServerForm('trap_apply_max_risk', checked)
                            }
                          />
                          <ToggleField
                            label="Alert telemetry"
                            checked={serverForm.trap_alert_telemetry}
                            onChange={(checked) =>
                              updateServerForm('trap_alert_telemetry', checked)
                            }
                          />
                        </div>
                        <div className="console-next-form-grid">
                          <Input
                            fill
                            label="Extended tarpit delay (ms)"
                            type="number"
                            value={serverForm.trap_extended_tarpit_ms}
                            onChange={(event) =>
                              updateServerForm(
                                'trap_extended_tarpit_ms',
                                event.currentTarget.value,
                              )
                            }
                            helper="Leave blank to omit the extra delay."
                          />
                          <div />
                        </div>
                        <Input
                          fill
                          multiline
                          rows={8}
                          label="Trap paths"
                          value={serverForm.trap_paths}
                          onChange={(event) => updateServerForm('trap_paths', event.currentTarget.value)}
                          helper="One glob path per line, for example /.git/* or /admin/backup*."
                        />
                      </Stack>
                    </Box>
                  ) : null}

                  <div className="console-next-button-row">
                    <Button type="submit" disabled={isAnySaveInFlight}>
                      {getSaveButtonLabel(
                        saveState,
                        isAnySaveInFlight,
                        'Save server config',
                      )}
                    </Button>
                    <Button
                      type="button"
                      variant="outlined"
                      onClick={() => {
                        setSaveState({ kind: 'idle' });
                        setServerForm(buildServerForm(state.fullConfig?.server));
                      }}
                      disabled={isAnySaveInFlight}
                    >
                      Reset form
                    </Button>
                  </div>
                </Stack>
              </form>
            )}
          </Stack>
        </section>
      ) : null}

      {state.kind === 'ready' && activeTab === 'sites' ? (
        <section role="tabpanel" id="panel-sites" aria-labelledby="tab-sites">
          <Stack gap="lg">
            {siteSaveState.kind === 'success' ? (
              <>
                <Alert status="success" title="Saved">
                  {siteSaveState.message}
                </Alert>
                {siteSaveState.warning ? (
                  <Alert status="warning" title="Reload required">
                    {siteSaveState.warning}
                  </Alert>
                ) : null}
              </>
            ) : null}

            {siteSaveState.kind === 'error' ? (
              <Alert status="error" title="Save failed">
                {siteSaveState.message}
              </Alert>
            ) : null}

            {!state.fullConfig ? (
              <Alert status="warning" title="Full config unavailable">
                Editing sites needs `config:write` on `GET /config` and `admin:write` on `POST
                /config`. The current session only has read-only dashboard data.
              </Alert>
            ) : null}

            {state.fullConfig ? (
              <div className="console-next-button-row">
                <Button
                  variant="primary"
                  disabled={siteEditor.mode !== 'idle' || isAnySaveInFlight}
                  onClick={() => {
                    setSiteSaveState({ kind: 'idle' });
                    setSiteEditor({ mode: 'add', form: buildSiteForm() });
                  }}
                >
                  Add site
                </Button>
              </div>
            ) : null}

            {state.fullConfig && siteEditor.mode === 'add' ? (
              <SiteEditor
                title="New site"
                form={siteEditor.form}
                saving={isAnySaveInFlight}
                submitButtonLabel={getSaveButtonLabel(
                  siteSaveState,
                  isAnySaveInFlight,
                  'Create site',
                )}
                onChange={updateSiteFormField}
                onCancel={() => {
                  setSiteEditor({ mode: 'idle' });
                  setSiteSaveState({ kind: 'idle' });
                }}
                onSubmit={() =>
                  void saveSiteMutation('add', { form: siteEditor.form })
                }
              />
            ) : null}

            {fullConfigSites.length > 0 ? (
              <Stack gap="md">
                {fullConfigSites.map((site, index) => {
                  const cardKey = `${site.hostname ?? 'unnamed'}-${index}`;
                  const isEditing =
                    siteEditor.mode === 'edit' && siteEditor.index === index;
                  const isConfirmingDelete =
                    siteEditor.mode === 'delete-confirm' && siteEditor.index === index;

                  if (isEditing) {
                    return (
                      <SiteEditor
                        key={cardKey}
                        title={`Edit ${site.hostname ?? 'site'}`}
                        form={siteEditor.form}
                        saving={isAnySaveInFlight}
                        submitButtonLabel={getSaveButtonLabel(
                          siteSaveState,
                          isAnySaveInFlight,
                          'Save site',
                        )}
                        onChange={updateSiteFormField}
                        onCancel={() => {
                          setSiteEditor({ mode: 'idle' });
                          setSiteSaveState({ kind: 'idle' });
                        }}
                        onSubmit={() =>
                          void saveSiteMutation('edit', {
                            index,
                            form: siteEditor.form,
                            baseSite: siteEditor.baseSite,
                          })
                        }
                      />
                    );
                  }

                  return (
                    <Box
                      key={cardKey}
                      bg="card"
                      p="lg"
                      border="subtle"
                      style={{ minWidth: 0 }}
                    >
                      <Stack gap="sm">
                        <Text variant="heading">{site.hostname ?? 'Unnamed site'}</Text>
                        <Text variant="body" color={colors.textSecondary}>
                          Upstreams: {formatUpstreams(site.upstreams)}
                        </Text>
                        <Text variant="body" color={colors.textSecondary}>
                          WAF: {formatBoolean(site.waf?.enabled)}
                        </Text>
                        <Text variant="body" color={colors.textSecondary}>
                          Headers: {site.headers ? Object.keys(site.headers).length : 0}
                        </Text>
                        <Text variant="body" color={colors.textSecondary}>
                          Rule overrides:{' '}
                          {site.waf?.rule_overrides
                            ? Object.keys(site.waf.rule_overrides).length
                            : 0}
                        </Text>

                        {isConfirmingDelete ? (
                          <Stack gap="sm">
                            <Text variant="body" color={colors.magenta}>
                              Delete {site.hostname ?? 'this site'}? This cannot be undone.
                            </Text>
                            <div className="console-next-button-row">
                              <Button
                                variant="magenta"
                                size="sm"
                                disabled={isAnySaveInFlight}
                                onClick={() =>
                                  void saveSiteMutation('delete', { index })
                                }
                              >
                                Confirm delete
                              </Button>
                              <Button
                                variant="outlined"
                                size="sm"
                                disabled={isAnySaveInFlight}
                                onClick={() => setSiteEditor({ mode: 'idle' })}
                              >
                                Cancel
                              </Button>
                            </div>
                          </Stack>
                        ) : (
                          <div className="console-next-button-row">
                            <Button
                              variant="outlined"
                              size="sm"
                              disabled={
                                siteEditor.mode !== 'idle' || isAnySaveInFlight
                              }
                              onClick={() => {
                                setSiteSaveState({ kind: 'idle' });
                                setSiteEditor({
                                  mode: 'edit',
                                  index,
                                  form: buildSiteForm(site),
                                  baseSite: structuredClone(site),
                                });
                              }}
                            >
                              Edit
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={
                                siteEditor.mode !== 'idle' || isAnySaveInFlight
                              }
                              onClick={() => {
                                setSiteSaveState({ kind: 'idle' });
                                setSiteEditor({ mode: 'delete-confirm', index });
                              }}
                            >
                              Delete
                            </Button>
                          </div>
                        )}
                      </Stack>
                    </Box>
                  );
                })}
              </Stack>
            ) : sensorFallbackSites.length > 0 ? (
              <Stack gap="md">
                {sensorFallbackSites.map((site, index) => (
                  <Box
                    key={String(`${site.hostname ?? 'unnamed'}-${index}`)}
                    bg="card"
                    p="lg"
                    border="subtle"
                    style={{ minWidth: 0 }}
                  >
                    <Stack gap="sm">
                      <Text variant="heading">{site.hostname ?? 'Unnamed site'}</Text>
                      <Text variant="body" color={colors.textSecondary}>
                        Upstreams:{' '}
                        {site.upstreams && site.upstreams.length > 0
                          ? site.upstreams.join(', ')
                          : 'Not configured'}
                      </Text>
                      <Text variant="body" color={colors.textSecondary}>
                        WAF: {formatBoolean(site.waf_enabled)}
                      </Text>
                      <Text variant="body" color={colors.textSecondary}>
                        TLS: {formatBoolean(site.tls_enabled)}
                      </Text>
                    </Stack>
                  </Box>
                ))}
              </Stack>
            ) : state.fullConfig ? (
              siteEditor.mode === 'add' ? null : (
                <EmptyState
                  title="No sites configured"
                  description="Use Add site above to register the first virtual host."
                />
              )
            ) : (
              <EmptyState
                title="No sites configured"
                description="This session cannot read the full config, so sites cannot be rendered yet."
              />
            )}
          </Stack>
        </section>
      ) : null}

      {state.kind === 'ready' && activeTab === 'rate-limit' ? (
        <section role="tabpanel" id="panel-rate-limit" aria-labelledby="tab-rate-limit">
          <Stack gap="lg">
            <Box bg="card" p="lg" border="top" borderColor={colors.skyBlue}>
              <Stack gap="sm">
                <Text variant="heading">Global rate-limit configuration</Text>
                <Text variant="body" color={colors.textSecondary}>
                  Applies across every virtual host. Per-site overrides live inside each site's
                  config and are not edited here.
                </Text>
              </Stack>
            </Box>

            {rateLimitSaveState.kind === 'success' ? (
              <>
                <Alert status="success" title="Saved">
                  {rateLimitSaveState.message}
                </Alert>
                {rateLimitSaveState.warning ? (
                  <Alert status="warning" title="Reload required">
                    {rateLimitSaveState.warning}
                  </Alert>
                ) : null}
              </>
            ) : null}

            {rateLimitSaveState.kind === 'error' ? (
              <Alert status="error" title="Save failed">
                {rateLimitSaveState.message}
              </Alert>
            ) : null}

            {!state.fullConfig ? (
              <Alert status="warning" title="Full config unavailable">
                This tab needs `config:write` on `GET /config` and `admin:write` on `POST /config`.
              </Alert>
            ) : (
              <form
                className="console-next-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void saveRateLimitConfig();
                }}
              >
                <Stack gap="lg">
                  <div className="console-next-form-grid">
                    <Input
                      fill
                      label="Requests per second"
                      type="number"
                      min={0}
                      step={1}
                      value={rateLimitForm.rps}
                      onChange={(event) =>
                        updateRateLimitForm('rps', event.currentTarget.value)
                      }
                      helper="Sustained rate ceiling; backend validates non-negative integer."
                    />
                    <Input
                      fill
                      label="Burst capacity"
                      type="number"
                      min={0}
                      step={1}
                      value={rateLimitForm.burst}
                      onChange={(event) =>
                        updateRateLimitForm('burst', event.currentTarget.value)
                      }
                      helper="Leave blank for backend default (rps × 2)."
                    />
                  </div>

                  <div className="console-next-toggle-grid">
                    <ToggleField
                      label="Rate limiting enabled"
                      helper="Global enable for the configured rps / burst values."
                      checked={rateLimitForm.enabled}
                      onChange={(checked) => updateRateLimitForm('enabled', checked)}
                    />
                  </div>

                  <div className="console-next-button-row">
                    <Button type="submit" disabled={isAnySaveInFlight}>
                      {getSaveButtonLabel(
                        rateLimitSaveState,
                        isAnySaveInFlight,
                        'Save rate-limit config',
                      )}
                    </Button>
                    <Button
                      type="button"
                      variant="outlined"
                      onClick={() => {
                        setRateLimitSaveState({ kind: 'idle' });
                        setRateLimitForm(buildRateLimitForm(state.fullConfig?.rate_limit));
                      }}
                      disabled={isAnySaveInFlight}
                    >
                      Reset form
                    </Button>
                  </div>
                </Stack>
              </form>
            )}
          </Stack>
        </section>
      ) : null}

      {state.kind === 'ready' && activeTab === 'profiler' ? (
        <section role="tabpanel" id="panel-profiler" aria-labelledby="tab-profiler">
          <Stack gap="lg">
            <Box bg="card" p="lg" border="top" borderColor={colors.skyBlue}>
              <Stack gap="sm">
                <Text variant="heading">Profiler configuration</Text>
                <Text variant="body" color={colors.textSecondary}>
                  Endpoint behavior learning: sample budgets, anomaly z-score thresholds, and
                  security controls for model poisoning / PII redaction.
                </Text>
              </Stack>
            </Box>

            {profilerSaveState.kind === 'success' ? (
              <>
                <Alert status="success" title="Saved">
                  {profilerSaveState.message}
                </Alert>
                {profilerSaveState.warning ? (
                  <Alert status="warning" title="Reload required">
                    {profilerSaveState.warning}
                  </Alert>
                ) : null}
              </>
            ) : null}

            {profilerSaveState.kind === 'error' ? (
              <Alert status="error" title="Save failed">
                {profilerSaveState.message}
              </Alert>
            ) : null}

            {!state.fullConfig ? (
              <Alert status="warning" title="Full config unavailable">
                This tab needs `config:write` on `GET /config` and `admin:write` on `POST /config`.
              </Alert>
            ) : (
              <form
                className="console-next-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void saveProfilerConfig();
                }}
              >
                <Stack gap="lg">
                  <Box bg="card" p="lg" border="top" borderColor={colors.magenta}>
                    <Stack gap="md">
                      <Text variant="heading">Core</Text>
                      <div className="console-next-form-grid">
                        <Input
                          fill
                          label="Max profiles"
                          type="number"
                          min={1}
                          step={1}
                          value={profilerForm.max_profiles}
                          onChange={(event) =>
                            updateProfilerForm('max_profiles', event.currentTarget.value)
                          }
                        />
                        <Input
                          fill
                          label="Max schemas"
                          type="number"
                          min={1}
                          step={1}
                          value={profilerForm.max_schemas}
                          onChange={(event) =>
                            updateProfilerForm('max_schemas', event.currentTarget.value)
                          }
                        />
                        <Input
                          fill
                          label="Min samples for validation"
                          type="number"
                          min={1}
                          step={1}
                          value={profilerForm.min_samples_for_validation}
                          onChange={(event) =>
                            updateProfilerForm(
                              'min_samples_for_validation',
                              event.currentTarget.value,
                            )
                          }
                        />
                      </div>
                      <div className="console-next-toggle-grid">
                        <ToggleField
                          label="Profiler enabled"
                          helper="Master enable for endpoint profiling + anomaly detection."
                          checked={profilerForm.enabled}
                          onChange={(checked) => updateProfilerForm('enabled', checked)}
                        />
                      </div>
                    </Stack>
                  </Box>

                  <Box bg="card" p="lg" border="top" borderColor={colors.orange}>
                    <Stack gap="md">
                      <Text variant="heading">Anomaly thresholds</Text>
                      <div className="console-next-form-grid">
                        <Input
                          fill
                          label="Payload z-threshold"
                          type="number"
                          inputMode="decimal"
                          min={0}
                          max={20}
                          step="any"
                          value={profilerForm.payload_z_threshold}
                          onChange={(event) =>
                            updateProfilerForm('payload_z_threshold', event.currentTarget.value)
                          }
                          helper="Default: 3.0; must be between 0 and 20."
                        />
                        <Input
                          fill
                          label="Parameter z-threshold"
                          type="number"
                          inputMode="decimal"
                          min={0}
                          max={20}
                          step="any"
                          value={profilerForm.param_z_threshold}
                          onChange={(event) =>
                            updateProfilerForm('param_z_threshold', event.currentTarget.value)
                          }
                          helper="Default: 4.0; must be between 0 and 20."
                        />
                        <Input
                          fill
                          label="Response z-threshold"
                          type="number"
                          inputMode="decimal"
                          min={0}
                          max={20}
                          step="any"
                          value={profilerForm.response_z_threshold}
                          onChange={(event) =>
                            updateProfilerForm('response_z_threshold', event.currentTarget.value)
                          }
                          helper="Default: 4.0; must be between 0 and 20."
                        />
                        <Input
                          fill
                          label="Minimum stddev"
                          type="number"
                          inputMode="decimal"
                          min={0}
                          max={100}
                          step="any"
                          value={profilerForm.min_stddev}
                          onChange={(event) =>
                            updateProfilerForm('min_stddev', event.currentTarget.value)
                          }
                          helper="Default: 0.01; must be between 0 and 100."
                        />
                        <Input
                          fill
                          label="Type-ratio threshold"
                          type="number"
                          inputMode="decimal"
                          min={0}
                          max={1}
                          step="any"
                          value={profilerForm.type_ratio_threshold}
                          onChange={(event) =>
                            updateProfilerForm(
                              'type_ratio_threshold',
                              event.currentTarget.value,
                            )
                          }
                          helper="0-1; default: 0.9"
                        />
                      </div>
                    </Stack>
                  </Box>

                  <Box bg="card" p="lg" border="top" borderColor={colors.green}>
                    <Stack gap="md">
                      <Text variant="heading">Security controls</Text>
                      <div className="console-next-form-grid">
                        <Input
                          fill
                          label="Max type counts"
                          type="number"
                          min={1}
                          step={1}
                          value={profilerForm.max_type_counts}
                          onChange={(event) =>
                            updateProfilerForm('max_type_counts', event.currentTarget.value)
                          }
                          helper="Prevents memory exhaustion."
                        />
                        <Input
                          fill
                          label="Freeze after samples"
                          type="number"
                          min={0}
                          step={1}
                          value={profilerForm.freeze_after_samples}
                          onChange={(event) =>
                            updateProfilerForm(
                              'freeze_after_samples',
                              event.currentTarget.value,
                            )
                          }
                          helper="0 disables background freezing; prevents model poisoning."
                        />
                      </div>
                      <div className="console-next-toggle-grid">
                        <ToggleField
                          label="Redact PII in anomaly descriptions"
                          helper="Leave enabled unless operating in a PII-safe environment."
                          checked={profilerForm.redact_pii}
                          onChange={(checked) => updateProfilerForm('redact_pii', checked)}
                        />
                      </div>
                    </Stack>
                  </Box>

                  <div className="console-next-button-row">
                    <Button type="submit" disabled={isAnySaveInFlight}>
                      {getSaveButtonLabel(
                        profilerSaveState,
                        isAnySaveInFlight,
                        'Save profiler config',
                      )}
                    </Button>
                    <Button
                      type="button"
                      variant="outlined"
                      onClick={() => {
                        setProfilerSaveState({ kind: 'idle' });
                        setProfilerForm(buildProfilerForm(state.fullConfig?.profiler));
                      }}
                      disabled={isAnySaveInFlight}
                    >
                      Reset form
                    </Button>
                  </div>
                </Stack>
              </form>
            )}
          </Stack>
        </section>
      ) : null}

      {activeTab === 'roadmap' ? (
        <section role="tabpanel" id="panel-roadmap" aria-labelledby="tab-roadmap">
          <Stack gap="md">
            <Box bg="card" p="lg" border="top" borderColor={colors.magenta}>
              <Stack gap="sm">
                <Text variant="heading">Next operator slices</Text>
                <Text variant="body" color={colors.textSecondary}>
                  Console Next now covers live per-site WAF and header overrides. The next
                  operator slice is finishing the remaining site-level controls and validation
                  guardrails.
                </Text>
              </Stack>
            </Box>
            <Box bg="card" p="lg" border="top" borderColor={colors.orange}>
              <Stack gap="xs">
                <Text variant="label" color={colors.textSecondary}>
                  Remaining UI gaps after this slice
                </Text>
                <Text variant="body">Per-site TLS and shadow mirror controls</Text>
                <Text variant="body">Per-site access control and rate-limit overrides</Text>
              </Stack>
            </Box>
          </Stack>
        </section>
      ) : null}
    </main>
  );
}
