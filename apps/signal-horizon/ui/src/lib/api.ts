/**
 * Shared API utilities for Signal Horizon UI
 * Provides centralized API configuration and authenticated fetch
 */

function normalizeApiBaseUrl(raw: string): string {
  const trimmed = raw.replace(/\/+$/, '');

  // Accept misconfigured inputs like "http://host:3100/api/v1/management" and normalize back to "/api/v1".
  try {
    const url = new URL(trimmed);
    const path = url.pathname.replace(/\/+$/, '');
    if (path.includes('/api/v1')) {
      url.pathname = '/api/v1';
      url.search = '';
      url.hash = '';
      return url.toString().replace(/\/+$/, '');
    }
    if (path.includes('/api')) {
      url.pathname = '/api/v1';
      url.search = '';
      url.hash = '';
      return url.toString().replace(/\/+$/, '');
    }
  } catch {
    // Non-URL (shouldn't happen for VITE_API_URL), fall back to suffix logic.
  }

  if (trimmed.endsWith('/api/v1')) return trimmed;
  if (trimmed.endsWith('/api')) return `${trimmed}/v1`;
  return `${trimmed}/api/v1`;
}

export const API_BASE_URL = normalizeApiBaseUrl(import.meta.env.VITE_API_URL || 'http://localhost:3100');
const ENV_API_KEY = import.meta.env.VITE_HORIZON_API_KEY || import.meta.env.VITE_API_KEY || '';
export const API_KEY = ENV_API_KEY || 'dev-dashboard-key';

interface FetchOptions {
  signal?: AbortSignal;
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  headers?: Record<string, string>;
}

const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function getCookie(name: string): string | undefined {
  if (typeof document === 'undefined') return undefined;
  const parts = document.cookie.split(';');
  for (const part of parts) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('='));
  }
  return undefined;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function generateRequestNonce(): string {
  // Server expects 16-64 chars; hex(16 bytes) = 32 chars, matches /^[a-zA-Z0-9-]+$/.
  if (typeof crypto !== 'undefined' && 'getRandomValues' in crypto) {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    return bytesToHex(buf);
  }
  // Fallback for older runtimes (shouldn't happen in modern browsers).
  return `${Date.now()}${Math.random().toString(16).slice(2)}`.replace(/[^a-zA-Z0-9]/g, '').slice(0, 32).padEnd(16, '0');
}

/**
 * Structured API error with HTTP status and server-provided details.
 * Catch blocks can use `instanceof ApiError` to access status/details.
 */
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public details?: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/** Maps common HTTP status codes to human-readable labels */
const HTTP_STATUS_LABELS: Record<number, string> = {
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  408: 'Request Timeout',
  409: 'Conflict',
  422: 'Unprocessable Entity',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable',
  504: 'Gateway Timeout',
};

/**
 * Build a human-readable error message from a failed response.
 * Tries to extract the server-provided error message from JSON body,
 * falling back to status text.
 */
async function buildApiError(response: Response): Promise<ApiError> {
  const status = response.status;
  const statusLabel = HTTP_STATUS_LABELS[status] || response.statusText;
  let serverMessage: string | undefined;

  try {
    const body = await response.json();
    // Common API error shapes: { error: "..." }, { message: "..." }, { detail: "..." }
    serverMessage =
      (typeof body.error === 'string' ? body.error : undefined) ??
      (typeof body.message === 'string' ? body.message : undefined) ??
      (typeof body.detail === 'string' ? body.detail : undefined);
  } catch {
    // Response body is not JSON or is empty - that's fine
  }

  const displayMessage = serverMessage
    ? `${status} ${statusLabel}: ${serverMessage}`
    : `${status} ${statusLabel}`;

  return new ApiError(status, displayMessage, serverMessage);
}

/**
 * Authenticated fetch wrapper for Signal Horizon API
 *
 * Authentication strategy (labs-n6nf):
 * - If VITE_HORIZON_API_KEY is set (programmatic / dev), sends Authorization: Bearer header.
 * - Otherwise relies on the httpOnly access_token cookie (set by /auth/login).
 *   `credentials: 'include'` ensures cookies are sent with every request.
 */
export async function apiFetch<T = any>(endpoint: string, options: FetchOptions = {}): Promise<T> {
  const { signal, method = 'GET', body, headers: extraHeaders } = options;

  const headers: Record<string, string> = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
  };

  // Programmatic API key is used if available. Browser sessions rely on cookies.
  if (API_KEY) headers.Authorization = `Bearer ${API_KEY}`;
  if (extraHeaders) Object.assign(headers, extraHeaders);

  // Replay-protection + CSRF for mutation endpoints.
  if (MUTATION_METHODS.has(method)) {
    if (!headers['X-Request-Nonce']) headers['X-Request-Nonce'] = generateRequestNonce();
    if (!headers['X-Request-Timestamp']) headers['X-Request-Timestamp'] = String(Date.now());

    // Double-submit CSRF cookie pattern (server sets csrf-token cookie on reads).
    const csrf = getCookie('csrf-token');
    if (csrf && !headers['X-CSRF-Token']) headers['X-CSRF-Token'] = csrf;
  }

  const url = `${API_BASE_URL}${endpoint}`;

  const doFetch = async (cache: RequestCache): Promise<Response> =>
    fetch(url, {
      method,
      headers,
      credentials: 'include', // labs-n6nf: send httpOnly cookies
      signal,
      cache,
      body: body ? JSON.stringify(body) : undefined,
    });

  // APIs are highly dynamic and auth-scoped; browser 304 revalidation breaks our JSON parsing.
  // Avoid conditional requests by bypassing the HTTP cache.
  let response = await doFetch('no-store');
  if (response.status === 304) {
    // Defensive: if the browser still revalidated, retry once with a stronger bypass.
    response = await doFetch('reload');
  }

  if (!response.ok) {
    throw await buildApiError(response);
  }

  // Some endpoints may respond with 204 or empty body.
  if (response.status === 204) return undefined as T;

  const text = await response.text();
  if (!text) return undefined as T;

  const contentType = response.headers.get('content-type') || '';
  if (contentType.toLowerCase().includes('json')) {
    return JSON.parse(text) as T;
  }
  return text as unknown as T;
}

/**
 * Format an error for user-facing display.
 * Returns status-aware message for ApiError, generic message for others.
 */
export function formatApiError(err: unknown, fallback = 'An unexpected error occurred'): string {
  if (err instanceof ApiError) {
    return err.message;
  }
  if (err instanceof Error) {
    return err.message;
  }
  return fallback;
}
