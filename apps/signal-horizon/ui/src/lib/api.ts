/**
 * Shared API utilities for Signal Horizon UI
 * Provides centralized API configuration and authenticated fetch
 */

function normalizeApiBaseUrl(raw: string): string {
  const trimmed = raw.replace(/\/+$/, '');
  if (trimmed.endsWith('/api/v1')) return trimmed;
  if (trimmed.endsWith('/api')) return `${trimmed}/v1`;
  return `${trimmed}/api/v1`;
}

export const API_BASE_URL = normalizeApiBaseUrl(import.meta.env.VITE_API_URL || 'http://localhost:3100');
export const API_KEY =
  import.meta.env.VITE_HORIZON_API_KEY ||
  import.meta.env.VITE_API_KEY ||
  'dev-dashboard-key';

interface FetchOptions {
  signal?: AbortSignal;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
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
export async function apiFetch<T>(endpoint: string, options: FetchOptions = {}): Promise<T> {
  const { signal, method = 'GET', body } = options;

  const headers: Record<string, string> = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
  };

  // Programmatic API key takes precedence (dev / CI / external consumers).
  // Browser sessions rely on the httpOnly cookie instead.
  if (API_KEY && API_KEY !== 'dev-dashboard-key') {
    headers['Authorization'] = `Bearer ${API_KEY}`;
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method,
    headers,
    credentials: 'include', // labs-n6nf: send httpOnly cookies
    signal,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    throw await buildApiError(response);
  }

  return response.json();
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
