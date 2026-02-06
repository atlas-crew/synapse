/**
 * Shared API utilities for Signal Horizon UI
 * Provides centralized API configuration and authenticated fetch
 */

export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3100/api/v1';
export const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';

interface FetchOptions {
  signal?: AbortSignal;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
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
    throw new Error(`API error: ${response.status} ${response.statusText}`);
  }

  return response.json();
}
