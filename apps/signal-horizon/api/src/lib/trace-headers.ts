import type { Request } from 'express';

const MAX_REQUEST_ID_LEN = 64;
const MAX_TRACEPARENT_LEN = 128;
const MAX_TRACESTATE_LEN = 512;

const TRACEPARENT_RE = /^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/i;

function hasCrlf(value: string): boolean {
  return value.includes('\r') || value.includes('\n');
}

function isAllZerosHex(value: string): boolean {
  // value expected to be hex-only
  return /^0+$/i.test(value);
}

function isValidTraceparent(value: string): boolean {
  if (!TRACEPARENT_RE.test(value)) return false;
  // version(2) - trace-id(32) - parent-id(16) - flags(2)
  const parts = value.split('-');
  const traceId = parts[1] ?? '';
  const parentId = parts[2] ?? '';
  // W3C: trace-id and parent-id must not be all zeros
  if (isAllZerosHex(traceId)) return false;
  if (isAllZerosHex(parentId)) return false;
  return true;
}

/**
 * Best-effort correlation propagation for downstream HTTP calls.
 *
 * - Always forward our hub `x-request-id` when present (set by request-id middleware).
 * - Forward OTEL headers if the client provided them (so downstream can join traces).
 */
export function buildTraceHeaders(req: Request): Record<string, string> {
  const headers: Record<string, string> = {};

  if (req.id) {
    const requestId = String(req.id).trim();
    if (requestId.length > 0 && requestId.length <= MAX_REQUEST_ID_LEN && !hasCrlf(requestId)) {
      headers['x-request-id'] = requestId;
    }
  }

  const traceparent = req.get('traceparent');
  if (traceparent) {
    const v = traceparent.trim();
    if (v.length > 0 && v.length <= MAX_TRACEPARENT_LEN && !hasCrlf(v) && isValidTraceparent(v)) {
      headers.traceparent = v;
    }
  }

  const tracestate = req.get('tracestate');
  if (tracestate) {
    const v = tracestate.trim();
    if (v.length > 0 && v.length <= MAX_TRACESTATE_LEN && !hasCrlf(v)) {
      headers.tracestate = v;
    }
  }

  return headers;
}
