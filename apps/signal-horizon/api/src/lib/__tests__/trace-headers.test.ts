import { describe, it, expect } from 'vitest';
import type { Request } from 'express';
import { buildTraceHeaders } from '../trace-headers.js';

function makeReq(input: { id?: string; headers?: Record<string, string | undefined> }): Request {
  const headers = input.headers ?? {};
  return {
    id: input.id,
    get: (name: string) => headers[name.toLowerCase()],
  } as unknown as Request;
}

describe('buildTraceHeaders', () => {
  it('includes x-request-id when req.id is present', () => {
    const req = makeReq({ id: '550e8400-e29b-41d4-a716-446655440000' });
    expect(buildTraceHeaders(req)).toEqual({
      'x-request-id': '550e8400-e29b-41d4-a716-446655440000',
    });
  });

  it('includes traceparent/tracestate when valid', () => {
    const req = makeReq({
      id: '550e8400-e29b-41d4-a716-446655440000',
      headers: {
        traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
        tracestate: 'vendor=opaque',
      },
    });

    expect(buildTraceHeaders(req)).toEqual({
      'x-request-id': '550e8400-e29b-41d4-a716-446655440000',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
      tracestate: 'vendor=opaque',
    });
  });

  it('drops invalid traceparent (bad format)', () => {
    const req = makeReq({ headers: { traceparent: 'not-a-trace' } });
    expect(buildTraceHeaders(req)).toEqual({});
  });

  it('drops invalid traceparent (all-zero trace-id or parent-id)', () => {
    const req1 = makeReq({
      headers: {
        traceparent: '00-00000000000000000000000000000000-00f067aa0ba902b7-01',
      },
    });
    expect(buildTraceHeaders(req1)).toEqual({});

    const req2 = makeReq({
      headers: {
        traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01',
      },
    });
    expect(buildTraceHeaders(req2)).toEqual({});
  });

  it('drops headers containing CRLF', () => {
    const req = makeReq({
      id: 'abc\r\nx: y',
      headers: {
        traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nx: y',
        tracestate: 'vendor=opaque\nx=y',
      },
    });
    expect(buildTraceHeaders(req)).toEqual({});
  });

  it('drops overly long tracestate', () => {
    const req = makeReq({
      headers: {
        tracestate: 'a='.padEnd(600, 'b'),
      },
    });
    expect(buildTraceHeaders(req)).toEqual({});
  });
});

