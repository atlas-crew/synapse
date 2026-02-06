/**
 * In-Memory Express Test Wrapper (labs-1s72)
 *
 * Rationale:
 * This wrapper replaces 'supertest' for unit and integration testing of Express routes.
 *
 * Why not Supertest?
 * 1. Performance: Supertest starts a real HTTP server on a random port for every test.
 *    This adds significant overhead (100ms+ per test) and can exhaust ports in CI.
 * 2. Reliability: Real network sockets are prone to flakes and isolation issues.
 * 3. Timer Control: Supertest's asynchronous socket behavior conflicts with Vitest's
 *    fake timers (vi.useFakeTimers()). test-request runs synchronously through the
 *    Express middleware chain, allowing precise control over virtual time.
 *
 * When to use:
 * - Use test-request for 90% of route/logic integration tests.
 * - Use supertest/Playwright only for full-stack E2E tests requiring real TCP behavior.
 *
 * Implementation Details:
 * - Directly invokes app.handle() using mocked HTTP primitives.
 * - Simulates the full Express lifecycle without any network overhead.
 * - Handles query parameter encoding via Express's native parser.
 */

import { EventEmitter } from 'node:events';
import { IncomingMessage } from 'node:http';
import { Socket } from 'node:net';
import type { Express } from 'express';

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface TestResponse<T = unknown> {
  status: number;
  body: T;
  headers: Record<string, string>;
}

function createMockRequest(
  method: HttpMethod,
  url: string,
  headers: Record<string, string>,
  body?: unknown
): IncomingMessage {
  const socket = new Socket();
  const req = new IncomingMessage(socket);

  req.method = method;
  req.url = url;
  req.headers = headers;

  if (body !== undefined) {
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    if (!req.headers['content-type']) {
      req.headers['content-type'] = 'application/json';
    }
    req.headers['content-length'] = Buffer.byteLength(payload).toString();
    req.push(payload);
  }

  req.push(null);
  return req;
}

class MockResponse extends EventEmitter {
  statusCode = 200;
  private headers = new Map<string, string>();
  private bodyBuffer: Buffer[] = [];
  private bodyValue: unknown;
  finished = false;

  status: (code: number) => this;
  set: (field: string, value: string) => this;
  get: (field: string) => string | undefined;
  setHeader: (field: string, value: string) => void;
  getHeader: (field: string) => string | undefined;
  writeHead: (code: number, headers?: Record<string, string>) => this;
  write: (chunk: unknown) => boolean;
  end: (chunk?: unknown) => this;
  json: (payload: unknown) => this;
  send: (payload?: unknown) => this;
  finish: () => void;

  constructor(private readonly onFinish: (response: TestResponse) => void) {
    super();

    this.status = (code: number) => {
      this.statusCode = code;
      return this;
    };

    this.set = (field: string, value: string) => {
      this.setHeader(field, value);
      return this;
    };

    this.get = (field: string) => this.getHeader(field);

    this.setHeader = (field: string, value: string) => {
      this.headers.set(field.toLowerCase(), value);
    };

    this.getHeader = (field: string) => this.headers.get(field.toLowerCase());

    this.writeHead = (code: number, headers?: Record<string, string>) => {
      this.statusCode = code;
      if (headers) {
        for (const [key, value] of Object.entries(headers)) {
          this.setHeader(key, value);
        }
      }
      return this;
    };

    this.write = (chunk: unknown) => {
      if (chunk !== undefined) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
        this.bodyBuffer.push(buffer);
      }
      return true;
    };

    this.end = (chunk?: unknown) => {
      if (chunk !== undefined) {
        this.write(chunk);
      }
      this.finish();
      return this;
    };

    this.json = (payload: unknown) => {
      this.bodyValue = payload;
      if (!this.getHeader('content-type')) {
        this.setHeader('content-type', 'application/json');
      }
      this.finish();
      return this;
    };

    this.send = (payload?: unknown) => {
      if (payload !== undefined) {
        this.bodyValue = payload;
      }
      this.finish();
      return this;
    };

    this.finish = () => {
      if (this.finished) return;
      this.finished = true;

      const headers: Record<string, string> = {};
      for (const [key, value] of this.headers.entries()) {
        headers[key] = value;
      }

      const body = this.bodyValue ?? (this.bodyBuffer.length > 0
        ? Buffer.concat(this.bodyBuffer).toString('utf8')
        : undefined);

      this.onFinish({
        status: this.statusCode,
        body,
        headers,
      });

      this.emit('finish');
    };
  }
}

class TestRequest<T = unknown> {
  private headers: Record<string, string> = {};
  private payload: unknown;
  private expectedStatus?: number;

  constructor(
    private readonly app: Express,
    private readonly method: HttpMethod,
    private readonly path: string
  ) {}

  set(field: string, value: string): this {
    this.headers[field.toLowerCase()] = value;
    return this;
  }

  send(body: unknown): this {
    this.payload = body;
    return this;
  }

  expect(status: number): this {
    this.expectedStatus = status;
    return this;
  }

  then<TResult1 = TestResponse<T>, TResult2 = never>(
    onfulfilled?: ((value: TestResponse<T>) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null
  ): Promise<TResult1 | TResult2> {
    return this.execute().then(onfulfilled, onrejected);
  }

  private async execute(): Promise<TestResponse<T>> {
    const response = await dispatchRequest<T>(this.app, this.method, this.path, this.headers, this.payload);

    if (this.expectedStatus !== undefined && response.status !== this.expectedStatus) {
      throw new Error(`Expected status ${this.expectedStatus} but received ${response.status}`);
    }

    return response;
  }
}

function dispatchRequest<T = unknown>(
  app: Express,
  method: HttpMethod,
  path: string,
  headers: Record<string, string>,
  payload?: unknown
): Promise<TestResponse<T>> {
  return new Promise((resolve, reject) => {
    const req = (createMockRequest(method, path, { ...headers }, payload) as unknown) as Parameters<Express['handle']>[0];
    const res = (new MockResponse(resolve) as unknown) as Parameters<Express['handle']>[1];
    const handle = (app.handle.bind(app) as unknown) as (
        req: Parameters<Express['handle']>[0],
        res: Parameters<Express['handle']>[1],
        next: Parameters<Express['handle']>[2]
      ) => void;

    try {
      handle(req, res, (err: unknown) => {
        if (err) {
          reject(err);
        }
      });
    } catch (error) {
      reject(error);
    }
  });
}

export default function request(app: Express) {
  return {
    get: <T = unknown>(path: string) => new TestRequest<T>(app, 'GET', path),
    post: <T = unknown>(path: string) => new TestRequest<T>(app, 'POST', path),
    put: <T = unknown>(path: string) => new TestRequest<T>(app, 'PUT', path),
    patch: <T = unknown>(path: string) => new TestRequest<T>(app, 'PATCH', path),
    delete: <T = unknown>(path: string) => new TestRequest<T>(app, 'DELETE', path),
  };
}
