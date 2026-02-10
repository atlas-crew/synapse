/**
 * Docs Routes — Path Traversal & Functional Tests (P0 Security)
 *
 * Validates the SH-001 path traversal guard on GET /api/v1/docs/:id and
 * GET /api/v1/docs/search, plus basic functional tests for the list and
 * search endpoints.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import request from '../../../__tests__/test-request.js';
import path from 'path';

// ---------------------------------------------------------------------------
// Mocks — must be hoisted before the module under test is imported
// ---------------------------------------------------------------------------

// Mock the logger so pino does not pollute test output
vi.mock('../../../lib/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    child: vi.fn().mockReturnThis(),
  },
}));

// We mock `fs/promises` and `fs` so the router never touches the real filesystem.
// The SITE_ROOT resolution in docs.ts calls existsSync at module-load time, so we
// need to control what it returns.
const mockReaddir = vi.fn();
const mockReadFile = vi.fn();
const mockStat = vi.fn();
const mockExistsSync = vi.fn();

vi.mock('fs/promises', () => ({
  default: {
    readdir: (...args: unknown[]) => mockReaddir(...args),
    readFile: (...args: unknown[]) => mockReadFile(...args),
    stat: (...args: unknown[]) => mockStat(...args),
  },
}));

vi.mock('fs', () => ({
  existsSync: (...args: unknown[]) => mockExistsSync(...args),
}));

// ---------------------------------------------------------------------------
// Import the router AFTER mocks are wired
// ---------------------------------------------------------------------------
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { default: docsRouter } = await import('../docs.js');

// ---------------------------------------------------------------------------
// Test app
// ---------------------------------------------------------------------------

function createApp() {
  const app = express();
  app.use('/api/v1/docs', docsRouter);
  return app;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FAKE_MTIME = new Date('2025-01-15T10:00:00.000Z');

function stubStatResult() {
  return { mtime: FAKE_MTIME };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('GET /api/v1/docs/:id — path traversal guard', () => {
  let app: ReturnType<typeof createApp>;

  beforeEach(() => {
    vi.clearAllMocks();
    app = createApp();

    // Default: readFile / stat succeed for any file inside SITE_ROOT
    mockReadFile.mockResolvedValue('# Hello\nSome documentation content');
    mockStat.mockResolvedValue(stubStatResult());
  });

  // -------------------------------------------------------------------------
  // 1. Dot-dot traversal encoded as a single :id segment → 403
  //    Express normalises raw `/../..` in the URL path before routing, so the
  //    classic `GET /api/v1/docs/../../../etc/passwd` never reaches the `:id`
  //    handler. Instead we test the realistic attack vector: an :id value that
  //    *contains* `..` after colon-to-sep conversion (covered in test 3 below)
  //    and the double-dot embedded as a literal path segment that survives
  //    Express routing.
  // -------------------------------------------------------------------------
  it('rejects dot-dot traversal in :id param via colon encoding', async () => {
    // This is equivalent to `../../etc/passwd` after colon→sep conversion
    const res = await request(app).get('/api/v1/docs/..:..:..:etc:passwd');

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'Access denied' });
  });

  // -------------------------------------------------------------------------
  // 2. URL-encoded traversal (%2F) → 403 or 404
  //    Express decodes %2F before matching, so path.resolve catches it.
  // -------------------------------------------------------------------------
  it('rejects URL-encoded traversal ..%2F..%2Fetc%2Fpasswd', async () => {
    const res = await request(app).get(
      '/api/v1/docs/..%2F..%2F..%2Fetc%2Fpasswd'
    );

    expect([403, 404]).toContain(res.status);
  });

  // -------------------------------------------------------------------------
  // 3. Colon-separated traversal → 403
  //    The router converts colons to path.sep, so `..:..:etc:passwd`
  //    becomes `../../etc/passwd` which resolves outside SITE_ROOT.
  // -------------------------------------------------------------------------
  it('rejects colon-separated traversal ..:..:..:..:etc:passwd with 403', async () => {
    const res = await request(app).get(
      '/api/v1/docs/..:..:..:..:etc:passwd'
    );

    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'Access denied' });
  });

  // -------------------------------------------------------------------------
  // 4. Legitimate doc ID → 200 with content
  // -------------------------------------------------------------------------
  it('returns 200 with content for a legitimate doc ID', async () => {
    const res = await request(app).get('/api/v1/docs/tutorials:sensor-onboarding');

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      id: 'tutorials:sensor-onboarding',
      content: expect.any(String),
      mtime: FAKE_MTIME.toISOString(),
    });
  });

  // -------------------------------------------------------------------------
  // 5. Non-existent doc → 404
  // -------------------------------------------------------------------------
  it('returns 404 for a non-existent doc', async () => {
    mockReadFile.mockRejectedValue(
      Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
    );

    const res = await request(app).get('/api/v1/docs/does-not-exist');

    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Documentation not found' });
  });
});

describe('GET /api/v1/docs — list endpoint', () => {
  let app: ReturnType<typeof createApp>;

  beforeEach(() => {
    vi.clearAllMocks();
    app = createApp();
  });

  // -------------------------------------------------------------------------
  // 6. List endpoint → 200 with array
  // -------------------------------------------------------------------------
  it('returns 200 with an array of doc items', async () => {
    // Simulate a SITE_ROOT containing one subdirectory with one .md file
    mockReaddir.mockImplementation(async (_dir: string) => {
      // Determine which level we are at based on whether _dir contains a subdir
      const basename = path.basename(_dir);
      if (basename === 'guides') {
        return [
          { name: 'getting-started.md', isDirectory: () => false, isFile: () => true },
        ];
      }
      // Root level
      return [
        { name: 'guides', isDirectory: () => true, isFile: () => false },
        { name: 'setup.md', isDirectory: () => false, isFile: () => true },
      ];
    });
    mockStat.mockResolvedValue(stubStatResult());

    const res = await request(app).get('/api/v1/docs');

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    // Should contain at least setup.md and guides/getting-started.md
    expect(res.body.length).toBeGreaterThanOrEqual(2);
    const ids = (res.body as Array<{ id: string }>).map((d) => d.id);
    expect(ids).toContain('setup');
    expect(ids).toContain('guides:getting-started');
  });
});

describe('GET /api/v1/docs/search — search endpoint', () => {
  let app: ReturnType<typeof createApp>;

  beforeEach(() => {
    vi.clearAllMocks();
    app = createApp();

    // Default: listDocs sees one file, readFile returns searchable content
    mockReaddir.mockResolvedValue([
      { name: 'setup.md', isDirectory: () => false, isFile: () => true },
    ]);
    mockStat.mockResolvedValue(stubStatResult());
    mockReadFile.mockResolvedValue('# Setup Guide\nFollow these steps to configure the test environment.');
  });

  // -------------------------------------------------------------------------
  // 7. Search endpoint → 200 with results array
  // -------------------------------------------------------------------------
  it('returns 200 with matching results for a valid query', async () => {
    const res = await request(app).get('/api/v1/docs/search?q=test');

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    // The mock content contains the word "test", so we should get a result
    expect(res.body.length).toBeGreaterThanOrEqual(1);
    expect((res.body as Array<{ snippet: string }>)[0].snippet).toBeDefined();
  });
});
