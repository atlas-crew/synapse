import { describe, it, expect, vi, afterEach } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { Logger } from 'pino';
import { FileRetryStore } from '../persistent-store.js';
import type { BufferedItem } from '../retry-buffer.js';

const createMockLogger = (): Logger =>
  ({
    child: vi.fn().mockReturnThis(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  } as unknown as Logger);

const mkTmpDir = async () => fs.mkdtemp(path.join(os.tmpdir(), 'sh-file-retry-store-'));

let tmpDir: string | null = null;

afterEach(async () => {
  vi.restoreAllMocks();
  if (tmpDir) {
    await fs.rm(tmpDir, { recursive: true, force: true });
    tmpDir = null;
  }
});

describe('FileRetryStore', () => {
  it('load() returns [] on ENOENT', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'missing.json');

    const store = new FileRetryStore(filePath, createMockLogger());
    await expect(store.load()).resolves.toEqual([]);
  });

  it('load() returns [] on malformed JSON and logs error', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'bad.json');
    await fs.writeFile(filePath, '{not-json', 'utf8');

    const logger = createMockLogger();
    const store = new FileRetryStore(filePath, logger);
    await expect(store.load()).resolves.toEqual([]);
    expect(logger.error).toHaveBeenCalled();
  });

  it('load() returns [] on non-array JSON and logs error', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'items.json');

    const logger = createMockLogger();
    const store = new FileRetryStore(filePath, logger);

    await fs.writeFile(filePath, JSON.stringify({}), 'utf8');
    await expect(store.load()).resolves.toEqual([]);
    expect(logger.error).toHaveBeenCalled();

    await fs.writeFile(filePath, JSON.stringify('string'), 'utf8');
    await expect(store.load()).resolves.toEqual([]);
    expect(logger.error).toHaveBeenCalled();
  });

  it('save() creates parent directories recursively', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'nested', 'dir', 'items.json');

    const store = new FileRetryStore(filePath, createMockLogger());
    await store.save([]);
    await expect(fs.stat(filePath)).resolves.toBeDefined();
    const raw = await fs.readFile(filePath, 'utf8');
    expect(JSON.parse(raw)).toEqual([]);
  });

  it('save() writes correct JSON and round-trips via load()', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'items.json');

    const items: BufferedItem[] = [
      {
        type: 'signal',
        data: [],
        attempts: 1,
        nextRetryAt: 123,
        addedAt: 456,
      },
      {
        type: 'transaction',
        data: [],
        attempts: 2,
        nextRetryAt: 789,
        addedAt: 1000,
      },
    ];

    const store = new FileRetryStore(filePath, createMockLogger());
    await store.save(items);

    const raw = await fs.readFile(filePath, 'utf8');
    expect(JSON.parse(raw)).toEqual(items);

    await expect(store.load()).resolves.toEqual(items);
    await expect(fs.stat(filePath)).rejects.toBeDefined();
  });

  it('load() deletes file after successful read', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'items.json');

    const items: BufferedItem[] = [
      {
        type: 'signal',
        data: [],
        attempts: 1,
        nextRetryAt: 123,
        addedAt: 456,
      },
    ];
    await fs.writeFile(filePath, JSON.stringify(items), 'utf8');

    const store = new FileRetryStore(filePath, createMockLogger());
    await expect(store.load()).resolves.toEqual(items);

    await expect(fs.stat(filePath)).rejects.toBeDefined();
  });

  it('load() suppresses unlink errors and still returns items', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'items.json');

    const items: BufferedItem[] = [
      {
        type: 'signal',
        data: [],
        attempts: 1,
        nextRetryAt: 123,
        addedAt: 456,
      },
    ];
    await fs.writeFile(filePath, JSON.stringify(items), 'utf8');

    const unlinkSpy = vi.spyOn(fs, 'unlink').mockRejectedValueOnce(new Error('nope'));

    const store = new FileRetryStore(filePath, createMockLogger());
    await expect(store.load()).resolves.toEqual(items);
    expect(unlinkSpy).toHaveBeenCalled();
  });

  it('load() drops invalid items and logs error', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'items.json');

    const valid: BufferedItem = {
      type: 'signal',
      data: [],
      attempts: 1,
      nextRetryAt: 123,
      addedAt: 456,
    };

    // Missing attempts/nextRetryAt/addedAt, and data is wrong shape.
    const invalid = { type: 'signal', data: null };

    await fs.writeFile(filePath, JSON.stringify([invalid, valid]), 'utf8');

    const logger = createMockLogger();
    const store = new FileRetryStore(filePath, logger);
    await expect(store.load()).resolves.toEqual([valid]);
    expect(logger.error).toHaveBeenCalled();

    await expect(fs.stat(filePath)).rejects.toBeDefined();
  });

  it('load() drops unknown type items and logs error', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'items.json');

    const valid: BufferedItem = {
      type: 'signal',
      data: [],
      attempts: 1,
      nextRetryAt: 123,
      addedAt: 456,
    };

    const invalid = {
      type: 'signals', // typo
      data: [],
      attempts: 1,
      nextRetryAt: 0,
      addedAt: 0,
    };

    await fs.writeFile(filePath, JSON.stringify([invalid, valid]), 'utf8');

    const logger = createMockLogger();
    const store = new FileRetryStore(filePath, logger);
    await expect(store.load()).resolves.toEqual([valid]);
    expect(logger.error).toHaveBeenCalled();
  });

  it('load() drops campaign items when data is an array (expects object)', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'items.json');

    const valid: BufferedItem = {
      type: 'signal',
      data: [],
      attempts: 1,
      nextRetryAt: 123,
      addedAt: 456,
    };

    const invalid = {
      type: 'campaign',
      data: [],
      attempts: 1,
      nextRetryAt: 0,
      addedAt: 0,
    };

    await fs.writeFile(filePath, JSON.stringify([invalid, valid]), 'utf8');

    const logger = createMockLogger();
    const store = new FileRetryStore(filePath, logger);
    await expect(store.load()).resolves.toEqual([valid]);
    expect(logger.error).toHaveBeenCalled();
  });

  it('load() drops non-campaign items when data is not an array', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'items.json');

    const valid: BufferedItem = {
      type: 'signal',
      data: [],
      attempts: 1,
      nextRetryAt: 123,
      addedAt: 456,
    };

    const invalid = {
      type: 'signal',
      data: {},
      attempts: 1,
      nextRetryAt: 0,
      addedAt: 0,
    };

    await fs.writeFile(filePath, JSON.stringify([invalid, valid]), 'utf8');

    const logger = createMockLogger();
    const store = new FileRetryStore(filePath, logger);
    await expect(store.load()).resolves.toEqual([valid]);
    expect(logger.error).toHaveBeenCalled();
  });

  it('save() propagates write errors', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'items.json');

    const writeSpy = vi.spyOn(fs, 'writeFile').mockRejectedValueOnce(new Error('disk full'));

    const store = new FileRetryStore(filePath, createMockLogger());
    await expect(store.save([])).rejects.toThrow(/disk full/i);
    expect(writeSpy).toHaveBeenCalled();
  });

  it('save() propagates mkdir errors', async () => {
    tmpDir = await mkTmpDir();
    const filePath = path.join(tmpDir, 'nested', 'dir', 'items.json');

    const mkdirSpy = vi.spyOn(fs, 'mkdir').mockRejectedValueOnce(new Error('no perms'));

    const store = new FileRetryStore(filePath, createMockLogger());
    await expect(store.save([])).rejects.toThrow(/no perms/i);
    expect(mkdirSpy).toHaveBeenCalled();
  });
});
