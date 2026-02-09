/**
 * Persistent storage for ClickHouse Retry Buffer
 * Supports saving/loading items to/from disk or Redis.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import type { Logger } from 'pino';
import type { IRetryPersistentStore, BufferedItem } from './retry-buffer.js';

const isBufferedItemLike = (value: unknown): value is BufferedItem => {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;

  const type = v.type;
  if (
    type !== 'signal' &&
    type !== 'campaign' &&
    type !== 'blocklist' &&
    type !== 'transaction' &&
    type !== 'log'
  ) {
    return false;
  }

  if (typeof v.attempts !== 'number') return false;
  if (typeof v.nextRetryAt !== 'number') return false;
  if (typeof v.addedAt !== 'number') return false;

  // Data shape: campaign is a single object; all others are arrays.
  if (type === 'campaign') {
    return typeof v.data === 'object' && v.data !== null && !Array.isArray(v.data);
  }
  return Array.isArray(v.data);
};

/**
 * File-based persistent store for telemetry items.
 * Simple implementation that writes to a JSON file.
 */
export class FileRetryStore implements IRetryPersistentStore {
  private filePath: string;
  private logger: Logger;

  constructor(filePath: string, logger: Logger) {
    this.filePath = filePath;
    this.logger = logger.child({ component: 'file-retry-store' });
  }

  async save(items: BufferedItem[]): Promise<void> {
    try {
      const dir = path.dirname(this.filePath);
      await fs.mkdir(dir, { recursive: true });
      
      const data = JSON.stringify(items);
      await fs.writeFile(this.filePath, data, 'utf8');
      
      this.logger.debug({ count: items.length, path: this.filePath }, 'Saved items to disk');
    } catch (error) {
      this.logger.error({ error, path: this.filePath }, 'Failed to save items to disk');
      throw error;
    }
  }

  async load(): Promise<BufferedItem[]> {
    try {
      const data = await fs.readFile(this.filePath, 'utf8');
      const parsed = JSON.parse(data) as unknown;
      if (!Array.isArray(parsed)) {
        this.logger.error(
          { path: this.filePath, parsedType: typeof parsed },
          'Persistent retry buffer data is not an array; ignoring'
        );
        await fs.unlink(this.filePath).catch(() => {});
        return [];
      }
      const itemsRaw = parsed as unknown[];
      const items: BufferedItem[] = [];
      let dropped = 0;
      for (const item of itemsRaw) {
        if (!isBufferedItemLike(item)) {
          dropped += 1;
          continue;
        }
        items.push(item);
      }
      if (dropped > 0) {
        this.logger.error(
          { path: this.filePath, dropped },
          'Persistent retry buffer contained invalid items; dropped'
        );
      }
      
      // Optional: Clean up file after loading
      await fs.unlink(this.filePath).catch(() => {});
      
      return items;
    } catch (error) {
      const errorCode =
        typeof error === 'object' && error !== null && 'code' in error
          ? (error as { code?: unknown }).code
          : undefined;
      if (errorCode === 'ENOENT') {
        return [];
      }
      this.logger.error({ error, path: this.filePath }, 'Failed to load items from disk');
      return [];
    }
  }
}
