/**
 * Persistent storage for ClickHouse Retry Buffer
 * Supports saving/loading items to/from disk or Redis.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import type { Logger } from 'pino';
import type { IRetryPersistentStore, BufferedItem } from './retry-buffer.js';

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
      const items = JSON.parse(data) as BufferedItem[];
      
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
