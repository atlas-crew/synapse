import { UsageError } from './types.js';

export function parseConfigValue(raw: string): unknown {
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  if (raw === 'null') return null;

  const trimmed = raw.trim();
  const looksJson =
    trimmed.startsWith('{') ||
    trimmed.startsWith('[') ||
    (trimmed.startsWith('"') && trimmed.endsWith('"'));

  if (looksJson) {
    try {
      return JSON.parse(trimmed);
    } catch {
      throw new UsageError(`Invalid JSON value: ${raw}`);
    }
  }

  if (/^-?\d+(\.\d+)?$/.test(trimmed)) return Number(trimmed);

  return raw;
}

