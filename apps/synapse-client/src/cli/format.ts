import type { IO } from './types.js';

export function pretty(io: IO, data: unknown): void {
  io.log(JSON.stringify(data, null, 2));
}

export function formatTable(rows: string[][]): string {
  if (rows.length === 0) return '';
  const cols = rows[0].length;
  const widths: number[] = Array(cols).fill(0);

  for (const row of rows) {
    for (let i = 0; i < row.length; i++) {
      widths[i] = Math.max(widths[i], row[i].length);
    }
  }

  return rows
    .map((row) => row.map((cell, i) => cell.padEnd(widths[i])).join('  '))
    .join('\n');
}

export function formatStatus(status: Record<string, unknown>): string {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(status)) {
    const displayKey = key.replace(/([A-Z])/g, ' $1').toLowerCase();
    lines.push(`${displayKey}: ${value}`);
  }
  return lines.join('\n');
}

