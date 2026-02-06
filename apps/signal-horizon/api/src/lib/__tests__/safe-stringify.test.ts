import { describe, it, expect } from 'vitest';
import { safeStringify } from '../safe-stringify.js';

describe('safeStringify', () => {
  it('should stringify simple objects', () => {
    const obj = { a: 1, b: 'test' };
    expect(safeStringify(obj)).toBe('{"a":1,"b":"test"}');
  });

  it('should handle circular references', () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj.self = obj;
    expect(safeStringify(obj)).toBe('{"a":1,"self":"[Circular]"}');
  });

  it('should limit depth', () => {
    const deepObj = { a: { b: { c: { d: { e: { f: 1 } } } } } };
    // Default depth is 5
    expect(safeStringify(deepObj, { maxDepth: 3 })).toContain('[Max Depth]');
  });

  it('should limit array length', () => {
    const longArray = new Array(1000).fill(1);
    const res = safeStringify(longArray, { maxArrayLength: 5 });
    const parsed = JSON.parse(res);
    expect(parsed).toHaveLength(6); // 5 items + truncation marker
    expect(parsed[5]).toBe('... 995 more items');
  });

  it('should limit output length', () => {
    const obj = { a: 'a'.repeat(1000) };
    const res = safeStringify(obj, { maxLength: 50 });
    expect(res.length).toBeLessThanOrEqual(65); // 50 + truncation overhead
    expect(res).toContain('...[Truncated]');
  });

  it('should handle massive objects without crashing', () => {
    const massiveObj: Record<string, { nested: string }> = {};
    for (let i = 0; i < 10000; i++) {
      massiveObj[`key${i}`] = { nested: 'value'.repeat(100) };
    }
    
    const start = performance.now();
    const res = safeStringify(massiveObj, { maxLength: 1000, maxDepth: 2 });
    const end = performance.now();
    
    expect(res.length).toBeLessThan(2000);
    expect(end - start).toBeLessThan(500); // Should be fast
  });
});
