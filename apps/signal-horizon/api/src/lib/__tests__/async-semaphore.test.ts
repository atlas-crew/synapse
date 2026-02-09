import { describe, it, expect } from 'vitest';
import { AsyncSemaphore } from '../async-semaphore.js';

describe('AsyncSemaphore', () => {
  it('acquires immediately up to capacity and blocks beyond it', async () => {
    const sem = new AsyncSemaphore(1);
    expect(sem.getAvailable()).toBe(1);
    expect(sem.getQueueDepth()).toBe(0);

    const release1 = await sem.acquire();
    expect(sem.getAvailable()).toBe(0);

    let acquired2 = false;
    const p2 = sem.acquire().then((release2) => {
      acquired2 = true;
      release2();
    });

    // Give the queued acquire a chance to run; it should still be blocked.
    await Promise.resolve();
    expect(acquired2).toBe(false);
    expect(sem.getQueueDepth()).toBe(1);

    release1();
    await p2;
    expect(acquired2).toBe(true);
    expect(sem.getQueueDepth()).toBe(0);
  });

  it('releases in FIFO order', async () => {
    const sem = new AsyncSemaphore(1);

    const release1 = await sem.acquire();

    const order: string[] = [];
    const p2 = sem.acquire().then((r) => {
      order.push('second');
      r();
    });
    const p3 = sem.acquire().then((r) => {
      order.push('third');
      r();
    });

    await Promise.resolve();
    release1();

    await Promise.all([p2, p3]);
    expect(order).toEqual(['second', 'third']);
  });

  it('supports aborting a queued acquire', async () => {
    const sem = new AsyncSemaphore(1);
    const release1 = await sem.acquire();

    const controller = new AbortController();
    const p2 = sem.acquire({ signal: controller.signal });
    controller.abort();

    await expect(p2).rejects.toThrow(/aborted/i);

    // Aborted waiter should not consume a permit when we release.
    release1();
    const release3 = await sem.acquire();
    release3();
  });
});
