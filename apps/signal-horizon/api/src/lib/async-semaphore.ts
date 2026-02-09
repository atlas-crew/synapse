export class AsyncSemaphore {
  private available: number;
  private readonly waiters: Array<(release: () => void) => void> = [];

  constructor(private readonly capacity: number) {
    this.available = capacity;
  }

  async acquire(options?: { signal?: AbortSignal }): Promise<() => void> {
    if (this.available > 0) {
      this.available -= 1;
      return this.makeRelease();
    }

    const signal = options?.signal;

    return new Promise((resolve, reject) => {
      let settled = false;

      const cleanup = () => {
        if (signal) signal.removeEventListener('abort', onAbort);
      };

      const onAbort = () => {
        if (settled) return;
        settled = true;
        const idx = this.waiters.indexOf(waiter);
        if (idx >= 0) this.waiters.splice(idx, 1);
        cleanup();
        reject(new Error('Semaphore acquire aborted'));
      };

      const waiter = (release: () => void) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(release);
      };

      if (signal?.aborted) {
        onAbort();
        return;
      }

      if (signal) {
        signal.addEventListener('abort', onAbort);
      }

      this.waiters.push(waiter);
    });
  }

  private makeRelease(): () => void {
    let released = false;

    return () => {
      if (released) return;
      released = true;

      const next = this.waiters.shift();
      if (next) {
        next(this.makeRelease());
        return;
      }

      this.available += 1;
    };
  }
}

