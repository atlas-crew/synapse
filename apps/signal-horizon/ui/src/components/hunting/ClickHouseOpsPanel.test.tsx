import { describe, it, expect, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ClickHouseOpsSnapshot } from '../../hooks/useHunt';
import { ClickHouseOpsPanel } from './ClickHouseOpsPanel';

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function makeSnapshot(overrides: Partial<ClickHouseOpsSnapshot> = {}): ClickHouseOpsSnapshot {
  return {
    sampledAt: '2026-02-09T00:00:00.000Z',
    clickhouse: {
      enabled: true,
      connected: true,
      config: {
        enabled: true,
        maxOpenConnections: 25,
        maxInFlightQueries: 25,
        maxInFlightStreamQueries: 2,
        queryTimeoutSec: 30,
        queueTimeoutSec: 30,
        maxRowsLimit: 100000,
      },
    },
    metrics: {
      clickhouseQueryQueueDepth: {
        name: 'horizon_clickhouse_query_queue_depth',
        help: 'x',
        type: 'gauge',
        values: [
          { value: 1, labels: { op: 'queryWithParams', queue: 'query' } },
          { value: 0, labels: { op: 'queryWithParams', queue: 'stream' } },
        ],
      },
      clickhouseQueriesInFlight: {
        name: 'horizon_clickhouse_queries_in_flight',
        help: 'x',
        type: 'gauge',
        values: [{ value: 2, labels: { op: 'queryWithParams' } }],
      },
      clickhouseQueryErrors: {
        name: 'horizon_clickhouse_query_errors_total',
        help: 'x',
        type: 'counter',
        values: [{ value: 3, labels: { op: 'queryWithParams' } }],
      },
      clickhouseQueryWaitDuration: {
        name: 'horizon_clickhouse_query_wait_seconds',
        help: 'x',
        type: 'histogram',
        values: [
          { value: 0.2, metricName: 'horizon_clickhouse_query_wait_seconds_sum', labels: { op: 'queryWithParams' } },
          { value: 4, metricName: 'horizon_clickhouse_query_wait_seconds_count', labels: { op: 'queryWithParams' } },
        ],
      },
      clickhouseQueryDuration: {
        name: 'horizon_clickhouse_query_duration_seconds',
        help: 'x',
        type: 'histogram',
        values: [
          { value: 1.0, metricName: 'horizon_clickhouse_query_duration_seconds_sum', labels: { op: 'queryWithParams' } },
          { value: 4, metricName: 'horizon_clickhouse_query_duration_seconds_count', labels: { op: 'queryWithParams' } },
        ],
      },
    },
    ...overrides,
  } as ClickHouseOpsSnapshot;
}

describe('ClickHouseOpsPanel', () => {
  it('does not fetch when ClickHouse is disabled', () => {
    const getClickHouseOpsSnapshot = vi.fn();
    render(
      <ClickHouseOpsPanel historicalEnabled={false} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />
    );
    expect(screen.getByText(/ClickHouse disabled/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeDisabled();
    expect(screen.queryByRole('table', { name: 'ClickHouse ops metrics' })).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByText(/Runtime limits/i)).not.toBeInTheDocument();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(getClickHouseOpsSnapshot).not.toHaveBeenCalled();
  });

  it('poll tick does not fetch when ClickHouse is disabled (refresh guard)', async () => {
    vi.useFakeTimers();
    try {
      const getClickHouseOpsSnapshot = vi.fn();
      render(<ClickHouseOpsPanel historicalEnabled={false} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
      await act(async () => {
        vi.advanceTimersByTime(60000);
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('clears loaded data/error when ClickHouse becomes disabled', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(makeSnapshot());
    const { rerender } = render(
      <ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />
    );

    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1));
    await screen.findByRole('table', { name: 'ClickHouse ops metrics' });

    rerender(<ClickHouseOpsPanel historicalEnabled={false} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    expect(screen.getByText(/ClickHouse disabled/i)).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: 'ClickHouse ops metrics' })).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('re-enabling ClickHouse triggers a fresh fetch', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(makeSnapshot());
    const { rerender } = render(
      <ClickHouseOpsPanel historicalEnabled={false} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />
    );
    expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(0);

    rerender(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1));

    rerender(<ClickHouseOpsPanel historicalEnabled={false} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1);

    rerender(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(2));
  });

  it('polling does not double-fire after toggle cycles', async () => {
    vi.useFakeTimers();
    try {
      const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(makeSnapshot());
      const { rerender } = render(
        <ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />
      );

      await act(async () => {
        await Promise.resolve();
      });
      await act(async () => {
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1); // initial

      await act(async () => {
        vi.advanceTimersByTime(30000);
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(2); // poll

      rerender(<ClickHouseOpsPanel historicalEnabled={false} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
      await act(async () => {
        vi.advanceTimersByTime(30000);
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(2); // no poll while disabled

      rerender(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
      await act(async () => {
        await Promise.resolve();
      });
      await act(async () => {
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(3); // re-enable auto-fetch

      await act(async () => {
        vi.advanceTimersByTime(30000);
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(4); // exactly one poll

      await act(async () => {
        vi.advanceTimersByTime(30000);
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(5); // still exactly one poll per interval
    } finally {
      vi.useRealTimers();
    }
  });

  it('changing getClickHouseOpsSnapshot identity does not trigger extra initial fetch or interval leaks', async () => {
    vi.useFakeTimers();
    try {
      const get1 = vi.fn().mockResolvedValue(makeSnapshot());
      const { rerender } = render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={get1} />);

      await act(async () => {
        await Promise.resolve();
      });
      await act(async () => {
        await Promise.resolve();
      });
      expect(get1).toHaveBeenCalledTimes(1);

      const get2 = vi.fn().mockResolvedValue(makeSnapshot());
      rerender(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={get2} />);

      await act(async () => {
        await Promise.resolve();
      });
      expect(get1).toHaveBeenCalledTimes(1);
      expect(get2).toHaveBeenCalledTimes(0);

      await act(async () => {
        vi.advanceTimersByTime(30000);
        await Promise.resolve();
      });
      expect(get1).toHaveBeenCalledTimes(1);
      expect(get2).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('fetches and renders metrics when enabled', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(makeSnapshot());
    render(
      <ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />
    );

    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1));
    expect(
      screen.getByText(
        'sampledAt=2026-02-09T00:00:00.000Z enabled=true connected=true'
      )
    ).toBeInTheDocument();
    expect(screen.getByText(/Runtime limits/i)).toBeInTheDocument();
    expect(screen.getByText('maxOpenConnections=25')).toBeInTheDocument();
    expect(screen.getByText('maxInFlightQueries=25')).toBeInTheDocument();
    expect(screen.getByText('maxInFlightStreamQueries=2')).toBeInTheDocument();
    expect(screen.getByText('queryTimeoutSec=30')).toBeInTheDocument();
    expect(screen.getByText('queueTimeoutSec=30')).toBeInTheDocument();
    expect(screen.getByText('maxRowsLimit=100000')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'ClickHouse ops metrics' })).toBeInTheDocument();
    expect(screen.getByText('queryWithParams')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument(); // inFlight
    expect(screen.getByText('1')).toBeInTheDocument(); // queue(query)
    expect(screen.getByText('3')).toBeInTheDocument(); // errors
    expect(screen.getByText('50ms')).toBeInTheDocument(); // wait(avg)
    expect(screen.getByText('250ms')).toBeInTheDocument(); // dur(avg)
  });

  it('renders null latency values as n/a (not NaN/null)', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(
      makeSnapshot({
        metrics: {
          ...makeSnapshot().metrics,
          clickhouseQueryWaitDuration: {
            name: 'horizon_clickhouse_query_wait_seconds',
            help: 'x',
            type: 'histogram',
            values: [],
          },
          clickhouseQueryDuration: {
            name: 'horizon_clickhouse_query_duration_seconds',
            help: 'x',
            type: 'histogram',
            values: [],
          },
        } as any,
      })
    );

    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1));

    const row = screen.getByText('queryWithParams').closest('tr');
    expect(row).not.toBeNull();
    const cells = Array.from(row!.querySelectorAll('td'));
    expect(cells.at(-2)).toHaveTextContent('n/a');
    expect(cells.at(-1)).toHaveTextContent('n/a');
    expect(row).not.toHaveTextContent(/NaN|null/i);
  });

  it('handles sparse metrics keys (some undefined) without crashing and uses defaults', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(
      makeSnapshot({
        metrics: {
          clickhouseQueriesInFlight: {
            name: 'horizon_clickhouse_queries_in_flight',
            help: 'x',
            type: 'gauge',
            values: [{ value: 4, labels: { op: 'onlyInflight' } }],
          },
          clickhouseQueryQueueDepth: undefined,
          clickhouseQueryErrors: undefined,
          clickhouseQueryWaitDuration: undefined,
          clickhouseQueryDuration: undefined,
        } as any,
      })
    );

    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1));

    const row = screen.getByText('onlyInflight').closest('tr');
    expect(row).not.toBeNull();
    const cells = Array.from(row!.querySelectorAll('td')).map((td) => td.textContent ?? '');
    expect(cells[0]).toBe('onlyInflight');
    expect(cells[1]).toBe('4'); // inFlight
    expect(cells[2]).toBe('0'); // queue(query)
    expect(cells[3]).toBe('0'); // queue(stream)
    expect(cells[4]).toBe('0'); // errors
    expect(cells[5]).toBe('n/a'); // wait(avg)
    expect(cells[6]).toBe('n/a'); // dur(avg)
  });

  it('renders defaults when an op appears only in errors', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(
      makeSnapshot({
        metrics: {
          clickhouseQueryQueueDepth: { name: 'a', help: 'a', type: 'gauge', values: [] },
          clickhouseQueriesInFlight: { name: 'b', help: 'b', type: 'gauge', values: [] },
          clickhouseQueryErrors: {
            name: 'c',
            help: 'c',
            type: 'counter',
            values: [{ value: 5, labels: { op: 'insertBatch' } }],
          },
          clickhouseQueryWaitDuration: { name: 'd', help: 'd', type: 'histogram', values: [] },
          clickhouseQueryDuration: { name: 'e', help: 'e', type: 'histogram', values: [] },
        } as any,
      })
    );

    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1));

    const row = screen.getByText('insertBatch').closest('tr');
    expect(row).not.toBeNull();
    const cells = Array.from(row!.querySelectorAll('td')).map((td) => td.textContent ?? '');
    expect(cells[0]).toBe('insertBatch');
    expect(cells[1]).toBe('0'); // inFlight
    expect(cells[2]).toBe('0'); // queue(query)
    expect(cells[3]).toBe('0'); // queue(stream)
    expect(cells[4]).toBe('5'); // errors
    expect(cells[5]).toBe('n/a'); // wait(avg)
    expect(cells[6]).toBe('n/a'); // dur(avg)
  });

  it('treats histogram sum>0 with count=0 as n/a (no NaN/Infinity)', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(
      makeSnapshot({
        metrics: {
          ...makeSnapshot().metrics,
          clickhouseQueryWaitDuration: {
            name: 'horizon_clickhouse_query_wait_seconds',
            help: 'x',
            type: 'histogram',
            values: [
              { value: 5.0, metricName: 'horizon_clickhouse_query_wait_seconds_sum', labels: { op: 'queryWithParams' } },
              { value: 0, metricName: 'horizon_clickhouse_query_wait_seconds_count', labels: { op: 'queryWithParams' } },
            ],
          },
        } as any,
      })
    );

    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1));

    const row = screen.getByText('queryWithParams').closest('tr');
    expect(row).not.toBeNull();
    const cells = Array.from(row!.querySelectorAll('td'));
    expect(cells.at(-2)).toHaveTextContent('n/a');
    expect(row).not.toHaveTextContent(/NaN|Infinity/i);
  });

  it('handles snapshots with missing metrics object', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(
      makeSnapshot({
        metrics: undefined as any,
      })
    );

    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/No ClickHouse ops metrics yet/i)).toBeInTheDocument();
    expect(screen.queryByRole('table', { name: 'ClickHouse ops metrics' })).not.toBeInTheDocument();
  });

  it('hides runtime limits when clickhouse config is null', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(
      makeSnapshot({
        clickhouse: {
          ...makeSnapshot().clickhouse,
          config: null as any,
        },
      })
    );

    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1));
    expect(screen.queryByText(/Runtime limits/i)).not.toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'ClickHouse ops metrics' })).toBeInTheDocument();
  });

  it('renders multiple ops as separate sorted rows', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(
      makeSnapshot({
        metrics: {
          clickhouseQueriesInFlight: {
            name: 'horizon_clickhouse_queries_in_flight',
            help: 'x',
            type: 'gauge',
            values: [
              { value: 2, labels: { op: 'betaOp' } },
              { value: 7, labels: { op: 'alphaOp' } },
            ],
          },
          clickhouseQueryQueueDepth: {
            name: 'horizon_clickhouse_query_queue_depth',
            help: 'x',
            type: 'gauge',
            values: [
              { value: 1, labels: { op: 'betaOp', queue: 'query' } },
              { value: 0, labels: { op: 'betaOp', queue: 'stream' } },
              { value: 0, labels: { op: 'alphaOp', queue: 'query' } },
              { value: 1, labels: { op: 'alphaOp', queue: 'stream' } },
            ],
          },
          clickhouseQueryErrors: { name: 'c', help: 'c', type: 'counter', values: [] },
          clickhouseQueryWaitDuration: { name: 'd', help: 'd', type: 'histogram', values: [] },
          clickhouseQueryDuration: { name: 'e', help: 'e', type: 'histogram', values: [] },
        } as any,
      })
    );

    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1));

    const table = screen.getByRole('table', { name: 'ClickHouse ops metrics' });
    expect(table).toBeInTheDocument();

    const rows = Array.from(table.querySelectorAll('tbody tr'));
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent('alphaOp');
    expect(rows[1]).toHaveTextContent('betaOp');
  });

  it('shows error when snapshot fetch fails (Error)', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockRejectedValue(new Error('boom'));
    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('boom');
  });

  it('clears error on successful subsequent refresh', async () => {
    const getClickHouseOpsSnapshot = vi
      .fn()
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce(makeSnapshot());

    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('boom');

    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.getByRole('table', { name: 'ClickHouse ops metrics' })).toBeInTheDocument()
    );
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('uses fallback error text when snapshot fetch rejects with non-Error', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockRejectedValue('nope');
    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    expect(await screen.findByRole('alert')).toHaveTextContent(/Failed to load ClickHouse ops snapshot/i);
  });

  it('renders empty state when ops metrics are missing/empty', async () => {
    const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(
      makeSnapshot({
        metrics: {
          clickhouseQueryQueueDepth: { name: 'a', help: 'a', type: 'gauge', values: [] },
          clickhouseQueriesInFlight: { name: 'b', help: 'b', type: 'gauge', values: [] },
          clickhouseQueryErrors: { name: 'c', help: 'c', type: 'counter', values: [] },
          clickhouseQueryWaitDuration: { name: 'd', help: 'd', type: 'histogram', values: [] },
          clickhouseQueryDuration: { name: 'e', help: 'e', type: 'histogram', values: [] },
        } as any,
      })
    );

    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    expect(await screen.findByText(/No ClickHouse ops metrics yet/i)).toBeInTheDocument();
  });

  it('discards stale responses from superseded refreshes (interval overlap)', async () => {
    vi.useFakeTimers();
    try {
      const d1 = deferred<ClickHouseOpsSnapshot>();
      const d2 = deferred<ClickHouseOpsSnapshot>();
      const getClickHouseOpsSnapshot = vi
        .fn()
        .mockImplementationOnce(() => d1.promise)
        .mockImplementationOnce(() => d2.promise);

      render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);

      await act(async () => {
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1);

      // Trigger the polling tick while the first request is still pending.
      await act(async () => {
        vi.advanceTimersByTime(30000);
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(2);

      d2.resolve(makeSnapshot({
        metrics: {
          ...makeSnapshot().metrics,
          clickhouseQueriesInFlight: {
            name: 'horizon_clickhouse_queries_in_flight',
            help: 'x',
            type: 'gauge',
            values: [{ value: 9, labels: { op: 'queryWithParams' } }],
          },
        } as any,
      }));

      await act(async () => {
        await Promise.resolve();
      });
      expect(screen.getByText('9')).toBeInTheDocument();

      d1.resolve(makeSnapshot({
        metrics: {
          ...makeSnapshot().metrics,
          clickhouseQueriesInFlight: {
            name: 'horizon_clickhouse_queries_in_flight',
            help: 'x',
            type: 'gauge',
            values: [{ value: 1, labels: { op: 'queryWithParams' } }],
          },
        } as any,
      }));

      await act(async () => {
        await Promise.resolve();
      });
      expect(screen.getByText('9')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('discards stale errors from superseded refreshes', async () => {
    vi.useFakeTimers();
    try {
      const d1 = deferred<ClickHouseOpsSnapshot>();
      const d2 = deferred<ClickHouseOpsSnapshot>();
      const getClickHouseOpsSnapshot = vi
        .fn()
        .mockImplementationOnce(() => d1.promise)
        .mockImplementationOnce(() => d2.promise);

      render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);

      await act(async () => {
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1);

      await act(async () => {
        vi.advanceTimersByTime(30000);
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(2);

      d2.resolve(makeSnapshot());
      await act(async () => {
        await Promise.resolve();
      });
      expect(screen.getByRole('table', { name: 'ClickHouse ops metrics' })).toBeInTheDocument();
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();

      d1.reject(new Error('late boom'));
      await act(async () => {
        await Promise.resolve();
      });
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
      expect(screen.getByRole('table', { name: 'ClickHouse ops metrics' })).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('skips polling when document is hidden', async () => {
    vi.useFakeTimers();
    const originalHidden = Object.getOwnPropertyDescriptor(document, 'hidden');
    try {
      const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(makeSnapshot());
      render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);

      await act(async () => {
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1);

      Object.defineProperty(document, 'hidden', { configurable: true, value: true });
      await act(async () => {
        vi.advanceTimersByTime(30000);
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1);

      Object.defineProperty(document, 'hidden', { configurable: true, value: false });
      await act(async () => {
        vi.advanceTimersByTime(29999);
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1);

      await act(async () => {
        vi.advanceTimersByTime(1);
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(2);
    } finally {
      if (originalHidden) {
        Object.defineProperty(document, 'hidden', originalHidden);
      } else {
        // Best-effort restore for environments without a native descriptor.
        Object.defineProperty(document, 'hidden', { configurable: true, value: false });
      }
      vi.useRealTimers();
    }
  });

  it('cleans up polling interval on unmount', async () => {
    vi.useFakeTimers();
    try {
      const getClickHouseOpsSnapshot = vi.fn().mockResolvedValue(makeSnapshot());
      const { unmount } = render(
        <ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />
      );

      await act(async () => {
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1);

      unmount();
      await act(async () => {
        vi.advanceTimersByTime(60000);
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('disables Refresh while loading and updates data on manual refresh', async () => {
    const d = deferred<ClickHouseOpsSnapshot>();
    const refreshed = makeSnapshot({
      metrics: {
        ...makeSnapshot().metrics,
        clickhouseQueriesInFlight: {
          name: 'horizon_clickhouse_queries_in_flight',
          help: 'x',
          type: 'gauge',
          values: [{ value: 99, labels: { op: 'queryWithParams' } }],
        },
      } as any,
    });
    const getClickHouseOpsSnapshot = vi
      .fn()
      .mockImplementationOnce(() => d.promise)
      .mockResolvedValueOnce(refreshed);
    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1));
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeDisabled();

    d.resolve(makeSnapshot());
    await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh' })).not.toBeDisabled());
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByText('99')).toBeInTheDocument());
  });

  it('ignores rapid double-click refresh while loading (no duplicate fetch)', async () => {
    const d = deferred<ClickHouseOpsSnapshot>();
    const refreshed = makeSnapshot({
      metrics: {
        ...makeSnapshot().metrics,
        clickhouseQueriesInFlight: {
          name: 'horizon_clickhouse_queries_in_flight',
          help: 'x',
          type: 'gauge',
          values: [{ value: 9, labels: { op: 'queryWithParams' } }],
        },
      } as any,
    });
    const getClickHouseOpsSnapshot = vi
      .fn()
      .mockResolvedValueOnce(makeSnapshot())
      .mockImplementationOnce(() => d.promise);

    render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
    await waitFor(() => expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1));

    const refreshBtn = screen.getByRole('button', { name: 'Refresh' });
    fireEvent.click(refreshBtn);
    await act(async () => {
      await Promise.resolve();
    });
    expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(2);
    expect(refreshBtn).toBeDisabled();

    fireEvent.click(refreshBtn);
    expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(2);

    d.resolve(refreshed);
    await waitFor(() => expect(screen.getByText('9')).toBeInTheDocument());
  });

  it('handles concurrent manual refresh and poll without stale overwrite', async () => {
    vi.useFakeTimers();
    try {
      const dManual = deferred<ClickHouseOpsSnapshot>();
      const dPoll = deferred<ClickHouseOpsSnapshot>();
      const getClickHouseOpsSnapshot = vi
        .fn()
        .mockResolvedValueOnce(makeSnapshot())
        .mockImplementationOnce(() => dManual.promise)
        .mockImplementationOnce(() => dPoll.promise);

      render(<ClickHouseOpsPanel historicalEnabled={true} getClickHouseOpsSnapshot={getClickHouseOpsSnapshot} />);
      await act(async () => {
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(1);
      await act(async () => {
        await Promise.resolve();
      });
      expect(screen.getByRole('table', { name: 'ClickHouse ops metrics' })).toBeInTheDocument();

      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
      await act(async () => {
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(2);

      await act(async () => {
        vi.advanceTimersByTime(30000);
        await Promise.resolve();
      });
      expect(getClickHouseOpsSnapshot).toHaveBeenCalledTimes(3);

      dPoll.resolve(
        makeSnapshot({
          metrics: {
            ...makeSnapshot().metrics,
            clickhouseQueriesInFlight: {
              name: 'horizon_clickhouse_queries_in_flight',
              help: 'x',
              type: 'gauge',
              values: [{ value: 9, labels: { op: 'queryWithParams' } }],
            },
          } as any,
        })
      );
      await act(async () => {
        await Promise.resolve();
      });
      expect(screen.getByText('9')).toBeInTheDocument();

      dManual.resolve(
        makeSnapshot({
          metrics: {
            ...makeSnapshot().metrics,
            clickhouseQueriesInFlight: {
              name: 'horizon_clickhouse_queries_in_flight',
              help: 'x',
              type: 'gauge',
              values: [{ value: 1, labels: { op: 'queryWithParams' } }],
            },
          } as any,
        })
      );
      await act(async () => {
        await Promise.resolve();
      });
      expect(screen.getByText('9')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});
