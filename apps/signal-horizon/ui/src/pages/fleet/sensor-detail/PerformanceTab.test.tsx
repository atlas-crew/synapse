import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { PerformanceTab } from './PerformanceTab';

vi.mock('@/ui', () => ({
  MetricCard: ({ label, value }: any) => (
    <div>
      <span>{label}</span>
      <span>{String(value)}</span>
    </div>
  ),
  Panel: ({ children }: any) => <div>{children}</div>,
}));

vi.mock('./shared', () => ({
  InfoRow: ({ label, value }: any) => (
    <div>
      <span>{label}</span>
      <span>{String(value)}</span>
    </div>
  ),
  formatBytes: (bytes: number) => `${bytes} B`,
}));

describe('PerformanceTab', () => {
  it('renders stable no-data states instead of crashing on missing telemetry', () => {
    render(
      <PerformanceTab
        data={{
          current: {
            cpu: null,
            memory: null,
            disk: null,
            loadAverage: [null, null, null],
            latencyAvg: null,
            latencyP99: null,
          },
          history: [],
          diskIO: {
            readBytesPerSec: null,
            writeBytesPerSec: null,
            iops: null,
            ioWait: null,
          },
          benchmarks: [],
        }}
      />
    );

    expect(screen.getByText('No historical performance data yet.')).toBeInTheDocument();
    expect(screen.getByText('Latency')).toBeInTheDocument();
    expect(screen.getByText('Latency P99')).toBeInTheDocument();
    expect(screen.getAllByText('—')).toHaveLength(10);
    expect(screen.getByText('No benchmark samples available yet.')).toBeInTheDocument();
  });
});
