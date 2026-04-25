import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { OverviewTab } from './OverviewTab';

vi.mock('@/ui', () => ({
  MetricCard: ({ label, value }: any) => (
    <div>
      <span>{label}</span>
      <span>{String(value)}</span>
    </div>
  ),
  Panel: ({ children }: any) => <div>{children}</div>,
  Stack: ({ children }: any) => <div>{children}</div>,
}));

vi.mock('../../../components/ui/Toast', () => ({
  useToast: () => ({ toast: { success: vi.fn(), error: vi.fn() } }),
}));

vi.mock('../../../components/ui/ConfirmDialog', () => ({
  ConfirmDialog: () => null,
}));

const apiFetchMock = vi.fn();
vi.mock('../../../lib/api', () => ({
  apiFetch: (...args: any[]) => apiFetchMock(...args),
}));

describe('OverviewTab', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    apiFetchMock.mockResolvedValue({ signals: [] });
  });

  it('renders resource cards from live performance data when sensor metadata is empty', async () => {
    render(
      <OverviewTab
        sensor={{
          id: 'sensor-1',
          name: 'Sensor 1',
          metadata: {},
          version: '1.0.0',
          region: 'us-east-1',
          connectionState: 'CONNECTED',
          lastHeartbeat: null,
          uptime: 3600,
        }}
        systemInfo={{ uptime: 3600 }}
        performance={{
          current: {
            cpu: 37.4,
            memory: 61.2,
            disk: 82,
            rps: 1420,
            latencyAvg: 11,
            latencyP99: 47,
          },
        }}
        diagnostics={null}
        onRestartSensor={vi.fn()}
      />
    );

    await waitFor(() => {
      expect(apiFetchMock).toHaveBeenCalledWith('/fleet/sensors/sensor-1/signals?limit=25', {
        method: 'GET',
      });
    });

    expect(screen.getByText('CPU')).toBeInTheDocument();
    expect(screen.getByText('Latency')).toBeInTheDocument();
    expect(screen.getByText('Latency P99')).toBeInTheDocument();
    expect(screen.getByText('37.4%')).toBeInTheDocument();
    expect(screen.getByText('61.2%')).toBeInTheDocument();
    expect(screen.getByText('82%')).toBeInTheDocument();
    expect(screen.getByText('1,420')).toBeInTheDocument();
    expect(screen.getByText('11ms')).toBeInTheDocument();
    expect(screen.getByText('47ms')).toBeInTheDocument();
  });

  it('renders zero-value metrics without collapsing them into blank cards', async () => {
    render(
      <OverviewTab
        sensor={{
          id: 'sensor-1',
          name: 'Sensor 1',
          metadata: {},
          version: '1.0.0',
          region: 'us-east-1',
          connectionState: 'CONNECTED',
          lastHeartbeat: null,
          uptime: 3600,
        }}
        systemInfo={{ uptime: 3600 }}
        performance={{
          current: {
            cpu: 0,
            memory: 0,
            disk: 0,
            rps: 0,
            latencyAvg: 0,
          },
        }}
        diagnostics={null}
        onRestartSensor={vi.fn()}
      />
    );

    await waitFor(() => {
      expect(apiFetchMock).toHaveBeenCalledWith('/fleet/sensors/sensor-1/signals?limit=25', {
        method: 'GET',
      });
    });

    expect(screen.getAllByText('0.0%')).toHaveLength(2);
    expect(screen.getByText('0%')).toBeInTheDocument();
    expect(screen.getByText('0ms')).toBeInTheDocument();
    expect(screen.getByText('0')).toBeInTheDocument();
    expect(screen.getByText('—')).toBeInTheDocument();
  });
});
