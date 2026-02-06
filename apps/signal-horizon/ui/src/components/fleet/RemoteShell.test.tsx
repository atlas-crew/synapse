/**
 * RemoteShell Component Test Suite
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';

vi.mock('@xterm/xterm', () => ({
  Terminal: vi.fn().mockImplementation(() => ({
    open: vi.fn(),
    write: vi.fn(),
    writeln: vi.fn(),
    onData: vi.fn().mockReturnValue({ dispose: vi.fn() }),
    dispose: vi.fn(),
    loadAddon: vi.fn(),
    focus: vi.fn(),
  })),
}));

vi.mock('@xterm/addon-fit', () => ({
  FitAddon: vi.fn().mockImplementation(() => ({
    fit: vi.fn(),
    proposeDimensions: vi.fn().mockReturnValue({ cols: 80, rows: 24 }),
    dispose: vi.fn(),
  })),
}));

vi.mock('@xterm/addon-web-links', () => ({
  WebLinksAddon: vi.fn().mockImplementation(() => ({
    dispose: vi.fn(),
  })),
}));

vi.mock('../../hooks/fleet/useRemoteShell', () => ({
  useRemoteShell: vi.fn(),
}));

import { RemoteShell } from './RemoteShell';
import { useRemoteShell } from '../../hooks/fleet/useRemoteShell';

const mockUseRemoteShell = vi.mocked(useRemoteShell);

const buildHookReturn = (overrides = {}) => ({
  status: 'disconnected' as const,
  connect: vi.fn(),
  disconnect: vi.fn(),
  resize: vi.fn(),
  session: null,
  isReconnecting: false,
  reconnectAttempt: 0,
  maxReconnectAttempts: 5,
  error: null,
  terminal: null,
  fitAddon: null,
  ...overrides,
});

describe('RemoteShell', () => {
  beforeEach(() => {
    mockUseRemoteShell.mockReturnValue(buildHookReturn());
  });

  it('shows connect button when disconnected', () => {
    const connect = vi.fn();
    mockUseRemoteShell.mockReturnValue(buildHookReturn({ connect }));

    render(<RemoteShell sensorId="sensor-1" sensorName="Alpha" />);

    const button = screen.getByRole('button', { name: 'Connect' });
    fireEvent.click(button);

    expect(connect).toHaveBeenCalled();
  });

  it('shows disconnect button when connected', () => {
    const disconnect = vi.fn();
    mockUseRemoteShell.mockReturnValue(buildHookReturn({ status: 'connected', disconnect }));

    render(<RemoteShell sensorId="sensor-1" sensorName="Alpha" />);

    const button = screen.getByRole('button', { name: 'Disconnect' });
    fireEvent.click(button);

    expect(disconnect).toHaveBeenCalled();
  });

  it('renders reconnecting status text and overlay', () => {
    mockUseRemoteShell.mockReturnValue(
      buildHookReturn({
        status: 'connecting',
        isReconnecting: true,
        reconnectAttempt: 2,
        maxReconnectAttempts: 5,
      })
    );

    render(<RemoteShell sensorId="sensor-1" sensorName="Alpha" />);

    expect(screen.getByText('Reconnecting (2/5)...')).toBeInTheDocument();
    expect(
      screen.getByText('Reconnecting to Alpha... (attempt 2/5)')
    ).toBeInTheDocument();
  });

  it('renders error message and retry action', () => {
    const connect = vi.fn();
    mockUseRemoteShell.mockReturnValue(
      buildHookReturn({ status: 'error', error: 'Failed to connect', connect })
    );

    render(<RemoteShell sensorId="sensor-1" sensorName="Alpha" />);

    expect(screen.getByText('Failed to connect')).toBeInTheDocument();

    const retryButton = screen.getByRole('button', { name: 'Retry' });
    fireEvent.click(retryButton);

    expect(connect).toHaveBeenCalled();
  });
});
