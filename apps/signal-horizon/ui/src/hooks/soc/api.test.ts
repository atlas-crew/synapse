import { describe, it, expect, vi, beforeEach } from 'vitest';
import { apiFetch } from '../../lib/api';
import {
  fetchFleetSessionDetail,
  fetchFleetSessions,
  fetchSessionDetail,
  fetchSessions,
} from './api';

vi.mock('../../lib/api', () => ({
  apiFetch: vi.fn(),
}));

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(apiFetch).mockResolvedValue({});
});

describe('SOC session API fetchers', () => {
  it('builds the fleet session list URL with fleet query params', async () => {
    await fetchFleetSessions({
      actorId: 'actor-a',
      suspicious: true,
      limit: 50,
      offset: 10,
    });

    expect(apiFetch).toHaveBeenCalledWith(
      '/synapse/sessions?actor_id=actor-a&suspicious=true&limit=50&offset=10',
    );
  });

  it('builds the fleet session detail URL', async () => {
    await fetchFleetSessionDetail('session-1');

    expect(apiFetch).toHaveBeenCalledWith('/synapse/sessions/session-1');
  });

  it('keeps the per-sensor session list URL available', async () => {
    await fetchSessions('sensor-1', { actorId: 'actor-a', limit: 25 });

    expect(apiFetch).toHaveBeenCalledWith('/synapse/sensor-1/sessions?actor_id=actor-a&limit=25');
  });

  it('keeps the per-sensor session detail URL available', async () => {
    await fetchSessionDetail('sensor-1', 'session-1');

    expect(apiFetch).toHaveBeenCalledWith('/synapse/sensor-1/sessions/session-1');
  });
});
