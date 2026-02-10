import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import type { CampaignTimelineEvent } from '../../hooks/useHunt';
import CampaignTimelinePage from '../hunting/CampaignTimelinePage';

const mockClearError = vi.fn();
const mockGetCampaignTimeline = vi.fn();

let mockIsLoading = false;
let mockError: string | null = null;

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

vi.mock('../../hooks/useHunt', async () => {
  const actual = await vi.importActual<typeof import('../../hooks/useHunt')>('../../hooks/useHunt');
  return {
    ...actual,
    useHunt: () => ({
      isLoading: mockIsLoading,
      error: mockError,
      clearError: mockClearError,
      getCampaignTimeline: mockGetCampaignTimeline,
    }),
  };
});

function LocationDisplay() {
  const loc = useLocation();
  return <div data-testid="location">{loc.pathname}</div>;
}

function GoToCampaignButton({ campaignId }: { campaignId: string }) {
  const navigate = useNavigate();
  return (
    <button type="button" onClick={() => navigate(`/hunting/campaign/${campaignId}`)}>
      GoTo
    </button>
  );
}

function renderRoute(initialEntry: string) {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route
          path="/hunting/campaign/:campaignId?"
          element={
            <>
              <CampaignTimelinePage />
              <LocationDisplay />
            </>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
}

function makeEvent(overrides: Partial<CampaignTimelineEvent> = {}): CampaignTimelineEvent {
  return {
    timestamp: overrides.timestamp ?? '2026-02-09T00:00:00.000Z',
    campaignId: overrides.campaignId ?? 'camp-1',
    eventType: overrides.eventType ?? 'created',
    name: overrides.name ?? 'Example Campaign',
    status: overrides.status ?? 'OPEN',
    severity: overrides.severity ?? 'HIGH',
    isCrossTenant: overrides.isCrossTenant ?? false,
    tenantsAffected: overrides.tenantsAffected ?? 1,
    confidence: overrides.confidence ?? 0.9,
  };
}

describe('CampaignTimelinePage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockIsLoading = false;
    mockError = null;
    mockGetCampaignTimeline.mockReset();
    document.title = '';
  });

  it('does not auto-run when no campaignId route param is present', async () => {
    renderRoute('/hunting/campaign');
    await waitFor(() => expect(mockGetCampaignTimeline).not.toHaveBeenCalled());
    expect(screen.getByText(/Run a query to load campaign history/i)).toBeInTheDocument();
    expect(screen.getByText('count=?')).toBeInTheDocument();
  });

  it('sets document title', () => {
    renderRoute('/hunting/campaign');
    expect(document.title).toContain('Campaign Timeline');
  });

  it('auto-runs when deep-linked with campaignId', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [makeEvent({ name: 'Deep Link Event' })],
      meta: { campaignId: 'camp-123', count: 1 },
    });

    renderRoute('/hunting/campaign/camp-123');

    await waitFor(() =>
      expect(mockGetCampaignTimeline).toHaveBeenCalledWith('camp-123', { startTime: undefined, endTime: undefined }),
    );
    expect(mockGetCampaignTimeline).toHaveBeenCalledTimes(1);

    expect(await screen.findByText('Deep Link Event')).toBeInTheDocument();
    expect(screen.getByLabelText('campaign_id')).toHaveValue('camp-123');
  });

  it('submits form and runs query for entered campaignId', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [makeEvent({ campaignId: 'camp-xyz', name: 'Form Event' })],
      meta: { campaignId: 'camp-xyz', count: 1 },
    });

    renderRoute('/hunting/campaign');

    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: 'camp-xyz' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run' }));

    await waitFor(() => expect(mockGetCampaignTimeline).toHaveBeenCalledWith('camp-xyz', { startTime: undefined, endTime: undefined }));
    expect(await screen.findByText('Form Event')).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('/hunting/campaign/camp-xyz');
  });

  it('shows error and allows dismiss', async () => {
    mockGetCampaignTimeline.mockRejectedValue(new Error('boom'));
    renderRoute('/hunting/campaign/camp-err');

    expect(await screen.findByText(/boom/i)).toBeInTheDocument();
    const callsBefore = mockClearError.mock.calls.length;

    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(mockClearError.mock.calls.length).toBe(callsBefore + 1);
    await waitFor(() => expect(screen.queryByText(/boom/i)).not.toBeInTheDocument());
  });

  it('URL-encodes campaignId on navigate (special chars)', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [],
      meta: { campaignId: 'x', count: 0 },
    });

    renderRoute('/hunting/campaign');

    const id = 'camp/../../admin?x=y';
    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: id } });
    fireEvent.click(screen.getByRole('button', { name: 'Run' }));

    await waitFor(() =>
      expect(mockGetCampaignTimeline).toHaveBeenCalledWith(id, { startTime: undefined, endTime: undefined }),
    );

    expect(screen.getByTestId('location')).toHaveTextContent(
      `/hunting/campaign/${encodeURIComponent(id)}`,
    );
  });

  it('ignores whitespace-only campaignId on submit (no API call, no navigate)', async () => {
    renderRoute('/hunting/campaign');

    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: '   ' } });

    const form = screen.getByRole('button', { name: 'Run' }).closest('form');
    expect(form).toBeTruthy();
    fireEvent.submit(form as HTMLFormElement);

    await waitFor(() => expect(mockGetCampaignTimeline).not.toHaveBeenCalled());
    expect(screen.getByTestId('location')).toHaveTextContent('/hunting/campaign');
  });

  it('renders potentially malicious strings as text (no HTML execution)', async () => {
    const payload = '<script>alert(1)</script>';
    mockGetCampaignTimeline.mockResolvedValue({
      events: [
        makeEvent({
          name: payload,
        }),
      ],
      meta: { campaignId: 'camp-xss', count: 1 },
    });

    renderRoute('/hunting/campaign/camp-xss');

    const hits = await screen.findAllByText(payload);
    expect(hits.length).toBeGreaterThan(0);
    expect(document.querySelector('script')).toBeNull();
  });

  it('disables Run/Refresh when campaignId empty (guard against empty submission)', async () => {
    renderRoute('/hunting/campaign');
    expect(screen.getByRole('button', { name: 'Run' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeDisabled();
  });

  it('does not run refresh handler when campaignId is empty (defense-in-depth)', async () => {
    renderRoute('/hunting/campaign');
    const refreshBtn = screen.getByRole('button', { name: 'Refresh' }) as HTMLButtonElement;
    expect(refreshBtn).toBeDisabled();
    refreshBtn.disabled = false;
    fireEvent.click(refreshBtn);
    await waitFor(() => expect(mockGetCampaignTimeline).not.toHaveBeenCalled());
  });

  it('does not run copy handler when campaignId is empty (defense-in-depth)', async () => {
    const original = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });

    renderRoute('/hunting/campaign');
    const copyBtn = screen.getByRole('button', { name: /Copy campaign id/i }) as HTMLButtonElement;
    expect(copyBtn).toBeDisabled();
    copyBtn.disabled = false;
    fireEvent.click(copyBtn);

    await waitFor(() => expect(writeText).not.toHaveBeenCalled());

    if (original) {
      Object.defineProperty(navigator, 'clipboard', original);
    }
  });

  it('disables Run/Refresh and shows loading placeholder when isLoading=true', async () => {
    mockIsLoading = true;
    renderRoute('/hunting/campaign/camp-load');

    expect(await screen.findByText(/Loading/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Run' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeDisabled();

    const refreshBtn = screen.getByRole('button', { name: 'Refresh' });
    const icon = refreshBtn.querySelector('svg');
    expect(icon?.getAttribute('class') ?? '').toMatch(/animate-spin/);
  });

  it('does not submit when isLoading=true even if campaignId is present', async () => {
    mockIsLoading = true;
    renderRoute('/hunting/campaign');

    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: 'camp-loading' } });

    const form = screen.getByRole('button', { name: 'Run' }).closest('form');
    fireEvent.submit(form as HTMLFormElement);

    await waitFor(() => expect(mockGetCampaignTimeline).not.toHaveBeenCalled());
    expect(screen.getByTestId('location')).toHaveTextContent('/hunting/campaign');
  });

  it('shows header placeholder and updates with trimmed campaignId', () => {
    renderRoute('/hunting/campaign');
    expect(screen.getByText('(enter campaign id)')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: ' camp-abc ' } });
    expect(screen.getByText('camp-abc')).toBeInTheDocument();

    const back = screen.getByRole('link', { name: /Back to hunting/i });
    expect(back).toHaveAttribute('href', '/hunting');
  });

  it('passes time window params to API (trimmed)', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [],
      meta: { campaignId: 'camp-time', count: 0 },
    });

    renderRoute('/hunting/campaign');

    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: 'camp-time' } });
    fireEvent.change(screen.getByLabelText(/startTime/i), { target: { value: ' 2026-02-09T00:00:00.000Z ' } });
    fireEvent.change(screen.getByLabelText(/endTime/i), { target: { value: '2026-02-09T12:00:00.000Z' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run' }));

    await waitFor(() =>
      expect(mockGetCampaignTimeline).toHaveBeenCalledWith('camp-time', {
        startTime: '2026-02-09T00:00:00.000Z',
        endTime: '2026-02-09T12:00:00.000Z',
      }),
    );
  });

  it('treats whitespace-only time params as undefined', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [],
      meta: { campaignId: 'camp-ws', count: 0 },
    });

    renderRoute('/hunting/campaign');

    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: 'camp-ws' } });
    fireEvent.change(screen.getByLabelText(/startTime/i), { target: { value: '   ' } });
    fireEvent.change(screen.getByLabelText(/endTime/i), { target: { value: ' ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run' }));

    await waitFor(() =>
      expect(mockGetCampaignTimeline).toHaveBeenCalledWith('camp-ws', { startTime: undefined, endTime: undefined }),
    );
  });

  it('shows empty results state when API returns no events', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [],
      meta: { campaignId: 'camp-empty', count: 0 },
    });
    renderRoute('/hunting/campaign/camp-empty');

    expect(await screen.findByText(/No events found/i)).toBeInTheDocument();
  });

  it('refresh button triggers a new query and clears stale error before running', async () => {
    mockGetCampaignTimeline.mockRejectedValueOnce(new Error('boom'));
    mockGetCampaignTimeline.mockResolvedValueOnce({
      events: [makeEvent({ name: 'After Refresh' })],
      meta: { campaignId: 'camp-refresh', count: 1 },
    });

    renderRoute('/hunting/campaign/camp-refresh');

    expect(await screen.findByText(/boom/i)).toBeInTheDocument();
    const callsBeforeRefresh = mockClearError.mock.calls.length;

    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));

    await waitFor(() =>
      expect(mockGetCampaignTimeline).toHaveBeenLastCalledWith('camp-refresh', { startTime: undefined, endTime: undefined }),
    );
    expect(mockClearError.mock.calls.length).toBeGreaterThan(callsBeforeRefresh);
    expect(await screen.findByText('After Refresh')).toBeInTheDocument();
    expect(screen.queryByText(/boom/i)).not.toBeInTheDocument();
  });

  it('refresh uses the latest time window params', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [],
      meta: { campaignId: 'camp-rt', count: 0 },
    });

    renderRoute('/hunting/campaign');

    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: 'camp-rt' } });
    fireEvent.change(screen.getByLabelText(/startTime/i), { target: { value: '2026-02-09T00:00:00.000Z' } });
    fireEvent.change(screen.getByLabelText(/endTime/i), { target: { value: '2026-02-09T01:00:00.000Z' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run' }));

    await waitFor(() =>
      expect(mockGetCampaignTimeline).toHaveBeenLastCalledWith('camp-rt', {
        startTime: '2026-02-09T00:00:00.000Z',
        endTime: '2026-02-09T01:00:00.000Z',
      }),
    );

    fireEvent.change(screen.getByLabelText(/startTime/i), { target: { value: '2026-02-09T02:00:00.000Z' } });
    fireEvent.change(screen.getByLabelText(/endTime/i), { target: { value: '2026-02-09T03:00:00.000Z' } });
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));

    await waitFor(() =>
      expect(mockGetCampaignTimeline).toHaveBeenLastCalledWith('camp-rt', {
        startTime: '2026-02-09T02:00:00.000Z',
        endTime: '2026-02-09T03:00:00.000Z',
      }),
    );
  });

  it('clears stale results on error', async () => {
    mockGetCampaignTimeline.mockResolvedValueOnce({
      events: [makeEvent({ name: 'Old Result' })],
      meta: { campaignId: 'camp-stale', count: 1 },
    });
    mockGetCampaignTimeline.mockRejectedValueOnce(new Error('new error'));

    renderRoute('/hunting/campaign/camp-stale');
    expect(await screen.findByText('Old Result')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));

    expect(await screen.findByText(/new error/i)).toBeInTheDocument();
    expect(screen.queryByText('Old Result')).not.toBeInTheDocument();
    expect(screen.getByText(/Run a query to load campaign history/i)).toBeInTheDocument();
  });

  it('syncs route campaignId changes into input and auto-runs', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [makeEvent({ name: 'A Event' })],
      meta: { campaignId: 'camp-a', count: 1 },
    });

    render(
      <MemoryRouter initialEntries={['/hunting/campaign/camp-a']}>
        <Routes>
          <Route
            path="/hunting/campaign/:campaignId"
            element={
              <>
                <CampaignTimelinePage />
                <GoToCampaignButton campaignId="camp-b" />
                <LocationDisplay />
              </>
            }
          />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText('A Event')).toBeInTheDocument();
    expect(screen.getByLabelText('campaign_id')).toHaveValue('camp-a');

    mockGetCampaignTimeline.mockResolvedValue({
      events: [makeEvent({ name: 'B Event' })],
      meta: { campaignId: 'camp-b', count: 1 },
    });

    fireEvent.click(screen.getByRole('button', { name: 'GoTo' }));

    await waitFor(() =>
      expect(mockGetCampaignTimeline).toHaveBeenLastCalledWith('camp-b', { startTime: undefined, endTime: undefined }),
    );
    expect(await screen.findByText('B Event')).toBeInTheDocument();
    expect(screen.getByLabelText('campaign_id')).toHaveValue('camp-b');
  });

  it('does not clobber user-typed campaignId when route param is stable', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [],
      meta: { campaignId: 'camp-typed', count: 0 },
    });

    renderRoute('/hunting/campaign/camp-typed');

    await waitFor(() =>
      expect(mockGetCampaignTimeline).toHaveBeenCalledWith('camp-typed', { startTime: undefined, endTime: undefined }),
    );

    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: 'user-typed' } });
    expect(screen.getByLabelText('campaign_id')).toHaveValue('user-typed');
  });

  it('does not auto-run again when time inputs change on a deep link', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [],
      meta: { campaignId: 'camp-timechange', count: 0 },
    });

    renderRoute('/hunting/campaign/camp-timechange');

    await waitFor(() => expect(mockGetCampaignTimeline).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByLabelText(/startTime/i), { target: { value: '2026-02-09T00:00:00.000Z' } });
    await waitFor(() => expect(mockGetCampaignTimeline).toHaveBeenCalledTimes(1));
  });

  it('does not show stale results when earlier request resolves after a later request', async () => {
    const d1 = deferred<{ events: CampaignTimelineEvent[]; meta: { campaignId: string; count: number } }>();
    const d2 = deferred<{ events: CampaignTimelineEvent[]; meta: { campaignId: string; count: number } }>();

    mockGetCampaignTimeline
      .mockReturnValueOnce(d1.promise)
      .mockReturnValueOnce(d2.promise);

    renderRoute('/hunting/campaign');

    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: 'camp-a' } });
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));

    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: 'camp-b' } });
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));

    d2.resolve({
      events: [makeEvent({ name: 'Second Result', campaignId: 'camp-b' })],
      meta: { campaignId: 'camp-b', count: 1 },
    });

    expect(await screen.findByText('Second Result')).toBeInTheDocument();

    d1.resolve({
      events: [makeEvent({ name: 'First Result', campaignId: 'camp-a' })],
      meta: { campaignId: 'camp-a', count: 1 },
    });

    await waitFor(() => expect(screen.queryByText('First Result')).not.toBeInTheDocument());
    expect(screen.getByText('Second Result')).toBeInTheDocument();
  });

  it('renders table columns and formats timestamp/confidence', async () => {
    const ts1 = '2026-02-09T00:00:00.000Z';
    const ts2 = '2026-02-09T00:00:01.000Z';
    mockGetCampaignTimeline.mockResolvedValue({
      events: [
        makeEvent({
          timestamp: ts1,
          eventType: 'created',
          name: 'E1',
          status: 'OPEN',
          severity: 'LOW',
          tenantsAffected: 2,
          confidence: 0,
        }),
        makeEvent({
          timestamp: ts2,
          eventType: 'updated',
          name: 'E2',
          status: 'CLOSED',
          severity: 'HIGH',
          tenantsAffected: 7,
          confidence: 0.999,
        }),
      ],
      meta: { campaignId: 'camp-table', count: 2 },
    });

    renderRoute('/hunting/campaign/camp-table');

    expect(await screen.findByText('E1')).toBeInTheDocument();
    expect(screen.getByText('E2')).toBeInTheDocument();
    expect(screen.getByText('count=2')).toBeInTheDocument();

    expect(screen.getByText(new Date(ts1).toISOString())).toBeInTheDocument();
    expect(screen.getByText(new Date(ts2).toISOString())).toBeInTheDocument();
    expect(screen.getByText('0.00')).toBeInTheDocument();
    expect(screen.getByText('1.00')).toBeInTheDocument();

    expect(screen.getByText('created')).toBeInTheDocument();
    expect(screen.getByText('updated')).toBeInTheDocument();
    expect(screen.getByText('OPEN')).toBeInTheDocument();
    expect(screen.getByText('CLOSED')).toBeInTheDocument();
    expect(screen.getByText('LOW')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
    expect(screen.getByText('7')).toBeInTheDocument();
  });

  it('formats confidence boundaries 0 and 1', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [
        makeEvent({ name: 'C0', confidence: 0 }),
        makeEvent({ name: 'C1', confidence: 1 }),
      ],
      meta: { campaignId: 'camp-bound', count: 2 },
    });
    renderRoute('/hunting/campaign/camp-bound');

    expect(await screen.findByText('C0')).toBeInTheDocument();
    expect(screen.getByText('C1')).toBeInTheDocument();
    expect(screen.getByText('0.00')).toBeInTheDocument();
    expect(screen.getByText('1.00')).toBeInTheDocument();
  });

  it('rounds small confidence decimals to two places', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [makeEvent({ name: 'Round Test', confidence: 0.005 })],
      meta: { campaignId: 'camp-round', count: 1 },
    });
    renderRoute('/hunting/campaign/camp-round');

    expect(await screen.findByText('Round Test')).toBeInTheDocument();
    expect(screen.getByText('0.01')).toBeInTheDocument();
  });

  it('shows fallback error message when rejection is non-Error', async () => {
    mockGetCampaignTimeline.mockRejectedValue('nope');
    renderRoute('/hunting/campaign/camp-nonerr');

    expect(await screen.findByText(/Campaign timeline query failed/i)).toBeInTheDocument();
  });

  it('does not crash when confidence is NaN and renders n/a', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      // Cast to force runtime-like bad value; the component should not crash.
      events: [makeEvent({ confidence: Number.NaN as unknown as number, name: 'Bad Confidence' })],
      meta: { campaignId: 'camp-nan', count: 1 },
    });
    renderRoute('/hunting/campaign/camp-nan');

    expect(await screen.findByText('Bad Confidence')).toBeInTheDocument();
    expect(screen.getByText('n/a')).toBeInTheDocument();
  });

  it('does not crash on invalid timestamp and renders Invalid Date', async () => {
    mockGetCampaignTimeline.mockResolvedValue({
      events: [makeEvent({ timestamp: 'not-a-date', name: 'Bad Timestamp' })],
      meta: { campaignId: 'camp-badts', count: 1 },
    });
    renderRoute('/hunting/campaign/camp-badts');

    expect(await screen.findByText('Bad Timestamp')).toBeInTheDocument();
    expect(screen.getByText('Invalid Date')).toBeInTheDocument();
  });

  it.each([
    ['Infinity', Infinity],
    ['-Infinity', -Infinity],
    ['negative', -0.5],
    ['just-below', -0.001],
    ['too-high', 1.5],
    ['just-above', 1.001],
    ['null', null],
    ['undefined', undefined],
    ['string', '0.5'],
  ])('renders n/a for non-finite confidence (%s)', async (_label, value) => {
    const ev = makeEvent({ confidence: 0.9, name: `Bad Confidence ${String(value)}` });
    (ev as unknown as { confidence: unknown }).confidence = value;

    mockGetCampaignTimeline.mockResolvedValue({
      events: [ev],
      meta: { campaignId: 'camp-badconf', count: 1 },
    });

    renderRoute('/hunting/campaign/camp-badconf');

    expect(await screen.findByText(`Bad Confidence ${String(value)}`)).toBeInTheDocument();
    expect(screen.getByText('n/a')).toBeInTheDocument();
  });

  it('does not issue duplicate API calls on rapid double-click Run', async () => {
    const d = deferred<{ events: CampaignTimelineEvent[]; meta: { campaignId: string; count: number } }>();
    mockGetCampaignTimeline
      .mockReturnValueOnce(d.promise)
      .mockResolvedValueOnce({
        events: [makeEvent({ name: 'Second Submit', campaignId: 'camp-next' })],
        meta: { campaignId: 'camp-next', count: 1 },
      });

    renderRoute('/hunting/campaign');
    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: 'camp-dbl' } });

    const runBtn = screen.getByRole('button', { name: 'Run' });
    fireEvent.click(runBtn);
    fireEvent.click(runBtn);

    await waitFor(() =>
      expect(mockGetCampaignTimeline).toHaveBeenCalledTimes(1),
    );

    d.resolve({
      events: [makeEvent({ name: 'After Double Click', campaignId: 'camp-dbl' })],
      meta: { campaignId: 'camp-dbl', count: 1 },
    });

    expect(await screen.findByText('After Double Click')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: 'camp-next' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run' }));

    await waitFor(() => expect(mockGetCampaignTimeline).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('Second Submit')).toBeInTheDocument();
  });

  it('disables Copy when campaignId is empty', () => {
    renderRoute('/hunting/campaign');
    expect(screen.getByRole('button', { name: /Copy campaign id/i })).toBeDisabled();
  });

  it('silently ignores clipboard write failures', async () => {
    const original = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
    const writeText = vi.fn().mockRejectedValue(new Error('clipboard denied'));
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });

    mockGetCampaignTimeline.mockResolvedValue({
      events: [],
      meta: { campaignId: 'camp-copy', count: 0 },
    });

    renderRoute('/hunting/campaign');
    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: ' camp-copy ' } });
    fireEvent.click(screen.getByRole('button', { name: /Copy campaign id/i }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith('camp-copy'));
    expect(screen.getByText(/Campaign Timeline/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Dismiss' })).not.toBeInTheDocument();

    if (original) {
      Object.defineProperty(navigator, 'clipboard', original);
    }
  });

  it('copies trimmed campaignId on success', async () => {
    const original = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });

    renderRoute('/hunting/campaign');
    fireEvent.change(screen.getByLabelText('campaign_id'), { target: { value: ' camp-ok ' } });
    fireEvent.click(screen.getByRole('button', { name: /Copy campaign id/i }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith('camp-ok'));
    expect(screen.queryByRole('button', { name: 'Dismiss' })).not.toBeInTheDocument();

    if (original) {
      Object.defineProperty(navigator, 'clipboard', original);
    }
  });

  it('renders hook-level error when provided by useHunt', async () => {
    mockError = 'hook error';
    renderRoute('/hunting/campaign/camp-hookerr');

    expect(await screen.findByText(/hook error/i)).toBeInTheDocument();
  });
});
