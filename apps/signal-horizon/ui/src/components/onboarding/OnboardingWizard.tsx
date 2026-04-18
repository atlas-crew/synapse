/**
 * Onboarding Wizard — guided three-step sensor enrollment.
 *
 * Step 1: Configure & generate a registration token.
 * Step 2: Show the exact bootstrap commands + live-poll `/onboarding/candidates`
 *         so the wizard surfaces "we see your sensor" feedback as it happens.
 * Step 3: Approve the pending sensor once the WebSocket handshake completes.
 *
 * The wizard wraps existing APIs — it does not own any new client state
 * beyond the step counter and the token captured in step 1. All sensor
 * data is live-queried from the server so the experience survives refresh.
 */

import React, { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, Copy, Rocket, Server, ShieldCheck } from 'lucide-react';
import {
  Alert,
  Box,
  Button,
  Drawer,
  Input,
  Panel,
  Select,
  Spinner,
  Stack,
  Text,
  colors,
  spacing,
} from '@/ui';
import { apiFetch } from '../../lib/api';

interface OnboardingWizardProps {
  open: boolean;
  onClose: () => void;
}

type WizardStep = 1 | 2 | 3;

interface GeneratedToken {
  token: string;
  id: string;
  name: string;
}

interface CandidateSummary {
  id: string;
  hostname: string | null;
  os: string | null;
  ipAddress: string | null;
  fingerprint: string;
  announceCount: number;
  lastSeenAt: string;
  status: 'announced' | 'claimed';
}

interface PendingSensorSummary {
  id: string;
  name: string;
  hostname: string;
  os: string | null;
  registrationToken: string | null;
}

const STEP_LABELS: Array<{ step: WizardStep; label: string }> = [
  { step: 1, label: 'Create token' },
  { step: 2, label: 'Install on sensor' },
  { step: 3, label: 'Approve sensor' },
];

function buildAnnounceUrl(): string {
  if (typeof window === 'undefined') return '/api/v1/sensors/announce';
  return `${window.location.origin}/api/v1/sensors/announce`;
}

function buildWebSocketUrl(): string {
  if (typeof window === 'undefined') return '/sensor-gateway';
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}/sensor-gateway`;
}

function buildSampleCurl(token: string): string {
  return [
    `curl -X POST ${buildAnnounceUrl()} \\`,
    `  -H "Authorization: Bearer ${token}" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -d '{`,
    `    "fingerprint": "$(cat /etc/machine-id)",`,
    `    "hostname": "$(hostname)",`,
    `    "os": "$(uname -s)",`,
    `    "version": "1.0.0"`,
    `  }'`,
  ].join('\n');
}

function CopyBlock({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <Stack gap="xs">
      <Stack direction="row" justify="space-between" align="center">
        <Text variant="caption" muted>
          {label}
        </Text>
        <Button variant="ghost" size="sm" onClick={copy}>
          <Stack as="span" inline direction="row" align="center" gap="xs">
            {copied ? <Check size={14} /> : <Copy size={14} />}
            {copied ? 'Copied' : 'Copy'}
          </Stack>
        </Button>
      </Stack>
      <Panel tone="default" padding="md">
        <Box
          as="pre"
          style={{
            margin: 0,
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
            fontSize: 12,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            color: colors.text,
          }}
        >
          {text}
        </Box>
      </Panel>
    </Stack>
  );
}

function StepIndicator({ current }: { current: WizardStep }) {
  return (
    <Stack direction="row" gap="sm" align="center">
      {STEP_LABELS.map(({ step, label }, idx) => {
        const state = step === current ? 'current' : step < current ? 'done' : 'upcoming';
        const bg =
          state === 'current'
            ? colors.blue
            : state === 'done'
              ? colors.green
              : colors.border.subtle;
        const labelColor = state === 'upcoming' ? colors.textMuted : colors.text;
        return (
          <React.Fragment key={step}>
            <Stack direction="row" align="center" gap="xs">
              <Box
                style={{
                  width: 24,
                  height: 24,
                  background: bg,
                  color: state === 'upcoming' ? colors.textMuted : colors.white,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 12,
                  fontWeight: 500,
                }}
              >
                {state === 'done' ? <Check size={14} /> : step}
              </Box>
              <Text variant="caption" style={{ color: labelColor }}>
                {label}
              </Text>
            </Stack>
            {idx < STEP_LABELS.length - 1 && (
              <Box style={{ flex: 1, height: 1, background: colors.border.subtle }} />
            )}
          </React.Fragment>
        );
      })}
    </Stack>
  );
}

function Step1CreateToken({
  onCreated,
}: {
  onCreated: (t: GeneratedToken) => void;
}): React.ReactElement {
  const [name, setName] = useState('');
  const [maxUses, setMaxUses] = useState(1);
  const [expiresIn, setExpiresIn] = useState<string>('7');
  const [region, setRegion] = useState('');

  const mutation = useMutation({
    mutationFn: async () =>
      apiFetch('/onboarding/tokens', {
        method: 'POST',
        body: {
          name,
          maxUses,
          expiresIn: expiresIn ? parseInt(expiresIn, 10) : undefined,
          region: region || undefined,
        },
      }),
    onSuccess: (data: any) => {
      onCreated({ token: data.token, id: data.id, name: data.name });
    },
  });

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!name.trim()) return;
        mutation.mutate();
      }}
    >
      <Stack gap="md">
        <Text variant="body" muted>
          The wizard will generate a registration token, then watch for your
          sensor to announce itself. Give the token a name you&apos;ll recognize
          later — you can revoke it at any time from the Tokens tab.
        </Text>

        <Input
          label="Token name"
          placeholder="e.g. us-east-edge-01"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />

        <Stack direction="row" gap="md">
          <Box style={{ flex: 1 }}>
            <Input
              label="Max sensor enrollments"
              type="number"
              min={1}
              max={1000}
              value={maxUses}
              onChange={(e) => setMaxUses(parseInt(e.target.value, 10) || 1)}
            />
          </Box>
          <Box style={{ flex: 1 }}>
            <Select
              label="Expires in"
              value={expiresIn}
              onChange={(e) => setExpiresIn(e.target.value)}
              options={[
                { value: '1', label: '1 day' },
                { value: '7', label: '7 days' },
                { value: '30', label: '30 days' },
                { value: '', label: 'Never' },
              ]}
            />
          </Box>
        </Stack>

        <Input
          label="Region (optional)"
          placeholder="us-east-1"
          value={region}
          onChange={(e) => setRegion(e.target.value)}
        />

        {mutation.isError && (
          <Alert status="error">Failed to generate token. Please try again.</Alert>
        )}

        <Stack direction="row" justify="flex-end">
          <Button type="submit" variant="primary" disabled={mutation.isPending || !name.trim()}>
            <Stack as="span" inline direction="row" align="center" gap="sm">
              <Rocket size={14} />
              {mutation.isPending ? 'Generating…' : 'Generate token'}
            </Stack>
          </Button>
        </Stack>
      </Stack>
    </form>
  );
}

function Step2Install({
  token,
  onCandidateDetected,
}: {
  token: GeneratedToken;
  onCandidateDetected: () => void;
}): React.ReactElement {
  const curlSample = useMemo(() => buildSampleCurl(token.token), [token.token]);
  const wsUrl = useMemo(() => buildWebSocketUrl(), []);

  const { data } = useQuery<{ items: CandidateSummary[] }>({
    queryKey: ['onboarding-candidates', token.id],
    queryFn: async () =>
      apiFetch(`/onboarding/candidates?tokenId=${encodeURIComponent(token.id)}`),
    refetchInterval: 3000,
  });
  const candidates = data?.items ?? [];
  const hasCandidate = candidates.length > 0;

  return (
    <Stack gap="lg">
      <Alert status="warning" title="Save this token now">
        <Text variant="body">It will not be shown again after you leave this step.</Text>
      </Alert>

      <CopyBlock label="Registration token" text={token.token} />
      <CopyBlock label="WebSocket URL" text={wsUrl} />
      <CopyBlock label="Test from sensor host" text={curlSample} />

      <Panel tone={hasCandidate ? 'success' : 'default'} padding="md">
        <Stack direction="row" align="center" gap="md">
          {hasCandidate ? (
            <ShieldCheck size={24} style={{ color: colors.green }} />
          ) : (
            <Spinner size={24} />
          )}
          <Box style={{ flex: 1 }}>
            <Text variant="body" weight="medium">
              {hasCandidate
                ? `${candidates.length} sensor${candidates.length === 1 ? '' : 's'} reached the announce endpoint`
                : 'Waiting for your sensor to announce itself…'}
            </Text>
            <Text variant="caption" muted>
              {hasCandidate
                ? 'Once the sensor completes its WebSocket handshake it will appear in step 3.'
                : 'Run the sample command above on the sensor host, or configure your sensor to call the announce endpoint at boot.'}
            </Text>
          </Box>
        </Stack>

        {hasCandidate && (
          <Box style={{ marginTop: spacing.md }}>
            <Stack gap="sm">
              {candidates.map((c) => (
                <Panel key={c.id} tone="default" padding="sm">
                  <Stack direction="row" align="center" gap="sm">
                    <Server size={16} style={{ color: colors.blue }} />
                    <Stack gap="xs">
                      <Text variant="body" weight="medium">
                        {c.hostname ?? 'unknown host'}
                        {c.os ? ` · ${c.os}` : ''}
                      </Text>
                      <Text variant="caption" muted>
                        fingerprint: {c.fingerprint.slice(0, 16)}… · announces:{' '}
                        {c.announceCount}
                      </Text>
                    </Stack>
                  </Stack>
                </Panel>
              ))}
            </Stack>
          </Box>
        )}
      </Panel>

      <Stack direction="row" justify="flex-end">
        <Button variant="primary" disabled={!hasCandidate} onClick={onCandidateDetected}>
          Continue to approval
        </Button>
      </Stack>
    </Stack>
  );
}

function Step3Approve({
  token,
  onDone,
}: {
  token: GeneratedToken;
  onDone: () => void;
}): React.ReactElement {
  const queryClient = useQueryClient();

  const { data } = useQuery<{ sensors: PendingSensorSummary[] }>({
    queryKey: ['pending-sensors', token.id],
    queryFn: async () => apiFetch('/onboarding/pending'),
    refetchInterval: 3000,
  });

  const matching = (data?.sensors ?? []).filter((s) => s.registrationToken === token.name);

  const approve = useMutation({
    mutationFn: async (sensorId: string) =>
      apiFetch(`/onboarding/pending/${sensorId}`, {
        method: 'POST',
        body: { action: 'approve' },
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['pending-sensors'] });
    },
  });

  return (
    <Stack gap="md">
      <Text variant="body" muted>
        Once your sensor completes the WebSocket handshake it will appear below
        for final approval. Verify the hostname and OS match the machine you
        expect before approving — the fingerprint ties this row to the
        candidate you saw in step 2.
      </Text>

      {matching.length === 0 ? (
        <Panel tone="default" padding="md">
          <Stack direction="row" align="center" gap="md">
            <Spinner size={24} />
            <Text variant="body">Waiting for the sensor to complete WebSocket handshake…</Text>
          </Stack>
        </Panel>
      ) : (
        <Stack gap="sm">
          {matching.map((s) => (
            <Panel key={s.id} tone="default" padding="md">
              <Stack direction="row" justify="space-between" align="center">
                <Stack gap="xs">
                  <Text variant="body" weight="medium">
                    {s.name || s.hostname}
                  </Text>
                  <Text variant="caption" muted>
                    {s.hostname}
                    {s.os ? ` · ${s.os}` : ''}
                  </Text>
                </Stack>
                <Button
                  variant="primary"
                  onClick={() => approve.mutate(s.id)}
                  disabled={approve.isPending}
                >
                  Approve
                </Button>
              </Stack>
            </Panel>
          ))}
        </Stack>
      )}

      <Stack direction="row" justify="flex-end">
        <Button variant="secondary" onClick={onDone}>
          Finish
        </Button>
      </Stack>
    </Stack>
  );
}

export function OnboardingWizard({ open, onClose }: OnboardingWizardProps): React.ReactElement {
  const [step, setStep] = useState<WizardStep>(1);
  const [token, setToken] = useState<GeneratedToken | null>(null);

  const reset = () => {
    setStep(1);
    setToken(null);
    onClose();
  };

  return (
    <Drawer open={open} onClose={reset} title="Guided sensor setup" width="560px">
      <Stack gap="lg">
        <StepIndicator current={step} />

        {step === 1 && (
          <Step1CreateToken
            onCreated={(t) => {
              setToken(t);
              setStep(2);
            }}
          />
        )}

        {step === 2 && token && (
          <Step2Install token={token} onCandidateDetected={() => setStep(3)} />
        )}

        {step === 3 && token && <Step3Approve token={token} onDone={reset} />}
      </Stack>
    </Drawer>
  );
}
