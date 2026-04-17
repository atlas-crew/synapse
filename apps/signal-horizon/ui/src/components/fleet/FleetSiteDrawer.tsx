/**
 * FleetSiteDrawer — Edit + delete for a single fleet site.
 *
 * Consumes the raw Synapse `/sites/:hostname` shape directly rather
 * than transforming to the Pingora editor components (WafConfig etc).
 * Those editors use a different shape (`requests_per_second` vs
 * Synapse's `rps`, nested rule_overrides object vs Synapse's flat
 * string map) because they were authored against the Horizon API's
 * pingora config endpoint, not the Synapse admin API. A transform
 * layer is a future refactor; for the fleet-wide sites MVP the
 * direct-shape editor is simpler and avoids round-trip lossy mapping.
 *
 * Hostname and upstreams are read-only here — changing either means
 * creating a new site. That's a different UX (Phase 3) and keeping
 * them immutable here prevents accidental topology changes while
 * editing quick knobs like WAF toggle or rate-limit rps.
 */

import { useEffect, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Trash2, Save, Shield, Gauge, Lock, ListFilter } from 'lucide-react';
import {
  Alert,
  Button,
  Drawer,
  Input,
  Modal,
  Panel,
  Select,
  Stack,
  Text,
  colors,
} from '@/ui';
import { apiFetch } from '../../lib/api';
import type { FleetSite } from '../../hooks/fleet';

interface FleetSiteDrawerProps {
  site: FleetSite | null;
  onClose: () => void;
}

/**
 * Editable slice of a site — only the fields this drawer surfaces.
 * Other fields (headers, shadow_mirror, waf.rule_overrides, TLS
 * cert_path / key_path) are preserved verbatim from `site.raw` on
 * save so they round-trip untouched.
 */
interface Editable {
  wafEnabled: boolean;
  wafThreshold: string; // keep as string to allow "" while editing
  rateLimitEnabled: boolean;
  rateLimitRps: string;
  acDefault: string; // 'allow' | 'deny' | ''
  acAllowText: string; // newline-separated CIDRs
  acDenyText: string;
}

function extractEditable(raw: Record<string, unknown>): Editable {
  const waf = (raw.waf as { enabled?: boolean; threshold?: number } | null) ?? null;
  const rl = (raw.rate_limit as { enabled?: boolean; rps?: number } | null) ?? null;
  const ac = (raw.access_control as
    | { allow?: string[]; deny?: string[]; default_action?: string }
    | null) ?? null;
  return {
    wafEnabled: waf?.enabled ?? true,
    wafThreshold: waf?.threshold != null ? String(waf.threshold) : '',
    rateLimitEnabled: rl?.enabled ?? false,
    rateLimitRps: rl?.rps != null ? String(rl.rps) : '',
    acDefault: ac?.default_action ?? '',
    acAllowText: (ac?.allow ?? []).join('\n'),
    acDenyText: (ac?.deny ?? []).join('\n'),
  };
}

// Convert the form state back into a Synapse site payload. Preserves
// every field in `raw` that this drawer doesn't surface (headers,
// shadow_mirror, tls, waf.rule_overrides) by spreading raw first.
function buildPayload(raw: Record<string, unknown>, edits: Editable): Record<string, unknown> {
  const parsedThreshold = edits.wafThreshold.trim() === '' ? null : Number(edits.wafThreshold);
  const wafThreshold =
    parsedThreshold != null && !Number.isNaN(parsedThreshold) ? parsedThreshold : null;
  const parsedRps = edits.rateLimitRps.trim() === '' ? null : Number(edits.rateLimitRps);
  const rateLimitRps =
    parsedRps != null && !Number.isNaN(parsedRps) ? parsedRps : null;

  const existingWaf = (raw.waf as Record<string, unknown> | null) ?? {};
  const existingRl = (raw.rate_limit as Record<string, unknown> | null) ?? {};
  const existingAc = (raw.access_control as Record<string, unknown> | null) ?? {};

  // Parse textareas into trimmed non-empty lines. Operators expect
  // newline separation to be the canonical CIDR-list format.
  const toList = (text: string): string[] =>
    text
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

  return {
    ...raw,
    waf: {
      ...existingWaf,
      enabled: edits.wafEnabled,
      threshold: wafThreshold,
    },
    rate_limit: rateLimitRps != null || edits.rateLimitEnabled
      ? {
          ...existingRl,
          enabled: edits.rateLimitEnabled,
          rps: rateLimitRps ?? 0,
        }
      : null,
    access_control: edits.acDefault || edits.acAllowText || edits.acDenyText
      ? {
          ...existingAc,
          allow: toList(edits.acAllowText),
          deny: toList(edits.acDenyText),
          default_action: edits.acDefault || undefined,
        }
      : null,
  };
}

export function FleetSiteDrawer({ site, onClose }: FleetSiteDrawerProps) {
  const queryClient = useQueryClient();
  const [edits, setEdits] = useState<Editable | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Reset edits whenever a new site is selected. This also handles
  // close-and-reopen: the form always reflects the current remote
  // state, never the previous session's in-progress edits.
  useEffect(() => {
    if (site) {
      setEdits(extractEditable(site.raw));
      setSaveError(null);
    } else {
      setEdits(null);
    }
  }, [site]);

  const saveMutation = useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      if (!site) throw new Error('No site selected');
      return apiFetch<unknown>(
        `/synapse/${encodeURIComponent(site.sensorId)}/proxy/sites/${encodeURIComponent(site.hostname)}`,
        { method: 'PUT', body: payload },
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'sites'] });
      onClose();
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : JSON.stringify(err);
      setSaveError(msg);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async () => {
      if (!site) throw new Error('No site selected');
      return apiFetch<unknown>(
        `/synapse/${encodeURIComponent(site.sensorId)}/proxy/sites/${encodeURIComponent(site.hostname)}`,
        { method: 'DELETE' },
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'sites'] });
      setConfirmDelete(false);
      onClose();
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : JSON.stringify(err);
      setSaveError(msg);
      setConfirmDelete(false);
    },
  });

  const handleSave = () => {
    if (!site || !edits) return;
    setSaveError(null);
    saveMutation.mutate(buildPayload(site.raw, edits));
  };

  const isOpen = site !== null;

  return (
    <>
      <Drawer
        open={isOpen}
        onClose={onClose}
        title={site ? `Edit site — ${site.hostname}` : ''}
        width="520px"
      >
        {site && edits && (
          <Stack direction="column" gap="md">
            {/* Read-only metadata. Changing hostname / upstreams is a
                create-new-site operation (Phase 3). Showing them here
                prevents confusion about why they're not editable. */}
            <Panel tone="default" padding="md" spacing="none">
              <Stack direction="column" gap="sm">
                <div>
                  <Text variant="label" muted>Sensor</Text>
                  <div className="text-sm text-ink-primary">{site.sensorName}</div>
                </div>
                <div>
                  <Text variant="label" muted>Hostname</Text>
                  <div className="font-mono text-sm text-ink-primary">{site.hostname}</div>
                </div>
                <div>
                  <Text variant="label" muted>Upstreams</Text>
                  <div className="font-mono text-xs text-ink-secondary">
                    {site.upstreams.length === 0 ? '(none)' : site.upstreams.join(', ')}
                  </div>
                </div>
                <Text variant="tag" muted>
                  Changing hostname or upstreams means recreating the site — use the Sites
                  table actions in Phase 3 for that.
                </Text>
              </Stack>
            </Panel>

            {/* WAF */}
            <Panel tone="info" padding="md" spacing="sm">
              <Stack direction="row" align="center" gap="sm" className="mb-2">
                <Shield className="w-4 h-4 text-ac-blue" />
                <Text variant="label">WAF</Text>
              </Stack>
              <label className="flex items-center gap-2 text-sm text-ink-primary cursor-pointer">
                <input
                  type="checkbox"
                  checked={edits.wafEnabled}
                  onChange={(e) => setEdits({ ...edits, wafEnabled: e.target.checked })}
                />
                Enabled
              </label>
              <Input
                id="site-waf-threshold"
                label="Risk threshold (0–100, blank = use global)"
                type="number"
                min={0}
                max={100}
                value={edits.wafThreshold}
                onChange={(e) => setEdits({ ...edits, wafThreshold: e.target.value })}
                placeholder="e.g. 70"
                size="sm"
              />
            </Panel>

            {/* Rate limiting */}
            <Panel tone="info" padding="md" spacing="sm">
              <Stack direction="row" align="center" gap="sm" className="mb-2">
                <Gauge className="w-4 h-4 text-ac-blue" />
                <Text variant="label">Rate limit</Text>
              </Stack>
              <label className="flex items-center gap-2 text-sm text-ink-primary cursor-pointer">
                <input
                  type="checkbox"
                  checked={edits.rateLimitEnabled}
                  onChange={(e) => setEdits({ ...edits, rateLimitEnabled: e.target.checked })}
                />
                Enabled
              </label>
              <Input
                id="site-rl-rps"
                label="Requests per second (blank to disable per-site cap)"
                type="number"
                min={0}
                value={edits.rateLimitRps}
                onChange={(e) => setEdits({ ...edits, rateLimitRps: e.target.value })}
                placeholder="e.g. 1000"
                size="sm"
                disabled={!edits.rateLimitEnabled}
              />
            </Panel>

            {/* Access control */}
            <Panel tone="info" padding="md" spacing="sm">
              <Stack direction="row" align="center" gap="sm" className="mb-2">
                <ListFilter className="w-4 h-4 text-ac-blue" />
                <Text variant="label">Access control</Text>
              </Stack>
              <Select
                id="site-ac-default"
                label="Default action (when no allow/deny rule matches)"
                value={edits.acDefault}
                onChange={(e) => setEdits({ ...edits, acDefault: e.target.value })}
                size="sm"
                options={[
                  { value: '', label: '(inherit global)' },
                  { value: 'allow', label: 'allow' },
                  { value: 'deny', label: 'deny' },
                ]}
              />
              <div>
                <Text variant="label" muted>Allow (one CIDR per line)</Text>
                <textarea
                  value={edits.acAllowText}
                  onChange={(e) => setEdits({ ...edits, acAllowText: e.target.value })}
                  placeholder="10.0.0.0/8&#10;192.168.0.0/16"
                  className="w-full bg-surface-subtle border border-border-subtle text-ink-primary font-mono text-xs p-2"
                  rows={3}
                />
              </div>
              <div>
                <Text variant="label" muted>Deny (one CIDR per line)</Text>
                <textarea
                  value={edits.acDenyText}
                  onChange={(e) => setEdits({ ...edits, acDenyText: e.target.value })}
                  placeholder="203.0.113.0/24"
                  className="w-full bg-surface-subtle border border-border-subtle text-ink-primary font-mono text-xs p-2"
                  rows={3}
                />
              </div>
            </Panel>

            {/* TLS (read-only — editing cert paths is a privileged op
                that typically happens out-of-band via config file or
                cert-manager, not through this drawer). */}
            <Panel tone="default" padding="md" spacing="none">
              <Stack direction="row" align="center" gap="sm" className="mb-2">
                <Lock className="w-4 h-4 text-ink-muted" />
                <Text variant="label" muted>TLS</Text>
              </Stack>
              <div className="text-sm text-ink-primary">
                {site.tlsEnabled ? 'Configured' : 'Not configured'}
              </div>
              <Text variant="tag" muted>
                Cert / key paths are managed via sensor config or cert-manager. Edit at
                the sensor level, not per-site in this UI.
              </Text>
            </Panel>

            {saveError && (
              <Alert status="error">
                <strong>Save failed:</strong> {saveError}
              </Alert>
            )}

            {/* Footer actions */}
            <Stack direction="row" justify="space-between" align="center" gap="md">
              <Button
                variant="ghost"
                size="sm"
                icon={<Trash2 className="w-3.5 h-3.5" />}
                onClick={() => setConfirmDelete(true)}
                style={{ color: colors.red }}
              >
                Delete site
              </Button>
              <Stack direction="row" gap="sm">
                <Button variant="ghost" size="sm" onClick={onClose}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  icon={<Save className="w-3.5 h-3.5" />}
                  onClick={handleSave}
                  disabled={saveMutation.isPending}
                >
                  {saveMutation.isPending ? 'Saving…' : 'Save'}
                </Button>
              </Stack>
            </Stack>
          </Stack>
        )}
      </Drawer>

      {/* Confirmation modal kept outside the Drawer so it stays
          visible if the Drawer scrolls. */}
      <Modal
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        title={site ? `Delete site ${site.hostname}?` : 'Delete site?'}
      >
        <Stack direction="column" gap="md">
          <Text variant="body">
            This removes the site from the sensor immediately. Existing traffic to this
            hostname will stop being proxied. The operation is irreversible from the UI
            — recreate the site in Phase 3 or edit the sensor config file directly.
          </Text>
          <Alert status="warning">
            <strong>Sensor:</strong> {site?.sensorName}
            <br />
            <strong>Hostname:</strong> {site?.hostname}
          </Alert>
          <Stack direction="row" justify="flex-end" gap="sm">
            <Button variant="ghost" size="sm" onClick={() => setConfirmDelete(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => deleteMutation.mutate()}
              disabled={deleteMutation.isPending}
              style={{ background: colors.red, borderColor: colors.red }}
            >
              {deleteMutation.isPending ? 'Deleting…' : 'Delete site'}
            </Button>
          </Stack>
        </Stack>
      </Modal>
    </>
  );
}
