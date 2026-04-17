/**
 * FleetSitesPage — Fleet-wide multi-site view
 *
 * Aggregates Synapse's per-sensor `/sites` response across every
 * connected sensor into a single scannable list. Phase 1 is
 * read-only: list + filter by hostname/sensor, plus KPI summary.
 * Editing (creating sites, toggling WAF, rule overrides, rate limits,
 * access control) will land in a follow-up by reusing the existing
 * `@components/fleet/pingora/*` editors in a detail drawer.
 *
 * Why client-side aggregation: the Horizon API has no fleet-level
 * sites endpoint today, and building one would require a dedicated
 * service layer (`FleetSessionQueryService`-style). That infrastructure
 * investment is deferred until a second caller justifies it. For
 * fleets under ~50 sensors, parallel client-side fetches through the
 * Synapse proxy are fast enough and ship immediately.
 */

import { useMemo, useState } from 'react';
import { Globe, Shield, ShieldOff, RefreshCw, Search, Plus } from 'lucide-react';
import {
  Alert,
  Button,
  CARD_HEADER_TITLE_STYLE,
  DataTable,
  EmptyState,
  Input,
  MetricCard,
  PAGE_TITLE_STYLE,
  Panel,
  SectionHeader,
  Select,
  Spinner,
  Stack,
  StatusBadge,
  ValuePill,
  colors,
} from '@/ui';
import { useSensors, useFleetSites, type FleetSite } from '../../hooks/fleet';
import { useIsDemo } from '../../stores/demoModeStore';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { FleetSiteDrawer } from '../../components/fleet/FleetSiteDrawer';
import { FleetSiteCreateDrawer } from '../../components/fleet/FleetSiteCreateDrawer';

const PAGE_HEADER_STYLE = { marginBottom: 0 };

export default function FleetSitesPage() {
  useDocumentTitle('Fleet Sites');

  const { data: sensors = [] } = useSensors();
  const { data: sites = [], isLoading, isFetching, refetch } = useFleetSites();
  // Write operations (create, edit save, delete) hit real Synapse
  // proxy endpoints that don't exist for demo sensors. We disable
  // those actions in demo mode and surface a banner explaining why,
  // rather than letting operators see cryptic 502/404 toasts.
  const isDemo = useIsDemo();

  // Filter state — client-side only for MVP. If the fleet grows past
  // a few hundred sites we'd want server-side pagination, but at that
  // scale we'd also want server-side aggregation (see file-level
  // comment), so this is a non-problem until both trigger together.
  const [search, setSearch] = useState('');
  const [sensorFilter, setSensorFilter] = useState<string>('');

  // Selected site for the edit drawer. Setting to null closes it.
  // The drawer handles its own invalidation on save/delete, so this
  // page doesn't need to explicitly refetch.
  const [selectedSite, setSelectedSite] = useState<FleetSite | null>(null);

  // Create drawer visibility. On successful creation the created-site
  // shape is forwarded to setSelectedSite so the edit drawer opens
  // immediately — bridges "create with defaults" → "tune the knobs"
  // without a detour through the table.
  const [createOpen, setCreateOpen] = useState(false);

  const filteredSites = useMemo(() => {
    const q = search.trim().toLowerCase();
    return sites.filter((site) => {
      if (sensorFilter && site.sensorId !== sensorFilter) return false;
      if (q && !site.hostname.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [sites, search, sensorFilter]);

  // KPI summary — aggregates across the filtered set so the numbers
  // match what the table below shows. Unfiltered state equals fleet-wide.
  const summary = useMemo(() => {
    const wafEnabled = filteredSites.filter((s) => s.wafEnabled).length;
    const tlsEnabled = filteredSites.filter((s) => s.tlsEnabled).length;
    const rateLimited = filteredSites.filter((s) => s.rateLimitRps != null).length;
    const sensorsWithSites = new Set(filteredSites.map((s) => s.sensorId)).size;
    return {
      total: filteredSites.length,
      wafEnabled,
      tlsEnabled,
      rateLimited,
      sensorsWithSites,
    };
  }, [filteredSites]);

  // Options for the sensor filter — pulled from live sensors list so
  // the dropdown stays accurate even for sensors that currently serve
  // zero sites (might be misconfigured or newly provisioned).
  const sensorOptions = useMemo(
    () => [
      { value: '', label: 'All sensors' },
      ...sensors.map((s) => ({ value: s.id, label: s.name ?? s.id })),
    ],
    [sensors],
  );

  return (
    <div className="p-6 space-y-6">
      <Stack direction="row" align="center" justify="space-between" gap="md">
        <SectionHeader
          title="Fleet Sites"
          description="Virtual hosts served across every connected sensor. One row per (sensor, hostname) pair."
          size="h1"
          style={PAGE_HEADER_STYLE}
          titleStyle={PAGE_TITLE_STYLE}
        />
        <Stack direction="row" gap="sm">
          <Button
            variant="outlined"
            size="sm"
            icon={<RefreshCw className="w-3.5 h-3.5" />}
            onClick={() => refetch()}
            disabled={isFetching}
          >
            {isFetching ? 'Refreshing' : 'Refresh'}
          </Button>
          <Button
            variant="primary"
            size="sm"
            icon={<Plus className="w-3.5 h-3.5" />}
            onClick={() => setCreateOpen(true)}
            disabled={sensors.length === 0 || isDemo}
            title={isDemo ? 'Disabled in demo mode' : undefined}
          >
            Create site
          </Button>
        </Stack>
      </Stack>

      {/* Demo-mode notice. Sites, edits, and deletes hit real Synapse
          proxy endpoints — demo sensors don't exist on the network
          side, so write actions would return cryptic errors. Show a
          banner so operators know the page is a read-only sample. */}
      {isDemo && (
        <Alert status="info">
          <strong>Demo mode.</strong> Sites shown below are synthetic and safe to
          browse — hostname filter, sensor filter, and row click (edit drawer) all
          work. <em>Create, save, and delete are disabled</em> until a real fleet is
          connected. Switch off demo mode to make changes against live sensors.
        </Alert>
      )}

      {/* KPI strip. Uses MetricCard rather than KpiStrip because we want
          individual border-l accents per card matching the Synapse icon
          palette (not the cycled KpiStrip colors). */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <MetricCard
          label="Sites"
          value={summary.total.toLocaleString()}
          subtitle={`${summary.sensorsWithSites} sensors`}
          borderColor={colors.blue}
        />
        <MetricCard
          label="WAF Enabled"
          value={summary.wafEnabled.toLocaleString()}
          subtitle={summary.total ? `${Math.round((summary.wafEnabled / summary.total) * 100)}% of sites` : '—'}
          borderColor={colors.green}
          valueColor={colors.green}
        />
        <MetricCard
          label="TLS Enabled"
          value={summary.tlsEnabled.toLocaleString()}
          subtitle={summary.total ? `${Math.round((summary.tlsEnabled / summary.total) * 100)}% of sites` : '—'}
          borderColor={colors.skyBlue}
        />
        <MetricCard
          label="Rate Limited"
          value={summary.rateLimited.toLocaleString()}
          subtitle="sites with explicit rps cap"
          borderColor={colors.orange}
        />
        <MetricCard
          label="Sensors"
          value={sensors.length.toLocaleString()}
          subtitle={`${summary.sensorsWithSites} currently hosting sites`}
          borderColor={colors.magenta}
        />
      </div>

      {/* Filters. Search is client-side substring-match on hostname;
          the sensor dropdown is a hard equality filter. */}
      <Panel tone="default" padding="md" spacing="none">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Input
            id="sites-search"
            label="Search hostname"
            placeholder="e.g. api.example.com"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            size="sm"
          />
          <Select
            id="sites-sensor"
            label="Sensor"
            value={sensorFilter}
            onChange={(e) => setSensorFilter(e.target.value)}
            size="sm"
            options={sensorOptions}
          />
        </div>
      </Panel>

      {/* Main sites table. */}
      <Panel tone="default">
        <Panel.Header>
          <SectionHeader
            title="Sites"
            description={`${filteredSites.length} of ${sites.length}`}
            size="h4"
            style={{ marginBottom: 0 }}
            titleStyle={CARD_HEADER_TITLE_STYLE}
          />
        </Panel.Header>
        <Panel.Body padding="none">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Spinner size={32} color={colors.blue} />
            </div>
          ) : filteredSites.length === 0 ? (
            <div className="py-6">
              <EmptyState
                icon={<Search className="w-8 h-8" />}
                title={sites.length === 0 ? 'No sites found across the fleet' : 'No sites match your filters'}
                description={
                  sites.length === 0
                    ? 'Once a sensor has sites configured in its Synapse config, they will appear here. Each site represents one virtual host served by that sensor.'
                    : 'Try clearing the hostname search or switching the sensor filter back to "All sensors".'
                }
                action={
                  sites.length > 0 ? (
                    <Button
                      variant="outlined"
                      size="sm"
                      onClick={() => {
                        setSearch('');
                        setSensorFilter('');
                      }}
                    >
                      Clear filters
                    </Button>
                  ) : undefined
                }
              />
            </div>
          ) : (
            <DataTable
              card={false}
              onRowClick={(row) => setSelectedSite(row)}
              columns={[
                {
                  key: 'hostname',
                  label: 'Hostname',
                  render: (_v, row: FleetSite) => (
                    <Stack direction="row" align="center" gap="sm">
                      <Globe className="w-3.5 h-3.5 text-ac-blue flex-shrink-0" />
                      <span className="font-mono text-sm">{row.hostname}</span>
                    </Stack>
                  ),
                },
                {
                  key: 'sensorName',
                  label: 'Sensor',
                  render: (_v, row: FleetSite) => (
                    <span className="text-ink-secondary text-sm">{row.sensorName}</span>
                  ),
                },
                {
                  key: 'upstreams',
                  label: 'Upstreams',
                  render: (_v, row: FleetSite) => (
                    <span className="font-mono text-[11px] text-ink-secondary">
                      {row.upstreams.length === 0
                        ? '—'
                        : row.upstreams.length === 1
                          ? row.upstreams[0]
                          : `${row.upstreams[0]} (+${row.upstreams.length - 1})`}
                    </span>
                  ),
                },
                {
                  key: 'wafEnabled',
                  label: 'WAF',
                  align: 'center',
                  render: (_v, row: FleetSite) =>
                    row.wafEnabled ? (
                      <StatusBadge status="success" variant="subtle" size="sm">
                        <Shield className="w-3 h-3 inline mr-1" />
                        On
                      </StatusBadge>
                    ) : (
                      <StatusBadge status="error" variant="subtle" size="sm">
                        <ShieldOff className="w-3 h-3 inline mr-1" />
                        Off
                      </StatusBadge>
                    ),
                },
                {
                  key: 'tlsEnabled',
                  label: 'TLS',
                  align: 'center',
                  render: (_v, row: FleetSite) =>
                    row.tlsEnabled ? (
                      <StatusBadge status="success" variant="subtle" size="sm">On</StatusBadge>
                    ) : (
                      <span className="text-ink-muted text-xs">—</span>
                    ),
                },
                {
                  key: 'rateLimitRps',
                  label: 'Rate Limit',
                  align: 'right',
                  render: (_v, row: FleetSite) =>
                    row.rateLimitRps != null ? (
                      <ValuePill value={`${row.rateLimitRps} rps`} color="blue" />
                    ) : (
                      <span className="text-ink-muted text-xs">—</span>
                    ),
                },
              ]}
              data={filteredSites}
            />
          )}
        </Panel.Body>
      </Panel>

      {/* Edit / delete drawer. Stays mounted so it can animate in/out
          smoothly; the drawer component handles its own open state
          via the `site` prop (null = closed). */}
      <FleetSiteDrawer
        site={selectedSite}
        onClose={() => setSelectedSite(null)}
        readOnly={isDemo}
      />

      {/* Create drawer. On success, the newly-created site is piped
          straight into the edit drawer via setSelectedSite so the
          operator can tune WAF/rate-limit/access-control knobs
          immediately without re-finding the row in the table. */}
      <FleetSiteCreateDrawer
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        sensors={sensors}
        defaultSensorId={sensorFilter || undefined}
        onCreated={(newSite) => {
          setSelectedSite(newSite);
        }}
      />
    </div>
  );
}
