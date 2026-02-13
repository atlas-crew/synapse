/**
 * Threat Overview Page
 * Live attack map, threat feed, sensor status, active campaigns
 *
 * Migrated to @/ui component library for brand consistency.
 */

import { motion } from 'framer-motion';
import { lazy, Suspense, useEffect, useMemo, useState } from 'react';
import { geoNaturalEarth1, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import type { GeometryCollection, Topology } from 'topojson-specification';
import land from 'world-atlas/land-110m.json';
import {
  Shield,
  AlertTriangle,
  Activity,
  Server,
  RefreshCw,
  Download,
  Settings,
  Database,
} from 'lucide-react';
import { clsx } from 'clsx';
import { useHorizonStore, useTimeRange } from '../stores/horizonStore';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import {
  StatsGridSkeleton,
  CampaignListSkeleton,
  AlertFeedSkeleton,
  TableSkeleton,
} from '../components/LoadingStates';
import { ErrorBoundary } from '../components/ErrorBoundary';
import {
  useAttackMap,
  type AttackPoint,
  type AttackRoute,
  type AttackSeverity,
} from '../hooks/useAttackMap';
import { useRelativeTime } from '../hooks/useRelativeTime';

// ─── @/ui library imports ────────────────────────────────────────────────────
import { SectionHeader, KpiStrip, Button, Stack, colors } from '@/ui';

const ActiveCampaignList = lazy(() => import('../components/soc/ActiveCampaignList'));
const ThreatTrajectoryFeed = lazy(() => import('../components/soc/ThreatTrajectoryFeed'));

const LAND_TOPOLOGY = land as unknown as Topology<{ land: GeometryCollection }>;
const LAND_GEO = feature(LAND_TOPOLOGY, LAND_TOPOLOGY.objects.land);

function AttackMap({ points, routes }: { points: AttackPoint[]; routes: AttackRoute[] }) {
  const W = 920;
  const H = 520;

  const projection = useMemo(() => geoNaturalEarth1().fitSize([W, H], LAND_GEO), []);

  const path = useMemo(() => geoPath(projection), [projection]);

  const byId = useMemo(() => new Map(points.map((p) => [p.id, p])), [points]);

  const severityColor = (s: AttackSeverity) => {
    if (s === 'CRITICAL') return colors.red;
    if (s === 'HIGH') return colors.magenta;
    if (s === 'MEDIUM') return colors.orange;
    return colors.skyBlue;
  };

  const projPoint = (p: AttackPoint): [number, number] | null => projection([p.lon, p.lat]);

  const routePath = (from: AttackPoint, to: AttackPoint) => {
    const a = projPoint(from);
    const b = projPoint(to);
    if (!a || !b) return null;
    const [x1, y1] = a;
    const [x2, y2] = b;
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2 - Math.min(120, Math.hypot(x2 - x1, y2 - y1) / 4);
    return `M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`;
  };

  return (
    <div className="relative w-full h-[520px] overflow-hidden border border-border-subtle bg-surface-base">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        height="100%"
        role="img"
        aria-label="Live attack map"
        preserveAspectRatio="xMidYMid meet"
      >
        <path
          d={path(LAND_GEO) ?? ''}
          fill="rgba(255,255,255,0.04)"
          stroke="rgba(255,255,255,0.06)"
        />

        {routes.map((r) => {
          const from = byId.get(r.from);
          const to = byId.get(r.to);
          if (!from || !to) return null;
          const d = routePath(from, to);
          if (!d) return null;
          const stroke = severityColor(r.severity);
          return (
            <motion.path
              key={r.id}
              d={d}
              fill="none"
              stroke={stroke}
              strokeOpacity={0.55}
              strokeWidth={1.5}
              initial={{ pathLength: 0 }}
              animate={{ pathLength: 1 }}
              transition={{ duration: 0.6 }}
            />
          );
        })}

        {points.map((p) => {
          const xy = projPoint(p);
          if (!xy) return null;
          const [x, y] = xy;
          const fill = severityColor(p.severity);
          const r = Math.max(2.5, Math.min(7, 2.5 + Math.log10(Math.max(10, p.count)) * 1.5));
          return (
            <g key={p.id}>
              <circle cx={x} cy={y} r={r + 4} fill={fill} opacity={0.08} />
              <circle cx={x} cy={y} r={r} fill={fill} opacity={0.9}>
                <title>
                  {p.label} · {p.count.toLocaleString()}
                </title>
              </circle>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

const fallbackAttackers = [
  { label: '185.228.101.0/24', value: 12421 },
  { label: '45.134.26.0/24', value: 8234 },
  { label: '91.240.148.0/24', value: 5891 },
  { label: 'AS12345', value: 5102 },
  { label: '45.134.26.0/24', value: 2567 },
];

const fallbackFingerprints = [
  { label: 'python-requests', value: 3421 },
  { label: 'curl/7.68', value: 2740 },
  { label: 'go-http-client', value: 2198 },
  { label: 'custom-scanner', value: 1203 },
  { label: 'headless-chrome', value: 901 },
];

const mapFilters = ['All Attacks', 'Top Bots (1h)', 'Cross-Tenant'];

export default function OverviewPage() {
  useDocumentTitle('Overview');
  const { campaigns, threats, alerts, stats, isLoading: isStoreLoading } = useHorizonStore();
  const timeRange = useTimeRange();
  const timeRangeLabel = timeRange || '24h';
  const {
    points: mapPoints,
    routes: mapRoutes,
    isLoading: isMapLoading,
    error,
    refetch,
  } = useAttackMap();
  const isLoading = isStoreLoading || isMapLoading;
  const [activeFilter, setActiveFilter] = useState(mapFilters[0]);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const lastUpdatedText = useRelativeTime(lastUpdated);

  useEffect(() => {
    if (!isLoading && (campaigns.length > 0 || threats.length > 0 || alerts.length > 0)) {
      setLastUpdated(Date.now());
    }
  }, [isLoading, campaigns.length, threats.length, alerts.length]);

  const filteredMapPoints = useMemo(() => {
    if (activeFilter === 'Top Bots (1h)') return mapPoints.filter((p) => p.category === 'bot');
    if (activeFilter === 'Cross-Tenant') return mapPoints.filter((p) => p.scope === 'fleet');
    return mapPoints;
  }, [activeFilter, mapPoints]);

  const filteredMapRoutes = useMemo(() => {
    const visible = new Set(filteredMapPoints.map((p) => p.id));
    return mapRoutes.filter((r) => {
      if (!visible.has(r.from) || !visible.has(r.to)) return false;
      if (activeFilter === 'Top Bots (1h)') return r.category === 'bot';
      return true;
    });
  }, [activeFilter, filteredMapPoints, mapRoutes]);

  const topAttackers = useMemo(() => {
    if (threats.length === 0) return fallbackAttackers;
    return [...threats]
      .sort((a, b) => b.hitCount - a.hitCount)
      .slice(0, 5)
      .map((t) => ({ label: t.indicator, value: t.hitCount }));
  }, [threats]);

  const topFingerprints = useMemo(() => {
    const fp = threats.filter((t) => t.threatType.toLowerCase().includes('fingerprint'));
    const source = fp.length > 0 ? fp : threats;
    if (source.length === 0) return fallbackFingerprints;
    return [...source]
      .sort((a, b) => b.hitCount - a.hitCount)
      .slice(0, 5)
      .map((t) => ({ label: t.indicator, value: t.hitCount }));
  }, [threats]);

  const kpiMetrics = useMemo(
    () => [
      {
        label: 'Active Campaigns',
        value: stats.activeCampaigns,
        subtitle: '+2 from yesterday',
        borderColor: colors.red,
        icon: <Shield className="w-4 h-4" />,
      },
      {
        label: 'Campaigns (24h)',
        value: campaigns.length,
        subtitle: '+4 from yesterday',
        borderColor: colors.orange,
        icon: <AlertTriangle className="w-4 h-4" />,
      },
      {
        label: 'Blocked',
        value: stats.blockedIndicators,
        subtitle: '+12% from yesterday',
        borderColor: colors.green,
        icon: <Activity className="w-4 h-4" />,
      },
      {
        label: 'Sensors Reporting',
        value: `${stats.sensorsOnline}`,
        subtitle: '1 sensor offline',
        borderColor: colors.blue,
        icon: <Server className="w-4 h-4" />,
      },
      {
        label: 'API Discovery',
        value: stats.apiStats?.discoveryEvents ?? 0,
        subtitle: `${stats.apiStats?.schemaViolations ?? 0} schema changes`,
        borderColor: colors.purple,
        icon: <Database className="w-4 h-4" />,
      },
    ],
    [stats, campaigns.length],
  );

  if (isLoading) {
    return (
      <div
        className="p-6 space-y-6"
        role="main"
        aria-busy="true"
        aria-label="Loading threat overview"
      >
        <SectionHeader
          eyebrow={`Signal Horizon · Last ${timeRangeLabel}`}
          title="Threat Overview"
          description="Loading fleet intelligence..."
          size="h3"
          mb="sm"
        />
        <StatsGridSkeleton />
        <div className="grid grid-cols-3 gap-6">
          <div className="col-span-2">
            <CampaignListSkeleton />
          </div>
          <AlertFeedSkeleton />
        </div>
        <TableSkeleton rows={5} />
      </div>
    );
  }

  const lastUpdatedSuffix = lastUpdatedText ? ` · Updated ${lastUpdatedText}` : '';

  return (
    <div className="p-6 space-y-6" role="main" aria-label="Threat overview dashboard">
      {/* ─── Header ──────────────────────────────────────────────────── */}
      <SectionHeader
        eyebrow={`Signal Horizon · Last ${timeRangeLabel}`}
        title="Threat Overview"
        description={`Fleet threat intelligence and collective defense across ${stats.sensorsOnline} sensors${lastUpdatedSuffix}`}
        size="h3"
        mb="sm"
        actions={
          <Stack direction="row" gap="sm">
            <Button
              variant="outlined"
              size="sm"
              icon={<RefreshCw className="w-4 h-4" />}
              onClick={() => refetch()}
            >
              Refresh
            </Button>
            <Button variant="outlined" size="sm" icon={<Download className="w-4 h-4" />}>
              Export Report
            </Button>
            <Button variant="secondary" size="sm" icon={<Settings className="w-4 h-4" />}>
              Settings
            </Button>
          </Stack>
        }
      />

      {/* ─── KPI Strip ───────────────────────────────────────────────── */}
      <KpiStrip metrics={kpiMetrics} cols={5} size="default" />

      {/* ─── Attack Map + Threat Feed ────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <section
          className="md:col-span-2 card scanlines tactical-bg relative overflow-hidden"
          aria-labelledby="attack-map-heading"
        >
          <div className="absolute top-0 right-0 w-1/2 h-full bg-white/5 diagonal-split pointer-events-none" />
          <div className="card-header flex items-center justify-between relative z-10">
            <Stack direction="row" align="center" gap="smPlus">
              <SectionHeader
                titleId="attack-map-heading"
                title="Live Attack Map"
                size="h4"
                mb="xs"
                style={{ marginBottom: 0 }}
                titleStyle={{
                  fontSize: '16px',
                  lineHeight: '24px',
                  fontWeight: 500,
                  letterSpacing: '0.02em',
                }}
              />
              {error && (
                <Stack
                  as="span"
                  inline
                  direction="row"
                  align="center"
                  gap="xs"
                  className="text-xs text-ac-orange"
                >
                  <AlertTriangle className="w-3 h-3" />
                  Using cached data
                </Stack>
              )}
            </Stack>
            <Stack direction="row" align="center" gap="sm">
              {mapFilters.map((filter) => (
                <Button
                  key={filter}
                  variant={activeFilter === filter ? 'primary' : 'ghost'}
                  size="sm"
                  onClick={() => setActiveFilter(filter)}
                  aria-pressed={activeFilter === filter}
                  className={clsx(activeFilter === filter && 'border-link')}
                  style={{ fontSize: '12px', height: '28px', padding: '0 12px' }}
                >
                  {filter}
                </Button>
              ))}
            </Stack>
          </div>
          <div className="card-body relative z-10">
            <AttackMap points={filteredMapPoints} routes={filteredMapRoutes} />
          </div>
        </section>
        <div className="flex flex-col h-fit">
          <ErrorBoundary fallback={<AlertFeedSkeleton />}>
            <Suspense fallback={<AlertFeedSkeleton />}>
              <ThreatTrajectoryFeed threats={threats} alerts={alerts} />
            </Suspense>
          </ErrorBoundary>
        </div>
      </div>

      {/* ─── Active Campaigns ────────────────────────────────────────── */}
      <section
        className="card border-t-4 border-ac-blue flex flex-col min-h-[300px]"
        aria-labelledby="campaigns-heading"
      >
        <div className="card-header flex items-center justify-between bg-surface-subtle/50 shrink-0">
          <SectionHeader
            titleId="campaigns-heading"
            title="Active Campaigns"
            size="h4"
            mb="xs"
            style={{ marginBottom: 0 }}
            titleStyle={{
              fontSize: '14px',
              lineHeight: '20px',
              fontWeight: 700,
              letterSpacing: '0.01em',
            }}
          />
          <Stack direction="row" align="center" gap="md">
            <span className="text-[10px] font-bold text-ink-muted uppercase tracking-widest">
              {campaigns.filter((c) => c.status === 'ACTIVE').length} ACTIVE
            </span>
            <Button
              variant="ghost"
              size="sm"
              style={{ fontSize: '10px', height: '24px', letterSpacing: '0.1em' }}
            >
              View All Campaigns &gt;
            </Button>
          </Stack>
        </div>
        <div className="card-body p-0">
          <ErrorBoundary fallback={<CampaignListSkeleton />}>
            <Suspense fallback={<CampaignListSkeleton />}>
              <ActiveCampaignList campaigns={campaigns} />
            </Suspense>
          </ErrorBoundary>
        </div>
      </section>

      {/* ─── Strategic Insights + Top Metrics ────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Strategic Insight hero */}
        <div
          className="group flex flex-col justify-center min-h-[450px] relative overflow-hidden"
          style={{ background: colors.navy, padding: '24px' }}
        >
          <div className="absolute top-0 right-0 w-32 h-full bg-white/5 diagonal-split transition-transform group-hover:scale-110 duration-500" />
          <div className="relative z-10">
            <Stack
              direction="row"
              align="center"
              gap="sm"
              className="mb-3"
              style={{ color: colors.skyBlue }}
            >
              <Shield className="w-4 h-4" />
              <span className="text-[10px] font-bold uppercase tracking-[0.2em]">
                Strategic Insight
              </span>
            </Stack>
            <h3
              className="text-xl font-light mb-4 tracking-tight"
              style={{ color: colors.gray.light }}
            >
              Fleet Vulnerability Analysis
            </h3>
            <p className="text-sm leading-relaxed mb-6" style={{ color: 'rgba(255,255,255,0.7)' }}>
              Current telemetry indicates a 14% increase in credential stuffing attempts targeting
              the catalog-api. Edge sensors have automatically shifted to aggressive rate-limiting.
            </p>
            <div className="space-y-4 mb-6">
              <div
                className="flex items-center justify-between text-[10px] uppercase tracking-widest"
                style={{ color: 'rgba(255,255,255,0.5)' }}
              >
                <span>Threat Level</span>
                <span className="text-ac-orange">Elevated</span>
              </div>
              <div
                className="h-1 w-full overflow-hidden"
                style={{ background: 'rgba(255,255,255,0.1)' }}
              >
                <div className="h-full w-[65%]" style={{ background: colors.orange }} />
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              iconAfter={<Activity className="w-3 h-3" />}
              style={{
                color: colors.magenta,
                fontSize: '10px',
                letterSpacing: '0.1em',
                padding: 0,
                height: 'auto',
              }}
            >
              Review Recommended Policies
            </Button>
          </div>
        </div>

        {/* Top Attackers */}
        <section
          className="card border-t border-border-subtle flex flex-col h-full min-h-[450px]"
          aria-labelledby="attackers-heading"
        >
          <div className="card-header py-3 bg-surface-subtle/30 shrink-0">
            <SectionHeader
              titleId="attackers-heading"
              title="Top Attackers (24h)"
              size="h4"
              mb="xs"
              style={{ marginBottom: 0 }}
              titleStyle={{
                fontSize: '12px',
                lineHeight: '16px',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                color: colors.gray.mid,
              }}
            />
          </div>
          <div className="card-body space-y-5 overflow-auto flex-grow">
            {topAttackers.map((a) => (
              <Stack key={a.label} direction="column" style={{ gap: '0.375rem' }}>
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-ink-secondary truncate pr-2">{a.label}</span>
                  <span className="text-ink-muted font-bold">{a.value.toLocaleString()}</span>
                </div>
                <div className="h-1 w-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
                  <div
                    className="h-full"
                    style={{
                      background: `${colors.blue}B3`,
                      width: `${Math.min(100, (a.value / (topAttackers[0]?.value || 1)) * 100)}%`,
                    }}
                  />
                </div>
              </Stack>
            ))}
          </div>
        </section>

        {/* Top Fingerprints */}
        <section
          className="card border-t border-border-subtle flex flex-col h-full min-h-[450px]"
          aria-labelledby="fingerprints-heading"
        >
          <div className="card-header py-3 bg-surface-subtle/30 shrink-0">
            <SectionHeader
              titleId="fingerprints-heading"
              title="Top Fingerprints (24h)"
              size="h4"
              mb="xs"
              style={{ marginBottom: 0 }}
              titleStyle={{
                fontSize: '12px',
                lineHeight: '16px',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                color: colors.gray.mid,
              }}
            />
          </div>
          <div className="card-body space-y-5 overflow-auto flex-grow">
            {topFingerprints.map((f) => (
              <Stack key={f.label} direction="column" style={{ gap: '0.375rem' }}>
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-ink-secondary truncate pr-2">{f.label}</span>
                  <span className="text-ink-muted font-bold">{f.value.toLocaleString()}</span>
                </div>
                <div className="h-1 w-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
                  <div
                    className="h-full"
                    style={{
                      background: `${colors.magenta}B3`,
                      width: `${Math.min(100, (f.value / (topFingerprints[0]?.value || 1)) * 100)}%`,
                    }}
                  />
                </div>
              </Stack>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
