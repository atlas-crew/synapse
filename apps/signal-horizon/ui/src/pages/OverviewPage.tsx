/**
 * Threat Overview Page
 * Live attack map, threat feed, sensor status, active campaigns
 */

import { motion } from 'framer-motion';
import { useMemo, useState } from 'react';
import { geoNaturalEarth1, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import type { Topology, GeometryCollection } from 'topojson-specification';
import land from 'world-atlas/land-110m.json';
import {
  Shield,
  AlertTriangle,
  Activity,
  Server,
  TrendingUp,
  Globe,
  RefreshCw,
  Download,
  Settings,
} from 'lucide-react';
import { clsx } from 'clsx';
import { useHorizonStore } from '../stores/horizonStore';
import {
  StatsGridSkeleton,
  CampaignListSkeleton,
  AlertFeedSkeleton,
  TableSkeleton,
} from '../components/LoadingStates';

const severityColors = {
  LOW: 'text-ac-blue bg-ac-blue/10 border-ac-blue/30',
  MEDIUM: 'text-ac-orange bg-ac-orange/10 border-ac-orange/30',
  HIGH: 'text-ac-orange bg-ac-orange/20 border-ac-orange/40',
  CRITICAL: 'text-ac-red bg-ac-red/15 border-ac-red/40',
};

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

type AttackSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
type AttackPoint = {
  id: number;
  lat: number;
  lon: number;
  severity: AttackSeverity;
  label: string;
  count: number;
  scope: 'fleet' | 'local';
  category: 'bot' | 'attack';
};

type AttackRoute = {
  id: string;
  from: number;
  to: number;
  severity: AttackSeverity;
  category: 'bot' | 'attack';
};

const mapPoints: AttackPoint[] = [
  { id: 1, lat: 39, lon: -77, severity: 'CRITICAL', label: 'US East', count: 1280, scope: 'fleet', category: 'attack' },
  { id: 2, lat: -15, lon: -60, severity: 'HIGH', label: 'LATAM', count: 860, scope: 'local', category: 'bot' },
  { id: 3, lat: 50, lon: 5, severity: 'MEDIUM', label: 'Western EU', count: 640, scope: 'fleet', category: 'attack' },
  { id: 4, lat: 30, lon: 35, severity: 'LOW', label: 'MENA', count: 420, scope: 'local', category: 'bot' },
  { id: 5, lat: 13, lon: 100, severity: 'HIGH', label: 'SEA', count: 980, scope: 'fleet', category: 'attack' },
  { id: 6, lat: 35, lon: 135, severity: 'CRITICAL', label: 'APAC Core', count: 1560, scope: 'fleet', category: 'attack' },
];

const mapRoutes: AttackRoute[] = [
  { id: 'na-eu', from: 1, to: 3, severity: 'HIGH', category: 'attack' },
  { id: 'na-apac', from: 1, to: 6, severity: 'CRITICAL', category: 'attack' },
  { id: 'latam-eu', from: 2, to: 3, severity: 'MEDIUM', category: 'bot' },
  { id: 'eu-sea', from: 3, to: 5, severity: 'HIGH', category: 'attack' },
  { id: 'mena-sea', from: 4, to: 5, severity: 'LOW', category: 'bot' },
];

const mapFilters = ['All Attacks', 'Top Bots (1h)', 'Cross-Tenant'];

export default function OverviewPage() {
  const { campaigns, threats, alerts, stats, isLoading } = useHorizonStore();
  const [activeFilter, setActiveFilter] = useState(mapFilters[0]);

  const filteredMapPoints = useMemo(() => {
    if (activeFilter === 'Top Bots (1h)') {
      return mapPoints.filter((point) => point.category === 'bot');
    }

    if (activeFilter === 'Cross-Tenant') {
      return mapPoints.filter((point) => point.scope === 'fleet');
    }

    return mapPoints;
  }, [activeFilter]);

  const filteredMapRoutes = useMemo(() => {
    const visiblePoints = new Set(filteredMapPoints.map((point) => point.id));
    return mapRoutes.filter((route) => {
      if (!visiblePoints.has(route.from) || !visiblePoints.has(route.to)) {
        return false;
      }
      if (activeFilter === 'Top Bots (1h)') {
        return route.category === 'bot';
      }
      if (activeFilter === 'Cross-Tenant') {
        return true;
      }
      return true;
    });
  }, [activeFilter, filteredMapPoints]);

  const topAttackers = useMemo(() => {
    if (threats.length === 0) return fallbackAttackers;
    return [...threats]
      .sort((a, b) => b.hitCount - a.hitCount)
      .slice(0, 5)
      .map((threat) => ({ label: threat.indicator, value: threat.hitCount }));
  }, [threats]);

  const topFingerprints = useMemo(() => {
    const fingerprintThreats = threats.filter((t) =>
      t.threatType.toLowerCase().includes('fingerprint')
    );
    const source = fingerprintThreats.length > 0 ? fingerprintThreats : threats;
    if (source.length === 0) return fallbackFingerprints;
    return [...source]
      .sort((a, b) => b.hitCount - a.hitCount)
      .slice(0, 5)
      .map((threat) => ({ label: threat.indicator, value: threat.hitCount }));
  }, [threats]);

  if (isLoading) {
    return (
      <div className="p-6 space-y-6" role="main" aria-busy="true" aria-label="Loading threat overview">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-light text-ink-primary">Threat Overview</h1>
            <p className="text-ink-secondary mt-1">Loading fleet intelligence...</p>
          </div>
        </div>
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

  return (
    <div className="p-6 space-y-6" role="main" aria-label="Threat overview dashboard">
      {/* Header */}
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs tracking-[0.2em] uppercase text-ink-muted">Signal Horizon</p>
          <h1 className="text-3xl font-light text-ink-primary">Threat Overview</h1>
          <p className="text-ink-secondary mt-1">
            Fleet threat intelligence and collective defense across {stats.sensorsOnline} sensors
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-outline h-10 px-4 text-xs">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </button>
          <button className="btn-outline h-10 px-4 text-xs">
            <Download className="w-4 h-4 mr-2" />
            Export Report
          </button>
          <button className="btn-secondary h-10 px-4 text-xs">
            <Settings className="w-4 h-4 mr-2" />
            Settings
          </button>
        </div>
      </header>

      {/* Stats Grid */}
      <section aria-label="Key metrics" className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          icon={Shield}
          label="Active Campaigns"
          value={stats.activeCampaigns}
          sublabel="+2 from yesterday"
          tone="text-ac-red"
        />
        <StatCard
          icon={AlertTriangle}
          label="Campaigns (24h)"
          value={campaigns.length}
          sublabel="+4 from yesterday"
          tone="text-ac-orange"
        />
        <StatCard
          icon={Activity}
          label="Blocked"
          value={stats.blockedIndicators}
          sublabel="+12% from yesterday"
          tone="text-ac-green"
        />
        <StatCard
          icon={Server}
          label="Sensors Reporting"
          value={`${stats.sensorsOnline}`}
          sublabel="1 sensor offline"
          tone="text-ac-blue"
        />
      </section>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Live Attack Map */}
        <section className="xl:col-span-2 card" aria-labelledby="attack-map-heading">
          <div className="card-header flex items-center justify-between">
            <h2 id="attack-map-heading" className="font-medium text-ink-primary">
              Live Attack Map
            </h2>
            <div className="flex items-center gap-2">
              {mapFilters.map((filter) => (
                <button
                  key={filter}
                  onClick={() => setActiveFilter(filter)}
                  className={clsx(
                    'px-3 py-1 text-xs border transition-colors',
                    activeFilter === filter
                      ? 'border-link text-link bg-surface-subtle'
                      : 'border-border-subtle text-ink-muted hover:text-ink-primary hover:bg-surface-subtle'
                  )}
                >
                  {filter}
                </button>
              ))}
            </div>
          </div>
          <div className="card-body">
            <AttackMap points={filteredMapPoints} routes={filteredMapRoutes} />
          </div>
        </section>

        {/* Threat Feed */}
        <section className="card" aria-labelledby="threat-feed-heading" aria-live="polite">
          <div className="card-header flex items-center justify-between">
            <h2 id="threat-feed-heading" className="font-medium text-ink-primary">Threat Feed</h2>
            <TrendingUp className="w-4 h-4 text-ink-muted" aria-hidden="true" />
          </div>
          <div className="card-body max-h-80 overflow-y-auto" role="log" aria-label="Recent threat alerts">
            {alerts.length === 0 ? (
              <div className="text-center text-ink-muted py-8" role="status">
                No recent alerts
              </div>
            ) : (
              <div className="space-y-2">
                {alerts.slice(0, 8).map((alert) => (
                  <motion.div
                    key={alert.id}
                    initial={{ opacity: 0, y: -6 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={clsx(
                      'p-3 border-l-2 bg-surface-inset',
                      alert.severity === 'CRITICAL' && 'border-ac-red',
                      alert.severity === 'HIGH' && 'border-ac-orange',
                      alert.severity === 'MEDIUM' && 'border-ac-orange',
                      alert.severity === 'LOW' && 'border-ac-blue'
                    )}
                  >
                    <div className="font-medium text-ink-primary">{alert.title}</div>
                    <div className="text-ink-secondary mt-0.5">{alert.description}</div>
                    <div className="text-ink-muted mt-1 text-xs">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </div>
                  </motion.div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Active Campaigns */}
        <section className="xl:col-span-2 card" aria-labelledby="campaigns-heading">
          <div className="card-header flex items-center justify-between">
            <h2 id="campaigns-heading" className="font-medium text-ink-primary">Active Campaigns</h2>
            <span className="text-xs text-ink-muted" aria-label={`${campaigns.length} active campaigns`}>
              {campaigns.length} active
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table" role="table" aria-label="Active campaigns">
              <thead>
                <tr>
                  <th scope="col">Campaign</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Tenants</th>
                  <th scope="col">Confidence</th>
                  <th scope="col">Last Activity</th>
                  <th scope="col">Scope</th>
                </tr>
              </thead>
              <tbody>
                {campaigns.slice(0, 6).map((campaign) => (
                  <tr key={campaign.id}>
                    <td className="font-medium text-ink-primary">{campaign.name}</td>
                    <td>
                      <span className={clsx('px-2 py-0.5 text-xs border', severityColors[campaign.severity])}>
                        {campaign.severity}
                      </span>
                    </td>
                    <td>{campaign.tenantsAffected}</td>
                    <td>{Math.round(campaign.confidence * 100)}%</td>
                    <td className="text-ink-muted text-sm">
                      {new Date(campaign.lastActivityAt).toLocaleTimeString()}
                    </td>
                    <td>
                      {campaign.isCrossTenant ? (
                        <span className="flex items-center gap-1 text-ac-purple">
                          <Globe className="w-3 h-3" />
                          Fleet
                        </span>
                      ) : (
                        <span className="text-ink-muted">Local</span>
                      )}
                    </td>
                  </tr>
                ))}
                {campaigns.length === 0 && (
                  <tr>
                    <td colSpan={6} className="text-center text-ink-muted py-6">
                      No active campaigns detected
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <div className="space-y-6">
          {/* Top Attackers */}
          <section className="card" aria-labelledby="attackers-heading">
            <div className="card-header">
              <h2 id="attackers-heading" className="font-medium text-ink-primary">Top Attackers (24h)</h2>
            </div>
            <div className="card-body space-y-3">
              {topAttackers.map((attacker) => (
                <div key={attacker.label} className="flex items-center justify-between text-sm">
                  <span className="text-ink-secondary">{attacker.label}</span>
                  <span className="text-ink-muted">{attacker.value.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </section>

          {/* Top Fingerprints */}
          <section className="card" aria-labelledby="fingerprints-heading">
            <div className="card-header">
              <h2 id="fingerprints-heading" className="font-medium text-ink-primary">Top Fingerprints (24h)</h2>
            </div>
            <div className="card-body space-y-3">
              {topFingerprints.map((fingerprint) => (
                <div key={fingerprint.label} className="flex items-center justify-between text-sm">
                  <span className="text-ink-secondary">{fingerprint.label}</span>
                  <span className="text-ink-muted">{fingerprint.value.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function AttackMap({
  points,
  routes,
}: {
  points: AttackPoint[];
  routes: AttackRoute[];
}) {
  const mapWidth = 1000;
  const mapHeight = 520;

  const landPath = useMemo(() => {
    const topology = land as unknown as Topology<{ land: GeometryCollection }>;
    const landFeature = feature(topology, topology.objects.land);
    const projection = geoNaturalEarth1().fitSize([mapWidth, mapHeight], landFeature);
    const pathGenerator = geoPath(projection);
    return pathGenerator(landFeature) ?? '';
  }, [mapHeight, mapWidth]);

  const projectedPoints = useMemo(() => {
    const topology = land as unknown as Topology<{ land: GeometryCollection }>;
    const landFeature = feature(topology, topology.objects.land);
    const projection = geoNaturalEarth1().fitSize([mapWidth, mapHeight], landFeature);

    return points
      .map((point) => {
        const projected = projection([point.lon, point.lat]);
        if (!projected) {
          return null;
        }
        const [x, y] = projected;
        return {
          ...point,
          x,
          y,
          xPercent: (x / mapWidth) * 100,
          yPercent: (y / mapHeight) * 100,
        };
      })
      .filter(
        (point): point is AttackPoint & {
          x: number;
          y: number;
          xPercent: number;
          yPercent: number;
        } => Boolean(point)
      );
  }, [mapHeight, mapWidth, points]);

  const pointLookup = useMemo(() => {
    const map = new Map<number, (typeof projectedPoints)[number]>();
    for (const point of projectedPoints) {
      map.set(point.id, point);
    }
    return map;
  }, [projectedPoints]);

  const routesToRender = useMemo(() => {
    return routes
      .map((route) => {
        const from = pointLookup.get(route.from);
        const to = pointLookup.get(route.to);
        if (!from || !to) return null;

        const midX = (from.x + to.x) / 2;
        const arcHeight = Math.max(30, Math.abs(from.x - to.x) * 0.15);
        const midY = Math.max(Math.min(from.y, to.y) - arcHeight, 16);
        const path = `M ${from.x} ${from.y} Q ${midX} ${midY} ${to.x} ${to.y}`;
        return { ...route, path };
      })
      .filter((route): route is AttackRoute & { path: string } => Boolean(route));
  }, [pointLookup, routes]);

  return (
    <div
      className="relative h-72 overflow-hidden border border-border-subtle bg-surface-inset"
      role="img"
      aria-label="Stylized world map with live attack activity"
    >
      <div
        className="absolute inset-0"
        style={{
          backgroundImage: [
            'radial-gradient(circle at 18% 30%, rgba(0, 87, 183, 0.16), transparent 45%)',
            'radial-gradient(circle at 72% 42%, rgba(227, 82, 5, 0.16), transparent 45%)',
            'radial-gradient(circle at 55% 75%, rgba(0, 177, 64, 0.12), transparent 38%)',
            'linear-gradient(180deg, rgba(0, 30, 98, 0.04), rgba(0, 30, 98, 0))',
            'radial-gradient(circle at 1px 1px, rgba(0, 87, 183, 0.22) 1px, transparent 0)',
          ].join(','),
          backgroundSize: '100% 100%, 100% 100%, 100% 100%, 100% 100%, 18px 18px',
          backgroundPosition: 'center, center, center, center, 0 0',
        }}
      />

      <svg
        className="absolute inset-0 h-full w-full"
        viewBox={`0 0 ${mapWidth} ${mapHeight}`}
        preserveAspectRatio="xMidYMid meet"
        style={{ color: 'var(--ac-blue)' }}
      >
        <g opacity="0.35" fill="currentColor">
          <path d={landPath} />
        </g>

        <g opacity="0.18" fill="none" stroke="currentColor" strokeWidth="0.6">
          <path d="M 0 200 Q 250 120 500 200 T 1000 200" />
          <path d="M 0 320 Q 250 250 500 320 T 1000 320" />
          <path d="M 180 0 Q 220 120 180 260 T 180 520" />
          <path d="M 500 0 Q 540 120 500 260 T 500 520" />
          <path d="M 820 0 Q 860 120 820 260 T 820 520" />
        </g>

      </svg>

      <svg
        className="absolute inset-0 h-full w-full"
        viewBox={`0 0 ${mapWidth} ${mapHeight}`}
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          <linearGradient id="attack-arc" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="var(--ac-blue)" stopOpacity="0.2" />
            <stop offset="50%" stopColor="var(--ac-sky-blue)" stopOpacity="0.65" />
            <stop offset="100%" stopColor="var(--ac-orange)" stopOpacity="0.35" />
          </linearGradient>
        </defs>

        {routesToRender.map((route, index) => (
          <motion.path
            key={route.id}
            d={route.path}
            stroke="url(#attack-arc)"
            strokeWidth={route.severity === 'CRITICAL' ? 0.6 : route.severity === 'HIGH' ? 0.5 : 0.4}
            fill="none"
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 0.8 }}
            transition={{
              duration: 1.4,
              ease: 'easeOut',
              delay: index * 0.15,
            }}
          />
        ))}
      </svg>

      <motion.div
        className="absolute left-0 right-0 h-px bg-ac-blue/40"
        initial={{ y: 24, opacity: 0.3 }}
        animate={{ y: [24, 200, 24], opacity: [0.2, 0.6, 0.2] }}
        transition={{ duration: 10, ease: 'linear', repeat: Infinity }}
      />

      {projectedPoints.map((point) => {
        const size = point.severity === 'CRITICAL' ? 10 : point.severity === 'HIGH' ? 8 : 6;
        const dotClass = clsx(
          point.severity === 'CRITICAL' && 'bg-ac-red',
          point.severity === 'HIGH' && 'bg-ac-orange',
          point.severity === 'MEDIUM' && 'bg-ac-blue',
          point.severity === 'LOW' && 'bg-ac-green'
        );

        return (
          <motion.div
            key={point.id}
            className="absolute group"
            style={{
              left: `${point.xPercent}%`,
              top: `${point.yPercent}%`,
              transform: 'translate(-50%, -50%)',
            }}
            initial={{ scale: 0.6, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
          >
            <span
              className={clsx('block rounded-full shadow-[0_0_12px_rgba(0,0,0,0.15)]', dotClass)}
              style={{ width: size, height: size }}
            />
            <span
              className={clsx(
                'absolute inset-0 rounded-full animate-ping-slow opacity-50',
                dotClass
              )}
              style={{ width: size, height: size }}
            />
            <span
              className="absolute left-3 top-1/2 -translate-y-1/2 whitespace-nowrap bg-surface-base/90 border border-border-subtle px-2 py-1 text-[10px] text-ink-secondary opacity-0 transition-opacity group-hover:opacity-100"
            >
              {point.label} · {point.count.toLocaleString()}
            </span>
          </motion.div>
        );
      })}

      <div className="absolute bottom-3 left-4 flex items-center gap-4 text-[10px] text-ink-muted">
        {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as AttackSeverity[]).map((severity) => (
          <div key={severity} className="flex items-center gap-1.5">
            <span
              className={clsx(
                'inline-block h-2 w-2 rounded-full',
                severity === 'CRITICAL' && 'bg-ac-red',
                severity === 'HIGH' && 'bg-ac-orange',
                severity === 'MEDIUM' && 'bg-ac-blue',
                severity === 'LOW' && 'bg-ac-green'
              )}
            />
            <span>{severity}</span>
          </div>
        ))}
      </div>

      <div className="absolute bottom-3 right-4 text-[10px] uppercase tracking-[0.2em] text-ink-muted">
        Live · 15s
      </div>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  sublabel,
  tone,
}: {
  icon: React.ElementType;
  label: string;
  value: number | string;
  sublabel?: string;
  tone: string;
}) {
  return (
    <article
      className="card p-4 flex items-center justify-between"
      aria-label={`${label}: ${value.toLocaleString()}`}
      tabIndex={0}
    >
      <div>
        <div className="text-xs tracking-[0.18em] uppercase text-ink-muted">{label}</div>
        <div className="text-2xl font-light text-ink-primary">{value}</div>
        {sublabel && <div className="text-xs text-ink-muted mt-1">{sublabel}</div>}
      </div>
      <div className={clsx('w-10 h-10 border border-border-subtle flex items-center justify-center', tone)}>
        <Icon className="w-5 h-5" />
      </div>
    </article>
  );
}
